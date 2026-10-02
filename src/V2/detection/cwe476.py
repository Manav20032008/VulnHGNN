import re

from ..analysis.finding import SecurityFinding


class CWE476Detector:
    cwe_id = "CWE-476"

    ALLOCATORS = {
        "malloc",
        "calloc",
        "realloc",
        "aligned_alloc",
    }

    MEMORY_FUNCTIONS = {
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "memcpy",
        "memmove",
        "memset",
        "sprintf",
        "snprintf",
        "scanf",
        "sscanf",
        "fscanf",
    }

    @staticmethod
    def tokens(text):
        return set(re.findall(r"%[-A-Za-z0-9._]+", text))

    @staticmethod
    def result(data):
        return data.get("result", "")

    @staticmethod
    def text(data):
        return data.get("text", "")

    def allocations(self, graph):
        """
        Find allocator calls.

        Returns:
            [(SSA_result, node_id), ...]
        """
        result = []

        for node, data in graph.nodes(data=True):
            if data.get("node_type") != "instruction":
                continue

            if data.get("opcode") != "call":
                continue

            text = self.text(data)
            value = self.result(data)

            if not value:
                continue

            if any(f"@{name}" in text for name in self.ALLOCATORS):
                result.append((value, node))

        return result

    def aliases(self, graph, alloc_value):
        """
        Recover aliases through LLVM stack slots.

        Example:

            %4 = call noalias ptr @malloc(...)
            store ptr %4, ptr %3
            %5 = load ptr, ptr %3

        Therefore:

            %4 == allocated pointer
            %5 == alias of allocated pointer

        The graph's data-flow edges do not directly connect the
        store to the subsequent load, so we infer this from the
        actual LLVM IR text.
        """

        aliases = {alloc_value}
        slots = set()

        # ---------------------------------------------------------
        # Pass 1:
        #
        # Find:
        #
        #   store ptr %ALLOC, ptr %SLOT
        #
        # ---------------------------------------------------------
        for _, data in graph.nodes(data=True):
            if data.get("node_type") != "instruction":
                continue

            if data.get("opcode") != "store":
                continue

            text = self.text(data)

            if alloc_value not in self.tokens(text):
                continue

            # store <value>, <destination>
            parts = text.split(",", 1)

            if len(parts) != 2:
                continue

            destination = self.tokens(parts[1])

            slots.update(destination)

        # ---------------------------------------------------------
        # Pass 2:
        #
        # Find:
        #
        #   %ALIAS = load ptr, ptr %SLOT
        #
        # ---------------------------------------------------------
        changed = True

        while changed:
            changed = False

            for _, data in graph.nodes(data=True):
                if data.get("node_type") != "instruction":
                    continue

                if data.get("opcode") != "load":
                    continue

                text = self.text(data)
                value = self.result(data)

                if not value:
                    continue

                if "load ptr" not in text:
                    continue

                source_tokens = self.tokens(text)

                if source_tokens & slots:
                    if value not in aliases:
                        aliases.add(value)
                        changed = True

        return aliases

    def is_dereference(self, data, aliases):
        """
        Determine whether an instruction actually dereferences
        an allocated pointer.

        IMPORTANT:

            store ptr %4, ptr %3

        does NOT dereference %4.

        But:

            store i32 500, ptr %6

        DOES dereference %6.
        """

        opcode = data.get("opcode", "")
        text = self.text(data)
        tokens = self.tokens(text)

        # ---------------------------------------------------------
        # load
        #
        # %x = load i32, ptr %p
        #
        # %p is being dereferenced.
        # ---------------------------------------------------------
        if opcode == "load":
            # `load ptr, ptr %slot` only retrieves the pointer value
            # from a stack slot. It does NOT dereference the allocated
            # memory.
            #
            # Actual dereference:
            #     %x = load i32, ptr %p
            #
            # Pointer retrieval:
            #     %x = load ptr, ptr %slot
            #
            # Only non-pointer loads through an allocated-pointer alias
            # are dereferences.
            if "load ptr" in text:
                return False

            return bool(tokens & aliases)
        # ---------------------------------------------------------
        # store
        #
        # store <value>, ptr <destination>
        #
        # Only destination is dereferenced.
        # ---------------------------------------------------------
        if opcode == "store":
            parts = text.split(",", 1)

            if len(parts) != 2:
                return False

            destination = self.tokens(parts[1])

            return bool(destination & aliases)

        # ---------------------------------------------------------
        # Known memory APIs.
        # ---------------------------------------------------------
        if opcode in {"call", "invoke"}:
            if not any(f"@{fn}" in text for fn in self.MEMORY_FUNCTIONS):
                return False

            return bool(tokens & aliases)

        return False

    def null_checks(self, graph, aliases):
        """
        Find:

            icmp ne ptr %alias, null

        and return the corresponding instruction nodes.
        """

        checks = []

        for node, data in graph.nodes(data=True):
            if data.get("node_type") != "instruction":
                continue

            if data.get("opcode") != "icmp":
                continue

            text = self.text(data)

            if "null" not in text:
                continue

            if " ne " not in f" {text} ":
                continue

            if not (self.tokens(text) & aliases):
                continue

            checks.append(node)

        return checks

    def containing_block(self, graph, node):
        """
        Find the basic block containing an instruction.
        """

        for block, data in graph.nodes(data=True):
            if data.get("node_type") != "block":
                continue

            if graph.has_edge(block, node):
                edge = graph.edges[block, node]

                if edge.get("edge_type") == "contains":
                    return block

        return None

    def instruction_position(self, graph, node):
        """
        Position based on NetworkX node insertion order.
        """

        for index, current in enumerate(graph.nodes()):
            if current == node:
                return index

        return -1

    def guarded_by_null_check(self, graph, check_node, use_node):
        """
        Determine whether a NULL check protects a dereference.

        For the current LLVM graph representation:

            check block
                 |
                 | control_flow
                 v
            protected block

        Example from the clean case:

            block_main_16
                 |
                 v
            block_main_20

        The NULL check is in block_main_16 and the dereference
        occurs in block_main_20.
        """

        check_block = self.containing_block(graph, check_node)
        use_block = self.containing_block(graph, use_node)

        if check_block is None or use_block is None:
            return False

        # Same block: check must appear before use.
        if check_block == use_block:
            return (
                self.instruction_position(graph, check_node)
                < self.instruction_position(graph, use_node)
            )

        # BFS over actual control-flow edges.
        visited = {check_block}
        queue = [check_block]

        while queue:
            current = queue.pop(0)

            for nxt in graph.successors(current):
                if nxt in visited:
                    continue

                edge = graph.edges[current, nxt]

                if edge.get("edge_type") != "control_flow":
                    continue

                if nxt == use_block:
                    return True

                visited.add(nxt)
                queue.append(nxt)

        return False

    
    
    def function_for_node(self, graph, node):
        """
        Resolve the LLVM function owning an instruction node.

        Instruction nodes may not carry a direct 'func' attribute.
        Their containing basic block does.
        """
        data = graph.nodes[node]

        # Direct function metadata, if available.
        function = data.get("func")
        if function:
            return function

        # Resolve through the containing block.
        for predecessor in graph.predecessors(node):
            predecessor_data = graph.nodes[predecessor]

            if predecessor_data.get("node_type") != "block":
                continue

            edge_data = graph.edges[predecessor, node]

            if edge_data.get("edge_type") != "contains":
                continue

            function = predecessor_data.get("func")
            if function:
                return function

        # Some graphs may expose the containing block through successors.
        for successor in graph.successors(node):
            successor_data = graph.nodes[successor]

            if successor_data.get("node_type") != "block":
                continue

            edge_data = graph.edges[node, successor]

            if edge_data.get("edge_type") != "contains":
                continue

            function = successor_data.get("func")
            if function:
                return function

        return None
    
    
    
    def detect(self, graph, context=None):
        findings = []

        for alloc_value, alloc_node in self.allocations(graph):

            aliases = self.aliases(
                graph,
                alloc_value,
            )

            checks = self.null_checks(
                graph,
                aliases,
            )

            # Find actual dereferences.
            for node, data in graph.nodes(data=True):

                if data.get("node_type") != "instruction":
                    continue

                if node == alloc_node:
                    continue

                if not self.is_dereference(data, aliases):
                    continue

                # -------------------------------------------------
                # Is this dereference protected by a NULL check?
                # -------------------------------------------------
                protected = False

                for check in checks:
                    if self.guarded_by_null_check(
                        graph,
                        check,
                        node,
                    ):
                        protected = True
                        break

                if protected:
                    continue

                findings.append(
                    SecurityFinding(
                        cwe_id="CWE-476",
                        title="NULL Pointer Dereference",
                        severity="HIGH",
                        confidence=0.99,
                        message=(
                            "Memory returned by an allocator is "
                            "dereferenced without a preceding NULL check."
                        ),
                        function=self.function_for_node(graph, node),
                        instruction=data.get("text", ""),
                        detector="CWE476Detector",
                        node_id=node,
                    )
                )

                # One finding per allocation is sufficient for
                # Phase 1.
                break

        return findings
