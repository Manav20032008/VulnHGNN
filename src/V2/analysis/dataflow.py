import re
from dataclasses import dataclass
from typing import Optional

_INT_RE = re.compile(r"^-?\d+$")
_RESULT_RE = re.compile(r"^\s*(%[-A-Za-z0-9$._]+)\s*=")
_ALLOC_RE = re.compile(r"\b(?:malloc|calloc|realloc)\s*\(")
_NULL_RE = re.compile(r"\bnull\b")
_VALUE_RE = re.compile(r"%[-A-Za-z0-9$._]+|-?\d+")

@dataclass
class InstructionInfo:
    node_id: object
    attrs: dict
    index: int
    function: str

class DataFlowAnalyzer:
    """
    Lightweight, deterministic LLVM-IR abstract interpreter for the Phase-1
    benchmark.

    It deliberately proves safety before reporting a finding:
      - constants are propagated through simple memory loads and aliases
      - signed arithmetic with `nsw` is reported only when safety cannot
        be proven from constants
      - division is reported only when the divisor is not proven non-zero
      - malloc-family results are tracked through bitcast aliases
    """

    def __init__(self, graph):
        self.graph = graph
        self.instructions = []
        self.by_result = {}
        self.memory_constants = {}
        self.constants = {}
        self.aliases = {}
        self._build()

    @staticmethod
    def _result(text):
        m = _RESULT_RE.match(text or "")
        return m.group(1) if m else None

    @staticmethod
    def _tokens(text):
        return _VALUE_RE.findall(text or "")

    @staticmethod
    def _int(token):
        if token is None:
            return None
        token = token.strip()
        return int(token) if _INT_RE.match(token) else None

    def _function_for_node(self, node_id, attrs):
        if attrs.get("func"):
            return attrs["func"]
        for parent, _, edata in self.graph.in_edges(node_id, data=True):
            if edata.get("edge_type") == "contains":
                p = self.graph.nodes[parent]
                if p.get("func"):
                    return p["func"]
        text = str(node_id)
        if text.startswith("inst_"):
            parts = text.split("_")
            if len(parts) >= 2:
                return parts[1]
        return "unknown"

    def _build(self):
        for idx, (node_id, attrs) in enumerate(self.graph.nodes(data=True)):
            if attrs.get("node_type") != "instruction":
                continue

            info = InstructionInfo(
                node_id=node_id,
                attrs=attrs,
                index=idx,
                function=self._function_for_node(node_id, attrs),
            )

            self.instructions.append(info)

            result = attrs.get("result") or self._result(attrs.get("text", ""))

            if result:
                self.by_result[result] = info

        # ------------------------------------------------------------
        # Pass 1:
        #   literal memory stores
        #   pointer stores
        #   direct pointer aliases
        # ------------------------------------------------------------

        for info in self.instructions:
            text = info.attrs.get("text", "")
            op = info.attrs.get("opcode", "")
            result = info.attrs.get("result") or self._result(text)

            # Integer constant stored in memory.
            if op == "store":
                m = re.search(
                    r"\bstore\b.*?\bi\d+\s+(-?\d+)\s*,\s*ptr\s+(%[-A-Za-z0-9$._]+)",
                    text,
                )

                if m:
                    self.memory_constants[m.group(2)] = int(m.group(1))

            # Pointer store:
            #
            #   store ptr %malloc_result, ptr %slot
            #
            # Remember that %slot contains %malloc_result.
            if op == "store":
                m = re.search(
                    r"\bstore\s+ptr\s+(%[-A-Za-z0-9$._]+)"
                    r"\s*,\s*ptr\s+(%[-A-Za-z0-9$._]+)",
                    text,
                )

                if m:
                    value_ptr = m.group(1)
                    memory_ptr = m.group(2)

                    self.aliases[memory_ptr] = value_ptr

            # Direct pointer-producing aliases.
            if result and op in {"bitcast", "addrspacecast", "getelementptr"}:
                toks = self._tokens(text.split("=", 1)[-1])

                if toks:
                    # Prefer the first SSA pointer operand.
                    ssa_tokens = [
                        token for token in toks
                        if token.startswith("%")
                    ]

                    if ssa_tokens:
                        self.aliases[result] = ssa_tokens[0]

        # ------------------------------------------------------------
        # Pass 2:
        # Resolve malloc -> stack slot -> load pointer chains.
        # ------------------------------------------------------------

        for _ in range(16):
            changed = False

            # Resolve aliases.
            for key, value in list(self.aliases.items()):
                root = value
                seen = set()

                while root in self.aliases and root not in seen:
                    seen.add(root)
                    root = self.aliases[root]

                if self.aliases.get(key) != root:
                    self.aliases[key] = root
                    changed = True

            # Load pointer values from stack slots.
            for info in self.instructions:
                text = info.attrs.get("text", "")
                op = info.attrs.get("opcode", "")
                result = info.attrs.get("result") or self._result(text)

                if not result:
                    continue

                if op == "load":
                    # Pointer load:
                    #
                    #   %p = load ptr, ptr %slot
                    #
                    pointer_load = re.search(
                        r"\bload\s+ptr\s*,\s*ptr\s+(%[-A-Za-z0-9$._]+)",
                        text,
                    )

                    if pointer_load:
                        memory_ptr = pointer_load.group(1)
                        root = self._root(memory_ptr)

                        if root in self.aliases:
                            source = self._root(self.aliases[root])

                            if self.aliases.get(result) != source:
                                self.aliases[result] = source
                                changed = True

                        continue

                    # Integer constant load.
                    m = re.search(
                        r"\bload\b.*?\bptr\s+(%[-A-Za-z0-9$._]+)",
                        text,
                    )

                    if m:
                        ptr = self._root(m.group(1))

                        if ptr in self.memory_constants:
                            val = self.memory_constants[ptr]

                            if self.constants.get(result) != val:
                                self.constants[result] = val
                                changed = True

                # Constant arithmetic propagation.
                if op in {"add", "sub", "mul"}:
                    vals = self._binary_operands(text, op)

                    if vals:
                        a, b = vals
                        av = self.value(a)
                        bv = self.value(b)

                        if av is not None and bv is not None:
                            value = {
                                "add": av + bv,
                                "sub": av - bv,
                                "mul": av * bv,
                            }[op]

                            if self.constants.get(result) != value:
                                self.constants[result] = value
                                changed = True

            if not changed:
                break

    def _root(self, value):
        seen = set()
        while value in self.aliases and value not in seen:
            seen.add(value)
            value = self.aliases[value]
        return value

    def value(self, operand) -> Optional[int]:
        literal = self._int(operand)
        if literal is not None:
            return literal
        operand = self._root(operand)
        return self.constants.get(operand)

    @staticmethod
    def _binary_operands(text, opcode):
        rhs = text.split("=", 1)[-1]
        m = re.search(
            rf"\b{re.escape(opcode)}\b(?:\s+nsw|\s+nuw|\s+exact)*\s+i\d+\s+([^,]+),\s*([^,\s]+)",
            rhs,
        )
        return (m.group(1).strip(), m.group(2).strip()) if m else None

    def arithmetic_info(self, info):
        op = info.attrs.get("opcode", "")
        text = info.attrs.get("text", "")
        if op not in {"add", "sub", "mul"}:
            return None
        operands = self._binary_operands(text, op)
        if not operands:
            return None
        a, b = operands
        return {
            "opcode": op,
            "a": a,
            "b": b,
            "a_value": self.value(a),
            "b_value": self.value(b),
            "nsw": "nsw" in text,
        }

    def division_info(self, info):
        op = info.attrs.get("opcode", "")
        text = info.attrs.get("text", "")

        if op not in {"sdiv", "udiv", "srem", "urem"}:
            return None

        rhs = text.split("=", 1)[-1]

        m = re.search(
            rf"\b{re.escape(op)}\b(?:\s+exact)?\s+i\d+\s+([^,]+),\s*([^,\s]+)",
            rhs,
        )

        if not m:
            return None

        divisor = m.group(2).strip()
        divisor_value = self.value(divisor)

        # Recognize SecureCC's branch-free zero-divisor repair:
        #
        #   %zero = icmp eq i32 %d, 0
        #   %safe = select i1 %zero, i32 1, i32 %d
        #
        # %safe can never be zero.
        if divisor_value is None and divisor.startswith("%"):
            definition = self.by_result.get(divisor)

            if definition is not None:
                def_text = definition.attrs.get("text", "")

                select_match = re.search(
                    r"\bselect\s+i1\s+(%[-A-Za-z0-9$._]+)"
                    r",\s*i\d+\s+(-?\d+)"
                    r",\s*i\d+\s+(%[-A-Za-z0-9$._]+)",
                    def_text,
                )

                if select_match:
                    condition = select_match.group(1)
                    fallback_value = int(select_match.group(2))
                    original_divisor = select_match.group(3)

                    if fallback_value != 0:
                        condition_info = self.by_result.get(condition)

                        if condition_info is not None:
                            condition_text = condition_info.attrs.get("text", "")

                            if (
                                "icmp eq" in condition_text
                                and original_divisor in condition_text
                            ):
                                divisor_value = fallback_value

        return {
            "opcode": op,
            "divisor": divisor,
            "divisor_value": divisor_value,
        }

    def allocation_results(self):
        results = []
        for info in self.instructions:
            text = info.attrs.get("text", "")
            op = info.attrs.get("opcode", "")
            result = info.attrs.get("result") or self._result(text)
            if result and op == "call" and _ALLOC_RE.search(text):
                results.append((result, info))
        return results

    def aliases_of(self, value):
        root = self._root(value)
        out = {value, root}
        changed = True
        while changed:
            changed = False
            for alias, source in self.aliases.items():
                if self._root(source) in out and alias not in out:
                    out.add(alias)
                    changed = True
        return out

    def null_checks(self, aliases):
        checks = []
        for info in self.instructions:
            if info.attrs.get("opcode") != "icmp":
                continue
            text = info.attrs.get("text", "")
            if not _NULL_RE.search(text):
                continue
            if any(alias in text for alias in aliases):
                checks.append(info)
        return checks

    def unsafe_pointer_use(self, alloc_result: str):

        graph = self.graph
        aliases = self.aliases_of(alloc_result)

        for node, data in graph.nodes(data=True):
            if data.get("node_type") != "instruction":
                continue

            opcode = data.get("opcode", "")
            text = data.get("text", "")

            if opcode == "load":
                operands = self._tokens(text)

                # LLVM load:
                #   %x = load i32, ptr %p
                #
                # The pointer operand is normally the last SSA operand.
                if operands and any(
                    alias in operands for alias in aliases
                ):
                    return node

            elif opcode == "store":
                operands = self._tokens(text)

                # LLVM store:
                #   store <value>, ptr <destination>
                #
                # Only the DESTINATION can be the dereferenced pointer.
                if len(operands) >= 2:
                    destination = operands[-1]

                    if destination in aliases:
                        return node

            elif opcode in {"call", "invoke"}:
                # Only treat known memory APIs as pointer uses.
                memory_functions = {
                    "strcpy",
                    "strncpy",
                    "strcat",
                    "strncat",
                    "memcpy",
                    "memmove",
                    "memset",
                    "free",
                    "printf",
                    "puts",
                    "scanf",
                    "fgets",
                }

                if any(
                    fn in text
                    for fn in memory_functions
                ):
                    if any(alias in text for alias in aliases):
                        return node

        return None
