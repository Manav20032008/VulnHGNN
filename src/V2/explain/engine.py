from .models import Explanation, EvidenceItem

INFO = {
    "CWE-190": {
        "title": "Integer Overflow", "severity": "HIGH",
        "impact": "An arithmetic result can exceed its representable range and produce an incorrect value.",
        "strategy": "Use checked arithmetic and verify the result before accepting the operation.",
    },
    "CWE-191": {
        "title": "Integer Underflow", "severity": "HIGH",
        "impact": "An arithmetic result can fall below the representable range and wrap or become invalid.",
        "strategy": "Use checked subtraction and validate operands/results before the operation.",
    },
    "CWE-369": {
        "title": "Divide By Zero", "severity": "HIGH",
        "impact": "A zero divisor can make integer division or remainder undefined and terminate the program.",
        "strategy": "Check the divisor for zero before division or remainder.",
    },
    "CWE-476": {
        "title": "NULL Pointer Dereference", "severity": "HIGH",
        "impact": "Dereferencing a NULL pointer can terminate the process and may become a memory-safety issue.",
        "strategy": "Validate the allocated pointer before the first memory dereference.",
    },
    "CWE-121": {
        "title": "Stack-based Buffer Overflow", "severity": "HIGH",
        "impact": "Unbounded copy into a fixed stack buffer can corrupt adjacent memory.",
        "strategy": "Use bounded APIs (strncpy, snprintf) and validate input length.",
    },
    "CWE-134": {
        "title": "Externally-Controlled Format String", "severity": "HIGH",
        "impact": "Attacker-controlled format strings can read or write arbitrary memory.",
        "strategy": "Use constant format literals; never pass user data as the format.",
    },
    "CWE-457": {
        "title": "Uninitialized Variable", "severity": "MEDIUM",
        "impact": "Reading uninitialized storage yields undefined behavior.",
        "strategy": "Initialize variables at declaration; enable -Wuninitialized.",
    },
    "CWE-787": {
        "title": "Out-of-bounds Write", "severity": "HIGH",
        "impact": "Writing past array bounds can corrupt memory and enable exploitation.",
        "strategy": "Validate indices against array size; use safe interfaces.",
    },
    "CWE-122": {
        "title": "Heap Buffer Overflow", "severity": "HIGH",
        "impact": "Writing past a heap allocation corrupts adjacent memory and metadata.",
        "strategy": "Use bounded copies and track allocation sizes.",
    },
    "CWE-125": {
        "title": "Out-of-bounds Read", "severity": "HIGH",
        "impact": "Reading outside allocated bounds leaks data or crashes.",
        "strategy": "Validate indices; enable compiler bounds checks.",
    },
    "CWE-789": {
        "title": "Excessive Allocation", "severity": "HIGH",
        "impact": "Huge or unchecked sizes can exhaust memory (OOM).",
        "strategy": "Cap sizes; check arithmetic before malloc.",
    },
    "CWE-400": {
        "title": "Resource Exhaustion", "severity": "HIGH",
        "impact": "Attacker-controlled allocation sizes can deny service.",
        "strategy": "Validate and bound resource requests.",
    },
    "CWE-415": {
        "title": "Double Free", "severity": "HIGH",
        "impact": "Freeing the same block twice corrupts heap allocators.",
        "strategy": "Set pointer to NULL after free; single owner for free.",
    },
    "CWE-416": {
        "title": "Use After Free", "severity": "HIGH",
        "impact": "Using freed memory is undefined and often exploitable.",
        "strategy": "Do not touch pointers after free; use clear ownership.",
    },
    "CWE-401": {
        "title": "Memory Leak", "severity": "MEDIUM",
        "impact": "Leaks exhaust memory over time.",
        "strategy": "Pair every allocation with release on all paths.",
    },
    "CWE-835": {
        "title": "Infinite Loop", "severity": "MEDIUM",
        "impact": "Non-terminating loops cause denial of service or hung threads.",
        "strategy": "Ensure loops have provable exit conditions; avoid while(1) without break.",
    },
    "CWE-833": {
        "title": "Deadlock", "severity": "HIGH",
        "impact": "Circular lock waits can freeze the program.",
        "strategy": "Use consistent lock ordering; avoid holding one lock while acquiring another.",
    },
    "CWE-667": {
        "title": "Improper Locking", "severity": "HIGH",
        "impact": "Double-locking the same mutex is undefined and may deadlock.",
        "strategy": "Never lock a mutex that is already held by the same thread.",
    },
}

EXPECTED = {
    "test_files_test_01_clean.json": [],
    "test_files_test_02_cwe190.json": ["CWE-190"],
    "test_files_test_03_cwe191.json": ["CWE-191"],
    "test_files_test_04_cwe369.json": ["CWE-369"],
    "test_files_test_05_cwe476.json": ["CWE-476"],
    "test_files_test_06_dual_190_191.json": ["CWE-190", "CWE-191"],
    "test_files_test_07_dual_369_476.json": ["CWE-369", "CWE-476"],
    "test_files_test_08_triple_190_191_369.json": ["CWE-190", "CWE-191", "CWE-369"],
    "test_files_test_09_triple_191_369_476.json": ["CWE-191", "CWE-369", "CWE-476"],
    "test_files_test_10_all_vulnerabilities.json": ["CWE-190", "CWE-191", "CWE-369", "CWE-476"],
}

class ExplainabilityEngine:
    def _instructions(self, graph):
        return [
            (n, a) for n, a in graph.nodes(data=True)
            if a.get("node_type") == "instruction"
        ]

    def _block(self, graph, node):
        for u, v, a in graph.in_edges(node, data=True):
            if graph.nodes[u].get("node_type") == "block":
                if a.get("edge_type") == "contains" or a.get("type") == "contains":
                    return u
        return "unknown"

    def _find(self, graph, cwe):
        insts = self._instructions(graph)

        if cwe == "CWE-190":
            return [(n,a) for n,a in insts
                    if a.get("opcode") in {"add","mul"} and "nsw" in a.get("text","")]

        if cwe == "CWE-191":
            return [(n,a) for n,a in insts
                    if a.get("opcode") == "sub" and "nsw" in a.get("text","")]

        if cwe == "CWE-369":
            return [(n,a) for n,a in insts
                    if a.get("opcode") in {"sdiv","udiv","srem","urem"}]

        if cwe == "CWE-476":
            alloc_results = {
                a.get("result") for n,a in insts
                if a.get("opcode") == "call" and "malloc" in a.get("text","")
            }
            out = []
            for n,a in insts:
                if a.get("opcode") not in {"load","store","gep"}:
                    continue
                text = a.get("text","")
                if any(r and r in text for r in alloc_results):
                    if not (a.get("opcode") == "load" and "load ptr" in text):
                        out.append((n,a))
            return out
        return []

    def explain(self, graph, cwe):
        if cwe not in INFO:
            return None
        matches = self._find(graph, cwe)
        if not matches:
            return None

        info = INFO[cwe]
        node, attrs = matches[0]
        block = self._block(graph, node)
        function = attrs.get("func") or "unknown"
        text = attrs.get("text","")

        evidence = [EvidenceItem(
            "vulnerable_operation", node, text, function, block,
            f"The graph contains the operation associated with {cwe}."
        )]

        for pred in list(graph.predecessors(node))[:3]:
            pdata = graph.nodes[pred]
            if pdata.get("node_type") == "instruction":
                evidence.append(EvidenceItem(
                    "local_graph_context", pred, pdata.get("text",""),
                    pdata.get("func") or function, self._block(graph,pred),
                    "Predecessor instruction provides local graph context."
                ))

        roots = {
            "CWE-190": "The arithmetic operation is marked with nsw, indicating a signed overflow-sensitive operation.",
            "CWE-191": "The subtraction operation is marked with nsw, indicating a signed underflow-sensitive operation.",
            "CWE-369": "The IR contains an integer division/remainder operation whose divisor must be proven non-zero.",
            "CWE-476": "An allocator-derived pointer reaches a memory dereference without evidence of a preceding NULL guard.",
        }

        return Explanation(
            cwe_id=cwe, title=info["title"], severity=info["severity"],
            root_cause=roots[cwe], security_impact=info["impact"],
            vulnerable_operation=text, function=function, block=block,
            node_id=node, evidence=evidence,
            repair_strategy=info["strategy"],
            verification="Phase 3 repair verification checks targeted-CWE removal and absence of new CWEs.",
            confidence_basis="Evidence coverage from the analyzed LLVM IR graph; not an invented probability.",
        )

    def explain_all(self, graph, cwes):
        return [x for cwe in cwes if (x := self.explain(graph, cwe)) is not None]
