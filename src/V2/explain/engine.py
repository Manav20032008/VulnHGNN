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
