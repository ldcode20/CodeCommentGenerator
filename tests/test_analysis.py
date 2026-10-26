"""
Week 8 Analysis Tests
======================
Tests for:
  - TestCFGBuilder     : build_cfg() structure and edge correctness
  - TestDFAEngine      : run_dfa() reaching defs, live vars, unused detection
  - TestPatternDetector: detect_patterns() reports findings correctly
"""
import unittest
from typing import List

from src.parser_module import parse_code
from src.ast_extractor import extract_features
from src.context_analyzer import analyze_context
from src.ir.ir_builder import build_ir
from src.ir.ir_nodes import IRModule, IROpcode
from src.analysis.cfg_builder import build_cfg, CFG, CFGNode
from src.analysis.dfa_engine import run_dfa, DFAResult
from src.analysis.pattern_detector import detect_patterns, AnalysisReport


# ── Shared fixtures ──────────────────────────────────────────────────────────

SIMPLE_CODE = """\
def add(a: int, b: int) -> int:
    return a + b
"""

COMPLEX_CODE = """\
def binary_search(arr, target):
    low, high = 0, len(arr) - 1
    while low <= high:
        mid = (low + high) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            low = mid + 1
        else:
            high = mid - 1
    return -1
"""

CALL_CODE = """\
def process(data):
    result = sorted(data)
    result = list(result)
    return result
"""


def _build_all(code: str):
    """Returns (ir_module, list_of_cfgs, list_of_dfa_results)."""
    tree = parse_code(code)
    mf = extract_features(tree, source_code=code)
    cg = analyze_context(mf, tree, code)
    ir_module = build_ir(mf, cg)
    cfgs = []
    dfa_results = []
    for ir_func in ir_module.functions:
        cfg = build_cfg(ir_func)
        dfa = run_dfa(cfg, ir_func)
        cfgs.append(cfg)
        dfa_results.append(dfa)
    return ir_module, cfgs, dfa_results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CFG Builder Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCFGBuilder(unittest.TestCase):

    def test_cfg_has_nodes(self):
        _, cfgs, _ = _build_all(SIMPLE_CODE)
        cfg = cfgs[0]
        self.assertGreater(len(cfg.nodes), 0)

    def test_cfg_has_entry_label(self):
        _, cfgs, _ = _build_all(SIMPLE_CODE)
        cfg = cfgs[0]
        self.assertNotEqual(cfg.entry, "")
        self.assertIn(cfg.entry, cfg.nodes)

    def test_cfg_entry_is_entry_block(self):
        _, cfgs, _ = _build_all(SIMPLE_CODE)
        cfg = cfgs[0]
        self.assertEqual(cfg.entry, "entry")

    def test_cfg_has_exit_nodes(self):
        _, cfgs, _ = _build_all(SIMPLE_CODE)
        cfg = cfgs[0]
        self.assertGreater(len(cfg.exits), 0)

    def test_cfg_exit_contains_return(self):
        _, cfgs, _ = _build_all(SIMPLE_CODE)
        cfg = cfgs[0]
        exit_label = cfg.exits[0]
        exit_node = cfg.nodes[exit_label]
        has_return = any(i.op == IROpcode.RETURN for i in exit_node.instructions)
        self.assertTrue(has_return)

    def test_complex_cfg_has_multiple_nodes(self):
        _, cfgs, _ = _build_all(COMPLEX_CODE)
        cfg = cfgs[0]
        self.assertGreater(len(cfg.nodes), 3)

    def test_successor_predecessor_consistency(self):
        _, cfgs, _ = _build_all(COMPLEX_CODE)
        cfg = cfgs[0]
        for label, node in cfg.nodes.items():
            for succ_label in node.successors:
                if succ_label in cfg.nodes:
                    self.assertIn(label, cfg.nodes[succ_label].predecessors)

    def test_topological_order_starts_at_entry(self):
        _, cfgs, _ = _build_all(SIMPLE_CODE)
        cfg = cfgs[0]
        order = cfg.topological_order()
        self.assertEqual(order[0], cfg.entry)

    def test_node_count_matches_ir_blocks(self):
        ir_module, cfgs, _ = _build_all(SIMPLE_CODE)
        self.assertEqual(len(cfgs[0].nodes), len(ir_module.functions[0].blocks))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DFA Engine Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDFAEngine(unittest.TestCase):

    def test_dfa_result_has_function_name(self):
        _, _, dfas = _build_all(SIMPLE_CODE)
        self.assertEqual(dfas[0].function_name, "add")

    def test_reaching_defs_populated(self):
        _, _, dfas = _build_all(SIMPLE_CODE)
        dfa = dfas[0]
        self.assertIsInstance(dfa.reaching_defs, dict)
        self.assertGreater(len(dfa.reaching_defs), 0)

    def test_live_vars_populated(self):
        _, _, dfas = _build_all(SIMPLE_CODE)
        dfa = dfas[0]
        self.assertIsInstance(dfa.live_vars, dict)
        self.assertGreater(len(dfa.live_vars), 0)

    def test_reaching_defs_are_sets(self):
        _, _, dfas = _build_all(SIMPLE_CODE)
        dfa = dfas[0]
        for label, s in dfa.reaching_defs.items():
            self.assertIsInstance(s, set, f"Expected set for block {label!r}")

    def test_live_vars_are_sets(self):
        _, _, dfas = _build_all(SIMPLE_CODE)
        dfa = dfas[0]
        for label, s in dfa.live_vars.items():
            self.assertIsInstance(s, set, f"Expected set for block {label!r}")

    def test_unused_vars_is_list(self):
        _, _, dfas = _build_all(SIMPLE_CODE)
        dfa = dfas[0]
        self.assertIsInstance(dfa.unused_vars, list)

    def test_complex_function_dfa_runs(self):
        """DFA should complete without error on a complex function."""
        _, cfgs, dfas = _build_all(COMPLEX_CODE)
        dfa = dfas[0]
        self.assertEqual(dfa.function_name, "binary_search")
        self.assertIsInstance(dfa.reaching_defs, dict)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Pattern Detector Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPatternDetector(unittest.TestCase):

    def test_report_is_analysis_report(self):
        ir_module, _, dfas = _build_all(SIMPLE_CODE)
        report = detect_patterns(ir_module, dfas)
        self.assertIsInstance(report, AnalysisReport)

    def test_report_source_file(self):
        ir_module, _, dfas = _build_all(SIMPLE_CODE)
        report = detect_patterns(ir_module, dfas)
        # source_file defaults to "" when no filepath given
        self.assertIsInstance(report.source_file, str)

    def test_findings_is_list(self):
        ir_module, _, dfas = _build_all(SIMPLE_CODE)
        report = detect_patterns(ir_module, dfas)
        self.assertIsInstance(report.findings, list)

    def test_summary_is_dict(self):
        ir_module, _, dfas = _build_all(SIMPLE_CODE)
        report = detect_patterns(ir_module, dfas)
        self.assertIsInstance(report.summary, dict)

    def test_complex_code_has_no_spurious_findings(self):
        """
        binary_search has no dead code, unused variables or unused parameters.

        This test used to assert *at least one* finding: the old count-based IR
        produced unused temporaries (P001) and condition blocks without
        predecessors (P003) for every function.  With IR lowered from the real
        AST those artefacts are gone (intentional behaviour change).
        """
        ir_module, _, dfas = _build_all(COMPLEX_CODE)
        report = detect_patterns(ir_module, dfas)
        self.assertEqual(report.findings, [])

    def test_real_smells_are_detected(self):
        code = (
            "def f(a, unused) -> int:\n"
            "    tmp = 1\n"
            "    if a:\n"
            "        return 2\n"
            "    print(a)\n"
        )
        ir_module, _, dfas = _build_all(code)
        ids = {f.pattern_id for f in detect_patterns(ir_module, dfas).findings}
        self.assertIn("P001", ids)   # tmp never read
        self.assertIn("P004", ids)   # falls off the end of an int function
        self.assertIn("P007", ids)   # 'unused' never read

    def test_findings_have_required_fields(self):
        ir_module, _, dfas = _build_all(COMPLEX_CODE)
        report = detect_patterns(ir_module, dfas)
        for f in report.findings:
            self.assertIn(f.severity, ("info", "warning", "error"))
            self.assertTrue(f.pattern_id.startswith("P"))
            self.assertIsInstance(f.function_name, str)
            self.assertIsInstance(f.message, str)

    def test_findings_sorted_by_function_and_lineno(self):
        ir_module, _, dfas = _build_all(COMPLEX_CODE)
        report = detect_patterns(ir_module, dfas)
        keys = [(f.function_name, f.lineno) for f in report.findings]
        self.assertEqual(keys, sorted(keys))

    def test_detect_patterns_without_dfa(self):
        """detect_patterns should work without DFA results (skips P001)."""
        ir_module, _, _ = _build_all(COMPLEX_CODE)
        report = detect_patterns(ir_module, dfa_results=None)
        self.assertIsInstance(report, AnalysisReport)

    def test_findings_for_helper(self):
        ir_module, _, dfas = _build_all(COMPLEX_CODE)
        report = detect_patterns(ir_module, dfas)
        func_findings = report.findings_for("binary_search")
        for f in func_findings:
            self.assertEqual(f.function_name, "binary_search")


if __name__ == "__main__":
    unittest.main(verbosity=2)
