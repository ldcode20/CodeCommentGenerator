"""
IR / CFG / DFA semantics tests
===============================
Regression tests for the AST-based lowering that replaced the count-based IR
builder, and for the data-flow analyses that now run on real definitions.
"""
import ast
import unittest

from src.analysis.cfg_builder import build_cfg
from src.analysis.dfa_engine import run_dfa
from src.analysis.pattern_detector import detect_patterns
from src.ast_extractor import extract_features
from src.context_analyzer import analyze_context
from src.ir.ir_builder import build_ir
from src.ir.ir_nodes import IRModule, IROpcode
from src.ir.lowering import lower_module


def lower(code: str) -> IRModule:
    return lower_module(ast.parse(code), code, "t.py")


def fn(code: str, name: str):
    m = lower(code)
    f = m.get_function(name)
    assert f is not None, name
    return f


def instrs(f, op):
    return [i for i in f.all_instructions() if i.op == op]


class TestLowering(unittest.TestCase):

    def test_assignments_are_real_statements(self):
        f = fn("def f(a):\n    x = a + 1\n    y = x\n    return y\n", "f")
        assigned = {i.result for i in instrs(f, IROpcode.ASSIGN)}
        self.assertTrue({"x", "y", "__return__"} <= assigned)
        binop = instrs(f, IROpcode.BINOP)[0]
        self.assertIn("a", binop.operands)       # t = BINOP(a, <const 1>)
        self.assertEqual(binop.lineno, 2)
        x_def = next(i for i in instrs(f, IROpcode.ASSIGN) if i.result == "x")
        self.assertEqual(x_def.operands, [binop.result])
        y_def = next(i for i in instrs(f, IROpcode.ASSIGN) if i.result == "y")
        self.assertEqual((y_def.operands, y_def.lineno), (["x"], 3))

    def test_no_placeholder_operands(self):
        f = fn("def f(a):\n    while a:\n        if a > 1:\n            a -= 1\n", "f")
        for i in f.all_instructions():
            for o in i.operands:
                self.assertFalse(o.startswith("__cond") or o in ("__iter__", "__end__"), o)

    def test_call_info_resolves_import_aliases(self):
        code = "import subprocess as sp\nfrom os import system as run\n" \
               "def f(x):\n    sp.run(x, shell=True)\n    run(x)\n"
        calls = instrs(fn(code, "f"), IROpcode.CALL)
        self.assertEqual(calls[0].call.callee, "subprocess.run")
        self.assertEqual(calls[0].call.const_kwargs.get("shell"), "True")
        self.assertEqual(calls[1].call.callee, "os.system")
        self.assertEqual((calls[0].lineno, calls[0].col), (4, 4))

    def test_method_call_has_receiver(self):
        call = instrs(fn("def f(cur, q):\n    cur.execute(q)\n", "f"), IROpcode.CALL)[0]
        self.assertEqual(call.call.receiver, "cur")
        self.assertEqual(call.call.method, "execute")
        self.assertEqual(call.call.args, ["q"])

    def test_nested_functions_and_methods_get_qualnames(self):
        code = ("class A:\n    def run(self):\n        pass\n"
                "class B:\n    def run(self):\n        pass\n"
                "def outer(x):\n    def inner():\n        return x\n    return inner\n")
        names = {f.qualname for f in lower(code).functions}
        self.assertTrue({"A.run", "B.run", "outer", "outer.inner"} <= names)
        inner = lower(code).get_function("outer.inner")
        self.assertIn("x", inner.free_vars)
        mk = instrs(lower(code).get_function("outer"), IROpcode.MAKEFUNC)[0]
        self.assertEqual(mk.operands, ["x"])     # closure capture recorded

    def test_unsupported_constructs_are_reported(self):
        f = fn("def f(xs):\n    return sorted(xs, key=lambda v: -v)\n", "f")
        self.assertTrue(any("lambda" in n for n in f.unsupported))

    def test_build_ir_keeps_one_function_per_feature(self):
        code = "class A:\n    def run(self):\n        return 1\n" \
               "class B:\n    def run(self):\n        return 2\n"
        tree = ast.parse(code)
        mf = extract_features(tree, code)
        ir = build_ir(mf, analyze_context(mf, tree, code, include_security=False))
        self.assertEqual([f.qualname for f in ir.functions], ["A.run", "B.run"])


class TestCFGShape(unittest.TestCase):

    def test_if_else_join_and_predecessors(self):
        f = fn("def f(c):\n    if c:\n        x = 1\n    else:\n        x = 2\n    return x\n", "f")
        cfg = build_cfg(f)
        self.assertEqual(cfg.nodes["branch_0_true"].predecessors, ["entry"])
        self.assertEqual(cfg.nodes["branch_0_false"].predecessors, ["entry"])
        self.assertEqual(sorted(cfg.nodes["branch_0_join"].predecessors),
                         ["branch_0_false", "branch_0_true"])

    def test_every_branch_block_is_reachable(self):
        """Regression: the old builder linked blocks before appending them."""
        f = fn("def f(a):\n    if a:\n        a = 1\n    if a:\n        a = 2\n    return a\n", "f")
        cfg = build_cfg(f)
        reach = cfg.reachable()
        for label in cfg.nodes:
            if label.startswith("branch_"):
                self.assertIn(label, reach)

    def test_loop_back_edge_break_and_continue(self):
        code = ("def f(xs):\n    for x in xs:\n        if x:\n            continue\n"
                "        if x > 3:\n            break\n    return 0\n")
        cfg = build_cfg(fn(code, "f"))
        header = cfg.nodes["loop_0_header"]
        self.assertIn("loop_0_body", header.successors)
        self.assertIn("loop_0_after", header.successors)
        self.assertIn("branch_0_true", header.predecessors)        # continue
        self.assertIn("branch_1_true", cfg.nodes["loop_0_after"].predecessors)  # break

    def test_early_return_and_unreachable_code(self):
        f = fn("def f(a):\n    return a\n    print('dead')\n", "f")
        cfg = build_cfg(f)
        self.assertIn("entry", cfg.nodes["exit"].predecessors)
        dead = [b for b in f.blocks if b.label.startswith("dead_")]
        self.assertTrue(dead)
        self.assertNotIn(dead[0].label, cfg.reachable())
        report = detect_patterns(IRModule(functions=[f]))
        p003 = [x for x in report.findings if x.pattern_id == "P003"]
        self.assertEqual([x.lineno for x in p003], [3])

    def test_infinite_loop_after_block_unreachable(self):
        f = fn("def f():\n    while True:\n        pass\n    return 1\n", "f")
        self.assertNotIn("loop_0_after", build_cfg(f).reachable())

    def test_try_body_blocks_reach_handler(self):
        code = "def f(p):\n    try:\n        x = open(p)\n    except OSError:\n        x = None\n    return x\n"
        cfg = build_cfg(fn(code, "f"))
        self.assertIn("try_0_body", cfg.nodes["try_0_except_0"].predecessors)

    def test_noreturn_call_terminates_path(self):
        code = "import sys\ndef f(a):\n    if not a:\n        sys.exit(1)\n    return a\n"
        cfg = build_cfg(fn(code, "f"))
        self.assertIn("exit", cfg.nodes["branch_0_true"].successors)
        self.assertNotIn("branch_0_join", cfg.nodes["branch_0_true"].successors)


class TestDataFlow(unittest.TestCase):

    def _dfa(self, code, name="f"):
        f = fn(code, name)
        cfg = build_cfg(f)
        return f, cfg, run_dfa(cfg, f)

    def test_reaching_definitions_merge_at_join(self):
        f, cfg, dfa = self._dfa("def f(c):\n    x = 1\n    if c:\n        x = 2\n    return x\n")
        x_defs = {d for d in dfa.reaching_defs["branch_0_join"] if d.startswith("x@")}
        self.assertEqual(len(x_defs), 2)

    def test_redefinition_kills(self):
        f, cfg, dfa = self._dfa("def f():\n    x = 1\n    x = 2\n    return x\n")
        # the exit block is reached only by the second definition of x
        x_defs = {d for d in dfa.reaching_defs["exit"] if d.startswith("x@")}
        self.assertEqual(len(x_defs), 1)
        self.assertIn(("x", 2), dfa.dead_stores)

    def test_liveness_in_loop(self):
        f, cfg, dfa = self._dfa("def f(n):\n    total = 0\n    while n:\n        total += n\n"
                                "        n -= 1\n    return total\n")
        self.assertIn("total", dfa.live_vars["loop_0_header"])
        self.assertIn("n", dfa.live_vars["loop_0_header"])

    def test_possibly_unbound(self):
        f, cfg, dfa = self._dfa("def f(c):\n    if c:\n        y = 1\n    return y\n")
        self.assertEqual(dfa.used_before_assigned, ["y"])
        f, cfg, dfa = self._dfa("def f(c):\n    y = 0\n    if c:\n        y = 1\n    return y\n")
        self.assertEqual(dfa.used_before_assigned, [])

    def test_converges_and_is_deterministic(self):
        code = ("def f(m):\n    for i in m:\n        for j in i:\n            while j:\n"
                "                j -= 1\n                if j == 3:\n                    break\n    return m\n")
        a = self._dfa(code)[2]
        b = self._dfa(code)[2]
        self.assertTrue(a.converged)
        self.assertEqual(a.reaching_defs.keys(), b.reaching_defs.keys())
        self.assertEqual({k: len(v) for k, v in a.reaching_defs.items()},
                         {k: len(v) for k, v in b.reaching_defs.items()})
        self.assertEqual(a.live_vars, b.live_vars)


class TestPatternRegressions(unittest.TestCase):

    def _ids(self, code):
        m = lower(code)
        dfas = [run_dfa(build_cfg(f), f) for f in m.functions]
        return detect_patterns(m, dfas).findings

    def test_p007_reports_unread_parameter(self):
        """Regression: P007 could never fire (every parameter got a LOAD)."""
        findings = self._ids("def f(a, b):\n    x = a * 2\n    return x\n")
        p007 = [f for f in findings if f.pattern_id == "P007"]
        self.assertEqual(len(p007), 1)
        self.assertIn("'b'", p007[0].message)

    def test_p007_ignores_self_stubs_and_abstract(self):
        code = ("import abc\nclass A:\n    def m(self, x):\n        return x\n"
                "    def stub(self, y):\n        pass\n"
                "    @abc.abstractmethod\n    def ab(self, z):\n        raise NotImplementedError\n")
        self.assertFalse([f for f in self._ids(code) if f.pattern_id == "P007"])

    def test_p007_sees_reads_in_doubly_nested_closures(self):
        """Regression: decorator factories read their parameter two scopes down."""
        code = ("def retry(max_attempts):\n    def decorator(func):\n        def wrapper(*a):\n"
                "            for _ in range(max_attempts):\n                return func(*a)\n"
                "        return wrapper\n    return decorator\n")
        self.assertFalse([f for f in self._ids(code) if f.pattern_id == "P007"])
        m = lower(code)
        self.assertIn("max_attempts", m.get_function("retry.decorator").free_vars)

    def test_p001_ignores_unused_loop_targets(self):
        code = "def f(n):\n    out = []\n    for i in range(n):\n        out.append(0)\n    return out\n"
        self.assertFalse([f for f in self._ids(code) if f.pattern_id == "P001"])

    def test_p001_unused_variable_line(self):
        findings = self._ids("def f(a):\n    a = a\n    unused = 3\n    return a\n")
        p001 = [f for f in findings if f.pattern_id == "P001"]
        self.assertEqual([(f.lineno, "unused" in f.message) for f in p001], [(3, True)])

    def test_p005_uses_real_nesting_depth(self):
        flat = "def f(a):\n    for x in a:\n        pass\n    for y in a:\n        pass\n" \
               "    for z in a:\n        pass\n"
        nested = "def g(a):\n    for x in a:\n        for y in x:\n            for z in y:\n                print(z)\n"
        self.assertFalse([f for f in self._ids(flat) if f.pattern_id == "P005"])
        self.assertTrue([f for f in self._ids(nested) if f.pattern_id == "P005"])

    def test_p004_only_when_none_can_be_returned(self):
        ok = "def f(a) -> int:\n    if a:\n        return 1\n    return 2\n"
        bad = "def f(a) -> int:\n    if a:\n        return 1\n"
        self.assertFalse([f for f in self._ids(ok) if f.pattern_id == "P004"])
        self.assertTrue([f for f in self._ids(bad) if f.pattern_id == "P004"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
