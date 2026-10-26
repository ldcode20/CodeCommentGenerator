"""
Taint engine and finding-schema tests
======================================
Focused positive / negative / edge cases for the interprocedural taint
analysis, sanitiser context handling, confidence derivation, suppression,
deduplication and the legacy SecurityReport adapter.
"""
import os
import textwrap
import unittest

from src.ast_extractor import extract_features
from src.context_analyzer import analyze_context
from src.parser_module import parse_code
from src.security import analyze_source
from src.security_analyzer import run_security_analysis

FLASK = "from flask import request, make_response\nimport sqlite3, os, subprocess, html, shlex\n"


def run(body: str, prefix: str = FLASK):
    return analyze_source(prefix + textwrap.dedent(body), "t.py")


def active(rep, rule=None):
    return [f for f in rep.active() if rule is None or f.rule_id == rule]


class TestDirectFlows(unittest.TestCase):

    def test_direct_flow_with_trace_and_locations(self):
        rep = run("""
            def view():
                q = request.args["q"]
                cur = sqlite3.connect("d").cursor()
                cur.execute("SELECT * FROM t WHERE a = '" + q + "'")
        """)
        [f] = active(rep, "SEC005")
        self.assertEqual(f.status, "confirmed")
        self.assertEqual(f.confidence, "high")
        self.assertEqual(f.cwe, "CWE-89")
        self.assertEqual((f.line, f.source["line"]), (7, 5))
        self.assertEqual(f.sink["name"], "cur.execute")
        self.assertEqual([s["kind"] for s in f.trace], ["source", "assign", "sink"])
        self.assertEqual(f.trace[0]["line"], 5)
        self.assertTrue(f.remediation)
        self.assertTrue(f.fingerprint)

    def test_untainted_value_same_sink_is_safe(self):
        rep = run("""
            def view():
                cur = sqlite3.connect("d").cursor()
                cur.execute("SELECT * FROM t WHERE a = '" + "fixed" + "'")
        """)
        self.assertEqual(active(rep, "SEC005"), [])

    def test_parameterised_query_is_safe(self):
        rep = run("""
            def view():
                q = request.args["q"]
                sqlite3.connect("d").execute("SELECT * FROM t WHERE a = ?", (q,))
        """)
        self.assertEqual(active(rep), [])

    def test_reassignment_kills_taint(self):
        rep = run("""
            def view():
                cmd = "ls " + request.args["d"]
                cmd = "ls /tmp"
                os.system(cmd)
        """)
        self.assertEqual(active(rep, "SEC002"), [])

    def test_branch_merge_is_may_tainted(self):
        rep = run("""
            def view(flag):
                if flag:
                    cmd = "ls " + request.args["d"]
                else:
                    cmd = "ls"
                os.system(cmd)
        """)
        [f] = active(rep, "SEC002")
        self.assertEqual(f.path_conditions, [])   # the sink itself is unconditional

    def test_loop_carried_taint(self):
        rep = run("""
            def view():
                cmd = "echo"
                for part in request.args.getlist("p"):
                    cmd = cmd + " " + part
                os.system(cmd)
        """)
        self.assertEqual(len(active(rep, "SEC002")), 1)

    def test_path_conditions_recorded(self):
        rep = run("""
            def view(debug):
                if debug:
                    os.system(request.args["c"])
        """)
        [f] = active(rep, "SEC002")
        self.assertEqual(f.path_conditions, ["if debug"])


class TestSanitizerContexts(unittest.TestCase):

    def test_html_escape_does_not_protect_sql_or_shell(self):
        rep = run("""
            def view():
                v = html.escape(request.args["v"])
                sqlite3.connect("d").execute("SELECT '" + v + "'")
                os.system("echo " + v)
                return make_response("<p>" + v + "</p>")
        """)
        self.assertEqual({f.rule_id for f in active(rep)}, {"SEC005", "SEC002"})
        sql = active(rep, "SEC005")[0]
        self.assertTrue(any("html.escape" in s for s in sql.sanitizers))

    def test_shlex_quote_only_protects_shell(self):
        rep = run("""
            def view():
                v = shlex.quote(request.args["v"])
                os.system("echo " + v)
                sqlite3.connect("d").execute("SELECT '" + v + "'")
        """)
        self.assertEqual({f.rule_id for f in active(rep)}, {"SEC005"})

    def test_function_named_sanitize_is_not_trusted(self):
        rep = run("""
            def sanitize(value):
                return value.strip()

            def view():
                os.system("echo " + sanitize(request.args["v"]))
        """)
        self.assertEqual(len(active(rep, "SEC002")), 1)

    def test_validation_on_branch_edges(self):
        rep = run("""
            ALLOWED = {"a", "b"}
            def view():
                v = request.args["v"]
                if v not in ALLOWED:
                    return "no"
                os.system("echo " + v)
                w = request.args["w"]
                if w.isdigit():
                    os.system("echo " + w)
                os.system("echo " + w)
        """)
        self.assertEqual([f.line for f in active(rep, "SEC002")], [13])

    def test_path_prefix_check_requires_canonical_path(self):
        base = """
            BASE = "/srv"
            def view():
                p = {expr}
                if not p.startswith(BASE):
                    raise ValueError()
                return open(p).read()
        """
        bad = run(base.format(expr='os.path.join(BASE, request.args["f"])'))
        good = run(base.format(expr='os.path.realpath(os.path.join(BASE, request.args["f"]))'))
        self.assertEqual(len(active(bad, "SEC013")), 1)
        self.assertTrue(any("non-canonicalised" in s for s in active(bad, "SEC013")[0].sanitizers))
        self.assertEqual(active(good, "SEC013"), [])


class TestInterprocedural(unittest.TestCase):

    def test_flow_into_callee_sink_reported_with_call_step(self):
        rep = run("""
            def run_cmd(c):
                subprocess.call(c, shell=True)

            def view():
                run_cmd("ls " + request.args["d"])

            def cron():
                run_cmd("uptime")
        """)
        [f] = active(rep, "SEC002")
        self.assertEqual(f.function, "run_cmd")
        self.assertEqual(f.line, 5)
        kinds = [s["kind"] for s in f.trace]
        self.assertEqual(kinds[0], "source")
        self.assertIn("call", kinds)
        self.assertIn("param", kinds)

    def test_callee_sanitiser_and_return_value(self):
        rep = run("""
            def to_int(v):
                return int(v)

            def passthrough(v):
                return v.strip()

            def view():
                os.system("kill " + str(to_int(request.args["pid"])))
                os.system("echo " + passthrough(request.args["msg"]))
        """)
        self.assertEqual([f.line for f in active(rep, "SEC002")], [12])

    def test_recursion_terminates(self):
        rep = run("""
            def walk(q, n):
                if n:
                    return walk(q + "x", n - 1)
                os.system(q)

            def view():
                walk(request.args["q"], 5)
        """)
        self.assertTrue(rep.converged)
        self.assertEqual(len(active(rep, "SEC002")), 1)

    def test_field_flow_through_constructor(self):
        rep = run("""
            class Job:
                def __init__(self, cmd):
                    self.cmd = cmd
                def go(self):
                    os.system(self.cmd)

            def view():
                Job(request.args["c"]).go()

            def cron():
                Job("uptime").go()
        """)
        [f] = active(rep, "SEC002")
        self.assertEqual(f.source["trust"], "remote")

    def test_closure_capture(self):
        rep = run("""
            def view():
                c = request.args["c"]
                def inner():
                    os.system(c)
                inner()
        """)
        self.assertEqual([f.function for f in active(rep, "SEC002")], ["view.inner"])

    def test_closure_two_levels_deep(self):
        rep = run("""
            def view():
                c = request.args["c"]
                def middle():
                    def inner():
                        os.system(c)
                    inner()
                middle()
        """)
        self.assertEqual([f.function for f in active(rep, "SEC002")], ["view.middle.inner"])


class TestConfidenceAndStatus(unittest.TestCase):

    def test_unknown_call_lowers_confidence(self):
        rep = run("""
            from somelib import transform
            def view():
                os.system(transform(request.args["c"]))
        """)
        [f] = active(rep, "SEC002")
        self.assertEqual((f.status, f.confidence), ("potential", "medium"))
        self.assertTrue(any("unresolved call somelib.transform" in r for r in f.confidence_reasons))

    def test_parameter_origin_is_low_confidence(self):
        rep = run("""
            def wrapper(code):
                return eval(code)
        """)
        [f] = active(rep, "SEC001")
        self.assertEqual((f.status, f.confidence), ("potential", "low"))
        self.assertEqual(f.source["kind"], "param")

    def test_path_parameter_origin_not_reported(self):
        rep = run("""
            def read(path):
                return open(path).read()
        """)
        self.assertEqual(active(rep, "SEC013"), [])

    def test_local_source_lowers_severity(self):
        rep = run("""
            def job():
                os.system(os.environ["CMD"])
        """)
        [f] = active(rep, "SEC002")
        self.assertEqual((f.severity, f.confidence, f.status), ("high", "medium", "potential"))
        self.assertIn("local", f.severity_reason)

    def test_confirmed_iff_high_confidence(self):
        with open(os.path.join(os.path.dirname(__file__), "security_fixtures",
                               "sqli_vulnerable.py"), encoding="utf-8") as fh:
            rep = analyze_source(fh.read(), "sqli_vulnerable.py")
        for f in rep.findings:
            if f.status != "suppressed":
                self.assertEqual(f.status == "confirmed", f.confidence == "high", f.format_text())


class TestSuppressionDedupDeterminism(unittest.TestCase):

    def test_nosec_requires_reason(self):
        rep = run("""
            def a():
                os.system(request.args["x"])  # nosec SEC002: input validated by the WAF
            def b():
                os.system(request.args["x"])  # nosec
            def c():
                os.system(request.args["x"])  # nosec SEC005: wrong rule
        """)
        by_fn = {f.function: f for f in rep.findings if f.rule_id == "SEC002"}
        self.assertEqual(by_fn["a"].status, "suppressed")
        self.assertIn("WAF", by_fn["a"].suppression_reason)
        self.assertNotEqual(by_fn["b"].status, "suppressed")
        self.assertTrue(any("without a justification" in r for r in by_fn["b"].confidence_reasons))
        self.assertNotEqual(by_fn["c"].status, "suppressed")

    def test_distinct_sources_same_sink_not_merged(self):
        rep = run("""
            def view():
                c = request.args["a"] + os.environ["B"]
                os.system(c)
        """)
        found = active(rep, "SEC002")
        self.assertEqual(len(found), 2)
        self.assertEqual({f.source["trust"] for f in found}, {"remote", "local"})

    def test_same_source_two_paths_reported_once(self):
        rep = run("""
            def view(flag):
                c = request.args["a"]
                if flag:
                    c = c.strip()
                os.system(c)
        """)
        self.assertEqual(len(active(rep, "SEC002")), 1)

    def test_repeated_runs_identical(self):
        path = os.path.join(os.path.dirname(__file__), "security_fixtures", "cmdi_vulnerable.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        a = [(f.fingerprint, f.status, f.confidence) for f in analyze_source(src, path).findings]
        b = [(f.fingerprint, f.status, f.confidence) for f in analyze_source(src, path).findings]
        self.assertEqual(a, b)

    def test_malformed_code_reports_parse_error(self):
        rep = analyze_source("def broken(:\n    pass\n", "bad.py")
        self.assertIsNotNone(rep.parse_error)
        self.assertEqual(rep.findings, [])


class TestLegacyIntegration(unittest.TestCase):

    def _features(self, path):
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        tree = parse_code(src)
        mf = extract_features(tree, src, filepath=path)
        return src, tree, mf

    def test_demo_showcase_retains_all_twelve_rules(self):
        path = os.path.join(os.path.dirname(__file__), "inputs", "demo_showcase.py")
        src, tree, mf = self._features(path)
        report = run_security_analysis(mf, analyze_context(mf, tree, src), src)
        ids = {i.pattern_id for i in report.issues}
        self.assertEqual(ids, {f"SEC{n:03d}" for n in range(1, 13)})
        # Every issue points at its own line, not the function's def line.
        defs = {ff.lineno for ff in mf.functions}
        self.assertTrue(all(i.lineno not in defs or i.pattern_id == "SEC007" for i in report.issues))
        self.assertIn("run_user_expression", report.function_scores)
        self.assertLess(report.module_safe_pct, 100.0)

    def test_context_security_issues_from_central_analyzer(self):
        path = os.path.join(os.path.dirname(__file__), "inputs", "test_security.py")
        src, tree, mf = self._features(path)
        on = {fc.name: fc.security_issues for fc in analyze_context(mf, tree, src).function_contexts}
        off = {fc.name: fc.security_issues
               for fc in analyze_context(mf, tree, src, include_security=False).function_contexts}
        self.assertTrue(any("SEC001" in s for s in on["run_unsafe_code"]))
        self.assertTrue(any("SEC003" in s for s in on["run_unsafe_code"]))
        self.assertEqual(on["standard_function"], [])
        self.assertEqual(off["run_unsafe_code"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
