"""
Project-level (cross-file) analysis tests over tests/security_fixtures_project.

Scenarios: (1) source and sink in different modules, (2) several cross-module hops,
(3) sanitiser before an inter-module sink, (4) patched/safe twin, (5) cyclic imports with
recursion, (6) unresolved external dependency, (7) independent vulnerabilities in two
modules, (8) file/line attribution for findings and every trace hop.
"""
import os
import shutil
import tempfile
import unittest

from src.ir.lowering import resolve_relative
from src.security import analyze_file
from src.security.evaluate import load_labels
from src.security.project import analyze_project, discover_modules

ROOT = os.path.join(os.path.dirname(__file__), "security_fixtures_project")


class TestProjectFixture(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rep = analyze_project(ROOT)
        cls.labels = []
        for base, _, files in os.walk(ROOT):
            for f in files:
                if f.endswith(".py"):
                    cls.labels += load_labels(os.path.join(base, f))

    def _site(self, f):
        return (os.path.normcase(os.path.abspath(f.file)), f.line, f.rule_id)

    def test_every_expected_flow_found_and_nothing_else(self):
        expected = {(os.path.normcase(os.path.abspath(l.file)), l.line, l.rule)
                    for l in self.labels if l.kind == "expect"}
        safe = {(os.path.normcase(os.path.abspath(l.file)), l.line, l.rule)
                for l in self.labels if l.kind == "safe"}
        found = {self._site(f) for f in self.rep.active()}
        self.assertEqual(found, expected)
        self.assertFalse(found & safe)
        self.assertGreaterEqual(len(expected), 8)

    def test_cross_module_trace_attribution(self):
        f = next(x for x in self.rep.active() if x.function == "webapp.db.run_sql")
        self.assertEqual(f.status, "confirmed")
        files = [os.path.basename(s["file"]) for s in f.trace]
        self.assertEqual(files[0], "routes.py")             # source hop
        self.assertEqual(files[-1], "db.py")                # sink hop
        self.assertTrue({"service.py", "util.py"} <= set(files))
        self.assertEqual(os.path.basename(f.source["file"]), "routes.py")
        for step in f.trace:                                # every hop points at real code
            with open(step["file"], encoding="utf-8") as fh:
                line = fh.read().splitlines()[step["line"] - 1]
            self.assertTrue(line.strip(), step)

    def test_sanitiser_and_safe_twins_not_reported(self):
        funcs = {f.function for f in self.rep.active()}
        for safe in ("webapp.db.find_user_safe", "webapp.db.count_rows", "webapp.service.archive"):
            self.assertNotIn(safe, funcs)

    def test_cycles_terminate(self):
        self.assertIn(["webapp.cycle_a", "webapp.cycle_b"], self.rep.cycles)
        self.assertTrue(self.rep.converged)
        f = next(x for x in self.rep.active() if x.function == "webapp.cycle_b.pong")
        self.assertEqual(os.path.basename(f.source["file"]), "cycle_a.py")

    def test_unresolved_external_dependency_lowers_confidence(self):
        f = next(x for x in self.rep.active() if x.function == "webapp.external.convert")
        self.assertEqual((f.status, f.confidence), ("potential", "medium"))
        self.assertTrue(any("thirdparty.text.transform" in r for r in f.confidence_reasons))
        self.assertIn("thirdparty", self.rep.external_imports["webapp.external"])

    def test_single_file_mode_unchanged_and_weaker(self):
        """Alone, db.py only sees parameter origins: potential/low, never confirmed."""
        rep = analyze_file(os.path.join(ROOT, "webapp", "db.py"))
        statuses = {(f.function, f.status, f.confidence) for f in rep.active()}
        self.assertIn(("find_user", "potential", "low"), statuses)
        self.assertTrue(all(s != "confirmed" for _, s, _ in statuses))

    def test_deterministic(self):
        again = analyze_project(ROOT)
        self.assertEqual(sorted(f.fingerprint for f in again.findings),
                         sorted(f.fingerprint for f in self.rep.findings))


class TestDiscoveryAndImports(unittest.TestCase):

    def test_relative_import_resolution(self):
        self.assertEqual(resolve_relative("util", 1, "pkg.sub.mod"), "pkg.sub.util")
        self.assertEqual(resolve_relative(None, 1, "pkg.sub.mod"), "pkg.sub")
        self.assertEqual(resolve_relative("x", 2, "pkg.sub.mod"), "pkg.x")
        self.assertEqual(resolve_relative("util", 1, "pkg.sub", is_package=True), "pkg.sub.util")
        self.assertEqual(resolve_relative("abs.mod", 0, "pkg.sub"), "abs.mod")

    def test_environment_directories_skipped(self):
        tmp = tempfile.mkdtemp()
        try:
            for d in ("app", ".venv/lib", "venv", "node_modules/x", "app/__pycache__",
                      "lib/site-packages/dep", ".git"):
                os.makedirs(os.path.join(tmp, d), exist_ok=True)
                open(os.path.join(tmp, d, "m.py"), "w").write("x = 1\n")
            names = {m for _, m, _ in discover_modules(tmp)}
            self.assertEqual(names, {"app.m"})
        finally:
            shutil.rmtree(tmp)

    def test_parse_error_reported_not_hidden(self):
        tmp = tempfile.mkdtemp()
        try:
            open(os.path.join(tmp, "ok.py"), "w").write("import os\nos.system('ls')\n")
            open(os.path.join(tmp, "bad.py"), "w").write("def broken(:\n")
            rep = analyze_project(tmp)
            self.assertIn(os.path.join(os.path.abspath(tmp), "bad.py"), rep.parse_errors)
            self.assertEqual(len(rep.files), 2)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
