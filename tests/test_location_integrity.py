"""
Source location integrity
==========================
Security findings must refer to the code the developer wrote, before and
after comment generation, and comment generation must not change behaviour
or overwrite the input file.
"""
import ast
import hashlib
import os
import shutil
import tempfile
import textwrap
import unittest

from src.ast_extractor import extract_features
from src.comment_attacher import attach_comments
from src.comment_generator import generate_comments
from src.context_analyzer import analyze_context
from src.logger import PipelineLogger
from src.main import run_pipeline
from src.parser_module import parse_code
from src.security import analyze_source

HERE = os.path.dirname(__file__)
FIXTURES = os.path.join(HERE, "security_fixtures")


def annotate(src: str):
    tree = parse_code(src)
    mf = extract_features(tree, src)
    cg = analyze_context(mf, tree, src)
    return attach_comments(src, generate_comments(mf, cg, source_code=src))


def strip_docstrings(tree: ast.AST) -> str:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    return ast.dump(tree, include_attributes=False)


class TestFindingsMapToOriginalLines(unittest.TestCase):

    def _check(self, name):
        with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
            src = fh.read()
        original = {(f.rule_id, f.line) for f in analyze_source(src, name).active()}
        result = annotate(src)
        self.assertGreater(len(result.annotated_source.splitlines()), len(src.splitlines()))
        after = analyze_source(result.annotated_source, name)
        mapped = set()
        for f in after.active():
            line = result.to_original_line(f.line)
            self.assertIsNotNone(line, f"finding on an inserted comment line: {f.format_text()}")
            mapped.add((f.rule_id, line))
        self.assertEqual(mapped, original)

    def test_sqli_fixture(self):
        self._check("sqli_vulnerable.py")

    def test_cmdi_fixture(self):
        self._check("cmdi_vulnerable.py")

    def test_patterns_fixture(self):
        self._check("patterns_mixed.py")


class TestDocumentationPreservesBehaviour(unittest.TestCase):

    def test_ast_unchanged_except_docstrings(self):
        for path in [os.path.join(HERE, "inputs", "demo_showcase.py"),
                     os.path.join(HERE, "inputs", "complex_sample.py"),
                     os.path.join(FIXTURES, "xss_vulnerable.py")]:
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            annotated = annotate(src).annotated_source
            self.assertEqual(strip_docstrings(ast.parse(annotated)), strip_docstrings(ast.parse(src)),
                             path)

    def test_multiline_signature_regression(self):
        """Docstrings used to be inserted inside multi-line parameter lists."""
        src = textwrap.dedent("""\
            def connect(host,
                        port,
                        timeout=5):
                return (host, port, timeout)
        """)
        out = annotate(src)
        tree = ast.parse(out.annotated_source)          # must still be valid Python
        fn = tree.body[0]
        self.assertIsInstance(fn.body[0].value, ast.Constant)
        self.assertEqual([a.arg for a in fn.args.args], ["host", "port", "timeout"])

    def test_one_line_body_is_not_modified(self):
        src = "def ident(x): return x\n"
        out = annotate(src)
        self.assertEqual(out.annotated_source.strip(), src.strip())
        self.assertEqual(out.skipped, 1)


class TestPipelineUsesOriginalSource(unittest.TestCase):

    def test_pipeline_findings_and_input_file_untouched(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "app.py")
            shutil.copy(os.path.join(FIXTURES, "cmdi_vulnerable.py"), path)
            with open(path, "rb") as fh:
                before = hashlib.sha256(fh.read()).hexdigest()
            result = run_pipeline(path, PipelineLogger(input_file=path))
            annotated, security_report = result[0], result[7]
            with open(path, "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), before)
            with open(path, encoding="utf-8") as fh:
                original_lines = fh.read().splitlines()
            self.assertNotEqual(len(annotated.splitlines()), len(original_lines))
            for issue in security_report.issues:
                # Every reported line is a line of the *original* file, e.g. the sink call.
                if issue.pattern_id == "SEC002":
                    self.assertTrue(
                        any(k in original_lines[issue.lineno - 1]
                            for k in ("os.", "subprocess", "sp.", "run_shell", "getattr")),
                        (issue.lineno, original_lines[issue.lineno - 1]))
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
