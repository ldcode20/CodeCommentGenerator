"""Java, C and C++ support: detection, extraction, comment generation and attachment."""
import os
import shutil
import subprocess
import tempfile

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")
pytest.importorskip("tree_sitter_c")
pytest.importorskip("tree_sitter_cpp")

from src.languages import detect_language, file_dialog_filter, is_supported
from src.languages.doc_render import generate_foreign_comments
from src.languages.pipeline import attach_foreign
from src.languages.treesitter_extract import analyze_source
from src.logger import PipelineLogger
from src.main import run_pipeline

HERE = os.path.dirname(__file__)
SAMPLES = os.path.join(HERE, "inputs", "multilang")


def _sample(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


def _analyze(name):
    path = os.path.join(SAMPLES, name)
    src = _sample(name)
    return analyze_source(src, detect_language(path, src), path)


def _fn(fa, name, owner=None):
    return next(f for f in fa.module_features.functions
                if f.name == name and (owner is None or f.parent_class == owner))


def _cc(fa, ff):
    return next(fc for fc in fa.context_graph.function_contexts if fc.node_id == ff.node_id).cyclomatic_complexity


# ── detection ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path,expected", [
    ("a.py", "python"), ("A.java", "java"), ("x.c", "c"), ("x.cpp", "cpp"),
    ("x.cc", "cpp"), ("x.hpp", "cpp"), ("x.h", "c"), ("README", "python"),
])
def test_detect_language_by_extension(path, expected):
    assert detect_language(path) == expected


def test_header_with_cpp_syntax_is_cpp():
    assert detect_language("w.h", "namespace ui {\nclass Widget {};\n}\n") == "cpp"
    assert detect_language("q.h", "struct node { int v; };\nvoid f(void);\n") == "c"


def test_supported_extensions_and_dialog_filter():
    assert is_supported("Main.java") and is_supported("x.hpp") and not is_supported("x.rs")
    assert "*.java" in file_dialog_filter() and "*.cpp" in file_dialog_filter()


# ── Java ─────────────────────────────────────────────────────────────────────

def test_java_extraction():
    fa = _analyze("Inventory.java")
    names = [c.name for c in fa.module_features.classes]
    assert names == ["Inventory", "Inventory.Listener", "Inventory.Category"]
    assert fa.facts[fa.module_features.classes[1].node_id].kind == "interface"
    ctor = _fn(fa, "Inventory")
    assert fa.facts[ctor.node_id].kind == "constructor" and ctor.return_annotation is None
    assert fa.facts[ctor.node_id].throws == ["IllegalArgumentException"]
    remove = _fn(fa, "removeItem")
    assert [(p.name, p.annotation) for p in remove.params] == [("name", "String"), ("quantity", "int")]
    assert remove.return_annotation == "int" and fa.facts[remove.node_id].throws == ["IOException"]
    # for + if + && + else-if + || = 5 decisions
    assert _cc(fa, _fn(fa, "findLowStock")) == 6
    assert _fn(fa, "addItem").has_docstring                     # existing /** */ is respected
    assert fa.facts[_fn(fa, "onChange").node_id].is_declaration_only


def test_java_comments_are_javadoc():
    fa = _analyze("Inventory.java")
    items = generate_foreign_comments(fa)
    by_name = {i.target_name: i for i in items if i.kind == "block"}
    assert "addItem" not in by_name
    remove = by_name["removeItem"].text
    assert remove.startswith("/**") and remove.endswith("*/")
    assert "@param name" in remove and "@return" in remove and "@throws IOException" in remove
    assert "Works with: {@code List<String>}" in by_name["findLowStock"].text      # generics inside {@code}
    assert "@return" not in by_name["Inventory"].text if "Inventory" in by_name else True
    assert "Checks whether it is valid name." in by_name["isValidName"].text


# ── C ────────────────────────────────────────────────────────────────────────

def test_c_extraction():
    fa = _analyze("matrix.c")
    assert [c.name for c in fa.module_features.classes] == ["Matrix"]            # typedef struct name
    names = [f.name for f in fa.module_features.functions]
    assert names.count("count_nonzero") == 1                                      # prototype + definition -> one
    create = _fn(fa, "matrix_create")
    assert create.return_annotation == "Matrix*"
    assert _fn(fa, "main").params == []                                           # (void)
    assert _fn(fa, "matrix_free").has_docstring                                   # // comment directly above
    assert _cc(fa, _fn(fa, "count_nonzero")) == 4                                 # 2 loops + 1 case


def test_c_header_prototypes_documented():
    fa = _analyze("queue.h")
    assert {f.name for f in fa.module_features.functions} == {"queue_init", "queue_push", "queue_pop", "queue_size"}
    assert all(fa.facts[f.node_id].is_declaration_only for f in fa.module_features.functions)
    text = {i.target_name: i.text for i in generate_foreign_comments(fa)}
    assert "@param[out] out_value" in text["queue_pop"]
    assert "@brief Returns the queue size." in text["queue_size"]


# ── C++ ──────────────────────────────────────────────────────────────────────

def test_cpp_extraction():
    fa = _analyze("shapes.cpp")
    circle = next(c for c in fa.module_features.classes if c.name == "Circle")
    assert circle.bases == ["Shape"]
    dtor = _fn(fa, "~Shape")
    assert fa.facts[dtor.node_id].kind == "destructor"
    ctor = _fn(fa, "Circle", owner="Circle")
    assert fa.facts[ctor.node_id].throws == ["std::invalid_argument"]
    clamp = _fn(fa, "clamp_value")
    src_lines = _sample("shapes.cpp").splitlines()
    insert = fa.facts[clamp.node_id].insert_line                                  # above template<...>
    assert src_lines[insert - 1].startswith("template") and src_lines[insert].startswith("T clamp_value")
    assert clamp.params[2].default == "T(100)"
    assert fa.facts[_fn(fa, "area", owner="Shape").node_id].is_declaration_only   # pure virtual


# ── pipeline and attachment ──────────────────────────────────────────────────

@pytest.mark.parametrize("name,lang,marker", [
    ("Inventory.java", "java", "/**"), ("matrix.c", "c", "@brief"),
    ("shapes.cpp", "cpp", "@brief"), ("queue.h", "c", "@brief"),
])
def test_run_pipeline_and_idempotence(name, lang, marker):
    path = os.path.join(SAMPLES, name)
    result = run_pipeline(path, PipelineLogger(input_file=path))
    assert result.language == lang
    assert marker in result.annotated_source
    assert result.ir_module.functions == [] and result.security_report.total_issues == 0
    original = _sample(name)
    # Every original line survives, in order, and the line map points back to it.
    out_lines = result.annotated_source.splitlines()
    for annotated_no, original_no in result.attach_result.line_map.items():
        assert out_lines[annotated_no - 1] == original.splitlines()[original_no - 1]
    # A second run over the annotated file adds no new doc comments.
    with tempfile.TemporaryDirectory() as tmp:
        again = os.path.join(tmp, name)
        with open(again, "w", encoding="utf-8") as fh:
            fh.write(result.annotated_source)
        second = run_pipeline(again, PipelineLogger(input_file=again))
    assert [c for c in second.comments if c.kind == "block"] == []


def test_attach_preserves_tab_indentation():
    src = "struct s {\n\tint x;\n};\n\nint f(int a)\n{\n\treturn a;\n}\n"
    fa = analyze_source(src, "c", "t.c")
    out = attach_foreign(src, generate_foreign_comments(fa)).annotated_source
    assert "\tint x;" in out and out.endswith("}\n")
    assert out.index("@brief Represents") < out.index("struct s {")


def test_python_path_unchanged():
    path = os.path.join(HERE, "..", "docs", "screenshots", "sample_input.py")
    result = run_pipeline(path, PipelineLogger(input_file=path))
    assert result.language == "python" and result.ir_module.functions


def test_syntax_error_is_a_warning_not_a_crash():
    fa = analyze_source("int f(int a {\n  return a;\n}\nint g(void) { return 1; }\n", "c", "bad.c")
    assert fa.syntax_warnings and "syntax error" in fa.syntax_warnings[0]


# ── the annotated files still compile ────────────────────────────────────────

def _compile(cmd, cwd):
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not installed")
def test_annotated_c_compiles(tmp_path):
    for name in ("matrix.c", "queue.h"):
        path = os.path.join(SAMPLES, name)
        (tmp_path / name).write_text(run_pipeline(path, PipelineLogger(input_file=path)).annotated_source)
    (tmp_path / "use_queue.c").write_text('#include "queue.h"\nint main(void){Queue q; queue_init(&q); return 0;}\n')
    _compile(["gcc", "-std=c11", "-fsyntax-only", "matrix.c"], tmp_path)
    _compile(["gcc", "-std=c11", "-fsyntax-only", "use_queue.c"], tmp_path)


@pytest.mark.skipif(shutil.which("g++") is None, reason="g++ not installed")
def test_annotated_cpp_compiles(tmp_path):
    path = os.path.join(SAMPLES, "shapes.cpp")
    (tmp_path / "shapes.cpp").write_text(run_pipeline(path, PipelineLogger(input_file=path)).annotated_source)
    _compile(["g++", "-std=c++17", "-D_USE_MATH_DEFINES", "-fsyntax-only", "shapes.cpp"], tmp_path)


@pytest.mark.skipif(shutil.which("javac") is None, reason="javac not installed")
def test_annotated_java_compiles(tmp_path):
    path = os.path.join(SAMPLES, "Inventory.java")
    (tmp_path / "shop").mkdir()
    (tmp_path / "shop" / "Inventory.java").write_text(run_pipeline(path, PipelineLogger(input_file=path)).annotated_source)
    _compile(["javac", "-d", "classes", os.path.join("shop", "Inventory.java")], tmp_path)
