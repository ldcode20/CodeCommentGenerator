"""
Pipeline for Java, C and C++ files.

Runs parse → extract → analyze → generate → attach with the tree-sitter front
end and returns the same ``PipelineResult`` shape as the Python pipeline. The
Python-only stages (IR, pattern analysis, security) return empty results with a
note, so every caller (CLI, GUI, tests) can treat both paths alike.
"""
from __future__ import annotations

from typing import Dict, List

from ..analysis.pattern_detector import AnalysisReport
from ..comment_attacher import AttachResult
from ..comment_generator import CommentItem
from ..ir.ir_nodes import IRModule
from ..security_analyzer import SecurityReport
from . import language_name
from .doc_render import generate_foreign_comments
from .treesitter_extract import analyze_source

PYTHON_ONLY_NOTE = "{lang} files get comments and code insights; IR, pattern analysis and security scanning are Python-only."


def attach_foreign(source_code: str, comments: List[CommentItem]) -> AttachResult:
    """Insert block comments above their declarations, copying each line's own indentation (tabs included)."""
    lines = source_code.splitlines()
    insertions: Dict[int, List[str]] = {}
    diff_log: List[str] = []
    for item in comments:
        idx = max(0, min(item.lineno - 1, len(lines)))
        target = lines[idx] if idx < len(lines) else ""
        indent = target[: len(target) - len(target.lstrip())]
        new_lines = [indent + text if text else indent.rstrip() for text in item.text.splitlines()]
        if idx not in insertions and idx > 0:
            prev = lines[idx - 1].strip()
            # Keep declarations visually separate: blank line unless the previous
            # line opens a block, is an access label, or is already blank.
            if prev and not prev.endswith(("{", ":")) and not prev.startswith("#"):
                new_lines.insert(0, "")
        insertions.setdefault(idx, []).extend(new_lines)
        diff_log.append(f"  + [{item.kind}] {item.node_type} '{item.target_name}' (before original line {idx + 1}):")
        diff_log.extend(f"      {nl}" for nl in new_lines)

    out: List[str] = []
    line_map: Dict[int, int] = {}
    for i, line in enumerate(lines):
        out.extend(insertions.get(i, []))
        out.append(line)
        line_map[len(out)] = i + 1
    out.extend(insertions.get(len(lines), []))
    text = "\n".join(out)
    if source_code.endswith("\n"):
        text += "\n"
    return AttachResult(annotated_source=text, diff_log=diff_log, comments_attached=len(comments),
                        line_map=line_map)


def run_foreign_pipeline(filepath: str, source_code: str, language: str, logger, engine: str = "rule_based"):
    from ..main import PipelineResult   # local import: main imports this module

    lang = language_name(language)
    logger.begin_stage("parse")
    analysis = analyze_source(source_code, language, filepath)
    logger.end_stage(summary={"total_lines": len(source_code.splitlines()), "file": filepath, "language": lang},
                     warnings=analysis.syntax_warnings)

    logger.begin_stage("validate")
    logger.end_stage(summary={"issues_found": len(analysis.syntax_warnings)}, warnings=analysis.syntax_warnings)

    mf, cg = analysis.module_features, analysis.context_graph
    logger.begin_stage("extract")
    logger.end_stage(summary={"functions": len(mf.functions), "classes": len(mf.classes), "imports": len(mf.imports)})

    logger.begin_stage("analyze")
    dist: Dict[str, int] = {}
    for fc in cg.function_contexts:
        dist[fc.complexity_label] = dist.get(fc.complexity_label, 0) + 1
    logger.end_stage(summary={"function_contexts": len(cg.function_contexts), "complexity_distribution": dist})

    logger.begin_stage("generate")
    warnings = []
    if engine != "rule_based":
        warnings.append(f"The ML model was trained on Python docstrings; {lang} comments use the rule-based engine.")
    comments = generate_foreign_comments(analysis)
    counts: Dict[str, int] = {}
    for c in comments:
        counts[c.kind] = counts.get(c.kind, 0) + 1
    logger.end_stage(summary={"total_comments": len(comments), "by_kind": counts, "engine": "rule_based",
                              "style": "javadoc" if language == "java" else "doxygen"}, warnings=warnings)
    logger.set_comments_generated(len(comments))

    logger.begin_stage("attach")
    attach_result = attach_foreign(source_code, comments)
    logger.end_stage(summary={"comments_attached": attach_result.comments_attached})

    note = PYTHON_ONLY_NOTE.format(lang=lang)
    for stage in ("build_ir", "analysis", "security"):
        logger.begin_stage(stage)
        logger.end_stage(summary={"skipped": note})

    return PipelineResult(
        attach_result.annotated_source, comments, mf, cg, attach_result,
        IRModule(source_file=filepath), AnalysisReport(source_file=filepath),
        SecurityReport(), language,
    )
