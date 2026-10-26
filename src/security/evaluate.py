"""
Security evaluation
====================
Reproducible precision/recall evaluation over the labelled fixtures in
``tests/security_fixtures`` (see the README there for the label syntax and the
evaluation unit).

    python -m src.security.evaluate                      # new analyzer
    python -m src.security.evaluate --confirmed-only     # count only confirmed findings
    python -m src.security.evaluate --granularity function
    python -m src.security.evaluate --baseline PATH/TO/old_security_analyzer.py
    python -m src.security.evaluate --json outputs/security_eval.json

Definitions (per class and overall):
    Precision = TP / (TP + FP)        Recall = TP / (TP + FN)
    F1        = 2·P·R / (P + R)       FPR    = FP / (FP + TN)
A metric whose denominator is zero is reported as ``undefined`` — never as 1.0.
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import re
import sys
import time
import tracemalloc
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .rules import RULES

LABEL_RE = re.compile(
    r"#\s*(?P<kind>expect-suppressed|expect|safe):\s*(?P<rules>SEC\d{3}(?:\s*,\s*SEC\d{3})*)"
    r"(?P<lim>\s*\(known limitation\))?"
)
DEFAULT_FIXTURES = os.path.join(os.path.dirname(__file__), "..", "..", "tests", "security_fixtures")


@dataclass(frozen=True)
class Label:
    file: str
    line: int
    rule: str
    kind: str            # expect | safe | expect-suppressed
    limitation: bool = False


@dataclass(frozen=True)
class Reported:
    file: str
    line: int
    rule: str
    status: str
    function: str = ""
    message: str = ""


def rule_class(rule_id: str) -> str:
    meta = RULES.get(rule_id)
    return meta.category if meta else rule_id


def load_labels(path: str) -> List[Label]:
    labels = []
    with open(path, encoding="utf-8") as fh:
        for lineno, text in enumerate(fh, start=1):
            for m in LABEL_RE.finditer(text):
                for rule in re.findall(r"SEC\d{3}", m.group("rules")):
                    labels.append(Label(path, lineno, rule, m.group("kind"), bool(m.group("lim"))))
    return labels


def fixture_files(fixture_dir: str) -> List[str]:
    return sorted(os.path.join(fixture_dir, f) for f in os.listdir(fixture_dir) if f.endswith(".py"))


# ---------------------------------------------------------------------------
# Analyzers under evaluation
# ---------------------------------------------------------------------------

def new_analyzer(path: str) -> Tuple[List[Reported], Dict[int, Tuple[int, int]]]:
    from .analyzer import analyze_file
    rep = analyze_file(path)
    out = [Reported(path, f.line, f.rule_id, f.status, f.function, f.message) for f in rep.findings]
    return out, _function_spans(path)


def legacy_analyzer_factory(legacy_path: str) -> Callable:
    """Load the original src/security_analyzer.py from a copy and adapt its output."""
    spec = importlib.util.spec_from_file_location("src._legacy_security_analyzer", legacy_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)   # relative imports resolve against package "src"

    def run(path: str):
        from ..ast_extractor import extract_features
        from ..context_analyzer import analyze_context
        from ..parser_module import parse_code
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        try:
            tree = parse_code(src)
        except Exception:
            return [], {}
        mf = extract_features(tree, src, filepath=path)
        cg = analyze_context(mf, tree, src, include_security=False)
        report = module.run_security_analysis(mf, cg, src)
        out = [Reported(path, i.lineno, i.pattern_id, "potential", i.function_name, i.message)
               for i in report.issues]
        return out, _function_spans(path)

    return run


def _function_spans(path: str) -> Dict[int, Tuple[int, int]]:
    """line → (start, end) of the innermost enclosing function (module = whole file)."""
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return {}
    n = len(src.splitlines())
    spans = [(1, n)]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            spans.append((node.lineno, node.end_lineno or node.lineno))
    out = {}
    for line in range(1, n + 1):
        inner = [s for s in spans if s[0] <= line <= s[1]]
        out[line] = min(inner, key=lambda s: s[1] - s[0])
    return out


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _ratio(num: int, den: int) -> Optional[float]:
    return None if den == 0 else num / den


def metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, object]:
    p = _ratio(tp, tp + fp)
    r = _ratio(tp, tp + fn)
    f1 = None if p is None or r is None or (p + r) == 0 else 2 * p * r / (p + r)
    if p is not None and r is not None and p + r == 0:
        f1 = 0.0
    fpr = _ratio(fp, fp + tn)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": p, "recall": r, "f1": f1,
            "false_positive_rate": fpr}


def score(labels: List[Label], reported: List[Reported], spans_by_file: Dict[str, dict],
          statuses=("confirmed", "potential"), granularity: str = "line") -> Dict[str, object]:
    active = [r for r in reported if r.status in statuses]
    suppressed = [r for r in reported if r.status == "suppressed"]

    def key(file, line):
        if granularity == "function":
            return (file, spans_by_file.get(file, {}).get(line, (line, line)))
        return (file, line)

    positives = [l for l in labels if l.kind == "expect"]
    negatives = [l for l in labels if l.kind in ("safe", "expect-suppressed")]
    rules_in_scope = {l.rule for l in labels}

    per_class: Dict[str, Dict[str, int]] = {}

    def bump(rule, field):
        c = per_class.setdefault(rule_class(rule), {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        c[field] += 1

    matched = set()
    fn_sites, fp_findings = [], []
    for lab in positives:
        hits = [i for i, r in enumerate(active)
                if r.rule == lab.rule and key(r.file, r.line) == key(lab.file, lab.line)]
        if hits:
            bump(lab.rule, "tp")
            matched.update(hits)
        else:
            bump(lab.rule, "fn")
            fn_sites.append(lab)
    neg_keys = {(l.rule, key(l.file, l.line)) for l in negatives}
    for lab in negatives:
        hit = any(r.rule == lab.rule and key(r.file, r.line) == key(lab.file, lab.line)
                  for r in active)
        if not hit:
            bump(lab.rule, "tn")
    for i, r in enumerate(active):
        if i in matched or r.rule not in rules_in_scope:
            continue
        bump(r.rule, "fp")
        fp_findings.append({"file": os.path.basename(r.file), "line": r.line, "rule": r.rule,
                            "status": r.status, "at_negative_label":
                            (r.rule, key(r.file, r.line)) in neg_keys, "message": r.message})

    supp_expected = [l for l in labels if l.kind == "expect-suppressed"]
    supp_ok = sum(1 for l in supp_expected
                  if any(r.rule == l.rule and r.line == l.line and r.file == l.file
                         for r in suppressed))

    totals = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for c in per_class.values():
        for k in totals:
            totals[k] += c[k]
    return {
        "per_class": {k: metrics(**v) for k, v in sorted(per_class.items())},
        "overall": metrics(**totals),
        "false_negatives": [{"file": os.path.basename(l.file), "line": l.line, "rule": l.rule,
                             "known_limitation": l.limitation} for l in fn_sites],
        "false_positives": fp_findings,
        "suppression_checks": {"expected": len(supp_expected), "correct": supp_ok},
        "labels": {"positive": len(positives), "negative": len(negatives)},
    }


def evaluate(fixture_dir: str = DEFAULT_FIXTURES, analyzer: Callable = new_analyzer,
             statuses=("confirmed", "potential"), granularity: str = "line") -> Dict[str, object]:
    fixture_dir = os.path.normpath(fixture_dir)
    files = fixture_files(fixture_dir)
    labels: List[Label] = []
    reported: List[Reported] = []
    spans: Dict[str, dict] = {}
    timings = {}
    tracemalloc.start()
    t0 = time.perf_counter()
    for path in files:
        labels += load_labels(path)
        t = time.perf_counter()
        out, sp = analyzer(path)
        timings[os.path.basename(path)] = round((time.perf_counter() - t) * 1000, 2)
        reported += out
        spans[path] = sp
    total_ms = (time.perf_counter() - t0) * 1000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    result = score(labels, reported, spans, statuses=statuses, granularity=granularity)
    result["config"] = {"fixtures": len(files), "statuses_counted": list(statuses),
                        "granularity": granularity, "unit": "labelled (file, line, rule) site"}
    result["performance"] = {"total_ms": round(total_ms, 2), "per_file_ms": timings,
                             "peak_traced_memory_kb": round(peak / 1024, 1)}
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _fmt(v) -> str:
    return "undefined" if v is None else f"{v:.3f}"


def format_table(result: Dict[str, object], title: str) -> str:
    lines = [title, "=" * len(title),
             f"{'class':<22}{'TP':>4}{'FP':>4}{'TN':>4}{'FN':>4}  {'precision':>9} {'recall':>9} "
             f"{'F1':>9} {'FPR':>9}"]
    rows = list(result["per_class"].items()) + [("OVERALL", result["overall"])]
    for name, m in rows:
        lines.append(f"{name:<22}{m['tp']:>4}{m['fp']:>4}{m['tn']:>4}{m['fn']:>4}  "
                     f"{_fmt(m['precision']):>9} {_fmt(m['recall']):>9} {_fmt(m['f1']):>9} "
                     f"{_fmt(m['false_positive_rate']):>9}")
    lab = result["labels"]
    perf = result["performance"]
    lines.append(f"labels: {lab['positive']} positive, {lab['negative']} negative; "
                 f"unit = {result['config']['unit']}; granularity = {result['config']['granularity']}; "
                 f"statuses counted = {', '.join(result['config']['statuses_counted'])}")
    sc = result["suppression_checks"]
    lines.append(f"suppression checks: {sc['correct']}/{sc['expected']} correctly suppressed")
    lines.append(f"runtime: {perf['total_ms']:.1f} ms total, peak traced memory "
                 f"{perf['peak_traced_memory_kb']:.0f} KiB")
    if result["false_negatives"]:
        lines.append("false negatives:")
        for f in result["false_negatives"]:
            tag = " (known limitation)" if f["known_limitation"] else ""
            lines.append(f"  {f['file']}:{f['line']} {f['rule']}{tag}")
    if result["false_positives"]:
        lines.append("false positives:")
        for f in result["false_positives"]:
            where = "negative label" if f["at_negative_label"] else "unlabelled line"
            lines.append(f"  {f['file']}:{f['line']} {f['rule']} [{f['status']}] ({where})")
    return "\n".join(lines)


def main(argv=None) -> int:
    from ..config import configure_stdio
    configure_stdio()
    ap = argparse.ArgumentParser(prog="python -m src.security.evaluate")
    ap.add_argument("--fixtures", default=DEFAULT_FIXTURES)
    ap.add_argument("--confirmed-only", action="store_true",
                    help="count only findings with status 'confirmed' as reported")
    ap.add_argument("--granularity", choices=["line", "function"], default="line")
    ap.add_argument("--baseline", metavar="LEGACY_PY",
                    help="also evaluate a copy of the original security_analyzer.py")
    ap.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    args = ap.parse_args(argv)

    statuses = ("confirmed",) if args.confirmed_only else ("confirmed", "potential")
    out = {"analyzer": evaluate(args.fixtures, new_analyzer, statuses, args.granularity)}
    print(format_table(out["analyzer"], "Taint/AST security analyzer"))
    if args.baseline:
        legacy = legacy_analyzer_factory(args.baseline)
        out["baseline"] = evaluate(args.fixtures, legacy, ("potential",), args.granularity)
        print()
        print(format_table(out["baseline"], "Baseline: original 12-pattern scanner"))
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
