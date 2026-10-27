"""
Independent benchmarks
=======================
Runs the analyzer on independently sourced cases and scores it against labels
that were *not* derived from the analyzer.

Datasets (fetched by ``benchmarks/fetch.py`` into ``.benchmarks/``):

* **OWASP BenchmarkPython** (GPL-3.0, pinned commit) — 1230 generated Flask test
  cases, each labelled real/false vulnerability with a CWE.
  Unit: one test case × its category. A case is *flagged* when any reported
  finding of a rule mapped to that category exists in the test file (OWASP's
  own scoring convention). Categories outside the analyzer's scope are
  reported as exclusions, never as true negatives.
* **GHSA real-world fix pairs** (``benchmarks/realworld/manifest.json``) — the
  vulnerable (parent) and patched (fix) revisions of files from Python security
  advisories. Unit: one case × one revision, scored over the labelled
  (file, function) sites. Vulnerable revision: TP if the case's rule fires in a
  labelled function, else FN. Patched revision: FP if it still fires there,
  else TN. Findings outside labelled functions are counted as *unscored*.

    python -m src.security.benchmarks owasp     [--split dev|heldout|all] [--project]
    python -m src.security.benchmarks realworld [--split dev|heldout|all]
    python -m src.security.benchmarks all --out outputs/benchmarks

Both write ``<name>_raw.json`` (every finding, per file) and
``<name>_summary.json`` (metrics) with run metadata.
"""
from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tracemalloc
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .evaluate import metrics

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
# Overridable so the same runner can score another checkout (e.g. a baseline worktree).
DATA = os.environ.get("SEC_BENCH_DATA", os.path.join(ROOT, ".benchmarks"))
OWASP_DIR = os.path.join(DATA, "BenchmarkPython")
OWASP_COMMIT = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
REALWORLD_DIR = os.path.join(DATA, "realworld")
MANIFEST = os.environ.get("SEC_BENCH_MANIFEST", os.path.join(ROOT, "benchmarks", "realworld", "manifest.json"))

# OWASP category → rules that count as detecting it.
OWASP_RULES: Dict[str, Tuple[str, ...]] = {
    "cmdi": ("SEC002",), "codeinj": ("SEC001",), "deserialization": ("SEC009", "SEC010"),
    "hash": ("SEC004",), "pathtraver": ("SEC013",), "sqli": ("SEC005",),
    "weakrand": ("SEC011",), "xss": ("SEC014",),
}
STATUS_SETS = {"confirmed+potential": ("confirmed", "potential"), "confirmed": ("confirmed",)}


# ---------------------------------------------------------------------------
# Run metadata
# ---------------------------------------------------------------------------

def analyzer_revision() -> Dict[str, object]:
    def git(*args):
        r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None
    head = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain", "--", "src"))
    digest = hashlib.sha256()
    for base, _, files in sorted(os.walk(os.path.join(ROOT, "src", "security"))):
        for f in sorted(files):
            if f.endswith(".py"):
                digest.update(open(os.path.join(base, f), "rb").read())
    for f in ("lowering.py", "ir_nodes.py"):
        digest.update(open(os.path.join(ROOT, "src", "ir", f), "rb").read())
    return {"git_head": head, "src_dirty": dirty, "security_source_sha256": digest.hexdigest()[:16]}


def run_meta(dataset: str, dataset_version: str, config: dict) -> dict:
    return {"dataset": dataset, "dataset_version": dataset_version, "config": config,
            "analyzer": analyzer_revision(),
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "python": sys.version.split()[0]}


# ---------------------------------------------------------------------------
# Analyzer adapters
# ---------------------------------------------------------------------------

def _finding_rows(report) -> List[dict]:
    return [{"rule": f.rule_id, "line": f.line, "function": f.function, "status": f.status,
             "confidence": f.confidence, "file": f.file} for f in report.findings]


def analyze_single(path: str) -> dict:
    from .analyzer import analyze_file
    t = time.perf_counter()
    try:
        rep = analyze_file(path)
    except Exception as exc:          # recorded, never silently treated as "clean"
        return {"error": f"{type(exc).__name__}: {exc}", "findings": [], "ms": 0.0}
    return {"error": rep.parse_error, "findings": _finding_rows(rep),
            "ms": round((time.perf_counter() - t) * 1000, 2), "converged": rep.converged}


# ---------------------------------------------------------------------------
# OWASP BenchmarkPython
# ---------------------------------------------------------------------------

def owasp_cases() -> List[dict]:
    path = os.path.join(OWASP_DIR, "expectedresults-0.1.csv")
    rows = []
    with open(path, encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            rows.append({"test": row[0].strip(), "category": row[1].strip(),
                         "real": row[2].strip().lower() == "true", "cwe": row[3].strip()})
    return rows


def owasp_group_key(test: str) -> str:
    """Normalised propagation paragraph (the code that derives ``bar`` from ``param``)."""
    src = open(os.path.join(OWASP_DIR, "testcode", f"{test}.py"), encoding="utf-8").read()
    body = src.split("_post():", 1)[-1]
    paragraphs = [p for p in re.split(r"\n\s*\n", body) if p.strip()]
    prop = next((p for p in paragraphs if re.search(r"^\s*bar\b", p, re.M)), "")
    prop = re.sub(r"BenchmarkTest\d+", "T", prop)
    # Generated identifiers carry random numbers (map44013, conf64047): normalise them so
    # one template family can never appear in both dev and held-out.
    prop = re.sub(r"\d+", "N", prop)
    prop = re.sub(r"\s+", " ", prop).strip()
    return hashlib.sha256(prop.encode()).hexdigest()[:12]


def owasp_split(test: str) -> str:
    return "heldout" if int(owasp_group_key(test), 16) % 2 == 0 else "dev"


def _owasp_metrics(results: List[dict]) -> dict:
    out = {}
    for status_name, statuses in STATUS_SETS.items():
        per: Dict[str, Dict[str, int]] = {}
        for r in results:
            cat = r["category"]
            if cat not in OWASP_RULES or r["error"]:
                continue
            flagged = any(rule in OWASP_RULES[cat] and st in statuses for rule, st in r["rules_reported"])
            c = per.setdefault(cat, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
            key = ("tp" if flagged else "fn") if r["real"] else ("fp" if flagged else "tn")
            c[key] += 1
        tot = {k: sum(c[k] for c in per.values()) for k in ("tp", "fp", "tn", "fn")}
        out[status_name] = {"per_category": {k: metrics(**v) for k, v in sorted(per.items())},
                            "overall": metrics(**tot)}
    return out


def run_owasp(split: str = "all", project: bool = False) -> Tuple[dict, dict]:
    if not os.path.isdir(OWASP_DIR):
        raise SystemExit(f"OWASP data missing at {OWASP_DIR}: run python benchmarks/fetch.py")
    cases = owasp_cases()
    raw, results = {}, []
    project_findings = None
    tracemalloc.start()
    t0 = time.perf_counter()
    if project:
        from .project import analyze_project
        prep = analyze_project(OWASP_DIR, include=["testcode", "helpers"])
        project_findings = {}
        for f in prep.findings:
            project_findings.setdefault(os.path.basename(f.file), []).append(
                {"rule": f.rule_id, "line": f.line, "function": f.function, "status": f.status,
                 "confidence": f.confidence, "file": f.file})
    for case in cases:
        group = owasp_group_key(case["test"])
        sp = "heldout" if int(group, 16) % 2 == 0 else "dev"
        if split != "all" and sp != split:
            continue
        path = os.path.join(OWASP_DIR, "testcode", f"{case['test']}.py")
        if project:
            out = {"error": None, "findings": project_findings.get(f"{case['test']}.py", []), "ms": None}
        else:
            out = analyze_single(path)
        raw[case["test"]] = out
        results.append({**case, "split": sp, "group": group, "error": out["error"],
                        "rules_reported": sorted({(f["rule"], f["status"]) for f in out["findings"]})})
    total_ms = (time.perf_counter() - t0) * 1000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    summary = {"unit": "OWASP test case x its category (file-level, OWASP convention)",
               "excluded_categories": {}, "excluded_cases": [],
               "metrics": _owasp_metrics(results), "metrics_by_split": {}}
    for sp_name in sorted({r["split"] for r in results}):
        summary["metrics_by_split"][sp_name] = _owasp_metrics([r for r in results if r["split"] == sp_name])
    for r in results:
        if r["category"] not in OWASP_RULES:
            summary["excluded_categories"][r["category"]] = summary["excluded_categories"].get(r["category"], 0) + 1
        elif r["error"]:
            summary["excluded_cases"].append({"test": r["test"], "reason": f"analysis error: {r['error']}"})
    summary["cases_scored"] = sum(1 for r in results if r["category"] in OWASP_RULES and not r["error"])
    summary["performance"] = {"total_ms": round(total_ms, 1), "peak_traced_memory_kb": round(peak / 1024, 1),
                              "files": len(results)}
    meta = run_meta("OWASP BenchmarkPython", f"v0.1 @ {OWASP_COMMIT}",
                    {"split": split, "project_mode": project, "category_rules": OWASP_RULES})
    return ({"meta": meta, "results": results, "raw": raw}, {"meta": meta, **summary})


# ---------------------------------------------------------------------------
# GHSA real-world fix pairs
# ---------------------------------------------------------------------------

def load_manifest() -> dict:
    return json.load(open(MANIFEST, encoding="utf-8"))


def run_realworld(split: str = "all") -> Tuple[dict, dict]:
    manifest = load_manifest()
    raw, results, missing = {}, [], []
    t0 = time.perf_counter()
    for case in manifest["cases"]:
        if split != "all" and case["split"] != split:
            continue
        rev_results = {}
        for rev in ("vulnerable", "patched"):
            if rev == "patched" and not case["patched_applicable"]:
                continue
            hit_sites, unscored, errors = [], 0, []
            for site in case["sites"]:
                path = os.path.join(REALWORLD_DIR, case["id"], rev, site["file"])
                if not os.path.exists(path):
                    missing.append(f"{case['id']}/{rev}/{site['file']}")
                    errors.append("file not downloaded")
                    continue
                out = analyze_single(path)
                raw[f"{case['id']}/{rev}/{site['file']}"] = out
                if out["error"]:
                    errors.append(out["error"])
                labelled = set(site[f"{rev}_functions"])
                for f in out["findings"]:
                    if f["rule"] != case["rule"]:
                        continue
                    if f["function"] in labelled:
                        hit_sites.append({"file": site["file"], **f})
                    else:
                        unscored += 1
            rev_results[rev] = {"hits": hit_sites, "unscored_same_rule": unscored, "errors": errors}
        results.append({"id": case["id"], "category": case["category"], "rule": case["rule"],
                        "scope": case["scope"], "split": case["split"], "revisions": rev_results})

    summary = {"unit": "advisory case x revision, scored over labelled (file, function) sites",
               "missing_files": missing, "metrics": {}}
    for scope_name, scopes in (("modelled_scope", ("modelled",)),
                               ("all_in_category", ("modelled", "api_not_modelled"))):
        summary["metrics"][scope_name] = {}
        for status_name, statuses in STATUS_SETS.items():
            per: Dict[str, Dict[str, int]] = {}
            excluded = []
            for r in results:
                if r["scope"] not in scopes:
                    continue
                c = per.setdefault(r["category"], {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
                for rev, data in r["revisions"].items():
                    if data["errors"]:
                        excluded.append({"id": r["id"], "revision": rev, "reason": "; ".join(data["errors"])})
                        continue
                    detected = any(h["status"] in statuses for h in data["hits"])
                    if rev == "vulnerable":
                        c["tp" if detected else "fn"] += 1
                    else:
                        c["fp" if detected else "tn"] += 1
            tot = {k: sum(c[k] for c in per.values()) for k in ("tp", "fp", "tn", "fn")}
            summary["metrics"][scope_name][status_name] = {
                "per_category": {k: metrics(**v) for k, v in sorted(per.items())},
                "overall": metrics(**tot), "excluded": excluded}
    summary["cases"] = [{"id": r["id"], "category": r["category"], "scope": r["scope"], "split": r["split"],
                         **{f"{rev}_detected": sorted({h['status'] for h in d['hits']})
                            for rev, d in r["revisions"].items()},
                         **{f"{rev}_unscored": d["unscored_same_rule"] for rev, d in r["revisions"].items()}}
                        for r in results]
    summary["performance"] = {"total_ms": round((time.perf_counter() - t0) * 1000, 1)}
    meta = run_meta("GHSA real-world fix pairs", manifest["version"], {"split": split})
    return ({"meta": meta, "results": results, "raw": raw}, {"meta": meta, **summary})


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _fmt(v):
    return "undefined" if v is None else f"{v:.3f}"


def print_table(title: str, block: dict) -> None:
    print(title)
    print(f"  {'category':<17}{'TP':>4}{'FP':>4}{'TN':>4}{'FN':>4}  {'prec':>9}{'recall':>9}{'F1':>9}{'FPR':>9}")
    for name, m in list(block["per_category"].items()) + [("OVERALL", block["overall"])]:
        print(f"  {name:<17}{m['tp']:>4}{m['fp']:>4}{m['tn']:>4}{m['fn']:>4}  {_fmt(m['precision']):>9}"
              f"{_fmt(m['recall']):>9}{_fmt(m['f1']):>9}{_fmt(m['false_positive_rate']):>9}")


def main(argv=None) -> int:
    from ..config import configure_stdio
    configure_stdio()
    ap = argparse.ArgumentParser(prog="python -m src.security.benchmarks")
    ap.add_argument("dataset", choices=["owasp", "realworld", "all"])
    ap.add_argument("--split", choices=["dev", "heldout", "all"], default="dev")
    ap.add_argument("--project", action="store_true", help="OWASP: project-level (cross-file) analysis")
    ap.add_argument("--out", default=os.path.join(ROOT, "outputs", "benchmarks"))
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    tag = f"{args.split}{'_project' if args.project else ''}"
    if args.dataset in ("owasp", "all"):
        raw, summ = run_owasp(args.split, args.project)
        json.dump(raw, open(os.path.join(args.out, f"owasp_{tag}_raw.json"), "w"), indent=1, sort_keys=True)
        json.dump(summ, open(os.path.join(args.out, f"owasp_{tag}_summary.json"), "w"), indent=1, sort_keys=True)
        for status in STATUS_SETS:
            print_table(f"OWASP BenchmarkPython [{args.split}{', project' if args.project else ''}] — {status}",
                        summ["metrics"][status])
        print(f"  scored cases: {summ['cases_scored']}; excluded categories: {summ['excluded_categories']}; "
              f"errors: {len(summ['excluded_cases'])}; {summ['performance']}")
    if args.dataset in ("realworld", "all"):
        raw, summ = run_realworld(args.split)
        json.dump(raw, open(os.path.join(args.out, f"realworld_{tag}_raw.json"), "w"), indent=1, sort_keys=True)
        json.dump(summ, open(os.path.join(args.out, f"realworld_{tag}_summary.json"), "w"), indent=1, sort_keys=True)
        for scope in ("modelled_scope", "all_in_category"):
            for status in STATUS_SETS:
                print_table(f"GHSA fix pairs [{args.split}] {scope} — {status}", summ["metrics"][scope][status])
        if summ["missing_files"]:
            print(f"  missing files: {len(summ['missing_files'])} (run benchmarks/fetch.py)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
