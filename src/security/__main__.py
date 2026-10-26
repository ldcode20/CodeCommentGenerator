"""
Security analyzer CLI
======================
    python -m src.security <file-or-directory> [...] [--json] [--all] [--no-trace]
        [--min-confidence low|medium|high] [--fail-on potential|confirmed]

Analyses the given files as written (no comment generation, no ML model) and
prints findings with their evidence traces.  ``--json`` emits the full finding
schema.  Exit status is 1 when ``--fail-on`` is given and a matching finding
exists, otherwise 0 (2 for usage/parse errors).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from ..config import configure_stdio
from .analyzer import analyze_file
from .findings import LEVELS


def _iter_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in
                                 ("__pycache__", "venv", ".venv", "node_modules"))
                for f in sorted(files):
                    if f.endswith(".py"):
                        yield os.path.join(root, f)
        else:
            yield p


def main(argv=None) -> int:
    configure_stdio()
    ap = argparse.ArgumentParser(prog="python -m src.security",
                                 description="Evidence-backed static security analysis")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--all", action="store_true", help="include suppressed findings")
    ap.add_argument("--no-trace", action="store_true", help="omit evidence traces")
    ap.add_argument("--min-confidence", choices=list(LEVELS), default="low")
    ap.add_argument("--fail-on", choices=["potential", "confirmed"], default=None)
    args = ap.parse_args(argv)

    reports = []
    exit_code = 0
    for path in _iter_files(args.paths):
        try:
            rep = analyze_file(path)
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            exit_code = 2
            continue
        rep.findings = [f for f in rep.findings
                        if (args.all or f.status != "suppressed")
                        and LEVELS[f.confidence] >= LEVELS[args.min_confidence]]
        reports.append(rep)
        if rep.parse_error:
            exit_code = 2

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        total = 0
        for rep in reports:
            if rep.parse_error:
                print(f"{rep.file}: could not parse — {rep.parse_error}")
                continue
            for f in rep.findings:
                print(f.format_text(show_trace=not args.no_trace))
                print()
                total += 1
            note = "" if rep.converged else "  (analysis did not fully converge)"
            print(f"{rep.file}: {len(rep.findings)} finding(s) {rep.by_status()} "
                  f"in {rep.runtime_ms:.1f} ms{note}")
        print(f"\nTotal: {total} finding(s) in {len(reports)} file(s)")

    if args.fail_on:
        wanted = {"potential": {"potential", "confirmed"}, "confirmed": {"confirmed"}}[args.fail_on]
        if any(f.status in wanted for r in reports for f in r.findings):
            exit_code = max(exit_code, 1)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
