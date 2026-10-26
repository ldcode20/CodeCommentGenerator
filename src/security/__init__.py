"""
Security analysis package
==========================
Evidence-backed static security analysis for Python source.

    from src.security import analyze_source
    report = analyze_source(open("app.py").read(), "app.py")
    for f in report.active():
        print(f.format_text())

Command line:  python -m src.security <file-or-directory> [--json] [--all]
Evaluation:    python -m src.security.evaluate
"""
from .analyzer import analyze_file, analyze_source, parse_suppressions
from .findings import Finding, SecurityFindings
from .rules import DEFAULT_REGISTRY, RULES, Registry

__all__ = ["analyze_source", "analyze_file", "parse_suppressions", "Finding",
           "SecurityFindings", "Registry", "RULES", "DEFAULT_REGISTRY"]
