"""
Security report adapter
========================
Keeps the ``SecurityReport`` / ``SecurityIssue`` interface used by the CLI
pipeline and the GUI, but every issue now comes from the central analyzer in
``src/security`` (taint analysis over the real IR + AST pattern rules).

The original implementation matched regexes against function source text and
reported every issue on the function's ``def`` line; it is superseded by
``src.security.analyze_source``.  Rule IDs SEC001–SEC012 are unchanged;
SEC013 (path traversal), SEC014 (XSS) and SEC015 (template injection) are new.
"""
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .ast_extractor import ModuleFeatures


@dataclass
class SecurityIssue:
    pattern_id: str
    severity: str
    function_name: str
    message: str
    lineno: int = 0
    remediation: str = ""
    # Added by the taint-based analyzer (defaults keep old constructors working)
    title: str = ""
    cwe: Optional[str] = None
    confidence: str = ""
    status: str = ""
    col: int = 0
    trace: List[str] = field(default_factory=list)
    confidence_reasons: List[str] = field(default_factory=list)


@dataclass
class SecurityReport:
    function_scores: Dict[str, float] = field(default_factory=dict)
    module_safe_pct: float = 100.0
    total_issues: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    issues: List[SecurityIssue] = field(default_factory=list)
    suppressed: List[SecurityIssue] = field(default_factory=list)
    by_status: Dict[str, int] = field(default_factory=dict)
    findings: list = field(default_factory=list)       # full src.security Finding objects
    parse_error: Optional[str] = None

    def add_issue(self, issue: SecurityIssue):
        self.issues.append(issue)
        self.total_issues += 1
        self.by_severity[issue.severity] = self.by_severity.get(issue.severity, 0) + 1

    def compute_function_score(self, func_name: str, issues: List[SecurityIssue]) -> float:
        # Severity-weighted as before; potential findings are not discounted, so an
        # unverified critical issue still marks the function as unsafe.
        weights = {"critical": 30, "high": 15, "medium": 5, "low": 1}
        penalty = sum(weights.get(i.severity, 0) for i in issues)
        return max(0.0, min(100.0, 100.0 - penalty))

    def compute_module_safe_pct(self, all_scores: Dict[str, float]) -> float:
        if not all_scores:
            return 100.0
        safe_count = sum(1 for s in all_scores.values() if s >= 80.0)
        return round(100.0 * safe_count / len(all_scores), 1)

    def to_dict(self) -> dict:
        def issue_dict(i: SecurityIssue) -> dict:
            return {
                "pattern_id": i.pattern_id,
                "severity": i.severity,
                "function_name": i.function_name,
                "message": i.message,
                "lineno": i.lineno,
                "col": i.col,
                "remediation": i.remediation,
                "title": i.title,
                "cwe": i.cwe,
                "confidence": i.confidence,
                "status": i.status,
                "trace": i.trace,
            }
        return {
            "function_scores": self.function_scores,
            "module_safe_pct": self.module_safe_pct,
            "total_issues": self.total_issues,
            "by_severity": self.by_severity,
            "by_status": self.by_status,
            "issues": [issue_dict(i) for i in self.issues],
            "suppressed": [issue_dict(i) for i in self.suppressed],
            "parse_error": self.parse_error,
        }


def _to_issue(f) -> SecurityIssue:
    short = f.function.rsplit(".", 1)[-1]
    return SecurityIssue(
        pattern_id=f.rule_id, severity=f.severity, function_name=short,
        message=f"{f.message} [{f.status}, {f.confidence} confidence]",
        lineno=f.line, remediation=f.remediation, title=f.title, cwe=f.cwe,
        confidence=f.confidence, status=f.status, col=f.col,
        trace=[f"L{s['line']} [{s['kind']}] {s['text']}" for s in f.trace],
        confidence_reasons=list(f.confidence_reasons),
    )


def run_security_analysis(
    module_features: ModuleFeatures,
    context_graph=None,
    source_code: str = "",
) -> SecurityReport:
    """
    Run the central security analyzer on the original source.

    ``context_graph`` is accepted for API compatibility; the analysis works
    from the source itself and never from generated comments.  Function scores
    are keyed by function name as before.
    """
    from .security import analyze_source

    if not source_code and module_features.filepath and os.path.isfile(module_features.filepath):
        with open(module_features.filepath, encoding="utf-8") as fh:
            source_code = fh.read()

    result = analyze_source(source_code or "", module_features.filepath or "<string>",
                            use_cache=True)
    report = SecurityReport(findings=result.findings, by_status=result.by_status(),
                            parse_error=result.parse_error)

    per_func: Dict[str, List[SecurityIssue]] = {ff.name: [] for ff in module_features.functions}
    spans = [(ff.name, ff.lineno, ff.lineno + ff.body_lines) for ff in module_features.functions]
    for f in result.findings:
        issue = _to_issue(f)
        if f.status == "suppressed":
            report.suppressed.append(issue)
            continue
        report.add_issue(issue)
        owner = None
        for name, start, end in spans:
            if start <= f.line <= end and (owner is None or start >= owner[1]):
                owner = (name, start)
        if owner is not None:
            per_func[owner[0]].append(issue)

    for name, issues in per_func.items():
        report.function_scores[name] = report.compute_function_score(name, issues)
    report.module_safe_pct = report.compute_module_safe_pct(report.function_scores)
    return report
