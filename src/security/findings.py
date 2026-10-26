"""
Finding schema
===============
One consistent record for every security result, whether it came from the
taint engine, a dangerous-API check, or an AST pattern rule.

Status
------
  confirmed  — supported source-to-sink path (or definite pattern) and every
               confidence factor is "high"
  potential  — the pattern/flow exists but some link is uncertain (see
               ``confidence_reasons``)
  suppressed — matched a ``# nosec <RULE>: <reason>`` comment or a rule-level
               exemption; kept in the report with the reason, excluded from
               scores

Confidence
----------
Confidence is the *minimum* level among explicit factors; there is no numeric
score.  Factors (each listed in ``confidence_reasons``):

  high   — default for a resolved sink fed by a recognised remote source
  medium — source is local (env/argv/file) or name-heuristic; sink matched only
           by method name; flow passes through an unresolved call; the
           function contains IR constructs that are not modelled
  low    — origin is a parameter of a function with no analysed caller; no
           untrusted source traced to a dangerous API; analysis hit a cap
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

LEVELS = {"high": 3, "medium": 2, "low": 1}
SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def lower_severity(sev: str) -> str:
    i = SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 1
    return SEVERITY_ORDER[max(0, i - 1)]


def min_level(levels: List[str]) -> str:
    if not levels:
        return "high"
    return min(levels, key=lambda l: LEVELS.get(l, 0))


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    cwe: Optional[str]
    severity: str
    confidence: str
    status: str                       # confirmed | potential | suppressed
    file: str
    function: str
    line: int
    col: int
    message: str
    remediation: str
    analysis: str                     # taint | api-use | sql-construction | ast-pattern
    severity_reason: str = ""
    confidence_reasons: List[str] = field(default_factory=list)
    suppression_reason: str = ""
    sink: Optional[Dict] = None
    source: Optional[Dict] = None
    trace: List[Dict] = field(default_factory=list)
    path_conditions: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    missing_protections: List[str] = field(default_factory=list)
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        src = self.source or {}
        parts = [self.rule_id, self.file, self.function, str(self.line), str(self.col),
                 (self.sink or {}).get("role", ""), str(src.get("description", "")),
                 str(src.get("line", ""))]
        self.fingerprint = hashlib.sha1("|".join(parts).encode("utf-8"),
                                        usedforsecurity=False).hexdigest()[:16]
        return self.fingerprint

    def to_dict(self) -> dict:
        return asdict(self)

    def format_text(self, show_trace: bool = True) -> str:
        loc = f"{self.file}:{self.line}:{self.col + 1}"
        head = (f"[{self.status.upper()}] {self.rule_id} {self.title} — {self.severity} severity, "
                f"{self.confidence} confidence\n  at {loc} in {self.function}()")
        lines = [head, f"  {self.message}"]
        if self.cwe:
            lines[0] += f" ({self.cwe})"
        if self.suppression_reason:
            lines.append(f"  suppressed: {self.suppression_reason}")
        if show_trace and self.trace:
            lines.append("  evidence:")
            for st in self.trace:
                lines.append(f"    L{st['line']:<4} [{st['kind']}] {st['text']}")
        if self.path_conditions:
            lines.append("  under conditions: " + "; ".join(self.path_conditions))
        if self.confidence_reasons:
            lines.append("  confidence: " + "; ".join(self.confidence_reasons))
        lines.append(f"  fix: {self.remediation}")
        return "\n".join(lines)


@dataclass
class SecurityFindings:
    """All findings for one source file plus analysis metadata."""
    file: str
    findings: List[Finding] = field(default_factory=list)
    functions_analysed: int = 0
    unmodelled: Dict[str, List[str]] = field(default_factory=dict)
    converged: bool = True
    rounds: int = 0
    runtime_ms: float = 0.0
    parse_error: Optional[str] = None

    def active(self) -> List[Finding]:
        return [f for f in self.findings if f.status != "suppressed"]

    def by_status(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.status] = out.get(f.status, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "parse_error": self.parse_error,
            "functions_analysed": self.functions_analysed,
            "converged": self.converged,
            "rounds": self.rounds,
            "runtime_ms": round(self.runtime_ms, 2),
            "summary": self.by_status(),
            "unmodelled_constructs": self.unmodelled,
            "findings": [f.to_dict() for f in self.findings],
        }
