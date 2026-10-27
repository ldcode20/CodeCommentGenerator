"""
Security analyzer
==================
Entry point that runs, on the *original* source:

  1. AST → IR lowering of every function, method, nested function and the
     module body (``ir.lowering``)
  2. interprocedural taint analysis (``security.taint``)
  3. AST pattern rules (``security.ast_rules``)

and converts everything into ``Finding`` records with derived severity,
confidence and status, applying ``# nosec`` suppressions.

It does not depend on comment generation or the ML model, and never reads
generated comments.
"""
from __future__ import annotations

import ast
import io
import re
import time
import tokenize
from dataclasses import replace
from typing import Dict, List, Optional, Tuple

from ..ir.lowering import lower_module
from .findings import Finding, SecurityFindings, lower_severity, min_level
from .rules import DEFAULT_REGISTRY, RULES, Registry
from .taint import Hit, TaintEngine

_NOSEC = re.compile(r"#\s*nosec\b(?P<rest>.*)$", re.IGNORECASE)
_RULE_IDS = re.compile(r"\bSEC\d{3}\b", re.IGNORECASE)
_UNMODELLED_PREFIXES = ("statement", "expression", "assignment")


# ---------------------------------------------------------------------------
# Suppression comments
# ---------------------------------------------------------------------------

def parse_suppressions(source: str) -> Dict[int, Tuple[Optional[set], str]]:
    """
    ``# nosec[ RULE[, RULE]][: reason]`` → {line: (rules or None, reason)}.

    A suppression on a comment-only line also applies to the next line.
    A marker without a reason is recorded with reason "" (and is not honoured).
    """
    out: Dict[int, Tuple[Optional[set], str]] = {}
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return out
    lines = source.splitlines()
    for tok in tokens:
        if tok.type != tokenize.COMMENT:
            continue
        m = _NOSEC.search(tok.string)
        if not m:
            continue
        rest = m.group("rest").split("#", 1)[0].strip()
        rules = {r.upper() for r in _RULE_IDS.findall(rest)} or None
        reason = _RULE_IDS.sub("", rest).strip(" ,:;-—\t")
        line = tok.start[0]
        out[line] = (rules, reason)
        text = lines[line - 1] if 0 < line <= len(lines) else ""
        if text.strip().startswith("#"):
            out[line + 1] = (rules, reason)
    return out


# ---------------------------------------------------------------------------
# Conversion of engine results
# ---------------------------------------------------------------------------

class _Builder:
    """Turns engine results into Findings; every location is attributed to its own file."""

    def __init__(self, engine: TaintEngine, files: Dict[str, List[str]], default_file: str,
                 registry: Registry):
        self.e = engine
        self.files = files
        self.file = default_file
        self.reg = registry

    def file_of(self, qualname: str) -> str:
        fn = self.e.function_by_qualname(qualname)
        return (fn.source_file if fn is not None and fn.source_file else None) or self.file

    def code_at(self, line: int, file: Optional[str] = None) -> str:
        lines = self.files.get(file or self.file, [])
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    def trace_dicts(self, steps) -> List[dict]:
        return [dict(st.to_dict(), file=self.file_of(st.function)) for st in steps]

    def function_notes(self, qualname: str) -> List[str]:
        fn = self.e.function_by_qualname(qualname)
        if fn is None:
            return []
        return [n for n in fn.unsupported if n.startswith(_UNMODELLED_PREFIXES)]

    def from_hit(self, h: Hit) -> Finding:
        rule = self.reg.rules[h.rule_id]
        origin = self.e.origins[h.origin_key]
        factors: List[Tuple[str, str]] = []
        if origin.kind == "param":
            factors.append(("low", f"value comes from {origin.description}, which has no analysed "
                                   f"caller in the analysed code; its real origin is unknown"))
        elif origin.trust == "local":
            factors.append(("medium", f"source is local ({origin.description}); attacker control "
                                      f"depends on how the program is deployed"))
        if origin.heuristic:
            factors.append(("medium", "source recognised by a naming heuristic, not an import"))
        if h.resolution == "method-name":
            factors.append(("medium", f"sink '{h.sink_name}' matched by method name; the "
                                      f"receiver's type was not resolved"))
        for u in sorted(h.info.unc)[:3]:
            factors.append(("medium", f"flow passes through {u}"))
        notes: List[str] = []
        for f in h.factors:
            level, _, text = f.partition(":")
            if level == "note":
                notes.append(text)
            else:
                factors.append((level, text))
        unmodelled = self.function_notes(h.function)
        if unmodelled:
            factors.append(("medium", "function contains constructs the IR does not model: "
                                      + "; ".join(unmodelled[:2])))
        if not self.e.converged or h.function in self.e.unconverged_functions:
            factors.append(("low", "analysis stopped at an iteration cap before a fixed point"))
        confidence = min_level([lvl for lvl, _ in factors])

        severity = h.severity_override or rule.severity
        sev_reason = f"base severity of {rule.rule_id} ({rule.category})"
        if h.severity_override:
            sev_reason = f"{severity}: {notes[0] if notes else 'sink condition'}"
        if origin.trust == "local":
            severity = lower_severity(severity)
            sev_reason += "; lowered one level because the source is local/operator-controlled"

        file = self.file_of(h.function)
        src_file = self.file_of(origin.function)
        trace = self.trace_dicts(h.info.trace)
        sanitizers = [s["text"] for s in trace if s["kind"] in ("sanitizer", "check")]
        missing = [f"no sanitizer valid for the '{rule.context}' context on this path"]
        if sanitizers:
            missing.append("sanitizers seen on the path do not cover the "
                           f"'{rule.context}' context")
        src_desc = origin.description
        if rule.context == "weakrand":
            message = (f"A {src_desc} reaches {h.operation} ({h.sink_name}); the random module is "
                       f"predictable and unsuitable for session, token or cookie values.")
            missing = ["value is not produced by secrets / random.SystemRandom"]
        else:
            message = (f"Data from {src_desc} reaches {h.operation} ({h.sink_name}) as "
                       f"{h.operand_role} without {rule.context}-context sanitisation."
                       + (f" Note: {'; '.join(notes)}." if notes else ""))
        f = Finding(
            rule_id=rule.rule_id, title=rule.title, category=rule.category, cwe=rule.cwe,
            severity=severity, confidence=confidence,
            status="confirmed" if confidence == "high" else "potential",
            file=file, function=h.function, line=h.lineno, col=h.col,
            message=message, remediation=rule.remediation, analysis="taint",
            severity_reason=sev_reason,
            confidence_reasons=[t for _, t in factors] or
            ["resolved sink reached by a recognised untrusted source on a feasible path"],
            sink={"name": h.sink_name, "operation": h.operation, "role": h.operand_role,
                  "line": h.lineno, "col": h.col, "code": self.code_at(h.lineno, file)},
            source={"description": origin.description, "kind": origin.kind,
                    "trust": origin.trust, "line": origin.lineno, "col": origin.col,
                    "function": origin.function, "file": src_file,
                    "code": self.code_at(origin.lineno, src_file)},
            trace=trace, path_conditions=list(h.guards), sanitizers=sanitizers,
            missing_protections=missing,
        )
        return f

    def from_api_use(self, u) -> Finding:
        rule = self.reg.rules[u.rule_id]
        file = self.file_of(u.function)
        return Finding(
            rule_id=rule.rule_id, title=rule.title, category=rule.category, cwe=rule.cwe,
            severity=lower_severity(rule.severity), confidence="low", status="potential",
            file=file, function=u.function, line=u.lineno, col=u.col,
            message=(f"{u.sink_name}() performs {u.operation} on a non-constant value whose origin "
                     f"was not traced to an untrusted source."),
            remediation=rule.remediation, analysis="api-use",
            severity_reason="base severity lowered one level: no untrusted flow was established",
            confidence_reasons=["no untrusted source was traced to this call; the API is unsafe for "
                                "any externally influenced input"],
            sink={"name": u.sink_name, "operation": u.operation, "role": "argument 1",
                  "line": u.lineno, "col": u.col, "code": self.code_at(u.lineno, file)},
            trace=[{"line": u.lineno, "col": u.col, "kind": "sink", "function": u.function,
                    "file": file, "text": self.code_at(u.lineno, file)}],
            path_conditions=list(u.guards),
            missing_protections=["argument is not a literal and its provenance is unknown"],
        )

    def from_sql_build(self, b) -> Finding:
        rule = self.reg.rules["SEC005"]
        origins = [self.e.origins[k] for k in b.origin_keys]
        remote = any(o.kind == "source" and o.trust == "remote" for o in origins)
        desc = ", ".join(sorted({o.description for o in origins})[:2])
        file = self.file_of(b.function)
        return Finding(
            rule_id="SEC005", title=rule.title, category=rule.category, cwe=rule.cwe,
            severity="medium", confidence="medium" if remote else "low", status="potential",
            file=file, function=b.function, line=b.lineno, col=b.col,
            message=(f"SQL text is built by string concatenation/formatting from {desc}; no "
                     f"execution of this text was observed in the analysed code."),
            remediation=rule.remediation, analysis="sql-construction",
            severity_reason="medium: the dangerous execution step was not observed",
            confidence_reasons=["the statement may be executed elsewhere (another module or an "
                                "unresolved call)"] +
                               ([] if remote else ["data origin is a parameter or local source"]),
            sink={"name": "SQL string construction", "operation": "SQL text construction",
                  "role": "string operand", "line": b.lineno, "col": b.col,
                  "code": self.code_at(b.lineno, file)},
            trace=[{"line": b.lineno, "col": b.col, "kind": "sink", "function": b.function,
                    "file": file, "text": b.text}],
        )

    def from_ast(self, raw: dict) -> Finding:
        rule = self.reg.rules[raw["rule_id"]]
        status = raw.get("status") or ("confirmed" if raw["confidence"] == "high" else "potential")
        line = raw["line"]
        file = raw.get("file") or self.file
        return Finding(
            rule_id=rule.rule_id, title=rule.title, category=rule.category, cwe=rule.cwe,
            severity=rule.severity, confidence=raw["confidence"], status=status,
            file=file, function=raw["function"], line=line, col=raw["col"],
            message=raw["message"], remediation=rule.remediation, analysis="ast-pattern",
            severity_reason=f"base severity of {rule.rule_id}",
            confidence_reasons=list(raw.get("confidence_reasons") or []) or
            ["structural pattern matched exactly"],
            suppression_reason=raw.get("suppression_reason", ""),
            sink={"name": rule.title, "operation": rule.category, "role": "code pattern",
                  "line": line, "col": raw["col"], "code": raw.get("code") or self.code_at(line, file)},
            trace=[{"line": line, "col": raw["col"], "kind": "pattern", "function": raw["function"],
                    "file": file, "text": raw.get("code") or self.code_at(line, file)}],
        )


def _dead_store_lines(engine: TaintEngine, qualname: str) -> set:
    from ..analysis import build_cfg, run_dfa
    fn = engine.function_by_qualname(qualname)
    if fn is None:
        return set()
    return {line for _, line in run_dfa(build_cfg(fn), fn).dead_stores}


def _function_locator(engine: TaintEngine, path: Optional[str] = None):
    """line -> qualname of the innermost function of ``path`` (all functions if None)."""
    body_names = {id(b) for b in engine.module_fns.values()}
    module_name = "<module>"
    for b in engine.module_fns.values():
        if path is None or b.source_file == path:
            module_name = b.qualname
            break
    spans = sorted(
        ((f.source_lineno, f.end_lineno or f.source_lineno, f.qualname) for f in engine.order
         if f is not None and id(f) not in body_names and (path is None or f.source_file == path)),
        key=lambda s: (s[0], -s[1]),
    )

    def func_at(line: int) -> str:
        best = module_name
        best_size = None
        for start, end, q in spans:
            if start <= line <= end and (best_size is None or end - start <= best_size):
                best, best_size = q, end - start
        return best

    return func_at


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_CACHE: Dict[Tuple[str, str], SecurityFindings] = {}
_CACHE_MAX = 8


def analyze_source(source: str, filepath: str = "<string>",
                   registry: Registry = DEFAULT_REGISTRY, use_cache: bool = False) -> SecurityFindings:
    """
    Analyse Python source text and return all security findings.

    ``use_cache`` lets several pipeline stages share one analysis of the same
    text (the result is shallow-copied so callers may filter ``findings``).
    """
    if use_cache and registry is DEFAULT_REGISTRY:
        key = (filepath, source)
        if key not in _CACHE:
            if len(_CACHE) >= _CACHE_MAX:
                _CACHE.pop(next(iter(_CACHE)))
            _CACHE[key] = analyze_source(source, filepath, registry)
        cached = _CACHE[key]
        return replace(cached, findings=list(cached.findings), unmodelled=dict(cached.unmodelled))
    t0 = time.perf_counter()
    result = SecurityFindings(file=filepath)
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as exc:
        result.parse_error = f"SyntaxError: {exc.msg} (line {exc.lineno})"
        result.runtime_ms = (time.perf_counter() - t0) * 1000
        return result

    ir = lower_module(tree, source, filepath)
    engine = TaintEngine(ir, registry).run()
    findings = assemble_findings(engine, {filepath: (tree, source)}, registry, filepath)[filepath]

    result.findings = findings
    result.functions_analysed = len(engine.order)
    result.unmodelled = {f.qualname: list(f.unsupported) for f in engine.order
                         if f is not None and f.unsupported}
    result.converged = engine.converged and not engine.unconverged_functions
    result.rounds = engine.rounds
    result.runtime_ms = (time.perf_counter() - t0) * 1000
    return result


def assemble_findings(engine: TaintEngine, units: Dict[str, Tuple[ast.Module, str]],
                      registry: Registry, default_file: str) -> Dict[str, List[Finding]]:
    """
    Convert one engine run into per-file findings: taint hits, dangerous-API uses, SQL
    construction, AST pattern rules and ``# nosec`` suppressions. Shared by single-file
    and project analysis.
    """
    files = {path: src.splitlines() for path, (_, src) in units.items()}
    builder = _Builder(engine, files, default_file, registry)

    findings: List[Finding] = []
    seen_hits = set()

    def reportable(h: Hit) -> bool:
        origin = engine.origins[h.origin_key]
        if origin.kind != "param":
            return True
        if engine.callers.get(origin.function):
            return False   # instantiated with real arguments at each analysed call site
        return registry.rules[h.rule_id].report_unknown_params

    seen_locations = set()
    for h in engine.hits + engine.entry_param_hits():
        # Same flow at the same source location (e.g. a finally body lowered on two paths).
        loc = (h.rule_id, h.function, h.lineno, h.col, h.operand_role, h.origin_key)
        if h.key() in seen_hits or loc in seen_locations or not reportable(h):
            continue
        seen_hits.add(h.key())
        seen_locations.add(loc)
        findings.append(builder.from_hit(h))

    hit_sites = {(h.function, h.sink_uid) for h in engine.hits}
    for s in engine.summaries.values():
        hit_sites |= {(h.function, h.sink_uid) for h in s.param_hits}
    seen_api = set()
    for u in engine.api_uses:
        k = (u.function, u.sink_uid, u.rule_id)
        if (u.function, u.sink_uid) in hit_sites or k in seen_api:
            continue
        seen_api.add(k)
        findings.append(builder.from_api_use(u))

    sql_lines = {(st["function"], st["line"]) for f in findings if f.rule_id == "SEC005"
                 for st in f.trace}
    seen_build = set()
    for b in engine.sql_builds:
        k = (b.function, b.lineno)
        if k in sql_lines or k in seen_build:
            continue
        if b.lineno in _dead_store_lines(engine, b.function):
            continue   # the constructed SQL is overwritten before any use
        keys = tuple(k for k in b.origin_keys
                     if engine.origins[k].kind != "param"
                     or not engine.callers.get(engine.origins[k].function))
        if not keys:
            continue   # only parameter origins that are bound at analysed call sites
        b = replace(b, origin_keys=keys)
        seen_build.add(k)
        findings.append(builder.from_sql_build(b))

    from .ast_rules import run_ast_rules
    from .findings import LEVELS
    flow_rand_sources = {(f.function, f.source["line"]) for f in findings
                         if f.rule_id == "SEC011" and f.source}
    for path, (tree, _src) in units.items():
        ast_best: Dict[tuple, Finding] = {}
        for raw in run_ast_rules(tree, path, _function_locator(engine, path if len(units) > 1 else None)):
            raw["file"] = path
            f = builder.from_ast(raw)
            if f.rule_id == "SEC011" and (f.function, f.line) in flow_rand_sources:
                continue   # the data-flow finding already covers this random call
            k = (f.rule_id, f.line, f.col)
            if k not in ast_best or LEVELS[f.confidence] > LEVELS[ast_best[k].confidence]:
                ast_best[k] = f
        findings.extend(ast_best.values())

    by_file: Dict[str, List[Finding]] = {path: [] for path in units}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    for path, flist in by_file.items():
        suppressions = parse_suppressions(units[path][1]) if path in units else {}
        for f in flist:
            sup = suppressions.get(f.line)
            if sup is None:
                continue
            rules, reason = sup
            if rules is not None and f.rule_id not in rules:
                continue
            if reason:
                f.status = "suppressed"
                f.suppression_reason = f"# nosec: {reason}"
            else:
                f.confidence_reasons.append("a '# nosec' marker without a justification was ignored")
        for f in flist:
            f.compute_fingerprint()
        flist.sort(key=lambda f: (f.line, f.col, f.rule_id, f.fingerprint))
    return by_file


def analyze_file(path: str, registry: Registry = DEFAULT_REGISTRY) -> SecurityFindings:
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    return analyze_source(source, path, registry)
