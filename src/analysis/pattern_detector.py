"""
Pattern Detector — Week 8
==========================
Detects code-quality patterns / code smells from IR and DFA results.

Patterns detected
-----------------
  P001  unused_variable      (warning)  — user variable assigned but never read
  P002  high_complexity      (warning)  — cyclomatic complexity > 10
  P003  dead_block           (info)     — block unreachable from the entry block
  P004  no_return_value      (info)     — annotated non-None function can return None
  P005  deeply_nested_loops  (warning)  — loop nesting depth ≥ 3
  P006  excessive_calls      (info)     — function calls > 10 distinct callees
  P007  unused_parameter     (info)     — parameter is never read

History: P007 used to be ``missing_param_load`` (“parameter has no LOAD in the
entry block”).  The IR builder always emits that LOAD, so the rule could never
fire.  It now reports parameters that no instruction ever reads, which is a
property the real IR and liveness analysis can establish.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from ..ir.ir_nodes import IRModule, IRFunction, IROpcode
from .cfg_builder import build_cfg
from .dfa_engine import DFAResult, instr_uses


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PatternFinding:
    """
    A single finding produced by the pattern detector.

    Attributes:
        pattern_id    : Short code like ``P001``.
        severity      : ``"info"``, ``"warning"``, or ``"error"``.
        function_name : Name of the function in which the pattern was detected.
        message       : Human-readable description.
        lineno        : Source line of the offending code (function line if unknown).
    """
    pattern_id: str
    severity: str          # "info" | "warning" | "error"
    function_name: str
    message: str
    lineno: int = 0

    def __repr__(self) -> str:
        return f"[{self.severity.upper()}] {self.pattern_id} in {self.function_name!r}: {self.message}"


@dataclass
class AnalysisReport:
    """
    Complete analysis report for all functions in an IRModule.

    Attributes:
        source_file : Path of the analysed source file.
        findings    : All patternFindings ordered by (function_name, lineno).
        summary     : Aggregate counts keyed by severity and pattern_id.
    """
    source_file: str = ""
    findings: List[PatternFinding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)

    def add(self, finding: PatternFinding) -> None:
        self.findings.append(finding)
        self.summary[finding.severity] = self.summary.get(finding.severity, 0) + 1
        self.summary[finding.pattern_id] = self.summary.get(finding.pattern_id, 0) + 1

    def findings_for(self, function_name: str) -> List[PatternFinding]:
        return [f for f in self.findings if f.function_name == function_name]

    def __repr__(self) -> str:
        return f"AnalysisReport({self.source_file!r}, {len(self.findings)} findings)"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TRIVIAL_OPS = (IROpcode.LABEL, IROpcode.JUMP, IROpcode.NOP)


def _first_def_line(ir_func: IRFunction, var: str) -> int:
    for instr in ir_func.all_instructions():
        if instr.result == var and instr.op not in _TRIVIAL_OPS:
            return instr.lineno
    return ir_func.source_lineno


def _real_instructions(block) -> list:
    return [i for i in block.instructions
            if i.op not in _TRIVIAL_OPS and i.meta.get("implicit_return") != "1"]


# ---------------------------------------------------------------------------
# Individual pattern checkers
# ---------------------------------------------------------------------------

def _check_unused_variables(ir_func: IRFunction, dfa: Optional[DFAResult],
                            report: AnalysisReport) -> None:
    """P001 — user variables assigned but never read."""
    if dfa is None:
        return
    # Loop / comprehension targets that are never read (``for i in range(n)``) are
    # conventional and not reported.
    non_loop_defs = {i.result for i in ir_func.all_instructions()
                     if i.result and i.op == IROpcode.ASSIGN and i.meta.get("loop_target") != "1"}
    for var in dfa.unused_vars:
        if var not in non_loop_defs:
            continue
        report.add(PatternFinding(
            pattern_id="P001",
            severity="warning",
            function_name=ir_func.name,
            message=f"Variable {var!r} is assigned but never read.",
            lineno=_first_def_line(ir_func, var),
        ))


def _cyclomatic_complexity(ir_func: IRFunction) -> int:
    decisions = 0
    for block in ir_func.blocks:
        for instr in block.instructions:
            if instr.op == IROpcode.BRANCH:
                decisions += max(1, len(instr.operands) - 2)
            if instr.op == IROpcode.BINOP and instr.meta.get("operator") in ("And", "Or"):
                decisions += len(instr.operands) - 1
        if block.meta.get("kind") == "except":
            decisions += 1
    return 1 + decisions


def _check_high_complexity(ir_func: IRFunction, report: AnalysisReport) -> None:
    """P002 — cyclomatic complexity (1 + decision points in the IR) above 10."""
    cc = _cyclomatic_complexity(ir_func)
    if cc > 10:
        report.add(PatternFinding(
            pattern_id="P002",
            severity="warning",
            function_name=ir_func.name,
            message=f"Cyclomatic complexity is {cc} (> 10) — consider splitting the function.",
            lineno=ir_func.source_lineno,
        ))


def _check_dead_blocks(ir_func: IRFunction, report: AnalysisReport,
                       reachable: Set[str]) -> None:
    """P003 — blocks with real code that cannot be reached from the entry block."""
    for block in ir_func.blocks:
        if block.label in reachable:
            continue
        real = _real_instructions(block)
        if not real:
            continue
        report.add(PatternFinding(
            pattern_id="P003",
            severity="info",
            function_name=ir_func.name,
            message=f"Code in block {block.label!r} (line {real[0].lineno}) is unreachable.",
            lineno=real[0].lineno,
        ))


def _check_no_return_value(ir_func: IRFunction, report: AnalysisReport,
                           reachable: Set[str]) -> None:
    """P004 — annotated non-None function with a reachable path returning None."""
    rt = (ir_func.return_type or "").replace(" ", "")
    if rt in ("", "None", "NoReturn") or "None" in rt or "Optional" in rt \
            or any(g in rt for g in ("Iterator", "Generator", "Iterable")):
        return
    has_yield = any(i.meta.get("kind") == "yield" for i in ir_func.all_instructions())
    if has_yield:
        return
    for block in ir_func.blocks:
        if block.label not in reachable:
            continue
        for instr in block.instructions:
            if instr.result != "__return__" or instr.op != IROpcode.ASSIGN:
                continue
            implicit = instr.meta.get("implicit_return") == "1"
            explicit_none = instr.meta.get("kind") == "return" and _is_none_temp(
                block, instr.operands[0] if instr.operands else "")
            if implicit or explicit_none:
                how = "can fall off the end" if implicit else "has a bare/None return"
                report.add(PatternFinding(
                    pattern_id="P004",
                    severity="info",
                    function_name=ir_func.name,
                    message=(f"Function declares return type {ir_func.return_type!r} "
                             f"but {how} (returns None)."),
                    lineno=instr.lineno,
                ))
                return


def _is_none_temp(block, operand: str) -> bool:
    for instr in block.instructions:
        if instr.result == operand and instr.op == IROpcode.ASSIGN and instr.meta.get("const") == "None":
            return True
    return False


def _check_deeply_nested_loops(ir_func: IRFunction, report: AnalysisReport) -> None:
    """P005 — loop nesting depth of three or more."""
    depth = max((int(b.meta.get("loop_depth", "0")) for b in ir_func.blocks), default=0)
    if depth >= 3:
        report.add(PatternFinding(
            pattern_id="P005",
            severity="warning",
            function_name=ir_func.name,
            message=f"Loops are nested {depth} levels deep — consider refactoring to reduce depth.",
            lineno=ir_func.source_lineno,
        ))


def _check_excessive_calls(ir_func: IRFunction, report: AnalysisReport) -> None:
    """P006 — function calls more than 10 distinct callees."""
    callees = set()
    for instr in ir_func.all_instructions():
        if instr.op == IROpcode.CALL and instr.meta.get("callee"):
            callees.add(instr.meta["callee"])
    if len(callees) > 10:
        report.add(PatternFinding(
            pattern_id="P006",
            severity="info",
            function_name=ir_func.name,
            message=(
                f"Function makes calls to {len(callees)} distinct callees — "
                "high coupling; consider splitting responsibilities."
            ),
            lineno=ir_func.source_lineno,
        ))


_STUB_DECORATORS = ("abstractmethod", "overload", "override")


def _check_unused_parameters(ir_func: IRFunction, report: AnalysisReport) -> None:
    """P007 — parameter never read by any instruction."""
    if any(any(s in d for s in _STUB_DECORATORS) for d in ir_func.decorators):
        return
    if ir_func.name.startswith("__") and ir_func.name.endswith("__"):
        return
    used: Set[str] = set()
    real = 0
    for instr in ir_func.all_instructions():
        used.update(instr_uses(instr))
        if instr.op not in _TRIVIAL_OPS and instr.op != IROpcode.LOAD \
                and instr.meta.get("implicit_return") != "1" and instr.op != IROpcode.RETURN:
            real += 1
    if real <= 1:
        return   # stub body (pass / ... / docstring only)
    for param in ir_func.params:
        if param in ("self", "cls") or param.startswith("_") or param in used:
            continue
        report.add(PatternFinding(
            pattern_id="P007",
            severity="info",
            function_name=ir_func.name,
            message=f"Parameter {param!r} is never read.",
            lineno=ir_func.source_lineno,
        ))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_patterns(
    ir_module: IRModule,
    dfa_results: Optional[List[DFAResult]] = None,
) -> AnalysisReport:
    """
    Run all pattern-detection checks over the IRModule.

    Args:
        ir_module   : IRModule produced by ``ir_builder.build_ir()``.
        dfa_results : Optional list of DFAResult objects (one per function)
                      produced by ``dfa_engine.run_dfa()``.  When supplied,
                      data-flow-based checks (P001) are also run.

    Returns:
        AnalysisReport with all discovered findings.
    """
    report = AnalysisReport(source_file=ir_module.source_file)

    dfa_map: Dict[str, DFAResult] = {}
    if dfa_results:
        for dr in dfa_results:
            dfa_map[dr.qualname or dr.function_name] = dr

    for ir_func in ir_module.functions:
        dfa = dfa_map.get(ir_func.qualname or ir_func.name) or dfa_map.get(ir_func.name)
        reachable = build_cfg(ir_func).reachable()
        _check_unused_variables(ir_func, dfa, report)
        _check_high_complexity(ir_func, report)
        _check_dead_blocks(ir_func, report, reachable)
        _check_no_return_value(ir_func, report, reachable)
        _check_deeply_nested_loops(ir_func, report)
        _check_excessive_calls(ir_func, report)
        _check_unused_parameters(ir_func, report)

    report.findings.sort(key=lambda f: (f.function_name, f.lineno, f.pattern_id))
    return report
