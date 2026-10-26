"""
Data-Flow Analysis Engine — Week 8
====================================
Implements two classical data-flow analyses over a CFG:

1. Reaching Definitions (forward analysis)
   ─────────────────────────────────────────
   A definition d reaches a point p if there exists a path from d to p along
   which d is not re-defined (killed).

   A definition is identified as ``"<var>@<uid>"`` where ``uid`` is the
   function-unique id of the defining instruction.  The entry block also
   receives a pseudo-definition ``"<var>@undef"`` for every local that is not
   a parameter, so a use reached by ``@undef`` may be unbound.

   GEN[B]  = last definition of each variable in B
   KILL[B] = every other definition of a variable defined in B
   IN[B]   = ∪{ OUT[P] : P ∈ predecessors(B) }
   OUT[B]  = GEN[B] ∪ (IN[B] − KILL[B])

2. Live Variable Analysis (backward analysis)
   ────────────────────────────────────────────
   A variable v is live at a point p if there exists a path from p to a use
   of v along which v is not re-defined.

   USE[B]  = variables used in B before any definition (upward-exposed uses)
   DEF[B]  = variables defined in B
   OUT[B]  = ∪{ IN[S] : S ∈ successors(B) }
   IN[B]   = USE[B] ∪ (OUT[B] − DEF[B])

Both use a worklist that iterates to a fixed point; the lattices are finite
(sets of definitions / variables of one function) and the transfer functions
monotone, so they terminate.  An explicit iteration cap guards against
malformed CFGs and is reported through ``DFAResult.converged``.

After running both analyses the engine also computes:
  - unused_vars          : user variables assigned but never read anywhere
  - dead_stores          : assignments whose value is never read afterwards
  - used_before_assigned : locals that may be read before any assignment
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from .cfg_builder import CFG, CFGNode
from ..ir.ir_nodes import IRInstruction, IROpcode, IRFunction

_TEMP = re.compile(r"^t\d+$")
_CONTROL_OPS = (IROpcode.LABEL, IROpcode.JUMP, IROpcode.NOP)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class DFAResult:
    """
    Complete data-flow analysis results for one function.

    Attributes:
        function_name        : Name of the analysed function.
        reaching_defs        : Map { block_label → set of definition ids
                               reaching the *entry* of that block }.
        live_vars            : Map { block_label → set of variable names
                               live at the *entry* of that block }.
        used_before_assigned : Locals that may be read on some path before
                               being assigned.
        unused_vars          : User variables assigned but never read.
        dead_stores          : (variable, line) of assignments never read later.
        converged            : False if an iteration cap was hit.
        iterations           : Worklist iterations used (both analyses).
    """
    function_name: str
    reaching_defs: Dict[str, Set[str]] = field(default_factory=dict)
    live_vars: Dict[str, Set[str]] = field(default_factory=dict)
    used_before_assigned: List[str] = field(default_factory=list)
    unused_vars: List[str] = field(default_factory=list)
    dead_stores: List[Tuple[str, int]] = field(default_factory=list)
    converged: bool = True
    iterations: int = 0
    qualname: str = ""


# ---------------------------------------------------------------------------
# Instruction-level def / use
# ---------------------------------------------------------------------------

def is_user_var(name: str) -> bool:
    return bool(name) and not _TEMP.match(name) and not name.startswith("__")


def instr_uses(instr: IRInstruction) -> List[str]:
    """Variables read by an instruction (branch/jump labels excluded)."""
    if instr.op in _CONTROL_OPS:
        return []
    if instr.op == IROpcode.BRANCH:
        return instr.operands[:1]
    if instr.op == IROpcode.LOAD and instr.meta.get("kind") == "param":
        return []
    return [o for o in instr.operands if o]


def instr_def(instr: IRInstruction) -> str:
    if instr.op in _CONTROL_OPS or instr.op == IROpcode.STORE:
        return ""
    return instr.result or ""


def def_id(instr: IRInstruction) -> str:
    return f"{instr.result}@{instr.uid}"


# ---------------------------------------------------------------------------
# Local gen / kill / use / def helpers
# ---------------------------------------------------------------------------

def _compute_gen_kill(node: CFGNode, defs_by_var: Dict[str, Set[str]]):
    """GEN = last definition of each variable in the block; KILL = all others."""
    last: Dict[str, str] = {}
    for instr in node.instructions:
        v = instr_def(instr)
        if v:
            last[v] = def_id(instr)
    gen = set(last.values())
    kill: Set[str] = set()
    for v in last:
        kill |= defs_by_var.get(v, set())
    return gen, kill - gen


def _compute_use_def(node: CFGNode):
    """USE = upward-exposed uses; DEF = variables defined in the block."""
    use: Set[str] = set()
    definition: Set[str] = set()
    for instr in node.instructions:
        for operand in instr_uses(instr):
            if operand not in definition:
                use.add(operand)
        v = instr_def(instr)
        if v:
            definition.add(v)
    return use, definition


# ---------------------------------------------------------------------------
# Reaching Definitions (forward, worklist)
# ---------------------------------------------------------------------------

def _reaching_definitions(cfg: CFG, undef_vars: Set[str]):
    defs_by_var: Dict[str, Set[str]] = {}
    for node in cfg.nodes.values():
        for instr in node.instructions:
            v = instr_def(instr)
            if v:
                defs_by_var.setdefault(v, set()).add(def_id(instr))
    for v in undef_vars:
        defs_by_var.setdefault(v, set()).add(f"{v}@undef")

    gen_map, kill_map, out_map, in_map = {}, {}, {}, {}
    for label, node in cfg.nodes.items():
        gen, kill = _compute_gen_kill(node, defs_by_var)
        if label == cfg.entry:
            # Pseudo-definitions are generated "before" the entry block.
            entry_defs = {f"{v}@undef" for v in undef_vars}
            defined_here = {instr_def(i) for i in node.instructions if instr_def(i)}
            gen |= {d for d in entry_defs if d.split("@")[0] not in defined_here}
        gen_map[label], kill_map[label] = gen, kill
        out_map[label] = set(gen)
        in_map[label] = set()

    worklist = list(cfg.nodes.keys())
    iterations = 0
    max_iter = max(100, len(cfg.nodes) * 50)
    while worklist and iterations < max_iter:
        iterations += 1
        label = worklist.pop(0)
        node = cfg.nodes[label]
        new_in: Set[str] = set()
        for pred_label in node.predecessors:
            new_in |= out_map.get(pred_label, set())
        new_out = gen_map[label] | (new_in - kill_map[label])
        in_map[label] = new_in
        if new_out != out_map[label]:
            out_map[label] = new_out
            for succ in node.successors:
                if succ not in worklist:
                    worklist.append(succ)
    for label, node in cfg.nodes.items():
        node.reach_in, node.reach_out = set(in_map[label]), set(out_map[label])
    return in_map, iterations, not worklist


# ---------------------------------------------------------------------------
# Live Variable Analysis (backward, worklist)
# ---------------------------------------------------------------------------

def _live_variables(cfg: CFG):
    use_map, def_map, in_map, out_map = {}, {}, {}, {}
    for label, node in cfg.nodes.items():
        use, defn = _compute_use_def(node)
        use_map[label], def_map[label] = use, defn
        in_map[label] = set(use)
        out_map[label] = set()

    order = cfg.topological_order()
    worklist = list(reversed(order)) + [l for l in cfg.nodes if l not in order]
    iterations = 0
    max_iter = max(100, len(cfg.nodes) * 50)
    while worklist and iterations < max_iter:
        iterations += 1
        label = worklist.pop(0)
        node = cfg.nodes[label]
        new_out: Set[str] = set()
        for succ_label in node.successors:
            new_out |= in_map.get(succ_label, set())
        new_in = use_map[label] | (new_out - def_map[label])
        out_map[label] = new_out
        if new_in != in_map[label]:
            in_map[label] = new_in
            for pred in node.predecessors:
                if pred not in worklist:
                    worklist.append(pred)
    for label, node in cfg.nodes.items():
        node.live_in, node.live_out = set(in_map[label]), set(out_map[label])
    return in_map, out_map, iterations, not worklist


# ---------------------------------------------------------------------------
# Derived facts
# ---------------------------------------------------------------------------

def _derived_facts(cfg: CFG, ir_function: IRFunction, reach_in, live_out, undef_vars):
    all_uses: Set[str] = set()
    defined: Set[str] = set()
    for node in cfg.nodes.values():
        for instr in node.instructions:
            all_uses.update(instr_uses(instr))
            v = instr_def(instr)
            if v:
                defined.add(v)

    params = set(ir_function.params)
    unused = sorted(v for v in defined - all_uses - params
                    if is_user_var(v) and v != "_" and not v.startswith("_"))

    dead: List[Tuple[str, int]] = []
    maybe_unbound: Set[str] = set()
    for label, node in cfg.nodes.items():
        # Backward pass inside the block for dead stores.
        live = set(live_out.get(label, set()))
        for instr in reversed(node.instructions):
            v = instr_def(instr)
            if v:
                if (is_user_var(v) and v not in live and v in all_uses
                        and instr.meta.get("kind") != "param" and not v.startswith("_")):
                    dead.append((v, instr.lineno))
                live.discard(v)
            live.update(instr_uses(instr))
        # Forward pass for possibly-unbound reads.
        reaching = set(reach_in.get(label, set()))
        if label == cfg.entry:
            reaching |= {f"{v}@undef" for v in undef_vars}
        for instr in node.instructions:
            for u in instr_uses(instr):
                if u in undef_vars and f"{u}@undef" in reaching:
                    maybe_unbound.add(u)
            v = instr_def(instr)
            if v:
                reaching = {d for d in reaching if d.split("@")[0] != v}
                reaching.add(def_id(instr))
    return unused, sorted(set(dead), key=lambda x: (x[1], x[0])), sorted(maybe_unbound)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_dfa(cfg: CFG, ir_function: IRFunction) -> DFAResult:
    """
    Run reaching-definitions and live-variable analyses over a CFG.

    Args:
        cfg         : CFG built by ``cfg_builder.build_cfg()``.
        ir_function : The corresponding IRFunction.

    Returns:
        DFAResult with all analysis data populated.
    """
    reachable = set(cfg.topological_order())
    undef_vars = {v for v in ir_function.locals - set(ir_function.params) if is_user_var(v)}
    reaching, it1, ok1 = _reaching_definitions(cfg, undef_vars)
    live_in, live_out, it2, ok2 = _live_variables(cfg)
    unused, dead, maybe_unbound = _derived_facts(
        cfg, ir_function,
        {l: s for l, s in reaching.items() if l in reachable},
        live_out, undef_vars,
    )
    return DFAResult(
        function_name=ir_function.name,
        reaching_defs={label: set(s) for label, s in reaching.items()},
        live_vars={label: set(s) for label, s in live_in.items()},
        used_before_assigned=maybe_unbound,
        unused_vars=unused,
        dead_stores=dead,
        converged=ok1 and ok2,
        iterations=it1 + it2,
        qualname=ir_function.qualname or ir_function.name,
    )
