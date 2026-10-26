"""
Taint Engine
=============
Context-sensitive (per security context), flow-sensitive taint analysis over
the real IR/CFG produced by ``ir.lowering``.

Abstract domain
---------------
State      : variable → TaintValue
TaintValue : origin-key → TaintInfo
TaintInfo  : contexts  — security contexts for which the value is still dangerous
             markers   — facts that hold on *every* path (``canonical`` path)
             unc       — reasons the flow is uncertain (unresolved calls, …)
             trace     — one representative evidence trace (not part of equality)

Join is per-origin: contexts ∪, markers ∩, unc ∪; the shorter trace is kept.
Fixed-point checks compare only (origin, contexts, markers, unc), which form a
finite lattice for one module, so both the intraprocedural worklist and the
interprocedural round loop terminate.  Explicit caps exist anyway and, when
hit, mark the affected results as incomplete instead of silently stopping.

Interprocedural analysis
------------------------
Each function is analysed with *symbolic* parameter origins ``("param", f, i)``.
Its summary records (a) which origins reach its return value and with which
contexts, and (b) sink hits whose origin is one of its parameters.  At a call
site the summary is instantiated with the caller's argument taint, so a flow
``caller source → callee param → callee sink`` is reported with the full trace,
and a callee that sanitises its parameter does not taint the caller.
Recursion is handled by iterating rounds until no summary changes.

Unknown calls (no summary, no model) propagate the union of their inputs and
record an uncertainty reason, which lowers the confidence of any finding.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field, replace
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from ..analysis.cfg_builder import build_cfg
from ..ir.ir_nodes import IRFunction, IRInstruction, IRModule, IROpcode
from ..ir.lowering import MODULE_QUALNAME, RETURN_VAR
from .rules import (
    ALL_CONTEXTS, CANONICALIZER_METHODS, DB_CREATORS, DB_METHODS, DEFAULT_REGISTRY,
    MUTATOR_METHODS, PATH_CREATORS, PATH_METHODS, PROPAGATOR_CALLEES, PROPAGATOR_METHODS,
    SAFE_YAML_LOADERS, Registry, SinkSpec,
)

MAX_TRACE = 40
MAX_ROUNDS = 25


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    lineno: int
    col: int
    kind: str          # source | param | assign | store | call | return | sanitizer | check | sink
    text: str
    function: str

    def to_dict(self) -> dict:
        return {"line": self.lineno, "col": self.col, "kind": self.kind,
                "text": self.text, "function": self.function}


@dataclass(frozen=True)
class Origin:
    key: tuple
    kind: str            # source | param
    description: str
    trust: str           # remote | local | unknown
    lineno: int
    col: int
    function: str
    heuristic: bool = False
    param_index: int = -1
    param_name: str = ""


@dataclass(frozen=True)
class TaintInfo:
    contexts: FrozenSet[str]
    markers: FrozenSet[str] = frozenset()
    unc: FrozenSet[str] = frozenset()
    trace: Tuple[Step, ...] = ()


TaintValue = Dict[tuple, TaintInfo]
State = Dict[str, TaintValue]
EMPTY: TaintValue = {}


def _join_info(a: TaintInfo, b: TaintInfo) -> TaintInfo:
    trace = a.trace if len(a.trace) <= len(b.trace) else b.trace
    return TaintInfo(a.contexts | b.contexts, a.markers & b.markers, a.unc | b.unc, trace)


def join_values(*values: TaintValue) -> TaintValue:
    out: TaintValue = {}
    for v in values:
        for k, info in v.items():
            out[k] = _join_info(out[k], info) if k in out else info
    return out


def value_sig(v: TaintValue) -> frozenset:
    return frozenset((k, i.contexts, i.markers, i.unc) for k, i in v.items())


def state_sig(s: State) -> frozenset:
    return frozenset((var, value_sig(v)) for var, v in s.items() if v)


def join_states(states: List[State]) -> State:
    out: State = {}
    for s in states:
        for var, v in s.items():
            out[var] = join_values(out[var], v) if var in out else v
    return out


def add_step(v: TaintValue, step: Step) -> TaintValue:
    out: TaintValue = {}
    for k, info in v.items():
        tr = info.trace
        if tr and tr[-1].lineno == step.lineno and tr[-1].text == step.text:
            out[k] = info
            continue
        if len(tr) >= MAX_TRACE:
            tr = tr[:MAX_TRACE // 2] + tr[-(MAX_TRACE // 2 - 1):]
        out[k] = replace(info, trace=tr + (step,))
    return out


def drop_markers(v: TaintValue) -> TaintValue:
    return {k: replace(i, markers=frozenset()) if i.markers else i for k, i in v.items()}


def remove_contexts(v: TaintValue, ctxs: FrozenSet[str], step: Optional[Step] = None) -> TaintValue:
    out: TaintValue = {}
    for k, info in v.items():
        left = info.contexts - ctxs
        if not left:
            continue
        new = replace(info, contexts=left)
        if step is not None and info.contexts & ctxs:
            new = replace(new, trace=new.trace + (step,))
        out[k] = new
    return out


# ---------------------------------------------------------------------------
# Hits and summaries
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Hit:
    """A tainted value reaching a sink (origin may be a symbolic parameter)."""
    rule_id: str
    function: str
    sink_uid: int
    lineno: int
    col: int
    sink_name: str
    operation: str
    operand_role: str
    origin_key: tuple
    info: TaintInfo
    resolution: str                # exact | method-name
    factors: Tuple[str, ...] = ()  # extra (level, reason) codes from sink conditions
    guards: Tuple[str, ...] = ()
    severity_override: Optional[str] = None
    via: Tuple[str, ...] = ()      # call chain from the reporting caller

    def key(self) -> tuple:
        return (self.rule_id, self.function, self.sink_uid, self.operand_role, self.origin_key)


@dataclass(frozen=True)
class ApiUse:
    """A dangerous API called with a non-constant argument and no tainted flow."""
    rule_id: str
    function: str
    sink_uid: int
    lineno: int
    col: int
    sink_name: str
    operation: str
    guards: Tuple[str, ...] = ()


@dataclass(frozen=True)
class SqlBuild:
    """SQL text built by concatenation/formatting from a tainted value."""
    function: str
    lineno: int
    col: int
    origin_keys: Tuple[tuple, ...]
    text: str


@dataclass
class Summary:
    ret: TaintValue = field(default_factory=dict)
    param_hits: List[Hit] = field(default_factory=list)

    def sig(self):
        return (value_sig(self.ret), frozenset((h.key(), h.info.contexts) for h in self.param_hits))


@dataclass
class _FnRun:
    summary: Summary
    hits: List[Hit]
    api_uses: List[ApiUse]
    sql_builds: List[SqlBuild]
    fields: Dict[Tuple[str, str], TaintValue]
    closures: Dict[str, Dict[str, TaintValue]]
    final_state: State
    converged: bool
    callees: Set[str]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_SQLISH = re.compile(r"^\s*(select\s.+\sfrom\s|insert\s+into\s|update\s+\S+\s+set\s|delete\s+from\s"
                     r"|replace\s+into\s|create\s+table\s|drop\s+table\s)", re.IGNORECASE | re.DOTALL)
_TEMPLATE_CHAIN = re.compile(r"\{\}|%s|\{\w*\}")


class TaintEngine:
    def __init__(self, ir_module: IRModule, registry: Registry = DEFAULT_REGISTRY,
                 max_rounds: int = MAX_ROUNDS):
        self.m = ir_module
        self.reg = registry
        self.max_rounds = max_rounds
        self.functions: Dict[str, IRFunction] = {f.qualname: f for f in ir_module.functions}
        self.module_fn = ir_module.module_body
        self.order: List[IRFunction] = ([self.module_fn] if self.module_fn else []) + \
            list(ir_module.functions)
        self.summaries: Dict[str, Summary] = {q: Summary() for q in self.functions}
        self.fields: Dict[Tuple[str, str], TaintValue] = {}
        self.closures: Dict[str, Dict[str, TaintValue]] = {}
        self.globals: State = {}
        self.origins: Dict[tuple, Origin] = {}
        self.callers: Dict[str, Set[str]] = {}
        self.converged = True
        self.rounds = 0
        self.unconverged_functions: Set[str] = set()
        # Final results (from the last round)
        self.hits: List[Hit] = []
        self.api_uses: List[ApiUse] = []
        self.sql_builds: List[SqlBuild] = []
        self._route_re = re.compile(registry.route_decorator_pattern)
        self.html_sink_callees = {c for s in registry.sinks if s.rule_id == "SEC014"
                                  for c in s.callees}
        self._module_types = self._compute_types(self.module_fn) if self.module_fn else {}
        self._type_cache: Dict[str, Dict[str, Set[str]]] = {}
        self._const_cache: Dict[str, Dict[str, object]] = {}
        self._def_cache: Dict[str, Dict[str, IRInstruction]] = {}
        self._makefunc: Dict[str, Dict[str, str]] = {}
        for fn in self.order:
            self._makefunc[fn.qualname] = {
                i.result: i.meta["func"] for i in fn.all_instructions()
                if i.op == IROpcode.MAKEFUNC and i.result
            }
        self._top_level = {f.qualname for f in ir_module.functions
                           if "." not in f.qualname}
        self._classes = {f.qualname.rsplit(".", 1)[0] for f in ir_module.functions if f.class_name}

    # ── public ─────────────────────────────────────────────────────────

    def run(self) -> "TaintEngine":
        for rnd in range(1, self.max_rounds + 1):
            self.rounds = rnd
            changed = False
            hits: Dict[tuple, Hit] = {}
            api_uses: List[ApiUse] = []
            sql_builds: List[SqlBuild] = []
            self.callers = {}
            self.unconverged_functions = set()
            for fn in self.order:
                run = self._analyze(fn)
                for callee in run.callees:
                    self.callers.setdefault(callee, set()).add(fn.qualname)
                if not run.converged:
                    self.unconverged_functions.add(fn.qualname)
                if fn is self.module_fn:
                    new_globals = {k: v for k, v in run.final_state.items() if v}
                    merged = {k: join_values(self.globals.get(k, {}), v) for k, v in new_globals.items()}
                    merged.update({k: v for k, v in self.globals.items() if k not in merged})
                    if state_sig(merged) != state_sig(self.globals):
                        changed = True
                        self.globals = merged
                else:
                    old = self.summaries[fn.qualname]
                    new = Summary(ret=join_values(old.ret, run.summary.ret),
                                  param_hits=_merge_hits(old.param_hits, run.summary.param_hits))
                    if new.sig() != old.sig():
                        changed = True
                        self.summaries[fn.qualname] = new
                for k, v in run.fields.items():
                    merged = join_values(self.fields.get(k, {}), v)
                    if value_sig(merged) != value_sig(self.fields.get(k, {})):
                        changed = True
                        self.fields[k] = merged
                for q, env in run.closures.items():
                    cur = self.closures.setdefault(q, {})
                    for var, v in env.items():
                        merged = join_values(cur.get(var, {}), v)
                        if value_sig(merged) != value_sig(cur.get(var, {})):
                            changed = True
                            cur[var] = merged
                for h in run.hits:
                    hits.setdefault(h.key(), h)
                api_uses.extend(run.api_uses)
                sql_builds.extend(run.sql_builds)
            self.hits = list(hits.values())
            self.api_uses = api_uses
            self.sql_builds = sql_builds
            if not changed:
                break
        else:
            self.converged = False
        return self

    def entry_param_hits(self) -> List[Hit]:
        """Parameter-origin sink hits of functions with no analysed caller."""
        out = []
        for q, s in self.summaries.items():
            if self.callers.get(q):
                continue
            out.extend(s.param_hits)
        return out

    # ── per-function analysis ──────────────────────────────────────────

    def _analyze(self, fn: IRFunction) -> _FnRun:
        cfg = build_cfg(fn)
        ctx = _FnCtx(self, fn)
        in_states: Dict[str, State] = {label: {} for label in cfg.nodes}
        out_states: Dict[str, State] = {}
        entry_state = ctx.entry_state()
        order = cfg.topological_order()
        worklist = list(order)
        iterations = 0
        max_iter = max(200, 40 * len(cfg.nodes))
        while worklist and iterations < max_iter:
            iterations += 1
            label = worklist.pop(0)
            node = cfg.nodes[label]
            if label == cfg.entry:
                state_in = dict(entry_state)
            else:
                state_in = join_states([ctx.edge_state(p, label, out_states.get(p))
                                        for p in node.predecessors if p in out_states])
            in_states[label] = state_in
            state_out = ctx.transfer_block(node.instructions, state_in, record=False)
            if label not in out_states or state_sig(state_out) != state_sig(out_states[label]):
                out_states[label] = state_out
                for s in node.successors:
                    if s not in worklist:
                        worklist.append(s)
        converged = not worklist

        # Record pass over the fixed point.
        reachable = set(order)
        for label in order:
            ctx.transfer_block(cfg.nodes[label].instructions, in_states[label], record=True)
        exit_state = in_states.get("exit", {})
        ret = ctx.get(exit_state, RETURN_VAR)
        if ctx.is_route and "exit" in reachable:
            ctx.route_return_hits(ret)
        summary = Summary(
            ret=ret,
            param_hits=[h for h in ctx.hits if self.origins[h.origin_key].kind == "param"
                        and self.origins[h.origin_key].function == fn.qualname],
        )
        concrete = [h for h in ctx.hits if self.origins[h.origin_key].kind != "param"
                    or self.origins[h.origin_key].function != fn.qualname]
        final_state = dict(exit_state) if fn is self.module_fn else {}
        return _FnRun(summary, concrete, ctx.api_uses, ctx.sql_builds, ctx.field_writes,
                      ctx.closure_writes, final_state, converged, ctx.callees)

    # ── helpers shared with _FnCtx ─────────────────────────────────────

    def origin(self, key: tuple, **kw) -> tuple:
        if key not in self.origins:
            self.origins[key] = Origin(key=key, **kw)
        return key

    def types_for(self, fn: IRFunction) -> Dict[str, Set[str]]:
        if fn.qualname not in self._type_cache:
            self._type_cache[fn.qualname] = self._compute_types(fn)
        return self._type_cache[fn.qualname]

    def _compute_types(self, fn: Optional[IRFunction]) -> Dict[str, Set[str]]:
        types: Dict[str, Set[str]] = {}
        if fn is None:
            return types
        module_types = getattr(self, "_module_types", {})

        def tget(name):
            return types.get(name) or (module_types.get(name, set()) if name not in fn.locals else set())

        for _ in range(8):
            changed = False
            for instr in fn.all_instructions():
                new: Set[str] = set()
                if instr.op == IROpcode.CALL and instr.call:
                    c = instr.call
                    if c.callee in DB_CREATORS:
                        new.add("db")
                    if c.callee in PATH_CREATORS:
                        new.add("path")
                    if c.method == "cursor" or (c.receiver and c.method in DB_METHODS
                                                and "db" in tget(c.receiver)):
                        new.add("db")
                    if c.receiver and c.method in PATH_METHODS | CANONICALIZER_METHODS \
                            and "path" in tget(c.receiver):
                        new.add("path")
                elif instr.op == IROpcode.ASSIGN and instr.operands:
                    new |= tget(instr.operands[0])
                elif instr.op == IROpcode.BINOP and instr.meta.get("operator") == "Div":
                    if any("path" in tget(o) for o in instr.operands):
                        new.add("path")
                if new and instr.result and not new <= types.get(instr.result, set()):
                    types.setdefault(instr.result, set()).update(new)
                    changed = True
            if not changed:
                break
        return types

    def consts_for(self, fn: IRFunction) -> Dict[str, object]:
        if fn.qualname not in self._const_cache:
            consts: Dict[str, object] = {}
            for instr in fn.all_instructions():
                if instr.op == IROpcode.ASSIGN and "const" in instr.meta and instr.result:
                    try:
                        consts[instr.result] = ast.literal_eval(instr.meta["const"])
                    except Exception:
                        consts[instr.result] = instr.meta["const"]
            self._const_cache[fn.qualname] = consts
        return self._const_cache[fn.qualname]

    def defs_for(self, fn: IRFunction) -> Dict[str, IRInstruction]:
        """Defining instruction of each compiler temporary (temps are assigned once)."""
        if fn.qualname not in self._def_cache:
            self._def_cache[fn.qualname] = {
                i.result: i for i in fn.all_instructions()
                if i.result and re.match(r"^t\d+$", i.result)
            }
        return self._def_cache[fn.qualname]

    def resolve(self, fn: IRFunction, instr: IRInstruction) -> Tuple[Optional[str], int]:
        """Project function called by ``instr`` and the number of bound leading params."""
        c = instr.call
        if c is None:
            return None, 0
        if c.receiver is None:
            name = c.callee
            if instr.meta.get("local_callable") == "1":
                scope: Optional[IRFunction] = fn
                while scope is not None:
                    q = self._makefunc.get(scope.qualname, {}).get(name)
                    if q:
                        return q, 0
                    scope = self.functions.get(scope.enclosing) if scope.enclosing else None
                return None, 0
            scope = fn
            while scope is not None and scope.enclosing:
                scope = self.functions.get(scope.enclosing)
                if scope is not None:
                    q = self._makefunc.get(scope.qualname, {}).get(name)
                    if q:
                        return q, 0
            if name in self._top_level and name in self.functions:
                return name, 0
            if name in self._classes:
                init = f"{name}.__init__"
                return (init, 1) if init in self.functions else (None, 0)
            return None, 0
        recv = instr.meta.get("receiver_name")
        if recv in ("self", "cls") and fn.class_name and c.method:
            cls_prefix = fn.qualname.rsplit(".", 1)[0]
            q = f"{cls_prefix}.{c.method}"
            if q in self.functions:
                return q, (0 if any("staticmethod" in d for d in self.functions[q].decorators) else 1)
        if recv in self._classes and c.method:
            q = f"{recv}.{c.method}"
            if q in self.functions:
                callee = self.functions[q]
                bound = 1 if any("classmethod" in d for d in callee.decorators) else 0
                return q, bound
        return None, 0

    def is_route(self, fn: IRFunction) -> bool:
        return any(self._route_re.search(d + "(") or self._route_re.search(d) for d in fn.decorators)


def _merge_hits(a: List[Hit], b: List[Hit]) -> List[Hit]:
    out: Dict[tuple, Hit] = {}
    for h in a + b:
        k = h.key()
        if k in out:
            prev = out[k]
            out[k] = replace(prev, info=_join_info(prev.info, h.info))
        else:
            out[k] = h
    return list(out.values())


# ---------------------------------------------------------------------------
# Per-function transfer context
# ---------------------------------------------------------------------------

class _FnCtx:
    def __init__(self, engine: TaintEngine, fn: IRFunction):
        self.e = engine
        self.fn = fn
        self.q = fn.qualname
        self.types = engine.types_for(fn)
        self.consts = engine.consts_for(fn)
        self.defs = engine.defs_for(fn)
        self.chains: Dict[str, str] = {}
        self.is_route = engine.is_route(fn)
        self.hits: List[Hit] = []
        self.api_uses: List[ApiUse] = []
        self.sql_builds: List[SqlBuild] = []
        self.field_writes: Dict[Tuple[str, str], TaintValue] = {}
        self.closure_writes: Dict[str, Dict[str, TaintValue]] = {}
        self.callees: Set[str] = set()
        self._recorded: Set[tuple] = set()
        self._cls = fn.qualname.rsplit(".", 1)[0] if fn.class_name else None

    # ── state access ────────────────────────────────────────────────────

    def get(self, state: State, name: Optional[str]) -> TaintValue:
        if not name:
            return EMPTY
        if name in state:
            return state[name]
        if name in self.fn.locals or re.match(r"^t\d+$", name) or name == RETURN_VAR:
            return EMPTY
        scope: Optional[IRFunction] = self.fn
        while scope is not None:
            env = self.e.closures.get(scope.qualname, {})
            if name in env:
                return env[name]
            if name in scope.locals and scope is not self.fn:
                break
            scope = self.e.functions.get(scope.enclosing) if scope.enclosing else None
        if self.fn is not self.e.module_fn:
            return self.e.globals.get(name, EMPTY)
        return EMPTY

    def step(self, instr: IRInstruction, kind: str, text: Optional[str] = None) -> Step:
        return Step(instr.lineno, instr.col, kind, text or instr.meta.get("src", ""), self.q)

    def entry_state(self) -> State:
        state: State = {}
        decl = self.fn.source_lineno
        for i, p in enumerate(self.fn.params):
            if p in ("self", "cls") and i == 0 and self.fn.is_method:
                continue
            if self.is_route:
                key = self.e.origin(("src", self.q, "route", p), kind="source",
                                    description=f"HTTP route parameter '{p}'", trust="remote",
                                    lineno=decl, col=0, function=self.q)
                trace = (Step(decl, 0, "source", f"'{p}' is bound from the request URL/query "
                              f"(route handler {self.q})", self.q),)
            else:
                key = self.e.origin(("param", self.q, i), kind="param",
                                    description=f"parameter '{p}' of {self.q}()", trust="unknown",
                                    lineno=decl, col=0, function=self.q, param_index=i,
                                    param_name=p)
                trace = (Step(decl, 0, "param", f"enters {self.q}() as parameter '{p}'", self.q),)
            state[p] = {key: TaintInfo(ALL_CONTEXTS, trace=trace)}
        return state

    def edge_state(self, pred_label: str, succ_label: str, out: Optional[State]) -> State:
        if out is None:
            return {}
        pred = self.fn.get_block(pred_label)
        term = pred.instructions[-1] if pred and pred.instructions else None
        if term is None or term.op != IROpcode.BRANCH or not term.refinements:
            return out
        if term.meta.get("kind") != "if":
            return out
        true_l, false_l = term.operands[1], term.operands[2]
        if succ_label not in (true_l, false_l) or true_l == false_l:
            return out
        on_true = succ_label == true_l
        state = dict(out)
        for r in term.refinements:
            if r.on_true != on_true:
                continue
            v = self.get(state, r.var)
            if not v:
                continue
            if r.kind == "allowlist":
                state[r.var] = {}
            elif r.kind.startswith("charset:"):
                ctxs = frozenset(r.kind.split(":", 1)[1].split(","))
                state[r.var] = remove_contexts(v, ctxs)
            elif r.kind == "path_prefix":
                new: TaintValue = {}
                for k, info in v.items():
                    if "canonical" in info.markers:
                        left = info.contexts - {"path"}
                        if left:
                            new[k] = replace(info, contexts=left)
                    else:
                        note = Step(term.lineno, term.col, "check",
                                    f"prefix check on a non-canonicalised path does not stop "
                                    f"'..' traversal: {term.meta.get('src', '')}", self.q)
                        new[k] = replace(info, trace=info.trace + (note,))
                state[r.var] = new
        return state

    # ── transfer ────────────────────────────────────────────────────────

    def transfer_block(self, instrs: List[IRInstruction], state_in: State, record: bool) -> State:
        state = dict(state_in)
        for instr in instrs:
            self.transfer(instr, state, record)
        return state

    def _ops_value(self, state: State, instr: IRInstruction) -> TaintValue:
        n = instr.meta.get("taint_ops")
        ops = instr.operands if n is None else instr.operands[:int(n)]
        return join_values(*[self.get(state, o) for o in ops])

    def transfer(self, instr: IRInstruction, state: State, record: bool) -> None:
        op = instr.op
        res = instr.result
        if op in (IROpcode.LABEL, IROpcode.JUMP, IROpcode.NOP, IROpcode.BRANCH,
                  IROpcode.RETURN, IROpcode.LOAD, IROpcode.PHI):
            return
        if op == IROpcode.ASSIGN:
            if "const" in instr.meta:
                state[res] = {}
                return
            v = self.get(state, instr.operands[0]) if instr.operands else {}
            if v and res and _is_user(res):
                v = add_step(v, self.step(instr, "assign"))
            elif v and res == RETURN_VAR:
                v = add_step(v, self.step(instr, "return", f"returned: {instr.meta.get('src', '')}"))
            state[res] = v
            return
        if op in (IROpcode.BINOP, IROpcode.UNOP, IROpcode.BUILD):
            v = drop_markers(self._ops_value(state, instr))
            if v and res and _is_user(res):
                v = add_step(v, self.step(instr, "assign"))
            state[res] = v
            if record and v:
                self._maybe_sql_build(instr, v)
            return
        if op == IROpcode.SUBSCR:
            v = self.get(state, instr.operands[0]) if instr.operands else {}
            state[res] = v if instr.meta.get("unpack") or instr.meta.get("index") == "iter" \
                else drop_markers(v)
            return
        if op == IROpcode.ATTR:
            state[res] = self._attr(instr, state)
            return
        if op == IROpcode.STORE:
            self._store(instr, state, record)
            return
        if op == IROpcode.MAKEFUNC:
            if record:
                env = self.closure_writes.setdefault(instr.meta.get("func", ""), {})
                for var in instr.operands:
                    v = self.get(state, var)
                    if v:
                        env[var] = join_values(env.get(var, {}), v)
            state[res] = {}
            return
        if op == IROpcode.CALL:
            self._call(instr, state, record)
            return

    def _attr(self, instr: IRInstruction, state: State) -> TaintValue:
        path = instr.meta.get("path")
        if path:
            self.chains[instr.result] = path
            src = self._source_for(path, instr, is_call=False)
            return src or {}
        base = instr.operands[0] if instr.operands else ""
        attr = instr.meta.get("attr", "")
        base_name = instr.meta.get("base_name")
        chain = f"{base_name}.{attr}" if base_name else (
            f"{self.chains[base]}.{attr}" if base in self.chains else "")
        if chain:
            self.chains[instr.result] = chain
        if base_name and f"{base_name}.{attr}" in state:
            v = state[f"{base_name}.{attr}"]
        else:
            v = self.get(state, base)
        if base_name in ("self", "cls") and self._cls:
            v = join_values(v, self.e.fields.get((self._cls, attr), {}))
        if chain:
            src = self._source_for(chain, instr, is_call=False, heuristic_only=True)
            if src:
                # The request-data attribute *is* the untrusted value; the request
                # object's own (parameter) taint would only duplicate the flow.
                return src
        return v

    def _store(self, instr: IRInstruction, state: State, record: bool) -> None:
        val = self.get(state, instr.operands[0]) if instr.operands else {}
        kind = instr.meta.get("kind")
        base_name = instr.meta.get("base_name")
        if kind == "attr" and base_name:
            key = f"{base_name}.{instr.meta.get('attr', '')}"
            v = add_step(val, self.step(instr, "store")) if val else val
            state[key] = v
            if record and base_name in ("self", "cls") and self._cls and v:
                fk = (self._cls, instr.meta.get("attr", ""))
                self.field_writes[fk] = join_values(self.field_writes.get(fk, {}), v)
        elif kind == "subscr" and base_name and val:
            state[base_name] = join_values(self.get(state, base_name),
                                           add_step(val, self.step(instr, "store")))

    # ── sources ─────────────────────────────────────────────────────────

    def _source_for(self, name: str, instr: IRInstruction, is_call: bool,
                    heuristic_only: bool = False) -> TaintValue:
        for spec in self.e.reg.sources:
            kind, _, pat = spec.match.partition(":")
            if heuristic_only and kind != "chain":
                continue
            if kind == "prefix":
                ok = name == pat.rstrip(".") or name.startswith(pat if pat.endswith(".") else pat + ".") \
                    or name == pat
            elif kind == "call":
                ok = is_call and name == pat
            elif kind == "chain":
                ok = heuristic_only and re.search(pat, name) is not None
            else:
                ok = False
            if not ok:
                continue
            key = self.e.origin(("src", self.q, instr.uid), kind="source",
                                description=f"{spec.description} ({name})", trust=spec.trust,
                                lineno=instr.lineno, col=instr.col, function=self.q,
                                heuristic=spec.heuristic)
            step = Step(instr.lineno, instr.col, "source",
                        f"untrusted {spec.description}: {instr.meta.get('src', name)}", self.q)
            return {key: TaintInfo(ALL_CONTEXTS, trace=(step,))}
        return {}

    # ── calls ───────────────────────────────────────────────────────────

    def _call(self, instr: IRInstruction, state: State, record: bool) -> None:
        c = instr.call
        res = instr.result
        recv_v = self.get(state, c.receiver) if c.receiver else {}
        arg_vs = [self.get(state, a) for a in c.args]
        kw_vs = {k: self.get(state, v) for k, v in c.keywords.items()}
        star_vs = [self.get(state, s) for s in c.star_args]
        inputs = join_values(recv_v, *arg_vs, *kw_vs.values(), *star_vs)
        callee = c.callee
        label = callee or c.raw_callee
        is_method = c.receiver is not None or bool(c.method)
        if callee:
            self.chains[res] = callee

        result: TaintValue
        src = self._source_for(callee, instr, is_call=True) if callee and c.receiver is None else {}
        qual, bound = self.e.resolve(self.fn, instr)
        sanitizer = self.e.reg.sanitizer_for(callee if c.receiver is None else "", c.method,
                                             c.receiver is not None)
        if src:
            result = src
        elif qual is not None:
            binding = self._bind(qual, bound, c, recv_v, arg_vs, kw_vs, star_vs)
            result = self._instantiate(qual, binding, instr)
            if record:
                self.callees.add(qual)
                self._instantiate_hits(qual, binding, instr)
                self._instantiate_envs(qual, binding, instr)
        elif sanitizer is not None:
            base = recv_v if (c.receiver and sanitizer.methods) else join_values(*arg_vs, *kw_vs.values(), *star_vs)
            missing = sorted(ALL_CONTEXTS - sanitizer.clears)
            text = (f"{label}() — {sanitizer.note}; removes taint for "
                    f"{', '.join(sorted(sanitizer.clears)) if sanitizer.clears != ALL_CONTEXTS else 'all contexts'}")
            if missing and sanitizer.clears != ALL_CONTEXTS:
                text += f" (still dangerous for {', '.join(missing)})"
            result = remove_contexts(base, sanitizer.clears, self.step(instr, "sanitizer", text))
            result = drop_markers(result)
        elif callee in self.e.reg.canonicalizers or (c.receiver and c.method in CANONICALIZER_METHODS):
            result = {k: replace(i, markers=i.markers | {"canonical"}) for k, i in inputs.items()}
            result = add_step(result, self.step(instr, "sanitizer",
                                                f"{label}() canonicalises the path (no boundary "
                                                f"check yet)")) if result else result
        elif callee in PROPAGATOR_CALLEES or (is_method and c.method in PROPAGATOR_METHODS):
            result = drop_markers(inputs)
        elif is_method and c.method in MUTATOR_METHODS:
            result = {}
            rn = instr.meta.get("receiver_name")
            added = join_values(*arg_vs, *kw_vs.values(), *star_vs)
            if rn and added:
                state[rn] = join_values(self.get(state, rn), add_step(added, self.step(instr, "store")))
        else:
            if inputs:
                why = f"unresolved call {label}()"
                result = {k: replace(i, unc=i.unc | {why}, markers=frozenset())
                          for k, i in inputs.items()}
                result = add_step(result, self.step(instr, "call",
                                                    f"passes through unresolved call {label}()"))
            else:
                result = {}
        if result and callee and callee in self.e.html_sink_callees:
            # The response/markup object was checked as an HTML sink here; returning it from
            # a route is the same flow and must not be reported twice.
            result = remove_contexts(result, frozenset({"html"}))
        state[res] = result
        if record:
            self._check_sinks(instr, state, recv_v, arg_vs, kw_vs)
            if c.method == "format" and c.receiver and result:
                tmpl = self.consts.get(c.receiver)
                if isinstance(tmpl, str) and _SQLISH.search(tmpl):
                    keys = tuple(k for k, i in result.items() if "sql" in i.contexts)
                    if keys:
                        self.sql_builds.append(SqlBuild(self.q, instr.lineno, instr.col, keys,
                                                        instr.meta.get("src", "")))

    def _bind(self, qual, bound, c, recv_v, arg_vs, kw_vs, star_vs) -> Dict[int, TaintValue]:
        callee = self.e.functions[qual]
        params = callee.params
        binding: Dict[int, TaintValue] = {}
        if bound and params:
            binding[0] = recv_v
        for i, v in enumerate(arg_vs):
            idx = bound + i
            if idx < len(params):
                binding[idx] = v
            elif params:
                binding[len(params) - 1] = join_values(binding.get(len(params) - 1, {}), v)
        for k, v in kw_vs.items():
            if k in params:
                binding[params.index(k)] = v
            elif params:
                binding[len(params) - 1] = join_values(binding.get(len(params) - 1, {}), v)
        if star_vs:
            star = join_values(*star_vs)
            star = {k: replace(i, unc=i.unc | {"*args/**kwargs bound to every parameter"})
                    for k, i in star.items()}
            for idx in range(bound, len(params)):
                binding[idx] = join_values(binding.get(idx, {}), star)
        return binding

    def _instantiate(self, qual: str, binding: Dict[int, TaintValue], instr: IRInstruction) -> TaintValue:
        summ = self.e.summaries.get(qual)
        if summ is None:
            return {}
        out: TaintValue = {}
        call_step = self.step(instr, "call", f"calls {qual}(): {instr.meta.get('src', '')}")
        ret_step = self.step(instr, "return", f"value returned from {qual}()")
        for okey, inf in summ.ret.items():
            o = self.e.origins.get(okey)
            if o is not None and o.kind == "param" and o.function == qual:
                for akey, ainf in binding.get(o.param_index, {}).items():
                    ctx = ainf.contexts & inf.contexts
                    if not ctx:
                        continue
                    new = TaintInfo(ctx, inf.markers, ainf.unc | inf.unc,
                                    ainf.trace + (call_step,) + inf.trace + (ret_step,))
                    out[akey] = _join_info(out[akey], new) if akey in out else new
            else:
                new = TaintInfo(inf.contexts, inf.markers, inf.unc, inf.trace + (ret_step,))
                out[okey] = _join_info(out[okey], new) if okey in out else new
        return out

    def _instantiate_hits(self, qual: str, binding: Dict[int, TaintValue], instr: IRInstruction) -> None:
        summ = self.e.summaries.get(qual)
        if summ is None:
            return
        call_step = self.step(instr, "call", f"calls {qual}(): {instr.meta.get('src', '')}")
        for h in summ.param_hits:
            o = self.e.origins[h.origin_key]
            rule = self.e.reg.rules[h.rule_id]
            for akey, ainf in binding.get(o.param_index, {}).items():
                ctx = ainf.contexts & h.info.contexts
                if rule.context not in ctx:
                    continue
                info = TaintInfo(ctx, h.info.markers, ainf.unc | h.info.unc,
                                 ainf.trace + (call_step,) + h.info.trace)
                self._add_hit(replace(h, origin_key=akey, info=info, via=(self.q,) + h.via))

    def _instantiate_envs(self, qual: str, binding: Dict[int, TaintValue], instr: IRInstruction) -> None:
        """
        Fields (``self.x = param``) and closure environments of functions nested in
        ``qual`` may hold ``qual``'s symbolic parameter origins.  Replace them with
        this call site's argument taint so the flow continues with real origins.
        """
        call_step = self.step(instr, "call", f"calls {qual}(): {instr.meta.get('src', '')}")

        def inst(v: TaintValue) -> TaintValue:
            out: TaintValue = {}
            for okey, inf in v.items():
                o = self.e.origins.get(okey)
                if o is None or o.kind != "param" or o.function != qual:
                    continue
                for akey, ainf in binding.get(o.param_index, {}).items():
                    ctx = ainf.contexts & inf.contexts
                    if ctx:
                        new = TaintInfo(ctx, inf.markers, ainf.unc | inf.unc,
                                        ainf.trace + (call_step,) + inf.trace)
                        out[akey] = _join_info(out[akey], new) if akey in out else new
            return out

        for fk, fv in list(self.e.fields.items()):
            add = inst(fv)
            if add:
                self.field_writes[fk] = join_values(self.field_writes.get(fk, {}), add)
        for inner, env in list(self.e.closures.items()):
            if not inner.startswith(qual + "."):
                continue
            for var, v in env.items():
                add = inst(v)
                if add:
                    cur = self.closure_writes.setdefault(inner, {})
                    cur[var] = join_values(cur.get(var, {}), add)

    def _add_hit(self, hit: Hit) -> None:
        k = hit.key()
        if k in self._recorded:
            for i, h in enumerate(self.hits):
                if h.key() == k:
                    self.hits[i] = replace(h, info=_join_info(h.info, hit.info))
            return
        self._recorded.add(k)
        self.hits.append(hit)

    # ── sinks ───────────────────────────────────────────────────────────

    def _is_const(self, operand: str, depth: int = 0) -> bool:
        if operand in self.consts:
            return True
        d = self.defs.get(operand)
        if d is None or depth > 6:
            return False
        if d.op in (IROpcode.BINOP, IROpcode.BUILD) and d.operands:
            return all(self._is_const(o, depth + 1) for o in d.operands)
        return False

    def _check_sinks(self, instr, state, recv_v, arg_vs, kw_vs) -> None:
        c = instr.call
        for spec in self.e.reg.sinks:
            resolution = None
            if c.receiver is None and c.callee and c.callee in spec.callees:
                resolution = "exact"
            elif c.receiver is not None and c.method and c.method in spec.methods:
                rtypes = self.types.get(c.receiver, set()) | (
                    self.e._module_types.get(instr.meta.get("receiver_name", ""), set())
                    if instr.meta.get("receiver_name") not in self.fn.locals else set())
                if spec.receiver is None or spec.receiver in rtypes:
                    resolution = "exact" if spec.receiver else "method-name"
                elif spec.method_only_ok:
                    resolution = "method-name"
            if resolution is None:
                continue
            for operand, role, factors, sev in self._dangerous_operands(spec, c, instr):
                v = self.get(state, operand)
                rule = self.e.reg.rules[spec.rule_id]
                hit_any = False
                for okey, info in v.items():
                    if rule.context not in info.contexts:
                        continue
                    hit_any = True
                    sink_step = self.step(instr, "sink",
                                          f"reaches {spec.operation} {c.raw_callee}() as {role}")
                    self._add_hit(Hit(
                        rule_id=spec.rule_id, function=self.q, sink_uid=instr.uid,
                        lineno=instr.lineno, col=instr.col, sink_name=c.callee or c.raw_callee,
                        operation=spec.operation, operand_role=role, origin_key=okey,
                        info=replace(info, trace=info.trace + (sink_step,)),
                        resolution=resolution, factors=tuple(factors), guards=tuple(instr.guards),
                        severity_override=sev,
                    ))
                if not hit_any and spec.api_fallback and not self._is_const(operand):
                    self.api_uses.append(ApiUse(spec.rule_id, self.q, instr.uid, instr.lineno,
                                                instr.col, c.callee or c.raw_callee,
                                                spec.operation, tuple(instr.guards)))

    def _dangerous_operands(self, spec: SinkSpec, c, instr):
        """Yield (operand, role, factors, severity_override) for a matched sink."""
        out = []
        if spec.use_receiver and c.receiver:
            out.append((c.receiver, "receiver path", [], None))
        for i in spec.args:
            if i < len(c.args):
                out.append((c.args[i], f"argument {i + 1}", [], None))
        for k in spec.kwargs:
            if k in c.keywords:
                out.append((c.keywords[k], f"keyword '{k}'", [], None))
        if spec.condition == "subprocess":
            shell = c.const_kwargs.get("shell")
            if shell == "True":
                return [(o, r + " (shell=True)", f, s) for o, r, f, s in out]
            if "shell" in c.keywords and shell is None:
                return [(o, r + " (shell= not a literal)", ["medium:shell= argument is not a "
                                                           "literal, shell use is undecidable"], s)
                        for o, r, f, s in out]
            prog = []
            for o, r, f, s in out:
                d = self.defs.get(o)
                if d is not None and d.op == IROpcode.BUILD and d.meta.get("kind") in ("list", "tuple"):
                    if d.operands:
                        prog.append((d.operands[0], "executable (argv[0])",
                                     ["note:no shell is used; the attacker selects the program"],
                                     "high"))
                else:
                    prog.append((o, r + " (no shell: string names the executable)",
                                 ["note:no shell is used; the attacker selects the program"],
                                 "high"))
            return prog
        if spec.condition == "mimetype":
            mt = c.const_kwargs.get("mimetype") or c.const_kwargs.get("content_type")
            if mt is not None and "html" not in mt.lower():
                return []
            return out
        if spec.condition == "exec_program":
            return [(o, "executable", ["note:the attacker selects the program"], "high")
                    for o, r, f, s in out]
        if spec.condition == "yaml":
            if c.callee in ("yaml.load", "yaml.load_all"):
                loader = c.const_kwargs.get("Loader")
                if loader is None and len(c.args) > 1:
                    d = self.defs.get(c.args[1])
                    loader = d.meta.get("path") if d is not None else None
                if loader in SAFE_YAML_LOADERS:
                    return []
            return out
        return out

    def route_return_hits(self, ret: TaintValue) -> None:
        for okey, info in ret.items():
            if "html" not in info.contexts:
                continue
            exit_block = self.fn.get_block("exit")
            ret_instr = exit_block.instructions[-1]
            ret_steps = [s for s in info.trace if s.kind == "return" and s.function == self.q]
            line, col = (ret_steps[-1].lineno, ret_steps[-1].col) if ret_steps else \
                (ret_instr.lineno, 0)
            step = Step(line, col, "sink",
                        f"returned as the HTTP response body of route handler {self.q}()", self.q)
            self._add_hit(Hit(
                rule_id="SEC014", function=self.q, sink_uid=ret_instr.uid, lineno=line,
                col=col, sink_name=f"return from {self.q}()", operation="HTTP response body",
                operand_role="return value", origin_key=okey,
                info=replace(info, trace=info.trace + (step,)), resolution="exact",
                factors=("medium:the route's response content type is assumed to be text/html",),
            ))

    def _maybe_sql_build(self, instr: IRInstruction, v: TaintValue) -> None:
        texts = []
        if instr.op == IROpcode.BUILD and instr.meta.get("kind") == "fstring":
            texts.append(instr.meta.get("template", ""))
        elif instr.op == IROpcode.BINOP and instr.meta.get("operator") in ("Add", "Mod"):
            for o in instr.operands:
                cv = self.consts.get(o)
                if isinstance(cv, str):
                    texts.append(cv)
        if not any(_SQLISH.search(t) for t in texts):
            return
        keys = tuple(k for k, i in v.items() if "sql" in i.contexts)
        if keys:
            self.sql_builds.append(SqlBuild(self.q, instr.lineno, instr.col, keys,
                                            instr.meta.get("src", "")))


def _is_user(name: str) -> bool:
    return not re.match(r"^t\d+$", name) and name != RETURN_VAR


def run_taint(ir_module: IRModule, registry: Registry = DEFAULT_REGISTRY) -> TaintEngine:
    return TaintEngine(ir_module, registry).run()
