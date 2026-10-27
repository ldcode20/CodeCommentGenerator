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
from ..ir.ir_nodes import CallInfo, IRFunction, IRInstruction, IRModule, IROpcode
from ..ir.lowering import MODULE_QUALNAME, RETURN_VAR
from . import values as cv
from .values import NOVAL
from .rules import (
    ALL_CONTEXTS, CANONICALIZER_METHODS, DB_CREATORS, DB_METHODS, DEFAULT_REGISTRY,
    MUTATOR_METHODS, PATH_CREATORS, RECEIVER_ONLY_METHODS, SANDBOX_CREATORS, SESSION_STORE_PATTERN, PATH_METHODS, PROPAGATOR_CALLEES, PROPAGATOR_METHODS,
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
    if a is b:
        return a
    trace = a.trace if len(a.trace) <= len(b.trace) else b.trace
    return TaintInfo(a.contexts | b.contexts, a.markers & b.markers, a.unc | b.unc, trace)


def join_values(*values: TaintValue) -> TaintValue:
    nonempty = [v for v in values if v]
    if not nonempty:
        return EMPTY
    if len(nonempty) == 1 or all(v is nonempty[0] for v in nonempty):
        return nonempty[0]
    out: TaintValue = {}
    for v in nonempty:
        for k, info in v.items():
            out[k] = _join_info(out[k], info) if k in out else info
    return out


def value_sig(v: TaintValue) -> frozenset:
    return frozenset((k, i.contexts, i.markers, i.unc) for k, i in v.items())


# Auxiliary facts live in the state under "#c:<var>" (known constant: ("c", value)) and
# "#s:<var>" (container shape: ("l", ((taint, const), ...)) or ("d", ((key, taint, const), ...))).
def _cval_sig(c) -> str:
    return "?" if c is NOVAL else repr(c)


MAX_CONST_SET = 16


def aux_sig(a) -> tuple:
    if a[0] == "a":
        return ("a", tuple(sorted(a[1])))
    if a[0] == "cs":
        return ("cs", tuple(sorted(f"{type(x).__name__}:{x!r}" for x in a[1])))
    if a[0] == "f":
        return ("f", repr(a[1]))
    if a[0] == "c":
        return ("c", type(a[1]).__name__, repr(a[1]))
    if a[0] == "l":
        return ("l", tuple((value_sig(t), _cval_sig(c)) for t, c in a[1]))
    return ("d", tuple((repr(k), value_sig(t), _cval_sig(c)) for k, t, c in a[1]))


def _same_const(a, b) -> bool:
    return type(a) is type(b) and a == b


def join_aux(values: list):
    first = values[0]
    if all(v is first for v in values):
        return first
    if all(v[0] in ("c", "cs") for v in values):
        if first[0] == "c" and all(v[0] == "c" and _same_const(v[1], first[1]) for v in values):
            return first
        # Different constants on different paths: keep the (small) set of possible literals.
        members = set()
        try:
            for v in values:
                members |= set(v[1]) if v[0] == "cs" else {(type(v[1]).__name__, v[1])}
        except TypeError:
            return None
        return ("cs", frozenset(members)) if len(members) <= MAX_CONST_SET else None
    if any(v[0] != first[0] for v in values):
        return None
    if first[0] == "f":           # callable descriptor: kept only if every path agrees
        return first if all(v[1] == first[1] for v in values) else None
    if first[0] == "l":
        if any(len(v[1]) != len(first[1]) for v in values):
            return None
        elems = []
        for i in range(len(first[1])):
            ts = [v[1][i][0] for v in values]
            cs = [v[1][i][1] for v in values]
            c = cs[0] if all(x is not NOVAL and _same_const(x, cs[0]) for x in cs) else NOVAL
            elems.append((join_values(*ts), c))
        return ("l", tuple(elems))
    keys = [k for k, _, _ in first[1]]
    key_set = {repr(k) for k in keys}
    if any({repr(k) for k, _, _ in v[1]} != key_set or len(v[1]) != len(keys) for v in values):
        return None
    by_key = [{repr(k): (t, c) for k, t, c in v[1]} for v in values]
    elems = []
    for k in keys:
        ts = [m[repr(k)][0] for m in by_key]
        cs = [m[repr(k)][1] for m in by_key]
        c = cs[0] if all(x is not NOVAL and _same_const(x, cs[0]) for x in cs) else NOVAL
        elems.append((k, join_values(*ts), c))
    return ("d", tuple(elems))


def state_sig(s: State) -> frozenset:
    return frozenset((var, aux_sig(v) if var[:1] == "#" else value_sig(v)) for var, v in s.items() if v)


def join_states(states: List[State]) -> State:
    if not states:
        return {}
    if len(states) == 1:
        return dict(states[0])
    out: State = dict(states[0])
    for s in states[1:]:
        for var, v in s.items():
            if var[:1] == "#":
                continue
            cur = out.get(var)
            if cur is None:
                out[var] = v
            elif cur is not v:
                out[var] = join_values(cur, v)
    # Alias groups ("#a:x") are may-alias facts: union over incoming paths.
    for s in states:
        for var, v in s.items():
            if var[:3] == "#a:":
                cur = out.get(var)
                out[var] = ("a", (cur[1] if cur else frozenset()) | v[1])
    for var in [k for k in out if k[:1] == "#" and k[:3] != "#a:"]:
        vals = [s.get(var) for s in states]
        joined = join_aux(vals) if all(v is not None for v in vals) else None
        if joined is None:
            del out[var]
        else:
            out[var] = joined
    # A strong-update key ("obj.attr") is only definitely untainted if every path set it.
    for var in [k for k, v in out.items() if not v and "." in k]:
        if any(var not in s for s in states):
            del out[var]
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

_CONFIGPARSER_TYPES = {"configparser.ConfigParser", "configparser.RawConfigParser",
                       "configparser.SafeConfigParser"}

_SQLISH = re.compile(r"^\s*(select\s.+\sfrom\s|insert\s+into\s|update\s+\S+\s+set\s|delete\s+from\s"
                     r"|replace\s+into\s|create\s+table\s|drop\s+table\s)", re.IGNORECASE | re.DOTALL)
_TEMPLATE_CHAIN = re.compile(r"\{\}|%s|\{\w*\}")


class TaintEngine:
    """
    Taint analysis over one module (single-file mode) or several modules (project mode,
    see ``security.project``). In project mode function qualnames carry their module
    prefix (``pkg.mod.func``) and every module keeps its own globals and types.
    """

    def __init__(self, ir_module, registry: Registry = DEFAULT_REGISTRY,
                 max_rounds: int = MAX_ROUNDS):
        mods: List[IRModule] = list(ir_module) if isinstance(ir_module, (list, tuple)) else [ir_module]
        self.modules = mods
        self.m = mods[0]
        self.reg = registry
        self.max_rounds = max_rounds
        self.functions: Dict[str, IRFunction] = {f.qualname: f for m in mods for f in m.functions}
        self.module_fns: Dict[str, IRFunction] = {m.module_name: m.module_body for m in mods
                                                  if m.module_body is not None}
        self._module_body_ids = {id(f) for f in self.module_fns.values()}
        self.module_fn = mods[0].module_body
        self.order: List[IRFunction] = list(self.module_fns.values()) + \
            [f for m in mods for f in m.functions]
        self.summaries: Dict[str, Summary] = {q: Summary() for q in self.functions}
        self.fields: Dict[Tuple[str, str], TaintValue] = {}
        self.closures: Dict[str, Dict[str, TaintValue]] = {}
        self.globals: Dict[str, State] = {name: {} for name in self.module_fns}
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
        self._module_types: Dict[str, Dict[str, Set[str]]] = {}
        self._type_cache: Dict[str, Dict[str, Set[str]]] = {}
        self._types_in_progress: Set[str] = set()
        self._const_cache: Dict[str, Dict[str, object]] = {}
        self._def_cache: Dict[str, Dict[str, IRInstruction]] = {}
        self._makefunc: Dict[str, Dict[str, str]] = {}
        for fn in self.order:
            self._makefunc[fn.qualname] = {
                i.result: i.meta["func"] for i in fn.all_instructions()
                if i.op == IROpcode.MAKEFUNC and i.result
            }
        self._top_level = {f.qualname for f in self.functions.values()
                           if f.enclosing is None and f.class_name is None}
        self._classes = {f.qualname.rsplit(".", 1)[0] for f in self.functions.values() if f.class_name}
        for m in mods:      # classes without methods still construct instances
            for cls in m.classes:
                self._classes.add(cls)
        for name, body in self.module_fns.items():
            self._module_types[name] = self._compute_types(body)

    @staticmethod
    def qn(module: str, name: str) -> str:
        return f"{module}.{name}" if module else name

    def function_by_qualname(self, qualname: str) -> Optional[IRFunction]:
        fn = self.functions.get(qualname)
        if fn is None:
            fn = next((m for m in self.module_fns.values() if m.qualname == qualname), None)
        return fn

    def is_module_body(self, fn: Optional[IRFunction]) -> bool:
        return fn is not None and id(fn) in self._module_body_ids

    def module_types(self, module: str) -> Dict[str, Set[str]]:
        return self._module_types.get(module, {})

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
                if self.is_module_body(fn):
                    old_g = self.globals.get(fn.module, {})
                    new_globals = {k: v for k, v in run.final_state.items() if v and k[:1] != "#"}
                    merged = {k: join_values(old_g.get(k, {}), v) for k, v in new_globals.items()}
                    merged.update({k: v for k, v in old_g.items() if k not in merged})
                    if state_sig(merged) != state_sig(old_g):
                        changed = True
                        self.globals[fn.module] = merged
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
        processed: Set[str] = set()
        iterations = 0
        max_iter = max(200, 40 * len(cfg.nodes))
        while worklist and iterations < max_iter:
            iterations += 1
            label = worklist.pop(0)
            node = cfg.nodes[label]
            if label == cfg.entry:
                state_in = dict(entry_state)
            else:
                preds = [p for p in node.predecessors
                         if p in out_states and ctx.feasible(p, label, out_states[p])]
                if not preds:
                    continue      # not reachable on any feasible path (yet)
                state_in = join_states([ctx.edge_state(p, label, out_states[p]) for p in preds])
            in_states[label] = state_in
            processed.add(label)
            state_out = ctx.prune(ctx.transfer_block(node.instructions, state_in, record=False))
            if label not in out_states or state_sig(state_out) != state_sig(out_states[label]):
                out_states[label] = state_out
                for s in node.successors:
                    if s not in worklist:
                        worklist.append(s)
        converged = not worklist

        # Record pass over the fixed point (blocks reachable along feasible edges only).
        reachable = processed
        for label in order:
            if label in processed:
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
        final_state = dict(exit_state) if self.is_module_body(fn) else {}
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
        module_types = self._module_types.get(fn.module, {})

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
                    if c.callee in SANDBOX_CREATORS:
                        new.add("jinja_sandbox")
                    if c.method == "cursor" or (c.receiver and c.method in DB_METHODS
                                                and "db" in tget(c.receiver)):
                        new.add("db")
                    if c.receiver and c.method in PATH_METHODS | CANONICALIZER_METHODS \
                            and "path" in tget(c.receiver):
                        new.add("path")
                    # Project classes: constructor calls and functions returning instances.
                    for q, _bound in self._resolve(fn, instr, tget):
                        if q.endswith(".__init__") and q[:-9] in self._classes:
                            new.add("class:" + q[:-9])
                        else:
                            new |= self.return_classes(q)
                    if c.receiver is None and c.callee:
                        for cls in (self.qn(fn.module, c.callee), c.callee):
                            if cls in self._classes and f"{cls}.__init__" not in self.functions:
                                new.add("class:" + cls)     # class without __init__
                                break
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

    def return_classes(self, qual: str) -> Set[str]:
        """Project classes whose instances function ``qual`` may return."""
        fn = self.functions.get(qual)
        if fn is None or qual in self._types_in_progress:
            return set()
        self._types_in_progress.add(qual)
        try:
            return {t for t in self.types_for(fn).get(RETURN_VAR, set()) if t.startswith("class:")}
        finally:
            self._types_in_progress.discard(qual)

    def consts_for(self, fn: IRFunction) -> Dict[str, object]:
        if fn.qualname not in self._const_cache:
            consts: Dict[str, object] = {}
            for instr in fn.all_instructions():
                if instr.op == IROpcode.ASSIGN and "const" in instr.meta and instr.result:
                    try:
                        consts[instr.result] = ast.literal_eval(instr.meta["const"])
                    except Exception:
                        pass   # not a literal: value unknown
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

    def resolve(self, fn: IRFunction, instr: IRInstruction) -> List[Tuple[str, int]]:
        """Project functions ``instr`` may call, each with its number of bound leading params."""
        types = self.types_for(fn)
        mtypes = self.module_types(fn.module)
        return self._resolve(fn, instr, lambda name: types.get(name, set()) or (
            mtypes.get(name, set()) if name not in fn.locals else set()))

    @staticmethod
    def _bound(target: IRFunction, default: int) -> int:
        if any("staticmethod" in d for d in target.decorators):
            return 0
        if any("classmethod" in d for d in target.decorators):
            return 1
        return default

    def _resolve(self, fn: IRFunction, instr: IRInstruction, tget) -> List[Tuple[str, int]]:
        c = instr.call
        if c is None:
            return []
        if c.receiver is None:
            name = c.callee
            if instr.meta.get("local_callable") == "1":
                scope: Optional[IRFunction] = fn
                while scope is not None:
                    q = self._makefunc.get(scope.qualname, {}).get(name)
                    if q:
                        return [(q, 0)]
                    scope = self.functions.get(scope.enclosing) if scope.enclosing else None
                return []
            scope = fn
            while scope is not None and scope.enclosing:
                scope = self.functions.get(scope.enclosing)
                if scope is not None:
                    q = self._makefunc.get(scope.qualname, {}).get(name)
                    if q:
                        return [(q, 0)]
            for cand in (self.qn(fn.module, name), name):
                if cand in self._top_level:
                    return [(cand, 0)]
                if cand in self._classes:
                    init = f"{cand}.__init__"
                    return [(init, 1)] if init in self.functions else []
                if cand in self.functions and self.functions[cand].class_name:
                    # imported ``Cls.method(...)``: static/class method called on the class
                    return [(cand, self._bound(self.functions[cand], 0))]
            return []
        recv = instr.meta.get("receiver_name")
        if recv in ("self", "cls") and fn.class_name and c.method:
            cls_prefix = fn.qualname.rsplit(".", 1)[0]
            q = f"{cls_prefix}.{c.method}"
            if q in self.functions:
                return [(q, self._bound(self.functions[q], 1))]
        if recv and c.method and recv not in fn.locals:
            for cls in (self.qn(fn.module, recv), recv):
                q = f"{cls}.{c.method}"
                if cls in self._classes and q in self.functions:
                    return [(q, self._bound(self.functions[q], 0))]
        if c.method and c.receiver:
            targets = []
            for t in sorted(tget(c.receiver)):
                if t.startswith("class:"):
                    q = f"{t[6:]}.{c.method}"
                    if q in self.functions:
                        targets.append((q, self._bound(self.functions[q], 1)))
            return targets
        return []

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
        self.cross_block_temps = self._cross_block_temps()

    def _cross_block_temps(self) -> Set[str]:
        """Temporaries read in a block other than the one defining them."""
        home: Dict[str, str] = {}
        for b in self.fn.blocks:
            for i in b.instructions:
                if i.result and re.match(r"^t\d+$", i.result):
                    home[i.result] = b.label
        out: Set[str] = set()
        for b in self.fn.blocks:
            for i in b.instructions:
                for o in i.operands:
                    if o in home and home[o] != b.label:
                        out.add(o)
                if i.op == IROpcode.BRANCH and i.operands and i.operands[0] in home:
                    out.add(i.operands[0])     # read by edge feasibility after the block
        return out

    def prune(self, state: State) -> State:
        """Drop untainted plain variables and block-local temporaries from a block's output.

        Absence means "untainted" for locals (``get`` returns EMPTY for them); strong-update
        keys such as ``obj.attr`` keep explicit empty values because their absence means
        "fall back to the base object's taint".
        """
        out: State = {}
        for var, v in state.items():
            name = var[3:] if var[:1] == "#" else var
            if not v and "." not in var:
                continue
            if re.match(r"^t\d+$", name) and name not in self.cross_block_temps:
                continue
            out[var] = v
        return out

    # ── constants and container shapes ──────────────────────────────────

    def cval(self, state: State, name: Optional[str]):
        if not name:
            return NOVAL
        if name in self.consts:
            return self.consts[name]
        a = state.get("#c:" + name)
        return a[1] if a is not None and a[0] == "c" else NOVAL

    def constlike(self, state: State, name: Optional[str]) -> bool:
        """True when every value reaching ``name`` is a literal (one or several)."""
        if not name:
            return False
        return name in self.consts or ("#c:" + name) in state

    def shape(self, state: State, name: Optional[str]):
        return state.get("#s:" + name) if name else None

    # ── object aliases ("#a:x" = other names bound to the same object) ──

    @staticmethod
    def aliases(state: State, name: Optional[str]) -> frozenset:
        a = state.get("#a:" + name) if name else None
        return a[1] if a else frozenset()

    def detach_alias(self, state: State, name: str) -> None:
        for m in self.aliases(state, name):
            rest = self.aliases(state, m) - {name}
            if rest:
                state["#a:" + m] = ("a", rest)
            else:
                state.pop("#a:" + m, None)
        state.pop("#a:" + name, None)

    def bind_alias(self, state: State, target: str, source: str) -> None:
        group = (self.aliases(state, source) | {source}) - {target}
        for m in group:
            state["#a:" + m] = ("a", (self.aliases(state, m) | {target}) - {m})
        state["#a:" + target] = ("a", frozenset(group))

    def taint_object(self, state: State, name: str, added: TaintValue, attr: Optional[str] = None) -> None:
        """Mutation through ``name`` (or ``name.attr``) is visible through every alias."""
        for m in {name} | self.aliases(state, name):
            if attr is None:
                state[m] = join_values(self.get(state, m), added)
            elif m != name:
                key = f"{m}.{attr}"
                state[key] = join_values(state.get(key, self.get(state, m)), added)

    def set_aux(self, state: State, name: Optional[str], const=NOVAL, shape=None) -> None:
        if not name or name == RETURN_VAR:
            return
        if _is_user(name) and "#a:" + name in state:
            self.detach_alias(state, name)
        state.pop("#c:" + name, None)
        state.pop("#s:" + name, None)
        state.pop("#f:" + name, None)
        if const is not NOVAL and cv.is_literal(const):
            state["#c:" + name] = ("c", const)
        if shape is not None:
            state["#s:" + name] = shape

    def feasible(self, pred_label: str, succ_label: str, out: State) -> bool:
        """False when a branch on a known constant can never take the edge pred → succ."""
        pred = self.fn.get_block(pred_label)
        term = pred.instructions[-1] if pred and pred.instructions else None
        if term is None or term.op != IROpcode.BRANCH:
            return True
        kind = term.meta.get("kind")
        c = self.cval(out, term.operands[0] if term.operands else None)
        if c is NOVAL:
            return True
        if kind in ("if", "while"):
            try:
                truth = bool(c)
            except Exception:
                return True
            if succ_label == term.operands[1]:
                return truth
            if succ_label == term.operands[2]:
                return not truth
            return True
        if kind == "match":
            cases = term.operands[1:]
            chosen = None
            for lbl in cases:
                mv = self.fn.get_block(lbl).meta.get("match_values", "unknown")
                if mv == "unknown":
                    return True
                if mv == "wildcard":
                    chosen = lbl
                    break
                try:
                    vals = ast.literal_eval(mv)
                except Exception:
                    return True
                if any(_same_const(c, v) or (type(c) in (int, float) and type(v) in (int, float) and c == v)
                       for v in vals):
                    chosen = lbl
                    break
            if chosen is not None:
                return succ_label == chosen
            return succ_label not in cases
        return True

    def _const_of_binop(self, state: State, instr: IRInstruction):
        ops = instr.operands
        vals = [self.cval(state, o) for o in ops]
        operator = instr.meta.get("operator", "")
        if instr.meta.get("kind") == "compare":
            return NOVAL if any(v is NOVAL for v in vals) else cv.compare(operator.split(","), vals)
        if operator in ("And", "Or"):
            # Python returns one operand; it is known once the deciding operands are known.
            result = NOVAL
            for v in vals:
                if v is NOVAL:
                    return NOVAL
                result = v
                if (operator == "And" and not v) or (operator == "Or" and v):
                    return v
            return result
        if len(vals) == 2 and NOVAL not in (vals[0], vals[1]) and vals[0] is not NOVAL and vals[1] is not NOVAL:
            return cv.binop(operator, vals[0], vals[1])
        return NOVAL

    def _boolop_selected(self, state: State, instr: IRInstruction) -> Optional[str]:
        """Operand returned by ``a and b`` / ``a or b`` when decidable from constants."""
        operator = instr.meta.get("operator", "")
        if operator not in ("And", "Or"):
            return None
        for o in instr.operands[:-1]:
            v = self.cval(state, o)
            if v is NOVAL:
                return None
            if (operator == "And" and not v) or (operator == "Or" and v):
                return o
        return instr.operands[-1] if instr.operands else None

    def _element(self, shape, index):
        """(taint, const) of a list/dict element, or None if not determinable."""
        if shape is None or index is NOVAL:
            return None
        kind, elems = shape
        if kind == "l":
            if isinstance(index, int) and not isinstance(index, bool) and -len(elems) <= index < len(elems):
                return elems[index]
            return None
        for k, t, c in elems:
            if _same_const(k, index):
                return (t, c)
        return (EMPTY, NOVAL)          # missing key: KeyError at runtime, no data flows

    def _drop_shapes_of(self, state: State, names) -> None:
        for n in names:
            if n and _is_user(n):
                state.pop("#s:" + n, None)

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
        if not self.e.is_module_body(self.fn):
            return self.e.globals.get(self.fn.module, {}).get(name, EMPTY)
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
            elif r.kind == "dotdot_check":
                why = "only a '..' substring check guards this path (absolute paths, encodings "                       "and other separators are not covered)"
                note = Step(term.lineno, term.col, "check", f"{why}: {term.meta.get('src', '')}", self.q)
                state[r.var] = {k: replace(i, unc=i.unc | {why}, trace=i.trace + (note,))
                                if "path" in i.contexts else i for k, i in v.items()}
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
                self.set_aux(state, res, self.consts.get(res, NOVAL))
                return
            src = instr.operands[0] if instr.operands else None
            v = self.get(state, src) if src else {}
            if v and res and _is_user(res):
                v = add_step(v, self.step(instr, "assign"))
            elif v and res == RETURN_VAR:
                v = add_step(v, self.step(instr, "return", f"returned: {instr.meta.get('src', '')}"))
            shape = self.shape(state, src)
            if shape is not None and src and _is_user(src):
                # b = a aliases one object: shapes would diverge on mutation, so drop both.
                state.pop("#s:" + src, None)
                shape = None
            const = self.cval(state, src)
            cset = state.get("#c:" + src) if src else None
            desc = self.callable_of(state, src) if src else None
            state[res] = v
            self.set_aux(state, res, const, shape)
            if const is NOVAL and cset is not None and cset[0] == "cs" and res != RETURN_VAR:
                state["#c:" + res] = cset
            if desc is not None and res and _is_user(res):
                state["#f:" + res] = ("f", desc)
            if src and _is_user(src) and res and _is_user(res) and const is NOVAL and src != res:
                self.bind_alias(state, res, src)
            return
        if op in (IROpcode.BINOP, IROpcode.UNOP, IROpcode.BUILD):
            v, const, shape = self._expr_value(state, instr)
            v = drop_markers(v)
            if v and res and _is_user(res):
                v = add_step(v, self.step(instr, "assign"))
            state[res] = v
            self.set_aux(state, res, const, shape)
            if record and v:
                self._maybe_sql_build(instr, v)
            return
        if op == IROpcode.SUBSCR:
            base = instr.operands[0] if instr.operands else None
            v = self.get(state, base) if base else {}
            const = NOVAL
            index = instr.meta.get("index")
            if instr.meta.get("unpack"):
                idx = int(index) if index and index.lstrip("-").isdigit() else NOVAL
            elif index == "iter":
                idx = NOVAL
            else:
                idx = self.cval(state, instr.operands[1]) if len(instr.operands) > 1 else NOVAL
            elem = self._element(self.shape(state, base), idx)
            if elem is not None:
                v, const = elem
            else:
                bc = self.cval(state, base)
                if bc is not NOVAL and idx is not NOVAL:
                    const = cv.subscript(bc, idx)
                    if const is not NOVAL:
                        v = {}
            state[res] = v if instr.meta.get("unpack") or index == "iter" else drop_markers(v)
            self.set_aux(state, res, const)
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
            self._call(self._devirtualize(instr, state), state, record)
            return

    def _expr_value(self, state: State, instr: IRInstruction):
        """(taint, const, shape) of a BINOP / UNOP / BUILD instruction."""
        ops = instr.operands
        kind = instr.meta.get("kind")
        if instr.op == IROpcode.BINOP:
            const = self._const_of_binop(state, instr)
            if const is not NOVAL and instr.meta.get("kind") == "compare":
                return {}, const, None
            sel = self._boolop_selected(state, instr)
            if sel is not None:
                return self.get(state, sel), self.cval(state, sel), None
            return self._ops_value(state, instr), const, None
        if instr.op == IROpcode.UNOP:
            c = self.cval(state, ops[0]) if ops else NOVAL
            const = cv.unop(instr.meta.get("operator", ""), c) if c is not NOVAL else NOVAL
            return self._ops_value(state, instr), const, None
        # BUILD
        if kind == "ifexp" and len(ops) >= 3:
            test = self.cval(state, ops[2])
            if test is not NOVAL:
                chosen = ops[0] if test else ops[1]
                return self.get(state, chosen), self.cval(state, chosen), None
            return self._ops_value(state, instr), NOVAL, None
        consts = [self.cval(state, o) for o in ops]
        if kind == "slice":
            if all(c is not NOVAL for c in consts) and len(consts) <= 3:
                return {}, slice(*consts), None
            return {}, NOVAL, None
        if instr.meta.get("starred"):
            return self._ops_value(state, instr), NOVAL, None
        if kind in ("list", "tuple"):
            self._drop_shapes_of(state, ops)
            shape = ("l", tuple((self.get(state, o), c) for o, c in zip(ops, consts)))
            const = NOVAL
            if kind == "tuple" and all(c is not NOVAL for c in consts):
                const = tuple(consts)       # lists are mutable: never tracked as constants
            return self._ops_value(state, instr), const, shape
        if kind == "dict":
            n = int(instr.meta.get("nkeys", "-1"))
            if n >= 0 and len(ops) == 2 * n:
                keys, vals = ops[:n], ops[n:]
                kc = [self.cval(state, k) for k in keys]
                if all(k is not NOVAL for k in kc):
                    try:
                        hashable = all(hash(k) is not None for k in kc)
                    except TypeError:
                        hashable = False
                    if hashable and len(set(map(repr, kc))) == len(kc):
                        shape = ("d", tuple((k, self.get(state, v), self.cval(state, v))
                                            for k, v in zip(kc, vals)))
                        return self.get_union(state, vals), NOVAL, shape
            return self._ops_value(state, instr), NOVAL, None
        return self._ops_value(state, instr), NOVAL, None

    def get_union(self, state: State, names) -> TaintValue:
        return join_values(*[self.get(state, n) for n in names])

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
            for m in self.aliases(state, base_name):      # same object: same attribute
                state[f"{m}.{instr.meta.get('attr', '')}"] = v
            if record and base_name in ("self", "cls") and self._cls and v:
                fk = (self._cls, instr.meta.get("attr", ""))
                self.field_writes[fk] = join_values(self.field_writes.get(fk, {}), v)
        elif kind == "subscr" and base_name:
            if record and val and re.search(SESSION_STORE_PATTERN, base_name):
                self._session_store_hit(instr, base_name, val)
            stored = add_step(val, self.step(instr, "store")) if val else val
            if val:
                self.taint_object(state, base_name, stored)
                for m in self.aliases(state, base_name):
                    state.pop("#s:" + m, None)
            shape = self.shape(state, base_name)
            if shape is not None:
                key = self.cval(state, instr.operands[2]) if len(instr.operands) > 2 else NOVAL
                const = self.cval(state, instr.operands[0])
                new_shape = None
                if key is not NOVAL:
                    kind_s, elems = shape
                    if kind_s == "d":
                        try:
                            hash(key)
                            if any(_same_const(e[0], key) for e in elems):
                                new_shape = ("d", tuple((key, stored, const) if _same_const(e[0], key)
                                                        else e for e in elems))
                            else:
                                new_shape = ("d", elems + ((key, stored, const),))
                        except TypeError:
                            new_shape = None
                    elif isinstance(key, int) and not isinstance(key, bool) and -len(elems) <= key < len(elems):
                        lst = list(elems)
                        lst[key] = (stored, const)
                        new_shape = ("l", tuple(lst))
                if new_shape is None:
                    state.pop("#s:" + base_name, None)
                else:
                    state["#s:" + base_name] = new_shape
            state.pop("#c:" + base_name, None)

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
            if not ok or any(name == x or name.startswith(x + ".") for x in spec.exclude):
                continue
            key = self.e.origin(("src", self.q, instr.uid), kind="source",
                                description=f"{spec.description} ({name})", trust=spec.trust,
                                lineno=instr.lineno, col=instr.col, function=self.q,
                                heuristic=spec.heuristic)
            step = Step(instr.lineno, instr.col, "source",
                        f"untrusted {spec.description}: {instr.meta.get('src', name)}", self.q)
            return {key: TaintInfo(spec.contexts or ALL_CONTEXTS, trace=(step,))}
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
        targets = self.e.resolve(self.fn, instr)
        sanitizer = self.e.reg.sanitizer_for(callee if c.receiver is None else "", c.method,
                                             c.receiver is not None)
        if src:
            result = src
        elif targets:
            parts = []
            for qual, bound in targets:
                binding = self._bind(qual, bound, c, recv_v, arg_vs, kw_vs, star_vs)
                parts.append(self._instantiate(qual, binding, instr))
                if record:
                    self.callees.add(qual)
                    self._instantiate_hits(qual, binding, instr)
                    self._instantiate_envs(qual, binding, instr)
            result = join_values(*parts)
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
        elif c.receiver and c.method in RECEIVER_ONLY_METHODS:
            result = recv_v
        elif callee in PROPAGATOR_CALLEES or (is_method and c.method in PROPAGATOR_METHODS):
            result = drop_markers(inputs)
        elif is_method and c.method in MUTATOR_METHODS:
            result = {}
            rn = instr.meta.get("receiver_name")
            added = join_values(*arg_vs, *kw_vs.values(), *star_vs)
            if rn and added:
                self.taint_object(state, rn, add_step(added, self.step(instr, "store")))
        else:
            if inputs and self.e.reg.unknown_calls_mutate_args:
                # Opt-in: an unknown callee may store any argument into a container argument.
                for a in list(c.args) + list(c.keywords.values()):
                    if a and _is_user(a) and a in self.fn.locals:
                        self.taint_object(state, a, add_step(inputs, self.step(
                            instr, "store", f"may be mutated by unresolved call {label}()")))
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
        precise, const, shape = self._call_precision(instr, state)
        if precise is not None:
            result = precise
        state[res] = result
        self.set_aux(state, res, const, shape)
        if record:
            self._check_sinks(instr, state, recv_v, arg_vs, kw_vs)
            if c.method == "format" and c.receiver and result:
                tmpl = self.consts.get(c.receiver)
                if isinstance(tmpl, str) and _SQLISH.search(tmpl):
                    keys = tuple(k for k, i in result.items() if "sql" in i.contexts)
                    if keys:
                        self.sql_builds.append(SqlBuild(self.q, instr.lineno, instr.col, keys,
                                                        instr.meta.get("src", "")))

    # ── statically resolvable callables (aliases, getattr, partial) ─────

    def callable_of(self, state: State, operand: Optional[str], depth: int = 0):
        """
        Descriptor of the callable held by ``operand`` when it is statically known:
        ("func", dotted_name) | ("method", receiver_operand, method, receiver_name) |
        ("partial", inner_descriptor, bound_arg_operands). None otherwise.
        """
        if not operand or depth > 4:
            return None
        a = state.get("#f:" + operand)
        if a is not None:
            return a[1]
        d = self.defs.get(operand)
        if d is None:
            if not _is_user(operand) or operand in self.fn.locals:
                return None
            return ("func", operand)            # free name: builtin, global or project function
        if d.op == IROpcode.ATTR:
            if d.meta.get("path"):
                return ("func", d.meta["path"])
            return ("method", d.operands[0] if d.operands else "", d.meta.get("attr", ""),
                    d.meta.get("base_name"))
        if d.op == IROpcode.CALL and d.call is not None:
            c = d.call
            if c.callee == "getattr" and len(c.args) >= 2 and not c.keywords:
                name = self.cval(state, c.args[1])
                if not isinstance(name, str) or not name.isidentifier():
                    return None                  # computed attribute name: not resolved
                obj = c.args[0]
                od = self.defs.get(obj)
                if od is not None and od.op == IROpcode.ATTR and od.meta.get("path"):
                    return ("func", f"{od.meta['path']}.{name}")
                return ("method", obj, name, obj if _is_user(obj) else None)
            if c.callee == "functools.partial" and c.args and not c.star_args:
                inner = self.callable_of(state, c.args[0], depth + 1)
                if inner is not None:
                    return ("partial", inner, tuple(c.args[1:]))
        return None

    def _devirtualize(self, instr: IRInstruction, state: State) -> IRInstruction:
        """Rewrite a call through a known callable value into the equivalent direct call."""
        c = instr.call
        if c is None:
            return instr
        if instr.meta.get("local_callable") == "1":
            holder = c.callee
            if self.e.resolve(self.fn, instr):
                return instr                     # nested project function: already resolved
        elif instr.meta.get("computed_callee") == "1":
            holder = c.receiver
        else:
            return instr
        desc = self.callable_of(state, holder)
        if desc is None:
            return instr
        args = list(c.args)
        while desc[0] == "partial":
            args = list(desc[2]) + args
            desc = desc[1]
        meta = {k: v for k, v in instr.meta.items() if k not in ("local_callable", "computed_callee",
                                                                  "receiver_name")}
        if desc[0] == "func":
            name = desc[1]
            info = CallInfo(callee=name, raw_callee=c.raw_callee, method=name.rsplit(".", 1)[-1]
                            if "." in name else None, args=args, keywords=dict(c.keywords),
                            const_kwargs=dict(c.const_kwargs), star_args=list(c.star_args))
        else:
            _, recv, method, recv_name = desc
            info = CallInfo(callee="", raw_callee=c.raw_callee, method=method, receiver=recv,
                            args=args, keywords=dict(c.keywords), const_kwargs=dict(c.const_kwargs),
                            star_args=list(c.star_args))
            if recv_name:
                meta["receiver_name"] = recv_name
        meta["callee"] = info.callee or f"{info.receiver}.{info.method}"
        meta["devirtualized"] = c.raw_callee
        operands = ([info.receiver] if info.receiver else []) + info.args + \
            list(info.keywords.values()) + info.star_args
        return replace(instr, call=info, meta=meta, operands=operands)

    def _call_precision(self, instr: IRInstruction, state: State):
        """
        Precise result for list/dict methods on a tracked container and pure builtins on
        constants. Returns (taint or None, const). Containers passed to any other call lose
        their shape (the callee may mutate them).
        """
        c = instr.call
        rn = instr.meta.get("receiver_name")
        shape = self.shape(state, rn) if rn else None
        precise, const = None, NOVAL
        handled = False
        if c.receiver is None and c.callee in _CONFIGPARSER_TYPES and not c.args:
            return None, NOVAL, ("d", ())        # empty (section, option) store
        if shape is not None and shape[0] == "d" and c.method in ("set", "get", "add_section",
                                                                  "has_section", "has_option") \
                and not c.keywords and not c.star_args:
            args = [self.cval(state, a) for a in c.args]
            elems = shape[1]
            if c.method == "set" and len(c.args) == 3 and args[0] is not NOVAL and args[1] is not NOVAL:
                key = (args[0], args[1])
                val = (self.get(state, c.args[2]), args[2])
                if any(_same_const(k, key) for k, _, _ in elems):
                    elems = tuple((k, *val) if _same_const(k, key) else (k, t, cc) for k, t, cc in elems)
                else:
                    elems = elems + ((key, *val),)
                state["#s:" + rn] = ("d", elems)
                return {}, NOVAL, None
            if c.method == "get" and len(c.args) >= 2 and args[0] is not NOVAL and args[1] is not NOVAL:
                found = [(t, cc) for k, t, cc in elems if _same_const(k, (args[0], args[1]))]
                return (found[0][0], found[0][1], None) if found else ({}, NOVAL, None)
            if c.method in ("add_section", "has_section", "has_option"):
                return {}, NOVAL, None
        if shape is not None and c.method and not c.keywords and not c.star_args:
            kind, elems = shape
            args = [self.cval(state, a) for a in c.args]
            if kind == "l" and c.method == "append" and len(c.args) == 1:
                state["#s:" + rn] = ("l", elems + ((self.get(state, c.args[0]), args[0]),))
                precise, handled = {}, True
            elif kind == "l" and c.method == "pop" and len(c.args) <= 1:
                i = args[0] if c.args else -1
                if isinstance(i, int) and not isinstance(i, bool) and -len(elems) <= i < len(elems):
                    lst = list(elems)
                    t, const = lst.pop(i)
                    state["#s:" + rn] = ("l", tuple(lst))
                    precise, handled = t, True
            elif kind == "l" and c.method == "insert" and len(c.args) == 2 and isinstance(args[0], int) \
                    and not isinstance(args[0], bool):
                lst = list(elems)
                lst.insert(args[0], (self.get(state, c.args[1]), args[1]))
                state["#s:" + rn] = ("l", tuple(lst))
                precise, handled = {}, True
            elif kind == "d" and c.method == "get" and 1 <= len(c.args) <= 2 and args[0] is not NOVAL:
                found = [(t, cc) for k, t, cc in elems if _same_const(k, args[0])]
                if found:
                    precise, const = found[0]
                elif len(c.args) == 2:
                    precise, const = self.get(state, c.args[1]), args[1]
                else:
                    precise = {}
                handled = True
        if not handled:
            # Any container reaching a call by reference may be mutated there.
            self._drop_shapes_of(state, [c.receiver] + list(c.args) + list(c.keywords.values())
                                 + list(c.star_args))
            if c.receiver is None and c.callee in ("len", "str", "int", "float", "abs", "bool", "ord",
                                                    "chr", "min", "max", "repr") \
                    and not c.keywords and not c.star_args:
                vals = [self.cval(state, a) for a in c.args]
                if c.args and all(v is not NOVAL for v in vals):
                    const = cv.pure_call(c.callee, vals)
        return precise, const, None

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
                    self.e.module_types(self.fn.module).get(instr.meta.get("receiver_name", ""), set())
                    if instr.meta.get("receiver_name") not in self.fn.locals else set())
                if set(spec.unless_receiver) & rtypes:
                    continue
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
                        severity_override=sev or spec.severity,
                    ))
                if (not hit_any and spec.api_fallback and not self._is_const(operand)
                        and not self.constlike(state, operand)):
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
            narrowed = []
            for o, r, f, s in out:
                d = self.defs.get(o)
                if d is not None and d.op == IROpcode.BUILD and d.meta.get("kind") == "tuple" \
                        and d.operands and not d.meta.get("starred"):
                    # make_response((body, status_or_headers, ...)): only the body is HTML
                    narrowed.append((d.operands[0], r + " (response body)", f, s))
                else:
                    narrowed.append((o, r, f, s))
            return narrowed
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

    def _session_store_hit(self, instr: IRInstruction, base_name: str, val: TaintValue) -> None:
        for okey, info in val.items():
            if "weakrand" not in info.contexts:
                continue
            step = self.step(instr, "sink", f"stored into security-sensitive state {base_name}[...]")
            self._add_hit(Hit(
                rule_id="SEC011", function=self.q, sink_uid=instr.uid, lineno=instr.lineno,
                col=instr.col, sink_name=f"{base_name}[...]", operation="session/cookie state",
                operand_role="stored value", origin_key=okey,
                info=replace(info, trace=info.trace + (step,)), resolution="method-name",
                factors=("medium:security relevance inferred from the container name "
                         f"'{base_name}'",), guards=tuple(instr.guards)))

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
