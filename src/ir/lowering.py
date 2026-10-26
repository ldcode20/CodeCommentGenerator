"""
AST → IR Lowering
==================
Lowers real Python statements and expressions into the 3-address IR defined
in ``ir_nodes``.  Unlike the original Week 8 builder (which synthesised blocks
from loop/branch *counts*), every instruction here corresponds to an actual
AST node and keeps its source line/column.

Control flow modelled
---------------------
  if / elif / else        cond block → true / false blocks → join block
  while / for (+ else)    header (BRANCH) → body (back-edge) → after
  break / continue        jump to loop after / header
  return                  ``__return__ = v`` then jump to the single exit block
  raise                   jump to exit (and to enclosing except handlers)
  try / except / finally  every block of the try body may jump to each handler
  with                    ``as`` target bound to the context-manager value
  match                   each case is a branch; captured names bound to subject

Approximations (recorded in ``IRFunction.unsupported``)
-------------------------------------------------------
  * ``return`` inside ``try ... finally`` skips the finally block.
  * Comprehension variables share the enclosing function namespace.
  * Lambda bodies are not analysed.
  * Short-circuit evaluation of ``and`` / ``or`` is not split into blocks.
"""
from __future__ import annotations

import ast
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .ir_nodes import (
    CallInfo, IRBlock, IRFunction, IRInstruction, IRModule, IROpcode, Refinement,
)

RETURN_VAR = "__return__"
MODULE_QUALNAME = "<module>"

# Calls that never return normally; control leaves the function like ``raise``.
NORETURN_CALLS = {
    "sys.exit", "exit", "quit", "os._exit", "os.abort", "flask.abort",
    "werkzeug.exceptions.abort", "fastapi.HTTPException", "pytest.fail", "pytest.skip",
}

_FUNC_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


# ---------------------------------------------------------------------------
# Name-binding pre-pass
# ---------------------------------------------------------------------------

def _target_names(target: ast.AST) -> Iterable[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _target_names(elt)
    elif isinstance(target, ast.Starred):
        yield from _target_names(target.value)


class _BindingCollector(ast.NodeVisitor):
    """Collect names bound in a function body without entering nested scopes."""

    def __init__(self):
        self.bound: Set[str] = set()
        self.loaded: Set[str] = set()
        self.globals: Set[str] = set()
        self.nonlocals: Set[str] = set()
        self.imports: Dict[str, str] = {}

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bound.add(node.id)
        else:
            self.loaded.add(node.id)

    def visit_FunctionDef(self, node):
        self.bound.add(node.name)
        for d in node.decorator_list:
            self.visit(d)
        for d in node.args.defaults + [d for d in node.args.kw_defaults if d]:
            self.visit(d)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.bound.add(node.name)
        for b in node.bases:
            self.visit(b)

    def visit_Lambda(self, node):
        for d in node.args.defaults:
            self.visit(d)

    def visit_Global(self, node):
        self.globals.update(node.names)

    def visit_Nonlocal(self, node):
        self.nonlocals.update(node.names)

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.imports[local] = alias.name if alias.asname else alias.name.split(".")[0]

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.imports[local] = f"{mod}.{alias.name}" if mod else alias.name

    def visit_ExceptHandler(self, node):
        if node.name:
            self.bound.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node):
        if node.name:
            self.bound.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node):
        if node.name:
            self.bound.add(node.name)

    def visit_MatchMapping(self, node):
        if node.rest:
            self.bound.add(node.rest)
        self.generic_visit(node)


def collect_module_imports(tree: ast.Module) -> Dict[str, str]:
    """Import aliases bound at module scope (also inside module-level if/try)."""
    imports: Dict[str, str] = {}

    def walk(stmts):
        for st in stmts:
            if isinstance(st, ast.Import):
                for alias in st.names:
                    local = alias.asname or alias.name.split(".")[0]
                    imports[local] = alias.name if alias.asname else alias.name.split(".")[0]
            elif isinstance(st, ast.ImportFrom):
                mod = st.module or ""
                for alias in st.names:
                    local = alias.asname or alias.name
                    imports[local] = f"{mod}.{alias.name}" if mod else alias.name
            elif isinstance(st, (ast.If, ast.Try, ast.With)) or type(st).__name__ == "TryStar":
                for attr in ("body", "orelse", "finalbody"):
                    walk(getattr(st, attr, []) or [])
                for h in getattr(st, "handlers", []) or []:
                    walk(h.body)

    walk(tree.body)
    return imports


# ---------------------------------------------------------------------------
# Regex / branch-condition refinement
# ---------------------------------------------------------------------------

# Characters that let data escape each security context.
CONTEXT_DANGEROUS_CHARS: Dict[str, Set[str]] = {
    "sql": set("'\"\\;=()") | set(" \t\r\n"),
    "shell": set(";&|$`<>(){}[]*?!~'\"\\#") | set(" \t\r\n"),
    "html": set("<>\"'&"),
    "path": set("/\\.:"),
    "template": set("{}%"),
    "code": set(),          # cleared only by a pure [A-Za-z0-9_] charset
    "deserialization": set(),
}
_WORD = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def _class_chars(body: str) -> Optional[Set[str]]:
    """Expand the inside of a ``[...]`` character class; None if unsupported."""
    if body.startswith("^"):
        return None
    chars: Set[str] = set()
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            esc = body[i + 1]
            if esc == "w":
                chars |= _WORD
            elif esc == "d":
                chars |= set("0123456789")
            elif esc == "s":
                chars |= set(" \t\r\n\f\v")
            elif esc.isalpha():
                return None
            else:
                chars.add(esc)
            i += 2
            continue
        if i + 2 < len(body) and body[i + 1] == "-":
            lo, hi = body[i], body[i + 2]
            if ord(hi) - ord(lo) > 200:
                return None
            chars |= {chr(x) for x in range(ord(lo), ord(hi) + 1)}
            i += 3
            continue
        chars.add(c)
        i += 1
    return chars


def regex_allowed_chars(pattern: str, require_end_anchor: bool) -> Optional[Set[str]]:
    """
    Over-approximate the characters a *full* match of ``pattern`` may contain.

    Returns None when the pattern is not understood or does not constrain the
    whole string (unanchored ``re.match``, alternation, ``.``, negated classes).
    """
    p = pattern
    if p.startswith("^"):
        p = p[1:]
    elif p.startswith("\\A"):
        p = p[2:]
    anchored = False
    if p.endswith("\\Z"):
        p, anchored = p[:-2], True
    elif p.endswith("$") and not p.endswith("\\$"):
        p, anchored = p[:-1], True
    if require_end_anchor and not anchored:
        return None
    allowed: Set[str] = set()
    i = 0
    while i < len(p):
        c = p[i]
        if c == "[":
            j = p.find("]", i + 2)
            if j < 0:
                return None
            cls = _class_chars(p[i + 1:j])
            if cls is None:
                return None
            allowed |= cls
            i = j + 1
        elif c == "\\" and i + 1 < len(p):
            esc = p[i + 1]
            if esc == "w":
                allowed |= _WORD
            elif esc == "d":
                allowed |= set("0123456789")
            elif esc.isalpha():
                return None
            else:
                allowed.add(esc)
            i += 2
        elif c in "+*?":
            i += 1
        elif c == "{":
            j = p.find("}", i)
            if j < 0 or not re.fullmatch(r"\d+(,\d*)?", p[i + 1:j]):
                return None
            i = j + 1
        elif c in "().|^$":
            return None
        else:
            allowed.add(c)
            i += 1
    return allowed


def contexts_cleared_by_charset(allowed: Set[str]) -> List[str]:
    cleared = []
    for ctx, bad in CONTEXT_DANGEROUS_CHARS.items():
        if ctx in ("code", "deserialization"):
            if allowed <= _WORD:
                cleared.append(ctx)
        elif not (allowed & bad):
            cleared.append(ctx)
    return sorted(cleared)


_ALL_CONTEXTS = "sql,shell,html,path,template,code,deserialization"
_CHARSET_METHODS = {"isdigit", "isnumeric", "isdecimal", "isalnum", "isalpha", "isidentifier"}
_SAFE_ISINSTANCE = {"int", "float", "bool", "complex"}


def _is_const_collection(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(isinstance(e, ast.Constant) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(isinstance(k, ast.Constant) for k in node.keys if k is not None)
    if isinstance(node, ast.Name):
        return node.id.isupper()
    if isinstance(node, ast.Attribute):
        return node.attr.isupper()
    return False


def branch_refinements(test: ast.AST, canonical) -> Tuple[List[Refinement], List[Refinement]]:
    """
    Validation facts for the (true edge, false edge) of a branch on ``test``.

    ``canonical`` resolves an expression to its import-qualified dotted name.
    """
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        t, f = branch_refinements(test.operand, canonical)
        return [Refinement(r.var, r.kind, False) for r in t], [Refinement(r.var, r.kind, True) for r in f]
    if isinstance(test, ast.BoolOp):
        parts = [branch_refinements(v, canonical) for v in test.values]
        if isinstance(test.op, ast.And):
            return [r for t, _ in parts for r in t], []
        return [], [r for _, f in parts for r in f]

    def on(var: str, kind: str, true_edge: bool):
        r = Refinement(var, kind, true_edge)
        return ([r], []) if true_edge else ([], [r])

    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        left, op, right = test.left, test.ops[0], test.comparators[0]
        if isinstance(left, ast.Name):
            if isinstance(op, (ast.In, ast.NotIn)) and _is_const_collection(right):
                return on(left.id, "allowlist", isinstance(op, ast.In))
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(right, ast.Constant):
                return on(left.id, "allowlist", isinstance(op, ast.Eq))
        # os.path.commonpath([p, base]) == base
        if (isinstance(left, ast.Call) and canonical(left.func) == "os.path.commonpath"
                and left.args and isinstance(left.args[0], (ast.List, ast.Tuple))
                and left.args[0].elts and isinstance(left.args[0].elts[0], ast.Name)
                and isinstance(op, (ast.Eq, ast.NotEq))):
            var = left.args[0].elts[0].id
            return on(var, "path_prefix", isinstance(op, ast.Eq))
        return [], []

    if isinstance(test, ast.Call):
        func = test.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            var = func.value.id
            if func.attr in _CHARSET_METHODS:
                return on(var, "charset:" + _ALL_CONTEXTS, True)
            if func.attr in ("startswith", "is_relative_to"):
                return on(var, "path_prefix", True)
        name = canonical(func)
        if name in ("re.fullmatch", "re.match") and len(test.args) >= 2:
            pat, subject = test.args[0], test.args[1]
            if isinstance(pat, ast.Constant) and isinstance(pat.value, str) and isinstance(subject, ast.Name):
                allowed = regex_allowed_chars(pat.value, require_end_anchor=(name == "re.match"))
                if allowed is not None:
                    cleared = contexts_cleared_by_charset(allowed)
                    if cleared:
                        return on(subject.id, "charset:" + ",".join(cleared), True)
        if (isinstance(func, ast.Name) and func.id == "isinstance" and len(test.args) == 2
                and isinstance(test.args[0], ast.Name)):
            types = test.args[1]
            names = [types] if not isinstance(types, ast.Tuple) else types.elts
            if names and all(isinstance(n, ast.Name) and n.id in _SAFE_ISINSTANCE for n in names):
                return on(test.args[0].id, "charset:" + _ALL_CONTEXTS, True)
    return [], []


# ---------------------------------------------------------------------------
# Function lowerer
# ---------------------------------------------------------------------------

class _LoopCtx:
    def __init__(self, header: str, after: str):
        self.header = header
        self.after = after


class FunctionLowerer:
    """Lower one function (or the module body) into an IRFunction."""

    def __init__(self, module: "ModuleLowerer", node: Optional[ast.AST], qualname: str,
                 class_name: Optional[str] = None, body: Optional[List[ast.stmt]] = None):
        self.m = module
        self.node = node
        self.qualname = qualname
        self.class_name = class_name
        self.is_module = node is None
        self.body = body if body is not None else node.body  # type: ignore[union-attr]

        collector = _BindingCollector()
        for st in self.body:
            collector.visit(st)
        params: List[str] = []
        if node is not None:
            a = node.args
            params = [x.arg for x in a.posonlyargs + a.args]
            if a.vararg:
                params.append(a.vararg.arg)
            params += [x.arg for x in a.kwonlyargs]
            if a.kwarg:
                params.append(a.kwarg.arg)
        self.params = params
        self.func_imports = collector.imports
        self.declared_globals = collector.globals | collector.nonlocals
        bound = collector.bound - set(self.func_imports) - self.declared_globals
        self.locals: Set[str] = bound | set(params)
        self.free = (collector.loaded - self.locals - set(self.func_imports)
                     - set(module.imports)) - {"self"}

        name = node.name if node is not None else MODULE_QUALNAME
        self.fn = IRFunction(
            name=name,
            params=params,
            return_type=(ast.unparse(node.returns) if node is not None and node.returns else None),
            is_method=class_name is not None,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            source_lineno=getattr(node, "lineno", 1),
            qualname=qualname,
            class_name=class_name,
            decorators=[ast.unparse(d) for d in getattr(node, "decorator_list", [])],
            locals=set(self.locals),
            free_vars=set(self.free),
            end_lineno=getattr(node, "end_lineno", 0) or 0,
        )
        self._temp = 0
        self._uid = 0
        self._counters: Dict[str, int] = {}
        self.cur: Optional[IRBlock] = None
        self.loops: List[_LoopCtx] = []
        self.guards: List[str] = []
        self.stmt_src = ""
        self.stmt_line = getattr(node, "lineno", 1)

    # ── block helpers ────────────────────────────────────────────────────

    def _count(self, kind: str) -> int:
        n = self._counters.get(kind, 0)
        self._counters[kind] = n + 1
        return n

    def new_block(self, label: str, **meta) -> IRBlock:
        b = IRBlock(label=label, meta={k: str(v) for k, v in meta.items()})
        b.instructions.append(IRInstruction(op=IROpcode.LABEL, lineno=self.stmt_line,
                                            meta={"name": label}, uid=self._next_uid()))
        self.fn.blocks.append(b)
        return b

    def link(self, src: Optional[IRBlock], dst_label: str) -> None:
        if src is None:
            return
        if dst_label not in src.successors:
            src.successors.append(dst_label)
        dst = self.fn.get_block(dst_label)
        if dst is not None and src.label not in dst.predecessors:
            dst.predecessors.append(src.label)

    def _link_labels(self, src_label: str, dst_label: str) -> None:
        self.link(self.fn.get_block(src_label), dst_label)

    def _next_uid(self) -> int:
        self._uid += 1
        return self._uid

    def temp(self) -> str:
        t = f"t{self._temp}"
        self._temp += 1
        return t

    def ensure_block(self) -> IRBlock:
        if self.cur is None:
            self.cur = self.new_block(f"dead_{self._count('dead')}", kind="unreachable")
        return self.cur

    def emit(self, op: IROpcode, result: Optional[str] = None, operands: Optional[List[str]] = None,
             node: Optional[ast.AST] = None, call: Optional[CallInfo] = None,
             refinements: Optional[List[Refinement]] = None, **meta) -> IRInstruction:
        block = self.ensure_block()
        lineno = getattr(node, "lineno", None) or self.stmt_line
        instr = IRInstruction(
            op=op, result=result, operands=list(operands or []), lineno=lineno,
            meta={k: str(v) for k, v in meta.items()},
            col=getattr(node, "col_offset", 0) or 0,
            end_lineno=getattr(node, "end_lineno", None) or lineno,
            call=call, refinements=list(refinements or []), guards=list(self.guards),
            uid=self._next_uid(),
        )
        if self.stmt_src:
            instr.meta.setdefault("src", self.stmt_src)
        block.instructions.append(instr)
        return instr

    def jump(self, label: str, **meta) -> None:
        if self.cur is None:
            return
        self.emit(IROpcode.JUMP, operands=[label], **meta)
        self.link(self.cur, label)
        self.cur = None

    def start_block(self, label: str, **meta) -> IRBlock:
        """Create ``label`` and make it current, falling through from the current block."""
        prev = self.cur
        if prev is not None and (prev.terminator is None):
            prev.instructions.append(IRInstruction(op=IROpcode.JUMP, operands=[label],
                                                   lineno=self.stmt_line, uid=self._next_uid()))
        blk = self.new_block(label, **meta)
        if prev is not None:
            self.link(prev, label)
        self.cur = blk
        return blk

    # ── name resolution ──────────────────────────────────────────────────

    def canonical(self, node: ast.AST) -> Optional[str]:
        """Import-qualified dotted name for a Name/Attribute chain, else None."""
        if isinstance(node, ast.Name):
            if node.id in self.func_imports:
                return self.func_imports[node.id]
            if node.id in self.locals:
                return None
            return self.m.imports.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.canonical(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def note(self, text: str) -> None:
        if text not in self.fn.unsupported:
            self.fn.unsupported.append(text)

    # ── entry point ──────────────────────────────────────────────────────

    def lower(self) -> IRFunction:
        self.cur = self.new_block("entry", kind="entry")
        for p in self.params:
            self.emit(IROpcode.LOAD, result=p, node=self.node, kind="param", name=p)
        self.lower_stmts(self.body)
        if self.cur is not None:
            self.stmt_src = ""
            t = self.emit(IROpcode.ASSIGN, result=RETURN_VAR, operands=[], const="None",
                          ctype="NoneType", implicit_return="1")
            t.lineno = self.fn.end_lineno or t.lineno
            self.jump("exit")
        exit_block = self.new_block("exit", kind="exit")
        exit_block.instructions.append(IRInstruction(
            op=IROpcode.RETURN, operands=[RETURN_VAR], lineno=self.fn.end_lineno or self.fn.source_lineno,
            meta={"return_type": self.fn.return_type or "None"}, uid=self._next_uid()))
        # Edges to "exit" were recorded before the block existed; add predecessors now.
        for b in self.fn.blocks:
            if "exit" in b.successors and b.label not in exit_block.predecessors:
                exit_block.predecessors.append(b.label)
        return self.fn

    # ── statements ───────────────────────────────────────────────────────

    def lower_stmts(self, stmts: List[ast.stmt]) -> None:
        for st in stmts:
            self.lower_stmt(st)

    def _set_stmt(self, st: ast.stmt) -> None:
        self.stmt_line = st.lineno
        lines = self.m.source_lines
        self.stmt_src = lines[st.lineno - 1].strip() if 0 < st.lineno <= len(lines) else ""

    def lower_stmt(self, st: ast.stmt) -> None:
        self._set_stmt(st)
        meth = getattr(self, "s_" + type(st).__name__, None)
        if meth is None:
            self.note(f"statement '{type(st).__name__}' at line {st.lineno} not modelled")
            self.emit(IROpcode.NOP, node=st, note=type(st).__name__)
            return
        meth(st)

    def s_Expr(self, st: ast.Expr):
        self.expr(st.value)
        if isinstance(st.value, ast.Call):
            func = st.value.func
            name = self.canonical(func) or (func.id if isinstance(func, ast.Name)
                                            and func.id not in self.locals else None)
            if name in NORETURN_CALLS:
                self.jump("exit", kind="noreturn")

    def s_Pass(self, st):
        pass

    def s_Global(self, st):
        pass

    s_Nonlocal = s_Global

    def s_Delete(self, st: ast.Delete):
        for t in st.targets:
            if not isinstance(t, ast.Name):
                self.expr(t)

    def s_Import(self, st):
        pass   # aliases resolved through func_imports / module imports

    s_ImportFrom = s_Import

    def s_Assign(self, st: ast.Assign):
        v = self.expr(st.value)
        for t in st.targets:
            self.assign_target(t, v, st)

    def s_AnnAssign(self, st: ast.AnnAssign):
        if st.value is not None:
            v = self.expr(st.value)
            self.assign_target(st.target, v, st)

    def s_AugAssign(self, st: ast.AugAssign):
        v = self.expr(st.value)
        op = type(st.op).__name__
        if isinstance(st.target, ast.Name):
            self.emit(IROpcode.BINOP, result=st.target.id, operands=[st.target.id, v],
                      node=st, operator=op, augmented="1")
        else:
            load = ast.copy_location(
                type(st.target)(**{**{f: getattr(st.target, f) for f in st.target._fields},
                                   "ctx": ast.Load()}), st.target)
            cur = self.expr(load)
            t = self.temp()
            self.emit(IROpcode.BINOP, result=t, operands=[cur, v], node=st, operator=op)
            self.assign_target(st.target, t, st)

    def assign_target(self, target: ast.AST, value: str, node: ast.AST, **meta) -> None:
        if isinstance(target, ast.Name):
            self.emit(IROpcode.ASSIGN, result=target.id, operands=[value], node=node, **meta)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for i, elt in enumerate(target.elts):
                t = self.temp()
                idx = "*" if isinstance(elt, ast.Starred) else str(i)
                self.emit(IROpcode.SUBSCR, result=t, operands=[value], node=elt, index=idx, unpack="1")
                self.assign_target(elt.value if isinstance(elt, ast.Starred) else elt, t, node, **meta)
        elif isinstance(target, ast.Starred):
            self.assign_target(target.value, value, node, **meta)
        elif isinstance(target, ast.Attribute):
            base = self.expr(target.value)
            meta = {"kind": "attr", "attr": target.attr}
            if isinstance(target.value, ast.Name):
                meta["base_name"] = target.value.id
            self.emit(IROpcode.STORE, operands=[value, base], node=target, **meta)
        elif isinstance(target, ast.Subscript):
            base = self.expr(target.value)
            idx = self.expr(target.slice)
            meta = {"kind": "subscr"}
            if isinstance(target.value, ast.Name):
                meta["base_name"] = target.value.id
            self.emit(IROpcode.STORE, operands=[value, base, idx], node=target, **meta)
        else:
            self.note(f"assignment target '{type(target).__name__}' not modelled")

    def s_Return(self, st: ast.Return):
        v = self.expr(st.value) if st.value is not None else self.const(None, st)
        self.emit(IROpcode.ASSIGN, result=RETURN_VAR, operands=[v], node=st, kind="return")
        self.jump("exit")

    def s_Raise(self, st: ast.Raise):
        if st.exc is not None:
            self.expr(st.exc)
        self.jump("exit", kind="raise")

    def s_Assert(self, st: ast.Assert):
        self.expr(st.test)
        self.emit(IROpcode.NOP, node=st, note="assert")

    def s_If(self, st: ast.If):
        n = self._count("branch")
        cond = self.expr(st.test)
        t_ref, f_ref = branch_refinements(st.test, self.canonical)
        true_l, false_l, join_l = f"branch_{n}_true", f"branch_{n}_false", f"branch_{n}_join"
        cond_block = self.ensure_block()
        self.emit(IROpcode.BRANCH, operands=[cond, true_l, false_l], node=st.test,
                  refinements=[*t_ref, *f_ref], kind="if")
        test_src = ast.unparse(st.test)
        depth = len(self.loops)

        self.cur = None
        self.new_block(true_l, kind="if_true", loop_depth=depth)
        self.link(cond_block, true_l)
        self.cur = self.fn.get_block(true_l)
        self.guards.append(f"if {test_src}")
        self.lower_stmts(st.body)
        self.guards.pop()
        true_end = self.cur

        self.cur = None
        self.new_block(false_l, kind="if_false", loop_depth=depth)
        self.link(cond_block, false_l)
        self.cur = self.fn.get_block(false_l)
        self.guards.append(f"not ({test_src})")
        self.lower_stmts(st.orelse)
        self.guards.pop()
        false_end = self.cur

        self.cur = None
        for end in (true_end, false_end):
            if end is not None:
                self.cur = end
                self.jump(join_l)
        self.new_block(join_l, kind="join", loop_depth=depth)
        for end in (true_end, false_end):
            if end is not None:
                self.link(end, join_l)
        reachable = true_end is not None or false_end is not None
        self.cur = self.fn.get_block(join_l) if reachable else None
        if not reachable:
            # Both arms leave the function: the join block is unreachable.
            self.fn.get_block(join_l).meta["kind"] = "unreachable"
            self.cur = None

    def _loop(self, st, header_cond_fn, bind_fn, kind: str):
        n = self._count("loop")
        header_l, body_l, after_l = f"loop_{n}_header", f"loop_{n}_body", f"loop_{n}_after"
        else_l = f"loop_{n}_else"
        depth = len(self.loops) + 1
        self.start_block(header_l, kind=f"{kind}_header", loop_depth=depth)
        cond, infinite = header_cond_fn()
        exit_target = else_l if st.orelse else after_l
        self.emit(IROpcode.BRANCH, operands=[cond, body_l, exit_target], node=st, kind=kind,
                  infinite="1" if infinite else "0")
        header = self.cur
        self.cur = None
        self.new_block(body_l, kind=f"{kind}_body", loop_depth=depth)
        self.link(header, body_l)
        self.cur = self.fn.get_block(body_l)
        self.loops.append(_LoopCtx(header_l, after_l))
        self.guards.append(f"{kind} {self._loop_guard_src(st)}")
        bind_fn()
        self.lower_stmts(st.body)
        self.guards.pop()
        self.loops.pop()
        self.jump(header_l, back_edge="1")
        if st.orelse:
            self.cur = None
            self.new_block(else_l, kind="loop_else", loop_depth=depth - 1)
            if not infinite:
                self.link(header, else_l)
            self.cur = self.fn.get_block(else_l)
            self.lower_stmts(st.orelse)
            self.jump(after_l)
        self.cur = None
        after = self.new_block(after_l, kind="loop_after", loop_depth=depth - 1)
        if not infinite and not st.orelse:
            self.link(header, after_l)
        for b in self.fn.blocks:
            if after_l in b.successors and b.label not in after.predecessors:
                after.predecessors.append(b.label)
        self.cur = after

    @staticmethod
    def _loop_guard_src(st) -> str:
        if isinstance(st, ast.While):
            return ast.unparse(st.test)
        return f"{ast.unparse(st.target)} in {ast.unparse(st.iter)}"

    def s_While(self, st: ast.While):
        infinite = isinstance(st.test, ast.Constant) and bool(st.test.value)

        def cond():
            return self.expr(st.test), infinite

        self._loop(st, cond, lambda: None, "while")

    def s_For(self, st):
        it = self.expr(st.iter)

        def cond():
            return it, False

        def bind():
            t = self.temp()
            self.emit(IROpcode.SUBSCR, result=t, operands=[it], node=st.target, index="iter")
            self.assign_target(st.target, t, st, loop_target="1")

        self._loop(st, cond, bind, "for")

    s_AsyncFor = s_For

    def s_Break(self, st):
        if self.loops:
            self.jump(self.loops[-1].after, kind="break")

    def s_Continue(self, st):
        if self.loops:
            self.jump(self.loops[-1].header, kind="continue")

    def s_With(self, st):
        for item in st.items:
            v = self.expr(item.context_expr)
            if item.optional_vars is not None:
                self.assign_target(item.optional_vars, v, st)
        self.lower_stmts(st.body)

    s_AsyncWith = s_With

    def s_Try(self, st):
        n = self._count("try")
        body_l = f"try_{n}_body"
        after_l = f"try_{n}_after"
        final_l = f"try_{n}_finally"
        self.start_block(body_l, kind="try_body", loop_depth=len(self.loops))
        first = len(self.fn.blocks) - 1
        self.lower_stmts(st.body)
        body_blocks = [b.label for b in self.fn.blocks[first:]]
        self.lower_stmts(st.orelse)
        target = final_l if st.finalbody else after_l
        ends: List[IRBlock] = []
        if self.cur is not None:
            ends.append(self.cur)
            self.jump(target)
        for k, h in enumerate(st.handlers):
            lbl = f"try_{n}_except_{k}"
            self.cur = None
            self.new_block(lbl, kind="except", loop_depth=len(self.loops))
            for bl in body_blocks:
                self._link_labels(bl, lbl)
            self.cur = self.fn.get_block(lbl)
            self._set_stmt(h)
            if h.type is not None:
                self.expr(h.type)
            if h.name:
                self.emit(IROpcode.ASSIGN, result=h.name, operands=[], node=h,
                          const="'<exception>'", ctype="exception")
            self.guards.append(f"except {ast.unparse(h.type) if h.type else ''}".strip())
            self.lower_stmts(h.body)
            self.guards.pop()
            if self.cur is not None:
                ends.append(self.cur)
                self.jump(target)
        self.cur = None
        if st.finalbody:
            fin = self.new_block(final_l, kind="finally", loop_depth=len(self.loops))
            for b in self.fn.blocks:
                if final_l in b.successors and b.label not in fin.predecessors:
                    fin.predecessors.append(b.label)
            if not st.handlers:
                for bl in body_blocks:
                    self._link_labels(bl, final_l)
            if any(isinstance(x, ast.Return) for x in ast.walk(ast.Module(body=st.body, type_ignores=[]))):
                self.note("return inside try/finally bypasses the finally block in the CFG")
            self.cur = fin
            self.lower_stmts(st.finalbody)
            self.jump(after_l)
        after = self.new_block(after_l, kind="try_after", loop_depth=len(self.loops))
        for b in self.fn.blocks:
            if after_l in b.successors and b.label not in after.predecessors:
                after.predecessors.append(b.label)
        self.cur = after if after.predecessors else None
        if not after.predecessors:
            after.meta["kind"] = "unreachable"

    s_TryStar = s_Try

    def s_FunctionDef(self, st):
        for d in st.decorator_list:
            self.expr(d)
        for d in st.args.defaults + [d for d in st.args.kw_defaults if d]:
            self.expr(d)
        qual = f"{self.qualname}.{st.name}" if not self.is_module else st.name
        inner = self.m.lower_function(st, qual, self.class_name if self.is_module else None,
                                      enclosing=self)
        captured = sorted(inner.free_vars & self.locals) if not self.is_module else []
        if not self.is_module:
            # Names the inner function reads from scopes further out are free here too
            # (decorator → wrapper reading the decorator factory's parameter).
            outer_free = inner.free_vars - self.locals - set(self.func_imports)
            self.free |= outer_free
            self.fn.free_vars |= outer_free
        self.emit(IROpcode.MAKEFUNC, result=st.name, operands=captured, node=st, func=qual)

    s_AsyncFunctionDef = s_FunctionDef

    def s_ClassDef(self, st: ast.ClassDef):
        for b in st.bases:
            self.expr(b)
        prefix = st.name if self.is_module else f"{self.qualname}.{st.name}"
        self.m.lower_class(st, prefix)
        self.emit(IROpcode.ASSIGN, result=st.name, operands=[], node=st, const=repr(st.name),
                  ctype="class", cls=prefix)

    def s_Match(self, st):
        n = self._count("match")
        subj = self.expr(st.subject)
        head = self.ensure_block()
        self.emit(IROpcode.BRANCH, operands=[subj] + [f"match_{n}_case_{k}" for k in range(len(st.cases))],
                  node=st, kind="match")
        self.note("match statement: case patterns are not used to refine values")
        join_l = f"match_{n}_join"
        ends = []
        for k, case in enumerate(st.cases):
            lbl = f"match_{n}_case_{k}"
            self.cur = None
            self.new_block(lbl, kind="match_case", loop_depth=len(self.loops))
            self.link(head, lbl)
            self.cur = self.fn.get_block(lbl)
            for node in ast.walk(case.pattern):
                name = getattr(node, "name", None) or getattr(node, "rest", None)
                if isinstance(name, str):
                    t = self.temp()
                    self.emit(IROpcode.SUBSCR, result=t, operands=[subj], node=case.pattern, index="match")
                    self.emit(IROpcode.ASSIGN, result=name, operands=[t], node=case.pattern)
            if case.guard is not None:
                self.expr(case.guard)
            self.lower_stmts(case.body)
            if self.cur is not None:
                ends.append(self.cur)
                self.jump(join_l)
        self.cur = None
        join = self.new_block(join_l, kind="join", loop_depth=len(self.loops))
        self.link(head, join_l)   # no case may match
        for e in ends:
            self.link(e, join_l)
        self.cur = join

    def s_TypeAlias(self, st):
        pass

    # ── expressions ──────────────────────────────────────────────────────

    def const(self, value, node) -> str:
        t = self.temp()
        self.emit(IROpcode.ASSIGN, result=t, operands=[], node=node,
                  const=repr(value), ctype=type(value).__name__)
        return t

    def expr(self, node: Optional[ast.AST]) -> str:
        if node is None:
            return self.const(None, None)
        meth = getattr(self, "e_" + type(node).__name__, None)
        if meth is None:
            self.note(f"expression '{type(node).__name__}' at line {getattr(node, 'lineno', '?')} not modelled")
            t = self.temp()
            self.emit(IROpcode.ASSIGN, result=t, operands=[], node=node, const="'<unsupported>'",
                      ctype="unsupported")
            return t
        return meth(node)

    def e_Constant(self, node: ast.Constant) -> str:
        return self.const(node.value, node)

    def e_Name(self, node: ast.Name) -> str:
        if node.id not in self.locals and (node.id in self.func_imports or node.id in self.m.imports):
            t = self.temp()
            self.emit(IROpcode.ATTR, result=t, operands=[], node=node,
                      path=self.canonical(node) or node.id, kind="module_ref")
            return t
        return node.id

    def e_Attribute(self, node: ast.Attribute) -> str:
        path = self.canonical(node)
        t = self.temp()
        if path:
            self.emit(IROpcode.ATTR, result=t, operands=[], node=node, path=path, attr=node.attr)
            return t
        base = self.expr(node.value)
        meta = {"attr": node.attr}
        if isinstance(node.value, ast.Name):
            meta["base_name"] = node.value.id
        self.emit(IROpcode.ATTR, result=t, operands=[base], node=node, **meta)
        return t

    def e_Subscript(self, node: ast.Subscript) -> str:
        base = self.expr(node.value)
        idx = self.expr(node.slice)
        t = self.temp()
        meta = {"taint_ops": "1"}
        if isinstance(node.slice, ast.Constant):
            meta["index"] = repr(node.slice.value)
        self.emit(IROpcode.SUBSCR, result=t, operands=[base, idx], node=node, **meta)
        return t

    def e_BinOp(self, node: ast.BinOp) -> str:
        left = self.expr(node.left)
        right = self.expr(node.right)
        t = self.temp()
        self.emit(IROpcode.BINOP, result=t, operands=[left, right], node=node,
                  operator=type(node.op).__name__)
        return t

    def e_BoolOp(self, node: ast.BoolOp) -> str:
        vals = [self.expr(v) for v in node.values]
        t = self.temp()
        self.emit(IROpcode.BINOP, result=t, operands=vals, node=node, operator=type(node.op).__name__)
        return t

    def e_Compare(self, node: ast.Compare) -> str:
        vals = [self.expr(node.left)] + [self.expr(c) for c in node.comparators]
        t = self.temp()
        self.emit(IROpcode.BINOP, result=t, operands=vals, node=node, kind="compare", taint_ops="0",
                  operator=",".join(type(o).__name__ for o in node.ops))
        return t

    def e_UnaryOp(self, node: ast.UnaryOp) -> str:
        v = self.expr(node.operand)
        t = self.temp()
        meta = {"operator": type(node.op).__name__}
        if isinstance(node.op, ast.Not):
            meta["taint_ops"] = "0"
        self.emit(IROpcode.UNOP, result=t, operands=[v], node=node, **meta)
        return t

    def e_IfExp(self, node: ast.IfExp) -> str:
        test = self.expr(node.test)
        body = self.expr(node.body)
        orelse = self.expr(node.orelse)
        t = self.temp()
        self.emit(IROpcode.BUILD, result=t, operands=[body, orelse, test], node=node,
                  kind="ifexp", taint_ops="2")
        return t

    def e_NamedExpr(self, node: ast.NamedExpr) -> str:
        v = self.expr(node.value)
        self.emit(IROpcode.ASSIGN, result=node.target.id, operands=[v], node=node)
        return node.target.id

    def e_Starred(self, node: ast.Starred) -> str:
        return self.expr(node.value)

    def e_Await(self, node: ast.Await) -> str:
        return self.expr(node.value)

    def e_Yield(self, node) -> str:
        if node.value is not None:
            v = self.expr(node.value)
            self.emit(IROpcode.BINOP, result=RETURN_VAR, operands=[RETURN_VAR, v], node=node,
                      operator="yield", kind="yield")
        return self.const(None, node)

    e_YieldFrom = e_Yield

    def e_Lambda(self, node: ast.Lambda) -> str:
        self.note("lambda bodies are not analysed")
        t = self.temp()
        self.emit(IROpcode.ASSIGN, result=t, operands=[], node=node, const="'<lambda>'", ctype="function")
        return t

    def _build(self, kind: str, elts: List[ast.AST], node: ast.AST, **meta) -> str:
        ops = [self.expr(e) for e in elts if e is not None]
        t = self.temp()
        self.emit(IROpcode.BUILD, result=t, operands=ops, node=node, kind=kind, **meta)
        return t

    def e_List(self, node):
        return self._build("list", node.elts, node)

    def e_Tuple(self, node):
        return self._build("tuple", node.elts, node)

    def e_Set(self, node):
        return self._build("set", node.elts, node)

    def e_Dict(self, node: ast.Dict):
        return self._build("dict", [k for k in node.keys if k is not None] + list(node.values), node)

    def e_Slice(self, node: ast.Slice):
        return self._build("slice", [node.lower, node.upper, node.step], node, taint_ops="0")

    def e_JoinedStr(self, node: ast.JoinedStr) -> str:
        parts: List[ast.AST] = []
        template = []
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                parts.append(v.value)
                template.append("{}")
            elif isinstance(v, ast.Constant):
                template.append(str(v.value))
        return self._build("fstring", parts, node, template="".join(template))

    def e_FormattedValue(self, node: ast.FormattedValue) -> str:
        return self.expr(node.value)

    def _comprehension(self, node, elts: List[ast.AST], kind: str) -> str:
        for gen in node.generators:
            it = self.expr(gen.iter)
            t = self.temp()
            self.emit(IROpcode.SUBSCR, result=t, operands=[it], node=gen.target, index="iter")
            self.assign_target(gen.target, t, gen.target, loop_target="1")
            for cond in gen.ifs:
                self.expr(cond)
        return self._build(kind, elts, node)

    def e_ListComp(self, node):
        return self._comprehension(node, [node.elt], "listcomp")

    def e_SetComp(self, node):
        return self._comprehension(node, [node.elt], "setcomp")

    def e_GeneratorExp(self, node):
        return self._comprehension(node, [node.elt], "genexp")

    def e_DictComp(self, node):
        return self._comprehension(node, [node.key, node.value], "dictcomp")

    def e_Call(self, node: ast.Call) -> str:
        func = node.func
        info = CallInfo(raw_callee=_safe_unparse(func))
        meta: Dict[str, str] = {}
        if isinstance(func, ast.Name):
            if func.id in self.locals:
                info.callee = func.id
                meta["local_callable"] = "1"
            else:
                info.callee = self.canonical(func) or func.id
        elif isinstance(func, ast.Attribute):
            path = self.canonical(func)
            info.method = func.attr
            if path:
                info.callee = path
            else:
                info.receiver = self.expr(func.value)
                if isinstance(func.value, ast.Name):
                    meta["receiver_name"] = func.value.id
        else:
            info.receiver = self.expr(func)
            meta["computed_callee"] = "1"

        for a in node.args:
            if isinstance(a, ast.Starred):
                info.star_args.append(self.expr(a.value))
            else:
                info.args.append(self.expr(a))
        for kw in node.keywords:
            v = self.expr(kw.value)
            if kw.arg is None:
                info.star_args.append(v)
                continue
            info.keywords[kw.arg] = v
            if isinstance(kw.value, ast.Constant):
                info.const_kwargs[kw.arg] = repr(kw.value.value)
            else:
                path = self.canonical(kw.value)
                if path:
                    info.const_kwargs[kw.arg] = path
        operands = ([info.receiver] if info.receiver else []) + info.args + \
            list(info.keywords.values()) + info.star_args
        t = self.temp()
        self.emit(IROpcode.CALL, result=t, operands=operands, node=node, call=info,
                  callee=info.callee or info.raw_callee, **meta)
        return t


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


# ---------------------------------------------------------------------------
# Module lowerer
# ---------------------------------------------------------------------------

class ModuleLowerer:
    """Lower a whole module: every function, method, nested function and the module body."""

    def __init__(self, tree: ast.Module, source: str = "", filepath: str = ""):
        self.tree = tree
        self.source_lines = source.splitlines()
        self.filepath = filepath
        self.imports = collect_module_imports(tree)
        self.functions: List[IRFunction] = []
        self.by_node: Dict[int, IRFunction] = {}

    def lower_function(self, node, qualname: str, class_name: Optional[str],
                       enclosing: Optional[FunctionLowerer] = None) -> IRFunction:
        fl = FunctionLowerer(self, node, qualname, class_name)
        if enclosing is not None and not enclosing.is_module:
            fl.fn.enclosing = enclosing.qualname
        fn = fl.lower()
        self.functions.append(fn)
        self.by_node[id(node)] = fn
        return fn

    def lower_class(self, node: ast.ClassDef, prefix: str) -> None:
        for item in node.body:
            if isinstance(item, _FUNC_NODES):
                self.lower_function(item, f"{prefix}.{item.name}", node.name)
            elif isinstance(item, ast.ClassDef):
                self.lower_class(item, f"{prefix}.{item.name}")

    def lower(self) -> IRModule:
        body_lowerer = FunctionLowerer(self, None, MODULE_QUALNAME, body=self.tree.body)
        module_body = body_lowerer.lower()
        module_body.end_lineno = len(self.source_lines)
        self.functions.sort(key=lambda f: (f.source_lineno, f.qualname))
        return IRModule(source_file=self.filepath, functions=list(self.functions),
                        imports=dict(self.imports), module_body=module_body)


def lower_module(tree: ast.Module, source: str = "", filepath: str = "") -> IRModule:
    """Lower every function (including methods and nested functions) plus the module body."""
    return ModuleLowerer(tree, source, filepath).lower()
