"""
Project-level (cross-file) analysis
====================================
Analyses several modules together so taint flows through calls between them.

    from src.security.project import analyze_project
    rep = analyze_project("path/to/project")              # discovers *.py under the root
    rep = analyze_project(root, include=["app", "lib"])    # only these sub-directories

Supported cross-module resolution
---------------------------------
* ``import pkg.mod`` / ``from pkg.mod import f`` / ``from . import f`` (relative imports are
  resolved against the importing module's package)
* calls of imported functions, classes (constructor → ``__init__``), static/class methods
* method calls on objects whose class is known from a constructor call or from a project
  function returning instances (``helpers.factory().run(x)``); several possible classes
  are all followed and their results joined
* module-level variables of each module (per-module globals)

Not resolved (reported in ``ProjectFindings.unresolved_imports`` / treated as unknown calls,
which propagate taint at lowered confidence): imports of modules outside the project,
``importlib``/``__import__``, ``getattr``-based dispatch, monkey patching, inheritance
from external classes, attributes assigned on modules from other modules.

Module discovery skips hidden directories, virtual environments, ``site-packages``,
build outputs and caches (``DEFAULT_EXCLUDES``).
"""
from __future__ import annotations

import ast
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..ir.ir_nodes import IRModule, IROpcode
from ..ir.lowering import MODULE_QUALNAME, lower_module
from .analyzer import assemble_findings
from .findings import SecurityFindings
from .rules import DEFAULT_REGISTRY, Registry
from .taint import TaintEngine

DEFAULT_EXCLUDES = {
    "__pycache__", "venv", "env", "site-packages", "dist-packages", "node_modules", "build",
    "dist", "outputs", "htmlcov",
}


@dataclass
class ProjectFindings:
    root: str
    files: Dict[str, SecurityFindings] = field(default_factory=dict)
    modules: Dict[str, str] = field(default_factory=dict)           # module -> file
    imports: Dict[str, List[str]] = field(default_factory=dict)     # module -> project modules
    cycles: List[List[str]] = field(default_factory=list)
    unresolved_imports: Dict[str, List[str]] = field(default_factory=dict)
    external_imports: Dict[str, List[str]] = field(default_factory=dict)
    parse_errors: Dict[str, str] = field(default_factory=dict)
    converged: bool = True
    rounds: int = 0
    runtime_ms: float = 0.0

    @property
    def findings(self):
        return [f for rep in self.files.values() for f in rep.findings]

    def active(self):
        return [f for f in self.findings if f.status != "suppressed"]

    def to_dict(self) -> dict:
        return {"root": self.root, "modules": self.modules, "imports": self.imports,
                "cycles": self.cycles, "unresolved_imports": self.unresolved_imports,
                "external_imports": self.external_imports,
                "parse_errors": self.parse_errors, "converged": self.converged,
                "rounds": self.rounds, "runtime_ms": round(self.runtime_ms, 1),
                "files": {p: r.to_dict() for p, r in sorted(self.files.items())}}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover_modules(root: str, include: Optional[Iterable[str]] = None,
                     excludes: Set[str] = DEFAULT_EXCLUDES) -> List[Tuple[str, str, bool]]:
    """(path, dotted module name, is_package) for project modules under ``root``."""
    root = os.path.abspath(root)
    starts = [os.path.join(root, i) for i in include] if include else [root]
    out = []
    for start in starts:
        if os.path.isfile(start):
            walk = [(os.path.dirname(start), [], [os.path.basename(start)])]
        else:
            walk = os.walk(start)
        for base, dirs, files in walk:
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in excludes
                             and not d.endswith(".egg-info"))
            for f in sorted(files):
                if not f.endswith(".py"):
                    continue
                path = os.path.join(base, f)
                rel = os.path.relpath(path, root)[:-3].replace(os.sep, ".")
                is_pkg = f == "__init__.py"
                name = rel[: -len(".__init__")] if is_pkg else rel
                out.append((path, name, is_pkg))
    return out


# ---------------------------------------------------------------------------
# IR construction with module-qualified names
# ---------------------------------------------------------------------------

def _prefix_module(ir: IRModule, module: str) -> None:
    """Give every function and class in ``ir`` a module-qualified name."""
    def q(name: Optional[str]) -> Optional[str]:
        return f"{module}.{name}" if name and module else name

    funcs = list(ir.functions) + ([ir.module_body] if ir.module_body else [])
    for fn in funcs:
        fn.module = module
        for instr in fn.all_instructions():
            if instr.op == IROpcode.MAKEFUNC and "func" in instr.meta:
                instr.meta["func"] = q(instr.meta["func"])
        fn.enclosing = q(fn.enclosing)
        fn.qualname = q(fn.qualname)
    ir.classes = [q(c) for c in ir.classes]
    ir.module_name = module


def _module_imports(tree: ast.Module, module: str, is_pkg: bool) -> Set[str]:
    from ..ir.lowering import resolve_relative
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = resolve_relative(node.module, node.level, module, is_pkg)
            names.add(base)
            names.update(f"{base}.{a.name}" if base else a.name for a in node.names)
    return names


def _cycles(graph: Dict[str, List[str]]) -> List[List[str]]:
    """Strongly connected components with more than one module (Tarjan)."""
    index, low, stack, on, out = {}, {}, [], set(), []
    counter = [0]

    def visit(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        for w in graph.get(v, []):
            if w not in index:
                visit(w)
                low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on.discard(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1 or v in graph.get(v, []):
                out.append(sorted(comp))

    for v in sorted(graph):
        if v not in index:
            visit(v)
    return sorted(out)


def analyze_project(root: str, include: Optional[Iterable[str]] = None,
                    registry: Registry = DEFAULT_REGISTRY,
                    excludes: Set[str] = DEFAULT_EXCLUDES) -> ProjectFindings:
    t0 = time.perf_counter()
    result = ProjectFindings(root=os.path.abspath(root))
    units: Dict[str, Tuple[ast.Module, str]] = {}
    irs: List[IRModule] = []
    raw_imports: Dict[str, Set[str]] = {}
    for path, module, is_pkg in discover_modules(root, include, excludes):
        try:
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            tree = ast.parse(src, filename=path)
        except (SyntaxError, UnicodeDecodeError, OSError) as exc:
            result.parse_errors[path] = f"{type(exc).__name__}: {exc}"
            result.files[path] = SecurityFindings(file=path, parse_error=result.parse_errors[path])
            continue
        ir = lower_module(tree, src, path, module, is_pkg)
        _prefix_module(ir, module)
        irs.append(ir)
        units[path] = (tree, src)
        result.modules[module] = path
        raw_imports[module] = _module_imports(tree, module, is_pkg)

    known = set(result.modules)
    project_tops = {m.split(".")[0] for m in known}
    for module, names in raw_imports.items():
        deps, missing, external = set(), set(), set()
        for n in names:
            if not n:
                continue
            parts = n.split(".")
            hit = next((".".join(parts[:i]) for i in range(len(parts), 0, -1)
                        if ".".join(parts[:i]) in known), None)
            if hit:
                if hit != module:
                    deps.add(hit)
            elif parts[0] in project_tops:
                missing.add(n)          # looks internal but no such module was found
            else:
                external.add(parts[0])  # outside the project: calls are "unknown calls"
        result.imports[module] = sorted(deps)
        if missing:
            result.unresolved_imports[module] = sorted(missing)
        if external:
            result.external_imports[module] = sorted(external)
    result.cycles = _cycles(result.imports)

    if irs:
        engine = TaintEngine(irs, registry).run()
        by_file = assemble_findings(engine, units, registry, next(iter(units)))
        for path in units:
            rep = SecurityFindings(file=path, findings=by_file.get(path, []))
            rep.functions_analysed = sum(1 for f in engine.order if f.source_file == path)
            rep.unmodelled = {f.qualname: list(f.unsupported) for f in engine.order
                              if f.source_file == path and f.unsupported}
            rep.converged = engine.converged and not any(
                engine.function_by_qualname(q) and engine.function_by_qualname(q).source_file == path
                for q in engine.unconverged_functions)
            rep.rounds = engine.rounds
            result.files[path] = rep
        result.converged = engine.converged and not engine.unconverged_functions
        result.rounds = engine.rounds
    result.runtime_ms = (time.perf_counter() - t0) * 1000
    return result
