"""
AST Feature Extractor — Week 7 Core Engine
==========================================
Traverses the Python AST and extracts rich structural features for every
function, class, loop, and conditional block in a source file.

Output: ModuleFeatures dict that feeds into the context_analyzer.
"""
import ast
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Data classes for extracted features
# ---------------------------------------------------------------------------

@dataclass
class ParamFeature:
    name: str
    annotation: Optional[str] = None
    default: Optional[str] = None


@dataclass
class FunctionFeature:
    node_id: str
    name: str
    lineno: int
    col_offset: int
    params: List[ParamFeature] = field(default_factory=list)
    return_annotation: Optional[str] = None
    decorators: List[str] = field(default_factory=list)
    has_docstring: bool = False
    docstring: Optional[str] = None
    body_lines: int = 0
    calls_made: List[str] = field(default_factory=list)
    loops: int = 0          # for/while count inside body
    conditionals: int = 0   # if/elif count inside body
    is_method: bool = False
    parent_class: Optional[str] = None
    is_async: bool = False


@dataclass
class ClassFeature:
    node_id: str
    name: str
    lineno: int
    col_offset: int
    bases: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    class_variables: List[str] = field(default_factory=list)
    has_docstring: bool = False
    docstring: Optional[str] = None


@dataclass
class ModuleFeatures:
    filepath: str = ""
    imports: List[str] = field(default_factory=list)
    global_vars: List[str] = field(default_factory=list)
    functions: List[FunctionFeature] = field(default_factory=list)
    classes: List[ClassFeature] = field(default_factory=list)
    total_lines: int = 0


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _annotation_to_str(node: Optional[ast.expr]) -> Optional[str]:
    """Convert an AST annotation node to a readable string."""
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def _default_to_str(node: Optional[ast.expr]) -> Optional[str]:
    """Convert a default-value AST node to a string representation."""
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:
        return "..."


def _collect_calls(body: List[ast.stmt]) -> List[str]:
    """Walk a function body and collect names of all called functions."""
    calls = []
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.Call):
            try:
                calls.append(ast.unparse(node.func))
            except Exception:
                pass
    return list(dict.fromkeys(calls))  # deduplicate, preserve order


def _count_branches(body: List[ast.stmt]) -> Dict[str, int]:
    """Count loops and conditionals directly within a function body tree."""
    loops = conditionals = 0
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
            loops += 1
        elif isinstance(node, ast.If):
            conditionals += 1
    return {"loops": loops, "conditionals": conditionals}


# ---------------------------------------------------------------------------
# Main visitor
# ---------------------------------------------------------------------------

class FeatureExtractor(ast.NodeVisitor):
    """
    AST NodeVisitor that extracts ModuleFeatures from a parsed Python module.
    """

    def __init__(self, filepath: str = ""):
        self.filepath = filepath
        self._module_features = ModuleFeatures(filepath=filepath)
        self._current_class: Optional[str] = None   # tracks class context

    # ------------------------------------------------------------------
    # Module-level nodes
    # ------------------------------------------------------------------

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self._module_features.imports.append(name)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            self._module_features.imports.append(f"{module}.{alias.name}")

    def visit_Assign(self, node: ast.Assign):
        """Capture module-level variable assignments."""
        if self._current_class is None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._module_features.global_vars.append(target.id)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Class nodes
    # ------------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef):
        node_id = f"class_{node.name}_{node.lineno}"
        bases = []
        for b in node.bases:
            try:
                bases.append(ast.unparse(b))
            except Exception:
                bases.append(type(b).__name__)

        # Collect class-level variable names
        class_vars = []
        for item in node.body:
            if isinstance(item, ast.Assign):
                for t in item.targets:
                    if isinstance(t, ast.Name):
                        class_vars.append(t.id)
            elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                class_vars.append(item.target.id)

        docstring = ast.get_docstring(node)
        methods = [
            n.name for n in node.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        cf = ClassFeature(
            node_id=node_id,
            name=node.name,
            lineno=node.lineno,
            col_offset=node.col_offset,
            bases=bases,
            methods=methods,
            class_variables=class_vars,
            has_docstring=docstring is not None,
            docstring=docstring,
        )
        self._module_features.classes.append(cf)

        # Visit children under this class context
        prev = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = prev

    # ------------------------------------------------------------------
    # Function nodes
    # ------------------------------------------------------------------

    def _extract_function(self, node, is_async: bool = False):
        node_id = f"func_{node.name}_{node.lineno}"

        # Parameters
        params = []
        args = node.args
        # Build default map (defaults align to the end of args.args)
        defaults = args.defaults
        num_args = len(args.args)
        default_offset = num_args - len(defaults)
        for i, arg in enumerate(args.args):
            default_val = None
            if i >= default_offset:
                default_val = _default_to_str(defaults[i - default_offset])
            params.append(ParamFeature(
                name=arg.arg,
                annotation=_annotation_to_str(arg.annotation),
                default=default_val,
            ))

        # Decorators
        decorators = []
        for d in node.decorator_list:
            try:
                decorators.append(ast.unparse(d))
            except Exception:
                decorators.append(type(d).__name__)

        # Body analysis
        docstring = ast.get_docstring(node)
        branches = _count_branches(node.body)
        calls = _collect_calls(node.body)

        body_lines = max(1, getattr(node, 'end_lineno', node.lineno) - node.lineno)

        ff = FunctionFeature(
            node_id=node_id,
            name=node.name,
            lineno=node.lineno,
            col_offset=node.col_offset,
            params=params,
            return_annotation=_annotation_to_str(node.returns),
            decorators=decorators,
            has_docstring=docstring is not None,
            docstring=docstring,
            body_lines=body_lines,
            calls_made=calls,
            loops=branches["loops"],
            conditionals=branches["conditionals"],
            is_method=self._current_class is not None,
            parent_class=self._current_class,
            is_async=is_async,
        )
        self._module_features.functions.append(ff)
        # Don't recurse deeper (nested functions would be caught separately)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._extract_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._extract_function(node, is_async=True)

    # ------------------------------------------------------------------
    # Result
    # ------------------------------------------------------------------

    def extract(self, tree: ast.AST, source_code: str = "") -> ModuleFeatures:
        """Run extraction on a parsed AST and return ModuleFeatures."""
        self._module_features.total_lines = len(source_code.splitlines())
        self.visit(tree)
        return self._module_features


def extract_features(tree: ast.AST, source_code: str = "", filepath: str = "") -> ModuleFeatures:
    """
    Public API: extract structural features from a parsed AST.

    Args:
        tree: Root AST node from ast.parse()
        source_code: Original source string (for line counting)
        filepath: Source file path (for metadata)

    Returns:
        ModuleFeatures dataclass with all extracted information
    """
    extractor = FeatureExtractor(filepath=filepath)
    mf = extractor.extract(tree, source_code)
    # Kept as plain attributes (not dataclass fields) so features_to_dict()
    # stays JSON-serialisable; build_ir() lowers from this tree.
    mf._ast_tree = tree
    mf._source = source_code
    return mf


def features_to_dict(mf: ModuleFeatures) -> Dict[str, Any]:
    """Serialize ModuleFeatures to a plain dict (JSON-compatible)."""
    import dataclasses
    def _convert(obj):
        if dataclasses.is_dataclass(obj):
            return {k: _convert(v) for k, v in dataclasses.asdict(obj).items()}
        elif isinstance(obj, list):
            return [_convert(i) for i in obj]
        else:
            return obj
    return _convert(mf)
