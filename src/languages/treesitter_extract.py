"""
tree-sitter front end for Java, C and C++.

Builds the same ``ModuleFeatures`` (functions, classes, params, calls, loops,
conditionals) and ``ContextGraph`` (cyclomatic complexity, variables, call
graph) that the Python ``ast`` front end produces, plus per-declaration facts
needed to write and place a doc comment (where the declaration starts, its
indentation, exceptions thrown, constructor/destructor flags).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from ..ast_extractor import ClassFeature, FunctionFeature, ModuleFeatures, ParamFeature
from ..context_analyzer import ContextGraph, FunctionContext, VariableInfo, _complexity_label
from ..error_handler import ParserError


# ---------------------------------------------------------------------------
# Parsers (loaded lazily so Python-only use never needs tree-sitter)
# ---------------------------------------------------------------------------

_PARSERS: Dict[str, object] = {}


def _parser(lang: str):
    if lang not in _PARSERS:
        try:
            import tree_sitter
            if lang == "java":
                import tree_sitter_java as grammar
            elif lang == "c":
                import tree_sitter_c as grammar
            elif lang == "cpp":
                import tree_sitter_cpp as grammar
            else:
                raise ValueError(f"No tree-sitter grammar for {lang!r}")
        except ImportError as exc:
            raise ParserError(
                f"{lang} support needs tree-sitter. Install it with: "
                "pip install tree-sitter tree-sitter-java tree-sitter-c tree-sitter-cpp"
            ) from exc
        _PARSERS[lang] = tree_sitter.Parser(tree_sitter.Language(grammar.language()))
    return _PARSERS[lang]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class DeclFacts:
    """Where and how to place a comment for one declaration."""
    kind: str                       # function | method | constructor | destructor | class | struct | interface | enum | record | union
    insert_line: int                # 1-based line the comment goes above
    indent: str                     # leading whitespace of that line, copied verbatim
    end_line: int
    throws: List[str] = field(default_factory=list)
    returns_value: bool = False
    is_declaration_only: bool = False   # prototype / abstract / interface method
    class_kind: str = ""            # for types: class | struct | interface | enum | record | union


@dataclass
class ForeignAnalysis:
    language: str
    module_features: ModuleFeatures
    context_graph: ContextGraph
    facts: Dict[str, DeclFacts]
    syntax_warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Node helpers
# ---------------------------------------------------------------------------

def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace") if node is not None else ""


def _squash(text: str, limit: int = 80) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _walk(node, stop: Callable[[object], bool] = lambda n: False) -> Iterable:
    """Pre-order walk; children of nodes for which ``stop`` is true are skipped."""
    stack = list(reversed(node.children))
    while stack:
        n = stack.pop()
        yield n
        if not stop(n):
            stack.extend(reversed(n.children))


def _line(node) -> int:
    return node.start_point[0] + 1


_LOOP_TYPES = {"for_statement", "enhanced_for_statement", "while_statement", "do_statement", "for_range_loop"}
_IF_TYPES = {"if_statement"}
_SWITCH_TYPES = {"switch_statement", "switch_expression"}
_NESTED_FUNCTIONS = {"lambda_expression", "class_body", "class_declaration", "function_definition",
                     "class_specifier", "struct_specifier", "local_class_declaration"}


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------

class _Extractor:
    def __init__(self, lang: str, source: str, filepath: str):
        self.lang = lang
        self.source = source
        self.src = source.encode("utf-8")
        self.lines = source.splitlines()
        self.filepath = filepath
        self.mf = ModuleFeatures(filepath=filepath, total_lines=len(self.lines))
        self.facts: Dict[str, DeclFacts] = {}
        self.bodies: Dict[str, object] = {}          # function node_id -> body node
        self.classes_by_name: Dict[str, ClassFeature] = {}
        self._ids: Set[str] = set()

    # ── shared helpers ──────────────────────────────────────────────────────
    def _node_id(self, prefix: str, name: str, line: int) -> str:
        base = f"{prefix}_{name}_{line}"
        nid, i = base, 2
        while nid in self._ids:
            nid, i = f"{base}_{i}", i + 1
        self._ids.add(nid)
        return nid

    def _indent_of(self, line_no: int) -> str:
        line = self.lines[line_no - 1] if 0 < line_no <= len(self.lines) else ""
        return line[: len(line) - len(line.lstrip())]

    def _doc_comment(self, decl) -> Optional[str]:
        """The comment directly above ``decl`` that documents it, if any."""
        prev = decl.prev_sibling
        if prev is None or prev.type not in ("comment", "block_comment", "line_comment"):
            return None
        if decl.start_point[0] - prev.end_point[0] > 1:     # a blank line separates them
            return None
        text = _text(prev, self.src).strip()
        if self.lang == "java":
            return text if text.startswith("/**") else None
        return text      # C / C++: any comment attached to the declaration documents it

    def _decl_start(self, decl):
        """Outermost node of a declaration (template<...> wrapper included)."""
        node = decl
        while node.parent is not None and node.parent.type == "template_declaration":
            node = node.parent
        return node

    # ── body facts ──────────────────────────────────────────────────────────
    def _stop_nested(self, n) -> bool:
        return n.type in _NESTED_FUNCTIONS

    def _body_stats(self, body) -> Tuple[int, int, int, List[str], List[str], bool]:
        """loops, conditionals, cyclomatic complexity, calls, throws, returns_value."""
        loops = conds = 0
        decisions = 0
        calls: List[str] = []
        throws: List[str] = []
        returns_value = False
        if body is None:
            return 0, 0, 1, [], [], False
        for n in _walk(body, self._stop_nested):
            t = n.type
            if t in _LOOP_TYPES:
                loops += 1
                decisions += 1
            elif t in _IF_TYPES:
                conds += 1
                decisions += 1
            elif t in _SWITCH_TYPES:
                conds += 1
            elif t == "switch_label" and _text(n, self.src).strip().startswith("case"):
                decisions += 1
            elif t == "case_statement" and n.child_by_field_name("value") is not None:
                decisions += 1
            elif t in ("catch_clause", "conditional_expression", "ternary_expression"):
                decisions += 1
            elif t == "binary_expression":
                op = n.child_by_field_name("operator")
                if op is not None and _text(op, self.src) in ("&&", "||"):
                    decisions += 1
            elif t == "method_invocation":
                obj, name = n.child_by_field_name("object"), n.child_by_field_name("name")
                call = (f"{_squash(_text(obj, self.src), 40)}.{_text(name, self.src)}" if obj is not None
                        else _text(name, self.src))
                calls.append(call)
            elif t == "call_expression":
                fn = n.child_by_field_name("function")
                if fn is not None:
                    calls.append(_squash(_text(fn, self.src), 60))
            elif t == "throw_statement" or t == "throw_expression":
                exc = self._thrown_type(n)
                if exc:
                    throws.append(exc)
            elif t == "return_statement":
                if any(c.is_named for c in n.children):
                    returns_value = True
        cc = 1 + decisions
        return loops, conds, cc, list(dict.fromkeys(calls)), list(dict.fromkeys(throws)), returns_value

    def _thrown_type(self, throw_node) -> Optional[str]:
        expr = next((c for c in throw_node.named_children), None)
        if expr is None:
            return None          # bare `throw;` rethrow
        if expr.type == "object_creation_expression":            # Java: throw new X(...)
            return _text(expr.child_by_field_name("type"), self.src)
        if expr.type == "call_expression":                       # C++: throw std::runtime_error(...)
            return _text(expr.child_by_field_name("function"), self.src)
        if expr.type in ("compound_literal_expression",):
            return _text(expr.child_by_field_name("type"), self.src)
        return None

    def _variables(self, body) -> List[VariableInfo]:
        if body is None:
            return []
        found: Dict[str, VariableInfo] = {}
        for n in _walk(body, self._stop_nested):
            if n.type in ("local_variable_declaration", "declaration"):
                type_text = _squash(_text(n.child_by_field_name("type"), self.src), 40) or None
                for d in n.children_by_field_name("declarator"):
                    name_node = d
                    while name_node is not None and name_node.type not in ("identifier",):
                        name_node = name_node.child_by_field_name("declarator") or name_node.child_by_field_name("name")
                    if name_node is None:
                        continue
                    name = _text(name_node, self.src)
                    vi = found.setdefault(name, VariableInfo(name=name, inferred_type=type_text))
                    vi.assigned_at.append(_line(n))
        if found:
            for n in _walk(body, self._stop_nested):
                if n.type == "identifier":
                    vi = found.get(_text(n, self.src))
                    if vi is not None and _line(n) not in vi.assigned_at:
                        vi.used_at.append(_line(n))
        return list(found.values())

    # ── Java ────────────────────────────────────────────────────────────────
    def _java_params(self, params_node) -> List[ParamFeature]:
        out = []
        for p in (params_node.named_children if params_node is not None else []):
            if p.type == "formal_parameter":
                out.append(ParamFeature(_text(p.child_by_field_name("name"), self.src),
                                        _squash(_text(p.child_by_field_name("type"), self.src), 40)))
            elif p.type == "spread_parameter":
                type_node = next((c for c in p.named_children if c.type not in ("modifiers", "variable_declarator")), None)
                decl = next((c for c in p.named_children if c.type == "variable_declarator"), None)
                name = _text(decl.child_by_field_name("name"), self.src) if decl is not None else "args"
                out.append(ParamFeature(name, f"{_text(type_node, self.src)}..."))
        return out

    def _java_modifiers(self, decl) -> List[str]:
        mods = next((c for c in decl.children if c.type == "modifiers"), None)
        if mods is None:
            return []
        out = []
        for c in mods.children:
            if c.type in ("marker_annotation", "annotation"):
                out.append(_text(c, self.src).lstrip("@").split("(")[0])
            elif c.is_named or c.type in ("static", "abstract", "final", "synchronized", "default", "native"):
                out.append(_text(c, self.src))
        return out

    def _java_type(self, decl, parent_class: Optional[str]):
        kind = decl.type.replace("_declaration", "")          # class, interface, enum, record, annotation_type
        name = _text(decl.child_by_field_name("name"), self.src)
        start = decl
        line = _line(start)
        bases: List[str] = []
        sup = decl.child_by_field_name("superclass")
        if sup is not None:
            bases += [_text(c, self.src) for c in sup.named_children]
        ifaces = decl.child_by_field_name("interfaces") or next(
            (c for c in decl.children if c.type in ("super_interfaces", "extends_interfaces")), None)
        if ifaces is not None:
            for c in _walk(ifaces):
                if c.type in ("type_identifier", "generic_type", "scoped_type_identifier") and c.parent.type == "type_list":
                    bases.append(_text(c, self.src))
        doc = self._doc_comment(start)
        qual = f"{parent_class}.{name}" if parent_class else name
        cf = ClassFeature(node_id=self._node_id("class", qual, line), name=qual, lineno=line,
                          col_offset=len(self._indent_of(line)), bases=bases,
                          has_docstring=doc is not None, docstring=doc)
        self.mf.classes.append(cf)
        self.facts[cf.node_id] = DeclFacts(kind=kind, insert_line=line, indent=self._indent_of(line),
                                           end_line=decl.end_point[0] + 1, class_kind=kind)
        body = decl.child_by_field_name("body")
        if body is None:
            return
        for member in body.named_children:
            if member.type in ("method_declaration", "constructor_declaration", "compact_constructor_declaration"):
                cf.methods.append(_text(member.child_by_field_name("name"), self.src))
                self._java_method(member, qual, kind)
            elif member.type == "field_declaration":
                for d in member.children_by_field_name("declarator"):
                    cf.class_variables.append(_text(d.child_by_field_name("name"), self.src))
            elif member.type == "enum_body_declarations":
                for m in member.named_children:
                    if m.type in ("method_declaration", "constructor_declaration"):
                        cf.methods.append(_text(m.child_by_field_name("name"), self.src))
                        self._java_method(m, qual, kind)
            elif member.type == "enum_constant":
                cf.class_variables.append(_text(member.child_by_field_name("name"), self.src))
            elif member.type.endswith("_declaration") and member.child_by_field_name("name") is not None \
                    and member.type in ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"):
                self._java_type(member, qual)

    def _java_method(self, decl, parent_class: str, owner_kind: str):
        name = _text(decl.child_by_field_name("name"), self.src)
        line = _line(decl)
        is_ctor = decl.type != "method_declaration"
        params = self._java_params(decl.child_by_field_name("parameters"))
        ret = None if is_ctor else _squash(_text(decl.child_by_field_name("type"), self.src), 40)
        mods = self._java_modifiers(decl)
        body = decl.child_by_field_name("body")
        loops, conds, cc, calls, throws, returns_value = self._body_stats(body)
        declared = []
        throws_node = next((c for c in decl.children if c.type == "throws"), None)
        if throws_node is not None:
            declared = [_text(c, self.src) for c in throws_node.named_children]
        doc = self._doc_comment(decl)
        ff = FunctionFeature(
            node_id=self._node_id("func", f"{parent_class}.{name}", line), name=name, lineno=line,
            col_offset=len(self._indent_of(line)), params=params, return_annotation=ret,
            decorators=mods, has_docstring=doc is not None, docstring=doc,
            body_lines=decl.end_point[0] - decl.start_point[0], calls_made=calls,
            loops=loops, conditionals=conds, is_method=True, parent_class=parent_class,
        )
        self.mf.functions.append(ff)
        self.bodies[ff.node_id] = body
        self.facts[ff.node_id] = DeclFacts(
            kind="constructor" if is_ctor else "method", insert_line=line, indent=self._indent_of(line),
            end_line=decl.end_point[0] + 1, throws=list(dict.fromkeys(declared + throws)),
            returns_value=returns_value, is_declaration_only=body is None,
        )
        self._cc[ff.node_id] = cc

    def extract_java(self, root):
        for node in root.named_children:
            if node.type in ("class_declaration", "interface_declaration", "enum_declaration",
                             "record_declaration", "annotation_type_declaration"):
                self._java_type(node, None)
            elif node.type == "import_declaration":
                self.mf.imports.append(_text(node, self.src).replace("import", "", 1).strip(" ;"))

    # ── C / C++ ─────────────────────────────────────────────────────────────
    def _func_declarator(self, declarator):
        """Unwrap pointer/reference declarators down to the function_declarator; count pointer levels."""
        suffix = ""
        node = declarator
        while node is not None and node.type != "function_declarator":
            if node.type == "pointer_declarator":
                suffix += "*"
            elif node.type == "reference_declarator":
                suffix += "&&" if _text(node, self.src).lstrip().startswith("&&") else "&"
            nxt = node.child_by_field_name("declarator")
            if nxt is None:
                nxt = next((c for c in node.named_children if c.type.endswith("declarator")), None)
            node = nxt
        return node, suffix

    def _c_params(self, params_node) -> List[ParamFeature]:
        out: List[ParamFeature] = []
        if params_node is None:
            return out
        for p in params_node.named_children:
            if p.type in ("parameter_declaration", "optional_parameter_declaration"):
                type_text = _text(p.child_by_field_name("type"), self.src)
                decl = p.child_by_field_name("declarator")
                if decl is None:
                    if type_text.strip() == "void":
                        continue
                    out.append(ParamFeature(f"arg{len(out) + 1}", _squash(type_text, 40)))
                    continue
                name_node, stars = decl, ""
                while name_node is not None and name_node.type not in ("identifier", "field_identifier"):
                    if name_node.type == "pointer_declarator":
                        stars += "*"
                    elif name_node.type == "reference_declarator":
                        stars += "&"
                    elif name_node.type == "array_declarator":
                        stars += "[]"
                    nxt = name_node.child_by_field_name("declarator")
                    if nxt is None:
                        nxt = next((c for c in name_node.named_children if c.type in ("identifier",) or c.type.endswith("declarator")), None)
                    name_node = nxt
                name = _text(name_node, self.src) if name_node is not None else f"arg{len(out) + 1}"
                default = p.child_by_field_name("default_value")
                out.append(ParamFeature(name, _squash(f"{type_text}{stars}", 40),
                                        _squash(_text(default, self.src), 30) if default is not None else None))
            elif p.type == "variadic_parameter" or _text(p, self.src).strip() == "...":
                out.append(ParamFeature("...", "variadic"))
        return out

    def _c_function(self, node, parent_class: Optional[str], declaration_only: bool,
                    declarator=None, type_node=None):
        declarator = declarator if declarator is not None else node.child_by_field_name("declarator")
        fdecl, stars = self._func_declarator(declarator)
        if fdecl is None:
            return None
        name_node = fdecl.child_by_field_name("declarator")
        raw_name = _text(name_node, self.src)
        owner = parent_class
        name = raw_name
        if name_node is not None and name_node.type == "qualified_identifier":
            scope = name_node.child_by_field_name("scope")
            inner = name_node.child_by_field_name("name")
            owner = owner or _text(scope, self.src)
            name = _text(inner, self.src)
        type_node = type_node if type_node is not None else node.child_by_field_name("type")
        ret_type = _squash(f"{_text(type_node, self.src)}{stars}", 40) if type_node is not None else None
        short_owner = (owner or "").split("::")[-1]
        is_dtor = name.startswith("~")
        is_ctor = owner is not None and not is_dtor and name == short_owner and ret_type is None
        start = self._decl_start(node)
        line = _line(start)
        body = node.child_by_field_name("body")
        loops, conds, cc, calls, throws, returns_value = self._body_stats(body)
        mods = []
        for c in node.children:
            if c.type in ("storage_class_specifier", "type_qualifier", "virtual", "function_specifier"):
                mods.append(_text(c, self.src))
        if start.type == "template_declaration":
            mods.append("template")
        doc = self._doc_comment(start)
        label = f"{owner}::{name}" if owner else name
        ff = FunctionFeature(
            node_id=self._node_id("func", label, line), name=name, lineno=line,
            col_offset=len(self._indent_of(line)), params=self._c_params(fdecl.child_by_field_name("parameters")),
            return_annotation=None if (is_ctor or is_dtor) else ret_type, decorators=mods,
            has_docstring=doc is not None, docstring=doc,
            body_lines=node.end_point[0] - node.start_point[0], calls_made=calls,
            loops=loops, conditionals=conds, is_method=owner is not None, parent_class=owner,
        )
        self.mf.functions.append(ff)
        self.bodies[ff.node_id] = body
        kind = "destructor" if is_dtor else "constructor" if is_ctor else ("method" if owner else "function")
        self.facts[ff.node_id] = DeclFacts(
            kind=kind, insert_line=line, indent=self._indent_of(line), end_line=node.end_point[0] + 1,
            throws=throws, returns_value=returns_value, is_declaration_only=declaration_only,
        )
        self._cc[ff.node_id] = cc
        if owner and owner in self.classes_by_name and name not in self.classes_by_name[owner].methods:
            self.classes_by_name[owner].methods.append(name)
        return ff

    def _c_record(self, spec, parent_class: Optional[str], typedef_name: Optional[str] = None, outer=None):
        """struct / class / union specifier with a body."""
        body = spec.child_by_field_name("body")
        if body is None:
            return
        name = _text(spec.child_by_field_name("name"), self.src) or typedef_name or "(anonymous)"
        kind = spec.type.replace("_specifier", "")            # struct | class | union | enum
        anchor = self._decl_start(outer if outer is not None else spec)
        line = _line(anchor)
        qual = f"{parent_class}::{name}" if parent_class else name
        bases = []
        base_clause = next((c for c in spec.children if c.type == "base_class_clause"), None)
        if base_clause is not None:
            bases = [_text(c, self.src) for c in base_clause.named_children
                     if c.type in ("type_identifier", "qualified_identifier", "template_type")]
        doc = self._doc_comment(anchor)
        cf = ClassFeature(node_id=self._node_id("class", qual, line), name=qual, lineno=line,
                          col_offset=len(self._indent_of(line)), bases=bases,
                          has_docstring=doc is not None, docstring=doc)
        self.mf.classes.append(cf)
        self.classes_by_name[qual] = cf
        self.classes_by_name.setdefault(name, cf)
        self.facts[cf.node_id] = DeclFacts(kind=kind, insert_line=line, indent=self._indent_of(line),
                                           end_line=anchor.end_point[0] + 1, class_kind=kind)
        if kind == "enum":
            cf.class_variables = [_text(e.child_by_field_name("name"), self.src)
                                  for e in body.named_children if e.type == "enumerator"]
            return
        for member in body.named_children:
            target = member
            if member.type == "template_declaration":
                target = next((c for c in member.named_children
                               if c.type in ("function_definition", "declaration", "field_declaration")), member)
            if target.type == "function_definition":
                ff = self._c_function(target, qual, declaration_only=False)
                if ff and ff.name not in cf.methods:
                    cf.methods.append(ff.name)
            elif target.type in ("field_declaration", "declaration"):
                fdecls = [d for d in target.children_by_field_name("declarator")]
                handled = False
                for d in fdecls:
                    fd, _ = self._func_declarator(d)
                    if fd is not None:
                        ff = self._c_function(target, qual, declaration_only=True, declarator=d)
                        if ff and ff.name not in cf.methods:
                            cf.methods.append(ff.name)
                        handled = True
                    else:
                        n = d
                        while n is not None and n.type not in ("field_identifier", "identifier"):
                            n = n.child_by_field_name("declarator")
                        if n is not None:
                            cf.class_variables.append(_text(n, self.src))
                if not handled:
                    t = target.child_by_field_name("type")
                    if t is not None and t.type in ("struct_specifier", "class_specifier", "union_specifier", "enum_specifier"):
                        self._c_record(t, qual, outer=target)

    def _c_block(self, container, parent_class: Optional[str] = None):
        for node in container.named_children:
            t = node.type
            target = node
            if t == "template_declaration":
                target = next((c for c in node.named_children
                               if c.type in ("function_definition", "class_specifier", "struct_specifier", "declaration")), None)
                if target is None:
                    continue
                t = target.type
            if t == "function_definition":
                self._c_function(target, parent_class, declaration_only=False)
            elif t in ("declaration", "type_definition"):
                type_node = target.child_by_field_name("type")
                if type_node is not None and type_node.type in ("struct_specifier", "class_specifier",
                                                                "union_specifier", "enum_specifier"):
                    typedef_name = None
                    if t == "type_definition":
                        d = target.child_by_field_name("declarator")
                        typedef_name = _text(d, self.src) if d is not None else None
                    self._c_record(type_node, parent_class, typedef_name, outer=target)
                    continue
                for d in target.children_by_field_name("declarator"):
                    fd, _ = self._func_declarator(d)
                    if fd is not None:                        # a prototype
                        self._prototypes.append((target, d))
            elif t in ("class_specifier", "struct_specifier", "union_specifier", "enum_specifier"):
                self._c_record(target, parent_class)
            elif t == "namespace_definition":
                body = target.child_by_field_name("body")
                if body is not None:
                    self._c_block(body, parent_class)
            elif t == "linkage_specification":
                body = target.child_by_field_name("body")
                if body is not None:
                    self._c_block(body if body.type == "declaration_list" else target, parent_class)
            elif t == "preproc_include":
                path = target.child_by_field_name("path")
                if path is not None:
                    self.mf.imports.append(_text(path, self.src).strip('<>"'))
            elif t in ("preproc_ifdef", "preproc_if", "preproc_else", "preproc_elif"):
                self._c_block(target, parent_class)      # include guards and #if blocks

    def extract_c(self, root):
        self._prototypes = []
        self._c_block(root)
        defined = {(f.parent_class, f.name) for f in self.mf.functions}
        for decl, d in self._prototypes:
            fd, _ = self._func_declarator(d)
            name_node = fd.child_by_field_name("declarator")
            if (None, _text(name_node, self.src)) in defined:
                continue                # documented at its definition instead
            self._c_function(decl, None, declaration_only=True, declarator=d)

    # ── entry ───────────────────────────────────────────────────────────────
    def run(self) -> ForeignAnalysis:
        self._cc: Dict[str, int] = {}
        tree = _parser(self.lang).parse(self.src)
        root = tree.root_node
        warnings = []
        if root.has_error:
            bad = next((n for n in _walk(root) if n.type == "ERROR" or n.is_missing), None)
            where = f" near line {_line(bad)}, column {bad.start_point[1] + 1}" if bad is not None else ""
            warnings.append(f"The parser recovered from a syntax error{where}; comments may be incomplete there.")
        if self.lang == "java":
            self.extract_java(root)
        else:
            self.extract_c(root)
        self.mf.functions.sort(key=lambda f: f.lineno)
        self.mf.classes.sort(key=lambda c: c.lineno)
        return ForeignAnalysis(self.lang, self.mf, self._context(), self.facts, warnings)

    def _context(self) -> ContextGraph:
        names = {f.name for f in self.mf.functions}
        cg = ContextGraph(module_name=self.filepath, module_function_names=names)
        for ff in self.mf.functions:
            cc = self._cc.get(ff.node_id, 1)

            def base(call: str) -> str:
                return call.replace("->", ".").replace("::", ".").split(".")[-1]
            internal = [c for c in ff.calls_made if base(c) in names and base(c) != ff.name]
            external = [c for c in ff.calls_made if base(c) not in names]
            cg.function_contexts.append(FunctionContext(
                node_id=ff.node_id, name=ff.name, cyclomatic_complexity=cc,
                variables=self._variables(self.bodies.get(ff.node_id)),
                calls_internal=internal, calls_external=external,
                complexity_label=_complexity_label(cc),
            ))
            cg.call_graph[ff.name] = ff.calls_made
        return cg


def analyze_source(source: str, language: str, filepath: str = "") -> ForeignAnalysis:
    """Parse Java / C / C++ source and return features, context and placement facts."""
    if language not in ("java", "c", "cpp"):
        raise ValueError(f"tree-sitter front end does not handle {language!r}")
    return _Extractor(language, source, filepath).run()
