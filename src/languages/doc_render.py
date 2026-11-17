"""
Rule-based doc comments for Java (Javadoc) and C / C++ (Doxygen).

The wording comes from the same NLP helpers as the Python generator
(identifier splitting, verb selection, body description), so a function gets
the same summary in every language; only the comment syntax differs.
"""
from __future__ import annotations

import re
import textwrap
from typing import Dict, List, Optional

from ..ast_extractor import ClassFeature, FunctionFeature
from ..comment_generator import (
    CommentItem, _VERB_MAP, _describe_body, _humanize, _meaningful_tokens, _pick_verb, _split_identifier,
)
from ..context_analyzer import FunctionContext, VariableInfo
from .treesitter_extract import DeclFacts, ForeignAnalysis

_WIDTH = 76
_VOID = {"void", "Void"}
_BOOL = {"boolean", "bool", "Boolean", "_Bool"}
_PRIMITIVES = {
    "int", "long", "short", "char", "byte", "float", "double", "bool", "boolean", "void", "auto",
    "unsigned", "signed", "size_t", "ssize_t", "String", "Integer", "Long", "Double", "Boolean",
    "var", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
    "std::string", "string", "const char*", "char*",
}
_NBSP = " "

# Python-centric sentences from _describe_body that never apply to these languages.
_DROP_PREFIXES = ("Runs asynchronously", "Defined as a", "Declared as an abstract", "Results are memoized", "Uses @overload")

_THROW_REASONS = {
    "IllegalArgumentException": "if an argument is invalid",
    "invalid_argument": "if an argument is invalid",
    "NullPointerException": "if a required value is null",
    "IllegalStateException": "if the object is in an invalid state",
    "IOException": "if an I/O error occurs",
    "FileNotFoundException": "if the file does not exist",
    "UncheckedIOException": "if an I/O error occurs",
    "IndexOutOfBoundsException": "if an index is out of range",
    "out_of_range": "if an index or key is out of range",
    "ArithmeticException": "if the arithmetic is undefined",
    "UnsupportedOperationException": "if the operation is not supported",
    "bad_alloc": "if memory cannot be allocated",
    "length_error": "if a size limit is exceeded",
    "domain_error": "if an argument is outside the valid domain",
    "overflow_error": "if the result overflows",
}


def _article(phrase: str) -> str:
    return "an" if phrase[:1].lower() in "aeiou" else "a"


def _noun_phrase(name: str) -> str:
    tokens = _meaningful_tokens(name)
    noun = " ".join(t for t in tokens if t not in _VERB_MAP).strip()
    return noun or _humanize(name).lower()


def _summary(ff: FunctionFeature, facts: DeclFacts) -> str:
    owner = (ff.parent_class or "").replace("::", ".").split(".")[-1]
    if facts.kind == "constructor":
        return f"Creates a new {owner or ff.name} instance."
    if facts.kind == "destructor":
        return f"Destroys the {owner or ff.name.lstrip('~')} and releases its resources."
    if ff.name == "main" and not ff.is_method:
        return "Program entry point."
    if ff.name in ("toString", "to_string"):
        return f"Returns a text representation of this {owner or 'object'}."
    if ff.name in ("equals", "operator=="):
        return "Checks whether another object is equal to this one."
    if ff.name == "hashCode":
        return "Computes a hash code for this object."
    raw = _split_identifier(ff.name)
    ret = (ff.return_annotation or "").strip()
    if raw and raw[0] in ("is", "has", "can", "should") and ret in _BOOL:
        rest = " ".join(raw[1:]) or "set"
        return f"Checks whether {'it is' if raw[0] == 'is' else 'it ' + raw[0]} {rest}."
    tokens = _meaningful_tokens(ff.name)
    if not any(t in _VERB_MAP for t in tokens) and ret and ret not in _VOID:
        return f"Returns the {_noun_phrase(ff.name)}."           # noun-only names: area(), size()
    return f"{_pick_verb(tokens)} {_noun_phrase(ff.name)}."


def _interesting_types(fc: Optional[FunctionContext]) -> List[str]:
    if fc is None:
        return []
    seen = []
    for vi in fc.variables:
        t = (vi.inferred_type or "").replace("const ", "").strip()
        if t and t not in _PRIMITIVES and t not in seen:
            seen.append(t)
    return seen[:4]


def _body_sentences(ff: FunctionFeature, fc: Optional[FunctionContext], facts: DeclFacts) -> List[str]:
    if facts.is_declaration_only:
        return []
    # _describe_body's own data-structure sentence filters Python types; ours filters C/Java primitives.
    trimmed = None
    if fc is not None:
        trimmed = FunctionContext(**{**fc.__dict__, "variables": []})
        trimmed.calls_external = [c for c in fc.calls_external if c not in facts.throws]
    sentences = [s for s in _describe_body(ff, trimmed, "") if not s.startswith(_DROP_PREFIXES)]
    types = _interesting_types(fc)
    if types:
        sentences.append("Works with: " + ", ".join(f"`{t}`" for t in types) + ".")
    return sentences


def _returns(ff: FunctionFeature, facts: DeclFacts) -> Optional[str]:
    ret = (ff.return_annotation or "").strip()
    if facts.kind in ("constructor", "destructor") or not ret or ret in _VOID:
        return None
    if ret in _BOOL:
        if _split_identifier(ff.name)[:1] in (["is"], ["has"], ["can"], ["should"]):
            return "true if the condition holds, false otherwise"
        return "true on success, false otherwise"
    if ff.name in ("toString", "to_string"):
        return "a text representation of this object"
    noun = _noun_phrase(ff.name)
    if ret.endswith("*"):
        allocates = any(a in c for c in ff.calls_made for a in ("malloc", "calloc", "realloc"))
        return f"a pointer to the {noun}, or NULL on failure" if allocates else f"a pointer to the {noun}"
    return f"the {noun}"


def _base_type(type_text: Optional[str]) -> str:
    t = (type_text or "").replace("const ", "").replace("struct ", "")
    return t.rstrip("*&[] ").strip()


def _param_tag(p, style: str) -> str:
    name = p.name
    if name == "...":
        return "@param ... additional arguments"
    tokens = _split_identifier(name)
    direction = ""
    if style == "doxygen" and tokens and tokens[0] in ("out", "result", "dest", "dst") and (p.annotation or "").endswith("*"):
        direction = "[out]"
        rest = " ".join(tokens[1:]) or "result"
        desc = f"receives the {rest}"
    elif len(name) <= 2 and _base_type(p.annotation):
        base = _base_type(p.annotation)
        desc = f"the {base} to operate on" if (p.annotation or "").rstrip().endswith(("*", "&")) else f"the {base} value"
    else:
        desc = f"the {_humanize(name).lower()}"
    if p.default:
        desc += f" (default {p.default})"
    return f"@param{direction} {name} {desc}"


def _throw_reason(exc: str) -> str:
    short = exc.split("::")[-1].split(".")[-1]
    return _THROW_REASONS.get(short, "if the operation fails")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _javadoc_text(text: str) -> str:
    """`x` -> {@code x}; escape <, >, & elsewhere (Javadoc is HTML)."""
    out, pos = [], 0
    for m in re.finditer(r"`([^`]+)`", text):
        out.append(text[pos:m.start()].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        out.append("{@code" + _NBSP + m.group(1).replace(" ", _NBSP) + "}")
        pos = m.end()
    out.append(text[pos:].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    return "".join(out)


def _doxygen_text(text: str) -> str:
    return re.sub(r"`([^`]+)`", lambda m: "`" + m.group(1).replace(" ", _NBSP) + "`", text)


def _wrap(text: str, first: str, rest: str) -> List[str]:
    lines = textwrap.wrap(text, width=_WIDTH, initial_indent=first, subsequent_indent=rest,
                          break_long_words=False, break_on_hyphens=False)
    return [ln.replace(_NBSP, " ") for ln in lines] or [first.rstrip()]


def _block(summary: str, body: List[str], tags: List[str], style: str) -> str:
    fmt = _javadoc_text if style == "javadoc" else _doxygen_text
    lines = ["/**"]
    lines += _wrap(fmt(summary if style == "javadoc" else f"@brief {summary}"), " * ", " * ")
    if body:
        lines.append(" *")
        if style == "javadoc":
            lines.append(" * <p>")
        for sentence in body:
            lines += _wrap(fmt(sentence), " * ", " * ")
    if tags:
        lines.append(" *")
        for tag in tags:
            lines += _wrap(fmt(tag), " * ", " *     ")
    lines.append(" */")
    return "\n".join(lines)


def render_function(ff: FunctionFeature, fc: Optional[FunctionContext], facts: DeclFacts, style: str) -> str:
    tags = [_param_tag(p, style) for p in ff.params]
    ret = _returns(ff, facts)
    if ret:
        tags.append(f"@return {ret}")
    for exc in facts.throws[:4]:
        tags.append(f"@throws {exc} {_throw_reason(exc)}")
    return _block(_summary(ff, facts), _body_sentences(ff, fc, facts), tags, style)


def render_class(cf: ClassFeature, facts: DeclFacts, style: str, language: str) -> str:
    short = cf.name.replace("::", ".").split(".")[-1]
    noun = " ".join(_meaningful_tokens(short)) or short
    kind = facts.class_kind or "class"
    summary = {
        "interface": f"Defines the contract for {noun}.",
        "enum": f"Enumerates the possible {noun} values.",
        "union": f"Holds one of several {noun} representations.",
        "record": f"Immutable record holding {noun} data.",
    }.get(kind, f"Represents {_article(noun)} {noun}.")
    body: List[str] = []
    if cf.bases:
        verb = "Extends" if language == "java" else "Derives from"
        body.append(f"{verb} {', '.join(f'`{b}`' for b in cf.bases)}.")
    if kind == "enum" and cf.class_variables:
        body.append("Values: " + ", ".join(cf.class_variables[:10]) + ".")
    elif kind in ("struct", "union") and cf.class_variables:
        body.append("Fields: " + ", ".join(f"`{v}`" for v in cf.class_variables[:10]) + ".")
    elif cf.class_variables:
        body.append("State: " + ", ".join(f"`{v}`" for v in cf.class_variables[:8]) + ".")
    public = [m for m in dict.fromkeys(cf.methods) if not m.startswith(("_", "~")) and m != short]
    if public and kind != "enum":
        body.append("Operations: " + ", ".join(f"`{m}()`" for m in public[:8]) + ".")
    return _block(summary, body, [], style)


def render_complexity_note(ff: FunctionFeature, fc: FunctionContext) -> Optional[str]:
    """A short // block above non-simple functions, mirroring the Python inline comment."""
    if fc.complexity_label == "simple":
        return None
    parts = []
    if ff.loops:
        parts.append(f"{ff.loops} loop(s)")
    if ff.conditionals:
        parts.append(f"{ff.conditionals} conditional(s)")
    lines = [f"// Complexity: cyclomatic {fc.cyclomatic_complexity} ({fc.complexity_label.replace('_', ' ')})"
             + (f"; {', '.join(parts)}." if parts else ".")]
    if fc.complexity_label in ("complex", "very_complex"):
        lines.append("// Consider splitting this function into smaller ones.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_foreign_comments(fa: ForeignAnalysis) -> List[CommentItem]:
    """Doc comments for every undocumented class and function in a Java / C / C++ file."""
    style = "javadoc" if fa.language == "java" else "doxygen"
    contexts: Dict[str, FunctionContext] = {fc.node_id: fc for fc in fa.context_graph.function_contexts}
    items: List[CommentItem] = []

    for cf in fa.module_features.classes:
        if cf.has_docstring:
            continue
        facts = fa.facts[cf.node_id]
        items.append(CommentItem(cf.node_id, "class", facts.insert_line, len(facts.indent),
                                 render_class(cf, facts, style, fa.language), "block", cf.name))

    for ff in fa.module_features.functions:
        if ff.has_docstring:
            continue
        facts = fa.facts[ff.node_id]
        fc = contexts.get(ff.node_id)
        note = render_complexity_note(ff, fc) if fc is not None else None
        if note:
            items.append(CommentItem(ff.node_id + "_inline", "inline", facts.insert_line, len(facts.indent),
                                     note, "inline", ff.name))
        items.append(CommentItem(ff.node_id, "function", facts.insert_line, len(facts.indent),
                                 render_function(ff, fc, facts, style), "block", ff.name))
    # Stable sort: within one declaration the complexity note stays above the doc comment.
    items.sort(key=lambda c: c.lineno)
    return items
