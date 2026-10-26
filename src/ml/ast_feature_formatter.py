"""
AST Feature Formatter
=====================
Converts structured AST data (FunctionFeature + FunctionContext + raises list)
into a structured natural-language text string that a T5 model can be trained on.

The model learns the mapping:
    AST feature text  →  natural-language docstring

This is the key to "AST + NLP" comment generation: the model's ONLY input is
the structured extraction of what the code does (loops, conditions, calls,
types, complexity, decorators, raises) — NOT the source code or function name.

Format example
--------------
    Generate docstring: process_items
    async: no | method: no
    params: items:list, threshold:int=5
    returns: dict
    loops: 1 | conditionals: 2 | body_size: 8
    complexity: moderate (cyclomatic=4)
    calls_internal: validate_input, store_result
    calls_external: os.path.join
    raises: ValueError, IOError
    decorators: staticmethod
"""

from typing import List, Optional

# Builtins excluded from calls_external (too noisy)
_BUILTINS = {
    "print", "len", "range", "str", "int", "float", "bool", "list", "dict",
    "set", "tuple", "type", "isinstance", "hasattr", "getattr", "setattr",
    "super", "enumerate", "zip", "map", "filter", "sorted", "reversed",
    "any", "all", "max", "min", "sum", "abs", "round", "repr", "vars",
    "open", "iter", "next", "format", "id", "hash", "dir", "help",
}


def format_for_model(ff, fc=None, raises: Optional[List[str]] = None) -> str:
    """
    Produce a compact, structured text representation of AST features.

    This is the **input** to the T5 model during both training and inference.
    Every field comes from the AST — no raw source code is included.

    Args:
        ff:     FunctionFeature dataclass (from ast_extractor).
        fc:     FunctionContext dataclass (from context_analyzer), optional.
        raises: List of exception names raised in the body (from
                ast_body_extractor.extract_raises), optional.

    Returns:
        Multi-line structured text string ready to prepend with T5 task prefix.
    """
    lines = []

    # ── Header: function identity ─────────────────────────────────────────────
    lines.append(f"Generate docstring: {ff.name}")

    # Async / method flags
    async_flag  = "yes" if ff.is_async else "no"
    method_flag = "yes" if ff.is_method else "no"
    lines.append(f"async: {async_flag} | method: {method_flag}")

    # ── Parameters ────────────────────────────────────────────────────────────
    real_params = [p for p in ff.params if p.name not in ("self", "cls")]
    if real_params:
        param_parts = []
        for p in real_params:
            part = f"{p.name}:{p.annotation}" if p.annotation else p.name
            if p.default is not None:
                part += f"={p.default}"
            param_parts.append(part)
        lines.append(f"params: {', '.join(param_parts)}")
    else:
        lines.append("params: none")

    # ── Return type ───────────────────────────────────────────────────────────
    if ff.return_annotation and ff.return_annotation not in ("None", "none"):
        lines.append(f"returns: {ff.return_annotation}")
    else:
        lines.append("returns: none")

    # ── Control-flow structure ────────────────────────────────────────────────
    lines.append(
        f"loops: {ff.loops} | conditionals: {ff.conditionals} | body_size: {ff.body_lines}"
    )

    # ── Semantic complexity ───────────────────────────────────────────────────
    if fc is not None:
        lines.append(
            f"complexity: {fc.complexity_label} (cyclomatic={fc.cyclomatic_complexity})"
        )

        # Internal module calls
        if fc.calls_internal:
            lines.append(f"calls_internal: {', '.join(fc.calls_internal[:6])}")

        # External calls (filtered)
        ext = [
            c for c in fc.calls_external
            if c.split(".")[0] not in _BUILTINS
        ][:5]
        if ext:
            lines.append(f"calls_external: {', '.join(ext)}")

        # Variable data structures
        struct_types = set()
        for vi in fc.variables:
            t = vi.inferred_type
            if t and t not in ("None", "NoneType", "bool", "int", "float",
                               "str", "object"):
                struct_types.add(t)
        if struct_types:
            lines.append(f"data_structures: {', '.join(sorted(struct_types)[:4])}")
    else:
        lines.append("complexity: unknown (cyclomatic=1)")

    # ── Exceptions ────────────────────────────────────────────────────────────
    if raises:
        lines.append(f"raises: {', '.join(raises[:4])}")
    else:
        lines.append("raises: none")

    # ── Decorators ────────────────────────────────────────────────────────────
    if ff.decorators:
        # Simplify decorator names
        dec_names = []
        for d in ff.decorators[:3]:
            simple = d.split(".")[-1].split("(")[0]
            dec_names.append(simple)
        lines.append(f"decorators: {', '.join(dec_names)}")
    else:
        lines.append("decorators: none")

    return "\n".join(lines)


def format_from_source(source_code: str, func_name: str) -> Optional[str]:
    """
    Parse a single function from source_code and return its formatted
    AST feature text.  Convenience wrapper used in the dataset builder.

    Returns None if the function cannot be found or parsed.
    """
    import ast as _ast
    try:
        from ..ast_extractor import extract_features
        from ..context_analyzer import analyze_context
        from ..ast_body_extractor import extract_raises

        tree = _ast.parse(source_code)
        mf   = extract_features(tree, source_code=source_code)
        cg   = analyze_context(mf, tree, source_code, include_security=False)

        fc_map = {fc.name: fc for fc in cg.function_contexts}

        for ff in mf.functions:
            if ff.name != func_name:
                continue
            fc = fc_map.get(ff.name)
            end = ff.lineno + ff.body_lines
            raises = extract_raises(source_code, ff.lineno, end)
            return format_for_model(ff, fc, raises)
    except Exception:
        pass
    return None
