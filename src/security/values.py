"""
Constant values and container shapes used by the taint engine for precision.

Only literal values are evaluated (numbers, strings, bytes, bools, None and
tuples/lists of those), with size limits so that analysing hostile code cannot
blow up memory or time. Anything else is "unknown" (``NOVAL``).
"""
from __future__ import annotations

import operator
from typing import Any, List, Sequence

NOVAL = object()
MAX_STR = 10_000
MAX_INT_BITS = 4096

_BIN = {
    "Add": operator.add, "Sub": operator.sub, "Mult": operator.mul, "Div": operator.truediv,
    "FloorDiv": operator.floordiv, "Mod": operator.mod, "Pow": operator.pow,
    "BitAnd": operator.and_, "BitOr": operator.or_, "BitXor": operator.xor,
    "LShift": operator.lshift, "RShift": operator.rshift,
}
_CMP = {
    "Eq": operator.eq, "NotEq": operator.ne, "Lt": operator.lt, "LtE": operator.le,
    "Gt": operator.gt, "GtE": operator.ge, "In": lambda a, b: a in b,
    "NotIn": lambda a, b: a not in b, "Is": operator.is_, "IsNot": operator.is_not,
}
_UN = {"Not": operator.not_, "USub": operator.neg, "UAdd": operator.pos, "Invert": operator.invert}
_PURE = {"len": len, "str": str, "int": int, "float": float, "abs": abs, "bool": bool,
         "ord": ord, "chr": chr, "min": min, "max": max, "repr": repr}


def is_literal(v: Any) -> bool:
    if v is None or isinstance(v, (bool, int, float)):
        return not isinstance(v, int) or v.bit_length() <= MAX_INT_BITS
    if isinstance(v, (str, bytes)):
        return len(v) <= MAX_STR
    if isinstance(v, tuple):          # immutable only: a list "constant" goes stale on append
        return len(v) <= 1000 and all(is_literal(x) for x in v)
    if isinstance(v, slice):
        return all(is_literal(x) for x in (v.start, v.stop, v.step))
    return False


def _guard(v: Any) -> Any:
    return v if is_literal(v) else NOVAL


def binop(op: str, a: Any, b: Any) -> Any:
    fn = _BIN.get(op)
    if fn is None:
        return NOVAL
    if op == "Pow" and (not isinstance(b, int) or abs(b) > 64):
        return NOVAL
    if op == "LShift" and (not isinstance(b, int) or b > 256):
        return NOVAL
    if op == "Mult" and isinstance(b, int) and isinstance(a, (str, bytes, tuple, list)) and len(a) * b > MAX_STR:
        return NOVAL
    try:
        return _guard(fn(a, b))
    except Exception:
        return NOVAL


def compare(ops: Sequence[str], values: Sequence[Any]) -> Any:
    try:
        for op, a, b in zip(ops, values, values[1:]):
            fn = _CMP.get(op)
            if fn is None:
                return NOVAL
            if not fn(a, b):
                return False
        return True
    except Exception:
        return NOVAL


def boolop(op: str, values: Sequence[Any]) -> Any:
    result = values[0]
    for v in values[1:]:
        if op == "And" and not result:
            return result
        if op == "Or" and result:
            return result
        result = v
    return result


def unop(op: str, a: Any) -> Any:
    fn = _UN.get(op)
    if fn is None:
        return NOVAL
    try:
        return _guard(fn(a))
    except Exception:
        return NOVAL


def subscript(base: Any, index: Any) -> Any:
    try:
        return _guard(base[index])
    except Exception:
        return NOVAL


def pure_call(name: str, args: List[Any]) -> Any:
    fn = _PURE.get(name)
    if fn is None:
        return NOVAL
    try:
        return _guard(fn(*args))
    except Exception:
        return NOVAL
