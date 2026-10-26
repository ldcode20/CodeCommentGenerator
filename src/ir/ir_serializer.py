"""
IR Serializer — Week 8
=======================
Two output formats for an IRModule:

1. serialize_ir(ir_module) → dict
   Produces a JSON-serializable nested dictionary.  Useful for logging /
   analysis tooling that consumes JSON.

2. pretty_print_ir(ir_module) → str
   Produces a human-readable textual representation that resembles LLVM IR
   text format:

   define i32 @search_sorted(arr, target)  ; line 1
   entry:
     t0 = LOAD(arr)
     t1 = LOAD(target)
   loop_0_header:
     t2 = BINOP(lt, __iter__, __end__)
     branch t2, loop_0_body, loop_0_after
   ...

"""
from __future__ import annotations

import dataclasses
import json
from typing import Any, Dict

from .ir_nodes import IRModule, IRFunction, IRBlock, IRInstruction, IROpcode


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------

def _instr_to_dict(instr: IRInstruction) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "op": instr.op.value,
        "result": instr.result,
        "operands": instr.operands,
        "lineno": instr.lineno,
        "col": instr.col,
        "meta": instr.meta,
    }
    if instr.call is not None:
        d["call"] = dataclasses.asdict(instr.call)
    if instr.refinements:
        d["refinements"] = [dataclasses.asdict(r) for r in instr.refinements]
    if instr.guards:
        d["guards"] = list(instr.guards)
    return d


def _block_to_dict(block: IRBlock) -> Dict[str, Any]:
    return {
        "label": block.label,
        "instructions": [_instr_to_dict(i) for i in block.instructions],
        "successors": block.successors,
        "predecessors": block.predecessors,
    }


def _function_to_dict(func: IRFunction) -> Dict[str, Any]:
    return {
        "name": func.name,
        "params": func.params,
        "return_type": func.return_type,
        "is_method": func.is_method,
        "is_async": func.is_async,
        "source_lineno": func.source_lineno,
        "blocks": [_block_to_dict(b) for b in func.blocks],
    }


def serialize_ir(ir_module: IRModule) -> Dict[str, Any]:
    """
    Serialize an IRModule to a JSON-compatible nested dict.

    Args:
        ir_module: The IRModule produced by ``build_ir()``.

    Returns:
        dict that can be passed to ``json.dumps()``.
    """
    return {
        "source_file": ir_module.source_file,
        "function_count": len(ir_module.functions),
        "functions": [_function_to_dict(f) for f in ir_module.functions],
    }


# ---------------------------------------------------------------------------
# Pretty-print  (LLVM-IR-inspired text format)
# ---------------------------------------------------------------------------

def _fmt_instr(instr: IRInstruction, indent: str = "  ") -> str:
    """Format one instruction as a human-readable line."""
    op = instr.op.value

    if instr.op == IROpcode.LABEL:
        return ""   # label is rendered as the block header

    if instr.op == IROpcode.BRANCH:
        cond, true_l, false_l = (instr.operands + ["?", "?", "?"])[:3]
        return f"{indent}branch {cond}, {true_l}, {false_l}"

    if instr.op == IROpcode.JUMP:
        target = instr.operands[0] if instr.operands else "?"
        return f"{indent}jump {target}"

    if instr.op == IROpcode.RETURN:
        val = instr.operands[0] if instr.operands else "void"
        return f"{indent}return {val}"

    if instr.op == IROpcode.PHI:
        operands_str = ", ".join(instr.operands)
        lhs = f"{instr.result} = " if instr.result else ""
        return f"{indent}{lhs}phi({operands_str})"

    if instr.op == IROpcode.NOP:
        note = instr.meta.get("note", "")
        comment = f"  ; {note}" if note else ""
        return f"{indent}nop{comment}"

    if instr.op == IROpcode.BINOP:
        operator = instr.meta.get("operator", "op")
        lhs_op, rhs_op = (instr.operands + ["?", "?"])[:2]
        lhs = f"{instr.result} = " if instr.result else ""
        return f"{indent}{lhs}{lhs_op} {operator} {rhs_op}"

    if instr.op == IROpcode.CALL:
        lhs = f"{instr.result} = " if instr.result else ""
        c = instr.call
        if c is None:
            callee = instr.meta.get("callee", "?")
            return f"{indent}{lhs}call {callee}({', '.join(instr.operands)})"
        callee = c.callee or (f"{c.receiver}.{c.method}" if c.receiver and c.method else c.raw_callee)
        args = list(c.args) + [f"{k}={v}" for k, v in c.keywords.items()] + \
            [f"*{s}" for s in c.star_args]
        return f"{indent}{lhs}call {callee}({', '.join(args)})"

    # Generic fallback: LOAD, STORE, ASSIGN, UNOP, ATTR, SUBSCR, BUILD, MAKEFUNC
    operands_str = ", ".join(instr.operands) if instr.operands else ""
    lhs = f"{instr.result} = " if instr.result else ""
    extra = f"({operands_str})" if operands_str else ""
    detail = ""
    for key in ("const", "path", "attr", "kind", "func"):
        if key in instr.meta:
            detail = f"  ; {key}={instr.meta[key]}"
            break
    return f"{indent}{lhs}{op}{extra}{detail}"


def _fmt_block(block: IRBlock) -> str:
    lines = [f"{block.label}:"]
    for instr in block.instructions:
        rendered = _fmt_instr(instr)
        if rendered:  # skip empty (LABEL instructions rendered as block header)
            lines.append(rendered)
    if block.successors:
        lines.append(f"  ; successors: {', '.join(block.successors)}")
    return "\n".join(lines)


def _fmt_function(func: IRFunction) -> str:
    async_kw = "async " if func.is_async else ""
    params_str = ", ".join(func.params)
    ret = func.return_type or "None"
    header = (
        f"{async_kw}define {ret} @{func.name}({params_str})"
        f"  ; line {func.source_lineno}, "
        f"{'method' if func.is_method else 'function'}"
    )
    blocks_text = "\n".join(_fmt_block(b) for b in func.blocks)
    return f"{header}\n{{\n{blocks_text}\n}}"


def pretty_print_ir(ir_module: IRModule) -> str:
    """
    Return a human-readable LLVM-IR-inspired text dump of the IRModule.

    Args:
        ir_module: The IRModule produced by ``build_ir()``.

    Returns:
        Multi-line string ready for stdout printing or file writing.
    """
    header = (
        f"; IR dump — {ir_module.source_file}\n"
        f"; {len(ir_module.functions)} function(s)\n"
        f"; {'=' * 60}\n"
    )
    body = "\n\n".join(_fmt_function(f) for f in ir_module.functions)
    return header + "\n" + body + "\n"
