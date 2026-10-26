"""
IR sub-package — Week 8
========================
Defines and constructs a language-agnostic Intermediate Representation
from the Week 7 AST features.
"""
from .ir_nodes import (
    IROpcode, IRInstruction, IRBlock, IRFunction, IRModule, CallInfo, Refinement,
)
from .ir_builder import build_ir
from .lowering import lower_module
from .ir_serializer import serialize_ir, pretty_print_ir

__all__ = [
    "IROpcode", "IRInstruction", "IRBlock", "IRFunction", "IRModule",
    "CallInfo", "Refinement",
    "build_ir", "lower_module", "serialize_ir", "pretty_print_ir",
]
