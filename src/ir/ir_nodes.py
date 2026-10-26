"""
IR Nodes — Week 8 Intermediate Representation
==============================================
Defines the language-agnostic, 3-address-code style IR that represents
Python source after lowering from the Week 7 AST features.

Hierarchy
---------
IRModule
  └── IRFunction (one per Python function / method)
        └── IRBlock  (one per basic block — entry, loop, branch, exit, etc.)
              └── IRInstruction  (one 3-address-code instruction)

Opcodes (IROpcode)
------------------
  ASSIGN   t0 = src             Variable assignment
  LOAD     t0 = load(name)      Load a variable into a temp
  STORE    store(name, t0)      Store a temp into a variable
  BINOP    t0 = lhs op rhs      Binary arithmetic / comparison
  UNOP     t0 = op src          Unary operation
  CALL     t0 = call f(args…)   Function / method call
  RETURN   return val           Function return
  BRANCH   branch cond L1 L2   Conditional jump to L1 (true) or L2 (false)
  JUMP     jump L               Unconditional jump
  LABEL    label L              Block-header label
  PHI      t0 = phi(t1, t2)    SSA phi node (placed at join points)
  NOP      nop                  No-operation placeholder
  ATTR     t0 = base.attr       Attribute read
  SUBSCR   t0 = base[index]     Subscript read
  BUILD    t0 = build(a, b…)    Container / f-string / comprehension construction
  MAKEFUNC f = makefunc(free…)  Nested function definition capturing free vars

Variables vs temporaries
------------------------
User variables keep their source names (``query``); compiler temporaries are
``tN``.  Every instruction carries the line/column of the AST node it was
lowered from, so analyses can report original source locations.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Opcodes
# ---------------------------------------------------------------------------

class IROpcode(str, enum.Enum):
    """3-address-code operation codes."""
    ASSIGN  = "ASSIGN"
    LOAD    = "LOAD"
    STORE   = "STORE"
    BINOP   = "BINOP"
    UNOP    = "UNOP"
    CALL    = "CALL"
    RETURN  = "RETURN"
    BRANCH  = "BRANCH"
    JUMP    = "JUMP"
    LABEL   = "LABEL"
    PHI     = "PHI"
    NOP     = "NOP"
    ATTR    = "ATTR"
    SUBSCR  = "SUBSCR"
    BUILD   = "BUILD"
    MAKEFUNC = "MAKEFUNC"


# ---------------------------------------------------------------------------
# Structured call / branch metadata
# ---------------------------------------------------------------------------

@dataclass
class CallInfo:
    """
    Structured description of a call site.

    Attributes:
        callee       : Canonical dotted name after import-alias resolution
                       (``subprocess.run``), or ``""`` for a method call on a
                       local value whose type is unknown.
        raw_callee   : The callee expression as written (``sp.run``).
        method       : Method name for ``obj.method(...)`` calls.
        receiver     : Operand holding the receiver of a method call.
        args         : Positional argument operands, in order.
        keywords     : Keyword name -> operand.
        const_kwargs : Keyword name -> ``repr`` of a literal keyword value
                       (lets rules see ``shell=True`` or ``Loader=SafeLoader``).
        star_args    : Operands passed via ``*args`` / ``**kwargs``.
    """
    callee: str = ""
    raw_callee: str = ""
    method: Optional[str] = None
    receiver: Optional[str] = None
    args: List[str] = field(default_factory=list)
    keywords: Dict[str, str] = field(default_factory=dict)
    const_kwargs: Dict[str, str] = field(default_factory=dict)
    star_args: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Refinement:
    """
    A validation fact implied by a branch condition.

    ``var`` is known to satisfy ``kind`` on the edge selected by ``on_true``
    (True = the condition's true successor).  Kinds:

      allowlist   — membership test against a constant collection
      charset     — str.isdigit()/isalnum()/re.fullmatch(<safe charset>)/isinstance
      path_prefix — startswith / is_relative_to / commonpath boundary check
    """
    var: str
    kind: str
    on_true: bool = True


# ---------------------------------------------------------------------------
# Instruction
# ---------------------------------------------------------------------------

@dataclass
class IRInstruction:
    """
    A single 3-address-code instruction.

    Attributes:
        op       : Operation code (IROpcode).
        result   : Destination / result temporary variable name (or None).
        operands : Source operands (variable names, temporaries, or literals).
        lineno   : Source line number that generated this instruction (0 = unknown).
        meta     : Free-form metadata dict (operator, callee name, etc.).
        col      : Source column of the originating AST node.
        end_lineno : Last source line of the originating AST node.
        call     : CallInfo for CALL instructions.
        refinements : Validation facts for BRANCH instructions.
        guards   : Enclosing branch conditions, outermost first.
        uid      : Function-unique instruction id (stable across runs).
    """
    op: IROpcode
    result: Optional[str] = None
    operands: List[str] = field(default_factory=list)
    lineno: int = 0
    meta: Dict[str, str] = field(default_factory=dict)
    col: int = 0
    end_lineno: int = 0
    call: Optional[CallInfo] = None
    refinements: List[Refinement] = field(default_factory=list)
    guards: List[str] = field(default_factory=list)
    uid: int = 0

    def __repr__(self) -> str:
        lhs = f"{self.result} = " if self.result else ""
        rhs = f"{self.op.value}({', '.join(self.operands)})"
        return f"[L{self.lineno}] {lhs}{rhs}"


# ---------------------------------------------------------------------------
# Basic Block
# ---------------------------------------------------------------------------

@dataclass
class IRBlock:
    """
    A basic block — a maximal straight-line sequence of instructions with:
      - a single entry point (the first instruction / LABEL)
      - no interior branches

    Attributes:
        label        : Unique block identifier, e.g. ``entry``, ``block_1``.
        instructions : Ordered list of IRInstruction in this block.
        successors   : Labels of basic blocks that may follow this one.
        predecessors : Labels of basic blocks that may precede this one.
        meta         : Block facts such as ``loop_depth`` or ``kind``.
    """
    label: str
    instructions: List[IRInstruction] = field(default_factory=list)
    successors: List[str] = field(default_factory=list)
    predecessors: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)

    # ── Convenience accessors ────────────────────────────────────────

    @property
    def terminator(self) -> Optional[IRInstruction]:
        """Last instruction in the block (BRANCH / JUMP / RETURN), or None."""
        if self.instructions:
            last = self.instructions[-1]
            if last.op in (IROpcode.BRANCH, IROpcode.JUMP, IROpcode.RETURN):
                return last
        return None

    def append(self, instr: IRInstruction) -> None:
        self.instructions.append(instr)

    def __repr__(self) -> str:
        return f"IRBlock({self.label!r}, {len(self.instructions)} instrs)"


# ---------------------------------------------------------------------------
# Function
# ---------------------------------------------------------------------------

@dataclass
class IRFunction:
    """
    IR representation of a single Python function or method.

    Attributes:
        name        : Function name.
        params      : Ordered parameter names.
        return_type : Return type annotation string (or None).
        is_method   : True if defined inside a class.
        is_async    : True if declared ``async def``.
        blocks      : Ordered list of IRBlock; blocks[0] is always the entry block.
        source_lineno: Line number in the original source.
        qualname    : Dotted qualified name (``Cls.method``, ``outer.inner``).
        class_name  : Enclosing class, if any.
        decorators  : Decorator expressions as written.
        locals      : Names bound inside the function body.
        free_vars   : Names read but not bound locally (closure / global).
        unsupported : Language features lowered only approximately.
        end_lineno  : Last source line of the function.
    """
    name: str
    params: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    is_method: bool = False
    is_async: bool = False
    blocks: List[IRBlock] = field(default_factory=list)
    source_lineno: int = 0
    qualname: str = ""
    class_name: Optional[str] = None
    decorators: List[str] = field(default_factory=list)
    locals: Set[str] = field(default_factory=set)
    free_vars: Set[str] = field(default_factory=set)
    unsupported: List[str] = field(default_factory=list)
    end_lineno: int = 0
    enclosing: Optional[str] = None

    # ── Convenience ──────────────────────────────────────────────────

    @property
    def entry_block(self) -> Optional[IRBlock]:
        return self.blocks[0] if self.blocks else None

    def get_block(self, label: str) -> Optional[IRBlock]:
        for b in self.blocks:
            if b.label == label:
                return b
        return None

    def all_instructions(self):
        """Iterate over every instruction in program order."""
        for block in self.blocks:
            yield from block.instructions

    def __repr__(self) -> str:
        return f"IRFunction({self.name!r}, {len(self.blocks)} blocks)"


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

@dataclass
class IRModule:
    """
    Top-level IR container for a single Python source file.

    Attributes:
        source_file : Path / name of the original source file.
        functions   : List of IRFunction objects (module-level + methods).
        imports     : Local alias -> canonical dotted name.
        module_body : Pseudo-function holding top-level statements, if lowered.
    """
    source_file: str = ""
    functions: List[IRFunction] = field(default_factory=list)
    imports: Dict[str, str] = field(default_factory=dict)
    module_body: Optional[IRFunction] = None

    def get_function(self, name: str) -> Optional[IRFunction]:
        for f in self.functions:
            if f.name == name:
                return f
        for f in self.functions:
            if f.qualname == name:
                return f
        return None

    def __repr__(self) -> str:
        return f"IRModule({self.source_file!r}, {len(self.functions)} functions)"
