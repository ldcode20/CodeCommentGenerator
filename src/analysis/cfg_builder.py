"""
CFG Builder — Week 8 Analysis
==============================
Builds a Control-Flow Graph (CFG) from an IRFunction produced by the IR builder.

A CFG is a directed graph whose nodes are basic blocks and whose edges
represent possible flow of control.  This module:
  - Copies each IRBlock into a CFGNode
  - Re-establishes all successor / predecessor edges from the block's
    successor list (already computed by the IR builder)
  - Identifies the entry node and all exit nodes

Data Structures
---------------
CFGNode
  label        : block label (str)
  instructions : shallow copy of IRInstruction list
  successors   : labels of next blocks
  predecessors : labels of prior blocks

CFG
  function_name : name of the owning function
  nodes         : dict { label → CFGNode }
  entry         : label of the entry node
  exits         : list of labels of exit nodes (blocks ending in RETURN)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..ir.ir_nodes import IRFunction, IRInstruction, IROpcode


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CFGNode:
    """A node in the control-flow graph (corresponds to one IRBlock)."""
    label: str
    instructions: List[IRInstruction] = field(default_factory=list)
    successors: List[str] = field(default_factory=list)
    predecessors: List[str] = field(default_factory=list)

    # ── Analysis annotations (filled in by DFA engine) ──────────────────
    # Reaching definitions: set of definition names that reach the *entry* of
    # this block (GEN / KILL computed during DFA).
    reach_in:  "set[str]" = field(default_factory=set)
    reach_out: "set[str]" = field(default_factory=set)

    # Live variables: set of variable names live at the *entry* of this block.
    live_in:  "set[str]" = field(default_factory=set)
    live_out: "set[str]" = field(default_factory=set)

    def __repr__(self) -> str:
        return (
            f"CFGNode({self.label!r}, "
            f"succ={self.successors}, "
            f"pred={self.predecessors}, "
            f"{len(self.instructions)} instrs)"
        )


@dataclass
class CFG:
    """Control-Flow Graph for a single function."""
    function_name: str
    nodes: Dict[str, CFGNode] = field(default_factory=dict)
    entry: str = ""
    exits: List[str] = field(default_factory=list)

    # ── Convenience ──────────────────────────────────────────────────────

    def get_node(self, label: str) -> Optional[CFGNode]:
        return self.nodes.get(label)

    def successors_of(self, label: str) -> List[CFGNode]:
        node = self.nodes.get(label)
        if node is None:
            return []
        return [self.nodes[s] for s in node.successors if s in self.nodes]

    def predecessors_of(self, label: str) -> List[CFGNode]:
        node = self.nodes.get(label)
        if node is None:
            return []
        return [self.nodes[p] for p in node.predecessors if p in self.nodes]

    def topological_order(self) -> List[str]:
        """
        Return block labels in a BFS traversal order from the entry.
        (Not a strict topological sort due to back-edges in loops.)
        """
        visited: List[str] = []
        queue = [self.entry]
        seen = set()
        while queue:
            label = queue.pop(0)
            if label in seen or label not in self.nodes:
                continue
            seen.add(label)
            visited.append(label)
            queue.extend(self.nodes[label].successors)
        return visited

    def reachable(self) -> "set[str]":
        """Labels reachable from the entry node."""
        return set(self.topological_order())

    def __repr__(self) -> str:
        return (
            f"CFG({self.function_name!r}, "
            f"{len(self.nodes)} nodes, "
            f"entry={self.entry!r}, "
            f"exits={self.exits})"
        )


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_cfg(ir_function: IRFunction) -> CFG:
    """
    Construct a CFG from an IRFunction.

    Args:
        ir_function: An IRFunction produced by ``ir_builder.build_ir()``.

    Returns:
        CFG with all nodes and edges populated.
    """
    cfg = CFG(function_name=ir_function.name)

    # ── Pass 1: create CFGNode for each IRBlock ──────────────────────────
    for block in ir_function.blocks:
        node = CFGNode(
            label=block.label,
            instructions=list(block.instructions),  # shallow copy
            successors=list(block.successors),
            predecessors=list(block.predecessors),
        )
        cfg.nodes[block.label] = node

    # ── Pass 2: resolve entry and exits ─────────────────────────────────
    if ir_function.blocks:
        cfg.entry = ir_function.blocks[0].label

    for node in cfg.nodes.values():
        # A block is an exit if its last non-NOP instruction is a RETURN,
        # or if it has no successors.
        is_return = any(i.op == IROpcode.RETURN for i in node.instructions)
        if is_return or not node.successors:
            cfg.exits.append(node.label)

    # ── Pass 3: verify edge consistency (add missing back-edges) ─────────
    # The IR builder fills both successors and predecessors, but do a
    # consistency check / repair to be safe.
    for label, node in cfg.nodes.items():
        for succ_label in node.successors:
            if succ_label in cfg.nodes:
                succ_node = cfg.nodes[succ_label]
                if label not in succ_node.predecessors:
                    succ_node.predecessors.append(label)

    return cfg
