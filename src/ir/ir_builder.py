"""
IR Builder — Week 8
====================
Converts the Week 7 ModuleFeatures + ContextGraph into an IRModule.

Lowering strategy
-----------------
Each function is lowered statement-by-statement from its real AST by
``ir.lowering`` (see that module for the control-flow constructs modelled).
Every instruction keeps the source line/column of the node it came from.

The original Week 8 builder synthesised ``loop_N`` / ``branch_N`` blocks from
loop and conditional *counts* with placeholder operands (``__cond_lhs__``),
so CFG and data-flow results did not describe the program.  It also linked
blocks before they were appended, leaving every branch-condition block
without predecessors.  ``build_ir`` keeps the same public signature and the
same block-label vocabulary (``entry``, ``exit``, ``loop_N_*``,
``branch_N_*``) so the CFG/DFA/pattern passes and the GUI continue to work.

``build_ir`` returns one IRFunction per FunctionFeature (module functions and
methods, in extraction order).  Security analysis uses
``lowering.lower_module`` directly, which additionally lowers nested
functions and the module body.
"""
from __future__ import annotations

import ast
import os
from typing import Dict, Optional, Tuple

from ..ast_extractor import ModuleFeatures
from ..context_analyzer import ContextGraph

from .ir_nodes import IRModule, IRFunction
from .lowering import lower_module


def _module_tree(module_features: ModuleFeatures) -> Tuple[ast.Module, str]:
    """Recover the AST and source that ``extract_features`` was run on."""
    tree = getattr(module_features, "_ast_tree", None)
    source = getattr(module_features, "_source", "") or ""
    if tree is None:
        path = module_features.filepath
        if not path or not os.path.isfile(path):
            raise ValueError(
                "build_ir needs the parsed AST: call extract_features(tree, source) "
                "first, or pass ast_tree= explicitly."
            )
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        tree = ast.parse(source)
    return tree, source


def build_ir(
    module_features: ModuleFeatures,
    context_graph: Optional[ContextGraph] = None,
    ast_tree: Optional[ast.Module] = None,
    source_code: Optional[str] = None,
) -> IRModule:
    """
    Lower Week 7 analysis results into an IRModule.

    Args:
        module_features : Output of ``ast_extractor.extract_features()``.
        context_graph   : Output of ``context_analyzer.analyze_context()``.
                          Accepted for API compatibility; lowering works
                          from the AST itself.
        ast_tree        : Parsed module (defaults to the tree recorded by
                          ``extract_features``).
        source_code     : Original source (used for statement snippets).

    Returns:
        IRModule containing one IRFunction per Python function in the source.
    """
    if ast_tree is None:
        ast_tree, recorded_source = _module_tree(module_features)
        source_code = source_code if source_code is not None else recorded_source
    lowered = lower_module(ast_tree, source_code or "", module_features.filepath)

    by_key: Dict[Tuple[str, int], IRFunction] = {
        (f.name, f.source_lineno): f for f in lowered.functions
    }
    ir_module = IRModule(source_file=module_features.filepath, imports=lowered.imports,
                         module_body=lowered.module_body)
    for ff in module_features.functions:
        fn = by_key.get((ff.name, ff.lineno))
        if fn is not None:
            ir_module.functions.append(fn)
    return ir_module
