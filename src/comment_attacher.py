"""
Comment Attacher — Week 7 Core Engine
=======================================
Inserts generated CommentItem objects back into the original source code.

Strategy:
  - For "docstring" kind  → insert the docstring immediately before the first
    statement of the function/class body, at that statement's indentation.
    (Inserting right after the ``def`` line broke multi-line signatures.)
    Bodies that start on the ``def`` line itself (``def f(): return 1``) are
    left unchanged and reported in the diff log.
  - For "inline" / "block" kind → insert as a comment line ABOVE the node

All original lines are kept verbatim and in order; ``line_map`` maps every
annotated line number back to its original line so findings computed on the
original source can be shown against the annotated file (and vice versa).
"""
import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .comment_generator import CommentItem


# ---------------------------------------------------------------------------
# Output dataclass
# ---------------------------------------------------------------------------

@dataclass
class AttachResult:
    annotated_source: str
    diff_log: List[str] = field(default_factory=list)   # human-readable diff lines
    comments_attached: int = 0
    # annotated line (1-based) -> original line (1-based); inserted lines are absent
    line_map: Dict[int, int] = field(default_factory=dict)
    skipped: int = 0

    def to_original_line(self, annotated_line: int) -> Optional[int]:
        """Original line for an annotated line, or None for an inserted comment line."""
        return self.line_map.get(annotated_line)

    def to_annotated_line(self, original_line: int) -> Optional[int]:
        for a, o in self.line_map.items():
            if o == original_line:
                return a
        return None


def _body_starts(source_code: str) -> Dict[int, Tuple[int, int]]:
    """def/class line -> (first body statement line, its column)."""
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return {}
    out: Dict[int, Tuple[int, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            out[node.lineno] = (first.lineno, first.col_offset)
    return out


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _indent(col_offset: int) -> str:
    """Return a string of spaces matching the node's indentation."""
    return " " * col_offset


def _indent_block(text: str, col_offset: int) -> str:
    """Indent every line of a multi-line text block."""
    pad = _indent(col_offset + 4)  # +4 for inside the def body
    return "\n".join(pad + line for line in text.splitlines())


def _format_docstring_lines(raw_docstring: str, col_offset: int,
                            body_col: Optional[int] = None) -> List[str]:
    """
    Convert a raw docstring (with triple-quotes) into indented source lines.
    The docstring goes inside the body, at the body's own indentation when
    known (falls back to col_offset + 4, one level deeper than the def).
    """
    inner_indent = _indent(body_col if body_col is not None else col_offset + 4)
    lines = raw_docstring.splitlines()
    result = []
    for line in lines:
        result.append(inner_indent + line)
    return result


def _format_inline_lines(raw_comment: str, col_offset: int) -> List[str]:
    """
    Split a raw inline/block comment into indented source lines,
    placed at the same indent level as the def/class statement.
    """
    pad = _indent(col_offset)
    return [pad + line for line in raw_comment.splitlines()]


# ---------------------------------------------------------------------------
# Main attacher
# ---------------------------------------------------------------------------

def attach_comments(source_code: str, comments: List[CommentItem]) -> AttachResult:
    """
    Insert CommentItems into source_code and return the annotated result.

    Args:
        source_code: Original Python source string.
        comments:    List of CommentItem (sorted by lineno, output of generator).

    Returns:
        AttachResult with the annotated source and a diff log.
    """
    source_lines = source_code.splitlines()
    # We'll build an output list of (original_lineno, text) to allow
    # easy insertion without off-by-one errors.
    # Use a dict: original_0indexed_line -> list of lines to insert BEFORE it.
    insertions: dict = {}   # {0-indexed line : [strings to insert before]}

    diff_log: List[str] = []
    attached = 0
    skipped = 0
    body_starts = _body_starts(source_code)

    for item in comments:
        # lineno is 1-indexed (from AST), convert to 0-indexed
        line_idx = item.lineno - 1

        if item.kind == "docstring":
            start = body_starts.get(item.lineno)
            if start is not None and start[0] == item.lineno:
                skipped += 1
                diff_log.append(
                    f"  - [docstring] {item.node_type} '{item.target_name}' skipped: body is on "
                    f"the def line ({item.lineno}); inserting would change the code")
                continue
            # Insert before the first body statement (handles multi-line signatures).
            insert_at = (start[0] - 1) if start is not None else line_idx + 1
            new_lines = _format_docstring_lines(item.text, item.col_offset,
                                                start[1] if start is not None else None)
        else:
            # Insert BEFORE the def/class line
            insert_at = line_idx
            new_lines = _format_inline_lines(item.text, item.col_offset)

        insertions.setdefault(insert_at, []).extend(new_lines)
        diff_log.append(
            f"  + [{item.kind}] {item.node_type} '{item.target_name}' "
            f"(before original line {insert_at + 1}):"
        )
        for nl in new_lines:
            diff_log.append(f"      {nl}")
        attached += 1

    # Rebuild source with insertions
    output_lines: List[str] = []
    line_map: Dict[int, int] = {}
    for i, original_line in enumerate(source_lines):
        if i in insertions:
            output_lines.extend(insertions[i])
        output_lines.append(original_line)
        line_map[len(output_lines)] = i + 1

    # Handle insertions beyond the last line (edge case)
    if len(source_lines) in insertions:
        output_lines.extend(insertions[len(source_lines)])

    return AttachResult(
        annotated_source="\n".join(output_lines),
        diff_log=diff_log,
        comments_attached=attached,
        line_map=line_map,
        skipped=skipped,
    )
