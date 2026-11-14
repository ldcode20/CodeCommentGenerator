"""
Code editor widget
==================
A ``QPlainTextEdit`` with what the plain text boxes lacked: a line-number
gutter, a current-line highlight, tinted marker lines (diff additions, the
line of a syntax error, the line a finding points at), jump-to-line, and
drag-and-drop of ``.py`` files.
"""
from typing import Dict, Iterable, Optional, Tuple

from PyQt6.QtCore import QRect, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QFontDatabase, QPainter, QTextCursor, QTextFormat
from PyQt6.QtWidgets import QPlainTextEdit, QTextEdit, QWidget

from src.gui import theme


def code_font(point_size: int = 10) -> QFont:
    """First installed family from the theme's monospace stack."""
    installed = set(QFontDatabase.families())
    family = next((f for f in theme.CODE_FONT_FAMILIES if f in installed), None)
    font = QFont(family) if family else QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSize(point_size)
    return font


def _tint(spec: Tuple[str, int]) -> QColor:
    color = QColor(spec[0])
    color.setAlpha(spec[1])
    return color


class _LineNumberArea(QWidget):
    def __init__(self, editor: "CodeEditor"):
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self) -> QSize:
        return QSize(self._editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self._editor.paint_line_numbers(event)


class CodeEditor(QPlainTextEdit):
    """Monospace editor with a gutter and per-line tints."""

    #: Emitted with a local path when a file is dropped on the editor.
    fileDropped = pyqtSignal(str)

    def __init__(self, parent=None, read_only: bool = False):
        super().__init__(parent)
        self.setFont(code_font())
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setTabStopDistance(4 * self.fontMetrics().horizontalAdvance(" "))
        self.setReadOnly(read_only)

        self._gutter = _LineNumberArea(self)
        self._tints: Dict[int, QColor] = {}       # 1-based line -> colour
        self._marker: Optional[Tuple[int, QColor]] = None

        self.blockCountChanged.connect(self._update_gutter_width)
        self.updateRequest.connect(self._on_update_request)
        self.cursorPositionChanged.connect(self._refresh_selections)
        self._update_gutter_width()
        self._refresh_selections()

    # ── gutter ────────────────────────────────────────────────────────────
    def line_number_area_width(self) -> int:
        digits = max(3, len(str(max(1, self.blockCount()))))
        return 14 + self.fontMetrics().horizontalAdvance("9") * digits

    def _update_gutter_width(self, _=0):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def _on_update_request(self, rect: QRect, dy: int):
        if dy:
            self._gutter.scroll(0, dy)
        else:
            self._gutter.update(0, rect.y(), self._gutter.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self._update_gutter_width()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self._gutter.setGeometry(QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height()))

    def paint_line_numbers(self, event):
        painter = QPainter(self._gutter)
        painter.fillRect(event.rect(), QColor(theme.BG_APP))
        painter.setPen(QColor(theme.BORDER))
        painter.drawLine(self._gutter.width() - 1, event.rect().top(),
                         self._gutter.width() - 1, event.rect().bottom())
        painter.setFont(self.font())

        block = self.firstVisibleBlock()
        number = block.blockNumber() + 1
        top = round(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + round(self.blockBoundingRect(block).height())
        current = self.textCursor().blockNumber() + 1
        height = self.fontMetrics().height()

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                painter.setPen(QColor(theme.TEXT if number == current else theme.TEXT_FAINT))
                painter.drawText(0, top, self._gutter.width() - 8, height,
                                 Qt.AlignmentFlag.AlignRight, str(number))
            block = block.next()
            top = bottom
            bottom = top + round(self.blockBoundingRect(block).height())
            number += 1
        painter.end()

    # ── line tints ────────────────────────────────────────────────────────
    def _line_selection(self, line: int, color: QColor) -> Optional[QTextEdit.ExtraSelection]:
        block = self.document().findBlockByNumber(line - 1)
        if not block.isValid():
            return None
        sel = QTextEdit.ExtraSelection()
        sel.format.setBackground(color)
        sel.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
        sel.cursor = QTextCursor(block)
        sel.cursor.clearSelection()
        return sel

    def _refresh_selections(self):
        selections = []
        if not self.isReadOnly():
            current = QColor(theme.ACCENT)
            current.setAlpha(14)
            sel = self._line_selection(self.textCursor().blockNumber() + 1, current)
            if sel:
                selections.append(sel)
        for line, color in self._tints.items():
            sel = self._line_selection(line, color)
            if sel:
                selections.append(sel)
        if self._marker:
            sel = self._line_selection(*self._marker)
            if sel:
                selections.append(sel)
        self.setExtraSelections(selections)
        self._gutter.update()

    def set_line_tints(self, lines: Iterable[int], tint: Tuple[str, int] = theme.DIFF_ADDED_TINT):
        """Tint the given 1-based lines (replaces any previous tints)."""
        color = _tint(tint)
        self._tints = {int(n): color for n in lines}
        self._refresh_selections()

    def clear_line_tints(self):
        self._tints = {}
        self._refresh_selections()

    def clear_marker(self):
        self._marker = None
        self._refresh_selections()

    # ── navigation ────────────────────────────────────────────────────────
    def goto_line(self, line: int, tint: Optional[Tuple[str, int]] = theme.JUMP_LINE_TINT,
                  column: int = 0) -> bool:
        """
        Move the cursor to a 1-based line, centre it and (optionally) mark it.

        Returns False when the document has no such line.
        """
        block = self.document().findBlockByNumber(int(line) - 1)
        if not block.isValid():
            return False
        cursor = QTextCursor(block)
        if column > 0:
            cursor.movePosition(QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.MoveAnchor,
                                min(column, max(0, block.length() - 1)))
        self.setTextCursor(cursor)
        self.centerCursor()
        self._marker = (int(line), _tint(tint)) if tint else None
        self._refresh_selections()
        return True

    def setPlainText(self, text: str):  # noqa: N802 (Qt naming)
        # New content invalidates line-based decorations.
        self._tints = {}
        self._marker = None
        super().setPlainText(text)
        self._refresh_selections()

    # ── drag and drop ─────────────────────────────────────────────────────
    @staticmethod
    def _dropped_path(mime) -> Optional[str]:
        if not mime.hasUrls():
            return None
        for url in mime.urls():
            if url.isLocalFile():
                return url.toLocalFile()
        return None

    def dragEnterEvent(self, event):
        if not self.isReadOnly() and self._dropped_path(event.mimeData()):
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if not self.isReadOnly() and self._dropped_path(event.mimeData()):
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        path = None if self.isReadOnly() else self._dropped_path(event.mimeData())
        if path:
            event.acceptProposedAction()
            self.fileDropped.emit(path)
        else:
            super().dropEvent(event)
