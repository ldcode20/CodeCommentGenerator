import math
from PyQt6.QtWidgets import QWidget, QToolTip
from PyQt6.QtCore import Qt, QRectF, QPointF
from PyQt6.QtGui import (
    QPainter, QPen, QBrush, QColor, QFont, QPainterPath,
)


_NODE_COLORS = {
    "Module": QColor("#6b7280"),
    "Import": QColor("#ca8a04"),
    "Class": QColor("#16a34a"),
    "Function": QColor("#2563eb"),
    "AsyncFunction": QColor("#7c3aed"),
    "Param": QColor("#0891b2"),
    "Loop": QColor("#ea580c"),
    "Conditional": QColor("#ea580c"),
    "Call": QColor("#7c3aed"),
    "Return": QColor("#dc2626"),
    "Decorator": QColor("#db2777"),
}

_EDGE_COLORS = {
    "parent": QColor("#9ca3af"),
    "call": QColor("#7c3aed"),
}

_COMPLEXITY_COLORS = {
    "simple": QColor("#16a34a"),
    "moderate": QColor("#ca8a04"),
    "complex": QColor("#ea580c"),
    "very_complex": QColor("#dc2626"),
}


class _ASTNode:
    def __init__(self, label, node_type, x=0.0, y=0.0, detail=""):
        self.label = label
        self.node_type = node_type
        self.x = x
        self.y = y
        self.detail = detail
        self.children: list["_ASTNode"] = []
        self.w = 120
        self.h = 36


class AstGraphWidget(QWidget):
    """Custom widget that renders an AST as an interactive tree graph."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._root: _ASTNode | None = None
        self._all_nodes: list[_ASTNode] = []
        self._hovered: _ASTNode | None = None
        self._offset_x = 0.0
        self._offset_y = 0.0
        self._scale = 1.0
        self._dragging = False
        self._last_mouse = None
        self._needs_fit = False
        self._user_moved = False
        self.setMinimumSize(400, 300)

    def set_data(self, module_features, ast_tree=None):
        self._root = self._build_tree(module_features)
        self._layout_tree()
        # Fit on first paint: the widget may be hidden (size unknown) right now
        self._needs_fit = True
        self._user_moved = False
        self.update()

    def fit_to_view(self):
        """Zoom and centre so the whole tree is visible (double-click to reset)."""
        if not self._all_nodes or self.width() <= 0 or self.height() <= 0:
            return
        left = min(n.x - n.w / 2 for n in self._all_nodes)
        right = max(n.x + n.w / 2 for n in self._all_nodes)
        top = min(n.y - n.h / 2 for n in self._all_nodes)
        bottom = max(n.y + n.h / 2 for n in self._all_nodes)
        margin = 20
        scale = min(1.0, (self.width() - 2 * margin) / max(1.0, right - left),
                    (self.height() - 2 * margin) / max(1.0, bottom - top))
        self._scale = max(0.2, scale)
        self._offset_x = (self.width() - (right - left) * self._scale) / 2 - left * self._scale
        self._offset_y = margin - top * self._scale
        self._needs_fit = False
        self.update()

    def _build_tree(self, mf) -> _ASTNode:
        root = _ASTNode("Module", "Module", detail=f"{mf.filepath or '<module>'}")

        if mf.imports:
            imp_node = _ASTNode(f"Imports ({len(mf.imports)})", "Import")
            for imp in mf.imports[:12]:
                child = _ASTNode(imp, "Import", detail=imp)
                imp_node.children.append(child)
            root.children.append(imp_node)

        for cls in mf.classes:
            cls_node = _ASTNode(cls.name, "Class", detail=f"line {cls.lineno}, bases: {', '.join(cls.bases) if cls.bases else 'none'}")
            for m in cls.methods[:8]:
                m_node = _ASTNode(f"{m}()", "Function", detail=f"method of {cls.name}")
                cls_node.children.append(m_node)
            root.children.append(cls_node)

        for func in mf.functions:
            detail_parts = [f"line {func.lineno}"]
            if func.is_async:
                detail_parts.append("async")
            if func.is_method and func.parent_class:
                detail_parts.append(f"method of {func.parent_class}")
            detail_parts.append(f"loops={func.loops} conds={func.conditionals}")
            if func.return_annotation:
                detail_parts.append(f"→ {func.return_annotation}")

            f_node = _ASTNode(func.name, "AsyncFunction" if func.is_async else "Function", detail=", ".join(detail_parts))

            for p in func.params:
                p_detail = p.name
                if p.annotation:
                    p_detail += f": {p.annotation}"
                if p.default is not None:
                    p_detail += f"={p.default}"
                f_node.children.append(_ASTNode(p_detail, "Param"))

            for dec in func.decorators[:3]:
                f_node.children.append(_ASTNode(f"@{dec}", "Decorator"))

            root.children.append(f_node)

        return root

    def _layout_tree(self):
        if not self._root:
            return
        self._all_nodes = []
        h_spacing = 140
        v_spacing = 56

        def _assign_depths(node: _ASTNode, depth=0):
            node.y = depth * v_spacing + 40
            self._all_nodes.append(node)
            for child in node.children:
                _assign_depths(child, depth + 1)

        _assign_depths(self._root)

        leaf_counter = [0]

        def _assign_x(node: _ASTNode):
            if not node.children:
                node.x = leaf_counter[0] * h_spacing + 80
                leaf_counter[0] += 1
                return node.x
            child_xs = [_assign_x(c) for c in node.children]
            node.x = (min(child_xs) + max(child_xs)) / 2
            return node.x

        _assign_x(self._root)

    def paintEvent(self, event):
        if not self._root:
            return
        if self._needs_fit:
            self.fit_to_view()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.translate(self._offset_x, self._offset_y)
        painter.scale(self._scale, self._scale)

        self._draw_edges(painter, self._root)
        self._draw_nodes(painter)

    def _draw_edges(self, painter, node: _ASTNode):
        for child in node.children:
            pen = QPen(_EDGE_COLORS["parent"], 1.5)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            path = QPainterPath()
            sx, sy = node.x, node.y + node.h / 2
            ex, ey = child.x, child.y - child.h / 2
            mid_y = (sy + ey) / 2
            path.moveTo(sx, sy)
            path.cubicTo(sx, mid_y, ex, mid_y, ex, ey)
            painter.drawPath(path)
            self._draw_edges(painter, child)

    def _draw_nodes(self, painter):
        for node in self._all_nodes:
            color = _NODE_COLORS.get(node.node_type, QColor("#6b7280"))
            is_hovered = node is self._hovered
            rect = QRectF(node.x - node.w / 2, node.y - node.h / 2, node.w, node.h)

            if is_hovered:
                painter.setPen(QPen(QColor("#1a1a2e"), 2.5))
            else:
                painter.setPen(QPen(color.darker(120), 1.5))

            painter.setBrush(QBrush(color))
            painter.drawRoundedRect(rect, 6, 6)

            painter.setPen(QPen(QColor("#ffffff")))
            font = QFont("Inter", 9, QFont.Weight.Bold)
            painter.setFont(font)
            text = node.label
            if len(text) > 14:
                text = text[:12] + ".."
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)

    def _node_at(self, pos: QPointF) -> _ASTNode | None:
        for node in reversed(self._all_nodes):
            rect = QRectF(node.x - node.w / 2, node.y - node.h / 2, node.w, node.h)
            if rect.contains(pos):
                return node
        return None

    def mouseMoveEvent(self, event):
        pos = QPointF(
            (event.position().x() - self._offset_x) / self._scale,
            (event.position().y() - self._offset_y) / self._scale,
        )
        if self._dragging and self._last_mouse:
            dx = event.position().x() - self._last_mouse.x()
            dy = event.position().y() - self._last_mouse.y()
            self._offset_x += dx
            self._offset_y += dy
            self._user_moved = True
            self._last_mouse = event.position()
            self.update()
            return

        hovered = self._node_at(pos)
        if hovered != self._hovered:
            self._hovered = hovered
            if hovered and hovered.detail:
                QToolTip.showText(event.globalPosition().toPoint(), hovered.detail, self)
            else:
                QToolTip.hideText()
            self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = True
            self._last_mouse = event.position()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = False
            self._last_mouse = None

    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        factor = 1.15 if delta > 0 else 1 / 1.15
        self._scale *= factor
        self._scale = max(0.2, min(5.0, self._scale))
        self._user_moved = True
        self.update()

    def mouseDoubleClickEvent(self, event):
        self._user_moved = False
        self.fit_to_view()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._root and not self._user_moved:
            self._needs_fit = True
