import math
import random
from PyQt6.QtWidgets import QWidget, QToolTip
from PyQt6.QtCore import Qt, QRectF, QPointF, QTimer
from src.gui import theme
from PyQt6.QtGui import (
    QPainter, QPen, QBrush, QColor, QFont, QPainterPath,
    QLinearGradient, QPalette,
)

_COMPLEXITY_COLORS = {
    "simple": QColor(theme.SUCCESS),
    "moderate": QColor(theme.WARNING),
    "complex": QColor(theme.ORANGE),
    "very_complex": QColor(theme.DANGER),
}

_COMPLEXITY_LABELS = {
    "simple": "Simple (CC ≤ 2)",
    "moderate": "Moderate (CC 3-5)",
    "complex": "Complex (CC 6-10)",
    "very_complex": "Very Complex (CC > 10)",
}

_SEC_BORDER_COLOR = QColor(theme.DANGER)
_EDGE_BASE_COLOR = QColor(theme.PURPLE)
_DIM_FACTOR = 180


class _CallGraphNode:
    def __init__(self, label, x=0.0, y=0.0, complexity="simple",
                 security_issues=None, calls_made=None,
                 cyclomatic=1, variables=None):
        self.label = label
        self.x = x
        self.y = y
        self.complexity = complexity
        self.security_issues = security_issues or []
        self.calls_made = calls_made or []
        self.cyclomatic = cyclomatic
        self.variables = variables or []
        self.outgoing: list["_CallGraphNode"] = []
        self.incoming: list["_CallGraphNode"] = []
        self.vx = 0.0
        self.vy = 0.0
        self.w = 0
        self.h = 32
        self._compute_size()

    def _compute_size(self):
        char_w = 7
        text_w = max(len(self.label) * char_w + 24, 80)
        self.w = min(text_w, 180)


class ContextGraphWidget(QWidget):
    """Custom widget rendering the call graph as a directed graph."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._nodes: list[_CallGraphNode] = []
        self._node_map: dict[str, _CallGraphNode] = {}
        self._edges: list[tuple[_CallGraphNode, _CallGraphNode]] = []
        self._hovered: _CallGraphNode | None = None
        self._selected: _CallGraphNode | None = None
        self._offset_x = 0.0
        self._offset_y = 0.0
        self._scale = 1.0
        self._dragging = False
        self._last_mouse = None
        self._layout_done = False
        self._dash_offset = 0.0
        self._anim_timer = QTimer(self)
        self._anim_timer.timeout.connect(self._tick_anim)
        self._anim_timer.setInterval(80)
        self.setMinimumSize(400, 300)
        self.setMouseTracking(True)

    def set_data(self, context_graph):
        self._nodes.clear()
        self._node_map.clear()
        self._edges.clear()
        self._selected = None
        self._hovered = None
        self._layout_done = False

        for fc in context_graph.function_contexts:
            node = _CallGraphNode(
                label=fc.name,
                complexity=fc.complexity_label,
                security_issues=getattr(fc, 'security_issues', []),
                calls_made=fc.calls_internal + fc.calls_external,
                cyclomatic=fc.cyclomatic_complexity,
                variables=fc.variables if hasattr(fc, 'variables') else [],
            )
            self._nodes.append(node)
            self._node_map[fc.name] = node

        module_fn_names = context_graph.module_function_names
        for fc in context_graph.function_contexts:
            src = self._node_map.get(fc.name)
            if not src:
                continue
            for call_name in fc.calls_internal:
                dst = self._node_map.get(call_name)
                if dst and dst is not src:
                    if (src, dst) not in self._edges:
                        src.outgoing.append(dst)
                        dst.incoming.append(src)
                        self._edges.append((src, dst))

        self._force_layout()
        self._anim_timer.start()
        self.update()

    def _tick_anim(self):
        if self._selected:
            self._dash_offset -= 2.0
            self.update()

    def _force_layout(self):
        if not self._nodes:
            return
        w = max(self.width(), 800)
        h = max(self.height(), 600)

        for n in self._nodes:
            n.x = random.uniform(100, w - 100)
            n.y = random.uniform(80, h - 80)

        for iteration in range(300):
            temp = 1.0 - iteration / 300.0

            for n in self._nodes:
                n.vx = 0.0
                n.vy = 0.0

            for i, a in enumerate(self._nodes):
                for j in range(i + 1, len(self._nodes)):
                    b = self._nodes[j]
                    dx = b.x - a.x
                    dy = b.y - a.y
                    dist = math.sqrt(dx * dx + dy * dy) + 0.1
                    force = 10000.0 / (dist * dist)
                    force = min(force, 15.0)
                    fx = force * dx / dist
                    fy = force * dy / dist
                    a.vx -= fx
                    a.vy -= fy
                    b.vx += fx
                    b.vy += fy

            for src, dst in self._edges:
                dx = dst.x - src.x
                dy = dst.y - src.y
                dist = math.sqrt(dx * dx + dy * dy) + 0.1
                ideal = 200
                force = (dist - ideal) * 0.06
                fx = force * dx / dist
                fy = force * dy / dist
                src.vx += fx
                src.vy += fy
                dst.vx -= fx
                dst.vy -= fy

            for n in self._nodes:
                n.vx -= (n.x - w / 2) * 0.005
                n.vy -= (n.y - h / 2) * 0.005
                damping = 0.85
                n.vx *= damping
                n.vy *= damping
                if temp < 0.3:
                    n.vx *= temp / 0.3
                    n.vy *= temp / 0.3
                n.x += n.vx
                n.y += n.vy
                margin = 80
                n.x = max(margin, min(w - margin, n.x))
                n.y = max(margin, min(h - margin, n.y))

        cx = sum(n.x for n in self._nodes) / max(len(self._nodes), 1)
        cy = sum(n.y for n in self._nodes) / max(len(self._nodes), 1)
        for n in self._nodes:
            n.x -= cx - w / 2
            n.y -= cy - h / 2

        self._layout_done = True

    def _is_neighbor(self, node: _CallGraphNode) -> bool:
        if not self._selected:
            return True
        if node is self._selected:
            return True
        if node in self._selected.outgoing:
            return True
        if node in self._selected.incoming:
            return True
        return False

    def _is_selected_edge(self, src, dst) -> bool:
        if not self._selected:
            return True
        if src is self._selected or dst is self._selected:
            return True
        return False

    def paintEvent(self, event):
        if not self._nodes:
            painter = QPainter(self)
            painter.end()
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        self._draw_grid(painter)

        painter.translate(self._offset_x, self._offset_y)
        painter.scale(self._scale, self._scale)

        for src, dst in self._edges:
            self._draw_edge(painter, src, dst)

        for node in self._nodes:
            self._draw_node(painter, node)

        painter.resetTransform()
        self._draw_legend(painter)
        self._draw_zoom_label(painter)

        painter.end()

    def _draw_grid(self, painter: QPainter):
        spacing = 24
        color = QColor("#e0e0e0")
        painter.setPen(QPen(color, 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        w = self.width()
        h = self.height()
        for x in range(0, w, spacing):
            for y in range(0, h, spacing):
                painter.drawPoint(x, y)

    def _draw_edge(self, painter, src: _CallGraphNode, dst: _CallGraphNode):
        is_sel = self._is_selected_edge(src, dst)
        dimmed = self._selected and not is_sel

        src_rect = QRectF(src.x - src.w / 2, src.y - src.h / 2, src.w, src.h)
        dst_rect = QRectF(dst.x - dst.w / 2, dst.y - dst.h / 2, dst.w, dst.h)

        sx = src.x
        sy = src.y
        ex = dst.x
        ey = dst.y
        dx = ex - sx
        dy = ey - sy
        dist = math.sqrt(dx * dx + dy * dy) + 0.1
        nx_dir = dx / dist
        ny_dir = dy / dist

        start_x = sx + nx_dir * (src.w / 2)
        start_y = sy + ny_dir * (src.h / 2)
        end_x = ex - nx_dir * (dst.w / 2)
        end_y = ey - ny_dir * (dst.h / 2)

        if dimmed:
            pen = QPen(QColor(_EDGE_BASE_COLOR.red(), _EDGE_BASE_COLOR.green(),
                              _EDGE_BASE_COLOR.blue(), 60), 1.0, Qt.PenStyle.SolidLine)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            path = QPainterPath()
            path.moveTo(start_x, start_y)
            path.lineTo(end_x, end_y)
            painter.drawPath(path)
            return

        grad = QLinearGradient(start_x, start_y, end_x, end_y)
        src_color = _COMPLEXITY_COLORS.get(src.complexity, QColor(theme.GRAY))
        dst_color = _COMPLEXITY_COLORS.get(dst.complexity, QColor(theme.GRAY))
        grad.setColorAt(0.0, src_color)
        grad.setColorAt(1.0, dst_color)

        width = 2.5 if is_sel and (src is self._selected or dst is self._selected) else 1.8
        pen_style = Qt.PenStyle.SolidLine
        pen = QPen(QBrush(grad), width, pen_style)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        if is_sel and (src is self._selected or dst is self._selected):
            pen.setDashOffset(self._dash_offset)
            pen.setStyle(Qt.PenStyle.DashLine)
            pen.setDashPattern([6, 3])

        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        path = QPainterPath()
        path.moveTo(start_x, start_y)

        mid_x = (start_x + end_x) / 2 + ny_dir * 20
        mid_y = (start_y + end_y) / 2 - nx_dir * 20
        path.quadTo(mid_x, mid_y, end_x, end_y)
        painter.drawPath(path)

        angle = math.atan2(ey - sy, ex - sx)
        tangent_angle = math.atan2(end_y - mid_y, end_x - mid_x)
        arrow_len = 10
        p1x = end_x - arrow_len * math.cos(tangent_angle - 0.35)
        p1y = end_y - arrow_len * math.sin(tangent_angle - 0.35)
        p2x = end_x - arrow_len * math.cos(tangent_angle + 0.35)
        p2y = end_y - arrow_len * math.sin(tangent_angle + 0.35)
        arrow = QPainterPath()
        arrow.moveTo(end_x, end_y)
        arrow.lineTo(p1x, p1y)
        arrow.lineTo(p2x, p2y)
        arrow.closeSubpath()
        arrow_color = QColor(dst_color)
        arrow_color.setAlpha(220)
        painter.setBrush(QBrush(arrow_color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPath(arrow)

    def _draw_node(self, painter, node: _CallGraphNode):
        is_neighbor = self._is_neighbor(node)
        is_hovered = node is self._hovered
        is_selected = node is self._selected
        dimmed = self._selected and not is_neighbor

        color = _COMPLEXITY_COLORS.get(node.complexity, QColor(theme.GRAY))
        if dimmed:
            color = QColor(color.red(), color.green(), color.blue(), 60)

        rect = QRectF(node.x - node.w / 2, node.y - node.h / 2, node.w, node.h)

        shadow_rect = QRectF(rect.x() + 2, rect.y() + 2, rect.width(), rect.height())
        painter.setPen(Qt.PenStyle.NoPen)
        shadow_color = QColor(0, 0, 0, 40)
        painter.setBrush(QBrush(shadow_color))
        painter.drawRoundedRect(shadow_rect, 8, 8)

        if node.security_issues and not dimmed:
            border_pen = QPen(_SEC_BORDER_COLOR, 2.5)
        elif is_selected:
            border_pen = QPen(QColor(theme.ACCENT_PRESSED), 2.5)
        elif is_hovered:
            border_pen = QPen(QColor("#1e1e2e"), 2.0)
        else:
            border_pen = QPen(color.darker(120), 1.2)

        painter.setPen(border_pen)

        if is_selected:
            bg = QColor(color.lighter(115))
        elif is_hovered:
            bg = QColor(color.lighter(105))
        else:
            bg = color
        if dimmed:
            bg = QColor(bg.red(), bg.green(), bg.blue(), 60)

        painter.setBrush(QBrush(bg))
        painter.drawRoundedRect(rect, 8, 8)

        text_color = QColor(theme.SURFACE) if not dimmed else QColor(255, 255, 255, 80)
        painter.setPen(QPen(text_color))
        font = QFont("Inter", 8, QFont.Weight.Bold)
        painter.setFont(font)
        text = node.label
        fm = painter.fontMetrics()
        elided = fm.elidedText(text, Qt.TextElideMode.ElideRight, int(node.w - 10))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, elided)

        if node.security_issues and not dimmed:
            badge_r = 7
            badge_x = node.x + node.w / 2 - badge_r - 2
            badge_y = node.y - node.h / 2 - badge_r + 2
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(_SEC_BORDER_COLOR))
            painter.drawEllipse(QPointF(badge_x, badge_y), badge_r, badge_r)
            painter.setPen(QPen(QColor(theme.SURFACE)))
            painter.setFont(QFont("Inter", 6, QFont.Weight.Bold))
            painter.drawText(QRectF(badge_x - badge_r, badge_y - badge_r,
                                     badge_r * 2, badge_r * 2),
                             Qt.AlignmentFlag.AlignCenter, "!")

        if is_selected:
            sel_rect = QRectF(rect.x() - 3, rect.y() - 3, rect.width() + 6, rect.height() + 6)
            painter.setPen(QPen(QColor(theme.ACCENT_PRESSED), 1.5, Qt.PenStyle.DashLine))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(sel_rect, 10, 10)

    def _draw_legend(self, painter: QPainter):
        legend_w = 180
        legend_h = 110
        margin = 12
        lx = self.width() - legend_w - margin
        ly = self.height() - legend_h - margin

        painter.setPen(QPen(QColor(theme.TEXT_FAINT), 1))
        painter.setBrush(QBrush(QColor("#f8fafc")))
        painter.drawRoundedRect(QRectF(lx, ly, legend_w, legend_h), 6, 6)

        painter.setPen(QPen(QColor("#1e293b")))
        painter.setFont(QFont("Inter", 8, QFont.Weight.Bold))
        painter.drawText(QRectF(lx + 6, ly + 4, legend_w - 12, 16),
                         Qt.AlignmentFlag.AlignLeft, "Complexity")
        row_y = ly + 22
        for key in ("simple", "moderate", "complex", "very_complex"):
            color = _COMPLEXITY_COLORS[key]
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(color))
            painter.drawRoundedRect(QRectF(lx + 8, row_y, 12, 12), 2, 2)
            painter.setPen(QPen(QColor("#334155")))
            painter.setFont(QFont("Inter", 7))
            painter.drawText(QRectF(lx + 26, row_y - 1, legend_w - 34, 14),
                             Qt.AlignmentFlag.AlignLeft, _COMPLEXITY_LABELS[key])
            row_y += 16

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor("#f8fafc")))
        painter.drawRect(QRectF(lx + 2, row_y + 2, legend_w - 4, 16))
        painter.setPen(QPen(_SEC_BORDER_COLOR, 2.0))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(QRectF(lx + 8, row_y + 4, 12, 12), 2, 2)
        painter.setPen(QPen(QColor("#334155")))
        painter.setFont(QFont("Inter", 7))
        painter.drawText(QRectF(lx + 26, row_y + 3, legend_w - 34, 14),
                         Qt.AlignmentFlag.AlignLeft, "Security issue")

    def _draw_zoom_label(self, painter: QPainter):
        pct = int(self._scale * 100)
        text = f"{pct}%"
        painter.setPen(QPen(QColor("#64748b")))
        painter.setFont(QFont("Inter", 9))
        painter.drawText(self.width() - 50, 20, text)

    def _node_at(self, pos: QPointF) -> _CallGraphNode | None:
        for node in reversed(self._nodes):
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
            self._last_mouse = event.position()
            self.update()
            return

        hovered = self._node_at(pos)
        if hovered != self._hovered:
            self._hovered = hovered
            if hovered:
                details = [
                    f"<b>{hovered.label}</b>",
                    f"Complexity: {hovered.complexity} (CC={hovered.cyclomatic})",
                    f"Variables: {len(hovered.variables)}",
                ]
                if hovered.calls_made:
                    details.append(f"Calls: {', '.join(hovered.calls_made[:6])}")
                if hovered.outgoing:
                    details.append(f"→ Calls: {', '.join(n.label for n in hovered.outgoing[:4])}")
                if hovered.incoming:
                    details.append(f"← Called by: {', '.join(n.label for n in hovered.incoming[:4])}")
                if hovered.security_issues:
                    details.append(f"<font color=theme.DANGER>Security: {len(hovered.security_issues)} issue(s)</font>")
                    for si in hovered.security_issues[:3]:
                        details.append(f"&nbsp;&nbsp;• {si}")
                QToolTip.showText(event.globalPosition().toPoint(),
                                   "<br>".join(details), self)
            else:
                QToolTip.hideText()
            self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            pos = QPointF(
                (event.position().x() - self._offset_x) / self._scale,
                (event.position().y() - self._offset_y) / self._scale,
            )
            clicked = self._node_at(pos)
            if clicked:
                self._selected = clicked if self._selected is not clicked else None
                self.update()
                return
            self._dragging = True
            self._last_mouse = event.position()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = False
            self._last_mouse = None

    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        old_scale = self._scale
        factor = 1.12 if delta > 0 else 1 / 1.12
        self._scale *= factor
        self._scale = max(0.2, min(5.0, self._scale))

        mouse_x = event.position().x()
        mouse_y = event.position().y()
        self._offset_x = mouse_x - (mouse_x - self._offset_x) * self._scale / old_scale
        self._offset_y = mouse_y - (mouse_y - self._offset_y) * self._scale / old_scale
        self.update()

    def resizeEvent(self, event):
        if self._nodes and not self._layout_done:
            self._force_layout()
            self.update()
