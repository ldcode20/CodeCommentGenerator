import math
from PyQt6.QtWidgets import QPushButton, QFrame, QLabel, QHBoxLayout, QGraphicsOpacityEffect
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QRect, QSize, pyqtProperty
from PyQt6.QtGui import QPainter, QPen, QColor, QFont, QConicalGradient
from src.gui import theme


class SpinningButton(QPushButton):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self._spinning = False
        self._angle = 0
        self._original_text = text
        self._spinner_timer = QTimer(self)
        self._spinner_timer.setInterval(40)
        self._spinner_timer.timeout.connect(self._tick)
        self._spinner_size = 18
        self._spinner_margin = 10

    def start_spinning(self, loading_text=None):
        self._spinning = True
        self._original_text = self.text()
        self.setText(loading_text or self._original_text)
        self.setEnabled(False)
        self._angle = 0
        self._spinner_timer.start()
        self.update()

    def stop_spinning(self):
        self._spinning = False
        self._spinner_timer.stop()
        self.setText(self._original_text)
        self.setEnabled(True)
        self.update()

    def is_spinning(self):
        return self._spinning

    def _tick(self):
        self._angle = (self._angle + 15) % 360
        self.update()

    def sizeHint(self):
        base = super().sizeHint()
        if self._spinning:
            base.setWidth(base.width() + self._spinner_size + self._spinner_margin)
        return base

    def paintEvent(self, event):
        super().paintEvent(event)
        if not self._spinning:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()
        spinner_r = self._spinner_size // 2
        cx = rect.x() + 14 + spinner_r
        cy = rect.y() + rect.height() // 2

        arc_rect = QRect(cx - spinner_r, cy - spinner_r, self._spinner_size, self._spinner_size)

        bg_pen = QPen(QColor(255, 255, 255, 60), 2.5)
        bg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(bg_pen)
        painter.drawArc(arc_rect, 0, 360 * 16)

        fg_pen = QPen(QColor(255, 255, 255, 220), 2.5)
        fg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(fg_pen)
        start_angle = int(self._angle * 16)
        span_angle = 270 * 16
        painter.drawArc(arc_rect, start_angle, span_angle)

        painter.end()


class ToastWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setStyleSheet("background: transparent; border: none;")

        self._inner = QFrame(self)
        self._inner.setStyleSheet(
            "border-radius: 8px; padding: 10px 18px;"
        )

        inner_layout = QHBoxLayout(self._inner)
        inner_layout.setContentsMargins(14, 10, 14, 10)
        inner_layout.setSpacing(8)

        self._icon_label = QLabel()
        self._icon_label.setStyleSheet("font-size: 16px; border: none;")
        inner_layout.addWidget(self._icon_label)

        self._msg_label = QLabel()
        self._msg_label.setStyleSheet("font-size: 13px; font-weight: 600; border: none;")
        inner_layout.addWidget(self._msg_label)

        outer_layout = QHBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(self._inner)

        self.setFixedHeight(44)

        self._opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity_effect)
        self._opacity_effect.setOpacity(0.0)

        self._fade_anim = QPropertyAnimation(self._opacity_effect, b"opacity")
        self._fade_anim.setDuration(250)

        self._auto_timer = QTimer(self)
        self._auto_timer.setSingleShot(True)
        self._auto_timer.timeout.connect(self._start_fade_out)

        self._fade_out_anim = QPropertyAnimation(self._opacity_effect, b"opacity")
        self._fade_out_anim.setDuration(350)
        self._fade_out_anim.finished.connect(self.hide)

    def show_toast(self, message, kind="success"):
        if kind == "success":
            bg = "#dcfce7"
            fg = "#166534"
            icon = "\u2713"
        elif kind == "error":
            bg = "#fef2f2"
            fg = "#991b1b"
            icon = "\u2717"
        else:
            bg = "#eff6ff"
            fg = theme.ACCENT_PRESSED
            icon = "\u2139"

        self._inner.setStyleSheet(
            f"background-color: {bg}; border-radius: 8px; border: 1px solid {fg}22;"
        )
        self._icon_label.setText(icon)
        self._icon_label.setStyleSheet(f"font-size: 16px; color: {fg}; border: none;")
        self._msg_label.setText(message)
        self._msg_label.setStyleSheet(f"font-size: 13px; font-weight: 600; color: {fg}; border: none;")

        self.adjustSize()
        self.setFixedHeight(44)

        if self.parent():
            parent_rect = self.parent().rect()
            x = parent_rect.width() - self.width() - 20
            y = 12
            self.move(x, y)

        self.show()
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        self._fade_anim.start()

        self._auto_timer.start(3500)

    def _start_fade_out(self):
        self._fade_out_anim.setStartValue(1.0)
        self._fade_out_anim.setEndValue(0.0)
        self._fade_out_anim.start()
