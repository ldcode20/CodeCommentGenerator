# -*- coding: utf-8 -*-
"""
PyQt6 theme — one palette, one stylesheet.

Every colour the GUI uses is a named constant here; widgets import the names
instead of repeating hex strings, so restyling (or adding a dark theme) means
editing this file only.
"""
from string import Template

# ── Palette ───────────────────────────────────────────────────────────────
BG_APP              = "#f8f9fa"   # window background, pane headers
SURFACE             = "#ffffff"   # cards, editors, tables
TEXT                = "#1a1a2e"   # primary text
TEXT_SECONDARY      = "#495057"   # labels, secondary buttons
TEXT_MUTED          = "#6c757d"   # status text, captions
TEXT_FAINT          = "#9ca3af"   # placeholders, comments, line numbers
BORDER              = "#e0e4e8"   # dividers, pane borders
BORDER_STRONG       = "#d0d5dd"   # input and button borders
BORDER_HOVER        = "#b0b7c3"   # hovered borders
HOVER_BG            = "#f1f3f5"   # hover background
ACCENT              = "#2563eb"   # primary actions, selection
ACCENT_HOVER        = "#1d4ed8"
ACCENT_PRESSED      = "#1e40af"
ACCENT_DISABLED     = "#93c5fd"
ACCENT_BG           = "#e8f0fe"   # selected rows, active sidebar item
SCROLL_HANDLE       = "#c4c9d1"
SCROLL_HANDLE_HOVER = "#a0a7b1"
SUCCESS             = "#16a34a"   # safe, completed, strings
WARNING             = "#ca8a04"   # medium severity
ORANGE              = "#ea580c"   # high severity, numbers
DANGER              = "#dc2626"   # critical severity, errors
PURPLE              = "#7c3aed"   # keywords
TEAL                = "#0d9488"   # builtins
GRAY                = "#6b7280"   # unknown severity

#: Monospace stack for code views.
CODE_FONT_FAMILIES = ["JetBrains Mono", "Cascadia Code", "Consolas", "Courier New"]

#: Severity → colour, shared by tables and charts.
SEVERITY_COLORS = {"critical": DANGER, "high": ORANGE, "medium": WARNING, "low": ACCENT}

#: Tints for diff / marker lines in the code editor (colour, alpha 0-255).
DIFF_ADDED_TINT = (SUCCESS, 34)
ERROR_LINE_TINT = (DANGER, 40)
JUMP_LINE_TINT = (WARNING, 60)


def rgba(hex_color: str, alpha: float) -> str:
    """``rgba(r,g,b,a)`` CSS string for a ``#rrggbb`` colour."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def badge_style(color: str, font_size: int = 13, filled: bool = True) -> str:
    """Stylesheet for a rounded status badge (safety score, engine state…)."""
    bg = f"background: {rgba(color, 0.08)};" if filled else ""
    return (f"color: {color}; font-weight: bold; font-size: {font_size}px; "
            f"padding: 4px 10px; border-radius: 6px; {bg}")


def score_color(safe_pct: float) -> str:
    """Green / amber / red for a 0-100 safety percentage."""
    if safe_pct >= 80:
        return SUCCESS
    return WARNING if safe_pct >= 50 else DANGER


_STYLESHEET_TEMPLATE = """
QMainWindow {
    background-color: $BG_APP;
    color: $TEXT;
}

QWidget {
    color: $TEXT;
    font-family: 'Segoe UI', 'Inter', 'Helvetica Neue', Arial, sans-serif;
}

#SidebarWidget {
    background-color: $SURFACE;
    border-right: 1px solid $BORDER;
}

#SidebarTitle {
    color: $TEXT;
    font-size: 16px;
    font-weight: bold;
}

#SidebarSubtitle {
    color: $TEXT_MUTED;
    font-size: 14px;
}

QPushButton.SidebarButton {
    background-color: transparent;
    color: $TEXT_SECONDARY;
    text-align: left;
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    border: none;
}

QPushButton.SidebarButton:hover {
    background-color: $HOVER_BG;
}

QPushButton.SidebarButton[active="true"] {
    background-color: $ACCENT_BG;
    color: $ACCENT;
    font-weight: 600;
}

#TopHeader {
    background-color: $SURFACE;
    border-bottom: 1px solid $BORDER;
}

QPushButton.PrimaryButton {
    background-color: $ACCENT;
    color: $SURFACE;
    border-radius: 6px;
    padding: 8px 20px;
    font-weight: 600;
    font-size: 13px;
    border: none;
}

QPushButton.PrimaryButton:hover {
    background-color: $ACCENT_HOVER;
}

QPushButton.PrimaryButton:pressed {
    background-color: $ACCENT_PRESSED;
}

QPushButton.PrimaryButton:disabled {
    background-color: $ACCENT_DISABLED;
    color: $SURFACE;
}

#WorkspaceHeader {
    background-color: $SURFACE;
    border-bottom: 1px solid $BORDER;
}

QLineEdit.DirInput {
    background-color: $SURFACE;
    border: 1px solid $BORDER_STRONG;
    border-radius: 6px;
    padding: 6px 12px;
    color: $TEXT;
    font-size: 14px;
}

QLineEdit.DirInput:focus {
    border: 2px solid $ACCENT;
    padding: 5px 11px;
}

QTextEdit.CodeEditor, QPlainTextEdit.CodeEditor {
    background-color: $SURFACE;
    color: $TEXT;
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 13px;
    border: none;
    line-height: 1.5;
}

QTextEdit.DiffEditor, QPlainTextEdit.DiffEditor {
    background-color: $SURFACE;
    color: $TEXT;
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 13px;
    border: none;
    line-height: 1.5;
}

#EditorPaneHeader {
    background-color: $BG_APP;
    border-bottom: 1px solid $BORDER;
}

#EditorPaneHeader QLabel {
    color: $TEXT_SECONDARY;
    font-size: 14px;
    font-weight: 500;
}

QPushButton.SecondaryButton {
    background-color: $SURFACE;
    color: $TEXT_SECONDARY;
    border: 1px solid $BORDER_STRONG;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 12px;
}

QPushButton.SecondaryButton:hover {
    background-color: $HOVER_BG;
    border-color: $BORDER_HOVER;
}

#PaneContainer {
    background-color: $SURFACE;
    border: 1px solid $BORDER;
}

QStatusBar {
    background-color: $SURFACE;
    color: $TEXT_MUTED;
    border-top: 1px solid $BORDER;
    font-size: 13px;
}

QStatusBar::item {
    border: none;
}

QSplitter::handle {
    background-color: $BORDER;
}

QRadioButton {
    color: $TEXT_SECONDARY;
    font-size: 13px;
    spacing: 6px;
}

QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border-radius: 8px;
    border: 2px solid $BORDER_HOVER;
    background-color: $SURFACE;
}

QRadioButton::indicator:checked {
    border-color: $ACCENT;
    background-color: $ACCENT;
}

QTabWidget::pane {
    border: 1px solid $BORDER;
    background: $SURFACE;
    border-radius: 6px;
}

QTabBar::tab {
    background: $HOVER_BG;
    color: $TEXT_MUTED;
    padding: 8px 18px;
    border: 1px solid $BORDER;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 500;
    margin-right: 2px;
}

QTabBar::tab:selected {
    background: $SURFACE;
    color: $ACCENT;
    border-bottom-color: $SURFACE;
    font-weight: 600;
}

QTabBar::tab:hover:!selected {
    background: $ACCENT_BG;
    color: $ACCENT;
}

QTreeWidget {
    background-color: $SURFACE;
    color: $TEXT;
    border: 1px solid $BORDER;
    font-size: 13px;
    border-radius: 4px;
}

QTreeWidget::item {
    padding: 3px;
}

QTreeWidget::item:selected {
    background-color: $ACCENT_BG;
    color: $ACCENT;
}

QTreeWidget::item:hover {
    background-color: $HOVER_BG;
}

QHeaderView::section {
    background-color: $BG_APP;
    color: $TEXT_SECONDARY;
    padding: 6px 8px;
    border: 1px solid $BORDER;
    font-weight: 600;
    font-size: 12px;
}

QTableWidget {
    background-color: $SURFACE;
    color: $TEXT;
    gridline-color: $BORDER;
    border: 1px solid $BORDER;
    font-size: 13px;
    border-radius: 4px;
}

QTableWidget::item:selected {
    background-color: $ACCENT_BG;
    color: $ACCENT;
}

QTableCornerButton::section {
    background-color: $BG_APP;
    border: 1px solid $BORDER;
}

QProgressBar {
    background-color: $BORDER;
    border: none;
    border-radius: 2px;
    height: 4px;
    max-height: 4px;
    text-align: center;
}

QProgressBar::chunk {
    background-color: $ACCENT;
    border-radius: 2px;
}

QScrollBar:vertical {
    background: $HOVER_BG;
    width: 10px;
    border: none;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background: $SCROLL_HANDLE;
    min-height: 30px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: $SCROLL_HANDLE_HOVER;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background: $HOVER_BG;
    height: 10px;
    border: none;
    border-radius: 5px;
}

QScrollBar::handle:horizontal {
    background: $SCROLL_HANDLE;
    min-width: 30px;
    border-radius: 5px;
}

QScrollBar::handle:horizontal:hover {
    background: $SCROLL_HANDLE_HOVER;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

QToolTip {
    background-color: $TEXT;
    color: $HOVER_BG;
    border: 1px solid $TEXT_SECONDARY;
    padding: 6px 10px;
    font-size: 12px;
    border-radius: 4px;
}

QPushButton.SecondaryButton:disabled {
    color: $TEXT_FAINT;
    border-color: $BORDER;
}

QPushButton.SecondaryButton:checked {
    background-color: $ACCENT_BG;
    border-color: $ACCENT;
    color: $ACCENT;
}

QPushButton.SecondaryButton:checked:disabled {
    background-color: $SURFACE;
    border-color: $BORDER;
    color: $TEXT_FAINT;
}

QPushButton.DangerButton {
    background-color: $SURFACE;
    color: $DANGER;
    border: 1px solid $DANGER;
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 12px;
    font-weight: 600;
}

QPushButton.DangerButton:hover {
    background-color: #fef2f2;
}

QPushButton.DangerButton:disabled {
    color: $TEXT_FAINT;
    border-color: $BORDER;
}

QRadioButton:disabled {
    color: $TEXT_FAINT;
}

QRadioButton::indicator:disabled {
    border-color: $BORDER;
    background-color: $HOVER_BG;
}

QComboBox, QSpinBox {
    font-size: 13px;
    min-height: 24px;
}

QCheckBox {
    color: $TEXT_SECONDARY;
    font-size: 13px;
    spacing: 6px;
}

QCheckBox:disabled {
    color: $TEXT_FAINT;
}

QFrame.Card {
    background-color: $SURFACE;
    border: 1px solid $BORDER;
    border-radius: 8px;
}

QLabel.PageTitle {
    font-size: 20px;
    font-weight: bold;
    color: $TEXT;
}

QLabel.SectionTitle {
    font-size: 14px;
    font-weight: bold;
    color: $TEXT;
}

QLabel.Caption {
    font-size: 12px;
    color: $TEXT_MUTED;
}

QLabel.EmptyState {
    color: $TEXT_FAINT;
    font-size: 14px;
    padding: 40px;
    background: transparent;
    border: none;
}

#ConsoleHeader {
    background-color: $BG_APP;
    border-bottom: 1px solid $BORDER;
}

#ConsoleHeader QLabel {
    color: $TEXT_SECONDARY;
    font-weight: 500;
    font-size: 12px;
}

QPushButton.LinkButton {
    background: transparent;
    border: none;
    color: $TEXT_MUTED;
    font-size: 12px;
    padding: 2px 8px;
}

QPushButton.LinkButton:hover {
    color: $ACCENT;
}
"""

MAIN_STYLESHEET = Template(_STYLESHEET_TEMPLATE).substitute(
    {k: v for k, v in globals().items() if k.isupper() and isinstance(v, str)}
)
