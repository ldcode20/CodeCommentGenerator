from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton, QStackedWidget
)
from PyQt6.QtGui import QColor, QBrush, QFont
from PyQt6.QtCore import Qt
from src.gui.security_graph_widget import SecurityGraphWidget

_EMPTY_STATE_STYLE = (
    "color: #9ca3af; font-size: 14px; padding: 40px; "
    "background: transparent; border: none;"
)


class SecurityWorkspace(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._security_report = None
        self._populated = False
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header_layout = QHBoxLayout()
        title = QLabel("Security Analysis")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #1a1a2e;")
        header_layout.addWidget(title)
        header_layout.addStretch()

        self.safety_score_label = QLabel("Safety Score: N/A")
        self.safety_score_label.setStyleSheet(
            "font-size: 16px; font-weight: bold; color: #6c757d; padding: 8px 16px;"
            "background: rgba(108,117,125,0.08); border-radius: 8px;"
        )
        header_layout.addWidget(self.safety_score_label)

        self.unsafe_pct_label = QLabel("N/A")
        self.unsafe_pct_label.setStyleSheet(
            "font-size: 14px; color: #6c757d; padding: 6px 12px;"
            "background: rgba(108,117,125,0.06); border-radius: 6px;"
        )
        header_layout.addWidget(self.unsafe_pct_label)

        layout.addLayout(header_layout)

        self._empty_state = QLabel(
            "Run code generation to perform security analysis.\n\n"
            "Safety scores, severity breakdown, per-function security ratings, "
            "and detailed issue reports will appear here."
        )
        self._empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_state.setStyleSheet(_EMPTY_STATE_STYLE)
        self._empty_state.setWordWrap(True)

        self.security_graph = SecurityGraphWidget()
        self._graph_stack = QStackedWidget()
        self._graph_stack.addWidget(self._empty_state)
        self._graph_stack.addWidget(self.security_graph)
        layout.addWidget(self._graph_stack, stretch=3)

        issues_label = QLabel("Security Issues Detail")
        issues_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #1a1a2e;")
        layout.addWidget(issues_label)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Severity", "Rule", "Function", "Line",
                                              "Status / Confidence", "Message / Remediation"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table, stretch=2)

    def populate(self, security_report):
        self._security_report = security_report
        if not security_report:
            if not self._populated:
                self._graph_stack.setCurrentIndex(0)
            self.safety_score_label.setText("Safety Score: N/A")
            self.safety_score_label.setStyleSheet(
                "font-size: 16px; font-weight: bold; color: #6c757d; padding: 8px 16px;"
                "background: rgba(108,117,125,0.08); border-radius: 8px;"
            )
            self.unsafe_pct_label.setText("N/A")
            self.unsafe_pct_label.setStyleSheet(
                "font-size: 14px; color: #6c757d; padding: 6px 12px;"
                "background: rgba(108,117,125,0.06); border-radius: 6px;"
            )
            return

        self._populated = True
        self._graph_stack.setCurrentIndex(1)

        safe_pct = security_report.module_safe_pct
        unsafe_pct = round(100.0 - safe_pct, 1)

        if safe_pct >= 80:
            color = "#16a34a"
            bg = "rgba(22,163,74,0.08)"
        elif safe_pct >= 50:
            color = "#ca8a04"
            bg = "rgba(202,138,4,0.08)"
        else:
            color = "#dc2626"
            bg = "rgba(220,38,38,0.08)"

        self.safety_score_label.setText(f"Safety: {safe_pct}% safe")
        self.safety_score_label.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {color}; padding: 8px 16px;"
            f"background: {bg}; border-radius: 8px;"
        )
        self.unsafe_pct_label.setText(f"{unsafe_pct}% unsafe")
        self.unsafe_pct_label.setStyleSheet(
            f"font-size: 14px; color: {'#dc2626' if unsafe_pct > 20 else '#ca8a04' if unsafe_pct > 0 else '#16a34a'}; "
            f"padding: 6px 12px; border-radius: 6px;"
        )

        self.security_graph.set_data(security_report)

        self.table.setRowCount(0)
        if security_report.issues:
            self.table.setRowCount(len(security_report.issues))
            for i, issue in enumerate(security_report.issues):
                sev_item = QTableWidgetItem(issue.severity.upper())
                sev_colors = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb"}
                sev_item.setForeground(QBrush(QColor(sev_colors.get(issue.severity, "#6b7280"))))
                self.table.setItem(i, 0, sev_item)
                rule_text = issue.pattern_id + (f" ({issue.cwe})" if getattr(issue, "cwe", None) else "")
                self.table.setItem(i, 1, QTableWidgetItem(rule_text))
                self.table.setItem(i, 2, QTableWidgetItem(issue.function_name))
                self.table.setItem(i, 3, QTableWidgetItem(str(issue.lineno)))
                status = getattr(issue, "status", "")
                confidence = getattr(issue, "confidence", "")
                self.table.setItem(i, 4, QTableWidgetItem(
                    f"{status} / {confidence}" if status else ""))
                msg = issue.message
                if issue.remediation:
                    msg += f" | Fix: {issue.remediation}"
                msg_item = QTableWidgetItem(msg)
                tip = []
                if getattr(issue, "trace", None):
                    tip.append("Evidence (original source lines):")
                    tip.extend("  " + t for t in issue.trace)
                if getattr(issue, "confidence_reasons", None):
                    tip.append("Confidence: " + "; ".join(issue.confidence_reasons))
                if tip:
                    tooltip = "\n".join(tip)
                    for col in range(6):
                        item = self.table.item(i, col) if col != 5 else msg_item
                        if item is not None:
                            item.setToolTip(tooltip)
                self.table.setItem(i, 5, msg_item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)
