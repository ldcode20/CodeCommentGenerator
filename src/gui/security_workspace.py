"""
Security workspace — scan a file or a folder, read the evidence, jump to code.
"""
import json
import os
import traceback
from typing import Callable, List, Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel, QMessageBox,
                             QPlainTextEdit, QProgressBar, QPushButton, QSplitter,
                             QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout,
                             QWidget)

from src.gui import theme
from src.gui.code_editor import code_font
from src.gui.security_graph_widget import SecurityGraphWidget

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_COLUMNS = ["Severity", "Rule", "Location", "Function", "Status", "Confidence", "Message"]
_EMPTY_TEXT = (
    "No security analysis yet.\n\n"
    "Scan the code in the Generator editor, scan a whole folder (cross-file analysis), "
    "or generate comments — the pipeline runs the same analysis.\n"
    "No trained model is needed."
)


class ScanWorker(QThread):
    """Runs one analysis callable off the UI thread."""
    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, fn: Callable[[], object]):
        super().__init__()
        self._fn = fn

    def run(self):
        try:
            self.done.emit(self._fn())
        except Exception:
            self.failed.emit(traceback.format_exc())


class SecurityWorkspace(QWidget):
    #: Ask the main window for the editor's code (it calls :meth:`scan_source`).
    scanEditorRequested = pyqtSignal()
    #: (path or "" for the code in the editor, 1-based line)
    jumpRequested = pyqtSignal(str, int)
    #: A single-file report was shown (used to refresh the Generator badge).
    reportShown = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._report = None           # SecurityReport (single file)
        self._project = None          # ProjectFindings (folder scan)
        self._findings: list = []     # every Finding of the current result
        self._visible: list = []      # the filtered subset, row order
        self._worker: Optional[ScanWorker] = None
        self._last_dir = ""
        self.setup_ui()

    # ── UI ────────────────────────────────────────────────────────────────
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        header = QHBoxLayout()
        title = QLabel("Security Analysis")
        title.setProperty("class", "PageTitle")
        header.addWidget(title)
        self.safety_score_label = QLabel()
        header.addWidget(self.safety_score_label)
        header.addStretch()

        self.btn_scan_editor = QPushButton("Scan Editor Code")
        self.btn_scan_editor.setProperty("class", "PrimaryButton")
        self.btn_scan_editor.setToolTip("Analyse the code in the Generator editor. "
                                        "No comment generation, no ML model.")
        self.btn_scan_editor.clicked.connect(lambda _checked=False: self.scanEditorRequested.emit())
        self.btn_scan_folder = QPushButton("Scan Folder…")
        self.btn_scan_folder.setProperty("class", "SecondaryButton")
        self.btn_scan_folder.setToolTip("Analyse every .py file in a folder, following calls "
                                        "between files.")
        self.btn_scan_folder.clicked.connect(lambda _checked=False: self.choose_folder())
        self.btn_export = QPushButton("Export JSON…")
        self.btn_export.setProperty("class", "SecondaryButton")
        self.btn_export.clicked.connect(lambda _checked=False: self.export_json())
        self.btn_export.setEnabled(False)
        for btn in (self.btn_scan_editor, self.btn_scan_folder, self.btn_export):
            header.addWidget(btn)
        layout.addLayout(header)

        self.source_label = QLabel("")
        self.source_label.setProperty("class", "Caption")
        self.source_label.setWordWrap(True)
        layout.addWidget(self.source_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(3)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # top: charts (single file) / summary (folder) / empty state
        self._empty_state = QLabel(_EMPTY_TEXT)
        self._empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_state.setProperty("class", "EmptyState")
        self._empty_state.setWordWrap(True)
        self.security_graph = SecurityGraphWidget()
        self._project_summary = QLabel()
        self._project_summary.setWordWrap(True)
        self._project_summary.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self._project_summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._project_summary.setStyleSheet(
            f"background: {theme.SURFACE}; border: 1px solid {theme.BORDER}; border-radius: 8px; "
            f"padding: 14px 18px; font-size: 13px; color: {theme.TEXT};")
        self._graph_stack = QStackedWidget()
        for w in (self._empty_state, self.security_graph, self._project_summary):
            self._graph_stack.addWidget(w)

        # bottom: filters + table | evidence
        bottom = QWidget()
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(8)

        filters = QHBoxLayout()
        issues_label = QLabel("Findings")
        issues_label.setProperty("class", "SectionTitle")
        filters.addWidget(issues_label)
        self.count_label = QLabel("")
        self.count_label.setProperty("class", "Caption")
        filters.addWidget(self.count_label)
        filters.addStretch()
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All severities", "critical", "high", "medium", "low"])
        self.status_filter = QComboBox()
        self.status_filter.addItems(["Active (not suppressed)", "All statuses", "confirmed",
                                     "potential", "suppressed"])
        for combo in (self.severity_filter, self.status_filter):
            combo.currentIndexChanged.connect(self._refill_table)
            filters.addWidget(combo)
        bottom_layout.addLayout(filters)

        self.table = QTableWidget()
        self.table.setColumnCount(len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setToolTip("Select a finding to read its evidence. Double-click to open the line.")
        self.table.itemSelectionChanged.connect(self._show_evidence)
        self.table.cellDoubleClicked.connect(self._on_double_click)

        evidence_box = QWidget()
        ev_layout = QVBoxLayout(evidence_box)
        ev_layout.setContentsMargins(0, 0, 0, 0)
        ev_layout.setSpacing(4)
        ev_head = QHBoxLayout()
        ev_title = QLabel("Evidence")
        ev_title.setProperty("class", "SectionTitle")
        self.btn_open_line = QPushButton("Open in editor")
        self.btn_open_line.setProperty("class", "SecondaryButton")
        self.btn_open_line.setEnabled(False)
        self.btn_open_line.clicked.connect(lambda: self._jump_to(self.table.currentRow()))
        ev_head.addWidget(ev_title)
        ev_head.addStretch()
        ev_head.addWidget(self.btn_open_line)
        ev_layout.addLayout(ev_head)
        self.evidence = QPlainTextEdit()
        self.evidence.setReadOnly(True)
        self.evidence.setFont(code_font(9))
        self.evidence.setPlaceholderText(
            "Select a finding to see how untrusted data reaches the sink, why the analyzer "
            "is confident, and how to fix it.")
        self.evidence.setStyleSheet(
            f"background: {theme.SURFACE}; border: 1px solid {theme.BORDER}; border-radius: 4px;")
        ev_layout.addWidget(self.evidence)

        self.detail_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.detail_splitter.addWidget(self.table)
        self.detail_splitter.addWidget(evidence_box)
        self.detail_splitter.setSizes([560, 440])
        bottom_layout.addWidget(self.detail_splitter, stretch=1)

        self.main_splitter = QSplitter(Qt.Orientation.Vertical)
        self.main_splitter.addWidget(self._graph_stack)
        self.main_splitter.addWidget(bottom)
        self.main_splitter.setSizes([330, 330])
        layout.addWidget(self.main_splitter, stretch=1)

        self._set_score_badge(None)

    # ── scanning ──────────────────────────────────────────────────────────
    def is_busy(self) -> bool:
        return self._worker is not None and self._worker.isRunning()

    def wait_for_worker(self, msecs: int = 15000) -> bool:
        return self._worker is None or self._worker.wait(msecs)

    def _start(self, fn: Callable[[], object], on_done: Callable[[object], None], label: str):
        if self.is_busy():
            return
        self.progress_bar.show()
        self.source_label.setText(label)
        self.btn_scan_editor.setEnabled(False)
        self.btn_scan_folder.setEnabled(False)
        self._worker = ScanWorker(fn)
        self._worker.done.connect(lambda result: (self._scan_finished(), on_done(result)))
        self._worker.failed.connect(self._scan_failed)
        self._worker.start()

    def _scan_finished(self):
        self.progress_bar.hide()
        self.btn_scan_editor.setEnabled(True)
        self.btn_scan_folder.setEnabled(True)

    def _scan_failed(self, trace: str):
        self._scan_finished()
        self.source_label.setText("Scan failed.")
        QMessageBox.warning(self, "Security scan failed", trace[-2000:])

    def scan_source(self, code: str, name: str):
        """Analyse a source string (the Generator editor's content)."""
        if not code.strip():
            QMessageBox.information(self, "Nothing to scan",
                                    "The Generator editor is empty. Open a file or paste code first.")
            return
        from src.security_analyzer import run_security_analysis_on_source
        self._start(lambda: run_security_analysis_on_source(code, name),
                    lambda report: self.populate(report, source=name),
                    f"Scanning {name}…")

    def choose_folder(self):
        root = QFileDialog.getExistingDirectory(self, "Choose a folder to scan", self._last_dir)
        if root:
            self._last_dir = root
            self.scan_folder(root)

    def scan_folder(self, root: str):
        from src.security.project import analyze_project
        self._start(lambda: analyze_project(root), self.populate_project,
                    f"Scanning folder {root}…")

    # ── results ───────────────────────────────────────────────────────────
    def _set_score_badge(self, text: Optional[str], color: str = theme.TEXT_MUTED):
        self.safety_score_label.setText(text or "Not analysed")
        self.safety_score_label.setStyleSheet(
            theme.badge_style(color, font_size=14, filled=text is not None))

    def populate(self, security_report, source: str = ""):
        """Show a single-file :class:`SecurityReport` (from a scan or a pipeline run)."""
        if security_report is None:
            return
        self._report, self._project = security_report, None
        self._findings = list(security_report.findings)
        self.btn_export.setEnabled(True)

        if security_report.parse_error:
            self._graph_stack.setCurrentIndex(0)
            self._empty_state.setText(f"Could not analyse {source or 'the code'}:\n\n"
                                      f"{security_report.parse_error}")
            self._set_score_badge("Could not parse", theme.DANGER)
        else:
            self._graph_stack.setCurrentIndex(1)
            self.security_graph.set_data(security_report)
            self._resize_top(300)
            safe = security_report.module_safe_pct
            self._set_score_badge(f"{safe:g}% of functions safe", theme.score_color(safe))

        n_supp = len(security_report.suppressed)
        self.source_label.setText(
            f"{source or 'Editor code'} — {security_report.total_issues} active finding(s)"
            + (f", {n_supp} suppressed" if n_supp else ""))
        self._refill_table()
        self.reportShown.emit(security_report)

    def populate_project(self, project):
        """Show a folder scan (:class:`src.security.project.ProjectFindings`)."""
        self._report, self._project = None, project
        self._findings = list(project.findings)
        self.btn_export.setEnabled(True)
        active = project.active()
        by_sev = {}
        for f in active:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        files_hit = len({f.file for f in active})
        worst = min((_SEVERITY_ORDER.get(s, 9) for s in by_sev), default=9)
        color = theme.SUCCESS if not active else (theme.DANGER if worst <= 1 else theme.WARNING)
        self._set_score_badge(f"{len(active)} active finding(s) in {files_hit} file(s)", color)

        sev_text = ", ".join(f"{by_sev[s]} {s}" for s in _SEVERITY_ORDER if s in by_sev) or "none"
        lines = [
            f"<b>{project.root}</b>",
            f"{len(project.modules)} module(s) analysed in {project.runtime_ms:.0f} ms "
            f"({project.rounds} cross-file round(s){'' if project.converged else ', did not converge'}).",
            f"Active findings by severity: {sev_text}.",
        ]
        if project.cycles:
            lines.append("Import cycles: " + "; ".join(" → ".join(c) for c in project.cycles[:5]))
        if project.parse_errors:
            lines.append(f"<span style='color:{theme.DANGER}'>{len(project.parse_errors)} file(s) "
                         f"could not be parsed and were skipped:</span> "
                         + ", ".join(os.path.basename(p) for p in list(project.parse_errors)[:8]))
        self._project_summary.setText("<br><br>".join(lines))
        self._graph_stack.setCurrentIndex(2)
        self._resize_top(150)
        self.source_label.setText(f"Folder scan — {project.root}")
        self._refill_table()

    def _resize_top(self, height: int):
        """Give the charts / summary only the height they need; the table gets the rest."""
        total = sum(self.main_splitter.sizes())
        if total > height + 150:
            self.main_splitter.setSizes([height, total - height])

    def _passes_filters(self, finding) -> bool:
        sev = self.severity_filter.currentText()
        if self.severity_filter.currentIndex() > 0 and finding.severity != sev:
            return False
        idx = self.status_filter.currentIndex()
        if idx == 0:
            return finding.status != "suppressed"
        if idx == 1:
            return True
        return finding.status == self.status_filter.currentText()

    def _location(self, finding) -> str:
        if self._project is not None:
            try:
                rel = os.path.relpath(finding.file, self._project.root)
            except ValueError:
                rel = finding.file
            return f"{rel}:{finding.line}"
        return f"line {finding.line}"

    def _refill_table(self):
        self._visible = sorted(
            (f for f in self._findings if self._passes_filters(f)),
            key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))
        self.table.setRowCount(0)
        self.table.setRowCount(len(self._visible))
        for row, f in enumerate(self._visible):
            sev_item = QTableWidgetItem(f.severity.upper())
            sev_item.setForeground(QBrush(QColor(theme.SEVERITY_COLORS.get(f.severity, theme.GRAY))))
            cells = [
                sev_item,
                QTableWidgetItem(f.rule_id + (f" ({f.cwe})" if f.cwe else "")),
                QTableWidgetItem(self._location(f)),
                QTableWidgetItem(f.function.rsplit(".", 1)[-1] if self._project is None else f.function),
                QTableWidgetItem(f.status),
                QTableWidgetItem(f.confidence),
                QTableWidgetItem(f"{f.title}: {f.message}" if f.title else f.message),
            ]
            for col, item in enumerate(cells):
                if f.status == "suppressed" and col:
                    item.setForeground(QBrush(QColor(theme.TEXT_FAINT)))
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)
        total = len(self._findings)
        self.count_label.setText(
            f"{len(self._visible)} shown of {total}" if total else
            ("No findings." if (self._report or self._project) else ""))
        self.evidence.clear()
        self.btn_open_line.setEnabled(False)
        if self._visible:
            self.table.selectRow(0)

    def _show_evidence(self):
        row = self.table.currentRow()
        if 0 <= row < len(self._visible):
            self.evidence.setPlainText(self._visible[row].format_text())
            self.btn_open_line.setEnabled(True)
        else:
            self.evidence.clear()
            self.btn_open_line.setEnabled(False)

    def _on_double_click(self, row: int, _col: int):
        self._jump_to(row)

    def _jump_to(self, row: int):
        if 0 <= row < len(self._visible):
            f = self._visible[row]
            self.jumpRequested.emit(f.file if self._project is not None else "", int(f.line))

    # ── export ────────────────────────────────────────────────────────────
    def export_data(self) -> Optional[dict]:
        if self._project is not None:
            return self._project.to_dict()
        if self._report is not None:
            data = self._report.to_dict()
            data["findings"] = [f.to_dict() for f in self._report.findings]
            return data
        return None

    def export_json(self):
        data = self.export_data()
        if data is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export security findings",
            os.path.join(self._last_dir, "security_findings.json"), "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except OSError as exc:
            QMessageBox.warning(self, "Cannot write file", f"{path}\n\n{exc}")
            return
        self.source_label.setText(f"Exported to {path}")

    # ── persisted state ───────────────────────────────────────────────────
    def save_settings(self, settings):
        settings.setValue("security/last_dir", self._last_dir)
        settings.setValue("security/main_splitter", self.main_splitter.saveState())
        settings.setValue("security/detail_splitter", self.detail_splitter.saveState())

    def restore_settings(self, settings):
        self._last_dir = str(settings.value("security/last_dir", "") or "")
        for key, splitter in (("security/main_splitter", self.main_splitter),
                              ("security/detail_splitter", self.detail_splitter)):
            state = settings.value(key)
            if state is not None:
                splitter.restoreState(state)
