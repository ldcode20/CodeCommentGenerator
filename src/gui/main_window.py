"""
Main window — sidebar navigation, the five workspaces and the console pane.
"""
import re
import sys

from PyQt6.QtCore import QObject, QSettings, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QKeySequence, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (QHBoxLayout, QLabel, QMainWindow, QMessageBox, QPlainTextEdit,
                             QPushButton, QSplitter, QStackedWidget, QVBoxLayout, QWidget)

from src.config import APP_NAME
from src.gui import theme
from src.gui.code_editor import code_font
from src.gui.generator_workspace import GeneratorWorkspace
from src.gui.insights_workspace import InsightsWorkspace
from src.gui.logs_workspace import LogsWorkspace
from src.gui.security_workspace import SecurityWorkspace
from src.gui.training_workspace import MLTrainingWorkspace
from src.gui.widgets import SpinningButton, ToastWidget

CONSOLE_MAX_LINES = 5000
_ERROR_RE = re.compile(r"\b(error|fail(ed|ure)?|exception|traceback)\b", re.IGNORECASE)
_SUCCESS_RE = re.compile(r"\b(success|completed|saved|done|finished)\b", re.IGNORECASE)


class StreamCapture(QObject):
    """File-like object that forwards writes to the console pane (thread-safe via signal)."""
    new_text = pyqtSignal(str, bool)

    def __init__(self, is_stderr=False):
        super().__init__()
        self._is_stderr = is_stderr

    def write(self, text):
        if text:
            self.new_text.emit(str(text), self._is_stderr)
        return len(text) if text else 0

    def flush(self):
        pass

    def isatty(self):
        return False


class MainWindow(QMainWindow):
    PAGES = ("Generator", "Insights", "ML Training", "Security", "Logs")

    def __init__(self, capture_output: bool = True, settings: QSettings = None):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self._settings = settings if settings is not None else QSettings("CodeCommentGenerator", "GUI")
        self._capture_output = capture_output
        self._console_sizes = [600, 150]
        self._status_reset_timer = QTimer(self)
        self._status_reset_timer.setSingleShot(True)
        self._status_reset_timer.timeout.connect(self._reset_status_style)
        self.setup_ui()
        self.setup_ui_connections()
        self.setup_shortcuts()
        self.restore_settings()

    # ── UI ────────────────────────────────────────────────────────────────
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self._toast_host = central_widget

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        top_header = QWidget()
        top_header.setObjectName("TopHeader")
        th_layout = QHBoxLayout(top_header)
        th_layout.setContentsMargins(16, 8, 16, 8)

        title_lbl = QLabel(APP_NAME)
        title_lbl.setStyleSheet(f"font-weight: bold; font-size: 15px; color: {theme.TEXT};")
        th_layout.addWidget(title_lbl)
        th_layout.addStretch()

        self.btn_generate = SpinningButton("Generate Comments")
        self.btn_generate.setProperty("class", "PrimaryButton")
        self.btn_generate.setToolTip("Generate and attach comments to the code in the editor (Ctrl+Enter)")
        self.btn_generate.clicked.connect(self.trigger_generation)
        th_layout.addWidget(self.btn_generate)
        main_layout.addWidget(top_header)

        self.body_splitter = QSplitter(Qt.Orientation.Horizontal)

        sidebar = QWidget()
        sidebar.setObjectName("SidebarWidget")
        sidebar.setMinimumWidth(170)
        sidebar.setMaximumWidth(230)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(12, 16, 12, 16)
        sb_layout.setSpacing(6)

        self.nav_buttons = []
        for idx, name in enumerate(self.PAGES):
            btn = QPushButton(name)
            btn.setProperty("class", "SidebarButton")
            btn.setToolTip(f"Alt+{idx + 1}")
            btn.clicked.connect(lambda _checked=False, i=idx: self.show_page(i))
            sb_layout.addWidget(btn)
            self.nav_buttons.append(btn)
        sb_layout.addStretch()
        self.body_splitter.addWidget(sidebar)

        self.stacked_widget = QStackedWidget()
        self.workspace_gen = GeneratorWorkspace()
        self.workspace_insights = InsightsWorkspace()
        self.workspace_ml = MLTrainingWorkspace()
        self.workspace_security = SecurityWorkspace()
        self.workspace_logs = LogsWorkspace()
        for workspace in (self.workspace_gen, self.workspace_insights, self.workspace_ml,
                          self.workspace_security, self.workspace_logs):
            self.stacked_widget.addWidget(workspace)

        self.content_splitter = QSplitter(Qt.Orientation.Vertical)
        self.content_splitter.addWidget(self.stacked_widget)

        console_widget = QWidget()
        console_widget.setObjectName("PaneContainer")
        console_layout = QVBoxLayout(console_widget)
        console_layout.setContentsMargins(0, 0, 0, 0)
        console_layout.setSpacing(0)

        console_header = QWidget()
        console_header.setObjectName("ConsoleHeader")
        ch_layout = QHBoxLayout(console_header)
        ch_layout.setContentsMargins(12, 4, 8, 4)
        ch_layout.addWidget(QLabel("Console"))
        ch_layout.addStretch()
        self.btn_console_clear = QPushButton("Clear")
        self.btn_console_clear.setProperty("class", "LinkButton")
        self.btn_console_toggle = QPushButton("Hide")
        self.btn_console_toggle.setProperty("class", "LinkButton")
        self.btn_console_toggle.clicked.connect(self.toggle_console)
        ch_layout.addWidget(self.btn_console_clear)
        ch_layout.addWidget(self.btn_console_toggle)

        self.console_output = QPlainTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setMaximumBlockCount(CONSOLE_MAX_LINES)
        self.console_output.setFont(code_font(9))
        self.console_output.setPlaceholderText("Pipeline and training output appears here…")
        self.console_output.setStyleSheet(f"background: {theme.SURFACE}; border: none;")
        self.btn_console_clear.clicked.connect(self.console_output.clear)

        console_layout.addWidget(console_header)
        console_layout.addWidget(self.console_output)
        self._console_header = console_header

        self.content_splitter.addWidget(console_widget)
        self.content_splitter.setCollapsible(0, False)
        self.content_splitter.setSizes(self._console_sizes)
        self.body_splitter.addWidget(self.content_splitter)
        self.body_splitter.setStretchFactor(1, 1)
        main_layout.addWidget(self.body_splitter, stretch=1)

        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet(f"padding: 0px 8px; color: {theme.TEXT_MUTED};")
        self.statusBar().addPermanentWidget(self._status_label)

        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        if self._capture_output:
            self.stdout_capture = StreamCapture(is_stderr=False)
            self.stdout_capture.new_text.connect(self.append_to_console)
            self.stderr_capture = StreamCapture(is_stderr=True)
            self.stderr_capture.new_text.connect(self.append_to_console)
            sys.stdout = self.stdout_capture
            sys.stderr = self.stderr_capture

        self.toast = ToastWidget(self._toast_host)
        self.toast.hide()
        self.show_page(0)

    def setup_ui_connections(self):
        gen, sec, ml = self.workspace_gen, self.workspace_security, self.workspace_ml
        gen.generationFinished.connect(self._on_generation_finished)
        gen.outputDirChanged.connect(self.workspace_logs.set_pipeline_dir)
        sec.scanEditorRequested.connect(self._scan_editor_code)
        sec.jumpRequested.connect(self._jump_to_finding)
        sec.reportShown.connect(gen.update_unsafe_pct)
        self.workspace_insights.jumpRequested.connect(lambda line: self._jump_to_finding("", line))
        ml.modelUpdated.connect(self._on_model_updated)
        self.workspace_logs.set_pipeline_dir(gen.output_dir())

    def setup_shortcuts(self):
        def bind(keys, slot):
            shortcut = QShortcut(QKeySequence(keys), self)
            shortcut.setContext(Qt.ShortcutContext.ApplicationShortcut)
            shortcut.activated.connect(slot)

        bind("Ctrl+O", self._open_file)
        bind("Ctrl+Return", self.trigger_generation)
        bind("Ctrl+Enter", self.trigger_generation)
        bind("Ctrl+S", self._save_output)
        for idx in range(len(self.PAGES)):
            bind(f"Alt+{idx + 1}", lambda i=idx: self.show_page(i))

    # ── navigation ────────────────────────────────────────────────────────
    def show_page(self, idx: int):
        self.stacked_widget.setCurrentIndex(idx)
        for i, btn in enumerate(self.nav_buttons):
            btn.setProperty("active", "true" if i == idx else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        if self.PAGES[idx] == "Logs":
            self.workspace_logs.load_log_list()

    def toggle_console(self):
        sizes = self.content_splitter.sizes()
        header_h = self._console_header.sizeHint().height()
        if sizes[1] > header_h + 4:
            self._console_sizes = sizes
            self.content_splitter.setSizes([sum(sizes) - header_h, header_h])
            self.btn_console_toggle.setText("Show")
        else:
            total = sum(sizes)
            bottom = max(120, min(self._console_sizes[1], total // 2))
            self.content_splitter.setSizes([total - bottom, bottom])
            self.btn_console_toggle.setText("Hide")

    # ── console and status ────────────────────────────────────────────────
    def append_to_console(self, text, is_stderr=False):
        fmt = QTextCharFormat()
        if _ERROR_RE.search(text) or (is_stderr and "Traceback" in text):
            fmt.setForeground(QColor(theme.DANGER))
        elif is_stderr:
            # Libraries (tqdm, transformers) write ordinary progress to stderr.
            fmt.setForeground(QColor(theme.TEXT_MUTED))
        elif _SUCCESS_RE.search(text):
            fmt.setForeground(QColor(theme.SUCCESS))
        else:
            fmt.setForeground(QColor(theme.TEXT))

        bar = self.console_output.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 4
        cursor = self.console_output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text, fmt)
        if at_bottom:  # do not yank the view while the user is reading older output
            bar.setValue(bar.maximum())

    def _set_status(self, message, color=theme.TEXT_MUTED, reset_after_ms: int = 0):
        self._status_label.setText(message)
        self._status_label.setStyleSheet(f"padding: 0px 8px; color: {color}; font-weight: 600;")
        self._status_reset_timer.stop()
        if reset_after_ms:
            self._status_reset_timer.start(reset_after_ms)

    def _reset_status_style(self):
        self._status_label.setText("Ready")
        self._status_label.setStyleSheet(f"padding: 0px 8px; color: {theme.TEXT_MUTED};")

    # ── actions ───────────────────────────────────────────────────────────
    def _open_file(self):
        self.show_page(0)
        self.workspace_gen.open_file()

    def _save_output(self):
        if not self.workspace_gen.has_output():
            self.toast.show_toast("Nothing to save yet — generate comments first", kind="info")
            return
        path = self.workspace_gen.save_output()
        if path:
            self.toast.show_toast("Annotated file saved", kind="success")
            self._set_status(f"Saved {path}", theme.SUCCESS, reset_after_ms=8000)

    def trigger_generation(self):
        if self.btn_generate.is_spinning():
            return
        self.show_page(0)
        # Only show the busy state once a run has really started; an empty
        # editor used to leave this button spinning and disabled forever.
        if self.workspace_gen.trigger_generation():
            self._set_status("Generating…", theme.ACCENT)
            self.btn_generate.start_spinning("Generating…")

    def _on_generation_finished(self, ok: bool, payload):
        self.btn_generate.stop_spinning()
        if not ok:
            self._set_status("✗ Generation failed", theme.DANGER, reset_after_ms=8000)
            self.toast.show_toast("Generation failed — see the message above the output",
                                  kind="error")
            return
        self.workspace_insights.populate_insights(payload)
        security_report = payload.get("security_report")
        language = payload.get("language", "python")
        if language != "python":
            from src.languages import language_name
            self.workspace_security.show_unsupported(language_name(language))
            self.workspace_gen.update_unsafe_pct(None, language=language)
            self._set_status(f"✓ {payload.get('comments', 0)} comments generated ({language_name(language)})",
                             theme.SUCCESS, reset_after_ms=8000)
            self.toast.show_toast("Comments generated", kind="success")
            return
        if security_report is not None:
            # populate() also refreshes the Generator's security badge.
            self.workspace_security.populate(security_report,
                                             source=self.workspace_gen.source_name())
            extra = f" | {security_report.total_issues} security issue(s)"
        else:
            extra = ""
        self._set_status(f"✓ {payload.get('comments', 0)} comments generated{extra}",
                         theme.SUCCESS, reset_after_ms=8000)
        self.toast.show_toast("Comments generated", kind="success")

    def _scan_editor_code(self):
        language = self.workspace_gen.selected_language()
        if language != "python":
            from src.languages import language_name
            self.workspace_security.show_unsupported(language_name(language))
            self.toast.show_toast(f"Security scanning is Python-only; {language_name(language)} "
                                  f"is not scanned", kind="info")
            return
        self.workspace_security.scan_source(self.workspace_gen.current_code(),
                                            self.workspace_gen.source_name())

    def _jump_to_finding(self, path: str, line: int):
        gen = self.workspace_gen
        if path and path != (gen.current_filepath or ""):
            if gen.is_busy():
                self.toast.show_toast("Wait for the current run to finish", kind="info")
                return
            if gen.current_code().strip() and not gen.current_filepath:
                answer = QMessageBox.question(
                    self, "Replace the editor content?",
                    f"Open {path} in the Generator editor?\n\nThe pasted code in the editor "
                    f"will be replaced.")
                if answer != QMessageBox.StandardButton.Yes:
                    return
            if not gen.load_file(path):
                return
        self.show_page(0)
        if not gen.goto_line(line):
            self.toast.show_toast(f"Line {line} is not in the current editor content", kind="info")

    def _on_model_updated(self):
        self.workspace_gen.invalidate_model()
        self.workspace_insights.refresh_evaluation()
        self.toast.show_toast("New model ready", kind="success")

    # ── persisted state ───────────────────────────────────────────────────
    def restore_settings(self):
        s = self._settings
        geometry = s.value("window/geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        else:
            self.resize(1200, 800)
        for key, splitter in (("window/body_splitter", self.body_splitter),
                              ("window/content_splitter", self.content_splitter)):
            state = s.value(key)
            if state is not None:
                splitter.restoreState(state)
        self.workspace_gen.restore_settings(s)
        self.workspace_security.restore_settings(s)
        self.workspace_ml.restore_settings(s)
        self.workspace_logs.set_pipeline_dir(self.workspace_gen.output_dir())

    def save_settings(self):
        s = self._settings
        s.setValue("window/geometry", self.saveGeometry())
        s.setValue("window/body_splitter", self.body_splitter.saveState())
        s.setValue("window/content_splitter", self.content_splitter.saveState())
        self.workspace_gen.save_settings(s)
        self.workspace_security.save_settings(s)
        self.workspace_ml.save_settings(s)
        s.sync()

    # ── shutdown ──────────────────────────────────────────────────────────
    def busy_tasks(self):
        tasks = []
        if self.workspace_ml.is_busy():
            tasks.append("model training")
        if self.workspace_gen.is_busy():
            tasks.append("comment generation")
        if self.workspace_security.is_busy():
            tasks.append("a security scan")
        return tasks

    def closeEvent(self, event):
        tasks = self.busy_tasks()
        if tasks:
            answer = QMessageBox.question(
                self, "Work in progress",
                f"Still running: {', '.join(tasks)}.\n\nStop and quit? "
                f"A training run in progress will be cancelled; the saved model is not affected.")
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._stop_workers()
        self.save_settings()
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        super().closeEvent(event)

    def _stop_workers(self):
        """Never destroy a running QThread: ask, wait, and only then force."""
        self._set_status("Stopping background work…", theme.WARNING)
        self.workspace_ml.cancel_training()
        threads = [self.workspace_ml.worker, self.workspace_gen.worker,
                   self.workspace_security._worker]
        for thread in threads:
            if thread is not None and thread.isRunning() and not thread.wait(20000):
                # Stuck in a step that cannot be interrupted (e.g. a download).
                thread.terminate()
                thread.wait(2000)
