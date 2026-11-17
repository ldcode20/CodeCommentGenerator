"""
Generator workspace — source in, annotated source out.
"""
import difflib
import os
import sys
import tempfile
import traceback
from typing import List, Optional

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import (QButtonGroup, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                             QMessageBox, QProgressBar, QPushButton, QRadioButton,
                             QSplitter, QVBoxLayout, QWidget)

from src.config import GUI_OUTPUT_DIR, OUTPUT_DIR, model_available, resolve_project_path
from src.error_handler import ParserError, format_error
from src.gui import theme
from src.gui.code_editor import CodeEditor
from src.gui.syntax_highlighter import make_code_highlighter
from src.languages import LANGUAGES, detect_language, file_dialog_filter, language_name
from src.logger import PipelineLogger

UNTITLED = "untitled.py"
LANGUAGE_KEYS = ("python", "java", "c", "cpp")


def default_extension(language: str) -> str:
    return LANGUAGES[language].extensions[0]


def pipeline_file_name(source_path: Optional[str], code: str, language: str) -> str:
    """Name for the pipeline's private copy: the real name when its extension matches
    the chosen language, otherwise the stem with the language's own extension."""
    if source_path:
        name = os.path.basename(source_path)
        if detect_language(name, code) == language:
            return name
        return os.path.splitext(name)[0] + default_extension(language)
    return "untitled" + default_extension(language)
ENGINES = ("rule_based", "neurosymbolic", "ml")
_NO_MODEL_HINT = "No trained model yet — train one in the ML Training tab."


def added_lines(original: str, annotated: str) -> List[int]:
    """1-based line numbers of ``annotated`` that are not in ``original``."""
    a, b = original.splitlines(), annotated.splitlines()
    out: List[int] = []
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("insert", "replace"):
            out.extend(range(j1 + 1, j2 + 1))
    return out


class GeneratorWorker(QThread):
    """Runs one pipeline pass off the UI thread."""
    progress = pyqtSignal(str)
    succeeded = pyqtSignal(object)      # dict: annotated, result, output_file
    failed = pyqtSignal(object)         # dict: message, detail, line, column
    modelLoaded = pyqtSignal(object)    # the loaded model, for reuse by later runs

    def __init__(self, code_text: str, engine: str, output_dir: str,
                 source_path: Optional[str], ast_model=None, language: str = "python"):
        super().__init__()
        self.code_text = code_text
        self.language = language
        self.engine = engine
        self.output_dir = output_dir
        self.source_path = source_path
        self.ast_model = ast_model

    def run(self):
        try:
            # Imported here so opening the window does not pay for torch.
            from src.main import run_pipeline

            name = pipeline_file_name(self.source_path, self.code_text, self.language)
            stem, ext = os.path.splitext(name)
            os.makedirs(self.output_dir, exist_ok=True)

            ast_model = self.ast_model
            if self.language != "python" and self.engine != "rule_based":
                self.progress.emit(f"The ML model was trained on Python; using rule-based "
                                   f"comments for {language_name(self.language)}…")
            elif self.engine in ("ml", "neurosymbolic") and ast_model is None:
                self.progress.emit("Loading AST+NLP model…")
                from src.ml.trainer import load_ast_model
                ast_model = load_ast_model(output_dir=str(OUTPUT_DIR))
                if ast_model is None:
                    raise RuntimeError(
                        "No trained AST+NLP model found. Train one in the ML Training tab, "
                        "or run: python -m src.main --train --quick")
                self.modelLoaded.emit(ast_model)

            self.progress.emit("Running pipeline…")
            # The editor text may differ from the file on disk, so the pipeline
            # reads a private copy — named like the original so reports and
            # logs show the real file name rather than a temp name.
            logger = PipelineLogger(input_file=self.source_path or name)
            with tempfile.TemporaryDirectory(prefix="ccg_") as tmp:
                tmp_in = os.path.join(tmp, name)
                with open(tmp_in, "w", encoding="utf-8") as fh:
                    fh.write(self.code_text)
                result = run_pipeline(
                    tmp_in, logger,
                    ast_model=ast_model if self.engine != "rule_based" else None,
                    strict_ml=self.engine in ("ml", "neurosymbolic"),
                    engine=self.engine,
                )

            # Findings were located in the private copy; report the real file.
            shown_path = self.source_path or name
            for finding in result.security_report.findings:
                finding.file = shown_path

            self.progress.emit("Saving output and logs…")
            out_file = os.path.join(self.output_dir, f"{stem}_annotated{ext}")
            with open(out_file, "w", encoding="utf-8") as fh:
                fh.write(result.annotated_source)
            logger.set_output_file(out_file)
            logger.save(os.path.join(self.output_dir, "logs"))

            self.succeeded.emit({"annotated": result.annotated_source, "result": result,
                                 "output_file": out_file})
        except ParserError as exc:
            self.failed.emit({"message": format_error(exc), "detail": "",
                              "line": exc.line, "column": exc.column})
        except Exception as exc:  # shown to the user, never swallowed
            self.failed.emit({"message": f"{type(exc).__name__}: {exc}",
                              "detail": traceback.format_exc(), "line": None, "column": None})


class GeneratorWorkspace(QWidget):
    generationStarted = pyqtSignal()
    #: (ok, payload) — payload is the results dict on success, the error dict otherwise.
    generationFinished = pyqtSignal(bool, object)
    #: Absolute output directory, emitted whenever it changes.
    outputDirChanged = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_filepath: Optional[str] = None
        self.last_output_file: Optional[str] = None
        self.worker: Optional[GeneratorWorker] = None
        self._ast_model = None
        self._last_dir = ""
        self._steps: List[str] = []
        self._source_for_output = ""
        self.setup_ui()
        self.refresh_engine_availability()
        if self.btn_neuro.isEnabled():
            self.btn_neuro.setChecked(True)

    # ── UI ────────────────────────────────────────────────────────────────
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QWidget()
        header.setObjectName("WorkspaceHeader")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 10, 16, 10)
        header_layout.setSpacing(12)

        engine_lbl = QLabel("Engine:")
        engine_lbl.setProperty("class", "Caption")
        header_layout.addWidget(engine_lbl)

        self.btn_rule = QRadioButton("Rule-Based")
        self.btn_neuro = QRadioButton("Neurosymbolic")
        self.btn_ml = QRadioButton("ML-Based")
        self.btn_rule.setToolTip("Deterministic, AST-driven. Needs no trained model.")
        self.engine_btn_group = QButtonGroup(self)
        for idx, btn in enumerate((self.btn_rule, self.btn_neuro, self.btn_ml)):
            self.engine_btn_group.addButton(btn, idx)
            header_layout.addWidget(btn)
        self.btn_rule.setChecked(True)

        header_layout.addStretch()

        self.unsafe_label = QLabel()
        header_layout.addWidget(self.unsafe_label)
        self.update_unsafe_pct(None, analysed=False)

        dir_label = QLabel("Output folder:")
        dir_label.setProperty("class", "Caption")
        self.out_dir_input = QLineEdit("./out/annotated")
        self.out_dir_input.setProperty("class", "DirInput")
        self.out_dir_input.setMinimumWidth(220)
        self.out_dir_input.setToolTip("Relative paths are resolved against the project folder.")
        self.out_dir_input.editingFinished.connect(self._emit_output_dir)
        self.btn_browse = QPushButton("Browse…")
        self.btn_browse.setProperty("class", "SecondaryButton")
        self.btn_browse.clicked.connect(self.browse_output_dir)
        header_layout.addWidget(dir_label)
        header_layout.addWidget(self.out_dir_input)
        header_layout.addWidget(self.btn_browse)

        layout.addWidget(header)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(3)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)

        # input pane
        input_pane = QWidget()
        input_pane.setObjectName("PaneContainer")
        input_layout = QVBoxLayout(input_pane)
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.setSpacing(0)

        input_header = QWidget()
        input_header.setObjectName("EditorPaneHeader")
        ih_layout = QHBoxLayout(input_header)
        ih_layout.setContentsMargins(16, 8, 16, 8)
        self.ih_title = QLabel("Input")
        self.btn_pick_file = QPushButton("Open File…")
        self.btn_pick_file.setProperty("class", "SecondaryButton")
        self.btn_pick_file.setToolTip("Open a Python, Java, C or C++ file (Ctrl+O). "
                                      "You can also drop a file on the editor.")
        self.btn_pick_file.clicked.connect(lambda: self.open_file())
        self.lang_combo = QComboBox()
        for key in LANGUAGE_KEYS:
            self.lang_combo.addItem(language_name(key), key)
        self.lang_combo.setToolTip("Language of the input. Set automatically when you open a file. "
                                   "Java, C and C++ get Javadoc / Doxygen comments and code insights; "
                                   "IR, pattern analysis, security scanning and the ML engines are Python-only.")
        self.lang_combo.currentIndexChanged.connect(lambda _i: self._apply_language())
        ih_layout.addWidget(self.ih_title)
        ih_layout.addStretch()
        lang_lbl = QLabel("Language:")
        lang_lbl.setProperty("class", "Caption")
        ih_layout.addWidget(lang_lbl)
        ih_layout.addWidget(self.lang_combo)
        ih_layout.addWidget(self.btn_pick_file)

        self.input_editor = CodeEditor()
        self.input_editor.setProperty("class", "CodeEditor")
        self.input_editor.setPlaceholderText(
            "Paste Python, Java, C or C++ code here, drop a source file, or use Open File…")
        self.input_highlighter = make_code_highlighter(self.input_editor.document(), "python")
        self.input_editor.fileDropped.connect(self.load_file)
        self.input_editor.textChanged.connect(self.input_editor.clear_marker)

        input_layout.addWidget(input_header)
        input_layout.addWidget(self.input_editor)

        # output pane
        output_pane = QWidget()
        output_pane.setObjectName("PaneContainer")
        output_layout = QVBoxLayout(output_pane)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.setSpacing(0)

        output_header = QWidget()
        output_header.setObjectName("EditorPaneHeader")
        oh_layout = QHBoxLayout(output_header)
        oh_layout.setContentsMargins(16, 8, 16, 8)
        oh_layout.setSpacing(8)
        self.oh_title = QLabel("Annotated Output")
        self.btn_diff = QPushButton("Highlight added lines")
        self.btn_diff.setProperty("class", "SecondaryButton")
        self.btn_diff.setCheckable(True)
        self.btn_diff.setChecked(True)
        self.btn_diff.toggled.connect(self._apply_diff)
        self.btn_copy = QPushButton("Copy")
        self.btn_copy.setProperty("class", "SecondaryButton")
        self.btn_copy.clicked.connect(self.copy_output)
        self.btn_save = QPushButton("Save As…")
        self.btn_save.setProperty("class", "SecondaryButton")
        self.btn_save.setToolTip("Save the annotated code to a file of your choice (Ctrl+S)")
        self.btn_save.clicked.connect(self.save_output)
        oh_layout.addWidget(self.oh_title)
        oh_layout.addStretch()
        for btn in (self.btn_diff, self.btn_copy, self.btn_save):
            oh_layout.addWidget(btn)

        self.error_banner = QLabel()
        self.error_banner.setWordWrap(True)
        self.error_banner.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.error_banner.setStyleSheet(
            f"background: {theme.rgba(theme.DANGER, 0.08)}; color: {theme.DANGER}; "
            f"padding: 10px 16px; font-size: 13px; font-weight: 600; "
            f"border-bottom: 1px solid {theme.rgba(theme.DANGER, 0.3)};")
        self.error_banner.hide()

        self.output_editor = CodeEditor(read_only=True)
        self.output_editor.setProperty("class", "DiffEditor")
        self.output_editor.setPlaceholderText("Annotated code will appear here…")
        self.output_highlighter = make_code_highlighter(self.output_editor.document(), "python")
        self._highlight_language = "python"

        output_layout.addWidget(output_header)
        output_layout.addWidget(self.error_banner)
        output_layout.addWidget(self.output_editor)

        self.splitter.addWidget(input_pane)
        self.splitter.addWidget(output_pane)
        layout.addWidget(self.splitter, stretch=1)

        self._set_output_actions_enabled(False)

    # ── language ──────────────────────────────────────────────────────────
    def selected_language(self) -> str:
        return self.lang_combo.currentData() or "python"

    def set_language(self, language: str):
        idx = self.lang_combo.findData(language)
        if idx >= 0:
            self.lang_combo.setCurrentIndex(idx)
        self._apply_language()

    def _apply_language(self):
        language = self.selected_language()
        if language == self._highlight_language:
            return
        self._highlight_language = language
        for attr, editor in (("input_highlighter", self.input_editor), ("output_highlighter", self.output_editor)):
            old = getattr(self, attr)
            old.setDocument(None)
            setattr(self, attr, make_code_highlighter(editor.document(), language))
        python = language == "python"
        for btn in (self.btn_neuro, self.btn_ml):
            if not python:
                btn.setToolTip("The ML model was trained on Python; other languages use rule-based comments.")
        if not python and not self.btn_rule.isChecked():
            self.btn_rule.setChecked(True)
        if python:
            self.refresh_engine_availability()
        else:
            self.btn_neuro.setEnabled(False)
            self.btn_ml.setEnabled(False)

    # ── engine selection ──────────────────────────────────────────────────
    def selected_engine(self) -> str:
        return ENGINES[max(0, self.engine_btn_group.checkedId())]

    def set_engine(self, engine: str):
        if engine in ENGINES:
            btn = self.engine_btn_group.button(ENGINES.index(engine))
            if btn.isEnabled():
                btn.setChecked(True)

    def refresh_engine_availability(self):
        """Enable the model-backed engines only when a checkpoint exists."""
        available = model_available() and self.selected_language() == "python"
        for btn, tip in ((self.btn_neuro, "Confidence-gated fusion of the ML summary and symbolic rules."),
                         (self.btn_ml, "Summary generated by the trained AST+NLP model.")):
            btn.setEnabled(available)
            btn.setToolTip(tip if available else _NO_MODEL_HINT)
        if not available and not self.btn_rule.isChecked():
            self.btn_rule.setChecked(True)

    def invalidate_model(self):
        """Drop the cached model (call after retraining) and re-check availability."""
        self._ast_model = None
        self.refresh_engine_availability()

    # ── files ─────────────────────────────────────────────────────────────
    def output_dir(self) -> str:
        return str(resolve_project_path(self.out_dir_input.text(), GUI_OUTPUT_DIR))

    def _emit_output_dir(self):
        self.outputDirChanged.emit(self.output_dir())

    def browse_output_dir(self):
        chosen = QFileDialog.getExistingDirectory(self, "Choose output folder", self.output_dir())
        if chosen:
            self.out_dir_input.setText(chosen)
            self._emit_output_dir()

    def open_file(self, path: Optional[str] = None):
        if not path:
            path, _ = QFileDialog.getOpenFileName(
                self, "Open source file", self._last_dir, file_dialog_filter())
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> bool:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            QMessageBox.warning(self, "Cannot open file", f"{path}\n\n{exc}")
            return False
        self.current_filepath = os.path.abspath(path)
        self._last_dir = os.path.dirname(self.current_filepath)
        self.set_language(detect_language(path, text))
        self.input_editor.setPlainText(text)
        self._update_input_title()
        return True

    def _update_input_title(self):
        if self.current_filepath:
            self.ih_title.setText(f"Input — {os.path.basename(self.current_filepath)}")
            self.ih_title.setToolTip(self.current_filepath)
        else:
            self.ih_title.setText("Input")
            self.ih_title.setToolTip("")

    def source_name(self) -> str:
        return pipeline_file_name(self.current_filepath, self.current_code(), self.selected_language())

    def current_code(self) -> str:
        return self.input_editor.toPlainText()

    def goto_line(self, line: int, tint=theme.JUMP_LINE_TINT) -> bool:
        ok = self.input_editor.goto_line(line, tint)
        self.input_editor.setFocus()
        return ok

    # ── output actions ────────────────────────────────────────────────────
    def _set_output_actions_enabled(self, enabled: bool):
        for btn in (self.btn_diff, self.btn_copy, self.btn_save):
            btn.setEnabled(enabled)

    def has_output(self) -> bool:
        return bool(self.output_editor.toPlainText())

    def copy_output(self):
        if self.has_output():
            QGuiApplication.clipboard().setText(self.output_editor.toPlainText())
            self.btn_copy.setText("Copied")
            QTimer.singleShot(1500, lambda: self.btn_copy.setText("Copy"))

    def save_output(self) -> Optional[str]:
        """Save the annotated code where the user chooses. Returns the path, or None."""
        if not self.has_output():
            return None
        stem, ext = os.path.splitext(self.source_name())
        start = os.path.join(self._last_dir or self.output_dir(), f"{stem}_annotated{ext}")
        path, _ = QFileDialog.getSaveFileName(self, "Save annotated code", start, file_dialog_filter())
        if not path:
            return None
        if self.current_filepath and os.path.abspath(path) == self.current_filepath:
            answer = QMessageBox.question(
                self, "Overwrite the input file?",
                f"{path}\n\nThis is the file you opened. Replace it with the annotated version?")
            if answer != QMessageBox.StandardButton.Yes:
                return None
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.output_editor.toPlainText())
        except OSError as exc:
            QMessageBox.warning(self, "Cannot save file", f"{path}\n\n{exc}")
            return None
        return path

    def _apply_diff(self, _checked=None):
        if self.btn_diff.isChecked() and self.has_output():
            self.output_editor.set_line_tints(
                added_lines(self._source_for_output, self.output_editor.toPlainText()))
        else:
            self.output_editor.clear_line_tints()

    # ── generation ────────────────────────────────────────────────────────
    def is_busy(self) -> bool:
        return self.worker is not None and self.worker.isRunning()

    def wait_for_worker(self, msecs: int = 15000) -> bool:
        return self.worker is None or self.worker.wait(msecs)

    def trigger_generation(self) -> bool:
        """
        Start a run.  Returns False (and starts nothing) when there is no code
        or a run is already in progress, so the caller never shows a busy state
        that nothing will clear.
        """
        if self.is_busy():
            return False
        code = self.current_code()
        if not code.strip():
            QMessageBox.warning(self, "No code", "Open a file or paste some code first.")
            return False

        self._steps = []
        self._source_for_output = code
        self.error_banner.hide()
        self.input_editor.clear_marker()
        self.output_editor.setPlainText("")
        self._set_output_actions_enabled(False)
        self.progress_bar.show()
        self.oh_title.setText("Annotated Output — generating…")
        self._emit_output_dir()

        self.worker = GeneratorWorker(code, self.selected_engine(), self.output_dir(),
                                      self.current_filepath, self._ast_model,
                                      language=self.selected_language())
        self.worker.progress.connect(self._on_worker_progress)
        self.worker.modelLoaded.connect(self._on_model_loaded)
        self.worker.succeeded.connect(self._on_succeeded)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()
        self.generationStarted.emit()
        return True

    def _on_model_loaded(self, model):
        self._ast_model = model

    def _on_worker_progress(self, msg: str):
        self._steps.append(msg)
        done = [f"  ✓ {s}" for s in self._steps[:-1]]
        self.output_editor.setPlaceholderText("\n".join(done + [f"  … {self._steps[-1]}"]))

    def _finish_run(self):
        self.progress_bar.hide()
        self.output_editor.setPlaceholderText("Annotated code will appear here…")

    def _on_succeeded(self, payload: dict):
        self._finish_run()
        result = payload["result"]
        self.last_output_file = payload["output_file"]
        self.output_editor.setPlainText(payload["annotated"])
        self._set_output_actions_enabled(True)
        self._apply_diff()
        n_added = len(added_lines(self._source_for_output, payload["annotated"]))
        self.oh_title.setText(f"Annotated Output — {len(result.comments)} comments, "
                              f"{n_added} lines added")
        self.oh_title.setToolTip(f"Saved to {self.last_output_file}")
        self.generationFinished.emit(True, {
            "mf": result.module_features,
            "cg": result.context_graph,
            "ir": result.ir_module,
            "analysis": result.analysis_report,
            "security_report": result.security_report,
            "output_file": self.last_output_file,
            "comments": len(result.comments),
            "language": getattr(result, "language", "python"),
        })

    def _on_failed(self, error: dict):
        self._finish_run()
        self.oh_title.setText("Annotated Output — failed")
        self.oh_title.setToolTip("")
        message = error.get("message") or "Generation failed."
        if error.get("line"):
            self.goto_line(error["line"], theme.ERROR_LINE_TINT)
            message += "  The line is highlighted in the input."
        if error.get("detail"):
            # Full traceback goes to the console pane, not into a code view.
            print(error["detail"], file=sys.stderr)
            message += "  Full details are in the console below."
        self.error_banner.setText(message)
        self.error_banner.show()
        # The badge described the previous run's code, not this one.
        self.update_unsafe_pct(None, analysed=False)
        self.generationFinished.emit(False, error)

    # ── security badge ────────────────────────────────────────────────────
    def update_unsafe_pct(self, security_report, analysed: bool = True, language: str = "python"):
        if language != "python":
            self.unsafe_label.setText("Security: Python only")
            self.unsafe_label.setToolTip(f"Security scanning is not available for {language_name(language)} yet.")
            self.unsafe_label.setStyleSheet(theme.badge_style(theme.TEXT_MUTED, filled=False))
            return
        if security_report is None or not analysed:
            self.unsafe_label.setText("Security: not analysed")
            self.unsafe_label.setToolTip("Generate comments or run a scan in the Security tab.")
            self.unsafe_label.setStyleSheet(theme.badge_style(theme.TEXT_MUTED, filled=False))
            return
        if getattr(security_report, "parse_error", None):
            self.unsafe_label.setText("Security: could not parse")
            self.unsafe_label.setStyleSheet(theme.badge_style(theme.DANGER))
            return
        unsafe_pct = round(100.0 - security_report.module_safe_pct, 1)
        issues = security_report.total_issues
        if unsafe_pct > 20:
            color = theme.DANGER
        elif unsafe_pct > 0 or issues:
            color = theme.WARNING
        else:
            color = theme.SUCCESS
        self.unsafe_label.setText(f"{unsafe_pct:g}% unsafe · {issues} issue{'s' if issues != 1 else ''}")
        self.unsafe_label.setToolTip("Share of functions scoring below 80 on the security analysis.")
        self.unsafe_label.setStyleSheet(theme.badge_style(color))

    # ── persisted state ───────────────────────────────────────────────────
    def save_settings(self, settings):
        settings.setValue("generator/engine", self.selected_engine())
        settings.setValue("generator/language", self.selected_language())
        settings.setValue("generator/output_dir", self.out_dir_input.text())
        settings.setValue("generator/last_dir", self._last_dir)
        settings.setValue("generator/splitter", self.splitter.saveState())
        settings.setValue("generator/highlight_added", self.btn_diff.isChecked())

    def restore_settings(self, settings):
        self.set_engine(str(settings.value("generator/engine", "") or ""))
        self.set_language(str(settings.value("generator/language", "python") or "python"))
        out_dir = settings.value("generator/output_dir", "")
        if out_dir:
            self.out_dir_input.setText(str(out_dir))
        self._last_dir = str(settings.value("generator/last_dir", "") or "")
        state = settings.value("generator/splitter")
        if state is not None:
            self.splitter.restoreState(state)
        self.btn_diff.setChecked(str(settings.value("generator/highlight_added", "true")).lower() != "false")
