from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QSplitter, QTextEdit, QLineEdit, QRadioButton,
                             QFileDialog, QButtonGroup, QMessageBox, QProgressBar,
                             QGraphicsOpacityEffect)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer, QPropertyAnimation
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QTextCursor, QSyntaxHighlighter
import sys
import os
import traceback

from src.main import run_pipeline
from src.logger import PipelineLogger
from src.gui.syntax_highlighter import PythonSyntaxHighlighter
from src.config import OUTPUT_DIR
from src.ml.trainer import load_ast_model

_SPINNER_FRAMES = ["\u28f7", "\u28ef", "\u28df", "\u28dd", "\u28d9", "\u28d1",
                   "\u28c1", "\u2881", "\u2882", "\u2884", "\u2888", "\u2890",
                   "\u28a0", "\u28e0", "\u28f0", "\u28f8"]


class GeneratorWorker(QThread):
    finished = pyqtSignal(str, str, object)
    status = pyqtSignal(str)

    def __init__(self, code_text, engine, output_dir):
        super().__init__()
        self.code_text = code_text
        self.engine = engine
        self.output_dir = output_dir

    def run(self):
        try:
            self.status.emit("Setting up temporary files...")
            os.makedirs(self.output_dir, exist_ok=True)
            tmp_in = os.path.join(self.output_dir, "gui_tmp_in.py")
            with open(tmp_in, 'w', encoding='utf-8') as f:
                f.write(self.code_text)

            logger = PipelineLogger(input_file=tmp_in)

            ast_model = None
            if self.engine in ("ml", "neurosymbolic"):
                self.status.emit("Loading AST+NLP ML model...")
                try:
                    ast_model = load_ast_model(output_dir=str(OUTPUT_DIR))
                    if ast_model is None:
                        raise RuntimeError(
                            "No trained AST+NLP model found. "
                            "Train first from ML Training tab or run: python3 -m src.main --train"
                        )
                except Exception as e:
                    raise RuntimeError(f"Failed to start ML mode: {e}") from e

            self.status.emit("Running pipeline...")
            annotated, comments, mf, cg, attach_result, ir_module, analysis_report, security_report = \
                run_pipeline(tmp_in, logger, ast_model=ast_model,
                             strict_ml=(self.engine in ("ml", "neurosymbolic")),
                             engine=self.engine)

            out_file = os.path.join(self.output_dir, "gui_annotated.py")
            with open(out_file, 'w', encoding='utf-8') as f:
                f.write(annotated)

            self.status.emit("Saving logs...")
            logger.set_output_file(out_file)
            logger.save(os.path.join(self.output_dir, "logs"))

            results_dict = {
                "mf": mf,
                "cg": cg,
                "ir": ir_module,
                "analysis": analysis_report,
                "security_report": security_report,
            }
            self.finished.emit("Success", annotated, results_dict)
        except Exception as e:
            err = traceback.format_exc()
            self.finished.emit(f"Error: {e}\n\n{err}", "", None)


class GeneratorWorkspace(QWidget):
    generationStarted = pyqtSignal()
    generationFinished = pyqtSignal(str, str, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_filepath = None
        self._is_generating = False
        self._step_spinner_frame = 0
        self._step_spinner_timer = QTimer(self)
        self._step_spinner_timer.setInterval(80)
        self._step_spinner_timer.timeout.connect(self._tick_step_spinner)
        self._current_step_line = None
        self._completed_steps = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QWidget()
        header.setObjectName("WorkspaceHeader")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 12, 16, 12)

        engine_group = QWidget()
        engine_layout = QHBoxLayout(engine_group)
        engine_layout.setContentsMargins(4, 4, 4, 4)
        engine_layout.setSpacing(8)

        self.btn_rule = QRadioButton("Rule-Based")
        self.btn_neuro = QRadioButton("Neurosymbolic")
        self.btn_ml = QRadioButton("ML-Based")
        self.btn_neuro.setChecked(True)

        self.engine_btn_group = QButtonGroup(self)
        self.engine_btn_group.addButton(self.btn_rule, 1)
        self.engine_btn_group.addButton(self.btn_neuro, 2)
        self.engine_btn_group.addButton(self.btn_ml, 3)

        engine_layout.addWidget(self.btn_rule)
        engine_layout.addWidget(self.btn_neuro)
        engine_layout.addWidget(self.btn_ml)

        header_layout.addWidget(engine_group)
        header_layout.addStretch()

        self.unsafe_label = QLabel("0% unsafe")
        self.unsafe_label.setStyleSheet(
            "color: #16a34a; font-weight: bold; font-size: 13px; "
            "padding: 4px 10px; background: rgba(22,163,74,0.08); border-radius: 6px;"
        )
        header_layout.addWidget(self.unsafe_label)

        dir_layout = QHBoxLayout()
        dir_label = QLabel("Output Dir:")
        dir_label.setStyleSheet("color: #495057; font-weight: 500; font-size: 14px;")

        self.out_dir_input = QLineEdit("./out/annotated")
        self.out_dir_input.setProperty("class", "DirInput")
        self.out_dir_input.setMinimumWidth(250)

        dir_layout.addWidget(dir_label)
        dir_layout.addWidget(self.out_dir_input)
        header_layout.addLayout(dir_layout)

        layout.addWidget(header)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(3)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)

        input_pane = QWidget()
        input_pane.setObjectName("PaneContainer")
        input_layout = QVBoxLayout(input_pane)
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.setSpacing(0)

        input_header = QWidget()
        input_header.setObjectName("EditorPaneHeader")
        ih_layout = QHBoxLayout(input_header)
        ih_layout.setContentsMargins(16, 8, 16, 8)
        ih_title = QLabel("Input Python Code")
        self.btn_pick_file = QPushButton("Pick File")
        self.btn_pick_file.setProperty("class", "SecondaryButton")
        self.btn_pick_file.clicked.connect(self.pick_file)
        ih_layout.addWidget(ih_title)
        ih_layout.addStretch()
        ih_layout.addWidget(self.btn_pick_file)

        self.input_editor = QTextEdit()
        self.input_editor.setProperty("class", "CodeEditor")
        self.input_editor.setPlaceholderText("Paste Python code here, or Pick File...")
        self.input_highlighter = PythonSyntaxHighlighter(self.input_editor.document())

        input_layout.addWidget(input_header)
        input_layout.addWidget(self.input_editor)

        output_pane = QWidget()
        output_pane.setObjectName("PaneContainer")
        output_layout = QVBoxLayout(output_pane)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.setSpacing(0)

        output_header = QWidget()
        output_header.setObjectName("EditorPaneHeader")
        oh_layout = QHBoxLayout(output_header)
        oh_layout.setContentsMargins(16, 8, 16, 8)
        self.oh_title = QLabel("Annotated Output")
        oh_layout.addWidget(self.oh_title)
        oh_layout.addStretch()

        self.output_editor = QTextEdit()
        self.output_editor.setProperty("class", "DiffEditor")
        self.output_editor.setReadOnly(True)
        self.output_editor.setPlaceholderText("Annotated code will appear here...")
        self.output_highlighter = PythonSyntaxHighlighter(self.output_editor.document())

        output_layout.addWidget(output_header)
        output_layout.addWidget(self.output_editor)

        self.splitter.addWidget(input_pane)
        self.splitter.addWidget(output_pane)

        self.splitter.setStyleSheet("QSplitter::handle { background-color: #e0e4e8; }")

        layout.addWidget(self.splitter, stretch=1)

    def pick_file(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select Python File", "", "Python Files (*.py);;All Files (*)"
        )
        if filepath:
            self.current_filepath = filepath
            with open(filepath, 'r', encoding='utf-8') as f:
                self.input_editor.setPlainText(f.read())

    def trigger_generation(self):
        code = self.input_editor.toPlainText().strip()
        if not code:
            QMessageBox.warning(self, "No Code", "Please pick a file or paste some code.")
            return

        if self.btn_neuro.isChecked():
            engine = "neurosymbolic"
        elif self.btn_ml.isChecked():
            engine = "ml"
        else:
            engine = "rule_based"

        self._is_generating = True
        self._completed_steps = []
        self._current_step_line = None
        self.progress_bar.show()
        self.output_editor.clear()
        self.output_editor.setPlaceholderText("")

        self.oh_title.setText("Annotated Output \u2014 Generating...")

        self.worker = GeneratorWorker(code, engine, self.out_dir_input.text().strip())
        self.worker.status.connect(self._on_worker_status)
        self.worker.finished.connect(self.on_generation_finished)
        self.worker.start()

        self.generationStarted.emit()
        self._step_spinner_timer.start()

    def _on_worker_status(self, msg):
        if self._current_step_line is not None:
            self._completed_steps.append(self._current_step_line)
            self._rewrite_progress()

        self._current_step_line = msg
        self._step_spinner_frame = 0
        self._rewrite_progress()

    def _rewrite_progress(self):
        cursor = self.output_editor.textCursor()
        cursor.select(QTextCursor.SelectionType.Document)
        cursor.removeSelectedText()

        fmt_done = QTextCharFormat()
        fmt_done.setForeground(QColor("#16a34a"))
        fmt_done.setFontWeight(QFont.Weight.Normal)

        fmt_active = QTextCharFormat()
        fmt_active.setForeground(QColor("#2563eb"))
        fmt_active.setFontWeight(QFont.Weight.Bold)

        fmt_label = QTextCharFormat()
        fmt_label.setForeground(QColor("#9ca3af"))
        fmt_label.setFontWeight(QFont.Weight.Normal)

        for step in self._completed_steps:
            cursor.setCharFormat(fmt_label)
            cursor.insertText("  ")
            cursor.setCharFormat(fmt_done)
            cursor.insertText("\u2713 ")
            cursor.setCharFormat(fmt_label)
            cursor.insertText(f"{step}\n")

        if self._current_step_line:
            spinner_char = _SPINNER_FRAMES[self._step_spinner_frame % len(_SPINNER_FRAMES)]
            cursor.setCharFormat(fmt_label)
            cursor.insertText("  ")
            cursor.setCharFormat(fmt_active)
            cursor.insertText(f"{spinner_char} ")
            cursor.setCharFormat(fmt_label)
            cursor.insertText(f"{self._current_step_line}")

    def _tick_step_spinner(self):
        self._step_spinner_frame += 1
        if self._current_step_line:
            self._rewrite_progress()

    def on_generation_finished(self, status, code, results_dict):
        self._is_generating = False
        self._step_spinner_timer.stop()
        self.progress_bar.hide()

        if self._current_step_line is not None:
            self._completed_steps.append(self._current_step_line)
            self._current_step_line = None

        if status == "Success":
            self.output_editor.setPlainText(code)
            self.oh_title.setText("Annotated Output")
            self.generationFinished.emit("Generation Completed", "", results_dict)
        else:
            cursor = self.output_editor.textCursor()
            cursor.select(QTextCursor.SelectionType.Document)
            cursor.removeSelectedText()

            fmt_done = QTextCharFormat()
            fmt_done.setForeground(QColor("#16a34a"))
            fmt_err = QTextCharFormat()
            fmt_err.setForeground(QColor("#dc2626"))
            fmt_err.setFontWeight(QFont.Weight.Bold)
            fmt_label = QTextCharFormat()
            fmt_label.setForeground(QColor("#9ca3af"))

            for step in self._completed_steps:
                cursor.setCharFormat(fmt_label)
                cursor.insertText("  ")
                cursor.setCharFormat(fmt_done)
                cursor.insertText("\u2713 ")
                cursor.setCharFormat(fmt_label)
                cursor.insertText(f"{step}\n")

            cursor.setCharFormat(fmt_label)
            cursor.insertText("  ")
            cursor.setCharFormat(fmt_err)
            cursor.insertText("\u2717 Generation failed\n\n")
            cursor.setCharFormat(fmt_err)
            cursor.insertText(status)

            self.oh_title.setText("Annotated Output \u2014 Failed")
            self.generationFinished.emit("Generation Failed", "", None)

    def update_annotated_code(self, code):
        self.output_editor.setPlainText(code)

    def update_unsafe_pct(self, security_report):
        if security_report is None:
            self.unsafe_label.setText("N/A")
            self.unsafe_label.setStyleSheet(
                "color: #6c757d; font-weight: bold; font-size: 13px; "
                "padding: 4px 10px; border-radius: 6px;"
            )
            return
        unsafe_pct = round(100.0 - security_report.module_safe_pct, 1)
        if unsafe_pct > 20:
            color = "#dc2626"
            bg = "rgba(220,38,38,0.08)"
        elif unsafe_pct > 0:
            color = "#ca8a04"
            bg = "rgba(202,138,4,0.08)"
        else:
            color = "#16a34a"
            bg = "rgba(22,163,74,0.08)"
        self.unsafe_label.setText(f"{unsafe_pct}% unsafe")
        self.unsafe_label.setStyleSheet(
            f"color: {color}; font-weight: bold; font-size: 13px; "
            f"padding: 4px 10px; background: {bg}; border-radius: 6px;"
        )
