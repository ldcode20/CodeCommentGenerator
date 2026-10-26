import sys
import traceback
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QTextEdit, QScrollArea, QFrame, QProgressBar)
from PyQt6.QtCore import pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QColor, QTextCharFormat, QTextCursor, QFont
import json

from src.config import OUTPUT_DIR
from src.ml.trainer import train_and_evaluate
from src.gui.widgets import SpinningButton


class TrainerWorker(QThread):
    status = pyqtSignal(str)
    finished = pyqtSignal(object)

    def run(self):
        try:
            self.status.emit("Starting AST+NLP training pipeline...")
            # Must match where GeneratorWorkspace loads the model from —
            # training into a separate directory is why GUI training never
            # cleared the "No trained AST+NLP model found" error.
            result = train_and_evaluate(
                output_dir=str(OUTPUT_DIR),
                verbose=True
            )
            self.status.emit("Training completed successfully!")
            self.finished.emit(result)
        except Exception as e:
            err = traceback.format_exc()
            self.status.emit(f"Error during training:\n{err}")
            self.finished.emit({"error": str(e), "trace": err})


class MLTrainingWorkspace(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header_layout = QHBoxLayout()
        title = QLabel("ML Training Dashboard")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #1a1a2e;")
        header_layout.addWidget(title)

        self.btn_train = SpinningButton("Start / Retrain Models")
        self.btn_train.setProperty("class", "PrimaryButton")
        self.btn_train.setMinimumHeight(35)
        self.btn_train.clicked.connect(self.start_training)
        header_layout.addStretch()
        header_layout.addWidget(self.btn_train)

        layout.addLayout(header_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(3)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        self.status_lbl = QLabel("Ready to train models.")
        self.status_lbl.setStyleSheet("color: #6c757d; font-size: 13px;")
        layout.addWidget(self.status_lbl)

        self.results_area = QTextEdit()
        self.results_area.setProperty("class", "CodeEditor")
        self.results_area.setReadOnly(True)
        self.results_area.setPlaceholderText("Training reports will appear here...")

        layout.addWidget(self.results_area)

    def start_training(self):
        if self.btn_train.is_spinning():
            return
        self.btn_train.start_spinning("Training...")
        self.progress_bar.show()
        self.status_lbl.setText("Running training pipeline...")
        self.status_lbl.setStyleSheet("color: #2563eb; font-size: 13px; font-weight: 600;")
        self.results_area.clear()

        self.worker = TrainerWorker()
        self.worker.status.connect(self.update_status)
        self.worker.finished.connect(self.on_training_finished)
        self.worker.start()

    def update_status(self, msg):
        self.status_lbl.setText(msg)
        cursor = self.results_area.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        fmt = QTextCharFormat()
        if "error" in msg.lower() or "fail" in msg.lower():
            fmt.setForeground(QColor("#dc2626"))
        elif "completed" in msg.lower() or "success" in msg.lower():
            fmt.setForeground(QColor("#16a34a"))
        else:
            fmt.setForeground(QColor("#495057"))

        cursor.setCharFormat(fmt)
        cursor.insertText(msg + "\n")

    def on_training_finished(self, result):
        self.btn_train.stop_spinning()
        self.progress_bar.hide()

        if "error" in result:
            self.status_lbl.setText("Training failed \u2014 check details below")
            self.status_lbl.setStyleSheet("color: #dc2626; font-size: 13px; font-weight: 600;")
            return

        self.status_lbl.setText("\u2713 Training completed successfully")
        self.status_lbl.setStyleSheet("color: #16a34a; font-size: 13px; font-weight: 600;")

        QTimer.singleShot(8000, self._reset_status_style)

        tr = result.get("training_report", {})
        ev = result.get("eval_report", {})

        report_text = f"""
======================================
  AST+NLP TRAINING COMPLETED
======================================
Dataset Total Samples  : {tr.get('dataset_total', 0)}
Training Samples (Seed): {tr.get('train_size', 0)}
Testing Samples (Seed) : {tr.get('test_size', 0)}

AST+NLP Pair Count      : {tr.get('data_profile', {}).get('ast_nlp_pairs', tr.get('dataset_total', 0))} pairs

EVALUATION METRICS
--------------------------------------
"""
        summary = ev.get('summary', {})
        report_text += f"Best BLEU-4 Score : {summary.get('best_bleu4', 0):.4f}\n"
        report_text += f"Best ROUGE-L Score: {summary.get('best_rouge_l', 0):.4f}\n"
        report_text += f"Exact Match Rate  : {summary.get('best_exact_match', 0):.4f}\n\n"

        report_text += "----- FULL JSON REPORTS -----\n"
        report_text += json.dumps(result, indent=2)

        self.results_area.setPlainText(report_text)

    def _reset_status_style(self):
        self.status_lbl.setText("Ready to train models.")
        self.status_lbl.setStyleSheet("color: #6c757d; font-size: 13px;")
