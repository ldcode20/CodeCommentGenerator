"""
ML Training workspace — choose a preset, watch progress, cancel safely.
"""
import json
import threading
import traceback
from datetime import datetime
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QColor, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel,
                             QProgressBar, QPushButton, QSpinBox, QTextEdit, QVBoxLayout,
                             QWidget)

from src.config import AST_MODEL_DIR, DATASET_JSON, EVAL_REPORT, OUTPUT_DIR, TRAINING_REPORT
from src.gui import theme
from src.gui.widgets import SpinningButton

# name -> (epochs, batch size, CodeSearchNet samples, stdlib files, description)
PRESETS = {
    "Quick check": (1, 8, 2000, 200,
                    "A few minutes. Proves the pipeline works; the model is not good enough for real output."),
    "Standard": (3, 8, 8000, 600,
                 "A medium-quality run. Roughly an hour on a mid-range GPU, much longer on CPU."),
    "Full": (4, 8, 20000, 1500,
             "The full default corpus. A multi-hour job even on a GPU."),
}
CUSTOM = "Custom"
_STAGE_TEXT = {
    "dataset": "Building the dataset (cannot be interrupted)…",
    "train": "Fine-tuning…",
    "evaluate": "Evaluating on the held-out split…",
    "save": "Saving the model…",
}


def _read_json(path) -> Optional[dict]:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


class TrainerWorker(QThread):
    status = pyqtSignal(str)
    progress = pyqtSignal(str, int, int, str)     # stage, done, total, message
    finished_ok = pyqtSignal(object)
    cancelled = pyqtSignal()
    failed = pyqtSignal(str, str)                 # message, traceback

    def __init__(self, params: dict):
        super().__init__()
        self.params = params
        self._stop = threading.Event()

    def request_stop(self):
        self._stop.set()

    def run(self):
        try:
            # Imported here so opening the window does not pay for torch.
            from src.ml.trainer import TrainingCancelled, train_and_evaluate
        except Exception as exc:
            self.failed.emit(f"Could not import the training code: {exc}", traceback.format_exc())
            return
        try:
            self.status.emit("Starting AST+NLP training pipeline…")
            # Must be the directory the Generator loads the model from.
            result = train_and_evaluate(
                output_dir=str(OUTPUT_DIR),
                verbose=True,
                progress_callback=self.progress.emit,
                should_stop=self._stop.is_set,
                **self.params,
            )
            self.finished_ok.emit(result)
        except TrainingCancelled:
            self.cancelled.emit()
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}", traceback.format_exc())


class MLTrainingWorkspace(QWidget):
    #: A new checkpoint was saved — the Generator must drop its cached model.
    modelUpdated = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: Optional[TrainerWorker] = None
        self._applying_preset = False
        self.setup_ui()
        self.refresh_model_status()

    # ── UI ────────────────────────────────────────────────────────────────
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        header_layout = QHBoxLayout()
        title = QLabel("ML Training")
        title.setProperty("class", "PageTitle")
        header_layout.addWidget(title)
        header_layout.addStretch()
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setProperty("class", "DangerButton")
        self.btn_cancel.setMinimumHeight(35)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel_training)
        self.btn_train = SpinningButton("Start Training")
        self.btn_train.setProperty("class", "PrimaryButton")
        self.btn_train.setMinimumHeight(35)
        self.btn_train.clicked.connect(self.start_training)
        header_layout.addWidget(self.btn_cancel)
        header_layout.addWidget(self.btn_train)
        layout.addLayout(header_layout)

        # current model card
        self.model_card = QFrame()
        self.model_card.setProperty("class", "Card")
        card_layout = QVBoxLayout(self.model_card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(4)
        self.model_title = QLabel()
        self.model_title.setStyleSheet("font-size: 14px; font-weight: bold; border: none;")
        self.model_detail = QLabel()
        self.model_detail.setWordWrap(True)
        self.model_detail.setStyleSheet(f"font-size: 13px; color: {theme.TEXT_SECONDARY}; border: none;")
        card_layout.addWidget(self.model_title)
        card_layout.addWidget(self.model_detail)
        layout.addWidget(self.model_card)

        # options card
        options = QFrame()
        options.setProperty("class", "Card")
        grid = QGridLayout(options)
        grid.setContentsMargins(16, 12, 16, 12)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        def caption(text):
            lbl = QLabel(text)
            lbl.setStyleSheet(f"font-size: 12px; color: {theme.TEXT_MUTED}; border: none;")
            return lbl

        self.preset_combo = QComboBox()
        self.preset_combo.addItems(list(PRESETS) + [CUSTOM])
        self.preset_combo.currentTextChanged.connect(self._apply_preset)

        def spin(lo, hi, step=1):
            box = QSpinBox()
            box.setRange(lo, hi)
            box.setSingleStep(step)
            box.setGroupSeparatorShown(True)
            box.valueChanged.connect(self._on_value_edited)
            return box

        self.spin_epochs = spin(1, 50)
        self.spin_batch = spin(1, 128)
        self.spin_csn = spin(0, 500000, 1000)
        self.spin_csn.setToolTip("CodeSearchNet functions to download (0 = skip CodeSearchNet).")
        self.spin_stdlib = spin(0, 20000, 100)
        self.spin_stdlib.setToolTip("Python standard-library files to mine (0 = skip).")

        for col, (text, widget) in enumerate((
                ("Preset", self.preset_combo), ("Epochs", self.spin_epochs),
                ("Batch size", self.spin_batch), ("CodeSearchNet samples", self.spin_csn),
                ("Stdlib files", self.spin_stdlib))):
            grid.addWidget(caption(text), 0, col)
            grid.addWidget(widget, 1, col)
        grid.setColumnStretch(5, 1)

        self.chk_reuse = QCheckBox("Reuse the saved dataset (skips the download and rebuild)")
        self.chk_reuse.toggled.connect(self._on_reuse_toggled)
        grid.addWidget(self.chk_reuse, 2, 0, 1, 6)
        self.preset_note = caption("")
        self.preset_note.setWordWrap(True)
        grid.addWidget(self.preset_note, 3, 0, 1, 6)
        layout.addWidget(options)
        self._options = options

        # progress
        self.status_lbl = QLabel("Ready to train.")
        self.status_lbl.setStyleSheet(f"color: {theme.TEXT_MUTED}; font-size: 13px;")
        layout.addWidget(self.status_lbl)
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        self.results_area = QTextEdit()
        self.results_area.setProperty("class", "CodeEditor")
        self.results_area.setReadOnly(True)
        self.results_area.setPlaceholderText(
            "The training report appears here. Detailed progress is printed in the console below.")
        layout.addWidget(self.results_area, stretch=1)

        self._apply_preset(self.preset_combo.currentText())

    # ── options ───────────────────────────────────────────────────────────
    def _apply_preset(self, name: str):
        if name in PRESETS:
            epochs, batch, csn, stdlib, note = PRESETS[name]
            self._applying_preset = True
            self.spin_epochs.setValue(epochs)
            self.spin_batch.setValue(batch)
            self.spin_csn.setValue(csn)
            self.spin_stdlib.setValue(stdlib)
            self._applying_preset = False
            self.preset_note.setText(note)
        else:
            self.preset_note.setText("Custom settings. On 'CUDA out of memory', halve the batch size.")

    def _on_value_edited(self, _value):
        if not self._applying_preset and self.preset_combo.currentText() != CUSTOM:
            self.preset_combo.blockSignals(True)
            self.preset_combo.setCurrentText(CUSTOM)
            self.preset_combo.blockSignals(False)
            self._apply_preset(CUSTOM)

    def _on_reuse_toggled(self, checked: bool):
        self.spin_csn.setEnabled(not checked)
        self.spin_stdlib.setEnabled(not checked)

    def training_params(self) -> dict:
        """Keyword arguments for ``train_and_evaluate`` from the current options."""
        params = {
            "epochs": self.spin_epochs.value(),
            "batch_size": self.spin_batch.value(),
            "codesearchnet_max": self.spin_csn.value(),
            "max_stdlib_files": self.spin_stdlib.value(),
            "include_codesearchnet": self.spin_csn.value() > 0,
            "include_stdlib": self.spin_stdlib.value() > 0,
        }
        if self.chk_reuse.isChecked() and DATASET_JSON.exists():
            params["dataset_json"] = str(DATASET_JSON)
        return params

    # ── current model ─────────────────────────────────────────────────────
    def refresh_model_status(self):
        has_dataset = DATASET_JSON.exists()
        self.chk_reuse.setEnabled(has_dataset)
        if not has_dataset:
            self.chk_reuse.setChecked(False)
            self.chk_reuse.setToolTip("No saved dataset yet — the first run builds one.")
        else:
            self.chk_reuse.setToolTip(str(DATASET_JSON))

        config = AST_MODEL_DIR / "config.json"
        if not config.exists():
            self.model_title.setText("No trained model yet")
            self.model_title.setStyleSheet(
                f"font-size: 14px; font-weight: bold; color: {theme.WARNING}; border: none;")
            self.model_detail.setText(
                "The ML-Based and Neurosymbolic engines are disabled until a model is trained. "
                "Start with the Quick check preset to confirm everything works.")
            return

        self.model_title.setText("Trained model available")
        self.model_title.setStyleSheet(
            f"font-size: 14px; font-weight: bold; color: {theme.SUCCESS}; border: none;")
        report = _read_json(TRAINING_REPORT) or {}
        summary = (_read_json(EVAL_REPORT) or {}).get("summary", {})
        when = report.get("trained_at")
        if not when:
            when = datetime.fromtimestamp(config.stat().st_mtime).isoformat(timespec="minutes")
        parts = [f"Saved {str(when).replace('T', ' ')}"]
        if report.get("dataset_total"):
            profile = report.get("training_profile", {})
            parts.append(f"{report['dataset_total']:,} pairs, {profile.get('epochs', '?')} epoch(s)")
        if summary:
            parts.append(f"BLEU-4 {summary.get('bleu4_mean', 0):.3f} · "
                         f"ROUGE-L {summary.get('rouge_l_mean', 0):.3f} · "
                         f"exact match {summary.get('exact_match_rate', 0):.1%}")
        self.model_detail.setText("   |   ".join(parts))

    # ── run ───────────────────────────────────────────────────────────────
    def is_busy(self) -> bool:
        return self.worker is not None and self.worker.isRunning()

    def wait_for_worker(self, msecs: int = 15000) -> bool:
        return self.worker is None or self.worker.wait(msecs)

    def _set_status(self, text: str, color: str = theme.TEXT_MUTED, bold: bool = False):
        self.status_lbl.setText(text)
        self.status_lbl.setStyleSheet(
            f"color: {color}; font-size: 13px;" + (" font-weight: 600;" if bold else ""))

    def _set_running(self, running: bool):
        self._options.setEnabled(not running)
        self.btn_cancel.setEnabled(running)
        self.btn_cancel.setText("Cancel")
        if running:
            self.btn_train.start_spinning("Training…")
            self.progress_bar.setRange(0, 0)
            self.progress_bar.show()
        else:
            self.btn_train.stop_spinning()
            self.progress_bar.hide()

    def start_training(self):
        if self.is_busy():
            return
        self.results_area.clear()
        self._set_running(True)
        self._set_status("Starting…", theme.ACCENT, bold=True)
        self.worker = TrainerWorker(self.training_params())
        self.worker.status.connect(self._log_line)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished_ok.connect(self._on_finished)
        self.worker.cancelled.connect(self._on_cancelled)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()

    def cancel_training(self):
        if self.is_busy():
            self.worker.request_stop()
            self.btn_cancel.setEnabled(False)
            self.btn_cancel.setText("Cancelling…")
            self._set_status("Cancelling — waiting for the current step to finish…",
                             theme.WARNING, bold=True)

    def _log_line(self, msg: str, color: str = theme.TEXT_SECONDARY):
        cursor = self.results_area.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(msg + "\n")

    def _on_progress(self, stage: str, done: int, total: int, message: str):
        if self.worker is not None and self.worker._stop.is_set():
            return  # keep the "Cancelling…" text
        if total > 0:
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(done)
            pct = 100.0 * done / total
            self._set_status(f"{_STAGE_TEXT.get(stage, stage)}  {pct:.0f}%  ({message})",
                             theme.ACCENT, bold=True)
        else:
            self.progress_bar.setRange(0, 0)
            self._set_status(_STAGE_TEXT.get(stage, message or stage), theme.ACCENT, bold=True)

    def _on_cancelled(self):
        self._set_running(False)
        self._set_status("Training cancelled. The previous model, if any, was left untouched.",
                         theme.WARNING, bold=True)
        self._log_line("Training cancelled.", theme.WARNING)

    def _on_failed(self, message: str, trace: str):
        self._set_running(False)
        self._set_status("Training failed — details below.", theme.DANGER, bold=True)
        self._log_line(message, theme.DANGER)
        self._log_line(trace, theme.TEXT_MUTED)

    def _on_finished(self, result: dict):
        self._set_running(False)
        tr = result.get("training_report", {})
        ev = result.get("eval_report", {})
        # train_and_evaluate reports a fine-tuning error in the report instead
        # of raising; treat that as a failure, not as a completed run.
        model_error = tr.get("ast_model", {}).get("error")
        if model_error:
            self._set_status("Training failed — no model was saved. Details below.",
                             theme.DANGER, bold=True)
            self._log_line(f"Fine-tuning error: {model_error}", theme.DANGER)
            self.refresh_model_status()
            return

        self._set_status("✓ Training completed — the new model is in use.", theme.SUCCESS, bold=True)
        summary = ev.get("summary", {})
        meta = tr.get("ast_model", {})
        report_text = "\n".join([
            "AST+NLP TRAINING COMPLETED",
            "=" * 38,
            f"Dataset pairs      : {tr.get('dataset_total', 0):,}",
            f"Train / test       : {tr.get('train_size', 0):,} / {tr.get('test_size', 0):,}",
            f"Epochs (best)      : {meta.get('epochs', '?')} ({meta.get('best_epoch', '?')})",
            f"Device / precision : {meta.get('device', '?')} / {meta.get('mixed_precision', '?')}",
            "",
            "EVALUATION (held-out split)",
            "-" * 38,
            f"BLEU-4      : {summary.get('bleu4_mean', 0):.4f}",
            f"ROUGE-L     : {summary.get('rouge_l_mean', 0):.4f}",
            f"Exact match : {summary.get('exact_match_rate', 0):.4f}",
            "",
            "TRAINING REPORT (JSON)",
            "-" * 38,
            json.dumps(tr, indent=2),
            "",
            "Per-function evaluation is in outputs/eval_report.json (Logs tab).",
        ])
        self.results_area.setPlainText(report_text)
        self.refresh_model_status()
        self.modelUpdated.emit()

    # ── persisted state ───────────────────────────────────────────────────
    def save_settings(self, settings):
        settings.setValue("training/preset", self.preset_combo.currentText())
        settings.setValue("training/epochs", self.spin_epochs.value())
        settings.setValue("training/batch", self.spin_batch.value())
        settings.setValue("training/csn", self.spin_csn.value())
        settings.setValue("training/stdlib", self.spin_stdlib.value())

    def restore_settings(self, settings):
        preset = str(settings.value("training/preset", "") or "")
        if preset in PRESETS:
            self.preset_combo.setCurrentText(preset)
        elif preset == CUSTOM:
            try:
                values = [int(settings.value(f"training/{k}")) for k in ("epochs", "batch", "csn", "stdlib")]
            except (TypeError, ValueError):
                return
            for box, value in zip((self.spin_epochs, self.spin_batch, self.spin_csn, self.spin_stdlib), values):
                box.setValue(value)
