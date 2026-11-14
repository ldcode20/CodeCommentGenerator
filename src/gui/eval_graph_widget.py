try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    import json
    import os
    _MPL_OK = True
except ImportError:
    _MPL_OK = False

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from src.gui import theme


class EvalGraphWidget(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)

        if not _MPL_OK:
            self._label = QLabel("Install matplotlib for evaluation charts: pip install matplotlib")
            self._label.setStyleSheet("color: #6c757d; padding: 20px;")
            self._layout.addWidget(self._label)
            self._fig = None
            return

        self._fig = Figure(figsize=(8, 6), facecolor=theme.SURFACE)
        self._canvas = FigureCanvas(self._fig)
        self._layout.addWidget(self._canvas)

    def set_data(self, eval_report_dict=None, training_report_dict=None,
                 eval_json_path=None, training_json_path=None):
        if not _MPL_OK or not self._fig:
            return

        if eval_json_path and os.path.exists(eval_json_path):
            with open(eval_json_path) as f:
                eval_report_dict = json.load(f)
        if training_json_path and os.path.exists(training_json_path):
            with open(training_json_path) as f:
                training_report_dict = json.load(f)

        self._fig.clear()
        self._fig.set_facecolor(theme.SURFACE)

        axes_params = {
            "facecolor": theme.BG_APP,
        }

        row_count = 0
        if training_report_dict:
            row_count += 1
        if eval_report_dict:
            row_count += 2

        if row_count == 0:
            ax = self._fig.add_subplot(111, **axes_params)
            ax.text(0.5, 0.5, "No evaluation data yet.\nTrain a model first.",
                    ha="center", va="center", fontsize=14, color=theme.TEXT_MUTED)
            ax.set_xticks([])
            ax.set_yticks([])
            self._canvas.draw()
            return

        idx = 1

        if training_report_dict:
            ast_model = training_report_dict.get("ast_model", {})
            loss_history = ast_model.get("loss_history", [])
            if loss_history:
                ax = self._fig.add_subplot(row_count, 1, idx, **axes_params)
                ax.plot(range(1, len(loss_history) + 1), loss_history,
                        color=theme.ACCENT, linewidth=2, label="Train Loss")
                ax.set_xlabel("Epoch", color=theme.TEXT_SECONDARY, fontsize=10)
                ax.set_ylabel("Loss", color=theme.TEXT_SECONDARY, fontsize=10)
                ax.set_title("Training Loss Curve", color=theme.TEXT, fontsize=12, fontweight="bold")
                ax.tick_params(colors=theme.TEXT_MUTED)
                ax.legend(facecolor=theme.SURFACE, edgecolor=theme.BORDER_STRONG, labelcolor=theme.TEXT)
                ax.grid(True, color=theme.BORDER, alpha=0.5)
                for spine in ax.spines.values():
                    spine.set_color(theme.BORDER_STRONG)
                idx += 1

        if eval_report_dict:
            ast_model_eval = eval_report_dict.get("ast_model", {})
            if ast_model_eval:
                metrics = {
                    "BLEU-4": ast_model_eval.get("bleu4_mean", 0),
                    "ROUGE-L": ast_model_eval.get("rouge_l_mean", 0),
                    "Exact Match": ast_model_eval.get("exact_match_rate", 0),
                }
                ax2 = self._fig.add_subplot(row_count, 1, idx, **axes_params)
                bars = ax2.bar(metrics.keys(), [v * 100 for v in metrics.values()],
                               color=[theme.ACCENT, theme.SUCCESS, theme.WARNING],
                               edgecolor=theme.BORDER_STRONG, width=0.5)
                ax2.set_ylabel("Score (%)", color=theme.TEXT_SECONDARY, fontsize=10)
                ax2.set_title("Evaluation Metrics", color=theme.TEXT, fontsize=12, fontweight="bold")
                ax2.tick_params(colors=theme.TEXT_MUTED)
                ax2.set_ylim(0, 100)
                for bar, val in zip(bars, metrics.values()):
                    ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 2,
                             f"{val:.4f}", ha="center", va="bottom", color=theme.TEXT, fontsize=9)
                ax2.grid(True, axis="y", color=theme.BORDER, alpha=0.5)
                for spine in ax2.spines.values():
                    spine.set_color(theme.BORDER_STRONG)
                idx += 1

            per_fn = ast_model_eval.get("per_function", []) if ast_model_eval else []
            if per_fn:
                ax3 = self._fig.add_subplot(row_count, 1, idx, **axes_params)
                confidences = [p.get("confidence", 0) for p in per_fn[:50]]
                bleus = [p.get("bleu4", 0) for p in per_fn[:50]]
                ax3.scatter(confidences, bleus, c=theme.ACCENT, alpha=0.7, s=30, edgecolors=theme.BORDER_STRONG)
                ax3.set_xlabel("ML Confidence", color=theme.TEXT_SECONDARY, fontsize=10)
                ax3.set_ylabel("BLEU-4", color=theme.TEXT_SECONDARY, fontsize=10)
                ax3.set_title("Confidence vs Quality", color=theme.TEXT, fontsize=12, fontweight="bold")
                ax3.tick_params(colors=theme.TEXT_MUTED)
                ax3.grid(True, color=theme.BORDER, alpha=0.5)
                for spine in ax3.spines.values():
                    spine.set_color(theme.BORDER_STRONG)

        self._fig.tight_layout(pad=1.5)
        self._canvas.draw()
