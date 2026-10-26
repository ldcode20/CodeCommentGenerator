"""
Trainer — AST-Feature NLP Comment Generation
=============================================
End-to-end pipeline:
  1. Build (AST feature text, docstring) corpus from CodeSearchNet + stdlib
  2. Train/validation split
  3. Fine-tune ASTCommentModel (T5-small) on AST features → docstrings
  4. Evaluate with BLEU-4, ROUGE-L, exact-match on holdout split
  5. Save model + JSON reports

Usage:
    python3 -m src.main --train
    python3 -m src.main --train --output-dir outputs/
    python3 -m src.main --train --epochs 3 --batch-size 8
"""
import json
import pathlib
import random
from typing import List, Optional

from ..config import resolve_output_dir
from .ast_dataset_builder import (
    build_full_dataset, save_dataset, ASTTrainPair, build_stdlib_dataset,
    load_dataset_from_json,
)
from .evaluator import compute_bleu, compute_rouge, compute_exact_match, EvalReport

import numpy as np


# ── Helpers ───────────────────────────────────────────────────────────────────

def _split(pairs: List[ASTTrainPair], test_ratio: float = 0.1, seed: int = 42):
    data = list(pairs)
    random.seed(seed)
    random.shuffle(data)
    split = max(1, int(len(data) * (1 - test_ratio)))
    return data[:split], data[split:]


def _evaluate_model(model, test_pairs: List[ASTTrainPair], cap: int = 200) -> dict:
    """
    Evaluate ASTCommentModel on a holdout set.

    Uses generate_from_feature_text() so evaluation is identical to training:
    the model only sees formatted AST features, never raw source.
    """
    bleu, rouge, em, per_fn = [], [], [], []
    for p in test_pairs[:cap]:
        try:
            pred, conf = model.generate_from_feature_text(p.input_text)
            pred_clean = pred.strip('"""').strip()
        except Exception:
            pred_clean, conf = "", 0.0

        b = compute_bleu(p.target_text, pred_clean)
        r = compute_rouge(p.target_text, pred_clean)
        e = compute_exact_match(p.target_text, pred_clean)
        bleu.append(b); rouge.append(r); em.append(e)
        per_fn.append({
            "func_name":   p.func_name,
            "reference":   p.target_text[:120],
            "hypothesis":  pred_clean[:120],
            "bleu4":       round(b, 4),
            "rouge_l":     round(r, 4),
            "exact_match": int(e),
            "confidence":  round(conf, 4),
        })

    return {
        "n_samples":       len(bleu),
        "bleu4_mean":      round(float(np.mean(bleu)), 4)  if bleu else 0.0,
        "bleu4_std":       round(float(np.std(bleu)), 4)   if bleu else 0.0,
        "rouge_l_mean":    round(float(np.mean(rouge)), 4) if rouge else 0.0,
        "rouge_l_std":     round(float(np.std(rouge)), 4)  if rouge else 0.0,
        "exact_match_rate":round(float(np.mean(em)), 4)    if em else 0.0,
        "per_function":    per_fn,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def train_and_evaluate(
    output_dir: Optional[str] = None,
    dataset_json: Optional[str] = None,
    include_codesearchnet: bool = True,
    include_stdlib: bool = True,
    codesearchnet_max: int = 20_000,
    max_stdlib_files: int = 1500,
    test_ratio: float = 0.1,
    epochs: int = 4,
    batch_size: int = 8,
    grad_accum_steps: int = 1,
    lr: float = 2e-4,
    verbose: bool = True,
) -> dict:
    """
    Full AST-feature NLP training pipeline.

    Trains T5-small to map structured AST feature text → natural-language
    docstrings.  The model never sees raw source code; its ONLY input is
    the structured AST extraction.

    Args:
        output_dir:            Directory to save model + reports. ``None``
                               means the project default (``outputs/``);
                               a relative path is resolved against the
                               project root, never the working directory.
        dataset_json:          Reuse a previously saved corpus instead of
                               rebuilding it (skips the HF download).
        include_codesearchnet: Download CodeSearchNet from HuggingFace.
        include_stdlib:        Crawl Python stdlib as offline supplement.
        codesearchnet_max:     Max samples from CodeSearchNet.
        max_stdlib_files:      Max stdlib .py files to crawl.
        test_ratio:            Holdout fraction for evaluation.
        epochs:                Fine-tuning epochs.
        batch_size:            Mini-batch size (reduce to 4 if OOM).
        grad_accum_steps:      Gradient accumulation steps.
        lr:                    Learning rate.
        verbose:               Print progress.

    Returns:
        dict with ``training_report`` and ``eval_report``.
    """
    out_dir   = resolve_output_dir(output_dir)
    model_dir = out_dir / "model" / "ast_model"
    out_dir.mkdir(parents=True, exist_ok=True)
    model_dir.mkdir(parents=True, exist_ok=True)

    def _log(msg):
        if verbose:
            print(f"  [trainer] {msg}")

    # ── 1. Build dataset ──────────────────────────────────────────────────────
    if dataset_json and pathlib.Path(dataset_json).exists():
        _log(f"Reusing saved corpus → {dataset_json}")
        pairs = load_dataset_from_json(dataset_json)
    else:
        _log("Building AST feature dataset …")
        pairs = build_full_dataset(
            include_codesearchnet=include_codesearchnet,
            include_stdlib=include_stdlib,
            codesearchnet_max=codesearchnet_max,
            max_stdlib_files=max_stdlib_files,
            verbose=verbose,
        )

    if len(pairs) < 10:
        # Absolute fallback: use stdlib only (always offline-available)
        _log("  Few samples found — falling back to stdlib-only dataset.")
        pairs = build_stdlib_dataset(max_files=500, verbose=verbose)

    if len(pairs) < 2:
        raise RuntimeError("Dataset too small (< 2 samples). Check your environment.")

    _log(f"Total dataset size: {len(pairs)} pairs")

    # Save for inspection
    corpus_info = save_dataset(pairs, output_dir=str(out_dir))
    _log(f"Dataset saved → {corpus_info['json_path']}")

    train_pairs, test_pairs = _split(pairs, test_ratio=test_ratio)
    _log(f"Split: train={len(train_pairs)}  test={len(test_pairs)}")

    # ── 2. Fine-tune ASTCommentModel ──────────────────────────────────────────
    training_meta = {"model": "ASTCommentModel", "error": "not attempted"}
    ast_model     = None

    try:
        from .ast_comment_model import ASTCommentModel
        _log(f"Fine-tuning ASTCommentModel on {len(train_pairs)} pairs …")
        ast_model = ASTCommentModel()
        training_meta = ast_model.fine_tune(
            train_pairs,
            epochs=epochs,
            batch_size=batch_size,
            grad_accum_steps=grad_accum_steps,
            lr=lr,
            verbose=verbose,
        )
    except ImportError as exc:
        _log(f"[skip] transformers/torch not installed: {exc}")
        training_meta["error"] = str(exc)
    except Exception as exc:
        _log(f"[warn] Training error: {exc}")
        training_meta["error"] = str(exc)
        ast_model = None

    # ── 3. Evaluate ───────────────────────────────────────────────────────────
    eval_report_dict = None
    if ast_model is not None and test_pairs:
        _log(f"Evaluating on {min(len(test_pairs), 200)} test samples …")
        eval_report_dict = _evaluate_model(ast_model, test_pairs)
        _log(
            f"  BLEU-4  = {eval_report_dict['bleu4_mean']:.4f} "
            f"  ROUGE-L = {eval_report_dict['rouge_l_mean']:.4f} "
            f"  EM      = {eval_report_dict['exact_match_rate']:.4f}"
        )

    # ── 4. Save model ─────────────────────────────────────────────────────────
    if ast_model is not None:
        ast_model.save(str(model_dir))
        _log(f"Model saved → {model_dir}/")

    # ── 5. Write report JSONs ─────────────────────────────────────────────────
    training_report = {
        "dataset_total":  len(pairs),
        "train_size":     len(train_pairs),
        "test_size":      len(test_pairs),
        "data_profile": {
            "input_mode": "AST structured features",
            "target_mode": "NLP docstring sentence",
            "ast_nlp_pairs": len(pairs),
        },
        "ast_model":      training_meta,
        "training_profile": {
            "quality_preset": "medium",
            "epochs": epochs,
            "batch_size": batch_size,
            "grad_accum_steps": grad_accum_steps,
            "learning_rate": lr,
            "codesearchnet_max": codesearchnet_max,
            "max_stdlib_files": max_stdlib_files,
        },
        "input_format":   "structured AST features (ast_feature_formatter)",
        "target_format":  "first sentence of function docstring",
        "source":         ["CodeSearchNet Python (HF)", "Python stdlib"],
    }

    full_eval_report = {
        "ast_model":     eval_report_dict,
        "summary": {
            "bleu4_mean":       eval_report_dict["bleu4_mean"] if eval_report_dict else 0.0,
            "rouge_l_mean":     eval_report_dict["rouge_l_mean"] if eval_report_dict else 0.0,
            "exact_match_rate": eval_report_dict["exact_match_rate"] if eval_report_dict else 0.0,
            # Backward-compatible keys used by older CLI/GUI paths
            "best_bleu4":       eval_report_dict["bleu4_mean"] if eval_report_dict else 0.0,
            "best_rouge_l":     eval_report_dict["rouge_l_mean"] if eval_report_dict else 0.0,
            "best_exact_match": eval_report_dict["exact_match_rate"] if eval_report_dict else 0.0,
            "dataset_size":     len(pairs),
        },
    }

    with open(out_dir / "training_report.json", "w") as f:
        json.dump(training_report, f, indent=2)
    with open(out_dir / "eval_report.json", "w") as f:
        json.dump(full_eval_report, f, indent=2)
    _log(f"Reports saved → {out_dir}/")

    return {"training_report": training_report, "eval_report": full_eval_report}


def load_ast_model(output_dir: Optional[str] = None) -> Optional["ASTCommentModel"]:
    """
    Load the saved ASTCommentModel.

    Args:
        output_dir: ``None`` for the project default (``outputs/``). Relative
                    paths resolve against the project root so the CLI and the
                    GUI always agree on where the checkpoint lives.

    Returns:
        The loaded model, or None if transformers is unavailable or no
        checkpoint has been trained yet.
    """
    model_path = resolve_output_dir(output_dir) / "model" / "ast_model"
    # An empty directory (e.g. created by a crashed run) is not a model.
    if not model_path.exists() or not (model_path / "config.json").exists():
        return None
    try:
        from .ast_comment_model import ASTCommentModel
        return ASTCommentModel.load(str(model_path))
    except Exception as exc:
        print(f"  [trainer] Could not load AST model: {exc}")
        return None
