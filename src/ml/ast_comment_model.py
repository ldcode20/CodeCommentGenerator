"""
AST Comment Model
=================
Fine-tunes ``google-t5/t5-small`` (60M params) to generate natural-language
docstrings from **structured AST feature text**.

Architecture
------------
  Base model : T5-small  (encoder-decoder)
  Task prefix: "Generate docstring: "
  Input      : structured AST feature text produced by ast_feature_formatter
               ─ NOT the source code or function name alone ─
  Output     : first sentence of a natural-language docstring

Training
--------
  Dataset  : CodeSearchNet Python  (via HuggingFace datasets)
  Input    : format_for_model(FunctionFeature, FunctionContext, raises)
  Target   : cleaned first-sentence docstring from the original function

Inference
---------
  Given a new function:
    1. Extract  FunctionFeature + FunctionContext + raises
    2. Call     format_for_model()
    3. Pass to  ASTCommentModel.generate(ff, fc, raises)
    4. Receive  (docstring_text, confidence)

Usage
-----
    model = ASTCommentModel()
    model.fine_tune(pairs, epochs=3)
    text, conf = model.generate(ff, fc, raises=["ValueError"])
    model.save("outputs/model/ast_model")
    model = ASTCommentModel.load("outputs/model/ast_model")
"""
import json
import math
import os
import pathlib
import random
import re
import textwrap
import time
from typing import List, Optional, Tuple

try:
    import torch
    from torch.optim import AdamW
    from torch.utils.data import Dataset as TorchDataset, DataLoader
    from transformers import (
        T5ForConditionalGeneration,
        AutoTokenizer,
        get_linear_schedule_with_warmup,
    )
    _TRANSFORMERS_OK = True
except ImportError:
    _TRANSFORMERS_OK = False

from .ast_feature_formatter import format_for_model

# Task prefix (T5-style)
TASK_PREFIX   = "Generate docstring: "
MODEL_NAME    = "google-t5/t5-small"
MAX_INPUT_LEN  = 256   # tokens for the structured AST feature text
MAX_TARGET_LEN = 64    # tokens for the generated docstring

# Worker subprocesses are a net loss on Windows: `spawn` re-imports the whole
# module for every worker, and inside the GUI's QThread the spawn handshake is
# fragile.  Linux/macOS keep the parallel loaders.
DATALOADER_WORKERS = 0 if os.name == "nt" else 2


# ── Torch Dataset ─────────────────────────────────────────────────────────────

class _ASTDataset(TorchDataset if _TRANSFORMERS_OK else object):
    """Maps ASTTrainPair list to tokenized tensors."""

    def __init__(self, pairs, tokenizer):
        self.pairs     = pairs
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.pairs)

    def __getitem__(self, idx):
        pair = self.pairs[idx]
        # T5 input = task_prefix + structured AST feature text
        input_text = TASK_PREFIX + pair.input_text

        enc = self.tokenizer(
            input_text,
            max_length=MAX_INPUT_LEN,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        dec = self.tokenizer(
            text_target=pair.target_text,
            max_length=MAX_TARGET_LEN,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        labels = dec["input_ids"].squeeze()
        labels[labels == self.tokenizer.pad_token_id] = -100

        return {
            "input_ids":      enc["input_ids"].squeeze(),
            "attention_mask": enc["attention_mask"].squeeze(),
            "labels":         labels,
        }


# ── Main Model Class ──────────────────────────────────────────────────────────

class ASTCommentModel:
    """
    T5-small fine-tuned to generate docstrings from structured AST features.

    The model ONLY sees AST-derived information:
      - Control flow  (loops, conditionals, cyclomatic complexity)
      - Calls         (internal / external function calls)
      - Types         (parameter types, return type, data structures)
      - Decorators    (@property, @staticmethod, etc.)
      - Raises        (exception types from raise statements)
      - Metadata      (async, method, body size)

    It does NOT see raw source code or depend on the function name for meaning.
    """

    def __init__(self, model_name: str = MODEL_NAME):
        if not _TRANSFORMERS_OK:
            raise ImportError(
                "transformers and torch are required:\n"
                "pip install transformers torch sentencepiece"
            )
        self._model_name      = model_name
        self._model           = None
        self._tokenizer       = None
        self._device          = "cuda" if torch.cuda.is_available() else "cpu"
        self._fine_tuned      = False
        self._loss_history: List[float] = []
        self._val_history:  List[float] = []

    # ── Lazy loading ──────────────────────────────────────────────────────────

    def _ensure_loaded(self):
        if self._model is not None:
            return
        print(f"  [ast_model] Loading {self._model_name} …")
        self._tokenizer = AutoTokenizer.from_pretrained(self._model_name)
        self._model     = T5ForConditionalGeneration.from_pretrained(self._model_name)
        self._model.to(self._device)
        print(f"  [ast_model] Model loaded on {self._device}.")

    # ── Fine-tuning ───────────────────────────────────────────────────────────

    def fine_tune(
        self,
        pairs,                       # List[ASTTrainPair]
        epochs: int = 3,
        batch_size: int = 8,
        lr: float = 2e-4,
        warmup_ratio: float = 0.1,
        val_split: float = 0.1,
        grad_accum_steps: int = 1,
        seed: int = 42,
        verbose: bool = True,
    ) -> dict:
        """
        Fine-tune T5 on (AST feature text, docstring) pairs.

        Args:
            pairs:       List of ASTTrainPair from ast_dataset_builder.
            epochs:      Training epochs (4 works well on GPU; reduce to 2 on CPU).
            batch_size:  Mini-batch size (reduce to 4 if OOM on CPU).
            lr:          Peak learning rate.
            warmup_ratio:Fraction of steps for LR warm-up.
            val_split:   Fraction withheld for validation loss reporting.
            grad_accum_steps: Number of gradient accumulation steps.
            seed:        Random seed.
            verbose:     Print per-epoch loss.

        Returns:
            Training metadata dict.
        """
        self._ensure_loaded()

        random.seed(seed)
        data = list(pairs)
        random.shuffle(data)
        split = max(1, int(len(data) * (1 - val_split)))
        train_data, val_data = data[:split], data[split:]

        train_ds = _ASTDataset(train_data, self._tokenizer)
        train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True,
                              num_workers=DATALOADER_WORKERS,
                              pin_memory=(self._device == "cuda"))

        val_dl = None
        if val_data:
            val_ds = _ASTDataset(val_data, self._tokenizer)
            val_dl = DataLoader(val_ds, batch_size=batch_size,
                                num_workers=DATALOADER_WORKERS,
                                pin_memory=(self._device == "cuda"))

        optimizer     = AdamW(self._model.parameters(), lr=lr, weight_decay=0.01)
        grad_accum_steps = max(1, int(grad_accum_steps))
        total_steps   = max(1, (len(train_dl) * epochs) // grad_accum_steps)
        warmup_steps  = int(total_steps * warmup_ratio)
        scheduler     = get_linear_schedule_with_warmup(
            optimizer, num_warmup_steps=warmup_steps,
            num_training_steps=total_steps,
        )

        # Mixed precision keeps batch_size 8 comfortable on a 4 GB card.
        #
        # bfloat16 specifically, NOT float16: T5 was pretrained in bf16 and its
        # attention logits routinely overflow fp16's range, which shows up as
        # NaN losses a few hundred steps in.  bf16 has the same exponent range
        # as fp32, so it is stable.  Ampere (RTX 30xx/20x0) and newer support
        # it; on anything older we simply train in fp32.
        use_amp   = (self._device == "cuda" and torch.cuda.is_bf16_supported())
        amp_dtype = torch.bfloat16
        # bf16 needs no loss scaling — the scaler stays disabled and its calls
        # below are no-ops, kept so the loop reads the same either way.
        scaler    = torch.amp.GradScaler("cuda", enabled=False)

        self._model.train()
        self._loss_history = []
        self._val_history = []
        best_val   = float("inf")
        best_state = None
        best_epoch = 0

        if verbose:
            print(f"  [ast_model] Fine-tuning on {len(train_data)} pairs "
                  f"(val={len(val_data)}) for {epochs} epoch(s) on {self._device} …")

        try:
            for epoch in range(epochs):
                t0 = time.time()
                epoch_loss = 0.0
                optimizer.zero_grad()
                for step_idx, batch in enumerate(train_dl, start=1):
                    batch = {k: v.to(self._device) for k, v in batch.items()}
                    with torch.amp.autocast("cuda", dtype=amp_dtype,
                                            enabled=use_amp):
                        loss = self._model(**batch).loss / grad_accum_steps
                    scaler.scale(loss).backward()
                    epoch_loss += loss.item() * grad_accum_steps

                    if step_idx % grad_accum_steps == 0 or step_idx == len(train_dl):
                        scaler.unscale_(optimizer)
                        torch.nn.utils.clip_grad_norm_(self._model.parameters(), 1.0)
                        scaler.step(optimizer)
                        scaler.update()
                        scheduler.step()
                        optimizer.zero_grad()

                avg = epoch_loss / max(len(train_dl), 1)
                self._loss_history.append(avg)

                val_loss = None
                if val_dl:
                    self._model.eval()
                    with torch.no_grad():
                        vl = sum(
                            self._model(
                                **{k: v.to(self._device) for k, v in b.items()}
                            ).loss.item()
                            for b in val_dl
                        )
                    val_loss = vl / max(len(val_dl), 1)
                    self._val_history.append(val_loss)
                    self._model.train()

                # Keep the best weights rather than whichever epoch ran last —
                # on a small corpus the final epoch is often already overfit.
                score = val_loss if val_loss is not None else avg
                if score < best_val:
                    best_val   = score
                    best_epoch = epoch + 1
                    best_state = {
                        k: v.detach().cpu().clone()
                        for k, v in self._model.state_dict().items()
                    }

                elapsed = time.time() - t0
                if verbose:
                    msg = (f"  [ast_model] Epoch {epoch+1}/{epochs} — "
                           f"train_loss={avg:.4f}")
                    if val_loss is not None:
                        msg += f"  val_loss={val_loss:.4f}"
                    msg += f"  ({elapsed:.1f}s)"
                    if best_epoch == epoch + 1:
                        msg += "  *best*"
                    print(msg)

                if self._device == "cuda":
                    torch.cuda.empty_cache()

        except torch.cuda.OutOfMemoryError as exc:
            torch.cuda.empty_cache()
            raise RuntimeError(
                f"CUDA ran out of memory at batch_size={batch_size}. "
                f"Retry smaller, e.g. --batch-size {max(1, batch_size // 2)} "
                f"--grad-accum-steps 2"
            ) from exc

        # Restore the best checkpoint so save() persists it, not the last epoch.
        if best_state is not None and best_epoch != epochs:
            if verbose:
                print(f"  [ast_model] Restoring best weights from epoch "
                      f"{best_epoch} (loss={best_val:.4f})")
            self._model.load_state_dict(best_state)

        self._fine_tuned = True
        return {
            "model": self._model_name,
            "train_size": len(train_data),
            "val_size":   len(val_data),
            "epochs":     epochs,
            "grad_accum_steps": grad_accum_steps,
            "final_loss": round(self._loss_history[-1], 4) if self._loss_history else None,
            "loss_history": [round(l, 4) for l in self._loss_history],
            "val_loss_history": [round(l, 4) for l in self._val_history],
            "best_epoch": best_epoch,
            "best_loss": round(best_val, 4) if best_val != float("inf") else None,
            "mixed_precision": "bfloat16" if use_amp else "fp32",
            "device": self._device,
        }

    # ── Inference ─────────────────────────────────────────────────────────────

    def generate(
        self,
        ff,
        fc=None,
        raises: Optional[List[str]] = None,
        num_beams: int = 6,
        max_length: int = 72,
        min_length: int = 8,
    ) -> Tuple[str, float]:
        """
        Generate a docstring from AST feature objects.

        Args:
            ff:        FunctionFeature (from ast_extractor).
            fc:        FunctionContext (from context_analyzer), optional.
            raises:    List of exception names raised in the body.
            num_beams: Beam search width.
            max_length:Max output tokens.
            min_length:Minimum output tokens.

        Returns:
            (docstring_text, confidence_score)
        """
        self._ensure_loaded()

        # Build input: task prefix + formatted AST features
        feature_text = format_for_model(ff, fc, raises or [])
        input_text   = TASK_PREFIX + feature_text

        enc = self._tokenizer(
            input_text,
            max_length=MAX_INPUT_LEN,
            truncation=True,
            return_tensors="pt",
        ).to(self._device)

        self._model.eval()
        with torch.no_grad():
            out = self._model.generate(
                **enc,
                num_beams=num_beams,
                max_length=max_length,
                min_length=min_length,
                early_stopping=True,
                no_repeat_ngram_size=3,
                repetition_penalty=1.15,
                length_penalty=0.9,
                output_scores=True,
                return_dict_in_generate=True,
            )

        text = self._postprocess_generated_text(
            self._tokenizer.decode(out.sequences[0], skip_special_tokens=True).strip()
        )

        # Confidence from beam score
        if hasattr(out, "sequences_scores") and out.sequences_scores is not None:
            confidence = float(min(1.0, math.exp(float(out.sequences_scores[0]))))
        else:
            confidence = 0.5 if self._fine_tuned else 0.3

        # Wrap as docstring
        if not text.startswith('"""'):
            text = f'"""{text}"""'

        return text, confidence

    def generate_from_feature_text(
        self, feature_text: str, num_beams: int = 6, max_length: int = 72, min_length: int = 8
    ) -> Tuple[str, float]:
        """
        Lower-level generate: accepts already-formatted AST feature text.
        Used by the evaluator and during corpus evaluation.
        """
        self._ensure_loaded()
        input_text = TASK_PREFIX + feature_text

        enc = self._tokenizer(
            input_text,
            max_length=MAX_INPUT_LEN,
            truncation=True,
            return_tensors="pt",
        ).to(self._device)

        self._model.eval()
        with torch.no_grad():
            out = self._model.generate(
                **enc,
                num_beams=num_beams,
                max_length=max_length,
                min_length=min_length,
                early_stopping=True,
                no_repeat_ngram_size=3,
                repetition_penalty=1.15,
                length_penalty=0.9,
                output_scores=True,
                return_dict_in_generate=True,
            )

        text = self._postprocess_generated_text(
            self._tokenizer.decode(out.sequences[0], skip_special_tokens=True).strip()
        )

        if hasattr(out, "sequences_scores") and out.sequences_scores is not None:
            confidence = float(min(1.0, math.exp(float(out.sequences_scores[0]))))
        else:
            confidence = 0.5 if self._fine_tuned else 0.3

        if not text.startswith('"""'):
            text = f'"""{text}"""'

        return text, confidence

    def _postprocess_generated_text(self, text: str) -> str:
        """Light cleanup to keep generated summaries concise and readable."""
        cleaned = re.sub(r"\s+", " ", text).strip()
        cleaned = cleaned.strip('"').strip("'").strip()
        # Remove repeated adjacent bigrams like "returns returns ..."
        cleaned = re.sub(r"\b(\w+)\s+\1\b", r"\1", cleaned, flags=re.I)
        if cleaned and cleaned[-1] not in ".!?":
            cleaned += "."
        return cleaned

    def training_report(self) -> dict:
        return {
            "model":        self._model_name,
            "fine_tuned":   self._fine_tuned,
            "device":       self._device,
            "loss_history": [round(l, 4) for l in self._loss_history],
        }

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, directory: str) -> None:
        """Save model + tokenizer + metadata to a local directory."""
        self._ensure_loaded()
        pathlib.Path(directory).mkdir(parents=True, exist_ok=True)
        self._model.save_pretrained(directory)
        self._tokenizer.save_pretrained(directory)
        meta = {
            "model_name":       self._model_name,
            "fine_tuned":       self._fine_tuned,
            "loss_history":     self._loss_history,
            "val_loss_history": getattr(self, "_val_history", []),
        }
        with open(os.path.join(directory, "ast_model_meta.json"), "w") as f:
            json.dump(meta, f, indent=2)
        print(f"  [ast_model] Saved to {directory}/")

    @staticmethod
    def load(directory: str) -> "ASTCommentModel":
        """Load a saved model from a local directory."""
        if not _TRANSFORMERS_OK:
            raise ImportError("transformers and torch are required.")
        meta_path = os.path.join(directory, "ast_model_meta.json")
        meta = {}
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                meta = json.load(f)

        inst = ASTCommentModel.__new__(ASTCommentModel)
        inst._model_name    = meta.get("model_name", MODEL_NAME)
        inst._device        = "cuda" if torch.cuda.is_available() else "cpu"
        inst._fine_tuned    = meta.get("fine_tuned", False)
        inst._loss_history  = meta.get("loss_history", [])
        inst._val_history   = meta.get("val_loss_history", [])

        inst._tokenizer = AutoTokenizer.from_pretrained(directory)
        inst._model     = T5ForConditionalGeneration.from_pretrained(directory)
        inst._model.to(inst._device)
        return inst
