"""
Project Paths & Defaults
========================
Single source of truth for where artifacts live.

Before this module existed, each caller built its own relative path:
the CLI used ``"outputs"`` resolved against the script location, the GUI's
training tab wrote to ``"outputs/gui_models"`` while the GUI's generator tab
read from ``"outputs"``, and the insights tab walked ``"../.."`` by hand.
The result was that training from the GUI never satisfied the generator's
model lookup, and every path depended on the process working directory.

Everything now resolves against the repository root, derived from this
file's own location, so behaviour is identical no matter where the
interpreter was launched from.
"""
import pathlib
import sys

# ── Roots ─────────────────────────────────────────────────────────────────
PROJECT_ROOT: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent

#: Where models, datasets and JSON reports are written.
OUTPUT_DIR: pathlib.Path = PROJECT_ROOT / "outputs"

#: The fine-tuned T5 checkpoint directory. ``load_ast_model()`` treats the
#: absence of this directory as "not trained yet".
AST_MODEL_DIR: pathlib.Path = OUTPUT_DIR / "model" / "ast_model"

# ── Report files ──────────────────────────────────────────────────────────
TRAINING_REPORT = OUTPUT_DIR / "training_report.json"
EVAL_REPORT     = OUTPUT_DIR / "eval_report.json"
DATASET_JSON    = OUTPUT_DIR / "ast_train_dataset.json"


def resolve_output_dir(output_dir=None) -> pathlib.Path:
    """
    Normalise a user-supplied output directory.

    Args:
        output_dir: ``None`` for the project default, an absolute path used
                    as-is, or a relative path resolved against the project
                    root (NOT the current working directory).

    Returns:
        An absolute :class:`pathlib.Path`.
    """
    if output_dir is None:
        return OUTPUT_DIR
    p = pathlib.Path(output_dir)
    return p if p.is_absolute() else (PROJECT_ROOT / p)


def ast_model_dir(output_dir=None) -> pathlib.Path:
    """Return the ``model/ast_model`` directory under ``output_dir``."""
    return resolve_output_dir(output_dir) / "model" / "ast_model"


def configure_stdio() -> None:
    """
    Force UTF-8 on stdout/stderr.

    Progress messages throughout the pipeline use ``->`` arrows, ellipses and
    box-drawing characters written as real Unicode.  A Windows console defaults
    to cp1252, which cannot encode them, so one log line was enough to kill an
    otherwise healthy multi-hour training run with ``UnicodeEncodeError``.
    Replacing unencodable characters is strictly better than losing the run.

    Safe to call more than once, and a no-op on streams that do not support
    reconfiguration (such as the GUI's stdout capture object).
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass
