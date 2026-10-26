# Code Comment Generator — AST + NLP

This project generates Python comments/docstrings using two engines:

- `Rule-Based` (deterministic AST analysis)
- `AST+NLP ML` (model trained on structured AST features -> natural-language docstrings)

It also contains a static **security analyzer** (taint analysis over a real
IR/CFG plus AST rules) that runs independently of comment generation — see
[Security analysis](#security-analysis) and [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md).

## Setup

> **The trained model is not in this repository.** `outputs/model/` is listed in
> `.gitignore` (checkpoints are hundreds of MB), so **every fresh clone must train
> once** before `--ml` or `--neurosymbolic` will work. See
> [Troubleshooting](#troubleshooting) if you hit the "No trained AST+NLP model found" error.

### 1. Use Python 3.11 or 3.12 — not 3.14

PyTorch publishes no wheels for Python 3.14, so `pip install torch` fails outright
there. Check what you have:

```bash
py -0p
```

Create the virtual environment with a supported interpreter:

```bash
py -3.12 -m venv .venv
```

### 2. Install dependencies

With an NVIDIA GPU (install the CUDA build of torch *first*, then the rest):

```bash
.venv/Scripts/python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cu121
.venv/Scripts/python.exe -m pip install -r requirements.txt
```

CPU-only (slower training, everything still works):

```bash
.venv/Scripts/python.exe -m pip install -r requirements.txt
```

### 3. Train once

```bash
# Smoke test — a few minutes, proves the pipeline end to end.
.venv/Scripts/python.exe -m src.main --train --quick

# Real run.
.venv/Scripts/python.exe -m src.main --train \
  --codesearchnet-max 8000 --max-stdlib-files 600 --epochs 3 --batch-size 8
```

The checkpoint lands in `outputs/model/ast_model/`. The CLI and the GUI both read
from that one location.

---

## Current ML Architecture

The active ML pipeline is centered on `src/ml/`:

- `ast_feature_formatter.py` — serializes extracted AST/context features into model input text
- `ast_dataset_builder.py` — builds `(input_text, target_text)` training pairs from:
  - CodeSearchNet Python
  - Python stdlib fallback
- `ast_comment_model.py` — T5-based generator used for AST+NLP comment generation
- `trainer.py` — end-to-end training/evaluation/report saving
- `evaluator.py` — BLEU-4 / ROUGE-L / exact-match metrics

## CLI Usage

### 1) Train AST+NLP model

```bash
python3 -m src.main --train
```

Useful tuning flags:

```bash
python3 -m src.main --train \
  --epochs 1 \
  --batch-size 2 \
  --codesearchnet-max 20 \
  --max-stdlib-files 10
```

### 2) Rule-based generation

```bash
python3 -m src.main tests/inputs/complex_sample.py
```

### 3) AST+NLP ML generation

```bash
python3 -m src.main tests/inputs/complex_sample.py --ml
```

`--ml` is strict AST+NLP mode. If no trained model exists, execution fails with a clear train-first message.

Recommended medium-quality run for RTX 4050:

```bash
python3 -m src.main --train \
  --codesearchnet-max 8000 \
  --max-stdlib-files 600 \
  --epochs 3 \
  --batch-size 8 \
  --grad-accum-steps 1
```

## Output Artifacts

After training, artifacts are written in `outputs/`:

- `outputs/model/ast_model/` — trained AST+NLP model
- `outputs/ast_train_dataset.json` — saved AST/NLP dataset
- `outputs/ast_train_dataset.csv` — dataset in CSV format
- `outputs/training_report.json` — training metadata
- `outputs/eval_report.json` — evaluation metrics

`training_report.json` includes:

- `data_profile.input_mode = "AST structured features"`
- `data_profile.target_mode = "NLP docstring sentence"`
- `data_profile.ast_nlp_pairs`

## Docstring Quality & Safety

Both generation engines apply automatic docstring sanitization to ensure generated code is syntactically valid:

- **Triple-quote escaping**: Prevents malformed docstrings when generated text contains quote characters
- **Raw string sanitization**: Removes invalid raw string prefixes (r""", u""", etc.) that could break syntax
- **Content validation**: All dynamic content (parameters, types, exceptions) is validated before insertion
- This guarantees output Python files are always compilable and valid

Docstrings are inserted before the first statement of the body, so functions
with multi-line signatures stay valid; one-line bodies (`def f(): return 1`)
are left untouched. The input file is never modified — use `--output`.

## Security analysis

The analyzer tracks untrusted data (HTTP request data, `input()`, environment,
`sys.argv`, files, network responses) through assignments, string building,
containers, branches, loops, fields, closures and calls between functions, to
SQL execution, shell/process execution, file-system access, HTML responses,
template compilation, `eval`/`exec` and unsafe deserializers. Sanitizers are
context-specific (HTML escaping does not make data safe for SQL). It also runs
AST rules for hardcoded secrets, weak hashes, bare `except`, mutable defaults,
`assert`, insecure randomness and hardcoded IPs.

Every finding has a rule ID, CWE, severity, **confidence** (high/medium/low with
the reasons), **status** (`confirmed` / `potential` / `suppressed`), the
original file location and a source-to-sink evidence trace:

```text
[CONFIRMED] SEC005 SQL injection — high severity, high confidence (CWE-89)
  at demo.py:13:5 in run_query()
  Data from Flask request data (flask.request.args.get) reaches SQL execution (cur.execute) as argument 1 without sql-context sanitisation.
  evidence:
    L17   [source] untrusted Flask request data: name = request.args.get("name")
    L17   [assign] name = request.args.get("name")
    L18   [call] calls build(): run_query(build(name))
    L7    [param] enters build() as parameter 'name'
    L8    [return] returned: return "SELECT * FROM users WHERE name = '" + name + "'"
    L18   [return] value returned from build()
    L18   [call] calls run_query(): run_query(build(name))
    L10   [param] enters run_query() as parameter 'q'
    L13   [sink] reaches SQL execution cur.execute() as argument 1
  confidence: resolved sink reached by a recognised untrusted source on a feasible path
```

```bash
# security only (no comment generation, no ML model)
python -m src.security path/to/file_or_dir [--json] [--fail-on confirmed]
python -m src.main path/to/file.py --security [--security-json out.json]

# full pipeline, also printing the findings
python -m src.main path/to/file.py --security-report --output out.py

# evaluation on the labelled fixtures (precision / recall / F1 / FPR)
python -m src.security.evaluate [--confirmed-only] [--granularity function]
```

Suppress a reviewed finding with a justification on the same line:
`cur.execute(q)  # nosec SEC005: read-only replica, input is an enum`
(a `# nosec` without a reason is ignored).

Design, full source/sink/sanitizer tables, evaluation results and known
limitations: [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md).

---

## Troubleshooting

### "No trained AST+NLP model found" / exit code 2

`--ml` and `--neurosymbolic` require a fine-tuned checkpoint at
`outputs/model/ast_model/`. That directory is gitignored, so it is absent in a
fresh clone. Run `python -m src.main --train --quick` once.

Confirm it worked:

```bash
ls outputs/model/ast_model/      # config.json, model.safetensors, tokenizer files
```

### `pip install torch` fails / "no matching distribution"

You are almost certainly on Python 3.14, which PyTorch does not support yet.
Build the venv with 3.11 or 3.12 — see [Setup](#setup).

### Training is unbearably slow

The defaults (`--epochs 4 --codesearchnet-max 20000 --max-stdlib-files 1500`) are
a multi-hour job. Use `--quick` while you are checking that things work, and
`--dataset-json outputs/ast_train_dataset.json` to skip rebuilding the corpus on
every re-run.

### CUDA out of memory

Halve the batch and compensate with accumulation:

```bash
python -m src.main --train --batch-size 4 --grad-accum-steps 2
```

Mixed precision (fp16) is enabled automatically on CUDA, which is what makes
`--batch-size 8` fit on a 4 GB card.

### "All CodeSearchNet sources failed"

The HuggingFace download was unreachable, or `datasets>=3.0` rejected the legacy
loading-script dataset. Training still proceeds on the Python standard library
crawl — a smaller and narrower corpus, so expect weaker metrics. Check your
network/proxy, or pass `--no-codesearchnet` to make the stdlib-only path explicit.

### GUI: training finishes but ML mode still says "not trained"

Fixed. The training tab used to write to `outputs/gui_models` while the generator
tab read from `outputs`. Both now resolve through `src/config.py`. If you
previously trained from the GUI, the stale checkpoint is in
`outputs/gui_models/model/ast_model/` — move it to `outputs/model/ast_model/` or
just retrain.
