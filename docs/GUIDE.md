# Code Comment Generator — Feature Guide

Quick reference for every feature and how to use it.

---

## Table of Contents

1. [Comment Generation Engines](#1-comment-generation-engines)
2. [Security Analysis](#2-security-analysis)
3. [AST & Context Visualization](#3-ast--context-visualization)
4. [Evaluation Metrics](#4-evaluation-metrics)
5. [IR & Pattern Analysis](#5-ir--pattern-analysis)
6. [ML Training](#6-ml-training)
7. [CLI Reference](#7-cli-reference)
8. [GUI Workspaces](#8-gui-workspaces)

---

## 1. Comment Generation Engines

Three engines generate docstrings and inline comments for undocumented Python functions and classes.

### Rule-Based (default)

- **What**: Deterministic AST-driven generation. Produces Google-style docstrings with summary, Args, Returns, Raises, and Security Warnings sections.
- **CLI**: `python -m src.main myfile.py`
- **GUI**: Generator workspace → select **Rule-Based** radio button

### ML-Based (AST+NLP)

- **What**: T5-small model generates a natural-language summary from structured AST features (never raw source). Full docstring assembled by adding AST-verified Args/Returns/Raises.
- **Requires**: Trained model (run `--train` first or use GUI ML Training tab).
- **CLI**: `python -m src.main myfile.py --ml`
- **GUI**: Generator workspace → select **ML-Based** radio button

### Neurosymbolic (confidence-gated fusion)

- **What**: Combines ML and symbolic reasoning. If ML confidence ≥ 0.4, ML summary leads; otherwise symbolic summary. Symbolic Args/Returns/Raises always appended. Consistency validation corrects ML-AST mismatches.
- **Confidence tiers**: ≥0.7 = neural, 0.4–0.7 = fused, <0.4 = symbolic
- **Requires**: Trained model (same as ML).
- **CLI**: `python -m src.main myfile.py --neurosymbolic`
- **GUI**: Generator workspace → select **Neurosymbolic** radio button (default)

---

## 2. Security Analysis

Always runs as part of the pipeline. Detects 12 security patterns with per-function scoring.

### Patterns Detected

| ID | What | Severity |
|----|------|----------|
| SEC001 | `eval()` / `exec()` / `compile()` | critical |
| SEC002 | `subprocess` with `shell=True` | critical |
| SEC003 | Hardcoded passwords/secrets/tokens | high |
| SEC004 | Weak crypto (md5, sha1) | medium |
| SEC005 | SQL string concatenation | high |
| SEC006 | Bare `except:` clauses | medium |
| SEC007 | Mutable default arguments | low |
| SEC008 | `assert` in non-test code | low |
| SEC009 | `pickle.load` on untrusted data | high |
| SEC010 | `yaml.load` without SafeLoader | high |
| SEC011 | Insecure `random` for crypto | medium |
| SEC012 | Hardcoded IPs/URLs | low |

### Scoring

- Per-function: starts at 100, minus critical×40, high×25, medium×5, low×1. Clamped 0–100.
- **Unsafe** = score < 80, so any high or critical finding makes a function unsafe.
- **Module safety** = % of functions scoring ≥ 80.

### How to view

- **CLI**: Automatically printed in the pipeline summary. Use `--logs` for full detail.
- **GUI**: Security workspace (safety score, charts, issue table) and Insights → Security tab.

---

## 3. AST & Context Visualization

Interactive graph renderings of the parsed code structure.

### AST Graph

- **What**: Hierarchical tree of the AST — Module, Imports, Classes, Functions, Params, Decorators.
- **Colors**: Module=gray, Import=yellow, Class=green, Function=blue, AsyncFunction=purple, Param=cyan
- **Interactions**: Click-drag to pan, scroll to zoom, hover for tooltips (line number, params, complexity, etc.)
- **GUI**: Insights → **AST Graph** tab

### Call Graph

- **What**: Force-directed directed graph of function calls. Nodes = functions, edges = internal calls.
- **Colors**: Complexity-coded (green=simple, yellow=moderate, orange=complex, red=very_complex). Red border on nodes with security issues.
- **Interactions**: Pan, zoom, hover for details (complexity, calls, security issue count).
- **GUI**: Insights → **Call Graph** tab

### CLI alternatives

- `--show-features` — dump AST features as JSON
- `--show-context` — dump context graph (complexity, calls, variables) as JSON

---

## 4. Evaluation Metrics

ML model quality metrics displayed as charts.

### Metrics

| Metric | What It Measures |
|--------|-----------------|
| BLEU-4 | 4-gram precision of generated vs. reference docstrings |
| ROUGE-L | Longest-common-subsequence F1 score |
| Exact Match | Normalized string equality |

### Charts (GUI)

- **Training Loss Curve** — epoch vs. loss
- **Metrics Bar Chart** — BLEU-4, ROUGE-L, Exact Match as percentages
- **Confidence vs Quality Scatter** — ML confidence vs. BLEU-4

**GUI**: Insights → **Evaluation** tab (auto-populated from `outputs/training_report.json` and `outputs/eval_report.json`)

---

## 5. IR & Pattern Analysis

### IR Dump

Lowered 3-address-code IR (LLVM-IR-inspired format) showing functions, basic blocks, instructions, and edges.

- **CLI**: `--ir`
- **GUI**: Insights → **IR Dump** tab

### Pattern Detection

| Pattern | Severity | What |
|---------|----------|------|
| P001 | warning | Unused variable |
| P002 | warning | High complexity (CC > 10) |
| P003 | info | Dead/unreachable block |
| P004 | info | No return value |
| P005 | warning | Deeply nested loops (≥3) |
| P006 | info | Excessive calls (>10 callees) |
| P007 | info | Missing parameter load |

- **CLI**: `--analysis`
- **GUI**: Insights → **Analysis Report** tab (table with severity coloring)

---

## 6. ML Training

Fine-tunes T5-small on structured AST features paired with docstring sentences.

### Quick Training (smoke test)

```bash
python -m src.main --train --output-dir outputs \
  --codesearchnet-max 20 --max-stdlib-files 10 --epochs 1 --batch-size 2
```

### Medium Quality (RTX 4050)

```bash
python -m src.main --train --output-dir outputs \
  --codesearchnet-max 8000 --max-stdlib-files 600 \
  --epochs 3 --batch-size 8
```

### GUI Training

ML Training workspace → click **Start / Retrain Models**. Progress appears in the bottom Terminal Output console.

### Output

- `outputs/model/ast_model/` — saved model + tokenizer
- `outputs/training_report.json` — dataset stats, loss history
- `outputs/eval_report.json` — BLEU-4, ROUGE-L, exact match

---

## 7. CLI Reference

```bash
python -m src.main <filepath>              # Rule-based generation
python -m src.main <filepath> --ml         # ML generation
python -m src.main <filepath> --neurosymbolic  # Neurosymbolic generation
python -m src.main <filepath> -o out.py    # Write annotated output to file
python -m src.main <filepath> --logs        # Save pipeline logs
python -m src.main <filepath> --show-features   # Print AST features JSON
python -m src.main <filepath> --show-context    # Print context graph JSON
python -m src.main <filepath> --ir              # Print IR dump
python -m src.main <filepath> --analysis       # Print pattern analysis
python -m src.main --train                       # Train ML model
```

### Training Flags

| Flag | Default | What |
|------|---------|------|
| `--epochs` | 4 | Fine-tuning epochs |
| `--batch-size` | 8 | Training batch size |
| `--grad-accum-steps` | 1 | Gradient accumulation steps |
| `--lr` | 2e-4 | Peak learning rate |
| `--codesearchnet-max` | 20000 | Max CodeSearchNet samples |
| `--max-stdlib-files` | 1500 | Max stdlib files to crawl |
| `--no-codesearchnet` | off | Disable CodeSearchNet source |
| `--no-stdlib` | off | Disable stdlib source |
| `--output-dir` | outputs | Output directory |
| `--block-max-pairs` | 20000 | Max inline-comment training pairs |

---

## 8. GUI Workspaces

Launch with `python run_gui.py`. Five workspaces accessible from the sidebar:

### Generator

- Split-pane editor: input code (left), annotated output (right)
- Engine toggle: Rule-Based / Neurosymbolic / ML-Based
- Pick File button to load `.py` files
- **% Unsafe** badge (green/yellow/red)

### Insights (8 tabs)

1. **AST Features** — tree of functions, classes, imports, params, complexity
2. **AST Graph** — interactive tree visualization (pan/zoom/hover)
3. **Context Graph** — tree with complexity coloring + security warnings
4. **Call Graph** — force-directed call graph visualization
5. **IR Dump** — syntax-highlighted IR text
6. **Analysis Report** — pattern findings table
7. **Evaluation** — training loss, metrics bars, confidence scatter charts
8. **Security** — safety pie, severity bars, function scores, issue types charts

### ML Training

- Start / Retrain Models button
- Training status label
- Results area showing BLEU-4, ROUGE-L, Exact Match after completion

### Security

- Module safety score (green/yellow/red)
- % Unsafe indicator
- Four matplotlib charts (safety pie, severity bars, per-function scores, issue types)
- Issues table: severity, pattern ID, function, line, message + remediation

### Logs

- File tree browser for pipeline logs, training outputs, reports
- Syntax-highlighted viewer for JSON and log files
- Refresh Files button to re-scan
