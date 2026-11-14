# Code Comment Generator — Walkthrough

## Architecture Overview

The pipeline: **parse → validate → extract AST features → analyze context → security analysis → generate comments (rule-based / ML / neurosymbolic) → attach → build IR → run analysis (CFG/DFA/patterns)**.

### Runtime Engines

| Engine | Function | Description |
|--------|----------|-------------|
| `Rule-Based` | `generate_comments()` | Deterministic AST-driven generation |
| `AST+NLP ML` | `ml_generate_comments()` | T5 model generates summary from structured AST features |
| `Neurosymbolic` | `neurosymbolic_generate_comments()` | Confidence-gated fusion: ML summary + symbolic Args/Returns/Raises with consistency validation |

### Core Pipeline Files

| File | Purpose |
|------|---------|
| `src/parser_module.py` | Reads source files and builds AST |
| `src/validator.py` | Semantic validation of AST |
| `src/ast_extractor.py` | Extracts structural features from AST |
| `src/ast_body_extractor.py` | Extracts function body snippets, raises, return types |
| `src/context_analyzer.py` | Cyclomatic complexity, variable tracking, call graph, basic security |
| `src/security_analyzer.py` | Comprehensive security pattern detection with scoring |
| `src/comment_generator.py` | Rule-based + ML comment generation |
| `src/comment_attacher.py` | Inserts generated comments into source code |
| `src/ir/` | IR builder, nodes, serializer (Week 8) |
| `src/analysis/` | CFG builder, DFA engine, pattern detector (Week 8) |

### Neurosymbolic Engine Files

| File | Purpose |  
|------|---------|
| `src/neurosymbolic/engine.py` | Confidence-gated fusion engine: ML summary + symbolic validation |
| `src/neurosymbolic/reasoner.py` | Symbolic knowledge base: pattern-to-description rules and constraint solver |

### ML Files

| File | Purpose |
|------|---------|
| `src/ml/ast_feature_formatter.py` | Converts AST/context signals into structured model input text |
| `src/ml/ast_dataset_builder.py` | Builds AST+NLP training pairs from CodeSearchNet + stdlib |
| `src/ml/ast_comment_model.py` | T5-based comment model used for ML generation |
| `src/ml/trainer.py` | Train/evaluate/save flow for AST+NLP |
| `src/ml/evaluator.py` | BLEU-4, ROUGE-L, exact-match |

## Training Data Contract

Every training sample follows:

- `input_text`: structured AST feature text from `ast_feature_formatter`
- `target_text`: first sentence of a function docstring

`training_report.json` explicitly tracks this under:

- `data_profile.input_mode = "AST structured features"`
- `data_profile.target_mode = "NLP docstring sentence"`
- `data_profile.ast_nlp_pairs`

## Output Files

```text
outputs/
├── ast_train_dataset.json
├── ast_train_dataset.csv
├── training_report.json
├── eval_report.json
└── model/
    └── ast_model/
```

## How to Run

```bash
# Train AST+NLP model
python -m src.main --train --output-dir outputs

# Fast smoke-training configuration
python -m src.main --train --output-dir outputs \
  --codesearchnet-max 20 --max-stdlib-files 10 --epochs 1 --batch-size 2

# Rule-based generation
python -m src.main tests/inputs/complex_sample.py

# AST+NLP ML generation
python -m src.main tests/inputs/complex_sample.py --ml

# Neurosymbolic generation (confidence-gated fusion)
python -m src.main tests/inputs/complex_sample.py --neurosymbolic

# Targeted tests
python -m pytest tests/ -q
```

## Neurosymbolic Engine Design

### Confidence-Gated Fusion

The neurosymbolic engine combines neural (ML) and symbolic (rule-based) generation:

1. **ML generates** a natural-language summary + confidence score
2. **If confidence >= threshold** (default 0.4): use ML summary as the docstring lead
3. **If confidence < threshold**: fall back to rule-based summary
4. **In both cases**, the symbolic engine augments with verified structural sections:
   - `Args:` — derived from `FunctionFeature.params` (always accurate)
   - `Returns:` — derived from `FunctionFeature.return_annotation` + inferred types
   - `Raises:` — derived from `ast_body_extractor.extract_raises()`
   - `Security Warnings:` — derived from security analysis
5. **Consistency validation** checks ML summary against AST facts:
   - If ML mentions a return type that conflicts with annotation, flag and use AST version
   - If ML describes control flow that contradicts loop/conditional counts, flag it
   - If ML omits params that exist, the symbolic Args section still lists them

### Symbolic Reasoner

The reasoner provides pattern-to-description rules:
- `1 loop + sorting call` → "Sorts and iterates over items"
- `@property + no params except self` → "Property accessor for..."
- `async + network call` → "Asynchronously fetches..."
- `eval/exec call` → "DANGER: Executes dynamic code"

Constraint solver ensures:
- All parameters are documented in Args section
- Return type section matches annotation
- Raises section matches actual raise statements

## Security Analysis

### Pattern Detection

| ID | Detection | Severity |
|----|-----------|----------|
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

- Per-function score: `100 - (critical*40 + high*25 + medium*5 + low*1)`, clamped 0-100
- **Unsafe** = score < 80 (any high or critical finding makes a function unsafe)
- Module safety = % of functions with score >= 80

## GUI Workspaces

1. **Generator** — code input, engine toggle (Rule/ML/Neurosymbolic), annotated output, % unsafe indicator
2. **Insights** — AST Features tree, Context Graph tree, AST Graph visualization, Call Graph visualization, IR Dump, Analysis Report, Evaluation Charts, Security Charts
3. **ML Training** — train/retrain models, evaluation graphs, metrics dashboard
4. **Security** — module safety score, pie/bar charts, issue table
5. **Logs** — pipeline and training log viewer

## Phase 7 Repository Cleanup

- Removed 33 tracked `.pyc` / `__pycache__/` files from git index (already covered by `.gitignore` `__pycache__/` and `*.py[codz]` rules, but had been accidentally committed)
- Removed 25 tracked pipeline log JSON files from `out/annotated/logs/`
- Removed 2 tracked GUI output files (`gui_annotated.py`, `gui_tmp_in.py`) from `out/annotated/`
- Added `out/` to `.gitignore` — all pipeline output artifacts are now untracked by default

## Phase 1 Bug Fixes Applied

- Removed duplicate `_VERB_MAP` entries (`reset`, `verify`)
- Fixed `_humanize_verb` (undefined function) in `build_full_docstring()` → now uses `_pick_verb(tokens) + _humanize(ff.name)`
- Fixed `warnings` variable shadowing `warnings` module in `main.py` → renamed to `val_warnings`
- Fixed subprocess security check slicing characters instead of lines in `context_analyzer.py`
- Fixed `body_lines = 0` for single-line functions in `ast_extractor.py` → `max(1, end_lineno - lineno)`
- Fixed potential NoneType crash in `ir_builder.py` → added `_link_block()` helper for safe edge creation
- Fixed redundant sanitization order in `_sanitize_docstring_content()` → raw-string prefix check now runs before triple-quote removal
- Updated docstring in `context_analyzer.py` that incorrectly said `source_code` was unused
- Removed dead `Tuple_str` alias from `logger.py`

## Medium Quality Preset (RTX 4050)

```bash
python -m src.main --train \
  --codesearchnet-max 8000 \
  --max-stdlib-files 600 \
  --epochs 3 \
  --batch-size 8 \
  --grad-accum-steps 1
```
