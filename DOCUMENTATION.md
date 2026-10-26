# Code Comment Generator — Complete Documentation

> **Compiler Design Project (SEM 4)** — An AST-driven, NLP-augmented Python docstring and comment generation system with static analysis, security scanning, and a full GUI.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Directory Structure](#3-directory-structure)
4. [Pipeline Stages](#4-pipeline-stages)
5. [Core Modules](#5-core-modules)
   - 5.1 [parser_module](#51-parser_module)
   - 5.2 [validator](#52-validator)
   - 5.3 [error_handler](#53-error_handler)
   - 5.4 [ast_extractor](#54-ast_extractor)
   - 5.5 [ast_body_extractor](#55-ast_body_extractor)
   - 5.6 [context_analyzer](#56-context_analyzer)
   - 5.7 [comment_generator](#57-comment_generator)
   - 5.8 [comment_attacher](#58-comment_attacher)
   - 5.9 [security_analyzer](#59-security_analyzer)
   - 5.10 [logger](#510-logger)
6. [Intermediate Representation (IR)](#6-intermediate-representation-ir)
   - 6.1 [ir_nodes](#61-ir_nodes)
   - 6.2 [ir_builder](#62-ir_builder)
   - 6.3 [ir_serializer](#63-ir_serializer)
7. [Static Analysis](#7-static-analysis)
   - 7.1 [cfg_builder](#71-cfg_builder)
   - 7.2 [dfa_engine](#72-dfa_engine)
   - 7.3 [pattern_detector](#73-pattern_detector)
8. [Machine Learning (ML)](#8-machine-learning-ml)
   - 8.1 [ast_feature_formatter](#81-ast_feature_formatter)
   - 8.2 [ast_dataset_builder](#82-ast_dataset_builder)
   - 8.3 [ast_comment_model](#83-ast_comment_model)
   - 8.4 [trainer](#84-trainer)
   - 8.5 [evaluator](#85-evaluator)
9. [Neurosymbolic Engine](#9-neurosymbolic-engine)
   - 9.1 [reasoner](#91-reasoner)
   - 9.2 [engine](#92-engine)
10. [Graphical User Interface (GUI)](#10-graphical-user-interface-gui)
    - 10.1 [main_window](#101-main_window)
    - 10.2 [generator_workspace](#102-generator_workspace)
    - 10.3 [training_workspace](#103-training_workspace)
    - 10.4 [insights_workspace](#104-insights_workspace)
    - 10.5 [security_workspace](#105-security_workspace)
    - 10.6 [logs_workspace](#106-logs_workspace)
    - 10.7 [theme](#107-theme)
    - 10.8 [widgets](#108-widgets)
    - 10.9 [syntax_highlighter](#109-syntax_highlighter)
    - 10.10 [Graph Widgets](#1010-graph-widgets)
11. [CLI Reference](#11-cli-reference)
12. [Data Structures Reference](#12-data-structures-reference)
13. [Security Analysis Patterns](#13-security-analysis-patterns)
14. [Pattern Detection Codes](#14-pattern-detection-codes)
15. [Testing](#15-testing)
16. [Output Artifacts](#16-output-artifacts)
17. [Dependencies](#17-dependencies)
18. [Running the Project](#18-running-the-project)
19. [Design Decisions](#19-design-decisions)
20. [License](#20-license)

---

## 1. Project Overview

**Code Comment Generator** is a multi-engine Python documentation tool that automatically generates docstrings and inline comments for Python source code. It combines compiler-design principles (AST parsing, IR generation, data-flow analysis) with NLP/AI techniques (T5-based sequence-to-sequence modeling) to produce rich, context-aware comments.

### Three Generation Engines

| Engine | Description | Requires Training |
|---|---|---|
| **Rule-Based** | Deterministic AST-driven comment generation. Always available. Uses verb maps, body analysis, and complexity metrics to produce Google-style docstrings. | No |
| **AST+NLP ML** | Fine-tuned T5-small model that maps structured AST feature text to natural-language docstring summaries. Args/Returns/Raises sections are still filled from AST. | Yes |
| **Neurosymbolic** | Confidence-gated fusion: ML summary when confidence >= threshold, symbolic fallback otherwise. Consistency validation between ML output and AST facts. Symbolic rules enrich warnings. | Yes |

### Key Capabilities

- **AST Feature Extraction**: Parses Python source into rich structural features (loops, conditionals, calls, decorators, complexity, variables, raises).
- **Context Analysis**: Computes cyclomatic complexity, tracks variable lifespans, builds call graphs, and performs basic type inference.
- **IR Generation**: Lowers AST features into a 3-address-code intermediate representation with basic blocks, control-flow edges, and SSA-style phi nodes.
- **Control-Flow Graph (CFG)**: Constructs CFGs from IR for each function.
- **Data-Flow Analysis (DFA)**: Implements reaching definitions (forward) and live variable analysis (backward) using worklist algorithms.
- **Pattern Detection**: Identifies 7 code-quality patterns (unused variables, high complexity, dead blocks, missing returns, deep nesting, excessive calls, missing param loads).
- **Security Analysis**: Interprocedural, per-context taint analysis over the real IR/CFG (SQL injection, command injection, XSS, path traversal, template injection, code injection, unsafe deserialization) plus AST rules (hardcoded secrets, weak hashes, bare except, mutable defaults, assert, insecure random, hardcoded IPs). Every finding carries CWE, severity, confidence, status and a source-to-sink evidence trace on original source lines. See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md).
- **ML Pipeline**: Builds datasets from CodeSearchNet + Python stdlib, fine-tunes T5-small on (AST feature text -> docstring) pairs, evaluates with BLEU-4/ROUGE-L/Exact Match.
- **Neurosymbolic Fusion**: Gated combination of ML and symbolic generation with consistency validation.
- **Docstring Safety**: Automatic sanitization prevents malformed docstrings (triple-quote escaping, raw string prefix removal).
- **GUI**: Full PyQt6 desktop application with generator, insights, ML training, security, and logs workspaces.
- **Structured Logging**: JSON + text pipeline logs with per-stage timing.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Code Comment Generator                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   │
│  │  Parse    │──▶│ Validate │──▶│ Extract  │──▶│ Analyze  │   │
│  │ (AST)    │   │ (Rules)  │   │ (Feats)  │   │ (Context)│   │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘   │
│                                                    │             │
│                    ┌───────────────────────────────┤             │
│                    │               │               │             │
│                    ▼               ▼               ▼             │
│           ┌────────────┐  ┌────────────┐  ┌────────────┐       │
│           │ Rule-Based │  │  ML (T5)   │  │Neurosym-   │       │
│           │ Generator  │  │ Generator  │  │bolic Gen.  │       │
│           └────────────┘  └────────────┘  └────────────┘       │
│                    │               │               │             │
│                    └───────────────┼───────────────┘           │
│                                    ▼                             │
│                           ┌────────────┐                        │
│                           │  Attach    │                        │
│                           │ (Insert)   │                        │
│                           └────────────┘                        │
│                                    │                             │
│              ┌─────────────────────┼─────────────────────┐     │
│              ▼                     ▼                     ▼     │
│      ┌────────────┐      ┌────────────┐      ┌────────────┐  │
│      │ Build IR   │      │  Security  │      │   Logger   │  │
│      │ (3-addr)   │      │ Analysis   │      │ (JSON/TXT) │  │
│      └────────────┘      └────────────┘      └────────────┘  │
│              │                                                 │
│              ▼                                                 │
│      ┌────────────┐      ┌────────────┐                      │
│      │Build CFG   │─────▶│  Run DFA   │                      │
│      └────────────┘      └────────────┘                      │
│              │                     │                           │
│              └──────────┬──────────┘                           │
│                         ▼                                      │
│                 ┌────────────┐                                │
│                 │  Detect    │                                │
│                 │  Patterns  │                                │
│                 └────────────┘                                │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    GUI (PyQt6)                            │  │
│  │  Generator │ Insights │ ML Training │ Security │ Logs    │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Directory Structure

```
CodeCommentGenerator/
├── run_gui.py                    # GUI entry point
├── src/
│   ├── __init__.py
│   ├── main.py                   # CLI entry point & pipeline orchestrator
│   ├── parser_module.py          # Source file reader & AST parser
│   ├── validator.py              # Semantic AST validator (naming conventions)
│   ├── error_handler.py          # Custom exceptions & formatting
│   ├── ast_extractor.py          # AST feature extractor (Week 7 core)
│   ├── ast_body_extractor.py     # Function body / raises / return extraction
│   ├── context_analyzer.py       # Cyclomatic complexity, variables, call graph
│   ├── comment_generator.py      # Rule-based + ML comment generation
│   ├── comment_attacher.py       # Insert comments into source code
│   ├── security_analyzer.py      # Security anti-pattern detection
│   ├── logger.py                 # Structured pipeline logging
│   │
│   ├── ir/
│   │   ├── __init__.py
│   │   ├── ir_nodes.py           # IR data structures (IRModule, IRFunction, etc.)
│   │   ├── ir_builder.py         # AST features → IR lowering
│   │   └── ir_serializer.py     # IR → JSON / pretty-print text
│   │
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── cfg_builder.py        # CFG from IR
│   │   ├── dfa_engine.py         # Reaching defs + live variable analysis
│   │   └── pattern_detector.py   # Code smell / pattern detection
│   │
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── ast_feature_formatter.py  # AST features → model input text
│   │   ├── ast_dataset_builder.py    # CodeSearchNet + stdlib dataset
│   │   ├── ast_comment_model.py      # T5-small fine-tuning & inference
│   │   ├── trainer.py                # End-to-end train/eval pipeline
│   │   └── evaluator.py             # BLEU-4, ROUGE-L, Exact Match
│   │
│   ├── neurosymbolic/
│   │   ├── __init__.py
│   │   ├── reasoner.py               # Symbolic rule base + consistency validation
│   │   └── engine.py                 # Confidence-gated ML + symbolic fusion
│   │
│   └── gui/
│       ├── __init__.py
│       ├── main_window.py            # Top-level window & navigation
│       ├── generator_workspace.py    # Code input/output & generation
│       ├── training_workspace.py     # ML training dashboard
│       ├── insights_workspace.py     # Feature/context/IR visualization
│       ├── security_workspace.py     # Security report display
│       ├── logs_workspace.py         # Pipeline log viewer
│       ├── theme.py                  # Global stylesheet
│       ├── widgets.py                # Custom widgets (SpinningButton, Toast)
│       ├── syntax_highlighter.py     # Python syntax highlighting
│       ├── ast_graph_widget.py       # AST tree visualization
│       ├── context_graph_widget.py   # Context graph visualization
│       ├── security_graph_widget.py  # Security chart visualization
│       └── eval_graph_widget.py      # Evaluation metrics chart
│
├── tests/
│   ├── __init__.py
│   ├── test_basic.py                 # Parser & validator tests
│   ├── test_core_engine.py           # AST extractor, context, generator, attacher
│   ├── test_ir.py                    # IR nodes, builder, serializer
│   ├── test_analysis.py              # CFG, DFA, pattern detector
│   ├── test_ast_nlp_model.py         # ML dataset builder, formatter, model
│   ├── inputs/
│   │   ├── complex_sample.py         # Test input: complex code
│   │   ├── test_security.py          # Test input: security patterns
│   │   └── demo_showcase.py          # Test input: demo code
│   ├── outputs/
│   │   ├── annotated_complex.py      # Expected output
│   │   ├── annonated_code.py         # Expected output
│   │   └── analysis_report.json      # Expected analysis report
│   └── logs/                         # Test pipeline logs
│
├── outputs/                          # Training outputs (gitignored)
│   ├── model/
│   │   ├── ast_model/               # Trained T5 model
│   │   └── codet5/                  # Alternative CodeT5 model
│   ├── ast_train_dataset.json/csv   # Saved training datasets
│   ├── training_report.json         # Training metadata
│   └── eval_report.json             # Evaluation metrics
│
├── README.md
├── LICENSE                           # MIT License
└── .gitignore
```

---

## 4. Pipeline Stages

The full pipeline is executed by `src/main.py:run_pipeline()` and consists of 9 sequential stages:

| Stage | Name | Module | Description |
|---|---|---|---|
| 1 | **parse** | `parser_module` | Read source file, parse to AST via `ast.parse()` |
| 2 | **validate** | `validator` | Check naming conventions (snake_case functions, CamelCase classes, arg count) |
| 3 | **extract** | `ast_extractor` | Walk AST to extract `ModuleFeatures` — functions, classes, imports, loops, conditionals, calls, decorators |
| 4 | **analyze** | `context_analyzer` | Compute cyclomatic complexity, variable tracking, call graph; security warnings taken from `src/security` → `ContextGraph` |
| 5 | **generate** | `comment_generator` / neurosymbolic | Generate docstrings + inline comments using rule-based, ML, or neurosymbolic engine |
| 6 | **attach** | `comment_attacher` | Insert generated comments into original source at correct positions with proper indentation |
| 7 | **build_ir** | `ir_builder` → `ir.lowering` | Lower the real AST of each function into `IRModule` (3-address code with basic blocks, source line/col on every instruction) |
| 8 | **analysis** | `cfg_builder` + `dfa_engine` + `pattern_detector` | Build CFG, run DFA (reaching defs + live vars), detect code quality patterns |
| 9 | **security** | `security_analyzer` → `src/security` | Taint + AST security analysis of the *original* source (15 rules) → `SecurityReport` |

---

## 5. Core Modules

### 5.1 parser_module

**File**: `src/parser_module.py` (33 lines)

Responsible for reading Python source files and parsing them into AST trees.

#### Functions

| Function | Signature | Description |
|---|---|---|
| `read_file` | `(filepath: str) -> str` | Reads a Python source file. Raises `ParserError` on `FileNotFoundError` or IO errors. |
| `parse_code` | `(source_code: str) -> ast.AST` | Parses source code string into a Python AST via `ast.parse()`. Raises `ParserError` on `SyntaxError`. |

#### Error Handling

- `FileNotFoundError` → `ParserError("File not found: ...")`
- `SyntaxError` → `ParserError("Syntax error: ...", line=..., column=...)`
- Other exceptions → `ParserError("Unexpected error during parsing: ...")`

---

### 5.2 validator

**File**: `src/validator.py` (51 lines)

Performs semantic validation on the parsed AST, checking Python naming conventions.

#### Class: `SemanticValidator(ast.NodeVisitor)`

Visits AST nodes and collects style/semantic violations.

| Visit Method | Rule | Error Message Pattern |
|---|---|---|
| `visit_FunctionDef` | Function names must be `snake_case` | `"Function '{name}' should be snake_case."` |
| `visit_FunctionDef` | Max 10 arguments | `"Function '{name}' has too many arguments ({n} > 10)."` |
| `visit_AsyncFunctionDef` | Same as `FunctionDef` | (delegated) |
| `visit_ClassDef` | Class names must start with uppercase (`CamelCase`) | `"Class '{name}' should be CamelCase (start with uppercase)."` |

#### Public API

| Function | Signature | Description |
|---|---|---|
| `validate_ast` | `(tree: ast.AST) -> List[ParserError]` | Run the semantic validator on an AST and return a list of violations. |

---

### 5.3 error_handler

**File**: `src/error_handler.py` (48 lines)

Defines custom exception hierarchy and error formatting utilities for the pipeline.

#### Exception Classes

| Exception | Purpose | Special Attributes |
|---|---|---|
| `ParserError` | Parsing and validation errors | `message`, `line`, `column` |
| `ExtractionError` | AST feature extraction failures | `message`, `node_type` |
| `CommentGenerationError` | Comment generation failures | `message`, `node_id` |

#### Functions

| Function | Signature | Description |
|---|---|---|
| `format_error` | `(error: Exception) -> str` | Formats any pipeline error into a readable string with location info when available. |

---

### 5.4 ast_extractor

**File**: `src/ast_extractor.py` (303 lines)

The **Week 7 core engine** — traverses the Python AST and extracts rich structural features for every function, class, loop, and conditional block.

#### Data Classes

**`ParamFeature`** — One function parameter:
| Field | Type | Description |
|---|---|---|
| `name` | `str` | Parameter name |
| `annotation` | `Optional[str]` | Type annotation (e.g., `"int"`, `"List[str]"`) |
| `default` | `Optional[str]` | Default value as a string (e.g., `"5"`, `"None"`) |

**`FunctionFeature`** — One function/method:
| Field | Type | Description |
|---|---|---|
| `node_id` | `str` | Unique identifier: `"func_{name}_{lineno}"` |
| `name` | `str` | Function name |
| `lineno` | `int` | Source line number |
| `col_offset` | `int` | Column offset (indentation) |
| `params` | `List[ParamFeature]` | Parameter list |
| `return_annotation` | `Optional[str]` | Return type annotation |
| `decorators` | `List[str]` | Decorator expressions |
| `has_docstring` | `bool` | Whether function already has a docstring |
| `docstring` | `Optional[str]` | Existing docstring text |
| `body_lines` | `int` | Number of body lines |
| `calls_made` | `List[str]` | All function calls in the body |
| `loops` | `int` | Number of for/while loops |
| `conditionals` | `int` | Number of if/elif branches |
| `is_method` | `bool` | True if defined inside a class |
| `parent_class` | `Optional[str]` | Name of the enclosing class |
| `is_async` | `bool` | True if `async def` |

**`ClassFeature`** — One class:
| Field | Type | Description |
|---|---|---|
| `node_id` | `str` | Unique identifier: `"class_{name}_{lineno}"` |
| `name` | `str` | Class name |
| `lineno` | `int` | Source line number |
| `col_offset` | `int` | Column offset |
| `bases` | `List[str]` | Base class names |
| `methods` | `List[str]` | Method names defined in the class |
| `class_variables` | `List[str]` | Class-level variable names |
| `has_docstring` | `bool` | Whether class has a docstring |
| `docstring` | `Optional[str]` | Existing docstring text |

**`ModuleFeatures`** — Top-level container:
| Field | Type | Description |
|---|---|---|
| `filepath` | `str` | Source file path |
| `imports` | `List[str]` | Import statements |
| `global_vars` | `List[str]` | Module-level variable names |
| `functions` | `List[FunctionFeature]` | All extracted functions |
| `classes` | `List[ClassFeature]` | All extracted classes |
| `total_lines` | `int` | Total source lines |

#### Class: `FeatureExtractor(ast.NodeVisitor)`

The main AST visitor that populates `ModuleFeatures`.

**Visited nodes:**
- `visit_Import` — captures top-level imports
- `visit_ImportFrom` — captures from-imports
- `visit_Assign` — captures module-level variable assignments
- `visit_ClassDef` — extracts class features, tracks class context for method detection
- `visit_FunctionDef` / `visit_AsyncFunctionDef` — extracts function features via `_extract_function()`

**Internal helpers:**
- `_annotation_to_str(node)` — Converts AST annotation to readable string via `ast.unparse()`
- `_default_to_str(node)` — Converts default value node to string
- `_collect_calls(body)` — Walks function body to collect all `ast.Call` function names
- `_count_branches(body)` — Counts loops (`For`/`While`/`AsyncFor`) and conditionals (`If`)

#### Public API

| Function | Signature | Description |
|---|---|---|
| `extract_features` | `(tree, source_code="", filepath="") -> ModuleFeatures` | Main entry point: creates a `FeatureExtractor` and runs it. |
| `features_to_dict` | `(mf: ModuleFeatures) -> Dict` | Serialize `ModuleFeatures` to JSON-compatible dict. |

---

### 5.5 ast_body_extractor

**File**: `src/ast_body_extractor.py` (226 lines)

Extracts clean function body snippets, raised exceptions, and return types from raw source code using line-number information from `FunctionFeature`.

#### Functions

| Function | Signature | Description |
|---|---|---|
| `extract_body_snippet` | `(source_code, lineno, end_lineno, max_lines=15) -> str` | Extracts the function body as a clean text snippet. Strips the existing docstring, dedents, and limits to `max_lines`. Falls back to raw line slicing on parse errors. |
| `extract_raises` | `(source_code, lineno, end_lineno) -> List[str]` | Returns deduplicated list of exception types raised explicitly in the function body (e.g., `["ValueError", "IOError"]`). |
| `extract_returned_types` | `(source_code, lineno, end_lineno) -> List[str]` | Returns best-effort list of types/values returned by the function. Infers from `return` statement expressions. |

#### Return Type Inference Heuristics

| Expression Type | Inferred Type |
|---|---|
| `ast.Constant` | `type(value).__name__` (e.g., `"int"`, `"str"`) |
| `ast.List` | `"list"` |
| `ast.Dict` | `"dict"` |
| `ast.Set` | `"set"` |
| `ast.Tuple` | `"tuple"` |
| `ast.JoinedStr` (f-string) | `"str"` |
| `ast.Call` | Function name from `ast.unparse(node.func)` |
| `ast.Name` | Variable name (`node.id`) |
| `ast.BoolOp` | `"bool"` |
| `ast.Compare` | `"bool"` |

---

### 5.6 context_analyzer

**File**: `src/context_analyzer.py` (299 lines)

Enriches `ModuleFeatures` with semantic analysis: cyclomatic complexity, variable lifespan tracking, call graphs, type inference, and basic security issue detection.

#### Data Classes

**`VariableInfo`** — A tracked variable:
| Field | Type | Description |
|---|---|---|
| `name` | `str` | Variable name |
| `assigned_at` | `List[int]` | Line numbers where assigned |
| `used_at` | `List[int]` | Line numbers where read |
| `inferred_type` | `Optional[str]` | Heuristically inferred type |

**`FunctionContext`** — Enriched context for one function:
| Field | Type | Description |
|---|---|---|
| `node_id` | `str` | Unique identifier |
| `name` | `str` | Function name |
| `cyclomatic_complexity` | `int` | McCabe cyclomatic complexity (default 1) |
| `variables` | `List[VariableInfo]` | Tracked variables |
| `calls_external` | `List[str]` | Calls to non-module functions |
| `calls_internal` | `List[str]` | Calls to other module functions |
| `complexity_label` | `str` | One of: `"simple"`, `"moderate"`, `"complex"`, `"very_complex"` |
| `security_issues` | `List[str]` | Basic security warnings |

**`ContextGraph`** — Module-level context:
| Field | Type | Description |
|---|---|---|
| `module_name` | `str` | Source file path |
| `function_contexts` | `List[FunctionContext]` | All function contexts |
| `call_graph` | `Dict[str, List[str]]` | Map: caller → [callees] |
| `module_function_names` | `Set[str]` | All function names in the module |

#### Cyclomatic Complexity

Computed by `CyclomaticComplexityVisitor`, which counts:
- Start at 1
- +1 for each: `If`, `For`, `While`, `AsyncFor`, `ExceptHandler`, `With`, `Assert`, `comprehension`
- +1 for each additional `and`/`or` operand in `BoolOp`

#### Complexity Labels

| Complexity Score | Label |
|---|---|
| 1–2 | `simple` |
| 3–5 | `moderate` |
| 6–10 | `complex` |
| 11+ | `very_complex` |

#### Variable Tracker

`VariableTracker(ast.NodeVisitor)` tracks:
- Assignments via `visit_Assign` and `visit_AnnAssign`
- Usage via `visit_Name` (when `ctx` is `Load`)
- Type inference from RHS literals (constants → type name, list/dict/set/tuple → type name, calls → function name)

#### Security warnings (from the central analyzer)

`FunctionContext.security_issues` is filled from `src.security.analyze_source`
(the same rules as the Security tab), formatted as
`"<title> (<rule>, line N; <status>, <confidence> confidence)"`. The context
analyzer no longer has its own security checks. Pass `include_security=False`
to skip the analysis (the ML dataset builder and feature formatter do; ML
features never use these strings).

#### Public API

| Function | Signature | Description |
|---|---|---|
| `analyze_context` | `(module_features, ast_tree, source_code="", include_security=True) -> ContextGraph` | Main entry: produces a `ContextGraph` from `ModuleFeatures`. |
| `compute_cyclomatic_complexity` | `(func_node_body) -> int` | Standalone complexity computation. |
| `context_to_dict` | `(cg: ContextGraph) -> Dict` | Serialize `ContextGraph` to JSON-compatible dict. |

---

### 5.7 comment_generator

**File**: `src/comment_generator.py` (807 lines)

The heart of comment generation — two complementary strategies:

1. **Rule-Based Engine** (always available): Deterministic, AST-driven. Produces Google-style docstrings with Args/Returns/Raises sections.
2. **ML Engine**: Activated via `ml_generate_comments()`. Feeds structured AST features into a fine-tuned T5 model.

#### Output Data Class

**`CommentItem`** — A single generated comment:
| Field | Type | Description |
|---|---|---|
| `node_id` | `str` | Target node identifier |
| `node_type` | `str` | `"function"`, `"class"`, or `"inline"` |
| `lineno` | `int` | Line before which the comment should be inserted |
| `col_offset` | `int` | Indentation of the target node |
| `text` | `str` | Full comment text (may be multi-line docstring) |
| `kind` | `str` | `"docstring"`, `"inline"`, or `"block"` |
| `target_name` | `str` | Name of the target function/class |

#### NLP Utilities

- **`_split_identifier(name)`** — Splits `snake_case` and `CamelCase` into lowercase tokens
- **`_meaningful_tokens(name)`** — Returns non-stop-word tokens from an identifier
- **`_pick_verb(tokens)`** — Maps first meaningful token to a verb phrase using `_VERB_MAP` (150+ entries, e.g., `"get"` → `"Retrieves"`, `"calculate"` → `"Calculates"`)
- **`_humanize(name)`** — Turns an identifier into a readable phrase
- **`_sanitize_docstring_content(text)`** — Prevents malformed docstrings by escaping triple quotes, removing raw string prefixes

#### Rule-Based Docstring Generation

**`_generate_function_docstring(ff, fc, source_code)`** produces:

1. **Summary line**: `{verb} {noun_phrase}.` (e.g., `"Calculates sum of two integers."`)
2. **Async prefix**: `"Asynchronously ..."` for async functions
3. **Body analysis** (`_describe_body`):
   - Loop count
   - Conditional branch count
   - Cyclomatic complexity + label (with refactoring suggestions for complex functions)
   - Internal/external call delegation
   - Data structure types used
   - Raised exceptions
   - Decorator descriptions (`@property`, `@staticmethod`, `@classmethod`, `@abstractmethod`, cache decorators)
   - Body length warnings (>50 lines)
4. **Args section**: Each parameter with type annotation and default value
5. **Returns section**: From annotation or inferred return types
6. **Raises section**: Exception types from `extract_raises()`
7. **Security Warnings**: From `FunctionContext.security_issues`

**`_generate_class_docstring(cf, source_code)`** produces:
1. `"Represents a {noun_phrase}."`
2. Inheritance info
3. Attributes section (public and private class variables)
4. Methods section (with verb descriptions)

**`_generate_inline_comment(ff, fc, source_code)`** produces a block comment for non-simple functions:
- Summary with complexity info
- Body summary (loops, conditionals, calls)
- Cyclomatic complexity score and label
- Raised exceptions
- Security warnings

#### ML Generation

**`ml_generate_comments(module_features, context_graph, ast_model, source_code, strict_ml)`**:
- For each undocumented function, calls `ast_model.generate(ff, fc, raises)` to get an ML summary
- Wraps the ML summary into a full docstring via `build_full_docstring()` (which adds Args/Returns/Raises from AST)
- Falls back to rule-based if model is unavailable (unless `strict_ml=True`)
- Security inline comments are added for functions with security issues

**`build_full_docstring(summary, ff, fc, source_code, raises)`**:
- Takes an ML-generated summary and augments it with AST-derived Args/Returns/Raises sections
- Ensures structured sections always come from AST analysis (deterministic accuracy)

---

### 5.8 comment_attacher

**File**: `src/comment_attacher.py` (130 lines)

Inserts generated `CommentItem` objects back into the original source code.

#### Output Data Class

**`AttachResult`**:
| Field | Type | Description |
|---|---|---|
| `annotated_source` | `str` | The annotated source code |
| `diff_log` | `List[str]` | Human-readable diff lines showing insertions |
| `comments_attached` | `int` | Count of comments successfully inserted |
| `line_map` | `Dict[int, int]` | Annotated line → original line (inserted lines are absent) |
| `skipped` | `int` | Docstrings not inserted because the body starts on the `def` line |

Helpers: `to_original_line(n)`, `to_annotated_line(n)`.

#### Insertion Strategy

| Comment Kind | Insertion Point | Indentation |
|---|---|---|
| `docstring` | **Before the first body statement** (correct for multi-line signatures) | that statement's indentation |
| `inline` / `block` | **Before** the `def`/`class` line | `col_offset` spaces |

One-line bodies (`def f(): return 1`) are left unchanged and noted in `diff_log`.
Earlier versions inserted docstrings directly after the `def` line, which
produced invalid Python for multi-line signatures (regression test in
`tests/test_location_integrity.py`).

#### Algorithm

1. Parse the source to find each function/class body's first statement
2. Build an insertion map: `{0-indexed line → [lines to insert before]}`
3. Rebuild source by iterating through original lines, inserting at marked
   positions and recording `line_map`

Security analysis always runs on the original source; `line_map` translates
between original and annotated line numbers.

---

### 5.9 security_analyzer

**File**: `src/security_analyzer.py`

Adapter that keeps the `SecurityReport` / `SecurityIssue` interface used by the
CLI pipeline and the GUI. All issues come from `src.security.analyze_source`
(taint analysis + AST rules) run on the original source — see
[SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md). Suppressed findings are kept in
`SecurityReport.suppressed` and excluded from scores.

#### Data Classes

**`SecurityIssue`**:
| Field | Type | Description |
|---|---|---|
| `pattern_id` | `str` | Pattern code (e.g., `"SEC001"`) |
| `severity` | `str` | `"critical"`, `"high"`, `"medium"`, or `"low"` |
| `function_name` | `str` | Function where found |
| `message` | `str` | Human-readable description |
| `lineno` | `int` | Source line of the sink / offending node (original file) |
| `remediation` | `str` | Suggested fix |
| `title`, `cwe` | `str` | Rule title and CWE id |
| `confidence` | `str` | `high` / `medium` / `low` (see SECURITY_ANALYSIS.md §3) |
| `status` | `str` | `confirmed` / `potential` |
| `col` | `int` | Source column |
| `trace` | `List[str]` | Evidence trace lines (`L<line> [<kind>] <text>`) |
| `confidence_reasons` | `List[str]` | Factors that determined the confidence |

**`SecurityReport`**:
| Field | Type | Description |
|---|---|---|
| `function_scores` | `Dict[str, float]` | Safety score per function (0–100) |
| `module_safe_pct` | `float` | Percentage of functions scoring >= 80 |
| `total_issues` | `int` | Total security issues found |
| `by_severity` | `Dict[str, int]` | Issue count by severity |
| `issues` | `List[SecurityIssue]` | Active (non-suppressed) issues |
| `suppressed` | `List[SecurityIssue]` | Suppressed issues with reasons |
| `by_status` | `Dict[str, int]` | Counts by status |
| `findings` | `List[Finding]` | Full `src.security` findings (schema in SECURITY_ANALYSIS.md) |

#### Scoring

- **Critical** issues: -30 points
- **High** issues: -15 points
- **Medium** issues: -5 points
- **Low** issues: -1 point
- Score = `max(0, 100 - total_penalty)`
- Module safe % = `count(scores >= 80) / count(all_scores) * 100`

#### Public API

| Function | Signature | Description |
|---|---|---|
| `run_security_analysis` | `(module_features, context_graph=None, source_code="") -> SecurityReport` | Analyse the original source with `src.security`. |
| `src.security.analyze_source` | `(source, filepath="<string>") -> SecurityFindings` | Standalone analysis (no comment generation, no ML). |

---

### 5.10 logger

**File**: `src/logger.py` (126 lines)

Structured logging for all pipeline stages. Writes both JSON (machine-readable) and text (human-readable) logs.

#### Data Classes

**`StageLog`**: Records one pipeline stage:
| Field | Type | Description |
|---|---|---|
| `stage` | `str` | Stage name |
| `duration_ms` | `float` | Duration in milliseconds |
| `summary` | `Dict[str, Any]` | Stage-specific summary data |
| `warnings` | `List[str]` | Warnings encountered |

**`PipelineLog`**: Complete pipeline log:
| Field | Type | Description |
|---|---|---|
| `input_file` | `str` | Source file path |
| `timestamp` | `str` | ISO format timestamp |
| `stages` | `List[StageLog]` | All stage logs |
| `total_duration_ms` | `float` | Total pipeline duration |
| `comments_generated` | `int` | Number of comments generated |
| `output_file` | `Optional[str]` | Output file path |

#### Class: `PipelineLogger`

| Method | Description |
|---|---|
| `begin_stage(stage_name)` | Mark start of a pipeline stage |
| `end_stage(summary, warnings)` | Mark end, record timing |
| `set_comments_generated(count)` | Record comment count |
| `set_output_file(path)` | Record output path |
| `finalize() -> PipelineLog` | Compute total duration |
| `save(logs_dir) -> (json_path, text_path)` | Write JSON and text logs to disk |

---

## 6. Intermediate Representation (IR)

### 6.1 ir_nodes

**File**: `src/ir/ir_nodes.py`

Defines the language-agnostic, 3-address-code style IR hierarchy.

#### Hierarchy

```
IRModule
  └── IRFunction (one per Python function)
        └── IRBlock (one per basic block)
              └── IRInstruction (one 3-address-code instruction)
```

#### IROpcode Enum

| Opcode | Meaning | Example |
|---|---|---|
| `ASSIGN` | Variable assignment | `t0 = ASSIGN(x)` |
| `LOAD` | Load variable into temp | `t0 = LOAD(param_name)` |
| `STORE` | Store temp into variable | `STORE(name, t0)` |
| `BINOP` | Binary operation | `t0 = lhs op rhs` |
| `UNOP` | Unary operation | `t0 = op src` |
| `CALL` | Function call | `t0 = call f(args)` |
| `RETURN` | Function return | `return val` |
| `BRANCH` | Conditional jump | `branch cond, L1, L2` |
| `JUMP` | Unconditional jump | `jump L` |
| `LABEL` | Block header label | `label L` |
| `PHI` | SSA phi node | `t0 = phi(t1, t2)` |
| `NOP` | No-operation placeholder | `nop` |

#### IRInstruction

| Field | Type | Description |
|---|---|---|
| `op` | `IROpcode` | Operation code |
| `result` | `Optional[str]` | Destination temporary name |
| `operands` | `List[str]` | Source operands |
| `lineno` | `int` | Source line number |
| `meta` | `Dict[str, str]` | Free-form metadata (operator, callee, etc.) |

#### IRBlock

| Field | Type | Description |
|---|---|---|
| `label` | `str` | Unique block identifier (e.g., `"entry"`, `"loop_0_header"`) |
| `instructions` | `List[IRInstruction]` | Ordered instruction list |
| `successors` | `List[str]` | Labels of successor blocks |
| `predecessors` | `List[str]` | Labels of predecessor blocks |

**Property** `terminator`: Returns the last instruction if it's a `BRANCH`, `JUMP`, or `RETURN`; otherwise `None`.

#### IRFunction

| Field | Type | Description |
|---|---|---|
| `name` | `str` | Function name |
| `params` | `List[str]` | Parameter names |
| `return_type` | `Optional[str]` | Return type annotation |
| `is_method` | `bool` | True if class method |
| `is_async` | `bool` | True if async |
| `blocks` | `List[IRBlock]` | Ordered blocks; `blocks[0]` is entry |
| `source_lineno` | `int` | Source line number |

#### IRModule

| Field | Type | Description |
|---|---|---|
| `source_file` | `str` | Source file path |
| `functions` | `List[IRFunction]` | All IR functions |

---

### 6.2 ir_builder

**File**: `src/ir/ir_builder.py`

Returns one `IRFunction` per `FunctionFeature`, lowered from the real AST by
`src/ir/lowering.py` (the tree recorded by `extract_features`).

> The original builder synthesised blocks from loop/conditional *counts* with
> placeholder operands and linked blocks before appending them (so branch
> blocks had no predecessors). It was replaced because no downstream analysis
> could be correct on that IR.

#### Lowering (`ir.lowering`)

| Construct | IR |
|---|---|
| assignment / unpacking / augmented | `x = ASSIGN(t)`, `SUBSCR` per element, `x = BINOP(x, t)` |
| attribute / subscript store | `STORE(value, base[, index])` |
| expressions | `BINOP`, `UNOP`, `ATTR`, `SUBSCR`, `BUILD` (list/dict/f-string/comprehension), constants as `ASSIGN` with `meta.const` |
| call | `CALL` with `CallInfo` (canonical callee after import-alias resolution, receiver, args, keywords, literal kwargs) |
| `if`/`elif`/`else` | `BRANCH` (+ validation `Refinement`s) → `branch_N_true` / `branch_N_false` → `branch_N_join` |
| `while` / `for` (+`else`) | `loop_N_header` (`BRANCH`) → `loop_N_body` (back-edge) → `loop_N_after`; `break`/`continue` jump to after/header |
| `return` / `raise` / no-return calls | `__return__ = v`; jump to the single `exit` block |
| `try`/`except`/`finally` | every try-body block has an edge to each handler |
| nested `def` | `MAKEFUNC` with captured variables; lowered as `outer.inner` |

Every instruction has `lineno`, `col`, `guards` (enclosing conditions) and a
function-unique `uid`. Approximated constructs are listed in
`IRFunction.unsupported`.

#### Public API

| Function | Signature | Description |
|---|---|---|
| `build_ir` | `(module_features, context_graph=None, ast_tree=None, source_code=None) -> IRModule` | One IRFunction per FunctionFeature. |
| `lower_module` | `(tree, source="", filepath="") -> IRModule` | All functions, methods, nested functions and the `<module>` body. |

---

### 6.3 ir_serializer

**File**: `src/ir/ir_serializer.py`

Two output formats for `IRModule`:

1. **JSON serialization**: `serialize_ir(ir_module) -> dict` — Produces a JSON-compatible nested dictionary.
2. **Pretty-print**: `pretty_print_ir(ir_module) -> str` — Produces an LLVM-IR-inspired text format.

#### Pretty-Print Format Example

```
; IR dump — test.py
; 1 function(s)
; ============================================================

define int @add(a, b)  ; line 1, function
{
entry:
  a = LOAD  ; kind=param
  b = LOAD  ; kind=param
  t0 = a Add b
  __return__ = ASSIGN(t0)  ; kind=return
  jump exit
  ; successors: exit
exit:
  return __return__
}
```

---

## 7. Static Analysis

### 7.1 cfg_builder

**File**: `src/analysis/cfg_builder.py`

Builds a Control-Flow Graph (CFG) from an `IRFunction`.

#### Data Structures

**`CFGNode`**:
| Field | Type | Description |
|---|---|---|
| `label` | `str` | Block label |
| `instructions` | `List[IRInstruction]` | Instructions in this block |
| `successors` | `List[str]` | Successor block labels |
| `predecessors` | `List[str]` | Predecessor block labels |
| `reach_in` | `set[str]` | Reaching definitions at entry (filled by DFA) |
| `reach_out` | `set[str]` | Reaching definitions at exit (filled by DFA) |
| `live_in` | `set[str]` | Live variables at entry (filled by DFA) |
| `live_out` | `set[str]` | Live variables at exit (filled by DFA) |

**`CFG`**:
| Field | Type | Description |
|---|---|---|
| `function_name` | `str` | Name of the owning function |
| `nodes` | `Dict[str, CFGNode]` | Map: label → CFGNode |
| `entry` | `str` | Entry block label |
| `exits` | `List[str]` | Exit block labels (blocks ending in RETURN) |

**CFG Methods**:
- `get_node(label)` — Get node by label
- `successors_of(label)` — Get successor nodes
- `predecessors_of(label)` — Get predecessor nodes
- `topological_order()` — BFS traversal from entry (accounts for back-edges)

#### Public API

| Function | Signature | Description |
|---|---|---|
| `build_cfg` | `(ir_function: IRFunction) -> CFG` | Construct CFG from IRFunction. |

---

### 7.2 dfa_engine

**File**: `src/analysis/dfa_engine.py`

Implements two classical data-flow analyses over a CFG:

#### 1. Reaching Definitions (Forward Analysis)

A definition `d` reaches a point `p` if there exists a path from `d` to `p` along which `d` is not killed.

```
GEN[B]  = definitions created in block B
KILL[B] = definitions whose variable is re-defined in B
IN[B]   = ∪{ OUT[P] : P ∈ predecessors(B) }
OUT[B]  = GEN[B] ∪ (IN[B] − KILL[B])
```

Uses a worklist algorithm with convergence detection.

#### 2. Live Variable Analysis (Backward Analysis)

A variable `v` is live at point `p` if there exists a path from `p` to a use of `v` along which `v` is not re-defined.

```
USE[B]  = variables used in B before any definition
DEF[B]  = variables defined in B
OUT[B]  = ∪{ IN[S] : S ∈ successors(B) }
IN[B]   = USE[B] ∪ (OUT[B] − DEF[B])
```

Uses a backward worklist starting from reversed topological order.

Definitions are `"<var>@<instruction uid>"`; non-parameter locals also get a
pseudo-definition `"<var>@undef"` at entry. Both analyses use worklists with a
convergence flag and an iteration cap.

#### Derived Facts

- **`unused_vars`**: user variables assigned but never read
- **`dead_stores`**: `(var, line)` assignments whose value is never read afterwards
- **`used_before_assigned`**: locals reached by `@undef` at a use (possibly unbound)

#### DFAResult Data Class

| Field | Type | Description |
|---|---|---|
| `function_name` | `str` | Function name |
| `reaching_defs` | `Dict[str, Set[str]]` | Map: block_label → reaching definition names |
| `live_vars` | `Dict[str, Set[str]]` | Map: block_label → live variable names |
| `used_before_assigned` | `List[str]` | Locals possibly read before assignment |
| `unused_vars` | `List[str]` | User variables assigned but never read |
| `dead_stores` | `List[Tuple[str, int]]` | Assignments never read afterwards |
| `converged` / `iterations` | `bool` / `int` | Fixed point reached / worklist iterations |
| `qualname` | `str` | Qualified function name |

#### Public API

| Function | Signature | Description |
|---|---|---|
| `run_dfa` | `(cfg: CFG, ir_function: IRFunction) -> DFAResult` | Run both analyses on a CFG. |

---

### 7.3 pattern_detector

**File**: `src/analysis/pattern_detector.py`

Detects code-quality patterns/code smells from IR and DFA results.

#### Detected Patterns

| Code | Pattern | Severity | Detection Logic |
|---|---|---|---|
| P001 | `unused_variable` | warning | User variable assigned but never read (loop targets excluded) |
| P002 | `high_complexity` | warning | 1 + decision points in the IR > 10 |
| P003 | `dead_block` | info | Block with real code unreachable from `entry` |
| P004 | `no_return_value` | info | Annotated non-None function with a reachable implicit/bare return |
| P005 | `deeply_nested_loops` | warning | Loop nesting depth ≥ 3 |
| P006 | `excessive_calls` | info | >10 distinct callees |
| P007 | `unused_parameter` | info | Parameter never read (was `missing_param_load`, which could never fire) |

#### Data Classes

**`PatternFinding`**:
| Field | Type | Description |
|---|---|---|
| `pattern_id` | `str` | Code like `"P001"` |
| `severity` | `str` | `"info"`, `"warning"`, or `"error"` |
| `function_name` | `str` | Function where detected |
| `message` | `str` | Human-readable description |
| `lineno` | `int` | Approximate source line |

**`AnalysisReport`**:
| Field | Type | Description |
|---|---|---|
| `source_file` | `str` | Source file path |
| `findings` | `List[PatternFinding]` | All findings sorted by (function_name, lineno) |
| `summary` | `Dict[str, int]` | Counts by severity and pattern_id |

#### Public API

| Function | Signature | Description |
|---|---|---|
| `detect_patterns` | `(ir_module, dfa_results=None) -> AnalysisReport` | Run all pattern checks. Works with or without DFA results. |

---

## 8. Machine Learning (ML)

### 8.1 ast_feature_formatter

**File**: `src/ml/ast_feature_formatter.py`

Converts structured AST data (`FunctionFeature` + `FunctionContext` + raises) into a structured natural-language text string that T5 can be trained on.

#### Format Example

```
Generate docstring: process_items
async: no | method: no
params: items:list, threshold:int=5
returns: dict
loops: 1 | conditionals: 2 | body_size: 8
complexity: moderate (cyclomatic=4)
calls_internal: validate_input, store_result
calls_external: os.path.join
data_structures: dict
raises: ValueError, IOError
decorators: staticmethod
```

The model ONLY sees this structured AST information — never raw source code or the function name alone.

#### Public API

| Function | Signature | Description |
|---|---|---|
| `format_for_model` | `(ff, fc=None, raises=None) -> str` | Produce structured AST feature text for T5 input. |
| `format_from_source` | `(source_code, func_name) -> Optional[str]` | Parse a single function and return its formatted feature text. |

---

### 8.2 ast_dataset_builder

**File**: `src/ml/ast_dataset_builder.py`

Builds `(AST feature text, docstring)` training corpus from two sources:

1. **CodeSearchNet Python** (via HuggingFace `datasets`) — primary, ~500k functions
2. **Python standard library** (offline crawl) — fallback when HuggingFace is unavailable

#### ASTTrainPair Data Class

| Field | Type | Description |
|---|---|---|
| `func_name` | `str` | Function name |
| `input_text` | `str` | Output of `format_for_model()` |
| `target_text` | `str` | Clean first-sentence docstring |

#### Docstring Cleaning Pipeline

1. Dedent and strip
2. Extract first paragraph (before `\n\n`)
3. Join lines into single paragraph
4. Skip section headers (e.g., `"Parameters"`)
5. Truncate to 200 chars, then split at sentence boundary
6. Remove noisy prefixes (`NOTE:`, `TODO:`, `WARNING:`, `DEPRECATED:`)
7. Ensure trailing period
8. Reject if < 12 chars

#### Quality Filtering (`_is_target_informative`)

- Minimum 12 chars, maximum 220 chars
- Minimum 3 words
- Minimum 2 unique informative words (excluding generic terms like `"function"`, `"method"`, `"value"`)
- No `TODO`/`FIXME`/`TBD`/`placeholder` stubs

#### Deduplication

Uses MD5 hash of normalized input text + normalized target text + function name for stable deduplication.

#### Public API

| Function | Signature | Description |
|---|---|---|
| `build_full_dataset` | `(include_codesearchnet=True, include_stdlib=True, ...) -> List[ASTTrainPair]` | Build complete training dataset from both sources with dedup. |
| `build_codesearchnet_dataset` | `(split="train", max_samples=30000, ...) -> List[ASTTrainPair]` | Download and extract from HuggingFace CodeSearchNet. |
| `build_stdlib_dataset` | `(max_files=500, ...) -> List[ASTTrainPair]` | Crawl Python stdlib for documented functions. |
| `save_dataset` | `(pairs, output_dir, ...) -> dict` | Save to JSON and CSV. |
| `load_dataset_from_json` | `(json_path) -> List[ASTTrainPair]` | Load a previously saved dataset. |

---

### 8.3 ast_comment_model

**File**: `src/ml/ast_comment_model.py`

Fine-tunes `google-t5/t5-small` (60M params) to generate natural-language docstrings from structured AST feature text.

#### Architecture

| Component | Value |
|---|---|
| Base model | `google-t5/t5-small` (60M parameters) |
| Task prefix | `"Generate docstring: "` |
| Input | Structured AST feature text (max 256 tokens) |
| Output | First sentence of docstring (max 64 tokens) |
| Decoder | Beam search (6 beams) with no-repeat n-gram and repetition penalty |

#### Training Configuration

| Parameter | Default |
|---|---|
| Epochs | 4 |
| Batch size | 8 |
| Learning rate | 2e-4 |
| Warmup ratio | 0.1 |
| Val split | 0.1 |
| Gradient accumulation | 1 |
| Optimizer | AdamW (weight decay 0.01) |
| Scheduler | Linear with warmup |
| Gradient clipping | 1.0 |

#### Inference

`model.generate(ff, fc, raises)` returns `(docstring_text, confidence_score)`:
- Input: Task prefix + formatted AST features
- Beam search: 6 beams, max 72 tokens, min 8 tokens
- Confidence: `min(1.0, exp(beam_score))` — exponential of the sequence score
- Post-processing: Collapse whitespace, strip quotes, remove repeated bigrams, ensure trailing period

#### Public API

| Method | Signature | Description |
|---|---|---|
| `fine_tune` | `(pairs, epochs=3, batch_size=8, ...) -> dict` | Fine-tune T5 on (AST text, docstring) pairs. |
| `generate` | `(ff, fc=None, raises=None, ...) -> Tuple[str, float]` | Generate docstring from AST features. |
| `generate_from_feature_text` | `(feature_text, ...) -> Tuple[str, float]` | Lower-level generate from pre-formatted text. |
| `save` | `(directory) -> None` | Save model + tokenizer + metadata. |
| `load` | `(directory) -> ASTCommentModel` | Load saved model (static method). |
| `training_report` | `() -> dict` | Return training metadata. |

---

### 8.4 trainer

**File**: `src/ml/trainer.py`

End-to-end training and evaluation pipeline.

#### Pipeline Steps

1. Build `(AST feature text, docstring)` corpus from CodeSearchNet + stdlib
2. Train/validation split (default 90/10)
3. Fine-tune `ASTCommentModel` (T5-small)
4. Evaluate with BLEU-4, ROUGE-L, exact-match on holdout split
5. Save model + JSON reports

#### Evaluation (`_evaluate_model`)

- Evaluates on up to 200 test samples
- For each sample: generates from `input_text`, computes BLEU-4/ROUGE-L/exact-match against `target_text`
- Reports mean, std, and per-function breakdown

#### Public API

| Function | Signature | Description |
|---|---|---|
| `train_and_evaluate` | `(output_dir="outputs", ...) -> dict` | Full training pipeline. Returns `{"training_report": ..., "eval_report": ...}`. |
| `load_ast_model` | `(output_dir="outputs") -> Optional[ASTCommentModel]` | Load saved model. Returns `None` if unavailable. |

---

### 8.5 evaluator

**File**: `src/ml/evaluator.py`

Computes standard NLP comment quality metrics:

| Metric | Implementation | Description |
|---|---|---|
| **BLEU-4** | NLTK `sentence_bleu` (with SmoothingFunction) or fallback unigram overlap | Measures n-gram precision (1–4 grams) between reference and hypothesis |
| **ROUGE-L** | Custom LCS-based implementation | Measures recall-oriented longest common subsequence |
| **Exact Match** | Normalized string equality | Binary: 1 if normalized strings match, 0 otherwise |

All metrics operate on `(reference, hypothesis)` docstring pairs and are averaged over the test dataset.

#### EvalReport Data Class

| Field | Type | Description |
|---|---|---|
| `n_samples` | `int` | Number of evaluated samples |
| `bleu4_scores` | `List[float]` | Per-sample BLEU-4 scores |
| `rouge_l_scores` | `List[float]` | Per-sample ROUGE-L scores |
| `exact_match_scores` | `List[int]` | Per-sample exact match flags |
| `mean_bleu4` | `float` | Average BLEU-4 |
| `mean_rouge_l` | `float` | Average ROUGE-L |
| `exact_match_rate` | `float` | Fraction of exact matches |
| `per_function` | `List[dict]` | Per-function score breakdown |

---

## 9. Neurosymbolic Engine

### 9.1 reasoner

**File**: `src/neurosymbolic/reasoner.py`

Symbolic knowledge base providing pattern-to-description rules and constraint validation for neurosymbolic comment generation.

#### SymbolicRule Data Class

| Field | Type | Description |
|---|---|---|
| `pattern_id` | `str` | Rule code (e.g., `"SYM006"`) |
| `condition` | `str` | Condition name |
| `description` | `str` | Description text |
| `severity` | `str` | `"info"` or `"warning"` |

#### SymbolicReasoner Rules

| Code | Condition | Description | Severity |
|---|---|---|---|
| SYM001 | loop_and_sort | Sorts and iterates over items using a loop | info |
| SYM002 | property_accessor | Property accessor for an attribute | info |
| SYM003 | static_method | Static method with no instance binding | info |
| SYM004 | class_method | Class method that receives the class as first argument | info |
| SYM005 | async_network | Asynchronously fetches data from a remote source | info |
| SYM006 | dangerous_eval | DANGER: Executes dynamic code — severe security risk | warning |
| SYM007 | dangerous_exec | DANGER: Executes dynamic code — severe security risk | warning |
| SYM008 | dangerous_compile | DANGER: Compiles and executes dynamic code | warning |
| SYM009 | hardcoded_secret | DANGER: Potential hardcoded secret in source | warning |
| SYM010 | iterator_pattern | Yields items one at a time (generator/iterator pattern) | info |
| SYM011 | context_manager | Context manager supporting the 'with' statement | info |
| SYM012 | recursive_pattern | Recursive function that calls itself | info |
| SYM013 | high_complexity | High control-flow complexity — consider refactoring | warning |

#### Rule Matching Logic

- **SYM001**: Loops > 0 AND calls include `sorted`/`list.sort`/`sort`
- **SYM002**: `@property` decorator
- **SYM003**: `@staticmethod` decorator
- **SYM004**: `@classmethod` decorator
- **SYM005**: Async function AND external calls include network libraries (`requests`, `httpx`, `urllib`, `aiohttp`)
- **SYM006–SYM008**: Calls `eval`/`exec`/`compile`
- **SYM009**: Security issues mentioning `secret`/`password`/`token`
- **SYM010**: `@contextmanager` or `@asynccontextmanager` decorator
- **SYM011**: Same as SYM010
- **SYM012**: Function name appears in its own calls_made (recursion)
- **SYM013**: Complexity label is `"complex"` or `"very_complex"`

#### Consistency Validation (`validate_consistency`)

Checks ML-generated summary against AST facts and returns validation flags:

| Flag | Condition |
|---|---|
| `return_type_mismatch` | ML summary doesn't mention the declared return type |
| `missing_raise` | ML summary omits a raised exception |
| `missing_security_warning` | Function has security issues but ML summary doesn't mention them |
| `missing_params` | ML summary doesn't mention any of the function's parameters |

---

### 9.2 engine

**File**: `src/neurosymbolic/engine.py`

Confidence-gated neurosymbolic fusion engine.

#### NeurosymbolicComment Data Class

| Field | Type | Description |
|---|---|---|
| `text` | `str` | Full docstring text |
| `confidence` | `float` | ML confidence score |
| `source` | `str` | `"neural"`, `"fused"`, or `"symbolic"` |
| `validation_flags` | `List[str]` | Consistency validation results |
| `ml_summary` | `str` | Raw ML-generated summary |
| `symbolic_sections` | `Dict[str, str]` | AST-derived sections (args, returns, raises) |

#### Fusion Logic

```
For each undocumented function:
  1. Get ML summary + confidence from ast_model.generate()
  2. If confidence >= 0.7: source = "neural" (use ML summary)
  3. If confidence >= 0.4 but < 0.7: source = "fused" (ML summary, symbolic augmented)
  4. If confidence < 0.4: source = "symbolic" (rule-based summary)
  5. In all cases: augment with symbolic Args/Returns/Raises
  6. Run validate_consistency() on ML vs AST
  7. Add symbolic warning rules to docstring
  8. Add security warnings if present
  9. Tag engine source and confidence in docstring
```

For classes: always uses rule-based generation.

---

## 10. Graphical User Interface (GUI)

### 10.1 main_window

**File**: `src/gui/main_window.py` (276 lines)

The top-level `QMainWindow` for the application. Title: **"Comment Gen Pro"**.

#### Layout

- **Top Header**: Title label + "Generate & Attach Comments" button (`SpinningButton`)
- **Sidebar** (200–250px): Navigation buttons for 5 workspaces
- **Content Area**: `QStackedWidget` with 5 workspace pages
- **Console Panel**: Live terminal output (captured stdout/stderr with color-coded text)
- **Status Bar**: Permanent status label with color feedback

#### Workspaces

| Index | Name | Widget Class |
|---|---|---|
| 0 | Generator | `GeneratorWorkspace` |
| 1 | Insights | `InsightsWorkspace` |
| 2 | ML Training | `MLTrainingWorkspace` |
| 3 | Security | `SecurityWorkspace` |
| 4 | Logs | `LogsWorkspace` |

#### StreamCapture

Captures `sys.stdout` and `sys.stderr`, emitting `pyqtSignal(str, bool)` for color-coded console output:
- Red: stderr or text matching `error|fail|exception|traceback`
- Green: text matching `success|completed|saved|done|finished`
- Default: normal text color

#### Generation Flow

1. User clicks "Generate & Attach Comments"
2. Sidebar switches to Generator workspace
3. `GeneratorWorkspace.trigger_generation()` is called
4. On completion: Insights and Security workspaces are populated
5. Status shows success/failure with safety percentage
6. Toast notification appears

---

### 10.2 generator_workspace

**File**: `src/gui/generator_workspace.py` (371 lines)

The primary workspace for code input, engine selection, and output display.

#### Layout

- **Header Bar**: Engine selection radio buttons (Rule-Based / Neurosymbolic / ML-Based), unsafe percentage label, output directory input
- **Progress Bar**: Indeterminate, shown during generation
- **Split Editor**: Left = input Python code, Right = annotated output
- **Syntax Highlighting**: `PythonSyntaxHighlighter` on both editors

#### Engine Selection

| Radio Button | Engine Value |
|---|---|
| Rule-Based | `"rule_based"` |
| Neurosymbolic (default) | `"neurosymbolic"` |
| ML-Based | `"ml"` |

#### GeneratorWorker (QThread)

Runs the pipeline in a background thread:
1. Writes input code to a temporary file
2. Creates a `PipelineLogger`
3. Loads ML model if needed
4. Calls `run_pipeline()` with the selected engine
5. Writes annotated output to file
6. Saves pipeline logs
7. Emits results back to the main thread

#### Progress Display

During generation, the output editor shows a step-by-step progress with spinning animation:
- Completed steps: green checkmark
- Current step: animated braille spinner + bold blue text

---

### 10.3 training_workspace

**File**: `src/gui/training_workspace.py` (146 lines)

Dashboard for training/retraining ML models.

#### Layout

- **Header**: Title + "Start / Retrain Models" button (`SpinningButton`)
- **Progress Bar**: Indeterminate during training
- **Status Label**: Current training status
- **Results Area**: Text display for training reports

#### TrainerWorker (QThread)

Calls `train_and_evaluate(output_dir="outputs/gui_models")` in a background thread.

#### Report Display

After training, displays:
- Dataset total samples, train/test sizes
- Training mode (AST structured features → NLP docstring sentence)
- Best BLEU-4, ROUGE-L, Exact Match scores
- Loss history
- Model save location

---

### 10.4 insights_workspace

**File**: `src/gui/insights_workspace.py`

Visualization of pipeline analysis results including:
- AST feature extraction summary
- Context graph with complexity distribution
- IR dump
- Analysis findings
- Interactive AST tree graph (`AstGraphWidget`)
- Context graph visualization (`ContextGraphWidget`)

#### populate_insights(results_dict)

Accepts a dictionary with keys: `"mf"`, `"cg"`, `"ir"`, `"analysis"`, `"security_report"` and populates all visualization tabs.

---

### 10.5 security_workspace

**File**: `src/gui/security_workspace.py`

Security report display with:
- Module safety percentage
- Per-function safety scores
- Issue list organized by severity (critical, high, medium, low)
- Remediation suggestions
- Security chart visualization (`SecurityGraphWidget`)

#### populate(security_report)

Accepts a `SecurityReport` and renders all security findings.

---

### 10.6 logs_workspace

**File**: `src/gui/logs_workspace.py`

Pipeline log viewer showing:
- JSON log data
- Text log data
- Evaluation metrics chart (`EvalGraphWidget`)
- Training history

---

### 10.7 theme

**File**: `src/gui/theme.py`

Defines `MAIN_STYLESHEET` — a comprehensive CSS stylesheet for the PyQt6 application with:
- Color scheme: Blues (#2563eb), greens (#16a34a), reds (#dc2626), neutrals
- Custom styling for `QMainWindow`, `QPushButton` (primary/secondary/sidebar), `QTextEdit`, `QLabel`, `QProgressBar`, `QRadioButton`, `QSplitter`
- Hover/active states for sidebar navigation buttons
- Property-based styling (`class=PrimaryButton`, `class=SidebarButton`, etc.)

---

### 10.8 widgets

**File**: `src/gui/widgets.py`

Custom reusable widgets:

| Widget | Description |
|---|---|
| `SpinningButton` | `QPushButton` that shows a braille spinner animation during long operations. Disables clicks while spinning. |
| `ToastWidget` | Non-intrusive notification overlay that fades in/out. Supports `"success"` (green) and `"error"` (red) kinds. Auto-hides after 3 seconds. |

---

### 10.9 syntax_highlighter

**File**: `src/gui/syntax_highlighter.py`

`QSyntaxHighlighter` subclass for Python code highlighting.

#### Highlighting Rules

| Pattern | Color |
|---|---|
| Keywords (`def`, `class`, `if`, `return`, etc.) | Bold blue |
| Builtins (`print`, `len`, `range`, etc.) | Dark cyan |
| Strings (single/double/triple quotes) | Dark green |
| Comments (`# ...`) | Gray |
| Decorators (`@...`) | Dark magenta |
| Numbers | Dark red |
| `self` | Dark magenta |

---

### 10.10 Graph Widgets

| Widget | File | Description |
|---|---|---|
| `AstGraphWidget` | `gui/ast_graph_widget.py` | Interactive tree visualization of AST features |
| `ContextGraphWidget` | `gui/context_graph_widget.py` | Context graph with complexity and call relationships |
| `SecurityGraphWidget` | `gui/security_graph_widget.py` | Bar/pie chart of security findings by severity |
| `EvalGraphWidget` | `gui/eval_graph_widget.py` | Line/bar charts for BLEU-4, ROUGE-L training history |

---

## 11. CLI Reference

### Basic Usage

```bash
# Rule-based generation (default)
python -m src.main <file.py>

# AST+NLP ML generation
python -m src.main <file.py> --ml

# Neurosymbolic generation
python -m src.main <file.py> --neurosymbolic

# Train models
python -m src.main --train
```

### All Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `filepath` | positional | required | Path to Python source file (not needed with `--train`) |
| `--output`, `-o` | str | stdout | Write annotated source to FILE |
| `--logs` | flag | off | Save pipeline logs (JSON + text) to `logs/` |
| `--show-features` | flag | off | Print extracted AST features as JSON |
| `--show-context` | flag | off | Print semantic context graph as JSON |
| `--ir` | flag | off | Print pretty-printed IR dump |
| `--analysis` | flag | off | Print pattern-analysis report |
| `--ml` | flag | off | Use AST+NLP ML generation (strict) |
| `--neurosymbolic` | flag | off | Use neurosymbolic (confidence-gated ML + symbolic) |
| `--train` | flag | off | Train/retrain ML models and exit |
| `--epochs` | int | 4 | Training epochs |
| `--batch-size` | int | 8 | Training batch size |
| `--grad-accum-steps` | int | 1 | Gradient accumulation steps |
| `--lr` | float | 2e-4 | Learning rate |
| `--codesearchnet-max` | int | 20000 | Max CodeSearchNet samples |
| `--max-stdlib-files` | int | 1500 | Max stdlib files for training |
| `--no-codesearchnet` | flag | off | Disable CodeSearchNet source |
| `--no-stdlib` | flag | off | Disable Python stdlib source |
| `--output-dir` | str | `"outputs"` | Output directory for models/reports |
| `--block-max-pairs` | int | 20000 | Max block-level training pairs |
| `--security` | flag | off | Security analysis only (no comment generation/ML); exit 1 if any active finding |
| `--security-report` | flag | off | Print full security findings with evidence traces after the run |
| `--security-json` | str | — | Write security findings (full schema) as JSON |

Standalone security CLI: `python -m src.security <file-or-dir> [--json] [--all] [--no-trace] [--min-confidence LEVEL] [--fail-on potential|confirmed]`.
Evaluation: `python -m src.security.evaluate [--confirmed-only] [--granularity line|function] [--baseline OLD.py] [--json FILE]`.

### GUI Entry Point

```bash
python run_gui.py
```

---

## 12. Data Structures Reference

### Pipeline Data Flow

```
source_code
    │
    ▼
 ast.AST ──────────────────► ModuleFeatures
    │                           │
    │                           ▼
    │                       ContextGraph
    │                           │
    ├───────────────────────────┤
    │                           │
    ▼                           ▼
 List[CommentItem]          IRModule
    │                           │
    ▼                           ▼
 AttachResult               CFG → DFAResult
    │                           │
    │                           ▼
    │                       AnalysisReport
    │
    ▼
 SecurityReport
```

### Key Data Class Relationships

| From | To | Relationship |
|---|---|---|
| `ModuleFeatures` | `FunctionFeature` | 1:N (module has many functions) |
| `ModuleFeatures` | `ClassFeature` | 1:N (module has many classes) |
| `FunctionFeature` | `ParamFeature` | 1:N (function has many params) |
| `ContextGraph` | `FunctionContext` | 1:N (graph has many contexts) |
| `FunctionContext` | `VariableInfo` | 1:N (context has many variables) |
| `IRModule` | `IRFunction` | 1:N (module has many functions) |
| `IRFunction` | `IRBlock` | 1:N (function has many blocks) |
| `IRBlock` | `IRInstruction` | 1:N (block has many instructions) |
| `SecurityReport` | `SecurityIssue` | 1:N (report has many issues) |
| `AnalysisReport` | `PatternFinding` | 1:N (report has many findings) |

---

## 13. Security Analysis Patterns

| Code | Title | CWE | Severity | Analysis |
|---|---|---|---|---|
| SEC001 | Code injection (`eval`/`exec`/`compile`) | CWE-95 | critical | taint (+ dangerous-API use) |
| SEC002 | OS command injection | CWE-78 | critical | taint |
| SEC003 | Hardcoded secret | CWE-798 | high | AST |
| SEC004 | Weak cryptographic hash | CWE-328 | medium | AST |
| SEC005 | SQL injection | CWE-89 | high | taint (+ SQL-construction heuristic) |
| SEC006 | Bare `except:` | CWE-396 | medium | AST |
| SEC007 | Mutable default argument | — | low | AST |
| SEC008 | `assert` in non-test code | CWE-703 | low | AST |
| SEC009 | Unsafe deserialization | CWE-502 | high | taint (+ dangerous-API use) |
| SEC010 | Unsafe YAML load | CWE-502 | high | taint (+ dangerous-API use) |
| SEC011 | Insecure randomness in a security context | CWE-338 | medium | AST |
| SEC012 | Hardcoded IP address | CWE-1051 | low | AST |
| SEC013 | Path traversal | CWE-22 | high | taint |
| SEC014 | Cross-site scripting | CWE-79 | high | taint |
| SEC015 | Server-side template injection | CWE-1336 | critical | taint |

Sources, sinks, sanitizers, confidence derivation, evaluation results and
limitations: [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md).

---

## 14. Pattern Detection Codes

| Code | Pattern | Severity | Condition |
|---|---|---|---|
| P001 | Unused variable | warning | DFA: user variable assigned but never read (loop targets excluded) |
| P002 | High complexity | warning | 1 + IR decision points > 10 |
| P003 | Dead block | info | Block with real code unreachable from entry |
| P004 | No return value | info | Annotated non-None function can return None |
| P005 | Deeply nested loops | warning | Loop nesting depth ≥ 3 |
| P006 | Excessive calls | info | >10 distinct callees |
| P007 | Unused parameter | info | Parameter never read |

---

## 15. Testing

### Test Files

| File | Tests | Scope |
|---|---|---|
| `test_basic.py` | `TestParser`, `TestValidator` | Parser (valid code, syntax error, empty module) and Validator (naming, arg count) |
| `test_core_engine.py` | `TestASTExtractor`, `TestContextAnalyzer`, `TestCommentGenerator`, `TestASTDrivenComments`, `TestCommentAttacher` | Full Week 7 pipeline |
| `test_ir.py` | `TestIRNodes`, `TestIRBuilder`, `TestIRSerializer` | IR nodes, builder, JSON/text serialization |
| `test_analysis.py` | `TestCFGBuilder`, `TestDFAEngine`, `TestPatternDetector` | CFG structure, DFA results, pattern findings |
| `test_ast_nlp_model.py` | `test_clean_docstring`, `test_ast_feature_formatter`, `test_dataset_builder_offline`, `test_ast_comment_model_generate` | ML pipeline components |
| `test_ir_semantics.py` | `TestLowering`, `TestCFGShape`, `TestDataFlow`, `TestPatternRegressions` | Real-AST lowering, CFG edges, reaching defs/liveness, P001/P003/P004/P005/P007 regressions |
| `test_security_taint.py` | flows, sanitizer contexts, interprocedural, confidence, suppression, legacy adapter | Taint engine and finding schema |
| `test_security_eval.py` | metric formulas, scoring rules, pinned fixture results | Evaluation methodology |
| `test_location_integrity.py` | original-line mapping, behaviour preservation, input file untouched | Comment generation vs. security locations |

### Running Tests

```bash
# All tests
python -m pytest tests/ -v

# Specific test file
python -m pytest tests/test_core_engine.py -v

# With unittest
python -m unittest tests.test_basic -v
```

### Test Input Files

| File | Purpose |
|---|---|
| `tests/inputs/complex_sample.py` | Complex code with loops, branches, classes |
| `tests/inputs/test_security.py` | Code with security anti-patterns |
| `tests/inputs/demo_showcase.py` | Demo code for showcase |
| `tests/security_fixtures/*.py` | Labelled vulnerable/secure programs for the security evaluation (see its README) |

---

## 16. Output Artifacts

After training (`--train`), the following artifacts are written to `outputs/`:

```
outputs/
├── model/
│   ├── ast_model/
│   │   ├── model.safetensors          # Trained T5 model weights
│   │   ├── config.json                # Model configuration
│   │   ├── tokenizer.json             # Tokenizer
│   │   ├── spiece.model               # SentencePiece model
│   │   ├── special_tokens_map.json    # Special token mappings
│   │   ├── tokenizer_config.json      # Tokenizer configuration
│   │   ├── generation_config.json     # Generation parameters
│   │   └── ast_model_meta.json        # Training metadata (model name, loss history)
│   ├── codet5/                        # Alternative CodeT5 model (if trained)
│   ├── template_model.pkl            # Template-based model
│   └── tfidf_model.pkl              # TF-IDF model
├── ast_train_dataset.json            # Full dataset in JSON
├── ast_train_dataset.csv             # Full dataset in CSV
├── training_corpus.json/csv          # Raw training corpus
├── block_corpus.json/csv             # Block-level corpus
├── training_report.json              # Training metadata
└── eval_report.json                  # Evaluation metrics
```

#### training_report.json Structure

```json
{
  "dataset_total": 5000,
  "train_size": 4500,
  "test_size": 500,
  "data_profile": {
    "input_mode": "AST structured features",
    "target_mode": "NLP docstring sentence",
    "ast_nlp_pairs": 5000
  },
  "ast_model": {
    "model": "google-t5/t5-small",
    "train_size": 4500,
    "val_size": 500,
    "epochs": 4,
    "final_loss": 0.2341,
    "loss_history": [1.2, 0.8, 0.4, 0.23],
    "device": "cuda"
  },
  "training_profile": { ... },
  "input_format": "structured AST features (ast_feature_formatter)",
  "target_format": "first sentence of function docstring",
  "source": ["CodeSearchNet Python (HF)", "Python stdlib"]
}
```

#### eval_report.json Structure

```json
{
  "ast_model": {
    "n_samples": 200,
    "bleu4_mean": 0.1234,
    "bleu4_std": 0.05,
    "rouge_l_mean": 0.3456,
    "rouge_l_std": 0.08,
    "exact_match_rate": 0.02,
    "per_function": [ ... ]
  },
  "summary": {
    "best_bleu4": 0.1234,
    "best_rouge_l": 0.3456,
    "best_exact_match": 0.02,
    "dataset_size": 5000
  }
}
```

---

## 17. Dependencies

### Core (Required)

| Package | Purpose |
|---|---|
| Python >= 3.10 | Runtime (uses `match` syntax, `ast.unparse()`) |
| `ast` | Standard library — AST parsing and traversal |

### ML (Optional — required for `--ml`/`--neurosymbolic`/`--train`)

| Package | Purpose |
|---|---|
| `torch` | PyTorch — model training and inference |
| `transformers` | HuggingFace Transformers — T5 model and tokenizer |
| `sentencepiece` | Tokenizer backend for T5 |
| `datasets` | HuggingFace Datasets — CodeSearchNet download |
| `nltk` | BLEU score computation |
| `numpy` | Metric statistics |

### GUI (Optional — required for `run_gui.py`)

| Package | Purpose |
|---|---|
| `PyQt6` | Qt6 bindings for Python — GUI framework |

### Installation

> **Python 3.11 or 3.12 is required for the ML extras.** PyTorch ships no wheels
> for Python 3.14, so `pip install torch` fails there. The rule-based engine runs
> on any Python >= 3.10.

All pinned dependencies live in `requirements.txt` at the repository root.

```bash
# 1. Virtual environment on a supported interpreter
py -3.12 -m venv .venv

# 2a. NVIDIA GPU: install the CUDA build of torch first
.venv/Scripts/python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cu121

# 2b. Everything else (CPU-only users can skip straight to this line)
.venv/Scripts/python.exe -m pip install -r requirements.txt
```

### A fresh clone has no trained model

`.gitignore` excludes `outputs/model/`, so the fine-tuned checkpoint is **not**
distributed with the source. `load_ast_model()` returns `None` when
`outputs/model/ast_model/config.json` is absent, and the CLI exits with code 2 and
a "train first" message. Train once per clone:

```bash
python -m src.main --train --quick     # minutes — pipeline check
python -m src.main --train             # full run
```

### Artifact locations

Every path resolves through `src/config.py` against the repository root, not the
current working directory, so the CLI and the GUI always agree:

| Constant | Path |
|---|---|
| `OUTPUT_DIR` | `outputs/` |
| `AST_MODEL_DIR` | `outputs/model/ast_model/` |
| `TRAINING_REPORT` | `outputs/training_report.json` |
| `EVAL_REPORT` | `outputs/eval_report.json` |
| `DATASET_JSON` | `outputs/ast_train_dataset.json` |

---

## 18. Running the Project

### CLI — Rule-Based Generation

```bash
python -m src.main tests/inputs/complex_sample.py
```

### CLI — ML Generation

```bash
# Train first (one-time)
python -m src.main --train

# Then generate with ML
python -m src.main tests/inputs/complex_sample.py --ml
```

### CLI — Neurosymbolic Generation

```bash
python -m src.main tests/inputs/complex_sample.py --neurosymbolic
```

### CLI — View Analysis

```bash
python -m src.main tests/inputs/complex_sample.py \
  --show-features --show-context --ir --analysis --logs
```

### CLI — Training with Custom Parameters

```bash
python -m src.main --train \
  --epochs 3 \
  --batch-size 8 \
  --codesearchnet-max 8000 \
  --max-stdlib-files 600 \
  --lr 2e-4
```

### GUI

```bash
python run_gui.py
```

---

## 19. Design Decisions

### Why AST Features as Model Input (Not Raw Source)?

The T5 model receives **structured AST feature text** — never raw source code. This ensures:
- The model learns to generalize from code structure, not memorize syntax
- Input is deterministic and reproducible
- The model can't leak sensitive code content
- Features are language-agnostic in principle (same structure could describe Java/C++)

### Why Confidence-Gated Fusion?

The neurosymbolic engine gates ML output by confidence:
- **High confidence (>= 0.7)**: ML output is used directly — it's likely accurate
- **Medium confidence (0.4–0.7)**: ML output is used but augmented with symbolic warnings
- **Low confidence (< 0.4)**: Falls back to deterministic rule-based generation
- This prevents low-quality ML output from degrading documentation

### Why Separate Args/Returns/Raises from ML?

Even in ML mode, the Args/Returns/Raises sections are always filled from AST analysis:
- These sections require exact type names and parameter lists — ML may hallucinate
- AST analysis is 100% accurate for these structural elements
- ML is only trusted for the natural-language summary line

### Why Docstring Sanitization?

Generated text may contain triple quotes, raw string prefixes, or other characters that would break Python syntax. `_sanitize_docstring_content()`:
- Replaces `"""` and `'''` with `''`
- Removes raw string prefixes (`r"""`, `u"""`, etc.)
- Ensures output files are always compilable Python

### Why Two Data-Flow Analyses?

- **Reaching Definitions** (forward): Identifies where variables are defined and whether those definitions propagate correctly — useful for detecting unused assignments
- **Live Variables** (backward): Identifies variables that are used after a point — useful for detecting dead stores and uninitialized reads
- Together they provide comprehensive data-flow coverage for pattern detection

---

## 20. License

MIT License — Copyright (c) 2026 rishi-2406

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
