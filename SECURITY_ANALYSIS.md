# Security Analysis — Design, Rules, Evaluation and Limitations

This document describes the security analyzer in `src/security/` and the
analysis foundation it relies on (`src/ir/lowering.py`, `src/analysis/`).
It reflects the code as implemented; numbers below are produced by the
commands in [Reproducing](#reproducing).

---

## 1. Architecture

```
source (original file, never the annotated output)
   │  ast.parse
   ▼
ir.lowering.lower_module ── every function, method, nested function + <module> body
   │      real statements/expressions → 3-address IR with line/col on every instruction
   │      (security.project: many modules, module-qualified names, cross-file calls)
   ▼
analysis.cfg_builder.build_cfg ── basic blocks, if/loop/break/continue/return/try/raise edges
   │
   ├─► analysis.dfa_engine     reaching definitions, liveness, dead stores, possibly-unbound
   │      └─► analysis.pattern_detector   P001–P007 code-quality patterns
   │
   └─► security.taint.TaintEngine   per-context taint, interprocedural summaries (fixed point)
          │
security.ast_rules ─────────────── SEC003/004/006/007/008/011/012 structural rules
          │
          ▼
security.analyzer.analyze_source ─ Finding records: severity, confidence, status,
                                   evidence trace, # nosec suppression, dedup
          │
          ├─► src/security_analyzer.py  (SecurityReport adapter: CLI pipeline + GUI)
          ├─► src/context_analyzer.py   (FunctionContext.security_issues → docstring warnings)
          └─► python -m src.security / python -m src.main --security
```

Independence from documentation generation:

* Security analysis runs on the source as read from disk, before comments are
  generated, and does not read generated comments or ML output.
* `python -m src.security FILE` and `python -m src.main FILE --security` run it
  without comment generation or the ML model.
* Generated docstrings *display* security warnings, but the information only
  flows security → documentation.

### What changed in the foundation (and why)

| Component | Before | Now |
|---|---|---|
| IR builder | Blocks synthesised from loop/conditional **counts** with placeholder operands (`__cond_lhs__`, `__iter__`); `_link_block` ran before blocks were appended, so every `branch_N_cond` had no predecessors. | `ir.lowering` lowers each real statement/expression; `build_ir` keeps its signature and block-label vocabulary (`entry`, `exit`, `loop_N_*`, `branch_N_*`). |
| DFA | Definitions were temporaries; "unused" meant "temp never used as operand" (always true for synthesised temps). | Definitions are `var@instruction-uid`; liveness on real uses; dead stores; possibly-unbound locals; convergence flag + iteration cap. |
| P003 | "Block has no predecessors" (fired on every `branch_N_cond`). | Block with real code unreachable from `entry`. |
| P007 | `missing_param_load` — impossible, the builder always emitted the LOAD. | `unused_parameter` — parameter never read (stubs, `self`, `_x`, abstract/overload excluded). |
| Security | Regexes over function source text; every issue on the `def` line; duplicated checks in `context_analyzer`. | One registry (`security/rules.py`), taint engine + AST rules, exact locations, evidence traces; `context_analyzer` consumes the central result. |
| Comment attacher | Docstring inserted after the `def` line — broke multi-line signatures (`SyntaxError`). | Inserted before the first body statement at its indentation; one-line bodies skipped; `line_map` back to original lines. |

---

## 2. Taint model

### Abstract domain

`State: variable → TaintValue`, `TaintValue: origin → TaintInfo` where

* `contexts` — security contexts in which the value is still dangerous:
  `sql, shell, html, path, template, code, deserialization`
* `markers` — facts true on every path (currently `canonical` for resolved paths)
* `unc` — reasons the flow is uncertain (unresolved calls, `*args` binding)
* `trace` — one representative evidence trace (not part of fixed-point equality)

Join: per origin, contexts ∪, markers ∩, uncertainty ∪, shorter trace kept.
Fixed-point checks ignore traces; the lattice is finite for one module, so the
intraprocedural worklist and the interprocedural rounds terminate. Caps
(`40 × blocks` iterations, 25 rounds) exist anyway; hitting one is reported
(`converged = false`, confidence `low`).

### Sources (`rules.SOURCES`)

| Match | Description | Trust |
|---|---|---|
| `flask.request.*`, `quart.request.*`, `bottle.request.*` (import-resolved) | HTTP request data | remote |
| `request.GET/POST/body/COOKIES/META/FILES/headers/data/json/args/form/…` on a local `request`/`self.request` | Django/DRF-style request (name heuristic) | remote, *heuristic* |
| parameters of functions decorated `@*.route/get/post/put/patch/delete(...)` | HTTP route parameter | remote |
| `input()`, `sys.stdin` | interactive / standard input | remote |
| `requests.*`, `urllib.request.urlopen` | response from a remote server | remote |
| `sys.argv`, `os.environ`, `os.getenv` | command line / environment | local |
| `open()`, `io.open`, `codecs.open` | file contents | local |
| parameter of a function with **no analysed caller** | origin unknown | unknown |

### Propagation

Assignments and reassignment (strong update of locals), tuple unpacking,
augmented assignment, `+`/`%`/f-strings/`.format`/`.join` and other string
methods, containers (list/tuple/set/dict literals, comprehensions,
`append/extend/add/update` mutate the receiver), subscripts (value taint
follows the container, not the index), attribute reads, `self.x` fields across
methods (flow-insensitive per class), closures (captured at the nested `def`,
including several levels deep), module globals (taint of the module body at
its end), `with … as`, `for` targets, `return`, yields.

Comparisons and `not` produce untainted booleans. Conditional branches and
loops are handled by the CFG fixed point (may-analysis: tainted on any path ⇒
tainted at the merge).

### Interprocedural analysis

Each function is analysed with symbolic parameter origins. Its **summary**
records which origins reach the return value (with surviving contexts) and
which parameter origins reach sinks. At each call site the summary is
instantiated with the actual argument taint:

* `caller source → callee param → callee sink` is reported at the callee's
  sink with a trace through the call (`[call]`, `[param]` steps);
* a callee that sanitises (e.g. `return int(v)`) yields an untainted result;
* constructor arguments stored in fields and closure variables of nested
  functions are instantiated the same way;
* recursion is handled by iterating rounds until no summary changes.

Resolved calls: module-level functions, nested functions (`MAKEFUNC`),
`self.method()`/`cls.method()`, `ClassName.method()`, `ClassName(...)` →
`__init__`. Anything else is an **unknown call**: its result carries the union
of its inputs and an uncertainty reason (`unresolved call x()`), which lowers
confidence.

A parameter-origin flow is reported only if the function has no analysed
caller (otherwise call sites decide) and the rule allows it — dangerous
wrappers such as `def run(code): eval(code)` are reported at **low**
confidence; `def read(path): open(path)` is not (ordinary API design).

### Sinks (`rules.SINKS`)

| Rule | Sink (canonical, after import-alias resolution) | Dangerous operand / condition |
|---|---|---|
| SEC001 | `eval`, `exec` (`compile()` only propagates taint into the code object) | arg 1 |
| SEC002 | `os.system`, `os.popen`, `subprocess.getoutput/getstatusoutput`, `asyncio.create_subprocess_shell` | arg 1 |
| SEC002 | `subprocess.run/call/check_call/check_output/Popen` | `shell=True`: the command; `shell=<expr>`: medium confidence; no shell: only the executable (string arg, or element 0 of a list literal) |
| SEC002 | `os.exec*`, `os.spawn*` | the program |
| SEC005 | `.execute/.executemany/.executescript/.raw` on DB cursors/connections (exact when the receiver came from `*.connect()`/`.cursor()`; otherwise method-name match, medium) ; `pandas.read_sql*`, `sqlalchemy.text` | arg 1 (parameters tuple is never a sink) |
| SEC009 | `pickle/cPickle/_pickle/dill/marshal .load(s)`, `shelve.open`, `jsonpickle.decode`, `pandas.read_pickle`, `joblib.load` | arg 1 |
| SEC010 | `yaml.load/load_all` without `Loader=SafeLoader/CSafeLoader/BaseLoader`, `yaml.unsafe_load*`, `yaml.full_load*` | arg 1 |
| SEC013 | `open`, `io.open`, `os.remove/unlink/rmdir/listdir/makedirs/…`, `shutil.copy*/move/rmtree`, `flask.send_file`; `Path.read_text/write_text/…` | path argument(s) / receiver |
| SEC014 | `flask.make_response/Response`, `django.http.HttpResponse` (skipped when `mimetype`/`content_type` is not HTML), `Markup`, `mark_safe`; **return value of a route handler** (medium: content type assumed HTML) | arg 1 / returned value |
| SEC015 | `flask.render_template_string`, `jinja2.Template`, `.from_string` | template source |

### Sanitizers and validation (context-specific)

| Sanitizer | Removes |
|---|---|
| `html.escape`, `markupsafe.escape`, `bleach.clean`, `django…escape`, … | `html` only |
| `jsonify`, `render_template(_string)` (variables), `redirect`, `url_for`, `JsonResponse` | `html` only |
| `shlex.quote` | `shell` only |
| `os.path.basename`, `werkzeug.utils.secure_filename` | `path` only |
| `urllib.parse.quote(_plus)` | `html`, `sql`, `shell` |
| `int`, `float`, `bool`, `len`, `uuid.UUID`, `ipaddress.ip_address`, `str.isdigit()` (value), … | all |
| `os.path.realpath/abspath/normpath`, `Path.resolve()` | nothing — adds the `canonical` marker |

Branch-edge refinements (applied only on the edge where the condition holds,
including `if not …: return/raise/abort()` patterns):

* `x in CONST_COLLECTION` / `x == "literal"` → all contexts (allowlist)
* `x.isdigit()/isalnum()/…`, `isinstance(x, int)` → all contexts
* `re.fullmatch(PATTERN, x)` (or `re.match` anchored with `$`/`\Z`) → contexts
  whose dangerous characters the pattern's character set excludes;
  unanchored `re.match` validates nothing
* `p.startswith(BASE)`, `p.is_relative_to(base)`,
  `os.path.commonpath([p, BASE]) == BASE` → `path`, **only if `p` carries the
  `canonical` marker**; on a non-canonical path the check is recorded in the
  trace as insufficient.

A function is never trusted because of its name; project functions are
analysed through their bodies (`def sanitize(v): return v.strip()` sanitises
nothing).

No-return calls (`sys.exit`, `flask.abort`, `os._exit`, …) end the path in the CFG.

---

## 3. Findings

Every finding (`security.findings.Finding`) has:

`rule_id, title, category, cwe, severity, severity_reason, confidence,
confidence_reasons, status, suppression_reason, file, function, line, col,
message, remediation, analysis (taint | api-use | sql-construction |
ast-pattern), sink{name, operation, role, line, col, code},
source{description, kind, trust, line, col, function, code},
trace[{line, col, kind, text, function}], path_conditions, sanitizers,
missing_protections, fingerprint`.

Locations are those of the original file. `trace` kinds: `source`, `param`,
`assign`, `store`, `call`, `return`, `sanitizer`, `check`, `sink`, `pattern`.

### Confidence (no numeric scores)

Confidence = the minimum level among explicit factors, each listed in
`confidence_reasons`:

| Level | Factors |
|---|---|
| high | resolved sink reached by a recognised remote source; exact structural pattern |
| medium | local source (env/argv/file); name-heuristic source; sink matched by method name only; flow through an unresolved call; route-return XSS (content type assumed); `shell=` not a literal; function contains un-modelled constructs; name-based secret/weak-hash/random/IP heuristics |
| low | origin is a parameter of a function with no analysed caller; dangerous API with a non-constant argument but no traced source (`api-use`); SQL built from tainted data with no observed execution (`sql-construction`, low/medium); analysis did not converge |

### Status

* **confirmed** — confidence high (a supported source-to-sink path / definite pattern)
* **potential** — anything less certain
* **suppressed** — `# nosec SEC005: <reason>` on the line (or a comment-only
  line above it), or a rule-level exemption (`usedforsecurity=False`, bare
  `except:` that re-raises). A `# nosec` **without** a reason is ignored and
  noted in `confidence_reasons`.

Static evidence never proves exploitability; messages say "reaches … without
… sanitisation", not "is exploitable".

### Severity

Rule base severity (table below); lowered one level for local sources and for
`api-use` findings; `high` instead of `critical` when only the executable (not
a shell command line) is attacker-selected.

### Deduplication

One finding per (rule, function, sink instruction, operand, origin). Distinct
origins reaching the same sink are **not** merged; the same origin over several
paths is reported once (shortest trace). AST findings are deduplicated per
(rule, line, column).

---

## 4. Rules

| ID | Title | CWE | Base severity | Analysis | Change vs. original scanner |
|---|---|---|---|---|---|
| SEC001 | Code injection (`eval`/`exec`; `compile` propagates) | CWE-95 | critical | taint (+ api-use) | literal arguments no longer reported; tainted flows confirmed |
| SEC002 | OS command injection | CWE-78 | critical | taint | was "subprocess + `shell=True` somewhere in the function"; now argument-level, covers `os.system/popen/exec*/spawn*`, list vs string, aliases |
| SEC003 | Hardcoded secret | CWE-798 | high | AST | adds module level, attributes, dict keys, kwargs, comparisons, defaults, key formats (AWS/GitHub/Slack/Stripe/Google/private keys/URL credentials); excludes placeholders, env-var names, prose |
| SEC004 | Weak hash (MD5/SHA-1) | CWE-328 | medium | AST | import-resolved; `hashlib.new("md5")`; `usedforsecurity=False` suppressed |
| SEC005 | SQL injection | CWE-89 | high | taint (+ sql-construction) | was a regex over function text; parameterised queries are safe by construction |
| SEC006 | Bare `except:` | CWE-396 | medium | AST | handler line; re-raising handlers suppressed |
| SEC007 | Mutable default argument | — (reliability) | low | AST | also `list()/dict()/set()` and keyword-only defaults |
| SEC008 | `assert` in non-test code | CWE-703 | low | AST | test detection fixed (the old prefix check never matched `_test`) |
| SEC009 | Unsafe deserialization | CWE-502 | high | taint (+ api-use) | adds `marshal`, `dill`, `shelve`, `jsonpickle`, `joblib`, `pandas.read_pickle` |
| SEC010 | Unsafe YAML load | CWE-502 | high | taint (+ api-use) | `Loader=yaml.SafeLoader` recognised as safe |
| SEC011 | Insecure randomness | CWE-338 | medium | AST | only in a security context (function/variable named token/password/secret/nonce/…) |
| SEC012 | Hardcoded IP address | CWE-1051 | low | AST | string literals only (not comments/docstrings); loopback/unspecified excluded |
| SEC013 | Path traversal | CWE-22 | high | taint | new |
| SEC014 | Cross-site scripting | CWE-79 | high | taint | new |
| SEC015 | Server-side template injection | CWE-1336 | critical | taint | new |

---

## 5. Evaluation

Three datasets are kept apart (details, provenance and labelling protocol in
[benchmarks/README.md](benchmarks/README.md)):

1. **Synthetic regression fixtures** (`tests/security_fixtures/`, `tests/security_fixtures_project/`)
   — written with the analyzer; regression tests, not accuracy evidence.
2. **OWASP BenchmarkPython** (independent labels, generated code) — dev / held-out by
   template family.
3. **GHSA real-world fix pairs** (50 advisories, manually labelled from advisory + diff,
   single annotator, no independent review) — dev / held-out by project.

Metric definitions everywhere: Precision = TP/(TP+FP), Recall = TP/(TP+FN),
F1 = 2PR/(P+R), FPR = FP/(FP+TN); zero denominators are reported as `undefined`.
"Original" = the analyzer at commit `53a0611`, run with the same runner and labels.

### 5.1 OWASP BenchmarkPython (unit: test case × category; 877 scored cases)

| Analyzer | Split | Counted | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|---|
| Original | dev | confirmed+potential | 124 | 115 | 267 | 84 | 0.519 | 0.596 | 0.555 | 0.301 |
| Final, single-file | dev | confirmed+potential | 208 | 43 | 339 | 0 | 0.829 | 1.000 | 0.906 | 0.113 |
| Final, project | dev | confirmed+potential | 208 | 38 | 344 | 0 | 0.846 | 1.000 | 0.916 | 0.099 |
| Original | held-out | confirmed+potential | 74 | 41 | 132 | 40 | 0.643 | 0.649 | 0.646 | 0.237 |
| Final, single-file | held-out | confirmed+potential | 114 | 25 | 148 | 0 | 0.820 | 1.000 | 0.901 | 0.145 |
| Final, project | held-out | confirmed+potential | 114 | 21 | 152 | 0 | 0.844 | 1.000 | 0.916 | 0.121 |
| Original | held-out | confirmed | 24 | 24 | 149 | 90 | 0.500 | 0.211 | 0.296 | 0.139 |
| Final, project | held-out | confirmed | 29 | 5 | 168 | 85 | 0.853 | 0.254 | 0.392 | 0.029 |

Excluded categories (out of scope): xpathi 186, xxe 28, securecookie 39, redirect 34,
trustbound 37, ldapi 29. No analysis errors. Runtime: 79 s single-file, 170 s project
mode for 1230 files (~200 MB peak traced memory in project mode).

**Not an independent held-out.** OWASP has 24 template families and nearly all were
inspected while debugging on dev; held-out differs in instances, not in templates.
Recall 1.000 includes many `potential` findings (e.g. all weak-randomness hits, whose
session relevance is inferred from a container name). Hash (MD5/SHA-1) findings are
never `confirmed`, because security use of a digest cannot be decided statically.

### 5.2 GHSA real-world fix pairs (unit: case × revision over labelled functions; modelled sinks)

| Analyzer | Split | Counted | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|---|
| Original | dev (25) | confirmed+potential | 22 | 10 | 13 | 3 | 0.688 | 0.880 | 0.772 | 0.435 |
| Final | dev (25) | confirmed+potential | 22 | 6 | 17 | 3 | 0.786 | 0.880 | 0.830 | 0.261 |
| Original | held-out (14) | confirmed+potential | 10 | 7 | 7 | 4 | 0.588 | 0.714 | 0.645 | 0.500 |
| **Final** | **held-out (14)** | **confirmed+potential** | 10 | 5 | 9 | 4 | **0.667** | **0.714** | **0.690** | **0.357** |
| Final | held-out (14) | confirmed | 0 | 0 | 14 | 14 | undefined | 0.000 | undefined | 0.000 |

Including the 11 cases whose sink API is not modelled ("all in category"), final
held-out confirmed+potential is P 0.667, R 0.571, F1 0.615, FPR 0.286.

**What this says.** On real library code nearly every detection is `potential/low`:
the attacker-controlled value enters as a parameter of a function with no caller in
the analysed file, so the analyzer cannot establish a source. At the `confirmed` level
recall on real code is close to zero (dev 3/25, held-out 0/14). The precision gains
measured on OWASP largely did **not** transfer: on held-out only the jinja2 sandbox
model (added for a dev case) changed outcomes, removing false positives on two unseen
projects. With 14 held-out cases these numbers are indicative only.

Per-case changes original → final: dev patched FPs removed for geopandas
(`bindparams`), postgraas (psycopg `sql.Identifier`), langflow (`compile` no longer a
sink), skyvern (sandboxed jinja2); held-out patched FPs removed for spacy-llm and mlflow
(sandboxed jinja2); changedetection.io (sink not modelled) is now flagged on *both*
revisions via the new existence-probe sinks — one more TP and one more FP.

### 5.3 Synthetic regression fixtures (unit: labelled (file, line, rule) site)

| Analyzer | Counted | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| Final | confirmed+potential | 74 | 0 | 53 | 2 | 1.000 | 0.974 | 0.987 | 0.000 |
| Final | confirmed only | 58 | 0 | 53 | 18 | 1.000 | 0.763 | 0.866 | 0.000 |

The two FNs are the remaining known limitations (callable passed as a callback,
`getattr` with a computed name). Label changes in this phase, all intentional: the
bound-method-alias and literal-`getattr` cases are no longer known limitations; the
`compile()` fixture now executes the code object (compiling alone is not a sink) and a
compile-only safe case was added. The multi-file project fixture reports exactly its 8
labelled flows and nothing else.

---

## 6. Known limitations

Modelled since the previous version: constant propagation with infeasible-branch
pruning (`if`, conditional expressions, `match` on constants), dict/list/ConfigParser
contents by constant key, object aliases (`b = a`), `return`/`raise` through
`finally`, function aliases / literal `getattr` / `functools.partial`, cross-file
analysis (`--project`).

Still approximated (listed per function in `SecurityFindings.unmodelled` where applicable):

* Exceptions raised inside `except` handlers are not routed to outer handlers;
  `break`/`continue` inside `try … finally` skip the `finally` block.
* Short-circuit `and`/`or` is not split into blocks (constant operands are folded);
  `match` patterns refine nothing beyond constant subjects; lambda and class bodies are
  not analysed; comprehension variables share the function namespace.
* An alias bound to different callables on different paths is left unresolved.

False-negative risks (measured where noted):

* **Library code without sources** (measured: dominant on GHSA): parameter-origin flows
  are reported only as `potential/low`, and for path traversal and XSS not at all.
* Callbacks/higher-order functions, `getattr` with computed names, decorators that
  change behaviour, dynamic imports, imports from outside the analysed project root.
* Sinks not in the registry (measured on GHSA: Prisma `query_raw`, HTML built as
  strings in renderers, `torch.load`, zmq `recv_pyobj`, `send_from_directory`'s
  directory argument).
* Mutation of containers by unresolved calls is ignored by default
  (`Registry(unknown_calls_mutate_args=True)` opts in, at a false-positive cost).

False-positive risks (measured where noted):

* **Validation in helper functions that raise** is not recognised (measured: piccolo,
  dulwich patched revisions), nor `assert`-based validation (Paddle) — deliberately,
  since asserts are stripped under `-O`.
* Value equivalence is not tracked (blender-mcp checks `abspath(x)` but opens `x`).
* Field (`self.x`) taint is flow-insensitive per class; unknown calls propagate taint
  from all inputs; `'../' in p` checks only lower confidence; route-handler return XSS
  assumes `text/html`; SEC011 session relevance is inferred from container names.

---

## 7. Reproducing

```bash
# environment (Python 3.11/3.12)
py -3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # no new dependencies

# security analysis only (no comment generation, no ML)
.venv/Scripts/python.exe -m src.security path/to/file.py
.venv/Scripts/python.exe -m src.security path/to/project --project      # cross-file
.venv/Scripts/python.exe -m src.main path/to/file.py --security --security-json outputs/sec.json

# tests and synthetic regression evaluation
.venv/Scripts/python.exe -m pytest tests -q
.venv/Scripts/python.exe -m src.security.evaluate [--confirmed-only]

# independent benchmarks (needs git + gh; data goes to the git-ignored .benchmarks/)
.venv/Scripts/python.exe benchmarks/fetch.py
.venv/Scripts/python.exe -m src.security.benchmarks owasp --split all [--project]
.venv/Scripts/python.exe -m src.security.benchmarks realworld --split all

# the same runner against the original analyzer (any checkout of commit 53a0611)
git worktree add --detach ../ccg-baseline 53a0611
cp src/security/benchmarks.py ../ccg-baseline/src/security/
cd ../ccg-baseline && SEC_BENCH_DATA=<repo>/.benchmarks SEC_BENCH_MANIFEST=<repo>/benchmarks/realworld/manifest.json \
    python -m src.security.benchmarks realworld --split all --out <repo>/outputs/benchmarks/baseline
```
