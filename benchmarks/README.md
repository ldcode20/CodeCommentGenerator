# Independent security benchmarks

Three datasets are kept strictly apart:

| Dataset | Where | Role |
|---|---|---|
| Synthetic regression fixtures | `tests/security_fixtures/`, `tests/security_fixtures_project/` | Written together with the analyzer. Regression tests only — **not** evidence of real-world accuracy. |
| OWASP BenchmarkPython | fetched to `.benchmarks/BenchmarkPython` | Independently labelled, generated Flask test cases. Split into dev / held-out by template family. |
| GHSA real-world fix pairs | labels in `realworld/manifest.json`, files fetched to `.benchmarks/realworld` | Vulnerable (parent) and patched (fix) revisions of real Python projects. Split into dev / held-out by project. |

Third-party code is never committed: `.benchmarks/` and `outputs/benchmarks/` are git-ignored.

```bash
python benchmarks/fetch.py                       # pinned OWASP commit + GHSA case files (needs git, gh)
python -m src.security.benchmarks owasp --split all              # single-file analysis
python -m src.security.benchmarks owasp --split all --project    # cross-file analysis
python -m src.security.benchmarks realworld --split all
```

Each run writes `<dataset>_<split>_raw.json` (every finding per file) and
`<dataset>_<split>_summary.json` (metrics, exclusions, run metadata: analyzer git HEAD +
dirty flag + hash of the security sources, dataset version, config, UTC timestamp).

## OWASP BenchmarkPython

* Source: <https://github.com/OWASP-Benchmark/BenchmarkPython>, commit
  `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (v0.1), GPL-3.0.
* Ground truth: the project's own `expectedresults-0.1.csv` (test, category, real vulnerability, CWE).
  Labels are used unchanged.
* Unit: one test case × its category, OWASP's convention — *flagged* if any finding of a
  mapped rule exists in the test file. Mapping: cmdi→SEC002, codeinj→SEC001,
  deserialization→SEC009/SEC010, hash→SEC004, pathtraver→SEC013, sqli→SEC005,
  weakrand→SEC011, xss→SEC014.
* Excluded categories (out of scope, reported as exclusions, never as true negatives):
  ldapi, redirect, securecookie, trustbound, xpathi, xxe.
* Split: cases are grouped by the normalised "propagation paragraph" (the code deriving
  `bar` from `param`, digits normalised). Whole groups go to dev or held-out.
  **Caveat:** there are only 24 template families and nearly all were inspected while
  debugging on dev (an early version of the split did not normalise digits, so some
  families inspected then now sit in held-out). OWASP held-out therefore measures
  generalisation across *instances*, not across unseen templates.

## GHSA real-world fix pairs

### Selection (mechanical, before any analyzer run)
1. Reviewed GitHub Security Advisories, ecosystem pip, CWE-89/78/22/79/94/95/502/1336.
2. Exactly one GitHub fix commit referenced; that commit has one parent, touches ≤ 3
   non-test `.py` files (all `modified`) and ≤ 80 changed lines.
3. Per category, candidates were read in GHSA-ID order and the first in-scope ones taken.

### Labelling protocol (manual, from advisory text + fix diff)
* In scope: the vulnerability is a data flow into a sink represented in the changed Python
  file. Excluded with a written reason (`EXCLUDED` in `realworld/build_manifest.py`):
  blocklists on intentionally executed input, driver/ORM internals, configuration-only or
  authorisation fixes, symlink/TOCTOU/Windows-only path handling, argument-injection
  denylists, sinks in other modules, duplicates of the same fix.
* `scope: modelled` — the sink API is one the analyzer models; `api_not_modelled` — the
  category is in scope but the sink API is not modelled (Prisma `query_raw`, HTML string
  renderers, `torch.load`, …). Both are scored; the latter only in "all_in_category".
* Sites: the (file, function) pairs containing the vulnerable sink in the parent revision
  and the corresponding functions in the fix revision.
* Each case records why the vulnerable revision should trigger the rule and why the
  patched one should not. `patched_applicable: false` when the fix removes the function
  or does not actually fix it.
* Labels were **not** derived from analyzer output and were **not independently
  reviewed** (single annotator). One correction was made after labelling
  (`LABEL_CORRECTIONS`), with its evidence recorded.

### Unit and scoring
One case × one revision over its labelled sites. Vulnerable revision: TP if the case's
rule fires in a labelled function, else FN. Patched revision: FP if it still fires there,
else TN. Findings of the rule elsewhere in the file are counted as *unscored* (their truth
is unknown). Revisions the analyzer cannot process are reported as exclusions, never as
negatives.

### Split
By project (`sha256(repo) % 2`), so no codebase appears in both dev and held-out. Held-out
results were computed once, after development stopped. Held-out is small (14 modelled
cases, no deserialization case): treat its metrics as indicative only.
