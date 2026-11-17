# Progress Against the Proposed Architecture

Status as of 18 November 2026. "Proposed architecture" = the design in
[architecture.png](architecture.png) and the project presentation (`CodeCommentGenerator.pptx`).
Every status below was checked by running the code (CLI, GUI and the 268-test suite), not
taken from earlier notes.

**Overall:** all 11 components of the proposed architecture are built, connected and
working end to end. The one remaining gap is quality, not building: the ML model's output
quality. Measured by components, roughly **90 %** of the
proposed system is complete. Two parts go beyond the original proposal: the security
analyzer, and support for Java, C and C++ input in addition to Python (item 12).

| # | Component (proposed) | Status | Evidence | Remaining work |
|---|---|---|---|---|
| 1 | Input: CLI and GUI entry points | ✅ Done | Screenshots A1–A2, B1–B2 | — |
| 2 | Parse + semantic validation | ✅ Done | Tests; syntax errors reported with line/column | — |
| 3 | AST feature extraction | ✅ Done | B4 (AST Features), B5 (AST Graph) | — |
| 4 | Context analysis (complexity, call graph, variables) | ✅ Done | B6, B7 | — |
| 5 | Rule-based NLP engine | ✅ Done | A3 | — |
| 6 | ML engine (T5-small on AST features) | ⚠️ Working, quality low | Trained on 13,480 pairs; BLEU-4 0.060, ROUGE-L 0.262, exact match 1 % (B10, B12) | Train on the full default corpus (20,000 CodeSearchNet functions, 4 epochs) or a code-specific model; add a small human evaluation of comment quality |
| 7 | Neuro-symbolic fusion (confidence-gated) | ✅ Done | A5: ML summary used in *fused* mode at 46 % confidence | Depends on item 6 for better summaries |
| 8 | Comment attachment | ✅ Done | A3, A5; output always compiles; multi-line signatures fixed; line map kept | — |
| 9 | IR + CFG + data-flow + 7 patterns | ✅ Done (rebuilt) | A6, A7, B8, B9; IR now lowered from the real AST (branches, loops, try/finally, match) | — |
| 10 | Security analysis | ✅ Done, beyond proposal | Proposal: 12 pattern rules with a score. Now: 15 rules, taint analysis with source→sink traces, cross-file analysis, benchmarks (A8, A9, B11) | Recognise validation done in helper functions; model more sink APIs (see SECURITY_ANALYSIS.md §6) |
| 11 | Outputs: annotated file, JSON reports, GUI views | ✅ Done | A2, B3, B13 | — |
| 12 | Other input languages: Java, C, C++ (not in the proposal) | ✅ Done, beyond proposal | tree-sitter front end feeding the same AST features and context analysis; Javadoc / Doxygen comments; annotated files compile with javac / gcc / g++ (A11–A14, B14–B18) | Security analysis, IR and the ML engines are still Python-only; more languages (C#, Go, JavaScript) could reuse the same front end |
| — | Evaluation (BLEU-4, ROUGE-L, exact match; security P/R/F1/FPR) | ✅ Done | B10, A9; OWASP held-out F1 0.90–0.92, real-world held-out F1 0.69 | Larger, independently reviewed real-world security benchmark |
| — | Automated tests | ✅ Done | 268 passed (A10), including Java/C/C++ extraction, idempotence and compile checks | — |
| — | Documentation | ✅ Done | README, docs/DOCUMENTATION.md, SECURITY_ANALYSIS.md, METHODOLOGY.md, existing and proposed architecture diagrams, these screenshots | — |

## Issues found while taking the screenshots — fixed on 10 November 2026

1. **GUI safety score was misleading.** A file with one high-severity SQL injection showed
   "100.0 % safe", because one high finding cost only 15 points and a function counted as
   unsafe only below 80. Weights are now critical 40, high 25, medium 5, low 1, so any high or
   critical finding makes the function unsafe; the sample now shows 83.3 % safe (B11).
   Regression test: `test_single_high_finding_makes_function_unsafe`.
2. **AST graph did not fit the window.** It now zooms and centres itself when data is loaded
   or the window is resized; double-click resets the view (B5).
3. **`matplotlib` was missing from `requirements.txt`** although the GUI charts need it. Added.

4. **Presentation was out of date.** `CodeCommentGenerator.pptx` has been corrected: 15 rules
   with taint analysis (slides 2, 4, 9), the new score weights (slide 4), the new severity
   groups including SEC013–SEC015 (slide 4), and P007 renamed to *Unused parameter* (slide 6).
