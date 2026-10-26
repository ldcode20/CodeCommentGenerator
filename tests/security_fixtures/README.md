# Security evaluation fixtures

Small, self-contained Python programs with **known expected outcomes**, used by
`python -m src.security.evaluate` and `tests/test_security_eval.py`.

These files are analysed, never executed. Their imports (`flask`, `yaml`, …)
need not be installed.

## Labels

Labels are trailing comments on the line where a finding is (or must not be)
reported — for flows that is the sink call's first line:

| Label | Meaning |
|---|---|
| `# expect: SEC005` | a real vulnerability of rule SEC005 starts on this line (positive) |
| `# safe: SEC005` | a secure use of a sensitive API; SEC005 must **not** be reported here (negative) |
| `# expect-suppressed: SEC005` | a vulnerability silenced by a justified `# nosec`; must appear only as `suppressed` |

Several rules may be listed: `# expect: SEC002, SEC013`.
`(known limitation)` after a label marks a case the analyzer is not designed
to catch yet; it is still counted, so recall reflects it.

## Evaluation unit

One labelled **(file, line, rule)** site.

* TP — positive site with a non-suppressed finding of that rule on that line
* FN — positive site without one
* TN — negative site without a non-suppressed finding of that rule
* FP — a non-suppressed finding that matches no positive site (at a negative
  site *or* on an unlabelled line)

Several findings on one positive site (distinct sources reaching one sink)
count as one TP. Metrics are reported per vulnerability class and overall,
both for all reported findings and for `confirmed`-only findings.

The fixtures are synthetic and were written for this project; no third-party
benchmark code is included.
