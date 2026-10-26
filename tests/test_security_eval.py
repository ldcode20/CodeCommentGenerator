"""
Security evaluation tests
==========================
* metric formulas checked against hand-computed values (incl. undefined cases)
* scoring rules (TP/FP/TN/FN assignment) on a synthetic label set
* the fixture suite: pinned counts so regressions in either direction fail
"""
import os
import unittest

from src.security.evaluate import (
    DEFAULT_FIXTURES, Label, Reported, evaluate, fixture_files, load_labels, metrics, score,
)


class TestMetricFormulas(unittest.TestCase):

    def test_hand_computed_values(self):
        m = metrics(tp=3, fp=1, tn=4, fn=2)
        self.assertAlmostEqual(m["precision"], 0.75)
        self.assertAlmostEqual(m["recall"], 0.6)
        self.assertAlmostEqual(m["f1"], 2 * 0.75 * 0.6 / (0.75 + 0.6))
        self.assertAlmostEqual(m["false_positive_rate"], 0.2)

    def test_zero_denominators_are_undefined_not_perfect(self):
        m = metrics(tp=0, fp=0, tn=0, fn=0)
        self.assertIsNone(m["precision"])
        self.assertIsNone(m["recall"])
        self.assertIsNone(m["f1"])
        self.assertIsNone(m["false_positive_rate"])
        m = metrics(tp=0, fp=0, tn=5, fn=3)
        self.assertIsNone(m["precision"])     # nothing reported
        self.assertEqual(m["recall"], 0.0)
        self.assertEqual(m["false_positive_rate"], 0.0)

    def test_f1_zero_when_precision_and_recall_zero(self):
        self.assertEqual(metrics(tp=0, fp=2, tn=0, fn=2)["f1"], 0.0)


class TestScoringRules(unittest.TestCase):

    def test_assignment_of_outcomes(self):
        labels = [
            Label("a.py", 10, "SEC005", "expect"),     # two findings → one TP
            Label("a.py", 20, "SEC005", "expect"),     # missed → FN
            Label("a.py", 30, "SEC005", "safe"),       # finding here → FP, not TN
            Label("a.py", 40, "SEC005", "safe"),       # clean → TN
            Label("a.py", 50, "SEC005", "expect-suppressed"),
        ]
        reported = [
            Reported("a.py", 10, "SEC005", "confirmed"),
            Reported("a.py", 10, "SEC005", "potential"),
            Reported("a.py", 30, "SEC005", "potential"),
            Reported("a.py", 60, "SEC005", "confirmed"),    # unlabelled → FP
            Reported("a.py", 50, "SEC005", "suppressed"),   # ignored, counts as TN
            Reported("a.py", 70, "SEC999", "confirmed"),    # rule never labelled → ignored
        ]
        r = score(labels, reported, {})
        o = r["overall"]
        self.assertEqual((o["tp"], o["fp"], o["tn"], o["fn"]), (1, 2, 2, 1))
        self.assertEqual(r["suppression_checks"], {"expected": 1, "correct": 1})
        self.assertEqual([f["line"] for f in r["false_positives"]], [30, 60])

    def test_confirmed_only_filter(self):
        labels = [Label("a.py", 10, "SEC002", "expect")]
        reported = [Reported("a.py", 10, "SEC002", "potential")]
        self.assertEqual(score(labels, reported, {}, statuses=("confirmed",))["overall"]["fn"], 1)

    def test_label_parsing(self):
        path = os.path.join(DEFAULT_FIXTURES, "patterns_mixed.py")
        labels = load_labels(path)
        kinds = {l.kind for l in labels}
        self.assertEqual(kinds, {"expect", "safe", "expect-suppressed"})
        sup = [l for l in labels if l.kind == "expect-suppressed"]
        self.assertEqual([l.rule for l in sup], ["SEC005"])


class TestFixtureSuite(unittest.TestCase):
    """Pinned results on tests/security_fixtures (update deliberately, with a reason)."""

    @classmethod
    def setUpClass(cls):
        cls.all = evaluate()
        cls.confirmed = evaluate(statuses=("confirmed",))

    def test_every_class_has_vulnerable_and_secure_examples(self):
        for name, m in self.all["per_class"].items():
            self.assertGreater(m["tp"] + m["fn"], 0, f"{name}: no positive example")
            self.assertGreater(m["tn"] + m["fp"], 0, f"{name}: no negative example")

    def test_overall_counts_all_reported(self):
        o = self.all["overall"]
        self.assertEqual((o["tp"], o["fp"], o["tn"], o["fn"]), (73, 0, 52, 1))
        self.assertEqual(self.all["false_negatives"],
                         [{"file": "cmdi_vulnerable.py", "line": 83, "rule": "SEC002",
                           "known_limitation": True}])
        self.assertEqual(self.all["suppression_checks"], {"expected": 1, "correct": 1})

    def test_overall_counts_confirmed_only(self):
        o = self.confirmed["overall"]
        self.assertEqual((o["tp"], o["fp"], o["tn"], o["fn"]), (56, 0, 52, 18))

    def test_counts_are_reproducible(self):
        again = evaluate()
        self.assertEqual(again["overall"], self.all["overall"])
        self.assertEqual(again["per_class"], self.all["per_class"])

    def test_malformed_fixture_does_not_crash(self):
        names = [os.path.basename(p) for p in fixture_files(DEFAULT_FIXTURES)]
        self.assertIn("malformed_input.py", names)
        self.assertIn("malformed_input.py", self.all["performance"]["per_file_ms"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
