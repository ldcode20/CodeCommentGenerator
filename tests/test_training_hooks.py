"""
Progress / cancel hooks of the training pipeline.

No model is downloaded: the trainer-level test cancels before the model is
created, and the fine-tune test reuses the local checkpoint (skipped when none
has been trained).
"""
import json
import os
import tempfile
import unittest

from src.config import AST_MODEL_DIR


def _write_dataset(path, n=24):
    records = [{"func_name": f"f{i}", "input_text": f"function f{i} params: a, b returns: int",
                "target_text": f"Return the sum number {i}."} for i in range(n)]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(records, fh)


class TestTrainerCancel(unittest.TestCase):

    def test_cancel_before_fine_tuning_saves_nothing(self):
        from src.ml.trainer import TrainingCancelled, train_and_evaluate
        stages = []
        with tempfile.TemporaryDirectory() as tmp:
            dataset = os.path.join(tmp, "data.json")
            _write_dataset(dataset)
            out = os.path.join(tmp, "out")
            with self.assertRaises(TrainingCancelled):
                train_and_evaluate(
                    output_dir=out, dataset_json=dataset, epochs=1, verbose=False,
                    progress_callback=lambda stage, done, total, msg: stages.append(stage),
                    should_stop=lambda: True,
                )
            self.assertEqual(stages, ["dataset"])
            # No checkpoint and no reports: a cancelled run must not look trained.
            self.assertFalse(os.path.exists(os.path.join(out, "model", "ast_model", "config.json")))
            self.assertFalse(os.path.exists(os.path.join(out, "training_report.json")))


@unittest.skipUnless((AST_MODEL_DIR / "config.json").exists(), "no local checkpoint to reuse")
class TestFineTuneHooks(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            from src.ml.ast_comment_model import ASTCommentModel
            cls.model = ASTCommentModel.load(str(AST_MODEL_DIR))
        except ImportError:
            raise unittest.SkipTest("torch / transformers not installed")
        from src.ml.ast_dataset_builder import ASTTrainPair
        cls.pairs = [ASTTrainPair(f"f{i}", f"function f{i} params: a returns: int",
                                  f"Return value {i}.") for i in range(20)]

    def test_progress_reaches_total(self):
        calls = []
        self.model.fine_tune(self.pairs, epochs=1, batch_size=4, verbose=False,
                             progress_callback=lambda done, total, msg: calls.append((done, total)))
        self.assertTrue(calls)
        done, total = calls[-1]
        self.assertEqual(done, total)
        self.assertTrue(all(0 < d <= t for d, t in calls))

    def test_should_stop_raises_training_cancelled(self):
        from src.ml.ast_comment_model import TrainingCancelled
        seen = []

        def stop():
            seen.append(1)
            return len(seen) > 2          # allow two batches, then stop

        with self.assertRaises(TrainingCancelled):
            self.model.fine_tune(self.pairs, epochs=3, batch_size=4, verbose=False,
                                 should_stop=stop)
        self.assertEqual(len(seen), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
