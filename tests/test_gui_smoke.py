"""
GUI smoke tests.

Run headless (Qt "offscreen" platform), with no trained model required: they
use the rule-based engine and the security analyzer only.  Skipped when PyQt6
is not installed.
"""
import os
import sys
import tempfile
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtCore import QSettings
    from PyQt6.QtWidgets import QApplication, QMessageBox
    _QT_OK = True
except ImportError:  # pragma: no cover
    _QT_OK = False

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECURITY_SAMPLE = os.path.join(ROOT, "tests", "inputs", "test_security.py")
PROJECT_FIXTURE = os.path.join(ROOT, "tests", "security_fixtures_project", "webapp")


def _wait(app, predicate, timeout=60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.processEvents()
        if predicate():
            app.processEvents()
            return True
        time.sleep(0.01)
    return False


@unittest.skipUnless(_QT_OK, "PyQt6 is not installed")
class TestGuiSmoke(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv[:1])
        from src.gui.theme import MAIN_STYLESHEET
        cls.app.setStyleSheet(MAIN_STYLESHEET)

    def setUp(self):
        from src.gui.main_window import MainWindow
        self.tmp = tempfile.TemporaryDirectory()
        settings = QSettings(os.path.join(self.tmp.name, "settings.ini"), QSettings.Format.IniFormat)
        self.window = MainWindow(capture_output=False, settings=settings)
        self.window.workspace_gen.out_dir_input.setText(os.path.join(self.tmp.name, "out"))
        # Any modal dialog would block a headless run; record instead.
        self.dialogs = []
        self._orig = (QMessageBox.warning, QMessageBox.information, QMessageBox.question)
        QMessageBox.warning = staticmethod(lambda *a, **k: self.dialogs.append(a[1:3]))
        QMessageBox.information = staticmethod(lambda *a, **k: self.dialogs.append(a[1:3]))
        QMessageBox.question = staticmethod(
            lambda *a, **k: self.dialogs.append(a[1:3]) or QMessageBox.StandardButton.Yes)

    def tearDown(self):
        QMessageBox.warning, QMessageBox.information, QMessageBox.question = self._orig
        self.window.close()
        self.app.processEvents()
        self.tmp.cleanup()

    def _generate(self, path=SECURITY_SAMPLE):
        gen = self.window.workspace_gen
        self.assertTrue(gen.load_file(path))
        gen.set_engine("rule_based")
        self.window.trigger_generation()
        self.assertTrue(_wait(self.app, lambda: not gen.is_busy() and not self.window.btn_generate.is_spinning()))
        return gen

    def test_window_builds_with_five_pages(self):
        self.assertEqual(self.window.stacked_widget.count(), 5)
        self.assertEqual(self.window.windowTitle(), "Code Comment Generator")
        self.assertIn("not analysed", self.window.workspace_gen.unsafe_label.text())

    def test_empty_input_does_not_lock_generate_button(self):
        self.window.trigger_generation()
        self.app.processEvents()
        self.assertEqual(len(self.dialogs), 1)
        self.assertFalse(self.window.btn_generate.is_spinning())
        self.assertTrue(self.window.btn_generate.isEnabled())

    def test_rule_based_generation_fills_every_workspace(self):
        gen = self._generate()
        output = gen.output_editor.toPlainText()
        self.assertIn('"""', output)
        compile(output, "annotated.py", "exec")
        # saved under the real file name, in the chosen folder
        self.assertEqual(os.path.basename(gen.last_output_file), "test_security_annotated.py")
        self.assertTrue(os.path.isfile(gen.last_output_file))
        self.assertTrue(os.listdir(os.path.join(gen.output_dir(), "logs")))
        self.assertIn("Pipeline Logs (GUI)", self.window.workspace_logs.output_dirs)
        self.assertEqual(self.window.workspace_logs.output_dirs["Pipeline Logs (GUI)"],
                         os.path.join(gen.output_dir(), "logs"))
        # insights, security tab and badge all populated
        self.assertGreater(self.window.workspace_insights.tree_ast.topLevelItemCount(), 0)
        sec = self.window.workspace_security
        self.assertGreater(sec.table.rowCount(), 0)
        self.assertIn("evidence", sec.evidence.toPlainText())
        self.assertIn("unsafe", gen.unsafe_label.text())
        self.assertTrue(gen.btn_save.isEnabled())

    def test_syntax_error_is_reported_on_the_line(self):
        gen = self.window.workspace_gen
        gen.input_editor.setPlainText("def ok():\n    return 1\n\ndef broken(:\n    pass\n")
        gen.set_engine("rule_based")
        self.window.trigger_generation()
        self.assertTrue(_wait(self.app, lambda: not gen.is_busy() and not self.window.btn_generate.is_spinning()))
        self.assertFalse(gen.error_banner.isHidden())
        self.assertIn("line 4", gen.error_banner.text())
        self.assertNotIn("Traceback", gen.error_banner.text())
        self.assertEqual(gen.input_editor.textCursor().blockNumber() + 1, 4)
        self.assertEqual(gen.output_editor.toPlainText(), "")

    def test_security_scan_without_generation_and_jump(self):
        gen, sec = self.window.workspace_gen, self.window.workspace_security
        self.assertTrue(gen.load_file(SECURITY_SAMPLE))
        sec.scanEditorRequested.emit()
        self.assertTrue(_wait(self.app, lambda: not sec.is_busy() and sec.table.rowCount() > 0))
        self.assertEqual(gen.output_editor.toPlainText(), "")       # nothing was generated
        finding = sec._visible[0]
        self.window.show_page(3)
        sec.table.cellDoubleClicked.emit(0, 0)
        self.app.processEvents()
        self.assertEqual(self.window.stacked_widget.currentIndex(), 0)
        self.assertEqual(gen.input_editor.textCursor().blockNumber() + 1, finding.line)
        # filters and export
        sec.status_filter.setCurrentIndex(4)                         # suppressed only
        self.assertEqual(sec.table.rowCount(), sum(f.status == "suppressed" for f in sec._findings))
        self.assertIn("findings", sec.export_data())

    def test_folder_scan_and_open_finding_file(self):
        gen, sec = self.window.workspace_gen, self.window.workspace_security
        sec.scan_folder(PROJECT_FIXTURE)
        self.assertTrue(_wait(self.app, lambda: not sec.is_busy() and sec._project is not None))
        self.assertGreater(sec.table.rowCount(), 0)
        finding = sec._visible[0]
        sec.table.cellDoubleClicked.emit(0, 0)
        self.app.processEvents()
        self.assertEqual(os.path.normcase(gen.current_filepath),
                         os.path.normcase(os.path.abspath(finding.file)))
        self.assertEqual(gen.input_editor.textCursor().blockNumber() + 1, finding.line)

    def test_training_options_follow_presets(self):
        ml = self.window.workspace_ml
        ml.preset_combo.setCurrentText("Quick check")
        params = ml.training_params()
        self.assertEqual((params["epochs"], params["codesearchnet_max"]), (1, 2000))
        ml.spin_epochs.setValue(7)
        self.assertEqual(ml.preset_combo.currentText(), "Custom")
        self.assertEqual(ml.training_params()["epochs"], 7)

    def test_settings_round_trip(self):
        gen = self.window.workspace_gen
        gen.set_engine("rule_based")
        gen.out_dir_input.setText(os.path.join(self.tmp.name, "elsewhere"))
        self.window.save_settings()
        from src.gui.main_window import MainWindow
        again = MainWindow(capture_output=False, settings=self.window._settings)
        try:
            self.assertEqual(again.workspace_gen.out_dir_input.text(),
                             os.path.join(self.tmp.name, "elsewhere"))
            self.assertEqual(again.workspace_gen.selected_engine(), "rule_based")
        finally:
            again.close()

    def test_java_file_gets_javadoc_and_python_only_notes(self):
        sample = os.path.join(ROOT, "tests", "inputs", "multilang", "Inventory.java")
        gen = self.window.workspace_gen
        self.assertTrue(gen.load_file(sample))
        self.assertEqual(gen.selected_language(), "java")
        self.assertFalse(gen.btn_ml.isEnabled() or gen.btn_neuro.isEnabled())
        self.assertEqual(type(gen.input_highlighter).__name__, "CFamilySyntaxHighlighter")
        self._generate(sample)
        output = gen.output_editor.toPlainText()
        self.assertIn("/**", output)
        self.assertIn("@throws IOException", output)
        self.assertEqual(os.path.basename(gen.last_output_file), "Inventory_annotated.java")
        self.assertIn("Python only", gen.unsafe_label.text())
        self.assertIn("not scanned", self.window.workspace_security.source_label.text())
        self.assertIn("Python only", self.window.workspace_insights.tab_ir.toPlainText())
        self.assertGreater(self.window.workspace_insights.tree_ast.topLevelItemCount(), 0)

    def test_language_switch_swaps_highlighter_and_engines(self):
        gen = self.window.workspace_gen
        for language in ("c", "cpp", "java"):
            gen.set_language(language)
            gen.input_editor.setPlainText('/* a\n b */ int main(void) { return "x\\"y"[0]; } // c\n')
            self.app.processEvents()
            self.assertEqual(type(gen.output_highlighter).__name__, "CFamilySyntaxHighlighter")
            self.assertEqual(gen.source_name(), "untitled" + {"c": ".c", "cpp": ".cpp", "java": ".java"}[language])
        gen.set_language("python")
        self.assertEqual(type(gen.input_highlighter).__name__, "PythonSyntaxHighlighter")
        self.assertEqual(gen.source_name(), "untitled.py")


if __name__ == "__main__":
    unittest.main(verbosity=2)
