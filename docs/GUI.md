# Code Comment Generator — GUI guide

Start it with `python run_gui.py` (or `code-comment-gen-gui` after `pip install -e .[gui]`).
The window has five pages in the sidebar and a console pane at the bottom.

| Shortcut | Action |
|---|---|
| Ctrl+O | Open a Python file |
| Ctrl+Enter | Generate comments |
| Ctrl+S | Save the annotated output as… |
| Alt+1 … Alt+5 | Switch page |

Window size, splitter positions, the chosen engine, the output folder and the training
options are remembered between sessions.

## Generator

- **Input** (left): paste code, use *Open File…*, or drop a `.py` file on the editor.
  Line numbers and the current line are shown.
- **Engine**: Rule-Based always works. Neurosymbolic and ML-Based are enabled only when a
  trained model exists in `outputs/model/ast_model/`; the model is loaded once and reused.
- **Generate Comments** (top right) runs the full pipeline off the UI thread.
- **Output** (right): the annotated code. *Highlight added lines* tints every line the
  generator added; *Copy* and *Save As…* export it. Each run is also written to
  `<output folder>/<name>_annotated.py`, with logs in `<output folder>/logs/`.
- **Output folder**: relative paths are resolved against the project folder, not the
  directory the app was launched from. The Logs page follows this folder.
- **Security badge**: "not analysed" until a run or a scan; then the share of unsafe
  functions and the number of issues.
- A syntax error is shown as one line above the output and the offending line is
  highlighted in the input. Other errors show a short message; the traceback goes to the console.

## Security

Works without a trained model and without generating comments.

- **Scan Editor Code** analyses the code currently in the Generator editor.
- **Scan Folder…** analyses every `.py` file in a folder, following calls between files
  (`src/security/project.py`).
- The charts (single file) show the safe/unsafe split, issues by severity, a score per
  function (`Class.method` for methods) and issue types. A folder scan shows a summary instead.
- **Findings** table: filter by severity and status (suppressed findings are hidden by default).
- **Evidence** panel: for the selected finding, the source-to-sink trace, path conditions,
  the reasons for the confidence level and the fix.
- Double-click a finding (or *Open in editor*) to jump to its line in the Generator; for a
  folder scan the file is opened first.
- **Export JSON…** writes the full findings.

## ML Training

- The card at the top shows whether a model exists, when it was saved and its last scores.
- **Preset**: *Quick check* (minutes, pipeline test only), *Standard*, *Full* (multi-hour),
  or *Custom* once any value is edited.
- **Reuse the saved dataset** skips the download and rebuild when
  `outputs/ast_train_dataset.json` exists.
- The progress bar is exact during fine-tuning and indeterminate while the dataset is
  built, evaluated or saved.
- **Cancel** stops between batches. Nothing is saved on cancel, so the previous model is
  kept. The dataset build (including the HuggingFace download) cannot be interrupted.
- After a successful run the Generator drops its cached model and the engines are re-enabled.

## Insights

Tabs: AST Features, AST Graph, Context Graph, Call Graph, IR Dump, Analysis Report,
Evaluation. They are filled by the last generation run. In **Analysis Report**, double-click
a row to open its line in the Generator. The graph views support drag to pan, scroll to zoom
and double-click to reset.

## Logs

A file tree of the GUI pipeline logs, CLI logs (`--logs`, written to `outputs/logs/`) and
training reports, with a viewer on the right. The list refreshes when the page is opened.

## Code map

| Part | File |
|---|---|
| Entry point | `src/gui/app.py` (`run_gui.py` calls it) |
| Window, navigation, console, shortcuts, settings | `src/gui/main_window.py` |
| Editor with line numbers and line tints | `src/gui/code_editor.py` |
| Generator / Security / Training / Insights / Logs pages | `src/gui/*_workspace.py` |
| Charts and graphs | `src/gui/*_graph_widget.py` |
| Palette and stylesheet | `src/gui/theme.py` |
| Headless smoke tests | `tests/test_gui_smoke.py` |
