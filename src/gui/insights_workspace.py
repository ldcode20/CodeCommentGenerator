from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTabWidget, QTextEdit, QLabel,
    QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem, QHeaderView,
    QStackedWidget
)
from PyQt6.QtGui import QColor, QBrush, QFont
from PyQt6.QtCore import Qt
from src.gui.syntax_highlighter import PythonSyntaxHighlighter
from src.gui.ast_graph_widget import AstGraphWidget
from src.gui.context_graph_widget import ContextGraphWidget
from src.gui.eval_graph_widget import EvalGraphWidget

_EMPTY_STATE_STYLE = (
    "color: #9ca3af; font-size: 14px; padding: 40px; "
    "background: transparent; border: none;"
)


def _make_empty_state(message):
    lbl = QLabel(message)
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lbl.setStyleSheet(_EMPTY_STATE_STYLE)
    lbl.setWordWrap(True)
    return lbl


class InsightsWorkspace(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._populated = False
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)

        title = QLabel("Insights & Code Visualizer")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 12px; color: #1a1a2e;")
        layout.addWidget(title)

        self.tabs = QTabWidget()

        self.tree_ast = QTreeWidget()
        self.tree_ast.setHeaderLabels(["AST Node", "Details"])
        self.tree_ast.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._empty_ast = _make_empty_state(
            "Run code generation to populate AST features.\n\n"
            "The AST tree will show functions, classes, parameters, and complexity metrics."
        )
        self._stack_ast = QStackedWidget()
        self._stack_ast.addWidget(self._empty_ast)
        self._stack_ast.addWidget(self.tree_ast)
        self.tabs.addTab(self._stack_ast, "AST Features")

        self.ast_graph = AstGraphWidget()
        self.ast_graph.setStyleSheet("background-color: #ffffff;")
        self._empty_ast_graph = _make_empty_state(
            "Run code generation to visualize the AST graph.\n\n"
            "An interactive tree graph will display nodes and their relationships."
        )
        self._stack_ast_graph = QStackedWidget()
        self._stack_ast_graph.addWidget(self._empty_ast_graph)
        self._stack_ast_graph.addWidget(self.ast_graph)
        self.tabs.addTab(self._stack_ast_graph, "AST Graph")

        self.tree_ctx = QTreeWidget()
        self.tree_ctx.setHeaderLabels(["Function", "Context Data"])
        self.tree_ctx.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._empty_ctx = _make_empty_state(
            "Run code generation to see context graph data.\n\n"
            "Function complexity, internal/external calls, and security warnings will appear here."
        )
        self._stack_ctx = QStackedWidget()
        self._stack_ctx.addWidget(self._empty_ctx)
        self._stack_ctx.addWidget(self.tree_ctx)
        self.tabs.addTab(self._stack_ctx, "Context Graph")

        self.call_graph = ContextGraphWidget()
        self.call_graph.setStyleSheet("background-color: #ffffff;")
        self._empty_call = _make_empty_state(
            "Run code generation to visualize the call graph.\n\n"
            "An interactive force-directed graph will display function call relationships."
        )
        self._stack_call = QStackedWidget()
        self._stack_call.addWidget(self._empty_call)
        self._stack_call.addWidget(self.call_graph)
        self.tabs.addTab(self._stack_call, "Call Graph")

        self.tab_ir = QTextEdit()
        self.tab_ir.setProperty("class", "CodeEditor")
        self.tab_ir.setReadOnly(True)
        self._empty_ir = _make_empty_state(
            "Run code generation to view the Intermediate Representation.\n\n"
            "The IR dump shows the internal representation used by the comment generator."
        )
        self._stack_ir = QStackedWidget()
        self._stack_ir.addWidget(self._empty_ir)
        self._stack_ir.addWidget(self.tab_ir)
        self.tabs.addTab(self._stack_ir, "IR Dump")

        self.table_analysis = QTableWidget()
        self.table_analysis.setColumnCount(4)
        self.table_analysis.setHorizontalHeaderLabels(["Severity", "Pattern", "Function", "Message"])
        self.table_analysis.horizontalHeader().setStretchLastSection(True)
        self.table_analysis.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table_analysis.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._empty_analysis = _make_empty_state(
            "Run code generation to see the analysis report.\n\n"
            "Pattern findings with severity, function, and message details will appear here."
        )
        self._stack_analysis = QStackedWidget()
        self._stack_analysis.addWidget(self._empty_analysis)
        self._stack_analysis.addWidget(self.table_analysis)
        self.tabs.addTab(self._stack_analysis, "Analysis Report")

        self.eval_graph = EvalGraphWidget()
        self.tabs.addTab(self.eval_graph, "Evaluation")

        layout.addWidget(self.tabs)

    def populate_insights(self, pipeline_results):
        self._populated = True
        mf = pipeline_results.get("mf")
        cg = pipeline_results.get("cg")
        ir_module = pipeline_results.get("ir")
        analysis_report = pipeline_results.get("analysis")

        self.tree_ast.clear()
        if mf:
            self._stack_ast.setCurrentIndex(1)
            self._stack_ast_graph.setCurrentIndex(1)
            root_funcs = QTreeWidgetItem(self.tree_ast, ["Functions", f"{len(mf.functions)} found"])
            for func in mf.functions:
                f_item = QTreeWidgetItem(root_funcs, [func.name, f"Line {func.lineno}"])

                if func.params:
                    p_root = QTreeWidgetItem(f_item, ["Parameters", ""])
                    for p in func.params:
                        p_desc = p.name
                        if p.annotation: p_desc += f": {p.annotation}"
                        if p.default: p_desc += f" = {p.default}"
                        QTreeWidgetItem(p_root, ["Param", p_desc])

                QTreeWidgetItem(f_item, ["Returns", func.return_annotation or "None"])
                QTreeWidgetItem(f_item, ["Complexity", f"Loops: {func.loops}, Conditionals: {func.conditionals}"])

            root_classes = QTreeWidgetItem(self.tree_ast, ["Classes", f"{len(mf.classes)} found"])
            for cls in mf.classes:
                c_item = QTreeWidgetItem(root_classes, [cls.name, f"Line {cls.lineno}"])
                if cls.bases: QTreeWidgetItem(c_item, ["Bases", ", ".join(cls.bases)])
                if cls.methods: QTreeWidgetItem(c_item, ["Methods", ", ".join(cls.methods)])

            self.tree_ast.expandAll()

            self.ast_graph.set_data(mf)

        self.tree_ctx.clear()
        if cg:
            self._stack_ctx.setCurrentIndex(1)
            self._stack_call.setCurrentIndex(1)
            for fc in cg.function_contexts:
                item = QTreeWidgetItem(self.tree_ctx, [fc.name, fc.complexity_label])

                if fc.complexity_label == "simple":
                    item.setForeground(1, QBrush(QColor("#16a34a")))
                elif fc.complexity_label == "moderate":
                    item.setForeground(1, QBrush(QColor("#ca8a04")))
                elif fc.complexity_label in ("complex", "very_complex"):
                    item.setForeground(1, QBrush(QColor("#dc2626")))

                if fc.calls_internal:
                    QTreeWidgetItem(item, ["Internal Calls", ", ".join(fc.calls_internal)])
                if fc.calls_external:
                    QTreeWidgetItem(item, ["External Calls", ", ".join(fc.calls_external)])

                security_issues = getattr(fc, 'security_issues', [])
                if security_issues:
                    sec_item = QTreeWidgetItem(item, ["Security Warnings", f"{len(security_issues)} found"])
                    sec_item.setForeground(0, QBrush(QColor("#dc2626")))
                    for sec in security_issues:
                        s_i = QTreeWidgetItem(sec_item, ["Warning", sec])
                        s_i.setForeground(1, QBrush(QColor("#dc2626")))
            self.tree_ctx.expandAll()

            self.call_graph.set_data(cg)

        if ir_module:
            self._stack_ir.setCurrentIndex(1)
            from src.ir import pretty_print_ir
            self.tab_ir.setPlainText(pretty_print_ir(ir_module))

        self.table_analysis.setRowCount(0)
        if analysis_report and analysis_report.findings:
            self._stack_analysis.setCurrentIndex(1)
            self.table_analysis.setRowCount(len(analysis_report.findings))
            for i, finding in enumerate(analysis_report.findings):
                sev_item = QTableWidgetItem(finding.severity.upper())
                if finding.severity == "warning":
                    sev_item.setForeground(QBrush(QColor("#ca8a04")))
                elif finding.severity == "error":
                    sev_item.setForeground(QBrush(QColor("#dc2626")))
                else:
                    sev_item.setForeground(QBrush(QColor("#2563eb")))

                self.table_analysis.setItem(i, 0, sev_item)
                self.table_analysis.setItem(i, 1, QTableWidgetItem(finding.pattern_id))
                self.table_analysis.setItem(i, 2, QTableWidgetItem(finding.function_name))
                self.table_analysis.setItem(i, 3, QTableWidgetItem(finding.message))
        self.table_analysis.resizeColumnsToContents()
        self.table_analysis.horizontalHeader().setStretchLastSection(True)

        import json, os
        from src.config import EVAL_REPORT, TRAINING_REPORT
        eval_path = str(EVAL_REPORT)
        train_path = str(TRAINING_REPORT)
        self.eval_graph.set_data(eval_json_path=eval_path, training_json_path=train_path)
