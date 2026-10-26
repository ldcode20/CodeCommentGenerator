import os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem)
from PyQt6.QtCore import Qt
from src.config import PROJECT_ROOT, OUTPUT_DIR
from src.gui.syntax_highlighter import JsonSyntaxHighlighter

class LogsWorkspace(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        # Absolute, so the viewer finds the files regardless of where the
        # app was launched from.
        self.output_dirs = {
            "Pipeline Logs": str(PROJECT_ROOT / "out" / "annotated" / "logs"),
            "Model Training Outputs": str(OUTPUT_DIR),
            "Model Training Logs": str(OUTPUT_DIR / "logs"),
        }
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        
        header_layout = QHBoxLayout()
        title = QLabel("Logs & Reports Viewer")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #1a1a2e;")
        
        self.btn_load_logs = QPushButton("Refresh Files")
        self.btn_load_logs.setProperty("class", "SecondaryButton")
        self.btn_load_logs.clicked.connect(self.load_log_list)
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(self.btn_load_logs)
        layout.addLayout(header_layout)
        
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderHidden(True)
        self.file_tree.itemClicked.connect(self.on_file_selected)
        
        self.log_viewer = QTextEdit()
        self.log_viewer.setProperty("class", "CodeEditor")
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setPlaceholderText("Select a file from the tree to view...")
        self.hl_logs = JsonSyntaxHighlighter(self.log_viewer.document())
        
        self.splitter.addWidget(self.file_tree)
        self.splitter.addWidget(self.log_viewer)
        self.splitter.setSizes([250, 600])
        
        layout.addWidget(self.splitter, stretch=1)
        self.load_log_list()
        
    def load_log_list(self):
        self.file_tree.clear()
        
        for category, search_dir in self.output_dirs.items():
            if not os.path.exists(search_dir):
                continue
                
            cat_item = QTreeWidgetItem([category])
            cat_item.setExpanded(True)
            self.file_tree.addTopLevelItem(cat_item)
            
            files = []
            for f in os.listdir(search_dir):
                if f.endswith(".log") or f.endswith(".json") or f.endswith(".txt") or f.endswith(".csv"):
                    abs_path = os.path.abspath(os.path.join(search_dir, f))
                    if os.path.isfile(abs_path):
                        files.append((f, abs_path))
            
            files.sort(key=lambda x: os.path.getmtime(x[1]), reverse=True)
            
            for f_name, f_path in files:
                child = QTreeWidgetItem([f_name])
                child.setData(0, Qt.ItemDataRole.UserRole, f_path)
                cat_item.addChild(child)
                        
    def on_file_selected(self, item, column):
        path = item.data(0, Qt.ItemDataRole.UserRole)
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.log_viewer.setPlainText(content)
            except Exception as e:
                self.log_viewer.setPlainText(f"Error reading file: {e}")
