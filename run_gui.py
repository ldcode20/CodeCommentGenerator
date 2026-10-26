import sys
import os

# Ensure the root project directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import configure_stdio
from PyQt6.QtWidgets import QApplication
from src.gui.main_window import MainWindow
from src.gui.theme import MAIN_STYLESHEET

def main():
    configure_stdio()
    app = QApplication(sys.argv)
    app.setStyleSheet(MAIN_STYLESHEET)
    
    window = MainWindow()
    window.resize(1100, 750)
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
