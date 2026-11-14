import os
import sys

# Ensure the project root is importable when launched as a script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.gui.app import main

if __name__ == "__main__":
    sys.exit(main())
