#!/usr/bin/env python3
import sys
import os

# Add the project root to sys.path so 'app' can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.ui.main_window import ProcSentinelGUI

def main():
    app = ProcSentinelGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
