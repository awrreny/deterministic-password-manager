#!/usr/bin/env python3
"""
Launcher script for the Deterministic Password Manager GUI
Run this script to start the graphical interface
"""

if __name__ == "__main__":
    try:
        from gui import main
        main()
    except ImportError as e:
        print(f"Error importing GUI module: {e}")
        print("Make sure you're in the correct directory and all dependencies are installed.")
        print("Try: pip install pyperclip")
    except Exception as e:
        print(f"Error starting GUI: {e}")
