"""
main.py
=======
Clean application entry point for the AES Image Encryption & Decryption suite.
Course Project: SCE 422e • Security Engineering.
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def main():
    """Verify runtime environment and launch the CustomTkinter GUI."""
    if sys.version_info < (3, 10):
        print(
            f"Error: Python 3.10 or higher is required. Current version is {sys.version}.",
            file=sys.stderr
        )
        sys.exit(1)

    # Optional: Enable high-DPI scaling awareness on Windows
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    from gui import AESImageCipherApp

    app = AESImageCipherApp()
    app.mainloop()


if __name__ == "__main__":
    main()
