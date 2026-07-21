"""Allow `python -m iis_log_reader`."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    # Ensure project root is importable when run as a module from source tree
    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from PySide6.QtWidgets import QApplication

    from iis_log_reader.config import AppConfig
    from iis_log_reader.gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("IIS Log 分析工具")
    app.setOrganizationName("IIS-LogReader")

    config = AppConfig(root / "app.config")
    win = MainWindow(config)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
