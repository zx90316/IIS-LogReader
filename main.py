"""IIS Log 分析工具 — 進入點。"""

from __future__ import annotations

import sys
from pathlib import Path

# 開發模式：確保專案根目錄在 path
if not getattr(sys, "frozen", False):
    ROOT_DEV = Path(__file__).resolve().parent
    if str(ROOT_DEV) not in sys.path:
        sys.path.insert(0, str(ROOT_DEV))

from PySide6.QtWidgets import QApplication

from iis_log_reader.config import AppConfig
from iis_log_reader.gui.main_window import MainWindow
from iis_log_reader.paths import get_app_dir


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("IIS Log 分析工具")
    app.setOrganizationName("IIS-LogReader")

    config = AppConfig(get_app_dir() / "app.config")
    win = MainWindow(config)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
