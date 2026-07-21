"""IIS Log 分析工具 — 進入點。"""

from __future__ import annotations

import sys
from pathlib import Path

# 確保專案根目錄在 path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication

from iis_log_reader.config import AppConfig
from iis_log_reader.gui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("IIS Log 分析工具")
    app.setOrganizationName("IIS-LogReader")

    config = AppConfig(ROOT / "app.config")
    win = MainWindow(config)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
