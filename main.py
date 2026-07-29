"""IIS Log 分析工具 — 進入點（GUI / CLI 雙模式）。"""

from __future__ import annotations

import argparse
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


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="IIS-LogReader",
        description="IIS Log 分析工具。不帶參數時開啟 GUI。",
    )
    parser.add_argument(
        "--cli",
        metavar="PATH",
        help="CLI 模式：分析指定的 log 檔案或資料夾，直接匯出報告與建議黑名單",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="DIR",
        default=None,
        help="輸出目錄（預設 ./iis_export）",
    )
    parser.add_argument(
        "--format",
        choices=["html", "md"],
        default="html",
        help="報告格式（預設 html）",
    )
    return parser


def main() -> int:
    args, _unknown = _build_arg_parser().parse_known_args()
    if args.cli:
        from iis_log_reader.cli import run_cli

        return run_cli(args.cli, args.output, args.format)

    app = QApplication(sys.argv)
    app.setApplicationName("IIS Log 分析工具")
    app.setOrganizationName("IIS-LogReader")

    config = AppConfig(get_app_dir() / "app.config")
    win = MainWindow(config)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
