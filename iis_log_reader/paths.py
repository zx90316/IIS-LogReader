"""應用程式根目錄解析（開發模式 vs Nuitka / 凍結 exe）。"""

from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    """是否以編譯後的二進位執行（Nuitka / 類似打包）。"""
    if getattr(sys, "frozen", False):
        return True
    # Nuitka 會在模組 globals 注入 __compiled__
    return "__compiled__" in globals()


def get_app_dir() -> Path:
    """
    可寫入的應用程式目錄：
    - 凍結後：exe 所在目錄（設定檔與 cache 放旁邊）
    - 開發時：專案根目錄
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent
