"""背景 QThread workers：載入、查詢、統計。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import QThread, Signal

from ..cache_store import (
    clear_cache_for,
    compute_fingerprint,
    get_cache_db_path,
    is_cache_valid,
    load_cache_meta,
    save_cache_meta,
)
from ..database import LogDatabase
from ..parser import collect_log_files, parse_files_into_db
from ..stats import compute_stats


class LoadLogsWorker(QThread):
    """背景解析 log 並寫入 SQLite（含快取命中判斷）。"""

    progress = Signal(str, int, int)  # file_name, current_file_idx, total_files
    # db, total, source_names, fields, fingerprint
    finished_ok = Signal(object, int, list, list, str)
    failed = Signal(str)
    cache_hit = Signal()  # 通知 UI 使用了快取

    def __init__(
        self,
        paths: list[str | Path],
        tz_name: str = "Asia/Taipei",
        force_reload: bool = False,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.paths = paths
        self.tz_name = tz_name
        self.force_reload = force_reload
        self._cancel = False
        self._db: LogDatabase | None = None

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        db: LogDatabase | None = None
        try:
            files = collect_log_files(list(self.paths))
            if not files:
                self.failed.emit("找不到可載入的 .log 檔案")
                return

            fingerprint = compute_fingerprint(files)

            if not self.force_reload and is_cache_valid(fingerprint):
                meta = load_cache_meta(fingerprint)
                if meta:
                    db_path = get_cache_db_path(fingerprint)
                    db = LogDatabase(path=db_path, existing=True)
                    db.source_files = meta.get("source_names", [])
                    self._db = db
                    self.cache_hit.emit()
                    self.finished_ok.emit(
                        db,
                        meta.get("total", db.total_raw),
                        meta.get("source_names", []),
                        meta.get("fields", []),
                        fingerprint,
                    )
                    return

            # 重新匯入：清掉舊 DB / meta / 統計快取
            clear_cache_for(fingerprint)
            cache_db_path = get_cache_db_path(fingerprint)
            db = LogDatabase(path=cache_db_path)
            self._db = db

            def on_progress(name: str, cur: int, total: int) -> None:
                self.progress.emit(name, cur, total)

            total, sources, fields = parse_files_into_db(
                [str(f) for f in files],
                db,
                tz_name=self.tz_name,
                progress=on_progress,
                should_cancel=lambda: self._cancel,
                resolved_files=files,
            )
            if self._cancel:
                db.close()
                self.failed.emit("已取消載入")
                return

            save_cache_meta(
                fingerprint,
                total,
                sources,
                fields,
                [str(f) for f in files],
            )
            self.finished_ok.emit(db, total, sources, fields, fingerprint)
        except Exception as exc:
            if db is not None:
                try:
                    db.close()
                except Exception:
                    pass
            self.failed.emit(str(exc))


class QueryWorker(QThread):
    """背景查詢 count + 當頁資料，避免阻塞 UI。"""

    finished = Signal(list, int, int)  # rows, total_filtered, total_raw
    failed = Signal(str)

    _generation = 0  # class-level counter for cancellation

    def __init__(
        self,
        db: LogDatabase,
        page: int,
        page_size: int,
        sort_key: str,
        sort_dir: str,
        filter_rules: list[dict[str, Any]],
        column_filters: dict[str, str],
        time_start_ms: int | None,
        time_end_ms: int | None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.db = db
        self.page = page
        self.page_size = page_size
        self.sort_key = sort_key
        self.sort_dir = sort_dir
        self.filter_rules = filter_rules
        self.column_filters = column_filters
        self.time_start_ms = time_start_ms
        self.time_end_ms = time_end_ms
        QueryWorker._generation += 1
        self._my_gen = QueryWorker._generation

    @property
    def is_latest(self) -> bool:
        return self._my_gen == QueryWorker._generation

    def run(self) -> None:
        try:
            if not self.is_latest:
                return
            total_filtered = self.db.count(
                self.filter_rules,
                self.column_filters,
                self.time_start_ms,
                self.time_end_ms,
            )
            if not self.is_latest:
                return
            rows = self.db.fetch_page(
                page=self.page,
                page_size=self.page_size,
                sort_key=self.sort_key,
                sort_dir=self.sort_dir,
                filter_rules=self.filter_rules,
                column_filters=self.column_filters,
                time_start_ms=self.time_start_ms,
                time_end_ms=self.time_end_ms,
            )
            if not self.is_latest:
                return
            self.finished.emit(rows, total_filtered, self.db.total_raw)
        except Exception as exc:
            self.failed.emit(str(exc))


class StatsWorker(QThread):
    """背景計算統計（僅套用過濾規則，不含表格欄位/時間篩選）。"""

    progress = Signal(str)
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        db: LogDatabase,
        filter_rules: list[dict[str, Any]],
        tz_name: str = "Asia/Taipei",
        thresholds: dict[str, Any] | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.db = db
        self.filter_rules = filter_rules
        self.tz_name = tz_name
        self.thresholds = thresholds or {}

    def run(self) -> None:
        try:
            result = compute_stats(
                self.db,
                self.filter_rules,
                column_filters=None,
                time_start_ms=None,
                time_end_ms=None,
                tz_name=self.tz_name,
                thresholds=self.thresholds,
                progress=lambda msg: self.progress.emit(msg),
            )
            self.finished_ok.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class ExportCsvWorker(QThread):
    """背景依目前表格條件串流匯出 CSV。"""

    progress = Signal(int)  # written rows
    finished_ok = Signal(str, int)  # path, count
    failed = Signal(str)

    def __init__(
        self,
        db: LogDatabase,
        path: str | Path,
        fields: list[str],
        filter_rules: list[dict[str, Any]],
        column_filters: dict[str, str],
        time_start_ms: int | None,
        time_end_ms: int | None,
        sort_key: str = "id",
        sort_dir: str = "asc",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.db = db
        self.path = path
        self.fields = fields
        self.filter_rules = filter_rules
        self.column_filters = column_filters
        self.time_start_ms = time_start_ms
        self.time_end_ms = time_end_ms
        self.sort_key = sort_key
        self.sort_dir = sort_dir
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        from ..export_csv import export_filtered_csv

        try:
            out, count = export_filtered_csv(
                self.db,
                self.path,
                self.fields,
                filter_rules=self.filter_rules,
                column_filters=self.column_filters,
                time_start_ms=self.time_start_ms,
                time_end_ms=self.time_end_ms,
                sort_key=self.sort_key,
                sort_dir=self.sort_dir,
                progress=lambda n: self.progress.emit(n),
                should_cancel=lambda: self._cancel,
            )
            if self._cancel:
                self.failed.emit("已取消匯出")
                return
            self.finished_ok.emit(str(out), count)
        except Exception as exc:
            self.failed.emit(str(exc))
