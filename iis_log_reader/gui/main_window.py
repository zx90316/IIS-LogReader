"""主視窗：載入多檔/資料夾、非阻塞查詢、快取管理。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..cache_store import (
    clear_all_cache,
    compute_stats_key,
    load_stats_cache,
    save_stats_cache,
)
from ..config import AppConfig
from ..constants import PREFERRED_VISIBLE_FIELDS
from ..database import LogDatabase
from .rules_tab import RulesTab
from .stats_tab import StatsTab
from .table_tab import TableTab
from .workers import ExportCsvWorker, LoadLogsWorker, StatsWorker


class MainWindow(QMainWindow):
    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self.config = config or AppConfig()
        self.db: LogDatabase | None = None
        self.available_fields: list[str] = []
        self._cache_fingerprint: str = ""
        self._stats_loaded_key: str = ""
        self._worker: LoadLogsWorker | None = None
        self._stats_worker: StatsWorker | None = None
        self._csv_worker: ExportCsvWorker | None = None
        self._build_ui()
        self._restore_geometry()

    def _build_ui(self) -> None:
        self.setWindowTitle("IIS Log 分析工具")
        self.resize(1280, 800)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # 工具列
        toolbar = QHBoxLayout()
        title = QLabel("IIS Log 分析工具")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        toolbar.addWidget(title)
        toolbar.addStretch()

        self.btn_files = QPushButton("載入 LOG 檔案…")
        self.btn_folder = QPushButton("載入資料夾…")
        self.btn_clear_cache = QPushButton("清除快取並重新載入")
        self.btn_files.clicked.connect(self.load_files)
        self.btn_folder.clicked.connect(self.load_folder)
        self.btn_clear_cache.clicked.connect(self._clear_cache_reload)
        self.btn_clear_cache.setEnabled(False)
        toolbar.addWidget(self.btn_files)
        toolbar.addWidget(self.btn_folder)
        toolbar.addWidget(self.btn_clear_cache)

        self.file_label = QLabel("尚未載入檔案")
        self.file_label.setStyleSheet("color: #475569;")
        toolbar.addWidget(self.file_label)
        root.addLayout(toolbar)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        root.addWidget(self.progress)

        self.status_msg = QLabel("")
        root.addWidget(self.status_msg)

        self.tabs = QTabWidget()
        self.table_tab = TableTab(page_size=self.config.page_size)
        self.rules_tab = RulesTab(self.config.filter_rules)
        self.stats_tab = StatsTab()
        self.stats_tab.set_thresholds(self.config.thresholds)
        self.tabs.addTab(self.table_tab, "資料表格")
        self.tabs.addTab(self.rules_tab, "過濾規則")
        self.tabs.addTab(self.stats_tab, "統計與異常分析")
        root.addWidget(self.tabs, stretch=1)

        self.setStatusBar(QStatusBar())

        # 訊號
        self.table_tab.filter_changed.connect(self.refresh_table)
        self.table_tab.sort_changed.connect(self._on_sort)
        self.table_tab.visible_fields_changed.connect(self._on_visible_fields)
        self.rules_tab.rules_changed.connect(self._on_rules_changed)
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.stats_tab.export_requested.connect(self._on_export_stats)
        self.stats_tab.thresholds_changed.connect(self._on_thresholds_changed)
        self.stats_tab.recompute_requested.connect(
            lambda: self.refresh_stats(force=True)
        )
        self.table_tab.export_csv_requested.connect(self._on_export_csv)

    def _restore_geometry(self) -> None:
        geo = self.config.window_geometry
        if geo:
            try:
                from PySide6.QtCore import QByteArray
                self.restoreGeometry(QByteArray.fromHex(geo.encode("ascii")))
            except Exception:
                pass

    def _save_geometry(self) -> None:
        try:
            self.config.window_geometry = bytes(self.saveGeometry().toHex()).decode("ascii")
            self.config.save()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 載入
    # ------------------------------------------------------------------
    def load_files(self) -> None:
        start = self.config.last_dir or ""
        files, _ = QFileDialog.getOpenFileNames(
            self, "選擇 IIS Log 檔案", start,
            "Log Files (*.log);;All Files (*.*)",
        )
        if files:
            self.config.last_dir = str(Path(files[0]).parent)
            self.config.save()
            self._start_load(files)

    def load_folder(self) -> None:
        start = self.config.last_dir or ""
        folder = QFileDialog.getExistingDirectory(self, "選擇 Log 資料夾", start)
        if folder:
            self.config.last_dir = folder
            self.config.save()
            self._start_load([folder])

    def _clear_cache_reload(self) -> None:
        clear_all_cache()
        self.status_msg.setText("已清除快取")
        if self._last_paths:
            self._start_load(self._last_paths, force_reload=True)

    _last_paths: list[str] = []

    def _start_load(self, paths: list[str], force_reload: bool = False) -> None:
        if self._worker and self._worker.isRunning():
            QMessageBox.information(self, "提示", "正在載入中，請稍候")
            return

        self._last_paths = list(paths)

        if self.db is not None:
            self.db.close()
            self.db = None
        self._cache_fingerprint = ""
        self._stats_loaded_key = ""
        self.stats_tab.set_stats(None)

        self.btn_files.setEnabled(False)
        self.btn_folder.setEnabled(False)
        self.btn_clear_cache.setEnabled(False)
        self.progress.show()
        self.status_msg.setText("讀取與解析中…")
        self.file_label.setText(
            "；".join(Path(p).name for p in paths[:5])
            + (f" 等 {len(paths)} 項" if len(paths) > 5 else "")
        )

        self._worker = LoadLogsWorker(
            paths, tz_name=self.config.timezone, force_reload=force_reload, parent=self
        )
        self._worker.progress.connect(self._on_load_progress)
        self._worker.finished_ok.connect(self._on_load_ok)
        self._worker.failed.connect(self._on_load_fail)
        self._worker.cache_hit.connect(
            lambda: self.status_msg.setText("使用快取（秒開）…")
        )
        self._worker.start()

    def _on_load_progress(self, name: str, cur: int, total: int) -> None:
        self.progress.setRange(0, total)
        self.progress.setValue(cur)
        self.status_msg.setText(f"解析中: {name} ({cur}/{total})")

    def _on_load_ok(
        self, db: object, total: int, sources: list, fields: list, fingerprint: str
    ) -> None:
        self.progress.hide()
        self.btn_files.setEnabled(True)
        self.btn_folder.setEnabled(True)
        self.btn_clear_cache.setEnabled(True)
        self.db = db  # type: ignore[assignment]
        self.available_fields = fields
        self._cache_fingerprint = fingerprint or ""
        self._stats_loaded_key = ""

        visible = [f for f in self.config.visible_fields if f in fields]
        if not visible:
            visible = [f for f in PREFERRED_VISIBLE_FIELDS if f in fields]
        if not visible:
            visible = fields[:8]
        self.config.visible_fields = visible
        self.config.save()

        self.table_tab.bind_db(self.db, total)
        self.table_tab.set_fields(fields, visible)
        self.table_tab.clear_filters()
        self.status_msg.setText(f"載入完成（{total:,} 筆，{len(sources)} 個檔案）")
        self.file_label.setText(
            f"{len(sources)} 個檔案: " + ", ".join(sources[:8])
            + ("…" if len(sources) > 8 else "")
        )
        self.refresh_table()
        # 統計僅依過濾規則；若已有實體快取則載入，否則等使用者開啟統計分頁再算
        if self.tabs.currentWidget() is self.stats_tab:
            self.refresh_stats(force=False)

    def _on_load_fail(self, msg: str) -> None:
        self.progress.hide()
        self.btn_files.setEnabled(True)
        self.btn_folder.setEnabled(True)
        self.btn_clear_cache.setEnabled(True)
        self.status_msg.setText(f"載入失敗: {msg}")
        QMessageBox.critical(self, "載入失敗", msg)

    # ------------------------------------------------------------------
    # 懶加載查詢（不做全表 COUNT，對齊 DB Browser）
    # ------------------------------------------------------------------
    def _query_args(self) -> dict[str, Any]:
        start_ms, end_ms = self.table_tab.get_time_range_ms()
        return {
            "filter_rules": self.config.filter_rules,
            "column_filters": dict(self.table_tab.column_filters),
            "time_start_ms": start_ms,
            "time_end_ms": end_ms,
        }

    def refresh_table(self) -> None:
        if self.db is None:
            self.table_tab.bind_db(None, 0)
            return
        args = self._query_args()
        self.table_tab.apply_query(
            args["filter_rules"],
            args["column_filters"],
            args["time_start_ms"],
            args["time_end_ms"],
        )

    # ------------------------------------------------------------------
    # 統計（僅過濾規則；結果實體快取，不隨表格條件重算）
    # ------------------------------------------------------------------
    def _current_stats_key(self) -> str:
        return compute_stats_key(self.config.filter_rules, self.config.thresholds)

    def refresh_stats(self, force: bool = False) -> None:
        if self.db is None or not self._cache_fingerprint:
            self.stats_tab.set_stats(None)
            return
        if self._stats_worker and self._stats_worker.isRunning():
            return

        stats_key = self._current_stats_key()

        # 記憶體已載入且 key 相同 → 不重算
        if (
            not force
            and self._stats_loaded_key == stats_key
            and self.stats_tab._stats is not None
        ):
            return

        # 磁碟快取命中 → 直接顯示
        if not force:
            cached = load_stats_cache(self._cache_fingerprint, stats_key)
            if cached is not None:
                self._stats_loaded_key = stats_key
                self.stats_tab.set_stats(cached, int(cached.get("total", 0)))
                self.status_msg.setText("已載入統計快取（未重算）")
                return

        self.stats_tab.show_loading("統計計算中…")
        self._stats_worker = StatsWorker(
            self.db,
            self.config.filter_rules,
            self.config.timezone,
            thresholds=self.config.thresholds,
            parent=self,
        )
        self._stats_worker.progress.connect(self.stats_tab.show_loading)
        self._stats_worker.finished_ok.connect(self._on_stats_ok)
        self._stats_worker.failed.connect(
            lambda m: self.status_msg.setText(f"統計失敗: {m}")
        )
        self._stats_worker.start()

    def _on_stats_ok(self, result: object) -> None:
        stats = result if isinstance(result, dict) else None
        if stats is None:
            self.stats_tab.set_stats(None)
            return
        stats_key = self._current_stats_key()
        self._stats_loaded_key = stats_key
        if self._cache_fingerprint:
            try:
                save_stats_cache(
                    self._cache_fingerprint,
                    stats_key,
                    stats,
                    self.config.filter_rules,
                    self.config.thresholds,
                )
            except OSError as exc:
                self.status_msg.setText(f"統計已完成，但快取寫入失敗: {exc}")
        total = int(stats.get("total", 0))
        self.stats_tab.set_stats(stats, total)
        self.status_msg.setText("統計完成（已儲存快取）")

    # ------------------------------------------------------------------
    # 訊號處理
    # ------------------------------------------------------------------
    def _on_sort(self, key: str, direction: str) -> None:
        self.table_tab.sort_key = key
        self.table_tab.sort_dir = direction
        self.refresh_table()

    def _on_visible_fields(self, fields: list) -> None:
        self.config.visible_fields = list(fields)
        self.config.save()
        self.refresh_table()

    def _on_rules_changed(self, rules: list) -> None:
        self.config.filter_rules = [dict(r) for r in rules]
        self.config.save()
        self._stats_loaded_key = ""  # 規則變更 → 統計需重算
        self.refresh_table()
        if self.tabs.currentWidget() is self.stats_tab:
            self.refresh_stats(force=True)

    def _on_tab_changed(self, index: int) -> None:
        if self.tabs.widget(index) is self.stats_tab:
            # 有快取則載入；已顯示則跳過；無快取才計算
            self.refresh_stats(force=False)

    def _on_thresholds_changed(self, thresholds: dict) -> None:
        self.config.thresholds = dict(thresholds)
        self.config.save()
        self._stats_loaded_key = ""
        self.refresh_stats(force=True)

    def _on_export_stats(self) -> None:
        if not self.stats_tab._stats:
            QMessageBox.information(self, "提示", "尚無統計結果可匯出")
            return
        from ..report import export_report

        meta = {
            "source_files": self.db.source_files if self.db else [],
            "filter_summary": f"{len(self.config.filter_rules)} 條規則",
        }
        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "匯出統計報告",
            "iis_log_report.pdf",
            "PDF (*.pdf);;HTML (*.html);;Markdown (*.md);;All Files (*.*)",
        )
        if not path:
            return
        # 依選擇的 filter 補副檔名
        lower = path.lower()
        if selected_filter.startswith("PDF") and not lower.endswith(".pdf"):
            path += ".pdf"
        elif selected_filter.startswith("HTML") and not (
            lower.endswith(".html") or lower.endswith(".htm")
        ):
            path += ".html"
        elif selected_filter.startswith("Markdown") and not lower.endswith(".md"):
            path += ".md"
        try:
            out = export_report(
                self.stats_tab._stats,
                path,
                meta=meta,
                thresholds=self.config.thresholds,
            )
            msg = f"已匯出: {out}"
            if out.suffix.lower() == ".pdf":
                html_side = out.with_suffix(".html")
                if html_side.exists():
                    msg += f"（並保留 HTML：{html_side.name}）"
            self.status_msg.setText(msg)
        except Exception as exc:
            QMessageBox.critical(self, "匯出失敗", str(exc))

    def _on_export_csv(self) -> None:
        if self.db is None:
            QMessageBox.information(self, "提示", "請先載入 LOG 檔案")
            return
        if self._csv_worker and self._csv_worker.isRunning():
            QMessageBox.information(self, "提示", "正在匯出 CSV，請稍候")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "匯出資料表格 CSV",
            "iis_log_export.csv",
            "CSV (*.csv);;All Files (*.*)",
        )
        if not path:
            return
        if not path.lower().endswith(".csv"):
            path += ".csv"

        reply = QMessageBox.question(
            self,
            "確認匯出",
            "將依目前「過濾規則 + 欄位篩選 + 時間條件」與可見欄位匯出全部符合的列。\n"
            "資料量大時可能需數分鐘，是否繼續？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        args = self._query_args()
        fields = list(self.table_tab.visible_fields)
        self.progress.show()
        self.progress.setRange(0, 0)
        self.status_msg.setText("正在匯出 CSV…")
        self.table_tab.btn_export_csv.setEnabled(False)

        self._csv_worker = ExportCsvWorker(
            self.db,
            path,
            fields,
            filter_rules=args["filter_rules"],
            column_filters=args["column_filters"],
            time_start_ms=args["time_start_ms"],
            time_end_ms=args["time_end_ms"],
            sort_key=self.table_tab.sort_key,
            sort_dir=self.table_tab.sort_dir,
            parent=self,
        )
        self._csv_worker.progress.connect(self._on_csv_progress)
        self._csv_worker.finished_ok.connect(self._on_csv_ok)
        self._csv_worker.failed.connect(self._on_csv_fail)
        self._csv_worker.start()

    def _on_csv_progress(self, written: int) -> None:
        self.status_msg.setText(f"正在匯出 CSV… 已寫入 {written:,} 列")

    def _on_csv_ok(self, path: str, count: int) -> None:
        self.progress.hide()
        self.table_tab.btn_export_csv.setEnabled(True)
        self.status_msg.setText(f"CSV 已匯出 {count:,} 列：{path}")
        QMessageBox.information(
            self, "匯出完成", f"已寫入 {count:,} 列\n{path}"
        )

    def _on_csv_fail(self, msg: str) -> None:
        self.progress.hide()
        self.table_tab.btn_export_csv.setEnabled(True)
        self.status_msg.setText(f"CSV 匯出失敗: {msg}")
        if msg != "已取消匯出":
            QMessageBox.critical(self, "匯出失敗", msg)

    def closeEvent(self, event: QCloseEvent) -> None:
        self._save_geometry()
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(3000)
        if self._csv_worker and self._csv_worker.isRunning():
            self._csv_worker.cancel()
            self._csv_worker.wait(3000)
        if self.db is not None:
            self.db.close()
            self.db = None
        super().closeEvent(event)
