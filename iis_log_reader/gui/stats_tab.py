"""統計與異常偵測分頁（含閾值設定與匯出）。"""

from __future__ import annotations

from collections import Counter
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QHeaderView,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..config import DEFAULT_THRESHOLDS
from .copy_utils import enable_table_copy, make_selectable_label


class StatsTab(QWidget):
    export_requested = Signal()
    thresholds_changed = Signal(dict)
    recompute_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._stats: dict[str, Any] | None = None
        self._copy_shortcuts: list = []
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        self.empty_label = QLabel(
            "無資料可分析，請先載入 LOG 檔案\n"
            "（統計僅套用「過濾規則」，不受資料表格篩選影響；結果會快取）"
        )
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setStyleSheet("color: #94a3b8; font-size: 16px;")
        root.addWidget(self.empty_label)

        # 閾值設定 + 匯出工具列
        self.toolbar = QHBoxLayout()
        self.btn_thresholds = QPushButton("閾值設定")
        self.btn_thresholds.clicked.connect(self._open_thresholds)
        self.btn_export = QPushButton("匯出報告…")
        self.btn_export.clicked.connect(lambda: self.export_requested.emit())
        self.btn_recompute = QPushButton("重新計算")
        self.btn_recompute.setToolTip("忽略快取，依目前過濾規則重新統計")
        self.btn_recompute.clicked.connect(lambda: self.recompute_requested.emit())
        self.toolbar.addWidget(self.btn_thresholds)
        self.toolbar.addWidget(self.btn_export)
        self.toolbar.addWidget(self.btn_recompute)
        self.toolbar.addStretch()
        hint = QLabel("僅依過濾規則統計（不含表格欄位/時間篩選）")
        hint.setStyleSheet("color: #64748b;")
        self.toolbar.addWidget(hint)
        self.toolbar_widget = QWidget()
        self.toolbar_widget.setLayout(self.toolbar)
        self.toolbar_widget.hide()
        root.addWidget(self.toolbar_widget)

        self.tabs = QTabWidget()
        self.tabs.hide()
        root.addWidget(self.tabs)

        self.ip_tab = QWidget()
        self.url_tab = QWidget()
        self.time_tab = QWidget()
        self.status_tab = QWidget()
        self.anomaly_tab = QWidget()

        self.tabs.addTab(self.ip_tab, "IP 排行")
        self.tabs.addTab(self.url_tab, "URL 排行")
        self.tabs.addTab(self.time_tab, "時段分布")
        self.tabs.addTab(self.status_tab, "狀態碼")
        self.tabs.addTab(self.anomaly_tab, "異常偵測")

        self._init_ip()
        self._init_url()
        self._init_time()
        self._init_status()
        self._init_anomaly()

    def _open_thresholds(self) -> None:
        from PySide6.QtWidgets import QDialog, QDialogButtonBox
        dlg = QDialog(self)
        dlg.setWindowTitle("異常閾值設定")
        layout = QVBoxLayout(dlg)
        form = QFormLayout()
        edits: dict[str, QLineEdit] = {}
        labels_map = {
            "high_freq_std_mult": "高頻 IP 標準差倍數",
            "burst_count": "爆量請求次數",
            "burst_window_ms": "爆量偵測視窗 (ms)",
            "slow_ms": "慢請求門檻 (ms)",
            "off_hour_start": "離峰起始 (時)",
            "off_hour_end": "離峰結束 (時)",
            "error_status_min": "錯誤狀態碼下限",
            "page_scrape_count": "同頁面抓取次數門檻",
            "page_scrape_min_span_min": "同頁面抓取最小持續 (分)",
            "scanner_ua_keywords": "可疑 UA 關鍵字 (逗號分隔)",
        }
        current = dict(DEFAULT_THRESHOLDS)
        if self._thresholds:
            current.update(self._thresholds)
        for key, label in labels_map.items():
            edit = QLineEdit(str(current.get(key, "")))
            edits[key] = edit
            form.addRow(label, edit)
        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            new_th: dict[str, Any] = {}
            for key, edit in edits.items():
                raw = edit.text().strip()
                default = DEFAULT_THRESHOLDS.get(key)
                if isinstance(default, float):
                    try:
                        new_th[key] = float(raw)
                    except ValueError:
                        new_th[key] = default
                elif isinstance(default, int):
                    try:
                        new_th[key] = int(raw)
                    except ValueError:
                        new_th[key] = default
                else:
                    new_th[key] = raw
            self._thresholds = new_th
            self.thresholds_changed.emit(new_th)

    _thresholds: dict[str, Any] = {}

    def set_thresholds(self, th: dict[str, Any]) -> None:
        self._thresholds = dict(th)

    def _wire_table_copy(self, table: QTableWidget) -> None:
        self._copy_shortcuts.append(enable_table_copy(table))

    def _init_ip(self) -> None:
        layout = QHBoxLayout(self.ip_tab)
        self.ip_table = QTableWidget(0, 2)
        self.ip_table.setHorizontalHeaderLabels(["來源 IP", "請求數"])
        self.ip_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ip_table.horizontalHeader().setStretchLastSection(True)
        self.ip_table.verticalHeader().setVisible(False)
        self._wire_table_copy(self.ip_table)
        layout.addWidget(self.ip_table, 1)
        right = QVBoxLayout()
        right.addWidget(QLabel("IP 存取排行（表格可多選 Ctrl+C）"))
        self.ip_bars = QVBoxLayout()
        wrap = QWidget()
        wrap.setLayout(self.ip_bars)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(wrap)
        right.addWidget(scroll, 1)
        layout.addLayout(right, 1)

    def _init_url(self) -> None:
        layout = QVBoxLayout(self.url_tab)
        hint = QLabel("可多選儲存格後 Ctrl+C 複製")
        hint.setStyleSheet("color: #64748b;")
        layout.addWidget(hint)
        self.url_table = QTableWidget(0, 2)
        self.url_table.setHorizontalHeaderLabels(["URI 路徑", "請求數"])
        self.url_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.url_table.horizontalHeader().setStretchLastSection(True)
        self.url_table.verticalHeader().setVisible(False)
        self._wire_table_copy(self.url_table)
        layout.addWidget(self.url_table)

    def _init_time(self) -> None:
        layout = QVBoxLayout(self.time_tab)
        layout.addWidget(QLabel("每小時請求分布（台北時間）"))
        hint = QLabel("紅色表示離峰時段 (00:00 ~ 07:00)；數字可選取複製")
        hint.setStyleSheet("color: #64748b;")
        layout.addWidget(hint)
        self.hour_bars = QHBoxLayout()
        wrap = QWidget()
        wrap.setLayout(self.hour_bars)
        wrap.setMinimumHeight(280)
        layout.addWidget(wrap)
        self.hour_summary = make_selectable_label("")
        self.hour_summary.setStyleSheet("color: #334155; padding: 6px 0;")
        layout.addWidget(self.hour_summary)
        layout.addStretch()

    def _init_status(self) -> None:
        layout = QHBoxLayout(self.status_tab)
        self.status_table = QTableWidget(0, 2)
        self.status_table.setHorizontalHeaderLabels(["HTTP 狀態碼", "次數"])
        self.status_table.horizontalHeader().setStretchLastSection(True)
        self.status_table.verticalHeader().setVisible(False)
        self._wire_table_copy(self.status_table)
        layout.addWidget(self.status_table, 1)
        right = QVBoxLayout()
        right.addWidget(QLabel("狀態碼分布比例（文字可選取）"))
        self.status_bars = QVBoxLayout()
        wrap = QWidget()
        wrap.setLayout(self.status_bars)
        right.addWidget(wrap)
        right.addStretch()
        layout.addLayout(right, 1)

    def _init_anomaly(self) -> None:
        outer = QVBoxLayout(self.anomaly_tab)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.anomaly_host = QWidget()
        self.anomaly_layout = QVBoxLayout(self.anomaly_host)
        scroll.setWidget(self.anomaly_host)
        outer.addWidget(scroll)

    def show_loading(self, message: str = "統計計算中…") -> None:
        self.empty_label.setText(message)
        self.empty_label.show()
        self.tabs.hide()
        self.toolbar_widget.hide()

    def set_stats(self, stats: dict[str, Any] | None, total_filtered: int = 0) -> None:
        self._stats = stats
        if not stats:
            self.empty_label.setText("無資料可分析，請先載入 LOG 檔案")
            self.empty_label.show()
            self.tabs.hide()
            self.toolbar_widget.hide()
            return

        self.empty_label.hide()
        self.tabs.show()
        self.toolbar_widget.show()
        self._fill_ip(stats)
        self._fill_url(stats)
        self._fill_time(stats)
        self._fill_status(stats, total_filtered or stats.get("total", 1))
        self._fill_anomaly(stats)

    def _clear_layout(self, layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
            child = item.layout()
            if child:
                self._clear_layout(child)

    def _fill_ip(self, stats: dict) -> None:
        items = stats.get("topIPs", [])
        self.ip_table.setRowCount(len(items))
        for i, row in enumerate(items):
            self.ip_table.setItem(i, 0, QTableWidgetItem(str(row["ip"])))
            cnt = QTableWidgetItem(f"{row['count']:,}")
            cnt.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.ip_table.setItem(i, 1, cnt)
        self._clear_layout(self.ip_bars)
        max_c = items[0]["count"] if items else 1
        for row in items:
            line = QHBoxLayout()
            lab = make_selectable_label(str(row["ip"]))
            lab.setFixedWidth(120)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(int(row["count"] / max(max_c, 1) * 100))
            bar.setFormat(f"{row['count']:,}")
            line.addWidget(lab)
            line.addWidget(bar)
            wrap = QWidget()
            wrap.setLayout(line)
            self.ip_bars.addWidget(wrap)
        self.ip_bars.addStretch()

    def _fill_url(self, stats: dict) -> None:
        items = stats.get("topURLs", [])
        self.url_table.setRowCount(len(items))
        for i, row in enumerate(items):
            self.url_table.setItem(i, 0, QTableWidgetItem(str(row["url"])))
            cnt = QTableWidgetItem(f"{row['count']:,}")
            cnt.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.url_table.setItem(i, 1, cnt)

    def _fill_time(self, stats: dict) -> None:
        hours = stats.get("hourCountMap", [0] * 24)
        self._clear_layout(self.hour_bars)
        max_c = max(hours) if hours else 1
        max_c = max(max_c, 1)
        summary_parts: list[str] = []
        for h, count in enumerate(hours):
            col = QVBoxLayout()
            bar = QProgressBar()
            bar.setOrientation(Qt.Orientation.Vertical)
            bar.setRange(0, 100)
            bar.setValue(int(count / max_c * 100))
            bar.setTextVisible(False)
            bar.setMinimumHeight(200)
            if h < 7:
                bar.setStyleSheet(
                    "QProgressBar::chunk { background-color: #f87171; }"
                    "QProgressBar { background: #e2e8f0; border: none; }"
                )
            else:
                bar.setStyleSheet(
                    "QProgressBar::chunk { background-color: #3b82f6; }"
                    "QProgressBar { background: #e2e8f0; border: none; }"
                )
            bar.setToolTip(f"{h:02d}:00 — {count:,} 筆")
            lab = make_selectable_label(f"{h:02d}")
            lab.setAlignment(Qt.AlignmentFlag.AlignCenter)
            col.addWidget(bar, alignment=Qt.AlignmentFlag.AlignBottom)
            col.addWidget(lab)
            wrap = QWidget()
            wrap.setLayout(col)
            self.hour_bars.addWidget(wrap)
            summary_parts.append(f"{h:02d}:00={count:,}")
        self.hour_summary.setText("每小時筆數：" + " ｜ ".join(summary_parts))

    def _fill_status(self, stats: dict, total: int) -> None:
        items = stats.get("statusList", [])
        self.status_table.setRowCount(len(items))
        for i, row in enumerate(items):
            st = int(row["status"])
            item = QTableWidgetItem(str(st))
            if st >= 500:
                item.setBackground(QBrush(QColor("#fecaca")))
            elif st >= 400:
                item.setBackground(QBrush(QColor("#ffedd5")))
            elif st >= 300:
                item.setBackground(QBrush(QColor("#fef9c3")))
            else:
                item.setBackground(QBrush(QColor("#dcfce7")))
            self.status_table.setItem(i, 0, item)
            cnt = QTableWidgetItem(f"{row['count']:,}")
            cnt.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.status_table.setItem(i, 1, cnt)
        self._clear_layout(self.status_bars)
        total = max(total, 1)
        for row in items:
            st = int(row["status"])
            pct = row["count"] / total * 100
            line = QVBoxLayout()
            head = QHBoxLayout()
            head.addWidget(make_selectable_label(f"Status {st}"))
            head.addStretch()
            head.addWidget(make_selectable_label(f"{pct:.1f}% ({row['count']:,})"))
            bar = QProgressBar()
            bar.setRange(0, 1000)
            bar.setValue(int(pct * 10))
            bar.setFormat("")
            color = "#ef4444" if st >= 500 else "#f97316" if st >= 400 else "#eab308" if st >= 300 else "#22c55e"
            bar.setStyleSheet(
                f"QProgressBar::chunk {{ background-color: {color}; }}"
                "QProgressBar { background: #e2e8f0; border: none; height: 12px; }"
            )
            hw = QWidget()
            hw.setLayout(head)
            line.addWidget(hw)
            line.addWidget(bar)
            wrap = QWidget()
            wrap.setLayout(line)
            self.status_bars.addWidget(wrap)

    def _anomaly_card(self, title: str, count: int, body: QWidget, kind: str) -> QFrame:
        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        colors = {
            "safe": ("#e2e8f0", "#f8fafc", "#334155"),
            "warning": ("#fed7aa", "#fff7ed", "#9a3412"),
            "danger": ("#fecaca", "#fef2f2", "#991b1b"),
        }
        border, bg, fg = colors.get(kind, colors["safe"])
        frame.setStyleSheet(
            f"QFrame {{ border: 1px solid {border}; border-radius: 8px; background: white; }}"
        )
        layout = QVBoxLayout(frame)
        header = QHBoxLayout()
        lab = make_selectable_label(title)
        lab.setStyleSheet(f"font-weight: bold; color: {fg}; background: {bg}; padding: 4px;")
        header.addWidget(lab)
        header.addStretch()
        if count > 0:
            badge = make_selectable_label(f"{count} 筆")
            badge.setStyleSheet(
                f"background: {border}; color: {fg}; padding: 2px 8px; border-radius: 8px;"
            )
            header.addWidget(badge)
        layout.addLayout(header)
        layout.addWidget(body)
        return frame

    def _fill_anomaly(self, stats: dict) -> None:
        self._clear_layout(self.anomaly_layout)
        a = stats.get("anomalies", {})

        # 高頻 IP
        high = a.get("highFreqIPs", [])
        if high:
            lines = [
                f"{item['ip']}  請求數: {item['count']} (閾值: {item['threshold']})"
                for item in high
            ]
            body = make_selectable_label("\n".join(lines), word_wrap=True)
        else:
            body = make_selectable_label("未偵測到異常高頻 IP")
        self.anomaly_layout.addWidget(
            self._anomaly_card(
                "高頻存取 IP (超過 mean + k×std)",
                len(high),
                body,
                "warning" if high else "safe",
            )
        )

        # 爆量
        bursts = a.get("bursts", [])
        if bursts:
            lines = [
                f"{b['ip']}  區間: {b['startStr']} ~ {b['endStr']}  {b['count']}次 / {b['windowSec']}秒"
                for b in bursts
            ]
            body = make_selectable_label("\n".join(lines), word_wrap=True)
        else:
            body = make_selectable_label("未偵測到短時間爆量請求")
        self.anomaly_layout.addWidget(
            self._anomaly_card(
                "爆量請求 (同 IP 短時間高頻)",
                len(bursts),
                body,
                "danger" if bursts else "safe",
            )
        )

        # 同頁面大量抓取
        scrapes = a.get("pageScrapes", [])
        scrape_count = a.get("pageScrapesCount", len(scrapes))
        if scrapes:
            lines = []
            for s in scrapes[:15]:
                q_desc = ""
                if s.get("queries"):
                    q_desc = "  參數: " + ", ".join(
                        f"{q['query']}({q['count']})" for q in s["queries"]
                    )
                    if s.get("queryCount", 0) > len(s["queries"]):
                        q_desc += f" …共{s['queryCount']}種"
                lines.append(
                    f"{s['ip']}  {s['url']}  {s['count']:,}次  "
                    f"{s['startStr']} ~ {s['endStr']}{q_desc}"
                )
            if scrape_count > 15:
                lines.append(f"僅顯示前 15 組，共 {scrape_count} 組…")
            body = make_selectable_label("\n".join(lines), word_wrap=True)
        else:
            body = make_selectable_label("未偵測到同 IP 持續大量抓取同頁面")
        self.anomaly_layout.addWidget(
            self._anomaly_card(
                "同頁面大量抓取 (同 IP 持續請求同頁面)",
                scrape_count,
                body,
                "danger" if scrapes else "safe",
            )
        )

        # 可疑 UA（優先使用 SQL 聚合的 count 欄位）
        sus = a.get("susUA", [])
        sus_count = a.get("susUACount", len(sus))
        if sus:
            if any("count" in x for x in sus):
                ranked = sorted(
                    (
                        (x.get("cs(User-Agent)", ""), int(x.get("count", 1)))
                        for x in sus
                        if "count" in x
                    ),
                    key=lambda t: -t[1],
                )[:10]
            else:
                ranked = Counter(
                    x.get("cs(User-Agent)", "") for x in sus
                ).most_common(10)
            lines = [f"[{cnt}次] {ua}" for ua, cnt in ranked]
            if len(ranked) >= 10:
                lines.append("僅顯示前 10 種…")
            body = make_selectable_label("\n".join(lines), word_wrap=True)
        else:
            body = make_selectable_label("未偵測到可疑掃描特徵")
        self.anomaly_layout.addWidget(
            self._anomaly_card(
                "可疑 User-Agent (掃描工具特徵)",
                sus_count,
                body,
                "danger" if sus else "safe",
            )
        )

        # 慢請求
        slow = a.get("slowReqs", [])
        slow_count = a.get("slowReqsCount", len(slow))
        if slow:
            sorted_slow = sorted(
                slow, key=lambda x: x.get("time-taken", 0), reverse=True
            )[:15]
            lines = [
                f"{s.get('datetimeStr','')}  {s.get('c-ip','')}  "
                f"{s.get('cs-uri-stem','')}  {s.get('time-taken')}ms"
                for s in sorted_slow
            ]
            body = make_selectable_label("\n".join(lines), word_wrap=True)
        else:
            body = make_selectable_label("無超過閾值的慢請求")
        self.anomaly_layout.addWidget(
            self._anomaly_card(
                "慢請求 (time-taken > 閾值)",
                slow_count,
                body,
                "warning" if slow else "safe",
            )
        )

        # 錯誤狀態
        errs = a.get("errorStatus", [])
        err_count = a.get("errorStatusCount", len(errs))
        if errs:
            by_st = Counter(e.get("sc-status") for e in errs)
            by_ip = Counter(e.get("c-ip") for e in errs)
            lines = ["錯誤代碼分布:"]
            for st, c in by_st.most_common():
                lines.append(f"  {st}: {c} 筆")
            lines.append("錯誤來源 IP Top 5:")
            for ip, c in by_ip.most_common(5):
                lines.append(f"  {ip}: {c} 次")
            body = make_selectable_label("\n".join(lines), word_wrap=True)
        else:
            body = make_selectable_label("無 4xx 或 5xx 錯誤記錄")
        self.anomaly_layout.addWidget(
            self._anomaly_card(
                "錯誤狀態碼 (4xx / 5xx)",
                err_count,
                body,
                "danger" if errs else "safe",
            )
        )
        self.anomaly_layout.addStretch()
