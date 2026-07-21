"""資料表格：DB Browser 風格篩選列 + 懶加載（無分頁 / 無前置 COUNT）。"""

from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QAction, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDateTimeEdit,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ..constants import FIELD_DEFS, PAGE_SIZE_DEFAULT
from ..database import LogDatabase
from .copy_utils import copy_view_selection
from .log_table_model import LazyLogModel

DEBOUNCE_MS = 300


class ColumnSettingsDialog(QDialog):
    def __init__(self, available: list[str], visible: list[str], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("欄位設定")
        self._checks: dict[str, QCheckBox] = {}
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("顯示與隱藏欄位"))
        for f in available:
            label = FIELD_DEFS.get(f, {}).get("label", f)
            cb = QCheckBox(label)
            cb.setChecked(f in visible)
            self._checks[f] = cb
            layout.addWidget(cb)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def selected_fields(self) -> list[str]:
        return [f for f, cb in self._checks.items() if cb.isChecked()]


class FilterHeaderBar(QWidget):
    """對齊各欄寬的 Row2 篩選列（隨水平捲動）。"""

    filter_text_changed = Signal(str, str)  # field, text

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setFixedHeight(30)
        self._edits: dict[str, QLineEdit] = {}
        self._fields: list[str] = []
        self._inner = QWidget(self)

    def set_fields(self, fields: list[str], values: dict[str, str] | None = None) -> None:
        values = values or {}
        for edit in self._edits.values():
            edit.deleteLater()
        self._edits.clear()
        self._fields = list(fields)
        for f in fields:
            edit = QLineEdit(self._inner)
            edit.setPlaceholderText("= > < <> LIKE")
            edit.setClearButtonEnabled(True)
            edit.setText(values.get(f, ""))
            edit.setFixedHeight(26)
            edit.textChanged.connect(self._make_handler(f))
            edit.show()
            self._edits[f] = edit

    def _make_handler(self, field: str) -> Callable[[str], None]:
        def handler(text: str) -> None:
            self.filter_text_changed.emit(field, text)
        return handler

    def sync_widths(
        self, header: QHeaderView, h_offset: int = 0, left_pad: int = 0
    ) -> None:
        x = 0
        for i, f in enumerate(self._fields):
            edit = self._edits.get(f)
            if not edit:
                continue
            w = header.sectionSize(i)
            edit.setGeometry(x, 2, max(40, w), 26)
            x += w
        self._inner.setFixedSize(max(x, 1), 30)
        self._inner.move(left_pad - h_offset, 0)

    def clear_texts(self) -> None:
        for edit in self._edits.values():
            edit.blockSignals(True)
            edit.clear()
            edit.blockSignals(False)


class TableTab(QWidget):
    """懶加載 log 資料表。"""

    filter_changed = Signal()
    sort_changed = Signal(str, str)
    visible_fields_changed = Signal(list)
    export_csv_requested = Signal()

    def __init__(self, page_size: int = PAGE_SIZE_DEFAULT, parent=None) -> None:
        super().__init__(parent)
        self.page_size = page_size  # 保留相容；實際用 model BATCH_SIZE
        self.available_fields: list[str] = []
        self.visible_fields: list[str] = []
        self.column_filters: dict[str, str] = {}
        # 預設依 id（列序）排序：與 DB Browser 相同，可瞬間 LIMIT；
        # 若預設 timestamp，大表 + 篩選會被迫對數百萬筆重排而變極慢。
        self.sort_key = "id"
        self.sort_dir = "asc"
        self.total_raw = 0
        self._model = LazyLogModel(self)
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(DEBOUNCE_MS)
        self._debounce_timer.timeout.connect(self._emit_filter)
        self._build_ui()
        self._model.status_changed.connect(self.status_label.setText)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("全局時間過濾:"))
        self.start_dt = QDateTimeEdit()
        self.start_dt.setCalendarPopup(True)
        self.start_dt.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.start_dt.setSpecialValueText("（未設定）")
        self.start_dt.setDateTime(self.start_dt.minimumDateTime())
        self.end_dt = QDateTimeEdit()
        self.end_dt.setCalendarPopup(True)
        self.end_dt.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.end_dt.setSpecialValueText("（未設定）")
        self.end_dt.setDateTime(self.end_dt.minimumDateTime())

        self.chk_start = QCheckBox("起始")
        self.chk_end = QCheckBox("結束")
        toolbar.addWidget(self.chk_start)
        toolbar.addWidget(self.start_dt)
        toolbar.addWidget(QLabel("~"))
        toolbar.addWidget(self.chk_end)
        toolbar.addWidget(self.end_dt)

        self.btn_clear = QPushButton("清除過濾條件")
        self.btn_cols = QPushButton("欄位設定")
        self.btn_export_csv = QPushButton("匯出 CSV…")
        self.btn_export_csv.setToolTip("依目前過濾規則、欄位篩選與時間條件匯出")
        self.btn_clear.clicked.connect(self.clear_filters)
        self.btn_cols.clicked.connect(self._open_col_settings)
        self.btn_export_csv.clicked.connect(lambda: self.export_csv_requested.emit())
        toolbar.addStretch()
        toolbar.addWidget(self.btn_clear)
        toolbar.addWidget(self.btn_cols)
        toolbar.addWidget(self.btn_export_csv)
        root.addLayout(toolbar)

        self.chk_start.toggled.connect(lambda _: self._schedule_filter())
        self.chk_end.toggled.connect(lambda _: self._schedule_filter())
        self.start_dt.dateTimeChanged.connect(lambda _: self._on_dt_changed())
        self.end_dt.dateTimeChanged.connect(lambda _: self._on_dt_changed())

        # Row2 篩選列
        self.filter_bar = FilterHeaderBar()
        self.filter_bar.filter_text_changed.connect(self._on_filter_text)
        root.addWidget(self.filter_bar)

        self.table = QTableView()
        self.table.setModel(self._model)
        self.table.setAlternatingRowColors(True)
        # SelectItems：可點單一欄位複製；Ctrl/Shift 仍可多選區塊
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)
        self.table.setHorizontalScrollMode(QTableView.ScrollMode.ScrollPerPixel)
        self.table.setVerticalScrollMode(QTableView.ScrollMode.ScrollPerPixel)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_context_menu)
        hh = self.table.horizontalHeader()
        hh.setSectionsClickable(True)
        hh.setStretchLastSection(True)
        hh.sectionClicked.connect(self._on_header_clicked)
        hh.sectionResized.connect(lambda *_: self._sync_filter_bar())
        self.table.horizontalScrollBar().valueChanged.connect(
            lambda *_: self._sync_filter_bar()
        )
        # Ctrl+C：只複製目前選取的儲存格（單格＝該欄位值）
        self._copy_shortcut = QShortcut(QKeySequence.StandardKey.Copy, self.table)
        self._copy_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._copy_shortcut.activated.connect(self._copy_selection)
        root.addWidget(self.table, stretch=1)

        self.status_label = QLabel("尚未載入資料（點選儲存格後 Ctrl+C 可複製該欄位）")
        root.addWidget(self.status_label)

    def _on_dt_changed(self) -> None:
        if self.chk_start.isChecked() or self.chk_end.isChecked():
            self._schedule_filter()

    def _schedule_filter(self) -> None:
        self._debounce_timer.start()

    def _emit_filter(self) -> None:
        self.filter_changed.emit()

    def _on_filter_text(self, field: str, text: str) -> None:
        if text.strip():
            self.column_filters[field] = text
        else:
            self.column_filters.pop(field, None)
        self._schedule_filter()

    def get_time_range_ms(self) -> tuple[int | None, int | None]:
        start_ms = end_ms = None
        if self.chk_start.isChecked():
            start_ms = int(self.start_dt.dateTime().toSecsSinceEpoch() * 1000)
        if self.chk_end.isChecked():
            end_ms = int(self.end_dt.dateTime().toSecsSinceEpoch() * 1000)
        return start_ms, end_ms

    def clear_filters(self) -> None:
        self.column_filters = {}
        self.filter_bar.clear_texts()
        self.chk_start.setChecked(False)
        self.chk_end.setChecked(False)
        self.filter_changed.emit()

    def bind_db(self, db: LogDatabase | None, total_raw: int = 0) -> None:
        self.total_raw = total_raw
        self._model.set_db(db, total_raw)

    def set_fields(self, available: list[str], visible: list[str]) -> None:
        self.available_fields = list(available)
        self.visible_fields = list(visible) if visible else list(available[:8])
        self._model.set_fields(self.visible_fields)
        self.filter_bar.set_fields(self.visible_fields, self.column_filters)
        for i, f in enumerate(self.visible_fields):
            w = FIELD_DEFS.get(f, {}).get("width", 120)
            self.table.setColumnWidth(i, w)
        QTimer.singleShot(0, self._sync_filter_bar)

    def apply_query(
        self,
        filter_rules: list[dict[str, Any]],
        column_filters: dict[str, str],
        time_start_ms: int | None,
        time_end_ms: int | None,
    ) -> None:
        """套用條件並立刻懶加載第一批（不做 COUNT）。"""
        self.column_filters = dict(column_filters)
        self._model.set_query(
            filter_rules=filter_rules,
            column_filters=self.column_filters,
            time_start_ms=time_start_ms,
            time_end_ms=time_end_ms,
            sort_key=self.sort_key,
            sort_dir=self.sort_dir,
        )

    def _sync_filter_bar(self) -> None:
        left = self.table.frameWidth() + self.table.verticalHeader().width()
        self.filter_bar.setFixedWidth(self.table.width())
        self.filter_bar.sync_widths(
            self.table.horizontalHeader(),
            self.table.horizontalScrollBar().value(),
            left_pad=left,
        )

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._sync_filter_bar()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        QTimer.singleShot(0, self._sync_filter_bar)

    def _on_header_clicked(self, index: int) -> None:
        if index < 0 or index >= len(self.visible_fields):
            return
        field = self.visible_fields[index]
        key = "timestamp" if field == "datetimeStr" else field
        if self.sort_key == key:
            self.sort_dir = "desc" if self.sort_dir == "asc" else "asc"
        else:
            self.sort_key = key
            self.sort_dir = "asc"
        # 點時間欄排序在超大表上可能較慢（需重排）；狀態列提示
        if key == "timestamp":
            self.status_label.setText("依時間排序中（大表可能需數秒）…")
        self.sort_changed.emit(self.sort_key, self.sort_dir)

    def _open_col_settings(self) -> None:
        if not self.available_fields:
            return
        dlg = ColumnSettingsDialog(self.available_fields, self.visible_fields, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            selected = dlg.selected_fields()
            if not selected:
                return
            ordered = [f for f in self.available_fields if f in selected]
            self.visible_fields = ordered
            self._model.set_fields(ordered)
            self.filter_bar.set_fields(ordered, self.column_filters)
            for i, f in enumerate(ordered):
                w = FIELD_DEFS.get(f, {}).get("width", 120)
                self.table.setColumnWidth(i, w)
            self.visible_fields_changed.emit(ordered)
            self.filter_changed.emit()
            QTimer.singleShot(0, self._sync_filter_bar)

    def _copy_selection(self) -> None:
        """Ctrl+C：只複製選取的儲存格（單格時即為該欄位值）。"""
        sm = self.table.selectionModel()
        if sm is None or not sm.selectedIndexes():
            return
        if copy_view_selection(self.table, include_headers=False):
            n = len(sm.selectedIndexes())
            if n == 1:
                self.status_label.setText("已複製 1 個儲存格到剪貼簿")
            else:
                self.status_label.setText(f"已複製 {n} 個儲存格到剪貼簿")

    def _copy_full_rows(self, *, include_headers: bool) -> None:
        """右鍵：依選取儲存格所在列，複製整列（不改動目前選取）。"""
        from PySide6.QtGui import QGuiApplication

        sm = self.table.selectionModel()
        model = self.table.model()
        if sm is None or model is None:
            return
        rows = sorted({idx.row() for idx in sm.selectedIndexes()})
        if not rows:
            return
        col_count = model.columnCount()
        lines: list[str] = []
        if include_headers:
            headers = []
            for c in range(col_count):
                h = model.headerData(
                    c, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole
                )
                headers.append(
                    "" if h is None else str(h).replace(" ▲", "").replace(" ▼", "")
                )
            lines.append("\t".join(headers))
        for r in rows:
            vals = []
            for c in range(col_count):
                text = model.data(
                    model.index(r, c), Qt.ItemDataRole.DisplayRole
                )
                vals.append("" if text is None else str(text))
            lines.append("\t".join(vals))
        QGuiApplication.clipboard().setText("\n".join(lines))
        self.status_label.setText(f"已複製 {len(rows)} 整列到剪貼簿")

    def _on_table_context_menu(self, pos) -> None:
        menu = QMenu(self)
        act_copy = QAction("複製選取內容\tCtrl+C", self)
        act_copy.setShortcut(QKeySequence.StandardKey.Copy)
        act_copy.triggered.connect(self._copy_selection)
        act_rows = QAction("複製所在整列（含欄名）", self)
        act_rows.triggered.connect(lambda: self._copy_full_rows(include_headers=True))
        act_rows_plain = QAction("複製所在整列（不含欄名）", self)
        act_rows_plain.triggered.connect(
            lambda: self._copy_full_rows(include_headers=False)
        )
        menu.addAction(act_copy)
        menu.addSeparator()
        menu.addAction(act_rows)
        menu.addAction(act_rows_plain)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    # 相容舊介面（main_window 可能仍呼叫）
    def show_loading(self) -> None:
        self.status_label.setText("載入中…")

    def show_rows(self, *args, **kwargs) -> None:
        pass
