"""懶加載表格模型：不 COUNT，捲動時再抓下一批（對齊 DB Browser）。"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QBrush, QColor

from ..constants import FIELD_DEFS
from ..database import LogDatabase

BATCH_SIZE = 500


class LazyLogModel(QAbstractTableModel):
    """
    只在需要時 SELECT … LIMIT N OFFSET …。
    篩選後立刻顯示第一批；不跑全表 COUNT（那是慢的主因）。
    """

    status_changed = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._db: LogDatabase | None = None
        self._rows: list[dict[str, Any]] = []
        self._fields: list[str] = []
        self._filter_rules: list[dict[str, Any]] = []
        self._column_filters: dict[str, str] = {}
        self._time_start_ms: int | None = None
        self._time_end_ms: int | None = None
        self._sort_key = "id"
        self._sort_dir = "asc"
        self._has_more = False
        self._total_raw = 0
        self._fetching = False

    def set_db(self, db: LogDatabase | None, total_raw: int = 0) -> None:
        self.beginResetModel()
        self._db = db
        self._total_raw = total_raw
        self._rows.clear()
        self._has_more = False
        self.endResetModel()

    def set_fields(self, fields: list[str]) -> None:
        self.beginResetModel()
        self._fields = list(fields)
        self.endResetModel()

    def set_query(
        self,
        filter_rules: list[dict[str, Any]] | None = None,
        column_filters: dict[str, str] | None = None,
        time_start_ms: int | None = None,
        time_end_ms: int | None = None,
        sort_key: str = "timestamp",
        sort_dir: str = "asc",
    ) -> None:
        self._filter_rules = list(filter_rules or [])
        self._column_filters = dict(column_filters or {})
        self._time_start_ms = time_start_ms
        self._time_end_ms = time_end_ms
        self._sort_key = sort_key
        self._sort_dir = sort_dir
        self.reload()

    def reload(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self._has_more = bool(self._db)
        self.endResetModel()
        if self._db:
            self.status_changed.emit("載入中…")
            self.fetchMore()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if parent.isValid():
            return 0
        return len(self._fields)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            if 0 <= section < len(self._fields):
                f = self._fields[section]
                label = FIELD_DEFS.get(f, {}).get("label", f)
                sk = self._sort_key
                if sk == f or (sk == "timestamp" and f == "datetimeStr"):
                    label += " ▲" if self._sort_dir == "asc" else " ▼"
                return label
        return str(section + 1)

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:  # noqa: N802
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if row < 0 or row >= len(self._rows) or col < 0 or col >= len(self._fields):
            return None

        field = self._fields[col]
        val = self._rows[row].get(field, "-")
        if val is None:
            val = "-"

        if role == Qt.ItemDataRole.DisplayRole:
            return str(val)

        if role == Qt.ItemDataRole.BackgroundRole:
            return self._bg(field, val)

        if role == Qt.ItemDataRole.ForegroundRole:
            if field == "time-taken":
                try:
                    if int(val) > 5000:
                        return QBrush(QColor("#dc2626"))
                except (TypeError, ValueError):
                    pass
            if str(val) == "-":
                return QBrush(QColor("#cbd5e1"))
        return None

    def canFetchMore(self, parent: QModelIndex = QModelIndex()) -> bool:  # noqa: N802
        if parent.isValid() or self._fetching or not self._db:
            return False
        return self._has_more

    def fetchMore(self, parent: QModelIndex = QModelIndex()) -> None:  # noqa: N802
        if parent.isValid() or not self._db or self._fetching or not self._has_more:
            return
        self._fetching = True
        try:
            offset = len(self._rows)
            batch = self._db.fetch_batch(
                offset=offset,
                limit=BATCH_SIZE,
                sort_key=self._sort_key,
                sort_dir=self._sort_dir,
                filter_rules=self._filter_rules,
                column_filters=self._column_filters,
                time_start_ms=self._time_start_ms,
                time_end_ms=self._time_end_ms,
            )
            if batch:
                first = offset
                last = offset + len(batch) - 1
                self.beginInsertRows(QModelIndex(), first, last)
                self._rows.extend(batch)
                self.endInsertRows()
            # 不足一批 → 已到底
            self._has_more = len(batch) >= BATCH_SIZE
            loaded = len(self._rows)
            if self._has_more:
                self.status_changed.emit(
                    f"已載入 {loaded:,} 筆（向下捲動載入更多）"
                    f" ｜ 原始 {self._total_raw:,} 筆"
                )
            else:
                self.status_changed.emit(
                    f"共 {loaded:,} 筆（已全部載入）"
                    f" ｜ 原始 {self._total_raw:,} 筆"
                )
        finally:
            self._fetching = False

    @staticmethod
    def _bg(field: str, val: Any) -> QBrush | None:
        if field == "sc-status":
            try:
                code = int(val)
            except (TypeError, ValueError):
                return None
            if code >= 500:
                return QBrush(QColor("#fecaca"))
            if code >= 400:
                return QBrush(QColor("#ffedd5"))
            if code >= 300:
                return QBrush(QColor("#fef9c3"))
            return QBrush(QColor("#dcfce7"))
        if field == "cs-method":
            if str(val) == "GET":
                return QBrush(QColor("#d1fae5"))
            if str(val) == "POST":
                return QBrush(QColor("#dbeafe"))
        return None
