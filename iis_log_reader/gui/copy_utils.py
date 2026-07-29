"""表格／文字選取複製共用工具。"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import QAbstractItemView, QLabel, QTableView, QTableWidget


def make_selectable_label(text: str = "", *, word_wrap: bool = False) -> QLabel:
    """可滑鼠／鍵盤選取並 Ctrl+C 的 QLabel。"""
    lab = QLabel(text)
    lab.setTextInteractionFlags(
        Qt.TextInteractionFlag.TextSelectableByMouse
        | Qt.TextInteractionFlag.TextSelectableByKeyboard
    )
    if word_wrap:
        lab.setWordWrap(True)
    return lab


def enable_table_copy(view: QAbstractItemView) -> QShortcut:
    """
    為 QTableView / QTableWidget 啟用多選複製（Ctrl+C）。
    回傳 Shortcut，呼叫端可保留參考避免被 GC。
    """
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    if isinstance(view, QTableWidget):
        view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
    shortcut = QShortcut(QKeySequence.StandardKey.Copy, view)
    shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
    shortcut.activated.connect(lambda: copy_view_selection(view))
    return shortcut


def copy_view_selection(view: QAbstractItemView, *, include_headers: bool = False) -> bool:
    """
    將目前選取內容以 TSV 寫入剪貼簿。
    回傳是否有寫入內容。
    """
    model = view.model()
    if model is None:
        return False

    indexes = view.selectionModel().selectedIndexes() if view.selectionModel() else []
    if not indexes:
        return False

    # 依列、欄排序，組成矩形文字
    indexes = sorted(indexes, key=lambda i: (i.row(), i.column()))
    rows: dict[int, dict[int, str]] = {}
    cols_used: set[int] = set()
    for idx in indexes:
        text = model.data(idx, Qt.ItemDataRole.DisplayRole)
        rows.setdefault(idx.row(), {})[idx.column()] = "" if text is None else str(text)
        cols_used.add(idx.column())

    col_list = sorted(cols_used)
    lines: list[str] = []
    if include_headers:
        headers = []
        for c in col_list:
            h = model.headerData(c, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)
            headers.append("" if h is None else str(h).replace(" ▲", "").replace(" ▼", ""))
        lines.append("\t".join(headers))

    for r in sorted(rows):
        lines.append("\t".join(rows[r].get(c, "") for c in col_list))

    text = "\n".join(lines)
    if not text:
        return False
    QGuiApplication.clipboard().setText(text)
    return True


def copy_table_view_rows(view: QTableView, *, include_headers: bool = True) -> bool:
    """依「整列選取」複製可見欄位（主資料表用）。"""
    model = view.model()
    if model is None or view.selectionModel() is None:
        return False
    row_indexes = view.selectionModel().selectedRows()
    if not row_indexes:
        # 若只選了 cell，退回一般選取複製
        return copy_view_selection(view, include_headers=include_headers)

    col_count = model.columnCount()
    lines: list[str] = []
    if include_headers:
        headers = []
        for c in range(col_count):
            h = model.headerData(c, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)
            headers.append("" if h is None else str(h).replace(" ▲", "").replace(" ▼", ""))
        lines.append("\t".join(headers))

    for ri in sorted(row_indexes, key=lambda i: i.row()):
        vals = []
        r = ri.row()
        for c in range(col_count):
            idx = model.index(r, c)
            text = model.data(idx, Qt.ItemDataRole.DisplayRole)
            vals.append("" if text is None else str(text))
        lines.append("\t".join(vals))

    QGuiApplication.clipboard().setText("\n".join(lines))
    return True
