"""過濾規則 CRUD 分頁。"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..constants import RULE_TYPES


class RulesTab(QWidget):
    """黑名單過濾規則：啟用、新增、刪除。"""

    rules_changed = Signal(list)

    def __init__(self, rules: list[dict[str, Any]], parent=None) -> None:
        super().__init__(parent)
        self.rules: list[dict[str, Any]] = [dict(r) for r in rules]
        self._build_ui()
        self.refresh_list()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        title = QLabel("設定黑名單（預先排除規則）")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        root.addWidget(title)

        hint = QLabel(
            "此處規則為第一順位生效，符合條件的記錄將直接被排除，"
            "不會出現在表格與統計中。"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #64748b; margin-bottom: 8px;")
        root.addWidget(hint)

        self.list_widget = QListWidget()
        root.addWidget(self.list_widget, stretch=1)

        btn_row = QHBoxLayout()
        self.btn_toggle = QPushButton("啟用 / 停用")
        self.btn_delete = QPushButton("刪除規則")
        self.btn_toggle.clicked.connect(self._toggle_selected)
        self.btn_delete.clicked.connect(self._delete_selected)
        btn_row.addWidget(self.btn_toggle)
        btn_row.addWidget(self.btn_delete)
        btn_row.addStretch()
        root.addLayout(btn_row)

        form_box = QWidget()
        form = QFormLayout(form_box)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("例如: 排除靜態檔案")
        self.type_combo = QComboBox()
        for value, label in RULE_TYPES:
            self.type_combo.addItem(label, value)
        self.value_edit = QLineEdit()
        self.value_edit.setPlaceholderText("輸入關鍵字或以逗號分隔")
        form.addRow("規則名稱", self.name_edit)
        form.addRow("比對類型", self.type_combo)
        form.addRow("比對值", self.value_edit)
        root.addWidget(form_box)

        self.btn_add = QPushButton("新增規則")
        self.btn_add.clicked.connect(self._add_rule)
        root.addWidget(self.btn_add)

    def set_rules(self, rules: list[dict[str, Any]]) -> None:
        self.rules = [dict(r) for r in rules]
        self.refresh_list()

    def refresh_list(self) -> None:
        self.list_widget.clear()
        for rule in self.rules:
            enabled = "✓" if rule.get("enabled", True) else "○"
            text = (
                f"{enabled}  {rule.get('name', '')}  "
                f"[{rule.get('type', '')}]  {rule.get('value', '')}"
            )
            item = QListWidgetItem(text)
            item.setData(256, rule.get("id"))  # Qt.UserRole
            if not rule.get("enabled", True):
                item.setForeground(item.foreground())
            self.list_widget.addItem(item)

    def _selected_rule_id(self) -> int | None:
        item = self.list_widget.currentItem()
        if not item:
            return None
        return item.data(256)

    def _toggle_selected(self) -> None:
        rid = self._selected_rule_id()
        if rid is None:
            return
        for r in self.rules:
            if r.get("id") == rid:
                r["enabled"] = not r.get("enabled", True)
                break
        self.refresh_list()
        self.rules_changed.emit(self.rules)

    def _delete_selected(self) -> None:
        rid = self._selected_rule_id()
        if rid is None:
            return
        self.rules = [r for r in self.rules if r.get("id") != rid]
        self.refresh_list()
        self.rules_changed.emit(self.rules)

    def _add_rule(self) -> None:
        name = self.name_edit.text().strip()
        value = self.value_edit.text().strip()
        if not name or not value:
            QMessageBox.warning(self, "提示", "請填寫規則名稱與比對值")
            return
        next_id = 1
        if self.rules:
            next_id = max(int(r.get("id", 0)) for r in self.rules) + 1
        self.rules.append(
            {
                "id": next_id,
                "name": name,
                "type": self.type_combo.currentData(),
                "value": value,
                "enabled": True,
            }
        )
        self.name_edit.clear()
        self.value_edit.clear()
        self.refresh_list()
        self.rules_changed.emit(self.rules)
