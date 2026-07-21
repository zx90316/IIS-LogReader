"""DB Browser 風格數值/文字篩選：優先直欄比較以利索引。"""

from __future__ import annotations

import re
from typing import Any


def parse_filter_expr(
    text: str, db_col: str, is_numeric: bool = False
) -> tuple[str, list[Any]] | None:
    """
    解析一個欄位的篩選表達式，回傳 (SQL片段, 參數列表)。
    若為空或無法解析，回傳 None。
    """
    text = text.strip()
    if not text:
        return None

    upper = text.upper()

    if upper == "NULL":
        return f"({db_col} IS NULL OR {db_col} = '' OR CAST({db_col} AS TEXT) = '-')", []

    if upper == "NOT NULL":
        return (
            f"({db_col} IS NOT NULL AND CAST({db_col} AS TEXT) != '' "
            f"AND CAST({db_col} AS TEXT) != '-')",
            [],
        )

    # LIKE / NOT LIKE
    m = re.match(r"^(NOT\s+)?LIKE\s+(.+)$", text, re.IGNORECASE)
    if m:
        negation = "NOT " if m.group(1) else ""
        pattern = m.group(2).strip()
        return (
            f"CAST(IFNULL({db_col},'') AS TEXT) {negation}LIKE ? COLLATE NOCASE",
            [pattern],
        )

    # Comparison operators: >=, <=, <>, !=, ==, =, >, <
    m = re.match(r"^(>=|<=|<>|!=|==|=|>|<)(.*)$", text)
    if m:
        op = m.group(1)
        val = m.group(2).strip()

        if is_numeric and op in ("=", "==", "<>", "!=", ">", ">=", "<", "<="):
            sql_op = "=" if op == "==" else ("!=" if op == "<>" else op)
            try:
                num_val: int | float = int(val)
                return f"{db_col} {sql_op} ?", [num_val]
            except ValueError:
                try:
                    num_val = float(val)
                    return f"{db_col} {sql_op} ?", [num_val]
                except ValueError:
                    pass

        if op in ("=", "=="):
            return (
                f"CAST(IFNULL({db_col},'') AS TEXT) = ? COLLATE NOCASE",
                [val],
            )

        if op in ("<>", "!="):
            return (
                f"CAST(IFNULL({db_col},'') AS TEXT) != ? COLLATE NOCASE",
                [val],
            )

        if op in (">", ">=", "<", "<="):
            return (
                f"CAST(IFNULL({db_col},'') AS TEXT) {op} ? COLLATE NOCASE",
                [val],
            )

    # 預設：LIKE %value%
    return (
        f"CAST(IFNULL({db_col},'') AS TEXT) LIKE ? COLLATE NOCASE",
        [f"%{text}%"],
    )
