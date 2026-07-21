"""依目前查詢條件串流匯出 CSV（UTF-8 BOM，方便 Excel）。"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Callable, Sequence

from .constants import FIELD_DEFS, LOGICAL_TO_DB
from .database import LogDatabase

ProgressCallback = Callable[[int], None]
CancelCallback = Callable[[], bool]

EXPORT_BATCH = 5000


def export_filtered_csv(
    db: LogDatabase,
    path: str | Path,
    fields: Sequence[str],
    *,
    filter_rules: Sequence[dict[str, Any]] | None = None,
    column_filters: dict[str, str] | None = None,
    time_start_ms: int | None = None,
    time_end_ms: int | None = None,
    sort_key: str = "id",
    sort_dir: str = "asc",
    progress: ProgressCallback | None = None,
    should_cancel: CancelCallback | None = None,
) -> tuple[Path, int]:
    """
    串流寫出符合條件的列。
    回傳 (實際路徑, 寫入筆數)。
    """
    out = Path(path)
    if out.suffix.lower() != ".csv":
        out = out.with_suffix(".csv")

    logical_fields = list(fields)
    if not logical_fields:
        logical_fields = ["datetimeStr", "c-ip", "cs-uri-stem", "sc-status"]

    headers = [
        str(FIELD_DEFS.get(f, {}).get("label", f)) for f in logical_fields
    ]

    written = 0
    offset = 0
    with out.open("w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(headers)
        while True:
            if should_cancel and should_cancel():
                break
            batch = db.fetch_batch(
                offset=offset,
                limit=EXPORT_BATCH,
                sort_key=sort_key,
                sort_dir=sort_dir,
                filter_rules=filter_rules,
                column_filters=column_filters,
                time_start_ms=time_start_ms,
                time_end_ms=time_end_ms,
            )
            if not batch:
                break
            for row in batch:
                writer.writerow(
                    [_cell(row.get(f)) for f in logical_fields]
                )
            written += len(batch)
            offset += len(batch)
            if progress:
                progress(written)
            if len(batch) < EXPORT_BATCH:
                break

    return out, written


def _cell(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def resolve_export_db_columns(fields: Sequence[str]) -> list[str]:
    """邏輯欄位 → DB 欄（供測試／除錯）。"""
    cols: list[str] = []
    for f in fields:
        if f in LOGICAL_TO_DB:
            cols.append(LOGICAL_TO_DB[f])
        elif f == "timestamp":
            cols.append("timestamp")
    return cols
