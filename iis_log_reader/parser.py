"""串流解析 IIS W3C Extended Log，UTC → Asia/Taipei，多檔合併。"""

from __future__ import annotations

import calendar
import time
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

from .constants import (
    DEFAULT_PARSED_FIELDS,
    IIS_TO_LOGICAL,
    INSERT_COLUMNS,
)
from .timezone_util import fixed_utc_offset_hours, format_local, get_tz

ProgressCallback = Callable[[str, int, int], None]

# INSERT_COLUMNS 索引（熱路徑用常數，避免反覆查表）
_IDX_SOURCE = 0
_IDX_TS = 1
_IDX_DTSTR = 2
_IDX_HOUR = 3
_IDX_DATE = 4
_IDX_TIME = 5

# IIS 欄位 → (INSERT 索引, kind)  kind: 0=str, 1=int, 2=ua(+→空白)
_KIND_STR, _KIND_INT, _KIND_UA = 0, 1, 2
_IIS_SLOT: dict[str, tuple[int, int]] = {
    "date": (_IDX_DATE, _KIND_STR),
    "time": (_IDX_TIME, _KIND_STR),
    "s-ip": (6, _KIND_STR),
    "cs-method": (7, _KIND_STR),
    "cs-uri-stem": (8, _KIND_STR),
    "cs-uri-query": (9, _KIND_STR),
    "s-port": (10, _KIND_STR),
    "cs-username": (11, _KIND_STR),
    "c-ip": (12, _KIND_STR),
    "cs(User-Agent)": (13, _KIND_UA),
    "cs(Referer)": (14, _KIND_STR),
    "sc-status": (15, _KIND_INT),
    "sc-substatus": (16, _KIND_INT),
    "sc-win32-status": (17, _KIND_INT),
    "time-taken": (18, _KIND_INT),
    "sc-bytes": (19, _KIND_INT),
    "cs-bytes": (20, _KIND_INT),
    "cs-host": (21, _KIND_STR),
}

# 預設列模板（source/timestamp/datetime/hour 會被覆寫）
_ROW_TEMPLATE: tuple[Any, ...] = (
    "",  # source_file
    0,  # timestamp
    "-",  # datetime_str
    -1,  # hour
    "-",  # date
    "-",  # time
    "-",  # s_ip
    "-",  # cs_method
    "-",  # cs_uri_stem
    "-",  # cs_uri_query
    "-",  # s_port
    "-",  # cs_username
    "-",  # c_ip
    "-",  # cs_user_agent
    "-",  # cs_referer
    0,  # sc_status
    0,  # sc_substatus
    0,  # sc_win32_status
    0,  # time_taken
    0,  # sc_bytes
    0,  # cs_bytes
    "-",  # cs_host
)

assert len(_ROW_TEMPLATE) == len(INSERT_COLUMNS)


class _FieldPlan:
    __slots__ = ("assigns", "date_part", "time_part", "field_key")

    def __init__(
        self,
        assigns: tuple[tuple[int, int, int], ...],
        date_part: int,
        time_part: int,
        field_key: tuple[str, ...],
    ) -> None:
        self.assigns = assigns
        self.date_part = date_part
        self.time_part = time_part
        self.field_key = field_key


def _compile_field_plan(field_names: Sequence[str]) -> _FieldPlan:
    assigns: list[tuple[int, int, int]] = []
    date_part = -1
    time_part = -1
    for i, name in enumerate(field_names):
        slot = _IIS_SLOT.get(name)
        if slot is None:
            continue
        dest, kind = slot
        assigns.append((i, dest, kind))
        if dest == _IDX_DATE:
            date_part = i
        elif dest == _IDX_TIME:
            time_part = i
    return _FieldPlan(tuple(assigns), date_part, time_part, tuple(field_names))


def collect_log_files(paths: list[str | Path]) -> list[Path]:
    """從檔案路徑與資料夾收集 .log 檔（資料夾遞迴），依路徑排序。"""
    found: list[Path] = []
    seen: set[str] = set()
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        if path.is_file():
            key = str(path.resolve()).lower()
            if key not in seen:
                seen.add(key)
                found.append(path.resolve())
        elif path.is_dir():
            for f in sorted(path.rglob("*.log")):
                if not f.is_file():
                    continue
                key = str(f.resolve()).lower()
                if key not in seen:
                    seen.add(key)
                    found.append(f.resolve())
    return sorted(found, key=lambda x: str(x).lower())


def _open_text(path: Path):
    """嘗試多種編碼開啟文字檔。"""
    for enc in ("utf-8-sig", "utf-8", "cp950", "big5", "latin-1"):
        try:
            f = path.open("r", encoding=enc, errors="strict")
            # 試讀一行確認
            pos = f.tell()
            f.readline()
            f.seek(pos)
            return f
        except (UnicodeDecodeError, UnicodeError):
            try:
                f.close()
            except Exception:
                pass
            continue
    return path.open("r", encoding="utf-8", errors="replace")


def _to_int(value: str | None, default: int = 0) -> int:
    if value is None or value == "" or value == "-":
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _fast_utc_ms_and_local(
    date_s: str, time_s: str, offset_hours: int
) -> tuple[int, str, int] | None:
    """手動解析 YYYY-MM-DD HH:MM:SS（UTC）→ epoch ms + 固定偏移本地時間字串。"""
    if (
        len(date_s) != 10
        or date_s[4] != "-"
        or date_s[7] != "-"
        or len(time_s) < 8
        or time_s[2] != ":"
        or time_s[5] != ":"
    ):
        return None
    try:
        y = int(date_s[0:4])
        mo = int(date_s[5:7])
        d = int(date_s[8:10])
        h = int(time_s[0:2])
        mi = int(time_s[3:5])
        s = int(time_s[6:8])
        ts = calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    lt = time.gmtime(ts + offset_hours * 3600)
    datetime_str = (
        f"{lt.tm_year:04d}-{lt.tm_mon:02d}-{lt.tm_mday:02d} "
        f"{lt.tm_hour:02d}:{lt.tm_min:02d}:{lt.tm_sec:02d}"
    )
    return ts * 1000, datetime_str, lt.tm_hour


def parse_line_tuple(
    parts: list[str],
    plan: _FieldPlan,
    source_file: str,
    *,
    offset_hours: int | None = 8,
    tz: tzinfo | None = None,
) -> tuple[Any, ...] | None:
    """熱路徑：直接產出對齊 INSERT_COLUMNS 的 tuple。"""
    if not parts:
        return None

    row = list(_ROW_TEMPLATE)
    row[_IDX_SOURCE] = source_file
    n = len(parts)

    for part_idx, dest, kind in plan.assigns:
        val = parts[part_idx] if part_idx < n else "-"
        if kind == _KIND_INT:
            if val is None or val == "" or val == "-":
                row[dest] = 0
            else:
                try:
                    row[dest] = int(val)
                except (ValueError, TypeError):
                    row[dest] = 0
        elif kind == _KIND_UA:
            if val and val != "-":
                row[dest] = val.replace("+", " ")
            else:
                row[dest] = val if val else "-"
        else:
            row[dest] = val if val else "-"

    date_s = row[_IDX_DATE]
    time_s = row[_IDX_TIME]
    if date_s != "-" and time_s != "-":
        parsed = None
        if offset_hours is not None:
            parsed = _fast_utc_ms_and_local(date_s, time_s, offset_hours)
        if parsed is not None:
            row[_IDX_TS], row[_IDX_DTSTR], row[_IDX_HOUR] = parsed
        else:
            # 非固定偏移或手動解析失敗：退回 datetime / ZoneInfo
            try:
                dt_utc = datetime.strptime(
                    f"{date_s} {time_s}", "%Y-%m-%d %H:%M:%S"
                ).replace(tzinfo=timezone.utc)
                row[_IDX_TS] = int(dt_utc.timestamp() * 1000)
                if tz is None:
                    tz = get_tz("Asia/Taipei")
                row[_IDX_DTSTR], row[_IDX_HOUR] = format_local(dt_utc, tz)
            except ValueError:
                row[_IDX_TS] = 0
                row[_IDX_DTSTR] = "-"
                row[_IDX_HOUR] = -1
    else:
        row[_IDX_TS] = 0
        row[_IDX_DTSTR] = "-"
        row[_IDX_HOUR] = -1

    return tuple(row)


def parse_line(
    parts: list[str],
    field_names: list[str],
    source_file: str,
    tz: tzinfo,
) -> dict[str, Any] | None:
    """將一行空白分隔的 log 轉成 DB row dict（相容 API）。"""
    plan = _compile_field_plan(field_names)
    offset = fixed_utc_offset_hours(tz)
    tup = parse_line_tuple(
        parts, plan, source_file, offset_hours=offset, tz=tz
    )
    if tup is None:
        return None
    return dict(zip(INSERT_COLUMNS, tup))


def iter_parse_file(
    path: Path,
    tz_name: str = "Asia/Taipei",
) -> Iterator[dict[str, Any]]:
    """串流解析單一 log 檔，產出 DB row dict。"""
    tz = get_tz(tz_name)
    offset = fixed_utc_offset_hours(tz)
    detected_fields: list[str] = []
    plan = _compile_field_plan(DEFAULT_PARSED_FIELDS)
    source_name = path.name

    with _open_text(path) as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#Fields:"):
                detected_fields = line[8:].strip().split()
                plan = _compile_field_plan(detected_fields)
                continue
            if line.startswith("#"):
                continue

            parts = line.split(" ")
            tup = parse_line_tuple(
                parts, plan, source_name, offset_hours=offset, tz=tz
            )
            if tup is not None:
                yield dict(zip(INSERT_COLUMNS, tup))


def parse_files_into_db(
    file_paths: list[str | Path],
    db: Any,
    tz_name: str = "Asia/Taipei",
    progress: ProgressCallback | None = None,
    should_cancel: Callable[[], bool] | None = None,
    *,
    resolved_files: list[Path] | None = None,
) -> tuple[int, list[str], list[str]]:
    """
    解析多個 log 寫入 LogDatabase。
    回傳 (總筆數, 來源檔名列表, 實際使用的邏輯欄位列表)。
    """
    from .constants import PREFERRED_VISIBLE_FIELDS

    files = resolved_files if resolved_files is not None else collect_log_files(
        list(file_paths)
    )
    if not files:
        raise FileNotFoundError("找不到可載入的 .log 檔案")

    available_iis: set[str] = set()
    source_names: list[str] = []
    total = 0
    n_files = len(files)
    tz = get_tz(tz_name)
    offset = fixed_utc_offset_hours(tz)
    default_plan = _compile_field_plan(DEFAULT_PARSED_FIELDS)
    cancel_every = 4096

    begin_import = getattr(db, "begin_import", None)
    if callable(begin_import):
        begin_import()

    add_row = db.add_row

    for fi, path in enumerate(files):
        if should_cancel and should_cancel():
            break
        source_names.append(path.name)
        plan = default_plan
        fields_locked = False
        line_i = 0

        with _open_text(path) as f:
            for line in f:
                line_i += 1
                if should_cancel and line_i % cancel_every == 0 and should_cancel():
                    break
                # 去掉換行即可；IIS 資料列幾乎不會有首尾空白需要 strip
                if line[-1:] == "\n":
                    line = line[:-1]
                if line[-1:] == "\r":
                    line = line[:-1]
                if not line:
                    continue
                if line[0] == "#":
                    if line.startswith("#Fields:"):
                        detected = line[8:].strip().split()
                        plan = _compile_field_plan(detected)
                        available_iis.update(detected)
                        fields_locked = True
                    continue

                if not fields_locked:
                    available_iis.update(DEFAULT_PARSED_FIELDS)
                    fields_locked = True

                parts = line.split(" ")
                tup = parse_line_tuple(
                    parts, plan, path.name, offset_hours=offset, tz=tz
                )
                if tup is not None:
                    add_row(tup)
                    total += 1
                    if progress and total % 20000 == 0:
                        progress(path.name, fi + 1, n_files)

        if progress:
            progress(path.name, fi + 1, n_files)

    db.finish_import(source_names)

    # 可用邏輯欄位
    logical_fields = ["datetimeStr"]
    for iis in DEFAULT_PARSED_FIELDS:
        # 保持穩定順序：先預設欄位中有出現的
        if iis in available_iis or not available_iis:
            logical = IIS_TO_LOGICAL.get(iis, iis)
            if logical not in logical_fields:
                logical_fields.append(logical)
    for iis in sorted(available_iis):
        logical = IIS_TO_LOGICAL.get(iis)
        if logical and logical not in logical_fields:
            logical_fields.append(logical)
    if "source_file" not in logical_fields:
        logical_fields.append("source_file")

    # 確保 preferred 中存在的優先
    _ = PREFERRED_VISIBLE_FIELDS  # 供呼叫端使用

    return total, source_names, logical_fields
