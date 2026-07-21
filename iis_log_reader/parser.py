"""串流解析 IIS W3C Extended Log，UTC → Asia/Taipei，多檔合併。"""

from __future__ import annotations

import os
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
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

# INSERT_COLUMNS 索引
_IDX_SOURCE = 0
_IDX_TS = 1
_IDX_DTSTR = 2
_IDX_HOUR = 3
_IDX_DATE = 4
_IDX_TIME = 5

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

_ROW_TEMPLATE: tuple[Any, ...] = (
    "",
    0,
    "-",
    -1,
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    0,
    0,
    0,
    0,
    0,
    0,
    "-",
)

assert len(_ROW_TEMPLATE) == len(INSERT_COLUMNS)

_DAYS_IN_MONTH = (0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)

# 常見 IIS #Fields（含你目前環境的 17 欄格式）
_FIELDS_STD15 = (
    "date",
    "time",
    "s-ip",
    "cs-method",
    "cs-uri-stem",
    "cs-uri-query",
    "s-port",
    "cs-username",
    "c-ip",
    "cs(User-Agent)",
    "cs(Referer)",
    "sc-status",
    "sc-substatus",
    "sc-win32-status",
    "time-taken",
)
_FIELDS_STD17 = (
    "date",
    "time",
    "s-ip",
    "cs-method",
    "cs-uri-stem",
    "cs-uri-query",
    "s-port",
    "cs-username",
    "c-ip",
    "cs(User-Agent)",
    "cs(Referer)",
    "sc-status",
    "sc-substatus",
    "sc-win32-status",
    "sc-bytes",
    "cs-bytes",
    "time-taken",
)


class _FieldPlan:
    __slots__ = ("assigns", "date_part", "time_part", "field_key", "fast_fn")

    def __init__(
        self,
        assigns: tuple[tuple[int, int, int], ...],
        date_part: int,
        time_part: int,
        field_key: tuple[str, ...],
        fast_fn: Callable[..., tuple[Any, ...] | None] | None = None,
    ) -> None:
        self.assigns = assigns
        self.date_part = date_part
        self.time_part = time_part
        self.field_key = field_key
        self.fast_fn = fast_fn


def _days_from_civil(y: int, m: int, d: int) -> int:
    """Civil date → days since Unix epoch（Howard Hinnant）。"""
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (9 if m <= 2 else -3)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _fast_utc_ms_and_local(
    date_s: str, time_s: str, offset_hours: int
) -> tuple[int, str, int] | None:
    """手動解析 YYYY-MM-DD HH:MM:SS（UTC）→ epoch ms + 固定偏移本地時間。"""
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
        ts = _days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s
    except (ValueError, OverflowError):
        return None

    # 本地時間：對固定偏移直接加小時（台灣 +8，無 DST）
    h2 = h + offset_hours
    if h2 >= 24:
        h2 -= 24
        d += 1
        if mo == 2 and (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)):
            md = 29
        else:
            md = _DAYS_IN_MONTH[mo]
        if d > md:
            d = 1
            mo += 1
            if mo > 12:
                mo = 1
                y += 1
    elif h2 < 0:
        # 理論上 offset>=0；保底
        h2 += 24
        d -= 1
        if d < 1:
            mo -= 1
            if mo < 1:
                mo = 12
                y -= 1
            if mo == 2 and (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)):
                d = 29
            else:
                d = _DAYS_IN_MONTH[mo]

    datetime_str = f"{y:04d}-{mo:02d}-{d:02d} {h2:02d}:{mi:02d}:{s:02d}"
    return ts * 1000, datetime_str, h2


def _iint(val: str) -> int:
    if not val or val == "-":
        return 0
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


def _parse_line_std17(
    parts: list[str], source_file: str, offset_hours: int = 8
) -> tuple[Any, ...] | None:
    """針對 17 欄常見 IIS 格式的展開熱路徑。"""
    n = len(parts)
    if n < 17:
        parts = parts + ["-"] * (17 - n)
    date_s = parts[0]
    time_s = parts[1]
    ua = parts[9]
    if ua and ua != "-" and "+" in ua:
        ua = ua.replace("+", " ")
    parsed = _fast_utc_ms_and_local(date_s, time_s, offset_hours)
    if parsed is None:
        ts, dtstr, hour = 0, "-", -1
    else:
        ts, dtstr, hour = parsed
    return (
        source_file,
        ts,
        dtstr,
        hour,
        date_s or "-",
        time_s or "-",
        parts[2] or "-",
        parts[3] or "-",
        parts[4] or "-",
        parts[5] or "-",
        parts[6] or "-",
        parts[7] or "-",
        parts[8] or "-",
        ua or "-",
        parts[10] or "-",
        _iint(parts[11]),
        _iint(parts[12]),
        _iint(parts[13]),
        _iint(parts[16]),  # time-taken
        _iint(parts[14]),  # sc-bytes
        _iint(parts[15]),  # cs-bytes
        "-",
    )


def _parse_line_std15(
    parts: list[str], source_file: str, offset_hours: int = 8
) -> tuple[Any, ...] | None:
    """針對 15 欄預設 IIS 格式的展開熱路徑。"""
    n = len(parts)
    if n < 15:
        parts = parts + ["-"] * (15 - n)
    date_s = parts[0]
    time_s = parts[1]
    ua = parts[9]
    if ua and ua != "-" and "+" in ua:
        ua = ua.replace("+", " ")
    parsed = _fast_utc_ms_and_local(date_s, time_s, offset_hours)
    if parsed is None:
        ts, dtstr, hour = 0, "-", -1
    else:
        ts, dtstr, hour = parsed
    return (
        source_file,
        ts,
        dtstr,
        hour,
        date_s or "-",
        time_s or "-",
        parts[2] or "-",
        parts[3] or "-",
        parts[4] or "-",
        parts[5] or "-",
        parts[6] or "-",
        parts[7] or "-",
        parts[8] or "-",
        ua or "-",
        parts[10] or "-",
        _iint(parts[11]),
        _iint(parts[12]),
        _iint(parts[13]),
        _iint(parts[14]),
        0,
        0,
        "-",
    )


_FAST_BY_FIELDS: dict[tuple[str, ...], Callable[..., tuple[Any, ...] | None]] = {
    _FIELDS_STD17: _parse_line_std17,
    _FIELDS_STD15: _parse_line_std15,
}


def _compile_field_plan(field_names: Sequence[str]) -> _FieldPlan:
    assigns: list[tuple[int, int, int]] = []
    date_part = -1
    time_part = -1
    key = tuple(field_names)
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
    return _FieldPlan(
        tuple(assigns), date_part, time_part, key, _FAST_BY_FIELDS.get(key)
    )


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
            f = path.open("r", encoding=enc, errors="strict", buffering=1024 * 1024)
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
    return path.open("r", encoding="utf-8", errors="replace", buffering=1024 * 1024)


def _to_int(value: str | None, default: int = 0) -> int:
    if value is None or value == "" or value == "-":
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


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

    off = 8 if offset_hours is None else offset_hours
    if plan.fast_fn is not None and offset_hours is not None:
        return plan.fast_fn(parts, source_file, off)

    row = list(_ROW_TEMPLATE)
    row[_IDX_SOURCE] = source_file
    n = len(parts)

    for part_idx, dest, kind in plan.assigns:
        val = parts[part_idx] if part_idx < n else "-"
        if kind == _KIND_INT:
            row[dest] = _iint(val)
        elif kind == _KIND_UA:
            if val and val != "-" and "+" in val:
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
    plan = _compile_field_plan(DEFAULT_PARSED_FIELDS)
    source_name = path.name

    with _open_text(path) as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#Fields:"):
                plan = _compile_field_plan(line[8:].strip().split())
                continue
            if line.startswith("#"):
                continue

            parts = line.split(" ")
            tup = parse_line_tuple(
                parts, plan, source_name, offset_hours=offset, tz=tz
            )
            if tup is not None:
                yield dict(zip(INSERT_COLUMNS, tup))


def _logical_fields_from_iis(available_iis: set[str]) -> list[str]:
    logical_fields = ["datetimeStr"]
    for iis in DEFAULT_PARSED_FIELDS:
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
    return logical_fields


def _parse_single_file_into_db(
    path: Path,
    db: Any,
    tz_name: str,
    should_cancel: Callable[[], bool] | None = None,
) -> tuple[int, set[str], str]:
    """串流解析單一檔寫入 db，回傳 (列數, available_iis, source_name)。"""
    tz = get_tz(tz_name)
    offset = fixed_utc_offset_hours(tz)
    plan = _compile_field_plan(DEFAULT_PARSED_FIELDS)
    source_name = path.name
    available_iis: set[str] = set()
    fields_locked = False
    local_batch: list[tuple[Any, ...]] = []
    cancel_every = 8192
    line_i = 0
    count = 0
    fast = None
    off = 8 if offset is None else offset
    add_tuples = getattr(db, "add_tuples", None)

    def _flush_local() -> None:
        nonlocal count
        if not local_batch:
            return
        if callable(add_tuples):
            add_tuples(local_batch)
        else:
            for row in local_batch:
                db.add_row(row)
        count += len(local_batch)
        local_batch.clear()

    with _open_text(path) as f:
        for line in f:
            line_i += 1
            if should_cancel and line_i % cancel_every == 0 and should_cancel():
                break
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
                    fast = plan.fast_fn
                    available_iis.update(detected)
                    fields_locked = True
                continue

            if not fields_locked:
                available_iis.update(DEFAULT_PARSED_FIELDS)
                fields_locked = True
                fast = plan.fast_fn

            parts = line.split(" ")
            if fast is not None and offset is not None:
                tup = fast(parts, source_name, off)
            else:
                tup = parse_line_tuple(
                    parts, plan, source_name, offset_hours=offset, tz=tz
                )
            if tup is not None:
                local_batch.append(tup)
                if len(local_batch) >= 8192:
                    _flush_local()

    _flush_local()
    return count, available_iis, source_name


def _runtime_frozen() -> bool:
    if getattr(sys, "frozen", False):
        return True
    return "__compiled__" in globals()


def _can_use_process_pool(n_files: int) -> bool:
    if n_files < 2:
        return False
    if _runtime_frozen():
        return False
    # Windows spawn 冷啟動成本高；檔案太少不划算
    return n_files >= 3


def _parse_file_to_shard(payload: tuple[str, str, str]) -> tuple[str, int, str, list[str]]:
    """ProcessPool worker：解析一檔到獨立 SQLite shard（無索引）。"""
    path_str, tz_name, shard_path = payload
    from .database import LogDatabase

    path = Path(path_str)
    db = LogDatabase(path=shard_path)
    try:
        # shard 用 DELETE/OFF，避免 WAL 殘留導致主行程 ATTACH/DETACH 鎖死
        db.conn.execute("PRAGMA journal_mode=DELETE")
        db.conn.commit()
        db.begin_import()
        count, available, source_name = _parse_single_file_into_db(
            path, db, tz_name
        )
        db.flush()
        db.conn.commit()
        db._importing = False
        return shard_path, count, source_name, sorted(available)
    finally:
        try:
            db.conn.close()
        except Exception:
            pass


def _parse_files_parallel(
    files: list[Path],
    db: Any,
    tz_name: str,
    progress: ProgressCallback | None,
    should_cancel: Callable[[], bool] | None,
) -> tuple[int, list[str], list[str]]:
    n_files = len(files)
    workers = max(1, min(n_files, os.cpu_count() or 4, 8))
    tmp_dir = tempfile.mkdtemp(prefix="iis_log_shards_")
    payloads: list[tuple[str, str, str]] = []
    for i, path in enumerate(files):
        shard = str(Path(tmp_dir) / f"shard_{i:04d}.db")
        payloads.append((str(path), tz_name, shard))

    begin_import = getattr(db, "begin_import", None)
    if callable(begin_import):
        begin_import()

    available_iis: set[str] = set()
    # 保持與輸入相同順序的結果槽位
    results: list[tuple[int, str, list[str]] | None] = [None] * n_files
    total = 0
    cancelled = False

    try:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            fut_map = {
                pool.submit(_parse_file_to_shard, payloads[i]): i
                for i in range(n_files)
            }
            done_files = 0
            for fut in as_completed(fut_map):
                idx = fut_map[fut]
                if should_cancel and should_cancel():
                    cancelled = True
                    for other in fut_map:
                        other.cancel()
                    break
                shard_path, count, source_name, avail = fut.result()
                absorb = getattr(db, "absorb_shard", None)
                if callable(absorb):
                    absorb(shard_path)
                else:
                    # 後備：重新讀 shard 不合理，改為略過
                    pass
                try:
                    Path(shard_path).unlink(missing_ok=True)
                    for suffix in ("-wal", "-shm"):
                        p = Path(shard_path + suffix)
                        if p.exists():
                            p.unlink()
                except OSError:
                    pass
                results[idx] = (count, source_name, avail)
                available_iis.update(avail)
                total += count
                done_files += 1
                if progress:
                    progress(source_name, done_files, n_files)
    finally:
        # 清理殘留 shard
        try:
            for p in Path(tmp_dir).glob("*"):
                try:
                    p.unlink()
                except OSError:
                    pass
            Path(tmp_dir).rmdir()
        except OSError:
            pass

    if cancelled:
        source_names = [
            r[1] if r else files[i].name for i, r in enumerate(results)
        ]
        db.finish_import(source_names)
        return total, source_names, _logical_fields_from_iis(available_iis)

    source_names = [
        (results[i][1] if results[i] else files[i].name) for i in range(n_files)
    ]
    for r in results:
        if r:
            available_iis.update(r[2])

    db.finish_import(source_names)
    return total, source_names, _logical_fields_from_iis(available_iis)


def _parse_files_sequential(
    files: list[Path],
    db: Any,
    tz_name: str,
    progress: ProgressCallback | None,
    should_cancel: Callable[[], bool] | None,
) -> tuple[int, list[str], list[str]]:
    available_iis: set[str] = set()
    source_names: list[str] = []
    total = 0
    n_files = len(files)

    begin_import = getattr(db, "begin_import", None)
    if callable(begin_import):
        begin_import()

    for fi, path in enumerate(files):
        if should_cancel and should_cancel():
            break
        count, avail, source_name = _parse_single_file_into_db(
            path, db, tz_name, should_cancel=should_cancel
        )
        source_names.append(source_name)
        available_iis.update(avail)
        total += count
        if progress:
            progress(source_name, fi + 1, n_files)

    db.finish_import(source_names)
    return total, source_names, _logical_fields_from_iis(available_iis)


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
    files = (
        resolved_files
        if resolved_files is not None
        else collect_log_files(list(file_paths))
    )
    if not files:
        raise FileNotFoundError("找不到可載入的 .log 檔案")

    if _can_use_process_pool(len(files)):
        try:
            return _parse_files_parallel(
                files, db, tz_name, progress, should_cancel
            )
        except Exception:
            # spawn / 權限等失敗時退回單行程（確保不留半開 transaction）
            try:
                if getattr(db, "conn", None) is not None and db.conn.in_transaction:
                    db.conn.commit()
            except Exception:
                pass

    return _parse_files_sequential(
        files, db, tz_name, progress, should_cancel
    )
