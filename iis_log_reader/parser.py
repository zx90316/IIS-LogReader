"""串流解析 IIS W3C Extended Log，UTC → Asia/Taipei，多檔合併。"""

from __future__ import annotations

from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import Any, Callable, Iterator

from .constants import DEFAULT_PARSED_FIELDS, FIELD_DEFS, IIS_TO_LOGICAL
from .timezone_util import format_local, get_tz

ProgressCallback = Callable[[str, int, int], None]


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
            for f in sorted(path.rglob("*")):
                if f.is_file() and f.suffix.lower() == ".log":
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


def parse_line(
    parts: list[str],
    field_names: list[str],
    source_file: str,
    tz: tzinfo,
) -> dict[str, Any] | None:
    """將一行空白分隔的 log 轉成 DB row dict。"""
    if not parts:
        return None

    # IIS 欄位名 → 值
    raw: dict[str, str] = {}
    for idx, name in enumerate(field_names):
        raw[name] = parts[idx] if idx < len(parts) else "-"

    row: dict[str, Any] = {col: None for col in (
        "source_file",
        "timestamp",
        "datetime_str",
        "hour",
        "date",
        "time",
        "s_ip",
        "cs_method",
        "cs_uri_stem",
        "cs_uri_query",
        "s_port",
        "cs_username",
        "c_ip",
        "cs_user_agent",
        "cs_referer",
        "sc_status",
        "sc_substatus",
        "sc_win32_status",
        "time_taken",
        "sc_bytes",
        "cs_bytes",
        "cs_host",
    )}
    row["source_file"] = source_file

    # 對應已知欄位
    for iis_name, value in raw.items():
        logical = IIS_TO_LOGICAL.get(iis_name)
        if not logical:
            # 未在 FIELD_DEFS 的欄位略過（固定 schema）
            continue
        db_col = FIELD_DEFS[logical]["db"]
        row[db_col] = value if value is not None else "-"

    # UA + → 空白
    ua = row.get("cs_user_agent")
    if isinstance(ua, str) and ua and ua != "-":
        row["cs_user_agent"] = ua.replace("+", " ")

    # 數值欄位
    row["sc_status"] = _to_int(row.get("sc_status"), 0)
    row["sc_substatus"] = _to_int(row.get("sc_substatus"), 0)
    row["sc_win32_status"] = _to_int(row.get("sc_win32_status"), 0)
    row["time_taken"] = _to_int(row.get("time_taken"), 0)
    row["sc_bytes"] = _to_int(row.get("sc_bytes"), 0)
    row["cs_bytes"] = _to_int(row.get("cs_bytes"), 0)

    # 字串欄位預設 "-"
    for key in (
        "date",
        "time",
        "s_ip",
        "cs_method",
        "cs_uri_stem",
        "cs_uri_query",
        "s_port",
        "cs_username",
        "c_ip",
        "cs_user_agent",
        "cs_referer",
        "cs_host",
    ):
        if row[key] is None or row[key] == "":
            row[key] = "-"

    d = row.get("date") or "-"
    t = row.get("time") or "-"
    if d != "-" and t != "-":
        try:
            # UTC
            dt_utc = datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
            ts_ms = int(dt_utc.timestamp() * 1000)
            datetime_str, hour = format_local(dt_utc, tz)
            row["timestamp"] = ts_ms
            row["datetime_str"] = datetime_str
            row["hour"] = hour
        except ValueError:
            row["timestamp"] = 0
            row["datetime_str"] = "-"
            row["hour"] = -1
    else:
        row["timestamp"] = 0
        row["datetime_str"] = "-"
        row["hour"] = -1

    return row


def iter_parse_file(
    path: Path,
    tz_name: str = "Asia/Taipei",
) -> Iterator[dict[str, Any]]:
    """串流解析單一 log 檔，產出 DB row dict。"""
    tz = get_tz(tz_name)
    detected_fields: list[str] = []
    source_name = path.name

    with _open_text(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#Fields:"):
                detected_fields = line[8:].strip().split()
                continue
            if line.startswith("#"):
                continue

            fields = detected_fields if detected_fields else list(DEFAULT_PARSED_FIELDS)
            parts = line.split(" ")
            row = parse_line(parts, fields, source_name, tz)
            if row is not None:
                yield row


def parse_files_into_db(
    file_paths: list[str | Path],
    db: Any,
    tz_name: str = "Asia/Taipei",
    progress: ProgressCallback | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> tuple[int, list[str], list[str]]:
    """
    解析多個 log 寫入 LogDatabase。
    回傳 (總筆數, 來源檔名列表, 實際使用的邏輯欄位列表)。
    """
    from .constants import PREFERRED_VISIBLE_FIELDS

    files = collect_log_files(list(file_paths))
    if not files:
        raise FileNotFoundError("找不到可載入的 .log 檔案")

    available_iis: set[str] = set()
    source_names: list[str] = []
    total = 0
    n_files = len(files)

    for fi, path in enumerate(files):
        if should_cancel and should_cancel():
            break
        source_names.append(path.name)
        file_count = 0
        detected: list[str] = []

        # 先掃 #Fields（與資料同趟讀取）
        tz = get_tz(tz_name)
        with _open_text(path) as f:
            for line in f:
                if should_cancel and should_cancel():
                    break
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#Fields:"):
                    detected = line[8:].strip().split()
                    available_iis.update(detected)
                    continue
                if line.startswith("#"):
                    continue
                fields = detected if detected else list(DEFAULT_PARSED_FIELDS)
                if not detected:
                    available_iis.update(DEFAULT_PARSED_FIELDS)
                parts = line.split(" ")
                row = parse_line(parts, fields, path.name, tz)
                if row is not None:
                    db.add_row(row)
                    file_count += 1
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
