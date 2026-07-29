"""持久化快取：以檔案指紋判斷是否需重新匯入；統計結果一併實體儲存。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def _get_cache_dir() -> Path:
    from .paths import get_app_dir

    d = get_app_dir() / "cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def compute_fingerprint(file_paths: list[Path]) -> str:
    """以路徑 + size + mtime 算 SHA256 hex 作為快取 key。"""
    entries: list[str] = []
    for p in sorted(file_paths, key=lambda x: str(x).lower()):
        try:
            st = p.stat()
            entries.append(f"{p.resolve()}|{st.st_size}|{int(st.st_mtime)}")
        except OSError:
            entries.append(f"{p.resolve()}|0|0")
    raw = "\n".join(entries).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def compute_stats_key(
    filter_rules: list[dict[str, Any]] | None,
    thresholds: dict[str, Any] | None,
) -> str:
    """統計快取 key：僅依過濾規則 + 異常閾值（不含表格篩選）。"""
    payload = {
        "filter_rules": filter_rules or [],
        "thresholds": thresholds or {},
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def get_cache_db_path(fingerprint: str) -> Path:
    return _get_cache_dir() / f"{fingerprint}.db"


def get_cache_meta_path(fingerprint: str) -> Path:
    return _get_cache_dir() / f"{fingerprint}.meta.json"


def get_stats_cache_path(fingerprint: str) -> Path:
    return _get_cache_dir() / f"{fingerprint}.stats.json"


def is_cache_valid(fingerprint: str) -> bool:
    db_path = get_cache_db_path(fingerprint)
    meta_path = get_cache_meta_path(fingerprint)
    return db_path.exists() and meta_path.exists()


def save_cache_meta(
    fingerprint: str,
    total: int,
    source_names: list[str],
    fields: list[str],
    file_paths: list[str],
) -> None:
    meta = {
        "fingerprint": fingerprint,
        "total": total,
        "source_names": source_names,
        "fields": fields,
        "file_paths": file_paths,
    }
    path = get_cache_meta_path(fingerprint)
    with path.open("w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


def load_cache_meta(fingerprint: str) -> dict[str, Any] | None:
    path = get_cache_meta_path(fingerprint)
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_stats_cache(
    fingerprint: str,
    stats_key: str,
    stats: dict[str, Any],
    filter_rules: list[dict[str, Any]],
    thresholds: dict[str, Any],
) -> None:
    """將統計結果寫入 cache/<fingerprint>.stats.json。"""
    path = get_stats_cache_path(fingerprint)
    payload = {
        "fingerprint": fingerprint,
        "stats_key": stats_key,
        "filter_rules": filter_rules,
        "thresholds": thresholds,
        "stats": stats,
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def load_stats_cache(
    fingerprint: str, stats_key: str
) -> dict[str, Any] | None:
    """若已存在且 stats_key 相符，回傳 stats；否則 None。"""
    path = get_stats_cache_path(fingerprint)
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    if payload.get("stats_key") != stats_key:
        return None
    stats = payload.get("stats")
    return stats if isinstance(stats, dict) else None


def clear_all_cache() -> int:
    """清除所有快取檔案，回傳刪除的檔案數。"""
    cache_dir = _get_cache_dir()
    removed = 0
    if cache_dir.exists():
        for f in cache_dir.iterdir():
            if f.is_file() and (
                f.suffix in (".db", ".json")
                or "-wal" in f.name
                or "-shm" in f.name
                or f.name.endswith(".stats.json")
            ):
                try:
                    f.unlink()
                    removed += 1
                except OSError:
                    pass
    return removed


def clear_cache_for(fingerprint: str) -> None:
    """清除特定指紋的快取（含統計結果）。"""
    for suffix in (".db", ".db-wal", ".db-shm", ".meta.json", ".stats.json"):
        p = _get_cache_dir() / f"{fingerprint}{suffix}"
        try:
            if p.exists():
                p.unlink()
        except OSError:
            pass


# ------------------------------------------------------------------
# 自動淘汰（LRU）
# ------------------------------------------------------------------

_ENTRY_SUFFIXES = (".db", ".db-wal", ".db-shm", ".meta.json", ".stats.json")


def _entry_fingerprint(name: str) -> str | None:
    for suffix in _ENTRY_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return None


def list_cache_entries(cache_dir: Path | None = None) -> list[dict[str, Any]]:
    """掃描 cache 目錄並依指紋歸組。

    回傳 [{"fingerprint", "files", "total_bytes", "latest_mtime", "has_db"}]，
    依 latest_mtime 新→舊排序。無 .db 的組視為孤兒（import 中斷殘留）。
    """
    d = cache_dir or _get_cache_dir()
    groups: dict[str, dict[str, Any]] = {}
    if not d.exists():
        return []
    for f in d.iterdir():
        if not f.is_file():
            continue
        fp = _entry_fingerprint(f.name)
        if fp is None:
            continue
        try:
            st = f.stat()
        except OSError:
            continue
        g = groups.setdefault(
            fp,
            {
                "fingerprint": fp,
                "files": [],
                "total_bytes": 0,
                "latest_mtime": 0.0,
                "has_db": False,
            },
        )
        g["files"].append(f)
        g["total_bytes"] += st.st_size
        g["latest_mtime"] = max(g["latest_mtime"], st.st_mtime)
        if f.name == f"{fp}.db":
            g["has_db"] = True
    entries = sorted(groups.values(), key=lambda g: -g["latest_mtime"])
    return entries


def prune_cache(
    max_entries: int = 3,
    max_total_bytes: int = 4096 * 1024 * 1024,
    max_age_days: int = 30,
    protect: str | None = None,
    cache_dir: Path | None = None,
    now: float | None = None,
) -> dict[str, int]:
    """依 LRU 淘汰快取：孤兒 → 超齡 → 超出保留組數 → 總量超標。

    protect 指紋（目前使用中）永遠保留；檔案鎖定時跳過該組。
    回傳 {"removed_entries", "removed_files", "freed_bytes"}。
    """
    import time

    d = cache_dir or _get_cache_dir()
    now = time.time() if now is None else now
    result = {"removed_entries": 0, "removed_files": 0, "freed_bytes": 0}

    def _remove_entry(g: dict[str, Any]) -> None:
        freed = 0
        removed = 0
        for f in g["files"]:
            try:
                size = f.stat().st_size
                f.unlink()
                freed += size
                removed += 1
            except OSError:
                pass
        if removed == len(g["files"]):
            result["removed_entries"] += 1
        result["removed_files"] += removed
        result["freed_bytes"] += freed
        g["_removed"] = removed > 0

    entries = list_cache_entries(d)

    # 1. 孤兒組（無 .db，import 中斷殘留）
    for g in entries:
        if not g["has_db"] and g["fingerprint"] != protect:
            _remove_entry(g)
    entries = [g for g in entries if g["has_db"] and not g.get("_removed")]

    # 2. 超齡
    if max_age_days > 0:
        cutoff = now - max_age_days * 86400
        for g in entries:
            if g["latest_mtime"] < cutoff and g["fingerprint"] != protect:
                _remove_entry(g)
        entries = [g for g in entries if not g.get("_removed")]

    # 3. 保留最新 N 組
    if max_entries >= 0:
        kept = 0
        for g in entries:
            if g["fingerprint"] == protect:
                kept += 1
                continue
            if kept < max_entries:
                kept += 1
            else:
                _remove_entry(g)
        entries = [g for g in entries if not g.get("_removed")]

    # 4. 總量超標：從最舊繼續刪（protect 保留）
    if max_total_bytes > 0:
        total = sum(g["total_bytes"] for g in entries)
        for g in reversed(entries):  # 舊→新
            if total <= max_total_bytes:
                break
            if g["fingerprint"] == protect:
                continue
            total -= g["total_bytes"]
            _remove_entry(g)

    return result


def cache_dir_size(cache_dir: Path | None = None) -> tuple[int, int]:
    """回傳 (總位元組, 組數)，供 UI 顯示用量。"""
    entries = list_cache_entries(cache_dir)
    return sum(g["total_bytes"] for g in entries), len(entries)
