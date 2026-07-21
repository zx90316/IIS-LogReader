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
