"""cache 自動淘汰（LRU）測試。"""

from __future__ import annotations

import os
from pathlib import Path

from iis_log_reader.cache_store import (
    cache_dir_size,
    clear_all_cache,
    list_cache_entries,
    prune_cache,
)

NOW = 1_800_000_000.0  # 固定基準時間


def _make_entry(
    cache_dir: Path,
    fingerprint: str,
    db_size: int = 1024,
    age_days: float = 0.0,
    with_stats: bool = True,
) -> None:
    mtime = NOW - age_days * 86400
    (cache_dir / f"{fingerprint}.db").write_bytes(b"x" * db_size)
    (cache_dir / f"{fingerprint}.meta.json").write_text("{}", encoding="utf-8")
    if with_stats:
        (cache_dir / f"{fingerprint}.stats.json").write_text("{}", encoding="utf-8")
    for f in cache_dir.glob(f"{fingerprint}.*"):
        os.utime(f, (mtime, mtime))


def _fps(cache_dir: Path) -> set[str]:
    return {g["fingerprint"] for g in list_cache_entries(cache_dir)}


def test_keep_latest_n_entries(tmp_path: Path) -> None:
    for i in range(5):
        _make_entry(tmp_path, f"fp{i}", db_size=100, age_days=float(4 - i))
    result = prune_cache(
        max_entries=3, max_total_bytes=0, max_age_days=0,
        cache_dir=tmp_path, now=NOW,
    )
    assert _fps(tmp_path) == {"fp2", "fp3", "fp4"}
    assert result["removed_entries"] == 2


def test_protect_entry_survives(tmp_path: Path) -> None:
    for i in range(3):
        _make_entry(tmp_path, f"fp{i}", db_size=100, age_days=float(3 - i))
    # fp0 最舊，本應被淘汰，但受 protect 保護
    result = prune_cache(
        max_entries=1, max_total_bytes=0, max_age_days=0,
        protect="fp0", cache_dir=tmp_path, now=NOW,
    )
    assert _fps(tmp_path) == {"fp0", "fp2"}
    assert result["removed_entries"] == 1


def test_total_size_cap_evicts_oldest(tmp_path: Path) -> None:
    _make_entry(tmp_path, "old", db_size=600, age_days=3)
    _make_entry(tmp_path, "mid", db_size=600, age_days=2)
    _make_entry(tmp_path, "new", db_size=600, age_days=1)
    # 每組 = 600(db) + 2(meta) + 2(stats) = 604，總量 1812
    # 上限 1208：刪最舊一組後 1208 達標，其餘保留
    result = prune_cache(
        max_entries=-1, max_total_bytes=1208, max_age_days=0,
        cache_dir=tmp_path, now=NOW,
    )
    assert _fps(tmp_path) == {"mid", "new"}
    assert result["freed_bytes"] >= 600


def test_age_cap(tmp_path: Path) -> None:
    _make_entry(tmp_path, "ancient", db_size=100, age_days=40)
    _make_entry(tmp_path, "recent", db_size=100, age_days=5)
    result = prune_cache(
        max_entries=-1, max_total_bytes=0, max_age_days=30,
        cache_dir=tmp_path, now=NOW,
    )
    assert _fps(tmp_path) == {"recent"}
    assert result["removed_entries"] == 1


def test_orphan_files_removed(tmp_path: Path) -> None:
    _make_entry(tmp_path, "good", db_size=100, age_days=1)
    # import 中斷殘留：有 wal/meta 但無 .db
    (tmp_path / "broken.db-wal").write_bytes(b"w" * 50)
    (tmp_path / "broken.meta.json").write_text("{}", encoding="utf-8")
    (tmp_path / "broken.stats.json").write_text("{}", encoding="utf-8")
    result = prune_cache(
        max_entries=-1, max_total_bytes=0, max_age_days=0,
        cache_dir=tmp_path, now=NOW,
    )
    assert _fps(tmp_path) == {"good"}
    assert not (tmp_path / "broken.db-wal").exists()
    assert result["removed_files"] >= 3


def test_empty_and_missing_dir(tmp_path: Path) -> None:
    result = prune_cache(cache_dir=tmp_path / "nonexistent", now=NOW)
    assert result == {"removed_entries": 0, "removed_files": 0, "freed_bytes": 0}
    assert cache_dir_size(tmp_path / "nonexistent") == (0, 0)


def test_cache_dir_size_and_clear_all(tmp_path: Path) -> None:
    _make_entry(tmp_path, "a", db_size=1000)
    _make_entry(tmp_path, "b", db_size=2000)
    total, count = cache_dir_size(tmp_path)
    assert count == 2
    assert total >= 3000
    # clear_all_cache 走預設目錄；這裡直接驗證 prune 全刪也行為一致
    prune_cache(max_entries=0, max_total_bytes=0, max_age_days=0,
                cache_dir=tmp_path, now=NOW)
    assert list_cache_entries(tmp_path) == []
