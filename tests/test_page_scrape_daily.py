"""同頁面大量抓取偵測的「每日」語意：跨日累計不得誤判正常使用者。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from iis_log_reader.database import LogDatabase
from iis_log_reader.stats import compute_stats

ATTACK_IP = "203.0.113.66"
HEAVY_USER_IP = "192.168.1.5"


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _row(ts_ms: int, ip: str, url: str) -> dict:
    local = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc) + timedelta(hours=8)
    return {
        "source_file": "test.log",
        "timestamp": ts_ms,
        "datetime_str": local.strftime("%Y-%m-%d %H:%M:%S"),
        "hour": local.hour,
        "c_ip": ip,
        "cs_uri_stem": url,
        "cs_uri_query": "-",
        "sc_status": 200,
        "time_taken": 30,
    }


def _fill(db: LogDatabase, ip: str, url: str, day: datetime, count: int) -> None:
    """在指定 UTC 日期的 01:00 起，每分鐘一筆填入 count 筆。"""
    base = day.replace(hour=1, minute=0, second=0, microsecond=0)
    db.add_rows(_row(_ms(base + timedelta(minutes=i)), ip, url) for i in range(count))


def _stats(db: LogDatabase) -> dict:
    return compute_stats(
        db, filter_rules=[], thresholds={"page_scrape_count": 100}
    )


def test_cross_day_accumulation_not_flagged() -> None:
    """每天 60 次、連續 3 天共 180 次：單日未達門檻，不得列入異常。"""
    db = LogDatabase()
    try:
        for d in range(3):
            _fill(db, HEAVY_USER_IP, "/index", datetime(2026, 7, 26 + d, tzinfo=timezone.utc), 60)
        db.flush()
        anomalies = _stats(db)["anomalies"]
        assert anomalies["pageScrapesCount"] == 0
        assert anomalies["pageScrapes"] == []
    finally:
        db.close()


def test_single_day_over_threshold_flagged_with_day() -> None:
    """同一天 120 次達門檻：列入異常並帶本地日期。"""
    db = LogDatabase()
    try:
        _fill(db, ATTACK_IP, "/products/detail", datetime(2026, 7, 28, tzinfo=timezone.utc), 120)
        db.flush()
        anomalies = _stats(db)["anomalies"]
        assert anomalies["pageScrapesCount"] == 1
        entry = anomalies["pageScrapes"][0]
        assert entry["ip"] == ATTACK_IP
        assert entry["day"] == "2026-07-28"
        assert entry["count"] == 120
    finally:
        db.close()


def test_multiple_days_each_over_threshold_separate_groups() -> None:
    """兩天各 120 次：拆成兩組，各自帶自己的日期。"""
    db = LogDatabase()
    try:
        _fill(db, ATTACK_IP, "/products/detail", datetime(2026, 7, 28, tzinfo=timezone.utc), 120)
        _fill(db, ATTACK_IP, "/products/detail", datetime(2026, 7, 29, tzinfo=timezone.utc), 120)
        db.flush()
        anomalies = _stats(db)["anomalies"]
        assert anomalies["pageScrapesCount"] == 2
        days = sorted(s["day"] for s in anomalies["pageScrapes"])
        assert days == ["2026-07-28", "2026-07-29"]
    finally:
        db.close()
