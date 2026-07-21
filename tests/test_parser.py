"""Unit tests for IIS log parser."""

from __future__ import annotations

from pathlib import Path

from iis_log_reader.database import LogDatabase
from iis_log_reader.parser import collect_log_files, parse_files_into_db, parse_line
from iis_log_reader.timezone_util import get_tz

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = ROOT / "_smoke_sample"


def test_collect_log_files() -> None:
    files = collect_log_files([SAMPLE_DIR])
    names = sorted(p.name for p in files)
    assert "u_ex240115.log" in names
    assert "u_ex240116.log" in names


def test_parse_line_basic() -> None:
    fields = [
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
    ]
    line = (
        "2024-01-15 02:10:00 192.168.1.1 GET /index.aspx - 80 - "
        "10.0.0.5 Mozilla/5.0+(Windows+NT+10.0) - 200 0 0 120"
    )
    parts = line.split()
    row = parse_line(parts, fields, source_file="test.log", tz=get_tz("Asia/Taipei"))
    assert row is not None
    assert row["cs_method"] == "GET"
    assert row["cs_uri_stem"] == "/index.aspx"
    assert row["c_ip"] == "10.0.0.5"
    assert row["sc_status"] == 200
    assert row["time_taken"] == 120
    assert "Windows" in (row["cs_user_agent"] or "")
    # UTC 02:10 → 台北 10:10
    assert row["datetime_str"] == "2024-01-15 10:10:00"
    assert row["hour"] == 10
    assert row["timestamp"] == 1705284600000


def test_parse_files_into_db() -> None:
    db = LogDatabase()
    try:
        total, sources, fields = parse_files_into_db(
            [SAMPLE_DIR / "u_ex240115.log"],
            db,
            tz_name="Asia/Taipei",
        )
        assert total > 0
        assert sources
        assert fields
        assert db.count() == total
    finally:
        db.close()
