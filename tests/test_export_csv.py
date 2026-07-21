"""CSV 匯出測試。"""

from __future__ import annotations

from pathlib import Path

from iis_log_reader.database import LogDatabase
from iis_log_reader.export_csv import export_filtered_csv
from iis_log_reader.parser import parse_files_into_db

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "_smoke_sample" / "u_ex240115.log"


def test_export_filtered_csv(tmp_path: Path) -> None:
    db = LogDatabase()
    try:
        total, _, _ = parse_files_into_db([SAMPLE], db, tz_name="Asia/Taipei")
        assert total > 0
        out = tmp_path / "out.csv"
        path, written = export_filtered_csv(
            db,
            out,
            ["datetimeStr", "c-ip", "cs-uri-stem", "sc-status"],
            filter_rules=[],
            column_filters={},
        )
        assert path.exists()
        assert written == total
        text = path.read_text(encoding="utf-8-sig")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        assert lines[0].startswith("時間")
        assert len(lines) == written + 1
    finally:
        db.close()
