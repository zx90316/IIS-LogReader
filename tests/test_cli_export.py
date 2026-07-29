"""CLI 匯出端到端測試：假 W3C log → run_cli → 報告/完整清單/黑名單。"""

from __future__ import annotations

import csv
from pathlib import Path

from iis_log_reader.cli import EXIT_NO_DATA, EXIT_OK, run_cli
from iis_log_reader.config import AppConfig

ATTACK_IP = "203.0.113.66"
NORMAL_IP = "192.168.1.5"

HEADER = """#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2026-07-28 00:00:00
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
"""


def _make_log(dir_path: Path, attack_rows: int = 120) -> Path:
    lines = [HEADER]
    for i in range(attack_rows):
        ts_min = i  # 每分鐘一次，跨 2 小時
        hh, mm = divmod(ts_min, 60)
        lines.append(
            f"2026-07-28 {hh:02d}:{mm:02d}:00 10.0.0.1 GET /products/detail "
            f"id={i % 5} 80 - {ATTACK_IP} Mozilla/5.0 - 200 0 0 50\n"
        )
    for i in range(10):
        lines.append(
            f"2026-07-28 10:{i:02d}:00 10.0.0.1 GET /index - 80 - "
            f"{NORMAL_IP} Mozilla/5.0 - 200 0 0 20\n"
        )
    log_path = dir_path / "u_ex260728.log"
    log_path.write_text("".join(lines), encoding="utf-8")
    return log_path


def _make_config(tmp_path: Path) -> AppConfig:
    cfg = AppConfig(tmp_path / "app.config")
    cfg.filter_rules = []
    cfg.thresholds["page_scrape_count"] = 100
    return cfg


def test_run_cli_exports_all_files(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    _make_log(log_dir)
    out_dir = tmp_path / "out"

    code = run_cli(str(log_dir), out_dir, "html", config=_make_config(tmp_path))

    assert code == EXIT_OK
    report = out_dir / "分析報告.html"
    scrape_csv = out_dir / "同頁面大量抓取_完整清單.csv"
    suggest = out_dir / "建議黑名單.txt"
    ip_txt = out_dir / "黑名單IP.txt"
    for p in (report, scrape_csv, suggest, ip_txt):
        assert p.exists(), f"缺少輸出：{p}"

    # 黑名單IP.txt：一行一 IP，無重複、無標頭
    ips = ip_txt.read_text(encoding="utf-8").split()
    assert ips == [ATTACK_IP]
    assert NORMAL_IP not in ips

    # 建議黑名單：含 IP 與完整理由（每日門檻語意）
    text = suggest.read_text(encoding="utf-8")
    assert ATTACK_IP in text
    assert "於 2026-07-28 對 /products/detail" in text
    assert "120" in text
    assert "每日門檻 100" in text
    assert "5 種參數" in text

    # 完整清單 CSV：header + 1 組資料
    with scrape_csv.open(encoding="utf-8-sig", newline="") as fp:
        rows = list(csv.reader(fp))
    assert rows[0] == ["IP", "目標頁面", "日期", "次數", "開始時間", "結束時間", "參數種數", "其餘瀏覽參數"]
    assert len(rows) == 2
    assert rows[1][0] == ATTACK_IP
    assert rows[1][1] == "/products/detail"
    assert rows[1][2] == "2026-07-28"
    assert rows[1][3] == "120"

    # 報告含同頁面大量抓取區塊
    html = report.read_text(encoding="utf-8")
    assert "同頁面大量抓取" in html
    assert ATTACK_IP in html


def test_run_cli_md_format(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    _make_log(log_dir)
    out_dir = tmp_path / "out"

    code = run_cli(str(log_dir), out_dir, "md", config=_make_config(tmp_path))

    assert code == EXIT_OK
    md = (out_dir / "分析報告.md").read_text(encoding="utf-8")
    assert "同頁面大量抓取" in md
    assert ATTACK_IP in md


def test_run_cli_single_file_input(tmp_path: Path) -> None:
    log_path = _make_log(tmp_path)
    out_dir = tmp_path / "out"

    code = run_cli(str(log_path), out_dir, "html", config=_make_config(tmp_path))

    assert code == EXIT_OK
    assert (out_dir / "黑名單IP.txt").exists()


def test_run_cli_no_logs(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    code = run_cli(str(empty), tmp_path / "out", "html", config=_make_config(tmp_path))
    assert code == EXIT_NO_DATA


def test_run_cli_respects_filter_rules(tmp_path: Path) -> None:
    """過濾規則排除攻擊頁面後，黑名單不得再有該 IP。"""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    _make_log(log_dir)
    out_dir = tmp_path / "out"

    cfg = _make_config(tmp_path)
    cfg.filter_rules = [
        {
            "id": 1,
            "name": "排除 products",
            "type": "uri_contains",
            "value": "/products/detail",
            "enabled": True,
        }
    ]
    code = run_cli(str(log_dir), out_dir, "html", config=cfg)

    assert code == EXIT_OK
    ips = (out_dir / "黑名單IP.txt").read_text(encoding="utf-8").split()
    assert ips == []
    text = (out_dir / "建議黑名單.txt").read_text(encoding="utf-8")
    assert ATTACK_IP not in text
    assert "未偵測到可疑 IP" in text
    # 120 筆攻擊流量被過濾，報告只剩 10 筆正常流量
    html = (out_dir / "分析報告.html").read_text(encoding="utf-8")
    assert ATTACK_IP not in html
    assert "1 條規則" in html
