"""依「同頁面大量抓取」偵測結果產生建議黑名單與完整清單匯出。"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

SUGGEST_FILENAME = "建議黑名單.txt"
IP_FILENAME = "黑名單IP.txt"
SCRAPE_CSV_FILENAME = "同頁面大量抓取_完整清單.csv"


def build_blacklist_suggestions(
    anomalies: dict[str, Any],
    thresholds: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """把 pageScrapes 依 IP 分組成黑名單建議，依總次數降序。"""
    scrapes = anomalies.get("pageScrapes", [])
    by_ip: dict[str, dict[str, Any]] = {}
    for s in scrapes:
        ip = str(s.get("ip", ""))
        if not ip:
            continue
        entry = by_ip.setdefault(ip, {"ip": ip, "total_count": 0, "entries": []})
        entry["total_count"] += int(s.get("count", 0))
        entry["entries"].append(s)
    suggestions = sorted(by_ip.values(), key=lambda x: -x["total_count"])
    threshold = int((thresholds or {}).get("page_scrape_count", 100))
    for item in suggestions:
        item["threshold"] = threshold
    return suggestions


def format_reason(entry: dict[str, Any], threshold: int) -> str:
    """單一目標頁面的完整理由文字。"""
    url = entry.get("url", "-")
    count = int(entry.get("count", 0))
    start = entry.get("startStr", "-")
    end = entry.get("endStr", "-")
    reason = (
        f"對 {url} 請求 {count:,} 次（門檻 {threshold:,}），"
        f"時間 {start} ~ {end}"
    )
    query_count = int(entry.get("queryCount", 0) or 0)
    queries = entry.get("queries") or []
    if query_count > 0:
        if queries:
            top = "、".join(f"{q['query']}×{q['count']}" for q in queries)
            reason += f"，帶 {query_count} 種參數（{top}…）"
        else:
            reason += f"，帶 {query_count} 種參數"
    return reason


def export_blacklist(
    suggestions: list[dict[str, Any]],
    out_dir: str | Path,
) -> tuple[Path, Path]:
    """寫出建議黑名單（含理由）與純 IP 清單，回傳兩個路徑。"""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    suggest_path = out_dir / SUGGEST_FILENAME
    lines: list[str] = [
        "建議黑名單（依「同頁面大量抓取」偵測結果）",
        "",
    ]
    if not suggestions:
        lines.append("未偵測到可疑 IP。")
    for item in suggestions:
        lines.append(f"{item['ip']}（合計 {item['total_count']:,} 次）")
        for entry in item["entries"]:
            lines.append(f"  - {format_reason(entry, item['threshold'])}")
        lines.append("")
    suggest_path.write_text("\n".join(lines), encoding="utf-8")

    ip_path = out_dir / IP_FILENAME
    ip_lines = [item["ip"] for item in suggestions]
    ip_path.write_text(
        "\n".join(ip_lines) + ("\n" if ip_lines else ""), encoding="utf-8"
    )
    return suggest_path, ip_path


def export_page_scrapes_csv(
    scrapes: list[dict[str, Any]],
    out_dir: str | Path,
) -> Path:
    """完整清單 CSV（UTF-8 BOM，Excel 可直接開啟）。"""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / SCRAPE_CSV_FILENAME
    with out_path.open("w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(
            ["IP", "目標頁面", "次數", "開始時間", "結束時間", "參數種數", "其餘瀏覽參數"]
        )
        for s in scrapes:
            queries = s.get("queries") or []
            top = "、".join(f"{q['query']}×{q['count']}" for q in queries)
            query_count = int(s.get("queryCount", 0) or 0)
            if query_count > len(queries):
                top += f" 等 {query_count} 種"
            writer.writerow(
                [
                    s.get("ip", ""),
                    s.get("url", ""),
                    int(s.get("count", 0)),
                    s.get("startStr", ""),
                    s.get("endStr", ""),
                    query_count,
                    top,
                ]
            )
    return out_path
