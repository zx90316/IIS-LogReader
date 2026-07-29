"""統計與異常分析報告：Markdown / HTML / PDF 匯出。"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def build_markdown_report(
    stats: dict[str, Any],
    meta: dict[str, Any] | None = None,
    thresholds: dict[str, Any] | None = None,
) -> str:
    """從統計結果產生完整 Markdown 報告。"""
    lines: list[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append("# IIS Log 分析報告")
    lines.append("")
    lines.append(f"產生時間：{now}")
    lines.append("")

    if meta:
        lines.append("## 資料來源")
        lines.append("")
        if meta.get("source_files"):
            for sf in meta["source_files"]:
                lines.append(f"- {sf}")
        if meta.get("time_range"):
            lines.append("")
            lines.append(f"時間範圍：{meta['time_range']}")
        if meta.get("filter_summary"):
            lines.append("")
            lines.append(f"已套用過濾規則：{meta['filter_summary']}")
        lines.append("")

    total = stats.get("total", 0)
    lines.append("## 總覽")
    lines.append("")
    lines.append(f"- 過濾後總筆數：**{total:,}**")
    lines.append("")

    if thresholds:
        lines.append("## 偵測閾值設定")
        lines.append("")
        lines.append("| 參數 | 值 |")
        lines.append("|------|-----|")
        labels = {
            "high_freq_std_mult": "高頻 IP 標準差倍數",
            "burst_count": "爆量請求次數",
            "burst_window_ms": "爆量偵測視窗 (ms)",
            "slow_ms": "慢請求門檻 (ms)",
            "off_hour_start": "離峰起始 (時)",
            "off_hour_end": "離峰結束 (時)",
            "error_status_min": "錯誤狀態碼下限",
            "page_scrape_count": "同頁面抓取次數門檻 (每日)",
            "page_scrape_min_span_min": "同頁面抓取最小持續 (分)",
        }
        for k, label in labels.items():
            v = thresholds.get(k, "")
            lines.append(f"| {label} | {v} |")
        lines.append("")

    top_ips = stats.get("topIPs", [])
    if top_ips:
        lines.append(f"## Top {len(top_ips)} 來源 IP")
        lines.append("")
        lines.append("| IP | 請求數 |")
        lines.append("|-----|--------|")
        for item in top_ips:
            lines.append(f"| {item['ip']} | {item['count']:,} |")
        lines.append("")

    top_urls = stats.get("topURLs", [])
    if top_urls:
        lines.append(f"## Top {len(top_urls)} URL")
        lines.append("")
        lines.append("| URI | 請求數 |")
        lines.append("|------|--------|")
        for item in top_urls:
            lines.append(f"| {item['url']} | {item['count']:,} |")
        lines.append("")

    hours = stats.get("hourCountMap", [])
    if hours and any(h > 0 for h in hours):
        lines.append("## 每小時請求分布（台北時間）")
        lines.append("")
        lines.append("| 時段 | 請求數 |")
        lines.append("|------|--------|")
        for h, count in enumerate(hours):
            mark = " ⚠️" if 0 <= h < 7 and count > 0 else ""
            lines.append(f"| {h:02d}:00 | {count:,}{mark} |")
        lines.append("")

    status_list = stats.get("statusList", [])
    if status_list:
        lines.append("## 狀態碼分布")
        lines.append("")
        lines.append("| 狀態碼 | 次數 | 比例 |")
        lines.append("|--------|------|------|")
        for item in status_list:
            pct = f"{item['count'] / total * 100:.1f}%" if total > 0 else "0%"
            lines.append(f"| {item['status']} | {item['count']:,} | {pct} |")
        lines.append("")

    anomalies = stats.get("anomalies", {})
    lines.append("## 異常偵測")
    lines.append("")

    hf = anomalies.get("highFreqIPs", [])
    k = thresholds.get("high_freq_std_mult", 2) if thresholds else 2
    lines.append(f"### 高頻存取 IP（超過 mean + {k}×std）")
    lines.append("")
    if hf:
        lines.append("| IP | 請求數 | 閾值 |")
        lines.append("|-----|--------|------|")
        for item in hf:
            lines.append(
                f"| {item['ip']} | {item['count']:,} | {item.get('threshold', '-')} |"
            )
    else:
        lines.append("未偵測到異常高頻 IP。")
    lines.append("")

    bursts = anomalies.get("bursts", [])
    bc = thresholds.get("burst_count", 60) if thresholds else 60
    bw = thresholds.get("burst_window_ms", 60000) if thresholds else 60000
    lines.append(f"### 爆量請求（同 IP {bw / 1000:.0f} 秒內 ≥ {bc} 次）")
    lines.append("")
    if bursts:
        lines.append("| IP | 開始 | 結束 | 次數 | 視窗(秒) |")
        lines.append("|-----|------|------|------|----------|")
        for b in bursts:
            lines.append(
                f"| {b['ip']} | {b['startStr']} | {b['endStr']} | "
                f"{b['count']} | {b['windowSec']} |"
            )
    else:
        lines.append("未偵測到短時間爆量請求。")
    lines.append("")

    scrapes = anomalies.get("pageScrapes", [])
    scrape_count = anomalies.get("pageScrapesCount", len(scrapes))
    psc = thresholds.get("page_scrape_count", 100) if thresholds else 100
    lines.append(f"### 同頁面大量抓取（同 IP 每日對同頁面 ≥ {psc} 次）")
    lines.append("")
    if scrapes:
        lines.append(f"共偵測到 {scrape_count} 組 IP＋頁面＋日期組合。前 15 組：")
        lines.append("")
        lines.append("| IP | 目標頁面 | 日期 | 次數 | 開始 | 結束 | 其餘瀏覽參數 |")
        lines.append("|-----|----------|------|------|------|------|--------------|")
        for s in scrapes[:15]:
            if s.get("queries"):
                q_desc = ", ".join(
                    f"{q['query']} ({q['count']})" for q in s["queries"]
                )
                if s.get("queryCount", 0) > len(s["queries"]):
                    q_desc += f" 等 {s['queryCount']} 種"
            else:
                q_desc = "-"
            url_cell = str(s["url"])[:60].replace("|", "\\|")
            q_cell = q_desc[:80].replace("|", "\\|")
            day = str(s.get("day") or "-")
            start_t = str(s["startStr"])[11:] if day != "-" else s["startStr"]
            end_t = str(s["endStr"])[11:] if day != "-" else s["endStr"]
            lines.append(
                f"| {s['ip']} | {url_cell} | {day} | {s['count']:,} | "
                f"{start_t} | {end_t} | {q_cell} |"
            )
    else:
        lines.append("未偵測到同 IP 每日大量抓取同頁面。")
    lines.append("")

    sus = anomalies.get("susUA", [])
    sus_count = anomalies.get("susUACount", len(sus))
    lines.append("### 可疑 User-Agent（掃描工具特徵）")
    lines.append("")
    if sus:
        ua_counts: dict[str, int] = {}
        for item in sus:
            ua = item.get("cs(User-Agent)", "")
            if not ua:
                continue
            if "count" in item:
                ua_counts[ua] = int(item["count"])
            else:
                ua_counts[ua] = ua_counts.get(ua, 0) + 1
        sorted_ua = sorted(ua_counts.items(), key=lambda x: -x[1])[:15]
        lines.append(f"共偵測到 {sus_count} 筆可疑 UA 請求。")
        lines.append("")
        lines.append("| User-Agent | 出現次數 |")
        lines.append("|------------|----------|")
        for ua, cnt in sorted_ua:
            lines.append(f"| {ua[:80]} | {cnt} |")
    else:
        lines.append("未偵測到可疑掃描特徵。")
    lines.append("")

    slow = anomalies.get("slowReqs", [])
    slow_count = anomalies.get("slowReqsCount", len(slow))
    slow_ms = thresholds.get("slow_ms", 10000) if thresholds else 10000
    lines.append(f"### 慢請求（time-taken > {slow_ms}ms）")
    lines.append("")
    if slow:
        lines.append(f"共 {slow_count} 筆。前 15 筆：")
        lines.append("")
        lines.append("| 時間 | IP | URI | 耗時(ms) |")
        lines.append("|------|-----|------|----------|")
        sorted_slow = sorted(slow, key=lambda x: -(x.get("time-taken", 0)))[:15]
        for s in sorted_slow:
            lines.append(
                f"| {s.get('datetimeStr', '-')} | {s.get('c-ip', '-')} | "
                f"{s.get('cs-uri-stem', '-')[:60]} | {s.get('time-taken', 0):,} |"
            )
    else:
        lines.append(f"無超過 {slow_ms}ms 的慢請求。")
    lines.append("")

    err = anomalies.get("errorStatus", [])
    err_count = anomalies.get("errorStatusCount", len(err))
    lines.append("### 錯誤狀態碼（4xx / 5xx）")
    lines.append("")
    if err:
        status_agg: dict[int, int] = {}
        ip_agg: dict[str, int] = {}
        for item in err:
            st = item.get("sc-status", 0)
            status_agg[st] = status_agg.get(st, 0) + 1
            ip = item.get("c-ip", "")
            ip_agg[ip] = ip_agg.get(ip, 0) + 1
        lines.append(f"共 {err_count} 筆錯誤。")
        lines.append("")
        lines.append("**錯誤代碼分布：**")
        lines.append("")
        lines.append("| 狀態碼 | 次數 |")
        lines.append("|--------|------|")
        for st, cnt in sorted(status_agg.items()):
            lines.append(f"| {st} | {cnt} |")
        lines.append("")
        lines.append("**錯誤來源 IP Top 5：**")
        lines.append("")
        lines.append("| IP | 次數 |")
        lines.append("|-----|------|")
        for ip, cnt in sorted(ip_agg.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"| {ip} | {cnt} |")
    else:
        lines.append("無 4xx 或 5xx 錯誤記錄。")
    lines.append("")

    lines.append("---")
    lines.append("*本報告由 IIS Log 分析工具自動產生*")
    return "\n".join(lines)


def build_html_report(
    stats: dict[str, Any],
    meta: dict[str, Any] | None = None,
    thresholds: dict[str, Any] | None = None,
) -> str:
    """
    產生適合轉 PDF 的 HTML。
    以 section.page 標記主要區塊，並用 CSS page-break 控制換頁時機。
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = int(stats.get("total", 0))
    thresholds = thresholds or {}
    meta = meta or {}
    anomalies = stats.get("anomalies", {})

    parts: list[str] = []
    parts.append(
        f"""<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8"/>
<title>IIS Log 分析報告</title>
<style>
  @page {{
    size: A4;
    margin: 18mm 16mm 18mm 16mm;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: "Microsoft JhengHei", "微軟正黑體", "Noto Sans TC", sans-serif;
    font-size: 11pt;
    color: #1e293b;
    line-height: 1.45;
  }}
  h1 {{ font-size: 22pt; margin: 0 0 8px 0; color: #0f172a; }}
  h2 {{
    font-size: 15pt;
    margin: 0 0 12px 0;
    padding-bottom: 6px;
    border-bottom: 2px solid #334155;
    color: #0f172a;
  }}
  h3 {{ font-size: 12pt; margin: 16px 0 8px 0; color: #1e293b; }}
  .meta {{ color: #64748b; margin-bottom: 16px; }}
  .section {{
    page-break-inside: avoid;
    break-inside: avoid;
    margin-bottom: 18px;
  }}
  /* 主要章節強制換頁（封面總覽後開始） */
  .page-break {{
    page-break-before: always;
    break-before: page;
  }}
  /* 表格列盡量不跨頁切斷 */
  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 8px 0 12px 0;
    font-size: 10pt;
  }}
  th, td {{
    border: 1px solid #cbd5e1;
    padding: 5px 8px;
    text-align: left;
    vertical-align: top;
  }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  tr {{ page-break-inside: avoid; break-inside: avoid; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .muted {{ color: #64748b; }}
  .badge {{
    display: inline-block;
    background: #e2e8f0;
    border-radius: 4px;
    padding: 1px 6px;
    font-size: 9pt;
  }}
  ul {{ margin: 6px 0 12px 18px; padding: 0; }}
  .footer {{
    margin-top: 24px;
    color: #94a3b8;
    font-size: 9pt;
    border-top: 1px solid #e2e8f0;
    padding-top: 8px;
  }}
  .warn {{ color: #b45309; }}
</style>
</head>
<body>
"""
    )

    # --- 第 1 頁：封面 / 總覽 / 閾值 ---
    parts.append('<div class="section">')
    parts.append("<h1>IIS Log 分析報告</h1>")
    parts.append(f'<div class="meta">產生時間：{_esc(now)}</div>')

    if meta.get("source_files") or meta.get("filter_summary") or meta.get("time_range"):
        parts.append("<h2>資料來源</h2>")
        if meta.get("source_files"):
            parts.append("<ul>")
            for sf in meta["source_files"]:
                parts.append(f"<li>{_esc(sf)}</li>")
            parts.append("</ul>")
        if meta.get("time_range"):
            parts.append(f"<p>時間範圍：{_esc(meta['time_range'])}</p>")
        if meta.get("filter_summary"):
            parts.append(f"<p>已套用過濾規則：{_esc(meta['filter_summary'])}</p>")

    parts.append("<h2>總覽</h2>")
    parts.append(f"<p>過濾後總筆數：<strong>{total:,}</strong></p>")

    if thresholds:
        parts.append("<h2>偵測閾值設定</h2>")
        parts.append("<table><thead><tr><th>參數</th><th>值</th></tr></thead><tbody>")
        labels = [
            ("high_freq_std_mult", "高頻 IP 標準差倍數"),
            ("burst_count", "爆量請求次數"),
            ("burst_window_ms", "爆量偵測視窗 (ms)"),
            ("slow_ms", "慢請求門檻 (ms)"),
            ("off_hour_start", "離峰起始 (時)"),
            ("off_hour_end", "離峰結束 (時)"),
            ("error_status_min", "錯誤狀態碼下限"),
            ("page_scrape_count", "同頁面抓取次數門檻 (每日)"),
            ("page_scrape_min_span_min", "同頁面抓取最小持續 (分)"),
        ]
        for key, label in labels:
            parts.append(
                f"<tr><td>{_esc(label)}</td><td class='num'>{_esc(thresholds.get(key, ''))}</td></tr>"
            )
        parts.append("</tbody></table>")
    parts.append("</div>")

    # --- Top IP（換頁）---
    top_ips = stats.get("topIPs", [])
    if top_ips:
        parts.append('<div class="section page-break">')
        parts.append(f"<h2>來源 IP 排行（共 {len(top_ips)} 筆）</h2>")
        parts.append("<table><thead><tr><th>IP</th><th class='num'>請求數</th></tr></thead><tbody>")
        for item in top_ips:
            parts.append(
                f"<tr><td>{_esc(item.get('ip'))}</td>"
                f"<td class='num'>{int(item.get('count', 0)):,}</td></tr>"
            )
        parts.append("</tbody></table></div>")

    # --- Top URL（換頁）---
    top_urls = stats.get("topURLs", [])
    if top_urls:
        parts.append('<div class="section page-break">')
        parts.append(f"<h2>URL 排行（共 {len(top_urls)} 筆）</h2>")
        parts.append("<table><thead><tr><th>URI</th><th class='num'>請求數</th></tr></thead><tbody>")
        for item in top_urls:
            parts.append(
                f"<tr><td>{_esc(item.get('url'))}</td>"
                f"<td class='num'>{int(item.get('count', 0)):,}</td></tr>"
            )
        parts.append("</tbody></table></div>")

    # --- 時段 + 狀態碼（換頁，同頁可共存）---
    hours = stats.get("hourCountMap", [])
    status_list = stats.get("statusList", [])
    if (hours and any(h > 0 for h in hours)) or status_list:
        parts.append('<div class="section page-break">')
        if hours and any(h > 0 for h in hours):
            parts.append("<h2>每小時請求分布（台北時間）</h2>")
            parts.append(
                "<table><thead><tr><th>時段</th><th class='num'>請求數</th>"
                "<th>備註</th></tr></thead><tbody>"
            )
            for h, count in enumerate(hours):
                note = '<span class="warn">離峰</span>' if 0 <= h < 7 and count > 0 else ""
                parts.append(
                    f"<tr><td>{h:02d}:00</td><td class='num'>{count:,}</td>"
                    f"<td>{note}</td></tr>"
                )
            parts.append("</tbody></table>")

        if status_list:
            parts.append("<h2>狀態碼分布</h2>")
            parts.append(
                "<table><thead><tr><th>狀態碼</th><th class='num'>次數</th>"
                "<th class='num'>比例</th></tr></thead><tbody>"
            )
            for item in status_list:
                cnt = int(item.get("count", 0))
                pct = f"{cnt / total * 100:.1f}%" if total > 0 else "0%"
                parts.append(
                    f"<tr><td>{_esc(item.get('status'))}</td>"
                    f"<td class='num'>{cnt:,}</td><td class='num'>{pct}</td></tr>"
                )
            parts.append("</tbody></table>")
        parts.append("</div>")

    # --- 異常偵測：各區塊獨立換頁判斷 ---
    parts.append('<div class="section page-break">')
    parts.append("<h2>異常偵測</h2>")

    # 高頻 IP
    hf = anomalies.get("highFreqIPs", [])
    k = thresholds.get("high_freq_std_mult", 2)
    parts.append(f"<h3>高頻存取 IP（超過 mean + {_esc(k)}×std）</h3>")
    if hf:
        parts.append(
            "<table><thead><tr><th>IP</th><th class='num'>請求數</th>"
            "<th class='num'>閾值</th></tr></thead><tbody>"
        )
        for item in hf:
            parts.append(
                f"<tr><td>{_esc(item.get('ip'))}</td>"
                f"<td class='num'>{int(item.get('count', 0)):,}</td>"
                f"<td class='num'>{_esc(item.get('threshold', '-'))}</td></tr>"
            )
        parts.append("</tbody></table>")
    else:
        parts.append('<p class="muted">未偵測到異常高頻 IP。</p>')

    # 爆量 — 資料多時另起一頁
    bursts = anomalies.get("bursts", [])
    bc = thresholds.get("burst_count", 60)
    bw = thresholds.get("burst_window_ms", 60000)
    burst_cls = "section page-break" if len(bursts) > 8 else "section"
    parts.append(f'<div class="{burst_cls}">')
    parts.append(
        f"<h3>爆量請求（同 IP {float(bw) / 1000:.0f} 秒內 ≥ {int(bc)} 次）</h3>"
    )
    if bursts:
        parts.append(
            "<table><thead><tr><th>IP</th><th>開始</th><th>結束</th>"
            "<th class='num'>次數</th><th class='num'>視窗(秒)</th></tr></thead><tbody>"
        )
        for b in bursts:
            parts.append(
                f"<tr><td>{_esc(b.get('ip'))}</td><td>{_esc(b.get('startStr'))}</td>"
                f"<td>{_esc(b.get('endStr'))}</td>"
                f"<td class='num'>{_esc(b.get('count'))}</td>"
                f"<td class='num'>{_esc(b.get('windowSec'))}</td></tr>"
            )
        parts.append("</tbody></table>")
    else:
        parts.append('<p class="muted">未偵測到短時間爆量請求。</p>')
    parts.append("</div>")

    # 同頁面大量抓取
    scrapes = anomalies.get("pageScrapes", [])
    scrape_count = anomalies.get("pageScrapesCount", len(scrapes))
    psc = thresholds.get("page_scrape_count", 100)
    scrape_cls = "section page-break" if len(scrapes) > 8 else "section"
    parts.append(f'<div class="{scrape_cls}">')
    parts.append(
        f"<h3>同頁面大量抓取（同 IP 每日對同頁面 ≥ {int(psc)} 次）</h3>"
    )
    if scrapes:
        parts.append(
            f"<p>共偵測到 <strong>{scrape_count}</strong> 組 IP＋頁面＋日期組合。前 15 組：</p>"
        )
        parts.append(
            "<table><thead><tr><th>IP</th><th>目標頁面</th><th>日期</th>"
            "<th class='num'>次數</th><th>開始</th><th>結束</th>"
            "<th>其餘瀏覽參數</th></tr></thead><tbody>"
        )
        for s in scrapes[:15]:
            if s.get("queries"):
                q_desc = ", ".join(
                    f"{q['query']} ({q['count']})" for q in s["queries"]
                )
                if s.get("queryCount", 0) > len(s["queries"]):
                    q_desc += f" 等 {s['queryCount']} 種"
            else:
                q_desc = "-"
            day = str(s.get("day") or "-")
            start_t = str(s.get("startStr", ""))[11:] if day != "-" else s.get("startStr", "-")
            end_t = str(s.get("endStr", ""))[11:] if day != "-" else s.get("endStr", "-")
            parts.append(
                f"<tr><td>{_esc(s.get('ip'))}</td>"
                f"<td>{_esc(str(s.get('url', ''))[:70])}</td>"
                f"<td>{_esc(day)}</td>"
                f"<td class='num'>{int(s.get('count', 0)):,}</td>"
                f"<td>{_esc(start_t)}</td>"
                f"<td>{_esc(end_t)}</td>"
                f"<td>{_esc(q_desc[:100])}</td></tr>"
            )
        parts.append("</tbody></table>")
    else:
        parts.append('<p class="muted">未偵測到同 IP 每日大量抓取同頁面。</p>')
    parts.append("</div>")

    # 可疑 UA
    sus = anomalies.get("susUA", [])
    sus_count = anomalies.get("susUACount", len(sus))
    parts.append('<div class="section">')
    parts.append("<h3>可疑 User-Agent（掃描工具特徵）</h3>")
    if sus:
        ua_counts: dict[str, int] = {}
        for item in sus:
            ua = item.get("cs(User-Agent)", "")
            if not ua:
                continue
            if "count" in item:
                ua_counts[ua] = int(item["count"])
            else:
                ua_counts[ua] = ua_counts.get(ua, 0) + 1
        sorted_ua = sorted(ua_counts.items(), key=lambda x: -x[1])[:15]
        parts.append(f"<p>共偵測到 <strong>{sus_count}</strong> 筆可疑 UA 請求。</p>")
        parts.append(
            "<table><thead><tr><th>User-Agent</th>"
            "<th class='num'>出現次數</th></tr></thead><tbody>"
        )
        for ua, cnt in sorted_ua:
            parts.append(
                f"<tr><td>{_esc(ua[:100])}</td><td class='num'>{cnt}</td></tr>"
            )
        parts.append("</tbody></table>")
    else:
        parts.append('<p class="muted">未偵測到可疑掃描特徵。</p>')
    parts.append("</div>")

    # 慢請求 — 明細較多時換頁
    slow = anomalies.get("slowReqs", [])
    slow_count = anomalies.get("slowReqsCount", len(slow))
    slow_ms = thresholds.get("slow_ms", 10000)
    slow_cls = "section page-break" if slow else "section"
    parts.append(f'<div class="{slow_cls}">')
    parts.append(f"<h3>慢請求（time-taken &gt; {int(slow_ms)}ms）</h3>")
    if slow:
        parts.append(f"<p>共 <strong>{slow_count}</strong> 筆。前 15 筆：</p>")
        parts.append(
            "<table><thead><tr><th>時間</th><th>IP</th><th>URI</th>"
            "<th class='num'>耗時(ms)</th></tr></thead><tbody>"
        )
        sorted_slow = sorted(slow, key=lambda x: -(x.get("time-taken", 0)))[:15]
        for s in sorted_slow:
            uri = str(s.get("cs-uri-stem", "-"))[:70]
            parts.append(
                f"<tr><td>{_esc(s.get('datetimeStr', '-'))}</td>"
                f"<td>{_esc(s.get('c-ip', '-'))}</td><td>{_esc(uri)}</td>"
                f"<td class='num'>{int(s.get('time-taken', 0)):,}</td></tr>"
            )
        parts.append("</tbody></table>")
    else:
        parts.append(f'<p class="muted">無超過 {int(slow_ms)}ms 的慢請求。</p>')
    parts.append("</div>")

    # 錯誤狀態碼
    err = anomalies.get("errorStatus", [])
    err_count = anomalies.get("errorStatusCount", len(err))
    err_cls = "section page-break" if err else "section"
    parts.append(f'<div class="{err_cls}">')
    parts.append("<h3>錯誤狀態碼（4xx / 5xx）</h3>")
    if err:
        status_agg: dict[int, int] = {}
        ip_agg: dict[str, int] = {}
        for item in err:
            st = item.get("sc-status", 0)
            status_agg[st] = status_agg.get(st, 0) + 1
            ip = item.get("c-ip", "")
            ip_agg[ip] = ip_agg.get(ip, 0) + 1
        parts.append(f"<p>共 <strong>{err_count}</strong> 筆錯誤。</p>")
        parts.append("<h3>錯誤代碼分布</h3>")
        parts.append(
            "<table><thead><tr><th>狀態碼</th><th class='num'>次數</th></tr></thead><tbody>"
        )
        for st, cnt in sorted(status_agg.items()):
            parts.append(f"<tr><td>{_esc(st)}</td><td class='num'>{cnt}</td></tr>")
        parts.append("</tbody></table>")
        parts.append("<h3>錯誤來源 IP Top 5</h3>")
        parts.append(
            "<table><thead><tr><th>IP</th><th class='num'>次數</th></tr></thead><tbody>"
        )
        for ip, cnt in sorted(ip_agg.items(), key=lambda x: -x[1])[:5]:
            parts.append(f"<tr><td>{_esc(ip)}</td><td class='num'>{cnt}</td></tr>")
        parts.append("</tbody></table>")
    else:
        parts.append('<p class="muted">無 4xx 或 5xx 錯誤記錄。</p>')
    parts.append("</div>")

    parts.append("</div>")  # end 異常偵測 wrapper

    parts.append(
        '<div class="footer">本報告由 IIS Log 分析工具自動產生'
        "（HTML → PDF，含章節換頁控制）</div>"
    )
    parts.append("</body></html>")
    return "".join(parts)


def html_to_pdf(html_content: str, pdf_path: str | Path) -> None:
    """
    將 HTML 轉成 PDF。
    流程：寫入 HTML → QPdfWriter + QTextDocument 輸出。

    注意：不可用 QPrinter(HighResolution) 的 DevicePixel 當 document pageSize，
    否則內容會縮在左上角一小塊（高 DPI 頁面座標與 HTML pt/px 不一致）。
    """
    from PySide6.QtCore import QMarginsF, QSizeF
    from PySide6.QtGui import (
        QFont,
        QPageLayout,
        QPageSize,
        QPdfWriter,
        QTextDocument,
    )

    pdf_path = Path(pdf_path)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    # 先落地 HTML，方便除錯與符合「先產生 HTML 再轉 PDF」流程
    html_side = pdf_path.with_suffix(".html")
    html_side.write_text(html_content, encoding="utf-8")

    # 72 DPI：1pt ≈ 1 device unit，與 HTML/CSS 字級對齊，版面才會鋪滿 A4
    dpi = 72
    writer = QPdfWriter(str(pdf_path))
    writer.setTitle("IIS Log 分析報告")
    writer.setResolution(dpi)
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    writer.setPageMargins(
        QMarginsF(5, 5, 5, 5), QPageLayout.Unit.Millimeter
    )

    # 可繪製區域（扣除邊界）作為文件頁面大小
    paint_rect = writer.pageLayout().paintRectPixels(dpi)
    page_size = QSizeF(paint_rect.size())

    doc = QTextDocument()
    doc.setDocumentMargin(0)
    doc.setDefaultFont(QFont("Microsoft JhengHei", 10))
    doc.setPageSize(page_size)
    doc.setHtml(html_content)
    # 確保文字寬度跟著頁寬走（避免仍用預設窄寬度排版）
    doc.setTextWidth(page_size.width())
    doc.print_(writer)


def export_report(
    stats: dict[str, Any],
    path: str | Path,
    meta: dict[str, Any] | None = None,
    thresholds: dict[str, Any] | None = None,
) -> Path:
    """依副檔名匯出 md / html / pdf。"""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        html_content = build_html_report(stats, meta, thresholds)
        html_to_pdf(html_content, path)
    elif suffix in (".html", ".htm"):
        path.write_text(build_html_report(stats, meta, thresholds), encoding="utf-8")
    else:
        if suffix != ".md":
            path = path.with_suffix(".md")
        path.write_text(build_markdown_report(stats, meta, thresholds), encoding="utf-8")
    return path
