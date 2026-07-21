"""統計與異常偵測：過濾結果物化一次，其餘走 SQL 聚合（避免重複全表掃描）。"""

from __future__ import annotations

import math
from collections import deque
from datetime import datetime, timezone, tzinfo
from typing import Any, Sequence

from .constants import KNOWN_SCANNER_UA_KEYWORDS
from .database import LogDatabase
from .timezone_util import get_tz

DETAIL_LIMIT = 50
BURST_CANDIDATE_LIMIT = 30
SRC = "_stats_src"
IP_COUNTS = "_ip_counts"


def compute_stats(
    db: LogDatabase,
    filter_rules: Sequence[dict[str, Any]] | None = None,
    column_filters: dict[str, str] | None = None,
    time_start_ms: int | None = None,
    time_end_ms: int | None = None,
    tz_name: str = "Asia/Taipei",
    thresholds: dict[str, Any] | None = None,
    progress: Any | None = None,
) -> dict[str, Any] | None:
    """對目前篩選條件計算完整統計與異常。無資料時回傳 None。"""
    th = thresholds or {}
    std_mult = float(th.get("high_freq_std_mult", 2.0))
    burst_count = int(th.get("burst_count", 60))
    burst_window_ms = int(th.get("burst_window_ms", 60000))
    slow_ms = int(th.get("slow_ms", 10000))
    off_start = int(th.get("off_hour_start", 0))
    off_end = int(th.get("off_hour_end", 7))
    err_min = int(th.get("error_status_min", 400))
    scanner_kw_raw = th.get("scanner_ua_keywords", "")
    if scanner_kw_raw and isinstance(scanner_kw_raw, str):
        keywords = [k.strip().lower() for k in scanner_kw_raw.split(",") if k.strip()]
    else:
        keywords = [k.lower() for k in KNOWN_SCANNER_UA_KEYWORDS]

    def _prog(msg: str) -> None:
        if progress:
            progress(msg)

    where, params = db.build_where(
        filter_rules, column_filters, time_start_ms, time_end_ms
    )
    conn = db.conn

    try:
        _prog("套用過濾條件（建立暫存資料）…")
        _materialize(conn, where, params)

        total = int(conn.execute(f"SELECT COUNT(*) FROM {SRC}").fetchone()[0])
        if total <= 0:
            return None

        _prog("聚合 IP / URL / 狀態碼…")
        conn.execute(f"DROP TABLE IF EXISTS temp.{IP_COUNTS}")
        conn.execute(
            f"""
            CREATE TEMP TABLE {IP_COUNTS} AS
            SELECT c_ip, COUNT(*) AS cnt FROM {SRC}
            WHERE c_ip IS NOT NULL AND c_ip != '-'
            GROUP BY c_ip
            """
        )

        top_ips_list = [
            {"ip": r["c_ip"], "count": r["cnt"]}
            for r in conn.execute(
                f"SELECT c_ip, cnt FROM {IP_COUNTS} ORDER BY cnt DESC LIMIT 20"
            ).fetchall()
        ]
        top_urls_list = [
            {"url": r["url"], "count": r["cnt"]}
            for r in conn.execute(
                f"""
                SELECT cs_uri_stem AS url, COUNT(*) AS cnt FROM {SRC}
                WHERE cs_uri_stem IS NOT NULL AND cs_uri_stem != '-'
                GROUP BY cs_uri_stem ORDER BY cnt DESC LIMIT 30
                """
            ).fetchall()
        ]
        status_list = [
            {"status": int(r["status"] or 0), "count": r["cnt"]}
            for r in conn.execute(
                f"SELECT sc_status AS status, COUNT(*) AS cnt FROM {SRC} "
                f"GROUP BY sc_status ORDER BY sc_status ASC"
            ).fetchall()
        ]
        hour_count_map = [0] * 24
        for r in conn.execute(
            f"SELECT hour, COUNT(*) AS cnt FROM {SRC} "
            f"WHERE hour >= 0 AND hour <= 23 GROUP BY hour"
        ).fetchall():
            h = int(r["hour"])
            if 0 <= h <= 23:
                hour_count_map[h] = r["cnt"]

        _prog("偵測異常（慢請求 / 錯誤 / 可疑 UA / 爆量）…")
        high_freq = _high_freq_from_ip_counts(conn, std_mult, top_ips_list)
        anomalies = _anomalies_from_src(
            conn,
            tz_name,
            keywords,
            slow_ms,
            off_start,
            off_end,
            err_min,
            burst_count,
            burst_window_ms,
            status_list,
        )
        anomalies["highFreqIPs"] = high_freq

        return {
            "total": total,
            "topIPs": top_ips_list,
            "topURLs": top_urls_list,
            "statusList": status_list,
            "hourCountMap": hour_count_map,
            "anomalies": anomalies,
        }
    finally:
        _cleanup(conn)


def _materialize(conn, where: str, params: list) -> None:
    """把昂貴的黑名單 WHERE 只算一次，後續聚合吃暫存表。"""
    conn.execute(f"DROP TABLE IF EXISTS temp.{SRC}")
    conn.execute(
        f"""
        CREATE TEMP TABLE {SRC} AS
        SELECT timestamp, datetime_str, hour, c_ip, cs_uri_stem,
               cs_user_agent, sc_status, time_taken
        FROM logs {where}
        """,
        params,
    )
    # 爆量查詢需要 (c_ip, timestamp) 才能邊掃邊提早結束
    conn.execute(
        f"CREATE INDEX IF NOT EXISTS idx_{SRC}_ip_ts ON {SRC}(c_ip, timestamp)"
    )


def _cleanup(conn) -> None:
    try:
        conn.execute(f"DROP TABLE IF EXISTS temp.{SRC}")
        conn.execute(f"DROP TABLE IF EXISTS temp.{IP_COUNTS}")
    except Exception:
        pass


def _high_freq_from_ip_counts(
    conn,
    std_mult: float,
    top_ips_list: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    row = conn.execute(
        f"SELECT COUNT(*) AS n, AVG(cnt) AS mean, AVG(cnt * cnt) AS mean_sq "
        f"FROM {IP_COUNTS}"
    ).fetchone()
    if not row or not row["n"] or row["n"] < 2:
        return []
    mean = float(row["mean"] or 0)
    mean_sq = float(row["mean_sq"] or 0)
    variance = max(0.0, mean_sq - mean * mean)
    std_dev = math.sqrt(variance)
    if std_dev <= 0:
        return []
    threshold_val = mean + std_mult * std_dev
    return [
        {**item, "threshold": int(threshold_val)}
        for item in top_ips_list
        if item["count"] > threshold_val
    ]


def _anomalies_from_src(
    conn,
    tz_name: str,
    keywords: list[str],
    slow_ms: int,
    off_start: int,
    off_end: int,
    err_min: int,
    burst_count: int,
    burst_window_ms: int,
    status_list: list[dict[str, Any]],
) -> dict[str, Any]:
    tz = get_tz(tz_name)

    # 離峰
    off_count = int(
        conn.execute(
            f"SELECT COUNT(*) FROM {SRC} "
            f"WHERE hour >= ? AND hour < ? AND IFNULL(c_ip,'') != '::1'",
            (off_start, off_end),
        ).fetchone()[0]
    )
    off_hours = [
        {
            "datetimeStr": r["datetime_str"] or "-",
            "c-ip": r["c_ip"] or "",
            "cs-uri-stem": r["cs_uri_stem"] or "",
            "hour": r["hour"],
        }
        for r in conn.execute(
            f"SELECT datetime_str, c_ip, cs_uri_stem, hour FROM {SRC} "
            f"WHERE hour >= ? AND hour < ? AND IFNULL(c_ip,'') != '::1' "
            f"ORDER BY timestamp ASC LIMIT {DETAIL_LIMIT}",
            (off_start, off_end),
        ).fetchall()
    ]

    # 錯誤：由狀態碼聚合加總，省一次 COUNT
    err_count = sum(
        s["count"] for s in status_list if s["status"] >= err_min
    )
    error_status = [
        {
            "datetimeStr": r["datetime_str"] or "-",
            "c-ip": r["c_ip"] or "",
            "cs-uri-stem": r["cs_uri_stem"] or "",
            "sc-status": int(r["sc_status"] or 0),
        }
        for r in conn.execute(
            f"SELECT datetime_str, c_ip, cs_uri_stem, sc_status FROM {SRC} "
            f"WHERE sc_status >= ? "
            f"ORDER BY sc_status DESC, timestamp DESC LIMIT {DETAIL_LIMIT}",
            (err_min,),
        ).fetchall()
    ]

    # 慢請求
    slow_count = int(
        conn.execute(
            f"SELECT COUNT(*) FROM {SRC} WHERE time_taken > ?", (slow_ms,)
        ).fetchone()[0]
    )
    slow_reqs = [
        {
            "datetimeStr": r["datetime_str"] or "-",
            "c-ip": r["c_ip"] or "",
            "cs-uri-stem": r["cs_uri_stem"] or "",
            "time-taken": int(r["time_taken"] or 0),
        }
        for r in conn.execute(
            f"SELECT datetime_str, c_ip, cs_uri_stem, time_taken FROM {SRC} "
            f"WHERE time_taken > ? ORDER BY time_taken DESC LIMIT {DETAIL_LIMIT}",
            (slow_ms,),
        ).fetchall()
    ]

    sus_count, sus_ua = _suspicious_ua_from_groupby(conn, keywords)
    bursts = _detect_bursts_early_exit(
        conn, tz, burst_count, burst_window_ms
    )

    return {
        "highFreqIPs": [],
        "offHours": off_hours,
        "offHoursCount": off_count,
        "errorStatus": error_status,
        "errorStatusCount": err_count,
        "slowReqs": slow_reqs,
        "slowReqsCount": slow_count,
        "susUA": sus_ua,
        "susUACount": sus_count,
        "bursts": bursts,
    }


def _suspicious_ua_from_groupby(
    conn, keywords: list[str]
) -> tuple[int, list[dict[str, Any]]]:
    """先 GROUP BY UA（約數千種），再在 Python 比對關鍵字 — 比全表 LIKE OR 快。"""
    if not keywords:
        return 0, []
    rows = conn.execute(
        f"""
        SELECT cs_user_agent AS ua, COUNT(*) AS cnt FROM {SRC}
        WHERE cs_user_agent IS NOT NULL AND cs_user_agent != '-'
        GROUP BY cs_user_agent
        """
    ).fetchall()
    hits: list[tuple[str, int]] = []
    total = 0
    for r in rows:
        ua = r["ua"] or ""
        ua_l = ua.lower()
        if any(kw in ua_l for kw in keywords):
            cnt = int(r["cnt"])
            hits.append((ua, cnt))
            total += cnt
    hits.sort(key=lambda x: -x[1])
    sus_ua = [
        {
            "datetimeStr": "-",
            "c-ip": "-",
            "cs(User-Agent)": ua,
            "count": cnt,
        }
        for ua, cnt in hits[:20]
    ]
    return total, sus_ua


def _detect_bursts_early_exit(
    conn,
    tz: tzinfo,
    burst_count: int,
    burst_window_ms: int,
) -> list[dict[str, Any]]:
    """對 Top N 候選 IP 逐一滑窗；找到爆量即跳下一 IP（需 ip+timestamp 索引）。"""
    candidates = [
        r["c_ip"]
        for r in conn.execute(
            f"SELECT c_ip FROM {IP_COUNTS} WHERE cnt >= ? "
            f"ORDER BY cnt DESC LIMIT ?",
            (burst_count, BURST_CANDIDATE_LIMIT),
        ).fetchall()
    ]
    if not candidates:
        return []

    bursts: list[dict[str, Any]] = []
    sql = f"SELECT timestamp FROM {SRC} WHERE c_ip = ? ORDER BY timestamp"
    for ip in candidates:
        window: deque[int] = deque(maxlen=burst_count)
        cur = conn.execute(sql, (ip,))
        while True:
            batch = cur.fetchmany(5000)
            if not batch:
                break
            stop = False
            for r in batch:
                ts = int(r["timestamp"] or 0)
                window.append(ts)
                if (
                    len(window) == burst_count
                    and window[-1] - window[0] <= burst_window_ms
                ):
                    start, end = window[0], window[-1]
                    bursts.append(
                        {
                            "ip": ip,
                            "startStr": _fmt_time(start, tz),
                            "endStr": _fmt_time(end, tz),
                            "count": burst_count,
                            "windowSec": f"{(end - start) / 1000:.1f}",
                        }
                    )
                    stop = True
                    break
            if stop:
                break
    return bursts


def _fmt_time(ts_ms: int, tz: tzinfo) -> str:
    if not ts_ms:
        return "-"
    dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).astimezone(tz)
    return dt.strftime("%H:%M:%S")
