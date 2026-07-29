"""CLI 模式：指定 log 檔案/資料夾，直接匯出報告與建議黑名單（排程自動化用）。"""

from __future__ import annotations

import traceback
from pathlib import Path

from .blacklist import (
    build_blacklist_suggestions,
    export_blacklist,
    export_page_scrapes_csv,
)
from .config import AppConfig
from .database import LogDatabase
from .parser import collect_log_files, parse_files_into_db
from .report import export_report
from .stats import compute_stats

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_DATA = 2

REPORT_BASENAME = "分析報告"


def _safe_print(*args: object) -> None:
    """exe 以 console 關閉模式打包時 stdout 可能是 None，列印不可崩潰。"""
    try:
        print(*args)
    except Exception:
        pass


def run_cli(
    input_path: str,
    output_dir: str | Path | None = None,
    fmt: str = "html",
    config: AppConfig | None = None,
) -> int:
    """解析 → 統計 → 匯出報告/完整清單/建議黑名單。回傳 process exit code。"""
    out_dir = Path(output_dir) if output_dir else Path.cwd() / "iis_export"
    fmt = (fmt or "html").lower()
    if fmt not in ("html", "md"):
        _safe_print(f"[錯誤] 不支援的格式：{fmt}（僅支援 html / md）")
        return EXIT_ERROR

    try:
        files = collect_log_files([input_path])
    except Exception as exc:
        _safe_print(f"[錯誤] 讀取輸入路徑失敗：{exc}")
        return EXIT_ERROR
    if not files:
        _safe_print(f"[錯誤] 找不到可分析的 .log 檔案：{input_path}")
        return EXIT_NO_DATA

    _safe_print(f"共找到 {len(files)} 個 log 檔，開始解析…")

    if config is None:
        config = AppConfig()
    db = LogDatabase()
    try:
        total, source_files, _fields = parse_files_into_db(
            files,
            db,
            tz_name=config.timezone,
            progress=lambda name, done, n: _safe_print(
                f"  解析中 ({done}/{n}) {name}"
            ),
        )
        db.finish_import(source_files)
        _safe_print(f"匯入完成，共 {total:,} 筆，開始統計分析…")

        stats = compute_stats(
            db,
            filter_rules=config.filter_rules,
            tz_name=config.timezone,
            thresholds=config.thresholds,
            scrape_limit=-1,
        )
        if not stats:
            _safe_print("[提示] 過濾後無資料，未產生任何輸出")
            return EXIT_NO_DATA

        out_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "source_files": source_files,
            "filter_summary": f"{len(config.filter_rules)} 條規則",
        }
        report_path = export_report(
            stats,
            out_dir / f"{REPORT_BASENAME}.{fmt}",
            meta=meta,
            thresholds=config.thresholds,
        )

        anomalies = stats.get("anomalies", {})
        scrapes = anomalies.get("pageScrapes", [])
        csv_path = export_page_scrapes_csv(scrapes, out_dir)
        suggestions = build_blacklist_suggestions(anomalies, config.thresholds)
        suggest_path, ip_path = export_blacklist(suggestions, out_dir)

        _safe_print("")
        _safe_print(f"分析完成（過濾後 {stats.get('total', 0):,} 筆）：")
        _safe_print(f"  報告：{report_path}")
        _safe_print(f"  完整清單：{csv_path}（{len(scrapes)} 組）")
        _safe_print(f"  建議黑名單：{suggest_path}（{len(suggestions)} 個 IP）")
        _safe_print(f"  黑名單 IP：{ip_path}")
        return EXIT_OK
    except Exception:
        _safe_print("[錯誤] 執行失敗：")
        _safe_print(traceback.format_exc())
        return EXIT_ERROR
    finally:
        try:
            db.close()
        except Exception:
            pass
