"""SQLite 暫存後端：WAL、批次插入、過濾、分頁查詢。"""

from __future__ import annotations

import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

from .constants import (
    BATCH_INSERT_SIZE,
    DB_COLUMNS,
    FIELD_DEFS,
    LOGICAL_TO_DB,
    PAGE_SIZE_DEFAULT,
)

# 插入時不含 id（AUTOINCREMENT）
INSERT_COLUMNS = [c for c in DB_COLUMNS if c != "id"]

NUMERIC_DB_COLS = frozenset(
    {
        "timestamp",
        "hour",
        "sc_status",
        "sc_substatus",
        "sc_win32_status",
        "time_taken",
        "sc_bytes",
        "cs_bytes",
        "s_port",
    }
)


class LogDatabase:
    """以 SQLite 檔儲存解析後的 IIS log，支援串流批次寫入與查詢。"""

    def __init__(
        self, path: Path | str | None = None, *, existing: bool = False
    ) -> None:
        if path is None:
            fd, name = tempfile.mkstemp(prefix="iis_log_", suffix=".db")
            import os

            os.close(fd)
            self.path = Path(name)
            self._owned_temp = True
        else:
            self.path = Path(path)
            self._owned_temp = False

        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._configure()
        if not existing:
            self._create_schema()
        self._batch: list[tuple] = []
        self.total_raw = 0
        self.source_files: list[str] = []
        if existing:
            cur = self.conn.execute("SELECT COUNT(*) FROM logs")
            self.total_raw = int(cur.fetchone()[0])

    def _configure(self) -> None:
        cur = self.conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA temp_store=MEMORY")
        cur.execute("PRAGMA cache_size=-64000")
        self.conn.commit()

    def _create_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_file TEXT,
                timestamp INTEGER,
                datetime_str TEXT,
                hour INTEGER,
                date TEXT,
                time TEXT,
                s_ip TEXT,
                cs_method TEXT,
                cs_uri_stem TEXT,
                cs_uri_query TEXT,
                s_port TEXT,
                cs_username TEXT,
                c_ip TEXT,
                cs_user_agent TEXT,
                cs_referer TEXT,
                sc_status INTEGER,
                sc_substatus INTEGER,
                sc_win32_status INTEGER,
                time_taken INTEGER,
                sc_bytes INTEGER,
                cs_bytes INTEGER,
                cs_host TEXT
            )
            """
        )
        self.conn.commit()

    def create_indexes(self) -> None:
        """匯入完成後建立查詢用索引（加速 INSERT 期間不建索引）。"""
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)"
        )
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_c_ip ON logs(c_ip)")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_logs_uri ON logs(cs_uri_stem)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_logs_status ON logs(sc_status)"
        )
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_hour ON logs(hour)")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_logs_time_taken ON logs(time_taken)"
        )
        self.conn.commit()

    def clear(self) -> None:
        self.flush()
        self.conn.execute("DELETE FROM logs")
        self.conn.commit()
        self.conn.execute("VACUUM")
        self.total_raw = 0
        self.source_files = []
        self._batch.clear()

    def add_row(self, row: dict[str, Any]) -> None:
        values = tuple(row.get(col) for col in INSERT_COLUMNS)
        self._batch.append(values)
        if len(self._batch) >= BATCH_INSERT_SIZE:
            self.flush()

    def add_rows(self, rows: Iterable[dict[str, Any]]) -> None:
        for row in rows:
            self.add_row(row)

    def flush(self) -> None:
        if not self._batch:
            return
        placeholders = ",".join("?" for _ in INSERT_COLUMNS)
        cols = ",".join(INSERT_COLUMNS)
        sql = f"INSERT INTO logs ({cols}) VALUES ({placeholders})"
        self.conn.executemany(sql, self._batch)
        self.conn.commit()
        self.total_raw += len(self._batch)
        self._batch.clear()

    def finish_import(self, source_files: Sequence[str] | None = None) -> int:
        self.flush()
        if source_files is not None:
            self.source_files = list(source_files)
        self.create_indexes()
        self.conn.execute("ANALYZE")
        self.conn.commit()
        cur = self.conn.execute("SELECT COUNT(*) FROM logs")
        self.total_raw = int(cur.fetchone()[0])
        return self.total_raw

    def close(self) -> None:
        try:
            self.flush()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass
        if self._owned_temp and self.path.exists():
            for suffix in ("", "-wal", "-shm"):
                p = Path(str(self.path) + suffix) if suffix else self.path
                try:
                    if p.exists():
                        p.unlink()
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # 過濾條件組裝
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_db_col(logical_or_db: str) -> str | None:
        if logical_or_db in LOGICAL_TO_DB:
            return LOGICAL_TO_DB[logical_or_db]
        if logical_or_db in INSERT_COLUMNS or logical_or_db == "id":
            return logical_or_db
        # 允許 timestamp 作為排序鍵
        if logical_or_db == "timestamp":
            return "timestamp"
        return None

    def build_where(
        self,
        filter_rules: Sequence[dict[str, Any]] | None = None,
        column_filters: dict[str, str] | None = None,
        time_start_ms: int | None = None,
        time_end_ms: int | None = None,
    ) -> tuple[str, list[Any]]:
        """回傳 (WHERE 子句含 WHERE 關鍵字或空字串, 參數列表)。"""
        clauses: list[str] = []
        params: list[Any] = []

        if filter_rules:
            for rule in filter_rules:
                if not rule.get("enabled", True):
                    continue
                rtype = rule.get("type", "")
                value = str(rule.get("value", "")).strip()
                if not value:
                    continue

                # 用 COLLATE NOCASE，避免 LOWER() 包欄位導致無法利用索引
                if rtype == "uri_contains":
                    clauses.append("IFNULL(cs_uri_stem,'') NOT LIKE ? COLLATE NOCASE")
                    params.append(f"%{value}%")
                elif rtype == "ip_equals":
                    clauses.append("IFNULL(c_ip,'') != ? COLLATE NOCASE")
                    params.append(value)
                elif rtype == "ip_contains":
                    clauses.append("IFNULL(c_ip,'') NOT LIKE ? COLLATE NOCASE")
                    params.append(f"%{value}%")
                elif rtype == "uri_extension":
                    exts = [e.strip() for e in value.split(",") if e.strip()]
                    if not exts:
                        continue
                    sub = " AND ".join(
                        "IFNULL(cs_uri_stem,'') NOT LIKE ? COLLATE NOCASE" for _ in exts
                    )
                    clauses.append(f"({sub})")
                    params.extend(f"%{ext}" for ext in exts)

        if column_filters:
            from .filter_expr import parse_filter_expr

            for key, search in column_filters.items():
                search = (search or "").strip()
                if not search:
                    continue
                col = self._resolve_db_col(key)
                if not col:
                    continue
                is_numeric = col in NUMERIC_DB_COLS
                result = parse_filter_expr(search, col, is_numeric)
                if result:
                    clause, plist = result
                    clauses.append(f"({clause})")
                    params.extend(plist)

        if time_start_ms is not None:
            clauses.append("timestamp >= ?")
            params.append(int(time_start_ms))
        if time_end_ms is not None:
            clauses.append("timestamp <= ?")
            params.append(int(time_end_ms))

        if not clauses:
            return "", params
        return "WHERE " + " AND ".join(clauses), params

    @staticmethod
    def parse_datetime_local(value: str, tz_name: str = "Asia/Taipei") -> int | None:
        """將 datetime-local 字串轉為 epoch ms（視為台北時間）。"""
        from .timezone_util import get_tz

        if not value or not str(value).strip():
            return None
        raw = str(value).strip().replace("T", " ")
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                dt = datetime.strptime(raw, fmt)
                dt = dt.replace(tzinfo=get_tz(tz_name))
                return int(dt.timestamp() * 1000)
            except ValueError:
                continue
        return None

    def count(
        self,
        filter_rules: Sequence[dict[str, Any]] | None = None,
        column_filters: dict[str, str] | None = None,
        time_start_ms: int | None = None,
        time_end_ms: int | None = None,
    ) -> int:
        where, params = self.build_where(
            filter_rules, column_filters, time_start_ms, time_end_ms
        )
        sql = f"SELECT COUNT(*) FROM logs {where}"
        return int(self.conn.execute(sql, params).fetchone()[0])

    def fetch_batch(
        self,
        offset: int = 0,
        limit: int = PAGE_SIZE_DEFAULT,
        sort_key: str = "id",
        sort_dir: str = "asc",
        filter_rules: Sequence[dict[str, Any]] | None = None,
        column_filters: dict[str, str] | None = None,
        time_start_ms: int | None = None,
        time_end_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        """懶加載：只取一批，不 COUNT。SQLite 找到 limit 筆即可停止。"""
        where, params = self.build_where(
            filter_rules, column_filters, time_start_ms, time_end_ms
        )
        col = self._resolve_db_col(sort_key) or "id"
        direction = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
        lim = max(1, int(limit))
        off = max(0, int(offset))

        # 已依 id 排序時不要再加第二鍵，避免多餘排序成本
        if col == "id":
            order_sql = f"ORDER BY id {direction}"
        else:
            order_sql = f"ORDER BY {col} {direction}, id ASC"

        sql = f"SELECT * FROM logs {where} {order_sql} LIMIT ? OFFSET ?"
        params = list(params) + [lim, off]
        rows = self.conn.execute(sql, params).fetchall()
        return [self._row_to_logical(r) for r in rows]

    def fetch_page(
        self,
        page: int = 0,
        page_size: int = PAGE_SIZE_DEFAULT,
        sort_key: str = "timestamp",
        sort_dir: str = "asc",
        filter_rules: Sequence[dict[str, Any]] | None = None,
        column_filters: dict[str, str] | None = None,
        time_start_ms: int | None = None,
        time_end_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        return self.fetch_batch(
            offset=max(0, int(page)) * max(1, int(page_size)),
            limit=page_size,
            sort_key=sort_key,
            sort_dir=sort_dir,
            filter_rules=filter_rules,
            column_filters=column_filters,
            time_start_ms=time_start_ms,
            time_end_ms=time_end_ms,
        )

    def fetch_all_filtered(
        self,
        filter_rules: Sequence[dict[str, Any]] | None = None,
        column_filters: dict[str, str] | None = None,
        time_start_ms: int | None = None,
        time_end_ms: int | None = None,
        columns: Sequence[str] | None = None,
    ) -> list[sqlite3.Row]:
        where, params = self.build_where(
            filter_rules, column_filters, time_start_ms, time_end_ms
        )
        if columns:
            safe = [c for c in columns if c in DB_COLUMNS or c == "id"]
            col_sql = ", ".join(safe) if safe else "*"
        else:
            col_sql = "*"
        sql = f"SELECT {col_sql} FROM logs {where}"
        return list(self.conn.execute(sql, params).fetchall())

    def execute_agg(
        self,
        select_sql: str,
        filter_rules: Sequence[dict[str, Any]] | None = None,
        column_filters: dict[str, str] | None = None,
        time_start_ms: int | None = None,
        time_end_ms: int | None = None,
        extra_params: Sequence[Any] | None = None,
    ) -> list[sqlite3.Row]:
        """執行自訂 SELECT，自動附加 WHERE（select_sql 應含 FROM logs）。"""
        where, params = self.build_where(
            filter_rules, column_filters, time_start_ms, time_end_ms
        )
        # 若 select 已有 WHERE，改用 AND；否則附加 WHERE
        sql = select_sql.strip()
        if where:
            if " where " in sql.lower():
                sql = sql + " AND " + where[6:]  # strip "WHERE "
            else:
                sql = sql + " " + where
        all_params = list(params)
        if extra_params:
            all_params.extend(extra_params)
        return list(self.conn.execute(sql, all_params).fetchall())

    @staticmethod
    def _row_to_logical(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        out: dict[str, Any] = {"id": d.get("id")}
        for logical, meta in FIELD_DEFS.items():
            db = meta["db"]
            out[logical] = d.get(db)
        out["timestamp"] = d.get("timestamp")
        out["hour"] = d.get("hour")
        return out
