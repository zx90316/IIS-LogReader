"""常數與欄位對應定義（對齊原 HTML 工具）。"""

from __future__ import annotations

PAGE_SIZE_DEFAULT = 500
# 匯入批次：越大則 executemany/commit 次數越少（記憶體略增）
BATCH_INSERT_SIZE = 50000
# 匯入期間每隔多少列 commit 一次（WAL 成長與 crash 安全折衷）
IMPORT_COMMIT_EVERY = 200000

# 顯示名稱 / DB 欄位 / 原始 IIS 欄位名
# key = UI / config 使用的邏輯欄位名
FIELD_DEFS: dict[str, dict] = {
    "datetimeStr": {
        "label": "時間 (UTC+8)",
        "db": "datetime_str",
        "iis": None,
        "width": 160,
    },
    "date": {"label": "日期 (UTC)", "db": "date", "iis": "date", "width": 100},
    "time": {"label": "時間 (UTC)", "db": "time", "iis": "time", "width": 100},
    "s-ip": {"label": "伺服器 IP", "db": "s_ip", "iis": "s-ip", "width": 120},
    "cs-method": {"label": "Method", "db": "cs_method", "iis": "cs-method", "width": 80},
    "cs-uri-stem": {"label": "URI", "db": "cs_uri_stem", "iis": "cs-uri-stem", "width": 250},
    "cs-uri-query": {"label": "Query", "db": "cs_uri_query", "iis": "cs-uri-query", "width": 200},
    "s-port": {"label": "Port", "db": "s_port", "iis": "s-port", "width": 80},
    "cs-username": {"label": "Username", "db": "cs_username", "iis": "cs-username", "width": 100},
    "c-ip": {"label": "來源 IP", "db": "c_ip", "iis": "c-ip", "width": 120},
    "cs(User-Agent)": {
        "label": "User-Agent",
        "db": "cs_user_agent",
        "iis": "cs(User-Agent)",
        "width": 250,
    },
    "cs(Referer)": {
        "label": "Referer",
        "db": "cs_referer",
        "iis": "cs(Referer)",
        "width": 200,
    },
    "sc-status": {"label": "狀態碼", "db": "sc_status", "iis": "sc-status", "width": 80},
    "sc-substatus": {
        "label": "子狀態",
        "db": "sc_substatus",
        "iis": "sc-substatus",
        "width": 80,
    },
    "sc-win32-status": {
        "label": "Win32狀態",
        "db": "sc_win32_status",
        "iis": "sc-win32-status",
        "width": 100,
    },
    "time-taken": {"label": "耗時(ms)", "db": "time_taken", "iis": "time-taken", "width": 80},
    "sc-bytes": {"label": "送出 Bytes", "db": "sc_bytes", "iis": "sc-bytes", "width": 100},
    "cs-bytes": {"label": "接收 Bytes", "db": "cs_bytes", "iis": "cs-bytes", "width": 100},
    "cs-host": {"label": "Host", "db": "cs_host", "iis": "cs-host", "width": 150},
    "source_file": {
        "label": "來源檔案",
        "db": "source_file",
        "iis": None,
        "width": 140,
    },
}

PREFERRED_VISIBLE_FIELDS = [
    "datetimeStr",
    "cs-method",
    "cs-uri-stem",
    "cs-uri-query",
    "c-ip",
    "sc-status",
    "time-taken",
    "cs(User-Agent)",
    "cs(Referer)",
]

DEFAULT_PARSED_FIELDS = [
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

# IIS 欄位名 → 邏輯欄位名
IIS_TO_LOGICAL = {v["iis"]: k for k, v in FIELD_DEFS.items() if v["iis"]}

# 邏輯欄位名 → DB 欄位
LOGICAL_TO_DB = {k: v["db"] for k, v in FIELD_DEFS.items()}
DB_TO_LOGICAL = {v: k for k, v in LOGICAL_TO_DB.items()}

# 可排序/篩選的 DB 欄位清單（固定 schema）
DB_COLUMNS = [
    "id",
    "source_file",
    "timestamp",
    "datetime_str",
    "hour",
    "date",
    "time",
    "s_ip",
    "cs_method",
    "cs_uri_stem",
    "cs_uri_query",
    "s_port",
    "cs_username",
    "c_ip",
    "cs_user_agent",
    "cs_referer",
    "sc_status",
    "sc_substatus",
    "sc_win32_status",
    "time_taken",
    "sc_bytes",
    "cs_bytes",
    "cs_host",
]

# 插入時不含 id（AUTOINCREMENT）；順序須與 parser 熱路徑 tuple 一致
INSERT_COLUMNS = [c for c in DB_COLUMNS if c != "id"]

KNOWN_SCANNER_UA_KEYWORDS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "gobuster",
    "dirbuster",
    "burpsuite",
    "owasp",
    "nuclei",
    "httpx",
    "python-requests",
    "curl",
    "wget",
    "scrapy",
]

DEFAULT_FILTER_RULES = [
    {
        "id": 1,
        "name": "AjaxSession.ashx (登入狀態驗證)",
        "type": "uri_contains",
        "value": "AjaxSession.ashx",
        "enabled": True,
    },
    {
        "id": 2,
        "name": "排程任務 ConvertOutputDoc",
        "type": "uri_contains",
        "value": "CommonAjax/ConvertOutputDoc",
        "enabled": True,
    },
    {
        "id": 3,
        "name": "靜態資源 (.css/.js/.png/.gif/.jpg/.ico)",
        "type": "uri_extension",
        "value": ".css,.js,.png,.gif,.jpg,.ico,.woff,.ttf,.svg",
        "enabled": True,
    },
]

RULE_TYPES = [
    ("uri_contains", "URI 包含 (uri_contains)"),
    ("uri_extension", "URI 結尾為 (uri_extension)"),
    ("ip_equals", "IP 等於 (ip_equals)"),
    ("ip_contains", "IP 包含 (ip_contains)"),
]
