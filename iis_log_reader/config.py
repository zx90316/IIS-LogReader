"""以 .config 實體檔案持久化設定。"""

from __future__ import annotations

import configparser
import json
from pathlib import Path
from typing import Any

from .constants import (
    DEFAULT_FILTER_RULES,
    KNOWN_SCANNER_UA_KEYWORDS,
    PAGE_SIZE_DEFAULT,
    PREFERRED_VISIBLE_FIELDS,
)

DEFAULT_CONFIG_NAME = "app.config"

DEFAULT_THRESHOLDS: dict[str, Any] = {
    "high_freq_std_mult": 2.0,
    "burst_count": 60,
    "burst_window_ms": 60000,
    "slow_ms": 10000,
    "off_hour_start": 0,
    "off_hour_end": 7,
    "error_status_min": 400,
    "page_scrape_count": 100,
    "page_scrape_min_span_min": 0,
    "scanner_ua_keywords": ",".join(KNOWN_SCANNER_UA_KEYWORDS),
}


class AppConfig:
    """讀寫 INI 風格 .config，規則與欄位偏好以 JSON 儲存於區段內。"""

    def __init__(self, path: Path | str | None = None) -> None:
        if path is None:
            from .paths import get_app_dir

            path = get_app_dir() / DEFAULT_CONFIG_NAME
        self.path = Path(path)
        self._parser = configparser.ConfigParser()
        self.page_size = PAGE_SIZE_DEFAULT
        self.last_dir = ""
        self.timezone = "Asia/Taipei"
        self.visible_fields: list[str] = list(PREFERRED_VISIBLE_FIELDS)
        self.filter_rules: list[dict[str, Any]] = [
            dict(r) for r in DEFAULT_FILTER_RULES
        ]
        self.window_geometry = ""
        self.thresholds: dict[str, Any] = dict(DEFAULT_THRESHOLDS)
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self.save()
            return

        self._parser.read(self.path, encoding="utf-8-sig")

        g = self._section("General")
        self.page_size = g.getint("page_size", PAGE_SIZE_DEFAULT)
        self.last_dir = g.get("last_dir", "")
        self.timezone = g.get("timezone", "Asia/Taipei")
        self.window_geometry = g.get("window_geometry", "")

        v = self._section("VisibleFields")
        raw_fields = v.get("fields", "").strip()
        if raw_fields:
            self.visible_fields = [f.strip() for f in raw_fields.split(",") if f.strip()]

        r = self._section("FilterRules")
        raw_rules = r.get("rules_json", "").strip()
        if raw_rules:
            try:
                loaded = json.loads(raw_rules)
                if isinstance(loaded, list) and loaded:
                    self.filter_rules = loaded
            except json.JSONDecodeError:
                pass

        # 異常閾值
        t = self._section("AnomalyThresholds")
        self.thresholds = dict(DEFAULT_THRESHOLDS)
        for key, default in DEFAULT_THRESHOLDS.items():
            raw = t.get(key, "").strip()
            if raw:
                if isinstance(default, float):
                    try:
                        self.thresholds[key] = float(raw)
                    except ValueError:
                        pass
                elif isinstance(default, int):
                    try:
                        self.thresholds[key] = int(raw)
                    except ValueError:
                        pass
                else:
                    self.thresholds[key] = raw

    def save(self) -> None:
        if not self._parser.has_section("General"):
            self._parser.add_section("General")
        if not self._parser.has_section("VisibleFields"):
            self._parser.add_section("VisibleFields")
        if not self._parser.has_section("FilterRules"):
            self._parser.add_section("FilterRules")
        if not self._parser.has_section("AnomalyThresholds"):
            self._parser.add_section("AnomalyThresholds")

        self._parser["General"]["page_size"] = str(self.page_size)
        self._parser["General"]["last_dir"] = self.last_dir
        self._parser["General"]["timezone"] = self.timezone
        self._parser["General"]["window_geometry"] = self.window_geometry

        self._parser["VisibleFields"]["fields"] = ",".join(self.visible_fields)
        self._parser["FilterRules"]["rules_json"] = json.dumps(
            self.filter_rules, ensure_ascii=False
        )

        for key, val in self.thresholds.items():
            self._parser["AnomalyThresholds"][key] = str(val)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as f:
            self._parser.write(f)

    def _section(self, name: str) -> configparser.SectionProxy:
        if not self._parser.has_section(name):
            self._parser.add_section(name)
        return self._parser[name]

    def next_rule_id(self) -> int:
        if not self.filter_rules:
            return 1
        return max(int(r.get("id", 0)) for r in self.filter_rules) + 1
