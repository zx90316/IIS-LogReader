"""時區工具：Windows 常缺 IANA 資料，優先 zoneinfo/tzdata，失敗則退回固定偏移。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo
from functools import lru_cache


# 台灣無夏令時間，固定 UTC+8 可作為可靠後備
_TAIPEI_FIXED = timezone(timedelta(hours=8), name="Asia/Taipei")


@lru_cache(maxsize=8)
def get_tz(tz_name: str = "Asia/Taipei") -> tzinfo:
    name = (tz_name or "Asia/Taipei").strip() or "Asia/Taipei"
    # 正規化常見別名
    aliases = {
        "asia/taipei": "Asia/Taipei",
        "taipei": "Asia/Taipei",
        "taiwan": "Asia/Taipei",
        "utc+8": "Asia/Taipei",
        "gmt+8": "Asia/Taipei",
    }
    name = aliases.get(name.lower(), name)

    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception:
        pass

    # 嘗試載入 tzdata 後再試一次
    try:
        import tzdata  # noqa: F401
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception:
        pass

    if name.lower() in ("asia/taipei", "utc", "etc/utc"):
        if name.upper() == "UTC" or name.lower() == "etc/utc":
            return timezone.utc
        return _TAIPEI_FIXED

    # 未知時區：仍以台北固定偏移，避免整個程式崩潰
    return _TAIPEI_FIXED


def format_local(dt_utc: datetime, tz: tzinfo) -> tuple[str, int]:
    local = dt_utc.astimezone(tz)
    return local.strftime("%Y-%m-%d %H:%M:%S"), local.hour
