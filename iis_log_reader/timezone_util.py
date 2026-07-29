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
    lower = name.lower()

    # 台灣無夏令時間：固定偏移比 ZoneInfo 快，且語意正確
    if lower in ("asia/taipei", "taipei", "taiwan"):
        return _TAIPEI_FIXED
    if lower in ("utc", "etc/utc"):
        return timezone.utc

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

    # 未知時區：仍以台北固定偏移，避免整個程式崩潰
    return _TAIPEI_FIXED


def fixed_utc_offset_hours(tz: tzinfo) -> int | None:
    """若為固定 UTC 偏移則回傳整數小時，否則 None（需走 ZoneInfo 路徑）。"""
    if tz is _TAIPEI_FIXED:
        return 8
    if tz is timezone.utc:
        return 0
    utcoffset = getattr(tz, "utcoffset", None)
    if callable(utcoffset):
        try:
            delta = utcoffset(None)
            if delta is not None and delta.total_seconds() % 3600 == 0:
                return int(delta.total_seconds() // 3600)
        except Exception:
            return None
    return None


def format_local(dt_utc: datetime, tz: tzinfo) -> tuple[str, int]:
    local = dt_utc.astimezone(tz)
    return local.strftime("%Y-%m-%d %H:%M:%S"), local.hour
