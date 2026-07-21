"""Unit tests for cache / stats key helpers."""

from __future__ import annotations

from iis_log_reader.cache_store import compute_stats_key


def test_stats_key_stable() -> None:
    rules = [{"id": 1, "enabled": True, "type": "uri_contains", "value": "x"}]
    th = {"slow_ms": 10000}
    a = compute_stats_key(rules, th)
    b = compute_stats_key(rules, th)
    assert a == b


def test_stats_key_changes_with_rules() -> None:
    th = {"slow_ms": 10000}
    a = compute_stats_key([{"id": 1, "value": "a"}], th)
    b = compute_stats_key([{"id": 1, "value": "b"}], th)
    assert a != b
