"""Unit tests for filter expression parser."""

from __future__ import annotations

from iis_log_reader.filter_expr import parse_filter_expr


def test_default_like() -> None:
    result = parse_filter_expr("api", "cs_uri_stem", False)
    assert result is not None
    clause, params = result
    assert "LIKE" in clause.upper()
    assert params == ["%api%"]


def test_equals_numeric() -> None:
    result = parse_filter_expr("=200", "sc_status", True)
    assert result is not None
    clause, params = result
    assert "sc_status" in clause
    assert "=" in clause
    assert params == [200]


def test_gt_numeric() -> None:
    result = parse_filter_expr(">1000", "time_taken", True)
    assert result is not None
    clause, params = result
    assert ">" in clause
    assert params == [1000]


def test_not_equal_text() -> None:
    result = parse_filter_expr("<>GET", "cs_method", False)
    assert result is not None
    clause, params = result
    assert "!=" in clause or "<>" in clause
    assert params == ["GET"]


def test_like_pattern() -> None:
    result = parse_filter_expr("LIKE %api%", "cs_uri_stem", False)
    assert result is not None
    clause, params = result
    assert "LIKE" in clause.upper()
    assert params == ["%api%"]


def test_null() -> None:
    result = parse_filter_expr("NULL", "cs_uri_query", False)
    assert result is not None
    clause, params = result
    assert "IS NULL" in clause.upper()
    assert params == []


def test_empty_returns_none() -> None:
    assert parse_filter_expr("   ", "c_ip", False) is None
