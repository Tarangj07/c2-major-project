"""Unit tests for the pure-functional memory parser.

These tests use committed JSON fixtures of Volatility 3 plugin
output. They do not require Volatility to be installed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from c2forensics.extraction.memory.parser import (
    parse_netscan,
    parse_plugin_rows,
    parse_pslist,
    tls_not_recovered,
)
from c2forensics.models.artifact import ArtifactSource
from c2forensics.models.memory import MemoryExtractionStatus

UTC = timezone.utc
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _load_rows(name: str) -> list[dict]:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return payload["rows"]


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------


def test_pick_returns_first_present() -> None:
    from c2forensics.extraction.memory.parser import _pick

    assert _pick({"a": 1, "b": 2}, "b", "a") == 2
    assert _pick({"a": 1, "b": 2}, "a", "b") == 1
    assert _pick({"a": "", "b": "x"}, "a", "b") == "x"
    assert _pick({"a": None, "b": 5}, "a", "b") == 5
    assert _pick({"a": 1}, "missing", "a") == 1
    assert _pick({"a": 1}, "missing") is None


def test_parse_int_handles_forms() -> None:
    from c2forensics.extraction.memory.parser import _parse_int

    assert _parse_int("1234") == 1234
    assert _parse_int(4580) == 4580
    assert _parse_int("0x1234") == 0x1234
    assert _parse_int("not-a-number") is None
    assert _parse_int(None) is None
    assert _parse_int("") is None
    assert _parse_int(0) == 0


def test_parse_datetime_handles_volatility_format() -> None:
    from c2forensics.extraction.memory.parser import _parse_datetime

    dt = _parse_datetime("2023-11-14 22:13:20.000000")
    assert dt is not None
    assert dt.year == 2023 and dt.month == 11 and dt.day == 14
    assert dt.hour == 22 and dt.minute == 13 and dt.second == 20
    assert dt.tzinfo == UTC  # naive timestamps are coerced to UTC

    iso = _parse_datetime("2023-11-14T22:13:20+00:00")
    assert iso == dt

    zulu = _parse_datetime("2023-11-14T22:13:20Z")
    assert zulu is not None
    assert zulu.tzinfo is not None

    assert _parse_datetime("") is None
    assert _parse_datetime("null") is None
    assert _parse_datetime("garbage") is None
    assert _parse_datetime(None) is None


# ---------------------------------------------------------------------------
# pslist
# ---------------------------------------------------------------------------


def test_parse_pslist_baseline() -> None:
    rows = _load_rows("volatility_pslist_encrypted_c2.json")
    procs, provs, diags = parse_pslist(
        rows,
        experiment_id="EXP001",
        image_sha256="0" * 64,
        image_path="/tmp/mem.raw",
        extractor_version="Volatility 3 Framework 2.5.0",
    )
    assert diags.rows_seen == 7
    assert diags.rows_parsed == 7
    assert diags.rows_skipped == 0
    # The test client is in the list.
    target = next(p for p in procs if p.pid == 4580)
    assert target.process_name == "test-client.exe"
    assert target.parent_pid == 880
    assert target.creation_time == datetime(2023, 11, 14, 22, 13, 25, tzinfo=UTC)
    assert target.termination_time is None
    # Provenance is recorded.
    prov = provs[procs.index(target)]
    assert prov.source == ArtifactSource.MEMORY
    assert prov.source_tool == "volatility3"
    assert prov.source_plugin == "windows.pslist.PsList"
    assert prov.experiment_id == "EXP001"


def test_parse_pslist_empty() -> None:
    rows = _load_rows("volatility_pslist_empty.json")
    procs, provs, diags = parse_pslist(
        rows,
        experiment_id="EXP001",
        image_sha256="0" * 64,
        image_path="/tmp/mem.raw",
        extractor_version="Volatility 3",
    )
    assert procs == []
    assert provs == []
    assert diags.rows_seen == 0


def test_parse_pslist_malformed() -> None:
    rows = _load_rows("volatility_pslist_malformed.json")
    procs, provs, diags = parse_pslist(
        rows,
        experiment_id="EXP001",
        image_sha256="0" * 64,
        image_path="/tmp/mem.raw",
        extractor_version="Volatility 3",
    )
    # The "no-pid-row" row must be skipped. The bad-ppid row has a
    # valid PID (100) so it is parsed with parent_pid=None.
    assert diags.rows_seen == 5
    assert diags.rows_skipped >= 1
    assert diags.missing_pid >= 1
    # PID 100 should still be parsed (defensive: unparseable PPID
    # becomes None).
    assert any(p.pid == 100 for p in procs)
    assert any(p.pid == 99 for p in procs)
    # Bad timestamps become None.
    assert any(p.creation_time is None for p in procs)


def test_parse_pslist_no_executable_path_field() -> None:
    """pslist does not emit an executable path; the field stays None."""
    rows = _load_rows("volatility_pslist_encrypted_c2.json")
    procs, _, _ = parse_pslist(
        rows,
        experiment_id="EXP001",
        image_sha256="0" * 64,
        image_path="/tmp/mem.raw",
        extractor_version="Volatility 3",
    )
    for p in procs:
        assert p.executable_path is None


def test_parse_pslist_is_deterministic() -> None:
    rows = _load_rows("volatility_pslist_encrypted_c2.json")
    a, _, diags_a = parse_pslist(
        rows,
        experiment_id="EXP001",
        image_sha256="0" * 64,
        image_path="/tmp/mem.raw",
        extractor_version="Volatility 3",
    )
    b, _, diags_b = parse_pslist(
        rows,
        experiment_id="EXP001",
        image_sha256="0" * 64,
        image_path="/tmp/mem.raw",
        extractor_version="Volatility 3",
    )
    assert [p.model_dump() for p in a] == [p.model_dump() for p in b]
    assert diags_a == diags_b


# ---------------------------------------------------------------------------
# netscan
# ---------------------------------------------------------------------------


def test_parse_netscan_baseline() -> None:
    rows = _load_rows("volatility_netscan_encrypted_c2.json")
    socks, provs, diags = parse_netscan(
        rows,
        experiment_id="EXP001",
        image_sha256="0" * 64,
        image_path="/tmp/mem.raw",
        extractor_version="Volatility 3",
    )
    assert diags.rows_seen == 4
    assert diags.rows_parsed == 4
    # The test client's socket to the C2 server is present.
    target = next(
        s for s in socks
        if s.pid == 4580
        and s.local_ip == "192.168.56.108"
        and s.local_port == 51000
        and s.remote_ip == "192.168.56.20"
        and s.remote_port == 8443
    )
    assert target.protocol == "tcp"
    assert target.state == "ESTABLISHED"
    assert target.timestamp == datetime(2023, 11, 14, 22, 13, 25, 500000, tzinfo=UTC)
    prov = provs[socks.index(target)]
    assert prov.source_plugin == "windows.netscan.NetScan"
    # IPv6 socket is also parsed.
    ipv6 = next(s for s in socks if s.protocol == "tcp" and s.local_ip == "fe80::1234")
    assert ipv6.local_port == 51001
    # UDP listening row.
    udp = next(s for s in socks if s.protocol == "udp")
    assert udp.local_port == 5353


def test_parse_netscan_drops_pidless_rows() -> None:
    rows = _load_rows("volatility_netscan_encrypted_c2.json")
    # Add a row with no PID.
    rows.append({"Protocol": "TCPv4", "LocalAddress": "1.1.1.1", "LocalPort": 1,
                 "RemoteAddress": "2.2.2.2", "RemotePort": 2, "State": "ESTABLISHED"})
    socks, provs, diags = parse_netscan(
        rows,
        experiment_id="EXP001",
        image_sha256="0" * 64,
        image_path="/tmp/mem.raw",
        extractor_version="Volatility 3",
    )
    assert diags.rows_seen == 5
    assert diags.rows_skipped == 1
    assert diags.missing_pid == 1
    assert len(socks) == 4  # the original four


# ---------------------------------------------------------------------------
# TLS absence
# ---------------------------------------------------------------------------


def test_tls_not_recovered_records_explicit_absence() -> None:
    tls, provs = tls_not_recovered(
        experiment_id="EXP001", extractor_version="Volatility 3"
    )
    assert len(tls) == 1
    assert tls[0].absent is True
    assert tls[0].source == "memory"
    assert provs[0].source_plugin == "none"
    # The note explains why; the message is recorded.
    assert "no TLS-extraction plugin" in tls[0].notes


# ---------------------------------------------------------------------------
# Plugin dispatch
# ---------------------------------------------------------------------------


def test_parse_plugin_rows_dispatches_pslist() -> None:
    rows = _load_rows("volatility_pslist_encrypted_c2.json")
    result = parse_plugin_rows(
        "windows.pslist.PsList",
        rows,
        experiment_id="EXP001",
        image_sha256="0" * 64,
        image_path="/tmp/mem.raw",
        extractor_version="Volatility 3",
    )
    assert len(result.processes) == 7
    assert len(result.sockets) == 0
    assert len(result.envelopes) == 1
    env = result.envelopes[0]
    assert env.artifact_kind == "processes"
    assert env.status == MemoryExtractionStatus.OK


def test_parse_plugin_rows_dispatches_netscan() -> None:
    rows = _load_rows("volatility_netscan_encrypted_c2.json")
    result = parse_plugin_rows(
        "windows.netscan.NetScan",
        rows,
        experiment_id="EXP001",
        image_sha256="0" * 64,
        image_path="/tmp/mem.raw",
        extractor_version="Volatility 3",
    )
    assert len(result.sockets) == 4
    assert len(result.processes) == 0
    assert result.envelopes[0].artifact_kind == "sockets"


def test_parse_plugin_rows_rejects_unknown_plugin() -> None:
    with pytest.raises(ValueError):
        parse_plugin_rows(
            "windows.handles.Handles",
            [],
            experiment_id="EXP001",
            image_sha256="0" * 64,
            image_path="/tmp/mem.raw",
            extractor_version="Volatility 3",
        )
