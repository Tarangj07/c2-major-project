"""Unit tests for the tshark subprocess wrapper.

These tests do not require tshark on ``PATH``. They exercise the
argument construction, error paths, and the parsing of tshark's
``-T fields`` output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from c2forensics.errors import ToolNotFoundError
from c2forensics.extraction.pcap.tshark import (
    TsharkError,
    TsharkInvocation,
    _parse_fields_output,
    _parse_json_output,
    resolve_binary,
    run_fields,
)


def test_invocation_argv_is_deterministic() -> None:
    inv = TsharkInvocation(
        binary="tshark",
        read_filter="ip and tcp",
        display_fields=("frame.number", "ip.src", "tcp.dstport"),
        timeout_seconds=30,
        pcap_path=Path("/tmp/capture.pcap"),
    )
    argv = inv.to_argv()
    assert argv[0] == "tshark"
    assert "-r" in argv
    assert "/tmp/capture.pcap" in argv
    assert "-T" in argv
    assert "fields" in argv
    assert "-Y" in argv
    assert "ip and tcp" in argv
    # All requested fields appear as -e arguments
    for f in ("frame.number", "ip.src", "tcp.dstport"):
        assert "-e" in argv
        assert f in argv


def test_invocation_argv_no_shell_quoting_artefacts() -> None:
    # tshark is invoked with shell=False, so no element of argv may
    # contain shell metacharacters. We just assert the field set is
    # a single argv element per field.
    inv = TsharkInvocation(
        binary="tshark",
        read_filter="ip",
        display_fields=("ip.src", "ip.dst"),
        timeout_seconds=30,
        pcap_path=Path("/tmp/c.pcap"),
    )
    argv = inv.to_argv()
    # Exactly two -e elements
    assert argv.count("-e") == 2
    assert "ip.src" in argv
    assert "ip.dst" in argv


def test_resolve_binary_rejects_empty() -> None:
    with pytest.raises(ToolNotFoundError):
        resolve_binary("")


def test_resolve_binary_rejects_missing_absolute(tmp_path: Path) -> None:
    with pytest.raises(ToolNotFoundError):
        resolve_binary(str(tmp_path / "nope"))


def test_resolve_binary_rejects_missing_name() -> None:
    with pytest.raises(ToolNotFoundError):
        resolve_binary("definitely-not-a-real-binary-xyz")


def test_run_fields_rejects_zero_timeout(tmp_path: Path) -> None:
    pcap = tmp_path / "c.pcap"
    pcap.write_bytes(b"not-a-pcap-but-it-is-a-file")
    inv = TsharkInvocation(
        binary="tshark",
        read_filter="ip",
        display_fields=("ip.src",),
        timeout_seconds=0,
        pcap_path=pcap,
    )
    with pytest.raises(TsharkError):
        run_fields(inv)


def test_run_fields_rejects_missing_pcap(tmp_path: Path) -> None:
    inv = TsharkInvocation(
        binary="tshark",
        read_filter="ip",
        display_fields=("ip.src",),
        timeout_seconds=30,
        pcap_path=tmp_path / "missing.pcap",
    )
    with pytest.raises(TsharkError):
        run_fields(inv)


def test_run_fields_handles_tshark_missing(tmp_path: Path) -> None:
    pcap = tmp_path / "c.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")  # PCAP magic
    inv = TsharkInvocation(
        binary="definitely-not-a-real-binary-xyz",
        read_filter="ip",
        display_fields=("ip.src",),
        timeout_seconds=30,
        pcap_path=pcap,
    )
    with pytest.raises(ToolNotFoundError):
        run_fields(inv)


def test_parse_fields_output_pads_short_rows() -> None:
    raw = "a\tb\tc\n\nd\te\n"  # empty line in the middle
    rows = _parse_fields_output(raw, field_count=3)
    assert rows == [["a", "b", "c"], ["d", "e", ""]]


def test_parse_fields_output_truncates_long_rows() -> None:
    raw = "a\tb\tc\td"
    rows = _parse_fields_output(raw, field_count=3)
    assert rows == [["a", "b", "c"]]


def test_parse_fields_output_empty() -> None:
    assert _parse_fields_output("", field_count=2) == []
    assert _parse_fields_output("\n\n\n", field_count=2) == []


def test_parse_json_output_handles_empty() -> None:
    assert _parse_json_output("") == []
    assert _parse_json_output("   \n  ") == []


def test_parse_json_output_handles_array() -> None:
    raw = '[{"_index": "0"}, {"_index": "1"}]'
    assert _parse_json_output(raw) == [{"_index": "0"}, {"_index": "1"}]


def test_parse_json_output_rejects_garbage() -> None:
    with pytest.raises(TsharkError):
        _parse_json_output("not json")


def test_parse_json_output_rejects_non_array() -> None:
    with pytest.raises(TsharkError):
        _parse_json_output('{"a": 1}')
