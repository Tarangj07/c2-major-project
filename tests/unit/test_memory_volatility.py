"""Unit tests for the Volatility 3 subprocess wrapper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from c2forensics.errors import ToolNotFoundError
from c2forensics.extraction.memory.volatility import (
    SUPPORTED_PLUGINS,
    VolatilityError,
    VolatilityInvocation,
    _parse_json_output,
    resolve_binary,
    run_plugin,
)


def test_supported_plugins_set_is_explicit() -> None:
    # The set is the framework's contract: it refuses to invoke
    # plugins it does not know how to parse.
    assert "windows.pslist.PsList" in SUPPORTED_PLUGINS
    assert "windows.netscan.NetScan" in SUPPORTED_PLUGINS
    # No Linux or macOS plugins: the framework is Windows-only in
    # Phase 3.
    assert all(p.startswith("windows.") for p in SUPPORTED_PLUGINS)


def test_invocation_argv_contains_required_flags() -> None:
    inv = VolatilityInvocation(
        binary="vol",
        image_path=Path("/tmp/mem.raw"),
        plugin="windows.pslist.PsList",
        timeout_seconds=60,
    )
    argv = inv.to_argv()
    assert argv[0] == "vol"
    # ``-q`` for quiet
    assert "-q" in argv
    # ``-f <image>`` for file
    i = argv.index("-f")
    assert argv[i + 1] == "/tmp/mem.raw"
    # ``-r json`` for machine-readable output
    j = argv.index("-r")
    assert argv[j + 1] == "json"
    # The plugin name is the last argv element.
    assert argv[-1] == "windows.pslist.PsList"


def test_invocation_argv_no_shell() -> None:
    inv = VolatilityInvocation(
        binary="vol",
        image_path=Path("/tmp/mem.raw"),
        plugin="windows.pslist.PsList",
        timeout_seconds=60,
    )
    argv = inv.to_argv()
    # No element should contain shell metacharacters.
    for a in argv:
        assert not any(c in a for c in [";", "|", "&", ">", "<", "`", "$("])


def test_resolve_binary_rejects_empty() -> None:
    with pytest.raises(ToolNotFoundError):
        resolve_binary("")


def test_resolve_binary_rejects_missing_absolute(tmp_path: Path) -> None:
    with pytest.raises(ToolNotFoundError):
        resolve_binary(str(tmp_path / "nope"))


def test_resolve_binary_rejects_missing_name() -> None:
    with pytest.raises(ToolNotFoundError):
        resolve_binary("definitely-not-a-real-binary-xyz")


def test_run_plugin_rejects_zero_timeout(tmp_path: Path) -> None:
    img = tmp_path / "m.raw"
    img.write_bytes(b"\x00" * 8)
    inv = VolatilityInvocation(
        binary="vol",
        image_path=img,
        plugin="windows.pslist.PsList",
        timeout_seconds=0,
    )
    with pytest.raises(VolatilityError):
        run_plugin(inv)


def test_run_plugin_rejects_missing_image(tmp_path: Path) -> None:
    inv = VolatilityInvocation(
        binary="vol",
        image_path=tmp_path / "missing.raw",
        plugin="windows.pslist.PsList",
        timeout_seconds=30,
    )
    with pytest.raises(VolatilityError):
        run_plugin(inv)


def test_run_plugin_rejects_empty_image(tmp_path: Path) -> None:
    img = tmp_path / "empty.raw"
    img.write_bytes(b"")
    inv = VolatilityInvocation(
        binary="vol",
        image_path=img,
        plugin="windows.pslist.PsList",
        timeout_seconds=30,
    )
    with pytest.raises(VolatilityError):
        run_plugin(inv)


def test_run_plugin_rejects_unsupported_plugin(tmp_path: Path) -> None:
    img = tmp_path / "m.raw"
    img.write_bytes(b"\x00" * 8)
    inv = VolatilityInvocation(
        binary="vol",
        image_path=img,
        plugin="windows.handles.Handles",
        timeout_seconds=30,
    )
    with pytest.raises(VolatilityError):
        run_plugin(inv)


def test_run_plugin_handles_missing_binary(tmp_path: Path) -> None:
    img = tmp_path / "m.raw"
    img.write_bytes(b"\x00" * 8)
    inv = VolatilityInvocation(
        binary="definitely-not-a-real-binary-xyz",
        image_path=img,
        plugin="windows.pslist.PsList",
        timeout_seconds=30,
    )
    with pytest.raises(ToolNotFoundError):
        run_plugin(inv)


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------


def test_parse_json_output_handles_array() -> None:
    raw = json.dumps([{"PID": 1}, {"PID": 2}])
    assert _parse_json_output(raw) == [{"PID": 1}, {"PID": 2}]


def test_parse_json_output_handles_single_object() -> None:
    raw = json.dumps({"PID": 1, "PPID": 0})
    assert _parse_json_output(raw) == [{"PID": 1, "PPID": 0}]


def test_parse_json_output_handles_ndjson() -> None:
    raw = '\n'.join([
        json.dumps({"PID": 1}),
        json.dumps({"PID": 2}),
        "",
        json.dumps({"PID": 3}),
    ])
    assert _parse_json_output(raw) == [{"PID": 1}, {"PID": 2}, {"PID": 3}]


def test_parse_json_output_handles_empty() -> None:
    assert _parse_json_output("") == []
    assert _parse_json_output("   \n  ") == []


def test_parse_json_output_rejects_garbage() -> None:
    with pytest.raises(VolatilityError):
        _parse_json_output("definitely not JSON")


def test_parse_json_output_rejects_top_level_non_collection() -> None:
    with pytest.raises(VolatilityError):
        _parse_json_output("42")
