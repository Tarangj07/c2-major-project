"""Integration test: drive the real Volatility 3 binary against a real
memory image.

This test is **skipped** when Volatility 3 is not on ``PATH``.
It exists to catch contract drift between the framework's plugin
set and the real Volatility 3 release. The test is also skipped
when a real Windows memory image is not available.

The current expected state on this dev environment: vol is not
installed, so the test skips. When Volatility 3 is installed and
a real Windows memory image is placed in a path readable by the
volatility user, the test executes the real subprocess and
validates the bundle.

The test does not fabricate tshark or Volatility output; it
either runs the real binary or it skips.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from c2forensics.acquisition import acquire_memory_image
from c2forensics.config import load_config
from c2forensics.experiment import init_experiment
from c2forensics.extraction.memory import (
    extract_memory,
    load_extracted_result,
)
from c2forensics.extraction.memory.volatility import resolve_binary

VOLATILITY_REQUIRED = pytest.mark.skipif(
    shutil.which("vol") is None,
    reason="volatility3 (vol) not on PATH; integration test skipped",
)


@VOLATILITY_REQUIRED
def test_real_volatility_against_real_image(
    tmp_path: Path, sample_lab_config_yaml: Path
) -> None:
    binary = resolve_binary("vol")
    assert binary  # resolve_binary raises if missing

    # Locate a real Windows memory image. The framework expects
    # the operator to place one of these via env var or path. If
    # none is present, the test skips with a documented reason.
    candidates = [
        Path("/tmp/win10_mem.raw"),
        Path("/tmp/mem.raw"),
        Path("/var/tmp/mem.raw"),
    ]
    image = next((p for p in candidates if p.is_file()), None)
    if image is None:
        pytest.skip(
            "no real Windows memory image available; place one at "
            "/tmp/win10_mem.raw or /tmp/mem.raw or /var/tmp/mem.raw to "
            "enable this test"
        )

    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    acquire_memory_image(paths, image)
    config = load_config(sample_lab_config_yaml)
    bundle = extract_memory(paths, config)
    reloaded = load_extracted_result(paths)
    assert reloaded == bundle


@VOLATILITY_REQUIRED
def test_real_volatility_plugin_failure_does_not_crash(
    tmp_path: Path, sample_lab_config_yaml: Path
) -> None:
    # A 4 KiB zero-filled file is not a valid memory image. Real
    # Volatility 3 cannot satisfy the plugin translation-layer
    # requirements against it and exits non-zero. That is a plugin
    # *execution failure*, not a successful search that found
    # nothing, so the framework must record "error" for both
    # plugins -- never "not_found". ("not_found" is reserved for a
    # successful plugin run that produced zero findings.)
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    src = tmp_path / "tiny.raw"
    src.write_bytes(b"\x00" * 4096)
    acquire_memory_image(paths, src)
    config = load_config(sample_lab_config_yaml)
    try:
        bundle = extract_memory(paths, config)
    except Exception as exc:
        # The framework may refuse to run on a clearly non-image
        # file; that is also acceptable. The contract is that the
        # user sees a typed error, not a stack trace.
        assert "not a valid" in str(exc) or "could not" in str(exc).lower() or "memory image" in str(exc).lower()
        return
    # The plugin failure must be recorded gracefully (no crash) as
    # an execution error for every supported plugin, and must never
    # be reported as a successful "not_found" observation.
    statuses = set(bundle.plugin_status.values())
    assert statuses == {"error"}, bundle.plugin_status
    assert "not_found" not in statuses
    assert bundle.processes == []
    assert bundle.sockets == []
