"""Unit tests for the high-level memory extractor.

The tests stub the Volatility backend so they run without a real
Volatility 3 binary. A separate integration test runs the real
backend when Volatility is installed.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from c2forensics.acquisition import acquire_memory_image
from c2forensics.config import load_config
from c2forensics.experiment import init_experiment
from c2forensics.extraction.memory import (
    EXTRACTED_DIAGNOSTICS_FILE,
    EXTRACTED_ENVELOPES_FILE,
    EXTRACTED_PROCESSES_FILE,
    EXTRACTED_RESULT_FILE,
    EXTRACTED_SOCKETS_FILE,
    EXTRACTED_TLS_FILE,
    MemoryExtractionError,
    extract_memory,
    load_extracted_result,
)
from c2forensics.extraction.memory.volatility import (
    SUPPORTED_PLUGINS,
    VolatilityInvocation,
    VolatilityResult,
    run_plugin,
)

UTC = timezone.utc
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _stub_volatility(
    monkeypatch: pytest.MonkeyPatch,
    rows_by_plugin: dict[str, list[dict]],
    version: str = "Volatility 3 Framework 2.5.0",
) -> None:
    """Replace :func:`run_plugin` with a deterministic stub.

    The stub returns the rows configured for the requested plugin
    and a fixed version string.
    """
    from c2forensics.extraction.memory import extractor as ext_mod

    def _fake(inv: VolatilityInvocation) -> VolatilityResult:
        return VolatilityResult(
            rows=rows_by_plugin.get(inv.plugin, []),
            raw_stdout="",
            raw_stderr="",
            return_code=0,
            version=version,
            plugin=inv.plugin,
        )

    monkeypatch.setattr(ext_mod, "run_plugin", _fake)


def _init_with_image(
    tmp_path: Path, content: bytes = b"FAKE-MEMORY-IMAGE"
) -> tuple[Path, Path]:
    """Initialise an experiment and ingest a fake memory image.

    Returns ``(repo_root, on_disk_image)``.
    """
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    src = tmp_path / "src.raw"
    src.write_bytes(content)
    acquire_memory_image(paths, src)
    return tmp_path, paths.memory / "src.raw"


# ---------------------------------------------------------------------------
# Top-level extraction with stubbed Volatility
# ---------------------------------------------------------------------------


def test_extract_memory_produces_full_bundle(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root, _ = _init_with_image(tmp_path)
    config = load_config(sample_lab_config_yaml)
    rows_pslist = json.loads((FIXTURES / "volatility_pslist_encrypted_c2.json").read_text())["rows"]
    rows_netscan = json.loads((FIXTURES / "volatility_netscan_encrypted_c2.json").read_text())["rows"]
    _stub_volatility(monkeypatch, {
        "windows.pslist.PsList": rows_pslist,
        "windows.netscan.NetScan": rows_netscan,
    })

    from c2forensics.paths import ExperimentPaths
    paths = ExperimentPaths.for_experiment(repo_root, "EXP001")
    result = extract_memory(paths, config, extracted_at=datetime(2026, 9, 4, tzinfo=UTC))

    assert result.experiment_id == "EXP001"
    assert result.platform == "windows"
    assert len(result.images) == 1
    assert result.images[0].sha256
    assert result.images[0].size_bytes > 0
    assert len(result.processes) == 7
    assert len(result.sockets) == 4
    # TLS is recorded as absent.
    assert len(result.tls_artifacts) == 1
    assert result.tls_artifacts[0].absent is True
    # Plugin status reflects both plugins succeeding.
    assert result.plugin_status["windows.pslist.PsList"] == "ok"
    assert result.plugin_status["windows.netscan.NetScan"] == "ok"


def test_extract_memory_writes_deterministic_files(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root, _ = _init_with_image(tmp_path)
    config = load_config(sample_lab_config_yaml)
    rows_pslist = json.loads((FIXTURES / "volatility_pslist_encrypted_c2.json").read_text())["rows"]
    rows_netscan = json.loads((FIXTURES / "volatility_netscan_encrypted_c2.json").read_text())["rows"]
    _stub_volatility(monkeypatch, {
        "windows.pslist.PsList": rows_pslist,
        "windows.netscan.NetScan": rows_netscan,
    })

    from c2forensics.paths import ExperimentPaths
    paths = ExperimentPaths.for_experiment(repo_root, "EXP001")
    fixed = datetime(2026, 9, 4, tzinfo=UTC)
    extract_memory(paths, config, extracted_at=fixed)
    first_files = {
        f: (paths.extracted / f).read_bytes()
        for f in [
            EXTRACTED_PROCESSES_FILE,
            EXTRACTED_SOCKETS_FILE,
            EXTRACTED_TLS_FILE,
            EXTRACTED_ENVELOPES_FILE,
            EXTRACTED_DIAGNOSTICS_FILE,
            EXTRACTED_RESULT_FILE,
        ]
    }
    extract_memory(paths, config, extracted_at=fixed)
    for f, content in first_files.items():
        assert (paths.extracted / f).read_bytes() == content, f


def test_extract_memory_round_trip(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root, _ = _init_with_image(tmp_path)
    config = load_config(sample_lab_config_yaml)
    rows_pslist = json.loads((FIXTURES / "volatility_pslist_encrypted_c2.json").read_text())["rows"]
    rows_netscan = json.loads((FIXTURES / "volatility_netscan_encrypted_c2.json").read_text())["rows"]
    _stub_volatility(monkeypatch, {
        "windows.pslist.PsList": rows_pslist,
        "windows.netscan.NetScan": rows_netscan,
    })
    from c2forensics.paths import ExperimentPaths
    paths = ExperimentPaths.for_experiment(repo_root, "EXP001")
    result = extract_memory(paths, config, extracted_at=datetime(2026, 9, 4, tzinfo=UTC))
    reloaded = load_extracted_result(paths)
    assert reloaded == result


def test_extract_memory_no_image(
    tmp_path: Path, sample_lab_config_yaml: Path
) -> None:
    init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    config = load_config(sample_lab_config_yaml)
    from c2forensics.paths import ExperimentPaths
    paths = ExperimentPaths.for_experiment(tmp_path, "EXP001")
    with pytest.raises(MemoryExtractionError):
        extract_memory(paths, config)


def test_extract_memory_volatility_not_found(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root, _ = _init_with_image(tmp_path)
    config = load_config(sample_lab_config_yaml)
    from c2forensics.extraction.memory.volatility import VolatilityNotFoundError
    from c2forensics.extraction.memory import extractor as ext_mod

    def _fake_missing(inv):
        raise VolatilityNotFoundError("volatility binary not found on PATH")

    monkeypatch.setattr(ext_mod, "run_plugin", _fake_missing)
    from c2forensics.paths import ExperimentPaths
    paths = ExperimentPaths.for_experiment(repo_root, "EXP001")
    with pytest.raises(MemoryExtractionError):
        extract_memory(paths, config)


def test_extract_memory_plugin_failure_does_not_crash(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If a single plugin fails, the run completes with that plugin's
    status set to 'error' and the other plugins still contribute."""
    repo_root, _ = _init_with_image(tmp_path)
    config = load_config(sample_lab_config_yaml)
    rows_netscan = json.loads((FIXTURES / "volatility_netscan_encrypted_c2.json").read_text())["rows"]
    from c2forensics.extraction.memory import extractor as ext_mod
    from c2forensics.extraction.memory.volatility import VolatilityError

    def _fake_partial(inv: VolatilityInvocation):
        if inv.plugin == "windows.pslist.PsList":
            raise VolatilityError("pslist crashed")
        return VolatilityResult(
            rows=rows_netscan,
            raw_stdout="",
            raw_stderr="",
            return_code=0,
            version="Volatility 3",
            plugin=inv.plugin,
        )

    monkeypatch.setattr(ext_mod, "run_plugin", _fake_partial)
    from c2forensics.paths import ExperimentPaths
    paths = ExperimentPaths.for_experiment(repo_root, "EXP001")
    result = extract_memory(paths, config, extracted_at=datetime(2026, 9, 4, tzinfo=UTC))
    assert result.plugin_status["windows.pslist.PsList"] == "error"
    assert result.plugin_status["windows.netscan.NetScan"] == "ok"
    # The failed plugin contributes zero processes; the successful
    # plugin still contributes its sockets.
    assert len(result.processes) == 0
    assert len(result.sockets) == 4


def test_extract_memory_handles_empty_pslist(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root, _ = _init_with_image(tmp_path)
    config = load_config(sample_lab_config_yaml)
    rows_netscan = json.loads((FIXTURES / "volatility_netscan_encrypted_c2.json").read_text())["rows"]
    _stub_volatility(monkeypatch, {
        "windows.pslist.PsList": [],
        "windows.netscan.NetScan": rows_netscan,
    })
    from c2forensics.paths import ExperimentPaths
    paths = ExperimentPaths.for_experiment(repo_root, "EXP001")
    result = extract_memory(paths, config, extracted_at=datetime(2026, 9, 4, tzinfo=UTC))
    assert result.processes == []
    assert result.plugin_status["windows.pslist.PsList"] == "not_found"
    assert len(result.sockets) == 4


def test_extract_memory_does_not_modify_image(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root, _ = _init_with_image(tmp_path, content=b"FAKE-MEMORY-BYTES")
    config = load_config(sample_lab_config_yaml)
    rows_netscan = json.loads((FIXTURES / "volatility_netscan_encrypted_c2.json").read_text())["rows"]
    _stub_volatility(monkeypatch, {
        "windows.pslist.PsList": [],
        "windows.netscan.NetScan": rows_netscan,
    })
    from c2forensics.paths import ExperimentPaths
    paths = ExperimentPaths.for_experiment(repo_root, "EXP001")
    from c2forensics.hashing import hash_file
    pre = hash_file(paths.memory / "src.raw")
    extract_memory(paths, config, extracted_at=datetime(2026, 9, 4, tzinfo=UTC))
    post = hash_file(paths.memory / "src.raw")
    assert pre == post


def test_extract_memory_no_pid_field_on_attribution(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bundle must not carry a flow_id or attribution_confidence
    field. The Phase 4 correlator will produce those.
    """
    repo_root, _ = _init_with_image(tmp_path)
    config = load_config(sample_lab_config_yaml)
    rows_pslist = json.loads((FIXTURES / "volatility_pslist_encrypted_c2.json").read_text())["rows"]
    rows_netscan = json.loads((FIXTURES / "volatility_netscan_encrypted_c2.json").read_text())["rows"]
    _stub_volatility(monkeypatch, {
        "windows.pslist.PsList": rows_pslist,
        "windows.netscan.NetScan": rows_netscan,
    })
    from c2forensics.paths import ExperimentPaths
    paths = ExperimentPaths.for_experiment(repo_root, "EXP001")
    result = extract_memory(paths, config, extracted_at=datetime(2026, 9, 4, tzinfo=UTC))
    serialised = json.dumps(result.model_dump(mode="json"))
    for forbidden in [
        '"attribution_confidence"',
        '"flow_id"',
        '"correlated_flow"',
        '"correlated_pcap"',
    ]:
        assert forbidden not in serialised, f"unexpected {forbidden} in bundle"


def test_extract_memory_persists_image_records(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root, _ = _init_with_image(tmp_path)
    config = load_config(sample_lab_config_yaml)
    _stub_volatility(monkeypatch, {
        "windows.pslist.PsList": [],
        "windows.netscan.NetScan": [],
    })
    from c2forensics.paths import ExperimentPaths
    paths = ExperimentPaths.for_experiment(repo_root, "EXP001")
    extract_memory(paths, config, extracted_at=datetime(2026, 9, 4, tzinfo=UTC))
    bundle = load_extracted_result(paths)
    assert len(bundle.images) == 1
    rec = bundle.images[0]
    assert rec.sha256 and len(rec.sha256) == 64
    assert rec.size_bytes > 0
    assert rec.mtime_utc.tzinfo == UTC
