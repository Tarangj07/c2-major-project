"""Unit tests for the high-level PCAP extractor.

The unit tests run against committed JSON fixtures of tshark rows,
not against a real tshark binary. There is a separate integration
test (``test_pcap_integration.py``) that runs the real tshark against
a tiny synthetic PCAP if tshark is on ``PATH``.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from c2forensics.config import load_config
from c2forensics.errors import C2ForensicsError
from c2forensics.experiment import init_experiment, read_metadata
from c2forensics.extraction.pcap import (
    NetworkEvidence,
    extract_pcap,
    load_extracted_bundle,
    emit_legacy_flows,
)
from c2forensics.extraction.pcap.extractor import PCAPExtractionError
from c2forensics.extraction.pcap.parser import (
    PCAP_FIELDS,
    ParseDiagnostics,
    assemble_bundle,
)
from c2forensics.extraction.pcap.tshark import (
    TsharkInvocation,
    TsharkNotFoundError,
    run_fields,
)
from c2forensics.paths import ExperimentPaths

UTC = timezone.utc
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _stub_tshark(monkeypatch: pytest.MonkeyPatch, rows: list[list[str]], version: str = "TShark 4.2.0") -> None:
    """Replace :func:`run_fields` with a deterministic stub.

    The stub returns the supplied rows and the supplied version,
    bypassing any subprocess invocation. This keeps the extractor
    test suite independent of tshark's availability.
    """
    from c2forensics.extraction.pcap import extractor as ext_mod

    def _fake(inv: TsharkInvocation):
        from c2forensics.extraction.pcap.tshark import TsharkResult

        return TsharkResult(
            fields=rows,
            raw_stdout="",
            raw_stderr="",
            return_code=0,
            version=version,
        )

    monkeypatch.setattr(ext_mod, "run_fields", _fake)


def _init_experiment_with_pcap(tmp_path: Path) -> tuple[ExperimentPaths, bytes]:
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    pcap = paths.raw / "capture.pcap"
    pcap_bytes = b"FAKE-PCAP-BYTES"
    pcap.write_bytes(pcap_bytes)
    return paths, pcap_bytes


# ---------------------------------------------------------------------------
# Extractor end-to-end (with stubbed tshark)
# ---------------------------------------------------------------------------


def test_extract_pcap_produces_network_evidence(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _ = _init_experiment_with_pcap(tmp_path)
    config = load_config(sample_lab_config_yaml)
    rows = json.loads((FIXTURES / "tshark_rows_encrypted_c2.json").read_text())["rows"]
    _stub_tshark(monkeypatch, rows)

    bundle = extract_pcap(paths, config)
    assert isinstance(bundle, NetworkEvidence)
    assert len(bundle.flows) == 1
    assert bundle.flows[0].flow_id == "tcp:192.168.56.108:50578->192.168.56.20:8443#0"
    assert bundle.extractor_version == "TShark 4.2.0"
    # The PCAP SHA-256 is recorded on the bundle.
    assert len(bundle.pcap_sha256) == 64


def test_extract_pcap_writes_deterministic_files(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, pcap_bytes = _init_experiment_with_pcap(tmp_path)
    config = load_config(sample_lab_config_yaml)
    rows = json.loads((FIXTURES / "tshark_rows_encrypted_c2.json").read_text())["rows"]
    _stub_tshark(monkeypatch, rows)
    fixed_ts = datetime(2026, 1, 1, tzinfo=UTC)

    extract_pcap(paths, config, extracted_at=fixed_ts)
    network_file = paths.extracted / "network-evidence.json"
    diag_file = paths.extracted / "pcap-diagnostics.json"
    assert network_file.is_file()
    assert diag_file.is_file()
    payload_first = network_file.read_bytes()
    diag_first = diag_file.read_bytes()
    # Re-run with the same fixed timestamp; outputs must be byte-identical.
    extract_pcap(paths, config, extracted_at=fixed_ts)
    payload_second = network_file.read_bytes()
    diag_second = diag_file.read_bytes()
    assert payload_first == payload_second
    assert diag_first == diag_second
    # The original PCAP is untouched.
    assert (paths.raw / "capture.pcap").read_bytes() == pcap_bytes


def test_extract_pcap_round_trip(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _ = _init_experiment_with_pcap(tmp_path)
    config = load_config(sample_lab_config_yaml)
    rows = json.loads((FIXTURES / "tshark_rows_encrypted_c2.json").read_text())["rows"]
    _stub_tshark(monkeypatch, rows)

    bundle = extract_pcap(paths, config)
    loaded = load_extracted_bundle(paths)
    assert loaded == bundle


def test_extract_pcap_preserves_pcap_hash(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Use the acquisition path so the metadata records the hash.
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    from c2forensics.acquisition import acquire_pcap

    src = tmp_path / "src.pcap"
    pcap_bytes = b"FAKE-PCAP-BYTES-FOR-HASH-CHECK"
    src.write_bytes(pcap_bytes)
    digest = acquire_pcap(paths, src)
    config = load_config(sample_lab_config_yaml)
    _stub_tshark(monkeypatch, [])
    extract_pcap(paths, config)
    meta = read_metadata(paths)
    assert meta.raw_hashes["raw/capture.pcap"] == digest
    from c2forensics.hashing import hash_file
    assert hash_file(paths.raw / "capture.pcap") == digest
    # The PCAP was not modified by extraction.
    assert (paths.raw / "capture.pcap").read_bytes() == pcap_bytes
    # The bundle carries the same digest.
    bundle = load_extracted_bundle(paths)
    assert bundle.pcap_sha256 == digest


def test_extract_pcap_empty(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _ = _init_experiment_with_pcap(tmp_path)
    config = load_config(sample_lab_config_yaml)
    _stub_tshark(monkeypatch, [])
    bundle = extract_pcap(paths, config)
    assert bundle.flows == []
    assert bundle.tcp_lifecycle == []
    assert bundle.tls_observations == []


def test_extract_pcap_missing_pcap(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    config = load_config(sample_lab_config_yaml)
    # No PCAP placed under raw/
    with pytest.raises(PCAPExtractionError):
        extract_pcap(paths, config)


def test_extract_pcap_tshark_not_found(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _ = _init_experiment_with_pcap(tmp_path)
    config = load_config(sample_lab_config_yaml)

    from c2forensics.extraction.pcap import extractor as ext_mod

    def _fake_missing(inv: TsharkInvocation):
        raise TsharkNotFoundError("tshark binary not found on PATH")

    monkeypatch.setattr(ext_mod, "run_fields", _fake_missing)
    with pytest.raises(PCAPExtractionError):
        extract_pcap(paths, config)


def test_extract_pcap_tshark_failure(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _ = _init_experiment_with_pcap(tmp_path)
    config = load_config(sample_lab_config_yaml)

    from c2forensics.extraction.pcap import extractor as ext_mod
    from c2forensics.extraction.pcap.tshark import TsharkError

    def _fake_fail(inv: TsharkInvocation):
        raise TsharkError("tshark exited with code 1: parse error")

    monkeypatch.setattr(ext_mod, "run_fields", _fake_fail)
    with pytest.raises(PCAPExtractionError):
        extract_pcap(paths, config)


def test_extract_pcap_handles_malformed_pcap(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Malformed PCAPs are surfaced as a graceful error, not a crash."""
    paths, _ = _init_experiment_with_pcap(tmp_path)
    config = load_config(sample_lab_config_yaml)
    # Garbage that is not a valid tshark fields row.
    garbage = [["abc", "def"], ["only", "two", "fields", "and", "bad", "things"]]
    _stub_tshark(monkeypatch, garbage)
    # The parser should still return an empty result rather than crash,
    # because every field is unreadable.
    bundle = extract_pcap(paths, config)
    assert bundle.flows == []


# ---------------------------------------------------------------------------
# Legacy NetworkFlow renderer
# ---------------------------------------------------------------------------


def test_emit_legacy_flows_preserves_tls_metadata(
    tmp_path: Path, sample_lab_config_yaml: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _ = _init_experiment_with_pcap(tmp_path)
    config = load_config(sample_lab_config_yaml)
    rows = json.loads((FIXTURES / "tshark_rows_encrypted_c2.json").read_text())["rows"]
    _stub_tshark(monkeypatch, rows)
    bundle = extract_pcap(paths, config)
    flows = emit_legacy_flows(bundle)
    assert len(flows) == 1
    f = flows[0]
    assert f["src_port"] == 50578
    assert f["dst_port"] == 8443
    assert f["packet_count"] == bundle.flows[0].frame_count
    assert f["tls_detected"] is True
    assert f["pcap_sha256"] == bundle.pcap_sha256
    # No PID anywhere.
    assert "pid" not in f
    assert "process" not in f
