"""Integration tests for Phase 4 memory-network correlation.

These tests drive the *full* CLI workflow (load Phase 2 bundle from disk,
load Phase 3 bundle from disk, correlate, persist, status transition) using
committed synthetic fixtures. They are fixture/integration-stub validations:
no real tshark, no real Volatility, and no real memory image are involved,
and they must never be described as real forensic validation.

Ground-truth isolation is asserted explicitly: an unreadable ground-truth
file is planted in the experiment directory and the run must still succeed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from c2forensics.cli.main import main
from c2forensics.config import load_config
from c2forensics.correlation import (
    CorrelationError,
    correlate_evidence,
    load_flow_outcomes,
    run_correlation,
)
from c2forensics.experiment import init_experiment, read_metadata
from c2forensics.extraction.memory import ImageRecord, MemoryExtractionResult
from c2forensics.extraction.memory.parser import parse_plugin_rows
from c2forensics.extraction.pcap import NetworkEvidence
from c2forensics.extraction.pcap.parser import assemble_bundle
from c2forensics.models.experiment import ExperimentStatus
from c2forensics.paths import ExperimentPaths

UTC = timezone.utc
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
EXTRACTED_AT = datetime(2023, 11, 14, 22, 20, tzinfo=UTC)


def _fixture_rows(name: str) -> list:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _build_network(experiment_id: str, fixture: str) -> NetworkEvidence:
    rows = _fixture_rows(fixture)["rows"]
    bundle, _ = assemble_bundle(
        experiment_id=experiment_id,
        pcap_path="raw/capture.pcap",
        pcap_sha256="a" * 64,
        extractor_version="tshark-stub",
        extracted_at=EXTRACTED_AT,
        rows=rows,
    )
    return bundle


def _build_memory(experiment_id: str) -> MemoryExtractionResult:
    netscan_rows = _fixture_rows("volatility_netscan_encrypted_c2.json")["rows"]
    pslist_rows = _fixture_rows("volatility_pslist_encrypted_c2.json")["rows"]
    socks = parse_plugin_rows(
        "windows.netscan.NetScan",
        netscan_rows,
        experiment_id=experiment_id,
        image_sha256="b" * 64,
        image_path="raw/memory/mem.raw",
        extractor_version="vol-stub",
    ).sockets
    procs = parse_plugin_rows(
        "windows.pslist.PsList",
        pslist_rows,
        experiment_id=experiment_id,
        image_sha256="b" * 64,
        image_path="raw/memory/mem.raw",
        extractor_version="vol-stub",
    ).processes
    return MemoryExtractionResult(
        experiment_id=experiment_id,
        images=[
            ImageRecord(
                path="raw/memory/mem.raw",
                sha256="b" * 64,
                size_bytes=4096,
                mtime_utc=EXTRACTED_AT,
            )
        ],
        extractor_version="vol-stub",
        extracted_at=EXTRACTED_AT,
        processes=procs,
        sockets=socks,
    )


@pytest.fixture()
def correlated_repo(
    tmp_path: Path, sample_lab_config_yaml: Path
) -> tuple[Path, Path, ExperimentPaths]:
    """A repo with an initialised EXP001 experiment carrying Phase 2/3 outputs."""
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    network = _build_network("EXP001", "tshark_rows_two_flows.json")
    memory = _build_memory("EXP001")
    (paths.extracted / "network-evidence.json").write_text(
        json.dumps(network.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (paths.extracted / "memory-result.json").write_text(
        json.dumps(memory.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return tmp_path, sample_lab_config_yaml, paths


# ---------------------------------------------------------------------------
# Fixture evidence semantics
# ---------------------------------------------------------------------------


REPO_CONFIG = Path(__file__).resolve().parents[2] / "config" / "lab.yaml"


def test_two_flows_positive_and_negative_controls() -> None:
    config = load_config(REPO_CONFIG).correlation
    network = _build_network("EXP001", "tshark_rows_two_flows.json")
    memory = _build_memory("EXP001")
    outcomes = correlate_evidence(network, memory, config)
    by_flow = {o.flow_id: o for o in outcomes}
    c2_flow = next(
        fid for fid in by_flow if fid.endswith("#0") and "192.168.56.20" in fid
    )
    benign_flow = next(fid for fid in by_flow if "192.168.56.30" in fid)
    # Temporally-unsupported control: the C2 flow matches the memory socket on
    # ports/protocol/process, but its first SYN (22:15:00) is ~94.5s away from
    # the socket Created time (22:13:25.5), far outside the 5s tolerance. The
    # remaining three active factors give 0.5/0.7 ~= 0.714 ("medium").
    matched = by_flow[c2_flow]
    assert matched.outcome == "MATCHED"
    best = matched.candidates[0]
    assert best.pid == 4580
    assert best.process_name == "test-client.exe"
    assert best.confidence == pytest.approx(0.5 / 0.7)
    assert best.classification == "medium"
    flags = {f.name: f.matched for f in best.factors}
    assert flags["timestamp_proximity"] is False
    assert flags["port_match"] is True
    # Negative control: benign HTTP flow with no memory socket at all.
    assert by_flow[benign_flow].outcome == "NO_MATCH"
    assert by_flow[benign_flow].candidates == []


def test_encrypted_c2_fixture_yields_only_weak_evidence() -> None:
    """The encrypted-C2 PCAP fixture (client port 50578, first SYN at
    22:13:20) and the netscan memory fixture (socket local port 51000,
    Created 22:13:25.5) share both endpoint IPs but disagree on the local
    port and fall 5.5s outside the 5s tolerance. Only protocol and process
    association match: 0.2/0.7 ~= 0.286 -> weak, never a strong attribution.
    A single weak candidate above the weak threshold is still MATCHED with
    'weak' confidence; the engine does not fabricate more support than the
    evidence provides."""
    config = load_config(REPO_CONFIG).correlation
    network = _build_network("EXP001", "tshark_rows_encrypted_c2.json")
    memory = _build_memory("EXP001")
    (outcome,) = correlate_evidence(network, memory, config)
    assert outcome.outcome == "MATCHED"  # single weak candidate, none close
    (best,) = outcome.candidates
    assert best.pid == 4580
    assert best.confidence == pytest.approx(0.2 / 0.7)
    assert best.classification == "weak"
    flags = {f.name: f.matched for f in best.factors}
    assert flags["port_match"] is False
    assert flags["timestamp_proximity"] is False
    assert flags["protocol_match"] is True
    assert flags["process_association"] is True


def test_synthetic_positive_control_is_strong() -> None:
    config = load_config(REPO_CONFIG).correlation
    network = _build_network("EXP001", "tshark_rows_positive_control.json")
    memory = _build_memory("EXP001")
    (outcome,) = correlate_evidence(network, memory, config)
    assert outcome.outcome == "MATCHED"
    assert outcome.candidates[0].confidence == pytest.approx(1.0)
    assert outcome.candidates[0].classification == "strong"


def test_missing_process_artifact_still_yields_candidate() -> None:
    config = load_config(REPO_CONFIG).correlation
    network = _build_network("EXP001", "tshark_rows_positive_control.json")
    memory = _build_memory("EXP001").model_copy(update={"processes": []})
    (outcome,) = correlate_evidence(network, memory, config)
    assert len(outcome.candidates) == 1
    best = outcome.candidates[0]
    # port + protocol + timestamp = 0.6/0.7 with process_association False.
    assert best.confidence == pytest.approx(0.6 / 0.7)
    assert best.classification == "strong"
    flags = {f.name: f.matched for f in best.factors}
    assert flags["process_association"] is False
    assert best.process_name == ""
    assert outcome.process_provenance == []


# ---------------------------------------------------------------------------
# CLI end-to-end
# ---------------------------------------------------------------------------


def test_cli_correlate_success_persists_and_advances_status(
    correlated_repo: tuple[Path, Path, ExperimentPaths],
    capsys: pytest.CaptureFixture[str],
) -> None:
    tmp_path, config_path, paths = correlated_repo
    capsys.readouterr()
    rc = main(
        [
            "--config",
            str(config_path),
            "--repo-root",
            str(tmp_path),
            "correlate",
            "EXP001",
        ]
    )
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["flows"] == 2
    assert set(summary["outcomes"].values()) == {"MATCHED", "NO_MATCH"}

    output = paths.correlation / "flow-outcomes.json"
    assert output.is_file()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert isinstance(payload, list) and len(payload) == 2
    # NO_MATCH flows are persisted too.
    assert {"NO_MATCH", "MATCHED"} == {entry["outcome"] for entry in payload}
    assert [entry["flow_id"] for entry in payload] == sorted(
        entry["flow_id"] for entry in payload
    )
    for entry in payload:
        assert entry["experiment_id"] == "EXP001"
        assert entry["flow_provenance"]["flow_id"] == entry["flow_id"]

    reloaded = load_flow_outcomes(paths)
    assert [o.model_dump(mode="json") for o in reloaded] == payload

    assert read_metadata(paths).status == ExperimentStatus.CORRELATED


def test_cli_correlate_is_deterministic(
    correlated_repo: tuple[Path, Path, ExperimentPaths],
    capsys: pytest.CaptureFixture[str],
) -> None:
    tmp_path, config_path, paths = correlated_repo
    run_correlation(paths, load_config(config_path).correlation)
    first = (paths.correlation / "flow-outcomes.json").read_bytes()
    run_correlation(paths, load_config(config_path).correlation)
    second = (paths.correlation / "flow-outcomes.json").read_bytes()
    assert first == second


def test_cli_correlate_missing_inputs_fails_without_status_change(
    tmp_path: Path, sample_lab_config_yaml: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    capsys.readouterr()
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "correlate",
            "EXP001",
        ]
    )
    assert rc == 2
    assert read_metadata(paths).status != ExperimentStatus.CORRELATED
    assert not (paths.correlation / "flow-outcomes.json").exists()


def test_cli_correlate_unknown_experiment_fails(
    tmp_path: Path, sample_lab_config_yaml: Path
) -> None:
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "correlate",
            "EXP404",
        ]
    )
    assert rc == 2


def test_correlation_rejects_multiple_memory_images(
    correlated_repo: tuple[Path, Path, ExperimentPaths],
) -> None:
    _, config_path, paths = correlated_repo
    memory_path = paths.extracted / "memory-result.json"
    memory = MemoryExtractionResult.model_validate(json.loads(memory_path.read_text()))
    extra = memory.model_copy(
        update={
            "images": [
                *memory.images,
                ImageRecord(
                    path="raw/memory/second.raw",
                    sha256="c" * 64,
                    size_bytes=2048,
                    mtime_utc=EXTRACTED_AT,
                ),
            ]
        }
    )
    memory_path.write_text(
        json.dumps(extra.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    config = load_config(config_path).correlation
    with pytest.raises(CorrelationError, match="exactly one memory image"):
        run_correlation(paths, config)
    assert read_metadata(paths).status != ExperimentStatus.CORRELATED


def test_correlation_never_reads_ground_truth(
    correlated_repo: tuple[Path, Path, ExperimentPaths],
) -> None:
    """A ground-truth file that cannot be parsed as JSON must be invisible to
    the correlation engine: it never opens it, so parsing never fails."""
    _, config_path, paths = correlated_repo
    paths.ground_truth_file.write_text("{ this is not json", encoding="utf-8")
    from c2forensics.correlation import correlate_and_mark

    outcomes = correlate_and_mark(paths, load_config(config_path).correlation)
    assert len(outcomes) == 2
    assert read_metadata(paths).status == ExperimentStatus.CORRELATED


def test_correlation_package_never_references_ground_truth() -> None:
    """The correlation package must not read the ground-truth artifact.

    Scans the actual source for code-level references (the paths helper
    constant, the metadata model, or the ground-truth loader), not prose.
    """
    correlation_root = Path(__file__).resolve().parents[2] / "src" / "c2forensics" / "correlation"
    files = sorted(correlation_root.rglob("*.py"))
    assert files
    forbidden = ("GROUND_TRUTH_FILE", "ground_truth_file", "GroundTruth", "load_ground_truth")
    for py in files:
        lines = py.read_text(encoding="utf-8").splitlines()
        for lineno, line in enumerate(lines, 1):
            code = line.split("#", 1)[0]
            if code.lstrip().startswith(('"""', "'''")):
                continue
            for token in forbidden:
                assert token not in code, f"{py.name}:{lineno} references ground truth: {line!r}"
