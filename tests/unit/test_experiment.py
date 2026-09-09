"""Unit tests for experiment I/O and metadata lifecycle."""

from __future__ import annotations

import json
from datetime import datetime, timezone  # noqa: F401
from pathlib import Path

import pytest

from c2forensics.errors import C2ForensicsError
from c2forensics.experiment import (
    detect_tool_versions,
    init_experiment,
    read_metadata,
    record_raw_hashes,
    update_status,
    utcnow,
    validate_experiment_id,
)
from c2forensics.models.experiment import ExperimentStatus


def test_validate_experiment_id_accepts_valid() -> None:
    assert validate_experiment_id("EXP001") == "EXP001"
    assert validate_experiment_id("exp_42") == "exp_42"


@pytest.mark.parametrize("bad", ["", "1bad", "x" * 65, "../EXP", "a/b", "a b"])
def test_validate_experiment_id_rejects_invalid(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_experiment_id(bad)


def test_init_creates_layout_and_metadata(tmp_repo_root: Path) -> None:
    paths = init_experiment(
        repo_root=tmp_repo_root,
        experiment_id="EXP001",
        description="baseline",
    )
    assert paths.root.is_dir()
    assert paths.raw.is_dir()
    assert paths.memory.is_dir()
    assert paths.metadata_file.is_file()
    meta = read_metadata(paths)
    assert meta.experiment_id == "EXP001"
    assert meta.status == ExperimentStatus.INITIALIZED
    assert meta.created_at.tzinfo is not None


def test_init_is_idempotent(tmp_repo_root: Path) -> None:
    init_experiment(repo_root=tmp_repo_root, experiment_id="EXP001", description="v1")
    paths = init_experiment(repo_root=tmp_repo_root, experiment_id="EXP001", description="v2")
    meta = read_metadata(paths)
    # Description from second call must NOT have overwritten the persisted file,
    # because the experiment was already initialised.
    assert meta.description == "v1"


def test_update_status_writes_to_disk(tmp_repo_root: Path) -> None:
    paths = init_experiment(repo_root=tmp_repo_root, experiment_id="EXP001")
    update_status(paths, ExperimentStatus.EVIDENCE_ACQUIRED)
    meta = read_metadata(paths)
    assert meta.status == ExperimentStatus.EVIDENCE_ACQUIRED
    assert meta.updated_at >= meta.created_at


def test_record_raw_hashes_records_pcap(tmp_repo_root: Path) -> None:
    paths = init_experiment(repo_root=tmp_repo_root, experiment_id="EXP001")
    pcap = paths.raw / "capture.pcap"
    pcap.write_bytes(b"dummy-pcap-bytes")
    updated = record_raw_hashes(paths, pcap_path=pcap)
    assert "raw/capture.pcap" in updated.raw_hashes
    # Length of a SHA-256 hex digest is 64
    assert len(updated.raw_hashes["raw/capture.pcap"]) == 64


def test_record_raw_hashes_rejects_missing(tmp_repo_root: Path) -> None:
    paths = init_experiment(repo_root=tmp_repo_root, experiment_id="EXP001")
    with pytest.raises(FileNotFoundError):
        record_raw_hashes(paths, pcap_path=paths.raw / "nope.pcap")


def test_read_metadata_missing(tmp_repo_root: Path) -> None:
    from c2forensics.paths import ExperimentPaths

    paths = ExperimentPaths.for_experiment(tmp_repo_root, "EXP_MISSING")
    with pytest.raises(FileNotFoundError):
        read_metadata(paths)


def test_utcnow_is_timezone_aware() -> None:
    ts = utcnow()
    assert ts.tzinfo is not None
    assert ts.utcoffset() == timezone.utc.utcoffset(ts)


def test_detect_tool_versions_handles_missing_binaries() -> None:
    # When binaries are missing we expect ``None``, not fabricated values.
    tv = detect_tool_versions(volatility3_binary="definitely-not-on-path-xyz")
    assert tv.python
    assert tv.framework
    assert tv.tshark is None or isinstance(tshark_unused := tv.tshark, str)
    assert tv.volatility3 is None
    # Use the local to silence linters about unused vars.
    _ = tv.os


def test_metadata_file_is_valid_json(tmp_repo_root: Path) -> None:
    paths = init_experiment(repo_root=tmp_repo_root, experiment_id="EXP001")
    with paths.metadata_file.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    assert payload["experiment_id"] == "EXP001"
    assert payload["status"] == ExperimentStatus.INITIALIZED.value
    # The timestamp is in UTC. Pydantic v2 may serialise UTC as either
    # "...+00:00" or "...Z" depending on the version, so we assert the
    # semantic property (zero offset) rather than a string suffix.
    assert _is_utc_string(payload["created_at"])


def test_metadata_round_trip_preserves_utc(tmp_repo_root: Path) -> None:
    paths = init_experiment(repo_root=tmp_repo_root, experiment_id="EXP001")
    meta = read_metadata(paths)
    # Pydantic re-parses the ISO 8601 string; ensure the offset is preserved.
    assert meta.created_at.tzinfo is not None
    assert meta.created_at.utcoffset().total_seconds() == 0.0
    serialised = meta.model_dump(mode="json")["created_at"]
    assert _is_utc_string(serialised)


def _is_utc_string(value: str) -> bool:
    """Return True if the ISO 8601 string represents an instant at offset 0."""
    # Both '...Z' and '...+00:00' are accepted by ``datetime.fromisoformat``
    # in Python 3.11+; we normalise to datetime and check the offset.
    if value.endswith("Z"):
        body = value[:-1] + "+00:00"
    else:
        body = value
    parsed = datetime.fromisoformat(body)
    assert parsed.tzinfo is not None
    return parsed.utcoffset().total_seconds() == 0.0
