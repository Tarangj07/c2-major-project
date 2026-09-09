"""Unit tests for PCAP acquisition."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from c2forensics.acquisition import PcapAcquisitionError, acquire_pcap
from c2forensics.experiment import init_experiment, read_metadata
from c2forensics.paths import ExperimentPaths


def test_acquire_pcap_copies_and_hashes(tmp_path: Path) -> None:
    # Initialise a fresh experiment
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    src = tmp_path / "src.pcap"
    src.write_bytes(b"some-pcap-bytes")

    digest = acquire_pcap(paths, src)
    # File is now at the canonical location
    pcap = paths.raw / "capture.pcap"
    assert pcap.is_file()
    assert pcap.read_bytes() == b"some-pcap-bytes"
    # Digest is a SHA-256 hex
    assert len(digest) == 64
    # Metadata is updated with the hash
    meta = read_metadata(paths)
    assert meta.raw_hashes.get("raw/capture.pcap") == digest


def test_acquire_pcap_rejects_missing_source(tmp_path: Path) -> None:
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    with pytest.raises(PcapAcquisitionError):
        acquire_pcap(paths, tmp_path / "missing.pcap")


def test_acquire_pcap_rejects_empty_source(tmp_path: Path) -> None:
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    src = tmp_path / "empty.pcap"
    src.write_bytes(b"")
    with pytest.raises(PcapAcquisitionError):
        acquire_pcap(paths, src)


def test_acquire_pcap_rejects_directory(tmp_path: Path) -> None:
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    with pytest.raises(PcapAcquisitionError):
        acquire_pcap(paths, tmp_path)


def test_acquire_pcap_rejects_symlink(tmp_path: Path) -> None:
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    real = tmp_path / "real.pcap"
    real.write_bytes(b"x" * 8)
    link = tmp_path / "link.pcap"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks unsupported on this filesystem")
    with pytest.raises(PcapAcquisitionError):
        acquire_pcap(paths, link)


def test_acquire_pcap_refuses_to_overwrite(tmp_path: Path) -> None:
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    src1 = tmp_path / "src1.pcap"
    src1.write_bytes(b"first")
    src2 = tmp_path / "src2.pcap"
    src2.write_bytes(b"second")
    acquire_pcap(paths, src1)
    with pytest.raises(PcapAcquisitionError):
        acquire_pcap(paths, src2)
    # Original file is preserved
    assert (paths.raw / "capture.pcap").read_bytes() == b"first"


def test_acquire_does_not_modify_source(tmp_path: Path) -> None:
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    src = tmp_path / "src.pcap"
    original = b"x" * 4096
    src.write_bytes(original)
    acquire_pcap(paths, src)
    assert src.read_bytes() == original
