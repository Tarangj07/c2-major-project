"""Unit tests for evidence hashing."""

from __future__ import annotations

from pathlib import Path

import pytest

from c2forensics.hashing import hash_directory, hash_file


def test_hash_file_known_vector(tmp_path: Path) -> None:
    # SHA-256 of empty input
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    assert hash_file(f) == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_hash_file_known_vector_abc(tmp_path: Path) -> None:
    f = tmp_path / "abc.txt"
    f.write_bytes(b"abc")
    assert hash_file(f) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_hash_file_missing(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        hash_file(tmp_path / "nope")


def test_hash_directory_walks_in_order(tmp_path: Path) -> None:
    (tmp_path / "memory").mkdir()
    (tmp_path / "capture.pcap").write_bytes(b"pcap-bytes")
    (tmp_path / "memory" / "mem.raw").write_bytes(b"mem-bytes")
    digests = hash_directory(tmp_path)
    assert set(digests.keys()) == {"capture.pcap", "memory/mem.raw"}
    # Different content -> different digests
    assert digests["capture.pcap"] != digests["memory/mem.raw"]


def test_hash_directory_missing(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        hash_directory(tmp_path / "nope")
