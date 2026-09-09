"""Unit tests for memory-image acquisition."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from c2forensics.acquisition import (
    MemoryAcquisitionError,
    acquire_memory_image,
    list_acquired_images,
)
from c2forensics.experiment import init_experiment, read_metadata
from c2forensics.paths import ExperimentPaths


def _init(tmp_path: Path) -> ExperimentPaths:
    """Initialise an experiment and return its :class:`ExperimentPaths`."""
    return init_experiment(repo_root=tmp_path, experiment_id="EXP001")


def test_acquire_memory_image_copies_and_hashes(tmp_path: Path) -> None:
    paths = _init(tmp_path)
    src = tmp_path / "mem.raw"
    src.write_bytes(b"some-memory-bytes")

    digest = acquire_memory_image(paths, src)
    images = list_acquired_images(paths)
    assert len(images) == 1
    img = images[0]
    assert img.is_file()
    assert img.read_bytes() == b"some-memory-bytes"
    assert len(digest) == 64
    # The metadata records the hash for the on-disk path.
    from c2forensics.hashing import hash_file
    assert hash_file(img) == digest


def test_acquire_memory_image_rejects_missing_source(tmp_path: Path) -> None:
    paths = _init(tmp_path)
    with pytest.raises(MemoryAcquisitionError):
        acquire_memory_image(paths, tmp_path / "nope.raw")


def test_acquire_memory_image_rejects_empty_source(tmp_path: Path) -> None:
    paths = _init(tmp_path)
    src = tmp_path / "empty.raw"
    src.write_bytes(b"")
    with pytest.raises(MemoryAcquisitionError):
        acquire_memory_image(paths, src)


def test_acquire_memory_image_rejects_directory(tmp_path: Path) -> None:
    paths = _init(tmp_path)
    with pytest.raises(MemoryAcquisitionError):
        acquire_memory_image(paths, tmp_path)


def test_acquire_memory_image_rejects_symlink(tmp_path: Path) -> None:
    paths = _init(tmp_path)
    real = tmp_path / "real.raw"
    real.write_bytes(b"x" * 16)
    link = tmp_path / "link.raw"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks unsupported on this filesystem")
    with pytest.raises(MemoryAcquisitionError):
        acquire_memory_image(paths, link)


def test_acquire_memory_image_refuses_overwrite(tmp_path: Path) -> None:
    paths = _init(tmp_path)
    src1 = tmp_path / "first.raw"
    src1.write_bytes(b"first")
    src2 = tmp_path / "second.raw"
    src2.write_bytes(b"second")
    acquire_memory_image(paths, src1)
    # Second acquire of the same file name refuses.
    src1_again = tmp_path / "first.raw"
    src1_again.write_bytes(b"first-modified")
    with pytest.raises(MemoryAcquisitionError):
        acquire_memory_image(paths, src1_again)
    # The on-disk file is the original bytes.
    images = list_acquired_images(paths)
    assert images[0].read_bytes() == b"first"


def test_acquire_memory_image_preserves_source(tmp_path: Path) -> None:
    paths = _init(tmp_path)
    src = tmp_path / "src.raw"
    original = b"x" * 4096
    src.write_bytes(original)
    acquire_memory_image(paths, src)
    assert src.read_bytes() == original


def test_acquire_memory_image_with_dest_name_override(tmp_path: Path) -> None:
    paths = _init(tmp_path)
    src = tmp_path / "src.raw"
    src.write_bytes(b"with override")
    digest = acquire_memory_image(paths, src, dest_name="lab-baseline.raw")
    images = list_acquired_images(paths)
    assert images[0].name == "lab-baseline.raw"
    assert images[0].read_bytes() == b"with override"
    assert len(digest) == 64


def test_acquire_memory_image_rejects_unsafe_dest_name(tmp_path: Path) -> None:
    paths = _init(tmp_path)
    src = tmp_path / "src.raw"
    src.write_bytes(b"x")
    with pytest.raises(MemoryAcquisitionError):
        acquire_memory_image(paths, src, dest_name="../escape.raw")
    with pytest.raises(MemoryAcquisitionError):
        acquire_memory_image(paths, src, dest_name="subdir/file.raw")


def test_acquire_memory_image_records_metadata_hash(tmp_path: Path) -> None:
    paths = _init(tmp_path)
    src = tmp_path / "src.raw"
    src.write_bytes(b"hash me")
    digest = acquire_memory_image(paths, src)
    meta = read_metadata(paths)
    # The on-disk path under raw/memory/ is the key.
    keys = [k for k in meta.raw_hashes if k.startswith("raw/memory/")]
    assert len(keys) == 1
    assert meta.raw_hashes[keys[0]] == digest
