"""Unit tests for filesystem path helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from c2forensics.paths import (
    CORRELATION_DIR,
    EVALUATION_DIR,
    EXTRACTED_DIR,
    MEMORY_SUBDIR,
    NORMALIZED_DIR,
    RAW_DIR,
    RECONSTRUCTION_DIR,
    TIMELINE_DIR,
    ExperimentPaths,
)


def test_paths_layout_has_expected_subdirs() -> None:
    paths = ExperimentPaths.for_experiment(Path("/tmp/repo"), "EXP001")
    assert paths.raw.name == RAW_DIR
    assert paths.memory.name == MEMORY_SUBDIR
    assert paths.extracted.name == EXTRACTED_DIR
    assert paths.normalized.name == NORMALIZED_DIR
    assert paths.correlation.name == CORRELATION_DIR
    assert paths.reconstruction.name == RECONSTRUCTION_DIR
    assert paths.timeline.name == TIMELINE_DIR
    assert paths.evaluation.name == EVALUATION_DIR


def test_paths_rejects_path_traversal() -> None:
    with pytest.raises(ValueError):
        ExperimentPaths.for_experiment(Path("/tmp/repo"), "../EXP001")
    with pytest.raises(ValueError):
        ExperimentPaths.for_experiment(Path("/tmp/repo"), "EXP001/sub")


def test_ensure_directories_creates_derived_but_not_raw() -> None:
    paths = ExperimentPaths.for_experiment(Path("/tmp/repo"), "EXP001")
    paths.ensure_directories()
    # Derived dirs exist
    for d in (
        paths.extracted,
        paths.normalized,
        paths.correlation,
        paths.reconstruction,
        paths.timeline,
        paths.evaluation,
    ):
        assert d.is_dir()
    # Raw is *not* created here; the acquisition stage creates it.
    assert not paths.raw.exists()
    assert not paths.memory.exists()
