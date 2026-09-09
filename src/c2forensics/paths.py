"""Filesystem layout helpers for the framework.

This module is the single place that knows how an experiment directory is
laid out on disk. The on-disk layout is:

    <repo_root>/experiments/<EXPERIMENT_ID>/
        metadata.json
        ground-truth.json
        raw/
            capture.pcap
            memory/
        extracted/
        normalized/
        correlation/
        reconstruction/
        timeline/
        evaluation/

The framework never hard-codes these names anywhere else. If the layout
changes, only this module and the YAML config need to be updated.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


# Subdirectory names. They match the YAML config but are also the source of
# truth used by the path helpers below; the YAML simply documents them.
RAW_DIR = "raw"
EXTRACTED_DIR = "extracted"
NORMALIZED_DIR = "normalized"
CORRELATION_DIR = "correlation"
RECONSTRUCTION_DIR = "reconstruction"
TIMELINE_DIR = "timeline"
EVALUATION_DIR = "evaluation"
MEMORY_SUBDIR = "memory"

# File names inside the experiment root.
METADATA_FILE = "metadata.json"
GROUND_TRUTH_FILE = "ground-truth.json"


@dataclass(frozen=True)
class ExperimentPaths:
    """Resolved paths for a single experiment.

    The framework never writes to ``raw_dir`` after acquisition; that
    directory is treated as immutable evidence. The other directories are
    safe to overwrite because they are derived products.
    """

    root: Path
    raw: Path
    memory: Path
    extracted: Path
    normalized: Path
    correlation: Path
    reconstruction: Path
    timeline: Path
    evaluation: Path
    metadata_file: Path
    ground_truth_file: Path

    @classmethod
    def for_experiment(cls, repo_root: Path, experiment_id: str) -> "ExperimentPaths":
        """Resolve all paths for a given experiment under ``repo_root``.

        ``repo_root`` is typically the parent of the ``experiments/``
        directory. The function does not perform any I/O; it only computes
        paths.
        """
        if not experiment_id or "/" in experiment_id or "\\" in experiment_id:
            raise ValueError(f"invalid experiment_id: {experiment_id!r}")
        root = repo_root / "experiments" / experiment_id
        return cls(
            root=root,
            raw=root / RAW_DIR,
            memory=root / RAW_DIR / MEMORY_SUBDIR,
            extracted=root / EXTRACTED_DIR,
            normalized=root / NORMALIZED_DIR,
            correlation=root / CORRELATION_DIR,
            reconstruction=root / RECONSTRUCTION_DIR,
            timeline=root / TIMELINE_DIR,
            evaluation=root / EVALUATION_DIR,
            metadata_file=root / METADATA_FILE,
            ground_truth_file=root / GROUND_TRUTH_FILE,
        )

    def ensure_directories(self) -> None:
        """Create the derived directories if they do not yet exist.

        Note that this does not create ``raw`` or ``memory``; those are
        created by the acquisition stage, not the framework core.
        """
        for d in (
            self.extracted,
            self.normalized,
            self.correlation,
            self.reconstruction,
            self.timeline,
            self.evaluation,
        ):
            d.mkdir(parents=True, exist_ok=True)
