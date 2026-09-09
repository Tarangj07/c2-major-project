"""Experiment I/O.

The framework keeps a single source of truth for each experiment:
``metadata.json`` at the experiment root. Every stage reads and updates
that file in well-defined, atomic ways. Ground truth is optional and
lives in its own file; it is read by the evaluation stage and never by
the forensic pipeline.
"""

from __future__ import annotations

import json
import os
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from c2forensics.hashing import hash_file
from c2forensics.logging import get_logger
from c2forensics.models.experiment import (
    ExperimentMetadata,
    ExperimentStatus,
    ToolVersions,
)
from c2forensics.paths import ExperimentPaths

_logger = get_logger("c2forensics.experiment")

_EXPERIMENT_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


def utcnow() -> datetime:
    """Return a UTC ``datetime`` with explicit ``tzinfo=UTC``."""
    return datetime.now(tz=timezone.utc)


def validate_experiment_id(experiment_id: str) -> str:
    """Validate an experiment ID; raise ``ValueError`` if it is not safe."""
    if not _EXPERIMENT_ID_PATTERN.fullmatch(experiment_id):
        raise ValueError(
            f"invalid experiment_id {experiment_id!r}: must match "
            r"^[A-Za-z][A-Za-z0-9_-]{0,63}$"
        )
    return experiment_id


def detect_tool_versions(volatility3_binary: str | None) -> ToolVersions:
    """Capture tool versions for reproducibility.

    We never *execute* the binaries here; we only call ``--version`` if the
    binary is on ``PATH``. If the binary is missing, the version field is
    left as ``None`` rather than fabricating a value.
    """
    from c2forensics import __version__ as framework_version

    def _safe_version(binary: str | None) -> str | None:
        if not binary:
            return None
        import shutil
        import subprocess

        resolved = shutil.which(binary)
        if resolved is None:
            return None
        try:
            out = subprocess.run(  # noqa: S603 - controlled input
                [resolved, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        text = (out.stdout or out.stderr).strip()
        return text.splitlines()[0] if text else None

    return ToolVersions(
        python=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        tshark=_safe_version("tshark"),
        volatility3=_safe_version(volatility3_binary),
        framework=framework_version,
        os=f"{platform.system()} {platform.release()}",
    )


def init_experiment(
    *,
    repo_root: Path,
    experiment_id: str,
    description: str = "",
    target_host: str | None = None,
    c2_server_host: str | None = None,
    c2_server_port: int | None = None,
    config_snapshot: dict[str, Any] | None = None,
    tags: list[str] | None = None,
) -> ExperimentPaths:
    """Create the directory tree and ``metadata.json`` for a new experiment.

    Idempotent on the directory level: if the experiment already exists,
    its ``metadata.json`` is left untouched and the existing paths are
    returned. The framework never overwrites raw evidence.
    """
    validate_experiment_id(experiment_id)
    paths = ExperimentPaths.for_experiment(repo_root, experiment_id)
    paths.ensure_directories()
    paths.raw.mkdir(parents=True, exist_ok=True)
    paths.memory.mkdir(parents=True, exist_ok=True)

    if paths.metadata_file.exists():
        _logger.info(
            "experiment already initialised",
            extra={"experiment_id": experiment_id, "metadata_file": str(paths.metadata_file)},
        )
        return paths

    now = utcnow()
    metadata = ExperimentMetadata(
        experiment_id=experiment_id,
        created_at=now,
        updated_at=now,
        description=description,
        target_host=target_host,
        c2_server_host=c2_server_host,
        c2_server_port=c2_server_port,
        config_snapshot=config_snapshot or {},
        tags=list(tags or []),
    )
    write_metadata(paths, metadata)
    _logger.info("experiment initialised", extra={"experiment_id": experiment_id})
    return paths


def write_metadata(paths: ExperimentPaths, metadata: ExperimentMetadata) -> None:
    """Atomically write ``metadata.json``.

    The write goes to a temporary file in the same directory and is then
    renamed. This ensures that an interrupted write never leaves a
    half-written file in place.
    """
    paths.root.mkdir(parents=True, exist_ok=True)
    tmp = paths.metadata_file.with_suffix(paths.metadata_file.suffix + ".tmp")
    payload = metadata.model_dump(mode="json")
    payload["updated_at"] = utcnow().isoformat()
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, paths.metadata_file)
    _logger.info("metadata written", extra={"path": str(paths.metadata_file)})


def read_metadata(paths: ExperimentPaths) -> ExperimentMetadata:
    """Load and validate ``metadata.json``."""
    if not paths.metadata_file.is_file():
        raise FileNotFoundError(f"metadata.json not found at {paths.metadata_file}")
    with paths.metadata_file.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return ExperimentMetadata.model_validate(data)


def update_status(
    paths: ExperimentPaths,
    new_status: ExperimentStatus,
) -> ExperimentMetadata:
    """Update the lifecycle status of an experiment and persist it."""
    current = read_metadata(paths)
    if current.status == new_status:
        return current
    updated = current.model_copy(update={"status": new_status})
    write_metadata(paths, updated)
    return updated


def record_raw_hashes(
    paths: ExperimentPaths,
    *,
    pcap_path: Path | None = None,
) -> ExperimentMetadata:
    """Hash the PCAP (and, in later phases, the memory dump) and update metadata.

    Only the PCAP is hashed in Phase 1 because memory acquisition is not
    yet implemented. The function is written to be additive: future phases
    will pass additional paths and they will all be hashed.
    """
    current = read_metadata(paths)
    new_hashes = dict(current.raw_hashes)
    if pcap_path is not None:
        if not pcap_path.is_file():
            raise FileNotFoundError(f"pcap not found: {pcap_path}")
        rel = pcap_path.relative_to(paths.root).as_posix()
        new_hashes[rel] = hash_file(pcap_path)
        _logger.info("hashed pcap", extra={"path": rel})
    updated = current.model_copy(update={"raw_hashes": new_hashes})
    write_metadata(paths, updated)
    return updated
