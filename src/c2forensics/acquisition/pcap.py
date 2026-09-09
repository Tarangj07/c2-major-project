"""PCAP acquisition.

This module is the only place in the framework that writes to the
``raw/`` subtree of an experiment. The PCAP is treated as immutable
evidence from the moment acquisition completes; the extractor in
``extraction/pcap/`` only ever reads it.

Acquisition performs three actions, in order:

1. Validate the source path: it must exist, be a regular file, and be
   non-empty. A zero-byte file is treated as a malformed PCAP, not a
   valid empty capture.
2. Copy the source into the experiment at ``raw/capture.pcap`` so the
   experiment owns a stable path. The copy is a bit-for-bit copy, not
   a re-encoding.
3. Hash the resulting file and update the experiment metadata with the
   SHA-256 digest. The framework reuses the Phase 1
   ``record_raw_hashes`` helper so that the on-disk layout and the
   metadata schema remain unchanged.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from c2forensics.errors import C2ForensicsError
from c2forensics.experiment import record_raw_hashes
from c2forensics.hashing import hash_file
from c2forensics.logging import get_logger
from c2forensics.paths import ExperimentPaths

_logger = get_logger("c2forensics.acquisition.pcap")

PCAP_FILENAME = "capture.pcap"


class PcapAcquisitionError(C2ForensicsError):
    """Raised when a PCAP cannot be acquired into an experiment."""


def _validate_source(src: Path) -> None:
    """Reject missing, empty, or non-regular source files.

    A directory or a symlink to a non-existent file is also rejected; the
    framework does not follow symlinks during acquisition so that the
    on-disk artefact is always a real file.

    The check is performed against the *original* path so that a
    symlink to a valid file is still rejected. We deliberately do
    *not* call ``Path.resolve()`` before this check, because
    ``resolve()`` follows symlinks and would mask the rejection.
    """
    if not src.exists():
        raise PcapAcquisitionError(f"pcap source does not exist: {src}")
    if src.is_symlink():
        raise PcapAcquisitionError(f"pcap source is a symlink; refusing: {src}")
    if not src.is_file():
        raise PcapAcquisitionError(f"pcap source is not a regular file: {src}")
    if src.stat().st_size == 0:
        raise PcapAcquisitionError(f"pcap source is empty: {src}")


def _copy_to_raw(src: Path, dest: Path) -> None:
    """Bit-for-bit copy ``src`` to ``dest`` with metadata preserved."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    # ``shutil.copy2`` preserves metadata, but we deliberately do not
    # trust the source's mtime/atime in the experiment record. The
    # framework records its own acquisition timestamp via ``record_raw_hashes``.
    shutil.copy2(src, dest)


def acquire_pcap(paths: ExperimentPaths, source: Path) -> str:
    """Acquire a PCAP into ``paths.raw / capture.pcap`` and hash it.

    Returns the SHA-256 digest of the on-disk file (post-copy). The
    experiment metadata is updated with the digest.
    """
    # We check the original path first so that symlinks are rejected
    # before any follow happens.
    _validate_source(source)
    src = source.expanduser().resolve()
    dest = paths.raw / PCAP_FILENAME
    if dest.exists():
        # The experiment already has a PCAP. Refuse to overwrite raw
        # evidence; the operator must move it aside explicitly.
        raise PcapAcquisitionError(
            f"pcap already acquired at {dest}; refusing to overwrite raw evidence"
        )
    _copy_to_raw(src, dest)
    record_raw_hashes(paths, pcap_path=dest)
    digest = hash_file(dest)
    _logger.info(
        "pcap acquired",
        extra={
            "experiment_id": paths.root.name,
            "pcap_path": str(dest),
            "sha256": digest,
        },
    )
    return digest
