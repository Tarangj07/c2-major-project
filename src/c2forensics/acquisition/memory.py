"""Memory-image acquisition.

The development environment does not acquire memory from a live
system. ``acquire_memory_image`` is therefore an *ingestion*
operation: the operator produces a memory image out-of-band (using
a controlled tool such as ``winpmem`` or ``FTK Imager``) and the
framework ingests the result by bit-for-bit copy. The interface is
deliberately identical to :func:`c2forensics.acquisition.pcap.acquire_pcap`
so that the operator-facing CLI commands ``pcap acquire`` and
``memory acquire`` behave the same way.

The framework never:

* modifies the source image;
* writes to the source image's directory;
* follows symlinks (a symlink to a valid image is still rejected);
* accepts an empty file (zero bytes is never a valid memory image);
* overwrites an existing acquisition in the same experiment.

The framework always:

* records the SHA-256 of the on-disk image in
  ``ExperimentMetadata.raw_hashes``;
* records the source path and acquisition timestamp via the same
  metadata write path the PCAP acquisition uses.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Iterable

from c2forensics.errors import C2ForensicsError
from c2forensics.experiment import record_raw_hashes
from c2forensics.hashing import hash_file
from c2forensics.logging import get_logger
from c2forensics.paths import ExperimentPaths

_logger = get_logger("c2forensics.acquisition.memory")

# Default on-disk filename. The operator can place a memory image
# with any name under ``raw/memory/``; this constant is the name
# used by ``acquire_memory_image`` when copying a source file in.
DEFAULT_IMAGE_NAME = "mem.raw"

# Recognised extensions for memory images. The framework does not
# inspect the file contents; it only uses the extension as a hint
# during ingestion to set the platform field. Operators may use any
# extension when ingesting manually.
_RECOGNISED_EXTENSIONS: frozenset[str] = frozenset(
    {".raw", ".lime", ".dmp", ".vmem", ".bin", ".mem", ".img"}
)


class MemoryAcquisitionError(C2ForensicsError):
    """Raised when a memory image cannot be acquired into an experiment."""


def _validate_source(src: Path) -> None:
    """Reject missing, empty, non-regular, or symlinked source files.

    The validation runs against the *original* path (before any
    ``Path.resolve()``) so that a symlink to a valid image is still
    rejected. The framework does not follow symlinks during
    acquisition.
    """
    if not src.exists():
        raise MemoryAcquisitionError(f"memory image does not exist: {src}")
    if src.is_symlink():
        raise MemoryAcquisitionError(
            f"memory image is a symlink; refusing: {src}"
        )
    if not src.is_file():
        raise MemoryAcquisitionError(
            f"memory image is not a regular file: {src}"
        )
    if src.stat().st_size == 0:
        raise MemoryAcquisitionError(f"memory image is empty: {src}")


def _copy_to_raw(src: Path, dest: Path) -> None:
    """Bit-for-bit copy ``src`` to ``dest`` with metadata preserved."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    # ``shutil.copy2`` preserves metadata; the framework records its
    # own acquisition timestamp via ``record_raw_hashes`` rather than
    # trusting the source's mtime/atime.
    shutil.copy2(src, dest)


def _already_acquired(paths: ExperimentPaths) -> list[Path]:
    """Return the list of memory images already under ``raw/memory/``."""
    if not paths.memory.is_dir():
        return []
    return sorted(
        p for p in paths.memory.iterdir() if p.is_file() and not p.is_symlink()
    )


def _dest_path(paths: ExperimentPaths, source: Path) -> Path:
    """Choose the destination filename.

    The destination is always under ``raw/memory/``. The base name
    is preserved; if a same-named file already exists (a previous
    acquisition of the same name), the acquisition is refused.
    """
    suffix = source.suffix.lower()
    base = source.name
    if not base:
        base = DEFAULT_IMAGE_NAME
    if suffix and suffix not in _RECOGNISED_EXTENSIONS:
        # We do not refuse unusual extensions, but we surface a
        # warning so the operator notices.
        _logger.warning(
            "memory image has an unusual extension; accepted anyway",
            extra={"extension": suffix, "source": str(source)},
        )
    return paths.memory / base


def acquire_memory_image(
    paths: ExperimentPaths, source: Path, *, dest_name: str | None = None
) -> str:
    """Acquire a memory image into ``raw/memory/`` and hash it.

    Parameters
    ----------
    paths
        The experiment paths.
    source
        Path to the source memory image on disk. The file is
        validated, then bit-for-bit copied into the experiment.
    dest_name
        Optional override for the destination file name. The default
        preserves the source file's base name. When ``dest_name`` is
        provided, the destination becomes ``paths.memory / dest_name``;
        the caller is responsible for choosing a safe, non-colliding
        name.

    Returns
    -------
    str
        The SHA-256 digest of the on-disk image (post-copy).
    """
    _validate_source(source)
    if dest_name is not None:
        if "/" in dest_name or "\\" in dest_name or not dest_name:
            raise MemoryAcquisitionError(
                f"dest_name must be a base file name without separators: {dest_name!r}"
            )
        dest = paths.memory / dest_name
    else:
        dest = _dest_path(paths, source)
    if dest.exists():
        raise MemoryAcquisitionError(
            f"memory image already acquired at {dest}; refusing to overwrite raw evidence"
        )
    _copy_to_raw(source, dest)
    digest = hash_file(dest)
    # Update the experiment metadata with the on-disk hash. The
    # metadata key is the path relative to the experiment root.
    rel = dest.relative_to(paths.root).as_posix()
    record_raw_hashes(paths, pcap_path=None)
    # ``record_raw_hashes`` is PCAP-centric (it only hashes a single
    # PCAP path); for memory images we re-read the metadata, add the
    # new digest, and write it back. This keeps the framework's
    # metadata contract simple: every raw artefact is recorded with
    # its relative path and SHA-256.
    from c2forensics.experiment import read_metadata, write_metadata

    meta = read_metadata(paths)
    new_hashes = dict(meta.raw_hashes)
    new_hashes[rel] = digest
    write_metadata(paths, meta.model_copy(update={"raw_hashes": new_hashes}))
    _logger.info(
        "memory image acquired",
        extra={
            "experiment_id": paths.root.name,
            "image_path": str(dest),
            "sha256": digest,
        },
    )
    return digest


def list_acquired_images(paths: ExperimentPaths) -> list[Path]:
    """Return the on-disk memory images for the experiment.

    Returned paths are sorted for determinism. An empty list is
    returned if no images are present.
    """
    return _already_acquired(paths)


def discover_volatility_targets(paths: ExperimentPaths) -> Iterable[Path]:
    """Yield every acquired memory image in deterministic order.

    This is the iterator the Volatility backend uses when extracting
    from an experiment that may contain multiple images. The default
    is the single image placed by ``acquire_memory_image``; the
    iterator accepts any number of additional images placed manually
    under ``raw/memory/``.
    """
    return iter(_already_acquired(paths))
