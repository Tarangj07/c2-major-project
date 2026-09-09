"""SHA-256 evidence hashing.

Every piece of raw evidence is hashed at acquisition time so that later
analyses can verify they are operating on the original artefact and not
on a corrupted copy. The framework supports hashing of a single file or
of an entire directory tree.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterator


CHUNK_SIZE = 1024 * 1024  # 1 MiB; large enough to amortise syscall overhead.


def hash_file(path: Path, *, algorithm: str = "sha256") -> str:
    """Compute the hex digest of ``path`` using ``algorithm``.

    The function reads the file in fixed-size chunks so that arbitrarily
    large memory dumps do not have to fit in RAM. It does not follow
    symlinks; following a symlink would risk hashing the wrong file.
    """
    if not path.is_file():
        raise FileNotFoundError(f"cannot hash: not a regular file: {path}")
    hasher = hashlib.new(algorithm)
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def iter_files(root: Path) -> Iterator[Path]:
    """Yield every regular file under ``root`` in deterministic order.

    Symlinks are not followed. The walk is sorted so that two runs over
    the same directory produce identical digests.
    """
    if not root.exists():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            yield path


def hash_directory(root: Path, *, algorithm: str = "sha256") -> dict[str, str]:
    """Hash every regular file under ``root`` and return a relative-path map.

    Keys are POSIX-style paths relative to ``root``, e.g.
    ``"memory/mem.raw"``. This is the format stored in
    ``ExperimentMetadata.raw_hashes``.
    """
    if not root.is_dir():
        raise NotADirectoryError(f"cannot hash: not a directory: {root}")
    return {
        str(path.relative_to(root)).replace("\\", "/"): hash_file(path, algorithm=algorithm)
        for path in iter_files(root)
    }
