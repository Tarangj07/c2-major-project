"""Safe subprocess wrapper for Volatility 3.

Volatility 3 is treated as an external forensic tool, just as
tshark is. This module is the only place in the framework that
invokes the Volatility CLI; downstream code consumes typed records
produced by the parser, never raw Volatility output.

The wrapper:

* never uses ``shell=True``;
* always passes the memory-image path as a single argv element;
* enforces a hard timeout from the lab configuration;
* captures stdout and stderr separately so the caller can surface
  them in errors without losing information;
* returns parsed JSON (or raises a typed error) so the downstream
  parser never has to deal with terminal formatting.

Volatility 3 is invoked as ``vol -f <image> -r json <plugin>``.
The framework assumes a recent Volatility 3 release. Older
versions are not supported.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from c2forensics.errors import C2ForensicsError, ToolNotFoundError
from c2forensics.logging import get_logger

_logger = get_logger("c2forensics.extraction.memory.volatility")


class VolatilityError(C2ForensicsError):
    """Raised when Volatility exits non-zero, times out, or returns invalid JSON."""


class VolatilityNotFoundError(ToolNotFoundError):
    """Raised when the Volatility binary cannot be located on ``PATH``."""


# ---------------------------------------------------------------------------
# Plugin and invocation types
# ---------------------------------------------------------------------------


# The set of plugins the framework actually invokes. Each plugin
# corresponds to a single evidence kind and produces a single
# normalised output. Adding a new plugin requires:
#
#   1. Adding the plugin name to this enum.
#   2. Implementing the corresponding parser in ``parser.py``.
#   3. Documenting the plugin in ``docs/memory-extraction.md``.
#
# The list is intentionally small. The framework does not claim
# comprehensive memory forensics; it produces only the evidence
# needed for the dissertation's RQ1 attribution question.
SUPPORTED_PLUGINS: tuple[str, ...] = (
    "windows.pslist.PsList",
    "windows.netscan.NetScan",
)


@dataclass(frozen=True)
class VolatilityInvocation:
    """Parameters for a single Volatility invocation.

    Keeping these in a small frozen record mirrors the tshark
    wrapper's design and makes the backend easy to unit-test:
    a test can construct a ``VolatilityInvocation`` and assert on
    the resulting argv list without ever running a subprocess.
    """

    binary: str
    image_path: Path
    plugin: str
    timeout_seconds: int

    def to_argv(self) -> list[str]:
        """Materialise the full argv list.

        ``-r json`` is the canonical machine-readable output mode
        in Volatility 3. The framework never invokes a plugin
        without ``-r json``; any plugin that cannot produce JSON
        is documented as not supported.
        """
        return [
            self.binary,
            "-q",
            "-f",
            str(self.image_path),
            "-r",
            "json",
            self.plugin,
        ]


@dataclass(frozen=True)
class VolatilityResult:
    """A successful Volatility invocation result."""

    rows: list[dict[str, Any]]
    raw_stdout: str
    raw_stderr: str
    return_code: int
    version: str
    plugin: str


# ---------------------------------------------------------------------------
# Binary resolution and version
# ---------------------------------------------------------------------------


def resolve_binary(name_or_path: str) -> str:
    """Resolve a Volatility binary name (or absolute path) to an executable.

    Raises :class:`VolatilityNotFoundError` if the binary is not
    on ``PATH`` and not an absolute path that exists. The wrapper
    trusts only non-symlink absolute paths; the operator may also
    pass a bare name like ``vol`` or ``vol3``.
    """
    if not name_or_path:
        raise VolatilityNotFoundError("volatility binary name is empty")
    if "/" in name_or_path or "\\" in name_or_path:
        p = Path(name_or_path).expanduser()
        if p.is_file() and not p.is_symlink():
            return str(p)
        raise VolatilityNotFoundError(f"volatility binary not found at {p}")
    resolved = shutil.which(name_or_path)
    if resolved is None:
        raise VolatilityNotFoundError(
            f"volatility binary not found on PATH: {name_or_path!r}"
        )
    return resolved


def get_version(binary: str) -> str:
    """Return the first line of ``<binary> --version`` if available.

    Volatility 3's ``vol`` does not implement ``--version``; the
    first non-empty line of ``vol -h`` is used as a proxy. The
    function returns ``"unknown"`` rather than raising so the
    extractor can record whatever it gets honestly.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - controlled argv
            [binary, "-h"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _logger.warning("volatility version probe failed", extra={"error": str(exc)})
        return "unknown"
    text = (proc.stdout or proc.stderr).strip()
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return "unknown"


# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------


def _validate_invocation(inv: VolatilityInvocation) -> None:
    if inv.timeout_seconds <= 0:
        raise VolatilityError(
            f"timeout must be > 0, got {inv.timeout_seconds}"
        )
    if not inv.image_path.is_file():
        raise VolatilityError(
            f"memory image is not a regular file: {inv.image_path}"
        )
    if inv.image_path.stat().st_size == 0:
        raise VolatilityError(
            f"memory image is empty: {inv.image_path}"
        )
    if inv.plugin not in SUPPORTED_PLUGINS:
        # The framework refuses plugins it does not know how to
        # parse. This is a deliberate guard: a silent fallback to
        # "best effort" parsing would surface wrong fields to the
        # user.
        raise VolatilityError(
            f"plugin not in SUPPORTED_PLUGINS: {inv.plugin!r}; "
            f"supported: {', '.join(SUPPORTED_PLUGINS)}"
        )


def _parse_json_output(raw_stdout: str) -> list[dict[str, Any]]:
    """Parse the JSON output of ``vol -r json <plugin>``.

    Volatility 3 emits a single JSON object per row when ``-r json``
    is used. Older Volatility 2 emits one JSON object per line.
    The framework supports both: a single top-level array is taken
    as-is; otherwise the input is split on newlines and each
    non-empty line is parsed.
    """
    text = raw_stdout.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try NDJSON: one JSON object per line.
        rows: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise VolatilityError(
                    f"volatility emitted invalid JSON: {exc}; first bad line: {line[:120]!r}"
                ) from exc
        return rows
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        return [data]
    raise VolatilityError(
        f"volatility JSON output must be a list or object, got {type(data).__name__}"
    )


def run_plugin(inv: VolatilityInvocation) -> VolatilityResult:
    """Run a Volatility plugin and return the parsed rows.

    The binary is resolved (raising
    :class:`VolatilityNotFoundError` if missing), the invocation is
    validated, and the configured plugin is invoked with ``-r json``.
    The output is parsed into a list of dictionaries; the
    type-specific parser (see :mod:`parser`) then narrows the rows
    into the framework's models.
    """
    _validate_invocation(inv)
    binary = resolve_binary(inv.binary)
    version = get_version(binary)
    argv = inv.to_argv()
    try:
        proc = subprocess.run(  # noqa: S603 - controlled argv, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=inv.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise VolatilityError(
            f"volatility timed out after {inv.timeout_seconds}s on {inv.image_path}"
        ) from exc
    except OSError as exc:
        raise VolatilityError(
            f"volatility could not be executed: {exc}"
        ) from exc

    if proc.returncode != 0:
        snippet = (proc.stderr or "").strip().splitlines()[-5:]
        raise VolatilityError(
            f"volatility exited with code {proc.returncode} on {inv.image_path} "
            f"(plugin {inv.plugin}): " + " | ".join(snippet)
        )

    rows = _parse_json_output(proc.stdout)
    return VolatilityResult(
        rows=rows,
        raw_stdout=proc.stdout,
        raw_stderr=proc.stderr,
        return_code=proc.returncode,
        version=version,
        plugin=inv.plugin,
    )
