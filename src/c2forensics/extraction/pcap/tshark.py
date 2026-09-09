"""Safe subprocess wrapper for tshark.

This module is the only place in the framework that invokes tshark.
The wrapper:

* never uses ``shell=True``;
* always passes the PCAP path as a single argv element;
* never modifies the input PCAP (read-only access by convention);
* captures stdout and stderr separately so the caller can surface
  them in errors without losing information;
* enforces a hard timeout from the lab configuration;
* returns a parsed JSON object (or raises a typed error) so that the
  downstream parser never has to deal with shell quoting or text
  parsing of tshark's human-readable output.

The tshark version is captured separately so that an extractor run
can record the exact toolchain version that produced the evidence.
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

_logger = get_logger("c2forensics.extraction.pcap.tshark")


class TsharkError(C2ForensicsError):
    """Raised when tshark exits non-zero, times out, or returns invalid JSON."""


class TsharkNotFoundError(ToolNotFoundError):
    """Raised when the tshark binary cannot be located on ``PATH``."""


@dataclass(frozen=True)
class TsharkInvocation:
    """Parameters for a single tshark invocation.

    Keeping these in a small frozen record makes the wrapper easy to
    test in isolation: the test can construct a ``TsharkInvocation``
    and assert on the resulting argv list without ever running a
    subprocess.
    """

    binary: str
    read_filter: str
    display_fields: tuple[str, ...]
    timeout_seconds: int
    pcap_path: Path

    def to_argv(self) -> list[str]:
        """Materialise the full argv list.

        The order is stable so that tests can compare invocations
        exactly: ``-r <pcap> -T fields -E separator=/t -E occurrence=f
        -E aggregator=, -Y <filter> <fields...>``.
        """
        argv: list[str] = [self.binary]
        argv += ["-r", str(self.pcap_path)]
        argv += ["-T", "fields"]
        argv += ["-E", "separator=/t"]
        argv += ["-E", "occurrence=f"]
        argv += ["-E", "aggregator=,"]
        argv += ["-Y", self.read_filter]
        for field in self.display_fields:
            argv += ["-e", field]
        # No -V, no -x; we only need machine-readable fields.
        return argv


@dataclass(frozen=True)
class TsharkResult:
    """A successful tshark invocation result."""

    fields: list[list[str]]
    raw_stdout: str
    raw_stderr: str
    return_code: int
    version: str


def resolve_binary(name_or_path: str) -> str:
    """Resolve a tshark binary name (or absolute path) to an executable path.

    Raises ``TsharkNotFoundError`` if the binary is not on ``PATH`` and
    not an absolute path that exists.
    """
    if not name_or_path:
        raise TsharkNotFoundError("tshark binary name is empty")
    # If the caller passed an absolute path, trust it.
    if "/" in name_or_path or "\\" in name_or_path:
        p = Path(name_or_path).expanduser()
        if p.is_file() and not p.is_symlink():
            return str(p)
        raise TsharkNotFoundError(f"tshark binary not found at {p}")
    resolved = shutil.which(name_or_path)
    if resolved is None:
        raise TsharkNotFoundError(f"tshark binary not found on PATH: {name_or_path!r}")
    return resolved


def get_version(binary: str) -> str:
    """Return the first line of ``<binary> --version``.

    On failure, returns ``"unknown"`` rather than raising. The extractor
    records whatever it gets so the experiment metadata is honest about
    its provenance.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - controlled argv
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _logger.warning("tshark --version failed", extra={"error": str(exc)})
        return "unknown"
    text = (proc.stdout or proc.stderr).strip()
    return text.splitlines()[0] if text else "unknown"


def _validate_invocation(inv: TsharkInvocation) -> None:
    if inv.timeout_seconds <= 0:
        raise TsharkError(f"timeout must be > 0, got {inv.timeout_seconds}")
    if not inv.pcap_path.is_file():
        raise TsharkError(f"pcap is not a regular file: {inv.pcap_path}")


def _parse_fields_output(raw_stdout: str, field_count: int) -> list[list[str]]:
    """Parse ``-T fields -E separator=/t`` output into rows.

    tshark emits one row per packet. Empty lines are skipped (tshark
    can emit them when the read filter matches nothing). Each row is
    split on the literal tab character. A row with fewer fields than
    expected is left-padded with empty strings; this matches the
    behaviour of tshark when a field is absent for a given packet.
    """
    rows: list[list[str]] = []
    for line in raw_stdout.splitlines():
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < field_count:
            parts = parts + [""] * (field_count - len(parts))
        elif len(parts) > field_count:
            parts = parts[:field_count]
        rows.append(parts)
    return rows


def run_fields(inv: TsharkInvocation) -> TsharkResult:
    """Run a tshark invocation and return its parsed output.

    The invocation is validated first (timeout, PCAP existence) and
    the binary is resolved after, so that argument-validation errors
    are surfaced even when tshark is not installed. The output is
    parsed into rows of strings, not into typed records; typed
    parsing is the parser's job.
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
        raise TsharkError(
            f"tshark timed out after {inv.timeout_seconds}s on {inv.pcap_path}"
        ) from exc
    except OSError as exc:
        raise TsharkError(f"tshark could not be executed: {exc}") from exc

    if proc.returncode != 0:
        # Truncate stderr to keep the error message readable.
        snippet = (proc.stderr or "").strip().splitlines()[-5:]
        raise TsharkError(
            f"tshark exited with code {proc.returncode} on {inv.pcap_path}: "
            + " | ".join(snippet)
        )

    rows = _parse_fields_output(proc.stdout, field_count=len(inv.display_fields))
    return TsharkResult(
        fields=rows,
        raw_stdout=proc.stdout,
        raw_stderr=proc.stderr,
        return_code=proc.returncode,
        version=version,
    )


# ---------------------------------------------------------------------------
# JSON-mode tshark wrapper (used only by the JSON emitter, not by the
# default field-based extractor). Kept for future expansion; the default
# extractor uses ``-T fields`` which is more portable across tshark
# versions than ``-T json``.
# ---------------------------------------------------------------------------


def _parse_json_output(raw_stdout: str) -> list[dict[str, Any]]:
    """Parse ``-T json`` output into a list of frame dicts.

    tshark emits a single JSON array. Empty captures yield ``[]``.
    """
    text = raw_stdout.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise TsharkError(f"tshark emitted invalid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise TsharkError("tshark JSON output must be a top-level array")
    return data
