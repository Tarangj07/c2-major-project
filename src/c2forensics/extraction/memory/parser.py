"""Pure-functional parser: Volatility JSON rows -> typed memory artefacts.

This module never invokes subprocesses and never touches the
filesystem. It accepts the JSON output of Volatility 3 plugins
(:class:`VolatilityResult.rows`) and emits typed
:class:`ProcessArtifact`, :class:`SocketArtifact`, and
:class:`TLSArtifact` records together with explicit
:class:`MemoryArtifactEnvelope` envelopes for the per-plugin view.

The parser is deliberately conservative: any field that cannot be
parsed is left as ``None`` and recorded in the per-plugin
diagnostics, so the caller can decide how to handle partial
information. The parser never fabricates a value.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from c2forensics.models.artifact import ArtifactProvenance, ArtifactSource
from c2forensics.models.memory import (
    MemoryArtifactEnvelope,
    MemoryExtractionStatus,
)
from c2forensics.models.process import ProcessArtifact
from c2forensics.models.socket import SocketArtifact
from c2forensics.models.tls import TLSArtifact


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _pick(row: dict[str, Any], *candidates: str) -> Any:
    """Return the first present value among the candidate keys.

    Volatility 3 column names have varied across releases; the
    parser is defensive against the small set of known aliases.
    Empty strings and ``None`` are treated as absent.
    """
    for c in candidates:
        if c in row:
            v = row[c]
            if v is None:
                continue
            if isinstance(v, str) and not v.strip():
                continue
            return v
    return None


def _parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.lower().startswith("0x"):
            try:
                return int(s, 16)
            except ValueError:
                return None
        try:
            return int(s)
        except ValueError:
            return None
    return None


def _parse_datetime(value: Any) -> datetime | None:
    """Parse a Volatility timestamp string into a UTC ``datetime``.

    Volatility 3 emits timestamps in the form
    ``"2023-11-14 22:13:20.000000"`` (no timezone). We treat the
    timestamp as UTC because the host clock captured the local
    time at the moment of memory acquisition and Volatility does
    not currently emit a timezone offset.

    A timestamp containing a timezone offset (``+00:00`` or ``Z``)
    is parsed via :func:`datetime.fromisoformat` after
    normalisation.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or s.lower() in ("null", "none", "n/a"):
        return None
    # Replace trailing "Z" so fromisoformat handles it on all Pythons.
    iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
    try:
        # Volatility 3 timestamps are space-separated, not T-separated.
        # fromisoformat in Python 3.11+ accepts both, but be safe:
        if " " in iso and "T" not in iso:
            iso = iso.replace(" ", "T", 1)
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # Treat naive timestamps as UTC. The framework never
        # silently coerces a timezone; the absence of one is
        # treated as UTC because Volatility 3 does not currently
        # emit a timezone offset and the host clock captured
        # the local time of the host that produced the image.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Per-plugin diagnostics
# ---------------------------------------------------------------------------


@dataclass
class PluginDiagnostics:
    """Counters for a single plugin's parse pass."""

    rows_seen: int = 0
    rows_parsed: int = 0
    rows_skipped: int = 0
    missing_pid: int = 0
    malformed_timestamp: int = 0
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# PSLIST (processes)
# ---------------------------------------------------------------------------


def parse_pslist(
    rows: Iterable[dict[str, Any]],
    *,
    experiment_id: str,
    image_sha256: str,
    image_path: str,
    extractor_version: str,
    extraction_status: MemoryExtractionStatus = MemoryExtractionStatus.OK,
) -> tuple[list[ProcessArtifact], list[ArtifactProvenance], PluginDiagnostics]:
    """Convert Volatility 3 ``windows.pslist.PsList`` rows.

    Returns
    -------
    (processes, provenances, diagnostics)
        ``processes`` is the list of typed process records,
        ``provenances`` is the matching provenance for each record
        (one-to-one), and ``diagnostics`` counts the parse edge
        cases for this plugin.
    """
    diags = PluginDiagnostics()
    procs: list[ProcessArtifact] = []
    provs: list[ArtifactProvenance] = []

    for row in rows:
        diags.rows_seen += 1
        pid = _parse_int(_pick(row, "PID", "pid", "ProcessId"))
        if pid is None:
            diags.rows_skipped += 1
            diags.missing_pid += 1
            continue
        name = _pick(row, "ImageFileName", "Name", "image_file_name", "process")
        if not isinstance(name, str) or not name:
            name = "<unknown>"
        ppid = _parse_int(_pick(row, "PPID", "ppid", "ParentProcessId"))
        create_time = _parse_datetime(
            _pick(row, "CreateTime", "Created", "create_time")
        )
        exit_time = _parse_datetime(
            _pick(row, "ExitTime", "Exited", "exit_time")
        )
        if create_time is None and _pick(row, "CreateTime", "Created"):
            diags.malformed_timestamp += 1
        procs.append(
            ProcessArtifact(
                experiment_id=experiment_id,
                pid=pid,
                process_name=name,
                executable_path=None,  # pslist does not emit a path
                parent_pid=ppid,
                creation_time=create_time,
                termination_time=exit_time,
            )
        )
        provs.append(
            ArtifactProvenance(
                source=ArtifactSource.MEMORY,
                source_tool="volatility3",
                source_plugin="windows.pslist.PsList",
                experiment_id=experiment_id,
                confidence=0.95,
            )
        )
        diags.rows_parsed += 1
    return procs, provs, diags


# ---------------------------------------------------------------------------
# NETSCAN (sockets)
# ---------------------------------------------------------------------------


_PROTO_MAP: dict[str, str] = {
    "TCPv4": "tcp",
    "TCPv6": "tcp",
    "UDPv4": "udp",
    "UDPv6": "udp",
    "TCP": "tcp",
    "UDP": "udp",
}


def _normalise_protocol(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v in _PROTO_MAP:
        return _PROTO_MAP[v]
    low = v.lower()
    if low in {"tcp", "udp"}:
        return low
    return None


def parse_netscan(
    rows: Iterable[dict[str, Any]],
    *,
    experiment_id: str,
    image_sha256: str,
    image_path: str,
    extractor_version: str,
    extraction_status: MemoryExtractionStatus = MemoryExtractionStatus.OK,
) -> tuple[list[SocketArtifact], list[ArtifactProvenance], PluginDiagnostics]:
    """Convert Volatility 3 ``windows.netscan.NetScan`` rows.

    Returns
    -------
    (sockets, provenances, diagnostics)
        Each row becomes one ``SocketArtifact``. The parser never
        creates a PID-less socket record; rows with no PID are
        dropped and counted in ``diagnostics.missing_pid``.
    """
    diags = PluginDiagnostics()
    socks: list[SocketArtifact] = []
    provs: list[ArtifactProvenance] = []

    for row in rows:
        diags.rows_seen += 1
        pid = _parse_int(_pick(row, "PID", "pid", "ProcessId", "OwnerPid"))
        if pid is None:
            diags.rows_skipped += 1
            diags.missing_pid += 1
            continue
        local_ip = _pick(
            row, "LocalAddress", "local_address", "LocalIp", "local_ip"
        )
        local_port = _parse_int(
            _pick(row, "LocalPort", "local_port", "LocalPortNumber")
        )
        if not isinstance(local_ip, str) or not local_ip:
            diags.rows_skipped += 1
            continue
        if local_port is None:
            diags.rows_skipped += 1
            continue
        remote_ip = _pick(
            row, "RemoteAddress", "remote_address", "RemoteIp", "remote_ip"
        )
        raw_remote_port = _parse_int(
            _pick(row, "RemotePort", "remote_port", "RemotePortNumber")
        )
        # ``RemotePort=0`` is Volatility's representation of a
        # LISTENING or wildcard socket with no remote endpoint. The
        # framework records this as ``remote_port=None`` so the
        # Phase 1 model invariant (port in [1, 65535]) is preserved.
        remote_port: int | None
        if raw_remote_port is None or raw_remote_port == 0:
            remote_port = None
        else:
            remote_port = raw_remote_port
        if isinstance(remote_ip, str) and remote_ip.strip() in ("", "*", "0.0.0.0", "::"):
            # Volatility emits a wildcard or empty remote address
            # for listening sockets; normalise to None.
            remote_ip = None
        proto = _normalise_protocol(_pick(row, "Protocol", "proto"))
        if proto is None:
            diags.rows_skipped += 1
            continue
        state = _pick(row, "State", "state", "ConnectionState")
        if state is not None and not isinstance(state, str):
            state = str(state)
        created = _parse_datetime(
            _pick(row, "Created", "created", "CreationTime", "CreateTime")
        )
        if created is None and _pick(row, "Created", "CreationTime"):
            diags.malformed_timestamp += 1
        socks.append(
            SocketArtifact(
                experiment_id=experiment_id,
                pid=pid,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=proto,
                state=state if state else None,
                timestamp=created,
            )
        )
        provs.append(
            ArtifactProvenance(
                source=ArtifactSource.MEMORY,
                source_tool="volatility3",
                source_plugin="windows.netscan.NetScan",
                experiment_id=experiment_id,
                confidence=0.85,
            )
        )
        diags.rows_parsed += 1
    return socks, provs, diags


# ---------------------------------------------------------------------------
# TLS (no plugin)
# ---------------------------------------------------------------------------


def tls_not_recovered(
    *,
    experiment_id: str,
    extractor_version: str,
    reason: str = "no TLS-extraction plugin in Phase 3",
) -> tuple[list[TLSArtifact], list[ArtifactProvenance]]:
    """Return a single explicit-absence TLS record.

    The Phase 3 extractor does not implement a TLS-from-memory
    plugin. Rather than silently omitting TLS, the framework
    records an explicit ``absent=True`` artefact so that Phase 4
    can reason about the absence.

    The plugin string is set to ``"none"`` so a downstream stage
    can distinguish this from a successful TLS observation.
    """
    t = TLSArtifact(
        experiment_id=experiment_id,
        absent=True,
        source="memory",
        confidence=1.0,
        notes=reason,
    )
    p = ArtifactProvenance(
        source=ArtifactSource.MEMORY,
        source_tool="volatility3",
        source_plugin="none",
        experiment_id=experiment_id,
        confidence=1.0,
    )
    return [t], [p]


# ---------------------------------------------------------------------------
# Envelope assembly
# ---------------------------------------------------------------------------


def _envelope(
    *,
    experiment_id: str,
    artifact_kind: str,
    rows: list[dict[str, Any]],
    status: MemoryExtractionStatus,
    plugin: str,
    extractor_version: str,
    notes: str,
) -> MemoryArtifactEnvelope:
    """Wrap raw rows in a :class:`MemoryArtifactEnvelope`."""
    return MemoryArtifactEnvelope(
        experiment_id=experiment_id,
        artifact_kind=artifact_kind,
        status=status,
        data=rows,
        source_tool="volatility3",
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Plugin dispatch
# ---------------------------------------------------------------------------


@dataclass
class MemoryParseResult:
    """Aggregated parser output for a single memory image.

    The result groups the typed artefacts by kind and exposes a
    coarse status count so the orchestrator can write a
    diagnostics file.
    """
    processes: list[ProcessArtifact] = field(default_factory=list)
    sockets: list[SocketArtifact] = field(default_factory=list)
    tls_artifacts: list[TLSArtifact] = field(default_factory=list)
    process_provenances: list[ArtifactProvenance] = field(default_factory=list)
    socket_provenances: list[ArtifactProvenance] = field(default_factory=list)
    tls_provenances: list[ArtifactProvenance] = field(default_factory=list)
    envelopes: list[MemoryArtifactEnvelope] = field(default_factory=list)
    per_plugin_diagnostics: dict[str, PluginDiagnostics] = field(
        default_factory=dict
    )
    status_counts: Counter = field(default_factory=Counter)
    extractor_version: str = "unknown"
    plugin_status: dict[str, str] = field(default_factory=dict)


def parse_plugin_rows(
    plugin: str,
    rows: list[dict[str, Any]],
    *,
    experiment_id: str,
    image_sha256: str,
    image_path: str,
    extractor_version: str,
) -> MemoryParseResult:
    """Dispatch to the right parser based on ``plugin``.

    The caller is expected to pass a plugin name from
    :data:`c2forensics.extraction.memory.volatility.SUPPORTED_PLUGINS`.
    Plugins not in the supported set are rejected by
    :func:`run_plugin` and never reach this function.
    """
    result = MemoryParseResult(extractor_version=extractor_version)
    if plugin == "windows.pslist.PsList":
        procs, provs, diags = parse_pslist(
            rows,
            experiment_id=experiment_id,
            image_sha256=image_sha256,
            image_path=image_path,
            extractor_version=extractor_version,
        )
        result.processes = procs
        result.process_provenances = provs
        result.envelopes.append(
            _envelope(
                experiment_id=experiment_id,
                artifact_kind="processes",
                rows=rows,
                status=(
                    MemoryExtractionStatus.OK
                    if procs
                    else MemoryExtractionStatus.NOT_FOUND
                ),
                plugin=plugin,
                extractor_version=extractor_version,
                notes=(
                    f"pslist parsed {len(procs)} processes "
                    f"({diags.rows_skipped} skipped)"
                ),
            )
        )
        result.per_plugin_diagnostics[plugin] = diags
    elif plugin == "windows.netscan.NetScan":
        socks, provs, diags = parse_netscan(
            rows,
            experiment_id=experiment_id,
            image_sha256=image_sha256,
            image_path=image_path,
            extractor_version=extractor_version,
        )
        result.sockets = socks
        result.socket_provenances = provs
        result.envelopes.append(
            _envelope(
                experiment_id=experiment_id,
                artifact_kind="sockets",
                rows=rows,
                status=(
                    MemoryExtractionStatus.OK
                    if socks
                    else MemoryExtractionStatus.NOT_FOUND
                ),
                plugin=plugin,
                extractor_version=extractor_version,
                notes=(
                    f"netscan parsed {len(socks)} sockets "
                    f"({diags.rows_skipped} skipped)"
                ),
            )
        )
        result.per_plugin_diagnostics[plugin] = diags
    else:
        # Defensive: run_plugin already rejects unknown plugins,
        # but if a caller bypasses that we still surface an error.
        raise ValueError(f"unsupported plugin: {plugin!r}")
    return result
