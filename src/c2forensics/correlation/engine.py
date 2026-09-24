"""Explainable memory-to-network correlation for Phase 4.

The engine deliberately keeps attribution separate from the Phase 2 and Phase 3
extractors. It consumes their typed, immutable artefacts and produces one
``FlowOutcome`` for every ``FlowObservation`` without reading experiment ground
truth.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

from pydantic import ValidationError

from c2forensics.config import CorrelationSection
from c2forensics.errors import C2ForensicsError
from c2forensics.experiment import update_status
from c2forensics.extraction.memory import (
    MemoryExtractionResult,
    load_extracted_result,
)
from c2forensics.extraction.pcap import (
    NetworkEvidence,
    load_extracted_bundle,
)
from c2forensics.models.correlation import (
    CorrelationEvidence,
    CorrelationFactor,
    CorrelationResult,
    FlowOutcome,
)
from c2forensics.models.experiment import ExperimentStatus
from c2forensics.models.pcap import FlowObservation
from c2forensics.models.process import ProcessArtifact
from c2forensics.models.socket import SocketArtifact
from c2forensics.paths import ExperimentPaths


class CorrelationError(C2ForensicsError):
    """Raised when correlation inputs or outputs violate the Phase 4 contract."""


@dataclass(frozen=True)
class _Candidate:
    socket: SocketArtifact
    process: ProcessArtifact | None
    result: CorrelationResult


def _normalise_ip(value: str) -> str:
    """Canonicalise valid IP literals while retaining malformed values safely."""
    text = value.strip()
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        # Phase 2/3 models accept a non-empty string. Keeping an invalid value
        # opaque prevents a malformed artefact from being silently matched.
        return text.lower()


def _endpoint_ips(value: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(_normalise_ip(item) for item in value))


def socket_canonical_endpoint(socket: SocketArtifact) -> tuple[str, int, str, int, str] | None:
    """Return a stable socket endpoint tuple, or ``None`` without a remote endpoint."""
    if socket.remote_ip is None or socket.remote_port is None:
        return None
    local = (_normalise_ip(socket.local_ip), socket.local_port)
    remote = (_normalise_ip(socket.remote_ip), socket.remote_port)
    if local <= remote:
        return (local[0], local[1], remote[0], remote[1], socket.protocol.lower())
    return (remote[0], remote[1], local[0], local[1], socket.protocol.lower())


def ip_compatible(flow: FlowObservation, socket: SocketArtifact) -> bool:
    """Return whether the flow and socket have the same unordered endpoint IPs."""
    if socket.remote_ip is None or socket.remote_port is None:
        return False
    flow_ips = _endpoint_ips((flow.src_ip, flow.dst_ip))
    socket_ips = _endpoint_ips((socket.local_ip, socket.remote_ip))
    return flow_ips == socket_ips


# Public alias used by callers that prefer the contract wording.
endpoints_ip_compatible = ip_compatible


def port_match(flow: FlowObservation, socket: SocketArtifact) -> bool:
    """Return whether ports match in either endpoint orientation."""
    return (
        flow.src_port == socket.local_port and flow.dst_port == socket.remote_port
    ) or (
        flow.src_port == socket.remote_port and flow.dst_port == socket.local_port
    )


def protocol_match(flow: FlowObservation, socket: SocketArtifact) -> bool:
    return flow.protocol.strip().lower() == socket.protocol.strip().lower()


def timestamp_proximity(
    flow: FlowObservation,
    socket: SocketArtifact,
    tolerance_seconds: float,
) -> tuple[bool, float | None]:
    """Return temporal match and absolute delta; ``None`` means unavailable."""
    if socket.timestamp is None:
        return False, None
    delta = abs((flow.first_seen - socket.timestamp).total_seconds())
    return delta <= tolerance_seconds, delta


def _socket_sort_key(socket: SocketArtifact) -> tuple[Any, ...]:
    return (
        _normalise_ip(socket.local_ip),
        socket.local_port,
        _normalise_ip(socket.remote_ip or ""),
        socket.remote_port if socket.remote_port is not None else -1,
        socket.protocol.lower(),
        socket.timestamp.isoformat() if socket.timestamp is not None else "",
        socket.pid,
    )


def _process_sort_key(process: ProcessArtifact) -> tuple[Any, ...]:
    return (
        process.pid,
        process.process_name,
        process.executable_path or "",
        process.parent_pid if process.parent_pid is not None else -1,
        process.creation_time.isoformat() if process.creation_time is not None else "",
        process.termination_time.isoformat() if process.termination_time is not None else "",
    )


def _classify(confidence: float, config: CorrelationSection) -> str:
    if confidence >= config.thresholds.strong:
        return "strong"
    if confidence >= config.thresholds.medium:
        return "medium"
    if confidence >= config.thresholds.weak:
        return "weak"
    return "none"


def _factor(
    name: Any,
    matched: bool,
    weight: float,
    contribution: float,
    detail: str,
) -> CorrelationFactor:
    return CorrelationFactor(
        name=name,
        matched=matched,
        weight=weight,
        contribution=round(contribution, 12),
        detail=detail,
    )


def score_candidate(
    flow: FlowObservation,
    socket: SocketArtifact,
    process: ProcessArtifact | None,
    config: CorrelationSection,
) -> CorrelationResult:
    """Score one IP-compatible flow/socket/process combination.

    IP compatibility is a candidate-generation gate and has zero score weight.
    Timestamp evidence is excluded from the normalization denominator when it
    is unavailable; a present-but-mismatched timestamp remains an available
    negative factor.
    """
    weights = config.weights
    port = port_match(flow, socket)
    protocol = protocol_match(flow, socket)
    temporal, delta = timestamp_proximity(
        flow, socket, config.timestamp_tolerance_seconds
    )
    associated = process is not None

    active = (
        ("port_match", weights.port_match, True, port),
        ("protocol_match", weights.protocol_match, True, protocol),
        (
            "timestamp_proximity",
            weights.timestamp_proximity,
            socket.timestamp is not None,
            temporal,
        ),
        ("process_association", weights.process_association, True, associated),
    )
    available_weight = sum(weight for _, weight, available, _ in active if available and weight > 0)
    normalized: dict[str, float] = {}
    if available_weight > 0:
        normalized = {
            name: weight / available_weight
            for name, weight, available, _ in active
            if available and weight > 0
        }

    temporal_detail = (
        f"absolute delta {delta:.6f}s <= {config.timestamp_tolerance_seconds:.6f}s"
        if delta is not None
        else "socket timestamp unavailable; factor excluded from normalization"
    )
    factors = [
        _factor(
            "ip_match",
            True,
            weights.ip_match,
            0.0,
            "unordered endpoint IP compatibility used only as the candidate gate",
        ),
        _factor(
            "port_match",
            port,
            weights.port_match,
            normalized.get("port_match", 0.0) if port else 0.0,
            "ports match in direct or reverse endpoint orientation" if port else "port mismatch",
        ),
        _factor(
            "protocol_match",
            protocol,
            weights.protocol_match,
            normalized.get("protocol_match", 0.0) if protocol else 0.0,
            "transport protocol matches" if protocol else "transport protocol mismatch",
        ),
        _factor(
            "timestamp_proximity",
            temporal,
            weights.timestamp_proximity,
            normalized.get("timestamp_proximity", 0.0) if temporal else 0.0,
            temporal_detail,
        ),
        _factor(
            "socket_match",
            socket_canonical_endpoint(socket) is not None,
            weights.socket_match,
            0.0,
            "reserved Phase 4 factor; no score contribution",
        ),
        _factor(
            "process_association",
            associated,
            weights.process_association,
            normalized.get("process_association", 0.0) if associated else 0.0,
            "ProcessArtifact linked by socket PID" if associated else "no ProcessArtifact for socket PID",
        ),
        _factor(
            "tls_metadata_match",
            False,
            weights.tls_metadata_match,
            0.0,
            "reserved Phase 4 factor; TLS metadata is not scored",
        ),
    ]
    confidence = round(sum(factor.contribution for factor in factors), 12)
    return CorrelationResult(
        experiment_id=flow.experiment_id,
        flow_id=flow.flow_id,
        pid=socket.pid,
        process_name=process.process_name if process is not None else "",
        confidence=confidence,
        classification=_classify(confidence, config),
        factors=factors,
        evidence=CorrelationEvidence(
            pcap=True,
            memory_socket=True,
            ip_match=True,
            port_match=port,
            timestamp_match=temporal,
            process_match=associated,
            tls_match=False,
        ),
    )


def _result_sort_key(candidate: _Candidate) -> tuple[Any, ...]:
    socket = candidate.socket
    return (
        -candidate.result.confidence,
        candidate.result.pid,
        _normalise_ip(socket.local_ip),
        socket.local_port,
        _normalise_ip(socket.remote_ip or ""),
        socket.remote_port if socket.remote_port is not None else -1,
        socket.protocol.lower(),
        socket.timestamp.isoformat() if socket.timestamp is not None else "",
    )


def _candidate_sort_key_for_selection(candidate: _Candidate) -> tuple[Any, ...]:
    """Select a deterministic winner, preferring lower PID on equal scores."""
    return (
        -candidate.result.confidence,
        candidate.result.pid,
        *_result_sort_key(candidate)[2:],
    )


def correlate_flow(
    flow: FlowObservation,
    sockets: Iterable[SocketArtifact],
    processes: Iterable[ProcessArtifact],
    config: CorrelationSection,
) -> FlowOutcome:
    """Correlate one flow and return exactly one explainable outcome."""
    process_by_pid: dict[int, ProcessArtifact] = {}
    for process in processes:
        current = process_by_pid.get(process.pid)
        if current is None or _process_sort_key(process) < _process_sort_key(current):
            process_by_pid[process.pid] = process

    candidates: list[_Candidate] = []
    compatible_sockets: list[SocketArtifact] = []
    for socket in sockets:
        if socket.experiment_id != flow.experiment_id:
            continue
        if not ip_compatible(flow, socket):
            continue
        compatible_sockets.append(socket)
        process = process_by_pid.get(socket.pid)
        result = score_candidate(flow, socket, process, config)
        candidates.append(_Candidate(socket=socket, process=process, result=result))

    # Attribution is process-level. If one PID owns multiple compatible sockets,
    # retain the strongest socket result while preserving every socket in the
    # flow outcome's socket provenance.
    best_by_pid: dict[int, _Candidate] = {}
    for candidate in candidates:
        current = best_by_pid.get(candidate.result.pid)
        if current is None or _candidate_sort_key_for_selection(candidate) < _candidate_sort_key_for_selection(current):
            best_by_pid[candidate.result.pid] = candidate
    candidates = sorted(best_by_pid.values(), key=_result_sort_key)

    if not candidates:
        outcome = "NO_MATCH"
    else:
        best = candidates[0]
        sufficiently_supported = [
            candidate
            for candidate in candidates
            if candidate.result.confidence >= config.thresholds.weak
        ]
        if best.result.confidence < config.thresholds.weak:
            outcome = "INSUFFICIENT_EVIDENCE"
        elif len(sufficiently_supported) < 2:
            outcome = "MATCHED"
        else:
            second = sufficiently_supported[1]
            outcome = (
                "MULTIPLE_CANDIDATES"
                if best.result.confidence - second.result.confidence
                < config.ambiguity_margin
                else "MATCHED"
            )

    flow_provenance = {
        "experiment_id": flow.experiment_id,
        "flow_id": flow.flow_id,
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "tcp_stream": flow.tcp_stream,
        "first_seen": flow.first_seen.isoformat(),
        "last_seen": flow.last_seen.isoformat(),
        "frame_count": flow.frame_count,
        "byte_count": flow.byte_count,
    }
    socket_provenance = [
        {
            "experiment_id": socket.experiment_id,
            "pid": socket.pid,
            "local_ip": socket.local_ip,
            "local_port": socket.local_port,
            "remote_ip": socket.remote_ip,
            "remote_port": socket.remote_port,
            "protocol": socket.protocol,
            "state": socket.state,
            "timestamp": socket.timestamp.isoformat() if socket.timestamp is not None else None,
        }
        for socket in sorted(compatible_sockets, key=_socket_sort_key)
    ]
    process_provenance = [
        {
            "experiment_id": process.experiment_id,
            "pid": process.pid,
            "process_name": process.process_name,
            "executable_path": process.executable_path,
            "parent_pid": process.parent_pid,
            "creation_time": (
                process.creation_time.isoformat()
                if process.creation_time is not None
                else None
            ),
            "termination_time": (
                process.termination_time.isoformat()
                if process.termination_time is not None
                else None
            ),
        }
        for process in sorted(
            (candidate.process for candidate in candidates if candidate.process is not None),
            key=_process_sort_key,
        )
    ]
    return FlowOutcome(
        experiment_id=flow.experiment_id,
        flow_id=flow.flow_id,
        outcome=outcome,
        candidates=[candidate.result for candidate in candidates],
        flow_provenance=flow_provenance,
        socket_provenance=socket_provenance,
        process_provenance=process_provenance,
    )


def _validate_artifact_experiment_ids(
    network: NetworkEvidence,
    memory: MemoryExtractionResult,
    expected_experiment_id: str,
) -> None:
    if network.experiment_id != expected_experiment_id:
        raise CorrelationError(
            f"network evidence experiment_id {network.experiment_id!r} does not match {expected_experiment_id!r}"
        )
    if memory.experiment_id != expected_experiment_id:
        raise CorrelationError(
            f"memory evidence experiment_id {memory.experiment_id!r} does not match {expected_experiment_id!r}"
        )
    if any(flow.experiment_id != expected_experiment_id for flow in network.flows):
        raise CorrelationError("network bundle contains a flow from another experiment")
    if any(process.experiment_id != expected_experiment_id for process in memory.processes):
        raise CorrelationError("memory bundle contains a process from another experiment")
    if any(socket.experiment_id != expected_experiment_id for socket in memory.sockets):
        raise CorrelationError("memory bundle contains a socket from another experiment")


def correlate_evidence(
    network: NetworkEvidence,
    memory: MemoryExtractionResult,
    config: CorrelationSection,
    *,
    expected_experiment_id: str | None = None,
) -> list[FlowOutcome]:
    """Correlate typed Phase 2 and Phase 3 bundles.

    Exactly one memory image is required. The engine never opens or imports
    ground-truth data.
    """
    if expected_experiment_id is not None:
        _validate_artifact_experiment_ids(network, memory, expected_experiment_id)
    elif network.experiment_id != memory.experiment_id:
        raise CorrelationError(
            "network and memory evidence belong to different experiments"
        )
    if len(memory.images) != 1:
        raise CorrelationError(
            "correlation requires exactly one memory image; "
            f"found {len(memory.images)}"
        )
    flow_ids = [flow.flow_id for flow in network.flows]
    if len(flow_ids) != len(set(flow_ids)):
        raise CorrelationError("network evidence contains duplicate flow_id values")

    outcomes = [
        correlate_flow(flow, memory.sockets, memory.processes, config)
        for flow in sorted(network.flows, key=lambda item: item.flow_id)
    ]
    return outcomes


def _flow_outcomes_path(paths: ExperimentPaths) -> Path:
    return paths.correlation / "flow-outcomes.json"


def persist_flow_outcomes(
    paths: ExperimentPaths,
    outcomes: Sequence[FlowOutcome],
) -> Path:
    """Atomically persist a deterministic JSON array of flow outcomes."""
    paths.ensure_directories()
    target = _flow_outcomes_path(paths)
    payload = [outcome.model_dump(mode="json") for outcome in sorted(outcomes, key=lambda item: item.flow_id)]
    tmp = target.with_suffix(target.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, target)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise
    return target


def load_flow_outcomes(paths: ExperimentPaths) -> list[FlowOutcome]:
    """Load the public Phase 4 flow-outcome artifact."""
    target = _flow_outcomes_path(paths)
    if not target.is_file():
        raise CorrelationError(f"no correlation outcomes at {target}")
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("flow-outcomes.json must contain a JSON array")
        return [FlowOutcome.model_validate(item) for item in payload]
    except (OSError, ValueError, ValidationError) as exc:
        raise CorrelationError(f"invalid correlation outcomes at {target}: {exc}") from exc


def load_correlation_inputs(
    paths: ExperimentPaths,
) -> tuple[NetworkEvidence, MemoryExtractionResult]:
    """Load and validate the Phase 2/3 inputs used by correlation."""
    try:
        network = load_extracted_bundle(paths)
        memory = load_extracted_result(paths)
    except CorrelationError:
        raise
    except (OSError, ValueError, ValidationError, C2ForensicsError) as exc:
        raise CorrelationError(f"unable to load correlation inputs: {exc}") from exc
    _validate_artifact_experiment_ids(network, memory, paths.root.name)
    if len(memory.images) != 1:
        raise CorrelationError(
            "correlation requires exactly one memory image; "
            f"found {len(memory.images)}"
        )
    return network, memory


def run_correlation(
    paths: ExperimentPaths,
    config: CorrelationSection,
) -> list[FlowOutcome]:
    """Load inputs, correlate, and persist outcomes without changing status."""
    network, memory = load_correlation_inputs(paths)
    outcomes = correlate_evidence(
        network,
        memory,
        config,
        expected_experiment_id=paths.root.name,
    )
    persist_flow_outcomes(paths, outcomes)
    return outcomes


def correlate_and_mark(
    paths: ExperimentPaths,
    config: CorrelationSection,
) -> list[FlowOutcome]:
    """Run correlation and advance status only after persistence succeeds."""
    outcomes = run_correlation(paths, config)
    update_status(paths, ExperimentStatus.CORRELATED)
    return outcomes


# Concise aliases for external callers and tests.
save_flow_outcomes = persist_flow_outcomes
correlate = correlate_evidence
