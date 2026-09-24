"""Unit tests for the Phase 4 memory-network correlation engine.

These tests exercise pure correlation logic: normalization, the IP-only
candidate gate, active-factor scoring, outcome classification, determinism,
FlowOutcome serialization, and configuration validation. They never touch
ground truth and never require tshark or Volatility.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from c2forensics.config import (
    CorrelationSection,
    CorrelationThresholds,
    CorrelationWeights,
    load_config,
)
from c2forensics.correlation import (
    CorrelationError,
    correlate_evidence,
    correlate_flow,
    endpoints_ip_compatible,
    ip_compatible,
    port_match,
    protocol_match,
    score_candidate,
    socket_canonical_endpoint,
    timestamp_proximity,
)
from c2forensics.extraction.pcap.parser import parse_rows
from c2forensics.models.correlation import FlowOutcome
from c2forensics.models.pcap import FlowObservation
from c2forensics.models.process import ProcessArtifact
from c2forensics.models.socket import SocketArtifact

UTC = timezone.utc
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

BASE_TS = datetime(2023, 11, 14, 22, 13, 25, tzinfo=UTC)


def make_config(**overrides: object) -> CorrelationSection:
    payload: dict[str, object] = {
        "weights": {
            "ip_match": 0.0,
            "port_match": 0.30,
            "protocol_match": 0.10,
            "timestamp_proximity": 0.20,
            "socket_match": 0.0,
            "process_association": 0.10,
            "tls_metadata_match": 0.0,
        },
        "timestamp_tolerance_seconds": 5.0,
        "ambiguity_margin": 0.05,
        "thresholds": {"strong": 0.80, "medium": 0.50, "weak": 0.20},
    }
    payload.update(overrides)
    return CorrelationSection.model_validate(payload)


def make_flow(
    *,
    src_ip: str = "192.168.56.108",
    src_port: int = 50578,
    dst_ip: str = "192.168.56.20",
    dst_port: int = 8443,
    protocol: str = "tcp",
    first_seen: datetime = BASE_TS,
    flow_id: str = "flow-1",
) -> FlowObservation:
    return FlowObservation(
        experiment_id="EXP001",
        flow_id=flow_id,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        first_seen=first_seen,
        last_seen=first_seen,
        frame_count=1,
        byte_count=100,
    )


def make_socket(
    *,
    pid: int = 4580,
    local_ip: str = "192.168.56.108",
    local_port: int = 50578,
    remote_ip: str | None = "192.168.56.20",
    remote_port: int | None = 8443,
    protocol: str = "tcp",
    timestamp: datetime | None = BASE_TS,
) -> SocketArtifact:
    return SocketArtifact(
        experiment_id="EXP001",
        pid=pid,
        local_ip=local_ip,
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        protocol=protocol,
        state="ESTABLISHED" if remote_ip is not None else "LISTENING",
        timestamp=timestamp,
    )


def make_process(pid: int = 4580, name: str = "test-client.exe") -> ProcessArtifact:
    return ProcessArtifact(
        experiment_id="EXP001",
        pid=pid,
        process_name=name,
        executable_path=None,
        parent_pid=880,
        creation_time=BASE_TS,
        termination_time=None,
    )


def _factors(result: object) -> dict[str, bool]:
    return {f.name: f.matched for f in result.factors}  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Phase 2 semantics consumed by Phase 4: SYN-derived direction, first SYN time
# ---------------------------------------------------------------------------


def _rows(name: str) -> list[list[str]]:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return payload["rows"]


def test_flow_direction_follows_syn_not_first_frame() -> None:
    """A mid-capture that begins with a SYN-ACK still reports the SYN sender
    as src, and first_seen as the first pure-SYN timestamp."""
    rows = [
        ["1", "1700000000.000000", "74", "192.168.56.20", "192.168.56.108",
         "8443", "50578", "", "", "0", "0x012", "", "", "", "", "", "", ""],
        ["2", "1700000000.500000", "66", "192.168.56.108", "192.168.56.20",
         "50578", "8443", "", "", "0", "0x010", "", "", "", "", "", "", ""],
        ["3", "1700000001.000000", "74", "192.168.56.108", "192.168.56.20",
         "50578", "8443", "", "", "0", "0x002", "", "", "", "", "", "", ""],
        ["4", "1700000002.000000", "74", "192.168.56.20", "192.168.56.108",
         "8443", "50578", "", "", "0", "0x012", "", "", "", "", "", "", ""],
    ]
    flows, _, _, _ = parse_rows(rows, experiment_id="EXP001")
    assert len(flows) == 1
    flow = flows[0]
    assert flow.src_ip == "192.168.56.108"
    assert flow.src_port == 50578
    assert flow.dst_ip == "192.168.56.20"
    assert flow.dst_port == 8443
    # First SYN is frame 3 at +1.0s, not the earliest packet at +0.0s.
    assert flow.first_seen == datetime.fromtimestamp(1700000001.0, tz=UTC)
    assert flow.last_seen == datetime.fromtimestamp(1700000002.0, tz=UTC)


def test_first_seen_is_first_syn_in_baseline_fixture() -> None:
    flows, _, _, _ = parse_rows(_rows("tshark_rows_encrypted_c2.json"), experiment_id="EXP001")
    assert len(flows) == 1
    # Frame 1 is the client SYN at epoch 1700000000.
    assert flows[0].first_seen == datetime.fromtimestamp(1700000000.0, tz=UTC)
    assert flows[0].src_port == 50578


def test_syn_ack_alone_does_not_set_initiator() -> None:
    """Without any pure SYN the flow keeps the stable canonical ordering."""
    rows = [
        ["1", "1700000000.000000", "74", "192.168.56.20", "192.168.56.108",
         "8443", "50578", "", "", "0", "0x012", "", "", "", "", "", "", ""],
        ["2", "1700000000.100000", "66", "192.168.56.108", "192.168.56.20",
         "50578", "8443", "", "", "0", "0x010", "", "", "", "", "", "", ""],
    ]
    flows, _, _, _ = parse_rows(rows, experiment_id="EXP001")
    assert len(flows) == 1
    flow = flows[0]
    # Canonical order: (192.168.56.108, 50578) < (192.168.56.20, 8443).
    assert (flow.src_ip, flow.src_port) == ("192.168.56.108", 50578)
    # No SYN evidence -> first_seen stays at the earliest packet.
    assert flow.first_seen == datetime.fromtimestamp(1700000000.0, tz=UTC)


# ---------------------------------------------------------------------------
# Canonical endpoint / IP gate
# ---------------------------------------------------------------------------


def test_socket_canonical_endpoint_direction_agnostic() -> None:
    a = make_socket(local_port=50578, remote_port=8443)
    b = make_socket(local_ip="192.168.56.20", local_port=8443,
                    remote_ip="192.168.56.108", remote_port=50578)
    assert socket_canonical_endpoint(a) == socket_canonical_endpoint(b)


def test_socket_canonical_endpoint_listening_is_none() -> None:
    assert socket_canonical_endpoint(make_socket(remote_ip=None, remote_port=None)) is None


def test_socket_canonical_endpoint_ipv6() -> None:
    s = make_socket(local_ip="fe80::1234", local_port=51001,
                    remote_ip="fe80::5678", remote_port=8443)
    endpoint = socket_canonical_endpoint(s)
    assert endpoint is not None
    assert {endpoint[0], endpoint[2]} == {"fe80::1234", "fe80::5678"}


def test_ip_gate_requires_unordered_pair_equality() -> None:
    flow = make_flow()
    assert ip_compatible(flow, make_socket()) is True
    # Reversed orientation still passes (unordered IP comparison).
    assert ip_compatible(
        flow,
        make_socket(local_ip="192.168.56.20", local_port=8443,
                    remote_ip="192.168.56.108", remote_port=50578),
    ) is True
    # Same remote endpoint, different local client -> gate rejects.
    assert ip_compatible(flow, make_socket(local_ip="192.168.56.99")) is False
    # Same local endpoint, different remote -> gate rejects.
    assert ip_compatible(flow, make_socket(remote_ip="192.168.56.30")) is False
    # Listening socket without remote endpoint -> no candidate.
    assert ip_compatible(flow, make_socket(remote_ip=None, remote_port=None)) is False
    assert endpoints_ip_compatible is ip_compatible


def test_port_protocol_timestamp_do_not_gate() -> None:
    """Everything that passes the IP gate becomes a candidate, whatever the
    port/protocol/timestamp say."""
    flow = make_flow()
    socket = make_socket(
        local_port=1234,          # port mismatch
        remote_port=9999,         # port mismatch
        protocol="udp",           # protocol mismatch
        timestamp=BASE_TS.replace(hour=1),  # timestamp mismatch
    )
    outcome = correlate_flow(flow, [socket], [], make_config())
    assert len(outcome.candidates) == 1
    flags = _factors(outcome.candidates[0])
    assert flags["port_match"] is False
    assert flags["protocol_match"] is False
    assert flags["timestamp_proximity"] is False
    assert flags["process_association"] is False


# ---------------------------------------------------------------------------
# Factor helpers
# ---------------------------------------------------------------------------


def test_port_match_either_orientation() -> None:
    flow = make_flow()
    assert port_match(flow, make_socket()) is True
    assert port_match(
        flow,
        make_socket(local_ip="192.168.56.20", local_port=8443,
                    remote_ip="192.168.56.108", remote_port=50578),
    ) is True
    assert port_match(flow, make_socket(local_port=50579)) is False


def test_protocol_match_is_case_insensitive() -> None:
    flow = make_flow(protocol="tcp")
    assert protocol_match(flow, make_socket(protocol="tcp")) is True
    assert protocol_match(flow, make_socket(protocol="udp")) is False


def test_timestamp_proximity_threshold_and_none() -> None:
    from datetime import timedelta

    flow = make_flow()
    close = make_socket(timestamp=BASE_TS)
    far = make_socket(timestamp=BASE_TS - timedelta(seconds=65))
    assert timestamp_proximity(flow, close, 5.0)[0] is True
    assert timestamp_proximity(flow, close, 5.0)[1] == pytest.approx(0.0)
    matched, delta = timestamp_proximity(flow, far, 5.0)
    assert matched is False
    assert delta == pytest.approx(65.0)
    matched, delta = timestamp_proximity(flow, make_socket(timestamp=None), 5.0)
    assert matched is False
    assert delta is None


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def test_reserved_factors_never_contribute() -> None:
    config = make_config(
        weights={
            "ip_match": 0.0,
            "port_match": 0.30,
            "protocol_match": 0.10,
            "timestamp_proximity": 0.20,
            "socket_match": 0.0,
            "process_association": 0.10,
            "tls_metadata_match": 0.0,
        }
    )
    flow = make_flow()
    result = score_candidate(flow, make_socket(), make_process(), config)
    contributions = {f.name: f.contribution for f in result.factors}
    assert contributions["ip_match"] == 0.0
    assert contributions["socket_match"] == 0.0
    assert contributions["tls_metadata_match"] == 0.0
    # gate-matching evidence must not inflate the score.
    assert sum(contributions.values()) == pytest.approx(result.confidence)


def test_score_normalizes_over_active_weights() -> None:
    config = make_config()
    flow = make_flow()
    result = score_candidate(flow, make_socket(), make_process(), config)
    # all four active factors match: confidence is 1.0 despite raw weights
    # summing to 0.7.
    assert result.confidence == pytest.approx(1.0)
    assert result.classification == "strong"
    contributions = {f.name: f.contribution for f in result.factors}
    assert contributions["port_match"] == pytest.approx(0.30 / 0.70)
    assert contributions["protocol_match"] == pytest.approx(0.10 / 0.70)
    assert contributions["timestamp_proximity"] == pytest.approx(0.20 / 0.70)
    assert contributions["process_association"] == pytest.approx(0.10 / 0.70)


def test_timestamp_unavailable_excluded_from_denominator() -> None:
    config = make_config()
    flow = make_flow()
    socket = make_socket(timestamp=None)
    result = score_candidate(flow, socket, make_process(), config)
    # port + protocol + process over active weight 0.5 (timestamp excluded).
    assert result.confidence == pytest.approx(0.5 / 0.5)
    ts_factor = next(f for f in result.factors if f.name == "timestamp_proximity")
    assert ts_factor.contribution == 0.0


def test_timestamp_present_but_mismatched_stays_in_denominator() -> None:
    from datetime import timedelta

    config = make_config()
    flow = make_flow()
    socket = make_socket(timestamp=BASE_TS - timedelta(seconds=65))
    result = score_candidate(flow, socket, make_process(), config)
    # port + protocol + process = 0.5 over full active 0.7.
    assert result.confidence == pytest.approx(0.5 / 0.7)
    assert result.classification == "medium"


def test_missing_process_artifact_survues_with_zero_factor() -> None:
    config = make_config()
    flow = make_flow()
    result = score_candidate(flow, make_socket(), None, config)
    flags = _factors(result)
    assert flags["process_association"] is False
    assert result.process_name == ""
    # port + protocol + timestamp = 0.6 / 0.7
    assert result.confidence == pytest.approx(0.6 / 0.7)


def test_classification_thresholds() -> None:
    config = make_config()
    flow = make_flow()
    # protocol + timestamp + process match, port mismatches: 0.4/0.7 ~= 0.571.
    socket = make_socket(local_port=1, remote_port=2, timestamp=BASE_TS)
    result = score_candidate(flow, socket, make_process(), config)
    assert result.confidence == pytest.approx(0.4 / 0.7)
    assert result.classification == "medium"  # >= medium 0.50
    # Only timestamp + process match: 0.3/0.7 ~= 0.429 -> weak.
    socket2 = make_socket(local_port=1, remote_port=2, timestamp=BASE_TS)
    result2 = score_candidate(
        flow, socket2, make_process(),
        make_config(weights={
            "ip_match": 0.0, "port_match": 0.50, "protocol_match": 0.0,
            "timestamp_proximity": 0.30, "socket_match": 0.0,
            "process_association": 0.20, "tls_metadata_match": 0.0,
        }),
    )
    assert result2.confidence == pytest.approx(0.5 / 1.0)
    assert result2.classification == "medium"


# ---------------------------------------------------------------------------
# Outcome classification
# ---------------------------------------------------------------------------


def _outcome_for(
    flow: FlowObservation,
    sockets: list[SocketArtifact],
    processes: list[ProcessArtifact],
    config: CorrelationSection,
) -> FlowOutcome:
    return correlate_flow(flow, sockets, processes, config)


def test_no_match_outcome() -> None:
    outcome = _outcome_for(make_flow(), [], [], make_config())
    assert outcome.outcome == "NO_MATCH"
    assert outcome.candidates == []
    assert outcome.socket_provenance == []
    assert outcome.flow_provenance["flow_id"] == "flow-1"


def test_no_match_still_has_lightweight_flow_provenance() -> None:
    outcome = _outcome_for(make_flow(), [], [], make_config())
    assert outcome.flow_provenance["src_port"] == 50578
    assert outcome.flow_provenance["dst_port"] == 8443


def test_matched_outcome_single_strong_candidate() -> None:
    outcome = _outcome_for(make_flow(), [make_socket()], [make_process()], make_config())
    assert outcome.outcome == "MATCHED"
    assert len(outcome.candidates) == 1
    best = outcome.candidates[0]
    assert best.pid == 4580
    assert best.process_name == "test-client.exe"
    assert best.classification == "strong"


def test_insufficient_evidence_outcome() -> None:
    config = make_config()
    # Only protocol matches: 0.1/0.7 ~= 0.143 < weak 0.20.
    socket = make_socket(
        local_port=1234,
        remote_port=5555,
        timestamp=BASE_TS.replace(minute=40),
    )
    outcome = _outcome_for(make_flow(), [socket], [], config)
    assert outcome.outcome == "INSUFFICIENT_EVIDENCE"
    assert len(outcome.candidates) == 1
    assert outcome.candidates[0].classification == "none"


def test_multiple_candidates_within_ambiguity_margin() -> None:
    config = make_config()
    flow = make_flow()
    # Two distinct PIDs own IP-compatible sockets with identical evidence.
    s1 = make_socket(pid=100)
    s2 = make_socket(pid=200)
    outcome = _outcome_for(flow, [s1, s2], [make_process(100), make_process(200)], config)
    assert outcome.outcome == "MULTIPLE_CANDIDATES"
    assert [c.pid for c in outcome.candidates] == [100, 200]
    assert outcome.candidates[0].confidence == pytest.approx(outcome.candidates[1].confidence)


def test_ambiguity_margin_resolves_when_gap_is_clear() -> None:
    config = make_config(ambiguity_margin=0.05)
    flow = make_flow()
    strong = make_socket(pid=100)  # everything matches -> 1.0
    # pid 200 socket: protocol + process only (port and timestamp mismatch).
    weak = make_socket(
        pid=200,
        local_port=1,
        remote_port=2,
        timestamp=BASE_TS.replace(minute=40),
    )
    outcome = _outcome_for(flow, [strong, weak], [make_process(100), make_process(200)], config)
    assert outcome.outcome == "MATCHED"
    assert outcome.candidates[0].pid == 100
    # All candidates remain preserved and ordered for downstream scrutiny.
    assert [c.pid for c in outcome.candidates] == [100, 200]


def test_candidate_ordering_is_deterministic() -> None:
    flow = make_flow()
    sockets = [make_socket(pid=p, local_port=50578) for p in (300, 100, 200)]
    processes = [make_process(p) for p in (100, 200, 300)]
    config = make_config()
    first = _outcome_for(flow, sockets, processes, config)
    second = _outcome_for(flow, list(reversed(sockets)), list(reversed(processes)), config)
    assert [c.pid for c in first.candidates] == [100, 200, 300]
    assert [c.pid for c in second.candidates] == [100, 200, 300]
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_multiple_sockets_same_pid_collapse_to_strongest() -> None:
    flow = make_flow()
    exact = make_socket(pid=100)
    partial = make_socket(pid=100, local_port=40000)
    outcome = _outcome_for(flow, [partial, exact], [make_process(100)], make_config())
    assert outcome.outcome == "MATCHED"
    assert len(outcome.candidates) == 1
    assert outcome.candidates[0].confidence == pytest.approx(1.0)
    # Every IP-compatible socket stays in provenance.
    assert len(outcome.socket_provenance) == 2


def test_socket_from_other_experiment_is_ignored() -> None:
    flow = make_flow()
    other = make_socket().model_copy(update={"experiment_id": "EXP999"})
    outcome = _outcome_for(flow, [other], [make_process()], make_config())
    assert outcome.outcome == "NO_MATCH"


# ---------------------------------------------------------------------------
# Bundle-level correlation
# ---------------------------------------------------------------------------


def _memory(sockets: list[SocketArtifact], processes: list[ProcessArtifact]) -> object:
    from c2forensics.extraction.memory import ImageRecord, MemoryExtractionResult

    image = ImageRecord(
        path="raw/memory/mem.raw",
        sha256="b" * 64,
        size_bytes=10,
        mtime_utc=BASE_TS,
    )
    return MemoryExtractionResult(
        experiment_id="EXP001",
        images=[image],
        extracted_at=BASE_TS,
        processes=processes,
        sockets=sockets,
    )


def _network(flows: list[FlowObservation]) -> object:
    from c2forensics.models.pcap import NetworkEvidence

    return NetworkEvidence(
        experiment_id="EXP001",
        pcap_path="raw/capture.pcap",
        pcap_sha256="a" * 64,
        extracted_at=BASE_TS,
        flows=flows,
    )


def test_exactly_one_memory_image_required() -> None:
    from c2forensics.extraction.memory import ImageRecord, MemoryExtractionResult

    result = MemoryExtractionResult(
        experiment_id="EXP001",
        images=[
            ImageRecord(path="a.raw", sha256="b" * 64, size_bytes=1, mtime_utc=BASE_TS),
            ImageRecord(path="c.raw", sha256="d" * 64, size_bytes=1, mtime_utc=BASE_TS),
        ],
        extracted_at=BASE_TS,
    )
    with pytest.raises(CorrelationError, match="exactly one memory image"):
        correlate_evidence(_network([make_flow()]), result, make_config())

    empty = MemoryExtractionResult(
        experiment_id="EXP001", images=[], extracted_at=BASE_TS
    )
    with pytest.raises(CorrelationError, match="exactly one memory image"):
        correlate_evidence(_network([make_flow()]), empty, make_config())


def test_cross_experiment_bundles_rejected() -> None:
    other = _network([make_flow()]).model_copy(update={"experiment_id": "EXP999"})
    with pytest.raises(CorrelationError):
        correlate_evidence(other, _memory([], []), make_config())


def test_duplicate_flow_ids_rejected() -> None:
    flows = [make_flow(), make_flow()]
    with pytest.raises(CorrelationError, match="duplicate flow_id"):
        correlate_evidence(_network(flows), _memory([], []), make_config())


def test_every_flow_gets_exactly_one_outcome_in_flow_id_order() -> None:
    flows = [
        make_flow(flow_id="flow-b"),
        make_flow(flow_id="flow-a", dst_ip="192.168.56.30"),
    ]
    outcomes = correlate_evidence(
        _network(flows), _memory([make_socket()], [make_process()]), make_config()
    )
    assert [o.flow_id for o in outcomes] == ["flow-a", "flow-b"]
    assert [o.outcome for o in outcomes] == ["NO_MATCH", "MATCHED"]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_ambiguity_margin_bounds() -> None:
    with pytest.raises(ValidationError):
        make_config(ambiguity_margin=1.5)
    with pytest.raises(ValidationError):
        make_config(ambiguity_margin=-0.1)


def test_active_weights_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        CorrelationSection(
            weights=CorrelationWeights(
                ip_match=0.5,
                port_match=0.0,
                protocol_match=0.0,
                timestamp_proximity=0.0,
                socket_match=0.5,
                process_association=0.0,
            ),
            thresholds=CorrelationThresholds(strong=0.8, medium=0.5, weak=0.2),
        )


def test_lab_yaml_phase4_configuration() -> None:
    repo_config = Path(__file__).resolve().parents[2] / "config" / "lab.yaml"
    cfg = load_config(repo_config).correlation
    assert cfg.weights.ip_match == 0.0
    assert cfg.weights.socket_match == 0.0
    assert cfg.weights.tls_metadata_match == 0.0
    assert cfg.weights.active_total() == pytest.approx(0.70)
    assert cfg.ambiguity_margin == 0.05
    assert cfg.timestamp_tolerance_seconds == 5.0
    assert cfg.thresholds.weak == 0.20


# ---------------------------------------------------------------------------
# FlowOutcome model
# ---------------------------------------------------------------------------


def test_flow_outcome_roundtrip() -> None:
    outcome = _outcome_for(make_flow(), [make_socket()], [make_process()], make_config())
    payload = json.loads(outcome.model_dump_json())
    assert payload["outcome"] == "MATCHED"
    restored = FlowOutcome.model_validate(payload)
    assert restored == outcome


def test_flow_outcome_rejects_unknown_outcome() -> None:
    with pytest.raises(ValidationError):
        FlowOutcome(
            experiment_id="EXP001",
            flow_id="f",
            outcome="PROBABLY",  # type: ignore[arg-type]
        )
