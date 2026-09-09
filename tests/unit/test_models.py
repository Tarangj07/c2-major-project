"""Unit tests for the typed data models."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from c2forensics.models.artifact import Artifact, ArtifactProvenance, ArtifactSource
from c2forensics.models.correlation import (
    CorrelationEvidence,
    CorrelationFactor,
    CorrelationResult,
)
from c2forensics.models.experiment import (
    ExperimentMetadata,
    ExperimentStatus,
    GroundTruth,
    ToolVersions,
)
from c2forensics.models.memory import (
    MemoryArtifactEnvelope,
    MemoryExtractionStatus,
)
from c2forensics.models.network import NetworkFlow
from c2forensics.models.process import ProcessArtifact
from c2forensics.models.socket import SocketArtifact
from c2forensics.models.timeline import TimelineEvent, TimelineEventKind
from c2forensics.models.tls import TLSArtifact


UTC = timezone.utc


# ---------------------------------------------------------------------------
# Experiment / metadata
# ---------------------------------------------------------------------------


def _ts(year: int = 2026, month: int = 1, day: int = 1) -> datetime:
    return datetime(year, month, day, tzinfo=UTC)


def test_experiment_metadata_roundtrip() -> None:
    meta = ExperimentMetadata(
        experiment_id="EXP001",
        created_at=_ts(),
        updated_at=_ts(),
        description="baseline",
    )
    payload = meta.model_dump_json()
    parsed = ExperimentMetadata.model_validate_json(payload)
    assert parsed == meta


@pytest.mark.parametrize("bad_id", ["", "1bad", "has space", "x" * 65, "..", "a/b"])
def test_experiment_metadata_rejects_bad_id(bad_id: str) -> None:
    with pytest.raises(ValidationError):
        ExperimentMetadata(
            experiment_id=bad_id,
            created_at=_ts(),
            updated_at=_ts(),
        )


def test_experiment_metadata_requires_utc_timestamps() -> None:
    with pytest.raises(ValidationError):
        ExperimentMetadata(
            experiment_id="EXP001",
            created_at=datetime(2026, 1, 1),  # naive
            updated_at=_ts(),
        )


def test_ground_truth_validation() -> None:
    gt = GroundTruth(
        experiment_id="EXP001",
        client_id="c1",
        pid=4580,
        client_ip="192.168.56.108",
        client_port=50578,
        server_ip="192.168.56.20",
        server_port=8443,
        tls_version="TLS 1.3",
        connection_start=_ts(),
        connection_end=_ts() + timedelta(seconds=10),
        heartbeat_timestamps=[_ts(), _ts() + timedelta(seconds=5)],
    )
    assert gt.heartbeat_timestamps[0].tzinfo is UTC
    payload = gt.model_dump_json()
    parsed = GroundTruth.model_validate_json(payload)
    assert parsed == gt


def test_ground_truth_rejects_naive_timestamps() -> None:
    with pytest.raises(ValidationError):
        GroundTruth(
            experiment_id="EXP001",
            client_id="c1",
            pid=1,
            client_ip="1.1.1.1",
            client_port=1,
            server_ip="2.2.2.2",
            server_port=2,
            connection_start=datetime(2026, 1, 1),  # naive
        )


def test_tool_versions_required_fields() -> None:
    tv = ToolVersions(python="3.11", framework="0.1.0", os="Linux 6.0")
    assert tv.tshark is None
    assert tv.volatility3 is None


# ---------------------------------------------------------------------------
# NetworkFlow
# ---------------------------------------------------------------------------


def _flow(**overrides: object) -> NetworkFlow:
    base: dict[str, object] = {
        "experiment_id": "EXP001",
        "flow_id": "flow-001",
        "src_ip": "192.168.56.108",
        "src_port": 51286,
        "dst_ip": "192.168.56.20",
        "dst_port": 8443,
        "protocol": "tcp",
        "start_time": _ts(),
        "end_time": _ts() + timedelta(seconds=2),
        "duration_seconds": 2.0,
        "packet_count": 10,
        "byte_count": 1500,
        "tcp_stream": 0,
        "tls_detected": True,
        "tls_version": "TLS 1.3",
        "sni": "c2.lab",
    }
    base.update(overrides)
    return NetworkFlow.model_validate(base)


def test_network_flow_roundtrip() -> None:
    flow = _flow()
    parsed = NetworkFlow.model_validate_json(flow.model_dump_json())
    assert parsed == flow


def test_network_flow_rejects_bad_port() -> None:
    with pytest.raises(ValidationError):
        _flow(src_port=0)
    with pytest.raises(ValidationError):
        _flow(dst_port=70000)


def test_network_flow_rejects_unknown_protocol() -> None:
    with pytest.raises(ValidationError):
        _flow(protocol="sctp")


def test_network_flow_accepts_lowercase_protocol() -> None:
    flow = _flow(protocol="TCP")
    assert flow.protocol == "tcp"


def test_network_flow_requires_utc() -> None:
    with pytest.raises(ValidationError):
        _flow(start_time=datetime(2026, 1, 1))


# ---------------------------------------------------------------------------
# Process / Socket / TLS
# ---------------------------------------------------------------------------


def test_process_artifact_minimal() -> None:
    p = ProcessArtifact(experiment_id="EXP001", pid=4580, process_name="test-client.exe")
    assert p.executable_path is None
    assert p.parent_pid is None
    assert p.creation_time is None


def test_socket_artifact_minimal() -> None:
    s = SocketArtifact(
        experiment_id="EXP001",
        pid=4580,
        local_ip="192.168.56.108",
        local_port=51286,
        remote_ip="192.168.56.20",
        remote_port=8443,
        protocol="tcp",
    )
    assert s.state is None
    assert s.timestamp is None


def test_socket_artifact_rejects_bad_protocol() -> None:
    with pytest.raises(ValidationError):
        SocketArtifact(
            experiment_id="EXP001",
            pid=1,
            local_ip="0.0.0.0",
            local_port=1,
            protocol="sctp",
        )


def test_tls_artifact_can_be_absent() -> None:
    t = TLSArtifact(
        experiment_id="EXP001",
        absent=True,
        source="memory",
        confidence=0.6,
        notes="no TLS metadata recovered from process memory",
    )
    assert t.absent is True
    assert t.key_material_recovered is False
    assert t.tls_version is None


def test_tls_artifact_confidence_bounds() -> None:
    with pytest.raises(ValidationError):
        TLSArtifact(experiment_id="EXP001", source="pcap", confidence=1.5)


# ---------------------------------------------------------------------------
# Memory envelope
# ---------------------------------------------------------------------------


def test_memory_envelope_statuses() -> None:
    env = MemoryArtifactEnvelope(
        experiment_id="EXP001",
        artifact_kind="sockets",
        status=MemoryExtractionStatus.NOT_FOUND,
        source_tool="volatility3",
        notes="no socket structures recovered",
    )
    assert env.status == MemoryExtractionStatus.NOT_FOUND
    assert env.data == []


# ---------------------------------------------------------------------------
# Artifact / provenance
# ---------------------------------------------------------------------------


def test_artifact_provenance_validation() -> None:
    prov = ArtifactProvenance(
        source=ArtifactSource.PCAP,
        source_tool="tshark",
        source_plugin="-Y tcp.stream",
        experiment_id="EXP001",
        confidence=0.9,
    )
    art = Artifact(artifact_type="flow", data={"x": 1}, provenance=prov)
    assert art.artifact_type == "flow"


def test_artifact_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Artifact(
            artifact_type="flow",
            provenance=ArtifactProvenance(
                source=ArtifactSource.PCAP,
                experiment_id="EXP001",
                confidence=0.5,
            ),
            unknown_field=1,  # type: ignore[call-arg]
        )


def test_artifact_frozen() -> None:
    art = Artifact(
        artifact_type="flow",
        provenance=ArtifactProvenance(
            source=ArtifactSource.PCAP,
            experiment_id="EXP001",
            confidence=0.5,
        ),
    )
    with pytest.raises(ValidationError):
        art.artifact_type = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Correlation models
# ---------------------------------------------------------------------------


def test_correlation_factor_validation() -> None:
    f = CorrelationFactor(
        name="ip_match",
        matched=True,
        weight=0.25,
        contribution=0.25,
        detail="src/dst IPs match",
    )
    assert f.matched is True
    with pytest.raises(ValidationError):
        CorrelationFactor(
            name="not_a_factor",  # type: ignore[arg-type]
            matched=True,
            weight=0.1,
            contribution=0.1,
        )


def test_correlation_result_classification_values() -> None:
    res = CorrelationResult(
        experiment_id="EXP001",
        flow_id="flow-001",
        pid=4580,
        process_name="test-client.exe",
        confidence=0.94,
        classification="strong",
        evidence=CorrelationEvidence(
            pcap=True,
            memory_socket=True,
            ip_match=True,
            port_match=True,
            timestamp_match=True,
        ),
    )
    assert res.classification == "strong"
    assert res.evidence.ip_match is True


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


def test_timeline_event_requires_utc() -> None:
    with pytest.raises(ValidationError):
        TimelineEvent(
            experiment_id="EXP001",
            timestamp=datetime(2026, 1, 1),  # naive
            kind=TimelineEventKind.PROCESS_STARTED,
            source="memory",
            confidence=0.9,
        )


def test_timeline_event_kind_is_closed_vocabulary() -> None:
    evt = TimelineEvent(
        experiment_id="EXP001",
        timestamp=_ts(),
        kind=TimelineEventKind.TLS_ESTABLISHED,
        source="pcap",
        confidence=0.9,
    )
    assert evt.kind == TimelineEventKind.TLS_ESTABLISHED
