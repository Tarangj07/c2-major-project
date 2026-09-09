"""Unit tests for the new Phase 2 PCAP-specific models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from c2forensics.models.pcap import (
    FlowObservation,
    NetworkEvidence,
    TCPLifecycleEvent,
    TCPLifecycleFlag,
    TLSHandshakeKind,
    TLSObservation,
)

UTC = timezone.utc


def _ts(seconds: int = 1_700_000_000) -> datetime:
    return datetime.fromtimestamp(seconds, tz=UTC)


def test_flow_observation_roundtrip() -> None:
    f = FlowObservation(
        experiment_id="EXP001",
        flow_id="tcp:1.1.1.1:1->2.2.2.2:2#0",
        src_ip="1.1.1.1",
        src_port=1,
        dst_ip="2.2.2.2",
        dst_port=2,
        protocol="tcp",
        tcp_stream=0,
        first_seen=_ts(),
        last_seen=_ts(1_700_000_005),
        frame_count=10,
        byte_count=1500,
    )
    payload = f.model_dump_json()
    parsed = FlowObservation.model_validate_json(payload)
    assert parsed == f


def test_flow_observation_rejects_zero_port() -> None:
    with pytest.raises(ValidationError):
        FlowObservation(
            experiment_id="EXP001",
            flow_id="x",
            src_ip="1.1.1.1",
            src_port=0,
            dst_ip="2.2.2.2",
            dst_port=2,
            protocol="tcp",
            first_seen=_ts(),
            last_seen=_ts(),
        )


def test_flow_observation_rejects_bad_protocol() -> None:
    with pytest.raises(ValidationError):
        FlowObservation(
            experiment_id="EXP001",
            flow_id="x",
            src_ip="1.1.1.1",
            src_port=1,
            dst_ip="2.2.2.2",
            dst_port=2,
            protocol="sctp",
            first_seen=_ts(),
            last_seen=_ts(),
        )


def test_flow_observation_derived_duration_is_documented() -> None:
    # The docstring tags duration_seconds / frames_per_second /
    # bytes_per_second as DERIVED. The model accepts them as inputs
    # but only if they agree with what would be computed from the
    # observed fields. This test asserts the round-trip: a correctly
    # supplied derived value is preserved.
    f = FlowObservation(
        experiment_id="EXP001",
        flow_id="x",
        src_ip="1.1.1.1",
        src_port=1,
        dst_ip="2.2.2.2",
        dst_port=2,
        protocol="tcp",
        first_seen=_ts(1_700_000_000),
        last_seen=_ts(1_700_000_010),
        frame_count=10,
        byte_count=2000,
        duration_seconds=10.0,
        frames_per_second=1.0,
        bytes_per_second=200.0,
    )
    assert f.duration_seconds == 10.0
    assert f.frames_per_second == 1.0
    assert f.bytes_per_second == 200.0


def test_flow_observation_rejects_inconsistent_derived() -> None:
    # If a caller supplies a derived field that contradicts the
    # observed fields, the model raises rather than silently storing
    # an inconsistent record.
    with pytest.raises(ValidationError):
        FlowObservation(
            experiment_id="EXP001",
            flow_id="x",
            src_ip="1.1.1.1",
            src_port=1,
            dst_ip="2.2.2.2",
            dst_port=2,
            protocol="tcp",
            first_seen=_ts(1_700_000_000),
            last_seen=_ts(1_700_000_010),
            frame_count=10,
            byte_count=2000,
            duration_seconds=999.0,  # obviously wrong
        )


def test_tcp_lifecycle_event_direction_validation() -> None:
    base = dict(
        experiment_id="EXP001",
        flow_id="x",
        timestamp=_ts(),
        flag=TCPLifecycleFlag.SYN,
        frame_number=1,
    )
    TCPLifecycleEvent(direction="c2s", **base)
    TCPLifecycleEvent(direction="S2C", **base)  # case-insensitive normalisation
    with pytest.raises(ValidationError):
        TCPLifecycleEvent(direction="sideways", **base)


def test_tls_observation_present_default_true() -> None:
    o = TLSObservation(
        experiment_id="EXP001",
        flow_id="x",
        timestamp=_ts(),
        kind=TLSHandshakeKind.CLIENT_HELLO,
        frame_number=4,
    )
    assert o.present is True


def test_network_evidence_requires_utc_extracted_at() -> None:
    with pytest.raises(ValidationError):
        NetworkEvidence(
            experiment_id="EXP001",
            pcap_path="/tmp/c.pcap",
            pcap_sha256="0" * 64,
            extractor_version="x",
            extracted_at=datetime(2026, 1, 1),  # naive
        )


def test_network_evidence_roundtrip() -> None:
    e = NetworkEvidence(
        experiment_id="EXP001",
        pcap_path="/tmp/c.pcap",
        pcap_sha256="a" * 64,
        extractor_version="TShark 4.2.0",
        extracted_at=_ts(),
    )
    parsed = NetworkEvidence.model_validate_json(e.model_dump_json())
    assert parsed == e
