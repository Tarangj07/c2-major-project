"""Network flow model extracted from a PCAP."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field, field_validator

from c2forensics.models.common import FrozenModel, identifier_field


def _require_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        raise ValueError("timestamps must be timezone-aware (UTC).")
    return value


class NetworkFlow(FrozenModel):
    """A single unidirectional or bidirectional flow extracted from a PCAP.

    A flow is identified by the canonical 5-tuple
    ``(src_ip, src_port, dst_ip, dst_port, protocol)`` together with a
    stream index. The framework treats flows as the primary unit of network
    evidence; later stages correlate flows with socket artefacts from memory.

    The PCAP-extraction stage populates this model with only what is
    directly observable on the wire. Process attribution is *not* a
    field on this model; it is the responsibility of the Phase 4
    correlation engine, which correlates ``NetworkFlow`` against
    ``SocketArtifact`` records from memory.
    """

    experiment_id: str = identifier_field("Identifier of the experiment.")
    flow_id: str = identifier_field("Stable identifier of this flow within the experiment.")
    src_ip: str = identifier_field("Source IP literal.")
    src_port: int = Field(ge=1, le=65535)
    dst_ip: str = identifier_field("Destination IP literal.")
    dst_port: int = Field(ge=1, le=65535)
    protocol: str = Field(
        min_length=1,
        description="Lower-case transport name, e.g. 'tcp' or 'udp'.",
    )
    start_time: datetime | None = Field(
        default=None,
        description="UTC timestamp of the first observed packet in the flow.",
    )
    end_time: datetime | None = Field(
        default=None,
        description="UTC timestamp of the last observed packet in the flow.",
    )
    duration_seconds: float | None = Field(
        default=None,
        ge=0.0,
        description="Duration of the flow in seconds; None if it cannot be determined.",
    )
    packet_count: int = Field(ge=0, description="Number of packets observed in the flow.")
    byte_count: int = Field(ge=0, description="Number of bytes (sum of frame.len) in the flow.")
    tcp_stream: int | None = Field(
        default=None,
        ge=0,
        description="Wireshark TCP stream index, when available.",
    )
    tls_detected: bool = Field(
        default=False,
        description="True if a TLS handshake was observed for this flow.",
    )
    tls_version: str | None = Field(
        default=None,
        description="Negotiated TLS version, e.g. 'TLS 1.3'.",
    )
    sni: str | None = Field(
        default=None,
        description="Server Name Indication value, when present in the ClientHello.",
    )
    # Provenance. Populated by the Phase 2 PCAP extractor; optional so the
    # model remains usable in unit tests that do not run tshark.
    pcap_path: str | None = Field(
        default=None,
        description="Path of the source PCAP that produced this flow.",
    )
    pcap_sha256: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="Hex-encoded SHA-256 digest of the source PCAP at extraction time.",
    )
    extractor_version: str | None = Field(
        default=None,
        description="Version string of the extractor that produced this flow.",
    )

    @field_validator("start_time", "end_time")
    @classmethod
    def _validate_timestamps(cls, value: datetime | None) -> datetime | None:
        return _require_utc(value)

    @field_validator("protocol")
    @classmethod
    def _validate_protocol(cls, value: str) -> str:
        v = value.strip().lower()
        if v not in {"tcp", "udp"}:
            # PCAPs may carry other transports; the framework is restrictive
            # here on purpose so that a malformed flow is rejected loudly.
            raise ValueError(f"unsupported transport protocol: {value!r}")
        return v
