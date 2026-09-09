"""PCAP-extraction-specific models.

These are the typed records produced by the Phase 2 PCAP extractor.
They reuse the Phase 1 models (``NetworkFlow``, ``TLSArtifact``,
``Artifact``, ``ArtifactProvenance``) wherever possible and only add
the strictly new shapes.

The vocabulary here mirrors the "observed vs derived vs inferred"
boundary that the dissertation requires:

* ``FlowObservation`` is a per-frame, per-flow aggregation that records
  exactly what was observed in the PCAP.
* ``TCPLifecycleEvent`` records SYN/SYN-ACK/ACK/FIN/RST observations
  with frame numbers and timestamps. Each event is an *observation*.
* ``TLSObservation`` records a single TLS handshake message
  (ClientHello / ServerHello / Finished) at a specific time.
* ``NetworkEvidence`` is the deterministic output bundle produced for
  one experiment: it groups observations into flows and surfaces a
  coarse list of derived values.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import Field, field_validator, model_validator

from c2forensics.models.common import FrozenModel, identifier_field


# ---------------------------------------------------------------------------
# TCP lifecycle events (OBSERVED)
# ---------------------------------------------------------------------------


class TCPLifecycleFlag(str, Enum):
    """TCP control-flag observations extracted from a PCAP.

    Each value corresponds to a single observed frame. The PCAP layer
    never *infers* a flag from the surrounding traffic; if the flag is
    not set in the captured TCP header, it is not recorded.
    """

    SYN = "syn"
    SYN_ACK = "syn_ack"
    ACK = "ack"
    FIN = "fin"
    RST = "rst"


class TCPLifecycleEvent(FrozenModel):
    """A single TCP control-flag observation.

    The ``frame_number`` field allows a downstream consumer to trace
    this event back to the original PCAP. ``direction`` distinguishes
    client-to-server (``"c2s"``) from server-to-client (``"s2c"``) by
    comparing each packet's endpoint to the canonical 5-tuple derived
    from the first observed SYN.
    """

    experiment_id: str = identifier_field("Identifier of the experiment.")
    flow_id: str = identifier_field("Identifier of the flow this event belongs to.")
    timestamp: datetime = Field(description="UTC timestamp of the frame.")
    flag: TCPLifecycleFlag = Field(description="Observed TCP control flag.")
    direction: str = Field(
        min_length=1,
        description="Packet direction relative to the initiator: 'c2s' or 's2c'.",
    )
    frame_number: int = Field(ge=1, description="1-based frame number in the PCAP.")

    @field_validator("timestamp")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError("timestamps must be timezone-aware (UTC).")
        return value

    @field_validator("direction")
    @classmethod
    def _validate_direction(cls, value: str) -> str:
        v = value.strip().lower()
        if v not in {"c2s", "s2c"}:
            raise ValueError("direction must be 'c2s' or 's2c'")
        return v


# ---------------------------------------------------------------------------
# TLS handshake observations (OBSERVED)
# ---------------------------------------------------------------------------


class TLSHandshakeKind(str, Enum):
    """The specific TLS handshake message observed."""

    CLIENT_HELLO = "client_hello"
    SERVER_HELLO = "server_hello"
    FINISHED = "finished"
    CERTIFICATE = "certificate"


class TLSObservation(FrozenModel):
    """A single observed TLS handshake message.

    The observation is intentionally narrow: only the *fields that
    appear on the wire in cleartext* are recorded. Anything the
    extractor derives from the surrounding context is documented
    separately in the ``NetworkEvidence`` bundle.

    The ``present`` field defaults to ``True``; the only ``False`` value
    is reserved for "looked for, did not find" envelopes used by
    correlation. PCAP observations always set it to ``True``.
    """

    experiment_id: str = identifier_field("Identifier of the experiment.")
    flow_id: str = identifier_field("Identifier of the flow this event belongs to.")
    timestamp: datetime = Field(description="UTC timestamp of the frame.")
    kind: TLSHandshakeKind = Field(description="Type of TLS handshake message.")
    frame_number: int = Field(ge=1, description="1-based frame number in the PCAP.")
    tls_version: str | None = Field(
        default=None,
        description="TLS version from the handshake message, e.g. 'TLS 1.3'.",
    )
    sni: str | None = Field(
        default=None,
        description="Server Name Indication value, when present in the ClientHello.",
    )
    cipher_suite: str | None = Field(
        default=None,
        description="Cipher suite identifier, when present in the ServerHello.",
    )
    certificate_subject: str | None = Field(
        default=None,
        description="Certificate subject DN, when a Certificate message was observed.",
    )
    certificate_issuer: str | None = Field(
        default=None,
        description="Certificate issuer DN, when a Certificate message was observed.",
    )
    present: bool = Field(default=True, description="True iff the message was observed.")

    @field_validator("timestamp")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError("timestamps must be timezone-aware (UTC).")
        return value


# ---------------------------------------------------------------------------
# Per-flow aggregation (DERIVED from observations)
# ---------------------------------------------------------------------------


class FlowObservation(FrozenModel):
    """A per-flow aggregation of *observed* PCAP facts.

    The fields are either directly observed in the PCAP (frame counts,
    byte counts, TCP stream index, first/last seen times) or derived
    deterministically from observations (duration, packet rate, byte
    rate). Each field's provenance is documented in the docstring.
    """

    experiment_id: str = identifier_field("Identifier of the experiment.")
    flow_id: str = identifier_field("Identifier of this flow within the experiment.")
    src_ip: str = identifier_field("Initiator source IP literal (observed in SYN).")
    src_port: int = Field(ge=1, le=65535, description="Initiator source port (observed in SYN).")
    dst_ip: str = identifier_field("Destination IP literal (observed in SYN).")
    dst_port: int = Field(ge=1, le=65535, description="Destination port (observed in SYN).")
    protocol: str = Field(min_length=1, description="Transport protocol, 'tcp' or 'udp'.")
    tcp_stream: int | None = Field(
        default=None,
        ge=0,
        description="Wireshark TCP stream index, when available (observed).",
    )
    first_seen: datetime = Field(description="UTC timestamp of the first frame (observed).")
    last_seen: datetime = Field(description="UTC timestamp of the last frame (observed).")
    frame_count: int = Field(ge=0, description="Number of frames in the flow (observed).")
    byte_count: int = Field(ge=0, description="Sum of frame.len in the flow (observed).")
    # Derived (NOT observed) fields. The parser computes them from the
    # observed fields above; they are optional on the model so that
    # callers can construct a ``FlowObservation`` with only the
    # observed fields and let the validator fill in the derived ones.
    duration_seconds: float | None = Field(
        default=None,
        ge=0.0,
        description="(DERIVED) last_seen - first_seen, in seconds.",
    )
    frames_per_second: float | None = Field(
        default=None,
        ge=0.0,
        description="(DERIVED) frame_count / duration_seconds when duration > 0, else 0.",
    )
    bytes_per_second: float | None = Field(
        default=None,
        ge=0.0,
        description="(DERIVED) byte_count / duration_seconds when duration > 0, else 0.",
    )

    @model_validator(mode="after")
    def _check_derived(self) -> "FlowObservation":
        """Validate that any supplied derived fields are consistent.

        The derived fields are computed by the parser and are not
        independent inputs. If a caller supplies a derived value
        that disagrees with what would be computed from the observed
        fields, we raise a ``ValueError`` so the contract violation
        surfaces loudly rather than silently corrupting a downstream
        calculation.
        """
        observed_duration = max(
            0.0, (self.last_seen - self.first_seen).total_seconds()
        )
        if self.duration_seconds is not None:
            if abs(self.duration_seconds - observed_duration) > 1e-9:
                raise ValueError(
                    f"duration_seconds={self.duration_seconds} does not match "
                    f"last_seen - first_seen = {observed_duration}"
                )
        return self

    @field_validator("protocol")
    @classmethod
    def _validate_protocol(cls, value: str) -> str:
        v = value.strip().lower()
        if v not in {"tcp", "udp"}:
            raise ValueError(f"unsupported transport protocol: {value!r}")
        return v

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError("timestamps must be timezone-aware (UTC).")
        return value


# ---------------------------------------------------------------------------
# Output bundle
# ---------------------------------------------------------------------------


class NetworkEvidence(FrozenModel):
    """The deterministic, fully-typed output of the PCAP extractor.

    Provenance lives in three places:

    * ``pcap_path`` and ``pcap_sha256`` identify the source PCAP and
      its digest at extraction time.
    * ``extractor_name`` / ``extractor_version`` identify the tool that
      produced this bundle.
    * ``extracted_at`` is the UTC time the extractor ran.

    Every ``flow`` carries an embedded ``flow_id`` and a list of
    associated TCP/TLS observations. The correlation stage in Phase 4
    is the only consumer that may *infer* process attribution; this
    bundle deliberately contains no PID field.
    """

    experiment_id: str = identifier_field("Identifier of the experiment.")
    pcap_path: str = identifier_field("Absolute or repo-relative path of the source PCAP.")
    pcap_sha256: str = Field(
        min_length=64,
        max_length=64,
        description="Hex-encoded SHA-256 digest of the source PCAP at extraction time.",
    )
    extractor_name: str = Field(default="tshark", min_length=1)
    extractor_version: str = Field(default="unknown", min_length=1)
    extracted_at: datetime = Field(description="UTC timestamp of the extraction run.")
    flows: list[FlowObservation] = Field(
        default_factory=list,
        description="Per-flow observed-and-derived aggregation.",
    )
    tcp_lifecycle: list[TCPLifecycleEvent] = Field(
        default_factory=list,
        description="Every observed TCP control-flag event, in PCAP order.",
    )
    tls_observations: list[TLSObservation] = Field(
        default_factory=list,
        description="Every observed TLS handshake message, in PCAP order.",
    )

    @field_validator("extracted_at")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError("timestamps must be timezone-aware (UTC).")
        return value
