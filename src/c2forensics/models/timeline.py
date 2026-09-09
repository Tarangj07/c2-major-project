"""Timeline event model.

A timeline event is a typed, timestamped observation that originated in
either a PCAP, a memory image, or a derived stage. Events are sorted
strictly by timestamp at rendering time; storing a sort order in the
model itself would be brittle.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import Field, field_validator

from c2forensics.models.common import FrozenModel, identifier_field


class TimelineEventKind(str, Enum):
    """Closed vocabulary of timeline event kinds.

    New event kinds may be added in later phases; downstream consumers must
    be able to handle unknown values gracefully (e.g. via a default case).
    """

    PROCESS_STARTED = "process_started"
    CONNECTION_ESTABLISHED = "connection_established"
    TLS_ESTABLISHED = "tls_established"
    C2_MESSAGE_OBSERVED = "c2_message_observed"
    CONNECTION_CLOSED = "connection_closed"
    PROCESS_TERMINATED = "process_terminated"
    MEMORY_ACQUIRED = "memory_acquired"
    PCAP_ACQUIRED = "pcap_acquired"
    ARTIFACT_RECOVERED = "artifact_recovered"


class TimelineEvent(FrozenModel):
    """A single timestamped event in the experiment timeline."""

    experiment_id: str = identifier_field("Identifier of the experiment.")
    timestamp: datetime = Field(description="UTC timestamp of the event.")
    kind: TimelineEventKind = Field(description="Closed-vocabulary event kind.")
    source: str = Field(
        min_length=1,
        description=(
            "Originating source of the event, e.g. 'pcap', 'memory', "
            "'ground_truth', 'derived'."
        ),
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Source-level confidence in [0, 1].",
    )
    description: str = Field(
        default="",
        description="Human-readable description of the event.",
    )
    flow_id: str | None = Field(
        default=None,
        description="Flow identifier, when the event is tied to a flow.",
    )
    pid: int | None = Field(
        default=None,
        ge=0,
        description="PID, when the event is tied to a process.",
    )

    @field_validator("timestamp")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError("timestamps must be timezone-aware (UTC).")
        return value
