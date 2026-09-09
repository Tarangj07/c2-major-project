"""Socket artefact model extracted from volatile memory.

A socket is the OS-level handle that ties a process to a network endpoint.
Recovering a socket from memory and matching it to a network flow is the
core of the RQ1 attribution hypothesis: even when the application data on
the wire is encrypted, the local endpoint of the connection is observable
in the process's address space.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field, field_validator

from c2forensics.models.common import FrozenModel, identifier_field


def _require_utc_optional(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        raise ValueError("timestamps must be timezone-aware (UTC).")
    return value


class SocketArtifact(FrozenModel):
    """A socket observed in volatile memory, tied to a PID."""

    experiment_id: str = identifier_field("Identifier of the experiment.")
    pid: int = Field(ge=0, description="PID of the owning process.")
    local_ip: str = identifier_field("Local IP literal of the socket.")
    local_port: int = Field(ge=1, le=65535)
    remote_ip: str | None = Field(
        default=None,
        description="Remote IP literal; None for unbound sockets.",
    )
    remote_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Remote port; None for unbound sockets.",
    )
    protocol: str = Field(
        min_length=1,
        description="Transport protocol, e.g. 'tcp' or 'udp'.",
    )
    state: str | None = Field(
        default=None,
        description="Socket state, e.g. 'ESTABLISHED', 'LISTENING', 'TIME_WAIT'.",
    )
    timestamp: datetime | None = Field(
        default=None,
        description="UTC timestamp at which the socket was observed in memory.",
    )

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, value: datetime | None) -> datetime | None:
        return _require_utc_optional(value)

    @field_validator("protocol")
    @classmethod
    def _validate_protocol(cls, value: str) -> str:
        v = value.strip().lower()
        if v not in {"tcp", "udp"}:
            raise ValueError(f"unsupported transport protocol: {value!r}")
        return v
