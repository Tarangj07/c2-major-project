"""Process artefact model extracted from volatile memory."""

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


class ProcessArtifact(FrozenModel):
    """A process observed in volatile memory."""

    experiment_id: str = identifier_field("Identifier of the experiment.")
    pid: int = Field(ge=0, description="OS-level PID of the process.")
    process_name: str = identifier_field("Short name of the process, e.g. 'test-client.exe'.")
    executable_path: str | None = Field(
        default=None,
        description="Full path of the executable on disk, when recoverable.",
    )
    parent_pid: int | None = Field(
        default=None,
        ge=0,
        description="OS-level PID of the parent process, when recoverable.",
    )
    creation_time: datetime | None = Field(
        default=None,
        description="UTC timestamp at which the process was created.",
    )
    termination_time: datetime | None = Field(
        default=None,
        description="UTC timestamp at which the process was observed as terminated.",
    )

    @field_validator("creation_time", "termination_time")
    @classmethod
    def _validate_timestamps(cls, value: datetime | None) -> datetime | None:
        return _require_utc_optional(value)
