"""Experiment metadata and ground-truth models.

An *experiment* is a self-contained, reproducible unit of forensic work. Each
experiment owns its raw evidence, intermediate products, and evaluation
outputs. Experiments are identified by a stable string ID and a SHA-256 hash
of the raw evidence is recorded at acquisition time so that downstream
analyses can be re-run deterministically.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import Field, field_validator

from c2forensics.models.common import FrozenModel


_EXPERIMENT_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


class ExperimentStatus(str, Enum):
    """Lifecycle state of an experiment directory.

    Experiments move monotonically through these states. A terminal
    ``COMPLETED`` or ``FAILED`` state is recorded in ``metadata.json`` so
    that an interrupted run can be safely resumed.
    """

    INITIALIZED = "initialized"
    EVIDENCE_ACQUIRED = "evidence_acquired"
    EXTRACTED = "extracted"
    NORMALIZED = "normalized"
    CORRELATED = "correlated"
    RECONSTRUCTED = "reconstructed"
    TIMED = "timed"
    EVALUATED = "evaluated"
    COMPLETED = "completed"
    FAILED = "failed"


class ToolVersions(FrozenModel):
    """Tool versions captured at experiment-creation time for reproducibility."""

    python: str = Field(min_length=1)
    tshark: str | None = None
    volatility3: str | None = None
    framework: str = Field(min_length=1)
    os: str = Field(min_length=1, description="OS string reported by the platform module.")
    notes: str | None = Field(
        default=None,
        description="Free-form notes about the toolchain, e.g. distribution package versions.",
    )


class ExperimentMetadata(FrozenModel):
    """Top-level metadata for a single experiment.

    This object is the *only* mutable, framework-controlled file inside the
    experiment directory. Raw evidence is never modified after acquisition.
    """

    experiment_id: str = Field(
        min_length=1,
        max_length=64,
        description="Stable identifier for the experiment. Used as the directory name.",
    )
    created_at: datetime = Field(
        description="UTC timestamp at which the experiment was created.",
    )
    updated_at: datetime = Field(
        description="UTC timestamp at which the metadata was last modified.",
    )
    status: ExperimentStatus = Field(
        default=ExperimentStatus.INITIALIZED,
        description="Lifecycle state of the experiment.",
    )
    description: str = Field(
        default="",
        description="Human-readable description of the experiment's purpose.",
    )
    target_host: str | None = Field(
        default=None,
        description="IP of the forensic target (the benign test client).",
    )
    c2_server_host: str | None = Field(
        default=None,
        description="IP of the controlled C2 server.",
    )
    c2_server_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="TCP port of the C2 server.",
    )
    protocol: str = Field(
        default="tls",
        description="Transport protocol under test, e.g. 'tls'.",
    )
    tool_versions: ToolVersions | None = Field(
        default=None,
        description="Tool versions captured at experiment creation time.",
    )
    raw_hashes: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Map of relative raw-evidence path (under the experiment directory) "
            "to a hex-encoded SHA-256 digest. Populated at acquisition time."
        ),
    )
    config_snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Snapshot of the relevant lab configuration at experiment creation "
            "time, so that an experiment can be analysed without re-reading lab.yaml."
        ),
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Free-form tags for grouping experiments in evaluation reports.",
    )

    @field_validator("experiment_id")
    @classmethod
    def _validate_experiment_id(cls, value: str) -> str:
        if not _EXPERIMENT_ID_PATTERN.fullmatch(value):
            raise ValueError(
                "experiment_id must match ^[A-Za-z][A-Za-z0-9_-]{0,63}$"
            )
        return value

    @field_validator("created_at", "updated_at")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware (UTC).")
        if value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError("timestamps must be in UTC.")
        return value


class GroundTruth(FrozenModel):
    """Ground truth recorded by the controlled C2 simulator.

    The forensic framework never uses ground truth to *produce* an answer.
    Ground truth is consumed only by the evaluation stage. This separation
    is essential to a scientifically valid experiment.
    """

    experiment_id: str = Field(min_length=1, max_length=64)
    client_id: str = Field(
        min_length=1,
        description="Identifier of the benign test client in the simulator.",
    )
    pid: int = Field(ge=0, description="OS-level PID of the test client.")
    client_ip: str = Field(min_length=1, description="IP of the test client.")
    client_port: int = Field(ge=1, le=65535, description="Ephemeral source port used by the client.")
    server_ip: str = Field(min_length=1, description="IP of the C2 server.")
    server_port: int = Field(ge=1, le=65535, description="TCP port of the C2 server.")
    tls_version: str | None = Field(
        default=None,
        description="Negotiated TLS version, e.g. 'TLS 1.3'.",
    )
    connection_start: datetime | None = Field(
        default=None,
        description="UTC timestamp at which the connection was established.",
    )
    connection_end: datetime | None = Field(
        default=None,
        description="UTC timestamp at which the connection was closed.",
    )
    heartbeat_timestamps: list[datetime] = Field(
        default_factory=list,
        description="UTC timestamps of every heartbeat emitted by the client.",
    )
    notes: str = Field(default="", description="Free-form simulator notes.")

    @field_validator("connection_start", "connection_end")
    @classmethod
    def _require_utc_optional(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError("timestamps must be timezone-aware (UTC).")
        return value

    @field_validator("heartbeat_timestamps")
    @classmethod
    def _require_utc_list(cls, values: list[datetime]) -> list[datetime]:
        for v in values:
            if v.tzinfo is None or v.utcoffset() != timezone.utc.utcoffset(v):
                raise ValueError("heartbeat timestamps must be timezone-aware (UTC).")
        return values
