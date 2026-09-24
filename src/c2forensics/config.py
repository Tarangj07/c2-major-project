"""Configuration loading.

The framework consumes a single YAML file (``config/lab.yaml`` by default)
that describes the laboratory environment, external tool locations, and
the default correlation weights/thresholds. The configuration is loaded
exactly once per CLI invocation and frozen; downstream modules receive
sub-views (``LabConfig.lab``, ``LabConfig.tools``, ``LabConfig.correlation``)
so they cannot accidentally mutate shared state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class LabSection(BaseModel):
    """The ``lab:`` section of the configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network_cidr: str = Field(min_length=1)
    target_host: str = Field(min_length=1)
    c2_server_host: str = Field(min_length=1)
    c2_server_port: int = Field(ge=1, le=65535)


class _ToolSpec(BaseModel):
    """A description of how to invoke an external tool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = Field(min_length=1, description="Executable name or absolute path.")
    timeout_seconds: int = Field(
        default=300,
        ge=1,
        le=24 * 3600,
        description="Hard timeout per invocation, in seconds.",
    )


class ToolsSection(BaseModel):
    """The ``tools:`` section of the configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tshark: _ToolSpec
    volatility3: _ToolSpec


class CorrelationWeights(BaseModel):
    """Per-factor weights for the correlation engine."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ip_match: float = Field(ge=0.0, le=1.0)
    port_match: float = Field(ge=0.0, le=1.0)
    protocol_match: float = Field(ge=0.0, le=1.0)
    timestamp_proximity: float = Field(ge=0.0, le=1.0)
    socket_match: float = Field(ge=0.0, le=1.0)
    process_association: float = Field(ge=0.0, le=1.0)
    tls_metadata_match: float = Field(default=0.0, ge=0.0, le=1.0)

    def total(self) -> float:
        """Return the sum of all weights, including reserved factors."""
        return float(
            self.ip_match
            + self.port_match
            + self.protocol_match
            + self.timestamp_proximity
            + self.socket_match
            + self.process_association
            + self.tls_metadata_match
        )

    def active_total(self) -> float:
        """Return the sum of weights eligible for Phase 4 scoring."""
        return float(
            self.port_match
            + self.protocol_match
            + self.timestamp_proximity
            + self.process_association
        )


class CorrelationThresholds(BaseModel):
    """Score thresholds for the ``strong``/``medium``/``weak`` classification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    strong: float = Field(ge=0.0, le=1.0)
    medium: float = Field(ge=0.0, le=1.0)
    weak: float = Field(ge=0.0, le=1.0)

    @field_validator("medium")
    @classmethod
    def _medium_le_strong(cls, v: float, info: Any) -> float:
        strong = info.data.get("strong")
        if strong is not None and v > strong:
            raise ValueError("correlation.thresholds.medium must be <= strong")
        return v

    @field_validator("weak")
    @classmethod
    def _weak_le_medium(cls, v: float, info: Any) -> float:
        medium = info.data.get("medium")
        if medium is not None and v > medium:
            raise ValueError("correlation.thresholds.weak must be <= medium")
        return v


class CorrelationSection(BaseModel):
    """The ``correlation:`` section of the configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    weights: CorrelationWeights
    timestamp_tolerance_seconds: float = Field(default=5.0, gt=0.0)
    ambiguity_margin: float = Field(default=0.05, ge=0.0, le=1.0)
    thresholds: CorrelationThresholds

    @model_validator(mode="after")
    def _require_active_weights(self) -> "CorrelationSection":
        if self.weights.active_total() <= 0.0:
            raise ValueError(
                "at least one Phase 4 active weight (port_match, protocol_match, "
                "timestamp_proximity, process_association) must be > 0"
            )
        return self


@dataclass(frozen=True)
class LabConfig:
    """Frozen view of the loaded lab configuration."""

    config_path: Path
    lab: LabSection
    tools: ToolsSection
    correlation: CorrelationSection
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def repo_root(self) -> Path:
        """The repository root is the parent of the config file's directory.

        This assumes the conventional layout where ``config/lab.yaml`` lives
        at the repository root. For a packaged install with no ``config/``
        directory next to it, the caller is expected to pass an explicit
        repo root.
        """
        return self.config_path.resolve().parent.parent

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serialisable snapshot of the configuration.

        Used to embed configuration in experiment metadata for reproducibility.
        """
        return self.raw


def load_config(path: Path) -> LabConfig:
    """Load and validate the lab configuration from ``path``.

    The function raises ``FileNotFoundError`` if the file is missing and
    ``ValueError`` (via Pydantic) if it is malformed. Both are the caller's
    responsibility to surface clearly.
    """
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"lab config not found: {resolved}")
    with resolved.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"lab config must be a YAML mapping, got {type(raw).__name__}")
    return LabConfig(
        config_path=resolved,
        lab=LabSection.model_validate(raw["lab"]),
        tools=ToolsSection.model_validate(raw["tools"]),
        correlation=CorrelationSection.model_validate(raw["correlation"]),
        raw=raw,
    )
