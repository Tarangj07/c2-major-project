"""Correlation result models.

The correlation engine is the central research component of the framework.
It produces *explainable* results: every correlation record stores both the
overall confidence and the individual factor-level evidence that produced it.
Weights are configurable and never hard-coded as scientifically validated.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from c2forensics.models.common import FrozenModel, identifier_field


FactorName = Literal[
    "ip_match",
    "port_match",
    "protocol_match",
    "timestamp_proximity",
    "socket_match",
    "process_association",
    "tls_metadata_match",
]


class CorrelationFactor(FrozenModel):
    """A single factor contributing to a correlation score."""

    name: FactorName = Field(description="Identifier of the factor.")
    matched: bool = Field(description="True iff the factor matched for this pair.")
    weight: float = Field(
        ge=0.0,
        le=1.0,
        description="Weight assigned to this factor in the configuration.",
    )
    contribution: float = Field(
        ge=0.0,
        le=1.0,
        description="Weight contributed to the overall score: weight if matched, else 0.",
    )
    detail: str = Field(
        default="",
        description="Free-form human-readable explanation of how the factor was evaluated.",
    )


class CorrelationEvidence(FrozenModel):
    """Coarse-grained evidence flags exposed to human readers.

    These are the public-facing flags that say, at a glance, what kinds of
    evidence supported a correlation. They are *derived* from the per-factor
    ``CorrelationFactor`` records; they are not the scoring primitives.
    """

    pcap: bool = False
    memory_socket: bool = False
    ip_match: bool = False
    port_match: bool = False
    timestamp_match: bool = False
    process_match: bool = False
    tls_match: bool = False


class CorrelationResult(FrozenModel):
    """The result of correlating one network flow with one memory process."""

    experiment_id: str = identifier_field("Identifier of the experiment.")
    flow_id: str = identifier_field("Identifier of the correlated flow.")
    pid: int = Field(ge=0, description="PID of the candidate process.")
    process_name: str = Field(
        default="",
        description="Process name at the time of correlation, when known.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Overall correlation confidence in [0, 1].",
    )
    classification: Literal["strong", "medium", "weak", "none"] = Field(
        description=(
            "Classification derived from configurable thresholds. 'none' is "
            "returned when the score is below the weakest threshold, so that "
            "downstream stages can still see the row."
        ),
    )
    factors: list[CorrelationFactor] = Field(
        default_factory=list,
        description="Per-factor evidence that produced the overall score.",
    )
    evidence: CorrelationEvidence = Field(
        default_factory=CorrelationEvidence,
        description="Coarse-grained public evidence flags.",
    )
