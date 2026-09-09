"""Generic artefact envelope and source-provenance types.

Every forensic artefact in the pipeline — regardless of whether it was
extracted from a PCAP, a memory image, ground truth, or derived from other
artefacts — must carry provenance. This module defines the vocabulary for
that provenance.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import Field

from c2forensics.models.common import FrozenModel


class ArtifactSource(str, Enum):
    """Where a forensic artefact originally came from.

    The framework never silently infers an artefact; every value must be
    traceable to one of these sources. ``DERIVED`` is reserved for artefacts
    produced by the pipeline itself (e.g. a correlation result).
    """

    PCAP = "pcap"
    MEMORY = "memory"
    GROUND_TRUTH = "ground_truth"
    MANUAL = "manual"
    DERIVED = "derived"


class ArtifactProvenance(FrozenModel):
    """Provenance metadata attached to every artefact.

    This is intentionally a small, fixed-shape envelope so that downstream
    code can reason about sources uniformly.
    """

    source: ArtifactSource = Field(description="Originating source of the artefact.")
    source_tool: str | None = Field(
        default=None,
        description="Tool that produced the artefact, e.g. 'tshark' or 'volatility3'.",
    )
    source_plugin: str | None = Field(
        default=None,
        description=(
            "Sub-component / plugin / filter that produced the artefact, "
            "e.g. 'vol --plugins=windows.netscan.NetScan' or '-Y tls.handshake'."
        ),
    )
    experiment_id: str = Field(
        min_length=1,
        description="Identifier of the experiment this artefact belongs to.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Source-level confidence in [0, 1]. This reflects the reliability "
            "of the extraction method, not the strength of any correlation. "
            "A tshark-extracted field has confidence 1.0 only when the "
            "field is unambiguous in the protocol; inferred values must score lower."
        ),
    )


class Artifact(FrozenModel):
    """Generic envelope for a forensic artefact with its raw payload.

    The framework is intentionally permissive about the *shape* of the raw
    payload (``data``), but strict about its *provenance* (``provenance``).
    Pipeline code that needs a more specific shape should narrow the payload
    into a specialised model (e.g. ``NetworkFlow``).
    """

    artifact_type: str = Field(
        min_length=1,
        description="Logical type of the artefact, e.g. 'socket', 'flow', 'process'.",
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw structured payload. Schema depends on artifact_type.",
    )
    provenance: ArtifactProvenance = Field(description="Where this artefact came from.")
