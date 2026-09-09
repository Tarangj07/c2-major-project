"""Memory-artefact envelope.

The memory backend (Volatility 3) may produce a heterogeneous collection of
artefacts. Until Phase 3 lands the actual backend, the framework represents
the output of any memory extractor as a typed envelope with explicit
``not_found`` / ``not_supported`` states.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import Field

from c2forensics.models.common import FrozenModel, identifier_field


class MemoryExtractionStatus(str, Enum):
    """Status of a single memory-extraction operation."""

    OK = "ok"
    NOT_FOUND = "not_found"
    NOT_SUPPORTED = "not_supported"
    ERROR = "error"


class MemoryArtifactEnvelope(FrozenModel):
    """An envelope for any artefact produced by a memory extractor.

    A real implementation in Phase 3 will narrow ``data`` into specialised
    models (processes, sockets, TLS metadata). Until then, the framework
    only guarantees a stable envelope with explicit status reporting.
    """

    experiment_id: str = identifier_field("Identifier of the experiment.")
    artifact_kind: str = identifier_field(
        "Logical kind of the artefact, e.g. 'processes', 'sockets', 'tls'."
    )
    status: MemoryExtractionStatus = Field(
        default=MemoryExtractionStatus.OK,
        description="Outcome of the extraction operation.",
    )
    data: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "List of extracted artefacts as plain dicts. Schema depends on "
            "artifact_kind; specialised parsing belongs to Phase 3."
        ),
    )
    source_tool: str = Field(
        min_length=1,
        description="Tool that produced the envelope, e.g. 'volatility3'.",
    )
    notes: str = Field(default="", description="Free-form notes about the extraction.")
