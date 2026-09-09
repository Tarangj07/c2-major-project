"""Typed data models for the forensic pipeline.

All models are Pydantic v2 BaseModel subclasses. They are the single source of
truth for the shape of artefacts flowing through the pipeline. Downstream
modules must import these models rather than constructing ad-hoc dicts.
"""

from __future__ import annotations

from c2forensics.models.artifact import Artifact, ArtifactProvenance, ArtifactSource
from c2forensics.models.correlation import (
    CorrelationEvidence,
    CorrelationFactor,
    CorrelationResult,
    FactorName,
)
from c2forensics.models.experiment import (
    ExperimentMetadata,
    ExperimentStatus,
    GroundTruth,
    ToolVersions,
)
from c2forensics.models.memory import MemoryArtifactEnvelope
from c2forensics.models.network import NetworkFlow
from c2forensics.models.pcap import (
    FlowObservation,
    NetworkEvidence,
    TCPLifecycleEvent,
    TCPLifecycleFlag,
    TLSHandshakeKind,
    TLSObservation,
)
from c2forensics.models.process import ProcessArtifact
from c2forensics.models.socket import SocketArtifact
from c2forensics.models.timeline import (
    TimelineEvent,
    TimelineEventKind,
)
from c2forensics.models.tls import TLSArtifact

__all__ = [
    "Artifact",
    "ArtifactProvenance",
    "ArtifactSource",
    "CorrelationEvidence",
    "CorrelationFactor",
    "CorrelationResult",
    "ExperimentMetadata",
    "ExperimentStatus",
    "FactorName",
    "FlowObservation",
    "GroundTruth",
    "MemoryArtifactEnvelope",
    "NetworkEvidence",
    "NetworkFlow",
    "ProcessArtifact",
    "SocketArtifact",
    "TCPLifecycleEvent",
    "TCPLifecycleFlag",
    "TLSArtifact",
    "TLSHandshakeKind",
    "TLSObservation",
    "TimelineEvent",
    "TimelineEventKind",
    "ToolVersions",
]
