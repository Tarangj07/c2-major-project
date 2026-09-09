"""Encrypted C2 Forensic Reconstruction Framework.

A research-grade, modular forensic analysis pipeline for controlled laboratory
experiments involving encrypted C2 communication. The framework correlates
volatile-memory artefacts with captured network traffic to attribute encrypted
flows to their originating processes.

The package is organised as a strict pipeline:

    Experiment -> Evidence -> Acquisition -> Extraction -> Normalization
    -> Correlation -> Reconstruction -> Timeline -> Persistence -> Evaluation

Every stage has a well-defined typed schema. Downstream modules never consume
raw tshark text or raw Volatility output directly; everything is normalised
into our own Pydantic models first.

This is a defensive digital-forensics research framework. It is not designed
for, and must not be used for, offensive operations.
"""

from __future__ import annotations

__all__ = [
    "__version__",
]

__version__ = "0.1.0"
