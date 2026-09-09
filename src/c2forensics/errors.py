"""Custom exception types for the forensic framework.

A small, well-named hierarchy makes CLI error handling explicit and
prevents the framework from accidentally swallowing real errors.
"""

from __future__ import annotations


class C2ForensicsError(Exception):
    """Base class for all framework-level errors."""


class ConfigError(C2ForensicsError):
    """Raised when the lab configuration cannot be loaded or is invalid."""


class ExperimentNotFoundError(C2ForensicsError):
    """Raised when an experiment ID is referenced but does not exist on disk."""


class EvidenceError(C2ForensicsError):
    """Raised when raw evidence is missing, malformed, or fails integrity checks."""


class NotImplementedByPhaseError(C2ForensicsError):
    """Raised when a CLI subcommand is invoked before its phase is implemented."""


class ToolNotFoundError(C2ForensicsError):
    """Raised when an external tool binary is not on ``PATH``."""
