"""Shared Pydantic configuration and primitives for all model modules."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FrozenModel(BaseModel):
    """Base model for immutable forensic artefacts.

    Forensic artefacts are facts-on-disk once they are written. Mutating them
    in-place after they have been emitted would corrupt downstream stages
    that hold references to the same object. We therefore freeze every model
    by default; if a later stage genuinely needs a mutable view, it should
    construct a new model rather than mutating an existing one.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class NonEmptyStr(str):
    """A non-empty string primitive used for identifier-like fields.

    Pydantic does not enforce non-emptiness on plain ``str`` fields, so we
    define a small primitive and validate it through ``Field(min_length=1)``
    in each model. This module exists to document that intent and to provide
    a single place to evolve the rule.
    """


def identifier_field(description: str) -> Field:
    """Return a ``Field`` configured as a required non-empty identifier."""
    return Field(min_length=1, description=description)
