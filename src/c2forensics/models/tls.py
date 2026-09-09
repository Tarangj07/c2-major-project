"""TLS artefact model.

TLS is the encryption layer under investigation. The framework never
assumes that key material will be recoverable. The absence of an artefact
is represented explicitly as ``TLSArtifact(absent=True, ...)`` rather than
as a missing record, so that downstream stages can reason about absence.
"""

from __future__ import annotations

from pydantic import Field

from c2forensics.models.common import FrozenModel, identifier_field


class TLSArtifact(FrozenModel):
    """A TLS-related artefact observed for a given process.

    ``absent`` is true when this artefact exists to record that the
    framework looked for TLS metadata and did not find it. The
    ``source`` and ``confidence`` fields describe how this conclusion
    was reached.
    """

    experiment_id: str = identifier_field("Identifier of the experiment.")
    pid: int | None = Field(
        default=None,
        ge=0,
        description="Owning process PID, when known.",
    )
    tls_version: str | None = Field(
        default=None,
        description="Negotiated TLS version, e.g. 'TLS 1.3'.",
    )
    cipher_suite: str | None = Field(
        default=None,
        description="Negotiated cipher suite, when recoverable.",
    )
    sni: str | None = Field(
        default=None,
        description="Server Name Indication value, when recoverable.",
    )
    session_metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Arbitrary session-related key/value pairs.",
    )
    key_material_recovered: bool = Field(
        default=False,
        description="True iff a session key, master secret, or pre-master secret was recovered.",
    )
    absent: bool = Field(
        default=False,
        description="True when the framework looked for TLS metadata and did not find it.",
    )
    source: str = Field(
        min_length=1,
        description=(
            "Originating source of this artefact, e.g. 'pcap', 'memory', "
            "'ground_truth', or 'derived'."
        ),
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Source-level confidence in [0, 1].",
    )
    notes: str = Field(
        default="",
        description="Free-form notes explaining recovery or absence.",
    )
