"""High-level memory extractor.

The extractor is the only piece of the Phase 3 pipeline that the
CLI ever invokes. It performs three steps in order:

1. Validate the experiment is initialised and has at least one
   memory image under ``raw/memory/``.
2. For every image, run the supported Volatility 3 plugins
   (:func:`c2forensics.extraction.memory.volatility.run_plugin`).
3. Hand each plugin's rows to
   :func:`c2forensics.extraction.memory.parser.parse_plugin_rows`
   and persist the result.

The extractor never modifies a memory image. The on-disk image file
is hashed before any plugin runs and the digest is recorded in the
bundle-level :class:`ImageRecord` provenance (per-artefact records do
not carry the image hash themselves). Phase 4 correlation enforces a
single-image bundle, so bundle-level image provenance is sufficient
for a downstream stage to detect tampering.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from c2forensics.config import LabConfig
from c2forensics.errors import C2ForensicsError
from c2forensics.experiment import utcnow
from c2forensics.hashing import hash_file
from c2forensics.logging import get_logger
from c2forensics.models.artifact import ArtifactProvenance
from c2forensics.models.memory import (
    MemoryArtifactEnvelope,
    MemoryExtractionStatus,
)
from c2forensics.models.process import ProcessArtifact
from c2forensics.models.socket import SocketArtifact
from c2forensics.models.tls import TLSArtifact
from c2forensics.paths import ExperimentPaths

from c2forensics.extraction.memory.parser import (
    MemoryParseResult,
    parse_plugin_rows,
    tls_not_recovered,
)
from c2forensics.extraction.memory.volatility import (
    SUPPORTED_PLUGINS,
    VolatilityError,
    VolatilityInvocation,
    VolatilityNotFoundError,
    run_plugin,
)

_logger = get_logger("c2forensics.extraction.memory.extractor")

EXTRACTED_PROCESSES_FILE = "memory-processes.json"
EXTRACTED_SOCKETS_FILE = "memory-sockets.json"
EXTRACTED_TLS_FILE = "memory-tls.json"
EXTRACTED_ENVELOPES_FILE = "memory-envelopes.json"
EXTRACTED_DIAGNOSTICS_FILE = "memory-diagnostics.json"
EXTRACTED_RESULT_FILE = "memory-result.json"


class MemoryExtractionError(C2ForensicsError):
    """Raised when the memory extractor cannot complete."""


class MemoryExtractionResult(BaseModel):
    """The deterministic, fully-typed output of the memory extractor.

    This is the top-level bundle a Phase 4 correlator consumes.
    It records:

    * the image(s) used (path, SHA-256, file size, modification
      time) so a downstream stage can detect drift;
    * the Volatility version string captured at run time;
    * the typed artefact lists (processes, sockets, TLS) with their
      matching provenance records;
    * a per-plugin status summary;
    * the raw envelopes (per-plugin) so an operator can re-derive
      a different view without re-running Volatility.

    Provenance is preserved at the artefact level: every
    ``ProcessArtifact`` and ``SocketArtifact`` has a matching
    ``ArtifactProvenance`` in the same index position. The
    framework never assigns a process attribution; every record
    is OBSERVED in the memory image.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    experiment_id: str = Field(min_length=1)
    images: list[ImageRecord] = Field(default_factory=list)
    extractor_name: str = Field(default="volatility3", min_length=1)
    extractor_version: str = Field(default="unknown", min_length=1)
    extracted_at: datetime = Field(description="UTC timestamp of the extraction run.")
    platform: str = Field(
        default="windows",
        description="Memory-image platform assumed by the plugin set.",
    )
    processes: list[ProcessArtifact] = Field(default_factory=list)
    sockets: list[SocketArtifact] = Field(default_factory=list)
    tls_artifacts: list[TLSArtifact] = Field(default_factory=list)
    process_provenances: list[ArtifactProvenance] = Field(default_factory=list)
    socket_provenances: list[ArtifactProvenance] = Field(default_factory=list)
    tls_provenances: list[ArtifactProvenance] = Field(default_factory=list)
    envelopes: list[MemoryArtifactEnvelope] = Field(default_factory=list)
    plugin_status: dict[str, str] = Field(
        default_factory=dict,
        description="Per-plugin status: 'ok', 'not_found', 'not_supported', or 'error'.",
    )

    @classmethod
    def utc_field_default(cls) -> datetime:
        return utcnow()


class ImageRecord(BaseModel):
    """Provenance record for a single memory image."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, description="Absolute or repo-relative path.")
    sha256: str = Field(min_length=64, max_length=64, description="Hex SHA-256.")
    size_bytes: int = Field(ge=0, description="File size at extraction time.")
    mtime_utc: datetime = Field(
        description="File modification time at extraction time (UTC).",
    )


# ---------------------------------------------------------------------------
# Image validation
# ---------------------------------------------------------------------------


def _discover_images(paths: ExperimentPaths) -> list[Path]:
    """Return the on-disk memory images for the experiment.

    The discovery is deliberately simple: every regular file under
    ``raw/memory/`` is treated as a memory image. The framework
    does not inspect file contents.
    """
    from c2forensics.acquisition.memory import list_acquired_images

    return list_acquired_images(paths)


def _verify_images(paths: ExperimentPaths) -> list[ImageRecord]:
    """Build the list of :class:`ImageRecord` for the experiment.

    Each record carries the path, SHA-256, size, and modification
    time of the image. The SHA-256 is recomputed at extraction
    time so a downstream stage can detect any drift between
    acquisition-time and extraction-time states.
    """
    records: list[ImageRecord] = []
    for p in _discover_images(paths):
        digest = hash_file(p)
        st = p.stat()
        records.append(
            ImageRecord(
                path=str(p),
                sha256=digest,
                size_bytes=st.st_size,
                mtime_utc=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
            )
        )
    return records


# ---------------------------------------------------------------------------
# Plugin execution
# ---------------------------------------------------------------------------


def _run_for_image(
    image: Path,
    *,
    binary: str,
    timeout_seconds: int,
    image_sha256: str,
    experiment_id: str,
) -> MemoryParseResult:
    """Run every supported plugin against a single image and aggregate.

    The function never raises on per-plugin failure; it records
    the failure in ``MemoryParseResult.plugin_status`` and
    continues. Volatility-level failures (binary missing, image
    unreadable) are surfaced by raising
    :class:`MemoryExtractionError`.
    """
    aggregated = MemoryParseResult()
    for plugin in SUPPORTED_PLUGINS:
        inv = VolatilityInvocation(
            binary=binary,
            image_path=image,
            plugin=plugin,
            timeout_seconds=timeout_seconds,
        )
        try:
            result = run_plugin(inv)
        except VolatilityNotFoundError as exc:
            raise MemoryExtractionError(str(exc)) from exc
        except VolatilityError as exc:
            _logger.warning(
                "volatility plugin failed",
                extra={"plugin": plugin, "image": str(image), "error": str(exc)},
            )
            # Still record the empty envelope so the operator can
            # see which plugins failed.
            aggregated.plugin_status[plugin] = (
                MemoryExtractionStatus.ERROR.value
            )
            aggregated.envelopes.append(
                MemoryArtifactEnvelope(
                    experiment_id=experiment_id,
                    artifact_kind=plugin.split(".")[-1].lower(),
                    status=MemoryExtractionStatus.ERROR,
                    data=[],
                    source_tool="volatility3",
                    notes=str(exc),
                )
            )
            continue
        parsed = parse_plugin_rows(
            result.plugin,
            result.rows,
            experiment_id=experiment_id,
            image_sha256=image_sha256,
            image_path=str(image),
            extractor_version=result.version,
        )
        aggregated.processes.extend(parsed.processes)
        aggregated.sockets.extend(parsed.sockets)
        aggregated.process_provenances.extend(parsed.process_provenances)
        aggregated.socket_provenances.extend(parsed.socket_provenances)
        aggregated.envelopes.extend(parsed.envelopes)
        for plugin_name, diags in parsed.per_plugin_diagnostics.items():
            aggregated.per_plugin_diagnostics[plugin_name] = diags
        # plugin_status is aggregated below as a flat dict.
    return aggregated


# ---------------------------------------------------------------------------
# Top-level extraction
# ---------------------------------------------------------------------------


def extract_memory(
    paths: ExperimentPaths,
    config: LabConfig,
    *,
    extracted_at: datetime | None = None,
) -> MemoryExtractionResult:
    """Extract memory artefacts from every image in the experiment.

    Returns the produced :class:`MemoryExtractionResult`. Side
    effects:

    * writes ``<exp>/extracted/memory-processes.json``
    * writes ``<exp>/extracted/memory-sockets.json``
    * writes ``<exp>/extracted/memory-tls.json``
    * writes ``<exp>/extracted/memory-envelopes.json``
    * writes ``<exp>/extracted/memory-diagnostics.json``
    * writes ``<exp>/extracted/memory-result.json``

    Raises :class:`MemoryExtractionError` if no memory image is
    present, the Volatility binary cannot be located, or a
    subprocess-level failure occurs.
    """
    image_records = _verify_images(paths)
    if not image_records:
        raise MemoryExtractionError(
            f"no memory image under {paths.memory}; "
            f"run 'c2forensics memory acquire {paths.root.name} <image>' first"
        )

    when = extracted_at if extracted_at is not None else utcnow()
    experiment_id = paths.root.name

    processes: list[ProcessArtifact] = []
    sockets: list[SocketArtifact] = []
    process_provenances: list[ArtifactProvenance] = []
    socket_provenances: list[ArtifactProvenance] = []
    envelopes: list[MemoryArtifactEnvelope] = []
    per_plugin_diags: dict[str, object] = {}
    plugin_status: dict[str, str] = {}
    last_version = "unknown"

    for rec in image_records:
        image = Path(rec.path)
        aggregated = _run_for_image(
            image,
            binary=config.tools.volatility3.binary,
            timeout_seconds=config.tools.volatility3.timeout_seconds,
            image_sha256=rec.sha256,
            experiment_id=experiment_id,
        )
        # Backfill experiment_id in the envelopes.
        for env in aggregated.envelopes:
            if not env.experiment_id:
                env = env.model_copy(update={"experiment_id": experiment_id})
            envelopes.append(env)
        processes.extend(aggregated.processes)
        sockets.extend(aggregated.sockets)
        process_provenances.extend(aggregated.process_provenances)
        socket_provenances.extend(aggregated.socket_provenances)
        for plugin_name, diags in aggregated.per_plugin_diagnostics.items():
            per_plugin_diags[plugin_name] = diags
            plugin_status[plugin_name] = (
                MemoryExtractionStatus.OK.value
                if diags.rows_parsed > 0
                else MemoryExtractionStatus.NOT_FOUND.value
            )
        # Error path entries from ``_run_for_image`` propagate
        # directly into ``aggregated.plugin_status``; copy them.
        for plugin_name, status in aggregated.plugin_status.items():
            if status == MemoryExtractionStatus.ERROR.value:
                plugin_status[plugin_name] = status
        # Use the version recorded on the parse result. Falls back
        # to the previous value if the version probe returned
        # "unknown".
        if aggregated.extractor_version and aggregated.extractor_version != "unknown":
            last_version = aggregated.extractor_version

    # TLS: explicit absence, because Phase 3 does not implement a
    # TLS-from-memory plugin. The TLS field of the result is
    # populated with a single ``absent=True`` record so Phase 4
    # can see the framework's position.
    tls_artifacts, tls_provs = tls_not_recovered(
        experiment_id=experiment_id, extractor_version=last_version
    )

    result = MemoryExtractionResult(
        experiment_id=experiment_id,
        images=image_records,
        extractor_version=last_version,
        extracted_at=when,
        platform="windows",
        processes=processes,
        sockets=sockets,
        tls_artifacts=tls_artifacts,
        process_provenances=process_provenances,
        socket_provenances=socket_provenances,
        tls_provenances=tls_provs,
        envelopes=envelopes,
        plugin_status=plugin_status,
    )
    _persist(paths, result, per_plugin_diags)
    _logger.info(
        "memory extracted",
        extra={
            "experiment_id": experiment_id,
            "images": [r.path for r in image_records],
            "processes": len(processes),
            "sockets": len(sockets),
            "tls_artifacts": len(tls_artifacts),
            "plugin_status": plugin_status,
        },
    )
    return result


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _persist(
    paths: ExperimentPaths,
    result: MemoryExtractionResult,
    per_plugin_diags: dict[str, object],
) -> None:
    """Write the bundle and per-plugin diagnostics as deterministic JSON."""
    paths.extracted.mkdir(parents=True, exist_ok=True)

    def _dump(model: BaseModel, filename: str) -> None:
        (paths.extracted / filename).write_text(
            json.dumps(model.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _dump_list(items: Iterable[BaseModel], filename: str) -> None:
        payload = [m.model_dump(mode="json") for m in items]
        (paths.extracted / filename).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    _dump_list(result.processes, EXTRACTED_PROCESSES_FILE)
    _dump_list(result.sockets, EXTRACTED_SOCKETS_FILE)
    _dump_list(result.tls_artifacts, EXTRACTED_TLS_FILE)
    _dump_list(result.envelopes, EXTRACTED_ENVELOPES_FILE)
    _dump(result, EXTRACTED_RESULT_FILE)

    # Diagnostics is a free-form mapping per plugin.
    diag_payload: dict[str, object] = {
        plugin_name: asdict(d) for plugin_name, d in per_plugin_diags.items()
    }
    (paths.extracted / EXTRACTED_DIAGNOSTICS_FILE).write_text(
        json.dumps(diag_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def load_extracted_result(paths: ExperimentPaths) -> MemoryExtractionResult:
    """Load a previously-written ``memory-result.json`` bundle."""
    p = paths.extracted / EXTRACTED_RESULT_FILE
    if not p.is_file():
        raise MemoryExtractionError(f"no memory result at {p}")
    payload = json.loads(p.read_text(encoding="utf-8"))
    return MemoryExtractionResult.model_validate(payload)
