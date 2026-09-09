"""High-level PCAP extractor.

The extractor is the only piece of the Phase 2 pipeline that the CLI
ever invokes. It performs four steps in order:

1. Validate the experiment is initialised and has a PCAP under ``raw/``.
2. Compute (or re-verify) the SHA-256 of the PCAP.
3. Invoke tshark through :mod:`c2forensics.extraction.pcap.tshark`
   using the field set declared in :mod:`parser`.
4. Hand the rows to :func:`assemble_bundle` and persist the result
   to ``extracted/network-evidence.json`` and
   ``extracted/pcap-diagnostics.json``.

The extractor never modifies the PCAP. It refuses to run on an
uninitialised experiment. The output files are deterministic and
regenerable; re-running the extractor produces byte-identical files
for the same input PCAP and tshark version.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from c2forensics.config import LabConfig
from c2forensics.errors import C2ForensicsError
from c2forensics.experiment import utcnow
from c2forensics.hashing import hash_file
from c2forensics.logging import get_logger
from c2forensics.models.pcap import NetworkEvidence
from c2forensics.paths import ExperimentPaths

from c2forensics.extraction.pcap.parser import (
    PCAP_FIELDS,
    ParseDiagnostics,
    assemble_bundle,
)
from c2forensics.extraction.pcap.tshark import (
    TsharkError,
    TsharkInvocation,
    TsharkNotFoundError,
    run_fields,
)

_logger = get_logger("c2forensics.extraction.pcap.extractor")

PCAP_FILENAME = "capture.pcap"
EXTRACTED_NETWORK_FILE = "network-evidence.json"
EXTRACTED_DIAGNOSTICS_FILE = "pcap-diagnostics.json"


class PCAPExtractionError(C2ForensicsError):
    """Raised when the PCAP extractor cannot complete."""


def _verify_pcap_hash(paths: ExperimentPaths) -> str:
    """Return the SHA-256 of the PCAP, or raise if it is missing.

    We do not re-hash the experiment metadata here; the framework
    trusts the on-disk file and surfaces any drift as a warning. The
    digest is what gets written into the evidence bundle so that a
    downstream stage can detect tampering.
    """
    pcap = paths.raw / PCAP_FILENAME
    if not pcap.is_file():
        raise PCAPExtractionError(
            f"no pcap at {pcap}; run 'c2forensics pcap acquire {paths.root.name} <source>' first"
        )
    return hash_file(pcap)


def extract_pcap(
    paths: ExperimentPaths,
    config: LabConfig,
    *,
    extracted_at: datetime | None = None,
) -> NetworkEvidence:
    """Extract network evidence from the experiment's PCAP.

    Returns the produced :class:`NetworkEvidence`. Side effects:

    * writes ``<exp>/extracted/network-evidence.json``
    * writes ``<exp>/extracted/pcap-diagnostics.json``

    The ``extracted_at`` parameter is exposed for tests and for
    reproducible reruns; when omitted it is set to the current UTC
    time. Two consecutive invocations of the extractor against the
    same PCAP and same tshark version therefore produce *byte-
    identical* output files when the same ``extracted_at`` is passed.

    Raises :class:`PCAPExtractionError` on any failure (missing file,
    tshark unavailable, tshark non-zero exit, malformed output).
    """
    digest = _verify_pcap_hash(paths)
    pcap_path = paths.raw / PCAP_FILENAME
    inv = TsharkInvocation(
        binary=config.tools.tshark.binary,
        read_filter="ip and (tcp or udp)",
        display_fields=PCAP_FIELDS,
        timeout_seconds=config.tools.tshark.timeout_seconds,
        pcap_path=pcap_path,
    )
    try:
        result = run_fields(inv)
    except TsharkNotFoundError as exc:
        raise PCAPExtractionError(str(exc)) from exc
    except TsharkError as exc:
        raise PCAPExtractionError(str(exc)) from exc

    when = extracted_at if extracted_at is not None else utcnow()
    bundle, diags = assemble_bundle(
        experiment_id=paths.root.name,
        pcap_path=str(pcap_path),
        pcap_sha256=digest,
        extractor_version=result.version,
        extracted_at=when,
        rows=result.fields,
    )
    _persist_bundle(paths, bundle, diags)
    _logger.info(
        "pcap extracted",
        extra={
            "experiment_id": paths.root.name,
            "pcap_sha256": digest,
            "flows": len(bundle.flows),
            "tcp_events": len(bundle.tcp_lifecycle),
            "tls_observations": len(bundle.tls_observations),
        },
    )
    return bundle


def _persist_bundle(
    paths: ExperimentPaths, bundle: NetworkEvidence, diags: ParseDiagnostics
) -> None:
    """Write the bundle and diagnostics as deterministic JSON."""
    paths.extracted.mkdir(parents=True, exist_ok=True)
    network_path = paths.extracted / EXTRACTED_NETWORK_FILE
    diag_path = paths.extracted / EXTRACTED_DIAGNOSTICS_FILE

    network_payload = bundle.model_dump(mode="json")
    network_path.write_text(
        json.dumps(network_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    diag_path.write_text(
        json.dumps(asdict(diags), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _logger.info(
        "pcap outputs written",
        extra={"network": str(network_path), "diagnostics": str(diag_path)},
    )


def load_extracted_bundle(paths: ExperimentPaths) -> NetworkEvidence:
    """Load a previously-written network evidence bundle."""
    network_path = paths.extracted / EXTRACTED_NETWORK_FILE
    if not network_path.is_file():
        raise PCAPExtractionError(f"no network evidence at {network_path}")
    payload = json.loads(network_path.read_text(encoding="utf-8"))
    return NetworkEvidence.model_validate(payload)


def emit_legacy_flows(bundle: NetworkEvidence) -> list[dict[str, object]]:
    """Render Phase 1 ``NetworkFlow``-shaped dicts from a bundle.

    This helper exists so that downstream code (timeline, evaluation)
    that was written against the Phase 1 ``NetworkFlow`` shape can
    consume Phase 2 output without duplicating the data model. The
    dict shape is intentionally close to ``NetworkFlow``; the
    conversion is deterministic.
    """
    out: list[dict[str, object]] = []
    for f in bundle.flows:
        # ``tls_detected`` is derived from the presence of any TLS
        # observation tied to this flow. This is the only inference
        # the legacy renderer makes; everything else is copied.
        tls = [o for o in bundle.tls_observations if o.flow_id == f.flow_id]
        tls_version = next(
            (o.tls_version for o in tls if o.kind.value == "server_hello" and o.tls_version),
            None,
        ) or next(
            (o.tls_version for o in tls if o.tls_version),
            None,
        )
        sni = next(
            (o.sni for o in tls if o.kind.value == "client_hello" and o.sni),
            None,
        )
        out.append(
            {
                "experiment_id": f.experiment_id,
                "flow_id": f.flow_id,
                "src_ip": f.src_ip,
                "src_port": f.src_port,
                "dst_ip": f.dst_ip,
                "dst_port": f.dst_port,
                "protocol": f.protocol,
                "start_time": f.first_seen.isoformat(),
                "end_time": f.last_seen.isoformat(),
                "duration_seconds": f.duration_seconds,
                "packet_count": f.frame_count,
                "byte_count": f.byte_count,
                "tcp_stream": f.tcp_stream,
                "tls_detected": bool(tls),
                "tls_version": tls_version,
                "sni": sni,
                "pcap_path": bundle.pcap_path,
                "pcap_sha256": bundle.pcap_sha256,
                "extractor_version": bundle.extractor_version,
            }
        )
    return out
