"""PCAP extraction subpackage.

Public surface:

* :func:`c2forensics.extraction.pcap.extractor.extract_pcap` — top-level
  extraction entry point.
* :func:`c2forensics.extraction.pcap.extractor.load_extracted_bundle` —
  load a previously-written bundle.
* :func:`c2forensics.extraction.pcap.extractor.emit_legacy_flows` —
  render Phase-1-shaped ``NetworkFlow`` dicts from a bundle.
* :func:`c2forensics.extraction.pcap.parser.parse_rows` — pure
  functional parser (unit-testable without tshark).
* :func:`c2forensics.extraction.pcap.tshark.run_fields` — safe
  subprocess wrapper around tshark.

The :class:`NetworkEvidence` model and related types are re-exported
from :mod:`c2forensics.models` for convenience.
"""

from __future__ import annotations

from c2forensics.extraction.pcap.extractor import (
    PCAPExtractionError,
    emit_legacy_flows,
    extract_pcap,
    load_extracted_bundle,
)
from c2forensics.extraction.pcap.parser import (
    PCAP_FIELDS,
    ParseDiagnostics,
    assemble_bundle,
    parse_rows,
)
from c2forensics.extraction.pcap.tshark import (
    TsharkError,
    TsharkInvocation,
    TsharkNotFoundError,
    TsharkResult,
    get_version,
    resolve_binary,
    run_fields,
)
from c2forensics.models.pcap import (
    FlowObservation,
    NetworkEvidence,
    TCPLifecycleEvent,
    TCPLifecycleFlag,
    TLSHandshakeKind,
    TLSObservation,
)

__all__ = [
    "FlowObservation",
    "NetworkEvidence",
    "PCAPExtractionError",
    "PCAP_FIELDS",
    "ParseDiagnostics",
    "TCPLifecycleEvent",
    "TCPLifecycleFlag",
    "TLSHandshakeKind",
    "TLSObservation",
    "TsharkError",
    "TsharkInvocation",
    "TsharkNotFoundError",
    "TsharkResult",
    "assemble_bundle",
    "emit_legacy_flows",
    "extract_pcap",
    "get_version",
    "load_extracted_bundle",
    "parse_rows",
    "resolve_binary",
    "run_fields",
]
