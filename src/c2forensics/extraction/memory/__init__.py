"""Memory extraction subpackage.

Public surface:

* :func:`c2forensics.extraction.memory.extractor.extract_memory` — top-level
  extraction entry point.
* :func:`c2forensics.extraction.memory.extractor.load_extracted_result` —
  load a previously-written ``memory-result.json`` bundle.
* :func:`c2forensics.extraction.memory.parser.parse_plugin_rows` — pure
  functional parser (unit-testable without Volatility).
* :func:`c2forensics.extraction.memory.volatility.run_plugin` — safe
  subprocess wrapper around Volatility 3.
* :class:`MemoryExtractionResult` — the top-level output bundle.
"""

from __future__ import annotations

from c2forensics.extraction.memory.extractor import (
    EXTRACTED_DIAGNOSTICS_FILE,
    EXTRACTED_ENVELOPES_FILE,
    EXTRACTED_PROCESSES_FILE,
    EXTRACTED_RESULT_FILE,
    EXTRACTED_SOCKETS_FILE,
    EXTRACTED_TLS_FILE,
    ImageRecord,
    MemoryExtractionError,
    MemoryExtractionResult,
    extract_memory,
    load_extracted_result,
)
from c2forensics.extraction.memory.parser import (
    MemoryParseResult,
    PluginDiagnostics,
    parse_netscan,
    parse_plugin_rows,
    parse_pslist,
    tls_not_recovered,
)
from c2forensics.extraction.memory.volatility import (
    SUPPORTED_PLUGINS,
    VolatilityError,
    VolatilityInvocation,
    VolatilityNotFoundError,
    VolatilityResult,
    get_version,
    resolve_binary,
    run_plugin,
)

__all__ = [
    "EXTRACTED_DIAGNOSTICS_FILE",
    "EXTRACTED_ENVELOPES_FILE",
    "EXTRACTED_PROCESSES_FILE",
    "EXTRACTED_RESULT_FILE",
    "EXTRACTED_SOCKETS_FILE",
    "EXTRACTED_TLS_FILE",
    "ImageRecord",
    "MemoryExtractionError",
    "MemoryExtractionResult",
    "MemoryParseResult",
    "PluginDiagnostics",
    "SUPPORTED_PLUGINS",
    "VolatilityError",
    "VolatilityInvocation",
    "VolatilityNotFoundError",
    "VolatilityResult",
    "extract_memory",
    "get_version",
    "load_extracted_result",
    "parse_netscan",
    "parse_plugin_rows",
    "parse_pslist",
    "resolve_binary",
    "run_plugin",
    "tls_not_recovered",
]
