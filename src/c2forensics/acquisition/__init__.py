"""Acquisition stage: ingest raw evidence into the experiment directory.

PCAP acquisition is implemented in Phase 2. Memory-image
acquisition is implemented in Phase 3. Both functions follow the
same pattern: validate, refuse symlinks, refuse to overwrite, hash,
record.
"""

from __future__ import annotations

from c2forensics.acquisition.memory import (
    DEFAULT_IMAGE_NAME,
    MemoryAcquisitionError,
    acquire_memory_image,
    discover_volatility_targets,
    list_acquired_images,
)
from c2forensics.acquisition.pcap import (
    PCAP_FILENAME,
    PcapAcquisitionError,
    acquire_pcap,
)

__all__ = [
    "DEFAULT_IMAGE_NAME",
    "MemoryAcquisitionError",
    "PCAP_FILENAME",
    "PcapAcquisitionError",
    "acquire_memory_image",
    "acquire_pcap",
    "discover_volatility_targets",
    "list_acquired_images",
]
