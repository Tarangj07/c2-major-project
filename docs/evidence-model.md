# Evidence model

## Types

The framework's typed models live in `src/c2forensics/models/`:

| Model | Purpose | Phase introduced |
|---|---|---|
| `ExperimentMetadata` | Lifecycle state of an experiment, tool versions, raw hashes | 1 |
| `GroundTruth` | Recorded by the C2 simulator, consumed only by evaluation | 1 |
| `ToolVersions` | Captured at experiment creation time | 1 |
| `NetworkFlow` | A flow extracted from a PCAP | 2 |
| `ProcessArtifact` | A process observed in memory | 3 |
| `SocketArtifact` | A socket observed in memory, tied to a PID | 3 |
| `TLSArtifact` | A TLS-related artefact (version, SNI, possibly key material) | 3 |
| `MemoryArtifactEnvelope` | Generic envelope for memory extractor output | 3 |
| `ArtifactProvenance` | Source, tool, plugin, experiment, confidence | 1 |
| `Artifact` | Generic artefact with provenance | 1 |
| `CorrelationFactor` | One factor in a correlation | 4 |
| `CorrelationEvidence` | Coarse-grained public evidence flags | 4 |
| `CorrelationResult` | Outcome of correlating a flow with a process | 4 |
| `TimelineEvent` | A timestamped event in the experiment timeline | 6 |

## Provenance

Every artefact carries a `provenance` field with:

- `source`: one of `pcap`, `memory`, `ground_truth`, `manual`,
  `derived`;
- `source_tool`: e.g. `tshark`, `volatility3`, `c2forensics`;
- `source_plugin`: the specific sub-component, e.g.
  `vol --plugins=windows.netscan.NetScan` or `tshark -Y tcp.stream`;
- `experiment_id`: ties the artefact to its experiment;
- `confidence`: in `[0, 1]`. Source-level confidence in the value, not
  the strength of any correlation.

## Absence

The framework never represents absence as a missing record. Instead:

- memory extraction results that did not find a structure are returned
  with `status = NOT_FOUND` or `NOT_SUPPORTED`;
- TLS artefacts that were looked for but not found are returned with
  `absent = True`, plus a `notes` field explaining the search.

## UTC timestamps

All timestamps are timezone-aware UTC. The validators in every model
reject naive datetimes. Use `c2forensics.experiment.utcnow()` to obtain
a correctly tagged current time.

## Frozen models

All forensic models are `frozen=True`. A stage that needs to "modify"
an artefact must construct a new model. This prevents accidental
in-place mutation of artefacts that have already been written to disk
or passed to a downstream stage.

## Configuration snapshot

`ExperimentMetadata.config_snapshot` stores a JSON-serialisable copy
of the relevant lab configuration at experiment creation time. This
means an experiment can be re-analysed without referring to the
original `lab.yaml`, which protects reproducibility when the lab
configuration evolves.
