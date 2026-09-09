# Architecture

## Goals

The framework is built around a strict pipeline:

```
Experiment
  → Evidence
  → Acquisition
  → Extraction
  → Normalization
  → Correlation
  → Reconstruction
  → Timeline
  → Persistence analysis
  → Evaluation
```

Every stage has a typed input/output schema, defined in
`src/c2forensics/models/`. Downstream modules never consume raw tshark
output or raw Volatility output directly; everything is normalised into
the framework's own models first. This is the central architectural
guarantee that the dissertation requires, and it is the reason every
phase ships behind a typed boundary.

## Design decisions

### Pydantic v2 over dataclasses

Forensic artefacts are facts that downstream stages reason about. A
malformed timestamp, a missing field, or an extra unexpected key should
fail loudly at the boundary, not silently corrupt a correlation
calculation. Pydantic v2 gives us:

- strict, declared schemas;
- automatic JSON serialisation;
- validation that surfaces Pydantic `ValidationError` with the exact
  failing field;
- frozen models so that artefacts cannot be mutated in place after
  they have been written.

Plain `dataclasses` are too permissive: a typo on `provenance.soruce`
would not be caught at construction time, and downstream code that
mutated an artefact would corrupt other stages holding the same
reference.

### One config file, three sub-views

The lab YAML is loaded exactly once per CLI invocation and frozen.
Modules receive the sub-view they need (`LabConfig.lab`,
`LabConfig.tools`, `LabConfig.correlation`) so they cannot mutate shared
state. The full file is also embedded in `metadata.json` as a
configuration snapshot for reproducibility.

### No third-party CLI framework

The framework's CLI surface is small. `argparse` is sufficient and
keeps the dependency surface minimal. The same logic is what is tested
in `tests/unit/test_cli.py`.

### Volatility and tshark are external tools

`tshark` is invoked as a subprocess in Phase 2. Volatility 3 is invoked
as a subprocess in Phase 3. Neither is imported as a Python library
yet. This keeps the framework decoupled from tool versions, which is
important for reproducibility — `tool_versions` is captured in
`metadata.json` at experiment creation time.

### Pyshark is explicitly **not** a hard dependency

Pyshark ties the framework to a specific tshark version and to a
specific Python wrapper. Invoking `tshark` directly with structured
output (JSON / fields) is more portable and easier to test.

## Repository layout

```
encrypted-c2-forensics/
├── README.md
├── LICENSE
├── pyproject.toml
├── requirements.txt
│
├── config/
│   └── lab.yaml                    # single source of truth for runtime config
│
├── docs/
│   ├── architecture.md             # this file
│   ├── methodology.md              # research methodology & RQ mapping
│   ├── evidence-model.md           # types, provenance, ground truth
│   ├── experiment-protocol.md      # how an experiment is created & run
│   └── development-roadmap.md      # phased delivery plan
│
├── src/c2forensics/
│   ├── __init__.py
│   ├── paths.py                    # filesystem layout helpers
│   ├── config.py                   # YAML config loader (frozen view)
│   ├── logging.py                  # structured JSON logging
│   ├── hashing.py                  # SHA-256 evidence hashing
│   ├── experiment.py               # experiment metadata I/O
│   ├── errors.py                   # custom exception hierarchy
│   ├── models/                     # Pydantic v2 typed models
│   ├── acquisition/                # (Phase 2+) raw evidence capture
│   ├── extraction/                 # (Phase 2+) tool-specific extraction
│   ├── normalization/              # (Phase 2+) intermediate normalisation
│   ├── correlation/                # (Phase 4) correlation engine
│   ├── reconstruction/             # (Phase 5) C2 case reconstruction
│   ├── timeline/                   # (Phase 6) timeline engine
│   ├── persistence/                # (Phase 8) persistence experiments
│   ├── evaluation/                 # (Phase 7) metrics & evaluation
│   └── cli/main.py                 # CLI entry point
│
├── tools/                          # external tool wrappers (later phases)
│
├── experiments/                    # one directory per experiment
│
├── tests/
│   ├── conftest.py
│   ├── unit/                       # unit tests
│   ├── integration/                # integration tests (later phases)
│   └── fixtures/                   # small synthetic fixtures
│
└── scripts/                        # convenience driver scripts
```

## Pipeline boundaries

Each pipeline stage is a transformation between two typed schemas:

| Stage | Input schema | Output schema | Phase |
|---|---|---|---|
| Experiment init | CLI args, lab config | `ExperimentMetadata` (on disk) | 1 |
| Acquisition | on-disk raw artefacts | `raw_hashes` field in metadata | 2+ |
| PCAP extraction | `capture.pcap` | `NetworkEvidence` (flows + TCP/TLS observations) | 2 |
| Memory extraction | memory image | `MemoryExtractionResult` (processes + sockets + TLS absence + envelopes) | 3 |
| Normalization | `NetworkEvidence`, `MemoryExtractionResult` | `list[ProcessArtifact]`, `list[SocketArtifact]`, `list[TLSArtifact]` | 2/3 |
| Correlation | flows + processes + sockets + TLS | `list[CorrelationResult]` | 4 |
| Reconstruction | correlation + flows + processes | C2 case JSON | 5 |
| Timeline | everything with a timestamp | `list[TimelineEvent]` | 6 |
| Evaluation | reconstruction + ground truth | `metrics.json` | 7 |

## PCAP extraction (Phase 2)

The Phase 2 implementation is split into three layers to keep the
subprocess boundary narrow and the parser independently testable:

```
acquisition/pcap.py
  └─ only writer to raw/

extraction/pcap/tshark.py
  └─ only subprocess invocation; -T fields; -Y filter

extraction/pcap/parser.py
  └─ pure-functional parser; tshark rows -> typed models

extraction/pcap/extractor.py
  └─ orchestration: validate -> hash -> run -> parse -> persist
```

The parser never imports `subprocess` and can be unit-tested
against committed JSON fixtures. The tshark wrapper never imports
the parser. The extractor is the only piece that depends on both.
See `docs/pcap-extraction.md` for the field-by-field evidence
boundary.

## Memory extraction (Phase 3)

The Phase 3 implementation mirrors the Phase 2 split:

```
acquisition/memory.py
  └─ only writer to raw/memory/

extraction/memory/volatility.py
  └─ only subprocess invocation; -r json; -f <image>

extraction/memory/parser.py
  └─ pure-functional parser; vol JSON rows -> typed models

extraction/memory/extractor.py
  └─ orchestration: validate -> hash -> run -> parse -> persist
```

The same three-layer pattern means:

- The parser never imports `subprocess` and is fully
  unit-testable against committed JSON fixtures.
- The Volatility wrapper never imports the parser.
- The extractor is the only piece that depends on both.

See `docs/memory-extraction.md` for the plugin set, the
supported memory-image platform, and the field-by-field
evidence boundary.

## Provenance

Every artefact in the pipeline carries a `provenance` field describing
its source. The framework never silently infers an artefact; absence is
represented explicitly as a `not_found` / `not_supported` status
(memory artefacts) or as `absent=True` (TLS artefacts). See
`docs/evidence-model.md` for the full provenance model.

## What this commit does **not** include

- PCAP parsing
- Memory analysis
- Correlation logic
- Timeline generation
- Evaluation metrics beyond the type definitions
- Persistence or anti-forensic experiments

These are reserved for later phases per `docs/development-roadmap.md`.
