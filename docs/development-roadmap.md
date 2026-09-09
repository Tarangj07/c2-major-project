# Development roadmap

## Phasing

| Phase | Scope | Status |
|---|---|---|
| 1 | Repository, configuration, data models, experiment metadata, hashing, CLI skeleton, unit-test infra, docs | **Shipped** |
| 2 | PCAP extraction via tshark, flow extraction, TLS metadata, normalised network evidence | **Shipped** |
| 3 | Volatility 3 abstraction, process/socket extraction, normalised memory evidence | **Shipped** |
| 4 | Correlation engine: multi-factor scoring, explainable results | Not started |
| 5 | Reconstruction: process → socket → flow → endpoint, case JSON | Not started |
| 6 | Timeline: events from PCAP and memory, sortable output | Not started |
| 7 | Evaluation: ground-truth comparison, precision/recall/F1, recovery rate, performance | Not started |
| 8 | Persistence experiments | Not started |
| 9 | Controlled anti-forensics experiments | Not started |

## Phase 1 deliverables (this commit)

- `pyproject.toml`, `requirements.txt`, `.gitignore`, `LICENSE`
- `config/lab.yaml` with the lab environment, external tool locations,
  evidence-handling settings, and correlation defaults
- `src/c2forensics/`:
  - `__init__.py` exposing `__version__`
  - `paths.py` (filesystem layout)
  - `config.py` (YAML config loader)
  - `logging.py` (structured JSON logging)
  - `hashing.py` (SHA-256 hashing for raw evidence)
  - `experiment.py` (metadata I/O)
  - `errors.py` (custom exception hierarchy)
  - `models/` (Pydantic v2 models for every pipeline artefact)
  - `cli/main.py` (argparse-based CLI)
- `tests/`:
  - `conftest.py`
  - `tests/unit/test_models.py`
  - `tests/unit/test_paths.py`
  - `tests/unit/test_config.py`
  - `tests/unit/test_hashing.py`
  - `tests/unit/test_experiment.py`
  - `tests/unit/test_logging.py`
  - `tests/unit/test_cli.py`
- `docs/`:
  - `architecture.md`
  - `methodology.md`
  - `evidence-model.md`
  - `experiment-protocol.md`
  - `development-roadmap.md` (this file)

## Safety notes for later phases

The following are explicitly out of scope for the framework itself and
must not appear in the source tree:

- real malware or malware-adjacent code;
- credential theft, keylogging, or destructive behaviour;
- persistence intended for real systems;
- privilege escalation;
- stealth or evasion intended for real deployment;
- command execution against arbitrary hosts;
- payload delivery;
- exploitation;
- real-world C2 infrastructure;
- autonomous malicious behaviour.

Anti-forensic behaviour is permitted only as a *controlled laboratory
test condition* for measuring forensic degradation. Any such behaviour
must be:

- implemented in a way that is clearly labelled as anti-forensic;
- restricted to the laboratory VM;
- described in the dissertation and the methodology documentation
  before it is enabled.
