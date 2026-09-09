# Methodology

## Research objective

When a controlled test client communicates with a C2 server over
encrypted TLS/HTTPS, how much C2 activity can be reconstructed by
correlating volatile-memory artefacts with captured network traffic?

## Research questions and pipeline mapping

| RQ | Question | Pipeline stages that produce evidence |
|---|---|---|
| RQ1 | Attribution of encrypted connections to their originating processes | Acquisition → PCAP extraction → Memory extraction → Normalization → Correlation |
| RQ2 | Forensic artefacts recoverable from memory that are not in the PCAP | Memory extraction → Normalization → Reconstruction |
| RQ3 | Change in recoverability over time | Repeated acquisition → Memory extraction → Persistence analysis |
| RQ4 | Effect of controlled anti-forensic behaviours on attribution | Modified acquisition conditions → Correlation → Evaluation |

## Controlled laboratory boundary

The C2 environment is a benign laboratory simulator. The framework
**must not** be used to:

- interact with real-world C2 infrastructure;
- deploy any operational capability;
- deploy, analyse, or attribute real malware.

The full list of out-of-scope behaviours is in the project specification
(see `docs/development-roadmap.md` for the implementation safety notes).

## Distinguishing claims

Every claim in the dissertation, in evaluation output, and in this
documentation must be labelled with one of:

- **research assumption** — a hypothesis stated in advance, not yet
  observed;
- **implementation decision** — a design choice made to make the
  experiment tractable, recorded so it can be revisited;
- **experimental observation** — a result produced by a real
  experiment, with an experiment ID and metadata hash.

The framework enforces this distinction through the `confidence` field
on every artefact: confidence is *source-level* and reflects the
reliability of the extraction method, not the strength of any
correlation. Correlation confidence is computed by the correlation
engine in Phase 4.

## Reproducibility

Every experiment records:

- experiment ID;
- creation and update timestamps (UTC);
- tool versions (`python`, `tshark`, `volatility3`, framework, OS);
- configuration snapshot of `config/lab.yaml`;
- SHA-256 hashes of every raw artefact (`capture.pcap`, memory dump,
  ground-truth file).

Raw artefacts are treated as immutable. The framework refuses to
overwrite them.
