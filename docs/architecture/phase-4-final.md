A. Evidence Contract (Actual Repository Contracts)

  - Phase 2 output (src/c2forensics/extraction/pcap/extractor.py):
    - NetworkEvidence persisted to <exp>/extracted/network-evidence.json.
    - Contains flows: list[FlowObservation] (see src/c2forensics/models/pcap.py).
    - FlowObservation fields: experiment_id, flow_id, src_ip, src_port, dst_ip, dst_port, protocol, tcp_stream, first_seen, last_seen, frame_count, byte_count, plus derived
      duration_seconds, frames_per_second, bytes_per_second.
    - Important: src_ip/src_port and dst_ip/dst_port are taken from the observed pure SYN when SYN evidence exists, thus preserving initiator/responder semantics; without SYN evidence the flow retains the deterministic canonical (lexicographic) endpoint ordering.
  - Phase 3 output (src/c2forensics/extraction/memory/extractor.py):
    - MemoryExtractionResult persisted to <exp>/extracted/memory-result.json.
    - Contains processes: list[ProcessArtifact], sockets: list[SocketArtifact], tls_artifacts: list[TLSArtifact], plus per‑artifact provenance lists.
    - Individual artefact files are also written: memory-processes.json, memory-sockets.json, memory-tls.json.
    - SocketArtifact fields: experiment_id, pid, local_ip, local_port, remote_ip (may be None), remote_port (may be None), protocol, state, timestamp (Volatility “Created” time).
    - ProcessArtifact fields: experiment_id, pid, process_name, executable_path, parent_pid, creation_time, termination_time.

  - Ground truth remains in <exp>/ground-truth.json and is never read by the correlation engine.
  - Experiment identification: all artefacts carry experiment_id; correlation is performed per‑experiment.

  B. Data Models (Unchanged + New)

  - Reuse existing frozen Pydantic models:
    - FlowObservation (models/pcap.py)
    - SocketArtifact (models/socket.py)
    - ProcessArtifact (models/process.py)
    - CorrelationResult, CorrelationFactor, CorrelationEvidence (models/correlation.py)

  - New model (src/c2forensics/models/correlation.py):
  class FlowOutcome(FrozenModel):
      """Per‑flow correlation decision with zero‑or‑more candidate processes."""
      experiment_id: str = identifier_field("Experiment identifier.")
      flow_id: str = identifier_field("Identifier of the FlowObservation being decided.")
      outcome: Literal["MATCHED", "MULTIPLE_CANDIDATES", "NO_MATCH", "INSUFFICIENT_EVIDENCE"] = Field(
          description="Flow‑level decision after evaluating all candidate sockets."
      )
      candidates: list[CorrelationResult] = Field(
          default_factory=list,
          description="Per‑process correlation results for this flow. Empty for NO_MATCH."
      )
      # Provenance: lightweight snapshots to enable traceability.
      flow_provenance: dict[str, Any] = Field(
          default_factory=dict,
          description="Snapshot of FlowObservation fields used for reproducibility."
      )
      socket_provenance: list[dict[str, Any]] = Field(
          default_factory=list,
          description="Snapshot of SocketArtifact fields considered as candidates."
      )
      process_provenance: list[dict[str, Any]] = Field(
          default_factory=list,
          description="Snapshot of ProcessArtifact fields for the candidate PIDs."
      )
  - Persistence: JSON array of FlowOutcome objects written atomically to <exp>/correlation/flow-outcomes.json (paths.correlation = experiment-root ``correlation/`` directory, not ``extracted/``).
  - Ordering: the persisted array is sorted by flow_id; within each flow, candidates are ordered by confidence descending with deterministic tie-breaks (lower pid, then socket endpoint tuple).

  C. Normalization (Use Actual Stored Representation)

  - FlowObservation is already in the form emitted by the PCAP extractor; no further transformation needed.
  - SocketArtifact → Canonical Endpoint (used only for candidate generation):
    - Only consider established sockets where remote_ip is not None and remote_port is not None.
    - Compute unordered endpoint pair:
  def socket_canonical_endpoint(sock: SocketArtifact) -> tuple[str, int, str, int, str] | None:
      if sock.remote_ip is None or sock.remote_port is None:
          return None  # listening/unbound – ignore for flow correlation
      a = (sock.local_ip, sock.local_port)
      b = (sock.remote_ip, sock.remote_port)
      if a <= b:
          return (sock.local_ip, sock.local_port, sock.remote_ip, sock.remote_port, sock.protocol.lower())
      else:
          return (sock.remote_ip, sock.remote_port, sock.local_ip, sock.local_port, sock.protocol.lower())
  - Protocol strings are lower‑cased (tcp/udp) as validated by the models.
  - IP literals are canonicalised via the stdlib ipaddress module before comparison (valid IPv4/IPv6 values are compared in compressed form); malformed values are retained opaquely so a malformed artefact cannot silently match a canonical one.
  - No modification of Phase 2 or Phase 3 models is required.

  D. Candidate Generation (IP‑Only Gate)

  1. Load all FlowObservation objects from network-evidence.json.
  2. Load all SocketArtifact objects from memory-sockets.json (or via MemoryExtractionResult).
  3. Load all ProcessArtifact objects from memory-processes.json and index by pid.
  4. For each flow f:
     - Skip any socket whose experiment_id differs from the flow's experiment_id.
     - Compute the unordered IP set {f.src_ip, f.dst_ip}.
     - For each socket s (remote_ip and remote_port both present, i.e. a valid canonical endpoint):
       - If {s.local_ip, s.remote_ip} != {f.src_ip, f.dst_ip} -> discard (IP gate).
       - No port or protocol check at this stage; those are scoring factors. A socket whose remote endpoint is unknown (None) is gate-rejected, not scored.

     - Remaining sockets are candidates for the flow.

  5. Link each candidate socket to its ProcessArtifact via pid; if missing, process_association is scored as an available negative (§H).
  6. Attribution is process-level: candidates are collapsed per PID, keeping the strongest candidate for each PID (deterministic tie-break by socket tuple). Every IP-compatible socket considered is still retained in socket_provenance.

  Double‐counting avoided: IP compatibility is the sole hard gate; port_match, protocol_match, timestamp_proximity, process_association are the only active scoring factors and are
  not guaranteed by the gate.

  E. Temporal Model (Socket Creation Time)

  - Use FlowObservation.first_seen (timestamp of the first pure SYN packet when SYN evidence exists; otherwise the first observed frame) as the network‐side time.
  - Use SocketArtifact.timestamp (Volatility “Created” time) as the memory‐side time.
  - If socket.timestamp is None, the timestamp evidence is *unavailable*: the factor is marked not matched, contributes 0, and is **excluded from the normalization denominator** (see §F). Absent evidence is never silently converted into negative evidence.
  - If socket.timestamp is present but the delta exceeds tolerance, the factor is an *available negative*: matched = False and its weight **remains in the denominator**, reducing the score.
  - Otherwise compute delta = abs(flow_timestamp - socket_timestamp).
  - Match if delta <= config.correlation.timestamp_tolerance_seconds.
  - Contribution = normalized weight if match else 0.0.
  - Note: a single socket timestamp does not imply the socket existed for the whole flow; only temporal proximity is evaluated.

  F. Evidence Factors and Scoring (Active Only)

  ┌─────────────────────┬─────────────────────────────────┬───────────────────┬────────────────────────────────────────────────────────────────────────────────────────────┬───────┐
  │       Factor        │             Source              │  Weight (config)  │                                            Role                                            │ Notes │
  ├─────────────────────┼─────────────────────────────────┼───────────────────┼────────────────────────────────────────────────────────────────────────────────────────────┼───────┤
  │ ip_match            │ IP/gate                         │ 0.0 (ignored)     │ Gate only – used to generate candidates; does not contribute to score.                     │       │
  ├─────────────────────┼─────────────────────────────────┼───────────────────┼────────────────────────────────────────────────────────────────────────────────────────────┼───────┤
  │ socket_match        │ Socket canonical equality       │ 0.0 (ignored)     │ Not an active factor in Phase 4 (reserved for future).                                     │       │
  ├─────────────────────┼─────────────────────────────────┼───────────────────┼────────────────────────────────────────────────────────────────────────────────────────────┼───────┤
  │ port_match          │ Port equality (either ordering) │ Configured (e.g., │ Active – true if (f.src_port == s.local_port and f.dst_port == s.remote_port) OR           │       │
  │                     │                                 │  0.30)            │ (f.src_port == s.remote_port and f.dst_port == s.local_port).                              │       │
  ├─────────────────────┼─────────────────────────────────┼───────────────────┼────────────────────────────────────────────────────────────────────────────────────────────┼───────┤
  │ protocol_match      │ Protocol equality               │ Configured (e.g., │ Active – true if f.protocol == s.protocol.                                                 │       │
  │                     │                                 │  0.10)            │                                                                                            │       │
  ├─────────────────────┼─────────────────────────────────┼───────────────────┼────────────────────────────────────────────────────────────────────────────────────────────┼───────┤
  │ timestamp_proximity │ Time delta ≤ tolerance          │ Configured (e.g., │ Active – as defined in §E.                                                                 │       │
  │                     │                                 │  0.20)            │                                                                                            │       │
  ├─────────────────────┼─────────────────────────────────┼───────────────────┼────────────────────────────────────────────────────────────────────────────────────────────┼───────┤
  │ process_association │ Presence of ProcessArtifact for │ Configured (e.g., │ Active – true if proc exists for the socket’s pid.                                         │       │
  │                     │  socket.pid                     │  0.10)            │                                                                                            │       │
  ├─────────────────────┼─────────────────────────────────┼───────────────────┼────────────────────────────────────────────────────────────────────────────────────────────┼───────┤
  │ tls_metadata_match  │ TLS metadata overlap (SNI,      │ 0.0 (ignored)     │ Inactive - the implementation hard-codes its contribution to 0.0 and does not snapshot TLS   │       │
  │                     │ version, cipher)                │                   │ evidence into the Phase 4 flow outcome.                                        │       │
  └─────────────────────┴─────────────────────────────────┴───────────────────┴────────────────────────────────────────────────────────────────────────────────────────────┴───────┘

  Score calculation (per flow–socket/process candidate) — available-factor normalization:
  1. Gather the four active factors with non-zero weight: port_match, protocol_match, timestamp_proximity, process_association.
  2. Determine which factors are *available* for this candidate:
     - port_match, protocol_match, process_association are always available (port/protocol are required model fields for any candidate that passed the IP gate; a missing ProcessArtifact is an *available negative* observation — the memory evidence positively lacks a linked process, so weight 0.10 stays in the denominator and contributes 0).
     - timestamp_proximity is unavailable only when SocketArtifact.timestamp is None.
  3. Normalize over the available, non-zero weights only:
     available_total = sum(weight for active factor if available and weight > 0)
     norm_w[factor] = weight[factor] / available_total
  4. For each available factor compute matched (bool) per definitions above.
  5. contribution = norm_w[factor] if matched else 0.0.
  6. confidence = sum(contributions); if no active factor is available, confidence = 0.
     Examples (lab.yaml weights .30/.10/.20/.10, available_total .70):
       all four match -> 1.0 (strong);
       socket timestamp missing, other three match -> 0.5/0.5 = 1.0 (strong, timestamp excluded from denominator);
       timestamp present but 94.5s away, other three match -> 0.5/0.7 = 0.714 (medium, timestamp in denominator as negative);
       ProcessArtifact missing, other three match -> 0.6/0.7 = 0.857 (strong);
       only protocol + process match -> 0.2/0.7 = 0.2857 (weak).
  7. Derive classification using thresholds from config:
     - strong if confidence >= strong_threshold
     - medium if confidence >= medium_threshold
     - weak if confidence >= weak_threshold
     - none otherwise.

  G. Outcome Semantics (Per Flow)

  Let C = list of candidates for a flow: the IP-gate-passing sockets collapsed per owning PID, keeping each PID's strongest candidate (every IP-compatible socket is still retained in socket_provenance).
  For each candidate compute (confidence, classification) as above.
  Let best = candidate with highest confidence (break ties by lower pid).
  Let S = candidates with confidence >= weak threshold.

  - NO_MATCH: |C| == 0 (no socket passed IP gate).
  - INSUFFICIENT_EVIDENCE: |C| ≥ 1 and best.confidence < weak threshold (S empty).
  - MATCHED: best.confidence >= weak threshold and either |S| < 2, or best is more than ambiguity_margin ahead of the next candidate in S.
  - MULTIPLE_CANDIDATES: |S| ≥ 2 and best.confidence - second.confidence < ambiguity_margin, where second is the next-highest candidate **within S** (below-weak candidates do not participate in the ambiguity comparison).

  ambiguity_margin is a config value (float in [0,1]) representing the maximum confidence difference that still constitutes ambiguity.
  Regardless of outcome, FlowOutcome.candidates retains **all** candidates (sorted deterministically: confidence descending, then pid, then socket tuple), and all IP-compatible sockets remain in socket_provenance.

  H. Missing Evidence

  - Missing fields are explicitly None (per Pydantic models) and treated as follows - never as a wildcard match and never silently converted into false evidence:
    - SocketArtifact.timestamp is None -> timestamp evidence is UNAVAILABLE: timestamp_proximity matched = False, contribution 0.0, and its weight is EXCLUDED from the normalization denominator (see §E/§F).
    - SocketArtifact.remote_ip is None or remote_port is None -> excluded from candidate generation (no canonical endpoint; gate rejection, not a scored non-match).
    - Missing ProcessArtifact for a socket's pid -> process_association is an AVAILABLE NEGATIVE observation: matched = False, contribution 0.0, and its weight REMAINS in the denominator (the memory positively lacks a linked process). The socket is still a candidate.
    - A timestamp that is present but outside tolerance is likewise an available negative: matched = False and its weight stays in the denominator.

  - No inference: absence is never treated as a wildcard match.
  - Diagnostics (optional) may log counts of missing fields per factor for transparency.

  I. Ambiguity Resolution

  - As defined in §G: ambiguity_margin prevents arbitrary winner selection when scores are close.
  - The FlowOutcome.candidates list contains all surviving per-PID CorrelationResults for the flow (strongest socket per PID, per section D step 6) regardless of the outcome label, enabling downstream phases to handle ambiguity (e.g., request more evidence, flag for analyst).
  - Deterministic tie‑breaking (lower pid) only applies when selecting the best candidate for outcome determination; the full list is preserved.

  J. Provenance and Evidence Integrity

  - FlowOutcome.provenance stores lightweight snapshots:
    - flow_provenance: snapshot of the FlowObservation fields used in the decision (experiment_id, flow_id, src_ip, src_port, dst_ip, dst_port, protocol, tcp_stream, first_seen, last_seen, frame_count, byte_count).
    - socket_provenance: for every IP-compatible socket considered (not only the winning candidate), snapshot of SocketArtifact fields (experiment_id, pid, local_ip, local_port, remote_ip, remote_port, protocol, state, timestamp).
    - process_provenance: for each candidate PID whose ProcessArtifact exists, snapshot of ProcessArtifact fields (experiment_id, pid, process_name, executable_path, parent_pid, creation_time, termination_time). A missing process yields no entry (its association was scored as an available negative).

  - Input artefact files (extracted/network-evidence.json, extracted/memory-*.json) are already hashed by Phases 2–3; correlation does not modify them.
  - Persistence is an idempotent atomic overwrite (temp file + os.replace, temp file cleaned up on failure); re-running correlation with identical inputs yields byte-identical output (deterministic sorting, tie-break by PID). Prior evidence files are never modified.

  K. CLI and Persistence (Actual Paths)

  - New CLI subcommand:
  c2forensics correlate --experiment-id EXP001 [--config /path/to/lab.yaml]
    Implemented in src/c2forensics/cli/main.py (add a correlate subcommand under the c2forensics group).
  - Configuration updates:
    - src/c2forensics/config.py: add ambiguity_margin: float = Field(ge=0.0, le=1.0) to CorrelationSection. Keep extra="forbid".
    - config/lab.yaml: add under correlation:
  ambiguity_margin: 0.05
  weights:
    ip_match: 0.0        # gate only
    port_match: 0.30
    protocol_match: 0.10
    timestamp_proximity: 0.20
    socket_match: 0.0    # reserved
    process_association: 0.10
    tls_metadata_match: 0.0  # reserved
  thresholds:
    strong: 0.80
    medium: 0.50
    weak: 0.20
    - Active weights must sum to >0; gating/reserved weights must be present but are zeroed in scoring.

  - Persistence path:
    - Use paths.correlation from src/c2forensics/paths.py (CORRELATION_DIR = "correlation").
    - Output file: paths.correlation / "flow-outcomes.json".

  - Workflow:
    a. Load config.
    b. Verify experiment directory exists.
    c. Load and validate the combined bundles: extracted/network-evidence.json (NetworkEvidence) and extracted/memory-result.json
       (MemoryExtractionResult). Cross-check every bundle- and artefact-level experiment_id against the experiment directory
       name, and require exactly one ImageRecord in the memory bundle. Raise on missing or invalid inputs.
    d. Perform correlation as described.
    e. Write flow-outcomes.json.
    f. Only on success: call experiment.update_status(paths, ExperimentStatus.CORRELATED).
    g. On any validation or correlation failure, exit non‑zero and do not update status.

  L. Test Strategy

  - Unit tests (tests/unit/test_correlation.py):
    - Test socket_canonical_endpoint (IPv4/IPv6, listening sockets).
    - Test IP‑gate (various match/mismatch).
    - Test factor matching logic (port, protocol, timestamp, process).
    - Test score normalization and classification.
    - Test outcome determination (NO_MATCH, INSUFFICIENT_EVIDENCE, MATCHED, MULTIPLE_CANDIDATES) with fixtures.
    - Test missing evidence handling (None timestamps, missing remote ports, missing process).
    - Test configuration loading and weight normalization.
    - Test FlowOutcome model validation and serialization.

  - Integration tests (tests/integration/test_correlation_integration.py):
    - End‐to‐end runs using existing committed synthetic fixtures (fixture/stub validation, not real tshark or Volatility):
      - tshark_rows_two_flows.json + memory fixtures -> one MATCHED flow (PID 4580, port 51000) whose first SYN is ~94.5s from the socket Created time: timestamp is an available negative, 0.5/0.7 ~= 0.714 -> medium; plus one NO_MATCH flow (benign HTTP to 192.168.56.30:80).
      - tshark_rows_encrypted_c2.json + same memory -> client port 50578 vs socket port 51000 and a 5.5s delta (> 5s tolerance): only protocol + process match, 0.2/0.7 ~= 0.286 >= weak 0.20, so the flow is a weak-evidence MATCHED (single candidate above weak), NOT INSUFFICIENT_EVIDENCE. The engine reports the weak support the evidence actually provides.
      - tshark_rows_positive_control.json + same memory -> all four active factors match -> confidence 1.0, strong, MATCHED.
      - positive control with the ProcessArtifact removed -> 0.6/0.7 ~= 0.857, strong, still a candidate (missing process is an available negative).

    - Verify persisted JSON matches the expected schema (every FlowObservation yields exactly one FlowOutcome, including NO_MATCH flows).
    - Verify experiment status transitions to CORRELATED only after successful persistence; failures leave status unchanged.
    - Negative controls: flow with no IP-compatible socket -> NO_MATCH; candidate whose only matching active factor scores below weak -> INSUFFICIENT_EVIDENCE (unit-level); two equally supported PIDs -> MULTIPLE_CANDIDATES with the ambiguity preserved.
    - Ground-truth isolation: an unparseable ground-truth.json is planted in the experiment directory and the run still succeeds; a source scan asserts the correlation package never references the ground-truth artefact.

  - Property‐based tests (optional, not implemented): determinism is instead asserted by repeated byte‐identical CLI runs (test_cli_correlate_is_deterministic).

  M. Experiment Status

  - Lifecycle (existing): INITIALIZED → EVIDENCE_ACQUIRED → EXTRACTED → CORRELATED → …
  - Phase 4 CLI only advances to CORRELATED when:
    - All input evidence files exist and are valid.
    - Correlation runs without raising validation errors.
    - flow-outcomes.json is successfully written.

  - On failure, status remains at the previous stage (e.g., EXTRACTED).
  - No invention of missing Phase 2/3 transitions.

  N. Limitations / Research Validity

  - No causation claim: correlation does not prove that the process caused the network flow.
  - Socket timestamp: a single memory socket observation does not guarantee the socket existed for the entire flow; only temporal proximity is evaluated.
  - Process artifact presence: a ProcessArtifact for a PID does not confirm the socket belonged to that process at the exact time; only linkage via PID.
  - TLS metadata: not used in scoring (tls_metadata_match is reserved at weight 0.0 and always contributes 0.0). Phase 4 flow-outcome provenance does not snapshot TLS evidence; cleartext TLS handshake observations remain available only in the Phase 2 NetworkEvidence bundle.
  - IPv6: IP literals are canonicalised with the stdlib ipaddress module before endpoint comparison (IPv4 and IPv6 accepted, compared in compressed form; malformed values stay opaque and cannot silently match canonical ones). Phase 2 fixtures currently exercise IPv4 plus one IPv6 socket-ordering unit case.
  - Multiple memory images: the Phase 3 extractor itself runs across every image found under raw/memory/ and aggregates the artefacts into a single bundle (it only raises MemoryExtractionError when zero images are present). Phase 4 correlation therefore enforces the one-image-per-run contract at input-load and correlate time: a bundle carrying zero or more than one ImageRecord raises CorrelationError("correlation requires exactly one memory image") and the experiment status is not advanced. This prevents artefacts from different images being silently mixed; there is no images[0] fallback. Future work may add per-artefact image-level provenance.
  - Ground truth isolation: ground truth is never read by correlation engine; used only in evaluation (Phase 8).

  O. Exact Implementation Files

  ┌───────────────────────────────────────────────────┬──────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                       Path                        │  Action  │                                                   Description                                                    │
  ├───────────────────────────────────────────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ src/c2forensics/models/correlation.py             │ Modify   │ Add FlowOutcome model; update imports.                                                                           │
  ├───────────────────────────────────────────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ src/c2forensics/config.py                         │ Modify   │ Add ambiguity_margin field to CorrelationSection.                                                                │
  ├───────────────────────────────────────────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ config/lab.yaml                                   │ Modify   │ Add ambiguity_margin under correlation:; set weights as described (ip_match, socket_match, tls_metadata_match =  │
  │                                                   │          │ 0.0).                                                                                                            │
  ├───────────────────────────────────────────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ src/c2forensics/cli/main.py                       │ Modify   │ Add new correlate subcommand under the c2forensics group.                                                        │
  ├───────────────────────────────────────────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ src/c2forensics/correlation/__init__.py           │ Create   │ New package: implement correlation engine (loading, gating, factor scoring, outcome decision, persistence).      │
  ├───────────────────────────────────────────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ tests/unit/test_correlation.py                    │ Create   │ Unit tests as described in §L.1.                                                                                 │
  ├───────────────────────────────────────────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ tests/integration/test_correlation_integration.py │ Create   │ Integration tests as described in §L.2.                                                                          │
  ├───────────────────────────────────────────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ src/c2forensics/paths.py                          │ No       │ Already defines CORRELATION_DIR = "correlation"; reuse.                                                          │
  │                                                   │ change   │                                                                                                                  │
  ├───────────────────────────────────────────────────┼──────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ src/c2forensics/experiment.py                     │ No       │ Reuse existing update_status and ExperimentStatus.CORRELATED.                                                    │
  │                                                   │ change   │                                                                                                                  │
  └───────────────────────────────────────────────────┴──────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  P. Phase 4 Scope Boundary (Final)

  Included (exactly as specified above):
  - Loading Phase 2 (network-evidence.json → FlowObservation list) and Phase 3 (memory-*.json → SocketArtifact/ProcessArtifact lists).
  - IP‑compatibility gate (unordered IP set equality).
  - Active scoring factors: port_match, protocol_match, timestamp_proximity, process_association (ip_match/socket_match/tls_metadata_match are gate-only/reserved and contribute 0.0).
  - Available-factor weight normalization and confidence calculation (section F: scores normalize over the active weights that are available for each candidate).
  - Classification via configurable thresholds.
  - Flow‑level outcome determination (NO_MATCH, INSUFFICIENT_EVIDENCE, MATCHED, MULTIPLE_CANDIDATES) with ambiguity_margin.
  - Persisting FlowOutcome JSON with provenance snapshots.
  - Advancing experiment status to CORRELATED only on successful correlation and output persistence.

  Excluded (future phases):
  - Command/payload reconstruction (Phase 5).
  - Timeline/persistence analysis (Phase 6).
  - Anti‑forensic testing (Phase 7).
  - Evaluation against ground truth (Phase 8).
  - TLS metadata scoring (weight reserved at 0.0).
  - Multiple‑image correlation (requires Phase 3 changes).
  - Optional fields like local_port being None (requires Phase 3 model change).
  - TLS‑from‑memory, C2 reconstruction, persistence, timeline analysis, ground‑truth‑assisted attribution, executable‑path inference.
