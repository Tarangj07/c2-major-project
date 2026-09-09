# PCAP extraction (Phase 2)

## Purpose

The PCAP extractor consumes a captured PCAP from a controlled
laboratory C2 experiment and produces a deterministic, fully-typed
bundle of network evidence.

The extractor deliberately does **not**:

- decrypt TLS application data;
- attempt to recover TLS session keys;
- attribute flows to processes (that is Phase 4's job);
- infer content, intent, or meaning of the encrypted payload.

What the extractor *does* produce is everything the dissertation's
RQ1 (Attribution) needs to ask "this encrypted flow was observed on
the wire" and nothing more.

## Evidence boundary

Every emitted field is labelled in its docstring as one of:

- **OBSERVED** — a fact that was directly read from a captured frame
  (SYN flag, ClientHello SNI, source port, frame number, …);
- **DERIVED** — a value computed deterministically from observed
  fields (flow duration = last_seen − first_seen, frame rate,
  byte rate, …);
- **INFERRED** — a value that required judgement beyond observation
  (this flow belongs to process X). The Phase 2 extractor produces
  **zero inferred fields**. Inference is the responsibility of
  Phase 4 (correlation).

This matters because the central research question is precisely
what encrypted network evidence can and cannot reveal. The Phase 2
extractor establishes the *can* side of that question; the rest of
the pipeline establishes the *cannot* side by adding memory-derived
evidence that the network alone could not supply.

## Stages

```
   capture.pcap
       │
       │  (1) acquisition
       ▼
   raw/capture.pcap  ── SHA-256 ──► metadata.raw_hashes
       │
       │  (2) tshark extraction
       ▼
   extracted/network-evidence.json
   extracted/pcap-diagnostics.json
```

1. **Acquisition** — `c2forensics pcap acquire EXP001 /path/to/capture.pcap`.
   Copies the PCAP into the experiment's `raw/` directory, refuses
   symlinks and empty files, refuses to overwrite an existing
   acquisition, hashes the file, and stores the digest in
   `metadata.json`. The source file is never modified.

2. **Extraction** — `c2forensics pcap extract EXP001`. Re-hashes the
   PCAP (for tamper detection), invokes tshark through a safe
   subprocess wrapper, parses the rows, and writes two deterministic
   JSON files under `extracted/`.

The two steps are independent: re-running extraction does not
require re-acquiring. A new acquisition requires a new experiment
directory.

## tshark field set

The extractor requests the following fields, in this order:

```
frame.number
frame.time_epoch
frame.len
ip.src
ip.dst
tcp.srcport
tcp.dstport
udp.srcport
udp.dstport
tcp.stream
tcp.flags
tls.handshake.type
tls.handshake.version
tls.handshake.ciphersuite
tls.handshake.extensions_server_name
x509sat.uTF8String
x509ce.dNSName
x509af.issuer
```

`tshark -T fields -E separator=/t -E occurrence=f` is used, so each
line of stdout is one packet. The wrapper never uses
`shell=True`; the binary path is resolved, the PCAP path is passed
as a single argv element, and stdout is parsed in pure Python.

## Output schema

`extracted/network-evidence.json` is a `NetworkEvidence` bundle:

```json
{
  "experiment_id": "EXP001",
  "pcap_path": "/abs/path/to/c2MinorProject/experiments/EXP001/raw/capture.pcap",
  "pcap_sha256": "<64-hex>",
  "extractor_name": "tshark",
  "extractor_version": "TShark 4.2.0 (v4.2.0-1)",
  "extracted_at": "2026-01-01T00:00:00+00:00",
  "flows": [ { FlowObservation } ],
  "tcp_lifecycle": [ { TCPLifecycleEvent } ],
  "tls_observations": [ { TLSObservation } ]
}
```

`extracted/pcap-diagnostics.json` is a `ParseDiagnostics` record:

```json
{
  "rows_seen": 13,
  "rows_skipped_no_timestamp": 0,
  "rows_skipped_no_endpoint": 0,
  "tcp_lifecycle_events": 5,
  "tls_observations": 4,
  "tls_handshake_unknown_type": [],
  "malformed_flags": []
}
```

Both files are deterministic: same PCAP and same tshark version
produce byte-identical output. The list order is stable
(`flows` are sorted by 5-tuple, `tcp_lifecycle` and
`tls_observations` are in PCAP frame order).

## Field provenance

| Field | Provenance | Notes |
|---|---|---|
| `flow.src_ip`, `flow.src_port` | OBSERVED | From the captured frame; ``initiator`` (c2s side) is set by the first observed SYN. |
| `flow.dst_ip`, `flow.dst_port` | OBSERVED | Symmetric to the above. |
| `flow.protocol` | OBSERVED | TCP if either port is set in the TCP header; UDP if in the UDP header. |
| `flow.first_seen` | OBSERVED | UTC timestamp of the first frame in the flow. |
| `flow.last_seen` | OBSERVED | UTC timestamp of the last frame in the flow. |
| `flow.frame_count` | OBSERVED | Number of frames in the flow. |
| `flow.byte_count` | OBSERVED | Sum of `frame.len` over the flow. |
| `flow.duration_seconds` | DERIVED | `last_seen - first_seen`. |
| `flow.frames_per_second` | DERIVED | `frame_count / duration_seconds` if `duration > 0`, else `0.0`. |
| `flow.bytes_per_second` | DERIVED | `byte_count / duration_seconds` if `duration > 0`, else `0.0`. |
| `tcp_lifecycle.*` | OBSERVED | SYN / SYN+ACK / ACK / FIN / RST observed in the TCP header. |
| `tls_observations.*` | OBSERVED | The four handshake messages (ClientHello, ServerHello, Certificate, Finished) seen in the cleartext TLS record layer. |
| `tls.cipher_suite` (parsed) | OBSERVED | IANA name where known; 4-hex-digit otherwise. The extractor never guesses. |
| `tls.tls_version` (in `tls_observations`) | OBSERVED | The version field in the handshake message. For TLS 1.3, the wire version is 0x0303 (TLS 1.2) on the legacy field; the *negotiated* version is in the `supported_versions` extension, which the Phase 2 parser does not yet decode. The `NetworkEvidence` records what the wire actually says. |
| `bundle.pcap_sha256` | OBSERVED | SHA-256 of the input PCAP at extraction time. |
| `bundle.extractor_version` | OBSERVED | First line of `tshark --version`. |

There is no inferred field in the Phase 2 output. Process
attribution, "is this C2 traffic", and "what is the application"
are explicitly deferred to later phases.

## What the extractor does not record

- TLS application-data contents. They are encrypted in the PCAP and
  the framework never attempts to decrypt them.
- TLS session keys, master secrets, or pre-master secrets.
- Any process metadata (PID, process name, executable path). Those
  are memory-side facts and only ever appear in the Phase 3
  artefacts.
- Any flow classification (e.g. "this is HTTPS", "this is C2").
  Classification belongs to the analysis layer, not to the
  extraction layer.
- Inference about the server side of a connection beyond what the
  ServerHello observed. The certificate subject / issuer fields are
  recorded as observations, not as identity claims.

## Failure modes

The extractor must produce a clear error in each of the following
cases:

| Case | Error class | Notes |
|---|---|---|
| PCAP missing at `raw/capture.pcap` | `PCAPExtractionError` | Operator must `pcap acquire` first. |
| `tshark` not on `PATH` | `PCAPExtractionError` wrapping `TsharkNotFoundError` | |
| `tshark` exits non-zero | `PCAPExtractionError` wrapping `TsharkError` | The last 5 lines of stderr are preserved in the error message. |
| `tshark` times out | `PCAPExtractionError` wrapping `TsharkError` | The configured `tools.tshark.timeout_seconds` is enforced. |
| PCAP is empty | `NetworkEvidence` with `flows = []` | A zero-byte PCAP is rejected at acquisition time, but a non-empty PCAP that contains no TCP/UDP frames produces an empty bundle, not an error. |
| Malformed PCAP | `NetworkEvidence` with diagnostics counters incremented | The parser never raises on a single malformed row; it skips and reports. |

The PCAP itself is never modified by the extractor; the SHA-256 of
the input is part of the output, so a downstream stage can detect
any change to the file.

## CLI

```bash
c2forensics pcap acquire EXP001 /path/to/capture.pcap
c2forensics pcap extract EXP001
```

The two commands can be combined in a script:

```bash
c2forensics init EXP001
c2forensics pcap acquire EXP001 /mnt/lab/EXP001/capture.pcap
c2forensics pcap extract EXP001
```

Both commands emit a small JSON summary on stdout. Errors are
reported on stderr with exit code 2.

## Implementation pointers

- `src/c2forensics/acquisition/pcap.py` — the only writer to `raw/`.
- `src/c2forensics/extraction/pcap/tshark.py` — the only subprocess
  invocation. `resolve_binary`, `run_fields`.
- `src/c2forensics/extraction/pcap/parser.py` — pure-functional
  parser, the unit-testable core.
- `src/c2forensics/extraction/pcap/extractor.py` — orchestration
  and persistence.
- `src/c2forensics/models/pcap.py` — typed output models.
