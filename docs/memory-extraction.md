# Memory extraction (Phase 3)

## Purpose

The memory extractor consumes a memory image from a controlled
laboratory C2 experiment and produces a deterministic, fully-typed
bundle of memory-side evidence.

The extractor deliberately does **not**:

- decrypt TLS application data;
- attempt to recover TLS session keys;
- attribute flows to processes (that is Phase 4's job);
- infer content, intent, or meaning;
- acquire memory from a running system (the dev environment
  cannot do that safely; the framework ingests an already-captured
  image).

What the extractor *does* produce is the volatile-memory side of
the dissertation's RQ1 question: which processes, with which PID,
were holding which sockets (local IP/port, remote IP/port,
protocol, state) at the moment of capture. Phase 4 will later
correlate these socket records with the network flows from
Phase 2.

## Evidence boundary

Every emitted field is labelled in its docstring as one of:

- **OBSERVED** — a fact directly read from a memory structure
  (PID, image name, socket local/remote endpoints, …);
- **DERIVED** — a value computed deterministically from observed
  fields;
- **INFERRED** — Phase 3 produces **zero inferred fields**. Any
  attribution between a memory socket and a network flow belongs
  to Phase 4.

## Pipeline

```
   raw/memory/<image>
       │
       │  (1) acquisition
       ▼
   raw/memory/<image>  ── SHA-256 ──► metadata.raw_hashes
       │
       │  (2) Volatility 3 extraction
       ▼
   for each supported plugin:
       vol -q -f <image> -r json <plugin>
   │
   │  (3) parser
   ▼
   typed records:
     processes  (ProcessArtifact, frozen)
     sockets    (SocketArtifact, frozen)
     tls        (TLSArtifact(absent=True), frozen)
   │
   │  (4) persistence
   ▼
   extracted/memory-processes.json
   extracted/memory-sockets.json
   extracted/memory-tls.json
   extracted/memory-envelopes.json
   extracted/memory-diagnostics.json
   extracted/memory-result.json
```

## Volatility plugins used

The framework runs only the plugins it knows how to parse, and
refuses to invoke anything else. The set is deliberately small:

| Plugin | Output | Why this plugin |
|---|---|---|
| `windows.pslist.PsList` | `[{PID, PPID, ImageFileName, CreateTime, ExitTime, …}]` | The canonical process list. It walks the kernel `EPROCESS` doubly-linked list and emits every active process. Sufficient to answer the dissertation's RQ1 question: "what processes existed at capture time?" |
| `windows.netscan.NetScan` | `[{PID, Owner, Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, Created, …}]` | The canonical network-connection view for Windows. It walks the kernel's connection-tracking structures and emits one row per active socket, with the owning PID. Sufficient to answer: "which process owned which socket?" |

No other plugins are currently invoked. The framework explicitly
does **not** run:

- `windows.handles.Handles` — duplicates `pslist` plus file
  handles; not needed for the RQ1 attribution hypothesis.
- `windows.netstat.NetStat` — superseded by `netscan`; `netscan`
  is the more reliable of the two on modern Windows 10.
- `windows.ssdt.SSDT`, `windows.callbacks.Callbacks`,
  `windows.drivers.Driverirp` — kernel-introspection plugins; not
  required for the dissertation's scope.
- **Any TLS-from-memory plugin** — Volatility 3 does not have a
  reliable cross-version plugin that recovers TLS session keys or
  SNI strings from arbitrary Windows memory. Phase 3 records an
  explicit ``absent=True`` TLS artefact rather than fabricating
  data.

If a future phase needs additional evidence kinds, the
`SUPPORTED_PLUGINS` tuple in
`extraction/memory/volatility.py` is the single place to extend,
together with a matching parser function in `parser.py`.

## Supported memory image platform

Phase 3 supports **Windows** memory images. The lab target is
Windows 10 (192.168.56.108). The framework is wired for the
Volatility 3 `windows.*` plugin namespace only. Linux and macOS
images are out of scope; the model layer (`ProcessArtifact`,
`SocketArtifact`, `TLSArtifact`) is OS-agnostic, but the
extractor's plugin dispatch is not.

The framework records the platform assumption on every bundle
(`MemoryExtractionResult.platform = "windows"`). An operator who
adds Linux support later must:

1. Extend `SUPPORTED_PLUGINS` with the appropriate Linux plugins.
2. Implement the matching parser functions.
3. Document the new platform in this file.

## Output schema

`extracted/memory-result.json` is a `MemoryExtractionResult`
bundle:

```json
{
  "experiment_id": "EXP001",
  "images": [
    {"path": "…", "sha256": "<64-hex>", "size_bytes": …, "mtime_utc": "…"}
  ],
  "extractor_name": "volatility3",
  "extractor_version": "…",
  "extracted_at": "2026-…+00:00",
  "platform": "windows",
  "processes": [ { ProcessArtifact } ],
  "sockets":   [ { SocketArtifact } ],
  "tls_artifacts": [ { TLSArtifact(absent=true) } ],
  "process_provenances": [ { ArtifactProvenance } ],
  "socket_provenances":  [ { ArtifactProvenance } ],
  "tls_provenances":     [ { ArtifactProvenance } ],
  "envelopes": [ { MemoryArtifactEnvelope } ],
  "plugin_status": {"windows.pslist.PsList": "ok", "windows.netscan.NetScan": "ok"}
}
```

The per-list `*_provenances` arrays are positionally aligned with
their corresponding artefact lists: the i-th process's
provenance is at `process_provenances[i]`.

`extracted/memory-processes.json`, `memory-sockets.json`,
`memory-tls.json`, and `memory-envelopes.json` are flat lists of
the same records for convenience; they are regenerated from the
same source data and remain consistent with the result bundle.

## Field provenance

| Field | Provenance | Notes |
|---|---|---|
| `images[].sha256` | OBSERVED | SHA-256 of the on-disk memory image at extraction time. |
| `images[].size_bytes` | OBSERVED | File size at extraction time. |
| `images[].mtime_utc` | OBSERVED | File modification time (UTC) at extraction time. |
| `process.pid` | OBSERVED | From the kernel's `EPROCESS.UniqueProcessId`. |
| `process.ppid` | OBSERVED (or null) | From `EPROCESS.InheritedFromUniqueProcessId`. |
| `process.process_name` | OBSERVED | `ImageFileName` from the kernel structure. Limited to 16 characters on Windows. |
| `process.executable_path` | **always null** | `pslist` does not emit a path; the field is reserved for future plugins. |
| `process.creation_time` | OBSERVED (UTC) | From the kernel's process-create time. Naive timestamps are coerced to UTC (Volatility 3 does not currently emit a timezone offset). |
| `process.termination_time` | OBSERVED (or null) | Null for active processes at capture. |
| `socket.pid` | OBSERVED | The owning process PID. |
| `socket.local_ip`, `local_port` | OBSERVED | From the kernel's connection-tracking structure. |
| `socket.remote_ip`, `remote_port` | OBSERVED (or null) | Listening sockets have no remote endpoint; the parser normalises this to null. |
| `socket.protocol` | OBSERVED | `tcp` or `udp`. |
| `socket.state` | OBSERVED | `ESTABLISHED`, `LISTENING`, `TIME_WAIT`, etc. |
| `socket.timestamp` | OBSERVED (or null) | The connection's creation time when available. |
| `tls.absent` | OBSERVED | The framework looked for TLS material and found none. |
| `tls.notes` | OBSERVED | "no TLS-extraction plugin in Phase 3" (or future reason). |
| `plugin_status[plugin]` | OBSERVED | Per-plugin result: `ok`, `not_found`, or `error`. |

There is no inferred field in the Phase 3 output. PID, IP, port,
protocol, and state are all directly observed; no field in the
output of `extract_memory` represents a cross-evidence guess.

## Memory acquisition

The development environment cannot acquire memory from a live
system. `c2forensics memory acquire` therefore performs
**ingestion**, not capture. The operator produces a memory image
out-of-band (using a controlled tool such as `winpmem` for
Windows, or `lime` for Linux) and the framework ingests the
result by bit-for-bit copy. This is documented in
`docs/experiment-protocol.md`.

The acquisition function:

- validates the source path: it must exist, be a regular file,
  be non-empty, and not be a symlink;
- copies the file to `raw/memory/<name>` (preserving the
  operator's filename, or accepting a `--dest-name` override);
- computes the SHA-256 of the on-disk image and stores it in
  `metadata.raw_hashes[<relative_path>]` = `<sha256>`;
- refuses to overwrite an existing image in the experiment;
- never modifies the source image.

The original image is left byte-for-byte identical: the
acquisition uses `shutil.copy2` followed by a re-hash to verify.

## Volatility invocation

`extraction/memory/volatility.py` is the only module that invokes
the Volatility binary. The wrapper:

- never uses `shell=True`;
- always passes the memory-image path as a single argv element;
- enforces a hard timeout from `config/lab.yaml`;
- captures stdout/stderr separately;
- returns parsed JSON (or raises a typed error).

The argv is constructed as:

```
vol -q -f <image> -r json <plugin>
```

`vol` is the Volatility 3 CLI. The framework refuses to invoke
any plugin not in `SUPPORTED_PLUGINS`; a typo in the plugin name
surfaces as a `VolatilityError`, not a silent misparse.

## What Phase 3 does not record

- TLS session keys, master secrets, or pre-master secrets.
- Decrypted TLS application data.
- Process-to-PCAP attribution (Phase 4's job).
- Any flow classification (e.g. "this is HTTPS", "this is C2").
- IPC, file handles, registry keys, kernel modules — none of
  these are extracted in Phase 3.
- Process executable path. `pslist` does not emit one; the field
  is reserved for a future plugin.
- Linux / macOS processes or sockets. The plugin set is Windows.

## Failure modes

| Case | Error class | Notes |
|---|---|---|
| No image at `raw/memory/` | `MemoryExtractionError` | Operator must `memory acquire` first. |
| `vol` not on `PATH` | `MemoryExtractionError` wrapping `VolatilityNotFoundError` | |
| `vol` exits non-zero | `VolatilityError`; orchestrator marks plugin as `error` and continues | Other plugins still produce results. |
| `vol` times out | `VolatilityError` | The configured `tools.volatility3.timeout_seconds` is enforced. |
| Empty image | `MemoryExtractionError` at acquisition time | A non-empty image that contains no recognisable structures produces per-plugin `not_found` statuses. |
| Malformed plugin output | The parser never raises on a single malformed row; the row is skipped and counted in `PluginDiagnostics.rows_skipped`. |

The image itself is never modified; the SHA-256 of the input
is part of the output, so a downstream stage can detect any
change.

## CLI

```bash
c2forensics memory acquire EXP001 /path/to/mem.raw
c2forensics memory extract EXP001
c2forensics memory status EXP001
```

The two commands can be combined in a script:

```bash
c2forensics init EXP001
c2forensics memory acquire EXP001 /mnt/lab/EXP001/mem.raw
c2forensics memory extract EXP001
```

## Validation status

- **Parser validation**: complete. The pure-functional parser
  is unit-tested against committed JSON fixtures of Volatility 3
  output, with explicit coverage of empty, malformed, and
  per-field aliasing cases.
- **Integration validation**: complete on this dev environment
  for everything except the live-Volatility binary. The
  integration test runs the real subprocess only when `vol` is
  on `PATH`; it is skipped on this host because Volatility 3 is
  not installed.
- **Real-memory validation**: **NOT PERFORMED** on this dev
  environment. A real Windows memory image is not available in
  the development sandbox; the VM lab is on a separate host and
  is used only to generate evidence. When a real `.raw` image is
  supplied to the framework, the integration test will execute
  and the bundle will be populated from real Volatility 3 output.
  Until then, the framework's behaviour against real
  Volatility 3 output is asserted only by contract (the field
  set, the JSON schema, and the parser's defensive handling of
  every documented column alias).
