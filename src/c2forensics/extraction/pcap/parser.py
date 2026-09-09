"""Pure-functional parser: tshark rows -> typed PCAP observations.

This module never invokes subprocesses and never touches the
filesystem. It accepts the *fields* output of tshark and emits the
typed ``FlowObservation`` / ``TCPLifecycleEvent`` / ``TLSObservation``
records. Keeping the parser pure means unit tests can exercise it
with synthetic tshark output committed under ``tests/fixtures/``,
without requiring tshark to be installed.

The parser is deliberately conservative: any field that cannot be
parsed is left as ``None`` and recorded in the returned diagnostics
list, so that the caller can decide how to handle partial
information.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from c2forensics.models.pcap import (
    FlowObservation,
    NetworkEvidence,
    TCPLifecycleEvent,
    TCPLifecycleFlag,
    TLSHandshakeKind,
    TLSObservation,
)


# ---------------------------------------------------------------------------
# Field set requested from tshark. Order is significant: ``to_argv``
# emits fields in this order, and the parser maps each row to a
# ``FrameRow`` using positional access. Reorder only by also editing
# ``_FrameRow``.
# ---------------------------------------------------------------------------

PCAP_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "tcp.flags",
    "tls.handshake.type",
    "tls.handshake.version",
    "tls.handshake.ciphersuite",
    "tls.handshake.extensions_server_name",
    "x509sat.uTF8String",
    "x509ce.dNSName",
    "x509af.issuer",
)


@dataclass(frozen=True)
class FrameRow:
    """One packet, in the field order declared in ``PCAP_FIELDS``."""

    frame_number: str
    frame_time_epoch: str
    frame_len: str
    ip_src: str
    ip_dst: str
    tcp_srcport: str
    tcp_dstport: str
    udp_srcport: str
    udp_dstport: str
    tcp_stream: str
    tcp_flags: str
    tls_handshake_type: str
    tls_handshake_version: str
    tls_handshake_ciphersuite: str
    tls_sni: str
    x509_subject_cn: str
    x509_dns_name: str
    x509_issuer: str


def _row_to_frame(row: list[str]) -> FrameRow:
    """Map a list of strings (one per PCAP_FIELDS entry) to a FrameRow.

    The defensive slicing guarantees that short rows do not raise
    ``IndexError`` here; missing trailing fields are filled with empty
    strings.
    """
    padded = list(row) + [""] * (len(PCAP_FIELDS) - len(row))
    return FrameRow(*padded[: len(PCAP_FIELDS)])


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_epoch(value: str) -> datetime | None:
    """Parse a tshark epoch seconds value to a UTC ``datetime``.

    tshark emits epoch seconds with microsecond precision. If the
    field is empty, ``None`` is returned. Malformed values are
    reported via diagnostics, not raised.
    """
    value = value.strip()
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def _parse_int(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _parse_tcp_flags(flags_hex: str) -> list[TCPLifecycleFlag]:
    """Translate a tcp.flags hex value into a list of observed flags.

    tshark's ``tcp.flags`` is a 3-character hex string (e.g. ``0x002``,
    ``0x012``, ``0x014``). We use the canonical bit definitions:

    * 0x002  SYN
    * 0x010  ACK
    * 0x001  FIN
    * 0x004  RST

    SYN+ACK is reported as both ``SYN`` and ``ACK``; the ``TCPLifecycleEvent``
    list will therefore contain two events for the same frame.
    """
    if not flags_hex:
        return []
    s = flags_hex.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    try:
        flags_int = int(s, 16)
    except ValueError:
        return []
    out: list[TCPLifecycleFlag] = []
    if flags_int & 0x002:
        out.append(TCPLifecycleFlag.SYN)
    if flags_int & 0x010:
        out.append(TCPLifecycleFlag.ACK)
    if flags_int & 0x001:
        out.append(TCPLifecycleFlag.FIN)
    if flags_int & 0x004:
        out.append(TCPLifecycleFlag.RST)
    return out


def _tls_kind(handshake_type: str) -> TLSHandshakeKind | None:
    """Map a tshark ``tls.handshake.type`` integer to a ``TLSHandshakeKind``.

    The numeric values are the IANA-defined TLS HandshakeType codes:

    *  1 -> ClientHello
    *  2 -> ServerHello
    * 11 -> Certificate
    * 20 -> Finished
    """
    n = _parse_int(handshake_type)
    if n is None:
        return None
    if n == 1:
        return TLSHandshakeKind.CLIENT_HELLO
    if n == 2:
        return TLSHandshakeKind.SERVER_HELLO
    if n == 11:
        return TLSHandshakeKind.CERTIFICATE
    if n == 20:
        return TLSHandshakeKind.FINISHED
    return None


def _normalise_tls_version(value: str) -> str | None:
    """Convert a tshark ``tls.handshake.version`` integer to a string.

    tshark encodes the protocol version as 0x0301 (TLS 1.0), 0x0302
    (TLS 1.1), 0x0303 (TLS 1.2), 0x0304 (TLS 1.3). The integer is
    emitted as a hex string.
    """
    value = value.strip().lower()
    if not value:
        return None
    if value.startswith("0x"):
        value = value[2:]
    try:
        n = int(value, 16)
    except ValueError:
        return None
    if n == 0x0301:
        return "TLS 1.0"
    if n == 0x0302:
        return "TLS 1.1"
    if n == 0x0303:
        return "TLS 1.2"
    if n == 0x0304:
        return "TLS 1.3"
    return None


def _normalise_cipher_suite(value: str) -> str | None:
    """Convert a tshark cipher-suite integer to its IANA name where possible.

    A full table is out of scope for a research prototype; the integer
    is preserved if the name is not known. Known common values are
    resolved.
    """
    if not value.strip():
        return None
    n = _parse_int(value)
    if n is None:
        return value.strip() or None
    known = {
        0x1301: "TLS_AES_128_GCM_SHA256",
        0x1302: "TLS_AES_256_GCM_SHA384",
        0x1303: "TLS_CHACHA20_POLY1305_SHA256",
        0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    }
    if n in known:
        return known[n]
    return f"0x{n:04X}"


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


@dataclass
class ParseDiagnostics:
    """Counters and samples for parser edge cases.

    These are surfaced in the ``NetworkEvidence`` bundle so that an
    operator can spot malformed PCAPs without having to re-run
    tshark.
    """

    rows_seen: int = 0
    rows_skipped_no_timestamp: int = 0
    rows_skipped_no_endpoint: int = 0
    tcp_lifecycle_events: int = 0
    tls_observations: int = 0
    tls_handshake_unknown_type: list[str] = field(default_factory=list)
    malformed_flags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Top-level parse
# ---------------------------------------------------------------------------


def _endpoint_key(fr: FrameRow) -> tuple[str, int, str, int, str] | None:
    """Return ``(src_ip, src_port, dst_ip, dst_port, proto)`` or None.

    The function prefers TCP if both TCP and UDP ports are present
    (this is the tshark convention when both stacks are visible).
    """
    if not fr.ip_src or not fr.ip_dst:
        return None
    if fr.tcp_srcport and fr.tcp_dstport:
        return (
            fr.ip_src,
            int(fr.tcp_srcport),
            fr.ip_dst,
            int(fr.tcp_dstport),
            "tcp",
        )
    if fr.udp_srcport and fr.udp_dstport:
        return (
            fr.ip_src,
            int(fr.udp_srcport),
            fr.ip_dst,
            int(fr.udp_dstport),
            "udp",
        )
    return None


def _derive_flow_id(ep: tuple[str, int, str, int, str], tcp_stream: int | None) -> str:
    """Produce a deterministic, human-readable flow identifier.

    The 5-tuple is sufficient to identify a flow in 99% of captures;
    the TCP stream index is appended when present so that a single PCAP
    with multiple coincident 5-tuples (reconnects, NATs) can be told
    apart. The format is intentionally stable across runs so that
    re-extraction of the same PCAP produces the same flow_id.
    """
    src_ip, src_port, dst_ip, dst_port, proto = ep
    if tcp_stream is not None:
        return f"{proto}:{src_ip}:{src_port}->{dst_ip}:{dst_port}#{tcp_stream}"
    return f"{proto}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"


def _canonicalise_endpoint(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int
) -> tuple[str, int, str, int]:
    """Return the endpoint pair in a stable, direction-independent order.

    A TCP flow is bidirectional: the SYN initiator and the SYN-ACK
    responder observe *opposite* 5-tuples. To collapse both into a
    single flow, we sort the two endpoints lexicographically by
    (ip, port). The chosen order is stable across re-runs, so the
    same PCAP always produces the same canonical 5-tuple.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return src_ip, src_port, dst_ip, dst_port
    return dst_ip, dst_port, src_ip, src_port


def parse_rows(
    rows: Iterable[list[str]],
    *,
    experiment_id: str,
) -> tuple[list[FlowObservation], list[TCPLifecycleEvent], list[TLSObservation], ParseDiagnostics]:
    """Convert tshark ``-T fields`` rows into typed observations.

    Returns a tuple of (flows, tcp_lifecycle, tls_observations,
    diagnostics). The flows are returned in a deterministic order so
    that re-running the parser on the same input yields the same
    output. The TCP and TLS events are returned in PCAP frame order.

    A flow is identified by the *canonicalised* 5-tuple: the two
    endpoints are sorted lexicographically by ``(ip, port)`` so that
    the initiator and responder see the same flow. The TCP stream
    index is appended as a tiebreaker for captures that have multiple
    coincident 5-tuples (e.g. reconnects).
    """
    diags = ParseDiagnostics()

    flows_data: dict[
        tuple[str, int, str, int, str, int | None],
        dict[str, object],
    ] = {}
    tcp_events: list[TCPLifecycleEvent] = []
    tls_events: list[TLSObservation] = []

    # Initiator tracking uses the same canonical 5-tuple so that the
    # SYN and the SYN-ACK see the same bucket.
    initiator: dict[tuple[str, int, str, int, str, int | None], tuple[str, int]] = {}

    for raw in rows:
        diags.rows_seen += 1
        fr = _row_to_frame(raw)
        ts = _parse_epoch(fr.frame_time_epoch)
        if ts is None:
            diags.rows_skipped_no_timestamp += 1
            continue
        ep = _endpoint_key(fr)
        if ep is None:
            diags.rows_skipped_no_endpoint += 1
            continue
        src_ip, src_port, dst_ip, dst_port, proto = ep
        stream = _parse_int(fr.tcp_stream)
        c_src_ip, c_src_port, c_dst_ip, c_dst_port = _canonicalise_endpoint(
            src_ip, src_port, dst_ip, dst_port
        )
        flow_key = (c_src_ip, c_src_port, c_dst_ip, c_dst_port, proto, stream)
        if flow_key not in flows_data:
            flows_data[flow_key] = {
                "first_seen": ts,
                "last_seen": ts,
                "frame_count": 0,
                "byte_count": 0,
            }
        bucket = flows_data[flow_key]
        if ts < bucket["first_seen"]:  # type: ignore[operator]
            bucket["first_seen"] = ts
        if ts > bucket["last_seen"]:  # type: ignore[operator]
            bucket["last_seen"] = ts
        bucket["frame_count"] = int(bucket["frame_count"]) + 1
        if fr.frame_len:
            try:
                bucket["byte_count"] = int(bucket["byte_count"]) + int(fr.frame_len)
            except ValueError:
                pass
        if proto == "tcp":
            # Record initiator on the first SYN we see.
            if stream is not None and fr.tcp_flags and (int(fr.tcp_flags, 16) & 0x002):
                if flow_key not in initiator:
                    initiator[flow_key] = (src_ip, src_port)

            for flag in _parse_tcp_flags(fr.tcp_flags):
                init = initiator.get(flow_key)
                direction = "c2s"
                if init is not None:
                    direction = "c2s" if (src_ip, src_port) == init else "s2c"
                frame_no = _parse_int(fr.frame_number) or 0
                tcp_events.append(
                    TCPLifecycleEvent(
                        experiment_id=experiment_id,
                        flow_id=_derive_flow_id(
                            (c_src_ip, c_src_port, c_dst_ip, c_dst_port, proto), stream
                        ),
                        timestamp=ts,
                        flag=flag,
                        direction=direction,
                        frame_number=frame_no,
                    )
                )
                diags.tcp_lifecycle_events += 1
            if fr.tcp_flags and not _parse_tcp_flags(fr.tcp_flags) and fr.tcp_flags.strip():
                diags.malformed_flags.append(fr.tcp_flags)

        # TLS handshake observations.
        if fr.tls_handshake_type:
            kind = _tls_kind(fr.tls_handshake_type)
            if kind is None:
                diags.tls_handshake_unknown_type.append(fr.tls_handshake_type)
                continue
            tls_events.append(
                TLSObservation(
                    experiment_id=experiment_id,
                    flow_id=_derive_flow_id(
                        (c_src_ip, c_src_port, c_dst_ip, c_dst_port, proto), stream
                    ),
                    timestamp=ts,
                    kind=kind,
                    frame_number=_parse_int(fr.frame_number) or 0,
                    tls_version=_normalise_tls_version(fr.tls_handshake_version),
                    sni=fr.tls_sni or None,
                    cipher_suite=_normalise_cipher_suite(fr.tls_handshake_ciphersuite),
                    certificate_subject=fr.x509_subject_cn or None,
                    certificate_issuer=fr.x509_issuer or None,
                )
            )
            diags.tls_observations += 1

    # Materialise the flows in deterministic order.
    flow_list: list[FlowObservation] = []
    for key in sorted(flows_data.keys(), key=lambda k: (k[0], k[1], k[2], k[3], k[4], k[5] or -1)):
        src_ip, src_port, dst_ip, dst_port, proto, stream = key
        bucket = flows_data[key]
        first_seen: datetime = bucket["first_seen"]  # type: ignore[assignment]
        last_seen: datetime = bucket["last_seen"]  # type: ignore[assignment]
        frame_count = int(bucket["frame_count"])
        byte_count = int(bucket["byte_count"])
        # Derived fields are always populated by the parser so that
        # every ``FlowObservation`` leaving Phase 2 carries them.
        duration = max(0.0, (last_seen - first_seen).total_seconds())
        fps = (frame_count / duration) if duration > 0 else 0.0
        bps = (byte_count / duration) if duration > 0 else 0.0
        flow_list.append(
            FlowObservation(
                experiment_id=experiment_id,
                flow_id=_derive_flow_id(
                    (src_ip, src_port, dst_ip, dst_port, proto), stream
                ),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                tcp_stream=stream,
                first_seen=first_seen,
                last_seen=last_seen,
                frame_count=frame_count,
                byte_count=byte_count,
                duration_seconds=duration,
                frames_per_second=fps,
                bytes_per_second=bps,
            )
        )
    return flow_list, tcp_events, tls_events, diags


def assemble_bundle(
    *,
    experiment_id: str,
    pcap_path: str,
    pcap_sha256: str,
    extractor_version: str,
    extracted_at: datetime,
    rows: Iterable[list[str]],
) -> tuple[NetworkEvidence, ParseDiagnostics]:
    """Convenience wrapper: parse rows and assemble a ``NetworkEvidence``."""
    flows, tcp_events, tls_events, diags = parse_rows(rows, experiment_id=experiment_id)
    bundle = NetworkEvidence(
        experiment_id=experiment_id,
        pcap_path=pcap_path,
        pcap_sha256=pcap_sha256,
        extractor_version=extractor_version,
        extracted_at=extracted_at,
        flows=flows,
        tcp_lifecycle=tcp_events,
        tls_observations=tls_events,
    )
    return bundle, diags
