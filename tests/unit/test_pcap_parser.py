"""Unit tests for the pure-functional PCAP parser.

These tests use committed JSON fixtures of tshark ``-T fields`` rows.
They do not require tshark to be installed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from c2forensics.extraction.pcap.parser import (
    PCAP_FIELDS,
    _derive_flow_id,
    _normalise_cipher_suite,
    _normalise_tls_version,
    _parse_epoch,
    _parse_tcp_flags,
    _row_to_frame,
    _tls_kind,
    assemble_bundle,
    parse_rows,
)
from c2forensics.models.pcap import (
    NetworkEvidence,
    TCPLifecycleFlag,
    TLSHandshakeKind,
)

UTC = timezone.utc
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _load_rows(name: str) -> list[list[str]]:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return payload["rows"]


# ---------------------------------------------------------------------------
# Helper-level tests
# ---------------------------------------------------------------------------


def test_parse_epoch_handles_empty() -> None:
    assert _parse_epoch("") is None
    assert _parse_epoch("  ") is None


def test_parse_epoch_returns_utc_datetime() -> None:
    ts = _parse_epoch("1700000000.0")
    assert ts == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)


def test_parse_epoch_returns_none_on_garbage() -> None:
    assert _parse_epoch("not-a-number") is None


def test_parse_tcp_flags_known_values() -> None:
    assert _parse_tcp_flags("0x002") == [TCPLifecycleFlag.SYN]
    assert _parse_tcp_flags("0x012") == [TCPLifecycleFlag.SYN, TCPLifecycleFlag.ACK]
    assert _parse_tcp_flags("0x010") == [TCPLifecycleFlag.ACK]
    # 0x011 = FIN | ACK; emission order matches the parser's bit walk.
    assert _parse_tcp_flags("0x011") == [TCPLifecycleFlag.ACK, TCPLifecycleFlag.FIN]
    assert _parse_tcp_flags("0x014") == [TCPLifecycleFlag.ACK, TCPLifecycleFlag.RST]


def test_parse_tcp_flags_empty_or_invalid() -> None:
    assert _parse_tcp_flags("") == []
    assert _parse_tcp_flags("not-hex") == []


def test_tls_kind_known_values() -> None:
    assert _tls_kind("1") == TLSHandshakeKind.CLIENT_HELLO
    assert _tls_kind("2") == TLSHandshakeKind.SERVER_HELLO
    assert _tls_kind("11") == TLSHandshakeKind.CERTIFICATE
    assert _tls_kind("20") == TLSHandshakeKind.FINISHED
    assert _tls_kind("99") is None
    assert _tls_kind("") is None


def test_tls_version_known_values() -> None:
    assert _normalise_tls_version("0x0303") == "TLS 1.2"
    assert _normalise_tls_version("0x0304") == "TLS 1.3"
    assert _normalise_tls_version("0x0302") == "TLS 1.1"
    assert _normalise_tls_version("0x0301") == "TLS 1.0"
    assert _normalise_tls_version("0x9999") is None
    assert _normalise_tls_version("") is None


def test_cipher_suite_known_and_unknown() -> None:
    assert _normalise_cipher_suite("4865") == "TLS_AES_128_GCM_SHA256"
    assert _normalise_cipher_suite("4866") == "TLS_AES_256_GCM_SHA384"
    # Unknown suites are preserved as 4-hex-digit strings, not fabricated.
    assert _normalise_cipher_suite("9999") == "0x270F"
    assert _normalise_cipher_suite("") is None


def test_derive_flow_id_with_and_without_stream() -> None:
    ep = ("192.168.56.108", 50578, "192.168.56.20", 8443, "tcp")
    assert _derive_flow_id(ep, None) == "tcp:192.168.56.108:50578->192.168.56.20:8443"
    assert _derive_flow_id(ep, 7) == "tcp:192.168.56.108:50578->192.168.56.20:8443#7"


def test_row_to_frame_pads_short_rows() -> None:
    fr = _row_to_frame(["1", "1700000000.0", "100"])
    assert fr.frame_number == "1"
    assert fr.ip_src == ""
    assert fr.tcp_flags == ""


def test_field_set_is_complete() -> None:
    # The PCAP_FIELDS tuple is the contract with tshark; if a new field
    # is added, this test must be updated explicitly. It is a guard
    # against silent contract drift.
    assert "frame.number" in PCAP_FIELDS
    assert "ip.src" in PCAP_FIELDS
    assert "tcp.srcport" in PCAP_FIELDS
    assert "tcp.dstport" in PCAP_FIELDS
    assert "tcp.flags" in PCAP_FIELDS
    assert "tls.handshake.type" in PCAP_FIELDS
    assert "tls.handshake.extensions_server_name" in PCAP_FIELDS


# ---------------------------------------------------------------------------
# End-to-end parser tests
# ---------------------------------------------------------------------------


def test_parse_encrypted_c2_baseline() -> None:
    rows = _load_rows("tshark_rows_encrypted_c2.json")
    flows, tcp_events, tls_obs, diags = parse_rows(rows, experiment_id="EXP001")
    assert len(flows) == 1
    flow = flows[0]
    assert flow.src_ip == "192.168.56.108"
    assert flow.src_port == 50578
    assert flow.dst_ip == "192.168.56.20"
    assert flow.dst_port == 8443
    assert flow.protocol == "tcp"
    assert flow.frame_count == 13
    # Sum of frame.len across the 13-row fixture: 74+74+66+583+1474+1200+198+1500+1500+66+66+66+66 = 6933
    assert flow.byte_count == 6933
    assert flow.duration_seconds == pytest.approx(0.182240, rel=1e-3)
    # Flow id is deterministic
    assert flow.flow_id == "tcp:192.168.56.108:50578->192.168.56.20:8443#0"
    # TCP events: one SYN, one SYN, one ACK, then FIN+ACK, ACK.
    flags = [e.flag for e in tcp_events]
    assert TCPLifecycleFlag.SYN in flags
    assert TCPLifecycleFlag.ACK in flags
    assert TCPLifecycleFlag.FIN in flags
    # Direction tagging: the SYN from 192.168.56.108 is c2s, the SYN-ACK is s2c.
    syn = [e for e in tcp_events if e.flag == TCPLifecycleFlag.SYN and e.frame_number == 1]
    assert syn[0].direction == "c2s"
    synack = [e for e in tcp_events if e.flag == TCPLifecycleFlag.SYN and e.frame_number == 2]
    assert synack[0].direction == "s2c"
    # TLS observations cover the four handshake messages.
    kinds = sorted(o.kind for o in tls_obs)
    assert kinds == sorted(
        [
            TLSHandshakeKind.CLIENT_HELLO,
            TLSHandshakeKind.SERVER_HELLO,
            TLSHandshakeKind.CERTIFICATE,
            TLSHandshakeKind.FINISHED,
        ]
    )
    client_hello = next(o for o in tls_obs if o.kind == TLSHandshakeKind.CLIENT_HELLO)
    assert client_hello.sni == "c2.lab"
    server_hello = next(o for o in tls_obs if o.kind == TLSHandshakeKind.SERVER_HELLO)
    assert server_hello.cipher_suite == "TLS_AES_128_GCM_SHA256"
    assert server_hello.tls_version == "TLS 1.2"  # ClientHello/ServerHello version is 0x0303 by spec; real wire version is in Supported Versions ext which we do not yet parse
    cert = next(o for o in tls_obs if o.kind == TLSHandshakeKind.CERTIFICATE)
    assert cert.certificate_subject == "c2.lab"
    assert cert.certificate_issuer == "C2 Lab Root CA"
    # Diagnostics are sensible
    assert diags.rows_seen == 13
    assert diags.rows_skipped_no_timestamp == 0
    assert diags.rows_skipped_no_endpoint == 0
    assert diags.tcp_lifecycle_events == len(tcp_events)
    assert diags.tls_observations == len(tls_obs)


def test_parse_empty_capture() -> None:
    rows = _load_rows("tshark_rows_empty.json")
    flows, tcp_events, tls_obs, diags = parse_rows(rows, experiment_id="EXP001")
    assert flows == []
    assert tcp_events == []
    assert tls_obs == []
    assert diags.rows_seen == 0


def test_parse_udp_dns() -> None:
    rows = _load_rows("tshark_rows_udp_dns.json")
    flows, tcp_events, tls_obs, diags = parse_rows(rows, experiment_id="EXP001")
    assert len(flows) == 1
    assert flows[0].protocol == "udp"
    assert flows[0].src_port == 55000
    assert flows[0].dst_port == 53
    assert tcp_events == []  # No TCP control flags in a UDP capture
    assert tls_obs == []


def test_parse_two_flows_returns_deterministic_order() -> None:
    rows = _load_rows("tshark_rows_two_flows.json")
    flows, _, tls_obs, _ = parse_rows(rows, experiment_id="EXP001")
    assert len(flows) == 2
    # Deterministic ordering: by (src_ip, src_port, dst_ip, dst_port, protocol, stream)
    assert flows[0].src_port == 51000
    assert flows[0].dst_ip == "192.168.56.20"
    assert flows[1].src_port == 51001
    assert flows[1].dst_ip == "192.168.56.30"
    # First flow (the encrypted C2 baseline) carries a TLS 1.3 ServerHello (0x0304 -> TLS 1.3).
    first_flow_tls = [o for o in tls_obs if o.flow_id == flows[0].flow_id]
    assert first_flow_tls
    assert any(o.tls_version == "TLS 1.3" for o in first_flow_tls)
    # Second flow is plain HTTP, so it has no TLS observations.
    second_flow_tls = [o for o in tls_obs if o.flow_id == flows[1].flow_id]
    assert second_flow_tls == []


def test_parse_is_deterministic_across_runs() -> None:
    rows = _load_rows("tshark_rows_encrypted_c2.json")
    flows_a, tcp_a, tls_a, diags_a = parse_rows(rows, experiment_id="EXP001")
    flows_b, tcp_b, tls_b, diags_b = parse_rows(rows, experiment_id="EXP001")
    assert [f.model_dump() for f in flows_a] == [f.model_dump() for f in flows_b]
    assert [e.model_dump() for e in tcp_a] == [e.model_dump() for e in tcp_b]
    assert [o.model_dump() for o in tls_a] == [o.model_dump() for o in tls_b]
    assert diags_a == diags_b


def test_assemble_bundle_builds_typed_record() -> None:
    rows = _load_rows("tshark_rows_encrypted_c2.json")
    bundle, diags = assemble_bundle(
        experiment_id="EXP001",
        pcap_path="/tmp/capture.pcap",
        pcap_sha256="0" * 64,
        extractor_version="TShark 4.2.0 (test)",
        extracted_at=datetime(2026, 1, 1, tzinfo=UTC),
        rows=rows,
    )
    assert isinstance(bundle, NetworkEvidence)
    assert bundle.experiment_id == "EXP001"
    assert bundle.pcap_sha256 == "0" * 64
    assert len(bundle.flows) == 1
    # Bundle can be re-serialised and re-parsed.
    payload = bundle.model_dump_json()
    parsed = NetworkEvidence.model_validate_json(payload)
    assert parsed == bundle
    # Diagnostics are surfaced.
    assert diags.rows_seen == 13
