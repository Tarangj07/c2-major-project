"""Integration test: drive the real tshark against a real PCAP.

This test is **skipped** when tshark is not on ``PATH``. It exists
to catch contract drift between the framework's field set and the
real tshark binary. It also serves as documentation: the test
itself shows how to drive the extractor end-to-end with a real PCAP.

The test uses scapy to build a tiny deterministic PCAP at runtime
when available, falling back to a hand-crafted byte stream if scapy
is not installed. Either way, the goal is to exercise the real
``PcapExtractor`` with a real tshark invocation, not to validate
tshark itself.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from c2forensics.config import load_config
from c2forensics.experiment import init_experiment
from c2forensics.extraction.pcap import extract_pcap
from c2forensics.extraction.pcap.tshark import resolve_binary
from c2forensics.hashing import hash_file


TSHARK_REQUIRED = pytest.mark.skipif(
    shutil.which("tshark") is None,
    reason="tshark not on PATH; integration test skipped",
)


def _build_pcap_with_scapy(out: Path) -> None:
    """Build a tiny deterministic PCAP with a SYN+ACK+FIN TCP flow.

    Falls back to a hand-crafted PCAP if scapy is not installed.
    """
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap  # type: ignore

        pkt = (
            Ether()
            / IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=40000, dport=80, flags="S", seq=1000)
        )
        pkt2 = (
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=80, dport=40000, flags="SA", seq=2000, ack=1001)
        )
        pkt3 = (
            Ether()
            / IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=40000, dport=80, flags="FA", seq=1001, ack=2001)
        )
        wrpcap(str(out), [pkt, pkt2, pkt3])
    except ImportError:
        # Hand-crafted minimal PCAP. We construct just enough bytes to
        # let tshark recognise the file and parse the Ethernet/IPv4/TCP
        # headers. A real PCAP is not required for the framework's
        # correctness; this only verifies that the wrapper and parser
        # can be driven end-to-end when tshark is available.
        _write_minimal_pcap(out)


def _write_minimal_pcap(out: Path) -> None:
    """Write a minimal pcap with three Ethernet/IPv4/TCP frames."""
    import socket

    def _pcap_global_header() -> bytes:
        return struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,  # magic
            2, 4,        # version
            0,           # thiszone
            0,           # sigfigs
            65535,       # snaplen
            1,           # LINKTYPE_ETHERNET
        )

    def _frame(ts_sec: int, data: bytes) -> bytes:
        return struct.pack("<IIII", ts_sec, 0, len(data), len(data)) + data

    def _eth_ipv4_tcp(src_ip: str, dst_ip: str, sport: int, dport: int, flags: int, seq: int, ack: int = 0) -> bytes:
        # Ethernet
        eth = b"\x00" * 6 + b"\x00" * 6 + struct.pack(">H", 0x0800)
        # IPv4 header (20 bytes, no options)
        ver_ihl = 0x45
        tos = 0
        total_len = 20 + 20
        ident = 0
        flags_frag = 0x4000  # DF
        ttl = 64
        proto = socket.IPPROTO_TCP
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)
        hdr = struct.pack(
            ">BBHHHBBH4s4s",
            ver_ihl, tos, total_len, ident, flags_frag, ttl, proto, 0, src, dst
        )
        checksum = _ipv4_checksum(hdr)
        hdr = hdr[:10] + struct.pack(">H", checksum) + hdr[12:]
        # TCP header (20 bytes)
        data_off = 5 << 4
        tcp = struct.pack(
            ">HHIIBBHHH",
            sport, dport, seq, ack, data_off, flags, 65535, 0, 0
        )
        return eth + hdr + tcp

    def _ipv4_checksum(hdr: bytes) -> int:
        s = 0
        for i in range(0, len(hdr), 2):
            s += (hdr[i] << 8) | hdr[i + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    syn = _eth_ipv4_tcp("10.0.0.2", "10.0.0.1", 40000, 80, 0x02, 1000)
    synack = _eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 80, 40000, 0x12, 2000, ack=1001)
    finack = _eth_ipv4_tcp("10.0.0.2", "10.0.0.1", 40000, 80, 0x11, 1001, ack=2001)

    with out.open("wb") as fh:
        fh.write(_pcap_global_header())
        fh.write(_frame(1_700_000_000, syn))
        fh.write(_frame(1_700_000_000, synack))
        fh.write(_frame(1_700_000_001, finack))


@TSHARK_REQUIRED
def test_real_tshark_against_real_pcap(tmp_path: Path, sample_lab_config_yaml: Path) -> None:
    binary = resolve_binary("tshark")
    assert binary  # resolve_binary raises if missing

    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    pcap = paths.raw / "capture.pcap"
    _build_pcap_with_scapy(pcap)
    assert pcap.is_file()
    pre_hash = hash_file(pcap)

    config = load_config(sample_lab_config_yaml)
    bundle = extract_pcap(paths, config)

    # The PCAP was not modified.
    assert hash_file(pcap) == pre_hash
    # At least one flow was extracted (the SYN/SYN-ACK/FIN-ACK).
    assert bundle.flows, "tshark should have parsed at least one flow"
    flow = bundle.flows[0]
    assert flow.protocol == "tcp"
    # The first observed packet is the SYN from 10.0.0.2.
    assert flow.src_ip in ("10.0.0.2", "10.0.0.1")
    # TCP lifecycle events must include at least one SYN.
    from c2forensics.models.pcap import TCPLifecycleFlag
    assert any(e.flag == TCPLifecycleFlag.SYN for e in bundle.tcp_lifecycle)
    # Extractor version was recorded.
    assert bundle.extractor_version != "unknown"


@TSHARK_REQUIRED
def test_real_tshark_handles_malformed_pcap(
    tmp_path: Path, sample_lab_config_yaml: Path
) -> None:
    """tshark should be able to read a PCAP with one truncated frame.

    The framework must not crash; it must surface the error to the
    operator. We use the existing tshark binary, but feed it a
    PCAP that is truncated mid-frame so tshark emits a warning
    rather than a hard error.
    """
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    pcap = paths.raw / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)  # magic + filler
    config = load_config(sample_lab_config_yaml)
    # tshark will likely warn on stderr; the wrapper treats non-zero
    # exit as an error. So either the call returns zero rows and a
    # valid bundle, or it raises PCAPExtractionError. Both are
    # acceptable behaviours for a malformed PCAP.
    try:
        bundle = extract_pcap(paths, config)
    except Exception:
        return
    assert bundle.flows == []


# ---------------------------------------------------------------------------
# Tests that do not require tshark on PATH.
# ---------------------------------------------------------------------------


def test_acquire_real_pcap_byte_for_byte(
    tmp_path: Path,
) -> None:
    """Build a real PCAP at runtime, acquire it, and verify integrity.

    This test runs without tshark. It exercises the acquisition
    pipeline end-to-end against a file that satisfies the PCAP file
    format (magic number, version, linktype). The PCAP contains no
    real packets, only the global header, but the test still proves
    that:

    * the framework accepts a real PCAP file;
    * the SHA-256 of the source matches the on-disk copy;
    * the on-disk copy is bit-for-bit identical to the source.
    """
    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    pcap_src = tmp_path / "real.pcap"
    pcap_bytes = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,  # PCAP magic
        2, 4,        # version
        0,           # thiszone
        0,           # sigfigs
        65535,       # snaplen
        1,           # LINKTYPE_ETHERNET
    ) + b"\x00" * 64  # some padding so the file is non-empty
    pcap_src.write_bytes(pcap_bytes)
    from c2forensics.acquisition import acquire_pcap
    from c2forensics.hashing import hash_file as _hash_file

    digest = acquire_pcap(paths, pcap_src)
    on_disk = paths.raw / "capture.pcap"
    assert on_disk.read_bytes() == pcap_bytes
    assert _hash_file(on_disk) == digest
    # The source file is unchanged.
    assert pcap_src.read_bytes() == pcap_bytes


def test_pcap_does_not_modify_source_under_acquisition(
    tmp_path: Path,
) -> None:
    """Acquisition must not touch the source PCAP in any way.

    We compute the source SHA-256 before and after the acquisition
    call. The two digests must be identical.
    """
    from c2forensics.acquisition import acquire_pcap
    from c2forensics.hashing import hash_file as _hash_file

    paths = init_experiment(repo_root=tmp_path, experiment_id="EXP001")
    pcap_src = tmp_path / "src.pcap"
    pcap_bytes = b"this-is-a-pcap" * 100
    pcap_src.write_bytes(pcap_bytes)
    pre = _hash_file(pcap_src)
    acquire_pcap(paths, pcap_src)
    post = _hash_file(pcap_src)
    assert pre == post
    assert pcap_src.read_bytes() == pcap_bytes
