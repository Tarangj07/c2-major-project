"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def tmp_repo_root(tmp_path: Path) -> Path:
    """Return a clean temporary directory suitable as a repository root."""
    return tmp_path


@pytest.fixture()
def sample_lab_config_yaml(tmp_path: Path) -> Path:
    """Write a minimal valid lab.yaml and return its path."""
    content = (
        "lab:\n"
        "  network_cidr: 192.168.56.0/24\n"
        "  target_host: 192.168.56.108\n"
        "  c2_server_host: 192.168.56.20\n"
        "  c2_server_port: 8443\n"
        "tools:\n"
        "  tshark:\n"
        "    binary: tshark\n"
        "    timeout_seconds: 60\n"
        "  volatility3:\n"
        "    binary: vol\n"
        "    timeout_seconds: 600\n"
        "correlation:\n"
        "  weights:\n"
        "    ip_match: 0.25\n"
        "    port_match: 0.25\n"
        "    protocol_match: 0.10\n"
        "    timestamp_proximity: 0.15\n"
        "    socket_match: 0.20\n"
        "    process_association: 0.05\n"
        "  timestamp_tolerance_seconds: 5\n"
        "  thresholds:\n"
        "    strong: 0.80\n"
        "    medium: 0.50\n"
        "    weak: 0.20\n"
    )
    cfg = tmp_path / "config"
    cfg.mkdir()
    path = cfg / "lab.yaml"
    path.write_text(content, encoding="utf-8")
    return path
