"""Unit tests for configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from c2forensics.config import (
    CorrelationThresholds,
    CorrelationWeights,
    LabSection,
    load_config,
)


def test_load_config_returns_frozen_view(sample_lab_config_yaml: Path) -> None:
    cfg = load_config(sample_lab_config_yaml)
    assert cfg.lab.target_host == "192.168.56.108"
    assert cfg.tools.tshark.timeout_seconds == 60
    assert cfg.correlation.timestamp_tolerance_seconds == 5


def test_load_config_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "missing.yaml")


def test_load_config_rejects_non_mapping(tmp_path: Path) -> None:
    p = tmp_path / "lab.yaml"
    p.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(p)


def test_lab_section_validates_port() -> None:
    with pytest.raises(ValidationError):
        LabSection(
            network_cidr="0.0.0.0/0",
            target_host="1.1.1.1",
            c2_server_host="2.2.2.2",
            c2_server_port=0,
        )


def test_correlation_thresholds_must_be_ordered() -> None:
    with pytest.raises(ValidationError):
        CorrelationThresholds(strong=0.5, medium=0.8, weak=0.2)
    with pytest.raises(ValidationError):
        CorrelationThresholds(strong=0.8, medium=0.5, weak=0.6)


def test_correlation_weights_total() -> None:
    w = CorrelationWeights(
        ip_match=0.25,
        port_match=0.25,
        protocol_match=0.10,
        timestamp_proximity=0.15,
        socket_match=0.20,
        process_association=0.05,
    )
    assert abs(w.total() - 1.0) < 1e-9
