"""Unit tests for the CLI surface.

These tests exercise the CLI in-process via ``main(argv)`` rather than via
a subprocess. The framework is small enough that this is sufficient, and
it keeps the test fast.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from c2forensics.cli.main import build_parser, main


def test_parser_rejects_unknown_subcommand() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["nope"])


def test_init_then_show(tmp_path: Path, sample_lab_config_yaml: Path) -> None:
    # Place the lab config at <tmp>/config/lab.yaml, and use <tmp> as repo root.
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
            "--description",
            "baseline run",
        ]
    )
    assert rc == 0

    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "show",
            "EXP001",
        ]
    )
    assert rc == 0


def test_show_missing_experiment(tmp_path: Path, sample_lab_config_yaml: Path) -> None:
    # Framework errors are caught by main() and reported via exit code 2.
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "show",
            "EXP_MISSING",
        ]
    )
    assert rc == 2


def test_init_rejects_bad_experiment_id(tmp_path: Path, sample_lab_config_yaml: Path) -> None:
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "../bad",
        ]
    )
    assert rc == 2


def test_init_prints_paths_json(tmp_path: Path, sample_lab_config_yaml: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["experiment_dir"].endswith("experiments/EXP001")
    assert Path(payload["experiment_dir"]).is_dir()


def test_missing_config_file(tmp_path: Path) -> None:
    rc = main(
        [
            "--config",
            str(tmp_path / "nope.yaml"),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
        ]
    )
    assert rc == 2


def test_not_implemented_subcommand_returns_2(tmp_path: Path, sample_lab_config_yaml: Path) -> None:
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "correlate",
            "EXP001",
        ]
    )
    assert rc == 2


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    # ``--version`` short-circuits before configuration is loaded, so it
    # must succeed even when --config is missing.
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "c2forensics" in out


# ---------------------------------------------------------------------------
# Phase 2: pcap subcommand
# ---------------------------------------------------------------------------


def test_pcap_acquire_succeeds(
    tmp_path: Path, sample_lab_config_yaml: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
        ]
    )
    assert rc == 0
    # Drain the init's stdout so the next call's JSON is read cleanly.
    capsys.readouterr()
    src = tmp_path / "source.pcap"
    src.write_bytes(b"some-fake-pcap")
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "pcap",
            "acquire",
            "EXP001",
            str(src),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["experiment_id"] == "EXP001"
    assert payload["sha256"]
    assert Path(payload["pcap_path"]).is_file()


def test_pcap_acquire_rejects_missing_source(
    tmp_path: Path, sample_lab_config_yaml: Path
) -> None:
    main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
        ]
    )
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "pcap",
            "acquire",
            "EXP001",
            str(tmp_path / "missing.pcap"),
        ]
    )
    assert rc == 2


def test_pcap_acquire_refuses_overwrite(
    tmp_path: Path, sample_lab_config_yaml: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
        ]
    )
    capsys.readouterr()
    src1 = tmp_path / "a.pcap"
    src1.write_bytes(b"first")
    src2 = tmp_path / "b.pcap"
    src2.write_bytes(b"second")
    main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "pcap",
            "acquire",
            "EXP001",
            str(src1),
        ]
    )
    capsys.readouterr()
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "pcap",
            "acquire",
            "EXP001",
            str(src2),
        ]
    )
    assert rc == 2


def test_pcap_extract_without_pcap(
    tmp_path: Path, sample_lab_config_yaml: Path
) -> None:
    main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
        ]
    )
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "pcap",
            "extract",
            "EXP001",
        ]
    )
    assert rc == 2


# ---------------------------------------------------------------------------
# Phase 3: memory subcommand
# ---------------------------------------------------------------------------


def test_memory_acquire_succeeds(
    tmp_path: Path, sample_lab_config_yaml: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
        ]
    )
    assert rc == 0
    capsys.readouterr()
    src = tmp_path / "mem.raw"
    src.write_bytes(b"some-memory-bytes")
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "memory",
            "acquire",
            "EXP001",
            str(src),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["experiment_id"] == "EXP001"
    assert payload["sha256"]
    assert Path(payload["image_path"]).is_file()


def test_memory_acquire_rejects_missing_source(
    tmp_path: Path, sample_lab_config_yaml: Path
) -> None:
    main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
        ]
    )
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "memory",
            "acquire",
            "EXP001",
            str(tmp_path / "missing.raw"),
        ]
    )
    assert rc == 2


def test_memory_acquire_refuses_overwrite(
    tmp_path: Path, sample_lab_config_yaml: Path
) -> None:
    main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
        ]
    )
    src1 = tmp_path / "src.raw"
    src1.write_bytes(b"first")
    main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "memory",
            "acquire",
            "EXP001",
            str(src1),
        ]
    )
    # A second acquire of the same source name must fail.
    src1_again = tmp_path / "src.raw"
    src1_again.write_bytes(b"first-modified")
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "memory",
            "acquire",
            "EXP001",
            str(src1_again),
        ]
    )
    assert rc == 2


def test_memory_extract_without_image(
    tmp_path: Path, sample_lab_config_yaml: Path
) -> None:
    main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
        ]
    )
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "memory",
            "extract",
            "EXP001",
        ]
    )
    assert rc == 2


def test_memory_status_empty(
    tmp_path: Path, sample_lab_config_yaml: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "init",
            "EXP001",
        ]
    )
    capsys.readouterr()
    rc = main(
        [
            "--config",
            str(sample_lab_config_yaml),
            "--repo-root",
            str(tmp_path),
            "memory",
            "status",
            "EXP001",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["images"] == []
    assert payload["latest_extraction"] is None
