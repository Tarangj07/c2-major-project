"""Command-line interface for the forensic framework.

The CLI is intentionally built on ``argparse`` rather than on Click or
Typer. The framework's command surface is small and stability matters
more than ergonomic decoration; staying on the stdlib keeps the
dependency surface minimal.

Subcommands are added by the phase that implements them. Phase 1 only
exposes ``init`` and ``show``; later phases will register
``pcap extract``, ``memory extract``, ``correlate``, ``reconstruct``,
``timeline``, ``evaluate``, and the top-level ``analyze`` aggregator.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from c2forensics import __version__
from c2forensics.config import LabConfig, load_config
from c2forensics.errors import (
    C2ForensicsError,
    ConfigError,
    ExperimentNotFoundError,
    NotImplementedByPhaseError,
)
from c2forensics.experiment import (
    init_experiment,
    read_metadata,
)
from c2forensics.logging import configure_logging, get_logger
from c2forensics.paths import ExperimentPaths

_logger = get_logger("c2forensics.cli")

DEFAULT_CONFIG_PATH = "config/lab.yaml"


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _add_config_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(DEFAULT_CONFIG_PATH),
        help="Path to the lab YAML configuration. Defaults to config/lab.yaml.",
    )


def _add_repo_root_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help=(
            "Path to the repository root. Defaults to the parent directory "
            "of the config file (config/lab.yaml -> <repo>/config/lab.yaml)."
        ),
    )


def _add_log_level_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--log-level",
        default=os.environ.get("C2FORENSICS_LOG_LEVEL", "INFO"),
        help="Log level (DEBUG, INFO, WARNING, ERROR). Default: INFO.",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser.

    Exposed as a public function so that tests can introspect the parser
    without invoking ``main``.
    """
    parser = argparse.ArgumentParser(
        prog="c2forensics",
        description=(
            "Encrypted C2 Forensic Reconstruction Framework. "
            "Defensive digital-forensics research tool for controlled "
            "laboratory experiments."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"c2forensics {__version__}",
    )
    _add_log_level_arg(parser)
    _add_config_arg(parser)
    _add_repo_root_arg(parser)

    sub = parser.add_subparsers(dest="command", required=True)

    # --- init ---------------------------------------------------------------
    p_init = sub.add_parser(
        "init",
        help="Create a new experiment directory and metadata.",
    )
    p_init.add_argument(
        "experiment_id",
        help="Experiment ID. Used as the directory name under experiments/.",
    )
    p_init.add_argument(
        "--description",
        default="",
        help="Human-readable description of the experiment.",
    )
    p_init.add_argument("--target-host", default=None)
    p_init.add_argument("--c2-server-host", default=None)
    p_init.add_argument(
        "--c2-server-port",
        type=int,
        default=None,
        help="TCP port of the C2 server (1-65535).",
    )
    p_init.add_argument(
        "--tag",
        action="append",
        default=[],
        help="Free-form tag. May be passed multiple times.",
    )
    p_init.set_defaults(func=_cmd_init)

    # --- show ---------------------------------------------------------------
    p_show = sub.add_parser(
        "show",
        help="Print the metadata of an existing experiment as JSON.",
    )
    p_show.add_argument("experiment_id")
    p_show.set_defaults(func=_cmd_show)

    # --- pcap ---------------------------------------------------------------
    p_pcap = sub.add_parser(
        "pcap",
        help="PCAP acquisition and extraction (Phase 2).",
    )
    pcap_sub = p_pcap.add_subparsers(dest="pcap_command", required=True)

    p_pcap_acquire = pcap_sub.add_parser(
        "acquire",
        help="Copy a PCAP into the experiment's raw/ directory and hash it.",
    )
    p_pcap_acquire.add_argument("experiment_id")
    p_pcap_acquire.add_argument(
        "source",
        type=Path,
        help="Path to the source PCAP file on disk.",
    )
    p_pcap_acquire.set_defaults(func=_cmd_pcap_acquire)

    p_pcap_extract = pcap_sub.add_parser(
        "extract",
        help="Run the PCAP extractor and write network-evidence.json.",
    )
    p_pcap_extract.add_argument("experiment_id")
    p_pcap_extract.set_defaults(func=_cmd_pcap_extract)

    # --- memory ------------------------------------------------------------
    p_mem = sub.add_parser(
        "memory",
        help="Memory-image acquisition and extraction (Phase 3).",
    )
    mem_sub = p_mem.add_subparsers(dest="memory_command", required=True)

    p_mem_acquire = mem_sub.add_parser(
        "acquire",
        help="Copy a memory image into the experiment's raw/memory/ directory and hash it.",
    )
    p_mem_acquire.add_argument("experiment_id")
    p_mem_acquire.add_argument(
        "source",
        type=Path,
        help="Path to the source memory image on disk.",
    )
    p_mem_acquire.add_argument(
        "--dest-name",
        default=None,
        help="Override the destination file name (default: source file name).",
    )
    p_mem_acquire.set_defaults(func=_cmd_memory_acquire)

    p_mem_extract = mem_sub.add_parser(
        "extract",
        help="Run the memory extractor and write the memory-result bundle.",
    )
    p_mem_extract.add_argument("experiment_id")
    p_mem_extract.set_defaults(func=_cmd_memory_extract)

    p_mem_status = mem_sub.add_parser(
        "status",
        help="Show the on-disk memory images and the latest extraction result.",
    )
    p_mem_status.add_argument("experiment_id")
    p_mem_status.set_defaults(func=_cmd_memory_status)

    # --- placeholders for later phases -------------------------------------
    for name, help_text in (
        ("normalize", "Evidence normalization (Phase 2/3)."),
        ("correlate", "Correlation (Phase 4)."),
        ("reconstruct", "Reconstruction (Phase 5)."),
        ("timeline", "Timeline (Phase 6)."),
        ("evaluate", "Evaluation (Phase 7)."),
        ("analyze", "End-to-end pipeline (Phase 2+)."),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("experiment_id")
        p.set_defaults(func=_cmd_not_implemented)
    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_repo_root(args: argparse.Namespace, config: LabConfig) -> Path:
    if args.repo_root is not None:
        return args.repo_root.expanduser().resolve()
    return config.repo_root


def _load_config_or_die(args: argparse.Namespace) -> LabConfig:
    try:
        return load_config(args.config)
    except FileNotFoundError as exc:
        raise ConfigError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------


def _cmd_init(args: argparse.Namespace) -> int:
    config = _load_config_or_die(args)
    repo_root = _resolve_repo_root(args, config)
    snapshot = config.snapshot()
    try:
        paths = init_experiment(
            repo_root=repo_root,
            experiment_id=args.experiment_id,
            description=args.description,
            target_host=args.target_host or config.lab.target_host,
            c2_server_host=args.c2_server_host or config.lab.c2_server_host,
            c2_server_port=args.c2_server_port or config.lab.c2_server_port,
            config_snapshot=snapshot,
            tags=args.tag,
        )
    except ValueError as exc:
        raise C2ForensicsError(str(exc)) from exc
    print(json.dumps({"experiment_dir": str(paths.root)}, indent=2))
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    config = _load_config_or_die(args)
    repo_root = _resolve_repo_root(args, config)
    paths = ExperimentPaths.for_experiment(repo_root, args.experiment_id)
    if not paths.metadata_file.is_file():
        raise ExperimentNotFoundError(
            f"experiment {args.experiment_id!r} is not initialised at {paths.root}"
        )
    metadata = read_metadata(paths)
    print(metadata.model_dump_json(indent=2))
    return 0


def _cmd_not_implemented(args: argparse.Namespace) -> int:  # pragma: no cover
    raise NotImplementedByPhaseError(
        f"subcommand {args.command!r} is not implemented in this phase"
    )


def _cmd_pcap_acquire(args: argparse.Namespace) -> int:
    from c2forensics.acquisition import acquire_pcap
    from c2forensics.errors import ExperimentNotFoundError

    config = _load_config_or_die(args)
    repo_root = _resolve_repo_root(args, config)
    paths = ExperimentPaths.for_experiment(repo_root, args.experiment_id)
    if not paths.metadata_file.is_file():
        raise ExperimentNotFoundError(
            f"experiment {args.experiment_id!r} is not initialised at {paths.root}"
        )
    digest = acquire_pcap(paths, args.source)
    print(
        json.dumps(
            {
                "experiment_id": args.experiment_id,
                "pcap_path": str(paths.raw / "capture.pcap"),
                "sha256": digest,
            },
            indent=2,
        )
    )
    return 0


def _cmd_pcap_extract(args: argparse.Namespace) -> int:
    from c2forensics.errors import ExperimentNotFoundError
    from c2forensics.extraction.pcap import extract_pcap

    config = _load_config_or_die(args)
    repo_root = _resolve_repo_root(args, config)
    paths = ExperimentPaths.for_experiment(repo_root, args.experiment_id)
    if not paths.metadata_file.is_file():
        raise ExperimentNotFoundError(
            f"experiment {args.experiment_id!r} is not initialised at {paths.root}"
        )
    bundle = extract_pcap(paths, config)
    summary = {
        "experiment_id": bundle.experiment_id,
        "pcap_sha256": bundle.pcap_sha256,
        "extractor_version": bundle.extractor_version,
        "flows": len(bundle.flows),
        "tcp_lifecycle_events": len(bundle.tcp_lifecycle),
        "tls_observations": len(bundle.tls_observations),
        "output": str(paths.extracted / "network-evidence.json"),
    }
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_memory_acquire(args: argparse.Namespace) -> int:
    from c2forensics.acquisition import acquire_memory_image
    from c2forensics.errors import ExperimentNotFoundError

    config = _load_config_or_die(args)
    repo_root = _resolve_repo_root(args, config)
    paths = ExperimentPaths.for_experiment(repo_root, args.experiment_id)
    if not paths.metadata_file.is_file():
        raise ExperimentNotFoundError(
            f"experiment {args.experiment_id!r} is not initialised at {paths.root}"
        )
    digest = acquire_memory_image(
        paths, args.source, dest_name=args.dest_name
    )
    # The on-disk path is determined by acquire_memory_image; the
    # operator used ``--dest-name`` only when supplied.
    from c2forensics.acquisition.memory import list_acquired_images

    images = list_acquired_images(paths)
    on_disk = images[-1] if images else paths.memory / args.source.name
    print(
        json.dumps(
            {
                "experiment_id": args.experiment_id,
                "image_path": str(on_disk),
                "sha256": digest,
            },
            indent=2,
        )
    )
    return 0


def _cmd_memory_extract(args: argparse.Namespace) -> int:
    from c2forensics.errors import ExperimentNotFoundError
    from c2forensics.extraction.memory import extract_memory

    config = _load_config_or_die(args)
    repo_root = _resolve_repo_root(args, config)
    paths = ExperimentPaths.for_experiment(repo_root, args.experiment_id)
    if not paths.metadata_file.is_file():
        raise ExperimentNotFoundError(
            f"experiment {args.experiment_id!r} is not initialised at {paths.root}"
        )
    result = extract_memory(paths, config)
    summary = {
        "experiment_id": result.experiment_id,
        "extractor_version": result.extractor_version,
        "platform": result.platform,
        "images": [r.path for r in result.images],
        "processes": len(result.processes),
        "sockets": len(result.sockets),
        "tls_artifacts": len(result.tls_artifacts),
        "plugin_status": result.plugin_status,
        "output": str(paths.extracted / "memory-result.json"),
    }
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_memory_status(args: argparse.Namespace) -> int:
    from c2forensics.acquisition import list_acquired_images
    from c2forensics.errors import ExperimentNotFoundError
    from c2forensics.extraction.memory import load_extracted_result

    config = _load_config_or_die(args)
    repo_root = _resolve_repo_root(args, config)
    paths = ExperimentPaths.for_experiment(repo_root, args.experiment_id)
    if not paths.metadata_file.is_file():
        raise ExperimentNotFoundError(
            f"experiment {args.experiment_id!r} is not initialised at {paths.root}"
        )
    images = list_acquired_images(paths)
    out: dict[str, object] = {
        "experiment_id": args.experiment_id,
        "images": [str(p) for p in images],
    }
    try:
        result = load_extracted_result(paths)
        out["latest_extraction"] = {
            "extractor_version": result.extractor_version,
            "extracted_at": result.extracted_at.isoformat(),
            "platform": result.platform,
            "processes": len(result.processes),
            "sockets": len(result.sockets),
            "tls_artifacts": len(result.tls_artifacts),
            "plugin_status": result.plugin_status,
        }
    except Exception as exc:  # noqa: BLE001 - status must not crash
        out["latest_extraction"] = None
        out["latest_extraction_error"] = str(exc)
    print(json.dumps(out, indent=2))
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point registered in ``pyproject.toml`` as ``c2forensics``."""
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(level=args.log_level)
    try:
        return int(args.func(args))
    except C2ForensicsError as exc:
        _logger.error("command failed", extra={"error": str(exc), "type": type(exc).__name__})
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        _logger.warning("interrupted by user")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


# Quiet an unused-import warning for ``Any`` while keeping it available for
# future subcommand additions.
_ = Any
