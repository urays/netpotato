"""Main CLI for NetPotato."""

from __future__ import annotations

import argparse
from dataclasses import replace
import sys

from .config import NetpotatoConfig, default_config
from .runtime import launch_command, print_status, watch_test_status


EPILOG = """examples:
  netpotato
  netpotato --status
  netpotato --check="change"
  netpotato --check="mismatch"
  netpotato --check="quality"
  netpotato --check="change,mismatch"
  netpotato claude
    equivalent to: netpotato --check="change" claude
  netpotato --check="change" claude
  netpotato --check="change,mismatch" codex --version
"""

DEFAULT_STATUS_LIMIT = 20

CHECK_SELECTOR_FIELDS = {
    "change": "check_ip_change",
    "mismatch": "check_ip_mismatch",
    "quality": "ip_quality_enabled",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netpotato",
        description=(
            "Run selected IP checks in test mode, or protect an app with those checks."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show recent guarded sessions.",
    )
    parser.add_argument(
        "--check",
        action="append",
        default=None,
        metavar="LIST",
        help=(
            "Comma-separated checks to enable: change, mismatch, quality. "
            "Without an app, runs the selected checks in test mode."
        ),
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Optional app command to protect. If omitted, selected checks run in test mode.",
    )
    return parser


def parse_selected_checks(raw_values: list[str] | None) -> list[str]:
    selected_checks: list[str] = []
    supported_names = ", ".join(CHECK_SELECTOR_FIELDS)
    for raw_value in raw_values or []:
        for chunk in raw_value.split(","):
            check_name = chunk.strip().lower()
            if not check_name:
                raise ValueError("--check requires one or more names such as change,mismatch.")
            if check_name not in CHECK_SELECTOR_FIELDS:
                raise ValueError(
                    f"Unsupported check {check_name!r}. Supported checks: {supported_names}."
                )
            if check_name not in selected_checks:
                selected_checks.append(check_name)
    return selected_checks


def config_from_selected_checks(selected_checks: list[str]) -> NetpotatoConfig:
    config = default_config()
    updates: dict[str, object] = {}

    if selected_checks:
        updates["check_ip_change"] = False
        updates["check_ip_mismatch"] = False
        updates["ip_quality_enabled"] = False
        for check_name in selected_checks:
            updates[CHECK_SELECTOR_FIELDS[check_name]] = True

    return replace(config, **updates)


def app_config_from_selected_checks(selected_checks: list[str]) -> NetpotatoConfig:
    # CLI app mode should launch immediately so short-lived commands do not stall in startup preflight.
    return replace(
        config_from_selected_checks(selected_checks),
        startup_fail_closed=False,
    )


def default_app_config() -> NetpotatoConfig:
    # App mode defaults to the lightest guard and launches immediately unless the user opts into more checks.
    return replace(
        default_config(),
        check_ip_change=True,
        check_ip_mismatch=False,
        ip_quality_enabled=False,
        startup_fail_closed=False,
    )


def normalize_command(argv: list[str]) -> list[str]:
    if argv and argv[0] == "--":
        return argv[1:]
    return argv


def print_cli_error(parser: argparse.ArgumentParser, message: str) -> int:
    parser.print_usage(sys.stderr)
    print(f"netpotato: error: {message}", file=sys.stderr)
    return 2


def run_cli(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(argv)
    command = normalize_command(args.command)
    try:
        selected_checks = parse_selected_checks(args.check)
    except ValueError as exc:
        return print_cli_error(parser, str(exc))

    if args.status:
        if selected_checks:
            return print_cli_error(parser, "--status cannot be combined with --check.")
        if command:
            return print_cli_error(parser, "--status cannot be combined with an app command.")
        return print_status(default_config(), limit=DEFAULT_STATUS_LIMIT)

    if command:
        config = app_config_from_selected_checks(selected_checks) if selected_checks else default_app_config()
        return launch_command(config, command)

    if selected_checks:
        config = config_from_selected_checks(selected_checks)
        return watch_test_status(config)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
