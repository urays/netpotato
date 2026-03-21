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
  netpotato --check="change,mismatch"
  netpotato claude
    best-effort change monitoring, plus automatic IP quality gates
  netpotato --fail-closed claude
  netpotato --check="change" claude
  netpotato --check="change,mismatch" codex --version

app mode runs an IP quality gate before launch and once for each newly observed IP.
"""

DEFAULT_STATUS_LIMIT = 20

CHECK_SELECTOR_FIELDS = {
    "change": "check_ip_change",
    "mismatch": "check_ip_mismatch",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netpotato",
        description=(
            "Run selected runtime IP checks in test mode, or protect an app with "
            "those checks plus a startup IP quality gate."
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
            "Comma-separated runtime checks to enable: change, mismatch. "
            "Without an app, runs the selected checks in test mode."
        ),
    )
    launch_mode_group = parser.add_mutually_exclusive_group()
    launch_mode_group.add_argument(
        "--fail-closed",
        action="store_true",
        help="In app mode, wait for startup checks before launching the command.",
    )
    launch_mode_group.add_argument(
        "--best-effort",
        action="store_true",
        help="In app mode, launch immediately and establish the baseline in the background (default).",
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


def app_config_from_selected_checks(
    selected_checks: list[str],
    *,
    startup_fail_closed: bool,
) -> NetpotatoConfig:
    return replace(
        config_from_selected_checks(selected_checks),
        startup_fail_closed=startup_fail_closed,
    )


def default_app_config(*, startup_fail_closed: bool) -> NetpotatoConfig:
    # App mode always runs a startup IP quality gate before launch. The default
    # runtime guard is still the lightest change-only monitor.
    return replace(
        default_config(),
        check_ip_change=True,
        check_ip_mismatch=False,
        ip_quality_enabled=False,
        startup_fail_closed=startup_fail_closed,
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

    if not command and (args.fail_closed or args.best_effort):
        return print_cli_error(parser, "--fail-closed/--best-effort require an app command.")

    if command:
        startup_fail_closed = args.fail_closed
        config = (
            app_config_from_selected_checks(
                selected_checks,
                startup_fail_closed=startup_fail_closed,
            )
            if selected_checks
            else default_app_config(startup_fail_closed=startup_fail_closed)
        )
        return launch_command(config, command)

    if selected_checks:
        config = config_from_selected_checks(selected_checks)
        return watch_test_status(config)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
