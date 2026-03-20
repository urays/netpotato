"""Main CLI for NetPotato."""

from __future__ import annotations

import argparse
from dataclasses import replace
import sys

from .config import default_config, expand_path
from .runtime import launch_command, print_status, watch_test_status


HELP_TEXT = """usage: netpotato [guard-options] <app> [args...]
       netpotato status [--limit N] [--state-dir PATH]
       netpotato test [guard-options]

Built-in commands: status, test.
Any other invocation is treated as the app to guard.

examples:
  netpotato codex
  netpotato --startup-fail-open python3 my_script.py
  netpotato test --interval 2
  netpotato status --limit 50
"""


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be >= 1")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be > 0")
    return parsed


def add_guard_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--interval", dest="interval_sec", type=positive_float, help="Seconds between guard checks.")
    parser.add_argument("--timeout", dest="timeout_sec", type=positive_float, help="Probe timeout in seconds.")
    parser.add_argument("--probe-url", help="Primary probe page used to discover public IP data.")
    parser.add_argument("--notify-command", help="Shell command executed when guard events fire.")
    parser.add_argument(
        "--bad-samples-to-block",
        dest="bad_samples_to_block",
        type=positive_int,
        help="How many consecutive blocking samples are required before freezing the app.",
    )
    parser.add_argument(
        "--inconclusive-samples-to-block",
        dest="inconclusive_samples_to_block",
        type=positive_int,
        help="How many consecutive inconclusive samples are required before blocking when --on-ip-mismatch=block.",
    )
    parser.add_argument(
        "--preflight-good-samples",
        dest="preflight_good_samples",
        type=positive_int,
        help="Healthy samples required before launch when startup fail-closed is enabled.",
    )
    parser.add_argument(
        "--recover-good-samples",
        dest="recover_good_samples",
        type=positive_int,
        help="Healthy samples required before resuming a blocked app.",
    )
    parser.add_argument(
        "--on-ip-change",
        choices=("block", "notify"),
        help="Action to take when the observed public IP differs from the session baseline.",
    )
    parser.add_argument(
        "--on-ip-mismatch",
        choices=("block", "notify"),
        help="Action to take when probe views are incomplete or disagree. Default is notify so inconclusive probes degrade instead of freezing.",
    )
    parser.add_argument(
        "--on-ip-quality",
        choices=("block", "notify"),
        help="Action to take when the startup or session IP is flagged as risky by Scamalytics.",
    )
    parser.add_argument(
        "--ip-quality-max-score",
        dest="ip_quality_max_score",
        type=positive_int,
        help="Block or warn when the Scamalytics fraud score is at or above this value.",
    )
    parser.add_argument(
        "--on-probe-failure",
        choices=("block", "notify"),
        help="Action to take when probe collection fails outright.",
    )
    parser.add_argument(
        "--ip-quality-check",
        dest="ip_quality_enabled",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable the Scamalytics IP quality lookup.",
    )
    parser.add_argument(
        "--ip-quality-block-proxy",
        dest="ip_quality_block_proxy",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Treat Scamalytics proxy/VPN/Tor findings as unsafe.",
    )
    startup_group = parser.add_mutually_exclusive_group()
    startup_group.add_argument(
        "--startup-fail-closed",
        dest="startup_fail_closed",
        action="store_true",
        help="Wait for a stable baseline IP before launching the protected app.",
    )
    startup_group.add_argument(
        "--startup-fail-open",
        dest="startup_fail_closed",
        action="store_false",
        help="Launch immediately and establish the baseline after startup.",
    )
    parser.set_defaults(startup_fail_closed=None)
    parser.add_argument(
        "--block-descendants",
        dest="block_descendants",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Whether freeze/unfreeze should include descendant processes.",
    )
    parser.add_argument("--state-dir", help="Directory where session state is stored.")


def config_from_args(args: argparse.Namespace):
    config = default_config()
    updates: dict[str, object] = {}

    for field_name in (
        "interval_sec",
        "timeout_sec",
        "probe_url",
        "notify_command",
        "bad_samples_to_block",
        "inconclusive_samples_to_block",
        "preflight_good_samples",
        "recover_good_samples",
        "startup_fail_closed",
        "ip_quality_enabled",
        "ip_quality_max_score",
        "ip_quality_block_proxy",
        "on_ip_change",
        "on_ip_mismatch",
        "on_ip_quality",
        "on_probe_failure",
        "block_descendants",
    ):
        value = getattr(args, field_name, None)
        if value is not None:
            updates[field_name] = value

    state_dir = getattr(args, "state_dir", None)
    if state_dir is not None:
        updates["state_dir"] = expand_path(state_dir)

    return replace(config, **updates)


def build_status_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netpotato status", description="Show recent guarded sessions.")
    parser.add_argument("--limit", type=positive_int, default=20, help="Maximum number of sessions to show.")
    parser.add_argument("--state-dir", help="Directory where session state is stored.")
    return parser


def build_test_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netpotato test", description="Print the live IP probe status.")
    add_guard_args(parser)
    return parser


def build_app_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netpotato",
        description="Guard a CLI process against unsafe public-IP changes.",
    )
    add_guard_args(parser)
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to launch under supervision.")
    return parser


def normalize_command(argv: list[str]) -> list[str]:
    if argv and argv[0] == "--":
        return argv[1:]
    return argv


def run_cli(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv:
        print(HELP_TEXT)
        return 2
    if argv[0] in {"-h", "--help", "help"}:
        print(HELP_TEXT)
        return 0

    if argv[0] == "status":
        args = build_status_parser().parse_args(argv[1:])
        return print_status(config_from_args(args), limit=args.limit)

    if argv[0] == "test":
        args = build_test_parser().parse_args(argv[1:])
        return watch_test_status(config_from_args(args))

    args = build_app_parser().parse_args(argv)
    command = normalize_command(args.command)
    if not command:
        print(HELP_TEXT)
        return 2
    return launch_command(config_from_args(args), command)


if __name__ == "__main__":
    raise SystemExit(run_cli())
