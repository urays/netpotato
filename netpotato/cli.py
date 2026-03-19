"""Main CLI for NetPotato."""

from __future__ import annotations

import argparse
import sys

from .config import default_config
from .runtime import launch_command, print_status, watch_test_status


HELP_TEXT = """usage: netpotato <app> [args...]
       netpotato status [--limit N]
       netpotato test

Built-in commands: status, test.
Any other invocation is treated as the app to guard.

examples:
  netpotato app_name
  netpotato python3 my_script.py
  netpotato test
  netpotato status
"""


def parse_global_args(argv: list[str]) -> list[str]:
    index = 0

    while index < len(argv):
        token = argv[index]
        if token in {"-h", "--help", "help"}:
            print(HELP_TEXT)
            raise SystemExit(0)
        if token.startswith("-"):
            raise ValueError(f"Unknown option: {token}")
        return argv[index:]

    return []


def build_status_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netpotato status", description="Show recent guarded sessions.")
    parser.add_argument("--limit", type=int, default=20, help="Maximum number of sessions to show.")
    return parser


def build_test_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(prog="netpotato test", description="Print the live IP probe status.")


def run_cli(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        remaining = parse_global_args(argv)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    config = default_config()

    if remaining and remaining[0] == "test":
        build_test_parser().parse_args(remaining[1:])
        return watch_test_status(config)

    if not remaining:
        print(HELP_TEXT)
        return 2

    if remaining[0] == "status":
        args = build_status_parser().parse_args(remaining[1:])
        return print_status(config, limit=args.limit)

    return launch_command(config, remaining)


if __name__ == "__main__":
    raise SystemExit(run_cli())
