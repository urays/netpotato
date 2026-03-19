"""Built-in defaults for NetPotato."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import shutil

from .probes import DEFAULT_PROBE_URL


def default_state_dir() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "netpotato"


def expand_path(value: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(value))).resolve()


@dataclass(frozen=True)
class NetpotatoConfig:
    interval_sec: float = 4.27
    timeout_sec: float = 10.0
    probe_url: str = DEFAULT_PROBE_URL
    notify_command: str | None = None
    bad_samples_to_block: int = 1
    good_samples_to_recover: int = 2
    backend: str = "freeze"
    on_ip_change: str = "block"
    on_ip_mismatch: str = "block"
    on_probe_failure: str = "notify"
    recovery_policy: str = "must_match_original_baseline"
    block_descendants: bool = True
    state_dir: Path = field(default_factory=default_state_dir)


def default_config() -> NetpotatoConfig:
    return NetpotatoConfig()


def resolve_command(command: list[str]) -> list[str]:
    if not command:
        raise ValueError("No command provided.")

    executable = command[0]
    if "/" in executable:
        resolved = expand_path(executable)
        if not resolved.exists():
            raise FileNotFoundError(f"Executable not found: {resolved}")
        return [str(resolved), *command[1:]]

    resolved_exec = shutil.which(executable)
    if not resolved_exec:
        raise FileNotFoundError(f"Could not resolve executable {executable!r} from PATH.")
    return [resolved_exec, *command[1:]]
