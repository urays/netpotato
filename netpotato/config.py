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
    interval_sec: float = 1
    timeout_sec: float = 10
    probe_url: str = DEFAULT_PROBE_URL
    notify_command: str | None = None
    bad_samples_to_block: int = 1
    inconclusive_samples_to_block: int = 3
    preflight_good_samples: int = 2
    recover_good_samples: int = 2
    backend: str = "freeze"
    startup_fail_closed: bool = True
    check_ip_change: bool = True
    check_ip_mismatch: bool = True
    ip_quality_enabled: bool = True
    ip_quality_max_score: int = 70
    ip_quality_block_proxy: bool = True
    on_ip_change: str = "block"
    on_ip_mismatch: str = "notify"
    on_ip_quality: str = "block"
    on_probe_failure: str = "notify"
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
        if not resolved.is_file():
            raise FileNotFoundError(f"Executable is not a file: {resolved}")
        if not os.access(resolved, os.X_OK):
            raise PermissionError(f"Executable is not runnable: {resolved}")
        return [str(resolved), *command[1:]]

    resolved_exec = shutil.which(executable)
    if not resolved_exec:
        raise FileNotFoundError(f"Could not resolve executable {executable!r} from PATH.")
    return [resolved_exec, *command[1:]]
