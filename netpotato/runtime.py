"""Session runtime for guarded applications."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import queue
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Optional
import uuid

from .config import NetpotatoConfig, resolve_command
from .probes import (
    Snapshot,
    fetch_ip_quality,
    fetch_snapshot,
    snapshot_change_ip,
    snapshot_consensus_ip,
    snapshot_diagnostics,
    snapshot_quality_reason,
    snapshot_summary,
)


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
EXIT_STARTUP_BLOCKED = 3
EXIT_LAUNCH_ERROR = 4
DEFAULT_CGROUP_ROOT = Path("/sys/fs/cgroup")
MOCK_CGROUP_MARKER = ".netpotato-mock-cgroup"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, PRIVATE_DIR_MODE)
    except OSError:
        pass


def sync_directory(path: Path) -> None:
    try:
        directory_fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        pass
    finally:
        os.close(directory_fd)


def write_text_atomic(path: Path, text: str) -> None:
    ensure_dir(path.parent)
    temp_path: Optional[Path] = None
    fd, raw_temp_path = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    try:
        temp_path = Path(raw_temp_path)
        try:
            os.fchmod(fd, PRIVATE_FILE_MODE)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        sync_directory(path.parent)
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def read_proc_identity(pid: int) -> Optional[tuple[int, int]]:
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None
    try:
        _prefix, suffix = stat_text.rsplit(") ", 1)
        parts = suffix.split()
        return int(parts[1]), int(parts[19])
    except (ValueError, IndexError):
        return None


def process_start_ticks(pid: Optional[int]) -> Optional[int]:
    if not pid:
        return None
    identity = read_proc_identity(pid)
    if identity is None:
        return None
    return identity[1]


def setup_file_logging(log_file: Path) -> None:
    ensure_dir(log_file.parent)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    try:
        os.chmod(log_file, PRIVATE_FILE_MODE)
    except OSError:
        pass
    handlers: list[logging.Handler] = [file_handler]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
        force=True,
    )


def write_json(path: Path, payload: dict[str, Any]) -> None:
    write_text_atomic(path, json.dumps(payload, ensure_ascii=False, indent=2))


@dataclass
class SessionRecord:
    session_id: str
    app_name: str
    backend: str
    started_at: str
    cwd: str
    argv: list[str]
    child_pid: Optional[int] = None
    child_start_ticks: Optional[int] = None
    supervisor_pid: int = field(default_factory=os.getpid)
    supervisor_start_ticks: Optional[int] = field(
        default_factory=lambda: process_start_ticks(os.getpid())
    )
    state: str = "starting"
    blocked: bool = False
    baseline_ip: Optional[str] = None
    block_reason: Optional[str] = None
    last_check_at: Optional[str] = None
    last_event: Optional[str] = None
    last_snapshot: Optional[dict[str, Any]] = None
    last_error: Optional[str] = None
    ip_mismatch_count: int = 0
    ip_change_count: int = 0
    ip_quality_issue_count: int = 0
    session_dir: str = ""
    log_file: str = ""
    child_exit_code: Optional[int] = None
    ended_at: Optional[str] = None


@dataclass
class MonitorState:
    record: SessionRecord
    baseline_ip: Optional[str] = None
    blocked: bool = False
    bad_streak: int = 0
    good_streak: int = 0
    last_error: Optional[str] = None
    last_snapshot: Optional[Snapshot] = None
    last_transition: Optional[str] = None
    mismatch_active: bool = False
    change_active: bool = False
    quality_active: bool = False
    inconclusive_streak: int = 0
    quality_checked_ip: Optional[str] = None
    quality_approved_ip: Optional[str] = None
    quality_blocked_ip: Optional[str] = None
    quality_reason: Optional[str] = None
    quality_gate_required: bool = False


@dataclass
class Evaluation:
    classification: str
    healthy_sample: bool
    should_block: bool
    should_block_inconclusive: bool
    reasons: list[str]
    observed_baseline: Optional[str]
    has_ip_mismatch: bool
    has_required_probe_failure: bool
    has_ip_change: bool
    has_poor_ip_quality: bool


@dataclass(frozen=True)
class QualityCheckResult:
    ip: Optional[str]
    verdict: str
    reason: Optional[str] = None


class StartupGuardError(RuntimeError):
    """Raised when startup checks determine the app should not launch."""


def use_direct_ip_probe(config: NetpotatoConfig) -> bool:
    # The IP-change-only path can avoid the heavier multi-vantage HTML probe flow.
    return config.check_ip_change and not config.check_ip_mismatch and not config.ip_quality_enabled


def monitor_baseline_samples(config: NetpotatoConfig) -> int:
    if config.startup_fail_closed:
        return config.preflight_good_samples
    return 1


def session_root(config: NetpotatoConfig) -> Path:
    return config.state_dir / "sessions"


def iter_sessions(config: NetpotatoConfig) -> list[Path]:
    root = session_root(config)
    if not root.exists():
        return []
    return sorted([path for path in root.iterdir() if path.is_dir()], reverse=True)


def is_pid_running(pid: Optional[int], expected_start_ticks: Optional[int] = None) -> bool:
    if not pid:
        return False
    identity = read_proc_identity(pid)
    if identity is None:
        return False
    _ppid, start_ticks = identity
    if expected_start_ticks is not None and start_ticks != expected_start_ticks:
        return False
    return True


def read_proc_ppids() -> dict[int, int]:
    mapping: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        identity = read_proc_identity(int(entry.name))
        if identity is None:
            continue
        ppid, _start_ticks = identity
        mapping[int(entry.name)] = ppid
    return mapping


def descendants_of(root_pid: int) -> set[int]:
    mapping = read_proc_ppids()
    result: set[int] = set()
    frontier = [root_pid]
    while frontier:
        current = frontier.pop()
        for pid, ppid in mapping.items():
            if ppid != current or pid in result or pid == os.getpid():
                continue
            result.add(pid)
            frontier.append(pid)
    return result


def read_cgroup_relative_path(pid: int) -> Optional[str]:
    try:
        entries = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None

    for entry in entries:
        try:
            hierarchy, _controllers, relative_path = entry.split(":", 2)
        except ValueError:
            continue
        if hierarchy == "0":
            return relative_path or "/"
    return None


def cgroup_root() -> Path:
    override = os.environ.get("NETPOTATO_CGROUP_ROOT")
    return Path(override) if override else DEFAULT_CGROUP_ROOT


def resolve_cgroup_parent_dir(root: Path, relative_path: Optional[str]) -> Path:
    normalized = (relative_path or "/").lstrip("/")
    return root / normalized if normalized else root


def is_mock_cgroup_root(root: Path) -> bool:
    return (root / MOCK_CGROUP_MARKER).exists()


def ensure_mock_cgroup_files(path: Path) -> None:
    for filename in ("cgroup.freeze", "cgroup.procs"):
        control_file = path / filename
        if not control_file.exists():
            control_file.write_text("", encoding="utf-8")


class FreezeController:
    backend_name = "freeze"

    def __init__(self, root_pid: int, block_descendants: bool) -> None:
        self.root_pid = root_pid
        self.block_descendants = block_descendants
        self._stopped_pids: set[int] = set()

    def _process_group(self) -> Optional[int]:
        try:
            return os.getpgid(self.root_pid)
        except ProcessLookupError:
            return None

    def _target_pids(self) -> set[int]:
        targets = {self.root_pid}
        if self.block_descendants:
            targets.update(descendants_of(self.root_pid))
        return targets

    def block(self) -> None:
        self._stopped_pids = set(self._target_pids())
        pgid = self._process_group()
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGSTOP)
            except ProcessLookupError:
                pass
        for pid in sorted(self._stopped_pids, reverse=True):
            try:
                os.kill(pid, signal.SIGSTOP)
            except ProcessLookupError:
                continue
        logging.info("Freeze backend applied to app PID %s", self.root_pid)

    def unblock(self) -> None:
        targets = self._stopped_pids | self._target_pids()
        pgid = self._process_group()
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        for pid in sorted(targets):
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                continue
        self._stopped_pids.clear()
        logging.info("Freeze backend released for app PID %s", self.root_pid)

    def forward_signal(self, signum: int) -> None:
        termination_signals = {signal.SIGINT, signal.SIGTERM}
        if hasattr(signal, "SIGHUP"):
            termination_signals.add(signal.SIGHUP)
        if hasattr(signal, "SIGQUIT"):
            termination_signals.add(signal.SIGQUIT)

        if signum in termination_signals:
            self.unblock()
        targets = self._stopped_pids | self._target_pids()
        pgid = self._process_group()
        if pgid is not None:
            try:
                os.killpg(pgid, signum)
            except ProcessLookupError:
                pass
        for pid in sorted(targets):
            try:
                os.kill(pid, signum)
            except ProcessLookupError:
                continue

    def cleanup(self) -> None:
        return


class CgroupFreezeController(FreezeController):
    backend_name = "cgroup"

    def __init__(
        self,
        root_pid: int,
        block_descendants: bool,
        *,
        session_id: str,
        root: Optional[Path] = None,
    ) -> None:
        super().__init__(root_pid, block_descendants)
        self.cgroup_root = cgroup_root() if root is None else root
        self.relative_path = read_cgroup_relative_path(root_pid)
        self.parent_dir = resolve_cgroup_parent_dir(self.cgroup_root, self.relative_path)
        self.group_dir = self.parent_dir / f"netpotato-{session_id}"
        self.mock_mode = is_mock_cgroup_root(self.cgroup_root)
        self._activated = False
        self._setup_group()

    def _write_control_file(self, path: Path, value: str) -> None:
        path.write_text(value, encoding="utf-8")

    def _setup_group(self) -> None:
        if not self.parent_dir.exists():
            raise RuntimeError(f"cgroup parent does not exist: {self.parent_dir}")
        if self.mock_mode:
            ensure_mock_cgroup_files(self.parent_dir)

        self.group_dir.mkdir()
        if self.mock_mode:
            ensure_mock_cgroup_files(self.group_dir)

        freeze_file = self.group_dir / "cgroup.freeze"
        procs_file = self.group_dir / "cgroup.procs"
        if not freeze_file.exists() or not procs_file.exists():
            raise RuntimeError(f"cgroup.freeze unavailable under {self.group_dir}")

        try:
            self._write_control_file(procs_file, f"{self.root_pid}\n")
        except OSError as exc:
            raise RuntimeError(f"could not attach process to cgroup: {exc}") from exc
        self._activated = True
        logging.info("Cgroup backend attached app PID %s to %s", self.root_pid, self.group_dir)

    def block(self) -> None:
        if not self._activated:
            return
        try:
            self._write_control_file(self.group_dir / "cgroup.freeze", "1\n")
        except OSError as exc:
            raise RuntimeError(f"failed to freeze cgroup {self.group_dir}: {exc}") from exc
        logging.info("Cgroup backend froze %s", self.group_dir)

    def unblock(self) -> None:
        if not self._activated:
            return
        try:
            self._write_control_file(self.group_dir / "cgroup.freeze", "0\n")
        except OSError as exc:
            raise RuntimeError(f"failed to unfreeze cgroup {self.group_dir}: {exc}") from exc
        logging.info("Cgroup backend unfroze %s", self.group_dir)

    def cleanup(self) -> None:
        if not self._activated:
            return
        try:
            if is_pid_running(self.root_pid):
                self._write_control_file(self.parent_dir / "cgroup.procs", f"{self.root_pid}\n")
            if self.mock_mode:
                for filename in ("cgroup.freeze", "cgroup.procs"):
                    try:
                        (self.group_dir / filename).unlink()
                    except FileNotFoundError:
                        pass
            self.group_dir.rmdir()
        except OSError as exc:
            logging.debug("Could not clean up cgroup backend %s: %s", self.group_dir, exc)
        finally:
            self._activated = False


def create_process_controller(
    config: NetpotatoConfig,
    root_pid: int,
    *,
    session_id: str,
) -> FreezeController:
    requested_backend = (config.backend or "auto").lower()
    if requested_backend in {"auto", "cgroup"} and sys.platform.startswith("linux"):
        try:
            return CgroupFreezeController(
                root_pid,
                config.block_descendants,
                session_id=session_id,
            )
        except Exception as exc:  # noqa: BLE001
            logging.info("Cgroup backend unavailable, falling back to signal freeze: %s", exc)

    return FreezeController(root_pid, config.block_descendants)


@dataclass(frozen=True)
class NotificationTask:
    event: str
    title: str
    message: str
    session_id: str
    app_name: str


class NotificationDispatcher:
    def __init__(
        self,
        notify_command: Optional[str],
        *,
        timeout_sec: float,
        queue_size: int,
    ) -> None:
        self.notify_command = notify_command
        self.timeout_sec = timeout_sec
        self._queue: queue.Queue[NotificationTask | None] = queue.Queue(maxsize=queue_size)
        self._worker: Optional[threading.Thread] = None
        self._closed = False
        if notify_command:
            self._worker = threading.Thread(
                target=self._run,
                name="netpotato-notify",
                daemon=True,
            )
            self._worker.start()

    def submit(
        self,
        event: str,
        title: str,
        message: str,
        session: SessionRecord,
    ) -> None:
        logging.warning("%s\n%s", title, message)
        if not self.notify_command or self._closed:
            return
        task = NotificationTask(
            event=event,
            title=title,
            message=message,
            session_id=session.session_id,
            app_name=session.app_name,
        )
        try:
            self._queue.put_nowait(task)
        except queue.Full:
            logging.error("Dropping notification because the queue is full: %s", title)

    def _run(self) -> None:
        while True:
            task = self._queue.get()
            try:
                if task is None:
                    return
                execute_notify_command(
                    self.notify_command,
                    task,
                    timeout_sec=self.timeout_sec,
                )
            finally:
                self._queue.task_done()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._worker is None:
            return
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            logging.error("Notification queue is full during shutdown; abandoning pending hooks.")
            return
        self._worker.join(timeout=0.2)


def execute_notify_command(
    notify_command: Optional[str],
    task: NotificationTask,
    timeout_sec: float = 5,
) -> None:
    if not notify_command:
        return
    try:
        argv = shlex.split(notify_command)
    except ValueError as exc:
        logging.error("Failed to parse notify command: %s", exc)
        return
    if not argv:
        logging.error("Failed to execute notify command: command is empty.")
        return

    payload = json.dumps(
        {
            "event": task.event,
            "title": task.title,
            "message": task.message,
            "session_id": task.session_id,
            "app": task.app_name,
            "timestamp": now_iso(),
        },
        ensure_ascii=False,
    )
    env = os.environ.copy()
    env.update(
        {
            "NETPOTATO_EVENT": task.event,
            "NETPOTATO_TITLE": task.title,
            "NETPOTATO_MESSAGE": task.message,
            "NETPOTATO_PAYLOAD": payload,
            "NETPOTATO_SESSION_ID": task.session_id,
            "NETPOTATO_APP": task.app_name,
        }
    )
    try:
        completed = subprocess.run(
            argv,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        logging.error("Notify command timed out after %.1f seconds.", timeout_sec)
        return
    except OSError as exc:
        logging.error("Failed to execute notify command: %s", exc)
        return
    if completed.returncode != 0:
        logging.error(
            "Notify command exited with non-zero status %s: %s",
            completed.returncode,
            completed.stderr.strip() or "<no stderr>",
        )


def notify_once(
    dispatcher: NotificationDispatcher,
    state: MonitorState,
    event: str,
    title: str,
    message: str,
) -> None:
    key = f"{event}:{title}:{message}"
    if state.last_transition == key:
        return
    state.last_transition = key
    dispatcher.submit(
        event,
        title,
        message,
        state.record,
    )


def update_session_record(
    session_file: Path,
    record: SessionRecord,
    snapshot: Optional[Snapshot],
    error_message: Optional[str],
) -> None:
    record.last_check_at = now_iso()
    record.last_error = error_message
    record.last_snapshot = asdict(snapshot) if snapshot else None
    write_json(session_file, asdict(record))


def check_changed_ip_quality(
    snapshot: Snapshot,
    config: NetpotatoConfig,
    state: MonitorState,
    *,
    force: bool = False,
) -> QualityCheckResult:
    observed_ip = snapshot_change_ip(snapshot)
    if not observed_ip:
        return QualityCheckResult(ip=None, verdict="skipped")

    if not force and observed_ip == state.quality_checked_ip:
        if state.quality_blocked_ip == observed_ip and state.quality_reason:
            return QualityCheckResult(ip=observed_ip, verdict="fail", reason=state.quality_reason)
        if state.quality_approved_ip == observed_ip:
            return QualityCheckResult(ip=observed_ip, verdict="pass")
        return QualityCheckResult(ip=observed_ip, verdict="unknown")

    try:
        snapshot.ip_quality = fetch_ip_quality(observed_ip, config.timeout_sec)
        snapshot.ip_quality_error = None
    except Exception as exc:  # noqa: BLE001
        snapshot.ip_quality = None
        snapshot.ip_quality_error = str(exc)
        state.quality_checked_ip = observed_ip
        state.quality_approved_ip = None
        state.quality_blocked_ip = None
        state.quality_reason = None
        state.quality_active = False
        return QualityCheckResult(ip=observed_ip, verdict="unknown")

    quality_reason = snapshot_quality_reason(snapshot, config)
    state.quality_checked_ip = observed_ip
    if quality_reason is None:
        state.quality_approved_ip = observed_ip
        state.quality_blocked_ip = None
        state.quality_reason = None
        state.quality_active = False
        return QualityCheckResult(ip=observed_ip, verdict="pass")

    if state.quality_blocked_ip != observed_ip:
        state.record.ip_quality_issue_count += 1
    state.quality_approved_ip = None
    state.quality_blocked_ip = observed_ip
    state.quality_reason = quality_reason
    state.quality_active = True
    return QualityCheckResult(ip=observed_ip, verdict="fail", reason=quality_reason)


def evaluate_snapshot(
    snapshot: Snapshot,
    baseline_ip: Optional[str],
    config: NetpotatoConfig,
) -> Evaluation:
    reasons: list[str] = []
    should_block = False
    should_block_inconclusive = False
    diagnostics = snapshot_diagnostics(snapshot, sections=("foreign", "google"))
    remote_missing = any(not value for value in (snapshot.foreign, snapshot.google))
    remote_mismatch = snapshot.is_remote_mismatch()
    has_ip_mismatch = config.check_ip_mismatch and (remote_missing or remote_mismatch)
    has_required_probe_failure = config.check_ip_mismatch and remote_missing

    if config.check_ip_mismatch and remote_missing:
        reason = "probe results did not include all required IPs"
        if diagnostics:
            reason = f"{reason} ({'; '.join(diagnostics)})"
        reasons.append(reason)
    if config.check_ip_mismatch and remote_mismatch:
        reasons.append("probe results were inconsistent across vantage points")

    observed_baseline = snapshot_change_ip(snapshot)
    has_ip_change = bool(
        config.check_ip_change and baseline_ip and observed_baseline and observed_baseline != baseline_ip
    )
    classification = "healthy"
    quality_reason = snapshot_quality_reason(snapshot, config)
    has_poor_ip_quality = config.ip_quality_enabled and quality_reason is not None
    quality_check_missing = bool(
        config.ip_quality_enabled and observed_baseline and snapshot.ip_quality is None
    )
    if has_ip_change:
        reasons.append(f"observed public IP {observed_baseline} differs from baseline {baseline_ip}")
        classification = "unsafe"
        should_block = should_block or config.on_ip_change == "block"
    elif has_poor_ip_quality:
        reasons.append(quality_reason)
        classification = "unsafe"
        should_block = should_block or config.on_ip_quality == "block"
    elif quality_check_missing:
        classification = "inconclusive"
        reasons.append(
            "IP quality check did not return a usable result"
            if not snapshot.ip_quality_error
            else f"IP quality check failed ({snapshot.ip_quality_error})"
        )
    elif has_ip_mismatch:
        classification = "inconclusive"
        should_block_inconclusive = remote_missing
    elif observed_baseline is None and (config.check_ip_change or config.ip_quality_enabled):
        classification = "inconclusive"
        reasons.append("probe results could not establish a stable public IP")

    healthy_sample = classification == "healthy"

    return Evaluation(
        classification=classification,
        healthy_sample=healthy_sample,
        should_block=should_block,
        should_block_inconclusive=should_block_inconclusive,
        reasons=reasons,
        observed_baseline=observed_baseline,
        has_ip_mismatch=has_ip_mismatch,
        has_required_probe_failure=has_required_probe_failure,
        has_ip_change=has_ip_change,
        has_poor_ip_quality=has_poor_ip_quality,
    )


def update_incident_counts(state: MonitorState, evaluation: Evaluation) -> None:
    if evaluation.has_ip_mismatch and not state.mismatch_active:
        state.record.ip_mismatch_count += 1
    if evaluation.has_ip_change and not state.change_active:
        state.record.ip_change_count += 1
    state.mismatch_active = evaluation.has_ip_mismatch
    state.change_active = evaluation.has_ip_change


def quality_recovery_ready(
    observed_ip: Optional[str],
    evaluation: Evaluation,
    state: MonitorState,
    config: NetpotatoConfig,
) -> bool:
    _ = config
    return bool(
        evaluation.has_ip_change
        and observed_ip
        and state.quality_approved_ip == observed_ip
        and not evaluation.has_ip_mismatch
        and not evaluation.has_required_probe_failure
    )


def preflight_launch(command: list[str], session: SessionRecord) -> subprocess.Popen[Any]:
    resolved_command = resolve_command(command)
    env = os.environ.copy()
    env["NETPOTATO_SESSION_ID"] = session.session_id
    env["NETPOTATO_APP"] = session.app_name
    env["NETPOTATO_SUPERVISOR_PID"] = str(os.getpid())
    process = subprocess.Popen(
        resolved_command,
        cwd=session.cwd,
        env=env,
        start_new_session=True,
    )
    session.child_pid = process.pid
    session.child_start_ticks = process_start_ticks(process.pid)
    return process


def run_startup_quality_gate(
    app_name: str,
    config: NetpotatoConfig,
    state: MonitorState,
    session_file: Path,
    dispatcher: NotificationDispatcher,
) -> None:
    state.record.state = "preflight"
    state.record.blocked = False
    state.record.block_reason = None
    state.record.last_event = "startup_quality"
    update_session_record(session_file, state.record, None, state.last_error)
    logging.info("Starting startup IP quality gate for %s", app_name)

    try:
        snapshot = fetch_snapshot(
            config.probe_url,
            config.timeout_sec,
            quality_enabled=False,
            quality_ip_allow_partial=True,
            prefer_direct_ip=True,
        )
    except Exception as exc:  # noqa: BLE001
        error_message = str(exc)
        state.last_error = error_message
        state.record.state = "starting"
        state.record.blocked = False
        state.record.block_reason = None
        update_session_record(session_file, state.record, None, error_message)
        logging.exception("Startup IP quality gate failed: %s", error_message)
        return

    state.last_error = None
    state.last_snapshot = snapshot
    quality_result = check_changed_ip_quality(snapshot, config, state, force=True)
    if quality_result.verdict != "fail":
        state.record.state = "starting"
        state.record.blocked = False
        state.record.block_reason = None
        update_session_record(session_file, state.record, snapshot, None)
        if quality_result.verdict == "unknown":
            logging.info(
                "Startup IP quality gate did not return a quality verdict: %s",
                snapshot.ip_quality_error or snapshot_summary(snapshot),
            )
        else:
            logging.info("Startup IP quality gate passed: %s", snapshot_summary(snapshot))
        return

    state.record.state = "blocked"
    state.record.blocked = True
    state.record.block_reason = quality_result.reason
    update_session_record(session_file, state.record, snapshot, None)
    notify_once(
        dispatcher,
        state,
        event="startup_blocked",
        title=f"{app_name} startup blocked by netpotato",
        message=f"{quality_result.reason}\n\nSnapshot: {snapshot_summary(snapshot)}",
    )
    print(
        f"netpotato: blocked startup for {app_name}: {quality_result.reason}",
        file=sys.stderr,
        flush=True,
    )
    raise StartupGuardError(quality_result.reason or "current IP quality is unsafe")


def run_preflight_checks(
    app_name: str,
    config: NetpotatoConfig,
    state: MonitorState,
    session_file: Path,
    dispatcher: NotificationDispatcher,
) -> None:
    required_samples = config.preflight_good_samples
    ready_to_launch = False
    wait_title = (
        f"{app_name} waiting for stable baseline"
        if config.check_ip_change
        else f"{app_name} waiting for healthy checks"
    )
    wait_prefix = "Reasons"
    state.record.state = "preflight"
    state.record.blocked = False
    state.record.block_reason = None
    update_session_record(session_file, state.record, None, None)
    logging.info("Starting preflight checks for %s", app_name)

    while not ready_to_launch:
        state.record.last_event = "preflight"
        try:
            snapshot = fetch_snapshot(
                config.probe_url,
                config.timeout_sec,
                quality_enabled=config.ip_quality_enabled,
                quality_ip_allow_partial=not config.check_ip_mismatch,
                prefer_direct_ip=use_direct_ip_probe(config),
            )
            evaluation = evaluate_snapshot(snapshot, None, config)
            state.last_error = None
            state.last_snapshot = snapshot
            update_incident_counts(state, evaluation)

            quality_is_blocking = evaluation.has_poor_ip_quality and config.on_ip_quality == "block"
            quality_is_notify_only = evaluation.has_poor_ip_quality and config.on_ip_quality != "block"

            if quality_is_blocking:
                message = "; ".join(evaluation.reasons) or "current IP quality is unsafe"
                state.record.state = "blocked"
                state.record.blocked = True
                state.record.block_reason = message
                update_session_record(session_file, state.record, snapshot, None)
                notify_once(
                    dispatcher,
                    state,
                    event="startup_blocked",
                    title=f"{app_name} startup blocked by netpotato",
                    message=f"{message}\n\nSnapshot: {snapshot_summary(snapshot)}",
                )
                print(
                    f"netpotato: blocked startup for {app_name}: {message}",
                    file=sys.stderr,
                    flush=True,
                )
                raise StartupGuardError(message)

            sample_ready = evaluation.healthy_sample or quality_is_notify_only
            if sample_ready and (not config.check_ip_change or evaluation.observed_baseline):
                state.bad_streak = 0
                state.good_streak += 1
                state.record.block_reason = None if evaluation.healthy_sample else "; ".join(evaluation.reasons) or None
                if quality_is_notify_only and evaluation.reasons:
                    notify_once(
                        dispatcher,
                        state,
                        event="ip_quality_warn",
                        title=f"{app_name} startup IP quality warning",
                        message="; ".join(evaluation.reasons),
                    )
                if state.good_streak >= required_samples:
                    state.record.state = "starting"
                    ready_to_launch = True
                    if config.check_ip_change:
                        state.baseline_ip = evaluation.observed_baseline
                        state.record.baseline_ip = state.baseline_ip
                        notify_once(
                            dispatcher,
                            state,
                            event="baseline_created",
                            title=f"{app_name} baseline established",
                            message=(
                                f"Baseline IP: {state.baseline_ip}\n\n"
                                f"Snapshot: {snapshot_summary(snapshot)}"
                            ),
                        )
            else:
                state.good_streak = 0
                state.record.state = "preflight"
                state.record.block_reason = "; ".join(evaluation.reasons) or None
                if evaluation.reasons:
                    notify_once(
                        dispatcher,
                        state,
                        event="preflight_wait",
                        title=wait_title,
                        message=f"{wait_prefix}: {'; '.join(evaluation.reasons)}",
                    )

            update_session_record(session_file, state.record, snapshot, None)
            logging.info(
                "Preflight result: status=%s baseline=%s snapshot=%s",
                evaluation.classification,
                state.baseline_ip,
                snapshot_summary(snapshot),
            )
        except StartupGuardError:
            raise
        except Exception as exc:  # noqa: BLE001
            error_message = str(exc)
            state.good_streak = 0
            state.mismatch_active = False
            state.change_active = False
            state.quality_active = False
            state.record.state = "preflight"
            state.record.block_reason = error_message
            if error_message != state.last_error:
                notify_once(
                    dispatcher,
                    state,
                    event="probe_failure",
                    title=f"{app_name} preflight probe failed",
                    message=error_message,
                )
            state.last_error = error_message
            update_session_record(session_file, state.record, None, error_message)
            logging.exception("Preflight probe failed: %s", error_message)

        if ready_to_launch:
            break
        time.sleep(config.interval_sec)


def run_monitor_loop(
    process: subprocess.Popen[Any],
    app_name: str,
    config: NetpotatoConfig,
    state: MonitorState,
    controller: FreezeController,
    session_file: Path,
    stop_event: threading.Event,
    dispatcher: NotificationDispatcher,
) -> None:
    first_check = True
    while not stop_event.is_set():
        if process.poll() is not None:
            stop_event.set()
            break
        state.record.last_event = "startup" if first_check else "interval"
        first_check = False

        try:
            snapshot = fetch_snapshot(
                config.probe_url,
                config.timeout_sec,
                quality_enabled=False,
                quality_ip_allow_partial=not config.check_ip_mismatch,
                prefer_direct_ip=use_direct_ip_probe(config),
            )
            quality_result = check_changed_ip_quality(snapshot, config, state)
            observed_ip = quality_result.ip or snapshot_change_ip(snapshot)
            evaluation = evaluate_snapshot(snapshot, state.baseline_ip, config)
            state.last_error = None
            state.last_snapshot = snapshot
            update_incident_counts(state, evaluation)
            current_ip_has_bad_quality = bool(
                observed_ip and state.quality_blocked_ip == observed_ip and state.quality_reason
            )
            approved_changed_ip = quality_recovery_ready(observed_ip, evaluation, state, config)
            current_ip_approved = bool(observed_ip and state.quality_approved_ip == observed_ip)

            if current_ip_has_bad_quality:
                state.bad_streak += 1
                state.good_streak = 0
                state.inconclusive_streak = 0
                state.quality_gate_required = True
                reasons = [state.quality_reason, *evaluation.reasons]
                block_reason = "; ".join(reason for reason in reasons if reason) or "unsafe IP quality"
                if not state.blocked and state.bad_streak >= config.bad_samples_to_block:
                    controller.block()
                    state.blocked = True
                    state.record.blocked = True
                    state.record.state = "blocked"
                    state.record.block_reason = block_reason
                    notify_once(
                        dispatcher,
                        state,
                        event="blocked",
                        title=f"{app_name} blocked by netpotato",
                        message=f"Reason: {block_reason}\n\nSnapshot: {snapshot_summary(snapshot)}",
                    )
                elif state.blocked:
                    state.record.state = "blocked"
                    state.record.block_reason = block_reason
                else:
                    state.record.state = "unsafe"
                    state.record.block_reason = block_reason
            elif evaluation.classification == "unsafe" and evaluation.should_block and not approved_changed_ip:
                state.bad_streak += 1
                state.good_streak = 0
                state.inconclusive_streak = 0
                if evaluation.has_ip_change:
                    state.quality_gate_required = True
                block_reason = "; ".join(evaluation.reasons) or "unsafe IP state"
                if not state.blocked and state.bad_streak >= config.bad_samples_to_block:
                    controller.block()
                    state.blocked = True
                    state.record.blocked = True
                    state.record.state = "blocked"
                    state.record.block_reason = block_reason
                    notify_once(
                        dispatcher,
                        state,
                        event="blocked",
                        title=f"{app_name} blocked by netpotato",
                        message=f"Reason: {block_reason}\n\nSnapshot: {snapshot_summary(snapshot)}",
                    )
                elif state.blocked:
                    state.record.state = "blocked"
                    state.record.block_reason = block_reason
                else:
                    state.record.state = "unsafe"
                    state.record.block_reason = block_reason
            elif evaluation.healthy_sample or approved_changed_ip:
                state.bad_streak = 0
                state.good_streak += 1
                state.inconclusive_streak = 0
                if config.check_ip_change and state.baseline_ip is None and evaluation.observed_baseline:
                    if state.good_streak >= monitor_baseline_samples(config):
                        state.baseline_ip = evaluation.observed_baseline
                        state.record.baseline_ip = state.baseline_ip
                        notify_once(
                            dispatcher,
                            state,
                            event="baseline_created",
                            title=f"{app_name} baseline established",
                            message=(
                                f"Baseline IP: {state.baseline_ip}\n\n"
                                f"Snapshot: {snapshot_summary(snapshot)}"
                            ),
                        )
                recovery_candidate_ip = observed_ip if approved_changed_ip and evaluation.has_ip_change else None
                recovery_needs_quality = state.blocked and state.quality_gate_required
                recovery_quality_ready = current_ip_approved or not recovery_needs_quality
                recovery_ready = (
                    recovery_quality_ready
                    and (
                        recovery_candidate_ip is not None
                        or not config.check_ip_change
                        or state.baseline_ip is not None
                    )
                )
                if state.blocked and not recovery_quality_ready:
                    state.record.state = "blocked"
                    state.record.block_reason = "current IP has not passed the quality gate"
                elif state.blocked and recovery_ready and state.good_streak >= config.recover_good_samples:
                    if recovery_candidate_ip is not None:
                        state.baseline_ip = recovery_candidate_ip
                        state.record.baseline_ip = recovery_candidate_ip
                    controller.unblock()
                    state.blocked = False
                    state.record.blocked = False
                    state.record.state = "healthy"
                    state.record.block_reason = None
                    state.quality_gate_required = False
                    recovery_message = (
                        f"Accepted current IP as baseline: {state.baseline_ip}\n\nSnapshot: {snapshot_summary(snapshot)}"
                        if state.baseline_ip is not None
                        else f"Selected checks are healthy again.\n\nSnapshot: {snapshot_summary(snapshot)}"
                    )
                    notify_once(
                        dispatcher,
                        state,
                        event="recovered",
                        title=f"{app_name} recovered",
                        message=recovery_message,
                    )
                elif state.blocked:
                    state.record.state = "recovering"
                    state.record.block_reason = None
                elif not state.blocked and (
                    state.baseline_ip is not None or not config.check_ip_change
                ):
                    state.record.state = "healthy"
                    state.record.block_reason = None
                    state.last_transition = "steady:healthy"
            else:
                state.bad_streak = 0
                state.good_streak = 0
                block_reason = "; ".join(evaluation.reasons) or "current IP state could not be validated"
                if evaluation.classification == "inconclusive":
                    state.inconclusive_streak += 1
                    required_streak = (
                        1
                        if evaluation.should_block_inconclusive
                        else config.inconclusive_samples_to_block
                    )
                    should_block_inconclusive = (
                        evaluation.should_block_inconclusive
                        or (
                            config.on_ip_mismatch == "block"
                            and not evaluation.has_required_probe_failure
                        )
                    ) and state.inconclusive_streak >= required_streak
                    if should_block_inconclusive:
                        if not state.blocked:
                            controller.block()
                            state.blocked = True
                            state.record.blocked = True
                            state.record.state = "blocked"
                            state.record.block_reason = block_reason
                            notify_once(
                                dispatcher,
                                state,
                                event="blocked",
                                title=f"{app_name} blocked by netpotato",
                                message=f"Reason: {block_reason}\n\nSnapshot: {snapshot_summary(snapshot)}",
                            )
                        else:
                            state.record.state = "blocked"
                            state.record.block_reason = block_reason
                    else:
                        if state.blocked:
                            state.record.state = "blocked"
                        else:
                            state.record.state = "degraded"
                        state.record.block_reason = block_reason
                        if evaluation.reasons:
                            notify_once(
                                dispatcher,
                                state,
                                event="degraded",
                                title=f"{app_name} probe degraded",
                                message=(
                                    "The guard could not fully validate the current IP state.\n\n"
                                    f"Reasons: {'; '.join(evaluation.reasons)}"
                                ),
                            )
                else:
                    state.inconclusive_streak = 0
                    if state.blocked:
                        state.record.state = "blocked"
                    else:
                        state.record.state = "unsafe"
                    state.record.block_reason = block_reason
                    if evaluation.reasons:
                        notify_once(
                            dispatcher,
                            state,
                            event="unsafe",
                            title=f"{app_name} flagged an unsafe IP state",
                            message=(
                                f"Reasons: {'; '.join(evaluation.reasons)}\n\n"
                                f"Snapshot: {snapshot_summary(snapshot)}"
                            ),
                        )

            update_session_record(session_file, state.record, snapshot, None)
            logging.info(
                "Guard check result: state=%s status=%s blocked=%s baseline=%s snapshot=%s",
                state.record.state,
                evaluation.classification,
                state.blocked,
                state.baseline_ip,
                snapshot_summary(snapshot),
            )
        except Exception as exc:  # noqa: BLE001
            error_message = str(exc)
            state.good_streak = 0
            state.inconclusive_streak = 0
            state.mismatch_active = False
            state.change_active = False
            state.quality_active = False
            state.record.block_reason = error_message
            if config.on_probe_failure == "block":
                state.bad_streak += 1
                if not state.blocked and state.bad_streak >= config.bad_samples_to_block:
                    controller.block()
                    state.blocked = True
                    state.record.blocked = True
                    state.record.state = "blocked"
                    notify_once(
                        dispatcher,
                        state,
                        event="blocked",
                        title=f"{app_name} blocked by netpotato",
                        message=f"Guard probe failure: {error_message}",
                    )
            else:
                state.bad_streak = 0
                if not state.blocked:
                    state.record.state = "degraded"
                if error_message != state.last_error:
                    notify_once(
                        dispatcher,
                        state,
                        event="probe_failure",
                        title=f"{app_name} probe failed",
                        message=error_message,
                    )
            state.last_error = error_message
            update_session_record(session_file, state.record, None, error_message)
            logging.exception("Guard probe failed: %s", error_message)

        if process.poll() is not None:
            stop_event.set()
            continue
        if stop_event.wait(timeout=config.interval_sec):
            break


def install_signal_handlers(
    controller: FreezeController,
    stop_event: threading.Event,
) -> None:
    termination_signals = {signal.SIGINT, signal.SIGTERM}
    if hasattr(signal, "SIGHUP"):
        termination_signals.add(signal.SIGHUP)
    if hasattr(signal, "SIGQUIT"):
        termination_signals.add(signal.SIGQUIT)

    def handler(signum: int, _frame: Any) -> None:
        logging.info("Supervisor received signal %s", signum)
        controller.forward_signal(signum)
        if signum in termination_signals:
            stop_event.set()

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, handler)
    if hasattr(signal, "SIGQUIT"):
        signal.signal(signal.SIGQUIT, handler)


def launch_command(config: NetpotatoConfig, command_argv: list[str]) -> int:
    if not command_argv:
        raise ValueError("No command provided.")

    runtime_config = replace(config, ip_quality_enabled=False)
    app_name = Path(command_argv[0]).name or command_argv[0]
    session_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    session_dir = session_root(runtime_config) / session_id
    log_file = session_dir / "session.log"
    session_file = session_dir / "session.json"

    session = SessionRecord(
        session_id=session_id,
        app_name=app_name,
        backend=config.backend,
        started_at=now_iso(),
        cwd=os.getcwd(),
        argv=command_argv,
        session_dir=str(session_dir),
        log_file=str(log_file),
    )
    try:
        ensure_dir(session_dir)
        setup_file_logging(log_file)
        update_session_record(session_file, session, None, None)
    except OSError as exc:
        error_message = f"failed to initialize session state under {session_dir}: {exc}"
        print(
            f"netpotato: failed to initialize state for {app_name}: {error_message}",
            file=sys.stderr,
            flush=True,
        )
        return EXIT_LAUNCH_ERROR
    state = MonitorState(record=session)
    dispatcher = NotificationDispatcher(
        config.notify_command,
        timeout_sec=config.notify_timeout_sec,
        queue_size=config.notify_queue_size,
    )
    controller: Optional[FreezeController] = None
    stop_event: Optional[threading.Event] = None
    monitor_thread: Optional[threading.Thread] = None
    return_code: Optional[int] = None
    try:
        try:
            run_startup_quality_gate(app_name, config, state, session_file, dispatcher)
            if runtime_config.startup_fail_closed:
                run_preflight_checks(app_name, runtime_config, state, session_file, dispatcher)
                state.good_streak = 0
                state.bad_streak = 0
                state.inconclusive_streak = 0
        except StartupGuardError:
            session.blocked = state.record.blocked
            session.state = state.record.state
            session.block_reason = state.record.block_reason
            session.baseline_ip = state.baseline_ip
            session.ended_at = now_iso()
            update_session_record(session_file, session, state.last_snapshot, state.last_error)
            return EXIT_STARTUP_BLOCKED

        logging.info("Launching command %s", command_argv)
        try:
            process = preflight_launch(command_argv, session)
        except (OSError, ValueError) as exc:
            error_message = str(exc)
            state.last_error = error_message
            session.state = "error"
            session.blocked = False
            session.block_reason = error_message
            session.ended_at = now_iso()
            update_session_record(session_file, session, state.last_snapshot, error_message)
            logging.error("Failed to launch command %s: %s", command_argv, error_message)
            print(
                f"netpotato: failed to launch {app_name}: {error_message}",
                file=sys.stderr,
                flush=True,
            )
            return EXIT_LAUNCH_ERROR
        update_session_record(session_file, session, state.last_snapshot, state.last_error)

        controller = create_process_controller(runtime_config, process.pid, session_id=session_id)
        session.backend = controller.backend_name
        update_session_record(session_file, session, state.last_snapshot, state.last_error)
        stop_event = threading.Event()
        install_signal_handlers(controller, stop_event)

        monitor_thread = threading.Thread(
            target=run_monitor_loop,
            name="netpotato-monitor",
            daemon=True,
            args=(
                process,
                app_name,
                runtime_config,
                state,
                controller,
                session_file,
                stop_event,
                dispatcher,
            ),
        )
        monitor_thread.start()

        while return_code is None:
            try:
                return_code = process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                continue
    finally:
        if stop_event is not None:
            stop_event.set()
        if monitor_thread is not None:
            # The monitor thread is daemonized. Keep shutdown responsive instead of
            # waiting for an in-flight probe to spend its full network timeout.
            monitor_thread.join(timeout=0.2)
        if state.blocked and controller is not None:
            controller.unblock()
            state.blocked = False
        if controller is not None:
            controller.cleanup()
        if session.child_pid is not None:
            session.child_exit_code = return_code if return_code is not None else process.poll()
            session.ended_at = now_iso()
            session.blocked = False
            session.state = "exited"
            session.block_reason = state.record.block_reason
            session.baseline_ip = state.baseline_ip
            update_session_record(session_file, session, state.last_snapshot, state.last_error)
            logging.info("App exited with code %s", session.child_exit_code)
            print("🥔 Bye!", flush=True)
        dispatcher.close()

    return session.child_exit_code if session.child_exit_code is not None else 1


def watch_test_status(config: NetpotatoConfig) -> int:
    baseline_ip: Optional[str] = None
    bad_streak = 0
    inconclusive_streak = 0
    try:
        while True:
            timestamp = now_iso()
            try:
                snapshot = fetch_snapshot(
                    config.probe_url,
                    config.timeout_sec,
                    quality_enabled=config.ip_quality_enabled,
                    quality_ip_allow_partial=not config.check_ip_mismatch,
                    prefer_direct_ip=use_direct_ip_probe(config),
                )
                observed_ip = snapshot_change_ip(snapshot)
                evaluation = evaluate_snapshot(snapshot, baseline_ip, config)
                diagnostics = list(evaluation.reasons)
                action = "allow"
                if evaluation.classification == "unsafe" and evaluation.should_block:
                    bad_streak += 1
                    inconclusive_streak = 0
                    action = "block" if bad_streak >= config.bad_samples_to_block else "warn"
                elif evaluation.classification == "unsafe":
                    bad_streak = 0
                    inconclusive_streak = 0
                    action = "warn"
                elif evaluation.classification == "inconclusive":
                    bad_streak = 0
                    inconclusive_streak += 1
                    required_streak = (
                        1
                        if evaluation.should_block_inconclusive
                        else config.inconclusive_samples_to_block
                    )
                    if (
                        (
                            evaluation.should_block_inconclusive
                            or (
                                config.on_ip_mismatch == "block"
                                and not evaluation.has_required_probe_failure
                            )
                        )
                        and inconclusive_streak >= required_streak
                    ):
                        action = "block"
                    else:
                        action = "degraded"
                else:
                    bad_streak = 0
                    inconclusive_streak = 0

                if config.check_ip_change and baseline_ip is None and observed_ip and (
                    evaluation.healthy_sample
                    or (evaluation.has_poor_ip_quality and config.on_ip_quality != "block")
                ):
                    baseline_ip = observed_ip

                prefix = "🥔 " if action == "block" else ""
                print(
                    f"{prefix}[{timestamp}] status={evaluation.classification} action={action} "
                    f"baseline={baseline_ip or 'unset'} {snapshot_summary(snapshot)}"
                )
                if diagnostics:
                    print(f"details: {'; '.join(diagnostics)}")
            except Exception as exc:  # noqa: BLE001
                if config.on_probe_failure == "block":
                    bad_streak += 1
                    prefix = "🥔 " if bad_streak >= config.bad_samples_to_block else ""
                    action = "block" if prefix else "warn"
                else:
                    bad_streak = 0
                    action = "degraded"
                    prefix = ""
                inconclusive_streak = 0
                print(f"{prefix}[{timestamp}] probe_error={exc} action={action}")
            print(end="", flush=True)
            time.sleep(config.interval_sec)
    except KeyboardInterrupt:
        return 0


def print_status(config: NetpotatoConfig, limit: int) -> int:
    sessions = iter_sessions(config)
    if not sessions:
        print("No netpotato sessions found.")
        return 0

    def reconcile_stale_session(
        session_file: Path,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if payload.get("ended_at") is not None:
            return payload
        if is_pid_running(
            payload.get("supervisor_pid"),
            payload.get("supervisor_start_ticks"),
        ):
            return payload

        payload["ended_at"] = now_iso()
        payload["state"] = "exited"
        payload["blocked"] = False
        try:
            write_json(session_file, payload)
        except OSError as exc:
            logging.debug("Could not persist stale session %s: %s", session_file, exc)
        return payload

    active_count = 0
    for session_dir in sessions[:limit]:
        session_file = session_dir / "session.json"
        if not session_file.exists():
            continue
        try:
            payload = json.loads(session_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        payload = reconcile_stale_session(session_file, payload)
        active = (
            payload.get("ended_at") is None
            and is_pid_running(payload.get("child_pid"), payload.get("child_start_ticks"))
            and is_pid_running(
                payload.get("supervisor_pid"),
                payload.get("supervisor_start_ticks"),
            )
        )
        if active:
            active_count += 1
        prefix = "active" if active else "ended "
        print(
            f"{prefix}  session={payload.get('session_id')} app={payload.get('app_name')} "
            f"state={payload.get('state')} blocked={payload.get('blocked')} "
            f"ip_mismatch_count={payload.get('ip_mismatch_count', 0)} "
            f"ip_change_count={payload.get('ip_change_count', 0)} "
            f"ip_quality_issue_count={payload.get('ip_quality_issue_count', 0)} "
            f"pid={payload.get('child_pid')} started_at={payload.get('started_at')}"
        )

    if active_count == 0:
        print("No active guarded sessions.")
    return 0
