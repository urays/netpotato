"""Session runtime for guarded applications."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from typing import Any, Optional
import uuid

from .config import NetpotatoConfig, resolve_command
from .probes import (
    Snapshot,
    fetch_snapshot,
    snapshot_baseline_ip,
    snapshot_diagnostics,
    snapshot_summary,
)


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def setup_file_logging(log_file: Path) -> None:
    ensure_dir(log_file.parent)
    handlers: list[logging.Handler] = [logging.FileHandler(log_file, encoding="utf-8")]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
        force=True,
    )


def write_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


@dataclass
class SessionRecord:
    session_id: str
    app_name: str
    backend: str
    started_at: str
    cwd: str
    argv: list[str]
    child_pid: Optional[int] = None
    supervisor_pid: int = field(default_factory=os.getpid)
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


@dataclass
class Evaluation:
    good_sample: bool
    should_block: bool
    reasons: list[str]
    observed_baseline: Optional[str]
    has_ip_mismatch: bool
    has_ip_change: bool


def session_root(config: NetpotatoConfig) -> Path:
    return config.state_dir / "sessions"


def iter_sessions(config: NetpotatoConfig) -> list[Path]:
    root = session_root(config)
    if not root.exists():
        return []
    return sorted([path for path in root.iterdir() if path.is_dir()], reverse=True)


def is_pid_running(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_proc_ppids() -> dict[int, int]:
    mapping: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat_text = (entry / "stat").read_text(encoding="utf-8")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        try:
            _prefix, suffix = stat_text.rsplit(") ", 1)
            parts = suffix.split()
            ppid = int(parts[1])
        except (ValueError, IndexError):
            continue
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


class FreezeController:
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


def emit_notification(
    notify_command: Optional[str],
    event: str,
    title: str,
    message: str,
    session: SessionRecord,
) -> None:
    logging.warning("%s\n%s", title, message)
    if not notify_command:
        return

    payload = json.dumps(
        {
            "event": event,
            "title": title,
            "message": message,
            "session_id": session.session_id,
            "app": session.app_name,
            "timestamp": now_iso(),
        },
        ensure_ascii=False,
    )
    env = os.environ.copy()
    env.update(
        {
            "NETPOTATO_EVENT": event,
            "NETPOTATO_TITLE": title,
            "NETPOTATO_MESSAGE": message,
            "NETPOTATO_PAYLOAD": payload,
            "NETPOTATO_SESSION_ID": session.session_id,
            "NETPOTATO_APP": session.app_name,
        }
    )
    try:
        completed = subprocess.run(
            notify_command,
            shell=True,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
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
    state: MonitorState,
    notify_command: Optional[str],
    event: str,
    title: str,
    message: str,
) -> None:
    key = f"{event}:{title}:{message}"
    if state.last_transition == key:
        return
    state.last_transition = key
    emit_notification(notify_command, event, title, message, state.record)


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


def evaluate_snapshot(
    snapshot: Snapshot,
    baseline_ip: Optional[str],
    config: NetpotatoConfig,
) -> Evaluation:
    reasons: list[str] = []
    should_block = False
    diagnostics = snapshot_diagnostics(snapshot)
    remote_missing = any(not value for value in (snapshot.domestic, snapshot.foreign, snapshot.google))
    has_ip_mismatch = remote_missing or snapshot.is_remote_mismatch()

    if remote_missing:
        reason = "probe results did not include all required IPs"
        if diagnostics:
            reason = f"{reason} ({'; '.join(diagnostics)})"
        reasons.append(reason)
        should_block = should_block or config.on_ip_mismatch == "block"
    if snapshot.is_remote_mismatch():
        reasons.append("probe results were inconsistent across vantage points")
        should_block = should_block or config.on_ip_mismatch == "block"

    observed_baseline = snapshot_baseline_ip(snapshot)
    has_ip_change = bool(baseline_ip and observed_baseline and observed_baseline != baseline_ip)
    if has_ip_change:
        reasons.append(f"observed public IP {observed_baseline} differs from baseline {baseline_ip}")
        should_block = should_block or config.on_ip_change == "block"

    good_sample = False
    if baseline_ip:
        good_sample = observed_baseline == baseline_ip and not reasons
    else:
        good_sample = observed_baseline is not None and not reasons

    return Evaluation(
        good_sample=good_sample,
        should_block=should_block,
        reasons=reasons,
        observed_baseline=observed_baseline,
        has_ip_mismatch=has_ip_mismatch,
        has_ip_change=has_ip_change,
    )


def update_incident_counts(state: MonitorState, evaluation: Evaluation) -> None:
    if evaluation.has_ip_mismatch and not state.mismatch_active:
        state.record.ip_mismatch_count += 1
    if evaluation.has_ip_change and not state.change_active:
        state.record.ip_change_count += 1
    state.mismatch_active = evaluation.has_ip_mismatch
    state.change_active = evaluation.has_ip_change


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
    return process


def run_monitor_loop(
    process: subprocess.Popen[Any],
    app_name: str,
    config: NetpotatoConfig,
    state: MonitorState,
    controller: FreezeController,
    session_file: Path,
    stop_event: threading.Event,
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
            )
            evaluation = evaluate_snapshot(snapshot, state.baseline_ip, config)
            state.last_error = None
            state.last_snapshot = snapshot
            update_incident_counts(state, evaluation)

            if evaluation.should_block:
                state.bad_streak += 1
                state.good_streak = 0
                block_reason = "; ".join(evaluation.reasons) or "unsafe IP state"
                if not state.blocked and state.bad_streak >= config.bad_samples_to_block:
                    controller.block()
                    state.blocked = True
                    state.record.blocked = True
                    state.record.state = "blocked"
                    state.record.block_reason = block_reason
                    notify_once(
                        state,
                        config.notify_command,
                        event="blocked",
                        title=f"{app_name} blocked by netpotato",
                        message=f"Reason: {block_reason}\n\nSnapshot: {snapshot_summary(snapshot)}",
                    )
                elif state.blocked:
                    state.record.state = "blocked"
                    state.record.block_reason = block_reason
                else:
                    state.record.state = "suspect"
                    state.record.block_reason = block_reason
            elif evaluation.good_sample:
                state.bad_streak = 0
                state.good_streak += 1
                if state.baseline_ip is None and evaluation.observed_baseline:
                    if state.good_streak >= config.good_samples_to_recover:
                        state.baseline_ip = evaluation.observed_baseline
                        state.record.baseline_ip = state.baseline_ip
                        state.record.state = "healthy"
                        state.record.block_reason = None
                        notify_once(
                            state,
                            config.notify_command,
                            event="baseline_created",
                            title=f"{app_name} baseline established",
                            message=(
                                f"Baseline IP: {state.baseline_ip}\n\n"
                                f"Snapshot: {snapshot_summary(snapshot)}"
                            ),
                        )
                elif state.blocked and state.good_streak >= config.good_samples_to_recover:
                    controller.unblock()
                    state.blocked = False
                    state.record.blocked = False
                    state.record.state = "healthy"
                    state.record.block_reason = None
                    notify_once(
                        state,
                        config.notify_command,
                        event="recovered",
                        title=f"{app_name} recovered",
                        message=(
                            f"Baseline IP restored: {state.baseline_ip}\n\n"
                            f"Snapshot: {snapshot_summary(snapshot)}"
                        ),
                    )
                elif not state.blocked and state.baseline_ip is not None:
                    state.record.state = "healthy"
                    state.record.block_reason = None
                    state.last_transition = "steady:healthy"
            else:
                state.bad_streak = 0
                state.good_streak = 0
                state.record.state = "blocked" if state.blocked else "degraded"
                state.record.block_reason = "; ".join(evaluation.reasons) or None
                if evaluation.reasons:
                    notify_once(
                        state,
                        config.notify_command,
                        event="degraded",
                        title=f"{app_name} probe degraded",
                        message=(
                            "The guard could not fully validate the current IP state.\n\n"
                            f"Reasons: {'; '.join(evaluation.reasons)}\n\n"
                            f"Snapshot: {snapshot_summary(snapshot)}"
                        ),
                    )

            update_session_record(session_file, state.record, snapshot, None)
            logging.info(
                "Guard check result: state=%s blocked=%s baseline=%s snapshot=%s",
                state.record.state,
                state.blocked,
                state.baseline_ip,
                snapshot_summary(snapshot),
            )
        except Exception as exc:  # noqa: BLE001
            error_message = str(exc)
            state.good_streak = 0
            state.mismatch_active = False
            state.change_active = False
            state.record.block_reason = error_message
            if config.on_probe_failure == "block":
                state.bad_streak += 1
                if not state.blocked and state.bad_streak >= config.bad_samples_to_block:
                    controller.block()
                    state.blocked = True
                    state.record.blocked = True
                    state.record.state = "blocked"
                    notify_once(
                        state,
                        config.notify_command,
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
                        state,
                        config.notify_command,
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

    app_name = Path(command_argv[0]).name or command_argv[0]
    session_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    session_dir = session_root(config) / session_id
    log_file = session_dir / "session.log"
    session_file = session_dir / "session.json"
    ensure_dir(session_dir)
    setup_file_logging(log_file)

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
    update_session_record(session_file, session, None, None)

    logging.info("Launching command %s", command_argv)
    process = preflight_launch(command_argv, session)
    update_session_record(session_file, session, None, None)

    controller = FreezeController(process.pid, config.block_descendants)
    stop_event = threading.Event()
    state = MonitorState(record=session)
    install_signal_handlers(controller, stop_event)

    monitor_thread = threading.Thread(
        target=run_monitor_loop,
        name="netpotato-monitor",
        daemon=True,
        args=(process, app_name, config, state, controller, session_file, stop_event),
    )
    monitor_thread.start()

    return_code: Optional[int] = None
    try:
        while return_code is None:
            try:
                return_code = process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                continue
    finally:
        stop_event.set()
        monitor_thread.join(timeout=2)
        if state.blocked:
            controller.unblock()
            state.blocked = False
        session.child_exit_code = return_code if return_code is not None else process.poll()
        session.ended_at = now_iso()
        session.blocked = False
        session.state = "exited"
        session.block_reason = state.record.block_reason
        session.baseline_ip = state.baseline_ip
        update_session_record(session_file, session, state.last_snapshot, state.last_error)
        logging.info("App exited with code %s", session.child_exit_code)

    return session.child_exit_code if session.child_exit_code is not None else 1


def watch_test_status(config: NetpotatoConfig) -> int:
    baseline_ip: Optional[str] = None
    try:
        while True:
            timestamp = now_iso()
            try:
                snapshot = fetch_snapshot(config.probe_url, config.timeout_sec)
                observed_ip = snapshot_baseline_ip(snapshot)
                evaluation = evaluate_snapshot(snapshot, baseline_ip, config)
                diagnostics = list(evaluation.reasons)
                if baseline_ip is None and observed_ip:
                    baseline_ip = observed_ip

                prefix = "🥔 " if diagnostics else ""
                print(f"{prefix}[{timestamp}] {snapshot_summary(snapshot)}")
                if diagnostics:
                    print(f"details: {'; '.join(diagnostics)}")
            except Exception as exc:  # noqa: BLE001
                print(f"🥔 [{timestamp}] probe_error={exc}")
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
        if is_pid_running(payload.get("supervisor_pid")):
            return payload

        payload["ended_at"] = now_iso()
        payload["state"] = "exited"
        payload["blocked"] = False
        try:
            write_json(session_file, payload)
        except OSError as exc:
            logging.warning("Could not persist stale session %s: %s", session_file, exc)
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
            and is_pid_running(payload.get("child_pid"))
            and is_pid_running(payload.get("supervisor_pid"))
        )
        if active:
            active_count += 1
        prefix = "active" if active else "ended "
        print(
            f"{prefix}  session={payload.get('session_id')} app={payload.get('app_name')} "
            f"state={payload.get('state')} blocked={payload.get('blocked')} "
            f"ip_mismatch_count={payload.get('ip_mismatch_count', 0)} "
            f"ip_change_count={payload.get('ip_change_count', 0)} "
            f"pid={payload.get('child_pid')} started_at={payload.get('started_at')}"
        )

    if active_count == 0:
        print("No active guarded sessions.")
    return 0
