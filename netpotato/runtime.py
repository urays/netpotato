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
import sys
import threading
import time
from typing import Any, Optional
import uuid

from .config import NetpotatoConfig, resolve_command
from .probes import (
    Snapshot,
    fetch_snapshot,
    snapshot_consensus_ip,
    snapshot_diagnostics,
    snapshot_quality_reason,
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


@dataclass
class Evaluation:
    classification: str
    healthy_sample: bool
    should_block: bool
    reasons: list[str]
    observed_baseline: Optional[str]
    has_ip_mismatch: bool
    has_ip_change: bool
    has_poor_ip_quality: bool


class StartupGuardError(RuntimeError):
    """Raised when startup checks determine the app should not launch."""


def use_direct_ip_probe(config: NetpotatoConfig) -> bool:
    # The IP-change-only path can avoid the heavier multi-vantage HTML probe flow.
    return config.check_ip_change and not config.check_ip_mismatch and not config.ip_quality_enabled


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
    remote_mismatch = snapshot.is_remote_mismatch()
    has_ip_mismatch = config.check_ip_mismatch and (remote_missing or remote_mismatch)

    if config.check_ip_mismatch and remote_missing:
        reason = "probe results did not include all required IPs"
        if diagnostics:
            reason = f"{reason} ({'; '.join(diagnostics)})"
        reasons.append(reason)
    if config.check_ip_mismatch and remote_mismatch:
        reasons.append("probe results were inconsistent across vantage points")

    observed_baseline = snapshot_consensus_ip(
        snapshot,
        allow_partial=not config.check_ip_mismatch,
    )
    has_ip_change = bool(
        config.check_ip_change and baseline_ip and observed_baseline and observed_baseline != baseline_ip
    )
    classification = "healthy"
    quality_reason = snapshot_quality_reason(snapshot, config)
    has_poor_ip_quality = config.ip_quality_enabled and quality_reason is not None
    if has_ip_change:
        reasons.append(f"observed public IP {observed_baseline} differs from baseline {baseline_ip}")
        classification = "unsafe"
        should_block = should_block or config.on_ip_change == "block"
    elif has_poor_ip_quality:
        reasons.append(quality_reason)
        classification = "unsafe"
        should_block = should_block or config.on_ip_quality == "block"
    elif has_ip_mismatch:
        classification = "inconclusive"
    elif observed_baseline is None and (config.check_ip_change or config.ip_quality_enabled):
        classification = "inconclusive"
        reasons.append("probe results could not establish a stable public IP")

    healthy_sample = classification == "healthy"

    return Evaluation(
        classification=classification,
        healthy_sample=healthy_sample,
        should_block=should_block,
        reasons=reasons,
        observed_baseline=observed_baseline,
        has_ip_mismatch=has_ip_mismatch,
        has_ip_change=has_ip_change,
        has_poor_ip_quality=has_poor_ip_quality,
    )


def update_incident_counts(state: MonitorState, evaluation: Evaluation) -> None:
    if evaluation.has_ip_mismatch and not state.mismatch_active:
        state.record.ip_mismatch_count += 1
    if evaluation.has_ip_change and not state.change_active:
        state.record.ip_change_count += 1
    if evaluation.has_poor_ip_quality and not state.quality_active:
        state.record.ip_quality_issue_count += 1
    state.mismatch_active = evaluation.has_ip_mismatch
    state.change_active = evaluation.has_ip_change
    state.quality_active = evaluation.has_poor_ip_quality


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


def run_preflight_checks(
    app_name: str,
    config: NetpotatoConfig,
    state: MonitorState,
    session_file: Path,
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
                    state,
                    config.notify_command,
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
                        state,
                        config.notify_command,
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
                            state,
                            config.notify_command,
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
                        state,
                        config.notify_command,
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
                    state,
                    config.notify_command,
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
) -> None:
    first_check = True
    while not stop_event.is_set():
        if process.poll() is not None:
            stop_event.set()
            break
        if first_check and not config.startup_fail_closed:
            # App mode launches immediately, so delay the first network probe to avoid
            # short-lived commands paying the cost of a monitor request on exit.
            if stop_event.wait(timeout=config.interval_sec):
                break
            if process.poll() is not None:
                stop_event.set()
                break
        state.record.last_event = "startup" if first_check else "interval"
        first_check = False

        try:
            snapshot = fetch_snapshot(
                config.probe_url,
                config.timeout_sec,
                quality_enabled=config.ip_quality_enabled,
                quality_ip_allow_partial=not config.check_ip_mismatch,
                prefer_direct_ip=use_direct_ip_probe(config),
            )
            evaluation = evaluate_snapshot(snapshot, state.baseline_ip, config)
            state.last_error = None
            state.last_snapshot = snapshot
            update_incident_counts(state, evaluation)

            if evaluation.classification == "unsafe" and evaluation.should_block:
                state.bad_streak += 1
                state.good_streak = 0
                state.inconclusive_streak = 0
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
                    state.record.state = "unsafe"
                    state.record.block_reason = block_reason
            elif evaluation.healthy_sample:
                state.bad_streak = 0
                state.good_streak += 1
                state.inconclusive_streak = 0
                if config.check_ip_change and state.baseline_ip is None and evaluation.observed_baseline:
                    if state.good_streak >= config.preflight_good_samples:
                        state.baseline_ip = evaluation.observed_baseline
                        state.record.baseline_ip = state.baseline_ip
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
                recovery_ready = not config.check_ip_change or state.baseline_ip is not None
                if state.blocked and recovery_ready and state.good_streak >= config.recover_good_samples:
                    controller.unblock()
                    state.blocked = False
                    state.record.blocked = False
                    state.record.state = "healthy"
                    state.record.block_reason = None
                    recovery_message = (
                        f"Baseline IP restored: {state.baseline_ip}\n\nSnapshot: {snapshot_summary(snapshot)}"
                        if state.baseline_ip is not None
                        else f"Selected checks are healthy again.\n\nSnapshot: {snapshot_summary(snapshot)}"
                    )
                    notify_once(
                        state,
                        config.notify_command,
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
                    should_block_inconclusive = (
                        config.on_ip_mismatch == "block"
                        and state.inconclusive_streak >= config.inconclusive_samples_to_block
                    )
                    if should_block_inconclusive:
                        if not state.blocked:
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
                                state,
                                config.notify_command,
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
                            state,
                            config.notify_command,
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
    state = MonitorState(record=session)
    try:
        if config.startup_fail_closed:
            run_preflight_checks(app_name, config, state, session_file)
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
        return 3

    logging.info("Launching command %s", command_argv)
    process = preflight_launch(command_argv, session)
    update_session_record(session_file, session, state.last_snapshot, state.last_error)

    controller = FreezeController(process.pid, config.block_descendants)
    stop_event = threading.Event()
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
        print("🥔: Bye!", flush=True)

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
                observed_ip = snapshot_consensus_ip(
                    snapshot,
                    allow_partial=not config.check_ip_mismatch,
                )
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
                    if (
                        config.on_ip_mismatch == "block"
                        and inconclusive_streak >= config.inconclusive_samples_to_block
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
            f"ip_quality_issue_count={payload.get('ip_quality_issue_count', 0)} "
            f"pid={payload.get('child_pid')} started_at={payload.get('started_at')}"
        )

    if active_count == 0:
        print("No active guarded sessions.")
    return 0
