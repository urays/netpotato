# 🥔 NetPotato

> Explicit IP guard for network-sensitive CLI commands.

NetPotato wraps a command-line process, keeps checking the machine's public IP, and pauses the protected app if the selected checks say the current IP state is unsafe.

If you do not pass an app command, NetPotato runs the selected checks in live test mode. If you do pass an app command, NetPotato protects that app with the selected checks.
If you pass an app command without any `--check` option, NetPotato defaults to `--check="change"`.

## What It Does

- Runs any CLI command under supervision.
- Supports three selectable checks: `ip change`, `ip mismatch`, and `ip quality`.
- Defaults to `ip change` only when you protect an app without an explicit `--check` value.
- In CLI app mode, launches the app immediately and establishes a baseline afterward when `ip change` protection is active.
- Uses Scamalytics only when `quality` is included in `--check`.
- Uses the multi-vantage `domestic` / `overseas` / `google` probe flow when mismatch validation is needed.
- Treats inconclusive probe results as `degraded` by default instead of freezing immediately.
- Pauses the app when an enabled check reports an unsafe state.
- Resumes the app automatically when the original baseline is restored.
- Records session state, logs, and IP incident counters on disk.

## Requirements

- Linux
- Python 3.12+

Linux is required because NetPotato relies on `/proc` inspection and POSIX signals such as `SIGSTOP` and `SIGCONT`.

## Setup

Create a Python environment in whichever way you prefer.

Example with conda:

```bash
conda create -n netpotato python=3.12
conda activate netpotato
```

Example with `venv`:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

Install NetPotato from this repository:

```bash
cd /path/to/netpotato
```

```bash
python -m pip install .
```

## Quick Start

Show help:

```bash
netpotato
```

Show recent session status:

```bash
netpotato --status
```

Run live checks without launching an app:

```bash
netpotato --check="change"
netpotato --check="mismatch"
netpotato --check="quality"
netpotato --check="change,mismatch"
```

Protect an app:

```bash
netpotato claude
# equivalent to: netpotato --check="change" claude
netpotato --check="change" claude
netpotato --check="change,mismatch" codex --version
```

If the protected app exits, `netpotato` exits too.
When the protected app exits normally, NetPotato prints `netpotato: Bye!`.

Supported options:

```bash
--status
--check="change"
--check="change,mismatch"
--check="change,mismatch,quality"
```

`--check` switches NetPotato into opt-in mode for checks. For example,
`--check="change"` only monitors whether the session IP stays fixed, while
`--check="change,quality"` enables fixed-IP drift and Scamalytics
quality checks.

When app mode runs without an explicit `--check` value, NetPotato behaves as if
`--check="change"` had been selected.

When only `--check="change"` is enabled, NetPotato tries direct plain-text IP
probe endpoints first and falls back to the HTML probe page if those endpoints
reject the request.

`--status` includes the current session state, whether the app is blocked, the
child PID, the session start time, and three persisted counters:

- `ip_mismatch_count`: how many times the probe results became inconsistent or incomplete.
- `ip_change_count`: how many times the observed public IP moved away from the session baseline.
- `ip_quality_issue_count`: how many times the active IP was flagged as risky by Scamalytics.

## How It Works

1. NetPotato creates a guarded session and starts collecting probe data for the enabled checks.
2. In CLI app mode, it launches the target command immediately in a new process session.
3. If `ip change` protection is active, it establishes a baseline IP after enough healthy samples.
4. If `ip quality` protection is active, it checks the observed IP on Scamalytics during monitoring.
5. It repeatedly fetches public-IP probe data while the app is running.
6. If `ip mismatch` is active and the probe results become inconclusive, NetPotato moves the session to `degraded` by default instead of freezing immediately.
7. If an enabled check confirms the current IP state is unsafe, NetPotato pauses the protected process tree.
8. When the selected checks become healthy again for enough consecutive samples, the app is resumed automatically.
9. When the target app exits, NetPotato finalizes the session record and exits.

## State Files

Session data is stored under:

```text
~/.local/state/netpotato/sessions/
```

Each session gets its own directory with files such as:

```text
~/.local/state/netpotato/sessions/<session-id>/session.json
~/.local/state/netpotato/sessions/<session-id>/session.log
```

`session.json` stores the most recent snapshot, block reason, baseline IP, and the accumulated IP incident counters for that session.

## Notes

- Temporary probe failures can put a session into a degraded state even when the network itself is fine.
- This project currently targets Linux terminal workloads rather than general desktop app sandboxing.

## Usage Notice

This project is licensed only for learning and research use.
Commercial use is strictly prohibited.
Any user who uses this project or any related results for commercial purposes does so without authorization and bears sole responsibility for all resulting risks and consequences.
See [LICENSE](LICENSE) for the full terms.
