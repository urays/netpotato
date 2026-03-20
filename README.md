# 🥔 NetPotato

> Explicit IP guard for network-sensitive CLI commands.

NetPotato wraps a command-line process, keeps checking the machine's public IP, and pauses the protected app if the observed IP becomes unsafe. By default it waits for a stable baseline IP before launching the protected app, checks the candidate IP against Scamalytics, and refuses to start if that IP looks risky.

NetPotato itself has two built-in commands: `test` and `status`. Any other invocation is treated as the target app to guard.

## What It Does

- Runs any CLI command under supervision.
- Establishes a baseline public IP from stable probe results before launch by default.
- Checks the startup IP quality with Scamalytics and blocks launch when the fraud score or proxy signals look risky.
- Checks three probe views: `domestic`, `overseas`, and `google`.
- Treats inconclusive probe results as `degraded` by default instead of freezing immediately.
- Pauses the app if the observed IP drifts away from the session baseline or the IP quality is unsafe.
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

Run a protected app:

```bash
netpotato python3 my_script.py
netpotato app_name
netpotato --startup-fail-open app_name
```

If the protected app exits, `netpotato` exits too.

Useful guard options:

```bash
netpotato --interval 2 --timeout 3 codex
netpotato --preflight-good-samples 3 --recover-good-samples 3 codex
netpotato --on-ip-mismatch block --inconclusive-samples-to-block 5 codex
netpotato --state-dir /tmp/netpotato-state codex
```

## Built-in Commands

Watch the live probe state without launching an app:

```bash
netpotato test
```

Show recent sessions:

```bash
netpotato status
netpotato status --limit 50
```

`status` includes the current session state, whether the app is blocked, the
child PID, the session start time, and three persisted counters:

- `ip_mismatch_count`: how many times the probe results became inconsistent or incomplete.
- `ip_change_count`: how many times the observed public IP moved away from the session baseline.
- `ip_quality_issue_count`: how many times the active IP was flagged as risky by Scamalytics.

## How It Works

1. NetPotato creates a guarded session and starts collecting probe data.
2. By default, it waits for enough healthy probe samples to establish a session baseline.
3. It looks up that candidate IP on Scamalytics and blocks startup immediately if the IP quality is risky.
4. It launches the target command in a new process session after the baseline is ready.
5. It repeatedly fetches public IP probe data while the app is running.
6. If the probe results become inconclusive, NetPotato moves the session to `degraded` by default instead of freezing immediately.
7. If the current probe results confirm that the public IP changed, or if the observed IP quality is unsafe, NetPotato pauses the protected process tree.
8. When the original baseline appears again for enough healthy checks, the app is resumed automatically.
9. When the target app exits, NetPotato finalizes the session record and exits.

Use `--startup-fail-open` if you prefer the older behavior where the app starts immediately and the baseline is established after launch.

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
