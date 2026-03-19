# 🥔 NetPotato

> Explicit IP guard for network-sensitive CLI commands.

NetPotato wraps a command-line process, keeps checking the machine's public IP, and pauses the protected app if the observed IP becomes unsafe. It is useful for long-running terminal workflows where an unexpected IP change should stop work immediately instead of letting it continue silently.

NetPotato itself has two built-in commands: `test` and `status`. Any other invocation is treated as the target app to guard.

## What It Does

- Runs any CLI command under supervision.
- Establishes a baseline public IP from stable probe results.
- Checks three probe views: `domestic`, `overseas`, and `google`.
- Pauses the app if the probe IPs disagree, disappear, or drift away from the session baseline.
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
```

If the protected app exits, `netpotato` exits too.

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
child PID, the session start time, and two persisted counters:

- `ip_mismatch_count`: how many times the probe results became inconsistent or incomplete.
- `ip_change_count`: how many times the observed public IP moved away from the session baseline.

## How It Works

1. NetPotato launches the target command in a new process session.
2. It repeatedly fetches public IP probe data.
3. Once the probe results are complete and consistent, NetPotato establishes a baseline IP for the session.
4. If the current probe results become inconsistent, incomplete, or different from the baseline, NetPotato pauses the protected process tree.
5. When the original baseline appears again for enough healthy checks, the app is resumed automatically.
6. When the target app exits, NetPotato finalizes the session record and exits.

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
