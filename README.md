<div align="center">
  <h1>🥔 NetPotato</h1>
  <p><strong>Keep network-sensitive commands on a stable public IP.</strong></p>
  <p>NetPotato watches your public IP while a command runs. If the network changes, it can pause the command and continue it after the connection looks normal again.</p>

  <p>
    <img alt="Python 3.12+" src="https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white">
    <img alt="CLI" src="https://img.shields.io/badge/Type-CLI-111111">
    <img alt="Linux" src="https://img.shields.io/badge/Full%20Protection-Linux-2ea44f?logo=linux&logoColor=white">
    <img alt="License" src="https://img.shields.io/badge/License-Learning%20%26%20Research-orange">
  </p>

  <p>
    <a href="#quick-start">Quick Start</a> ·
    <a href="#checks">Checks</a> ·
    <a href="#status-files">Status Files</a> ·
    <a href="#license">License</a>
  </p>
</div>

---

## Quick Start

Install:

```bash
python -m pip install .
```

Use the default protection:

```bash
netpotato my-command
```

This is the same as:

```bash
netpotato --check="change" --best-effort my-command
```

For strict startup protection:

```bash
netpotato --fail-closed my-command
```

Common commands:

| What you want | Command |
| --- | --- |
| Show help | `netpotato` |
| Show recent sessions | `netpotato --status` |
| Watch the network only | `netpotato --check="change"` |
| Watch with stricter checks | `netpotato --check="change,mismatch"` |
| Protect a command in best-effort mode | `netpotato my-command` |
| Protect a command with fail-closed startup checks | `netpotato --fail-closed my-command` |
| Protect a command with stricter checks | `netpotato --fail-closed --check="change,mismatch" my-command` |

> Full pause/resume protection is designed for Linux.
> On other systems with Python and a terminal, `--check` mode may still work, but command protection is not the main target of the current release.

## Protection Modes

- `--best-effort`: launch the command immediately and establish the baseline in the background. This is the default in app mode.
- `--fail-closed`: wait for startup probes before launching the command. Use this mode for short-lived or security-sensitive commands.

If a command exits before the first probe finishes in `--best-effort` mode, NetPotato may not have enough time to establish a baseline. For strict enforcement, prefer `--fail-closed`.

## Checks

- `change`: pause the command if your public IP changes
- `mismatch`: warn when different probes do not agree on the current IP
- `quality`: check whether the current IP looks risky

## Status Files

NetPotato saves recent session data here:

```text
~/.local/state/netpotato/
```

## License

Learning and research use only. Commercial use is not allowed. See [LICENSE](LICENSE).
