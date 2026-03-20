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
netpotato --check="change" my-command
```

Common commands:

| What you want | Command |
| --- | --- |
| Show help | `netpotato` |
| Show recent sessions | `netpotato --status` |
| Watch the network only | `netpotato --check="change"` |
| Watch with stricter checks | `netpotato --check="change,mismatch"` |
| Protect a command | `netpotato my-command` |
| Protect a command with stricter checks | `netpotato --check="change,mismatch" my-command` |

> Full pause/resume protection is designed for Linux.
> On other systems with Python and a terminal, `--check` mode may still work, but command protection is not the main target of the current release.

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
