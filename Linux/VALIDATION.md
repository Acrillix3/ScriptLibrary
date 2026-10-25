# Linux validation

Completed **2026-10-23**. The source/control suite passed **369 checks**, and the three targeted fixture suites passed **268 checks**: **637 total**.

| Suite | Checks | Scope |
|---|---:|---|
| validate-library.py | 369 | 45 expected scripts, comment sections, shell syntax, help/argument validation, 16 distro identifiers, nonexecuting os-release parsing, private reports, redaction, capture failures/truncation, plan and deferred restart controls. |
| test-device-storage-troubleshooting.py | 145 | Battery, CPU/hardware, driver, storage, permissions, kernel/security/restart and evidence projections with fake proc/sys data and command providers. |
| test-network-print-services.py | 50 | Network/printer/service syntax and isolated action plans, profile/URI validation, safe projections and restart/activation deferral. |
| test-software-users-workstation.py | 73 | Package adapters, DNF update exit codes, failed account creation, additive firewall changes, package deferral, time-daemon aliases and write-failure restart protection. |

Validation ran using the installed Git for Windows shell runtime. Production scripts use `/bin/sh` syntax; fixture execution used Bash and the available dash where appropriate. No WSL distribution, Linux VM or Linux host was available for live integration. Scripts were not run against real Linux services, package managers, hardware, identities, printers, network profiles or firewall policy. The shell fixtures use mock commands and private temporary directories; the device/storage fixture runner itself needs Bash.

These checks do not establish release-by-release integration support. Test the selected audit or setup operation in a representative disposable Linux VM before using it in production. Missing commands, access restrictions, unsupported active backends and incomplete evidence must remain Unknown. The guides describe implemented adapters and limits rather than claiming every combination was certified.

From the repository root on Linux with Python 3.10+ (validation only; operational socket probes use their existing Python 3):

```sh
python3 Linux/tests/validate-library.py
python3 Linux/tests/test-device-storage-troubleshooting.py --shell /bin/bash
python3 Linux/tests/test-network-print-services.py
python3 Linux/tests/test-software-users-workstation.py
```

Each runner accepts `--root` and `--shell` for an alternate library or shell executable. Fixtures can retain private local evidence in temporary folders; inspect their output. See [the Linux guide](GUIDE.md) and [script index](SCRIPT-INDEX.md).

## Consolidation regression update — 2026-10-24

All original **637 checks** remain passing. The new actual-entrypoint suite `tests/test-merged-linux-tools.py` adds **65 passing checks**, for **702 total**. It runs the four compatibility entrypoints from private copied library trees with fake CUPS, SSH, socket, key and configuration providers, checking legacy scope/filenames, Match contexts, redaction and failure states. Both new `.inc` collectors also passed dash syntax checks. No live Linux/CUPS/SSH/network operation was performed.

```sh
python3 Linux/tests/test-merged-linux-tools.py
```
