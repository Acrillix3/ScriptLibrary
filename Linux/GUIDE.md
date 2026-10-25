# Linux technician scripts

The library contains 45 tools: five in each existing category. The [script index](SCRIPT-INDEX.md) lists every tool. Each script begins with **What it does**, **Available flags**, and **How it works**.

Copy the complete `Linux` folder to the Linux computer. The category scripts share `lib/common.inc`; the merged CUPS and SSH entrypoints also use `lib/cups-audit.inc` and `lib/ssh-audit.inc`. Copying an entrypoint without its dependencies produces a clear error. See [the consolidation guide](../CONSOLIDATION-GUIDE.md). Run the tools with `sh`, so executable permissions are optional. Run only a trusted copy of this library: setup tools execute with the permissions of the invoking account.

## Platforms and dependencies

Debian and Ubuntu are the primary targets, including common Debian derivatives. The scripts identify the operating system from data in `/etc/os-release`, detect the active init system, and check command availability before collecting evidence. They do not execute the contents of that file or install missing audit dependencies automatically.

| Family | Package inventory / planning | Installation adapter | Service adapter |
|---|---|---|---|
| Debian, Ubuntu, Mint, Pop!_OS | dpkg / cached APT | apt-get | systemd when active |
| RHEL, Rocky, AlmaLinux, Oracle Linux | RPM / cached DNF | dnf | systemd when active |
| Fedora | RPM / cached DNF | dnf | systemd when active |
| Amazon Linux | RPM; cached DNF when present | AL2023: dnf; AL2: yum | detected systemd |
| SUSE / openSUSE | RPM / cached zypper | zypper | detected systemd |
| Arch / Manjaro | pacman / existing sync metadata | Plan only; perform reviewed full upgrades separately | detected systemd |
| Alpine | apk / cached simulation | apk | OpenRC when active |

These are implemented adapters, not a claim of live certification on every release. Audit coverage also depends on hardware, installed tools, permissions, kernel interfaces, and the selected backend. Missing tools, denied access, failed probes, and unsupported operations produce **Unknown** findings. An inventory entry or successful collection does not by itself establish health. Minimal containers, immutable images, and appliances may need their native administration workflow. Package installation is refused on detected immutable/transactional systems.

The scripts use `/bin/sh` syntax and common POSIX utilities, with capability checks around optional Linux commands. Network socket probes use Python 3 where a bounded portable test is needed. Hardware health uses existing smartmontools/NVMe tools; printing uses CUPS; filesystem ACL checks use existing ACL tools. Alpine account creation needs the approved shadow `useradd` utility. Each tool's `--help` describes its inputs.

## Running audits

Run these examples from the repository root on Linux. Replace hostnames, paths, interfaces, ports, and thresholds with values from your environment.

```sh
sh Linux/Device-Information/get-device-information.sh
sh Linux/Network-and-DNS/test-network-connectivity.sh --help
sh Linux/Software/plan-system-updates.sh
sh Linux/Users-and-Groups/audit-ssh-access.sh --help
sh Linux/Storage-and-Permissions/get-filesystem-capacity.sh
sh Linux/Troubleshooting/collect-support-bundle.sh --include-network no
sh Linux/Workstation-Setup/test-workstation-readiness.sh \
  --min-memory-mb 4096 --min-root-free-mb 10240 --required-commands curl,ssh
```

Audits do not repair configuration, refresh package indexes, start SMART self-tests, submit print jobs, or reboot the computer. Selected DNS, TCP, IPP, and TLS probes generate network traffic. Filesystem scans and hardware reads may require elevated access and have an operational cost; use the per-script scope and limit flags. Bounded report output is not a universal timeout on every local diagnostic command.

Package update plans use existing metadata, which may be stale. DNF's update-available result is interpreted separately from failure. Arch installation remains a plan because partial upgrades need to be avoided. Restart checks distinguish evidence from uncertainty; a missing reboot marker does not establish that no restart is needed.

## Plans, changes, and restarts

The ten setup/repair tools default to a plan. Use the same inputs with `--apply` to authorize changes. `--dry-run` makes the default intent explicit; it cannot be combined with `--apply`. Root is required for applying changes. Plans can still require read access to the selected service or configuration. There is no reboot action in this Linux set.

```sh
# Review the plan first.
sh Linux/Services/configure-service-state.sh \
  --service ssh --enabled yes --state restart

# Apply startup settings; leave the restart pending.
sudo sh Linux/Services/configure-service-state.sh \
  --service ssh --enabled yes --state restart --apply --defer-restarts

# Review a hostname change, then explicitly apply it.
sh Linux/Workstation-Setup/configure-workstation-baseline.sh --hostname helpdesk01
sudo sh Linux/Workstation-Setup/configure-workstation-baseline.sh --hostname helpdesk01 --apply
```

Service restarts and network profile activation require a separate interactive confirmation after `--apply`. Noninteractive execution defers them. `--defer-restarts` always defers them. Software installation asks separately because package maintainer scripts can start or restart services; with `--defer-restarts`, the entire installation is deferred. The library cannot individually control every installer hook. A failed action blocks later shared change actions, and partial work is recorded for review.

| Setup tool | Supported change and limits |
|---|---|
| configure-static-network | New NetworkManager Ethernet IPv4 profile cloned from an explicitly selected active profile. Preserves the original and asks before activation. Other network backends remain plans. No timed automatic rollback is promised; use local console access and the recorded original-profile recovery command. |
| configure-network-printer | Create a new selected CUPS queue using driverless printing or an approved installed driver. Existing queues are not overwritten. |
| repair-print-queue | Selected enable/accept/release operation. No job deletion; release may resume printing and asks separately. |
| configure-service-state | One selected systemd/OpenRC service and startup setting; restart confirmation is separate. |
| install-approved-software | Explicit family/package TSV manifest, current repository trust, native dependency resolution. No untrusted repositories or signature bypass. |
| provision-local-user | New local account, existing local groups, optional expiry and validated public key. Refuses existing account/home conflicts; password stays locked. |
| initialize-technician-workstation | Explicit built-in support-tool profile or approved package manifest; package side-effect confirmation still applies. |
| configure-workstation-baseline | Explicit hostname, installed timezone, or already generated locale. systemd adapter; limited Alpine/OpenRC adapter. |
| configure-time-synchronization | Dedicated approved-source file for one existing active chrony or timesyncd daemon; no competing daemon is installed. ntpd variants remain audit/plan only. |
| configure-endpoint-firewall | One additive port allowance in an already active UFW or firewalld backend. No manager enablement, flush, default-policy replacement, or firewall reload. Firewalld zone is explicit; source restriction is supported by the UFW adapter. |

For approved software, copy and edit [the example manifest](config/approved-software.example.tsv). It contains actual tab separators and one package per line. Only the detected family and `all` entries are selected. Review package dependencies and configured repositories before applying.

```sh
sh Linux/Software/install-approved-software.sh --manifest Linux/config/approved-software.example.tsv
sudo sh Linux/Software/install-approved-software.sh \
  --manifest Linux/config/approved-software.example.tsv --apply
```

## Reports and sensitive information

Every run creates a unique private folder under `Linux/Reports` (ignored by Git). Use `--output-dir DIRECTORY` for another location. `findings.tsv` contains status, check, and detail; `facts.tsv` contains selected metadata. Captured command evidence is limited to 500 lines, with a truncation marker. Standard error is excluded because third-party diagnostics can echo credentials. Capture failures retain their numeric status and are marked Unknown.

The tools avoid shadow hashes, private keys, environment dumps, raw authentication logs, arbitrary process arguments, and complete secret-bearing service configurations. URI credentials, query strings, and common credential assignments receive additional redaction. Hostnames, addresses, account names, file paths, public-key fingerprints, share names, and installed software can still be sensitive. Review reports before sharing.

**Configuration backups are an exception:** applying a change can preserve an original configuration file in the private `backups` subfolder. These recovery files are not sanitized and may contain secrets. Keep them local and do not include them in a shared support report. Exported printer information is a sanitized inventory, not a full restorable credential/configuration backup.

Exit codes are `0` completed, `1` failed finding/action, `2` invalid input/precondition, and `3` incomplete/unknown evidence. Warnings and explicitly deferred actions do not mean an action completed; inspect findings and verification evidence.

## Validation and references

See [validation results](VALIDATION.md). To rerun source and isolated fixture checks with Python 3.10+ and a POSIX shell (Bash is also required for the device fixture runner):

```sh
python3 Linux/tests/validate-library.py
python3 Linux/tests/test-network-print-services.py
python3 Linux/tests/test-software-users-workstation.py
python3 Linux/tests/test-merged-linux-tools.py
python3 Linux/tests/test-device-storage-troubleshooting.py
```

Source/control mocks do not replace disposable-VM checks of your actual distribution, package versions, hardware, directory integration, print server, firewall policy, or network profile. Test setup scripts in a representative lab and inspect the plan before production use.

Command behavior and platform handling were checked against primary documentation, including [os-release](https://www.freedesktop.org/software/systemd/man/os-release.html), [systemctl](https://www.freedesktop.org/software/systemd/man/systemctl.html), [Debian package administration](https://www.debian.org/doc/manuals/debian-faq/uptodate.html), [NetworkManager nmcli](https://networkmanager.dev/docs/api/latest/nmcli.html), [OpenRC](https://docs.alpinelinux.org/user-handbook/0.1a/Working/openrc.html), [Alpine apk](https://wiki.alpinelinux.org/wiki/Apk), [zypper](https://manpages.opensuse.org/Tumbleweed/zypper/zypper.8.en.html), and [Amazon Linux package management](https://docs.aws.amazon.com/linux/al2023/ug/package-management.html).
