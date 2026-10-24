# Linux script index

45 operational scripts, grouped into the nine existing categories. Copy the complete Linux folder: the tools use `lib/common.inc`.

See [the Linux guide](GUIDE.md) for platform coverage, safeguards, examples, and validation.

## Device Information

| Script | Purpose | Mode |
|---|---|---|
| [get-device-information.sh](Device-Information/get-device-information.sh) | Inventory the local operating system, CPU, memory, hardware model, firmware, and virtualization. | Audit |
| [check-hardware-health.sh](Device-Information/check-hardware-health.sh) | Read existing SMART/NVMe health and thermal sensors without starting tests or waking standby disks. | Audit |
| [audit-drivers-and-firmware.sh](Device-Information/audit-drivers-and-firmware.sh) | Inventory loaded kernel modules, PCI drivers, network firmware versions, and recent firmware failure counts. | Audit |
| [get-battery-health.sh](Device-Information/get-battery-health.sh) | Read battery charge, cycle count, and full-capacity versus design-capacity wear from sysfs. | Audit |
| [test-virtualization-readiness.sh](Device-Information/test-virtualization-readiness.sh) | Check CPU virtualization hints, KVM availability and permissions, and IOMMU visibility. | Audit |

## Network and DNS

| Script | Purpose | Mode |
|---|---|---|
| [test-network-connectivity.sh](Network-and-DNS/test-network-connectivity.sh) | Inspect interfaces, routes, and an explicitly selected TCP endpoint. | Audit |
| [audit-dns-configuration.sh](Network-and-DNS/audit-dns-configuration.sh) | Inspect active resolver settings and optional forward and reverse lookups. | Audit |
| [audit-firewall-rules.sh](Network-and-DNS/audit-firewall-rules.sh) | Audit available firewall backends and local listeners without changing rules. | Audit |
| [configure-static-network.sh](Network-and-DNS/configure-static-network.sh) | Plan a static IPv4 Ethernet profile cloned from the active NetworkManager profile, with separate activation confirmation. | Plan / apply |
| [test-remote-access.sh](Network-and-DNS/test-remote-access.sh) | Inspect SSH service configuration and listeners, with an optional TCP reachability test. | Audit |

## Printing

| Script | Purpose | Mode |
|---|---|---|
| [get-printer-inventory.sh](Printing/get-printer-inventory.sh) | List CUPS queues, default destination, accepting state, device endpoints, and installed driver choices. | Audit |
| [test-printer-connectivity.sh](Printing/test-printer-connectivity.sh) | Test a selected printer TCP endpoint and optionally read-only IPP attributes. | Audit |
| [configure-network-printer.sh](Printing/configure-network-printer.sh) | Plan or create a local CUPS queue using IPP Everywhere or an explicitly approved installed model. | Plan / apply |
| [repair-print-queue.sh](Printing/repair-print-queue.sh) | Plan or perform one narrow CUPS queue recovery action without deleting jobs. | Plan / apply |
| [export-print-configuration.sh](Printing/export-print-configuration.sh) | Export sanitized CUPS queue and security metadata into the private report directory. | Audit |

## Services

| Script | Purpose | Mode |
|---|---|---|
| [audit-service-health.sh](Services/audit-service-health.sh) | Inspect service startup, failed states, and selected service dependencies using systemd or OpenRC. | Audit |
| [audit-scheduled-jobs.sh](Services/audit-scheduled-jobs.sh) | Inventory systemd timers, cron metadata, and pending at jobs without exporting scheduled command text. | Audit |
| [configure-service-state.sh](Services/configure-service-state.sh) | Plan or change one selected service's startup and runtime state, with separate restart confirmation. | Plan / apply |
| [audit-web-services.sh](Services/audit-web-services.sh) | Check installed nginx and Apache configuration syntax, listeners, and optional remote TLS certificate dates. | Audit |
| [audit-time-synchronization.sh](Services/audit-time-synchronization.sh) | Detect active time services, inspect configured sources and synchronization status, and flag competing daemons. | Audit |

## Software

| Script | Purpose | Mode |
|---|---|---|
| [get-software-inventory.sh](Software/get-software-inventory.sh) | Inventory installed native packages and optional Flatpak and Snap applications. | Audit |
| [audit-package-health.sh](Software/audit-package-health.sh) | Check package database consistency and optionally verify a selected installed package. | Audit |
| [audit-package-repositories.sh](Software/audit-package-repositories.sh) | Audit configured repository identities, trust settings, and source entries without refreshing metadata. | Audit |
| [plan-system-updates.sh](Software/plan-system-updates.sh) | Plan system updates using cached metadata, held packages, free space, and restart indicators. | Audit |
| [install-approved-software.sh](Software/install-approved-software.sh) | Install a reviewed package manifest through the detected distribution package manager. | Plan / apply |

## Storage and Permissions

| Script | Purpose | Mode |
|---|---|---|
| [get-filesystem-capacity.sh](Storage-and-Permissions/get-filesystem-capacity.sh) | Check space and inode capacity on a selected filesystem and inventory mount types and read-only states. | Audit |
| [find-large-and-open-deleted-files.sh](Storage-and-Permissions/find-large-and-open-deleted-files.sh) | Find large files within a bounded directory scan and inventory deleted files still held open. | Audit |
| [audit-filesystem-permissions.sh](Storage-and-Permissions/audit-filesystem-permissions.sh) | Audit a selected tree for world-writable objects, unprotected writable directories, special executable bits, and root ACL metadata. | Audit |
| [audit-network-shares.sh](Storage-and-Permissions/audit-network-shares.sh) | Inspect selected Samba security settings, NFS export flags, and mounted network-share types without exposing passwords. | Audit |
| [audit-storage-layout.sh](Storage-and-Permissions/audit-storage-layout.sh) | Inventory block-device topology, LVM thin/snapshot capacity, MD RAID, Btrfs, and ZFS where present. | Audit |

## Troubleshooting

| Script | Purpose | Mode |
|---|---|---|
| [collect-support-bundle.sh](Troubleshooting/collect-support-bundle.sh) | Build a private support report containing selected system, storage, network, service, and package metadata. | Audit |
| [get-performance-snapshot.sh](Troubleshooting/get-performance-snapshot.sh) | Collect bounded CPU, memory, disk counters, load, process names, and pressure-stall snapshots. | Audit |
| [audit-boot-and-kernel-errors.sh](Troubleshooting/audit-boot-and-kernel-errors.sh) | Summarize kernel error classes for a selected boot and list crash metadata without exporting raw messages or dumps. | Audit |
| [audit-security-policy-denials.sh](Troubleshooting/audit-security-policy-denials.sh) | Check SELinux/AppArmor state, a selected path's label metadata, and bounded denial counts without disabling protection. | Audit |
| [check-restart-requirements.sh](Troubleshooting/check-restart-requirements.sh) | Report reboot indicators, supported library/service restart hints, and running-kernel module availability without restarting anything. | Audit |

## Users and Groups

| Script | Purpose | Mode |
|---|---|---|
| [audit-users-and-groups.sh](Users-and-Groups/audit-users-and-groups.sh) | Audit local account IDs, account state, home directories, and local versus NSS identities. | Audit |
| [audit-elevated-access.sh](Users-and-Groups/audit-elevated-access.sh) | Audit privileged group membership and sudo/doas policy metadata without exposing policy command arguments. | Audit |
| [audit-ssh-access.sh](Users-and-Groups/audit-ssh-access.sh) | Audit effective SSH access policy and selected public-key fingerprints and file permissions. | Audit |
| [provision-local-user.sh](Users-and-Groups/provision-local-user.sh) | Create a new local account with optional local groups, expiry, and one public SSH key. | Plan / apply |
| [audit-domain-integration.sh](Users-and-Groups/audit-domain-integration.sh) | Audit realmd, SSSD, winbind, Kerberos prerequisites, and domain identity resolution without rejoining. | Audit |

## Workstation Setup

| Script | Purpose | Mode |
|---|---|---|
| [initialize-technician-workstation.sh](Workstation-Setup/initialize-technician-workstation.sh) | Plan or install an approved technician support-tool profile using native distribution packages. | Plan / apply |
| [configure-workstation-baseline.sh](Workstation-Setup/configure-workstation-baseline.sh) | Plan or configure an explicit hostname, timezone, or existing generated locale. | Plan / apply |
| [configure-time-synchronization.sh](Workstation-Setup/configure-time-synchronization.sh) | Configure approved NTP sources for the single active chrony or timesyncd daemon, with separate restart confirmation. | Plan / apply |
| [configure-endpoint-firewall.sh](Workstation-Setup/configure-endpoint-firewall.sh) | Add one approved port rule to an already active UFW or firewalld policy while preserving management access. | Plan / apply |
| [test-workstation-readiness.sh](Workstation-Setup/test-workstation-readiness.sh) | Test a workstation against an explicit resource and capability baseline. | Audit |
