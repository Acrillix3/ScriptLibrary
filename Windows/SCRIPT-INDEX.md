# Windows script index

91 public operational PowerShell entrypoints and 22 code-validation scripts, plus 7 private implementation files, grouped by task. Each script documents its own flags at the top. Reports default to Windows\Reports. Merged entrypoints require the complete Windows folder, including `lib`; see [the consolidation guide](../CONSOLIDATION-GUIDE.md).

## Active Directory

| Script | What it does |
|---|---|
| [Get-ADGroupMembership.ps1](Active-Directory/Get-ADGroupMembership.ps1) | Lists one AD user's direct, primary, and nested group memberships. |
| [Get-ADUserStatus.ps1](Active-Directory/Get-ADUserStatus.ps1) | Reports one Active Directory user's account status, lockout state, and password expiration. |
| [Get-GroupPolicyDiagnostics.ps1](Active-Directory/Get-GroupPolicyDiagnostics.ps1) | Collects local applied/denied Group Policy results and recent processing errors. |
| [Invoke-ADAudit.ps1](Active-Directory/Invoke-ADAudit.ps1) | Audits AD domain details, domain controllers, replication, password policies, privileged groups, and stale accounts. |
| [Test-DomainTrust.ps1](Active-Directory/Test-DomainTrust.ps1) | Checks local domain membership, locator DNS records, and a member computer's secure channel. |

## Backup and Recovery

| Script | What it does |
|---|---|
| [Get-WindowsBackupStatus.ps1](Backup-and-Recovery/Get-WindowsBackupStatus.ps1) | Reports local Windows Server Backup jobs, summary history, and cataloged backup versions. |

## Device Information

| Script | What it does |
|---|---|
| [Get-ConnectedPeripheralAudit.ps1](Device-Information/Get-ConnectedPeripheralAudit.ps1) | Audits currently present peripherals with optional serial identifiers and provider visibility. |
| [Get-ConnectedMonitorDetails.ps1](Device-Information/Get-ConnectedMonitorDetails.ps1) | Reports connected monitor EDID identity, dimensions, connection and preferred mode. |
| [Export-BatteryHealth.ps1](Device-Information/Export-BatteryHealth.ps1) | Creates a battery usage and capacity report with a battery-device inventory. |
| [Get-DeviceInformation.ps1](Device-Information/Get-DeviceInformation.ps1) | Collects computer, Windows, hardware, uptime, and domain details for a support ticket. |
| [Get-DriverIssues.ps1](Device-Information/Get-DriverIssues.ps1) | Reports Plug and Play device errors and available signed-driver metadata. |

## Network and DNS

| Script | What it does |
|---|---|
| [Get-DHCPServerHealth.ps1](Network-and-DNS/Get-DHCPServerHealth.ps1) | Reports IPv4 DHCP scope capacity, declined leases, server counters, and failover state. |
| [Invoke-DNSAudit.ps1](Network-and-DNS/Invoke-DNSAudit.ps1) | Audits a Windows DNS server's settings, zones, aging configuration, and optional records and DNS responses. |
| [Test-MappedDrives.ps1](Network-and-DNS/Test-MappedDrives.ps1) | Lists mapped drives and checks whether their roots are accessible. |
| [Test-NetworkDiagnostics.ps1](Network-and-DNS/Test-NetworkDiagnostics.ps1) | Checks IP settings, gateways, DNS resolution, and TCP connectivity to selected targets. |
| [Test-RemoteDesktopHealth.ps1](Network-and-DNS/Test-RemoteDesktopHealth.ps1) | Reports local RDP settings, services, listeners, firewall candidates, certificates, and optional session or remote-port evidence. |
| [Test-TimeSynchronization.ps1](Network-and-DNS/Test-TimeSynchronization.ps1) | Collects Windows Time configuration and status, with an optional time-server offset sample. |

## Printing

| Script | What it does |
|---|---|
| [Clear-PrinterQueueAndCache.ps1](Printing/Clear-PrinterQueueAndCache.ps1) | Plans or clears selected print queues and optionally recovers the default spool cache with separately confirmed Spooler cycling. |
| [Get-PrinterDiagnostics.ps1](Printing/Get-PrinterDiagnostics.ps1) | Reports printers, ports, queued jobs, the default printer, and spooler status. |

## Security

| Script | What it does |
|---|---|
| [Test-Php2ShellExposure.ps1](Security/Test-Php2ShellExposure.ps1) | Audits local PHP version/configuration evidence for CVE-2026-109618 and CVE-2026-109619 without executing binaries or exploits. |
| [Get-CertificateExpiryReport.ps1](Security/Get-CertificateExpiryReport.ps1) | Reports certificate expiry, intended usage, and optional chain-trust results from selected local stores. |
| [Get-FirewallRuleReport.ps1](Security/Get-FirewallRuleReport.ps1) | Reports local active firewall profiles and selected rules with their port, address, application, and service filters. |

## Services

| Script | What it does |
|---|---|
| [Get-ScheduledTaskFailures.ps1](Services/Get-ScheduledTaskFailures.ps1) | Reports scheduled task results, missed runs, disabled tasks, and optional stale-run flags. |
| [Get-ServiceHealth.ps1](Services/Get-ServiceHealth.ps1) | Reports the status and startup mode of selected Windows services. |

## Software

| Script | What it does |
|---|---|
| [Get-InstalledSoftwareAudit.ps1](Software/Get-InstalledSoftwareAudit.ps1) | Audits registry/AppX registrations, optional loaded-user scope and baseline differences. |
| [Get-InstalledSoftware.ps1](Software/Get-InstalledSoftware.ps1) | Exports installed desktop application names and versions. |

## Storage and Permissions

| Script | What it does |
|---|---|
| [Clear-TemporaryFiles.ps1](Storage-and-Permissions/Clear-TemporaryFiles.ps1) | Plans or removes old regular files from known temporary and optional closed-browser cache folders. |
| [Export-FolderPermissions.ps1](Storage-and-Permissions/Export-FolderPermissions.ps1) | Exports folder owners and NTFS permission entries for a local or network folder. |
| [Find-LargeFiles.ps1](Storage-and-Permissions/Find-LargeFiles.ps1) | Lists the largest files in a chosen folder without deleting anything. |
| [Get-DiskSpaceReport.ps1](Storage-and-Permissions/Get-DiskSpaceReport.ps1) | Reports drive space and flags volumes below your free-space limits. |
| [Get-SmbOpenFiles.ps1](Storage-and-Permissions/Get-SmbOpenFiles.ps1) | Lists files opened by SMB clients on this Windows file server. |
| [Get-StorageHealth.ps1](Storage-and-Permissions/Get-StorageHealth.ps1) | Reports disk and volume health with hardware reliability counters when available. |

## Troubleshooting

| Script | What it does |
|---|---|
| [Reset-AmdGpuCache.ps1](Troubleshooting/Reset-AmdGpuCache.ps1) | Plans or clears executing-user AMD shader caches and separately confirms an exact AMD graphics-device restart. |
| [Repair-WindowsSystemFiles.ps1](Troubleshooting/Repair-WindowsSystemFiles.ps1) | Plans or automates DISM repair followed by SFC with logs, native result handling and separate restart confirmation. |
| [Collect-SupportEvidence.ps1](Troubleshooting/Collect-SupportEvidence.ps1) | Packages local device, disk, network, and recent event details for a support ticket. |
| [Export-RecentEventErrors.ps1](Troubleshooting/Export-RecentEventErrors.ps1) | Exports recent critical/error events, with optional warnings. |
| [Get-PendingRestartStatus.ps1](Troubleshooting/Get-PendingRestartStatus.ps1) | Reports common Windows indicators that a restart or naming/domain change is pending. |
| [Get-PerformanceSnapshot.ps1](Troubleshooting/Get-PerformanceSnapshot.ps1) | Samples CPU, memory, disk activity/latency, and busy processes during a slowdown. |
| [Get-UnexpectedRestartTimeline.ps1](Troubleshooting/Get-UnexpectedRestartTimeline.ps1) | Builds a restart, bugcheck, and hardware-error timeline with available crash-dump metadata. |
| [Test-SystemFileHealth.ps1](Troubleshooting/Test-SystemFileHealth.ps1) | Runs Windows component-store diagnostics and optionally verifies protected system files. |
| [Test-UserProfileHealth.ps1](Troubleshooting/Test-UserProfileHealth.ps1) | Reports local user profile inconsistencies, temporary profiles, and recent profile errors. |
| [Test-WindowsUpdateHealth.ps1](Troubleshooting/Test-WindowsUpdateHealth.ps1) | Collects recent update failures, update history, service state, and configured update policy. |

## Virtualization

| Script | What it does |
|---|---|
| [Get-HyperVHealth.ps1](Virtualization/Get-HyperVHealth.ps1) | Reports local Hyper-V VM states, integration services, checkpoint ages, and storage paths. |

## Web Services

| Script | What it does |
|---|---|
| [Get-IISHealth.ps1](Web-Services/Get-IISHealth.ps1) | Reports local IIS website and application pool states, bindings, and recent event errors. |

## Workstation Setup

| Script | What it does |
|---|---|
| [Set-TechnicianPowerSettings.ps1](Workstation-Setup/Set-TechnicianPowerSettings.ps1) | Plans or applies sleep/hibernate/display timers and supported USB power controls with original-value recovery. |
| [Test-WorkstationReadiness.ps1](Workstation-Setup/Test-WorkstationReadiness.ps1) | Checks disk space, domain membership, encryption, applications, and services against your JSON baseline. |


## Veeam-Backup-and-Replication-v12

| Script | What it does |
|---|---|
| [Get-VBRBackupCopyJobAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRBackupCopyJobAudit.ps1) | Audits modern and legacy v12 backup copy job metadata with explicit API coverage. |
| [Get-VBRBackupJobAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRBackupJobAudit.ps1) | Reports classic VMware/Hyper-V backup job scheduling and configured object selections. |
| [Get-VBRConfigurationBackupAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRConfigurationBackupAudit.ps1) | Audits configuration backup scheduling, encryption-enabled metadata, retention, and last-result fields. |
| [Get-VBRHostDiagnostics.ps1](Veeam-Backup-and-Replication-v12/Get-VBRHostDiagnostics.ps1) | Collects Windows Veeam service, local-disk, memory, uptime, and recent event metadata. |
| [Get-VBRPlatformAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRPlatformAudit.ps1) | Audits VBR 12 server build, safe license summary fields, and managed server inventory. |
| [Get-VBRProxyAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRProxyAudit.ps1) | Audits VMware and Hyper-V backup proxy inventories and exposed configuration states in VBR 12. |
| [Get-VBRReplicationJobAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRReplicationJobAudit.ps1) | Reports classic VMware/Hyper-V replication job scheduling and configured object selections. |
| [Get-VBRRepositoryAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRRepositoryAudit.ps1) | Audits repository inventories, available capacity evidence, and reported immutability settings in VBR 12. |
| [Get-VBRRestorePointAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRRestorePointAudit.ps1) | Reports cataloged restore points and configurable per-object age findings without testing restores. |
| [Get-VBRScaleOutRepositoryAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRScaleOutRepositoryAudit.ps1) | Audits VBR 12 scale-out repository policies and performance, capacity, and archive extent states. |
| [Get-VBRSecurityAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRSecurityAudit.ps1) | Audits VBR 12 user/group role assignments, selected security settings, and configuration backup encryption state. |
| [Get-VBRSessionAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRSessionAudit.ps1) | Reports bounded v12 backup/replication/copy session results and per-object task statuses. |
| [Get-VBRWANAcceleratorAudit.ps1](Veeam-Backup-and-Replication-v12/Get-VBRWANAcceleratorAudit.ps1) | Audits VBR 12 WAN accelerator inventory and any exposed host/cache configuration metadata. |
| [Invoke-VBRReadOnlyAuditSuite.ps1](Veeam-Backup-and-Replication-v12/Invoke-VBRReadOnlyAuditSuite.ps1) | Runs the product's passive audit tools and summarizes their report locations and states. |
| [Test-VBRBackupValidation.ps1](Veeam-Backup-and-Replication-v12/Test-VBRBackupValidation.ps1) | Plans or explicitly runs Veeam v12 Backup Validator CRC checks on the backup server. |
| [Test-VBRConnectivity.ps1](Veeam-Backup-and-Replication-v12/Test-VBRConnectivity.ps1) | Tests DNS and TCP reachability from a chosen Windows host and records Veeam console authentication. |
| [Test-VBRDatabaseHealth.ps1](Veeam-Backup-and-Replication-v12/Test-VBRDatabaseHealth.ps1) | Discovers configured active Veeam database endpoints and optionally tests read-only engine metadata. |


## Veeam-Microsoft-365

| Script | What it does |
|---|---|
| [Get-VBOBackupCopyJobAudit.ps1](Veeam-Microsoft-365/Get-VBOBackupCopyJobAudit.ps1) | Audits backup copy jobs, source relationships, target-class metadata, and last reported outcomes. |
| [Get-VBOBackupJobAudit.ps1](Veeam-Microsoft-365/Get-VBOBackupJobAudit.ps1) | Audits configured backup jobs, schedules, last outcomes, and bounded inclusion/exclusion metadata counts. |
| [Get-VBOHostDiagnostics.ps1](Veeam-Microsoft-365/Get-VBOHostDiagnostics.ps1) | Collects Windows Veeam service, local-disk, memory, uptime, and recent event metadata. |
| [Get-VBOOrganizationAudit.ps1](Veeam-Microsoft-365/Get-VBOOrganizationAudit.ps1) | Lists configured VB365 organizations, enabled workloads, and reported backup-history indicators. |
| [Get-VBOPlatformAudit.ps1](Veeam-Microsoft-365/Get-VBOPlatformAudit.ps1) | Audits VB365 platform, license, TLS-certificate, and reported component metadata. |
| [Get-VBOProtectionAudit.ps1](Veeam-Microsoft-365/Get-VBOProtectionAudit.ps1) | Combines configured organization/job scope with bounded restore-point evidence and sample freshness. |
| [Get-VBOProxyAudit.ps1](Veeam-Microsoft-365/Get-VBOProxyAudit.ps1) | Audits reported backup-proxy state, component versions, and supported proxy pools. |
| [Get-VBORepositoryAudit.ps1](Veeam-Microsoft-365/Get-VBORepositoryAudit.ps1) | Audits JET/object repositories, retention metadata, and known storage usage without assuming missing capacity. |
| [Get-VBOSessionAudit.ps1](Veeam-Microsoft-365/Get-VBOSessionAudit.ps1) | Reports bounded VB365 backup/copy session outcomes and selected processing statistics. |
| [Invoke-VBOReadOnlyAuditSuite.ps1](Veeam-Microsoft-365/Invoke-VBOReadOnlyAuditSuite.ps1) | Runs the product's passive audit tools and summarizes their report locations and states. |
| [Test-VBOConnectivity.ps1](Veeam-Microsoft-365/Test-VBOConnectivity.ps1) | Tests DNS and TCP reachability from a chosen Windows host and records Veeam console authentication. |
| [Test-VBODatabaseHealth.ps1](Veeam-Microsoft-365/Test-VBODatabaseHealth.ps1) | Discovers configured active Veeam database endpoints and optionally tests read-only engine metadata. |
| [Test-VBORepositoryIntegrity.ps1](Veeam-Microsoft-365/Test-VBORepositoryIntegrity.ps1) | Plans or explicitly runs a vendor Microsoft 365 repository integrity scan. |


## Veeam-Validation

| Script | What it does |
|---|---|
| [Test-MergedVeeamTools.ps1](Veeam-Validation/Test-MergedVeeamTools.ps1) | Tests product/default forwarding, report identity and isolated VBR/VB365 core execution. |
| [Invoke-VeeamValidation.ps1](Veeam-Validation/Invoke-VeeamValidation.ps1) | Runs every included Veeam code-validation suite with mocked providers. |
| [Test-VBOAudits.ps1](Veeam-Validation/Test-VBOAudits.ps1) | Runs Microsoft 365 v7/v8 platform, tenant, proxy, repository, job and protection mocks without contacting Veeam, Windows hosts, or databases. |
| [Test-VBRInfrastructureAudits.ps1](Veeam-Validation/Test-VBRInfrastructureAudits.ps1) | Runs VBR repository, SOBR, WAN, proxy, platform and security mocks without contacting Veeam, Windows hosts, or databases. |
| [Test-VBRJobAudits.ps1](Veeam-Validation/Test-VBRJobAudits.ps1) | Runs VBR backup/copy/replication, sessions, configuration backup and restore-point mocks without contacting Veeam, Windows hosts, or databases. |
| [Test-VeeamDatabaseAudits.ps1](Veeam-Validation/Test-VeeamDatabaseAudits.ps1) | Runs Active-database discovery, connection parsing, compatibility and error mocks without contacting Veeam, Windows hosts, or databases. |
| [Test-VeeamDiagnostics.ps1](Veeam-Validation/Test-VeeamDiagnostics.ps1) | Runs Host, connectivity and explicitly gated integrity/validator mocks without contacting Veeam, Windows hosts, or databases. |
| [Test-VeeamPackage.ps1](Veeam-Validation/Test-VeeamPackage.ps1) | Checks Veeam script syntax, short headers, category placement, and passive suite behavior. |

See [Veeam usage and scope](VEEAM-GUIDE.md) and [Veeam validation](VEEAM-VALIDATION.md).


## Server-Setup

| Script | What it does |
|---|---|
| [Initialize-SqlServerPrerequisites.ps1](Server-Setup/Initialize-SqlServerPrerequisites.ps1) | Checks SQL preparation baselines and creates new protected data, log, tempdb and backup directories. |
| [Initialize-WindowsServer.ps1](Server-Setup/Initialize-WindowsServer.ps1) | Plans or applies selected server naming, time zone and PowerShell remoting settings. |
| [Install-DhcpServer.ps1](Server-Setup/Install-DhcpServer.ps1) | Plans or installs the local DHCP role and optionally creates one IPv4 scope with safe options and explicit AD authorization. |
| [Install-DnsServer.ps1](Server-Setup/Install-DnsServer.ps1) | Plans or installs the local DNS role and safely adds optional primary zones and forwarders. |
| [Install-DomainController.ps1](Server-Setup/Install-DomainController.ps1) | Plans or stages AD DS and, when explicitly requested, promotes this server into a new forest or an existing domain. |
| [Install-FileServer.ps1](Server-Setup/Install-FileServer.ps1) | Plan or install the File Server role, protected NTFS folders, and encrypted SMB shares from JSON. |
| [Install-FsrmServer.ps1](Server-Setup/Install-FsrmServer.ps1) | Plan or install File Server Resource Manager and optional folder quotas from JSON. |
| [Install-HyperVHost.ps1](Server-Setup/Install-HyperVHost.ps1) | Plan or install Hyper-V and optionally create an external switch in a separate run. |
| [Install-NpsServer.ps1](Server-Setup/Install-NpsServer.ps1) | Plans or installs NPS and optionally creates one trusted RADIUS client on a member server. |
| [Install-PrintServer.ps1](Server-Setup/Install-PrintServer.ps1) | Plan or install the Print Server role and optional controlled TCP/IP printer queues from JSON. |
| [Install-RemoteDesktopServer.ps1](Server-Setup/Install-RemoteDesktopServer.ps1) | Stage RDS roles, then optionally create a new single-host session deployment with explicit licensing. |
| [Install-WebServer.ps1](Server-Setup/Install-WebServer.ps1) | Stage IIS features and optionally create new stopped sites and application pools from JSON. |
| [Install-WindowsServerBackup.ps1](Server-Setup/Install-WindowsServerBackup.ps1) | Plans or installs Windows Server Backup and optionally creates a new scheduled local-volume policy. |
| [Join-ServerDomain.ps1](Server-Setup/Join-ServerDomain.ps1) | Plans or joins the local workgroup server to an Active Directory domain and reports any required restart. |
| [Set-ServerNetwork.ps1](Server-Setup/Set-ServerNetwork.ps1) | Plans or applies one explicit static IPv4 address, optional gateway and ordered DNS server list. |


## Server-Setup-Validation

| Script | What it does |
|---|---|
| [Invoke-ServerSetupValidation.ps1](Server-Setup-Validation/Invoke-ServerSetupValidation.ps1) | Runs all five server setup validation suites with mocked Windows providers. |
| [Test-ApplicationRoleSetup.ps1](Server-Setup-Validation/Test-ApplicationRoleSetup.ps1) | Runs isolated mocked checks for RDS, IIS, and Hyper-V setup tools without changing server roles. |
| [Test-BaseAndKeyRoleSetup.ps1](Server-Setup-Validation/Test-BaseAndKeyRoleSetup.ps1) | Tests server baseline, network, SQL prerequisites, backup policy, NPS clients, and restart confirmation with mocked Windows providers. |
| [Test-IdentityServerSetup.ps1](Server-Setup-Validation/Test-IdentityServerSetup.ps1) | Tests the four identity and network server setup tools with mocked Windows providers. |
| [Test-ServerSetupPackage.ps1](Server-Setup-Validation/Test-ServerSetupPackage.ps1) | Checks the server setup package's syntax, documented flags, plan defaults and restart gates. |
| [Test-StorageAndPrintSetup.ps1](Server-Setup-Validation/Test-StorageAndPrintSetup.ps1) | Tests file-server, print-server, and FSRM setup behavior with mocked Windows management commands. |

See [server setup instructions](SERVER-SETUP-GUIDE.md) and [validation results](SERVER-SETUP-VALIDATION.md).

## Technician Tools Validation

| Script | What it does |
|---|---|
| [Test-ImplementationConsolidation.ps1](Technician-Tools-Validation/Test-ImplementationConsolidation.ps1) | Checks all sixteen merged entrypoints and 94 preserved Windows parameters, including positional order. |
| [Test-MergedWindowsTools.ps1](Technician-Tools-Validation/Test-MergedWindowsTools.ps1) | Tests software/DISM compatibility through actual entrypoints and private mocked providers. |
| [Test-AmdGpuCacheSafety.ps1](Technician-Tools-Validation/Test-AmdGpuCacheSafety.ps1) | Tests AMD cache boundaries, explicit adapter selection, previews and separately confirmed device restart using mocks. |
| [Invoke-TechnicianToolsValidation.ps1](Technician-Tools-Validation/Invoke-TechnicianToolsValidation.ps1) | Checks the eight-tool package and runs all four isolated validation suites. |
| [Test-HardwareSoftwareAudits.ps1](Technician-Tools-Validation/Test-HardwareSoftwareAudits.ps1) | Tests peripheral, monitor and software inventory behavior using fixtures. |
| [Test-Php2ShellAudit.ps1](Technician-Tools-Validation/Test-Php2ShellAudit.ps1) | Tests PHP version rules and safe XML/path handling. |
| [Test-PowerSettingsMock.ps1](Technician-Tools-Validation/Test-PowerSettingsMock.ps1) | Tests power planning, policy and USB controls without changing devices. |
| [Test-RepairCleanupSafety.ps1](Technician-Tools-Validation/Test-RepairCleanupSafety.ps1) | Tests servicing, spool recovery and cleanup safeguards using mocks. |

Usage and examples: [Technician tools](TECHNICIAN-TOOLS.md). Verification: [validation results](TECHNICIAN-TOOLS-VALIDATION.md).

## Private shared implementations

These seven files are dependencies, not additional technician entrypoints. Use the existing category commands.

| File | Shared responsibility |
|---|---|
| [Invoke-SoftwareInventoryCore.ps1](lib/Invoke-SoftwareInventoryCore.ps1) | Registry/AppX collection and compatible legacy/audit projections |
| [Invoke-WindowsIntegrityCore.ps1](lib/Invoke-WindowsIntegrityCore.ps1) | DISM/SFC native execution, modes, reports and restart controls |
| [Invoke-VeeamHostDiagnosticsCore.ps1](lib/Invoke-VeeamHostDiagnosticsCore.ps1) | VBR/VB365 host evidence |
| [Invoke-VeeamConnectivityCore.ps1](lib/Invoke-VeeamConnectivityCore.ps1) | VBR/VB365 bounded endpoint evidence |
| [Invoke-VeeamDatabaseHealthCore.ps1](lib/Invoke-VeeamDatabaseHealthCore.ps1) | VBR/VB365 database discovery and selected engine queries |
| [Invoke-VbrClassicJobAuditCore.ps1](lib/Invoke-VbrClassicJobAuditCore.ps1) | Classic backup/replication job family collection |
| [Veeam-AuditCommon.ps1](lib/Veeam-AuditCommon.ps1) | Veeam connection/version/report helpers used by the four merged Veeam cores |
