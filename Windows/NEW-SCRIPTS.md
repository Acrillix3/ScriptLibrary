# Additional Windows diagnostics

These 20 scripts collect evidence for Windows 11 and Windows Server. Role-specific tools require the corresponding feature/management module and read access. All use Windows PowerShell 5.1, preferably 64-bit. Examples start at the ScriptLibrary root; replace example machines/users with your own.

Each creates a unique folder containing summary.json, overview.txt, collection-status.csv, query-errors.csv, and script-specific evidence. -OutputDirectory selects another destination. Complete means requested reads completed, not that the system is healthy; individual findings/counters can still be unknown or require review. Caps, optional checks, and scope limits appear in the reports.

## Requirements

| Tool | Specific requirement |
|---|---|
| Windows Update | Local Windows Update Agent COM access; optional Get-WindowsUpdateLog. Does not initiate update detection/install. |
| Pending restart | Native 64-bit registry view; ConfigMgr SDK only when requested. |
| Performance | Local CIM performance providers and process read access. |
| Profiles/drivers/restart timeline | Local CIM, selected registry/log access, and dump metadata access as applicable. |
| System file health | Elevated session; DISM/SFC diagnostic modes can run for several minutes and write Windows diagnostic logs/state. |
| Domain trust | Local domain membership/CIM and secure-channel permissions; secure-channel test is skipped on DCs. |
| Group Policy | gpresult and existing local RSoP; computer scope normally requires elevation. User scope reflects the selected/executing user. |
| Time synchronization | w32tm, time-service/registry read access. Optional stripchart makes network probes. |
| Remote Desktop | Local RDP/registry/service/listener/certificate/firewall access; optional sessions and remote TCP test are separately scoped. |
| Certificates | Selected local certificate-store read access. Optional trust checks may retrieve issuer certificates; they do not check revocation or private-key access. |
| Firewall | NetSecurity/NetConnection and policy read access. Rule matches do not prove end-to-end reachability. |
| Storage health | Storage module/provider; hardware may expose incomplete counters. Clustered hosts can expose cluster storage. |
| SMB files | SmbShare management access on the local file-serving host; only SMB handles are covered. |
| DHCP | DhcpServer management tools and access to the selected DHCP server. |
| Scheduled tasks | ScheduledTasks and permission to read selected task definitions/results. |
| Backup | WindowsServerBackup and authorized local backup management access; no recoverability test. |
| IIS | Local IIS/WebAdministration and selected event-log access. |
| Hyper-V | Hyper-V module and local host read access. |

No script installs management tools or makes repairs/configuration changes. Provider calls and native utilities can take time; row/sample limits are not universal hard timeouts. Reports can contain internal names, paths, users, and event text. Keep them in your approved support location.

## Examples

### Get-GroupPolicyDiagnostics.ps1

Collects local applied/denied Group Policy results and recent processing errors.

~~~powershell
.\Windows\Active-Directory\Get-GroupPolicyDiagnostics.ps1 -Scope Both
~~~

### Test-DomainTrust.ps1

Checks local domain membership, locator DNS records, and a member computer's secure channel.

~~~powershell
.\Windows\Active-Directory\Test-DomainTrust.ps1 -Server 'dc01.contoso.com'
~~~

### Get-WindowsBackupStatus.ps1

Reports local Windows Server Backup jobs, summary history, and cataloged backup versions.

~~~powershell
.\Windows\Backup-and-Recovery\Get-WindowsBackupStatus.ps1 -MaxBackupAgeHours 48
~~~

### Get-DriverIssues.ps1

Reports Plug and Play device errors and available signed-driver metadata.

~~~powershell
.\Windows\Device-Information\Get-DriverIssues.ps1
~~~

### Get-DHCPServerHealth.ps1

Reports IPv4 DHCP scope capacity, declined leases, server counters, and failover state.

~~~powershell
.\Windows\Network-and-DNS\Get-DHCPServerHealth.ps1 -ComputerName 'dhcp01.contoso.com' -WarningPercentInUse 90
~~~

### Test-RemoteDesktopHealth.ps1

Reports local RDP settings, services, listeners, firewall candidates, certificates, and optional session or remote-port evidence.

~~~powershell
.\Windows\Network-and-DNS\Test-RemoteDesktopHealth.ps1 -IncludeSessions
~~~

### Test-TimeSynchronization.ps1

Collects Windows Time configuration and status, with an optional time-server offset sample.

~~~powershell
.\Windows\Network-and-DNS\Test-TimeSynchronization.ps1 -TimeServer 'dc01.contoso.com'
~~~

### Get-CertificateExpiryReport.ps1

Reports certificate expiry, intended usage, and optional chain-trust results from selected local stores.

~~~powershell
.\Windows\Security\Get-CertificateExpiryReport.ps1 -ExpiringWithinDays 30
~~~

### Get-FirewallRuleReport.ps1

Reports local active firewall profiles and selected rules with their port, address, application, and service filters.

~~~powershell
.\Windows\Security\Get-FirewallRuleReport.ps1 -Direction Inbound -Enabled True -Action Block
~~~

### Get-ScheduledTaskFailures.ps1

Reports scheduled task results, missed runs, disabled tasks, and optional stale-run flags.

~~~powershell
.\Windows\Services\Get-ScheduledTaskFailures.ps1 -StaleAfterHours 48
~~~

### Get-SmbOpenFiles.ps1

Lists files opened by SMB clients on this Windows file server.

~~~powershell
.\Windows\Storage-and-Permissions\Get-SmbOpenFiles.ps1 -ClientComputerName 'PC01'
~~~

### Get-StorageHealth.ps1

Reports disk and volume health with hardware reliability counters when available.

~~~powershell
.\Windows\Storage-and-Permissions\Get-StorageHealth.ps1
~~~

### Get-PendingRestartStatus.ps1

Reports common Windows indicators that a restart or naming/domain change is pending.

~~~powershell
.\Windows\Troubleshooting\Get-PendingRestartStatus.ps1
~~~

### Get-PerformanceSnapshot.ps1

Samples CPU, memory, disk activity/latency, and busy processes during a slowdown.

~~~powershell
.\Windows\Troubleshooting\Get-PerformanceSnapshot.ps1 -Samples 5 -IntervalSeconds 2
~~~

### Get-UnexpectedRestartTimeline.ps1

Builds a restart, bugcheck, and hardware-error timeline with available crash-dump metadata.

~~~powershell
.\Windows\Troubleshooting\Get-UnexpectedRestartTimeline.ps1 -Days 7
~~~

### Test-SystemFileHealth.ps1

Runs Windows component-store diagnostics and optionally verifies protected system files.

~~~powershell
.\Windows\Troubleshooting\Test-SystemFileHealth.ps1 -ScanComponentStore -VerifySystemFiles
~~~

### Test-UserProfileHealth.ps1

Reports local user profile inconsistencies, temporary profiles, and recent profile errors.

~~~powershell
.\Windows\Troubleshooting\Test-UserProfileHealth.ps1 -LookbackDays 7
~~~

### Test-WindowsUpdateHealth.ps1

Collects recent update failures, update history, service state, and configured update policy.

~~~powershell
.\Windows\Troubleshooting\Test-WindowsUpdateHealth.ps1 -Hours 48
~~~

### Get-HyperVHealth.ps1

Reports local Hyper-V VM states, integration services, checkpoint ages, and storage paths.

~~~powershell
.\Windows\Virtualization\Get-HyperVHealth.ps1 -CheckpointAgeDays 14
~~~

### Get-IISHealth.ps1

Reports local IIS website and application pool states, bindings, and recent event errors.

~~~powershell
.\Windows\Web-Services\Get-IISHealth.ps1 -LookbackHours 24
~~~

## Interpretation

- Update history dates are UTC and history is bounded; it is not a missing-patch compliance scan.
- Restart indicators are common evidence, not an exhaustive application readiness/restart decision.
- Restart timeline lists default Windows dump locations only and does not analyze dump contents or determine the cause from Event 41 alone.
- Performance percentages use process CPU deltas; missing/idle disk counters are not assumed to be zero latency.
- Native command exit code zero indicates completion; review the saved diagnostic output for its actual finding.
- Disabled/stale tasks, stopped sites, old checkpoints, or expiring certificates require context and are not automatically safe to remove or restart.
- Backup catalog entries do not prove usable media or successful recovery.

## Microsoft references

- [Windows Update Agent history](https://learn.microsoft.com/windows/win32/wua_sdk/iupdatesearcher-methods)
- [WUA history date is UTC](https://learn.microsoft.com/openspecs/windows_protocols/ms-uamg/81f33109-ff5f-4c51-8a1c-412f49c47bab)
- [System File Checker modes](https://learn.microsoft.com/windows-server/administration/windows-commands/sfc)
- [Unexpected restart evidence](https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [Domain secure-channel scope](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/test-computersecurechannel?view=powershell-5.1)
- [DHCP scope statistics](https://learn.microsoft.com/powershell/module/dhcpserver/get-dhcpserverv4scopestatistics)
- [SMB open-file evidence](https://learn.microsoft.com/powershell/module/smbshare/get-smbopenfile)