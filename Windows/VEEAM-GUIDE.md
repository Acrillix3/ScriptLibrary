# Veeam audits and diagnostic tests

30 tools are organized under **Veeam-Backup-and-Replication-v12** and **Veeam-Microsoft-365**. The Microsoft 365 category detects **v7 and v8**; optional commands and parameters are checked against the installed build. **Veeam-Validation** contains seven scripts for testing this code with mocked providers.

## Start here

Install the matching Veeam console/PowerShell components on the Veeam server or Windows management workstation. Use a fresh PowerShell process and the runtime supported by that installed Veeam build. The scripts parse in Windows PowerShell 5.1; later Microsoft 365 v8 releases may require PowerShell 7. Consult [Veeam's Microsoft 365 runtime requirements](https://helpcenter.veeam.com/docs/vbo365/powershell/getting_started.html?ver=8).

From the ScriptLibrary root:

~~~powershell
# Uses the current Windows identity. Replace example names with real hosts.
.\Windows\Veeam-Backup-and-Replication-v12\Invoke-VBRReadOnlyAuditSuite.ps1 -Server vbr01.example.com
.\Windows\Veeam-Microsoft-365\Invoke-VBOReadOnlyAuditSuite.ps1 -Server vb36501.example.com

# Individual tools also work independently.
.\Windows\Veeam-Backup-and-Replication-v12\Get-VBRWANAcceleratorAudit.ps1 -Server vbr01.example.com
.\Windows\Veeam-Microsoft-365\Get-VBORepositoryAudit.ps1 -Server vb36501.example.com
~~~

The standard suites collect metadata, test the requested console endpoint, and audit discovered database settings. They do not run intensive content verification or optional engine queries. Each child produces its own report; suite-summary.csv links those reports and preserves failures.

## Connections and version detection

Every tool accepts **Server**, **Port**, **Credential**, **HostCredential**, and **OutputDirectory**. Console defaults are VBR **9392** and Microsoft 365 **9191**. Use an account with the appropriate Veeam read permissions. Windows services/configuration/events additionally need host read access; remote host evidence uses Windows remoting. Database authentication is separate. The console connection parameter sets are documented by [VBR](https://helpcenter.veeam.com/archive/backup/120/powershell/connect-vbrserver.html) and [Microsoft 365](https://helpcenter.veeam.com/docs/vbo365/powershell/connect-vboserver.html?ver=8).

~~~powershell
$veeamCredential = Get-Credential
$hostCredential = Get-Credential
.\Windows\Veeam-Microsoft-365\Invoke-VBOReadOnlyAuditSuite.ps1 -Server vb36501.example.com -Credential $veeamCredential -HostCredential $hostCredential
~~~

Toolkit product version, PowerShell module manifest version, and verified server build are separate report fields. Microsoft 365 version detection uses Get-VBOVersion and, when host access permits, the requested server's installed service binary. VBR uses product evidence rather than assuming its module manifest number is the product major; connected-server build evidence is used when exposed. A workstation toolkit does not by itself verify a remote server build. Mismatched/unsupported product majors stop product audit queries; unavailable host verification stays Unknown. See [Get-VBOVersion](https://helpcenter.veeam.com/docs/vbo365/powershell/get-vboversion.html) and [VBR server build information](https://helpcenter.veeam.com/archive/backup/120/powershell/get-vbrbackupserverinfo.html).

Run these scripts in a fresh session. They explicitly connect to the requested server, close only a connection they successfully created, and never force-disconnect an existing session.

## Tools and scope

| VBR v12 tool | Evidence collected |
|---|---|
| Get-VBRPlatformAudit.ps1 | Server build, license dates/usage, managed-server inventory |
| Get-VBRRepositoryAudit.ps1 | Standard/object repositories, exposed capacity and immutability metadata |
| Get-VBRScaleOutRepositoryAudit.ps1 | SOBR performance/capacity/archive extents and exposed states |
| Get-VBRWANAcceleratorAudit.ps1 | WAN accelerator identities and exposed host/cache settings |
| Get-VBRProxyAudit.ps1 | VMware/Hyper-V proxies and exposed transport/task/disabled fields |
| Get-VBRSecurityAudit.ps1 | Role assignments, selected security settings and configuration-backup encryption flag |
| Get-VBRBackupJobAudit.ps1 | Classic VMware/Hyper-V backup jobs, schedules and configured selections |
| Get-VBRBackupCopyJobAudit.ps1 | Modern and legacy backup copy metadata; supported legacy source mappings |
| Get-VBRReplicationJobAudit.ps1 | Classic VMware/Hyper-V replication jobs, schedules and configured selections |
| Get-VBRSessionAudit.ps1 | Recent backup/replication/copy sessions and per-object task results |
| Get-VBRRestorePointAudit.ps1 | Cataloged restore-point evidence and configurable age findings |
| Get-VBRConfigurationBackupAudit.ps1 | Configuration-backup enablement, destination, schedule, retention, encryption |
| Test-VBRDatabaseHealth.ps1 | Active SQL Server/PostgreSQL configuration; optional engine metadata |
| Get-VBRHostDiagnostics.ps1 | Requested Windows server services, memory, disks and event metadata |
| Test-VBRConnectivity.ps1 | Explicit DNS/TCP path tests and console authentication evidence |
| Test-VBRBackupValidation.ps1 | Plan or explicitly gated native CRC scan |
| Invoke-VBRReadOnlyAuditSuite.ps1 | Runs the 15 passive tools with their default limits |

| Microsoft 365 v7/v8 tool | Evidence collected |
|---|---|
| Get-VBOPlatformAudit.ps1 | Version evidence, licensing, TLS certificate metadata, exposed components |
| Get-VBOOrganizationAudit.ps1 | Configured organizations, workloads and reported protection indicators |
| Get-VBOProxyAudit.ps1 | Proxy state/build/settings; v8 proxy pools when supported |
| Get-VBORepositoryAudit.ps1 | Repository retention, JET capacity, object/legacy-model metadata |
| Get-VBOBackupJobAudit.ps1 | Backup job state/schedule/last result and bounded configured-scope counts |
| Get-VBOBackupCopyJobAudit.ps1 | Copy jobs, source/target metadata and exposed archive classification |
| Get-VBOSessionAudit.ps1 | Job-session outcomes and selected processing statistics |
| Get-VBOProtectionAudit.ps1 | Per-organization job and restore-point evidence with freshness findings |
| Test-VBODatabaseHealth.ps1 | v7 JET/ESE candidate file metadata; v8 configured PostgreSQL/cache endpoints and optional metadata |
| Get-VBOHostDiagnostics.ps1 | Requested Windows server services, memory, disks and event metadata |
| Test-VBOConnectivity.ps1 | Explicit DNS/TCP path tests and console authentication evidence |
| Test-VBORepositoryIntegrity.ps1 | Plan or explicitly gated vendor source-repository integrity scan |
| Invoke-VBOReadOnlyAuditSuite.ps1 | Runs the 11 passive tools with their default limits |

Capabilities differ across builds. The VBR references use the [archived v12 PowerShell documentation](https://helpcenter.veeam.com/archive/backup/120/powershell/). Microsoft 365 commands use [Veeam's PowerShell reference](https://helpcenter.veeam.com/docs/vbo365/powershell/cmdlets.html?ver=8) with runtime capability checks; current v8 documentation is not evidence that every feature exists in v7.

These are bounded audits, not exhaustive coverage of every Veeam workload or entitlement. In particular, classic job audits do not expand dynamic selections or cover every Agent/NAS/CDP/tape/plugin/cloud job family. WAN cache usage and associations are not inferred when the public API does not expose them. License inventory is not a compliance finding; security metadata is not a full hardening assessment.

## Active database troubleshooting

VBR reads **SqlActiveConfiguration** and only the selected engine's safe host/instance/database fields. It does not assume the default engine is active. Microsoft 365 v8 reads selected fields from **ControllerPostgres**, **ProxyPostgres**, and **PersistentCachePostgres** configuration nodes. Stored passwords, encrypted passwords and complete connection strings are never exported or reused. Discovery follows [Veeam KB1471](https://www.veeam.com/kb1471) and [KB4676](https://www.veeam.com/kb4676).

~~~powershell
# Discovery without engine login:
.\Windows\Veeam-Backup-and-Replication-v12\Test-VBRDatabaseHealth.ps1 -Server vbr01.example.com

# Fixed read-only SQL queries; current Windows database identity:
.\Windows\Veeam-Backup-and-Replication-v12\Test-VBRDatabaseHealth.ps1 -Server vbr01.example.com -QueryDatabase

# v8 PostgreSQL configuration/cache checks, including a Windows proxy:
.\Windows\Veeam-Microsoft-365\Test-VBODatabaseHealth.ps1 -Server vb36501.example.com -ProxyComputerName proxy01.example.com -QueryDatabase -PsqlPath 'C:\Program Files\PostgreSQL\15\bin\psql.exe' -PostgresUser audit_reader -PostgresPassFile 'C:\Secure\veeam-audit.pgpass'
~~~

Use an existing, appropriately secured libpq password file or SSPI for PostgreSQL. SQL Server accepts optional **DatabaseCredential**; omitting it uses Windows integrated authentication. Do not put plaintext passwords in commands. Connections validate TLS trust and server identity; unavailable TLS trust, permissions, provider tooling or engine access produce Unknown. No settings are changed to make a connection work.

SQL metadata covers engine version, database state/recovery mode, data/log sizes and log reuse waits. PostgreSQL metadata covers size, recovery mode, connections, lock waiters and cumulative counters; the latter need interpretation against statistics reset time. Fixed SELECT statements use connection and statement timeouts. These are not table corruption checks. Queries do not read Veeam application tables, query texts, credentials, or payload data.

Microsoft 365 **v7** JET/ESE checks report metadata for the default config.edb candidate. Its existence does not establish the active path or database consistency. Live EDB files are never opened, copied or repaired. v8 PostgreSQL cache checks also do not validate legacy JET repository contents. Add every Windows proxy explicitly for cache discovery; unlisted Windows hosts and Linux proxies are outside this Windows tool's host scope.

## Path tests

~~~powershell
# Tests from this management workstation:
.\Windows\Veeam-Backup-and-Replication-v12\Test-VBRConnectivity.ps1 -Server vbr01.example.com -Endpoint 'wan02.example.com:6164','pgsql01.example.com:5432'

# Tests the selected path from a Windows Veeam host through WinRM:
.\Windows\Veeam-Microsoft-365\Test-VBOConnectivity.ps1 -Server vb36501.example.com -ProbeComputerName proxy01.example.com -Endpoint 'outlook.office365.com:443'
~~~

Select endpoints/ports that apply to your build and deployment. TCP success proves only that a selected listener accepted a connection from the selected source. It does not prove TLS, cloud permissions, repository I/O, WAN throughput or restore success. Veeam console authentication is recorded separately.

## Intensive checks

Both tools below default to **plan only**. Explicit run flags and PowerShell ShouldProcess controls are required to start scans. They are excluded from both standard audit suites.

~~~powershell
# Plan:
.\Windows\Veeam-Microsoft-365\Test-VBORepositoryIntegrity.ps1 -Server vb36501.example.com -RepositoryName 'Source Repo'
.\Windows\Veeam-Backup-and-Replication-v12\Test-VBRBackupValidation.ps1 -Server vbr01.example.com -BackupName 'Exact child backup name'

# Request the scan; PowerShell asks for confirmation:
.\Windows\Veeam-Microsoft-365\Test-VBORepositoryIntegrity.ps1 -Server vb36501.example.com -RepositoryName 'Source Repo' -RunIntegrityTest
.\Windows\Veeam-Backup-and-Replication-v12\Test-VBRBackupValidation.ps1 -Server vbr01.example.com -BackupName 'Exact child backup name' -RunValidation
~~~

[Microsoft 365 repository integrity testing](https://helpcenter.veeam.com/docs/vbo365/powershell/test-vborepository.html?ver=8) covers supported Exchange, SharePoint and Teams source backup data; it does not directly verify backup-copy targets. It can be long and I/O intensive. Inconsistent-object counts are reported without running repairs. There is no hard runtime timeout for this vendor cmdlet.

[VBR v12 Backup Validator](https://helpcenter.veeam.com/archive/backup/120/vsphere/backup_validator_validate.html) runs on the backup server, locally or through WinRM. Use the precise backup/child name accepted by the installed utility. It writes its native HTML on that server and enforces the selected wrapper timeout. Administrative rights and supported account authentication are vendor prerequisites; the scripts do not alter MFA. Object storage, Cloud Connect, unstructured data and chain-format restrictions follow the vendor reference. Review the native report; an exit code alone is not interpreted as successful verification.

Neither scan establishes bootability or application/item recovery. A real restore/SureBackup exercise needs an isolated recovery plan and environment-specific approval, networking, licensing and success criteria; this package does not launch one automatically.

## Reports and limits

Reports default to **Windows\Reports**, with a unique folder per tool/run. Each includes **summary.json**, **findings.csv**, **collection-status.csv**, a short README, and component CSVs. Empty tables retain column headers.

Findings distinguish **Pass**, **Review**, **Fail**, **Unknown**, and **NotApplicable**. Summary **Incomplete** means required evidence is unknown; **Collected** means collection completed, not that protection is verified. Review failures, unavailable fields and truncation before drawing conclusions. Row caps limit inspected/exported results; they are not general provider-call timeouts or proof that all objects were seen.

Exports use named fields instead of serializing entire vendor objects. Raw error text, event messages, database strings, service account details, credential objects and key material are excluded. Reports still contain operational names, IDs and paths, so store them appropriately.

## Code validation

~~~powershell
.\Windows\Veeam-Validation\Invoke-VeeamValidation.ps1
~~~

The included suites cover syntax/header/flag checks, both supported Microsoft 365 majors, realistic VBR manifest versions, successful and failed queries, partial/missing evidence, limits, time handling, database parsing, connection ownership, sensitive canaries, and intensive-operation gates. They use fixtures and do not contact Veeam hosts, databases or network endpoints. Passing mocks do not certify a live installation. See [VEEAM-VALIDATION.md](VEEAM-VALIDATION.md) for the recorded run.
