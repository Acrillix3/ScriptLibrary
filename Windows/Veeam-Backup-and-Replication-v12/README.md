# Veeam-Backup-and-Replication-v12  [Usage, prerequisites, version handling, reports and test scope](../VEEAM-GUIDE.md).  | Script | What it does | |---|---|
| [Get-VBRBackupCopyJobAudit.ps1](Get-VBRBackupCopyJobAudit.ps1) | Audits modern and legacy v12 backup copy job metadata with explicit API coverage. |
| [Get-VBRBackupJobAudit.ps1](Get-VBRBackupJobAudit.ps1) | Reports classic VMware/Hyper-V backup job scheduling and configured object selections. |
| [Get-VBRConfigurationBackupAudit.ps1](Get-VBRConfigurationBackupAudit.ps1) | Audits configuration backup scheduling, encryption-enabled metadata, retention, and last-result fields. |
| [Get-VBRHostDiagnostics.ps1](Get-VBRHostDiagnostics.ps1) | Collects Windows Veeam service, local-disk, memory, uptime, and recent event metadata. |
| [Get-VBRPlatformAudit.ps1](Get-VBRPlatformAudit.ps1) | Audits VBR 12 server build, safe license summary fields, and managed server inventory. |
| [Get-VBRProxyAudit.ps1](Get-VBRProxyAudit.ps1) | Audits VMware and Hyper-V backup proxy inventories and exposed configuration states in VBR 12. |
| [Get-VBRReplicationJobAudit.ps1](Get-VBRReplicationJobAudit.ps1) | Reports classic VMware/Hyper-V replication job scheduling and configured object selections. |
| [Get-VBRRepositoryAudit.ps1](Get-VBRRepositoryAudit.ps1) | Audits repository inventories, available capacity evidence, and reported immutability settings in VBR 12. |
| [Get-VBRRestorePointAudit.ps1](Get-VBRRestorePointAudit.ps1) | Reports cataloged restore points and configurable per-object age findings without testing restores. |
| [Get-VBRScaleOutRepositoryAudit.ps1](Get-VBRScaleOutRepositoryAudit.ps1) | Audits VBR 12 scale-out repository policies and performance, capacity, and archive extent states. |
| [Get-VBRSecurityAudit.ps1](Get-VBRSecurityAudit.ps1) | Audits VBR 12 user/group role assignments, selected security settings, and configuration backup encryption state. |
| [Get-VBRSessionAudit.ps1](Get-VBRSessionAudit.ps1) | Reports bounded v12 backup/replication/copy session results and per-object task statuses. |
| [Get-VBRWANAcceleratorAudit.ps1](Get-VBRWANAcceleratorAudit.ps1) | Audits VBR 12 WAN accelerator inventory and any exposed host/cache configuration metadata. |
| [Invoke-VBRReadOnlyAuditSuite.ps1](Invoke-VBRReadOnlyAuditSuite.ps1) | Runs the product's passive audit tools and summarizes their report locations and states. |
| [Test-VBRBackupValidation.ps1](Test-VBRBackupValidation.ps1) | Plans or explicitly runs Veeam v12 Backup Validator CRC checks on the backup server. |
| [Test-VBRConnectivity.ps1](Test-VBRConnectivity.ps1) | Tests DNS and TCP reachability from a chosen Windows host and records Veeam console authentication. |
| [Test-VBRDatabaseHealth.ps1](Test-VBRDatabaseHealth.ps1) | Discovers configured active Veeam database endpoints and optionally tests read-only engine metadata. |
