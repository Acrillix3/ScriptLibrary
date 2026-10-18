# Veeam-Microsoft-365  [Usage, prerequisites, version handling, reports and test scope](../VEEAM-GUIDE.md).  | Script | What it does | |---|---|
| [Get-VBOBackupCopyJobAudit.ps1](Get-VBOBackupCopyJobAudit.ps1) | Audits backup copy jobs, source relationships, target-class metadata, and last reported outcomes. |
| [Get-VBOBackupJobAudit.ps1](Get-VBOBackupJobAudit.ps1) | Audits configured backup jobs, schedules, last outcomes, and bounded inclusion/exclusion metadata counts. |
| [Get-VBOHostDiagnostics.ps1](Get-VBOHostDiagnostics.ps1) | Collects Windows Veeam service, local-disk, memory, uptime, and recent event metadata. |
| [Get-VBOOrganizationAudit.ps1](Get-VBOOrganizationAudit.ps1) | Lists configured VB365 organizations, enabled workloads, and reported backup-history indicators. |
| [Get-VBOPlatformAudit.ps1](Get-VBOPlatformAudit.ps1) | Audits VB365 platform, license, TLS-certificate, and reported component metadata. |
| [Get-VBOProtectionAudit.ps1](Get-VBOProtectionAudit.ps1) | Combines configured organization/job scope with bounded restore-point evidence and sample freshness. |
| [Get-VBOProxyAudit.ps1](Get-VBOProxyAudit.ps1) | Audits reported backup-proxy state, component versions, and supported proxy pools. |
| [Get-VBORepositoryAudit.ps1](Get-VBORepositoryAudit.ps1) | Audits JET/object repositories, retention metadata, and known storage usage without assuming missing capacity. |
| [Get-VBOSessionAudit.ps1](Get-VBOSessionAudit.ps1) | Reports bounded VB365 backup/copy session outcomes and selected processing statistics. |
| [Invoke-VBOReadOnlyAuditSuite.ps1](Invoke-VBOReadOnlyAuditSuite.ps1) | Runs the product's passive audit tools and summarizes their report locations and states. |
| [Test-VBOConnectivity.ps1](Test-VBOConnectivity.ps1) | Tests DNS and TCP reachability from a chosen Windows host and records Veeam console authentication. |
| [Test-VBODatabaseHealth.ps1](Test-VBODatabaseHealth.ps1) | Discovers configured active Veeam database endpoints and optionally tests read-only engine metadata. |
| [Test-VBORepositoryIntegrity.ps1](Test-VBORepositoryIntegrity.ps1) | Plans or explicitly runs a vendor Microsoft 365 repository integrity scan. |
