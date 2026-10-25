# Veeam validation

Validated on **2026-10-24** with **Windows PowerShell 5.1.26100.9711** and **PowerShell 7.6.5**. Each runtime passed all seven suites: **1,186 checks per runtime**.

| Delivered test | Assertions | Main coverage |
|---|---:|---|
| Test-VeeamPackage.ps1 | 501 | Syntax, short headers, every declared flag, names/categories, both passive suite runners, child failure handling and intensive-check exclusion |
| Test-VBRJobAudits.ps1 | 180 | Backup/copy/replication filters, legacy/modern families, selections, sessions/tasks, UTC freshness, caps, configuration backup, scalar-only secret exclusion |
| Test-VBRInfrastructureAudits.ps1 | 145 | Repositories, SOBR extents/status, WAN/proxies, platform/security evidence, caps, missing fields and independent failures |
| Test-VBOAudits.ps1 | 129 | Every audit under v7/v8 fixtures, version/build separation, optional capability gates, repositories/pools, jobs/sessions/protection, missing evidence |
| Test-VeeamDatabaseAudits.ps1 | 60 | Active engine selection, real in-memory XML/connection-string parsing, SQL builder settings, native endpoint validation, v7 candidate handling, manifest 1.0, service outages, version rejection, redaction |
| Test-VeeamDiagnostics.ps1 | 65 | Local/remote dispatch, host partial results, TCP outcome validation, plan/WhatIf/confirmation gates, unsupported options, integrity counts, validator dispatch |
| Test-MergedVeeamTools.ps1 | 106 | Shared-core dispatch, default/credential forwarding, report identity, sequential product-state isolation and owned-only cleanup |

The eight scripts in Veeam-Validation are these seven suites and **Invoke-VeeamValidation.ps1**, which runs each in a fresh process using the current runtime. No Pester dependency is required.

From the repository root:

~~~powershell
.\Windows\Veeam-Validation\Invoke-VeeamValidation.ps1
~~~

Individual tests accept **WindowsRoot** and **OutputDirectory**. Their defaults select the Windows folder and Windows\Reports. The runner records each exit code and a log, then fails if any suite fails. Keep report paths short when using Windows PowerShell 5.1 because some file APIs retain legacy path-length limits.

All vendor imports, Veeam connections, Windows host reads, network probes, integrity scans and native-validator execution were replaced with local fixtures during validation. SQL connection tests stop before connecting; PostgreSQL execution is not performed. Synthetic XML and registry providers verify actual production parsing without reading a live Veeam configuration.

**No live Veeam server, active database, backup chain, repository scan, restore, or cloud tenant was tested.** These results validate code behavior, not a production system or every vendor build. Use the matching installed console/runtime, authorized accounts, and environment-specific endpoints when performing live audits. Review vendor support constraints before explicitly requesting intensive tests.

Installation verification also checks source-copy hashes, parses all installed PowerShell scripts, and verifies that the original 37 scripts and Linux files are unchanged.

## Consolidation regression update — 2026-10-24

The complete seven-suite controller passed **1,186 checks per runtime** on Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5 after the four Veeam merge groups. The new 106-check merged suite covers wrapper defaults/credentials/limits, VB365 proxy parameters, report identity and sequential same-process VBR12/VBO7/VBO8 success/failure isolation with owned-only cleanup. Package and database/diagnostic source-loading checks include the shared cores. No live Veeam, WinRM or database endpoint was used. See [consolidation validation](../CONSOLIDATION-VALIDATION.md).
