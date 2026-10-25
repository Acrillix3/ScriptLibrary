# Veeam-Validation  [Usage, prerequisites, version handling, reports and test scope](../VEEAM-GUIDE.md).  | Script | What it does | |---|---|
| [Invoke-VeeamValidation.ps1](Invoke-VeeamValidation.ps1) | Runs every included Veeam code-validation suite with mocked providers. |
| [Test-VBOAudits.ps1](Test-VBOAudits.ps1) | Runs Microsoft 365 v7/v8 platform, tenant, proxy, repository, job and protection mocks without contacting Veeam, Windows hosts, or databases. |
| [Test-VBRInfrastructureAudits.ps1](Test-VBRInfrastructureAudits.ps1) | Runs VBR repository, SOBR, WAN, proxy, platform and security mocks without contacting Veeam, Windows hosts, or databases. |
| [Test-VBRJobAudits.ps1](Test-VBRJobAudits.ps1) | Runs VBR backup/copy/replication, sessions, configuration backup and restore-point mocks without contacting Veeam, Windows hosts, or databases. |
| [Test-VeeamDatabaseAudits.ps1](Test-VeeamDatabaseAudits.ps1) | Runs Active-database discovery, connection parsing, compatibility and error mocks without contacting Veeam, Windows hosts, or databases. |
| [Test-VeeamDiagnostics.ps1](Test-VeeamDiagnostics.ps1) | Runs Host, connectivity and explicitly gated integrity/validator mocks without contacting Veeam, Windows hosts, or databases. |
| [Test-VeeamPackage.ps1](Test-VeeamPackage.ps1) | Checks Veeam script syntax, short headers, category placement, and passive suite behavior. |

`Test-MergedVeeamTools.ps1` is included in the controller. It tests shared-core dispatch, product/default forwarding and isolated connection state. Keep `Windows/lib` with the product folders and validation tools.
