# Technician tools validation

Run `Invoke-TechnicianToolsValidation.ps1` in native Windows PowerShell 5.1. It checks the nine [technician tools](../TECHNICIAN-TOOLS.md) and runs seven isolated mock/fixture and contract suites. No live configuration or remediation is performed.

- `Test-HardwareSoftwareAudits.ps1`: Peripheral, monitor and software audit fixtures.
- `Test-Php2ShellAudit.ps1`: Version rules, safe XML and local-path fixtures.
- `Test-PowerSettingsMock.ps1`: Power plan, policy and USB device controls with native writes mocked.
- `Test-RepairCleanupSafety.ps1`: Servicing sequence, spool recovery and file-cleanup boundaries.

- `Test-AmdGpuCacheSafety.ps1`: Known-cache boundaries, AMD selection, previews and separate GPU restart confirmation.

- `Test-MergedWindowsTools.ps1`: Legacy/current inventory and DISM/SFC entrypoint compatibility.
- `Test-ImplementationConsolidation.ps1`: Shared-core mappings and saved public parameter contracts.

See [validation results and limits](../TECHNICIAN-TOOLS-VALIDATION.md).
