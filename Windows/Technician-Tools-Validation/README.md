# Technician tools validation

Run `Invoke-TechnicianToolsValidation.ps1` in native Windows PowerShell 5.1. It checks the eight [technician tools](../TECHNICIAN-TOOLS.md) and runs four isolated mock/fixture suites. No live configuration or remediation is performed.

- `Test-HardwareSoftwareAudits.ps1`: Peripheral, monitor and software audit fixtures.
- `Test-Php2ShellAudit.ps1`: Version rules, safe XML and local-path fixtures.
- `Test-PowerSettingsMock.ps1`: Power plan, policy and USB device controls with native writes mocked.
- `Test-RepairCleanupSafety.ps1`: Servicing sequence, spool recovery and file-cleanup boundaries.

See [validation results and limits](../TECHNICIAN-TOOLS-VALIDATION.md).
