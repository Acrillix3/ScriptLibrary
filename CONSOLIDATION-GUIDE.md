# Consolidated implementations

Eight merge groups now use one substantive implementation per group. All sixteen existing entrypoint filenames remain available with their original parameters and default behavior. Existing report identities and compatibility schemas remain in place. The old commands are small entrypoints that select a profile and call shared code.

**Copy the complete operating-system folder, including `lib`.** The twelve affected Windows entrypoints now require `Windows/lib`. Linux already required its shared library and now has two additional shared collectors. Missing implementation files produce a clear error. Private files are implementation details, not additional technician commands.

| Group | Existing entrypoints | Shared implementation |
|---|---|---|
| Software inventory | `Windows/Software/Get-InstalledSoftware.ps1`, `Get-InstalledSoftwareAudit.ps1` | `Windows/lib/Invoke-SoftwareInventoryCore.ps1` |
| DISM/SFC | `Windows/Troubleshooting/Test-SystemFileHealth.ps1`, `Repair-WindowsSystemFiles.ps1` | `Windows/lib/Invoke-WindowsIntegrityCore.ps1` |
| Veeam host diagnostics | VBR/VB365 `Get-*HostDiagnostics.ps1` | `Windows/lib/Invoke-VeeamHostDiagnosticsCore.ps1` |
| Veeam connectivity | VBR/VB365 `Test-*Connectivity.ps1` | `Windows/lib/Invoke-VeeamConnectivityCore.ps1` |
| Veeam database health | VBR/VB365 `Test-*DatabaseHealth.ps1` | `Windows/lib/Invoke-VeeamDatabaseHealthCore.ps1` |
| Classic VBR jobs | `Get-VBRBackupJobAudit.ps1`, `Get-VBRReplicationJobAudit.ps1` | `Windows/lib/Invoke-VbrClassicJobAuditCore.ps1` |
| Linux CUPS evidence | `get-printer-inventory.sh`, `export-print-configuration.sh` | `Linux/lib/cups-audit.inc` |
| Linux SSH policy | `test-remote-access.sh`, `audit-ssh-access.sh` | `Linux/lib/ssh-audit.inc` |

The four Veeam implementations also use `Windows/lib/Veeam-AuditCommon.ps1` for connection/version/report handling. Each core executes in its own script scope, and tests cover sequential product runs and owned-connection cleanup. The other specialized Veeam and server-role tools retain their separate workflows.

## Software compatibility

`Get-InstalledSoftwareAudit.ps1` remains the expanded audit entrypoint, with loaded-user/AppX options and baseline comparison. `Get-InstalledSoftware.ps1` selects a compatibility projection from the same registry/AppX collector: it retains `installed-software.csv`, optional `appx-packages.csv`, the legacy column/scope values, full AppX package names and its original summary fields. Legacy inventory keeps its earlier process-architecture compatibility; the expanded audit retains its own preflight rules. Neither command invokes installer consistency/repair operations.

## Clearer DISM/SFC modes

`Repair-WindowsSystemFiles.ps1` now offers explicit `-Mode` selection:

| Mode | Operation | Authorization |
|---|---|---|
| Check | DISM CheckHealth only | Runs a diagnostic; `-WhatIf` previews it |
| Scan | DISM ScanHealth only | Runs a diagnostic; `-WhatIf` previews it |
| Verify | SFC verifyonly only | Runs verification; `-WhatIf` previews it |
| Repair | DISM RestoreHealth followed by SFC scannow when permitted | Requires `-Apply`; otherwise produces a plan |

The existing `-Diagnose` flag still selects CheckHealth plus SFC verifyonly. Calling the repair command without a mode or apply/diagnose flag still produces a plan. Read-only modes cannot be combined with `-Apply`, and `-Mode` cannot be combined with `-Diagnose`. The existing `-Source`, `-SourceIndex`, `-LimitAccess`, `-SkipRestartPrompt`, report and common parameters retain their meanings.

From the repository root in elevated native Windows PowerShell 5.1:

```powershell
.\Windows\Troubleshooting\Repair-WindowsSystemFiles.ps1 -Mode Scan
.\Windows\Troubleshooting\Repair-WindowsSystemFiles.ps1 -Mode Verify
.\Windows\Troubleshooting\Repair-WindowsSystemFiles.ps1 -Mode Repair -Apply -WhatIf
.\Windows\Troubleshooting\Repair-WindowsSystemFiles.ps1 -Mode Repair -Apply -SkipRestartPrompt
```

`Test-SystemFileHealth.ps1` remains compatible: it runs CheckHealth by default, `-ScanComponentStore` selects ScanHealth, and `-VerifySystemFiles` adds SFC verification. Its legacy report filenames and fields are retained. It also retains its old read-only behavior of attempting requested SFC verification after a DISM collection failure. The repair sequence continues to stop after a failed DISM or a native restart-required result.

Native output and exit codes remain evidence to review, rather than an automatic clean-health verdict. DISM repair suppresses automatic Windows restart; any requested restart still requires separate confirmation after reports are saved. `-SkipRestartPrompt` defers it.

## Veeam compatibility

VBR and VB365 entrypoints preserve their product selection, default ports, credential parameters, version checks and report identities. The database audit preserves VB365 proxy inputs and the distinction between metadata collection and explicitly requested engine queries. The classic backup and replication job tools share collection logic while retaining their respective family filters. Backup-copy jobs keep their separate modern/legacy adapters.

This change does not merge the products' APIs into an assumed common capability set, include active content checks in passive suites, or loosen v12/v7/v8 and ownership checks. Continue using the existing [Veeam guide](Windows/VEEAM-GUIDE.md).

## Linux compatibility

The CUPS collector applies the existing inventory/export views: queue filtering, drivers/sharing and extended scheduler/security/PPD metadata keep their original scope and report filenames. Export remains sanitized metadata, not a restorable credential backup.

The SSH collector keeps the remote-access tool's explicit default Match context separate from the access audit's default-policy query. Listener/route/TCP evidence and explicitly selected key/permission checks remain profile-specific. Missing tools, unreadable configuration and failed probes still produce Unknown evidence; URI redaction and bounded output remain active.

No public Linux flag names or catalog entries changed. The four original Python regression suites remain, and the new merged-tool suite invokes all four actual entrypoints with private fixtures and mocked providers.

## Validation and maintenance

Run the existing validation controllers; they now include the merged Windows and Veeam regressions. The Linux merged-entrypoint suite is separately runnable:

```powershell
.\Windows\Technician-Tools-Validation\Invoke-TechnicianToolsValidation.ps1
.\Windows\Veeam-Validation\Invoke-VeeamValidation.ps1
```

```sh
python3 Linux/tests/validate-library.py
python3 Linux/tests/test-device-storage-troubleshooting.py --shell /bin/bash
python3 Linux/tests/test-network-print-services.py
python3 Linux/tests/test-software-users-workstation.py
python3 Linux/tests/test-merged-linux-tools.py
```

The consolidation contract suite checks all 94 existing declared Windows parameters across the twelve affected entrypoints, including their types, validation attributes and defaults. It also checks the sixteen public-to-core mappings. Saved parameter contracts are a regression fixture; intentionally changing the public API requires a reviewed fixture/documentation change.

See [consolidation validation results](CONSOLIDATION-VALIDATION.md) for counts and practical limits. These tests use mock providers and private files. No live software inventory, DISM/SFC repair, Veeam connection/database query, CUPS operation or SSH/network probe was performed as part of this refactor.
