# Windows technician tools

Eight standalone tools supplement the existing diagnostic scripts. Run them in Windows PowerShell 5.1. Repair and power configuration target Windows 11 and Windows Server 2022/2025; individual providers and driver controls may be unavailable on some installations. Each script starts with **What it does**, **Available flags**, and **How it works**. Use `Get-Help <script> -Full` for its parameter syntax.

| Category | Script | Purpose |
|---|---|---|
| Troubleshooting | [Repair-WindowsSystemFiles.ps1](Troubleshooting/Repair-WindowsSystemFiles.ps1) | DISM image repair followed by SFC, native logs and exit codes, separately confirmed restart. |
| Security | [Test-Php2ShellExposure.ps1](Security/Test-Php2ShellExposure.ps1) | Local evidence for CVE-2026-109618 and CVE-2026-109619. |
| Device Information | [Get-ConnectedPeripheralAudit.ps1](Device-Information/Get-ConnectedPeripheralAudit.ps1) | Present peripheral inventory, driver/problem metadata, optional serial identifiers. |
| Device Information | [Get-ConnectedMonitorDetails.ps1](Device-Information/Get-ConnectedMonitorDetails.ps1) | EDID identity, dimensions, connection technology and preferred mode. |
| Printing | [Clear-PrinterQueueAndCache.ps1](Printing/Clear-PrinterQueueAndCache.ps1) | Selected queue cancellation and optional all-queue spool cache recovery. |
| Storage and Permissions | [Clear-TemporaryFiles.ps1](Storage-and-Permissions/Clear-TemporaryFiles.ps1) | Age-based cleanup of known temporary folders and optional closed-browser caches. |
| Software | [Get-InstalledSoftwareAudit.ps1](Software/Get-InstalledSoftwareAudit.ps1) | Registry/AppX inventory with optional loaded-user scope and baseline differences. |
| Workstation Setup | [Set-TechnicianPowerSettings.ps1](Workstation-Setup/Set-TechnicianPowerSettings.ps1) | Never-sleep timers, one-hour display timeout, visible unattended sleep and supported USB power controls. |

## Audits

Examples assume the ScriptLibrary root is the current directory. Replace example paths and queue names with your environment's values.

```powershell
.\Windows\Device-Information\Get-ConnectedPeripheralAudit.ps1
.\Windows\Device-Information\Get-ConnectedMonitorDetails.ps1 -IncludeSerialNumbers
.\Windows\Software\Get-InstalledSoftwareAudit.ps1 -IncludeAppx
.\Windows\Software\Get-InstalledSoftwareAudit.ps1 -IncludeLoadedUserHives -AllUsersAppx
.\Windows\Software\Get-InstalledSoftwareAudit.ps1 -BaselineCsv 'C:\Audit\PriorRun\software.csv'
.\Windows\Security\Test-Php2ShellExposure.ps1 -SearchRoot 'C:\VendorApplication'
.\Windows\Security\Test-Php2ShellExposure.ps1 -PhpPath 'C:\PHP\php-cgi.exe' `
    -ApacheConfigPath 'C:\Apache24\conf\httpd.conf' -PhpIniPath 'C:\PHP\php.ini'
```

Peripheral presence comes from the current PnP inventory when available. A CIM fallback retains **Unknown** presence rather than asserting that every registered device is connected. Full instance identifiers and monitor serials are masked by default. Include serial numbers only when needed for asset tracking.

Monitor dimensions come from EDID/WMI and can be absent or inaccurate for docks, KVMs, virtual displays and some drivers. Preferred mode is separate from the current per-monitor desktop mode. This tool reports the latter **Unknown** when it has no reliable per-monitor source; GPU-level resolution is not substituted.

Software inventory reads both uninstall registry views. Other user hives are queried only if already loaded; no hives are mounted. All-user AppX inventory requires elevation. Portable applications and unloaded user profiles can be missing. Use the same flags, identity and privileges when comparing inventories; differences are inventory evidence, not vulnerability verdicts. The previous `Get-InstalledSoftware.ps1` remains available for the simpler report.

The PHP audit uses the [PHP project's advisory](https://www.php.net/archive/2026.php#2026-10-21-5), reviewed **2026-10-23**. Published fixed upstream versions for both requested CVEs are **8.2.35, 8.3.36, 8.4.27 and 8.5.12**. Discovery includes selected common folders, explicit paths, PATH, running PHP image paths and IIS mappings. Add vendor roots and explicit Apache configurations to improve coverage. The advisory covers web PHP beyond Windows CGI.

The checker reads metadata without executing discovered binaries or sending exploit traffic. A matching fixed version is recorded as `MeetsPublishedFixedVersion`; complete asset coverage, vendor backports, wrapper/embedded PHP versions, integrity, effective configuration and replacement of already loaded web workers require further evidence. Unknown branches and prerelease builds are not declared fixed. Optional ini values are selected file settings, not effective SAPI/pool/application values. This is an audit, with no updates, web-server changes or restarts.

## Repair and cleanup

The four change tools default to a plan. `-Apply` enables their guarded actions. `-WhatIf` previews an apply run and still writes the report. Elevation is required where Windows servicing, system Temp, spool recovery or machine power settings require it.

```powershell
# Review, diagnose, then repair if appropriate.
.\Windows\Troubleshooting\Repair-WindowsSystemFiles.ps1
.\Windows\Troubleshooting\Repair-WindowsSystemFiles.ps1 -Diagnose
.\Windows\Troubleshooting\Repair-WindowsSystemFiles.ps1 -Apply -WhatIf
.\Windows\Troubleshooting\Repair-WindowsSystemFiles.ps1 -Apply -SkipRestartPrompt

# An optional matching Windows repair image.
.\Windows\Troubleshooting\Repair-WindowsSystemFiles.ps1 -Apply `
    -Source 'D:\sources\install.wim' -SourceIndex 2 -LimitAccess -SkipRestartPrompt

# Queue-specific cancellation, followed by optional global spool cache recovery.
.\Windows\Printing\Clear-PrinterQueueAndCache.ps1 -PrinterName 'Office Printer'
.\Windows\Printing\Clear-PrinterQueueAndCache.ps1 -PrinterName 'Office Printer' -Apply
.\Windows\Printing\Clear-PrinterQueueAndCache.ps1 -AllPrinters -ClearSpoolCache -Apply

# Clean known temporary folders; optionally include closed-browser caches.
.\Windows\Storage-and-Permissions\Clear-TemporaryFiles.ps1 -OlderThanDays 14
.\Windows\Storage-and-Permissions\Clear-TemporaryFiles.ps1 -OlderThanDays 14 -Apply -WhatIf
.\Windows\Storage-and-Permissions\Clear-TemporaryFiles.ps1 -OlderThanDays 14 `
    -IncludeSystemTemp -IncludeBrowserCache -Apply
```

DISM uses `NoRestart`. A DISM failure or restart-required result stops the sequence before SFC. Native output and exit codes remain in the report; successful completion alone does not establish clean system files. If DISM requires a reboot, rerun after the separately approved restart to complete SFC. Windows Update may supply repair content unless `-LimitAccess` is selected. A source image must match the installed Windows version, edition, language and servicing level. The earlier diagnostic-only `Test-SystemFileHealth.ps1` remains available.

Queue cancellation removes the discovered job IDs for the selected queues. **Spool cache recovery affects all local queues**, requires `-AllPrinters -ClearSpoolCache`, and supports only the default validated spool directory. It removes only regular SPL/SHD files and preserves printer drivers. A running Spooler is stopped/restored only after a separate confirmation. `-SkipRestartPrompt` defers that cache work; it does not cancel a separately requested queue-cancellation action. Keep the recovery window free of new print submissions.

Temporary cleanup considers regular files older than the selected last-write threshold. It skips reparse points, checks parent paths and rechecks file age/modification before deletion. Browser caches require closed browser processes. Locked or changed files are skipped. It leaves directories, Downloads, Installer, WinSxS, Prefetch, browser settings, cookies and password stores alone. Limits can leave files uninspected. This is routine maintenance for trusted local folders, not a deletion boundary against a hostile process racing filesystem changes.

## Power profile

```powershell
.\Windows\Workstation-Setup\Set-TechnicianPowerSettings.ps1
.\Windows\Workstation-Setup\Set-TechnicianPowerSettings.ps1 -Apply -WhatIf
.\Windows\Workstation-Setup\Set-TechnicianPowerSettings.ps1 -Apply

# AC only, with no optional restart prompt.
.\Windows\Workstation-Setup\Set-TechnicianPowerSettings.ps1 `
    -Apply -PowerSource AC -SkipRestartPrompt
```

By default, the active plan is selected and **both AC and DC** values are planned: sleep, unattended sleep and hibernate idle timers become zero (never); the display timer becomes 3,600 seconds; USB selective suspend becomes disabled. The hidden unattended sleep setting is made visible. Changing an idle hibernate timer does not remove the hibernation feature or its file; `-DisableHibernation` explicitly requests that additional action and also affects Fast Startup.

Device power saving uses exact matches between present USB input devices/ancestors and driver-exposed WMI power controls. It does not alter unrelated device registry keys. Drivers without a matching control remain Unknown. Input-device scope is the default; `-UsbScope AllUsb` broadens the request. A selected USB hub can also serve other peripherals. Stored-value verification does not override firmware, Modern Standby, lock-screen/presence sensing, critical-battery behavior, Group Policy or MDM. Wake-on-input policy is separate. Original values and reviewed recovery instructions are saved before changes.

Required servicing/Spooler restarts ask for separate confirmation. The power script offers a computer restart only with `-OfferRestart`, then asks separately. `-SkipRestartPrompt` always defers; `-Confirm:$false` does not bypass these separate restart questions.

## Reports and validation

Each run creates a unique folder under `Windows\Reports`; use `-OutputDirectory` to select another location. Review CSV/JSON status and error records. Reports may contain device IDs (when opted in), user SIDs, software registrations, file paths and diagnostic log excerpts; handle them as support evidence. Reports and test artifacts are not committed.

Run the isolated tests from a native Windows PowerShell 5.1 session:

```powershell
.\Windows\Technician-Tools-Validation\Invoke-TechnicianToolsValidation.ps1
```

See [validation details](TECHNICIAN-TOOLS-VALIDATION.md). Tests exercise mock providers and private fixtures; they do not perform servicing, cancel real print jobs, clean user folders, modify power settings or prove successful remediation on every driver/server. Configuration changes and PHP web-worker patch state need verification on the target machine.
