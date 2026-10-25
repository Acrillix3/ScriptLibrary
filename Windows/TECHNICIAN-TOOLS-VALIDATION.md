# Technician tools validation

Validated on **2026-10-24** with native **Windows PowerShell 5.1.26100.9711**. All **967 assertions passed**.

| Suite | Assertions | Evidence covered |
|---|---:|---|
| Package contracts | 82 | Nine expected scripts, PowerShell parsing, concise comment sections, report parameters, explicit apply and WhatIf support. |
| PHP2Shell | 75 | Fixed-version boundaries for four branches, legacy/prerelease/future/conflicting metadata, passive-command constraints, safe XML parsing and private path fixtures. |
| Hardware and software | 121 | Present-device projection, identifier masking, provider failure states, EDID decoding/dimensions/preferred modes, registry/AppX data transformations and baseline comparison. |
| Repair and cleanup | 29 | DISM failure/restart sequencing, full-entrypoint WhatIf reports, deferred/declined Spooler consent, mock stop/delete/restore, old/recent/changed files and path/reparse boundaries. |
| Power settings | 36 | Setting GUIDs, seconds/zero values, AC/DC plan, exact USB identity/ancestry, policy failures, original-value recovery and full-entrypoint WhatIf with zero device/power writes. |
| AMD GPU cache and restart | 73 | Known-cache boundaries, changed/locked files, AMD-only and multiple-device selection, previews, separate restart consent, native failures/reboot-required outcomes and stop-on-unverified-restart behavior. |
| Merged Windows tools | 53 | Actual-wrapper software schema and DISM/SFC mode, error, WhatIf and restart compatibility using private fixtures. |
| Implementation consolidation | 498 | Sixteen shared-core dependencies; 94 pre-merge Windows parameter names, types, validation/defaults and original positional order. |

The repair/cleanup suite also passed its 29 checks on PowerShell 7.6.5. Actual servicing execution remains restricted by that script to elevated native 64-bit Windows PowerShell 5.1.

The tests replace native tools and hardware/service providers with mocks and use private temporary/workspace files. They do not run real DISM/SFC repair, execute PHP, send exploit traffic, cancel print jobs, stop services, clean the user's Temp/cache folders, alter USB devices, set actual power policy, delete user shader caches or restart an actual graphics device. The power interop declarations compiled without invoking their live APIs during the suite.

No live AMD GPU reset/cache purge, driver/monitor matrix, representative Windows Server servicing test, real printer recovery, real PHP web-worker patch verification, or production Group Policy/MDM integration test was performed. Source and fixture checks establish the tested logic and safeguards; they do not establish successful remediation on a particular machine.

From the repository root in Windows PowerShell 5.1:

```powershell
.\Windows\Technician-Tools-Validation\Invoke-TechnicianToolsValidation.ps1
```

Each suite can also run separately. The controller saves a structured validation summary under `Windows\Reports`; fixtures can retain local reports for inspection. See [the usage guide](TECHNICIAN-TOOLS.md) before applying changes.

Consolidation coverage and platform limits are summarized in [the consolidation validation report](../CONSOLIDATION-VALIDATION.md).
