# Validation record for the 20 additional scripts

Validated on October 18, 2026 with **Windows PowerShell 5.1.26100.9711**.

All 20 additions pass the PowerShell 5.1 parser. Their three-section headers cover every declared flag, their filenames have no leading numbers, and every script is located directly beneath a Windows task category. Each embeds its own reporting functions and computes the default report path after parameter binding.

**298 mock assertions/checks passed** across four isolated suites:

| Suite | Passed | Main coverage |
|---|---:|---|
| Update, restart indicators, performance, restart timeline, system-file diagnostics | 40 | UTC update history/HRESULTs, sanitized endpoints, registry failures, ConfigMgr indicator, raw disk timer/rate calculations, process CPU deltas, provider-specific events, message privacy, native exit codes, diagnostic-only modes, JSON validity. |
| Profiles, drivers, storage, SMB, Group Policy | 79 | Access failures, registry/path observations, missing hardware counters, driver metadata, SMB filters/caps, native gpresult success/failure and scope, syntax/headers. |
| DHCP, tasks, backup, IIS, Hyper-V | 120 | Documented DHCP statistics fields and missing-field handling, task result classification, independent role failures, backup/catalog scope, provider caps, missing modules, sensitive-field exclusion, syntax/headers. |
| Domain trust, time, RDP, certificates, firewall | 59 | Member/DC gating, raw w32tm results, local/remote scope, RDP firewall evidence, certificate dates/EKU/trust caps, filter failures, truncation, syntax/headers. |

An additional full-library gate checked all 20 new scripts for expected locations, parameter documentation, embedded reporting, and selected unexpected configuration-changing commands. This command-name guard supplements source review; it is not a security proof.

All 20 also completed separate Windows PowerShell **-File runs with no OutputDirectory argument**, creating reports under a disposable Windows\Reports directory. Query providers and native diagnostics were replaced with failure mocks so these checks exercised report defaults and unavailable-data handling without reading real system state.

Independent source/API review found and corrected a DHCP property-name mismatch and a UTC/local-time comparison in Windows Update history. It also verified disk counter formulas and prompted RDP firewall evidence and bounded certificate processing.

## Limits

These checks used simulated CIM, registry, COM, event, certificate, management-module, native-utility, and network responses. Test fixture/report writes were real; no live AD/DC, DHCP, IIS, backup, Hyper-V, SMB, firewall, or Windows repair diagnostic was run against the user's systems.

Tests validate script behavior and evidence handling. They do not certify every Windows edition/server release, driver/provider, permission model, remote-management arrangement, or production role. Missing features and denied data should appear in each script's collection status and errors; individual findings/counters may also remain unknown.

The production files contain no validation harness dependency. Existing 17 scripts were preserved; the library now contains 37 operational PowerShell scripts.
