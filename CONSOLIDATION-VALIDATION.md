# Consolidation validation

Completed **2026-10-24**. All **3,844 checks passed** in the combined source/mock/fixture coverage below. The Veeam suite also passed its 1,186 checks separately on PowerShell 7.6.5.

| Area | Checks | Runtime and coverage |
|---|---:|---|
| Technician tools and merge contracts | 967 | Native Windows PowerShell 5.1.26100.9711: existing 416 checks, 53 new actual-entrypoint software/DISM regressions and 498 source/API/dependency contracts. |
| Veeam | 1,186 | Seven suites on Windows PowerShell 5.1.26100.9711; same complete suite also passed on PowerShell 7.6.5. Includes 106 merged wrapper/core regressions. |
| Linux | 702 | Existing 637 checks retained, plus 65 actual-entrypoint regressions against private copied libraries. Git Bash/dash source and command-fixture execution on Windows. |
| Unchanged server setup tools | 989 | All five server setup validation suites passed again on native Windows PowerShell 5.1; operational role files remain unchanged. |

The 498 consolidation contracts cover sixteen public entrypoints, their eight shared engines, all **94 pre-existing declared Windows parameters**, their types/validation/defaults and original positional order. A new optional parameter does not displace an existing positional parameter. The mapping and parameter snapshots are stored under `Windows/Technician-Tools-Validation/config` for future regression checking.

The merged Windows tests invoke copied public entrypoints with substituted private native/registry/AppX providers. They check legacy CSV names/columns, AppX full package names, raw blank legacy metadata, expanded audit/baseline scope, existing CheckHealth/ScanHealth/SFC defaults, repair source handling, failure/restart sequencing, inherited WhatIf and separate restart consent. Existing 121 hardware/software and 29 repair/cleanup assertions remain passing.

The merged Veeam tests verify public product/port/credential/limit forwarding, VB365 proxy inputs, report identities and real private-core execution in sequential VBR12, VBO7 and VBO8 success/failure scenarios. They check owned-only disconnection and that caller script state does not leak between runs. Database/source-loader and package tests now follow the private core dependencies without removing their prior provider/failure scenarios.

The merged Linux tests execute all four original CUPS/SSH entrypoints with mocked external commands and private configuration/key/cache paths. They retain queue/global section distinctions, legacy evidence filenames, default versus Match-context SSH policy, credential redaction, producer failures and missing-provider Unknown behavior. Both new `.inc` files passed dash syntax checks. Python validation requires 3.10+; production `.sh` entrypoints retain their existing dependencies.

These are code/regression checks. **No live software inventory, servicing repair, Windows role/policy change, restart, Veeam/WinRM/database connection, CUPS operation, SSH authentication or external TCP probe was performed.** Live Windows/Veeam builds and Linux distributions still need their normal environment-specific validation. Helper extraction is not evidence of successful remediation or complete real-world platform coverage.

Run the existing Windows validation controllers and all five Linux runners as described in [the consolidation guide](CONSOLIDATION-GUIDE.md). Detailed suite reports are retained locally during a run under the selected output directory; reports are excluded from Git.
