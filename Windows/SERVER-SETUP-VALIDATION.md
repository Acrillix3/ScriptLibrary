# Server setup validation

Validated on 2026-10-18 using native **Windows PowerShell 5.1.26100.9711**. All five suites passed: **989 assertions**.

| Suite | Assertions | Main coverage |
|---|---:|---|
| Test-ServerSetupPackage.ps1 | 328 | All 15 tools and six test/runner scripts parse; short headers, declared flags, Apply defaults, central restart gates, no forced computer reboot, valid JSON examples |
| Test-IdentityServerSetup.ps1 | 232 | 51 scenarios for AD DS prerequisites/promotion, compatible new-forest levels, joins, DNS zones/forwarders, DHCP ranges/options/authorization/activation, deferred stages and credentials |
| Test-StorageAndPrintSetup.ps1 | 89 | Protected ACLs, encrypted shares, existing-setting conflicts, exact drivers/ports/queue permissions, quota scope and limits |
| Test-ApplicationRoleSetup.ps1 | 71 | RDS role stages, licensing/group verification and failure quarantine; IIS stopped/secure commit and race checks; Hyper-V adapter/switch conflicts |
| Test-BaseAndKeyRoleSetup.ps1 | 269 | Baseline/network/SQL/backup/NPS behavior; server/client/admin guards; original-policy races; SQL ownership/path races; separate positive, declined, unavailable and failed server/service restart consent |

From the repository root:

~~~powershell
.\Windows\Server-Setup-Validation\Invoke-ServerSetupValidation.ps1
~~~

The runner executes each suite in a fresh native Windows PowerShell 5.1 process, saves logs and exit codes, and fails if a suite fails. No Pester installation is required. Individual test flags are listed at the beginning of each script. Keep report destinations reasonably short for Windows PowerShell 5.1 file APIs.

The tests execute copies of the actual standalone scripts with local fixtures and mocked providers. Administrator and interactive-consent probes are replaced in those fixture copies. The SQL directory native call is substituted so tests can examine ownership/ACL behavior without creating production directories. IIS configuration is also tested through an in-memory fake API model, including a pre-commit conflict race.

**No live server role, domain, DHCP scope, SQL component, production folder/share, printer, RDS farm, backup policy, RADIUS client, VM switch, computer restart or service restart was changed.** The tests simulate both Windows Server 2022 and 2025; passing fixtures does not establish production role compatibility, service availability or recoverability in a specific environment.

Microsoft references and operational scope are in [SERVER-SETUP-GUIDE.md](SERVER-SETUP-GUIDE.md). Apply on the intended server, review reports and native logs, then perform role-specific client, authentication, connectivity and recovery acceptance tests.

Installation verification checks source-copy hashes, parses all installed PowerShell scripts and confirms that the pre-existing 74 scripts and Linux files remain unchanged.
