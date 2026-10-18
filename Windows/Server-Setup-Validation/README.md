# Server-Setup-Validation  [Usage, prerequisites, restart confirmation and examples](../SERVER-SETUP-GUIDE.md).  | Script | What it does | |---|---|
| [Invoke-ServerSetupValidation.ps1](Invoke-ServerSetupValidation.ps1) | Runs all five server setup validation suites with mocked Windows providers. |
| [Test-ApplicationRoleSetup.ps1](Test-ApplicationRoleSetup.ps1) | Runs isolated mocked checks for RDS, IIS, and Hyper-V setup tools without changing server roles. |
| [Test-BaseAndKeyRoleSetup.ps1](Test-BaseAndKeyRoleSetup.ps1) | Tests server baseline, network, SQL prerequisites, backup policy, NPS clients, and restart confirmation with mocked Windows providers. |
| [Test-IdentityServerSetup.ps1](Test-IdentityServerSetup.ps1) | Tests the four identity and network server setup tools with mocked Windows providers. |
| [Test-ServerSetupPackage.ps1](Test-ServerSetupPackage.ps1) | Checks the server setup package's syntax, documented flags, plan defaults and restart gates. |
| [Test-StorageAndPrintSetup.ps1](Test-StorageAndPrintSetup.ps1) | Tests file-server, print-server, and FSRM setup behavior with mocked Windows management commands. |
