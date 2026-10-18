# Windows Server setup tools

15 standalone tools target **Windows Server 2022 and 2025**, using **native 64-bit Windows PowerShell 5.1** on the intended server. Each defaults to a report-only plan. Use **Apply** to request changes; each operation supports **WhatIf** and **Confirm**.

These are individual role workflows. Select the tools for each server's intended role rather than installing every role on one machine. SQL preparation and RDS deployment refuse domain controllers.

## Review, apply, restart

From the ScriptLibrary root:

~~~powershell
# Review the plan.
.\Windows\Server-Setup\Initialize-WindowsServer.ps1 -NewComputerName FS01 -TimeZoneId 'UTC'

# Request those changes.
.\Windows\Server-Setup\Initialize-WindowsServer.ps1 -NewComputerName FS01 -TimeZoneId 'UTC' -Apply

# Preview an Apply run without making configuration changes.
.\Windows\Server-Setup\Initialize-WindowsServer.ps1 -NewComputerName FS01 -Apply -WhatIf
~~~

Run Apply in an elevated session. Plans and results go into a unique folder below **Windows\Reports**; use **OutputDirectory** to select another location. Read **plan.csv**, **checks.csv**, and **summary.json**. Reports are written even with WhatIf.

Required restarts ask a **separate confirmation after the report is saved**. Declining leaves the restart pending. **Confirm false does not approve a restart.** **SkipRestartPrompt** defers required server and service restarts for unattended runs; it never authorizes them. If confirmation is unavailable, the restart is deferred. Existing pending restarts block further setup until resolved.

~~~powershell
# Approve ordinary setup operations without interactive per-step questions,
# while explicitly leaving any required restart for later.
.\Windows\Server-Setup\Install-HyperVHost.ps1 -Apply -Confirm:$false -SkipRestartPrompt
~~~

Several roles use two passes: install the binaries/tools, complete a confirmed restart if required, then rerun with the configuration flags/file. This permits inspection of the actual role's existing settings before configuring it. A failed operation stops further changes. Previously completed steps remain applied; these scripts do not perform automatic rollback.

## Tools

| Tool | Scope |
|---|---|
| Initialize-WindowsServer.ps1 | Explicit name, time zone, and optional standard PowerShell remoting setup |
| Set-ServerNetwork.ps1 | One selected static IPv4 address, optional gateway, ordered DNS servers |
| Join-ServerDomain.ps1 | Join a workgroup server to the specified domain; preserves matching membership |
| Install-DomainController.ps1 | Stage AD DS, then promote a new forest or an additional DC with native prerequisite tests |
| Install-DnsServer.ps1 | DNS role, optional file/AD zones, and appended forwarders |
| Install-DhcpServer.ps1 | DHCP role, one inactive-by-default IPv4 scope, options, explicit AD authorization/activation |
| Install-FileServer.ps1 | File role, new protected NTFS folders, explicit grants and encrypted SMB shares |
| Install-FsrmServer.ps1 | FSRM role and explicit soft/hard quota definitions |
| Install-PrintServer.ps1 | Print role, trusted installed drivers, RAW TCP ports and restricted printer queues |
| Install-RemoteDesktopServer.ps1 | RDS roles, new single-server broker/web/session deployment, licensing reference and optional restricted collection |
| Initialize-SqlServerPrerequisites.ps1 | SQL 2022/2025 readiness baselines and new protected directories; no SQL installation |
| Install-WebServer.ps1 | IIS role and new stopped sites/pools with Windows authentication |
| Install-HyperVHost.ps1 | Hyper-V role and separately requested external virtual switch |
| Install-WindowsServerBackup.ps1 | Backup feature and optional new local-volume scheduled VSS-copy policy |
| Install-NpsServer.ps1 | NPS role and optional individual RADIUS client with a secure in-memory secret |

Role availability depends on edition and installation type. RDS requires Desktop Experience; other roles still require their Windows feature and management components to be available. These tools do not activate Windows, buy licenses, initialize/format disks, apply a universal security baseline, or replace application-specific acceptance testing.

## Suggested order

1. Prepare the VM/hardware and storage through your normal provisioning process.
2. Configure the name, time zone, explicit networking and DNS. Complete required restarts.
3. Create/promote a DC on its intended server, or join member servers to the domain.
4. Install the selected role, finish any required restart, then apply its reviewed configuration.
5. Review reports and use the library's AD, DNS, service, storage, print, IIS, Hyper-V and backup audit tools for live checks.

## Networking and domain membership

~~~powershell
.\Windows\Server-Setup\Set-ServerNetwork.ps1 -InterfaceAlias 'Ethernet' -IPAddress '10.20.30.20' -PrefixLength 24 -DefaultGateway '10.20.30.1' -DnsServer '10.20.30.10','10.20.30.11'
.\Windows\Server-Setup\Join-ServerDomain.ps1 -DomainName 'corp.example.com'
$domainCredential = Get-Credential
.\Windows\Server-Setup\Join-ServerDomain.ps1 -DomainName 'corp.example.com' -Credential $domainCredential -Apply
~~~

Use a local or out-of-band console for address/gateway/DNS changes because connectivity can drop. The network tool does not select an adapter automatically or remove existing static addresses/routes. DHCP conversion needs an explicit flag; converting the same currently leased address is deliberately refused. IPv6 remains enabled. Verify Windows Duplicate Address Detection and actual connectivity afterwards. [Microsoft's New-NetIPAddress reference](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netipaddress?view=windowsserver2025-ps) describes DHCP and address-detection behavior.

## Domain controller, DNS and DHCP

~~~powershell
# Stage AD DS first.
.\Windows\Server-Setup\Install-DomainController.ps1 -DomainName 'corp.example.com' -Apply

# After staging/restart, review promotion, then request it with a SecureString DSRM password.
$dsrmPassword = Read-Host 'DSRM password' -AsSecureString
.\Windows\Server-Setup\Install-DomainController.ps1 -DomainName 'corp.example.com' -Promote -SafeModeAdministratorPassword $dsrmPassword -Apply

# An additional controller uses Mode AdditionalDC and a deployment credential.
# Existing forests/domains are never recreated or demoted.

# DNS optional configuration after its role is installed:
.\Windows\Server-Setup\Install-DnsServer.ps1 -ZoneStorage ActiveDirectory -ReverseNetworkId '10.20.30.0/24' -ForwarderIPAddress '10.20.40.10'

# Stage DHCP first, then request a scope on a later run.
.\Windows\Server-Setup\Install-DhcpServer.ps1 -Apply
.\Windows\Server-Setup\Install-DhcpServer.ps1 -ScopeName 'Office' -StartRange '10.20.30.100' -EndRange '10.20.30.200' -SubnetMask '255.255.255.0' -RouterIPAddress '10.20.30.1' -DnsServerIPAddress '10.20.30.10' -DnsDomain 'corp.example.com'
~~~

Promotion requires preferred static IPv4 networking and successful native AD DS tests; no built-in prerequisite checks are skipped. New forests explicitly use the **2016 functional level** so both targeted server versions can host DCs. Additional-controller installation preserves the existing domain's functional level. Native automatic reboot is suppressed; the shared confirmation handles the required restart. See [Microsoft AD DS deployment](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-).

File-based DNS zones disable dynamic updates; AD zones require a DC and secure updates. Existing different zones/forwarders are not replaced. DHCP ranges/options are checked for overlap and drift. New scopes stay inactive unless **ActivateScope** is explicit. **AuthorizeInAD** additionally requires **AuthorizationIPAddress** matching this server and an identity with the appropriate AD permissions. Use these only after reviewing the intended network; [Microsoft DHCP installation guidance](https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/quickstart-install-configure-dhcp-server) describes the role and authorization workflow.

## Files, quotas, printers and IIS

Copy and edit the five example files in **Windows\Server-Setup\config**. Replace domain groups, paths, addresses and exact printer driver names before using them. Keep actual secrets out of JSON.

~~~powershell
Copy-Item '.\Windows\Server-Setup\config\file-server.example.json' '.\Windows\Server-Setup\config\file-server.json'
.\Windows\Server-Setup\Install-FileServer.ps1 -ConfigurationPath '.\Windows\Server-Setup\config\file-server.json'

# Print/FSRM/IIS: stage the role first, then use the edited configuration.
.\Windows\Server-Setup\Install-PrintServer.ps1 -Apply
.\Windows\Server-Setup\Install-FsrmServer.ps1 -Apply
.\Windows\Server-Setup\Install-WebServer.ps1 -Apply
~~~

File shares require explicit principals, protected NTFS ACLs and SMB encryption. Existing ACLs/shares must match; they are not replaced. Quotas default to soft limits; new hard quotas require empty targets. Printer setup uses exact preinstalled x64 drivers, with no download or Point-and-Print security relaxation. Install approved drivers separately before configuring queues.

IIS sites are created **stopped**, with anonymous authentication disabled and Windows authentication enabled. HTTP is loopback only; HTTPS requires an installed matching certificate. The script preserves pre-existing sites. On first role installation it stops/disables only the newly created default site; standard Windows role installation can briefly create that default site before it is stopped. Review content permissions, certificates, application requirements and bindings before starting a site.

## Remote Desktop Services

~~~powershell
.\Windows\Server-Setup\Install-RemoteDesktopServer.ps1 -Apply

# After role staging/restart, target an existing activated licensing server.
.\Windows\Server-Setup\Install-RemoteDesktopServer.ps1 -ConfigureDeployment -LicenseServer 'rdlic01.corp.example.com' -LicensingMode PerUser -CollectionName 'BusinessApps' -CollectionUserGroup 'CORP\RDS-Users'
~~~

This creates a **new** single-host session deployment; it does not edit an existing farm or provide high availability. Applying collection setup temporarily disables new sessions until explicit group access is verified. A failed collection/access step leaves new sessions disabled for console review; existing sessions stay connected.

Licensing-server activation, matching CALs/entitlements, trusted RDS certificates, Gateway design, external access and application installation remain environment-specific steps. See [Microsoft session deployment](https://learn.microsoft.com/en-us/powershell/module/remotedesktop/new-rdsessiondeployment?view=windowsserver2025-ps) and [RDS licensing configuration](https://learn.microsoft.com/en-us/powershell/module/remotedesktop/set-rdlicenseconfiguration?view=windowsserver2025-ps).

## SQL prerequisites only

~~~powershell
.\Windows\Server-Setup\Initialize-SqlServerPrerequisites.ps1 -SqlVersion 2022 -DataPath 'D:\SqlData' -LogPath 'L:\SqlLogs' -TempDbPath 'T:\SqlTempDb' -BackupPath 'B:\SqlBackups'
~~~

This checks .NET, memory and fixed-volume free-space baselines and can create new protected directories. Parent directories/volumes must already exist. Existing path ownership/permissions must match the baseline; paths, including their ancestors, cannot be reparse points. SQL Setup or a separate reviewed step must later grant the chosen SQL service identity access.

It installs no SQL components, downloads nothing, accepts no license, configures no database/instance, and opens no ports. The editable memory/free-space thresholds are preparation baselines rather than workload sizing. Validate edition support, CPU/storage layout/sector size, accounts, updates, backup isolation and other installer requirements separately against [SQL Server 2022 requirements](https://learn.microsoft.com/en-us/sql/sql-server/install/hardware-and-software-requirements-for-installing-sql-server-2022?view=sql-server-ver16) or [SQL Server 2025 requirements](https://learn.microsoft.com/en-us/sql/sql-server/install/hardware-and-software-requirements-for-installing-sql-server-2025?view=sql-server-ver17).

## Hyper-V, backup and NPS

Hyper-V setup stages the role first. A later **CreateSwitch** run requires exact **SwitchName** and **NetAdapterName** and preserves management OS connectivity. Creating an external switch can still interrupt the selected connection. No VM, VLAN, storage format or cluster is created.

Windows backup stages the feature, then accepts an edited **backup.example.json**. It creates only a **new** daily VSS-copy policy; an existing schedule is never replaced. It rechecks for conflicts at application time. No disk is formatted and no immediate backup starts, but the next selected schedule time can trigger a backup. A different volume letter does not establish independent backup storage. Test restore separately.

NPS stages the role, then can add one named IPv4 client with a **SharedSecret SecureString** of at least 16 characters. New clients require Message-Authenticator verification. Existing clients/secrets are not edited. Native NPS requires a string, so the secret is converted transiently in memory inside the gated action. Reports never contain it. The required **IAS service restart asks for separate confirmation**.

NPS installation adds default RADIUS firewall exceptions on all adapters. Scope those rules, configure AD registration, network/request policies, certificates and accounting, and test authentication before service acceptance. [Microsoft NPS installation](https://learn.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-manage-install) and [client creation](https://learn.microsoft.com/en-us/powershell/module/nps/new-npsradiusclient?view=windowsserver2025-ps) document those native behaviors.

## Validation and acceptance

~~~powershell
.\Windows\Server-Setup-Validation\Invoke-ServerSetupValidation.ps1
~~~

The included tests use fixtures and mocked providers. They never install a live role, contact a domain, configure a database, create a real RADIUS client, or restart a computer/service. See [SERVER-SETUP-VALIDATION.md](SERVER-SETUP-VALIDATION.md).

**Plan**, **Complete**, **Incomplete**, **Blocked**, **RestartRequired**, **ServiceRestartRequired** and **RestartRequested** describe this script's scope. They do not certify a complete production service. Review the native management logs after a failure and perform role-specific functional/client/recovery tests after applying on a server.
