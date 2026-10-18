# ScriptLibrary

Scripts are grouped by operating system, then by the task you need to perform.

## Windows

General Windows tools use Windows PowerShell 5.1. Veeam tools require the runtime supported by the installed Veeam console; see the [Veeam guide](Windows/VEEAM-GUIDE.md). Each script starts with three short sections: What it does, Available flags, and How it works. Standard PowerShell common parameters, such as -Verbose and -ErrorAction, are also available.

| Category | Purpose | Scripts |
|---|---|---:|
| [Active Directory](Windows/Active-Directory) | Accounts, memberships, domain trust, Group Policy, and AD audits | 5 |
| [Backup and Recovery](Windows/Backup-and-Recovery) | Windows Server Backup job and catalog evidence | 1 |
| [Device Information](Windows/Device-Information) | Hardware inventory, batteries, and driver issues | 3 |
| [Network and DNS](Windows/Network-and-DNS) | Connectivity, DNS, DHCP, remote desktop, mapped drives, and time | 6 |
| [Printing](Windows/Printing) | Printers, ports, queues, and spooler diagnostics | 1 |
| [Security](Windows/Security) | Certificate metadata and firewall rule evidence | 2 |
| [Server Setup](Windows/Server-Setup) | Windows Server 2022/2025 role and baseline setup; SQL prerequisites only; confirmed restarts | 15 |
| [Server Setup Validation](Windows/Server-Setup-Validation) | Mocked server setup tests and package validation | 6 |
| [Services](Windows/Services) | Windows services and scheduled tasks | 2 |
| [Software](Windows/Software) | Installed application inventory | 1 |
| [Storage and Permissions](Windows/Storage-and-Permissions) | Disk capacity, file sizes, storage health, permissions, and SMB handles | 5 |
| [Troubleshooting](Windows/Troubleshooting) | Events, evidence packages, updates, performance, profiles, restarts, and system files | 8 |
| [Veeam Backup and Replication v12](Windows/Veeam-Backup-and-Replication-v12) | Database, repository, WAN, proxy, job, session and recovery-point audits/tests | 17 |
| [Veeam Microsoft 365](Windows/Veeam-Microsoft-365) | Auto-detected v7/v8 platform, database/cache, proxy, repository, job and protection audits/tests | 13 |
| [Veeam Validation](Windows/Veeam-Validation) | Mocked code tests and package validation | 7 |
| [Virtualization](Windows/Virtualization) | Hyper-V VM, integration, storage-path, and checkpoint evidence | 1 |
| [Web Services](Windows/Web-Services) | IIS websites, bindings, application pools, and recent events | 1 |
| [Workstation Setup](Windows/Workstation-Setup) | Readiness checks against an editable baseline | 1 |

There are 82 operational Windows scripts and 13 code-validation scripts. See the [complete script index](Windows/SCRIPT-INDEX.md) and [examples for the 20 new tools](Windows/NEW-SCRIPTS.md). Validation details are in [Windows/VALIDATION.md](Windows/VALIDATION.md). Veeam usage and examples are in [Windows/VEEAM-GUIDE.md](Windows/VEEAM-GUIDE.md); Veeam test results are in [Windows/VEEAM-VALIDATION.md](Windows/VEEAM-VALIDATION.md). Server setup instructions are in [Windows/SERVER-SETUP-GUIDE.md](Windows/SERVER-SETUP-GUIDE.md), with [validation results](Windows/SERVER-SETUP-VALIDATION.md).

Examples below assume your current directory is the ScriptLibrary root:

~~~powershell
.\Windows\Device-Information\Get-DeviceInformation.ps1
.\Windows\Network-and-DNS\Test-NetworkDiagnostics.ps1 -Target fileserver.contoso.com -Port 445
.\Windows\Active-Directory\Invoke-ADAudit.ps1 -Server dc01.contoso.com
.\Windows\Network-and-DNS\Invoke-DNSAudit.ps1 -ComputerName dc01.contoso.com -ExpectedDomain contoso.com
~~~

Replace example names and paths with values from your environment. General tools and passive Veeam suites collect reports without changing configuration. Server setup tools default to plans, require -Apply for changes, and ask separately before required server/service restarts. Intensive Veeam integrity/CRC tests require explicit run flags and are excluded from the passive suites. By default, reports go into Windows\Reports; use -OutputDirectory to choose another destination. Each run creates its own report folder.

The original AD inventory/audit scripts require the Microsoft ActiveDirectory module; the new local trust and Group Policy tools use their documented Windows facilities. The DNS audit requires DnsServer; printing diagnostics require PrintManagement. Use an account that can read the requested data. User-specific software, printers, and mapped drives reflect the executing user. Audit results that are partial or unknown need their error reports reviewed.

For workstation readiness, copy and edit the example baseline before using it:

~~~powershell
Copy-Item '.\Windows\Workstation-Setup\config\workstation-requirements.example.json' '.\Windows\Workstation-Setup\config\workstation-requirements.json'
notepad '.\Windows\Workstation-Setup\config\workstation-requirements.json'
.\Windows\Workstation-Setup\Test-WorkstationReadiness.ps1 -ConfigPath '.\Windows\Workstation-Setup\config\workstation-requirements.json'
~~~

The example baseline is a starting point to customize, not a universal workstation requirement.

## Linux

Linux is prepared for future shell scripts with these categories:

- Device-Information
- Network-and-DNS
- Printing
- Services
- Software
- Storage-and-Permissions
- Troubleshooting
- Users-and-Groups
- Workstation-Setup

The .gitkeep files retain empty category folders in Git. All .ps1 scripts belong under Windows.
