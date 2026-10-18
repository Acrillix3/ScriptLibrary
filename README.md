# ScriptLibrary

Scripts are grouped by operating system, then by the task you need to perform.

## Windows

Run the PowerShell scripts with Windows PowerShell 5.1. Each script starts with three short sections: What it does, Available flags, and How it works. Standard PowerShell common parameters, such as -Verbose and -ErrorAction, are also available.

| Category | Scripts |
|---|---|
| [Active Directory](Windows/Active-Directory) | Get-ADUserStatus, Get-ADGroupMembership, Invoke-ADAudit |
| [Device information](Windows/Device-Information) | Get-DeviceInformation, Export-BatteryHealth |
| [Network and DNS](Windows/Network-and-DNS) | Test-NetworkDiagnostics, Test-MappedDrives, Invoke-DNSAudit |
| [Printing](Windows/Printing) | Get-PrinterDiagnostics |
| [Services](Windows/Services) | Get-ServiceHealth |
| [Software](Windows/Software) | Get-InstalledSoftware |
| [Storage and permissions](Windows/Storage-and-Permissions) | Get-DiskSpaceReport, Find-LargeFiles, Export-FolderPermissions |
| [Troubleshooting](Windows/Troubleshooting) | Export-RecentEventErrors, Collect-SupportEvidence |
| [Workstation setup](Windows/Workstation-Setup) | Test-WorkstationReadiness and its example configuration |

Examples below assume your current directory is the ScriptLibrary root:

~~~powershell
.\Windows\Device-Information\Get-DeviceInformation.ps1
.\Windows\Network-and-DNS\Test-NetworkDiagnostics.ps1 -Target fileserver.contoso.com -Port 445
.\Windows\Active-Directory\Invoke-ADAudit.ps1 -Server dc01.contoso.com
.\Windows\Network-and-DNS\Invoke-DNSAudit.ps1 -ComputerName dc01.contoso.com -ExpectedDomain contoso.com
~~~

Replace example names and paths with values from your environment. All scripts write reports without making configuration changes. By default, reports go into Windows\Reports; use -OutputDirectory to choose another destination. Each run creates its own report folder.

AD scripts require the Microsoft ActiveDirectory module. The DNS audit requires DnsServer; printing diagnostics require PrintManagement. Use an account that can read the requested data. User-specific software, printers, and mapped drives reflect the executing user. Audit results that are partial or unknown need their error reports reviewed.

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
