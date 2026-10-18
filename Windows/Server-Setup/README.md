# Server-Setup  [Usage, prerequisites, restart confirmation and examples](../SERVER-SETUP-GUIDE.md).  | Script | What it does | |---|---|
| [Initialize-SqlServerPrerequisites.ps1](Initialize-SqlServerPrerequisites.ps1) | Checks SQL preparation baselines and creates new protected data, log, tempdb and backup directories. |
| [Initialize-WindowsServer.ps1](Initialize-WindowsServer.ps1) | Plans or applies selected server naming, time zone and PowerShell remoting settings. |
| [Install-DhcpServer.ps1](Install-DhcpServer.ps1) | Plans or installs the local DHCP role and optionally creates one IPv4 scope with safe options and explicit AD authorization. |
| [Install-DnsServer.ps1](Install-DnsServer.ps1) | Plans or installs the local DNS role and safely adds optional primary zones and forwarders. |
| [Install-DomainController.ps1](Install-DomainController.ps1) | Plans or stages AD DS and, when explicitly requested, promotes this server into a new forest or an existing domain. |
| [Install-FileServer.ps1](Install-FileServer.ps1) | Plan or install the File Server role, protected NTFS folders, and encrypted SMB shares from JSON. |
| [Install-FsrmServer.ps1](Install-FsrmServer.ps1) | Plan or install File Server Resource Manager and optional folder quotas from JSON. |
| [Install-HyperVHost.ps1](Install-HyperVHost.ps1) | Plan or install Hyper-V and optionally create an external switch in a separate run. |
| [Install-NpsServer.ps1](Install-NpsServer.ps1) | Plans or installs NPS and optionally creates one trusted RADIUS client on a member server. |
| [Install-PrintServer.ps1](Install-PrintServer.ps1) | Plan or install the Print Server role and optional controlled TCP/IP printer queues from JSON. |
| [Install-RemoteDesktopServer.ps1](Install-RemoteDesktopServer.ps1) | Stage RDS roles, then optionally create a new single-host session deployment with explicit licensing. |
| [Install-WebServer.ps1](Install-WebServer.ps1) | Stage IIS features and optionally create new stopped sites and application pools from JSON. |
| [Install-WindowsServerBackup.ps1](Install-WindowsServerBackup.ps1) | Plans or installs Windows Server Backup and optionally creates a new scheduled local-volume policy. |
| [Join-ServerDomain.ps1](Join-ServerDomain.ps1) | Plans or joins the local workgroup server to an Active Directory domain and reports any required restart. |
| [Set-ServerNetwork.ps1](Set-ServerNetwork.ps1) | Plans or applies one explicit static IPv4 address, optional gateway and ordered DNS server list. |

Copy and edit files in [config](config) before requesting configuration. Default is plan only; Apply and separate restart confirmation are required.
