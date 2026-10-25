<#
What it does:
  Collects Windows Veeam service, local-disk, memory, uptime, and recent event metadata.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9191.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -Hours: Event look-back window; default 48.
  -MaxEvents: Matching event rows retained; default 200.
  -MinimumFreePercent: Local-disk free-space review threshold; default 15.

How it works:
  Uses the shared implementation in Windows\lib; copy the complete Windows folder.
  Reads the requested Windows server locally or through WinRM. Exports selected service/CIM and event metadata without command lines, event messages, or account secrets; does not restart services or change the host.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9191,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateRange(1,8760)][int]$Hours=48,
    [ValidateRange(1,10000)][int]$MaxEvents=200,
    [ValidateRange(1,99)][int]$MinimumFreePercent=15
)

$ErrorActionPreference='Stop'
$core=Join-Path $PSScriptRoot '..\lib\Invoke-VeeamHostDiagnosticsCore.ps1'
if(-not (Test-Path -LiteralPath $core -PathType Leaf)){throw 'Missing shared Veeam implementation. Copy the complete Windows folder, including Windows\lib.'}
$forward=@{}
foreach($key in $PSBoundParameters.Keys){$forward[$key]=$PSBoundParameters[$key]}
$forward.Port=$Port
$forward.Product='VBO'
$forward.EntryPointName='Get-VBOHostDiagnostics'
& $core @forward
