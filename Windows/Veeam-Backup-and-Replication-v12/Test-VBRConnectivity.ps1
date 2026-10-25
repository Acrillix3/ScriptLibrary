<#
What it does:
  Tests DNS and TCP reachability from a chosen Windows host and records Veeam console authentication.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -Endpoint: Additional hostname:port or [IPv6]:port targets; default none.
  -ProbeComputerName: Windows source for network tests; default localhost.
  -TimeoutMilliseconds: TCP timeout per address, 100-60000; default 3000.

How it works:
  Uses the shared implementation in Windows\lib; copy the complete Windows folder.
  Resolves explicit endpoints and attempts bounded TCP connections locally or through WinRM. Reports only the tested path; TCP success is separate from Veeam authentication and data-path health.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateCount(0,100)][string[]]$Endpoint=@(),
    [string]$ProbeComputerName='localhost',
    [ValidateRange(100,60000)][int]$TimeoutMilliseconds=3000
)

$ErrorActionPreference='Stop'
$core=Join-Path $PSScriptRoot '..\lib\Invoke-VeeamConnectivityCore.ps1'
if(-not (Test-Path -LiteralPath $core -PathType Leaf)){throw 'Missing shared Veeam implementation. Copy the complete Windows folder, including Windows\lib.'}
$forward=@{}
foreach($key in $PSBoundParameters.Keys){$forward[$key]=$PSBoundParameters[$key]}
$forward.Port=$Port
$forward.Product='VBR'
$forward.EntryPointName='Test-VBRConnectivity'
& $core @forward
