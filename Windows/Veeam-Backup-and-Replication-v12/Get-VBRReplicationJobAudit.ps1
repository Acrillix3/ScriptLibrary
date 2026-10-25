<#
What it does:
  Reports classic VMware/Hyper-V replication job scheduling and configured object selections.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -NamePattern: Classic job-name wildcard; default *.
  -MaxJobs: Maximum matching jobs inspected; default 100.
  -MaxObjectsPerJob: Maximum configured selections per job; default 200.

How it works:
  Uses the shared implementation in Windows\lib; copy the complete Windows folder.
  Reads Get-VBRJob Replica jobs, schedule settings, and configured objects through installed v12 tools. Excludes CDP and failover state evaluation; no replication, failover, or configuration change occurs.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateNotNullOrEmpty()][string]$NamePattern='*',
[ValidateRange(1,10000)][int]$MaxJobs=100,
[ValidateRange(1,10000)][int]$MaxObjectsPerJob=200
)

$ErrorActionPreference='Stop'
$core=Join-Path $PSScriptRoot '..\lib\Invoke-VbrClassicJobAuditCore.ps1'
if(-not (Test-Path -LiteralPath $core -PathType Leaf)){throw 'Missing shared Veeam implementation. Copy the complete Windows folder, including Windows\lib.'}
$forward=@{}
foreach($key in $PSBoundParameters.Keys){$forward[$key]=$PSBoundParameters[$key]}
$forward.Port=$Port
$forward.Product='VBR'
$forward.EntryPointName='Get-VBRReplicationJobAudit'
$forward.Family='Replication'
& $core @forward
