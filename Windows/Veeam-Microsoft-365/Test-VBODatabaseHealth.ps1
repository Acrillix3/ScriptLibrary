<#
What it does:
  Discovers configured active Veeam database endpoints and optionally tests read-only engine metadata.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9191.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -QueryDatabase: Opt in to fixed read-only engine metadata queries.
  -DatabaseCredential: SQL Server PSCredential only; integrated Windows authentication when omitted.
  -PsqlPath: Optional path to a compatible psql.exe for PostgreSQL metadata.
  -PostgresUser: Optional libpq user; current libpq/SSPI identity when omitted.
  -PostgresPassFile: Optional existing, secured libpq password file; never copied into reports.
  -ConnectionTimeoutSeconds: Database connection timeout; default 10.
  -QueryTimeoutSeconds: Engine statement timeout; default 30.
  -MaxDatabases: Maximum configured endpoints per inspected host; default 64.
  -ProxyComputerName: Up to 32 additional Windows proxies to inspect through WinRM.

How it works:
  Uses the shared implementation in Windows\lib; copy the complete Windows folder.
  Reads only selected active database configuration fields on the requested server. Detects product version, uses WinRM from a workstation, and distinguishes missing access, untested engines, JET/ESE candidates, and incomplete scope.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9191,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [switch]$QueryDatabase,
    [PSCredential]$DatabaseCredential,
    [string]$PsqlPath,
    [string]$PostgresUser,
    [string]$PostgresPassFile,
    [ValidateRange(1,120)][int]$ConnectionTimeoutSeconds=10,
    [ValidateRange(1,300)][int]$QueryTimeoutSeconds=30,
    [ValidateRange(1,500)][int]$MaxDatabases=64, 
    [ValidateCount(0,32)][string[]]$ProxyComputerName=@()
)

$ErrorActionPreference='Stop'
$core=Join-Path $PSScriptRoot '..\lib\Invoke-VeeamDatabaseHealthCore.ps1'
if(-not (Test-Path -LiteralPath $core -PathType Leaf)){throw 'Missing shared Veeam implementation. Copy the complete Windows folder, including Windows\lib.'}
$forward=@{}
foreach($key in $PSBoundParameters.Keys){$forward[$key]=$PSBoundParameters[$key]}
$forward.Port=$Port
$forward.Product='VBO'
$forward.EntryPointName='Test-VBODatabaseHealth'
& $core @forward
