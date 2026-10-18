<#
What it does:
  Runs the product's passive audit tools and summarizes their report locations and states.

Available flags:
  -Server: Veeam server; default localhost.
  -Port: Veeam console port; default 9191.
  -Credential: Optional Veeam PSCredential; current identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for host and version evidence.
  -OutputDirectory: Report destination; default Windows\Reports.
  -QueryDatabase: Opt in to fixed read-only engine metadata queries in the database tool.
  -DatabaseCredential: SQL Server PSCredential only; integrated Windows identity when omitted.
  -PsqlPath: Optional psql.exe path for PostgreSQL engine metadata.
  -PostgresUser: Optional libpq user; otherwise the current libpq/SSPI identity.
  -PostgresPassFile: Existing secured libpq password file; not copied or exported.
  -ProxyComputerName: Windows proxy hosts for Microsoft 365 database discovery; ignored for VBR.

How it works:
  Runs an explicit list of sibling scripts sequentially with their documented default limits.
  Each script creates and closes its own connection. Intensive integrity scans are excluded.
  Child errors and unknown results stay visible in suite-summary.csv; no jobs or repairs run.
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
    [ValidateCount(0,32)][string[]]$ProxyComputerName=@()
)
$ErrorActionPreference='Stop'
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$suiteDirectory=Join-Path $OutputDirectory ('VBO-audit-suite-'+(Get-Date -Format yyyyMMdd-HHmmss)+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $suiteDirectory -Force
$rows=New-Object 'System.Collections.Generic.List[object]'
$scripts=@(
    'Get-VBOBackupCopyJobAudit.ps1',
    'Get-VBOBackupJobAudit.ps1',
    'Get-VBOHostDiagnostics.ps1',
    'Get-VBOOrganizationAudit.ps1',
    'Get-VBOPlatformAudit.ps1',
    'Get-VBOProtectionAudit.ps1',
    'Get-VBOProxyAudit.ps1',
    'Get-VBORepositoryAudit.ps1',
    'Get-VBOSessionAudit.ps1',
    'Test-VBOConnectivity.ps1',
    'Test-VBODatabaseHealth.ps1'
)
foreach($name in $scripts){
    $arguments=@{Server=$Server;Port=$Port;OutputDirectory=$suiteDirectory}
    if($Credential){$arguments.Credential=$Credential}
    if($HostCredential){$arguments.HostCredential=$HostCredential}
    if($name -like 'Test-*DatabaseHealth.ps1'){
        $arguments.QueryDatabase=$QueryDatabase
        if($DatabaseCredential){$arguments.DatabaseCredential=$DatabaseCredential}
        if($PsqlPath){$arguments.PsqlPath=$PsqlPath}
        if($PostgresUser){$arguments.PostgresUser=$PostgresUser}
        if($PostgresPassFile){$arguments.PostgresPassFile=$PostgresPassFile}
        if('VBO' -eq 'VBO'){$arguments.ProxyComputerName=$ProxyComputerName}
    }
    try{
        $path=Join-Path $PSScriptRoot $name
        if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw [IO.FileNotFoundException]::new('Missing sibling tool')}
        $result=& $path @arguments
        if($null -eq $result -or -not $result.ReportDirectory){throw [InvalidOperationException]::new('Tool did not produce a report summary')}
        $rows.Add([pscustomobject]@{Script=$name;State=$result.State;ReportDirectory=$result.ReportDirectory;ErrorType=$null})
    }catch{
        $rows.Add([pscustomobject]@{Script=$name;State='Incomplete';ReportDirectory=$null;ErrorType=$_.Exception.GetType().FullName})
    }
}
$rows.ToArray() | Export-Csv -LiteralPath (Join-Path $suiteDirectory 'suite-summary.csv') -NoTypeInformation -Encoding UTF8
@('Review each child findings.csv, collection-status.csv and summary.json. Empty results and successful API connections do not establish recoverability. Intensive CRC/repository integrity operations must be run separately with explicit flags.','Run the suite in a fresh PowerShell process using the runtime supported by the installed Veeam console. The default per-tool row caps apply; rerun individual tools with larger limits where required.') | Set-Content -LiteralPath (Join-Path $suiteDirectory 'README.txt') -Encoding UTF8
[pscustomobject]@{Server=$Server;Scripts=$rows.Count;Fail=@($rows | Where-Object State -eq Fail).Count;Incomplete=@($rows | Where-Object State -eq Incomplete).Count;Review=@($rows | Where-Object State -eq Review).Count;ReportDirectory=[IO.Path]::GetFullPath($suiteDirectory)}