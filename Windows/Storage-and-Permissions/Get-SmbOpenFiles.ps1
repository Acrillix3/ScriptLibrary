<#
What it does:
  Lists files opened by SMB clients on this Windows file server.

Available flags:
  -ClientComputerName: Optional exact SMB client name or IP filter.
  -ClientUserName: Optional exact domain\user filter.
  -PathPattern: Optional wildcard against the server-side file path (default *).
  -MaxFiles: Maximum matching handles to report (5000 by default).
  -OutputDirectory: Report location (Windows\Reports by default).

How it works:
  Reads SMB handles, applies optional filters, and writes bounded CSV/JSON reports. Requires
  SmbShare and query permissions. Reports SMB handles, not every local file lock.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()][string]$ClientComputerName,
    [ValidateNotNullOrEmpty()][string]$ClientUserName,
    [ValidateNotNullOrEmpty()][string]$PathPattern = '*',
    [ValidateRange(1,100000)][int]$MaxFiles = 5000,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) {
    $OutputDirectory = Join-Path $PSScriptRoot '..\Reports'
}
$scriptLabel = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runName = '{0}-{1}-{2}' -f $scriptLabel,[datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),[guid]::NewGuid().ToString('N').Substring(0,8)
$reportDirectory = (New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force -ErrorAction Stop).FullName
$queryLog = New-Object 'System.Collections.Generic.List[object]'
$queryErrors = New-Object 'System.Collections.Generic.List[object]'
function Invoke-ReportQuery {
    param([string]$Section,[scriptblock]$Action,[switch]$RequireData)
    try {
        $items = @(& $Action)
        if ($RequireData -and $items.Count -eq 0) { throw 'Required data was not returned.' }
        $queryLog.Add([pscustomobject]@{Section=$Section;Status=$(if($items.Count){'Collected'}else{'Empty'});Count=$items.Count;Error=''})
        [pscustomobject]@{Succeeded=$true;Data=$items}
    } catch {
        $queryErrors.Add([pscustomobject]@{Section=$Section;Error=$_.Exception.Message;ErrorId=$_.FullyQualifiedErrorId})
        $queryLog.Add([pscustomobject]@{Section=$Section;Status='Unknown';Count=$null;Error=$_.Exception.Message})
        [pscustomobject]@{Succeeded=$false;Data=@()}
    }
}
function Write-ReportCsv {
    param([string]$Name,[object[]]$Rows,[string[]]$Columns)
    $path=Join-Path $reportDirectory ($Name+'.csv')
    if (@($Rows).Count) {
        $Rows | Select-Object -Property $Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    } else {
        (($Columns | ForEach-Object { '"'+$_.Replace('"','""')+'"' }) -join ',') | Set-Content -LiteralPath $path -Encoding UTF8
    }
}
function Complete-Report {
    param([object]$Data,[string[]]$Notes)
    Write-ReportCsv -Name 'collection-status' -Rows $queryLog.ToArray() -Columns @('Section','Status','Count','Error')
    Write-ReportCsv -Name 'query-errors' -Rows $queryErrors.ToArray() -Columns @('Section','Error','ErrorId')
    $status='Complete'
    if($queryErrors.Count){$status='Partial'}
    if($queryErrors.Count -and @($queryLog | Where-Object Status -ne 'Unknown').Count -eq 0){$status='Unavailable'}
    $summary=[pscustomobject]@{
        Script=$scriptLabel;ComputerName=$env:COMPUTERNAME;CollectedUtc=[datetime]::UtcNow.ToString('o')
        CollectionStatus=$status;QueryErrorCount=$queryErrors.Count;ReportDirectory=$reportDirectory
        Data=$Data;Sections=$queryLog.ToArray();Notes=@('Collection status describes available evidence, not overall system health.')+$Notes
    }
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $reportDirectory 'summary.json') -Encoding UTF8
    @(
        $scriptLabel
        ('Collection: {0}; query errors: {1}' -f $status,$queryErrors.Count)
        ('Reports: '+$reportDirectory)
        ''
        'Collection results:'
        ($queryLog | Format-Table Section,Status,Count -AutoSize | Out-String -Width 180)
        'Interpretation:'
        ($summary.Notes -join [Environment]::NewLine)
    ) | Set-Content -LiteralPath (Join-Path $reportDirectory 'overview.txt') -Encoding UTF8
    if($queryErrors.Count){Write-Warning 'Some data was unavailable; review query-errors.csv and collection-status.csv.'}
    $summary
}

$handles = Invoke-ReportQuery -Section 'SMB open files' -Action {
    $queryParameters = @{ErrorAction='Stop'}
    if ($ClientComputerName) { $queryParameters.ClientComputerName = $ClientComputerName }
    if ($ClientUserName) { $queryParameters.ClientUserName = $ClientUserName }
    # Select-Object bounds the retained result to one extra handle to detect truncation.
    Get-SmbOpenFile @queryParameters | Where-Object { $_.Path -like $PathPattern } | Select-Object -First ($MaxFiles+1)
}
$truncated = $null
$count = $null
$rows = @()
if ($handles.Succeeded) {
    $truncated = $handles.Data.Count -gt $MaxFiles
    $rows = @($handles.Data | Select-Object -First $MaxFiles | Select-Object FileId,SessionId,Path,ShareRelativePath,ClientComputerName,ClientUserName,Locks,ScopeName,ClusterNodeName)
    $count = $rows.Count
}
$clients = @($rows | Group-Object ClientComputerName,ClientUserName | ForEach-Object {
    [pscustomobject]@{ClientComputerName=$_.Group[0].ClientComputerName;ClientUserName=$_.Group[0].ClientUserName;ReportedOpenHandles=$_.Count}
})
Write-ReportCsv -Name 'smb-open-files' -Rows $rows -Columns @('FileId','SessionId','Path','ShareRelativePath','ClientComputerName','ClientUserName','Locks','ScopeName','ClusterNodeName')
Write-ReportCsv -Name 'smb-clients' -Rows $clients -Columns @('ClientComputerName','ClientUserName','ReportedOpenHandles')
Complete-Report -Data ([pscustomobject]@{ReportedHandleCount=$count;Truncated=$truncated;MaximumHandles=$MaxFiles;ClientFilter=$ClientComputerName;UserFilter=$ClientUserName;PathPattern=$PathPattern;Handles=$rows;Clients=$clients}) -Notes @(
    'Run on the server hosting the share, normally from an elevated session. This reports SMB server handles and does not identify every local process file lock.'
    'Counts describe the filtered, retained snapshot only. When Truncated is true, counts are lower bounds; SMB handles can change during collection.'
    'Query failures are Unknown, not zero open files. No file handle or client session is closed.'
)
