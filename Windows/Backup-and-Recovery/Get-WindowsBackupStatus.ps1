<#
What it does:
  Reports local Windows Server Backup jobs, summary history, and cataloged backup versions.

Available flags:
  -PreviousJobCount: Previous backup or recovery jobs to query (default 20).
  -MaxBackupSets: Maximum catalog entries to export (default 100).
  -MaxBackupAgeHours: Age threshold for cataloged backup versions (default 48).
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Reads WindowsServerBackup using administrator or Backup Operators access. Current jobs, previous
  jobs, summary, and local catalog are queried independently. No backup or restore runs. Catalog
  entries and successful jobs do not establish recoverability.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1,1000)][int]$PreviousJobCount=20,
    [ValidateRange(1,10000)][int]$MaxBackupSets=100,
    [ValidateRange(1,876000)][int]$MaxBackupAgeHours=48,
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

$currentRows=@();$previousRows=@();$historyRows=@();$setRows=@();$backupSetCapReached=$false;$newest=$null;$newestAge=$null;$freshness='Unknown';$catalogStatus='Unknown'
$tools=Invoke-ReportQuery -Section 'Windows Server Backup tools' -RequireData -Action { Import-Module WindowsServerBackup -ErrorAction Stop; 'Available' }
function Convert-BackupJobRow {
    param($Job,[string]$Kind)
    [pscustomobject]@{Kind=$Kind;JobState=[string]$Job.JobState;JobType=[string]$Job.JobType;StartTime=$Job.StartTime;EndTime=$Job.EndTime;HResult=$Job.HResult;DetailedHResult=$Job.DetailedHResult}
}
if($tools.Succeeded){
    $current=Invoke-ReportQuery -Section 'Current backup or recovery job' -Action { Get-WBJob -ErrorAction Stop }
    $currentRows=@($current.Data | ForEach-Object {Convert-BackupJobRow $_ 'Current'})
    $previous=Invoke-ReportQuery -Section 'Previous backup or recovery jobs' -Action { Get-WBJob -Previous $PreviousJobCount -ErrorAction Stop | Select-Object -First $PreviousJobCount }
    $previousRows=@($previous.Data | ForEach-Object {Convert-BackupJobRow $_ 'Previous'})
    $history=Invoke-ReportQuery -Section 'Backup summary history' -RequireData -Action { Get-WBSummary -ErrorAction Stop }
    $historyRows=@($history.Data | Select-Object LastBackupTime,LastSuccessfulBackupTime,LastBackupResultHR,NextBackupTime,NumberOfVersions)
    $sets=Invoke-ReportQuery -Section 'Local backup catalog versions' -Action { Get-WBBackupSet -ErrorAction Stop | Select-Object -First ($MaxBackupSets+1) }
    $backupSetCapReached=$sets.Data.Count -gt $MaxBackupSets
    $setRows=@($sets.Data | Select-Object -First $MaxBackupSets | ForEach-Object { [pscustomobject]@{VersionId=$_.VersionId;BackupTime=$_.BackupTime} })
    if($sets.Succeeded){
        $catalogStatus=$(if($setRows.Count){'Collected'}else{'Empty'})
        $times=@($setRows | Where-Object BackupTime | ForEach-Object {[datetime]$_.BackupTime} | Sort-Object -Descending)
        if($times.Count){$newest=$times[0];$newestAge=[math]::Round(((Get-Date)-$newest).TotalHours,2);$freshness=$(if($backupSetCapReached){'Unknown: catalog cap reached'}elseif($newestAge -ge $MaxBackupAgeHours){'Review age threshold'}else{'Below age threshold'})}
        elseif(-not $setRows.Count){$freshness='No catalog versions returned'}
    }
}
Write-ReportCsv 'current-jobs' $currentRows @('Kind','JobState','JobType','StartTime','EndTime','HResult','DetailedHResult')
Write-ReportCsv 'previous-jobs' $previousRows @('Kind','JobState','JobType','StartTime','EndTime','HResult','DetailedHResult')
Write-ReportCsv 'backup-summary' $historyRows @('LastBackupTime','LastSuccessfulBackupTime','LastBackupResultHR','NextBackupTime','NumberOfVersions')
Write-ReportCsv 'catalog-versions' $setRows @('VersionId','BackupTime')
$summaryData=[pscustomobject]@{CurrentJobCount=$currentRows.Count;PreviousJobCount=$previousRows.Count;PreviousJobsWithNonzeroHResult=@($previousRows | Where-Object {$null -ne $_.HResult -and [long]$_.HResult -ne 0}).Count;CatalogStatus=$catalogStatus;CatalogVersionCount=$setRows.Count;BackupSetCapReached=$backupSetCapReached;NewestInspectedVersionTime=$newest;NewestInspectedVersionAgeHours=$newestAge;MaxBackupAgeHours=$MaxBackupAgeHours;CatalogAgeFlag=$freshness;Recoverability='Not tested'}
Complete-Report $summaryData @('Windows Server Backup only; third-party backup products and client backup features are outside this report.','An empty current-job result can mean no operation is running. Review each collection status before interpreting empty files.','Catalog results come from the local system catalog. Their presence and age do not prove backup media availability, consistency, or successful recovery.','No restore validation is performed. The catalog cap limits inspected results; provider calls are not given a hard timeout.')

