<#
What it does:
  Builds a restart, bugcheck, and hardware-error timeline with available crash-dump metadata.

Available flags:
  -Days: Look-back window; default 14 days.
  -MaxEventsPerSource: Maximum events per selected provider; default 300.
  -MaxDumpFiles: Maximum minidump files listed; default 25.
  -IncludeMessages: Include event message text, which may contain user/application details.
  -OutputDirectory: Report destination; default Windows\Reports.

How it works:
  Queries specific System-log provider/event pairs and lists default Windows dump locations, sizes,
  and dates without reading dump contents. Access failures and query caps are explicit. Event
  41/6008 indicate an unclean shutdown but do not identify its cause.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
[ValidateRange(1,365)][int]$Days=14,
[ValidateRange(1,5000)][int]$MaxEventsPerSource=300,
[ValidateRange(1,500)][int]$MaxDumpFiles=25,
[switch]$IncludeMessages,
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

$cutoff=(Get-Date).AddDays(-$Days)
$timeline=New-Object 'System.Collections.Generic.List[object]'
$sourceCaps=New-Object 'System.Collections.Generic.List[object]'
$sources=@(
    @{Provider='Microsoft-Windows-Kernel-Power';Ids=@(41);Kind='UncleanRestart'},
    @{Provider='EventLog';Ids=@(6005,6006,6008,6009);Kind='EventLogStartStop'},
    @{Provider='User32';Ids=@(1074);Kind='RequestedShutdown'},
    @{Provider='Microsoft-Windows-WER-SystemErrorReporting';Ids=@(1001);Kind='Bugcheck'},
    @{Provider='Microsoft-Windows-Kernel-General';Ids=@(12,13);Kind='OperatingSystemStartStop'},
    @{Provider='Microsoft-Windows-WHEA-Logger';Ids=@(1,17,18,19,20,46);Kind='HardwareErrorEvidence'}
)
foreach($source in $sources){
    $result=Invoke-ReportQuery -Section ('Events: '+$source.Provider) -Action {
        try{Get-WinEvent -FilterHashtable @{LogName='System';ProviderName=$source.Provider;Id=$source.Ids;StartTime=$cutoff} -MaxEvents $MaxEventsPerSource -ErrorAction Stop}
        catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
    }
    $sourceCaps.Add([pscustomobject]@{Provider=$source.Provider;QuerySucceeded=$result.Succeeded;Count=$(if($result.Succeeded){$result.Data.Count}else{$null});AtLimit=($result.Data.Count -ge $MaxEventsPerSource)})
    foreach($event in $result.Data){
        $message='[excluded]'; $messageState='NotRequested'
        if($IncludeMessages){
            try{$message=$event.Message;$messageState='Available'}
            catch{$message='[message unavailable]';$messageState='Unknown';$queryErrors.Add([pscustomobject]@{Section=('Event message '+$event.RecordId);Error=$_.Exception.Message;ErrorId=$_.FullyQualifiedErrorId})}
        }
        $timeline.Add([pscustomobject]@{TimeCreated=$event.TimeCreated;EvidenceType=$source.Kind;Provider=$event.ProviderName;Id=$event.Id;Level=$event.LevelDisplayName;RecordId=$event.RecordId;MessageStatus=$messageState;Message=$message})
    }
}
$events=@($timeline | Sort-Object TimeCreated)
Write-ReportCsv 'restart-timeline' $events @('TimeCreated','EvidenceType','Provider','Id','Level','RecordId','MessageStatus','Message')
Write-ReportCsv 'event-source-status' $sourceCaps.ToArray() @('Provider','QuerySucceeded','Count','AtLimit')
$dumps=Invoke-ReportQuery -Section 'Crash dump file metadata' -Action {
    $paths=@((Join-Path $env:WINDIR 'MEMORY.DMP'))
    $smallDumpDirectory=Join-Path $env:WINDIR 'Minidump'
    try{
        $small=@(Get-ChildItem -LiteralPath $smallDumpDirectory -Filter '*.dmp' -File -ErrorAction Stop | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First $MaxDumpFiles)
        $paths+=@($small | Select-Object -ExpandProperty FullName)
    }catch{if($_.CategoryInfo.Category -ne 'ObjectNotFound'){throw}}
    foreach($path in $paths){
        try{
            $file=Get-Item -LiteralPath $path -ErrorAction Stop
            if(-not $file.PSIsContainer){[pscustomobject]@{Path=$file.FullName;Bytes=$file.Length;LastWriteTimeUtc=$file.LastWriteTimeUtc}}
        }catch{if($_.CategoryInfo.Category -ne 'ObjectNotFound'){throw}}
    }
}
Write-ReportCsv 'crash-dump-metadata' $dumps.Data @('Path','Bytes','LastWriteTimeUtc')
$settings=Invoke-ReportQuery -Section 'Crash-control settings' -RequireData -Action {
    $value=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction Stop
    [pscustomobject]@{CrashDumpEnabled=$value.CrashDumpEnabled;AutoReboot=$value.AutoReboot;LogEvent=$value.LogEvent;Overwrite=$value.Overwrite}
}
Write-ReportCsv 'crash-control' $settings.Data @('CrashDumpEnabled','AutoReboot','LogEvent','Overwrite')
Complete-Report -Data ([ordered]@{
    Days=$Days;EventRows=$events.Count;ProvidersAtLimit=@($sourceCaps | Where-Object AtLimit | ForEach-Object Provider)
    DumpFilesListed=$dumps.Data.Count;MessagesIncluded=[bool]$IncludeMessages
}) -Notes @(
    'Event 41 and 6008 record evidence of an unclean shutdown; they do not distinguish power loss, hangs, hardware faults, and every other cause.'
    'Events are selected by provider and ID. Capped providers may have older matching events omitted; separate event times are not guaranteed to describe separate incidents.'
    'Only default Windows MEMORY.DMP and Minidump locations are inspected; custom dump locations are outside this report. Contents are neither copied nor analyzed.'
    'MaxDumpFiles limits the minidump list after folder enumeration/sorting; it is not a hard runtime or enumeration bound. Dump metadata is not restricted to the event time window.'
    'Missing dumps can reflect configuration, permissions, retention, or failure to create a dump. Messages may include internal/user information.'
)
