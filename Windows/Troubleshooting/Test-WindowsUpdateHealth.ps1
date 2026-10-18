<#
What it does:
  Collects recent update failures, update history, service state, and configured update policy.

Available flags:
  -Hours: Event look-back window; default 168.
  -MaxEvents: Maximum update events; default 300.
  -MaxHistory: Maximum recent history entries examined; default 100.
  -ExportUpdateLog: Also create a static WindowsUpdate.log; can take several minutes.
  -OutputDirectory: Report destination; default Windows\Reports.

How it works:
  Reads the local Windows Update Agent history, selected registry policy, services, and update
  events. Optional log conversion uses Get-WindowsUpdateLog. Does not search for, download, install,
  or reset updates; history is not a complete missing-patch assessment.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
[ValidateRange(1,8760)][int]$Hours=168,
[ValidateRange(1,5000)][int]$MaxEvents=300,
[ValidateRange(1,1000)][int]$MaxHistory=100,
[switch]$ExportUpdateLog,
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

$cutoff=(Get-Date).AddHours(-$Hours)
$historyCutoffUtc=[datetime]::UtcNow.AddHours(-$Hours)
$history=Invoke-ReportQuery -Section 'Windows Update history' -Action {
    $session=$null; $searcher=$null; $entries=$null
    try {
        $session=New-Object -ComObject Microsoft.Update.Session
        $searcher=$session.CreateUpdateSearcher()
        $total=$searcher.GetTotalHistoryCount()
        $take=[math]::Min($total,$MaxHistory)
        if($take -gt 0) {
            $entries=$searcher.QueryHistory(0,$take)
            foreach($entry in $entries) {
                # WUA history COM DATE values are documented in UTC even when Kind is Unspecified.
                $dateUtc=[datetime]::SpecifyKind([datetime]$entry.Date,[DateTimeKind]::Utc)
                if($dateUtc -lt $historyCutoffUtc){continue}
                $code=[int]$entry.ResultCode
                $result=switch($code){0{'NotStarted'}1{'InProgress'}2{'Succeeded'}3{'SucceededWithErrors'}4{'Failed'}5{'Aborted'}default{'UnknownCode'}}
                $unsigned=[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$entry.HResult),0)
                [pscustomobject]@{DateUtc=$dateUtc.ToString('o');Title=$entry.Title;Operation=[string]$entry.Operation;ResultCode=$code;Result=$result;HResult=('0x{0:X8}' -f $unsigned)}
            }
        }
    } finally {
        foreach($comObject in @($entries,$searcher,$session)){
            if($null -ne $comObject -and [Runtime.InteropServices.Marshal]::IsComObject($comObject)){
                $null=[Runtime.InteropServices.Marshal]::ReleaseComObject($comObject)
            }
        }
    }
}
Write-ReportCsv 'update-history' $history.Data @('DateUtc','Title','Operation','ResultCode','Result','HResult')
$services=Invoke-ReportQuery -Section 'Update services' -Action {
    foreach($name in @('wuauserv','BITS','UsoSvc','TrustedInstaller')){
        $item=Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $name) -ErrorAction Stop
        [pscustomobject]@{Name=$name;Installed=($null -ne $item);State=$item.State;StartMode=$item.StartMode}
    }
}
Write-ReportCsv 'update-services' $services.Data @('Name','Installed','State','StartMode')
$policy=Invoke-ReportQuery -Section 'Configured update policy' -Action {
    if([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell to inspect the native update policy registry view.'}
    $definitions=@(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate';Names=@('WUServer','WUStatusServer','DoNotConnectToWindowsUpdateInternetLocations','DisableWindowsUpdateAccess')},
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';Names=@('UseWUServer','NoAutoUpdate','AUOptions','NoAutoRebootWithLoggedOnUsers')}
    )
    foreach($definition in $definitions){
        $values=$null
        try{$values=Get-ItemProperty -LiteralPath $definition.Path -ErrorAction Stop}
        catch{if($_.CategoryInfo.Category -ne 'ObjectNotFound'){throw}}
        foreach($name in $definition.Names){
            $value=$null; $state='NotConfigured'
            if($null -ne $values -and $null -ne $values.PSObject.Properties[$name]){
                $value=$values.$name; $state='Configured'
                if($name -in @('WUServer','WUStatusServer')){
                    # Keep the endpoint, but remove possible URL user-info and query strings.
                    $uri=$null
                    if([uri]::TryCreate([string]$value,[UriKind]::Absolute,[ref]$uri)){$value=$uri.GetLeftPart([UriPartial]::Authority) -replace '//[^/]*@','//'; $value+=$uri.AbsolutePath}
                    else{$value='[unparseable endpoint omitted]'}
                }
            }
            [pscustomobject]@{RegistryPath=$definition.Path;Setting=$name;State=$state;Value=$value}
        }
    }
}
Write-ReportCsv 'update-policy' $policy.Data @('RegistryPath','Setting','State','Value')
$events=Invoke-ReportQuery -Section 'Windows Update operational events' -Action {
    try{
        Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';StartTime=$cutoff;Level=@(1,2,3)} -MaxEvents $MaxEvents -ErrorAction Stop |
            Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,RecordId,Message
    }catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
}
Write-ReportCsv 'update-events' $events.Data @('TimeCreated','Id','LevelDisplayName','ProviderName','RecordId','Message')
if($ExportUpdateLog){
    $log=Invoke-ReportQuery -Section 'Static Windows Update log conversion' -Action {
        $path=Join-Path $reportDirectory 'WindowsUpdate.log'
        $null=Get-WindowsUpdateLog -LogPath $path -ErrorAction Stop
        if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'Log conversion did not create the requested file.'}
        [pscustomobject]@{Path=$path;Bytes=(Get-Item -LiteralPath $path -ErrorAction Stop).Length}
    }
}else{$queryLog.Add([pscustomobject]@{Section='Static Windows Update log conversion';Status='NotRequested';Count=0;Error=''})}
Complete-Report -Data ([ordered]@{
    Hours=$Hours;HistoryCutoffUtc=$historyCutoffUtc.ToString('o');HistoryEntriesExaminedLimit=$MaxHistory;HistoryRows=$history.Data.Count
    FailedOrAbortedHistoryRows=@($history.Data | Where-Object ResultCode -in @(4,5)).Count
    EventRows=$events.Data.Count;EventQueryAtLimit=($events.Data.Count -ge $MaxEvents)
    UpdateLogRequested=[bool]$ExportUpdateLog
}) -Notes @(
    'This does not initiate update detection, downloads, installation, reset, or service changes.'
    'History is bounded by MaxHistory before the time filter, can be reset by servicing, and is not an authoritative missing-patch inventory.'
    'Stopped trigger-start update services can be normal. Registry policy is selected legacy/WSUS evidence, not complete MDM policy.'
    'Update messages and endpoints may contain internal information; review reports before sharing.'
)
