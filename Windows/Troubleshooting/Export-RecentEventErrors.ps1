<#
What it does:
  Exports recent critical/error events, with optional warnings.

Available flags:
  -LogName <names>: Exact log names; default System and Application.
  -Hours <number>: Look-back window; default 24 hours.
  -MaxEventsPerLog <number>: Newest matches per log; default 500.
  -IncludeWarnings: Also collect warning events.
  -OutputDirectory <path>: Report destination; default Windows\Reports.

How it works:
  Uses filtered Get-WinEvent queries and saves event/status CSVs plus a JSON summary. Distinguishes
  no matches from access failures and marks capped results; messages may contain user or application
  data.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateCount(1,20)][ValidateNotNullOrEmpty()][string[]]$LogName=@('System','Application'),
    [ValidateRange(1,8760)][int]$Hours=24,
    [ValidateRange(1,100000)][int]$MaxEventsPerLog=500,
    [switch]$IncludeWarnings,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
foreach ($name in $LogName) { if ($name.IndexOfAny([char[]]'*?[]') -ge 0) { throw 'Use exact event log names, without wildcard characters.' } }
$runName='06-RecentEvents-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), ([guid]::NewGuid().ToString('N').Substring(0,8))
$report=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force).FullName
$start=(Get-Date).AddHours(-$Hours); $end=Get-Date
$levels=@(1,2); if ($IncludeWarnings) { $levels+=3 }
$events=New-Object 'System.Collections.Generic.List[object]'
$logStatus=New-Object 'System.Collections.Generic.List[object]'
foreach ($name in ($LogName | Sort-Object -Unique)) {
    try {
        $items=@(Get-WinEvent -FilterHashtable @{LogName=$name; StartTime=$start; EndTime=$end; Level=$levels} -MaxEvents $MaxEventsPerLog -ErrorAction Stop)
        foreach ($item in $items) {
            $message=''; $messageStatus='Available'
            try { $message=$item.Message }
            catch { $messageStatus='Unavailable'; $message=$_.Exception.Message }
            $events.Add([pscustomobject]@{
                LogName=$item.LogName; TimeCreated=$item.TimeCreated; Id=$item.Id
                Level=$item.Level; LevelDisplayName=$item.LevelDisplayName
                ProviderName=$item.ProviderName; RecordId=$item.RecordId
                MachineName=$item.MachineName; MessageStatus=$messageStatus; Message=$message
            })
        }
        $logStatus.Add([pscustomobject]@{LogName=$name; Status=$(if ($items.Count) {'Collected'} else {'NoMatches'}); EventCount=$items.Count; AtLimit=($items.Count -ge $MaxEventsPerLog); Error=''})
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            $logStatus.Add([pscustomobject]@{LogName=$name; Status='NoMatches'; EventCount=0; AtLimit=$false; Error=''})
        } else {
            $logStatus.Add([pscustomobject]@{LogName=$name; Status='Unknown'; EventCount=0; AtLimit=$false; Error=$_.Exception.Message})
        }
    }
}
if ($events.Count) { $events | Sort-Object TimeCreated -Descending | Export-Csv -LiteralPath (Join-Path $report 'events.csv') -NoTypeInformation -Encoding UTF8 }
else { '"LogName","TimeCreated","Id","Level","LevelDisplayName","ProviderName","RecordId","MachineName","MessageStatus","Message"' | Set-Content -LiteralPath (Join-Path $report 'events.csv') -Encoding UTF8 }
$logStatus | Export-Csv -LiteralPath (Join-Path $report 'log-status.csv') -NoTypeInformation -Encoding UTF8
$unknown=@($logStatus | Where-Object Status -eq 'Unknown').Count
$messageErrors=@($events | Where-Object MessageStatus -eq 'Unavailable').Count
$summary=[pscustomobject]@{
    Status=$(if ($unknown -or $messageErrors) {'Partial'} else {'Complete'})
    ComputerName=$env:COMPUTERNAME; StartTimeUtc=$start.ToUniversalTime().ToString('o'); EndTimeUtc=$end.ToUniversalTime().ToString('o')
    Levels=$levels; EventCount=$events.Count; UnknownLogCount=$unknown; UnavailableMessageCount=$messageErrors
    MaxEventsPerLog=$MaxEventsPerLog; LogsAtLimit=@($logStatus | Where-Object AtLimit).LogName
    Notes='Only selected levels and time window are covered. Reaching the limit may omit older matches. NoMatches does not mean a computer is healthy.'
    ReportDirectory=$report
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
if ($unknown -or $messageErrors) { Write-Warning 'Some event data could not be read; see log-status.csv and MessageStatus.' }
$summary

