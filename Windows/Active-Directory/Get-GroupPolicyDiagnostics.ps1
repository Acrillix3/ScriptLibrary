<#
What it does:
  Collects local applied/denied Group Policy results and recent processing errors.

Available flags:
  -Scope: Computer, User, or Both (Both by default).
  -User: Optional domain\user whose existing user RSoP should be reported.
  -LookbackDays: Days of processing events to inspect (7 by default).
  -MaxEvents: Maximum recent events to save (100 by default).
  -OutputDirectory: Report location (Windows\Reports by default).

How it works:
  Runs local gpresult /r separately per requested scope and checks native exit codes. Saves verbatim
  policy results and bounded event logs; never refreshes or changes policy.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Computer','User','Both')][string]$Scope = 'Both',
    [ValidateNotNullOrEmpty()][string]$User,
    [ValidateRange(1,365)][int]$LookbackDays = 7,
    [ValidateRange(1,5000)][int]$MaxEvents = 100,
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

$scopeNames = @($Scope)
if ($Scope -eq 'Both') { $scopeNames = @('Computer','User') }
$policyRows = @(
    foreach ($scopeName in $scopeNames) {
        $textPath = Join-Path $reportDirectory ('gpresult-'+$scopeName+'.txt')
        $nativeState = [pscustomobject]@{ExitCode=$null}
        $capture = Invoke-ReportQuery -Section ('gpresult '+$scopeName) -RequireData -Action {
            $null = Get-Command -Name gpresult.exe -ErrorAction Stop
            $arguments = @('/r','/scope',$scopeName)
            if ($scopeName -eq 'User' -and $User) { $arguments += @('/user',$User) }
            # Native stderr is retained as evidence; success requires exit code zero.
            $savedPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $nativeText = @(& gpresult.exe @arguments 2>&1 | ForEach-Object { [string]$_ })
                $nativeState.ExitCode = $LASTEXITCODE
            } finally { $ErrorActionPreference = $savedPreference }
            $nativeText | Set-Content -LiteralPath $textPath -Encoding UTF8 -ErrorAction Stop
            if ($null -eq $nativeState.ExitCode -or $nativeState.ExitCode -ne 0) { throw ('gpresult {0} failed with native exit code {1}; inspect the saved text.' -f $scopeName,$nativeState.ExitCode) }
            if ($nativeText.Count -eq 0) { throw 'gpresult returned no text.' }
            [pscustomobject]@{ExitCode=$nativeState.ExitCode;ReportFile=$textPath}
        }
        [pscustomobject]@{Scope=$scopeName;RequestedUser=$(if($scopeName -eq 'User'){if($User){$User}else{'Current execution identity'}}else{''});EvidenceStatus=$(if($capture.Succeeded){'Collected'}else{'Unknown'});NativeExitCode=$nativeState.ExitCode;ReportFile=$textPath}
    }
)
$events = Invoke-ReportQuery -Section 'Recent Group Policy errors and warnings' -Action {
    try {
        Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-GroupPolicy/Operational';Level=@(1,2,3);StartTime=(Get-Date).AddDays(-$LookbackDays)} -MaxEvents $MaxEvents -ErrorAction Stop |
            Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message
    } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
}
Write-ReportCsv -Name 'policy-scopes' -Rows $policyRows -Columns @('Scope','RequestedUser','EvidenceStatus','NativeExitCode','ReportFile')
Write-ReportCsv -Name 'group-policy-events' -Rows $events.Data -Columns @('TimeCreated','Id','LevelDisplayName','ProviderName','Message')
Complete-Report -Data ([pscustomobject]@{Scopes=$policyRows;Events=$events.Data;EventLimitReached=($events.Data.Count -ge $MaxEvents)}) -Notes @(
    'Applied and denied policies are recorded verbatim in each gpresult text report, preserving localized output and the reasons actually reported. Denial can be expected filtering, not a processing failure.'
    'Computer scope normally requires elevation. User scope uses the execution identity unless -User is supplied, and requires existing RSoP data for that user on this computer.'
    'Running under another administrator account changes the default user scope. This reports the local machine and does not query or alter domain-wide GPO definitions.'
    'Missing logs, insufficient permission, unavailable gpresult, or unavailable RSoP data remain Unknown. A reached event limit may omit older events.'
)
