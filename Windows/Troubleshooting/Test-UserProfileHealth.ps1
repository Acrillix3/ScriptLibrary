<#
What it does:
  Reports local user profile inconsistencies, temporary profiles, and recent profile errors.

Available flags:
  -LookbackDays: Days of profile events to inspect (7 by default).
  -MaxEvents: Maximum recent events to save (100 by default).
  -OutputDirectory: Report location (Windows\Reports by default).

How it works:
  Reads CIM profiles, ProfileList registry entries, folder existence, and bounded event logs. Run
  elevated for complete evidence. Writes CSV/JSON reports without changing profiles.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
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

$profiles = Invoke-ReportQuery -Section 'CIM profiles' -RequireData -Action {
    Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop
}
$registry = Invoke-ReportQuery -Section 'ProfileList keys' -RequireData -Action {
    Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop
}
$registryBySid = @{}
if ($registry.Succeeded) {
    foreach ($key in $registry.Data) {
        $entry = Invoke-ReportQuery -Section ('ProfileList '+$key.PSChildName) -RequireData -Action {
            Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
        }
        $registryBySid[[string]$key.PSChildName] = $entry
    }
}
$cimBySid = @{}
foreach ($profile in $profiles.Data) { $cimBySid[[string]$profile.SID] = $profile }
$sids = @(@($cimBySid.Keys) + @($registryBySid.Keys) | Sort-Object -Unique)
$profileRows = @(
    foreach ($sid in $sids) {
        $profile = $cimBySid[$sid]
        $reg = $registryBySid[$sid]
        $entry = $null
        if ($reg -and $reg.Succeeded) { $entry = @($reg.Data)[0] }
        $registryPath = $null
        if ($entry -and $entry.ProfileImagePath) { $registryPath = [Environment]::ExpandEnvironmentVariables([string]$entry.ProfileImagePath) }
        $localPath = $registryPath
        if ($profile -and $profile.LocalPath) { $localPath = [string]$profile.LocalPath }
        $folderState = 'Unknown'
        if ($localPath) {
            $folderQuery = Invoke-ReportQuery -Section ('Profile folder '+$sid) -RequireData -Action {
                Test-Path -LiteralPath $localPath -PathType Container -ErrorAction Stop
            }
            if ($folderQuery.Succeeded) { $folderState = $(if ($folderQuery.Data[0]) {'Exists'} else {'Missing'}) }
        }
        $special = $null
        if ($profile) { $special = $profile.Special }
        if ($sid -match '^S-1-5-(18|19|20|80)(-|$)') { $special = $true }
        $findings = New-Object 'System.Collections.Generic.List[string]'
        if ($sid -match '\.bak$') { $findings.Add('Backup ProfileList key; investigate alongside the matching SID.') }
        if ($folderState -eq 'Missing') { $findings.Add('Profile folder is missing.') }
        if ($profile -and $null -ne $profile.Status) {
            if (([uint32]$profile.Status -band 1) -ne 0) { $findings.Add('CIM reports a temporary profile.') }
            if (([uint32]$profile.Status -band 8) -ne 0) { $findings.Add('CIM reports profile corruption.') }
        }
        if ($profile -and $null -ne $profile.HealthStatus -and [int]$profile.HealthStatus -in @(1,2)) {
            $findings.Add('CIM profile HealthStatus reports unhealthy or caution.')
        }
        if ($profile -and $registry.Succeeded -and -not $reg) { $findings.Add('No corresponding ProfileList key was returned.') }
        if (-not $profile -and $profiles.Succeeded -and $sid -notmatch '\.bak$') { $findings.Add('No corresponding CIM profile was returned.') }
        if ($profile -and $registryPath -and $profile.LocalPath -and ([string]$profile.LocalPath -ne $registryPath)) { $findings.Add('CIM and registry profile paths differ.') }
        $evidence = 'Collected'
        if (-not $profiles.Succeeded -or -not $registry.Succeeded -or ($reg -and -not $reg.Succeeded) -or $folderState -eq 'Unknown') { $evidence = 'Unknown' }
        [pscustomobject]@{
            SID=$sid;LocalPath=$localPath;RegistryPath=$registryPath;FolderState=$folderState
            Loaded=$(if($profile){$profile.Loaded}else{$null});SpecialOrService=$special
            LastUseTime=$(if($profile){$profile.LastUseTime}else{$null});StatusBits=$(if($profile){$profile.Status}else{$null})
            HealthStatus=$(if($profile){$profile.HealthStatus}else{$null});EvidenceStatus=$evidence
            Findings=($findings.ToArray() -join ' ')
        }
    }
)
$events = Invoke-ReportQuery -Section 'Recent profile events' -Action {
    try {
        Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='Microsoft-Windows-User Profiles Service';Id=@(1500,1502,1508,1509,1511,1515,1530,1542);StartTime=(Get-Date).AddDays(-$LookbackDays)} -MaxEvents $MaxEvents -ErrorAction Stop |
            Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message
    } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
}
Write-ReportCsv -Name 'profiles' -Rows $profileRows -Columns @('SID','LocalPath','RegistryPath','FolderState','Loaded','SpecialOrService','LastUseTime','StatusBits','HealthStatus','EvidenceStatus','Findings')
Write-ReportCsv -Name 'profile-events' -Rows $events.Data -Columns @('TimeCreated','Id','LevelDisplayName','ProviderName','Message')
Complete-Report -Data ([pscustomobject]@{Profiles=$profileRows;Events=$events.Data;EventLimitReached=($events.Data.Count -ge $MaxEvents)}) -Notes @(
    'Special and service profiles are identified for context; age alone is not evidence that any profile should be deleted.'
    'An empty event result only means no matching retained events were returned in the selected period. A reached limit may omit older events.'
    'No folders, registry values, user hives, or profiles are changed.'
)
