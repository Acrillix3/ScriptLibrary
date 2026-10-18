<#
What it does:
  Reports local IIS website and application pool states, bindings, and recent event errors.

Available flags:
  -MaxSites: Maximum websites to inspect (default 100).
  -MaxAppPools: Maximum application pools to inspect (default 100).
  -MaxBindingsPerSite: Maximum bindings per website (default 100).
  -LookbackHours: Recent IIS/WAS event window (default 24).
  -MaxEvents: Maximum matching warning/error events (default 200).
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Reads WebAdministration and bounded IIS/WAS System events. Queries fail independently; missing
  modules or denied access are Unknown. Does not send web requests, restart sites, or expose
  application pool credentials. Run locally with IIS read access.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1,10000)][int]$MaxSites=100,
    [ValidateRange(1,10000)][int]$MaxAppPools=100,
    [ValidateRange(1,10000)][int]$MaxBindingsPerSite=100,
    [ValidateRange(1,8760)][int]$LookbackHours=24,
    [ValidateRange(1,10000)][int]$MaxEvents=200,
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

$siteRows=New-Object 'System.Collections.Generic.List[object]';$bindingRows=New-Object 'System.Collections.Generic.List[object]';$poolRows=New-Object 'System.Collections.Generic.List[object]'
$eventRows=@();$siteCapReached=$false;$poolCapReached=$false;$bindingCapSites=0;$eventCapReached=$false
$tools=Invoke-ReportQuery -Section 'IIS tools' -RequireData -Action { Import-Module WebAdministration -ErrorAction Stop; 'Available' }
if($tools.Succeeded){
    $sites=Invoke-ReportQuery -Section 'IIS websites' -Action { Get-Website -ErrorAction Stop | Select-Object -First ($MaxSites+1) }
    $siteCapReached=$sites.Data.Count -gt $MaxSites
    foreach($site in @($sites.Data | Select-Object -First $MaxSites)){
        $siteRows.Add([pscustomobject]@{Name=$site.Name;Id=$site.Id;State=[string]$site.State;ApplicationPool=$site.ApplicationPool;StateFlag=$(if([string]::IsNullOrWhiteSpace([string]$site.State)){'Unknown'}elseif([string]$site.State -eq 'Started'){'Started reported'}else{'Review'})})
        $bindings=Invoke-ReportQuery -Section ('Bindings '+$site.Name) -Action { Get-WebBinding -Name $site.Name -ErrorAction Stop | Select-Object -First ($MaxBindingsPerSite+1) }
        if($bindings.Data.Count -gt $MaxBindingsPerSite){$bindingCapSites++}
        foreach($binding in @($bindings.Data | Select-Object -First $MaxBindingsPerSite)){$bindingRows.Add([pscustomobject]@{SiteName=$site.Name;Protocol=[string]$binding.protocol;BindingInformation=[string]$binding.bindingInformation;SslFlags=[string]$binding.sslFlags})}
    }
    $pools=Invoke-ReportQuery -Section 'IIS application pools' -Action { Get-ChildItem -LiteralPath 'IIS:\AppPools' -ErrorAction Stop | Select-Object -First ($MaxAppPools+1) }
    $poolCapReached=$pools.Data.Count -gt $MaxAppPools
    foreach($pool in @($pools.Data | Select-Object -First $MaxAppPools)){
        $state=Invoke-ReportQuery -Section ('Application pool state '+$pool.Name) -RequireData -Action { Get-WebAppPoolState -Name $pool.Name -ErrorAction Stop }
        $value=[string]($state.Data | Select-Object -First 1 -ExpandProperty Value)
        $poolRows.Add([pscustomobject]@{Name=$pool.Name;State=$(if($state.Succeeded){$value}else{'Unknown'});RuntimeVersion=[string]$pool.managedRuntimeVersion;PipelineMode=[string]$pool.managedPipelineMode;StateFlag=$(if(-not $state.Succeeded -or [string]::IsNullOrWhiteSpace($value)){'Unknown'}elseif($value -eq 'Started'){'Started reported'}else{'Review'})})
    }
}
$events=Invoke-ReportQuery -Section 'Recent IIS and WAS System events' -Action {
    try { Get-WinEvent -FilterHashtable @{LogName='System';ProviderName=@('Microsoft-Windows-WAS','Microsoft-Windows-IIS-W3SVC','Microsoft-Windows-IIS-W3SVC-WP');Level=@(1,2,3);StartTime=(Get-Date).AddHours(-$LookbackHours)} -MaxEvents ($MaxEvents+1) -ErrorAction Stop }
    catch { if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){return}; throw }
}
$eventCapReached=$events.Data.Count -gt $MaxEvents
$eventRows=@($events.Data | Select-Object -First $MaxEvents | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,RecordId)
Write-ReportCsv 'websites' $siteRows.ToArray() @('Name','Id','State','ApplicationPool','StateFlag')
Write-ReportCsv 'bindings' $bindingRows.ToArray() @('SiteName','Protocol','BindingInformation','SslFlags')
Write-ReportCsv 'application-pools' $poolRows.ToArray() @('Name','State','RuntimeVersion','PipelineMode','StateFlag')
Write-ReportCsv 'recent-events' $eventRows @('TimeCreated','Id','LevelDisplayName','ProviderName','RecordId')
$summaryData=[pscustomobject]@{SiteCount=$siteRows.Count;SitesToReview=@($siteRows | Where-Object StateFlag -eq 'Review').Count;BindingCount=$bindingRows.Count;AppPoolCount=$poolRows.Count;AppPoolsToReview=@($poolRows | Where-Object StateFlag -eq 'Review').Count;UnknownAppPoolStates=@($poolRows | Where-Object StateFlag -eq 'Unknown').Count;RecentWarningErrorCount=$eventRows.Count;LookbackHours=$LookbackHours;SiteCapReached=$siteCapReached;AppPoolCapReached=$poolCapReached;BindingCapSiteCount=$bindingCapSites;EventCapReached=$eventCapReached;WebsiteResponses='Not tested'}
Complete-Report $summaryData @('A started site or pool does not establish HTTP availability, application correctness, or certificate validity. Stopped items can be intentional.','Recent events cover the specified IIS/WAS providers in the System log; HTTP access logs and application-specific logs are not scanned. Event messages are excluded.','Counts cover inspected items only. Caps and the event time window bound collected evidence; IIS provider calls have no hard timeout.')

