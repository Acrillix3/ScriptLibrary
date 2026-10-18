<#
What it does:
  Reports IPv4 DHCP scope capacity, declined leases, server counters, and failover state.

Available flags:
  -ComputerName: DHCP server name; defaults to the local computer.
  -WarningPercentInUse: Capacity percentage to flag (default 85).
  -MaxScopes: Maximum scopes to inspect (default 100).
  -MaxDeclinedLeasesPerScope: Maximum declined leases per scope (default 100).
  -MaxFailoverRelationships: Maximum failover relationships (default 100).
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Uses installed DHCP management tools and read access. Exports bounded IPv4 evidence; missing tools
  or failed queries are Unknown. Does not change scopes or leases.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()][string]$ComputerName = $env:COMPUTERNAME,
    [ValidateRange(1,100)][int]$WarningPercentInUse = 85,
    [ValidateRange(1,10000)][int]$MaxScopes = 100,
    [ValidateRange(1,10000)][int]$MaxDeclinedLeasesPerScope = 100,
    [ValidateRange(1,10000)][int]$MaxFailoverRelationships = 100,
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

$scopeRows=New-Object 'System.Collections.Generic.List[object]'
$leaseRows=New-Object 'System.Collections.Generic.List[object]'
$failoverRows=@(); $serverRows=@(); $scopeCapReached=$false; $leaseCapScopes=0; $failoverCapReached=$false
$tools=Invoke-ReportQuery -Section 'DHCP tools' -RequireData -Action { Import-Module DhcpServer -ErrorAction Stop; 'Available' }
if($tools.Succeeded){
    $serverResult=Invoke-ReportQuery -Section 'IPv4 server statistics' -RequireData -Action { Get-DhcpServerv4Statistics -ComputerName $ComputerName -ErrorAction Stop }
    $serverRows=@($serverResult.Data | Select-Object ServerStartTime,TotalScopes,TotalAddresses,AddressesInUse,AddressesAvailable,Discovers,Offers,Requests,Acks,Naks,Declines,Releases)
    $scopes=Invoke-ReportQuery -Section 'IPv4 scopes' -Action { Get-DhcpServerv4Scope -ComputerName $ComputerName -ErrorAction Stop | Select-Object -First ($MaxScopes+1) }
    $scopeCapReached=$scopes.Data.Count -gt $MaxScopes
    foreach($scope in @($scopes.Data | Select-Object -First $MaxScopes)){
        $scopeId=[string]$scope.ScopeId
        $stats=Invoke-ReportQuery -Section ('Scope statistics '+$scopeId) -RequireData -Action {
            $nativeStats=@(Get-DhcpServerv4ScopeStatistics -ComputerName $ComputerName -ScopeId $scope.ScopeId -ErrorAction Stop)
            if($nativeStats.Count -ne 1){throw 'Exactly one scope statistics record was required.'}
            foreach($requiredField in @('PercentageInUse','AddressesInUse','AddressesFree')){
                $property=$nativeStats[0].PSObject.Properties[$requiredField]
                if($null -eq $property -or $null -eq $property.Value -or [string]::IsNullOrWhiteSpace([string]$property.Value)){
                    throw ('Required scope statistics field is missing or null: '+$requiredField)
                }
            }
            $percent=[double]$nativeStats[0].PercentageInUse
            if([double]::IsNaN($percent) -or [double]::IsInfinity($percent) -or $percent -lt 0 -or $percent -gt 100){throw 'Scope utilization percentage was outside 0 through 100.'}
            if([long]$nativeStats[0].AddressesInUse -lt 0 -or [long]$nativeStats[0].AddressesFree -lt 0){throw 'Scope address counts cannot be negative.'}
            $nativeStats[0]
        }
        $stat=$stats.Data | Select-Object -First 1
        $scopeRows.Add([pscustomobject]@{ScopeId=$scopeId;Name=$scope.Name;State=[string]$scope.State;StartRange=[string]$scope.StartRange;EndRange=[string]$scope.EndRange;StatisticsStatus=$(if($stats.Succeeded){'Collected'}else{'Unknown'});PercentageInUse=$(if($stats.Succeeded){$stat.PercentageInUse}else{$null});AddressesInUse=$(if($stats.Succeeded){$stat.AddressesInUse}else{$null});AddressesFree=$(if($stats.Succeeded){$stat.AddressesFree}else{$null});CapacityFlag=$(if(-not $stats.Succeeded){'Unknown'}elseif($stat.PercentageInUse -ge $WarningPercentInUse){'Review'}else{'Below threshold'})})
        $declines=Invoke-ReportQuery -Section ('Declined leases '+$scopeId) -Action { Get-DhcpServerv4Lease -ComputerName $ComputerName -ScopeId $scope.ScopeId -BadLeases -ErrorAction Stop | Select-Object -First ($MaxDeclinedLeasesPerScope+1) }
        if($declines.Data.Count -gt $MaxDeclinedLeasesPerScope){$leaseCapScopes++}
        foreach($lease in @($declines.Data | Select-Object -First $MaxDeclinedLeasesPerScope)){
            $leaseRows.Add([pscustomobject]@{ScopeId=$scopeId;IPAddress=[string]$lease.IPAddress;AddressState=[string]$lease.AddressState;LeaseExpiryTime=$lease.LeaseExpiryTime})
        }
    }
    $failover=Invoke-ReportQuery -Section 'IPv4 failover relationships' -Action { Get-DhcpServerv4Failover -ComputerName $ComputerName -ErrorAction Stop | Select-Object -First ($MaxFailoverRelationships+1) }
    $failoverCapReached=$failover.Data.Count -gt $MaxFailoverRelationships
    $failoverRows=@($failover.Data | Select-Object -First $MaxFailoverRelationships | ForEach-Object { [pscustomobject]@{Name=$_.Name;PartnerServer=$_.PartnerServer;Mode=[string]$_.Mode;ServerRole=[string]$_.ServerRole;State=[string]$_.State;ScopeIds=($_.ScopeId -join ';');StateFlag=$(if([string]::IsNullOrWhiteSpace([string]$_.State)){'Unknown'}elseif([string]$_.State -eq 'Normal'){'Normal reported'}else{'Review'})} })
}
Write-ReportCsv 'scopes' $scopeRows.ToArray() @('ScopeId','Name','State','StartRange','EndRange','StatisticsStatus','PercentageInUse','AddressesInUse','AddressesFree','CapacityFlag')
Write-ReportCsv 'declined-leases' $leaseRows.ToArray() @('ScopeId','IPAddress','AddressState','LeaseExpiryTime')
Write-ReportCsv 'failover' $failoverRows @('Name','PartnerServer','Mode','ServerRole','State','ScopeIds','StateFlag')
Write-ReportCsv 'server-statistics' $serverRows @('ServerStartTime','TotalScopes','TotalAddresses','AddressesInUse','AddressesAvailable','Discovers','Offers','Requests','Acks','Naks','Declines','Releases')
$summaryData=[pscustomobject]@{Target=$ComputerName;ScopeCount=$scopeRows.Count;ScopesAtCapacityThreshold=@($scopeRows | Where-Object CapacityFlag -eq 'Review').Count;ScopesWithUnknownCapacity=@($scopeRows | Where-Object CapacityFlag -eq 'Unknown').Count;DeclinedLeaseCount=$leaseRows.Count;FailoverCount=$failoverRows.Count;FailoverReviewCount=@($failoverRows | Where-Object StateFlag -eq 'Review').Count;ScopeCapReached=$scopeCapReached;DeclinedLeaseCapScopeCount=$leaseCapScopes;FailoverCapReached=$failoverCapReached;WarningPercentInUse=$WarningPercentInUse}
Complete-Report $summaryData @('IPv4 only. An empty failover result means no relationship was returned; check section status for failures.','Counts cover inspected items only. Configurable caps limit enumeration and follow-up work; provider calls can still wait on the server.','Declined addresses can indicate conflicts. Failover state alone does not prove lease availability. Client names, identifiers, and shared secrets are excluded.')

