<#
What it does:
  Audits a Windows DNS server's settings, zones, aging configuration, and optional records and DNS
  responses.

Available flags:
  -ComputerName: DNS server name or IP address; defaults to the local computer.
  -OutputDirectory: Report destination; defaults to Windows\Reports.
  -ZoneName: Optional exact zone names; server settings and full zone inventory are still collected.
  -IncludeRecords: Scan and export selected primary/secondary zone records; disabled by default.
  -ExpectedDomain: Optional AD DNS domain for domain-controller SRV queries.
  -TestName: Optional 1-10 fully qualified hostnames for A-record queries.

How it works:
  Uses the DnsServer module and DNS management read access to save settings, evidence, and
  collection errors; optional DNS queries require Resolve-DnsName. Record scans can be large, cover
  the default scope and virtualization instance only, and record age does not prove that a record is
  unused or safe to delete.
#>
#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName = $env:COMPUTERNAME,

    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [ValidateNotNullOrEmpty()]
    [string[]]$ZoneName,

    [switch]$IncludeRecords,

    [ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$')]
    [string]$ExpectedDomain,

    [ValidateCount(1,10)]
    [ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$')]
    [string[]]$TestName
)

$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$auditStarted = Get-Date
$auditErrors = New-Object 'System.Collections.Generic.List[object]'
$collections = New-Object 'System.Collections.Generic.List[object]'
$flags = New-Object 'System.Collections.Generic.List[object]'
$configuration = New-Object 'System.Collections.Generic.List[object]'
$zoneRows = New-Object 'System.Collections.Generic.List[object]'
$agingRows = New-Object 'System.Collections.Generic.List[object]'
$recordRows = New-Object 'System.Collections.Generic.List[object]'
$recordCounts = New-Object 'System.Collections.Generic.List[object]'
$candidates = New-Object 'System.Collections.Generic.List[object]'
$queryRows = New-Object 'System.Collections.Generic.List[object]'
$reportName = 'DNSAudit-{0}-{1}' -f $auditStarted.ToString('yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0,8))
$reportPath = Join-Path $OutputDirectory $reportName
$null = New-Item -Path $reportPath -ItemType Directory -Force -ErrorAction Stop
$reportPath = (Resolve-Path -LiteralPath $reportPath).Path

function Get-AuditValue {
    param([object]$InputObject, [string]$Name)
    if ($null -ne $InputObject -and $null -ne $InputObject.PSObject.Properties[$Name]) {
        return $InputObject.PSObject.Properties[$Name].Value
    }
    return $null
}

function Add-AuditCollection {
    param([string]$Area, [string]$Target, [string]$Status, [object]$Count, [string]$Details)
    $collections.Add([pscustomobject]@{Area=$Area; Target=$Target; Status=$Status; Count=$Count; Details=$Details})
}

function Add-AuditError {
    param([string]$Area, [string]$Target, [object]$ErrorRecord)
    $message = [string]$ErrorRecord
    $errorId = ''
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $message = $ErrorRecord.Exception.Message
        $errorId = $ErrorRecord.FullyQualifiedErrorId
    }
    $auditErrors.Add([pscustomobject]@{Area=$Area; Target=$Target; Message=$message; ErrorId=$errorId})
    Add-AuditCollection -Area $Area -Target $Target -Status 'Failed' -Count $null -Details $message
}

function Add-ReviewFlag {
    param([string]$Area, [string]$Target, [string]$Finding, [string]$Review)
    $flags.Add([pscustomobject]@{Area=$Area; Target=$Target; Finding=$Finding; Review=$Review})
}

function Convert-AuditText {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [timespan]) { return $Value.ToString() }
    if ($Value -is [datetime]) { return $Value.ToString('o') }
    if ($Value -is [System.Net.IPAddress]) { return $Value.IPAddressToString }
    if ($Value -is [string] -or $Value.GetType().IsValueType) { return [string]$Value }
    if ($Value -is [System.Collections.IEnumerable]) {
        return (@($Value | ForEach-Object { Convert-AuditText -Value $_ }) -join '; ')
    }
    return ($Value | ConvertTo-Json -Depth 5 -Compress)
}

function Add-Configuration {
    param([string]$Area, [object[]]$Items)
    $itemNumber = 0
    foreach ($item in $Items) {
        $itemNumber++
        foreach ($property in $item.PSObject.Properties) {
            if ($property.Name -notmatch '^(CimClass|CimInstanceProperties|CimSystemProperties|PSComputerName|PSShowComputerName|RunspaceId)$') {
                $configuration.Add([pscustomobject]@{Area=$Area; Item=$itemNumber; Name=$property.Name; Value=(Convert-AuditText $property.Value)})
            }
        }
    }
}

function Invoke-AuditRead {
    param([string]$Area, [scriptblock]$Read)
    try {
        $items = @(& $Read)
        $status = 'Succeeded'
        if ($items.Count -eq 0) { $status = 'Empty' }
        Add-AuditCollection $Area $ComputerName $status $items.Count 'Read completed; empty is not a health assertion.'
        Add-Configuration -Area $Area -Items $items
        return $items
    }
    catch { Add-AuditError $Area $ComputerName $_ }
}

function Export-AuditCsv {
    param([string]$Name, [object[]]$Rows, [string[]]$Columns)
    $path = Join-Path $reportPath $Name
    if ($Rows.Count -gt 0) {
        $Rows | Select-Object -Property $Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    }
    else {
        # Keep a header even when the dataset is empty, skipped or unavailable.
        $header = ($Columns | ForEach-Object { '"' + $_.Replace('"','""') + '"' }) -join ','
        Set-Content -LiteralPath $path -Value $header -Encoding UTF8
    }
}

$dnsModuleAvailable = $false
try {
    Import-Module DnsServer -ErrorAction Stop
    $dnsModuleAvailable = $true
    Add-AuditCollection 'DnsServer module' $ComputerName 'Succeeded' 1 'Module imported; no installation attempted.'
}
catch {
    Add-AuditError 'DnsServer module' $ComputerName $_
    Write-Warning 'The DnsServer module could not be imported. DNS management data is unavailable; see Errors.csv. Install the appropriate DNS management tools separately.'
}

$zones = @()
$recursion = @()
$forwarders = @()
$rootHints = @()
$scavenging = @()
if ($dnsModuleAvailable) {
    $null = Invoke-AuditRead 'Server settings' { Get-DnsServerSetting -ComputerName $ComputerName -All -ErrorAction Stop }
    $recursion = @(Invoke-AuditRead 'Recursion' { Get-DnsServerRecursion -ComputerName $ComputerName -ErrorAction Stop })
    $forwarders = @(Invoke-AuditRead 'Forwarders' { Get-DnsServerForwarder -ComputerName $ComputerName -ErrorAction Stop })
    $rootHints = @(Invoke-AuditRead 'Root hints' { Get-DnsServerRootHint -ComputerName $ComputerName -ErrorAction Stop })
    $scavenging = @(Invoke-AuditRead 'Server scavenging' { Get-DnsServerScavenging -ComputerName $ComputerName -ErrorAction Stop })
    try {
        $zones = @(Get-DnsServerZone -ComputerName $ComputerName -ErrorAction Stop)
        $status = 'Succeeded'
        if ($zones.Count -eq 0) { $status = 'Empty' }
        Add-AuditCollection 'Zone inventory' $ComputerName $status $zones.Count 'Default DNS virtualization instance only.'
    }
    catch { Add-AuditError 'Zone inventory' $ComputerName $_ }
}
else {
    foreach ($area in @('Server settings','Recursion','Forwarders','Root hints','Server scavenging','Zone inventory')) {
        Add-AuditCollection $area $ComputerName 'NotAvailable' $null 'DnsServer module could not be imported.'
    }
}

# Objective configuration observations. These require review against local policy.
if ($recursion.Count -gt 0 -and $null -ne (Get-AuditValue $recursion[0] 'Enable')) {
    if ([bool](Get-AuditValue $recursion[0] 'Enable')) {
        Add-ReviewFlag 'Recursion' $ComputerName 'Recursion is enabled.' 'Confirm this resolver is restricted to intended clients by network and DNS policy. This audit does not test Internet exposure.'
        $addresses = @($forwarders | ForEach-Object { Get-AuditValue $_ 'IPAddress' } | Where-Object { $null -ne $_ })
        $forwarderRead = @($collections | Where-Object { $_.Area -eq 'Forwarders' -and $_.Status -in @('Succeeded','Empty') })
        $hintRead = @($collections | Where-Object { $_.Area -eq 'Root hints' -and $_.Status -in @('Succeeded','Empty') })
        if ($addresses.Count -eq 0 -and $rootHints.Count -eq 0 -and $forwarderRead.Count -gt 0 -and $hintRead.Count -gt 0) {
            Add-ReviewFlag 'Resolution path' $ComputerName 'Recursion is enabled; no global forwarder addresses or root hints were returned.' 'Review intended external resolution. Conditional forwarders, authoritative root zones, recursion scopes and policies can change expected behavior.'
        }
    }
}

if ($scavenging.Count -gt 0 -and $null -ne (Get-AuditValue $scavenging[0] 'ScavengingState')) {
    if (-not [bool](Get-AuditValue $scavenging[0] 'ScavengingState')) {
        Add-ReviewFlag 'Server scavenging' $ComputerName 'Automatic scavenging is disabled on this server.' 'This may be intentional when another server performs scavenging. Review all designated scavenging servers before changing settings.'
    }
}

if ($ZoneName) {
    foreach ($requested in @($ZoneName | Sort-Object -Unique)) {
        if (@($zones | Where-Object { [string](Get-AuditValue $_ 'ZoneName') -eq $requested }).Count -eq 0) {
            Add-AuditError 'Requested zone' $requested 'Requested zone was not returned. It may be absent or the zone inventory may be unavailable.'
        }
    }
}

foreach ($zone in @($zones | Sort-Object ZoneName)) {
    $name = [string](Get-AuditValue $zone 'ZoneName')
    $zoneType = [string](Get-AuditValue $zone 'ZoneType')
    $selected = (-not $ZoneName -or $name -in $ZoneName)
    $zoneRows.Add([pscustomobject]@{
        ZoneName=$name; Selected=$selected; ZoneType=$zoneType
        IsDsIntegrated=(Get-AuditValue $zone 'IsDsIntegrated')
        IsReverseLookupZone=(Get-AuditValue $zone 'IsReverseLookupZone')
        DynamicUpdate=(Get-AuditValue $zone 'DynamicUpdate')
        ReplicationScope=(Get-AuditValue $zone 'ReplicationScope')
        DirectoryPartitionName=(Get-AuditValue $zone 'DirectoryPartitionName')
        IsPaused=(Get-AuditValue $zone 'IsPaused')
        IsShutdown=(Get-AuditValue $zone 'IsShutdown')
        IsAutoCreated=(Get-AuditValue $zone 'IsAutoCreated')
        IsSigned=(Get-AuditValue $zone 'IsSigned')
        MasterServers=(Convert-AuditText (Get-AuditValue $zone 'MasterServers'))
    })
    if (-not $selected) { continue }
    if ([string](Get-AuditValue $zone 'DynamicUpdate') -eq 'NonsecureAndSecure') {
        Add-ReviewFlag 'Dynamic updates' $name 'Zone allows nonsecure and secure dynamic updates.' 'Review whether unauthenticated updates are intended. AD-integrated internal zones commonly use secure-only updates.'
    }
    if ((Get-AuditValue $zone 'IsPaused') -eq $true -or (Get-AuditValue $zone 'IsShutdown') -eq $true) {
        Add-ReviewFlag 'Zone state' $name 'Zone is paused or shut down.' 'Confirm whether this is an expected maintenance state.'
    }

    $aging = $null
    $window = $null
    $cutoff = $null
    $agingEnabled = $null
    if ($zoneType -eq 'Primary') {
        try {
            $agingResult = @(Get-DnsServerZoneAging -ComputerName $ComputerName -Name $name -ErrorAction Stop)
            if ($agingResult.Count -eq 0) {
                Add-AuditError 'Zone aging' $name 'Aging query returned no settings. Aging status is unknown.'
            }
            else {
                $aging = $agingResult[0]
                $agingEnabled = Get-AuditValue $aging 'AgingEnabled'
                $noRefresh = Get-AuditValue $aging 'NoRefreshInterval'
                $refresh = Get-AuditValue $aging 'RefreshInterval'
                if ($noRefresh -is [timespan] -and $refresh -is [timespan]) {
                    $window = $noRefresh + $refresh
                    $cutoff = $auditStarted.Subtract($window)
                }
                $agingRows.Add([pscustomobject]@{
                    ZoneName=$name; AgingEnabled=$agingEnabled
                    NoRefreshInterval=(Convert-AuditText $noRefresh)
                    RefreshInterval=(Convert-AuditText $refresh)
                    ReviewWindowHours=$(if ($null -ne $window) { $window.TotalHours } else { $null })
                    TimestampReviewCutoff=$(if ($null -ne $cutoff) { $cutoff.ToString('o') } else { '' })
                    AvailForScavengeTime=(Convert-AuditText (Get-AuditValue $aging 'AvailForScavengeTime'))
                    ScavengeServers=(Convert-AuditText (Get-AuditValue $aging 'ScavengeServers'))
                })
                Add-AuditCollection 'Zone aging' $name 'Succeeded' 1 'Reported server value AvailForScavengeTime is not a predicted record deletion time.'
                if ($agingEnabled -eq $false) {
                    Add-ReviewFlag 'Zone aging' $name 'Zone aging is disabled.' 'This may be deliberate for static zones. Review registration and cleanup policy before enabling aging.'
                }
            }
        }
        catch { Add-AuditError 'Zone aging' $name $_ }
    }
    else {
        Add-AuditCollection 'Zone aging' $name 'NotApplicable' $null 'Zone aging configuration is collected only for primary zones.'
    }

    if (-not $IncludeRecords) {
        Add-AuditCollection 'Records' $name 'NotRequested' $null 'Use -IncludeRecords to opt in to record counts, full export and timestamp review.'
        continue
    }
    if ($zoneType -notin @('Primary','Secondary')) {
        Add-AuditCollection 'Records' $name 'NotApplicable' $null 'Record enumeration is limited to primary and secondary zones.'
        continue
    }
    $zoneRecords = @()
    try {
        $zoneRecords = @(Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $name -ErrorAction Stop)
        $status = 'Succeeded'
        if ($zoneRecords.Count -eq 0) { $status = 'Empty' }
        Add-AuditCollection 'Records' $name $status $zoneRecords.Count 'Default zone scope only. Failed queries are not counted as empty zones.'
    }
    catch {
        Add-AuditError 'Records' $name $_
        continue
    }
    $staticCount = 0
    $timestampCount = 0
    $unknownTimestampCount = 0
    $candidateCount = 0
    $futureCount = 0
    foreach ($record in $zoneRecords) {
        $rawTimestamp = Get-AuditValue $record 'Timestamp'
        $timestamp = $null
        $timestampClass = 'Unknown'
        if ($null -eq $rawTimestamp -or [string]$rawTimestamp -eq '' -or [string]$rawTimestamp -eq '0' -or ($rawTimestamp -is [datetime] -and $rawTimestamp.Year -le 1601)) {
            $timestampClass = 'StaticOrNoTimestamp'
            $staticCount++
        }
        elseif ($rawTimestamp -is [datetime]) {
            $timestamp = $rawTimestamp
            $timestampClass = 'Timestamped'
            $timestampCount++
        }
        else {
            $parsed = [datetime]::MinValue
            if ($rawTimestamp -is [string] -and [datetime]::TryParse($rawTimestamp, [ref]$parsed)) {
                if ($parsed.Year -le 1601) {
                    $timestampClass = 'StaticOrNoTimestamp'
                    $staticCount++
                }
                else {
                    $timestamp = $parsed
                    $timestampClass = 'Timestamped'
                    $timestampCount++
                }
            }
            else { $unknownTimestampCount++ }
        }
        $isCandidate = $false
        if ($null -ne $timestamp -and $timestamp -gt $auditStarted) { $futureCount++ }
        if ($null -ne $timestamp -and $null -ne $cutoff -and $timestamp -lt $cutoff) {
            $isCandidate = $true
            $candidateCount++
        }
        $row = [pscustomobject]@{
            ZoneName=$name; HostName=(Get-AuditValue $record 'HostName')
            RecordType=(Get-AuditValue $record 'RecordType')
            Timestamp=(Convert-AuditText $rawTimestamp); TimestampClass=$timestampClass
            TimeToLive=(Convert-AuditText (Get-AuditValue $record 'TimeToLive'))
            RecordData=(Convert-AuditText (Get-AuditValue $record 'RecordData'))
            TimestampOlderThanWindow=$(if ($null -ne $cutoff -and $timestampClass -ne 'Unknown') { $isCandidate } else { $null })
            ZoneAgingEnabled=$agingEnabled
        }
        $recordRows.Add($row)
        if ($isCandidate) { $candidates.Add($row) }
    }
    foreach ($group in @($zoneRecords | Group-Object RecordType)) {
        $recordCounts.Add([pscustomobject]@{ZoneName=$name; Measure='RecordType'; RecordType=$group.Name; Count=$group.Count})
    }
    foreach ($measure in @(
        @{Name='Total'; Value=$zoneRecords.Count},
        @{Name='StaticOrNoTimestamp'; Value=$staticCount},
        @{Name='Timestamped'; Value=$timestampCount},
        @{Name='UnknownTimestamp'; Value=$unknownTimestampCount},
        @{Name='FutureTimestamp'; Value=$futureCount},
        @{Name='TimestampOlderThanWindow'; Value=$(if ($null -ne $cutoff) { $candidateCount } else { $null })}
    )) {
        $recordCounts.Add([pscustomobject]@{ZoneName=$name; Measure=$measure.Name; RecordType=''; Count=$measure.Value})
    }
    if ($candidateCount -gt 0) {
        Add-ReviewFlag 'Record timestamps' $name ("{0} record timestamps are older than the zone no-refresh + refresh window." -f $candidateCount) 'Candidates require validation with owners and registration/replication activity. They are not proven unused or deletion eligible; aging can be disabled.'
    }
    if ($futureCount -gt 0) {
        Add-ReviewFlag 'Record timestamps' $name ("{0} records have timestamps later than audit start time." -f $futureCount) 'Review clock alignment and timestamp interpretation.'
    }
}

$tests = New-Object 'System.Collections.Generic.List[object]'
if ($ExpectedDomain) {
    $domain = $ExpectedDomain.TrimEnd('.')
    foreach ($prefix in @('_ldap._tcp.dc._msdcs','_kerberos._tcp','_ldap._tcp.pdc._msdcs')) {
        $tests.Add([pscustomobject]@{Name=($prefix + '.' + $domain); Type='SRV'; Purpose='AD service location'})
    }
}
foreach ($name in @($TestName | Sort-Object -Unique)) {
    if ($name) { $tests.Add([pscustomobject]@{Name=$name; Type='A'; Purpose='Operator-specified hostname'}) }
}
if ($tests.Count -eq 0) {
    Add-AuditCollection 'DNS query tests' $ComputerName 'NotRequested' $null 'Use -ExpectedDomain and/or -TestName for targeted DNS queries.'
}
foreach ($test in $tests) {
    try {
        $answers = @(Resolve-DnsName -Name $test.Name -Type $test.Type -Server $ComputerName -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
        $matching = @($answers | Where-Object { [string](Get-AuditValue $_ 'Type') -eq $test.Type -and [string](Get-AuditValue $_ 'Section') -eq 'Answer' })
        $status = 'Answered'
        if ($matching.Count -eq 0) { $status = 'NoRequestedAnswer' }
        $queryRows.Add([pscustomobject]@{
            Name=$test.Name; Type=$test.Type; Server=$ComputerName; Purpose=$test.Purpose
            Status=$status; RequestedAnswerCount=$matching.Count
            Answers=($answers | ConvertTo-Json -Depth 5 -Compress); Error=''
        })
        Add-AuditCollection 'DNS query' $test.Name 'Succeeded' $matching.Count $status
        if ($matching.Count -eq 0) {
            Add-ReviewFlag 'DNS query' $test.Name 'Query returned no requested record in the answer section.' 'Review zone contents, delegation, split DNS and whether this record type is expected. A valid empty answer does not establish a server outage.'
        }
    }
    catch {
        Add-AuditError 'DNS query' $test.Name $_
        $queryRows.Add([pscustomobject]@{
            Name=$test.Name; Type=$test.Type; Server=$ComputerName; Purpose=$test.Purpose
            Status='Failed'; RequestedAnswerCount=$null; Answers=''; Error=$_.Exception.Message
        })
    }
}

$recordColumns = @('ZoneName','HostName','RecordType','Timestamp','TimestampClass','TimeToLive','RecordData','TimestampOlderThanWindow','ZoneAgingEnabled')
Export-AuditCsv 'Collections.csv' $collections.ToArray() @('Area','Target','Status','Count','Details')
Export-AuditCsv 'Errors.csv' $auditErrors.ToArray() @('Area','Target','Message','ErrorId')
Export-AuditCsv 'ReviewFlags.csv' $flags.ToArray() @('Area','Target','Finding','Review')
Export-AuditCsv 'ServerConfiguration.csv' $configuration.ToArray() @('Area','Item','Name','Value')
Export-AuditCsv 'Zones.csv' $zoneRows.ToArray() @('ZoneName','Selected','ZoneType','IsDsIntegrated','IsReverseLookupZone','DynamicUpdate','ReplicationScope','DirectoryPartitionName','IsPaused','IsShutdown','IsAutoCreated','IsSigned','MasterServers')
Export-AuditCsv 'ZoneAging.csv' $agingRows.ToArray() @('ZoneName','AgingEnabled','NoRefreshInterval','RefreshInterval','ReviewWindowHours','TimestampReviewCutoff','AvailForScavengeTime','ScavengeServers')
Export-AuditCsv 'RecordCounts.csv' $recordCounts.ToArray() @('ZoneName','Measure','RecordType','Count')
Export-AuditCsv 'Records.csv' $recordRows.ToArray() $recordColumns
Export-AuditCsv 'TimestampReviewCandidates.csv' $candidates.ToArray() $recordColumns
Export-AuditCsv 'DnsQueries.csv' $queryRows.ToArray() @('Name','Type','Server','Purpose','Status','RequestedAnswerCount','Answers','Error')

$status = 'Complete'
if ($auditErrors.Count -gt 0) { $status = 'Partial' }
if (-not $dnsModuleAvailable) { $status = 'ManagementDataUnavailable' }
$summary = [pscustomobject]@{
    Script=$MyInvocation.MyCommand.Name; ComputerName=$ComputerName
    Started=$auditStarted.ToString('o'); Finished=(Get-Date).ToString('o')
    CollectionStatus=$status; ReportDirectory=$reportPath; ReportPath=$reportPath
    RequestedZones=@($ZoneName); ExpectedDomain=$ExpectedDomain; TestName=@($TestName)
    IncludeRecords=[bool]$IncludeRecords; Scope='Default DNS virtualization instance and default zone scopes only'
    ZoneInventoryCount=$zoneRows.Count
    SelectedZoneCount=@($zoneRows | Where-Object { $_.Selected }).Count
    ExportedRecordCount=$recordRows.Count
    TimestampReviewCandidateCount=$candidates.Count
    ReviewFlagCount=$flags.Count; ErrorCount=$auditErrors.Count
    Caveats=@(
        'CollectionStatus describes data collection, not DNS or AD health. Failed and unavailable sections remain unknown.',
        'Complete means requested reads completed; omitted record scans and DNS query tests are listed as NotRequested.',
        'Timestamp age does not prove a record is unused, safe to delete or currently eligible for scavenging.',
        'No next scavenging date is calculated. Server schedules, zone grace periods and designated servers affect actual deletion.',
        'DNS responses test service-location records only; they do not verify AD service health or every domain controller.',
        'No DNS changes, scavenging, service restarts or module installations were performed.'
    )
    Collections=$collections.ToArray(); ReviewFlags=$flags.ToArray(); Errors=$auditErrors.ToArray()
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $reportPath 'Summary.json') -Encoding UTF8
$overview = New-Object 'System.Collections.Generic.List[string]'
$overview.Add('DNS server audit')
$overview.Add(('Server: {0}' -f $ComputerName))
$overview.Add(('Started: {0}' -f $auditStarted.ToString('o')))
$overview.Add(('Collection status: {0} (not a health verdict)' -f $status))
$overview.Add(('Zones inventoried: {0}; selected: {1}' -f $zoneRows.Count, $summary.SelectedZoneCount))
$overview.Add(('Full record scan requested: {0}; records exported: {1}; timestamp review candidates: {2}' -f [bool]$IncludeRecords, $recordRows.Count, $candidates.Count))
$overview.Add(('Review flags: {0}; failed queries: {1}' -f $flags.Count, $auditErrors.Count))
$overview.Add('')
$overview.Add('Collection results:')
foreach ($item in $collections) { $overview.Add(('{0} | {1} | {2} | {3}' -f $item.Area, $item.Target, $item.Status, $item.Details)) }
$overview.Add('')
$overview.Add('Review flags:')
if ($flags.Count -eq 0) { $overview.Add('No flags generated from available data. Check failed, unavailable and skipped collections before drawing conclusions.') }
foreach ($flag in $flags) { $overview.Add(('{0}: {1} {2}' -f $flag.Target, $flag.Finding, $flag.Review)) }
$overview.Add('')
$overview.Add('Limits and interpretation:')
foreach ($caveat in $summary.Caveats) { $overview.Add($caveat) }
$overview.Add('Header-only CSV files contain no rows; Collections.csv explains whether each source was empty, skipped or unavailable.')
$overview.Add('Protect these reports as internal infrastructure data.')
$overview | Set-Content -LiteralPath (Join-Path $reportPath 'Overview.txt') -Encoding UTF8
Write-Host ('DNS audit saved to: {0}' -f $reportPath)
Write-Host ('Collection status: {0}; review flags: {1}; failed queries: {2}' -f $status, $flags.Count, $auditErrors.Count)
$summary

