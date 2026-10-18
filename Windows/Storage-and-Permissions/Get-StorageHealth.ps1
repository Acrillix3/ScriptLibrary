<#
What it does:
  Reports disk and volume health with hardware reliability counters when available.

Available flags:
  -OutputDirectory: Report location (Windows\Reports by default).

How it works:
  Reads Storage-module disk, physical disk, volume, and reliability information. Unsupported
  counters remain unknown. Run elevated; writes reports without repairing disks.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([ValidateNotNullOrEmpty()][string]$OutputDirectory)
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

$disks = Invoke-ReportQuery -Section 'Disks' -RequireData -Action { Get-Disk -ErrorAction Stop }
$physicalDisks = Invoke-ReportQuery -Section 'Physical disks' -RequireData -Action { Get-PhysicalDisk -ErrorAction Stop }
$volumes = Invoke-ReportQuery -Section 'Volumes' -RequireData -Action { Get-Volume -ErrorAction Stop }
$diskRows = @(
    foreach ($disk in $disks.Data) {
        $finding = New-Object 'System.Collections.Generic.List[string]'
        if ($disk.IsOffline -eq $true) { $finding.Add('Disk is offline.') }
        if ($disk.IsReadOnly -eq $true) { $finding.Add('Disk is read-only; confirm whether this is expected.') }
        if ($disk.HealthStatus -and [string]$disk.HealthStatus -ne 'Healthy') { $finding.Add('Provider health is '+[string]$disk.HealthStatus+'.') }
        [pscustomobject]@{Number=$disk.Number;FriendlyName=$disk.FriendlyName;BusType=$disk.BusType;PartitionStyle=$disk.PartitionStyle;SizeBytes=$disk.Size;HealthStatus=$disk.HealthStatus;OperationalStatus=($disk.OperationalStatus -join '; ');IsOffline=$disk.IsOffline;IsReadOnly=$disk.IsReadOnly;EvidenceStatus=$(if($null -eq $disk.HealthStatus){'Unknown'}else{'Collected'});Findings=($finding.ToArray() -join ' ')}
    }
)
$physicalRows = @(
    foreach ($physical in $physicalDisks.Data) {
        [pscustomobject]@{DeviceId=$physical.DeviceId;FriendlyName=$physical.FriendlyName;MediaType=$physical.MediaType;BusType=$physical.BusType;SizeBytes=$physical.Size;HealthStatus=$physical.HealthStatus;OperationalStatus=($physical.OperationalStatus -join '; ');EvidenceStatus=$(if($null -eq $physical.HealthStatus){'Unknown'}else{'Collected'});Findings=$(if($physical.HealthStatus -and [string]$physical.HealthStatus -ne 'Healthy'){'Provider health is '+[string]$physical.HealthStatus+'.'}else{''})}
    }
)
$volumeRows = @(
    foreach ($volume in $volumes.Data) {
        [pscustomobject]@{DriveLetter=$volume.DriveLetter;Path=$volume.Path;FileSystemLabel=$volume.FileSystemLabel;FileSystem=$volume.FileSystem;SizeBytes=$volume.Size;FreeBytes=$volume.SizeRemaining;HealthStatus=$volume.HealthStatus;OperationalStatus=($volume.OperationalStatus -join '; ');EvidenceStatus=$(if($null -eq $volume.HealthStatus){'Unknown'}else{'Collected'});Findings=$(if($volume.HealthStatus -and [string]$volume.HealthStatus -ne 'Healthy'){'Provider health is '+[string]$volume.HealthStatus+'.'}else{''})}
    }
)
$counterRows = @(
    foreach ($physical in $physicalDisks.Data) {
        $counters = Invoke-ReportQuery -Section ('Reliability '+$physical.DeviceId) -RequireData -Action { Get-StorageReliabilityCounter -PhysicalDisk $physical -ErrorAction Stop }
        $counter = $null
        if ($counters.Succeeded) { $counter = @($counters.Data)[0] }
        $values = @('Temperature','Wear','PowerOnHours','ReadErrorsUncorrected','WriteErrorsUncorrected')
        $missing = @($values | Where-Object { -not $counter -or $null -eq $counter.$_ })
        $finding = New-Object 'System.Collections.Generic.List[string]'
        if ($counter -and $null -ne $counter.ReadErrorsUncorrected -and $counter.ReadErrorsUncorrected -gt 0) { $finding.Add('Lifetime uncorrected read errors were reported.') }
        if ($counter -and $null -ne $counter.WriteErrorsUncorrected -and $counter.WriteErrorsUncorrected -gt 0) { $finding.Add('Lifetime uncorrected write errors were reported.') }
        [pscustomobject]@{
            DeviceId=$physical.DeviceId;FriendlyName=$physical.FriendlyName;CounterStatus=$(if(-not $counters.Succeeded -or $missing.Count -eq $values.Count){'Unknown'}elseif($missing.Count){'Partial'}else{'Collected'})
            TemperatureC=$(if($counter){$counter.Temperature}else{$null});WearPercent=$(if($counter){$counter.Wear}else{$null});PowerOnHours=$(if($counter){$counter.PowerOnHours}else{$null})
            ReadErrorsUncorrected=$(if($counter){$counter.ReadErrorsUncorrected}else{$null});WriteErrorsUncorrected=$(if($counter){$counter.WriteErrorsUncorrected}else{$null})
            UnknownCounters=($missing -join '; ');Findings=($finding.ToArray() -join ' ')
        }
    }
)
Write-ReportCsv -Name 'disks' -Rows $diskRows -Columns @('Number','FriendlyName','BusType','PartitionStyle','SizeBytes','HealthStatus','OperationalStatus','IsOffline','IsReadOnly','EvidenceStatus','Findings')
Write-ReportCsv -Name 'physical-disks' -Rows $physicalRows -Columns @('DeviceId','FriendlyName','MediaType','BusType','SizeBytes','HealthStatus','OperationalStatus','EvidenceStatus','Findings')
Write-ReportCsv -Name 'volumes' -Rows $volumeRows -Columns @('DriveLetter','Path','FileSystemLabel','FileSystem','SizeBytes','FreeBytes','HealthStatus','OperationalStatus','EvidenceStatus','Findings')
Write-ReportCsv -Name 'reliability-counters' -Rows $counterRows -Columns @('DeviceId','FriendlyName','CounterStatus','TemperatureC','WearPercent','PowerOnHours','ReadErrorsUncorrected','WriteErrorsUncorrected','UnknownCounters','Findings')
Complete-Report -Data ([pscustomobject]@{Disks=$diskRows;PhysicalDisks=$physicalRows;Volumes=$volumeRows;Reliability=$counterRows}) -Notes @(
    'Requires the Windows Storage module and permission to query storage providers. RAID controllers, virtual disks, and some hardware do not expose counters.'
    'Blank or unsupported counters remain unknown, never zero. Provider Healthy status does not guarantee future disk reliability.'
    'Storage cmdlets may expose cluster-wide storage when run on a failover cluster. Disk and physical-disk IDs are separate namespaces and are not assumed to match.'
    'No surface scan, CHKDSK repair, optimization, volume change, or disk configuration operation is performed.'
)
