<#
What it does:
  Samples CPU, memory, disk activity/latency, and busy processes during a slowdown.

Available flags:
  -Samples: Number of snapshots, 2-60; default 5.
  -IntervalSeconds: Delay between snapshots, 1-30 seconds; default 2.
  -TopProcesses: Processes retained per interval; default 10.
  -OutputDirectory: Report destination; default Windows\Reports.

How it works:
  Reads local CIM performance data and process CPU deltas, normalized by logical CPU count. Disk
  latency uses raw counter deltas; idle or unavailable counters remain distinct. Requires readable
  performance providers; collected samples are observations, not a diagnosis.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
[ValidateRange(2,60)][int]$Samples=5,
[ValidateRange(1,30)][int]$IntervalSeconds=2,
[ValidateRange(1,100)][int]$TopProcesses=10,
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

$machine=Invoke-ReportQuery -Section 'Logical processor count' -RequireData -Action {
    $computer=Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if($null -eq $computer.NumberOfLogicalProcessors -or $computer.NumberOfLogicalProcessors -le 0){throw 'Logical processor count was unavailable.'}
    [pscustomobject]@{LogicalProcessors=[int]$computer.NumberOfLogicalProcessors}
}
$logicalProcessors=$null
if($machine.Succeeded){$logicalProcessors=$machine.Data[0].LogicalProcessors}
$systemRows=New-Object 'System.Collections.Generic.List[object]'
$diskRows=New-Object 'System.Collections.Generic.List[object]'
$rawDiskRows=New-Object 'System.Collections.Generic.List[object]'
$processRows=New-Object 'System.Collections.Generic.List[object]'
$previousProcesses=@{}; $previousDisks=@{}; $previousTime=$null
for($sample=1;$sample -le $Samples;$sample++){
    if($sample -gt 1){Start-Sleep -Seconds $IntervalSeconds}
    $cpu=Invoke-ReportQuery -Section ("CPU sample $sample") -RequireData -Action {
        $value=Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
        if($null -eq $value.PercentProcessorTime){throw 'Processor performance value was not returned.'}
        $value | Select-Object Name,PercentProcessorTime
    }
    $memory=Invoke-ReportQuery -Section ("Memory sample $sample") -RequireData -Action {
        $value=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if($value.TotalVisibleMemorySize -le 0 -or $null -eq $value.FreePhysicalMemory){throw 'Memory performance values were not returned.'}
        $value | Select-Object TotalVisibleMemorySize,FreePhysicalMemory
    }
    $disks=Invoke-ReportQuery -Section ("Disk raw counters sample $sample") -RequireData -Action {
        Get-CimInstance -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk -ErrorAction Stop |
            Where-Object Name -ne '_Total' |
            Select-Object Name,Timestamp_PerfTime,Frequency_PerfTime,AvgDisksecPerTransfer,AvgDisksecPerTransfer_Base,DiskReadBytesPersec,DiskWriteBytesPersec,CurrentDiskQueueLength
    }
    $processes=Invoke-ReportQuery -Section ("Process sample $sample") -RequireData -Action {
        foreach($process in @(Get-Process -ErrorAction Stop)){
            $cpuSeconds=$null; $start=$null; $state='Available'
            try{$cpuSeconds=$process.TotalProcessorTime.TotalSeconds; $start=$process.StartTime.ToUniversalTime().ToString('o')}
            catch{$state='AccessLimited'}
            [pscustomobject]@{Id=$process.Id;Name=$process.ProcessName;StartTimeUtc=$start;CpuSeconds=$cpuSeconds;WorkingSetBytes=$process.WorkingSet64;MetricStatus=$state}
        }
    }
    $sampleTime=Get-Date
    $systemRows.Add([pscustomobject]@{
        Sample=$sample;TimestampUtc=$sampleTime.ToUniversalTime().ToString('o')
        CpuPercent=$(if($cpu.Succeeded){$cpu.Data[0].PercentProcessorTime}else{$null})
        TotalMemoryMB=$(if($memory.Succeeded){[math]::Round($memory.Data[0].TotalVisibleMemorySize/1KB,2)}else{$null})
        AvailableMemoryMB=$(if($memory.Succeeded){[math]::Round($memory.Data[0].FreePhysicalMemory/1KB,2)}else{$null})
        MemoryUsedPercent=$(if($memory.Succeeded){[math]::Round(100*(1-([double]$memory.Data[0].FreePhysicalMemory/$memory.Data[0].TotalVisibleMemorySize)),2)}else{$null})
    })
    $currentDisks=@{}
    foreach($disk in $disks.Data){
        $currentDisks[$disk.Name]=$disk
        $rawDiskRows.Add([pscustomobject]@{
            Sample=$sample;Name=$disk.Name;Timestamp_PerfTime=$disk.Timestamp_PerfTime;Frequency_PerfTime=$disk.Frequency_PerfTime
            AvgDisksecPerTransfer=$disk.AvgDisksecPerTransfer;AvgDisksecPerTransfer_Base=$disk.AvgDisksecPerTransfer_Base
            DiskReadBytesPersec=$disk.DiskReadBytesPersec;DiskWriteBytesPersec=$disk.DiskWriteBytesPersec;CurrentDiskQueueLength=$disk.CurrentDiskQueueLength
        })
        if($sample -gt 1){
            $latency=$null; $readRate=$null; $writeRate=$null; $state='UnavailableOrReset'
            $previous=$previousDisks[$disk.Name]
            if($previous -and $disk.Frequency_PerfTime -gt 0 -and $disk.Frequency_PerfTime -eq $previous.Frequency_PerfTime){
                $elapsed=([double]$disk.Timestamp_PerfTime-[double]$previous.Timestamp_PerfTime)/[double]$disk.Frequency_PerfTime
                $transfers=[double]$disk.AvgDisksecPerTransfer_Base-[double]$previous.AvgDisksecPerTransfer_Base
                $ticks=[double]$disk.AvgDisksecPerTransfer-[double]$previous.AvgDisksecPerTransfer
                $readBytes=[double]$disk.DiskReadBytesPersec-[double]$previous.DiskReadBytesPersec
                $writeBytes=[double]$disk.DiskWriteBytesPersec-[double]$previous.DiskWriteBytesPersec
                $required=@('Timestamp_PerfTime','Frequency_PerfTime','AvgDisksecPerTransfer','AvgDisksecPerTransfer_Base','DiskReadBytesPersec','DiskWriteBytesPersec')
                $missing=@($required | Where-Object {$null -eq $disk.$_ -or $null -eq $previous.$_}).Count
                if(-not $missing -and $elapsed -gt 0 -and $transfers -ge 0 -and $ticks -ge 0 -and $readBytes -ge 0 -and $writeBytes -ge 0){
                    $readRate=[math]::Round($readBytes/$elapsed,2); $writeRate=[math]::Round($writeBytes/$elapsed,2)
                    if($transfers -gt 0){$latency=[math]::Round(1000*$ticks/[double]$disk.Frequency_PerfTime/$transfers,3); $state='Measured'}
                    else{$state='NoTransfers'}
                }
            }
            $diskRows.Add([pscustomobject]@{Sample=$sample;TimestampUtc=$sampleTime.ToUniversalTime().ToString('o');Disk=$disk.Name;ReadBytesPerSecond=$readRate;WriteBytesPerSecond=$writeRate;AverageTransferMilliseconds=$latency;CurrentQueueLength=$disk.CurrentDiskQueueLength;MetricStatus=$state})
        }
    }
    $currentProcesses=@{}; $intervalRows=@()
    foreach($process in $processes.Data){
        $key=[string]$process.Id
        $currentProcesses[$key]=$process
        if($sample -gt 1){
            $previous=$previousProcesses[$key]; $delta=$null; $percent=$null; $state='NoComparableBaseline'
            if($previous -and $process.StartTimeUtc -and $process.StartTimeUtc -eq $previous.StartTimeUtc -and $null -ne $process.CpuSeconds -and $null -ne $previous.CpuSeconds){
                $seconds=($sampleTime-$previousTime).TotalSeconds
                $delta=[double]$process.CpuSeconds-[double]$previous.CpuSeconds
                if($delta -ge 0 -and $seconds -gt 0){
                    $state='CpuDeltaAvailable'
                    if($logicalProcessors){$percent=[math]::Round(100*$delta/($seconds*$logicalProcessors),2);$state='Measured'}
                }else{$delta=$null;$state='UnavailableOrReset'}
            }
            $intervalRows += [pscustomobject]@{Sample=$sample;TimestampUtc=$sampleTime.ToUniversalTime().ToString('o');Id=$process.Id;Name=$process.Name;CpuSecondsDelta=$delta;CpuPercentOfMachine=$percent;WorkingSetMB=[math]::Round($process.WorkingSetBytes/1MB,2);MetricStatus=$state}
        }
    }
    foreach($row in @($intervalRows | Sort-Object CpuSecondsDelta,WorkingSetMB -Descending | Select-Object -First $TopProcesses)){$processRows.Add($row)}
    $previousProcesses=$currentProcesses; $previousDisks=$currentDisks; $previousTime=$sampleTime
}
Write-ReportCsv 'system-samples' $systemRows.ToArray() @('Sample','TimestampUtc','CpuPercent','TotalMemoryMB','AvailableMemoryMB','MemoryUsedPercent')
Write-ReportCsv 'disk-samples' $diskRows.ToArray() @('Sample','TimestampUtc','Disk','ReadBytesPerSecond','WriteBytesPerSecond','AverageTransferMilliseconds','CurrentQueueLength','MetricStatus')
Write-ReportCsv 'disk-raw-samples' $rawDiskRows.ToArray() @('Sample','Name','Timestamp_PerfTime','Frequency_PerfTime','AvgDisksecPerTransfer','AvgDisksecPerTransfer_Base','DiskReadBytesPersec','DiskWriteBytesPersec','CurrentDiskQueueLength')
Write-ReportCsv 'top-processes' $processRows.ToArray() @('Sample','TimestampUtc','Id','Name','CpuSecondsDelta','CpuPercentOfMachine','WorkingSetMB','MetricStatus')
Complete-Report -Data ([ordered]@{Samples=$Samples;IntervalSeconds=$IntervalSeconds;LogicalProcessors=$logicalProcessors;SystemSamples=$systemRows.Count;ProcessIntervalRows=$processRows.Count;DiskIntervalRows=$diskRows.Count}) -Notes @(
    'Process CPU percentages use total CPU-time deltas divided by elapsed time and logical processor count; PID start times must match.'
    'Access-limited, new, or terminated processes may not have a comparable interval. Only the top requested processes per interval are retained.'
    'Disk latency uses PERF_AVERAGE_TIMER deltas. NoTransfers has no measured latency; unavailable/reset counters are not zero latency.'
    'Provider sampling cadence and collection overhead affect timing. No fixed performance threshold or root cause is inferred.'
)
