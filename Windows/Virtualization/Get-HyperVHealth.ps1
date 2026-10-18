<#
What it does:
  Reports local Hyper-V VM states, integration services, checkpoint ages, and storage paths.

Available flags:
  -MaxVMs: Maximum VMs to inspect (default 100).
  -MaxCheckpointsPerVM: Maximum checkpoints per VM (default 100).
  -MaxDisksPerVM: Maximum attached disks per VM (default 64).
  -CheckpointAgeDays: Checkpoint age threshold to flag (default 7).
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Reads installed Hyper-V tools with host read access. Checks local host defaults and attached disk
  paths without mounting disks. Failed sections remain Unknown. No VM, checkpoint, replication,
  disk, or integration setting is changed.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1,10000)][int]$MaxVMs=100,
    [ValidateRange(1,10000)][int]$MaxCheckpointsPerVM=100,
    [ValidateRange(1,1000)][int]$MaxDisksPerVM=64,
    [ValidateRange(1,36500)][int]$CheckpointAgeDays=7,
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

$vmRows=New-Object 'System.Collections.Generic.List[object]';$integrationRows=New-Object 'System.Collections.Generic.List[object]';$checkpointRows=New-Object 'System.Collections.Generic.List[object]';$pathRows=New-Object 'System.Collections.Generic.List[object]'
$vmCapReached=$false;$checkpointCapVMs=0;$diskCapVMs=0;$observed=Get-Date
function Add-HyperVPathEvidence {
    param([string]$Owner,[string]$Kind,[string]$Path)
    $check=Invoke-ReportQuery -Section ('Path '+$Owner+' '+$Kind+' '+$Path) -RequireData -Action {
        if([string]::IsNullOrWhiteSpace($Path)){throw 'No path was supplied by the provider.'}
        Get-Item -LiteralPath $Path -Force -ErrorAction Stop | Select-Object FullName,PSIsContainer
    }
    $pathRows.Add([pscustomobject]@{Owner=$Owner;Kind=$Kind;Path=$Path;AccessStatus=$(if($check.Succeeded){'Accessible'}else{'Unknown: missing or inaccessible'});IsDirectory=$(if($check.Succeeded){($check.Data | Select-Object -First 1).PSIsContainer}else{$null})})
}
$tools=Invoke-ReportQuery -Section 'Hyper-V tools' -RequireData -Action { Import-Module Hyper-V -ErrorAction Stop; 'Available' }
if($tools.Succeeded){
    $hostResult=Invoke-ReportQuery -Section 'Hyper-V host' -RequireData -Action { Get-VMHost -ErrorAction Stop }
    foreach($hostData in $hostResult.Data){
        Add-HyperVPathEvidence 'Host' 'Default VM folder' ([string]$hostData.VirtualMachinePath)
        Add-HyperVPathEvidence 'Host' 'Default disk folder' ([string]$hostData.VirtualHardDiskPath)
    }
    $vms=Invoke-ReportQuery -Section 'Virtual machines' -Action { Get-VM -ErrorAction Stop | Select-Object -First ($MaxVMs+1) }
    $vmCapReached=$vms.Data.Count -gt $MaxVMs
    foreach($vm in @($vms.Data | Select-Object -First $MaxVMs)){
        $vmRows.Add([pscustomobject]@{Name=$vm.Name;Id=[string]$vm.Id;State=[string]$vm.State;Status=[string]$vm.Status;Generation=$vm.Generation;CPUUsage=$vm.CPUUsage;MemoryAssigned=$vm.MemoryAssigned;Uptime=[string]$vm.Uptime;ReplicationState=[string]$vm.ReplicationState;ReplicationHealth=[string]$vm.ReplicationHealth})
        $services=Invoke-ReportQuery -Section ('Integration services '+$vm.Name) -Action { Get-VMIntegrationService -VM $vm -ErrorAction Stop }
        foreach($service in $services.Data){$integrationRows.Add([pscustomobject]@{VMName=$vm.Name;Name=$service.Name;Enabled=$service.Enabled;PrimaryStatus=[string]$service.PrimaryStatusDescription;SecondaryStatus=[string]$service.SecondaryStatusDescription;PrimaryOperationalStatus=[string]$service.PrimaryOperationalStatus;SecondaryOperationalStatus=[string]$service.SecondaryOperationalStatus})}
        $checkpoints=Invoke-ReportQuery -Section ('Checkpoints '+$vm.Name) -Action { Get-VMSnapshot -VM $vm -ErrorAction Stop | Select-Object -First ($MaxCheckpointsPerVM+1) }
        if($checkpoints.Data.Count -gt $MaxCheckpointsPerVM){$checkpointCapVMs++}
        foreach($checkpoint in @($checkpoints.Data | Select-Object -First $MaxCheckpointsPerVM)){
            $age=$null;$flag='Unknown'
            if($checkpoint.CreationTime){$age=[math]::Round(($observed-[datetime]$checkpoint.CreationTime).TotalDays,2);$flag=$(if($age -ge $CheckpointAgeDays){'Review age threshold'}else{'Below age threshold'})}
            $checkpointRows.Add([pscustomobject]@{VMName=$vm.Name;Name=$checkpoint.Name;Id=[string]$checkpoint.Id;SnapshotType=[string]$checkpoint.SnapshotType;CreationTime=$checkpoint.CreationTime;AgeDays=$age;AgeFlag=$flag})
        }
        $disks=Invoke-ReportQuery -Section ('Attached disks '+$vm.Name) -Action { Get-VMHardDiskDrive -VM $vm -ErrorAction Stop | Select-Object -First ($MaxDisksPerVM+1) }
        if($disks.Data.Count -gt $MaxDisksPerVM){$diskCapVMs++}
        foreach($disk in @($disks.Data | Select-Object -First $MaxDisksPerVM)){
            if([string]::IsNullOrWhiteSpace([string]$disk.Path)){$pathRows.Add([pscustomobject]@{Owner=$vm.Name;Kind='Attached disk';Path='';AccessStatus='Not applicable: no file path (for example pass-through disk)';IsDirectory=$null})}
            else{Add-HyperVPathEvidence $vm.Name 'Attached disk' ([string]$disk.Path)}
        }
    }
}
Write-ReportCsv 'virtual-machines' $vmRows.ToArray() @('Name','Id','State','Status','Generation','CPUUsage','MemoryAssigned','Uptime','ReplicationState','ReplicationHealth')
Write-ReportCsv 'integration-services' $integrationRows.ToArray() @('VMName','Name','Enabled','PrimaryStatus','SecondaryStatus','PrimaryOperationalStatus','SecondaryOperationalStatus')
Write-ReportCsv 'checkpoints' $checkpointRows.ToArray() @('VMName','Name','Id','SnapshotType','CreationTime','AgeDays','AgeFlag')
Write-ReportCsv 'storage-paths' $pathRows.ToArray() @('Owner','Kind','Path','AccessStatus','IsDirectory')
$summaryData=[pscustomobject]@{VMCount=$vmRows.Count;RunningVMCount=@($vmRows | Where-Object State -eq 'Running').Count;VMsWithReportedReplicationConcern=@($vmRows | Where-Object {$_.ReplicationHealth -and $_.ReplicationHealth -notin @('Normal','NotApplicable')}).Count;IntegrationServiceCount=$integrationRows.Count;DisabledIntegrationServiceCount=@($integrationRows | Where-Object Enabled -eq $false).Count;CheckpointCount=$checkpointRows.Count;OldCheckpointCount=@($checkpointRows | Where-Object AgeFlag -eq 'Review age threshold').Count;UnknownOrInaccessiblePathCount=@($pathRows | Where-Object AccessStatus -like 'Unknown*').Count;VMCapReached=$vmCapReached;CheckpointCapVMCount=$checkpointCapVMs;DiskCapVMCount=$diskCapVMs;CheckpointAgeDays=$CheckpointAgeDays}
Complete-Report $summaryData @('Local host only. Paths are checked using the caller account; access does not prove the VM service account can use them. Missing and denied paths are Unknown.','Off or paused VMs and disabled integration services can be intentional. Integration statuses depend on VM state and guest support.','Checkpoint age is a review threshold, not a recommendation to delete checkpoints. No disk integrity, capacity, or recovery test is performed.','Counts cover inspected items only. Caps limit VM, checkpoint, and disk enumeration; provider calls have no hard timeout.')

