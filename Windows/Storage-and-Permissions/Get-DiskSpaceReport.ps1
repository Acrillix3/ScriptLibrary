<#
What it does:
  Reports drive space and flags volumes below your free-space limits.

Available flags:
  -MinimumFreeGB <number>: Minimum free GiB; default 10.
  -MinimumFreePercent <number>: Minimum free percentage; default 15.
  -IncludeRemovable: Also check removable drive-letter volumes.
  -OutputDirectory <path>: Report destination; default Windows\Reports.

How it works:
  Reads local drive-letter disk data through CIM and flags a volume when either limit is crossed.
  Saves CSV/JSON reports; does not clean disks or cover directory-only mount points.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateRange(0,1048576)][double]$MinimumFreeGB=10,
    [ValidateRange(0,100)][double]$MinimumFreePercent=15,
    [switch]$IncludeRemovable,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$runName='03-DiskSpace-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), ([guid]::NewGuid().ToString('N').Substring(0,8))
$report=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force).FullName
$filter='DriveType=3'
if ($IncludeRemovable) { $filter='DriveType=3 OR DriveType=2' }
try { $disks=@(Get-CimInstance -ClassName Win32_LogicalDisk -Filter $filter -ErrorAction Stop) }
catch {
    [pscustomobject]@{Status='Failed'; Error=$_.Exception.Message; ReportDirectory=$report} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
    throw
}
$rows=@(foreach ($disk in $disks) {
    $freeGB=$null; $freePercent=$null; $status='Unknown'
    if ($disk.Size -gt 0 -and $null -ne $disk.FreeSpace) {
        $freeGB=[double]$disk.FreeSpace / 1GB
        $freePercent=100 * [double]$disk.FreeSpace / [double]$disk.Size
        $status=if ($freeGB -lt $MinimumFreeGB -or $freePercent -lt $MinimumFreePercent) {'Review'} else {'OK'}
    }
    [pscustomobject]@{
        Drive=$disk.DeviceID; Label=$disk.VolumeName; FileSystem=$disk.FileSystem
        DriveType=$disk.DriveType; SizeGB=[math]::Round([double]$disk.Size / 1GB,2)
        FreeGB=$(if ($null -ne $freeGB) {[math]::Round($freeGB,2)} else {$null})
        FreePercent=$(if ($null -ne $freePercent) {[math]::Round($freePercent,2)} else {$null})
        Status=$status
    }
})
if ($rows.Count) { $rows | Export-Csv -LiteralPath (Join-Path $report 'disk-space.csv') -NoTypeInformation -Encoding UTF8 }
else { '"Drive","Label","FileSystem","DriveType","SizeGB","FreeGB","FreePercent","Status"' | Set-Content -LiteralPath (Join-Path $report 'disk-space.csv') -Encoding UTF8 }
$summary=[pscustomobject]@{
    Status=$(if (!$rows.Count -or @($rows | Where-Object Status -eq 'Unknown').Count) {'Partial'} else {'Complete'})
    CollectedUtc=[datetime]::UtcNow.ToString('o'); ComputerName=$env:COMPUTERNAME
    VolumeCount=$rows.Count; ReviewCount=@($rows | Where-Object Status -eq 'Review').Count
    UnknownCount=@($rows | Where-Object Status -eq 'Unknown').Count
    MinimumFreeGB=$MinimumFreeGB; MinimumFreePercent=$MinimumFreePercent
    Units='GB values use GiB (1,073,741,824 bytes).'; ReportDirectory=$report
}
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
$summary

