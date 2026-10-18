<#
What it does:
  Lists mapped drives and checks whether their roots are accessible.

Available flags:
  -OutputDirectory <path>: Report destination; default Windows\Reports.

How it works:
  Combines CIM mappings with persistent mappings in the current user's registry, then reads each
  drive root. Saves CSV/JSON reports; use the affected user's logon context and allow for Windows
  network timeouts.
#>
#requires -Version 5.1

[CmdletBinding()]
param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$reportDirectory = Join-Path $OutputDirectory ('09-MappedDrives_{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $reportDirectory -Force -ErrorAction Stop
$mappings = @{}
$failures = New-Object 'System.Collections.Generic.List[object]'
try {
    foreach ($disk in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=4' -ErrorAction Stop)) {
        $mappings[[string]$disk.DeviceID] = [pscustomobject]@{Drive=[string]$disk.DeviceID;RemotePath=[string]$disk.ProviderName;Source='ConnectedCIM'}
    }
} catch { $failures.Add([pscustomobject]@{Step='ConnectedMappings';Error=$_.Exception.Message}) }
try {
    if (Test-Path -LiteralPath 'HKCU:\Network' -ErrorAction Stop) {
        foreach ($key in @(Get-ChildItem -LiteralPath 'HKCU:\Network' -ErrorAction Stop)) {
            try {
                $property = Get-ItemProperty -LiteralPath $key.PSPath -Name RemotePath -ErrorAction Stop
                $driveName = '{0}:' -f $key.PSChildName
                if ($mappings.ContainsKey($driveName)) { $mappings[$driveName].Source = 'ConnectedCIM+PersistentHKCU' }
                else { $mappings[$driveName] = [pscustomobject]@{Drive=$driveName;RemotePath=[string]$property.RemotePath;Source='PersistentHKCU'} }
            } catch { $failures.Add([pscustomobject]@{Step=('PersistentMapping '+$key.PSChildName);Error=$_.Exception.Message}) }
        }
    }
} catch { $failures.Add([pscustomobject]@{Step='PersistentMappings';Error=$_.Exception.Message}) }
$rows = New-Object 'System.Collections.Generic.List[object]'
foreach ($mapping in @($mappings.Values | Sort-Object Drive)) {
    $result = 'Accessible'; $problem = ''
    try { $null = Get-Item -LiteralPath ($mapping.Drive+'\') -ErrorAction Stop }
    catch { $result = 'UnavailableOrInaccessible'; $problem = $_.Exception.Message }
    $rows.Add([pscustomobject]@{Drive=$mapping.Drive;RemotePath=$mapping.RemotePath;Source=$mapping.Source;Result=$result;Error=$problem})
}
if ($rows.Count -gt 0) { $rows | Export-Csv -LiteralPath (Join-Path $reportDirectory 'drives.csv') -NoTypeInformation -Encoding UTF8 }
else { '"Drive","RemotePath","Source","Result","Error"' | Set-Content -LiteralPath (Join-Path $reportDirectory 'drives.csv') -Encoding UTF8 }
$unavailable = @($rows | Where-Object Result -ne 'Accessible').Count
$status = 'Success'
if ($failures.Count -gt 0) { $status = 'Partial'; if ($rows.Count -eq 0) { $status = 'Failed' } }
elseif ($rows.Count -eq 0) { $status = 'NoData' } elseif ($unavailable -gt 0) { $status = 'NeedsReview' }
$summary = [pscustomobject]@{ReportDirectory=$reportDirectory;Status=$status;MappingCount=$rows.Count;UnavailableCount=$unavailable;DiscoveryFailureCount=$failures.Count}
[pscustomobject]@{Summary=$summary;Drives=@($rows.ToArray());DiscoveryFailures=@($failures.ToArray())} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $reportDirectory 'report.json') -Encoding UTF8
'Scope: connected CIM mappings and persistent HKCU mappings in this process logon context. No mappings found does not establish that another user/session has no mappings. A root read can block until Windows network timeouts expire. Root access does not prove access to every file. UNC names and internal server names may appear in reports.' | Set-Content -LiteralPath (Join-Path $reportDirectory 'notes.txt') -Encoding UTF8
foreach ($failure in $failures) { Write-Warning ('{0}: {1}' -f $failure.Step,$failure.Error) }
$summary

