<#
What it does:
  Lists the largest files in a chosen folder without deleting anything.

Available flags:
  -LiteralPath <folder>: Required; folder to scan.
  -Top <number>: Maximum files to list; default 25.
  -MinimumSizeMB <number>: Minimum file size in MiB; default 100.
  -Recurse: Include subfolders.
  -OutputDirectory <path>: Report destination; default Windows\Reports.

How it works:
  Scans file metadata, keeps the largest matches, and saves CSV/JSON reports. Skips links/reparse
  points and this run's report folder; records folders it cannot read.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$LiteralPath,
    [ValidateRange(1,10000)][int]$Top=25,
    [ValidateRange(0,1048576)][double]$MinimumSizeMB=100,
    [switch]$Recurse,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$root=Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
if (!$root.PSIsContainer -or $root.PSProvider.Name -ne 'FileSystem') { throw 'LiteralPath must be an existing filesystem directory.' }
if ($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'The scan root is a reparse point. Choose a physical directory.' }
$runName='04-LargeFiles-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), ([guid]::NewGuid().ToString('N').Substring(0,8))
$report=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force).FullName
$excludedRoot=[IO.Path]::GetFullPath($report).TrimEnd('\')
$queryErrors=New-Object 'System.Collections.Generic.List[object]'
$pending=New-Object 'System.Collections.Generic.Stack[string]'
$pending.Push($root.FullName)
$candidates=@(); $filesScanned=0; $directoriesScanned=0; $skippedLinks=0; $excludedDirectories=0
$minimumBytes=$MinimumSizeMB * 1MB
while ($pending.Count) {
    $directory=$pending.Pop()
    if ($directory.TrimEnd('\').Equals($excludedRoot,[StringComparison]::OrdinalIgnoreCase) -or $directory.StartsWith($excludedRoot+'\',[StringComparison]::OrdinalIgnoreCase)) {
        $excludedDirectories++; continue
    }
    try {
        $items=@(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)
        $directoriesScanned++
    } catch {
        $queryErrors.Add([pscustomobject]@{Path=$directory; Error=$_.Exception.Message})
        continue
    }
    foreach ($item in $items) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { $skippedLinks++; continue }
        if ($item.PSIsContainer) {
            if ($Recurse) { $pending.Push($item.FullName) }
        } else {
            $filesScanned++
            if ($item.Length -ge $minimumBytes) {
                $candidates += [pscustomobject]@{
                    FullName=$item.FullName; SizeBytes=$item.Length
                    SizeMB=[math]::Round($item.Length / 1MB,2); LastWriteTimeUtc=$item.LastWriteTimeUtc
                }
                if ($candidates.Count -gt (2*$Top)) { $candidates=@($candidates | Sort-Object SizeBytes -Descending | Select-Object -First $Top) }
            }
        }
    }
}
$rows=@($candidates | Sort-Object SizeBytes -Descending | Select-Object -First $Top)
if ($rows.Count) { $rows | Export-Csv -LiteralPath (Join-Path $report 'large-files.csv') -NoTypeInformation -Encoding UTF8 }
else { '"FullName","SizeBytes","SizeMB","LastWriteTimeUtc"' | Set-Content -LiteralPath (Join-Path $report 'large-files.csv') -Encoding UTF8 }
if ($queryErrors.Count) { $queryErrors | Export-Csv -LiteralPath (Join-Path $report 'query-errors.csv') -NoTypeInformation -Encoding UTF8 }
else { '"Path","Error"' | Set-Content -LiteralPath (Join-Path $report 'query-errors.csv') -Encoding UTF8 }
$summary=[pscustomobject]@{
    Status=$(if ($queryErrors.Count) {'Partial'} else {'Complete'})
    ScanRoot=$root.FullName; Recursive=[bool]$Recurse; FilesScanned=$filesScanned
    DirectoriesScanned=$directoriesScanned; SkippedReparsePoints=$skippedLinks
    ExcludedReportDirectories=$excludedDirectories; ReturnedFiles=$rows.Count
    MinimumSizeMB=$MinimumSizeMB; Top=$Top; QueryErrorCount=$queryErrors.Count
    CollectedUtc=[datetime]::UtcNow.ToString('o'); ReportDirectory=$report
}
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
if ($queryErrors.Count) { Write-Warning 'Some directories could not be read; see query-errors.csv.' }
$summary

