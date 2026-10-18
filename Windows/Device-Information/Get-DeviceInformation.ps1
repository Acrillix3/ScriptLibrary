<#
What it does:
  Collects computer, Windows, hardware, uptime, and domain details for a support ticket.

Available flags:
  -OutputDirectory <path>: Report destination; default Windows\Reports.

How it works:
  Reads local CIM inventory and saves CSV, JSON, and a ticket summary. Unreadable data is recorded
  as a partial result; no settings change.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$runName = '01-DeviceInformation-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), ([guid]::NewGuid().ToString('N').Substring(0,8))
$report = (New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force).FullName
$queryErrors = New-Object 'System.Collections.Generic.List[object]'
function Read-DeviceClass {
    param([string]$ClassName)
    try {
        $items=@(Get-CimInstance -ClassName $ClassName -ErrorAction Stop)
        if (!$items.Count) { throw 'No required inventory object was returned.' }
        $items
    }
    catch { $queryErrors.Add([pscustomobject]@{ Query=$ClassName; Error=$_.Exception.Message }) }
}
$os = Read-DeviceClass 'Win32_OperatingSystem'
$computer = Read-DeviceClass 'Win32_ComputerSystem'
$bios = Read-DeviceClass 'Win32_BIOS'
$processors = @(Read-DeviceClass 'Win32_Processor')
$uptime = $null
if ($os -and $os.LastBootUpTime) { $uptime = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 2) }
$data = [pscustomobject][ordered]@{
    CollectedUtc = [datetime]::UtcNow.ToString('o')
    ComputerName = $env:COMPUTERNAME
    ExecutingUser = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
    ConsoleUser = $computer.UserName
    Manufacturer = $computer.Manufacturer
    Model = $computer.Model
    SerialNumber = $bios.SerialNumber
    BIOSVersion = $bios.SMBIOSBIOSVersion
    WindowsEdition = $os.Caption
    WindowsVersion = $os.Version
    BuildNumber = $os.BuildNumber
    Architecture = $os.OSArchitecture
    LastBootTime = $os.LastBootUpTime
    UptimeHours = $uptime
    InstalledRAMGB = $(if ($computer.TotalPhysicalMemory) { [math]::Round($computer.TotalPhysicalMemory / 1GB, 2) } else { $null })
    Processor = (($processors | Select-Object -ExpandProperty Name -Unique) -join '; ')
    LogicalProcessors = ($processors | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    DomainOrWorkgroup = $computer.Domain
    DomainJoined = $computer.PartOfDomain
}
$data | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $report 'device.json') -Encoding UTF8
$data | Export-Csv -LiteralPath (Join-Path $report 'device.csv') -NoTypeInformation -Encoding UTF8
$data | Format-List * | Out-String -Width 200 | Set-Content -LiteralPath (Join-Path $report 'ticket-summary.txt') -Encoding UTF8
if ($queryErrors.Count) {
    $queryErrors | Export-Csv -LiteralPath (Join-Path $report 'query-errors.csv') -NoTypeInformation -Encoding UTF8
    Write-Warning 'Some device queries failed; see query-errors.csv.'
} else { '"Query","Error"' | Set-Content -LiteralPath (Join-Path $report 'query-errors.csv') -Encoding UTF8 }
$summary = [pscustomobject]@{
    Status = $(if ($queryErrors.Count) { 'Partial' } else { 'Complete' })
    ComputerName = $env:COMPUTERNAME
    QueryErrorCount = $queryErrors.Count
    ReportDirectory = $report
}
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
$summary

