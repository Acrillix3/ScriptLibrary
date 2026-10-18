<#
What it does:
  Creates a battery usage and capacity report with a battery-device inventory.

Available flags:
  -DurationDays: Battery history window, 1-365 days; default 7.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Uses local CIM and powercfg /batteryreport, then verifies the generated HTML report; powercfg
  support and sufficient local access are required. Review capacity information in the HTML because
  charge percentage alone does not measure battery health, and some systems expose no battery data.
#>
#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateRange(1,365)][int]$DurationDays = 7,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$reportDirectory = Join-Path $OutputDirectory ('13-BatteryHealth_{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $reportDirectory -Force -ErrorAction Stop
$batteries = @(); $batteryStatus = 'Unknown'; $batteryError = ''; $nativeError = ''; $exitCode = $null; $nativeSuccess = $false
try {
    $batteries = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop | Select-Object Name,DeviceID,Status,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime)
    $batteryStatus = 'Detected'; if ($batteries.Count -eq 0) { $batteryStatus = 'NoneReported' }
} catch { $batteryError = $_.Exception.Message; Write-Warning ('Battery device query failed: '+$batteryError) }
if ($batteries.Count -gt 0) { $batteries | Export-Csv -LiteralPath (Join-Path $reportDirectory 'batteries.csv') -NoTypeInformation -Encoding UTF8 }
else { '"Name","DeviceID","Status","BatteryStatus","EstimatedChargeRemaining","EstimatedRunTime"' | Set-Content -LiteralPath (Join-Path $reportDirectory 'batteries.csv') -Encoding UTF8 }
$htmlPath = Join-Path $reportDirectory 'battery-report.html'
$nativeOutput = @()
try {
    $powercfg = Get-Command -Name powercfg.exe -CommandType Application -ErrorAction Stop
    # Capturing stderr must not prevent reading the native process exit code in PS 5.1.
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $nativeOutput = @(& $powercfg.Source /batteryreport /output $htmlPath /duration $DurationDays 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($null -eq $exitCode -or $exitCode -ne 0) { throw ('powercfg failed; exit code: '+$exitCode) }
    if (-not (Test-Path -LiteralPath $htmlPath -PathType Leaf -ErrorAction Stop)) { throw 'powercfg returned success but did not create the destination HTML file.' }
    if ((Get-Item -LiteralPath $htmlPath -ErrorAction Stop).Length -le 0) { throw 'powercfg created an empty HTML file.' }
    $nativeSuccess = $true
} catch { $nativeError = $_.Exception.Message; Write-Warning ('Battery report failed: '+$nativeError) }
if ($nativeOutput.Count -gt 0) { $nativeOutput | Set-Content -LiteralPath (Join-Path $reportDirectory 'powercfg-output.txt') -Encoding UTF8 }
else { 'No native output was captured. See report.json for status/errors.' | Set-Content -LiteralPath (Join-Path $reportDirectory 'powercfg-output.txt') -Encoding UTF8 }
$status = 'Success'
if (-not $nativeSuccess) { $status = 'Failed' } elseif ($batteryStatus -eq 'Unknown') { $status = 'Partial' } elseif ($batteryStatus -eq 'NoneReported') { $status = 'NoBatteryDetected' }
$summary = [pscustomobject]@{ReportDirectory=$reportDirectory;Status=$status;BatteryDetection=$batteryStatus;BatteryCount=$batteries.Count;NativeReportCreated=$nativeSuccess;PowercfgExitCode=$exitCode;DurationDays=$DurationDays;BatteryQueryError=$batteryError;NativeError=$nativeError}
[pscustomobject]@{Summary=$summary;Batteries=$batteries;HtmlReport=$(if ($nativeSuccess) { $htmlPath } else { $null })} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $reportDirectory 'report.json') -Encoding UTF8
'NoBatteryDetected means Win32_Battery returned no devices; virtual machines, desktops, or driver limitations can explain this. A successful native HTML report may still have no installed-battery data. Current charge is not a capacity-health measure. Review the native report before sharing because it contains device identifiers and usage history. No power settings were changed.' | Set-Content -LiteralPath (Join-Path $reportDirectory 'notes.txt') -Encoding UTF8
$summary

