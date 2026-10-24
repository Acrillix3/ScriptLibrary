<#
What it does:
  Audits active monitors, EDID names, manufacture dates, physical size, connection type, and preferred mode.
Available flags:
  -IncludeInactive: Include provider-listed inactive displays. -IncludeSerialNumbers: Reveal EDID serials and instance IDs.
  -OutputDirectory <path>: Report destination; default Windows\Reports.
How it works:
  Joins root\wmi monitor classes by exact instance name and saves CSV, JSON, query status, and errors.
  Preferred mode is not current resolution. Missing data is Unknown; no display settings change.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$IncludeInactive,[switch]$IncludeSerialNumbers,[ValidateNotNullOrEmpty()][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
function ConvertFrom-MonitorText {
    param([object[]]$Values,[int]$Length=0)
    if (-not $Values -or $Values.Count -gt 1024) { return 'Unknown' }
    $limit = $Values.Count
    if ($Length -gt 0 -and $Length -lt $limit) { $limit = $Length }
    $builder = New-Object Text.StringBuilder
    for ($i=0; $i -lt $limit; $i++) {
        $number = 0
        if (-not [int]::TryParse([string]$Values[$i],[ref]$number)) { return 'Unknown' }
        if ($number -in @(0,10,13)) { break }
        if ($number -lt 32 -or $number -gt 126) { return 'Unknown' }
        [void]$builder.Append([char]$number)
    }
    $text = $builder.ToString().Trim()
    if ($text) { return $text }
    return 'Unknown'
}
function Get-MonitorKey {
    param([string]$InstanceName)
    if (-not $InstanceName) { return 'Unknown' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($InstanceName.ToUpperInvariant())))).Replace('-','').Substring(0,24) }
    finally { $sha.Dispose() }
}
function Get-MonitorConnectionLabel {
    param([object]$Code)
    if ($null -eq $Code) { return 'Unknown' }
    $labels = @{ '0'='VGA (HD15)'; '1'='S-Video'; '2'='Composite video'; '3'='Component video'; '4'='DVI'; '5'='HDMI'; '6'='LVDS / MIPI DSI'; '8'='D-Jpn'; '9'='SDI'; '10'='DisplayPort external'; '11'='DisplayPort embedded'; '12'='UDI external'; '13'='UDI embedded'; '14'='SDTV dongle'; '15'='Miracast'; '16'='Indirect wired'; '2147483648'='Internal'; '4294967295'='Other'; '4294967294'='Uninitialized' }
    $key = [string]$Code
    if ($labels.ContainsKey($key)) { return $labels[$key] }
    return 'Unknown code ' + $key
}
function ConvertTo-MonitorRecord {
    param([string]$InstanceName,[object]$Identity,[object]$Basic,[object]$Connection,[object]$Modes,[bool]$IncludeSerial)
    $activity = 'Unknown'
    foreach ($item in @($Identity,$Basic,$Connection,$Modes)) {
        if ($null -ne $item -and $item.PSObject.Properties['Active'] -and $null -ne $item.Active) { $activity = if ([bool]$item.Active) { 'Active' } else { 'Inactive' }; break }
    }
    $width = $null; $height = $null; $diagonal = $null
    if ($Basic -and [double]$Basic.MaxHorizontalImageSize -gt 0 -and [double]$Basic.MaxVerticalImageSize -gt 0) {
        $width = [double]$Basic.MaxHorizontalImageSize; $height = [double]$Basic.MaxVerticalImageSize
        $diagonal = [math]::Round([math]::Sqrt($width*$width+$height*$height)/2.54,2)
    }
    $preferredWidth = $null; $preferredHeight = $null; $preferredHz = $null
    if ($Modes -and $null -ne $Modes.PreferredMonitorSourceModeIndex) {
        $index = [int]$Modes.PreferredMonitorSourceModeIndex
        $modeList = @($Modes.MonitorSourceModes)
        if ($index -ge 0 -and $index -lt $modeList.Count -and $index -ne 65535) {
            $preferred = $modeList[$index]
            if ([int]$preferred.HorizontalActivePixels -gt 0 -and [int]$preferred.VerticalActivePixels -gt 0) {
                $preferredWidth = [int]$preferred.HorizontalActivePixels; $preferredHeight = [int]$preferred.VerticalActivePixels
                if ([double]$preferred.VerticalRefreshRateDenominator -gt 0) { $preferredHz = [math]::Round([double]$preferred.VerticalRefreshRateNumerator/[double]$preferred.VerticalRefreshRateDenominator,3) }
            }
        }
    }
    $serial = if ($IncludeSerial -and $Identity) { ConvertFrom-MonitorText $Identity.SerialNumberID } else { '[redacted]' }
    $code = if ($Connection) { $Connection.VideoOutputTechnology } else { $null }
    [pscustomobject][ordered]@{
        MonitorKey = Get-MonitorKey $InstanceName
        InstanceName = $(if ($IncludeSerial) { $InstanceName } else { '[redacted; use MonitorKey to correlate]' })
        Activity = $activity
        Manufacturer = $(if ($Identity) { ConvertFrom-MonitorText $Identity.ManufacturerName $Identity.ManufacturerNameLength } else { 'Unknown' })
        Model = $(if ($Identity) { ConvertFrom-MonitorText $Identity.UserFriendlyName $Identity.UserFriendlyNameLength } else { 'Unknown' })
        ProductCode = $(if ($Identity) { ConvertFrom-MonitorText $Identity.ProductCodeID } else { 'Unknown' })
        SerialNumber = $serial
        ManufactureWeek = $(if ($Identity -and [int]$Identity.WeekOfManufacture -ge 1 -and [int]$Identity.WeekOfManufacture -le 53) { [int]$Identity.WeekOfManufacture } else { $null })
        ManufactureYear = $(if ($Identity -and [int]$Identity.YearOfManufacture -ge 1990 -and [int]$Identity.YearOfManufacture -le ((Get-Date).Year + 1)) { [int]$Identity.YearOfManufacture } else { $null })
        WidthCm = $width; HeightCm = $height; ApproximateDiagonalInches = $diagonal
        SizeStatus = $(if ($null -ne $diagonal) { 'EDID image dimensions, rounded to centimeters; approximate diagonal' } else { 'Unknown; zero or missing dimensions are not a physical size' })
        Connection = Get-MonitorConnectionLabel $code
        ConnectionCode = $code
        PreferredWidthPixels = $preferredWidth; PreferredHeightPixels = $preferredHeight; PreferredRefreshHz = $preferredHz
        PreferredModeStatus = $(if ($null -ne $preferredWidth) { 'Provider preferred source mode; not proof of native or current mode' } else { 'Unknown' })
        CurrentResolution = 'Unknown; active display paths are not queried by this EDID inventory'
        Source = 'root\wmi monitor classes joined by exact InstanceName; device-reported metadata'
    }
}
function Read-MonitorClass {
    param([string]$ClassName)
    try {
        $items = @(Get-CimInstance -Namespace 'root\wmi' -ClassName $ClassName -ErrorAction Stop)
        $script:queryStatus.Add([pscustomobject]@{ Query=$ClassName; Status=$(if ($items.Count) { 'Success' } else { 'Unknown' }); Count=$items.Count; Detail=$(if ($items.Count) { 'Provider metadata collected.' } else { 'Provider returned no monitor records.' }) })
        return $items
    } catch {
        $script:queryStatus.Add([pscustomobject]@{ Query=$ClassName; Status='Unknown'; Count=0; Detail='Provider unavailable, unsupported, or access denied.' })
        $script:queryErrors.Add([pscustomobject]@{ Query=$ClassName; ErrorType=$_.Exception.GetType().FullName; HResult=$_.Exception.HResult; Detail='Raw error omitted to protect monitor identifiers.' })
    }
}
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Run in 64-bit Windows PowerShell 5.1 or later on Windows.' }
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$runName = 'ConnectedMonitorDetails-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),([guid]::NewGuid().ToString('N').Substring(0,8))
$report = (New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -ErrorAction Stop).FullName
$queryStatus = New-Object 'System.Collections.Generic.List[object]'; $queryErrors = New-Object 'System.Collections.Generic.List[object]'
$classes = @('WmiMonitorID','WmiMonitorBasicDisplayParams','WmiMonitorConnectionParams','WmiMonitorListedSupportedSourceModes')
$byClass = @{}; $instances = @{}
foreach ($class in $classes) {
    $map = @{}
    foreach ($item in @(Read-MonitorClass $class)) {
        if ($item.InstanceName) { $map[[string]$item.InstanceName] = $item; $instances[[string]$item.InstanceName] = $true }
    }
    $byClass[$class] = $map
}
$rows = New-Object 'System.Collections.Generic.List[object]'
foreach ($instance in @($instances.Keys | Sort-Object)) {
    $row = ConvertTo-MonitorRecord $instance $byClass.WmiMonitorID[$instance] $byClass.WmiMonitorBasicDisplayParams[$instance] $byClass.WmiMonitorConnectionParams[$instance] $byClass.WmiMonitorListedSupportedSourceModes[$instance] ([bool]$IncludeSerialNumbers)
    if ($IncludeInactive -or $row.Activity -eq 'Active') { $rows.Add($row) }
}
if (-not $rows.Count) { $queryStatus.Add([pscustomobject]@{ Query='Selected monitor inventory'; Status='Unknown'; Count=0; Detail='No active monitor metadata returned. Remote, headless, virtual, or unsupported displays may not expose EDID.' }) }
if ($rows.Count) { $rows.ToArray() | Export-Csv -LiteralPath (Join-Path $report 'monitors.csv') -NoTypeInformation -Encoding UTF8 } else { '"MonitorKey","Activity","Manufacturer","Model","SerialNumber","WidthCm","HeightCm","ApproximateDiagonalInches","Connection","PreferredWidthPixels","PreferredHeightPixels","CurrentResolution"' | Set-Content -LiteralPath (Join-Path $report 'monitors.csv') -Encoding UTF8 }
ConvertTo-Json -InputObject @($rows.ToArray()) -Depth 6 | Set-Content -LiteralPath (Join-Path $report 'monitors.json') -Encoding UTF8
$queryStatus.ToArray() | Export-Csv -LiteralPath (Join-Path $report 'query-status.csv') -NoTypeInformation -Encoding UTF8
ConvertTo-Json -InputObject @($queryStatus.ToArray()) -Depth 5 | Set-Content -LiteralPath (Join-Path $report 'query-status.json') -Encoding UTF8
if ($queryErrors.Count) { $queryErrors.ToArray() | Export-Csv -LiteralPath (Join-Path $report 'query-errors.csv') -NoTypeInformation -Encoding UTF8 } else { '"Query","ErrorType","HResult","Detail"' | Set-Content -LiteralPath (Join-Path $report 'query-errors.csv') -Encoding UTF8 }
$summary = [pscustomobject]@{ CollectedUtc=[datetime]::UtcNow.ToString('o'); ComputerName=$env:COMPUTERNAME; Status=$(if (@($queryStatus | Where-Object Status -ne 'Success').Count) { 'Partial' } else { 'Complete' }); MonitorCount=$rows.Count; QueryErrorCount=$queryErrors.Count; ReportDirectory=$report; Limitation='EDID is device-reported and may be unavailable or inaccurate. Preferred mode is separate from current display resolution. Display labels may contain vendor identifiers.' }
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
$summary
