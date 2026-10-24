<#
What it does:
  Inventories present USB, input, Bluetooth, print, audio, camera, display, and network devices.
Available flags:
  -AllClasses: Include every PnP class. -IncludeSerialNumbers: Include full device instance IDs.
  -OutputDirectory <path>: Report destination; default Windows\Reports.
How it works:
  Uses present PnP devices, with a CIM fallback that labels unverified presence Unknown.
  Saves CSV, JSON, query status, and errors. Makes no device changes; identifiers are masked by default.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$AllClasses, [switch]$IncludeSerialNumbers, [ValidateNotNullOrEmpty()][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'

function Get-PeripheralDeviceKey {
    param([string]$InstanceId)
    if ([string]::IsNullOrWhiteSpace($InstanceId)) { return 'Unknown' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($InstanceId.ToUpperInvariant())))).Replace('-', '').Substring(0,24) }
    finally { $sha.Dispose() }
}
function Protect-PeripheralInstanceId {
    param([string]$InstanceId, [bool]$IncludeSerial)
    if ([string]::IsNullOrWhiteSpace($InstanceId)) { return 'Unknown' }
    if ($IncludeSerial) { return $InstanceId }
    $parts = $InstanceId -split '\\',3
    if ($parts.Count -gt 1) { return ($parts[0..1] -join '\') + '\[redacted]' }
    return '[redacted]'
}
function ConvertTo-PeripheralRecord {
    param([object]$Device, [ValidateSet('PnP','CIM')][string]$Source, [bool]$IncludeSerial)
    $instance = if ($Source -eq 'PnP') { [string]$Device.InstanceId } else { [string]$Device.DeviceID }
    $class = if ($Source -eq 'PnP') { [string]$Device.Class } else { [string]$Device.PNPClass }
    $name = if ($Source -eq 'PnP') { [string]$Device.FriendlyName } else { [string]$Device.Name }
    $present = 'Present'
    if ($Source -eq 'CIM') {
        $present = 'Unknown'
        if ($Device.PSObject.Properties['Present'] -and $null -ne $Device.Present) {
            $present = if ([bool]$Device.Present) { 'Present' } else { 'NotPresent' }
        }
    }
    $problem = if ($Source -eq 'CIM') { $Device.ConfigManagerErrorCode } elseif ($Device.PSObject.Properties['Problem']) { $Device.Problem } else { $null }
    [pscustomobject][ordered]@{
        DeviceKey = Get-PeripheralDeviceKey $instance
        Name = $(if ($name) { $name } else { 'Unknown' })
        Class = $(if ($class) { $class } else { 'Unknown' })
        Presence = $present
        Status = $(if ($Device.Status) { [string]$Device.Status } else { 'Unknown' })
        ProblemCode = $problem
        Manufacturer = $(if ($Device.Manufacturer) { [string]$Device.Manufacturer } else { 'Unknown' })
        InstanceId = Protect-PeripheralInstanceId $instance $IncludeSerial
        IdentifierPolicy = $(if ($IncludeSerial) { 'Full instance ID requested' } else { 'Instance-specific suffix masked; DeviceKey is a hash' })
        Source = $(if ($Source -eq 'PnP') { 'Get-PnpDevice -PresentOnly' } else { 'Win32_PnPEntity; presence requires explicit Present property' })
    }
}
function Test-PeripheralClass {
    param([string]$Class, [string]$InstanceId, [bool]$EveryClass)
    if ($EveryClass) { return $true }
    return ($Class -in @('USB','HIDClass','Keyboard','Mouse','Bluetooth','Printer','PrintQueue','MEDIA','AudioEndpoint','Camera','Image','Monitor','Net','Ports','SmartCardReader','Sensor','Biometric','WPD','DiskDrive','CDROM') -or $InstanceId -match '^(USB|USBSTOR|HID|BTHENUM|BTHLEDEVICE)\\')
}
function Add-PeripheralQuery {
    param([string]$Query,[string]$Status,[int]$Count,[string]$Detail)
    $script:queryStatus.Add([pscustomobject]@{ Query=$Query; Status=$Status; Count=$Count; Detail=$Detail })
}
function Add-PeripheralError {
    param([string]$Query,[object]$ErrorRecord)
    $script:queryErrors.Add([pscustomobject]@{ Query=$Query; ErrorType=$ErrorRecord.Exception.GetType().FullName; HResult=$ErrorRecord.Exception.HResult; Detail='Query failed; raw error omitted to protect device identifiers.' })
}
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Run in 64-bit Windows PowerShell 5.1 or later on Windows.' }
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$runName = 'ConnectedPeripheralAudit-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),([guid]::NewGuid().ToString('N').Substring(0,8))
$report = (New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -ErrorAction Stop).FullName
$queryStatus = New-Object 'System.Collections.Generic.List[object]'
$queryErrors = New-Object 'System.Collections.Generic.List[object]'
$rows = New-Object 'System.Collections.Generic.List[object]'
$source = 'PnP'
$devices = @()
$needFallback = $true
if (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) {
    try {
        $devices = @(Get-PnpDevice -PresentOnly -ErrorAction Stop)
        Add-PeripheralQuery 'Present PnP devices' 'Success' $devices.Count 'Present at collection time; internal devices can also appear.'
        $needFallback = $false
    } catch { Add-PeripheralError 'Present PnP devices' $_; Add-PeripheralQuery 'Present PnP devices' 'Unknown' 0 'PnP query failed; trying CIM.' }
} else { Add-PeripheralQuery 'Present PnP devices' 'Unknown' 0 'Get-PnpDevice is unavailable; trying CIM.' }
if ($needFallback) {
    $source = 'CIM'
    try {
        $devices = @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop)
        Add-PeripheralQuery 'CIM PnP fallback' 'Partial' $devices.Count 'Only records explicitly Present=False are excluded. Remaining unverified presence is Unknown.'
    } catch { Add-PeripheralError 'CIM PnP fallback' $_; Add-PeripheralQuery 'CIM PnP fallback' 'Unknown' 0 'No reliable device inventory was collected.' }
}
foreach ($device in $devices) {
    $class = if ($source -eq 'PnP') { [string]$device.Class } else { [string]$device.PNPClass }
    $instance = if ($source -eq 'PnP') { [string]$device.InstanceId } else { [string]$device.DeviceID }
    if (-not (Test-PeripheralClass $class $instance ([bool]$AllClasses))) { continue }
    $row = ConvertTo-PeripheralRecord $device $source ([bool]$IncludeSerialNumbers)
    if ($row.Presence -ne 'NotPresent') { $rows.Add($row) }
}
if (-not $rows.Count) { Add-PeripheralQuery 'Selected device inventory' 'Unknown' 0 'No matching devices returned; this is not proof that no peripherals are connected.' }
$rows.ToArray() | Export-Csv -LiteralPath (Join-Path $report 'peripherals.csv') -NoTypeInformation -Encoding UTF8
if (-not $rows.Count) { '"DeviceKey","Name","Class","Presence","Status","ProblemCode","Manufacturer","InstanceId","IdentifierPolicy","Source"' | Set-Content -LiteralPath (Join-Path $report 'peripherals.csv') -Encoding UTF8 }
ConvertTo-Json -InputObject @($rows.ToArray()) -Depth 6 | Set-Content -LiteralPath (Join-Path $report 'peripherals.json') -Encoding UTF8
$queryStatus.ToArray() | Export-Csv -LiteralPath (Join-Path $report 'query-status.csv') -NoTypeInformation -Encoding UTF8
ConvertTo-Json -InputObject @($queryStatus.ToArray()) -Depth 5 | Set-Content -LiteralPath (Join-Path $report 'query-status.json') -Encoding UTF8
if ($queryErrors.Count) { $queryErrors.ToArray() | Export-Csv -LiteralPath (Join-Path $report 'query-errors.csv') -NoTypeInformation -Encoding UTF8 } else { '"Query","ErrorType","HResult","Detail"' | Set-Content -LiteralPath (Join-Path $report 'query-errors.csv') -Encoding UTF8 }
$summary = [pscustomobject]@{ CollectedUtc=[datetime]::UtcNow.ToString('o'); ComputerName=$env:COMPUTERNAME; Status=$(if (@($queryStatus | Where-Object Status -ne 'Success').Count) { 'Partial' } else { 'Complete' }); DeviceCount=$rows.Count; QueryErrorCount=$queryErrors.Count; ReportDirectory=$report; Limitation='Present PnP is not proof of physical external attachment; virtual and internal devices may appear. Display labels are vendor supplied and may contain identifiers.' }
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
$summary
