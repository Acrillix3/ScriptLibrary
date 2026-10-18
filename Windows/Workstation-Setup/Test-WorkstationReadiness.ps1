<#
What it does:
  Checks disk space, domain membership, encryption, applications, and services against your JSON
  baseline.

Available flags:
  -ConfigPath: Required path to your edited JSON requirements baseline.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Reads local CIM, registry, and service information and saves Pass, Fail, Unknown, or NotRequired
  results. Optional encryption checks need Get-BitLockerVolume and sufficient access; unavailable
  data stays Unknown, and application checks cover uninstall registry entries only.
#>
#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ConfigPath,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$reportDirectory = Join-Path $OutputDirectory ('12-WorkstationReadiness_{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $reportDirectory -Force -ErrorAction Stop
$checks = New-Object 'System.Collections.Generic.List[object]'
function Add-ReadinessCheck {
    param([string]$Check,[string]$Result,[string]$Expected,[string]$Observed,[string]$Detail)
    $checks.Add([pscustomobject]@{Check=$Check;Result=$Result;Expected=$Expected;Observed=$Observed;Detail=$Detail})
}
$configurationValid = $false
try {
    $config = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $required = @('MinimumFreeDiskGB','DiskMountPoint','RequireDomainJoined','ExpectedDomain','RequireEncryption','ExpectedApplications','ExpectedServices')
    foreach ($field in $required) { if ($null -eq $config.PSObject.Properties[$field]) { throw ('Missing configuration field: '+$field) } }
    if ($config.RequireDomainJoined -isnot [bool] -or $config.RequireEncryption -isnot [bool]) { throw 'RequireDomainJoined and RequireEncryption must be JSON booleans.' }
    $minimumDisk = 0.0
    if (-not [double]::TryParse([string]$config.MinimumFreeDiskGB,[ref]$minimumDisk) -or $minimumDisk -lt 0) { throw 'MinimumFreeDiskGB must be a non-negative number.' }
    if ([string]$config.DiskMountPoint -notmatch '^[A-Za-z]:$') { throw 'DiskMountPoint must be a local drive letter, for example C:.' }
    if ($config.ExpectedDomain -and -not $config.RequireDomainJoined) { throw 'ExpectedDomain requires RequireDomainJoined=true.' }
    foreach ($application in @($config.ExpectedApplications)) {
        if (-not $application.NamePattern) { throw 'Each expected application requires NamePattern.' }
        if ($application.MinimumVersion) { $parsedVersion = $null; if (-not [version]::TryParse([string]$application.MinimumVersion,[ref]$parsedVersion)) { throw ('Invalid MinimumVersion for '+$application.NamePattern) } }
    }
    foreach ($service in @($config.ExpectedServices)) { if (-not $service.Name -or $service.ExpectedState -notin @('Running','Stopped')) { throw 'Each expected service requires Name and ExpectedState (Running or Stopped).' } }
    $configurationValid = $true
} catch { Add-ReadinessCheck 'Configuration' 'Unknown' 'Valid explicit baseline' '' $_.Exception.Message }
if ($configurationValid) {
    try {
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $config.DiskMountPoint) -ErrorAction Stop
        if ($null -eq $disk -or $null -eq $disk.FreeSpace) { throw 'No readable disk/free-space data was returned.' }
        $freeGB = [math]::Round(([double]$disk.FreeSpace / 1GB),2)
        $result = 'Fail'; if ([double]$disk.FreeSpace / 1GB -ge $minimumDisk) { $result = 'Pass' }
        Add-ReadinessCheck 'FreeDiskSpace' $result (">= $minimumDisk GB") ("$freeGB GB") ([string]$config.DiskMountPoint)
    } catch { Add-ReadinessCheck 'FreeDiskSpace' 'Unknown' (">= $minimumDisk GB") '' $_.Exception.Message }
    if ($config.RequireDomainJoined) {
        try {
            $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            if ($null -eq $computer -or $null -eq $computer.PartOfDomain) { throw 'Domain membership data unavailable.' }
            $result = 'Fail'
            if ($computer.PartOfDomain -and (-not $config.ExpectedDomain -or $computer.Domain -eq $config.ExpectedDomain)) { $result = 'Pass' }
            Add-ReadinessCheck 'ADDomainMembership' $result ('Joined; domain='+$config.ExpectedDomain) ('Joined={0}; Domain={1}' -f $computer.PartOfDomain,$computer.Domain) 'AD domain membership only; does not assess Microsoft Entra join or domain trust health.'
        } catch { Add-ReadinessCheck 'ADDomainMembership' 'Unknown' 'Domain joined' '' $_.Exception.Message }
    } else { Add-ReadinessCheck 'ADDomainMembership' 'NotRequired' 'Not required' '' '' }
    if ($config.RequireEncryption) {
        try {
            $null = Get-Command -Name Get-BitLockerVolume -ErrorAction Stop
            $volume = Get-BitLockerVolume -MountPoint $config.DiskMountPoint -ErrorAction Stop
            if ($null -eq $volume -or $null -eq $volume.VolumeStatus -or $null -eq $volume.ProtectionStatus) { throw 'BitLocker returned no usable status.' }
            $result = 'Fail'
            if ([string]$volume.VolumeStatus -eq 'FullyEncrypted' -and [string]$volume.ProtectionStatus -eq 'On') { $result = 'Pass' }
            Add-ReadinessCheck 'BitLocker' $result 'FullyEncrypted; ProtectionStatus On' ('VolumeStatus={0}; ProtectionStatus={1}' -f $volume.VolumeStatus,$volume.ProtectionStatus) 'Selected drive only; suspended protection does not pass.'
        } catch { Add-ReadinessCheck 'BitLocker' 'Unknown' 'FullyEncrypted; ProtectionStatus On' '' $_.Exception.Message }
    } else { Add-ReadinessCheck 'BitLocker' 'NotRequired' 'Not required' '' '' }
    if (@($config.ExpectedApplications).Count -gt 0) {
        $apps = New-Object 'System.Collections.Generic.List[object]'; $appErrors = New-Object 'System.Collections.Generic.List[string]'
        foreach ($registryPath in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
            try {
                $basePath = $registryPath.Substring(0,$registryPath.Length-2)
                if (Test-Path -LiteralPath $basePath -ErrorAction Stop) {
                    foreach ($app in @(Get-ItemProperty -Path $registryPath -ErrorAction Stop)) { if ($app.DisplayName) { $apps.Add([pscustomobject]@{Name=$app.DisplayName;Version=[string]$app.DisplayVersion}) } }
                }
            } catch { $appErrors.Add($registryPath+': '+$_.Exception.Message) }
        }
        foreach ($expectedApp in @($config.ExpectedApplications)) {
            $matches = @($apps | Where-Object Name -like $expectedApp.NamePattern)
            $result = 'Fail'; $detail = 'Uninstall registry inventory only.'
            if ($matches.Count -gt 0) {
                if (-not $expectedApp.MinimumVersion) { $result = 'Pass' }
                else {
                    $hasUnknownVersion = $false
                    foreach ($match in $matches) {
                        $installedVersion = $null
                        if ([version]::TryParse([string]$match.Version,[ref]$installedVersion)) { if ($installedVersion -ge [version]$expectedApp.MinimumVersion) { $result = 'Pass' } }
                        else { $hasUnknownVersion = $true }
                    }
                    if ($result -ne 'Pass' -and $hasUnknownVersion) { $result = 'Unknown'; $detail += ' An installed version could not be parsed.' }
                }
            }
            if ($result -ne 'Pass' -and $appErrors.Count -gt 0) { $result = 'Unknown'; $detail += ' Inventory incomplete: '+($appErrors -join '; ') }
            Add-ReadinessCheck ('Application: '+$expectedApp.NamePattern) $result ('MinimumVersion='+$expectedApp.MinimumVersion) (($matches | ForEach-Object { '{0} ({1})' -f $_.Name,$_.Version }) -join '; ') $detail
        }
    }
    foreach ($expectedService in @($config.ExpectedServices)) {
        try {
            $escapedName = ([string]$expectedService.Name).Replace("'","''")
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$escapedName'" -ErrorAction Stop
            $result = 'Fail'; $observed = 'NotFound'
            if ($service) { $observed = [string]$service.State; if ($observed -eq $expectedService.ExpectedState) { $result = 'Pass' } }
            Add-ReadinessCheck ('Service: '+$expectedService.Name) $result $expectedService.ExpectedState $observed 'Observe only; on-demand services can normally be stopped. Set your baseline accordingly.'
        } catch { Add-ReadinessCheck ('Service: '+$expectedService.Name) 'Unknown' $expectedService.ExpectedState '' $_.Exception.Message }
    }
}
$checks | Export-Csv -LiteralPath (Join-Path $reportDirectory 'checks.csv') -NoTypeInformation -Encoding UTF8
$failed = @($checks | Where-Object Result -eq 'Fail').Count; $unknown = @($checks | Where-Object Result -eq 'Unknown').Count
$status = 'Ready'
if (-not $configurationValid) { $status = 'Failed' } elseif ($unknown -gt 0) { $status = 'Incomplete' } elseif ($failed -gt 0) { $status = 'NotReady' }
$summary = [pscustomobject]@{ReportDirectory=$reportDirectory;Status=$status;ConfigurationValid=$configurationValid;PassCount=@($checks | Where-Object Result -eq 'Pass').Count;FailCount=$failed;UnknownCount=$unknown}
[pscustomobject]@{Summary=$summary;Checks=@($checks.ToArray())} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $reportDirectory 'report.json') -Encoding UTF8
'Readiness is relative to your selected baseline. Incomplete means at least one required observation is unknown, even when another check fails. AD domain membership does not assess Entra ID or domain trust health. Application inventory covers machine uninstall keys and the current user only, not all installed/portable/Store applications. No encryption protector material is exported.' | Set-Content -LiteralPath (Join-Path $reportDirectory 'notes.txt') -Encoding UTF8
if ($unknown -gt 0) { Write-Warning "$unknown checks could not be determined; see checks.csv." }
$summary

