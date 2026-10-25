<#
What it does:
  Validates hardware/software audit transformations and mocked hardware report runs.
Available flags:
  -StagedWindows <path>: Staged Windows directory. -OutputDirectory <path>: Test artifacts.
How it works:
  Loads function definitions through the parser and supplies fake PnP/CIM data. Never queries real hardware
  or installed software. Checks schemas, redaction, Unknown states, monitor units, and baseline comparison.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$StagedWindows,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if (-not $StagedWindows) {
    $stagingCandidate=Join-Path $PSScriptRoot '..\staged\Windows'
    $StagedWindows=if (Test-Path -LiteralPath $stagingCandidate -PathType Container) { $stagingCandidate } else { Join-Path $PSScriptRoot '..' }
}
if (-not $OutputDirectory) { $OutputDirectory=Join-Path $StagedWindows ('Reports\HardwareSoftwareValidation-'+[guid]::NewGuid().ToString('N').Substring(0,8)) }
$null=New-Item -ItemType Directory -Path $OutputDirectory
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$script:assertions=0
function Assert-Audit {
    param([bool]$Condition,[string]$Name)
    $script:assertions++
    if (-not $Condition) { throw ('Assertion failed: '+$Name) }
}
$paths=@(Join-Path $StagedWindows 'Device-Information\Get-ConnectedPeripheralAudit.ps1'); $paths+=Join-Path $StagedWindows 'Device-Information\Get-ConnectedMonitorDetails.ps1'; $paths+=Join-Path $StagedWindows 'Software\Get-InstalledSoftwareAudit.ps1'
foreach ($path in $paths) {
    $tokens=$null; $parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$parseErrors)
    Assert-Audit (@($parseErrors).Count -eq 0) ('Syntax '+$path)
    $functionAst=$ast
    if([IO.Path]::GetFileName($path) -eq 'Get-InstalledSoftwareAudit.ps1'){
        $core=Join-Path $StagedWindows 'lib\Invoke-SoftwareInventoryCore.ps1'
        $coreTokens=$null;$coreErrors=$null
        $functionAst=[Management.Automation.Language.Parser]::ParseFile($core,[ref]$coreTokens,[ref]$coreErrors)
        if($coreErrors.Count){throw 'Shared software core did not parse.'}
    }
    $definitions=@($functionAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] },$false) | ForEach-Object { $_.Extent.Text })
    . ([scriptblock]::Create($definitions -join [Environment]::NewLine))
    $text=Get-Content -LiteralPath $path -Raw
    foreach ($heading in @('What it does:','Available flags:','How it works:')) { Assert-Audit ($text.Contains($heading)) ($heading+' '+$path) }
    Assert-Audit ($text -notmatch '(?im)^\s*#Requires\s+-RunAsAdministrator') 'Read-only inventory does not unnecessarily require elevation'
    $commands=@($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] },$true) | ForEach-Object { $_.GetCommandName() })
    Assert-Audit (-not @($commands | Where-Object { $_ -match '^(Set-|Remove-|Restart-|Stop-|Start-|Invoke-Expression|Invoke-CimMethod|Get-WmiObject)' -and $_ -ne 'Set-Content' }).Count) 'No system-changing commands in audit scripts'
}
foreach ($class in @('USB','HIDClass','Keyboard','Mouse','Bluetooth','Printer','PrintQueue','MEDIA','AudioEndpoint','Camera','Image','Monitor','Net','Ports','SmartCardReader','Sensor','Biometric','WPD','DiskDrive','CDROM')) { Assert-Audit (Test-PeripheralClass $class 'PCI\TEST\SERIAL' $false) ('Peripheral class '+$class) }
Assert-Audit (-not (Test-PeripheralClass 'System' 'PCI\TEST\SERIAL' $false)) 'System class excluded by default'
Assert-Audit (Test-PeripheralClass 'System' 'PCI\TEST\SERIAL' $true) 'AllClasses includes system devices'
Assert-Audit (Test-PeripheralClass 'Unusual' 'USB\VID_1234&PID_5678\SECRET' $false) 'USB enumerator includes unfamiliar class'
$pnp=[pscustomobject]@{ InstanceId='USB\VID_1234&PID_5678\SECRET123'; Class='HIDClass'; FriendlyName='Fixture keyboard'; Status='OK'; Manufacturer='Fixture maker'; Problem=0 }
$row=ConvertTo-PeripheralRecord $pnp 'PnP' $false
Assert-Audit ($row.Presence -eq 'Present') 'PnP PresentOnly source is present'
Assert-Audit ($row.InstanceId -notmatch 'SECRET123') 'Serial suffix redacted'
Assert-Audit ($row.DeviceKey -match '^[A-F0-9]{24}$') 'Stable opaque device key'
Assert-Audit ((Get-PeripheralDeviceKey $pnp.InstanceId) -eq (Get-PeripheralDeviceKey $pnp.InstanceId.ToLowerInvariant())) 'Case-insensitive stable PnP key'
Assert-Audit ((ConvertTo-PeripheralRecord $pnp 'PnP' $true).InstanceId -match 'SECRET123') 'Opt-in identifiers included'
Assert-Audit ((Protect-PeripheralInstanceId 'UNDIVIDEDSECRET' $false) -eq '[redacted]') 'Unknown identifier shape fully redacted'
$cim=[pscustomobject]@{ DeviceID='USB\VID_1234&PID_5678\SECRET456'; PNPClass='USB'; Name='Fixture device'; Status='OK'; ConfigManagerErrorCode=0 }
Assert-Audit ((ConvertTo-PeripheralRecord $cim 'CIM' $false).Presence -eq 'Unknown') 'Fallback missing presence is Unknown'
$cim | Add-Member NoteProperty Present $false
Assert-Audit ((ConvertTo-PeripheralRecord $cim 'CIM' $false).Presence -eq 'NotPresent') 'Fallback explicit false excluded'
$cim.Present=$true
Assert-Audit ((ConvertTo-PeripheralRecord $cim 'CIM' $false).Presence -eq 'Present') 'Fallback explicit true recognized'
Assert-Audit ((ConvertFrom-MonitorText @(65,66,0,67)) -eq 'AB') 'EDID null terminates'
Assert-Audit ((ConvertFrom-MonitorText @(65,66,10,67)) -eq 'AB') 'EDID newline terminates descriptor'
Assert-Audit ((ConvertFrom-MonitorText @(65,66,67) 2) -eq 'AB') 'EDID declared length respected'
foreach ($invalid in @(@(65,7,66),@(65,65535),@('not-a-number'),@())) { Assert-Audit ((ConvertFrom-MonitorText $invalid) -eq 'Unknown') 'Invalid EDID text is Unknown' }
foreach ($connectionCase in @(@(0,'VGA (HD15)'),@(4,'DVI'),@(5,'HDMI'),@(10,'DisplayPort external'),@(11,'DisplayPort embedded'),@(15,'Miracast'),@(16,'Indirect wired'),@(2147483648,'Internal'),@(4294967295,'Other'))) { Assert-Audit ((Get-MonitorConnectionLabel $connectionCase[0]) -eq $connectionCase[1]) ('Monitor connector '+$connectionCase[0]) }
Assert-Audit ((Get-MonitorConnectionLabel $null) -eq 'Unknown') 'Missing connection Unknown'
Assert-Audit ((Get-MonitorConnectionLabel 999) -eq 'Unknown code 999') 'Unrecognized connection retained'
$id=[pscustomobject]@{ InstanceName='DISPLAY\ABC123\SERIAL001_0'; Active=$true; ManufacturerName=@(65,66,67,0); ManufacturerNameLength=3; UserFriendlyName=@(84,101,115,116,0); UserFriendlyNameLength=4; ProductCodeID=@(49,50,0); SerialNumberID=@(83,69,67,82,69,84,0); WeekOfManufacture=0; YearOfManufacture=2020 }
$basic=[pscustomobject]@{ Active=$true; MaxHorizontalImageSize=60; MaxVerticalImageSize=34 }
$connection=[pscustomobject]@{ Active=$true; VideoOutputTechnology=10 }
$modes=[pscustomobject]@{ Active=$true; PreferredMonitorSourceModeIndex=0; MonitorSourceModes=@([pscustomobject]@{ HorizontalActivePixels=3840; VerticalActivePixels=2160; VerticalRefreshRateNumerator=60000; VerticalRefreshRateDenominator=1001 }) }
$monitor=ConvertTo-MonitorRecord $id.InstanceName $id $basic $connection $modes $false
Assert-Audit ($monitor.Activity -eq 'Active') 'Active monitor detected'
Assert-Audit ($monitor.Model -eq 'Test') 'Monitor friendly name decoded'
Assert-Audit ($monitor.SerialNumber -eq '[redacted]') 'Monitor serial masked'
Assert-Audit ($monitor.InstanceName -notmatch 'SERIAL001') 'Monitor instance identifier masked'
Assert-Audit ($monitor.WidthCm -eq 60 -and $monitor.HeightCm -eq 34) 'Monitor dimensions in centimeters'
Assert-Audit ($monitor.ApproximateDiagonalInches -eq 27.15) 'Centimeter to inch diagonal conversion'
Assert-Audit ($monitor.PreferredWidthPixels -eq 3840 -and $monitor.PreferredHeightPixels -eq 2160) 'Preferred source mode indexed'
Assert-Audit ($monitor.PreferredRefreshHz -eq 59.94) 'Preferred refresh rational conversion'
Assert-Audit ($monitor.CurrentResolution -like 'Unknown*') 'Preferred not mislabeled current resolution'
Assert-Audit ($null -eq $monitor.ManufactureWeek) 'Undefined EDID week not labeled week zero'
$basic.MaxHorizontalImageSize=0; $modes.PreferredMonitorSourceModeIndex=65535
$unknownMonitor=ConvertTo-MonitorRecord $id.InstanceName $id $basic $null $modes $true
Assert-Audit ($null -eq $unknownMonitor.ApproximateDiagonalInches) 'Zero EDID dimension becomes Unknown'
Assert-Audit ($null -eq $unknownMonitor.PreferredWidthPixels) 'Invalid preferred mode sentinel rejected'
Assert-Audit ($unknownMonitor.SerialNumber -eq 'SECRET') 'Opt-in monitor serial decoded'
$modes.PreferredMonitorSourceModeIndex=4
Assert-Audit ($null -eq (ConvertTo-MonitorRecord $id.InstanceName $id $basic $null $modes $false).PreferredWidthPixels) 'Out of range preferred index rejected'
$modes.PreferredMonitorSourceModeIndex=0; $modes.MonitorSourceModes[0].VerticalRefreshRateDenominator=0
Assert-Audit ($null -eq (ConvertTo-MonitorRecord $id.InstanceName $id $basic $null $modes $false).PreferredRefreshHz) 'Zero refresh denominator Unknown'
Assert-Audit ((ConvertTo-SoftwareInstallDate '20240229') -eq '2024-02-29') 'Valid leap date parsed'
foreach ($date in @('20230229','20241301','not-a-date','', $null)) { Assert-Audit ($null -eq (ConvertTo-SoftwareInstallDate $date)) 'Invalid install date remains Unknown' }
$values=[pscustomobject]@{ DisplayName='Fixture Editor'; DisplayVersion='1.0'; Publisher='Example'; InstallDate='20240229'; EstimatedSize=512; WindowsInstaller=1; SystemComponent=0 }
$software=ConvertTo-SoftwareRegistryRow $values 'Machine' '' 'Registry64' '{REGISTRY-ENTRY}'
Assert-Audit ($software.InstallDateRaw -eq '20240229') 'Raw install date preserved'
Assert-Audit ($software.InstallDateISO -eq '2024-02-29') 'ISO install date separate'
Assert-Audit ($software.RegistryView -eq 'Registry64') 'Registry view retained without architecture claim'
Assert-Audit ($software.Source -eq 'UninstallRegistry') 'Software source retained'
Assert-Audit ($null -eq (ConvertTo-SoftwareRegistryRow ([pscustomobject]@{ DisplayName=' ' }) 'Machine' '' 'Registry64' 'x')) 'Unnamed registry entries excluded'
$before=New-SoftwareAuditRow @{ Name='Fixture Editor'; Version='1.0'; Publisher='Example'; Scope='Machine'; RegistryView='Registry64'; Source='UninstallRegistry' }
$now=New-SoftwareAuditRow @{ Name='fixture editor'; Version='1.0'; Publisher='example'; Scope='Machine'; RegistryView='Registry64'; Source='UninstallRegistry' }
Assert-Audit (@(Compare-SoftwareAudit @($now) @($before)).Count -eq 0) 'Comparison identity case-insensitive'
$now.Version='2.0'
$drift=@(Compare-SoftwareAudit @($now) @($before))
Assert-Audit ($drift.Count -eq 1 -and $drift[0].Difference -eq 'VersionDifference') 'Version drift detected'
Assert-Audit ($drift[0].BaselineVersions -eq '1.0' -and $drift[0].CurrentVersions -eq '2.0') 'Drift versions preserved'
Assert-Audit (@(Compare-SoftwareAudit @() @($before))[0].Difference -eq 'MissingFromCurrentInventory') 'Missing record not falsely called uninstalled'
Assert-Audit (@(Compare-SoftwareAudit @($now) @())[0].Difference -eq 'NotInBaseline') 'New inventory record detected'
$now.RegistryView='Registry32'
Assert-Audit (@(Compare-SoftwareAudit @($now) @($before)).Count -eq 2) 'Different registry views distinct'
$now.RegistryView='Registry64'; $now.Scope='CurrentUser'; $now.UserSid='S-1-5-21-1-2-3-1001'
Assert-Audit (@(Compare-SoftwareAudit @($now) @($before)).Count -eq 2) 'Machine and user scopes distinct'
$unknown=New-SoftwareAuditRow @{}
Assert-Audit ($unknown.Version -eq 'Unknown' -and $unknown.Name -eq 'Unknown') 'Missing software metadata Unknown'

# Mock every hardware query before invoking either complete inventory script.
$global:AuditFixturePnpMode='Success'
function Get-PnpDevice { [CmdletBinding()]param([switch]$PresentOnly) if (-not $PresentOnly) { throw 'Expected PresentOnly' }; if ($global:AuditFixturePnpMode -eq 'Fail') { throw 'Fixture PnP failure SECRET' }; $pnp }
$global:AuditFixtureCimMode='Success'
function Get-CimInstance {
    [CmdletBinding()]param([string]$Namespace,[string]$ClassName)
    if ($global:AuditFixtureCimMode -eq 'Fail') { throw 'Fixture query failure SECRET' }
    if ($ClassName -eq 'Win32_PnPEntity') { return @([pscustomobject]@{ DeviceID='USB\TEST\SECRET456'; PNPClass='USB'; Name='Unknown presence fixture'; Status='OK' },[pscustomobject]@{ DeviceID='USB\TEST\SECRET789'; PNPClass='USB'; Name='Disconnected fixture'; Present=$false }) }
    switch ($ClassName) {
        'WmiMonitorID' { return @($id,[pscustomobject]@{ InstanceName='DISPLAY\INACTIVE\SERIAL002'; Active=$false; ManufacturerName=@(65,0); UserFriendlyName=@(66,0) }) }
        'WmiMonitorBasicDisplayParams' { $record=$basic | Select-Object *; $record | Add-Member NoteProperty InstanceName $id.InstanceName; return $record }
        'WmiMonitorConnectionParams' { $record=$connection | Select-Object *; $record | Add-Member NoteProperty InstanceName $id.InstanceName; return $record }
        'WmiMonitorListedSupportedSourceModes' { $record=$modes | Select-Object *; $record | Add-Member NoteProperty InstanceName $id.InstanceName; return $record }
        default { throw ('Unexpected query: '+$ClassName) }
    }
}
$pnpRun=& $paths[0] -OutputDirectory $OutputDirectory
Assert-Audit ($pnpRun.DeviceCount -eq 1) 'Complete peripheral fixture script runs'
$pnpJson=Get-Content -LiteralPath (Join-Path $pnpRun.ReportDirectory 'peripherals.json') -Raw
Assert-Audit ($pnpJson -notmatch 'SECRET123') 'Peripheral report excludes serial'
Assert-Audit ($pnpJson.TrimStart().StartsWith('[')) 'Single-record JSON remains array'
foreach ($name in @('peripherals.csv','peripherals.json','query-status.csv','query-status.json','query-errors.csv','summary.json')) { Assert-Audit (Test-Path -LiteralPath (Join-Path $pnpRun.ReportDirectory $name)) ('Peripheral report '+$name) }
$global:AuditFixturePnpMode='Fail'
$fallbackRun=& $paths[0] -OutputDirectory $OutputDirectory
$fallback=@(Import-Csv -LiteralPath (Join-Path $fallbackRun.ReportDirectory 'peripherals.csv'))
Assert-Audit ($fallback.Count -eq 1 -and $fallback[0].Presence -eq 'Unknown') 'Whole fallback excludes false presence and retains Unknown'
Assert-Audit ($fallbackRun.Status -eq 'Partial' -and $fallbackRun.QueryErrorCount -eq 1) 'Fallback records partial status and error'
Assert-Audit ((Get-Content -LiteralPath (Join-Path $fallbackRun.ReportDirectory 'query-errors.csv') -Raw) -notmatch 'SECRET') 'Raw errors do not leak serials'
$monitorRun=& $paths[1] -OutputDirectory $OutputDirectory
Assert-Audit ($monitorRun.MonitorCount -eq 1) 'Inactive monitor excluded by default'
$monitorAllRun=& $paths[1] -IncludeInactive -IncludeSerialNumbers -OutputDirectory $OutputDirectory
Assert-Audit ($monitorAllRun.MonitorCount -eq 2) 'IncludeInactive includes inactive monitors'
Assert-Audit ((Get-Content -LiteralPath (Join-Path $monitorAllRun.ReportDirectory 'monitors.json') -Raw) -match 'SERIAL001') 'Full monitor script honors identifier opt-in'
$global:AuditFixtureCimMode='Fail'
$failedRun=& $paths[1] -OutputDirectory $OutputDirectory
Assert-Audit ($failedRun.MonitorCount -eq 0 -and $failedRun.Status -eq 'Partial') 'Unavailable monitor providers are Partial rather than healthy empty'
Assert-Audit ($failedRun.QueryErrorCount -eq 4) 'Every failed monitor provider retained'
Assert-Audit (((Get-Content -LiteralPath (Join-Path $failedRun.ReportDirectory 'monitors.json') -Raw) -replace '\s','') -eq '[]') 'Empty monitor JSON remains empty array'
Assert-Audit ((Get-Content -LiteralPath (Join-Path $failedRun.ReportDirectory 'query-errors.csv') -Raw) -notmatch 'SECRET') 'Monitor raw errors omitted'
$summary=[pscustomobject]@{ Status='Passed'; Assertions=$script:assertions; PowerShellVersion=$PSVersionTable.PSVersion.ToString(); TestArtifacts=$OutputDirectory; Scope='Function fixtures and fully mocked hardware scripts only; no host hardware or software queried.' }
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'test-summary.json') -Encoding UTF8
$summary
