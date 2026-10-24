<#
What it does
  Tests power-policy planning and USB correlation with isolated fixtures.
Available flags
  -ScriptPath: Optional full path to Set-TechnicianPowerSettings.ps1.
How it works
  Replaces all native power/device operations with mocks, checks reports in a unique
  temporary folder, and fails on unexpected behavior. No machine settings are changed.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$ScriptPath)
$ErrorActionPreference='Stop'
if (-not $ScriptPath) {
    $windowsRoot = Split-Path -Parent $PSScriptRoot
    if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'staged\Windows')) { $windowsRoot = Join-Path $PSScriptRoot 'staged\Windows' }
    $ScriptPath = Join-Path $windowsRoot 'Workstation-Setup\Set-TechnicianPowerSettings.ps1'
}
. $ScriptPath
$script:checks=0
function Assert-TP { param([bool]$Condition,[string]$Name) if (-not $Condition) { throw "FAILED: $Name" }; $script:checks++ }
$definitions=@(Get-TPDefinitions -Minutes 60)
Assert-TP ($definitions.Count -eq 5) 'Five requested settings'
Assert-TP ($definitions[3].Desired -eq 3600) 'Display seconds'
Assert-TP ($definitions[0].Desired -eq 0 -and $definitions[1].Desired -eq 0 -and $definitions[2].Desired -eq 0 -and $definitions[4].Desired -eq 0) 'Never timers and selective suspend disabled'
Assert-TP ($definitions[1].Setting -eq '7bc4a2f9-d8fc-4469-b07b-33eb785aaca0') 'Unattended timeout GUID'
Assert-TP ($definitions[4].Subgroup -eq '2a737441-1930-4402-8d77-b2bebba308a3') 'USB subgroup GUID'
Assert-TP ($definitions[4].Setting -eq '48e6b7a6-50f5-4782-a5d4-53bb8f07e226') 'USB suspend GUID'

# PnP fixtures exercise exact identity, USB ancestor selection, and non-USB exclusion.
$script:present=@(
    [pscustomobject]@{InstanceId='HID\VID_1234\KEY';Class='Keyboard';FriendlyName='USB keyboard'},
    [pscustomobject]@{InstanceId='USB\VID_1234\RX';Class='USB';FriendlyName='Receiver'},
    [pscustomobject]@{InstanceId='USB\ROOT_HUB30\1';Class='USB';FriendlyName='Root hub'},
    [pscustomobject]@{InstanceId='PCI\USBHOST\1';Class='USB';FriendlyName='Host'},
    [pscustomobject]@{InstanceId='BTH\MOUSE\1';Class='Mouse';FriendlyName='Bluetooth mouse'},
    [pscustomobject]@{InstanceId='USB\VID_ABCD\NIC';Class='Net';FriendlyName='Network'},
    [pscustomobject]@{InstanceId='ACPI\PNP0303\1';Class='Keyboard';FriendlyName='Internal keyboard'}
)
$script:parent=@{'HID\VID_1234\KEY'='USB\VID_1234\RX';'USB\VID_1234\RX'='USB\ROOT_HUB30\1';'USB\ROOT_HUB30\1'='PCI\USBHOST\1'}
$script:wmi=@(
    [pscustomobject]@{InstanceName='HID\VID_1234\KEY_0';Enable=$true},
    [pscustomobject]@{InstanceName='USB\VID_1234\RX_0';Enable=$true},
    [pscustomobject]@{InstanceName='USB\ROOT_HUB30\1_0';Enable=$true},
    [pscustomobject]@{InstanceName='HID\VID_1234\KEY_EXTRA_0';Enable=$true},
    [pscustomobject]@{InstanceName='USB\VID_ABCD\NIC_0';Enable=$true}
)
function Get-PnpDevice { param([switch]$PresentOnly,$ErrorAction) $script:present }
function Get-PnpDeviceProperty { param($InstanceId,$KeyName,$ErrorAction) [pscustomobject]@{Data=$script:parent[$InstanceId]} }
function Get-CimInstance { param($Namespace,$ClassName,$ErrorAction) if ($ClassName -eq 'MSPower_DeviceEnable') { $script:wmi } else { [pscustomobject]@{BuildNumber='26100';ProductType=1;Caption='Fixture Windows 11'} } }
$usb=Get-TPUsbTargets -Scope InputDevices
Assert-TP ($usb.Targets.Count -eq 3) 'USB input and two USB ancestors only'
Assert-TP (@($usb.Targets | Where-Object {$_.State -eq 'Known'}).Count -eq 3) 'Exact WMI ordinal matches'
Assert-TP (@($usb.Targets | Where-Object {$_.InstanceId -match 'PCI|BTH|NIC|ACPI'}).Count -eq 0) 'Non-USB inputs and unrelated NIC excluded'
$script:wmi += [pscustomobject]@{InstanceName='HID\VID_1234\KEY_1';Enable=$true}
$ambiguous=Get-TPUsbTargets -Scope InputDevices
Assert-TP (@($ambiguous.Targets | Where-Object {$_.InstanceId -eq 'HID\VID_1234\KEY' -and $_.State -eq 'Unknown'}).Count -eq 1) 'Ambiguous WMI is Unknown'

# Full entrypoint mocks exercise the real plan/apply/WhatIf flow, no power writes.
function Initialize-TPNative {}
function Test-TPAdministrator { $true }
function Get-TPActiveScheme { [guid]'381b4222-f694-41f0-9685-ff5bb260df2e' }
function Get-TPPolicyCode { param($Setting,$Source) if ($script:policySetting -eq [string]$Setting -and $Source -in @('AC','DC')) {1260} else {0} }
function Get-TPUsbTargets { param($Scope) [pscustomobject]@{Targets=@();Notes=@('Fixture: optional driver control unavailable')} }
function Get-TPAttributes { param($Subgroup,$Setting) [pscustomobject]@{Known=$true;Value=$script:attributes} }
function Read-TPValue { param($Scheme,$Subgroup,$Setting,$Source) [pscustomobject]@{Code=if ($script:unknownSetting -eq [string]$Setting) {2} else {0};Value=[uint32]$script:values[([string]$Setting+'|'+$Source)]} }
function Invoke-TPPowerCfg {
    param([string[]]$Arguments)
    if ($Arguments[0] -eq '/list') { 'Power scheme 381b4222-f694-41f0-9685-ff5bb260df2e'; return }
    $script:calls.Add(@($Arguments))
    if ($Arguments[0] -match '^/set(ac|dc)valueindex$') { $source=$Matches[1].ToUpperInvariant(); $script:values[$Arguments[3]+'|'+$source]=[uint32]$Arguments[4] }
    elseif ($Arguments[0] -eq '/attributes') { $script:attributes=0 }
}
function Restart-Computer { throw 'Unexpected reboot call' }
function Reset-TPFixture {
    $script:values=@{}
    foreach ($definition in @(Get-TPDefinitions)) { foreach ($source in @('AC','DC')) { $script:values[$definition.Setting+'|'+$source]=[uint32]120 } }
    $script:calls=New-Object 'System.Collections.Generic.List[object]'
    $script:attributes=1; $script:policySetting=''; $script:unknownSetting=''
}
$testOutput=Join-Path ([IO.Path]::GetTempPath()) ('ScriptLibrary-PowerFixture-'+[guid]::NewGuid().ToString('N').Substring(0,8))
Reset-TPFixture
$result=Invoke-TechnicianPowerSettings -OutputDirectory $testOutput
Assert-TP ($script:calls.Count -eq 0) 'Default plan never writes power settings'
Assert-TP ($result.Settings -eq 11) 'Both-source plan plus visibility'
Assert-TP (Test-Path -LiteralPath (Join-Path $result.ReportDirectory 'RecoveryPlan.json')) 'Recovery written before apply'
$report=Get-Content -LiteralPath (Join-Path $result.ReportDirectory 'PowerSettings.json') -Raw | ConvertFrom-Json
Assert-TP ($report.Plan.Count -eq 11) 'Plan report contains every row'
Assert-TP ($report.Mode -eq 'Plan') 'Plan report mode'
Reset-TPFixture
$result=Invoke-TechnicianPowerSettings -Apply -WhatIf -OutputDirectory $testOutput
Assert-TP ($script:calls.Count -eq 0) 'WhatIf blocks writes'
Assert-TP ($result.Applied -eq 0) 'WhatIf does not claim applied'
Assert-TP (Test-Path -LiteralPath (Join-Path $result.ReportDirectory 'RecoveryPlan.json')) 'WhatIf still writes reviewable recovery report'
Reset-TPFixture
$result=Invoke-TechnicianPowerSettings -Apply -Confirm:$false -SkipRestartPrompt -OutputDirectory $testOutput
Assert-TP ($script:calls.Count -eq 12) 'Ten timer writes, visibility, activation'
Assert-TP ($result.Applied -eq 11) 'Every applied stored setting verified'
$ac=@($script:calls | Where-Object {$_[0] -eq '/setacvalueindex'})
$dc=@($script:calls | Where-Object {$_[0] -eq '/setdcvalueindex'})
Assert-TP ($ac.Count -eq 5 -and $dc.Count -eq 5) 'AC and DC independently written'
Assert-TP (@($script:calls | Where-Object {$_[0] -eq '/hibernate'}).Count -eq 0) 'No implicit hiberfile deletion'
Assert-TP (@($script:calls | Where-Object {$_[0] -eq '/setacvalueindex' -and $_[3] -eq '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e' -and $_[4] -eq '3600'}).Count -eq 1) 'Screen is one hour in seconds'
Reset-TPFixture
$result=Invoke-TechnicianPowerSettings -Apply -PowerSource AC -Confirm:$false -OutputDirectory $testOutput
Assert-TP (@($script:calls | Where-Object {$_[0] -eq '/setdcvalueindex'}).Count -eq 0) 'AC-only never changes DC timers'
Reset-TPFixture
$script:policySetting='7bc4a2f9-d8fc-4469-b07b-33eb785aaca0'
$result=Invoke-TechnicianPowerSettings -Apply -Confirm:$false -OutputDirectory $testOutput
Assert-TP (@($script:calls | Where-Object {$_[0] -match '^/set[ad]cvalueindex$' -and $_[3] -eq $script:policySetting}).Count -eq 0) 'Managed timers skipped'
Assert-TP (@($script:calls | Where-Object {$_[0] -eq '/attributes'}).Count -eq 0) 'Managed unattended visibility skipped'
Reset-TPFixture
$script:unknownSetting='48e6b7a6-50f5-4782-a5d4-53bb8f07e226'
$result=Invoke-TechnicianPowerSettings -Apply -Confirm:$false -OutputDirectory $testOutput
Assert-TP (@($script:calls | Where-Object {$_[0] -match '^/set[ad]cvalueindex$' -and $_[3] -eq $script:unknownSetting}).Count -eq 0) 'Unsupported setting never written'
Assert-TP ($result.UnknownOrFailed -eq 2) 'Unsupported AC/DC both Unknown'
Reset-TPFixture
$result=Invoke-TechnicianPowerSettings -Apply -OfferRestart -SkipRestartPrompt -Confirm:$false -OutputDirectory $testOutput
Assert-TP ($result.Restart -eq 'Deferred') 'Unattended restart explicitly deferred'
Reset-TPFixture
$script:wmi=@([pscustomobject]@{InstanceName='HID\VID_1234\KEY_0';Enable=$true})
$script:deviceWrites=0
function Get-TPUsbTargets {
    param($Scope)
    [pscustomobject]@{Targets=@([pscustomobject]@{InstanceId='HID\VID_1234\KEY';Name='Fixture keyboard';InstanceName=$script:wmi[0].InstanceName;Original=$script:wmi[0].Enable;State='Known';CimInstance=$script:wmi[0]});Notes=@()}
}
function Set-CimInstance { param($InputObject,$Property,$ErrorAction) $script:deviceWrites++; Assert-TP ($Property.Count -eq 1 -and $Property.ContainsKey('Enable') -and -not $Property.Enable) 'Only device Enable is changed'; $InputObject.Enable=$false }
$result=Invoke-TechnicianPowerSettings -Apply -Confirm:$false -OutputDirectory $testOutput
Assert-TP ($script:deviceWrites -eq 1) 'One exactly correlated USB device changed'
Assert-TP ($result.Applied -eq 12) 'USB stored value verified with timers'
$report=Get-Content -LiteralPath (Join-Path $result.ReportDirectory 'PowerSettings.json') -Raw | ConvertFrom-Json
Assert-TP ($report.Restart -match 'may be needed') 'Device driver restart implication reported'
Assert-TP (-not ((Get-Content -LiteralPath (Join-Path $result.ReportDirectory 'PowerSettings.json') -Raw) -match 'CimInstance')) 'Reports do not serialize CIM objects'
Reset-TPFixture
$script:wmi[0].Enable=$true
$script:deviceWrites=0
$result=Invoke-TechnicianPowerSettings -Apply -WhatIf -OutputDirectory $testOutput
Assert-TP ($script:deviceWrites -eq 0 -and $script:wmi[0].Enable) 'WhatIf prevents USB device power change'
$tokens=$null; $errors=$null
[Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors) | Out-Null
Assert-TP ($errors.Count -eq 0) 'PowerShell 5.1 parse'
'Passed {0} power settings mock assertions. No actual power settings or devices were changed.' -f $script:checks
