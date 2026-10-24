<#
What it does
  Plans or applies never-sleep/hibernate timers, a 60-minute display timer, visible
  unattended sleep settings, and disabled USB power saving for connected inputs.
Available flags
  -Apply [-WhatIf] [-Confirm], -PowerSource AC|DC|Both, -ScreenTimeoutMinutes,
  -PowerSchemeGuid, -UsbScope InputDevices|AllUsb, -DisableHibernation,
  -OfferRestart, -SkipRestartPrompt, -OutputDirectory. Run Get-Help for syntax.
How it works
  Reads numeric power settings and policy restrictions, saves original values and
  recovery instructions, then changes only approved settings. USB changes require
  exact present-device matches. Restarts always require a separate confirmation.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$Apply,
    [ValidateSet('AC', 'DC', 'Both')][string]$PowerSource = 'Both',
    [ValidateRange(1, 1440)][int]$ScreenTimeoutMinutes = 60,
    [guid]$PowerSchemeGuid = [guid]::Empty,
    [ValidateSet('InputDevices', 'AllUsb')][string]$UsbScope = 'InputDevices',
    [switch]$DisableHibernation,
    [switch]$OfferRestart,
    [switch]$SkipRestartPrompt,
    [string]$OutputDirectory
)

function Initialize-TPNative {
    if ('TechnicianPower.NativeV1' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace TechnicianPower {
  public static class NativeV1 {
    [DllImport("powrprof.dll")] public static extern uint PowerGetActiveScheme(IntPtr root, out IntPtr scheme);
    [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr value);
    [DllImport("powrprof.dll")] public static extern uint PowerReadACValueIndex(IntPtr root, ref Guid scheme, ref Guid subgroup, ref Guid setting, out uint value);
    [DllImport("powrprof.dll")] public static extern uint PowerReadDCValueIndex(IntPtr root, ref Guid scheme, ref Guid subgroup, ref Guid setting, out uint value);
    [DllImport("powrprof.dll")] public static extern uint PowerSettingAccessCheckEx(uint access, ref Guid setting, uint desiredAccess);
    public static Guid Active() {
      IntPtr p; uint error = PowerGetActiveScheme(IntPtr.Zero, out p);
      if (error != 0) throw new System.ComponentModel.Win32Exception((int)error);
      try { return (Guid)Marshal.PtrToStructure(p, typeof(Guid)); } finally { LocalFree(p); }
    }
  }
}
'@ -ErrorAction Stop
}

function Get-TPDefinitions {
    param([int]$Minutes = 60)
    @(
        [pscustomobject]@{ Name='Sleep idle timeout'; Subgroup='238c9fa8-0aad-41ed-83f4-97be242c8f20'; Setting='29f6c1db-86da-48c5-9fdb-f2b67b1f44da'; Desired=[uint32]0 },
        [pscustomobject]@{ Name='Unattended sleep timeout'; Subgroup='238c9fa8-0aad-41ed-83f4-97be242c8f20'; Setting='7bc4a2f9-d8fc-4469-b07b-33eb785aaca0'; Desired=[uint32]0 },
        [pscustomobject]@{ Name='Hibernate idle timeout'; Subgroup='238c9fa8-0aad-41ed-83f4-97be242c8f20'; Setting='9d7815a6-7ee4-497e-8888-515a05f02364'; Desired=[uint32]0 },
        [pscustomobject]@{ Name='Display idle timeout'; Subgroup='7516b95f-f776-4464-8c53-06167f40cc99'; Setting='3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'; Desired=[uint32]($Minutes * 60) },
        [pscustomobject]@{ Name='USB selective suspend'; Subgroup='2a737441-1930-4402-8d77-b2bebba308a3'; Setting='48e6b7a6-50f5-4782-a5d4-53bb8f07e226'; Desired=[uint32]0 }
    )
}

function Read-TPValue {
    param([guid]$Scheme, [guid]$Subgroup, [guid]$Setting, [ValidateSet('AC','DC')][string]$Source)
    [uint32]$value = 0
    if ($Source -eq 'AC') { $code = [TechnicianPower.NativeV1]::PowerReadACValueIndex([IntPtr]::Zero, [ref]$Scheme, [ref]$Subgroup, [ref]$Setting, [ref]$value) }
    else { $code = [TechnicianPower.NativeV1]::PowerReadDCValueIndex([IntPtr]::Zero, [ref]$Scheme, [ref]$Subgroup, [ref]$Setting, [ref]$value) }
    [pscustomobject]@{ Code=[uint32]$code; Value=$value }
}

function Get-TPPolicyCode {
    param([guid]$Setting, [ValidateSet('AC','DC','Scheme','ActiveScheme')][string]$Source)
    $access = switch ($Source) { 'AC' {0} 'DC' {1} 'Scheme' {16} 'ActiveScheme' {19} }
    [TechnicianPower.NativeV1]::PowerSettingAccessCheckEx([uint32]$access, [ref]$Setting, [uint32]0x20006)
}

function Get-TPActiveScheme { [TechnicianPower.NativeV1]::Active() }

function Get-TPAttributes {
    param([string]$Subgroup, [string]$Setting)
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\{0}\{1}' -f $Subgroup,$Setting
    try {
        $value = Get-ItemProperty -LiteralPath $path -Name Attributes -ErrorAction Stop
        [pscustomobject]@{ Known=$true; Value=[uint32]$value.Attributes }
    } catch { [pscustomobject]@{ Known=$false; Value=$null } }
}

function Invoke-TPPowerCfg {
    param([string[]]$Arguments)
    $binary = Join-Path $env:WINDIR 'System32\powercfg.exe'
    $text = @(& $binary @Arguments 2>&1 | ForEach-Object { [string]$_ })
    if ($LASTEXITCODE -ne 0) { throw ('powercfg failed with exit code {0}.' -f $LASTEXITCODE) }
    $text
}

function Test-TPAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    finally { $identity.Dispose() }
}

function Get-TPUsbTargets {
    param([ValidateSet('InputDevices','AllUsb')][string]$Scope)
    $notes = New-Object 'System.Collections.Generic.List[string]'
    $targets = @{}
    try { $present = @(Get-PnpDevice -PresentOnly -ErrorAction Stop) }
    catch { return [pscustomobject]@{ Targets=@(); Notes=@('Unknown: present PnP inventory unavailable.'); Instances=@() } }
    $byId = @{}
    foreach ($device in $present) { $byId[[string]$device.InstanceId] = $device }
    if ($Scope -eq 'AllUsb') { $starts = @($present | Where-Object { $_.InstanceId -like 'USB\*' }) }
    else { $starts = @($present | Where-Object { $_.Class -in @('Keyboard','Mouse') }) }
    foreach ($start in $starts) {
        $chain = New-Object 'System.Collections.Generic.List[object]'
        $seen = @{}
        $current = $start
        $usbFound = $false
        for ($level = 0; $current -and $level -lt 24; $level++) {
            $id = [string]$current.InstanceId
            if ($seen.ContainsKey($id)) { break }
            $seen[$id] = $true
            $chain.Add($current)
            if ($id -like 'USB\*') { $usbFound = $true }
            try {
                $parentId = [string](Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_Parent' -ErrorAction Stop).Data
                if ($byId.ContainsKey($parentId)) { $current = $byId[$parentId] } else { $current = $null }
            } catch {
                $notes.Add(('Unknown parent trace for {0}; completed USB ancestors only.' -f $id))
                $current = $null
            }
        }
        if ($usbFound) {
            foreach ($device in $chain) {
                # Exclude PCI host controllers, Bluetooth stacks, and unrelated ancestors.
                if ($device.InstanceId -like 'USB\*' -or ($device.InstanceId -like 'HID\*' -and $device.Class -in @('Keyboard','Mouse'))) {
                    $targets[[string]$device.InstanceId] = $device
                }
            }
        }
    }
    try { $instances = @(Get-CimInstance -Namespace 'root\wmi' -ClassName MSPower_DeviceEnable -ErrorAction Stop) }
    catch { $instances = @(); $notes.Add('Unknown: MSPower_DeviceEnable is unavailable or inaccessible; no device power writes will be made.') }
    $result = New-Object 'System.Collections.Generic.List[object]'
    foreach ($id in @($targets.Keys | Sort-Object)) {
        # WMI adds an instance ordinal. Require an exact ID followed only by that ordinal.
        $pattern = '^{0}(?:_\d+)?$' -f [regex]::Escape($id)
        $matches = @($instances | Where-Object { [string]$_.InstanceName -match $pattern })
        if ($matches.Count -eq 1) {
            $result.Add([pscustomobject]@{ InstanceId=$id; Name=[string]$targets[$id].FriendlyName; InstanceName=[string]$matches[0].InstanceName; Original=[bool]$matches[0].Enable; State='Known'; CimInstance=$matches[0] })
        } else {
            $result.Add([pscustomobject]@{ InstanceId=$id; Name=[string]$targets[$id].FriendlyName; InstanceName=$null; Original=$null; State='Unknown'; CimInstance=$null })
            $notes.Add(('Unknown driver power control for {0}: {1} exact WMI matches.' -f $id,$matches.Count))
        }
    }
    if ($result.Count -eq 0) { $notes.Add('No supported connected USB input power controls were identified; this is not a pass result.') }
    [pscustomobject]@{ Targets=@($result.ToArray()); Notes=@($notes.ToArray()) }
}

function New-TPPlan {
    param([guid]$Scheme, [string]$Source, [int]$Minutes)
    $sources = if ($Source -eq 'Both') { @('AC','DC') } else { @($Source) }
    foreach ($definition in @(Get-TPDefinitions -Minutes $Minutes)) {
        foreach ($power in $sources) {
            $read = Read-TPValue -Scheme $Scheme -Subgroup $definition.Subgroup -Setting $definition.Setting -Source $power
            $policy = Get-TPPolicyCode -Setting $definition.Setting -Source $power
            $state = if ($read.Code -ne 0) { 'Unknown' } elseif ($policy -ne 0) { 'BlockedByPolicyOrAccess' } elseif ($read.Value -eq $definition.Desired) { 'Unchanged' } else { 'Planned' }
            [pscustomobject]@{ Kind='PowerSetting'; Name=$definition.Name; Source=$power; Scheme=$Scheme.ToString(); Subgroup=$definition.Subgroup; Setting=$definition.Setting; Original=if ($read.Code -eq 0) {$read.Value} else {$null}; Desired=$definition.Desired; ReadCode=$read.Code; PolicyCode=$policy; Status=$state; Verified=$false }
        }
    }
}

function Save-TPReports {
    param([string]$Directory, [object]$Report, [object[]]$Plan, [object[]]$Recovery)
    $Report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Directory 'PowerSettings.json') -Encoding UTF8 -ErrorAction Stop -WhatIf:$false -Confirm:$false
    $Plan | Select-Object Kind,Name,Source,Scheme,Subgroup,Setting,Original,Desired,ReadCode,PolicyCode,Status,Verified | Export-Csv -LiteralPath (Join-Path $Directory 'PowerSettings.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop -WhatIf:$false -Confirm:$false
    ConvertTo-Json -InputObject @($Recovery) -Depth 8 | Set-Content -LiteralPath (Join-Path $Directory 'RecoveryPlan.json') -Encoding UTF8 -ErrorAction Stop -WhatIf:$false -Confirm:$false
}

function Invoke-TechnicianPowerSettings {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [switch]$Apply,
        [ValidateSet('AC','DC','Both')][string]$PowerSource='Both',
        [ValidateRange(1,1440)][int]$ScreenTimeoutMinutes=60,
        [guid]$PowerSchemeGuid=[guid]::Empty,
        [ValidateSet('InputDevices','AllUsb')][string]$UsbScope='InputDevices',
        [switch]$DisableHibernation, [switch]$OfferRestart, [switch]$SkipRestartPrompt,
        [string]$OutputDirectory
    )
    $ErrorActionPreference = 'Stop'
    if ($PSVersionTable.PSVersion -lt [version]'5.1' -or $env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Use native 64-bit Windows PowerShell 5.1 or later on Windows.' }
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $build = [int]$os.BuildNumber
    if (($os.ProductType -eq 1 -and $build -lt 22000) -or ($os.ProductType -ne 1 -and $build -notin @(20348,26100))) { throw 'Supported targets are Windows 11 and Windows Server 2022/2025.' }
    if ($Apply -and -not $WhatIfPreference -and -not (Test-TPAdministrator)) { throw 'Run elevated to apply settings. Omit -Apply to create a plan.' }
    Initialize-TPNative
    $active = Get-TPActiveScheme
    $scheme = if ($PowerSchemeGuid -eq [guid]::Empty) { $active } else { $PowerSchemeGuid }
    $listed = (Invoke-TPPowerCfg -Arguments @('/list')) -join [Environment]::NewLine
    if (-not [regex]::IsMatch($listed, [regex]::Escape($scheme.ToString()), [Text.RegularExpressions.RegexOptions]::IgnoreCase)) { throw 'Requested power scheme does not exist.' }
    $schemePolicy = Get-TPPolicyCode -Setting $scheme -Source Scheme
    $activationPolicy = Get-TPPolicyCode -Setting $scheme -Source ActiveScheme
    if ($Apply -and ($schemePolicy -ne 0 -or $activationPolicy -ne 0)) { throw ('Power scheme is restricted by policy or access (scheme={0}; activation={1}).' -f $schemePolicy,$activationPolicy) }
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path (Split-Path -Parent $PSScriptRoot) 'Reports\PowerSettings' }
    $base = [IO.Path]::GetFullPath($OutputDirectory)
    $directory = Join-Path $base ('{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
    # Report writes are intentional even under -WhatIf; operational changes remain guarded.
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $plan = @(New-TPPlan -Scheme $scheme -Source $PowerSource -Minutes $ScreenTimeoutMinutes)
    $usb = Get-TPUsbTargets -Scope $UsbScope
    $unattended = @(Get-TPDefinitions -Minutes $ScreenTimeoutMinutes | Where-Object { $_.Name -eq 'Unattended sleep timeout' })[0]
    $attributes = Get-TPAttributes -Subgroup $unattended.Subgroup -Setting $unattended.Setting
    $visibilityState = if (-not $attributes.Known) { 'Unknown' } elseif (($attributes.Value -band 1) -eq 0) { 'Unchanged' } else { 'Planned' }
    $visibility = [pscustomobject]@{ Kind='Visibility'; Name='Show unattended sleep setting (global visibility)'; Source='Global'; Scheme=$null; Subgroup=$unattended.Subgroup; Setting=$unattended.Setting; Original=$attributes.Value; Desired='Hide bit cleared'; ReadCode=$null; PolicyCode=$null; Status=$visibilityState; Verified=$false }
    $plan += $visibility
    foreach ($target in $usb.Targets) {
        $state = if ($target.State -ne 'Known') { 'Unknown' } elseif (-not $target.Original) { 'Unchanged' } else { 'Planned' }
        $plan += [pscustomobject]@{ Kind='UsbDevice'; Name=$target.InstanceId; Source='Device'; Scheme=$null; Subgroup=$null; Setting=$target.InstanceName; Original=$target.Original; Desired=$false; ReadCode=$null; PolicyCode=$null; Status=$state; Verified=$false }
    }
    $recovery = New-Object 'System.Collections.Generic.List[object]'
    foreach ($row in $plan | Where-Object { $_.Kind -eq 'PowerSetting' -and $null -ne $_.Original }) {
        $recovery.Add([pscustomobject]@{ Kind='PowerSetting'; ReviewBeforeUse=$true; Program='powercfg.exe'; Arguments=@(('/set{0}valueindex' -f $row.Source.ToLowerInvariant()),$row.Scheme,$row.Subgroup,$row.Setting,[string]$row.Original) })
    }
    if ($attributes.Known) {
        $flag = if (($attributes.Value -band 1) -eq 1) { '+ATTRIB_HIDE' } else { '-ATTRIB_HIDE' }
        $recovery.Add([pscustomobject]@{ Kind='Visibility'; ReviewBeforeUse=$true; Program='powercfg.exe'; Arguments=@('/attributes',$unattended.Subgroup,$unattended.Setting,$flag) })
    }
    foreach ($target in $usb.Targets | Where-Object { $_.State -eq 'Known' }) {
        $recovery.Add([pscustomobject]@{ Kind='UsbDevice'; ReviewBeforeUse=$true; Namespace='root\wmi'; Class='MSPower_DeviceEnable'; InstanceName=$target.InstanceName; OriginalEnable=$target.Original; Instruction='Re-identify the same present PnP device and exact WMI instance before restoring Enable. Do not restore to a different device.' })
    }
    $recovery.Add([pscustomobject]@{ Kind='ActiveScheme'; ReviewBeforeUse=$true; Program='powercfg.exe'; Arguments=@('/setactive',$active.ToString()); Instruction='Reapply the original active scheme after reviewing restored settings.' })
    $report = [ordered]@{
        CreatedUtc=(Get-Date).ToUniversalTime().ToString('o'); ComputerName=$env:COMPUTERNAME; Mode=if ($Apply) {'Apply'} else {'Plan'};
        OS=[string]$os.Caption; Build=$build; OriginalActiveScheme=$active.ToString(); TargetScheme=$scheme.ToString(); PowerSource=$PowerSource;
        ScreenTimeoutMinutes=$ScreenTimeoutMinutes; UsbScope=$UsbScope; Plan=$plan; UsbNotes=$usb.Notes; HibernateFeature='Unchanged'; HibernateFeatureAction=if ($DisableHibernation) {'Plan: disable hibernation feature and remove hiberfile; also affects Fast Startup'} else {'Leave hibernation feature and hiberfile unchanged; disable idle timer only'}; Restart='Not requested';
        Limitations=@('Power indices verify stored settings, not all firmware, Modern Standby, presence sensing, lock-screen, policy, battery-critical, or application behavior.', 'GPO/MDM can override these values. No policy registry keys are changed.', 'Device driver power controls are optional; Unknown is not successful remediation.', 'USB ancestor hub changes also affect other devices on that hub. Device settings apply independently of AC/DC selection.', 'Disabling selective suspend increases power consumption. Wake-on-input settings are not changed.', 'Unattended setting visibility is global; timer values belong to the selected plan.');
        Sources=@('https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options','https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-sleep-unattended-idle-timeout','https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/display-settings-display-idle-timeout','https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/teams-rooms-and-devices/usb-selective-suspend-status-unhealthy','https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/wmi-and-the-power-management-tab','https://learn.microsoft.com/en-us/windows/win32/api/powrprof/nf-powrprof-powersettingaccesscheckex')
    }
    Save-TPReports -Directory $directory -Report $report -Plan $plan -Recovery $recovery.ToArray()
    $changedPlan = $false
    $changedDevices = $false
    if ($Apply) {
        foreach ($row in $plan | Where-Object { $_.Status -eq 'Planned' }) {
            if (-not $PSCmdlet.ShouldProcess($row.Name, ('Set {0} from {1} to {2}' -f $row.Source,$row.Original,$row.Desired))) { $row.Status='Skipped'; continue }
            try {
                switch ($row.Kind) {
                    'PowerSetting' {
                        # Recheck managed status immediately before the individual write.
                        $code = Get-TPPolicyCode -Setting $row.Setting -Source $row.Source
                        if ($code -ne 0) { $row.PolicyCode=$code; $row.Status='BlockedByPolicyOrAccess'; continue }
                        Invoke-TPPowerCfg -Arguments @(('/set{0}valueindex' -f $row.Source.ToLowerInvariant()),$row.Scheme,$row.Subgroup,$row.Setting,[string]$row.Desired) | Out-Null
                        $changedPlan = $true
                        $after = Read-TPValue -Scheme $scheme -Subgroup $row.Subgroup -Setting $row.Setting -Source $row.Source
                        $row.Verified = $after.Code -eq 0 -and $after.Value -eq $row.Desired
                    }
                    'Visibility' {
                        if (@($plan | Where-Object { $_.Name -eq 'Unattended sleep timeout' -and $_.PolicyCode -ne 0 }).Count -gt 0) { $row.Status='BlockedByPolicyOrAccess'; continue }
                        Invoke-TPPowerCfg -Arguments @('/attributes',$row.Subgroup,$row.Setting,'-ATTRIB_HIDE') | Out-Null
                        $afterAttributes = Get-TPAttributes -Subgroup $row.Subgroup -Setting $row.Setting
                        $row.Verified = $afterAttributes.Known -and ($afterAttributes.Value -band 1) -eq 0
                    }
                    'UsbDevice' {
                        # Re-enumerate before mutation to avoid stale or newly disconnected device matches.
                        $current = Get-TPUsbTargets -Scope $UsbScope
                        $matches = @($current.Targets | Where-Object { $_.State -eq 'Known' -and $_.InstanceId -eq $row.Name -and $_.InstanceName -eq $row.Setting })
                        if ($matches.Count -ne 1) { $row.Status='Unknown'; continue }
                        Set-CimInstance -InputObject $matches[0].CimInstance -Property @{ Enable=$false } -ErrorAction Stop | Out-Null
                        $changedDevices = $true
                        $verify = @(Get-CimInstance -Namespace 'root\wmi' -ClassName MSPower_DeviceEnable -ErrorAction Stop | Where-Object { $_.InstanceName -eq $row.Setting })
                        $row.Verified = $verify.Count -eq 1 -and -not [bool]$verify[0].Enable
                    }
                }
                $row.Status = if ($row.Verified) { 'AppliedStoredValueVerified' } else { 'ChangedVerificationUnknown' }
            } catch { $row.Status='Failed'; Write-Warning ('{0}: {1}' -f $row.Name,$_.Exception.Message) }
            Save-TPReports -Directory $directory -Report $report -Plan $plan -Recovery $recovery.ToArray()
        }
        if ($changedPlan -and $PSCmdlet.ShouldProcess($scheme.ToString(), 'Activate or refresh the selected power plan')) {
            try {
                if ((Get-TPPolicyCode -Setting $scheme -Source ActiveScheme) -ne 0) { throw 'Power plan activation is restricted by policy or access.' }
                Invoke-TPPowerCfg -Arguments @('/setactive',$scheme.ToString()) | Out-Null
                $report['ActiveSchemeAfter'] = (Get-TPActiveScheme).ToString()
            } catch { $report['ActivationError']=$_.Exception.Message; Write-Warning $_.Exception.Message }
        }
        if ($DisableHibernation -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Disable hibernation feature and remove its hiberfile (also affects Fast Startup)')) {
            try {
                $originalHibernate = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -ErrorAction Stop
                if (-not $originalHibernate.PSObject.Properties['HibernateEnabled']) { throw 'Original hibernation state cannot be established.' }
                $recovery.Add([pscustomobject]@{ Kind='HibernateFeature'; ReviewBeforeUse=$true; OriginalEnabled=[bool]$originalHibernate.HibernateEnabled; OriginalHiberFileType=$originalHibernate.HiberFileType; OriginalHiberFileSizePercent=$originalHibernate.HiberFileSizePercent; Instruction='Review the recorded original feature state, hiberfile size/type, and Fast Startup policy before any powercfg /hibernate on/off recovery.' })
                Save-TPReports -Directory $directory -Report $report -Plan $plan -Recovery $recovery.ToArray()
                Invoke-TPPowerCfg -Arguments @('/hibernate','off') | Out-Null
                $report['HibernateFeature']='Disabled; native command succeeded'
            } catch { $report['HibernateFeature']='Failed or unknown'; Write-Warning $_.Exception.Message }
        }
    }
    if ($changedDevices) { $report['Restart']='Device reconnect or restart may be needed by individual drivers; no restart has been performed.' }
    Save-TPReports -Directory $directory -Report $report -Plan $plan -Recovery $recovery.ToArray()
    if ($Apply -and $OfferRestart -and ($changedDevices -or $changedPlan)) {
        if ($SkipRestartPrompt -or $WhatIfPreference) { $report['Restart']='Deferred' }
        else {
            $yesToAll = $false; $noToAll = $false
            if ($PSCmdlet.ShouldContinue('Restart this computer now? Save open work first. Declining defers the restart.', 'Separate restart confirmation', [ref]$yesToAll, [ref]$noToAll)) {
                if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restart computer after explicit confirmation')) {
                    $report['Restart']='Approved; restart requested'
                    Save-TPReports -Directory $directory -Report $report -Plan $plan -Recovery $recovery.ToArray()
                    Restart-Computer -ErrorAction Stop
                }
            } else { $report['Restart']='Deferred by user' }
        }
    }
    Save-TPReports -Directory $directory -Report $report -Plan $plan -Recovery $recovery.ToArray()
    [pscustomobject]@{ Mode=$report.Mode; TargetScheme=$scheme; PowerSource=$PowerSource; Settings=@($plan).Count; Applied=@($plan | Where-Object { $_.Status -eq 'AppliedStoredValueVerified' }).Count; UnknownOrFailed=@($plan | Where-Object { $_.Status -match 'Unknown|Failed|Blocked' }).Count; ReportDirectory=$directory; Restart=$report.Restart }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-TechnicianPowerSettings @PSBoundParameters
}
