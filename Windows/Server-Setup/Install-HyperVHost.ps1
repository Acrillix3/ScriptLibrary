<#
What it does:
  Plan or install Hyper-V and optionally create an external switch in a separate run.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -CreateSwitch: Create an external switch only after Hyper-V is installed and restarted.
  -SwitchName: Explicit name for the new external switch.
  -NetAdapterName: Literal adapter name selected for that switch; management OS access remains enabled.

How it works:
  Checks host capabilities, existing switches and adapter conflicts, then gates installation or switch creation behind Apply and ShouldProcess. A required restart needs separate confirmation; no VMs are created.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$Apply,
    [string]$OutputDirectory,
    [switch]$SkipRestartPrompt,
        [switch]$CreateSwitch,
    [string]$SwitchName,
    [string]$NetAdapterName
)
$ErrorActionPreference='Stop'
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$setupScriptName=[IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Path)
$setupReportDirectory=Join-Path $OutputDirectory ($setupScriptName+'-'+(Get-Date -Format yyyyMMdd-HHmmss)+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $setupReportDirectory -Force -WhatIf:$false -Confirm:$false
$setupSteps=New-Object 'System.Collections.Generic.List[object]'
$setupChecks=New-Object 'System.Collections.Generic.List[object]'
$setupServiceRestarts=New-Object 'System.Collections.Generic.List[object]'
$setupBlocked=$false;$setupCanApply=[bool]$Apply;$setupRestartRequired=$false;$setupChanges=0;$setupCmdlet=$PSCmdlet;$setupRestartOffered=$false;$setupRestartDecision=$null
$setupHost=[pscustomobject]@{Computer=$env:COMPUTERNAME;Caption=$null;Build=$null;ProductType=$null;DomainRole=$null;PartOfDomain=$null;Domain=$null;Runtime=[string]$PSVersionTable.PSVersion;Administrator=$false;PendingRestart=$null}
function Set-SetupBlocked {
    param([string]$Reason)
    $script:setupBlocked=$true;$script:setupCanApply=$false
    $setupChecks.Add([pscustomobject]@{Name='ApplyGate';State='Blocked';Evidence=$Reason;Rows=$null;ErrorType=$null})
}
function Test-SetupCommand {
    param([string]$Name,[string[]]$Parameters=@())
    $command=Get-Command -Name $Name -ErrorAction SilentlyContinue
    if($null -eq $command){return $false}
    foreach($parameterName in $Parameters){if(-not $command.Parameters.ContainsKey($parameterName)){return $false}}
    return $true
}
function Invoke-SetupQuery {
    param([string]$Name,[scriptblock]$Action,[switch]$RequireData)
    try{
        $data=@(& $Action)
        if($RequireData -and $data.Count -eq 0){throw [InvalidOperationException]::new('Required evidence absent')}
        $setupChecks.Add([pscustomobject]@{Name=$Name;State='Collected';Evidence='Read completed; raw provider objects and messages are not serialized.';Rows=$data.Count;ErrorType=$null})
        return [pscustomobject]@{Succeeded=$true;Data=$data}
    }catch{
        $setupChecks.Add([pscustomobject]@{Name=$Name;State='Unknown';Evidence='Query failed. Check the requested role, permissions, runtime and native management logs.';Rows=$null;ErrorType=$_.Exception.GetType().FullName})
        Set-SetupBlocked -Reason ('Required inspection failed: '+$Name+'. No further configuration changes will run.')
        return [pscustomobject]@{Succeeded=$false;Data=@()}
    }
}
function Add-SetupStep {
    param([string]$Name,[string]$Target,[string]$Action,[string]$Evidence,[string]$State='Planned')
    $setupSteps.Add([pscustomobject]@{Name=$Name;Target=$Target;Action=$Action;State=$State;Evidence=$Evidence})
}
function Invoke-SetupAction {
    param([string]$Name,[string]$Target,[scriptblock]$Action)
    $step=$setupSteps | Where-Object {$_.Name -eq $Name -and $_.Target -eq $Target} | Select-Object -Last 1
    if(-not $step){Add-SetupStep -Name $Name -Target $Target -Action 'Configure' -Evidence 'Explicitly gated setup operation.';$step=$setupSteps[$setupSteps.Count-1]}
    if(-not $Apply){return [pscustomobject]@{Succeeded=$false;Data=@();Skipped=$true}}
    if(-not $setupCanApply -or $setupBlocked){$step.State='Blocked';return [pscustomobject]@{Succeeded=$false;Data=@();Skipped=$true}}
    if(-not $setupCmdlet.ShouldProcess($Target,$Name)){$step.State='Skipped';return [pscustomobject]@{Succeeded=$false;Data=@();Skipped=$true}}
    try{
        $data=@(& $Action)
        foreach($item in $data){
            if($null -ne $item -and $item.PSObject.Properties['RestartNeeded'] -and [string]$item.RestartNeeded -eq 'Yes'){$script:setupRestartRequired=$true}
            if($null -ne $item -and $item.PSObject.Properties['Success'] -and $item.Success -is [bool] -and -not $item.Success){throw [InvalidOperationException]::new('Provider reported failure')}
        }
        $step.State='Applied';$script:setupChanges++
        return [pscustomobject]@{Succeeded=$true;Data=$data;Skipped=$false}
    }catch{
        $step.State='Failed'
        $setupChecks.Add([pscustomobject]@{Name=$Name;State='Failed';Evidence='Setup operation failed. Inspect native management logs before retrying; previous successful steps remain applied.';Rows=$null;ErrorType=$_.Exception.GetType().FullName})
        Set-SetupBlocked -Reason ('Setup stopped after failure: '+$Name+'. No rollback or automatic restart was attempted.')
        return [pscustomobject]@{Succeeded=$false;Data=@();Skipped=$false}
    }
}
function Save-SetupReport {
    param([object]$Summary,[string[]]$Notes)
    foreach($table in @(@{Name='plan';Rows=$setupSteps.ToArray();Columns=@('Name','Target','Action','State','Evidence')},@{Name='checks';Rows=$setupChecks.ToArray();Columns=@('Name','State','Evidence','Rows','ErrorType')})){
        $path=Join-Path $setupReportDirectory ($table.Name+'.csv')
        if($table.Rows.Count){$table.Rows | Select-Object $table.Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false}
        else{($table.Columns | ForEach-Object {'"'+$_+'"'}) -join ',' | Set-Content -LiteralPath $path -Encoding UTF8 -WhatIf:$false -Confirm:$false}
    }
    $Summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $setupReportDirectory 'summary.json') -Encoding UTF8 -WhatIf:$false -Confirm:$false
    @('Review plan.csv and checks.csv before applying. State describes this script scope, not a complete production acceptance test.','Default is plan only. Apply and ShouldProcess authorization are required for changes. Reports are written even with WhatIf.','Required restarts need a separate confirmation after the report is saved. SkipRestartPrompt leaves the server pending restart; Confirm false does not bypass the restart question.','Restart decision: '+$Summary.RestartDecision,'No automatic rollback occurs. Stop after a failed action and inspect the server before retrying.','',$Notes) | Set-Content -LiteralPath (Join-Path $setupReportDirectory 'README.txt') -Encoding UTF8 -WhatIf:$false -Confirm:$false
}
function Confirm-SetupRestart {
    return $setupCmdlet.ShouldContinue(('Restart '+$setupHost.Computer+' now? This disconnects sessions and interrupts services. The setup report is saved at '+[IO.Path]::GetFullPath($setupReportDirectory)+'.'),'Confirm required server restart')
}
function Request-SetupServiceRestart {
    param([string]$Name,[string]$Reason)
    $setupServiceRestarts.Add([pscustomobject]@{Name=$Name;Reason=$Reason;Decision='PendingConfirmation'})
    Add-SetupStep -Name 'Required service restart' -Target $Name -Action Restart -Evidence $Reason -State Deferred
}
function Confirm-SetupServiceRestart {
    param([string]$Name)
    return $setupCmdlet.ShouldContinue(('Restart service '+$Name+' on '+$setupHost.Computer+' now? This interrupts that service. The setup report has been saved.'),'Confirm required service restart')
}
function Complete-SetupReport {
    param([string[]]$Notes)
    $state=if($setupBlocked){'Blocked'}elseif(-not $Apply){'Plan'}elseif($setupRestartRequired){'RestartRequired'}elseif(@($setupSteps | Where-Object State -in @('Planned','Deferred','Skipped')).Count){'Incomplete'}else{'Complete'}
    $restartHostSupported=$setupHost.ProductType -in @(2,3) -and $setupHost.Build -in @('20348','26100') -and $setupHost.Administrator -and [Environment]::Is64BitProcess -and $PSVersionTable.PSEdition -eq 'Desktop' -and $PSVersionTable.PSVersion.Major -eq 5
    $decision=if(-not $setupRestartRequired){'NotRequired'}elseif(-not $Apply -or $WhatIfPreference){'PlanOnly'}elseif($SkipRestartPrompt){'DeferredByOption'}elseif(-not $restartHostSupported){'RestartNotAuthorized'}elseif($setupRestartOffered){$setupRestartDecision}else{'PendingConfirmation'}
    $summary=[pscustomobject]@{Script=$setupScriptName;GeneratedUtc=[datetime]::UtcNow.ToString('o');State=$state;ApplyRequested=[bool]$Apply;AppliedOperations=$setupChanges;RestartRequired=$setupRestartRequired;RestartDecision=$decision;ServiceRestarts=$setupServiceRestarts.ToArray();Host=$setupHost;Notes=$Notes;ReportDirectory=[IO.Path]::GetFullPath($setupReportDirectory)}
    Save-SetupReport -Summary $summary -Notes $Notes
    if(-not $setupRestartRequired -and $setupServiceRestarts.Count){
        foreach($request in $setupServiceRestarts){
            $restartServiceNow=$false
            if(-not $Apply -or $WhatIfPreference){$request.Decision='PlanOnly'}
            elseif($SkipRestartPrompt){$request.Decision='DeferredByOption'}
            elseif(-not $restartHostSupported){$request.Decision='RestartNotAuthorized'}
            else{
                try{if(Confirm-SetupServiceRestart -Name $request.Name){$request.Decision='Confirmed';$restartServiceNow=$true}else{$request.Decision='Declined'}}catch{$request.Decision='ConfirmationUnavailable'}
            }
            Save-SetupReport -Summary $summary -Notes $Notes
            if($restartServiceNow){
                try{
                    Restart-Service -Name $request.Name -Confirm:$false -ErrorAction Stop
                    $request.Decision='Restarted'
                    ($setupSteps | Where-Object {$_.Name -eq 'Required service restart' -and $_.Target -eq $request.Name} | Select-Object -Last 1).State='Applied'
                }catch{
                    $request.Decision='RequestFailed'
                    Set-SetupBlocked -Reason ('Required service restart failed: '+$request.Name+'. Restart it manually after review.')
                }
            }
        }
        $summary.State=if($setupBlocked){'Blocked'}elseif(@($setupServiceRestarts | Where-Object Decision -ne Restarted).Count){'ServiceRestartRequired'}else{'Complete'}
        Save-SetupReport -Summary $summary -Notes $Notes
    }
    if($decision -eq 'PendingConfirmation'){
        $script:setupRestartOffered=$true
        try{
            if(Confirm-SetupRestart){$summary.RestartDecision='Confirmed'}else{$summary.RestartDecision='Declined'}
        }catch{$summary.RestartDecision='ConfirmationUnavailable'}
        $script:setupRestartDecision=$summary.RestartDecision
        $setupChecks.Add([pscustomobject]@{Name='RequiredRestart';State=$summary.RestartDecision;Evidence='A restart occurs only after a positive response to the separate required-restart question.';Rows=$null;ErrorType=$null})
        Save-SetupReport -Summary $summary -Notes $Notes
        if($summary.RestartDecision -eq 'Confirmed'){
            try{
                Restart-Computer -Confirm:$false -ErrorAction Stop
                $summary.State='RestartRequested'
            }catch{
                $summary.State='RestartFailed';$summary.RestartDecision='RequestFailed'
                $setupChecks.Add([pscustomobject]@{Name='RequiredRestart';State='Failed';Evidence='Windows did not accept the restart request. Restart manually after reviewing the server.';Rows=$null;ErrorType=$_.Exception.GetType().FullName})
            }
            Save-SetupReport -Summary $summary -Notes $Notes
        }
    }
    return $summary
}
function Test-SetupAdministrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Initialize-SetupHost {
    $os=Invoke-SetupQuery -Name 'OperatingSystem' -RequireData -Action {Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop}
    $computer=Invoke-SetupQuery -Name 'ComputerMembership' -RequireData -Action {Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop}
    if($os.Succeeded -and $os.Data.Count -eq 1){
        $setupHost.Caption=[string]$os.Data[0].Caption;$setupHost.Build=[string]$os.Data[0].BuildNumber;$setupHost.ProductType=$os.Data[0].ProductType
        if($setupHost.ProductType -notin @(2,3) -or $setupHost.Build -notin @('20348','26100')){Set-SetupBlocked 'Only Windows Server 2022 (20348) and 2025 (26100) are targeted.'}
    }else{Set-SetupBlocked 'The operating system could not be identified unambiguously.'}
    if($computer.Succeeded -and $computer.Data.Count -eq 1){
        $setupHost.Computer=[string]$computer.Data[0].Name;$setupHost.DomainRole=$computer.Data[0].DomainRole;$setupHost.PartOfDomain=$computer.Data[0].PartOfDomain;$setupHost.Domain=[string]$computer.Data[0].Domain
        if($setupHost.DomainRole -notin @(2,3,4,5) -or $setupHost.PartOfDomain -isnot [bool]){Set-SetupBlocked 'Server membership evidence is missing or invalid.'}
    }else{Set-SetupBlocked 'Computer membership could not be identified unambiguously.'}
    if(-not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){Set-SetupBlocked 'Use native 64-bit Windows PowerShell 5.1 on the target server.'}
    try{$setupHost.Administrator=Test-SetupAdministrator}catch{$setupHost.Administrator=$false}
    if($Apply -and -not $setupHost.Administrator){Set-SetupBlocked 'Apply requires an elevated administrator session on the target server.'}
    $pending=Invoke-SetupQuery -Name 'PendingRestart' -RequireData -Action {
        $required=(Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        $session=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
        if(@($session.PendingFileRenameOperations | Where-Object {$_}).Count){$required=$true}
        $active=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction Stop
        $configured=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction Stop
        if($active.ComputerName -ne $configured.ComputerName){$required=$true}
        [pscustomobject]@{Required=[bool]$required}
    }
    if($pending.Succeeded){$setupHost.PendingRestart=$pending.Data[0].Required;if($setupHost.PendingRestart){$script:setupRestartRequired=$true;if($Apply){Set-SetupBlocked 'Restart the server to finish existing pending changes before applying this setup.'}}}
}
Initialize-SetupHost

try {
$notes = New-Object 'System.Collections.Generic.List[string]'
$notes.Add('Installs only the Hyper-V role and management tools. No VM, storage, cluster, migration, or firewall settings are created. A required restart asks for separate confirmation after reports are saved. Restart and rerun before creating a switch.')
$notes.Add('An external virtual switch can briefly disconnect this host. Use local or out-of-band console access. Management OS access remains enabled; IP addresses and VLANs are not changed by this script.')
$featureReadyAtEntry = $false
$missingFeatures = @()
$switches = @()
$adapter = $null

if (Test-SetupCommand -Name 'Get-WindowsFeature') {
    $featureQuery = Invoke-SetupQuery -Name 'Hyper-V feature inventory' -RequireData -Action { Get-WindowsFeature -Name Hyper-V -ErrorAction Stop }
    if ($featureQuery.Succeeded) {
        if (@($featureQuery.Data).Count -ne 1 -or @($featureQuery.Data)[0].Name -ne 'Hyper-V') { Set-SetupBlocked -Reason 'The Hyper-V feature was not identified unambiguously.' }
        $featureReadyAtEntry = @($featureQuery.Data | Where-Object { $_.Name -eq 'Hyper-V' -and $_.Installed }).Count -eq 1
        $missingFeatures = @($featureQuery.Data | Where-Object { -not $_.Installed } | Select-Object -ExpandProperty Name)
    }
}
else { Set-SetupBlocked -Reason 'Get-WindowsFeature is unavailable.' }

$computerQuery = Invoke-SetupQuery -Name 'Host virtualization and domain role' -RequireData -Action { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
$processorQuery = Invoke-SetupQuery -Name 'Processor virtualization capabilities' -RequireData -Action { Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop }
$osQuery = Invoke-SetupQuery -Name 'Data execution prevention capability' -RequireData -Action { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
if ($computerQuery.Succeeded) {
    $computer = @($computerQuery.Data)[0]
    if ([int]$computer.DomainRole -in @(4,5)) { Set-SetupBlocked -Reason 'Use a dedicated Hyper-V host; this computer is a domain controller.' }
    if ($computer.HypervisorPresent -and -not $featureReadyAtEntry) {
        Add-SetupStep -Name 'Existing hypervisor detected' -Target 'Local host' -Action 'Review exposed virtualization capabilities' -Evidence 'A hypervisor can mean a guest VM or host security virtualization. This does not prove that nested virtualization is supported.' -State 'Review'
    }
}
if (-not $featureReadyAtEntry -and $processorQuery.Succeeded -and $osQuery.Succeeded) {
    foreach ($processor in @($processorQuery.Data)) {
        foreach ($capability in @('VirtualizationFirmwareEnabled','VMMonitorModeExtensions','SecondLevelAddressTranslationExtensions')) {
            if ($processor.PSObject.Properties[$capability] -and $processor.$capability -eq $true) {
                Add-SetupStep -Name $capability -Target ([string]$processor.DeviceID) -Action 'Check processor capability' -Evidence 'The operating system reports this capability as available.' -State 'Ready'
            }
            else { Set-SetupBlocked -Reason ('Processor capability {0} is false or unreported. Verify firmware or nested virtualization support before installation.' -f $capability) }
        }
    }
    if (@($osQuery.Data)[0].DataExecutionPrevention_Available -ne $true) { Set-SetupBlocked -Reason 'Hardware data execution prevention is false or unreported.' }
}
if (-not (Test-SetupCommand -Name 'Install-WindowsFeature' -Parameters @('Name','IncludeManagementTools'))) { Set-SetupBlocked -Reason 'The required feature installation command is unavailable.' }

if (-not $CreateSwitch -and ($SwitchName -or $NetAdapterName)) { Set-SetupBlocked -Reason 'SwitchName and NetAdapterName require -CreateSwitch.' }
if ($CreateSwitch) {
    if ([string]::IsNullOrWhiteSpace($SwitchName) -or [string]::IsNullOrWhiteSpace($NetAdapterName)) { Set-SetupBlocked -Reason 'Creating a switch requires an explicit SwitchName and NetAdapterName.' }
    if ($SwitchName -match '[\x00-\x1F*?\[\]]' -or $SwitchName.Length -gt 64 -or $NetAdapterName -match '[\x00-\x1F*?\[\]]') { Set-SetupBlocked -Reason 'Use literal, non-wildcard names for the switch and network adapter.' }
    if (-not $featureReadyAtEntry) { Set-SetupBlocked -Reason 'Install Hyper-V first, restart manually, then rerun with -CreateSwitch. Switch creation never shares the feature installation run.' }
    foreach ($commandName in @('Get-VMSwitch','New-VMSwitch','Get-NetAdapter','Get-Service')) {
        if (-not (Test-SetupCommand -Name $commandName)) { Set-SetupBlocked -Reason ('Required switch command is unavailable: ' + $commandName) }
    }
    if (Test-SetupCommand -Name 'Get-VMSwitch') {
        $switchQuery = Invoke-SetupQuery -Name 'Existing virtual switches' -Action { Get-VMSwitch -ErrorAction Stop }
        if ($switchQuery.Succeeded) { $switches = @($switchQuery.Data) }
    }
    if (Test-SetupCommand -Name 'Get-NetAdapter') {
        $adapterQuery = Invoke-SetupQuery -Name 'Exact network adapter selection' -RequireData -Action { Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Name -eq $NetAdapterName } }
        if ($adapterQuery.Succeeded -and @($adapterQuery.Data).Count -eq 1) { $adapter = @($adapterQuery.Data)[0] }
        else { Set-SetupBlocked -Reason 'The selected network adapter was not found uniquely.' }
    }
    if (Test-SetupCommand -Name 'Get-Service') {
        $vmmsQuery = Invoke-SetupQuery -Name 'Hyper-V management service' -RequireData -Action { Get-Service -Name vmms -ErrorAction Stop }
        if ($vmmsQuery.Succeeded -and @($vmmsQuery.Data)[0].Status -ne 'Running') { Set-SetupBlocked -Reason 'The Hyper-V management service is not running. Restart or investigate before creating a switch.' }
    }
    if ($adapter) {
        if ($adapter.Status -ne 'Up') { Set-SetupBlocked -Reason 'The selected network adapter must report Up.' }
        if (@($switches | Where-Object { $_.Name -eq $SwitchName }).Count) { Set-SetupBlocked -Reason 'The switch name already exists. Existing switches are not changed.' }
        if (@($switches | Where-Object { $_.SwitchType -eq 'External' -and $_.NetAdapterInterfaceDescription -eq $adapter.InterfaceDescription }).Count) { Set-SetupBlocked -Reason 'The selected adapter is already attached to an external virtual switch.' }
    }
}

if ($missingFeatures.Count -and -not $CreateSwitch) {
    Add-SetupStep -Name 'Install Hyper-V' -Target 'Local host' -Action 'Install-WindowsFeature Hyper-V with management tools and no automatic restart' -Evidence 'No VM or network switch is included.'
    $installResult = Invoke-SetupAction -Name 'Install Hyper-V' -Target 'Local host' -Action {
        $result = Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -ErrorAction Stop
        if (-not $result.Success) { throw 'Feature installation did not succeed.' }
        if ([string]$result.RestartNeeded -ne 'No') { $script:setupRestartRequired = $true }
        $result | Select-Object Success, RestartNeeded, ExitCode
    }
}
elseif ($featureReadyAtEntry) { Add-SetupStep -Name 'Hyper-V role' -Target 'Local host' -Action 'Preserve installed role' -Evidence 'Hyper-V was installed before this run.' -State 'Ready' }
if ($CreateSwitch) {
    Add-SetupStep -Name 'Create external switch' -Target $SwitchName -Action 'New-VMSwitch on the explicitly selected adapter, AllowManagementOS true' -Evidence ('Adapter: {0}. Connectivity may be interrupted; console access is recommended.' -f $NetAdapterName)
    $switchResult = Invoke-SetupAction -Name 'Create external switch' -Target $SwitchName -Action {
        New-VMSwitch -Name $SwitchName -NetAdapterName $NetAdapterName -AllowManagementOS $true -ErrorAction Stop | Select-Object Name,SwitchType,AllowManagementOS
    }
}
Complete-SetupReport -Notes @($notes)

} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
