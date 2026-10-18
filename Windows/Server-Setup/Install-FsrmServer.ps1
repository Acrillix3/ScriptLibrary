<#
What it does:
  Plan or install File Server Resource Manager and optional folder quotas from JSON.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -ConfigurationPath: Optional quota JSON file; omit for role-only installation. Soft quotas are the default; explicit hard quotas require empty new targets.

How it works:
  Validates existing NTFS folders and quota conflicts before applying. Creates quotas without templates or actions. Existing quotas must match, overlapping policies are blocked, and required restarts need confirmation.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$Apply,
    [string]$OutputDirectory,
    [switch]$SkipRestartPrompt,
    [string]$ConfigurationPath
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
function Get-FsrmSetupPath {
    param([string]$Value)
    if ($Value -notmatch '^[A-Za-z]:\\[^:*?"<>|]+$' -or $Value -match '[\x00-\x1f]' -or $Value -match '(?:^|\\)\.{1,2}(?:\\|$)' -or $Value.EndsWith('\') -or $Value -match '[. ](?:\\|$)' -or $Value.Length -gt 220 -or $Value -match '(?i)(?:^|\\)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.[^\\]*)?(?:\\|$)') { throw 'Use a canonical local folder path.' }
    $full=[IO.Path]::GetFullPath($Value)
    if($full -ine $Value){throw 'Use a canonical local folder path.'}
    $drive=Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $full.Substring(0,2)) -ErrorAction Stop
    if(@($drive).Count -ne 1 -or $drive.DriveType -ne 3 -or $drive.FileSystem -ne 'NTFS'){throw 'FSRM requires a fixed NTFS volume.'}
    foreach($reserved in @($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramData,(Join-Path $env:SystemDrive 'Users'))){
        if($reserved -and ($full -ieq $reserved -or $full.StartsWith($reserved.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase))){throw 'System and profile folders cannot be quota targets.'}
    }
    $cursor=$full
    while($cursor){
        $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Quota targets and all ancestors must be existing ordinary folders.'}
        $parent=[IO.Path]::GetDirectoryName($cursor)
        if($parent -eq $cursor){break}
        $cursor=$parent
    }
    return $full
}
function Test-FsrmSetupOverlap {
    param([string]$First,[string]$Second)
    $a=$First.TrimEnd('\');$b=$Second.TrimEnd('\')
    return ($a -ieq $b -or $a.StartsWith($b+'\',[StringComparison]::OrdinalIgnoreCase) -or $b.StartsWith($a+'\',[StringComparison]::OrdinalIgnoreCase))
}

$fsrmReady=$true
$fsrmRoleInstalled=$false
$fsrmPlan=New-Object 'System.Collections.Generic.List[object]'
try{
    if(-not (Test-SetupCommand -Name 'Get-WindowsFeature') -or -not (Test-SetupCommand -Name 'Install-WindowsFeature')){throw 'ServerManager commands are required.'}
    $feature=@(Get-WindowsFeature -Name FS-Resource-Manager -ErrorAction Stop)
    if($feature.Count -ne 1){throw 'The FSRM role is unavailable.'}
    $fsrmRoleInstalled=[bool]$feature[0].Installed
    if($ConfigurationPath){
        foreach($command in @('Get-FsrmQuota','Get-FsrmAutoQuota','New-FsrmQuota')){if(-not (Test-SetupCommand -Name $command)){throw 'Install the FSRM role first, then rerun with quota configuration.'}}
        $configItem=Get-Item -LiteralPath $ConfigurationPath -ErrorAction Stop
        if($configItem.PSIsContainer -or $configItem.Length -gt 1MB){throw 'Configuration must be a JSON file of at most 1 MB.'}
        $config=Get-Content -LiteralPath $configItem.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if(@($config.PSObject.Properties.Name | Where-Object {$_ -notin @('Quotas')}).Count -gt 0 -or -not $config.Quotas){throw 'Use the documented Quotas schema.'}
        $quotas=@($config.Quotas)
        if($quotas.Count -gt 100){throw 'At most 100 quotas may be configured per run.'}
        $existingQuotas=@(Get-FsrmQuota -ErrorAction Stop)
        $existingAutoQuotas=@(Get-FsrmAutoQuota -ErrorAction Stop)
        foreach($quota in $quotas){
            if(@($quota.PSObject.Properties.Name | Where-Object {$_ -notin @('Path','SizeGB','SoftLimit','Description')}).Count -gt 0){throw 'Unknown quota configuration property.'}
            $path=Get-FsrmSetupPath -Value ([string]$quota.Path)
            if($quota.SizeGB -isnot [int] -and $quota.SizeGB -isnot [long]){throw 'SizeGB must be an integer.'}
            if($quota.SizeGB -lt 1 -or $quota.SizeGB -gt 1048576){throw 'SizeGB must be between 1 and 1048576.'}
            $size=[uint64]$quota.SizeGB * [uint64]1GB
            $soft=$true
            if($null -ne $quota.SoftLimit){if($quota.SoftLimit -isnot [bool]){throw 'SoftLimit must be a JSON boolean.'};$soft=$quota.SoftLimit}
            $description=[string]$quota.Description
            if($description.Length -gt 256 -or $description -match '[\x00-\x1f]'){throw 'Descriptions must be single-line text of at most 256 characters.'}
            foreach($entry in $fsrmPlan){if(Test-FsrmSetupOverlap -First $path -Second $entry.Path){throw 'Configured quota paths cannot overlap.'}}
            $existing=@($existingQuotas | Where-Object {$_.Path.TrimEnd('\') -ieq $path})
            if($existing.Count -gt 1){throw 'Multiple quota objects match the requested path.'}
            if($existing.Count){
                $current=$existing[0]
                if([uint64]$current.Size -ne $size -or [bool]$current.SoftLimit -ne $soft -or $current.Disabled -or [string]$current.Description -cne $description -or $current.Template -or @($current.Threshold | Where-Object {$null -ne $_}).Count){throw 'An existing quota differs, uses a template, or has threshold actions.'}
            }else{
                if(@($existingQuotas | Where-Object {Test-FsrmSetupOverlap -First $path -Second $_.Path}).Count){throw 'A new quota cannot overlap an existing quota.'}
                if(-not $soft -and @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop | Select-Object -First 1).Count){throw 'New hard quotas require empty folders to avoid blocking writes to existing data.'}
            }
            if(@($existingAutoQuotas | Where-Object {Test-FsrmSetupOverlap -First $path -Second $_.Path}).Count){throw 'The requested path overlaps an automatic quota rule.'}
            $fsrmPlan.Add([pscustomobject]@{Path=$path;Size=$size;SizeGB=[long]$quota.SizeGB;SoftLimit=$soft;Description=$description;Exists=($existing.Count -gt 0)})
        }
    }
}catch{Set-SetupBlocked -Reason 'FSRM preflight failed: inspect the JSON schema, role tools, existing NTFS folders, quota conflicts, and hard-quota empty-folder requirement. No setup changes were made.';$fsrmReady=$false}

Add-SetupStep -Name 'FSRM role' -Target 'Local server' -Action 'Install FS-Resource-Manager with management tools, without restarting' -Evidence ('Installed={0};QuotaConfigurationProvided={1}' -f $fsrmRoleInstalled,[bool]$ConfigurationPath) -State $(if($fsrmRoleInstalled){'AlreadyConfigured'}else{'Planned'})
foreach($entry in $fsrmPlan){Add-SetupStep -Name 'Folder quota' -Target $entry.Path -Action 'Create explicit FSRM quota without templates, thresholds, or custom actions' -Evidence ('SizeGB={0};SoftLimit={1};HardQuotaRequiresEmptyNewTarget=True' -f $entry.SizeGB,$entry.SoftLimit) -State $(if($entry.Exists){'AlreadyConfigured'}else{'Planned'})}
if($fsrmReady -and $setupCanApply){
    if(-not $fsrmRoleInstalled){
        $role=Invoke-SetupAction -Name 'FSRM role' -Target 'Local server' -Action {$r=Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools -ErrorAction Stop;if(-not $r.Success){throw 'Role installation failed.'};$r}
        if(-not $role.Succeeded){$fsrmReady=$false}
        elseif(@($role.Data | Where-Object {[string]$_.RestartNeeded -ne 'No'}).Count){$script:setupRestartRequired=$true;Set-SetupBlocked -Reason 'Restart required after FSRM role installation. Restart manually, then rerun.';$fsrmReady=$false}
    }
    foreach($entry in $fsrmPlan){
        if(-not $fsrmReady -or -not $setupCanApply){break}
        if(-not $entry.Exists){
            $created=Invoke-SetupAction -Name 'Folder quota' -Target $entry.Path -Action {
                [void](Get-FsrmSetupPath -Value $entry.Path)
                if(-not $entry.SoftLimit -and @(Get-ChildItem -LiteralPath $entry.Path -Force -ErrorAction Stop | Select-Object -First 1).Count){throw 'Hard quota target gained data after preflight.'}
                $overlap=@(Get-FsrmQuota -ErrorAction Stop | Where-Object {Test-FsrmSetupOverlap -First $entry.Path -Second $_.Path})
                $auto=@(Get-FsrmAutoQuota -ErrorAction Stop | Where-Object {Test-FsrmSetupOverlap -First $entry.Path -Second $_.Path})
                if($overlap.Count -or $auto.Count){throw 'Quota configuration changed after preflight.'}
                $splat=@{Path=$entry.Path;Size=$entry.Size;Description=$entry.Description;ErrorAction='Stop';Confirm=$false}
                if($entry.SoftLimit){$splat.SoftLimit=$true}
                New-FsrmQuota @splat | Out-Null
                $observed=@(Get-FsrmQuota -ErrorAction Stop | Where-Object {$_.Path.TrimEnd('\') -ieq $entry.Path})
                if($observed.Count -ne 1 -or [uint64]$observed[0].Size -ne $entry.Size -or [bool]$observed[0].SoftLimit -ne $entry.SoftLimit -or $observed[0].Disabled){throw 'Created quota verification failed.'}
                $observed | Select-Object Path,Size,SoftLimit,Disabled
            }
            if(-not $created.Succeeded){$fsrmReady=$false;break}
        }
    }
}
Complete-SetupReport -Notes @('Run locally on Windows Server 2022 or 2025. Omit ConfigurationPath to install only the role/tools; rerun with JSON after creating the target folders.','Only NTFS volumes are supported. Existing quota objects must match exactly; no quotas, templates, or automatic quota rules are overwritten.','Soft quotas are the default and report usage without enforcing the size limit. Hard quotas require explicit SoftLimit=false and an empty target when creating a new quota.','Quota folders must already exist. The script creates no file screens, file-classification rules, email actions, command actions, or automatic restart.')

} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
