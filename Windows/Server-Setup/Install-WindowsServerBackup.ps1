<#
What it does:
  Plans or installs Windows Server Backup and optionally creates a new scheduled local-volume policy.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -ConfigurationPath: Optional JSON policy; omit to install the feature only. Existing scheduled policies are never replaced.

How it works:
  Uses two passes for a new server: install tools, then validate explicit source/target volumes and daily times. Apply creates a VSS-copy schedule without formatting storage or starting an immediate backup.
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
$feature=Invoke-SetupQuery -Name 'WindowsBackupFeature' -RequireData -Action {Get-WindowsFeature -Name Windows-Server-Backup -ErrorAction Stop}
$installed=$feature.Succeeded -and $feature.Data.Count -eq 1 -and $feature.Data[0].Installed -eq $true
Add-SetupStep -Name 'Install Windows Server Backup' -Target Windows-Server-Backup -Action Install -Evidence 'Installs the Windows backup role tools without automatic restart.' -State $(if($installed){'AlreadyConfigured'}else{'Planned'})
$configuration=$null;$sourceObjects=@();$schedule=@()
if($ConfigurationPath){
    if(-not $installed -or -not (Test-SetupCommand Get-WBPolicy)){Set-SetupBlocked 'Install the backup feature first without ConfigurationPath, then rerun with a configuration.'}
    $configRead=Invoke-SetupQuery -Name 'BackupConfiguration' -RequireData -Action {Get-Content -LiteralPath $ConfigurationPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop}
    if($configRead.Succeeded -and $configRead.Data.Count -eq 1){
        $configuration=$configRead.Data[0]
        $allowed=@('SchemaVersion','SourceVolumes','TargetVolume','DailySchedule','IncludeSystemState','IncludeBareMetal','MinimumTargetFreeGB')
        if(@($configuration.PSObject.Properties.Name | Where-Object {$_ -notin $allowed}).Count -or $configuration.SchemaVersion -ne 1){Set-SetupBlocked 'Unsupported or misspelled backup configuration fields/schema.'}
        $sources=@($configuration.SourceVolumes)
        $times=@($configuration.DailySchedule)
        if($sources.Count -lt 1 -or $sources.Count -gt 16 -or @($sources | Select-Object -Unique).Count -ne $sources.Count){Set-SetupBlocked 'Choose 1-16 unique source volume drive letters.'}
        foreach($volume in @($sources)+@($configuration.TargetVolume)){if($volume -isnot [string] -or $volume -notmatch '^[A-Za-z]:$'){Set-SetupBlocked 'Source and target volumes must be drive-letter roots such as D:.'}}
        if($configuration.TargetVolume -in $sources -or $configuration.TargetVolume -ieq $env:SystemDrive){Set-SetupBlocked 'Backup target cannot be a source volume or the Windows system volume.'}
        if($configuration.IncludeSystemState -isnot [bool] -or $configuration.IncludeBareMetal -isnot [bool]){Set-SetupBlocked 'IncludeSystemState and IncludeBareMetal must be JSON booleans.'}
        if($times.Count -lt 1 -or $times.Count -gt 8 -or @($times | Select-Object -Unique).Count -ne $times.Count){Set-SetupBlocked 'Choose 1-8 unique daily times in HH:mm format.'}
        foreach($time in $times){
            $parsedTime=[datetime]::MinValue
            if($time -isnot [string] -or -not [datetime]::TryParseExact($time,'HH:mm',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsedTime)){Set-SetupBlocked 'DailySchedule contains an invalid HH:mm time.'}else{$schedule+=([datetime]::Today.Add($parsedTime.TimeOfDay))}
        }
        $minimum=0.0
        if(-not [double]::TryParse([string]$configuration.MinimumTargetFreeGB,[ref]$minimum) -or $minimum -lt 1 -or $minimum -gt 1048576){Set-SetupBlocked 'MinimumTargetFreeGB must be a positive baseline between 1 and 1048576.'}
        $disks=Invoke-SetupQuery -Name 'BackupVolumes' -RequireData -Action {Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop}
        foreach($volume in @($sources)+@($configuration.TargetVolume)){
            $match=@($disks.Data | Where-Object DeviceID -eq $volume)
            if($match.Count -ne 1 -or $match[0].FileSystem -notin @('NTFS','ReFS')){Set-SetupBlocked ('A fixed NTFS/ReFS source or target volume was not established: '+$volume+'.')}
            if($volume -ieq $configuration.TargetVolume -and ($null -eq $match[0].FreeSpace -or [double]$match[0].FreeSpace -lt ($minimum*1GB))){Set-SetupBlocked 'The backup target is below the selected free-space baseline.'}
        }
        if($installed){
            $existing=Invoke-SetupQuery -Name 'ExistingScheduledBackupPolicy' -Action {Get-WBPolicy -ErrorAction Stop | Where-Object {$null -ne $_}}
            if($existing.Data.Count){Set-SetupBlocked 'A scheduled Windows backup policy already exists. It will not be overwritten, disabled, or edited by this setup script.'}
            $volumes=Invoke-SetupQuery -Name 'BackupSourceVolumeObjects' -RequireData -Action {foreach($volume in $sources){Get-WBVolume -VolumePath $volume -WhatIf:$false -Confirm:$false -ErrorAction Stop}}
            $sourceObjects=@($volumes.Data)
            if($sourceObjects.Count -ne $sources.Count){Set-SetupBlocked 'Not every requested source volume could be mapped to a Windows backup volume object.'}
        }
        Add-SetupStep -Name 'Create scheduled backup policy' -Target ([string]$configuration.TargetVolume) -Action Configure -Evidence ('Creates a new VSS-copy policy for '+($sources -join ', ')+' at '+($times -join ', ')+'. Scheduled execution can begin at the next selected local time; no immediate backup starts.')
    }else{Set-SetupBlocked 'Backup configuration must contain one JSON object.'}
}
if(-not $setupBlocked){
    if(-not $installed){$null=Invoke-SetupAction -Name 'Install Windows Server Backup' -Target Windows-Server-Backup -Action {Install-WindowsFeature -Name Windows-Server-Backup -IncludeManagementTools -Restart:$false -ErrorAction Stop}}
    if($configuration){
        $null=Invoke-SetupAction -Name 'Create scheduled backup policy' -Target ([string]$configuration.TargetVolume) -Action {
            $existingPolicy=Get-WBPolicy -ErrorAction Stop
            if($null -ne $existingPolicy){throw 'A scheduled backup policy appeared after preflight; it will not be overwritten.'}
            $policy=New-WBPolicy -ErrorAction Stop
            Add-WBVolume -Policy $policy -Volume $sourceObjects -ErrorAction Stop
            $target=New-WBBackupTarget -VolumePath $configuration.TargetVolume -ErrorAction Stop
            Add-WBBackupTarget -Policy $policy -Target $target -ErrorAction Stop
            if($configuration.IncludeSystemState){Add-WBSystemState -Policy $policy -ErrorAction Stop}
            if($configuration.IncludeBareMetal){Add-WBBareMetalRecovery -Policy $policy -ErrorAction Stop}
            Set-WBVssBackupOptions -Policy $policy -VssCopyBackup -ErrorAction Stop
            Set-WBSchedule -Policy $policy -Schedule $schedule -ErrorAction Stop
            $existingPolicy=Get-WBPolicy -ErrorAction Stop
            if($null -ne $existingPolicy){throw 'A scheduled backup policy appeared while preparing this policy; it will not be overwritten.'}
            Set-WBPolicy -Policy $policy -Force -ErrorAction Stop
        }
    }
}
Complete-SetupReport -Notes @(
    'Installs the backup feature or creates one new local-volume scheduled policy. No disks are formatted, dedicated, resized or cleared, and no immediate backup is launched.'
    'Existing scheduled backup policies are refused rather than edited. Rerun without ConfigurationPath to inspect/install the role, or manage an existing policy through a separate reviewed workflow.'
    'Use storage isolated from the protected server and test recovery separately. A different drive letter does not prove a separate disk or disaster resilience; this script does not claim backup success or recoverability.'
)

} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
