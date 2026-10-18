<#
What it does:
  Checks SQL preparation baselines and creates new protected data, log, tempdb and backup directories.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -SqlVersion: SQL preparation target, 2022 or 2025; default 2022.
  -DataPath: Required dedicated data directory with an existing parent.
  -LogPath: Required separate transaction-log directory with an existing parent.
  -TempDbPath: Required separate tempdb directory with an existing parent.
  -BackupPath: Required separate backup directory with an existing parent.
  -MinimumMemoryGB: Editable memory baseline; default 4 GB.
  -MinimumFreeGB: Editable free-space baseline per selected volume; default 10 GB.

How it works:
  Validates the member server, .NET, memory, local volumes, paths and existing ACLs before Apply. New directories get protected SYSTEM/Administrators permissions. Does not install SQL, accept licenses, grant service-account rights, download software or open ports.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$Apply,
    [string]$OutputDirectory,
    [switch]$SkipRestartPrompt,
    [ValidateSet('2022','2025')][string]$SqlVersion='2022',
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$DataPath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$LogPath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$TempDbPath,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$BackupPath,
    [ValidateRange(1,1048576)][int]$MinimumMemoryGB=4,
    [ValidateRange(1,1048576)][int]$MinimumFreeGB=10
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
if($setupHost.DomainRole -in @(4,5)){Set-SetupBlocked 'Prepare a dedicated member server for SQL Server. This tool does not prepare SQL Server on a domain controller.'}
$paths=@($DataPath,$LogPath,$TempDbPath,$BackupPath)
$normalized=New-Object 'System.Collections.Generic.List[string]'
foreach($path in $paths){
    if($path -notmatch '^[A-Za-z]:\\' -or $path -match '[*?\r\n]' -or $path.Length -lt 4){Set-SetupBlocked 'SQL directories must be explicit local absolute paths below a drive root.';continue}
    $full=[IO.Path]::GetFullPath($path).TrimEnd('\')
    if($full -match '(?i)^[A-Z]:\\(?:Windows|Program Files(?: \(x86\))?|ProgramData|Users)(?:\\|$)'){Set-SetupBlocked 'SQL preparation directories must not be system, application, profile, or ProgramData folders.'}
    $normalized.Add($full)
}
for($first=0;$first -lt $normalized.Count;$first++){for($second=$first+1;$second -lt $normalized.Count;$second++){
    if($normalized[$first] -ieq $normalized[$second] -or $normalized[$first].StartsWith($normalized[$second]+'\',[StringComparison]::OrdinalIgnoreCase) -or $normalized[$second].StartsWith($normalized[$first]+'\',[StringComparison]::OrdinalIgnoreCase)){Set-SetupBlocked 'Data, log, tempdb and backup paths must be distinct, non-nested directories.'}
}}
$framework=Invoke-SetupQuery -Name 'NetFrameworkRelease' -RequireData -Action {Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction Stop | Select-Object Release}
if($framework.Succeeded -and [int64]$framework.Data[0].Release -lt 461808){Set-SetupBlocked '.NET Framework 4.7.2 or newer is required. Install a supported framework through your normal OS maintenance process.'}
$memory=Invoke-SetupQuery -Name 'SqlMemoryBaseline' -RequireData -Action {Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop | Select-Object TotalPhysicalMemory}
if($memory.Succeeded){
    if($null -eq $memory.Data[0].TotalPhysicalMemory -or [double]$memory.Data[0].TotalPhysicalMemory -lt ($MinimumMemoryGB*1GB)){Set-SetupBlocked 'Physical memory is missing or below the selected SQL preparation baseline.'}
}
$volumes=Invoke-SetupQuery -Name 'SqlFixedVolumes' -RequireData -Action {Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop}
$create=New-Object 'System.Collections.Generic.List[string]'
foreach($path in $normalized){
    $drive=[IO.Path]::GetPathRoot($path).TrimEnd('\')
    $disk=@($volumes.Data | Where-Object DeviceID -eq $drive)
    if($disk.Count -ne 1 -or $disk[0].FileSystem -notin @('NTFS','ReFS') -or $null -eq $disk[0].FreeSpace -or [double]$disk[0].FreeSpace -lt ($MinimumFreeGB*1GB)){Set-SetupBlocked ('A fixed NTFS/ReFS volume with sufficient free space was not established for '+$path+'.')}
    $parent=Split-Path $path -Parent
    if(-not (Test-Path -LiteralPath $parent -PathType Container)){Set-SetupBlocked ('Create and review the parent directory first: '+$parent+'.')}
    $ancestor=$path
    while($ancestor){
        if(Test-Path -LiteralPath $ancestor){
            $item=Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){Set-SetupBlocked ('Reparse points are not allowed in SQL preparation paths: '+$ancestor+'.')}
        }
        $next=Split-Path $ancestor -Parent
        if($next -eq $ancestor){break}
        $ancestor=$next
    }
    if(Test-Path -LiteralPath $path){
        if(-not (Test-Path -LiteralPath $path -PathType Container)){Set-SetupBlocked ('A non-directory exists at '+$path+'.');continue}
        $aclQuery=Invoke-SetupQuery -Name ('ExistingSqlDirectoryAcl:'+ $path) -RequireData -Action {Get-Acl -LiteralPath $path -ErrorAction Stop}
        if($aclQuery.Succeeded){
            $acl=$aclQuery.Data[0];$rules=@($acl.Access)
            $safe=$acl.AreAccessRulesProtected -and $rules.Count -eq 2 -and $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544'
            $identities=New-Object 'System.Collections.Generic.List[string]'
            foreach($rule in $rules){
                try{$sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value}catch{$sid='Unknown'}
                $identities.Add($sid)
                if($sid -notin @('S-1-5-18','S-1-5-32-544') -or [string]$rule.FileSystemRights -ne 'FullControl' -or [string]$rule.AccessControlType -ne 'Allow' -or [string]$rule.InheritanceFlags -ne 'ContainerInherit, ObjectInherit' -or [string]$rule.PropagationFlags -ne 'None'){$safe=$false}
            }
            if(@($identities | Select-Object -Unique).Count -ne 2){$safe=$false}
            if(-not $safe){Set-SetupBlocked ('Existing SQL path permissions differ from the new-directory baseline; they will not be replaced: '+$path+'.')}
        }
        Add-SetupStep -Name 'Prepare SQL directory' -Target $path -Action Create -Evidence 'Existing directory is inspected; only a matching protected SYSTEM/Administrators baseline is accepted.' -State AlreadyConfigured
    }else{
        $create.Add($path)
        Add-SetupStep -Name 'Prepare SQL directory' -Target $path -Action Create -Evidence 'Creates a new protected folder granting FullControl only to SYSTEM and built-in Administrators. SQL Setup must later grant the selected SQL service identity access.'
    }
}
Add-SetupStep -Name 'SQL installation handoff' -Target ('SQL Server '+$SqlVersion) -Action Review -Evidence 'Prerequisites only: no installer, edition selection, license acceptance, service installation, database configuration, downloads, firewall changes, or service-account rights changes.' -State AlreadyConfigured
if(-not $setupBlocked){foreach($path in $create){
    $null=Invoke-SetupAction -Name 'Prepare SQL directory' -Target $path -Action {
        if(Test-Path -LiteralPath $path){throw 'SQL directory appeared after preflight. Its existing permissions will not be changed.'}
        $ancestor=Split-Path $path -Parent
        while($ancestor){
            $item=Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
            if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'SQL path ancestry changed after preflight.'}
            $next=Split-Path $ancestor -Parent
            if($next -eq $ancestor){break}
            $ancestor=$next
        }
        $security=New-Object Security.AccessControl.DirectorySecurity
        $security.SetAccessRuleProtection($true,$false)
        foreach($sidText in @('S-1-5-18','S-1-5-32-544')){
            $sid=New-Object Security.Principal.SecurityIdentifier($sidText)
            $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit, ObjectInherit','None','Allow')
            $security.AddAccessRule($rule)
        }
        $security.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        $null=[IO.Directory]::CreateDirectory($path,$security)
        $observed=Get-Acl -LiteralPath $path -ErrorAction Stop
        $rules=@($observed.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        $verified=$observed.AreAccessRulesProtected -and $observed.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544' -and $rules.Count -eq 2
        $seen=@{}
        foreach($rule in $rules){
            $sid=$rule.IdentityReference.Value
            if($seen.ContainsKey($sid) -or $sid -notin @('S-1-5-18','S-1-5-32-544') -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or [int]$rule.InheritanceFlags -ne 3 -or [int]$rule.PropagationFlags -ne 0 -or $rule.IsInherited){$verified=$false}
            $seen[$sid]=$true
        }
        if(-not $verified){throw 'Created SQL directory security differs from the required protected baseline. No existing ACL was replaced.'}
    }
}}
Complete-SetupReport -Notes @(
    'Prepares new SQL Server 2022/2025 hosts only. Does not install SQL, SSMS, client drivers, cumulative updates or .NET, accept a license, enable mixed authentication, or open firewall ports.'
    'Memory and free-space thresholds are editable preparation baselines, not workload sizing. Validate SQL edition/OS support, CPU capacity, sector size, allocation units, storage performance, backup isolation, service accounts and installer prerequisites separately.'
    'No existing directory ACL is replaced. The SQL installer or a separately reviewed permission step must grant the SQL service identity access. Separate paths do not prove separate physical disks or resilient backup storage.'
)

} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
