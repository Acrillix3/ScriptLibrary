<#
What it does:
  Plan or install the File Server role, protected NTFS folders, and encrypted SMB shares from JSON.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -ConfigurationPath: Required JSON file containing up to 100 explicit shares and named access grants.

How it works:
  Validates every path, principal, existing ACL, and share before applying. Only new folders receive ACLs; existing settings must match. Required restarts need confirmation; existing ACLs are never replaced.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$Apply,
    [string]$OutputDirectory,
    [switch]$SkipRestartPrompt,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ConfigurationPath
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
function Get-FileSetupPath {
    param([string]$Value)
    if ($Value -notmatch '^[A-Za-z]:\\[^:*?"<>|]+$' -or $Value -match '[\x00-\x1f]' -or $Value -match '(?:^|\\)\.{1,2}(?:\\|$)' -or $Value.EndsWith('\') -or $Value -match '[. ](?:\\|$)' -or $Value -match '(?i)(?:^|\\)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.[^\\]*)?(?:\\|$)') { throw 'Invalid local data path.' }
    $full = [IO.Path]::GetFullPath($Value)
    if ($full -ine $Value -or $full.Length -gt 220) { throw 'Use a canonical local data path.' }
    $drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $full.Substring(0,2)) -ErrorAction Stop
    if (@($drive).Count -ne 1 -or $drive.DriveType -ne 3 -or $drive.FileSystem -ne 'NTFS') { throw 'A fixed NTFS volume is required.' }
    foreach ($reserved in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, (Join-Path $env:SystemDrive 'Users'))) {
        if ($reserved -and ($full -ieq $reserved -or $full.StartsWith($reserved.TrimEnd('\')+'\', [StringComparison]::OrdinalIgnoreCase))) { throw 'System and profile folders cannot be shared.' }
    }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'All existing path components must be ordinary folders.' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($full)) -PathType Container)) { throw 'The immediate parent folder must already exist.' }
    return $full
}
function Get-FileSetupSid {
    param([string]$Account)
    if ([string]::IsNullOrWhiteSpace($Account) -or $Account.Length -gt 256 -or $Account -match '[\x00-\x1f*?]') { throw 'Invalid account name.' }
    $sid = (New-Object Security.Principal.NTAccount($Account)).Translate([Security.Principal.SecurityIdentifier])
    if ($sid.Value -in @('S-1-1-0','S-1-5-7','S-1-5-11','S-1-5-32-545','S-1-5-32-546')) { throw 'Broad anonymous, Everyone, authenticated-user, user, and guest grants are not accepted.' }
    return $sid.Value
}
function New-FileSetupAcl {
    param([object[]]$Grants)
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    $rightsBySid = @{'S-1-5-18'='FullControl';'S-1-5-32-544'='FullControl'}
    foreach ($grant in $Grants) { $rightsBySid[$grant.Sid] = $grant.NtfsRight }
    foreach ($sidText in $rightsBySid.Keys) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, [Security.AccessControl.FileSystemRights]$rightsBySid[$sidText], [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit', [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}
function Get-FileSetupAclKey {
    param($Acl)
    $keys = @($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.IdentityReference.Value,[int64]$_.FileSystemRights,$_.AccessControlType,[int]$_.InheritanceFlags,[int]$_.PropagationFlags,$_.IsInherited
    } | Sort-Object)
    return ($keys -join ';')
}
function Test-FileSetupAcl {
    param([string]$Path,$Desired)
    $actual = Get-Acl -LiteralPath $Path -ErrorAction Stop
    return ($actual.AreAccessRulesProtected -and $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544' -and (Get-FileSetupAclKey $actual) -ceq (Get-FileSetupAclKey $Desired))
}

$filePlan = New-Object 'System.Collections.Generic.List[object]'
$fileReady = $true
$featureInstalled = $false
try {
    if (-not (Test-SetupCommand -Name 'Get-WindowsFeature') -or -not (Test-SetupCommand -Name 'Install-WindowsFeature')) { throw 'ServerManager commands are required.' }
    $feature = @(Get-WindowsFeature -Name FS-FileServer -ErrorAction Stop)
    if ($feature.Count -ne 1) { throw 'The File Server role is unavailable.' }
    $featureInstalled = [bool]$feature[0].Installed
    foreach ($command in @('Get-SmbShare','Get-SmbShareAccess','New-SmbShare')) { if (-not (Test-SetupCommand -Name $command)) { throw 'SMB management commands are required before planning shares.' } }
    $configItem = Get-Item -LiteralPath $ConfigurationPath -ErrorAction Stop
    if ($configItem.PSIsContainer -or $configItem.Length -gt 1MB) { throw 'Configuration must be a JSON file of at most 1 MB.' }
    $config = Get-Content -LiteralPath $configItem.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if (@($config.PSObject.Properties.Name | Where-Object { $_ -notin @('Shares') }).Count -gt 0 -or -not $config.Shares) { throw 'Use the documented Shares configuration schema.' }
    $shares = @($config.Shares)
    if ($shares.Count -gt 100) { throw 'At most 100 shares may be configured per run.' }
    $seenNames = @{}
    $seenPaths = New-Object 'System.Collections.Generic.List[string]'
    $allExistingShares = @(Get-SmbShare -ErrorAction Stop)
    foreach ($share in $shares) {
        if (@($share.PSObject.Properties.Name | Where-Object { $_ -notin @('Name','Path','Description','FullAccess','ChangeAccess','ReadAccess') }).Count -gt 0) { throw 'Unknown share configuration property.' }
        $name = [string]$share.Name
        if ($name -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,79}$' -or $name -in @('ADMIN','IPC','PRINT') -or $seenNames.ContainsKey($name)) { throw 'Share names must be unique simple names without administrative suffixes.' }
        $seenNames[$name] = $true
        $path = Get-FileSetupPath -Value ([string]$share.Path)
        foreach ($otherPath in $seenPaths) {
            if ($path -ieq $otherPath -or $path.StartsWith($otherPath+'\',[StringComparison]::OrdinalIgnoreCase) -or $otherPath.StartsWith($path+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Configured share paths cannot overlap.' }
        }
        $seenPaths.Add($path)
        $description = [string]$share.Description
        if ($description.Length -gt 256 -or $description -match '[\x00-\x1f]') { throw 'Descriptions must be single-line text of at most 256 characters.' }
        $grants = New-Object 'System.Collections.Generic.List[object]'
        $seenSids = @{}
        foreach ($mapping in @(@('FullAccess','Full','FullControl'),@('ChangeAccess','Change','Modify'),@('ReadAccess','Read','ReadAndExecute'))) {
            $accounts = @($share.($mapping[0]))
            foreach ($account in $accounts) {
                if ($null -eq $account) { continue }
                if ($account -isnot [string]) { throw 'Account grants must be strings.' }
                $sid = Get-FileSetupSid -Account $account
                if ($seenSids.ContainsKey($sid)) { throw 'Each principal must appear in exactly one permission level.' }
                if ($sid -in @('S-1-5-18','S-1-5-32-544') -and $mapping[1] -ne 'Full') { throw 'SYSTEM and Administrators cannot receive reduced grants.' }
                $seenSids[$sid] = $true
                $grants.Add([pscustomobject]@{Account=$account;Sid=$sid;ShareRight=$mapping[1];NtfsRight=$mapping[2]})
            }
        }
        if (@($grants | Where-Object ShareRight -eq 'Full').Count -eq 0 -or $grants.Count -gt 50) { throw 'Each share requires a FullAccess account, with at most 50 total principals.' }
        $desiredAcl = New-FileSetupAcl -Grants $grants.ToArray()
        $existing = @($allExistingShares | Where-Object Name -ieq $name)
        if ($existing.Count -gt 1) { throw 'Clustered or duplicate share scopes require manual configuration.' }
        $pathExists = Test-Path -LiteralPath $path -PathType Container
        if ($pathExists -and -not (Test-FileSetupAcl -Path $path -Desired $desiredAcl)) { throw 'An existing folder ACL differs. No existing ACL will be altered.' }
        if ($existing.Count -eq 1) {
            if (-not $pathExists -or $existing[0].Path.TrimEnd('\') -ine $path -or -not $existing[0].EncryptData -or [string]$existing[0].FolderEnumerationMode -ne 'AccessBased' -or [string]$existing[0].CachingMode -ne 'None' -or [string]$existing[0].Description -cne $description) { throw 'An existing share differs from the requested settings.' }
            $access = @(Get-SmbShareAccess -Name $name -ErrorAction Stop)
            $actualGrants = @($access | ForEach-Object {
                if ([string]$_.AccessControlType -ne 'Allow') { throw 'Existing share has a deny entry.' }
                '{0}|{1}' -f (Get-FileSetupSid -Account ([string]$_.AccountName)), $_.AccessRight
            } | Sort-Object)
            $desiredGrants = @($grants | ForEach-Object { '{0}|{1}' -f $_.Sid,$_.ShareRight } | Sort-Object)
            if (($actualGrants -join ';') -cne ($desiredGrants -join ';')) { throw 'Existing share permissions differ.' }
        } else {
            if (@($allExistingShares | Where-Object { $_.Path -and ($_.Path.TrimEnd('\') -ieq $path) -and -not $_.Special }).Count -gt 0) { throw 'Another share already publishes the requested path.' }
            if ($pathExists -and @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop | Select-Object -First 1).Count -gt 0) { throw 'New shares require a new or empty folder so descendant permissions are not assumed safe.' }
        }
        $filePlan.Add([pscustomobject]@{Name=$name;Path=$path;Description=$description;Grants=$grants.ToArray();Acl=$desiredAcl;FolderExists=$pathExists;ShareExists=($existing.Count -eq 1)})
    }
} catch { Set-SetupBlocked -Reason 'File-server preflight failed: validate the JSON schema, role tools, NTFS paths, account resolution, ACLs, and existing share settings. No setup changes were made.'; $fileReady=$false }

Add-SetupStep -Name 'File Server role' -Target 'Local server' -Action 'Install FS-FileServer with management tools, without restarting' -Evidence ('Installed={0}' -f $featureInstalled) -State $(if($featureInstalled){'AlreadyConfigured'}else{'Planned'})
foreach ($entry in $filePlan) {
    Add-SetupStep -Name 'NTFS folder' -Target $entry.Path -Action 'Create a new protected folder ACL: SYSTEM and Administrators FullControl, plus configured Full/Modify/Read grants' -Evidence ('Existing={0};RootAclOnly=True;NoExistingAclChanges=True' -f $entry.FolderExists) -State $(if($entry.FolderExists){'AlreadyConfigured'}else{'Planned'})
    Add-SetupStep -Name 'Encrypted SMB share' -Target $entry.Name -Action 'Create encrypted SMB share with access-based enumeration, offline caching disabled, and explicit share permissions' -Evidence ('Path={0};Principals={1};Existing={2}' -f $entry.Path,$entry.Grants.Count,$entry.ShareExists) -State $(if($entry.ShareExists){'AlreadyConfigured'}else{'Planned'})
}
if ($fileReady -and $setupCanApply) {
    if (-not $featureInstalled) {
        $role = Invoke-SetupAction -Name 'File Server role' -Target 'Local server' -Action { $r = Install-WindowsFeature -Name FS-FileServer -IncludeManagementTools -ErrorAction Stop; if (-not $r.Success) { throw 'Role installation failed.' }; $r }
        if (-not $role.Succeeded) { $fileReady=$false }
        elseif (@($role.Data | Where-Object { [string]$_.RestartNeeded -ne 'No' }).Count -gt 0) { $script:setupRestartRequired=$true; Set-SetupBlocked -Reason 'Restart required after File Server role installation. Restart manually, then rerun the script.'; $fileReady=$false }
    }
    foreach ($entry in $filePlan) {
        if (-not $fileReady -or -not $setupCanApply) { break }
        if (-not $entry.FolderExists) {
            $folder = Invoke-SetupAction -Name 'NTFS folder' -Target $entry.Path -Action {
                [void](Get-FileSetupPath -Value $entry.Path)
                if (Test-Path -LiteralPath $entry.Path) { throw 'Path appeared after preflight.' }
                [void](New-Item -ItemType Directory -Path $entry.Path -ErrorAction Stop)
                Set-Acl -LiteralPath $entry.Path -AclObject $entry.Acl -ErrorAction Stop
                if (-not (Test-FileSetupAcl -Path $entry.Path -Desired $entry.Acl)) { throw 'New folder ACL verification failed.' }
            }
            if (-not $folder.Succeeded) { $fileReady=$false; break }
        }
        if (-not $entry.ShareExists) {
            $published = Invoke-SetupAction -Name 'Encrypted SMB share' -Target $entry.Name -Action {
                [void](Get-FileSetupPath -Value $entry.Path)
                if (-not (Test-FileSetupAcl -Path $entry.Path -Desired $entry.Acl)) { throw 'Folder permissions changed after preflight.' }
                $splat = @{Name=$entry.Name;Path=$entry.Path;Description=$entry.Description;EncryptData=$true;FolderEnumerationMode='AccessBased';CachingMode='None';FullAccess=@($entry.Grants | Where-Object ShareRight -eq 'Full' | ForEach-Object Account);ErrorAction='Stop';Confirm=$false}
                $change = @($entry.Grants | Where-Object ShareRight -eq 'Change' | ForEach-Object Account)
                $read = @($entry.Grants | Where-Object ShareRight -eq 'Read' | ForEach-Object Account)
                if ($change.Count) { $splat.ChangeAccess=$change }
                if ($read.Count) { $splat.ReadAccess=$read }
                New-SmbShare @splat | Select-Object Name,Path,EncryptData,FolderEnumerationMode,CachingMode
            }
            if (-not $published.Succeeded) { $fileReady=$false; break }
        }
    }
}
Complete-SetupReport -Notes @('Run locally on Windows Server 2022 or 2025. Plans never alter roles, folders, or shares.','Only new folders receive ACLs; existing matching root ACLs are inspected and existing descendant ACLs are never rewritten.','New shares require empty folders. Existing shares are accepted only when root ACL, settings, and share grants match.','SMB encryption and access-based enumeration are enabled for new shares; offline caching is disabled. SMB firewall policy is not broadened.','No SMB1, guest access, automatic restart, or recursive permission replacement is enabled. A partially completed run can leave secured folders or role installation in place; review the report before rerunning.')

} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
