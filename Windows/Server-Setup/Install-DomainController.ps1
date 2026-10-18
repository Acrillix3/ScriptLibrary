<#
What it does:
  Plans or stages AD DS and, when explicitly requested, promotes this server into a new forest or an existing domain.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -DomainName: Required DNS domain name.
  -Mode: NewForest (default) or AdditionalDC.
  -Promote: Enable promotion after the AD DS role has been staged.
  -DomainNetbiosName: Optional new-forest NetBIOS name.
  -InstallDns: Boolean; defaults to true.
  -SiteName and -ReplicationSourceDC: Optional additional-controller placement and source FQDN.
  -SafeModeAdministratorPassword: SecureString required for Apply with Promote.
  -Credential: PSCredential required for Apply with AdditionalDC and Promote.

How it works:
  Inspects membership, role state, and static IPv4 networking. Apply without Promote stages the role first. New forests use explicit 2016 domain and forest functional levels for 2022/2025 DC compatibility. Promotion requires successful native AD DS prerequisite tests, retains built-in checks, and suppresses automatic reboot; restart promptly after promotion.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$Apply,
    [string]$OutputDirectory,
    [switch]$SkipRestartPrompt,
    [Parameter(Mandatory=$true)][string]$DomainName,
    [ValidateSet('NewForest','AdditionalDC')][string]$Mode='NewForest',
    [switch]$Promote,
    [string]$DomainNetbiosName,
    [bool]$InstallDns=$true,
    [string]$SiteName,
    [string]$ReplicationSourceDC,
    [Security.SecureString]$SafeModeAdministratorPassword,
    [pscredential]$Credential
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
$identityNotes = @('Run locally on the intended server. Promotion suppresses its automatic reboot and leaves the server awaiting a controlled restart; restart promptly before using it as a domain controller. The shared setup runner asks separately before restarting.')
if ($Mode -eq 'NewForest') { $identityNotes += 'New forests explicitly use Windows Server 2016 domain and forest functional levels so both Windows Server 2022 and 2025 domain controllers are supported. Existing forest or domain levels are never changed.' }
if ([string]::IsNullOrWhiteSpace($DomainName) -or $DomainName.Length -gt 253 -or $DomainName -notmatch '^(?=.{3,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') {
    Set-SetupBlocked -Reason 'Supply a valid DNS domain name with at least two labels.'
}
if ($DomainNetbiosName -and ($Mode -ne 'NewForest' -or $DomainNetbiosName -notmatch '^[A-Za-z][A-Za-z0-9-]{0,14}$')) {
    Set-SetupBlocked -Reason 'DomainNetbiosName is supported only for a new forest and must be a valid name of 1 through 15 characters.'
}
if ($Mode -eq 'NewForest' -and ($DomainName -split '\.')[0].Length -gt 15 -and -not $DomainNetbiosName) { Set-SetupBlocked -Reason 'A domain first label longer than 15 characters requires an explicit DomainNetbiosName.' }
if ($Mode -eq 'NewForest' -and ($SiteName -or $ReplicationSourceDC)) { Set-SetupBlocked -Reason 'SiteName and ReplicationSourceDC apply only to an additional domain controller.' }
if ($ReplicationSourceDC -and $ReplicationSourceDC -notmatch '^(?:[A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z0-9][A-Za-z0-9-]*$') { Set-SetupBlocked -Reason 'ReplicationSourceDC must be a DNS fully qualified name.' }
$machine = Invoke-SetupQuery -Name 'Inspect local domain membership' -RequireData -Action { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
$features = Invoke-SetupQuery -Name 'Inspect AD DS role' -RequireData -Action { Get-WindowsFeature -Name AD-Domain-Services -ErrorAction Stop }
$alreadyDc = $false
if ($machine.Succeeded) {
    $system = @($machine.Data)[0]
    $alreadyDc = [int]$system.DomainRole -in @(4,5)
    Add-SetupStep -Name 'Inspect domain role' -Target $env:COMPUTERNAME -Action 'Read current domain role and membership' -Evidence ('Domain={0}; DomainRole={1}; PartOfDomain={2}' -f $system.Domain,$system.DomainRole,$system.PartOfDomain) -State 'AlreadyConfigured'
    if ($alreadyDc) {
        if ([string]$system.Domain -ine $DomainName) { Set-SetupBlocked -Reason 'This server is already a domain controller for a different domain.' }
        Add-SetupStep -Name 'Domain controller already present' -Target $DomainName -Action 'Preserve existing domain controller' -Evidence 'No promotion or demotion is attempted.' -State 'AlreadyConfigured'
    } elseif ($Mode -eq 'NewForest' -and $system.PartOfDomain) { Set-SetupBlocked -Reason 'NewForest requires a workgroup server. Existing domain membership is preserved.' }
    elseif ($Mode -eq 'AdditionalDC' -and $system.PartOfDomain -and [string]$system.Domain -ine $DomainName) { Set-SetupBlocked -Reason 'This server is joined to a different domain; it will not be moved automatically.' }
} else { Set-SetupBlocked -Reason 'Local domain role could not be verified.' }
if (-not $features.Succeeded) { Set-SetupBlocked -Reason 'AD DS role state could not be verified.' }
$roleInstalled = $features.Succeeded -and [bool]@($features.Data)[0].Installed
if (-not $roleInstalled) {
    Add-SetupStep -Name 'Install AD DS binaries' -Target 'AD-Domain-Services' -Action 'Install role and management tools without restarting' -Evidence 'Role staging only; rerun with Promote after inspecting prerequisites.'
}
if (-not $alreadyDc -and $Promote) {
    Add-SetupStep -Name 'Run AD DS prerequisite tests' -Target $DomainName -Action ('Test {0} installation' -f $Mode) -Evidence 'Requires installed AD DS management commands and a secure DSRM password. A failed or unrecognized result prevents promotion.'
    Add-SetupStep -Name 'Promote local server' -Target $DomainName -Action ('Promote as {0}; InstallDns={1}; no automatic restart' -f $Mode,$InstallDns) -Evidence 'AD DS retains its own prerequisite checks; no SkipPreChecks or forced controller reinstall.'
    if (-not $roleInstalled) { Set-SetupBlocked -Reason 'Stage the AD DS role first without Promote, then rerun with Promote so prerequisites can be tested before any promotion.' }
    $network = Invoke-SetupQuery -Name 'Inspect static IPv4 configuration' -Action { Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and [string]$_.PrefixOrigin -eq 'Manual' -and [string]$_.AddressState -eq 'Preferred' } }
    if (-not $network.Succeeded -or @($network.Data).Count -eq 0) { Set-SetupBlocked -Reason 'Promotion requires a verified preferred static IPv4 address. Configure and validate networking first.' }
    $testCommand = if ($Mode -eq 'NewForest') { 'Test-ADDSForestInstallation' } else { 'Test-ADDSDomainControllerInstallation' }
    $installCommand = if ($Mode -eq 'NewForest') { 'Install-ADDSForest' } else { 'Install-ADDSDomainController' }
    if (-not (Test-SetupCommand -Name $testCommand) -or -not (Test-SetupCommand -Name $installCommand)) { Set-SetupBlocked -Reason 'The required AD DS deployment commands are unavailable.' }
    if ($setupCanApply -and -not $WhatIfPreference) {
        if (-not $SafeModeAdministratorPassword -or $SafeModeAdministratorPassword.Length -eq 0) { Set-SetupBlocked -Reason 'Apply with Promote requires a nonempty SecureString SafeModeAdministratorPassword; no plaintext password or interactive prompt is used.' }
        if ($Mode -eq 'AdditionalDC' -and -not $Credential) { Set-SetupBlocked -Reason 'Apply for an additional controller requires an explicit PSCredential with deployment permissions.' }
    }
    if ($setupCanApply -and -not $WhatIfPreference) {
        $promotionParameters = @{ DomainName=$DomainName; SafeModeAdministratorPassword=$SafeModeAdministratorPassword; InstallDns=[bool]$InstallDns; CreateDnsDelegation=$false; NoRebootOnCompletion=$true; ErrorAction='Stop' }
        if ($Mode -eq 'NewForest') { $promotionParameters.DomainMode='WinThreshold'; $promotionParameters.ForestMode='WinThreshold' }
        if ($Mode -eq 'NewForest' -and $DomainNetbiosName) { $promotionParameters.DomainNetbiosName=$DomainNetbiosName }
        if ($Mode -eq 'AdditionalDC') {
            $promotionParameters.Credential=$Credential
            if ($SiteName) { $promotionParameters.SiteName=$SiteName }
            if ($ReplicationSourceDC) { $promotionParameters.ReplicationSourceDC=$ReplicationSourceDC }
        }
        $precheck = Invoke-SetupQuery -Name 'Run AD DS prerequisites' -Action { & $testCommand @promotionParameters -WarningAction SilentlyContinue }
        $testRows = @($precheck.Data)
        $passed = $precheck.Succeeded -and $testRows.Count -gt 0
        foreach ($row in $testRows) { if (-not $row.PSObject.Properties['Status'] -or [string]$row.Status -ne 'Success') { $passed=$false } }
        if (-not $passed) { Set-SetupBlocked -Reason 'AD DS prerequisite tests did not return explicit Success. Review the DirectoryServices-Deployment event log before retrying.' }
        if ($setupCanApply -and $passed) {
            $promotion = Invoke-SetupAction -Name 'Promote local server' -Target $DomainName -Action {
                $result = & $installCommand @promotionParameters -Confirm:$false -WarningAction SilentlyContinue
                $script:setupRestartRequired=$true
                if (-not $result -or [string]$result.Status -ne 'Success') { throw 'AD DS deployment did not report explicit Success.' }
                [pscustomobject]@{ Status='Success'; RestartRequired=$true }
            }
        }
    } else { $identityNotes += 'Promotion prerequisites are deferred until Apply with Promote and secure password parameters. WhatIf does not run promotion prerequisites or prompt for passwords.' }
} elseif (-not $alreadyDc) { $identityNotes += 'Use Promote explicitly to enable promotion. Without it, Apply installs only the AD DS role and management tools.' }
if ($setupCanApply -and -not $roleInstalled -and -not $Promote) {
    $install = Invoke-SetupAction -Name 'Install AD DS binaries' -Target 'AD-Domain-Services' -Action {
        $result=Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Restart:$false -ErrorAction Stop
        if (-not $result.Success) { throw 'Role installation did not report success.' }
        if ([string]$result.RestartNeeded -eq 'Yes') { $script:setupRestartRequired=$true }
        [pscustomobject]@{ Success=[bool]$result.Success; RestartNeeded=[string]$result.RestartNeeded }
    }
}
Complete-SetupReport -Notes $identityNotes

} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
