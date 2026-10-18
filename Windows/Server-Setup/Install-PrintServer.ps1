<#
What it does:
  Plan or install the Print Server role and optional controlled TCP/IP printer queues from JSON.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -ConfigurationPath: Optional JSON file with queues, exact preinstalled x64 drivers, IPv4 endpoints, and named PrintUsers; omit for role-only installation.

How it works:
  Validates all drivers, ports, queue settings, and printer permissions first. Creates RAW TCP ports and queues with explicit permissions. Existing objects must match; no drivers are downloaded or security policies relaxed.
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
function Get-PrintSetupSddl {
    param([object[]]$Accounts)
    if ($Accounts.Count -lt 1 -or $Accounts.Count -gt 50) { throw 'Specify 1 through 50 named print principals.' }
    $sidSet = @{}
    foreach ($account in $Accounts) {
        if ($account -isnot [string] -or [string]::IsNullOrWhiteSpace($account) -or $account.Length -gt 256 -or $account -match '[\x00-\x1f*?]') { throw 'Invalid print account name.' }
        $sid = (New-Object Security.Principal.NTAccount($account)).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -in @('S-1-1-0','S-1-5-7','S-1-5-11','S-1-5-32-545','S-1-5-32-546')) { throw 'Use named authorized print groups, not broad or guest grants.' }
        if ($sidSet.ContainsKey($sid)) { throw 'Duplicate print principal.' }
        $sidSet[$sid] = $true
    }
    $sddl = 'O:BAG:SYD:P(A;;0x000F000C;;;SY)(A;;0x000F000C;;;BA)'
    foreach ($sid in @($sidSet.Keys | Sort-Object)) {
        if ($sid -notin @('S-1-5-18','S-1-5-32-544')) { $sddl += '(A;;0x00020008;;;'+$sid+')' }
    }
    return $sddl
}
function Get-PrintSetupDaclKey {
    param([string]$Sddl)
    $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    if (-not $descriptor.DiscretionaryAcl) { throw 'A printer must have an explicit nonempty DACL.' }
    $keys = @($descriptor.DiscretionaryAcl | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.AceType,[int]$_.AceFlags,$_.AccessMask,$_.SecurityIdentifier.Value } | Sort-Object)
    return ($keys -join ';')
}

$printReady=$true
$printRoleInstalled=$false
$printPlan = New-Object 'System.Collections.Generic.List[object]'
try {
    if (-not (Test-SetupCommand -Name 'Get-WindowsFeature') -or -not (Test-SetupCommand -Name 'Install-WindowsFeature')) { throw 'ServerManager commands are required.' }
    $feature = @(Get-WindowsFeature -Name Print-Server -ErrorAction Stop)
    if ($feature.Count -ne 1) { throw 'The Print Server role is unavailable.' }
    $printRoleInstalled=[bool]$feature[0].Installed
    if ($ConfigurationPath) {
        foreach ($command in @('Get-Printer','Get-PrinterDriver','Get-PrinterPort','Add-Printer','Add-PrinterPort')) { if (-not (Test-SetupCommand -Name $command)) { throw 'Install the role first, then rerun with queue configuration.' } }
        $service = Get-Service -Name Spooler -ErrorAction Stop
        if ([string]$service.Status -ne 'Running') { throw 'The print spooler must already be running for configuration preflight.' }
        $configItem = Get-Item -LiteralPath $ConfigurationPath -ErrorAction Stop
        if ($configItem.PSIsContainer -or $configItem.Length -gt 1MB) { throw 'Configuration must be a JSON file of at most 1 MB.' }
        $config = Get-Content -LiteralPath $configItem.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if (@($config.PSObject.Properties.Name | Where-Object { $_ -notin @('Printers') }).Count -gt 0 -or -not $config.Printers) { throw 'Use the documented Printers schema.' }
        $printers = @($config.Printers)
        if ($printers.Count -gt 100) { throw 'At most 100 queues may be configured per run.' }
        $drivers = @(Get-PrinterDriver -ErrorAction Stop)
        $ports = @(Get-PrinterPort -ErrorAction Stop)
        $queues = @(Get-Printer -Full -ErrorAction Stop)
        $seenNames=@{}; $seenShares=@{}; $seenPorts=@{}
        foreach ($printer in $printers) {
            if (@($printer.PSObject.Properties.Name | Where-Object { $_ -notin @('Name','DriverName','Address','PortNumber','Shared','ShareName','Location','Comment','PrintUsers') }).Count -gt 0) { throw 'Unknown printer configuration property.' }
            $name=[string]$printer.Name
            if ($name -notmatch '^[A-Za-z][A-Za-z0-9 _-]{0,79}$' -or $name.EndsWith(' ') -or $seenNames.ContainsKey($name)) { throw 'Queue names must be unique simple names.' }
            $seenNames[$name]=$true
            if ($printer.DriverName -isnot [string] -or [string]::IsNullOrWhiteSpace($printer.DriverName) -or $printer.DriverName -match '[\x00-\x1f*?]') { throw 'Specify an exact installed driver name.' }
            $driver=@($drivers | Where-Object { $_.Name -ceq $printer.DriverName -and $_.PrinterEnvironment -eq 'Windows x64' })
            if ($driver.Count -ne 1) { throw 'The exact trusted Windows x64 driver must already be installed.' }
            $address=[string]$printer.Address
            $ip=$null
            if (-not [Net.IPAddress]::TryParse($address,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -cne $address -or $address -match '^(0|127|169\.254|22[4-9]|23[0-9]|24[0-9]|25[0-5])\.' -or $address -eq '255.255.255.255') { throw 'Use a canonical unicast IPv4 printer address.' }
            $portNumber=9100
            if ($null -ne $printer.PortNumber) {
                if ($printer.PortNumber -isnot [int] -and $printer.PortNumber -isnot [long]) { throw 'PortNumber must be an integer.' }
                $portNumber=[int]$printer.PortNumber
            }
            if ($portNumber -lt 1 -or $portNumber -gt 65535) { throw 'PortNumber is out of range.' }
            $portName='TCP_'+$address+'_'+$portNumber
            $shared=$false
            if ($null -ne $printer.Shared) { if ($printer.Shared -isnot [bool]) { throw 'Shared must be a JSON boolean.' }; $shared=$printer.Shared }
            $shareName=[string]$printer.ShareName
            if ($shared) {
                if ($shareName -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,79}$' -or $seenShares.ContainsKey($shareName)) { throw 'Shared queues require a unique simple ShareName.' }
                $seenShares[$shareName]=$true
                if (@($queues | Where-Object { $_.Shared -and $_.ShareName -ieq $shareName -and $_.Name -ine $name }).Count) { throw 'The printer share name is already used.' }
            } elseif ($shareName) { throw 'ShareName is only accepted when Shared is true.' }
            foreach ($field in @('Location','Comment')) { if (([string]$printer.$field).Length -gt 256 -or [string]$printer.$field -match '[\x00-\x1f]') { throw 'Queue notes must be single-line text of at most 256 characters.' } }
            $sddl=Get-PrintSetupSddl -Accounts @($printer.PrintUsers)
            $existingPort=@($ports | Where-Object Name -ieq $portName)
            if ($existingPort.Count -gt 1) { throw 'Duplicate existing port names.' }
            if ($existingPort.Count -and ($existingPort[0].PrinterHostAddress -cne $address -or $existingPort[0].PortNumber -ne $portNumber -or $existingPort[0].Protocol -ne 1 -or $existingPort[0].SNMPEnabled -isnot [bool] -or $existingPort[0].SNMPEnabled)) { throw 'An existing port differs from the requested RAW TCP settings.' }
            $existingQueue=@($queues | Where-Object Name -ieq $name)
            if ($existingQueue.Count -gt 1) { throw 'Duplicate existing queue names.' }
            if ($existingQueue.Count) {
                $queue=$existingQueue[0]
                if ($queue.DriverName -cne $printer.DriverName -or $queue.PortName -cne $portName -or [bool]$queue.Shared -ne $shared -or ($shared -and $queue.ShareName -cne $shareName) -or [string]$queue.Location -cne [string]$printer.Location -or [string]$queue.Comment -cne [string]$printer.Comment -or $queue.Published -or $queue.KeepPrintedJobs -or (Get-PrintSetupDaclKey -Sddl $queue.PermissionSDDL) -cne (Get-PrintSetupDaclKey -Sddl $sddl)) { throw 'An existing queue or its permissions differ from the requested settings.' }
            }
            $portAlreadyPlanned=$seenPorts.ContainsKey($portName)
            $seenPorts[$portName]=$true
            $printPlan.Add([pscustomobject]@{Name=$name;DriverName=[string]$printer.DriverName;Address=$address;PortNumber=$portNumber;PortName=$portName;Shared=$shared;ShareName=$shareName;Location=[string]$printer.Location;Comment=[string]$printer.Comment;Sddl=$sddl;PortExists=($existingPort.Count -gt 0);PortAlreadyPlanned=$portAlreadyPlanned;QueueExists=($existingQueue.Count -gt 0)})
        }
    }
} catch { Set-SetupBlocked -Reason 'Print-server preflight failed: inspect the JSON schema, running spooler, role tools, exact installed x64 drivers, IPv4 endpoints, existing ports, queue names, and permissions. No setup changes were made.'; $printReady=$false }

Add-SetupStep -Name 'Print Server role' -Target 'Local server' -Action 'Install Print-Server with management tools, without restarting' -Evidence ('Installed={0};QueueConfigurationProvided={1}' -f $printRoleInstalled,[bool]$ConfigurationPath) -State $(if($printRoleInstalled){'AlreadyConfigured'}else{'Planned'})
foreach ($entry in $printPlan) {
    if (-not $entry.PortAlreadyPlanned) { Add-SetupStep -Name 'RAW TCP printer port' -Target $entry.PortName -Action 'Create standard TCP/IP RAW port with SNMP polling disabled' -Evidence ('Address={0};Port={1}' -f $entry.Address,$entry.PortNumber) -State $(if($entry.PortExists){'AlreadyConfigured'}else{'Planned'}) }
    Add-SetupStep -Name 'Printer queue' -Target $entry.Name -Action 'Create queue with installed driver and explicit printer DACL; retain no completed jobs and do not publish in AD' -Evidence ('Driver={0};Shared={1};ShareName={2}' -f $entry.DriverName,$entry.Shared,$entry.ShareName) -State $(if($entry.QueueExists){'AlreadyConfigured'}else{'Planned'})
}
if ($printReady -and $setupCanApply) {
    if (-not $printRoleInstalled) {
        $role=Invoke-SetupAction -Name 'Print Server role' -Target 'Local server' -Action { $r=Install-WindowsFeature -Name Print-Server -IncludeManagementTools -ErrorAction Stop; if(-not $r.Success){throw 'Role installation failed.'};$r }
        if(-not $role.Succeeded){$printReady=$false}
        elseif(@($role.Data | Where-Object {[string]$_.RestartNeeded -ne 'No'}).Count){$script:setupRestartRequired=$true;Set-SetupBlocked -Reason 'Restart required after Print Server role installation. Restart manually, then rerun.';$printReady=$false}
    }
    foreach ($entry in $printPlan) {
        if(-not $printReady -or -not $setupCanApply){break}
        if(-not $entry.PortExists -and -not $entry.PortAlreadyPlanned){
            $port=Invoke-SetupAction -Name 'RAW TCP printer port' -Target $entry.PortName -Action {
                Add-PrinterPort -Name $entry.PortName -PrinterHostAddress $entry.Address -PortNumber $entry.PortNumber -ErrorAction Stop | Out-Null
                $observed=@(Get-PrinterPort -ErrorAction Stop | Where-Object Name -ieq $entry.PortName)
                if($observed.Count -ne 1 -or $observed[0].PrinterHostAddress -cne $entry.Address -or $observed[0].PortNumber -ne $entry.PortNumber -or $observed[0].Protocol -ne 1 -or $observed[0].SNMPEnabled -isnot [bool] -or $observed[0].SNMPEnabled){throw 'Created port verification failed.'}
                $observed | Select-Object Name,PrinterHostAddress,PortNumber
            }
            if(-not $port.Succeeded){$printReady=$false;break}
        }
        if(-not $entry.QueueExists){
            $queue=Invoke-SetupAction -Name 'Printer queue' -Target $entry.Name -Action {
                $splat=@{Name=$entry.Name;DriverName=$entry.DriverName;PortName=$entry.PortName;Shared=$entry.Shared;PermissionSDDL=$entry.Sddl;Location=$entry.Location;Comment=$entry.Comment;ErrorAction='Stop';Confirm=$false}
                if($entry.Shared){$splat.ShareName=$entry.ShareName}
                Add-Printer @splat | Out-Null
                $observed=@(Get-Printer -Full -ErrorAction Stop | Where-Object Name -ieq $entry.Name)
                if($observed.Count -ne 1 -or $observed[0].DriverName -cne $entry.DriverName -or $observed[0].PortName -cne $entry.PortName -or [bool]$observed[0].Shared -ne $entry.Shared -or ($entry.Shared -and $observed[0].ShareName -cne $entry.ShareName) -or (Get-PrintSetupDaclKey -Sddl $observed[0].PermissionSDDL) -cne (Get-PrintSetupDaclKey -Sddl $entry.Sddl)){throw 'Created queue verification failed.'}
                $observed | Select-Object Name,DriverName,PortName,Shared,ShareName
            }
            if(-not $queue.Succeeded){$printReady=$false;break}
        }
    }
}
Complete-SetupReport -Notes @('Run locally on Windows Server 2022 or 2025. Omit ConfigurationPath to install only the role/tools.','For new servers: install the role, manually stage approved signed x64 drivers, then rerun with the queue JSON.','The script creates standard RAW TCP/IP ports and explicit printer DACLs; it never downloads drivers or changes Point and Print security.','Only named PrintUsers receive basic print permission. Administrators and SYSTEM receive printer administration rights. Queues are not published in AD and completed jobs are not retained.','Existing queues and ports must match; no queue replacement, job deletion, spooler restart, test-page printing, or automatic reboot is performed. Firewall policy remains an administrator decision.')

} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
