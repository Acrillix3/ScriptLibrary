<#
What it does:
  Plans or installs the local DHCP role and optionally creates one IPv4 scope with safe options and explicit AD authorization.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -ScopeName, -StartRange, -EndRange, and -SubnetMask: Supply together for one scope.
  -RouterIPAddress: Optional scope gateway addresses.
  -DnsServerIPAddress and -DnsDomain: Optional scope DNS addresses and suffix.
  -ActivateScope: Explicitly activate the scope after successful configuration; new scopes default Inactive.
  -AuthorizeInAD: Explicitly add this server to AD DHCP authorization.
  -AuthorizationIPAddress: Required with AuthorizeInAD; must match a local preferred static IPv4 address.

How it works:
  Stages the role on a first Apply. A second run verifies existing scopes, subnet overlap, options, and requested AD authorization before making changes. Conflicting existing settings block all changes. Creates an inactive scope, fills missing options, then optionally activates it. Never changes existing ranges or restarts the service.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$Apply,
    [string]$OutputDirectory,
    [switch]$SkipRestartPrompt,
    [string]$ScopeName,
    [string]$StartRange,
    [string]$EndRange,
    [string]$SubnetMask,
    [string[]]$RouterIPAddress=@(),
    [string[]]$DnsServerIPAddress=@(),
    [string]$DnsDomain,
    [switch]$ActivateScope,
    [switch]$AuthorizeInAD,
    [string]$AuthorizationIPAddress
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
$identityNotes=@('Only the local DHCP server is configured. New scopes start Inactive. Existing scope ranges, masks, names, options, and authorizations are never replaced. No service restart is initiated; the shared setup runner asks separately before any required server restart.')
function ConvertTo-IdentityIPv4Number {
    param([string]$Value)
    $parsed=$null
    if ($Value -notmatch '^\d{1,3}(?:\.\d{1,3}){3}$' -or -not [System.Net.IPAddress]::TryParse($Value,[ref]$parsed) -or [string]$parsed -cne $Value -or $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }
    $bytes=$parsed.GetAddressBytes()
    return ([uint64]$bytes[0]*16777216+[uint64]$bytes[1]*65536+[uint64]$bytes[2]*256+[uint64]$bytes[3])
}
function ConvertFrom-IdentityIPv4Number {
    param([uint64]$Value)
    return ('{0}.{1}.{2}.{3}' -f (($Value -shr 24) -band 255),(($Value -shr 16) -band 255),(($Value -shr 8) -band 255),($Value -band 255))
}
function Test-IdentityUnicastIPv4 {
    param([string]$Value)
    $number=ConvertTo-IdentityIPv4Number $Value
    if ($null -eq $number) { return $false }
    $first=$number -shr 24
    return ($first -gt 0 -and $first -lt 224 -and $first -ne 127 -and ($number -band 4294901760) -ne 2851995648)
}
$scopeInputs=@($ScopeName,$StartRange,$EndRange,$SubnetMask | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$wantsScope=$scopeInputs.Count -gt 0
$validScope=$false
$scopeId=$null
$networkNumber=$null
$broadcastNumber=$null
if ($wantsScope -and $scopeInputs.Count -ne 4) { Set-SetupBlocked -Reason 'ScopeName, StartRange, EndRange, and SubnetMask must be supplied together.' }
if ($ScopeName -and ($ScopeName.Length -gt 128 -or $ScopeName -match '[\r\n\x00]')) { Set-SetupBlocked -Reason 'ScopeName must be a nonempty single-line name of at most 128 characters.' }
if (-not $wantsScope -and (@($RouterIPAddress).Count -gt 0 -or @($DnsServerIPAddress).Count -gt 0 -or $DnsDomain -or $ActivateScope)) { Set-SetupBlocked -Reason 'Scope options and ActivateScope require a complete scope definition.' }
if (@($RouterIPAddress).Count -gt 8 -or @($DnsServerIPAddress).Count -gt 8) { Set-SetupBlocked -Reason 'At most eight router and eight DNS addresses can be supplied.' }
foreach ($address in @($RouterIPAddress)+@($DnsServerIPAddress)) { if (-not (Test-IdentityUnicastIPv4 $address)) { Set-SetupBlocked -Reason 'Router and DNS options require unicast IPv4 addresses.' } }
if ($DnsDomain -and ($DnsDomain.Length -gt 253 -or $DnsDomain -notmatch '^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')) { Set-SetupBlocked -Reason 'DnsDomain must be a valid DNS name with at least two labels.' }
if ($scopeInputs.Count -eq 4) {
    $startNumber=ConvertTo-IdentityIPv4Number $StartRange
    $endNumber=ConvertTo-IdentityIPv4Number $EndRange
    $maskNumber=ConvertTo-IdentityIPv4Number $SubnetMask
    $maskBits=''
    if ($null -ne $maskNumber) { foreach ($part in ($SubnetMask -split '\.')) { $maskBits += [Convert]::ToString([int]$part,2).PadLeft(8,'0') } }
    if (-not (Test-IdentityUnicastIPv4 $StartRange) -or -not (Test-IdentityUnicastIPv4 $EndRange) -or $maskBits -notmatch '^1{1,30}0{2,31}$') { Set-SetupBlocked -Reason 'The range must contain unicast IPv4 addresses and a contiguous subnet mask with at least two host bits.' }
    else {
        $networkNumber=$startNumber -band $maskNumber
        $broadcastNumber=$networkNumber+(4294967295-$maskNumber)
        $scopeId=ConvertFrom-IdentityIPv4Number $networkNumber
        $validScope=$startNumber -le $endNumber -and $startNumber -gt $networkNumber -and $endNumber -lt $broadcastNumber -and ($endNumber -band $maskNumber) -eq $networkNumber
        if (-not $validScope) { Set-SetupBlocked -Reason 'The lease range must be ordered, remain in one subnet, and exclude network and broadcast addresses.' }
        foreach ($router in @($RouterIPAddress)) {
            $routerNumber=ConvertTo-IdentityIPv4Number $router
            if ($null -ne $routerNumber -and ($routerNumber -le $networkNumber -or $routerNumber -ge $broadcastNumber)) { Set-SetupBlocked -Reason 'Each router must be a host address in the requested scope subnet.' }
            if ($null -ne $routerNumber -and $routerNumber -ge $startNumber -and $routerNumber -le $endNumber) { Set-SetupBlocked -Reason 'The lease range includes a router address. Choose a range that excludes infrastructure addresses.' }
        }
        foreach ($dnsAddress in @($DnsServerIPAddress)) { $dnsNumber=ConvertTo-IdentityIPv4Number $dnsAddress; if ($null -ne $dnsNumber -and $dnsNumber -ge $startNumber -and $dnsNumber -le $endNumber) { Set-SetupBlocked -Reason 'The lease range includes a DNS server address. Choose a range that excludes infrastructure addresses.' } }
    }
}
if ($AuthorizeInAD -and -not (Test-IdentityUnicastIPv4 $AuthorizationIPAddress)) { Set-SetupBlocked -Reason 'AuthorizeInAD requires an explicit unicast AuthorizationIPAddress belonging to this server.' }
if (-not $AuthorizeInAD -and $AuthorizationIPAddress) { Set-SetupBlocked -Reason 'AuthorizationIPAddress is accepted only with AuthorizeInAD.' }
$feature=Invoke-SetupQuery -Name 'Inspect DHCP role' -RequireData -Action { Get-WindowsFeature -Name DHCP -ErrorAction Stop }
if (-not $feature.Succeeded) { Set-SetupBlocked -Reason 'DHCP role state could not be verified.' }
$roleInstalled=$feature.Succeeded -and [bool]@($feature.Data)[0].Installed
$authorizationName=$null
$needsAuthorization=$false
if ($AuthorizeInAD) {
    $computer=Invoke-SetupQuery -Name 'Inspect domain authorization prerequisites' -RequireData -Action { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
    $addresses=Invoke-SetupQuery -Name 'Inspect static DHCP server addresses' -Action { Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { [string]$_.PrefixOrigin -eq 'Manual' -and [string]$_.AddressState -eq 'Preferred' } | Select-Object -ExpandProperty IPAddress }
    if (-not $computer.Succeeded -or -not @($computer.Data)[0].PartOfDomain -or [string]::IsNullOrWhiteSpace([string]@($computer.Data)[0].DNSHostName)) { Set-SetupBlocked -Reason 'AD authorization requires a verified domain-joined local server with a DNS host name.' }
    else { $authorizationName=([string]@($computer.Data)[0].DNSHostName)+'.'+([string]@($computer.Data)[0].Domain) }
    if (-not $addresses.Succeeded -or $AuthorizationIPAddress -notin @($addresses.Data)) { Set-SetupBlocked -Reason 'AuthorizationIPAddress must match a verified preferred static IPv4 address of this server.' }
}
if (-not $roleInstalled) {
    Add-SetupStep -Name 'Install DHCP role' -Target 'DHCP' -Action 'Install role and management tools without restarting' -Evidence 'Scope, option, and AD authorization changes are deferred to a second run.'
    $identityNotes += 'After role installation, rerun with the same scope and authorization parameters. Review DHCP post-installation tasks and service state before activating a scope.'
    if ($wantsScope) { Add-SetupStep -Name 'Deferred DHCP scope configuration' -Target $(if ($scopeId) { $scopeId } else { $ScopeName }) -Action 'Inspect then configure on a second run' -Evidence 'DHCP role must be installed before existing scopes and options can be checked.' -State 'Deferred' }
    if ($AuthorizeInAD) { Add-SetupStep -Name 'Deferred DHCP authorization' -Target $authorizationName -Action 'Inspect then authorize on a second run' -Evidence 'DHCP role must be installed before AD authorization commands are available.' -State 'Deferred' }
} else { Add-SetupStep -Name 'DHCP role already installed' -Target 'DHCP' -Action 'Preserve installed feature' -Evidence 'Existing role detected.' -State 'AlreadyConfigured' }
$existingScope=$null
$missingOptions=@()
$needsActivation=$false
if ($roleInstalled -and $validScope) {
    foreach ($command in @('Get-DhcpServerv4Scope','Add-DhcpServerv4Scope','Get-DhcpServerv4OptionValue','Set-DhcpServerv4OptionValue')) { if (-not (Test-SetupCommand -Name $command)) { Set-SetupBlocked -Reason ('Required DHCP command unavailable: '+$command) } }
    if ($ActivateScope -and -not (Test-SetupCommand -Name Set-DhcpServerv4Scope)) { Set-SetupBlocked -Reason 'Scope activation command is unavailable.' }
    $scopes=Invoke-SetupQuery -Name 'Inspect existing DHCP scopes' -Action { Get-DhcpServerv4Scope -ErrorAction Stop }
    if (-not $scopes.Succeeded) { Set-SetupBlocked -Reason 'Existing DHCP scopes could not be inspected.' }
    else {
        foreach ($otherScope in @($scopes.Data)) {
            if ([string]$otherScope.ScopeId -eq $scopeId) { $existingScope=$otherScope; continue }
            $otherId=ConvertTo-IdentityIPv4Number ([string]$otherScope.ScopeId)
            $otherMask=ConvertTo-IdentityIPv4Number ([string]$otherScope.SubnetMask)
            if ($null -eq $otherId -or $null -eq $otherMask) { Set-SetupBlocked -Reason 'An existing scope has unrecognized address metadata; subnet overlap cannot be excluded.' }
            elseif ($networkNumber -le ($otherId+4294967295-$otherMask) -and $broadcastNumber -ge $otherId) { Set-SetupBlocked -Reason 'The requested subnet overlaps an existing DHCP scope.' }
        }
        if ($existingScope) {
            if ([string]$existingScope.StartRange -ne $StartRange -or [string]$existingScope.EndRange -ne $EndRange -or [string]$existingScope.SubnetMask -ne $SubnetMask -or [string]$existingScope.Name -cne $ScopeName) { Set-SetupBlocked -Reason 'The existing scope differs in name, range, or mask. Existing scopes are preserved.' }
            Add-SetupStep -Name 'Existing DHCP scope' -Target $scopeId -Action 'Preserve scope definition' -Evidence ('Current state={0}; the default never deactivates an existing scope.' -f $existingScope.State) -State 'AlreadyConfigured'
            if ($ActivateScope -and [string]$existingScope.State -eq 'InActive') { $needsActivation=$true }
            elseif ([string]$existingScope.State -notin @('Active','InActive')) { Set-SetupBlocked -Reason 'The existing DHCP scope state is unrecognized.' }
        } else {
            Add-SetupStep -Name 'Create DHCP scope' -Target $scopeId -Action 'Create scope in Inactive state' -Evidence ('{0}: {1} through {2}; mask {3}' -f $ScopeName,$StartRange,$EndRange,$SubnetMask)
            $needsActivation=[bool]$ActivateScope
        }
        $desiredOptions=@()
        if (@($RouterIPAddress).Count -gt 0) { $desiredOptions += [pscustomobject]@{Id=3; Values=@($RouterIPAddress)} }
        if (@($DnsServerIPAddress).Count -gt 0) { $desiredOptions += [pscustomobject]@{Id=6; Values=@($DnsServerIPAddress)} }
        if ($DnsDomain) { $desiredOptions += [pscustomobject]@{Id=15; Values=@($DnsDomain)} }
        $currentOptions=@()
        if ($existingScope -and $desiredOptions.Count -gt 0) {
            $options=Invoke-SetupQuery -Name 'Inspect existing scope options' -Action { Get-DhcpServerv4OptionValue -ScopeId ([System.Net.IPAddress]$scopeId) -ErrorAction Stop }
            if (-not $options.Succeeded) { Set-SetupBlocked -Reason 'Existing scope options could not be inspected.' }
            else { $currentOptions=@($options.Data) }
        }
        foreach ($option in $desiredOptions) {
            $matching=@($currentOptions | Where-Object { [int]$_.OptionId -eq $option.Id })
            if ($matching.Count -eq 0) {
                $missingOptions += $option
                Add-SetupStep -Name 'Set missing DHCP scope option' -Target ($scopeId+' / '+$option.Id) -Action 'Create scope-level option' -Evidence ('Values='+($option.Values -join ', '))
            } else {
                $actual=@($matching[0].Value | ForEach-Object { [string]$_ }) -join '|'
                $expected=@($option.Values | ForEach-Object { [string]$_ }) -join '|'
                if ($matching.Count -ne 1 -or $actual -ine $expected) { Set-SetupBlocked -Reason ('Existing scope option {0} differs from the request and will not be replaced.' -f $option.Id) }
            }
        }
        if ($needsActivation) { Add-SetupStep -Name 'Activate DHCP scope' -Target $scopeId -Action 'Explicitly activate scope after options are configured' -Evidence 'Requested by ActivateScope; this allows the server to offer addresses to clients.' }
    }
}
if ($roleInstalled -and $AuthorizeInAD -and $authorizationName) {
    if (-not (Test-SetupCommand -Name Get-DhcpServerInDC) -or -not (Test-SetupCommand -Name Add-DhcpServerInDC)) { Set-SetupBlocked -Reason 'AD authorization commands are unavailable.' }
    $authorized=Invoke-SetupQuery -Name 'Inspect AD DHCP authorization' -Action { Get-DhcpServerInDC -ErrorAction Stop }
    if (-not $authorized.Succeeded) { Set-SetupBlocked -Reason 'Existing AD DHCP authorizations could not be inspected.' }
    else {
        $matching=@($authorized.Data | Where-Object { [string]$_.DnsName -ieq $authorizationName -or [string]$_.IPAddress -eq $AuthorizationIPAddress })
        if ($matching.Count -eq 0) { $needsAuthorization=$true; Add-SetupStep -Name 'Authorize DHCP in AD' -Target $authorizationName -Action 'Add explicit AD authorization' -Evidence ('Authorized address='+$AuthorizationIPAddress) }
        elseif (@($matching | Where-Object { [string]$_.DnsName -ine $authorizationName -or [string]$_.IPAddress -ne $AuthorizationIPAddress }).Count -gt 0) { Set-SetupBlocked -Reason 'A requested DHCP authorization name or address conflicts with an existing AD entry.' }
        else { Add-SetupStep -Name 'AD authorization already present' -Target $authorizationName -Action 'Preserve authorization' -Evidence 'The DNS name and static IPv4 address match.' -State 'AlreadyConfigured' }
    }
}
if ($setupCanApply -and -not $roleInstalled) {
    $installed=Invoke-SetupAction -Name 'Install DHCP role' -Target 'DHCP' -Action {
        $result=Install-WindowsFeature -Name DHCP -IncludeManagementTools -Restart:$false -ErrorAction Stop
        if (-not $result.Success) { throw 'DHCP role installation did not report success.' }
        if ([string]$result.RestartNeeded -eq 'Yes') { $script:setupRestartRequired=$true }
        [pscustomobject]@{ Success=$true; RestartNeeded=[string]$result.RestartNeeded }
    }
}
if ($setupCanApply -and $roleInstalled) {
    $proceed=$true
    if ($needsAuthorization) {
        $authResult=Invoke-SetupAction -Name 'Authorize DHCP in AD' -Target $authorizationName -Action {
            Add-DhcpServerInDC -DnsName $authorizationName -IPAddress ([System.Net.IPAddress]$AuthorizationIPAddress) -ErrorAction Stop | Out-Null
            $verified=@(Get-DhcpServerInDC -ErrorAction Stop | Where-Object { [string]$_.DnsName -ieq $authorizationName -and [string]$_.IPAddress -eq $AuthorizationIPAddress })
            if ($verified.Count -ne 1) { throw 'DHCP AD authorization could not be verified.' }
            [pscustomobject]@{ Authorized=$true; DnsName=$authorizationName }
        }
        if (-not $authResult.Succeeded) { $proceed=$false }
    }
    if ($proceed -and $validScope -and -not $existingScope -and $setupCanApply) {
        $created=Invoke-SetupAction -Name 'Create DHCP scope' -Target $scopeId -Action {
            Add-DhcpServerv4Scope -Name $ScopeName -StartRange ([System.Net.IPAddress]$StartRange) -EndRange ([System.Net.IPAddress]$EndRange) -SubnetMask ([System.Net.IPAddress]$SubnetMask) -State InActive -ErrorAction Stop | Out-Null
            $verified=Get-DhcpServerv4Scope -ScopeId ([System.Net.IPAddress]$scopeId) -ErrorAction Stop
            if ([string]$verified.State -ne 'InActive') { throw 'The new DHCP scope was not verified as Inactive.' }
            [pscustomobject]@{ ScopeId=$scopeId; State='InActive' }
        }
        if (-not $created.Succeeded) { $proceed=$false }
    }
    foreach ($option in $missingOptions) {
        if (-not $proceed -or -not $setupCanApply) { break }
        $configured=Invoke-SetupAction -Name 'Set missing DHCP scope option' -Target ($scopeId+' / '+$option.Id) -Action {
            Set-DhcpServerv4OptionValue -ScopeId ([System.Net.IPAddress]$scopeId) -OptionId ([uint32]$option.Id) -Value ([string[]]$option.Values) -ErrorAction Stop | Out-Null
            $verified=@(Get-DhcpServerv4OptionValue -ScopeId ([System.Net.IPAddress]$scopeId) -ErrorAction Stop | Where-Object { [int]$_.OptionId -eq $option.Id })
            if ($verified.Count -ne 1 -or (@($verified[0].Value | ForEach-Object { [string]$_ }) -join '|') -ine (@($option.Values | ForEach-Object { [string]$_ }) -join '|')) { throw 'The requested DHCP scope option could not be verified.' }
            [pscustomobject]@{ ScopeId=$scopeId; OptionId=$option.Id }
        }
        if (-not $configured.Succeeded) { $proceed=$false }
    }
    if ($proceed -and $needsActivation -and $setupCanApply) {
        $activated=Invoke-SetupAction -Name 'Activate DHCP scope' -Target $scopeId -Action {
            Set-DhcpServerv4Scope -ScopeId ([System.Net.IPAddress]$scopeId) -State Active -ErrorAction Stop | Out-Null
            $verified=Get-DhcpServerv4Scope -ScopeId ([System.Net.IPAddress]$scopeId) -ErrorAction Stop
            if ([string]$verified.State -ne 'Active') { throw 'DHCP scope activation could not be verified.' }
            [pscustomobject]@{ ScopeId=$scopeId; State='Active' }
        }
    }
}
Complete-SetupReport -Notes $identityNotes

} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
