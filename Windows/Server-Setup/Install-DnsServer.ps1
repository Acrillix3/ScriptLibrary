<#
What it does:
  Plans or installs the local DNS role and safely adds optional primary zones and forwarders.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -ForwardZoneName: Optional new forward lookup zone DNS name.
  -ReverseNetworkId: Optional canonical IPv4 /8, /16, or /24 network.
  -ZoneStorage: File (default) or ActiveDirectory; AD storage requires a domain controller.
  -ForwarderIPAddress: Optional IPv4 forwarders to append; existing entries are preserved.

How it works:
  Installs the role on a first Apply, then uses a second run to inspect existing zones and forwarders before configuration. File zones disable dynamic updates; AD zones allow secure updates with domain replication. Conflicting zones and forwarding to this server are blocked.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$Apply,
    [string]$OutputDirectory,
    [switch]$SkipRestartPrompt,
    [string]$ForwardZoneName,
    [string]$ReverseNetworkId,
    [ValidateSet('File','ActiveDirectory')][string]$ZoneStorage='File',
    [string[]]$ForwarderIPAddress=@()
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
$identityNotes=@('Changes target only this server. Existing zones are inspected and preserved; existing forwarders remain in place. No records, scavenging, recursion, DNS client settings, or firewall policies are changed.')
function Test-IdentityDnsName {
    param([string]$Value)
    return ($Value.Length -le 253 -and $Value -match '^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
}
function Test-IdentityDnsIPv4 {
    param([string]$Value)
    $parsed=$null
    return ($Value -match '^\d{1,3}(?:\.\d{1,3}){3}$' -and [System.Net.IPAddress]::TryParse($Value,[ref]$parsed) -and [string]$parsed -ceq $Value -and $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and -not [System.Net.IPAddress]::IsLoopback($parsed) -and $parsed.GetAddressBytes()[0] -gt 0 -and $parsed.GetAddressBytes()[0] -lt 224 -and $Value -notmatch '^169\.254\.')
}
if ($ForwardZoneName -and -not (Test-IdentityDnsName $ForwardZoneName)) { Set-SetupBlocked -Reason 'ForwardZoneName must be a valid DNS name with at least two labels.' }
$reverseZoneName=$null
if ($ReverseNetworkId) {
    if ($ReverseNetworkId -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})/(8|16|24)$' -or -not (Test-IdentityDnsIPv4 (($ReverseNetworkId -split '/')[0]))) { Set-SetupBlocked -Reason 'ReverseNetworkId supports canonical unicast IPv4 /8, /16, or /24 networks.' }
    else {
        $parts=$ReverseNetworkId -split '/'
        $octets=$parts[0] -split '\.'
        $prefixOctets=[int]$parts[1]/8
        $canonical=$true
        for ($i=$prefixOctets;$i -lt 4;$i++) { if ([int]$octets[$i] -ne 0) { $canonical=$false } }
        if (-not $canonical) { Set-SetupBlocked -Reason 'ReverseNetworkId must use the subnet network address, with all host octets zero.' }
        $labels=@()
        for ($i=$prefixOctets-1;$i -ge 0;$i--) { $labels += [string][int]$octets[$i] }
        $reverseZoneName=($labels -join '.')+'.in-addr.arpa'
    }
}
if (@($ForwarderIPAddress).Count -gt 16) { Set-SetupBlocked -Reason 'At most 16 forwarders can be supplied.' }
foreach ($address in @($ForwarderIPAddress)) { if (-not (Test-IdentityDnsIPv4 $address)) { Set-SetupBlocked -Reason 'ForwarderIPAddress requires unicast IPv4 addresses; no loopback or multicast targets.' } }
$feature=Invoke-SetupQuery -Name 'Inspect DNS role' -RequireData -Action { Get-WindowsFeature -Name DNS -ErrorAction Stop }
if (-not $feature.Succeeded) { Set-SetupBlocked -Reason 'DNS role state could not be verified.' }
$roleInstalled=$feature.Succeeded -and [bool]@($feature.Data)[0].Installed
$zoneNames=@()
if ($ForwardZoneName) { $zoneNames += $ForwardZoneName }
if ($reverseZoneName) { $zoneNames += $reverseZoneName }
if ($ZoneStorage -eq 'ActiveDirectory' -and $zoneNames.Count -gt 0) {
    $computer=Invoke-SetupQuery -Name 'Inspect AD-integrated DNS prerequisite' -RequireData -Action { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
    if (-not $computer.Succeeded -or [int]@($computer.Data)[0].DomainRole -notin @(4,5)) { Set-SetupBlocked -Reason 'AD-integrated zones require this server to be an existing domain controller.' }
}
if (-not $roleInstalled) {
    Add-SetupStep -Name 'Install DNS role' -Target 'DNS' -Action 'Install DNS role and management tools without restarting' -Evidence 'DNS configuration is deferred until a second run can inspect the installed service.'
    if ($zoneNames.Count -gt 0 -or @($ForwarderIPAddress).Count -gt 0) { $identityNotes += 'On the first Apply, only DNS role installation is performed. Rerun the same parameters after any required restart to inspect and configure zones and forwarders.' }
    foreach ($zoneName in $zoneNames) { Add-SetupStep -Name 'Deferred DNS zone configuration' -Target $zoneName -Action 'Inspect then configure on a second run' -Evidence 'DNS role must be installed before existing zones can be checked.' -State 'Deferred' }
    if (@($ForwarderIPAddress).Count -gt 0) { Add-SetupStep -Name 'Deferred DNS forwarder configuration' -Target 'DNS' -Action 'Inspect then append forwarders on a second run' -Evidence 'DNS role must be installed before existing forwarders can be checked.' -State 'Deferred' }
} else {
    Add-SetupStep -Name 'DNS role already installed' -Target 'DNS' -Action 'Preserve installed feature' -Evidence 'Existing role detected.' -State 'AlreadyConfigured'
}
$missingZones=@()
$missingForwarders=@()
if ($roleInstalled -and $zoneNames.Count -gt 0) {
    if (-not (Test-SetupCommand -Name Get-DnsServerZone) -or -not (Test-SetupCommand -Name Add-DnsServerPrimaryZone)) { Set-SetupBlocked -Reason 'DNS zone management commands are unavailable.' }
    else {
        $zones=Invoke-SetupQuery -Name 'Inspect existing DNS zones' -Action { Get-DnsServerZone -ErrorAction Stop }
        if (-not $zones.Succeeded) { Set-SetupBlocked -Reason 'Existing DNS zones could not be inspected.' }
        else {
            foreach ($zoneName in $zoneNames) {
                $matching=@($zones.Data | Where-Object { $_.ZoneName -ieq $zoneName })
                if ($matching.Count -eq 0) {
                    $missingZones += $zoneName
                    Add-SetupStep -Name 'Create DNS primary zone' -Target $zoneName -Action ('Create {0} primary zone' -f $ZoneStorage) -Evidence $(if ($ZoneStorage -eq 'ActiveDirectory') { 'Domain replication scope; secure dynamic updates only.' } else { 'File-backed zone; dynamic updates disabled.' })
                } else {
                    $zone=$matching[0]
                    $expectedIntegrated=$ZoneStorage -eq 'ActiveDirectory'
                    $expectedUpdate=if ($expectedIntegrated) { 'Secure' } else { 'None' }
                    if ($matching.Count -ne 1 -or [string]$zone.ZoneType -ne 'Primary' -or -not $zone.PSObject.Properties['IsDsIntegrated'] -or [bool]$zone.IsDsIntegrated -ne $expectedIntegrated -or -not $zone.PSObject.Properties['DynamicUpdate'] -or [string]$zone.DynamicUpdate -ne $expectedUpdate) { Set-SetupBlocked -Reason ('Existing zone {0} conflicts with the requested zone storage, primary role, or dynamic update policy; no zone is overwritten.' -f $zoneName) }
                    Add-SetupStep -Name 'Existing DNS zone' -Target $zoneName -Action 'Preserve existing zone' -Evidence 'No replication scope or DNS record changes are attempted for an existing zone.' -State 'AlreadyConfigured'
                }
            }
        }
    }
}
if ($roleInstalled -and @($ForwarderIPAddress).Count -gt 0) {
    if (-not (Test-SetupCommand -Name Get-DnsServerForwarder) -or -not (Test-SetupCommand -Name Add-DnsServerForwarder)) { Set-SetupBlocked -Reason 'DNS forwarder management commands are unavailable.' }
    else {
        $localAddresses=Invoke-SetupQuery -Name 'Inspect local IPv4 addresses' -Action { Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Select-Object -ExpandProperty IPAddress }
        if (-not $localAddresses.Succeeded) { Set-SetupBlocked -Reason 'Local addresses could not be inspected to prevent forwarding to this server.' }
        foreach ($address in @($ForwarderIPAddress)) { if ([string]$address -in @($localAddresses.Data)) { Set-SetupBlocked -Reason 'A requested forwarder is a local server address, which would create a forwarding loop.' } }
        $forwarders=Invoke-SetupQuery -Name 'Inspect DNS forwarders' -Action { Get-DnsServerForwarder -ErrorAction Stop }
        if (-not $forwarders.Succeeded) { Set-SetupBlocked -Reason 'Existing DNS forwarders could not be inspected.' }
        else {
            $current=@($forwarders.Data | ForEach-Object { $_.IPAddress } | ForEach-Object { [string]$_ })
            $missingForwarders=@($ForwarderIPAddress | Select-Object -Unique | Where-Object { $_ -notin $current })
            foreach ($address in $missingForwarders) { Add-SetupStep -Name 'Add DNS forwarder' -Target $address -Action 'Append forwarder without replacing existing forwarders' -Evidence 'Existing forwarder order, timeout, and recursion settings are preserved.' }
            if ($missingForwarders.Count -eq 0) { Add-SetupStep -Name 'Forwarders already present' -Target 'DNS' -Action 'Preserve forwarders' -Evidence 'All requested forwarder addresses are already configured.' -State 'AlreadyConfigured' }
        }
    }
}
if ($setupCanApply -and -not $roleInstalled) {
    $installed=Invoke-SetupAction -Name 'Install DNS role' -Target 'DNS' -Action {
        $result=Install-WindowsFeature -Name DNS -IncludeManagementTools -Restart:$false -ErrorAction Stop
        if (-not $result.Success) { throw 'DNS role installation did not report success.' }
        if ([string]$result.RestartNeeded -eq 'Yes') { $script:setupRestartRequired=$true }
        [pscustomobject]@{ Success=$true; RestartNeeded=[string]$result.RestartNeeded }
    }
}
if ($setupCanApply -and $roleInstalled) {
    $proceed=$true
    foreach ($zoneName in $missingZones) {
        if (-not $proceed) { break }
        $created=Invoke-SetupAction -Name 'Create DNS primary zone' -Target $zoneName -Action {
            $zoneParameters=@{ ErrorAction='Stop'; Confirm=$false }
            if ($zoneName -eq $reverseZoneName) { $zoneParameters.NetworkId=$ReverseNetworkId } else { $zoneParameters.Name=$zoneName }
            if ($ZoneStorage -eq 'ActiveDirectory') { $zoneParameters.ReplicationScope='Domain'; $zoneParameters.DynamicUpdate='Secure' }
            else { $zoneParameters.ZoneFile=$zoneName+'.dns'; $zoneParameters.DynamicUpdate='None' }
            Add-DnsServerPrimaryZone @zoneParameters | Out-Null
            $verified=Get-DnsServerZone -Name $zoneName -ErrorAction Stop
            if ([string]$verified.ZoneType -ne 'Primary') { throw 'The requested DNS primary zone was not verified.' }
            [pscustomobject]@{ ZoneName=$zoneName; ZoneType='Primary' }
        }
        if (-not $created.Succeeded -and -not $created.Skipped) { $proceed=$false }
    }
    if ($proceed -and $missingForwarders.Count -gt 0 -and $setupCanApply) {
        $forwarded=Invoke-SetupAction -Name 'Add DNS forwarders' -Target ($missingForwarders -join ', ') -Action {
            Add-DnsServerForwarder -IPAddress ([System.Net.IPAddress[]]$missingForwarders) -ErrorAction Stop | Out-Null
            $current=@((Get-DnsServerForwarder -ErrorAction Stop).IPAddress | ForEach-Object { [string]$_ })
            if (@($missingForwarders | Where-Object { $_ -notin $current }).Count -gt 0) { throw 'The requested DNS forwarders were not verified.' }
            [pscustomobject]@{ AddedCount=$missingForwarders.Count }
        }
    }
}
Complete-SetupReport -Notes $identityNotes

} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
