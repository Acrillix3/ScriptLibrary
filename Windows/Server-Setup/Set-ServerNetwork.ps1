<#
What it does:
  Plans or applies one explicit static IPv4 address, optional gateway and ordered DNS server list.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -InterfaceAlias: Required exact adapter name.
  -IPAddress: Required canonical unicast IPv4 address.
  -PrefixLength: Required IPv4 subnet prefix, 1-30.
  -DefaultGateway: Optional same-subnet unicast gateway.
  -DnsServer: Required ordered list of 1-8 IPv4 resolver addresses.
  -AllowDhcpConversion: Explicitly allow adding a new static address to a DHCP adapter.

How it works:
  Reads only the named adapter and refuses conflicting static addresses, origins, prefixes or gateways. Apply and ShouldProcess gate changes; no address or route is removed, and IPv6 is preserved.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$Apply,
    [string]$OutputDirectory,
    [switch]$SkipRestartPrompt,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$InterfaceAlias,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$IPAddress,
    [Parameter(Mandatory=$true)][ValidateRange(1,30)][int]$PrefixLength,
    [string]$DefaultGateway,
    [Parameter(Mandatory=$true)][ValidateCount(1,8)][string[]]$DnsServer,
    [switch]$AllowDhcpConversion
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
function Convert-SetupIPv4 {
    param([string]$Text,[switch]$AllowLoopback)
    $parsed=$null
    if(-not [Net.IPAddress]::TryParse($Text,[ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $parsed.ToString() -ne $Text){throw 'A canonical dotted-decimal IPv4 address is required.'}
    $bytes=$parsed.GetAddressBytes()
    if($bytes[0] -eq 0 -or $bytes[0] -ge 224 -or ($bytes[0] -eq 127 -and -not $AllowLoopback) -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254)){throw 'An ordinary unicast IPv4 address is required.'}
    return $parsed
}
$desired=Convert-SetupIPv4 $IPAddress
$addressBytes=$desired.GetAddressBytes()
$hostBits=$PrefixLength;$hostAllZero=$true;$hostAllOne=$true
for($index=0;$index -lt 4;$index++){
    $networkBits=[math]::Min(8,[math]::Max(0,$hostBits))
    $hostMask=[int]([math]::Pow(2,8-$networkBits)-1)
    $value=$addressBytes[$index] -band $hostMask
    if($value -ne 0){$hostAllZero=$false}
    if($value -ne $hostMask){$hostAllOne=$false}
    $hostBits-=8
}
if($hostAllZero -or $hostAllOne){Set-SetupBlocked 'The server address cannot be the subnet network or broadcast address.'}
foreach($dnsAddress in $DnsServer){$null=Convert-SetupIPv4 $dnsAddress -AllowLoopback}
if(@($DnsServer | Select-Object -Unique).Count -ne $DnsServer.Count){Set-SetupBlocked 'DNS server addresses must be unique.'}
if($DefaultGateway){
    $gateway=Convert-SetupIPv4 $DefaultGateway
    if($gateway.Equals($desired)){Set-SetupBlocked 'The gateway cannot be the server address.'}
    $a=$desired.GetAddressBytes();$b=$gateway.GetAddressBytes();$remaining=$PrefixLength;$gatewayAllZero=$true;$gatewayAllOne=$true
    for($index=0;$index -lt 4;$index++){
        $bits=[math]::Min(8,[math]::Max(0,$remaining));$mask=if($bits){256-[math]::Pow(2,8-$bits)}else{0}
        if(($a[$index] -band [int]$mask) -ne ($b[$index] -band [int]$mask)){Set-SetupBlocked 'The default gateway must be in the requested IPv4 subnet.'}
        $hostMask=255-[int]$mask;$gatewayHostValue=$b[$index] -band $hostMask
        if($gatewayHostValue -ne 0){$gatewayAllZero=$false}
        if($gatewayHostValue -ne $hostMask){$gatewayAllOne=$false}
        $remaining-=8
    }
    if($gatewayAllZero -or $gatewayAllOne){Set-SetupBlocked 'The gateway cannot be the subnet network or broadcast address.'}
}
$adapter=Invoke-SetupQuery -Name 'SelectedNetworkAdapter' -RequireData -Action {Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop | Where-Object Name -eq $InterfaceAlias}
if($adapter.Succeeded -and $adapter.Data.Count -ne 1){Set-SetupBlocked 'InterfaceAlias must identify exactly one network adapter.'}
$addresses=@();$routes=@();$interface=$null;$dns=$null;$addressNeeded=$true;$routeNeeded=$false;$dnsNeeded=$true
if($adapter.Succeeded -and $adapter.Data.Count -eq 1){
    $interfaceIndex=$adapter.Data[0].ifIndex
    if($adapter.Data[0].Status -ne 'Up'){Set-SetupBlocked 'The selected adapter must be Up; no disabled/disconnected adapter is configured.'}
    $ipQuery=Invoke-SetupQuery -Name 'ExistingIPv4Addresses' -Action {Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction Stop}
    $routeQuery=Invoke-SetupQuery -Name 'ExistingDefaultRoutes' -Action {Get-NetRoute -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction Stop | Where-Object DestinationPrefix -eq '0.0.0.0/0'}
    $interfaceQuery=Invoke-SetupQuery -Name 'IPv4Interface' -RequireData -Action {Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction Stop}
    $dnsQuery=Invoke-SetupQuery -Name 'ExistingDnsServers' -RequireData -Action {Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction Stop}
    $addresses=@($ipQuery.Data);$routes=@($routeQuery.Data)
    if($interfaceQuery.Succeeded){$interface=$interfaceQuery.Data[0]}
    if($dnsQuery.Succeeded){$dns=$dnsQuery.Data[0]}
    $meaningful=@($addresses | Where-Object {$_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1'})
    if(@($meaningful | Where-Object {$_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -ne $IPAddress}).Count){Set-SetupBlocked 'A different static IPv4 address exists. This tool does not remove or replace static addresses.'}
    $same=@($meaningful | Where-Object IPAddress -eq $IPAddress)
    if($same.Count){
        if($same.Count -ne 1 -or $same[0].PrefixOrigin -ne 'Manual' -or $same[0].PrefixLength -ne $PrefixLength){Set-SetupBlocked 'The requested address already exists with a different origin or prefix. Reconcile it manually; a DHCP lease is not silently converted.'}
        else{$addressNeeded=$false}
        if($same[0].AddressState -in @('Duplicate','Invalid')){Set-SetupBlocked 'Windows reports the requested address as Duplicate or Invalid.'}
    }
    if($interface.Dhcp -eq 'Enabled' -and -not $AllowDhcpConversion){Set-SetupBlocked 'The adapter uses DHCP. AllowDhcpConversion is required to add a new static address and disable DHCP.'}
    if($DefaultGateway){
        if(@($routes | Where-Object NextHop -ne $DefaultGateway).Count){Set-SetupBlocked 'A different default gateway exists. Routes are never removed by this tool.'}
        $routeNeeded=-not @($routes | Where-Object NextHop -eq $DefaultGateway).Count -and -not $addressNeeded
    }
    if($dns){$dnsNeeded=(@($dns.ServerAddresses) -join ',') -ne ($DnsServer -join ',')}
}
Add-SetupStep -Name 'Configure static IPv4' -Target ($InterfaceAlias+':'+$IPAddress+'/'+$PrefixLength) -Action Create -Evidence 'Adds one static IPv4 address; New-NetIPAddress disables DHCP on that interface. Existing different static addresses are refused.' -State $(if($addressNeeded){'Planned'}else{'AlreadyConfigured'})
if($DefaultGateway){Add-SetupStep -Name 'Configure default gateway' -Target $DefaultGateway -Action Create -Evidence 'Creates a missing default route only; existing different routes are refused.' -State $(if($routeNeeded -or $addressNeeded){'Planned'}else{'AlreadyConfigured'})}
Add-SetupStep -Name 'Set adapter DNS servers' -Target $InterfaceAlias -Action Configure -Evidence ('Ordered DNS server list: '+($DnsServer -join ', ')) -State $(if($dnsNeeded){'Planned'}else{'AlreadyConfigured'})
if(-not $setupBlocked){
    if($addressNeeded){
        $created=Invoke-SetupAction -Name 'Configure static IPv4' -Target ($InterfaceAlias+':'+$IPAddress+'/'+$PrefixLength) -Action {
            $parameters=@{InterfaceIndex=$interfaceIndex;IPAddress=$IPAddress;PrefixLength=$PrefixLength;AddressFamily='IPv4';ErrorAction='Stop'}
            if($DefaultGateway){$parameters.DefaultGateway=$DefaultGateway}
            New-NetIPAddress @parameters
        }
        if($created.Succeeded -and $DefaultGateway){($setupSteps | Where-Object {$_.Name -eq 'Configure default gateway'} | Select-Object -Last 1).State='Applied'}
    }
    if($routeNeeded){$null=Invoke-SetupAction -Name 'Configure default gateway' -Target $DefaultGateway -Action {New-NetRoute -InterfaceIndex $interfaceIndex -DestinationPrefix '0.0.0.0/0' -NextHop $DefaultGateway -ErrorAction Stop}}
    if($dnsNeeded){$null=Invoke-SetupAction -Name 'Set adapter DNS servers' -Target $InterfaceAlias -Action {Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ServerAddresses $DnsServer -ErrorAction Stop}}
}
Complete-SetupReport -Notes @('Run from a local or out-of-band console: changing the management address, gateway or DNS can disconnect a remote session. The script does not choose adapters or remove existing static addresses/routes.','Windows Duplicate Address Detection runs after address creation. Verify the final address state and connectivity before continuing server-role deployment; no ping result is treated as proof an address is unused.','This tool configures IPv4 only; IPv6 is not disabled. An existing DHCP lease matching the desired address requires a separate reviewed conversion procedure.')

} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
