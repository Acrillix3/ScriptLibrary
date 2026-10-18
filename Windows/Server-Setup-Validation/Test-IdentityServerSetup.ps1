<#
What it does:
  Tests the four identity and network server setup tools with mocked Windows providers.

Available flags:
  -SourceDirectory: Folder containing the four generated setup scripts.
  -OutputDirectory: Folder for fixture scripts, reports, and the test summary.

How it works:
  Copies each script into an isolated fixture folder, replaces only the administrator check, and shadows every referenced provider mutation. Verifies planning, WhatIf, drift gates, secure credentials, and reboot suppression without installing a role or contacting a domain.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$SourceDirectory,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if (-not $PSBoundParameters.ContainsKey('SourceDirectory')) { $SourceDirectory=Join-Path $PSScriptRoot '..\Server-Setup' }
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory=Join-Path $PSScriptRoot '..\Reports' }
$runDirectory=Join-Path $OutputDirectory ('id-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$fixtureDirectory=Join-Path $runDirectory 'fixtures'
$null=New-Item -ItemType Directory -Path $fixtureDirectory -Force
$script:assertions=0
$script:scenarios=0
$global:identitySetupFixture=$null
$global:identitySetupMutations=$null
function Assert-IdentitySetup {
    param([bool]$Condition,[string]$Message)
    $script:assertions++
    if (-not $Condition) { throw ('Identity setup assertion failed: '+$Message) }
}
function New-IdentityFixture {
    $global:identitySetupFixture=[pscustomobject]@{
        Computer=[pscustomobject]@{Name='TESTSRV';DNSHostName='testsrv';Domain='WORKGROUP';PartOfDomain=$false;DomainRole=2}
        OS=[pscustomobject]@{Caption='Microsoft Windows Server 2025 Standard';BuildNumber='26100';ProductType=3}
        FeatureInstalled=$true;FeatureSuccess=$true;RestartNeeded='No';PrecheckStatus='Success';PrecheckEmpty=$false;PrecheckThrow=$false;PromotionStatus='Success';PrecheckDomainMode=$null;PrecheckForestMode=$null
        Addresses=@([pscustomobject]@{IPAddress='10.20.30.10';PrefixOrigin='Manual';AddressState='Preferred'})
        Zones=@();Forwarders=@();Scopes=@();Options=@();Authorizations=@();DnsDiscovery=$true;JoinSucceeds=$true;OptionThrow=$false
    }
    $global:identitySetupMutations=New-Object 'System.Collections.Generic.List[object]'
}
function Add-IdentityMutation {
    param([string]$Name,[object]$Data)
    $global:identitySetupMutations.Add([pscustomobject]@{Name=$Name;Data=$Data})
}
function Restart-Computer { [CmdletBinding(SupportsShouldProcess=$true)]param([switch]$Force) throw 'Identity fixtures never authorize a real restart.' }
function Get-CimInstance {
    [CmdletBinding()]param([string]$ClassName)
    if ($ClassName -eq 'Win32_OperatingSystem') { return $global:identitySetupFixture.OS }
    if ($ClassName -eq 'Win32_ComputerSystem') { return $global:identitySetupFixture.Computer }
    throw 'Unmocked CIM class.'
}
function Test-Path {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Path)
    $target=if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($target -like 'HKLM:*') { return $false }
    return Microsoft.PowerShell.Management\Test-Path -LiteralPath $target
}
function Get-ItemProperty {
    [CmdletBinding()]param([string]$LiteralPath)
    if ($LiteralPath -like '*Session Manager') { return [pscustomobject]@{PendingFileRenameOperations=@()} }
    if ($LiteralPath -like '*ComputerName*') { return [pscustomobject]@{ComputerName='TESTSRV'} }
    throw 'Unmocked registry query.'
}
function Get-WindowsFeature { [CmdletBinding()]param([string[]]$Name) foreach ($item in $Name) { [pscustomobject]@{Name=$item;Installed=$global:identitySetupFixture.FeatureInstalled} } }
function Install-WindowsFeature {
    [CmdletBinding()]param([string[]]$Name,[switch]$IncludeManagementTools,[switch]$Restart)
    Add-IdentityMutation 'Install-WindowsFeature' ([pscustomobject]@{Name=$Name;Restart=[bool]$Restart})
    [pscustomobject]@{Success=$global:identitySetupFixture.FeatureSuccess;RestartNeeded=$global:identitySetupFixture.RestartNeeded}
}
function Get-NetIPAddress { [CmdletBinding()]param([string]$AddressFamily) $global:identitySetupFixture.Addresses }
function Resolve-DnsName {
    [CmdletBinding()]param([string]$Name,[string]$Type,[switch]$DnsOnly)
    if (-not $global:identitySetupFixture.DnsDiscovery) { throw 'fixture DNS discovery failed' }
    [pscustomobject]@{Type='SRV';Name=$Name;NameTarget='dc01.contoso.test';Port=389}
}
function Add-Computer {
    [CmdletBinding(SupportsShouldProcess=$true)]param([string]$DomainName,[pscredential]$Credential,[switch]$Restart,[switch]$PassThru,[string]$OUPath,[string]$Server)
    Add-IdentityMutation 'Add-Computer' ([pscustomobject]@{Restart=[bool]$Restart;SecureCredential=($Credential -is [pscredential]);DomainName=$DomainName})
    [pscustomobject]@{HasSucceeded=$global:identitySetupFixture.JoinSucceeds;ComputerName='TESTSRV'}
}
function Test-ADDSForestInstallation {
    [CmdletBinding()]param([string]$DomainName,[Security.SecureString]$SafeModeAdministratorPassword,[bool]$InstallDns,[bool]$CreateDnsDelegation,[switch]$NoRebootOnCompletion,[string]$DomainNetbiosName,[string]$DomainMode,[string]$ForestMode)
    $global:identitySetupFixture.PrecheckDomainMode=$DomainMode;$global:identitySetupFixture.PrecheckForestMode=$ForestMode
    if ($global:identitySetupFixture.PrecheckThrow) { throw 'fixture prerequisite failure including TEST-DSRM-NOT-A-SECRET' }
    if (-not $global:identitySetupFixture.PrecheckEmpty) { [pscustomobject]@{Status=$global:identitySetupFixture.PrecheckStatus} }
}
function Test-ADDSDomainControllerInstallation {
    [CmdletBinding()]param([string]$DomainName,[Security.SecureString]$SafeModeAdministratorPassword,[bool]$InstallDns,[bool]$CreateDnsDelegation,[switch]$NoRebootOnCompletion,[pscredential]$Credential,[string]$SiteName,[string]$ReplicationSourceDC)
    Test-ADDSForestInstallation -DomainName $DomainName -SafeModeAdministratorPassword $SafeModeAdministratorPassword -InstallDns $InstallDns -CreateDnsDelegation $CreateDnsDelegation -NoRebootOnCompletion:$NoRebootOnCompletion
}
function Install-ADDSForest {
    [CmdletBinding(SupportsShouldProcess=$true)]param([string]$DomainName,[Security.SecureString]$SafeModeAdministratorPassword,[bool]$InstallDns,[bool]$CreateDnsDelegation,[switch]$NoRebootOnCompletion,[string]$DomainNetbiosName,[string]$DomainMode,[string]$ForestMode)
    Add-IdentityMutation 'Install-ADDSForest' ([pscustomobject]@{NoReboot=[bool]$NoRebootOnCompletion;SecurePassword=($SafeModeAdministratorPassword -is [Security.SecureString]);DomainMode=$DomainMode;ForestMode=$ForestMode})
    [pscustomobject]@{Status=$global:identitySetupFixture.PromotionStatus}
}
function Install-ADDSDomainController {
    [CmdletBinding(SupportsShouldProcess=$true)]param([string]$DomainName,[Security.SecureString]$SafeModeAdministratorPassword,[bool]$InstallDns,[bool]$CreateDnsDelegation,[switch]$NoRebootOnCompletion,[pscredential]$Credential,[string]$SiteName,[string]$ReplicationSourceDC)
    Add-IdentityMutation 'Install-ADDSDomainController' ([pscustomobject]@{NoReboot=[bool]$NoRebootOnCompletion;SecurePassword=($SafeModeAdministratorPassword -is [Security.SecureString]);SecureCredential=($Credential -is [pscredential])})
    [pscustomobject]@{Status=$global:identitySetupFixture.PromotionStatus}
}
function Get-DnsServerZone {
    [CmdletBinding()]param([string]$Name)
    if ($Name) { return @($global:identitySetupFixture.Zones | Where-Object ZoneName -eq $Name) }
    $global:identitySetupFixture.Zones
}
function Add-DnsServerPrimaryZone {
    [CmdletBinding(SupportsShouldProcess=$true)]param([string]$Name,[string]$NetworkId,[string]$ZoneFile,[string]$ReplicationScope,[string]$DynamicUpdate)
    if ($NetworkId) {
        $netParts=$NetworkId -split '/';$octets=$netParts[0] -split '\.';$labels=@();for ($i=([int]$netParts[1]/8)-1;$i -ge 0;$i--) { $labels += $octets[$i] };$Name=($labels -join '.')+'.in-addr.arpa'
    }
    Add-IdentityMutation 'Add-DnsServerPrimaryZone' ([pscustomobject]@{Name=$Name;NetworkId=$NetworkId;DynamicUpdate=$DynamicUpdate;ReplicationScope=$ReplicationScope})
    $global:identitySetupFixture.Zones += [pscustomobject]@{ZoneName=$Name;ZoneType='Primary';IsDsIntegrated=([bool]$ReplicationScope);DynamicUpdate=$DynamicUpdate}
}
function Get-DnsServerForwarder { [CmdletBinding()]param() [pscustomobject]@{IPAddress=$global:identitySetupFixture.Forwarders} }
function Add-DnsServerForwarder {
    [CmdletBinding()]param([System.Net.IPAddress[]]$IPAddress)
    Add-IdentityMutation 'Add-DnsServerForwarder' ([pscustomobject]@{IPAddress=@($IPAddress | ForEach-Object { [string]$_ })})
    $global:identitySetupFixture.Forwarders += @($IPAddress | ForEach-Object { [string]$_ })
}
function Get-DhcpServerv4Scope {
    [CmdletBinding()]param([System.Net.IPAddress]$ScopeId)
    if ($ScopeId) { return @($global:identitySetupFixture.Scopes | Where-Object { [string]$_.ScopeId -eq [string]$ScopeId }) }
    $global:identitySetupFixture.Scopes
}
function Add-DhcpServerv4Scope {
    [CmdletBinding()]param([string]$Name,[System.Net.IPAddress]$StartRange,[System.Net.IPAddress]$EndRange,[System.Net.IPAddress]$SubnetMask,[string]$State)
    Add-IdentityMutation 'Add-DhcpServerv4Scope' ([pscustomobject]@{State=$State;Name=$Name})
    $global:identitySetupFixture.Scopes += [pscustomobject]@{Name=$Name;ScopeId='10.20.30.0';StartRange=[string]$StartRange;EndRange=[string]$EndRange;SubnetMask=[string]$SubnetMask;State=$State}
}
function Get-DhcpServerv4OptionValue { [CmdletBinding()]param([System.Net.IPAddress]$ScopeId) $global:identitySetupFixture.Options }
function Set-DhcpServerv4OptionValue {
    [CmdletBinding()]param([System.Net.IPAddress]$ScopeId,[uint32]$OptionId,[string[]]$Value)
    Add-IdentityMutation 'Set-DhcpServerv4OptionValue' ([pscustomobject]@{OptionId=$OptionId;Value=$Value})
    if ($global:identitySetupFixture.OptionThrow) { throw 'fixture option failure' }
    $global:identitySetupFixture.Options += [pscustomobject]@{OptionId=$OptionId;Value=$Value}
}
function Set-DhcpServerv4Scope {
    [CmdletBinding()]param([System.Net.IPAddress]$ScopeId,[string]$State)
    Add-IdentityMutation 'Set-DhcpServerv4Scope' ([pscustomobject]@{State=$State})
    foreach ($scope in $global:identitySetupFixture.Scopes) { if ([string]$scope.ScopeId -eq [string]$ScopeId) { $scope.State=$State } }
}
function Get-DhcpServerInDC { [CmdletBinding()]param() $global:identitySetupFixture.Authorizations }
function Add-DhcpServerInDC {
    [CmdletBinding()]param([string]$DnsName,[System.Net.IPAddress]$IPAddress)
    Add-IdentityMutation 'Add-DhcpServerInDC' ([pscustomobject]@{DnsName=$DnsName;IPAddress=[string]$IPAddress})
    $global:identitySetupFixture.Authorizations += [pscustomobject]@{DnsName=$DnsName;IPAddress=[string]$IPAddress}
}
foreach ($fileName in @('Install-DomainController.ps1','Join-ServerDomain.ps1','Install-DnsServer.ps1','Install-DhcpServer.ps1')) {
    $source=Get-Content -LiteralPath (Join-Path $SourceDirectory $fileName) -Raw
    $pattern='(?s)function Test-SetupAdministrator \{.*?\r?\n\}'
    Assert-IdentitySetup ([regex]::Matches($source,$pattern).Count -eq 1) ($fileName+' has exactly one replaceable administrator provider')
    $source=[regex]::Replace($source,$pattern,'function Test-SetupAdministrator { return $true }')
    [IO.File]::WriteAllText((Join-Path $fixtureDirectory $fileName),$source,(New-Object Text.UTF8Encoding($true)))
}
$testPassword=ConvertTo-SecureString 'TEST-DSRM-NOT-A-SECRET' -AsPlainText -Force
$testCredential=New-Object pscredential('TEST\fixture',$testPassword)
function Invoke-IdentityScenario {
    param([string]$File,[hashtable]$Parameters=@{},[scriptblock]$Arrange,[scriptblock]$Verify)
    New-IdentityFixture
    if ($Arrange) { & $Arrange }
    $script:scenarios++
    $arguments=@{OutputDirectory=(Join-Path $runDirectory 'reports');Confirm=$false;SkipRestartPrompt=$true}
    foreach ($key in $Parameters.Keys) { $arguments[$key]=$Parameters[$key] }
    $report=@(& (Join-Path $fixtureDirectory $File) @arguments)
    Assert-IdentitySetup ($report.Count -eq 1) ($File+' returns exactly one sanitized summary')
    $summary=$report[0]
    Assert-IdentitySetup ([bool]$summary.ReportDirectory) ($File+' returns a report directory')
    $checks=@(Import-Csv -LiteralPath (Join-Path $summary.ReportDirectory 'checks.csv'))
    $plan=@(Import-Csv -LiteralPath (Join-Path $summary.ReportDirectory 'plan.csv'))
    $text=(Get-ChildItem -LiteralPath $summary.ReportDirectory -File | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
    Assert-IdentitySetup ($text -notmatch 'TEST-DSRM-NOT-A-SECRET') ($File+' never writes passwords or raw secret-bearing provider errors')
    if ($Verify) { & $Verify $summary $plan $checks }
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test'} { $global:identitySetupFixture.FeatureInstalled=$false } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Plan') 'DC defaults to Plan';Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 0) 'DC plan does not install roles'
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Apply=$true} { $global:identitySetupFixture.FeatureInstalled=$false } {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 1 -and $global:identitySetupMutations[0].Name -eq 'Install-WindowsFeature') 'DC defaults to role staging only';Assert-IdentitySetup (-not $global:identitySetupMutations[0].Data.Restart) 'DC staging never restarts'
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Apply=$true;Promote=$true;SafeModeAdministratorPassword=$testPassword} { $global:identitySetupFixture.FeatureInstalled=$false } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked') 'DC promotion requires prior role staging';Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 0) 'DC no partial feature change when promotion cannot be checked'
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Apply=$true;Promote=$true;SafeModeAdministratorPassword=$testPassword} $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'RestartRequired') 'DC promotion marks reboot requirement';Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 1 -and $global:identitySetupMutations[0].Name -eq 'Install-ADDSForest') 'New forest uses correct provider';Assert-IdentitySetup ($global:identitySetupMutations[0].Data.NoReboot -and $global:identitySetupMutations[0].Data.SecurePassword) 'Promotion passes secure password and no-reboot';Assert-IdentitySetup ($global:identitySetupFixture.PrecheckDomainMode -eq 'WinThreshold' -and $global:identitySetupFixture.PrecheckForestMode -eq 'WinThreshold') 'New-forest prerequisite tests explicitly use 2016 functional levels';Assert-IdentitySetup ($global:identitySetupMutations[0].Data.DomainMode -eq 'WinThreshold' -and $global:identitySetupMutations[0].Data.ForestMode -eq 'WinThreshold') 'New-forest installation explicitly uses the same 2016 functional levels'
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Mode='AdditionalDC';Apply=$true;Promote=$true;SafeModeAdministratorPassword=$testPassword;Credential=$testCredential} $null {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 1 -and $global:identitySetupMutations[0].Name -eq 'Install-ADDSDomainController') 'Additional controller uses correct provider';Assert-IdentitySetup ($global:identitySetupMutations[0].Data.SecureCredential) 'Additional controller passes PSCredential'
}
foreach ($status in @('Error','Warning','Unknown')) {
    $fixtureStatus=$status
    Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Apply=$true;Promote=$true;SafeModeAdministratorPassword=$testPassword} { $global:identitySetupFixture.PrecheckStatus=$fixtureStatus } {
        param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked') 'Non-success AD DS prerequisites block';Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 0) 'Failed prerequisite cannot promote'
    }
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Apply=$true;Promote=$true;SafeModeAdministratorPassword=$testPassword} { $global:identitySetupFixture.PrecheckEmpty=$true } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'Empty prerequisite evidence is not success'
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Apply=$true;Promote=$true;SafeModeAdministratorPassword=$testPassword} { $global:identitySetupFixture.PrecheckThrow=$true } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'Thrown prerequisites block without leaking error text'
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Apply=$true;Promote=$true} $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'Missing DSRM blocks Apply without prompting'
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Apply=$true;Promote=$true;WhatIf=$true} $null {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 0) 'DC WhatIf never mutates or prompts for a password'
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Apply=$true;Promote=$true;SafeModeAdministratorPassword=$testPassword} { $global:identitySetupFixture.Addresses=@() } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'DC promotion requires static IPv4 evidence'
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Apply=$true;Promote=$true;SafeModeAdministratorPassword=$testPassword} { $global:identitySetupFixture.Computer.PartOfDomain=$true;$global:identitySetupFixture.Computer.Domain='other.test' } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'New forest preserves existing domain membership'
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='contoso.test';Apply=$true;Promote=$true;SafeModeAdministratorPassword=$testPassword} { $global:identitySetupFixture.Computer.PartOfDomain=$true;$global:identitySetupFixture.Computer.Domain='contoso.test';$global:identitySetupFixture.Computer.DomainRole=5 } {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 0) 'Existing same-domain DC never re-promotes'
}
Invoke-IdentityScenario 'Join-ServerDomain.ps1' @{DomainName='contoso.test'} $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Plan' -and $global:identitySetupMutations.Count -eq 0) 'Domain join defaults to plan'
}
Invoke-IdentityScenario 'Join-ServerDomain.ps1' @{DomainName='contoso.test';Apply=$true;Credential=$testCredential} $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'RestartRequired') 'Domain join marks restart required';Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 1 -and -not $global:identitySetupMutations[0].Data.Restart -and $global:identitySetupMutations[0].Data.SecureCredential) 'Domain join uses PSCredential and never restarts'
}
Invoke-IdentityScenario 'Join-ServerDomain.ps1' @{DomainName='contoso.test';Apply=$true;Credential=$testCredential;WhatIf=$true} $null {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 0) 'Domain join WhatIf never mutates'
}
Invoke-IdentityScenario 'Join-ServerDomain.ps1' @{DomainName='contoso.test';Apply=$true} $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'Domain join requires explicit credential only on Apply'
}
foreach ($domain in @('contoso.test','other.test')) {
    $currentDomain=$domain
    Invoke-IdentityScenario 'Join-ServerDomain.ps1' @{DomainName='contoso.test';Apply=$true;Credential=$testCredential} { $global:identitySetupFixture.Computer.PartOfDomain=$true;$global:identitySetupFixture.Computer.Domain=$currentDomain } {
        param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 0) 'Existing membership is never rejoined or migrated'
    }
}
Invoke-IdentityScenario 'Join-ServerDomain.ps1' @{DomainName='contoso.test';Apply=$true;Credential=$testCredential} { $global:identitySetupFixture.DnsDiscovery=$false } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'Missing DNS discovery blocks join'
}
Invoke-IdentityScenario 'Install-DnsServer.ps1' @{ForwardZoneName='contoso.test';ForwarderIPAddress=@('1.1.1.1')} $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Plan' -and $global:identitySetupMutations.Count -eq 0) 'DNS defaults to plan'
}
Invoke-IdentityScenario 'Install-DnsServer.ps1' @{Apply=$true;ForwardZoneName='contoso.test';ReverseNetworkId='10.20.30.0/24';ForwarderIPAddress=@('1.1.1.1')} { $global:identitySetupFixture.Forwarders=@('8.8.8.8') } {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 3) 'DNS creates two zones and appends forwarders';Assert-IdentitySetup ($global:identitySetupFixture.Forwarders -contains '8.8.8.8') 'DNS preserves existing forwarders';Assert-IdentitySetup (@($global:identitySetupMutations | Where-Object { $_.Name -eq 'Add-DnsServerPrimaryZone' -and $_.Data.DynamicUpdate -ne 'None' }).Count -eq 0) 'File zones disable dynamic update';Assert-IdentitySetup (@($global:identitySetupMutations | Where-Object { $_.Data.NetworkId -eq '10.20.30.0/24' }).Count -eq 1) 'Reverse zone uses exact NetworkId provider parameter'
}
Invoke-IdentityScenario 'Install-DnsServer.ps1' @{Apply=$true;ForwardZoneName='contoso.test';ZoneStorage='ActiveDirectory'} { $global:identitySetupFixture.Computer.DomainRole=5;$global:identitySetupFixture.Computer.PartOfDomain=$true;$global:identitySetupFixture.Computer.Domain='contoso.test' } {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 1 -and $global:identitySetupMutations[0].Data.DynamicUpdate -eq 'Secure' -and $global:identitySetupMutations[0].Data.ReplicationScope -eq 'Domain') 'AD DNS requires secure updates and domain replication'
}
Invoke-IdentityScenario 'Install-DnsServer.ps1' @{Apply=$true;ForwardZoneName='contoso.test';ZoneStorage='ActiveDirectory'} $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'AD DNS requires an existing DC'
}
Invoke-IdentityScenario 'Install-DnsServer.ps1' @{Apply=$true;ForwardZoneName='contoso.test';ForwarderIPAddress=@('1.1.1.1')} { $global:identitySetupFixture.Zones=@([pscustomobject]@{ZoneName='contoso.test';ZoneType='Secondary';IsDsIntegrated=$false;DynamicUpdate='None'}) } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'DNS conflicting zone blocks all changes'
}
Invoke-IdentityScenario 'Install-DnsServer.ps1' @{Apply=$true;ForwarderIPAddress=@('10.20.30.10')} $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'DNS detects local forwarding loop'
}
Invoke-IdentityScenario 'Install-DnsServer.ps1' @{Apply=$true;ReverseNetworkId='10.20.30.1/24'} $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'Reverse DNS requires canonical network'
}
Invoke-IdentityScenario 'Install-DnsServer.ps1' @{Apply=$true;ForwardZoneName='contoso.test';WhatIf=$true} $null {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 0) 'DNS WhatIf never mutates'
}
Invoke-IdentityScenario 'Install-DnsServer.ps1' @{Apply=$true;ForwardZoneName='contoso.test'} { $global:identitySetupFixture.FeatureInstalled=$false } {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 1 -and $global:identitySetupMutations[0].Name -eq 'Install-WindowsFeature') 'DNS first Apply stages role only'
}
$scopeParameters=@{ScopeName='Clients';StartRange='10.20.30.50';EndRange='10.20.30.200';SubnetMask='255.255.255.0';RouterIPAddress=@('10.20.30.1');DnsServerIPAddress=@('10.20.30.10');DnsDomain='contoso.test'}
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeParameters $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Plan' -and $global:identitySetupMutations.Count -eq 0) 'DHCP defaults to plan'
}
$scopeApply=$scopeParameters.Clone();$scopeApply.Apply=$true
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeApply $null {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 4) 'DHCP creates scope and three missing options';Assert-IdentitySetup ($global:identitySetupMutations[0].Data.State -eq 'InActive') 'DHCP starts scope inactive';Assert-IdentitySetup (@($global:identitySetupMutations | Where-Object Name -eq 'Set-DhcpServerv4Scope').Count -eq 0) 'DHCP activation requires separate explicit flag';Assert-IdentitySetup (@($global:identitySetupMutations | Where-Object Name -eq 'Add-DhcpServerInDC').Count -eq 0) 'DHCP AD authorization is never implicit'
}
$scopeActive=$scopeApply.Clone();$scopeActive.ActivateScope=$true;$scopeActive.AuthorizeInAD=$true;$scopeActive.AuthorizationIPAddress='10.20.30.10'
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeActive { $global:identitySetupFixture.Computer.PartOfDomain=$true;$global:identitySetupFixture.Computer.Domain='contoso.test' } {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations[0].Name -eq 'Add-DhcpServerInDC') 'Requested authorization precedes activation';Assert-IdentitySetup ($global:identitySetupMutations[$global:identitySetupMutations.Count-1].Name -eq 'Set-DhcpServerv4Scope') 'Explicit activation occurs last'
}
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeActive { $global:identitySetupFixture.Computer.PartOfDomain=$true;$global:identitySetupFixture.Computer.Domain='contoso.test';$global:identitySetupFixture.OptionThrow=$true } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked') 'DHCP stops on failed option';Assert-IdentitySetup (@($global:identitySetupMutations | Where-Object Name -eq 'Set-DhcpServerv4Scope').Count -eq 0) 'Failed configuration never activates a new scope'
}
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeApply { $global:identitySetupFixture.Scopes=@([pscustomobject]@{Name='Old';ScopeId='10.20.30.0';StartRange='10.20.30.5';EndRange='10.20.30.25';SubnetMask='255.255.255.0';State='Active'}) } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'DHCP preserves conflicting existing ranges'
}
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeApply { $global:identitySetupFixture.Scopes=@([pscustomobject]@{Name='Broad';ScopeId='10.20.0.0';StartRange='10.20.1.1';EndRange='10.20.255.200';SubnetMask='255.255.0.0';State='Active'}) } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'DHCP detects overlapping subnet even without lease-range overlap'
}
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeApply { $global:identitySetupFixture.Scopes=@([pscustomobject]@{Name='Clients';ScopeId='10.20.30.0';StartRange='10.20.30.50';EndRange='10.20.30.200';SubnetMask='255.255.255.0';State='Active'});$global:identitySetupFixture.Options=@([pscustomobject]@{OptionId=3;Value=@('10.20.30.254')}) } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'DHCP conflicting option prevents all mutations'
}
$badScope=$scopeApply.Clone();$badScope.SubnetMask='255.0.255.0'
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $badScope $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'DHCP rejects non-contiguous mask'
}
$badScope=$scopeApply.Clone();$badScope.StartRange='10.20.30.0'
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $badScope $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'DHCP rejects network address in pool'
}
$scopeWhatIf=$scopeApply.Clone();$scopeWhatIf.WhatIf=$true
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeWhatIf $null {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 0) 'DHCP WhatIf never mutates'
}
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeApply { $global:identitySetupFixture.FeatureInstalled=$false } {
    param($s,$p,$c) Assert-IdentitySetup ($global:identitySetupMutations.Count -eq 1 -and $global:identitySetupMutations[0].Name -eq 'Install-WindowsFeature') 'DHCP first Apply stages role only';Assert-IdentitySetup (-not $global:identitySetupMutations[0].Data.Restart) 'DHCP staging never restarts'
}
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeActive { $global:identitySetupFixture.Computer.PartOfDomain=$true;$global:identitySetupFixture.Computer.Domain='contoso.test';$global:identitySetupFixture.Addresses=@([pscustomobject]@{IPAddress='10.20.30.11';PrefixOrigin='Manual';AddressState='Preferred'}) } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'AD DHCP authorization requires matching local static address'
}
Invoke-IdentityScenario 'Install-DnsServer.ps1' @{Apply=$true;ForwardZoneName='contoso.test';ForwarderIPAddress=@('1.1.1.1')} {
    $global:identitySetupFixture.Zones=@([pscustomobject]@{ZoneName='contoso.test';ZoneType='Primary';IsDsIntegrated=$false;DynamicUpdate='None'})
    $global:identitySetupFixture.Forwarders=@('1.1.1.1','8.8.8.8')
} {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Complete' -and $global:identitySetupMutations.Count -eq 0) 'DNS repeats an already configured request without mutation'
}
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeApply {
    $global:identitySetupFixture.Scopes=@([pscustomobject]@{Name='Clients';ScopeId='10.20.30.0';StartRange='10.20.30.50';EndRange='10.20.30.200';SubnetMask='255.255.255.0';State='Active'})
    $global:identitySetupFixture.Options=@([pscustomobject]@{OptionId=3;Value=@('10.20.30.1')},[pscustomobject]@{OptionId=6;Value=@('10.20.30.10')},[pscustomobject]@{OptionId=15;Value=@('contoso.test')})
} {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Complete' -and $global:identitySetupMutations.Count -eq 0) 'DHCP repeats an already configured request without mutation';Assert-IdentitySetup ($global:identitySetupFixture.Scopes[0].State -eq 'Active') 'DHCP default preserves an existing active scope'
}
$infrastructureScope=$scopeApply.Clone();$infrastructureScope.StartRange='10.20.30.1'
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $infrastructureScope $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'DHCP lease pool excludes router and DNS infrastructure addresses'
}
Invoke-IdentityScenario 'Install-DhcpServer.ps1' @{Apply=$true;ScopeName='Partial'} $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'DHCP requires all four scope definition fields'
}
Invoke-IdentityScenario 'Install-DnsServer.ps1' @{Apply=$true;ForwardZoneName='contoso.test'} { $global:identitySetupFixture.FeatureInstalled=$false } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Incomplete') 'DNS role staging leaves requested zone configuration incomplete';Assert-IdentitySetup (@($p | Where-Object State -eq 'Deferred').Count -eq 1) 'DNS reports deferred zone work explicitly'
}
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $scopeApply { $global:identitySetupFixture.FeatureInstalled=$false } {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Incomplete') 'DHCP role staging leaves requested scope configuration incomplete';Assert-IdentitySetup (@($p | Where-Object State -eq 'Deferred').Count -eq 1) 'DHCP reports deferred scope work explicitly'
}
Invoke-IdentityScenario 'Install-DomainController.ps1' @{DomainName='averylongdomainlabel.contoso.test';Apply=$true} $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'Long forest DNS first label requires explicit NetBIOS name without prompting'
}
$ambiguousScope=$scopeApply.Clone();$ambiguousScope.StartRange='10.20.030.50'
Invoke-IdentityScenario 'Install-DhcpServer.ps1' $ambiguousScope $null {
    param($s,$p,$c) Assert-IdentitySetup ($s.State -eq 'Blocked' -and $global:identitySetupMutations.Count -eq 0) 'DHCP rejects ambiguous IPv4 octal notation'
}
$result=[pscustomobject]@{Suite='IdentityServerSetup';Scenarios=$script:scenarios;Assertions=$script:assertions;Passed=$true;Runtime=[string]$PSVersionTable.PSVersion;OutputDirectory=$runDirectory}
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runDirectory 'test-summary.json') -Encoding UTF8
$result
