<#
What it does:
  Runs isolated mocked checks for RDS, IIS, and Hyper-V setup tools without changing server roles.

Available flags:
  -LibraryPath: Folder containing the materialized Server-Setup scripts.
  -OutputDirectory: Optional location for temporary fixtures and a JSON test summary.

How it works:
  Replaces provider calls in memory, executes the actual standalone script with controlled fixtures, and checks plan, apply, conflict, failure, and restart behavior.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$LibraryPath,[string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
if (-not $LibraryPath) { $LibraryPath = Join-Path $PSScriptRoot '..\Server-Setup' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$testRoot = [IO.Path]::GetFullPath((Join-Path $OutputDirectory ('app-' + [guid]::NewGuid().ToString('N').Substring(0,8))))
$null = New-Item -ItemType Directory -Path $testRoot -Force
$contentDirectory = Join-Path $testRoot 'SiteContent'
$secondContentDirectory = Join-Path $testRoot 'SecondContent'
$null = New-Item -ItemType Directory -Path $contentDirectory,$secondContentDirectory -Force
$results = New-Object 'System.Collections.Generic.List[object]'

function Assert-ApplicationSetup {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw ('Application role test failed: ' + $Message) }
    $results.Add([pscustomobject]@{Check=$Message;Passed=$true})
}
function Invoke-ApplicationSetupCase {
    param([string]$Script,[hashtable]$Parameters=@{},[hashtable]$Scenario=@{})
    $source = Get-Content -LiteralPath (Join-Path $LibraryPath $Script) -Raw
    $tokens=$null; $parseErrors=$null
    $ast = [Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$parseErrors)
    if ($parseErrors) { throw 'The setup source did not parse.' }
    $replacements = @{
        'Test-SetupAdministrator' = 'function Test-SetupAdministrator { return $true }'
        'Get-IisSetupInventory' = 'function Get-IisSetupInventory { if($testScenario.InventoryFailure){throw "Mocked inventory failure"}; return $testScenario.Inventory }'
        'New-IisSetupSites' = 'function New-IisSetupSites { param([object[]]$Sites) $testCalls.Add("CommitIisSites"); $testScenario.CreatedSites=@($Sites); foreach($definition in $Sites){[pscustomobject]@{Name=$definition.Name;Started=$false;Authentication="Windows"}} }'
    }
    foreach ($definition in @($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object { $replacements.ContainsKey($_.Name) } | Sort-Object { $_.Extent.StartOffset } -Descending)) {
        $source = $source.Substring(0,$definition.Extent.StartOffset) + $replacements[$definition.Name] + $source.Substring($definition.Extent.EndOffset)
    }
    & {
        param($testSource,$testParameters,$testOverrides)
        $testScenario = @{
            Installed=@(); DomainRole=3; PartOfDomain=$true; InstallationType='Server'; SecureChannel=$true; Capabilities=$true; DEP=$true; HypervisorPresent=$false; Restart='No'; FeatureSuccess=$true; ServiceStatus='Running'; AdapterStatus='Up'; Switches=@(); ExistingDeployment=$false; FailLicense=$false; WrongLicense=$false; Logons='0'; FailCollectionAccess=$false; WrongCollectionGroups=$false; FailRestore=$false; ExistingApplicationHost=$false; Inventory=[pscustomobject]@{Sites=@();PoolNames=@()}; CertificatePrivateKey=$true; CertificateExpired=$false; LocalIp='192.0.2.10'
        }
        foreach($key in $testOverrides.Keys){$testScenario[$key]=$testOverrides[$key]}
        $testCalls=New-Object 'System.Collections.Generic.List[string]'
        function Get-CimInstance {
            param([string]$ClassName)
            switch($ClassName){
                'Win32_OperatingSystem' { [pscustomobject]@{Caption='Microsoft Windows Server 2022';BuildNumber='20348';ProductType=3;DataExecutionPrevention_Available=$testScenario.DEP} }
                'Win32_ComputerSystem' { [pscustomobject]@{Name='TESTSRV';DNSHostName='TESTSRV';Domain='example.test';PartOfDomain=$testScenario.PartOfDomain;DomainRole=$testScenario.DomainRole;HypervisorPresent=$testScenario.HypervisorPresent} }
                'Win32_Processor' { [pscustomobject]@{DeviceID='CPU0';VirtualizationFirmwareEnabled=$testScenario.Capabilities;VMMonitorModeExtensions=$testScenario.Capabilities;SecondLevelAddressTranslationExtensions=$testScenario.Capabilities} }
                'Win32_TerminalServiceSetting' { [pscustomobject]@{Logons=$testScenario.Logons} }
                default {throw 'Unmocked CIM class.'}
            }
        }
        function Set-CimInstance {
            param([object]$InputObject,[hashtable]$Property)
            if($Property.Keys.Count -ne 1 -or -not $Property.ContainsKey('Logons')){throw 'Unexpected CIM mutation.'}
            $testCalls.Add('SetLogons:'+[string]$Property.Logons)
            if($testScenario.FailRestore -and [string]$Property.Logons -eq '0'){throw 'Mocked logon restore failure.'}
            $testScenario.Logons=[string]$Property.Logons
            [pscustomobject]@{Logons=$testScenario.Logons}
        }
        function Get-ItemProperty {
            param([string]$LiteralPath,[string]$Name)
            if($LiteralPath -like '*CurrentVersion'){return [pscustomobject]@{InstallationType=$testScenario.InstallationType}}
            if($LiteralPath -like '*ComputerName*'){return [pscustomobject]@{ComputerName='TESTSRV'}}
            return [pscustomobject]@{PendingFileRenameOperations=@()}
        }
        function Test-Path {
            param([string]$LiteralPath)
            if($LiteralPath -like 'HKLM:*'){return $false}
            if($LiteralPath -like '*applicationHost.config'){return $testScenario.ExistingApplicationHost}
            Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
        }
        function Get-WindowsFeature {
            param([string[]]$Name)
            foreach($feature in $Name){[pscustomobject]@{Name=$feature;Installed=($feature -in $testScenario.Installed)}}
        }
        function Install-WindowsFeature {
            param([string[]]$Name,[switch]$IncludeManagementTools)
            $testCalls.Add('InstallFeatures:' + ($Name -join ','))
            [pscustomobject]@{Success=$testScenario.FeatureSuccess;RestartNeeded=$testScenario.Restart;ExitCode='Success'}
        }
        function Resolve-DnsName { param([string]$Name,[switch]$DnsOnly) [pscustomobject]@{Name=$Name;IPAddress='192.0.2.10'} }
        function Test-ComputerSecureChannel {return $testScenario.SecureChannel}
        function Get-Service {param([string]$Name) [pscustomobject]@{Name=$Name;Status=$testScenario.ServiceStatus}}
        function Get-NetAdapter { [pscustomobject]@{Name='Ethernet0';InterfaceDescription='Test NIC';Status=$testScenario.AdapterStatus} }
        function Get-NetIPAddress { [pscustomobject]@{IPAddress=$testScenario.LocalIp} }
        function Get-VMSwitch {return $testScenario.Switches}
        function New-VMSwitch {
            param([string]$Name,[string]$NetAdapterName,[bool]$AllowManagementOS)
            if(-not $AllowManagementOS){throw 'Management OS access must remain enabled.'}
            $testCalls.Add('CreateSwitch:'+$Name+':'+$NetAdapterName)
            [pscustomobject]@{Name=$Name;SwitchType='External';AllowManagementOS=$AllowManagementOS}
        }
        function New-RDSessionDeployment {
            param([string]$ConnectionBroker,[string]$WebAccessServer,[string[]]$SessionHost)
            $testCalls.Add('CreateRdsDeployment')
            if($testScenario.ExistingDeployment){throw 'Existing deployment.'}
            if($ConnectionBroker -ne $WebAccessServer -or @($SessionHost).Count -ne 1 -or $SessionHost[0] -ne $ConnectionBroker){throw 'Expected an explicitly local single-host deployment.'}
        }
        function Set-RDLicenseConfiguration {
            param([string]$ConnectionBroker,[string[]]$LicenseServer,[string]$Mode,[switch]$Force)
            $testCalls.Add('SetRdsLicense:'+$Mode)
            if($testScenario.FailLicense){throw 'License configuration failed.'}
            $testScenario.ObservedLicenseMode=$Mode;$testScenario.ObservedLicenseServer=$LicenseServer
        }
        function Get-RDLicenseConfiguration {param([string]$ConnectionBroker) [pscustomobject]@{Mode=if($testScenario.WrongLicense){'NotConfigured'}else{$testScenario.ObservedLicenseMode};LicenseServer=$testScenario.ObservedLicenseServer}}
        function New-RDSessionCollection {param([string]$CollectionName,[string[]]$SessionHost,[string]$ConnectionBroker) if($testScenario.Logons -ne '1'){throw 'New sessions must be disabled before creating a collection.'};$testCalls.Add('CreateCollection')}
        function Set-RDSessionCollectionConfiguration {
            param([string]$CollectionName,[string]$ConnectionBroker,[string[]]$UserGroup)
            $testCalls.Add('SetCollectionGroups:' + ($UserGroup -join ','))
            if($testScenario.FailCollectionAccess){throw 'Mocked access configuration failure.'}
            $testScenario.ObservedCollectionGroups=$UserGroup
        }
        function Get-RDSessionCollectionConfiguration {param([string]$CollectionName,[string]$ConnectionBroker,[switch]$UserGroup) [pscustomobject]@{UserGroup=if($testScenario.WrongCollectionGroups){@('EXAMPLE\Wrong-Group')}else{$testScenario.ObservedCollectionGroups}}}
        function Add-Type {param([string]$Path) if($Path -notlike '*Microsoft.Web.Administration.dll'){throw 'Unmocked assembly.'}}
        function Get-Item {
            param([string]$LiteralPath)
            if($LiteralPath -like 'Cert:*'){
                $certificate=[pscustomobject]@{HasPrivateKey=$testScenario.CertificatePrivateKey;NotBefore=(Get-Date).AddDays(-1);NotAfter=if($testScenario.CertificateExpired){(Get-Date).AddDays(-1)}else{(Get-Date).AddDays(30)}}
                $certificate | Add-Member -MemberType ScriptMethod -Name GetCertHash -Value {return [byte[]](1..20)}
                return $certificate
            }
            Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath
        }
        function New-Object {
            param([Parameter(Position=0)][string]$TypeName,[Parameter(Position=1)][object[]]$ArgumentList)
            if($TypeName -eq 'Microsoft.Web.Administration.ServerManager'){
                $site=[pscustomobject]@{ServerAutoStart=$true;State='Started'}
                $site | Add-Member -MemberType ScriptMethod -Name Stop -Value { $testCalls.Add('StopGeneratedDefaultSite');$this.State='Stopped';return 'Stopped' }
                $manager=[pscustomobject]@{Sites=@{'Default Web Site'=$site}}
                $manager | Add-Member -MemberType ScriptMethod -Name CommitChanges -Value { if($this.Sites['Default Web Site'].ServerAutoStart){throw 'Default site must not autostart.'}; $testCalls.Add('DisableGeneratedDefaultSiteStartup') }
                $manager | Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
                return $manager
            }
            if($TypeName -eq 'System.Security.Principal.NTAccount'){
                $account=[pscustomobject]@{Name=[string]$ArgumentList[0]}
                $account | Add-Member -MemberType ScriptMethod -Name Translate -Value {param($targetType) $sum=0;foreach($byte in [Text.Encoding]::UTF8.GetBytes($this.Name.ToLowerInvariant())){$sum+=[int]$byte};[pscustomobject]@{Value=('S-1-5-21-100-200-300-'+$sum)}}
                return $account
            }
            if($ArgumentList -and $ArgumentList.Count){return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList}
            return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName
        }
        $testParameters.OutputDirectory=Join-Path $testRoot ([guid]::NewGuid().ToString('N').Substring(0,8))
        $testParameters.Confirm=$false
        if($testSource -match '\$SkipRestartPrompt'){$testParameters.SkipRestartPrompt=$true}
        $mockScriptPath=Join-Path $testRoot ('m'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.ps1')
        [IO.File]::WriteAllText($mockScriptPath,$testSource,(New-Object Text.UTF8Encoding($true)))
        $summary=@(& $mockScriptPath @testParameters)[-1]
        [pscustomobject]@{Summary=$summary;Calls=$testCalls.ToArray();Scenario=$testScenario;Plan=@(Import-Csv -LiteralPath (Join-Path $summary.ReportDirectory 'plan.csv'));Checks=@(Import-Csv -LiteralPath (Join-Path $summary.ReportDirectory 'checks.csv'))}
    } $source $Parameters $Scenario
}
function Write-TestIisConfiguration {
    param([object[]]$Sites)
    $path=Join-Path $testRoot ([guid]::NewGuid().ToString('N')+'.json')
    @{Sites=$Sites} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}
function New-TestIisSite {
    param([string]$Name='InternalSite',[string]$PhysicalPath=$contentDirectory,[string]$Protocol='http',[string]$IPAddress='127.0.0.1',[int]$Port=8080,[string]$HostName='')
    return [ordered]@{Name=$Name;PhysicalPath=$PhysicalPath;AppPool=($Name+'Pool');Protocol=$Protocol;IPAddress=$IPAddress;Port=$Port;HostName=$HostName}
}

$hv='Install-HyperVHost.ps1';$rds='Install-RemoteDesktopServer.ps1';$iis='Install-WebServer.ps1'
$rdsFeatures=@('RDS-Connection-Broker','RDS-Web-Access','RDS-RD-Server')
$iisFeatures=@('Web-Server','Web-Windows-Auth','Web-Scripting-Tools')
$case=Invoke-ApplicationSetupCase $hv
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Plan') 'Hyper-V default plan performs no changes'
$case=Invoke-ApplicationSetupCase $hv @{Apply=$true} @{Restart='Yes'}
Assert-ApplicationSetup ($case.Calls.Count -eq 1 -and $case.Calls[0] -like 'InstallFeatures:*') 'Hyper-V apply installs only the role'
Assert-ApplicationSetup ($case.Summary.RestartRequired -and $case.Summary.State -eq 'RestartRequired') 'Hyper-V installation reports manual restart requirement'
foreach($scenario in @(@{Capabilities=$false},@{DEP=$false},@{DomainRole=5},@{FeatureSuccess=$false})){
    $case=Invoke-ApplicationSetupCase $hv @{Apply=$true} $scenario
    Assert-ApplicationSetup ($case.Summary.State -eq 'Blocked') ('Hyper-V prerequisite or provider failure blocks completion: '+($scenario.Keys -join ','))
    if(-not $scenario.ContainsKey('FeatureSuccess')){Assert-ApplicationSetup ($case.Calls.Count -eq 0) 'Failed Hyper-V prerequisite prevents feature mutation'}
}
$switchParameters=@{Apply=$true;CreateSwitch=$true;SwitchName='Production';NetAdapterName='Ethernet0'}
$case=Invoke-ApplicationSetupCase $hv $switchParameters
Assert-ApplicationSetup ($case.Summary.State -eq 'Blocked' -and $case.Calls.Count -eq 0) 'Switch cannot be created during first Hyper-V installation'
$case=Invoke-ApplicationSetupCase $hv @{Apply=$true;SwitchName='Unapproved'} @{Installed=@('Hyper-V')}
Assert-ApplicationSetup ($case.Summary.State -eq 'Blocked' -and $case.Calls.Count -eq 0) 'Switch parameters require explicit switch creation flag'
$case=Invoke-ApplicationSetupCase $hv $switchParameters @{Installed=@('Hyper-V');HypervisorPresent=$true;Capabilities=$false}
Assert-ApplicationSetup ($case.Calls.Count -eq 1 -and $case.Calls[0] -eq 'CreateSwitch:Production:Ethernet0') 'Installed Hyper-V permits explicit switch with masked processor flags'
Assert-ApplicationSetup ($case.Summary.State -eq 'Complete') 'Switch creation preserves management OS access and completes'
foreach($scenario in @(@{Switches=@([pscustomobject]@{Name='Production';SwitchType='Internal'})},@{Switches=@([pscustomobject]@{Name='Other';SwitchType='External';NetAdapterInterfaceDescription='Test NIC'})},@{AdapterStatus='Disabled'},@{ServiceStatus='Stopped'})){
    $scenario.Installed=@('Hyper-V')
    $case=Invoke-ApplicationSetupCase $hv $switchParameters $scenario
    Assert-ApplicationSetup ($case.Summary.State -eq 'Blocked' -and $case.Calls.Count -eq 0) ('Conflicting switch or unavailable adapter/service prevents creation: '+($scenario.Keys -join ','))
}
$whatIfSwitch=@{};foreach($key in $switchParameters.Keys){$whatIfSwitch[$key]=$switchParameters[$key]};$whatIfSwitch.WhatIf=$true
$case=Invoke-ApplicationSetupCase $hv $whatIfSwitch @{Installed=@('Hyper-V')}
Assert-ApplicationSetup ($case.Calls.Count -eq 0) 'Hyper-V WhatIf does not create a switch'
$case=Invoke-ApplicationSetupCase $hv @{Apply=$true;CreateSwitch=$true;SwitchName='Wildcard';NetAdapterName='Ether*'} @{Installed=@('Hyper-V')}
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Blocked') 'Hyper-V refuses wildcard adapter selection'

$case=Invoke-ApplicationSetupCase $rds
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Plan') 'RDS default plan performs no changes'
$case=Invoke-ApplicationSetupCase $rds @{Apply=$true} @{Restart='Yes'}
Assert-ApplicationSetup ($case.Calls.Count -eq 1 -and $case.Calls[0] -like 'InstallFeatures:*') 'RDS first apply stages roles without creating deployment'
Assert-ApplicationSetup ($case.Summary.RestartRequired) 'RDS role installation reports restart without restarting'
$deploymentParameters=@{Apply=$true;ConfigureDeployment=$true;LicenseServer='licensing.example.test';LicensingMode='PerUser'}
$case=Invoke-ApplicationSetupCase $rds $deploymentParameters
Assert-ApplicationSetup ($case.Summary.State -eq 'Blocked' -and $case.Calls.Count -eq 0) 'RDS deployment requires roles already present'
foreach($scenario in @(@{InstallationType='Server Core'},@{DomainRole=5},@{SecureChannel=$false},@{PartOfDomain=$false},@{ServiceStatus='Stopped'})){
    $scenario.Installed=$rdsFeatures
    $case=Invoke-ApplicationSetupCase $rds $deploymentParameters $scenario
    Assert-ApplicationSetup ($case.Summary.State -eq 'Blocked' -and $case.Calls.Count -eq 0) ('RDS member, GUI, domain or remoting prerequisite enforced: '+($scenario.Keys -join ','))
}
$case=Invoke-ApplicationSetupCase $rds @{Apply=$true;ConfigureDeployment=$true;LicenseServer='licensing.example.test'} @{Installed=$rdsFeatures}
Assert-ApplicationSetup ($case.Summary.State -eq 'Blocked' -and $case.Calls.Count -eq 0) 'RDS licensing mode cannot be implicitly selected'
$case=Invoke-ApplicationSetupCase $rds $deploymentParameters @{Installed=$rdsFeatures}
Assert-ApplicationSetup ($case.Calls.Count -eq 2 -and $case.Calls[0] -eq 'CreateRdsDeployment' -and $case.Calls[1] -eq 'SetRdsLicense:PerUser') 'RDS creates local standard deployment before explicit license configuration'
$case=Invoke-ApplicationSetupCase $rds $deploymentParameters @{Installed=$rdsFeatures;ExistingDeployment=$true}
Assert-ApplicationSetup ($case.Calls.Count -eq 1 -and $case.Summary.State -eq 'Blocked') 'Existing deployment rejection prevents all licensing and collection changes'
$collectionParameters=@{};foreach($key in $deploymentParameters.Keys){$collectionParameters[$key]=$deploymentParameters[$key]};$collectionParameters.CollectionName='Accounting';$collectionParameters.CollectionUserGroup=@('EXAMPLE\RDS-Accounting')
$case=Invoke-ApplicationSetupCase $rds $collectionParameters @{Installed=$rdsFeatures}
Assert-ApplicationSetup ($case.Calls.Count -eq 6 -and $case.Calls[2] -eq 'SetLogons:1' -and $case.Calls[4] -eq 'SetCollectionGroups:EXAMPLE\RDS-Accounting' -and $case.Calls[5] -eq 'SetLogons:0') 'Optional collection access is configured while new sessions are suspended, then prior policy restored'
Assert-ApplicationSetup ($case.Scenario.Logons -eq '0') 'Verified collection access restores the prior new-session policy'
$case=Invoke-ApplicationSetupCase $rds $collectionParameters @{Installed=$rdsFeatures;FailLicense=$true}
Assert-ApplicationSetup ($case.Calls.Count -eq 2 -and $case.Summary.State -eq 'Blocked') 'License configuration failure prevents collection creation'
$case=Invoke-ApplicationSetupCase $rds @{Apply=$true;ConfigureDeployment=$true;LicenseServer='licensing.example.test';LicensingMode='PerUser';CollectionName='Accounting'} @{Installed=$rdsFeatures}
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Blocked') 'Collection requires explicit access groups before any RDS deployment changes'
$case=Invoke-ApplicationSetupCase $rds $deploymentParameters @{Installed=$rdsFeatures;LocalIp='192.0.2.11'}
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Blocked') 'RDS refuses a local FQDN that resolves to another host address'
foreach($scenario in @(@{FailCollectionAccess=$true},@{WrongCollectionGroups=$true},@{FailRestore=$true})){
    $scenario.Installed=$rdsFeatures
    $case=Invoke-ApplicationSetupCase $rds $collectionParameters $scenario
    Assert-ApplicationSetup ($case.Summary.State -eq 'Blocked' -and $case.Scenario.Logons -eq '1') ('Failed collection access or restore leaves new RDS sessions disabled: '+($scenario.Keys -join ','))
}
$case=Invoke-ApplicationSetupCase $rds $collectionParameters @{Installed=$rdsFeatures;WrongLicense=$true}
Assert-ApplicationSetup ($case.Calls.Count -eq 2 -and $case.Summary.State -eq 'Blocked' -and $case.Scenario.Logons -eq '0') 'RDS licensing readback mismatch prevents collection and logon policy mutations'
$case=Invoke-ApplicationSetupCase $rds $collectionParameters @{Installed=$rdsFeatures;ExistingDeployment=$true}
Assert-ApplicationSetup ($case.Calls.Count -eq 1 -and $case.Scenario.Logons -eq '0') 'Existing deployment failure cannot suspend logons or change collection access'

$case=Invoke-ApplicationSetupCase $iis
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Plan') 'IIS default plan performs no changes'
$case=Invoke-ApplicationSetupCase $iis @{Apply=$true}
Assert-ApplicationSetup ($case.Calls.Count -eq 3 -and $case.Calls[1] -eq 'DisableGeneratedDefaultSiteStartup' -and $case.Calls[2] -eq 'StopGeneratedDefaultSite') 'First IIS installation disables and stops only generated default site'
$case=Invoke-ApplicationSetupCase $iis @{Apply=$true} @{Installed=@('Web-Server')}
Assert-ApplicationSetup ($case.Calls.Count -eq 1) 'Existing IIS Default Web Site is preserved when adding feature prerequisites'
$case=Invoke-ApplicationSetupCase $iis @{Apply=$true} @{ExistingApplicationHost=$true}
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Blocked') 'Old IIS config prevents first-role installation from reactivating existing sites'
$goodSite=New-TestIisSite
$configPath=Write-TestIisConfiguration @($goodSite)
$case=Invoke-ApplicationSetupCase $iis @{Apply=$true;ConfigurationPath=$configPath}
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Blocked') 'IIS custom sites require feature installation in a prior invocation'
$case=Invoke-ApplicationSetupCase $iis @{Apply=$true;ConfigurationPath=$configPath} @{Installed=$iisFeatures}
Assert-ApplicationSetup ($case.Calls.Count -eq 1 -and $case.Calls[0] -eq 'CommitIisSites' -and $case.Summary.State -eq 'Complete') 'Validated loopback site is committed without starting or opening firewall'
Assert-ApplicationSetup ($case.Scenario.CreatedSites[0].IPAddress -eq '127.0.0.1' -and $case.Scenario.CreatedSites[0].Protocol -eq 'http') 'Validated site projection preserves explicit loopback binding'
foreach($badSite in @((New-TestIisSite -IPAddress '192.0.2.10'),(New-TestIisSite -IPAddress '0.0.0.0'),(New-TestIisSite -Name 'Bad/Name'),(New-TestIisSite -Protocol 'ftp'))){
    $badPath=Write-TestIisConfiguration @($badSite)
    $case=Invoke-ApplicationSetupCase $iis @{Apply=$true;ConfigurationPath=$badPath} @{Installed=$iisFeatures}
    Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Blocked') ('IIS rejects invalid site or unsafe binding: '+$badSite.Name+'/'+$badSite.Protocol+'/'+$badSite.IPAddress)
}
$duplicatePath=Write-TestIisConfiguration @($goodSite,$goodSite)
$case=Invoke-ApplicationSetupCase $iis @{Apply=$true;ConfigurationPath=$duplicatePath} @{Installed=$iisFeatures}
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Blocked') 'Duplicate sites are rejected before any IIS mutation'
$collisionInventory=[pscustomobject]@{Sites=@([pscustomobject]@{Name='Existing';PhysicalPath=$secondContentDirectory;Bindings=@([pscustomobject]@{Protocol='http';BindingInformation='*:8080:'})});PoolNames=@()}
$case=Invoke-ApplicationSetupCase $iis @{Apply=$true;ConfigurationPath=$configPath} @{Installed=$iisFeatures;Inventory=$collisionInventory}
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Blocked') 'IIS wildcard binding collision prevents new site'
$existingPool=[pscustomobject]@{Sites=@();PoolNames=@('InternalSitePool')}
$case=Invoke-ApplicationSetupCase $iis @{Apply=$true;ConfigurationPath=$configPath} @{Installed=$iisFeatures;Inventory=$existingPool}
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Blocked') 'Existing application pool is not reused or changed'
$unknownProperty=New-TestIisSite;$unknownProperty.AnonymousAccess=$true
$unknownPath=Write-TestIisConfiguration @($unknownProperty)
$case=Invoke-ApplicationSetupCase $iis @{Apply=$true;ConfigurationPath=$unknownPath} @{Installed=$iisFeatures}
Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Blocked') 'Unknown IIS JSON properties cannot silently select insecure settings'
$httpsSite=New-TestIisSite -Protocol 'https' -IPAddress '192.0.2.10' -Port 443 -HostName 'internal.example.test';$httpsSite.CertificateThumbprint=('A'*40)
$httpsPath=Write-TestIisConfiguration @($httpsSite)
$case=Invoke-ApplicationSetupCase $iis @{Apply=$true;ConfigurationPath=$httpsPath} @{Installed=$iisFeatures}
Assert-ApplicationSetup ($case.Calls.Count -eq 1 -and $case.Scenario.CreatedSites[0].CertificateHash.Count -eq 20) 'HTTPS requires and projects an existing private-key certificate'
foreach($scenario in @(@{CertificatePrivateKey=$false},@{CertificateExpired=$true},@{LocalIp='192.0.2.11'},@{InventoryFailure=$true})){
    $scenario.Installed=$iisFeatures
    $case=Invoke-ApplicationSetupCase $iis @{Apply=$true;ConfigurationPath=$httpsPath} $scenario
    Assert-ApplicationSetup ($case.Calls.Count -eq 0 -and $case.Summary.State -eq 'Blocked') ('HTTPS certificate, local IP and inventory evidence enforced: '+($scenario.Keys -join ','))
}

# Exercise the real in-memory IIS builder against a small fake API object model.
# Its CommitChanges method rejects an exposed or anonymously accessible new site.
if (-not ('ScriptLibrarySetupTests.IisManager' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
namespace ScriptLibrarySetupTests {
 public class Attributes {
  public Dictionary<string, object> Values = new Dictionary<string, object>();
  public void SetAttributeValue(string name, object value) { Values[name] = value; }
 }
 public class Binding : Attributes {
  public string Protocol {get;set;}
  public string BindingInformation {get;set;}
  public byte[] CertificateHash {get;set;}
  public string CertificateStoreName {get;set;}
 }
 public class VirtualDirectory { public string PhysicalPath {get;set;} }
 public class Application {
  public string ApplicationPoolName {get;set;}
  public Dictionary<string, VirtualDirectory> VirtualDirectories = new Dictionary<string, VirtualDirectory>();
 }
 public class Site {
  public string Name {get;set;}
  public bool ServerAutoStart {get;set;}
  public List<Binding> Bindings = new List<Binding>();
  public Dictionary<string, Application> Applications = new Dictionary<string, Application>();
 }
 public class Pool { public string ManagedRuntimeVersion {get;set;} }
 public class SiteCollection : IEnumerable {
  public Dictionary<string, Site> Items = new Dictionary<string, Site>();
  public Site this[string name] {get {return Items.ContainsKey(name) ? Items[name] : null;}}
  public Site Add(string name,string protocol,string binding,string physicalPath) {
   var site = new Site{Name=name,ServerAutoStart=true};
   site.Bindings.Add(new Binding{Protocol=protocol,BindingInformation=binding});
   var app = new Application(); app.VirtualDirectories.Add("/",new VirtualDirectory{PhysicalPath=physicalPath});
   site.Applications.Add("/",app); Items.Add(name,site); return site;
  }
  public IEnumerator GetEnumerator() { return Items.Values.GetEnumerator(); }
 }
 public class PoolCollection {
  public Dictionary<string, Pool> Items = new Dictionary<string, Pool>();
  public Pool this[string name] {get {return Items.ContainsKey(name) ? Items[name] : null;}}
  public Pool Add(string name) { var pool=new Pool();Items.Add(name,pool);return pool; }
 }
 public class Configuration {
  public Dictionary<string, Attributes> Sections = new Dictionary<string, Attributes>();
  public Attributes GetSection(string section,string site) {
   string key=site+"|"+section;
   if(!Sections.ContainsKey(key)) Sections.Add(key,new Attributes());
   return Sections[key];
  }
 }
 public class IisManager {
  public SiteCollection Sites = new SiteCollection();
  public PoolCollection ApplicationPools = new PoolCollection();
  public Configuration Configuration = new Configuration();
  public bool Committed {get;set;}
  public bool Disposed {get;set;}
  public bool ValidateSecurity = true;
  public Configuration GetApplicationHostConfiguration() {return Configuration;}
  public void CommitChanges() {
   if(ValidateSecurity) foreach(Site site in Sites) {
    if(site.ServerAutoStart) throw new InvalidOperationException("New site was not stopped before commit.");
    var anonymous=Configuration.GetSection("system.webServer/security/authentication/anonymousAuthentication",site.Name);
    var windows=Configuration.GetSection("system.webServer/security/authentication/windowsAuthentication",site.Name);
    if(!anonymous.Values.ContainsKey("enabled") || (bool)anonymous.Values["enabled"]) throw new InvalidOperationException("Anonymous authentication remained enabled.");
    if(!windows.Values.ContainsKey("enabled") || !(bool)windows.Values["enabled"]) throw new InvalidOperationException("Windows authentication was not enabled.");
   }
   Committed=true;
  }
  public void Dispose() {Disposed=true;}
 }
}
'@
}
$iisSource = Get-Content -LiteralPath (Join-Path $LibraryPath $iis) -Raw
$apiTokens=$null;$apiParseErrors=$null
$iisAst=[Management.Automation.Language.Parser]::ParseInput($iisSource,[ref]$apiTokens,[ref]$apiParseErrors)
$apiDefinitions=@($iisAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Test-IisSetupBindingConflict','Test-IisSetupPathOverlap','New-IisSetupSites')},$true) | ForEach-Object {$_.Extent.Text}) -join [Environment]::NewLine
$apiCase = & {
    param($functionSource)
    . ([scriptblock]::Create($functionSource))
    $fakeManager=[ScriptLibrarySetupTests.IisManager]::new()
    function New-Object { param([string]$TypeName) if($TypeName -ne 'Microsoft.Web.Administration.ServerManager'){throw 'Unexpected API object.'};return $fakeManager }
    $definitions=@(
        [pscustomobject]@{Name='ApiHttp';AppPool='ApiHttpPool';Protocol='http';IPAddress='127.0.0.1';Port=8080;HostName='';PhysicalPath='C:\TestSiteOne';CertificateHash=$null},
        [pscustomobject]@{Name='ApiHttps';AppPool='ApiHttpsPool';Protocol='https';IPAddress='192.0.2.10';Port=443;HostName='secure.example.test';PhysicalPath='C:\TestSiteTwo';CertificateHash=[byte[]](1..20)}
    )
    $rows=@(New-IisSetupSites -Sites $definitions)
    [pscustomobject]@{Manager=$fakeManager;Rows=$rows;PathOverlap=(Test-IisSetupPathOverlap -FirstPath 'C:\Sites\Parent' -SecondPath 'C:\Sites\Parent\Child');DifferentPath=(Test-IisSetupPathOverlap -FirstPath 'C:\Sites\Parent' -SecondPath 'C:\Sites\Parent2');CrossProtocolCollision=(Test-IisSetupBindingConflict -Protocol https -IPAddress '127.0.0.1' -Port 8080 -HostName '' -ExistingBindings @([pscustomobject]@{Protocol='http';BindingInformation='*:8080:'}))}
} $apiDefinitions
Assert-ApplicationSetup ($apiCase.Manager.Committed -and $apiCase.Manager.Disposed) 'Actual IIS builder commits validated in-memory configuration and disposes API manager'
Assert-ApplicationSetup (-not $apiCase.Manager.Sites['ApiHttp'].ServerAutoStart -and -not $apiCase.Manager.Sites['ApiHttps'].ServerAutoStart) 'Actual IIS builder disables startup before either site is committed'
Assert-ApplicationSetup ($apiCase.Rows.Count -eq 2 -and @($apiCase.Rows | Where-Object Started).Count -eq 0) 'Actual IIS builder returns stopped-site evidence'
Assert-ApplicationSetup ($apiCase.Manager.Sites['ApiHttps'].Bindings[0].CertificateHash.Length -eq 20 -and $apiCase.Manager.Sites['ApiHttps'].Bindings[0].CertificateStoreName -eq 'My') 'Actual HTTPS builder binds certificate hash to the machine My store'
Assert-ApplicationSetup ([int]$apiCase.Manager.Sites['ApiHttps'].Bindings[0].Values['sslFlags'] -eq 1) 'Actual HTTPS builder enables SNI for the explicit host name'
Assert-ApplicationSetup ($apiCase.Manager.ApplicationPools['ApiHttpPool'].ManagedRuntimeVersion -eq '' -and $apiCase.Manager.Sites['ApiHttp'].Applications['/'].ApplicationPoolName -eq 'ApiHttpPool') 'Actual IIS builder connects each site to its new pool without selecting a CLR runtime'
Assert-ApplicationSetup ($apiCase.PathOverlap -and -not $apiCase.DifferentPath) 'Content path overlap includes parent and child directories without matching sibling prefixes'
Assert-ApplicationSetup ($apiCase.CrossProtocolCollision) 'HTTP and HTTPS cannot accidentally share an overlapping endpoint'
$raceCase = & {
    param($functionSource)
    . ([scriptblock]::Create($functionSource))
    $fakeManager=[ScriptLibrarySetupTests.IisManager]::new()
    $null=$fakeManager.Sites.Add('ConcurrentSite','http','*:8080:','C:\ExistingSite')
    function New-Object { param([string]$TypeName) return $fakeManager }
    $failed=$false
    try { $null=New-IisSetupSites -Sites @([pscustomobject]@{Name='NewSite';AppPool='NewPool';Protocol='http';IPAddress='127.0.0.1';Port=8080;HostName='';PhysicalPath='C:\NewSite'}) } catch {$failed=$true}
    [pscustomobject]@{Failed=$failed;Committed=$fakeManager.Committed;Disposed=$fakeManager.Disposed}
} $apiDefinitions
Assert-ApplicationSetup ($raceCase.Failed -and -not $raceCase.Committed -and $raceCase.Disposed) 'A binding appearing after preflight prevents the actual IIS builder from committing changes'
$summary=[pscustomobject]@{Suite='ApplicationRoleSetup';Passed=$results.Count;Failed=0;ReportDirectory=[IO.Path]::GetFullPath($testRoot);Runtime=[string]$PSVersionTable.PSVersion}
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $testRoot 'summary.json') -Encoding UTF8
$results | Export-Csv -LiteralPath (Join-Path $testRoot 'checks.csv') -NoTypeInformation -Encoding UTF8
$summary
