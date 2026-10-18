<#
What it does:
  Tests server baseline, network, SQL prerequisites, backup policy, NPS clients, and restart confirmation with mocked Windows providers.

Available flags:
  -ScriptsDirectory: Folder containing the standalone server setup scripts.
  -OutputDirectory: Local folder for test fixtures and reports.

How it works:
  Replaces administrator identity, interactive consent, and the native SQL-directory creation call in fixture copies. Mock providers record changes; no production setting, backup policy, RADIUS client, or restart is touched.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$ScriptsDirectory,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $ScriptsDirectory){$ScriptsDirectory=Join-Path $PSScriptRoot '..\Server-Setup'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$OutputDirectory=Join-Path $OutputDirectory ('st-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $OutputDirectory -Force
$script:rootAssertions=0
$global:rootServerSetupMock=@{}
function Assert-RootSetupTest {param([bool]$Condition,[string]$Message) $script:rootAssertions++;if(-not $Condition){throw ('Assertion failed: '+$Message)}}
function Reset-RootSetupMock {
    $global:rootServerSetupMock=@{Build='20348';ProductType=3;DomainRole=2;PartOfDomain=$false;Administrator=$true;ComputerName='MOCK-SERVER';PendingRestart=$false;TimeZone='UTC';Consent=$false;ConsentThrows=$false;ConsentCount=0;RestartFails=$false;RestartCount=0;ServiceConsent=$false;ServiceConsentCount=0;ServiceRestartCount=0;ServiceRestartFails=$false;FeatureInstalled=$true;RestartNeeded='No';FrameworkRelease=528449;Dhcp='Disabled';AdapterStatus='Up';Addresses=(New-Object 'System.Collections.Generic.List[object]');Routes=(New-Object 'System.Collections.Generic.List[object]');Dns=@('192.0.2.10');Mutations=(New-Object 'System.Collections.Generic.List[string]');Paths=@{'D:\'=$true;'D:\Sql'=$true};Acls=@{};SqlCreateRace=$false;ReparsePath='';BackupPolicy=$null;BackupPolicyReads=0;BackupPolicyAppearsOnRead=0;NpsClients=(New-Object 'System.Collections.Generic.List[object]');NpsFails=$false;Marker='TEST-SECRET-MUST-NOT-APPEAR-92731'}
}
function Get-CimInstance {
    [CmdletBinding()]param([string]$ClassName,[string]$Filter,[string]$Namespace)
    switch($ClassName){
        Win32_OperatingSystem {[pscustomobject]@{Caption='Mock Windows Server';BuildNumber=$global:rootServerSetupMock.Build;ProductType=$global:rootServerSetupMock.ProductType;Version='10.0';OSArchitecture='64-bit'}}
        Win32_ComputerSystem {[pscustomobject]@{Name=$global:rootServerSetupMock.ComputerName;DomainRole=$global:rootServerSetupMock.DomainRole;PartOfDomain=$global:rootServerSetupMock.PartOfDomain;Domain='example.test';TotalPhysicalMemory=32GB}}
        Win32_LogicalDisk {foreach($letter in @('C:','D:','E:')){[pscustomobject]@{DeviceID=$letter;DriveType=3;FileSystem='NTFS';FreeSpace=500GB;Size=1TB}}}
        default {throw ('Unexpected mock CIM class: '+$ClassName)}
    }
}
function Test-Path {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Path,[string]$PathType)
    $p=if($LiteralPath){$LiteralPath}else{$Path}
    if($p.StartsWith('HKLM:',[StringComparison]::OrdinalIgnoreCase)){return $global:rootServerSetupMock.PendingRestart -and $p -like '*RebootPending'}
    if($p.StartsWith('D:\',[StringComparison]::OrdinalIgnoreCase)){return $global:rootServerSetupMock.Paths.ContainsKey($p)}
    return Microsoft.PowerShell.Management\Test-Path -LiteralPath $p -PathType $(if($PathType){$PathType}else{'Any'})
}
function Get-ItemProperty {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Name)
    if($LiteralPath -like '*Session Manager'){return [pscustomobject]@{PendingFileRenameOperations=@()}}
    if($LiteralPath -like '*ComputerName*'){return [pscustomobject]@{ComputerName=$global:rootServerSetupMock.ComputerName}}
    if($LiteralPath -like '*NET Framework Setup*'){return [pscustomobject]@{Release=$global:rootServerSetupMock.FrameworkRelease}}
    return [pscustomobject]@{}
}
function Get-Item {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Force)
    if($LiteralPath.StartsWith('D:\',[StringComparison]::OrdinalIgnoreCase)){
        if(-not $global:rootServerSetupMock.Paths.ContainsKey($LiteralPath)){throw 'Mock path missing.'}
        $attributes=[IO.FileAttributes]::Directory
        if($LiteralPath -ieq $global:rootServerSetupMock.ReparsePath){$attributes=$attributes -bor [IO.FileAttributes]::ReparsePoint}
        return [pscustomobject]@{FullName=$LiteralPath;PSIsContainer=$true;Attributes=$attributes}
    }
    Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force
}
function Get-ChildItem {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Path,[switch]$Force,[switch]$Directory,[switch]$File)
    $p=if($LiteralPath){$LiteralPath}else{$Path}
    if($p.StartsWith('D:\',[StringComparison]::OrdinalIgnoreCase)){return}
    Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $p -Force:$Force
}
function New-Item {
    [CmdletBinding(SupportsShouldProcess=$true)]param([string]$ItemType,[string]$Path,[switch]$Force)
    if($Path.StartsWith('D:\',[StringComparison]::OrdinalIgnoreCase)){$global:rootServerSetupMock.Mutations.Add('Folder');$global:rootServerSetupMock.Paths[$Path]=$true;return [pscustomobject]@{FullName=$Path}}
    Microsoft.PowerShell.Management\New-Item -ItemType $ItemType -Path $Path -Force:$Force -WhatIf:$false -Confirm:$false
}
function Get-Acl {[CmdletBinding()]param([string]$LiteralPath,[string]$Path) $p=if($LiteralPath){$LiteralPath}else{$Path};if(-not $global:rootServerSetupMock.Acls.ContainsKey($p)){throw 'Mock ACL missing.'};$global:rootServerSetupMock.Acls[$p]}
function Set-Acl {[CmdletBinding(SupportsShouldProcess=$true)]param([string]$LiteralPath,[string]$Path,$AclObject) $p=if($LiteralPath){$LiteralPath}else{$Path};$global:rootServerSetupMock.Mutations.Add('ACL');$global:rootServerSetupMock.Acls[$p]=$AclObject}
function Get-TimeZone {[CmdletBinding()]param([string]$Id) if($Id -and $Id -notin @('UTC','Eastern Standard Time')){throw 'Unknown mock time zone.'};[pscustomobject]@{Id=$(if($Id){$Id}else{$global:rootServerSetupMock.TimeZone})}}
function Set-TimeZone {[CmdletBinding(SupportsShouldProcess=$true)]param([string]$Id) $global:rootServerSetupMock.Mutations.Add('TimeZone');$global:rootServerSetupMock.TimeZone=$Id}
function Enable-PSRemoting {[CmdletBinding(SupportsShouldProcess=$true)]param([switch]$Force) $global:rootServerSetupMock.Mutations.Add('Remoting')}
function Rename-Computer {[CmdletBinding(SupportsShouldProcess=$true)]param([string]$NewName,[switch]$PassThru,[switch]$Force,[pscredential]$DomainCredential) $global:rootServerSetupMock.Mutations.Add('Rename');[pscustomobject]@{HasSucceeded=$true;OldComputerName=$global:rootServerSetupMock.ComputerName;NewComputerName=$NewName}}
function Restart-Computer {
    [CmdletBinding(SupportsShouldProcess=$true)]param()
    $global:rootServerSetupMock.RestartCount++
    if($global:rootServerSetupMock.RestartFails){throw 'Mock restart denied.'}
    $global:rootServerSetupMock.Mutations.Add('Restart')
}
function Restart-Service {
    [CmdletBinding(SupportsShouldProcess=$true)]param([string]$Name)
    if($Name -ne 'IAS'){throw 'Unexpected service restart.'}
    $global:rootServerSetupMock.ServiceRestartCount++
    if($global:rootServerSetupMock.ServiceRestartFails){throw 'Mock service restart denied.'}
    $global:rootServerSetupMock.Mutations.Add('ServiceRestart')
}
function Get-NetAdapter {[CmdletBinding()]param([string]$Name) [pscustomobject]@{Name='Ethernet';ifIndex=12;Status=$global:rootServerSetupMock.AdapterStatus}}
function Get-NetIPAddress {[CmdletBinding()]param([int]$InterfaceIndex,[string]$AddressFamily) $global:rootServerSetupMock.Addresses.ToArray()}
function Get-NetRoute {[CmdletBinding()]param([int]$InterfaceIndex,[string]$AddressFamily) $global:rootServerSetupMock.Routes.ToArray()}
function Get-NetIPInterface {[CmdletBinding()]param([int]$InterfaceIndex,[string]$AddressFamily) [pscustomobject]@{InterfaceIndex=12;Dhcp=$global:rootServerSetupMock.Dhcp}}
function Get-DnsClientServerAddress {[CmdletBinding()]param([int]$InterfaceIndex,[string]$AddressFamily) [pscustomobject]@{InterfaceIndex=12;ServerAddresses=$global:rootServerSetupMock.Dns}}
function New-NetIPAddress {
    [CmdletBinding(SupportsShouldProcess=$true)]param([int]$InterfaceIndex,[string]$IPAddress,[int]$PrefixLength,[string]$AddressFamily,[string]$DefaultGateway)
    $global:rootServerSetupMock.Mutations.Add('Address');$global:rootServerSetupMock.Dhcp='Disabled'
    $address=[pscustomobject]@{IPAddress=$IPAddress;PrefixLength=$PrefixLength;PrefixOrigin='Manual';AddressState='Preferred'};$global:rootServerSetupMock.Addresses.Add($address)
    if($DefaultGateway){$global:rootServerSetupMock.Routes.Add([pscustomobject]@{DestinationPrefix='0.0.0.0/0';NextHop=$DefaultGateway})}
    $address
}
function New-NetRoute {[CmdletBinding(SupportsShouldProcess=$true)]param([int]$InterfaceIndex,[string]$DestinationPrefix,[string]$NextHop) $global:rootServerSetupMock.Mutations.Add('Route');$global:rootServerSetupMock.Routes.Add([pscustomobject]@{DestinationPrefix=$DestinationPrefix;NextHop=$NextHop})}
function Set-DnsClientServerAddress {[CmdletBinding(SupportsShouldProcess=$true)]param([int]$InterfaceIndex,[string[]]$ServerAddresses) $global:rootServerSetupMock.Mutations.Add('DNS');$global:rootServerSetupMock.Dns=$ServerAddresses}
function Get-WindowsFeature {[CmdletBinding()]param([string[]]$Name) foreach($feature in $Name){[pscustomobject]@{Name=$feature;Installed=$global:rootServerSetupMock.FeatureInstalled}}}
function Install-WindowsFeature {[CmdletBinding()]param([string[]]$Name,[switch]$IncludeManagementTools,[switch]$Restart) if($Restart){throw 'The setup must not request an implicit feature restart.'};$global:rootServerSetupMock.Mutations.Add('Role');[pscustomobject]@{Success=$true;RestartNeeded=$global:rootServerSetupMock.RestartNeeded}}
function New-MockSqlDirectory {
    [CmdletBinding()]param([string]$Path,$Security)
    if(-not $Path.StartsWith('D:\Sql\',[StringComparison]::OrdinalIgnoreCase)){throw 'SQL fixture path escaped mock data parent.'}
    $global:rootServerSetupMock.Mutations.Add('SqlFolder');$global:rootServerSetupMock.Paths[$Path]=$true
    if($global:rootServerSetupMock.SqlCreateRace){$global:rootServerSetupMock.Acls[$Path]=New-Object Security.AccessControl.DirectorySecurity}else{$global:rootServerSetupMock.Acls[$Path]=$Security}
    [pscustomobject]@{FullName=$Path}
}
function Get-WBPolicy {
    [CmdletBinding()]param()
    $global:rootServerSetupMock.BackupPolicyReads++
    if($global:rootServerSetupMock.BackupPolicyAppearsOnRead -gt 0 -and $global:rootServerSetupMock.BackupPolicyReads -ge $global:rootServerSetupMock.BackupPolicyAppearsOnRead -and $null -eq $global:rootServerSetupMock.BackupPolicy){$global:rootServerSetupMock.BackupPolicy=[pscustomobject]@{Existing='Concurrent policy, preserve unchanged'}}
    if($null -ne $global:rootServerSetupMock.BackupPolicy){$global:rootServerSetupMock.BackupPolicy}
}
function Get-WBVolume {[CmdletBinding(SupportsShouldProcess=$true)]param([string]$VolumePath) [pscustomobject]@{VolumePath=$VolumePath}}
function New-WBPolicy {[CmdletBinding()]param() [pscustomobject]@{Sources=@();Targets=@();Schedule=@();SystemState=$false;BareMetal=$false;VssCopy=$false}}
function Add-WBVolume {[CmdletBinding()]param($Policy,[object[]]$Volume) $Policy.Sources=@($Volume)}
function New-WBBackupTarget {[CmdletBinding()]param([string]$VolumePath) [pscustomobject]@{VolumePath=$VolumePath}}
function Add-WBBackupTarget {[CmdletBinding()]param($Policy,$Target) $Policy.Targets=@($Target)}
function Add-WBSystemState {[CmdletBinding()]param($Policy) $Policy.SystemState=$true}
function Add-WBBareMetalRecovery {[CmdletBinding()]param($Policy) $Policy.BareMetal=$true}
function Set-WBVssBackupOptions {[CmdletBinding()]param($Policy,[switch]$VssCopyBackup) $Policy.VssCopy=[bool]$VssCopyBackup}
function Set-WBSchedule {[CmdletBinding()]param($Policy,[datetime[]]$Schedule) $Policy.Schedule=$Schedule}
function Set-WBPolicy {[CmdletBinding()]param($Policy,[switch]$Force) $global:rootServerSetupMock.Mutations.Add('BackupPolicy');$global:rootServerSetupMock.BackupPolicy=$Policy}
function Get-NpsRadiusClient {[CmdletBinding()]param() $global:rootServerSetupMock.NpsClients.ToArray()}
function New-NpsRadiusClient {
    [CmdletBinding()]param([string]$Name,[string]$Address,[string]$SharedSecret,[bool]$AuthAttributeRequired)
    $global:rootServerSetupMock.Mutations.Add('NpsClient')
    if($global:rootServerSetupMock.NpsFails){throw ('Mock native error containing secret: '+$SharedSecret)}
    if($SharedSecret -cne $global:rootServerSetupMock.Marker){throw 'Expected in-memory test secret absent.'}
    $client=[pscustomobject]@{Name=$Name;Address=$Address;Enabled=$true;SharedSecret=$SharedSecret;AuthAttributeRequired=$AuthAttributeRequired};$global:rootServerSetupMock.NpsClients.Add($client);$client
}

$rootTestScripts=@{}
foreach($name in @('Initialize-WindowsServer.ps1','Set-ServerNetwork.ps1','Initialize-SqlServerPrerequisites.ps1','Install-WindowsServerBackup.ps1','Install-NpsServer.ps1')){
    $source=Get-Content -LiteralPath (Join-Path $ScriptsDirectory $name) -Raw
    $tokens=$null;$parseErrors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$parseErrors)
    Assert-RootSetupTest (-not $parseErrors) ($name+' parses')
    $consent=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Confirm-SetupRestart'},$true)
    Assert-RootSetupTest ($null -ne $consent -and $consent.Extent.Text -match '\.ShouldContinue\(') ($name+' uses an unconditional separate restart consent probe')
    $serviceConsent=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Confirm-SetupServiceRestart'},$true)
    Assert-RootSetupTest ($null -ne $serviceConsent -and $serviceConsent.Extent.Text -match '\.ShouldContinue\(') ($name+' independently confirms required service restarts')
    $complete=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Complete-SetupReport'},$true)
    Assert-RootSetupTest ($complete.Extent.Text.IndexOf('Save-SetupReport') -lt $complete.Extent.Text.IndexOf('Confirm-SetupRestart') -and $complete.Extent.Text.IndexOf('Confirm-SetupRestart') -lt $complete.Extent.Text.IndexOf('Restart-Computer')) ($name+' saves report before consent and restarts only later')
    $replacements=@{
        'Test-SetupAdministrator'='function Test-SetupAdministrator { return $global:rootServerSetupMock.Administrator }'
        'Confirm-SetupRestart'='function Confirm-SetupRestart { $global:rootServerSetupMock.ConsentCount++; if(-not (Test-Path -LiteralPath (Join-Path $setupReportDirectory ''summary.json''))){throw ''Report must exist before consent.''}; if($global:rootServerSetupMock.ConsentThrows){throw ''No interactive host.''}; return $global:rootServerSetupMock.Consent }'
        'Confirm-SetupServiceRestart'='function Confirm-SetupServiceRestart { param([string]$Name) $global:rootServerSetupMock.ServiceConsentCount++; if(-not (Test-Path -LiteralPath (Join-Path $setupReportDirectory ''summary.json''))){throw ''Report must exist before service consent.''}; return $global:rootServerSetupMock.ServiceConsent }'
    }
    $nodes=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Test-SetupAdministrator','Confirm-SetupRestart','Confirm-SetupServiceRestart')},$true) | Sort-Object {$_.Extent.StartOffset} -Descending)
    Assert-RootSetupTest ($nodes.Count -eq 3) ($name+' contains replaceable identity/consent probes')
    foreach($node in $nodes){$source=$source.Substring(0,$node.Extent.StartOffset)+$replacements[$node.Name]+$source.Substring($node.Extent.EndOffset)}
    if($name -eq 'Initialize-SqlServerPrerequisites.ps1'){
        Assert-RootSetupTest ($source.Contains('$null=[IO.Directory]::CreateDirectory($path,$security)')) 'SQL uses protected ACL at directory creation'
        $commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
        Assert-RootSetupTest (@($commands | Where-Object {$_ -in @('Invoke-WebRequest','Invoke-RestMethod','Start-Process','Invoke-Sqlcmd','sqlcmd','setup.exe','Start-BitsTransfer','New-NetFirewallRule','Set-ExecutionPolicy')}).Count -eq 0) 'SQL prerequisites do not download or install SQL, run database commands, or open firewall ports'
        $source=$source.Replace('$null=[IO.Directory]::CreateDirectory($path,$security)','$null=New-MockSqlDirectory -Path $path -Security $security')
    }
    if($name -eq 'Install-WindowsServerBackup.ps1'){
        $policyCalls=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Get-WBPolicy'},$true))
        Assert-RootSetupTest ($policyCalls.Count -ge 3 -and @($policyCalls | Where-Object {$_.Extent.Text -match '-(?:WhatIf|Confirm)(?:\s|:|$)'}).Count -eq 0) 'Backup policy reads use supported parameters and recheck before saving'
    }
    $path=Join-Path $OutputDirectory $name
    [IO.File]::WriteAllText($path,$source,(New-Object Text.UTF8Encoding($true)))
    $rootTestScripts[$name]=$path
}
function Invoke-RootSetupScenario {
    param([string]$Name,[hashtable]$Parameters=@{},[switch]$Apply,[switch]$WhatIf,[switch]$AskForRestart)
    $arguments=@{OutputDirectory=(Join-Path $OutputDirectory 'reports');Confirm=$false;SkipRestartPrompt=(-not [bool]$AskForRestart)}
    foreach($key in $Parameters.Keys){$arguments[$key]=$Parameters[$key]}
    if($Apply){$arguments.Apply=$true};if($WhatIf){$arguments.WhatIf=$true}
    $result=@(& $rootTestScripts[$Name] @arguments)
    $summary=@($result | Where-Object {$_.PSObject.Properties['State'] -and $_.PSObject.Properties['ReportDirectory']})
    Assert-RootSetupTest ($summary.Count -eq 1) ($Name+' emits one summary')
    Assert-RootSetupTest (Microsoft.PowerShell.Management\Test-Path -LiteralPath (Join-Path $summary[0].ReportDirectory 'summary.json')) ($Name+' saves its report')
    $texts=@(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $summary[0].ReportDirectory -File | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw}) -join "`n"
    Assert-RootSetupTest ($texts -notmatch [regex]::Escape($global:rootServerSetupMock.Marker)) ($Name+' report omits test secrets')
    return $summary[0]
}

# Baseline, host eligibility, and independent restart consent.
Reset-RootSetupMock;$baseline=@{NewComputerName='SERVER-NEW';TimeZoneId='Eastern Standard Time';EnableRemoting=$true}
$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters $baseline
Assert-RootSetupTest ($summary.State -eq 'Plan' -and $global:rootServerSetupMock.Mutations.Count -eq 0 -and $global:rootServerSetupMock.ConsentCount -eq 0) 'Baseline plan does not mutate or prompt for restart'
$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters $baseline -Apply -WhatIf -AskForRestart
Assert-RootSetupTest ($summary.State -eq 'Incomplete' -and $global:rootServerSetupMock.Mutations.Count -eq 0 -and $global:rootServerSetupMock.ConsentCount -eq 0) 'Baseline WhatIf never invokes restart consent or mutations'
$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters $baseline -Apply
Assert-RootSetupTest ($summary.RestartRequired -and $summary.RestartDecision -eq 'DeferredByOption' -and $global:rootServerSetupMock.RestartCount -eq 0 -and ($global:rootServerSetupMock.Mutations -join ',') -eq 'TimeZone,Remoting,Rename') 'SkipRestartPrompt defers after selected baseline operations'
Reset-RootSetupMock;$global:rootServerSetupMock.Consent=$false;$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters @{NewComputerName='SERVER-NEW'} -Apply -AskForRestart
Assert-RootSetupTest ($summary.RestartDecision -eq 'Declined' -and $global:rootServerSetupMock.ConsentCount -eq 1 -and $global:rootServerSetupMock.RestartCount -eq 0) 'Declining separate question prevents restart despite Confirm false'
Reset-RootSetupMock;$global:rootServerSetupMock.Consent=$true;$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters @{NewComputerName='SERVER-NEW'} -Apply -AskForRestart
Assert-RootSetupTest ($summary.State -eq 'RestartRequested' -and $summary.RestartDecision -eq 'Confirmed' -and $global:rootServerSetupMock.ConsentCount -eq 1 -and $global:rootServerSetupMock.RestartCount -eq 1) 'Positive separate restart confirmation invokes mocked Restart Computer once'
Reset-RootSetupMock;$global:rootServerSetupMock.ConsentThrows=$true;$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters @{NewComputerName='SERVER-NEW'} -Apply -AskForRestart
Assert-RootSetupTest ($summary.RestartDecision -eq 'ConfirmationUnavailable' -and $global:rootServerSetupMock.RestartCount -eq 0) 'Missing interactive confirmation host never defaults to restart'
Reset-RootSetupMock;$global:rootServerSetupMock.Consent=$true;$global:rootServerSetupMock.RestartFails=$true;$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters @{NewComputerName='SERVER-NEW'} -Apply -AskForRestart
Assert-RootSetupTest ($summary.State -eq 'RestartFailed' -and $summary.RestartDecision -eq 'RequestFailed' -and $global:rootServerSetupMock.RestartCount -eq 1) 'Rejected restart is reported without repeat attempts'
foreach($build in @('20348','26100')){
    Reset-RootSetupMock;$global:rootServerSetupMock.Build=$build;$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters @{TimeZoneId='Eastern Standard Time'} -Apply
    Assert-RootSetupTest ($summary.State -eq 'Complete' -and $global:rootServerSetupMock.Mutations.Count -eq 1) ('Supported server build '+$build+' applies selected settings')
}
Reset-RootSetupMock;$global:rootServerSetupMock.ProductType=1;$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters @{TimeZoneId='Eastern Standard Time'} -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Windows client is blocked even with a matching kernel build'
Reset-RootSetupMock;$global:rootServerSetupMock.Administrator=$false;$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters @{TimeZoneId='Eastern Standard Time'} -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Unelevated apply is blocked'
Reset-RootSetupMock;$global:rootServerSetupMock.PendingRestart=$true;$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters @{TimeZoneId='Eastern Standard Time'} -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $summary.RestartRequired -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Existing pending reboot blocks new setup changes'
foreach($restriction in @('Client','Administrator','UnsupportedBuild')){
    Reset-RootSetupMock;$global:rootServerSetupMock.PendingRestart=$true;$global:rootServerSetupMock.Consent=$true
    switch($restriction){Client {$global:rootServerSetupMock.ProductType=1};Administrator {$global:rootServerSetupMock.Administrator=$false};UnsupportedBuild {$global:rootServerSetupMock.Build='17763'}}
    $summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters @{TimeZoneId='Eastern Standard Time'} -Apply -AskForRestart
    Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $summary.RestartDecision -eq 'RestartNotAuthorized' -and $global:rootServerSetupMock.RestartCount -eq 0 -and $global:rootServerSetupMock.ConsentCount -eq 0) ('Pending restart cannot bypass host/runtime eligibility: '+$restriction)
}
Reset-RootSetupMock;$global:rootServerSetupMock.DomainRole=5;$global:rootServerSetupMock.PartOfDomain=$true;$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters @{NewComputerName='SERVER-NEW'} -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Generic baseline never renames a domain controller'
Reset-RootSetupMock;$global:rootServerSetupMock.PartOfDomain=$true;$summary=Invoke-RootSetupScenario Initialize-WindowsServer.ps1 -Parameters @{NewComputerName='SERVER-NEW'} -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Domain-member rename requires explicitly supplied domain identity'

# Explicit adapter selection and additive static IPv4 configuration.
$network=@{InterfaceAlias='Ethernet';IPAddress='192.0.2.20';PrefixLength=24;DefaultGateway='192.0.2.1';DnsServer=@('192.0.2.11','192.0.2.12')}
Reset-RootSetupMock;$summary=Invoke-RootSetupScenario Set-ServerNetwork.ps1 -Parameters $network
Assert-RootSetupTest ($summary.State -eq 'Plan' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Network plan leaves addresses and DNS untouched'
$summary=Invoke-RootSetupScenario Set-ServerNetwork.ps1 -Parameters $network -Apply -WhatIf
Assert-RootSetupTest ($summary.State -eq 'Incomplete' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Network WhatIf leaves connectivity untouched'
$summary=Invoke-RootSetupScenario Set-ServerNetwork.ps1 -Parameters $network -Apply
Assert-RootSetupTest ($summary.State -eq 'Complete' -and ($global:rootServerSetupMock.Mutations -join ',') -eq 'Address,DNS') 'Creates explicit address/gateway then ordered DNS servers'
$before=$global:rootServerSetupMock.Mutations.Count;$summary=Invoke-RootSetupScenario Set-ServerNetwork.ps1 -Parameters $network -Apply
Assert-RootSetupTest ($summary.State -eq 'Complete' -and $global:rootServerSetupMock.Mutations.Count -eq $before) 'Matching static network settings are idempotent'
Reset-RootSetupMock;$global:rootServerSetupMock.Addresses.Add([pscustomobject]@{IPAddress='192.0.2.99';PrefixLength=24;PrefixOrigin='Manual';AddressState='Preferred'});$summary=Invoke-RootSetupScenario Set-ServerNetwork.ps1 -Parameters $network -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Different static address blocks changes instead of removing it'
Reset-RootSetupMock;$global:rootServerSetupMock.Dhcp='Enabled';$summary=Invoke-RootSetupScenario Set-ServerNetwork.ps1 -Parameters $network -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'DHCP conversion requires explicit flag'
$networkConversion=$network.Clone();$networkConversion.AllowDhcpConversion=$true;$summary=Invoke-RootSetupScenario Set-ServerNetwork.ps1 -Parameters $networkConversion -Apply
Assert-RootSetupTest ($summary.State -eq 'Complete' -and $global:rootServerSetupMock.Dhcp -eq 'Disabled') 'Explicit DHCP conversion adds new static configuration'
Reset-RootSetupMock;$global:rootServerSetupMock.Routes.Add([pscustomobject]@{DestinationPrefix='0.0.0.0/0';NextHop='192.0.2.254'});$summary=Invoke-RootSetupScenario Set-ServerNetwork.ps1 -Parameters $network -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Different default route blocks changes'
Reset-RootSetupMock;$badNetwork=$network.Clone();$badNetwork.DefaultGateway='198.51.100.1';$summary=Invoke-RootSetupScenario Set-ServerNetwork.ps1 -Parameters $badNetwork -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Gateway outside requested subnet is rejected'
foreach($field in @('IPAddress','DefaultGateway')){foreach($invalidAddress in @('192.0.2.0','192.0.2.255')){
    Reset-RootSetupMock;$badNetwork=$network.Clone();$badNetwork[$field]=$invalidAddress;$summary=Invoke-RootSetupScenario Set-ServerNetwork.ps1 -Parameters $badNetwork -Apply
    Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) ('Subnet network/broadcast values rejected: '+$field+'='+$invalidAddress)
}}

# SQL preparation creates only protected new directories; installer and database operations are absent.
$sql=@{SqlVersion='2022';DataPath='D:\Sql\Data';LogPath='D:\Sql\Logs';TempDbPath='D:\Sql\TempDb';BackupPath='D:\Sql\Backup';MinimumMemoryGB=4;MinimumFreeGB=20}
Reset-RootSetupMock;$summary=Invoke-RootSetupScenario Initialize-SqlServerPrerequisites.ps1 -Parameters $sql
Assert-RootSetupTest ($summary.State -eq 'Plan' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'SQL preparation plan does not create directories'
$summary=Invoke-RootSetupScenario Initialize-SqlServerPrerequisites.ps1 -Parameters $sql -Apply -WhatIf
Assert-RootSetupTest ($summary.State -eq 'Incomplete' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'SQL preparation WhatIf does not call native directory creation'
$summary=Invoke-RootSetupScenario Initialize-SqlServerPrerequisites.ps1 -Parameters $sql -Apply
Assert-RootSetupTest ($summary.State -eq 'Complete' -and $global:rootServerSetupMock.Mutations.Count -eq 4 -and @($global:rootServerSetupMock.Mutations | Where-Object {$_ -ne 'SqlFolder'}).Count -eq 0) 'SQL apply performs only four directory preparations'
foreach($path in @($sql.DataPath,$sql.LogPath,$sql.TempDbPath,$sql.BackupPath)){
    $acl=$global:rootServerSetupMock.Acls[$path]
    Assert-RootSetupTest ($acl.AreAccessRulesProtected -and $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]).Count -eq 2) ('SQL directory ACL protected with exactly two principals: '+$path)
}
$before=$global:rootServerSetupMock.Mutations.Count;$summary=Invoke-RootSetupScenario Initialize-SqlServerPrerequisites.ps1 -Parameters $sql -Apply
Assert-RootSetupTest ($summary.State -eq 'Complete' -and $global:rootServerSetupMock.Mutations.Count -eq $before) 'Matching SQL preparation is idempotent'
Reset-RootSetupMock;$badSql=$sql.Clone();$badSql.LogPath='D:\Sql\Data\Logs';$summary=Invoke-RootSetupScenario Initialize-SqlServerPrerequisites.ps1 -Parameters $badSql -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Nested SQL directories block all preparation'
Reset-RootSetupMock;$global:rootServerSetupMock.FrameworkRelease=400000;$summary=Invoke-RootSetupScenario Initialize-SqlServerPrerequisites.ps1 -Parameters $sql -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Insufficient framework blocks SQL preparation without downloading a replacement'
Reset-RootSetupMock;$global:rootServerSetupMock.DomainRole=5;$summary=Invoke-RootSetupScenario Initialize-SqlServerPrerequisites.ps1 -Parameters $sql -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'SQL preparation refuses domain controllers'
Reset-RootSetupMock;$global:rootServerSetupMock.ReparsePath='D:\Sql';$summary=Invoke-RootSetupScenario Initialize-SqlServerPrerequisites.ps1 -Parameters $sql -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'SQL preparation refuses a reparse-point ancestor'
Reset-RootSetupMock;$global:rootServerSetupMock.SqlCreateRace=$true;$summary=Invoke-RootSetupScenario Initialize-SqlServerPrerequisites.ps1 -Parameters $sql -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 1 -and -not $global:rootServerSetupMock.Acls[$sql.DataPath].AreAccessRulesProtected) 'SQL detects native existing-directory return with unverified ACL and never rewrites it'

# Backup policies are newly created only; existing scheduled policies are never overwritten.
$backupConfigPath=Join-Path $OutputDirectory 'backup.json'
$backupConfig=@{SchemaVersion=1;SourceVolumes=@('D:');TargetVolume='E:';DailySchedule=@('01:00','13:00');IncludeSystemState=$true;IncludeBareMetal=$true;MinimumTargetFreeGB=20}
$backupConfig | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupConfigPath -Encoding UTF8
$backup=@{ConfigurationPath=$backupConfigPath}
Reset-RootSetupMock;$summary=Invoke-RootSetupScenario Install-WindowsServerBackup.ps1 -Parameters $backup
Assert-RootSetupTest ($summary.State -eq 'Plan' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Backup plan does not create or schedule a policy'
$summary=Invoke-RootSetupScenario Install-WindowsServerBackup.ps1 -Parameters $backup -Apply -WhatIf
Assert-RootSetupTest ($summary.State -eq 'Incomplete' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Backup WhatIf leaves policy absent'
$summary=Invoke-RootSetupScenario Install-WindowsServerBackup.ps1 -Parameters $backup -Apply
Assert-RootSetupTest ($summary.State -eq 'Complete' -and ($global:rootServerSetupMock.Mutations -join ',') -eq 'BackupPolicy') 'Backup apply creates one scheduled policy'
Assert-RootSetupTest ($global:rootServerSetupMock.BackupPolicy.VssCopy -and $global:rootServerSetupMock.BackupPolicy.SystemState -and $global:rootServerSetupMock.BackupPolicy.BareMetal -and $global:rootServerSetupMock.BackupPolicy.Schedule.Count -eq 2) 'Backup policy sets explicit VSS-copy, recovery inclusions, and schedule'
$existingPolicy=$global:rootServerSetupMock.BackupPolicy;$before=$global:rootServerSetupMock.Mutations.Count;$summary=Invoke-RootSetupScenario Install-WindowsServerBackup.ps1 -Parameters $backup -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq $before -and [object]::ReferenceEquals($existingPolicy,$global:rootServerSetupMock.BackupPolicy)) 'Existing scheduled backup policy remains untouched'
foreach($appearanceRead in @(2,3)){
    Reset-RootSetupMock;$global:rootServerSetupMock.BackupPolicyAppearsOnRead=$appearanceRead;$summary=Invoke-RootSetupScenario Install-WindowsServerBackup.ps1 -Parameters $backup -Apply
    Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0 -and $global:rootServerSetupMock.BackupPolicy.Existing -eq 'Concurrent policy, preserve unchanged') ('Backup policy created after preflight remains untouched at read '+$appearanceRead)
}
Reset-RootSetupMock;$global:rootServerSetupMock.FeatureInstalled=$false;$summary=Invoke-RootSetupScenario Install-WindowsServerBackup.ps1 -Apply
Assert-RootSetupTest ($summary.State -eq 'Complete' -and ($global:rootServerSetupMock.Mutations -join ',') -eq 'Role') 'Backup role-only setup does not schedule or launch a backup'
Reset-RootSetupMock;$invalidBackup=$backupConfig.Clone();$invalidBackup.TargetVolume='D:';$invalidBackup | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupConfigPath -Encoding UTF8;$summary=Invoke-RootSetupScenario Install-WindowsServerBackup.ps1 -Parameters $backup -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Backup source/target overlap blocks scheduling'

# NPS role/client setup keeps plaintext transient and does not overwrite existing client secrets.
Reset-RootSetupMock;$global:rootServerSetupMock.PartOfDomain=$true
$nps=@{RadiusClientName='MockSwitch';RadiusClientAddress='192.0.2.50';SharedSecret=(ConvertTo-SecureString $global:rootServerSetupMock.Marker -AsPlainText -Force)}
$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Parameters $nps
Assert-RootSetupTest ($summary.State -eq 'Plan' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'NPS plan creates no clients'
$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Parameters $nps -Apply -WhatIf
Assert-RootSetupTest ($summary.State -eq 'Incomplete' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'NPS WhatIf does not reveal or submit secrets'
$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Parameters $nps -Apply
Assert-RootSetupTest ($summary.State -eq 'ServiceRestartRequired' -and $summary.ServiceRestarts[0].Decision -eq 'DeferredByOption' -and ($global:rootServerSetupMock.Mutations -join ',') -eq 'NpsClient' -and $global:rootServerSetupMock.NpsClients.Count -eq 1 -and $global:rootServerSetupMock.NpsClients[0].AuthAttributeRequired) 'NPS creates one Message-Authenticator-protected client and defers required service restart'
$before=$global:rootServerSetupMock.Mutations.Count;$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Parameters $nps -Apply
Assert-RootSetupTest ($summary.State -eq 'Complete' -and $global:rootServerSetupMock.Mutations.Count -eq $before) 'Matching NPS client is not rewritten or rotated'
$global:rootServerSetupMock.NpsClients[0].Enabled=$false;$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Parameters $nps -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq $before) 'Disabled existing NPS client requires manual review'
Reset-RootSetupMock;$global:rootServerSetupMock.PartOfDomain=$true;$global:rootServerSetupMock.NpsFails=$true;$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Parameters $nps -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.NpsClients.Count -eq 0) 'NPS cmdlet error containing secret is redacted and stops setup'
Reset-RootSetupMock;$global:rootServerSetupMock.PartOfDomain=$true;$shortNps=$nps.Clone();$shortNps.SharedSecret=ConvertTo-SecureString 'short' -AsPlainText -Force;$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Parameters $shortNps -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'Short new RADIUS secret is refused before submission'
Reset-RootSetupMock;$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Apply
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $global:rootServerSetupMock.Mutations.Count -eq 0) 'NPS refuses setup before intended domain join'
Reset-RootSetupMock;$global:rootServerSetupMock.PartOfDomain=$true;$global:rootServerSetupMock.FeatureInstalled=$false;$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Apply
Assert-RootSetupTest ($summary.State -eq 'Complete' -and ($global:rootServerSetupMock.Mutations -join ',') -eq 'Role') 'NPS role-only setup does not create policies or clients'
Reset-RootSetupMock;$global:rootServerSetupMock.PartOfDomain=$true;$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Parameters $nps -Apply -AskForRestart
Assert-RootSetupTest ($summary.State -eq 'ServiceRestartRequired' -and $summary.ServiceRestarts[0].Decision -eq 'Declined' -and $global:rootServerSetupMock.ServiceConsentCount -eq 1 -and $global:rootServerSetupMock.ServiceRestartCount -eq 0) 'NPS service restart requires separate positive consent'
Reset-RootSetupMock;$global:rootServerSetupMock.PartOfDomain=$true;$global:rootServerSetupMock.ServiceConsent=$true;$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Parameters $nps -Apply -AskForRestart
Assert-RootSetupTest ($summary.State -eq 'Complete' -and $summary.ServiceRestarts[0].Decision -eq 'Restarted' -and $global:rootServerSetupMock.ServiceConsentCount -eq 1 -and $global:rootServerSetupMock.ServiceRestartCount -eq 1) 'NPS service restarts once after separate positive consent'
Reset-RootSetupMock;$global:rootServerSetupMock.PartOfDomain=$true;$global:rootServerSetupMock.ServiceConsent=$true;$global:rootServerSetupMock.ServiceRestartFails=$true;$summary=Invoke-RootSetupScenario Install-NpsServer.ps1 -Parameters $nps -Apply -AskForRestart
Assert-RootSetupTest ($summary.State -eq 'Blocked' -and $summary.ServiceRestarts[0].Decision -eq 'RequestFailed' -and $global:rootServerSetupMock.ServiceRestartCount -eq 1) 'Failed NPS service restart is reported without retry'

[pscustomobject]@{Suite='Server baseline and key roles';Passed=$script:rootAssertions;Failed=0;LiveSystemsTested=$false;OutputDirectory=$OutputDirectory}
