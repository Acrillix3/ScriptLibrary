<#
What it does:
  Tests file-server, print-server, and FSRM setup behavior with mocked Windows management commands.

Available flags:
  -ScriptsDirectory: Folder containing the three standalone setup scripts.
  -OutputDirectory: Local folder for test fixtures and reports.

How it works:
  Copies each script and replaces only the administrator identity probe with a test identity. All server providers and target-folder mutations are mocked; no server role or production setting changes.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$ScriptsDirectory,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $ScriptsDirectory){$ScriptsDirectory=Join-Path $PSScriptRoot '..\Server-Setup'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$OutputDirectory=Join-Path $OutputDirectory ('st-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $OutputDirectory -Force
$script:assertions=0
$global:storagePrintMock=@{}
function Assert-StorageTest {param([bool]$Condition,[string]$Message) $script:assertions++;if(-not $Condition){throw ('Assertion failed: '+$Message)}}
function Reset-StorageMock {
    $global:storagePrintMock=@{FeatureInstalled=$true;Restart='No';FailMutation='';NonEmpty=@{};Paths=@{'D:\'= $true;'D:\MockShares'=$true};Acls=@{};Shares=(New-Object 'System.Collections.Generic.List[object]');Ports=(New-Object 'System.Collections.Generic.List[object]');Queues=(New-Object 'System.Collections.Generic.List[object]');Quotas=(New-Object 'System.Collections.Generic.List[object]');AutoQuotas=@();Mutations=(New-Object 'System.Collections.Generic.List[string]');DriverAvailable=$true;Build='20348';Spooler='Running'}
}
function Get-CimInstance {
    [CmdletBinding()]param([string]$ClassName,[string]$Filter)
    switch($ClassName){
        Win32_OperatingSystem {[pscustomobject]@{Caption='Microsoft Windows Server 2022';BuildNumber=$global:storagePrintMock.Build;ProductType=3}}
        Win32_ComputerSystem {[pscustomobject]@{Name='MOCK-SERVER';DomainRole=3;PartOfDomain=$true;Domain='example.test'}}
        Win32_LogicalDisk {[pscustomobject]@{DeviceID='D:';DriveType=3;FileSystem='NTFS'}}
        default {throw 'Unexpected CIM query.'}
    }
}
function Test-Path {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Path,[string]$PathType)
    $p=if($LiteralPath){$LiteralPath}else{$Path}
    if($p.StartsWith('HKLM:',[StringComparison]::OrdinalIgnoreCase)){return $false}
    if($p.StartsWith('D:\',[StringComparison]::OrdinalIgnoreCase)){return $global:storagePrintMock.Paths.ContainsKey($p)}
    return Microsoft.PowerShell.Management\Test-Path -LiteralPath $p -PathType $(if($PathType){$PathType}else{'Any'})
}
function Get-ItemProperty {
    [CmdletBinding()]param([string]$LiteralPath)
    if($LiteralPath -like '*Session Manager'){return [pscustomobject]@{PendingFileRenameOperations=@()}}
    return [pscustomobject]@{ComputerName='MOCK-SERVER'}
}
function Get-Item {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Force)
    if($LiteralPath.StartsWith('D:\',[StringComparison]::OrdinalIgnoreCase)){
        if(-not $global:storagePrintMock.Paths.ContainsKey($LiteralPath)){throw 'Mock path absent.'}
        return [pscustomobject]@{PSIsContainer=$true;FullName=$LiteralPath;Attributes=[IO.FileAttributes]::Directory}
    }
    return Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force
}
function Get-ChildItem {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Force)
    if($LiteralPath.StartsWith('D:\',[StringComparison]::OrdinalIgnoreCase)){if($global:storagePrintMock.NonEmpty.ContainsKey($LiteralPath)){[pscustomobject]@{Name='existing.txt'}};return}
    Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Force:$Force
}
function New-Item {
    [CmdletBinding(SupportsShouldProcess=$true)]param([string]$ItemType,[string]$Path,[switch]$Force)
    if($Path.StartsWith('D:\',[StringComparison]::OrdinalIgnoreCase)){$global:storagePrintMock.Mutations.Add('Folder');$global:storagePrintMock.Paths[$Path]=$true;return [pscustomobject]@{FullName=$Path}}
    Microsoft.PowerShell.Management\New-Item -ItemType $ItemType -Path $Path -Force:$Force -Confirm:$false -WhatIf:$false
}
function Get-Acl {[CmdletBinding()]param([string]$LiteralPath) if(-not $global:storagePrintMock.Acls.ContainsKey($LiteralPath)){throw 'No mock ACL.'};$global:storagePrintMock.Acls[$LiteralPath]}
function Set-Acl {[CmdletBinding(SupportsShouldProcess=$true)]param([string]$LiteralPath,$AclObject) $global:storagePrintMock.Mutations.Add('ACL');$global:storagePrintMock.Acls[$LiteralPath]=$AclObject}
function Get-WindowsFeature {[CmdletBinding()]param([string]$Name) [pscustomobject]@{Name=$Name;Installed=$global:storagePrintMock.FeatureInstalled}}
function Install-WindowsFeature {
    [CmdletBinding()]param([string]$Name,[switch]$IncludeManagementTools)
    $global:storagePrintMock.Mutations.Add('Role');[pscustomobject]@{Success=$true;RestartNeeded=$global:storagePrintMock.Restart}
}
function Get-SmbShare {[CmdletBinding()]param() $global:storagePrintMock.Shares.ToArray()}
function Get-SmbShareAccess {
    [CmdletBinding()]param([string]$Name)
    $share=$global:storagePrintMock.Shares | Where-Object Name -eq $Name | Select-Object -First 1
    $share.MockAccess
}
function New-SmbShare {
    [CmdletBinding(SupportsShouldProcess=$true)]param([string]$Name,[string]$Path,[string]$Description,[bool]$EncryptData,[string]$FolderEnumerationMode,[string]$CachingMode,[string[]]$FullAccess,[string[]]$ChangeAccess,[string[]]$ReadAccess)
    $global:storagePrintMock.Mutations.Add('Share');if($global:storagePrintMock.FailMutation -eq 'Share'){throw 'Mock share failure.'}
    $access=@();foreach($mapping in @(@($FullAccess,'Full'),@($ChangeAccess,'Change'),@($ReadAccess,'Read'))){foreach($account in @($mapping[0])){if($account){$access += [pscustomobject]@{AccountName=$account;AccessControlType='Allow';AccessRight=$mapping[1]}}}}
    $share=[pscustomobject]@{Name=$Name;Path=$Path;Description=$Description;EncryptData=$EncryptData;FolderEnumerationMode=$FolderEnumerationMode;CachingMode=$CachingMode;Special=$false;MockAccess=$access}
    $global:storagePrintMock.Shares.Add($share);$share
}
function Get-Service {[CmdletBinding()]param([string]$Name) [pscustomobject]@{Name=$Name;Status=$global:storagePrintMock.Spooler}}
function Get-PrinterDriver {[CmdletBinding()]param() if($global:storagePrintMock.DriverAvailable){[pscustomobject]@{Name='Mock Signed Driver';PrinterEnvironment='Windows x64'}}}
function Get-PrinterPort {[CmdletBinding()]param() $global:storagePrintMock.Ports.ToArray()}
function Get-Printer {[CmdletBinding()]param([switch]$Full) $global:storagePrintMock.Queues.ToArray()}
function Add-PrinterPort {
    [CmdletBinding(SupportsShouldProcess=$true)]param([string]$Name,[string]$PrinterHostAddress,[uint32]$PortNumber,[uint32]$SNMP)
    $global:storagePrintMock.Mutations.Add('Port');$port=[pscustomobject]@{Name=$Name;PrinterHostAddress=$PrinterHostAddress;PortNumber=$PortNumber;Protocol=1;SNMPEnabled=($SNMP -ne 0)};$global:storagePrintMock.Ports.Add($port);$port
}
function Add-Printer {
    [CmdletBinding(SupportsShouldProcess=$true)]param([string]$Name,[string]$DriverName,[string]$PortName,[switch]$Shared,[string]$ShareName,[string]$PermissionSDDL,[string]$Location,[string]$Comment)
    $global:storagePrintMock.Mutations.Add('Queue');if($global:storagePrintMock.FailMutation -eq 'Queue'){throw 'Mock queue failure.'}
    $queue=[pscustomobject]@{Name=$Name;DriverName=$DriverName;PortName=$PortName;Shared=[bool]$Shared;ShareName=$ShareName;PermissionSDDL=$PermissionSDDL;Location=$Location;Comment=$Comment;Published=$false;KeepPrintedJobs=$false};$global:storagePrintMock.Queues.Add($queue);$queue
}
function Get-FsrmQuota {[CmdletBinding()]param() $global:storagePrintMock.Quotas.ToArray()}
function Get-FsrmAutoQuota {[CmdletBinding()]param() $global:storagePrintMock.AutoQuotas}
function New-FsrmQuota {
    [CmdletBinding(SupportsShouldProcess=$true)]param([string]$Path,[uint64]$Size,[string]$Description,[switch]$SoftLimit)
    $global:storagePrintMock.Mutations.Add('Quota');$quota=[pscustomobject]@{Path=$Path;Size=$Size;Description=$Description;SoftLimit=[bool]$SoftLimit;Disabled=$false;Template=$null;Threshold=@()};$global:storagePrintMock.Quotas.Add($quota);$quota
}

$testScripts=@{}
foreach($name in @('Install-FileServer.ps1','Install-PrintServer.ps1','Install-FsrmServer.ps1')){
    $source=Get-Content -LiteralPath (Join-Path $ScriptsDirectory $name) -Raw
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
    Assert-StorageTest (-not $errors) ($name+' parses')
    $probe=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-SetupAdministrator'},$true)
    Assert-StorageTest ($null -ne $probe) ($name+' has an administrator gate')
    $source=$source.Substring(0,$probe.Extent.StartOffset)+'function Test-SetupAdministrator { return $true }'+$source.Substring($probe.Extent.EndOffset)
    $path=Join-Path $OutputDirectory $name
    [IO.File]::WriteAllText($path,$source,(New-Object Text.UTF8Encoding($true)))
    $testScripts[$name]=$path
}
$configPath=Join-Path $OutputDirectory 'configuration.json'
function Invoke-StorageScenario {
    param([string]$Name,$Config,[switch]$Apply,[switch]$WhatIf)
    $arguments=@{OutputDirectory=(Join-Path $OutputDirectory 'reports');Confirm=$false;SkipRestartPrompt=$true}
    if($null -ne $Config){$Config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $configPath -Encoding UTF8;$arguments.ConfigurationPath=$configPath}
    if($Apply){$arguments.Apply=$true};if($WhatIf){$arguments.WhatIf=$true}
    $result=@(& $testScripts[$Name] @arguments)
    $summary=@($result | Where-Object {$_.PSObject.Properties['State'] -and $_.PSObject.Properties['ReportDirectory']})
    Assert-StorageTest ($summary.Count -eq 1) ($Name+' emits one summary')
    Assert-StorageTest (Microsoft.PowerShell.Management\Test-Path -LiteralPath (Join-Path $summary[0].ReportDirectory 'summary.json')) ($Name+' saves report')
    return $summary[0]
}
function New-FileTestConfig {
    @{Shares=@(@{Name='Data';Path='D:\MockShares\Data';Description='Test share';FullAccess=@('BUILTIN\Administrators');ChangeAccess=@();ReadAccess=@()})}
}
function New-PrintTestConfig {
    @{Printers=@(@{Name='Office';DriverName='Mock Signed Driver';Address='192.0.2.50';PortNumber=9100;Shared=$true;ShareName='OfficePrinter';Location='Lab';Comment='Test';PrintUsers=@('BUILTIN\Administrators')})}
}
function New-FsrmTestConfig {
    @{Quotas=@(@{Path='D:\MockShares\Data';SizeGB=10;SoftLimit=$true;Description='Test quota'})}
}

# File creation, idempotence, permission drift, atomic preflight, and stopped writes.
Reset-StorageMock;$config=New-FileTestConfig
$summary=Invoke-StorageScenario -Name Install-FileServer.ps1 -Config $config
Assert-StorageTest ($summary.State -eq 'Plan' -and $global:storagePrintMock.Mutations.Count -eq 0) 'File plan performs no setup changes'
$summary=Invoke-StorageScenario -Name Install-FileServer.ps1 -Config $config -Apply -WhatIf
Assert-StorageTest ($global:storagePrintMock.Mutations.Count -eq 0 -and $summary.State -eq 'Incomplete') 'File WhatIf does not create folders or shares'
$summary=Invoke-StorageScenario -Name Install-FileServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Complete' -and ($global:storagePrintMock.Mutations -join ',') -eq 'Folder,ACL,Share') 'File apply orders secured folder before share'
Assert-StorageTest ($global:storagePrintMock.Shares[0].EncryptData -and $global:storagePrintMock.Shares[0].CachingMode -eq 'None') 'SMB secure settings passed'
$before=$global:storagePrintMock.Mutations.Count;$summary=Invoke-StorageScenario -Name Install-FileServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Complete' -and $global:storagePrintMock.Mutations.Count -eq $before) 'Matching file setup is idempotent'
$global:storagePrintMock.Shares[0].EncryptData=$false;$summary=Invoke-StorageScenario -Name Install-FileServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Blocked' -and $global:storagePrintMock.Mutations.Count -eq $before) 'Share drift blocks changes'
Reset-StorageMock;$config=New-FileTestConfig;$bad=@{Name='Bad';Path='D:\MockShares\Bad';FullAccess=@('Everyone')};$config.Shares+= $bad
$summary=Invoke-StorageScenario -Name Install-FileServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Blocked' -and $global:storagePrintMock.Mutations.Count -eq 0) 'Invalid final share blocks earlier valid share'
Reset-StorageMock;$global:storagePrintMock.FailMutation='Share';$config=New-FileTestConfig;$summary=Invoke-StorageScenario -Name Install-FileServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Blocked' -and $global:storagePrintMock.Shares.Count -eq 0) 'Share failure is reported and stops setup'
Reset-StorageMock;$global:storagePrintMock.FeatureInstalled=$false;$global:storagePrintMock.Restart='Yes';$summary=Invoke-StorageScenario -Name Install-FileServer.ps1 -Config (New-FileTestConfig) -Apply
Assert-StorageTest ($summary.RestartRequired -and ($global:storagePrintMock.Mutations -join ',') -eq 'Role') 'File role restart defers publishing'
Reset-StorageMock;$global:storagePrintMock.Paths['D:\MockShares\Data']=$true;$summary=Invoke-StorageScenario -Name Install-FileServer.ps1 -Config (New-FileTestConfig) -Apply
Assert-StorageTest ($summary.State -eq 'Blocked' -and $global:storagePrintMock.Mutations.Count -eq 0) 'Unreadable existing ACL blocks before mutation'

# Printer drivers, explicit permissions, shared ports, queue drift, and role-only setup.
Reset-StorageMock;$config=New-PrintTestConfig;$summary=Invoke-StorageScenario -Name Install-PrintServer.ps1 -Config $config
Assert-StorageTest ($summary.State -eq 'Plan' -and $global:storagePrintMock.Mutations.Count -eq 0) 'Print plan performs no setup changes'
$summary=Invoke-StorageScenario -Name Install-PrintServer.ps1 -Config $config -Apply -WhatIf
Assert-StorageTest ($summary.State -eq 'Incomplete' -and $global:storagePrintMock.Mutations.Count -eq 0) 'Print WhatIf performs no setup changes'
$summary=Invoke-StorageScenario -Name Install-PrintServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Complete' -and ($global:storagePrintMock.Mutations -join ',') -eq 'Port,Queue') 'Print apply creates port before queue'
Assert-StorageTest (-not $global:storagePrintMock.Ports[0].SNMPEnabled -and $global:storagePrintMock.Queues[0].PermissionSDDL -notmatch ';;;WD\)') 'Printer uses explicit ACL without Everyone and no SNMP polling'
$before=$global:storagePrintMock.Mutations.Count;$summary=Invoke-StorageScenario -Name Install-PrintServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Complete' -and $global:storagePrintMock.Mutations.Count -eq $before) 'Matching printer setup is idempotent'
$global:storagePrintMock.Ports[0].PortNumber=515;$summary=Invoke-StorageScenario -Name Install-PrintServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Blocked' -and $global:storagePrintMock.Mutations.Count -eq $before) 'Port drift blocks all configuration changes'
Reset-StorageMock;$global:storagePrintMock.DriverAvailable=$false;$summary=Invoke-StorageScenario -Name Install-PrintServer.ps1 -Config (New-PrintTestConfig) -Apply
Assert-StorageTest ($summary.State -eq 'Blocked' -and $global:storagePrintMock.Mutations.Count -eq 0) 'Missing exact approved driver blocks setup'
Reset-StorageMock;$config=New-PrintTestConfig;$second=$config.Printers[0].Clone();$second.Name='Second';$second.ShareName='SecondPrinter';$config.Printers+= $second
$summary=Invoke-StorageScenario -Name Install-PrintServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Complete' -and @($global:storagePrintMock.Mutations | Where-Object {$_ -eq 'Port'}).Count -eq 1 -and $global:storagePrintMock.Queues.Count -eq 2) 'Two queues reuse one configured port'
Reset-StorageMock;$global:storagePrintMock.FeatureInstalled=$false;$summary=Invoke-StorageScenario -Name Install-PrintServer.ps1 -Config $null -Apply
Assert-StorageTest ($summary.State -eq 'Complete' -and ($global:storagePrintMock.Mutations -join ',') -eq 'Role') 'Print role-only installation works without queue tools'
Reset-StorageMock;$global:storagePrintMock.Spooler='Stopped';$summary=Invoke-StorageScenario -Name Install-PrintServer.ps1 -Config (New-PrintTestConfig) -Apply
Assert-StorageTest ($summary.State -eq 'Blocked' -and $global:storagePrintMock.Mutations.Count -eq 0) 'Stopped spooler is not automatically restarted'

# Quota defaults, hard-quota safeguards, overlapping policies, drift, and NTFS scope.
Reset-StorageMock;$global:storagePrintMock.Paths['D:\MockShares\Data']=$true;$config=New-FsrmTestConfig
$summary=Invoke-StorageScenario -Name Install-FsrmServer.ps1 -Config $config
Assert-StorageTest ($summary.State -eq 'Plan' -and $global:storagePrintMock.Mutations.Count -eq 0) 'Quota plan performs no setup changes'
$summary=Invoke-StorageScenario -Name Install-FsrmServer.ps1 -Config $config -Apply -WhatIf
Assert-StorageTest ($summary.State -eq 'Incomplete' -and $global:storagePrintMock.Mutations.Count -eq 0) 'Quota WhatIf performs no setup changes'
$summary=Invoke-StorageScenario -Name Install-FsrmServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Complete' -and $global:storagePrintMock.Quotas[0].Size -eq 10GB -and $global:storagePrintMock.Quotas[0].SoftLimit) 'Soft quota uses explicit byte size'
$before=$global:storagePrintMock.Mutations.Count;$summary=Invoke-StorageScenario -Name Install-FsrmServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Complete' -and $global:storagePrintMock.Mutations.Count -eq $before) 'Matching quota is idempotent'
$global:storagePrintMock.Quotas[0].Size=20GB;$summary=Invoke-StorageScenario -Name Install-FsrmServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Blocked' -and $global:storagePrintMock.Mutations.Count -eq $before) 'Quota drift never resizes an existing quota'
Reset-StorageMock;$global:storagePrintMock.Paths['D:\MockShares\Data']=$true;$global:storagePrintMock.NonEmpty['D:\MockShares\Data']=$true;$config=New-FsrmTestConfig;$config.Quotas[0].SoftLimit=$false
$summary=Invoke-StorageScenario -Name Install-FsrmServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Blocked' -and $global:storagePrintMock.Mutations.Count -eq 0) 'New hard quota rejects populated folder'
Reset-StorageMock;$global:storagePrintMock.Paths['D:\MockShares\Data']=$true;$global:storagePrintMock.AutoQuotas=@([pscustomobject]@{Path='D:\MockShares'});$summary=Invoke-StorageScenario -Name Install-FsrmServer.ps1 -Config (New-FsrmTestConfig) -Apply
Assert-StorageTest ($summary.State -eq 'Blocked' -and $global:storagePrintMock.Mutations.Count -eq 0) 'Overlapping auto-quota blocks setup'
Reset-StorageMock;$global:storagePrintMock.Paths['D:\MockShares\Data']=$true;$config=New-FsrmTestConfig;$config.Quotas[0].SoftLimit='false';$summary=Invoke-StorageScenario -Name Install-FsrmServer.ps1 -Config $config -Apply
Assert-StorageTest ($summary.State -eq 'Blocked' -and $global:storagePrintMock.Mutations.Count -eq 0) 'String false cannot silently enable a hard quota'
Reset-StorageMock;$global:storagePrintMock.FeatureInstalled=$false;$summary=Invoke-StorageScenario -Name Install-FsrmServer.ps1 -Config $null -Apply
Assert-StorageTest ($summary.State -eq 'Complete' -and ($global:storagePrintMock.Mutations -join ',') -eq 'Role') 'FSRM role-only installation works'

[pscustomobject]@{Suite='Storage and print setup';Passed=$script:assertions;Failed=0;LiveSystemsTested=$false;OutputDirectory=$OutputDirectory}
