<#
What it does:
  Runs VBR repository, SOBR, WAN, proxy, platform and security mocks without contacting Veeam, Windows hosts, or databases.

Available flags:
  -WindowsRoot: Windows category root to validate; default parent of this folder.
  -OutputDirectory: Mock report destination; default Windows\Reports.

How it works:
  Replaces provider commands with local fixtures, runs production scripts, and asserts
  failures, partial evidence, limits, compatibility and secret exclusion. Throws on failure.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$WindowsRoot,[string]$OutputDirectory)
if(-not $WindowsRoot){$WindowsRoot=Split-Path $PSScriptRoot -Parent}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $WindowsRoot 'Reports'}
$SourceRoot=$WindowsRoot
$ReportRoot=$OutputDirectory
$ErrorActionPreference='Stop'
$base=Split-Path $PSScriptRoot -Parent
$staged=Join-Path $WindowsRoot 'Veeam-Backup-and-Replication-v12'
$reportBase=Join-Path $OutputDirectory ('vi-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$global:InfraFixtureFailure='';$global:InfraFixtureShape='';$global:InfraFixtureVersion='12.3.2.4854';$global:InfraFixtureCalls=New-Object 'System.Collections.Generic.List[string]';$script:assertions=0
function Assert-Infra {param([bool]$Condition,[string]$Description) if(-not $Condition){throw ('FAILED: '+$Description)};$script:assertions++}
function Invoke-InfraMockGuard {param([string]$Name) $global:InfraFixtureCalls.Add($Name);if($global:InfraFixtureFailure -eq $Name){throw ('DO-NOT-EXPORT mocked vendor error with secret for '+$Name)}}
function Import-Module {[CmdletBinding()]param($Name,[switch]$PassThru) Invoke-InfraMockGuard 'Import';if($PassThru){[pscustomobject]@{Version=[version]$global:InfraFixtureVersion;Name=$Name}}}
function Invoke-Command {[CmdletBinding()]param($ComputerName,$ScriptBlock,$ArgumentList,$Credential) Invoke-InfraMockGuard 'VersionProbe';[pscustomobject]@{ProductVersion=$global:InfraFixtureVersion}}
function Get-CimInstance {[CmdletBinding()]param($ClassName,$Filter) throw 'Tests must not query local services.'}
function Connect-VBRServer {[CmdletBinding()]param($Server,$Port,$Credential) Invoke-InfraMockGuard 'Connect';$global:InfraFixtureLastServer=$Server}
function Disconnect-VBRServer {[CmdletBinding()]param() Invoke-InfraMockGuard 'Disconnect'}
function Get-VBRBackupServerInfo {[CmdletBinding()]param() Invoke-InfraMockGuard 'Build';[pscustomobject]@{Name='vbr-fixture';Build=[version]$global:InfraFixtureVersion;PatchLevel='fixture';RawCredentials='DO-NOT-EXPORT'}}
function Get-VBRBackupRepository {
    [CmdletBinding()]param([switch]$ScaleOut)
    if($ScaleOut){Invoke-InfraMockGuard 'ScaleOut';1..2 | ForEach-Object {[pscustomobject]@{Id=('sobr'+$_);Name=('SOBR'+$_);PolicyType='DataLocality';UsePerVMBackupFiles=$true;PerformFullWhenExtentOffline=$false;EncryptionKey='DO-NOT-EXPORT'}};return}
    Invoke-InfraMockGuard 'Repositories'
    if($global:InfraFixtureShape -eq 'EmptyRepositories'){return}
    [pscustomobject]@{Id='repo1';Name='Repo1';Type='Linux';CapacityBytes=[int64]1000;FreeSpaceBytes=[int64]100;ImmutabilityEnabled=$true;Credential='DO-NOT-EXPORT'}
    [pscustomobject]@{Id='repo2';Name='Repo2';Type='Windows';CapacityBytes=$null;FreeSpaceBytes=$null;Credential='DO-NOT-EXPORT'}
    [pscustomobject]@{Id='repo3';Name='Repo3';Type='Windows';CachedTotalSpace=[pscustomobject]@{InBytes=[int64]1000};CachedFreeSpace=[pscustomobject]@{InBytes=[int64]800};ImmutabilityEnabled=$false}
}
function Get-VBRObjectStorageRepository {[CmdletBinding()]param() Invoke-InfraMockGuard 'ObjectRepositories';[pscustomobject]@{Id='object1';Name='Object1';Type='AmazonS3';CapacityBytes=[int64]2000;FreeSpaceBytes=[int64]1000;Password='DO-NOT-EXPORT'};[pscustomobject]@{Id='object2';Name='Object2';Type='AzureBlob';SizeLimit=100;Credential='DO-NOT-EXPORT'}}
function Get-VBRRepositoryExtent {[CmdletBinding()]param($Repository) Invoke-InfraMockGuard 'PerformanceExtents';[pscustomobject]@{Id='extent1';ParentId=$Repository.Id;Repository=[pscustomobject]@{Id='repo1';Name='Repo1';Password='DO-NOT-EXPORT'};Status='Normal'};[pscustomobject]@{Id='extent2';ParentId=$Repository.Id;Repository=[pscustomobject]@{Id='repo2';Name='Repo2'};Status='Maintenance'}}
function Get-VBRCapacityExtent {[CmdletBinding()]param($Repository) Invoke-InfraMockGuard 'CapacityExtents';[pscustomobject]@{ParentId=$Repository.Id;Repository=[pscustomobject]@{Id='object1';Name='Object1'};Status=$(if($global:InfraFixtureShape -eq 'UnknownExtentStatus'){256}else{10})}}
function Get-VBRArchiveExtent {[CmdletBinding()]param($Repository) Invoke-InfraMockGuard 'ArchiveExtents';if($global:InfraFixtureShape -eq 'EmptyArchive'){return};[pscustomobject]@{ParentId=$Repository.Id;Repository=[pscustomobject]@{Id='archive1';Name='Archive1'};Status='Sealed'}}
function Get-VBRWANAccelerator {[CmdletBinding()]param() Invoke-InfraMockGuard 'WAN';[pscustomobject]@{Id='wan1';Name='Display name is not a host';Host=[pscustomobject]@{Name='wan-host1'};CachePath='D:\WAN';CacheSizeGB=100;Password='DO-NOT-EXPORT'};[pscustomobject]@{Id='wan2';Name='WAN2';Capacity=1000;CacheSize=1000;Credential='DO-NOT-EXPORT'}}
function Get-VBRViProxy {[CmdletBinding()]param() Invoke-InfraMockGuard 'VMwareProxies';[pscustomobject]@{Id='vi1';Name='LinuxProxy';Host=[pscustomobject]@{Name='linux-proxy';Type='Linux'};IsDisabled=$false;Options=[pscustomobject]@{TransportMode='Network';MaxTasksCount=4};Password='DO-NOT-EXPORT'};[pscustomobject]@{Id='vi2';Name='WindowsProxy';Host=[pscustomobject]@{Name='windows-proxy';Type='Windows'};IsDisabled='false';Password='DO-NOT-EXPORT'}}
function Get-VBRHvProxy {[CmdletBinding()]param() Invoke-InfraMockGuard 'HyperVProxies';[pscustomobject]@{Id='hv1';Name='HVProxy';Host=[pscustomobject]@{Name='hv-proxy';Type='Windows'};IsDisabled=$true;MaxTasksCount=2;Credential='DO-NOT-EXPORT'}}
function Get-VBRInstalledLicense {
    [CmdletBinding()]param()
    Invoke-InfraMockGuard 'License'
    $expiry=(Get-Date).AddDays(10);$licensed=100
    if($global:InfraFixtureShape -eq 'ObjectShapedLicense'){$expiry=[pscustomobject]@{Password='DO-NOT-EXPORT'};$licensed=[pscustomobject]@{Password='DO-NOT-EXPORT'}}
    $socketCount=$(if($global:InfraFixtureShape -eq 'SocketCap'){51}else{2})
    $socketRows=@(1..$socketCount | ForEach-Object {[pscustomobject]@{Type='vSphere';LicensedSocketsNumber=10;UsedSocketsNumber=5;RemainingSocketsNumber=5;Workload='DO-NOT-EXPORT'}})
    [pscustomobject]@{Status='Valid';Type='Subscription';Edition='EnterprisePlus';ExpirationDate=$expiry;SupportExpirationDate=(Get-Date).AddDays(20);LicensedTo='DO-NOT-EXPORT';SupportId='DO-NOT-EXPORT';LicenseFile='DO-NOT-EXPORT';InstanceLicenseSummary=[pscustomobject]@{LicensedInstancesNumber=$licensed;UsedInstancesNumber=50;Workload='DO-NOT-EXPORT'};SocketLicenseSummary=$socketRows}
}
function Get-VBRServer {[CmdletBinding()]param() Invoke-InfraMockGuard 'Servers';1..2 | ForEach-Object {[pscustomobject]@{Id=('server'+$_);Name=('server'+$_);Type='Windows';Credentials='DO-NOT-EXPORT'}}}
function Get-VBRUserRoleAssignment {[CmdletBinding()]param() Invoke-InfraMockGuard 'Roles';[pscustomobject]@{Id='role1';Name='EXAMPLE\VeeamAdmins';Type='Group';Role='BackupAdmin';Credential='DO-NOT-EXPORT'};[pscustomobject]@{Id='role2';Name='EXAMPLE\Readers';Type='Group';Role='BackupViewer'}}
function Get-VBRSecurityOptions {[CmdletBinding()]param() Invoke-InfraMockGuard 'SecurityOptions';[pscustomobject]@{AuditLogsPath='C:\Veeam\Audit';CompressOldAuditLogs=$true;FipsCompliantModeEnabled=$false;Certificate=[pscustomobject]@{PrivateKey='DO-NOT-EXPORT'};TrustedHosts='DO-NOT-EXPORT'}}
function Get-VBRConfigurationBackupJob {[CmdletBinding()]param() Invoke-InfraMockGuard 'ConfigurationEncryption';$encryption=$true;if($global:InfraFixtureShape -eq 'MissingEncryption'){$encryption=$null}elseif($global:InfraFixtureShape -eq 'StringEncryption'){$encryption='false'}elseif($global:InfraFixtureShape -eq 'DisabledEncryption'){$encryption=$false};[pscustomobject]@{Enabled=$true;EncryptionOptions=[pscustomobject]@{Enabled=$encryption;Key=[pscustomobject]@{Password='DO-NOT-EXPORT'}}}}
function Get-VBREncryptionKey {[CmdletBinding()]param() throw 'Encryption key getter must never be called.'}
function Get-VBRCredentials {[CmdletBinding()]param() throw 'Credential getter must never be called.'}
function Invoke-InfraFixture {
    param([string]$File,[hashtable]$Arguments=@{})
    if(-not $Arguments.ContainsKey('Server')){$Arguments.Server='vbr-fixture.example.test'}
    $Arguments.OutputDirectory=$reportBase;$Arguments.WarningAction='SilentlyContinue'
    & (Join-Path $staged $File) @Arguments
}
function Read-InfraEvidence {param($Summary,[string]$Name) @(Import-Csv -LiteralPath (Join-Path $Summary.ReportDirectory ($Name+'.csv')))}
$files=@('Get-VBRRepositoryAudit.ps1','Get-VBRScaleOutRepositoryAudit.ps1','Get-VBRWANAcceleratorAudit.ps1','Get-VBRProxyAudit.ps1','Get-VBRPlatformAudit.ps1','Get-VBRSecurityAudit.ps1')
foreach($file in $files){
    $source=Get-Content -LiteralPath (Join-Path $staged $file) -Raw;$tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
    Assert-Infra ($errors.Count -eq 0) ($file+' PowerShell 5.1 syntax')
    $header=$source.Substring(0,$source.IndexOf('#>'))
    foreach($parameter in $ast.ParamBlock.Parameters){Assert-Infra ($header -match ('(?m)^\s*-'+[regex]::Escape($parameter.Name.VariablePath.UserPath)+':')) ($file+' parameter documented: '+$parameter.Name.VariablePath.UserPath)}
    $bodyAst=$ast
    $mutations=@($bodyAst.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()} | Where-Object {$_ -match '^(Set|Start|Stop|Remove|Sync|Rescan|Mount|Clear|Update|Install|Enable|Disable)-VBR'})
    Assert-Infra ($mutations.Count -eq 0) ($file+' body has no vendor mutation commands')
}
$repository=Invoke-InfraFixture $files[0]
Assert-Infra ($repository.Data.RepositoryCount -eq 3 -and $repository.Data.ObjectStorageRepositoryCount -eq 2) 'Repository independent inventories counted'
Assert-Infra ($repository.Data.InspectedLowFreeSpaceCount -eq 1 -and $repository.Data.InspectedCapacityUnknownCount -eq 2) 'Repository thresholds and unknown values distinguished'
$repoRows=Read-InfraEvidence $repository 'repositories'
Assert-Infra (($repoRows | Where-Object Name -eq 'Repo3').CapacitySource -eq 'CachedTotalSpace.InBytes') 'Repository uses only exposed capacity property without internal method'
Assert-Infra (($repoRows | Where-Object Name -eq 'Object2').CapacityBytes -eq '') 'Unlabeled object quota never coerced to capacity'
Assert-Infra (@($repoRows | Where-Object { $_.InventorySource -eq 'ObjectStorage' -and $_.CloudQuotaAssessment -notlike 'Unknown*'}).Count -eq 0) 'Object account quota remains unknown'
$global:InfraFixtureFailure='Repositories';$repositoryFailure=Invoke-InfraFixture $files[0];$global:InfraFixtureFailure=''
Assert-Infra ($null -eq $repositoryFailure.Data.RepositoryCount -and $repositoryFailure.Data.RepositoryInventoryStatus -eq 'Unknown' -and $repositoryFailure.Data.ObjectStorageRepositoryCount -eq 2) 'Repository failure preserves object inventory without claiming zero repositories'
$global:InfraFixtureShape='EmptyRepositories';$repoEmpty=Invoke-InfraFixture $files[0];$global:InfraFixtureShape=''
Assert-Infra ($repoEmpty.Data.RepositoryCount -eq 0 -and $repoEmpty.Data.RepositoryInventoryStatus -eq 'Empty') 'Empty repository inventory distinct from failure'
$repoCap=Invoke-InfraFixture $files[0] @{MaxRepositories=1}
Assert-Infra ($repoCap.Data.RepositoryCapReached -and $repoCap.Data.ObjectStorageCapReached -and $repoCap.Data.RepositoryCount -eq 1) 'Repository caps detected independently'
$sobr=Invoke-InfraFixture $files[1]
Assert-Infra ($sobr.Data.ScaleOutRepositoryCount -eq 2 -and $sobr.Data.InspectedExtentCount -eq 8) 'SOBR all supported tiers independently enumerated'
$tierRows=Read-InfraEvidence $sobr 'tier-extents'
Assert-Infra (@($tierRows | Where-Object {$_.Tier -eq 'Capacity' -and $_.Maintenance -eq 'Yes' -and $_.Sealed -eq 'Yes'}).Count -eq 2) 'SOBR combined numeric capacity flags decoded'
Assert-Infra (@($tierRows | Where-Object {$_.Immutability -notlike 'Unknown*'}).Count -eq 0) 'SOBR sealed state never interpreted as immutability'
$global:InfraFixtureShape='UnknownExtentStatus';$sobrUnknownStatus=Invoke-InfraFixture $files[1];$global:InfraFixtureShape=''
$unknownStatusRows=Read-InfraEvidence $sobrUnknownStatus 'tier-extents'
Assert-Infra (@($unknownStatusRows | Where-Object {$_.Tier -eq 'Capacity' -and $_.FindingState -eq 'Unknown' -and $_.Maintenance -eq 'Unknown' -and $_.Sealed -eq 'Unknown'}).Count -eq 2) 'Unsupported extent status bits never imply no maintenance or no sealed state'
$global:InfraFixtureFailure='CapacityExtents';$sobrFailure=Invoke-InfraFixture $files[1];$global:InfraFixtureFailure=''
Assert-Infra ($sobrFailure.Data.InspectedExtentCount -eq 6 -and $sobrFailure.State -eq 'Incomplete') 'SOBR unsupported tier preserves performance and archive evidence'
$global:InfraFixtureShape='EmptyArchive';$sobrEmpty=Invoke-InfraFixture $files[1];$global:InfraFixtureShape=''
Assert-Infra (@((Read-InfraEvidence $sobrEmpty 'findings') | Where-Object {$_.Component -like '*Archive tier inventory' -and $_.State -eq 'NotApplicable'}).Count -eq 2) 'SOBR empty archive tier distinct from failed getter'
$sobrCap=Invoke-InfraFixture $files[1] @{MaxRepositories=1;MaxExtentsPerTier=1}
Assert-Infra ($sobrCap.Data.RepositoryCapReached -and $sobrCap.Data.CappedTierQueryCount -eq 1 -and $sobrCap.Data.InspectedExtentCount -eq 3) 'SOBR repository and per-tier caps explicit'
$wan=Invoke-InfraFixture $files[2]
Assert-Infra ($wan.Data.AcceleratorCount -eq 2 -and $wan.Data.AcceleratorsWithUnknownHost -eq 1 -and $wan.Data.AcceleratorsWithUnknownCacheSize -eq 1) 'WAN optional host/cache evidence preserves unknowns'
$wanRows=Read-InfraEvidence $wan 'wan-accelerators'
Assert-Infra (($wanRows | Where-Object Name -eq 'WAN2').ConfiguredCacheSizeGB -eq '') 'WAN unlabeled capacity and cache numbers not assumed GB'
Assert-Infra ($wan.Data.JobAssociations -eq 'Unknown') 'WAN job associations not guessed'
$global:InfraFixtureFailure='WAN';$wanFailure=Invoke-InfraFixture $files[2];$global:InfraFixtureFailure=''
Assert-Infra ($wanFailure.Data.InventoryStatus -eq 'Unknown' -and $null -eq $wanFailure.Data.AcceleratorCount) 'Unavailable WAN getter remains unknown rather than unhealthy or zero'
$wanCap=Invoke-InfraFixture $files[2] @{MaxAccelerators=1}
Assert-Infra ($wanCap.Data.AcceleratorCapReached -and $wanCap.Data.AcceleratorCount -eq 1) 'WAN cap explicit'
$proxy=Invoke-InfraFixture $files[3]
Assert-Infra ($proxy.Data.VMwareProxyCount -eq 2 -and $proxy.Data.HyperVProxyCount -eq 1) 'Proxy VMware and HyperV independent inventories'
Assert-Infra ($proxy.Data.InspectedUnknownEnabledStateCount -eq 1 -and $proxy.Data.InspectedDisabledProxyCount -eq 1) 'Proxy string false not treated as true or false boolean'
$proxyRows=Read-InfraEvidence $proxy 'backup-proxies'
Assert-Infra (($proxyRows | Where-Object Name -eq 'LinuxProxy').HostType -eq 'Linux') 'Linux VMware proxy host type exported from explicit field'
$global:InfraFixtureFailure='VMwareProxies';$proxyFailure=Invoke-InfraFixture $files[3];$global:InfraFixtureFailure=''
Assert-Infra ($null -eq $proxyFailure.Data.VMwareProxyCount -and $proxyFailure.Data.HyperVProxyCount -eq 1) 'Proxy VMware failure preserves HyperV evidence'
$proxyCap=Invoke-InfraFixture $files[3] @{MaxProxiesPerPlatform=1}
Assert-Infra ($proxyCap.Data.VMwareCapReached -and $proxyCap.Data.VMwareProxyCount -eq 1 -and -not $proxyCap.Data.HyperVCapReached) 'Proxy per-platform cap explicit'
$platform=Invoke-InfraFixture $files[4]
Assert-Infra ($platform.Data.BuildStatus -eq 'Collected' -and $platform.Data.LicenseStatus -eq 'Collected' -and $platform.Data.ManagedServerCount -eq 2) 'Platform build license and managed inventory collected'
$licenseRows=Read-InfraEvidence $platform 'license'
Assert-Infra ($licenseRows[0].LicensedInstances -eq '100' -and $licenseRows[0].ExpirationFlag -eq 'Within warning window') 'Platform safe license numeric/date projection'
$global:InfraFixtureFailure='License';$platformFailure=Invoke-InfraFixture $files[4];$global:InfraFixtureFailure=''
Assert-Infra ($platformFailure.Data.LicenseStatus -eq 'Unknown' -and $platformFailure.Data.ManagedServerCount -eq 2) 'License failure preserves platform server inventory'
$platformCap=Invoke-InfraFixture $files[4] @{MaxServers=1}
Assert-Infra ($platformCap.Data.ServerCapReached -and $platformCap.Data.ManagedServerCount -eq 1) 'Managed server cap explicit'
$global:InfraFixtureShape='ObjectShapedLicense';$platformObject=Invoke-InfraFixture $files[4];$global:InfraFixtureShape=''
$objectLicense=Read-InfraEvidence $platformObject 'license'
Assert-Infra ($objectLicense[0].ExpirationDate -eq '' -and $objectLicense[0].LicensedInstances -eq '' -and $objectLicense[0].ExpirationFlag -eq 'Unknown') 'Object-shaped license fields never serialized as scalar evidence'
$global:InfraFixtureShape='SocketCap';$platformSocket=Invoke-InfraFixture $files[4];$global:InfraFixtureShape=''
Assert-Infra ($platformSocket.Data.SocketSummaryCapReached -and (Read-InfraEvidence $platformSocket 'socket-license-summary').Count -eq 50) 'Defensive socket summary cap explicit'
$security=Invoke-InfraFixture $files[5]
Assert-Infra ($security.Data.RoleAssignmentCount -eq 2 -and $security.Data.AdministrativeAssignmentCount -eq 1 -and $security.Data.ConfigurationBackupEncryption -eq 'Enabled') 'Security roles and documented encryption enabled bool collected'
$global:InfraFixtureFailure='Roles';$securityFailure=Invoke-InfraFixture $files[5];$global:InfraFixtureFailure=''
Assert-Infra ($null -eq $securityFailure.Data.RoleAssignmentCount -and $securityFailure.Data.ConfigurationBackupEncryption -eq 'Enabled') 'Role access failure preserves independent encryption evidence'
foreach($shape in @('MissingEncryption','StringEncryption')){
    $global:InfraFixtureShape=$shape;$securityMissing=Invoke-InfraFixture $files[5];$global:InfraFixtureShape=''
    Assert-Infra ($securityMissing.Data.ConfigurationBackupEncryption -eq 'Unknown') ('Missing or wrong-type encryption does not mean disabled: '+$shape)
}
$global:InfraFixtureShape='DisabledEncryption';$securityDisabled=Invoke-InfraFixture $files[5];$global:InfraFixtureShape=''
Assert-Infra ($securityDisabled.Data.ConfigurationBackupEncryption -eq 'Disabled') 'Real false configuration encryption bool reported disabled'
$securityCap=Invoke-InfraFixture $files[5] @{MaxRoleAssignments=1}
Assert-Infra ($securityCap.Data.RoleCapReached -and $securityCap.Data.RoleAssignmentCount -eq 1) 'Role assignment cap explicit'
foreach($file in $files){
    $global:InfraFixtureVersion='13.0.0.1';$global:InfraFixtureCalls.Clear();$unsupported=Invoke-InfraFixture $file;$global:InfraFixtureVersion='12.3.2.4854'
    Assert-Infra (-not $unsupported.Context.ConnectionSucceeded -and -not $global:InfraFixtureCalls.Contains('Connect')) ($file+' unsupported major skips connection and body queries')
}
foreach($summary in @($repository,$sobr,$wan,$proxy,$platform,$platformObject,$security,$securityFailure)){
    foreach($name in @('summary.json','README.txt','findings.csv','collection-status.csv')){Assert-Infra (Test-Path -LiteralPath (Join-Path $summary.ReportDirectory $name)) ($summary.Script+' common artifact '+$name)}
    $allEvidence=(Get-ChildItem -LiteralPath $summary.ReportDirectory -File | Get-Content -Raw) -join ''
    Assert-Infra (-not $allEvidence.Contains('DO-NOT-EXPORT')) ($summary.Script+' raw vendor errors and secret fields excluded')
    Assert-Infra ($summary.Context.RemoteVersionVerified -and $summary.Context.ServerVersion -eq '12.3.2.4854') ($summary.Script+' management workstation target version verified')
}
Assert-Infra ($global:InfraFixtureLastServer -eq 'vbr-fixture.example.test') 'Requested management server passed to connection'
$global:InfraFixtureCalls.Clear();$localPlatform=Invoke-InfraFixture $files[4] @{Server='localhost'}
Assert-Infra ($localPlatform.Context.Server -eq 'localhost' -and $localPlatform.Context.ConnectionSucceeded -and $localPlatform.Data.ManagedServerCount -eq 2) 'Local console connection collects supported platform data'
Assert-Infra (-not $global:InfraFixtureCalls.Contains('VersionProbe') -and $localPlatform.Context.VersionSource -eq 'Get-VBRBackupServerInfo') 'Local console uses local probe path and connected server build evidence'
Write-Output ('PASS: {0} VBR infrastructure assertions under PowerShell {1}' -f $script:assertions,$PSVersionTable.PSVersion)
Write-Output ('Mock reports: '+$reportBase)
