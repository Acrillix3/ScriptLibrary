<#
What it does:
  Runs Microsoft 365 v7/v8 platform, tenant, proxy, repository, job and protection mocks without contacting Veeam, Windows hosts, or databases.

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
$suiteRoot=Split-Path $PSScriptRoot -Parent
$scriptRoot=Join-Path $WindowsRoot 'Veeam-Microsoft-365'
$resultRoot=Join-Path $OutputDirectory ('vbo-results-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $resultRoot -Force
$global:VboMockMajor=8;$global:VboMockScenario='Success';$global:VboLeakMarker='MOCK-DO-NOT-EXPORT-TOKEN-987654'
$global:VboConnectCalls=0;$global:VboDisconnectCalls=0;$global:VboPoolCalls=0;$global:VboLegacyCalls=0;$global:VboSessionCalls=0;$global:VboLastConnect=$null
$checks=New-Object 'System.Collections.Generic.List[object]'
function Assert-Vbo {
    param([bool]$Condition,[string]$Label)
    if(-not $Condition){throw ('FAILED: '+$Label)}
    $checks.Add([pscustomobject]@{Check=$Label;Result='Passed'})
}
function Add-MockPrivateFields {
    param([object]$InputObject)
    $InputObject | Add-Member -NotePropertyName Description -NotePropertyValue $global:VboLeakMarker -Force
    $InputObject | Add-Member -NotePropertyName ConnectionSettings -NotePropertyValue ([pscustomobject]@{Token=$global:VboLeakMarker;Credential=$global:VboLeakMarker}) -Force
    $InputObject | Add-Member -NotePropertyName ServiceAccount -NotePropertyValue $global:VboLeakMarker -Force
    $InputObject | Add-Member -NotePropertyName ScriptText -NotePropertyValue $global:VboLeakMarker -Force
    $InputObject
}
function Import-Module {
    [CmdletBinding()]param([string]$Name,[switch]$PassThru)
    if($Name -ne 'Veeam.Archiver.PowerShell'){throw 'Unexpected module import blocked'}
    [pscustomobject]@{Name=$Name;Version=[version]($global:VboMockMajor.ToString()+'.0.0.0')}
}
function Get-VBOVersion {[CmdletBinding()]param() [pscustomobject]@{ProductVersion=($global:VboMockMajor.ToString()+'.0.0.1000')}}
function Invoke-Command {
    [CmdletBinding()]param([string]$ComputerName,[scriptblock]$ScriptBlock,[object[]]$ArgumentList,[PSCredential]$Credential)
    if($global:VboMockScenario -eq 'HostUnavailable'){throw $global:VboLeakMarker}
    $major=$global:VboMockMajor;if($global:VboMockScenario -eq 'VersionMismatch'){$major=7}
    [pscustomobject]@{ProductVersion=($major.ToString()+'.0.0.2000')}
}
function Connect-VBOServer {
    [CmdletBinding()]param([string]$Server,[int]$Port,[PSCredential]$Credential)
    $global:VboConnectCalls++;$global:VboLastConnect=[pscustomobject]@{Server=$Server;Port=$Port}
    if($global:VboMockScenario -eq 'ConnectDenied'){throw $global:VboLeakMarker}
}
function Disconnect-VBOServer {[CmdletBinding()]param() $global:VboDisconnectCalls++}
function Get-Command {
    [CmdletBinding()]param([Parameter(Position=0)][string]$Name)
    $parameterNames=@{
        'Get-VBOSecuritySettings'=@();'Get-VBOServerComponents'=@();'Get-VBOProxy'=@('ExtendedView');'Get-VBOProxyPool'=@();'Get-VBORepository'=@('LongTerm');'Get-VBOObjectStorageRepository'=@();'Get-VBOBackupItem'=@('Job');'Get-VBOExcludedBackupItem'=@('Job');'Get-VBOJobSession'=@('JobType','Last');'Get-VBOJob'=@('Organization');'Get-VBORestorePoint'=@('Organization')
    }
    if(-not $parameterNames.ContainsKey($Name)){return}
    if($Name -eq 'Get-VBOProxyPool' -and ($global:VboMockMajor -eq 7 -or $global:VboMockScenario -eq 'PoolUnavailable')){return}
    $parameters=@{ErrorAction=$null}
    foreach($key in $parameterNames[$Name]){$parameters[$key]=$null}
    if($global:VboMockScenario -eq 'NoExtendedView' -and $Name -eq 'Get-VBOProxy'){$parameters.Remove('ExtendedView')}
    if($global:VboMockScenario -eq 'NoLongTerm' -and $Name -eq 'Get-VBORepository'){$parameters.Remove('LongTerm')}
    if($global:VboMockScenario -eq 'NoJobType' -and $Name -eq 'Get-VBOJobSession'){$parameters.Remove('JobType')}
    if($global:VboMockScenario -eq 'NoRestoreOrganization' -and $Name -eq 'Get-VBORestorePoint'){$parameters.Remove('Organization')}
    [pscustomobject]@{Name=$Name;Parameters=$parameters}
}
function Get-VBOServer {[CmdletBinding()]param() Add-MockPrivateFields ([pscustomobject]@{TempFolderPath='C:\MockVeeamTemp'})}
function Get-VBOLicense {[CmdletBinding()]param() Add-MockPrivateFields ([pscustomobject]@{Status='Valid';Type='Subscription';ExpirationDate=(Get-Date).AddDays(90);TotalNumber=100;UsedNumber=20;NewNumber=1;LicensedTo=$global:VboLeakMarker;Email=$global:VboLeakMarker;SupportId=$global:VboLeakMarker})}
function Get-VBOSecuritySettings {[CmdletBinding()]param() Add-MockPrivateFields ([pscustomobject]@{CertificateIssuedTo='CN=vbo.mock.test';CertificateIssuedBy='CN=Mock CA';CertificateThumbprint='ABCDEF';CertificateExpirationDate=(Get-Date).AddDays(90);PrivateKey=$global:VboLeakMarker})}
function Get-VBOServerComponents {
    [CmdletBinding()]param()
    foreach($index in 1,2){Add-MockPrivateFields ([pscustomobject]@{Id=('component-'+$index);Name='Proxy';ServerName=('proxy'+$index+'.mock.test');IsOnline=$true;ExtendedLoggingEnabled=$false;DistributedTracingEnabled=$false})}
}
function New-MockVboOrganization {
    param([int]$Index=1)
    Add-MockPrivateFields ([pscustomobject]@{Id=('org-'+$Index);Name=('Mock organization '+$Index);Type='Office365';IsBackedUp=$true;BackupParts='Office365All';BackupTeams=$true;BackupTeamsChats=$true;VeeamAADApplicationUsed=$true;BackupAccounts=@($global:VboLeakMarker)})
}
function Get-VBOOrganization {
    [CmdletBinding()]param()
    if($global:VboMockScenario -eq 'OrganizationDenied'){throw $global:VboLeakMarker}
    if($global:VboMockScenario -eq 'OrganizationEmpty'){return}
    New-MockVboOrganization 1
    New-MockVboOrganization 2
}
function Get-VBOProxy {
    [CmdletBinding()]param([switch]$ExtendedView)
    foreach($index in 1,2){
        $item=[pscustomobject]@{Id=('proxy-'+$index);Hostname=('proxy'+$index+'.mock.test');Port=9193;State=$(if($global:VboMockScenario -eq 'ProxyOffline'){'Offline'}else{'Online'});Version=($global:VboMockMajor.ToString()+'.0.0.1234');Type='Domain';IsOutdated=$false;ThreadsNumber=8;ThrottlingValue=0;ThrottlingUnit='Mbps'}
        if($global:VboMockMajor -eq 8){$item | Add-Member -NotePropertyName OperatingSystemKind -NotePropertyValue 'Windows';$item | Add-Member -NotePropertyName MaintenanceModeState -NotePropertyValue 'Disabled';$item | Add-Member -NotePropertyName PoolId -NotePropertyValue 'pool-1'}
        Add-MockPrivateFields $item
    }
}
function Get-VBOProxyPool {
    [CmdletBinding()]param()
    $global:VboPoolCalls++
    if($global:VboMockMajor -eq 7){throw 'A v7 proxy-pool query must never be attempted'}
    [pscustomobject]@{Id='pool-1';Name='Mock pool';Proxies=@([pscustomobject]@{Id='proxy-1'},[pscustomobject]@{Id='proxy-2'},[pscustomobject]@{Id='proxy-3'})}
}
function New-MockVboRepository {
    param([switch]$ObjectStorage,[switch]$Archive)
    $item=[pscustomobject]@{Id=$(if($Archive){'repo-archive'}elseif($ObjectStorage){'repo-object'}else{'repo-jet'});Name=$(if($Archive){'Mock archive'}elseif($ObjectStorage){'Mock object'}else{'Mock JET'});IsObjectStorage=[bool]$ObjectStorage;IsLongTerm=[bool]$Archive;Path='D:\MockRepo';Proxy=[pscustomobject]@{Hostname='proxy1.mock.test'};RetentionType='SnapshotBased';RetentionPeriod='Years3';Capacity=$(if($ObjectStorage){$null}else{100GB});FreeSpace=$(if($ObjectStorage){$null}else{20GB});UsedSpace=$(if($global:VboMockMajor -eq 8 -and $ObjectStorage -and $global:VboMockScenario -ne 'ObjectCapacityMissing'){30GB}else{$null});EnableImmutability=$true;ImmutabilityPeriod=30}
    Add-MockPrivateFields $item
}
function Get-VBORepository {
    [CmdletBinding()]param([switch]$LongTerm)
    if($LongTerm){New-MockVboRepository -ObjectStorage -Archive;return}
    New-MockVboRepository
    New-MockVboRepository -ObjectStorage
}
function Get-VBOObjectStorageRepository {
    [CmdletBinding()]param()
    $global:VboLegacyCalls++
    Add-MockPrivateFields ([pscustomobject]@{Id='legacy-object';Name='Mock legacy object';Type='AmazonS3';IsLongTerm=$true;UsedSpace=5GB;FreeSpace=$null;EnableSizeLimit=$true;SizeLimit=500;EnableImmutability=$true;ImmutabilityPeriod=30})
}
function New-MockVboJob {
    param([int]$Index=1,[object]$Organization)
    if($null -eq $Organization){$Organization=New-MockVboOrganization 1}
    Add-MockPrivateFields ([pscustomobject]@{Id=('job-'+$Index);Name=('Mock backup '+$Index);Organization=$Organization;Repository=(New-MockVboRepository);JobType='Backup';JobBackupType='SelectedItems';IsEnabled=($global:VboMockScenario -ne 'JobFailed');LastStatus=$(if($global:VboMockScenario -eq 'JobFailed'){'Failed'}else{'Success'});LastRun=(Get-Date).AddHours(-1);LastBackup=(Get-Date).AddHours(-1);NextRun=(Get-Date).AddHours(23);SchedulePolicy=[pscustomobject]@{EnableSchedule=$true;Type='Daily';DailyType='Everyday';DailyTime=[timespan]::FromHours(1);RetryEnabled=$true;RetryNumber=3};SelectedItems=@($global:VboLeakMarker);ExcludedItems=@($global:VboLeakMarker)})
}
function Get-VBOJob {[CmdletBinding()]param([object]$Organization) New-MockVboJob -Index 1 -Organization $Organization;New-MockVboJob -Index 2 -Organization $Organization}
function Get-VBOBackupItem {[CmdletBinding()]param([object]$Job) Add-MockPrivateFields ([pscustomobject]@{Type='User';User=$global:VboLeakMarker});Add-MockPrivateFields ([pscustomobject]@{Type='O365Group';Group=$global:VboLeakMarker})}
function Get-VBOExcludedBackupItem {[CmdletBinding()]param([object]$Job) Add-MockPrivateFields ([pscustomobject]@{Type='User';User=$global:VboLeakMarker})}
function Get-VBOCopyJob {
    [CmdletBinding()]param()
    foreach($index in 1,2){$archive=$global:VboMockMajor -eq 7 -or $index -eq 2;Add-MockPrivateFields ([pscustomobject]@{Id=('copy-'+$index);Name=('Mock copy '+$index);JobType='Copy';BackupJob=(New-MockVboJob -Index $index);Repository=(New-MockVboRepository -ObjectStorage -Archive:$archive);IsEnabled=$true;LastStatus='Success';LastRun=(Get-Date).AddHours(-2);LastBackup=(Get-Date).AddHours(-2);NextRun=(Get-Date).AddHours(22);SchedulePolicy=[pscustomobject]@{Type='Daily'}})}
}
function Get-VBOJobSession {
    [CmdletBinding()]param([string]$JobType,[switch]$Last)
    $global:VboSessionCalls++
    foreach($index in 1,2){Add-MockPrivateFields ([pscustomobject]@{JobId=('job-'+$index);JobName=('Mock backup '+$index);Status=$(if($index -eq 2){'Warning'}else{'Success'});JobSessionConfigType='Incremental';Statistics=[pscustomobject]@{ProcessedObjects=100;ProcessingRate='10 MB/s';ReadRate='20 MB/s';WriteRate='10 MB/s';TransferredData='10 MB';Bottleneck='Target'}});if($Last){break}}
}
function Get-VBORestorePoint {
    [CmdletBinding()]param([object]$Organization)
    if($global:VboMockScenario -eq 'RestorePointsDenied'){throw $global:VboLeakMarker}
    if($global:VboMockScenario -eq 'RestorePointsEmpty'){return}
    foreach($index in 1,2){Add-MockPrivateFields ([pscustomobject]@{Id=('point-'+$index);OrganizationId=$Organization.Id;JobId='job-1';RepositoryId='repo-jet';BackupTime=(Get-Date).AddHours(-$index);IsExchange=$true;IsSharePoint=$true;IsOneDrive=$true;IsTeams=$true;IsLongTermCopy=$false;IsCopy=$false;IsRetrieved=$false;IsRetrievable=$true;ImmutabilityExpiresOn=(Get-Date).AddDays(30)})}
}
function Invoke-VboCase {
    param([string]$Script,[int]$Major=8,[string]$Scenario='Success',[hashtable]$Arguments=@{})
    $global:VboMockMajor=$Major;$global:VboMockScenario=$Scenario;$global:VboConnectCalls=0;$global:VboDisconnectCalls=0;$global:VboPoolCalls=0;$global:VboLegacyCalls=0;$global:VboSessionCalls=0
    $directory=Join-Path $resultRoot ('c-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    & (Join-Path $scriptRoot $Script) -Server 'vbo.mock.test' -OutputDirectory $directory @Arguments -WarningAction SilentlyContinue
}
$scriptNames=@('Get-VBOPlatformAudit.ps1','Get-VBOOrganizationAudit.ps1','Get-VBOProxyAudit.ps1','Get-VBORepositoryAudit.ps1','Get-VBOBackupJobAudit.ps1','Get-VBOBackupCopyJobAudit.ps1','Get-VBOSessionAudit.ps1','Get-VBOProtectionAudit.ps1')
foreach($name in $scriptNames){
    $path=Join-Path $scriptRoot $name;$tokens=$null;$errors=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-Vbo ($errors.Count -eq 0) ($name+' parses')
    $text=Get-Content -LiteralPath $path -Raw;$header=[regex]::Match($text,'(?s)^<#(.*?)#>').Groups[1].Value
    $sections=@([regex]::Matches($header,'(?m)^(What it does|Available flags|How it works):') | ForEach-Object {$_.Groups[1].Value})
    Assert-Vbo (($sections -join '|') -eq 'What it does|Available flags|How it works') ($name+' has the three opening sections')
    $actual=@($ast.ParamBlock.Parameters | ForEach-Object {$_.Name.VariablePath.UserPath});$documented=@([regex]::Matches($header,'(?m)^\s+-(\w+)') | ForEach-Object {$_.Groups[1].Value})
    Assert-Vbo (@(Compare-Object $actual $documented).Count -eq 0) ($name+' documents every actual parameter')
    $body=$text
    Assert-Vbo ($body -notmatch '(?im)^\s*(?:Set|Start|Stop|Sync|Remove|Update|Test)-VBO(?:Repository|Job|CopyJob|Proxy|Organization|DataRetrieval)\b') ($name+' contains no VBO operation command')
}
foreach($major in 7,8){
    foreach($name in $scriptNames){
        $result=Invoke-VboCase -Script $name -Major $major
        Assert-Vbo ($result.Context.ConnectionSucceeded -and $global:VboConnectCalls -eq 1 -and $global:VboDisconnectCalls -eq 1) ($name+' v'+$major+' owns and closes one explicit connection')
        Assert-Vbo ($global:VboLastConnect.Server -eq 'vbo.mock.test' -and $global:VboLastConnect.Port -eq 9191) ($name+' v'+$major+' uses requested target and documented console port')
        Assert-Vbo ($result.Context.MajorVersion -eq $major -and $result.Context.ToolkitProductVersion -eq ($major.ToString()+'.0.0.1000') -and $result.Context.ServerVersion -eq ($major.ToString()+'.0.0.2000')) ($name+' v'+$major+' separates toolkit and verified server builds')
        $files=@(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $result.ReportDirectory -File)
        $combined=($files | Where-Object Extension -in '.csv','.json','.txt' | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw}) -join [Environment]::NewLine
        Assert-Vbo ($combined -notlike ('*'+$global:VboLeakMarker+'*')) ($name+' v'+$major+' excludes secret canaries from all reports')
        if($name -eq 'Get-VBOProxyAudit.ps1'){Assert-Vbo (($major -eq 7 -and $global:VboPoolCalls -eq 0 -and $result.Data.PoolCapability -eq 'Unsupported') -or ($major -eq 8 -and $global:VboPoolCalls -eq 1)) ('Proxy pools are gated for v'+$major)}
        if($name -eq 'Get-VBORepositoryAudit.ps1'){Assert-Vbo (($major -eq 7 -and $global:VboLegacyCalls -eq 1) -or ($major -eq 8 -and $global:VboLegacyCalls -eq 0)) ('Legacy object-store inventory is separate for v'+$major)}
        if($name -eq 'Get-VBOBackupCopyJobAudit.ps1'){Assert-Vbo (($major -eq 7 -and $result.Data.ArchiveTargetsObserved -eq 2 -and $result.Data.StandardTargetsObserved -eq 0) -or ($major -eq 8 -and $result.Data.ArchiveTargetsObserved -eq 1 -and $result.Data.StandardTargetsObserved -eq 1)) ('Copy target classes stay distinct for v'+$major)}
        if($name -eq 'Get-VBOProtectionAudit.ps1'){Assert-Vbo ($result.Data.TenantWideCoverageAssessment -eq 'NotEstablished' -and $result.Data.RestorePointsReported -eq 4) ('Configured jobs and restore points never become a tenant coverage claim for v'+$major)}
    }
}
$result=Invoke-VboCase -Script $scriptNames[0] -Scenario 'HostUnavailable'
Assert-Vbo (-not $result.Context.RemoteVersionVerified -and $null -eq $result.Context.ServerVersion -and $result.Context.ToolkitProductVersion -eq '8.0.0.1000' -and $result.State -eq 'Incomplete') 'Unavailable host version is not inferred from toolkit build'
$result=Invoke-VboCase -Script $scriptNames[1] -Scenario 'ConnectDenied'
Assert-Vbo (-not $result.Context.ConnectionSucceeded -and $global:VboDisconnectCalls -eq 0 -and $result.Data.OrganizationsReported -eq 0) 'Failed connection never queries tenants or disconnects an unowned session'
$result=Invoke-VboCase -Script $scriptNames[1] -Scenario 'OrganizationDenied'
$status=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'collection-status.csv')
Assert-Vbo ($result.State -eq 'Incomplete' -and @($status | Where-Object { $_.Section -eq 'VBOOrganizations' -and $_.State -eq 'Unknown' }).Count -eq 1) 'Organization query failure is Unknown rather than empty success'
Assert-Vbo (((Get-Content -LiteralPath (Join-Path $result.ReportDirectory 'findings.csv') -Raw) -notlike ('*'+$global:VboLeakMarker+'*'))) 'Vendor exception text is redacted'
$result=Invoke-VboCase -Script $scriptNames[1] -Scenario 'OrganizationEmpty'
$status=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'collection-status.csv')
Assert-Vbo (@($status | Where-Object { $_.Section -eq 'VBOOrganizations' -and $_.State -eq 'Collected' -and $_.Rows -eq '0' }).Count -eq 1) 'Readable empty organization inventory is explicitly distinguishable'
$result=Invoke-VboCase -Script $scriptNames[2] -Scenario 'PoolUnavailable'
Assert-Vbo ($result.Data.PoolCapability -eq 'Unsupported' -and $global:VboPoolCalls -eq 0) 'Missing v8 optional pool capability is recorded without calling it'
$result=Invoke-VboCase -Script $scriptNames[2] -Scenario 'NoExtendedView' -Arguments @{ExtendedView=$true}
Assert-Vbo ($result.State -eq 'Incomplete' -and $result.Data.ProxiesReported -eq 0) 'Requested unsupported ExtendedView is an explicit gap'
$result=Invoke-VboCase -Script $scriptNames[2] -Scenario 'ProxyOffline'
$status=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'collection-status.csv')
Assert-Vbo ($result.State -eq 'Fail' -and @($status | Where-Object State -eq 'Unknown').Count -eq 0) 'An offline proxy finding is separate from successful evidence collection'
$result=Invoke-VboCase -Script $scriptNames[2] -Arguments @{MaxPoolMembers=2;MaxProxies=1}
$poolRows=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'proxy-pools.csv')
Assert-Vbo ($result.Data.ProxyOutputTruncated -and $poolRows[0].MembersObserved -eq '2' -and $poolRows[0].MemberListTruncated -eq 'True') 'Proxy and pool-member inspection caps are explicit'
$result=Invoke-VboCase -Script $scriptNames[3] -Scenario 'NoLongTerm'
Assert-Vbo ($result.Data.LongTermCapability -eq 'Unsupported') 'Missing LongTerm parameter does not become an empty healthy class'
$result=Invoke-VboCase -Script $scriptNames[3] -Scenario 'ObjectCapacityMissing'
$repoRows=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'repositories.csv')
Assert-Vbo (@($repoRows | Where-Object { $_.StorageClass -eq 'ObjectStorage' -and $_.ObjectUsedBytes -eq '' -and $_.JetCapacityBytes -eq '' }).Count -eq 2) 'Missing object capacity is blank/unknown and never JET or zero capacity'
$result=Invoke-VboCase -Script $scriptNames[4] -Arguments @{MaxJobs=1;MaxScopeItems=1}
$jobs=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'backup-jobs.csv')
Assert-Vbo ($result.Data.JobsTruncated -and $jobs[0].IncludedConfiguredItemsObserved -eq '1' -and $jobs[0].IncludedScopeTruncated -eq 'True') 'Job and configured inclusion scope caps are explicit'
$result=Invoke-VboCase -Script $scriptNames[4] -Scenario 'JobFailed'
Assert-Vbo ($result.State -eq 'Fail') 'Failed job outcome is reported as a finding'
$result=Invoke-VboCase -Script $scriptNames[6] -Scenario 'NoJobType' -Arguments @{JobType='Copy'}
Assert-Vbo ($result.State -eq 'Incomplete' -and $global:VboSessionCalls -eq 0) 'Unsupported requested session filter prevents an unscoped fallback'
$result=Invoke-VboCase -Script $scriptNames[6] -Arguments @{MaxSessions=1}
Assert-Vbo ($result.Data.Truncated -and $result.Data.SessionsReported -eq 1) 'Session output limit is explicit'
$result=Invoke-VboCase -Script $scriptNames[7] -Scenario 'RestorePointsDenied'
$orgRows=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'organization-protection-evidence.csv')
Assert-Vbo ($result.State -eq 'Incomplete' -and $orgRows[0].RestorePointCollection -eq 'Unknown' -and $orgRows[0].RestorePointsObserved -eq '') 'Restore-point access failure is Unknown rather than zero protection'
$result=Invoke-VboCase -Script $scriptNames[7] -Scenario 'NoRestoreOrganization'
Assert-Vbo ($result.State -eq 'Incomplete') 'Unsupported per-organization point query remains incomplete'
$result=Invoke-VboCase -Script $scriptNames[7] -Arguments @{MaxOrganizations=1;MaxJobsPerOrganization=1;MaxRestorePointsPerOrganization=1}
$orgRows=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'organization-protection-evidence.csv')
Assert-Vbo ($result.Data.OrganizationsTruncated -and $orgRows[0].JobsTruncated -eq 'True' -and $orgRows[0].RestorePointsTruncated -eq 'True') 'Protection organization/job/point caps are explicit'
$result=Invoke-VboCase -Script $scriptNames[0] -Scenario 'VersionMismatch'
Assert-Vbo ($result.State -eq 'Fail' -and $global:VboConnectCalls -eq 0) 'Toolkit/server major mismatch blocks audit connection'
$checks | Export-Csv -LiteralPath (Join-Path $resultRoot 'test-results.csv') -NoTypeInformation -Encoding UTF8
[pscustomobject]@{Passed=$checks.Count;Failed=0;PowerShellVersion=$PSVersionTable.PSVersion.ToString();ResultsDirectory=$resultRoot;Scope='Synthetic v7/v8 module, connection, host, inventory, session, and restore-point mocks; no Veeam product or remote host was contacted.'}

$global:CrossReviewChecks=0
function Assert-CrossReview {param([bool]$Condition,[string]$Description) if(-not $Condition){throw ('FAILED cross-review: '+$Description)};$global:CrossReviewChecks++}
function Get-VBOProxyPool {[CmdletBinding()]param() [pscustomobject]@{Id='pool-missing';Name='Missing member metadata'}}
$missingPool=Invoke-VboCase -Script 'Get-VBOProxyAudit.ps1'
$missingPoolRows=@(Import-Csv -LiteralPath (Join-Path $missingPool.ReportDirectory 'proxy-pools.csv'))
Assert-CrossReview ($missingPool.State -eq 'Incomplete' -and $missingPoolRows[0].MembersObserved -eq '' -and $missingPoolRows[0].MembershipVisibility -eq 'Unknown') 'Absent pool membership is Unknown with a blank count, not zero'
$missingPoolCapability=Invoke-VboCase -Script 'Get-VBOProxyAudit.ps1' -Scenario 'PoolUnavailable'
Assert-CrossReview ($missingPoolCapability.State -eq 'Incomplete') 'Missing v8 pool getter is an evidence gap'
$global:CrossReviewOriginalGetCommand=(Get-Item -LiteralPath 'Function:Get-Command').ScriptBlock
function Get-Command {
    [CmdletBinding()]param([Parameter(Position=0)][string]$Name)
    if($Name -in @('Get-VBOSecuritySettings','Get-VBOServerComponents')){return}
    & $global:CrossReviewOriginalGetCommand @PSBoundParameters
}
$missingPlatform=Invoke-VboCase -Script 'Get-VBOPlatformAudit.ps1'
$missingPlatformFindings=@(Import-Csv -LiteralPath (Join-Path $missingPlatform.ReportDirectory 'findings.csv'))
Assert-CrossReview ($missingPlatform.State -eq 'Incomplete' -and @($missingPlatformFindings | Where-Object {$_.Component -in @('PlatformTlsCertificate','ComponentInventory') -and $_.State -eq 'Unknown'}).Count -eq 2) 'Missing security and component getters do not imply NotApplicable'
function Get-VBORestorePoint {[CmdletBinding()]param([object]$Organization) [pscustomobject]@{Id='point-without-time';JobId='job-1';RepositoryId='repo-jet';BackupTime=$null}}
$missingPointTimes=Invoke-VboCase -Script 'Get-VBOProtectionAudit.ps1'
$missingTimeRows=@(Import-Csv -LiteralPath (Join-Path $missingPointTimes.ReportDirectory 'organization-protection-evidence.csv'))
Assert-CrossReview ($missingPointTimes.State -eq 'Incomplete' -and $missingTimeRows[0].SampleFreshness -eq 'Unknown') 'Unusable restore-point time makes freshness assessment incomplete'
function Get-VBORepository {
    [CmdletBinding()]param([switch]$LongTerm)
    if($LongTerm){return}
    [pscustomobject]@{Id='inconsistent';Name='Free greater than capacity';IsObjectStorage=$false;Capacity=100;FreeSpace=200}
    [pscustomobject]@{Id='wrong-type';Name='Nonnumeric fields';IsObjectStorage=$false;Capacity='not numeric';FreeSpace='not numeric'}
    [pscustomobject]@{Id='wrong-bool';Name='Unusable storage class';IsObjectStorage='False';Capacity=100;FreeSpace=20}
}
$invalidJet=Invoke-VboCase -Script 'Get-VBORepositoryAudit.ps1'
$invalidJetRows=@(Import-Csv -LiteralPath (Join-Path $invalidJet.ReportDirectory 'repositories.csv'))
Assert-CrossReview ($invalidJet.State -eq 'Incomplete' -and @($invalidJetRows | Where-Object JetFreePercent -ne '').Count -eq 0) 'JET invalid and inconsistent values never yield a healthy percentage'
Assert-CrossReview (($invalidJetRows | Where-Object Id -eq 'wrong-bool').StorageClass -eq 'Unknown') 'String false is not a repository classification boolean'

Write-Output ('PASS: '+$global:CrossReviewChecks+' additional evidence/secret regression checks.')
