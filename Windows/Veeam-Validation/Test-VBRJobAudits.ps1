<#
What it does:
  Runs VBR backup/copy/replication, sessions, configuration backup and restore-point mocks without contacting Veeam, Windows hosts, or databases.

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
$global:VbrJobsMode='Normal';$global:VbrJobsChecks=0;$global:VbrJobsConnects=0;$global:VbrJobsDisconnects=0;$global:VbrJobsQueries=0;$global:VbrJobsKeyReads=0
$outputRoot=Join-Path $OutputDirectory ('vj-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$stageRoot=Join-Path $WindowsRoot 'Veeam-Backup-and-Replication-v12'
function Assert-True {param([bool]$Condition,[string]$Label) if(-not $Condition){throw ('FAIL: '+$Label)};$global:VbrJobsChecks++}
function Invoke-Subject {param([string]$Name,[hashtable]$Parameters=@{}) $Parameters.Server='mock-vbr.example.invalid';$Parameters.OutputDirectory=$outputRoot;& (Join-Path $stageRoot ($Name+'.ps1')) @Parameters}
function Read-Csv {param($Result,[string]$Name) @(Import-Csv -LiteralPath (Join-Path $Result.ReportDirectory ($Name+'.csv')))}
function Read-Findings {param($Result) Read-Csv $Result 'findings'}
function Assert-NoSecrets {param($Result) $allText=@(Get-ChildItem -LiteralPath $Result.ReportDirectory -File | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw}) -join "`n";Assert-True ($allText -notlike '*DO_NOT_EXPORT_SECRET*') ('No vendor options or secret values serialized: '+$Result.Script)}

function Import-Module {
    [CmdletBinding()]param([string]$Name,[switch]$PassThru)
    if($Name -ne 'Veeam.Backup.PowerShell'){throw ('Unexpected module import blocked: '+$Name)}
    if($global:VbrJobsMode -eq 'ModuleDenied'){throw 'Mock module unavailable DO_NOT_EXPORT_SECRET'}
    [pscustomobject]@{Name=$Name;Version=[version]'12.3.2.0'}
}
function Invoke-Command {
    [CmdletBinding()]param([string]$ComputerName,[scriptblock]$ScriptBlock,[object[]]$ArgumentList,[PSCredential]$Credential)
    if($ComputerName -ne 'mock-vbr.example.invalid'){throw 'Unexpected remote query blocked.'}
    if($global:VbrJobsMode -eq 'HostVersionDenied'){throw 'Mock host version access denied.'}
    [pscustomobject]@{ProductVersion='12.3.2.4854'}
}
function Connect-VBRServer {
    [CmdletBinding()]param([string]$Server,[int]$Port,[PSCredential]$Credential)
    Assert-True ($Server -eq 'mock-vbr.example.invalid' -and $Port -eq 9392) 'Connection targets requested server and documented port'
    if($global:VbrJobsMode -eq 'ConnectDenied'){throw 'Mock denied DO_NOT_EXPORT_SECRET'}
    $global:VbrJobsConnects++
}
function Disconnect-VBRServer {[CmdletBinding()]param() $global:VbrJobsDisconnects++}
function Get-VBRBackupServerInfo {[CmdletBinding()]param() [pscustomobject]@{Build='12.3.2.4854'}}
function Get-Command {
    [CmdletBinding()]param([string[]]$Name,[Management.Automation.CommandTypes]$CommandType)
    if($global:VbrJobsMode -eq 'NoModern' -and $Name -contains 'Get-VBRBackupCopyJob'){return}
    if($global:VbrJobsMode -eq 'NoLegacySource' -and $Name -contains 'Get-VBRLegacyBackupCopySourceJob'){return}
    Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
}
function Get-VBRJob {
    [CmdletBinding()]param([string[]]$Name)
    $global:VbrJobsQueries++
    if($global:VbrJobsMode -eq 'JobsDenied'){throw 'Mock jobs denied DO_NOT_EXPORT_SECRET'}
    if($global:VbrJobsMode -eq 'NoJobs'){return}
    if($global:VbrJobsMode -eq 'JobsMalformed'){return [pscustomobject]@{Name='Unclassified';Id='unknown-job';Options='DO_NOT_EXPORT_SECRET'}}
    $items=@(
        [pscustomobject]@{Id='backup-1';Name='Backup A';JobType='Backup';IsScheduleEnabled=$true;Options=[pscustomobject]@{Password='DO_NOT_EXPORT_SECRET';PreJobScript='DO_NOT_EXPORT_SECRET'}},
        [pscustomobject]@{Id='replica-1';Name='Replica A';JobType='Replica';IsScheduleEnabled=$false},
        [pscustomobject]@{Id='copy-shared';Name='Shared Copy';JobType='BackupSync';IsScheduleEnabled=$true},
        [pscustomobject]@{Id='copy-legacy';Name='Legacy Copy';JobType='BackupSync';IsScheduleEnabled=$false}
    )
    if($global:VbrJobsMode -eq 'JobsCap'){$items+=1..3 | ForEach-Object {[pscustomobject]@{Id=('backup-extra-'+$_);Name=('Extra Backup '+$_);JobType='Backup';IsScheduleEnabled=$true}}}
    if($global:VbrJobsMode -eq 'JobsBadBool'){$items[0].IsScheduleEnabled='False'}
    $items | Where-Object {if(-not $Name){return $true};$itemName=$_.Name;@($Name | Where-Object {$itemName -like $_}).Count -gt 0}
}
function Get-VBRJobScheduleOptions {
    [CmdletBinding()]param([object[]]$Job)
    if($global:VbrJobsMode -eq 'ScheduleDenied'){throw 'Mock schedule denied.'}
    if($global:VbrJobsMode -eq 'ScheduleMissing'){return [pscustomobject]@{UnsupportedOptions='DO_NOT_EXPORT_SECRET'}}
    [pscustomobject]@{OptionsDaily=[pscustomobject]@{Enabled=$true};OptionsMonthly=[pscustomobject]@{Enabled=$false};OptionsPeriodically=[pscustomobject]@{Enabled=$false};OptionsContinuous=[pscustomobject]@{Enabled=$false};PostJobScript='DO_NOT_EXPORT_SECRET'}
}
function Get-VBRJobObject {
    [CmdletBinding()]param([object]$Job)
    if($global:VbrJobsMode -eq 'ObjectsDenied'){throw 'Mock object access denied.'}
    if($global:VbrJobsMode -eq 'ObjectsEmpty'){return}
    foreach($index in 1..3){[pscustomobject]@{Name=('VM-'+$index);ObjectId=('object-'+$index);Type='VM';IsExcluded=($index -eq 3);GuestCredential='DO_NOT_EXPORT_SECRET'}}
}
function Get-VBRBackupCopyJob {
    [CmdletBinding()]param()
    $global:VbrJobsQueries++
    if($global:VbrJobsMode -eq 'ModernDenied'){throw 'Mock modern copy denied.'}
    [pscustomobject]@{Id='copy-shared';Name='Shared Copy';Mode='Immediate';Enabled=$true;TargetRepository=[pscustomobject]@{Name='Target repository';Credential='DO_NOT_EXPORT_SECRET'};LastResult='Success';LastState='Stopped';Options='DO_NOT_EXPORT_SECRET'}
    if($global:VbrJobsMode -eq 'CopyCap'){1..3 | ForEach-Object {[pscustomobject]@{Id=('copy-new-'+$_);Name=('New Copy '+$_);Mode='Periodic';Enabled=$true}}}
    if($global:VbrJobsMode -eq 'CopyFallbackBool'){[pscustomobject]@{Id='copy-fallback';Name='Fallback Copy';IsScheduleEnabled=$false;Repository=[pscustomobject]@{Name='Fallback repository'}}}
}
function Get-VBRLegacyBackupCopySourceJob {
    [CmdletBinding()]param([object]$Job)
    foreach($index in 1..3){[pscustomobject]@{Id=('source-'+$index);Name=('Source Job '+$index);Options='DO_NOT_EXPORT_SECRET'}}
}
function Get-VBRBackupSession {
    [CmdletBinding()]param()
    $global:VbrJobsQueries++
    if($global:VbrJobsMode -eq 'SessionsDenied'){throw 'Mock sessions denied.'}
    if($global:VbrJobsMode -eq 'SessionsEmpty'){return}
    $created=[datetime]::SpecifyKind([datetime]::UtcNow.AddHours(-1),[DateTimeKind]::Unspecified)
    if($global:VbrJobsMode -eq 'SessionTimeMissing'){$created=$null}
    [pscustomobject]@{Id='session-1';Name='Backup A (Incremental)';JobId='backup-1';JobType='Backup';State='Stopped';Result='Success';CreationTimeUTC=$created;EndTimeUTC=[datetime]::UtcNow;Options='DO_NOT_EXPORT_SECRET'}
    [pscustomobject]@{Id='session-old';Name='Backup A (Full)';JobId='backup-1';State='Stopped';Result='Failed';CreationTimeUTC=[datetime]::UtcNow.AddDays(-400);EndTimeUTC=[datetime]::UtcNow.AddDays(-400)}
    if($global:VbrJobsMode -eq 'SessionsCap'){1..3 | ForEach-Object {[pscustomobject]@{Id=('session-extra-'+$_);Name=('Other Backup '+$_);JobId='backup-1';JobType='Backup';State='Stopped';Result='Warning';CreationTimeUTC=[datetime]::UtcNow}}}
}
function Get-VBRTaskSession {
    [CmdletBinding()]param([object]$Session)
    if($global:VbrJobsMode -eq 'TasksDenied'){throw 'Mock task access denied.'}
    if($global:VbrJobsMode -eq 'TasksEmpty'){return}
    foreach($index in 1..3){[pscustomobject]@{Id=('task-'+$index);Name=('VM-'+$index);Status=$(if($global:VbrJobsMode -eq 'TaskFailure' -and $index -eq 2){'Failed'}else{'Success'});FailureLog='DO_NOT_EXPORT_SECRET'}}
}
function Get-VBRBackup {
    [CmdletBinding()]param([string[]]$Name)
    $global:VbrJobsQueries++
    if($global:VbrJobsMode -eq 'BackupsDenied'){throw 'Mock backup access denied.'}
    if($global:VbrJobsMode -eq 'BackupsEmpty'){return}
    [pscustomobject]@{Id='catalog-1';Name='Backup A';Options='DO_NOT_EXPORT_SECRET'}
    if($global:VbrJobsMode -eq 'BackupsCap'){1..3 | ForEach-Object {[pscustomobject]@{Id=('catalog-extra-'+$_);Name=('Other Catalog '+$_)}}}
}
function Get-VBRRestorePoint {
    [CmdletBinding()]param([object[]]$Backup,[string[]]$Name)
    Assert-True ($Name.Count -eq 1 -and $Name[0] -eq '*') 'Restore-point query always passes Agent-compatible name wildcard'
    if($global:VbrJobsMode -eq 'PointsDenied'){throw 'Mock restore point access denied.'}
    if($global:VbrJobsMode -eq 'PointsEmpty'){return}
    $created=[datetime]::SpecifyKind([datetime]::UtcNow.AddHours(-2),[DateTimeKind]::Unspecified)
    if($global:VbrJobsMode -in @('PointsOld','PointsOldCap','PointsOldMissing')){$created=[datetime]::UtcNow.AddDays(-10)}
    if($global:VbrJobsMode -eq 'PointsMissingUtc'){$created=$null}
    if($global:VbrJobsMode -eq 'PointsFuture'){$created=[datetime]::UtcNow.AddDays(1)}
    [pscustomobject]@{Id='point-1';Name='VM-A';ObjectId='vm-a';Type='Increment';CreationTimeUtc=$created;IsCorrupted=($global:VbrJobsMode -eq 'PointsCorrupt');CryptoKey='DO_NOT_EXPORT_SECRET'}
    if($global:VbrJobsMode -eq 'PointsOldMissing'){[pscustomobject]@{Id='point-unknown';Name='VM-A';ObjectId='vm-a';Type='Full';IsCorrupted=$false}}
    if($global:VbrJobsMode -in @('PointsOldCap','PointsObjectCap')){1..3 | ForEach-Object {[pscustomobject]@{Id=('point-extra-'+$_);Name=('VM-'+$_);ObjectId=('vm-'+$_);Type='Full';CreationTimeUtc=$created;IsCorrupted=$false}}}
}
function Get-VBRConfigurationBackupJob {
    [CmdletBinding()]param()
    $global:VbrJobsQueries++
    if($global:VbrJobsMode -eq 'ConfigDenied'){throw 'Mock configuration access denied.'}
    $crypto=[pscustomobject]@{Enabled=$true}
    $crypto | Add-Member -MemberType ScriptProperty -Name Key -Value {$global:VbrJobsKeyReads++;throw 'DO_NOT_EXPORT_SECRET'}
    if($global:VbrJobsMode -eq 'ConfigMissing'){$crypto=[pscustomobject]@{Unexpected=$true}}
    $job=[pscustomobject]@{Id='config-1';Name='Backup Configuration Job';Enabled=$true;Repository=[pscustomobject]@{Name='Config repository';Credential='DO_NOT_EXPORT_SECRET'};ScheduleOptions=[pscustomobject]@{Enabled=$true;Type='Daily';DailyOptions=[pscustomobject]@{Period=[timespan]'01:00:00'}};RestorePointsToKeep=10;EncryptionOptions=$crypto;LastResult='Warning';LastState='Stopped';NextRun=[datetime]'2026-10-19T01:00:00';Script='DO_NOT_EXPORT_SECRET'}
    if($global:VbrJobsMode -eq 'ConfigDisabled'){$job.Enabled=$false;$job.ScheduleOptions.Enabled=$false;$crypto.Enabled=$false}
    if($global:VbrJobsMode -eq 'ConfigBadBool'){$job.Enabled='False';$job.RestorePointsToKeep='garbage'}
    $job
    if($global:VbrJobsMode -eq 'ConfigDuplicate'){$job}
}

$subjects=@('Get-VBRBackupJobAudit','Get-VBRBackupCopyJobAudit','Get-VBRReplicationJobAudit','Get-VBRSessionAudit','Get-VBRRestorePointAudit','Get-VBRConfigurationBackupAudit')
foreach($subject in $subjects){
    $tokens=$null;$problems=$null;$path=Join-Path $stageRoot ($subject+'.ps1')
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$problems)
    Assert-True (@($problems).Count -eq 0) ('PS5.1 AST parses '+$subject)
    $source=Get-Content -LiteralPath $path -Raw;$header=$source.Substring(0,$source.IndexOf('#>')+2)
    Assert-True ($header -match 'What it does:' -and $header -match 'Available flags:' -and $header -match 'How it works:') ('Three concise sections '+$subject)
    foreach($parameter in $ast.ParamBlock.Parameters){Assert-True ($header -match ('-'+[regex]::Escape($parameter.Name.VariablePath.UserPath)+'\b')) ('Documented parameter '+$parameter.Name.VariablePath.UserPath+' '+$subject)}
    $global:VbrJobsMode='Normal';$result=Invoke-Subject $subject
    Assert-True ($result.Context.MajorVersion -eq 12 -and $result.Context.RemoteVersionVerified) ('Verified requested v12 context '+$subject)
    Assert-NoSecrets $result
}

$global:VbrJobsMode='Normal';$result=Invoke-Subject $subjects[0]
Assert-True ($result.Data.InspectedJobs -eq 1) 'Classic backup family excludes replica and copy jobs'
Assert-True ((Read-Csv $result 'configured-job-objects').Count -eq 3) 'Configured object selections are exported'
Assert-True ((Read-Csv $result 'schedule-settings')[0].DailyEnabled -eq 'True') 'Actual daily Boolean is retained'
$global:VbrJobsMode='JobsCap';$result=Invoke-Subject $subjects[0] @{MaxJobs=2;MaxObjectsPerJob=2}
Assert-True ($result.Data.JobCapReached -and $result.Data.JobsWithObjectCap -eq 2 -and $result.Data.InspectedJobs -eq 2) 'Job and per-job object caps are explicit and enforced'
$global:VbrJobsMode='JobsMalformed';$result=Invoke-Subject $subjects[0]
Assert-True ($result.State -eq 'Incomplete' -and (Read-Csv $result 'jobs')[0].EvidenceStatus -eq 'Unknown') 'Unclassified job metadata remains unknown without follow-up'
$global:VbrJobsMode='JobsBadBool';$result=Invoke-Subject $subjects[0]
Assert-True ((Read-Csv $result 'jobs')[0].ScheduleEnabled -eq '' -and $result.State -eq 'Incomplete') 'String False cannot become Boolean True'
$global:VbrJobsMode='ScheduleMissing';$result=Invoke-Subject $subjects[0]
Assert-True (@(Read-Findings $result | Where-Object { $_.Component -like 'Schedule detail*' -and $_.State -eq 'Unknown'}).Count -eq 1) 'Unsupported schedule shape does not imply every mode disabled'
$global:VbrJobsMode='ObjectsDenied';$result=Invoke-Subject $subjects[0]
Assert-True ($result.State -eq 'Incomplete') 'Denied configured objects cannot appear complete'
$global:VbrJobsMode='Normal';$result=Invoke-Subject $subjects[2]
Assert-True ($result.Data.InspectedJobs -eq 1 -and (Read-Csv $result 'jobs')[0].JobType -eq 'Replica' -and $result.State -eq 'Review') 'Replica family and intentionally disabled schedule are distinct'

$global:VbrJobsMode='Normal';$result=Invoke-Subject $subjects[1]
Assert-True ($result.Data.InspectedJobs -eq 2) 'Modern and legacy copy IDs are deduplicated'
Assert-True ((Read-Csv $result 'legacy-copy-source-jobs').Count -eq 3) 'Supported legacy source-job API is queried'
$global:VbrJobsMode='NoModern';$result=Invoke-Subject $subjects[1]
Assert-True (-not $result.Data.ModernCmdletAvailable -and $result.Data.InspectedJobs -eq 2 -and $result.State -eq 'Incomplete') 'Modern capability absence uses explicit limited legacy fallback'
$global:VbrJobsMode='ModernDenied';$result=Invoke-Subject $subjects[1]
Assert-True ($result.State -eq 'Incomplete' -and $result.Data.InspectedJobs -eq 2) 'Modern query failure stays unknown while legacy query proceeds'
$global:VbrJobsMode='CopyFallbackBool';$result=Invoke-Subject $subjects[1]
Assert-True (@(Read-Csv $result 'backup-copy-jobs' | Where-Object { $_.Id -eq 'copy-fallback' -and $_.Enabled -eq 'False' -and $_.EnabledSource -eq 'IsScheduleEnabled'}).Count -eq 1) 'Optional modern Boolean compatibility fallback preserves False'
$global:VbrJobsMode='CopyCap';$result=Invoke-Subject $subjects[1] @{MaxJobs=1;MaxSourceJobsPerJob=1}
Assert-True ($result.Data.ModernJobCapReached -and $result.Data.LegacyJobCapReached) 'Modern and legacy job caps are reported independently'
$global:VbrJobsMode='NoLegacySource';$result=Invoke-Subject $subjects[1]
Assert-True ($result.State -eq 'Incomplete') 'Missing legacy source capability remains unknown'

$global:VbrJobsMode='Normal';$result=Invoke-Subject $subjects[3]
$sessionRows=@(Read-Csv $result 'sessions')
Assert-True ($sessionRows.Count -eq 1 -and $sessionRows[0].CreationTimeUtc -match 'Z$') 'UTC lookback excludes old sessions and normalizes explicit Unspecified UTC field'
Assert-True ((Read-Csv $result 'session-tasks').Count -eq 3) 'Per-session object task rows are collected'
$global:VbrJobsMode='TaskFailure';$result=Invoke-Subject $subjects[3]
Assert-True ($result.State -eq 'Fail' -and (Read-Csv $result 'sessions')[0].Result -eq 'Success') 'Task failure cannot be hidden by successful parent session'
$global:VbrJobsMode='TasksDenied';$result=Invoke-Subject $subjects[3]
Assert-True ($result.State -eq 'Incomplete' -and $result.Data.TasksReported -eq 0) 'Task permission failure remains unknown'
$global:VbrJobsMode='SessionsCap';$result=Invoke-Subject $subjects[3] @{MaxSessions=2;MaxTasksPerSession=2}
Assert-True ($result.Data.SessionCapReached -and $result.Data.SessionsWithTaskCap -eq 2 -and $result.Data.TasksReported -eq 4) 'Session/task caps bound reported data'
$global:VbrJobsMode='SessionTimeMissing';$result=Invoke-Subject $subjects[3]
Assert-True ((Read-Csv $result 'sessions')[0].TimeEvidence -eq 'Unknown') 'Missing UTC timestamp is not cast into a false time'
$global:VbrJobsMode='SessionsEmpty';$result=Invoke-Subject $subjects[3]
Assert-True ($result.State -eq 'Incomplete') 'Empty recent sessions do not prove jobs ran'

$global:VbrJobsMode='Normal';$result=Invoke-Subject $subjects[4]
Assert-True ((Read-Csv $result 'object-point-age')[0].AgeAssessment -eq 'Pass' -and $result.Data.Recoverability -eq 'NotTested') 'Recent point only passes age metadata, never restore validation'
Assert-True ((Read-Csv $result 'restore-points')[0].IsCorrupted -eq 'False') 'Actual False corruption metadata is retained'
$global:VbrJobsMode='PointsOld';$result=Invoke-Subject $subjects[4]
Assert-True ((Read-Csv $result 'object-point-age')[0].AgeAssessment -eq 'Review') 'Old complete catalog point exceeds configurable age threshold'
$global:VbrJobsMode='PointsOldCap';$result=Invoke-Subject $subjects[4] @{MaxRestorePointsPerBackup=1}
Assert-True ($result.Data.BackupsWithPointCap -eq 1 -and (Read-Csv $result 'object-point-age')[0].AgeAssessment -eq 'Unknown') 'Capped old point set cannot assert newest point is old'
$global:VbrJobsMode='PointsOldMissing';$result=Invoke-Subject $subjects[4]
Assert-True ((Read-Csv $result 'object-point-age')[0].AgeAssessment -eq 'Unknown') 'Unknown point time prevents false oldest/newest completeness claim'
$global:VbrJobsMode='PointsObjectCap';$result=Invoke-Subject $subjects[4] @{MaxObjectsPerBackup=1}
Assert-True ($result.Data.BackupsWithObjectCap -eq 1 -and $result.Data.ObjectsReported -eq 1) 'Per-backup object age summary cap is visible'
$global:VbrJobsMode='PointsMissingUtc';$result=Invoke-Subject $subjects[4]
Assert-True ((Read-Csv $result 'object-point-age')[0].AgeAssessment -eq 'Unknown' -and (Read-Csv $result 'restore-points')[0].AgeHours -eq '') 'Missing point time stays unknown rather than age zero'
$global:VbrJobsMode='PointsFuture';$result=Invoke-Subject $subjects[4]
Assert-True ((Read-Csv $result 'object-point-age')[0].AgeAssessment -eq 'Unknown') 'Future timestamps require review instead of freshness pass'
$global:VbrJobsMode='PointsCorrupt';$result=Invoke-Subject $subjects[4]
Assert-True ($result.State -eq 'Fail') 'Provider-reported corruption is a separate failure finding'
$global:VbrJobsMode='PointsDenied';$result=Invoke-Subject $subjects[4]
Assert-True ($result.State -eq 'Incomplete' -and (Read-Csv $result 'backups')[0].QueryStatus -eq 'Unknown') 'Restore point query denial is explicitly unknown'

$global:VbrJobsMode='Normal';$result=Invoke-Subject $subjects[5]
$configuration=(Read-Csv $result 'configuration-backup')[0]
Assert-True ($configuration.EncryptionEnabled -eq 'True' -and $configuration.RestorePointsToKeep -eq '10') 'Configuration encryption-enabled and retention scalar metadata are collected'
Assert-True ($configuration.LastSuccessfulBackupTimeUtc -eq '' -and $result.Data.LastSuccessfulBackupAge -eq 'Unknown') 'Unsupported last successful time is not invented'
Assert-True ($configuration.LastResult -eq 'Warning' -and $configuration.LastState -eq 'Stopped') 'Optional v12 configuration last-result/state metadata is preserved'
$global:VbrJobsMode='ConfigDisabled';$result=Invoke-Subject $subjects[5]
Assert-True (@(Read-Findings $result | Where-Object {$_.Component -in @('Configuration backup enabled','Configuration backup schedule','Configuration backup encryption') -and $_.State -eq 'Review'}).Count -eq 3) 'Disabled configuration protection settings are individually flagged'
$global:VbrJobsMode='ConfigMissing';$result=Invoke-Subject $subjects[5]
Assert-True ((Read-Csv $result 'configuration-backup')[0].EncryptionEnabled -eq '' -and @(Read-Findings $result | Where-Object {$_.Component -eq 'Configuration backup encryption' -and $_.State -eq 'Unknown'}).Count -eq 1) 'Missing encryption metadata stays unknown'
$global:VbrJobsMode='ConfigBadBool';$result=Invoke-Subject $subjects[5]
Assert-True ((Read-Csv $result 'configuration-backup')[0].Enabled -eq '' -and (Read-Csv $result 'configuration-backup')[0].RestorePointsToKeep -eq '') 'Malformed Boolean/retention fields stay unknown without conversion crash'
$global:VbrJobsMode='ConfigDuplicate';$result=Invoke-Subject $subjects[5]
Assert-True ($result.Data.ConfigurationJobsReported -eq 0 -and $result.State -eq 'Incomplete') 'Multiple configuration jobs violate expected singleton shape safely'
Assert-True ($global:VbrJobsKeyReads -eq 0) 'Encryption Key property getter is never accessed'

foreach($subject in $subjects){
    $global:VbrJobsMode='ModuleDenied';$beforeQueries=$global:VbrJobsQueries;$result=Invoke-Subject $subject
    Assert-True ($result.State -eq 'Incomplete' -and $global:VbrJobsQueries -eq $beforeQueries) ('Missing module skips every vendor audit query '+$subject)
    Assert-NoSecrets $result
}
$global:VbrJobsMode='ConnectDenied';$beforeQueries=$global:VbrJobsQueries;$result=Invoke-Subject $subjects[0]
Assert-True ($result.State -eq 'Incomplete' -and $beforeQueries -eq $global:VbrJobsQueries) 'Connection failure skips job queries'
Assert-True ($global:VbrJobsConnects -eq $global:VbrJobsDisconnects) 'Every successfully owned mock connection is disconnected'
Write-Output ('PASS: {0} mock-only VBR job/data checks on Windows PowerShell {1}.' -f $global:VbrJobsChecks,$PSVersionTable.PSVersion)

$global:CrossReviewChecks=0
function Assert-CrossReview {param([bool]$Condition,[string]$Description) if(-not $Condition){throw ('FAILED cross-review: '+$Description)};$global:CrossReviewChecks++}
$global:VbrJobsMode='Normal'
function Get-VBRJob {
    [CmdletBinding()]param([string[]]$Name)
    [pscustomobject]@{Id='safe-id';Name=[pscustomobject]@{Password='DO_NOT_EXPORT_SECRET'};JobType='Backup';IsScheduleEnabled=$true}
}
$objectShapedJob=Invoke-Subject -Name 'Get-VBRBackupJobAudit'
$objectShapedRows=Read-Csv $objectShapedJob 'jobs'
Assert-CrossReview ($objectShapedJob.State -eq 'Incomplete' -and $objectShapedRows[0].Name -eq '') 'Object-shaped job name is rejected instead of stringified'
Assert-NoSecrets $objectShapedJob
function Get-VBRConfigurationBackupJob {
    [CmdletBinding()]param()
    [pscustomobject]@{Enabled=$true;Repository=[pscustomobject]@{Name='SafeRepo'};ScheduleOptions=[pscustomobject]@{Enabled=$true;Type='Daily';DailyOptions=[pscustomobject]@{Period=[pscustomobject]@{Password='DO_NOT_EXPORT_SECRET'}}};RestorePointsToKeep=14;EncryptionOptions=[pscustomobject]@{Enabled=$true;Key='DO_NOT_EXPORT_SECRET'};LastResult='Success';LastState='Stopped';NextRun=[pscustomobject]@{Password='DO_NOT_EXPORT_SECRET'}}
}
$objectShapedConfig=Invoke-Subject -Name 'Get-VBRConfigurationBackupAudit'
$objectShapedConfigRows=Read-Csv $objectShapedConfig 'configuration-backup'
Assert-CrossReview ($objectShapedConfigRows[0].DailyTimeRaw -eq '' -and $objectShapedConfigRows[0].NextRunRaw -eq '') 'Object-shaped optional configuration fields are omitted'
Assert-NoSecrets $objectShapedConfig

Write-Output ('PASS: '+$global:CrossReviewChecks+' additional evidence/secret regression checks.')
