<#
What it does:
  Reports classic VMware/Hyper-V backup or replication job scheduling and configured object selections.

Available flags:
  -Product: Private VBR profile supplied by the public entrypoint.
  -EntryPointName: Private report identity supplied by the public entrypoint.
  -Family: Private classic Backup/Replication profile.
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -NamePattern: Classic job-name wildcard; default *.
  -MaxJobs: Maximum matching jobs inspected; default 100.
  -MaxObjectsPerJob: Maximum configured selections per job; default 200.

How it works:
  Private shared implementation; invoke a public product entrypoint instead. Reports retain its name.
  Reads Get-VBRJob Backup/Replica jobs, schedule settings, and configured objects through installed v12 tools. Container selections are not expanded; missing evidence remains unknown. No job is run or changed.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Backup','Replication')][string]$Family,
    [Parameter(Mandatory=$true)][ValidateSet('VBR')][string]$Product,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z][A-Za-z0-9_-]+$')][string]$EntryPointName,
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateNotNullOrEmpty()][string]$NamePattern='*',
[ValidateRange(1,10000)][int]$MaxJobs=100,
[ValidateRange(1,10000)][int]$MaxObjectsPerJob=200
)
if($Product -ne 'VBR'){throw 'Classic job audits require VBR.'}
$jobType=if($Family -eq 'Backup'){'Backup'}else{'Replica'}
$familyLabel=$Family.ToLowerInvariant()
$jobScopeNote='Scope is classic VMware/Hyper-V '+$familyLabel+' jobs returned by Get-VBRJob with JobType '+$jobType+'. Agent, NAS/unstructured, tape, CDP, SureBackup, plug-in, and cloud-native jobs are outside this script.'
$script:VeeamProduct=$Product
$ErrorActionPreference='Stop'
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$runName=$EntryPointName
$runDirectory=Join-Path $OutputDirectory ($runName+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $runDirectory -Force
$collectionStatus=New-Object 'System.Collections.Generic.List[object]'
$findings=New-Object 'System.Collections.Generic.List[object]'
$veeamReady=$false;$ownsVeeamConnection=$false
$veeamContext=[pscustomobject]@{Product=$script:VeeamProduct;Server=$Server;Port=$Port;MajorVersion=$null;ServerVersion=$null;ToolkitProductVersion=$null;ModuleVersion=$null;VersionSource='Unknown';RemoteVersionVerified=$false;VersionRejected=$false;ConnectionSucceeded=$false;PowerShellVersion=[string]$PSVersionTable.PSVersion}
. (Join-Path $PSScriptRoot 'Veeam-AuditCommon.ps1')

try {
    Initialize-VeeamConnection
function Get-JobAuditText {
    param([object]$Object,[string]$Path)
    $value=Get-VeeamValue -Object $Object -Path $Path
    if($value -is [datetime]){return $value.ToString('o')}
    if($value -is [string] -or $value -is [guid] -or $value -is [enum] -or $value -is [version] -or $value -is [timespan] -or $value -is [byte] -or $value -is [int16] -or $value -is [uint16] -or $value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64] -or $value -is [single] -or $value -is [double] -or $value -is [decimal]){return [string]$value}
    return $null
}
function Get-JobAuditBoolean {param($Object,[string]$Path) $value=Get-VeeamValue $Object $Path;if($value -is [bool]){return $value};return $null}
$jobRows=New-Object 'System.Collections.Generic.List[object]'
$objectRows=New-Object 'System.Collections.Generic.List[object]'
$scheduleRows=New-Object 'System.Collections.Generic.List[object]'
$jobCapReached=$false; $objectCapJobs=0
if($veeamReady){
    $jobs=Invoke-ReportQuery -Section ($familyLabel+' job inventory') -Action {
        Get-VBRJob -Name $NamePattern -ErrorAction Stop | Where-Object {
            $kind=Get-VeeamValue -Object $_ -Path 'JobType'
            $null -eq $kind -or [string]$kind -eq $jobType
        } | Select-Object -First ($MaxJobs+1)
    }
    $jobCapReached=$jobs.Data.Count -gt $MaxJobs
    foreach($job in @($jobs.Data | Select-Object -First $MaxJobs)){
        $id=(Get-JobAuditText -Object $job -Path 'Id'); $name=(Get-JobAuditText -Object $job -Path 'Name')
        $type=(Get-JobAuditText -Object $job -Path 'JobType')
        $enabled=Get-JobAuditBoolean $job 'IsScheduleEnabled'
        $identityKnown=$id -and $name -and $type -eq $jobType
        $row=[pscustomobject]@{Id=$id;Name=$name;JobType=$type;ScheduleEnabled=$enabled;EvidenceStatus=$(if($identityKnown -and $null -ne $enabled){'Collected'}else{'Unknown'})}
        $jobRows.Add($row)
        if(-not $identityKnown){Add-VeeamFinding -Component ('Job '+$id) -State Unknown -Evidence 'A required job identity/type field was unavailable. No object or schedule follow-up was attempted.';continue}
        if($null -eq $enabled){Add-VeeamFinding -Component ('Schedule '+$name) -State Unknown -Evidence 'The job did not expose IsScheduleEnabled.'}
        elseif(-not [bool]$enabled){Add-VeeamFinding -Component ('Schedule '+$name) -State Review -Evidence 'The provider reports scheduling disabled; confirm whether manual or chained execution is intentional.'}
        $schedule=Invoke-ReportQuery -Section ('Schedule '+$name) -RequireData -Action {Get-VBRJobScheduleOptions -Job $job -ErrorAction Stop}
        $settings=$null;if($schedule.Succeeded){$settings=$schedule.Data[0]}
        $scheduleRow=[pscustomobject]@{JobId=$id;JobName=$name;QueryStatus=$(if($schedule.Succeeded){'Collected'}else{'Unknown'});DailyEnabled=(Get-JobAuditBoolean $settings 'OptionsDaily.Enabled');MonthlyEnabled=(Get-JobAuditBoolean $settings 'OptionsMonthly.Enabled');PeriodicEnabled=(Get-JobAuditBoolean $settings 'OptionsPeriodically.Enabled');ContinuousEnabled=(Get-JobAuditBoolean $settings 'OptionsContinuous.Enabled')}
        $scheduleRows.Add($scheduleRow)
        if($null -eq $scheduleRow.DailyEnabled -and $null -eq $scheduleRow.MonthlyEnabled -and $null -eq $scheduleRow.PeriodicEnabled -and $null -eq $scheduleRow.ContinuousEnabled){Add-VeeamFinding -Component ('Schedule detail '+$name) -State Unknown -Evidence 'No supported Boolean schedule mode fields were available; do not infer that no schedule mode is enabled.'}
        $objects=Invoke-ReportQuery -Section ('Configured objects '+$name) -Action {Get-VBRJobObject -Job $job -ErrorAction Stop | Select-Object -First ($MaxObjectsPerJob+1)}
        if($objects.Data.Count -gt $MaxObjectsPerJob){$objectCapJobs++}
        if(-not $objects.Succeeded){Add-VeeamFinding -Component ('Configured objects '+$name) -State Unknown -Evidence 'Configured job objects could not be collected.'}
        elseif(-not $objects.Data.Count){Add-VeeamFinding -Component ('Configured objects '+$name) -State Review -Evidence 'No configured objects were returned; verify selection and exclusions in the console.'}
        foreach($item in @($objects.Data | Select-Object -First $MaxObjectsPerJob)){
            $objectRows.Add([pscustomobject]@{JobId=$id;JobName=$name;Name=(Get-JobAuditText -Object $item -Path 'Name');ObjectId=(Get-JobAuditText -Object $item -Path 'ObjectId');Type=(Get-JobAuditText -Object $item -Path 'Type');IsExcluded=(Get-JobAuditBoolean $item 'IsExcluded')})
        }
    }
    if($jobCapReached){Add-VeeamFinding -Component ($familyLabel+' job scope') -State Unknown -Evidence 'MaxJobs was exceeded; additional jobs and their configuration were not inspected.'}
    if($objectCapJobs){Add-VeeamFinding -Component 'Configured object scope' -State Unknown -Evidence ('Object listings were truncated for '+$objectCapJobs+' inspected jobs.')}
    if($jobs.Succeeded -and -not $jobRows.Count){Add-VeeamFinding -Component ($familyLabel+' job inventory') -State NotApplicable -Evidence 'No matching jobs were returned in the supported classic VM job family.'}
}
Write-ReportCsv -Name 'jobs' -Rows $jobRows.ToArray() -Columns @('Id','Name','JobType','ScheduleEnabled','EvidenceStatus')
Write-ReportCsv -Name 'schedule-settings' -Rows $scheduleRows.ToArray() -Columns @('JobId','JobName','QueryStatus','DailyEnabled','MonthlyEnabled','PeriodicEnabled','ContinuousEnabled')
Write-ReportCsv -Name 'configured-job-objects' -Rows $objectRows.ToArray() -Columns @('JobId','JobName','Name','ObjectId','Type','IsExcluded')
Complete-Report -Data ([pscustomobject]@{Context=$veeamContext;Family=$familyLabel;NamePattern=$NamePattern;InspectedJobs=$jobRows.Count;ConfiguredObjectsReported=$objectRows.Count;JobCapReached=$jobCapReached;JobsWithObjectCap=$objectCapJobs}) -Notes @(
    $jobScopeNote
    'Get-VBRJobObject reports configured objects or containers, not expanded VM membership, effective exclusions, or proof that every workload was protected.'
    'Schedule option booleans are provider metadata. Blank optional fields remain unknown; chained/manual execution and backup windows need console review.'
    'Caps apply to inspected jobs and configured objects; provider calls may enumerate more internally and have no imposed timeout. Provider order is not assumed to rank importance.'
    'No complete options objects, guest credentials, encryption keys, or pre/post command lines are exported. No job is started, edited, enabled, or disabled.'
)

} finally {Close-OwnedVeeamConnection}