<#
What it does:
  Reports classic VMware/Hyper-V replication job scheduling and configured object selections.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -NamePattern: Classic job-name wildcard; default *.
  -MaxJobs: Maximum matching jobs inspected; default 100.
  -MaxObjectsPerJob: Maximum configured selections per job; default 200.

How it works:
  Reads Get-VBRJob Replica jobs, schedule settings, and configured objects through installed v12 tools. Excludes CDP and failover state evaluation; no replication, failover, or configuration change occurs.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateNotNullOrEmpty()][string]$NamePattern='*',
[ValidateRange(1,10000)][int]$MaxJobs=100,
[ValidateRange(1,10000)][int]$MaxObjectsPerJob=200
)
$script:VeeamProduct='VBR'
$ErrorActionPreference='Stop'
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$runName=[IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Path)
$runDirectory=Join-Path $OutputDirectory ($runName+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $runDirectory -Force
$collectionStatus=New-Object 'System.Collections.Generic.List[object]'
$findings=New-Object 'System.Collections.Generic.List[object]'
$veeamReady=$false;$ownsVeeamConnection=$false
$veeamContext=[pscustomobject]@{Product=$script:VeeamProduct;Server=$Server;Port=$Port;MajorVersion=$null;ServerVersion=$null;ToolkitProductVersion=$null;ModuleVersion=$null;VersionSource='Unknown';RemoteVersionVerified=$false;VersionRejected=$false;ConnectionSucceeded=$false;PowerShellVersion=[string]$PSVersionTable.PSVersion}
function Get-VeeamValue {
    param([object]$Object,[string]$Path)
    $value=$Object
    foreach($part in $Path.Split('.')){
        if($null -eq $value){return $null}
        if($value -is [System.Collections.IDictionary]){if(-not $value.Contains($part)){return $null};$value=$value[$part]}
        else{$property=$value.PSObject.Properties[$part];if($null -eq $property){return $null};try{$value=$property.Value}catch{return $null}}
    }
    return $value
}
function Add-VeeamFinding {
    param([string]$Component,[ValidateSet('Pass','Review','Fail','Unknown','NotApplicable')][string]$State,[string]$Evidence)
    $findings.Add([pscustomobject]@{Component=$Component;State=$State;Evidence=$Evidence})
}
function Invoke-ReportQuery {
    param([string]$Section,[scriptblock]$Action,[switch]$RequireData)
    try{
        $items=@(& $Action)
        if($RequireData -and $items.Count -eq 0){throw [System.InvalidOperationException]::new('Required data absent')}
        $collectionStatus.Add([pscustomobject]@{Section=$Section;State='Collected';Rows=$items.Count;ErrorType=$null})
        return [pscustomobject]@{Succeeded=$true;Data=$items}
    }catch{
        $collectionStatus.Add([pscustomobject]@{Section=$Section;State='Unknown';Rows=$null;ErrorType=$_.Exception.GetType().FullName})
        Add-VeeamFinding -Component $Section -State Unknown -Evidence 'Collection failed or required data was absent. Check permissions, component availability, version, and connectivity. Raw vendor error text is excluded to avoid exposing secrets.'
        return [pscustomobject]@{Succeeded=$false;Data=@()}
    }
}
function Write-ReportCsv {
    param([string]$Name,[AllowNull()][AllowEmptyCollection()][object[]]$Rows,[string[]]$Columns)
    $path=Join-Path $runDirectory ($Name+'.csv')
    if(@($Rows).Count -gt 0){$Rows | Select-Object -Property $Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8}
    else{($Columns | ForEach-Object {'"'+$_.Replace('"','""')+'"'}) -join ',' | Set-Content -LiteralPath $path -Encoding UTF8}
}
function Complete-Report {
    param([object]$Data,[string[]]$Notes)
    Write-ReportCsv -Name 'collection-status' -Rows $collectionStatus.ToArray() -Columns @('Section','State','Rows','ErrorType')
    Write-ReportCsv -Name 'findings' -Rows $findings.ToArray() -Columns @('Component','State','Evidence')
    $state=if(@($findings | Where-Object State -eq Fail).Count){'Fail'}elseif(@($findings | Where-Object State -eq Unknown).Count){'Incomplete'}elseif(@($findings | Where-Object State -eq Review).Count){'Review'}else{'Collected'}
    $summary=[pscustomobject]@{Script=$runName;GeneratedUtc=[datetime]::UtcNow.ToString('o');State=$state;Context=$veeamContext;Data=$Data;Notes=$Notes;ReportDirectory=[IO.Path]::GetFullPath($runDirectory)}
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runDirectory 'summary.json') -Encoding UTF8
    @('Script: '+$runName,'State: '+$state,'Target: '+$Server,'Version source: '+$veeamContext.VersionSource,'',($Notes -join [Environment]::NewLine),'','Unknown or empty results do not establish health, recoverability, or complete coverage. Review collection-status.csv and findings.csv.') | Set-Content -LiteralPath (Join-Path $runDirectory 'README.txt') -Encoding UTF8
    return $summary
}
function Get-ProductHostVersion {
    param([string]$ComputerName,[string]$ServiceName)
    $probe={
        param($RequestedService)
        $service=Get-CimInstance -ClassName Win32_Service -Filter ("Name='"+$RequestedService+"'") -ErrorAction Stop
        if($null -eq $service){return}
        $match=[regex]::Match([string]$service.PathName,'^(?:"([^"]+\.exe)"|(.+?\.exe))(?:\s|$)','IgnoreCase')
        if(-not $match.Success){return}
        $binary=if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value}
        if(Test-Path -LiteralPath $binary -PathType Leaf){[pscustomobject]@{ProductVersion=[Diagnostics.FileVersionInfo]::GetVersionInfo($binary).ProductVersion}}
    }
    $localNames=@('localhost','.','127.0.0.1','::1',$env:COMPUTERNAME,([Net.Dns]::GetHostName()))
    if($ComputerName -in $localNames){& $probe $ServiceName}
    else{
        $arguments=@{ComputerName=$ComputerName;ScriptBlock=$probe;ArgumentList=@($ServiceName);ErrorAction='Stop'}
        if($HostCredential){$arguments.Credential=$HostCredential}
        Invoke-Command @arguments | Select-Object ProductVersion
    }
}
function Initialize-VeeamConnection {
    $moduleName=if($script:VeeamProduct -eq 'VBR'){'Veeam.Backup.PowerShell'}else{'Veeam.Archiver.PowerShell'}
    $module=Invoke-ReportQuery -Section 'ImportVeeamModule' -Action {Import-Module -Name $moduleName -PassThru -ErrorAction Stop | Select-Object -First 1} -RequireData
    if(-not $module.Succeeded){return}
    $veeamContext.ModuleVersion=[string]$module.Data[0].Version
    # VBR manifest Version 1.0 is shared by multiple product majors.
    # Compare product-version evidence, never the manifest version, with a server.
    $toolVersion=$null
    if($script:VeeamProduct -eq 'VBO'){
        $version=Invoke-ReportQuery -Section 'ToolkitProductVersion' -Action {Get-VBOVersion -ErrorAction Stop} -RequireData
        if($version.Succeeded){$toolVersion=[string](Get-VeeamValue $version.Data[0] 'ProductVersion');$veeamContext.ToolkitProductVersion=$toolVersion}
    }else{
        try{
            $cmdlet=Get-Command -Name Get-VBRJob -ErrorAction Stop
            $assemblyPath=Get-VeeamValue $cmdlet 'ImplementingType.Assembly.Location'
            if($assemblyPath){
                $candidate=[Diagnostics.FileVersionInfo]::GetVersionInfo([string]$assemblyPath).ProductVersion
                if($candidate -match '^\d+\.\d+'){$toolVersion=[string]$candidate;$veeamContext.ToolkitProductVersion=$toolVersion}
            }
        }catch{<# Server-side version evidence below can resolve an unavailable local assembly version. #>}
    }
    if($toolVersion -match '^(\d+)\.'){$veeamContext.MajorVersion=[int]$Matches[1];$veeamContext.VersionSource='LocalToolkitProductVersion'}
    $serviceName=if($script:VeeamProduct -eq 'VBR'){'VeeamBackupSvc'}else{'Veeam.Archiver.Service'}
    $hostVersion=Invoke-ReportQuery -Section 'ServerServiceBinaryVersion' -Action {Get-ProductHostVersion -ComputerName $Server -ServiceName $serviceName} -RequireData
    if($hostVersion.Succeeded){
        $serverBuild=[string](Get-VeeamValue $hostVersion.Data[0] 'ProductVersion')
        if($serverBuild -match '^(\d+)\.'){
            $serverMajor=[int]$Matches[1]
            if($null -ne $veeamContext.MajorVersion -and $veeamContext.MajorVersion -ne $serverMajor){$veeamContext.VersionRejected=$true;Add-VeeamFinding 'ToolkitServerVersion' Fail 'Toolkit and requested server have different major versions. Use a matching supported console.';return}
            $veeamContext.MajorVersion=$serverMajor;$veeamContext.ServerVersion=$serverBuild;$veeamContext.RemoteVersionVerified=$true;$veeamContext.VersionSource='RequestedServerServiceBinary'
        }
    }
    $allowedMajors=if($script:VeeamProduct -eq 'VBR'){@(12)}else{@(7,8)}
    $canVerifyConnectedVbr=$script:VeeamProduct -eq 'VBR' -and $null -ne (Get-Command Get-VBRBackupServerInfo -ErrorAction SilentlyContinue)
    if($null -ne $veeamContext.MajorVersion -and $veeamContext.MajorVersion -notin $allowedMajors){$veeamContext.VersionRejected=$true;Add-VeeamFinding 'SupportedVersion' Unknown 'The detected product major version is outside this toolkit target range. Product queries were skipped.';return}
    if($null -eq $veeamContext.MajorVersion -and -not $canVerifyConnectedVbr){Add-VeeamFinding 'SupportedVersion' Unknown 'No supported product version could be established. A module manifest version is not a product version; product queries were skipped.';return}
    $connectName=if($script:VeeamProduct -eq 'VBR'){'Connect-VBRServer'}else{'Connect-VBOServer'}
    $connection=Invoke-ReportQuery -Section 'ConnectRequestedVeeamServer' -Action {
        $arguments=@{Server=$Server;Port=$Port;ErrorAction='Stop'}
        if($Credential){$arguments.Credential=$Credential}
        & $connectName @arguments | Out-Null
    }
    if(-not $connection.Succeeded){return}
    $script:ownsVeeamConnection=$true;$veeamContext.ConnectionSucceeded=$true
    if($canVerifyConnectedVbr){
        $info=Invoke-ReportQuery -Section 'ConnectedVBRServerVersion' -Action {Get-VBRBackupServerInfo -ErrorAction Stop} -RequireData
        if($info.Succeeded){
            $build=[string](Get-VeeamValue $info.Data[0] 'Build')
            if($build -match '^(\d+)\.'){
                if([int]$Matches[1] -ne 12){$veeamContext.VersionRejected=$true;Add-VeeamFinding 'ConnectedServerVersion' Fail 'Connected backup server is outside VBR v12. Queries were skipped.';return}
                $veeamContext.MajorVersion=12;$veeamContext.ServerVersion=$build;$veeamContext.RemoteVersionVerified=$true;$veeamContext.VersionSource='Get-VBRBackupServerInfo'
            }
        }
    }
    if($script:VeeamProduct -eq 'VBR' -and -not $veeamContext.RemoteVersionVerified){Add-VeeamFinding 'ServerVersion' Unknown 'The requested VBR server product version was not verified; audit queries were skipped.';return}
    if($veeamContext.MajorVersion -notin $allowedMajors){Add-VeeamFinding 'SupportedVersion' Unknown 'The connected product major version is unknown or unsupported; audit queries were skipped.';return}
    if(-not $veeamContext.RemoteVersionVerified){Add-VeeamFinding 'ServerVersion' Unknown 'Only the local toolkit product version was detected. The requested server build remains unverified; no version is inferred from proxy or component names.'}
    $script:veeamReady=$true
}
function Close-OwnedVeeamConnection {
    if($ownsVeeamConnection){
        try{if($script:VeeamProduct -eq 'VBR'){Disconnect-VBRServer -ErrorAction Stop | Out-Null}else{Disconnect-VBOServer -ErrorAction Stop | Out-Null}}
        catch{Write-Warning 'The session created by this script could not be disconnected. Start a fresh PowerShell process before the next run.'}
    }
}

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
    $jobs=Invoke-ReportQuery -Section 'replication job inventory' -Action {
        Get-VBRJob -Name $NamePattern -ErrorAction Stop | Where-Object {
            $kind=Get-VeeamValue -Object $_ -Path 'JobType'
            $null -eq $kind -or [string]$kind -eq 'Replica'
        } | Select-Object -First ($MaxJobs+1)
    }
    $jobCapReached=$jobs.Data.Count -gt $MaxJobs
    foreach($job in @($jobs.Data | Select-Object -First $MaxJobs)){
        $id=(Get-JobAuditText -Object $job -Path 'Id'); $name=(Get-JobAuditText -Object $job -Path 'Name')
        $type=(Get-JobAuditText -Object $job -Path 'JobType')
        $enabled=Get-JobAuditBoolean $job 'IsScheduleEnabled'
        $identityKnown=$id -and $name -and $type -eq 'Replica'
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
    if($jobCapReached){Add-VeeamFinding -Component 'replication job scope' -State Unknown -Evidence 'MaxJobs was exceeded; additional jobs and their configuration were not inspected.'}
    if($objectCapJobs){Add-VeeamFinding -Component 'Configured object scope' -State Unknown -Evidence ('Object listings were truncated for '+$objectCapJobs+' inspected jobs.')}
    if($jobs.Succeeded -and -not $jobRows.Count){Add-VeeamFinding -Component 'replication job inventory' -State NotApplicable -Evidence 'No matching jobs were returned in the supported classic VM job family.'}
}
Write-ReportCsv -Name 'jobs' -Rows $jobRows.ToArray() -Columns @('Id','Name','JobType','ScheduleEnabled','EvidenceStatus')
Write-ReportCsv -Name 'schedule-settings' -Rows $scheduleRows.ToArray() -Columns @('JobId','JobName','QueryStatus','DailyEnabled','MonthlyEnabled','PeriodicEnabled','ContinuousEnabled')
Write-ReportCsv -Name 'configured-job-objects' -Rows $objectRows.ToArray() -Columns @('JobId','JobName','Name','ObjectId','Type','IsExcluded')
Complete-Report -Data ([pscustomobject]@{Context=$veeamContext;Family='replication';NamePattern=$NamePattern;InspectedJobs=$jobRows.Count;ConfiguredObjectsReported=$objectRows.Count;JobCapReached=$jobCapReached;JobsWithObjectCap=$objectCapJobs}) -Notes @(
    'Scope is classic VMware/Hyper-V replication jobs returned by Get-VBRJob with JobType Replica. Agent, NAS/unstructured, tape, CDP, SureBackup, plug-in, and cloud-native jobs are outside this script.'
    'Get-VBRJobObject reports configured objects or containers, not expanded VM membership, effective exclusions, or proof that every workload was protected.'
    'Schedule option booleans are provider metadata. Blank optional fields remain unknown; chained/manual execution and backup windows need console review.'
    'Caps apply to inspected jobs and configured objects; provider calls may enumerate more internally and have no imposed timeout. Provider order is not assumed to rank importance.'
    'No complete options objects, guest credentials, encryption keys, or pre/post command lines are exported. No job is started, edited, enabled, or disabled.'
)

} finally {Close-OwnedVeeamConnection}