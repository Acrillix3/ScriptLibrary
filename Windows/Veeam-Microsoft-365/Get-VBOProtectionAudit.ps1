<#
What it does:
  Combines configured organization/job scope with bounded restore-point evidence and sample freshness.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9191.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -OrganizationName: Organization-name wildcard; default all organizations.
  -MaxOrganizations: Maximum organizations, 1-10000; default 100.
  -MaxJobsPerOrganization: Maximum configured jobs per organization, 1-10000; default 200.
  -MaxRestorePointsPerOrganization: Maximum restore points per organization, 1-10000; default 500.
  -FreshnessHours: Sample restore-point review threshold, 1-87600 hours; default 48.

How it works:
  Uses supported v7/v8 per-organization getters without tenant synchronization or restore execution. Sample points and configured scopes cannot prove every user/workload is protected; provider-order caps and unknown fields remain explicit.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9191,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateNotNullOrEmpty()][string]$OrganizationName='*',
    [ValidateRange(1,10000)][int]$MaxOrganizations=100,
    [ValidateRange(1,10000)][int]$MaxJobsPerOrganization=200,
    [ValidateRange(1,10000)][int]$MaxRestorePointsPerOrganization=500,
    [ValidateRange(1,87600)][int]$FreshnessHours=48
)
$script:VeeamProduct='VBO'
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
function Get-VBOAuditScalar {
    param([object]$InputObject,[string]$Path)
    $value=Get-VeeamValue -Object $InputObject -Path $Path
    if($null -eq $value){return $null}
    if($value -is [datetime]){return $value.ToString('o')}
    if($value -is [guid] -or $value -is [timespan] -or $value -is [enum]){return [string]$value}
    if($value -is [string] -or $value -is [bool] -or $value -is [byte] -or $value -is [int16] -or $value -is [uint16] -or $value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64] -or $value -is [single] -or $value -is [double] -or $value -is [decimal]){return $value}
    $null
}
function Test-VBOAuditCapability {
    param([string]$Name,[string[]]$Parameters=@())
    $command=Get-Command -Name $Name -ErrorAction SilentlyContinue
    if($null -eq $command){return $false}
    foreach($parameterName in $Parameters){if(-not $command.Parameters.ContainsKey($parameterName)){return $false}}
    $true
}

$organizationRows=New-Object 'System.Collections.Generic.List[object]';$jobRows=New-Object 'System.Collections.Generic.List[object]';$pointRows=New-Object 'System.Collections.Generic.List[object]';$organizationsTruncated=$false
if($veeamReady){
    $organizations=Invoke-ReportQuery -Section 'VBOProtectionOrganizations' -Action {Get-VBOOrganization -ErrorAction Stop | Where-Object {$_.Name -like $OrganizationName} | Select-Object -First ($MaxOrganizations+1)}
    $organizationsTruncated=$organizations.Data.Count -gt $MaxOrganizations
    foreach($organization in @($organizations.Data | Select-Object -First $MaxOrganizations)){
        $orgId=Get-VBOAuditScalar $organization 'Id';$orgName=Get-VBOAuditScalar $organization 'Name'
        $jobs=Invoke-ReportQuery -Section ('ConfiguredProtectionJobs:'+ $orgId) -Action {
            if(-not (Test-VBOAuditCapability 'Get-VBOJob' @('Organization'))){throw 'The installed job getter has no Organization parameter; this bounded per-organization query is unsupported.'}
            Get-VBOJob -Organization $organization -ErrorAction Stop | Select-Object -First ($MaxJobsPerOrganization+1)
        }
        $jobsTruncated=$jobs.Data.Count -gt $MaxJobsPerOrganization
        $enabledObserved=0
        foreach($job in @($jobs.Data | Select-Object -First $MaxJobsPerOrganization)){
            $enabled=Get-VBOAuditScalar $job 'IsEnabled';if($enabled -eq $true){$enabledObserved++}
            $jobRows.Add([pscustomobject]@{OrganizationId=$orgId;OrganizationName=$orgName;JobId=Get-VBOAuditScalar $job 'Id';JobName=Get-VBOAuditScalar $job 'Name';IsEnabled=$enabled;ConfiguredScope=Get-VBOAuditScalar $job 'JobBackupType';Repository=Get-VBOAuditScalar $job 'Repository.Name';LastStatus=Get-VBOAuditScalar $job 'LastStatus';LastBackup=Get-VBOAuditScalar $job 'LastBackup'})
        }
        $points=Invoke-ReportQuery -Section ('RestorePointEvidence:'+ $orgId) -Action {
            if(-not (Test-VBOAuditCapability 'Get-VBORestorePoint' @('Organization'))){throw 'The installed restore-point getter has no Organization parameter; this bounded query is unsupported.'}
            Get-VBORestorePoint -Organization $organization -ErrorAction Stop | Select-Object -First ($MaxRestorePointsPerOrganization+1)
        }
        $pointsTruncated=$points.Data.Count -gt $MaxRestorePointsPerOrganization
        $orgPointRows=@(foreach($point in @($points.Data | Select-Object -First $MaxRestorePointsPerOrganization)){
            [pscustomobject]@{OrganizationId=$orgId;OrganizationName=$orgName;Id=Get-VBOAuditScalar $point 'Id';JobId=Get-VBOAuditScalar $point 'JobId';RepositoryId=Get-VBOAuditScalar $point 'RepositoryId';BackupTime=Get-VBOAuditScalar $point 'BackupTime';IsExchange=Get-VBOAuditScalar $point 'IsExchange';IsSharePoint=Get-VBOAuditScalar $point 'IsSharePoint';IsOneDrive=Get-VBOAuditScalar $point 'IsOneDrive';IsTeams=Get-VBOAuditScalar $point 'IsTeams';IsLongTermCopy=Get-VBOAuditScalar $point 'IsLongTermCopy';IsCopy=Get-VBOAuditScalar $point 'IsCopy';IsRetrieved=Get-VBOAuditScalar $point 'IsRetrieved';IsRetrievable=Get-VBOAuditScalar $point 'IsRetrievable';ImmutabilityExpiresOn=Get-VBOAuditScalar $point 'ImmutabilityExpiresOn'}
        })
        foreach($pointRow in $orgPointRows){$pointRows.Add($pointRow)}
        $sampleTimes=New-Object 'System.Collections.Generic.List[datetime]'
        foreach($pointRow in $orgPointRows){if($pointRow.BackupTime){$parsedTime=[datetime]::MinValue;if([datetime]::TryParse([string]$pointRow.BackupTime,[ref]$parsedTime)){$sampleTimes.Add($parsedTime)}}}
        $newest=$null;$ageHours=$null;$freshness='Unknown'
        if($sampleTimes.Count){$newest=@($sampleTimes | Sort-Object -Descending)[0];$ageHours=[math]::Round(((Get-Date)-$newest).TotalHours,2);$freshness=if($ageHours -lt 0){'FutureTimestampReview'}elseif($ageHours -gt $FreshnessHours){'SampleOlderThanThreshold'}else{'RecentPointObserved'}}
        if($jobs.Succeeded -and $jobs.Data.Count -eq 0){Add-VeeamFinding -Component ('ConfiguredProtection:'+ $orgName) -State Review -Evidence 'No backup jobs were returned for this configured organization scope.'}
        if($points.Succeeded -and $points.Data.Count -eq 0){Add-VeeamFinding -Component ('RestorePointEvidence:'+ $orgName) -State Review -Evidence 'No restore points were returned by the default per-organization query; this is not a tenant-wide protection verdict.'}
        if($freshness -in 'FutureTimestampReview','SampleOlderThanThreshold'){Add-VeeamFinding -Component ('PointFreshness:'+ $orgName) -State Review -Evidence ($freshness+' in the bounded sample; review scope and intended recovery objectives.')}
        elseif($freshness -eq 'Unknown'){Add-VeeamFinding -Component ('PointFreshness:'+ $orgName) -State Unknown -Evidence 'No usable restore-point timestamp was returned; sample freshness could not be assessed.'}
        if($jobsTruncated -or $pointsTruncated){Add-VeeamFinding -Component ('ProtectionScope:'+ $orgName) -State Review -Evidence 'Job or restore-point evidence was capped for this organization.'}
        $organizationRows.Add([pscustomobject]@{OrganizationId=$orgId;OrganizationName=$orgName;ConfiguredBackupParts=Get-VBOAuditScalar $organization 'BackupParts';OrganizationIsBackedUp=Get-VBOAuditScalar $organization 'IsBackedUp';JobCollection=$(if($jobs.Succeeded){'Collected'}else{'Unknown'});JobsObserved=$(if($jobs.Succeeded){[math]::Min($jobs.Data.Count,$MaxJobsPerOrganization)}else{$null});EnabledJobsObserved=$(if($jobs.Succeeded){$enabledObserved}else{$null});JobsTruncated=$jobsTruncated;RestorePointCollection=$(if($points.Succeeded){'Collected'}else{'Unknown'});RestorePointsObserved=$(if($points.Succeeded){$orgPointRows.Count}else{$null});RestorePointsTruncated=$pointsTruncated;NewestSampleBackupTime=$(if($null -ne $newest){$newest.ToString('o')}else{$null});NewestSampleAgeHours=$ageHours;SampleFreshness=$freshness;TenantWideCoverageAssessment='NotEstablished'})
    }
    if($organizationsTruncated){Add-VeeamFinding -Component 'ProtectionOrganizationScope' -State Review -Evidence 'Organization enumeration was capped by MaxOrganizations.'}
}else{Add-VeeamFinding -Component 'ProtectionAudit' -State Unknown -Evidence 'VBO connection or supported-version detection did not complete.'}
Write-ReportCsv -Name 'organization-protection-evidence' -Rows $organizationRows.ToArray() -Columns @('OrganizationId','OrganizationName','ConfiguredBackupParts','OrganizationIsBackedUp','JobCollection','JobsObserved','EnabledJobsObserved','JobsTruncated','RestorePointCollection','RestorePointsObserved','RestorePointsTruncated','NewestSampleBackupTime','NewestSampleAgeHours','SampleFreshness','TenantWideCoverageAssessment')
Write-ReportCsv -Name 'configured-protection-jobs' -Rows $jobRows.ToArray() -Columns @('OrganizationId','OrganizationName','JobId','JobName','IsEnabled','ConfiguredScope','Repository','LastStatus','LastBackup')
Write-ReportCsv -Name 'restore-point-evidence' -Rows $pointRows.ToArray() -Columns @('OrganizationId','OrganizationName','Id','JobId','RepositoryId','BackupTime','IsExchange','IsSharePoint','IsOneDrive','IsTeams','IsLongTermCopy','IsCopy','IsRetrieved','IsRetrievable','ImmutabilityExpiresOn')
Complete-Report -Data ([pscustomobject]@{OrganizationsReported=$organizationRows.Count;OrganizationsTruncated=$organizationsTruncated;ConfiguredJobsReported=$jobRows.Count;RestorePointsReported=$pointRows.Count;MaxOrganizations=$MaxOrganizations;MaxJobsPerOrganization=$MaxJobsPerOrganization;MaxRestorePointsPerOrganization=$MaxRestorePointsPerOrganization;FreshnessHours=$FreshnessHours;TenantWideCoverageAssessment='NotEstablished'}) -Notes @(
    'This joins configured organization/job metadata with bounded restore-point observations. It cannot prove that every tenant user, mailbox, site, OneDrive, team, or workload is protected.'
    'Group expansion, dynamic membership, exclusions, licensing, overlapping job scopes, deleted entities, tenant enumeration and per-object restore success are not evaluated. Use configured-scope counts from the separate backup job audit for additional definition evidence.'
    'The default restore-point query is used; copy/archive/retrieved points are not assumed included. v7/v8-specific point flags stay blank when unavailable; no copy/retrieval capability is inferred.'
    'Provider-order caps mean the newest point in a sample may not be the newest point overall. Freshness depends on the local clock and does not demonstrate recoverability or compliance.'
    'No synchronization, indexing, integrity test, restore session, backup, copy, or retrieval is started.'
)


} finally {Close-OwnedVeeamConnection}