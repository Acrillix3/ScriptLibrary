<#
What it does:
  Audits configured backup jobs, schedules, last outcomes, and bounded inclusion/exclusion metadata counts.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9191.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -Name: Backup-job name wildcard; default all jobs.
  -MaxJobs: Maximum matching jobs, 1-10000; default 500.
  -MaxScopeItems: Maximum definition items per job and inclusion/exclusion query, 1-10000; default 1000.
  -StaleHours: Last-success review threshold, 1-87600 hours; default 48.

How it works:
  Reads v7/v8 backup jobs and supported configured-scope getters, with explicit query gaps and caps. Definition counts do not expand group membership or prove tenant coverage, and jobs are never started.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9191,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateNotNullOrEmpty()][string]$Name='*',
    [ValidateRange(1,10000)][int]$MaxJobs=500,
    [ValidateRange(1,10000)][int]$MaxScopeItems=1000,
    [ValidateRange(1,87600)][int]$StaleHours=48
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

$rows=New-Object 'System.Collections.Generic.List[object]';$scopeRows=New-Object 'System.Collections.Generic.List[object]';$truncated=$false
if($veeamReady){
    $inventory=Invoke-ReportQuery -Section 'VBOBackupJobs' -Action {Get-VBOJob -ErrorAction Stop | Where-Object { $_.Name -like $Name } | Select-Object -First ($MaxJobs+1)}
    $truncated=$inventory.Data.Count -gt $MaxJobs
    foreach($item in @($inventory.Data | Select-Object -First $MaxJobs)){
        $id=Get-VBOAuditScalar $item 'Id';$jobName=Get-VBOAuditScalar $item 'Name'
        $includedCount=$null;$excludedCount=$null;$includedTruncated=$false;$excludedTruncated=$false
        foreach($scopeKind in @('Included','Excluded')){
            $commandName='Get-VBOBackupItem';if($scopeKind -eq 'Excluded'){$commandName='Get-VBOExcludedBackupItem'}
            if(Test-VBOAuditCapability $commandName @('Job')){
                $scope=Invoke-ReportQuery -Section ('JobScope:'+ $id+':'+$scopeKind) -Action {& $commandName -Job $item -ErrorAction Stop | Select-Object -First ($MaxScopeItems+1)}
                if($scope.Succeeded){
                    $count=[math]::Min($scope.Data.Count,$MaxScopeItems);$limited=$scope.Data.Count -gt $MaxScopeItems
                    if($scopeKind -eq 'Included'){$includedCount=$count;$includedTruncated=$limited}else{$excludedCount=$count;$excludedTruncated=$limited}
                    $types=@($scope.Data | Select-Object -First $MaxScopeItems | ForEach-Object { $type=Get-VBOAuditScalar $_ 'Type';if($null -eq $type){'Unknown'}else{[string]$type} } | Group-Object)
                    foreach($typeGroup in $types){$scopeRows.Add([pscustomobject]@{JobId=$id;JobName=$jobName;ScopeKind=$scopeKind;ConfiguredItemType=$typeGroup.Name;ObservedCount=$typeGroup.Count;ScopeTruncated=$limited})}
                }
            }else{Add-VeeamFinding -Component ('JobScope:'+ $jobName+':'+$scopeKind) -State Unknown -Evidence ($commandName+' or its Job parameter is unavailable; scope count was not inferred.')}
        }
        $row=[pscustomobject]@{Id=$id;Name=$jobName;Organization=Get-VBOAuditScalar $item 'Organization.Name';Repository=Get-VBOAuditScalar $item 'Repository.Name';JobType=Get-VBOAuditScalar $item 'JobType';JobBackupType=Get-VBOAuditScalar $item 'JobBackupType';IsEnabled=Get-VBOAuditScalar $item 'IsEnabled';LastStatus=Get-VBOAuditScalar $item 'LastStatus';LastRun=Get-VBOAuditScalar $item 'LastRun';LastBackup=Get-VBOAuditScalar $item 'LastBackup';NextRun=Get-VBOAuditScalar $item 'NextRun';ScheduleEnabled=Get-VBOAuditScalar $item 'SchedulePolicy.EnableSchedule';ScheduleType=Get-VBOAuditScalar $item 'SchedulePolicy.Type';DailyType=Get-VBOAuditScalar $item 'SchedulePolicy.DailyType';DailyTime=Get-VBOAuditScalar $item 'SchedulePolicy.DailyTime';PeriodicallyEvery=Get-VBOAuditScalar $item 'SchedulePolicy.PeriodicallyEvery';RetryEnabled=Get-VBOAuditScalar $item 'SchedulePolicy.RetryEnabled';RetryNumber=Get-VBOAuditScalar $item 'SchedulePolicy.RetryNumber';IncludedConfiguredItemsObserved=$includedCount;IncludedScopeTruncated=$includedTruncated;ExcludedConfiguredItemsObserved=$excludedCount;ExcludedScopeTruncated=$excludedTruncated}
        if($row.IsEnabled -eq $false){Add-VeeamFinding -Component ('BackupJob:'+ $jobName) -State Review -Evidence 'Backup job is disabled.'}
        if($row.LastStatus -eq 'Failed'){Add-VeeamFinding -Component ('BackupJob:'+ $jobName) -State Fail -Evidence 'Last reported job status is Failed.'}
        elseif($row.LastStatus -eq 'Warning'){Add-VeeamFinding -Component ('BackupJob:'+ $jobName) -State Review -Evidence 'Last reported job status is Warning.'}
        if($row.LastBackup){try{if([datetime]$row.LastBackup -lt (Get-Date).AddHours(-$StaleHours)){Add-VeeamFinding -Component ('BackupFreshness:'+ $jobName) -State Review -Evidence ('Last successful backup is older than '+$StaleHours+' hours.')}}catch{Add-VeeamFinding -Component ('BackupFreshness:'+ $jobName) -State Unknown -Evidence 'Last successful backup time was invalid.'}}
        else{Add-VeeamFinding -Component ('BackupFreshness:'+ $jobName) -State Unknown -Evidence 'Last successful backup time was not reported.'}
        if($includedTruncated -or $excludedTruncated){Add-VeeamFinding -Component ('JobScopeLimit:'+ $jobName) -State Review -Evidence 'Configured inclusion or exclusion definitions exceeded MaxScopeItems.'}
        $rows.Add($row)
    }
    if($truncated){Add-VeeamFinding -Component 'BackupJobScope' -State Review -Evidence 'Backup job inventory was capped by MaxJobs.'}
}else{Add-VeeamFinding -Component 'BackupJobAudit' -State Unknown -Evidence 'VBO connection or supported-version detection did not complete.'}
Write-ReportCsv -Name 'backup-jobs' -Rows $rows.ToArray() -Columns @('Id','Name','Organization','Repository','JobType','JobBackupType','IsEnabled','LastStatus','LastRun','LastBackup','NextRun','ScheduleEnabled','ScheduleType','DailyType','DailyTime','PeriodicallyEvery','RetryEnabled','RetryNumber','IncludedConfiguredItemsObserved','IncludedScopeTruncated','ExcludedConfiguredItemsObserved','ExcludedScopeTruncated')
Write-ReportCsv -Name 'configured-scope-counts' -Rows $scopeRows.ToArray() -Columns @('JobId','JobName','ScopeKind','ConfiguredItemType','ObservedCount','ScopeTruncated')
Complete-Report -Data ([pscustomobject]@{JobsReported=$rows.Count;JobsTruncated=$truncated;MaxJobs=$MaxJobs;MaxScopeItemsPerJobAndKind=$MaxScopeItems;StaleHours=$StaleHours}) -Notes @(
    'Scope counts describe configured definition objects, not expanded tenant users/sites, unique protected entities, workload completion, or exclusion precedence. Group/dynamic selections and EntireOrganization require further assessment.'
    'Only metadata counts and item types are exported; no scope account details, connection settings, script bodies, credentials, or tokens are exported.'
    'LastStatus and LastBackup are observations, not proof of recoverability. StaleHours is your review threshold and can differ from the intended schedule.'
    'No backup, copy, synchronization, rescan, or restore is started.'
)


} finally {Close-OwnedVeeamConnection}