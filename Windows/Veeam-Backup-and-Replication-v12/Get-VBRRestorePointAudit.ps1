<#
What it does:
  Reports cataloged restore points and configurable per-object age findings without testing restores.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -BackupNamePattern: Backup catalog-name wildcard; default *.
  -ObjectNamePattern: Restore-point object-name wildcard, always passed for Agent visibility; default *.
  -MaxBackups: Maximum backup catalogs inspected; default 100.
  -MaxRestorePointsPerBackup: Maximum points retained per backup; default 1000.
  -MaxObjectsPerBackup: Maximum object age summaries per backup; default 200.
  -MaxAgeHours: Age threshold for review; default 48.

How it works:
  Reads Get-VBRBackup catalogs and Get-VBRRestorePoint metadata, using only explicit UTC times for age. Caps and missing data prevent completeness claims. No backup is opened, rescanned, mounted, or restored.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateNotNullOrEmpty()][string]$BackupNamePattern='*',
[ValidateNotNullOrEmpty()][string]$ObjectNamePattern='*',
[ValidateRange(1,10000)][int]$MaxBackups=100,
[ValidateRange(1,100000)][int]$MaxRestorePointsPerBackup=1000,
[ValidateRange(1,10000)][int]$MaxObjectsPerBackup=200,
[ValidateRange(1,876000)][int]$MaxAgeHours=48
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
function Convert-RestorePointUtc {
    param($Value)
    if($null -eq $Value){return $null}
    try{$date=[datetime]$Value;if($date.Year -lt 1901){return $null};if($date.Kind -eq [DateTimeKind]::Local){return $date.ToUniversalTime()};return [datetime]::SpecifyKind($date,[DateTimeKind]::Utc)}catch{return $null}
}
$backupRows=New-Object 'System.Collections.Generic.List[object]';$pointRows=New-Object 'System.Collections.Generic.List[object]';$objectRows=New-Object 'System.Collections.Generic.List[object]'
$backupCap=$false;$pointCapBackups=0;$objectCapBackups=0;$observedUtc=[datetime]::UtcNow
if($veeamReady){
    $backups=Invoke-ReportQuery -Section 'Backup catalog inventory' -Action {Get-VBRBackup -Name $BackupNamePattern -ErrorAction Stop | Select-Object -First ($MaxBackups+1)}
    $backupCap=$backups.Data.Count -gt $MaxBackups
    foreach($backup in @($backups.Data | Select-Object -First $MaxBackups)){
        $backupId=(Get-JobAuditText -Object $backup -Path 'Id');$backupName=(Get-JobAuditText -Object $backup -Path 'Name')
        $points=Invoke-ReportQuery -Section ('Restore points '+$backupId+' '+$backupName) -Action {Get-VBRRestorePoint -Backup $backup -Name $ObjectNamePattern -ErrorAction Stop | Select-Object -First ($MaxRestorePointsPerBackup+1)}
        $pointCap=$points.Data.Count -gt $MaxRestorePointsPerBackup;if($pointCap){$pointCapBackups++}
        $localRows=New-Object 'System.Collections.Generic.List[object]'
        foreach($point in @($points.Data | Select-Object -First $MaxRestorePointsPerBackup)){
            $created=Convert-RestorePointUtc (Get-VeeamValue $point 'CreationTimeUtc');$age=$null
            if($created){$age=[math]::Round(($observedUtc-$created).TotalHours,2)}
            $name=(Get-JobAuditText -Object $point -Path 'Name');$objectId=(Get-JobAuditText -Object $point -Path 'ObjectId')
            $corrupted=Get-VeeamValue $point 'IsCorrupted';if($corrupted -isnot [bool]){$corrupted=$null}
            $row=[pscustomobject]@{BackupId=$backupId;BackupName=$backupName;RestorePointId=(Get-JobAuditText -Object $point -Path 'Id');ObjectId=$objectId;ObjectName=$name;Type=(Get-JobAuditText -Object $point -Path 'Type');CreationTimeUtc=$(if($created){$created.ToString('o')}else{$null});AgeHours=$age;IsCorrupted=$corrupted;TimeEvidence=$(if($created){'ExplicitUtcField'}else{'Unknown'})}
            $localRows.Add($row);$pointRows.Add($row)
            if($row.IsCorrupted -eq $true){Add-VeeamFinding -Component ('Restore point '+$row.RestorePointId) -State Fail -Evidence 'The catalog provider reports this restore point as corrupted; no repair or verification was attempted.'}
        }
        $groups=@($localRows | Group-Object ObjectId,ObjectName | Select-Object -First ($MaxObjectsPerBackup+1))
        $objectCap=$groups.Count -gt $MaxObjectsPerBackup;if($objectCap){$objectCapBackups++}
        foreach($group in @($groups | Select-Object -First $MaxObjectsPerBackup)){
            $first=$group.Group[0];$dated=@($group.Group | Where-Object {$null -ne $_.AgeHours} | Sort-Object AgeHours)
            $youngest=$null;if($dated.Count){$youngest=$dated[0]}
            $assessment='Unknown';$evidence='No usable explicit UTC restore-point time was returned.'
            if($youngest){
                if($youngest.AgeHours -lt 0){$evidence='A restore point appears in the future; review clocks and time metadata.'}
                elseif($youngest.AgeHours -ge $MaxAgeHours){if($pointCap -or $dated.Count -lt $group.Count){$evidence='Inspected dated points are old but the point cap or missing timestamps prevent a newest-point completeness claim.'}else{$assessment='Review';$evidence='The newest observed catalog point exceeds the configured age threshold.'}}
                else{$assessment='Pass';$evidence='At least one inspected catalog point is within the configured age threshold; recoverability is not tested.'}
            }
            if(-not $first.ObjectId -and -not $first.ObjectName){$assessment='Unknown';$evidence='Object identity is unavailable; point grouping cannot establish workload coverage.'}
            $objectRows.Add([pscustomobject]@{BackupId=$backupId;BackupName=$backupName;ObjectId=$first.ObjectId;ObjectName=$first.ObjectName;InspectedPointCount=$group.Count;NewestInspectedPointUtc=$(if($youngest){$youngest.CreationTimeUtc}else{$null});NewestInspectedPointAgeHours=$(if($youngest){$youngest.AgeHours}else{$null});AgeAssessment=$assessment;PointScopeTruncated=$pointCap;Evidence=$evidence})
            Add-VeeamFinding -Component ('Catalog age '+$backupName+' '+$first.ObjectName) -State $assessment -Evidence $evidence
        }
        $backupRows.Add([pscustomobject]@{Id=$backupId;Name=$backupName;QueryStatus=$(if($points.Succeeded){'Collected'}else{'Unknown'});InspectedPoints=$localRows.Count;PointCapReached=$pointCap;ObjectCapReached=$objectCap})
        if(-not $points.Succeeded -or -not $localRows.Count){Add-VeeamFinding -Component ('Restore-point evidence '+$backupName) -State Unknown -Evidence 'No usable matching restore-point evidence was returned; do not infer a successful backup.'}
    }
    if($backupCap -or $pointCapBackups -or $objectCapBackups){Add-VeeamFinding -Component 'Catalog coverage' -State Unknown -Evidence 'One or more backup, restore-point, or object caps were exceeded.'}
    if($backups.Succeeded -and -not $backupRows.Count){Add-VeeamFinding -Component 'Backup catalog' -State Unknown -Evidence 'No matching backups were returned; expected protection scope is not established.'}
}
Write-ReportCsv -Name 'backups' -Rows $backupRows.ToArray() -Columns @('Id','Name','QueryStatus','InspectedPoints','PointCapReached','ObjectCapReached')
Write-ReportCsv -Name 'restore-points' -Rows $pointRows.ToArray() -Columns @('BackupId','BackupName','RestorePointId','ObjectId','ObjectName','Type','CreationTimeUtc','AgeHours','IsCorrupted','TimeEvidence')
Write-ReportCsv -Name 'object-point-age' -Rows $objectRows.ToArray() -Columns @('BackupId','BackupName','ObjectId','ObjectName','InspectedPointCount','NewestInspectedPointUtc','NewestInspectedPointAgeHours','AgeAssessment','PointScopeTruncated','Evidence')
Complete-Report -Data ([pscustomobject]@{Context=$veeamContext;ObservedUtc=$observedUtc.ToString('o');MaxAgeHours=$MaxAgeHours;BackupsReported=$backupRows.Count;PointsReported=$pointRows.Count;ObjectsReported=$objectRows.Count;BackupCapReached=$backupCap;BackupsWithPointCap=$pointCapBackups;BackupsWithObjectCap=$objectCapBackups;Recoverability='NotTested'}) -Notes @(
    'Scope is CBackup catalogs returned by Get-VBRBackup and points supported by Get-VBRRestorePoint. It does not establish every NAS, tape, plug-in, CDP, or cloud-native recovery catalog.'
    'ObjectNamePattern defaults to * and is always passed as -Name, as required for Agent restore-point visibility in the v12 reference. Filters can intentionally exclude workloads.'
    'Only explicit CreationTimeUtc is used for ages. Unspecified-kind values in that explicit UTC field are marked UTC; local-only timestamps are not assumed to use the reporting computer timezone.'
    'Age Pass means a catalog timestamp met a threshold. Catalog presence, no reported corruption, and recent age do not prove usable media, application consistency, valid credentials/keys, complete job coverage, or successful restore.'
    'Point and object caps are per inspected backup. A capped point set may omit newer points and entire objects; old-age assessment remains Unknown when completeness is unavailable.'
    'No backup files are opened, mounted, copied, repaired, rescanned, or restored. No encryption keys are read or exported.'
)

} finally {Close-OwnedVeeamConnection}