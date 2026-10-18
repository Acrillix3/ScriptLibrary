<#
What it does:
  Audits modern and legacy v12 backup copy job metadata with explicit API coverage.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -NamePattern: Copy job-name wildcard; default *.
  -MaxJobs: Maximum inspected jobs in each modern/legacy family; default 100.
  -MaxSourceJobsPerJob: Maximum source jobs for each legacy periodic copy job; default 100.

How it works:
  Uses the modern copy cmdlet when available plus legacy Get-VBRJob BackupSync results, deduplicating IDs. Source expansion is limited to supported legacy periodic jobs. Optional fields stay unknown; no synchronization or configuration change occurs.
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
[ValidateRange(1,10000)][int]$MaxSourceJobsPerJob=100
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
function Get-CopyAuditBoolean {param($Object,[string]$Path) $value=Get-VeeamValue $Object $Path;if($value -is [bool]){return $value};return $null}
$rows=New-Object 'System.Collections.Generic.List[object]'
$sources=New-Object 'System.Collections.Generic.List[object]'
$seenIds=@{};$modernCap=$false;$legacyCap=$false;$sourceCapJobs=0;$modernAvailable=$false
if($veeamReady){
    $modernAvailable=$null -ne (Get-Command -Name Get-VBRBackupCopyJob -ErrorAction SilentlyContinue)
    if($modernAvailable){
        $modern=Invoke-ReportQuery -Section 'Modern backup copy jobs' -Action {Get-VBRBackupCopyJob -ErrorAction Stop | Where-Object {(Get-JobAuditText -Object $_ -Path 'Name') -like $NamePattern} | Select-Object -First ($MaxJobs+1)}
        $modernCap=$modern.Data.Count -gt $MaxJobs
        foreach($job in @($modern.Data | Select-Object -First $MaxJobs)){
            $id=(Get-JobAuditText -Object $job -Path 'Id');$name=(Get-JobAuditText -Object $job -Path 'Name');$enabled=Get-CopyAuditBoolean $job 'Enabled'
            $enabledField='Enabled'
            if($null -eq $enabled){$enabled=Get-CopyAuditBoolean $job 'IsScheduleEnabled';$enabledField='IsScheduleEnabled'}
            if($id){$seenIds[$id]=$true}
            $target=(Get-JobAuditText -Object $job -Path 'TargetRepository.Name')
            if(-not $target){$target=(Get-JobAuditText -Object $job -Path 'Repository.Name')}
            $rows.Add([pscustomobject]@{Id=$id;Name=$name;ApiFamily='Get-VBRBackupCopyJob';Mode=(Get-JobAuditText -Object $job -Path 'Mode');Enabled=$enabled;EnabledSource=$enabledField;TargetRepositoryName=$target;LastResult=(Get-JobAuditText -Object $job -Path 'LastResult');LastState=(Get-JobAuditText -Object $job -Path 'LastState');EvidenceStatus=$(if($id -and $name -and $null -ne $enabled){'Collected'}else{'Unknown'})})
            if($null -eq $enabled){Add-VeeamFinding -Component ('Copy job '+$name) -State Unknown -Evidence 'Enabled state was not exposed by this build; absence is not treated as enabled.'}
            elseif(-not [bool]$enabled){Add-VeeamFinding -Component ('Copy job '+$name) -State Review -Evidence 'The provider reports this copy job disabled; confirm intent.'}
        }
    }else{Add-VeeamFinding -Component 'Modern copy-job capability' -State Unknown -Evidence 'Get-VBRBackupCopyJob is unavailable in the loaded v12 module; legacy inventory cannot establish coverage of newer copy-job formats.'}
    $legacy=Invoke-ReportQuery -Section 'Legacy BackupSync jobs' -Action {
        Get-VBRJob -Name $NamePattern -ErrorAction Stop | Where-Object {(Get-JobAuditText -Object $_ -Path 'JobType') -eq 'BackupSync'} | Select-Object -First ($MaxJobs+1)
    }
    $legacyCap=$legacy.Data.Count -gt $MaxJobs
    foreach($job in @($legacy.Data | Select-Object -First $MaxJobs)){
        $id=(Get-JobAuditText -Object $job -Path 'Id');$name=(Get-JobAuditText -Object $job -Path 'Name');$enabled=Get-CopyAuditBoolean $job 'IsScheduleEnabled'
        if($id -and $seenIds.ContainsKey($id)){continue}
        $rows.Add([pscustomobject]@{Id=$id;Name=$name;ApiFamily='Legacy Get-VBRJob BackupSync';Mode='Legacy';Enabled=$enabled;EnabledSource='IsScheduleEnabled';TargetRepositoryName='';LastResult='';LastState='';EvidenceStatus=$(if($id -and $name -and $null -ne $enabled){'Collected'}else{'Unknown'})})
        if($null -eq $enabled){Add-VeeamFinding -Component ('Legacy copy job '+$name) -State Unknown -Evidence 'Scheduling state was not exposed.'}
        elseif(-not [bool]$enabled){Add-VeeamFinding -Component ('Legacy copy job '+$name) -State Review -Evidence 'The provider reports legacy copy scheduling disabled; confirm intent.'}
        $capability=Get-Command -Name Get-VBRLegacyBackupCopySourceJob -ErrorAction SilentlyContinue
        if($capability){
            $sourceResult=Invoke-ReportQuery -Section ('Legacy source jobs '+$name) -Action {Get-VBRLegacyBackupCopySourceJob -Job $job -ErrorAction Stop | Select-Object -First ($MaxSourceJobsPerJob+1)}
            if($sourceResult.Data.Count -gt $MaxSourceJobsPerJob){$sourceCapJobs++}
            foreach($source in @($sourceResult.Data | Select-Object -First $MaxSourceJobsPerJob)){$sources.Add([pscustomobject]@{CopyJobId=$id;CopyJobName=$name;SourceJobId=(Get-JobAuditText -Object $source -Path 'Id');SourceJobName=(Get-JobAuditText -Object $source -Path 'Name')})}
        }else{Add-VeeamFinding -Component ('Legacy sources '+$name) -State Unknown -Evidence 'The legacy source-job cmdlet is unavailable in this module; no unsupported method fallback is used.'}
    }
    if($modernCap -or $legacyCap -or $sourceCapJobs){Add-VeeamFinding -Component 'Copy-job coverage' -State Unknown -Evidence 'One or more configured caps were exceeded; see summary cap fields.'}
}
Write-ReportCsv -Name 'backup-copy-jobs' -Rows $rows.ToArray() -Columns @('Id','Name','ApiFamily','Mode','Enabled','EnabledSource','TargetRepositoryName','LastResult','LastState','EvidenceStatus')
Write-ReportCsv -Name 'legacy-copy-source-jobs' -Rows $sources.ToArray() -Columns @('CopyJobId','CopyJobName','SourceJobId','SourceJobName')
Complete-Report -Data ([pscustomobject]@{Context=$veeamContext;ModernCmdletAvailable=$modernAvailable;InspectedJobs=$rows.Count;ModernJobCapReached=$modernCap;LegacyJobCapReached=$legacyCap;JobsWithSourceCap=$sourceCapJobs}) -Notes @(
    'Modern and legacy v12 copy APIs are queried independently and deduplicated by nonempty ID. MaxJobs applies to each family, so at most twice that many job rows can be retained.'
    'When the modern cmdlet is absent, the tested fallback covers legacy BackupSync jobs only. A failed modern query is not replaced by a misleading healthy legacy result.'
    'Legacy source-job names are metadata only. New copy-job source expansion, plug-in copy, tape copy, HPE Catalyst copy, and cloud-native copy jobs are outside this report.'
    'Optional fields vary across v12 builds; blank fields remain unknown. No whole options object, key, password, or script command is exported.'
    'Caps bound retained data and follow-up work, not provider execution time. Copy jobs are never synchronized, started, changed, or stopped.'
)

} finally {Close-OwnedVeeamConnection}