<#
What it does:
  Audits VBR 12 scale-out repository policies and performance, capacity, and archive extent states.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -MaxRepositories: Maximum scale-out repositories; default 100.
  -MaxExtentsPerTier: Maximum extents per repository/tier; default 100.

How it works:
  Reads scale-out repositories and each tier independently through supported VBR 12 getters. Reports maintenance/sealed states without changing them. Missing getters or fields remain Unknown; extent state does not validate immutability or offload success.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateRange(1,10000)][int]$MaxRepositories=100,
    [ValidateRange(1,10000)][int]$MaxExtentsPerTier=100
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
function Get-InfraText {
    param([object]$Object,[string]$Path)
    $value=Get-VeeamValue -Object $Object -Path $Path
    if($value -is [string] -or $value -is [guid] -or $value -is [enum] -or $value -is [version] -or $value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64]){return [string]$value}
    return $null
}
$sobrRows=New-Object 'System.Collections.Generic.List[object]';$extentRows=New-Object 'System.Collections.Generic.List[object]'
$sobrStatus='Unknown';$repositoryCapReached=$false;$tierCapCount=0
if($veeamReady){
    $repositories=Invoke-ReportQuery -Section 'Scale-out repositories' -Action { Get-VBRBackupRepository -ScaleOut -ErrorAction Stop | Select-Object -First ($MaxRepositories+1) }
    if($repositories.Succeeded){
        $sobrStatus=$(if($repositories.Data.Count){'Collected'}else{'Empty'});$repositoryCapReached=$repositories.Data.Count -gt $MaxRepositories
        foreach($sobr in @($repositories.Data | Select-Object -First $MaxRepositories)){
            $sobrName=(Get-InfraText -Object $sobr -Path 'Name');$sobrId=(Get-InfraText -Object $sobr -Path 'Id')
            $perVM=Get-VeeamValue -Object $sobr -Path 'UsePerVMBackupFiles';$fullOffline=Get-VeeamValue -Object $sobr -Path 'PerformFullWhenExtentOffline'
            $sobrRows.Add([pscustomobject]@{Id=$sobrId;Name=$sobrName;PolicyType=(Get-InfraText -Object $sobr -Path 'PolicyType');UsePerVMBackupFiles=$(if($perVM -is [bool]){$perVM}else{$null});PerformFullWhenExtentOffline=$(if($fullOffline -is [bool]){$fullOffline}else{$null});Immutability='Unknown: not validated by extent status';OffloadCompletion='Not assessed'})
            foreach($tier in @('Performance','Capacity','Archive')){
                $getter=switch($tier){'Performance'{'Get-VBRRepositoryExtent'};'Capacity'{'Get-VBRCapacityExtent'};'Archive'{'Get-VBRArchiveExtent'}}
                $extents=Invoke-ReportQuery -Section ($tier+' extents: '+$sobrName) -Action { & $getter -Repository $sobr -ErrorAction Stop | Select-Object -First ($MaxExtentsPerTier+1) }
                if(-not $extents.Succeeded){Add-VeeamFinding -Component ($sobrName+' '+$tier+' tier') -State Unknown -Evidence 'The tier getter was unavailable or failed; no tier or health conclusion can be made.';continue}
                if($extents.Data.Count -gt $MaxExtentsPerTier){$tierCapCount++;Add-VeeamFinding -Component ($sobrName+' '+$tier+' tier') -State Review -Evidence ('Extent export capped at '+$MaxExtentsPerTier+'.')}
                if(-not $extents.Data.Count){Add-VeeamFinding -Component ($sobrName+' '+$tier+' tier inventory') -State NotApplicable -Evidence 'No extents were returned by a successful tier query. Tier policy and licensing still require separate interpretation.'}
                foreach($extent in @($extents.Data | Select-Object -First $MaxExtentsPerTier)){
                    $status=(Get-InfraText -Object $extent -Path 'Status');$state='Unknown';$statusMeaning='Unknown';$maintenance='Unknown';$sealed='Unknown'
                    if($tier -eq 'Performance'){
                        switch($status){
                            'Normal'{$state='Pass';$statusMeaning='Working mode reported';$maintenance='No'}
                            'Pending'{$state='Review';$statusMeaning='Switching to maintenance';$maintenance='Pending'}
                            'Maintenance'{$state='Review';$statusMeaning='Maintenance reported';$maintenance='Yes'}
                            'Evacuate'{$state='Review';$statusMeaning='Maintenance and evacuation reported';$maintenance='Yes'}
                            default{$state='Unknown'}
                        }
                    }else{
                        if($status -eq 'Normal' -or $status -eq '0'){$state='Pass';$statusMeaning='Normal extent status reported';$maintenance='No';$sealed='No'}
                        elseif($status -match 'Maintenance|Pending|Evacuat|Sealed|Resync|Tenant' -or $status -match '^\d+$'){
                            $state='Review';$statusMeaning='Non-normal or combined extent status reported'
                            if($status -match 'Maintenance'){$maintenance='Yes'}elseif($status -match 'Pending'){$maintenance='Pending'}
                            if($status -match 'Sealed'){$sealed='Yes'}
                            if($status -match '^\d+$'){
                                $flags=0L;$knownMask=$(if($tier -eq 'Capacity'){63L}else{11L})
                                if(-not [long]::TryParse($status,[ref]$flags) -or ($flags -band (-bnot $knownMask)) -ne 0){
                                    $state='Unknown';$statusMeaning='Unsupported numeric extent status';$maintenance='Unknown';$sealed='Unknown'
                                }else{
                                    if(($flags -band 2) -ne 0){$maintenance='Yes'}elseif(($flags -band 1) -ne 0){$maintenance='Pending'}else{$maintenance='No'}
                                    $sealed=$(if(($flags -band 8) -ne 0){'Yes'}else{'No'})
                                }
                            }
                        }
                    }
                    $extentName=(Get-InfraText -Object $extent -Path 'Repository.Name')
                    $extentRows.Add([pscustomobject]@{ScaleOutId=$sobrId;ScaleOutName=$sobrName;Tier=$tier;ExtentId=(Get-InfraText -Object $extent -Path 'Id');RepositoryId=(Get-InfraText -Object $extent -Path 'Repository.Id');RepositoryName=$extentName;ReportedStatus=$status;StatusMeaning=$statusMeaning;Maintenance=$maintenance;Sealed=$sealed;FindingState=$state;Immutability='Unknown: not established by maintenance or sealed state'})
                    Add-VeeamFinding -Component ($sobrName+' '+$tier+' '+$extentName) -State $state -Evidence ($statusMeaning+'; reported Status='+$status+'. This does not validate storage access or backup recoverability.')
                }
            }
        }
        if($repositoryCapReached){Add-VeeamFinding -Component 'Scale-out repository inventory' -State Review -Evidence ('Repository export capped at '+$MaxRepositories+'.')}
    }else{Add-VeeamFinding -Component 'Scale-out repository inventory' -State Unknown -Evidence 'Scale-out repository query unavailable.'}
}
Write-ReportCsv -Name 'scale-out-repositories' -Rows $sobrRows.ToArray() -Columns @('Id','Name','PolicyType','UsePerVMBackupFiles','PerformFullWhenExtentOffline','Immutability','OffloadCompletion')
Write-ReportCsv -Name 'tier-extents' -Rows $extentRows.ToArray() -Columns @('ScaleOutId','ScaleOutName','Tier','ExtentId','RepositoryId','RepositoryName','ReportedStatus','StatusMeaning','Maintenance','Sealed','FindingState','Immutability')
$summaryData=[pscustomobject]@{Target=$veeamContext.Server;ScaleOutInventoryStatus=$sobrStatus;ScaleOutRepositoryCount=$(if($sobrStatus -ne 'Unknown'){$sobrRows.Count}else{$null});InspectedExtentCount=$extentRows.Count;ExtentReviewCount=@($extentRows | Where-Object FindingState -eq 'Review').Count;UnknownExtentStateCount=@($extentRows | Where-Object FindingState -eq 'Unknown').Count;RepositoryCapReached=$repositoryCapReached;CappedTierQueryCount=$tierCapCount;Immutability='Not validated';OffloadCompletion='Not assessed'}
Complete-Report -Data $summaryData -Notes @('Queries performance, capacity, and archive extents independently using documented VBR 12 getters. Availability varies by build, edition, permissions, and configuration.','Maintenance, evacuation, pending, and sealed modes can be intentional. Sealed mode is not evidence of immutable storage. A Normal status does not prove storage access or successful offload.','Unknown and blank provider fields remain unknown. Empty tier results are recorded separately from failed or unsupported queries. No internal repository methods or offload synchronization commands are invoked.','Counts cover inspected extents. MaxRepositories and MaxExtentsPerTier limit exported inventory and follow-up work, not hard provider timeouts.')

} finally {Close-OwnedVeeamConnection}