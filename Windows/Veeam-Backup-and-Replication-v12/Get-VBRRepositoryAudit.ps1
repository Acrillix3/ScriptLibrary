<#
What it does:
  Audits repository inventories, available capacity evidence, and reported immutability settings in VBR 12.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -MaxRepositories: Maximum records per repository inventory; default 200.
  -FreeSpaceWarningPercent: Free-space percentage review threshold; default 15.

How it works:
  Connects locally or from a matching Veeam management console. Reads standard/object repository getters; optional public scalar capacity and immutability fields are labeled by source. Missing fields and cloud quota remain Unknown. No rescan or internal methods run.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateRange(1,10000)][int]$MaxRepositories=200,
    [ValidateRange(1,99)][int]$FreeSpaceWarningPercent=15
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
function Get-RepositoryNumericEvidence {
    param([object]$Object,[string[]]$Paths)
    foreach($path in $Paths){
        $value=Get-VeeamValue -Object $Object -Path $path
        if($value -is [byte] -or $value -is [int16] -or $value -is [uint16] -or $value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64] -or $value -is [decimal] -or $value -is [single] -or $value -is [double]){
            if([double]::IsNaN([double]$value) -or [double]::IsInfinity([double]$value)){continue}
            return [pscustomobject]@{Value=[decimal]$value;Source=$path}
        }
    }
    [pscustomobject]@{Value=$null;Source='Not exposed as a supported scalar byte count'}
}
function Get-RepositoryImmutabilityEvidence {
    param([object]$Object)
    foreach($path in @('ImmutabilityEnabled','IsImmutabilityEnabled','ImmutabilityOptions.Enabled')){
        $value=Get-VeeamValue -Object $Object -Path $path
        if($value -is [bool]){return [pscustomobject]@{State=$(if($value){'Enabled reported'}else{'Disabled reported'});Source=$path}}
    }
    [pscustomobject]@{State='Unknown';Source='No explicit public boolean was exposed'}
}
$repositoryRows=New-Object 'System.Collections.Generic.List[object]'
$standardStatus='Unknown';$objectStatus='Unknown';$standardCapReached=$false;$objectCapReached=$false
if($veeamReady){
    foreach($kind in @('Repository','ObjectStorage')){
        $getter=$(if($kind -eq 'Repository'){'Get-VBRBackupRepository'}else{'Get-VBRObjectStorageRepository'})
        $result=Invoke-ReportQuery -Section ($kind+' inventory') -Action { & $getter -ErrorAction Stop | Select-Object -First ($MaxRepositories+1) }
        if(-not $result.Succeeded){Add-VeeamFinding -Component ($kind+' inventory') -State Unknown -Evidence 'The supported inventory getter was unavailable or failed.';continue}
        $status=$(if($result.Data.Count){'Collected'}else{'Empty'});$capped=$result.Data.Count -gt $MaxRepositories
        if($kind -eq 'Repository'){$standardStatus=$status;$standardCapReached=$capped}else{$objectStatus=$status;$objectCapReached=$capped}
        foreach($repository in @($result.Data | Select-Object -First $MaxRepositories)){
            $name=(Get-InfraText -Object $repository -Path 'Name')
            $capacity=Get-RepositoryNumericEvidence -Object $repository -Paths @('CapacityBytes','CachedTotalSpace.InBytes')
            $free=Get-RepositoryNumericEvidence -Object $repository -Paths @('FreeSpaceBytes','CachedFreeSpace.InBytes')
            $capacityState='Unknown';$freePercent=$null
            if($null -ne $capacity.Value -and $null -ne $free.Value){
                if($capacity.Value -gt 0 -and $free.Value -ge 0 -and $free.Value -le $capacity.Value){
                    $freePercent=[math]::Round([double]($free.Value/$capacity.Value*100),2)
                    $capacityState=$(if($freePercent -le $FreeSpaceWarningPercent){'Review threshold'}else{'Above free-space threshold'})
                }else{$capacityState='Unknown: inconsistent or nonpositive capacity'}
            }
            $immutability=Get-RepositoryImmutabilityEvidence -Object $repository
            $repositoryRows.Add([pscustomobject]@{InventorySource=$kind;Id=(Get-InfraText -Object $repository -Path 'Id');Name=$name;Type=(Get-InfraText -Object $repository -Path 'Type');CapacityBytes=$capacity.Value;CapacitySource=$capacity.Source;FreeSpaceBytes=$free.Value;FreeSpaceSource=$free.Source;FreePercent=$freePercent;CapacityFlag=$capacityState;CloudQuotaAssessment=$(if($kind -eq 'ObjectStorage'){'Unknown: provider account quota not queried'}else{'Not applicable'});Immutability=$immutability.State;ImmutabilitySource=$immutability.Source;Reachability='Not tested'})
            $findingState=$(if($capacityState -like 'Unknown*'){'Unknown'}elseif($capacityState -eq 'Review threshold'){'Review'}else{'Pass'})
            Add-VeeamFinding -Component ($kind+' capacity: '+$name) -State $findingState -Evidence ('Capacity='+$capacityState+'. Only explicitly exposed public byte counts are used; storage was not rescanned.')
            if($immutability.State -eq 'Unknown'){Add-VeeamFinding -Component ($kind+' immutability: '+$name) -State Unknown -Evidence 'No explicit immutability enabled boolean was exposed. Storage type or repository name is not proof of immutability.'}
            elseif($immutability.State -eq 'Disabled reported'){Add-VeeamFinding -Component ($kind+' immutability: '+$name) -State Review -Evidence ('Disabled was reported by '+$immutability.Source+'; compare with required retention policy.')}
        }
        if($capped){Add-VeeamFinding -Component ($kind+' inventory coverage') -State Review -Evidence ('Export capped at '+$MaxRepositories+' records for this inventory getter.')}
    }
}
Write-ReportCsv -Name 'repositories' -Rows $repositoryRows.ToArray() -Columns @('InventorySource','Id','Name','Type','CapacityBytes','CapacitySource','FreeSpaceBytes','FreeSpaceSource','FreePercent','CapacityFlag','CloudQuotaAssessment','Immutability','ImmutabilitySource','Reachability')
$summaryData=[pscustomobject]@{Target=$veeamContext.Server;RepositoryInventoryStatus=$standardStatus;ObjectStorageInventoryStatus=$objectStatus;RepositoryCount=$(if($standardStatus -ne 'Unknown'){@($repositoryRows | Where-Object InventorySource -eq 'Repository').Count}else{$null});ObjectStorageRepositoryCount=$(if($objectStatus -ne 'Unknown'){@($repositoryRows | Where-Object InventorySource -eq 'ObjectStorage').Count}else{$null});InspectedCapacityUnknownCount=@($repositoryRows | Where-Object CapacityFlag -like 'Unknown*').Count;InspectedLowFreeSpaceCount=@($repositoryRows | Where-Object CapacityFlag -eq 'Review threshold').Count;RepositoryCapReached=$standardCapReached;ObjectStorageCapReached=$objectCapReached;FreeSpaceWarningPercent=$FreeSpaceWarningPercent;CloudAccountQuota='Unknown'}
Complete-Report -Data $summaryData -Notes @('Standard and object storage inventories are queried independently. Source counts are not a deduplicated total; repository representations may overlap.','Legacy v12 providers do not guarantee public capacity fields. Only CapacityBytes/FreeSpaceBytes or already exposed CachedTotalSpace.InBytes/CachedFreeSpace.InBytes properties are read. No GetContainer method, rescan, cache refresh, or filesystem/cloud query runs.','Capacity values can be cached and may represent a repository limit rather than a cloud account quota. Cloud quota is always Unknown in this audit. Missing fields are blank, never zero.','An explicit immutability boolean describes reported configuration only. No immutable object lock, retention enforcement, access, or recovery validation is performed. MaxRepositories applies independently to each getter and is not a hard query timeout.')

} finally {Close-OwnedVeeamConnection}