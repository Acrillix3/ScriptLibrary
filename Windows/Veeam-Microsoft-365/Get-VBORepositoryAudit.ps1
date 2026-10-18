<#
What it does:
  Audits JET/object repositories, retention metadata, and known storage usage without assuming missing capacity.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9191.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -Name: Repository-name wildcard; default all repositories.
  -MaxRepositories: Maximum repositories per query class, 1-10000; default 500.
  -MinimumFreePercent: JET free-space review threshold, 0-100; default 15.

How it works:
  Separates regular, supported long-term, and v7 legacy object-store inventories. Missing fields stay unknown, soft limits are not physical capacity, and no integrity execution, indexing, rescan, or synchronization runs.
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
    [ValidateRange(1,10000)][int]$MaxRepositories=500,
    [ValidateRange(0,100)][double]$MinimumFreePercent=15
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
function Get-VBORepositoryNumber {
    param([object]$InputObject,[string]$Path)
    $value=Get-VeeamValue -Object $InputObject -Path $Path
    if($value -is [byte] -or $value -is [int16] -or $value -is [uint16] -or $value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64] -or $value -is [single] -or $value -is [double] -or $value -is [decimal]){
        if(-not [double]::IsNaN([double]$value) -and -not [double]::IsInfinity([double]$value) -and $value -ge 0){return $value}
    }
    return $null
}

$rows=New-Object 'System.Collections.Generic.List[object]';$legacyRows=@();$regularTruncated=$false;$longTermTruncated=$false;$legacyTruncated=$false;$longTermCapability='Unsupported';$legacyCapability='NotRequestedForModernToolkit'
if($veeamReady){
    foreach($queryClass in @('Regular','LongTerm')){
        if($queryClass -eq 'LongTerm' -and -not (Test-VBOAuditCapability 'Get-VBORepository' @('LongTerm'))){Add-VeeamFinding -Component 'LongTermRepositoryInventory' -State Unknown -Evidence 'The installed Get-VBORepository command has no LongTerm parameter; this separate repository class was not assessed.';continue}
        if($queryClass -eq 'LongTerm'){$longTermCapability='Available'}
        $inventory=Invoke-ReportQuery -Section ('VBORepositories:'+ $queryClass) -Action {
            $parameters=@{ErrorAction='Stop'};if($queryClass -eq 'LongTerm'){$parameters.LongTerm=$true}
            Get-VBORepository @parameters | Where-Object { $_.Name -like $Name } | Select-Object -First ($MaxRepositories+1)
        }
        $limited=$inventory.Data.Count -gt $MaxRepositories
        if($queryClass -eq 'LongTerm'){$longTermTruncated=$limited}else{$regularTruncated=$limited}
        foreach($item in @($inventory.Data | Select-Object -First $MaxRepositories)){
            $objectFlag=Get-VBOAuditScalar $item 'IsObjectStorage';if($objectFlag -isnot [bool]){$objectFlag=$null};$storageClass='Unknown';$capacity=$null;$free=$null;$freePercent=$null
            if($null -ne $objectFlag -and $objectFlag -eq $false){$storageClass='JET';$capacity=Get-VBORepositoryNumber $item 'Capacity';$free=Get-VBORepositoryNumber $item 'FreeSpace';if($null -ne $capacity -and $null -ne $free -and $capacity -gt 0 -and $free -le $capacity){$freePercent=[math]::Round(100*[double]$free/[double]$capacity,2)}}
            elseif($objectFlag -eq $true){$storageClass='ObjectStorage'}
            $row=[pscustomobject]@{QueryClass=$queryClass;Id=Get-VBOAuditScalar $item 'Id';Name=Get-VBOAuditScalar $item 'Name';StorageClass=$storageClass;IsObjectStorage=$objectFlag;Path=Get-VBOAuditScalar $item 'Path';Proxy=Get-VBOAuditScalar $item 'Proxy.Hostname';ProxyPool=Get-VBOAuditScalar $item 'ProxyPool.Name';RetentionType=Get-VBOAuditScalar $item 'RetentionType';RetentionPeriod=Get-VBOAuditScalar $item 'RetentionPeriod';JetCapacityBytes=$capacity;JetFreeBytes=$free;JetFreePercent=$freePercent;ObjectUsedBytes=Get-VBOAuditScalar $item 'UsedSpace';ObjectFreeBytes=Get-VBOAuditScalar $item 'FreeSpace';ObjectSoftLimitEnabled=Get-VBOAuditScalar $item 'EnableSizeLimit';ObjectSoftLimitGB=Get-VBOAuditScalar $item 'SizeLimit';ImmutabilityEnabled=Get-VBOAuditScalar $item 'EnableImmutability';ImmutabilityPeriodDays=Get-VBOAuditScalar $item 'ImmutabilityPeriod'}
            if($storageClass -ne 'ObjectStorage'){$row.ObjectUsedBytes=$null;$row.ObjectFreeBytes=$null;$row.ObjectSoftLimitEnabled=$null;$row.ObjectSoftLimitGB=$null}
            if($null -ne $freePercent -and $freePercent -lt $MinimumFreePercent){Add-VeeamFinding -Component ('JetRepository:'+ $row.Name) -State Review -Evidence ('Reported JET free space is '+$freePercent+' percent.')}
            if($storageClass -eq 'JET' -and $null -eq $freePercent){Add-VeeamFinding -Component ('JetCapacity:'+ $row.Name) -State Unknown -Evidence 'JET capacity/free-space data was absent or did not permit a percentage calculation.'}
            if($storageClass -eq 'Unknown'){Add-VeeamFinding -Component ('RepositoryStorageClass:'+ $row.Name) -State Unknown -Evidence 'An explicit IsObjectStorage boolean was not exposed; repository storage class was not inferred.'}
            if($storageClass -eq 'ObjectStorage' -and $null -eq $row.ObjectUsedBytes){Add-VeeamFinding -Component ('ObjectCapacity:'+ $row.Name) -State Unknown -Evidence 'Object-storage usage/capacity is not exposed by this returned repository type; no zero capacity was inferred.'}
            $rows.Add($row)
        }
    }
    if($veeamContext.MajorVersion -eq 7 -and (Test-VBOAuditCapability 'Get-VBOObjectStorageRepository')){
        $legacyCapability='Available'
        $legacy=Invoke-ReportQuery -Section 'VBOLegacyObjectStorageRepositories' -Action {Get-VBOObjectStorageRepository -ErrorAction Stop | Where-Object { $_.Name -like $Name } | Select-Object -First ($MaxRepositories+1)}
        $legacyTruncated=$legacy.Data.Count -gt $MaxRepositories
        $legacyRows=@(foreach($item in @($legacy.Data | Select-Object -First $MaxRepositories)){[pscustomobject]@{Id=Get-VBOAuditScalar $item 'Id';Name=Get-VBOAuditScalar $item 'Name';Type=Get-VBOAuditScalar $item 'Type';IsLongTerm=Get-VBOAuditScalar $item 'IsLongTerm';UsedBytes=Get-VBOAuditScalar $item 'UsedSpace';FreeBytes=Get-VBOAuditScalar $item 'FreeSpace';SoftLimitEnabled=Get-VBOAuditScalar $item 'EnableSizeLimit';SoftLimitGB=Get-VBOAuditScalar $item 'SizeLimit';ImmutabilityEnabled=Get-VBOAuditScalar $item 'EnableImmutability';ImmutabilityPeriodDays=Get-VBOAuditScalar $item 'ImmutabilityPeriod'}})
    }elseif($veeamContext.MajorVersion -eq 7){$legacyCapability='Unsupported';Add-VeeamFinding -Component 'LegacyObjectStorageInventory' -State Unknown -Evidence 'The legacy object-storage getter is absent from this toolkit; legacy object-store details were not assessed.'}
    if($regularTruncated -or $longTermTruncated -or $legacyTruncated){Add-VeeamFinding -Component 'RepositoryScope' -State Review -Evidence 'At least one repository class was truncated by MaxRepositories.'}
}else{Add-VeeamFinding -Component 'RepositoryAudit' -State Unknown -Evidence 'VBO connection or supported-version detection did not complete.'}
Write-ReportCsv -Name 'repositories' -Rows $rows.ToArray() -Columns @('QueryClass','Id','Name','StorageClass','IsObjectStorage','Path','Proxy','ProxyPool','RetentionType','RetentionPeriod','JetCapacityBytes','JetFreeBytes','JetFreePercent','ObjectUsedBytes','ObjectFreeBytes','ObjectSoftLimitEnabled','ObjectSoftLimitGB','ImmutabilityEnabled','ImmutabilityPeriodDays')
Write-ReportCsv -Name 'legacy-object-storage' -Rows $legacyRows -Columns @('Id','Name','Type','IsLongTerm','UsedBytes','FreeBytes','SoftLimitEnabled','SoftLimitGB','ImmutabilityEnabled','ImmutabilityPeriodDays')
Complete-Report -Data ([pscustomobject]@{RepositoriesReported=$rows.Count;RegularTruncated=$regularTruncated;LongTermTruncated=$longTermTruncated;LongTermCapability=$longTermCapability;LegacyObjectStoresReported=$legacyRows.Count;LegacyObjectStoresTruncated=$legacyTruncated;LegacyCapability=$legacyCapability;MaxRepositoriesPerClass=$MaxRepositories;MinimumJetFreePercent=$MinimumFreePercent}) -Notes @(
    'JET capacity and object-storage consumption are different measures. Missing capacity is unknown, not zero; object-store soft limits are not physical storage capacity.'
    'Regular and LongTerm repository queries are reported separately and can overlap according to product/build behavior; this is not a deduplicated global capacity total.'
    'v7 legacy object-storage settings are a separate inventory; the deprecated getter is not required on v8. New proxy-pool/cache/PostgreSQL behavior is not assumed on v7.'
    'No repository integrity execution, synchronization, indexing, rescan, or configuration change is performed. Retention/immutability metadata does not prove a recovery point remains recoverable.'
)


} finally {Close-OwnedVeeamConnection}