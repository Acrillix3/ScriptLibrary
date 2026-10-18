<#
What it does:
  Audits VBR 12 WAN accelerator inventory and any exposed host/cache configuration metadata.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -MaxAccelerators: Maximum accelerators to export; default 100.

How it works:
  Reads the supported WAN inventory getter. Optional scalar host/cache values show their source; missing values, usage, and job associations remain Unknown. Does not infer hosts from display names, invoke internal methods, or clear/populate caches.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateRange(1,10000)][int]$MaxAccelerators=100
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
function Get-WANTextEvidence {
    param([object]$Object,[string[]]$Paths)
    foreach($path in $Paths){$value=Get-VeeamValue -Object $Object -Path $path;if($value -is [string] -and -not [string]::IsNullOrWhiteSpace($value)){return [pscustomobject]@{Value=$value;Source=$path}}}
    [pscustomobject]@{Value=$null;Source='Not exposed'}
}
function Get-WANCacheSizeEvidence {
    param([object]$Object)
    foreach($path in @('CacheSizeGB','CacheCapacityGB','Options.CacheSizeGB')){
        $value=Get-VeeamValue -Object $Object -Path $path
        if($value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64] -or $value -is [decimal] -or $value -is [double]){
            if(-not [double]::IsNaN([double]$value) -and -not [double]::IsInfinity([double]$value) -and $value -ge 0){return [pscustomobject]@{Value=[decimal]$value;Source=$path}}
        }
    }
    [pscustomobject]@{Value=$null;Source='No public scalar with an explicit GB unit was exposed'}
}
$acceleratorRows=New-Object 'System.Collections.Generic.List[object]';$inventoryStatus='Unknown';$acceleratorCapReached=$false
if($veeamReady){
    $accelerators=Invoke-ReportQuery -Section 'WAN accelerator inventory' -Action { Get-VBRWANAccelerator -ErrorAction Stop | Select-Object -First ($MaxAccelerators+1) }
    if($accelerators.Succeeded){
        $inventoryStatus=$(if($accelerators.Data.Count){'Collected'}else{'Empty'});$acceleratorCapReached=$accelerators.Data.Count -gt $MaxAccelerators
        foreach($accelerator in @($accelerators.Data | Select-Object -First $MaxAccelerators)){
            $name=(Get-InfraText -Object $accelerator -Path 'Name')
            $hostEvidence=Get-WANTextEvidence -Object $accelerator -Paths @('Host.Name','Server.Name','HostName')
            $cachePath=Get-WANTextEvidence -Object $accelerator -Paths @('CachePath','Options.CachePath')
            $cacheSize=Get-WANCacheSizeEvidence -Object $accelerator
            $acceleratorRows.Add([pscustomobject]@{Id=(Get-InfraText -Object $accelerator -Path 'Id');Name=$name;ReportedHost=$hostEvidence.Value;HostSource=$hostEvidence.Source;CachePath=$cachePath.Value;CachePathSource=$cachePath.Source;ConfiguredCacheSizeGB=$cacheSize.Value;CacheSizeSource=$cacheSize.Source;CacheUsage='Unknown: not queried';HostReachability='Not tested';JobAssociations='Unknown: no supported association getter used'})
            if($null -eq $hostEvidence.Value){Add-VeeamFinding -Component ('WAN host: '+$name) -State Unknown -Evidence 'No public scalar host name was exposed. The accelerator display name was not assumed to be a host name.'}
            if($null -eq $cachePath.Value -or $null -eq $cacheSize.Value){Add-VeeamFinding -Component ('WAN cache: '+$name) -State Unknown -Evidence 'Cache path or explicitly unit-labeled cache size was not exposed. Undocumented object methods and guessed units were not used.'}
        }
        if($acceleratorCapReached){Add-VeeamFinding -Component 'WAN accelerator inventory' -State Review -Evidence ('Export capped at '+$MaxAccelerators+' accelerators.')}
        if(-not $accelerators.Data.Count){Add-VeeamFinding -Component 'WAN accelerator inventory' -State NotApplicable -Evidence 'No accelerators were returned by the successful inventory query.'}
    }else{Add-VeeamFinding -Component 'WAN accelerator inventory' -State Unknown -Evidence 'WAN inventory getter unavailable or query failed; this is not evidence of unhealthy accelerators.'}
    Add-VeeamFinding -Component 'WAN cache and job association coverage' -State Unknown -Evidence 'Configured cache metadata is exported only when public scalar properties exist. Cache usage, disk access, service reachability, and job source/target associations are not validated by this v12 inventory audit.'
}
Write-ReportCsv -Name 'wan-accelerators' -Rows $acceleratorRows.ToArray() -Columns @('Id','Name','ReportedHost','HostSource','CachePath','CachePathSource','ConfiguredCacheSizeGB','CacheSizeSource','CacheUsage','HostReachability','JobAssociations')
$summaryData=[pscustomobject]@{Target=$veeamContext.Server;InventoryStatus=$inventoryStatus;AcceleratorCount=$(if($inventoryStatus -ne 'Unknown'){$acceleratorRows.Count}else{$null});AcceleratorsWithUnknownHost=@($acceleratorRows | Where-Object {$null -eq $_.ReportedHost}).Count;AcceleratorsWithUnknownCacheSize=@($acceleratorRows | Where-Object {$null -eq $_.ConfiguredCacheSizeGB}).Count;AcceleratorCapReached=$acceleratorCapReached;CacheUsage='Unknown';JobAssociations='Unknown';Reachability='Not tested'}
Complete-Report -Data $summaryData -Notes @('Uses the documented Get-VBRWANAccelerator getter available in VBR 12. Feature availability depends on edition and configuration; an unavailable getter does not mean the infrastructure is unhealthy.','Legacy CWanAccelerator schemas differ. Optional public scalar properties are labeled with their exact source. Missing host/cache fields remain Unknown; a display name is not interpreted as a host.','Only cache size properties with explicit GB names are accepted. Unlabeled Capacity/CacheSize numbers are not assumed to use GB, MB, or bytes. No cache clear, population, filesystem inspection, or remote service command runs.','Job associations are not inferred from names or undocumented methods. MaxAccelerators limits exported inventory, not Veeam provider execution time.')

} finally {Close-OwnedVeeamConnection}