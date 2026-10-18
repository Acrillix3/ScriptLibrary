<#
What it does:
  Audits VMware and Hyper-V backup proxy inventories and exposed configuration states in VBR 12.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -MaxProxiesPerPlatform: Maximum proxies per platform inventory; default 200.

How it works:
  Reads VMware and Hyper-V getters independently, including Windows/Linux VMware proxies returned by the provider. Optional public scalar settings are source-labeled; missing booleans remain Unknown. No proxies, transport modes, task limits, or components are changed.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateRange(1,10000)][int]$MaxProxiesPerPlatform=200
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
function Get-ProxyTextEvidence {
    param([object]$Object,[string[]]$Paths)
    foreach($path in $Paths){$value=Get-VeeamValue -Object $Object -Path $path;if(($value -is [string] -or $value -is [enum]) -and -not [string]::IsNullOrWhiteSpace([string]$value)){return [pscustomobject]@{Value=[string]$value;Source=$path}}}
    [pscustomobject]@{Value=$null;Source='Not exposed'}
}
$proxyRows=New-Object 'System.Collections.Generic.List[object]';$vmwareStatus='Unknown';$hyperVStatus='Unknown';$vmwareCapReached=$false;$hyperVCapReached=$false
if($veeamReady){
    foreach($platform in @('VMware','Hyper-V')){
        $getter=$(if($platform -eq 'VMware'){'Get-VBRViProxy'}else{'Get-VBRHvProxy'})
        $proxies=Invoke-ReportQuery -Section ($platform+' backup proxies') -Action { & $getter -ErrorAction Stop | Select-Object -First ($MaxProxiesPerPlatform+1) }
        if(-not $proxies.Succeeded){Add-VeeamFinding -Component ($platform+' proxy inventory') -State Unknown -Evidence 'The platform getter was unavailable or query failed; no proxy health conclusion can be made.';continue}
        $status=$(if($proxies.Data.Count){'Collected'}else{'Empty'});$capped=$proxies.Data.Count -gt $MaxProxiesPerPlatform
        if($platform -eq 'VMware'){$vmwareStatus=$status;$vmwareCapReached=$capped}else{$hyperVStatus=$status;$hyperVCapReached=$capped}
        foreach($proxy in @($proxies.Data | Select-Object -First $MaxProxiesPerPlatform)){
            $name=(Get-InfraText -Object $proxy -Path 'Name')
            $hostEvidence=Get-ProxyTextEvidence -Object $proxy -Paths @('Host.Name','Server.Name','HostName')
            $hostType=Get-ProxyTextEvidence -Object $proxy -Paths @('Host.Type','Server.Type','HostType')
            $transport=Get-ProxyTextEvidence -Object $proxy -Paths @('TransportMode','Options.TransportMode')
            $disabled=$null;$enabledSource='Not exposed'
            foreach($path in @('IsDisabled','Disabled')){$value=Get-VeeamValue -Object $proxy -Path $path;if($value -is [bool]){$disabled=$value;$enabledSource=$path;break}}
            if($null -eq $disabled){$value=Get-VeeamValue -Object $proxy -Path 'IsEnabled';if($value -is [bool]){$disabled=-not $value;$enabledSource='IsEnabled'}}
            $maxTasks=$null;$taskSource='Not exposed'
            foreach($path in @('MaxTasksCount','Options.MaxTasksCount')){$value=Get-VeeamValue -Object $proxy -Path $path;if(($value -is [int32] -or $value -is [uint32] -or $value -is [int64]) -and $value -ge 0){$maxTasks=$value;$taskSource=$path;break}}
            $enabledState=$(if($null -eq $disabled){'Unknown'}elseif($disabled){'Disabled reported'}else{'Enabled reported'})
            $proxyRows.Add([pscustomobject]@{Platform=$platform;Id=(Get-InfraText -Object $proxy -Path 'Id');Name=$name;ReportedHost=$hostEvidence.Value;HostSource=$hostEvidence.Source;HostType=$hostType.Value;HostTypeSource=$hostType.Source;EnabledState=$enabledState;EnabledSource=$enabledSource;TransportMode=$transport.Value;TransportSource=$transport.Source;ConfiguredMaxTasks=$maxTasks;TaskLimitSource=$taskSource;RuntimeLoad='Not assessed';HostReachability='Not tested'})
            if($enabledState -eq 'Disabled reported'){Add-VeeamFinding -Component ($platform+' proxy: '+$name) -State Review -Evidence 'Proxy was reported disabled; confirm that this is intentional. No enable command was run.'}
            elseif($enabledState -eq 'Unknown'){Add-VeeamFinding -Component ($platform+' proxy: '+$name) -State Unknown -Evidence 'No explicit public enabled/disabled boolean was exposed.'}
            if($null -eq $hostType.Value){Add-VeeamFinding -Component ('Proxy host platform: '+$name) -State Unknown -Evidence 'No explicit public host type was exposed; OS was not inferred from the display name.'}
        }
        if($capped){Add-VeeamFinding -Component ($platform+' proxy inventory coverage') -State Review -Evidence ('Export capped at '+$MaxProxiesPerPlatform+' proxies for this platform.')}
        if(-not $proxies.Data.Count){Add-VeeamFinding -Component ($platform+' proxy inventory') -State NotApplicable -Evidence 'No proxies were returned by the successful platform query.'}
    }
}
Write-ReportCsv -Name 'backup-proxies' -Rows $proxyRows.ToArray() -Columns @('Platform','Id','Name','ReportedHost','HostSource','HostType','HostTypeSource','EnabledState','EnabledSource','TransportMode','TransportSource','ConfiguredMaxTasks','TaskLimitSource','RuntimeLoad','HostReachability')
$summaryData=[pscustomobject]@{Target=$veeamContext.Server;VMwareInventoryStatus=$vmwareStatus;HyperVInventoryStatus=$hyperVStatus;VMwareProxyCount=$(if($vmwareStatus -ne 'Unknown'){@($proxyRows | Where-Object Platform -eq 'VMware').Count}else{$null});HyperVProxyCount=$(if($hyperVStatus -ne 'Unknown'){@($proxyRows | Where-Object Platform -eq 'Hyper-V').Count}else{$null});InspectedDisabledProxyCount=@($proxyRows | Where-Object EnabledState -eq 'Disabled reported').Count;InspectedUnknownEnabledStateCount=@($proxyRows | Where-Object EnabledState -eq 'Unknown').Count;VMwareCapReached=$vmwareCapReached;HyperVCapReached=$hyperVCapReached;RuntimeCapacity='Not assessed'}
Complete-Report -Data $summaryData -Notes @('Get-VBRViProxy inventories VMware backup proxies, including Windows/Linux proxy roles exposed by that getter. Get-VBRHvProxy is queried separately for Hyper-V. There is no guessed Get-VBRViLinuxProxy command.','Optional public scalar settings are exported with their exact member source. Missing enabled state, host type, transport mode, or task limit remains blank/Unknown; missing booleans are never treated as disabled.','Configured task limits and transport modes do not establish current load or compatibility for every workload. No job placement, operating system compatibility, component update, or connectivity test is performed.','MaxProxiesPerPlatform applies independently to VMware and Hyper-V inventories. It limits exports, not provider execution time.')

} finally {Close-OwnedVeeamConnection}