<#
What it does:
  Audits reported backup-proxy state, component versions, and supported proxy pools.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9191.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -ExtendedView: Request extra proxy fields only when the installed getter supports it.
  -MaxProxies: Maximum proxies and pools per inventory, 1-10000; default 200.
  -MaxPoolMembers: Maximum members counted per pool, 1-10000; default 500.

How it works:
  Reads proxy metadata and uses runtime capability checks for optional v8 pools and legacy ExtendedView. It never rescans or upgrades proxies; online state and proxy-service version do not verify server build or workload health.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9191,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [switch]$ExtendedView,
    [ValidateRange(1,10000)][int]$MaxProxies=200,
    [ValidateRange(1,10000)][int]$MaxPoolMembers=500
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

$proxyRows=@();$poolRows=@();$truncated=$false;$poolsTruncated=$false;$poolCapability='Unsupported'
if($veeamReady){
    $inventory=Invoke-ReportQuery -Section 'VBOProxies' -Action {
        $parameters=@{ErrorAction='Stop'}
        if($ExtendedView){if(-not (Test-VBOAuditCapability 'Get-VBOProxy' @('ExtendedView'))){throw 'ExtendedView is unsupported by the installed Get-VBOProxy command.'};$parameters.ExtendedView=$true}
        Get-VBOProxy @parameters | Select-Object -First ($MaxProxies+1)
    }
    $truncated=$inventory.Data.Count -gt $MaxProxies
    $proxyRows=@(foreach($item in @($inventory.Data | Select-Object -First $MaxProxies)){
        $row=[pscustomobject]@{Id=Get-VBOAuditScalar $item 'Id';Hostname=Get-VBOAuditScalar $item 'Hostname';Port=Get-VBOAuditScalar $item 'Port';State=Get-VBOAuditScalar $item 'State';Version=Get-VBOAuditScalar $item 'Version';Type=Get-VBOAuditScalar $item 'Type';IsOutdated=Get-VBOAuditScalar $item 'IsOutdated';OperatingSystemKind=Get-VBOAuditScalar $item 'OperatingSystemKind';ProxyRoles=Get-VBOAuditScalar $item 'ProxyRoles';MaintenanceModeState=Get-VBOAuditScalar $item 'MaintenanceModeState';PoolId=Get-VBOAuditScalar $item 'PoolId';ThreadsNumber=Get-VBOAuditScalar $item 'ThreadsNumber';ThrottlingValue=Get-VBOAuditScalar $item 'ThrottlingValue';ThrottlingUnit=Get-VBOAuditScalar $item 'ThrottlingUnit'}
        if($row.State -eq 'Offline'){Add-VeeamFinding -Component ('Proxy:'+ $row.Hostname) -State Fail -Evidence 'VBO reports the proxy offline.'}
        elseif($null -eq $row.State){Add-VeeamFinding -Component ('Proxy:'+ $row.Hostname) -State Unknown -Evidence 'Proxy state was not returned.'}
        if($row.IsOutdated -eq $true){Add-VeeamFinding -Component ('ProxyVersion:'+ $row.Hostname) -State Review -Evidence 'VBO reports that the proxy is out of date.'}
        if($row.MaintenanceModeState -in 'Enabled','Enabling'){Add-VeeamFinding -Component ('ProxyMaintenance:'+ $row.Hostname) -State Review -Evidence 'Proxy maintenance mode is enabled or enabling; review expected operational scope.'}
        $row
    })
    if($veeamContext.MajorVersion -ge 8 -and (Test-VBOAuditCapability 'Get-VBOProxyPool')){
        $poolCapability='Available'
        $pools=Invoke-ReportQuery -Section 'VBOProxyPools' -Action {Get-VBOProxyPool -ErrorAction Stop | Select-Object -First ($MaxProxies+1)}
        $poolsTruncated=$pools.Data.Count -gt $MaxProxies
        $poolRows=@(foreach($item in @($pools.Data | Select-Object -First $MaxProxies)){
            $membershipProperty=$item.PSObject.Properties['Proxies'];$memberCount=$null;$membersCapped=$false;$membershipVisibility='Unknown'
            if($null -ne $membershipProperty -and $null -ne $membershipProperty.Value -and $membershipProperty.Value -is [System.Collections.IEnumerable] -and $membershipProperty.Value -isnot [string]){
                $members=@($membershipProperty.Value | Select-Object -First ($MaxPoolMembers+1))
                $memberCount=[math]::Min($members.Count,$MaxPoolMembers);$membersCapped=$members.Count -gt $MaxPoolMembers;$membershipVisibility='Returned'
            }else{Add-VeeamFinding -Component ('ProxyPoolMembership:'+ (Get-VBOAuditScalar $item 'Name')) -State Unknown -Evidence 'A usable pool member collection was not exposed; missing membership is not zero members.'}
            [pscustomobject]@{Id=Get-VBOAuditScalar $item 'Id';Name=Get-VBOAuditScalar $item 'Name';MembersObserved=$memberCount;MemberListTruncated=$membersCapped;MembershipVisibility=$membershipVisibility}
        })
    }else{
        $poolFindingState=$(if($veeamContext.MajorVersion -lt 8){'NotApplicable'}else{'Unknown'})
        Add-VeeamFinding -Component 'ProxyPools' -State $poolFindingState -Evidence 'Proxy-pool capability is unavailable for this major version or installed toolkit; pool health was not assessed.'
    }
    if($truncated -or $poolsTruncated){Add-VeeamFinding -Component 'ProxyScope' -State Review -Evidence 'Proxy or pool output was capped by MaxProxies.'}
}else{Add-VeeamFinding -Component 'ProxyAudit' -State Unknown -Evidence 'VBO connection or supported-version detection did not complete.'}
Write-ReportCsv -Name 'proxies' -Rows $proxyRows -Columns @('Id','Hostname','Port','State','Version','Type','IsOutdated','OperatingSystemKind','ProxyRoles','MaintenanceModeState','PoolId','ThreadsNumber','ThrottlingValue','ThrottlingUnit')
Write-ReportCsv -Name 'proxy-pools' -Rows $poolRows -Columns @('Id','Name','MembersObserved','MemberListTruncated','MembershipVisibility')
Complete-Report -Data ([pscustomobject]@{ProxiesReported=$proxyRows.Count;ProxyOutputTruncated=$truncated;PoolsReported=$poolRows.Count;PoolsTruncated=$poolsTruncated;PoolCapability=$poolCapability;MaxProxies=$MaxProxies;MaxPoolMembers=$MaxPoolMembers}) -Notes @(
    'No proxy rescan, synchronization, upgrade, maintenance change, or service action is performed. Reported online state is not a workload/network test.'
    'Proxy Version is the proxy-service build, not proof of the backup server build. v8-only fields stay blank when absent on v7.'
    'Proxy service-account and internet-proxy settings are never exported. Pool member counts are bounded observations, not a capacity or availability guarantee.'
)


} finally {Close-OwnedVeeamConnection}