<#
What it does:
  Audits VB365 platform, license, TLS-certificate, and reported component metadata.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9191.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -MaxComponents: Maximum reported components, 1-10000; default 500.
  -CertificateWarningDays: Certificate-expiry review window, 0-3650 days; default 30.

How it works:
  Uses installed VB365 v7/v8 read commands and scalar metadata only. Toolkit and verified server versions remain separate; missing capabilities and failed queries remain explicit, and this does not establish overall security or recovery readiness.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9191,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateRange(1,10000)][int]$MaxComponents=500,
    [ValidateRange(0,3650)][int]$CertificateWarningDays=30
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

$platformRows=New-Object 'System.Collections.Generic.List[object]'
$licenseRows=@();$securityRows=@();$componentRows=@();$componentsTruncated=$false
if($veeamReady){
    $settings=Invoke-ReportQuery -Section 'VBOPlatformSettings' -Action {Get-VBOServer -ErrorAction Stop} -RequireData
    foreach($item in @($settings.Data)){$platformRows.Add([pscustomobject]@{RequestedServer=$veeamContext.Server;ToolkitProductVersion=$veeamContext.ToolkitProductVersion;VerifiedServerVersion=$veeamContext.ServerVersion;DetectedMajor=$veeamContext.MajorVersion;ModuleVersion=$veeamContext.ModuleVersion;TempFolderPath=Get-VBOAuditScalar $item 'TempFolderPath';RemoteBuildVerification='NotEstablishedByGetVBOServer'})}
    $license=Invoke-ReportQuery -Section 'VBOLicense' -Action {Get-VBOLicense -ErrorAction Stop} -RequireData
    $licenseRows=@(foreach($item in @($license.Data)){
        $row=[pscustomobject]@{Status=Get-VBOAuditScalar $item 'Status';Type=Get-VBOAuditScalar $item 'Type';ExpirationDate=Get-VBOAuditScalar $item 'ExpirationDate';TotalNumber=Get-VBOAuditScalar $item 'TotalNumber';UsedNumber=Get-VBOAuditScalar $item 'UsedNumber';NewNumber=Get-VBOAuditScalar $item 'NewNumber'}
        if($row.Status -eq 'Expired'){Add-VeeamFinding -Component 'License' -State Fail -Evidence 'VBO reports an expired license.'}
        elseif($null -eq $row.Status){Add-VeeamFinding -Component 'License' -State Unknown -Evidence 'License status was not exposed by this build.'}
        if($null -ne $row.TotalNumber -and $null -ne $row.UsedNumber -and $row.TotalNumber -gt 0 -and $row.UsedNumber -gt $row.TotalNumber){Add-VeeamFinding -Component 'LicenseConsumption' -State Review -Evidence 'Reported consumed units exceed licensed units.'}
        $row
    })
    if(Test-VBOAuditCapability 'Get-VBOSecuritySettings'){
        $security=Invoke-ReportQuery -Section 'VBOTlsCertificateMetadata' -Action {Get-VBOSecuritySettings -ErrorAction Stop} -RequireData
        $securityRows=@(foreach($item in @($security.Data)){
            $expires=Get-VBOAuditScalar $item 'CertificateExpirationDate';$state='Unknown'
            if($expires){try{if([datetime]$expires -lt (Get-Date)){$state='Expired'}elseif([datetime]$expires -le (Get-Date).AddDays($CertificateWarningDays)){$state='ExpiringSoon'}else{$state='BeyondWarningWindow'}}catch{$state='Unknown'}}
            if($state -eq 'Expired'){Add-VeeamFinding -Component 'PlatformTlsCertificate' -State Fail -Evidence 'Reported TLS certificate has expired.'}
            elseif($state -eq 'ExpiringSoon'){Add-VeeamFinding -Component 'PlatformTlsCertificate' -State Review -Evidence ('Reported certificate expires within '+$CertificateWarningDays+' days.')}
            elseif($state -eq 'Unknown'){Add-VeeamFinding -Component 'PlatformTlsCertificate' -State Unknown -Evidence 'Certificate expiration metadata was unavailable or invalid.'}
            [pscustomobject]@{IssuedTo=Get-VBOAuditScalar $item 'CertificateIssuedTo';IssuedBy=Get-VBOAuditScalar $item 'CertificateIssuedBy';Thumbprint=Get-VBOAuditScalar $item 'CertificateThumbprint';ExpirationDate=$expires;DateAssessment=$state}
        })
    }else{Add-VeeamFinding -Component 'PlatformTlsCertificate' -State Unknown -Evidence 'Get-VBOSecuritySettings is unavailable in the installed toolkit; certificate metadata was not assessed.'}
    if(Test-VBOAuditCapability 'Get-VBOServerComponents'){
        $components=Invoke-ReportQuery -Section 'VBOReportedComponents' -Action {Get-VBOServerComponents -ErrorAction Stop | Select-Object -First ($MaxComponents+1)}
        $componentsTruncated=$components.Data.Count -gt $MaxComponents
        $componentRows=@(foreach($item in @($components.Data | Select-Object -First $MaxComponents)){
            $row=[pscustomobject]@{Id=Get-VBOAuditScalar $item 'Id';Name=Get-VBOAuditScalar $item 'Name';ServerName=Get-VBOAuditScalar $item 'ServerName';IsOnline=Get-VBOAuditScalar $item 'IsOnline';ExtendedLoggingEnabled=Get-VBOAuditScalar $item 'ExtendedLoggingEnabled';DistributedTracingEnabled=Get-VBOAuditScalar $item 'DistributedTracingEnabled'}
            if($null -ne $row.IsOnline -and -not $row.IsOnline){Add-VeeamFinding -Component ('Component:'+ $row.Name) -State Review -Evidence ('Component reports offline on '+$row.ServerName+'.')}
            $row
        })
        if($componentsTruncated){Add-VeeamFinding -Component 'ComponentScope' -State Review -Evidence 'Component output was truncated by MaxComponents.'}
    }else{Add-VeeamFinding -Component 'ComponentInventory' -State Unknown -Evidence 'Get-VBOServerComponents is unavailable in this toolkit; component host evidence was not collected.'}
}else{Add-VeeamFinding -Component 'PlatformAudit' -State Unknown -Evidence 'VBO connection or supported-version detection did not complete.'}
Write-ReportCsv -Name 'platform' -Rows $platformRows.ToArray() -Columns @('RequestedServer','ToolkitProductVersion','VerifiedServerVersion','DetectedMajor','ModuleVersion','TempFolderPath','RemoteBuildVerification')
Write-ReportCsv -Name 'license' -Rows $licenseRows -Columns @('Status','Type','ExpirationDate','TotalNumber','UsedNumber','NewNumber')
Write-ReportCsv -Name 'tls-certificate' -Rows $securityRows -Columns @('IssuedTo','IssuedBy','Thumbprint','ExpirationDate','DateAssessment')
Write-ReportCsv -Name 'components' -Rows $componentRows -Columns @('Id','Name','ServerName','IsOnline','ExtendedLoggingEnabled','DistributedTracingEnabled')
Complete-Report -Data ([pscustomobject]@{ComponentsReported=$componentRows.Count;ComponentsTruncated=$componentsTruncated;MaxComponents=$MaxComponents;CertificateWarningDays=$CertificateWarningDays}) -Notes @(
    'Get-VBOServer exposes temporary-storage settings, not server identity or product build. Get-VBOVersion product output and module version are separate evidence; no remote build is inferred from either component host names or proxy versions.'
    'This is a metadata audit. Certificate chain, endpoint identity, license entitlement, and product security posture require separate validation.'
    'Only named scalar properties are exported. License identities, email addresses, connection settings, accounts, credentials, keys, and tokens are excluded.'
)


} finally {Close-OwnedVeeamConnection}