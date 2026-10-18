<#
What it does:
  Audits VBR 12 server build, safe license summary fields, and managed server inventory.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -MaxServers: Maximum managed servers to export; default 500.
  -LicenseWarningDays: Review window before a reported license expiration date; default 30.

How it works:
  Reads documented build, license, and server getters locally or through a management-console connection. Exports only selected metadata. Reports missing evidence as Unknown; does not determine patch currency, compliance, or component connectivity.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateRange(1,10000)][int]$MaxServers=500,
    [ValidateRange(1,3650)][int]$LicenseWarningDays=30
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
function Get-PlatformNumber {
    param([object]$Object,[string]$Path)
    $value=Get-VeeamValue -Object $Object -Path $Path
    if($value -is [byte] -or $value -is [int16] -or $value -is [uint16] -or $value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64] -or $value -is [decimal]){return $value}
    return $null
}
$serverRows=New-Object 'System.Collections.Generic.List[object]'
$buildRows=@();$licenseRows=@();$socketRows=@();$serverCapReached=$false;$socketCapReached=$false
$buildStatus='Unknown';$licenseStatus='Unknown';$serverInventoryStatus='Unknown'
if($veeamReady){
    $buildResult=Invoke-ReportQuery -Section 'Backup server build' -RequireData -Action { Get-VBRBackupServerInfo -ErrorAction Stop }
    if($buildResult.Succeeded){
        $buildStatus='Collected'
        $buildRows=@($buildResult.Data | Select-Object -First 1 | ForEach-Object {[pscustomobject]@{Name=(Get-InfraText -Object $_ -Path 'Name');Build=(Get-InfraText -Object $_ -Path 'Build');PatchLevel=(Get-InfraText -Object $_ -Path 'PatchLevel')}})
        if([string]::IsNullOrWhiteSpace($buildRows[0].Build)){$buildStatus='Unknown';Add-VeeamFinding -Component 'Backup server build' -State Unknown -Evidence 'The getter returned no Build value.'}
        else{Add-VeeamFinding -Component 'Backup server build' -State Pass -Evidence ('Installed build was reported: '+$buildRows[0].Build+'. Patch currency and vulnerability status were not assessed.')}
    }else{Add-VeeamFinding -Component 'Backup server build' -State Unknown -Evidence 'Build query unavailable; see collection status.'}
    $licenseResult=Invoke-ReportQuery -Section 'Installed license' -RequireData -Action { Get-VBRInstalledLicense -ErrorAction Stop }
    if($licenseResult.Succeeded){
        $licenseStatus='Collected'
        $license=$licenseResult.Data | Select-Object -First 1
        $expiration=Get-VeeamValue -Object $license -Path 'ExpirationDate'
        if($expiration -isnot [datetime]){$expiration=$null}
        $supportExpiration=Get-VeeamValue -Object $license -Path 'SupportExpirationDate'
        if($supportExpiration -isnot [datetime]){$supportExpiration=$null}
        $expirationDays=$null;$expiryFlag='Unknown'
        if($expiration -is [datetime] -and $expiration.Year -ge 2000){
            $expirationDays=[math]::Round(($expiration-(Get-Date)).TotalDays,1)
            $expiryFlag=$(if($expirationDays -lt 0){'Reported date is past'}elseif($expirationDays -le $LicenseWarningDays){'Within warning window'}else{'Beyond warning window'})
        }
        $licenseRows=@([pscustomobject]@{Status=(Get-InfraText -Object $license -Path 'Status');Type=(Get-InfraText -Object $license -Path 'Type');Edition=(Get-InfraText -Object $license -Path 'Edition');ExpirationDate=$expiration;DaysToReportedExpiration=$expirationDays;ExpirationFlag=$expiryFlag;SupportExpirationDate=$supportExpiration;LicensedInstances=Get-PlatformNumber -Object $license -Path 'InstanceLicenseSummary.LicensedInstancesNumber';UsedInstances=Get-PlatformNumber -Object $license -Path 'InstanceLicenseSummary.UsedInstancesNumber'})
        if([string]::IsNullOrWhiteSpace($licenseRows[0].Status)){$licenseStatus='Unknown';Add-VeeamFinding -Component 'License status' -State Unknown -Evidence 'No scalar license status was returned.'}
        $socketEvidence=@(@(Get-VeeamValue -Object $license -Path 'SocketLicenseSummary') | Where-Object {$null -ne $_} | Select-Object -First 51)
        $socketCapReached=$socketEvidence.Count -gt 50
        $socketRows=@($socketEvidence | Select-Object -First 50 | ForEach-Object {[pscustomobject]@{Type=(Get-InfraText -Object $_ -Path 'Type');LicensedSockets=Get-PlatformNumber -Object $_ -Path 'LicensedSocketsNumber';UsedSockets=Get-PlatformNumber -Object $_ -Path 'UsedSocketsNumber';RemainingSockets=Get-PlatformNumber -Object $_ -Path 'RemainingSocketsNumber'}})
        if($socketCapReached){Add-VeeamFinding -Component 'Socket license summary coverage' -State Review -Evidence 'Socket platform summary export reached its defensive maximum of 50 rows.'}
        if($expiryFlag -in @('Reported date is past','Within warning window')){Add-VeeamFinding -Component 'License expiration date' -State Review -Evidence ($expiryFlag+'; review license type and the vendor-reported status before interpreting the date.')}
        elseif($expiryFlag -eq 'Unknown'){Add-VeeamFinding -Component 'License expiration date' -State Unknown -Evidence 'No usable expiration date; perpetual and special licenses need their own interpretation.'}
        else{Add-VeeamFinding -Component 'License expiration date' -State Pass -Evidence ('The reported date is beyond '+$LicenseWarningDays+' days; this is not a license compliance conclusion.')}
    }else{Add-VeeamFinding -Component 'Installed license' -State Unknown -Evidence 'License query unavailable or returned no license.'}
    $servers=Invoke-ReportQuery -Section 'Managed servers' -Action { Get-VBRServer -ErrorAction Stop | Select-Object -First ($MaxServers+1) }
    if($servers.Succeeded){
        $serverInventoryStatus=$(if($servers.Data.Count){'Collected'}else{'Empty'})
        $serverCapReached=$servers.Data.Count -gt $MaxServers
        foreach($managedServer in @($servers.Data | Select-Object -First $MaxServers)){
            $serverRows.Add([pscustomobject]@{Id=(Get-InfraText -Object $managedServer -Path 'Id');Name=(Get-InfraText -Object $managedServer -Path 'Name');Type=(Get-InfraText -Object $managedServer -Path 'Type');ConnectionHealth='Unknown: configuration inventory only'})
        }
        if($serverCapReached){Add-VeeamFinding -Component 'Managed server inventory' -State Review -Evidence ('Export capped at '+$MaxServers+' servers; inventory is incomplete.')}
    }else{Add-VeeamFinding -Component 'Managed server inventory' -State Unknown -Evidence 'Managed server query unavailable.'}
}
Write-ReportCsv -Name 'server-build' -Rows $buildRows -Columns @('Name','Build','PatchLevel')
Write-ReportCsv -Name 'license' -Rows $licenseRows -Columns @('Status','Type','Edition','ExpirationDate','DaysToReportedExpiration','ExpirationFlag','SupportExpirationDate','LicensedInstances','UsedInstances')
Write-ReportCsv -Name 'socket-license-summary' -Rows $socketRows -Columns @('Type','LicensedSockets','UsedSockets','RemainingSockets')
Write-ReportCsv -Name 'managed-servers' -Rows $serverRows.ToArray() -Columns @('Id','Name','Type','ConnectionHealth')
$summaryData=[pscustomobject]@{Target=$veeamContext.Server;ServerVersion=$veeamContext.ServerVersion;ModuleVersion=$veeamContext.ModuleVersion;BuildStatus=$buildStatus;LicenseStatus=$licenseStatus;ManagedServerStatus=$serverInventoryStatus;ManagedServerCount=$(if($serverInventoryStatus -ne 'Unknown'){$serverRows.Count}else{$null});ServerCapReached=$serverCapReached;SocketSummaryCapReached=$socketCapReached;LicenseWarningDays=$LicenseWarningDays;LicenseCompliance='Not assessed';PatchCurrency='Not assessed'}
Complete-Report -Data $summaryData -Notes @('VBR 12.x configuration inventory. No component rescan, service probe, update, or vulnerability feed is used.','License holder identity, support ID, raw license data, credentials, and workload details are excluded. Missing numeric license fields remain blank.','A reported expiration date needs interpretation with license type and status; perpetual licenses may have sentinel dates. Socket license summaries are limited to the vendor platform summary, with a defensive maximum of 50 rows.','The managed server cap limits exported inventory, not a hard timeout for Veeam provider calls.')

} finally {Close-OwnedVeeamConnection}