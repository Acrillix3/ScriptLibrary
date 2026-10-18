<#
What it does:
  Audits VBR 12 user/group role assignments, selected security settings, and configuration backup encryption state.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -MaxRoleAssignments: Maximum role assignments to export; default 500.

How it works:
  Reads supported role, security, and configuration-backup getters. Projects the encryption enabled boolean without querying keys or credentials. Missing fields remain Unknown; compare findings with approved access and organizational policy.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateRange(1,10000)][int]$MaxRoleAssignments=500
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
$roleRows=New-Object 'System.Collections.Generic.List[object]'
$optionRows=@();$configRows=@();$roleStatus='Unknown';$roleCapReached=$false;$configurationEncryption='Unknown'
if($veeamReady){
    $roles=Invoke-ReportQuery -Section 'Veeam user and group role assignments' -Action { Get-VBRUserRoleAssignment -ErrorAction Stop | Select-Object -First ($MaxRoleAssignments+1) }
    if($roles.Succeeded){
        $roleStatus=$(if($roles.Data.Count){'Collected'}else{'Empty'})
        $roleCapReached=$roles.Data.Count -gt $MaxRoleAssignments
        foreach($role in @($roles.Data | Select-Object -First $MaxRoleAssignments)){
            $name=(Get-InfraText -Object $role -Path 'Name');$roleName=(Get-InfraText -Object $role -Path 'Role')
            $roleRows.Add([pscustomobject]@{Id=(Get-InfraText -Object $role -Path 'Id');Name=$name;Type=(Get-InfraText -Object $role -Path 'Type');Role=$roleName;ReviewFlag=$(if([string]::IsNullOrWhiteSpace($roleName)){'Unknown'}elseif($roleName -eq 'BackupAdmin'){'Review administrative access'}else{'Compare with approved access'})})
            if($roleName -eq 'BackupAdmin'){Add-VeeamFinding -Component ('Administrative role: '+$name) -State Review -Evidence 'BackupAdmin assignment was reported. Compare it with approved access and least-privilege requirements.'}
        }
        if($roleCapReached){Add-VeeamFinding -Component 'Role assignment inventory' -State Review -Evidence ('Export capped at '+$MaxRoleAssignments+' assignments.')}
    }else{Add-VeeamFinding -Component 'Role assignments' -State Unknown -Evidence 'Role assignment query unavailable; no conclusion about access can be made.'}
    $security=Invoke-ReportQuery -Section 'Global security options' -RequireData -Action { Get-VBRSecurityOptions -ErrorAction Stop }
    if($security.Succeeded){
        $securityValue=$security.Data | Select-Object -First 1
        $compress=Get-VeeamValue -Object $securityValue -Path 'CompressOldAuditLogs';$fips=Get-VeeamValue -Object $securityValue -Path 'FipsCompliantModeEnabled'
        $optionRows=@([pscustomobject]@{AuditLogsPath=(Get-InfraText -Object $securityValue -Path 'AuditLogsPath');CompressOldAuditLogs=$(if($compress -is [bool]){$compress}else{$null});FipsCompliantModeEnabled=$(if($fips -is [bool]){$fips}else{$null});FipsEvidence=$(if($fips -is [bool]){'Reported setting; compare with policy'}else{'Unknown: boolean unavailable'});MFAEnforcement='Unknown: not assessed by this v12 audit';CertificateValidation='Not assessed'})
        if($fips -isnot [bool]){Add-VeeamFinding -Component 'FIPS mode setting' -State Unknown -Evidence 'A boolean FipsCompliantModeEnabled value was not returned; it was not treated as disabled.'}
    }else{Add-VeeamFinding -Component 'Global security options' -State Unknown -Evidence 'Global security options unavailable.'}
    $configuration=Invoke-ReportQuery -Section 'Configuration backup encryption setting' -RequireData -Action { Get-VBRConfigurationBackupJob -ErrorAction Stop }
    if($configuration.Succeeded){
        $config=$configuration.Data | Select-Object -First 1
        $enabled=Get-VeeamValue -Object $config -Path 'Enabled';$encrypted=Get-VeeamValue -Object $config -Path 'EncryptionOptions.Enabled'
        $configurationEncryption=$(if($encrypted -isnot [bool]){'Unknown'}elseif($encrypted){'Enabled'}else{'Disabled'})
        $configRows=@([pscustomobject]@{ConfigurationBackupEnabled=$(if($enabled -is [bool]){$enabled}else{$null});EncryptionState=$configurationEncryption;EncryptionEnabled=$(if($encrypted -is [bool]){$encrypted}else{$null});EvidenceSource='VBRConfigurationBackupJob.EncryptionOptions.Enabled'})
        if($configurationEncryption -eq 'Unknown'){Add-VeeamFinding -Component 'Configuration backup encryption' -State Unknown -Evidence 'EncryptionOptions.Enabled was absent or not a boolean.'}
        elseif($configurationEncryption -eq 'Disabled'){Add-VeeamFinding -Component 'Configuration backup encryption' -State Review -Evidence 'The configuration backup encryption setting was reported disabled; compare with the organization security policy.'}
        else{Add-VeeamFinding -Component 'Configuration backup encryption' -State Pass -Evidence 'The configuration backup encryption setting was reported enabled. Existing backup files and keys were not inspected.'}
        if($enabled -is [bool] -and -not $enabled){Add-VeeamFinding -Component 'Configuration backup schedule' -State Review -Evidence 'The configuration backup job was reported disabled; verify that this is intentional.'}
    }else{Add-VeeamFinding -Component 'Configuration backup encryption' -State Unknown -Evidence 'Configuration backup getter unavailable; encryption state remains Unknown.'}
    Add-VeeamFinding -Component 'Security audit coverage' -State Unknown -Evidence 'This is a settings review, not a complete compliance assessment. Job backup encryption, MFA enforcement, group expansion, certificate trust, host security, and immutable retention were not validated.'
}
Write-ReportCsv -Name 'role-assignments' -Rows $roleRows.ToArray() -Columns @('Id','Name','Type','Role','ReviewFlag')
Write-ReportCsv -Name 'security-options' -Rows $optionRows -Columns @('AuditLogsPath','CompressOldAuditLogs','FipsCompliantModeEnabled','FipsEvidence','MFAEnforcement','CertificateValidation')
Write-ReportCsv -Name 'configuration-backup-encryption' -Rows $configRows -Columns @('ConfigurationBackupEnabled','EncryptionState','EncryptionEnabled','EvidenceSource')
$summaryData=[pscustomobject]@{Target=$veeamContext.Server;RoleAssignmentStatus=$roleStatus;RoleAssignmentCount=$(if($roleStatus -ne 'Unknown'){$roleRows.Count}else{$null});AdministrativeAssignmentCount=$(if($roleStatus -ne 'Unknown'){@($roleRows | Where-Object Role -eq 'BackupAdmin').Count}else{$null});RoleCapReached=$roleCapReached;ConfigurationBackupEncryption=$configurationEncryption;JobBackupEncryption='Not assessed';MFAEnforcement='Unknown';Compliance='Not assessed'}
Complete-Report -Data $summaryData -Notes @('Reads the documented VBR 12 user role, security settings, and configuration backup getters. User/group assignments are exported without expanding domain membership.','Only the EncryptionOptions.Enabled boolean is read; encryption key objects, passwords, certificates, and stored credentials are never queried or serialized.','Enabled encryption is a current setting, not proof that every historical backup is encrypted or recoverable. MFA enforcement and job encryption require separate evidence.','Review findings require comparison with organizational policy. A missing boolean is Unknown rather than false. The role cap limits exported records, not provider query time.')

} finally {Close-OwnedVeeamConnection}