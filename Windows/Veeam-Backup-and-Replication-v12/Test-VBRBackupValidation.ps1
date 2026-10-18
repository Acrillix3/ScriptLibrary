<#
What it does:
  Plans or explicitly runs Veeam v12 Backup Validator CRC checks on the backup server.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -BackupName: Required precise backup or child-backup name accepted by Veeam Validator.
  -RunValidation: Opt in to intensive CRC scanning.
  -ValidatorPath: Optional validator executable path on the requested VBR server.
  -ServerReportDirectory: Native HTML destination on the VBR server; default its TEMP\ScriptLibrary-VeeamValidation.
  -TimeoutMinutes: Stop only this validator process after this duration; default 120.
  -WhatIf and -Confirm: Standard ShouldProcess controls for the active scan.

How it works:
  Uses the v12 vendor executable on the requested backup server, locally or through WinRM. Default is plan only. Records exit/report evidence and leaves native results for review; no recovery or repair is performed.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$BackupName,
    [switch]$RunValidation,
    [string]$ValidatorPath,
    [string]$ServerReportDirectory,
    [ValidateRange(1,1440)][int]$TimeoutMinutes=120
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
$execution=@();$invoked=$false
if($BackupName -match '["\r\n\x00]'){throw 'BackupName cannot contain quotes, line breaks, or NUL.'}
if(-not $RunValidation){Add-VeeamFinding 'BackupValidation' Unknown 'Plan only. Add RunValidation to request an intensive CRC scan on the VBR server. No backup content was scanned.'}
elseif(-not $veeamReady){Add-VeeamFinding 'BackupValidation' Unknown 'A supported VBR connection was not established. No validation ran.'}
elseif($PSCmdlet.ShouldProcess(($Server+':'+$BackupName),'Run Veeam Backup Validator CRC scan on the backup server')){
    $invoked=$true
    $validatorAction={
        param($SelectedBackup,$Executable,$ReportFolder,$LimitMinutes)
        if(-not $Executable){$Executable=Join-Path $env:ProgramFiles 'Veeam\Backup and Replication\Backup\Veeam.Backup.Validator.exe'}
        if(-not (Test-Path -LiteralPath $Executable -PathType Leaf)){throw [IO.FileNotFoundException]::new('Validator absent on server')}
        if([IO.Path]::GetFileName($Executable) -ne 'Veeam.Backup.Validator.exe'){throw [InvalidOperationException]::new('Unexpected executable')}
        $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($Executable)
        if($version.ProductVersion -notmatch '^12\.'){throw [InvalidOperationException]::new('Validator is not v12')}
        if(-not $ReportFolder){$ReportFolder=Join-Path $env:TEMP 'ScriptLibrary-VeeamValidation'}
        $null=New-Item -ItemType Directory -Path $ReportFolder -Force
        $report=[IO.Path]::GetFullPath((Join-Path $ReportFolder ('validator-'+[guid]::NewGuid().ToString('N')+'.html')))
        if($report -match '["\r\n\x00]'){throw [InvalidOperationException]::new('Invalid report path')}
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=$Executable;$info.WorkingDirectory=Split-Path -Parent $Executable
        $info.Arguments='/backup:"'+$SelectedBackup+'" /silence /report:"'+$report+'" /format:html'
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true
        $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $process=New-Object Diagnostics.Process;$process.StartInfo=$info
        try{
            $null=$process.Start();$out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
            $finished=$process.WaitForExit($LimitMinutes*60000)
            if(-not $finished){$process.Kill();$process.WaitForExit()}
            $null=$out.GetAwaiter().GetResult();$null=$err.GetAwaiter().GetResult()
            [pscustomobject]@{ExecutionComputer=$env:COMPUTERNAME;Completed=$finished;ExitCode=$(if($finished){$process.ExitCode}else{$null});NativeReportPath=$report;NativeReportExists=Test-Path -LiteralPath $report -PathType Leaf}
        }finally{$process.Dispose()}
    }
    $result=Invoke-ReportQuery -Section 'VendorBackupValidator' -RequireData -Action {
        if($Server -in @('localhost','.','127.0.0.1','::1',$env:COMPUTERNAME)){& $validatorAction $BackupName $ValidatorPath $ServerReportDirectory $TimeoutMinutes}
        else{
            $request=@{ComputerName=$Server;ScriptBlock=$validatorAction;ArgumentList=@($BackupName,$ValidatorPath,$ServerReportDirectory,$TimeoutMinutes);ErrorAction='Stop'}
            if($HostCredential){$request.Credential=$HostCredential}
            Invoke-Command @request
        }
    }
    $execution=@($result.Data)
    if($result.Succeeded){
        foreach($item in $execution){
            if(-not $item.Completed){Add-VeeamFinding 'BackupValidation' Unknown 'Validator exceeded TimeoutMinutes; only this validator process was stopped. Validation is incomplete.'}
            elseif($item.ExitCode -ne 0 -or -not $item.NativeReportExists){Add-VeeamFinding 'BackupValidation' Review 'Validator returned a nonzero exit code or no native report. Inspect the native Veeam evidence.'}
            else{Add-VeeamFinding 'BackupValidation' Review 'Validator exited and produced a native report. Review that report for per-VM CRC results; this wrapper does not infer success from exit code alone.'}
        }
    }
}else{Add-VeeamFinding 'BackupValidation' Unknown 'Validation was declined or WhatIf was used.'}
Write-ReportCsv -Name 'backup-validator' -Rows $execution -Columns @('ExecutionComputer','Completed','ExitCode','NativeReportPath','NativeReportExists')
Complete-Report -Data ([pscustomobject]@{BackupName=$BackupName;Requested=[bool]$RunValidation;Invoked=$invoked;TimeoutMinutes=$TimeoutMinutes}) -Notes @(
    'Opt-in CRC/file-content validation using the installed v12 Veeam.Backup.Validator.exe on the VBR server. RunValidation and ShouldProcess authorization are required. Native reports remain on that server; no arbitrary executable or password arguments are accepted.'
    'Use the precise backup or child backup name required by your v12 backup format. Object-storage/performance-tier, encrypted, cloud, and per-machine-chain limitations follow the vendor utility documentation. This wrapper does not discover child backups using undocumented methods.'
    'CRC validation is I/O intensive and does not prove bootability, application recovery, or item restoration. Native report contents require review. No jobs, restores, repairs, or configuration changes are started.'
)

} finally {Close-OwnedVeeamConnection}