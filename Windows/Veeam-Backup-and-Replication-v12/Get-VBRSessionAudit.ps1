<#
What it does:
  Reports bounded v12 backup/replication/copy session results and per-object task statuses.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -Hours: Session creation look-back window in UTC; default 168.
  -JobNamePattern: Session display-name wildcard; default *.
  -MaxSessions: Maximum matching provider-order sessions; default 200.
  -MaxTasksPerSession: Maximum tasks inspected per session; default 200.

How it works:
  Reads Get-VBRBackupSession and independently queries Get-VBRTaskSession for inspected sessions. Preserves explicit UTC times and unknown task evidence; a successful result does not establish recoverability. No sessions are started or stopped.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateRange(1,8760)][int]$Hours=168,
[ValidateNotNullOrEmpty()][string]$JobNamePattern='*',
[ValidateRange(1,10000)][int]$MaxSessions=200,
[ValidateRange(1,10000)][int]$MaxTasksPerSession=200
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
function Get-JobAuditText {
    param([object]$Object,[string]$Path)
    $value=Get-VeeamValue -Object $Object -Path $Path
    if($value -is [datetime]){return $value.ToString('o')}
    if($value -is [string] -or $value -is [guid] -or $value -is [enum] -or $value -is [version] -or $value -is [timespan] -or $value -is [byte] -or $value -is [int16] -or $value -is [uint16] -or $value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64] -or $value -is [single] -or $value -is [double] -or $value -is [decimal]){return [string]$value}
    return $null
}
function Convert-SessionUtc {
    param($Value)
    if($null -eq $Value){return $null}
    try{$date=[datetime]$Value;if($date.Year -lt 1901){return $null};if($date.Kind -eq [DateTimeKind]::Local){return $date.ToUniversalTime()};return [datetime]::SpecifyKind($date,[DateTimeKind]::Utc)}catch{return $null}
}
$rows=New-Object 'System.Collections.Generic.List[object]';$tasks=New-Object 'System.Collections.Generic.List[object]'
$sessionCap=$false;$taskCapSessions=0;$cutoff=[datetime]::UtcNow.AddHours(-$Hours)
if($veeamReady){
    $sessions=Invoke-ReportQuery -Section 'Backup/replication session inventory' -Action {
        Get-VBRBackupSession -ErrorAction Stop | Where-Object {
            $name=(Get-JobAuditText -Object $_ -Path 'Name');$created=Convert-SessionUtc (Get-VeeamValue $_ 'CreationTimeUTC')
            $name -like $JobNamePattern -and ($null -eq $created -or $created -ge $cutoff)
        } | Select-Object -First ($MaxSessions+1)
    }
    $sessionCap=$sessions.Data.Count -gt $MaxSessions
    foreach($session in @($sessions.Data | Select-Object -First $MaxSessions)){
        $id=(Get-JobAuditText -Object $session -Path 'Id');$name=(Get-JobAuditText -Object $session -Path 'Name');$result=(Get-JobAuditText -Object $session -Path 'Result');$state=(Get-JobAuditText -Object $session -Path 'State')
        $created=Convert-SessionUtc (Get-VeeamValue $session 'CreationTimeUTC');$ended=Convert-SessionUtc (Get-VeeamValue $session 'EndTimeUTC')
        $observation='Unknown';if($result -eq 'Failed'){$observation='Fail'}elseif($result -eq 'Warning'){$observation='Review'}elseif($result -eq 'Success'){$observation='Pass'}elseif($state -and $state -ne 'Stopped'){$observation='Review'}
        $rows.Add([pscustomobject]@{Id=$id;Name=$name;JobId=(Get-JobAuditText -Object $session -Path 'JobId');JobType=(Get-JobAuditText -Object $session -Path 'JobType');State=$state;Result=$result;CreationTimeUtc=$(if($created){$created.ToString('o')}else{$null});EndTimeUtc=$(if($ended){$ended.ToString('o')}else{$null});ResultAssessment=$observation;TimeEvidence=$(if($created){'ExplicitUtcField'}else{'Unknown'})})
        Add-VeeamFinding -Component ('Session '+$id+' '+$name) -State $observation -Evidence ('Provider session result='+$result+'; state='+$state+'. This observes execution, not restore validation.')
        if(-not $id){Add-VeeamFinding -Component 'Session identity' -State Unknown -Evidence 'A session ID was unavailable; task follow-up skipped.';continue}
        $taskResult=Invoke-ReportQuery -Section ('Task results '+$id) -Action {Get-VBRTaskSession -Session $session -ErrorAction Stop | Select-Object -First ($MaxTasksPerSession+1)}
        if($taskResult.Data.Count -gt $MaxTasksPerSession){$taskCapSessions++}
        if(-not $taskResult.Succeeded -or -not $taskResult.Data.Count){Add-VeeamFinding -Component ('Session tasks '+$id) -State Unknown -Evidence 'No usable task evidence was returned; do not infer that every object succeeded.'}
        foreach($task in @($taskResult.Data | Select-Object -First $MaxTasksPerSession)){
            $status=(Get-JobAuditText -Object $task -Path 'Status');$assessment='Unknown'
            if($status -eq 'Failed'){$assessment='Fail'}elseif($status -eq 'Warning'){$assessment='Review'}elseif($status -eq 'Success'){$assessment='Pass'}elseif($status){$assessment='Review'}
            $taskId=(Get-JobAuditText -Object $task -Path 'Id');$taskName=(Get-JobAuditText -Object $task -Path 'Name')
            $tasks.Add([pscustomobject]@{SessionId=$id;SessionName=$name;TaskId=$taskId;ObjectName=$taskName;Status=$status;ResultAssessment=$assessment})
            if($assessment -ne 'Pass'){Add-VeeamFinding -Component ('Task '+$taskId+' '+$taskName) -State $assessment -Evidence ('Task status='+$status+' in session '+$id+'.')}
        }
    }
    if($sessionCap -or $taskCapSessions){Add-VeeamFinding -Component 'Session/task scope' -State Unknown -Evidence 'Configured caps excluded additional session or task evidence.'}
    if($sessions.Succeeded -and -not $rows.Count){Add-VeeamFinding -Component 'Recent sessions' -State Unknown -Evidence 'No matching retained sessions were returned; this does not establish that required jobs ran.'}
}
Write-ReportCsv -Name 'sessions' -Rows $rows.ToArray() -Columns @('Id','Name','JobId','JobType','State','Result','CreationTimeUtc','EndTimeUtc','ResultAssessment','TimeEvidence')
Write-ReportCsv -Name 'session-tasks' -Rows $tasks.ToArray() -Columns @('SessionId','SessionName','TaskId','ObjectName','Status','ResultAssessment')
Complete-Report -Data ([pscustomobject]@{Context=$veeamContext;Hours=$Hours;UtcCutoff=$cutoff.ToString('o');SessionsReported=$rows.Count;TasksReported=$tasks.Count;SessionCapReached=$sessionCap;SessionsWithTaskCap=$taskCapSessions}) -Notes @(
    'Get-VBRBackupSession in v12 covers its documented backup, replication, copy, and file-backup session families; this is not an inventory of every Agent, tape, SureBackup, plug-in, CDP, or cloud-native session API.'
    'The name pattern matches session display names, which may include run type; it is not an exact job-name resolver.'
    'Only explicit CreationTimeUTC/EndTimeUTC fields are normalized to UTC. Missing UTC fields are retained as unknown and are not filtered out as old.'
    'The cap retains provider-order matches; it does not guarantee newest-first coverage. Retention and caps can hide both earlier and later results; use narrower filters or larger limits.'
    'A successful session/task result is execution evidence only and does not prove all intended workloads, current RPO, media availability, or recoverability. No logs or free-form error/credential objects are exported.'
)

} finally {Close-OwnedVeeamConnection}