<#
What it does:
  Collects Windows Veeam service, local-disk, memory, uptime, and recent event metadata.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -Hours: Event look-back window; default 48.
  -MaxEvents: Matching event rows retained; default 200.
  -MinimumFreePercent: Local-disk free-space review threshold; default 15.

How it works:
  Reads the requested Windows server locally or through WinRM. Exports selected service/CIM and event metadata without command lines, event messages, or account secrets; does not restart services or change the host.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateRange(1,8760)][int]$Hours=48,
    [ValidateRange(1,10000)][int]$MaxEvents=200,
    [ValidateRange(1,99)][int]$MinimumFreePercent=15
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
$hostRows=@();$serviceRows=@();$diskRows=@();$eventRows=@()
$capture={
    param($RequestedProduct,$LookbackHours,$EventLimit)
    $prefix=if($RequestedProduct -eq 'VBR'){'Veeam'}else{'Veeam.Archiver'}
    try{
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if($null -eq $os){throw [InvalidOperationException]::new('Required operating system evidence was absent')}
        [pscustomobject]@{Kind='Host';Computer=$env:COMPUTERNAME;Caption=$os.Caption;Version=$os.Version;LastBootUpTime=$os.LastBootUpTime;FreePhysicalMemoryKB=$os.FreePhysicalMemory;TotalVisibleMemoryKB=$os.TotalVisibleMemorySize}
    }catch{[pscustomobject]@{Kind='CollectionError';Section='OperatingSystem';ErrorType=$_.Exception.GetType().FullName}}
    try{
        foreach($service in Get-CimInstance Win32_Service -Filter ("Name LIKE '"+$prefix+"%'") -ErrorAction Stop){
            [pscustomobject]@{Kind='Service';Name=$service.Name;DisplayName=$service.DisplayName;State=$service.State;StartMode=$service.StartMode;ExitCode=$service.ExitCode;ProcessId=$service.ProcessId}
        }
    }catch{[pscustomobject]@{Kind='CollectionError';Section='Services';ErrorType=$_.Exception.GetType().FullName}}
    try{
        foreach($disk in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop){
            [pscustomobject]@{Kind='Disk';Drive=$disk.DeviceID;SizeBytes=$disk.Size;FreeBytes=$disk.FreeSpace}
        }
    }catch{[pscustomobject]@{Kind='CollectionError';Section='LocalDisks';ErrorType=$_.Exception.GetType().FullName}}
    try{
        $filter=@{LogName='Application';StartTime=(Get-Date).AddHours(-$LookbackHours);Level=@(1,2,3)}
        # Provider names are matched on the host. Raw event messages may contain secrets.
        Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | Where-Object ProviderName -like 'Veeam*' | Select-Object -First ($EventLimit+1) | ForEach-Object {
            [pscustomobject]@{Kind='Event';TimeCreatedUtc=$_.TimeCreated.ToUniversalTime().ToString('o');ProviderName=$_.ProviderName;Id=$_.Id;LevelDisplayName=$_.LevelDisplayName;RecordId=$_.RecordId}
        }
    }catch{
        if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){[pscustomobject]@{Kind='EventQueryEmpty'}}
        else{[pscustomobject]@{Kind='CollectionError';Section='ApplicationEvents';ErrorType=$_.Exception.GetType().FullName}}
    }
}
$result=Invoke-ReportQuery -Section 'WindowsVeeamHostEvidence' -RequireData -Action {
    if($Server -in @('localhost','.','127.0.0.1','::1',$env:COMPUTERNAME)){& $capture $script:VeeamProduct $Hours $MaxEvents}
    else{
        $request=@{ComputerName=$Server;ScriptBlock=$capture;ArgumentList=@($script:VeeamProduct,$Hours,$MaxEvents);ErrorAction='Stop'}
        if($HostCredential){$request.Credential=$HostCredential}
        Invoke-Command @request
    }
}
if($result.Succeeded){
    foreach($gap in @($result.Data | Where-Object Kind -eq CollectionError)){
        $collectionStatus.Add([pscustomobject]@{Section=('WindowsHost:'+ $gap.Section);State='Unknown';Rows=$null;ErrorType=$gap.ErrorType})
        Add-VeeamFinding -Component ('WindowsHost:'+ $gap.Section) -State Unknown -Evidence 'This host section could not be collected. Other returned host evidence was preserved; raw error text is excluded.'
    }
    $hostRows=@($result.Data | Where-Object Kind -eq Host | Select-Object Computer,Caption,Version,LastBootUpTime,FreePhysicalMemoryKB,TotalVisibleMemoryKB)
    $serviceRows=@($result.Data | Where-Object Kind -eq Service | Select-Object Name,DisplayName,State,StartMode,ExitCode,ProcessId)
    $diskRows=@(foreach($disk in @($result.Data | Where-Object Kind -eq Disk)){
        $percent=if($null -ne $disk.SizeBytes -and $null -ne $disk.FreeBytes -and $disk.SizeBytes -gt 0){[math]::Round(100*$disk.FreeBytes/$disk.SizeBytes,2)}else{$null}
        if($null -eq $percent){Add-VeeamFinding ('LocalDiskCapacity:'+ $disk.Drive) Unknown 'Disk capacity or free-space evidence was unavailable; no zero free-space value was inferred.'}
        if($null -ne $percent -and $percent -lt $MinimumFreePercent){Add-VeeamFinding ('LocalDisk:'+ $disk.Drive) Review 'Free space is below the selected warning threshold.'}
        [pscustomobject]@{Drive=$disk.Drive;SizeBytes=$disk.SizeBytes;FreeBytes=$disk.FreeBytes;FreePercent=$percent}
    })
    $eventRows=@($result.Data | Where-Object Kind -eq Event)
    if($eventRows.Count -gt $MaxEvents){Add-VeeamFinding 'EventScope' Review 'Matching event output was capped; event evidence is incomplete.';$eventRows=@($eventRows | Select-Object -First $MaxEvents)}
    foreach($service in $serviceRows){if($service.StartMode -eq 'Auto' -and $service.State -ne 'Running'){Add-VeeamFinding ('Service:'+ $service.Name) Review 'An automatic Veeam service is not Running. Review its role; optional components can be intentionally stopped.'}}
    if($serviceRows.Count -eq 0){Add-VeeamFinding 'VeeamServices' Unknown 'No matching Windows service was returned on the requested host.'}
    if($eventRows.Count){Add-VeeamFinding 'VeeamEvents' Review 'Recent warning/error/critical event metadata was found. Inspect the selected events on the host for details.'}
}
Write-ReportCsv -Name 'host' -Rows $hostRows -Columns @('Computer','Caption','Version','LastBootUpTime','FreePhysicalMemoryKB','TotalVisibleMemoryKB')
Write-ReportCsv -Name 'services' -Rows $serviceRows -Columns @('Name','DisplayName','State','StartMode','ExitCode','ProcessId')
Write-ReportCsv -Name 'local-disks' -Rows $diskRows -Columns @('Drive','SizeBytes','FreeBytes','FreePercent')
Write-ReportCsv -Name 'event-metadata' -Rows $eventRows -Columns @('TimeCreatedUtc','ProviderName','Id','LevelDisplayName','RecordId')
Complete-Report -Data ([pscustomobject]@{Services=$serviceRows.Count;LocalDisks=$diskRows.Count;Events=$eventRows.Count;LookbackHours=$Hours}) -Notes @(
    'Inspects the requested Windows Veeam host locally or through Windows remoting, using HostCredential when supplied. The workstation is never silently substituted for a remote host.'
    'VBR matches Windows service names Veeam*; Microsoft 365 matches Veeam.Archiver*. Local fixed disks are not a complete repository inventory and do not describe Linux, SMB, object storage, or cache database capacity.'
    'Application-log event metadata only: no event messages, service account names, command lines, database connection strings, or log file contents are exported. Inspect native logs when more detail is needed.'
)

} finally {Close-OwnedVeeamConnection}