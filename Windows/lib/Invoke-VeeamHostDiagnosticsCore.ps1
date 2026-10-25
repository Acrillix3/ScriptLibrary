<#
What it does:
  Collects Windows Veeam service, local-disk, memory, uptime, and recent event metadata.

Available flags:
  -Product: Private VBR/VBO profile supplied by the public entrypoint.
  -EntryPointName: Private report identity supplied by the public entrypoint.
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -Hours: Event look-back window; default 48.
  -MaxEvents: Matching event rows retained; default 200.
  -MinimumFreePercent: Local-disk free-space review threshold; default 15.

How it works:
  Private shared implementation; invoke a public product entrypoint instead. Reports retain its name.
  Reads the requested Windows server locally or through WinRM. Exports selected service/CIM and event metadata without command lines, event messages, or account secrets; does not restart services or change the host.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('VBR','VBO')][string]$Product,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z][A-Za-z0-9_-]+$')][string]$EntryPointName,
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateRange(1,8760)][int]$Hours=48,
    [ValidateRange(1,10000)][int]$MaxEvents=200,
    [ValidateRange(1,99)][int]$MinimumFreePercent=15
)
$script:VeeamProduct=$Product
$ErrorActionPreference='Stop'
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$runName=$EntryPointName
$runDirectory=Join-Path $OutputDirectory ($runName+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $runDirectory -Force
$collectionStatus=New-Object 'System.Collections.Generic.List[object]'
$findings=New-Object 'System.Collections.Generic.List[object]'
$veeamReady=$false;$ownsVeeamConnection=$false
$veeamContext=[pscustomobject]@{Product=$script:VeeamProduct;Server=$Server;Port=$Port;MajorVersion=$null;ServerVersion=$null;ToolkitProductVersion=$null;ModuleVersion=$null;VersionSource='Unknown';RemoteVersionVerified=$false;VersionRejected=$false;ConnectionSucceeded=$false;PowerShellVersion=[string]$PSVersionTable.PSVersion}
. (Join-Path $PSScriptRoot 'Veeam-AuditCommon.ps1')

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