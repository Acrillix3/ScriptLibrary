<#
What it does:
  Tests DNS and TCP reachability from a chosen Windows host and records Veeam console authentication.

Available flags:
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -Endpoint: Additional hostname:port or [IPv6]:port targets; default none.
  -ProbeComputerName: Windows source for network tests; default localhost.
  -TimeoutMilliseconds: TCP timeout per address, 100-60000; default 3000.

How it works:
  Resolves explicit endpoints and attempts bounded TCP connections locally or through WinRM. Reports only the tested path; TCP success is separate from Veeam authentication and data-path health.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9392,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [ValidateCount(0,100)][string[]]$Endpoint=@(),
    [string]$ProbeComputerName='localhost',
    [ValidateRange(100,60000)][int]$TimeoutMilliseconds=3000
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
$networkRows=New-Object 'System.Collections.Generic.List[object]'
$endpoints=@([pscustomobject]@{HostName=$Server;Port=$Port;Source='Requested console endpoint'})
foreach($text in $Endpoint){
    if($text -match '^\[([^\]]+)\]:(\d{1,5})$' -or $text -match '^([^:\s]+):(\d{1,5})$'){
        $hostText=$Matches[1];$portNumber=[int]$Matches[2]
        if($portNumber -lt 1 -or $portNumber -gt 65535){throw 'Endpoint port must be between 1 and 65535.'}
        $endpoints+=[pscustomobject]@{HostName=$hostText;Port=$portNumber;Source='Operator-specified endpoint'}
    }else{throw 'Endpoint format must be hostname:port or [IPv6]:port.'}
}
$probe={
    param($HostName,$TcpPort,$Timeout)
    $addresses=@([Net.Dns]::GetHostAddresses($HostName))
    if($addresses.Count -eq 0){throw [Net.Sockets.SocketException]::new()}
    foreach($address in $addresses | Select-Object -First 8){
        $client=New-Object Net.Sockets.TcpClient($address.AddressFamily)
        $timer=[Diagnostics.Stopwatch]::StartNew();$connected=$false
        try{
            $pending=$client.BeginConnect($address,[int]$TcpPort,$null,$null)
            try{if($pending.AsyncWaitHandle.WaitOne([int]$Timeout)){$client.EndConnect($pending);$connected=$client.Connected}}finally{$pending.AsyncWaitHandle.Close()}
        }catch{$connected=$false}finally{$timer.Stop();$client.Close()}
        [pscustomobject]@{Address=[string]$address;Connected=$connected;ElapsedMilliseconds=$timer.ElapsedMilliseconds}
    }
}
foreach($endpointItem in $endpoints){
    $result=Invoke-ReportQuery -Section ('TcpProbe:'+ $endpointItem.HostName+':'+$endpointItem.Port) -RequireData -Action {
        if($ProbeComputerName -in @('localhost','.','127.0.0.1','::1',$env:COMPUTERNAME)){& $probe $endpointItem.HostName $endpointItem.Port $TimeoutMilliseconds}
        else{
            $request=@{ComputerName=$ProbeComputerName;ScriptBlock=$probe;ArgumentList=@($endpointItem.HostName,$endpointItem.Port,$TimeoutMilliseconds);ErrorAction='Stop'}
            if($HostCredential){$request.Credential=$HostCredential}
            Invoke-Command @request
        }
    }
    $validSamples=@();$unknownSamples=0
    foreach($sample in $result.Data){
        $parsedProbeAddress=$null
        $sampleValid=$sample.Connected -is [bool] -and $sample.Address -is [string] -and [Net.IPAddress]::TryParse($sample.Address,[ref]$parsedProbeAddress)
        if($sampleValid){$validSamples+= $sample}else{$unknownSamples++}
        $networkRows.Add([pscustomobject]@{ProbeComputer=$ProbeComputerName;HostName=$endpointItem.HostName;Port=$endpointItem.Port;Source=$endpointItem.Source;ResolvedAddress=$(if($null -ne $parsedProbeAddress){[string]$parsedProbeAddress}else{$null});TcpConnected=$(if($sampleValid){$sample.Connected}else{$null});ElapsedMilliseconds=$(if($sample.ElapsedMilliseconds -is [int32] -or $sample.ElapsedMilliseconds -is [int64]){$sample.ElapsedMilliseconds}else{$null})})
    }
    if($result.Succeeded){
        if($unknownSamples){Add-VeeamFinding ('TcpEvidence:'+ $endpointItem.HostName+':'+$endpointItem.Port) Unknown 'A probe result lacked a Boolean connection observation or address; incomplete evidence was not interpreted as a connection failure.'}
        if(@($validSamples | Where-Object Connected -eq $true).Count){Add-VeeamFinding ('Tcp:'+ $endpointItem.HostName+':'+$endpointItem.Port) Pass 'At least one resolved address accepted a TCP connection from the selected probe host.'}
        elseif($validSamples.Count -and -not $unknownSamples){Add-VeeamFinding ('Tcp:'+ $endpointItem.HostName+':'+$endpointItem.Port) Fail 'No inspected address accepted TCP within the per-address timeout.'}
    }
}
Write-ReportCsv -Name 'endpoint-tests' -Rows $networkRows.ToArray() -Columns @('ProbeComputer','HostName','Port','Source','ResolvedAddress','TcpConnected','ElapsedMilliseconds')
Complete-Report -Data ([pscustomobject]@{Endpoints=$endpoints.Count;AddressSamples=$networkRows.Count;ProbeComputer=$ProbeComputerName;TcpTimeoutMilliseconds=$TimeoutMilliseconds;ConsoleAuthenticationSucceeded=$veeamContext.ConnectionSucceeded}) -Notes @(
    'Tests DNS and TCP from the selected Windows probe computer, then separately records the console connection performed by this script. A TCP listener is not proof of Veeam authentication, TLS trust, throughput, or data-path operation.'
    'Add explicit component, WAN, repository, SQL/PostgreSQL, or Microsoft 365 endpoints with Endpoint. Port requirements vary by role/build/configuration; no universal data-path port list is assumed.'
    'Up to eight DNS addresses per endpoint are tested. The timeout applies to each TCP connect, not DNS, WinRM, or Veeam provider calls. Remote probe hosts require Windows remoting and use HostCredential when provided.'
)

} finally {Close-OwnedVeeamConnection}