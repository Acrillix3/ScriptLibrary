<#
What it does:
  Tests DNS and TCP reachability from a chosen Windows host and records Veeam console authentication.

Available flags:
  -Product: Private VBR/VBO profile supplied by the public entrypoint.
  -EntryPointName: Private report identity supplied by the public entrypoint.
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9392.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -Endpoint: Additional hostname:port or [IPv6]:port targets; default none.
  -ProbeComputerName: Windows source for network tests; default localhost.
  -TimeoutMilliseconds: TCP timeout per address, 100-60000; default 3000.

How it works:
  Private shared implementation; invoke a public product entrypoint instead. Reports retain its name.
  Resolves explicit endpoints and attempts bounded TCP connections locally or through WinRM. Reports only the tested path; TCP success is separate from Veeam authentication and data-path health.
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
    [ValidateCount(0,100)][string[]]$Endpoint=@(),
    [string]$ProbeComputerName='localhost',
    [ValidateRange(100,60000)][int]$TimeoutMilliseconds=3000
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