<#
What it does:
  Checks IP settings, gateways, DNS resolution, and TCP connectivity to selected targets.

Available flags:
  -Target <names/IPs>: Required; up to 10 targets.
  -Port <numbers>: Up to 10 TCP ports per target; default 443.
  -DnsServer <server>: Optional resolver for DNS tests only.
  -OutputDirectory <path>: Report destination; default Windows\Reports.

How it works:
  Reads adapter settings, probes gateways, resolves A/AAAA answers, and tests TCP ports. TCP uses
  normal system resolution; blocked ICMP does not prove an outage. Saves CSV/JSON reports without
  changing network settings.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateCount(1,10)][ValidateNotNullOrEmpty()][string[]]$Target,
    [ValidateCount(1,10)][ValidateRange(1,65535)][int[]]$Port = @(443),
    [ValidateNotNullOrEmpty()][string]$DnsServer,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$runName = '02-NetworkDiagnostics-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), ([guid]::NewGuid().ToString('N').Substring(0,8))
$report = (New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force).FullName
$queryErrors = New-Object 'System.Collections.Generic.List[object]'
function Export-NetworkCsv {
    param([object[]]$Rows, [string]$Name, [string]$Header)
    if (@($Rows).Count) { $Rows | Export-Csv -LiteralPath (Join-Path $report $Name) -NoTypeInformation -Encoding UTF8 }
    else { $Header | Set-Content -LiteralPath (Join-Path $report $Name) -Encoding UTF8 }
}
$adapters = @()
$gatewayAddresses = @()
try {
    $config = @(Get-NetIPConfiguration -Detailed -ErrorAction Stop)
    $adapters = @($config | ForEach-Object {
        [pscustomobject]@{
            InterfaceAlias=$_.InterfaceAlias; InterfaceIndex=$_.InterfaceIndex
            IPv4Address=($_.IPv4Address.IPAddress -join '; ')
            IPv6Address=($_.IPv6Address.IPAddress -join '; ')
            IPv4Gateway=($_.IPv4DefaultGateway.NextHop -join '; ')
            IPv6Gateway=($_.IPv6DefaultGateway.NextHop -join '; ')
            DnsServers=($_.DNSServer.ServerAddresses -join '; ')
        }
    })
    $gatewayAddresses = @($config | ForEach-Object { $_.IPv4DefaultGateway.NextHop; $_.IPv6DefaultGateway.NextHop } | Where-Object { $_ } | Sort-Object -Unique)
} catch { $queryErrors.Add([pscustomobject]@{Query='IP configuration'; Error=$_.Exception.Message}) }
$gateways = @(foreach ($gateway in $gatewayAddresses) {
    try {
        $reachable = Test-Connection -ComputerName $gateway -Count 2 -Quiet -ErrorAction Stop
        [pscustomobject]@{Gateway=$gateway; IcmpReachable=[bool]$reachable; Status='Tested'; Error=''}
    } catch {
        [pscustomobject]@{Gateway=$gateway; IcmpReachable=$null; Status='Unknown'; Error=$_.Exception.Message}
        $queryErrors.Add([pscustomobject]@{Query="Gateway $gateway"; Error=$_.Exception.Message})
    }
})
$dnsRows = New-Object 'System.Collections.Generic.List[object]'
$tcpRows = New-Object 'System.Collections.Generic.List[object]'
foreach ($targetName in ($Target | Sort-Object -Unique)) {
    $parsedAddress = $null
    if ([System.Net.IPAddress]::TryParse($targetName, [ref]$parsedAddress)) {
        $dnsRows.Add([pscustomobject]@{Target=$targetName; Name=$targetName; Type='LiteralIP'; Answer=$targetName; Status='NotNeeded'; Error=''})
    } else {
        try {
            $dnsParameters = @{Name=$targetName; Type='A_AAAA'; DnsOnly=$true; NoHostsFile=$true; ErrorAction='Stop'}
            if ($DnsServer) { $dnsParameters.Server = $DnsServer }
            $answers = @(Resolve-DnsName @dnsParameters)
            foreach ($answer in $answers) {
                $dnsRows.Add([pscustomobject]@{
                    Target=$targetName; Name=$answer.Name; Type=[string]$answer.Type
                    Answer=$(if ($answer.IPAddress) {$answer.IPAddress} elseif ($answer.NameHost) {$answer.NameHost} else {''})
                    Status=$(if ([string]$answer.Section -eq 'Answer' -and [string]$answer.Type -in @('A','AAAA') -and $answer.IPAddress) {'Resolved'} else {'SupportingRecord'}); Error=''
                })
            }
            $addressAnswers=@($answers | Where-Object { [string]$_.Section -eq 'Answer' -and [string]$_.Type -in @('A','AAAA') -and $_.IPAddress })
            if (!$addressAnswers.Count) {
                $dnsRows.Add([pscustomobject]@{Target=$targetName; Name=$targetName; Type='A_AAAA'; Answer=''; Status='NoRequestedAnswer'; Error='No answer-section A or AAAA record was returned.'})
                $queryErrors.Add([pscustomobject]@{Query="DNS $targetName"; Error='No answer-section A or AAAA record was returned.'})
            }
        } catch {
            $dnsRows.Add([pscustomobject]@{Target=$targetName; Name=''; Type=''; Answer=''; Status='Failed'; Error=$_.Exception.Message})
            $queryErrors.Add([pscustomobject]@{Query="DNS $targetName"; Error=$_.Exception.Message})
        }
    }
    foreach ($tcpPort in ($Port | Sort-Object -Unique)) {
        try {
            $test = Test-NetConnection -ComputerName $targetName -Port $tcpPort -InformationLevel Detailed -WarningAction SilentlyContinue -ErrorAction Stop
            $tcpRows.Add([pscustomobject]@{Target=$targetName; Port=$tcpPort; RemoteAddress=[string]$test.RemoteAddress; TcpSucceeded=$test.TcpTestSucceeded; Status='Tested'; Error=''})
        } catch {
            $tcpRows.Add([pscustomobject]@{Target=$targetName; Port=$tcpPort; RemoteAddress=''; TcpSucceeded=$null; Status='Unknown'; Error=$_.Exception.Message})
            $queryErrors.Add([pscustomobject]@{Query="TCP $targetName port $tcpPort"; Error=$_.Exception.Message})
        }
    }
}
Export-NetworkCsv -Rows $adapters -Name 'ip-configuration.csv' -Header '"InterfaceAlias","InterfaceIndex","IPv4Address","IPv6Address","IPv4Gateway","IPv6Gateway","DnsServers"'
Export-NetworkCsv -Rows @($gateways) -Name 'gateway-tests.csv' -Header '"Gateway","IcmpReachable","Status","Error"'
Export-NetworkCsv -Rows @($dnsRows.ToArray()) -Name 'dns-tests.csv' -Header '"Target","Name","Type","Answer","Status","Error"'
Export-NetworkCsv -Rows @($tcpRows.ToArray()) -Name 'tcp-tests.csv' -Header '"Target","Port","RemoteAddress","TcpSucceeded","Status","Error"'
Export-NetworkCsv -Rows @($queryErrors.ToArray()) -Name 'query-errors.csv' -Header '"Query","Error"'
$summary = [pscustomobject]@{
    Status=$(if ($queryErrors.Count) {'Partial'} else {'Complete'})
    ComputerName=$env:COMPUTERNAME; CollectedUtc=[datetime]::UtcNow.ToString('o')
    DnsTestServer=$(if ($DnsServer) {$DnsServer} else {'System default'})
    Targets=@($Target); Ports=@($Port); AdapterCount=$adapters.Count
    FailedTcpTests=@($tcpRows | Where-Object {$_.Status -eq 'Tested' -and !$_.TcpSucceeded}).Count
    QueryErrorCount=$queryErrors.Count; ReportDirectory=$report
    Notes='Complete describes collection, not network health. ICMP may be blocked. TCP uses normal system resolution even if DnsServer is supplied. IPv6 link-local gateways may require an interface scope.'
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
if ($queryErrors.Count) { Write-Warning 'Some tests failed or could not run; see the detailed reports.' }
$summary

