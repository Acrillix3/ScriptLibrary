<#
What it does:
  Reports local RDP settings, services, listeners, firewall candidates, certificates, and optional
  session or remote-port evidence.

Available flags:
  -RemoteTarget: Optional remote hostname or IP for a TCP test from this computer.
  -RemotePort: Port for the optional remote test, 1-65535; default 3389.
  -IncludeSessions: Capture local session-list output; it can include usernames.
  -MaxFirewallRules: Enabled inbound rules to inspect, 1-10000; default 500.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Reads local CIM, registry, TCP listeners, and certificate metadata with sufficient local access.
  RemoteTarget tests a remote TCP port only; local evidence does not describe that remote host, and
  a TCP response does not prove an RDP sign-in works.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()][string]$RemoteTarget,
    [ValidateRange(1,65535)][int]$RemotePort = 3389,
    [switch]$IncludeSessions,
    [ValidateRange(1,10000)][int]$MaxFirewallRules = 500,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) {
    $OutputDirectory = Join-Path $PSScriptRoot '..\Reports'
}
$scriptLabel = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runName = '{0}-{1}-{2}' -f $scriptLabel,[datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),[guid]::NewGuid().ToString('N').Substring(0,8)
$reportDirectory = (New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force -ErrorAction Stop).FullName
$queryLog = New-Object 'System.Collections.Generic.List[object]'
$queryErrors = New-Object 'System.Collections.Generic.List[object]'
function Invoke-ReportQuery {
    param([string]$Section,[scriptblock]$Action,[switch]$RequireData)
    try {
        $items = @(& $Action)
        if ($RequireData -and $items.Count -eq 0) { throw 'Required data was not returned.' }
        $queryLog.Add([pscustomobject]@{Section=$Section;Status=$(if($items.Count){'Collected'}else{'Empty'});Count=$items.Count;Error=''})
        [pscustomobject]@{Succeeded=$true;Data=$items}
    } catch {
        $queryErrors.Add([pscustomobject]@{Section=$Section;Error=$_.Exception.Message;ErrorId=$_.FullyQualifiedErrorId})
        $queryLog.Add([pscustomobject]@{Section=$Section;Status='Unknown';Count=$null;Error=$_.Exception.Message})
        [pscustomobject]@{Succeeded=$false;Data=@()}
    }
}
function Write-ReportCsv {
    param([string]$Name,[object[]]$Rows,[string[]]$Columns)
    $path=Join-Path $reportDirectory ($Name+'.csv')
    if (@($Rows).Count) {
        $Rows | Select-Object -Property $Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    } else {
        (($Columns | ForEach-Object { '"'+$_.Replace('"','""')+'"' }) -join ',') | Set-Content -LiteralPath $path -Encoding UTF8
    }
}
function Complete-Report {
    param([object]$Data,[string[]]$Notes)
    Write-ReportCsv -Name 'collection-status' -Rows $queryLog.ToArray() -Columns @('Section','Status','Count','Error')
    Write-ReportCsv -Name 'query-errors' -Rows $queryErrors.ToArray() -Columns @('Section','Error','ErrorId')
    $status='Complete'
    if($queryErrors.Count){$status='Partial'}
    if($queryErrors.Count -and @($queryLog | Where-Object Status -ne 'Unknown').Count -eq 0){$status='Unavailable'}
    $summary=[pscustomobject]@{
        Script=$scriptLabel;ComputerName=$env:COMPUTERNAME;CollectedUtc=[datetime]::UtcNow.ToString('o')
        CollectionStatus=$status;QueryErrorCount=$queryErrors.Count;ReportDirectory=$reportDirectory
        Data=$Data;Sections=$queryLog.ToArray();Notes=@('Collection status describes available evidence, not overall system health.')+$Notes
    }
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $reportDirectory 'summary.json') -Encoding UTF8
    @(
        $scriptLabel
        ('Collection: {0}; query errors: {1}' -f $status,$queryErrors.Count)
        ('Reports: '+$reportDirectory)
        ''
        'Collection results:'
        ($queryLog | Format-Table Section,Status,Count -AutoSize | Out-String -Width 180)
        'Interpretation:'
        ($summary.Notes -join [Environment]::NewLine)
    ) | Set-Content -LiteralPath (Join-Path $reportDirectory 'overview.txt') -Encoding UTF8
    if($queryErrors.Count){Write-Warning 'Some data was unavailable; review query-errors.csv and collection-status.csv.'}
    $summary
}

$findings=New-Object 'System.Collections.Generic.List[object]'
$settings=New-Object 'System.Collections.Generic.List[object]'
$certRows=New-Object 'System.Collections.Generic.List[object]'
$os = Invoke-ReportQuery 'LocalOperatingSystem' {
    $item=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $item.ProductType -or $null -eq $item.OperatingSystemSKU) { throw 'Operating-system role or SKU was not returned.' }
    $assessment='UnknownEditionReviewRequired'
    if ([int]$item.ProductType -in 2,3) { $assessment='ServerRdpCapable' }
    elseif ([int]$item.ProductType -eq 1) {
        if ([int]$item.OperatingSystemSKU -in 2,3,5,11,26,47,98,99,100,101) { $assessment='ClientEditionDoesNotHostRdp' }
        elseif ([int]$item.OperatingSystemSKU -in 4,27,48,49,70,72,121,122,125,126,161,162) { $assessment='ClientEditionRdpCapable' }
    }
    [pscustomobject]@{Scope='Local';Caption=$item.Caption;ProductType=$item.ProductType;OperatingSystemSKU=$item.OperatingSystemSKU;EditionAssessment=$assessment}
} -RequireData
if ($os.Succeeded) { $findings.Add([pscustomobject]@{Scope='Local';Check='Edition';Result=$os.Data[0].EditionAssessment;Detail='RDP host capability only; RDS role, licensing, user rights, and deployment readiness are not established.'}) }
function Read-RdpSetting {
    param([string]$Label,[string]$Path,[switch]$Optional)
    Invoke-ReportQuery $Label {
        if ($Optional -and -not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return [pscustomobject]@{Scope='Local';Source=$Label;RegistryPath=$Path;Present=$false;fDenyTSConnections=$null;PortNumber=$null;UserAuthentication=$null;SecurityLayer=$null;MinEncryptionLevel=$null} }
        $item=Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        [pscustomobject]@{Scope='Local';Source=$Label;RegistryPath=$Path;Present=$true;fDenyTSConnections=$item.fDenyTSConnections;PortNumber=$item.PortNumber;UserAuthentication=$item.UserAuthentication;SecurityLayer=$item.SecurityLayer;MinEncryptionLevel=$item.MinEncryptionLevel}
    } -RequireData
}
$localSetting=Read-RdpSetting 'LocalRdpSetting' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$policySetting=Read-RdpSetting 'LocalRdpPolicy' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Optional
$listenerSetting=Read-RdpSetting 'LocalRdpListenerSetting' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
foreach($result in @($localSetting,$policySetting,$listenerSetting)){foreach($row in @($result.Data)){$settings.Add($row)}}
$deny=$null; $source='Unknown'
if($policySetting.Succeeded -and $policySetting.Data[0].Present -and $null -ne $policySetting.Data[0].fDenyTSConnections){$deny=$policySetting.Data[0].fDenyTSConnections;$source='PolicyRegistry'}
elseif($policySetting.Succeeded -and $localSetting.Succeeded -and $null -ne $localSetting.Data[0].fDenyTSConnections){$deny=$localSetting.Data[0].fDenyTSConnections;$source='LocalRegistry'}
$settingResult='Unknown';if($null -ne $deny){if([int]$deny -eq 0){$settingResult='ConfiguredToAllow'}elseif([int]$deny -eq 1){$settingResult='ConfiguredToDeny'}}
$findings.Add([pscustomobject]@{Scope='Local';Check='RdpConnections';Result=$settingResult;Detail=('Observed source='+$source+'; registry observation is not full policy or user-rights evaluation.')})
$services=Invoke-ReportQuery 'LocalRdpServices' {
    $items=@(Get-CimInstance -ClassName Win32_Service -Filter "Name='TermService' OR Name='UmRdpService' OR Name='SessionEnv'" -ErrorAction Stop)
    if(-not @($items | Where-Object Name -eq 'TermService').Count){throw 'The TermService service was not returned.'}
    $items | Select-Object Name,State,StartMode,ProcessId
} -RequireData
if($services.Succeeded){foreach($item in @($services.Data)){if($item.State -ne 'Running'){$findings.Add([pscustomobject]@{Scope='Local';Check=$item.Name;Result='Review';Detail=('Observed state='+$item.State+'; trigger-start or disabled-RDP configurations can explain stopped services.')})}}}
$localPort=$null
if($listenerSetting.Succeeded -and $null -ne $listenerSetting.Data[0].PortNumber -and [int]$listenerSetting.Data[0].PortNumber -ge 1 -and [int]$listenerSetting.Data[0].PortNumber -le 65535){$localPort=[int]$listenerSetting.Data[0].PortNumber}
$listenerRows=@()
if($null -ne $localPort){
    $listeners=Invoke-ReportQuery 'LocalTcpListeners' { Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object LocalPort -eq $localPort | Select-Object LocalAddress,LocalPort,State,OwningProcess }
    $listenerRows=@($listeners.Data)
    $listenerFinding='Unknown';if($listeners.Succeeded){$listenerFinding=if($listenerRows.Count){'TcpListenerObserved'}else{'NoTcpListenerObserved'}}
    $findings.Add([pscustomobject]@{Scope='Local';Check='ConfiguredTcpPort';Result=$listenerFinding;Detail=('Port='+$localPort+'; TCP listener ownership and RDP protocol readiness require review.')})
}else{$queryLog.Add([pscustomobject]@{Section='LocalTcpListeners';Status='Skipped';Count=0;Error='Configured local RDP port is unknown; no default port was assumed.'});$findings.Add([pscustomobject]@{Scope='Local';Check='ConfiguredTcpPort';Result='Unknown';Detail='Listener configuration did not supply a valid TCP port.'})}
$firewallScanRows=New-Object 'System.Collections.Generic.List[object]'
$firewallCandidates=New-Object 'System.Collections.Generic.List[object]'
$firewallTruncated=$false
$firewallInventory=Invoke-ReportQuery 'LocalInboundFirewallRuleScope' {
    $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -Enabled True -Direction Inbound -ErrorAction Stop | Select-Object -First ($MaxFirewallRules+1))
    [pscustomobject]@{Rules=@($rules | Select-Object -First $MaxFirewallRules);Truncated=($rules.Count -gt $MaxFirewallRules)}
} -RequireData
function Test-RdpPortCandidate {
    param([object[]]$Ports,[int]$ConfiguredPort)
    foreach($portValue in $Ports){
        foreach($part in ([string]$portValue -split ',')){
            $part=$part.Trim()
            if($part -eq 'Any' -or $part -eq [string]$ConfiguredPort){return $true}
            if($part -match '^(\d+)-(\d+)$' -and $ConfiguredPort -ge [int]$Matches[1] -and $ConfiguredPort -le [int]$Matches[2]){return $true}
        }
    }
    $false
}
if($firewallInventory.Succeeded){
    $firewallTruncated=[bool]$firewallInventory.Data[0].Truncated
    if($firewallTruncated){$queryLog.Add([pscustomobject]@{Section='LocalFirewallRuleScope';Status='Truncated';Count=$MaxFirewallRules;Error='Additional enabled inbound rules exist; candidate discovery is incomplete.'})}
    foreach($rule in @($firewallInventory.Data[0].Rules)){
        $portFilter=Invoke-ReportQuery ('LocalFirewallPort:'+ $rule.Name) { Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } -RequireData
        $serviceFilter=Invoke-ReportQuery ('LocalFirewallService:'+ $rule.Name) { Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } -RequireData
        $serviceMatches=$false;$portMatches=$false
        if($serviceFilter.Succeeded){$serviceMatches=@($serviceFilter.Data | Where-Object Service -eq 'TermService').Count -gt 0}
        if($portFilter.Succeeded -and $null -ne $localPort){
            foreach($filter in @($portFilter.Data)){
                if([string]$filter.Protocol -in 'TCP','UDP','6','17','Any','256' -and (Test-RdpPortCandidate @($filter.LocalPort) $localPort)){$portMatches=$true}
            }
        }
        $candidateResult='NotMatchedInInspectedFilters'
        if($serviceMatches -or $portMatches){$candidateResult='Candidate'}
        elseif(-not $portFilter.Succeeded -or -not $serviceFilter.Succeeded -or $null -eq $localPort){$candidateResult='Unknown'}
        $firewallScanRows.Add([pscustomobject]@{Scope='Local';RuleName=$rule.Name;DisplayName=$rule.DisplayName;CandidateAssessment=$candidateResult;ConfiguredPort=$localPort;PortMatch=$portMatches;TermServiceMatch=$serviceMatches;PortFilterStatus=$(if($portFilter.Succeeded){'Collected'}else{'Unknown'});ServiceFilterStatus=$(if($serviceFilter.Succeeded){'Collected'}else{'Unknown'})})
        if($candidateResult -eq 'Candidate'){
            $addressFilter=Invoke-ReportQuery ('LocalFirewallAddress:'+ $rule.Name) { Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } -RequireData
            $applicationFilter=Invoke-ReportQuery ('LocalFirewallApplication:'+ $rule.Name) { Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } -RequireData
            $firewallCandidates.Add([pscustomobject]@{Scope='LocalCandidateOnly';RuleName=$rule.Name;DisplayName=$rule.DisplayName;Enabled=[string]$rule.Enabled;Direction=[string]$rule.Direction;Action=[string]$rule.Action;Profile=[string]$rule.Profile;EnforcementStatus=(@($rule.EnforcementStatus)-join ';');PolicyStoreSource=$rule.PolicyStoreSource;PortMatch=$portMatches;TermServiceMatch=$serviceMatches;PortFilterStatus=$(if($portFilter.Succeeded){'Collected'}else{'Unknown'});PortFilters=($portFilter.Data | ConvertTo-Json -Compress -Depth 4);ServiceFilterStatus=$(if($serviceFilter.Succeeded){'Collected'}else{'Unknown'});ServiceFilters=($serviceFilter.Data | ConvertTo-Json -Compress -Depth 4);AddressFilterStatus=$(if($addressFilter.Succeeded){'Collected'}else{'Unknown'});AddressFilters=($addressFilter.Data | ConvertTo-Json -Compress -Depth 4);ApplicationFilterStatus=$(if($applicationFilter.Succeeded){'Collected'}else{'Unknown'});ApplicationFilters=($applicationFilter.Data | ConvertTo-Json -Compress -Depth 4)})
        }
    }
}
$binding=Invoke-ReportQuery 'LocalRdpCertificateBinding' { Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'" -ErrorAction Stop | Select-Object TerminalName,SSLCertificateSHA1Hash,SSLCertificateSHA1HashType,UserAuthenticationRequired,SecurityLayer } -RequireData
foreach($store in @('Cert:\LocalMachine\My','Cert:\LocalMachine\Remote Desktop')){
    $certificates=Invoke-ReportQuery ('LocalCertificateStore:'+ $store) { Get-ChildItem -LiteralPath $store -ErrorAction Stop }
    foreach($cert in @($certificates.Data)){
        $hashes=@($binding.Data | ForEach-Object {([string]$_.SSLCertificateSHA1Hash -replace '\s','').ToUpperInvariant()})
        $isBound=([string]$cert.Thumbprint).ToUpperInvariant() -in $hashes
        if($isBound -or $store -eq 'Cert:\LocalMachine\Remote Desktop'){
            $expiry='ValidDates';if($cert.NotAfter -lt (Get-Date)){$expiry='Expired'}elseif($cert.NotBefore -gt (Get-Date)){$expiry='NotYetValid'}
            $certRows.Add([pscustomobject]@{Scope='Local';Store=$store;Subject=$cert.Subject;Issuer=$cert.Issuer;Thumbprint=$cert.Thumbprint;NotBefore=$cert.NotBefore;NotAfter=$cert.NotAfter;Validity=$expiry;MatchesObservedBinding=$isBound;HasPrivateKeyAssociation=$cert.HasPrivateKey;KeyAccessibility='NotTested'})
        }
    }
}
if($binding.Succeeded -and $binding.Data[0].SSLCertificateSHA1Hash -and -not @($certRows | Where-Object MatchesObservedBinding).Count){$findings.Add([pscustomobject]@{Scope='Local';Check='CertificateBinding';Result='Review';Detail='The observed binding hash was not found in readable selected stores; inaccessible stores or another certificate location may explain the gap.'})}
if($IncludeSessions){
    $sessions=Invoke-ReportQuery 'LocalSessionListing' {
        $command=Get-Command -Name qwinsta.exe -CommandType Application -ErrorAction Stop
        $global:LASTEXITCODE=$null;$savedPreference=$ErrorActionPreference
        try{$ErrorActionPreference='Continue';$raw=@(& $command.Source 2>&1 | ForEach-Object {$_.ToString()});$code=$LASTEXITCODE}finally{$ErrorActionPreference=$savedPreference}
        ($raw -join [Environment]::NewLine) | Set-Content -LiteralPath (Join-Path $reportDirectory 'local-sessions.txt') -Encoding UTF8
        [pscustomobject]@{Scope='Local';ExitCode=$code;RawFile='local-sessions.txt'} | Export-Csv -LiteralPath (Join-Path $reportDirectory 'session-command.csv') -NoTypeInformation -Encoding UTF8
        if($null -eq $code -or $code -ne 0){throw ('Session command failed; exit='+$code+'; raw output retained.')}
        if(-not $raw.Count){throw 'Session command returned no output.'}
        [pscustomobject]@{Scope='Local';RawFile='local-sessions.txt';ExitCode=$code}
    } -RequireData
}else{$queryLog.Add([pscustomobject]@{Section='LocalSessionListing';Status='Skipped';Count=0;Error='IncludeSessions was not specified.'})}
$remoteRows=@()
if($RemoteTarget){
    $remote=Invoke-ReportQuery 'RemoteTcpTestFromThisComputer' {
        $test=Test-NetConnection -ComputerName $RemoteTarget -Port $RemotePort -InformationLevel Detailed -WarningAction SilentlyContinue -ErrorAction Stop
        if($null -eq $test.TcpTestSucceeded){throw 'TCP test returned no success observation.'}
        [pscustomobject]@{Scope='RemoteTcpOnly';Target=$RemoteTarget;Port=$RemotePort;RemoteAddress=[string]$test.RemoteAddress;TcpSucceeded=[bool]$test.TcpTestSucceeded}
    } -RequireData
    $remoteRows=@($remote.Data)
}else{$queryLog.Add([pscustomobject]@{Section='RemoteTcpTestFromThisComputer';Status='Skipped';Count=0;Error='RemoteTarget was not specified.'})}
Write-ReportCsv 'operating-system' @($os.Data) @('Scope','Caption','ProductType','OperatingSystemSKU','EditionAssessment')
Write-ReportCsv 'rdp-settings' $settings.ToArray() @('Scope','Source','RegistryPath','Present','fDenyTSConnections','PortNumber','UserAuthentication','SecurityLayer','MinEncryptionLevel')
Write-ReportCsv 'rdp-services' @($services.Data) @('Name','State','StartMode','ProcessId')
Write-ReportCsv 'tcp-listeners' $listenerRows @('LocalAddress','LocalPort','State','OwningProcess')
Write-ReportCsv 'firewall-rule-scan' $firewallScanRows.ToArray() @('Scope','RuleName','DisplayName','CandidateAssessment','ConfiguredPort','PortMatch','TermServiceMatch','PortFilterStatus','ServiceFilterStatus')
Write-ReportCsv 'rdp-firewall-candidates' $firewallCandidates.ToArray() @('Scope','RuleName','DisplayName','Enabled','Direction','Action','Profile','EnforcementStatus','PolicyStoreSource','PortMatch','TermServiceMatch','PortFilterStatus','PortFilters','ServiceFilterStatus','ServiceFilters','AddressFilterStatus','AddressFilters','ApplicationFilterStatus','ApplicationFilters')
Write-ReportCsv 'certificate-binding' @($binding.Data) @('TerminalName','SSLCertificateSHA1Hash','SSLCertificateSHA1HashType','UserAuthenticationRequired','SecurityLayer')
Write-ReportCsv 'certificate-metadata' $certRows.ToArray() @('Scope','Store','Subject','Issuer','Thumbprint','NotBefore','NotAfter','Validity','MatchesObservedBinding','HasPrivateKeyAssociation','KeyAccessibility')
Write-ReportCsv 'remote-tcp-test' $remoteRows @('Scope','Target','Port','RemoteAddress','TcpSucceeded')
Write-ReportCsv 'findings' $findings.ToArray() @('Scope','Check','Result','Detail')
Complete-Report -Data ([pscustomobject]@{LocalComputer=$env:COMPUTERNAME;LocalConfiguredPort=$localPort;MaxFirewallRules=$MaxFirewallRules;FirewallRulesInspected=$firewallScanRows.Count;FirewallRuleScanTruncated=$firewallTruncated;FirewallCandidateCount=$firewallCandidates.Count;Findings=$findings.ToArray();RemoteTcpEvidence=$remoteRows}) -Notes @(
    'All OS, registry, service, listener, certificate, and session observations are local. RemoteTarget adds only a TCP test from this computer; it does not collect remote configuration.'
    'TCP reachability does not establish RDP protocol health, TLS identity/trust, authentication, licensing, user rights, gateway routing, or end-to-end access.'
    'Firewall inspection examines at most MaxFirewallRules enabled inbound ActiveStore rules in provider order. Candidates match TermService or the configured TCP/UDP port, including broad Any/range rules; truncated scans can omit relevant rules.'
    'Firewall candidates and filters are evidence for review, not a computed effective allow/block verdict. Other filters, policy precedence, interface profiles, IPsec, and other firewalls can change actual access. No localized display-group name is assumed.'
    'Certificate records contain metadata only; private-key accessibility and the RDP service account ability to use a key are not tested. Binding visibility can require elevation.'
    'Optional session text is localized and contains account/session information; it is not parsed as a health verdict. No sessions are disconnected.'
    'Reference: https://learn.microsoft.com/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting'
    'Reference: https://learn.microsoft.com/troubleshoot/windows-server/remote/remote-desktop-listener-certificate-configurations'
)
