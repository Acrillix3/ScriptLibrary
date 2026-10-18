<#
What it does:
  Checks local domain membership, locator DNS records, and a member computer's secure channel.

Available flags:
  -Server: Optional domain controller for the member-computer channel test.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Reads the computer role first, then uses CIM, Resolve-DnsName, and a read-only channel test. Run
  with local administrative access; domain controllers skip the member-only test, and DNS answers
  alone do not verify trust.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()][string]$Server,
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

$findings = New-Object 'System.Collections.Generic.List[object]'
$computerRows = @(); $locatorRows = @(); $serviceRows = @(); $channelRows = @()
$membership = Invoke-ReportQuery 'ComputerRoleAndMembership' {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($null -eq $computer -or $null -eq $computer.DomainRole -or $null -eq $computer.PartOfDomain) { throw 'Computer role or membership was not returned.' }
    if ([int]$computer.DomainRole -notin 0,1,2,3,4,5) { throw 'Unrecognized computer domain role.' }
    [pscustomobject]@{Name=$computer.Name;Domain=$computer.Domain;PartOfDomain=[bool]$computer.PartOfDomain;DomainRole=[int]$computer.DomainRole}
} -RequireData
if ($membership.Succeeded) {
    $computerRows = @($membership.Data)
    $computer = $computerRows[0]
    $isController = $computer.DomainRole -in 4,5
    $isMember = $computer.PartOfDomain -and $computer.DomainRole -in 1,3
    $membershipResult = 'Workgroup'
    if ($isController) { $membershipResult = 'DomainController' } elseif ($isMember) { $membershipResult = 'DomainMember' }
    $findings.Add([pscustomobject]@{Check='Membership';Result=$membershipResult;Detail=('Domain={0}; role={1}' -f $computer.Domain,$computer.DomainRole)})
    if ($computer.PartOfDomain -and $computer.Domain) {
        $locator = Invoke-ReportQuery 'DomainLocatorDns' {
            $answers = @(Resolve-DnsName -Name ('_ldap._tcp.dc._msdcs.'+$computer.Domain) -Type SRV -DnsOnly -NoHostsFile -ErrorAction Stop)
            $srv = @($answers | Where-Object { [string]$_.Type -eq 'SRV' -and $_.NameTarget })
            if (-not $srv.Count) { throw 'No domain-controller locator SRV answer was returned.' }
            $srv | ForEach-Object { [pscustomobject]@{Query=('_ldap._tcp.dc._msdcs.'+$computer.Domain);Target=$_.NameTarget;Port=$_.Port;Priority=$_.Priority;Weight=$_.Weight} }
        } -RequireData
        $locatorRows = @($locator.Data)
    } else { $queryLog.Add([pscustomobject]@{Section='DomainLocatorDns';Status='Skipped';Count=0;Error='Computer is not joined to a known AD domain.'}) }
    $netlogon = Invoke-ReportQuery 'NetlogonService' {
        Get-CimInstance -ClassName Win32_Service -Filter "Name='Netlogon'" -ErrorAction Stop | Select-Object Name,State,StartMode
    } -RequireData
    $serviceRows = @($netlogon.Data)
    if ($isMember) {
        $channel = Invoke-ReportQuery 'MemberSecureChannel' {
            $parameters = @{ErrorAction='Stop'}
            if ($Server) { $parameters.Server = $Server }
            $result = @(Test-ComputerSecureChannel @parameters)
            if ($result.Count -ne 1 -or $result[0] -isnot [bool]) { throw 'The channel test did not return one Boolean result.' }
            [pscustomobject]@{Server=$(if($Server){$Server}else{'Automatically selected'});Result=$(if($result[0]){'Passed'}else{'Failed'});SecureChannelWorking=[bool]$result[0]}
        } -RequireData
        $channelRows = @($channel.Data)
        if ($channel.Succeeded) { $findings.Add([pscustomobject]@{Check='MemberSecureChannel';Result=$channelRows[0].Result;Detail='Observed local member-computer secure channel; no repair was attempted.'}) }
        else { $findings.Add([pscustomobject]@{Check='MemberSecureChannel';Result='Unknown';Detail='The test could not complete; review collection errors.'}) }
    } else {
        $reason = 'Not a domain member workstation or server.'
        if ($isController) { $reason = 'Domain controller: Test-ComputerSecureChannel is unsupported and can report false errors.' }
        $queryLog.Add([pscustomobject]@{Section='MemberSecureChannel';Status='Skipped';Count=0;Error=$reason})
        $findings.Add([pscustomobject]@{Check='MemberSecureChannel';Result='NotApplicable';Detail=$reason})
    }
} else {
    $queryLog.Add([pscustomobject]@{Section='MemberSecureChannel';Status='Skipped';Count=0;Error='Role is unknown; no channel test was attempted.'})
    $findings.Add([pscustomobject]@{Check='Membership';Result='Unknown';Detail='Computer role and membership could not be read.'})
}
Write-ReportCsv 'computer-membership' $computerRows @('Name','Domain','PartOfDomain','DomainRole')
Write-ReportCsv 'domain-locator-dns' $locatorRows @('Query','Target','Port','Priority','Weight')
Write-ReportCsv 'netlogon-service' $serviceRows @('Name','State','StartMode')
Write-ReportCsv 'secure-channel' $channelRows @('Server','Result','SecureChannelWorking')
Write-ReportCsv 'findings' $findings.ToArray() @('Check','Result','Detail')
Complete-Report -Data ([pscustomobject]@{Findings=$findings.ToArray();ChannelTest=$channelRows;Computer=$computerRows}) -Notes @(
    'This local-computer check does not audit inter-domain trusts or validate a domain controller secure channel.'
    'DNS locator SRV records do not prove a DC is reachable, authenticating users, or healthy. No AD module is required.'
    'The read-only channel test needs sufficient local access, normally an elevated Windows PowerShell session. Denied or failed collection remains Unknown.'
    'Reference: https://learn.microsoft.com/powershell/module/microsoft.powershell.management/test-computersecurechannel'
)
