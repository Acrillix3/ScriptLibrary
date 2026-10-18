<#
What it does:
  Reports local active firewall profiles and selected rules with their port, address, application,
  and service filters.

Available flags:
  -DisplayName: Optional rule display-name wildcard; default all rules.
  -Direction: Inbound, Outbound, or Any; default Any.
  -Enabled: True, False, or Any; default True.
  -Action: Allow, Block, or Any; default Any.
  -MaxRules: Maximum selected rules to inspect, 1-10000; default 500.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Uses NetSecurity read commands against ActiveStore and records filter-query failures separately.
  Requires firewall management tools and sufficient local access; rule observations do not determine
  effective end-to-end reachability.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()][string]$DisplayName = '*',
    [ValidateSet('Inbound','Outbound','Any')][string]$Direction = 'Any',
    [ValidateSet('True','False','Any')][string]$Enabled = 'True',
    [ValidateSet('Allow','Block','Any')][string]$Action = 'Any',
    [ValidateRange(1,10000)][int]$MaxRules = 500,
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

$ruleRows=New-Object 'System.Collections.Generic.List[object]'
$filterRows=New-Object 'System.Collections.Generic.List[object]'
$findings=New-Object 'System.Collections.Generic.List[object]'
$requestedAction=$Action
$profiles=Invoke-ReportQuery 'ActiveStoreProfiles' {
    Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules,NotifyOnListen,LogAllowed,LogBlocked,LogFileName
} -RequireData
$connections=Invoke-ReportQuery 'CurrentNetworkProfiles' { Get-NetConnectionProfile -ErrorAction Stop | Select-Object InterfaceAlias,InterfaceIndex,NetworkCategory,IPv4Connectivity,IPv6Connectivity }
if($profiles.Succeeded){foreach($profile in @($profiles.Data)){if([string]$profile.Enabled -eq 'False'){$findings.Add([pscustomobject]@{Check='FirewallProfile';Result='Review';Target=$profile.Name;Detail='Firewall profile is configured disabled in ActiveStore; inspect whether it applies to current interfaces.'})}}}
$inventory=Invoke-ReportQuery 'SelectedActiveStoreRules' {
    $parameters=@{PolicyStore='ActiveStore';TracePolicyStore=$true;ErrorAction='Stop'}
    $rules=@(Get-NetFirewallRule @parameters | Where-Object {
        $_.DisplayName -like $DisplayName -and ($Direction -eq 'Any' -or [string]$_.Direction -eq $Direction) -and ($Enabled -eq 'Any' -or [string]$_.Enabled -eq $Enabled) -and ($requestedAction -eq 'Any' -or [string]$_.Action -eq $requestedAction)
    } | Sort-Object Name)
    [pscustomobject]@{TotalSelected=$rules.Count;Inspected=@($rules | Select-Object -First $MaxRules);Truncated=($rules.Count -gt $MaxRules)}
} -RequireData
$totalSelected=$null;$truncated=$false
if($inventory.Succeeded){
    $totalSelected=$inventory.Data[0].TotalSelected;$truncated=[bool]$inventory.Data[0].Truncated
    if($truncated){$findings.Add([pscustomobject]@{Check='RuleScope';Result='Truncated';Target='Selected rules';Detail=('Selected '+$totalSelected+' rules; inspected the first '+$MaxRules+' by name.')})}
    foreach($rule in @($inventory.Data[0].Inspected)){
        $ruleRows.Add([pscustomobject]@{Name=$rule.Name;DisplayName=$rule.DisplayName;Description=$rule.Description;Enabled=[string]$rule.Enabled;Direction=[string]$rule.Direction;Action=[string]$rule.Action;Profile=[string]$rule.Profile;PrimaryStatus=[string]$rule.PrimaryStatus;Status=$rule.Status;EnforcementStatus=(@($rule.EnforcementStatus) -join ';');PolicyStoreSource=$rule.PolicyStoreSource;PolicyStoreSourceType=[string]$rule.PolicyStoreSourceType})
        foreach($kind in @('Port','Address','Application','Service','Interface','InterfaceType','Security')){
            $filter=Invoke-ReportQuery ('RuleFilter:'+ $rule.Name+':'+$kind) {
                switch($kind){
                    'Port' {Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop | ForEach-Object {[pscustomobject]@{Protocol=$_.Protocol;LocalPort=(@($_.LocalPort)-join ';');RemotePort=(@($_.RemotePort)-join ';');IcmpType=(@($_.IcmpType)-join ';');DynamicTarget=$_.DynamicTarget}}}
                    'Address' {Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop | ForEach-Object {[pscustomobject]@{LocalAddress=(@($_.LocalAddress)-join ';');RemoteAddress=(@($_.RemoteAddress)-join ';')}}}
                    'Application' {Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop | Select-Object Program,Package}
                    'Service' {Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop | Select-Object Service}
                    'Interface' {Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop | ForEach-Object {[pscustomobject]@{InterfaceAlias=(@($_.InterfaceAlias)-join ';')}}}
                    'InterfaceType' {Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop | Select-Object InterfaceType}
                    'Security' {Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop | Select-Object Authentication,Encryption,OverrideBlockRules,LocalUser,RemoteUser,RemoteMachine}
                }
            } -RequireData
            if($filter.Succeeded){foreach($item in @($filter.Data)){$filterRows.Add([pscustomobject]@{RuleName=$rule.Name;FilterType=$kind;Status='Collected';Values=($item | ConvertTo-Json -Compress -Depth 5)})}}
            else{$filterRows.Add([pscustomobject]@{RuleName=$rule.Name;FilterType=$kind;Status='Unknown';Values=''})}
        }
    }
}
Write-ReportCsv 'firewall-profiles' @($profiles.Data) @('Name','Enabled','DefaultInboundAction','DefaultOutboundAction','AllowInboundRules','AllowLocalFirewallRules','AllowLocalIPsecRules','NotifyOnListen','LogAllowed','LogBlocked','LogFileName')
Write-ReportCsv 'network-profiles' @($connections.Data) @('InterfaceAlias','InterfaceIndex','NetworkCategory','IPv4Connectivity','IPv6Connectivity')
Write-ReportCsv 'rules' $ruleRows.ToArray() @('Name','DisplayName','Description','Enabled','Direction','Action','Profile','PrimaryStatus','Status','EnforcementStatus','PolicyStoreSource','PolicyStoreSourceType')
Write-ReportCsv 'rule-filters' $filterRows.ToArray() @('RuleName','FilterType','Status','Values')
Write-ReportCsv 'findings' $findings.ToArray() @('Check','Result','Target','Detail')
Complete-Report -Data ([pscustomobject]@{PolicyStore='ActiveStore';DisplayName=$DisplayName;Direction=$Direction;Enabled=$Enabled;Action=$Action;SelectedRuleCount=$totalSelected;InspectedRuleCount=$ruleRows.Count;Truncated=$truncated;Findings=$findings.ToArray()}) -Notes @(
    'ActiveStore combines applicable local and policy rule data. A listed or enabled rule is not proof it applies to a given packet; inspect profiles, filters, enforcement status, and policy sources.'
    'This report does not calculate final Windows Filtering Platform decisions, IPsec negotiation, service state, other security products, upstream firewalls, or end-to-end reachability.'
    'No matching rules means only the selected filters had no matches. Query failures remain Unknown; MaxRules truncation is explicit.'
    'Current network profiles and configured firewall profiles are separate observations. Some machines have several interface categories active at once.'
    'No rules, services, logging settings, or policy are changed.'
    'Reference: https://learn.microsoft.com/powershell/module/netsecurity/get-netfirewallrule'
)
