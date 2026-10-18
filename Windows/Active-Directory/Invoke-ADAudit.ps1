<#
What it does:
  Audits AD domain details, domain controllers, replication, password policies, privileged groups,
  and stale accounts.

Available flags:
  -OutputDirectory: Report destination; defaults to Windows\Reports.
  -Server: Domain controller or AD domain; defaults to your authenticated domain.
  -SearchBase: Optional distinguished name limiting stale-account and user-count searches only.
  -StaleDays: Stale-account age threshold, 1-36500 days; default 90.

How it works:
  Uses the ActiveDirectory module and your directory read permissions to export evidence, findings,
  and collection errors without changing AD. SearchBase does not restrict domain, forest,
  replication, policy, or privileged-group queries; stale logon dates are investigation candidates,
  and completed collection does not establish security health.
#>
#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()][string]$OutputDirectory,
    [string]$Server,
    [string]$SearchBase,
    [ValidateRange(1, 36500)][int]$StaleDays = 90
)

$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$started = Get-Date
$cutoff = $started.ToUniversalTime().AddDays(-$StaleDays)
$reportPath = Join-Path $OutputDirectory ('ADAudit_{0}_{1}' -f $started.ToString('yyyyMMdd_HHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $reportPath -Force
$reportPath = (Resolve-Path -LiteralPath $reportPath).Path
$queryStatus = New-Object 'System.Collections.Generic.List[object]'
$queryErrors = New-Object 'System.Collections.Generic.List[object]'
$findings = New-Object 'System.Collections.Generic.List[object]'
$tables = [ordered]@{}
$schemas = [ordered]@{
    Domain = @('DNSRoot','NetBIOSName','DistinguishedName','DomainSID','DomainMode','PDCEmulator','RIDMaster','InfrastructureMaster','LogonTimeSyncIntervalDays')
    Forest = @('Name','RootDomain','ForestMode','Domains','Sites','GlobalCatalogs','SchemaMaster','DomainNamingMaster')
    DomainControllers = @('HostName','Site','IPv4Address','IPv6Address','OperatingSystem','IsGlobalCatalog','IsReadOnly','Enabled','OperationMasterRoles')
    FSMOHolders = @('Role','Holder','Scope')
    ReplicationFailures = @('QueriedDC','Server','Partner','FailureType','FirstFailureTime','FailureCount','LastError')
    ReplicationPartners = @('QueriedDC','Server','Partner','Partition','PartnerType','LastReplicationAttempt','LastReplicationSuccess','LastReplicationResult','ConsecutiveReplicationFailures')
    PasswordPolicy = @('PolicyType','Name','DistinguishedName','Precedence','MinPasswordLength','PasswordHistoryCount','ComplexityEnabled','ReversibleEncryptionEnabled','MinPasswordAge','MaxPasswordAge','LockoutThreshold','LockoutDuration','LockoutObservationWindow','AppliesTo')
    FineGrainedPasswordPolicies = @('PolicyType','Name','DistinguishedName','Precedence','MinPasswordLength','PasswordHistoryCount','ComplexityEnabled','ReversibleEncryptionEnabled','MinPasswordAge','MaxPasswordAge','LockoutThreshold','LockoutDuration','LockoutObservationWindow','AppliesTo')
    StaleUsers = @('SamAccountName','Name','DistinguishedName','Enabled','WhenCreated','LastLogonDate','TimestampEvidence','PasswordLastSet')
    StaleComputers = @('SamAccountName','Name','DistinguishedName','Enabled','WhenCreated','LastLogonDate','TimestampEvidence','OperatingSystem')
    AccountCounts = @('Metric','Count','Scope','Status')
    PrivilegedMembers = @('PrivilegeLabel','GroupName','GroupSID','QueryServer','MembershipType','MemberName','SamAccountName','ObjectClass','SID','DistinguishedName')
}
foreach ($tableName in $schemas.Keys) { $tables[$tableName] = New-Object 'System.Collections.Generic.List[object]' }

function Invoke-AuditQuery {
    param([string]$Name, [string]$Target, [scriptblock]$Action, [switch]$RequireResult)
    try {
        $items = @(& $Action)
        if ($RequireResult -and $items.Count -eq 0) { throw 'The query returned no required objects; collection coverage is unknown.' }
        $null = $queryStatus.Add([pscustomobject]@{ Query=$Name; Target=$Target; Status='COMPLETED'; RecordCount=$items.Count; Detail='' })
        return [pscustomobject]@{ Succeeded=$true; Items=$items }
    } catch {
        $message = $_.Exception.Message
        $null = $queryErrors.Add([pscustomobject]@{ Query=$Name; Target=$Target; TimestampUtc=(Get-Date).ToUniversalTime().ToString('o'); ErrorType=$_.Exception.GetType().FullName; Message=$message })
        $null = $queryStatus.Add([pscustomobject]@{ Query=$Name; Target=$Target; Status='UNKNOWN'; RecordCount=$null; Detail=$message })
        return [pscustomobject]@{ Succeeded=$false; Items=@() }
    }
}

function Add-Finding {
    param([string]$Category,[string]$Severity,[string]$Subject,[string]$Evidence,[string]$Review)
    $null = $findings.Add([pscustomobject]@{ Category=$Category; Severity=$Severity; Subject=$Subject; Evidence=$Evidence; Review=$Review })
}

function Format-AuditDate {
    param($Value)
    if ($null -eq $Value) { return '' }
    return ([datetime]$Value).ToUniversalTime().ToString('o')
}

function Add-PolicyRow {
    param($Policy,[string]$Type,[string]$TableName)
    $null = $tables[$TableName].Add([pscustomobject]@{
        PolicyType=$Type; Name=$Policy.Name; DistinguishedName=$Policy.DistinguishedName; Precedence=$Policy.Precedence
        MinPasswordLength=$Policy.MinPasswordLength; PasswordHistoryCount=$Policy.PasswordHistoryCount
        ComplexityEnabled=$Policy.ComplexityEnabled; ReversibleEncryptionEnabled=$Policy.ReversibleEncryptionEnabled
        MinPasswordAge=[string]$Policy.MinPasswordAge; MaxPasswordAge=[string]$Policy.MaxPasswordAge
        LockoutThreshold=$Policy.LockoutThreshold; LockoutDuration=[string]$Policy.LockoutDuration
        LockoutObservationWindow=[string]$Policy.LockoutObservationWindow; AppliesTo=($Policy.AppliesTo -join '; ')
    })
    if ($Policy.ReversibleEncryptionEnabled -eq $true) {
        Add-Finding 'PasswordPolicy' 'REVIEW' $Policy.DistinguishedName 'ReversibleEncryptionEnabled=True' 'Review against the approved password policy and application requirements.'
    }
}

function Add-PrivilegeRows {
    param($GroupSpec,$Group,[object[]]$Members,[string]$MembershipType)
    foreach ($member in $Members) {
        $null = $tables.PrivilegedMembers.Add([pscustomobject]@{
            PrivilegeLabel=$GroupSpec.Label; GroupName=$Group.Name; GroupSID=[string]$Group.SID; QueryServer=$GroupSpec.Server
            MembershipType=$MembershipType; MemberName=$member.Name; SamAccountName=$member.SamAccountName
            ObjectClass=$member.ObjectClass; SID=[string]$member.SID; DistinguishedName=$member.DistinguishedName
        })
    }
}

$module = Invoke-AuditQuery 'ActiveDirectoryModule' 'Local computer' { Import-Module ActiveDirectory -ErrorAction Stop }
$domain = $null
$forest = $null
$queryServer = $Server
$scope = @{}
if ($module.Succeeded) {
    $domainResult = Invoke-AuditQuery 'DomainDiscovery' $(if ($Server) { $Server } else { 'Authenticated user domain' }) -RequireResult -Action {
        if ($Server) { Get-ADDomain -Server $Server -ErrorAction Stop } else { Get-ADDomain -Current LoggedOnUser -ErrorAction Stop }
    }
    if ($domainResult.Succeeded -and $domainResult.Items.Count -eq 1) {
        $domain = $domainResult.Items[0]
        if (-not $queryServer) { $queryServer = $domain.PDCEmulator }
        $scope = @{ Server=$queryServer; ErrorAction='Stop' }
        if ($SearchBase) { $scope.SearchBase = $SearchBase }
        $domainAttrs = Invoke-AuditQuery 'DomainLogonTimestampInterval' $queryServer -RequireResult -Action {
            Get-ADObject -Identity $domain.DistinguishedName -Properties 'msDS-LogonTimeSyncInterval' -Server $queryServer -ErrorAction Stop
        }
        $syncInterval = $null
        if ($domainAttrs.Succeeded -and $domainAttrs.Items.Count -gt 0) { $syncInterval = $domainAttrs.Items[0].'msDS-LogonTimeSyncInterval' }
        $null = $tables.Domain.Add([pscustomobject]@{
            DNSRoot=$domain.DNSRoot; NetBIOSName=$domain.NetBIOSName; DistinguishedName=$domain.DistinguishedName
            DomainSID=[string]$domain.DomainSID; DomainMode=[string]$domain.DomainMode; PDCEmulator=$domain.PDCEmulator
            RIDMaster=$domain.RIDMaster; InfrastructureMaster=$domain.InfrastructureMaster; LogonTimeSyncIntervalDays=$syncInterval
        })
        foreach ($role in @('PDCEmulator','RIDMaster','InfrastructureMaster')) {
            $null = $tables.FSMOHolders.Add([pscustomobject]@{ Role=$role; Holder=$domain.$role; Scope=$domain.DNSRoot })
        }
        $forestResult = Invoke-AuditQuery 'ForestDiscovery' $queryServer -RequireResult -Action { Get-ADForest -Server $queryServer -ErrorAction Stop }
        if ($forestResult.Succeeded -and $forestResult.Items.Count -gt 0) {
            $forest = $forestResult.Items[0]
            $null = $tables.Forest.Add([pscustomobject]@{
                Name=$forest.Name; RootDomain=$forest.RootDomain; ForestMode=[string]$forest.ForestMode
                Domains=($forest.Domains -join '; '); Sites=($forest.Sites -join '; '); GlobalCatalogs=($forest.GlobalCatalogs -join '; ')
                SchemaMaster=$forest.SchemaMaster; DomainNamingMaster=$forest.DomainNamingMaster
            })
            foreach ($role in @('SchemaMaster','DomainNamingMaster')) {
                $null = $tables.FSMOHolders.Add([pscustomobject]@{ Role=$role; Holder=$forest.$role; Scope=$forest.Name })
            }
        }
        $dcs = Invoke-AuditQuery 'DomainControllerInventory' $queryServer -RequireResult -Action { Get-ADDomainController -Filter '*' -Server $queryServer -ErrorAction Stop }
        foreach ($dc in $dcs.Items) {
            $null = $tables.DomainControllers.Add([pscustomobject]@{
                HostName=$dc.HostName; Site=$dc.Site; IPv4Address=$dc.IPv4Address; IPv6Address=$dc.IPv6Address
                OperatingSystem=$dc.OperatingSystem; IsGlobalCatalog=$dc.IsGlobalCatalog; IsReadOnly=$dc.IsReadOnly
                Enabled=$dc.Enabled; OperationMasterRoles=($dc.OperationMasterRoles -join '; ')
            })
            $dcName = $dc.HostName
            $failures = Invoke-AuditQuery 'ReplicationFailures' $dcName { Get-ADReplicationFailure -Target $dcName -Scope Server -ErrorAction Stop }
            foreach ($failure in $failures.Items) {
                $null = $tables.ReplicationFailures.Add([pscustomobject]@{
                    QueriedDC=$dcName; Server=$failure.Server; Partner=$failure.Partner; FailureType=[string]$failure.FailureType
                    FirstFailureTime=(Format-AuditDate $failure.FirstFailureTime); FailureCount=$failure.FailureCount; LastError=$failure.LastError
                })
                Add-Finding 'Replication' 'REVIEW' $dcName ('Partner={0}; count={1}; error={2}' -f $failure.Partner,$failure.FailureCount,$failure.LastError) 'Investigate the replication failure; this script does not attempt repair.'
            }
            $partners = Invoke-AuditQuery 'ReplicationPartnerMetadata' $dcName { Get-ADReplicationPartnerMetadata -Target $dcName -Scope Server -Partition '*' -PartnerType Both -ErrorAction Stop }
            foreach ($partner in $partners.Items) {
                $null = $tables.ReplicationPartners.Add([pscustomobject]@{
                    QueriedDC=$dcName; Server=$partner.Server; Partner=$partner.Partner; Partition=$partner.Partition
                    PartnerType=[string]$partner.PartnerType; LastReplicationAttempt=(Format-AuditDate $partner.LastReplicationAttempt)
                    LastReplicationSuccess=(Format-AuditDate $partner.LastReplicationSuccess); LastReplicationResult=$partner.LastReplicationResult
                    ConsecutiveReplicationFailures=$partner.ConsecutiveReplicationFailures
                })
                if (($null -ne $partner.LastReplicationResult -and $partner.LastReplicationResult -ne 0) -or $partner.ConsecutiveReplicationFailures -gt 0) {
                    Add-Finding 'ReplicationPartner' 'REVIEW' $dcName ('Partner={0}; partition={1}; result={2}; consecutiveFailures={3}' -f $partner.Partner,$partner.Partition,$partner.LastReplicationResult,$partner.ConsecutiveReplicationFailures) 'Review partner evidence and replication topology.'
                }
            }
        }
        $policy = Invoke-AuditQuery 'DefaultPasswordPolicy' $queryServer -RequireResult -Action { Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -Server $queryServer -ErrorAction Stop }
        foreach ($item in $policy.Items) { Add-PolicyRow $item 'DefaultDomain' 'PasswordPolicy' }
        $finePolicies = Invoke-AuditQuery 'FineGrainedPasswordPolicies' $queryServer { Get-ADFineGrainedPasswordPolicy -Filter '*' -Server $queryServer -ErrorAction Stop }
        foreach ($item in $finePolicies.Items) { Add-PolicyRow $item 'FineGrained' 'FineGrainedPasswordPolicies' }

        $stamp = $cutoff.ToFileTimeUtc()
        $createdCutoff = $cutoff.ToString('yyyyMMddHHmmss.0Z',[System.Globalization.CultureInfo]::InvariantCulture)
        $staleFilter = '(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(lastLogonTimestamp<={0})(!(lastLogonTimestamp=*)))(whenCreated<={1})' -f $stamp,$createdCutoff
        $staleUsers = Invoke-AuditQuery 'StaleEnabledUsers' $(if ($SearchBase) { $SearchBase } else { $domain.DistinguishedName }) {
            Get-ADUser -LDAPFilter ('(&(objectCategory=person)(objectClass=user){0})' -f $staleFilter) -Properties LastLogonDate,whenCreated,PasswordLastSet @scope
        }
        foreach ($user in $staleUsers.Items) {
            $null = $tables.StaleUsers.Add([pscustomobject]@{
                SamAccountName=$user.SamAccountName; Name=$user.Name; DistinguishedName=$user.DistinguishedName; Enabled=$user.Enabled
                WhenCreated=(Format-AuditDate $user.whenCreated); LastLogonDate=(Format-AuditDate $user.LastLogonDate)
                TimestampEvidence=$(if ($null -eq $user.LastLogonDate) { 'No replicated timestamp recorded' } else { 'Replicated timestamp at/before cutoff' })
                PasswordLastSet=(Format-AuditDate $user.PasswordLastSet)
            })
        }
        $staleComputers = Invoke-AuditQuery 'StaleEnabledComputers' $(if ($SearchBase) { $SearchBase } else { $domain.DistinguishedName }) {
            Get-ADComputer -LDAPFilter ('(&(objectCategory=computer){0})' -f $staleFilter) -Properties LastLogonDate,whenCreated,OperatingSystem @scope
        }
        foreach ($computer in $staleComputers.Items) {
            $null = $tables.StaleComputers.Add([pscustomobject]@{
                SamAccountName=$computer.SamAccountName; Name=$computer.Name; DistinguishedName=$computer.DistinguishedName; Enabled=$computer.Enabled
                WhenCreated=(Format-AuditDate $computer.whenCreated); LastLogonDate=(Format-AuditDate $computer.LastLogonDate)
                TimestampEvidence=$(if ($null -eq $computer.LastLogonDate) { 'No replicated timestamp recorded' } else { 'Replicated timestamp at/before cutoff' })
                OperatingSystem=$computer.OperatingSystem
            })
        }
        if ($staleUsers.Succeeded -and $staleUsers.Items.Count -gt 0) { Add-Finding 'StaleAccounts' 'REVIEW' 'Enabled users' ('Candidates={0}; cutoffUtc={1}' -f $staleUsers.Items.Count,$cutoff.ToString('o')) 'Confirm activity with account owners and authoritative evidence before any account action.' }
        if ($staleComputers.Succeeded -and $staleComputers.Items.Count -gt 0) { Add-Finding 'StaleAccounts' 'REVIEW' 'Enabled computers' ('Candidates={0}; cutoffUtc={1}' -f $staleComputers.Items.Count,$cutoff.ToString('o')) 'Confirm device status; replicated logon timestamps can lag actual use.' }
        $locked = Invoke-AuditQuery 'LockedUserCount' $queryServer { Search-ADAccount -LockedOut -UsersOnly @scope | Measure-Object | Select-Object -ExpandProperty Count }
        $disabled = Invoke-AuditQuery 'DisabledUserCount' $queryServer { Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' @scope | Measure-Object | Select-Object -ExpandProperty Count }
        foreach ($countSpec in @(@{ Name='LockedUsers'; Result=$locked },@{ Name='DisabledUsers'; Result=$disabled })) {
            $null = $tables.AccountCounts.Add([pscustomobject]@{ Metric=$countSpec.Name; Count=$(if ($countSpec.Result.Succeeded) { $countSpec.Result.Items[0] } else { $null }); Scope=$(if ($SearchBase) { $SearchBase } else { $domain.DistinguishedName }); Status=$(if ($countSpec.Result.Succeeded) { 'COLLECTED' } else { 'UNKNOWN' }) })
        }

        $groupSpecs = New-Object 'System.Collections.Generic.List[object]'
        foreach ($ridAndName in @(@(512,'Domain Admins'),@(520,'Group Policy Creator Owners'))) {
            $null = $groupSpecs.Add([pscustomobject]@{ Label=$ridAndName[1]; SID=('{0}-{1}' -f $domain.DomainSID,$ridAndName[0]); Server=$queryServer; DomainDN=$domain.DistinguishedName; PrimaryRID=$ridAndName[0] })
        }
        foreach ($ridAndName in @(@(544,'Administrators'),@(548,'Account Operators'),@(549,'Server Operators'),@(550,'Print Operators'),@(551,'Backup Operators'))) {
            $null = $groupSpecs.Add([pscustomobject]@{ Label=$ridAndName[1]; SID=('S-1-5-32-{0}' -f $ridAndName[0]); Server=$queryServer; DomainDN=$domain.DistinguishedName; PrimaryRID=$null })
        }
        if ($null -ne $forest) {
            $rootDomain = $null
            if ($forest.RootDomain -eq $domain.DNSRoot) { $rootDomain = $domain } else {
                $rootResult = Invoke-AuditQuery 'ForestRootDomainDiscovery' $forest.RootDomain -RequireResult -Action { Get-ADDomain -Identity $forest.RootDomain -Server $forest.RootDomain -ErrorAction Stop }
                if ($rootResult.Succeeded -and $rootResult.Items.Count -gt 0) { $rootDomain = $rootResult.Items[0] }
            }
            if ($null -ne $rootDomain) {
                foreach ($ridAndName in @(@(518,'Schema Admins'),@(519,'Enterprise Admins'))) {
                    $null = $groupSpecs.Add([pscustomobject]@{ Label=$ridAndName[1]; SID=('{0}-{1}' -f $rootDomain.DomainSID,$ridAndName[0]); Server=$(if ($forest.RootDomain -eq $domain.DNSRoot) { $queryServer } else { $rootDomain.PDCEmulator }); DomainDN=$rootDomain.DistinguishedName; PrimaryRID=$ridAndName[0] })
                }
            }
        }
        foreach ($spec in $groupSpecs) {
            $groupResult = Invoke-AuditQuery ('PrivilegedGroup:{0}' -f $spec.Label) $spec.Server -RequireResult -Action { Get-ADGroup -Identity $spec.SID -Server $spec.Server -ErrorAction Stop }
            if (-not $groupResult.Succeeded -or $groupResult.Items.Count -eq 0) { continue }
            $group = $groupResult.Items[0]
            $direct = Invoke-AuditQuery ('DirectMembers:{0}' -f $spec.Label) $spec.Server { Get-ADGroupMember -Identity $group.DistinguishedName -Server $spec.Server -ErrorAction Stop }
            Add-PrivilegeRows $spec $group $direct.Items 'Direct'
            $expanded = Invoke-AuditQuery ('RecursiveLeafMembers:{0}' -f $spec.Label) $spec.Server { Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -Server $spec.Server -ErrorAction Stop }
            Add-PrivilegeRows $spec $group $expanded.Items 'RecursiveLeaf'
            if ($null -ne $spec.PrimaryRID) {
                $primary = Invoke-AuditQuery ('PrimaryGroupMembers:{0}' -f $spec.Label) $spec.Server { Get-ADObject -LDAPFilter ('(primaryGroupID={0})' -f $spec.PrimaryRID) -SearchBase $spec.DomainDN -Properties objectSid,sAMAccountName -Server $spec.Server -ErrorAction Stop | Select-Object Name,SamAccountName,ObjectClass,DistinguishedName,@{Name='SID';Expression={$_.objectSid}} }
                Add-PrivilegeRows $spec $group $primary.Items 'PrimaryGroup'
            }
        }
        if ($tables.PrivilegedMembers.Count -gt 0) { Add-Finding 'PrivilegedMembership' 'INFORMATION' 'Selected privileged groups' ('Evidence rows={0}; membership types may repeat the same principal.' -f $tables.PrivilegedMembers.Count) 'Review direct, recursive leaf, and primary-group evidence separately against approved membership. This is not an exhaustive effective-rights audit.' }
    }
}
if (-not $module.Succeeded) { Write-Warning 'ActiveDirectory module could not be imported. Use a domain controller with AD DS management tools, or a workstation with the Microsoft RSAT Active Directory tools. See QueryErrors.csv.' }

function Export-AuditCsv {
    param([string]$Name,[object[]]$Rows,[string[]]$Columns)
    $path = Join-Path $reportPath ($Name + '.csv')
    if ($Rows.Count -gt 0) { $Rows | Select-Object $Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 } else {
        # A header-only CSV represents a valid empty result; QueryStatus distinguishes failure.
        (($Columns | ForEach-Object { '"{0}"' -f $_.Replace('"','""') }) -join ',') | Set-Content -LiteralPath $path -Encoding UTF8
    }
}
foreach ($tableName in $schemas.Keys) { Export-AuditCsv $tableName @($tables[$tableName].ToArray()) $schemas[$tableName] }
Export-AuditCsv 'QueryStatus' @($queryStatus.ToArray()) @('Query','Target','Status','RecordCount','Detail')
Export-AuditCsv 'QueryErrors' @($queryErrors.ToArray()) @('Query','Target','TimestampUtc','ErrorType','Message')
Export-AuditCsv 'Findings' @($findings.ToArray()) @('Category','Severity','Subject','Evidence','Review')
$collectionStatus = if ($null -eq $domain) { 'UNKNOWN' } elseif ($queryErrors.Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' }
$recordCounts = [ordered]@{}
foreach ($tableName in $schemas.Keys) { $recordCounts[$tableName] = $tables[$tableName].Count }
$caveats = @(
    'COMPLETE describes collection only. It does not certify security or AD health.'
    'No Security event logs, full user inventory, passwords, recovery keys, or directory changes are included.'
    'SearchBase limits stale-account and locked/disabled-user queries only; other queries have domain or forest-root scope.'
    'Replication targets discoverable DCs in the selected domain; other forest domains are not fully audited.'
    'LastLogonDate derives from replicated lastLogonTimestamp, which can lag activity. Missing timestamps do not prove no logons. Validate stale candidates before account changes.'
    'Privileged group evidence covers selected well-known SID/RID groups, not every delegated right, trust, SIDHistory, custom privileged group, or nested primary-group path.'
    'RecursiveLeaf membership may repeat Direct members. Do not add row counts to obtain unique account totals.'
    'Access restrictions can silently hide objects. Results reflect what the current account can read, including an empty successful query.'
)
$summary = [ordered]@{
    Tool='Active Directory audit'; StartedUtc=$started.ToUniversalTime().ToString('o'); CompletedUtc=(Get-Date).ToUniversalTime().ToString('o')
    ComputerName=$env:COMPUTERNAME; RequestedServer=$Server; QueryServer=$queryServer; ReportDirectory=$reportPath
    Domain=$(if ($null -ne $domain) { $domain.DNSRoot } else { $null }); SearchBase=$SearchBase; StaleDays=$StaleDays; StaleCutoffUtc=$cutoff.ToString('o')
    CollectionStatus=$collectionStatus; Assessment='REVIEW_EVIDENCE'; QueryErrorCount=$queryErrors.Count; FindingCount=$findings.Count
    RecordCounts=$recordCounts; Queries=@($queryStatus.ToArray()); Caveats=$caveats
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $reportPath 'summary.json') -Encoding UTF8
$overview = New-Object 'System.Collections.Generic.List[string]'
$null = $overview.Add('Active Directory audit - report only')
$null = $overview.Add(('Collection: {0}; query errors: {1}; findings: {2}' -f $collectionStatus,$queryErrors.Count,$findings.Count))
$null = $overview.Add(('Domain: {0}; query server: {1}; stale cutoff UTC: {2}' -f $summary.Domain,$queryServer,$cutoff.ToString('o')))
$null = $overview.Add(('Account search scope: {0}' -f $(if ($SearchBase) { $SearchBase } elseif ($domain) { $domain.DistinguishedName } else { 'UNKNOWN' })))
$null = $overview.Add('')
foreach ($tableName in $recordCounts.Keys) { $null = $overview.Add(('{0}: {1} evidence rows' -f $tableName,$recordCounts[$tableName])) }
$null = $overview.Add('')
$null = $overview.Add('Collection caveats:')
foreach ($note in $caveats) { $null = $overview.Add(('- ' + $note)) }
$null = $overview.Add('')
$null = $overview.Add('Read Findings.csv for review items; QueryStatus.csv and QueryErrors.csv explain gaps. Empty evidence files do not establish a healthy result.')
$overview | Set-Content -LiteralPath (Join-Path $reportPath 'Overview.txt') -Encoding UTF8
Write-Host ('AD audit reports: {0}' -f $reportPath)
Write-Host ('Collection status: {0}; query errors: {1}' -f $collectionStatus,$queryErrors.Count)
[pscustomobject]@{ ReportDirectory=$reportPath; ReportPath=$reportPath; CollectionStatus=$collectionStatus; QueryErrorCount=$queryErrors.Count; FindingCount=$findings.Count }

