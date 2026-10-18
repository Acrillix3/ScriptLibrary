<#
What it does:
  Lists one AD user's direct, primary, and nested group memberships.

Available flags:
  -Identity: Required user account name, distinguished name, GUID, or SID.
  -Server: Optional domain controller or AD domain to query.
  -MaxDepth: Maximum group nesting depth, 1-100; default 20.
  -MaxGroups: Maximum groups inspected, 1-10000; default 1000.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Uses the ActiveDirectory module and directory read access to follow group links and resolve the
  primary group, then saves CSV and JSON reports. Limits and query failures are recorded; membership
  does not establish effective permissions or all cross-forest access.
#>
#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Identity,
    [string]$Server,
    [ValidateRange(1,100)][int]$MaxDepth = 20,
    [ValidateRange(1,10000)][int]$MaxGroups = 1000,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$reportDirectory = Join-Path $OutputDirectory ('11-ADGroupMembership_{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $reportDirectory -Force -ErrorAction Stop
$rows = New-Object 'System.Collections.Generic.List[object]'
$failures = New-Object 'System.Collections.Generic.List[object]'
$queue = New-Object System.Collections.Queue
$seen = @{}; $direct = @{}; $primarySid = ''; $primaryResolved = $false; $userFound = $false
$status = 'Success'
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $query = @{Identity=$Identity;Properties=@('memberOf','primaryGroupID','SID');ErrorAction='Stop'}
    if ($Server) { $query.Server = $Server }
    $user = Get-ADUser @query
    if ($null -eq $user) { throw 'The directory returned no user.' }
    $userFound = $true
    foreach ($dn in @($user.memberOf)) {
        if ($dn) { $direct[[string]$dn] = $true; $queue.Enqueue([pscustomobject]@{Identity=[string]$dn;Depth=1;Primary=$false}) }
    }
    if ($user.SID -and $null -ne $user.primaryGroupID) {
        $primarySid = ([string]$user.SID -replace '-\d+$','') + '-' + [string]$user.primaryGroupID
        $queue.Enqueue([pscustomobject]@{Identity=$primarySid;Depth=1;Primary=$true})
    } else { $failures.Add([pscustomobject]@{Step='PrimaryGroup';Error='SID or primaryGroupID unavailable; primary group could not be established.'}) }
    while ($queue.Count -gt 0) {
        $node = $queue.Dequeue()
        if ($seen.ContainsKey($node.Identity)) { continue }
        if ($rows.Count -ge $MaxGroups) { $failures.Add([pscustomobject]@{Step='TraversalLimit';Error="Maximum group count $MaxGroups reached; results are incomplete."}); break }
        $seen[$node.Identity] = $true
        try {
            $groupQuery = @{Identity=$node.Identity;Properties=@('memberOf');ErrorAction='Stop'}
            if ($Server) { $groupQuery.Server = $Server }
            $group = Get-ADGroup @groupQuery
            if ($null -eq $group) { throw ('No group returned for '+$node.Identity) }
            $dn = [string]$group.DistinguishedName
            $isPrimary = ([string]$group.SID -eq $primarySid -and $primarySid -ne '')
            if ($isPrimary) { $primaryResolved = $true }
            # A primary group can also already have been encountered through a DN.
            if (@($rows | Where-Object DistinguishedName -eq $dn).Count -gt 0) { continue }
            $isDirect = $direct.ContainsKey($dn)
            $type = 'Nested'
            if ($isPrimary) { $type = 'Primary' } elseif ($isDirect) { $type = 'Direct' }
            $rows.Add([pscustomobject]@{Name=$group.Name;SamAccountName=$group.SamAccountName;DistinguishedName=$dn;SID=[string]$group.SID;GroupCategory=[string]$group.GroupCategory;GroupScope=[string]$group.GroupScope;MembershipType=$type;Depth=$node.Depth;IsDirect=$isDirect;IsPrimary=$isPrimary})
            $seen[$dn] = $true
            foreach ($parent in @($group.memberOf)) {
                if (-not $parent -or $seen.ContainsKey([string]$parent)) { continue }
                if ($node.Depth -ge $MaxDepth) { $failures.Add([pscustomobject]@{Step='DepthLimit';Error=('Parent beyond maximum depth {0}: {1}' -f $MaxDepth,$parent)}) }
                else { $queue.Enqueue([pscustomobject]@{Identity=[string]$parent;Depth=($node.Depth+1);Primary=$false}) }
            }
        } catch { $failures.Add([pscustomobject]@{Step=('Group '+$node.Identity);Error=$_.Exception.Message}) }
    }
} catch { $status = 'Failed'; $failures.Add([pscustomobject]@{Step='UserLookup';Error=$_.Exception.Message}) }
if ($status -ne 'Failed' -and $failures.Count -gt 0) { $status = 'Partial' }
if ($status -eq 'Success' -and $rows.Count -eq 0) { $status = 'NoData' }
if ($rows.Count -gt 0) { $rows | Sort-Object Depth,Name | Export-Csv -LiteralPath (Join-Path $reportDirectory 'groups.csv') -NoTypeInformation -Encoding UTF8 }
else { '"Name","SamAccountName","DistinguishedName","SID","GroupCategory","GroupScope","MembershipType","Depth","IsDirect","IsPrimary"' | Set-Content -LiteralPath (Join-Path $reportDirectory 'groups.csv') -Encoding UTF8 }
$summary = [pscustomobject]@{ReportDirectory=$reportDirectory;Status=$status;RequestedIdentity=$Identity;UserFound=$userFound;GroupCount=$rows.Count;DirectCount=@($rows | Where-Object IsDirect).Count;NestedCount=@($rows | Where-Object MembershipType -eq 'Nested').Count;PrimaryGroupResolved=$primaryResolved;FailureCount=$failures.Count}
[pscustomobject]@{Summary=$summary;Groups=@($rows.ToArray());Failures=@($failures.ToArray())} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $reportDirectory 'report.json') -Encoding UTF8
'Scope: memberOf links visible to the chosen directory server plus the primary group derived from SID/primaryGroupID. Depth 1 = direct or primary. Higher depth = parent/nested. Groups reached by multiple routes appear once with the shortest observed depth. This is not an effective access, tokenGroups, SIDHistory, or cross-forest resource-domain entitlement calculation. Query failures and traversal limits mean results are incomplete.' | Set-Content -LiteralPath (Join-Path $reportDirectory 'notes.txt') -Encoding UTF8
foreach ($failure in $failures) { Write-Warning ('{0}: {1}' -f $failure.Step,$failure.Error) }
$summary

