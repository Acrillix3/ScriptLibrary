<#
What it does:
  Exports folder owners and NTFS permission entries for a local or network folder.

Available flags:
  -Path: Required literal local or UNC folder path; wildcards are not expanded.
  -Recurse: Include child folders within the specified limits.
  -MaxDepth: Maximum child-folder depth, 0-32; default 4.
  -MaxFolders: Maximum folders inspected, 1-10000; default 500.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Reads folder ACLs using your current account and saves CSV and JSON reports, recording access
  failures and traversal limits. Requires permission to list folders and read their ACLs; recursion
  skips reparse points, and results do not calculate effective access or SMB share permissions.
#>
#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Path,
    [switch]$Recurse,
    [ValidateRange(0,32)][int]$MaxDepth = 4,
    [ValidateRange(1,10000)][int]$MaxFolders = 500,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$reportDirectory = Join-Path $OutputDirectory ('14-FolderPermissions_{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $reportDirectory -Force -ErrorAction Stop
$entries = New-Object 'System.Collections.Generic.List[object]'
$folders = New-Object 'System.Collections.Generic.List[object]'
$failures = New-Object 'System.Collections.Generic.List[object]'
$queue = New-Object System.Collections.Queue
$rootValid = $false
try {
    $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $root.PSIsContainer -or $root.PSProvider.Name -ne 'FileSystem') { throw 'Path must identify a filesystem folder.' }
    if (($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'The selected folder is a reparse point. Select its actual target explicitly.' }
    $queue.Enqueue([pscustomobject]@{Path=$root.FullName;Depth=0}); $rootValid = $true
} catch { $failures.Add([pscustomobject]@{Path=$Path;Step='ValidatePath';Error=$_.Exception.Message}) }
while ($queue.Count -gt 0) {
    if ($folders.Count -ge $MaxFolders) { $failures.Add([pscustomobject]@{Path=$Path;Step='FolderLimit';Error="Maximum folder count $MaxFolders reached; results are incomplete."}); break }
    $node = $queue.Dequeue()
    try {
        $acl = Get-Acl -LiteralPath $node.Path -ErrorAction Stop
        $folders.Add([pscustomobject]@{Path=$node.Path;Depth=$node.Depth;Owner=[string]$acl.Owner;AccessRulesProtected=$acl.AreAccessRulesProtected;RuleCount=@($acl.Access).Count;Result='Read';Error=''})
        foreach ($rule in @($acl.Access)) {
            $entries.Add([pscustomobject]@{Path=$node.Path;Identity=[string]$rule.IdentityReference;AccessControlType=[string]$rule.AccessControlType;FileSystemRights=[string]$rule.FileSystemRights;IsInherited=$rule.IsInherited;InheritanceFlags=[string]$rule.InheritanceFlags;PropagationFlags=[string]$rule.PropagationFlags})
        }
    } catch {
        $folders.Add([pscustomobject]@{Path=$node.Path;Depth=$node.Depth;Owner='';AccessRulesProtected=$null;RuleCount=$null;Result='Failed';Error=$_.Exception.Message})
        $failures.Add([pscustomobject]@{Path=$node.Path;Step='ReadDACL';Error=$_.Exception.Message})
    }
    if ($Recurse) {
        try {
            # Enumerate one level at a time so depth/count limits and reparse points are explicit.
            $children = @(Get-ChildItem -LiteralPath $node.Path -Directory -Force -ErrorAction Stop)
            foreach ($child in $children) {
                if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $failures.Add([pscustomobject]@{Path=$child.FullName;Step='SkippedReparsePoint';Error='Not followed; select the target explicitly if needed.'}); continue
                }
                if ($node.Depth -ge $MaxDepth) { $failures.Add([pscustomobject]@{Path=$child.FullName;Step='DepthLimit';Error="Beyond requested maximum depth $MaxDepth; results are scoped/truncated."}) }
                elseif ($folders.Count + $queue.Count -ge $MaxFolders) { $failures.Add([pscustomobject]@{Path=$child.FullName;Step='FolderLimit';Error="Beyond requested maximum folder count $MaxFolders; results are incomplete."}); break }
                else { $queue.Enqueue([pscustomobject]@{Path=$child.FullName;Depth=($node.Depth+1)}) }
            }
        } catch { $failures.Add([pscustomobject]@{Path=$node.Path;Step='EnumerateChildren';Error=$_.Exception.Message}) }
    }
}
if ($entries.Count -gt 0) { $entries | Export-Csv -LiteralPath (Join-Path $reportDirectory 'acl.csv') -NoTypeInformation -Encoding UTF8 }
else { '"Path","Identity","AccessControlType","FileSystemRights","IsInherited","InheritanceFlags","PropagationFlags"' | Set-Content -LiteralPath (Join-Path $reportDirectory 'acl.csv') -Encoding UTF8 }
if ($folders.Count -gt 0) { $folders | Export-Csv -LiteralPath (Join-Path $reportDirectory 'folders.csv') -NoTypeInformation -Encoding UTF8 }
else { '"Path","Depth","Owner","AccessRulesProtected","RuleCount","Result","Error"' | Set-Content -LiteralPath (Join-Path $reportDirectory 'folders.csv') -Encoding UTF8 }
$status = 'Success'
if (-not $rootValid -or @($folders | Where-Object Result -eq 'Read').Count -eq 0) { $status = 'Failed' } elseif ($failures.Count -gt 0) { $status = 'Partial' }
$summary = [pscustomobject]@{ReportDirectory=$reportDirectory;Status=$status;RequestedPath=$Path;Recursive=[bool]$Recurse;FolderCount=$folders.Count;AccessRuleCount=$entries.Count;FailureOrScopeNoteCount=$failures.Count}
[pscustomobject]@{Summary=$summary;Folders=@($folders.ToArray());AccessRules=@($entries.ToArray());Failures=@($failures.ToArray())} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $reportDirectory 'report.json') -Encoding UTF8
'NTFS owner/DACL entries for folders only. This report does not calculate effective access, resolve all nested group memberships, inspect SACLs, or include SMB share permissions. A readable folder with zero listed rules is reported as such; a failed ACL read is never an empty successful ACL. Recursive scope limits and skipped reparse points are explicit. Reports contain account and folder names.' | Set-Content -LiteralPath (Join-Path $reportDirectory 'notes.txt') -Encoding UTF8
foreach ($failure in $failures) { Write-Warning ('{0}: {1}: {2}' -f $failure.Step,$failure.Path,$failure.Error) }
$summary

