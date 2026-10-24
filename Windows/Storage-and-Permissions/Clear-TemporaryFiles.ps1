<#
What it does:
  Plans or removes old files from bounded, known temporary and optional browser cache folders.

Available flags:
  -Apply: Remove approved files; default is a plan. -OlderThanDays: File age, default 7.
  -IncludeSystemTemp: Include Windows Temp; requires elevation for Apply.
  -IncludeBrowserCache: Include known Edge, Chrome, and Firefox caches only when closed.
  -MaxFiles: Maximum filesystem entries inspected, default 5000. -MaxDepth: Depth, default 8.
  -OutputDirectory: Report location. -WhatIf, -Confirm: Standard PowerShell controls.

How it works:
  Uses the current profile's fixed AppData Local Temp path. Skips reparse points and checks
  every parent before literal per-file deletion. Rechecks age and modification time, reports
  locked/skipped files, and never removes directories, downloads, cookies, or installer caches.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param(
    [switch]$Apply,[ValidateRange(1,3650)][int]$OlderThanDays=7,
    [switch]$IncludeSystemTemp,[switch]$IncludeBrowserCache,
    [ValidateRange(1,100000)][int]$MaxFiles=5000,[ValidateRange(1,32)][int]$MaxDepth=8,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT'){throw 'This script supports Windows only.'}
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$runName='Clear-TemporaryFiles-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),[guid]::NewGuid().ToString('N').Substring(0,8)
$reportDirectory=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force -WhatIf:$false -Confirm:$false).FullName
$fileResults=New-Object 'System.Collections.Generic.List[object]'
$scopeResults=New-Object 'System.Collections.Generic.List[object]'
$roots=New-Object 'System.Collections.Generic.List[object]'
$cutoff=[datetime]::UtcNow.AddDays(-$OlderThanDays)
$inspected=0;$entriesInspected=0;$removedBytes=[int64]0;$limitReached=$false
function Assert-CleanupBoundary {
    param([string]$Path,[string]$Root,[switch]$File)
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    $approved=[IO.Path]::GetFullPath($Root).TrimEnd('\')
    if($full -match '^\\\\' -or $approved -notmatch '^[A-Za-z]:\\'){throw 'Only local drive paths are supported.'}
    if(-not [string]::Equals($full,$approved,[StringComparison]::OrdinalIgnoreCase) -and -not $full.StartsWith($approved+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Path escaped the approved cleanup folder.'}
    if($File -and [string]::Equals($full,$approved,[StringComparison]::OrdinalIgnoreCase)){throw 'The cleanup root itself cannot be removed.'}
    $cursor=$full
    while($cursor){
        $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse points and paths through reparse points are excluded.'}
        $parent=[IO.Directory]::GetParent($cursor)
        if($null -eq $parent){break};$cursor=$parent.FullName
    }
    $leaf=Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if($File -and $leaf.PSIsContainer){throw 'Directory deletion is prohibited.'}
    if(-not $File -and -not $leaf.PSIsContainer){throw 'A cleanup root must be a directory.'}
    $leaf
}
function Add-CleanupScope {
    param([string]$Name,[string]$Path,[bool]$RequiresAdministrator,[string]$BrowserProcess='')
    try{
        if(-not (Test-Path -LiteralPath $Path)){ $scopeResults.Add([pscustomobject]@{Scope=$Name;Path=$Path;Status='NotPresent';Detail=''});return }
        $null=Assert-CleanupBoundary $Path $Path
        $roots.Add([pscustomobject]@{Name=$Name;Path=[IO.Path]::GetFullPath($Path).TrimEnd('\');RequiresAdministrator=$RequiresAdministrator;BrowserProcess=$BrowserProcess})
        $scopeResults.Add([pscustomobject]@{Scope=$Name;Path=$Path;Status='Included';Detail=''})
    }catch{$scopeResults.Add([pscustomobject]@{Scope=$Name;Path=$Path;Status='Skipped';Detail=$_.Exception.Message})}
}
function Test-CleanupAdministrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Test-BrowserClosed {
    param([string]$ProcessName)
    if(-not $ProcessName){return $true}
    try{return (@(Get-Process -Name $ProcessName -ErrorAction Stop).Count -eq 0)}
    catch{if($_.FullyQualifiedErrorId -like 'NoProcessFoundForGivenName*'){return $true};throw 'Browser process state could not be determined.'}
}
function Get-KnownBrowserCaches {
    param([string]$LocalAppData)
    foreach($family in @(@{Name='Edge';Relative='Microsoft\Edge\User Data';Process='msedge'},@{Name='Chrome';Relative='Google\Chrome\User Data';Process='chrome'})){
        $base=Join-Path $LocalAppData $family.Relative
        if(-not (Test-Path -LiteralPath $base -PathType Container)){continue}
        try{
            $null=Assert-CleanupBoundary $base $base
            if(-not (Test-BrowserClosed $family.Process)){$scopeResults.Add([pscustomobject]@{Scope=$family.Name;Path=$base;Status='SkippedBrowserRunning';Detail='Close all instances of this browser before including its cache.'});continue}
            foreach($profile in @(Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction Stop | Where-Object {$_.Name -eq 'Default' -or $_.Name -match '^Profile [0-9]+$'})){
                foreach($cache in @('Cache','Code Cache','GPUCache')){Add-CleanupScope ($family.Name+' '+$profile.Name+' '+$cache) (Join-Path $profile.FullName $cache) $false $family.Process}
            }
        }catch{$scopeResults.Add([pscustomobject]@{Scope=$family.Name;Path=$base;Status='Unknown';Detail='Could not safely enumerate browser cache folders.'})}
    }
    $firefox=Join-Path $LocalAppData 'Mozilla\Firefox\Profiles'
    if(Test-Path -LiteralPath $firefox -PathType Container){
        try{
            $null=Assert-CleanupBoundary $firefox $firefox
            if(-not (Test-BrowserClosed 'firefox')){$scopeResults.Add([pscustomobject]@{Scope='Firefox';Path=$firefox;Status='SkippedBrowserRunning';Detail='Close all Firefox instances first.'});return}
            foreach($profile in @(Get-ChildItem -LiteralPath $firefox -Directory -Force -ErrorAction Stop)){Add-CleanupScope ('Firefox '+$profile.Name+' cache2') (Join-Path $profile.FullName 'cache2') $false 'firefox'}
        }catch{$scopeResults.Add([pscustomobject]@{Scope='Firefox';Path=$firefox;Status='Unknown';Detail='Could not safely enumerate Firefox caches.'})}
    }
}
function Get-CleanupFileDecision {
    param([System.IO.FileInfo]$Current,[datetime]$CutoffUtc,[datetime]$ObservedWriteUtc,[int64]$ObservedLength)
    if($Current.LastWriteTimeUtc -ge $CutoffUtc){return 'SkippedTooRecent'}
    if($Current.LastWriteTimeUtc -ne $ObservedWriteUtc -or $Current.Length -ne $ObservedLength){return 'SkippedChangedSinceInventory'}
    'Eligible'
}
$profile=[Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
if([string]::IsNullOrWhiteSpace($profile) -or $profile -notmatch '^[A-Za-z]:\\'){throw 'A local current-user profile could not be identified.'}
$localAppData=Join-Path $profile 'AppData\Local'
Add-CleanupScope 'Current user temporary files' (Join-Path $localAppData 'Temp') $false
if($IncludeSystemTemp){
    $windowsFolder=[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    if(-not $windowsFolder){throw 'Windows folder could not be identified.'}
    Add-CleanupScope 'Windows temporary files' (Join-Path $windowsFolder 'Temp') $true
}
if($IncludeBrowserCache){Get-KnownBrowserCaches $localAppData}
foreach($scope in $roots){
    if($entriesInspected -ge $MaxFiles){$limitReached=$true;break}
    if($Apply -and -not $WhatIfPreference -and $scope.RequiresAdministrator -and -not (Test-CleanupAdministrator)){$scopeResults.Add([pscustomobject]@{Scope=$scope.Name;Path=$scope.Path;Status='SkippedRequiresElevation';Detail='System Temp was not changed.'});continue}
    $pending=New-Object 'System.Collections.Generic.Stack[object]'
    $pending.Push([pscustomobject]@{Path=$scope.Path;Depth=0})
    while($pending.Count -gt 0 -and $entriesInspected -lt $MaxFiles){
        $directory=$pending.Pop()
        try{
            $null=Assert-CleanupBoundary $directory.Path $scope.Path
            $remaining=$MaxFiles-$entriesInspected
            $entries=@(Get-ChildItem -LiteralPath $directory.Path -Force -ErrorAction Stop | Select-Object -First ($remaining+1))
            foreach($entry in $entries){
                if($entriesInspected -ge $MaxFiles){$limitReached=$true;break}
                $entriesInspected++
                if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){$fileResults.Add([pscustomobject]@{Scope=$scope.Name;Path=$entry.FullName;Bytes=$null;LastWriteUtc='';Status='SkippedReparsePoint';Detail=''});continue}
                if($entry.PSIsContainer){
                    if($directory.Depth -lt $MaxDepth){$pending.Push([pscustomobject]@{Path=$entry.FullName;Depth=($directory.Depth+1)})}
                    else{$scopeResults.Add([pscustomobject]@{Scope=$scope.Name;Path=$entry.FullName;Status='DepthLimit';Detail='Descendants were not inspected.'})}
                    continue
                }
                $inspected++
                $observedWrite=$entry.LastWriteTimeUtc;$observedLength=$entry.Length
                $row=[pscustomobject]@{Scope=$scope.Name;Path=$entry.FullName;Bytes=$entry.Length;LastWriteUtc=$observedWrite.ToString('o');Status='TooRecent';Detail=''}
                if($observedWrite -lt $cutoff){
                    $row.Status='Planned'
                    if($Apply -and $PSCmdlet.ShouldProcess($entry.FullName,'Remove old temporary/cache file')){
                        try{
                            $current=Assert-CleanupBoundary $entry.FullName $scope.Path -File
                            $decision=Get-CleanupFileDecision $current $cutoff $observedWrite $observedLength
                            if(-not (Test-BrowserClosed $scope.BrowserProcess)){$decision='SkippedBrowserRunning'}
                            if($decision -eq 'Eligible'){Remove-Item -LiteralPath $current.FullName -Force -ErrorAction Stop;$row.Status='Removed';$removedBytes+=$observedLength}
                            else{$row.Status=$decision}
                        }catch{$row.Status='Skipped';$row.Detail='File could not be safely removed; it may be locked, unavailable, or outside the approved boundary.'}
                    }
                }
                $fileResults.Add($row)
            }
            if($entries.Count -gt $remaining){$limitReached=$true}
        }catch{$scopeResults.Add([pscustomobject]@{Scope=$scope.Name;Path=$directory.Path;Status='Skipped';Detail=$_.Exception.Message})}
    }
    if($pending.Count -gt 0){$limitReached=$true}
}
$fileResults.ToArray() | Export-Csv -LiteralPath (Join-Path $reportDirectory 'files.csv') -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false
$scopeResults.ToArray() | Export-Csv -LiteralPath (Join-Path $reportDirectory 'scopes.csv') -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false
$summary=[pscustomobject]@{
    Script='Clear-TemporaryFiles';CollectedUtc=[datetime]::UtcNow.ToString('o');Apply=[bool]$Apply;OlderThanDays=$OlderThanDays
    CutoffUtc=$cutoff.ToString('o');EntriesInspected=$entriesInspected;FilesInspected=$inspected;FilesRemoved=@($fileResults | Where-Object Status -eq 'Removed').Count
    BytesRemoved=$removedBytes;MaxFiles=$MaxFiles;MaxDepth=$MaxDepth;LimitReached=$limitReached;ReportDirectory=$reportDirectory
    Notes=@('Only regular files in known Temp/cache folders are considered. No recursive directory deletion is used.','Downloads, Windows Installer, WinSxS, Prefetch, browser profiles/settings/cookies/password stores, and recycle bins are excluded.','Age is based on last-write time. Old files can still be in use; locked files are reported as skipped.','Browser cache inclusion requires all detected browser instances to be closed at inventory; keep them closed until completion.','Filesystem checks reduce path replacement risk; this is not intended for folders controlled by a hostile concurrent process.','Limits can leave uninspected files. Review scopes.csv and files.csv; repeat a plan if more coverage is needed.')
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $reportDirectory 'summary.json') -Encoding UTF8 -WhatIf:$false -Confirm:$false
$summary
