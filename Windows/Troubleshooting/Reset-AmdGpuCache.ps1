<#
What it does:
  Clears known AMD shader caches for the executing user, then requests a selected AMD GPU restart.

Available flags:
  -Apply: Make changes; default is a plan. -InstanceId <ids> or -AllAmdAdapters: Select multiple GPUs.
  -IncludeDirectXCache: Also clear this user's shared Windows D3DSCache. -SkipRestartPrompt: Defer restart.
  -MaxEntries (5000), -MaxDepth (8), -VerifyTimeoutSeconds (10): Bound scanning and device verification.
  -OutputDirectory: Default Windows\Reports. -WhatIf, -Confirm: Standard PowerShell controls.

How it works:
  Selects present AMD Display devices by PCI vendor ID 1002. Deletes only regular files inside five
  known cache folders, skipping reparse/changed/locked files. Saves reports before a separate driver
  restart confirmation, then uses PnPUtil for exact device IDs. Does not request a Windows reboot.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param(
    [switch]$Apply,
    [string[]]$InstanceId=@(),
    [switch]$AllAmdAdapters,
    [switch]$IncludeDirectXCache,
    [switch]$SkipRestartPrompt,
    [ValidateRange(1,100000)][int]$MaxEntries=5000,
    [ValidateRange(1,32)][int]$MaxDepth=8,
    [ValidateRange(1,30)][int]$VerifyTimeoutSeconds=10,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)

function Assert-AmdPlatform {
    if($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'Run native 64-bit Windows PowerShell 5.1.'}
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if(($os.ProductType -eq 1 -and [int]$os.BuildNumber -lt 22000) -or ($os.ProductType -ne 1 -and [int]$os.BuildNumber -notin @(20348,26100))){throw 'Supported targets are Windows 11 and Windows Server 2022/2025.'}
}
function Test-AmdAdministrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{(New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}finally{$identity.Dispose()}
}
function Get-AmdLocalAppData {
    $path=[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if(-not $path -or $path -notmatch '^[A-Za-z]:\\'){throw 'An executing-user local AppData folder could not be identified.'}
    [IO.Path]::GetFullPath($path).TrimEnd('\')
}
function Get-AmdAdapters {
    $devices=@(Get-PnpDevice -Class Display -PresentOnly -ErrorAction Stop)
    foreach($device in $devices){
        if($device.Class -ne 'Display' -or [string]$device.InstanceId -notmatch '^PCI\\VEN_1002(?:&|\\)'){continue}
        $problem=$null
        if($null -ne $device.Problem){try{$problem=[int]$device.Problem}catch{}}
        [pscustomobject]@{InstanceId=[string]$device.InstanceId;FriendlyName=[string]$device.FriendlyName;Status=[string]$device.Status;ProblemCode=$problem}
    }
}
function Select-AmdAdapters {
    param([object[]]$Devices,[string[]]$Ids,[bool]$All)
    if($All -and @($Ids).Count){throw 'Choose InstanceId or AllAmdAdapters, not both.'}
    if(-not @($Devices).Count){throw 'No present AMD PCI display adapter was found. No cache or device changes were made.'}
    if($All){return $Devices}
    if(@($Ids).Count){
        foreach($id in @($Ids | Sort-Object -Unique)){
            $match=@($Devices | Where-Object {$_.InstanceId -eq $id})
            if($match.Count -ne 1){throw 'Every InstanceId must exactly match one currently present AMD Display device. See adapters.csv.'}
        }
        return @($Devices | Where-Object {$Ids -contains $_.InstanceId})
    }
    if($Devices.Count -ne 1){throw 'Multiple AMD GPUs are present. Choose exact InstanceId values or AllAmdAdapters; see adapters.csv. No changes were made.'}
    $Devices[0]
}
function Get-AmdCacheRoots {
    param([string]$LocalAppData,[bool]$IncludeDirectX)
    if($LocalAppData -notmatch '^[A-Za-z]:\\'){throw 'Only a local AppData path is supported.'}
    foreach($name in @('DxCache','DxcCache','GLCache','VkCache','DX9Cache')){
        [pscustomobject]@{Name=('AMD '+$name);Path=(Join-Path $LocalAppData ('AMD\'+$name))}
    }
    if($IncludeDirectX){[pscustomobject]@{Name='Shared Windows DirectX';Path=(Join-Path $LocalAppData 'D3DSCache')}}
}
function Assert-AmdCacheBoundary {
    param([string]$Path,[string]$Root,[switch]$File)
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\');$approved=[IO.Path]::GetFullPath($Root).TrimEnd('\')
    if($full -notmatch '^[A-Za-z]:\\' -or $approved -notmatch '^[A-Za-z]:\\'){throw 'Only local filesystem paths are supported.'}
    $same=[string]::Equals($full,$approved,[StringComparison]::OrdinalIgnoreCase)
    if(-not $same -and -not $full.StartsWith($approved+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'A path escaped the selected cache folder.'}
    if($File -and $same){throw 'A cache directory cannot be deleted.'}
    $cursor=$full
    while($cursor){
        $entry=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse-point ancestry is excluded.'}
        $parent=[IO.Directory]::GetParent($cursor)
        if($null -eq $parent){break};$cursor=$parent.FullName
    }
    $leaf=Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if($File -and $leaf.PSIsContainer){throw 'Directory deletion is prohibited.'}
    if(-not $File -and -not $leaf.PSIsContainer){throw 'Cache scan target must be a directory.'}
    $leaf
}
function Get-AmdCacheInventory {
    param([object[]]$Roots,[int]$EntryLimit,[int]$DepthLimit)
    $items=New-Object 'System.Collections.Generic.List[object]';$scopes=New-Object 'System.Collections.Generic.List[object]'
    $inspected=0;$limit=$false
    foreach($root in $Roots){
        if($inspected -ge $EntryLimit){$limit=$true;break}
        try{
            if(-not (Test-Path -LiteralPath $root.Path)){$scopes.Add([pscustomobject]@{Cache=$root.Name;Path=$root.Path;Status='NotPresent';Detail='No directory at this known location.'});continue}
            $null=Assert-AmdCacheBoundary $root.Path $root.Path
            $scopes.Add([pscustomobject]@{Cache=$root.Name;Path=$root.Path;Status='Included';Detail='Executing-user cache; shared by this account across AMD adapters.'})
            $pending=New-Object 'System.Collections.Generic.Stack[object]'
            $pending.Push([pscustomobject]@{Path=$root.Path;Depth=0})
            while($pending.Count -gt 0 -and $inspected -lt $EntryLimit){
                $node=$pending.Pop()
                try{
                    $null=Assert-AmdCacheBoundary $node.Path $root.Path
                    $remaining=$EntryLimit-$inspected
                    $entries=@(Get-ChildItem -LiteralPath $node.Path -Force -ErrorAction Stop | Select-Object -First ($remaining+1))
                    foreach($entry in $entries){
                        if($inspected -ge $EntryLimit){$limit=$true;break}
                        $inspected++
                        if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){$scopes.Add([pscustomobject]@{Cache=$root.Name;Path=$entry.FullName;Status='SkippedReparsePoint';Detail='Not followed or removed.'});continue}
                        if($entry.PSIsContainer){
                            if($node.Depth -lt $DepthLimit){$pending.Push([pscustomobject]@{Path=$entry.FullName;Depth=($node.Depth+1)})}
                            else{$limit=$true;$scopes.Add([pscustomobject]@{Cache=$root.Name;Path=$entry.FullName;Status='DepthLimit';Detail='Descendants uninspected.'})}
                        }else{
                            $items.Add([pscustomobject]@{Path=$entry.FullName;Root=$root.Path;Cache=$root.Name;Bytes=[int64]$entry.Length;LastWriteUtc=$entry.LastWriteTimeUtc;CreationUtc=$entry.CreationTimeUtc;Status='Planned';Detail=''})
                        }
                    }
                    if($entries.Count -gt $remaining){$limit=$true}
                }catch{$scopes.Add([pscustomobject]@{Cache=$root.Name;Path=$node.Path;Status='Unknown';Detail='Directory unreadable or unsafe; no files removed from this scan.'})}
            }
            if($pending.Count -gt 0){$limit=$true}
        }catch{$scopes.Add([pscustomobject]@{Cache=$root.Name;Path=$root.Path;Status='Unknown';Detail='Known cache folder is unreadable or has reparse-point ancestry.'})}
    }
    [pscustomobject]@{Items=$items.ToArray();Scopes=$scopes.ToArray();EntriesInspected=$inspected;LimitReached=$limit}
}
function Get-AmdCacheFileDecision {
    param([IO.FileInfo]$Current,[object]$Observed)
    if($Current.Length -ne $Observed.Bytes -or $Current.LastWriteTimeUtc -ne $Observed.LastWriteUtc -or $Current.CreationTimeUtc -ne $Observed.CreationUtc){return 'SkippedChanged'}
    'Eligible'
}
function Invoke-AmdPnpRestart {
    param([string]$Id,[string]$OutputPath)
    $native=Join-Path $env:WINDIR 'System32\pnputil.exe'
    if(-not (Test-Path -LiteralPath $native -PathType Leaf)){throw 'Windows PnPUtil is unavailable.'}
    $saved=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';$global:LASTEXITCODE=$null;$output=@(& $native @('/restart-device',$Id) 2>&1 | ForEach-Object {[string]$_});$code=$LASTEXITCODE}finally{$ErrorActionPreference=$saved}
    [IO.File]::WriteAllLines($OutputPath,[string[]]$output,(New-Object Text.UTF8Encoding($false)))
    [pscustomobject]@{ExitCode=$code;OutputFile=[IO.Path]::GetFileName($OutputPath)}
}
function Wait-AmdAdapterReady {
    param([string]$Id,[int]$TimeoutSeconds)
    $watch=[Diagnostics.Stopwatch]::StartNew();$last=$null
    do{
        try{$last=@(Get-AmdAdapters | Where-Object {$_.InstanceId -eq $Id}) | Select-Object -First 1}catch{$last=$null}
        if($null -ne $last -and $last.Status -eq 'OK' -and $null -ne $last.ProblemCode -and $last.ProblemCode -eq 0){return [pscustomobject]@{Status=$last.Status;ProblemCode=$last.ProblemCode;Assessment='PresentPnPStatusVerified'}}
        if($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds){break}
        Start-Sleep -Milliseconds 500
    }while($true)
    [pscustomobject]@{Status=$(if($last){$last.Status}else{'Unknown'});ProblemCode=$(if($last){$last.ProblemCode}else{$null});Assessment='UnknownAfterRestart'}
}
function Confirm-AmdDriverRestart {
    param([Management.Automation.PSCmdlet]$Cmdlet,[string]$TargetNames)
    try{$Cmdlet.ShouldContinue(('Restart these AMD graphics devices now: {0}? Displays may go blank and GPU applications or remote sessions may disconnect. Save your work first.' -f $TargetNames),'Separate graphics-driver restart confirmation')}catch{$false}
}
function Save-AmdGpuReport {
    param([string]$Directory,[object]$Summary,[object[]]$Adapters,[object[]]$Files,[object[]]$Scopes,[object[]]$Actions)
    foreach($dataset in @(
        @{Name='adapters';Rows=$Adapters;Columns=@('InstanceId','FriendlyName','Status','ProblemCode')},
        @{Name='cache-files';Rows=$Files;Columns=@('Path','Root','Cache','Bytes','LastWriteUtc','CreationUtc','Status','Detail')},
        @{Name='cache-scopes';Rows=$Scopes;Columns=@('Cache','Path','Status','Detail')},
        @{Name='driver-actions';Rows=$Actions;Columns=@('InstanceId','Status','ExitCode','OutputFile','ProblemCodeAfter','Detail')}
    )){
        $target=Join-Path $Directory ($dataset.Name+'.csv')
        if(@($dataset.Rows).Count){$dataset.Rows | Select-Object $dataset.Columns | Export-Csv -LiteralPath $target -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false}
        else{[IO.File]::WriteAllText($target,(($dataset.Columns | ForEach-Object {'"'+$_+'"'}) -join ',')+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))}
    }
    [IO.File]::WriteAllText((Join-Path $Directory 'summary.json'),($Summary | ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
}
function Invoke-AmdGpuCacheReset {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
    param(
        [switch]$Apply,[string[]]$InstanceId=@(),[switch]$AllAmdAdapters,[switch]$IncludeDirectXCache,[switch]$SkipRestartPrompt,
        [ValidateRange(1,100000)][int]$MaxEntries=5000,[ValidateRange(1,32)][int]$MaxDepth=8,
        [ValidateRange(1,30)][int]$VerifyTimeoutSeconds=10,[ValidateNotNullOrEmpty()][string]$OutputDirectory
    )
    Assert-AmdPlatform
    if($AllAmdAdapters -and $InstanceId.Count){throw 'Choose InstanceId or AllAmdAdapters, not both.'}
    if($Apply -and -not $WhatIfPreference -and -not (Test-AmdAdministrator)){throw 'Run elevated to apply cache cleanup and the graphics-device restart.'}
    $roots=@(Get-AmdCacheRoots -LocalAppData (Get-AmdLocalAppData) -IncludeDirectX ([bool]$IncludeDirectXCache))
    if(-not $OutputDirectory){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
    $directory=[IO.Path]::GetFullPath((Join-Path $OutputDirectory ('Reset-AmdGpuCache-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),[guid]::NewGuid().ToString('N').Substring(0,8))))
    foreach($root in $roots){$cacheRoot=[IO.Path]::GetFullPath($root.Path).TrimEnd('\');if($directory.StartsWith($cacheRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Reports must be outside the cache folders being cleared.'}}
    $null=[IO.Directory]::CreateDirectory($directory)
    $adapters=@();$files=@();$scopes=@();$actions=New-Object 'System.Collections.Generic.List[object]'
    $summary=[ordered]@{Script='Reset-AmdGpuCache';CollectedUtc=[datetime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;ExecutingUser=[Environment]::UserName;Mode=$(if($WhatIfPreference){'WhatIf'}elseif($Apply){'Apply'}else{'Plan'});RunStatus='Initializing';SelectedInstanceIds=@();EntriesInspected=0;LimitReached=$false;FilesRemoved=0;BytesRemoved=[int64]0;RestartStatus='Planned';WindowsRebootRequested=$false;Error='';ReportDirectory=$directory;Notes=@('Close games and GPU applications before applying. Locked or changing files are skipped; caches may rebuild immediately.','Cache locations belong to the executing account and are shared across its AMD adapters. Device selection controls restart scope, not per-adapter cache separation.','Optional D3DSCache is a shared Windows cache and may include other GPU vendors.','No cache directories, driver packages, settings/profiles, game caches, or application data outside the explicit cache allowlist are deleted.','Only an exact AMD PCI Display device is restarted with PnPUtil. No disable/enable fallback, driver uninstall, global hotkey reset, force flag, or Windows reboot is requested.','PnP status verification does not establish successful 3D rendering or complete removal of in-memory cache state.','Path/metadata checks support routine maintenance of trusted local folders; they do not eliminate hostile concurrent filesystem races.')}
    try{
        $adapters=@(Get-AmdAdapters)
        Save-AmdGpuReport $directory $summary $adapters $files $scopes $actions.ToArray()
        $selected=@(Select-AmdAdapters -Devices $adapters -Ids $InstanceId -All ([bool]$AllAmdAdapters))
        $summary.SelectedInstanceIds=@($selected | ForEach-Object {$_.InstanceId})
        foreach($device in $selected){$actions.Add([pscustomobject]@{InstanceId=$device.InstanceId;Status='Planned';ExitCode=$null;OutputFile='';ProblemCodeAfter=$null;Detail='Separate restart confirmation required.'})}
        $inventory=Get-AmdCacheInventory -Roots $roots -EntryLimit $MaxEntries -DepthLimit $MaxDepth
        $files=@($inventory.Items);$scopes=@($inventory.Scopes);$summary.EntriesInspected=$inventory.EntriesInspected;$summary.LimitReached=$inventory.LimitReached
        $summary.RunStatus='Plan'
        Save-AmdGpuReport $directory $summary $adapters $files $scopes $actions.ToArray()
        if($Apply){
            foreach($file in $files){
                if($PSCmdlet.ShouldProcess($file.Path,'Remove AMD/selected Windows shader-cache file')){
                    try{
                        $current=Assert-AmdCacheBoundary -Path $file.Path -Root $file.Root -File
                        $decision=Get-AmdCacheFileDecision -Current $current -Observed $file
                        if($decision -eq 'Eligible'){Remove-Item -LiteralPath $current.FullName -Force -ErrorAction Stop;$file.Status='Removed';$summary.FilesRemoved++;$summary.BytesRemoved+=$file.Bytes}
                        else{$file.Status=$decision}
                    }catch{$file.Status='Skipped';$file.Detail='Locked, unreadable, removed concurrently, or failed a boundary check.'}
                }else{$file.Status='NotExecuted'}
            }
            $summary.RunStatus='CachePassComplete';$summary.RestartStatus='PendingSeparateConfirmation'
            Save-AmdGpuReport $directory $summary $adapters $files $scopes $actions.ToArray()
            if($SkipRestartPrompt){$summary.RestartStatus='Deferred';foreach($action in $actions){$action.Status='DeferredByFlag'}}
            elseif(-not $PSCmdlet.ShouldProcess(($summary.SelectedInstanceIds -join '; '),'Restart selected AMD graphics device(s)')){$summary.RestartStatus='NotExecuted';foreach($action in $actions){$action.Status='NotExecuted'}}
            elseif(-not (Confirm-AmdDriverRestart -Cmdlet $PSCmdlet -TargetNames (($selected | ForEach-Object {$_.FriendlyName}) -join '; '))){$summary.RestartStatus='Deferred';foreach($action in $actions){$action.Status='DeferredNoConsent'}}
            else{
                $summary.RestartStatus='Attempted';$halt=$false;$ordinal=0
                foreach($action in $actions){
                    if($halt){$action.Status='SkippedAfterUnresolvedRestart';continue}
                    try{
                        $present=@(Get-AmdAdapters | Where-Object {$_.InstanceId -eq $action.InstanceId})
                        if($present.Count -ne 1){$action.Status='DeferredDeviceChanged';$action.Detail='Selected AMD device is no longer present; no restart attempted.';continue}
                        $ordinal++;$action.Status='RestartPending'
                        Save-AmdGpuReport $directory $summary $adapters $files $scopes $actions.ToArray()
                        $native=Invoke-AmdPnpRestart -Id $action.InstanceId -OutputPath (Join-Path $directory ('pnputil-{0}.txt' -f $ordinal))
                        $action.ExitCode=$native.ExitCode;$action.OutputFile=$native.OutputFile
                        if($native.ExitCode -eq 3010){$action.Status='WindowsRestartRequired';$action.Detail='Native result requires a later separately authorized Windows restart. None was requested.';$halt=$true}
                        elseif($null -eq $native.ExitCode -or $native.ExitCode -ne 0){$action.Status='Failed';$action.Detail='Review native output; no disable/enable fallback performed.';$halt=$true}
                        else{
                            $after=Wait-AmdAdapterReady -Id $action.InstanceId -TimeoutSeconds $VerifyTimeoutSeconds
                            $action.ProblemCodeAfter=$after.ProblemCode;$action.Status=$after.Assessment
                            $action.Detail='Native restart returned success; verification concerns PnP presence/status only.'
                            if($after.Assessment -ne 'PresentPnPStatusVerified'){$halt=$true}
                        }
                    }catch{$action.Status='Failed';$action.Detail='Restart or device verification failed. Review target state before retrying.';$halt=$true}
                    Save-AmdGpuReport $directory $summary $adapters $files $scopes $actions.ToArray()
                }
                if(@($actions | Where-Object Status -eq 'WindowsRestartRequired').Count){$summary.RestartStatus='WindowsRestartRequired'}
                elseif(@($actions | Where-Object {$_.Status -ne 'PresentPnPStatusVerified'}).Count){$summary.RestartStatus='IncompleteOrFailed'}
                else{$summary.RestartStatus='PresentPnPStatusVerified'}
            }
            $summary.RunStatus='CompletedReviewResults'
        }
    }catch{$summary.RunStatus='Failed';$summary.Error=$_.Exception.Message;throw}
    finally{Save-AmdGpuReport $directory $summary $adapters $files $scopes $actions.ToArray()}
    [pscustomobject]$summary
}

if($MyInvocation.InvocationName -ne '.') { Invoke-AmdGpuCacheReset @PSBoundParameters }
