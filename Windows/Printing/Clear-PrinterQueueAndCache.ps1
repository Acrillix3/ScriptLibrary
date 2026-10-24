<#
What it does:
  Plans or clears selected local print queues and optionally the default spool cache.

Available flags:
  -PrinterName: Exact local queue names, or use -AllPrinters explicitly.
  -ClearSpoolCache: Also remove SPL/SHD spool files; requires AllPrinters.
  -Apply: Perform approved actions. Default is a plan. -SkipRestartPrompt: Defer cache work
  that needs a Spooler stop/start. -OutputDirectory: Report location. -WhatIf, -Confirm.

How it works:
  Cancels only discovered job IDs, without exporting document names. Cache clearing requires
  elevation, the default spool folder, no reparse points, and a separate confirmation before
  stopping a running Spooler. Restores its original running state; never removes drivers.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param(
    [string[]]$PrinterName,[switch]$AllPrinters,[switch]$ClearSpoolCache,
    [switch]$Apply,[switch]$SkipRestartPrompt,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
if(($AllPrinters -and $PrinterName) -or (-not $AllPrinters -and -not $PrinterName)){throw 'Choose exact PrinterName values or AllPrinters.'}
if($ClearSpoolCache -and -not $AllPrinters){throw 'ClearSpoolCache affects all local queues and requires AllPrinters.'}
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$runName='Clear-PrinterQueueAndCache-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),[guid]::NewGuid().ToString('N').Substring(0,8)
$reportDirectory=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force -WhatIf:$false -Confirm:$false).FullName
$results=New-Object 'System.Collections.Generic.List[object]'
$cacheStatus='NotRequested'
function Add-PrintResult {
    param([string]$Kind,[string]$Target,[string]$Status,[string]$Detail)
    $results.Add([pscustomobject]@{Kind=$Kind;Target=$Target;Status=$Status;Detail=$Detail})
}
function Assert-SpoolPath {
    param([string]$Path,[string]$ExpectedRoot,[switch]$File)
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root=[IO.Path]::GetFullPath($ExpectedRoot).TrimEnd('\')
    if($File){if(-not [string]::Equals([IO.Path]::GetDirectoryName($full),$root,[StringComparison]::OrdinalIgnoreCase)){throw 'Spool file is outside the approved folder.'}}
    elseif(-not [string]::Equals($full,$root,[StringComparison]::OrdinalIgnoreCase)){throw 'Only the default canonical spool folder is supported.'}
    $cursor=$full
    while($cursor){
        $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Spool path contains a reparse point.'}
        $parent=[IO.Directory]::GetParent($cursor)
        if($null -eq $parent){break};$cursor=$parent.FullName
    }
    $leaf=Get-Item -LiteralPath $full -Force
    if($File -and ($leaf.PSIsContainer -or $leaf.Extension.ToLowerInvariant() -notin @('.spl','.shd'))){throw 'Only regular SPL and SHD files can be removed.'}
    $full
}
function Assert-DefaultSpoolConfiguration {
    param([string]$ExpectedRoot)
    $printKey='HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers'
    $global=Get-ItemProperty -LiteralPath $printKey -ErrorAction Stop
    $configured=[string]$global.DefaultSpoolDirectory
    if($configured){
        $expanded=[Environment]::ExpandEnvironmentVariables($configured)
        if(-not [string]::Equals([IO.Path]::GetFullPath($expanded).TrimEnd('\'),$ExpectedRoot.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Custom default spool directory detected; cache clearing is blocked.'}
    }
    foreach($key in @(Get-ChildItem -LiteralPath $printKey -ErrorAction Stop)){
        $custom=[string](Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop).SpoolDirectory
        if($custom){
            $expanded=[Environment]::ExpandEnvironmentVariables($custom)
            if(-not [string]::Equals([IO.Path]::GetFullPath($expanded).TrimEnd('\'),$ExpectedRoot.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)){throw 'A printer has a custom spool directory; cache clearing is blocked.'}
        }
    }
}
function Assert-PrintAdministrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Spool cache clearing requires an elevated administrator session.'}
}
function Invoke-SpoolCacheCleanup {
    param([string]$SpoolRoot,[bool]$RestoreRunningState)
    $stoppedByThisRun=$false
    try{
        if($RestoreRunningState){$stoppedByThisRun=$true;Stop-Service -Name Spooler -ErrorAction Stop}
        $state=Get-Service -Name Spooler -ErrorAction Stop
        if($state.Status -ne 'Stopped'){throw 'Spooler is not stopped; no cache files will be removed.'}
        $null=Assert-SpoolPath $SpoolRoot $SpoolRoot
        foreach($file in @(Get-ChildItem -LiteralPath $SpoolRoot -File -Force -ErrorAction Stop | Where-Object {$_.Extension.ToLowerInvariant() -in @('.spl','.shd')})){
            try{
                $approved=Assert-SpoolPath $file.FullName $SpoolRoot -File
                if($PSCmdlet.ShouldProcess($approved,'Remove spool job cache file')){Remove-Item -LiteralPath $approved -Force -ErrorAction Stop;Add-PrintResult 'CacheFile' $file.Name 'Removed' ''}
                else{Add-PrintResult 'CacheFile' $file.Name 'NotExecuted' ''}
            }catch{Add-PrintResult 'CacheFile' $file.Name 'Skipped' $_.Exception.Message}
        }
    }finally{
        if($stoppedByThisRun){
            try{Start-Service -Name Spooler -ErrorAction Stop;Add-PrintResult 'Service' 'Spooler' 'RunningStateRestored' ''}
            catch{Add-PrintResult 'Service' 'Spooler' 'RestoreFailed' $_.Exception.Message;Write-Warning 'Spooler could not be restored; review the report and start it manually.'}
        }
    }
}
$failure=''
try{
    if($env:OS -ne 'Windows_NT'){throw 'This script supports Windows only.'}
    Import-Module PrintManagement -ErrorAction Stop
    $available=@(Get-Printer -ErrorAction Stop)
    if($AllPrinters){$selected=$available}else{
        $selected=@(foreach($requested in $PrinterName){
            $match=@($available | Where-Object {[string]::Equals($_.Name,$requested,[StringComparison]::OrdinalIgnoreCase)})
            if($match.Count -ne 1){throw ('Exact printer name was not found uniquely: '+$requested)}
            $match[0]
        })
        $selected=@($selected | Sort-Object Name -Unique)
    }
    foreach($printer in $selected){
        try{
            $jobs=@(Get-PrintJob -PrinterName $printer.Name -ErrorAction Stop)
            Add-PrintResult 'Queue' $printer.Name 'Collected' ('JobCount='+$jobs.Count)
            foreach($job in $jobs){
                $target='{0}; Job ID {1}' -f $printer.Name,$job.ID
                if($Apply -and $PSCmdlet.ShouldProcess($target,'Cancel print job')){
                    try{Remove-PrintJob -PrinterName $printer.Name -ID $job.ID -ErrorAction Stop;Add-PrintResult 'Job' $target 'Cancelled' ''}
                    catch{Add-PrintResult 'Job' $target 'Failed' $_.Exception.Message}
                }else{Add-PrintResult 'Job' $target 'PlannedOrNotExecuted' ''}
            }
        }catch{Add-PrintResult 'Queue' $printer.Name 'Unknown' 'Job inventory failed; document content was not collected.'}
    }
    if($ClearSpoolCache){
        $spoolRoot=[IO.Path]::GetFullPath((Join-Path $env:WINDIR 'System32\spool\PRINTERS')).TrimEnd('\')
        $null=Assert-SpoolPath $spoolRoot $spoolRoot
        Assert-DefaultSpoolConfiguration $spoolRoot
        $service=Get-Service -Name Spooler -ErrorAction Stop
        if($service.Status -notin @('Running','Stopped')){throw 'Spooler is transitioning; wait for a stable state and run again.'}
        $cacheStatus='Planned'
        if($Apply -and $PSCmdlet.ShouldProcess($spoolRoot,'Clear all SPL/SHD files; stop and restore Spooler if it is running')){
            Assert-PrintAdministrator
            if($service.Status -eq 'Running' -and $SkipRestartPrompt){$cacheStatus='DeferredRestartPromptSkipped'}
            elseif($service.Status -eq 'Running' -and -not $PSCmdlet.ShouldContinue('Cache clearing stops and restarts Print Spooler and interrupts all local print queues. Continue with this service restart?','Separate service restart confirmation')){$cacheStatus='DeferredConfirmationDeclined'}
            else{Invoke-SpoolCacheCleanup $spoolRoot ($service.Status -eq 'Running');$cacheStatus='ExecutedReviewResults'}
        }
    }
}catch{$failure=$_.Exception.Message;if($ClearSpoolCache){$cacheStatus='Blocked'};Add-PrintResult 'Run' 'Local computer' 'Failed' $failure}
$results.ToArray() | Export-Csv -LiteralPath (Join-Path $reportDirectory 'actions.csv') -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false
$summary=[pscustomobject]@{
    Script='Clear-PrinterQueueAndCache';CollectedUtc=[datetime]::UtcNow.ToString('o');Apply=[bool]$Apply
    AllPrinters=[bool]$AllPrinters;PrinterName=$PrinterName;CacheStatus=$cacheStatus;Error=$failure;Actions=$results.ToArray();ReportDirectory=$reportDirectory
    Notes=@('No document names or spool contents were exported. Cache deletion removes queued print data for all local printers.','Custom spool paths and reparse points block cache clearing. Driver caches and printer drivers are not touched.','The separate Spooler confirmation is required even with Confirm:$false. SkipRestartPrompt defers cache clearing when Spooler is running.','Starting the service in finally restores the running state explicitly approved before stopping it. Concurrent service configuration changes are outside this script control.')
}
$summary | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $reportDirectory 'summary.json') -Encoding UTF8 -WhatIf:$false -Confirm:$false
$summary
