<#
What it does:
  Tests repair, spooler, and cleanup safety using isolated mocks and temporary fixtures.

Available flags:
  -ScriptRoot: Staged Windows folder. -OutputDirectory: Test fixture/report destination.

How it works:
  Never invokes DISM/SFC, printer mutation, or a real service restart. Uses copied script
  text with named dependencies replaced and confines cleanup fixtures to this test folder.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$ScriptRoot,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $ScriptRoot){$ScriptRoot=Split-Path -Parent $PSScriptRoot;if(-not (Test-Path -LiteralPath (Join-Path $ScriptRoot 'Troubleshooting\Repair-WindowsSystemFiles.ps1'))){$ScriptRoot=Join-Path $PSScriptRoot '..\staged\Windows'}}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $PSScriptRoot ('runs\'+[guid]::NewGuid().ToString('N').Substring(0,8))}
$OutputDirectory=(New-Item -ItemType Directory -Path $OutputDirectory -Force).FullName
$script:checks=0
function Assert-Check {param([bool]$Condition,[string]$Message) if(-not $Condition){throw ('FAILED: '+$Message)};$script:checks++}
function Get-TestSource {param([string]$Relative) Get-Content -LiteralPath (Join-Path $ScriptRoot $Relative) -Raw}
function Replace-Function {
    param([string]$Text,[string]$Name,[string]$Replacement)
    $tokens=$null;$errors=$null;$ast=[System.Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
    if($errors){throw 'Test source did not parse.'}
    $node=$ast.Find({param($n)$n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name},$true)
    if(-not $node){throw ('Test function was not found: '+$Name)}
    $Text.Substring(0,$node.Extent.StartOffset)+$Replacement+$Text.Substring($node.Extent.EndOffset)
}
function Invoke-RepairCase {
    param([int[]]$Codes,[hashtable]$Arguments)
    $text=Get-TestSource 'Troubleshooting\Repair-WindowsSystemFiles.ps1'
    $text=Replace-Function $text 'Assert-NativeAdministrator' 'function Assert-NativeAdministrator {}'
    $text=Replace-Function $text 'Invoke-SystemFileUtility' @'
function Invoke-SystemFileUtility {
    param([string]$Executable,[string[]]$Arguments,[string]$Label)
    $script:NativeCalls.Add($Executable)
    $code=$script:NativeCodes.Dequeue()
    [pscustomobject]@{Utility=$Executable;Arguments=($Arguments -join ' ');ExitCode=$code;Assessment='ReviewNativeOutput';OutputFile='mock.txt'}
}
'@
    $module=New-Module -ScriptBlock {
        function Run-Case {
            param($Text,$Codes,$Arguments)
            $script:NativeCalls=New-Object 'System.Collections.Generic.List[string]'
            $script:NativeCodes=New-Object 'System.Collections.Generic.Queue[int]'
            foreach($code in $Codes){$script:NativeCodes.Enqueue($code)}
            $result=& ([scriptblock]::Create($Text)) @Arguments
            [pscustomobject]@{Result=$result;Calls=$script:NativeCalls.ToArray()}
        }
        function Restart-Computer {throw 'A test attempted a reboot.'}
        Export-ModuleMember -Function Run-Case
    }
    & $module {param($Text,$Codes,$Arguments)Run-Case $Text $Codes $Arguments} $text $Codes $Arguments
}
$base=@{Apply=$true;SkipRestartPrompt=$true;LogTailLines=0;Confirm=$false;OutputDirectory=(Join-Path $OutputDirectory 'repair')}
$failed=Invoke-RepairCase @(5) $base
Assert-Check (@($failed.Calls).Count -eq 1 -and $failed.Calls[0] -eq 'dism.exe') 'Failed DISM must skip SFC.'
Assert-Check ($failed.Result.RunStatus -eq 'NativeFailed') 'Failed DISM must classify the overall run as NativeFailed.'
$pending=Invoke-RepairCase @(3010) $base
Assert-Check (@($pending.Calls).Count -eq 1) 'DISM restart required must defer SFC.'
$pendingSummary=Get-Content -LiteralPath (Join-Path $pending.Result.ReportDirectory 'summary.json') -Raw | ConvertFrom-Json
Assert-Check ([bool]$pendingSummary.RestartRequired) 'Exit 3010 must persist a restart requirement.'
Assert-Check ($pendingSummary.RestartStatus -eq 'RequiredDeferred') 'SkipRestartPrompt must defer a required reboot.'
$success=Invoke-RepairCase @(0,0) $base
Assert-Check (@($success.Calls).Count -eq 2 -and $success.Calls[1] -eq 'sfc.exe') 'Successful DISM must be followed by SFC.'
$whatIfArgs=$base.Clone();$whatIfArgs.WhatIf=$true
$preview=Invoke-RepairCase @(0,0) $whatIfArgs
Assert-Check (@($preview.Calls).Count -eq 0) 'WhatIf must skip all native integrity utilities.'
$plan=Invoke-RepairCase @(0,0) @{OutputDirectory=(Join-Path $OutputDirectory 'repair-plan');LogTailLines=0}
Assert-Check (@($plan.Calls).Count -eq 0) 'Default repair mode must be a plan.'

function Invoke-PrintCase {
    param([hashtable]$Arguments,[bool]$Consent=$true)
    $text=Get-TestSource 'Printing\Clear-PrinterQueueAndCache.ps1'
    $text=Replace-Function $text 'Assert-SpoolPath' 'function Assert-SpoolPath {param($Path,$ExpectedRoot,[switch]$File) $Path}'
    $text=Replace-Function $text 'Assert-DefaultSpoolConfiguration' 'function Assert-DefaultSpoolConfiguration {}'
    $text=Replace-Function $text 'Assert-PrintAdministrator' 'function Assert-PrintAdministrator {}'
    $answer=if($Consent){'$true'}else{'$false'}
    $text=$text.Replace("`$PSCmdlet.ShouldContinue('Cache clearing stops and restarts Print Spooler and interrupts all local print queues. Continue with this service restart?','Separate service restart confirmation')",$answer)
    $module=New-Module -ScriptBlock {
        function Run-Case {
            param($Text,$Arguments)
            $script:StopCount=0;$script:StartCount=0;$script:DeleteCount=0;$script:JobCount=0
            $result=& ([scriptblock]::Create($Text)) @Arguments
            [pscustomobject]@{Result=$result;Stops=$script:StopCount;Starts=$script:StartCount;Deletes=$script:DeleteCount;Jobs=$script:JobCount}
        }
        function Import-Module {}
        function Get-Printer {[pscustomobject]@{Name='Fixture printer'}}
        function Get-PrintJob {[pscustomobject]@{ID=17;DocumentName='MUST NOT EXPORT'}}
        function Remove-PrintJob {$script:JobCount++}
        function Get-Service {[pscustomobject]@{Status=$(if($script:StopCount -gt $script:StartCount){'Stopped'}else{'Running'})}}
        function Stop-Service {$script:StopCount++}
        function Start-Service {$script:StartCount++}
        function Remove-Item {$script:DeleteCount++}
        function Get-ChildItem {[pscustomobject]@{FullName='C:\WINDOWS\System32\spool\PRINTERS\fixture.SPL';Name='fixture.SPL';Extension='.SPL'}}
        Export-ModuleMember -Function Run-Case
    }
    & $module {param($Text,$Arguments)Run-Case $Text $Arguments} $text $Arguments
}
$deferred=Invoke-PrintCase @{Apply=$true;AllPrinters=$true;ClearSpoolCache=$true;SkipRestartPrompt=$true;Confirm=$false;OutputDirectory=(Join-Path $OutputDirectory 'print')}
Assert-Check ($deferred.Stops -eq 0 -and $deferred.Starts -eq 0 -and $deferred.Deletes -eq 0) 'Deferred Spooler restart must not stop/start/delete cache.'
Assert-Check ($deferred.Result.CacheStatus -eq 'DeferredRestartPromptSkipped') 'Skipped restart prompt must be reported as deferred.'
Assert-Check ($deferred.Jobs -eq 1) 'Explicitly requested job cancellation remains independent from deferred cache cleanup.'
Assert-Check ((Get-Content -LiteralPath (Join-Path $deferred.Result.ReportDirectory 'actions.csv') -Raw) -notmatch 'MUST NOT EXPORT') 'Print reports must omit document names.'
$printPreview=Invoke-PrintCase @{Apply=$true;AllPrinters=$true;ClearSpoolCache=$true;WhatIf=$true;Confirm=$false;OutputDirectory=(Join-Path $OutputDirectory 'print-preview')}
Assert-Check ($printPreview.Stops -eq 0 -and $printPreview.Starts -eq 0 -and $printPreview.Deletes -eq 0 -and $printPreview.Jobs -eq 0) 'Print WhatIf must suppress every printer/service mutation.'
$printAllowed=Invoke-PrintCase @{Apply=$true;AllPrinters=$true;ClearSpoolCache=$true;Confirm=$false;OutputDirectory=(Join-Path $OutputDirectory 'print-approved')}
Assert-Check ($printAllowed.Stops -eq 1 -and $printAllowed.Starts -eq 1 -and $printAllowed.Deletes -eq 1) 'Approved cache cleanup must stop, remove the mock spool file, and restore Spooler exactly once.'
$printDeclined=Invoke-PrintCase @{Apply=$true;AllPrinters=$true;ClearSpoolCache=$true;Confirm=$false;OutputDirectory=(Join-Path $OutputDirectory 'print-declined')} $false
Assert-Check ($printDeclined.Stops -eq 0 -and $printDeclined.Starts -eq 0 -and $printDeclined.Deletes -eq 0) 'Declining separate service consent must defer all cache/service changes even with Confirm false.'
Assert-Check ($printDeclined.Result.CacheStatus -eq 'DeferredConfirmationDeclined') 'Declined Spooler confirmation must be reported.'

$tempText=Get-TestSource 'Storage-and-Permissions\Clear-TemporaryFiles.ps1'
$fixtureProfile=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory 'fixture-profile') -Force).FullName
$fixtureTemp=(New-Item -ItemType Directory -Path (Join-Path $fixtureProfile 'AppData\Local\Temp') -Force).FullName
$oldPath=Join-Path $fixtureTemp 'old.tmp';$newPath=Join-Path $fixtureTemp 'recent.tmp'
Set-Content -LiteralPath $oldPath -Value 'old fixture';Set-Content -LiteralPath $newPath -Value 'new fixture'
[IO.File]::SetLastWriteTimeUtc($oldPath,[datetime]::UtcNow.AddDays(-30))
$tempText=$tempText.Replace('[Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)',("'"+$fixtureProfile.Replace("'","''")+"'"))
$tempPlan=& ([scriptblock]::Create($tempText)) -OutputDirectory (Join-Path $OutputDirectory 'temp-plan')
Assert-Check ((Test-Path -LiteralPath $oldPath) -and $tempPlan.FilesRemoved -eq 0) 'Default cleanup must preserve eligible old files.'
$tempPreview=& ([scriptblock]::Create($tempText)) -Apply -WhatIf -Confirm:$false -OutputDirectory (Join-Path $OutputDirectory 'temp-preview')
Assert-Check ((Test-Path -LiteralPath $oldPath) -and $tempPreview.FilesRemoved -eq 0) 'Cleanup WhatIf must preserve eligible old files.'
$tempApply=& ([scriptblock]::Create($tempText)) -Apply -Confirm:$false -OutputDirectory (Join-Path $OutputDirectory 'temp-apply')
Assert-Check (-not (Test-Path -LiteralPath $oldPath) -and (Test-Path -LiteralPath $newPath)) 'Cleanup Apply must remove the old fixture and preserve the recent fixture.'
Assert-Check ($tempApply.FilesRemoved -eq 1) 'Cleanup must report the exact fixture deletion count.'

$tokens=$null;$errors=$null;$tempAst=[System.Management.Automation.Language.Parser]::ParseInput($tempText,[ref]$tokens,[ref]$errors)
$boundary=$tempAst.Find({param($n)$n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-CleanupBoundary'},$true).Extent.Text
. ([scriptblock]::Create($boundary))
$escaped=$false;try{$null=Assert-CleanupBoundary (Join-Path ($fixtureTemp+'-sibling') 'file.tmp') $fixtureTemp -File}catch{$escaped=$true}
Assert-Check $escaped 'A sibling with the same path prefix must fail the cleanup boundary check.'
$rootRemoval=$false;try{$null=Assert-CleanupBoundary $fixtureTemp $fixtureTemp -File}catch{$rootRemoval=$true}
Assert-Check $rootRemoval 'The cleanup root itself must never be a removable file.'
$reparseModule=New-Module -ScriptBlock {
    function Check-Reparse {param($Source,$Path,$Root) . ([scriptblock]::Create($Source));$script:MockPath=$Root;try{$null=Assert-CleanupBoundary $Path $Root -File;return $false}catch{return ($_.Exception.Message -like '*Reparse*')}}
    function Get-Item {
        param($LiteralPath,[switch]$Force,$ErrorAction)
        if($LiteralPath -eq $script:MockPath){[pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint;PSIsContainer=$true;FullName=$LiteralPath}}
        else{Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop}
    }
    Export-ModuleMember -Function Check-Reparse
}
$blocked=& $reparseModule {param($Source,$Path,$Root)Check-Reparse $Source $Path $Root} $boundary $newPath $fixtureTemp
Assert-Check $blocked 'An ancestor reparse point must block cleanup.'
foreach($relative in @('Troubleshooting\Repair-WindowsSystemFiles.ps1','Printing\Clear-PrinterQueueAndCache.ps1','Storage-and-Permissions\Clear-TemporaryFiles.ps1')){
    $text=Get-TestSource $relative
    $tokens=$null;$errors=$null;$null=[System.Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
    Assert-Check (@($errors).Count -eq 0) ($relative+' must parse.')
    Assert-Check ($text -match 'SupportsShouldProcess=\$true') ($relative+' must support WhatIf.')
}
$result=[pscustomobject]@{Checks=$script:checks;Status='Passed';PowerShellVersion=$PSVersionTable.PSVersion.ToString();OutputDirectory=$OutputDirectory;Scope='Mocks and workspace fixtures only; no live repair/print changes'}
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'test-results.json') -Encoding UTF8
$result
