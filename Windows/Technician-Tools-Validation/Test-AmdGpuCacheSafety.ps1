<#
What it does:
  Tests AMD cache cleanup and graphics-device restart safeguards with isolated fixtures.
Available flags:
  -WindowsRoot: Windows folder under test. -OutputDirectory: Private test artifacts.
How it works:
  Uses fixture cache files and mocked GPU/native providers. Never queries real GPU hardware,
  deletes the user's shader caches, restarts a graphics device, or reboots Windows.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$WindowsRoot,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $WindowsRoot){
    $candidate=Join-Path $PSScriptRoot 'staged\Windows'
    $WindowsRoot=if(Test-Path -LiteralPath $candidate -PathType Container){$candidate}else{Split-Path $PSScriptRoot -Parent}
}
$sourcePath=Join-Path $WindowsRoot 'Troubleshooting\Reset-AmdGpuCache.ps1'
$source=Get-Content -LiteralPath $sourcePath -Raw
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$parseErrors)
$script:assertions=0
function Assert-AmdFixture {
    param([bool]$Condition,[string]$Message)
    $script:assertions++
    if(-not $Condition){throw ('AMD fixture failed: '+$Message)}
}
Assert-AmdFixture (@($parseErrors).Count -eq 0) 'Source parses in Windows PowerShell 5.1.'
foreach($heading in @('What it does','Available flags','How it works')){Assert-AmdFixture ($source.Contains($heading)) ('Comment section '+$heading)}
Assert-AmdFixture ($source -match 'SupportsShouldProcess\s*=\s*\$true') 'Explicit WhatIf support.'
$commands=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
foreach($forbidden in @('Disable-PnpDevice','Enable-PnpDevice','Restart-Computer','Stop-Process','Invoke-Expression')){Assert-AmdFixture ($commands -notcontains $forbidden) ('No '+$forbidden+' fallback.')}
Assert-AmdFixture ($source -notmatch '(?im)Remove-Item[^\r\n]*-Recurse') 'No recursive directory deletion.'

function Replace-AmdFixtureFunction {
    param([string]$Text,[string]$Name,[string]$Replacement)
    $replacementTokens=$null;$replacementErrors=$null
    $replacementAst=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$replacementTokens,[ref]$replacementErrors)
    if($replacementErrors){throw 'Fixture source did not parse.'}
    $node=$replacementAst.Find({param($item)$item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq $Name},$true)
    if(-not $node){throw ('Fixture dependency was not found: '+$Name)}
    $Text.Substring(0,$node.Extent.StartOffset)+$Replacement+$Text.Substring($node.Extent.EndOffset)
}

if(-not $OutputDirectory){$OutputDirectory=Join-Path ([IO.Path]::GetTempPath()) ('amd-cache-validation-'+[guid]::NewGuid().ToString('N').Substring(0,8))}
$null=New-Item -ItemType Directory -Path $OutputDirectory -Force
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$script:caseNumber=0
function Invoke-AmdFixtureCase {
    param([hashtable]$Arguments=@{},[object[]]$Adapters=@([pscustomobject]@{InstanceId='PCI\VEN_1002&DEV_1234\FIXTURE';FriendlyName='Fixture AMD GPU';Status='OK';ProblemCode=0}),[bool]$Consent=$true,[int]$NativeCode=0,[switch]$LockCacheFile,[string]$WaitAssessment='PresentPnPStatusVerified')
    $script:caseNumber++
    $caseRoot=Join-Path $OutputDirectory ('case-'+$script:caseNumber)
    $local=Join-Path $caseRoot 'Local'
    foreach($relative in @('AMD\DxCache','AMD\DxcCache','AMD\GLCache','AMD\VkCache','AMD\DX9Cache','AMD\CN','D3DSCache')){$null=New-Item -ItemType Directory -Path (Join-Path $local $relative) -Force}
    foreach($relative in @('AMD\DxCache\shader.bin','AMD\DxcCache\shader.bin','AMD\GLCache\shader.bin','AMD\VkCache\shader.bin','AMD\DX9Cache\shader.bin','AMD\CN\settings.json','D3DSCache\shared.bin')){[IO.File]::WriteAllText((Join-Path $local $relative),'private fixture')}
    $fixtureText=$source
    $memberCalls=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -eq 'ShouldContinue'},$true))
    foreach($call in @($memberCalls | Sort-Object {$_.Extent.StartOffset} -Descending)){
        $fixtureText=$fixtureText.Substring(0,$call.Extent.StartOffset)+'$script:FixtureConsent'+$fixtureText.Substring($call.Extent.EndOffset)
    }
    $fixtureText=Replace-AmdFixtureFunction $fixtureText 'Assert-AmdPlatform' 'function Assert-AmdPlatform {}'
    $fixtureText=Replace-AmdFixtureFunction $fixtureText 'Test-AmdAdministrator' 'function Test-AmdAdministrator {$true}'
    $fixtureText=Replace-AmdFixtureFunction $fixtureText 'Get-AmdLocalAppData' 'function Get-AmdLocalAppData {$script:FixtureLocal}'
    $fixtureText=Replace-AmdFixtureFunction $fixtureText 'Get-AmdAdapters' 'function Get-AmdAdapters {$script:FixtureAdapters}'
    $fixtureText=Replace-AmdFixtureFunction $fixtureText 'Invoke-AmdPnpRestart' @'
function Invoke-AmdPnpRestart {
    param([string]$Id,[string]$OutputPath)
    $script:FixtureNativeCalls.Add($Id)
    [IO.File]::WriteAllText($OutputPath,'mock PnPUtil output')
    [pscustomobject]@{ExitCode=$script:FixtureNativeCode;OutputFile=$OutputPath}
}

'@
    $fixtureText=Replace-AmdFixtureFunction $fixtureText 'Wait-AmdAdapterReady' @'
function Wait-AmdAdapterReady {
    param([string]$Id,[int]$TimeoutSeconds)
    $script:FixtureWaitCalls++
    [pscustomobject]@{Status='OK';ProblemCode=0;Assessment='FixtureAssessmentPlaceholder'}
}
'@
    $fixtureText=$fixtureText.Replace('FixtureAssessmentPlaceholder',$WaitAssessment)
    $fixtureArguments=@{OutputDirectory=(Join-Path $caseRoot 'Reports');Confirm=$false}
    foreach($key in $Arguments.Keys){$fixtureArguments[$key]=$Arguments[$key]}
    $module=New-Module -ScriptBlock {
        function Invoke-Fixture {
            param($Text,$Arguments,$Local,$Adapters,$Consent,$Code)
            $script:FixtureLocal=$Local;$script:FixtureAdapters=$Adapters;$script:FixtureConsent=$Consent;$script:FixtureNativeCode=$Code
            $script:FixtureNativeCalls=New-Object 'System.Collections.Generic.List[string]';$script:FixtureWaitCalls=0
            $failure='';$result=$null
            try{$result=& ([scriptblock]::Create($Text)) @Arguments}catch{$failure=$_.Exception.Message}
            [pscustomobject]@{Result=$result;Failure=$failure;NativeCalls=$script:FixtureNativeCalls.ToArray();WaitCalls=$script:FixtureWaitCalls}
        }
        Export-ModuleMember -Function Invoke-Fixture
    }
    $heldFile=$null
    try{
        if($LockCacheFile){$heldFile=[IO.File]::Open((Join-Path $local 'AMD\DxCache\shader.bin'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
        $outcome=& $module {param($Text,$Arguments,$Local,$Adapters,$Consent,$Code)Invoke-Fixture $Text $Arguments $Local $Adapters $Consent $Code} $fixtureText $fixtureArguments $local $Adapters $Consent $NativeCode
    }finally{if($heldFile){$heldFile.Dispose()}}
    $outcome | Add-Member -NotePropertyName Local -NotePropertyValue $local
    $outcome | Add-Member -NotePropertyName CaseRoot -NotePropertyValue $caseRoot
    $outcome
}

$plan=Invoke-AmdFixtureCase
Assert-AmdFixture (-not $plan.Failure) ('Plan completes: '+$plan.Failure)
Assert-AmdFixture (Test-Path -LiteralPath (Join-Path $plan.Local 'AMD\DxCache\shader.bin')) 'Plan keeps AMD cache files.'
Assert-AmdFixture (@($plan.NativeCalls).Count -eq 0) 'Plan makes zero driver restart calls.'
$preview=Invoke-AmdFixtureCase @{Apply=$true;WhatIf=$true}
Assert-AmdFixture (-not $preview.Failure) ('WhatIf completes: '+$preview.Failure)
Assert-AmdFixture (Test-Path -LiteralPath (Join-Path $preview.Local 'AMD\DxCache\shader.bin')) 'WhatIf keeps AMD cache files.'
Assert-AmdFixture (@($preview.NativeCalls).Count -eq 0) 'WhatIf makes zero driver restart calls.'
Assert-AmdFixture (@(Get-ChildItem -LiteralPath (Join-Path $preview.CaseRoot 'Reports') -Filter '*.json' -Recurse -File).Count -gt 0) 'WhatIf still saves reports.'
$deferred=Invoke-AmdFixtureCase @{Apply=$true;SkipRestartPrompt=$true}
Assert-AmdFixture (-not $deferred.Failure) ('Deferred run completes: '+$deferred.Failure)
Assert-AmdFixture (-not (Test-Path -LiteralPath (Join-Path $deferred.Local 'AMD\DxCache\shader.bin'))) 'Apply clears selected AMD fixture cache.'
Assert-AmdFixture (@($deferred.NativeCalls).Count -eq 0) 'SkipRestartPrompt prevents PnP restart.'
Assert-AmdFixture (Test-Path -LiteralPath (Join-Path $deferred.Local 'AMD\CN\settings.json')) 'AMD control-panel settings remain intact.'
Assert-AmdFixture (Test-Path -LiteralPath (Join-Path $deferred.Local 'D3DSCache\shared.bin')) 'Shared DirectX cache is opt-in.'
$declined=Invoke-AmdFixtureCase -Arguments @{Apply=$true} -Consent $false
Assert-AmdFixture (-not $declined.Failure) ('Declined run completes: '+$declined.Failure)
Assert-AmdFixture (@($declined.NativeCalls).Count -eq 0) 'Declined separate confirmation blocks restart even with Confirm false.'
$approved=Invoke-AmdFixtureCase @{Apply=$true}
Assert-AmdFixture (-not $approved.Failure) ('Approved run completes: '+$approved.Failure)
Assert-AmdFixture (@($approved.NativeCalls).Count -eq 1 -and $approved.NativeCalls[0] -eq 'PCI\VEN_1002&DEV_1234\FIXTURE') 'Confirmed apply restarts exactly the selected AMD instance.'
Assert-AmdFixture ($approved.WaitCalls -eq 1) 'Confirmed restart checks post-reset PnP readiness.'
Assert-AmdFixture (Test-Path -LiteralPath (Join-Path $approved.Local 'AMD\DxCache') -PathType Container) 'Cache directories are retained.'
$shared=Invoke-AmdFixtureCase @{Apply=$true;SkipRestartPrompt=$true;IncludeDirectXCache=$true}
Assert-AmdFixture (-not (Test-Path -LiteralPath (Join-Path $shared.Local 'D3DSCache\shared.bin'))) 'Explicit IncludeDirectXCache clears only the shared fixture cache.'
$multiAdapters=@(
 [pscustomobject]@{InstanceId='PCI\VEN_1002&DEV_1111\GPU1';FriendlyName='Fixture AMD one';Status='OK';ProblemCode=0},
 [pscustomobject]@{InstanceId='PCI\VEN_1002&DEV_2222\GPU2';FriendlyName='Fixture AMD two';Status='OK';ProblemCode=0}
)
$ambiguous=Invoke-AmdFixtureCase -Arguments @{Apply=$true} -Adapters $multiAdapters
Assert-AmdFixture (@($ambiguous.NativeCalls).Count -eq 0) 'Multiple adapters require explicit selection.'
Assert-AmdFixture (Test-Path -LiteralPath (Join-Path $ambiguous.Local 'AMD\DxCache\shader.bin')) 'Ambiguous apply does not clear cache before selection.'
$selected=Invoke-AmdFixtureCase -Arguments @{Apply=$true;InstanceId=@('PCI\VEN_1002&DEV_2222\GPU2')} -Adapters $multiAdapters
Assert-AmdFixture (-not $selected.Failure) ('Explicit adapter run completes: '+$selected.Failure)
Assert-AmdFixture (@($selected.NativeCalls).Count -eq 1 -and $selected.NativeCalls[0] -eq 'PCI\VEN_1002&DEV_2222\GPU2') 'Explicit instance selects only its exact AMD adapter.'
$all=Invoke-AmdFixtureCase -Arguments @{Apply=$true;AllAmdAdapters=$true} -Adapters $multiAdapters
Assert-AmdFixture (@($all.NativeCalls).Count -eq 2) 'AllAmdAdapters explicitly selects both fixture adapters.'
$unknown=Invoke-AmdFixtureCase @{Apply=$true;InstanceId=@('PCI\VEN_10DE&DEV_1234\OTHER')}
Assert-AmdFixture (@($unknown.NativeCalls).Count -eq 0) 'Unmatched/non-AMD selection never restarts a device.'
Assert-AmdFixture (Test-Path -LiteralPath (Join-Path $unknown.Local 'AMD\DxCache\shader.bin')) 'Invalid selection never clears cache.'
$empty=Invoke-AmdFixtureCase -Arguments @{Apply=$true} -Adapters @()
Assert-AmdFixture (@($empty.NativeCalls).Count -eq 0) 'No AMD adapter means no restart.'
Assert-AmdFixture (Test-Path -LiteralPath (Join-Path $empty.Local 'AMD\DxCache\shader.bin')) 'No AMD adapter means no cache cleanup.'
$failed=Invoke-AmdFixtureCase -Arguments @{Apply=$true} -NativeCode 5
Assert-AmdFixture (@($failed.NativeCalls).Count -eq 1) 'A failed native restart is attempted once only.'
Assert-AmdFixture ($failed.WaitCalls -eq 0) 'A failed restart is not treated as verified ready.'
$rebootRequired=Invoke-AmdFixtureCase -Arguments @{Apply=$true} -NativeCode 3010
Assert-AmdFixture (@($rebootRequired.NativeCalls).Count -eq 1) 'A reboot-required native result does not retry through fallback methods.'

$locked=Invoke-AmdFixtureCase -Arguments @{Apply=$true;SkipRestartPrompt=$true} -LockCacheFile
Assert-AmdFixture (-not $locked.Failure) ('Locked-file run completes: '+$locked.Failure)
Assert-AmdFixture (Test-Path -LiteralPath (Join-Path $locked.Local 'AMD\DxCache\shader.bin')) 'A locked cache file is retained.'
Assert-AmdFixture (-not (Test-Path -LiteralPath (Join-Path $locked.Local 'AMD\GLCache\shader.bin'))) 'Other eligible files can still be cleared.'
$lockedRows=@(Import-Csv -LiteralPath (Join-Path $locked.Result.ReportDirectory 'cache-files.csv'))
Assert-AmdFixture (@($lockedRows | Where-Object {$_.Path -eq (Join-Path $locked.Local 'AMD\DxCache\shader.bin') -and $_.Status -eq 'Skipped'}).Count -eq 1) 'Locked file is reported as skipped.'
$pendingActions=@(Import-Csv -LiteralPath (Join-Path $rebootRequired.Result.ReportDirectory 'driver-actions.csv'))
Assert-AmdFixture ($pendingActions[0].Status -eq 'WindowsRestartRequired') 'Exit 3010 records the pending Windows restart without requesting it.'
Assert-AmdFixture (-not $rebootRequired.Result.WindowsRebootRequested) 'Native 3010 never requests a computer reboot.'
$unresolved=Invoke-AmdFixtureCase -Arguments @{Apply=$true;AllAmdAdapters=$true} -Adapters $multiAdapters -WaitAssessment UnknownAfterRestart
Assert-AmdFixture (@($unresolved.NativeCalls).Count -eq 1) 'Unresolved first restart prevents resetting another selected GPU.'
$unresolvedActions=@(Import-Csv -LiteralPath (Join-Path $unresolved.Result.ReportDirectory 'driver-actions.csv'))
Assert-AmdFixture ($unresolvedActions[1].Status -eq 'SkippedAfterUnresolvedRestart') 'Remaining GPU explains its unresolved-restart deferral.'
$conflict=Invoke-AmdFixtureCase -Arguments @{Apply=$true;AllAmdAdapters=$true;InstanceId=@('PCI\VEN_1002&DEV_1111\GPU1')} -Adapters $multiAdapters
Assert-AmdFixture (@($conflict.NativeCalls).Count -eq 0 -and (Test-Path -LiteralPath (Join-Path $conflict.Local 'AMD\DxCache\shader.bin'))) 'Conflicting selection flags make no mutations.'
$limited=Invoke-AmdFixtureCase @{Apply=$true;SkipRestartPrompt=$true;MaxEntries=1}
Assert-AmdFixture ($limited.Result.LimitReached -and $limited.Result.EntriesInspected -eq 1) 'Entry limit is enforced and reported.'
Assert-AmdFixture ((Get-ChildItem -LiteralPath (Join-Path $limited.Local 'AMD') -Filter shader.bin -Recurse -File).Count -eq 4) 'Entry limit leaves uninspected cache files intact.'

# Pure helpers use only the private fixture filesystem.
foreach($name in @('Assert-AmdCacheBoundary','Get-AmdCacheFileDecision','Get-AmdCacheRoots')){
    $functionAst=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    . ([scriptblock]::Create($functionAst.Extent.Text))
}
$fixtureFile=Join-Path $plan.Local 'AMD\DxCache\shader.bin'
$fixtureRoot=Join-Path $plan.Local 'AMD\DxCache'
$current=Assert-AmdCacheBoundary -Path $fixtureFile -Root $fixtureRoot -File
Assert-AmdFixture ($current.FullName -eq $fixtureFile) 'A regular file inside the approved cache boundary is accepted.'
foreach($attempt in @(@{Path=$fixtureRoot;File=$true},@{Path=(Join-Path $plan.Local 'AMD\CN\settings.json');File=$true},@{Path=(Join-Path $plan.Local 'AMD\DxCache-sibling\file');File=$true},@{Path=(Join-Path $fixtureRoot '..\CN\settings.json');File=$true})){
    $blocked=$false
    try{$null=Assert-AmdCacheBoundary -Path $attempt.Path -Root $fixtureRoot -File:$attempt.File}catch{$blocked=$true}
    Assert-AmdFixture $blocked ('Boundary rejects directory, sibling or dot traversal: '+$attempt.Path)
}
$observed=[pscustomobject]@{Bytes=$current.Length;LastWriteUtc=$current.LastWriteTimeUtc;CreationUtc=$current.CreationTimeUtc}
Assert-AmdFixture ((Get-AmdCacheFileDecision -Current $current -Observed $observed) -eq 'Eligible') 'Unchanged file is eligible.'
[IO.File]::AppendAllText($fixtureFile,' changed')
$current=Get-Item -LiteralPath $fixtureFile -Force
Assert-AmdFixture ((Get-AmdCacheFileDecision -Current $current -Observed $observed) -eq 'SkippedChanged') 'Changed cache metadata prevents deletion.'
$roots=@(Get-AmdCacheRoots -LocalAppData $plan.Local -IncludeDirectX $false)
Assert-AmdFixture ($roots.Count -eq 5) 'Default cache allowlist contains five AMD cache roots.'
Assert-AmdFixture (@($roots | Where-Object {$_.Path -eq (Join-Path $plan.Local 'AMD\CN')}).Count -eq 0) 'Control-panel configuration is outside the allowlist.'

# Exercise actual AMD discovery with a fake Get-PnpDevice provider.
$discoveryAst=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-AmdAdapters'},$true)
$discoveryModule=New-Module -ScriptBlock {
    function Run-Discovery {
        param($Definition)
        . ([scriptblock]::Create($Definition))
        @(Get-AmdAdapters)
    }
    function Get-PnpDevice {
        [CmdletBinding()]
        param([string]$Class,[switch]$PresentOnly)
        if($Class -ne 'Display' -or -not $PresentOnly){throw 'Discovery did not restrict its provider to present Display devices.'}
        @(
            [pscustomobject]@{Class='Display';InstanceId='PCI\VEN_1002&DEV_1234\AMD';FriendlyName='AMD';Status='OK';Problem=0},
            [pscustomobject]@{Class='Display';InstanceId='PCI\VEN_10DE&DEV_1234\NVIDIA';FriendlyName='AMD misleading name';Status='OK';Problem=0},
            [pscustomobject]@{Class='Display';InstanceId='PCI\VEN_8086&DEV_1234\INTEL';FriendlyName='Intel';Status='OK';Problem=0},
            [pscustomobject]@{Class='System';InstanceId='PCI\VEN_1002&DEV_1234\CHIPSET';FriendlyName='AMD chipset';Status='OK';Problem=0},
            [pscustomobject]@{Class='Display';InstanceId='PCI\VEN_10020&DEV_1234\PREFIX';FriendlyName='Wrong vendor prefix';Status='OK';Problem=0}
        )
    }
    Export-ModuleMember -Function Run-Discovery
}
$discovered=@(& $discoveryModule {param($Definition)Run-Discovery $Definition} $discoveryAst.Extent.Text)
Assert-AmdFixture ($discovered.Count -eq 1) 'Discovery rejects other vendors, misleading names, chipset class and vendor-prefix collisions.'
Assert-AmdFixture ($discovered[0].InstanceId -eq 'PCI\VEN_1002&DEV_1234\AMD') 'Discovery retains the exact AMD display instance.'

$nativeAst=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-AmdPnpRestart'},$true)
$nativeStrings=@($nativeAst.FindAll({param($node)$node -is [Management.Automation.Language.StringConstantExpressionAst]},$true) | ForEach-Object {$_.Value})
Assert-AmdFixture ($nativeStrings -contains '/restart-device') 'Native operation is a device restart.'
foreach($argument in @('/reboot','/force','/disable-device','/enable-device','/remove-device','/delete-driver')){Assert-AmdFixture ($nativeStrings -notcontains $argument) ('Native arguments exclude '+$argument)}
Assert-AmdFixture ($nativeStrings -contains 'System32\pnputil.exe') 'Native executable is the Windows System32 PnPUtil.'

# Mark an ancestor as a reparse point without creating a junction on the machine.
$boundaryAst=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-AmdCacheBoundary'},$true)
$reparseModule=New-Module -ScriptBlock {
    function Test-BlockedAncestor {
        param($Definition,$Path,$Root)
        $script:BlockedAncestor=$Root
        . ([scriptblock]::Create($Definition))
        try{$null=Assert-AmdCacheBoundary -Path $Path -Root $Root -File;return $false}catch{return $true}
    }
    function Get-Item {
        [CmdletBinding()]
        param([string]$LiteralPath,[switch]$Force)
        if($LiteralPath -eq $script:BlockedAncestor){return [pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint;PSIsContainer=$true;FullName=$LiteralPath}}
        Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force
    }
    Export-ModuleMember -Function Test-BlockedAncestor
}
$blocked=& $reparseModule {param($Definition,$Path,$Root)Test-BlockedAncestor $Definition $Path $Root} $boundaryAst.Extent.Text $fixtureFile $fixtureRoot
Assert-AmdFixture $blocked 'Reparse-point ancestry blocks cleanup.'

$summary=[pscustomobject]@{Suite='AMD GPU cache';Assertions=$script:assertions;Result='Passed';PowerShellVersion=$PSVersionTable.PSVersion.ToString();OutputDirectory=$OutputDirectory;Scope='Isolated cache fixtures and mocked GPU/native providers; no real cache cleanup, display restart or reboot.'}
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'test-summary.json') -Encoding UTF8
$summary
