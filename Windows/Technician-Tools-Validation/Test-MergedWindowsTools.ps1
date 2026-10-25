<#
What it does:
  Regression-tests the merged software and DISM/SFC engines through the real public entrypoints.
Available flags:
  -WindowsRoot: Complete Windows library under test. -OutputDirectory: Private fixture/report folder.
How it works:
  Copies the four wrappers and two engines into private fixtures, replacing only OS providers and
  native calls. Checks compatible reports and safe modes without querying software or repairing Windows.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$WindowsRoot,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $WindowsRoot){$WindowsRoot=Split-Path $PSScriptRoot -Parent}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $WindowsRoot ('Reports\MergedWindowsValidation-'+[guid]::NewGuid().ToString('N').Substring(0,8))}
$OutputDirectory=(New-Item -ItemType Directory -Path $OutputDirectory -Force).FullName
$script:checks=0;$script:caseNumber=0
function Assert-Merged {param([bool]$Condition,[string]$Message);$script:checks++;if(-not $Condition){throw ('Merged Windows assertion: '+$Message)}}
function Replace-FixtureFunction {
 param([string]$Text,[string]$Name,[string]$Replacement)
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'Source did not parse.'}
 $node=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name},$true)
 if(-not $node){throw ('Missing provider: '+$Name)}
 $Text.Substring(0,$node.Extent.StartOffset)+$Replacement+$Text.Substring($node.Extent.EndOffset)
}
function New-FixtureTree {
 $script:caseNumber++
 $root=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory ('case-'+$script:caseNumber)) -Force).FullName
 foreach($folder in @('Software','Troubleshooting','lib')){$null=New-Item -ItemType Directory -Path (Join-Path $root $folder)}
 foreach($relative in @('Software\Get-InstalledSoftware.ps1','Software\Get-InstalledSoftwareAudit.ps1','Troubleshooting\Test-SystemFileHealth.ps1','Troubleshooting\Repair-WindowsSystemFiles.ps1')){Copy-Item -LiteralPath (Join-Path $WindowsRoot $relative) -Destination (Join-Path $root $relative)}
 $root
}
function Invoke-SoftwareFixture {
 param([string]$Entry,[hashtable]$Arguments=@{})
 $root=New-FixtureTree
 $source=[IO.File]::ReadAllText((Join-Path $WindowsRoot 'lib\Invoke-SoftwareInventoryCore.ps1'))
 $source=Replace-FixtureFunction $source 'Assert-SoftwarePlatform' 'function Assert-SoftwarePlatform {}'
 $source=Replace-FixtureFunction $source 'Get-SoftwareCurrentSid' "function Get-SoftwareCurrentSid { 'S-1-5-21-1-2-3-1001' }"
 $source=Replace-FixtureFunction $source 'Test-SoftwareAppxAvailable' 'function Test-SoftwareAppxAvailable { $true }'
 $source=Replace-FixtureFunction $source 'Test-SoftwareAuditAdministrator' 'function Test-SoftwareAuditAdministrator { $true }'
 $source=Replace-FixtureFunction $source 'Get-SoftwareRegistrySnapshot' @'
function Get-SoftwareRegistrySnapshot {
 foreach($fixture in @(
  @{DisplayName='Fixture Editor';DisplayVersion='1.0';Publisher='Example';InstallDate='20240229';SystemComponent=1;Scope='Machine';View='Registry64';Key='editor'},
  @{DisplayName='Blank Version';DisplayVersion='';Publisher='';InstallDate='';SystemComponent=0;Scope='Machine';View='Registry32';Key='blank'},
  @{DisplayName='User App';DisplayVersion='2.0';Publisher='Example';InstallDate='20240101';SystemComponent=0;Scope='CurrentUser';View='Registry64';Key='user'}
 )){
  $row=ConvertTo-SoftwareRegistryRow ([pscustomobject]$fixture) $fixture.Scope $(if($fixture.Scope -eq 'CurrentUser'){$currentSid}else{''}) $fixture.View $fixture.Key
  $script:rows.Add($row)
 }
 Add-SoftwareStatus 'Fixture registry views' 'Success' 3 'Mocked registry snapshot.'
}
'@
 $source=Replace-FixtureFunction $source 'Get-SoftwareAppxPackages' @'
function Get-SoftwareAppxPackages {
 param([bool]$AllUsers)
 [pscustomobject]@{Name='Fixture.App';Version='3.0.0.0';Publisher='CN=Example';Architecture='X64';PackageFullName='Fixture.App_3.0.0.0_x64__fixture';PackageFamilyName='Fixture.App_fixture';PackageUserInformation=@([pscustomobject]@{UserSecurityId='S-1-5-21-9-8-7-1002';InstallState='Installed'})}
}
'@
 [IO.File]::WriteAllText((Join-Path $root 'lib\Invoke-SoftwareInventoryCore.ps1'),$source,[Text.UTF8Encoding]::new($false))
 $Arguments=$Arguments.Clone();$Arguments.OutputDirectory=Join-Path $root 'reports'
 & (Join-Path $root ('Software\'+$Entry)) @Arguments
}
$legacy=Invoke-SoftwareFixture 'Get-InstalledSoftware.ps1' @{IncludeAppx=$true}
$audit=Invoke-SoftwareFixture 'Get-InstalledSoftwareAudit.ps1' @{IncludeAppx=$true}
$legacyRows=@(Import-Csv -LiteralPath (Join-Path $legacy.ReportDirectory 'installed-software.csv'))
$auditRows=@(Import-Csv -LiteralPath (Join-Path $audit.ReportDirectory 'software.csv'))
Assert-Merged ($legacy.DesktopEntryCount -eq 3 -and $audit.SoftwareRecordCount -eq 4) 'Both wrappers use the common fixture collector with their compatible scopes.'
Assert-Merged ($legacyRows[0].PSObject.Properties.Name -join ',' -eq 'Name,Version,Publisher,InstallDate,Scope,RegistryView,RegistryKey,IsSystemComponent') 'Legacy desktop CSV columns stay exact.'
Assert-Merged (@($legacyRows | Where-Object Scope -eq 'LocalMachine').Count -eq 2) 'Legacy LocalMachine scope mapping retained.'
Assert-Merged (@($auditRows | Where-Object Scope -eq 'Machine').Count -eq 2) 'Expanded audit Machine scope retained.'
Assert-Merged (($legacyRows | Where-Object Name -eq 'Blank Version').Version -eq '') 'Legacy missing display version stays blank.'
Assert-Merged (($auditRows | Where-Object Name -eq 'Blank Version').Version -eq 'Unknown') 'Expanded audit missing version remains Unknown.'
Assert-Merged (($legacyRows | Where-Object Name -eq 'Fixture Editor').IsSystemComponent -eq 'True') 'Legacy system-component field stays boolean.'
Assert-Merged (($auditRows | Where-Object Name -eq 'Fixture Editor').InstallDateISO -eq '2024-02-29') 'Canonical date normalization remains available.'
$legacyAppx=@(Import-Csv -LiteralPath (Join-Path $legacy.ReportDirectory 'appx-packages.csv'))
Assert-Merged ($legacyAppx.Count -eq 1 -and $legacyAppx[0].PackageFullName -eq 'Fixture.App_3.0.0.0_x64__fixture') 'Legacy AppX full package identity retained.'
Assert-Merged ($legacyAppx[0].PSObject.Properties.Name -join ',' -eq 'Name,Version,Publisher,Architecture,PackageFullName') 'Legacy AppX CSV columns stay exact.'
Assert-Merged ($legacy.AppxPackageCount -eq 1 -and $legacy.AppxIncluded) 'Legacy summary preserves AppX fields.'
Assert-Merged ($auditRows[0].PSObject.Properties.Name -notcontains 'RawDisplayVersion') 'Internal legacy metadata does not leak into public audit CSV.'
$auditJson=[IO.File]::ReadAllText((Join-Path $audit.ReportDirectory 'software.json'))
Assert-Merged ($auditJson -notmatch 'RawDisplayVersion|RawPublisher') 'Internal fields do not change public audit JSON schema.'
$noAppx=Invoke-SoftwareFixture 'Get-InstalledSoftware.ps1'
Assert-Merged (-not (Test-Path -LiteralPath (Join-Path $noAppx.ReportDirectory 'appx-packages.csv'))) 'Legacy AppX remains opt-in.'
$baseline=Invoke-SoftwareFixture 'Get-InstalledSoftwareAudit.ps1' @{IncludeAppx=$true;BaselineCsv=(Join-Path $audit.ReportDirectory 'software.csv')}
Assert-Merged ($baseline.DifferenceCount -eq 0) 'Baseline comparison works through the common collector.'
$allUsers=Invoke-SoftwareFixture 'Get-InstalledSoftwareAudit.ps1' @{AllUsersAppx=$true;IncludeLoadedUserHives=$true}
$allRows=@(Import-Csv -LiteralPath (Join-Path $allUsers.ReportDirectory 'software.csv'))
Assert-Merged (($allRows | Where-Object Source -eq 'Appx').UserSid -eq 'S-1-5-21-9-8-7-1002') 'All-user AppX registrations preserve returned SID.'
$softwareSource=[IO.File]::ReadAllText((Join-Path $WindowsRoot 'lib\Invoke-SoftwareInventoryCore.ps1'))
Assert-Merged ($softwareSource -match 'if\(\[Environment\]::Is64BitOperatingSystem\)') '32-bit Windows uses Registry32; Registry64 is conditional.'
$platformTokens=$null;$platformErrors=$null;$softwareAst=[Management.Automation.Language.Parser]::ParseInput($softwareSource,[ref]$platformTokens,[ref]$platformErrors)
$platform=$softwareAst.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-SoftwarePlatform'},$true)
Assert-Merged ($platform.Extent.Text -notmatch 'Is64BitProcess') 'Legacy software entrypoint is not newly restricted to a 64-bit process.'

function Invoke-IntegrityFixture {
 param([string]$Entry,[hashtable]$Arguments=@{},[int]$DismExit=0,[int]$SfcExit=0)
 $root=New-FixtureTree
 $source=[IO.File]::ReadAllText((Join-Path $WindowsRoot 'lib\Invoke-WindowsIntegrityCore.ps1'))
 $source=Replace-FixtureFunction $source 'Assert-NativeAdministrator' 'function Assert-NativeAdministrator {}'
 $native=@'
function Invoke-SystemFileUtility {
 param([string]$Executable,[string[]]$Arguments,[string]$Label)
 $code=if($Executable -eq 'dism.exe'){FIXTURE_DISM}else{FIXTURE_SFC}
 [pscustomobject]@{Executable=$Executable;Arguments=$Arguments;ExitCode=$code} | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $reportDirectory 'fixture-native.jsonl') -Encoding UTF8
 'Mock native output' | Set-Content -LiteralPath (Join-Path $reportDirectory ($Label+'-output.txt')) -Encoding UTF8 -WhatIf:$false -Confirm:$false
 [pscustomobject]@{Utility=$Executable;Arguments=($Arguments -join ' ');ExitCode=$code;Assessment='ReviewNativeOutput';OutputFile=($Label+'-output.txt')}
}
'@
 $native=$native.Replace('FIXTURE_DISM',[string]$DismExit).Replace('FIXTURE_SFC',[string]$SfcExit)
 $source=Replace-FixtureFunction $source 'Invoke-SystemFileUtility' $native
 $source=Replace-FixtureFunction $source 'Copy-IntegrityLogTail' @'
function Copy-IntegrityLogTail {
 param([string]$Name,[string]$Source,[string]$Output)
 'Mock historic log' | Set-Content -LiteralPath (Join-Path $reportDirectory $Output) -Encoding UTF8 -WhatIf:$false -Confirm:$false
 if($Compatibility -eq 'Diagnostic'){$queryLog.Add([pscustomobject]@{Section=($Name+' log tail');Status='Collected';Count=1;Error=''})}
 [pscustomobject]@{Source=$Source;Output=$Output;Lines=1;Status='Collected'}
}
'@
 $consent="`$PSCmdlet.ShouldContinue('A native utility reported that Windows must restart. Restart this computer now? Save your work first.','Separate restart confirmation')"
 $source=$source.Replace($consent,'$false')
 $source=$source.Replace('Restart-Computer -ErrorAction Stop',"throw 'FORBIDDEN fixture reboot'")
 [IO.File]::WriteAllText((Join-Path $root 'lib\Invoke-WindowsIntegrityCore.ps1'),$source,[Text.UTF8Encoding]::new($false))
 $Arguments=$Arguments.Clone();$Arguments.OutputDirectory=Join-Path $root 'reports'
 $result=& (Join-Path $root ('Troubleshooting\'+$Entry)) @Arguments
 $callFile=Join-Path $result.ReportDirectory 'fixture-native.jsonl'
 $calls=@();if(Test-Path -LiteralPath $callFile){$calls=@(Get-Content -LiteralPath $callFile | ForEach-Object {$_ | ConvertFrom-Json})}
 [pscustomobject]@{Result=$result;Calls=$calls;Root=$root}
}
$quick=Invoke-IntegrityFixture 'Test-SystemFileHealth.ps1'
Assert-Merged ($quick.Calls.Count -eq 1 -and $quick.Calls[0].Arguments -contains '/CheckHealth') 'Old diagnostic default executes only CheckHealth.'
Assert-Merged ($quick.Calls[0].Arguments -contains '/English') 'Old diagnostic DISM output still requests English.'
Assert-Merged ($quick.Result.Data.SystemFileVerificationRequested -eq $false) 'Old SFC flag remains opt-in.'
$internalPreview=& (Join-Path $quick.Root 'lib\Invoke-WindowsIntegrityCore.ps1') -Compatibility Diagnostic -VerifySystemFiles -WhatIf -OutputDirectory (Join-Path $quick.Root 'core-preview')
Assert-Merged (-not (Test-Path -LiteralPath (Join-Path $internalPreview.ReportDirectory 'fixture-native.jsonl'))) 'Private core honors inherited WhatIf for diagnostic native calls too.'
foreach($name in @('native-command-results.csv','collection-status.csv','query-errors.csv','log-tail-sources.csv','overview.txt','summary.json','CBS-tail.txt','DISM-existing-tail.txt')){Assert-Merged (Test-Path -LiteralPath (Join-Path $quick.Result.ReportDirectory $name)) ('Old diagnostic output retained: '+$name)}
$scan=Invoke-IntegrityFixture 'Test-SystemFileHealth.ps1' @{ScanComponentStore=$true;VerifySystemFiles=$true}
Assert-Merged ($scan.Calls.Count -eq 2 -and $scan.Calls[0].Arguments -contains '/ScanHealth' -and $scan.Calls[1].Arguments -contains '/verifyonly') 'Old scan and SFC flags map through one sequence.'
$oldFailure=Invoke-IntegrityFixture 'Test-SystemFileHealth.ps1' @{VerifySystemFiles=$true} 5 0
Assert-Merged ($oldFailure.Calls.Count -eq 2 -and $oldFailure.Result.QueryErrorCount -eq 1) 'Diagnostic SFC still runs independently after a failed DISM result.'
$old3010=Invoke-IntegrityFixture 'Test-SystemFileHealth.ps1' @{VerifySystemFiles=$true} 3010 0
Assert-Merged ($old3010.Calls.Count -eq 2) 'Old diagnostics never turn a result into an automatic reboot.'
$plan=Invoke-IntegrityFixture 'Repair-WindowsSystemFiles.ps1'
Assert-Merged ($plan.Calls.Count -eq 0 -and $plan.Result.RunStatus -eq 'Plan') 'Repair wrapper default remains a plan.'
$repair=Invoke-IntegrityFixture 'Repair-WindowsSystemFiles.ps1' @{Apply=$true;SkipRestartPrompt=$true;Confirm=$false;LogTailLines=0}
Assert-Merged ($repair.Calls.Count -eq 2 -and $repair.Calls[0].Arguments -contains '/RestoreHealth' -and $repair.Calls[1].Arguments -contains '/scannow') 'Apply uses RestoreHealth then scannow.'
Assert-Merged ($repair.Calls[0].Arguments -contains '/NoRestart') 'Repair DISM retains NoRestart.'
Assert-Merged (Test-Path -LiteralPath (Join-Path $repair.Result.ReportDirectory 'native-results.csv')) 'Repair native-results schema/name retained.'
$failed=Invoke-IntegrityFixture 'Repair-WindowsSystemFiles.ps1' @{Apply=$true;SkipRestartPrompt=$true;Confirm=$false;LogTailLines=0} 5 0
Assert-Merged ($failed.Calls.Count -eq 1 -and $failed.Result.RunStatus -eq 'NativeFailed') 'Repair failure skips SFC and reports NativeFailed.'
$pending=Invoke-IntegrityFixture 'Repair-WindowsSystemFiles.ps1' @{Apply=$true;SkipRestartPrompt=$true;Confirm=$false;LogTailLines=0} 3010 0
Assert-Merged ($pending.Calls.Count -eq 1 -and $pending.Result.RestartRequired -and $pending.Result.RestartStatus -eq 'RequiredDeferred') 'Repair restart-required defers SFC and restart.'
$declined=Invoke-IntegrityFixture 'Repair-WindowsSystemFiles.ps1' @{Apply=$true;Confirm=$false;LogTailLines=0} 3010 0
Assert-Merged ($declined.Result.RestartStatus -eq 'RequiredDeferred') 'Separate restart consent cannot be bypassed by Confirm false.'
$preview=Invoke-IntegrityFixture 'Repair-WindowsSystemFiles.ps1' @{Apply=$true;WhatIf=$true;LogTailLines=0}
Assert-Merged ($preview.Calls.Count -eq 0 -and (Test-Path -LiteralPath (Join-Path $preview.Result.ReportDirectory 'summary.json'))) 'Wrapper WhatIf suppresses native calls and still saves report.'
$diagnose=Invoke-IntegrityFixture 'Repair-WindowsSystemFiles.ps1' @{Diagnose=$true;Confirm=$false;LogTailLines=0}
Assert-Merged ($diagnose.Calls.Count -eq 2 -and $diagnose.Calls[0].Arguments -contains '/CheckHealth' -and $diagnose.Calls[1].Arguments -contains '/verifyonly') 'Legacy Diagnose remains both read-only checks.'
foreach($mode in @('Check','Scan','Verify','Repair')){
 $case=Invoke-IntegrityFixture 'Repair-WindowsSystemFiles.ps1' @{Mode=$mode;Confirm=$false;LogTailLines=0}
 $expected=switch($mode){Check{'/CheckHealth'}Scan{'/ScanHealth'}Verify{'/verifyonly'}Repair{''}}
 if($mode -eq 'Repair'){Assert-Merged ($case.Calls.Count -eq 0) 'Explicit Repair mode also needs Apply.'}
 else{Assert-Merged ($case.Calls.Count -eq 1 -and $case.Calls[0].Arguments -contains $expected) ('Explicit mode '+$mode+' selects one read-only utility mode.')}
}
$image=Join-Path $OutputDirectory 'matching source.wim'
'Fixture only; no image is serviced' | Set-Content -LiteralPath $image -Encoding UTF8
$withSource=Invoke-IntegrityFixture 'Repair-WindowsSystemFiles.ps1' @{Apply=$true;Source=$image;SourceIndex=2;LimitAccess=$true;SkipRestartPrompt=$true;Confirm=$false;LogTailLines=0}
Assert-Merged ($withSource.Calls[0].Arguments -contains ('/Source:wim:'+([IO.Path]::GetFullPath($image))+':2')) 'Repair source path/index remain one correctly forwarded DISM argument.'
Assert-Merged ($withSource.Calls[0].Arguments -contains '/LimitAccess') 'LimitAccess remains an explicit native option.'
$badCombination=$false
try{$null=Invoke-IntegrityFixture 'Repair-WindowsSystemFiles.ps1' @{Mode='Scan';Apply=$true;LogTailLines=0}}catch{$badCombination=$true}
Assert-Merged $badCombination 'Explicit read-only mode refuses a conflicting Apply flag.'
foreach($relative in @('Software\Get-InstalledSoftware.ps1','Software\Get-InstalledSoftwareAudit.ps1','Troubleshooting\Test-SystemFileHealth.ps1','Troubleshooting\Repair-WindowsSystemFiles.ps1')){
 $text=[IO.File]::ReadAllText((Join-Path $WindowsRoot $relative))
 Assert-Merged ($text.Length -lt 3500 -and $text -match '& \$core') ($relative+' is a thin dispatcher, not a second collection implementation.')
}
$summary=[pscustomobject]@{Status='Passed';Assertions=$script:checks;PowerShellVersion=$PSVersionTable.PSVersion.ToString();OutputDirectory=$OutputDirectory;Scope='Actual compatibility entrypoints with private fixture engines; no registry/AppX queries, DISM/SFC execution or restart.'}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'merged-windows-results.json') -Encoding UTF8
$summary
