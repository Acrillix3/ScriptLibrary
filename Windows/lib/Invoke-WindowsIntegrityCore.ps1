<#
What it does:
  Implements shared DISM/SFC execution and compatible diagnostic/repair reports.
Available flags:
  Internal Compatibility Diagnostic|Repair; callers forward their documented flags and optional Mode.
How it works:
  One native runner and sequence apply caller-specific scan, failure and restart policies. Reports
  are saved before separate restart confirmation. Copy Windows/lib with both public entrypoints.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param(
 [ValidateSet('Diagnostic','Repair')][string]$Compatibility='Repair',
 [switch]$ScanComponentStore,[switch]$VerifySystemFiles,
 [switch]$Apply,[switch]$Diagnose,[ValidateSet('Check','Scan','Verify','Repair')][string]$Mode,
 [string]$Source,[ValidateRange(1,65535)][int]$SourceIndex,[switch]$LimitAccess,[switch]$SkipRestartPrompt,
 [ValidateRange(0,5000)][int]$LogTailLines=200,[ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
if($Apply -and $Diagnose){throw 'Choose Apply or Diagnose, not both.'}
if($PSBoundParameters.ContainsKey('Mode') -and $Diagnose){throw 'Mode and Diagnose cannot be combined.'}
if($Mode -and $Mode -ne 'Repair' -and $Apply){throw 'Read-only Mode values cannot be combined with Apply.'}
if(($Source -or $LimitAccess) -and -not $Apply){throw 'Source and LimitAccess require Apply (WhatIf can preview Apply).'}
if($SourceIndex -and -not $Source){throw 'SourceIndex requires a WIM or ESD Source file.'}
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$scriptLabel=if($Compatibility -eq 'Diagnostic'){'Test-SystemFileHealth'}else{'Repair-WindowsSystemFiles'}
$runName='{0}-{1}-{2}' -f $scriptLabel,[datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),[guid]::NewGuid().ToString('N').Substring(0,8)
$reportDirectory=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force -WhatIf:$false -Confirm:$false).FullName
$rows=New-Object 'System.Collections.Generic.List[object]'
$queryLog=New-Object 'System.Collections.Generic.List[object]'
$queryErrors=New-Object 'System.Collections.Generic.List[object]'
$runState=@{RestartRequired=$false;RestartStatus='NotIndicated'}
function Assert-NativeAdministrator {
 if($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess){throw 'Run native 64-bit Windows PowerShell 5.1 on 64-bit Windows.'}
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 try{if(-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run elevated as an administrator.'}}finally{$identity.Dispose()}
}
function Resolve-RepairSource {
 param([string]$Path,[int]$Index)
 if($Path -match '[\r\n"\x00]'){throw 'Source contains unsupported characters.'}
 $item=Get-Item -LiteralPath $Path -ErrorAction Stop
 if($item.PSProvider.Name -ne 'FileSystem'){throw 'Source must be a filesystem path.'}
 if($item.PSIsContainer){if($Index){throw 'SourceIndex is only for a WIM or ESD file.'};return $item.FullName}
 $extension=$item.Extension.ToLowerInvariant()
 if($extension -notin @('.wim','.esd') -or $Index -lt 1){throw 'A WIM or ESD source requires SourceIndex; other source files are unsupported.'}
 '{0}:{1}:{2}' -f $extension.TrimStart('.'),$item.FullName,$Index
}
function Write-IntegrityCsv {
 param([string]$Name,[object[]]$Rows,[string[]]$Columns)
 $path=Join-Path $reportDirectory ($Name+'.csv')
 if(@($Rows).Count){$Rows | Select-Object $Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false}
 else{(($Columns | ForEach-Object {'"'+$_.Replace('"','""')+'"'}) -join ',') | Set-Content -LiteralPath $path -Encoding UTF8 -WhatIf:$false -Confirm:$false}
}
function Invoke-SystemFileUtility {
 param([string]$Executable,[string[]]$Arguments,[string]$Label)
 $nativePath=Join-Path $env:WINDIR ('System32\'+$Executable)
 if(-not (Test-Path -LiteralPath $nativePath -PathType Leaf)){throw ('Missing Windows utility: '+$Executable)}
 $savedPreference=$ErrorActionPreference
 try{
  $ErrorActionPreference='Continue';$global:LASTEXITCODE=$null
  $output=@(& $nativePath @Arguments 2>&1 | ForEach-Object {([string]$_).Replace([string][char]0,'')})
  $exitCode=$LASTEXITCODE
 }finally{$ErrorActionPreference=$savedPreference}
 $output | Set-Content -LiteralPath (Join-Path $reportDirectory ($Label+'-output.txt')) -Encoding UTF8 -WhatIf:$false -Confirm:$false
 [pscustomobject]@{Utility=$Executable;Arguments=($Arguments -join ' ');ExitCode=$exitCode;Assessment='ReviewNativeOutput';OutputFile=($Label+'-output.txt')}
}
function Add-IntegrityQueryResult {
 param([string]$Section,[object]$Result,[string]$Failure)
 if($Failure -or $null -eq $Result.ExitCode -or $Result.ExitCode -ne 0){
  $message=if($Failure){$Failure}else{('{0} returned exit code {1}; see {2}.' -f $Result.Utility,$Result.ExitCode,$Result.OutputFile)}
  $queryErrors.Add([pscustomobject]@{Section=$Section;Error=$message;ErrorId='IntegrityUtilityResult'})
  $queryLog.Add([pscustomobject]@{Section=$Section;Status='Unknown';Count=$null;Error=$message})
 }else{$queryLog.Add([pscustomobject]@{Section=$Section;Status='Collected';Count=1;Error=''})}
}
function Invoke-RepairSequence {
 param([bool]$Repair,[string]$RepairSource,[bool]$OfflineOnly,[string]$DiagnosticDism='/CheckHealth',[bool]$RunSfc=$true,[bool]$ContinueOnDismFailure=$false,[bool]$English=$false,[bool]$SkipDism=$false)
 $dismFailed=$false
 if(-not $SkipDism){
  $dismMode=if($Repair){'/RestoreHealth'}else{$DiagnosticDism}
  $log=if($Compatibility -eq 'Diagnostic'){'dism-run.log'}else{'dism-current-run.log'}
  $arguments=@('/Online','/Cleanup-Image',$dismMode)
  if($Compatibility -ne 'Diagnostic'){$arguments+='/NoRestart'}
  if($English){$arguments+='/English'}
  $arguments+=('/LogPath:'+(Join-Path $reportDirectory $log))
  if($RepairSource){$arguments+=('/Source:'+$RepairSource)}
  if($OfflineOnly){$arguments+='/LimitAccess'}
  $dism=$null
  try{
   $dism=Invoke-SystemFileUtility 'dism.exe' $arguments 'dism';$rows.Add($dism)
   $dismFailed=$null -eq $dism.ExitCode -or $dism.ExitCode -ne 0
   if($Compatibility -eq 'Diagnostic'){Add-IntegrityQueryResult 'Component store diagnostic' $dism ''}
  }catch{
   $dismFailed=$true
   if($Compatibility -eq 'Diagnostic'){Add-IntegrityQueryResult 'Component store diagnostic' $null $_.Exception.Message}else{throw}
  }
  if(-not $ContinueOnDismFailure){
   if($null -ne $dism -and $dism.ExitCode -eq 3010){$runState.RestartRequired=$true;$runState.RestartStatus='RequiredDeferred';return}
   if($dismFailed){$rows.Add([pscustomobject]@{Utility='sfc.exe';Arguments='';ExitCode=$null;Assessment='SkippedBecauseDismFailed';OutputFile=''});return}
  }
 }
 if($RunSfc){
  $sfcMode=if($Repair){'/scannow'}else{'/verifyonly'}
  try{
   $sfc=Invoke-SystemFileUtility 'sfc.exe' @($sfcMode) 'sfc';$rows.Add($sfc)
   if($Compatibility -eq 'Diagnostic'){Add-IntegrityQueryResult 'Protected system file verification' $sfc ''}
   elseif($sfc.ExitCode -eq 3010){$runState.RestartRequired=$true;$runState.RestartStatus='RequiredDeferred'}
  }catch{if($Compatibility -eq 'Diagnostic'){Add-IntegrityQueryResult 'Protected system file verification' $null $_.Exception.Message}else{throw}}
 }elseif($Compatibility -eq 'Diagnostic'){$queryLog.Add([pscustomobject]@{Section='Protected system file verification';Status='NotRequested';Count=0;Error=''})}
}
function Copy-IntegrityLogTail {
 param([string]$Name,[string]$Source,[string]$Output)
 try{
  $lines=@(Get-Content -LiteralPath $Source -Tail $LogTailLines -ErrorAction Stop)
  $lines | Set-Content -LiteralPath (Join-Path $reportDirectory $Output) -Encoding UTF8 -WhatIf:$false -Confirm:$false
  if($Compatibility -eq 'Diagnostic'){$queryLog.Add([pscustomobject]@{Section=($Name+' log tail');Status='Collected';Count=1;Error=''})}
  [pscustomobject]@{Source=$Source;Output=$Output;Lines=$lines.Count;Status='Collected'}
 }catch{
  if($Compatibility -eq 'Diagnostic'){
   if($_.CategoryInfo.Category -eq 'ObjectNotFound'){$queryLog.Add([pscustomobject]@{Section=($Name+' log tail');Status='Collected';Count=1;Error=''})}
   else{$queryErrors.Add([pscustomobject]@{Section=($Name+' log tail');Error=$_.Exception.Message;ErrorId=$_.FullyQualifiedErrorId});$queryLog.Add([pscustomobject]@{Section=($Name+' log tail');Status='Unknown';Count=$null;Error=$_.Exception.Message})}
  }else{$rows.Add([pscustomobject]@{Utility=($Name+' log tail');Arguments='';ExitCode=$null;Assessment='Unavailable';OutputFile=''})}
  [pscustomobject]@{Source=$Source;Output='';Lines=0;Status='NotPresent'}
 }
}
function Save-SystemFileReport {
 param([string]$RunStatus,[string]$Failure)
 Write-IntegrityCsv 'native-results' $rows.ToArray() @('Utility','Arguments','ExitCode','Assessment','OutputFile')
 [pscustomobject]@{Script='Repair-WindowsSystemFiles';CollectedUtc=[datetime]::UtcNow.ToString('o');RunStatus=$RunStatus;Error=$Failure;Apply=[bool]$Apply;Diagnose=[bool]$Diagnose;Mode=$Mode;RestartRequired=$runState.RestartRequired;RestartStatus=$runState.RestartStatus;Assessment='ReviewNativeOutput';NativeResults=$rows.ToArray();ReportDirectory=$reportDirectory;Notes=@('Successful native completion does not by itself prove absence of corruption. Review DISM/SFC output and CBS timestamps.','A source must match installed Windows version, edition, language and servicing level. Windows Update may be contacted unless LimitAccess is used.','A DISM restart requirement defers SFC until after restart. Run again to complete verification.','Existing CBS tails may include earlier runs; correlate timestamps.')} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $reportDirectory 'summary.json') -Encoding UTF8 -WhatIf:$false -Confirm:$false
}
function Complete-LegacyIntegrityReport {
 param([string]$DismMode,[object[]]$LogRows)
 $nativeRows=@($rows | ForEach-Object {[pscustomobject]@{Executable=$_.Utility;Arguments=$_.Arguments;ExitCode=$_.ExitCode;OutputFile=$_.OutputFile;Assessment=$_.Assessment}})
 Write-IntegrityCsv 'native-command-results' $nativeRows @('Executable','Arguments','ExitCode','OutputFile','Assessment')
 Write-IntegrityCsv 'collection-status' $queryLog.ToArray() @('Section','Status','Count','Error')
 Write-IntegrityCsv 'query-errors' $queryErrors.ToArray() @('Section','Error','ErrorId')
 Write-IntegrityCsv 'log-tail-sources' $LogRows @('Source','Output','Lines','Status')
 $collection=if($queryErrors.Count){'Partial'}else{'Complete'}
 if($queryErrors.Count -and @($queryLog | Where-Object Status -ne 'Unknown').Count -eq 0){$collection='Unavailable'}
 $notes=@('Collection status describes available evidence, not overall system health.','Run elevated. DISM CheckHealth reads known corruption state; ScanHealth performs a longer diagnostic scan. SFC verifyonly verifies without repairing.','No RestoreHealth, scannow, component cleanup, reboot, or repair is requested. Windows utilities may write their own diagnostic logs/state.','Exit code zero indicates utility completion, not by itself an assessment that corruption is absent. Review native output and current-run logs.','Existing CBS/DISM log tails can contain earlier operations; correlate timestamps before attributing entries to this run.')
 $summary=[pscustomobject]@{Script=$scriptLabel;ComputerName=$env:COMPUTERNAME;CollectedUtc=[datetime]::UtcNow.ToString('o');CollectionStatus=$collection;QueryErrorCount=$queryErrors.Count;ReportDirectory=$reportDirectory;Data=[ordered]@{DismMode=$DismMode;SystemFileVerificationRequested=[bool]$VerifySystemFiles;NativeCommands=$nativeRows;Assessment='ReviewNativeOutput';LogTailLines=$LogTailLines};Sections=$queryLog.ToArray();Notes=$notes}
 $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $reportDirectory 'summary.json') -Encoding UTF8 -WhatIf:$false -Confirm:$false
 @($scriptLabel;('Collection: {0}; query errors: {1}' -f $collection,$queryErrors.Count);('Reports: '+$reportDirectory);'';'Collection results:';($queryLog | Format-Table Section,Status,Count -AutoSize | Out-String -Width 180);'Interpretation:';($notes -join [Environment]::NewLine)) | Set-Content -LiteralPath (Join-Path $reportDirectory 'overview.txt') -Encoding UTF8 -WhatIf:$false -Confirm:$false
 if($queryErrors.Count){Write-Warning 'Some data was unavailable; review query-errors.csv and collection-status.csv.'}
 $summary
}
if($Compatibility -eq 'Diagnostic'){
 $dismMode=if($ScanComponentStore){'/ScanHealth'}else{'/CheckHealth'}
 if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Run selected diagnostic-only DISM and optional SFC verification')){
  Invoke-RepairSequence -Repair $false -RepairSource '' -OfflineOnly $false -DiagnosticDism $dismMode -RunSfc ([bool]$VerifySystemFiles) -ContinueOnDismFailure $true -English $true
 }else{
  $queryLog.Add([pscustomobject]@{Section='Component store diagnostic';Status='NotExecuted';Count=0;Error=''})
  $queryLog.Add([pscustomobject]@{Section='Protected system file verification';Status=$(if($VerifySystemFiles){'NotExecuted'}else{'NotRequested'});Count=0;Error=''})
 }
 $logRows=@(Copy-IntegrityLogTail 'CBS' (Join-Path $env:WINDIR 'Logs\CBS\CBS.log') 'CBS-tail.txt';Copy-IntegrityLogTail 'DISM-existing' (Join-Path $env:WINDIR 'Logs\DISM\dism.log') 'DISM-existing-tail.txt')
 Complete-LegacyIntegrityReport $dismMode $logRows
}else{
 $status='Plan';$failure=''
 try{
  $repairSource='';if($Source){$repairSource=Resolve-RepairSource $Source $SourceIndex}
  $execute=$Apply -or $Diagnose -or ($Mode -and $Mode -ne 'Repair')
  if($execute){
   $repair=[bool]$Apply;$dismMode=if($Mode -eq 'Scan'){'/ScanHealth'}else{'/CheckHealth'}
   $runSfc=if($Mode -in @('Check','Scan')){$false}else{$true}
   $action=if($repair){'Run DISM RestoreHealth, then SFC scannow if DISM succeeds without requiring restart'}else{'Run selected read-only DISM/SFC checks'}
   if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,$action)){
    Assert-NativeAdministrator
    Invoke-RepairSequence -Repair $repair -RepairSource $repairSource -OfflineOnly ([bool]$LimitAccess) -DiagnosticDism $dismMode -RunSfc $runSfc -SkipDism ($Mode -eq 'Verify')
    $status=if(@($rows | Where-Object {$_.Assessment -eq 'ReviewNativeOutput' -and ($null -eq $_.ExitCode -or $_.ExitCode -notin @(0,3010))}).Count){'NativeFailed'}else{'ExecutedReviewNativeResults'}
   }else{$status='NotExecuted'}
  }
 }catch{$status='Failed';$failure=$_.Exception.Message}
 if($status -in @('ExecutedReviewNativeResults','NativeFailed') -and $LogTailLines -gt 0){$null=Copy-IntegrityLogTail 'CBS' (Join-Path $env:WINDIR 'Logs\CBS\CBS.log') 'CBS-tail.txt'}
 Save-SystemFileReport $status $failure
 if($runState.RestartRequired -and -not $SkipRestartPrompt -and -not $WhatIfPreference){
  try{
   if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Restart Windows after saving repair reports') -and $PSCmdlet.ShouldContinue('A native utility reported that Windows must restart. Restart this computer now? Save your work first.','Separate restart confirmation')){
    $runState.RestartStatus='RestartRequested';Save-SystemFileReport $status $failure;Restart-Computer -ErrorAction Stop
   }
  }catch{$runState.RestartStatus='RestartNotPerformed';$failure=$_.Exception.Message;Save-SystemFileReport $status $failure}
 }
 [pscustomobject]@{RunStatus=$status;RestartRequired=$runState.RestartRequired;RestartStatus=$runState.RestartStatus;ReportDirectory=$reportDirectory;Error=$failure}
 if($status -eq 'Failed'){Write-Warning ('Repair did not complete: '+$failure)}
}
