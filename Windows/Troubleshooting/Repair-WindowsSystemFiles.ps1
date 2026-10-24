<#
What it does:
  Plans or runs DISM image repair followed by SFC, preserving native results and logs.

Available flags:
  -Apply: Repair with DISM RestoreHealth and SFC scannow. Default is a plan.
  -Diagnose: Run CheckHealth and SFC verifyonly instead of repairs; cannot combine with Apply.
  -Source, -SourceIndex: Optional repair folder or WIM/ESD file and positive image index.
  -LimitAccess: Do not contact Windows Update for repair content.
  -SkipRestartPrompt: Defer any required restart without prompting.
  -LogTailLines: Existing CBS log lines to copy; default 200. -OutputDirectory: Report location.
  -WhatIf, -Confirm: Standard PowerShell change controls.

How it works:
  Requires native 64-bit elevated Windows PowerShell for execution. DISM uses NoRestart;
  failed DISM or a required restart prevents SFC. Saves results before a separate restart
  confirmation. Exit zero alone does not establish health; review localized native output.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param(
    [switch]$Apply,[switch]$Diagnose,
    [string]$Source,[ValidateRange(1,65535)][int]$SourceIndex,
    [switch]$LimitAccess,[switch]$SkipRestartPrompt,
    [ValidateRange(0,5000)][int]$LogTailLines=200,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
if($Apply -and $Diagnose){throw 'Choose Apply or Diagnose, not both.'}
if(($Source -or $LimitAccess) -and -not $Apply){throw 'Source and LimitAccess require Apply (WhatIf can preview Apply).'}
if($SourceIndex -and -not $Source){throw 'SourceIndex requires a WIM or ESD Source file.'}
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$runName='Repair-WindowsSystemFiles-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),[guid]::NewGuid().ToString('N').Substring(0,8)
$reportDirectory=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force -WhatIf:$false -Confirm:$false).FullName
$rows=New-Object 'System.Collections.Generic.List[object]'
$runState=@{RestartRequired=$false;RestartStatus='NotIndicated'}
function Assert-NativeAdministrator {
    if($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess){throw 'Run native 64-bit Windows PowerShell 5.1 on 64-bit Windows.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run elevated as an administrator.'}
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
function Invoke-SystemFileUtility {
    param([string]$Executable,[string[]]$Arguments,[string]$Label)
    $nativePath=Join-Path $env:WINDIR ('System32\'+$Executable)
    if(-not (Test-Path -LiteralPath $nativePath -PathType Leaf)){throw ('Missing Windows utility: '+$Executable)}
    $savedPreference=$ErrorActionPreference
    try{
        $ErrorActionPreference='Continue'
        $output=@(& $nativePath @Arguments 2>&1 | ForEach-Object {([string]$_).Replace([string][char]0,'')})
        $exitCode=$LASTEXITCODE
    }finally{$ErrorActionPreference=$savedPreference}
    $output | Set-Content -LiteralPath (Join-Path $reportDirectory ($Label+'-output.txt')) -Encoding UTF8 -WhatIf:$false -Confirm:$false
    [pscustomobject]@{Utility=$Executable;Arguments=($Arguments -join ' ');ExitCode=$exitCode;Assessment='ReviewNativeOutput';OutputFile=($Label+'-output.txt')}
}
function Invoke-RepairSequence {
    param([bool]$Repair,[string]$RepairSource,[bool]$OfflineOnly)
    $dismMode=if($Repair){'/RestoreHealth'}else{'/CheckHealth'}
    $arguments=@('/Online','/Cleanup-Image',$dismMode,'/NoRestart',('/LogPath:'+(Join-Path $reportDirectory 'dism-current-run.log')))
    if($RepairSource){$arguments+=('/Source:'+$RepairSource)}
    if($OfflineOnly){$arguments+='/LimitAccess'}
    $dism=Invoke-SystemFileUtility 'dism.exe' $arguments 'dism'
    $rows.Add($dism)
    if($dism.ExitCode -eq 3010){$runState.RestartRequired=$true;$runState.RestartStatus='RequiredDeferred';return}
    if($null -eq $dism.ExitCode -or $dism.ExitCode -ne 0){$rows.Add([pscustomobject]@{Utility='sfc.exe';Arguments='';ExitCode=$null;Assessment='SkippedBecauseDismFailed';OutputFile=''});return}
    $sfcMode=if($Repair){'/scannow'}else{'/verifyonly'}
    $sfc=Invoke-SystemFileUtility 'sfc.exe' @($sfcMode) 'sfc'
    $rows.Add($sfc)
    if($sfc.ExitCode -eq 3010){$runState.RestartRequired=$true;$runState.RestartStatus='RequiredDeferred'}
}
function Save-SystemFileReport {
    param([string]$RunStatus,[string]$Failure)
    $rows.ToArray() | Export-Csv -LiteralPath (Join-Path $reportDirectory 'native-results.csv') -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false
    [pscustomobject]@{
        Script='Repair-WindowsSystemFiles';CollectedUtc=[datetime]::UtcNow.ToString('o');RunStatus=$RunStatus;Error=$Failure
        Apply=[bool]$Apply;Diagnose=[bool]$Diagnose;RestartRequired=$runState.RestartRequired;RestartStatus=$runState.RestartStatus
        Assessment='ReviewNativeOutput';NativeResults=$rows.ToArray();ReportDirectory=$reportDirectory
        Notes=@('Successful native completion does not by itself prove absence of corruption. Review DISM/SFC output and CBS timestamps.','A source must match the installed Windows version, edition, language, and servicing level. Windows Update may be contacted unless LimitAccess is used.','A DISM restart requirement defers SFC until after restart. Run again to complete verification.','Existing CBS tails may include earlier runs. Reports can contain computer paths and should be handled as support evidence.')
    } | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $reportDirectory 'summary.json') -Encoding UTF8 -WhatIf:$false -Confirm:$false
}
$status='Plan';$failure=''
try{
    $repairSource=''
    if($Source){$repairSource=Resolve-RepairSource $Source $SourceIndex}
    if($Apply -or $Diagnose){
        $action=if($Apply){'Run DISM RestoreHealth, then SFC scannow if DISM succeeds without requiring restart'}else{'Run DISM CheckHealth, then SFC verifyonly if DISM succeeds'}
        if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,$action)){
            Assert-NativeAdministrator
            Invoke-RepairSequence ([bool]$Apply) $repairSource ([bool]$LimitAccess)
            $status=if(@($rows | Where-Object {$_.Assessment -eq 'ReviewNativeOutput' -and ($null -eq $_.ExitCode -or $_.ExitCode -notin @(0,3010))}).Count){'NativeFailed'}else{'ExecutedReviewNativeResults'}
        }else{$status='NotExecuted'}
    }
}catch{$status='Failed';$failure=$_.Exception.Message}
if($status -in @('ExecutedReviewNativeResults','NativeFailed') -and $LogTailLines -gt 0){
    try{Get-Content -LiteralPath (Join-Path $env:WINDIR 'Logs\CBS\CBS.log') -Tail $LogTailLines -ErrorAction Stop | Set-Content -LiteralPath (Join-Path $reportDirectory 'CBS-tail.txt') -Encoding UTF8 -WhatIf:$false -Confirm:$false}catch{$rows.Add([pscustomobject]@{Utility='CBS log tail';Arguments='';ExitCode=$null;Assessment='Unavailable';OutputFile=''})}
}
Save-SystemFileReport $status $failure
if($runState.RestartRequired -and -not $SkipRestartPrompt -and -not $WhatIfPreference){
    try{
        if($PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Restart Windows after saving repair reports') -and $PSCmdlet.ShouldContinue('A native utility reported that Windows must restart. Restart this computer now? Save your work first.','Separate restart confirmation')){
            $runState.RestartStatus='RestartRequested';Save-SystemFileReport $status $failure
            Restart-Computer -ErrorAction Stop
        }
    }catch{$runState.RestartStatus='RestartNotPerformed';$failure=$_.Exception.Message;Save-SystemFileReport $status $failure}
}
[pscustomobject]@{RunStatus=$status;RestartRequired=$runState.RestartRequired;RestartStatus=$runState.RestartStatus;ReportDirectory=$reportDirectory;Error=$failure}
if($status -eq 'Failed'){Write-Warning ('Repair did not complete: '+$failure)}
