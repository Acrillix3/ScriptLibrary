<#
What it does:
  Runs Windows component-store diagnostics and optionally verifies protected system files.

Available flags:
  -ScanComponentStore: Use DISM ScanHealth instead of the faster default CheckHealth.
  -VerifySystemFiles: Also run SFC verifyonly; can take several minutes.
  -LogTailLines: Maximum lines copied from each existing diagnostic log; default 200.
  -OutputDirectory: Report destination; default Windows\Reports.

How it works:
  Runs diagnostic-only DISM and optional SFC modes, preserving native output and exit codes plus log
  tails. Requires an elevated session; failures remain unknown. Never uses RestoreHealth or scannow,
  and a successful command exit alone does not prove clean system files.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
[switch]$ScanComponentStore,
[switch]$VerifySystemFiles,
[ValidateRange(10,5000)][int]$LogTailLines=200,
[ValidateNotNullOrEmpty()][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) {
    $OutputDirectory = Join-Path $PSScriptRoot '..\Reports'
}
$scriptLabel = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runName = '{0}-{1}-{2}' -f $scriptLabel,[datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),[guid]::NewGuid().ToString('N').Substring(0,8)
$reportDirectory = (New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force -ErrorAction Stop).FullName
$queryLog = New-Object 'System.Collections.Generic.List[object]'
$queryErrors = New-Object 'System.Collections.Generic.List[object]'
function Invoke-ReportQuery {
    param([string]$Section,[scriptblock]$Action,[switch]$RequireData)
    try {
        $items = @(& $Action)
        if ($RequireData -and $items.Count -eq 0) { throw 'Required data was not returned.' }
        $queryLog.Add([pscustomobject]@{Section=$Section;Status=$(if($items.Count){'Collected'}else{'Empty'});Count=$items.Count;Error=''})
        [pscustomobject]@{Succeeded=$true;Data=$items}
    } catch {
        $queryErrors.Add([pscustomobject]@{Section=$Section;Error=$_.Exception.Message;ErrorId=$_.FullyQualifiedErrorId})
        $queryLog.Add([pscustomobject]@{Section=$Section;Status='Unknown';Count=$null;Error=$_.Exception.Message})
        [pscustomobject]@{Succeeded=$false;Data=@()}
    }
}
function Write-ReportCsv {
    param([string]$Name,[object[]]$Rows,[string[]]$Columns)
    $path=Join-Path $reportDirectory ($Name+'.csv')
    if (@($Rows).Count) {
        $Rows | Select-Object -Property $Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    } else {
        (($Columns | ForEach-Object { '"'+$_.Replace('"','""')+'"' }) -join ',') | Set-Content -LiteralPath $path -Encoding UTF8
    }
}
function Complete-Report {
    param([object]$Data,[string[]]$Notes)
    Write-ReportCsv -Name 'collection-status' -Rows $queryLog.ToArray() -Columns @('Section','Status','Count','Error')
    Write-ReportCsv -Name 'query-errors' -Rows $queryErrors.ToArray() -Columns @('Section','Error','ErrorId')
    $status='Complete'
    if($queryErrors.Count){$status='Partial'}
    if($queryErrors.Count -and @($queryLog | Where-Object Status -ne 'Unknown').Count -eq 0){$status='Unavailable'}
    $summary=[pscustomobject]@{
        Script=$scriptLabel;ComputerName=$env:COMPUTERNAME;CollectedUtc=[datetime]::UtcNow.ToString('o')
        CollectionStatus=$status;QueryErrorCount=$queryErrors.Count;ReportDirectory=$reportDirectory
        Data=$Data;Sections=$queryLog.ToArray();Notes=@('Collection status describes available evidence, not overall system health.')+$Notes
    }
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $reportDirectory 'summary.json') -Encoding UTF8
    @(
        $scriptLabel
        ('Collection: {0}; query errors: {1}' -f $status,$queryErrors.Count)
        ('Reports: '+$reportDirectory)
        ''
        'Collection results:'
        ($queryLog | Format-Table Section,Status,Count -AutoSize | Out-String -Width 180)
        'Interpretation:'
        ($summary.Notes -join [Environment]::NewLine)
    ) | Set-Content -LiteralPath (Join-Path $reportDirectory 'overview.txt') -Encoding UTF8
    if($queryErrors.Count){Write-Warning 'Some data was unavailable; review query-errors.csv and collection-status.csv.'}
    $summary
}

$nativeRows=New-Object 'System.Collections.Generic.List[object]'
function Invoke-IntegrityUtility {
    param([string]$Executable,[string[]]$Arguments,[string]$OutputFile)
    $command=Get-Command -Name $Executable -CommandType Application -ErrorAction Stop
    $savedPreference=$ErrorActionPreference; $captured=@(); $exitCode=$null
    try{
        $ErrorActionPreference='Continue'
        $captured=@(& $command.Source @Arguments 2>&1 | ForEach-Object {([string]$_).Replace([string][char]0,'')})
        $exitCode=$LASTEXITCODE
    }finally{$ErrorActionPreference=$savedPreference}
    $captured | Set-Content -LiteralPath (Join-Path $reportDirectory $OutputFile) -Encoding UTF8
    $row=[pscustomobject]@{Executable=$Executable;Arguments=($Arguments -join ' ');ExitCode=$exitCode;OutputFile=$OutputFile;Assessment='ReviewNativeOutput'}
    $nativeRows.Add($row)
    if($null -eq $exitCode -or $exitCode -ne 0){throw ("{0} returned exit code {1}; see {2}." -f $Executable,$exitCode,$OutputFile)}
    $row
}
$dismMode=if($ScanComponentStore){'/ScanHealth'}else{'/CheckHealth'}
$dism=Invoke-ReportQuery -Section 'Component store diagnostic' -Action {
    Invoke-IntegrityUtility -Executable 'dism.exe' -Arguments @('/Online','/Cleanup-Image',$dismMode,'/English',('/LogPath:'+(Join-Path $reportDirectory 'dism-run.log'))) -OutputFile 'dism-output.txt'
}
if($VerifySystemFiles){
    $sfc=Invoke-ReportQuery -Section 'Protected system file verification' -Action {
        Invoke-IntegrityUtility -Executable 'sfc.exe' -Arguments @('/verifyonly') -OutputFile 'sfc-output.txt'
    }
}else{$queryLog.Add([pscustomobject]@{Section='Protected system file verification';Status='NotRequested';Count=0;Error=''})}
Write-ReportCsv 'native-command-results' $nativeRows.ToArray() @('Executable','Arguments','ExitCode','OutputFile','Assessment')
$logRows=New-Object 'System.Collections.Generic.List[object]'
foreach($definition in @(
    @{Name='CBS';Source=(Join-Path $env:WINDIR 'Logs\CBS\CBS.log');Output='CBS-tail.txt'},
    @{Name='DISM-existing';Source=(Join-Path $env:WINDIR 'Logs\DISM\dism.log');Output='DISM-existing-tail.txt'}
)){
    $log=Invoke-ReportQuery -Section ($definition.Name+' log tail') -Action {
        try{
            $lines=@(Get-Content -LiteralPath $definition.Source -Tail $LogTailLines -ErrorAction Stop)
            $lines | Set-Content -LiteralPath (Join-Path $reportDirectory $definition.Output) -Encoding UTF8
            [pscustomobject]@{Source=$definition.Source;Output=$definition.Output;Lines=$lines.Count;Status='Collected'}
        }catch{
            if($_.CategoryInfo.Category -eq 'ObjectNotFound'){[pscustomobject]@{Source=$definition.Source;Output='';Lines=0;Status='NotPresent'}}
            else{throw}
        }
    }
    foreach($row in $log.Data){$logRows.Add($row)}
}
Write-ReportCsv 'log-tail-sources' $logRows.ToArray() @('Source','Output','Lines','Status')
Complete-Report -Data ([ordered]@{
    DismMode=$dismMode;SystemFileVerificationRequested=[bool]$VerifySystemFiles
    NativeCommands=$nativeRows.ToArray();Assessment='ReviewNativeOutput';LogTailLines=$LogTailLines
}) -Notes @(
    'Run elevated. DISM CheckHealth reads known corruption state; ScanHealth performs a longer diagnostic scan. SFC verifyonly verifies without repairing.'
    'No RestoreHealth, scannow, component cleanup, reboot, or repair is requested. Windows utilities may write their own diagnostic logs/state.'
    'Exit code zero indicates utility completion, not by itself an assessment that corruption is absent. Review native output and current-run logs.'
    'Existing CBS/DISM log tails can contain earlier operations; correlate timestamps before attributing entries to this run.'
)
