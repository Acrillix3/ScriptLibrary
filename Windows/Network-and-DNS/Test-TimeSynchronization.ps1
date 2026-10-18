<#
What it does:
  Collects Windows Time configuration and status, with an optional time-server offset sample.

Available flags:
  -TimeServer: Optional hostname or IP address for a bounded stripchart measurement.
  -Samples: Offset samples, 1-10; default 3.
  -PeriodSeconds: Seconds between offset samples, 1-10; default 2.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Reads W32Time service/registry data and captures w32tm output with exit codes. Requires Windows
  Time tools and sufficient access; localized text is saved for review, and successful collection
  does not prove synchronization.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:\-]{0,252}$')][string]$TimeServer,
    [ValidateRange(1,10)][int]$Samples = 3,
    [ValidateRange(1,10)][int]$PeriodSeconds = 2,
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

$nativeRows = New-Object 'System.Collections.Generic.List[object]'
$findings = New-Object 'System.Collections.Generic.List[object]'
$service = Invoke-ReportQuery 'WindowsTimeService' {
    Get-CimInstance -ClassName Win32_Service -Filter "Name='W32Time'" -ErrorAction Stop | Select-Object Name,State,StartMode
} -RequireData
if ($service.Succeeded -and $service.Data[0].State -ne 'Running') {
    $findings.Add([pscustomobject]@{Check='WindowsTimeService';Result='Review';Detail=('Observed state: '+$service.Data[0].State+'; on-demand service state alone does not establish a fault.')})
}
$configuration = Invoke-ReportQuery 'ConfiguredTimeParameters' {
    $item = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction Stop
    if ($null -eq $item.PSObject.Properties['Type']) { throw 'The configured time-client Type value was not available.' }
    [pscustomobject]@{Type=$item.Type;NtpServer=$item.NtpServer;ServiceDll=$item.ServiceDll;Scope='Local registry; effective policy/provider behavior may differ'}
} -RequireData
$native = Invoke-ReportQuery 'WindowsTimeTool' { Get-Command -Name w32tm.exe -CommandType Application -ErrorAction Stop } -RequireData
function Invoke-TimeCapture {
    param([string]$Name,[string[]]$Arguments)
    $capture = Invoke-ReportQuery $Name {
        $global:LASTEXITCODE = $null
        $savedPreference = $ErrorActionPreference
        try { $ErrorActionPreference='Continue'; $textOutput=@(& $native.Data[0].Source @Arguments 2>&1 | ForEach-Object { $_.ToString() }); $exitCode=$LASTEXITCODE }
        finally { $ErrorActionPreference=$savedPreference }
        ($textOutput -join [Environment]::NewLine) | Set-Content -LiteralPath (Join-Path $reportDirectory ($Name+'.txt')) -Encoding UTF8
        $nativeRows.Add([pscustomobject]@{Command=$Name;Arguments=($Arguments -join ' ');ExitCode=$exitCode;RawFile=($Name+'.txt');Result=$(if($exitCode -eq 0){'CommandSucceeded'}else{'CommandFailed'})})
        if ($null -eq $exitCode) { throw 'The native command did not supply an exit code.' }
        if ($exitCode -ne 0) { throw ('w32tm exited with code '+$exitCode+'; raw output was retained.') }
        if (-not $textOutput.Count) { throw 'The command succeeded but returned no output.' }
        [pscustomobject]@{RawFile=($Name+'.txt');ExitCode=$exitCode}
    } -RequireData
    if (-not $capture.Succeeded) { $findings.Add([pscustomobject]@{Check=$Name;Result='Unknown';Detail='Command failed or data was unavailable; review raw output and query errors.'}) }
}
if ($native.Succeeded) {
    Invoke-TimeCapture 'time-source' @('/query','/source')
    Invoke-TimeCapture 'time-status' @('/query','/status','/verbose')
    Invoke-TimeCapture 'time-configuration' @('/query','/configuration')
    if ($TimeServer) { Invoke-TimeCapture 'offset-samples' @('/stripchart',('/computer:'+$TimeServer),('/samples:'+$Samples),('/period:'+$PeriodSeconds),'/dataonly') }
    else { $queryLog.Add([pscustomobject]@{Section='offset-samples';Status='Skipped';Count=0;Error='TimeServer was not specified.'}) }
}
Write-ReportCsv 'time-service' @($service.Data) @('Name','State','StartMode')
Write-ReportCsv 'configured-parameters' @($configuration.Data) @('Type','NtpServer','ServiceDll','Scope')
Write-ReportCsv 'native-commands' $nativeRows.ToArray() @('Command','Arguments','ExitCode','RawFile','Result')
Write-ReportCsv 'findings' $findings.ToArray() @('Check','Result','Detail')
Complete-Report -Data ([pscustomobject]@{TimeServer=$TimeServer;Samples=$(if($TimeServer){$Samples}else{0});NativeCommands=$nativeRows.ToArray();Findings=$findings.ToArray();SynchronizationAssessment='ManualReviewRequired'}) -Notes @(
    'w32tm text is localized and is not parsed into a trusted synchronization verdict. Read time-status.txt and time-source.txt for synchronization state and last successful sync.'
    'A zero exit code establishes command completion, not a correct source, acceptable offset, or sustained synchronization. Stripchart samples can contain per-sample errors; review raw output.'
    'Stripchart uses bounded samples but Windows network timeouts still apply. Its ephemeral UDP source port differs from the Windows Time client path.'
    'No resynchronization, time change, service change, or configuration update is performed.'
    'Reference: https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings'
)
