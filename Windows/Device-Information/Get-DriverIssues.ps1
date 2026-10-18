<#
What it does:
  Reports Plug and Play device errors and available signed-driver metadata.

Available flags:
  -IncludeHealthy: Also include devices with error code zero and complete driver metadata.
  -OutputDirectory: Report location (Windows\Reports by default).

How it works:
  Joins Win32_PnPEntity device codes to Win32_PnPSignedDriver records by device ID. Missing metadata
  stays unknown. Writes CSV/JSON reports without modifying drivers.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$IncludeHealthy,
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

$devices = Invoke-ReportQuery -Section 'PnP devices' -RequireData -Action { Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop }
$drivers = Invoke-ReportQuery -Section 'Signed driver metadata' -RequireData -Action { Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop }
$driversById = @{}
foreach ($driver in $drivers.Data) {
    if ($driver.DeviceID) { $driversById[[string]$driver.DeviceID] = $driver }
}
$rows = @(
    foreach ($device in $devices.Data) {
        $driver = $driversById[[string]$device.DeviceID]
        $code = $device.ConfigManagerErrorCode
        $deviceState = 'Unknown'
        if ($null -ne $code) { $deviceState = $(if ([int]$code -eq 0) { 'NoDeviceErrorReported' } else { 'DeviceErrorReported' }) }
        $metadata = 'Unknown'
        if ($driver -and $driver.DriverVersion -and $driver.InfName -and $null -ne $driver.IsSigned) { $metadata = 'Collected' }
        $finding = New-Object 'System.Collections.Generic.List[string]'
        if ($deviceState -eq 'DeviceErrorReported') { $finding.Add(('Device reports ConfigManagerErrorCode {0}.' -f $code)) }
        if ($null -ne $code -and [int]$code -eq 28) { $finding.Add('The device reports that its drivers are not installed.') }
        if ($metadata -eq 'Unknown') { $finding.Add('Driver metadata is incomplete or unavailable; this alone does not prove a missing driver.') }
        if ($driver -and $null -ne $driver.IsSigned -and -not $driver.IsSigned) { $finding.Add('The provider reports this driver as unsigned.') }
        if ($IncludeHealthy -or $deviceState -ne 'NoDeviceErrorReported' -or $metadata -eq 'Unknown' -or ($driver -and $null -ne $driver.IsSigned -and -not $driver.IsSigned)) {
            [pscustomobject]@{
                Name=$device.Name;DeviceID=$device.DeviceID;Manufacturer=$device.Manufacturer;DeviceStatus=$device.Status
                ConfigManagerErrorCode=$code;DeviceEvidence=$deviceState;DriverMetadata=$metadata
                DriverVersion=$(if($driver){$driver.DriverVersion}else{$null});DriverDate=$(if($driver){$driver.DriverDate}else{$null})
                DriverProvider=$(if($driver){$driver.DriverProviderName}else{$null});InfName=$(if($driver){$driver.InfName}else{$null})
                IsSigned=$(if($driver){$driver.IsSigned}else{$null});Signer=$(if($driver){$driver.Signer}else{$null});Findings=($finding.ToArray() -join ' ')
            }
        }
    }
)
Write-ReportCsv -Name 'device-drivers' -Rows $rows -Columns @('Name','DeviceID','Manufacturer','DeviceStatus','ConfigManagerErrorCode','DeviceEvidence','DriverMetadata','DriverVersion','DriverDate','DriverProvider','InfName','IsSigned','Signer','Findings')
Complete-Report -Data ([pscustomobject]@{DevicesExamined=$devices.Data.Count;RecordsReturned=$rows.Count;IncludeHealthy=[bool]$IncludeHealthy;Devices=$rows}) -Notes @(
    'A nonzero device code is the device provider observation; disabled or absent devices may be intentional. Review the numeric code before action.'
    'A zero error code is not a complete hardware health test. Signed-driver metadata does not verify the current file signature or establish driver trust.'
    'Only device metadata is read; no driver installation, removal, reset, or enable/disable operation is performed.'
)
