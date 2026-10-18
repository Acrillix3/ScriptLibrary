<#
What it does:
  Reports printers, ports, queued jobs, the default printer, and spooler status.

Available flags:
  -IncludeDocumentNames: Include potentially sensitive print-job titles.
  -OutputDirectory <path>: Report destination; default Windows\Reports.

How it works:
  Reads PrintManagement, CIM, and service data in the executing user's context. Saves CSV/JSON
  reports; does not clear jobs or restart services. Requires Windows printing management tools.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$IncludeDocumentNames,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$runName='07-PrinterDiagnostics-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), ([guid]::NewGuid().ToString('N').Substring(0,8))
$report=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force).FullName
$queryErrors=New-Object 'System.Collections.Generic.List[object]'
function Export-PrinterCsv {
    param([object[]]$Rows,[string]$Name,[string]$Header)
    if (@($Rows).Count) { $Rows | Export-Csv -LiteralPath (Join-Path $report $Name) -NoTypeInformation -Encoding UTF8 }
    else { $Header | Set-Content -LiteralPath (Join-Path $report $Name) -Encoding UTF8 }
}
$printers=@(); $ports=@(); $defaults=@(); $spooler=$null
$jobs=New-Object 'System.Collections.Generic.List[object]'
$queues=New-Object 'System.Collections.Generic.List[object]'
try { Import-Module PrintManagement -ErrorAction Stop }
catch {
    [pscustomobject]@{Status='Failed'; Error=$_.Exception.Message; ReportDirectory=$report} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
    throw 'PrintManagement is unavailable. Run in Windows PowerShell 5.1 on a Windows system with printing tools installed.'
}
try { $defaults=@(Get-CimInstance -ClassName Win32_Printer -ErrorAction Stop | Where-Object Default | Select-Object -ExpandProperty Name) }
catch { $queryErrors.Add([pscustomobject]@{Query='Default printer'; Error=$_.Exception.Message}) }
try { $spooler=Get-Service -Name Spooler -ErrorAction Stop | Select-Object Name,DisplayName,Status,StartType }
catch { $queryErrors.Add([pscustomobject]@{Query='Print Spooler'; Error=$_.Exception.Message}) }
try { $printers=@(Get-Printer -ErrorAction Stop) }
catch { $queryErrors.Add([pscustomobject]@{Query='Printer inventory'; Error=$_.Exception.Message}) }
try { $ports=@(Get-PrinterPort -ErrorAction Stop | Select-Object Name,Description,PrinterHostAddress,PortNumber,Protocol,SNMPEnabled) }
catch { $queryErrors.Add([pscustomobject]@{Query='Printer ports'; Error=$_.Exception.Message}) }
$printerRows=@(foreach ($printer in $printers) {
    [pscustomobject]@{
        Name=$printer.Name; DriverName=$printer.DriverName; PortName=$printer.PortName
        Type=[string]$printer.Type; Shared=$printer.Shared; ShareName=$printer.ShareName
        PrinterStatus=[string]$printer.PrinterStatus
        IsDefault=$(if (@($queryErrors | Where-Object Query -eq 'Default printer').Count) {$null} else {$defaults -contains $printer.Name})
    }
    try {
        $queueJobs=@(Get-PrintJob -PrinterName $printer.Name -ErrorAction Stop)
        foreach ($job in $queueJobs) {
            $jobs.Add([pscustomobject]@{
                PrinterName=$printer.Name; Id=$job.Id; JobStatus=[string]$job.JobStatus
                SubmittedTime=$job.SubmittedTime; Size=$job.Size; TotalPages=$job.TotalPages
                DocumentName=$(if ($IncludeDocumentNames) {$job.DocumentName} else {'[excluded]'})
            })
        }
        $queues.Add([pscustomobject]@{PrinterName=$printer.Name; Status='Collected'; JobCount=$queueJobs.Count; Error=''})
    } catch {
        $queues.Add([pscustomobject]@{PrinterName=$printer.Name; Status='Unknown'; JobCount=$null; Error=$_.Exception.Message})
        $queryErrors.Add([pscustomobject]@{Query="Queue $($printer.Name)"; Error=$_.Exception.Message})
    }
})
Export-PrinterCsv -Rows $printerRows -Name 'printers.csv' -Header '"Name","DriverName","PortName","Type","Shared","ShareName","PrinterStatus","IsDefault"'
Export-PrinterCsv -Rows $ports -Name 'printer-ports.csv' -Header '"Name","Description","PrinterHostAddress","PortNumber","Protocol","SNMPEnabled"'
Export-PrinterCsv -Rows @($jobs.ToArray()) -Name 'print-jobs.csv' -Header '"PrinterName","Id","JobStatus","SubmittedTime","Size","TotalPages","DocumentName"'
Export-PrinterCsv -Rows @($queues.ToArray()) -Name 'queue-status.csv' -Header '"PrinterName","Status","JobCount","Error"'
Export-PrinterCsv -Rows @($queryErrors.ToArray()) -Name 'query-errors.csv' -Header '"Query","Error"'
ConvertTo-Json -InputObject $spooler | Set-Content -LiteralPath (Join-Path $report 'spooler.json') -Encoding UTF8
$summary=[pscustomobject]@{
    Status=$(if ($queryErrors.Count) {'Partial'} else {'Complete'})
    ComputerName=$env:COMPUTERNAME; ExecutingUser=('{0}\{1}' -f $env:USERDOMAIN,$env:USERNAME)
    PrinterCount=$printers.Count; JobCount=$jobs.Count; DefaultPrinters=$defaults
    SpoolerStatus=[string]$spooler.Status; QueryErrorCount=$queryErrors.Count
    DocumentNamesIncluded=[bool]$IncludeDocumentNames; CollectedUtc=[datetime]::UtcNow.ToString('o')
    ReportDirectory=$report
}
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
if ($queryErrors.Count) { Write-Warning 'Some printer details could not be read; see query-errors.csv.' }
$summary

