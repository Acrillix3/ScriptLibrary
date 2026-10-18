<#
What it does:
  Reports the status and startup mode of selected Windows services.

Available flags:
  -Name <names>: Exact service names; default Spooler, wuauserv, BITS, Dnscache, and
    LanmanWorkstation.
  -OutputDirectory <path>: Report destination; default Windows\Reports.

How it works:
  Reads local service information through CIM and saves CSV/JSON reports. Missing services and
  failed queries are distinct; stopped on-demand services are not automatically faults.
#>
#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()][string[]]$Name = @('Spooler','wuauserv','BITS','Dnscache','LanmanWorkstation'),
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$reportDirectory = Join-Path $OutputDirectory ('08-ServiceHealth_{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $reportDirectory -Force -ErrorAction Stop
$rows = New-Object 'System.Collections.Generic.List[object]'
foreach ($serviceName in ($Name | Select-Object -Unique)) {
    try {
        $escapedName = $serviceName.Replace("'","''")
        $service = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='$escapedName'" -ErrorAction Stop)
        if ($service.Count -eq 0) {
            $rows.Add([pscustomobject]@{Name=$serviceName;DisplayName='';State='';StartMode='';Result='NotFound';Error='No service with this exact name was returned.'})
        } else {
            foreach ($item in $service) {
                $rows.Add([pscustomobject]@{Name=$item.Name;DisplayName=$item.DisplayName;State=$item.State;StartMode=$item.StartMode;Result='Observed';Error=''})
            }
        }
    } catch {
        $rows.Add([pscustomobject]@{Name=$serviceName;DisplayName='';State='';StartMode='';Result='QueryFailed';Error=$_.Exception.Message})
        Write-Warning ('Could not inspect {0}: {1}' -f $serviceName,$_.Exception.Message)
    }
}
$rows | Export-Csv -LiteralPath (Join-Path $reportDirectory 'services.csv') -NoTypeInformation -Encoding UTF8
$failed = @($rows | Where-Object Result -eq 'QueryFailed').Count
$missing = @($rows | Where-Object Result -eq 'NotFound').Count
$status = 'Success'
if ($failed -eq $rows.Count) { $status = 'Failed' } elseif ($failed -gt 0) { $status = 'Partial' } elseif ($missing -gt 0) { $status = 'NeedsReview' }
$summary = [pscustomobject]@{ReportDirectory=$reportDirectory;Status=$status;RequestedServiceCount=$rows.Count;RunningCount=@($rows | Where-Object State -eq 'Running').Count;MissingCount=$missing;QueryFailureCount=$failed}
[pscustomobject]@{Summary=$summary;Services=@($rows.ToArray())} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $reportDirectory 'report.json') -Encoding UTF8
'Observed service state only. Stopped/manual/trigger-start services can be normal. No service was restarted or reconfigured.' | Set-Content -LiteralPath (Join-Path $reportDirectory 'notes.txt') -Encoding UTF8
$summary

