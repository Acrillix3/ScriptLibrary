<#
What it does:
  Exports installed desktop application names and versions.

Available flags:
  -IncludeAppx: Also list the executing user's AppX/MSIX packages.
  -OutputDirectory <path>: Report destination; default Windows\Reports.

How it works:
  Reads machine and current-user uninstall registrations in both registry views. Saves CSV/JSON
  reports without invoking installer repair checks; portable apps and other users' registrations may
  be absent.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$IncludeAppx,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$runName='05-InstalledSoftware-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), ([guid]::NewGuid().ToString('N').Substring(0,8))
$report=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force).FullName
$rows=New-Object 'System.Collections.Generic.List[object]'
$queryErrors=New-Object 'System.Collections.Generic.List[object]'
$views=@([Microsoft.Win32.RegistryView]::Registry32)
if ([Environment]::Is64BitOperatingSystem) { $views+= [Microsoft.Win32.RegistryView]::Registry64 }
foreach ($hive in @([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryHive]::CurrentUser)) {
    foreach ($view in $views) {
        $baseKey=$null; $uninstallKey=$null
        try {
            $baseKey=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
            $uninstallKey=$baseKey.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',$false)
            if ($null -eq $uninstallKey) { continue }
            foreach ($subKeyName in $uninstallKey.GetSubKeyNames()) {
                $entry=$null
                try {
                    $entry=$uninstallKey.OpenSubKey($subKeyName,$false)
                    if ($null -eq $entry) { continue }
                    $displayName=$entry.GetValue('DisplayName')
                    if ([string]::IsNullOrWhiteSpace([string]$displayName)) { continue }
                    $rows.Add([pscustomobject]@{
                        Name=[string]$displayName; Version=[string]$entry.GetValue('DisplayVersion')
                        Publisher=[string]$entry.GetValue('Publisher'); InstallDate=[string]$entry.GetValue('InstallDate')
                        Scope=[string]$hive; RegistryView=[string]$view; RegistryKey=$subKeyName
                        IsSystemComponent=($entry.GetValue('SystemComponent') -eq 1)
                    })
                } catch { $queryErrors.Add([pscustomobject]@{Query="$hive/$view/$subKeyName"; Error=$_.Exception.Message}) }
                finally { if ($entry) { $entry.Dispose() } }
            }
        } catch { $queryErrors.Add([pscustomobject]@{Query="$hive/$view"; Error=$_.Exception.Message}) }
        finally {
            if ($uninstallKey) { $uninstallKey.Dispose() }
            if ($baseKey) { $baseKey.Dispose() }
        }
    }
}
$inventory=@($rows | Sort-Object Name,Version,Scope,RegistryKey,RegistryView -Unique)
if ($inventory.Count) { $inventory | Export-Csv -LiteralPath (Join-Path $report 'installed-software.csv') -NoTypeInformation -Encoding UTF8 }
else { '"Name","Version","Publisher","InstallDate","Scope","RegistryView","RegistryKey","IsSystemComponent"' | Set-Content -LiteralPath (Join-Path $report 'installed-software.csv') -Encoding UTF8 }
$appx=@()
if ($IncludeAppx) {
    try {
        $appx=@(Get-AppxPackage -ErrorAction Stop | Select-Object Name,Version,Publisher,Architecture,PackageFullName)
    } catch { $queryErrors.Add([pscustomobject]@{Query='Current-user AppX/MSIX'; Error=$_.Exception.Message}) }
    if ($appx.Count) { $appx | Export-Csv -LiteralPath (Join-Path $report 'appx-packages.csv') -NoTypeInformation -Encoding UTF8 }
    else { '"Name","Version","Publisher","Architecture","PackageFullName"' | Set-Content -LiteralPath (Join-Path $report 'appx-packages.csv') -Encoding UTF8 }
}
if ($queryErrors.Count) { $queryErrors | Export-Csv -LiteralPath (Join-Path $report 'query-errors.csv') -NoTypeInformation -Encoding UTF8 }
else { '"Query","Error"' | Set-Content -LiteralPath (Join-Path $report 'query-errors.csv') -Encoding UTF8 }
$summary=[pscustomobject]@{
    Status=$(if ($queryErrors.Count) {'Partial'} else {'Complete'})
    ComputerName=$env:COMPUTERNAME; ExecutingUser=('{0}\{1}' -f $env:USERDOMAIN,$env:USERNAME)
    DesktopEntryCount=$inventory.Count; AppxIncluded=[bool]$IncludeAppx; AppxPackageCount=$appx.Count
    QueryErrorCount=$queryErrors.Count; CollectedUtc=[datetime]::UtcNow.ToString('o')
    Notes='Uninstall registrations may include updates/components and miss portable applications. CurrentUser refers to the executing account. Registry view duplicates can be legitimate.'
    ReportDirectory=$report
}
$summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
if ($queryErrors.Count) { Write-Warning 'Some inventory queries failed; see query-errors.csv.' }
$summary

