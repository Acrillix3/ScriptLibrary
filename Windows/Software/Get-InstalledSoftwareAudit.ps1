<#
What it does:
  Audits registered desktop software and optional AppX/MSIX packages, with optional baseline comparison.
Available flags:
  -IncludeLoadedUserHives: Read other already-loaded user hives. -IncludeAppx: Add current-user AppX/MSIX.
  -AllUsersAppx: Add AppX/MSIX user registrations; requires administrator. -BaselineCsv <path>: Compare a prior software.csv.
  -OutputDirectory <path>: Report destination; default Windows\Reports.
How it works:
  Reads both registry views without loading hives or invoking installer repair. Exports CSV, JSON, query status,
  errors, and optional inventory differences. Portable apps may be absent; differences are not vulnerability findings.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$IncludeLoadedUserHives,[switch]$IncludeAppx,[switch]$AllUsersAppx,[ValidateNotNullOrEmpty()][string]$BaselineCsv,[ValidateNotNullOrEmpty()][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
function ConvertTo-SoftwareInstallDate {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $date = [datetime]::MinValue
    if ([datetime]::TryParseExact([string]$Value,'yyyyMMdd',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$date)) { return $date.ToString('yyyy-MM-dd') }
    return $null
}
function New-SoftwareAuditRow {
    param([hashtable]$Values)
    $record = [ordered]@{ Name='Unknown'; Version='Unknown'; Publisher='Unknown'; Scope='Unknown'; UserSid=''; RegistryView='NotApplicable'; RegistryKeyName=''; InstallDateRaw=''; InstallDateISO=$null; EstimatedSizeKB=$null; WindowsInstaller=$null; SystemComponent=$null; Source='Unknown'; PackageArchitecture=''; InstallState='Unknown' }
    foreach ($key in $Values.Keys) { if ($record.Contains($key)) { $record[$key] = $Values[$key] } }
    [pscustomobject]$record
}
function ConvertTo-SoftwareRegistryRow {
    param([object]$Values,[string]$Scope,[string]$UserSid,[string]$View,[string]$KeyName)
    if ([string]::IsNullOrWhiteSpace([string]$Values.DisplayName)) { return }
    New-SoftwareAuditRow @{ Name=[string]$Values.DisplayName; Version=$(if ($Values.DisplayVersion) { [string]$Values.DisplayVersion } else { 'Unknown' }); Publisher=$(if ($Values.Publisher) { [string]$Values.Publisher } else { 'Unknown' }); Scope=$Scope; UserSid=$UserSid; RegistryView=$View; RegistryKeyName=$KeyName; InstallDateRaw=[string]$Values.InstallDate; InstallDateISO=(ConvertTo-SoftwareInstallDate $Values.InstallDate); EstimatedSizeKB=$Values.EstimatedSize; WindowsInstaller=$Values.WindowsInstaller; SystemComponent=$Values.SystemComponent; Source='UninstallRegistry'; InstallState='Registered; not executable presence verification' }
}
function Get-SoftwareComparisonKey {
    param([object]$Row)
    $parts = @('Name','Publisher','Scope','UserSid','RegistryView','Source') | ForEach-Object { ([string]$Row.$_).Trim().ToUpperInvariant() }
    return (ConvertTo-Json -InputObject @($parts) -Compress)
}
function Compare-SoftwareAudit {
    param([object[]]$Current,[object[]]$Baseline)
    $currentMap = @{}; $baselineMap = @{}; $keys = @{}
    foreach ($row in $Current) {
        $key = Get-SoftwareComparisonKey $row; $keys[$key]=$true
        if (-not $currentMap.ContainsKey($key)) { $currentMap[$key] = New-Object 'System.Collections.Generic.List[object]' }
        $currentMap[$key].Add($row)
    }
    foreach ($row in $Baseline) {
        $key = Get-SoftwareComparisonKey $row; $keys[$key]=$true
        if (-not $baselineMap.ContainsKey($key)) { $baselineMap[$key] = New-Object 'System.Collections.Generic.List[object]' }
        $baselineMap[$key].Add($row)
    }
    foreach ($key in @($keys.Keys | Sort-Object)) {
        $now = @(); $before = @()
        if ($currentMap.ContainsKey($key)) { $now = @($currentMap[$key].ToArray()) }
        if ($baselineMap.ContainsKey($key)) { $before = @($baselineMap[$key].ToArray()) }
        $example = if ($now.Count) { $now[0] } else { $before[0] }
        $currentVersions = @($now | ForEach-Object { ([string]$_.Version).Trim() } | Sort-Object -Unique)
        $baselineVersions = @($before | ForEach-Object { ([string]$_.Version).Trim() } | Sort-Object -Unique)
        $status = 'NoDifference'
        if (-not $before.Count) { $status = 'NotInBaseline' }
        elseif (-not $now.Count) { $status = 'MissingFromCurrentInventory' }
        elseif ((ConvertTo-Json -InputObject @($currentVersions) -Compress) -cne (ConvertTo-Json -InputObject @($baselineVersions) -Compress)) { $status = 'VersionDifference' }
        if ($status -ne 'NoDifference') {
            [pscustomobject]@{ Name=$example.Name; Publisher=$example.Publisher; Scope=$example.Scope; UserSid=$example.UserSid; RegistryView=$example.RegistryView; Source=$example.Source; Difference=$status; BaselineVersions=($baselineVersions -join '; '); CurrentVersions=($currentVersions -join '; '); Interpretation='Inventory comparison only. Missing records may reflect query scope or access; version differences are not security findings.' }
        }
    }
}
function Add-SoftwareStatus {
    param([string]$Query,[string]$Status,[int]$Count,[string]$Detail)
    $script:queryStatus.Add([pscustomobject]@{ Query=$Query; Status=$Status; Count=$Count; Detail=$Detail })
}
function Add-SoftwareError {
    param([string]$Query,[object]$ErrorRecord)
    $script:queryErrors.Add([pscustomobject]@{ Query=$Query; ErrorType=$ErrorRecord.Exception.GetType().FullName; HResult=$ErrorRecord.Exception.HResult; Detail='Query failed; raw error omitted to avoid exposing paths or package metadata outside the selected fields.' })
}
function Read-SoftwareUninstallKey {
    param([Microsoft.Win32.RegistryKey]$Base,[string]$Path,[string]$Scope,[string]$Sid,[string]$View)
    $query = '{0}/{1}/{2}' -f $Scope,$Sid,$View
    $rootKey = $null; $count = 0; $failed = 0
    try {
        $rootKey = $Base.OpenSubKey($Path,$false)
        if ($null -eq $rootKey) { Add-SoftwareStatus $query 'Success' 0 'Uninstall key does not exist in this loaded hive/view.'; return }
        foreach ($name in $rootKey.GetSubKeyNames()) {
            $entry = $null
            try {
                $entry = $rootKey.OpenSubKey($name,$false)
                if ($null -eq $entry) { throw 'Registry entry disappeared during collection.' }
                $values = @{}
                foreach ($field in @('DisplayName','DisplayVersion','Publisher','InstallDate','EstimatedSize','WindowsInstaller','SystemComponent')) { $values[$field]=$entry.GetValue($field,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
                $row = ConvertTo-SoftwareRegistryRow ([pscustomobject]$values) $Scope $Sid $View $name
                if ($row) { $script:rows.Add($row); $count++ }
            } catch { $failed++; Add-SoftwareError $query $_ }
            finally { if ($entry) { $entry.Dispose() } }
        }
        Add-SoftwareStatus $query $(if ($failed) { 'Partial' } else { 'Success' }) $count ('Named software entries read; failed entries: {0}.' -f $failed)
    } catch { Add-SoftwareError $query $_; Add-SoftwareStatus $query 'Unknown' $count 'Registry key could not be fully read.' }
    finally { if ($rootKey) { $rootKey.Dispose() } }
}
function Test-SoftwareAuditAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { return (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    finally { $identity.Dispose() }
}
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) { throw 'Run in 64-bit Windows PowerShell 5.1 or later on Windows.' }
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$baseline = @()
if ($PSBoundParameters.ContainsKey('BaselineCsv')) {
    $baseline = @(Import-Csv -LiteralPath $BaselineCsv -ErrorAction Stop)
    if (-not $baseline.Count) { throw 'BaselineCsv must contain at least one data row from software.csv.' }
    foreach ($required in @('Name','Version','Publisher','Scope','UserSid','RegistryView','Source')) { if ($required -notin $baseline[0].PSObject.Properties.Name) { throw ('BaselineCsv is missing required column {0}.' -f $required) } }
}
$runName = 'InstalledSoftwareAudit-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),([guid]::NewGuid().ToString('N').Substring(0,8))
$report = (New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -ErrorAction Stop).FullName
$queryStatus = New-Object 'System.Collections.Generic.List[object]'; $queryErrors = New-Object 'System.Collections.Generic.List[object]'; $rows = New-Object 'System.Collections.Generic.List[object]'
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
try { $currentSid = $currentIdentity.User.Value } finally { $currentIdentity.Dispose() }
$uninstallPath = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
$views = @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)
foreach ($view in $views) {
    foreach ($scope in @('Machine','CurrentUser')) {
        $base = $null
        try {
            $hive = if ($scope -eq 'Machine') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
            Read-SoftwareUninstallKey $base $uninstallPath $scope $(if ($scope -eq 'CurrentUser') { $currentSid } else { '' }) ([string]$view)
        } catch { Add-SoftwareError ($scope+'/'+$view) $_; Add-SoftwareStatus ($scope+'/'+$view) 'Unknown' 0 'Registry hive unavailable.' }
        finally { if ($base) { $base.Dispose() } }
    }
    if ($IncludeLoadedUserHives) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users,$view)
            $sids = @($base.GetSubKeyNames() | Where-Object { $_ -match '^S-1-5-\d+(?:-\d+)+$' -and $_ -ne $currentSid })
            Add-SoftwareStatus ('LoadedUserHiveEnumeration/'+$view) 'Success' $sids.Count 'Already-loaded user SIDs only; no hives loaded. Includes service-account SIDs if already loaded.'
            foreach ($sid in $sids) { Read-SoftwareUninstallKey $base ($sid+'\'+$uninstallPath) 'LoadedUser' $sid ([string]$view) }
        } catch { Add-SoftwareError ('LoadedUserHives/'+$view) $_; Add-SoftwareStatus ('LoadedUserHives/'+$view) 'Unknown' 0 'Loaded users could not be enumerated.' }
        finally { if ($base) { $base.Dispose() } }
    }
}
if ($IncludeAppx -or $AllUsersAppx) {
    $query = if ($AllUsersAppx) { 'AppxAllUsers' } else { 'AppxCurrentUser' }
    try {
        if (-not (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) { throw 'Get-AppxPackage is unavailable.' }
        if ($AllUsersAppx -and -not (Test-SoftwareAuditAdministrator)) { throw 'AllUsersAppx requires administrator permissions.' }
        $packages = if ($AllUsersAppx) { @(Get-AppxPackage -AllUsers -ErrorAction Stop) } else { @(Get-AppxPackage -ErrorAction Stop) }
        $count = 0
        foreach ($package in $packages) {
            $registrations = @([pscustomobject]@{ Sid=$currentSid; State='Installed for queried current user' })
            if ($AllUsersAppx) {
                $registrations = @($package.PackageUserInformation | ForEach-Object { [pscustomobject]@{ Sid=[string]$_.UserSecurityId; State=[string]$_.InstallState } })
                if (-not $registrations.Count) { $registrations=@([pscustomobject]@{ Sid='Unknown'; State='Unknown; package has no returned user registration' }) }
            }
            foreach ($registration in $registrations) {
                $rows.Add((New-SoftwareAuditRow @{ Name=[string]$package.Name; Version=[string]$package.Version; Publisher=[string]$package.Publisher; Scope='AppxUser'; UserSid=$registration.Sid; Source='Appx'; PackageArchitecture=[string]$package.Architecture; InstallState=$registration.State; RegistryKeyName=[string]$package.PackageFamilyName }))
                $count++
            }
        }
        Add-SoftwareStatus $query 'Success' $count 'Main and Framework package registrations from Get-AppxPackage defaults; provisioned packages and portable apps are outside scope.'
    } catch { Add-SoftwareError $query $_; Add-SoftwareStatus $query 'Unknown' 0 'AppX/MSIX inventory could not be collected for the requested scope.' }
}
$inventory = @($rows.ToArray() | Sort-Object Scope,UserSid,Name,RegistryView,Version)
if ($inventory.Count) { $inventory | Export-Csv -LiteralPath (Join-Path $report 'software.csv') -NoTypeInformation -Encoding UTF8 } else { '"Name","Version","Publisher","Scope","UserSid","RegistryView","RegistryKeyName","InstallDateRaw","InstallDateISO","EstimatedSizeKB","WindowsInstaller","SystemComponent","Source","PackageArchitecture","InstallState"' | Set-Content -LiteralPath (Join-Path $report 'software.csv') -Encoding UTF8; Add-SoftwareStatus 'Inventory coverage' 'Unknown' 0 'No registered software returned; this is not proof that no software is installed.' }
ConvertTo-Json -InputObject @($inventory) -Depth 6 | Set-Content -LiteralPath (Join-Path $report 'software.json') -Encoding UTF8
$differences = @()
if ($PSBoundParameters.ContainsKey('BaselineCsv')) {
    $differences = @(Compare-SoftwareAudit $inventory $baseline)
    if ($differences.Count) { $differences | Export-Csv -LiteralPath (Join-Path $report 'baseline-differences.csv') -NoTypeInformation -Encoding UTF8 } else { '"Name","Publisher","Scope","UserSid","RegistryView","Source","Difference","BaselineVersions","CurrentVersions","Interpretation"' | Set-Content -LiteralPath (Join-Path $report 'baseline-differences.csv') -Encoding UTF8 }
    ConvertTo-Json -InputObject @($differences) -Depth 5 | Set-Content -LiteralPath (Join-Path $report 'baseline-differences.json') -Encoding UTF8
}
$queryStatus.ToArray() | Export-Csv -LiteralPath (Join-Path $report 'query-status.csv') -NoTypeInformation -Encoding UTF8
ConvertTo-Json -InputObject @($queryStatus.ToArray()) -Depth 5 | Set-Content -LiteralPath (Join-Path $report 'query-status.json') -Encoding UTF8
if ($queryErrors.Count) { $queryErrors.ToArray() | Export-Csv -LiteralPath (Join-Path $report 'query-errors.csv') -NoTypeInformation -Encoding UTF8 } else { '"Query","ErrorType","HResult","Detail"' | Set-Content -LiteralPath (Join-Path $report 'query-errors.csv') -Encoding UTF8 }
$summary = [pscustomobject]@{ CollectedUtc=[datetime]::UtcNow.ToString('o'); ComputerName=$env:COMPUTERNAME; Status=$(if (@($queryStatus | Where-Object Status -ne 'Success').Count) { 'Partial' } else { 'Complete' }); SoftwareRecordCount=$inventory.Count; DifferenceCount=$differences.Count; QueryErrorCount=$queryErrors.Count; ReportDirectory=$report; Coverage='Both registry views of HKLM and current HKCU. Other loaded users and AppX are opt-in. Registry views are not proof of executable architecture. Unregistered/portable applications and unloaded profiles are not enumerated.' }
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $report 'summary.json') -Encoding UTF8
$summary
