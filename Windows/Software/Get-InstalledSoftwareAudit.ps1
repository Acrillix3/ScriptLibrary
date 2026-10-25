<#
What it does:
  Audits registered desktop software and optional AppX/MSIX packages, with optional baseline comparison.
Available flags:
  -IncludeLoadedUserHives: Read other already-loaded user hives. -IncludeAppx: Add current-user AppX/MSIX.
  -AllUsersAppx: Add AppX/MSIX user registrations; requires administrator. -BaselineCsv <path>: Compare a prior software.csv.
  -OutputDirectory <path>: Report destination; default Windows\Reports.
How it works:
  Uses Windows/lib to read registry views without hive loading or installer repair. Exports CSV, JSON, query status,
  errors, and optional inventory differences. Portable apps may be absent; differences are not vulnerability findings.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$IncludeLoadedUserHives,[switch]$IncludeAppx,[switch]$AllUsersAppx,[ValidateNotNullOrEmpty()][string]$BaselineCsv,[ValidateNotNullOrEmpty()][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$core=Join-Path $PSScriptRoot '..\lib\Invoke-SoftwareInventoryCore.ps1'
if(-not (Test-Path -LiteralPath $core -PathType Leaf)){throw 'Missing Windows/lib/Invoke-SoftwareInventoryCore.ps1; copy the complete Windows library.'}
& $core -Compatibility Audit @PSBoundParameters
