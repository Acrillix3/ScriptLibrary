<#
What it does:
  Exports installed desktop application names and versions.

Available flags:
  -IncludeAppx: Also list the executing user's AppX/MSIX packages.
  -OutputDirectory <path>: Report destination; default Windows\Reports.

How it works:
  Uses the shared Windows/lib collector for machine/current-user uninstall registrations. Saves CSV/JSON
  reports without invoking installer repair checks; portable apps and other users' registrations may
  be absent.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$IncludeAppx,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
$core=Join-Path $PSScriptRoot '..\lib\Invoke-SoftwareInventoryCore.ps1'
if(-not (Test-Path -LiteralPath $core -PathType Leaf)){throw 'Missing Windows/lib/Invoke-SoftwareInventoryCore.ps1; copy the complete Windows library.'}
& $core -Compatibility Legacy @PSBoundParameters
