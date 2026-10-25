<#
What it does:
  Runs Windows component-store diagnostics and optionally verifies protected system files.

Available flags:
  -ScanComponentStore: Use DISM ScanHealth instead of the faster default CheckHealth.
  -VerifySystemFiles: Also run SFC verifyonly; can take several minutes.
  -LogTailLines: Maximum lines copied from each existing diagnostic log; default 200.
  -OutputDirectory: Report destination; default Windows\Reports.

How it works:
  Uses the shared Windows/lib integrity engine in diagnostic-only mode, preserving output and exit codes plus log
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

$ErrorActionPreference='Stop'
$core=Join-Path $PSScriptRoot '..\lib\Invoke-WindowsIntegrityCore.ps1'
if(-not (Test-Path -LiteralPath $core -PathType Leaf)){throw 'Missing Windows/lib/Invoke-WindowsIntegrityCore.ps1; copy the complete Windows library.'}
& $core -Compatibility Diagnostic @PSBoundParameters
