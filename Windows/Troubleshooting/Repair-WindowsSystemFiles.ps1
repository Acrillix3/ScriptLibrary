<#
What it does:
  Plans or runs DISM image repair followed by SFC, preserving native results and logs.

Available flags:
  -Apply: Repair with DISM RestoreHealth and SFC scannow. Default is a plan.
  -Mode Check|Scan|Verify|Repair: Explicit mode; read-only modes run immediately, Repair needs Apply.
  -Diagnose: Run CheckHealth and SFC verifyonly instead of repairs; cannot combine with Apply.
  -Source, -SourceIndex: Optional repair folder or WIM/ESD file and positive image index.
  -LimitAccess: Do not contact Windows Update for repair content.
  -SkipRestartPrompt: Defer any required restart without prompting.
  -LogTailLines: Existing CBS log lines to copy; default 200. -OutputDirectory: Report location.
  -WhatIf, -Confirm: Standard PowerShell change controls.

How it works:
  Uses the shared Windows/lib integrity engine in native elevated Windows PowerShell. DISM uses NoRestart;
  failed DISM or a required restart prevents SFC. Saves results before a separate restart
  confirmation. Exit zero alone does not establish health; review localized native output.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param(
    [switch]$Apply,[switch]$Diagnose,
    [string]$Source,[ValidateRange(1,65535)][int]$SourceIndex,
    [switch]$LimitAccess,[switch]$SkipRestartPrompt,
    [ValidateRange(0,5000)][int]$LogTailLines=200,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory,
    [ValidateSet('Check','Scan','Verify','Repair')][string]$Mode
)
$ErrorActionPreference='Stop'
$core=Join-Path $PSScriptRoot '..\lib\Invoke-WindowsIntegrityCore.ps1'
if(-not (Test-Path -LiteralPath $core -PathType Leaf)){throw 'Missing Windows/lib/Invoke-WindowsIntegrityCore.ps1; copy the complete Windows library.'}
& $core -Compatibility Repair @PSBoundParameters
