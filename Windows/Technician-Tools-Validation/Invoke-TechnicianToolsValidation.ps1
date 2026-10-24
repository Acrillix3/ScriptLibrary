<#
What it does:
  Validates the nine technician scripts and runs their isolated mock/fixture tests.
Available flags:
  -WindowsRoot: Windows folder under test. -OutputDirectory: Test reports, default Windows\Reports.
How it works:
  Checks source contracts in Windows PowerShell 5.1, then runs hardware/software, PHP, power,
  repair, cleanup and AMD GPU fixtures. No live repair, deletion, printer, PHP or power action is requested.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$WindowsRoot,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'Run validation in native Windows PowerShell 5.1.'}
if(-not $WindowsRoot){$WindowsRoot=Split-Path $PSScriptRoot -Parent}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $WindowsRoot ('Reports\TechnicianToolsValidation-'+[guid]::NewGuid().ToString('N').Substring(0,8))}
$OutputDirectory=(New-Item -ItemType Directory -Path $OutputDirectory -Force).FullName
$checks=0
function Assert-Package {param([bool]$Condition,[string]$Message);$script:checks++;if(-not $Condition){throw $Message}}
$definitions=@(
    @{Path='Troubleshooting\Repair-WindowsSystemFiles.ps1';Change=$true},
    @{Path='Security\Test-Php2ShellExposure.ps1';Change=$false},
    @{Path='Device-Information\Get-ConnectedPeripheralAudit.ps1';Change=$false},
    @{Path='Device-Information\Get-ConnectedMonitorDetails.ps1';Change=$false},
    @{Path='Printing\Clear-PrinterQueueAndCache.ps1';Change=$true},
    @{Path='Storage-and-Permissions\Clear-TemporaryFiles.ps1';Change=$true},
    @{Path='Software\Get-InstalledSoftwareAudit.ps1';Change=$false},
    @{Path='Workstation-Setup\Set-TechnicianPowerSettings.ps1';Change=$true},
    @{Path='Troubleshooting\Reset-AmdGpuCache.ps1';Change=$true}
)
foreach($definition in $definitions){
    $file=Join-Path $WindowsRoot $definition.Path
    Assert-Package (Test-Path -LiteralPath $file -PathType Leaf) ('Missing script: '+$definition.Path)
    $text=Get-Content -LiteralPath $file -Raw
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
    Assert-Package ($errors.Count -eq 0) ('Parse error: '+$definition.Path)
    foreach($heading in @('What it does','Available flags','How it works')){Assert-Package ($text -match [regex]::Escape($heading)) ('Missing '+$heading+': '+$definition.Path)}
    Assert-Package ($text -match '(?im)^#Requires\s+-Version\s+5\.1') ('Missing PowerShell requirement: '+$definition.Path)
    $params=@($ast.ParamBlock.Parameters | ForEach-Object {$_.Name.VariablePath.UserPath})
    Assert-Package ($params -contains 'OutputDirectory') ('Missing report parameter: '+$definition.Path)
    if($definition.Change){
        Assert-Package ($params -contains 'Apply') ('Missing apply gate: '+$definition.Path)
        Assert-Package ($text -match 'SupportsShouldProcess\s*=\s*\$true') ('Missing WhatIf support: '+$definition.Path)
    }
    Assert-Package ($text -notmatch '(?i)Win32_Product') ('Installer consistency query not permitted: '+$definition.Path)
}
$results=New-Object 'System.Collections.Generic.List[object]'
$results.Add([pscustomobject]@{Suite='Package contracts';Assertions=$checks;Result='Passed'})
$php=@(& (Join-Path $PSScriptRoot 'Test-Php2ShellAudit.ps1') -ScriptRoot $WindowsRoot | Where-Object {$_.PSObject.Properties['Assertions']})[-1]
if(-not $php -or $php.Result -ne 'Passed'){throw 'PHP suite did not complete.'}
$results.Add([pscustomobject]@{Suite='PHP2Shell';Assertions=[int]$php.Assertions;Result='Passed'})
$hardware=@(& (Join-Path $PSScriptRoot 'Test-HardwareSoftwareAudits.ps1') -StagedWindows $WindowsRoot -OutputDirectory (Join-Path $OutputDirectory 'hardware-software') | Where-Object {$_.PSObject.Properties['Assertions']})[-1]
if(-not $hardware -or $hardware.Status -ne 'Passed'){throw 'Hardware/software suite did not complete.'}
$results.Add([pscustomobject]@{Suite='Hardware and software';Assertions=[int]$hardware.Assertions;Result='Passed'})
$repair=@(& (Join-Path $PSScriptRoot 'Test-RepairCleanupSafety.ps1') -ScriptRoot $WindowsRoot -OutputDirectory (Join-Path $OutputDirectory 'repair-cleanup') | Where-Object {$_.PSObject.Properties['Checks']})[-1]
if(-not $repair -or $repair.Status -ne 'Passed'){throw 'Repair/cleanup suite did not complete.'}
$results.Add([pscustomobject]@{Suite='Repair and cleanup';Assertions=[int]$repair.Checks;Result='Passed'})
$power=@(& (Join-Path $PSScriptRoot 'Test-PowerSettingsMock.ps1') -ScriptPath (Join-Path $WindowsRoot 'Workstation-Setup\Set-TechnicianPowerSettings.ps1'))
$powerLine=@($power | Where-Object {[string]$_ -match '^Passed \d+ power settings mock assertions\.'})[-1]
if(-not $powerLine){throw 'Power suite did not complete.'}
$powerCount=[int]([regex]::Match([string]$powerLine,'^Passed (\d+)').Groups[1].Value)
$results.Add([pscustomobject]@{Suite='Power settings';Assertions=$powerCount;Result='Passed'})
$amd=@(& (Join-Path $PSScriptRoot 'Test-AmdGpuCacheSafety.ps1') -WindowsRoot $WindowsRoot -OutputDirectory (Join-Path $OutputDirectory 'amd-gpu') | Where-Object {$_.PSObject.Properties['Assertions']})[-1]
if(-not $amd -or $amd.Result -ne 'Passed'){throw 'AMD GPU suite did not complete.'}
$results.Add([pscustomobject]@{Suite='AMD GPU cache and restart';Assertions=[int]$amd.Assertions;Result='Passed'})
$summary=[pscustomobject]@{Status='Passed';Assertions=[int](($results | Measure-Object Assertions -Sum).Sum);PowerShellVersion=$PSVersionTable.PSVersion.ToString();Suites=$results.ToArray();OutputDirectory=$OutputDirectory;Scope='Source contracts, mocked providers, and private file fixtures only; no live configuration/remediation.'}
$summary | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'validation-summary.json') -Encoding UTF8
$summary
