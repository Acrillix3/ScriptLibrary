<#
What it does:
  Runs every included Veeam code-validation suite with mocked providers.

Available flags:
  -WindowsRoot: Windows category root to validate; default parent of this folder.
  -OutputDirectory: Mock reports and test logs; default Windows\Reports.

How it works:
  Starts each trusted sibling test in a fresh instance of the current PowerShell runtime.
  Captures results and throws if a suite fails. No live Veeam audit, network probe or scan runs.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$WindowsRoot,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $WindowsRoot){$WindowsRoot=Split-Path $PSScriptRoot -Parent}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $WindowsRoot 'Reports'}
$reportDirectory=Join-Path $OutputDirectory ('VeeamValidation-'+(Get-Date -Format yyyyMMdd-HHmmss)+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $reportDirectory -Force
$engine=if($PSVersionTable.PSEdition -eq 'Core'){Join-Path $PSHOME 'pwsh.exe'}else{Join-Path $PSHOME 'powershell.exe'}
$names=@('Test-VeeamPackage.ps1','Test-VBRJobAudits.ps1','Test-VBRInfrastructureAudits.ps1','Test-VBOAudits.ps1','Test-VeeamDatabaseAudits.ps1','Test-VeeamDiagnostics.ps1','Test-MergedVeeamTools.ps1')
$rows=New-Object 'System.Collections.Generic.List[object]'
foreach($name in $names){
    $path=Join-Path $PSScriptRoot $name
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw ('Missing validation script: '+$name)}
    $log=Join-Path $reportDirectory ([IO.Path]::GetFileNameWithoutExtension($name)+'.txt')
    $previousPreference=$ErrorActionPreference
    try{
        $ErrorActionPreference='Continue'
        & $engine -NoProfile -NonInteractive -File $path -WindowsRoot $WindowsRoot -OutputDirectory $reportDirectory *> $log
        $code=$LASTEXITCODE
    }finally{$ErrorActionPreference=$previousPreference}
    $rows.Add([pscustomobject]@{Suite=$name;ExitCode=$code;State=$(if($code -eq 0){'Passed'}else{'Failed'});Log=$log})
}
$rows.ToArray() | Export-Csv -LiteralPath (Join-Path $reportDirectory 'validation-summary.csv') -NoTypeInformation -Encoding UTF8
$rows.ToArray() | Format-Table Suite,State,ExitCode -AutoSize | Out-String | Write-Output
Write-Output ('Validation reports: '+[IO.Path]::GetFullPath($reportDirectory))
if(@($rows | Where-Object ExitCode -ne 0).Count){throw 'One or more code-validation suites failed. Review validation-summary.csv and the corresponding logs.'}
