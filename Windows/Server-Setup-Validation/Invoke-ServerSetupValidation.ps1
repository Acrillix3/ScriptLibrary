<#
What it does:
  Runs all five server setup validation suites with mocked Windows providers.

Available flags:
  -ScriptsDirectory: Setup script category; default the sibling Server-Setup folder.
  -OutputDirectory: Test logs and fixture reports; default Windows\Reports.

How it works:
  Runs each trusted test in a fresh native Windows PowerShell 5.1 process and records
  its exit code. Fails if any suite fails. No role, policy, client or restart is applied.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$ScriptsDirectory,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $ScriptsDirectory){$ScriptsDirectory=Join-Path $PSScriptRoot '..\Server-Setup'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$runDirectory=Join-Path $OutputDirectory ('ssv-'+(Get-Date -Format yyyyMMdd-HHmmss)+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $runDirectory -Force
$engine=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
if([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess){$engine=Join-Path $env:WINDIR 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'}
if(-not (Test-Path -LiteralPath $engine -PathType Leaf)){throw 'Native Windows PowerShell 5.1 is required for these server-role validation suites.'}
$suites=@(
    @{File='Test-ServerSetupPackage.ps1';Parameter='ScriptsDirectory'},
    @{File='Test-IdentityServerSetup.ps1';Parameter='SourceDirectory'},
    @{File='Test-StorageAndPrintSetup.ps1';Parameter='ScriptsDirectory'},
    @{File='Test-ApplicationRoleSetup.ps1';Parameter='LibraryPath'},
    @{File='Test-BaseAndKeyRoleSetup.ps1';Parameter='ScriptsDirectory'}
)
$rows=New-Object 'System.Collections.Generic.List[object]'
foreach($suite in $suites){
    $path=Join-Path $PSScriptRoot $suite.File
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw ('Missing validation file: '+$suite.File)}
    $log=Join-Path $runDirectory ([IO.Path]::GetFileNameWithoutExtension($suite.File)+'.txt')
    $arguments=@('-NoProfile','-NonInteractive','-File',$path,('-'+$suite.Parameter),$ScriptsDirectory,'-OutputDirectory',$runDirectory)
    $previous=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';& $engine @arguments *> $log;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$previous}
    $rows.Add([pscustomobject]@{Suite=$suite.File;State=$(if($code -eq 0){'Passed'}else{'Failed'});ExitCode=$code;Log=$log})
}
$rows.ToArray() | Export-Csv -LiteralPath (Join-Path $runDirectory 'validation-summary.csv') -NoTypeInformation -Encoding UTF8
$rows.ToArray() | Format-Table Suite,State,ExitCode -AutoSize | Out-String | Write-Output
Write-Output ('Validation reports: '+[IO.Path]::GetFullPath($runDirectory))
if(@($rows | Where-Object ExitCode -ne 0).Count){throw 'One or more setup code-validation suites failed. Review validation-summary.csv and the corresponding logs.'}
