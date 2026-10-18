<#
What it does:
  Checks the server setup package's syntax, documented flags, plan defaults and restart gates.

Available flags:
  -ScriptsDirectory: Setup script category; default the sibling Server-Setup folder.
  -OutputDirectory: Validation report destination; default Windows\Reports.

How it works:
  Parses all delivered setup and test scripts without loading Windows server roles.
  Verifies shared confirmation gates, suppressed native reboots, and valid JSON examples.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$ScriptsDirectory,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $ScriptsDirectory){$ScriptsDirectory=Join-Path $PSScriptRoot '..\Server-Setup'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$directory=Join-Path $OutputDirectory ('pkg-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $directory -Force
$checks=New-Object 'System.Collections.Generic.List[object]'
function Assert-ServerPackage {param([bool]$Condition,[string]$Name) if(-not $Condition){throw ('FAIL: '+$Name)};$checks.Add([pscustomobject]@{Check=$Name;Passed=$true})}
$setupFiles=@(Get-ChildItem -LiteralPath $ScriptsDirectory -Filter *.ps1 -File)
$testFiles=@(Get-ChildItem -LiteralPath $PSScriptRoot -Filter *.ps1 -File)
Assert-ServerPackage ($setupFiles.Count -eq 15) 'Fifteen standalone setup tools'
Assert-ServerPackage ($testFiles.Count -eq 6) 'Five validation suites and one runner'
foreach($file in @($setupFiles)+@($testFiles)){
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
    Assert-ServerPackage ($errors.Count -eq 0) ('Syntax: '+$file.Name)
    $text=Get-Content -LiteralPath $file.FullName -Raw
    Assert-ServerPackage ($text -match '^(?:\uFEFF)?<#\r?\nWhat it does:') ('Short header starts file: '+$file.Name)
    $header=$text.Substring(0,$text.IndexOf('#>')+2)
    Assert-ServerPackage ($header -match '(?m)^Available flags:' -and $header -match '(?m)^How it works:') ('Three header sections: '+$file.Name)
    foreach($parameter in $ast.ParamBlock.Parameters){
        $name=$parameter.Name.VariablePath.UserPath
        Assert-ServerPackage ($header -match ('(?i)(?<!\w)-'+[regex]::Escape($name)+'(?=\s|:|,|$)')) ('Flag documented: '+$file.Name+' '+$name)
    }
    Assert-ServerPackage ($file.Name -notmatch '^\d') ('No leading number: '+$file.Name)
    if($file.DirectoryName -ieq [IO.Path]::GetFullPath($ScriptsDirectory)){
        $apply=@($ast.ParamBlock.Parameters | Where-Object {$_.Name.VariablePath.UserPath -eq 'Apply'})
        Assert-ServerPackage ($apply.Count -eq 1 -and $null -eq $apply[0].DefaultValue) ('Apply defaults off: '+$file.Name)
        Assert-ServerPackage ($text -match '\$setupCmdlet\.ShouldProcess\(\$Target,\$Name\)') ('Setup actions use ShouldProcess: '+$file.Name)
        Assert-ServerPackage ($text -match '\$setupCmdlet\.ShouldContinue\(') ('Restart uses separate ShouldContinue: '+$file.Name)
        Assert-ServerPackage ($text -match 'elseif\(\$SkipRestartPrompt\)') ('Restart skip option defers: '+$file.Name)
        $commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))
        Assert-ServerPackage (@($commands | Where-Object {$_.GetCommandName() -eq 'Invoke-SetupAction'}).Count -ge 1) ('Gated setup dispatcher used: '+$file.Name)
        foreach($command in $commands | Where-Object {$_.GetCommandName() -in @('Restart-Computer','Restart-Service')}){
            $parent=$command.Parent
            while($parent -and $parent -isnot [Management.Automation.Language.FunctionDefinitionAst]){$parent=$parent.Parent}
            Assert-ServerPackage ($parent -and $parent.Name -eq 'Complete-SetupReport') ('Restarts centralized after report/consent: '+$file.Name)
        }
        Assert-ServerPackage ($text -notmatch '(?i)Restart-Computer\s+-Force') ('No forced computer restart: '+$file.Name)
    }
}
foreach($file in Get-ChildItem -LiteralPath (Join-Path $ScriptsDirectory 'config') -Filter *.example.json){
    $parsed=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
    Assert-ServerPackage ($null -ne $parsed) ('Valid JSON: '+$file.Name)
}
$checks.ToArray() | Export-Csv -LiteralPath (Join-Path $directory 'package-checks.csv') -NoTypeInformation -Encoding UTF8
[pscustomobject]@{Suite='Server setup package';Passed=$checks.Count;Failed=0;OutputDirectory=[IO.Path]::GetFullPath($directory);LiveSystemsTested=$false}
