<#
What it does:
  Tests PHP2Shell version rules and isolated XML/path handling without querying installed PHP.

Available flags:
  -ScriptRoot: Windows folder under test. Defaults to the validation folder's parent.

How it works:
  Loads selected functions from the script's syntax tree and uses private fixture files. Does not
  execute the operational audit, PHP, web requests, repairs, cleanup, or power changes.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$ScriptRoot)
$ErrorActionPreference='Stop'
if(-not $ScriptRoot){$ScriptRoot=Split-Path $PSScriptRoot -Parent}
$path=Join-Path $ScriptRoot 'Security\Test-Php2ShellExposure.ps1'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ($parseErrors.Message -join '; ')}
$checks=0
function Assert-PhpTest {param([bool]$Condition,[string]$Message);$script:checks++;if(-not $Condition){throw $Message}}
foreach($name in @('Get-PhpVersionAssessment','Read-SafeXmlDocument','Test-NoReparseAncestry')){
    $node=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -eq $name | Select-Object -First 1
    . ([scriptblock]::Create($node.Extent.Text))
}
$fixedVersions=@{'8.2'=[version]'8.2.35';'8.3'=[version]'8.3.36';'8.4'=[version]'8.4.27';'8.5'=[version]'8.5.12'}
foreach($branch in $fixedVersions.Keys){
    $fix=$fixedVersions[$branch]
    $below='{0}.{1}.{2}' -f $fix.Major,$fix.Minor,($fix.Build-1)
    $after='{0}.{1}.{2}' -f $fix.Major,$fix.Minor,($fix.Build+1)
    foreach($case in @(
        @{Value=$below;Expected='PotentiallyAffected'},
        @{Value=$fix.ToString();Expected='MeetsPublishedFixedVersion'},
        @{Value=($fix.ToString()+'.0');Expected='MeetsPublishedFixedVersion'},
        @{Value=$after;Expected='MeetsPublishedFixedVersion'},
        @{Value=($fix.ToString()+'RC1');Expected='UnknownPrerelease'},
        @{Value=($fix.ToString()+'-dev');Expected='UnknownPrerelease'},
        @{Value=($below+'-vendor-fix');Expected='PotentiallyAffected'}
    )){
        $actual=Get-PhpVersionAssessment $case.Value
        Assert-PhpTest ($actual.Assessment -eq $case.Expected) ('Incorrect assessment for '+$case.Value+': '+$actual.Assessment)
        Assert-PhpTest ($actual.FixedVersion -eq $fix.ToString()) ('Incorrect fixed version for '+$case.Value)
    }
}
foreach($legacy in @('5.4.0','5.6.40','7.4.33','8.0.30','8.1.34')){Assert-PhpTest ((Get-PhpVersionAssessment $legacy).Assessment -eq 'PotentiallyAffectedLegacy') ('Legacy build must require evidence: '+$legacy)}
foreach($unknown in @('','not a version','8.4','8.6.0','9.0.0','4.4.9','8.4.27foo','8.4.27 bundled 8.2.34')){Assert-PhpTest ((Get-PhpVersionAssessment $unknown).Assessment -eq 'Unknown') ('Unknown version must not be declared fixed: '+$unknown)}
$commands=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
Assert-PhpTest (@($commands | Where-Object {$_ -in @('Invoke-WebRequest','Invoke-RestMethod','Invoke-Expression','Start-Process','Restart-Service','Restart-Computer')}).Count -eq 0) 'Passive audit must not request exploit/web/execution/restart actions.'
Assert-PhpTest (@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq [Management.Automation.Language.TokenKind]::Ampersand},$true)).Count -eq 0) 'No discovered binary execution.'
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('phpaudit-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $fixture
try{
    $normal=Join-Path $fixture 'safe.xml'
    '<configuration><system.webServer><fastCgi><application fullPath="C:\PHP\php-cgi.exe" /></fastCgi></system.webServer></configuration>' | Set-Content -LiteralPath $normal -Encoding UTF8
    $document=Read-SafeXmlDocument $normal
    Assert-PhpTest ($document.SelectNodes('//fastCgi/application').Count -eq 1) 'Safe IIS mapping XML must parse.'
    $external=Join-Path $fixture 'dtd.xml'
    '<!DOCTYPE configuration [<!ENTITY leak SYSTEM "file:///never-read-this">]><configuration>&leak;</configuration>' | Set-Content -LiteralPath $external -Encoding UTF8
    $rejected=$false
    try{$null=Read-SafeXmlDocument $external}catch{$rejected=$true}
    Assert-PhpTest $rejected 'DTD/entity input must be rejected.'
    Assert-PhpTest (Test-NoReparseAncestry $normal) 'Ordinary private fixture must be readable.'
    Assert-PhpTest (-not (Test-NoReparseAncestry (Join-Path $fixture 'missing'))) 'Unreadable path must fail closed.'
}finally{
    $resolved=[IO.Path]::GetFullPath($fixture)
    $tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(-not $resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup target.'}
    # Known fixture files only; never recursively delete a computed directory.
    foreach($name in @('safe.xml','dtd.xml')){Remove-Item -LiteralPath (Join-Path $fixture $name) -Force -ErrorAction SilentlyContinue}
    Remove-Item -LiteralPath $fixture -ErrorAction SilentlyContinue
}
[pscustomobject]@{Suite='PHP2Shell';Assertions=$checks;Result='Passed';Scope='Pure version rules and private XML/path fixtures; no live PHP or exploit test.'}
