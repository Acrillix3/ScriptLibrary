<#
What it does:
  Checks Veeam script syntax, short headers, category placement, and passive suite behavior.

Available flags:
  -WindowsRoot: Windows category root to validate; default parent of this folder.
  -OutputDirectory: Fixture/report destination; default Windows\Reports.

How it works:
  Parses source without importing vendor modules. Runs suite copies against fake local
  sibling scripts to verify continued reporting and exclusion of intensive checks.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$WindowsRoot,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $WindowsRoot){$WindowsRoot=Split-Path $PSScriptRoot -Parent}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $WindowsRoot 'Reports'}
$testDirectory=Join-Path $OutputDirectory ('pkg-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $testDirectory -Force
$checks=0
function Assert-Package {param([bool]$Condition,[string]$Description) if(-not $Condition){throw ('FAIL: '+$Description)};$script:checks++}
$categories=@('Veeam-Backup-and-Replication-v12','Veeam-Microsoft-365','Veeam-Validation')
$files=@(foreach($category in $categories){Get-ChildItem -LiteralPath (Join-Path $WindowsRoot $category) -Filter *.ps1 -File})
Assert-Package ($files.Count -ge 37) 'Thirty operational tools and seven validation scripts exist'
foreach($file in $files){
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
    Assert-Package ($errors.Count -eq 0) ('Syntax: '+$file.Name)
    $text=Get-Content -LiteralPath $file.FullName -Raw
    Assert-Package ($text -match '^(?:\uFEFF)?<#\r?\nWhat it does:') ('Short header begins file: '+$file.Name)
    $header=$text.Substring(0,$text.IndexOf('#>')+2)
    Assert-Package ($header -match '(?m)^Available flags:' -and $header -match '(?m)^How it works:') ('Three header sections: '+$file.Name)
    foreach($parameter in $ast.ParamBlock.Parameters){
        $name=$parameter.Name.VariablePath.UserPath
        Assert-Package ($header -match ('(?im)^\s*-'+[regex]::Escape($name)+'(?:\s|:)')) ('Flag documented: '+$file.Name+' '+$name)
    }
    Assert-Package ($file.Name -notmatch '^\d') ('No numbered filename: '+$file.Name)
}
foreach($product in @('VBR','VBO')){
    $category=if($product -eq 'VBR'){$categories[0]}else{$categories[1]}
    $source=Join-Path (Join-Path $WindowsRoot $category) ('Invoke-'+$product+'ReadOnlyAuditSuite.ps1')
    $fixture=Join-Path $testDirectory $category
    $null=New-Item -ItemType Directory -Path $fixture -Force
    Copy-Item -LiteralPath $source -Destination (Join-Path $fixture ([IO.Path]::GetFileName($source)))
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
    $names=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value -like '*.ps1' -and $node.Value -notmatch '[*?]'},$true) | ForEach-Object Value | Select-Object -Unique)
    $expected=if($product -eq 'VBR'){15}else{11}
    Assert-Package ($names.Count -eq $expected) ($product+' passive tool count')
    Assert-Package (@($names | Where-Object {$_ -in @('Test-VBRBackupValidation.ps1','Test-VBORepositoryIntegrity.ps1')}).Count -eq 0) ($product+' excludes intensive checks')
    foreach($name in $names){
        $body=if($name -like '*HostDiagnostics*'){'throw ''fixture secret must not be exported'''}else{'param($Server,$Port,$OutputDirectory,$Credential,$HostCredential,$QueryDatabase,$DatabaseCredential,$PsqlPath,$PostgresUser,$PostgresPassFile,$ProxyComputerName); [pscustomobject]@{State=''Review'';ReportDirectory=$OutputDirectory}'}
        [IO.File]::WriteAllText((Join-Path $fixture $name),$body)
    }
    $suiteResult=& (Join-Path $fixture ([IO.Path]::GetFileName($source))) -Server 'fixture.invalid' -OutputDirectory $testDirectory
    $rows=@(Import-Csv -LiteralPath (Join-Path $suiteResult.ReportDirectory 'suite-summary.csv'))
    Assert-Package ($rows.Count -eq $expected) ($product+' continues after child failure')
    Assert-Package (@($rows | Where-Object State -eq Incomplete).Count -eq 1) ($product+' records failed child as incomplete')
    Assert-Package (@($rows | Where-Object State -eq Review).Count -eq ($expected-1)) ($product+' preserves successful child state')
    Assert-Package ((Get-Content -LiteralPath (Join-Path $suiteResult.ReportDirectory 'suite-summary.csv') -Raw) -notmatch 'fixture secret') ($product+' redacts errors')
}
Write-Output ('PASS: '+$checks+' package and suite checks.')
