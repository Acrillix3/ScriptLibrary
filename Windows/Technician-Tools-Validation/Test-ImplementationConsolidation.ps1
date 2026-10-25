<#
What it does:
  Checks merged entrypoints, implementation dependencies and preserved public parameters.
Available flags:
  -LibraryRoot: ScriptLibrary root; default two folders above this validation category.
How it works:
  Parses source and compares the saved pre-merge parameter contract. Checks shared-core wiring
  without invoking software, servicing, Veeam, printer or SSH providers.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$LibraryRoot)
$ErrorActionPreference='Stop'
if(-not $LibraryRoot){$LibraryRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent}
$config=Join-Path $PSScriptRoot 'config'
$contracts=Get-Content -LiteralPath (Join-Path $config 'merge-parameter-contracts.json') -Raw | ConvertFrom-Json
$mapping=Get-Content -LiteralPath (Join-Path $config 'merged-entrypoints.json') -Raw | ConvertFrom-Json
$checks=0
function Assert-Consolidated {param([bool]$Condition,[string]$Message);$script:checks++;if(-not $Condition){throw $Message}}
function Normalize-ContractText {
 param([string]$Text)
 if([string]::IsNullOrEmpty($Text)){return ''}
 $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
 (@($tokens | Where-Object {$_.Kind -notin @('Comment','NewLine','LineContinuation','EndOfInput')} | ForEach-Object {$_.Text}) -join '|').ToLowerInvariant()
}
foreach($contract in $contracts){
 $path=Join-Path $LibraryRoot $contract.Path
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
 Assert-Consolidated ($errors.Count -eq 0) ('Entrypoint parses: '+$contract.Path)
 $parameters=@{}
 foreach($parameter in $ast.ParamBlock.Parameters){$parameters[$parameter.Name.VariablePath.UserPath]=$parameter}
 $priorOrder=@($contract.Parameters | ForEach-Object {$_.Name.ToLowerInvariant()})
 $currentPriorOrder=@($ast.ParamBlock.Parameters | ForEach-Object {$_.Name.VariablePath.UserPath.ToLowerInvariant()} | Where-Object {$priorOrder -contains $_})
 Assert-Consolidated (($priorOrder -join '|') -eq ($currentPriorOrder -join '|')) ('Preserved positional parameter order: '+$contract.Path)
 foreach($prior in $contract.Parameters){
  Assert-Consolidated ($parameters.ContainsKey($prior.Name)) ('Preserved parameter '+$contract.Path+' -'+$prior.Name)
  $current=$parameters[$prior.Name]
  Assert-Consolidated ($current.StaticType.FullName -eq $prior.StaticType) ('Preserved type '+$contract.Path+' -'+$prior.Name)
  $currentAttributes=@($current.Attributes | ForEach-Object {Normalize-ContractText $_.Extent.Text}) -join ';'
  $priorAttributes=@($prior.Attributes | ForEach-Object {Normalize-ContractText $_}) -join ';'
  Assert-Consolidated ($currentAttributes -eq $priorAttributes) ('Preserved validation '+$contract.Path+' -'+$prior.Name)
  $currentDefault=if($current.DefaultValue){$current.DefaultValue.Extent.Text}else{''}
  Assert-Consolidated ((Normalize-ContractText $currentDefault) -eq (Normalize-ContractText $prior.Default)) ('Preserved default '+$contract.Path+' -'+$prior.Name)
 }
 Assert-Consolidated (@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)).Count -eq 0) ('Public entrypoint delegates instead of embedding an engine: '+$contract.Path)
}
Assert-Consolidated ($mapping.Count -eq 16) 'Sixteen existing entrypoints retained across eight merge groups.'
foreach($item in $mapping){
 $public=Join-Path $LibraryRoot $item.Public
 $core=Join-Path $LibraryRoot $item.Core
 Assert-Consolidated (Test-Path -LiteralPath $public -PathType Leaf) ('Public entrypoint exists: '+$item.Public)
 Assert-Consolidated (Test-Path -LiteralPath $core -PathType Leaf) ('Shared implementation exists: '+$item.Core)
 $text=[IO.File]::ReadAllText($public)
 Assert-Consolidated ($text.Contains([IO.Path]::GetFileName($core))) ('Wrapper names its shared implementation: '+$item.Public)
 Assert-Consolidated ($text.Contains('What it does') -and $text.Contains('Available flags') -and $text.Contains('How it works')) ('Short wrapper sections: '+$item.Public)
 if($item.Public.EndsWith('.sh')){
  Assert-Consolidated ($text -notmatch '(?m)^\s*(?:capture\s+\S+\s+)?(?:lpstat|lpinfo|sshd|ssh-keygen)\s') ('Linux wrapper delegates provider collection: '+$item.Public)
 }
}
$cores=@($mapping.Core | Sort-Object -Unique)
Assert-Consolidated ($cores.Count -eq 8) 'One substantive engine for each merge group.'
foreach($relative in $cores+@('Windows\lib\Veeam-AuditCommon.ps1')){
 $path=Join-Path $LibraryRoot $relative
 $text=[IO.File]::ReadAllText($path)
 Assert-Consolidated ($text.Contains('What it does') -and $text.Contains('Available flags') -and $text.Contains('How it works')) ('Shared implementation sections: '+$relative)
 if($relative.EndsWith('.ps1')){
  $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
  Assert-Consolidated ($errors.Count -eq 0) ('Private implementation parses: '+$relative)
 }
}
[pscustomobject]@{Suite='Implementation consolidation';Status='Passed';Assertions=$checks;PublicEntrypoints=$mapping.Count;SharedEngines=$cores.Count;Scope='Static source/dependency and pre-merge parameter contracts; no operational execution.'}
