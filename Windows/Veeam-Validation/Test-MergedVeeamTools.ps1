<#
What it does:
  Tests merged Veeam wrapper contracts, private-core selection and per-run state isolation.
Available flags:
  -WindowsRoot: Windows folder under test; default parent of this validation folder.
  -OutputDirectory: Private mock reports and wrapper fixtures; default Windows\Reports.
How it works:
  Uses fake private cores to inspect forwarded parameters, then real merged host cores with mocked
  module, connection and remote providers. No live Veeam, host, network or database query is made.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$WindowsRoot,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $WindowsRoot){$WindowsRoot=Split-Path $PSScriptRoot -Parent}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $WindowsRoot 'Reports'}
$fixtureRoot=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory ('merged-veeam-'+[guid]::NewGuid().ToString('N').Substring(0,8))) -Force).FullName
$script:mergeChecks=0
function Assert-MergedVeeam {param([bool]$Condition,[string]$Message);$script:mergeChecks++;if(-not $Condition){throw ('FAIL: '+$Message)}}
$mappings=@(
 @{Category='Veeam-Backup-and-Replication-v12';Name='Get-VBRHostDiagnostics';Core='Invoke-VeeamHostDiagnosticsCore';Product='VBR';Port=9392;Family=''},
 @{Category='Veeam-Microsoft-365';Name='Get-VBOHostDiagnostics';Core='Invoke-VeeamHostDiagnosticsCore';Product='VBO';Port=9191;Family=''},
 @{Category='Veeam-Backup-and-Replication-v12';Name='Test-VBRConnectivity';Core='Invoke-VeeamConnectivityCore';Product='VBR';Port=9392;Family=''},
 @{Category='Veeam-Microsoft-365';Name='Test-VBOConnectivity';Core='Invoke-VeeamConnectivityCore';Product='VBO';Port=9191;Family=''},
 @{Category='Veeam-Backup-and-Replication-v12';Name='Test-VBRDatabaseHealth';Core='Invoke-VeeamDatabaseHealthCore';Product='VBR';Port=9392;Family=''},
 @{Category='Veeam-Microsoft-365';Name='Test-VBODatabaseHealth';Core='Invoke-VeeamDatabaseHealthCore';Product='VBO';Port=9191;Family=''},
 @{Category='Veeam-Backup-and-Replication-v12';Name='Get-VBRBackupJobAudit';Core='Invoke-VbrClassicJobAuditCore';Product='VBR';Port=9392;Family='Backup'},
 @{Category='Veeam-Backup-and-Replication-v12';Name='Get-VBRReplicationJobAudit';Core='Invoke-VbrClassicJobAuditCore';Product='VBR';Port=9392;Family='Replication'}
)
$mockWindows=Join-Path $fixtureRoot 'Windows'
$null=New-Item -ItemType Directory -Path (Join-Path $mockWindows 'lib') -Force
$fakeCore=@'
[CmdletBinding()]
param($Product,$EntryPointName,$Family,$Server='localhost',$Port,$Credential,$HostCredential,$OutputDirectory,$Hours=48,$MaxEvents=200,$MinimumFreePercent=15,$Target,$ProbeComputerName,$ProbeCredential,$TimeoutMilliseconds,$QueryDatabase,$DatabaseCredential,$PsqlPath,$PostgresUser,$PostgresPassFile,$ConnectionTimeoutSeconds,$QueryTimeoutSeconds,$MaxDatabases,$ProxyComputerName,$NamePattern,$MaxJobs,$MaxObjectsPerJob)
[pscustomobject]@{Product=$Product;EntryPointName=$EntryPointName;Family=$Family;Server=$Server;Port=$Port;OutputDirectory=$OutputDirectory;Credential=$Credential;HostCredential=$HostCredential;QueryDatabase=$QueryDatabase;ProxyComputerName=$ProxyComputerName;NamePattern=$NamePattern;MaxJobs=$MaxJobs;MaxObjectsPerJob=$MaxObjectsPerJob;BoundNames=@($PSBoundParameters.Keys)}
'@
foreach($coreName in @($mappings.Core | Select-Object -Unique)){
 [IO.File]::WriteAllText((Join-Path $mockWindows ('lib\'+$coreName+'.ps1')),$fakeCore)
 $source=Join-Path $WindowsRoot ('lib\'+$coreName+'.ps1')
 Assert-MergedVeeam (Test-Path -LiteralPath $source -PathType Leaf) ('Private core exists '+$coreName)
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
 Assert-MergedVeeam ($errors.Count -eq 0) ('Private core parses '+$coreName)
 Assert-MergedVeeam ($null -eq $ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Initialize-VeeamConnection'},$true)) ('Connection engine is centralized '+$coreName)
 Assert-MergedVeeam ([IO.File]::ReadAllText($source).Contains(". (Join-Path `$PSScriptRoot 'Veeam-AuditCommon.ps1')")) ('Core loads one shared connection/report helper '+$coreName)
}
$secure=ConvertTo-SecureString 'fixture-only-password' -AsPlainText -Force
$credential=New-Object Management.Automation.PSCredential('fixture-user',$secure)
foreach($map in $mappings){
 $source=Join-Path $WindowsRoot ($map.Category+'\'+$map.Name+'.ps1')
 $category=(New-Item -ItemType Directory -Path (Join-Path $mockWindows $map.Category) -Force).FullName
 $wrapper=Join-Path $category ($map.Name+'.ps1')
 Copy-Item -LiteralPath $source -Destination $wrapper
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
 Assert-MergedVeeam ($errors.Count -eq 0) ('Wrapper parses '+$map.Name)
 Assert-MergedVeeam (@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)).Count -eq 0) ('Wrapper contains no duplicate collector '+$map.Name)
 $result=& $wrapper
 Assert-MergedVeeam ($result.Product -eq $map.Product -and $result.Port -eq $map.Port) ('Legacy product and default port '+$map.Name)
 Assert-MergedVeeam ($result.EntryPointName -eq $map.Name) ('Legacy report identity '+$map.Name)
 Assert-MergedVeeam ([string]$result.Family -eq $map.Family) ('Job family selector '+$map.Name)
 Assert-MergedVeeam ($result.BoundNames -notcontains 'OutputDirectory') ('Default output is resolved by core, not overwritten '+$map.Name)
 $parameters=@{Server='selected.example.invalid';Port=12345;Credential=$credential;HostCredential=$credential;OutputDirectory=$fixtureRoot}
 if($map.Name -like '*DatabaseHealth'){$parameters.QueryDatabase=$true;$parameters.ConnectionTimeoutSeconds=7;$parameters.QueryTimeoutSeconds=8;$parameters.MaxDatabases=2}
 if($map.Product -eq 'VBO' -and $map.Name -like '*DatabaseHealth'){$parameters.ProxyComputerName=@('proxy-one.invalid','proxy-two.invalid')}
 if($map.Family){$parameters.NamePattern='Selected*';$parameters.MaxJobs=3;$parameters.MaxObjectsPerJob=4}
 $custom=& $wrapper @parameters
 Assert-MergedVeeam ($custom.Server -eq 'selected.example.invalid' -and $custom.Port -eq 12345 -and $custom.OutputDirectory -eq $fixtureRoot) ('Caller server/port/output preserved '+$map.Name)
 Assert-MergedVeeam ([object]::ReferenceEquals($custom.Credential,$credential) -and [object]::ReferenceEquals($custom.HostCredential,$credential)) ('Credential objects forwarded without plaintext '+$map.Name)
 if($parameters.ContainsKey('QueryDatabase')){Assert-MergedVeeam ([bool]$custom.QueryDatabase) ('Database opt-in remains explicit '+$map.Name)}
 if($parameters.ContainsKey('ProxyComputerName')){Assert-MergedVeeam (($custom.ProxyComputerName -join ',') -eq 'proxy-one.invalid,proxy-two.invalid') 'VB365 proxy selection preserved'}
 if($map.Family){Assert-MergedVeeam ($custom.NamePattern -eq 'Selected*' -and $custom.MaxJobs -eq 3 -and $custom.MaxObjectsPerJob -eq 4) ('Job limits and name filter preserved '+$map.Name)}
}
$badProxyRejected=$false
try{& (Join-Path $mockWindows 'Veeam-Backup-and-Replication-v12\Test-VBRDatabaseHealth.ps1') -ProxyComputerName 'not-a-vbr-parameter' | Out-Null}catch{$badProxyRejected=$true}
Assert-MergedVeeam $badProxyRejected 'VBR wrapper does not silently accept the VB365-only proxy flag'

# These mocks test the real shared core's script-scope isolation in one PowerShell process.
$global:MergedProduct='VBR';$global:MergedMajor=12;$global:MergedMode='Normal';$global:MergedConnects=0;$global:MergedDisconnects=0
function Import-Module {[CmdletBinding()]param([string]$Name,[switch]$PassThru) if($Name -notin @('Veeam.Backup.PowerShell','Veeam.Archiver.PowerShell')){throw 'Unexpected import blocked.'};[pscustomobject]@{Name=$Name;Version=[version]'1.0'}}
function Get-VBOVersion {[CmdletBinding()]param() [pscustomobject]@{ProductVersion=($global:MergedMajor.ToString()+'.0.0.1')}}
function Get-VBRBackupServerInfo {[CmdletBinding()]param() [pscustomobject]@{Build='12.3.2.1'}}
function Get-VBRJob {[CmdletBinding()]param() throw 'Unexpected job query blocked in host-only isolation test.'}
function Connect-VBRServer {[CmdletBinding()]param($Server,$Port,$Credential) if($global:MergedMode -eq 'ConnectDenied'){throw 'fixture-secret-do-not-export'};$global:MergedConnects++}
function Connect-VBOServer {[CmdletBinding()]param($Server,$Port,$Credential) if($global:MergedMode -eq 'ConnectDenied'){throw 'fixture-secret-do-not-export'};$global:MergedConnects++}
function Disconnect-VBRServer {[CmdletBinding()]param() $global:MergedDisconnects++}
function Disconnect-VBOServer {[CmdletBinding()]param() $global:MergedDisconnects++}
function Get-CimInstance {[CmdletBinding()]param($ClassName,$Filter) throw 'Actual CIM access blocked.'}
function Invoke-Command {
 [CmdletBinding()]param($ComputerName,[scriptblock]$ScriptBlock,[object[]]$ArgumentList,[PSCredential]$Credential)
 if($ArgumentList.Count -eq 1){return [pscustomobject]@{ProductVersion=($global:MergedMajor.ToString()+'.0.0.2')}}
 if($ArgumentList.Count -eq 3){
  return [pscustomobject]@{Kind='Host';Computer=$ComputerName;Caption='Fixture Windows';Version='10.0';LastBootUpTime=[datetime]'2026-01-01';FreePhysicalMemoryKB=1024;TotalVisibleMemoryKB=2048}
 }
 throw 'Unexpected remote operation blocked.'
}
$script:VeeamProduct='caller-product-sentinel';$script:veeamReady='caller-ready-sentinel';$script:ownsVeeamConnection='caller-connection-sentinel'
foreach($case in @(@{Product='VBR';Major=12;Mode='Normal';ExpectedConnects=1},@{Product='VBO';Major=7;Mode='Normal';ExpectedConnects=1},@{Product='VBO';Major=8;Mode='ConnectDenied';ExpectedConnects=0},@{Product='VBR';Major=12;Mode='Normal';ExpectedConnects=1},@{Product='VBO';Major=8;Mode='Normal';ExpectedConnects=1})){
 $global:MergedProduct=$case.Product;$global:MergedMajor=$case.Major;$global:MergedMode=$case.Mode;$global:MergedConnects=0;$global:MergedDisconnects=0
 $category=if($case.Product -eq 'VBR'){'Veeam-Backup-and-Replication-v12'}else{'Veeam-Microsoft-365'}
 $entry='Get-'+$case.Product+'HostDiagnostics'
 $result=& (Join-Path $WindowsRoot ($category+'\'+$entry+'.ps1')) -Server 'isolated.invalid' -OutputDirectory $fixtureRoot
 Assert-MergedVeeam ($result.Script -eq $entry -and $result.Context.Product -eq $case.Product -and $result.Context.MajorVersion -eq $case.Major) ('Real core preserves product/version/report identity '+$case.Product+$case.Major+$case.Mode)
 Assert-MergedVeeam ($global:MergedConnects -eq $case.ExpectedConnects -and $global:MergedDisconnects -eq $case.ExpectedConnects) ('Only owned successful connections close '+$case.Product+$case.Mode)
 Assert-MergedVeeam ($script:VeeamProduct -eq 'caller-product-sentinel' -and $script:veeamReady -eq 'caller-ready-sentinel' -and $script:ownsVeeamConnection -eq 'caller-connection-sentinel') 'Private core does not overwrite the caller script state'
 Assert-MergedVeeam (([IO.File]::ReadAllText((Join-Path $result.ReportDirectory 'summary.json'))) -notlike '*fixture-secret-do-not-export*') 'Failure reports do not export raw credential-like provider errors'
}
$summary=[pscustomobject]@{Suite='Merged Veeam tools';Assertions=$script:mergeChecks;Result='Passed';PowerShellVersion=$PSVersionTable.PSVersion.ToString();OutputDirectory=$fixtureRoot;Scope='Public-wrapper forwarding plus real private-core isolation with mocked module, connection and remote providers; no live Veeam operation.'}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $fixtureRoot 'merged-test-results.json') -Encoding UTF8
$summary
