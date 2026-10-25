<#
What it does:
  Runs Active-database discovery, connection parsing, compatibility and error mocks without contacting Veeam, Windows hosts, or databases.

Available flags:
  -WindowsRoot: Windows category root to validate; default parent of this folder.
  -OutputDirectory: Mock report destination; default Windows\Reports.

How it works:
  Replaces provider commands with local fixtures, runs production scripts, and asserts
  failures, partial evidence, limits, compatibility and secret exclusion. Throws on failure.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([string]$WindowsRoot,[string]$OutputDirectory)
if(-not $WindowsRoot){$WindowsRoot=Split-Path $PSScriptRoot -Parent}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $WindowsRoot 'Reports'}
$SourceRoot=$WindowsRoot
$ReportRoot=$OutputDirectory
$ErrorActionPreference='Stop'
if($WindowsRoot){$SourceRoot=$WindowsRoot}
if($OutputDirectory){$ReportRoot=$OutputDirectory}
if(-not $SourceRoot){$SourceRoot=Join-Path (Split-Path $PSScriptRoot -Parent) 'staged\Windows'}
if(-not $ReportRoot){$ReportRoot=Join-Path $PSScriptRoot ('database-reports-'+[guid]::NewGuid().ToString('N'))}
$fixtureRoot=Join-Path $ReportRoot 'mock-program-data'
$configRoot=Join-Path $fixtureRoot 'Veeam\Backup365'
$null=New-Item -ItemType Directory -Path $configRoot -Force
$global:DbTestMode='Normal';$global:DbProduct='VBR';$global:DbMajor=12;$global:DbHostMajor=0;$global:DbConnectedMajor=0;$global:DbManifest='1.0';$global:DbActive='MsSql';$global:DbDiscoveryCalls=0;$global:DbConnects=0;$global:DbDisconnects=0;$global:DbChecks=0;$global:DbSqlMock=$null
function Assert-Database {param([bool]$Condition,[string]$Label) if(-not $Condition){throw ('FAIL: '+$Label)};$global:DbChecks++}
function Invoke-DatabaseSubject {
    param([string]$Product='VBR',[hashtable]$Parameters=@{})
    $global:DbProduct=$Product
    if(-not $Parameters.ContainsKey('Server')){$Parameters.Server='database-fixture.example.invalid'}
    $Parameters.OutputDirectory=$ReportRoot
    $category=if($Product -eq 'VBR'){'Veeam-Backup-and-Replication-v12'}else{'Veeam-Microsoft-365'}
    & (Join-Path (Join-Path $SourceRoot $category) ('Test-'+$Product+'DatabaseHealth.ps1')) @Parameters
}
function Read-DatabaseCsv {param($Result,[string]$Name) Import-Csv -LiteralPath (Join-Path $Result.ReportDirectory ($Name+'.csv'))}
function Assert-DatabaseRedaction {
    param($Result)
    $text=@(Get-ChildItem -LiteralPath $Result.ReportDirectory -File | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw}) -join "`n"
    Assert-Database ($text -notlike '*DO_NOT_EXPORT_DB_SECRET*') ('Selected DB fields only: '+$Result.Script)
    Assert-Database ($text -notmatch 'ControllerConnectionString|password=|username=') ('No whole connection strings/credentials: '+$Result.Script)
}
function Import-Module {
    [CmdletBinding()]param([string]$Name,[switch]$PassThru)
    if($Name -notin @('Veeam.Backup.PowerShell','Veeam.Archiver.PowerShell')){throw 'Unexpected module import blocked.'}
    if($global:DbTestMode -eq 'ModuleDenied'){throw 'DO_NOT_EXPORT_DB_SECRET'}
    [pscustomobject]@{Name=$Name;Version=[version]$global:DbManifest}
}
function Get-VBOVersion {[CmdletBinding()]param() [pscustomobject]@{ProductVersion=($global:DbMajor.ToString()+'.0.0.1000')}}
function Get-CimInstance {[CmdletBinding()]param($ClassName,$Filter) throw 'Tests must not query actual local services.'}
function Invoke-Command {
    [CmdletBinding()]param([string]$ComputerName,[scriptblock]$ScriptBlock,[object[]]$ArgumentList,[PSCredential]$Credential)
    if($ArgumentList.Count -eq 1){
        if($global:DbTestMode -in @('HostVersionDenied','AllRemoteDenied')){throw 'DO_NOT_EXPORT_DB_SECRET'}
        $major=$global:DbMajor;if($global:DbHostMajor){$major=$global:DbHostMajor}
        return [pscustomobject]@{ProductVersion=($major.ToString()+'.0.0.2000')}
    }
    if($ArgumentList.Count -ne 2){throw 'Unexpected remote operation blocked.'}
    $global:DbDiscoveryCalls++
    if($global:DbTestMode -eq 'AllRemoteDenied'){throw 'DO_NOT_EXPORT_DB_SECRET'}
    # Execute the production read-only probe against mock registry and fixture XML only.
    & $ScriptBlock @ArgumentList
}
function Connect-VBRServer {[CmdletBinding()]param($Server,$Port,$Credential) if($global:DbTestMode -eq 'ConnectDenied'){throw 'DO_NOT_EXPORT_DB_SECRET'};$global:DbConnects++}
function Disconnect-VBRServer {[CmdletBinding()]param() $global:DbDisconnects++}
function Connect-VBOServer {[CmdletBinding()]param($Server,$Port,$Credential) if($global:DbTestMode -eq 'ConnectDenied'){throw 'DO_NOT_EXPORT_DB_SECRET'};$global:DbConnects++}
function Disconnect-VBOServer {[CmdletBinding()]param() $global:DbDisconnects++}
function Get-VBRBackupServerInfo {[CmdletBinding()]param() $major=$global:DbMajor;if($global:DbConnectedMajor){$major=$global:DbConnectedMajor};[pscustomobject]@{Build=[version]($major.ToString()+'.0.0.2000')}}
function Get-ItemPropertyValue {
    [CmdletBinding()]param([string]$LiteralPath,[string]$Name)
    if($LiteralPath -ne 'HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations' -or $Name -ne 'SqlActiveConfiguration'){throw 'Unexpected registry value read blocked.'}
    if($global:DbTestMode -eq 'RegistryDenied'){throw 'DO_NOT_EXPORT_DB_SECRET'}
    $global:DbActive
}
function Get-ItemProperty {
    [CmdletBinding()]param([string]$LiteralPath)
    if($LiteralPath -like '*\DatabaseConfigurations\MsSql'){
        $hostName='localhost';$instance='VEEAMSQL';$database='VeeamBackup'
        if($global:DbTestMode -eq 'SqlTcpLoopback'){$hostName='tcp:localhost,1433';$instance=''}
        if($global:DbTestMode -eq 'SqlDefaultInstance'){$instance='MSSQLSERVER'}
        if($global:DbTestMode -eq 'EndpointMissing'){$database=''}
        return [pscustomobject]@{SqlServerName=$hostName;SqlInstanceName=$instance;SqlDatabaseName=$database;SqlPassword='DO_NOT_EXPORT_DB_SECRET'}
    }
    if($LiteralPath -like '*\DatabaseConfigurations\PostgreSql'){
        $port='5432';if($global:DbTestMode -eq 'PortMalformed'){$port='999999999999999999999999999999'}
        return [pscustomobject]@{SqlHostName='127.0.0.1';SqlHostPort=$port;SqlDatabaseName='VeeamBackup';Password='DO_NOT_EXPORT_DB_SECRET'}
    }
    throw 'Unexpected registry key read blocked.'
}
function Set-DatabaseXmlFixture {
    param([string]$Config,[string]$Proxy)
    $configPath=Join-Path $configRoot 'Config.xml';$proxyPath=Join-Path $configRoot 'Proxy.xml'
    if($null -ne $Config -and $Config -ne ''){$Config | Set-Content -LiteralPath $configPath -Encoding UTF8}
    elseif(Test-Path -LiteralPath $configPath){Remove-Item -LiteralPath $configPath}
    if($null -ne $Proxy -and $Proxy -ne ''){$Proxy | Set-Content -LiteralPath $proxyPath -Encoding UTF8}
    elseif(Test-Path -LiteralPath $proxyPath){Remove-Item -LiteralPath $proxyPath}
}

$savedProgramData=$env:ProgramData
$env:ProgramData=$fixtureRoot
try{
    foreach($product in @('VBR','VBO')){
        $category=if($product -eq 'VBR'){'Veeam-Backup-and-Replication-v12'}else{'Veeam-Microsoft-365'}
        $path=Join-Path (Join-Path $SourceRoot $category) ('Test-'+$product+'DatabaseHealth.ps1')
        $tokens=$null;$problems=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$problems)
        Assert-Database (@($problems).Count -eq 0) ('PS5.1 database script syntax '+$product)
    }
    $global:DbMajor=12;$global:DbActive='MsSql';$global:DbTestMode='Normal'
    $result=Invoke-DatabaseSubject
    $endpoint=@(Read-DatabaseCsv $result 'active-database-endpoints')[0]
    Assert-Database ($result.Context.MajorVersion -eq 12 -and $result.Context.ModuleVersion -eq '1.0') 'Real VBR manifest1.0 is not mistaken for productmajor1'
    Assert-Database ($endpoint.DatabaseHost -eq 'database-fixture.example.invalid\VEEAMSQL' -and $endpoint.DatabaseName -eq 'VeeamBackup') 'Active SQL registry instance maps loopback to inspected server'
    Assert-Database ($endpoint.Engine -eq 'MSSQL' -and $endpoint.MetadataState -eq 'NotRequested') 'Discovery does not silently query database engines'
    Assert-DatabaseRedaction $result
    $global:DbTestMode='SqlTcpLoopback';$result=Invoke-DatabaseSubject
    Assert-Database ((@(Read-DatabaseCsv $result 'active-database-endpoints')[0]).DatabaseHost -eq 'tcp:database-fixture.example.invalid,1433') 'SQL protocol and port survive workstation loopback normalization'
    $global:DbTestMode='SqlDefaultInstance';$result=Invoke-DatabaseSubject
    Assert-Database ((@(Read-DatabaseCsv $result 'active-database-endpoints')[0]).DatabaseHost -eq 'database-fixture.example.invalid') 'MSSQLSERVER default instance is not appended as a named instance'
    $global:DbTestMode='ConnectDenied';$before=$global:DbDiscoveryCalls;$result=Invoke-DatabaseSubject
    Assert-Database ($global:DbDiscoveryCalls -gt $before -and $result.Data.DiscoveredEndpoints -eq 1 -and -not $result.Context.ConnectionSucceeded) 'Confirmed v12 database discovery survives Veeam service outage'
    $global:DbTestMode='HostVersionDenied';$result=Invoke-DatabaseSubject
    Assert-Database ($result.Context.VersionSource -eq 'Get-VBRBackupServerInfo' -and $result.Context.MajorVersion -eq 12 -and $result.Data.DiscoveredEndpoints -eq 1) 'Connected server Build verifies product when WinRM service-version probe is unavailable'
    $global:DbTestMode='Normal';$global:DbConnectedMajor=13;$before=$global:DbDiscoveryCalls;$result=Invoke-DatabaseSubject
    Assert-Database ($result.Context.VersionRejected -and $before -eq $global:DbDiscoveryCalls -and $result.Data.DiscoveredEndpoints -eq 0) 'Rejected connected VBR13 build cannot reuse previously supported host12 context for database discovery'
    $global:DbConnectedMajor=0;$global:DbMajor=8;$global:DbHostMajor=7;$before=$global:DbDiscoveryCalls;$result=Invoke-DatabaseSubject 'VBO'
    Assert-Database ($result.Context.VersionRejected -and $before -eq $global:DbDiscoveryCalls -and $result.Data.DiscoveredEndpoints -eq 0) 'VBO toolkit8 and host7 mismatch skips discovery instead of choosing the wrong engine branch'
    $global:DbHostMajor=0
    $global:DbMajor=13;$global:DbTestMode='Normal';$before=$global:DbDiscoveryCalls;$result=Invoke-DatabaseSubject
    Assert-Database ($before -eq $global:DbDiscoveryCalls -and $result.Data.DiscoveredEndpoints -eq 0 -and $result.State -eq 'Incomplete') 'Unsupported productmajor skips configuration discovery'
    $global:DbMajor=12;$global:DbTestMode='ModuleDenied';$before=$global:DbDiscoveryCalls;$result=Invoke-DatabaseSubject
    Assert-Database ($before -eq $global:DbDiscoveryCalls -and $null -eq $result.Context.MajorVersion) 'Unknown product version after module failure skips discovery'
    Assert-DatabaseRedaction $result
    $global:DbTestMode='RegistryDenied';$result=Invoke-DatabaseSubject
    Assert-Database ($result.Data.DiscoveredEndpoints -eq 0 -and $result.State -eq 'Incomplete') 'Registry permission failure remains unknown'
    $global:DbTestMode='AllRemoteDenied';$result=Invoke-DatabaseSubject
    Assert-Database ($result.Data.DiscoveredEndpoints -eq 0 -and $result.State -eq 'Incomplete') 'Remote discovery failure cannot substitute workstation data'
    Assert-DatabaseRedaction $result
    $global:DbTestMode='EndpointMissing';$result=Invoke-DatabaseSubject
    Assert-Database ((@(Read-DatabaseCsv $result 'active-database-endpoints')[0]).MetadataState -eq 'Unknown') 'Missing active database name remains unknown'
    $global:DbTestMode='Normal';$global:DbActive='PostgreSql';$result=Invoke-DatabaseSubject
    $endpoint=@(Read-DatabaseCsv $result 'active-database-endpoints')[0]
    Assert-Database ($endpoint.DatabaseHost -eq 'database-fixture.example.invalid' -and $endpoint.DatabasePort -eq '5432' -and $endpoint.Engine -eq 'PostgreSQL') 'Active PostgreSQL registry fields project correctly'
    $global:DbTestMode='PortMalformed';$result=Invoke-DatabaseSubject
    Assert-Database ((@(Read-DatabaseCsv $result 'active-database-endpoints')[0]).MetadataState -eq 'Unknown') 'Oversized malformed port cannot throw or become a default endpoint'
    $global:DbTestMode='Normal';$global:DbActive='UnknownEngine';$result=Invoke-DatabaseSubject
    Assert-Database ($result.Data.DiscoveredEndpoints -eq 0 -and $result.State -eq 'Incomplete') 'Unrecognized active registry engine stays unknown'

    $global:DbMajor=8;$global:DbManifest='1.0'
    $config='<Settings><ControllerPostgres ControllerConnectionString="host=localhost;port=5432;database=VeeamBackup365;username=DO_NOT_EXPORT_DB_SECRET;password=DO_NOT_EXPORT_DB_SECRET" /></Settings>'
    $proxy='<Settings><ProxyPostgres ConnectionString="host=proxy-db;port=5433;database=ProxyConfig;password=DO_NOT_EXPORT_DB_SECRET" /><PersistentCachePostgres ConnectionString="host=cache-db;port=5434;database=RepoCache;password=DO_NOT_EXPORT_DB_SECRET" /></Settings>'
    Set-DatabaseXmlFixture $config $proxy
    $result=Invoke-DatabaseSubject 'VBO'
    $endpoints=@(Read-DatabaseCsv $result 'active-database-endpoints')
    Assert-Database ($endpoints.Count -eq 3 -and @($endpoints | Where-Object Role -eq 'Configuration').Count -eq 1) 'VB365v8 parses controller, proxy, and persistent-cache connection strings'
    Assert-Database (($endpoints | Where-Object Role -eq 'Configuration').DatabaseHost -eq 'database-fixture.example.invalid') 'VB365 local database host resolves relative to requested controller'
    Assert-Database (($endpoints | Where-Object Role -eq 'RepositoryCache').DatabaseName -eq 'RepoCache') 'Cache database name is a selected scalar'
    Assert-DatabaseRedaction $result
    Set-DatabaseXmlFixture '<Settings><ControllerPostgres ControllerConnectionString="host=localhost;database=&quot;Quoted;Db&quot;;password=&quot;DO_NOT_EXPORT_DB_SECRET;hidden&quot;" /></Settings>' ''
    $result=Invoke-DatabaseSubject 'VBO';$endpoint=@(Read-DatabaseCsv $result 'active-database-endpoints')[0]
    Assert-Database ($endpoint.DatabaseName -eq 'Quoted;Db' -and $endpoint.DatabasePort -eq '5432') 'Real DbConnectionStringBuilder handles quoted semicolons and standard omitted port'
    Assert-DatabaseRedaction $result
    Set-DatabaseXmlFixture '<Settings><Broken' $proxy
    $result=Invoke-DatabaseSubject 'VBO';$endpoints=@(Read-DatabaseCsv $result 'active-database-endpoints')
    Assert-Database (@($endpoints | Where-Object Role -eq 'RepositoryCache').Count -eq 1 -and @($endpoints | Where-Object MetadataState -eq 'Unknown').Count -eq 1) 'Malformed controller XML preserves independently valid proxy/cache evidence'
    Assert-Database ($result.State -eq 'Incomplete') 'XML parse errors never appear healthy'
    Set-DatabaseXmlFixture '<!DOCTYPE Settings [<!ENTITY secret SYSTEM "file:///DO_NOT_EXPORT_DB_SECRET">]><Settings><ControllerPostgres ControllerConnectionString="host=db;database=&secret;" /></Settings>' ''
    $result=Invoke-DatabaseSubject 'VBO'
    Assert-Database ((@(Read-DatabaseCsv $result 'active-database-endpoints')[0]).MetadataState -eq 'Unknown') 'DTD/external entities are prohibited before expansion'
    Assert-DatabaseRedaction $result
    Set-DatabaseXmlFixture '' ''
    $result=Invoke-DatabaseSubject 'VBO'
    Assert-Database ($result.Data.DiscoveredEndpoints -eq 0 -and $result.State -eq 'Incomplete') 'Missing VB365v8 configuration remains unknown without invented database'
    $global:DbMajor=7
    $candidateFolder=Join-Path $configRoot 'ConfigDB';$null=New-Item -ItemType Directory -Path $candidateFolder -Force
    'mock bytes, never a real EDB' | Set-Content -LiteralPath (Join-Path $candidateFolder 'config.edb') -Encoding UTF8
    $result=Invoke-DatabaseSubject 'VBO';$endpoint=@(Read-DatabaseCsv $result 'active-database-endpoints')[0]
    Assert-Database ($endpoint.Engine -eq 'JET/ESE' -and $endpoint.ActiveEvidence -eq 'False' -and $endpoint.MetadataState -eq 'NotSupportedOnline' -and [long]$endpoint.FileBytes -gt 0) 'VB365v7 reports default EDB metadata only as a candidate, never active/consistent proof'
    Assert-DatabaseRedaction $result

    # Extract the actual shipped production helper definitions, not duplicated implementations.
    $production=Join-Path (Join-Path $SourceRoot 'lib') 'Invoke-VeeamDatabaseHealthCore.ps1'
    $tokens=$null;$problems=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($production,[ref]$tokens,[ref]$problems)
    foreach($functionName in @('Resolve-VeeamDatabaseHost','ConvertFrom-VeeamPostgresMetadataCsv','Invoke-VeeamSqlMetadata')){
        $node=$ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq $functionName},$true)
        Assert-Database ($null -ne $node) ('Production function available '+$functionName)
        . ([scriptblock]::Create($node.Extent.Text))
    }
    Assert-Database ((Resolve-VeeamDatabaseHost 'tcp:[::1],1433' 'server.example') -eq 'tcp:server.example,1433') 'IPv6 SQL loopback preserves protocol/port'
    Assert-Database ((Resolve-VeeamDatabaseHost '(local)\INSTANCE' 'server.example') -eq 'server.example\INSTANCE') 'SQL local token resolves on inspected host'
    Assert-Database ((Resolve-VeeamDatabaseHost 'remote-db\INSTANCE' 'server.example') -eq 'remote-db\INSTANCE') 'Explicit remote SQL host remains unchanged'
    $csv=ConvertFrom-VeeamPostgresMetadataCsv -Text '"Db,WithComma",15.9,1234,f,4,0,,2026-10-18 00:00:00+00,0'
    Assert-Database ($csv.DatabaseName -eq 'Db,WithComma' -and $csv.ChecksumFailuresSinceReset -eq '' -and $csv.LockWaiters -eq '0') 'Native CSV quotes and null-versus-zero counters are preserved'
    foreach($bad in @('','db,15.9,not-a-number,f,1,0,0,,0','db,15.9,100,unknown,1,0,0,,0','db,15.9,100,f,,0,0,,0','db,15.9,9223372036854775808,f,1,0,0,,0',"db,15.9,100,f,1,0,0,,0`ndb2,15.9,200,f,2,0,0,,0")){
        $rejected=$false;try{$null=ConvertFrom-VeeamPostgresMetadataCsv -Text $bad}catch{$rejected=$true}
        Assert-Database $rejected 'Malformed or ambiguous PostgreSQL metadata is rejected'
    }
    # Mock the connection object only; production SQL string building uses the real .NET builder.
    function New-Object {
        [CmdletBinding()]param([Parameter(Position=0)][string]$TypeName,[Parameter(Position=1)][object[]]$ArgumentList)
        if($TypeName -eq 'System.Data.SqlClient.SqlConnection'){
            $fake=[pscustomobject]@{ConnectionString='';Credential=$null}
            $fake | Add-Member -MemberType ScriptMethod -Name Open -Value {throw [OperationCanceledException]::new('MOCK_CONNECTION_BLOCKED')}
            $fake | Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
            $global:DbSqlMock=$fake
            return $fake
        }
        Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
    }
    $DatabaseCredential=$null;$ConnectionTimeoutSeconds=10;$QueryTimeoutSeconds=30
    $rejected=$false;try{$null=Invoke-VeeamSqlMetadata -Database ([pscustomobject]@{DatabaseHost='tcp:sql.example,1433';DatabaseName='VeeamBackup'})}catch{if($_.Exception.ToString() -match 'MOCK_CONNECTION_BLOCKED'){$rejected=$true}else{throw}}
    Assert-Database $rejected 'SQL metadata test blocks before any real connection'
    $builder=New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder.PSBase.ConnectionString=$global:DbSqlMock.ConnectionString
    Assert-Database ($builder['Data Source'] -eq 'tcp:sql.example,1433' -and $builder['Initial Catalog'] -eq 'VeeamBackup') 'Production SQL builder uses supported dictionary keywords under PS5.1'
    Assert-Database ([bool]$builder['Encrypt'] -and -not [bool]$builder['TrustServerCertificate'] -and [bool]$builder['Integrated Security']) 'Production SQL settings require encrypted verified trust and Windows authentication'
    Assert-Database ($builder['Connect Timeout'] -eq 10 -and -not $builder.ShouldSerialize('Password')) 'SQL connection timeout is bounded and no password is serialized'
    Assert-Database ($global:DbConnects -eq $global:DbDisconnects) 'Every successful owned mock Veeam connection is disconnected'
}finally{$env:ProgramData=$savedProgramData}
Write-Output ('PASS: {0} mock-only database/common checks on Windows PowerShell {1}.' -f $global:DbChecks,$PSVersionTable.PSVersion)
