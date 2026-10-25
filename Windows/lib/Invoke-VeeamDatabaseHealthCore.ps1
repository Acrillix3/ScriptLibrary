<#
What it does:
  Discovers configured active Veeam database endpoints and optionally tests read-only engine metadata.

Available flags:
  -Product: Private VBR/VBO profile supplied by the public entrypoint.
  -EntryPointName: Private report identity supplied by the public entrypoint.
  -Server: Veeam server name; default localhost.
  -Port: Console connection port; default 9191.
  -Credential: Optional Veeam PSCredential; current Windows identity when omitted.
  -HostCredential: Optional Windows/WinRM credential for server version and host evidence; current identity when omitted.
  -OutputDirectory: Report destination; default Windows\Reports.
  -QueryDatabase: Opt in to fixed read-only engine metadata queries.
  -DatabaseCredential: SQL Server PSCredential only; integrated Windows authentication when omitted.
  -PsqlPath: Optional path to a compatible psql.exe for PostgreSQL metadata.
  -PostgresUser: Optional libpq user; current libpq/SSPI identity when omitted.
  -PostgresPassFile: Optional existing, secured libpq password file; never copied into reports.
  -ConnectionTimeoutSeconds: Database connection timeout; default 10.
  -QueryTimeoutSeconds: Engine statement timeout; default 30.
  -MaxDatabases: Maximum configured endpoints per inspected host; default 64.
  -ProxyComputerName: Up to 32 additional Windows proxies to inspect through WinRM.

How it works:
  Private shared implementation; invoke a public product entrypoint instead. Reports retain its name.
  Reads only selected active database configuration fields on the requested server. Detects product version, uses WinRM from a workstation, and distinguishes missing access, untested engines, JET/ESE candidates, and incomplete scope.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('VBR','VBO')][string]$Product,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z][A-Za-z0-9_-]+$')][string]$EntryPointName,
    [string]$Server='localhost',
    [ValidateRange(1,65535)][int]$Port=9191,
    [PSCredential]$Credential,
    [PSCredential]$HostCredential,
    [string]$OutputDirectory,
    [switch]$QueryDatabase,
    [PSCredential]$DatabaseCredential,
    [string]$PsqlPath,
    [string]$PostgresUser,
    [string]$PostgresPassFile,
    [ValidateRange(1,120)][int]$ConnectionTimeoutSeconds=10,
    [ValidateRange(1,300)][int]$QueryTimeoutSeconds=30,
    [ValidateRange(1,500)][int]$MaxDatabases=64, 
    [ValidateCount(0,32)][string[]]$ProxyComputerName=@()
)
$script:VeeamProduct=$Product
$ErrorActionPreference='Stop'
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$runName=$EntryPointName
$runDirectory=Join-Path $OutputDirectory ($runName+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $runDirectory -Force
$collectionStatus=New-Object 'System.Collections.Generic.List[object]'
$findings=New-Object 'System.Collections.Generic.List[object]'
$veeamReady=$false;$ownsVeeamConnection=$false
$veeamContext=[pscustomobject]@{Product=$script:VeeamProduct;Server=$Server;Port=$Port;MajorVersion=$null;ServerVersion=$null;ToolkitProductVersion=$null;ModuleVersion=$null;VersionSource='Unknown';RemoteVersionVerified=$false;VersionRejected=$false;ConnectionSucceeded=$false;PowerShellVersion=[string]$PSVersionTable.PSVersion}
. (Join-Path $PSScriptRoot 'Veeam-AuditCommon.ps1')

try {
    Initialize-VeeamConnection
function Invoke-VeeamHostRead {
    param([string]$ComputerName,[scriptblock]$Action,[object[]]$Arguments)
    if($ComputerName -in @('localhost','.','127.0.0.1','::1',$env:COMPUTERNAME,([Net.Dns]::GetHostName()))){& $Action @Arguments}
    else{
        $request=@{ComputerName=$ComputerName;ScriptBlock=$Action;ArgumentList=$Arguments;ErrorAction='Stop'}
        if($HostCredential){$request.Credential=$HostCredential}
        Invoke-Command @request
    }
}
function Get-VeeamDatabaseDiscovery {
    param([string]$ComputerName,[string]$Product,[int]$Major)
    Invoke-VeeamHostRead -ComputerName $ComputerName -Arguments @($Product,$Major) -Action {
        param($RequestedProduct,$DetectedMajor)
        if($RequestedProduct -eq 'VBR'){
            if([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess){throw [InvalidOperationException]::new('Use a native 64-bit PowerShell host for the active database registry view')}
            $base='HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations'
            $active=[string](Get-ItemPropertyValue -LiteralPath $base -Name SqlActiveConfiguration -ErrorAction Stop)
            if($active -eq 'MsSql'){
                $config=Get-ItemProperty -LiteralPath (Join-Path $base 'MsSql') -ErrorAction Stop
                $dbHost=[string]$config.SqlServerName
                if($config.SqlInstanceName -and $config.SqlInstanceName -ne 'MSSQLSERVER' -and $dbHost -notmatch '\\' -and $dbHost -notmatch ',\d+$'){$dbHost+='\'+[string]$config.SqlInstanceName}
                [pscustomobject]@{Role='Configuration';Engine='MSSQL';DatabaseHost=$dbHost;DatabasePort=$null;DatabaseName=[string]$config.SqlDatabaseName;Source='Registry active MsSql configuration';ActiveEvidence=$true;FilePath=$null;FileBytes=$null}
            }elseif($active -eq 'PostgreSql'){
                $config=Get-ItemProperty -LiteralPath (Join-Path $base 'PostgreSql') -ErrorAction Stop
                [pscustomobject]@{Role='Configuration';Engine='PostgreSQL';DatabaseHost=[string]$config.SqlHostName;DatabasePort=$config.SqlHostPort;DatabaseName=[string]$config.SqlDatabaseName;Source='Registry active PostgreSql configuration';ActiveEvidence=$true;FilePath=$null;FileBytes=$null}
            }else{throw [InvalidOperationException]::new('Unrecognized active engine')}
        }elseif($DetectedMajor -eq 7){
            $candidate=Join-Path $env:ProgramData 'Veeam\Backup365\ConfigDB\config.edb'
            $file=if(Test-Path -LiteralPath $candidate -PathType Leaf){Get-Item -LiteralPath $candidate -ErrorAction Stop}else{$null}
            [pscustomobject]@{Role='ConfigurationCandidate';Engine='JET/ESE';DatabaseHost=$env:COMPUTERNAME;DatabasePort=$null;DatabaseName=$null;Source='v7 default-path candidate; active file not proven';ActiveEvidence=$false;FilePath=$candidate;FileBytes=$(if($file){$file.Length}else{$null})}
        }elseif($DetectedMajor -eq 8){
            foreach($filename in @('Config.xml','Proxy.xml')){
                $path=Join-Path (Join-Path $env:ProgramData 'Veeam\Backup365') $filename
                if(-not (Test-Path -LiteralPath $path -PathType Leaf)){continue}
                try{
                $settings=New-Object Xml.XmlReaderSettings
                $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
                $settings.MaxCharactersInDocument=16777216
                $reader=[Xml.XmlReader]::Create($path,$settings)
                try{$document=New-Object Xml.XmlDocument;$document.XmlResolver=$null;$document.Load($reader)}finally{$reader.Dispose()}
                foreach($node in $document.SelectNodes('//*[local-name()="ControllerPostgres" or local-name()="ProxyPostgres" or local-name()="PersistentCachePostgres"]')){
                    foreach($attribute in $node.Attributes){
                        if($attribute.Value -notmatch '(?i)(?:^|;)\s*database\s*='){continue}
                        $builder=New-Object System.Data.Common.DbConnectionStringBuilder
                        # IDictionary adaptation otherwise adds a literal ConnectionString entry in PS5.1.
                        $builder.PSBase.ConnectionString=$attribute.Value
                        $dbHost=if($builder.ContainsKey('Host')){[string]$builder['Host']}else{$null}
                        $dbName=if($builder.ContainsKey('Database')){[string]$builder['Database']}else{$null}
                        $dbPort=if($builder.ContainsKey('Port')){[int]$builder['Port']}else{5432}
                        $role=switch($node.LocalName){'ControllerPostgres'{'Configuration'};'PersistentCachePostgres'{'RepositoryCache'};default{'ProxyConfiguration'}}
                        [pscustomobject]@{Role=$role;Engine='PostgreSQL';DatabaseHost=$dbHost;DatabasePort=$dbPort;DatabaseName=$dbName;Source=($filename+':'+$node.LocalName);ActiveEvidence=$true;FilePath=$null;FileBytes=$null}
                        $builder.Clear()
                    }
                }
                }catch{
                    # Preserve evidence from other files; never return raw XML/parser/connection-string text.
                    [pscustomobject]@{Role='UnresolvedConfiguration';Engine='Unknown';DatabaseHost=$null;DatabasePort=$null;DatabaseName=$null;Source=($filename+':unreadable or invalid configuration');ActiveEvidence=$false;FilePath=$null;FileBytes=$null}
                }
            }
        }else{throw [InvalidOperationException]::new('Unsupported or undetected product major')}
    }
}
function Resolve-VeeamDatabaseHost {
    param([string]$ConfiguredHost,[string]$SourceComputer)
    $value=$ConfiguredHost.Trim()
    # Preserve SQL protocol, instance, and port while resolving loopback on the inspected host.
    $match=[regex]::Match($value,'^(?<prefix>(?:tcp:|np:|lpc:)?)(?<host>\[::1\]|::1|127\.0\.0\.1|localhost|\.|\(local\))(?<suffix>(?:\\[^,\\]+)?(?:,\d+)?)$','IgnoreCase')
    if($match.Success){
        return $match.Groups['prefix'].Value+$SourceComputer+$match.Groups['suffix'].Value
    }
    return $value
}
function Invoke-VeeamSqlMetadata {
    param([object]$Database)
    $builder=New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder['Data Source']=$Database.DatabaseHost;$builder['Initial Catalog']=$Database.DatabaseName
    $builder['Connect Timeout']=$ConnectionTimeoutSeconds;$builder['Application Name']='ScriptLibrary read-only metadata'
    $builder['Encrypt']=$true;$builder['TrustServerCertificate']=$false
    $connection=New-Object System.Data.SqlClient.SqlConnection
    $secure=$null;$command=$null;$reader=$null
    if($DatabaseCredential){
        $builder['Integrated Security']=$false
        $secure=$DatabaseCredential.Password.Copy();$secure.MakeReadOnly()
        $sqlCredential=New-Object System.Data.SqlClient.SqlCredential($DatabaseCredential.UserName,$secure)
        $connection.ConnectionString=$builder.PSBase.ConnectionString;$connection.Credential=$sqlCredential
    }else{$builder['Integrated Security']=$true;$connection.ConnectionString=$builder.PSBase.ConnectionString}
    try{
        $connection.Open()
        $command=$connection.CreateCommand();$command.CommandTimeout=$QueryTimeoutSeconds
        $command.CommandText=@'
SELECT DB_NAME() AS DatabaseName,
 CONVERT(nvarchar(128),SERVERPROPERTY('ProductVersion')) AS EngineVersion,
 state_desc AS DatabaseState,recovery_model_desc AS RecoveryModel,
 is_read_only AS IsReadOnly,log_reuse_wait_desc AS LogReuseWait,
 (SELECT SUM(CONVERT(bigint,size))*8192 FROM sys.database_files WHERE type=0) AS DataBytes,
 (SELECT SUM(CONVERT(bigint,size))*8192 FROM sys.database_files WHERE type=1) AS LogBytes
FROM sys.databases WHERE database_id=DB_ID();
'@
        $reader=$command.ExecuteReader()
        while($reader.Read()){
            $row=[ordered]@{}
            for($index=0;$index -lt $reader.FieldCount;$index++){$row[$reader.GetName($index)]=$(if($reader.IsDBNull($index)){$null}else{$reader.GetValue($index)})}
            [pscustomobject]$row
        }
    }finally{if($reader){$reader.Dispose()};if($command){$command.Dispose()};$connection.Dispose();if($secure){$secure.Dispose()}}
}
function Invoke-VeeamPostgresMetadata {
    param([object]$Database)
    if($DatabaseCredential){throw [InvalidOperationException]::new('Use a secured libpq password file or SSPI for PostgreSQL; PSCredential is SQL Server only')}
    $executable=$PsqlPath
    if(-not $executable){$executable=(Get-Command psql.exe -ErrorAction Stop).Source}
    if(-not (Test-Path -LiteralPath $executable -PathType Leaf)){throw [IO.FileNotFoundException]::new('psql executable absent')}
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$executable;$info.Arguments='--no-psqlrc --no-password --csv --tuples-only --set=ON_ERROR_STOP=1 --set=QUIET=1'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    # Child-only environment: no connection string or password is copied from Veeam.
    $info.EnvironmentVariables['PGHOST']=[string]$Database.DatabaseHost
    $info.EnvironmentVariables['PGPORT']=[string]$Database.DatabasePort
    $info.EnvironmentVariables['PGDATABASE']=[string]$Database.DatabaseName
    $info.EnvironmentVariables['PGCONNECT_TIMEOUT']=[string]$ConnectionTimeoutSeconds
    $info.EnvironmentVariables['PGSSLMODE']='verify-full'
    $info.EnvironmentVariables['PGOPTIONS']=('-c default_transaction_read_only=on -c statement_timeout='+($QueryTimeoutSeconds*1000))
    if($PostgresUser){$info.EnvironmentVariables['PGUSER']=$PostgresUser}
    if($PostgresPassFile){$info.EnvironmentVariables['PGPASSFILE']=[IO.Path]::GetFullPath($PostgresPassFile)}
    $null=$info.EnvironmentVariables.Remove('PGPASSWORD')
    $null=$info.EnvironmentVariables.Remove('PGSERVICE')
    $null=$info.EnvironmentVariables.Remove('PGHOSTADDR')
    $query=@'
SELECT current_database(),current_setting('server_version'),pg_database_size(current_database()),pg_is_in_recovery(),
 numbackends,deadlocks,checksum_failures,stats_reset,
 (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock')
FROM pg_stat_database WHERE datname=current_database();
'@
    $process=New-Object Diagnostics.Process;$process.StartInfo=$info
    try{
        $null=$process.Start()
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        $process.StandardInput.WriteLine($query);$process.StandardInput.Close()
        if(-not $process.WaitForExit(($ConnectionTimeoutSeconds+$QueryTimeoutSeconds+10)*1000)){
            $process.Kill();$process.WaitForExit();throw [TimeoutException]::new('PostgreSQL query timeout')
        }
        $output=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
        if($process.ExitCode -ne 0){throw [InvalidOperationException]::new('psql metadata query failed')}
        ConvertFrom-VeeamPostgresMetadataCsv -Text $output
    }finally{$process.Dispose()}
}
function ConvertFrom-VeeamPostgresMetadataCsv {
    param([string]$Text)
    $rows=@($Text | ConvertFrom-Csv -Header @('DatabaseName','EngineVersion','DatabaseBytes','InRecovery','Connections','DeadlocksSinceReset','ChecksumFailuresSinceReset','StatisticsReset','LockWaiters'))
    if($rows.Count -ne 1 -or [string]::IsNullOrWhiteSpace($rows[0].DatabaseName) -or [string]::IsNullOrWhiteSpace($rows[0].EngineVersion)){throw [InvalidOperationException]::new('Unexpected metadata result')}
    foreach($name in @('DatabaseBytes','Connections','DeadlocksSinceReset','ChecksumFailuresSinceReset','LockWaiters')){
        $value=[string]$rows[0].$name
        $number=[long]0
        if($value -and ($value -notmatch '^\d+$' -or -not [long]::TryParse($value,[ref]$number))){throw [InvalidOperationException]::new('Invalid numeric metadata value')}
    }
    if([string]::IsNullOrWhiteSpace($rows[0].DatabaseBytes) -or [string]::IsNullOrWhiteSpace($rows[0].Connections) -or $rows[0].InRecovery -notin @('t','f')){throw [InvalidOperationException]::new('Required metadata value absent')}
    return $rows[0]
}
$discovered=New-Object 'System.Collections.Generic.List[object]'
$metadata=New-Object 'System.Collections.Generic.List[object]'
$computers=@($Server)
if($script:VeeamProduct -eq 'VBO'){$computers+=@($ProxyComputerName);$computers=@($computers | Select-Object -Unique)}
$databaseVersionSupported=-not $veeamContext.VersionRejected -and (($script:VeeamProduct -eq 'VBR' -and $veeamContext.MajorVersion -eq 12) -or ($script:VeeamProduct -eq 'VBO' -and $veeamContext.MajorVersion -in @(7,8)))
if(-not $databaseVersionSupported){Add-VeeamFinding 'DatabaseDiscoveryVersion' Unknown 'A supported product major version was not established; no configuration database discovery was attempted.'}
if($databaseVersionSupported){foreach($computer in $computers){
    $discovery=Invoke-ReportQuery -Section ('ActiveDatabaseDiscovery:'+ $computer) -RequireData -Action {Get-VeeamDatabaseDiscovery -ComputerName $computer -Product $script:VeeamProduct -Major $veeamContext.MajorVersion | Select-Object -First ($MaxDatabases+1)}
    if(-not $discovery.Succeeded){continue}
    if($script:VeeamProduct -eq 'VBO' -and $veeamContext.MajorVersion -eq 8 -and $computer -eq $Server -and -not @($discovery.Data | Where-Object Role -eq 'Configuration').Count){Add-VeeamFinding 'ControllerConfigurationDatabase' Unknown 'No usable controller configuration database node was found on the requested controller host.'}
    if($discovery.Data.Count -gt $MaxDatabases){Add-VeeamFinding 'DatabaseScope' Review 'Database discovery exceeded MaxDatabases for a host; only the first configured endpoints are inspected.'}
    foreach($item in @($discovery.Data | Select-Object -First $MaxDatabases)){
        $row=[pscustomobject]@{SourceComputer=$computer;Role=[string]$item.Role;Engine=[string]$item.Engine;DatabaseHost=Resolve-VeeamDatabaseHost -ConfiguredHost ([string]$item.DatabaseHost) -SourceComputer $computer;DatabasePort=$item.DatabasePort;DatabaseName=[string]$item.DatabaseName;Source=[string]$item.Source;ActiveEvidence=[bool]$item.ActiveEvidence;FilePath=[string]$item.FilePath;FileBytes=$item.FileBytes;MetadataState='NotRequested'}
        $parsedPort=0;$postgresPortValid=[int]::TryParse([string]$row.DatabasePort,[ref]$parsedPort) -and $parsedPort -ge 1 -and $parsedPort -le 65535
        if($row.Engine -eq 'JET/ESE'){
            $row.MetadataState='NotSupportedOnline'
            Add-VeeamFinding ('JET/ESE:'+ $computer) Unknown 'v7 uses JET/ESE. Only default-path file metadata was checked; this does not prove the active file or database consistency. Live EDB files are not opened, copied, or repaired.'
        }elseif([string]::IsNullOrWhiteSpace($row.DatabaseHost) -or [string]::IsNullOrWhiteSpace($row.DatabaseName) -or $row.DatabaseHost -match '[\r\n\x00]' -or $row.DatabaseName -match '[\r\n\x00]' -or ($row.Engine -eq 'PostgreSQL' -and (-not $postgresPortValid -or $row.DatabaseHost -match '[/,;=\s]'))){
            $row.MetadataState='Unknown';Add-VeeamFinding 'DatabaseEndpoint' Unknown 'An active configuration record lacks a host, database name, or PostgreSQL port. No fallback endpoint was invented.'
        }elseif($QueryDatabase){
            $result=Invoke-ReportQuery -Section ('DatabaseMetadata:'+ $computer+':'+$row.Role+':'+$row.DatabaseName) -RequireData -Action {
                if($row.Engine -eq 'MSSQL'){Invoke-VeeamSqlMetadata -Database $row}
                elseif($row.Engine -eq 'PostgreSQL'){Invoke-VeeamPostgresMetadata -Database $row}
                else{throw [InvalidOperationException]::new('Unsupported engine')}
            }
            if($result.Succeeded){
                $row.MetadataState='Collected'
                foreach($sample in $result.Data){
                    $metadata.Add([pscustomobject]@{SourceComputer=$computer;Role=$row.Role;DatabaseName=$sample.DatabaseName;Engine=$row.Engine;EngineVersion=$sample.EngineVersion;DatabaseState=$sample.DatabaseState;RecoveryModel=$sample.RecoveryModel;IsReadOnly=$sample.IsReadOnly;LogReuseWait=$sample.LogReuseWait;DataBytes=$sample.DataBytes;LogBytes=$sample.LogBytes;DatabaseBytes=$sample.DatabaseBytes;InRecovery=$sample.InRecovery;Connections=$sample.Connections;DeadlocksSinceReset=$sample.DeadlocksSinceReset;ChecksumFailuresSinceReset=$sample.ChecksumFailuresSinceReset;StatisticsReset=$sample.StatisticsReset;LockWaiters=$sample.LockWaiters})
                    if($sample.DatabaseState -and $sample.DatabaseState -ne 'ONLINE'){Add-VeeamFinding 'SqlDatabaseState' Fail 'SQL Server reports a database state other than ONLINE.'}
                    if($sample.LogReuseWait -and $sample.LogReuseWait -notin @('NOTHING','CHECKPOINT')){Add-VeeamFinding 'SqlLogReuseWait' Review ('Log reuse wait: '+$sample.LogReuseWait+'. Assess workload and log backups; no shrink or recovery changes are performed.')}
                    if($sample.InRecovery -eq 't'){Add-VeeamFinding 'PostgresRecovery' Review 'PostgreSQL reports recovery/standby mode; confirm this is the intended Veeam endpoint.'}
                    if($sample.ChecksumFailuresSinceReset -and [long]$sample.ChecksumFailuresSinceReset -gt 0){Add-VeeamFinding 'PostgresChecksums' Fail 'PostgreSQL reports checksum failures since the statistics reset. Inspect the server logs and engage database support.'}
                    if($sample.LockWaiters -and [long]$sample.LockWaiters -gt 0){Add-VeeamFinding 'PostgresLockWaits' Review 'A snapshot found sessions waiting on locks. No sessions were terminated.'}
                }
            }else{$row.MetadataState='Unknown'}
        }else{Add-VeeamFinding 'DatabaseEngineMetadata' Unknown 'Active endpoint was discovered, but engine metadata queries were not requested. Use QueryDatabase with an authorized read account.'}
        $discovered.Add($row)
    }
}
}
if($script:VeeamProduct -eq 'VBO'){Add-VeeamFinding 'DatabaseCoverage' Review 'Only the controller and explicitly listed Windows proxies were inspected. Add ProxyComputerName for every Windows proxy. Linux proxy configurations and unlisted repository caches require separate review.'}
Write-ReportCsv -Name 'active-database-endpoints' -Rows $discovered.ToArray() -Columns @('SourceComputer','Role','Engine','DatabaseHost','DatabasePort','DatabaseName','Source','ActiveEvidence','FilePath','FileBytes','MetadataState')
Write-ReportCsv -Name 'database-metadata' -Rows $metadata.ToArray() -Columns @('SourceComputer','Role','DatabaseName','Engine','EngineVersion','DatabaseState','RecoveryModel','IsReadOnly','LogReuseWait','DataBytes','LogBytes','DatabaseBytes','InRecovery','Connections','DeadlocksSinceReset','ChecksumFailuresSinceReset','StatisticsReset','LockWaiters')
Complete-Report -Data ([pscustomobject]@{DiscoveredEndpoints=$discovered.Count;MetadataSamples=$metadata.Count;EngineQueriesRequested=[bool]$QueryDatabase;MaxDatabasesPerHost=$MaxDatabases}) -Notes @(
    'VBR selects the engine from SqlActiveConfiguration. Microsoft 365 v8 reads only host/port/database fields from ControllerPostgres, ProxyPostgres and PersistentCachePostgres nodes. Stored credentials and whole configuration files never leave the inspected host.'
    'v7 default-path EDB existence is candidate evidence only. No online ESE consistency claim is made. v8 repositories may still use JET/ESE data; PostgreSQL cache checks do not validate those repositories.'
    'SQL metadata uses fixed SELECT statements with encrypted, certificate-validated connections. PostgreSQL requires a compatible psql (CSV support), SSPI or a pre-secured libpq password file, and TLS trust/hostname validation. Veeam service credentials are never reused.'
    'Engine queries are optional, bounded by connection/statement timeouts, and read only. Deadlock/checksum counters are cumulative since reset; blank checksum counts may mean checksums are disabled. These are not full integrity, restore, or application consistency tests.'
)

} finally {Close-OwnedVeeamConnection}