<#
What it does:
  Runs Host, connectivity and explicitly gated integrity/validator mocks without contacting Veeam, Windows hosts, or databases.

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
if(-not $SourceRoot){
    $candidateRoot=Join-Path (Split-Path $PSScriptRoot -Parent) 'staged\Windows'
    $SourceRoot=if(Test-Path -LiteralPath $candidateRoot){$candidateRoot}else{Split-Path $PSScriptRoot -Parent}
}
if(-not $ReportRoot){$ReportRoot=Join-Path $PSScriptRoot ('diagnostics-results-'+[guid]::NewGuid().ToString('N').Substring(0,8))}
$null=New-Item -ItemType Directory -Path $ReportRoot -Force
$global:DiagScenario='Success';$global:DiagProduct='VBR';$global:DiagMajor=12;$global:DiagMarker='MOCK-PRIVATE-DIAGNOSTIC-SECRET-123456'
$global:DiagConnects=0;$global:DiagDisconnects=0;$global:DiagHostReads=0;$global:DiagProbes=0;$global:DiagIntegrityCalls=0;$global:DiagValidatorCalls=0;$global:DiagLastProbe=$null;$global:DiagLastValidator=$null
$checks=New-Object 'System.Collections.Generic.List[object]'
function Assert-Diagnostic {
    param([bool]$Condition,[string]$Message)
    if(-not $Condition){throw ('FAILED: '+$Message)}
    $checks.Add([pscustomobject]@{Check=$Message;Result='Passed'})
}
function Import-Module {
    [CmdletBinding()]param([string]$Name,[switch]$PassThru)
    if($Name -notin 'Veeam.Backup.PowerShell','Veeam.Archiver.PowerShell'){throw 'Unexpected module import blocked'}
    [pscustomobject]@{Name=$Name;Version=[version]($global:DiagMajor.ToString()+'.0.0.0')}
}
function Get-VBOVersion {[CmdletBinding()]param() [pscustomobject]@{ProductVersion=($global:DiagMajor.ToString()+'.0.0.1000')}}
function Get-VBRBackupServerInfo {[CmdletBinding()]param() [pscustomobject]@{Build='12.3.0.2000'}}
function Connect-VBRServer {[CmdletBinding()]param([string]$Server,[int]$Port,[PSCredential]$Credential) $global:DiagConnects++}
function Connect-VBOServer {[CmdletBinding()]param([string]$Server,[int]$Port,[PSCredential]$Credential) $global:DiagConnects++}
function Disconnect-VBRServer {[CmdletBinding()]param() $global:DiagDisconnects++}
function Disconnect-VBOServer {[CmdletBinding()]param() $global:DiagDisconnects++}
function Get-Command {
    [CmdletBinding()]param([Parameter(Position=0)][string]$Name)
    if($Name -eq 'Get-VBRBackupServerInfo'){return [pscustomobject]@{Name=$Name;Parameters=@{}}}
    if($Name -eq 'Test-VBORepository'){
        if($global:DiagScenario -eq 'IntegrityUnsupported'){return}
        $parameters=@{Repository=$null;ErrorAction=$null}
        if($global:DiagScenario -ne 'ParallelismUnsupported'){$parameters.MaxDegreeOfExecutionParallelism=$null}
        return [pscustomobject]@{Name=$Name;Parameters=$parameters}
    }
    return
}
function Get-CimInstance {
    [CmdletBinding()]param([Parameter(Position=0)][string]$ClassName,[string]$Filter)
    switch($ClassName){
        'Win32_OperatingSystem' {
            if($global:DiagScenario -eq 'HostOsDenied'){throw $global:DiagMarker}
            [pscustomobject]@{Caption='Mock Windows Server';Version='10.0.26100';LastBootUpTime=(Get-Date).AddDays(-2);FreePhysicalMemory=1024;TotalVisibleMemorySize=8192;CommandLine=$global:DiagMarker}
        }
        'Win32_Service' {
            if($global:DiagScenario -eq 'HostServicesDenied'){throw $global:DiagMarker}
            if($global:DiagScenario -eq 'HostNoServices'){return}
            $name=if($global:DiagProduct -eq 'VBO'){'Veeam.Archiver.Service'}else{'VeeamBackupSvc'}
            [pscustomobject]@{Name=$name;DisplayName='Mock Veeam service';State=$(if($global:DiagScenario -eq 'HostStoppedService'){'Stopped'}else{'Running'});StartMode='Auto';ExitCode=0;ProcessId=100;StartName=$global:DiagMarker;PathName=$global:DiagMarker}
        }
        'Win32_LogicalDisk' {
            if($global:DiagScenario -eq 'HostDiskDenied'){throw $global:DiagMarker}
            [pscustomobject]@{DeviceID='D:';Size=100GB;FreeSpace=$(if($global:DiagScenario -eq 'HostUnknownFreeSpace'){$null}elseif($global:DiagScenario -eq 'HostLowDisk'){1GB}else{50GB})}
        }
        default {throw ('Unexpected live CIM request blocked: '+$ClassName)}
    }
}
function Get-WinEvent {
    [CmdletBinding()]param([hashtable]$FilterHashtable)
    if($global:DiagScenario -eq 'HostEventsDenied'){throw $global:DiagMarker}
    if($global:DiagScenario -eq 'HostEventsCapped'){
        foreach($number in 1,2,3){[pscustomobject]@{TimeCreated=(Get-Date).AddMinutes(-$number);ProviderName='Veeam Backup';Id=100+$number;LevelDisplayName='Error';RecordId=$number;Message=$global:DiagMarker;ToXml=$global:DiagMarker}}
        return
    }
    $record=[System.Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('Mock no matching events'),'NoMatchingEventsFound',[System.Management.Automation.ErrorCategory]::ObjectNotFound,$null)
    throw $record
}
function Get-VBORepository {
    [CmdletBinding()]param([string]$Name)
    if($global:DiagScenario -eq 'RepositoryDenied'){throw $global:DiagMarker}
    if($global:DiagScenario -eq 'RepositoryMissing'){return}
    [pscustomobject]@{Name=$Name;Id='repo-1';IsObjectStorage=$true;IsLongTerm=$false;Credential=$global:DiagMarker}
    if($global:DiagScenario -eq 'RepositoryAmbiguous'){[pscustomobject]@{Name=$Name;Id='repo-2'}}
}
function Test-VBORepository {
    [CmdletBinding()]param([object]$Repository,[int]$MaxDegreeOfExecutionParallelism)
    $global:DiagIntegrityCalls++
    if($global:DiagScenario -eq 'IntegrityFailure'){throw $global:DiagMarker}
    if($global:DiagScenario -eq 'IntegrityInconsistent'){[pscustomobject]@{User=$global:DiagMarker;Reason=$global:DiagMarker};[pscustomobject]@{Site=$global:DiagMarker;Reason=$global:DiagMarker}}
}
function Invoke-Command {
    [CmdletBinding()]param([string]$ComputerName,[scriptblock]$ScriptBlock,[object[]]$ArgumentList,[PSCredential]$Credential)
    $firstParameter=$ScriptBlock.Ast.ParamBlock.Parameters[0].Name.VariablePath.UserPath
    switch($firstParameter){
        'RequestedService' {[pscustomobject]@{ProductVersion=($global:DiagMajor.ToString()+'.0.0.2000')}}
        'RequestedProduct' {
            $global:DiagHostReads++
            if($global:DiagScenario -eq 'HostRemoteDenied'){throw $global:DiagMarker}
            foreach($row in @(& $ScriptBlock @ArgumentList)){
                if($row.Kind -eq 'Host'){$row.Computer=$ComputerName}
                $row | Add-Member -NotePropertyName PrivatePayload -NotePropertyValue $global:DiagMarker -Force
                $row
            }
        }
        'HostName' {
            $global:DiagProbes++;$global:DiagLastProbe=[pscustomobject]@{Computer=$ComputerName;Arguments=$ArgumentList}
            if($global:DiagScenario -eq 'ProbeDenied'){throw $global:DiagMarker}
            if($global:DiagScenario -eq 'ProbeEmpty'){return}
            if($global:DiagScenario -eq 'ProbeMalformed'){return [pscustomobject]@{Address=[pscustomobject]@{Secret=$global:DiagMarker};Connected=$null;ElapsedMilliseconds=[pscustomobject]@{Secret=$global:DiagMarker}}}
            [pscustomobject]@{Address=$(if($ArgumentList[0] -like '*:*'){'2001:db8::20'}else{'192.0.2.44'});Connected=($global:DiagScenario -ne 'ProbeRefused');ElapsedMilliseconds=5;PrivatePayload=$global:DiagMarker}
        }
        'SelectedBackup' {
            $global:DiagValidatorCalls++;$global:DiagLastValidator=[pscustomobject]@{Computer=$ComputerName;Arguments=$ArgumentList;Code=$ScriptBlock.ToString()}
            if($global:DiagScenario -eq 'ValidatorDenied'){throw $global:DiagMarker}
            [pscustomobject]@{ExecutionComputer=$ComputerName;Completed=($global:DiagScenario -ne 'ValidatorTimeout');ExitCode=$(if($global:DiagScenario -eq 'ValidatorTimeout'){$null}elseif($global:DiagScenario -eq 'ValidatorNonzero'){7}else{0});NativeReportPath='C:\MockNativeReports\validator.html';NativeReportExists=($global:DiagScenario -ne 'ValidatorNoReport');PrivatePayload=$global:DiagMarker}
        }
        default {throw ('Unexpected remote request blocked: '+$firstParameter)}
    }
}
function New-Object {
    [CmdletBinding()]param([Parameter(Position=0)][string]$TypeName,[Parameter(Position=1)][object[]]$ArgumentList)
    if($TypeName -match 'TcpClient|Diagnostics\.Process'){throw 'A real network/process constructor was blocked by this mock suite'}
    $forward=@{TypeName=$TypeName};if($PSBoundParameters.ContainsKey('ArgumentList')){$forward.ArgumentList=$ArgumentList}
    Microsoft.PowerShell.Utility\New-Object @forward
}
$scriptNames=@('Get-VBRHostDiagnostics.ps1','Get-VBOHostDiagnostics.ps1','Test-VBRConnectivity.ps1','Test-VBOConnectivity.ps1','Test-VBORepositoryIntegrity.ps1','Test-VBRBackupValidation.ps1')
$scriptPaths=@{}
foreach($name in $scriptNames){
    # Resolve the production category directly so retained Reports fixtures do not look like duplicate tools.
    $category=if($name -match '-VBO'){'Veeam-Microsoft-365'}else{'Veeam-Backup-and-Replication-v12'}
    $matches=@(Microsoft.PowerShell.Management\Get-Item -LiteralPath (Join-Path (Join-Path $SourceRoot $category) $name) -ErrorAction Stop)
    if($matches.Count -ne 1){throw ('SourceRoot must contain exactly one '+$name)}
    $scriptPaths[$name]=$matches[0].FullName
    $tokens=$null;$errors=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile($matches[0].FullName,[ref]$tokens,[ref]$errors)
    Assert-Diagnostic ($errors.Count -eq 0) ($name+' parses')
    $header=[regex]::Match((Get-Content -LiteralPath $matches[0].FullName -Raw),'(?s)^<#(.*?)#>').Groups[1].Value
    $sections=@([regex]::Matches($header,'(?m)^(What it does|Available flags|How it works):') | ForEach-Object {$_.Groups[1].Value})
    Assert-Diagnostic (($sections -join '|') -eq 'What it does|Available flags|How it works') ($name+' has three opening sections')
    $actual=@($ast.ParamBlock.Parameters | ForEach-Object {$_.Name.VariablePath.UserPath});$documented=@([regex]::Matches($header,'(?m)^\s+-(\w+)') | ForEach-Object {$_.Groups[1].Value} | Where-Object {$_ -notin 'WhatIf','Confirm'})
    Assert-Diagnostic (@(Compare-Object $actual $documented).Count -eq 0) ($name+' documents all actual parameters')
}
function Invoke-DiagnosticCase {
    param([string]$Name,[string]$Scenario='Success',[hashtable]$Arguments=@{},[int]$VboMajor=8)
    $global:DiagScenario=$Scenario;$global:DiagProduct=if($Name -match '-VBO'){'VBO'}else{'VBR'};$global:DiagMajor=if($global:DiagProduct -eq 'VBO'){$VboMajor}else{12}
    $global:DiagConnects=0;$global:DiagDisconnects=0;$global:DiagHostReads=0;$global:DiagProbes=0;$global:DiagIntegrityCalls=0;$global:DiagValidatorCalls=0
    $target=if($global:DiagProduct -eq 'VBO'){'vbo.mock.test'}else{'vbr.mock.test'}
    & $scriptPaths[$Name] -Server $target -OutputDirectory (Join-Path $ReportRoot ('d-'+[guid]::NewGuid().ToString('N').Substring(0,8))) @Arguments -WarningAction SilentlyContinue
}
foreach($name in $scriptNames[0..1]){
    $result=Invoke-DiagnosticCase $name
    $hostRows=@(Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'host.csv'))
    Assert-Diagnostic ($global:DiagHostReads -eq 1 -and $hostRows[0].Computer -eq $result.Context.Server) ($name+' collects the requested remote host without workstation substitution')
    Assert-Diagnostic ($result.Data.Services -eq 1 -and $result.Data.LocalDisks -eq 1 -and $result.Data.Events -eq 0) ($name+' distinguishes readable no-event history from failure')
    $combined=(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $result.ReportDirectory -File | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw}) -join [Environment]::NewLine
    Assert-Diagnostic ($combined -notlike ('*'+$global:DiagMarker+'*')) ($name+' excludes event text, command lines, accounts, and extra payloads')
    $result=Invoke-DiagnosticCase $name 'HostServicesDenied'
    $hostRows=@(Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'host.csv'))
    $status=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'collection-status.csv')
    Assert-Diagnostic ($result.State -eq 'Incomplete' -and $hostRows.Count -eq 1 -and $result.Data.LocalDisks -eq 1 -and @($status | Where-Object { $_.Section -eq 'WindowsHost:Services' -and $_.State -eq 'Unknown' }).Count -eq 1) ($name+' preserves OS/disk evidence when service access fails')
    $result=Invoke-DiagnosticCase $name 'HostEventsDenied'
    Assert-Diagnostic ($result.State -eq 'Incomplete' -and $result.Data.Services -eq 1 -and $result.Data.LocalDisks -eq 1) ($name+' preserves other evidence when event access fails')
    $result=Invoke-DiagnosticCase $name 'HostRemoteDenied'
    Assert-Diagnostic ($result.State -eq 'Incomplete' -and $result.Data.Services -eq 0 -and $global:DiagHostReads -eq 1) ($name+' reports unavailable remote evidence without local fallback')
}
$result=Invoke-DiagnosticCase $scriptNames[0] 'HostUnknownFreeSpace'
$diskRows=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'local-disks.csv')
Assert-Diagnostic ($diskRows[0].FreePercent -eq '' -and $result.State -eq 'Incomplete') 'Missing disk free space is Unknown rather than zero percent'
$result=Invoke-DiagnosticCase $scriptNames[1] 'HostEventsCapped' @{MaxEvents=1}
$events=@(Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'event-metadata.csv'))
Assert-Diagnostic ($events.Count -eq 1 -and $result.State -eq 'Review') 'Host event metadata retention is capped and requires review'
foreach($name in $scriptNames[2..3]){
    $result=Invoke-DiagnosticCase $name 'Success' @{ProbeComputerName='probe.mock.test';Endpoint=@('[2001:db8::10]:5432');TimeoutMilliseconds=500}
    $networkRows=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'endpoint-tests.csv')
    Assert-Diagnostic ($global:DiagProbes -eq 2 -and $result.Data.Endpoints -eq 2 -and $result.Data.ConsoleAuthenticationSucceeded) ($name+' records remote TCP probes separately from console authentication')
    Assert-Diagnostic ($global:DiagLastProbe.Computer -eq 'probe.mock.test' -and $global:DiagLastProbe.Arguments[0] -eq '2001:db8::10' -and $global:DiagLastProbe.Arguments[1] -eq 5432 -and $global:DiagLastProbe.Arguments[2] -eq 500) ($name+' forwards source host, IPv6 target, port, and timeout correctly')
    Assert-Diagnostic ($networkRows.Count -eq 2 -and $networkRows[1].ResolvedAddress -eq '2001:db8::20') ($name+' retains only selected probe metadata')
    $result=Invoke-DiagnosticCase $name 'ProbeRefused' @{ProbeComputerName='probe.mock.test'}
    Assert-Diagnostic ($result.State -eq 'Fail') ($name+' records a collected TCP refusal as a finding')
    $result=Invoke-DiagnosticCase $name 'ProbeDenied' @{ProbeComputerName='probe.mock.test'}
    Assert-Diagnostic ($result.State -eq 'Incomplete' -and $result.Data.AddressSamples -eq 0) ($name+' records probe access failure as Unknown')
    $result=Invoke-DiagnosticCase $name 'ProbeMalformed' @{ProbeComputerName='probe.mock.test'}
    $networkRows=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'endpoint-tests.csv')
    Assert-Diagnostic ($result.State -eq 'Incomplete' -and $networkRows[0].TcpConnected -eq '' -and $networkRows[0].ResolvedAddress -eq '') ($name+' never interprets missing/malformed probe evidence as TCP failure')
}
$integrity=$scriptNames[4]
foreach($major in 7,8){
    $result=Invoke-DiagnosticCase $integrity 'Success' @{RepositoryName='MockRepo'} -VboMajor $major
    Assert-Diagnostic (-not $result.Data.Invoked -and $global:DiagIntegrityCalls -eq 0 -and $null -eq $result.Data.InconsistentObjects) ('v'+$major+' integrity defaults to a plan with unknown scan results')
    $result=Invoke-DiagnosticCase $integrity 'Success' @{RepositoryName='MockRepo';RunIntegrityTest=$true;Confirm=$false} -VboMajor $major
    Assert-Diagnostic ($result.Data.Invoked -and $result.Data.Completed -and $result.Data.InconsistentObjects -eq 0 -and $global:DiagIntegrityCalls -eq 1) ('v'+$major+' explicit integrity success counts zero returned inconsistencies')
}
$result=Invoke-DiagnosticCase $integrity 'Success' @{RepositoryName='MockRepo';RunIntegrityTest=$true;WhatIf=$true;Confirm=$false}
Assert-Diagnostic (-not $result.Data.Invoked -and $global:DiagIntegrityCalls -eq 0) 'Integrity WhatIf never invokes the vendor scan'
$result=Invoke-DiagnosticCase $integrity 'IntegrityUnsupported' @{RepositoryName='MockRepo';RunIntegrityTest=$true;Confirm=$false}
Assert-Diagnostic (-not $result.Data.Invoked -and $result.State -eq 'Incomplete') 'Missing vendor integrity capability is an explicit gap'
$result=Invoke-DiagnosticCase $integrity 'ParallelismUnsupported' @{RepositoryName='MockRepo';RunIntegrityTest=$true;Parallelism=4;Confirm=$false}
Assert-Diagnostic (-not $result.Data.Invoked -and $global:DiagIntegrityCalls -eq 0 -and $result.State -eq 'Incomplete') 'Unsupported requested parallelism does not silently run with a different setting'
$result=Invoke-DiagnosticCase $integrity 'RepositoryAmbiguous' @{RepositoryName='MockRepo';RunIntegrityTest=$true;Confirm=$false}
Assert-Diagnostic (-not $result.Data.Invoked -and $global:DiagIntegrityCalls -eq 0) 'Ambiguous repository names never trigger an integrity scan'
$result=Invoke-DiagnosticCase $integrity 'RepositoryMissing' @{RepositoryName='MockRepo';RunIntegrityTest=$true;Confirm=$false}
Assert-Diagnostic (-not $result.Data.Invoked -and $result.State -eq 'Incomplete') 'Missing repository evidence is not a clean integrity result'
$result=Invoke-DiagnosticCase $integrity 'IntegrityInconsistent' @{RepositoryName='MockRepo';RunIntegrityTest=$true;Parallelism=2;Confirm=$false}
Assert-Diagnostic ($result.State -eq 'Fail' -and $result.Data.Completed -and $result.Data.InconsistentObjects -eq 2 -and $result.Data.AppliedParallelism -eq 2) 'Returned inconsistent objects are counted without exporting workload details'
$combined=(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $result.ReportDirectory -File | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw}) -join [Environment]::NewLine
Assert-Diagnostic ($combined -notlike ('*'+$global:DiagMarker+'*')) 'Integrity output excludes inconsistent object payloads'
$result=Invoke-DiagnosticCase $integrity 'IntegrityFailure' @{RepositoryName='MockRepo';RunIntegrityTest=$true;Confirm=$false}
Assert-Diagnostic ($result.Data.Invoked -and -not $result.Data.Completed -and $null -eq $result.Data.InconsistentObjects -and $result.State -eq 'Incomplete') 'Failed vendor integrity execution remains incomplete with unknown count'
$validator=$scriptNames[5]
$result=Invoke-DiagnosticCase $validator 'Success' @{BackupName='Mock backup'}
Assert-Diagnostic (-not $result.Data.Invoked -and $global:DiagValidatorCalls -eq 0) 'Backup validation defaults to plan only'
$result=Invoke-DiagnosticCase $validator 'Success' @{BackupName='Mock backup';RunValidation=$true;WhatIf=$true;Confirm=$false}
Assert-Diagnostic (-not $result.Data.Invoked -and $global:DiagValidatorCalls -eq 0) 'Validator WhatIf never dispatches native execution'
$result=Invoke-DiagnosticCase $validator 'Success' @{BackupName='Mock backup';RunValidation=$true;ValidatorPath='C:\Veeam\Veeam.Backup.Validator.exe';ServerReportDirectory='C:\MockNativeReports';TimeoutMinutes=15;Confirm=$false}
$nativeRows=Import-Csv -LiteralPath (Join-Path $result.ReportDirectory 'backup-validator.csv')
Assert-Diagnostic ($result.Data.Invoked -and $global:DiagValidatorCalls -eq 1 -and $global:DiagLastValidator.Computer -eq 'vbr.mock.test') 'Explicit validator execution is dispatched to the requested backup server'
Assert-Diagnostic ($global:DiagLastValidator.Arguments[0] -eq 'Mock backup' -and $global:DiagLastValidator.Arguments[1] -eq 'C:\Veeam\Veeam.Backup.Validator.exe' -and $global:DiagLastValidator.Arguments[2] -eq 'C:\MockNativeReports' -and $global:DiagLastValidator.Arguments[3] -eq 15) 'Validator forwards only declared operation inputs'
Assert-Diagnostic ($nativeRows[0].ExecutionComputer -eq 'vbr.mock.test' -and $nativeRows[0].ExitCode -eq '0' -and $nativeRows[0].NativeReportExists -eq 'True' -and $result.State -eq 'Review') 'Validator exit/report metadata requires native result review rather than fabricating a CRC pass'
Assert-Diagnostic ($global:DiagLastValidator.Code -match 'Veeam\.Backup\.Validator\.exe' -and $global:DiagLastValidator.Code -match 'ProductVersion -notmatch') 'Remote validator block restricts the expected executable and major version'
$result=Invoke-DiagnosticCase $validator 'ValidatorTimeout' @{BackupName='Mock backup';RunValidation=$true;Confirm=$false}
Assert-Diagnostic ($result.State -eq 'Incomplete') 'Incomplete timed-out validator metadata never becomes successful validation'
$result=Invoke-DiagnosticCase $validator 'ValidatorDenied' @{BackupName='Mock backup';RunValidation=$true;Confirm=$false}
Assert-Diagnostic ($result.State -eq 'Incomplete' -and $global:DiagDisconnects -eq 1) 'Remote validator failure is redacted and the owned console session closes'
$failedAsExpected=$false
try{$null=Invoke-DiagnosticCase $validator 'Success' @{BackupName='bad"name';RunValidation=$true;Confirm=$false}}catch{$failedAsExpected=$true}
Assert-Diagnostic ($failedAsExpected -and $global:DiagValidatorCalls -eq 0 -and $global:DiagDisconnects -eq 1) 'Invalid validator backup-name quoting is rejected before dispatch and still closes the owned session'
$checks | Export-Csv -LiteralPath (Join-Path $ReportRoot 'test-results.csv') -NoTypeInformation -Encoding UTF8
[pscustomobject]@{Passed=$checks.Count;Failed=0;PowerShellVersion=$PSVersionTable.PSVersion.ToString();SourceRoot=[IO.Path]::GetFullPath($SourceRoot);ResultsDirectory=[IO.Path]::GetFullPath($ReportRoot);Scope='Mocked Veeam imports/connections, host queries, remote probes, integrity scan, and validator dispatch; no actual network connection, Veeam operation, or process execution.'}
