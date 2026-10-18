<#
What it does:
  Reports common Windows indicators that a restart or naming/domain change is pending.

Available flags:
  -IncludeConfigMgr: Also query the Configuration Manager client SDK when installed.
  -OutputDirectory: Report destination; default Windows\Reports.

How it works:
  Reads servicing, update, file-rename, computer-name, and domain-join indicators; optional
  ConfigMgr reads use its local CIM provider. Reports evidence and unknown checks without
  restarting. No checked indicator does not prove that every application is ready or no restart is
  required. Use 64-bit Windows PowerShell.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
[switch]$IncludeConfigMgr,
[ValidateNotNullOrEmpty()][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) {
    $OutputDirectory = Join-Path $PSScriptRoot '..\Reports'
}
$scriptLabel = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runName = '{0}-{1}-{2}' -f $scriptLabel,[datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),[guid]::NewGuid().ToString('N').Substring(0,8)
$reportDirectory = (New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName) -Force -ErrorAction Stop).FullName
$queryLog = New-Object 'System.Collections.Generic.List[object]'
$queryErrors = New-Object 'System.Collections.Generic.List[object]'
function Invoke-ReportQuery {
    param([string]$Section,[scriptblock]$Action,[switch]$RequireData)
    try {
        $items = @(& $Action)
        if ($RequireData -and $items.Count -eq 0) { throw 'Required data was not returned.' }
        $queryLog.Add([pscustomobject]@{Section=$Section;Status=$(if($items.Count){'Collected'}else{'Empty'});Count=$items.Count;Error=''})
        [pscustomobject]@{Succeeded=$true;Data=$items}
    } catch {
        $queryErrors.Add([pscustomobject]@{Section=$Section;Error=$_.Exception.Message;ErrorId=$_.FullyQualifiedErrorId})
        $queryLog.Add([pscustomobject]@{Section=$Section;Status='Unknown';Count=$null;Error=$_.Exception.Message})
        [pscustomobject]@{Succeeded=$false;Data=@()}
    }
}
function Write-ReportCsv {
    param([string]$Name,[object[]]$Rows,[string[]]$Columns)
    $path=Join-Path $reportDirectory ($Name+'.csv')
    if (@($Rows).Count) {
        $Rows | Select-Object -Property $Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    } else {
        (($Columns | ForEach-Object { '"'+$_.Replace('"','""')+'"' }) -join ',') | Set-Content -LiteralPath $path -Encoding UTF8
    }
}
function Complete-Report {
    param([object]$Data,[string[]]$Notes)
    Write-ReportCsv -Name 'collection-status' -Rows $queryLog.ToArray() -Columns @('Section','Status','Count','Error')
    Write-ReportCsv -Name 'query-errors' -Rows $queryErrors.ToArray() -Columns @('Section','Error','ErrorId')
    $status='Complete'
    if($queryErrors.Count){$status='Partial'}
    if($queryErrors.Count -and @($queryLog | Where-Object Status -ne 'Unknown').Count -eq 0){$status='Unavailable'}
    $summary=[pscustomobject]@{
        Script=$scriptLabel;ComputerName=$env:COMPUTERNAME;CollectedUtc=[datetime]::UtcNow.ToString('o')
        CollectionStatus=$status;QueryErrorCount=$queryErrors.Count;ReportDirectory=$reportDirectory
        Data=$Data;Sections=$queryLog.ToArray();Notes=@('Collection status describes available evidence, not overall system health.')+$Notes
    }
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $reportDirectory 'summary.json') -Encoding UTF8
    @(
        $scriptLabel
        ('Collection: {0}; query errors: {1}' -f $status,$queryErrors.Count)
        ('Reports: '+$reportDirectory)
        ''
        'Collection results:'
        ($queryLog | Format-Table Section,Status,Count -AutoSize | Out-String -Width 180)
        'Interpretation:'
        ($summary.Notes -join [Environment]::NewLine)
    ) | Set-Content -LiteralPath (Join-Path $reportDirectory 'overview.txt') -Encoding UTF8
    if($queryErrors.Count){Write-Warning 'Some data was unavailable; review query-errors.csv and collection-status.csv.'}
    $summary
}

$indicators=New-Object 'System.Collections.Generic.List[object]'
function Read-RestartRegistryKey {
    param([string]$Path)
    if([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell for native registry indicators.'}
    try{Get-Item -LiteralPath $Path -ErrorAction Stop}
    catch{if($_.CategoryInfo.Category -ne 'ObjectNotFound'){throw}}
}
foreach($definition in @(
    @{Name='Component servicing reboot pending';Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'},
    @{Name='Component servicing reboot in progress';Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress'},
    @{Name='Windows Update reboot required';Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'}
)){
    $result=Invoke-ReportQuery -Section $definition.Name -Action {
        $key=Read-RestartRegistryKey $definition.Path
        [pscustomobject]@{Indicator=$definition.Name;Status='Checked';Indicated=($null -ne $key);Evidence=$(if($key){'Registry key exists'}else{'Registry key absent'})}
    }
    if($result.Succeeded){foreach($row in $result.Data){$indicators.Add($row)}}
    else{$indicators.Add([pscustomobject]@{Indicator=$definition.Name;Status='Unknown';Indicated=$null;Evidence='See query-errors.csv'})}
}
$renames=Invoke-ReportQuery -Section 'Pending file rename operations' -Action {
    $key=Read-RestartRegistryKey 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    if($null -eq $key){throw 'Required Session Manager registry key was not readable.'}
    $values=Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
    $count=0
    foreach($name in @('PendingFileRenameOperations','PendingFileRenameOperations2')){
        if($values.PSObject.Properties[$name]){$count+=@($values.$name | Where-Object {$_}).Count}
    }
    [pscustomobject]@{Indicator='Pending file rename operations';Status='Checked';Indicated=($count -gt 0);Evidence=("$count nonempty entries; paths intentionally excluded")}
}
if($renames.Succeeded){foreach($row in $renames.Data){$indicators.Add($row)}}
else{$indicators.Add([pscustomobject]@{Indicator='Pending file rename operations';Status='Unknown';Indicated=$null;Evidence='See query-errors.csv'})}
$names=Invoke-ReportQuery -Section 'Computer rename pending' -Action {
    $activeKey=Read-RestartRegistryKey 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName'
    $configuredKey=Read-RestartRegistryKey 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'
    if(-not $activeKey -or -not $configuredKey){throw 'Computer-name registry keys were not available.'}
    $active=(Get-ItemProperty -LiteralPath $activeKey.PSPath -ErrorAction Stop).ComputerName
    $configured=(Get-ItemProperty -LiteralPath $configuredKey.PSPath -ErrorAction Stop).ComputerName
    if(-not $active -or -not $configured){throw 'Required computer-name values were not available.'}
    [pscustomobject]@{Indicator='Computer rename pending';Status='Checked';Indicated=($active -ne $configured);Evidence=("Active=$active; configured=$configured")}
}
if($names.Succeeded){foreach($row in $names.Data){$indicators.Add($row)}}
else{$indicators.Add([pscustomobject]@{Indicator='Computer rename pending';Status='Unknown';Indicated=$null;Evidence='See query-errors.csv'})}
$join=Invoke-ReportQuery -Section 'Netlogon join indicators' -Action {
    $key=Read-RestartRegistryKey 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon'
    if(-not $key){throw 'Netlogon registry key was not available.'}
    $values=Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
    $present=@('JoinDomain','AvoidSpnSet' | Where-Object {$null -ne $values.PSObject.Properties[$_]})
    [pscustomobject]@{Indicator='Netlogon join indicators';Status='Checked';Indicated=($present.Count -gt 0);Evidence=$(if($present.Count){$present -join '; '}else{'Checked values absent'})}
}
if($join.Succeeded){foreach($row in $join.Data){$indicators.Add($row)}}
else{$indicators.Add([pscustomobject]@{Indicator='Netlogon join indicators';Status='Unknown';Indicated=$null;Evidence='See query-errors.csv'})}
if($IncludeConfigMgr){
    $client=Invoke-ReportQuery -Section 'Configuration Manager restart state' -Action {
        $value=Invoke-CimMethod -Namespace 'root\ccm\ClientSDK' -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Stop
        if($null -eq $value -or $null -eq $value.ReturnValue -or $value.ReturnValue -ne 0){throw 'Configuration Manager method did not return a successful result.'}
        if($null -eq $value.RebootPending -or $null -eq $value.IsHardRebootPending){throw 'Configuration Manager returned no usable pending status.'}
        [pscustomobject]@{Indicator='Configuration Manager restart state';Status='Checked';Indicated=($value.RebootPending -or $value.IsHardRebootPending);Evidence=("RebootPending=$($value.RebootPending); HardRebootPending=$($value.IsHardRebootPending)")}
    }
    if($client.Succeeded){foreach($row in $client.Data){$indicators.Add($row)}}
    else{$indicators.Add([pscustomobject]@{Indicator='Configuration Manager restart state';Status='Unknown';Indicated=$null;Evidence='See query-errors.csv'})}
}else{$queryLog.Add([pscustomobject]@{Section='Configuration Manager restart state';Status='NotRequested';Count=0;Error=''})}
Write-ReportCsv 'restart-indicators' $indicators.ToArray() @('Indicator','Status','Indicated','Evidence')
$positive=@($indicators | Where-Object {$_.Indicated -eq $true}).Count
$unknown=@($indicators | Where-Object Status -eq 'Unknown').Count
$assessment=if($positive){'RestartIndicated'}elseif($unknown){'Unknown'}else{'NoCheckedIndicatorFound'}
Complete-Report -Data ([ordered]@{Assessment=$assessment;PositiveIndicators=$positive;UnknownIndicators=$unknown;ConfigMgrRequested=[bool]$IncludeConfigMgr}) -Notes @(
    'This is a set of common indicators, not an exhaustive Windows/application restart requirement API.'
    'Pending file operations can be stale or application-specific. Review evidence before deciding on a restart.'
    'A negative result does not establish that restarting is unnecessary or safe; no restart is initiated.'
)
