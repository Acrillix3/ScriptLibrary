<#
What it does:
  Packages local device, disk, network, and recent event details for a support ticket.

Available flags:
  -Hours: Event look-back window, 1-168 hours; default 24.
  -MaxEventsPerLog: Event limit per log, 1-2000; default 200.
  -LogName: Application and/or System logs; default both.
  -NetworkTarget: Optional 1-8 hostnames or IP addresses for DNS and ICMP checks.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Reads local CIM and event metadata into CSV and JSON files with a collection-status manifest; it
  requires access to CIM and the selected logs. Optional DNS checks need Resolve-DnsName; ICMP
  failure does not establish an outage, and collected event metadata excludes message text.
#>
#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateRange(1,168)][int]$Hours = 24,
    [ValidateRange(1,2000)][int]$MaxEventsPerLog = 200,
    [ValidateSet('Application','System')][string[]]$LogName = @('Application','System'),
    [ValidateCount(1,8)][string[]]$NetworkTarget,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$reportDirectory = Join-Path $OutputDirectory ('15-SupportEvidence_{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $reportDirectory -Force -ErrorAction Stop
$manifest = New-Object 'System.Collections.Generic.List[object]'
function Export-EvidenceSection {
    param([string]$Name,[object[]]$Rows,[string[]]$Columns,[string]$Status='Success',[string]$ErrorMessage='')
    $data = @($Rows)
    if ($data.Count -eq 0 -and $Status -eq 'Success') { $Status = 'NoData' }
    $csvPath = Join-Path $reportDirectory ($Name+'.csv')
    if ($data.Count -gt 0) { $data | Select-Object -Property $Columns | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 }
    else { (($Columns | ForEach-Object { '"'+$_+'"' }) -join ',') | Set-Content -LiteralPath $csvPath -Encoding UTF8 }
    ConvertTo-Json -InputObject $data -Depth 6 | Set-Content -LiteralPath (Join-Path $reportDirectory ($Name+'.json')) -Encoding UTF8
    $manifest.Add([pscustomobject]@{Section=$Name;Status=$Status;RecordCount=$data.Count;CsvFile=($Name+'.csv');JsonFile=($Name+'.json');Error=$ErrorMessage})
    if ($ErrorMessage) { Write-Warning ('{0}: {1}' -f $Name,$ErrorMessage) }
}
$definitions = @(
    @{Name='device';Class='Win32_ComputerSystem';Required=$true;Columns=@('Name','Manufacturer','Model','TotalPhysicalMemory','PartOfDomain','Domain')},
    @{Name='operating-system';Class='Win32_OperatingSystem';Required=$true;Columns=@('Caption','Version','BuildNumber','OSArchitecture','LastBootUpTime','InstallDate')},
    @{Name='bios';Class='Win32_BIOS';Required=$true;Columns=@('Manufacturer','SMBIOSBIOSVersion','SerialNumber','ReleaseDate')},
    @{Name='disks';Class='Win32_LogicalDisk';Filter='DriveType=3';Columns=@('DeviceID','VolumeName','FileSystem','Size','FreeSpace')},
    @{Name='network';Class='Win32_NetworkAdapterConfiguration';Filter='IPEnabled=True';Columns=@('Description','MACAddress','IPAddress','IPSubnet','DefaultIPGateway','DNSServerSearchOrder','DHCPEnabled')}
)
foreach ($definition in $definitions) {
    try {
        $arguments = @{ClassName=$definition.Class;ErrorAction='Stop'}
        if ($definition.ContainsKey('Filter')) { $arguments.Filter = $definition.Filter }
        $data = @(Get-CimInstance @arguments | Select-Object -Property $definition.Columns)
        if ($definition.ContainsKey('Required') -and $definition.Required -and $data.Count -eq 0) { throw ('Required CIM class returned no objects: '+$definition.Class) }
        # CSV cannot directly display address arrays; preserve readable values in both formats.
        if ($definition.Name -eq 'network') {
            foreach ($adapter in $data) { foreach ($column in @('IPAddress','IPSubnet','DefaultIPGateway','DNSServerSearchOrder')) { $adapter.$column = @($adapter.$column) -join '; ' } }
        }
        Export-EvidenceSection -Name $definition.Name -Rows $data -Columns $definition.Columns
    } catch { Export-EvidenceSection -Name $definition.Name -Rows @() -Columns $definition.Columns -Status 'Failed' -ErrorMessage $_.Exception.Message }
}
$startTime = (Get-Date).AddHours(-$Hours)
foreach ($log in ($LogName | Select-Object -Unique)) {
    $columns = @('TimeCreated','Id','LevelDisplayName','ProviderName','LogName','MachineName','RecordId')
    try {
        $events = @(Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=$startTime;Level=@(1,2,3)} -MaxEvents $MaxEventsPerLog -ErrorAction Stop | Select-Object -Property $columns)
        Export-EvidenceSection -Name ('events-'+$log) -Rows $events -Columns $columns
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { Export-EvidenceSection -Name ('events-'+$log) -Rows @() -Columns $columns -Status 'NoData' }
        else { Export-EvidenceSection -Name ('events-'+$log) -Rows @() -Columns $columns -Status 'Failed' -ErrorMessage $_.Exception.Message }
    }
}
if ($NetworkTarget) {
    $targetRows = New-Object 'System.Collections.Generic.List[object]'; $targetErrors = New-Object 'System.Collections.Generic.List[string]'
    foreach ($target in ($NetworkTarget | Select-Object -Unique)) {
        $dnsStatus = 'Failed'; $addresses = ''; $pingStatus = 'Unknown'; $detail = New-Object 'System.Collections.Generic.List[string]'
        try {
            $literalAddress = $null
            if ([Net.IPAddress]::TryParse($target,[ref]$literalAddress)) {
                $addresses = $literalAddress.ToString(); $dnsStatus = 'NotApplicableLiteralIP'
            } else {
                $records = @(Resolve-DnsName -Name $target -Type A_AAAA -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
                $addressAnswers = @($records | Where-Object { [string]$_.Section -eq 'Answer' -and [string]$_.Type -in @('A','AAAA','1','28') -and $_.IPAddress })
                $addresses = ($addressAnswers | Select-Object -ExpandProperty IPAddress -Unique) -join '; '
                $dnsStatus = 'Resolved'
                if ($addressAnswers.Count -eq 0) {
                    $dnsStatus = 'NoAddressAnswer'; $detail.Add('No answer-section A/AAAA addresses were returned.'); $targetErrors.Add('DNS '+$target+': no answer-section A/AAAA addresses.')
                }
            }
        } catch { $detail.Add('DNS: '+$_.Exception.Message); $targetErrors.Add('DNS '+$target+': '+$_.Exception.Message) }
        try {
            $replied = Test-Connection -ComputerName $target -Count 2 -Quiet -ErrorAction Stop
            $pingStatus = 'NoReply'; if ($replied) { $pingStatus = 'ReplyReceived' }
        } catch { $detail.Add('ICMP: '+$_.Exception.Message); $targetErrors.Add('ICMP '+$target+': '+$_.Exception.Message) }
        $targetRows.Add([pscustomobject]@{Target=$target;DNSStatus=$dnsStatus;Addresses=$addresses;ICMPStatus=$pingStatus;Detail=($detail -join '; ')})
    }
    $targetStatus = 'Success'; if ($targetErrors.Count -gt 0) { $targetStatus = 'Partial' }
    Export-EvidenceSection -Name 'target-tests' -Rows $targetRows.ToArray() -Columns @('Target','DNSStatus','Addresses','ICMPStatus','Detail') -Status $targetStatus -ErrorMessage ($targetErrors -join '; ')
} else { $manifest.Add([pscustomobject]@{Section='target-tests';Status='NotRequested';RecordCount=0;CsvFile=$null;JsonFile=$null;Error=''}) }
$failed = @($manifest | Where-Object Status -in @('Failed','Partial')).Count
$status = 'Success'
if ($failed -gt 0) { $status = 'Partial'; if (@($manifest | Where-Object Status -in @('Success','NoData')).Count -eq 0) { $status = 'Failed' } }
$summary = [pscustomobject]@{ReportDirectory=$reportDirectory;Status=$status;SectionCount=$manifest.Count;FailedOrPartialSections=$failed;EventWindowHours=$Hours;MaxEventsPerLog=$MaxEventsPerLog;EventWindowStart=$startTime.ToString('o');CollectedAt=(Get-Date).ToString('o')}
[pscustomobject]@{Summary=$summary;Sections=@($manifest.ToArray())} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $reportDirectory 'manifest.json') -Encoding UTF8
'Evidence scope: selected device/OS/BIOS/local-disk/IP fields; bounded Critical/Error/Warning metadata from Application/System. No event message text or XML, complete environment dump, command lines, credentials, Wi-Fi passwords, or encryption keys. Empty event data means no matches were returned within the requested window; MaxEvents limits can omit additional matches. A successful collection reports observations, not device health. Optional DNS/ICMP results do not establish application reachability. Partial/Failed sections must be reviewed in manifest.json. Reports include internal names, addresses, serial numbers and identifiers; review before attaching to a ticket.' | Set-Content -LiteralPath (Join-Path $reportDirectory 'notes.txt') -Encoding UTF8
$summary

