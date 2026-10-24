<#
What it does:
  Audits local PHP binaries against CVE-2026-109618 and CVE-2026-109619 fixed versions.

Available flags:
  -PhpPath <files>: Explicit PHP executable/module files. -SearchRoot <folders>: Additional search roots.
  -ApacheConfigPath / -PhpIniPath <files>: Optional selected configuration files to inspect.
  -MaxDepth (4), -MaxEntries (25000): Bound discovery. -OutputDirectory: Default Windows\Reports.

How it works:
  Reads file versions, PATH, running PHP image paths, and IIS handler mappings without executing PHP
  or sending exploit traffic. Compares upstream branches to the 2026-10-21 advisory; vendor backports,
  embedded runtimes, live worker replacement, and undiscovered installations require separate evidence.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string[]]$PhpPath=@(),
    [string[]]$SearchRoot=@(),
    [string[]]$ApacheConfigPath=@(),
    [string[]]$PhpIniPath=@(),
    [ValidateRange(0,12)][int]$MaxDepth=4,
    [ValidateRange(100,1000000)][int]$MaxEntries=25000,
    [ValidateNotNullOrEmpty()][string]$OutputDirectory
)

$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'Run this local audit on Windows.'}
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$reportDirectory=(New-Item -ItemType Directory -Path (Join-Path $OutputDirectory ('Test-Php2ShellExposure-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'),[guid]::NewGuid().ToString('N').Substring(0,8))) -Force).FullName
$script:queryRows=New-Object 'System.Collections.Generic.List[object]'
$script:queryErrors=New-Object 'System.Collections.Generic.List[object]'
$script:candidates=@{}
$script:associations=New-Object 'System.Collections.Generic.List[object]'
$script:configurationRows=New-Object 'System.Collections.Generic.List[object]'
$fixedVersions=@{'8.2'=[version]'8.2.35';'8.3'=[version]'8.3.36';'8.4'=[version]'8.4.27';'8.5'=[version]'8.5.12'}
$advisoryUrl='https://www.php.net/archive/2026.php#2026-10-21-5'

function Add-AuditStatus {
    param([string]$Section,[string]$Status,[string]$Detail)
    $script:queryRows.Add([pscustomobject]@{Section=$Section;Status=$Status;Detail=$Detail})
}
function Add-AuditError {
    param([string]$Section,[string]$Message)
    # Exception messages may echo a complete configuration line; keep a bounded category only.
    $script:queryErrors.Add([pscustomobject]@{Section=$Section;ErrorCategory=$Message})
    Add-AuditStatus $Section Unknown $Message
}
function Export-AuditCsv {
    param([string]$Name,[object[]]$Rows,[string[]]$Columns)
    $target=Join-Path $reportDirectory ($Name+'.csv')
    if(@($Rows).Count){$Rows | Select-Object $Columns | Export-Csv -LiteralPath $target -NoTypeInformation -Encoding UTF8}
    else{(($Columns|ForEach-Object{'"'+$_.Replace('"','""')+'"'}) -join ',') | Set-Content -LiteralPath $target -Encoding UTF8}
}
function Get-PhpVersionAssessment {
    param([AllowEmptyString()][string]$VersionText)
    $pattern='(?<!\d)(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:\.\d+)?(?<suffix>(?:[-.]?(?:RC|alpha|beta|dev|snapshot)[\w.-]*)?)(?![\dA-Za-z])'
    $metadataMatches=[regex]::Matches($VersionText,$pattern,[Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if(@($metadataMatches | ForEach-Object { '{0}.{1}.{2}' -f $_.Groups['major'].Value,$_.Groups['minor'].Value,$_.Groups['patch'].Value } | Sort-Object -Unique).Count -gt 1){return [pscustomobject]@{Version=$null;Branch='';FixedVersion='';Assessment='Unknown';Reason='Conflicting version triplets occur in the metadata; obtain the actual runtime build version.'}}
    $match=[regex]::Match($VersionText,$pattern,[Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if(-not $match.Success){return [pscustomobject]@{Version=$null;Branch='';FixedVersion='';Assessment='Unknown';Reason='Readable PHP version metadata was not found.'}}
    try{$version=[version]('{0}.{1}.{2}' -f $match.Groups['major'].Value,$match.Groups['minor'].Value,$match.Groups['patch'].Value)}catch{return [pscustomobject]@{Version=$null;Branch='';FixedVersion='';Assessment='Unknown';Reason='Version metadata could not be parsed.'}}
    $branch='{0}.{1}' -f $version.Major,$version.Minor
    $minimum=$fixedVersions[$branch]
    $assessment='Unknown'; $reason='This branch has no verified upstream rule in this audit. Check the vendor advisory.'
    if($null -ne $minimum){
        if($version -lt $minimum){$assessment='PotentiallyAffected';$reason='Below the published upstream fixed version; vendor backports are not verified by this audit.'}
        elseif($match.Groups['suffix'].Value){$assessment='UnknownPrerelease';$reason='Prerelease/development metadata is not treated as a fixed final build.'}
        else{$assessment='MeetsPublishedFixedVersion';$reason='Version metadata meets the upstream fix for these two CVEs. Verify the actual web runtime/build and replacement of old workers.'}
    }elseif($version -lt [version]'8.2.0' -and $version -ge [version]'5.4.0'){
        $assessment='PotentiallyAffectedLegacy';$reason='Legacy upstream branch: a backported fix requires vendor/build evidence. Source backports do not prove this installed binary is patched.'
    }
    [pscustomobject]@{Version=$version.ToString();Branch=$branch;FixedVersion=$(if($minimum){$minimum.ToString()}else{''});Assessment=$assessment;Reason=$reason}
}
function Test-NoReparseAncestry {
    param([string]$Path)
    try{
        $current=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        while($null -ne $current){
            if(($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){return $false}
            if($current.PSIsContainer){$current=$current.Parent}else{$current=$current.Directory}
        }
        return $true
    }catch{return $false}
}
function Add-PhpCandidate {
    param([string]$Path,[string]$Source,[string]$Association='')
    if([string]::IsNullOrWhiteSpace($Path)){return}
    $expanded=[Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    if(-not [IO.Path]::IsPathRooted($expanded) -or $expanded.StartsWith('\\')){Add-AuditStatus $Source Unknown 'A nonlocal or unresolved binary path was skipped.';return}
    try{
        $file=Get-Item -LiteralPath $expanded -Force -ErrorAction Stop
        if($file.PSIsContainer){Add-AuditStatus $Source Unknown 'A binary path refers to a directory.';return}
        if($file.Name -notmatch '^(php(?:-cgi)?\.exe|php[578](?:ts|apache2_4)?\.dll|lsphp\.exe|frankenphp\.exe)$'){Add-AuditStatus $Source Unknown 'A mapped runtime has no supported PHP binary name; inspect the vendor build separately.';return}
        if(-not (Test-NoReparseAncestry $file.FullName)){Add-AuditStatus $Source Unknown 'A binary path with reparse-point ancestry was skipped.';return}
        $key=$file.FullName.ToLowerInvariant()
        if(-not $script:candidates.ContainsKey($key)){$script:candidates[$key]=[pscustomobject]@{Path=$file.FullName;Name=$file.Name;Sources=(New-Object 'System.Collections.Generic.List[string]')}}
        if(-not $script:candidates[$key].Sources.Contains($Source)){$script:candidates[$key].Sources.Add($Source)}
        if($Association){$script:associations.Add([pscustomobject]@{Kind=$Source;BinaryPath=$file.FullName;Context=$Association})}
    }catch{Add-AuditError $Source 'Binary path unavailable or access denied.'}
}
function Search-PhpDirectory {
    param([string]$Root)
    if(-not (Test-Path -LiteralPath $Root -PathType Container)){return}
    if(-not (Test-NoReparseAncestry $Root)){Add-AuditStatus 'Directory discovery' Unknown 'A root with unreadable or reparse-point ancestry was skipped.';return}
    $stack=New-Object 'System.Collections.Generic.Stack[object]'
    $stack.Push([pscustomobject]@{Path=(Get-Item -LiteralPath $Root).FullName;Depth=0})
    $visited=0
    while($stack.Count -gt 0){
        $node=$stack.Pop()
        try{
            foreach($entry in Get-ChildItem -LiteralPath $node.Path -Force -ErrorAction Stop){
                $visited++
                if($visited -gt $MaxEntries){Add-AuditStatus 'Directory discovery' Unknown 'Search entry limit reached; narrow roots or increase the explicit bound.';return}
                if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){continue}
                if($entry.PSIsContainer){if($node.Depth -lt $MaxDepth){$stack.Push([pscustomobject]@{Path=$entry.FullName;Depth=($node.Depth+1)})}}
                elseif($entry.Name -match '^(php(?:-cgi)?\.exe|php[578](?:ts|apache2_4)?\.dll|lsphp\.exe|frankenphp\.exe)$'){Add-PhpCandidate $entry.FullName 'Directory discovery'}
            }
        }catch{Add-AuditError 'Directory discovery' 'A directory could not be enumerated.'}
    }
    Add-AuditStatus 'Directory discovery' Collected ('Inspected {0} entries in a selected root, with maximum depth {1}.' -f $visited,$MaxDepth)
}
function Read-SafeXmlDocument {
    param([string]$Path)
    $settings=New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver=$null
    $settings.MaxCharactersInDocument=16777216
    $reader=[Xml.XmlReader]::Create($Path,$settings)
    try{$document=New-Object Xml.XmlDocument;$document.XmlResolver=$null;$document.Load($reader);return $document}finally{$reader.Dispose()}
}

foreach($path in $PhpPath){Add-PhpCandidate $path 'Explicit path'}
try{
    foreach($command in @(Get-Command -Name php.exe,php-cgi.exe,lsphp.exe,frankenphp.exe -CommandType Application -All -ErrorAction SilentlyContinue)){Add-PhpCandidate $command.Source 'PATH discovery'}
    Add-AuditStatus 'PATH discovery' Collected 'Resolved application paths without executing them.'
}catch{Add-AuditError 'PATH discovery' 'Application discovery failed.'}
try{
    $processes=@(Get-CimInstance -ClassName Win32_Process -Filter "Name='php.exe' OR Name='php-cgi.exe' OR Name='lsphp.exe' OR Name='frankenphp.exe'" -ErrorAction Stop)
    foreach($process in $processes){
        if($process.ExecutablePath){Add-PhpCandidate $process.ExecutablePath 'Running image' ('PID {0}; on-disk metadata does not identify the already loaded image version.' -f $process.ProcessId)}
        else{Add-AuditStatus 'Running image' Unknown 'A PHP process exists but its executable path could not be read.'}
    }
    Add-AuditStatus 'Running images' Collected ('Found {0} named PHP process(es); Apache/embedded PHP modules require separate mappings.' -f $processes.Count)
}catch{Add-AuditError 'Running images' 'Process path query unavailable.'}

$iisConfig=Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
if(Test-Path -LiteralPath $iisConfig){
    try{
        $xml=Read-SafeXmlDocument $iisConfig
        $mapped=0
        foreach($node in @($xml.SelectNodes('//fastCgi/application[@fullPath]'))){
            $runtime=[string]$node.GetAttribute('fullPath')
            if($runtime -match '(?i)php|lsphp|frankenphp'){Add-PhpCandidate $runtime 'IIS FastCGI' 'Configured FastCGI application; not proof of an active site.';$mapped++}
        }
        foreach($node in @($xml.SelectNodes('//handlers/add[@scriptProcessor]'))){
            $runtime=([string]$node.GetAttribute('scriptProcessor') -split '\|',2)[0]
            if($runtime -match '(?i)php|lsphp|frankenphp'){Add-PhpCandidate $runtime 'IIS handler' 'Configured handler; inherited/site web.config overrides were not enumerated.';$mapped++}
        }
        Add-AuditStatus 'IIS configuration' Collected ('Read {0} PHP mapping(s) from applicationHost.config only.' -f $mapped)
    }catch{Add-AuditError 'IIS configuration' 'IIS configuration unavailable, too large, or invalid XML.'}
}else{Add-AuditStatus 'IIS configuration' NotPresent 'No readable standard applicationHost.config was found; this does not rule out other web servers.'}

$defaultRoots=New-Object 'System.Collections.Generic.List[string]'
foreach($candidateRoot in @((Join-Path $env:SystemDrive 'PHP'),(Join-Path $env:SystemDrive 'xampp\php'),(Join-Path $env:SystemDrive 'wamp64'),(Join-Path $env:SystemDrive 'wamp'),(Join-Path $env:SystemDrive 'tools\php'))){$defaultRoots.Add($candidateRoot)}
foreach($programRoot in @($env:ProgramFiles,${env:ProgramFiles(x86)})){
    if($programRoot){$defaultRoots.Add((Join-Path $programRoot 'PHP'))}
}
foreach($root in @($defaultRoots.ToArray()+$SearchRoot | Sort-Object -Unique)){Search-PhpDirectory $root}

foreach($config in $ApacheConfigPath){
    try{
        if(-not (Test-NoReparseAncestry $config)){throw 'Unsafe configuration path.'}
        $item=Get-Item -LiteralPath $config -Force
        if($item.Length -gt 4194304){throw 'Configuration exceeds bound.'}
        foreach($line in @(Get-Content -LiteralPath $item.FullName -TotalCount 10000)){
            $module=[regex]::Match($line,'^\s*LoadModule\s+php\w*\s+(?:"(?<path>[^"]+)"|(?<path>\S+))',[Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if($module.Success){
                $modulePath=$module.Groups['path'].Value
                if([IO.Path]::IsPathRooted($modulePath)){Add-PhpCandidate $modulePath 'Apache module' 'Selected configuration directive; Include, ServerRoot, variable and runtime overrides require manual review.'}
                else{Add-AuditStatus 'Apache module' Unknown 'Relative PHP module path requires ServerRoot resolution; no path was guessed.'}
            }
        }
        Add-AuditStatus 'Apache configuration' Collected 'Inspected selected LoadModule directives only; no include traversal or configuration dump.'
    }catch{Add-AuditError 'Apache configuration' 'Selected Apache configuration unreadable or unsupported.'}
}
foreach($config in $PhpIniPath){
    try{
        if(-not (Test-NoReparseAncestry $config)){throw 'Unsafe configuration path.'}
        $item=Get-Item -LiteralPath $config -Force
        if($item.Length -gt 4194304){throw 'Configuration exceeds bound.'}
        $found=0
        foreach($line in @(Get-Content -LiteralPath $item.FullName -TotalCount 10000)){
            $setting=[regex]::Match($line,'^\s*(?<key>memory_limit|post_max_size|upload_max_filesize|session\.upload_progress\.enabled|fatal_error_backtraces)\s*=\s*(?<value>[^;\r\n]*)',[Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if($setting.Success){
                $key=$setting.Groups['key'].Value.ToLowerInvariant();$value=$setting.Groups['value'].Value.Trim().Trim('"').Trim("'")
                if($value -notmatch '^(?:-?\d+(?:[KMG])?|on|off|yes|no|true|false)$'){$value='[Unresolved or nonliteral value]'}
                $script:configurationRows.Add([pscustomobject]@{File=$item.FullName;Setting=$key;ConfiguredValue=$value;EffectiveValue='Unknown';Note='Selected file only; worker, SAPI, pool, application and per-directory overrides not resolved.'});$found++
            }
        }
        Add-AuditStatus 'Selected PHP ini' Collected ('Captured {0} whitelisted literal setting(s); these are not proof of mitigation.' -f $found)
    }catch{Add-AuditError 'Selected PHP ini' 'Selected ini unreadable or unsupported.'}
}

$binaryRows=New-Object 'System.Collections.Generic.List[object]'
foreach($candidate in @($script:candidates.Values | Sort-Object Path)){
    try{
        $versionInfo=[Diagnostics.FileVersionInfo]::GetVersionInfo($candidate.Path)
        $versionText=[string]$versionInfo.ProductVersion
        if([string]::IsNullOrWhiteSpace($versionText)){$versionText=[string]$versionInfo.FileVersion}
        $assessment=Get-PhpVersionAssessment $versionText
        if($candidate.Name -match '^(frankenphp|lsphp)\.exe$'){$assessment=[pscustomobject]@{Version='';Branch='';FixedVersion='';Assessment='UnknownEmbeddedRuntime';Reason='Wrapper product version is not accepted as the embedded PHP version. Obtain vendor/runtime build evidence.'}}
        $binaryRows.Add([pscustomobject]@{Path=$candidate.Path;Sources=($candidate.Sources -join '; ');ProductVersion=$versionText;ParsedPhpVersion=$assessment.Version;Branch=$assessment.Branch;MinimumFixedVersion=$assessment.FixedVersion;Assessment=$assessment.Assessment;Reason=$assessment.Reason;Cves='CVE-2026-109618; CVE-2026-109619'})
    }catch{Add-AuditError 'Version metadata' 'Binary metadata unreadable or file changed during audit.'}
}
if($binaryRows.Count -eq 0){Add-AuditStatus 'PHP discovery' Unknown 'No readable PHP binaries found in this scope. This does not prove that PHP is absent or that embedded/vendor/container installations are patched.'}
Add-AuditStatus 'Scope' Unknown 'Bounded local discovery cannot establish complete asset coverage or active web-worker patch state. Explicitly include vendor bundles and Apache modules.'
$rows=$binaryRows.ToArray()
$affected=@($rows | Where-Object Assessment -like 'PotentiallyAffected*').Count
$fixed=@($rows | Where-Object Assessment -eq 'MeetsPublishedFixedVersion').Count
Export-AuditCsv php-binaries $rows @('Path','Sources','ProductVersion','ParsedPhpVersion','Branch','MinimumFixedVersion','Assessment','Reason','Cves')
Export-AuditCsv web-runtime-associations $script:associations.ToArray() @('Kind','BinaryPath','Context')
Export-AuditCsv selected-ini-settings $script:configurationRows.ToArray() @('File','Setting','ConfiguredValue','EffectiveValue','Note')
Export-AuditCsv collection-status $script:queryRows.ToArray() @('Section','Status','Detail')
Export-AuditCsv query-errors $script:queryErrors.ToArray() @('Section','ErrorCategory')
$summary=[pscustomobject]@{
    Script='Test-Php2ShellExposure';ComputerName=$env:COMPUTERNAME;CollectedUtc=[datetime]::UtcNow.ToString('o')
    Cves=@('CVE-2026-109618','CVE-2026-109619');RulesReviewed='2026-10-23';Advisory=$advisoryUrl
    Finding=$(if($affected){'PotentiallyAffectedInstallationsFound'}elseif($fixed){'PublishedFixedVersionsFound_CoverageIncomplete'}else{'Unknown'})
    BinaryCount=$rows.Count;PotentiallyAffectedCount=$affected;MeetsPublishedFixedVersionCount=$fixed
    CollectionStatus='Partial';QueryErrorCount=$script:queryErrors.Count;ReportDirectory=$reportDirectory
    FixedUpstreamVersions=@('8.2.35','8.3.36','8.4.27','8.5.12')
    Notes=@('Read-only local version/configuration audit; no binaries executed, HTTP requests, exploit payloads, updates or restarts.'
        'Version metadata is evidence, not proof of exploitability, integrity, vendor backports, complete discovery, or live worker replacement.'
        'All web SAPIs are in scope of the PHP advisory, not only Windows CGI. CLI discoveries do not prove web exposure.'
        'Review original vendor build evidence for backports/embedded runtimes. Updates, service restarts, and application testing require separate actions.'
        'Configuration snippets are not resolved effective runtime values; reduced exposure does not replace the published fixes.')
}
$summary | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $reportDirectory 'summary.json') -Encoding UTF8
$summary
