<#
What it does:
  Stage IIS features and optionally create new stopped sites and application pools from JSON.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -ConfigurationPath: Optional JSON file with a Sites array; use only after IIS features are installed.

How it works:
  Validates site names, paths, bindings, addresses and certificates before changes. Creates stopped sites with Windows authentication; HTTP is loopback only. Existing sites are preserved and no automatic restart occurs.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$Apply,
    [string]$OutputDirectory,
    [switch]$SkipRestartPrompt,
        [string]$ConfigurationPath
)
$ErrorActionPreference='Stop'
if(-not $PSBoundParameters.ContainsKey('OutputDirectory')){$OutputDirectory=Join-Path $PSScriptRoot '..\Reports'}
$setupScriptName=[IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Path)
$setupReportDirectory=Join-Path $OutputDirectory ($setupScriptName+'-'+(Get-Date -Format yyyyMMdd-HHmmss)+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $setupReportDirectory -Force -WhatIf:$false -Confirm:$false
$setupSteps=New-Object 'System.Collections.Generic.List[object]'
$setupChecks=New-Object 'System.Collections.Generic.List[object]'
$setupServiceRestarts=New-Object 'System.Collections.Generic.List[object]'
$setupBlocked=$false;$setupCanApply=[bool]$Apply;$setupRestartRequired=$false;$setupChanges=0;$setupCmdlet=$PSCmdlet;$setupRestartOffered=$false;$setupRestartDecision=$null
$setupHost=[pscustomobject]@{Computer=$env:COMPUTERNAME;Caption=$null;Build=$null;ProductType=$null;DomainRole=$null;PartOfDomain=$null;Domain=$null;Runtime=[string]$PSVersionTable.PSVersion;Administrator=$false;PendingRestart=$null}
function Set-SetupBlocked {
    param([string]$Reason)
    $script:setupBlocked=$true;$script:setupCanApply=$false
    $setupChecks.Add([pscustomobject]@{Name='ApplyGate';State='Blocked';Evidence=$Reason;Rows=$null;ErrorType=$null})
}
function Test-SetupCommand {
    param([string]$Name,[string[]]$Parameters=@())
    $command=Get-Command -Name $Name -ErrorAction SilentlyContinue
    if($null -eq $command){return $false}
    foreach($parameterName in $Parameters){if(-not $command.Parameters.ContainsKey($parameterName)){return $false}}
    return $true
}
function Invoke-SetupQuery {
    param([string]$Name,[scriptblock]$Action,[switch]$RequireData)
    try{
        $data=@(& $Action)
        if($RequireData -and $data.Count -eq 0){throw [InvalidOperationException]::new('Required evidence absent')}
        $setupChecks.Add([pscustomobject]@{Name=$Name;State='Collected';Evidence='Read completed; raw provider objects and messages are not serialized.';Rows=$data.Count;ErrorType=$null})
        return [pscustomobject]@{Succeeded=$true;Data=$data}
    }catch{
        $setupChecks.Add([pscustomobject]@{Name=$Name;State='Unknown';Evidence='Query failed. Check the requested role, permissions, runtime and native management logs.';Rows=$null;ErrorType=$_.Exception.GetType().FullName})
        Set-SetupBlocked -Reason ('Required inspection failed: '+$Name+'. No further configuration changes will run.')
        return [pscustomobject]@{Succeeded=$false;Data=@()}
    }
}
function Add-SetupStep {
    param([string]$Name,[string]$Target,[string]$Action,[string]$Evidence,[string]$State='Planned')
    $setupSteps.Add([pscustomobject]@{Name=$Name;Target=$Target;Action=$Action;State=$State;Evidence=$Evidence})
}
function Invoke-SetupAction {
    param([string]$Name,[string]$Target,[scriptblock]$Action)
    $step=$setupSteps | Where-Object {$_.Name -eq $Name -and $_.Target -eq $Target} | Select-Object -Last 1
    if(-not $step){Add-SetupStep -Name $Name -Target $Target -Action 'Configure' -Evidence 'Explicitly gated setup operation.';$step=$setupSteps[$setupSteps.Count-1]}
    if(-not $Apply){return [pscustomobject]@{Succeeded=$false;Data=@();Skipped=$true}}
    if(-not $setupCanApply -or $setupBlocked){$step.State='Blocked';return [pscustomobject]@{Succeeded=$false;Data=@();Skipped=$true}}
    if(-not $setupCmdlet.ShouldProcess($Target,$Name)){$step.State='Skipped';return [pscustomobject]@{Succeeded=$false;Data=@();Skipped=$true}}
    try{
        $data=@(& $Action)
        foreach($item in $data){
            if($null -ne $item -and $item.PSObject.Properties['RestartNeeded'] -and [string]$item.RestartNeeded -eq 'Yes'){$script:setupRestartRequired=$true}
            if($null -ne $item -and $item.PSObject.Properties['Success'] -and $item.Success -is [bool] -and -not $item.Success){throw [InvalidOperationException]::new('Provider reported failure')}
        }
        $step.State='Applied';$script:setupChanges++
        return [pscustomobject]@{Succeeded=$true;Data=$data;Skipped=$false}
    }catch{
        $step.State='Failed'
        $setupChecks.Add([pscustomobject]@{Name=$Name;State='Failed';Evidence='Setup operation failed. Inspect native management logs before retrying; previous successful steps remain applied.';Rows=$null;ErrorType=$_.Exception.GetType().FullName})
        Set-SetupBlocked -Reason ('Setup stopped after failure: '+$Name+'. No rollback or automatic restart was attempted.')
        return [pscustomobject]@{Succeeded=$false;Data=@();Skipped=$false}
    }
}
function Save-SetupReport {
    param([object]$Summary,[string[]]$Notes)
    foreach($table in @(@{Name='plan';Rows=$setupSteps.ToArray();Columns=@('Name','Target','Action','State','Evidence')},@{Name='checks';Rows=$setupChecks.ToArray();Columns=@('Name','State','Evidence','Rows','ErrorType')})){
        $path=Join-Path $setupReportDirectory ($table.Name+'.csv')
        if($table.Rows.Count){$table.Rows | Select-Object $table.Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false}
        else{($table.Columns | ForEach-Object {'"'+$_+'"'}) -join ',' | Set-Content -LiteralPath $path -Encoding UTF8 -WhatIf:$false -Confirm:$false}
    }
    $Summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $setupReportDirectory 'summary.json') -Encoding UTF8 -WhatIf:$false -Confirm:$false
    @('Review plan.csv and checks.csv before applying. State describes this script scope, not a complete production acceptance test.','Default is plan only. Apply and ShouldProcess authorization are required for changes. Reports are written even with WhatIf.','Required restarts need a separate confirmation after the report is saved. SkipRestartPrompt leaves the server pending restart; Confirm false does not bypass the restart question.','Restart decision: '+$Summary.RestartDecision,'No automatic rollback occurs. Stop after a failed action and inspect the server before retrying.','',$Notes) | Set-Content -LiteralPath (Join-Path $setupReportDirectory 'README.txt') -Encoding UTF8 -WhatIf:$false -Confirm:$false
}
function Confirm-SetupRestart {
    return $setupCmdlet.ShouldContinue(('Restart '+$setupHost.Computer+' now? This disconnects sessions and interrupts services. The setup report is saved at '+[IO.Path]::GetFullPath($setupReportDirectory)+'.'),'Confirm required server restart')
}
function Request-SetupServiceRestart {
    param([string]$Name,[string]$Reason)
    $setupServiceRestarts.Add([pscustomobject]@{Name=$Name;Reason=$Reason;Decision='PendingConfirmation'})
    Add-SetupStep -Name 'Required service restart' -Target $Name -Action Restart -Evidence $Reason -State Deferred
}
function Confirm-SetupServiceRestart {
    param([string]$Name)
    return $setupCmdlet.ShouldContinue(('Restart service '+$Name+' on '+$setupHost.Computer+' now? This interrupts that service. The setup report has been saved.'),'Confirm required service restart')
}
function Complete-SetupReport {
    param([string[]]$Notes)
    $state=if($setupBlocked){'Blocked'}elseif(-not $Apply){'Plan'}elseif($setupRestartRequired){'RestartRequired'}elseif(@($setupSteps | Where-Object State -in @('Planned','Deferred','Skipped')).Count){'Incomplete'}else{'Complete'}
    $restartHostSupported=$setupHost.ProductType -in @(2,3) -and $setupHost.Build -in @('20348','26100') -and $setupHost.Administrator -and [Environment]::Is64BitProcess -and $PSVersionTable.PSEdition -eq 'Desktop' -and $PSVersionTable.PSVersion.Major -eq 5
    $decision=if(-not $setupRestartRequired){'NotRequired'}elseif(-not $Apply -or $WhatIfPreference){'PlanOnly'}elseif($SkipRestartPrompt){'DeferredByOption'}elseif(-not $restartHostSupported){'RestartNotAuthorized'}elseif($setupRestartOffered){$setupRestartDecision}else{'PendingConfirmation'}
    $summary=[pscustomobject]@{Script=$setupScriptName;GeneratedUtc=[datetime]::UtcNow.ToString('o');State=$state;ApplyRequested=[bool]$Apply;AppliedOperations=$setupChanges;RestartRequired=$setupRestartRequired;RestartDecision=$decision;ServiceRestarts=$setupServiceRestarts.ToArray();Host=$setupHost;Notes=$Notes;ReportDirectory=[IO.Path]::GetFullPath($setupReportDirectory)}
    Save-SetupReport -Summary $summary -Notes $Notes
    if(-not $setupRestartRequired -and $setupServiceRestarts.Count){
        foreach($request in $setupServiceRestarts){
            $restartServiceNow=$false
            if(-not $Apply -or $WhatIfPreference){$request.Decision='PlanOnly'}
            elseif($SkipRestartPrompt){$request.Decision='DeferredByOption'}
            elseif(-not $restartHostSupported){$request.Decision='RestartNotAuthorized'}
            else{
                try{if(Confirm-SetupServiceRestart -Name $request.Name){$request.Decision='Confirmed';$restartServiceNow=$true}else{$request.Decision='Declined'}}catch{$request.Decision='ConfirmationUnavailable'}
            }
            Save-SetupReport -Summary $summary -Notes $Notes
            if($restartServiceNow){
                try{
                    Restart-Service -Name $request.Name -Confirm:$false -ErrorAction Stop
                    $request.Decision='Restarted'
                    ($setupSteps | Where-Object {$_.Name -eq 'Required service restart' -and $_.Target -eq $request.Name} | Select-Object -Last 1).State='Applied'
                }catch{
                    $request.Decision='RequestFailed'
                    Set-SetupBlocked -Reason ('Required service restart failed: '+$request.Name+'. Restart it manually after review.')
                }
            }
        }
        $summary.State=if($setupBlocked){'Blocked'}elseif(@($setupServiceRestarts | Where-Object Decision -ne Restarted).Count){'ServiceRestartRequired'}else{'Complete'}
        Save-SetupReport -Summary $summary -Notes $Notes
    }
    if($decision -eq 'PendingConfirmation'){
        $script:setupRestartOffered=$true
        try{
            if(Confirm-SetupRestart){$summary.RestartDecision='Confirmed'}else{$summary.RestartDecision='Declined'}
        }catch{$summary.RestartDecision='ConfirmationUnavailable'}
        $script:setupRestartDecision=$summary.RestartDecision
        $setupChecks.Add([pscustomobject]@{Name='RequiredRestart';State=$summary.RestartDecision;Evidence='A restart occurs only after a positive response to the separate required-restart question.';Rows=$null;ErrorType=$null})
        Save-SetupReport -Summary $summary -Notes $Notes
        if($summary.RestartDecision -eq 'Confirmed'){
            try{
                Restart-Computer -Confirm:$false -ErrorAction Stop
                $summary.State='RestartRequested'
            }catch{
                $summary.State='RestartFailed';$summary.RestartDecision='RequestFailed'
                $setupChecks.Add([pscustomobject]@{Name='RequiredRestart';State='Failed';Evidence='Windows did not accept the restart request. Restart manually after reviewing the server.';Rows=$null;ErrorType=$_.Exception.GetType().FullName})
            }
            Save-SetupReport -Summary $summary -Notes $Notes
        }
    }
    return $summary
}
function Test-SetupAdministrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Initialize-SetupHost {
    $os=Invoke-SetupQuery -Name 'OperatingSystem' -RequireData -Action {Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop}
    $computer=Invoke-SetupQuery -Name 'ComputerMembership' -RequireData -Action {Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop}
    if($os.Succeeded -and $os.Data.Count -eq 1){
        $setupHost.Caption=[string]$os.Data[0].Caption;$setupHost.Build=[string]$os.Data[0].BuildNumber;$setupHost.ProductType=$os.Data[0].ProductType
        if($setupHost.ProductType -notin @(2,3) -or $setupHost.Build -notin @('20348','26100')){Set-SetupBlocked 'Only Windows Server 2022 (20348) and 2025 (26100) are targeted.'}
    }else{Set-SetupBlocked 'The operating system could not be identified unambiguously.'}
    if($computer.Succeeded -and $computer.Data.Count -eq 1){
        $setupHost.Computer=[string]$computer.Data[0].Name;$setupHost.DomainRole=$computer.Data[0].DomainRole;$setupHost.PartOfDomain=$computer.Data[0].PartOfDomain;$setupHost.Domain=[string]$computer.Data[0].Domain
        if($setupHost.DomainRole -notin @(2,3,4,5) -or $setupHost.PartOfDomain -isnot [bool]){Set-SetupBlocked 'Server membership evidence is missing or invalid.'}
    }else{Set-SetupBlocked 'Computer membership could not be identified unambiguously.'}
    if(-not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){Set-SetupBlocked 'Use native 64-bit Windows PowerShell 5.1 on the target server.'}
    try{$setupHost.Administrator=Test-SetupAdministrator}catch{$setupHost.Administrator=$false}
    if($Apply -and -not $setupHost.Administrator){Set-SetupBlocked 'Apply requires an elevated administrator session on the target server.'}
    $pending=Invoke-SetupQuery -Name 'PendingRestart' -RequireData -Action {
        $required=(Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        $session=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
        if(@($session.PendingFileRenameOperations | Where-Object {$_}).Count){$required=$true}
        $active=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction Stop
        $configured=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction Stop
        if($active.ComputerName -ne $configured.ComputerName){$required=$true}
        [pscustomobject]@{Required=[bool]$required}
    }
    if($pending.Succeeded){$setupHost.PendingRestart=$pending.Data[0].Required;if($setupHost.PendingRestart){$script:setupRestartRequired=$true;if($Apply){Set-SetupBlocked 'Restart the server to finish existing pending changes before applying this setup.'}}}
}
Initialize-SetupHost

try {
function Test-IisSetupBindingConflict {
    param([string]$Protocol,[string]$IPAddress,[int]$Port,[string]$HostName,[object[]]$ExistingBindings)
    foreach ($binding in @($ExistingBindings)) {
        if ([string]$binding.BindingInformation -notmatch '^(.*):(\d+):([^:]*)$') { return $true }
        $existingIp = $Matches[1].Trim('[',']'); $existingPort = [int]$Matches[2]; $existingHost = $Matches[3]
        if ($existingPort -ne $Port) { continue }
        $ipOverlap = $existingIp -in @('*','0.0.0.0','::','') -or $existingIp -eq $IPAddress
        $hostOverlap = [string]::IsNullOrWhiteSpace($existingHost) -or [string]::IsNullOrWhiteSpace($HostName) -or $existingHost.Contains('*') -or $existingHost -eq $HostName
        if ($ipOverlap -and $hostOverlap) { return $true }
    }
    return $false
}
function Test-IisSetupPathOverlap {
    param([string]$FirstPath,[string]$SecondPath)
    if ([string]::IsNullOrWhiteSpace($FirstPath) -or [string]::IsNullOrWhiteSpace($SecondPath)) { return $false }
    $first = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($FirstPath)).TrimEnd('\')
    $second = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($SecondPath)).TrimEnd('\')
    return $first.Equals($second,[StringComparison]::OrdinalIgnoreCase) -or $first.StartsWith(($second+'\'),[StringComparison]::OrdinalIgnoreCase) -or $second.StartsWith(($first+'\'),[StringComparison]::OrdinalIgnoreCase)
}
function Get-IisSetupInventory {
    $assemblyPath = Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll'
    Add-Type -Path $assemblyPath -ErrorAction Stop
    $manager = New-Object Microsoft.Web.Administration.ServerManager
    try {
        $siteRows = @(foreach ($site in $manager.Sites) {
            [pscustomobject]@{Name=$site.Name; PhysicalPath=$site.Applications['/'].VirtualDirectories['/'].PhysicalPath; Bindings=@(foreach ($binding in $site.Bindings) { [pscustomobject]@{Protocol=$binding.Protocol;BindingInformation=$binding.BindingInformation} })}
        })
        [pscustomobject]@{Sites=$siteRows;PoolNames=@($manager.ApplicationPools | ForEach-Object { $_.Name })}
    }
    finally { $manager.Dispose() }
}
function New-IisSetupSites {
    param([object[]]$Sites)
    $manager = New-Object Microsoft.Web.Administration.ServerManager
    try {
        foreach ($definition in $Sites) {
            if ($manager.Sites[$definition.Name] -or $manager.ApplicationPools[$definition.AppPool]) { throw 'A site or application pool appeared after preflight; creation was stopped.' }
            foreach ($currentSite in $manager.Sites) {
                if (Test-IisSetupPathOverlap -FirstPath $currentSite.Applications['/'].VirtualDirectories['/'].PhysicalPath -SecondPath $definition.PhysicalPath) { throw 'A conflicting content path appeared after preflight; creation was stopped.' }
                $currentBindings = @(foreach ($currentBinding in $currentSite.Bindings) { [pscustomobject]@{Protocol=$currentBinding.Protocol;BindingInformation=$currentBinding.BindingInformation} })
                if (Test-IisSetupBindingConflict -Protocol $definition.Protocol -IPAddress $definition.IPAddress -Port $definition.Port -HostName $definition.HostName -ExistingBindings $currentBindings) { throw 'A conflicting binding appeared after preflight; creation was stopped.' }
            }
            $pool = $manager.ApplicationPools.Add($definition.AppPool)
            $pool.ManagedRuntimeVersion = ''
            $bindingIp = $definition.IPAddress
            if ($bindingIp.Contains(':')) { $bindingIp = '[' + $bindingIp + ']' }
            $bindingInformation = '{0}:{1}:{2}' -f $bindingIp,$definition.Port,$definition.HostName
            $site = $manager.Sites.Add($definition.Name,$definition.Protocol,$bindingInformation,$definition.PhysicalPath)
            $site.ServerAutoStart = $false
            $site.Applications['/'].ApplicationPoolName = $definition.AppPool
            if ($definition.Protocol -eq 'https') {
                $site.Bindings[0].CertificateHash = [byte[]]$definition.CertificateHash
                $site.Bindings[0].CertificateStoreName = 'My'
                $site.Bindings[0].SetAttributeValue('sslFlags',1)
            }
            $configuration = $manager.GetApplicationHostConfiguration()
            $configuration.GetSection('system.webServer/security/authentication/anonymousAuthentication',$definition.Name).SetAttributeValue('enabled',$false)
            $configuration.GetSection('system.webServer/security/authentication/windowsAuthentication',$definition.Name).SetAttributeValue('enabled',$true)
            $configuration.GetSection('system.webServer/directoryBrowse',$definition.Name).SetAttributeValue('enabled',$false)
        }
        $manager.CommitChanges()
        foreach ($definition in $Sites) { [pscustomobject]@{Name=$definition.Name;ApplicationPool=$definition.AppPool;Started=$false;Authentication='Windows';Protocol=$definition.Protocol} }
    }
    finally { $manager.Dispose() }
}

$notes = New-Object 'System.Collections.Generic.List[string]'
$notes.Add('Default scope installs IIS with Windows authentication and scripting tools. On a first installation with no prior IIS configuration, the generated Default Web Site is stopped and automatic startup is disabled. Existing sites, including an existing Default Web Site, are preserved.')
$notes.Add('An optional JSON file creates only new, stopped sites and new application pools. HTTP is limited to loopback; HTTPS requires a local IP, DNS host name, and existing valid private-key certificate. Windows authentication is enabled and anonymous authentication is disabled. No custom firewall rule, content, permissions, DNS record, certificate, application runtime, or application deployment is created.')
$notes.Add('Review IIS-generated firewall/service changes after role installation. Before starting a site, verify certificate name and trust, content ACLs, application runtime, authentication and authorization, application pool identity, logging, and the intended network perimeter. This is not a production security acceptance test.')
$features = @('Web-Server','Web-Windows-Auth','Web-Scripting-Tools')
$missingFeatures = @()
$iisReadyAtEntry = $false
$allFeaturesReadyAtEntry = $false
$validatedSites = New-Object 'System.Collections.Generic.List[object]'
$existingBindings = New-Object 'System.Collections.Generic.List[object]'
$inventory = $null

foreach ($commandName in @('Get-WindowsFeature','Install-WindowsFeature')) {
    if (-not (Test-SetupCommand -Name $commandName)) { Set-SetupBlocked -Reason ('Required IIS command is unavailable: ' + $commandName) }
}
$featureQuery = Invoke-SetupQuery -Name 'IIS feature inventory' -RequireData -Action { Get-WindowsFeature -Name $features -ErrorAction Stop }
if ($featureQuery.Succeeded) {
    if (@($featureQuery.Data).Count -ne $features.Count) { Set-SetupBlocked -Reason 'The required IIS features were not all reported.' }
    $missingFeatures = @($featureQuery.Data | Where-Object { -not $_.Installed } | Select-Object -ExpandProperty Name)
    $iisReadyAtEntry = @($featureQuery.Data | Where-Object { $_.Name -eq 'Web-Server' -and $_.Installed }).Count -eq 1
    $allFeaturesReadyAtEntry = $missingFeatures.Count -eq 0 -and @($featureQuery.Data).Count -eq $features.Count
}
$applicationHostPath = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
if (-not $iisReadyAtEntry -and (Test-Path -LiteralPath $applicationHostPath)) { Set-SetupBlocked -Reason 'IIS configuration already exists while the role is absent. Review it and install the role manually so existing sites are not unexpectedly activated or changed.' }
if ($ConfigurationPath) {
    if (-not $allFeaturesReadyAtEntry) { Set-SetupBlocked -Reason 'Install IIS features first without ConfigurationPath, then rerun with the JSON file. Site creation requires all features to be installed before this invocation.' }
    if ($allFeaturesReadyAtEntry) {
        $inventoryQuery = Invoke-SetupQuery -Name 'Existing IIS sites, pools, paths, and bindings' -RequireData -Action { Get-IisSetupInventory }
        if ($inventoryQuery.Succeeded) {
            $inventory = @($inventoryQuery.Data)[0]
            foreach ($existingSite in @($inventory.Sites)) { foreach ($binding in @($existingSite.Bindings)) { $existingBindings.Add($binding) } }
        }
    }
    $configurationQuery = Invoke-SetupQuery -Name 'IIS JSON validation' -RequireData -Action {
        $configurationItem = Get-Item -LiteralPath $ConfigurationPath -ErrorAction Stop
        if ($configurationItem.PSIsContainer -or $configurationItem.Length -gt 1048576) { throw 'The JSON file must be a file no larger than 1 MiB.' }
        $configuration = Get-Content -LiteralPath $ConfigurationPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if (-not $configuration -or @($configuration.PSObject.Properties.Name | Where-Object { $_ -ne 'Sites' }).Count -or -not $configuration.PSObject.Properties['Sites']) { throw 'Expected a JSON object with only a Sites array.' }
        if (@($configuration.Sites).Count -eq 0 -or @($configuration.Sites).Count -gt 25) { throw 'Provide between 1 and 25 sites.' }
        foreach ($definition in @($configuration.Sites)) {
            $allowedProperties = @('Name','PhysicalPath','AppPool','Protocol','IPAddress','Port','HostName','CertificateThumbprint')
            if (@($definition.PSObject.Properties.Name | Where-Object { $_ -notin $allowedProperties }).Count) { throw 'An unknown site property was supplied.' }
            foreach ($requiredName in @('Name','PhysicalPath','AppPool','Protocol','IPAddress','Port','HostName')) { if (-not $definition.PSObject.Properties[$requiredName]) { throw 'A required site property was omitted.' } }
            if ([string]$definition.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$' -or [string]$definition.AppPool -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') { throw 'Site and app pool names must use simple letters, numbers, dot, underscore, or hyphen.' }
            if ([string]$definition.Protocol -notin @('http','https')) { throw 'Protocol must be http or https.' }
            $portNumber = 0
            if (-not [int]::TryParse([string]$definition.Port,[ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535) { throw 'Port must be between 1 and 65535.' }
            $siteIp = $null
            if (-not [Net.IPAddress]::TryParse([string]$definition.IPAddress,[ref]$siteIp) -or $siteIp.Equals([Net.IPAddress]::Any) -or $siteIp.Equals([Net.IPAddress]::IPv6Any)) { throw 'Specify an individual IP address; wildcard addresses are not accepted.' }
            if ($definition.Protocol -eq 'http' -and -not [Net.IPAddress]::IsLoopback($siteIp)) { throw 'HTTP sites must bind to a loopback address. Use HTTPS for a network-facing site.' }
            if ($definition.HostName -and [string]$definition.HostName -notmatch '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') { throw 'HostName must be a literal DNS name or empty for loopback HTTP.' }
            if ([string]$definition.PhysicalPath -notmatch '^[A-Za-z]:\\') { throw 'PhysicalPath must be an existing local absolute directory.' }
            $contentItem = Get-Item -LiteralPath $definition.PhysicalPath -ErrorAction Stop
            if (-not $contentItem.PSIsContainer -or ($contentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'PhysicalPath must be a regular directory, not a reparse point.' }
            $physicalPath = [IO.Path]::GetFullPath([string]$contentItem.FullName).TrimEnd('\')
            if ($physicalPath -eq [IO.Path]::GetPathRoot($physicalPath).TrimEnd('\')) { throw 'A volume root cannot be used as a site content directory.' }
            $parentItem = $contentItem.Parent
            while ($parentItem) { if ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'A site content ancestor is a reparse point.' }; $parentItem = $parentItem.Parent }
            if (@($validatedSites | Where-Object { $_.Name -eq $definition.Name -or $_.AppPool -eq $definition.AppPool -or (Test-IisSetupPathOverlap -FirstPath $_.PhysicalPath -SecondPath $physicalPath) }).Count) { throw 'Site name, pool name, or overlapping content path is duplicated in this request.' }
            if ($inventory -and (@($inventory.Sites | Where-Object { $_.Name -eq $definition.Name -or (Test-IisSetupPathOverlap -FirstPath ([string]$_.PhysicalPath) -SecondPath $physicalPath) }).Count -or @($inventory.PoolNames | Where-Object { $_ -eq $definition.AppPool }).Count)) { throw 'The site name, application pool, or overlapping content directory is already in use.' }
            $certificateHash = $null
            if ($definition.Protocol -eq 'https') {
                $thumbprint = ([string]$definition.CertificateThumbprint -replace '\s','').ToUpperInvariant()
                if ($thumbprint -notmatch '^[A-F0-9]{40}$' -or [string]::IsNullOrWhiteSpace([string]$definition.HostName)) { throw 'HTTPS requires a DNS HostName and a certificate thumbprint from LocalMachine\My.' }
                $certificate = Get-Item -LiteralPath ('Cert:\LocalMachine\My\' + $thumbprint) -ErrorAction Stop
                if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le (Get-Date) -or $certificate.NotBefore -gt (Get-Date)) { throw 'The certificate must be valid now and have a private key.' }
                $certificateHash = $certificate.GetCertHash()
            }
            elseif ($definition.CertificateThumbprint) { throw 'CertificateThumbprint is only valid for HTTPS.' }
            if (Test-IisSetupBindingConflict -Protocol $definition.Protocol -IPAddress $siteIp.ToString() -Port $portNumber -HostName ([string]$definition.HostName) -ExistingBindings $existingBindings.ToArray()) { throw 'A requested binding overlaps an existing or requested binding.' }
            $bindingIp = $siteIp.ToString(); if ($bindingIp.Contains(':')) { $bindingIp = '[' + $bindingIp + ']' }
            $existingBindings.Add([pscustomobject]@{Protocol=$definition.Protocol;BindingInformation=('{0}:{1}:{2}' -f $bindingIp,$portNumber,$definition.HostName)})
            $row = [pscustomobject]@{Name=[string]$definition.Name;AppPool=[string]$definition.AppPool;PhysicalPath=$physicalPath;Protocol=[string]$definition.Protocol;IPAddress=$siteIp.ToString();Port=$portNumber;HostName=[string]$definition.HostName;CertificateHash=$certificateHash}
            $validatedSites.Add($row)
            $row
        }
    }
    if (@($validatedSites | Where-Object { -not [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($_.IPAddress)) }).Count) {
        if (-not (Test-SetupCommand -Name 'Get-NetIPAddress')) { Set-SetupBlocked -Reason 'Get-NetIPAddress is needed to verify network-facing binding addresses.' }
        else {
            $addressQuery = Invoke-SetupQuery -Name 'Local binding IP addresses' -RequireData -Action { Get-NetIPAddress -ErrorAction Stop }
            if ($addressQuery.Succeeded) {
                foreach ($definition in $validatedSites.ToArray()) {
                    if (-not [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($definition.IPAddress)) -and @($addressQuery.Data | Where-Object { $_.IPAddress -eq $definition.IPAddress }).Count -eq 0) { Set-SetupBlocked -Reason ('A requested binding IP address is not assigned locally: ' + $definition.IPAddress) }
                }
            }
        }
    }
}

if ($missingFeatures.Count -and -not $ConfigurationPath) {
    Add-SetupStep -Name 'Install IIS features' -Target 'Local server' -Action 'Install IIS, Windows authentication, and scripting tools without automatic restart' -Evidence 'If this is the first IIS installation, the newly generated Default Web Site will be stopped and automatic startup disabled. Existing IIS sites are preserved.'
    $installResult = Invoke-SetupAction -Name 'Install IIS features' -Target 'Local server' -Action {
        $result = Install-WindowsFeature -Name $missingFeatures -IncludeManagementTools -ErrorAction Stop
        if (-not $result.Success) { throw 'IIS feature installation did not succeed.' }
        if ([string]$result.RestartNeeded -ne 'No') { $script:setupRestartRequired = $true }
        if (-not $iisReadyAtEntry) {
            $assemblyPath = Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll'
            Add-Type -Path $assemblyPath -ErrorAction Stop
            $manager = New-Object Microsoft.Web.Administration.ServerManager
            try {
                $generatedDefault = $manager.Sites['Default Web Site']
                if ($generatedDefault) {
                    $generatedDefault.ServerAutoStart = $false
                    $manager.CommitChanges()
                    if ([string]$generatedDefault.State -ne 'Stopped') { $null = $generatedDefault.Stop() }
                }
            }
            finally { $manager.Dispose() }
        }
        $result | Select-Object Success,RestartNeeded,ExitCode
    }
}
elseif ($allFeaturesReadyAtEntry) { Add-SetupStep -Name 'IIS features' -Target 'Local server' -Action 'Preserve installed features' -Evidence 'All required IIS features were installed before this run.' -State 'Ready' }
if ($ConfigurationPath -and $validatedSites.Count) {
    foreach ($definition in $validatedSites.ToArray()) { Add-SetupStep -Name 'Create stopped IIS site' -Target $definition.Name -Action 'Create a new application pool and stopped site using Windows authentication' -Evidence ('{0}://{1}:{2}, host {3}, path {4}; anonymous access disabled.' -f $definition.Protocol,$definition.IPAddress,$definition.Port,$definition.HostName,$definition.PhysicalPath) }
    Add-SetupStep -Name 'Commit new IIS sites' -Target 'Local IIS configuration' -Action 'Commit all validated new stopped sites in one configuration update' -Evidence 'Existing sites and application pools are not changed. New pools use no managed CLR; application runtime setup remains manual.'
    $siteResult = Invoke-SetupAction -Name 'Commit new IIS sites' -Target 'Local IIS configuration' -Action { New-IisSetupSites -Sites $validatedSites.ToArray() }
    if ($siteResult.Succeeded) { foreach ($step in @($setupSteps | Where-Object { $_.Name -eq 'Create stopped IIS site' })) { $step.State = 'Applied' } }
}
Complete-SetupReport -Notes $notes.ToArray()


} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
