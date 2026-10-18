<#
What it does:
  Stage RDS roles, then optionally create a new single-host session deployment with explicit licensing.

Available flags:
  -Apply: Opt in to configuration changes; default is a report-only plan.
  -OutputDirectory: Report destination; default Windows\Reports.
  -SkipRestartPrompt: Defer required restarts for unattended use; never authorizes a restart.
  -WhatIf and -Confirm: Standard controls for changes; required restarts always need a separate confirmation.
  -ConfigureDeployment: On a later run, create a new deployment using already installed roles.
  -LicenseServer: FQDN of the existing activated license server; required for deployment.
  -LicensingMode: Explicit PerUser or PerDevice CAL mode; required for deployment.
  -CollectionName: Optional new collection name; requires explicit access groups.
  -CollectionUserGroup: DOMAIN\Group names allowed to use the optional collection.

How it works:
  Requires a domain member with Desktop Experience and separates role installation from deployment. Verifies explicit licensing and collection groups; temporarily suspends new sessions during collection setup. A required restart needs separate confirmation.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$Apply,
    [string]$OutputDirectory,
    [switch]$SkipRestartPrompt,
        [switch]$ConfigureDeployment,
    [string]$LicenseServer,
    [ValidateSet('PerUser','PerDevice')][string]$LicensingMode,
    [string]$CollectionName,
    [string[]]$CollectionUserGroup
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
$notes = New-Object 'System.Collections.Generic.List[string]'
$notes.Add('This is a single-host standard RDS session deployment on a dedicated domain member with Desktop Experience: Connection Broker, Web Access, and Session Host. It does not build a high-availability farm.')
$notes.Add('Install roles first; a required restart asks for separate confirmation after reports are saved. A later run with -ConfigureDeployment creates the deployment, configures explicit licensing, and optionally creates a collection for specified groups. Existing deployments are never repaired or expanded.')
$notes.Add('License server activation, matching Windows Server CALs and RDS CALs, trusted deployment certificates, application testing, profile storage, RD Gateway, external DNS, MFA, and perimeter rules require separate administration before production use. This script does not grant internet access.')
$features = @('RDS-Connection-Broker','RDS-Web-Access','RDS-RD-Server')
$featureReadyAtEntry = $false
$missingFeatures = @()
$localFqdn = $null
$rdsOriginalLogons = $null

foreach ($commandName in @('Get-WindowsFeature','Install-WindowsFeature','Get-CimInstance','Get-ItemProperty','Resolve-DnsName','Test-ComputerSecureChannel','Get-Service','Get-NetIPAddress')) {
    if (-not (Test-SetupCommand -Name $commandName)) { Set-SetupBlocked -Reason ('Required RDS command is unavailable: ' + $commandName) }
}
$featureQuery = Invoke-SetupQuery -Name 'RDS feature inventory' -RequireData -Action { Get-WindowsFeature -Name $features -ErrorAction Stop }
if ($featureQuery.Succeeded) {
    if (@($featureQuery.Data).Count -ne $features.Count) { Set-SetupBlocked -Reason 'The required RDS features were not all reported.' }
    $missingFeatures = @($featureQuery.Data | Where-Object { -not $_.Installed } | Select-Object -ExpandProperty Name)
    $featureReadyAtEntry = $missingFeatures.Count -eq 0 -and @($featureQuery.Data).Count -eq $features.Count
}
$computerQuery = Invoke-SetupQuery -Name 'RDS domain member identity' -RequireData -Action { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
if ($computerQuery.Succeeded) {
    $computer = @($computerQuery.Data)[0]
    if ($computer.PartOfDomain -ne $true -or [int]$computer.DomainRole -ne 3) { Set-SetupBlocked -Reason 'A dedicated domain member server is required. Workgroup computers and domain controllers are excluded.' }
    if ($computer.DNSHostName -and $computer.Domain) { $localFqdn = ([string]$computer.DNSHostName + '.' + [string]$computer.Domain).ToLowerInvariant() }
    else { Set-SetupBlocked -Reason 'The domain member FQDN could not be established.' }
}
$installationQuery = Invoke-SetupQuery -Name 'Desktop Experience requirement' -RequireData -Action { Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType -ErrorAction Stop }
if ($installationQuery.Succeeded -and @($installationQuery.Data)[0].InstallationType -ne 'Server') { Set-SetupBlocked -Reason 'This RDS deployment requires Windows Server Desktop Experience; Server Core lacks Session Host and Web Access.' }
$conflictQuery = Invoke-SetupQuery -Name 'Conflicting server roles' -Action { Get-WindowsFeature -Name AD-Domain-Services,Hyper-V,ADCS-Cert-Authority -ErrorAction Stop | Where-Object { $_.Installed } }
if ($conflictQuery.Succeeded -and @($conflictQuery.Data).Count) { Set-SetupBlocked -Reason 'Use a dedicated member server without AD DS, Hyper-V, or certification authority roles.' }
$channelQuery = Invoke-SetupQuery -Name 'Domain secure channel' -RequireData -Action { Test-ComputerSecureChannel -ErrorAction Stop }
if ($channelQuery.Succeeded -and @($channelQuery.Data)[0] -ne $true) { Set-SetupBlocked -Reason 'The domain secure channel is not healthy.' }
if ($localFqdn) {
    $dnsQuery = Invoke-SetupQuery -Name 'Local RDS FQDN resolution' -RequireData -Action { Resolve-DnsName -Name $localFqdn -DnsOnly -ErrorAction Stop | Where-Object { $_.IPAddress } }
    $localAddressQuery = Invoke-SetupQuery -Name 'Local RDS IP address ownership' -RequireData -Action { Get-NetIPAddress -ErrorAction Stop }
    if ($dnsQuery.Succeeded -and $localAddressQuery.Succeeded) {
        foreach ($answer in @($dnsQuery.Data)) {
            if (@($localAddressQuery.Data | Where-Object { $_.IPAddress -eq $answer.IPAddress }).Count -eq 0) { Set-SetupBlocked -Reason 'The local RDS FQDN resolves to an address not assigned to this host. Correct DNS before deployment.' }
        }
    }
}

if (-not $ConfigureDeployment -and ($LicenseServer -or $PSBoundParameters.ContainsKey('LicensingMode') -or $CollectionName -or $CollectionUserGroup)) { Set-SetupBlocked -Reason 'Deployment, licensing, and collection options require -ConfigureDeployment.' }
if ($ConfigureDeployment) {
    if (-not $featureReadyAtEntry) { Set-SetupBlocked -Reason 'Install the RDS roles without -ConfigureDeployment first, restart manually, and rerun. Deployment creation never shares the role installation run.' }
    if ([string]::IsNullOrWhiteSpace($LicenseServer) -or -not $PSBoundParameters.ContainsKey('LicensingMode')) { Set-SetupBlocked -Reason 'Specify an existing LicenseServer FQDN and explicitly choose LicensingMode PerUser or PerDevice.' }
    if ($LicenseServer -notmatch '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z0-9-]+$') { Set-SetupBlocked -Reason 'LicenseServer must be a literal fully qualified DNS name.' }
    foreach ($commandName in @('New-RDSessionDeployment','Set-RDLicenseConfiguration','Get-RDLicenseConfiguration')) {
        if (-not (Test-SetupCommand -Name $commandName)) { Set-SetupBlocked -Reason ('Required deployment command is unavailable: ' + $commandName) }
    }
    if ($LicenseServer) { $licenseDnsQuery = Invoke-SetupQuery -Name 'License server DNS resolution' -RequireData -Action { Resolve-DnsName -Name $LicenseServer -DnsOnly -ErrorAction Stop | Where-Object { $_.IPAddress } } }
    $winrmQuery = Invoke-SetupQuery -Name 'WinRM service for RDS deployment' -RequireData -Action { Get-Service -Name WinRM -ErrorAction Stop }
    if ($winrmQuery.Succeeded -and @($winrmQuery.Data)[0].Status -ne 'Running') { Set-SetupBlocked -Reason 'WinRM must already be configured and running. This script does not enable remoting or weaken TrustedHosts.' }
    if ($CollectionName -or $CollectionUserGroup) {
        if ([string]::IsNullOrWhiteSpace($CollectionName) -or -not $CollectionUserGroup -or @($CollectionUserGroup).Count -eq 0) { Set-SetupBlocked -Reason 'Collection creation requires both CollectionName and explicit CollectionUserGroup values.' }
        if ($CollectionName -match '[\x00-\x1F]' -or $CollectionName.Length -gt 64) { Set-SetupBlocked -Reason 'CollectionName must be a printable name of at most 64 characters.' }
        foreach ($commandName in @('New-RDSessionCollection','Set-RDSessionCollectionConfiguration','Get-RDSessionCollectionConfiguration','Set-CimInstance')) {
            if (-not (Test-SetupCommand -Name $commandName)) { Set-SetupBlocked -Reason ('Required collection command is unavailable: ' + $commandName) }
        }
        $groupQuery = Invoke-SetupQuery -Name 'Collection group identity validation' -RequireData -Action {
            foreach ($group in @($CollectionUserGroup)) {
                if ([string]::IsNullOrWhiteSpace($group) -or $group -notmatch '^[^\\\r\n]+\\[^\\\r\n]+$') { throw 'Use explicit DOMAIN\Group names for collection access.' }
                $account = New-Object System.Security.Principal.NTAccount($group)
                $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
                [pscustomobject]@{ Group = $group; SID = $sid.Value }
            }
        }
        $logonQuery = Invoke-SetupQuery -Name 'Local RDS new-session control' -RequireData -Action { Get-CimInstance -Namespace 'root\cimv2\terminalservices' -ClassName Win32_TerminalServiceSetting -ErrorAction Stop }
        if ($logonQuery.Succeeded -and @($logonQuery.Data).Count -eq 1 -and [string]$logonQuery.Data[0].Logons -in @('0','1')) { $rdsOriginalLogons=[string]$logonQuery.Data[0].Logons }
        else { Set-SetupBlocked -Reason 'The current RDS new-session policy could not be verified. Collection creation requires a working local Terminal Services CIM provider.' }
        $notes.Add('While the new collection is configured, new RDS sessions are disabled locally; existing sessions stay connected. The prior new-session policy is restored only after access-group verification succeeds. A failed collection step leaves new sessions disabled; use console access to investigate before explicitly re-enabling logons.')
    }
}

if ($missingFeatures.Count -and -not $ConfigureDeployment) {
    Add-SetupStep -Name 'Install RDS role services' -Target 'Local server' -Action 'Install broker, Web Access, and Session Host roles with management tools; do not restart automatically' -Evidence 'A separate run after a manual restart is required to configure the deployment.'
    $roleResult = Invoke-SetupAction -Name 'Install RDS role services' -Target 'Local server' -Action {
        $result = Install-WindowsFeature -Name $missingFeatures -IncludeManagementTools -ErrorAction Stop
        if (-not $result.Success) { throw 'RDS feature installation did not succeed.' }
        if ([string]$result.RestartNeeded -ne 'No') { $script:setupRestartRequired = $true }
        $result | Select-Object Success,RestartNeeded,ExitCode
    }
}
elseif ($featureReadyAtEntry) { Add-SetupStep -Name 'RDS role services' -Target 'Local server' -Action 'Preserve installed role services' -Evidence 'All three roles were installed before this run.' -State 'Ready' }
if ($ConfigureDeployment) {
    Add-SetupStep -Name 'Create standard RDS session deployment' -Target $localFqdn -Action 'New-RDSessionDeployment with local broker, Web Access, and Session Host' -Evidence 'The create-only cmdlet rejects an existing deployment; this script never changes an existing farm.'
    $deploymentResult = Invoke-SetupAction -Name 'Create standard RDS session deployment' -Target $localFqdn -Action {
        New-RDSessionDeployment -ConnectionBroker $localFqdn -WebAccessServer $localFqdn -SessionHost @($localFqdn) -ErrorAction Stop
    }
    Add-SetupStep -Name 'Configure new deployment licensing' -Target $LicenseServer -Action ('Set-RDLicenseConfiguration with mode ' + $LicensingMode) -Evidence 'Points the newly created deployment at the specified server. Activation, CAL installation, version compatibility, and entitlements are not verified.'
    if (-not $Apply -or $deploymentResult.Succeeded) {
        $licenseResult = Invoke-SetupAction -Name 'Configure new deployment licensing' -Target $LicenseServer -Action {
            Set-RDLicenseConfiguration -ConnectionBroker $localFqdn -LicenseServer @($LicenseServer) -Mode $LicensingMode -Force -ErrorAction Stop
            $observed=@(Get-RDLicenseConfiguration -ConnectionBroker $localFqdn -ErrorAction Stop)
            if ($observed.Count -ne 1 -or [string]$observed[0].Mode -ne $LicensingMode -or @($observed[0].LicenseServer).Count -ne 1 -or [string]@($observed[0].LicenseServer)[0] -ine $LicenseServer) { throw 'The requested RDS licensing mode and server were not verified.' }
            [pscustomobject]@{ Mode=$LicensingMode; LicenseServer=$LicenseServer }
        }
    }
    if ($CollectionName) {
        Add-SetupStep -Name 'Suspend new RDS sessions' -Target $localFqdn -Action 'Temporarily set local Terminal Services Logons to disabled' -Evidence 'Prevents default collection access from accepting new sessions before explicit access groups are verified. Existing sessions are retained.'
        if (-not $Apply -or ($deploymentResult.Succeeded -and $licenseResult.Succeeded)) {
            $suspendResult = Invoke-SetupAction -Name 'Suspend new RDS sessions' -Target $localFqdn -Action {
                $current=@(Get-CimInstance -Namespace 'root\cimv2\terminalservices' -ClassName Win32_TerminalServiceSetting -ErrorAction Stop)
                if ($current.Count -ne 1 -or [string]$current[0].Logons -ne $rdsOriginalLogons) { throw 'The new-session policy changed after preflight.' }
                Set-CimInstance -InputObject $current[0] -Property @{Logons='1'} -ErrorAction Stop | Out-Null
                $verified=@(Get-CimInstance -Namespace 'root\cimv2\terminalservices' -ClassName Win32_TerminalServiceSetting -ErrorAction Stop)
                if ($verified.Count -ne 1 -or [string]$verified[0].Logons -ne '1') { throw 'New-session suspension could not be verified.' }
                [pscustomobject]@{ NewSessionsAllowed=$false }
            }
        }
        Add-SetupStep -Name 'Create session collection' -Target $CollectionName -Action 'Create a session collection and immediately restrict it to the explicit groups' -Evidence ('Groups: ' + (@($CollectionUserGroup) -join ', '))
        if (-not $Apply -or ($deploymentResult.Succeeded -and $licenseResult.Succeeded -and $suspendResult.Succeeded)) {
            $collectionResult = Invoke-SetupAction -Name 'Create session collection' -Target $CollectionName -Action {
                New-RDSessionCollection -CollectionName $CollectionName -SessionHost @($localFqdn) -ConnectionBroker $localFqdn -ErrorAction Stop | Out-Null
                Set-RDSessionCollectionConfiguration -CollectionName $CollectionName -ConnectionBroker $localFqdn -UserGroup $CollectionUserGroup -ErrorAction Stop
                $observed=@(Get-RDSessionCollectionConfiguration -CollectionName $CollectionName -ConnectionBroker $localFqdn -UserGroup -ErrorAction Stop)
                $reportedGroups=@()
                if ($observed.Count -eq 1 -and $observed[0].PSObject.Properties['UserGroup']) { $reportedGroups=@($observed[0].UserGroup) }
                elseif ($observed.Count -gt 0 -and @($observed | Where-Object { $_ -isnot [string] }).Count -eq 0) { $reportedGroups=@($observed) }
                if ($reportedGroups.Count -eq 0 -or @($reportedGroups | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) { throw 'The collection access groups were not reported as account names.' }
                $actualSids=@(foreach ($group in $reportedGroups) { (New-Object System.Security.Principal.NTAccount([string]$group)).Translate([System.Security.Principal.SecurityIdentifier]).Value }) | Sort-Object -Unique
                $expectedSids=@($groupQuery.Data | ForEach-Object { [string]$_.SID } | Sort-Object -Unique)
                if (($actualSids -join '|') -cne ($expectedSids -join '|')) { throw 'The collection access groups do not match the explicitly requested principals.' }
                [pscustomobject]@{ CollectionName=$CollectionName; AccessGroupCount=@($expectedSids).Count }
            }
        }
        Add-SetupStep -Name 'Restore prior RDS new-session policy' -Target $localFqdn -Action 'Restore the preflight Logons policy only after verified collection access' -Evidence 'Any failed collection or access-verification step leaves new sessions disabled for operator review.'
        if (-not $Apply -or $collectionResult.Succeeded) {
            $restoreResult = Invoke-SetupAction -Name 'Restore prior RDS new-session policy' -Target $localFqdn -Action {
                $current=@(Get-CimInstance -Namespace 'root\cimv2\terminalservices' -ClassName Win32_TerminalServiceSetting -ErrorAction Stop)
                if ($current.Count -ne 1 -or [string]$current[0].Logons -ne '1') { throw 'The suspended new-session state could not be verified.' }
                Set-CimInstance -InputObject $current[0] -Property @{Logons=$rdsOriginalLogons} -ErrorAction Stop | Out-Null
                $verified=@(Get-CimInstance -Namespace 'root\cimv2\terminalservices' -ClassName Win32_TerminalServiceSetting -ErrorAction Stop)
                if ($verified.Count -ne 1 -or [string]$verified[0].Logons -ne $rdsOriginalLogons) { throw 'The prior new-session policy was not restored.' }
                [pscustomobject]@{ RestoredLogonsPolicy=$rdsOriginalLogons }
            }
        }
    }
}
Complete-SetupReport -Notes @($notes)

} catch {
    Set-SetupBlocked -Reason 'Unexpected setup validation failure. No further changes were attempted; inspect prerequisites and native management logs.'
    Complete-SetupReport -Notes @('Unexpected error type: '+$_.Exception.GetType().FullName)
}
