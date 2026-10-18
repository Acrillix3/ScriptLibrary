<#
What it does:
  Reports certificate expiry, intended usage, and optional chain-trust results from selected local
  stores.

Available flags:
  -StorePath: 1-20 direct LocalMachine/CurrentUser certificate stores; default both My stores.
  -Subject: Optional subject wildcard filter.
  -ExpiringWithinDays: Expiry warning window, 0-3650 days; default 30.
  -RequiredEkuOid: Optional intended-usage OID to compare with certificate EKUs.
  -CheckTrust: Build chains using the executing account's trust context; revocation is not checked.
  -MaxCertificates: Maximum matching certificates inspected, 1-10000; default 1000.
  -MaxTrustChecks: Maximum chain builds, 1-1000; default 50.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Reads certificate metadata through the Windows certificate provider and classifies date/usage
  findings. Optional chain building can retrieve issuer certificates; key access, endpoint identity,
  and revocation are not tested, and private keys are never exported.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateCount(1,20)][ValidatePattern('^Cert:\\(?:LocalMachine|CurrentUser)\\[^\\/:*?]+$')][string[]]$StorePath = @('Cert:\LocalMachine\My','Cert:\CurrentUser\My'),
    [ValidateNotNullOrEmpty()][string]$Subject,
    [ValidateRange(0,3650)][int]$ExpiringWithinDays = 30,
    [ValidatePattern('^\d+(?:\.\d+)+$')][string]$RequiredEkuOid,
    [switch]$CheckTrust,
    [ValidateRange(1,10000)][int]$MaxCertificates = 1000,
    [ValidateRange(1,1000)][int]$MaxTrustChecks = 50,
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

$now=Get-Date
$rows=New-Object 'System.Collections.Generic.List[object]'
$certificatesInspected=0;$inventoryTruncated=$false;$trustChecksAttempted=0;$trustChecksSkipped=0
$uninspectedStores=New-Object 'System.Collections.Generic.List[string]'
foreach($store in @($StorePath | Sort-Object -Unique)){
    if($inventoryTruncated){
        $uninspectedStores.Add($store)
        $queryLog.Add([pscustomobject]@{Section=('CertificateStore:'+ $store);Status='Skipped';Count=0;Error='Certificate inspection cap was reached in an earlier store.'})
        continue
    }
    $remaining=$MaxCertificates-$certificatesInspected
    $inventory=Invoke-ReportQuery ('CertificateStore:'+ $store) {
        Get-ChildItem -LiteralPath $store -ErrorAction Stop | Where-Object {-not $Subject -or $_.Subject -like $Subject} | Select-Object -First ($remaining+1)
    }
    foreach($cert in @($inventory.Data)){
        if($certificatesInspected -ge $MaxCertificates){
            $inventoryTruncated=$true
            $queryLog.Add([pscustomobject]@{Section='CertificateInspectionScope';Status='Truncated';Count=$certificatesInspected;Error='At least one additional matching certificate was observed but not inspected.'})
            break
        }
        $certificatesInspected++
        $metadata=Invoke-ReportQuery ('CertificateMetadata:'+ $store+'\'+$cert.Thumbprint) {
            if($null -eq $cert.NotBefore -or $null -eq $cert.NotAfter -or -not $cert.Thumbprint){throw 'Certificate identity or validity dates were unavailable.'}
            $validity='ValidBeyondWarningWindow'
            if($cert.NotAfter -lt $now){$validity='Expired'}elseif($cert.NotBefore -gt $now){$validity='NotYetValid'}elseif($cert.NotAfter -le $now.AddDays($ExpiringWithinDays)){$validity='ExpiringSoon'}
            $ekuExtension=@($cert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.37'})
            $ekuOids=@();$ekuNames=@();$ekuAssessment='NoEkuRestriction'
            if($ekuExtension.Count){
                $decoded=New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension
                $decoded.CopyFrom($ekuExtension[0])
                $ekuOids=@($decoded.EnhancedKeyUsages | ForEach-Object {$_.Value})
                $ekuNames=@($decoded.EnhancedKeyUsages | ForEach-Object {$_.FriendlyName})
                $ekuAssessment='ListedEkus'
            }
            if($RequiredEkuOid){
                if(-not $ekuExtension.Count){$ekuAssessment='NoEkuRestriction'}
                elseif($RequiredEkuOid -in $ekuOids -or '2.5.29.37.0' -in $ekuOids){$ekuAssessment='RequiredEkuAllowed'}
                else{$ekuAssessment='RequiredEkuNotListed'}
            }
            [pscustomobject]@{Store=$store;Subject=$cert.Subject;Issuer=$cert.Issuer;Thumbprint=$cert.Thumbprint;SerialNumber=$cert.SerialNumber;NotBefore=$cert.NotBefore;NotAfter=$cert.NotAfter;DaysUntilExpiry=[math]::Floor(($cert.NotAfter-$now).TotalDays);Validity=$validity;EkuOids=($ekuOids -join ';');EkuNames=($ekuNames -join ';');EkuAssessment=$ekuAssessment;RequiredEkuOid=$RequiredEkuOid;HasPrivateKeyAssociation=[bool]$cert.HasPrivateKey;KeyAccessibility='NotTested';TrustAssessment='NotChecked';ChainStatus='';TrustError=''}
        } -RequireData
        if(-not $metadata.Succeeded){continue}
        $row=$metadata.Data[0]
        if($CheckTrust -and $trustChecksAttempted -ge $MaxTrustChecks){
            $row.TrustAssessment='SkippedByLimit';$trustChecksSkipped++
        }elseif($CheckTrust){
            $trustChecksAttempted++
            $chainResult=Invoke-ReportQuery ('CertificateChain:'+ $store+'\'+$cert.Thumbprint) {
                $chain=$null
                try{
                    $chain=New-Object System.Security.Cryptography.X509Certificates.X509Chain
                    $chain.ChainPolicy.RevocationMode=[System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                    $chain.ChainPolicy.VerificationFlags=[System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
                    $chain.ChainPolicy.VerificationTime=$now
                    $chain.ChainPolicy.UrlRetrievalTimeout=[timespan]::FromSeconds(3)
                    if($RequiredEkuOid){$null=$chain.ChainPolicy.ApplicationPolicy.Add((New-Object System.Security.Cryptography.Oid -ArgumentList $RequiredEkuOid))}
                    $trusted=$chain.Build($cert)
                    [pscustomobject]@{TrustAssessment=$(if($trusted){'ChainAcceptedWithoutRevocation'}else{'ChainRejected'});ChainStatus=(@($chain.ChainStatus | ForEach-Object {$_.Status.ToString()+': '+$_.StatusInformation.Trim()}) -join ';')}
                }finally{if($null -ne $chain){$chain.Dispose()}}
            } -RequireData
            if($chainResult.Succeeded){$row.TrustAssessment=$chainResult.Data[0].TrustAssessment;$row.ChainStatus=$chainResult.Data[0].ChainStatus}
            else{$row.TrustAssessment='Unknown';$row.TrustError='Chain evaluation failed; see query-errors.csv.'}
        }
        $rows.Add($row)
    }
}
if($trustChecksSkipped){$queryLog.Add([pscustomobject]@{Section='CertificateTrustScope';Status='Truncated';Count=$trustChecksAttempted;Error=($trustChecksSkipped.ToString()+' reported certificates skipped chain building because MaxTrustChecks was reached.')})}
Write-ReportCsv 'certificates' $rows.ToArray() @('Store','Subject','Issuer','Thumbprint','SerialNumber','NotBefore','NotAfter','DaysUntilExpiry','Validity','EkuOids','EkuNames','EkuAssessment','RequiredEkuOid','HasPrivateKeyAssociation','KeyAccessibility','TrustAssessment','ChainStatus','TrustError')
Complete-Report -Data ([pscustomobject]@{Stores=$StorePath;SubjectFilter=$Subject;ExpiringWithinDays=$ExpiringWithinDays;MaxCertificates=$MaxCertificates;CertificatesInspected=$certificatesInspected;InventoryTruncated=$inventoryTruncated;UninspectedStores=$uninspectedStores.ToArray();CertificatesReported=$rows.Count;Expired=@($rows | Where-Object Validity -eq 'Expired').Count;ExpiringSoon=@($rows | Where-Object Validity -eq 'ExpiringSoon').Count;NotYetValid=@($rows | Where-Object Validity -eq 'NotYetValid').Count;TrustRequested=[bool]$CheckTrust;MaxTrustChecks=$MaxTrustChecks;TrustChecksAttempted=$trustChecksAttempted;TrustChecksSkippedDueToLimit=$trustChecksSkipped;TrustRejected=@($rows | Where-Object TrustAssessment -eq 'ChainRejected').Count;RequiredEkuNotListed=@($rows | Where-Object EkuAssessment -eq 'RequiredEkuNotListed').Count}) -Notes @(
    'Selected stores are local to this computer; CurrentUser is the executing account. Empty readable stores are distinct from inaccessible stores.'
    'HasPrivateKeyAssociation reports certificate metadata only. No private key is opened, exported, or tested for service-account accessibility; a false value is not proof that a required key is lost.'
    'CheckTrust is optional and uses the current account trust context. It may retrieve issuer certificates; revocation is deliberately not checked, and chain acceptance is not endpoint identity or application compatibility validation.'
    'MaxCertificates caps inspected matches across stores, and MaxTrustChecks caps attempted chain builds. Truncation and skipped stores/checks are explicit; counts describe inspected evidence, not total inventory. Collection Complete can still be deliberately scoped.'
    'Certificate provider enumeration and chain network retrieval have no guaranteed total runtime. The chain URL timeout is not an overall script or chain-build deadline.'
    'No EKU extension means no EKU restriction in this certificate, not guaranteed suitability for an application. Other extensions and application policy can still restrict use.'
    'Date findings depend on the local clock. No renewal, installation, deletion, or trust-store changes are performed.'
    'Reference: https://learn.microsoft.com/powershell/module/microsoft.powershell.security/about/about_certificate_provider'
)
