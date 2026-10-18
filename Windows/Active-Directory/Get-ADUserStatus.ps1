<#
What it does:
  Reports one Active Directory user's account status, lockout state, and password expiration.

Available flags:
  -Identity: Required user account name, distinguished name, GUID, or SID.
  -Server: Optional domain controller or AD domain to query.
  -OutputDirectory: Report destination; defaults to Windows\Reports.

How it works:
  Uses the ActiveDirectory module and your current account's directory read access, then saves CSV
  and JSON reports. LastLogonDate is approximate; failed queries are reported without changing the
  account.
#>
#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Identity,
    [string]$Server,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) { $OutputDirectory = Join-Path $PSScriptRoot '..\Reports' }
$reportDirectory = Join-Path $OutputDirectory ('10-ADUserStatus_{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $reportDirectory -Force -ErrorAction Stop
$record = $null; $problem = ''; $status = 'Success'
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $arguments = @{Identity=$Identity;Properties=@('Enabled','LockedOut','PasswordLastSet','PasswordExpired','PasswordNeverExpires','AccountExpirationDate','LastLogonDate','msDS-UserPasswordExpiryTimeComputed');ErrorAction='Stop'}
    if ($Server) { $arguments.Server = $Server }
    $user = Get-ADUser @arguments
    if ($null -eq $user) { throw 'The directory returned no user.' }
    $expiryUtc = $null; $expiryStatus = 'Unavailable'
    $rawExpiry = $user.'msDS-UserPasswordExpiryTimeComputed'
    if ($user.PasswordNeverExpires) { $expiryStatus = 'NeverExpires' }
    elseif ($null -ne $rawExpiry -and [string]$rawExpiry -ne '') {
        $ticks = [long]$rawExpiry
        if ($ticks -eq 0) { $expiryStatus = 'MustChangeAtNextLogonOrNotSet' }
        elseif ($ticks -eq [long]::MaxValue) { $expiryStatus = 'NoComputedExpiry' }
        else { $expiryUtc = [datetime]::FromFileTimeUtc($ticks).ToString('o'); $expiryStatus = 'Computed' }
    }
    $record = [pscustomobject]@{SamAccountName=$user.SamAccountName;Name=$user.Name;DistinguishedName=$user.DistinguishedName;Enabled=$user.Enabled;LockedOut=$user.LockedOut;PasswordExpired=$user.PasswordExpired;PasswordNeverExpires=$user.PasswordNeverExpires;PasswordLastSet=$user.PasswordLastSet;PasswordExpiryStatus=$expiryStatus;PasswordExpiresUtc=$expiryUtc;AccountExpirationDate=$user.AccountExpirationDate;LastLogonDateApproximate=$user.LastLogonDate}
    $record | Export-Csv -LiteralPath (Join-Path $reportDirectory 'user-status.csv') -NoTypeInformation -Encoding UTF8
} catch {
    $status = 'Failed'; $problem = $_.Exception.Message
    '"Status","Error"' , ('"Failed","{0}"' -f $problem.Replace('"','""')) | Set-Content -LiteralPath (Join-Path $reportDirectory 'user-status.csv') -Encoding UTF8
    Write-Warning ('AD user lookup failed: '+$problem)
}
$summary = [pscustomobject]@{ReportDirectory=$reportDirectory;Status=$status;RequestedIdentity=$Identity;Server=$Server;UserFound=($null -ne $record);Error=$problem}
[pscustomobject]@{Summary=$summary;User=$record} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $reportDirectory 'report.json') -Encoding UTF8
'Directory snapshot only. LastLogonDate is replicated/approximate. Password expiry is reported only when directory data supports it. Reports contain account identifiers and should be attached only to authorized tickets. No password, token, or recovery key is collected.' | Set-Content -LiteralPath (Join-Path $reportDirectory 'notes.txt') -Encoding UTF8
$summary

