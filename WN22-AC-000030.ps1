<#
SYNOPSIS: Configures the period before the account lockout counter is reset to 15 minutes or greater.

AUTHOR: Reginald D
STIG ID: WN22-AC-000030
SRG: SRG-OS-000021-GPOS-00005
SEVERITY: Medium (CAT II)
CCI: CCI-000044
VULNERABILITY ID: V-254287

VULNERABILITY DISCUSSION
Account lockout prevents brute-force attacks. Configuring the reset period ensures the
bad logon counter remains effective by requiring a minimum time before failed attempts
are cleared, reducing the chance of repeated unauthorized access.
#>

$desiredReset=15   # minutes
$resetLine = $netAccounts | Where-Object { $_ -match "Reset account lockout counter" }

if([int]$currentReset -lt $desiredReset){
    net accounts /lockoutwindow:$desiredReset | Out-Null
    Write-Host "WN22-AC-000030 remediation applied: Reset counter set to $desiredReset minutes."
}else{
    Write-Host "WN22-AC-000030 compliant: Reset counter meets STIG requirements."
}
