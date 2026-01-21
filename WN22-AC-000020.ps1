<#
SYNOPSIS: Configures account lockout threshold to 3 or fewer invalid logon attempts.

AUTHOR: Reginald D
STIG ID: WN22-AC-000020
SRG: SRG-OS-000021-GPOS-00005
SEVERITY: Medium (CAT II)
CCI: CCI-000044
VULNERABILITY ID: V-254286

VULNERABILITY DISCUSSION
Account lockout helps prevent brute-force attacks. Limiting the number of allowed
failed logon attempts to three or fewer strengthens security while still allowing
for occasional user mistakes.
#>

$desiredThreshold=3
$currentThreshold=(net accounts | Select-String "Lockout threshold").ToString().Split(":")[1].Trim().Split(" ")[0]

if([int]$currentThreshold -eq 0 -or [int]$currentThreshold -gt $desiredThreshold){
    net accounts /lockoutthreshold:$desiredThreshold | Out-Null
    Write-Host "WN22-AC-000020 remediation applied: Lockout threshold set to $desiredThreshold attempts."
}else{
    Write-Host "WN22-AC-000020 compliant: Lockout threshold meets STIG requirements."
}
