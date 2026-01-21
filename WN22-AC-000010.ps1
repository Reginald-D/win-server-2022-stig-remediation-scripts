<#
SYNOPSIS: Configures account lockout duration to 15 minutes or greater.

AUTHOR: Reginald D
STIG ID: WN22-AC-000010
SRG: SRG-OS-000329-GPOS-00128
SEVERITY: Medium (CAT II)
CCI: CCI-002238
VULNERABILITY ID: V-254285

VULNERABILITY DISCUSSION
Account lockout helps prevent brute-force attacks. Configuring the lockout duration
ensures that accounts remain inaccessible for a sufficient period after failed logon
attempts, mitigating unauthorized access risks.
#>

$desiredDuration=15  # minutes; 0 = admin unlock
$currentDuration=(net accounts | Select-String "Lockout duration").ToString().Split(":")[1].Trim().Split(" ")[0]

if([int]$currentDuration -lt $desiredDuration -and [int]$currentDuration -ne 0){
    net accounts /lockoutduration:$desiredDuration | Out-Null
    Write-Host "WN22-AC-000010 remediation applied: Lockout duration set to $desiredDuration minutes."
}elseif([int]$currentDuration -eq 0){
    Write-Host "WN22-AC-000010 compliant: Lockout duration is 0 (admin unlock)."
}else{
    Write-Host "WN22-AC-000010 compliant: Lockout duration meets STIG requirements."
}
