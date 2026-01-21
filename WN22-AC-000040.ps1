<#
SYNOPSIS: Configures password history to remember 24 previous passwords.

AUTHOR: Reginald D
STIG ID: WN22-AC-000040
SRG: SRG-OS-000077-GPOS-00045
SEVERITY: Medium (CAT II)
CCI: CCI-004061
VULNERABILITY ID: V-254288

VULNERABILITY DISCUSSION
Recycling old passwords reduces the effectiveness of periodic password changes.
Enforcing a history of 24 passwords prevents users from reusing recent passwords,
strengthening account security.
#>

$desiredHistory = 24

try {
    $currentHistory = (Get-LocalUser | ForEach-Object { net accounts }).ToString() -match "Password history size\s+(\d+)"
    if($matches[1]) { $currentHistory = [int]$matches[1] } else { $currentHistory = 0 }
}catch{
    $currentHistory = 0
}

if($currentHistory -lt $desiredHistory){
    secedit /export /cfg C:\Temp\SecPolicy.cfg
    secedit /configure /db C:\Windows\security\Database\secedit.sdb /cfg C:\Temp\SecPolicy.cfg /areas SECURITYPOLICY
    net accounts /uniquepw:$desiredHistory | Out-Null
    Write-Host "WN22-AC-000040 remediation applied: Password history set to $desiredHistory passwords."
}else{
    Write-Host "WN22-AC-000040 compliant: Password history meets STIG requirements."
}
