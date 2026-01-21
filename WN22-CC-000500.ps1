<#
SYNOPSIS: Disables WinRM Basic authentication.

AUTHOR: Reginald D
STIG ID:WN22-CC-000500
SRG: SRG-OS-000125-GPOS-00065
SEVERITY: High (CAT I)
CCI: CCI-000877
VULNERABILITY ID: V-254381

VULNERABILITY DISCUSSION
Basic authentication transmits credentials in plain text and can be intercepted,
leading to potential system compromise. Disabling Basic authentication reduces
this risk by enforcing stronger authentication mechanisms for WinRM.
#>

$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$Name = "AllowBasic"

if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name $Name -Type DWord -Value 0

if ((Get-ItemProperty $Path).AllowBasic -eq 0) {
    Write-Host "WinRM Basic authentication disabled (STIG compliant)."
} else {
    Write-Host "WinRM Basic authentication remediation failed."
}


