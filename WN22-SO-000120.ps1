<#
SYNOPSIS:Configures the machine inactivity limit to lock the system after 15 minutes of inactivity.


AUTHOR: Reginald D
STIGID: WN22-SO-000120
SRG: SRG-OS-000028-GPOS-00009
Severity: Medium (CAT II)
CCI: CCI-000056, CCI-000057, CCI-000060
Vulnerability ID: V-254456


.VULNERABILITY DISCUSSION
Unattended systems are vulnerable to unauthorized use. Enforcing a machine inactivity
limit ensures the system locks automatically after a defined period, protecting
sensitive data from unauthorized physical access.
#>

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$regName = "InactivityTimeoutSecs"
$timeout = 900

if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name $regName -Type DWord -Value $timeout