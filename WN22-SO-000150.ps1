<#
SYNOPSIS: Configures Smart Card removal behavior to lock the workstation or force logoff.

AUTHOR: Reginald D
STIG ID: WN22-SO-000150
SRG: SRG-OS-000480-GPOS-00227
SEVERITY: Medium (CAT II)
CCI: CCI-000366
VULNERABILITY ID: V-254459

VULNERABILITY DISCUSSION
Unattended systems are vulnerable to unauthorized use. Configuring Smart Card removal
to lock the workstation or force logoff ensures the system is inaccessible when
the user is away, protecting sensitive data from unauthorized access.
#>

$regPath="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$regName="Scremoveoption"
$desiredValue=1  # 1=Lock Workstation, 2=Force Logoff

if(-not (Test-Path $regPath)){New-Item -Path $regPath -Force|Out-Null}
Set-ItemProperty -Path $regPath -Name $regName -Type String -Value $desiredValue

$currentValue=(Get-ItemProperty -Path $regPath -Name $regName).Scremoveoption
if($currentValue -eq $desiredValue){
    Write-Host "WN22-SO-000150 compliant: Smart Card removal behavior configured."
}else{
    Write-Host "WN22-SO-000150 non-compliant: remediation failed."
}
