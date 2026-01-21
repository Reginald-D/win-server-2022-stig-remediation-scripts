<#
SYNOPSIS: Disables insecure guest logons to SMB servers to prevent unauthenticated access.

AUTHOR: Reginald D

STIG ID: WN22-CC-000070
SRG: SRG-OS-000480-GPOS-00227
Severity: Medium (CAT II)
CCI: CCI-000366
Vulnerability ID: V-254339

VULNERABILITY DISCUSSION
Insecure guest logons permit unauthenticated access to shared folders over SMB.
This increases the risk of unauthorized data access and lateral movement.
Disabling this setting enforces authentication for all SMB connections.
#>

$Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$Name="AllowInsecureGuestAuth"

if(!(Test-Path $Path)){New-Item -Path $Path -Force|Out-Null}
Set-ItemProperty -Path $Path -Name $Name -Type DWord -Value 0

if((Get-ItemProperty -Path $Path -Name $Name).AllowInsecureGuestAuth -eq 0){
    Write-Host "WN22-CC-000070 compliant: Insecure SMB guest logons disabled."
}else{
    Write-Host "WN22-CC-000070 non-compliant: remediation failed."

}


