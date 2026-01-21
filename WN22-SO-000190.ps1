<#
SYNOPSIS: Enables SMB server to digitally sign all communications.

AUTHOR: Reginald D
STIG ID: WN22-SO-000190
SRG: SRG-OS-000423-GPOS-00187
SEVERITY: Medium (CAT II)
CCI: CCI-002418,CCI-002421
VULNERABILITY ID: V-254463

VULNERABILITY DISCUSSION
Digitally signing SMB packets prevents man-in-the-middle attacks by ensuring
communications between SMB clients and servers are authenticated. Enabling this
setting ensures only clients that support SMB signing can communicate with the server.
#>

$regPath="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$regName="RequireSecuritySignature"
$desiredValue=1

if(-not (Test-Path $regPath)){New-Item -Path $regPath -Force|Out-Null}
Set-ItemProperty -Path $regPath -Name $regName -Type DWord -Value $desiredValue

$currentValue=(Get-ItemProperty -Path $regPath -Name $regName).RequireSecuritySignature
if($currentValue -eq $desiredValue){
    Write-Host "WN22-SO-000190 compliant: SMB server requires digital signing."
}else{
    Write-Host "WN22-SO-000190 non-compliant: remediation failed."
}
