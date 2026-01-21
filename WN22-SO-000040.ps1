<#
SYNOPSIS: Renames the built-in Guest account to a non-default name.

AUTHOR: Reginald D
STIG ID: WN22-SO-000040
SRG: SRG-OS-000480-GPOS-00227
SEVERITY: Medium (CAT II)
CCI: CCI-000366
VULNERABILITY ID: V-254448

VULNERABILITY DISCUSSION
The built-in Guest account is well-known and, by default, does not require a password.
Renaming it reduces the risk of unauthorized access to system resources and improves
overall system security.
#>

$NewGuestName="DisabledGuest"  # Replace with your desired name

# Get the current Guest account
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

if($guest){
    try{
        Rename-LocalUser -Name "Guest" -NewName $NewGuestName
        Write-Host "WN22-SO-000040 compliant: Guest account renamed to '$NewGuestName'."
    }catch{
        Write-Host "WN22-SO-000040 remediation failed: $_"
    }
}else{
    Write-Host "WN22-SO-000040 not applicable: Guest account does not exist."
}
