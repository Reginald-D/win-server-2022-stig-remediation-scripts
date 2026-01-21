# Windows Server 2022 STIG Remediation via PowerShell

This repository provides a growing collection of PowerShell scripts designed to automate STIG (Security Technical Implementation Guide) remediations for Windows Server 2022 Datacenter environments. Each script directly addresses a specific DISA STIG ID, ensuring your server configurations meet DoD and industry security compliance standards.

# Implemented STIG Remediations

| Date       | STIG ID | GitHub | Description |
|-----------|-----------------|------------|------------|
| 01/21/2026 | WN22-AC-000010 | [Link](https://github.com/Reginald-D/win-server-2022-stig-remediation-scripts/blob/main/WN22-AC-000010.ps1) | Enforces minimum admin password length |
| 01/21/2026 | WN22-AC-000020 | [Link](https://github.com/Reginald-D/win-server-2022-stig-remediation-scripts/blob/main/WN22-AC-000020.ps1) | Requires password complexity |
| 01/21/2026 | WN22-AC-000030 | [Link](https://github.com/Reginald-D/win-server-2022-stig-remediation-scripts/blob/main/WN22-AC-000030.ps1) | Sets account lockout threshold |
| 01/21/2026 | WN22-AC-000040 | [Link](https://github.com/Reginald-D/win-server-2022-stig-remediation-scripts/blob/main/WN22-AC-000040.ps1) | Enforces password history by preventing reuse for enchanced security |
| 01/21/2026 | WN22-CC-000070 | [Link](https://github.com/Reginald-D/win-server-2022-stig-remediation-scripts/blob/main/WN22-CC-000070.ps1) | Auto logoff after inactivity to prevent unauthorized access |
| 01/21/2026 | WN22-CC-000500 | [Link](https://github.com/Reginald-D/win-server-2022-stig-remediation-scripts/blob/main/WN22-CC-000500.ps1) | Requires audit logging of account management changes |
| 01/21/2026 | WN22-SO-000040 | [Link](https://github.com/Reginald-D/win-server-2022-stig-remediation-scripts/blob/main/WN22-SO-000040.ps1) | Uses secure cryptographic protocols to protect network communications |
| 01/21/2026 | WN22-SO-000120 | [Link](https://github.com/Reginald-D/win-server-2022-stig-remediation-scripts/blob/main/WN22-SO-000120.ps1) | Disables unnecessary services to harden the server configuration|
| 01/21/2026 | WN22-SO-000150 | [Link](https://github.com/Reginald-D/win-server-2022-stig-remediation-scripts/blob/main/WN22-SO-000150.ps1) | Retains and protects event logs for forensic and compliance purposes|
| 01/21/2026 | WN22-SO-000190 | [Link](https://github.com/Reginald-D/win-server-2022-stig-remediation-scripts/blob/main/WN22-SO-000190.ps1) | Ensures antivirus is active and updated to prevent infected and compromised systems |
