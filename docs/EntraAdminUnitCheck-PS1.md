# Invoke-EntraAdminUnitCheck.ps1

## Overview

`Invoke-EntraAdminUnitCheck.ps1` is a PowerShell 7+ script designed to enumerate and analyze Azure Entra ID Administrative Units and their scoped role assignments. This tool is part of the EvilMist toolkit and helps security teams identify who has administrative privileges scoped to specific Administrative Units, assess the security posture of scoped administrators, and identify potential privilege escalation paths.

## Purpose

Administrative Units allow organizations to delegate administrative control to specific subsets of users, groups, or devices. Scoped role assignments grant administrators privileges limited to their assigned Administrative Unit. This script helps:

- **Security Auditors**: Identify scoped administrators and assess their security posture
- **Penetration Testers**: Discover scoped admin access for privilege escalation
- **IT Administrators**: Audit Administrative Unit configurations and scoped role assignments
- **Compliance Teams**: Generate reports for delegated administrative access governance

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Administrative Unit Enumeration**: Lists all AUs with configuration details
- ✅ **Scoped Role Assignment Analysis**: Identifies all scoped administrators and their roles
- ✅ **Member Enumeration**: Shows AU members and their roles
- ✅ **MFA Status Detection**: Identifies scoped administrators without Multi-Factor Authentication
- ✅ **Last Sign-In Tracking**: Shows last login date/time and activity patterns
- ✅ **Risk Assessment**: Categorizes assignments by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **Activity Analytics**: Sign-in statistics, stale accounts, inactive administrators
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only administrators without MFA or include disabled accounts

## Administrative Units Explained

Administrative Units (AUs) are containers that can hold users, groups, and devices. They enable organizations to:

- **Delegate Administration**: Grant administrative privileges scoped to specific AUs instead of the entire tenant
- **Organize by Geography**: Create AUs for different regions or offices
- **Organize by Department**: Create AUs for different business units
- **Limit Administrative Scope**: Reduce the blast radius of compromised admin accounts

### Scoped Role Assignments

When a role is assigned with an Administrative Unit scope, the administrator can only manage objects within that AU:

- **Global Admin Scoped to AU**: Can manage users/groups/devices only in that AU (not tenant-wide)
- **User Admin Scoped to AU**: Can create/modify/delete users only in that AU
- **Groups Admin Scoped to AU**: Can manage groups only in that AU

### Risk Implications

Scoped administrators pose unique security risks:

- **Privilege Escalation**: Compromised scoped admin can escalate within their AU
- **Lateral Movement**: Scoped admins can move between AUs if they have multiple assignments
- **Hidden Administrative Access**: Scoped assignments may be overlooked in security audits
- **MFA Gaps**: Scoped admins without MFA are high-value targets

## Requirements

### Prerequisites

1. **PowerShell 7+**
   - Download: https://aka.ms/powershell-release?tag=stable
   - The script will check and warn if older version is detected

2. **Microsoft Graph PowerShell SDK**
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```
   
   Or install individual modules:
   ```powershell
   Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
   Install-Module Microsoft.Graph.Users -Scope CurrentUser
   Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
   Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
   ```

### Required Permissions

The script requires the following Microsoft Graph API permissions:

- **Primary Scopes** (preferred):
  - `Directory.Read.All` - Read directory data
  - `AdministrativeUnit.Read.All` - Read Administrative Units
  - `RoleManagement.Read.Directory` - Read scoped role assignments
  - `User.Read.All` - Read all user profiles
  - `UserAuthenticationMethod.Read.All` - Read authentication methods

- **Fallback Scopes** (if full access unavailable):
  - `Directory.Read.All` - Read directory data
  - `AdministrativeUnit.Read.All` - Read Administrative Units
  - `User.ReadBasic.All` - Read basic user info

**Note**: If `RoleManagement.Read.Directory` is not available, the script will not be able to retrieve scoped role assignments. Administrative Unit enumeration will still work.

## Usage

### Basic Usage

```powershell
# Simple scan of all Administrative Units and scoped role assignments
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -ExportPath "admin-units.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -ExportPath "admin-units.json"
```

### Include Disabled User Accounts

```powershell
# Scan all administrators including disabled accounts
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -IncludeDisabledUsers -ExportPath "all-admins.csv"
```

### Show Only Administrators Without MFA

```powershell
# Filter to show only scoped administrators without MFA
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -OnlyNoMFA

# Matrix view with MFA filter
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -OnlyNoMFA -Matrix
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all administrators, all AUs, with export
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "full-audit.csv"

# Security focus: high-risk administrators only (no MFA)
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -OnlyNoMFA -Matrix -ExportPath "high-risk-admins.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
```

## Parameters

### General Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-ExportPath` | String | Path to export results (CSV or JSON based on extension) | None |
| `-TenantId` | String | Optional Tenant ID. Uses home tenant if not specified | None |
| `-UseAzCliToken` | Switch | Try to use Azure CLI cached token first | False |
| `-UseAzPowerShellToken` | Switch | Try to use Azure PowerShell cached token first | False |
| `-IncludeDisabledUsers` | Switch | Include disabled user accounts in results | False |
| `-OnlyNoMFA` | Switch | Show only scoped administrators without MFA enabled | False |
| `-Matrix` | Switch | Display results in matrix/table format | False |

### Stealth & Evasion Parameters

| Parameter | Type | Range | Description | Default |
|-----------|------|-------|-------------|---------|
| `-EnableStealth` | Switch | - | Enable stealth mode with default delays (500ms + 300ms jitter) | False |
| `-RequestDelay` | Double | 0-60 | Base delay in seconds between API requests | 0 |
| `-RequestJitter` | Double | 0-30 | Random jitter range in seconds (+/-) | 0 |
| `-MaxRetries` | Int | 1-10 | Maximum retries on throttling (429) responses | 3 |
| `-QuietStealth` | Switch | - | Suppress stealth-related status messages | False |

## Output

### Standard Output

The script provides detailed information about each scoped role assignment:

```
[CRITICAL] Sales Department - User Administrator
  Principal Name: John Admin
  Principal Type: User
  User Principal Name: john.admin@company.com
  Display Name: John Admin
  Email: john.admin@company.com
  Job Title: IT Administrator
  Department: IT
  Administrative Unit: Sales Department
  AU Visibility: Public
  Role: User Administrator
  Role Risk Level: HIGH
  Account Status: Enabled
  MFA Enabled: No
  Auth Methods: Password Only
  Last Sign-In: 2024-12-20 14:23:45 (3 days ago) (Interactive)
  Created: 2023-05-10T08:15:00Z (591 days old)
  Licenses: 2 assigned
```

### Matrix Output (with `-Matrix`)

```
Risk      Role Risk  MFA  Type  Status   Admin Unit         Role                Principal Name    User Principal Name      Last Sign-In  Department
----      ---------  ---  ----  ------   -----------         ----                --------------    -------------------      ------------  ----------
CRITICAL  HIGH       No   User  Enabled  Sales Department    User Administrator  John Admin       john.admin@company.com   3d ago        IT
HIGH      HIGH       Yes  User  Enabled  IT Department       Groups Administrator Jane Secure      jane.secure@company.com   1d ago        Security
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total Administrative Units: 5
Total scoped role assignments: 12
Unique user administrators: 8
  - CRITICAL risk: 3
  - HIGH risk: 5
  - MEDIUM risk: 3
  - LOW risk: 1

[MFA STATUS]
  With MFA enabled: 7
  Without MFA: 5

[ASSIGNMENTS BY ADMINISTRATIVE UNIT]
  Sales Department: 4
  IT Department: 3
  HR Department: 2
  Finance Department: 2
  Operations Department: 1

[ASSIGNMENTS BY ROLE]
  User Administrator: 5
  Groups Administrator: 3
  Helpdesk Administrator: 2
  Authentication Administrator: 1
  Directory Readers: 1

[TOP DEPARTMENTS]
  IT: 5
  Security: 3
  Operations: 2

[SIGN-IN ACTIVITY]
  Never signed in: 0
  Recent (≤30 days): 10
  Stale (>90 days): 2
```

## Risk Levels

The script assigns risk levels based on role criticality, MFA status, and account status:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | HIGH/CRITICAL role WITHOUT MFA OR CRITICAL role with active account | Red | **IMMEDIATE ACTION REQUIRED**: Enable MFA or review assignment |
| **HIGH** | HIGH role WITHOUT MFA OR MEDIUM role without MFA | Yellow | **HIGH PRIORITY**: Enable MFA immediately |
| **MEDIUM** | MEDIUM/LOW role OR HIGH role with MFA | Green | Monitor: Acceptable risk with MFA |
| **LOW** | LOW role with MFA OR disabled account | Gray | Monitor: Low risk |

### Risk Assessment Logic

```
IF role is CRITICAL:
    IF no MFA: RISK = CRITICAL
    ELSE: RISK = MEDIUM
ELSE IF role is HIGH:
    IF no MFA: RISK = CRITICAL
    ELSE: RISK = MEDIUM
ELSE IF role is MEDIUM:
    IF no MFA: RISK = HIGH
    ELSE: RISK = MEDIUM
ELSE (LOW role):
    IF no MFA: RISK = MEDIUM
    ELSE: RISK = LOW
```

### Roles Analyzed

The script categorizes roles by risk level:

#### CRITICAL Roles
- Global Administrator
- Privileged Role Administrator
- Privileged Authentication Administrator

#### HIGH Roles
- User Administrator
- Groups Administrator
- Authentication Administrator
- Password Administrator
- Helpdesk Administrator
- Security Administrator
- Compliance Administrator

#### MEDIUM Roles
- Application Administrator
- License Administrator
- Billing Administrator

#### LOW Roles
- Directory Readers
- Directory Writers
- Guest Inviter

## Security Considerations

### Why Scoped Administrators Matter

Scoped administrators have administrative privileges limited to their assigned Administrative Unit:

- **Limited Scope**: Can only manage objects within their AU (not tenant-wide)
- **Privilege Escalation Risk**: Compromised scoped admin can escalate within their AU
- **Hidden Access**: Scoped assignments may be overlooked in security audits
- **MFA Gaps**: Scoped admins without MFA are high-value targets

### High-Risk Scenarios

1. **Scoped Admin Without MFA** (CRITICAL/HIGH Risk)
   - Can authenticate with just username/password
   - Has administrative privileges scoped to their AU
   - High likelihood of credential stuffing/phishing success

2. **Multiple AU Assignments** (Variable Risk)
   - Administrators with assignments to multiple AUs
   - Increased attack surface and lateral movement potential
   - May indicate over-privileged accounts

3. **Stale Assignments** (MEDIUM Risk)
   - Administrators who haven't signed in for 90+ days but still have scoped access
   - May indicate forgotten or orphaned accounts
   - Potential for account takeover if credentials leaked

4. **Hidden Administrative Units** (MEDIUM Risk)
   - AUs with HiddenMembership visibility
   - May hide sensitive administrative assignments
   - Requires careful review

### Best Practices

#### For Security Teams

1. **Regular Audits**: Run monthly to track scoped admin access changes
2. **MFA Enforcement**: Ensure all scoped administrators have MFA enabled
3. **Least Privilege**: Review assignments and remove unnecessary scoped access
4. **Monitor Activity**: Track sign-in patterns and unusual behavior
5. **Document Changes**: Maintain records of who has scoped access and why

#### For Penetration Testers

1. **Initial Reconnaissance**: Identify scoped administrators and their AUs
2. **Target Selection**: Prioritize CRITICAL/HIGH risk scoped admins without MFA
3. **Privilege Escalation**: Focus on scoped admins for AU-level escalation
4. **Lateral Movement**: Document scoped assignments for movement between AUs
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

#### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify scoped access aligns with business needs
3. **Trend Analysis**: Compare results over time
4. **Remediation Tracking**: Monitor MFA adoption rates
5. **Access Reviews**: Use reports for quarterly access certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- AdminUnitId, AdminUnitName, AdminUnitVisibility
- RoleDefinitionId, RoleName, RoleRiskLevel
- PrincipalId, PrincipalName, PrincipalType, PrincipalUPN
- DisplayName, Email, AccountEnabled, UserType
- JobTitle, Department
- CreatedDateTime, DaysOld
- LastSignIn, LastSignInDisplay, DaysSinceLastSignIn, SignInType
- MFAEnabled, AuthMethods, MethodCount
- HasLicenses, LicenseCount
- RiskLevel

### JSON Export

Structured format for automation:
```json
[
  {
    "AdminUnitId": "12345678-1234-1234-1234-123456789012",
    "AdminUnitName": "Sales Department",
    "AdminUnitVisibility": "Public",
    "RoleName": "User Administrator",
    "RoleRiskLevel": "HIGH",
    "PrincipalName": "John Admin",
    "PrincipalUPN": "john.admin@company.com",
    "MFAEnabled": false,
    "AuthMethods": "Password Only",
    "RiskLevel": "CRITICAL",
    "LastSignInDisplay": "2024-12-20 14:23:45 (3 days ago)",
    "DaysSinceLastSignIn": 3
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "No Administrative Units found in this tenant"

**Cause**: The tenant doesn't have any Administrative Units configured.

**Solution**: 
- Administrative Units are optional features
- They must be explicitly created by administrators
- This is normal for tenants not using AU delegation

#### 2. "No scoped role assignments found"

**Cause**: No roles have been assigned with Administrative Unit scope.

**Solution**:
- Check if Administrative Units exist
- Verify roles are assigned with AU scope (not tenant-wide)
- Ensure you have `RoleManagement.Read.Directory` permission

#### 3. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1
# Accept permission consent when prompted
```

#### 4. Module Import Failures

**Cause**: Missing or outdated Microsoft.Graph modules.

**Solution**:
```powershell
# Update all Graph modules
Update-Module Microsoft.Graph -Force

# Or reinstall
Uninstall-Module Microsoft.Graph -AllVersions
Install-Module Microsoft.Graph -Scope CurrentUser
```

#### 5. Slow Performance

**Cause**: Large number of Administrative Units or assignments.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -OnlyNoMFA
```

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all scoped administrators
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all scoped administrators, risk levels, and MFA status.

### Example 2: High-Risk Administrator Detection

```powershell
# Find scoped administrators with privileged access but no MFA
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -OnlyNoMFA -Matrix

# Review output, then remediate
```

**Use Case**: Identify immediate security risks for remediation.

### Example 3: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of scoped administrators during engagement.

### Example 4: Compliance Reporting

```powershell
# Monthly audit including disabled accounts
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track scoped access changes and MFA adoption over time.

### Example 5: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -TenantId "customer-tenant-id" -ExportPath "customer_admins.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\AdminUnits_$date.csv"
    
    C:\Tools\Invoke-EntraAdminUnitCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if high-risk administrators found
    $results = Import-Csv $path
    $highRisk = $results | Where-Object { $_.RiskLevel -in @("CRITICAL", "HIGH") }
    
    if ($highRisk.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($highRisk.Count) high-risk scoped administrators found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyAdminUnitCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Admin Unit Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_scoped_admin"
        severity = $_.RiskLevel
        admin_unit = $_.AdminUnitName
        role = $_.RoleName
        user = $_.PrincipalUPN
        mfa_enabled = $_.MFAEnabled
        last_signin = $_.LastSignInDisplay
    }
}

$siemEvents | ConvertTo-Json | Out-File "siem_formatted.json"
```

### PowerShell Remoting

```powershell
# Run remotely on jump box or admin workstation
$session = New-PSSession -ComputerName "admin-server.company.com"

Invoke-Command -Session $session -ScriptBlock {
    cd C:\Tools
    .\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -Matrix -ExportPath "C:\Reports\admins.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\admins.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Administrative Unit enumeration
- Scoped role assignment analysis
- MFA detection and risk assessment
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive administrator analytics

## License

This script is part of the EvilMist toolkit.

**Copyright (C) 2025 Logisek**

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See the LICENSE file for more details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

Visit: https://github.com/Logisek/EvilMist

## Support

For questions, issues, or feature requests:
- GitHub Issues: https://github.com/Logisek/EvilMist/issues
- Email: info@logisek.com
- Website: https://logisek.com

## Related Tools

- **Invoke-EntraRecon.ps1**: Comprehensive Azure AD reconnaissance
- **Invoke-EntraRoleCheck.ps1**: Privileged role assignment audit
- **Invoke-EntraAppAccess.ps1**: Critical administrative application access audit
- **Invoke-EntraMFACheck.ps1**: MFA compliance audit

---

