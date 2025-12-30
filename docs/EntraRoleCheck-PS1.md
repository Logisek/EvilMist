# Invoke-EntraRoleCheck.ps1

## Overview

`Invoke-EntraRoleCheck.ps1` is a PowerShell 7+ script designed to enumerate and analyze Azure Entra ID users with privileged directory roles including Global Administrators, Privileged Role Administrators, and other high-privilege roles. This tool is part of the EvilMist toolkit and helps security teams identify users with privileged access, analyze their security posture, and assess risks associated with role assignments.

## Purpose

Privileged directory roles provide extensive administrative capabilities. This script helps:
- **Security Auditors**: Identify users with privileged roles and assess their security posture
- **Penetration Testers**: Discover high-value targets and privilege escalation paths
- **IT Administrators**: Audit role assignments and ensure proper security controls
- **Compliance Teams**: Generate reports for privileged access governance and PIM compliance

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Comprehensive Role Coverage**: Enumerates all directory roles including CRITICAL, HIGH, MEDIUM, and LOW risk roles
- ✅ **PIM Support**: Identifies both permanent (Active) and PIM-managed (Eligible/Active) role assignments
- ✅ **Assignment Tracking**: Shows assignment dates, duration, and expiration dates
- ✅ **MFA Status Detection**: Identifies privileged users without Multi-Factor Authentication
- ✅ **Last Sign-In Tracking**: Shows last login date/time and activity patterns
- ✅ **Risk Assessment**: Categorizes users by risk level based on role criticality and security posture
- ✅ **Activity Analytics**: Sign-in statistics, stale accounts, inactive users
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only users without MFA, only permanent assignments, or include disabled accounts

## Roles Analyzed

The script analyzes all directory roles and categorizes them by risk level:

### CRITICAL Risk Roles

These roles have the highest level of privilege and pose the greatest security risk:

1. **Global Administrator**
   - Full control over all Azure AD resources
   - Can manage all other administrators
   - Can reset passwords for all users including other Global Admins
   - Can modify tenant-wide settings and policies

2. **Privileged Role Administrator**
   - Can manage role assignments in Azure AD
   - Can activate PIM roles for other users
   - Can modify role definitions and assignments
   - Critical for privilege escalation attacks

3. **Privileged Authentication Administrator**
   - Can manage authentication methods for all users
   - Can reset passwords for all users including Global Admins
   - Can modify MFA settings
   - High risk for credential attacks

### HIGH Risk Roles

These roles provide significant administrative capabilities:

- **Exchange Administrator**: Full control over Exchange Online
- **SharePoint Administrator**: Full control over SharePoint Online
- **Security Administrator**: Manages security policies and threat protection
- **Compliance Administrator**: Manages compliance policies and eDiscovery
- **Application Administrator**: Manages application registrations and service principals
- **Cloud Application Administrator**: Manages cloud applications and app proxy
- **Hybrid Identity Administrator**: Manages hybrid identity and directory sync
- **Identity Governance Administrator**: Manages access reviews and lifecycle policies

### MEDIUM Risk Roles

These roles provide moderate administrative capabilities:

- **User Administrator**: Can create and manage users
- **Helpdesk Administrator**: Can reset passwords for non-admins
- **License Administrator**: Manages license assignments
- **Billing Administrator**: Manages billing and subscriptions
- **Authentication Administrator**: Can manage authentication methods for non-admins
- **Groups Administrator**: Manages groups and group settings

### LOW Risk Roles

These roles provide limited administrative capabilities:

- **Directory Readers**: Read-only access to directory data
- **Directory Writers**: Can create directory objects
- **Guest Inviter**: Can invite guest users

## Assignment Types

The script identifies three types of role assignments:

### 1. Active (Permanent)

- **Type**: Direct, permanent role assignment
- **Risk**: Higher risk - roles are always active
- **Use Case**: Legacy assignments or roles that require constant access
- **Recommendation**: Consider migrating to PIM for high-privilege roles

### 2. PIM Eligible

- **Type**: User is eligible for the role but must activate it
- **Risk**: Lower risk - role is not active until activated
- **Use Case**: Just-in-time access for occasional administrative tasks
- **Recommendation**: Preferred method for privileged access

### 3. PIM Active

- **Type**: User has activated their eligible role assignment
- **Risk**: Medium risk - role is currently active (time-limited)
- **Use Case**: Temporary elevated access for specific tasks
- **Recommendation**: Monitor activation duration and ensure proper expiration

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
  - `Directory.Read.All` - Read directory data and roles
  - `RoleManagement.Read.Directory` - Read role assignments and PIM data
  - `User.Read.All` - Read all user profiles
  - `UserAuthenticationMethod.Read.All` - Read authentication methods
  - `AuditLog.Read.All` - Read audit logs and sign-in activity (optional)

- **Fallback Scopes** (if full access unavailable):
  - `Directory.Read.All` - Read directory data and roles
  - `RoleManagement.Read.Directory` - Read role assignments
  - `User.ReadBasic.All` - Read basic user info

**Note**: If `AuditLog.Read.All` is not available, the script will automatically fall back to retrieving users without sign-in activity data. If `RoleManagement.Read.Directory` is not available, PIM data will not be retrieved. All other features will continue to work normally.

## Usage

### Basic Usage

```powershell
# Simple scan of all users with privileged roles
.\scripts\powershell\Invoke-EntraRoleCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -ExportPath "privileged-roles.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -ExportPath "role-results.json"
```

### Include Disabled User Accounts

```powershell
# Scan all users including disabled accounts
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -IncludeDisabledUsers -ExportPath "all-roles.csv"
```

### Show Only Users Without MFA

```powershell
# Filter to show only privileged users without MFA
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -OnlyNoMFA

# Matrix view with MFA filter
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -OnlyNoMFA -Matrix
```

### Show Only Permanent Assignments

```powershell
# Show only permanent (non-PIM) role assignments
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -OnlyPermanent

# Export permanent assignments
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -OnlyPermanent -ExportPath "permanent-admins.csv"
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all users, all roles, with export
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "full-audit.csv"

# Security focus: high-risk users only (no MFA, permanent assignments)
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -OnlyNoMFA -OnlyPermanent -Matrix -ExportPath "high-risk-roles.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
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
| `-OnlyNoMFA` | Switch | Show only users without MFA enabled | False |
| `-OnlyPermanent` | Switch | Show only permanent (non-PIM) role assignments | False |
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

The script provides detailed information about each role assignment:

```
[CRITICAL] john.admin@company.com - Global Administrator
  Display Name: John Admin
  User Type: Member
  Email: john.admin@company.com
  Job Title: IT Administrator
  Department: IT
  Account Status: Enabled
  Role: Global Administrator
  Role Risk Level: CRITICAL
  Assignment Type: Active
  Assignment Date: 2023-01-15T10:30:00Z (342 days ago)
  MFA Enabled: No
  Auth Methods: Password Only
  Last Sign-In: 2024-12-20 14:23:45 (3 days ago) (Interactive)
  Created: 2022-05-10T08:15:00Z (591 days old)
  Licenses: 2 assigned
```

### Matrix Output (with `-Matrix`)

```
Risk      Role Risk  MFA  Type         Status   User Principal Name         Display Name    Role                      Last Sign-In  Duration  Department
----      ---------  ---  ----         ------   -------------------         ------------    ----                      ------------  --------  ----------
CRITICAL  CRITICAL   No   Active       Enabled  john.admin@company.com      John Admin      Global Administrator      3d ago        342d      IT
HIGH      HIGH       Yes  PIM Eligible Enabled  jane.secure@company.com      Jane Secure     Exchange Administrator    1d ago        -         Security
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total role assignments: 25
Unique users with roles: 18
  - CRITICAL risk: 3
  - HIGH risk: 8
  - MEDIUM risk: 10
  - LOW risk: 4

[MFA STATUS]
  With MFA enabled: 15
  Without MFA: 10

[ASSIGNMENT TYPES]
  Permanent (Active): 12
  PIM Eligible: 8
  PIM Active: 5

[USERS BY ROLE]
  Global Administrator: 3
  Exchange Administrator: 5
  Security Administrator: 4
  User Administrator: 6
  SharePoint Administrator: 3
  Application Administrator: 2
  Compliance Administrator: 2

[TOP DEPARTMENTS]
  IT: 10
  Security: 5
  Operations: 3

[SIGN-IN ACTIVITY]
  Never signed in: 1
  Recent (≤30 days): 18
  Stale (>90 days): 6
```

## Risk Levels

The script assigns risk levels based on role criticality, assignment type, and MFA configuration:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | CRITICAL role without MFA OR HIGH role without MFA with permanent assignment | Red | **IMMEDIATE ACTION REQUIRED**: Enable MFA or migrate to PIM |
| **HIGH** | HIGH role without MFA OR MEDIUM role without MFA with permanent assignment | Yellow | **URGENT**: Enable MFA or migrate to PIM |
| **MEDIUM** | CRITICAL/HIGH role with MFA OR MEDIUM role without MFA OR PIM-managed assignment | Green | **REVIEW**: Consider PIM for permanent assignments |
| **LOW** | LOW risk role OR disabled account | Gray | **MONITOR**: Acceptable risk |

### Risk Assessment Logic

```
IF role is CRITICAL:
    IF no MFA AND permanent assignment:
        RISK = CRITICAL
    ELSE IF no MFA:
        RISK = CRITICAL
    ELSE IF permanent assignment:
        RISK = HIGH
    ELSE:
        RISK = MEDIUM
ELSE IF role is HIGH:
    IF no MFA AND permanent assignment:
        RISK = CRITICAL
    ELSE IF no MFA:
        RISK = HIGH
    ELSE IF permanent assignment:
        RISK = HIGH
    ELSE:
        RISK = MEDIUM
ELSE IF role is MEDIUM:
    IF no MFA AND permanent assignment:
        RISK = HIGH
    ELSE IF no MFA:
        RISK = MEDIUM
    ELSE:
        RISK = MEDIUM
ELSE:
    RISK = LOW
```

## Security Considerations

### Why Privileged Roles Matter

Users with privileged directory roles can:
- **Full Tenant Control**: Global Admins can modify any setting, create/delete any object
- **Privilege Escalation**: Privileged Role Admins can grant themselves or others Global Admin
- **Credential Attacks**: Privileged Authentication Admins can reset passwords for all users
- **Data Exfiltration**: Exchange/SharePoint Admins can access all emails and documents
- **Security Bypass**: Security Admins can modify security policies and disable protections
- **Application Control**: Application Admins can create service principals with high permissions
- **Identity Manipulation**: Can modify authentication methods, bypass MFA, reset credentials

### High-Risk Scenarios

1. **Global Admin Without MFA** (CRITICAL Risk)
   - Single point of failure for entire tenant
   - Can be compromised with just username/password
   - Immediate remediation required

2. **Permanent High-Privilege Assignments** (HIGH Risk)
   - Roles are always active, increasing attack surface
   - No time-limited access controls
   - Should be migrated to PIM

3. **Stale Privileged Accounts** (MEDIUM-HIGH Risk)
   - Users who haven't signed in for 90+ days but still have roles
   - May indicate forgotten or orphaned accounts
   - Potential for account takeover if credentials leaked

4. **Multiple CRITICAL Roles** (CRITICAL Risk)
   - Users with multiple high-privilege roles
   - Increased attack surface and blast radius
   - Should be reviewed for business justification

### PIM Best Practices

1. **Migrate Permanent Assignments**: Convert permanent assignments to PIM eligible
2. **Time-Limited Activations**: Set maximum activation duration (e.g., 8 hours)
3. **Approval Requirements**: Require approval for high-privilege role activations
4. **Regular Access Reviews**: Review eligible assignments quarterly
5. **MFA Enforcement**: Require MFA for all role activations
6. **Alerting**: Monitor role activations and unusual patterns

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track role assignments and changes
2. **MFA Enforcement**: Ensure all privileged users have MFA enabled
3. **PIM Migration**: Migrate permanent assignments to PIM for high-privilege roles
4. **Least Privilege**: Review assignments and remove unnecessary roles
5. **Monitor Activity**: Track sign-in patterns and role activations
6. **Document Changes**: Maintain records of role assignments and business justification

### For Penetration Testers

1. **Initial Reconnaissance**: Identify users with privileged roles
2. **Target Selection**: Prioritize CRITICAL risk users without MFA
3. **Privilege Escalation**: Document role assignments for attack paths
4. **PIM Analysis**: Identify PIM-eligible roles that could be activated
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify role assignments align with business needs
3. **Trend Analysis**: Compare results over time
4. **Remediation Tracking**: Monitor MFA adoption and PIM migration rates
5. **Access Reviews**: Use reports for quarterly access certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- DisplayName, UserPrincipalName, Email
- AccountEnabled, UserType
- JobTitle, Department
- CreatedDateTime, DaysOld
- RoleName, RoleId, RoleRiskLevel
- AssignmentType, AssignmentDate, AssignmentDuration, AssignmentEndDate
- LastSignIn, LastSignInDisplay, DaysSinceLastSignIn, SignInType
- MFAEnabled, AuthMethods, MethodCount
- HasLicenses, LicenseCount
- RiskLevel

### JSON Export

Structured format for automation:
```json
[
  {
    "DisplayName": "John Admin",
    "UserPrincipalName": "john.admin@company.com",
    "Email": "john.admin@company.com",
    "AccountEnabled": true,
    "UserType": "Member",
    "JobTitle": "IT Administrator",
    "Department": "IT",
    "RoleName": "Global Administrator",
    "RoleRiskLevel": "CRITICAL",
    "AssignmentType": "Active",
    "AssignmentDate": "2023-01-15T10:30:00Z",
    "AssignmentDuration": 342,
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

#### 1. "No users with privileged roles found"

**Cause**: No users have been assigned directory roles, or roles haven't been activated.

**Solution**: 
- Verify roles exist in your tenant
- Check if roles are assigned via PIM (may require different permissions)
- Ensure you have proper read permissions

#### 2. "Failed to retrieve PIM eligible assignments"

**Cause**: Insufficient permissions for PIM data.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraRoleCheck.ps1
# Accept permission consent when prompted (RoleManagement.Read.Directory)
```

#### 3. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraRoleCheck.ps1
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

**Cause**: Large number of role assignments or throttling.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -OnlyNoMFA
```

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all users with privileged roles
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all role assignments, risk levels, and MFA status.

### Example 2: High-Risk User Detection

```powershell
# Find privileged users without MFA
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -OnlyNoMFA -Matrix

# Review output, then remediate
```

**Use Case**: Identify immediate security risks for remediation.

### Example 3: PIM Compliance Check

```powershell
# Find permanent assignments (should be migrated to PIM)
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -OnlyPermanent -Matrix -ExportPath "permanent-assignments.csv"
```

**Use Case**: Identify roles that should be migrated to PIM.

### Example 4: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of high-value targets during engagement.

### Example 5: Compliance Reporting

```powershell
# Monthly audit including disabled accounts
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track role assignments and MFA adoption over time.

### Example 6: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -TenantId "customer-tenant-id" -ExportPath "customer_roles.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\RoleCheck_$date.csv"
    
    C:\Tools\Invoke-EntraRoleCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if critical-risk users found
    $results = Import-Csv $path
    $criticalRisk = $results | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    
    if ($criticalRisk.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($criticalRisk.Count) critical-risk privileged users found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyRoleCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Role Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_role_assignment"
        severity = $_.RiskLevel
        user = $_.UserPrincipalName
        role = $_.RoleName
        role_risk = $_.RoleRiskLevel
        assignment_type = $_.AssignmentType
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
    .\scripts\powershell\Invoke-EntraRoleCheck.ps1 -Matrix -ExportPath "C:\Reports\roles.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\roles.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Support for all directory roles
- PIM eligible and active assignment detection
- MFA detection and risk assessment
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive user analytics

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
- **Invoke-EntraMFACheck.ps1**: MFA compliance audit
- **Invoke-EntraGuestCheck.ps1**: Guest account security analysis
- **Invoke-EntraAppAccess.ps1**: Critical administrative application access audit

---

