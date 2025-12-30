# Invoke-EntraAppAccess.ps1

## Overview

`Invoke-EntraAppAccess.ps1` is a PowerShell 7+ script designed to enumerate and analyze Azure Entra ID users with access to critical administrative applications including PowerShell tools, management portals, core Microsoft 365 services, and privileged identity management. This tool is part of the EvilMist toolkit and helps security teams identify users with privileged administrative access in their Azure AD tenant.

## Purpose

PowerShell and Graph CLI tools provide powerful administrative capabilities. This script helps:
- **Security Auditors**: Identify users with management tool access
- **Penetration Testers**: Discover potential privileged access attack vectors
- **IT Administrators**: Audit administrative tool access and compliance
- **Compliance Teams**: Generate reports for privileged access governance

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Explicit Assignment Focus**: Shows users with administrative/elevated access
- ✅ **Multiple Application Coverage**: Tracks 10 critical administrative applications
- ✅ **Default Access Detection**: Automatically detects and warns about apps with default access
- ✅ **Security-Focused Results**: Filters out noise from basic user access
- ✅ **MFA Status Detection**: Identifies users without Multi-Factor Authentication
- ✅ **Last Sign-In Tracking**: Shows last login date/time and activity patterns
- ✅ **Assignment Tracking**: Shows when users were granted access
- ✅ **Risk Assessment**: Categorizes users by risk level (HIGH/MEDIUM/LOW)
- ✅ **Activity Analytics**: Sign-in statistics, stale accounts, inactive users
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only users without MFA or include disabled accounts

## Applications Monitored

The script checks user access to the following 10 critical enterprise applications:

### Development & API Tools

1. **Azure Active Directory PowerShell** (`1b730954-1685-4b74-9bfd-dac224a7b894`)
   - Classic Azure AD PowerShell module
   - Provides comprehensive directory management capabilities
   - Enables automated user/group/app management

2. **Microsoft Azure PowerShell** (`1950a258-227b-4e31-a9cf-717495945fc2`)
   - Modern Azure PowerShell Az module
   - Manages Azure resources and services
   - Full infrastructure control via scripts

3. **Microsoft Graph Command Line Tools** (`14d82eec-204b-4c2f-b7e8-296a70dab67e`)
   - Microsoft Graph CLI (mg cli)
   - Provides command-line access to Microsoft Graph API
   - Programmatic access to all Microsoft 365 data

4. **Graph Explorer** (`de8bc8b5-d9f9-48b1-a8ad-b748da725064`)
   - Web-based Graph API explorer and testing tool
   - Allows interactive Graph API queries and testing
   - Low barrier to entry for API access

5. **Azure CLI** (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`)
   - Cross-platform Azure command-line interface
   - Full programmatic access to Azure resources
   - Most widely used Azure management tool

### Administrative Portals

6. **Microsoft 365 Admin Portal** (`618dd325-23f6-4b6f-8380-4df78026e39b`)
   - Web-based Microsoft 365 tenant administration
   - User creation, role assignments, license management
   - Complete tenant configuration control

7. **Azure Portal** (`c44b4083-3bb0-49c1-b47d-974e53cbdf3c`)
   - Web-based Azure infrastructure management
   - Resource creation, configuration, monitoring
   - Full Azure subscription control

### Core Microsoft 365 Services

8. **Office 365 Exchange Online** (`00000002-0000-0ff1-ce00-000000000000`)
   - Email and calendar service access
   - Mailbox access, mail flow rules, transport settings
   - Can read/exfiltrate emails from all mailboxes

9. **Office 365 SharePoint Online** (`00000003-0000-0ff1-ce00-000000000000`)
   - Document management and collaboration platform
   - Access to all document libraries and sites
   - Can read/exfiltrate documents from all SharePoint sites

### Security & Identity Management

10. **MS-PIM** (Privileged Identity Management) (`01fc33a7-78ba-4d2f-a4b7-768e336e890e`)
    - Just-in-time privileged access management
    - Can activate elevated roles (Global Admin, etc.)
    - Critical for privilege escalation attacks

## Default Access Detection & Warnings

This script intelligently detects and warns about applications with **default access** while showing only explicit assignments:

### How It Works

1. **Checks Each Application's Configuration**
   - Queries the `AppRoleAssignmentRequired` property of each service principal
   - Determines if the app requires explicit assignment or has default access

2. **Shows Explicit Assignments Only**
   - Displays users who have been **explicitly assigned** to applications
   - These are typically users with **administrative or elevated access**
   - Focuses on security-relevant access (not basic user access)

3. **Warns About Default Access Apps**
   - Identifies apps where ALL tenant users have basic access
   - Shows clear warnings during scan and in summary
   - Common for: Exchange Online, SharePoint Online, Azure Portal, Graph Command Line Tools

### Why Explicit Assignments Matter

For **security auditing**, you need to know who has **privileged/administrative access**, not just basic user access:

| Access Type | Example | Shown in Results? |
|-------------|---------|-------------------|
| **Explicit Assignment** | User assigned to MS-PIM or M365 Admin Portal | ✅ **YES** - Security relevant |
| **Default Access** | All users can access their own mailbox in Exchange | ❌ **NO** - Not security relevant |
| **Default Access + Admin Perms** | User with Exchange admin role | ✅ **YES** - Would have explicit assignment |

### Default Access Warning Example

When apps have default access, you'll see:
```
[!] IMPORTANT: The following 4 app(s) have DEFAULT ACCESS:
    - Office 365 Exchange Online
    - Office 365 SharePoint Online  
    - Azure Portal
    - Graph Command Line Tools
[!] This means ALL tenant users have basic access to these apps
[*] User list below shows only EXPLICIT ASSIGNMENTS (administrative/elevated access)
```

This approach provides **actionable security insights** without overwhelming you with thousands of regular users.

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
   Install-Module Microsoft.Graph.Applications -Scope CurrentUser
   Install-Module Microsoft.Graph.Users -Scope CurrentUser
   Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
   ```

### Required Permissions

The script requires the following Microsoft Graph API permissions:

- **Primary Scopes** (preferred):
  - `Application.Read.All` - Read enterprise applications
  - `Directory.Read.All` - Read directory data
  - `User.Read.All` - Read all user profiles
  - `UserAuthenticationMethod.Read.All` - Read authentication methods
  - `AuditLog.Read.All` - Read audit logs and sign-in activity (optional)

- **Fallback Scopes** (if full access unavailable):
  - `Application.Read.All` - Read enterprise applications
  - `Directory.Read.All` - Read directory data
  - `User.ReadBasic.All` - Read basic user info

**Note**: If `AuditLog.Read.All` is not available, the script will automatically fall back to retrieving users without sign-in activity data. All other features will continue to work normally.

## Usage

### Basic Usage

```powershell
# Simple scan of all users with app access
.\scripts\powershell\Invoke-EntraAppAccess.ps1

# During the scan, you'll see which apps have default access:
# [!] IMPORTANT: The following apps have DEFAULT ACCESS (all users):
#     - Office 365 Exchange Online
#     - Office 365 SharePoint Online
#     - Azure Portal
#     - Graph Command Line Tools
# [*] This means ALL tenant users can access these apps
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -ExportPath "app-access.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -ExportPath "app-results.json"
```

### Include Disabled User Accounts

```powershell
# Scan all users including disabled accounts
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -IncludeDisabledUsers -ExportPath "all-app-users.csv"
```

### Show Only Users Without MFA

```powershell
# Filter to show only users without MFA
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -OnlyNoMFA

# Matrix view with MFA filter
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -OnlyNoMFA -Matrix
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all users, all apps, with export
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -IncludeDisabledUsers -Matrix -ExportPath "full-audit.csv"

# Security focus: high-risk users only (no MFA)
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -OnlyNoMFA -Matrix -ExportPath "high-risk-access.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
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

The script provides detailed information about each user with explicit app assignments:

```
[HIGH] john.admin@company.com
  Display Name: John Admin
  User Type: Member
  Email: john.admin@company.com
  Job Title: IT Administrator
  Department: IT
  Account Status: Enabled
  Assigned Apps (4): Azure AD PowerShell, Azure CLI, Microsoft 365 Admin Portal, MS-PIM
  Assignment Date: 2024-01-15T10:30:00Z (342 days ago)
  MFA Enabled: No
  Auth Methods: Password Only
  Last Sign-In: 2024-12-20 14:23:45 (3 days ago) (Interactive)
  Created: 2023-05-10T08:15:00Z (591 days old)
  Licenses: 2 assigned
```

**Note**: This user has **explicit assignments** to 4 critical apps. If Exchange Online or SharePoint Online appeared in the warnings as having default access, this user also has basic access to those (like all users), but those aren't shown here since they don't indicate elevated permissions.

### Matrix Output (with `-Matrix`)

```
Risk  MFA  Status   User Principal Name         Display Name    Apps                                    Last Sign-In  Department
----  ---  ------   -------------------         ------------    ----                                    ------------  ----------
HIGH  No   Enabled  john.admin@company.com      John Admin      Azure AD PowerShell, Graph Command ...  3d ago        IT
LOW   Yes  Enabled  jane.secure@company.com     Jane Secure     Graph Command Line Tools                1d ago        Security
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total users with explicit assignments: 15
  - HIGH risk (active without MFA): 5
  - MEDIUM risk (disabled/inactive): 2
  - LOW risk (MFA enabled/disabled): 8

[!] Note: 4 app(s) have DEFAULT ACCESS (all users):
    - Office 365 Exchange Online
    - Office 365 SharePoint Online
    - Azure Portal
    - Graph Command Line Tools
  Regular users with default access are not shown in this list

[MFA STATUS]
  With MFA enabled: 10
  Without MFA: 5

[USERS BY APPLICATION]
  Microsoft 365 Admin Portal: 15
  Azure Portal: 12
  Office 365 Exchange Online: 25
  Azure CLI: 10
  Azure AD PowerShell: 8
  Graph Command Line Tools: 7
  Azure PowerShell: 6
  Office 365 SharePoint Online: 22
  MS-PIM: 4
  Graph Explorer: 5

[TOP DEPARTMENTS]
  IT: 7
  Security: 4
  Operations: 2

[SIGN-IN ACTIVITY]
  Never signed in: 1
  Recent (≤30 days): 11
  Stale (>90 days): 3
```

## Risk Levels

The script assigns risk levels based on account status and MFA configuration:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **HIGH** | Enabled account with app access WITHOUT MFA | Red | **IMMEDIATE ACTION REQUIRED**: Enable MFA |
| **MEDIUM** | Disabled account with app access | Yellow | Review: May be stale assignment |
| **LOW** | Enabled account with MFA OR disabled account | Green | Monitor: Acceptable risk |

### Risk Assessment Logic

```
IF account is enabled AND has PowerShell/CLI access:
    IF no MFA configured:
        RISK = HIGH (Privileged access without MFA)
    ELSE:
        RISK = LOW (Protected with MFA)
ELSE IF account is disabled:
    RISK = LOW (Cannot sign in)
```

## Security Considerations

### Understanding Default Access vs Explicit Assignment

**IMPORTANT**: This script shows **explicit assignments** (elevated/administrative access) and warns about **default access** (basic user access).

| Access Model | What It Means | Example | Shown in Results? |
|--------------|---------------|---------|-------------------|
| **Explicit Assignment** | User specifically granted access to the app | John assigned to MS-PIM | ✅ **YES** |
| **Default Access** | All users can access (no assignment required) | All users have Exchange mailboxes | ⚠️ **Warning Only** |

#### Why This Distinction Matters

- **Exchange Online Default Access**: Users access their own mailbox (normal user behavior)
- **Exchange Online Explicit Assignment**: User has admin permissions or special roles (security concern!)

The script focuses on finding users with **elevated/administrative access**, not cataloging every user with a mailbox or OneDrive.

#### Common Default Access Apps
- **Office 365 Exchange Online**: All users can access their own mailbox
- **Office 365 SharePoint Online**: All users can access sites they have permissions to
- **Azure Portal**: All users can sign in (may see nothing without permissions)
- **Graph Command Line Tools**: Often has default access enabled

#### Recommendation
1. **Review users with explicit assignments** (shown in results) - These may have elevated permissions
2. **Check apps with default access** (shown in warnings) - Consider enabling "User assignment required"
3. **Use Conditional Access** to restrict default access apps if needed
4. **Run this script regularly** to monitor changes in administrative access

### Why This Matters

Users with access to these 10 critical applications can:
- **Read sensitive directory data**: User accounts, groups, configurations, licenses
- **Modify directory objects**: Create/modify users, groups, applications, policies
- **Escalate privileges**: Grant themselves Global Admin or other elevated roles via PIM
- **Bypass conditional access**: Use programmatic access that may evade CA policies
- **Automate attacks**: Script-based reconnaissance and exploitation at scale
- **Persist access**: Create service principals, app registrations, hidden admin accounts
- **Access all emails**: Read, export, or modify mailboxes via Exchange Online
- **Access all documents**: Download, modify, or delete files from SharePoint/OneDrive
- **Manage entire tenant**: Full administrative control via M365 Admin Portal
- **Control Azure infrastructure**: Create/modify/delete Azure resources and subscriptions
- **Interactive API testing**: Graph Explorer and portals allow real-time exploration

### High-Risk Scenarios

1. **Active User Without MFA** (HIGH Risk)
   - Can authenticate with just username/password
   - PowerShell/CLI access provides full programmatic control
   - High likelihood of credential stuffing/phishing success

2. **Stale Assignments** (MEDIUM Risk)
   - Users who haven't signed in for 90+ days but still have access
   - May indicate forgotten or orphaned accounts
   - Potential for account takeover if credentials leaked

3. **Guest Users with Access** (Variable Risk)
   - External users with management tool access
   - May not be subject to same security policies
   - Review carefully for business justification

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track access changes
2. **MFA Enforcement**: Ensure all users with app access have MFA enabled
3. **Least Privilege**: Review assignments and remove unnecessary access
4. **Monitor Activity**: Track sign-in patterns and unusual behavior
5. **Document Changes**: Maintain records of who has access and why

### For Penetration Testers

1. **Initial Reconnaissance**: Identify users with privileged tool access
2. **Target Selection**: Prioritize HIGH risk users without MFA
3. **Credential Attacks**: Focus on accounts with management access
4. **Persistence**: Document for privilege escalation paths
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify access aligns with business needs
3. **Trend Analysis**: Compare results over time
4. **Remediation Tracking**: Monitor MFA adoption rates
5. **Access Reviews**: Use reports for quarterly access certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- DisplayName, UserPrincipalName, Email
- AccountEnabled, UserType
- JobTitle, Department
- CreatedDateTime, DaysOld
- AssignedApps, AppCount
- AssignmentDate, DaysSinceAssignment
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
    "AssignedApps": "Azure AD PowerShell, Graph Command Line Tools",
    "AppCount": 2,
    "MFAEnabled": false,
    "AuthMethods": "Password Only",
    "RiskLevel": "HIGH",
    "LastSignInDisplay": "2024-12-20 14:23:45 (3 days ago)",
    "DaysSinceLastSignIn": 3
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "No target applications found in this tenant"

**Cause**: The PowerShell/Graph CLI service principals don't exist in your tenant.

**Solution**: 
- Apps are only created when first used in a tenant
- At least one user must have signed in with one of these tools
- This is normal for new/small tenants

#### 2. "No user assignments found for target applications"

**Cause**: No users have been explicitly assigned to these apps.

**Solution**:
- Check if apps use default access (all users can access)
- Review conditional access policies
- Verify assignment requirements in Azure AD

#### 3. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraAppAccess.ps1
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

**Cause**: Large number of users or throttling.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -OnlyNoMFA
```

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all users with PowerShell/CLI access
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all users, risk levels, and MFA status.

### Example 2: High-Risk User Detection

```powershell
# Find users with privileged access but no MFA
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -OnlyNoMFA -Matrix

# Review output, then remediate
```

**Use Case**: Identify immediate security risks for remediation.

### Example 3: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of high-value targets during engagement.

### Example 4: Compliance Reporting

```powershell
# Monthly audit including disabled accounts
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -IncludeDisabledUsers -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track access changes and MFA adoption over time.

### Example 5: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -TenantId "customer-tenant-id" -ExportPath "customer_access.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\AppAccess_$date.csv"
    
    C:\Tools\Invoke-EntraAppAccess.ps1 -Matrix -ExportPath $path
    
    # Send alert if high-risk users found
    $results = Import-Csv $path
    $highRisk = $results | Where-Object { $_.Risk -eq "HIGH" }
    
    if ($highRisk.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($highRisk.Count) high-risk app access accounts found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyAppAccessCheck.ps1"
Register-ScheduledTask -TaskName "Weekly App Access Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_app_access"
        severity = $_.RiskLevel
        user = $_.UserPrincipalName
        apps = $_.AssignedApps
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
    .\scripts\powershell\Invoke-EntraAppAccess.ps1 -Matrix -ExportPath "C:\Reports\access.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\access.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Support for 3 key management applications
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

---
