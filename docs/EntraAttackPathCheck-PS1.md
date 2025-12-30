# Invoke-EntraAttackPathCheck.ps1

## Overview

`Invoke-EntraAttackPathCheck.ps1` is a PowerShell 7+ script designed to analyze Azure Entra ID attack paths including privilege escalation paths, password reset delegations, transitive group memberships, and shared mailbox access. This tool is part of the EvilMist toolkit and helps security teams identify potential security vulnerabilities and attack vectors in their Azure AD tenant.

## Purpose

Attack path analysis helps identify how attackers could escalate privileges or move laterally through an organization. This script helps:

- **Security Auditors**: Identify privilege escalation paths and security gaps
- **Penetration Testers**: Discover attack paths for privilege escalation and lateral movement
- **IT Administrators**: Understand and remediate security vulnerabilities
- **Compliance Teams**: Generate reports for security posture assessment

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Privilege Escalation Analysis**: Identifies paths to elevated privileges through role-assignable groups
- ✅ **Password Reset Delegation Detection**: Finds users who can reset passwords for other users
- ✅ **Transitive Group Membership Analysis**: Identifies indirect access to privileged groups
- ✅ **Shared Mailbox Access Detection**: Identifies shared mailboxes that could be used for lateral movement
- ✅ **MFA Status Detection**: Identifies users without Multi-Factor Authentication in attack paths
- ✅ **Last Sign-In Tracking**: Shows last login date/time and activity patterns
- ✅ **Risk Assessment**: Categorizes attack paths by risk level (CRITICAL/HIGH/MEDIUM)
- ✅ **Path Complexity Analysis**: Evaluates attack path complexity (Low/Medium/High)
- ✅ **Activity Analytics**: Sign-in statistics, stale accounts, inactive users
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only high-risk paths or include disabled accounts

## Attack Path Types Analyzed

The script analyzes four main types of attack paths:

### 1. Privilege Escalation Paths

Identifies users who have transitive membership in role-assignable groups, which could allow them to be assigned privileged directory roles.

**How it works:**
- Enumerates all role-assignable groups (groups that can be assigned directory roles)
- Identifies all transitive members of these groups
- Flags users who could potentially be granted elevated privileges

**Risk Level:**
- **CRITICAL**: Role-assignable group membership without MFA
- **HIGH**: Role-assignable group membership with MFA
- **MEDIUM**: Disabled accounts with role-assignable group membership

**Example Attack Path:**
```
User: john.doe@company.com
→ Transitive Member of: "IT Admins" (role-assignable group)
→ Could be assigned: Global Administrator role
→ Risk: CRITICAL (no MFA)
```

### 2. Password Reset Delegations

Identifies users who can reset passwords for other users through directory roles.

**Roles Analyzed:**
- **User Administrator**: Can reset passwords for all users
- **Helpdesk Administrator**: Can reset passwords for non-administrative users
- **Privileged Authentication Administrator**: Can reset passwords for all users including administrators

**Risk Level:**
- **CRITICAL**: Password reset capability without MFA
- **HIGH**: Password reset capability with MFA
- **MEDIUM**: Disabled accounts with password reset capability

**Example Attack Path:**
```
User: helpdesk@company.com
→ Role: Helpdesk Administrator
→ Can reset passwords for: All non-administrative users
→ Risk: CRITICAL (no MFA)
```

### 3. Transitive Group Memberships

Identifies users who have indirect access to privileged groups through nested group memberships.

**How it works:**
- Identifies privileged groups (role-assignable or with privileged names)
- Analyzes transitive memberships to find indirect access
- Flags users who have access through nested groups rather than direct membership

**Risk Level:**
- **CRITICAL**: Indirect access to role-assignable groups without MFA
- **HIGH**: Indirect access to privileged groups
- **MEDIUM**: Disabled accounts with indirect access

**Example Attack Path:**
```
User: contractor@company.com
→ Member of: "Contractors" group
→ "Contractors" group is member of: "IT Support" group
→ "IT Support" group is member of: "Global Admins" (role-assignable)
→ Risk: CRITICAL (indirect access, no MFA)
```

### 4. Shared Mailbox Access

Identifies shared mailboxes that could be used for lateral movement or data exfiltration.

**How it works:**
- Identifies potential shared mailboxes (users without licenses or with shared mailbox indicators)
- Flags high-value mailboxes (finance, HR, admin, exec, legal, CEO, CFO)
- Notes that full mailbox permissions require Exchange Online PowerShell

**Shared Mailbox Indicators:**
- Email addresses containing: shared, info@, support@, sales@, hr@, finance@, admin@, noreply@, helpdesk@, team@, group@
- Users without assigned licenses
- High-value indicators: finance, hr, admin, exec, legal, ceo, cfo

**Risk Level:**
- **HIGH**: High-value shared mailboxes (finance, HR, admin, exec, legal, CEO, CFO)
- **MEDIUM**: Standard shared mailboxes

**Example Attack Path:**
```
Shared Mailbox: finance@company.com
→ Type: Shared Mailbox (no license)
→ High-value indicator: finance
→ Potential access: Financial data, sensitive documents
→ Risk: HIGH
```

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
   Install-Module Microsoft.Graph.Groups -Scope CurrentUser
   Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
   Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
   ```

### Required Permissions

The script requires the following Microsoft Graph API permissions:

- **Primary Scopes** (preferred):
  - `Directory.Read.All` - Read directory data
  - `Group.Read.All` - Read all groups
  - `User.Read.All` - Read all user profiles
  - `UserAuthenticationMethod.Read.All` - Read authentication methods
  - `RoleManagement.Read.Directory` - Read directory role assignments
  - `AuditLog.Read.All` - Read audit logs and sign-in activity (optional)

- **Fallback Scopes** (if full access unavailable):
  - `Directory.Read.All` - Read directory data
  - `Group.Read.All` - Read all groups
  - `User.ReadBasic.All` - Read basic user info

**Note**: If `AuditLog.Read.All` is not available, the script will automatically fall back to retrieving users without sign-in activity data. All other features will continue to work normally.

## Usage

### Basic Usage

```powershell
# Analyze all attack paths
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -ExportPath "attack-paths.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -ExportPath "attack-paths.json"
```

### Show Only High-Risk Paths

```powershell
# Filter to show only CRITICAL and HIGH risk paths
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -OnlyHighRisk

# High-risk paths in matrix view
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -OnlyHighRisk -Matrix
```

### Include Disabled User Accounts

```powershell
# Scan all attack paths including disabled accounts
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -IncludeDisabledUsers -ExportPath "all-paths.csv"
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all paths, with export
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "full-audit.csv"

# Security focus: high-risk paths only
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -OnlyHighRisk -Matrix -ExportPath "high-risk-paths.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
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
| `-OnlyHighRisk` | Switch | Show only attack paths with CRITICAL or HIGH risk | False |
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

The script provides detailed information about each attack path:

```
[CRITICAL] Privilege Escalation: john.doe@company.com
  Source User: John Doe (john.doe@company.com)
  Target Resource: IT Admins (role-assignable group)
  Path Description: User has transitive membership in role-assignable group
  Path Complexity: Medium
  Access Type: Transitive Group Membership
  Account Status: Enabled
  MFA Enabled: No
  Last Sign-In: 2024-12-20 14:23:45 (3 days ago)
```

### Matrix Output (with `-Matrix`)

```
Risk      Path Type                    Source User              Target Resource                    Complexity  MFA  Status   Last Sign-In
----      ---------                    -----------              --------------                    ----------  ---  ------   ------------
CRITICAL  Privilege Escalation         john.doe@company.com    IT Admins (role-assignable)       Medium      No   Enabled  3d ago
HIGH      Password Reset Delegation    helpdesk@company.com    All Users (via User Admin role)   Low         Yes  Enabled  1d ago
CRITICAL  Transitive Group Membership  contractor@company.com  Global Admins (role-assignable)    Medium      No   Enabled  5d ago
HIGH      Shared Mailbox Access        finance@company.com     Shared Mailbox: Finance            Low         No   Enabled  Never
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total attack paths: 25

[RISK BREAKDOWN]
  - CRITICAL risk: 8
  - HIGH risk: 12
  - MEDIUM risk: 5

[ATTACK PATHS BY TYPE]
  Privilege Escalation: 10
  Password Reset Delegation: 5
  Transitive Group Membership: 7
  Shared Mailbox Access: 3

[MFA STATUS]
  With MFA enabled: 10
  Without MFA: 15
```

## Risk Levels

The script assigns risk levels based on attack path type, complexity, and user security posture:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Role-assignable group access without MFA OR Password reset capability without MFA OR Indirect access to privileged groups without MFA | Red | **IMMEDIATE ACTION REQUIRED**: Enable MFA, review group memberships, restrict access |
| **HIGH** | Privileged access with MFA OR High-value shared mailbox OR Role-assignable group access with MFA | Yellow | **REVIEW REQUIRED**: Verify business justification, monitor access |
| **MEDIUM** | Disabled accounts with attack paths OR Standard shared mailboxes | Green | **MONITOR**: Review periodically, ensure accounts remain disabled |

### Risk Assessment Logic

```
IF attack path involves role-assignable groups:
    IF user has no MFA:
        RISK = CRITICAL
    ELSE IF account is disabled:
        RISK = MEDIUM
    ELSE:
        RISK = HIGH
ELSE IF attack path is password reset delegation:
    IF user has no MFA:
        RISK = CRITICAL
    ELSE IF account is disabled:
        RISK = MEDIUM
    ELSE:
        RISK = HIGH
ELSE IF attack path is transitive membership:
    IF target is role-assignable group AND no MFA:
        RISK = CRITICAL
    ELSE IF no MFA:
        RISK = HIGH
    ELSE:
        RISK = MEDIUM
ELSE IF attack path is shared mailbox:
    IF high-value mailbox:
        RISK = HIGH
    ELSE:
        RISK = MEDIUM
```

## Security Considerations

### Why Attack Path Analysis Matters

Attack paths represent potential routes that attackers could use to:

1. **Escalate Privileges**: Gain access to more powerful roles or permissions
2. **Move Laterally**: Access additional resources or systems
3. **Maintain Persistence**: Create backdoors or maintain access
4. **Exfiltrate Data**: Access sensitive information through shared resources

### Common Attack Scenarios

1. **Privilege Escalation via Role-Assignable Groups** (CRITICAL)
   - Attacker compromises a user account
   - User is a transitive member of a role-assignable group
   - Attacker can assign themselves privileged roles
   - **Mitigation**: Restrict role-assignable group membership, enable MFA

2. **Password Reset Abuse** (CRITICAL)
   - Attacker compromises a Helpdesk Administrator account
   - Attacker resets passwords for high-value targets
   - Attacker gains access to privileged accounts
   - **Mitigation**: Require MFA for password reset roles, implement approval workflows

3. **Transitive Group Exploitation** (HIGH)
   - Attacker compromises a low-privilege account
   - Account is member of nested groups
   - Nested groups provide access to privileged resources
   - **Mitigation**: Review nested group memberships, implement least privilege

4. **Shared Mailbox Lateral Movement** (MEDIUM-HIGH)
   - Attacker gains access to a shared mailbox
   - Mailbox contains sensitive information or credentials
   - Attacker uses information to access additional systems
   - **Mitigation**: Restrict shared mailbox access, monitor mailbox access logs

### Best Practices

1. **Regular Audits**: Run attack path analysis monthly to track changes
2. **MFA Enforcement**: Ensure all users in attack paths have MFA enabled
3. **Least Privilege**: Review and restrict unnecessary group memberships
4. **Monitor Activity**: Track sign-in patterns and unusual behavior
5. **Document Changes**: Maintain records of group memberships and role assignments
6. **Review Role-Assignable Groups**: Regularly audit groups that can be assigned roles
7. **Restrict Password Reset**: Limit password reset capabilities to necessary personnel
8. **Review Nested Groups**: Understand transitive memberships and their implications

## Export Formats

### CSV Export

Includes all fields for analysis:
- AttackPathType, SourceUser, SourceDisplayName, SourceUserId
- TargetResource, TargetResourceId, PathDescription, PathComplexity
- AccessType, RiskLevel, MFAEnabled, AccountEnabled
- LastSignIn, DaysSinceLastSignIn

### JSON Export

Structured format for automation:
```json
[
  {
    "AttackPathType": "Privilege Escalation",
    "SourceUser": "john.doe@company.com",
    "SourceDisplayName": "John Doe",
    "TargetResource": "IT Admins (role-assignable group)",
    "PathDescription": "User has transitive membership in role-assignable group",
    "PathComplexity": "Medium",
    "AccessType": "Transitive Group Membership",
    "RiskLevel": "CRITICAL",
    "MFAEnabled": false,
    "AccountEnabled": true,
    "DaysSinceLastSignIn": 3
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "No attack paths found"

**Cause**: No attack paths detected in the tenant, or insufficient permissions.

**Solution**: 
- Verify you have the required Graph API permissions
- Check if role-assignable groups exist in your tenant
- Ensure you have access to read group memberships

#### 2. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1
# Accept permission consent when prompted
```

#### 3. Module Import Failures

**Cause**: Missing or outdated Microsoft.Graph modules.

**Solution**:
```powershell
# Update all Graph modules
Update-Module Microsoft.Graph -Force

# Or reinstall
Uninstall-Module Microsoft.Graph -AllVersions
Install-Module Microsoft.Graph -Scope CurrentUser
```

#### 4. Slow Performance

**Cause**: Large number of groups/users or throttling.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -EnableStealth -MaxRetries 5

# Or filter to high-risk paths only
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -OnlyHighRisk
```

#### 5. Shared Mailbox Detection Limitations

**Cause**: Full mailbox permissions require Exchange Online PowerShell.

**Solution**:
- The script identifies potential shared mailboxes based on indicators
- For full mailbox permission analysis, use Exchange Online PowerShell:
  ```powershell
  Get-MailboxPermission -Identity "shared-mailbox@company.com"
  ```

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all attack paths
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -Matrix -ExportPath "attack-paths_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all attack paths, risk levels, and MFA status.

### Example 2: High-Risk Path Detection

```powershell
# Find only CRITICAL and HIGH risk attack paths
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -OnlyHighRisk -Matrix

# Review output, then remediate
```

**Use Case**: Identify immediate security risks for remediation.

### Example 3: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "attack-paths.json"
```

**Use Case**: Silent enumeration of attack paths during engagement.

### Example 4: Compliance Reporting

```powershell
# Monthly audit including disabled accounts
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track attack paths and security posture over time.

### Example 5: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -TenantId "customer-tenant-id" -ExportPath "customer-paths.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\AttackPaths_$date.csv"
    
    C:\Tools\Invoke-EntraAttackPathCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if critical paths found
    $results = Import-Csv $path
    $criticalPaths = $results | Where-Object { $_.Risk -eq "CRITICAL" }
    
    if ($criticalPaths.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($criticalPaths.Count) critical attack paths found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyAttackPathCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Attack Path Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraAttackPathCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_attack_path"
        severity = $_.RiskLevel
        source_user = $_.SourceUser
        target_resource = $_.TargetResource
        path_type = $_.AttackPathType
        mfa_enabled = $_.MFAEnabled
    }
}

$siemEvents | ConvertTo-Json | Out-File "siem_formatted.json"
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Support for privilege escalation path analysis
- Password reset delegation detection
- Transitive group membership analysis
- Shared mailbox access detection
- Risk assessment and path complexity analysis
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive attack path analytics

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
- **Invoke-EntraGroupCheck.ps1**: Group security analysis
- **Invoke-EntraAppAccess.ps1**: Critical administrative access audit

---

