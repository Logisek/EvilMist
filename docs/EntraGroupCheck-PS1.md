# Invoke-EntraGroupCheck.ps1

## Overview

`Invoke-EntraGroupCheck.ps1` is a PowerShell 7+ script designed to enumerate and analyze Azure Entra ID groups, identify security issues including groups with no owners, owners without MFA, excessive membership, and role-assignable groups. This tool is part of the EvilMist toolkit and helps security teams identify group security risks in their tenant.

## Purpose

Groups in Azure Entra ID can have significant security implications. This script helps:
- **Security Auditors**: Identify groups with security misconfigurations
- **Penetration Testers**: Discover potential privilege escalation and lateral movement vectors
- **IT Administrators**: Audit group ownership and security posture
- **Compliance Teams**: Generate reports for group governance and risk assessment

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Comprehensive Group Enumeration**: Enumerates all groups (Security, Microsoft 365, Distribution, Dynamic)
- ✅ **Owner Analysis**: Identifies group owners and checks their MFA status
- ✅ **No Owner Detection**: Identifies groups with no owners (orphaned groups)
- ✅ **Excessive Membership Detection**: Identifies groups with excessive members (>100 or >500)
- ✅ **Role-Assignable Group Detection**: Identifies groups that can be assigned to directory roles (CRITICAL risk)
- ✅ **Risk Assessment**: Categorizes groups by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **MFA Status Detection**: Identifies owners without Multi-Factor Authentication
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only groups with no owners, excessive members, or high-risk groups

## Group Types Analyzed

The script analyzes all group types in Azure Entra ID:

### Security Groups
- Used for access control and permissions
- Can be assigned to resources and applications
- Security-enabled groups with no owners pose HIGH risk

### Microsoft 365 Groups
- Unified groups for collaboration
- Includes Teams, SharePoint, and other M365 services
- Owners without MFA pose MEDIUM risk

### Distribution Groups
- Email distribution lists
- Generally lower risk unless used for security purposes

### Dynamic Groups
- Membership based on rules/queries
- Can automatically grant access based on user attributes
- Requires careful review of membership rules

### Role-Assignable Groups (CRITICAL)
- Groups that can be assigned to directory roles
- If compromised, can grant privileged access
- **CRITICAL RISK** - Immediate review required

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
  - `AuditLog.Read.All` - Read audit logs (optional)

- **Fallback Scopes** (if full access unavailable):
  - `Directory.Read.All` - Read directory data
  - `Group.Read.All` - Read all groups
  - `User.ReadBasic.All` - Read basic user info

**Note**: If `AuditLog.Read.All` is not available, the script will continue to work but may have limited sign-in activity data. All other features will continue to work normally.

## Usage

### Basic Usage

```powershell
# Enumerate all groups and analyze security posture
.\scripts\powershell\Invoke-EntraGroupCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -ExportPath "groups.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -ExportPath "groups.json"
```

### Show Only Groups with No Owners

```powershell
# Filter to show only groups with no owners
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -OnlyNoOwners

# Matrix view with no owners filter
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -OnlyNoOwners -Matrix
```

### Show Only Groups with Excessive Members

```powershell
# Filter to show only groups with excessive members (>100)
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -OnlyExcessiveMembers

# Export excessive membership groups
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -OnlyExcessiveMembers -ExportPath "large-groups.csv"
```

### Show Only High-Risk Groups

```powershell
# Filter to show only CRITICAL and HIGH risk groups
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -OnlyHighRisk

# Matrix view with high-risk filter
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -OnlyHighRisk -Matrix
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all groups, with export
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -Matrix -ExportPath "full-audit.csv"

# Security focus: high-risk groups only
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -OnlyHighRisk -Matrix -ExportPath "high-risk.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
```

## Parameters

### General Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-ExportPath` | String | Path to export results (CSV or JSON based on extension) | None |
| `-TenantId` | String | Optional Tenant ID. Uses home tenant if not specified | None |
| `-UseAzCliToken` | Switch | Try to use Azure CLI cached token first | False |
| `-UseAzPowerShellToken` | Switch | Try to use Azure PowerShell cached token first | False |
| `-OnlyNoOwners` | Switch | Show only groups with no owners | False |
| `-OnlyExcessiveMembers` | Switch | Show only groups with excessive members (>100) | False |
| `-OnlyHighRisk` | Switch | Show only groups with CRITICAL or HIGH risk | False |
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

The script provides detailed information about each group:

```
[CRITICAL] Admin Group
  Group Type: Security
  Group ID: 12345678-1234-1234-1234-123456789012
  Security Enabled: Yes
  Mail Enabled: No
  Role-Assignable: Yes
  Created: 2024-01-15T10:30:00Z
  Owners: 2
    Owners without MFA: 1
    - John Admin (john.admin@company.com)
      MFA: Yes (Authenticator App, Phone)
    - Jane User (jane.user@company.com)
      MFA: No
  Members: 45
  Risk Factors: Role-assignable group, 1 owner(s) without MFA
```

### Matrix Output (with `-Matrix`)

```
Risk      Group Name              Type         Owners  Owners w/o MFA  Members  Role-Assignable  Risk Factors
----      ----------              ----         ------  ---------------  -------  ---------------  ------------
CRITICAL  Admin Group             Security     2       1               45       Yes              Role-assignable group, 1 owner(s) without MFA
HIGH      Orphaned Security Group Security     0       0               12       No               No owners
HIGH      Large Distribution      Distribution 1       0               523      No               Excessive members (523)
MEDIUM    Marketing Team          Microsoft 365 3       1               89       No               1 owner(s) without MFA
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total groups analyzed: 245
Groups in results: 245

[RISK BREAKDOWN]
  - CRITICAL risk: 3
  - HIGH risk: 12
  - MEDIUM risk: 45
  - LOW risk: 185

[SECURITY METRICS]
  - Groups with no owners: 8
  - Groups with excessive members (>100): 23
  - Role-assignable groups: 3
  - Total owners without MFA: 15

[GROUPS BY TYPE]
  Security: 89
  Microsoft 365: 123
  Distribution: 28
  Dynamic: 5
```

## Risk Levels

The script assigns risk levels based on group configuration and security posture:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Group is role-assignable (can be assigned to directory roles) | Red | **IMMEDIATE ACTION REQUIRED**: Review and restrict role-assignable groups |
| **HIGH** | Security group with no owners OR group with >500 members OR security group with owners without MFA | Red | **URGENT REVIEW**: Assign owners, review membership, or enable MFA for owners |
| **MEDIUM** | Group with >100 members OR group with no owners (non-security) OR Microsoft 365 group with owners without MFA | Yellow | **REVIEW**: Monitor membership, assign owners, or enable MFA |
| **LOW** | Group with standard configuration and secure owners | Green | **MONITOR**: Acceptable risk, regular review recommended |

### Risk Assessment Logic

```
IF group is role-assignable:
    RISK = CRITICAL
ELSE IF security group AND no owners:
    RISK = HIGH
ELSE IF member count > 500:
    RISK = HIGH
ELSE IF security group AND owners without MFA:
    RISK = HIGH
ELSE IF member count > 100:
    RISK = MEDIUM
ELSE IF no owners (non-security):
    RISK = MEDIUM
ELSE IF Microsoft 365 group AND owners without MFA:
    RISK = MEDIUM
ELSE:
    RISK = LOW
```

## Security Considerations

### Why Group Security Matters

Groups in Azure Entra ID can:
- **Grant access to resources**: Security groups control access to applications, files, and services
- **Assign directory roles**: Role-assignable groups can grant privileged access
- **Enable lateral movement**: Large groups may provide broad access across the organization
- **Create orphaned access**: Groups with no owners cannot be properly managed
- **Bypass security controls**: Owners without MFA are easier to compromise

### High-Risk Scenarios

1. **Role-Assignable Groups** (CRITICAL)
   - Groups that can be assigned to directory roles (Global Admin, etc.)
   - If compromised, can grant privileged access to attackers
   - **Action**: Immediate review and restrict to essential groups only

2. **Groups with No Owners** (HIGH)
   - Security groups without owners cannot be properly managed
   - May indicate abandoned or orphaned groups
   - **Action**: Assign owners immediately

3. **Excessive Membership** (HIGH/MEDIUM)
   - Groups with >500 members provide broad access
   - Difficult to audit and manage
   - **Action**: Review membership and consider splitting into smaller groups

4. **Owners Without MFA** (HIGH/MEDIUM)
   - Owners can modify group membership and settings
   - Without MFA, easier to compromise via credential attacks
   - **Action**: Enable MFA for all group owners

5. **Dynamic Groups** (Variable Risk)
   - Membership based on rules/queries
   - Can automatically grant access based on user attributes
   - **Action**: Review membership rules regularly

### Best Practices

1. **Regular Audits**: Run monthly to track group changes
2. **Owner Assignment**: Ensure all groups have at least one owner
3. **MFA for Owners**: Require MFA for all group owners
4. **Limit Role-Assignable Groups**: Minimize role-assignable groups
5. **Monitor Membership**: Review large groups regularly
6. **Document Purpose**: Maintain records of group purpose and membership
7. **Review Dynamic Rules**: Audit dynamic group membership rules
8. **Least Privilege**: Limit group membership to necessary users only

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track group security posture
2. **Risk Prioritization**: Focus on CRITICAL and HIGH risk groups first
3. **Owner Management**: Ensure all groups have assigned owners
4. **MFA Enforcement**: Require MFA for all group owners
5. **Role-Assignable Review**: Audit and restrict role-assignable groups

### For Penetration Testers

1. **Initial Reconnaissance**: Identify role-assignable groups
2. **Target Selection**: Prioritize CRITICAL and HIGH risk groups
3. **Owner Analysis**: Focus on groups with owners without MFA
4. **Lateral Movement**: Identify large groups for potential access paths
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify group configuration aligns with policies
3. **Trend Analysis**: Compare results over time to track risk trends
4. **Remediation Tracking**: Monitor reduction in high-risk groups
5. **Access Reviews**: Use reports for quarterly group access certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- Id, DisplayName, Description
- GroupType, SecurityEnabled, MailEnabled, IsAssignableToRole
- CreatedDateTime, OnPremisesSyncEnabled
- OwnerCount, OwnersWithoutMFA, OwnerNames, OwnerUPNs, OwnerInfoJSON
- MemberCount, HasExcessiveMembers, HasNoOwners
- RiskLevel, RiskFactors

### JSON Export

Structured format for automation:
```json
[
  {
    "Id": "12345678-1234-1234-1234-123456789012",
    "DisplayName": "Admin Group",
    "GroupType": "Security",
    "SecurityEnabled": true,
    "IsAssignableToRole": true,
    "OwnerCount": 2,
    "OwnersWithoutMFA": 1,
    "MemberCount": 45,
    "RiskLevel": "CRITICAL",
    "RiskFactors": "Role-assignable group, 1 owner(s) without MFA"
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "No groups found or access denied"

**Cause**: Insufficient Graph API permissions.

**Solution**: 
- Ensure you have Directory.Read.All and Group.Read.All permissions
- Try re-authenticating with proper scopes
- Verify access token has required permissions

#### 2. "Unable to retrieve group owners"

**Cause**: Some groups may not allow owner enumeration or insufficient permissions.

**Solution**:
- Verify Group.Read.All permission is granted
- Some groups may be synced from on-premises and have limited visibility
- Check if group has any owners assigned

#### 3. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraGroupCheck.ps1
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

**Cause**: Large number of groups or throttling.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -OnlyHighRisk
```

#### 6. Member Count Inaccurate

**Cause**: Member count API may not be available or groups may have dynamic membership.

**Solution**:
- Script uses best-effort member counting
- Dynamic groups may show estimated counts
- Large groups may have approximate counts due to API limitations

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all groups and security issues
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all groups, risk levels, and security details.

### Example 2: High-Risk Group Detection

```powershell
# Find groups with CRITICAL or HIGH risk
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -OnlyHighRisk -Matrix

# Review output, then remediate
```

**Use Case**: Identify immediate security risks for remediation.

### Example 3: Orphaned Group Detection

```powershell
# Find all groups with no owners
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -OnlyNoOwners -ExportPath "orphaned-groups.csv"

# Review and assign owners
```

**Use Case**: Identify groups that need owner assignment.

### Example 4: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using Azure CLI token
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of high-value targets during engagement.

### Example 5: Compliance Reporting

```powershell
# Monthly audit with export
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track group security changes and risk trends over time.

### Example 6: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -TenantId "customer-tenant-id" -ExportPath "customer-groups.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\Groups_$date.csv"
    
    C:\Tools\Invoke-EntraGroupCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if critical groups found
    $results = Import-Csv $path
    $critical = $results | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    
    if ($critical.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($critical.Count) critical groups found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyGroupCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Group Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraGroupCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "group_security_risk"
        severity = $_.RiskLevel
        group_name = $_.DisplayName
        group_type = $_.GroupType
        no_owners = $_.HasNoOwners
        excessive_members = $_.HasExcessiveMembers
        role_assignable = $_.IsAssignableToRole
        owners_without_mfa = $_.OwnersWithoutMFA
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
    .\scripts\powershell\Invoke-EntraGroupCheck.ps1 -Matrix -ExportPath "C:\Reports\groups.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\groups.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Comprehensive group enumeration
- Owner analysis with MFA status detection
- No owner detection
- Excessive membership detection
- Role-assignable group detection
- Risk assessment framework (CRITICAL/HIGH/MEDIUM/LOW)
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive group analytics

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
- **Invoke-EntraRoleCheck.ps1**: Privileged directory role assignment check
- **Invoke-EntraAppAccess.ps1**: Critical administrative application access check

---

