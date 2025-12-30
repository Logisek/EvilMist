# Invoke-EntraPasswordPolicyCheck.ps1

## Overview

`Invoke-EntraPasswordPolicyCheck.ps1` is a PowerShell 7+ script designed to analyze Azure Entra ID password policies and identify security gaps and weak configurations. This tool is part of the EvilMist toolkit and helps security teams identify users with weak password policies, password expiration issues, and policy misconfigurations in their Azure AD tenant.

## Purpose

Password policies are a critical component of identity security. This script helps:
- **Security Auditors**: Identify users with weak password policies
- **Penetration Testers**: Discover accounts with password policy vulnerabilities
- **IT Administrators**: Audit password policy compliance and identify gaps
- **Compliance Teams**: Generate reports for password policy governance

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Password Expiration Analysis**: Checks password expiration policies per user
- ✅ **Never Expires Detection**: Identifies users with "password never expires" flag
- ✅ **Complexity Requirements**: Checks password complexity requirements (strong password enforcement)
- ✅ **Weak Policy Detection**: Identifies users with weak password policies
- ✅ **Password Age Tracking**: Calculates password age and expiration risk
- ✅ **Risk Assessment**: Categorizes users by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **Activity Analytics**: Sign-in statistics, stale accounts, password age analysis
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only weak policies or never expires accounts

## Password Policy Checks

The script performs comprehensive password policy analysis:

### User-Level Policy Checks

1. **Password Never Expires** (`DisablePasswordExpiration`)
   - Identifies users with passwords that never expire
   - High risk for long-lived credentials
   - Violates security best practices

2. **Strong Password Disabled** (`DisableStrongPassword`)
   - Identifies users with complexity requirements disabled
   - Allows weak passwords (e.g., "Password123")
   - Critical security vulnerability

3. **Password Age Analysis**
   - Calculates days since last password change
   - Identifies expired passwords
   - Flags passwords approaching expiration

4. **Policy Strength Assessment**
   - **Strong**: Complexity enabled, expiration enabled
   - **Moderate**: Complexity enabled, expiration disabled
   - **Weak**: Complexity disabled (regardless of expiration)

### Directory-Level Policy Checks

- Attempts to retrieve directory-wide password policy configuration
- Provides context for user-level policy exceptions
- Requires additional permissions (may not be available in all tenants)

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
   Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
   ```

### Required Permissions

The script requires the following Microsoft Graph API permissions:

- **Primary Scopes** (preferred):
  - `User.Read.All` - Read all user profiles
  - `Directory.Read.All` - Read directory data
  - `AuditLog.Read.All` - Read audit logs and sign-in activity (for password change dates)

- **Fallback Scopes** (if full access unavailable):
  - `User.ReadBasic.All` - Read basic user info
  - `Directory.Read.All` - Read directory data

**Note**: If `AuditLog.Read.All` is not available, the script will automatically fall back to retrieving users without password change date data. All other features will continue to work normally.

## Usage

### Basic Usage

```powershell
# Simple scan of all password policies
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -ExportPath "password-policies.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -ExportPath "policy-results.json"
```

### Include Disabled User Accounts

```powershell
# Scan all users including disabled accounts
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -IncludeDisabledUsers -ExportPath "all-policies.csv"
```

### Show Only Weak Policies

```powershell
# Filter to show only users with weak password policies
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -OnlyWeakPolicies

# Matrix view with weak policies filter
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -OnlyWeakPolicies -Matrix
```

### Show Only Never Expires

```powershell
# Filter to show only users with password never expires
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -OnlyNeverExpires

# Matrix view with never expires filter
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -OnlyNeverExpires -Matrix
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all users, weak policies, with export
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -IncludeDisabledUsers -OnlyWeakPolicies -Matrix -ExportPath "full-audit.csv"

# Security focus: never expires accounts only
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -OnlyNeverExpires -Matrix -ExportPath "never-expires.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
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
| `-OnlyWeakPolicies` | Switch | Show only users with weak password policies | False |
| `-OnlyNeverExpires` | Switch | Show only users with password never expires | False |
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

The script provides detailed information about each user with password policy issues:

```
[HIGH] john.admin@company.com
  Display Name: John Admin
  User Type: Member
  Email: john.admin@company.com
  Job Title: IT Administrator
  Department: IT
  Account Status: Enabled
  Risk Reasons: Password never expires
  Password Policy Strength: Moderate
  Password Never Expires: Yes
  Strong Password: Enabled
  Password Policies: DisablePasswordExpiration
  Password Age: Never expires
  Last Sign-In: 2024-12-20 14:23:45 (3 days ago) (Interactive)
  Created: 2023-05-10T08:15:00Z
```

### Matrix Output (with `-Matrix`)

```
Risk     Policy    Never Expires  Strong Pwd  User Principal Name         Password Age    Last Sign-In  Department
----     ------    -------------  ----------  -------------------         -------------   ------------  ----------
HIGH     Moderate  Yes            Enabled     john.admin@company.com       Never expires   3d ago        IT
CRITICAL Weak      Yes            Disabled    service.account@company.com Never expires   Never         IT
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total users scanned: 150
Users with policy issues: 12
  - CRITICAL risk: 2
  - HIGH risk: 5
  - MEDIUM risk: 3
  - LOW risk: 2

[PASSWORD POLICY GAPS]
  Users with password never expires: 8
  Users with strong password disabled: 2
  Users with expired passwords: 3
  Users with weak policies: 2

[TOP DEPARTMENTS WITH POLICY ISSUES]
  IT: 5
  Operations: 3
  Security: 2

[PASSWORD AGE]
  Passwords >365 days old: 4
  Passwords ≤90 days old: 8
```

## Risk Levels

The script assigns risk levels based on password policy configuration:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Strong password disabled AND password never expires | Red | **IMMEDIATE ACTION REQUIRED**: Enable strong password and expiration |
| **HIGH** | Strong password disabled OR password never expires OR expired password | Yellow | **URGENT**: Fix password policy configuration |
| **MEDIUM** | Password >365 days old OR expiring soon (≤7 days) | Cyan | Review: Consider password rotation |
| **LOW** | Strong policy with recent password change | Green | Monitor: Acceptable risk |

### Risk Assessment Logic

```
IF strong password disabled AND never expires:
    RISK = CRITICAL (Weakest possible policy)
ELSE IF strong password disabled:
    RISK = HIGH (Weak passwords allowed)
ELSE IF never expires:
    RISK = HIGH (No password rotation)
ELSE IF password expired:
    RISK = HIGH (Security risk)
ELSE IF password >365 days old:
    RISK = MEDIUM (Consider rotation)
ELSE IF password expiring soon (≤7 days):
    RISK = MEDIUM (Upcoming expiration)
ELSE:
    RISK = LOW (Strong policy)
```

## Security Considerations

### Why Password Policies Matter

Weak password policies create significant security risks:

1. **Password Never Expires**
   - Passwords remain valid indefinitely
   - Compromised credentials remain usable long-term
   - No forced rotation reduces security posture
   - Violates compliance requirements (NIST, ISO 27001, etc.)

2. **Strong Password Disabled**
   - Allows weak passwords (e.g., "Password123", "Welcome1")
   - Vulnerable to dictionary attacks
   - Easier to brute force
   - Increases credential stuffing success rate

3. **Expired Passwords**
   - Users may not be aware passwords expired
   - Can lead to account lockouts or security bypasses
   - Indicates poor password management

4. **Old Passwords**
   - Passwords unchanged for >365 days increase risk
   - Longer exposure window if compromised
   - May violate organizational policies

### High-Risk Scenarios

1. **CRITICAL: Service Accounts with Weak Policies**
   - Service accounts with strong password disabled AND never expires
   - Often have elevated permissions
   - Rarely monitored for sign-ins
   - High-value targets for attackers

2. **HIGH: Administrative Accounts**
   - Admin accounts with password never expires
   - Privileged access without rotation
   - Long-lived credentials increase attack surface

3. **HIGH: Expired Passwords**
   - Users with expired passwords may bypass security
   - Indicates policy enforcement gaps
   - Can lead to account compromise

4. **MEDIUM: Old Passwords**
   - Passwords unchanged for extended periods
   - May indicate forgotten or shared credentials
   - Consider forced rotation

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track policy compliance
2. **Policy Enforcement**: Ensure all users have strong password policies
3. **Exception Management**: Document and review any policy exceptions
4. **Password Rotation**: Enforce regular password changes for sensitive accounts
5. **Monitor Changes**: Track when policies are modified or exceptions granted

### For Penetration Testers

1. **Initial Reconnaissance**: Identify users with weak password policies
2. **Target Selection**: Prioritize CRITICAL and HIGH risk accounts
3. **Credential Attacks**: Focus on accounts with weak complexity requirements
4. **Persistence**: Document for long-term access opportunities
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify policies align with compliance requirements
3. **Trend Analysis**: Compare results over time
4. **Remediation Tracking**: Monitor policy improvements
5. **Exception Tracking**: Maintain records of policy exceptions

## Export Formats

### CSV Export

Includes all fields for analysis:
- DisplayName, UserPrincipalName, Email
- AccountEnabled, UserType
- JobTitle, Department
- CreatedDateTime
- PasswordPolicies, NeverExpires, StrongPasswordDisabled
- PolicyStrength
- LastPasswordChange, DaysSincePasswordChange
- IsExpired, ExpiresInDays, PasswordAgeDisplay
- LastSignIn, LastSignInDisplay, DaysSinceLastSignIn, SignInType
- RiskLevel, RiskReasons

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
    "PasswordPolicies": "DisablePasswordExpiration",
    "NeverExpires": true,
    "StrongPasswordDisabled": false,
    "PolicyStrength": "Moderate",
    "PasswordAgeDisplay": "Never expires",
    "RiskLevel": "HIGH",
    "RiskReasons": "Password never expires"
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "Could not retrieve directory password policy"

**Cause**: Directory-level password policy requires additional permissions.

**Solution**: 
- This is informational only
- User-level policies are still analyzed
- Directory policy retrieval is optional

#### 2. "Password change date unavailable"

**Cause**: Missing `AuditLog.Read.All` permission.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1
# Accept permission consent when prompted
```

#### 3. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1
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
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -OnlyWeakPolicies
```

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all users with password policy issues
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all users, risk levels, and policy details.

### Example 2: Critical Risk Detection

```powershell
# Find users with CRITICAL risk (weak policies)
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -OnlyWeakPolicies -Matrix

# Review output, then remediate
```

**Use Case**: Identify immediate security risks for remediation.

### Example 3: Never Expires Audit

```powershell
# Find all users with password never expires
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -OnlyNeverExpires -Matrix -ExportPath "never-expires.csv"
```

**Use Case**: Compliance audit for password expiration policies.

### Example 4: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of high-value targets during engagement.

### Example 5: Compliance Reporting

```powershell
# Monthly audit including disabled accounts
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track policy compliance and improvements over time.

### Example 6: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -TenantId "customer-tenant-id" -ExportPath "customer_policies.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\PasswordPolicy_$date.csv"
    
    C:\Tools\Invoke-EntraPasswordPolicyCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if critical risks found
    $results = Import-Csv $path
    $criticalRisk = $results | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    
    if ($criticalRisk.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($criticalRisk.Count) critical password policy issues found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyPasswordPolicyCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Password Policy Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_password_policy"
        severity = $_.RiskLevel
        user = $_.UserPrincipalName
        never_expires = $_.NeverExpires
        strong_password_disabled = $_.StrongPasswordDisabled
        policy_strength = $_.PolicyStrength
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
    .\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -Matrix -ExportPath "C:\Reports\policies.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\policies.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Password expiration policy analysis
- Password complexity requirement checking
- Never expires detection
- Weak policy identification
- Risk assessment framework
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive policy analytics

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
- **Invoke-EntraStaleAccountCheck.ps1**: Account hygiene and stale account analysis

---

