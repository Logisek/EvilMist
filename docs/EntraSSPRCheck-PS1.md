# Invoke-EntraSSPRCheck.ps1

## Overview

`Invoke-EntraSSPRCheck.ps1` is a PowerShell 7+ script designed to enumerate and analyze Azure Entra ID users with Self-Service Password Reset (SSPR) enabled. This tool is part of the EvilMist toolkit and helps security teams identify users with SSPR configuration, assess their registration methods, and identify security risks related to password reset capabilities.

## Purpose

Self-Service Password Reset (SSPR) allows users to reset their passwords without administrator intervention. While convenient, SSPR can be an attack vector if not properly configured. This script helps:

- **Security Auditors**: Identify users with SSPR enabled and assess their registration methods
- **Penetration Testers**: Discover potential password reset attack vectors
- **IT Administrators**: Audit SSPR configuration and ensure proper backup methods are configured
- **Compliance Teams**: Generate reports for password reset governance

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **SSPR Status Detection**: Identifies users with SSPR enabled, registered, or capable
- ✅ **Registration Method Analysis**: Analyzes registered authentication methods for SSPR
- ✅ **Backup Method Detection**: Identifies users without backup methods configured
- ✅ **Strong Method Detection**: Distinguishes between strong and weak authentication methods
- ✅ **MFA Status Correlation**: Cross-references SSPR configuration with MFA status
- ✅ **Last Sign-In Tracking**: Shows last login date/time and activity patterns
- ✅ **Risk Assessment**: Categorizes users by risk level (HIGH/MEDIUM/LOW)
- ✅ **Activity Analytics**: Sign-in statistics, stale accounts, inactive users
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only users without backup methods or include disabled accounts

## SSPR Configuration Analysis

The script analyzes three key SSPR status indicators:

### SSPR Status Indicators

1. **isSsprEnabled** - Whether SSPR is enabled for the user (tenant-level policy)
2. **isSsprRegistered** - Whether the user has completed SSPR registration
3. **isSsprCapable** - Whether the user is capable of using SSPR (meets requirements)

### Registration Methods

The script analyzes registered authentication methods for SSPR:

**Strong Methods:**
- `mobilePhone` - Mobile phone number
- `alternateMobilePhone` - Alternate mobile phone number
- `officePhone` - Office phone number
- `email` - Email address
- `authenticatorApp` - Microsoft Authenticator app

**Weak Methods:**
- `securityQuestions` - Security questions (less secure)

### Backup Method Requirements

Microsoft recommends configuring **at least 2 authentication methods** for SSPR to ensure users can always reset their passwords. The script identifies:

- **Has Backup Methods**: User has 2+ methods registered
- **Has Strong Backup**: User has 2+ strong methods registered
- **No Backup Methods**: User has fewer than 2 methods (HIGH RISK)

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
  - `UserAuthenticationMethod.Read.All` - Read authentication methods
  - `Reports.Read.All` - Read authentication method registration reports
  - `AuditLog.Read.All` - Read audit logs and sign-in activity (optional)

- **Fallback Scopes** (if full access unavailable):
  - `User.ReadBasic.All` - Read basic user info
  - `Reports.Read.All` - Read authentication method registration reports

**Note**: The `Reports.Read.All` permission is required to access the `/reports/authenticationMethods/userRegistrationDetails` endpoint which provides SSPR registration data.

## Usage

### Basic Usage

```powershell
# Simple scan of all users with SSPR enabled
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -ExportPath "sspr-users.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -ExportPath "sspr-results.json"
```

### Include Disabled User Accounts

```powershell
# Scan all users including disabled accounts
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -IncludeDisabledUsers -ExportPath "all-sspr-users.csv"
```

### Show Only Users Without Backup Methods

```powershell
# Filter to show only users without backup methods (HIGH RISK)
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -OnlyNoBackup

# Matrix view with backup filter
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -OnlyNoBackup -Matrix
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all users, all SSPR configs, with export
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "full-audit.csv"

# Security focus: high-risk users only (no backup methods)
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -OnlyNoBackup -Matrix -ExportPath "high-risk-sspr.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
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
| `-OnlyNoBackup` | Switch | Show only users without SSPR backup methods | False |
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

The script provides detailed information about each user with SSPR configuration:

```
[HIGH] john.user@company.com
  Display Name: John User
  User Type: Member
  Email: john.user@company.com
  Job Title: Employee
  Department: Sales
  Account Status: Enabled
  SSPR Enabled: Yes
  SSPR Registered: No
  SSPR Methods (1): mobilePhone
  Backup Methods: No
  Strong Backup Methods: No
  MFA Enabled: No
  MFA Methods: Password Only
  Last Sign-In: 2024-12-20 14:23:45 (3 days ago) (Interactive)
  Created: 2023-05-10T08:15:00Z (591 days old)
  Licenses: 1 assigned
```

### Matrix Output (with `-Matrix`)

```
Risk  SSPR    Registered  Backup  MFA  Status   User Principal Name         Display Name    SSPR Methods        Last Sign-In  Department
----  ----    ----------  ------  ---  ------   -------------------         ------------    -------------       ------------  ----------
HIGH  Enabled No          No      No   Enabled  john.user@company.com       John User       mobilePhone         3d ago        Sales
MEDIUM Enabled Yes        Yes     No   Enabled  jane.user@company.com      Jane User       mobilePhone, email  1d ago        IT
LOW   Enabled Yes         Yes     Yes  Enabled  admin.user@company.com      Admin User      mobilePhone, auth... Today         IT
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total users with SSPR: 150
  - HIGH risk (no backup/enabled but not registered): 25
  - MEDIUM risk (weak backup/no MFA): 45
  - LOW risk (properly configured): 80

[SSPR STATUS]
  SSPR Enabled: 150
  SSPR Registered: 125
  With Backup Methods: 120
  Without Backup Methods: 30

[MFA STATUS]
  With MFA enabled: 100
  Without MFA: 50

[TOP DEPARTMENTS]
  IT: 35
  Sales: 28
  Operations: 15

[SSPR METHODS]
  mobilePhone, email: 45
  mobilePhone, securityQuestions: 30
  mobilePhone: 25

[SIGN-IN ACTIVITY]
  Never signed in: 5
  Recent (≤30 days): 120
  Stale (>90 days): 25
```

## Risk Levels

The script assigns risk levels based on SSPR configuration and account status:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **HIGH** | SSPR enabled but not registered OR no backup methods | Red | **IMMEDIATE ACTION REQUIRED**: Complete registration or add backup methods |
| **MEDIUM** | Only weak backup methods OR SSPR configured but no MFA | Yellow | Review: Add strong backup methods or enable MFA |
| **LOW** | Properly configured with strong backup methods | Green | Monitor: Acceptable risk |

### Risk Assessment Logic

```
IF account is enabled:
    IF SSPR enabled but NOT registered:
        RISK = HIGH (Enabled but not configured)
    ELSE IF no backup methods (< 2 methods):
        RISK = HIGH (No backup - account lockout risk)
    ELSE IF only weak backup methods (security questions only):
        RISK = MEDIUM (Weak security)
    ELSE IF no MFA configured:
        RISK = MEDIUM (SSPR without MFA)
    ELSE:
        RISK = LOW (Properly configured)
ELSE IF account is disabled:
    RISK = LOW (Cannot sign in)
```

## Security Considerations

### Why SSPR Security Matters

Self-Service Password Reset can be an attack vector if not properly secured:

1. **Account Takeover**: Attackers may attempt to reset passwords for high-value accounts
2. **Social Engineering**: Weak backup methods (security questions) are vulnerable to social engineering
3. **Single Point of Failure**: Users with only one method registered risk account lockout
4. **Privileged Account Risk**: Administrative accounts with weak SSPR configuration pose significant risk

### High-Risk Scenarios

1. **SSPR Enabled But Not Registered** (HIGH Risk)
   - User can potentially reset password but hasn't configured methods
   - May indicate incomplete onboarding or forgotten configuration
   - Risk of account lockout or unauthorized access

2. **No Backup Methods** (HIGH Risk)
   - User has only one authentication method registered
   - If method is lost/unavailable, user cannot reset password
   - Account lockout risk

3. **Weak Backup Methods Only** (MEDIUM Risk)
   - User relies solely on security questions
   - Vulnerable to social engineering attacks
   - Should be supplemented with stronger methods

4. **SSPR Without MFA** (MEDIUM Risk)
   - User can reset password but doesn't have MFA enabled
   - Password reset may be easier to compromise than MFA-protected accounts
   - Should enable MFA for additional security

### Best Practices

1. **Require Multiple Methods**: Ensure users register at least 2 authentication methods
2. **Prefer Strong Methods**: Encourage mobile phone, authenticator app, or email over security questions
3. **Enable MFA**: Users with SSPR should also have MFA enabled
4. **Regular Audits**: Run this script regularly to identify misconfigurations
5. **Monitor Changes**: Track SSPR registration changes over time
6. **Privileged Accounts**: Apply stricter requirements for administrative accounts

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track SSPR configuration changes
2. **Backup Method Enforcement**: Ensure all users have at least 2 methods registered
3. **Strong Method Preference**: Encourage strong methods over security questions
4. **MFA Correlation**: Cross-reference SSPR with MFA status
5. **Documentation**: Maintain records of SSPR configuration and changes

### For Penetration Testers

1. **Initial Reconnaissance**: Identify users with weak SSPR configuration
2. **Target Selection**: Prioritize HIGH risk users without backup methods
3. **Social Engineering**: Focus on users with security questions only
4. **Account Takeover**: Document SSPR configuration for password reset attacks
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify SSPR configuration aligns with security policies
3. **Trend Analysis**: Compare results over time
4. **Remediation Tracking**: Monitor backup method adoption rates
5. **Access Reviews**: Use reports for quarterly SSPR configuration certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- DisplayName, UserPrincipalName, Email
- AccountEnabled, UserType
- JobTitle, Department
- CreatedDateTime, DaysOld
- IsSSPRRegistered, IsSSPREnabled, IsSSPRCapable
- SSPRMethods, SSPRMethodCount
- BackupMethodCount, StrongMethodCount, WeakMethodCount
- HasBackupMethods, HasStrongBackup
- LastSignIn, LastSignInDisplay, DaysSinceLastSignIn, SignInType
- MFAEnabled, MFAMethods, MFAMethodCount
- HasLicenses, LicenseCount
- RiskLevel

### JSON Export

Structured format for automation:
```json
[
  {
    "DisplayName": "John User",
    "UserPrincipalName": "john.user@company.com",
    "Email": "john.user@company.com",
    "AccountEnabled": true,
    "IsSSPREnabled": true,
    "IsSSPRRegistered": false,
    "SSPRMethods": "mobilePhone",
    "SSPRMethodCount": 1,
    "HasBackupMethods": false,
    "RiskLevel": "HIGH",
    "MFAEnabled": false,
    "LastSignInDisplay": "2024-12-20 14:23:45 (3 days ago)"
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "No users with SSPR configuration found"

**Cause**: No users have SSPR enabled or registered in the tenant.

**Solution**: 
- Verify SSPR is enabled at the tenant level
- Check if users have completed SSPR registration
- Ensure you have `Reports.Read.All` permission

#### 2. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1
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

**Cause**: Large number of users or throttling.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -OnlyNoBackup
```

#### 5. "Reports.Read.All permission required"

**Cause**: The script requires `Reports.Read.All` to access SSPR registration data.

**Solution**:
- Request `Reports.Read.All` permission from your administrator
- The script will attempt to use fallback scopes but SSPR data may be limited

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all users with SSPR enabled
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all users, risk levels, and SSPR configuration.

### Example 2: High-Risk User Detection

```powershell
# Find users with SSPR but no backup methods
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -OnlyNoBackup -Matrix

# Review output, then remediate
```

**Use Case**: Identify immediate security risks for remediation.

### Example 3: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of users with weak SSPR configuration during engagement.

### Example 4: Compliance Reporting

```powershell
# Monthly audit including disabled accounts
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track SSPR configuration changes and backup method adoption over time.

### Example 5: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -TenantId "customer-tenant-id" -ExportPath "customer_sspr.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\SSPR_$date.csv"
    
    C:\Tools\Invoke-EntraSSPRCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if high-risk users found
    $results = Import-Csv $path
    $highRisk = $results | Where-Object { $_.RiskLevel -eq "HIGH" }
    
    if ($highRisk.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($highRisk.Count) high-risk SSPR accounts found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklySSPRCheck.ps1"
Register-ScheduledTask -TaskName "Weekly SSPR Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_sspr_config"
        severity = $_.RiskLevel
        user = $_.UserPrincipalName
        sspr_enabled = $_.IsSSPREnabled
        sspr_registered = $_.IsSSPRRegistered
        backup_methods = $_.HasBackupMethods
        mfa_enabled = $_.MFAEnabled
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
    .\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -Matrix -ExportPath "C:\Reports\sspr.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\sspr.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- SSPR status detection (enabled, registered, capable)
- Registration method analysis
- Backup method detection
- Strong vs weak method classification
- MFA status correlation
- Risk assessment framework
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
- **Invoke-EntraAppAccess.ps1**: Critical administrative access audit
- **Invoke-EntraRoleCheck.ps1**: Privileged role assignment audit

---

