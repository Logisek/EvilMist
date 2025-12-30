# Invoke-EntraLegacyAuthCheck.ps1

## Overview

`Invoke-EntraLegacyAuthCheck.ps1` is a PowerShell 7+ script designed to identify and analyze Azure Entra ID users and applications using legacy authentication protocols. Legacy authentication bypasses modern security controls like Multi-Factor Authentication (MFA) and Conditional Access policies, making it a significant security risk. This tool is part of the EvilMist toolkit and helps security teams identify and remediate legacy authentication usage in their Azure AD tenant.

## Purpose

Legacy authentication protocols (IMAP, POP3, SMTP, Exchange ActiveSync, etc.) do not support modern security features and can bypass MFA and Conditional Access policies. This script helps:

- **Security Auditors**: Identify users and applications using legacy authentication
- **Penetration Testers**: Discover attack vectors that bypass security controls
- **IT Administrators**: Audit legacy protocol usage and plan migration
- **Compliance Teams**: Generate reports for security policy compliance
- **Security Teams**: Prioritize remediation of high-risk legacy auth usage

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Comprehensive Protocol Detection**: Identifies 10 legacy authentication protocols
- ✅ **Sign-In Log Analysis**: Queries audit logs for legacy authentication usage
- ✅ **Last Usage Tracking**: Shows last legacy authentication date and time
- ✅ **MFA Status Detection**: Identifies users without Multi-Factor Authentication using legacy auth
- ✅ **Risk Assessment**: Categorizes users by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **Usage Statistics**: Tracks successful/failed sign-ins per protocol
- ✅ **Activity Analytics**: Sign-in statistics, protocol breakdowns, usage recency
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only recent usage or include disabled accounts

## Legacy Protocols Detected

The script detects the following legacy authentication protocols:

### Email Protocols

1. **IMAP4** (Internet Message Access Protocol)
   - Legacy email client protocol
   - Does not support modern authentication
   - Commonly used by older email clients

2. **POP3** (Post Office Protocol 3)
   - Legacy email retrieval protocol
   - Downloads emails to local client
   - No support for modern security features

3. **SMTP** (Simple Mail Transfer Protocol)
   - Email sending protocol
   - Authenticated SMTP for sending emails
   - Can bypass MFA requirements

4. **Authenticated SMTP**
   - SMTP with authentication
   - Used for sending emails from applications
   - Often bypasses security controls

### Exchange Protocols

5. **Exchange ActiveSync**
   - Mobile device synchronization protocol
   - Used by older mobile email clients
   - Limited security feature support

6. **MAPI Over HTTP**
   - Messaging Application Programming Interface over HTTP
   - Legacy Outlook connectivity
   - Replaced by modern authentication methods

7. **Autodiscover**
   - Automatic email configuration protocol
   - Can be used for reconnaissance
   - Legacy implementation lacks security features

8. **Exchange Online PowerShell**
   - Legacy PowerShell module for Exchange
   - Uses basic authentication
   - Being deprecated in favor of modern auth

9. **Outlook Anywhere** (RPC over HTTP)
   - Legacy Outlook connectivity method
   - Replaced by modern authentication
   - Security vulnerabilities present

### Other Legacy Clients

10. **Other clients**
    - Miscellaneous legacy authentication clients
    - Various older applications
    - Unknown or unclassified legacy protocols

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
   Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
   Install-Module Microsoft.Graph.Users -Scope CurrentUser
   ```

### Required Permissions

The script requires the following Microsoft Graph API permissions:

- **Primary Scopes** (preferred):
  - `AuditLog.Read.All` - **REQUIRED** for querying sign-in logs
  - `Directory.Read.All` - Read directory data
  - `User.Read.All` - Read all user profiles
  - `UserAuthenticationMethod.Read.All` - Read authentication methods

- **Fallback Scopes** (if full access unavailable):
  - `Directory.Read.All` - Read directory data
  - `User.ReadBasic.All` - Read basic user info

**Note**: Without `AuditLog.Read.All` permission, the script cannot query sign-in logs and will not be able to detect legacy authentication usage. This permission is essential for the script to function properly.

## Usage

### Basic Usage

```powershell
# Simple scan of all legacy authentication usage
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1

# The script queries sign-in logs for the last 90 days
# and identifies users who have used legacy protocols
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -ExportPath "legacy-auth.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -ExportPath "legacy-results.json"
```

### Show Only Recent Usage

```powershell
# Show only users with legacy auth in the last 30 days
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -OnlyRecent

# Matrix view with recent usage filter
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -OnlyRecent -Matrix
```

### Include Disabled User Accounts

```powershell
# Scan all users including disabled accounts
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -IncludeDisabledUsers -ExportPath "all-legacy-users.csv"
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all users, all protocols, with export
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "full-audit.csv"

# Security focus: recent usage only
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -OnlyRecent -Matrix -ExportPath "recent-legacy-auth.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
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
| `-OnlyRecent` | Switch | Show only users with legacy auth in the last 30 days | False |
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

The script provides detailed information about each user with legacy authentication usage:

```
[CRITICAL] john.user@company.com
  Display Name: John User
  User Type: Member
  Email: john.user@company.com
  Job Title: Sales Representative
  Department: Sales
  Account Status: Enabled
  Legacy Protocols (2): IMAP4, Exchange ActiveSync
  Last Legacy Auth: 2024-12-20 14:23:45 (3 days ago) (3 days ago)
  Legacy Sign-In Statistics: 45 total (42 successful, 3 failed)
  MFA Enabled: No
  Auth Methods: Password Only
  Last Sign-In: 2024-12-20 14:25:00 (3 days ago) (Interactive)
  Risk Reasons: Active user without MFA using legacy auth
  Created: 2023-05-10T08:15:00Z (591 days old)
```

### Matrix Output (with `-Matrix`)

```
Risk      MFA  Status   User Principal Name         Display Name    Protocols                    Last Legacy Auth  Sign-Ins  Department
----      ---  ------   -------------------         ------------    ---------                    -----------------  --------  ----------
CRITICAL  No   Enabled  john.user@company.com        John User       IMAP4, Exchange ActiveSync  This week         45        Sales
HIGH      Yes  Enabled  jane.admin@company.com       Jane Admin      SMTP                          This month         12        IT
MEDIUM    Yes  Enabled  bob.old@company.com          Bob Old         POP3                          60d ago           3         Finance
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total users with legacy auth usage: 15
  - CRITICAL risk (active without MFA): 5
  - HIGH risk (recent usage): 7
  - MEDIUM risk (older usage): 2
  - LOW risk (disabled accounts): 1

[MFA STATUS]
  With MFA enabled: 8
  Without MFA: 7

[USERS BY PROTOCOL]
  Exchange ActiveSync: 12
  IMAP4: 8
  SMTP: 5
  POP3: 3
  MAPI Over HTTP: 2
  Exchange Online PowerShell: 1

[TOP DEPARTMENTS]
  Sales: 7
  IT: 4
  Finance: 2

[USAGE RECENCY]
  Last 7 days: 3
  Last 30 days: 10
  >90 days ago: 2
```

## Risk Levels

The script assigns risk levels based on account status, MFA configuration, and usage recency:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Enabled account without MFA using legacy auth | Red | **IMMEDIATE ACTION REQUIRED**: Enable MFA and block legacy auth |
| **HIGH** | Recent legacy auth usage (within 30 days) | Yellow | **URGENT**: Investigate and migrate to modern auth |
| **MEDIUM** | Older legacy auth usage (31-90 days ago) | Cyan | **PRIORITY**: Plan migration and block legacy auth |
| **LOW** | Disabled account with legacy auth history | Green | **MONITOR**: Account disabled, low immediate risk |

### Risk Assessment Logic

```
IF account is enabled AND has legacy auth usage:
    IF no MFA configured:
        RISK = CRITICAL (Legacy auth bypasses security)
    ELSE IF usage within 7 days:
        RISK = HIGH (Recent usage, security risk)
    ELSE IF usage within 30 days:
        RISK = HIGH (Recent usage)
    ELSE:
        RISK = MEDIUM (Older usage, still a risk)
ELSE IF account is disabled:
    RISK = LOW (Cannot sign in)
```

## Security Considerations

### Why Legacy Authentication is Dangerous

Legacy authentication protocols pose significant security risks:

1. **Bypasses MFA**: Legacy protocols cannot enforce Multi-Factor Authentication
2. **Bypasses Conditional Access**: Most CA policies don't apply to legacy auth
3. **Password-Only Authentication**: Relies solely on username/password
4. **Credential Theft Risk**: Easier to intercept and replay credentials
5. **Brute Force Vulnerable**: No account lockout protection
6. **No Modern Security Features**: Missing device trust, location-based access, etc.

### High-Risk Scenarios

1. **Active User Without MFA** (CRITICAL Risk)
   - Can authenticate with just username/password
   - Legacy protocols bypass all security controls
   - High likelihood of credential compromise success

2. **Recent Usage** (HIGH Risk)
   - Active legacy authentication indicates ongoing use
   - May indicate applications or devices still using legacy protocols
   - Immediate migration required

3. **Multiple Protocols** (HIGH Risk)
   - Users using multiple legacy protocols indicate heavy legacy dependency
   - May require comprehensive migration planning
   - Higher attack surface

4. **Failed Sign-In Attempts** (HIGH Risk)
   - Failed legacy auth attempts may indicate:
     - Brute force attacks
     - Credential stuffing attempts
     - Account enumeration
   - Should be investigated immediately

### Migration Recommendations

1. **Immediate Actions**:
   - Block legacy authentication for all users
   - Enable MFA for all users
   - Review and update Conditional Access policies

2. **Short-Term Actions**:
   - Identify applications/devices using legacy protocols
   - Migrate email clients to modern authentication
   - Update scripts and automation to use modern auth

3. **Long-Term Actions**:
   - Implement security baselines
   - Regular audits of legacy auth usage
   - User training on modern authentication methods

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track legacy auth usage
2. **Block Legacy Auth**: Use Conditional Access to block legacy protocols
3. **MFA Enforcement**: Ensure all users have MFA enabled
4. **Monitor Activity**: Track sign-in patterns and unusual behavior
5. **Document Changes**: Maintain records of migration progress

### For Penetration Testers

1. **Initial Reconnaissance**: Identify users using legacy auth
2. **Target Selection**: Prioritize CRITICAL risk users without MFA
3. **Credential Attacks**: Legacy auth is easier to attack
4. **Bypass Testing**: Verify that legacy auth bypasses security controls
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify legacy auth aligns with security policies
3. **Trend Analysis**: Compare results over time
4. **Remediation Tracking**: Monitor migration progress
5. **Access Reviews**: Use reports for quarterly security assessments

## Export Formats

### CSV Export

Includes all fields for analysis:
- DisplayName, UserPrincipalName, Email
- AccountEnabled, UserType
- JobTitle, Department
- CreatedDateTime, DaysOld
- LegacyProtocols, ProtocolCount
- LastLegacySignIn, DaysSinceLastLegacyAuth, LastLegacySignInDisplay
- TotalLegacySignIns, SuccessfulLegacySignIns, FailedLegacySignIns
- LastSignIn, LastSignInDisplay, DaysSinceLastSignIn, SignInType
- MFAEnabled, AuthMethods, MethodCount
- RiskLevel, RiskReasons

### JSON Export

Structured format for automation:
```json
[
  {
    "DisplayName": "John User",
    "UserPrincipalName": "john.user@company.com",
    "Email": "john.user@company.com",
    "AccountEnabled": true,
    "LegacyProtocols": "IMAP4, Exchange ActiveSync",
    "ProtocolCount": 2,
    "LastLegacySignIn": "2024-12-20T14:23:45Z",
    "DaysSinceLastLegacyAuth": 3,
    "TotalLegacySignIns": 45,
    "SuccessfulLegacySignIns": 42,
    "FailedLegacySignIns": 3,
    "MFAEnabled": false,
    "AuthMethods": "Password Only",
    "RiskLevel": "CRITICAL",
    "RiskReasons": "Active user without MFA using legacy auth"
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "AuditLog.Read.All permission not available"

**Cause**: The script requires `AuditLog.Read.All` permission to query sign-in logs.

**Solution**: 
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1
# Accept permission consent when prompted
```

**Note**: Without this permission, the script cannot detect legacy authentication usage.

#### 2. "No legacy authentication usage found"

**Cause**: Either no legacy auth usage exists, or the time window (90 days) doesn't contain any usage.

**Solution**:
- Verify that legacy authentication is actually being used
- Check if sign-in logs are being retained
- Review Conditional Access policies - legacy auth may already be blocked

#### 3. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1
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

**Cause**: Large number of sign-ins or throttling.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -EnableStealth -MaxRetries 5

# Or filter to recent usage only
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -OnlyRecent
```

#### 6. Throttling Errors (429)

**Cause**: Too many API requests in a short time.

**Solution**:
```powershell
# Enable stealth mode with delays
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -EnableStealth -RequestDelay 2 -RequestJitter 1

# Increase retry count
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -MaxRetries 10
```

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all users with legacy authentication usage
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all users, risk levels, protocols, and usage statistics.

### Example 2: Critical Risk Detection

```powershell
# Find users without MFA using legacy auth (CRITICAL risk)
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -Matrix | Where-Object { $_.RiskLevel -eq "CRITICAL" }
```

**Use Case**: Identify immediate security risks for remediation.

### Example 3: Recent Usage Analysis

```powershell
# Show only users with legacy auth in the last 30 days
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -OnlyRecent -Matrix -ExportPath "recent-usage.csv"
```

**Use Case**: Focus on active legacy authentication usage.

### Example 4: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of legacy auth attack vectors during engagement.

### Example 5: Compliance Reporting

```powershell
# Monthly audit including disabled accounts
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track legacy auth usage and migration progress over time.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\LegacyAuth_$date.csv"
    
    C:\Tools\Invoke-EntraLegacyAuthCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if critical risk users found
    $results = Import-Csv $path
    $criticalRisk = $results | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    
    if ($criticalRisk.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($criticalRisk.Count) critical legacy auth users found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyLegacyAuthCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Legacy Auth Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "legacy_auth_usage"
        severity = $_.RiskLevel
        user = $_.UserPrincipalName
        protocols = $_.LegacyProtocols
        last_usage = $_.LastLegacySignIn
        mfa_enabled = $_.MFAEnabled
        sign_in_count = $_.TotalLegacySignIns
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
    .\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -Matrix -ExportPath "C:\Reports\legacy-auth.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\legacy-auth.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Support for 10 legacy authentication protocols
- Sign-in log analysis for last 90 days
- MFA detection and risk assessment
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive usage analytics

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
- **Invoke-EntraConditionalAccessCheck.ps1**: Conditional Access policy analysis
- **Invoke-EntraAppAccess.ps1**: Critical administrative access audit

---

