# Invoke-EntraStaleAccountCheck.ps1

## Overview

`Invoke-EntraStaleAccountCheck.ps1` is a PowerShell 7+ script designed to identify stale Azure Entra ID accounts and analyze account hygiene issues. This tool is part of the EvilMist toolkit and helps security teams identify accounts that pose security risks due to inactivity, expired passwords, or misconfigured license assignments.

## Purpose

Stale accounts can pose significant security risks:
- **Inactive accounts** may be forgotten but still have access to resources
- **Disabled accounts with licenses** waste resources and may indicate incomplete offboarding
- **Expired passwords** can indicate accounts that haven't been used in a long time
- **Never-signed-in accounts** may be test accounts or accounts created but never activated

This script helps:
- **Security Auditors**: Identify accounts that need review or removal
- **IT Administrators**: Clean up stale accounts and optimize license usage
- **Compliance Teams**: Generate reports for account hygiene audits
- **Penetration Testers**: Identify potential attack vectors (forgotten accounts)

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Stale Account Detection**: Identifies accounts with no recent sign-in (>90 days)
- ✅ **Never Signed-In Detection**: Finds accounts that have never been used
- ✅ **License Waste Detection**: Identifies disabled accounts still assigned licenses
- ✅ **Password Expiration Tracking**: Detects accounts with expired passwords
- ✅ **Account Age Analysis**: Calculates account age and correlates with inactivity
- ✅ **Risk Assessment**: Categorizes accounts by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **Activity Analytics**: Sign-in statistics, stale account breakdowns
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Include or exclude disabled accounts

## Stale Account Indicators

The script identifies accounts with one or more of the following stale indicators:

### 1. No Recent Sign-In (>90 Days)
- Accounts that haven't signed in for more than 90 days
- Includes both interactive and non-interactive sign-ins
- Uses the most recent sign-in date (interactive or non-interactive)

### 2. Never Signed In
- Accounts that have never been used since creation
- May indicate test accounts, service accounts, or accounts created but never activated
- Higher risk if account is old (>90 days) and has licenses assigned

### 3. Disabled Accounts with Licenses
- Accounts that are disabled but still have licenses assigned
- Indicates incomplete offboarding process
- Wastes license resources and may indicate security gaps

### 4. Expired Passwords
- Accounts with passwords that haven't been changed in >90 days
- Assumes standard 90-day password expiration policy
- Accounts with "password never expires" policy are flagged separately

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
  - `AuditLog.Read.All` - Read audit logs and sign-in activity

- **Fallback Scopes** (if full access unavailable):
  - `User.ReadBasic.All` - Read basic user info
  - `Directory.Read.All` - Read directory data

**Note**: If `AuditLog.Read.All` is not available, the script will automatically fall back to retrieving users without sign-in activity data. Password expiration and license checks will continue to work normally.

## Usage

### Basic Usage

```powershell
# Simple scan of all stale accounts
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -ExportPath "stale-accounts.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -ExportPath "stale-results.json"
```

### Include Disabled User Accounts

```powershell
# Scan all users including disabled accounts
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -IncludeDisabledUsers -ExportPath "all-stale-accounts.csv"
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all users, matrix view, with export
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "full-audit.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
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

The script provides detailed information about each stale account:

```
[CRITICAL] john.doe@company.com
  Display Name: John Doe
  Email: john.doe@company.com
  Job Title: Former Employee
  Department: IT
  Account Status: Disabled
  Last Sign-In: 2023-06-15 10:23:45 (180 days ago) (Interactive)
  Account Age: 730 days old
  Licenses: 2 assigned
  Password: 180 days old
  Stale Reasons: Disabled account with 2 license(s); No sign-in for 180 days
  Risk Factors: Disabled account with licenses; Stale account (>90 days) with licenses
```

### Matrix Output (with `-Matrix`)

```
Risk      Status    User Principal Name         Display Name    Last Sign-In  Licenses  Password        Stale Reason
----      ------    -------------------         ------------    ------------  --------  --------        ------------
CRITICAL  Disabled  john.doe@company.com        John Doe        180d ago     2         180 days old    Disabled account with 2 license(s); No sign-in for 180 days
HIGH      Enabled   test.user@company.com       Test User       Never         1         Never expires   Never signed in (account >90 days old)
MEDIUM    Enabled   old.account@company.com     Old Account     120d ago      0         120 days old    No sign-in for 120 days
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total stale accounts: 25
  - CRITICAL risk: 5
  - HIGH risk: 8
  - MEDIUM risk: 10
  - LOW risk: 2

[STALE INDICATORS]
  Never signed in: 3
  No sign-in >90 days: 18
  Disabled with licenses: 5
  Expired passwords: 12

[TOP DEPARTMENTS]
  IT: 8
  Sales: 5
  Operations: 3
```

## Risk Levels

The script assigns risk levels based on account status, inactivity, and license assignments:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Disabled account with licenses assigned | Red | **IMMEDIATE ACTION REQUIRED**: Remove licenses from disabled accounts |
| **HIGH** | Never signed in (account >90 days old) OR Stale account (>90 days) with licenses OR Expired password | Red | **HIGH PRIORITY**: Review and remove or remediate |
| **MEDIUM** | Stale account (>90 days inactive) OR Never signed in | Yellow | **REVIEW**: Determine if account should be removed |
| **LOW** | Other stale indicators | Gray | **MONITOR**: Low priority cleanup |

### Risk Assessment Logic

```
IF account is disabled AND has licenses:
    RISK = CRITICAL (License waste + incomplete offboarding)
ELSE IF never signed in AND account age >90 days:
    RISK = HIGH (Old unused account)
ELSE IF days since last sign-in >90 AND has licenses:
    RISK = HIGH (Stale account with licenses)
ELSE IF password expired:
    RISK = HIGH (Security risk)
ELSE IF days since last sign-in >90:
    RISK = MEDIUM (Stale account)
ELSE IF never signed in:
    RISK = MEDIUM (Unused account)
ELSE:
    RISK = LOW
```

## Security Considerations

### Why Stale Accounts Matter

Stale accounts pose several security risks:

1. **License Waste**
   - Disabled accounts with licenses waste subscription costs
   - May indicate incomplete offboarding processes

2. **Attack Surface**
   - Forgotten accounts may have weak or default passwords
   - Inactive accounts may not be monitored for suspicious activity
   - Expired passwords indicate accounts that haven't been used recently

3. **Compliance Issues**
   - Stale accounts may violate access review policies
   - Never-signed-in accounts may indicate test accounts that should be removed
   - Accounts with expired passwords may violate password policy requirements

4. **Operational Risk**
   - Old accounts may have outdated permissions
   - Inactive accounts may be used for lateral movement if compromised

### High-Risk Scenarios

1. **Disabled Account with Licenses** (CRITICAL Risk)
   - Indicates incomplete offboarding
   - Wastes license resources
   - May indicate the account was disabled but not fully removed

2. **Never Signed In + Old Account** (HIGH Risk)
   - Account created but never used
   - May be a test account or forgotten account
   - Higher risk if licenses are assigned

3. **Stale Account with Licenses** (HIGH Risk)
   - Account hasn't been used in 90+ days but still has licenses
   - May indicate the user left but account wasn't cleaned up
   - Wastes resources and poses security risk

4. **Expired Password** (HIGH Risk)
   - Password hasn't been changed in 90+ days
   - May indicate account is not actively used
   - May violate password policy requirements

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track stale accounts
2. **License Optimization**: Remove licenses from disabled accounts immediately
3. **Account Cleanup**: Remove or archive accounts that haven't been used in 90+ days
4. **Password Policy**: Ensure expired passwords are handled according to policy
5. **Offboarding Process**: Verify that disabled accounts have licenses removed

### For IT Administrators

1. **Automated Cleanup**: Use script output to automate account cleanup workflows
2. **License Management**: Regularly review and optimize license assignments
3. **Account Lifecycle**: Implement processes to remove unused accounts
4. **Documentation**: Maintain records of account removal decisions
5. **Access Reviews**: Use reports for quarterly access certification

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify account hygiene aligns with policies
3. **Trend Analysis**: Compare results over time to track improvements
4. **Remediation Tracking**: Monitor stale account reduction rates
5. **Access Reviews**: Use reports for quarterly access certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- DisplayName, UserPrincipalName, Email
- AccountEnabled, UserType
- JobTitle, Department
- CreatedDateTime, AccountAgeDays
- LastSignIn, LastSignInDisplay, DaysSinceLastSignIn, SignInType
- NeverSignedIn
- HasLicenses, LicenseCount
- PasswordNeverExpires, LastPasswordChange, DaysSincePasswordChange, PasswordExpired, PasswordAgeDisplay
- StaleReasons
- RiskLevel, RiskFactors

### JSON Export

Structured format for automation:
```json
[
  {
    "DisplayName": "John Doe",
    "UserPrincipalName": "john.doe@company.com",
    "Email": "john.doe@company.com",
    "AccountEnabled": false,
    "DaysSinceLastSignIn": 180,
    "HasLicenses": true,
    "LicenseCount": 2,
    "PasswordExpired": false,
    "StaleReasons": "Disabled account with 2 license(s); No sign-in for 180 days",
    "RiskLevel": "CRITICAL",
    "RiskFactors": "Disabled account with licenses; Stale account (>90 days) with licenses"
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "Sign-in data unavailable"

**Cause**: Missing `AuditLog.Read.All` permission.

**Solution**: 
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1
# Accept permission consent when prompted
```

#### 2. "No stale accounts found" but you know there are some

**Cause**: The script only shows accounts with stale indicators. Check if accounts meet the criteria:
- No sign-in for >90 days
- Never signed in
- Disabled with licenses
- Expired password

**Solution**: Use `-IncludeDisabledUsers` to include disabled accounts in the scan.

#### 3. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1
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
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -EnableStealth -MaxRetries 5
```

## Examples

### Example 1: Basic Account Hygiene Audit

```powershell
# Identify all stale accounts
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all stale accounts, risk levels, and indicators.

### Example 2: License Waste Detection

```powershell
# Find disabled accounts with licenses
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -IncludeDisabledUsers -Matrix | Where-Object { $_.RiskLevel -eq "CRITICAL" }
```

**Use Case**: Identify accounts wasting license resources.

### Example 3: Never-Signed-In Account Detection

```powershell
# Find accounts that have never been used
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -Matrix | Where-Object { $_.NeverSignedIn -eq $true }
```

**Use Case**: Identify test accounts or accounts created but never activated.

### Example 4: Compliance Reporting

```powershell
# Monthly audit including disabled accounts
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track account hygiene improvements over time.

### Example 5: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -TenantId "customer-tenant-id" -ExportPath "customer_stale.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\StaleAccounts_$date.csv"
    
    C:\Tools\Invoke-EntraStaleAccountCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if critical-risk accounts found
    $results = Import-Csv $path
    $critical = $results | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    
    if ($critical.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($critical.Count) critical stale accounts found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyStaleAccountCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Stale Account Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_stale_account"
        severity = $_.RiskLevel
        user = $_.UserPrincipalName
        stale_reasons = $_.StaleReasons
        days_inactive = $_.DaysSinceLastSignIn
        has_licenses = $_.HasLicenses
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
    .\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -Matrix -ExportPath "C:\Reports\stale.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\stale.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Stale account detection (>90 days inactive)
- Never-signed-in account detection
- Disabled account with license detection
- Password expiration tracking
- Risk assessment framework
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive account analytics

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
- **Invoke-EntraAppAccess.ps1**: Critical administrative access check
- **Invoke-EntraRoleCheck.ps1**: Privileged role assignment audit

---

