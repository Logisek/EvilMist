# Invoke-EntraLicenseCheck.ps1

## Overview

`Invoke-EntraLicenseCheck.ps1` is a PowerShell 7+ script designed to enumerate and analyze Azure Entra ID tenant license SKUs and user license assignments. This tool is part of the EvilMist toolkit and helps security teams identify privileged license users, detect unused licenses, and assess license-related security risks in their Azure AD tenant.

## Purpose

License assignments in Azure Entra ID can provide users with elevated privileges and access to premium features. This script helps:
- **Security Auditors**: Identify users with privileged licenses (E5, P2, etc.)
- **Penetration Testers**: Discover potential privilege escalation paths through license assignments
- **IT Administrators**: Audit license assignments and identify unused licenses
- **Compliance Teams**: Generate reports for license governance and cost optimization

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Tenant SKU Enumeration**: Lists all subscribed license SKUs and their consumption
- ✅ **User License Assignment Tracking**: Identifies all users with license assignments
- ✅ **Privileged License Detection**: Automatically identifies E5, P2, and other high-privilege licenses
- ✅ **Unused License Detection**: Identifies licenses assigned to users who have never signed in
- ✅ **Risk Assessment**: Categorizes license assignments by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **License Usage Analytics**: Consumption statistics, unused license tracking, SKU breakdowns
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only privileged licenses, unused licenses, or include disabled accounts

## License SKUs Analyzed

The script identifies and categorizes license SKUs including:

### CRITICAL Risk Licenses

- **ENTERPRISEPREMIUM** (E5) - Full enterprise features with advanced security
- **M365_E5** - Microsoft 365 E5 with all premium features
- **AAD_PREMIUM_P2** - Azure AD Premium P2 with PIM and advanced security
- **M365_E5_SECURITY** - Microsoft 365 E5 Security add-on
- **M365_E5_COMPLIANCE** - Microsoft 365 E5 Compliance add-on
- **EMS_E5** - Enterprise Mobility + Security E5

### HIGH Risk Licenses

- **ENTERPRISEPACK** (E3) - Enterprise features with standard security
- **M365_E3** - Microsoft 365 E3
- **AAD_PREMIUM** (P1) - Azure AD Premium P1
- **EMS** - Enterprise Mobility + Security
- **O365_E5** - Office 365 E5
- **O365_E3** - Office 365 E3

### MEDIUM Risk Licenses

- **M365_F3** - Microsoft 365 F3 (Frontline)
- **M365_F1** - Microsoft 365 F1 (Frontline)
- **INTUNE_A** - Intune device management
- **POWER_BI_PRO** - Power BI Pro
- **POWERAPPS_PER_USER** - Power Apps per user
- **POWERAUTOMATE_PER_USER** - Power Automate per user

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
   ```

### Required Permissions

The script requires the following Microsoft Graph API permissions:

- **Primary Scopes** (preferred):
  - `Organization.Read.All` - Read organization and license information
  - `Directory.Read.All` - Read directory data
  - `User.Read.All` - Read all user profiles
  - `UserAuthenticationMethod.Read.All` - Read authentication methods (optional)

- **Fallback Scopes** (if full access unavailable):
  - `Organization.Read.All` - Read organization and license information
  - `Directory.Read.All` - Read directory data
  - `User.ReadBasic.All` - Read basic user info

**Note**: If `UserAuthenticationMethod.Read.All` is not available, the script will continue without MFA status checks. All other features will work normally.

## Usage

### Basic Usage

```powershell
# Simple scan of all license SKUs and user assignments
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -ExportPath "licenses.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -ExportPath "license-results.json"
```

### Include Disabled User Accounts

```powershell
# Scan all users including disabled accounts
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -IncludeDisabledUsers -ExportPath "all-licenses.csv"
```

### Show Only Privileged Licenses

```powershell
# Filter to show only users with privileged licenses (E5, P2, etc.)
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -OnlyPrivilegedLicenses

# Matrix view with privileged licenses only
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -OnlyPrivilegedLicenses -Matrix
```

### Show Only Unused Licenses

```powershell
# Filter to show only unused license assignments
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -OnlyUnusedLicenses

# Export unused licenses
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -OnlyUnusedLicenses -ExportPath "unused-licenses.csv"
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all licenses, all users, with export
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "full-audit.csv"

# Security focus: privileged licenses only
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -OnlyPrivilegedLicenses -Matrix -ExportPath "privileged-licenses.csv"

# Cost optimization: unused licenses only
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -OnlyUnusedLicenses -Matrix -ExportPath "unused-licenses.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
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
| `-OnlyPrivilegedLicenses` | Switch | Show only users with privileged licenses (E5, P2, etc.) | False |
| `-OnlyUnusedLicenses` | Switch | Show only unused license assignments | False |
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

The script provides detailed information about each license assignment:

```
[CRITICAL] john.admin@company.com - ENTERPRISEPREMIUM
  Display Name: John Admin
  User Type: Member
  Email: john.admin@company.com
  Job Title: IT Administrator
  Department: IT
  Account Status: Enabled
  License SKU: ENTERPRISEPREMIUM
  License Risk Level: CRITICAL
  Privileged License: Yes
  Unused License: No
  Last Sign-In: 2024-12-20 14:23:45 (3 days ago) (Interactive)
  Created: 2023-05-10T08:15:00Z (591 days old)
```

### Matrix Output (with `-Matrix`)

```
Risk      License Risk  Privileged  Unused  Status   User Principal Name         Display Name    License SKU          Last Sign-In  Department
----      ------------  ----------  ------  ------   -------------------         ------------    ------------         ------------  ----------
CRITICAL  CRITICAL      Yes         No      Enabled  john.admin@company.com      John Admin      ENTERPRISEPREMIUM    3d ago        IT
HIGH      HIGH          Yes         No      Enabled  jane.user@company.com       Jane User       ENTERPRISEPACK       1d ago        Sales
CRITICAL  CRITICAL      Yes         Yes     Enabled  unused@company.com          Unused Account  ENTERPRISEPREMIUM    Never         IT
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total license assignments: 150
Unique users with licenses: 120
  - CRITICAL risk: 25
  - HIGH risk: 45
  - MEDIUM risk: 50
  - LOW risk: 30

[LICENSE TYPES]
  Privileged licenses: 70
  Unused licenses: 15

[LICENSES BY SKU]
  ENTERPRISEPREMIUM: 25
  ENTERPRISEPACK: 45
  M365_E3: 30
  AAD_PREMIUM_P2: 10
  INTUNE_A: 20

[TOP DEPARTMENTS]
  IT: 35
  Sales: 25
  Operations: 15

[SIGN-IN ACTIVITY]
  Never signed in: 15
  Recent (≤30 days): 100
  Stale (>90 days): 35

[TENANT SKU SUMMARY]
Total SKUs: 8
  Total enabled: 200
  Total consumed: 150
  Total available: 50

[PRIVILEGED SKUs]
  ENTERPRISEPREMIUM: 25/30 (83.33%)
  AAD_PREMIUM_P2: 10/15 (66.67%)
```

## Risk Levels

The script assigns risk levels based on license type and usage:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Privileged license (E5, P2) assigned to unused account OR unused privileged license | Red | **IMMEDIATE ACTION REQUIRED**: Review assignment or remove unused license |
| **HIGH** | Privileged license (E5, P2) assigned to active user OR unused high-tier license | Yellow | **REVIEW REQUIRED**: Verify business justification |
| **MEDIUM** | Standard license (E3, etc.) assigned OR medium-tier license | Green | **MONITOR**: Acceptable risk, monitor usage |
| **LOW** | Basic license assigned to active user | Gray | **ACCEPTABLE**: Low risk, standard assignment |

### Risk Assessment Logic

```
IF license is privileged (E5, P2, etc.):
    IF user never signed in (unused):
        RISK = CRITICAL (Waste of expensive license)
    ELSE IF license is CRITICAL tier:
        RISK = CRITICAL (High privilege access)
    ELSE:
        RISK = HIGH (Privileged but used)
ELSE IF license is unused:
    RISK = HIGH (Waste of license)
ELSE IF license is HIGH tier:
    RISK = HIGH (Standard privileged access)
ELSE IF license is MEDIUM tier:
    RISK = MEDIUM (Standard access)
ELSE:
    RISK = LOW (Basic access)
```

## Security Considerations

### Why License Assignments Matter

Users with privileged licenses can have access to:
- **Advanced Security Features**: PIM, Advanced Threat Protection, Advanced Compliance
- **Administrative Capabilities**: Enhanced admin roles, privileged access management
- **Premium Services**: Power Platform, Power BI Pro, Advanced Analytics
- **Compliance Tools**: Advanced eDiscovery, Advanced Audit, Compliance Manager
- **Identity Protection**: Azure AD Identity Protection, Risk-based Conditional Access

### High-Risk Scenarios

1. **Unused Privileged Licenses** (CRITICAL Risk)
   - Expensive licenses assigned to accounts that never sign in
   - Indicates poor license governance
   - Wastes budget and increases attack surface

2. **Privileged Licenses on Guest Accounts** (HIGH Risk)
   - External users with E5 or P2 licenses
   - May not be subject to same security policies
   - Review carefully for business justification

3. **Disabled Accounts with Licenses** (HIGH Risk)
   - Disabled accounts still consuming licenses
   - Indicates incomplete offboarding process
   - Wastes budget and creates compliance issues

4. **Stale License Assignments** (MEDIUM Risk)
   - Licenses assigned to users who haven't signed in for 90+ days
   - May indicate forgotten assignments
   - Potential for account takeover if credentials leaked

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track license assignments and identify unused licenses
2. **Privileged License Review**: Verify all E5/P2 assignments are justified
3. **Unused License Cleanup**: Remove licenses from accounts that never sign in
4. **Cost Optimization**: Identify and reclaim unused licenses to reduce costs
5. **Compliance Tracking**: Maintain records of who has privileged licenses and why

### For Penetration Testers

1. **Initial Reconnaissance**: Identify users with privileged licenses
2. **Target Selection**: Prioritize users with E5/P2 licenses without MFA
3. **Privilege Escalation**: Document license-based privilege escalation paths
4. **Persistence**: Note users with administrative licenses for persistence scenarios
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify license assignments align with business needs
3. **Trend Analysis**: Compare results over time to track changes
4. **Remediation Tracking**: Monitor unused license cleanup progress
5. **Access Reviews**: Use reports for quarterly license certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- DisplayName, UserPrincipalName, Email
- AccountEnabled, UserType
- JobTitle, Department
- CreatedDateTime, DaysOld
- SkuId, SkuPartNumber
- LicenseRiskLevel, IsPrivilegedLicense
- LastSignIn, LastSignInDisplay, DaysSinceLastSignIn, SignInType
- IsUnusedLicense
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
    "SkuPartNumber": "ENTERPRISEPREMIUM",
    "LicenseRiskLevel": "CRITICAL",
    "IsPrivilegedLicense": true,
    "IsUnusedLicense": false,
    "RiskLevel": "CRITICAL",
    "LastSignInDisplay": "2024-12-20 14:23:45 (3 days ago)",
    "DaysSinceLastSignIn": 3
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "No license assignments found"

**Cause**: No users have licenses assigned, or insufficient permissions.

**Solution**: 
- Verify you have `Organization.Read.All` and `User.Read.All` permissions
- Check if your tenant has any license SKUs subscribed
- Ensure users actually have licenses assigned

#### 2. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1
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
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -OnlyPrivilegedLicenses
```

## Examples

### Example 1: Basic License Audit

```powershell
# Identify all license assignments
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all license assignments, risk levels, and usage statistics.

### Example 2: Privileged License Detection

```powershell
# Find users with privileged licenses (E5, P2, etc.)
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -OnlyPrivilegedLicenses -Matrix

# Review output, then verify business justification
```

**Use Case**: Identify immediate security risks and verify privileged access.

### Example 3: Unused License Cleanup

```powershell
# Find unused license assignments
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -OnlyUnusedLicenses -ExportPath "unused-licenses.csv"

# Review and remove unused licenses
```

**Use Case**: Cost optimization and license governance.

### Example 4: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of high-value targets during engagement.

### Example 5: Compliance Reporting

```powershell
# Monthly audit including disabled accounts
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track license assignments and unused licenses over time.

### Example 6: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -TenantId "customer-tenant-id" -ExportPath "customer_licenses.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\Licenses_$date.csv"
    
    C:\Tools\Invoke-EntraLicenseCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if unused licenses found
    $results = Import-Csv $path
    $unused = $results | Where-Object { $_.IsUnusedLicense -eq "True" }
    
    if ($unused.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($unused.Count) unused licenses found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyLicenseCheck.ps1"
Register-ScheduledTask -TaskName "Weekly License Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_license_assignment"
        severity = $_.RiskLevel
        user = $_.UserPrincipalName
        license_sku = $_.SkuPartNumber
        is_privileged = $_.IsPrivilegedLicense
        is_unused = $_.IsUnusedLicense
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
    .\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -Matrix -ExportPath "C:\Reports\licenses.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\licenses.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Support for tenant SKU enumeration
- User license assignment tracking
- Privileged license detection (E5, P2, etc.)
- Unused license detection
- Risk assessment based on license privileges
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive license analytics

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
- **Invoke-EntraAppAccess.ps1**: Critical administrative access audit
- **Invoke-EntraStaleAccountCheck.ps1**: Stale account and license waste detection

---

