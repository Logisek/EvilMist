# Invoke-EntraApplicationCheck.ps1

## Overview

`Invoke-EntraApplicationCheck.ps1` is a PowerShell 7+ script designed to enumerate and analyze Azure Entra ID application registrations and their security posture. This tool is part of the EvilMist toolkit and helps security teams identify application registrations with security risks including expired credentials, high-risk API permissions, and owners without Multi-Factor Authentication (MFA).

## Purpose

Application registrations in Azure Entra ID can pose significant security risks if not properly managed. This script helps:
- **Security Auditors**: Identify applications with security misconfigurations
- **Penetration Testers**: Discover high-risk applications and credential exposure
- **IT Administrators**: Audit application registrations and credential management
- **Compliance Teams**: Generate reports for application security governance

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Comprehensive Application Enumeration**: Enumerates all application registrations in the tenant
- ✅ **Credential Analysis**: Identifies applications with secrets and certificates
- ✅ **Expiration Tracking**: Detects expired and expiring credentials
- ✅ **API Permission Analysis**: Identifies applications with high-risk permissions
- ✅ **Owner Security Assessment**: Checks app owners and their MFA status
- ✅ **Risk Assessment**: Categorizes applications by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only apps with credentials, expired credentials, or high permissions

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
  - `Application.Read.All` - Read application registrations
  - `Directory.Read.All` - Read directory data
  - `User.Read.All` - Read all user profiles
  - `UserAuthenticationMethod.Read.All` - Read authentication methods
  - `AuditLog.Read.All` - Read audit logs (optional)

- **Fallback Scopes** (if full access unavailable):
  - `Application.Read.All` - Read application registrations
  - `Directory.Read.All` - Read directory data
  - `User.ReadBasic.All` - Read basic user info

**Note**: If `AuditLog.Read.All` is not available, the script will continue to work normally. All other features will function as expected.

## Usage

### Basic Usage

```powershell
# Simple scan of all application registrations
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1

# Using dispatcher (recommended)
.\Invoke-EvilMist.ps1 -Script EntraApplicationCheck
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -ExportPath "applications.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -ExportPath "app-results.json"
```

### Show Only Applications With Credentials

```powershell
# Filter to show only applications with credentials/secrets
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -OnlyWithCredentials

# Matrix view with credentials filter
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -OnlyWithCredentials -Matrix
```

### Show Only Expired Credentials

```powershell
# Display only applications with expired credentials
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -OnlyExpiredCredentials

# Matrix view with expired credentials filter
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -OnlyExpiredCredentials -Matrix
```

### Show Only High-Permission Applications

```powershell
# Filter to show only applications with high-risk permissions
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -OnlyHighPermission

# Matrix view with high permission filter
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -OnlyHighPermission -Matrix
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all applications with export
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -Matrix -ExportPath "full-audit.csv"

# Security focus: high-risk applications only
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -OnlyHighPermission -Matrix -ExportPath "high-risk-apps.csv"

# Credential management: expired credentials only
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -OnlyExpiredCredentials -ExportPath "expired-creds.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
```

## Parameters

### General Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-ExportPath` | String | Path to export results (CSV or JSON based on extension) | None |
| `-TenantId` | String | Optional Tenant ID. Uses home tenant if not specified | None |
| `-UseAzCliToken` | Switch | Try to use Azure CLI cached token first | False |
| `-UseAzPowerShellToken` | Switch | Try to use Azure PowerShell cached token first | False |
| `-IncludeDisabled` | Switch | Include disabled application registrations in results | False |
| `-OnlyWithCredentials` | Switch | Show only applications with credentials/secrets | False |
| `-OnlyExpiredCredentials` | Switch | Show only applications with expired credentials | False |
| `-OnlyHighPermission` | Switch | Show only applications with high-risk API permissions | False |
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

The script provides detailed information about each application registration:

```
[HIGH] My Application
  App ID: 12345678-1234-1234-1234-123456789012
  Application ID: abcdef12-3456-7890-abcd-ef1234567890
  Sign-In Audience: AzureADMyOrg
  Credentials: 2 secret(s), 1 expired
  [!] EXPIRED CREDENTIALS DETECTED
  Permissions: 5 total (3 delegated, 2 application)
  [!] High-risk permissions detected
  Delegated permissions: User.Read, Mail.Read, Files.ReadWrite.All
  Application permissions: Directory.Read.All, User.ReadWrite.All
  Owners: 2
  [!] 1 owner(s) without MFA
  Owner details: admin@company.com (MFA: No); secure@company.com (MFA: Yes)
  Created: 2023-05-10T08:15:00Z (591 days old)
```

### Matrix Output (with `-Matrix`)

```
Risk     Display Name        App ID                                Credentials              Delegated  App Perms  High Risk  Owners  Owners No MFA
----     ------------        ------                                -----------              ---------  ----------  ---------  ------  -------------
CRITICAL My Application      12345678-1234-1234-1234-123456789012  2 secret(s), 1 expired  3          2          Yes        2       1
HIGH     Test App            abcdef12-3456-7890-abcd-ef1234567890  1 cert(s)               5          0          Yes        1       0
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total application registrations analyzed: 45
  - CRITICAL risk: 2
  - HIGH risk: 8
  - MEDIUM risk: 15
  - LOW risk: 20

[CREDENTIALS]
  With credentials: 30
  With expired credentials: 5
  With expiring soon (≤30 days): 3

[PERMISSIONS]
  With high-risk permissions: 12

[OWNERS]
  With owners without MFA: 8
```

## Risk Levels

The script assigns risk levels based on permissions, credentials, and owner security:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Has critical permissions AND expired credentials | Red | **IMMEDIATE ACTION REQUIRED**: Rotate credentials, review permissions |
| **HIGH** | Has high-risk permissions OR expired credentials OR owners without MFA | Yellow | **URGENT**: Review permissions, rotate credentials, enable MFA for owners |
| **MEDIUM** | Has credentials expiring soon OR has API permissions | Cyan | **REVIEW**: Monitor credential expiration, review permissions |
| **LOW** | No credentials, no high-risk permissions, secure owners | Green | **MONITOR**: Acceptable risk, maintain current security posture |

### Risk Assessment Logic

```
IF has critical permissions AND expired credentials:
    RISK = CRITICAL (Highest risk - immediate action required)
ELSE IF has high-risk permissions OR expired credentials OR owners without MFA:
    RISK = HIGH (Urgent review needed)
ELSE IF has credentials expiring soon OR has API permissions:
    RISK = MEDIUM (Review recommended)
ELSE:
    RISK = LOW (Acceptable risk)
```

## High-Risk Permissions

The script identifies the following high-risk permissions:

### Critical Permissions (Highest Risk)
- `RoleManagement.ReadWrite.Directory` - Can modify directory roles
- `AppRoleAssignment.ReadWrite.All` - Can assign app roles
- `Application.ReadWrite.All` - Can modify applications
- `Directory.ReadWrite.All` - Can modify directory data
- `PrivilegedAccess.ReadWrite.AzureAD` - Can modify privileged access

### High-Risk Permissions
- `Directory.ReadWrite.All` - Full directory write access
- `User.ReadWrite.All` - Can modify all users
- `Group.ReadWrite.All` - Can modify all groups
- `Mail.ReadWrite` - Can read/write mail
- `Mail.Send` - Can send mail on behalf of users
- `Files.ReadWrite.All` - Can read/write all files
- `Sites.ReadWrite.All` - Can read/write all SharePoint sites
- `Exchange.ManageAsApp` - Exchange management permissions
- `full_access_as_app` - Full application access
- `User.Export.All` - Can export user data
- `Directory.Read.All` - Can read all directory data
- `AuditLog.Read.All` - Can read audit logs
- `Policy.ReadWrite.ConditionalAccess` - Can modify CA policies
- `PrivilegedAccess.ReadWrite.AzureResources` - Can modify Azure resource access

## Security Considerations

### Why Application Registrations Matter

Application registrations can pose significant security risks:

1. **Credential Exposure**: Expired or leaked credentials can be used to authenticate as the application
2. **Over-Privileged Access**: Applications with excessive permissions can access sensitive data
3. **Owner Security**: Owners without MFA can be compromised, leading to application compromise
4. **Credential Management**: Poor credential rotation practices increase attack surface

### High-Risk Scenarios

1. **Expired Credentials with Critical Permissions** (CRITICAL Risk)
   - Credentials may have been leaked before expiration
   - Critical permissions allow privilege escalation
   - Immediate credential rotation required

2. **Owners Without MFA** (HIGH Risk)
   - Compromised owner accounts can modify applications
   - Can add new credentials or modify permissions
   - Enable MFA for all application owners

3. **High-Risk Permissions** (HIGH Risk)
   - Applications can access sensitive data
   - Can modify directory objects or grant permissions
   - Review and reduce permissions to minimum required

4. **Expiring Credentials** (MEDIUM Risk)
   - Credentials expiring soon need rotation
   - Plan credential rotation before expiration
   - Monitor and rotate proactively

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track application security posture
2. **Credential Rotation**: Rotate credentials before expiration
3. **Permission Review**: Regularly review and reduce API permissions
4. **Owner Security**: Ensure all owners have MFA enabled
5. **Documentation**: Maintain records of application purpose and permissions

### For Penetration Testers

1. **Initial Reconnaissance**: Identify high-risk applications
2. **Credential Analysis**: Focus on expired credentials and weak owner security
3. **Permission Mapping**: Map applications with high-risk permissions
4. **Attack Path Analysis**: Use applications as potential privilege escalation vectors
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify applications align with business needs
3. **Trend Analysis**: Compare results over time
4. **Remediation Tracking**: Monitor credential rotation and permission reduction
5. **Access Reviews**: Use reports for quarterly application certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- DisplayName, AppId, ApplicationId
- SignInAudience, CreatedDateTime, DaysOld
- HasSecrets, HasCertificates, SecretCount, CertificateCount
- ExpiredSecretsCount, ExpiredCertificatesCount
- ExpiringSoonSecretsCount, ExpiringSoonCertificatesCount
- CredentialSummary
- DelegatedPermissionCount, ApplicationPermissionCount, TotalPermissionCount
- HasHighRiskPerms, HasCriticalPerms
- DelegatedPermissions, ApplicationPermissions
- OwnerCount, OwnersWithoutMFA, OwnerDetails
- RiskLevel

### JSON Export

Structured format for automation:
```json
[
  {
    "DisplayName": "My Application",
    "AppId": "12345678-1234-1234-1234-123456789012",
    "ApplicationId": "abcdef12-3456-7890-abcd-ef1234567890",
    "SignInAudience": "AzureADMyOrg",
    "HasSecrets": true,
    "SecretCount": 2,
    "ExpiredSecretsCount": 1,
    "HasHighRiskPerms": true,
    "HasCriticalPerms": false,
    "DelegatedPermissionCount": 3,
    "ApplicationPermissionCount": 2,
    "OwnerCount": 2,
    "OwnersWithoutMFA": 1,
    "RiskLevel": "HIGH"
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "No application registrations found"

**Cause**: No application registrations exist in the tenant or filters are too restrictive.

**Solution**: 
- Remove filters (`-OnlyWithCredentials`, `-OnlyExpiredCredentials`, `-OnlyHighPermission`)
- Verify you have `Application.Read.All` permission
- Check if applications exist in Azure Portal

#### 2. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1
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

**Cause**: Large number of applications or throttling.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -OnlyWithCredentials
```

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all application registrations
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all applications, risk levels, and security details.

### Example 2: Expired Credentials Detection

```powershell
# Find applications with expired credentials
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -OnlyExpiredCredentials -Matrix

# Review output, then remediate
```

**Use Case**: Identify immediate security risks for credential rotation.

### Example 3: High-Permission Application Review

```powershell
# Find applications with high-risk permissions
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -OnlyHighPermission -ExportPath "high-perm-apps.csv"

# Review permissions and reduce to minimum required
```

**Use Case**: Identify over-privileged applications for permission reduction.

### Example 4: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of high-value targets during engagement.

### Example 5: Compliance Reporting

```powershell
# Monthly audit including all applications
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track application security changes and credential management over time.

### Example 6: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -TenantId "customer-tenant-id" -ExportPath "customer_apps.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\Applications_$date.csv"
    
    C:\Tools\Invoke-EntraApplicationCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if critical-risk applications found
    $results = Import-Csv $path
    $criticalRisk = $results | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    
    if ($criticalRisk.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($criticalRisk.Count) critical-risk applications found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyApplicationCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Application Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraApplicationCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_application_check"
        severity = $_.RiskLevel
        app_name = $_.DisplayName
        app_id = $_.AppId
        has_expired_creds = ($_.ExpiredSecretsCount -gt 0 -or $_.ExpiredCertificatesCount -gt 0)
        has_high_risk_perms = $_.HasHighRiskPerms
        owners_without_mfa = $_.OwnersWithoutMFA
    }
}

$siemEvents | ConvertTo-Json | Out-File "siem_formatted.json"
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Application registration enumeration
- Credential analysis (secrets and certificates)
- Expiration tracking
- API permission analysis
- Owner security assessment
- Risk assessment framework
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods

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

- **Invoke-EntraServicePrincipalCheck.ps1**: Service principal security analysis
- **Invoke-EntraAppAccess.ps1**: User access to critical administrative applications
- **Invoke-EntraRoleCheck.ps1**: Privileged role assignment audit

---

