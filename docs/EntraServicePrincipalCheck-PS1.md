# Invoke-EntraServicePrincipalCheck.ps1

## Overview

`Invoke-EntraServicePrincipalCheck.ps1` is a PowerShell 7+ script designed to enumerate and analyze Azure Entra ID service principals (service accounts) and perform a comprehensive security audit. This tool identifies high-risk service accounts by analyzing credentials, permissions, owners, and usage patterns. This script is part of the EvilMist toolkit and helps security teams identify misconfigured or high-risk service principals in their Azure AD tenant.

## Purpose

Service principals are non-human accounts used by applications and services to authenticate and access Azure AD resources. This script helps:
- **Security Auditors**: Identify service principals with expired credentials, high permissions, or insecure configurations
- **Penetration Testers**: Discover high-value service accounts for privilege escalation attacks
- **IT Administrators**: Audit service principal security posture and compliance
- **Compliance Teams**: Generate reports for service account governance

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Credential Enumeration**: Identifies service principals with secrets and certificates
- ✅ **Expiration Tracking**: Detects expired credentials and credentials expiring soon (≤30 days)
- ✅ **Permission Analysis**: Identifies high-risk and critical permissions assigned to service principals
- ✅ **Owner Analysis**: Checks service principal owners and their MFA status
- ✅ **Risk Assessment**: Categorizes service principals by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **Activity Tracking**: Identifies unused/inactive service principals
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Filter by credentials, expired credentials, or high permissions

## Service Principal Security Analysis

The script performs comprehensive security analysis on all service principals in the tenant:

### Credential Analysis

1. **Secret Detection**
   - Identifies service principals with password credentials (secrets)
   - Tracks secret expiration dates
   - Flags expired secrets
   - Warns about secrets expiring within 30 days

2. **Certificate Detection**
   - Identifies service principals with key credentials (certificates)
   - Tracks certificate expiration dates
   - Flags expired certificates
   - Warns about certificates expiring within 30 days

### Permission Analysis

The script identifies service principals with high-risk permissions:

#### Critical Permissions (Highest Risk)
- `RoleManagement.ReadWrite.Directory` - Can grant directory roles
- `AppRoleAssignment.ReadWrite.All` - Can assign app roles
- `Application.ReadWrite.All` - Can modify applications
- `Directory.ReadWrite.All` - Can modify directory objects
- `PrivilegedAccess.ReadWrite.AzureAD` - Can manage privileged access

#### High-Risk Permissions
- `Directory.ReadWrite.All` - Full directory write access
- `User.ReadWrite.All` - Can modify all users
- `Group.ReadWrite.All` - Can modify all groups
- `Mail.ReadWrite` - Can read/write emails
- `Files.ReadWrite.All` - Can access all files
- `Sites.ReadWrite.All` - Can access all SharePoint sites
- `Exchange.ManageAsApp` - Exchange management permissions
- `AuditLog.Read.All` - Can read audit logs
- `Policy.ReadWrite.ConditionalAccess` - Can modify CA policies
- And more...

### Owner Analysis

- Enumerates all owners of each service principal
- Checks MFA status for each owner
- Flags service principals with owners without MFA
- Identifies service principals without owners

### Activity Analysis

- Tracks service principal creation dates
- Identifies old/unused service principals
- Can be extended with audit log queries for usage patterns

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
  - `Application.Read.All` - Read application registrations and credentials
  - `Directory.Read.All` - Read directory data
  - `User.Read.All` - Read user profiles (for owner analysis)
  - `UserAuthenticationMethod.Read.All` - Read authentication methods (for MFA check)
  - `AuditLog.Read.All` - Read audit logs (optional, for usage tracking)

- **Fallback Scopes** (if full access unavailable):
  - `Application.Read.All` - Read application registrations
  - `Directory.Read.All` - Read directory data
  - `User.ReadBasic.All` - Read basic user info

**Note**: `Application.Read.All` is required to read credential information. Without it, credential analysis will be limited.

## Usage

### Basic Usage

```powershell
# Simple scan of all service principals
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1

# The script will analyze all service principals and show security findings
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -ExportPath "service-principals.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -ExportPath "sp-results.json"
```

### Include Disabled Service Principals

```powershell
# Scan all service principals including disabled ones
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -IncludeDisabled -ExportPath "all-sp.csv"
```

### Show Only Service Principals With Credentials

```powershell
# Filter to show only service principals with secrets/certificates
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyWithCredentials

# Matrix view with credentials filter
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyWithCredentials -Matrix
```

### Show Only Expired Credentials

```powershell
# Filter to show only service principals with expired credentials
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyExpiredCredentials

# Matrix view with expired credentials filter
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyExpiredCredentials -Matrix
```

### Show Only High-Permission Service Principals

```powershell
# Filter to show only service principals with high-risk permissions
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyHighPermission

# Matrix view with high permission filter
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyHighPermission -Matrix
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all service principals with export
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -IncludeDisabled -Matrix -ExportPath "full-audit.csv"

# Security focus: high-risk service principals only
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyHighPermission -OnlyExpiredCredentials -Matrix -ExportPath "high-risk-sp.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
```

## Parameters

### General Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-ExportPath` | String | Path to export results (CSV or JSON based on extension) | None |
| `-TenantId` | String | Optional Tenant ID. Uses home tenant if not specified | None |
| `-UseAzCliToken` | Switch | Try to use Azure CLI cached token first | False |
| `-UseAzPowerShellToken` | Switch | Try to use Azure PowerShell cached token first | False |
| `-IncludeDisabled` | Switch | Include disabled service principals in results | False |
| `-OnlyWithCredentials` | Switch | Show only service principals with credentials/secrets | False |
| `-OnlyExpiredCredentials` | Switch | Show only service principals with expired credentials | False |
| `-OnlyHighPermission` | Switch | Show only service principals with high-risk permissions | False |
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

The script provides detailed information about each service principal:

```
[CRITICAL] MyApp Service Principal
  App ID: 12345678-1234-1234-1234-123456789abc
  Service Principal ID: 87654321-4321-4321-4321-cba987654321
  Type: Application
  Account Status: Enabled
  Credentials: 2 secret(s), 1 expired, 1 cert(s)
  [!] EXPIRED CREDENTIALS DETECTED
  Permissions: 5 assigned
  [!] CRITICAL permissions detected
  Permission details: Microsoft Graph, Exchange Online
  Owners: 2
  [!] 1 owner(s) without MFA
  Owner details: admin@company.com (MFA: No); secure@company.com (MFA: Yes)
  Created: 2023-01-15T10:30:00Z (365 days old)
```

### Matrix Output (with `-Matrix`)

```
Risk      Status   Display Name              App ID                                 Credentials              Permissions  High Risk  Owners  Owners No MFA
----      ------   ------------              ------                                 -----------              -----------  ---------  ------  --------------
CRITICAL  Enabled  MyApp Service Principal   12345678-1234-1234-1234-123456789abc   2 secret(s), 1 expired   5            Yes        2       1
HIGH      Enabled  Another SP                87654321-4321-4321-4321-cba987654321   1 cert(s)                3            Yes        1       0
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total service principals analyzed: 45
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
  With owners without MFA: 7
```

## Risk Levels

The script assigns risk levels based on credentials, permissions, and owner security:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Has critical permissions AND expired credentials | Red | **IMMEDIATE ACTION REQUIRED**: Rotate credentials, review permissions |
| **HIGH** | Has high-risk/critical permissions OR expired credentials OR owners without MFA | Yellow | **URGENT**: Review and remediate security issues |
| **MEDIUM** | Has credentials expiring soon OR has permissions assigned | Cyan | **REVIEW**: Monitor and plan credential rotation |
| **LOW** | No credentials, no high-risk permissions, secure owners | Green | **ACCEPTABLE**: Low risk, monitor periodically |

### Risk Assessment Logic

```
IF has critical permissions AND expired credentials:
    RISK = CRITICAL (Highest risk - immediate action needed)
ELSE IF has high-risk permissions OR expired credentials OR owners without MFA:
    RISK = HIGH (Urgent security issues)
ELSE IF has credentials expiring soon OR has permissions:
    RISK = MEDIUM (Needs attention)
ELSE:
    RISK = LOW (Acceptable risk)
```

## Security Considerations

### Why Service Principal Security Matters

Service principals are non-human accounts that can have extensive permissions. Compromised service principals can lead to:

- **Privilege Escalation**: Service principals with high permissions can grant themselves or others elevated roles
- **Data Exfiltration**: Service principals with read permissions can access sensitive data
- **Persistent Access**: Expired credentials may still be valid if not properly rotated
- **Lateral Movement**: Service principals can be used to move between tenants or resources
- **Compliance Violations**: Unmanaged service principals violate security best practices

### High-Risk Scenarios

1. **Expired Credentials with Critical Permissions** (CRITICAL Risk)
   - Service principal can still authenticate with expired credentials in some cases
   - Critical permissions allow privilege escalation
   - Immediate credential rotation required

2. **Owners Without MFA** (HIGH Risk)
   - Owners can modify service principal configuration
   - Without MFA, owner accounts are vulnerable to credential attacks
   - Compromised owner = compromised service principal

3. **Unused Service Principals with Credentials** (MEDIUM Risk)
   - Old service principals may have forgotten credentials
   - Unused accounts are often not monitored
   - Potential for abuse if credentials are leaked

4. **Service Principals Without Owners** (MEDIUM Risk)
   - No accountability for the service principal
   - Difficult to track who manages it
   - May be orphaned or forgotten

### Best Practices

1. **Credential Management**
   - Rotate credentials regularly (every 90 days or less)
   - Use certificates instead of secrets when possible
   - Set expiration dates for all credentials
   - Remove expired credentials immediately

2. **Permission Management**
   - Follow principle of least privilege
   - Regularly review and audit permissions
   - Remove unnecessary permissions
   - Use managed identities when possible

3. **Owner Management**
   - Assign at least 2 owners to each service principal
   - Ensure all owners have MFA enabled
   - Regularly review owner assignments
   - Remove inactive owners

4. **Monitoring**
   - Monitor service principal usage
   - Alert on credential expiration
   - Track permission changes
   - Audit service principal creation

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track service principal changes
2. **Credential Rotation**: Ensure all credentials are rotated before expiration
3. **Permission Reviews**: Review and remove unnecessary permissions quarterly
4. **Owner Verification**: Verify all owners have MFA enabled
5. **Documentation**: Maintain records of service principal purpose and owners

### For Penetration Testers

1. **Initial Reconnaissance**: Identify high-value service principals for targeting
2. **Credential Hunting**: Focus on service principals with expired or expiring credentials
3. **Permission Analysis**: Identify service principals with privilege escalation capabilities
4. **Owner Targeting**: Target service principals with owners without MFA
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify service principals align with security policies
3. **Trend Analysis**: Compare results over time to track improvements
4. **Remediation Tracking**: Monitor credential rotation and permission cleanup
5. **Access Reviews**: Use reports for quarterly service principal certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- DisplayName, AppId, ServicePrincipalId
- ServicePrincipalType, AccountEnabled
- CreatedDateTime, DaysOld
- HasSecrets, HasCertificates
- SecretCount, CertificateCount
- ExpiredSecretsCount, ExpiredCertificatesCount
- ExpiringSoonSecretsCount, ExpiringSoonCertificatesCount
- CredentialSummary
- PermissionCount, HasHighRiskPerms, HasCriticalPerms
- Permissions
- OwnerCount, OwnersWithoutMFA
- OwnerDetails
- RiskLevel

### JSON Export

Structured format for automation:
```json
[
  {
    "DisplayName": "MyApp Service Principal",
    "AppId": "12345678-1234-1234-1234-123456789abc",
    "ServicePrincipalId": "87654321-4321-4321-4321-cba987654321",
    "ServicePrincipalType": "Application",
    "AccountEnabled": true,
    "HasSecrets": true,
    "HasCertificates": true,
    "SecretCount": 2,
    "CertificateCount": 1,
    "ExpiredSecretsCount": 1,
    "ExpiredCertificatesCount": 0,
    "PermissionCount": 5,
    "HasHighRiskPerms": true,
    "HasCriticalPerms": true,
    "OwnerCount": 2,
    "OwnersWithoutMFA": 1,
    "RiskLevel": "CRITICAL"
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "No service principals found matching the specified criteria"

**Cause**: Filters are too restrictive or no service principals match.

**Solution**: 
- Remove filters to see all service principals
- Check if filters are correct for your use case
- Verify you have permissions to read service principals

#### 2. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1
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

**Cause**: Large number of service principals or throttling.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyWithCredentials
```

#### 5. Credential Information Not Available

**Cause**: Missing `Application.Read.All` permission.

**Solution**:
- Ensure you have `Application.Read.All` permission
- This permission is required to read credential details
- Without it, credential analysis will be limited

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all service principals with security issues
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -Matrix -ExportPath "sp-audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all service principals, risk levels, and security findings.

### Example 2: Expired Credentials Detection

```powershell
# Find service principals with expired credentials
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyExpiredCredentials -Matrix
```

**Use Case**: Identify immediate security risks requiring credential rotation.

### Example 3: High-Permission Service Principal Audit

```powershell
# Find service principals with high-risk permissions
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyHighPermission -ExportPath "high-perm-sp.csv"
```

**Use Case**: Review service principals with elevated permissions for compliance.

### Example 4: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of high-value service principals during engagement.

### Example 5: Compliance Reporting

```powershell
# Monthly audit including disabled service principals
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -IncludeDisabled -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track service principal security posture changes over time.

### Example 6: Credential Expiration Monitoring

```powershell
# Find service principals with credentials expiring soon
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyWithCredentials -Matrix | Where-Object { $_.ExpiringSoonSecretsCount -gt 0 -or $_.ExpiringSoonCertificatesCount -gt 0 }
```

**Use Case**: Proactive credential rotation planning.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\ServicePrincipals_$date.csv"
    
    C:\Tools\Invoke-EntraServicePrincipalCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if critical-risk service principals found
    $results = Import-Csv $path
    $criticalRisk = $results | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    
    if ($criticalRisk.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($criticalRisk.Count) critical-risk service principals found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklySPCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Service Principal Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_service_principal_audit"
        severity = $_.RiskLevel
        service_principal = $_.DisplayName
        app_id = $_.AppId
        has_expired_credentials = ($_.ExpiredSecretsCount -gt 0 -or $_.ExpiredCertificatesCount -gt 0)
        has_high_permissions = $_.HasHighRiskPerms
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
    .\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -Matrix -ExportPath "C:\Reports\sp-audit.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\sp-audit.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Service principal enumeration
- Credential detection and expiration tracking
- Permission analysis
- Owner MFA status checking
- Risk assessment framework
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive security analytics

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

