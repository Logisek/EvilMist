# Invoke-EntraDirectorySyncCheck.ps1

## Overview

`Invoke-EntraDirectorySyncCheck.ps1` is a PowerShell 7+ script designed to analyze Azure Entra ID directory synchronization status, enumerate sync errors, identify sync conflicts, and check sync scope and filters. This tool is part of the EvilMist toolkit and helps security teams and IT administrators assess the health and configuration of directory synchronization in their Azure AD tenant.

## Purpose

Directory synchronization is critical for hybrid identity environments. This script helps:
- **IT Administrators**: Monitor sync health and identify sync issues
- **Security Teams**: Assess sync configuration and detect sync-related security gaps
- **Compliance Teams**: Generate reports for sync status and error tracking
- **Penetration Testers**: Identify sync misconfigurations and potential attack vectors

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Comprehensive Sync Analysis**: Identifies synced vs cloud-only users
- ✅ **Sync Error Detection**: Enumerates all provisioning and sync errors
- ✅ **Stale Sync Detection**: Identifies users with stale synchronization (>7 days)
- ✅ **Sync Conflict Identification**: Detects duplicate attributes and conflicts
- ✅ **Sync Scope Analysis**: Checks sync configuration and scope
- ✅ **Risk Assessment**: Categorizes users by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **Activity Analytics**: Sync statistics, error breakdowns, domain analysis
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only sync errors, stale sync, or include disabled accounts

## Sync Status Analysis

The script analyzes directory synchronization across multiple dimensions:

### Sync Source Identification

1. **On-Premises Synced Users**
   - Users synchronized from on-premises Active Directory
   - Identified by `onPremisesSyncEnabled`, `onPremisesImmutableId`, or `onPremisesSecurityIdentifier`
   - Includes domain, SAM account name, and distinguished name information

2. **Cloud-Only Users**
   - Users created directly in Azure AD
   - No on-premises synchronization
   - Typically service accounts, guest users, or cloud-native accounts

### Sync Health Indicators

- **Last Sync Timestamp**: Shows when each user was last synchronized
- **Days Since Last Sync**: Calculates sync staleness
- **Sync Errors**: Enumerates provisioning errors and conflicts
- **Error Categories**: Groups errors by type (PropertyConflict, DuplicateAttribute, etc.)

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
  - `Directory.Read.All` - Read directory data and sync configuration
  - `User.Read.All` - Read all user profiles and sync properties
  - `AuditLog.Read.All` - Read audit logs (optional, for sync history)

- **Fallback Scopes** (if full access unavailable):
  - `Directory.Read.All` - Read directory data
  - `User.ReadBasic.All` - Read basic user info

**Note**: Full sync error details require `User.Read.All` permission. With reduced permissions, basic sync status will still be available.

## Usage

### Basic Usage

```powershell
# Simple scan of all users' sync status
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1

# During the scan, you'll see sync status for all users:
# [+] Retrieved 1250 total users
# [*] Analyzing sync status for each user...
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -ExportPath "sync-status.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -ExportPath "sync-results.json"
```

### Include Disabled User Accounts

```powershell
# Scan all users including disabled accounts
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -IncludeDisabledUsers -ExportPath "all-sync-status.csv"
```

### Show Only Users with Sync Errors

```powershell
# Filter to show only users with sync errors
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -OnlySyncErrors

# Matrix view with error filter
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -OnlySyncErrors -Matrix
```

### Show Only Stale Sync Users

```powershell
# Filter to show only users with stale sync (>7 days)
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -OnlyStaleSync

# Export stale sync users
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -OnlyStaleSync -ExportPath "stale-sync.csv"
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all users, all sync data, with export
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "full-sync-audit.csv"

# Security focus: sync errors only
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -OnlySyncErrors -Matrix -ExportPath "sync-errors.csv"

# Stale sync analysis
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -OnlyStaleSync -Matrix -ExportPath "stale-sync-analysis.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
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
| `-OnlySyncErrors` | Switch | Show only users with sync errors | False |
| `-OnlyStaleSync` | Switch | Show only users with stale sync (>7 days) | False |
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

The script provides detailed information about each user's sync status:

```
[HIGH] john.doe@company.com
  Display Name: John Doe
  Sync Source: On-Premises AD
  On-Premises Domain: COMPANY.LOCAL
  SAM Account Name: jdoe
  Distinguished Name: CN=John Doe,OU=Users,DC=company,DC=local
  Account Status: Enabled
  Last Sync: 2024-12-20 14:23:45 (3 days ago)
  Sync Errors: 2 error(s)
  Error Categories: PropertyConflict, DuplicateAttribute
  Error Details:
    - Category: PropertyConflict
      Property: mail
      Value: john.doe@company.com
      Occurred: 2024-12-18T10:30:00Z
    - Category: DuplicateAttribute
      Property: userPrincipalName
      Value: john.doe@company.com
      Occurred: 2024-12-18T10:30:00Z
  Risk Factors: 2 sync error(s)
```

### Matrix Output (with `-Matrix`)

```
Risk  Source          Status   User Principal Name    Display Name  Domain         Last Sync  Errors  Error Categories
----  ------          ------   -------------------    ------------  ------         ----------  ------  ---------------
HIGH  On-Premises AD  Enabled  john.doe@company.com  John Doe      COMPANY.LOCAL  3d ago     2       PropertyConflict, DuplicateAttribute
LOW   Cloud-Only      Enabled  jane.smith@company.com Jane Smith   -              -          0       -
MEDIUM On-Premises AD Enabled  bob.wilson@company.com Bob Wilson    COMPANY.LOCAL  15d ago   0       -
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total users analyzed: 1250
Users in results: 1250
  - Synced from On-Premises: 850
  - Cloud-Only: 400
  - Users with Sync Errors: 12
  - Stale Sync (>7 days): 45

[RISK BREAKDOWN]
  - CRITICAL risk: 0
  - HIGH risk: 12
  - MEDIUM risk: 45
  - LOW risk: 1193

[USERS BY DOMAIN]
  COMPANY.LOCAL: 850
  SUBSIDIARY.LOCAL: 120

[ERROR CATEGORIES]
  PropertyConflict: 8
  DuplicateAttribute: 4
  QuotaExceeded: 2
```

## Risk Levels

The script assigns risk levels based on sync health and errors:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Multiple sync errors or very stale sync (>30 days) | Red | **IMMEDIATE ACTION REQUIRED**: Resolve sync errors or investigate stale sync |
| **HIGH** | Users with sync errors | Red | **URGENT**: Fix sync errors to prevent authentication issues |
| **MEDIUM** | Stale sync (>7 days but ≤30 days) | Yellow | **REVIEW**: Investigate why sync is stale, may indicate sync service issues |
| **LOW** | Healthy sync or cloud-only users | Green | **MONITOR**: Normal sync status |

### Risk Assessment Logic

```
IF user has sync errors:
    RISK = HIGH (Sync errors can cause authentication failures)
ELSE IF user is synced AND days since last sync > 30:
    RISK = HIGH (Very stale sync indicates sync service failure)
ELSE IF user is synced AND days since last sync > 7:
    RISK = MEDIUM (Stale sync may indicate issues)
ELSE:
    RISK = LOW (Healthy sync or cloud-only user)
```

## Security Considerations

### Understanding Sync Status

**IMPORTANT**: Directory synchronization status affects authentication and access:

| Sync Status | What It Means | Security Implications |
|-------------|---------------|----------------------|
| **Synced from On-Premises** | User account synchronized from AD | Password changes happen on-premises, may bypass cloud MFA policies |
| **Cloud-Only** | User created directly in Azure AD | Full cloud control, subject to all cloud security policies |
| **Sync Errors** | Synchronization failed | User may not be able to authenticate, or may have inconsistent attributes |
| **Stale Sync** | No sync in 7+ days | May indicate sync service issues, password changes may not sync |

#### Why Sync Status Matters

- **On-Premises Synced Users**: Password changes happen on-premises, may bypass cloud password policies
- **Sync Errors**: Can cause authentication failures or inconsistent user attributes
- **Stale Sync**: May indicate sync service issues or configuration problems
- **Duplicate Attributes**: Can cause authentication conflicts and security issues

#### Common Sync Error Categories

- **PropertyConflict**: Attribute value conflicts between on-premises and cloud
- **DuplicateAttribute**: Duplicate attribute values (e.g., duplicate UPNs)
- **QuotaExceeded**: Sync quota limits exceeded
- **InvalidAttributeValue**: Invalid attribute value format or content
- **ObjectNotFound**: Referenced object not found in on-premises AD

#### Recommendation

1. **Monitor sync errors regularly** - Fix errors promptly to prevent authentication issues
2. **Investigate stale sync** - May indicate sync service problems or configuration issues
3. **Review sync scope** - Ensure only necessary OUs are synchronized
4. **Use sync filters** - Limit sync scope to reduce attack surface
5. **Monitor sync health** - Set up alerts for sync errors and stale sync

### Why This Matters

Sync issues can lead to:
- **Authentication Failures**: Users unable to sign in due to sync errors
- **Security Gaps**: Stale sync may bypass security policy updates
- **Data Inconsistency**: Attribute conflicts can cause access issues
- **Compliance Violations**: Sync errors may prevent proper access controls
- **Privilege Escalation**: Duplicate attributes or sync conflicts can be exploited

### High-Risk Scenarios

1. **Users with Sync Errors** (HIGH Risk)
   - May be unable to authenticate
   - Attribute conflicts can cause access issues
   - May indicate configuration problems

2. **Stale Sync** (MEDIUM-HIGH Risk)
   - Password changes may not sync
   - Security policy updates may not apply
   - May indicate sync service failure

3. **Duplicate Attributes** (HIGH Risk)
   - Can cause authentication conflicts
   - May allow unauthorized access
   - Indicates data quality issues

## Best Practices

### For IT Administrators

1. **Regular Monitoring**: Run weekly to track sync health
2. **Error Resolution**: Fix sync errors promptly to prevent authentication issues
3. **Stale Sync Investigation**: Investigate users with stale sync (>7 days)
4. **Sync Scope Review**: Regularly review sync scope and filters
5. **Documentation**: Maintain records of sync configuration and changes

### For Security Teams

1. **Sync Health Assessment**: Use as part of security audits
2. **Error Analysis**: Analyze sync errors for security implications
3. **Compliance Reporting**: Generate reports for compliance audits
4. **Attack Surface Analysis**: Identify sync-related security gaps
5. **Monitoring**: Set up alerts for sync errors and stale sync

### For Penetration Testers

1. **Reconnaissance**: Identify sync configuration and scope
2. **Error Exploitation**: Look for sync errors that may indicate misconfigurations
3. **Stale Sync Analysis**: Identify users with stale sync for potential exploitation
4. **Scope Analysis**: Understand sync scope to identify attack vectors
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Error Tracking**: Monitor sync errors for compliance issues
3. **Health Reporting**: Generate reports for sync health assessments
4. **Trend Analysis**: Compare results over time to track improvements
5. **Remediation Tracking**: Monitor sync error resolution progress

## Export Formats

### CSV Export

Includes all fields for analysis:
- DisplayName, UserPrincipalName, Email
- AccountEnabled, UserType
- SyncSource, OnPremisesSyncEnabled
- OnPremisesDomainName, OnPremisesSamAccountName, OnPremisesDistinguishedName
- OnPremisesLastSyncDateTime, DaysSinceLastSync
- OnPremisesImmutableId, OnPremisesSecurityIdentifier
- HasSyncErrors, ErrorCount, ErrorCategories
- ErrorDetailsJSON (JSON string of error details)
- RiskLevel, RiskFactors

### JSON Export

Structured format for automation:
```json
[
  {
    "DisplayName": "John Doe",
    "UserPrincipalName": "john.doe@company.com",
    "Email": "john.doe@company.com",
    "SyncSource": "On-Premises AD",
    "OnPremisesSyncEnabled": true,
    "OnPremisesDomainName": "COMPANY.LOCAL",
    "OnPremisesLastSyncDateTime": "2024-12-20T14:23:45Z",
    "DaysSinceLastSync": 3,
    "HasSyncErrors": true,
    "ErrorCount": 2,
    "ErrorCategories": "PropertyConflict, DuplicateAttribute",
    "RiskLevel": "HIGH",
    "RiskFactors": "2 sync error(s)"
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "No sync data found"

**Cause**: No users found or insufficient permissions.

**Solution**: 
- Verify you have `Directory.Read.All` and `User.Read.All` permissions
- Check if tenant has any synced users
- Try with `-IncludeDisabledUsers` to include all users

#### 2. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1
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
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -EnableStealth -MaxRetries 5

# Or filter results
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -OnlySyncErrors
```

#### 5. Missing Sync Configuration

**Cause**: Sync configuration may not be accessible via Graph API.

**Solution**:
- Full sync configuration requires Azure AD Connect PowerShell module
- Basic sync status is available via Graph API
- Check Azure AD Connect server for detailed configuration

## Examples

### Example 1: Basic Sync Health Check

```powershell
# Check sync status for all users
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -Matrix -ExportPath "sync_health_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all users, sync status, and health indicators.

### Example 2: Sync Error Detection

```powershell
# Find users with sync errors
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -OnlySyncErrors -Matrix

# Review output, then remediate
```

**Use Case**: Identify immediate sync issues for remediation.

### Example 3: Stale Sync Analysis

```powershell
# Find users with stale sync
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -OnlyStaleSync -ExportPath "stale-sync.csv"

# Investigate why sync is stale
```

**Use Case**: Identify sync service issues or configuration problems.

### Example 4: Comprehensive Audit

```powershell
# Full sync audit including disabled accounts
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -IncludeDisabledUsers -Matrix -ExportPath "full-sync-audit.csv"

# Compare with previous month's report
```

**Use Case**: Track sync health changes and error resolution over time.

### Example 5: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -TenantId "customer-tenant-id" -ExportPath "customer-sync.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly sync health checks
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SyncAudits\SyncHealth_$date.csv"
    
    C:\Tools\Invoke-EntraDirectorySyncCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if sync errors found
    $results = Import-Csv $path
    $syncErrors = $results | Where-Object { $_.HasSyncErrors -eq "True" }
    
    if ($syncErrors.Count -gt 0) {
        Send-MailMessage -To "it@company.com" `
            -Subject "ALERT: $($syncErrors.Count) users with sync errors" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklySyncCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Sync Health Check" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_sync_status"
        severity = $_.RiskLevel
        user = $_.UserPrincipalName
        sync_source = $_.SyncSource
        has_errors = $_.HasSyncErrors
        error_count = $_.ErrorCount
        days_since_sync = $_.DaysSinceLastSync
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
    .\scripts\powershell\Invoke-EntraDirectorySyncCheck.ps1 -Matrix -ExportPath "C:\Reports\sync.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\sync.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Sync status detection (synced vs cloud-only)
- Sync error enumeration
- Stale sync detection (>7 days)
- Risk assessment framework
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive sync analytics

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
- **Invoke-EntraStaleAccountCheck.ps1**: Stale account and account hygiene check

---

