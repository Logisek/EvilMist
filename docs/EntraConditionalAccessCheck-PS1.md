# Invoke-EntraConditionalAccessCheck.ps1

## Overview

`Invoke-EntraConditionalAccessCheck.ps1` is a PowerShell 7+ script designed to analyze Azure Entra ID Conditional Access policies to identify security gaps, exclusions, and misconfigurations. This tool is part of the EvilMist toolkit and helps security teams assess the effectiveness of their Conditional Access policy coverage and identify potential attack vectors.

## Purpose

Conditional Access policies are critical security controls that enforce access requirements based on conditions. This script helps:
- **Security Auditors**: Identify policy gaps and exclusions that could be exploited
- **Penetration Testers**: Discover users, groups, and applications excluded from security controls
- **IT Administrators**: Audit Conditional Access policy coverage and MFA enforcement
- **Compliance Teams**: Generate reports for security policy governance

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Comprehensive Policy Analysis**: Enumerates all CA policies and analyzes configurations
- ✅ **Exclusion Detection**: Identifies users, groups, roles, and applications excluded from policies
- ✅ **MFA Enforcement Gaps**: Detects policies without MFA requirements
- ✅ **Critical App Coverage**: Checks if critical applications are protected by policies
- ✅ **Legacy Auth Detection**: Identifies policies targeting legacy authentication methods
- ✅ **Risk Assessment**: Categorizes policies by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **Conflict Detection**: Identifies redundant or conflicting policies
- ✅ **Coverage Gap Analysis**: Highlights areas without policy protection
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only policies with exclusions or MFA gaps

## Critical Applications Monitored

The script checks if policies cover the following 10 critical enterprise applications:

### Management & Administrative Tools

1. **Microsoft Azure Management** (`797f4846-ba00-4fd7-ba43-dac1f8f63013`)
   - Azure Resource Manager API
   - Full infrastructure control capabilities

2. **Azure Portal** (`c44b4083-3bb0-49c1-b47d-974e53cbdf3c`)
   - Web-based Azure infrastructure management
   - Resource creation, configuration, monitoring

3. **Microsoft 365 Admin Portal** (`618dd325-23f6-4b6f-8380-4df78026e39b`)
   - Web-based Microsoft 365 tenant administration
   - User creation, role assignments, license management

### PowerShell & API Tools

4. **Azure AD PowerShell** (`1b730954-1685-4b74-9bfd-dac224a7b894`)
   - Classic Azure AD PowerShell module
   - Comprehensive directory management capabilities

5. **Microsoft Azure PowerShell** (`1950a258-227b-4e31-a9cf-717495945fc2`)
   - Modern Azure PowerShell Az module
   - Manages Azure resources and services

6. **Microsoft Graph Command Line Tools** (`14d82eec-204b-4c2f-b7e8-296a70dab67e`)
   - Microsoft Graph CLI (mg cli)
   - Programmatic access to all Microsoft 365 data

### Core Microsoft 365 Services

7. **Office 365 Exchange Online** (`00000002-0000-0ff1-ce00-000000000000`)
   - Email and calendar service access
   - Mailbox access, mail flow rules, transport settings

8. **Office 365 SharePoint Online** (`00000003-0000-0ff1-ce00-000000000000`)
   - Document management and collaboration platform
   - Access to all document libraries and sites

9. **Microsoft Graph** (`00000003-0000-0000-c000-000000000000`)
   - Core Microsoft Graph API
   - Programmatic access to Microsoft 365 data

### Security & Identity Management

10. **MS-PIM** (Privileged Identity Management) (`01fc33a7-78ba-4d2f-a4b7-768e336e890e`)
    - Just-in-time privileged access management
    - Can activate elevated roles (Global Admin, etc.)

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
   ```

### Required Permissions

The script requires the following Microsoft Graph API permissions:

- **Primary Scopes** (preferred):
  - `Policy.Read.All` - Read Conditional Access policies (REQUIRED)
  - `Directory.Read.All` - Read directory data
  - `Application.Read.All` - Read application information
  - `User.Read.All` - Read user profiles (for exclusion resolution)

- **Fallback Scopes** (if full access unavailable):
  - `Policy.Read.All` - Read Conditional Access policies (REQUIRED)
  - `Directory.Read.All` - Read directory data

**Note**: `Policy.Read.All` is **required** to enumerate Conditional Access policies. Without this permission, the script cannot function.

## Usage

### Basic Usage

```powershell
# Analyze all Conditional Access policies
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -ExportPath "ca-policies.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -ExportPath "ca-results.json"
```

### Include Disabled Policies

```powershell
# Scan all policies including disabled ones
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -IncludeDisabled -ExportPath "all-policies.csv"
```

### Show Only Policies With Exclusions

```powershell
# Filter to show only policies with exclusions
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -OnlyWithExclusions

# Matrix view with exclusions filter
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -OnlyWithExclusions -Matrix
```

### Show Only MFA Gaps

```powershell
# Filter to show only policies without MFA requirement
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -OnlyMFAgaps

# Matrix view with MFA gaps filter
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -OnlyMFAgaps -Matrix
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all policies including disabled, with export
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -IncludeDisabled -Matrix -ExportPath "full-audit.csv"

# Security focus: policies with exclusions only
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -OnlyWithExclusions -Matrix -ExportPath "exclusions-audit.csv"

# MFA gap analysis
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -OnlyMFAgaps -Matrix -ExportPath "mfa-gaps.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
```

## Parameters

### General Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-ExportPath` | String | Path to export results (CSV or JSON based on extension) | None |
| `-TenantId` | String | Optional Tenant ID. Uses home tenant if not specified | None |
| `-UseAzCliToken` | Switch | Try to use Azure CLI cached token first | False |
| `-UseAzPowerShellToken` | Switch | Try to use Azure PowerShell cached token first | False |
| `-IncludeDisabled` | Switch | Include disabled policies in results | False |
| `-OnlyWithExclusions` | Switch | Show only policies with exclusions | False |
| `-OnlyMFAgaps` | Switch | Show only policies without MFA enforcement | False |
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

The script provides detailed information about each Conditional Access policy:

```
[CRITICAL] Block Legacy Authentication
  Policy ID: 12345678-1234-1234-1234-123456789012
  State: Disabled
  Risk Reasons: Policy disabled
  MFA Required: No
  Exclusions: 5 user(s), 2 group(s)
  Includes: All users
  Covers Critical Apps: No
  Created: 2024-01-15T10:30:00Z
```

### Matrix Output (with `-Matrix`)

```
Risk      Status   Policy Name                    MFA  Exclusions              Critical Apps  Legacy Auth  Blocks
----      ------   -----------                    ---  ----------              --------------  ------------  ------
CRITICAL  Disabled Block Legacy Authentication    No   5 user(s), 2 group(s)   No              Yes           No
HIGH      Enabled  Require MFA for Admins         Yes  1 user(s)                Yes             No            No
MEDIUM    Enabled  Require Compliant Device       Yes  None                     No              No            No
LOW       Enabled  Baseline Protection            Yes  None                     Yes             No            No
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total policies analyzed: 12
  - CRITICAL risk: 2
  - HIGH risk: 3
  - MEDIUM risk: 4
  - LOW risk: 3

[POLICY GAPS]
  Policies with exclusions: 5
  Policies without MFA requirement: 3
  Disabled policies: 2
  Policies covering critical apps: 8

[EXCLUSIONS SUMMARY]
  Unique excluded users: 15
  Unique excluded groups: 8
  Unique excluded roles: 2
  Unique excluded apps: 3
```

## Risk Levels

The script assigns risk levels based on policy configuration and security posture:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Disabled policy OR no MFA requirement with exclusions | Red | **IMMEDIATE ACTION REQUIRED**: Enable policy or add MFA requirement |
| **HIGH** | Has exclusions OR no MFA requirement OR targets legacy auth | Yellow | **REVIEW REQUIRED**: Review exclusions and add MFA requirement |
| **MEDIUM** | No user targeting (all users) OR no device requirement | Cyan | **CONSIDER**: Refine targeting and add device requirements |
| **LOW** | Properly configured with MFA and appropriate targeting | Green | **MONITOR**: Acceptable configuration |

### Risk Assessment Logic

```
IF policy is disabled:
    RISK = CRITICAL
ELSE IF no MFA required AND has exclusions:
    RISK = CRITICAL
ELSE IF has exclusions:
    RISK = HIGH
ELSE IF no MFA required:
    RISK = HIGH
ELSE IF targets legacy auth:
    RISK = HIGH
ELSE IF no user targeting (all users):
    RISK = MEDIUM
ELSE IF no device requirement:
    RISK = MEDIUM
ELSE:
    RISK = LOW
```

## Security Considerations

### Understanding Policy Exclusions

**IMPORTANT**: Exclusions in Conditional Access policies create security gaps that can be exploited:

| Exclusion Type | Risk | Example Attack Vector |
|----------------|------|----------------------|
| **User Exclusions** | HIGH | Admin accounts excluded from MFA requirement |
| **Group Exclusions** | HIGH | Security group excluded from device compliance |
| **Role Exclusions** | CRITICAL | Global Administrators excluded from all policies |
| **Application Exclusions** | MEDIUM-HIGH | Critical apps excluded from MFA requirement |

#### Why Exclusions Matter

- **Bypass Security Controls**: Excluded entities are not subject to policy requirements
- **Privilege Escalation**: Excluded admin accounts can bypass MFA requirements
- **Attack Surface**: Exclusions create predictable security gaps
- **Compliance Violations**: Exclusions may violate security policies

#### Common Exclusion Scenarios

1. **Emergency Break-Glass Accounts**
   - Legitimate use case but should be monitored
   - Should have additional compensating controls

2. **Service Accounts**
   - Often excluded from MFA policies
   - Should use managed identities or certificate-based auth

3. **Legacy Applications**
   - Excluded due to compatibility issues
   - Should be migrated or replaced

4. **Administrative Roles**
   - Sometimes excluded for convenience
   - **CRITICAL RISK**: Should never be excluded

### MFA Enforcement Gaps

Policies without MFA requirements create security vulnerabilities:

- **Credential Attacks**: Accounts protected only by passwords
- **Phishing Susceptibility**: No second factor to prevent account takeover
- **Compliance Violations**: May violate security policies requiring MFA
- **Privilege Escalation**: Admin accounts without MFA are high-value targets

### Critical Application Coverage

Policies should protect critical applications:

- **Management Tools**: Azure Portal, M365 Admin Portal, PowerShell tools
- **Core Services**: Exchange Online, SharePoint Online, Microsoft Graph
- **Identity Management**: PIM, Azure AD management

**Gap Analysis**: If critical apps are not covered by policies, they may be accessible without security controls.

### Legacy Authentication

Policies targeting legacy authentication methods are important but risky:

- **Legacy Auth**: Exchange ActiveSync, IMAP, POP3, SMTP
- **Security Risk**: Legacy protocols often don't support modern security features
- **Recommendation**: Block legacy auth entirely where possible

### Policy Conflicts and Redundancy

Multiple policies can create conflicts:

- **Conflicting Requirements**: One policy requires MFA, another blocks access
- **Redundant Policies**: Multiple policies applying same controls
- **Order Dependency**: Policy evaluation order matters

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track policy changes and exclusions
2. **Exclusion Review**: Review all exclusions quarterly and document justification
3. **MFA Enforcement**: Ensure all policies require MFA for privileged access
4. **Critical App Coverage**: Verify all critical applications are protected
5. **Documentation**: Maintain records of policy purpose and exclusions

### For Penetration Testers

1. **Initial Reconnaissance**: Identify policies and exclusions
2. **Target Selection**: Prioritize excluded users/groups/roles
3. **Attack Path Analysis**: Use exclusions to bypass security controls
4. **Gap Exploitation**: Exploit policies without MFA requirements
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify policies align with security requirements
3. **Trend Analysis**: Compare results over time
4. **Remediation Tracking**: Monitor exclusion reduction and MFA adoption
5. **Access Reviews**: Use reports for quarterly policy certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- PolicyId, DisplayName, State
- CreatedDateTime, ModifiedDateTime
- RiskLevel, RiskReasons
- ExcludeUsersCount, ExcludeGroupsCount, ExcludeRolesCount, ExcludeAppsCount
- ExclusionSummary
- IncludeUsersCount, IncludeGroupsCount, IncludeRolesCount, IncludeAppsCount
- MFARequired, RequireCompliantDevice, RequireHybridAzureADJoinedDevice
- RequireApprovedClientApp, RequireAppProtectionPolicy
- BlocksAccess, TargetsLegacyAuth, ClientAppTypes
- CoversCriticalApps, CoveredCriticalApps
- ExcludeLocationsCount, IncludeLocationsCount
- IncludePlatforms, ExcludePlatforms

### JSON Export

Structured format for automation:
```json
[
  {
    "PolicyId": "12345678-1234-1234-1234-123456789012",
    "DisplayName": "Require MFA for Admins",
    "State": "enabled",
    "RiskLevel": "HIGH",
    "RiskReasons": "Has exclusions (1 user(s))",
    "ExcludeUsersCount": 1,
    "ExcludeGroupsCount": 0,
    "MFARequired": true,
    "CoversCriticalApps": true,
    "CoveredCriticalApps": "Microsoft Azure Management, Azure Portal"
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "No Conditional Access policies found"

**Cause**: No policies exist in the tenant or insufficient permissions.

**Solution**: 
- Verify `Policy.Read.All` permission is granted
- Check if policies exist in Azure AD portal
- Ensure you're querying the correct tenant

#### 2. "Access denied - Policy.Read.All permission required"

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1
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

**Cause**: Large number of policies or throttling.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -OnlyWithExclusions
```

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all policies and their security posture
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all policies, risk levels, and security gaps.

### Example 2: Exclusion Analysis

```powershell
# Find policies with exclusions
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -OnlyWithExclusions -Matrix

# Review output, then remediate
```

**Use Case**: Identify security gaps from policy exclusions.

### Example 3: MFA Gap Detection

```powershell
# Find policies without MFA requirement
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -OnlyMFAgaps -Matrix
```

**Use Case**: Identify policies that don't enforce MFA.

### Example 4: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of policy gaps during engagement.

### Example 5: Compliance Reporting

```powershell
# Monthly audit including disabled policies
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -IncludeDisabled -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track policy changes and exclusion trends over time.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\CAPolicies_$date.csv"
    
    C:\Tools\Invoke-EntraConditionalAccessCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if critical risks found
    $results = Import-Csv $path
    $criticalRisk = $results | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    
    if ($criticalRisk.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($criticalRisk.Count) critical CA policy risks found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyCAPolicyCheck.ps1"
Register-ScheduledTask -TaskName "Weekly CA Policy Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "conditional_access_policy"
        severity = $_.RiskLevel
        policy_name = $_.DisplayName
        policy_id = $_.PolicyId
        state = $_.State
        has_exclusions = ($_.ExcludeUsersCount + $_.ExcludeGroupsCount + $_.ExcludeRolesCount + $_.ExcludeAppsCount) -gt 0
        mfa_required = $_.MFARequired
        covers_critical_apps = $_.CoversCriticalApps
    }
}

$siemEvents | ConvertTo-Json | Out-File "siem_formatted.json"
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Support for Conditional Access policy enumeration
- Exclusion detection (users, groups, roles, apps)
- MFA enforcement gap detection
- Critical application coverage analysis
- Risk assessment based on gaps and exclusions
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
- **Invoke-EntraAppAccess.ps1**: Critical administrative access audit
- **Invoke-EntraRoleCheck.ps1**: Privileged role assignment audit
- **Invoke-EntraServicePrincipalCheck.ps1**: Service principal security audit

---

