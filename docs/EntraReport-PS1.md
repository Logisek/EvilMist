# Invoke-EntraReport.ps1

## Overview

The **Invoke-EntraReport.ps1** script is a consolidated HTML security report generator that runs multiple EvilMist security checks and generates a unified executive dashboard report. It provides comprehensive security assessment with risk trending, remediation priority matrix, and detailed findings by category.

## Features

- **Consolidated Reporting**: Run multiple security checks with a single command
- **Executive Dashboard**: Professional HTML report with security score and risk overview
- **Remediation Priority Matrix**: Prioritized findings for efficient remediation
- **Trend Analysis**: Compare against baseline reports to track security posture over time
- **Multiple Scan Modes**: Quick scan, comprehensive scan, or custom check selection
- **JSON Export**: Automatic JSON export for baseline comparison

## Prerequisites

- PowerShell 7.0 or later
- Microsoft Graph PowerShell SDK modules
- Appropriate Microsoft Graph permissions:
  - `Directory.Read.All`
  - `User.Read.All`
  - `UserAuthenticationMethod.Read.All`
  - `RoleManagement.Read.Directory`
  - `Policy.Read.All`
  - `Application.Read.All`
  - `Group.Read.All`
  - `AuditLog.Read.All`

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Checks` | String | Comma-separated list of checks to run or 'All' |
| `-ExportPath` | String | Path to export the HTML report (defaults to timestamped filename) |
| `-TenantId` | String | Target tenant ID (optional) |
| `-UseAzCliToken` | Switch | Use Azure CLI cached token |
| `-UseAzPowerShellToken` | Switch | Use Azure PowerShell cached token |
| `-EnableStealth` | Switch | Enable stealth mode with delays |
| `-RequestDelay` | Double | Base delay between API requests (0-60s) |
| `-RequestJitter` | Double | Random jitter range (0-30s) |
| `-MaxRetries` | Int | Maximum retries on throttling (1-10) |
| `-QuietStealth` | Switch | Suppress stealth status messages |
| `-BaselinePath` | String | Path to previous report JSON for trend comparison |
| `-IncludeDisabledUsers` | Switch | Include disabled user accounts |
| `-QuickScan` | Switch | Run core security checks only |
| `-ComprehensiveScan` | Switch | Run all available checks |

## Available Checks

### Identity Security
- **MFA** - Multi-Factor Authentication Check
- **SSPR** - Self-Service Password Reset Check
- **PasswordPolicy** - Password Policy Check
- **LegacyAuth** - Legacy Authentication Check
- **SignInRisk** - Sign-In Risk Analysis

### Access Control
- **Roles** - Privileged Role Assignment Check
- **ConditionalAccess** - Conditional Access Policy Check
- **Groups** - Group Security Check
- **Applications** - Application Registration Check
- **ServicePrincipals** - Service Principal Check
- **AdminUnits** - Administrative Unit Check
- **AppAccess** - Critical Administrative Access Check
- **OAuthConsent** - OAuth Consent Grant Audit
- **PIM** - Privileged Identity Management Check

### Identity Hygiene
- **Guests** - Guest Account Check
- **StaleAccounts** - Stale Account Check

### Attack Analysis
- **AttackPaths** - Attack Path Analysis
- **AzureAttackPath** - Azure Attack Path Analysis

### Azure Infrastructure
- **KeyVault** - Key Vault Security Audit
- **StorageAccount** - Storage Account Security Audit
- **NetworkSecurity** - Network Security Audit
- **ManagedIdentity** - Managed Identity Audit
- **AzureRBAC** - Azure RBAC Check

### Microsoft 365
- **Exchange** - Exchange Online Security
- **SharePoint** - SharePoint Online Security
- **Teams** - Microsoft Teams Security
- **PowerPlatform** - Power Platform Audit

### Configuration
- **Devices** - Device Trust Check
- **DirectorySync** - Directory Sync Check
- **Licenses** - License Analysis

## Usage Examples

### Basic Report with Core Checks
```powershell
.\Invoke-EvilMist.ps1 -Script EntraReport -Checks MFA,Roles,ConditionalAccess
```

### Quick Security Scan
```powershell
.\Invoke-EvilMist.ps1 -Script EntraReport -QuickScan -ExportPath "quick-assessment.html"
```

### Comprehensive Security Assessment
```powershell
.\Invoke-EvilMist.ps1 -Script EntraReport -ComprehensiveScan -ExportPath "full-assessment.html"
```

### All Checks with Custom Output
```powershell
.\Invoke-EvilMist.ps1 -Script EntraReport -Checks All -ExportPath "security-report.html"
```

### Trend Analysis with Baseline
```powershell
.\Invoke-EvilMist.ps1 -Script EntraReport -ComprehensiveScan -BaselinePath "previous-report.json"
```

### Stealth Mode Assessment
```powershell
.\Invoke-EvilMist.ps1 -Script EntraReport -QuickScan -EnableStealth -QuietStealth
```

### Specific Tenant Assessment
```powershell
.\Invoke-EvilMist.ps1 -Script EntraReport -Checks MFA,Roles -TenantId "your-tenant-id"
```

### Using Azure CLI Token
```powershell
.\Invoke-EvilMist.ps1 -Script EntraReport -QuickScan -UseAzCliToken
```

## Report Output

The script generates two output files:

1. **HTML Report** (`*.html`) - Executive dashboard with:
   - Security score (0-100) with visual indicator
   - Finding counts by severity (Critical, High, Medium, Low)
   - Executive summary
   - Trend analysis (if baseline provided)
   - Remediation priority matrix
   - Detailed findings by category

2. **JSON Data** (`*.json`) - Structured data that can be:
   - Used as a baseline for future comparisons
   - Imported into other tools
   - Used for custom reporting

## Report Sections

### Security Score
A calculated score (0-100) based on findings:
- Each CRITICAL finding: -10 points
- Each HIGH finding: -5 points
- Each MEDIUM finding: -2 points
- Each LOW finding: -0.5 points

### Remediation Priority Matrix
| Priority | Risk Level | Recommended Timeline |
|----------|------------|---------------------|
| P1 | CRITICAL | Within 24 hours |
| P2 | HIGH | Within 1 week |
| P3 | MEDIUM | Within 1 month |
| P4 | LOW | During regular maintenance |

### Detailed Findings
Organized by category with:
- Risk level badge
- Finding type
- Details (user, policy, or resource affected)
- Recommended remediation

## Scan Modes

### Quick Scan (-QuickScan)
Runs core security checks for rapid assessment:
- MFA Check
- Role Check
- Conditional Access Check
- Attack Path Check
- OAuth Consent Check
- PIM Check

### Comprehensive Scan (-ComprehensiveScan)
Runs all available checks for complete coverage. Best for:
- Initial security assessments
- Compliance audits
- Periodic comprehensive reviews

### Custom Checks (-Checks)
Specify exactly which checks to run:
```powershell
-Checks "MFA,Roles,Guests,Applications"
```

## Red Team Applications

1. **Reconnaissance**: Quickly assess security posture of target tenant
2. **Attack Surface Mapping**: Identify weak points across multiple domains
3. **Privilege Escalation**: Find attack paths and excessive permissions
4. **Persistence Opportunities**: Identify OAuth apps, service principals with high privileges

## Blue Team Applications

1. **Security Assessments**: Regular security posture reviews
2. **Compliance Reporting**: Executive-ready documentation
3. **Trend Tracking**: Monitor security improvements over time
4. **Remediation Planning**: Prioritized action items

## Sample Output

```
[*] Running 6 security check(s)...
[*] Checks: MFA, Roles, ConditionalAccess, AttackPaths, OAuthConsent, PIM

============================================================
[MFA] Multi-Factor Authentication Check
============================================================
[*] Running MFA Check...
[+] MFA Check: Found 12 users without MFA out of 150 total

============================================================
[Roles] Privileged Role Assignment Check
============================================================
[*] Running Privileged Role Check...
[+] Role Check: Found 8 privileged role assignments

...

============================================================
ASSESSMENT SUMMARY
============================================================

Tenant: Contoso Corporation
Checks Run: 6
Total Findings: 25

  CRITICAL: 3
  HIGH: 8
  MEDIUM: 10
  LOW: 4

[+] Report generated: EvilMist-Report-20260121-143022.html
[*] Security report generation completed successfully!
```

## Troubleshooting

### "Failed to retrieve users"
Ensure you have `User.Read.All` permission and the account is not blocked by Conditional Access.

### "PIM data requires RoleManagement.Read.Directory"
PIM checks require additional permissions. Run with appropriate Graph scopes.

### Report shows no findings
Verify authentication was successful and you have read access to the tenant.

## Related Scripts

- [Invoke-EntraMFACheck.ps1](EntraMFACheck-PS1.md) - Detailed MFA analysis
- [Invoke-EntraRoleCheck.ps1](EntraRoleCheck-PS1.md) - Detailed role analysis
- [Invoke-EntraConditionalAccessCheck.ps1](EntraConditionalAccessCheck-PS1.md) - Detailed CA analysis
- [Invoke-EntraAttackPathCheck.ps1](EntraAttackPathCheck-PS1.md) - Attack path analysis

## Version History

- **1.0.0** - Initial release with core reporting capabilities
  - HTML report generation
  - JSON baseline export
  - Trend analysis
  - Remediation priority matrix
  - Quick and comprehensive scan modes
