# Invoke-EntraComplianceCheck.ps1

## Overview

`Invoke-EntraComplianceCheck.ps1` is a PowerShell script that performs comprehensive compliance assessments of Azure Entra ID configuration against industry-standard frameworks including CIS, NIST, SOC 2, ISO 27001, and GDPR.

## Purpose

This script evaluates your Azure Entra ID security configuration against multiple compliance frameworks:

- **CIS Microsoft Azure Foundations Benchmark** (v2.0/v2.1)
- **NIST 800-53 Rev 5** Security Controls
- **SOC 2 Type II** Trust Service Criteria
- **ISO 27001:2022** Controls
- **GDPR** Compliance Indicators

The script generates detailed compliance reports with control mappings, gap analysis, and remediation guidance.

## Assessment Areas

The compliance check evaluates the following security domains:

| Domain | Controls Evaluated |
|--------|-------------------|
| Identity & Access Management | MFA enforcement, privileged access, password policies |
| Conditional Access | Risk policies, legacy auth blocking, Zero Trust |
| Application Security | OAuth consent, app permissions, credential hygiene |
| External Identity | Guest access, invitation settings, directory restrictions |
| Logging & Monitoring | Diagnostic settings, log retention, security alerts |
| Device Security | Compliance requirements, registration settings |
| Data Protection | Security defaults, admin portal access |

## Prerequisites

- PowerShell 7.0 or later
- Microsoft.Graph PowerShell modules (automatically installed if missing):
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Users
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Identity.DirectoryManagement
  - Microsoft.Graph.Applications
- Appropriate permissions:
  - Directory.Read.All
  - Policy.Read.All
  - User.Read.All
  - Application.Read.All
  - AuditLog.Read.All
  - RoleManagement.Read.Directory
  - IdentityRiskyUser.Read.All
  - IdentityRiskEvent.Read.All
  - UserAuthenticationMethod.Read.All

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ExportPath` | String | None | Path to export results (CSV, JSON, or HTML based on extension) |
| `-TenantId` | String | None | Optional Tenant ID. Uses user's home tenant if not specified |
| `-UseAzCliToken` | Switch | False | Use Azure CLI cached token for authentication |
| `-UseAzPowerShellToken` | Switch | False | Use Azure PowerShell cached token for authentication |
| `-EnableStealth` | Switch | False | Enable stealth mode with default delays and jitter |
| `-RequestDelay` | Double | 0 | Base delay in seconds between API requests (0-60) |
| `-RequestJitter` | Double | 0 | Random jitter range in seconds to add/subtract from delay (0-30) |
| `-MaxRetries` | Int | 3 | Maximum retries on throttling (429) responses (1-10) |
| `-QuietStealth` | Switch | False | Suppress stealth-related status messages |
| `-Framework` | String | All | Compliance framework to focus on: CIS, NIST, SOC2, ISO27001, GDPR, or All |
| `-ControlFamily` | String | None | Filter by control family (e.g., "AC" for NIST Access Control) |
| `-OnlyFailed` | Switch | False | Show only failed/non-compliant controls |
| `-OnlyPassed` | Switch | False | Show only passed/compliant controls |
| `-MinimumSeverity` | String | Low | Minimum severity level: Critical, High, Medium, Low |
| `-IncludeRemediation` | Switch | False | Include detailed remediation steps in output |
| `-GenerateExecutiveReport` | Switch | False | Generate executive summary with compliance scores |
| `-Matrix` | Switch | False | Display results in matrix/table format |

## Usage Examples

### Basic Assessment

```powershell
# Comprehensive compliance assessment against all frameworks
.\Invoke-EntraComplianceCheck.ps1

# Display results in matrix format
.\Invoke-EntraComplianceCheck.ps1 -Matrix
```

### Framework-Specific Assessments

```powershell
# CIS Azure Benchmark assessment
.\Invoke-EntraComplianceCheck.ps1 -Framework CIS -ExportPath "cis-compliance.csv"

# NIST 800-53 assessment
.\Invoke-EntraComplianceCheck.ps1 -Framework NIST -Matrix

# SOC 2 Type II assessment with remediation guidance
.\Invoke-EntraComplianceCheck.ps1 -Framework SOC2 -IncludeRemediation -ExportPath "soc2-gaps.json"

# ISO 27001 assessment
.\Invoke-EntraComplianceCheck.ps1 -Framework ISO27001 -GenerateExecutiveReport

# GDPR compliance indicators
.\Invoke-EntraComplianceCheck.ps1 -Framework GDPR -OnlyFailed
```

### Control Family Filtering

```powershell
# NIST Access Control (AC) family only
.\Invoke-EntraComplianceCheck.ps1 -Framework NIST -ControlFamily AC -Matrix

# CIS Section 1 controls
.\Invoke-EntraComplianceCheck.ps1 -Framework CIS -ControlFamily 1

# Filter by control ID pattern
.\Invoke-EntraComplianceCheck.ps1 -ControlFamily IAM
```

### Executive Reporting

```powershell
# Generate executive summary with compliance score
.\Invoke-EntraComplianceCheck.ps1 -GenerateExecutiveReport

# Executive report showing only failed critical/high controls
.\Invoke-EntraComplianceCheck.ps1 -OnlyFailed -MinimumSeverity High -GenerateExecutiveReport

# Full HTML report for stakeholders
.\Invoke-EntraComplianceCheck.ps1 -GenerateExecutiveReport -ExportPath "executive-report.html"
```

### Export Options

```powershell
# Export to CSV (spreadsheet-friendly)
.\Invoke-EntraComplianceCheck.ps1 -ExportPath "compliance-results.csv"

# Export to JSON (programmatic processing)
.\Invoke-EntraComplianceCheck.ps1 -ExportPath "compliance-results.json"

# Export to HTML (visual report)
.\Invoke-EntraComplianceCheck.ps1 -ExportPath "compliance-report.html"
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraComplianceCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraComplianceCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraComplianceCheck -Matrix

# With framework filter
.\Invoke-EvilMist.ps1 -Script EntraComplianceCheck -Framework CIS -ExportPath "cis-report.html"
```

## Compliance Framework Mappings

### CIS Microsoft Azure Foundations Benchmark

| Control | Description |
|---------|-------------|
| 1.1.1 | Ensure Security Defaults is enabled or MFA is enforced |
| 1.1.2 | Ensure MFA is enabled for all users in administrative roles |
| 1.1.3 | Ensure MFA is enabled for all guest users |
| 1.1.4 | Ensure legacy authentication is blocked |
| 1.2.1 | Ensure Conditional Access policies are enabled |
| 1.2.2 | Ensure sign-in risk policy is enabled |
| 1.2.3 | Ensure user risk policy is enabled |
| 1.3 | Ensure fewer than 5 Global Administrators |
| 1.4 | Ensure PIM is used to manage privileged access |
| 1.5 | Ensure password expiration policy follows NIST guidelines |
| 2.1 | Ensure users cannot consent to applications |
| 2.2 | Review applications with high-privilege permissions |
| 3.1 | Ensure guest invitation settings are restricted |
| 3.2 | Ensure stale guest accounts are removed |
| 5.1 | Ensure diagnostic logging is enabled |

### NIST 800-53 Rev 5 Controls

| Control | Family | Description |
|---------|--------|-------------|
| IA-2(1) | IA | Multi-factor Authentication to Privileged Accounts |
| IA-2(12) | IA | Acceptance of PIV Credentials |
| IA-5(1) | IA | Password-Based Authentication |
| IA-8(4) | IA | Use of PIV-I Credentials |
| AC-2 | AC | Account Management |
| AC-2(1) | AC | Automated Account Management |
| AC-2(3) | AC | Disable Accounts |
| AC-2(7) | AC | Privileged User Accounts |
| AC-2(13) | AC | Disable Accounts for High-Risk Individuals |
| AC-3 | AC | Access Enforcement |
| AC-6 | AC | Least Privilege |
| AC-6(1) | AC | Authorize Access to Security Functions |
| AC-6(5) | AC | Privileged Accounts |
| AC-17 | AC | Remote Access |
| AC-19 | AC | Access Control for Mobile Devices |
| AU-6 | AU | Audit Record Review, Analysis, and Reporting |
| AU-11 | AU | Audit Record Retention |
| SI-4 | SI | System Monitoring |

### SOC 2 Trust Service Criteria

| Criteria | Category | Description |
|----------|----------|-------------|
| CC6.1 | Logical and Physical Access | Logical access security measures |
| CC6.2 | Logical and Physical Access | Restrict access to privileged functions |
| CC6.3 | Logical and Physical Access | External parties are properly authenticated |
| CC6.6 | Logical and Physical Access | Secure system authentication |
| CC6.7 | Logical and Physical Access | Third-party access management |
| CC7.2 | System Operations | Monitor system components |
| CC7.3 | System Operations | Security incident response |

### ISO 27001:2022 Controls

| Control | Description |
|---------|-------------|
| A.5.15 | Access control - Identification and authentication |
| A.5.17 | Authentication information |
| A.5.18 | Access rights |
| A.5.19 | Information security in supplier relationships |
| A.8.1 | User endpoint devices |
| A.8.2 | Privileged access rights |
| A.8.5 | Secure authentication |
| A.8.9 | Configuration management |
| A.8.15 | Logging |
| A.8.16 | Monitoring activities |

### GDPR Articles

| Article | Description |
|---------|-------------|
| Article 5 | Principles relating to processing - storage limitation |
| Article 25 | Data protection by design and by default |
| Article 28 | Processor - data processing agreements |
| Article 30 | Records of processing activities |
| Article 32 | Security of processing |
| Article 33 | Notification of a personal data breach |

## Control Severity Levels

| Severity | Description |
|----------|-------------|
| Critical | Fundamental security controls that must be addressed immediately |
| High | Important security controls that should be addressed soon |
| Medium | Security controls that should be addressed as part of normal operations |
| Low | Minor security improvements or informational items |

## Sample Output

### Standard Output

```
[FAIL] IAM-MFA-001 - Require MFA for all users
  Severity: Critical
  Details: MFA is not enforced for all users
  CIS: 1.1.1 - Ensure Security Defaults is enabled or MFA is enforced
  NIST: IA-2(1) (IA) - Identification and Authentication: Multi-factor Authentication to Privileged Accounts
  SOC2: CC6.1 - The entity implements logical access security measures
  ISO27001: A.5.15 - Access control - Identification and authentication
  GDPR: Article 32 - Security of processing - appropriate technical measures

[PASS] IAM-CA-001 - Block legacy authentication protocols
  Severity: Critical
  Details: Legacy authentication is blocked
  Evidence:
    - Blocking policies: Block Legacy Authentication, Block Basic Auth
```

### Matrix Output

```
================================================================================
COMPLIANCE ASSESSMENT MATRIX
================================================================================

Status        Severity  Control ID     CIS    NIST      SOC2   Title
------        --------  ----------     ---    ----      ----   -----
Fail          Critical  IAM-MFA-001    1.1.1  IA-2(1)   CC6.1  Require MFA for all users
Pass          Critical  IAM-CA-001     1.1.4  IA-2(12)  CC6.6  Block legacy authentication
Fail          Critical  IAM-PA-001     1.3    AC-6(5)   CC6.2  Limit Global Administrator count
Pass          High      IAM-CA-002     1.2.1  AC-2(1)   CC6.1  Require Conditional Access
Manual Review High      IAM-PA-003     1.4.1  AC-6(1)   CC6.2  Configure PIM approval

================================================================================

[COMPLIANCE SUMMARY]
Total Controls Assessed: 25
  - Passed: 15
  - Failed: 7
  - Manual Review: 3

Compliance Score: 68.2%
(Excludes Manual Review items)

[BY SEVERITY]
  Failed - Critical: 3
  Failed - High: 2
  Failed - Medium: 2
  Failed - Low: 0

[BY FRAMEWORK - Failed Controls]
  CIS Azure Benchmark: 7
  NIST 800-53: 7
  SOC 2: 5
  ISO 27001: 6
  GDPR: 4
```

### Executive Report

```
================================================================================
EXECUTIVE COMPLIANCE REPORT
================================================================================

Organization: Contoso Inc
Tenant ID: 12345678-1234-1234-1234-123456789012
Assessment Date: 2026-01-21 14:30:45
Framework(s): All

----------------------------------------
OVERALL COMPLIANCE SCORE
----------------------------------------

[########------------] 68.2%

15 of 22 controls passed

----------------------------------------
PRIORITY REMEDIATION ITEMS
----------------------------------------

[CRITICAL - Immediate Action Required]
  - Require MFA for all users
    MFA is not enforced for all users
  - Limit Global Administrator count
    8 Global Administrators - maximum 5 recommended
  - Enable Privileged Identity Management
    PIM is not enabled or has no eligible assignments

[HIGH - Action Required Soon]
  - Block high-risk sign-ins
    Sign-in risk policy is not enabled
  - Restrict user consent for applications
    Users can consent to applications accessing organizational data

================================================================================
```

## Remediation Recommendations

### Critical Priority

1. **Enable MFA for All Users**
   - Enable Security Defaults for basic protection, or
   - Create Conditional Access policy requiring MFA for all users
   - Use Azure AD Identity Protection for risk-based MFA

2. **Block Legacy Authentication**
   - Create Conditional Access policy blocking "Other clients"
   - Monitor sign-in logs for legacy auth usage before blocking
   - Update any applications still using legacy protocols

3. **Reduce Global Administrator Count**
   - Limit to 2-5 Global Administrators
   - Use PIM for eligible assignments
   - Assign more specific roles (Security Admin, User Admin, etc.)

4. **Enable PIM**
   - Convert permanent admin assignments to eligible
   - Configure approval and MFA requirements
   - Set maximum activation duration (1-4 hours for critical roles)

### High Priority

5. **Enable Risk Policies**
   - Configure sign-in risk policy (block high, MFA for medium)
   - Configure user risk policy (require password change)
   - Monitor and respond to risky users/sign-ins

6. **Restrict User Consent**
   - Set user consent to "Do not allow user consent"
   - Implement admin consent workflow
   - Review existing consent grants

7. **Enable Guest Restrictions**
   - Restrict who can invite guests
   - Limit guest directory access
   - Implement guest Access Reviews

## Integration with Other EvilMist Scripts

The compliance check integrates with findings from:

- `Invoke-EntraMFACheck.ps1` - MFA status verification
- `Invoke-EntraRoleCheck.ps1` - Privileged role analysis
- `Invoke-EntraConditionalAccessCheck.ps1` - CA policy audit
- `Invoke-EntraPIMCheck.ps1` - PIM configuration audit
- `Invoke-EntraOAuthConsentCheck.ps1` - OAuth consent review
- `Invoke-EntraGuestCheck.ps1` - Guest account analysis
- `Invoke-EntraSignInRiskCheck.ps1` - Risk policy verification

## References

- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [NIST 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [SOC 2 Trust Service Criteria](https://www.aicpa.org/resources/download/soc-2-trust-services-criteria)
- [ISO 27001:2022](https://www.iso.org/standard/27001)
- [GDPR - General Data Protection Regulation](https://gdpr.eu/)
- [Microsoft Entra ID Security Best Practices](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
