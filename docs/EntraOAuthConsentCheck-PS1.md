# Invoke-EntraOAuthConsentCheck.ps1

## Overview

`Invoke-EntraOAuthConsentCheck.ps1` is a PowerShell script that detects illicit OAuth consent grants and risky OAuth application permissions in Azure Entra ID. OAuth consent grant attacks are a major attack vector used in phishing campaigns and for establishing persistent access to organizational data.

## Purpose

This script performs a comprehensive audit of OAuth consent grants to identify potential security risks, including:

- **Enumeration of all OAuth2PermissionGrants** (delegated permissions)
- **Admin vs User consent identification** - distinguishes between tenant-wide admin consent and individual user consent
- **Detection of dangerous permissions** - identifies high-risk scopes like Mail.ReadWrite, Files.ReadWrite.All, User.ReadWrite.All
- **Stale/unused consent detection** - finds consent grants not used in 90+ days
- **Third-party app analysis** - identifies non-Microsoft applications with elevated permissions
- **Risk assessment** - categorizes grants as CRITICAL, HIGH, MEDIUM, or LOW risk

## Attack Scenario Context

### Illicit Consent Grant Attack

1. Attacker creates a malicious OAuth application
2. Attacker sends phishing link to victim requesting OAuth consent
3. Victim grants consent (often unknowingly) to dangerous permissions
4. Attacker uses the granted permissions to:
   - Read/exfiltrate emails (Mail.ReadWrite)
   - Access/download files (Files.ReadWrite.All)
   - Enumerate users and organization (User.Read.All)
   - Maintain persistent access even after password changes

### Red Team Value

- Identify existing consent grants that could be leveraged for persistence
- Find overly permissive admin consent grants
- Discover third-party apps with dangerous permissions
- Identify stale apps that may have been forgotten but still have access

### Blue Team Value

- Audit and review all OAuth consent grants
- Identify potentially malicious third-party applications
- Clean up stale/unused consent grants
- Verify admin consent grants are appropriate
- Detect signs of consent grant attacks

## Prerequisites

- PowerShell 7.0 or later
- Microsoft.Graph PowerShell modules (automatically installed if missing):
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Applications
  - Microsoft.Graph.Users
  - Microsoft.Graph.Identity.SignIns
- Appropriate permissions:
  - Directory.Read.All
  - Application.Read.All
  - DelegatedPermissionGrant.Read.All
  - User.Read.All (for sign-in activity)
  - AuditLog.Read.All (for sign-in activity)

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ExportPath` | String | None | Path to export results (CSV or JSON based on extension) |
| `-TenantId` | String | None | Optional Tenant ID. Uses user's home tenant if not specified |
| `-UseAzCliToken` | Switch | False | Use Azure CLI cached token for authentication |
| `-UseAzPowerShellToken` | Switch | False | Use Azure PowerShell cached token for authentication |
| `-EnableStealth` | Switch | False | Enable stealth mode with default delays and jitter |
| `-RequestDelay` | Double | 0 | Base delay in seconds between API requests (0-60) |
| `-RequestJitter` | Double | 0 | Random jitter range in seconds to add/subtract from delay (0-30) |
| `-MaxRetries` | Int | 3 | Maximum retries on throttling (429) responses (1-10) |
| `-QuietStealth` | Switch | False | Suppress stealth-related status messages |
| `-StaleDays` | Int | 90 | Days without sign-in activity to consider a consent grant stale (1-365) |
| `-OnlyHighRisk` | Switch | False | Show only HIGH and CRITICAL risk consent grants |
| `-OnlyThirdParty` | Switch | False | Show only third-party (non-Microsoft) applications |
| `-OnlyStale` | Switch | False | Show only stale/unused consent grants |
| `-OnlyAdminConsent` | Switch | False | Show only admin consent (tenant-wide) grants |
| `-Matrix` | Switch | False | Display results in matrix/table format |

## Usage Examples

### Basic Scan

```powershell
# Enumerate all OAuth consent grants
.\Invoke-EntraOAuthConsentCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\Invoke-EntraOAuthConsentCheck.ps1 -ExportPath "consent-grants.csv"

# Export to JSON
.\Invoke-EntraOAuthConsentCheck.ps1 -ExportPath "consent-grants.json"
```

### Filtered Scans

```powershell
# Show only high-risk consent grants in matrix format
.\Invoke-EntraOAuthConsentCheck.ps1 -OnlyHighRisk -Matrix

# Show only third-party apps with admin consent
.\Invoke-EntraOAuthConsentCheck.ps1 -OnlyThirdParty -OnlyAdminConsent

# Show consent grants not used in the last 60 days
.\Invoke-EntraOAuthConsentCheck.ps1 -StaleDays 60 -OnlyStale

# Focus on third-party apps only
.\Invoke-EntraOAuthConsentCheck.ps1 -OnlyThirdParty -Matrix
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraOAuthConsentCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraOAuthConsentCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Alternative Authentication

```powershell
# Use Azure CLI token
.\Invoke-EntraOAuthConsentCheck.ps1 -UseAzCliToken

# Use Azure PowerShell token
.\Invoke-EntraOAuthConsentCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\Invoke-EntraOAuthConsentCheck.ps1 -TenantId "your-tenant-id"
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraOAuthConsentCheck -Matrix

# With export
.\Invoke-EvilMist.ps1 -Script EntraOAuthConsentCheck -ExportPath "results.csv" -OnlyHighRisk
```

## Risk Levels

The script categorizes consent grants into four risk levels:

### CRITICAL

- Admin consent (tenant-wide) + critical permissions + third-party app
- Example: Third-party app with tenant-wide Mail.ReadWrite.All or Directory.ReadWrite.All

### HIGH

- Admin consent with dangerous permissions
- User consent with critical permissions
- Third-party app with dangerous permissions (any consent type)

### MEDIUM

- Any dangerous permissions (Microsoft apps included)
- Stale consent grants
- Third-party app with any permissions

### LOW

- Microsoft apps with non-dangerous permissions
- Active consent grants with standard permissions

## Dangerous Permissions Detected

### Critical Permissions (Highest Risk)

| Permission | Risk Description |
|------------|------------------|
| Mail.ReadWrite | Full mailbox access - data exfiltration |
| Mail.ReadWrite.All | Tenant-wide mail access |
| Mail.Send | Send email as user - phishing, BEC |
| Files.ReadWrite.All | Access all files - data exfiltration |
| Sites.ReadWrite.All | SharePoint/OneDrive write access |
| Sites.FullControl.All | Full SharePoint control |
| User.ReadWrite.All | Modify all users - privilege escalation |
| Directory.ReadWrite.All | Modify directory - privilege escalation |
| RoleManagement.ReadWrite.Directory | Assign admin roles |
| Application.ReadWrite.All | Create/modify apps - persistence |

### Dangerous Permissions

| Permission | Risk Description |
|------------|------------------|
| Mail.Read | Read emails - reconnaissance |
| Files.Read.All | Read all files - data exfiltration |
| User.Read.All | Enumerate users - reconnaissance |
| Directory.Read.All | Read directory - reconnaissance |
| Contacts.Read | Access contacts - social engineering |
| Calendars.Read | View calendars - reconnaissance |
| Chat.Read | Read Teams chat - data exfiltration |
| Notes.Read.All | Read OneNote - data exfiltration |

## Output Fields

| Field | Description |
|-------|-------------|
| AppDisplayName | Name of the application with consent |
| AppId | Application (client) ID |
| ServicePrincipalId | Service principal object ID |
| Publisher | Application publisher name |
| IsMicrosoftApp | Whether app is from Microsoft |
| AppType | "Microsoft" or "Third-Party" |
| ConsentType | "AdminConsent" or "UserConsent" |
| ConsentTypeDisplay | Human-readable consent type |
| GrantedTo | User or "All Users (Tenant-Wide)" |
| GrantedToType | "User" or "Tenant" |
| ResourceName | The API/resource being accessed |
| PermissionCount | Number of permissions granted |
| Permissions | Comma-separated list of all permissions |
| HasDangerousPermissions | Boolean - contains dangerous perms |
| HasCriticalPermissions | Boolean - contains critical perms |
| DangerousPermissions | List of dangerous permissions found |
| DangerousPermissionCount | Count of dangerous permissions |
| LastSignIn | Last sign-in date (if available) |
| DaysSinceLastSignIn | Days since last sign-in |
| IsStale | Whether consent is stale/unused |
| StaleStatus | "Active", "Stale (X days)", or "Unknown" |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |

## Sample Output

### Standard Output

```
[CRITICAL] OAuth Consent: PhishingApp (Third-Party)
  App ID: abc12345-1234-1234-1234-abc123456789
  Publisher: Unknown Publisher
  Consent Type: Admin Consent (Tenant-Wide)
  Granted To: All Users (Tenant-Wide)
  Resource: Microsoft Graph
  Permissions (4): Mail.ReadWrite, Files.ReadWrite.All, User.Read.All, offline_access
  [!] DANGEROUS Permissions: Mail.ReadWrite, Files.ReadWrite.All
  [!] CRITICAL Permissions detected - potential for full compromise
  Status: Stale (120 days)
  [!] Third-Party Application - verify legitimacy
```

### Matrix Output

```
================================================================================
MATRIX VIEW - OAUTH CONSENT GRANT SECURITY AUDIT
================================================================================

Risk      App Type     Application          Consent Type  Granted To            Perms  Dangerous
----      --------     -----------          ------------  ----------            -----  ---------
CRITICAL  Third-Party  PhishingApp          AdminConsent  All Users (Tenant...  4      2
HIGH      Third-Party  SuspiciousApp        UserConsent   user@company.com      3      1
MEDIUM    Third-Party  BusinessApp          AdminConsent  All Users (Tenant...  2      0
LOW       Microsoft    Microsoft Graph...   AdminConsent  All Users (Tenant...  5      0

================================================================================

[SUMMARY]
Total consent grants analyzed: 47
  - CRITICAL risk: 1
  - HIGH risk: 3
  - MEDIUM risk: 12
  - LOW risk: 31

[CONSENT TYPES]
  Admin Consent (Tenant-Wide): 28
  User Consent (Individual): 19

[APPLICATION TYPES]
  Microsoft Apps: 35
  Third-Party Apps: 12

[DANGEROUS PERMISSIONS]
  With dangerous permissions: 8
  With critical permissions: 2

[STALE GRANTS]
  Stale/unused (>90 days): 5

[TOP RISKY THIRD-PARTY APPS]
  PhishingApp: 1 consent grant(s)
  SuspiciousApp: 2 consent grant(s)
```

## Remediation Recommendations

### For CRITICAL/HIGH Risk Findings

1. **Verify application legitimacy** - Confirm the third-party app is known and approved
2. **Review consent scope** - Determine if permissions are necessary for app function
3. **Revoke suspicious consent** - Remove consent grants for unknown/malicious apps
4. **Check for compromise indicators** - Review sign-in logs and audit logs
5. **Reset affected user credentials** - If user consent was phished

### For Stale Consent Grants

1. **Review app necessity** - Determine if app is still needed
2. **Remove unused consent** - Clean up consent grants for apps no longer in use
3. **Implement consent policies** - Require admin approval for new consent

### Preventive Measures

1. **Disable user consent** - Require admin consent for all apps
2. **Configure consent workflow** - Implement admin approval process
3. **Block risky permissions** - Create policies to block dangerous permission requests
4. **Monitor consent activity** - Alert on new consent grants
5. **Regular consent reviews** - Periodically audit consent grants

## Related Scripts

- `Invoke-EntraApplicationCheck.ps1` - Application registration security audit
- `Invoke-EntraServicePrincipalCheck.ps1` - Service principal security analysis
- `Invoke-EntraAppAccess.ps1` - Critical administrative app access check
- `Invoke-EntraConditionalAccessCheck.ps1` - Conditional Access policy audit

## References

- [Microsoft: Understanding consent grant attacks](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants)
- [Azure AD OAuth 2.0 consent framework](https://docs.microsoft.com/en-us/azure/active-directory/develop/consent-framework)
- [MITRE ATT&CK: Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK: Application Access Token (T1550.001)](https://attack.mitre.org/techniques/T1550/001/)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
