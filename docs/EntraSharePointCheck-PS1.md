# Invoke-EntraSharePointCheck.ps1

## Overview

`Invoke-EntraSharePointCheck.ps1` is a PowerShell script that audits SharePoint Online sharing settings to identify oversharing and external access risks. It provides comprehensive visibility into tenant-level and site-level sharing configurations that could expose sensitive data to unauthorized external parties.

## Purpose

This script performs a comprehensive audit of SharePoint Online security to identify potential data exposure and oversharing risks, including:

- **Tenant-level external sharing settings** - Organization-wide sharing policies
- **Anonymous link policies and expiration** - "Anyone" link configurations
- **Site-level sharing overrides** - Sites with more permissive settings than tenant
- **Guest access to sensitive sites** - External user access to team sites
- **OneDrive external sharing configuration** - Personal storage sharing settings
- **Sensitivity label coverage gaps** - Sites without data classification
- **Default link types and permissions** - Default sharing behavior analysis

## Attack Scenario Context

### Data Exfiltration via Oversharing

1. Attacker compromises user credentials
2. User has access to SharePoint sites with external sharing enabled
3. Attacker creates anonymous links to sensitive documents
4. Links are shared externally for data exfiltration
5. No audit trail of who accessed the anonymous links

### Anonymous Link Abuse

1. Organization allows "Anyone" links at tenant or site level
2. Users create anonymous links for convenience
3. Links are shared beyond intended recipients
4. Sensitive documents become publicly accessible
5. No expiration = indefinite exposure

### Guest Access Persistence

1. External collaborator invited to SharePoint site
2. Collaboration ends but guest access not revoked
3. Guest retains access to all shared content
4. Former partner/contractor maintains visibility into sensitive data

### Red Team Value

- Identify sites with anonymous sharing for data exfiltration
- Find sites with permissive overrides for targeting
- Discover OneDrive locations with external sharing
- Locate sensitive team sites accessible to guests

### Blue Team Value

- Audit sharing configurations across all sites
- Identify sites more permissive than tenant policy
- Detect missing sensitivity labels on shared content
- Review anonymous link policies and expiration
- Ensure compliance with data governance policies

## Prerequisites

- PowerShell 7.0 or later
- PnP.PowerShell module (automatically installed if missing)
- Appropriate permissions:
  - SharePoint Administrator or Global Administrator role
  - Or delegated admin permissions for SharePoint Online

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ExportPath` | String | None | Path to export results (CSV or JSON based on extension) |
| `-TenantId` | String | None | Optional Tenant ID. Uses user's home tenant if not specified |
| `-AdminUrl` | String | None | SharePoint Admin URL (e.g., https://contoso-admin.sharepoint.com) |
| `-UseAzCliToken` | Switch | False | Use Azure CLI cached token for authentication |
| `-UseAzPowerShellToken` | Switch | False | Use Azure PowerShell cached token for authentication |
| `-EnableStealth` | Switch | False | Enable stealth mode with default delays and jitter |
| `-RequestDelay` | Double | 0 | Base delay in seconds between API requests (0-60) |
| `-RequestJitter` | Double | 0 | Random jitter range in seconds to add/subtract from delay (0-30) |
| `-MaxRetries` | Int | 3 | Maximum retries on throttling (429) responses (1-10) |
| `-QuietStealth` | Switch | False | Suppress stealth-related status messages |
| `-OnlyExternalSharing` | Switch | False | Show only sites with external sharing enabled |
| `-OnlyHighRisk` | Switch | False | Show only HIGH and CRITICAL risk findings |
| `-OnlyAnonymousLinks` | Switch | False | Show only sites that allow anonymous links |
| `-OnlyPermissiveOverrides` | Switch | False | Show only sites with sharing more permissive than tenant |
| `-IncludeSensitivityLabels` | Switch | False | Include sensitivity label configuration analysis |
| `-IncludeOneDrive` | Switch | False | Include OneDrive for Business sharing analysis |
| `-IncludeLinkSettings` | Switch | False | Include detailed default link type and permission analysis |
| `-Matrix` | Switch | False | Display results in matrix/table format |

## Usage Examples

### Basic Scan

```powershell
# Enumerate all SharePoint sharing configurations
.\Invoke-EntraSharePointCheck.ps1

# With specific Admin URL
.\Invoke-EntraSharePointCheck.ps1 -AdminUrl "https://contoso-admin.sharepoint.com"
```

### Export Results

```powershell
# Export to CSV
.\Invoke-EntraSharePointCheck.ps1 -ExportPath "sharepoint-security.csv"

# Export to JSON
.\Invoke-EntraSharePointCheck.ps1 -ExportPath "sharepoint-security.json"
```

### Filtered Scans

```powershell
# Show only sites allowing anonymous links in matrix format
.\Invoke-EntraSharePointCheck.ps1 -OnlyAnonymousLinks -Matrix

# Show only sites with permissive overrides
.\Invoke-EntraSharePointCheck.ps1 -OnlyPermissiveOverrides -Matrix

# Show only high-risk findings
.\Invoke-EntraSharePointCheck.ps1 -OnlyHighRisk -Matrix

# Show only sites with external sharing
.\Invoke-EntraSharePointCheck.ps1 -OnlyExternalSharing
```

### Comprehensive Scan

```powershell
# Include OneDrive and sensitivity label analysis
.\Invoke-EntraSharePointCheck.ps1 -IncludeOneDrive -IncludeSensitivityLabels -Matrix

# Full scan with export
.\Invoke-EntraSharePointCheck.ps1 -IncludeOneDrive -IncludeSensitivityLabels -ExportPath "full-audit.csv"
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraSharePointCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraSharePointCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraSharePointCheck -Matrix

# With export
.\Invoke-EvilMist.ps1 -Script EntraSharePointCheck -ExportPath "results.csv" -OnlyAnonymousLinks
```

## Risk Levels

The script categorizes findings into four risk levels:

### CRITICAL

- Site has sharing settings more permissive than tenant default
- Anonymous links allowed on sensitive team sites
- OneDrive with permissive override

### HIGH

- Anonymous links (Anyone) allowed at site level
- Team site with external guest sharing
- No sensitivity label with anonymous sharing enabled

### MEDIUM

- External guest sharing enabled (new and existing guests)
- No sensitivity label on sites with sharing
- Default link type is Anonymous

### LOW

- External sharing limited to existing guests only
- External sharing disabled
- Sensitivity labels properly applied

## Sharing Capability Levels

| Level | Description | Risk |
|-------|-------------|------|
| `Disabled` | No external sharing allowed | LOW |
| `ExistingExternalUserSharingOnly` | Only existing guests can access | LOW |
| `ExternalUserSharingOnly` | New and existing guests (no anonymous) | MEDIUM |
| `ExternalUserAndGuestSharing` | Anyone links (anonymous access) | HIGH |

## Output Fields

### Tenant Settings

| Field | Description |
|-------|-------------|
| SharingCapability | Tenant-level sharing setting |
| DefaultSharingLinkType | Default link type for new shares |
| DefaultLinkPermission | Default permission level (View/Edit) |
| RequireAnonymousLinksExpireInDays | Anonymous link expiration policy |
| OneDriveSharingCapability | OneDrive sharing policy |
| SharingDomainRestrictionMode | Domain allow/block list mode |
| ExternalUserExpirationRequired | Guest access expiration setting |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |

### Site Details

| Field | Description |
|-------|-------------|
| SiteUrl | Site collection URL |
| SiteTitle | Site display name |
| SiteTemplate | SharePoint template type |
| SharingCapability | Site-level sharing setting |
| IsMorePermissiveThanTenant | Whether site overrides tenant |
| DefaultSharingLinkType | Site default link type |
| HasSensitivityLabel | Whether sensitivity label is applied |
| SensitivityLabel | Applied sensitivity label name |
| IsGroupConnected | Whether connected to Microsoft 365 Group |
| DisableSharingForNonOwners | Whether only owners can share |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |
| RiskReasons | List of reasons for risk level |

## Sample Output

### Standard Output

```
[TENANT SHARING SETTINGS]
  Sharing Capability: Anyone (anonymous links)
  Default Link Type: Organization only
  OneDrive Sharing: New and existing guests
  Risk Level: HIGH

Total sites scanned: 45
Sites with findings: 12

--------------------------------------------------------------------------------
SITE DETAILS:
--------------------------------------------------------------------------------

[CRITICAL] Marketing Team Site
  URL: https://contoso.sharepoint.com/sites/marketing
  Sharing: Anyone (anonymous links)
  [!] MORE PERMISSIVE than tenant default
  [!] No sensitivity label applied
  Risk Reasons: Sharing more permissive than tenant default; Anonymous links allowed
```

### Matrix Output

```
================================================================================
MATRIX VIEW - SHAREPOINT ONLINE SECURITY AUDIT
================================================================================

[TENANT SHARING SETTINGS]
--------------------------------------------------------------------------------
  Sharing Capability: Anyone (anonymous links)
  Default Link Type: Organization only
  Default Link Permission: Edit
  Anonymous Link Expiration: 30 days
  OneDrive Sharing: New and existing guests
  Risk Level: HIGH
  Risk Reasons: Anonymous links (Anyone) allowed at tenant level

[SHAREPOINT SITES]
--------------------------------------------------------------------------------
Risk      Site Title                 Sharing                Override  Anonymous  Label  URL
----      ----------                 -------                --------  ---------  -----  ---
CRITICAL  Marketing Team Site        Anyone (anonymous)     YES       YES        No     https://contoso.sharepoint...
HIGH      Sales Portal               Anyone (anonymous)     -         YES        No     https://contoso.sharepoint...
MEDIUM    HR Documents               New and existing guests-         -          Yes    https://contoso.sharepoint...
LOW       IT Knowledge Base          Existing guests only   -         -          Yes    https://contoso.sharepoint...

================================================================================

[SUMMARY]
Total sites scanned: 45
Sites with findings: 12
  - CRITICAL risk: 2
  - HIGH risk: 4
  - MEDIUM risk: 6

[SHARING ANALYSIS]
  Sites allowing anonymous links: 6
  Sites with permissive overrides: 2
  Sites without sensitivity labels: 8
```

## Remediation Recommendations

### For CRITICAL/HIGH Risk Findings

1. **Permissive Overrides**
   - Review and align site sharing with tenant policy
   - Remove site-level overrides unless business justified
   - Document exceptions with business approval

2. **Anonymous Links**
   - Disable "Anyone" links where not required
   - Implement link expiration policies
   - Require sign-in for sensitive content

3. **Missing Sensitivity Labels**
   - Apply appropriate sensitivity labels
   - Enable mandatory labeling policies
   - Configure auto-labeling for sensitive content

### Preventive Measures

1. **Restrict Anonymous Sharing**
   ```powershell
   # Disable anonymous links at tenant level
   Set-PnPTenant -SharingCapability ExternalUserSharingOnly
   
   # Require anonymous links to expire
   Set-PnPTenant -RequireAnonymousLinksExpireInDays 30
   ```

2. **Implement Domain Restrictions**
   ```powershell
   # Allow sharing only with specific domains
   Set-PnPTenant -SharingDomainRestrictionMode AllowList
   Set-PnPTenant -SharingAllowedDomainList "partner.com", "vendor.com"
   ```

3. **Default Link Settings**
   ```powershell
   # Set default to organization-only links
   Set-PnPTenant -DefaultSharingLinkType Internal
   Set-PnPTenant -DefaultLinkPermission View
   ```

4. **Site-Level Controls**
   ```powershell
   # Prevent non-owners from sharing
   Set-PnPSite -Identity "https://contoso.sharepoint.com/sites/sensitive" `
       -DisableSharingForNonOwnersStatus $true
   ```

5. **Sensitivity Labels**
   - Implement Microsoft Purview sensitivity labels
   - Configure container labels for SharePoint sites
   - Enable auto-labeling for sensitive content

## Related Scripts

- `Invoke-EntraConditionalAccessCheck.ps1` - Conditional Access policy audit
- `Invoke-EntraExchangeCheck.ps1` - Exchange Online security audit
- `Invoke-EntraGroupCheck.ps1` - Group security analysis
- `Invoke-EntraOAuthConsentCheck.ps1` - OAuth consent grant audit
- `Invoke-EntraGuestCheck.ps1` - Guest account security analysis

## References

- [Microsoft: SharePoint and OneDrive sharing settings](https://docs.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off)
- [Microsoft: Manage sharing settings](https://docs.microsoft.com/en-us/sharepoint/manage-sharing)
- [Microsoft: Control access from unmanaged devices](https://docs.microsoft.com/en-us/sharepoint/control-access-from-unmanaged-devices)
- [Microsoft: Sensitivity labels for SharePoint sites](https://docs.microsoft.com/en-us/microsoft-365/compliance/sensitivity-labels-sharepoint-onedrive-files)
- [PnP PowerShell Documentation](https://pnp.github.io/powershell/)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
