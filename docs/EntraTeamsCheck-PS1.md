# Invoke-EntraTeamsCheck.ps1

## Overview

`Invoke-EntraTeamsCheck.ps1` is a PowerShell script that audits Microsoft Teams collaboration security settings to identify potential risks. It provides comprehensive visibility into external access, guest policies, meeting configurations, and app permissions that could expose sensitive data or enable unauthorized collaboration.

## Purpose

This script performs a comprehensive audit of Microsoft Teams security to identify potential security risks, including:

- **External access (federation) settings** - Control who can communicate from outside the organization
- **Guest access policies** - Guest user capabilities and permissions
- **Unmanaged Teams (shadow IT)** - Teams created without governance controls
- **App permission policies** - Third-party and custom app access controls
- **Meeting policies** - Anonymous join, lobby bypass, and recording settings
- **Private channel creation policies** - Who can create private channels
- **Messaging policies** - Chat and message capabilities
- **Teams inventory** - Visibility and guest membership analysis

## Attack Scenario Context

### External Federation Abuse

1. Attacker identifies target organization allows Teams federation
2. Attacker creates malicious tenant with convincing domain
3. Attacker initiates chat with target users (phishing via Teams)
4. User trusts internal-looking Teams message over email
5. Attacker delivers malware or harvests credentials

### Guest Account Persistence

1. Attacker gains initial access to organization
2. Attacker invites external guest account they control
3. Guest account is added to sensitive Teams
4. Attacker maintains persistent access even after initial compromise remediation
5. Exfiltrates data through Teams file sharing

### Anonymous Meeting Bombing

1. Attacker discovers meeting link (shared publicly or leaked)
2. Anonymous join enabled allows immediate access
3. Attacker disrupts meeting or captures sensitive information
4. No audit trail due to anonymous participation

### Red Team Value

- Identify organizations with open federation for phishing attacks
- Find Teams with guest access for persistent access
- Discover anonymous meeting capabilities for reconnaissance
- Identify shadow IT Teams with weak governance

### Blue Team Value

- Audit external access settings for least-privilege
- Review guest capabilities and permissions
- Ensure meeting policies require authentication
- Validate app permission policies block risky apps
- Monitor for public Teams with sensitive data

## Prerequisites

- PowerShell 7.0 or later
- MicrosoftTeams PowerShell module (automatically installed if missing)
- Appropriate permissions:
  - Teams Administrator or Global Administrator role
  - Or Skype for Business Administrator for limited functionality
  - Teams communications admin for meeting policies

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
| `-OnlyHighRisk` | Switch | False | Show only HIGH and CRITICAL risk findings |
| `-OnlyExternalAccess` | Switch | False | Show only external access and federation findings |
| `-OnlyGuestAccess` | Switch | False | Show only guest access related findings |
| `-OnlyMeetingRisks` | Switch | False | Show only meeting policy risks |
| `-IncludeTeamsInventory` | Switch | False | Include full Teams inventory enumeration |
| `-IncludeAppPolicies` | Switch | False | Include Teams app permission policies analysis |
| `-IncludeMessagingPolicies` | Switch | False | Include messaging policies analysis |
| `-Matrix` | Switch | False | Display results in matrix/table format |

## Usage Examples

### Basic Scan

```powershell
# Enumerate all Teams security configurations
.\Invoke-EntraTeamsCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\Invoke-EntraTeamsCheck.ps1 -ExportPath "teams-security.csv"

# Export to JSON
.\Invoke-EntraTeamsCheck.ps1 -ExportPath "teams-security.json"
```

### Filtered Scans

```powershell
# Show only external access findings in matrix format
.\Invoke-EntraTeamsCheck.ps1 -OnlyExternalAccess -Matrix

# Show only meeting policy risks
.\Invoke-EntraTeamsCheck.ps1 -OnlyMeetingRisks -Matrix

# Show only high-risk findings
.\Invoke-EntraTeamsCheck.ps1 -OnlyHighRisk -Matrix

# Show only guest access findings
.\Invoke-EntraTeamsCheck.ps1 -OnlyGuestAccess
```

### Comprehensive Scan

```powershell
# Include Teams inventory, app policies, and messaging policies
.\Invoke-EntraTeamsCheck.ps1 -IncludeTeamsInventory -IncludeAppPolicies -IncludeMessagingPolicies -Matrix

# Full scan with export
.\Invoke-EntraTeamsCheck.ps1 -IncludeTeamsInventory -IncludeAppPolicies -ExportPath "full-audit.csv"
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraTeamsCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraTeamsCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraTeamsCheck -Matrix

# With export
.\Invoke-EvilMist.ps1 -Script EntraTeamsCheck -ExportPath "results.csv" -OnlyExternalAccess
```

## Risk Levels

The script categorizes findings into four risk levels:

### CRITICAL

- Anonymous users can START meetings
- Lobby bypass enabled with anonymous join allowed
- App sideloading enabled (arbitrary code execution)

### HIGH

- Anonymous users can join meetings
- Federation open to ALL external domains
- Teams consumer (personal accounts) access enabled
- Skype consumer access enabled
- Guests can create/delete channels

### MEDIUM

- Guest access enabled for Teams
- Lobby bypass enabled (internal users only)
- Third-party apps allowed with minimal restrictions
- Public Teams (anyone in org can join)
- Teams with guest members

### LOW

- Standard meeting policies with authentication required
- Restricted app policies
- Private Teams with owner approval

## Key Security Indicators

### External Access (Federation) Indicators

| Setting | Risk Description |
|---------|------------------|
| AllowFederatedUsers = True (no domain list) | Open federation - anyone can contact users |
| AllowTeamsConsumer = True | Personal Teams accounts can chat |
| AllowPublicUsers = True | Skype consumer accounts can communicate |
| No blocked domains | No protection against known malicious domains |

### Meeting Policy Indicators

| Setting | Risk Description |
|---------|------------------|
| AllowAnonymousUsersToJoinMeeting = True | Unauthenticated access to meetings |
| AllowAnonymousUsersToStartMeeting = True | Anonymous users can create/start meetings |
| AutoAdmittedUsers = Everyone | Lobby bypass for all participants |
| AllowPSTNUsersToBypassLobby = True | Phone callers skip lobby |
| ScreenSharingMode = EntireScreen | Full desktop sharing (data exposure) |

### Guest Access Indicators

| Setting | Risk Description |
|---------|------------------|
| AllowGuestUser = True | Guests can access Teams |
| AllowGuestCreateUpdateChannels = True | Guests can modify team structure |
| AllowGuestDeleteChannels = True | Guests can delete channels |
| AllowPrivateCalling = True | Guests can make private calls |

### App Policy Indicators

| Setting | Risk Description |
|---------|------------------|
| GlobalCatalogAppsType = BlockedAppList | Third-party apps broadly allowed |
| PrivateCatalogAppsType = BlockedAppList | Custom apps broadly allowed |
| AllowSideloading = True | Users can upload arbitrary apps |

## Output Fields

### External Access Configuration

| Field | Description |
|-------|-------------|
| AllowFederatedUsers | Whether external federation is enabled |
| AllowTeamsConsumer | Whether Teams consumer accounts allowed |
| AllowPublicUsers | Whether Skype consumer accounts allowed |
| AllowedDomains | Allowed domain list (or "All" if open) |
| BlockedDomains | Blocked domain list |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |
| RiskReasons | List of reasons for risk level |

### Meeting Policy Details

| Field | Description |
|-------|-------------|
| PolicyName | Policy identity |
| IsGlobal | Whether this is the Global (default) policy |
| AllowAnonymousUsersToJoinMeeting | Anonymous join setting |
| AllowAnonymousUsersToStartMeeting | Anonymous start setting |
| AutoAdmittedUsers | Who bypasses lobby |
| AllowCloudRecording | Recording enabled |
| ScreenSharingMode | Screen sharing scope |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |

### Teams Inventory

| Field | Description |
|-------|-------------|
| DisplayName | Team name |
| Visibility | Public or Private |
| MemberCount | Number of members |
| OwnerCount | Number of owners |
| GuestCount | Number of guest members |
| IsArchived | Whether team is archived |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |

## Sample Output

### Standard Output

```
[HIGH] TenantFederation
  Federation Enabled: True
  Teams Consumer: True
  Skype Consumer: False
  Allowed Domains: All (Open)
  Risk Reasons: Federation open to ALL external domains; Teams consumer (personal accounts) access enabled

[CRITICAL] Global
  Anonymous Join: True
  Anonymous Start: False
  Auto-Admitted: Everyone
  Recording: True
  Risk Reasons: Anonymous users can join meetings; Lobby bypass enabled with anonymous join
```

### Matrix Output

```
================================================================================
MATRIX VIEW - MICROSOFT TEAMS SECURITY AUDIT
================================================================================

[TENANT INFORMATION]
--------------------------------------------------------------------------------
  Tenant Name: Contoso
  Tenant ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

[EXTERNAL ACCESS (FEDERATION)]
--------------------------------------------------------------------------------
  [HIGH] External Access Configuration
      Federation Enabled: True
      Teams Consumer: True
      Skype Consumer: False
      Allowed Domains: All (Open)
      Risk Reasons: Federation open to ALL external domains

[MEETING POLICIES]
--------------------------------------------------------------------------------
Risk      Policy                   AnonJoin  AnonStart  LobbyBypass    Recording  Global
----      ------                   --------  ---------  -----------    ---------  ------
CRITICAL  Global                   YES       -          Everyone       ON         Yes
HIGH      AllStaff                 YES       -          EveryoneInOrg  ON         -
LOW       Executive                -         -          OrganizerOnly  ON         -

================================================================================

[SUMMARY]

[EXTERNAL ACCESS]
  CRITICAL findings: 0
  HIGH findings: 1

[MEETING POLICIES]
  Total policies: 3
  CRITICAL risk: 1
  HIGH risk: 1
  Anonymous join enabled: 2
```

## Remediation Recommendations

### For CRITICAL/HIGH Risk Findings

1. **Anonymous Meeting Access**
   - Disable anonymous join for sensitive meeting policies
   - Require authentication for all meeting participants
   - Configure lobby settings to require organizer approval

   ```powershell
   # Disable anonymous join in Global policy
   Set-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToJoinMeeting $false
   
   # Require lobby for external users
   Set-CsTeamsMeetingPolicy -Identity Global -AutoAdmittedUsers "EveryoneInCompanyExcludingGuests"
   ```

2. **External Federation**
   - Restrict federation to specific allowed domains
   - Disable Teams consumer access unless required
   - Disable Skype consumer access

   ```powershell
   # Restrict federation to specific domains
   Set-CsTenantFederationConfiguration -AllowedDomainsAsAList @{Add="partner.com","vendor.com"}
   
   # Disable consumer access
   Set-CsTenantFederationConfiguration -AllowTeamsConsumer $false -AllowPublicUsers $false
   ```

3. **Guest Access**
   - Limit guest capabilities to minimum required
   - Disable guest channel management
   - Review and remove stale guest accounts

   ```powershell
   # Restrict guest channel permissions
   Set-Team -GroupId <GroupId> -AllowGuestCreateUpdateChannels $false -AllowGuestDeleteChannels $false
   ```

4. **App Sideloading**
   - Disable app sideloading except for developers
   - Use allowed app lists instead of blocked lists

   ```powershell
   # Disable sideloading in Global policy
   Set-CsTeamsAppSetupPolicy -Identity Global -AllowSideloading $false
   ```

### Preventive Measures

1. **Meeting Security**
   - Enable meeting watermarks for sensitive content
   - Require registration for webinars
   - Use breakout rooms with organizer control

2. **External Collaboration**
   - Implement domain allow/block lists
   - Enable external access only for specific users
   - Monitor external federation activity

3. **Guest Lifecycle**
   - Implement guest access reviews
   - Set guest expiration policies
   - Monitor guest activity in audit logs

4. **App Governance**
   - Use Microsoft Defender for Cloud Apps for app visibility
   - Implement app consent workflow
   - Regular app permission audits

## Related Scripts

- `Invoke-EntraConditionalAccessCheck.ps1` - Conditional Access policy audit
- `Invoke-EntraGuestCheck.ps1` - Guest account enumeration
- `Invoke-EntraSharePointCheck.ps1` - SharePoint sharing settings (Teams files)
- `Invoke-EntraOAuthConsentCheck.ps1` - OAuth consent grant audit (Teams apps)

## References

- [Microsoft: Manage external access in Microsoft Teams](https://docs.microsoft.com/en-us/microsoftteams/manage-external-access)
- [Microsoft: Manage guest access in Microsoft Teams](https://docs.microsoft.com/en-us/microsoftteams/guest-access)
- [Microsoft: Meeting policies in Microsoft Teams](https://docs.microsoft.com/en-us/microsoftteams/meeting-policies-in-teams)
- [Microsoft: Manage app permission policies](https://docs.microsoft.com/en-us/microsoftteams/teams-app-permission-policies)
- [MITRE ATT&CK: Phishing via Service (T1566.003)](https://attack.mitre.org/techniques/T1566/003/)
- [CIS Microsoft 365 Foundations Benchmark](https://www.cisecurity.org/benchmark/microsoft_365)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
