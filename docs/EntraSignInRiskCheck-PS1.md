# Invoke-EntraSignInRiskCheck.ps1

## Overview

`Invoke-EntraSignInRiskCheck.ps1` is a PowerShell script that analyzes Azure AD Identity Protection signals, risky users, and suspicious sign-in patterns in Azure Entra ID. It provides comprehensive visibility into identity-based risks detected by Microsoft's threat intelligence and machine learning systems.

## Purpose

This script performs a comprehensive analysis of Azure AD Identity Protection data to identify potential security risks, including:

- **Risky user enumeration** - Lists all users flagged by Identity Protection with their risk levels and states
- **Risk level analysis** - Categorizes users by HIGH, MEDIUM, and LOW risk levels
- **Risk state tracking** - Shows whether risks are active, remediated, or dismissed
- **Risk detection analysis** - Enumerates specific risk events like impossible travel, anonymous IPs, leaked credentials
- **Pattern detection** - Identifies suspicious patterns like after-hours activity, password spray attacks, multiple risk types per user
- **Timing analysis** - Tracks weekend and after-hours suspicious activity

## Attack Scenario Context

### Identity Protection Signals

Azure AD Identity Protection detects various risk types:

1. **Real-time detections** - Evaluated at sign-in time
   - Anonymous IP address (VPN, Tor, proxies)
   - Malicious/suspicious IP address
   - Unfamiliar sign-in properties
   - Leaked credentials (real-time)

2. **Offline detections** - Calculated after sign-in
   - Impossible travel
   - Password spray attacks
   - Anomalous token usage
   - New country sign-in

### Red Team Value

- Identify users already flagged as risky (potential targets or compromised accounts)
- Discover attack patterns that have been detected (for evasion improvement)
- Find users with leaked credentials (credential stuffing targets)
- Understand detection timing (real-time vs offline)
- Identify blind spots in detection coverage

### Blue Team Value

- Audit all risky users requiring remediation
- Track risk detection trends over time
- Identify users requiring immediate action (high risk, active)
- Analyze attack patterns (password spray, impossible travel)
- Verify remediation effectiveness
- Detect potential ongoing attacks

## Prerequisites

- PowerShell 7.0 or later
- Microsoft.Graph PowerShell modules (automatically installed if missing):
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Users
- Appropriate permissions:
  - IdentityRiskyUser.Read.All (required)
  - IdentityRiskEvent.Read.All (for risk detections)
  - User.Read.All (for user details)
  - AuditLog.Read.All (for sign-in activity)
- Azure AD Premium P2 license (required for Identity Protection features)

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
| `-DaysBack` | Int | 30 | Days to look back for risky sign-ins and detections (1-365) |
| `-OnlyHighRisk` | Switch | False | Show only HIGH risk users and detections |
| `-OnlyActive` | Switch | False | Show only users with active (not remediated) risk |
| `-IncludeRiskySignIns` | Switch | False | Include detailed risky sign-in analysis |
| `-IncludeRiskDetections` | Switch | False | Include risk detection pattern analysis |
| `-Matrix` | Switch | False | Display results in matrix/table format |

## Usage Examples

### Basic Scan

```powershell
# Enumerate all risky users
.\Invoke-EntraSignInRiskCheck.ps1
```

### Export Results

```powershell
# Export to CSV (creates -users.csv and -detections.csv files)
.\Invoke-EntraSignInRiskCheck.ps1 -ExportPath "risk-analysis.csv"

# Export to JSON
.\Invoke-EntraSignInRiskCheck.ps1 -ExportPath "risk-analysis.json"
```

### Filtered Scans

```powershell
# Show only high-risk users in matrix format
.\Invoke-EntraSignInRiskCheck.ps1 -OnlyHighRisk -Matrix

# Show only active (not remediated) risks
.\Invoke-EntraSignInRiskCheck.ps1 -OnlyActive

# Include risky sign-ins from the last 7 days
.\Invoke-EntraSignInRiskCheck.ps1 -IncludeRiskySignIns -DaysBack 7

# Full analysis with pattern detection
.\Invoke-EntraSignInRiskCheck.ps1 -IncludeRiskySignIns -IncludeRiskDetections -Matrix

# High-risk active users only
.\Invoke-EntraSignInRiskCheck.ps1 -OnlyHighRisk -OnlyActive -Matrix
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraSignInRiskCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraSignInRiskCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Alternative Authentication

```powershell
# Use Azure CLI token
.\Invoke-EntraSignInRiskCheck.ps1 -UseAzCliToken

# Use Azure PowerShell token
.\Invoke-EntraSignInRiskCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\Invoke-EntraSignInRiskCheck.ps1 -TenantId "your-tenant-id"
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraSignInRiskCheck -Matrix

# With full analysis
.\Invoke-EvilMist.ps1 -Script EntraSignInRiskCheck -IncludeRiskySignIns -IncludeRiskDetections -DaysBack 14

# Export high-risk only
.\Invoke-EvilMist.ps1 -Script EntraSignInRiskCheck -OnlyHighRisk -ExportPath "high-risk.csv"
```

## Risk Levels

The script uses Azure AD Identity Protection's risk levels:

### HIGH

- Strong indicator of compromise
- Requires immediate investigation
- Examples: Leaked credentials, malicious IP, confirmed compromised

### MEDIUM

- Moderate indicator of compromise
- Should be investigated
- Examples: Unfamiliar sign-in properties, atypical travel

### LOW

- Minor indicator of potential risk
- Should be monitored
- Examples: Anonymous IP (VPN), new country

## Risk States

| State | Description | Action Required |
|-------|-------------|-----------------|
| At Risk | Active risk, not yet addressed | Yes - Investigate |
| Confirmed Compromised | Admin confirmed compromise | Yes - Remediate |
| Remediated | Risk addressed (password reset, etc.) | No |
| Dismissed | Admin dismissed as false positive | No |
| Confirmed Safe | Admin confirmed as legitimate | No |

## Risk Event Types Detected

### Critical Severity

| Event Type | Description |
|------------|-------------|
| leakedCredentials | User's credentials found in data breach |
| maliciousIPAddress | Sign-in from known malicious IP |
| adminConfirmedUserCompromised | Admin confirmed user is compromised |
| passwordSpray | Password spray attack detected |
| mcasSuspiciousInboxManipulationRules | Suspicious inbox rules (BEC indicator) |
| investigationsThreatIntelligence | Flagged by Microsoft threat intelligence |

### High Severity

| Event Type | Description |
|------------|-------------|
| anonymizedIPAddress | Sign-in from VPN/Tor/proxy |
| impossibleTravel | Sign-ins from geographically distant locations |
| suspiciousIPAddress | Sign-in from suspicious IP |
| anomalousToken | Unusual token usage pattern |
| riskyIPAddress | Sign-in from risky IP |

### Medium Severity

| Event Type | Description |
|------------|-------------|
| unfamiliarFeatures | Sign-in with unfamiliar properties |
| newCountry | Sign-in from new country/region |
| atypicalTravelPatterns | Unusual travel patterns |
| suspiciousBrowser | Suspicious browser detected |

## Output Fields

### Risky Users

| Field | Description |
|-------|-------------|
| UserPrincipalName | User's UPN |
| DisplayName | User's display name |
| UserId | User object ID |
| RiskLevel | HIGH, MEDIUM, or LOW |
| RiskState | Current risk state |
| IsActive | Whether risk is still active |
| RiskDetail | Additional risk details |
| RiskLastUpdated | When risk was last updated |
| AccountEnabled | Whether account is enabled |
| JobTitle | User's job title |
| Department | User's department |
| LastSignIn | Last sign-in date |

### Risk Detections

| Field | Description |
|-------|-------------|
| RiskEventType | Type of risk event |
| RiskEventDescription | Human-readable description |
| RiskEventSeverity | CRITICAL, HIGH, MEDIUM, LOW |
| RiskEventCategory | Category (e.g., Impossible Travel) |
| IPAddress | Source IP address |
| Location | City, Country |
| ActivityDateTime | When activity occurred |
| IsAfterHours | Activity outside business hours |
| IsWeekend | Activity on weekend |
| DetectionTimingType | realtime or offline |

## Sample Output

### Standard Output

```
[HIGH] user@company.com
  Display Name: John Smith
  Risk State: At Risk
  Risk Detail: userPerformedSecuredPasswordReset
  Risk Updated: 2024-01-15 10:30:00 (5 days ago)
  Job Title: IT Administrator
  Department: Information Technology
  Account Status: Enabled
  Last Sign-In: 2 days ago
  [!] ACTION REQUIRED: Risk is still active

[CRITICAL] impossibleTravel
  User: admin@company.com
  Description: Impossible travel (sign-ins from geographically distant locations)
  Category: Impossible Travel
  Risk Level: HIGH
  IP Address: 185.123.45.67
  Location: Moscow, Russia
  Activity Time: 2024-01-18 03:45:00 [AFTER HOURS]
  State: At Risk
```

### Matrix Output

```
================================================================================
MATRIX VIEW - IDENTITY PROTECTION RISK ANALYSIS
================================================================================

[RISKY USERS]
--------------------------------------------------------------------------------
Risk    State              Active  User Principal Name              Department
----    -----              ------  -------------------              ----------
HIGH    At Risk            Yes     admin@company.com                IT
HIGH    At Risk            Yes     finance.lead@company.com         Finance
MEDIUM  Remediated         No      user@company.com                 Sales
LOW     Dismissed          No      guest@external.com               -

[RISK DETECTIONS / RISKY SIGN-INS]
--------------------------------------------------------------------------------
Risk    Category            Event Type           User                    Location
----    --------            ----------           ----                    --------
HIGH    Impossible Travel   impossibleTravel     admin@company.com       Moscow, RU
HIGH    Anonymous Access    anonymizedIPAddress  finance.lead@co...      Unknown
MEDIUM  Credential Attack   passwordSpray        multiple-users          Various

================================================================================

[SUMMARY]
Total risky users: 4
  - HIGH risk: 2
  - MEDIUM risk: 1
  - LOW risk: 1
  - Active (not remediated): 2

Total risk detections: 15
  - HIGH/CRITICAL severity: 5
  - Active detections: 8

[TOP RISK CATEGORIES]
  Impossible Travel: 4
  Anonymous Access: 3
  Credential Attack: 2

[RISK PATTERNS DETECTED]
  Users with multiple risk types: 2
  Anonymous/VPN access attempts: 3
  Impossible travel detections: 4
  Password spray attacks: 1
  After-hours activity: 6
  Weekend activity: 2
```

## Remediation Recommendations

### For HIGH Risk / Active Users

1. **Confirm compromise status** - Review sign-in logs and activity
2. **Force password reset** - Require new password at next sign-in
3. **Revoke sessions** - Invalidate all refresh tokens
4. **Enable MFA** - If not already enabled
5. **Review permissions** - Check for unauthorized access grants
6. **Check for persistence** - Review OAuth apps, inbox rules, device registrations

### For Specific Risk Types

| Risk Type | Recommended Action |
|-----------|-------------------|
| Leaked Credentials | Force password reset, enable MFA, check for unauthorized access |
| Impossible Travel | Verify with user, check for session hijacking |
| Anonymous IP | Review if legitimate (remote worker, VPN policy) |
| Password Spray | Check for successful attacks, strengthen password policy |
| Malicious IP | Block IP, investigate for compromise |

### Preventive Measures

1. **Enable risk-based Conditional Access** - Block or require MFA for risky sign-ins
2. **Configure Identity Protection policies** - Auto-remediate high-risk users
3. **Deploy passwordless authentication** - Reduce password spray attack surface
4. **Enable continuous access evaluation** - Respond to risk in real-time
5. **Regular monitoring** - Review Identity Protection dashboard regularly

## Related Scripts

- `Invoke-EntraMFACheck.ps1` - MFA enrollment audit
- `Invoke-EntraConditionalAccessCheck.ps1` - Conditional Access policy audit
- `Invoke-EntraStaleAccountCheck.ps1` - Stale account detection
- `Invoke-EntraLegacyAuthCheck.ps1` - Legacy authentication detection
- `Invoke-EntraAttackPathCheck.ps1` - Attack path analysis

## License Requirements

Azure AD Identity Protection requires **Azure AD Premium P2** licensing. Without P2 licensing:

- Risky users may not be populated
- Risk detections will not be available
- Some risk types require additional Microsoft Defender licenses

## References

- [Azure AD Identity Protection Overview](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection)
- [Risk detection types](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks)
- [Investigate risk](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-investigate-risk)
- [MITRE ATT&CK: Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK: Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
