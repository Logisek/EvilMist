# Invoke-EntraExchangeCheck.ps1

## Overview

`Invoke-EntraExchangeCheck.ps1` is a PowerShell script that detects mail-based attack vectors and data exfiltration risks in Exchange Online. It provides comprehensive visibility into inbox rules, forwarding configurations, mailbox delegations, and transport rules that could be exploited for data theft or business email compromise (BEC).

## Purpose

This script performs a comprehensive audit of Exchange Online security to identify potential security risks, including:

- **Inbox rules forwarding to external addresses** - Primary data exfiltration vector in BEC attacks
- **Transport rules (mail flow rules) analysis** - Organization-wide mail routing that could expose data
- **Auto-forwarding settings** - SMTP-level forwarding configured on mailboxes
- **Mailbox delegation and permissions** - Full Access, Send-As, and Send-On-Behalf permissions
- **Mailbox audit logging status** - Detection capability for forensic investigations
- **OWA (Outlook Web App) policies** - Web access security configurations
- **Client access rules** - Legacy access control policies

## Attack Scenario Context

### Business Email Compromise (BEC) Attack

1. Attacker compromises user credentials (phishing, credential stuffing)
2. Attacker creates inbox rules to:
   - Forward copies of emails to external address
   - Delete security notifications
   - Move emails to hidden folders
3. Attacker monitors email for payment/financial information
4. Attacker impersonates user to request wire transfers

### Persistent Access via Forwarding

1. Attacker gains initial access to mailbox
2. Configures SMTP forwarding or inbox rule forwarding
3. Continues receiving all emails even after password reset
4. Uses forwarded emails for reconnaissance or further attacks

### Red Team Value

- Identify existing forwarding rules for reconnaissance
- Find mailboxes with external forwarding for data exfiltration
- Discover delegations that could be leveraged for lateral movement
- Locate mailboxes without audit logging for stealthy access

### Blue Team Value

- Audit all inbox rules for suspicious patterns
- Identify unauthorized external forwarding
- Detect potential BEC attack indicators
- Verify mailbox audit logging is enabled
- Review delegations for least-privilege compliance

## Prerequisites

- PowerShell 7.0 or later
- ExchangeOnlineManagement PowerShell module (automatically installed if missing)
- Appropriate permissions:
  - Exchange Administrator or Global Administrator role
  - Or Compliance Administrator with Mail Flow permissions
  - Recipient Management role for mailbox enumeration

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
| `-OnlyExternalForwarding` | Switch | False | Show only mailboxes with external forwarding |
| `-OnlyHighRisk` | Switch | False | Show only HIGH and CRITICAL risk findings |
| `-OnlySuspiciousRules` | Switch | False | Show only suspicious inbox rules |
| `-OnlyNoAudit` | Switch | False | Show only mailboxes without audit logging |
| `-IncludeTransportRules` | Switch | False | Include transport (mail flow) rules analysis |
| `-IncludeClientAccess` | Switch | False | Include client access rules analysis |
| `-IncludeOWAPolicies` | Switch | False | Include OWA policies analysis |
| `-Matrix` | Switch | False | Display results in matrix/table format |

## Usage Examples

### Basic Scan

```powershell
# Enumerate all Exchange security configurations
.\Invoke-EntraExchangeCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\Invoke-EntraExchangeCheck.ps1 -ExportPath "exchange-security.csv"

# Export to JSON
.\Invoke-EntraExchangeCheck.ps1 -ExportPath "exchange-security.json"
```

### Filtered Scans

```powershell
# Show only mailboxes with external forwarding in matrix format
.\Invoke-EntraExchangeCheck.ps1 -OnlyExternalForwarding -Matrix

# Show only suspicious inbox rules
.\Invoke-EntraExchangeCheck.ps1 -OnlySuspiciousRules

# Show only high-risk findings
.\Invoke-EntraExchangeCheck.ps1 -OnlyHighRisk -Matrix

# Show mailboxes without audit logging
.\Invoke-EntraExchangeCheck.ps1 -OnlyNoAudit
```

### Comprehensive Scan

```powershell
# Include transport rules, OWA policies, and client access rules
.\Invoke-EntraExchangeCheck.ps1 -IncludeTransportRules -IncludeOWAPolicies -IncludeClientAccess -Matrix

# Full scan with export
.\Invoke-EntraExchangeCheck.ps1 -IncludeTransportRules -IncludeOWAPolicies -ExportPath "full-audit.csv"
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraExchangeCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraExchangeCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraExchangeCheck -Matrix

# With export
.\Invoke-EvilMist.ps1 -Script EntraExchangeCheck -ExportPath "results.csv" -OnlyExternalForwarding
```

## Risk Levels

The script categorizes findings into four risk levels:

### CRITICAL

- External SMTP forwarding configured on mailbox
- Inbox rules forwarding to external addresses
- Transport rules sending copies to external addresses

### HIGH

- Inbox rules deleting messages (hiding activity)
- Rules applying to ALL messages with forwarding
- External delegations (non-tenant users with access)
- Transport rules bypassing spam filters

### MEDIUM

- Internal forwarding configured
- Mailbox audit logging disabled
- Inbox rules with suspicious keywords
- Rules moving emails to hidden folders

### LOW

- Standard delegations to internal users
- Basic inbox rules without forwarding
- Enabled audit logging

## Suspicious Indicators

### Inbox Rule Indicators

| Indicator | Risk Description |
|-----------|------------------|
| ForwardTo external address | Data exfiltration - copies sent externally |
| RedirectTo external address | Data exfiltration - emails redirected externally |
| DeleteMessage enabled | Hiding activity - security notifications deleted |
| No conditions (applies to all) | Broad scope - all emails affected |
| Suspicious keywords in name | BEC patterns - invoice, payment, wire, transfer |
| MoveToFolder (RSS, Archive, Junk) | Hiding emails in obscure folders |

### Transport Rule Indicators

| Indicator | Risk Description |
|-----------|------------------|
| BlindCopyTo external | Organization-wide data exfiltration |
| RedirectMessageTo external | Mail flow hijacking |
| DeleteMessage | Message suppression |
| SetSCL -1 | Bypass spam filtering |
| No conditions | Applies to all mail flow |

## Output Fields

### Mailbox Summary

| Field | Description |
|-------|-------------|
| DisplayName | Mailbox display name |
| UserPrincipalName | User's UPN (email) |
| PrimarySmtpAddress | Primary SMTP address |
| MailboxType | Type (UserMailbox, SharedMailbox, etc.) |
| HasForwarding | Whether forwarding is configured |
| ForwardingAddress | Internal forwarding address |
| ForwardingSmtpAddress | External SMTP forwarding address |
| IsExternalForwarding | Whether forwarding is external |
| AuditEnabled | Whether audit logging is enabled |
| TotalInboxRules | Number of inbox rules |
| SuspiciousRules | Number of suspicious rules |
| ExternalForwardingRules | Number of rules forwarding externally |
| TotalDelegations | Number of delegations |
| ExternalDelegations | Number of external delegations |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |
| RiskReasons | List of reasons for risk level |

### Inbox Rule Details

| Field | Description |
|-------|-------------|
| MailboxIdentity | Mailbox identifier |
| RuleName | Inbox rule name |
| RuleEnabled | Whether rule is enabled |
| IsSuspicious | Whether rule is flagged as suspicious |
| SuspiciousReasons | Reasons for suspicious flag |
| HasExternalForwarding | Whether rule forwards externally |
| ExternalTargets | External email addresses |
| Actions | Rule actions (Forward, Redirect, Delete, etc.) |
| Conditions | Rule conditions |
| HasNoConditions | Whether rule applies to all messages |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |

## Sample Output

### Standard Output

```
[CRITICAL] user@company.com
  Display Name: John Doe
  Mailbox Type: UserMailbox
  [!] EXTERNAL Forwarding: attacker@malicious.com
  Deliver to Mailbox AND Forward: True
  Audit Logging: Enabled
  Inbox Rules: 3 (Suspicious: 2, External Forwarding: 1)
  Delegations: 1 (External: 0)
  Risk Reasons: External SMTP forwarding configured; 1 rule(s) forward externally
```

### Matrix Output

```
================================================================================
MATRIX VIEW - EXCHANGE ONLINE SECURITY AUDIT
================================================================================

[MAILBOX SUMMARY]
--------------------------------------------------------------------------------
Risk      Type          User                           ExtFwd  Rules  Suspicious  Audit
----      ----          ----                           ------  -----  ----------  -----
CRITICAL  UserMailbox   user@company.com               YES     3      2           ON
HIGH      UserMailbox   admin@company.com              -       5      1           OFF
MEDIUM    SharedMailbox finance@company.com            -       2      0           ON
LOW       UserMailbox   employee@company.com           -       1      0           ON

[SUSPICIOUS INBOX RULES]
--------------------------------------------------------------------------------
Risk      Mailbox                   Rule Name              ExtFwd  External Targets
----      -------                   ---------              ------  ----------------
CRITICAL  user@company.com          Forward All            YES     attacker@malicious.com
HIGH      admin@company.com         Clean Notifications    -       -

================================================================================

[SUMMARY]
Total mailboxes scanned: 150
Mailboxes with findings: 4
  - CRITICAL risk: 1
  - HIGH risk: 1
  - MEDIUM risk: 1

[FORWARDING ANALYSIS]
  Mailboxes with external SMTP forwarding: 1
  Mailboxes with external forwarding rules: 1

[AUDIT LOGGING]
  Mailboxes without audit logging: 1

[INBOX RULES]
  Total inbox rules scanned: 45
  Suspicious rules: 3
  Rules forwarding externally: 2
```

## Remediation Recommendations

### For CRITICAL/HIGH Risk Findings

1. **External Forwarding**
   - Immediately remove external SMTP forwarding
   - Delete inbox rules forwarding to external addresses
   - Review sign-in logs for unauthorized access
   - Reset user credentials if compromise suspected

2. **Suspicious Inbox Rules**
   - Review and delete unauthorized rules
   - Check rule creation timestamps vs sign-in history
   - Look for other indicators of compromise

3. **Disabled Audit Logging**
   - Enable mailbox audit logging
   - Consider unified audit log for organization-wide visibility

### Preventive Measures

1. **Block Auto-Forwarding**
   ```powershell
   # Create transport rule to block external auto-forwarding
   New-TransportRule -Name "Block External Forwarding" `
       -SentToScope NotInOrganization `
       -MessageTypeMatches AutoForward `
       -RejectMessageEnhancedStatusCode 5.7.1 `
       -RejectMessageReasonText "External auto-forwarding is blocked"
   ```

2. **Enable Audit Logging by Default**
   ```powershell
   # Enable audit logging for all mailboxes
   Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true
   ```

3. **Conditional Access Policies**
   - Require MFA for Exchange Online access
   - Block legacy authentication protocols
   - Implement session controls

4. **Regular Audits**
   - Schedule periodic inbox rule reviews
   - Monitor for new external forwarding configurations
   - Alert on suspicious transport rule changes

## Related Scripts

- `Invoke-EntraConditionalAccessCheck.ps1` - Conditional Access policy audit
- `Invoke-EntraSignInRiskCheck.ps1` - Identity Protection and risky sign-ins
- `Invoke-EntraMFACheck.ps1` - MFA status analysis
- `Invoke-EntraOAuthConsentCheck.ps1` - OAuth consent grant audit

## References

- [Microsoft: Detect and Remediate Illicit Consent Grants](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants)
- [Microsoft: Block auto-forwarding with transport rules](https://docs.microsoft.com/en-us/exchange/policy-and-compliance/mail-flow-rules/mail-flow-rules)
- [MITRE ATT&CK: Email Forwarding Rule (T1114.003)](https://attack.mitre.org/techniques/T1114/003/)
- [MITRE ATT&CK: Email Collection (T1114)](https://attack.mitre.org/techniques/T1114/)
- [Microsoft: Mailbox audit logging in Exchange Online](https://docs.microsoft.com/en-us/exchange/policy-and-compliance/mailbox-audit-logging)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
