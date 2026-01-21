# Invoke-EntraPIMCheck.ps1

## Overview

`Invoke-EntraPIMCheck.ps1` is a PowerShell script that performs a comprehensive audit of Azure AD Privileged Identity Management (PIM) configuration. PIM is critical for implementing Just-In-Time (JIT) privileged access and reducing standing administrative exposure.

## Purpose

This script analyzes PIM configuration to identify security gaps and misconfigurations, including:

- **JIT access configuration gaps** - Max activation duration, approval requirements
- **Eligible role assignments** - Users/groups eligible for privileged roles
- **Approval workflow gaps** - Missing approvers, disabled approval requirements
- **MFA and justification requirements** - Missing security controls for activation
- **Notification configuration** - Alert settings for role activations
- **Permanent vs eligible assignments** - Standing privileges vs JIT access
- **PIM for Groups** - Group-based privileged access management
- **Access Reviews** - Periodic certification of privileged access

## Attack Scenario Context

### Why PIM Configuration Matters

Poor PIM configuration can lead to:
1. **Privilege escalation** - Users activating roles without proper approval/oversight
2. **Persistence** - Long activation windows allowing extended unauthorized access
3. **Detection evasion** - Disabled notifications preventing security teams from seeing role activations
4. **Lateral movement** - Excessive eligible users increasing attack surface

### Red Team Value

- Identify roles with weak activation requirements (no MFA, no approval)
- Find permanent/standing privileged access that bypasses PIM
- Discover long activation windows for activated role abuse
- Identify eligible users who could be targeted for privilege escalation
- Find roles with no notification, making activations harder to detect

### Blue Team Value

- Audit PIM configuration against security best practices
- Ensure critical roles have proper approval workflows
- Verify MFA and justification requirements are enforced
- Confirm notification settings alert security teams
- Reduce standing privileged access through eligible assignments
- Implement Access Reviews for periodic certification

## Prerequisites

- PowerShell 7.0 or later
- Microsoft.Graph PowerShell modules (automatically installed if missing):
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.Governance
  - Microsoft.Graph.Users
  - Microsoft.Graph.Groups
  - Microsoft.Graph.Identity.DirectoryManagement
- Azure AD Premium P2 license (required for PIM)
- Appropriate permissions:
  - Directory.Read.All
  - RoleManagement.Read.Directory
  - RoleManagement.Read.All
  - PrivilegedAccess.Read.AzureAD
  - User.Read.All
  - Group.Read.All (for PIM for Groups)
  - AccessReview.Read.All (for Access Reviews)

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
| `-OnlyCritical` | Switch | False | Show only roles with CRITICAL risk findings |
| `-OnlyHighPrivilege` | Switch | False | Show only high-privilege roles |
| `-OnlyMisconfigurations` | Switch | False | Show only roles with configuration gaps |
| `-IncludeGroups` | Switch | False | Include PIM for Groups analysis |
| `-IncludeAccessReviews` | Switch | False | Include Access Reviews configuration analysis |
| `-MaxActivationHours` | Int | 8 | Maximum recommended activation duration (1-24 hours) |
| `-Matrix` | Switch | False | Display results in matrix/table format |

## Usage Examples

### Basic Scan

```powershell
# Perform comprehensive PIM configuration audit
.\Invoke-EntraPIMCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\Invoke-EntraPIMCheck.ps1 -ExportPath "pim-audit.csv"

# Export to JSON
.\Invoke-EntraPIMCheck.ps1 -ExportPath "pim-audit.json"
```

### Filtered Scans

```powershell
# Show only critical findings in matrix format
.\Invoke-EntraPIMCheck.ps1 -OnlyCritical -Matrix

# Audit high-privilege roles with strict 2-hour activation limit
.\Invoke-EntraPIMCheck.ps1 -OnlyHighPrivilege -MaxActivationHours 2

# Show only roles with misconfigurations
.\Invoke-EntraPIMCheck.ps1 -OnlyMisconfigurations -Matrix

# Include PIM for Groups and Access Reviews
.\Invoke-EntraPIMCheck.ps1 -IncludeGroups -IncludeAccessReviews
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraPIMCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraPIMCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Alternative Authentication

```powershell
# Use Azure CLI token
.\Invoke-EntraPIMCheck.ps1 -UseAzCliToken

# Use Azure PowerShell token
.\Invoke-EntraPIMCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\Invoke-EntraPIMCheck.ps1 -TenantId "your-tenant-id"
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraPIMCheck -Matrix

# With export
.\Invoke-EvilMist.ps1 -Script EntraPIMCheck -ExportPath "results.csv" -OnlyCritical
```

## Risk Levels

The script categorizes PIM configuration findings into four risk levels:

### CRITICAL

- Critical roles (Global Admin, Privileged Role Admin) with:
  - No approval required for activation
  - No MFA required for activation
  - Long activation windows (>8 hours default)
  - No approvers configured despite approval requirement

### HIGH

- High-privilege roles with weak activation requirements
- Critical roles with missing justification requirements
- High-privilege roles with excessive permanent assignments

### MEDIUM

- Missing justification requirements
- Missing notification on activation
- Long activation windows for non-critical roles
- Excessive number of eligible users for critical roles

### LOW

- Properly configured roles with all recommended controls
- Roles with minor deviations from best practices

## Critical Roles

The following roles are considered **critical** and require the strictest controls:

| Role | Description |
|------|-------------|
| Global Administrator | Full control over Azure AD and Microsoft 365 |
| Privileged Role Administrator | Can manage role assignments including PIM |
| Privileged Authentication Administrator | Can reset passwords for any user |

## High-Privilege Roles

The following roles are considered **high-privilege**:

| Role | Risk Area |
|------|-----------|
| Security Administrator | Security settings management |
| Exchange Administrator | Email system control |
| SharePoint Administrator | SharePoint/OneDrive control |
| Application Administrator | Application management |
| Cloud Application Administrator | Cloud app management |
| Hybrid Identity Administrator | Directory sync control |
| Identity Governance Administrator | Access lifecycle management |
| Intune Administrator | Device management |
| Compliance Administrator | Compliance controls |

## Recommended PIM Settings

| Setting | Recommendation | Rationale |
|---------|---------------|-----------|
| Max Activation Duration | 1-8 hours | Limits window for abuse |
| Require Approval | Yes (critical roles) | Ensures oversight |
| Require Justification | Yes (all roles) | Creates audit trail |
| Require MFA | Yes (all roles) | Prevents credential theft |
| Notification on Activation | Yes (all roles) | Enables monitoring |

## Output Fields

| Field | Description |
|-------|-------------|
| RoleId | Role definition ID |
| RoleName | Display name of the role |
| RoleDescription | Description of the role |
| IsBuiltIn | Whether role is built-in or custom |
| IsHighPrivilege | Whether role is high-privilege |
| IsCritical | Whether role is critical |
| MaxActivationDurationHours | Maximum activation window in hours |
| RequireApproval | Whether approval is required |
| ApproverCount | Number of configured approvers |
| RequireJustification | Whether justification is required |
| RequireMFA | Whether MFA is required |
| RequireTicketInfo | Whether ticket info is required |
| NotifyOnActivation | Whether notification is enabled |
| EligibleCount | Number of eligible assignments |
| ActiveCount | Number of active assignments |
| PermanentCount | Number of permanent assignments |
| Findings | List of configuration gaps |
| FindingCount | Number of findings |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |
| HasMisconfigurations | Whether role has any gaps |

## Sample Output

### Standard Output

```
[CRITICAL] PIM Gap: Global Administrator
  [!] CRITICAL ROLE - requires strictest controls
  Role ID: 62e90394-69f5-4237-9190-012177145e10
  Built-in: True
  Eligible Users: 5
  Active Assignments: 2
  Permanent Assignments: 1

  [Configuration]
  Max Activation: 8 hours (recommended: 8 hours)
  Approval Required: No
  Justification Required: No
  MFA Required: Yes
  Notification on Activation: No

  [Findings]
    - Approval is NOT required for activation
    - Justification is NOT required for activation
    - Admin notification on activation is DISABLED
    - 1 permanent (non-PIM) assignment(s) exist
    - 5 users are eligible for this critical role (recommended: 2-5 for critical roles)

  [Eligible Principals]
    - John Admin (user)
    - Jane Admin (user)
    - Break Glass Account (user)
    - Security Team (group)
    - IT Managers (group)
```

### Matrix Output

```
================================================================================
MATRIX VIEW - PIM CONFIGURATION AUDIT
================================================================================

Risk      Role                             Critical MaxHrs Approval MFA  Justify Notify Eligible Active Perm Issues
----      ----                             -------- ------ -------- ---  ------- ------ -------- ------ ---- ------
CRITICAL  Global Administrator             Yes      8      No       Yes  No      No     5        2      1    5
CRITICAL  Privileged Role Administrator    Yes      8      No       Yes  No      No     3        1      0    4
HIGH      Security Administrator           No       8      No       Yes  Yes     Yes    4        0      0    1
MEDIUM    Exchange Administrator           No       12     Yes      Yes  Yes     No     2        1      0    2
LOW       Helpdesk Administrator           No       4      Yes      Yes  Yes     Yes    8        0      0    0

================================================================================

[SUMMARY]
Total roles analyzed: 15
  - CRITICAL risk: 2
  - HIGH risk: 3
  - MEDIUM risk: 6
  - LOW risk: 4

[CONFIGURATION GAPS]
  No approval required: 5
  No MFA required: 1
  No justification required: 3
  No activation notification: 7
  Long activation window (>8h): 4

[ASSIGNMENT SUMMARY]
  Total eligible assignments: 45
  Total active assignments: 12
  Total permanent assignments: 3

[CRITICAL ROLES]
  Global Administrator: 5 eligible, 2 active, 1 permanent
  Privileged Role Administrator: 3 eligible, 1 active, 0 permanent
  Privileged Authentication Administrator: 2 eligible, 0 active, 1 permanent
```

## Remediation Recommendations

### For CRITICAL/HIGH Risk Findings

1. **Enable approval for critical roles** - Require approval for Global Admin, Privileged Role Admin
2. **Configure approvers** - Assign appropriate approvers for approval workflows
3. **Require MFA** - Ensure MFA is required for all role activations
4. **Enable justification** - Require business justification for audit trail
5. **Reduce activation window** - Set maximum activation to 1-4 hours for critical roles

### For Permanent Assignments

1. **Convert to eligible** - Migrate permanent assignments to eligible where possible
2. **Break-glass accounts** - Maintain only 2 break-glass accounts with permanent access
3. **Monitor usage** - Ensure permanent assignments are actively needed
4. **Document exceptions** - Maintain documentation for required permanent access

### For Notification Gaps

1. **Enable admin notification** - Alert security team on role activations
2. **Configure recipients** - Ensure appropriate personnel receive alerts
3. **Integrate with SIEM** - Forward PIM alerts to security monitoring

### Access Reviews

1. **Configure periodic reviews** - Quarterly reviews for critical roles
2. **Assign reviewers** - Role owners or security team as reviewers
3. **Enable auto-apply** - Automatically remove access for non-certified users

## Related Scripts

- `Invoke-EntraRoleCheck.ps1` - Privileged role assignment check
- `Invoke-EntraAttackPathCheck.ps1` - Attack path analysis for privilege escalation
- `Invoke-EntraConditionalAccessCheck.ps1` - Conditional Access policy audit
- `Invoke-EntraServicePrincipalCheck.ps1` - Service principal security analysis

## References

- [Microsoft: What is Azure AD Privileged Identity Management](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure)
- [Microsoft: PIM for Azure AD roles](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-add-role-to-user)
- [Microsoft: Configure PIM role settings](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-change-default-settings)
- [MITRE ATT&CK: Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/)
- [CIS Azure Foundations Benchmark - Identity and Access Management](https://www.cisecurity.org/benchmark/azure)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
