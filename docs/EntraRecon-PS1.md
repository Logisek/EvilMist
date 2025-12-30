# Invoke-EntraRecon.ps1 - Documentation

A comprehensive PowerShell script for Azure Entra ID user enumeration and security assessment, designed for cloud penetration testing and red team operations.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Parameters](#parameters)
- [Features](#features)
- [Authentication Methods](#authentication-methods)
- [Usage Examples](#usage-examples)
- [Menu Options Reference](#menu-options-reference)

---

## Overview

`Invoke-EntraRecon.ps1` is part of the EvilMist toolkit. It provides extensive enumeration capabilities for Azure Entra ID (formerly Azure Active Directory) environments. The script is designed to work in restricted environments where direct user enumeration may be blocked, offering 15+ fallback methods to discover users.

**Key Capabilities:**
- Multiple user enumeration methods with automatic fallback
- Security assessment and misconfiguration detection
- Attack path analysis
- Credential attack surface mapping
- BloodHound/AzureHound compatible export
- Stealth mode with configurable delays and jitter

---

## Requirements

- **PowerShell 7+** (required)
- **Microsoft.Graph.Users** PowerShell module (auto-installed if missing)
- Valid Azure AD credentials or cached tokens
- Appropriate API permissions based on desired enumeration scope

### Minimum Permissions
- `User.Read` - Read own profile
- `User.ReadBasic.All` - Read basic user properties (recommended minimum)
- `User.Read.All` - Full user enumeration (ideal)

---

## Installation

1. Clone or download the EvilMist repository
2. Ensure PowerShell 7+ is installed
3. Run the script - it will auto-install required modules

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Run the script
.\scripts\powershell\Invoke-EntraRecon.ps1
```

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ExportPath` | String | None | Path to export results (CSV or JSON based on extension). Enables non-interactive mode. |
| `-TenantId` | String | User's home tenant | Target tenant ID for enumeration |
| `-UseAzCliToken` | Switch | False | Use cached Azure CLI token for authentication |
| `-UseAzPowerShellToken` | Switch | False | Use cached Azure PowerShell token for authentication |
| `-EnableStealth` | Switch | False | Enable stealth mode with default delays (500ms + 300ms jitter) |
| `-RequestDelay` | Double | 0 | Base delay in seconds between API requests (0-60) |
| `-RequestJitter` | Double | 0 | Random jitter range in seconds (0-30) |
| `-MaxRetries` | Int | 3 | Maximum retries on 429 throttling responses (1-10) |
| `-QuietStealth` | Switch | False | Suppress stealth-related status messages |

---

## Features

### 1. User Enumeration Methods

The script supports 15+ enumeration methods that work even when direct `/users` access is blocked:

| Method | Description | Permissions Needed |
|--------|-------------|-------------------|
| Direct /users | Standard Graph API user endpoint | User.Read.All |
| People API | Discover users from personal connections | People.Read |
| Manager Chain | Enumerate via organizational hierarchy | User.Read.All |
| Direct Reports | Find users through reporting structure | User.Read.All |
| Group Membership | Extract users from group memberships | GroupMember.Read.All |
| Microsoft Search API | Search-based discovery | Sites.Read.All |
| Calendar Attendees | Extract from meeting attendees | Calendars.Read |
| Email Recipients | Discover from email recipients | Mail.Read |
| OneDrive Sharing | Users from shared file permissions | Files.Read |
| Teams Rosters | Team and channel member enumeration | Team.ReadBasic.All |
| Planner Assignees | Users assigned to Planner tasks | Tasks.Read |
| SharePoint Profiles | User profiles from SharePoint | Sites.Read.All |
| Azure Resource Manager | Users with Azure RBAC roles | Azure RBAC |
| Meeting Rooms/Resources | Room and resource discovery | Place.Read.All |
| Yammer/Viva Engage | Community member enumeration | Yammer API |

### 2. Security Assessment

| Feature | Risk Level | Description |
|---------|------------|-------------|
| MFA Status Check | HIGH | Identify users without MFA enabled |
| Privileged Role Enumeration | HIGH | Find Global Admins, Privileged Role Admins, etc. |
| Applications & Service Principals | HIGH | Enumerate apps with credentials and high permissions |
| Stale Accounts | MEDIUM | Accounts with no recent sign-in activity |
| Guest/External Users | MEDIUM | External collaboration accounts |
| Password Never Expires | MEDIUM | Accounts exempt from password rotation |

### 3. Credential Attack Surface

| Feature | Risk Level | Description |
|---------|------------|-------------|
| Password Policies | HIGH | Per-user password policy enumeration |
| SSPR Enabled Users | HIGH | Self-Service Password Reset targets |
| Legacy Authentication | HIGH | Users with legacy auth (bypasses MFA) |
| App Passwords | HIGH | Users with app passwords (bypasses MFA) |

### 4. Conditional Access Analysis

| Feature | Risk Level | Description |
|---------|------------|-------------|
| CA Policy Enumeration | HIGH | List all Conditional Access policies |
| CA Policy Exclusions | HIGH | Identify users/groups excluded from CA policies |
| MFA Enforcement Gaps | HIGH | Find scenarios where MFA is not required |

### 5. Device Enumeration

| Feature | Risk Level | Description |
|---------|------------|-------------|
| All Registered Devices | MEDIUM | Complete device inventory |
| Non-Compliant Devices | HIGH | Devices failing compliance policies |
| BYOD/Personal Devices | MEDIUM | Unmanaged personal devices |
| Devices per User | MEDIUM | User-device associations |

### 6. Intune/Endpoint Manager

| Feature | Risk Level | Description |
|---------|------------|-------------|
| Managed Devices | HIGH | Intune-managed device inventory |
| Compliance Policies | HIGH | Policy configuration review |
| Configuration Profiles | MEDIUM | Device configuration analysis |
| Device Administrators | HIGH | Privileged Intune roles |

### 7. Administrative Units

| Feature | Risk Level | Description |
|---------|------------|-------------|
| List Administrative Units | MEDIUM | AU structure enumeration |
| Scoped Role Assignments | HIGH | AU-level admin delegations |

### 8. License Information

| Feature | Risk Level | Description |
|---------|------------|-------------|
| Tenant License SKUs | MEDIUM | Available licenses in tenant |
| User License Assignments | HIGH | Who has which licenses |
| E5/P2 Privileged Users | HIGH | Users with premium security features |

### 9. Directory Sync

| Feature | Risk Level | Description |
|---------|------------|-------------|
| Sync Status | MEDIUM | On-prem synced vs cloud-only users |
| Sync Errors | HIGH | Failed sync objects (potential attack surface) |

### 10. Attack Path Analysis

| Feature | Risk Level | Description |
|---------|------------|-------------|
| Full Attack Path Analysis | CRITICAL | Comprehensive privilege escalation paths |
| Password Reset Delegations | HIGH | Who can reset whose passwords |
| Privileged Group Owners | HIGH | Owners of privileged groups |
| Group Membership Privileges | HIGH | Group-based privilege escalation |

### 11. Power Platform

| Feature | Risk Level | Description |
|---------|------------|-------------|
| Power Apps | HIGH | App owners and users enumeration |
| Power Automate Flows | CRITICAL | Flows with sensitive connectors (SQL, HTTP, etc.) |

### 12. Lateral Movement Analysis

| Feature | Risk Level | Description |
|---------|------------|-------------|
| Full Lateral Movement | CRITICAL | Comprehensive lateral movement opportunities |
| Transitive Group Memberships | HIGH | Nested group privilege escalation |
| Shared Mailbox Access | HIGH | Shared mailbox delegations |
| Calendar/Mailbox Delegations | HIGH | Send-as, send-on-behalf permissions |

### 13. Export Capabilities

| Feature | Description |
|---------|-------------|
| BloodHound Export | Export to BloodHound/AzureHound compatible JSON |
| HTML Report | Interactive HTML security assessment report |
| CSV Export | Standard CSV format |
| JSON Export | Structured JSON output |

---

## Authentication Methods

The script supports multiple authentication methods:

1. **Interactive Browser** - Opens browser for login
2. **Device Code Flow** - Code-based authentication for headless environments
3. **Azure CLI Token** - Use cached `az login` token
4. **Azure PowerShell Token** - Use cached `Connect-AzAccount` token
5. **Microsoft Graph PowerShell** - Native Graph module authentication

---

## Usage Examples

### Basic Usage - Interactive Mode

```powershell
# Run in interactive mode
.\scripts\powershell\Invoke-EntraRecon.ps1
```

### Non-Interactive Export

```powershell
# Export all users to CSV
.\scripts\powershell\Invoke-EntraRecon.ps1 -ExportPath "users.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraRecon.ps1 -ExportPath "users.json"
```

### Use Cached Tokens

```powershell
# Use Azure CLI token
.\scripts\powershell\Invoke-EntraRecon.ps1 -UseAzCliToken

# Use Azure PowerShell token
.\scripts\powershell\Invoke-EntraRecon.ps1 -UseAzPowerShellToken
```

### Target Specific Tenant

```powershell
# Enumerate specific tenant
.\scripts\powershell\Invoke-EntraRecon.ps1 -TenantId "example.onmicrosoft.com"

# With tenant GUID
.\scripts\powershell\Invoke-EntraRecon.ps1 -TenantId "12345678-1234-1234-1234-123456789012"
```

### Stealth Mode

```powershell
# Enable stealth with defaults (500ms delay, 300ms jitter)
.\scripts\powershell\Invoke-EntraRecon.ps1 -EnableStealth

# Custom stealth settings
.\scripts\powershell\Invoke-EntraRecon.ps1 -RequestDelay 2 -RequestJitter 1

# Stealth with quiet output
.\scripts\powershell\Invoke-EntraRecon.ps1 -EnableStealth -QuietStealth
```

### Combined Examples

```powershell
# Stealth export to specific tenant
.\scripts\powershell\Invoke-EntraRecon.ps1 -TenantId "target.com" -EnableStealth -ExportPath "output.json"

# Maximum stealth configuration
.\scripts\powershell\Invoke-EntraRecon.ps1 -RequestDelay 5 -RequestJitter 2 -MaxRetries 5 -QuietStealth -ExportPath "stealth_enum.csv"
```

---

## Menu Options Reference

### Enumeration Options (1-18)
| Option | Description |
|--------|-------------|
| 1 | Direct /users endpoint |
| 2 | Search users by name |
| 3 | Basic alternatives (People, Groups, Managers) |
| 4 | Advanced fallbacks (Calendar, Email, Teams, etc.) |
| 5 | FULL enumeration - ALL methods |
| 6-18 | Individual enumeration methods |
| 19 | Export users to file |

### Security Assessment (20-26)
| Option | Description |
|--------|-------------|
| 20 | [HIGH] MFA Status Check |
| 21 | [HIGH] Privileged Role Enumeration |
| 22 | [HIGH] Applications and Service Principals |
| 23 | [MED] Stale Accounts |
| 24 | [MED] Guest/External Users |
| 25 | [MED] Password Never Expires |
| 26 | Full Security Assessment |

### Credential Attack Surface (27-31)
| Option | Description |
|--------|-------------|
| 27 | [HIGH] Password Policies per User |
| 28 | [HIGH] SSPR Enabled Users |
| 29 | [HIGH] Legacy Authentication Users |
| 30 | [HIGH] App Passwords Configured |
| 31 | Full Credential Attack Surface Assessment |

### Conditional Access (32-35)
| Option | Description |
|--------|-------------|
| 32 | [HIGH] Enumerate CA Policies |
| 33 | [HIGH] CA Policy Exclusions |
| 34 | [HIGH] MFA Enforcement Gaps |
| 35 | Full CA Analysis |

### Device & Intune (36-43)
| Option | Description |
|--------|-------------|
| 36-39 | Device enumeration options |
| 40-43 | Intune/Endpoint Manager options |

### Administrative & Licensing (44-50)
| Option | Description |
|--------|-------------|
| 44-45 | Administrative Unit enumeration |
| 46-48 | License information |
| 49-50 | Directory sync status |

### Attack Path & Lateral Movement (51-60)
| Option | Description |
|--------|-------------|
| 51-54 | Attack path analysis |
| 55-56 | Power Platform enumeration |
| 57-60 | Lateral movement analysis |

### Export & Reports (61-62)
| Option | Description |
|--------|-------------|
| 61 | [CRIT] Export to BloodHound/AzureHound Format |
| 62 | [NEW] Generate Interactive HTML Report |

### System Options
| Option | Description |
|--------|-------------|
| 99 | Change authentication method |
| 0 | Disconnect and exit |

---

## Security Considerations

- This tool is intended for authorized penetration testing and security assessments only
- Always obtain proper authorization before running against any environment
- The tool may generate significant API traffic that could be logged and monitored
- Use stealth mode in sensitive environments to reduce detection risk

---

## License

GNU General Public License v3.0 - See LICENSE file for details.

**Copyright (C) 2025 Logisek**

