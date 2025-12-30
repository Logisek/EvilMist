# entra_recon.py - Documentation

A comprehensive Python script for Azure Entra ID user enumeration and security assessment, designed for cloud penetration testing and red team operations.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Features](#features)
- [Authentication Methods](#authentication-methods)
- [Usage Examples](#usage-examples)
- [Menu Options Reference](#menu-options-reference)
- [Stealth Configuration](#stealth-configuration)

---

## Overview

`entra_recon.py` is part of the EvilMist toolkit. It provides extensive enumeration capabilities for Azure Entra ID (formerly Azure Active Directory) environments using Python and the Microsoft Graph API. The script is designed to work in restricted environments where direct user enumeration may be blocked, offering 15+ fallback methods to discover users.

**Key Capabilities:**
- Multiple user enumeration methods with automatic fallback
- Security assessment and misconfiguration detection
- Attack path analysis
- Credential attack surface mapping
- BloodHound/AzureHound compatible export
- Stealth mode with configurable delays and jitter
- Cross-platform compatibility (Windows, Linux, macOS)
- No app secrets required - uses public client authentication

---

## Requirements

- **Python 3.8+**
- Required packages (install via pip):
  - `msal` - Microsoft Authentication Library
  - `requests` - HTTP library
- Optional packages:
  - `azure-identity` - Additional authentication methods (DefaultAzureCredential, etc.)

---

## Installation

1. Clone or download the EvilMist repository
2. Install required dependencies:

```bash
# Install required packages
pip install -r requirements.txt

# Or install manually
pip install msal requests

# Optional: Install azure-identity for additional auth methods
pip install azure-identity
```

3. (Optional) Download Microsoft Apps database for extended App ID support:

```bash
# The script will prompt to download this on first run
# Or download manually from:
# https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json
```

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
| Power Automate Flows | CRITICAL | Flows with sensitive connectors (SQL, HTTP, Key Vault, etc.) |

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

The script supports 11 authentication methods:

| # | Method | Description |
|---|--------|-------------|
| 1 | Interactive Browser | Opens browser for OAuth login |
| 2 | Device Code Flow | Code-based auth for headless environments |
| 3 | Auto-detect | Automatically tries all cached credential methods |
| 4 | Azure CLI Token | Uses cached `az login` token |
| 5 | Azure PowerShell Token | Uses cached `Connect-AzAccount` token |
| 6 | Shared Token Cache | Windows cached credentials |
| 7 | VS Code Credential | Azure extension cached token |
| 8 | Managed Identity | For Azure-hosted environments |
| 9 | Environment Variable | `GRAPH_ACCESS_TOKEN`, `AZURE_ACCESS_TOKEN`, or `ACCESS_TOKEN` |
| 10 | Manual Token Input | Paste a token directly |
| 11 | Refresh Token Exchange | Use tokens from ROADtools, TokenTactics, etc. |

### Pre-configured App IDs

The script comes with 10 pre-configured Microsoft first-party App IDs commonly pre-consented in tenants:

- Microsoft Graph PowerShell
- Graph Explorer
- Microsoft Office
- Microsoft Teams
- Azure CLI
- Azure PowerShell
- Office 365 Exchange Online
- Office 365 SharePoint Online
- Azure Portal
- Microsoft Intune

You can also use the extended Microsoft Apps database (4000+ App IDs) or provide a custom App ID.

---

## Usage Examples

### Basic Usage

```bash
# Run in interactive mode
python scripts\python\entra_recon.py
```

### Authentication Examples

```bash
# The script will prompt for authentication method selection
# Choose from 11 available methods

# Example flow:
# 1. Run script
# 2. Select authentication method (1-11)
# 3. For browser/device code: select App ID
# 4. Complete authentication
# 5. Use interactive menu
```

### Using Environment Variables

```bash
# Set access token via environment variable
export GRAPH_ACCESS_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGc..."

# Or
export AZURE_ACCESS_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGc..."

# Run script and select option 9 (Environment Variable)
python scripts\python\entra_recon.py
```

### Using Refresh Tokens

```bash
# Useful for tokens obtained from other tools
# Example with ROADtools or TokenTactics output

python scripts\python\entra_recon.py
# Select option 11 (Refresh Token Exchange)
# Paste the refresh token when prompted
# Specify tenant ID (or press Enter for 'common')
```

### Programmatic Token Reuse

```python
# If you have a token from another source
import os
os.environ['GRAPH_ACCESS_TOKEN'] = 'your-token-here'

# Then run the script and select option 9
```

---

## Stealth Configuration

The Python script includes a dedicated stealth configuration menu (option 98):

### Stealth Settings

| Setting | Range | Default | Description |
|---------|-------|---------|-------------|
| Enabled | On/Off | Off | Master switch for stealth mode |
| Base Delay | 0-60s | 0 | Fixed delay between requests |
| Jitter | 0-30s | 0 | Random variance added to delay |
| Max Retries | 1-10 | 3 | Retries on 429 throttling |
| Quiet Mode | On/Off | Off | Suppress stealth status messages |

### Stealth Presets

| Preset | Delay | Jitter | Retries | Quiet |
|--------|-------|--------|---------|-------|
| Aggressive | 0.1s | 0.05s | 2 | On |
| Balanced | 0.5s | 0.3s | 3 | Off |
| Paranoid | 2.0s | 1.5s | 5 | Off |

### Stealth Menu Options

```
1. Toggle stealth mode
2. Set base delay
3. Set jitter range
4. Set max retries
5. Toggle quiet mode
6. Reset to defaults
7. Apply AGGRESSIVE preset
8. Apply BALANCED preset
9. Apply PARANOID preset
0. Back to main menu
```

---

## Menu Options Reference

### Enumeration Options (1-18)
| Option | Description |
|--------|-------------|
| 1 | Direct /users endpoint |
| 2 | Search users by name |
| 3 | Basic alternatives (People API, Groups, Manager chain) |
| 4 | Advanced fallbacks (Calendar, Email, Teams, etc.) |
| 5 | FULL enumeration - ALL methods |
| 6-18 | Individual enumeration methods |
| 19 | Export users to file |

### Security Assessment (20-26)
| Option | Description |
|--------|-------------|
| 20 | [HIGH] MFA Status Check |
| 21 | [HIGH] Privileged Role Enumeration |
| 22 | [HIGH] Applications & Service Principals |
| 23 | [MED] Stale Accounts (no recent login) |
| 24 | [MED] Guest/External Users |
| 25 | [MED] Password Never Expires |
| 26 | Full Security Assessment (all above) |

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
| 33 | [HIGH] CA Policy Exclusions (Security Gaps) |
| 34 | [HIGH] MFA Enforcement Gaps |
| 35 | Full CA Analysis (all above) |

### Device & Intune (36-43)
| Option | Description |
|--------|-------------|
| 36 | [MED] All Registered Devices |
| 37 | [HIGH] Non-Compliant Devices |
| 38 | [MED] BYOD/Personal Devices |
| 39 | [MED] Devices per User |
| 40 | [HIGH] Intune Managed Devices |
| 41 | [HIGH] Intune Compliance Policies |
| 42 | [MED] Intune Configuration Profiles |
| 43 | [HIGH] Intune Device Administrators |

### Administrative & Licensing (44-50)
| Option | Description |
|--------|-------------|
| 44 | [MED] List Administrative Units |
| 45 | [HIGH] Scoped Role Assignments (AU Admins) |
| 46 | [MED] Tenant License SKUs |
| 47 | [HIGH] User License Assignments |
| 48 | [HIGH] E5/P2 Privileged Users (PIM/Defender access) |
| 49 | [MED] On-Prem Synced vs Cloud-Only Users |
| 50 | [HIGH] Directory Sync Errors |

### Attack Path & Lateral Movement (51-60)
| Option | Description |
|--------|-------------|
| 51 | [CRIT] Full Attack Path Analysis |
| 52 | [HIGH] Password Reset Delegations |
| 53 | [HIGH] Privileged Group Owners |
| 54 | [HIGH] Group Membership Privileges |
| 55 | [HIGH] Power Apps Enumeration (Owners/Users) |
| 56 | [CRIT] Power Automate Flows (Sensitive Connectors) |
| 57 | [CRIT] Full Lateral Movement Analysis |
| 58 | [HIGH] Transitive Group Memberships (Group Nesting) |
| 59 | [HIGH] Shared Mailbox Access |
| 60 | [HIGH] Calendar/Mailbox Delegations |

### Export & Reports (61-62)
| Option | Description |
|--------|-------------|
| 61 | [CRIT] Export to BloodHound/AzureHound Format |
| 62 | [NEW] Generate Interactive HTML Report |

### System Options
| Option | Description |
|--------|-------------|
| 98 | Configure stealth settings |
| 99 | Change authentication method |
| 0 | Exit |

---

## Sensitive Connector Detection

The Power Automate flow analysis (option 56) detects the following high-risk connectors:

### Critical Risk
- Azure Active Directory
- Azure Key Vault
- HTTP (custom web requests)

### High Risk
- SQL Server / Azure SQL Database
- Cosmos DB
- Azure Blob Storage
- Amazon S3 / Google Cloud Storage
- SharePoint Online
- OneDrive for Business
- FTP / SFTP
- SendGrid / SMTP
- HTTP with Azure AD
- Azure Functions
- Azure Automation
- Azure DevOps / GitHub
- Dataverse / Dynamics 365
- Salesforce
- ServiceNow
- Custom Connectors

### Medium Risk
- Azure Table Storage
- Azure File Storage
- Office 365 Outlook
- Microsoft Teams
- Excel Online
- Azure Logic Apps
- Twilio SMS
- Slack

---

## Troubleshooting

### Common Issues

**Authentication fails with "AADSTS..."**
- Try a different App ID (some are blocked per-tenant)
- Use device code flow if browser auth fails
- Check if Conditional Access is blocking the app

**Access denied errors**
- Verify required permissions are consented
- Try enumeration methods that require lower privileges
- Use the auto-fallback enumeration (option 5)

**Throttling (429 errors)**
- Enable stealth mode with appropriate delays
- Use the "Paranoid" preset for heavily monitored environments
- The script automatically handles retries with backoff

**Import errors**
```bash
# Ensure all dependencies are installed
pip install msal requests azure-identity
```

---

## Security Considerations

- This tool is intended for authorized penetration testing and security assessments only
- Always obtain proper authorization before running against any environment
- The tool may generate significant API traffic that could be logged and monitored
- Use stealth mode in sensitive environments to reduce detection risk
- Tokens and credentials should be handled securely

---

## License

GNU General Public License v3.0 - See LICENSE file for details.

**Copyright (C) 2025 Logisek**

