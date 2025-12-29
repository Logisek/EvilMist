# EvilMist

EvilMist is a collection of scripts and utilities designed to support cloud penetration testing & red teaming. The toolkit helps identify misconfigurations, assess privilege-escalation paths, and simulate attack techniques. EvilMist aims to streamline cloud-focused red-team workflows and improve the overall security posture of cloud infrastructures

---

## Tools

### Enumerate-EntraUsers

Comprehensive Azure Entra ID (Azure AD) user enumeration and security assessment tool, available in both PowerShell and Python versions.

**Key Features:**
- **15+ User Enumeration Methods** - Works even when direct `/users` access is blocked
- **Security Assessment** - MFA status, privileged roles, stale accounts, guest users
- **Credential Attack Surface** - SSPR, legacy auth, app passwords analysis
- **Conditional Access Analysis** - Policy enumeration and gap detection
- **Device & Intune Enumeration** - Managed devices, compliance policies
- **Attack Path Analysis** - Privilege escalation paths and lateral movement
- **Power Platform** - Power Apps and Power Automate flow enumeration
- **Export Options** - BloodHound/AzureHound JSON, HTML reports, CSV/JSON
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraRecon-PS1.md](EntraRecon-PS1.md) | `Invoke-EntraRecon.ps1` |
| Python | [EntraRecon-PY.md](EntraRecon-PY.md) | `entra_recon.py` |

---

### MFA Security Check

Focused security assessment tool to identify Azure Entra ID users without Multi-Factor Authentication (MFA) enabled. Includes advanced features for shared mailbox detection and sign-in activity analysis.

**Key Features:**
- **MFA Detection** - Identifies users without strong authentication methods
- **Last Sign-In Tracking** - Shows last login date/time and activity patterns
- **Shared Mailbox Detection** - Automatically identifies and filters shared mailbox accounts
- **Sign-In Capability Check** - Determines if accounts can actually authenticate
- **Risk Assessment** - Categorizes users by risk level (HIGH/MEDIUM/LOW)
- **Activity Analytics** - Sign-in statistics, department breakdowns, stale accounts
- **Matrix View** - Compact table format for quick visual scanning
- **Export Options** - CSV/JSON with comprehensive user details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraMFACheck-PS1.md](EntraMFACheck-PS1.md) | `Invoke-EntraMFACheck.ps1` |

---

### Guest Account Enumeration

Comprehensive guest account analysis tool to identify, analyze, and assess the security posture of external users in Azure Entra ID. Essential for guest access governance and security audits.

**Key Features:**
- **Guest Account Discovery** - Enumerate all guest users in the tenant
- **MFA Status Detection** - Identify guests without Multi-Factor Authentication
- **Last Sign-In Tracking** - Shows login date/time and activity patterns for guests
- **Guest Domain Extraction** - Identifies originating organizations of guest users
- **Invite Status Tracking** - Shows accepted, pending, or expired invitations
- **Risk Assessment** - Categorizes guests by risk level (HIGH/MEDIUM/LOW)
- **Activity Analytics** - Sign-in statistics, stale accounts, unused invites
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only guests without MFA or include disabled accounts
- **Export Options** - CSV/JSON with comprehensive guest details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraGuestCheck-PS1.md](EntraGuestCheck-PS1.md) | `Invoke-EntraGuestCheck.ps1` |

---

### Critical Administrative Access Check

Comprehensive security assessment tool to identify Azure Entra ID users with access to 10 critical administrative applications including PowerShell tools, management portals, core Microsoft 365 services, and privileged identity management. Essential for privileged access governance and administrative tool auditing.

**Key Features:**
- **Critical Access Discovery** - Enumerate users with administrative application access across all tiers
- **Explicit Assignment Focus** - Shows users with elevated/administrative access (not basic user access)
- **Default Access Detection** - Automatically detects and warns about apps with default access
- **Security-Focused Results** - Filters out noise from basic user access to focus on privileged users
- **Multiple Application Coverage** - Tracks 10 critical apps: Azure/AD PowerShell, Azure CLI, Graph Tools, M365/Azure Portals, Exchange/SharePoint Online, and PIM
- **MFA Status Detection** - Identify privileged users without Multi-Factor Authentication
- **Last Sign-In Tracking** - Shows login date/time and activity patterns
- **Assignment Tracking** - Shows when users were granted management access
- **Risk Assessment** - Categorizes users by risk level (HIGH/MEDIUM/LOW)
- **Activity Analytics** - Sign-in statistics, stale accounts, inactive users
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only users without MFA or include disabled accounts
- **Export Options** - CSV/JSON with comprehensive access details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraAppAccess-PS1.md](EntraAppAccess-PS1.md) | `Invoke-EntraAppAccess.ps1` |

---

## Quick Start

### Enumerate-EntraUsers (PowerShell)

**Requirements:** PowerShell 7+

```powershell
# Interactive mode
.\Invoke-EntraRecon.ps1

# With Azure CLI token
.\Invoke-EntraRecon.ps1 -UseAzCliToken

# Export all users
.\Invoke-EntraRecon.ps1 -ExportPath "users.csv"

# Stealth mode
.\Invoke-EntraRecon.ps1 -EnableStealth
```

📖 **Full documentation:** [EntraRecon-PS1.md](EntraRecon-PS1.md)

### Enumerate-EntraUsers (Python)

**Requirements:** Python 3.8+, `msal`, `requests`

```bash
# Install dependencies
pip install -r requirements.txt

# Run interactive mode
python entra_recon.py
```

📖 **Full documentation:** [EntraRecon-PY.md](EntraRecon-PY.md)

### MFA Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Scan for users without MFA
.\Invoke-EntraMFACheck.ps1

# Export results to CSV
.\Invoke-EntraMFACheck.ps1 -ExportPath "no-mfa-users.csv"

# Matrix view with all features
.\Invoke-EntraMFACheck.ps1 -Matrix -IncludeDisabledUsers

# Stealth mode
.\Invoke-EntraMFACheck.ps1 -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraMFACheck-PS1.md](EntraMFACheck-PS1.md)

### Guest Account Enumeration (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Enumerate all guest accounts
.\Invoke-EntraGuestCheck.ps1

# Export results to CSV
.\Invoke-EntraGuestCheck.ps1 -ExportPath "guest-accounts.csv"

# Show only guests without MFA in matrix view
.\Invoke-EntraGuestCheck.ps1 -Matrix -OnlyNoMFA

# Include disabled guests with stealth mode
.\Invoke-EntraGuestCheck.ps1 -IncludeDisabledGuests -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraGuestCheck-PS1.md](EntraGuestCheck-PS1.md)

### Critical Administrative Access Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check users with critical administrative access (10 apps)
.\Invoke-EntraAppAccess.ps1

# Export results to CSV
.\Invoke-EntraAppAccess.ps1 -ExportPath "app-access.csv"

# Show only users without MFA in matrix view
.\Invoke-EntraAppAccess.ps1 -Matrix -OnlyNoMFA

# Stealth mode scan
.\Invoke-EntraAppAccess.ps1 -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraAppAccess-PS1.md](EntraAppAccess-PS1.md)

### Privileged Role Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check users with privileged directory roles
.\Invoke-EntraRoleCheck.ps1

# Export results to CSV
.\Invoke-EntraRoleCheck.ps1 -ExportPath "privileged-roles.csv"

# Show only users without MFA in matrix view
.\Invoke-EntraRoleCheck.ps1 -Matrix -OnlyNoMFA

# Show only permanent (non-PIM) assignments
.\Invoke-EntraRoleCheck.ps1 -OnlyPermanent -ExportPath "permanent-admins.csv"

# Stealth mode scan
.\Invoke-EntraRoleCheck.ps1 -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraRoleCheck-PS1.md](EntraRoleCheck-PS1.md)

### Service Principal Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check all service principals and analyze security posture
.\Invoke-EntraServicePrincipalCheck.ps1

# Export results to CSV
.\Invoke-EntraServicePrincipalCheck.ps1 -ExportPath "service-principals.csv"

# Show only service principals with expired credentials in matrix view
.\Invoke-EntraServicePrincipalCheck.ps1 -Matrix -OnlyExpiredCredentials

# Show only high-permission service principals
.\Invoke-EntraServicePrincipalCheck.ps1 -OnlyHighPermission -ExportPath "high-perm-sp.csv"

# Stealth mode scan
.\Invoke-EntraServicePrincipalCheck.ps1 -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraServicePrincipalCheck-PS1.md](EntraServicePrincipalCheck-PS1.md)

**Key Features:**
- **Comprehensive Role Coverage** - Enumerates all directory roles including CRITICAL, HIGH, MEDIUM, and LOW risk roles
- **PIM Support** - Identifies both permanent (Active) and PIM-managed (Eligible/Active) role assignments
- **Assignment Tracking** - Shows assignment dates, duration, and expiration dates
- **MFA Status Detection** - Identify privileged users without Multi-Factor Authentication
- **Last Sign-In Tracking** - Shows login date/time and activity patterns
- **Risk Assessment** - Categorizes users by risk level based on role criticality and security posture
- **Activity Analytics** - Sign-in statistics, stale accounts, inactive users
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only users without MFA, only permanent assignments, or include disabled accounts
- **Export Options** - CSV/JSON with comprehensive role assignment details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraServicePrincipalCheck-PS1.md](EntraServicePrincipalCheck-PS1.md) | `Invoke-EntraServicePrincipalCheck.ps1` |

---

### Conditional Access Policy Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Analyze all Conditional Access policies
.\Invoke-EntraConditionalAccessCheck.ps1

# Export results to CSV
.\Invoke-EntraConditionalAccessCheck.ps1 -ExportPath "ca-policies.csv"

# Show only policies with exclusions in matrix view
.\Invoke-EntraConditionalAccessCheck.ps1 -Matrix -OnlyWithExclusions

# Show only policies without MFA enforcement
.\Invoke-EntraConditionalAccessCheck.ps1 -OnlyMFAgaps -ExportPath "mfa-gaps.csv"

# Stealth mode scan
.\Invoke-EntraConditionalAccessCheck.ps1 -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraConditionalAccessCheck-PS1.md](EntraConditionalAccessCheck-PS1.md)

**Key Features:**
- **Comprehensive Policy Analysis** - Enumerates all Conditional Access policies and analyzes configurations
- **Exclusion Detection** - Identifies users, groups, roles, and applications excluded from policies
- **MFA Enforcement Gaps** - Detects policies without MFA requirements
- **Critical App Coverage** - Checks if critical applications are protected by policies
- **Legacy Auth Detection** - Identifies policies targeting legacy authentication methods
- **Risk Assessment** - Categorizes policies by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on gaps and exclusions
- **Conflict Detection** - Identifies redundant or conflicting policies
- **Coverage Gap Analysis** - Highlights areas without policy protection
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only policies with exclusions, MFA gaps, or include disabled policies
- **Export Options** - CSV/JSON with comprehensive policy details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraConditionalAccessCheck-PS1.md](EntraConditionalAccessCheck-PS1.md) | `Invoke-EntraConditionalAccessCheck.ps1` |

---

## Documentation

| Document | Description |
|----------|-------------|
| [EntraRecon-PS1.md](EntraRecon-PS1.md) | Full PowerShell script documentation including all parameters, features, and usage examples |
| [EntraRecon-PY.md](EntraRecon-PY.md) | Full Python script documentation including authentication methods, stealth configuration, and examples |
| [EntraMFACheck-PS1.md](EntraMFACheck-PS1.md) | MFA Security Check documentation including shared mailbox detection, sign-in tracking, and risk assessment |
| [EntraGuestCheck-PS1.md](EntraGuestCheck-PS1.md) | Guest Account Enumeration documentation including guest domain extraction, invite tracking, and security analysis |
| [EntraAppAccess-PS1.md](EntraAppAccess-PS1.md) | PowerShell & Graph CLI Access Check documentation including app access tracking, assignment dates, and privileged access analysis |
| [EntraRoleCheck-PS1.md](EntraRoleCheck-PS1.md) | Privileged Role Check documentation including role enumeration, PIM assignment tracking, risk assessment, and security analysis |
| [EntraServicePrincipalCheck-PS1.md](EntraServicePrincipalCheck-PS1.md) | Service Principal Security Check documentation including credential enumeration, expiration tracking, permission analysis, owner security, and risk assessment |
| [EntraConditionalAccessCheck-PS1.md](EntraConditionalAccessCheck-PS1.md) | Conditional Access Policy Security Check documentation including policy enumeration, exclusion detection, MFA enforcement gaps, critical app coverage, and risk assessment |

---

## Feature Comparison

### Enumerate-EntraUsers Versions

Both versions provide the same core functionality:

| Feature | PowerShell | Python |
|---------|------------|--------|
| User Enumeration (15+ methods) | ✅ | ✅ |
| Security Assessment | ✅ | ✅ |
| Credential Attack Surface | ✅ | ✅ |
| Conditional Access Analysis | ✅ | ✅ |
| Device/Intune Enumeration | ✅ | ✅ |
| Attack Path Analysis | ✅ | ✅ |
| Power Platform Enumeration | ✅ | ✅ |
| Lateral Movement Analysis | ✅ | ✅ |
| BloodHound Export | ✅ | ✅ |
| HTML Report Generation | ✅ | ✅ |
| Stealth Mode | ✅ | ✅ |
| Interactive Menu | ✅ | ✅ |
| Azure CLI Token | ✅ | ✅ |
| Device Code Flow | ✅ | ✅ |
| Refresh Token Exchange | ❌ | ✅ |
| Extended App ID Database | ❌ | ✅ |
| Stealth Presets | ❌ | ✅ |

### Toolkit Comparison

| Feature | Enumerate-EntraUsers | MFA Security Check | Guest Account Enumeration | Critical Admin Access Check | Privileged Role Check | Service Principal Check | Conditional Access Check |
|---------|---------------------|-------------------|---------------------------|----------------------------|----------------------|------------------------|--------------------------|
| **Purpose** | Comprehensive user enumeration | Focused MFA security audit | Guest access governance | Critical administrative access audit | Privileged role assignment audit | Service account security audit | Security policy gap analysis |
| User Enumeration | 15+ methods | Standard method | Guest-focused | App assignment-based | Role assignment-based | Service principal-focused |
| MFA Detection | Basic check | Advanced with method types | Advanced with method types | Advanced with method types | Advanced with method types | Owner MFA check |
| Shared Mailbox Detection | ❌ | ✅ Automatic | ❌ (N/A for guests) | ❌ (N/A for app access) | ❌ (N/A for roles) | ❌ (N/A for SPs) |
| Guest Domain Extraction | ❌ | ❌ | ✅ Automatic | ❌ | ❌ | ❌ |
| Invite Status Tracking | ❌ | ❌ | ✅ With acceptance dates | ❌ | ❌ | ❌ |
| App Access Tracking | ❌ | ❌ | ❌ | ✅ Multi-app coverage | ❌ | ❌ |
| Role Assignment Tracking | ❌ | ❌ | ❌ | ❌ | ✅ All directory roles | ❌ |
| PIM Assignment Tracking | ❌ | ❌ | ❌ | ❌ | ✅ Eligible & Active | ❌ |
| Credential Enumeration | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Secrets & certificates |
| Credential Expiration Tracking | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Expired & expiring soon |
| Permission Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ High-risk & critical |
| Owner Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ With MFA status | ❌ |
| Assignment Date Tracking | ❌ | ❌ | ✅ Invite dates | ✅ Assignment dates | ✅ Assignment dates & duration | ❌ | ❌ |
| Policy Exclusion Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Users, groups, roles, apps |
| MFA Enforcement Gaps | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Policy-level analysis |
| Critical App Coverage | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 10 critical apps |
| Legacy Auth Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Policy targeting |
| Policy Conflict Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Redundant/conflicting |
| Last Sign-In Tracking | ✅ | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics | Limited (SP activity) | ❌ |
| Sign-In Capability Check | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Risk Level Assessment | Basic | Advanced (HIGH/MEDIUM/LOW) | Advanced (HIGH/MEDIUM/LOW) | Advanced (HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) |
| Activity Analytics | Limited | Detailed (stale/recent/never) | Detailed (stale/recent/never) | Detailed (stale/recent/never) | Detailed (stale/recent/never) | Basic (age-based) | Policy gap analysis |
| Matrix View | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Department Analysis | ✅ | ✅ With statistics | ✅ With statistics | ✅ With statistics | ✅ With statistics | ❌ | ❌ |
| BloodHound Export | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| HTML Report | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CSV/JSON Export | ✅ | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields |
| Stealth Mode | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Best For** | Red team reconnaissance | MFA compliance audits | External user security | Privileged access audit | Privileged role governance | Service account security | Security policy gap analysis |

---

## Installation

### Python Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install msal requests

# Optional: Additional authentication methods
pip install azure-identity
```

### PowerShell Dependencies

**Enumerate-EntraUsers:** The script will automatically install the required `Microsoft.Graph.Users` module on first run.

**MFA Security Check, Guest Account Enumeration, Critical Admin Access Check, Privileged Role Check, Service Principal Check, and Conditional Access Check:** Require Microsoft Graph PowerShell SDK:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

Or install individual modules:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Applications -Scope CurrentUser
```

---

## Authentication

Both scripts support multiple authentication methods:

- **Interactive Browser** - OAuth login via browser
- **Device Code Flow** - Code-based authentication for headless environments
- **Azure CLI Token** - Use cached `az login` credentials
- **Azure PowerShell Token** - Use cached `Connect-AzAccount` credentials
- **Environment Variables** - Set `GRAPH_ACCESS_TOKEN` or `AZURE_ACCESS_TOKEN`
- **Manual Token Input** - Paste a token directly

The Python version additionally supports:
- **Refresh Token Exchange** - Use tokens from ROADtools, TokenTactics, etc.
- **Managed Identity** - For Azure-hosted environments
- **VS Code Credential** - Azure extension cached token
- **Shared Token Cache** - Windows cached credentials

---

## Legal Disclaimer

This toolkit is intended for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before using these tools against any systems. The authors assume no liability for misuse of this software.

---

## License

GNU General Public License v3.0 - See [LICENSE](LICENSE) file for details.

**Copyright (C) 2025 Logisek**

---

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

---

## Acknowledgments

- [Microsoft Graph API](https://docs.microsoft.com/en-us/graph/) - Primary data source
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Attack path analysis inspiration
- [AzureHound](https://github.com/BloodHoundAD/AzureHound) - Azure data collection format
- [microsoft-info](https://github.com/merill/microsoft-info) - Microsoft First Party App Names & Graph Permissions 

---
