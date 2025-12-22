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

---

## Documentation

| Document | Description |
|----------|-------------|
| [EntraRecon-PS1.md](EntraRecon-PS1.md) | Full PowerShell script documentation including all parameters, features, and usage examples |
| [EntraRecon-PY.md](EntraRecon-PY.md) | Full Python script documentation including authentication methods, stealth configuration, and examples |
| [EntraMFACheck-PS1.md](EntraMFACheck-PS1.md) | MFA Security Check documentation including shared mailbox detection, sign-in tracking, and risk assessment |
| [EntraGuestCheck-PS1.md](EntraGuestCheck-PS1.md) | Guest Account Enumeration documentation including guest domain extraction, invite tracking, and security analysis |

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

| Feature | Enumerate-EntraUsers | MFA Security Check | Guest Account Enumeration |
|---------|---------------------|-------------------|---------------------------|
| **Purpose** | Comprehensive user enumeration | Focused MFA security audit | Guest access governance |
| User Enumeration | 15+ methods | Standard method | Guest-focused |
| MFA Detection | Basic check | Advanced with method types | Advanced with method types |
| Shared Mailbox Detection | ❌ | ✅ Automatic | ❌ (N/A for guests) |
| Guest Domain Extraction | ❌ | ❌ | ✅ Automatic |
| Invite Status Tracking | ❌ | ❌ | ✅ With acceptance dates |
| Last Sign-In Tracking | ✅ | ✅ With analytics | ✅ With analytics |
| Sign-In Capability Check | ❌ | ✅ | ✅ |
| Risk Level Assessment | Basic | Advanced (HIGH/MEDIUM/LOW) | Advanced (HIGH/MEDIUM/LOW) |
| Activity Analytics | Limited | Detailed (stale/recent/never) | Detailed (stale/recent/never) |
| Matrix View | ❌ | ✅ | ✅ |
| Department Analysis | ✅ | ✅ With statistics | ✅ With statistics |
| BloodHound Export | ✅ | ❌ | ❌ |
| HTML Report | ✅ | ❌ | ❌ |
| CSV/JSON Export | ✅ | ✅ Enhanced fields | ✅ Enhanced fields |
| Stealth Mode | ✅ | ✅ | ✅ |
| **Best For** | Red team reconnaissance | MFA compliance audits | External user security |

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

**MFA Security Check:** Requires Microsoft Graph PowerShell SDK:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

Or install individual modules:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
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
