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
| PowerShell | [Enumerate-EntraUsers-PS1.md](Enumerate-EntraUsers-PS1.md) | `Enumerate-EntraUsers.ps1` |
| Python | [Enumerate-EntraUsers-PY.md](Enumerate-EntraUsers-PY.md) | `Enumerate-EntraUsers.py` |

---

## Quick Start

### PowerShell Version

**Requirements:** PowerShell 7+

```powershell
# Interactive mode
.\Enumerate-EntraUsers.ps1

# With Azure CLI token
.\Enumerate-EntraUsers.ps1 -UseAzCliToken

# Export all users
.\Enumerate-EntraUsers.ps1 -ExportPath "users.csv"

# Stealth mode
.\Enumerate-EntraUsers.ps1 -EnableStealth
```

📖 **Full documentation:** [Enumerate-EntraUsers-PS1.md](Enumerate-EntraUsers-PS1.md)

### Python Version

**Requirements:** Python 3.8+, `msal`, `requests`

```bash
# Install dependencies
pip install -r requirements.txt

# Run interactive mode
python Enumerate-EntraUsers.py
```

📖 **Full documentation:** [Enumerate-EntraUsers-PY.md](Enumerate-EntraUsers-PY.md)

---

## Documentation

| Document | Description |
|----------|-------------|
| [Enumerate-EntraUsers-PS1.md](Enumerate-EntraUsers-PS1.md) | Full PowerShell script documentation including all parameters, features, and usage examples |
| [Enumerate-EntraUsers-PY.md](Enumerate-EntraUsers-PY.md) | Full Python script documentation including authentication methods, stealth configuration, and examples |

---

## Feature Comparison

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

The script will automatically install the required `Microsoft.Graph.Users` module on first run.

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

---
