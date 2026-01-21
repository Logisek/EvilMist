<div align="center">
  <img src="assets/EvilMist.png" alt="EvilMist Logo" width="400"/>
</div>

# EvilMist

EvilMist is a collection of scripts and utilities designed to support cloud security configuration audit, cloud penetration testing & cloud red teaming. The toolkit helps identify misconfigurations, assess privilege-escalation paths, and simulate attack techniques. EvilMist aims to streamline cloud-focused red-team workflows and improve the overall security posture of cloud infrastructures

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
| PowerShell | [EntraRecon-PS1.md](docs/EntraRecon-PS1.md) | `scripts/powershell/Invoke-EntraRecon.ps1` |
| Python | [EntraRecon-PY.md](docs/EntraRecon-PY.md) | `scripts/python/entra_recon.py` |

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
| PowerShell | [EntraMFACheck-PS1.md](docs/EntraMFACheck-PS1.md) | `scripts/powershell/Invoke-EntraMFACheck.ps1` |

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
| PowerShell | [EntraGuestCheck-PS1.md](docs/EntraGuestCheck-PS1.md) | `scripts/powershell/Invoke-EntraGuestCheck.ps1` |

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
| PowerShell | [EntraAppAccess-PS1.md](docs/EntraAppAccess-PS1.md) | `scripts/powershell/Invoke-EntraAppAccess.ps1` |

---

## Quick Start

### Script Dispatcher (PowerShell)

**Execute any script from the root directory without navigating to subfolders:**

```powershell
# Interactive mode - shows menu to select script
.\Invoke-EvilMist.ps1

# Execute specific script directly
.\Invoke-EvilMist.ps1 -Script EntraRecon -ExportPath "users.csv"

# List all available scripts
.\Invoke-EvilMist.ps1 -List

# Execute with any parameters (all passed through to target script)
.\Invoke-EvilMist.ps1 -Script EntraMFACheck -Matrix -OnlyNoMFA
```

**Available scripts:** EntraRecon, EntraMFACheck, EntraGuestCheck, EntraAppAccess, EntraRoleCheck, EntraServicePrincipalCheck, EntraConditionalAccessCheck, EntraAdminUnitCheck, EntraStaleAccountCheck, EntraDeviceCheck, EntraSSPRCheck, EntraPasswordPolicyCheck, EntraLegacyAuthCheck, EntraLicenseCheck, EntraDirectorySyncCheck, EntraPowerPlatformCheck, EntraGroupCheck, EntraApplicationCheck, EntraAttackPathCheck, EntraAzureRBACCheck, EntraOAuthConsentCheck, EntraSignInRiskCheck, EntraPIMCheck, EntraKeyVaultCheck, EntraStorageAccountCheck, EntraNetworkSecurityCheck, EntraManagedIdentityCheck, EntraExchangeCheck, EntraSharePointCheck, EntraTeamsCheck, EntraAzureAttackPathCheck, EntraReport, EntraComplianceCheck

### Enumerate-EntraUsers (PowerShell)

**Requirements:** PowerShell 7+

```powershell
# Using dispatcher (recommended)
.\Invoke-EvilMist.ps1 -Script EntraRecon

# With Azure CLI token
.\Invoke-EvilMist.ps1 -Script EntraRecon -UseAzCliToken

# Export all users
.\Invoke-EvilMist.ps1 -Script EntraRecon -ExportPath "users.csv"

# Stealth mode
.\Invoke-EvilMist.ps1 -Script EntraRecon -EnableStealth
```

📖 **Full documentation:** [EntraRecon-PS1.md](docs/EntraRecon-PS1.md)

### Enumerate-EntraUsers (Python)

**Requirements:** Python 3.8+, `msal`, `requests`

```bash
# Install dependencies
pip install -r requirements.txt

# Run directly from subfolder
python scripts\python\entra_recon.py
```

📖 **Full documentation:** [EntraRecon-PY.md](docs/EntraRecon-PY.md)

### MFA Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Using dispatcher (recommended)
.\Invoke-EvilMist.ps1 -Script EntraMFACheck

# Scan for users without MFA
.\Invoke-EvilMist.ps1 -Script EntraMFACheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraMFACheck -ExportPath "no-mfa-users.csv"

# Matrix view with all features
.\Invoke-EvilMist.ps1 -Script EntraMFACheck -Matrix -IncludeDisabledUsers

# Stealth mode
.\Invoke-EvilMist.ps1 -Script EntraMFACheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraMFACheck-PS1.md](docs/EntraMFACheck-PS1.md)

### Guest Account Enumeration (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Enumerate all guest accounts
.\Invoke-EvilMist.ps1 -Script EntraGuestCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraGuestCheck -ExportPath "guest-accounts.csv"

# Show only guests without MFA in matrix view
.\Invoke-EvilMist.ps1 -Script EntraGuestCheck -Matrix -OnlyNoMFA

# Include disabled guests with stealth mode
.\Invoke-EvilMist.ps1 -Script EntraGuestCheck -IncludeDisabledGuests -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraGuestCheck-PS1.md](docs/EntraGuestCheck-PS1.md)

### Critical Administrative Access Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check users with critical administrative access (10 apps)
.\Invoke-EvilMist.ps1 -Script EntraAppAccess

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraAppAccess -ExportPath "app-access.csv"

# Show only users without MFA in matrix view
.\Invoke-EvilMist.ps1 -Script EntraAppAccess -Matrix -OnlyNoMFA

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraAppAccess -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraAppAccess-PS1.md](docs/EntraAppAccess-PS1.md)

### Privileged Role Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check users with privileged directory roles
.\Invoke-EvilMist.ps1 -Script EntraRoleCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraRoleCheck -ExportPath "privileged-roles.csv"

# Show only users without MFA in matrix view
.\Invoke-EvilMist.ps1 -Script EntraRoleCheck -Matrix -OnlyNoMFA

# Show only permanent (non-PIM) assignments
.\Invoke-EvilMist.ps1 -Script EntraRoleCheck -OnlyPermanent -ExportPath "permanent-admins.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraRoleCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraRoleCheck-PS1.md](docs/EntraRoleCheck-PS1.md)

### Service Principal Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check all service principals and analyze security posture
.\Invoke-EvilMist.ps1 -Script EntraServicePrincipalCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraServicePrincipalCheck -ExportPath "service-principals.csv"

# Show only service principals with expired credentials in matrix view
.\Invoke-EvilMist.ps1 -Script EntraServicePrincipalCheck -Matrix -OnlyExpiredCredentials

# Show only high-permission service principals
.\Invoke-EvilMist.ps1 -Script EntraServicePrincipalCheck -OnlyHighPermission -ExportPath "high-perm-sp.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraServicePrincipalCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraServicePrincipalCheck-PS1.md](docs/EntraServicePrincipalCheck-PS1.md)

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
| PowerShell | [EntraServicePrincipalCheck-PS1.md](docs/EntraServicePrincipalCheck-PS1.md) | `scripts/powershell/Invoke-EntraServicePrincipalCheck.ps1` |

---

### Application Registration Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check all application registrations and analyze security posture
.\Invoke-EvilMist.ps1 -Script EntraApplicationCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraApplicationCheck -ExportPath "applications.csv"

# Show only applications with expired credentials in matrix view
.\Invoke-EvilMist.ps1 -Script EntraApplicationCheck -Matrix -OnlyExpiredCredentials

# Show only high-permission applications
.\Invoke-EvilMist.ps1 -Script EntraApplicationCheck -OnlyHighPermission -ExportPath "high-perm-apps.csv"

# Show only applications with credentials
.\Invoke-EvilMist.ps1 -Script EntraApplicationCheck -OnlyWithCredentials -ExportPath "apps-with-creds.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraApplicationCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraApplicationCheck-PS1.md](docs/EntraApplicationCheck-PS1.md)

**Key Features:**
- **Comprehensive Application Enumeration** - Enumerates all application registrations in the tenant
- **Credential Analysis** - Identifies applications with secrets and certificates
- **Expiration Tracking** - Detects expired and expiring credentials (≤30 days)
- **API Permission Analysis** - Identifies applications with high-risk and critical permissions
- **Owner Security Assessment** - Checks app owners and their MFA status
- **Risk Assessment** - Categorizes applications by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on permissions and credentials
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only apps with credentials, expired credentials, or high permissions
- **Export Options** - CSV/JSON with comprehensive application details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraApplicationCheck-PS1.md](docs/EntraApplicationCheck-PS1.md) | `scripts/powershell/Invoke-EntraApplicationCheck.ps1` |

---

### Conditional Access Policy Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Analyze all Conditional Access policies
.\Invoke-EvilMist.ps1 -Script EntraConditionalAccessCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraConditionalAccessCheck -ExportPath "ca-policies.csv"

# Show only policies with exclusions in matrix view
.\Invoke-EvilMist.ps1 -Script EntraConditionalAccessCheck -Matrix -OnlyWithExclusions

# Show only policies without MFA enforcement
.\Invoke-EvilMist.ps1 -Script EntraConditionalAccessCheck -OnlyMFAgaps -ExportPath "mfa-gaps.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraConditionalAccessCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraConditionalAccessCheck-PS1.md](docs/EntraConditionalAccessCheck-PS1.md)

### Administrative Unit Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Analyze all Administrative Units and scoped role assignments
.\Invoke-EvilMist.ps1 -Script EntraAdminUnitCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraAdminUnitCheck -ExportPath "admin-units.csv"

# Show only scoped administrators without MFA in matrix view
.\Invoke-EvilMist.ps1 -Script EntraAdminUnitCheck -Matrix -OnlyNoMFA

# Include disabled accounts
.\Invoke-EvilMist.ps1 -Script EntraAdminUnitCheck -IncludeDisabledUsers -ExportPath "all-admins.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraAdminUnitCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraAdminUnitCheck-PS1.md](docs/EntraAdminUnitCheck-PS1.md)

**Key Features:**
- **Administrative Unit Enumeration** - Enumerates all Administrative Units with configuration details
- **Scoped Role Assignment Analysis** - Identifies all scoped administrators and their roles
- **Member Enumeration** - Shows AU members and their roles
- **MFA Status Detection** - Identify scoped administrators without Multi-Factor Authentication
- **Last Sign-In Tracking** - Shows login date/time and activity patterns
- **Risk Assessment** - Categorizes assignments by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on scoped admin access
- **Activity Analytics** - Sign-in statistics, stale accounts, inactive administrators
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only administrators without MFA or include disabled accounts
- **Export Options** - CSV/JSON with comprehensive scoped assignment details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraAdminUnitCheck-PS1.md](docs/EntraAdminUnitCheck-PS1.md) | `scripts/powershell/Invoke-EntraAdminUnitCheck.ps1` |

---

### Stale Account Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Identify stale accounts and account hygiene issues
.\Invoke-EvilMist.ps1 -Script EntraStaleAccountCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraStaleAccountCheck -ExportPath "stale-accounts.csv"

# Include disabled accounts in matrix view
.\Invoke-EvilMist.ps1 -Script EntraStaleAccountCheck -IncludeDisabledUsers -Matrix

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraStaleAccountCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraStaleAccountCheck-PS1.md](docs/EntraStaleAccountCheck-PS1.md)

**Key Features:**
- **Stale Account Detection** - Identifies accounts with no recent sign-in (>90 days)
- **Never Signed-In Detection** - Finds accounts that have never been used
- **License Waste Detection** - Identifies disabled accounts still assigned licenses
- **Password Expiration Tracking** - Detects accounts with expired passwords
- **Account Age Analysis** - Calculates account age and correlates with inactivity
- **Risk Assessment** - Categorizes accounts by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- **Activity Analytics** - Sign-in statistics, stale account breakdowns
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Include or exclude disabled accounts
- **Export Options** - CSV/JSON with comprehensive account details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraStaleAccountCheck-PS1.md](docs/EntraStaleAccountCheck-PS1.md) | `scripts/powershell/Invoke-EntraStaleAccountCheck.ps1` |

---

### Device Trust and Compliance Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Analyze all registered devices
.\Invoke-EvilMist.ps1 -Script EntraDeviceCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraDeviceCheck -ExportPath "devices.csv"

# Show only non-compliant devices in matrix view
.\Invoke-EvilMist.ps1 -Script EntraDeviceCheck -Matrix -OnlyNonCompliant

# Show only BYOD devices
.\Invoke-EvilMist.ps1 -Script EntraDeviceCheck -OnlyBYOD -ExportPath "byod-devices.csv"

# Show only devices with stale sign-ins
.\Invoke-EvilMist.ps1 -Script EntraDeviceCheck -OnlyStale -ExportPath "stale-devices.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraDeviceCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraDeviceCheck-PS1.md](docs/EntraDeviceCheck-PS1.md)

**Key Features:**
- **Comprehensive Device Enumeration** - Enumerates all registered devices in the tenant
- **Compliance Status Detection** - Identifies compliant, non-compliant, and unknown compliance devices
- **BYOD Detection** - Automatically identifies personal/BYOD devices
- **Stale Sign-In Detection** - Identifies devices with stale sign-ins (>90 days)
- **Device Trust Analysis** - Analyzes join types (Azure AD Joined, Hybrid Joined, Registered)
- **Management Status** - Identifies managed vs unmanaged devices
- **Intune Compliance Policies** - Enumerates Intune compliance policies and assignments
- **Risk Assessment** - Categorizes devices by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on compliance gaps and trust issues
- **Activity Analytics** - Sign-in statistics, stale devices, registration dates
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only non-compliant, BYOD, or stale devices
- **Export Options** - CSV/JSON with comprehensive device details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraDeviceCheck-PS1.md](docs/EntraDeviceCheck-PS1.md) | `scripts/powershell/Invoke-EntraDeviceCheck.ps1` |

---

### Self-Service Password Reset Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check users with SSPR enabled
.\Invoke-EvilMist.ps1 -Script EntraSSPRCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraSSPRCheck -ExportPath "sspr-users.csv"

# Show only users without backup methods in matrix view
.\Invoke-EvilMist.ps1 -Script EntraSSPRCheck -Matrix -OnlyNoBackup

# Include disabled users
.\Invoke-EvilMist.ps1 -Script EntraSSPRCheck -IncludeDisabledUsers -ExportPath "all-sspr-users.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraSSPRCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraSSPRCheck-PS1.md](docs/EntraSSPRCheck-PS1.md)

**Key Features:**
- **SSPR Status Detection** - Identifies users with SSPR enabled, registered, or capable
- **Registration Method Analysis** - Analyzes registered authentication methods for SSPR
- **Backup Method Detection** - Identifies users without backup methods configured
- **Strong Method Detection** - Distinguishes between strong and weak authentication methods
- **MFA Status Correlation** - Cross-references SSPR configuration with MFA status
- **Last Sign-In Tracking** - Shows login date/time and activity patterns
- **Risk Assessment** - Categorizes users by risk level (HIGH/MEDIUM/LOW) based on SSPR configuration
- **Activity Analytics** - Sign-in statistics, stale accounts, inactive users
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only users without backup methods or include disabled accounts
- **Export Options** - CSV/JSON with comprehensive SSPR details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraSSPRCheck-PS1.md](docs/EntraSSPRCheck-PS1.md) | `scripts/powershell/Invoke-EntraSSPRCheck.ps1` |

---

### Password Policy Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Analyze all password policies
.\Invoke-EvilMist.ps1 -Script EntraPasswordPolicyCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraPasswordPolicyCheck -ExportPath "password-policies.csv"

# Show only users with weak password policies in matrix view
.\Invoke-EvilMist.ps1 -Script EntraPasswordPolicyCheck -Matrix -OnlyWeakPolicies

# Show only users with password never expires
.\Invoke-EvilMist.ps1 -Script EntraPasswordPolicyCheck -OnlyNeverExpires -ExportPath "never-expires.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraPasswordPolicyCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraPasswordPolicyCheck-PS1.md](docs/EntraPasswordPolicyCheck-PS1.md)

**Key Features:**
- **Password Expiration Analysis** - Checks password expiration policies per user
- **Never Expires Detection** - Identifies users with "password never expires" flag
- **Complexity Requirements** - Checks password complexity requirements (strong password enforcement)
- **Weak Policy Detection** - Identifies users with weak password policies
- **Password Age Tracking** - Calculates password age and expiration risk
- **Risk Assessment** - Categorizes users by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on policy strength
- **Activity Analytics** - Sign-in statistics, password age analysis, policy gaps
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only weak policies or never expires accounts
- **Export Options** - CSV/JSON with comprehensive policy details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraPasswordPolicyCheck-PS1.md](docs/EntraPasswordPolicyCheck-PS1.md) | `scripts/powershell/Invoke-EntraPasswordPolicyCheck.ps1` |

---

### Legacy Authentication Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Analyze all legacy authentication usage
.\Invoke-EvilMist.ps1 -Script EntraLegacyAuthCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraLegacyAuthCheck -ExportPath "legacy-auth.csv"

# Show only recent usage (last 30 days) in matrix view
.\Invoke-EvilMist.ps1 -Script EntraLegacyAuthCheck -Matrix -OnlyRecent

# Include disabled accounts
.\Invoke-EvilMist.ps1 -Script EntraLegacyAuthCheck -IncludeDisabledUsers -ExportPath "all-legacy-users.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraLegacyAuthCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraLegacyAuthCheck-PS1.md](docs/EntraLegacyAuthCheck-PS1.md)

**Key Features:**
- **Legacy Protocol Detection** - Identifies 10 legacy authentication protocols (IMAP, POP3, SMTP, Exchange ActiveSync, etc.)
- **Sign-In Log Analysis** - Queries audit logs for legacy authentication usage (last 90 days)
- **Last Usage Tracking** - Shows last legacy authentication date and time
- **Protocol Statistics** - Tracks successful/failed sign-ins per protocol
- **MFA Status Detection** - Identify users without Multi-Factor Authentication using legacy auth
- **Risk Assessment** - Categorizes users by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on usage patterns and recency
- **Activity Analytics** - Sign-in statistics, protocol breakdowns, usage recency
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only recent usage or include disabled accounts
- **Export Options** - CSV/JSON with comprehensive legacy auth details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraLegacyAuthCheck-PS1.md](docs/EntraLegacyAuthCheck-PS1.md) | `scripts/powershell/Invoke-EntraLegacyAuthCheck.ps1` |

---

### License and SKU Analysis (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Analyze all license SKUs and user assignments
.\Invoke-EvilMist.ps1 -Script EntraLicenseCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraLicenseCheck -ExportPath "licenses.csv"

# Show only users with privileged licenses (E5, P2) in matrix view
.\Invoke-EvilMist.ps1 -Script EntraLicenseCheck -Matrix -OnlyPrivilegedLicenses

# Show only unused license assignments
.\Invoke-EvilMist.ps1 -Script EntraLicenseCheck -OnlyUnusedLicenses -ExportPath "unused-licenses.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraLicenseCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraLicenseCheck-PS1.md](docs/EntraLicenseCheck-PS1.md)

**Key Features:**
- **Tenant SKU Enumeration** - Lists all subscribed license SKUs and their consumption
- **User License Assignment Tracking** - Identifies all users with license assignments
- **Privileged License Detection** - Automatically identifies E5, P2, and other high-privilege licenses
- **Unused License Detection** - Identifies licenses assigned to users who have never signed in
- **Risk Assessment** - Categorizes license assignments by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on license privileges
- **License Usage Analytics** - Consumption statistics, unused license tracking, SKU breakdowns
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only privileged licenses, unused licenses, or include disabled accounts
- **Export Options** - CSV/JSON with comprehensive license details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraLicenseCheck-PS1.md](docs/EntraLicenseCheck-PS1.md) | `scripts/powershell/Invoke-EntraLicenseCheck.ps1` |

---

### Directory Sync Status Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check directory sync status for all users
.\Invoke-EvilMist.ps1 -Script EntraDirectorySyncCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraDirectorySyncCheck -ExportPath "sync-status.csv"

# Show only users with sync errors in matrix view
.\Invoke-EvilMist.ps1 -Script EntraDirectorySyncCheck -Matrix -OnlySyncErrors

# Show only users with stale sync (>7 days)
.\Invoke-EvilMist.ps1 -Script EntraDirectorySyncCheck -OnlyStaleSync -ExportPath "stale-sync.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraDirectorySyncCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraDirectorySyncCheck-PS1.md](docs/EntraDirectorySyncCheck-PS1.md)

**Key Features:**
- **Sync Status Analysis** - Identifies synced vs cloud-only users
- **Sync Error Detection** - Enumerates all provisioning and sync errors
- **Stale Sync Detection** - Identifies users with stale synchronization (>7 days)
- **Sync Conflict Identification** - Detects duplicate attributes and conflicts
- **Sync Scope Analysis** - Checks sync configuration and scope
- **Risk Assessment** - Categorizes users by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on sync health
- **Activity Analytics** - Sync statistics, error breakdowns, domain analysis
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only sync errors, stale sync, or include disabled accounts
- **Export Options** - CSV/JSON with comprehensive sync details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraDirectorySyncCheck-PS1.md](docs/EntraDirectorySyncCheck-PS1.md) | `scripts/powershell/Invoke-EntraDirectorySyncCheck.ps1` |

---

### Power Platform Enumeration (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules, Power Platform Admin or Environment Maker permissions

**Authentication:** The script automatically handles Power Platform API authentication:
- **Default**: Device code flow (browser prompt) - no setup needed
- **Azure CLI**: Use `-UseAzCliToken` - automatically runs `az login` if needed
- **Azure PowerShell**: Use `-UseAzPowerShellToken` - automatically runs `Connect-AzAccount` if needed (uses same account as Graph auth)

```powershell
# Enumerate all Power Apps and Power Automate flows
.\Invoke-EvilMist.ps1 -Script EntraPowerPlatformCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraPowerPlatformCheck -ExportPath "power-platform.csv"

# Show only high-risk resources (CRITICAL/HIGH) in matrix view
.\Invoke-EvilMist.ps1 -Script EntraPowerPlatformCheck -Matrix -OnlyHighRisk

# Show only resources with sensitive connectors
.\Invoke-EvilMist.ps1 -Script EntraPowerPlatformCheck -OnlySensitiveConnectors -ExportPath "sensitive.csv"

# Use Azure CLI (automatically runs 'az login' if needed)
.\Invoke-EvilMist.ps1 -Script EntraPowerPlatformCheck -UseAzCliToken

# Use Azure PowerShell (automatically runs 'Connect-AzAccount' if needed, uses Graph context account)
.\Invoke-EvilMist.ps1 -Script EntraPowerPlatformCheck -UseAzPowerShellToken

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraPowerPlatformCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraPowerPlatformCheck-PS1.md](docs/EntraPowerPlatformCheck-PS1.md)

**Key Features:**
- **Power Apps Enumeration** - Enumerates all Power Apps with owner and sharing information
- **Power Automate Flow Enumeration** - Enumerates all flows with connector and action analysis
- **Sensitive Connector Detection** - Identifies 30+ sensitive connectors (CRITICAL, HIGH, MEDIUM, LOW risk)
- **High-Risk Action Detection** - Identifies flows with high-risk actions (Delete, Create, Modify, etc.)
- **Risk Assessment** - Categorizes resources by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on connector types and actions
- **Connector Analysis** - Analyzes connector usage and categorizes by risk level
- **Automatic Authentication** - Automatically handles Power Platform API authentication (device code flow, Azure CLI, or Azure PowerShell)
- **Activity Analytics** - Resource statistics, environment breakdowns, owner analysis
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only high-risk resources or resources with sensitive connectors
- **Export Options** - CSV/JSON with comprehensive resource details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraPowerPlatformCheck-PS1.md](docs/EntraPowerPlatformCheck-PS1.md) | `scripts/powershell/Invoke-EntraPowerPlatformCheck.ps1` |

---

### Attack Path Analysis (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Analyze all attack paths (privilege escalation, password reset, transitive groups, shared mailboxes)
.\Invoke-EvilMist.ps1 -Script EntraAttackPathCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraAttackPathCheck -ExportPath "attack-paths.csv"

# Show only high-risk paths (CRITICAL/HIGH) in matrix view
.\Invoke-EvilMist.ps1 -Script EntraAttackPathCheck -Matrix -OnlyHighRisk

# Include disabled accounts
.\Invoke-EvilMist.ps1 -Script EntraAttackPathCheck -IncludeDisabledUsers -ExportPath "all-paths.csv"

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraAttackPathCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraAttackPathCheck-PS1.md](docs/EntraAttackPathCheck-PS1.md)

**Key Features:**
- **Privilege Escalation Analysis** - Identifies paths to elevated privileges through role-assignable groups
- **Password Reset Delegation Detection** - Finds users who can reset passwords for other users
- **Transitive Group Membership Analysis** - Identifies indirect access to privileged groups
- **Shared Mailbox Access Detection** - Identifies shared mailboxes that could be used for lateral movement
- **Risk Assessment** - Categorizes attack paths by risk level (CRITICAL/HIGH/MEDIUM) based on path type and user security posture
- **Path Complexity Analysis** - Evaluates attack path complexity (Low/Medium/High)
- **MFA Status Detection** - Identify users without Multi-Factor Authentication in attack paths
- **Last Sign-In Tracking** - Shows login date/time and activity patterns
- **Activity Analytics** - Sign-in statistics, stale accounts, inactive users
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only high-risk paths or include disabled accounts
- **Export Options** - CSV/JSON with comprehensive attack path details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraAttackPathCheck-PS1.md](docs/EntraAttackPathCheck-PS1.md) | `scripts/powershell/Invoke-EntraAttackPathCheck.ps1` |

---

### Azure RBAC Role Assignment Audit & Drift Detection (PowerShell)

**Requirements:** PowerShell 7+, Az.Accounts, Az.Resources, Microsoft.Graph.Authentication modules

```powershell
# Export all Azure RBAC role assignments across ALL tenants and subscriptions to baseline JSON
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode Export

# Export to specific file
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode Export -ExportPath "rbac-baseline.json"

# Skip tenants with MFA/Conditional Access issues (common in multi-tenant scenarios)
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode Export -SkipFailedTenants

# Show all users with their Azure permissions in matrix format
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode Export -SkipFailedTenants -ShowAllUsersPermissions

# Expand group memberships to show all users who have Azure access via groups
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode Export -SkipFailedTenants -ExpandGroupMembers

# Combined: Show all users including those with access via groups
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode Export -SkipFailedTenants -ExpandGroupMembers -ShowAllUsersPermissions

# Detect drift against baseline across all tenants
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode DriftDetect -BaselinePath "rbac-baseline.json"

# Detect drift with matrix view and export report
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode DriftDetect -BaselinePath "rbac-baseline.json" -Matrix -ExportPath "drift-report.json"

# Export specific tenant only
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode Export -TenantId "tenant-id-123"

# Export specific subscription with Azure CLI auth
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode Export -SubscriptionId "sub-123" -UseAzCliToken

# Stealth mode drift detection
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode DriftDetect -BaselinePath "baseline.json" -EnableStealth -QuietStealth

# Export excluding PIM/JIT time-bounded assignments (focus on permanent assignments only)
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode Export -ExcludePIM

# Detect drift excluding PIM/JIT assignments (ignore temporary elevated access)
.\Invoke-EvilMist.ps1 -Script EntraAzureRBACCheck -Mode DriftDetect -BaselinePath "baseline.json" -ExcludePIM
```

📖 **Full documentation:** [EntraAzureRBACCheck-PS1.md](docs/EntraAzureRBACCheck-PS1.md)

**Key Features:**
- **Multi-Tenant Support** - Automatically scans ALL accessible tenants unless a specific tenant is specified
- **Skip Failed Tenants** - Continue processing when MFA/Conditional Access blocks access to some tenants (`-SkipFailedTenants`)
- **Baseline Export** - Maps and exports all Azure RBAC role assignments across tenants and subscriptions to JSON (desired state)
- **Drift Detection** - Compares current Azure RBAC state against baseline to identify unauthorized changes
- **Multi-Subscription Support** - Scans all accessible subscriptions across all tenants or specific subscriptions
- **All Users Permissions Matrix** - Shows all principals and their Azure permissions in a user-centric view (`-ShowAllUsersPermissions`)
- **Group Member Expansion** - Expands group memberships to reveal all users with Azure access via groups (`-ExpandGroupMembers`)
- **Nested Group Support** - Recursively expands nested groups up to 5 levels deep
- **PIM/JIT Exclusion** - Exclude time-bounded PIM role assignments to focus on permanent access (`-ExcludePIM`)
- **Comprehensive Coverage** - Captures assignments at all scopes (subscription, resource group, resource) across tenants
- **New Assignment Detection** - Identifies role assignments created outside of baseline
- **Removed Assignment Detection** - Detects role assignments removed since baseline
- **Modified Assignment Detection** - Identifies changes to existing role assignments (scope, role, principal)
- **ABAC Condition Mismatch Detection** - Detects when role assignment conditions differ from baseline (added, removed, or modified)
- **Risk Assessment** - Categorizes drift by risk level (CRITICAL/HIGH/MEDIUM) based on role and principal type
- **Remediation Instructions** - Generates Terraform import blocks, Azure CLI, and PowerShell commands for each drift issue
- **Principal Analysis** - Tracks users, groups, and service principals with role assignments
- **Role Definition Details** - Captures built-in vs custom roles, permissions, and descriptions
- **Scope Hierarchy** - Analyzes assignments across subscription, resource group, and resource scopes
- **Condition Support** - Tracks ABAC (Attribute-Based Access Control) conditions on assignments
- **Tenant Tracking** - Includes tenant information for all assignments to support multi-tenant environments
- **Matrix View** - Compact table format for quick drift visualization with tenant information
- **Flexible Authentication** - Azure CLI (az login) or Azure PowerShell (Connect-AzAccount) authentication
- **Export Options** - JSON baseline export, expanded group export, and JSON drift report with detailed recommendations
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraAzureRBACCheck-PS1.md](docs/EntraAzureRBACCheck-PS1.md) | `scripts/powershell/Invoke-EntraAzureRBACCheck.ps1` |

---

### OAuth Consent Grant Audit (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Enumerate all OAuth consent grants and analyze security posture
.\Invoke-EvilMist.ps1 -Script EntraOAuthConsentCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraOAuthConsentCheck -ExportPath "consent-grants.csv"

# Show only high-risk consent grants in matrix view
.\Invoke-EvilMist.ps1 -Script EntraOAuthConsentCheck -Matrix -OnlyHighRisk

# Show only third-party apps with admin consent
.\Invoke-EvilMist.ps1 -Script EntraOAuthConsentCheck -OnlyThirdParty -OnlyAdminConsent

# Show consent grants not used in the last 60 days
.\Invoke-EvilMist.ps1 -Script EntraOAuthConsentCheck -StaleDays 60 -OnlyStale

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraOAuthConsentCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraOAuthConsentCheck-PS1.md](docs/EntraOAuthConsentCheck-PS1.md)

**Key Features:**
- **OAuth2PermissionGrant Enumeration** - Enumerates all delegated permission grants in the tenant
- **Admin vs User Consent Detection** - Distinguishes between tenant-wide admin consent and individual user consent
- **Dangerous Permission Detection** - Identifies high-risk scopes (Mail.ReadWrite, Files.ReadWrite.All, User.ReadWrite.All, etc.)
- **Stale Consent Detection** - Finds unused consent grants (configurable threshold, default 90 days)
- **Third-Party App Identification** - Automatically identifies non-Microsoft applications with elevated permissions
- **Sign-In Activity Correlation** - Cross-references with sign-in activity to detect dormant apps
- **Risk Assessment** - Categorizes consent grants by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on consent type, permissions, and app origin
- **Publisher Analysis** - Tracks application publishers and verified publisher status
- **Resource Tracking** - Identifies which APIs/resources each app has access to
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only high-risk, third-party, stale, or admin consent grants
- **Export Options** - CSV/JSON with comprehensive consent grant details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraOAuthConsentCheck-PS1.md](docs/EntraOAuthConsentCheck-PS1.md) | `scripts/powershell/Invoke-EntraOAuthConsentCheck.ps1` |

---

### Sign-In Risk Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules, Azure AD Premium P2

```powershell
# Enumerate all risky users
.\Invoke-EvilMist.ps1 -Script EntraSignInRiskCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraSignInRiskCheck -ExportPath "risky-users.csv"

# Show only high-risk users in matrix view
.\Invoke-EvilMist.ps1 -Script EntraSignInRiskCheck -Matrix -OnlyHighRisk

# Show only active (not remediated) risks
.\Invoke-EvilMist.ps1 -Script EntraSignInRiskCheck -OnlyActive

# Include risky sign-ins from the last 7 days
.\Invoke-EvilMist.ps1 -Script EntraSignInRiskCheck -IncludeRiskySignIns -DaysBack 7

# Full analysis with pattern detection
.\Invoke-EvilMist.ps1 -Script EntraSignInRiskCheck -IncludeRiskySignIns -IncludeRiskDetections -Matrix

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraSignInRiskCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraSignInRiskCheck-PS1.md](docs/EntraSignInRiskCheck-PS1.md)

**Key Features:**
- **Risky User Enumeration** - Lists all users flagged by Azure AD Identity Protection
- **Risk Level Analysis** - Categorizes users by HIGH, MEDIUM, and LOW risk levels
- **Risk State Tracking** - Shows whether risks are active, remediated, or dismissed
- **Risk Detection Analysis** - Enumerates specific risk events (impossible travel, anonymous IPs, leaked credentials)
- **Pattern Detection** - Identifies suspicious patterns (after-hours activity, password spray attacks, multiple risk types per user)
- **Timing Analysis** - Tracks weekend and after-hours suspicious activity
- **Impossible Travel Detection** - Identifies sign-ins from geographically distant locations
- **Anonymous IP Detection** - Flags VPN, Tor, and proxy usage
- **Password Spray Detection** - Identifies credential stuffing attacks
- **Leaked Credentials Detection** - Users with credentials found in data breaches
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only high-risk or only active risks
- **Export Options** - CSV/JSON with comprehensive risk details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraSignInRiskCheck-PS1.md](docs/EntraSignInRiskCheck-PS1.md) | `scripts/powershell/Invoke-EntraSignInRiskCheck.ps1` |

---

### Privileged Identity Management (PIM) Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules, Azure AD Premium P2

```powershell
# Perform comprehensive PIM configuration audit
.\Invoke-EvilMist.ps1 -Script EntraPIMCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraPIMCheck -ExportPath "pim-audit.csv"

# Show only critical findings in matrix view
.\Invoke-EvilMist.ps1 -Script EntraPIMCheck -Matrix -OnlyCritical

# Audit high-privilege roles with strict 2-hour activation limit
.\Invoke-EvilMist.ps1 -Script EntraPIMCheck -OnlyHighPrivilege -MaxActivationHours 2

# Include PIM for Groups and Access Reviews
.\Invoke-EvilMist.ps1 -Script EntraPIMCheck -IncludeGroups -IncludeAccessReviews

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraPIMCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraPIMCheck-PS1.md](docs/EntraPIMCheck-PS1.md)

**Key Features:**
- **JIT Access Configuration Audit** - Analyzes max activation duration, approval requirements, MFA enforcement
- **Approval Workflow Analysis** - Identifies roles without approval or with missing approvers
- **Justification Requirements** - Detects roles without mandatory justification for activation
- **MFA Enforcement** - Identifies roles that don't require MFA for activation
- **Notification Configuration** - Analyzes admin notification settings for role activations
- **Permanent Assignment Detection** - Finds standing privileged access that bypasses PIM
- **PIM for Groups** - Analyzes group-based privileged access management
- **Access Reviews** - Checks periodic access certification configuration
- **Risk Assessment** - Categorizes roles by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on configuration gaps
- **Eligible vs Active Analysis** - Compares eligible assignments with active/permanent assignments
- **Break-Glass Account Detection** - Identifies permanent assignments that may be break-glass accounts
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only critical roles, high-privilege roles, or misconfigurations
- **Export Options** - CSV/JSON with comprehensive PIM configuration details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraPIMCheck-PS1.md](docs/EntraPIMCheck-PS1.md) | `scripts/powershell/Invoke-EntraPIMCheck.ps1` |

---

### Azure Key Vault Security Check (PowerShell)

**Requirements:** PowerShell 7+, Az.Accounts, Az.KeyVault, Az.Resources, Az.Monitor modules

```powershell
# Perform comprehensive Key Vault security audit
.\Invoke-EvilMist.ps1 -Script EntraKeyVaultCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraKeyVaultCheck -ExportPath "keyvault-audit.csv"

# Show only critical findings in matrix view
.\Invoke-EvilMist.ps1 -Script EntraKeyVaultCheck -Matrix -OnlyCritical

# Audit only Key Vaults with public access enabled
.\Invoke-EvilMist.ps1 -Script EntraKeyVaultCheck -OnlyPublicAccess

# Include secret and certificate expiration analysis
.\Invoke-EvilMist.ps1 -Script EntraKeyVaultCheck -IncludeSecrets -IncludeCertificates -ExpirationDays 90

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraKeyVaultCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraKeyVaultCheck-PS1.md](docs/EntraKeyVaultCheck-PS1.md)

**Key Features:**
- **Access Model Analysis** - Compares RBAC vs legacy access policies
- **Protection Status** - Checks soft delete and purge protection configuration
- **Network Security Audit** - Identifies public access, firewall rules, VNet integration
- **Private Endpoint Detection** - Verifies private connectivity configuration
- **Overly Permissive Access Detection** - Finds access policies with excessive permissions ('all', 'purge')
- **Diagnostic Logging Check** - Verifies audit logging is enabled
- **Secret/Certificate/Key Expiration** - Tracks items approaching or past expiration
- **Risk Assessment** - Categorizes Key Vaults by risk level (CRITICAL/HIGH/MEDIUM/LOW) based on configuration gaps
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only critical, public access, or unprotected Key Vaults
- **Export Options** - CSV/JSON with comprehensive Key Vault details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraKeyVaultCheck-PS1.md](docs/EntraKeyVaultCheck-PS1.md) | `scripts/powershell/Invoke-EntraKeyVaultCheck.ps1` |

---

### Azure Storage Account Security Audit

Comprehensive Azure Storage Account security audit tool that detects exposed storage accounts and data exfiltration risks. Identifies public blob containers, network misconfigurations, and data protection gaps.

```powershell
# Perform comprehensive Storage Account security audit
.\Invoke-EvilMist.ps1 -Script EntraStorageAccountCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraStorageAccountCheck -ExportPath "storage-audit.csv"

# Show only critical findings in matrix view
.\Invoke-EvilMist.ps1 -Script EntraStorageAccountCheck -Matrix -OnlyCritical

# Find storage accounts with anonymous containers
.\Invoke-EvilMist.ps1 -Script EntraStorageAccountCheck -OnlyAnonymousContainers -IncludeContainers

# Include key rotation age analysis
.\Invoke-EvilMist.ps1 -Script EntraStorageAccountCheck -IncludeKeyAge -KeyRotationDays 60

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraStorageAccountCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraStorageAccountCheck-PS1.md](docs/EntraStorageAccountCheck-PS1.md)

**Key Features:**
- **Public Blob Container Detection** - Identifies containers with anonymous access (Blob/Container level)
- **HTTPS Enforcement Check** - Detects storage accounts allowing unencrypted HTTP traffic
- **Shared Key Access Analysis** - Identifies accounts using storage keys vs Azure AD authentication
- **Network Security Audit** - Checks public access, firewall rules, VNet integration, private endpoints
- **Data Protection Analysis** - Blob soft delete, container soft delete, versioning status
- **Key Rotation Tracking** - Identifies storage account keys exceeding rotation threshold
- **Cross-Tenant Replication** - Detects data replication to other tenants (exfiltration risk)
- **TLS Version Verification** - Ensures minimum TLS 1.2 enforcement
- **Infrastructure Encryption** - Checks for double encryption configuration
- **Diagnostic Logging Check** - Verifies audit logging is enabled
- **Risk Assessment** - Categorizes Storage Accounts by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- **Matrix View** - Compact table format for quick visual scanning
- **Filtering Options** - Show only critical, public access, or anonymous containers
- **Export Options** - CSV/JSON with comprehensive Storage Account details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraStorageAccountCheck-PS1.md](docs/EntraStorageAccountCheck-PS1.md) | `scripts/powershell/Invoke-EntraStorageAccountCheck.ps1` |

---

### Network Security Check (PowerShell)

**Requirements:** PowerShell 7+, Azure PowerShell modules

```powershell
# Perform comprehensive Network Security audit
.\Invoke-EvilMist.ps1 -Script EntraNetworkSecurityCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraNetworkSecurityCheck -ExportPath "network-audit.csv"

# Show only NSGs with open management ports
.\Invoke-EvilMist.ps1 -Script EntraNetworkSecurityCheck -OnlyOpenPorts -Matrix

# Full scan with VNets, Bastion, and DDoS analysis
.\Invoke-EvilMist.ps1 -Script EntraNetworkSecurityCheck -IncludeVNets -IncludeBastion -IncludeDDoS -Matrix

# Include NSG flow logs analysis
.\Invoke-EvilMist.ps1 -Script EntraNetworkSecurityCheck -IncludeFlowLogs -Matrix

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraNetworkSecurityCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraNetworkSecurityCheck-PS1.md](docs/EntraNetworkSecurityCheck-PS1.md)

**Key Features:**
- **NSG Rules Analysis** - Detects overly permissive rules (0.0.0.0/0, Any-Any)
- **Open Management Ports** - Identifies exposed RDP (3389), SSH (22), WinRM (5985/5986)
- **Azure Bastion Analysis** - Compares Bastion usage vs direct RDP/SSH access
- **DDoS Protection Status** - Verifies DDoS protection on VNets
- **VNet Security** - Peering analysis, subnet NSG coverage, service endpoints
- **NSG Flow Logs** - Flow log configuration and traffic analytics status
- **VPN/ExpressRoute** - Gateway configuration analysis
- **Risk Assessment** - CRITICAL/HIGH/MEDIUM/LOW classification with findings
- **Matrix View** - Compact tabular format for quick review
- **Export Options** - CSV/JSON with comprehensive network security details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraNetworkSecurityCheck-PS1.md](docs/EntraNetworkSecurityCheck-PS1.md) | `scripts/powershell/Invoke-EntraNetworkSecurityCheck.ps1` |

---

### Managed Identity Security Audit

Comprehensive Azure Managed Identity security audit tool that identifies excessive permissions and security risks. Detects high-privilege managed identities, cross-subscription access, and unused identities.

```powershell
# Perform comprehensive Managed Identity security audit
.\Invoke-EvilMist.ps1 -Script EntraManagedIdentityCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraManagedIdentityCheck -ExportPath "managed-identity-audit.csv"

# Show only high-privilege managed identities
.\Invoke-EvilMist.ps1 -Script EntraManagedIdentityCheck -OnlyHighPrivilege -Matrix

# Show identities with cross-subscription access
.\Invoke-EvilMist.ps1 -Script EntraManagedIdentityCheck -OnlyCrossSubscription -Matrix

# Include detailed role assignment information
.\Invoke-EvilMist.ps1 -Script EntraManagedIdentityCheck -IncludeRoleDetails -Matrix

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraManagedIdentityCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraManagedIdentityCheck-PS1.md](docs/EntraManagedIdentityCheck-PS1.md)

**Key Features:**
- **Identity Inventory** - System-assigned vs user-assigned managed identity enumeration
- **Role Assignment Analysis** - Azure RBAC permissions for each managed identity
- **High-Privilege Detection** - Identifies Owner, Contributor, User Access Administrator roles
- **Critical Role Detection** - Flags identities with Owner, UAA, or RBAC Admin roles
- **Cross-Subscription Access** - Detects identities with permissions beyond home subscription
- **Unused Identity Detection** - Finds managed identities with no role assignments
- **Resource Coverage** - VMs, App Services, Function Apps, User-Assigned Identities
- **Scope Analysis** - Subscription-wide vs resource group vs resource-level permissions
- **Risk Assessment** - CRITICAL/HIGH/MEDIUM/LOW classification with findings
- **Matrix View** - Compact tabular format for quick review
- **Export Options** - CSV/JSON with comprehensive identity details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraManagedIdentityCheck-PS1.md](docs/EntraManagedIdentityCheck-PS1.md) | `scripts/powershell/Invoke-EntraManagedIdentityCheck.ps1` |

---

### Exchange Online Security Audit

Comprehensive Exchange Online security audit tool that detects mail-based attack vectors and data exfiltration risks. Identifies inbox rules forwarding to external addresses, suspicious transport rules, mailbox delegations, and audit logging gaps.

```powershell
# Perform comprehensive Exchange Online security audit
.\Invoke-EvilMist.ps1 -Script EntraExchangeCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraExchangeCheck -ExportPath "exchange-audit.csv"

# Show only mailboxes with external forwarding
.\Invoke-EvilMist.ps1 -Script EntraExchangeCheck -OnlyExternalForwarding -Matrix

# Show only suspicious inbox rules
.\Invoke-EvilMist.ps1 -Script EntraExchangeCheck -OnlySuspiciousRules -Matrix

# Include transport rules and OWA policies
.\Invoke-EvilMist.ps1 -Script EntraExchangeCheck -IncludeTransportRules -IncludeOWAPolicies -Matrix

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraExchangeCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraExchangeCheck-PS1.md](docs/EntraExchangeCheck-PS1.md)

**Key Features:**
- **Inbox Rule Analysis** - Detects rules forwarding to external addresses (data exfiltration)
- **External Forwarding Detection** - Identifies SMTP forwarding configured on mailboxes
- **Transport Rules Audit** - Analyzes mail flow rules for suspicious configurations
- **Mailbox Delegation Analysis** - Full Access, Send-As, Send-On-Behalf permissions
- **Audit Logging Status** - Identifies mailboxes without audit logging enabled
- **OWA Policy Analysis** - Outlook Web App security configuration review
- **Client Access Rules** - Legacy access control policy audit
- **BEC Indicator Detection** - Identifies patterns common in Business Email Compromise
- **Suspicious Rule Detection** - Flags rules with keywords like invoice, payment, wire, transfer
- **Risk Assessment** - CRITICAL/HIGH/MEDIUM/LOW classification with findings
- **Matrix View** - Compact tabular format for quick review
- **Export Options** - CSV/JSON with comprehensive mailbox and rule details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraExchangeCheck-PS1.md](docs/EntraExchangeCheck-PS1.md) | `scripts/powershell/Invoke-EntraExchangeCheck.ps1` |

---

### SharePoint Online Security Check

Comprehensive SharePoint Online security assessment tool to identify oversharing and external access risks. Audits tenant-level and site-level sharing configurations to detect potential data exposure.

```powershell
# Perform comprehensive SharePoint Online security audit
.\Invoke-EvilMist.ps1 -Script EntraSharePointCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraSharePointCheck -ExportPath "sharepoint-audit.csv"

# Show only sites allowing anonymous links
.\Invoke-EvilMist.ps1 -Script EntraSharePointCheck -OnlyAnonymousLinks -Matrix

# Show sites with sharing more permissive than tenant
.\Invoke-EvilMist.ps1 -Script EntraSharePointCheck -OnlyPermissiveOverrides -Matrix

# Include OneDrive and sensitivity label analysis
.\Invoke-EvilMist.ps1 -Script EntraSharePointCheck -IncludeOneDrive -IncludeSensitivityLabels -Matrix

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraSharePointCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraSharePointCheck-PS1.md](docs/EntraSharePointCheck-PS1.md)

**Key Features:**
- **Tenant Sharing Settings** - Organization-wide external sharing policy analysis
- **Anonymous Link Detection** - Identifies sites allowing "Anyone" links
- **Site-Level Overrides** - Detects sites with sharing more permissive than tenant
- **Guest Access Analysis** - External user access to sensitive sites
- **OneDrive Sharing** - Personal storage external sharing configuration
- **Sensitivity Label Coverage** - Identifies sites missing data classification
- **Default Link Analysis** - Default link type and permission configuration
- **Link Expiration Policy** - Anonymous link expiration settings
- **Domain Restrictions** - Allow/block list configuration
- **Risk Assessment** - CRITICAL/HIGH/MEDIUM/LOW classification with findings
- **Matrix View** - Compact tabular format for quick review
- **Export Options** - CSV/JSON with comprehensive site details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraSharePointCheck-PS1.md](docs/EntraSharePointCheck-PS1.md) | `scripts/powershell/Invoke-EntraSharePointCheck.ps1` |

---

### Teams Security Check

Comprehensive Microsoft Teams security assessment tool to audit collaboration security settings. Identifies external access risks, guest policies, meeting security gaps, and app permission issues.

```powershell
# Perform comprehensive Teams security audit
.\Invoke-EvilMist.ps1 -Script EntraTeamsCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraTeamsCheck -ExportPath "teams-audit.csv"

# Show only meeting policy risks
.\Invoke-EvilMist.ps1 -Script EntraTeamsCheck -OnlyMeetingRisks -Matrix

# Show only external access findings
.\Invoke-EvilMist.ps1 -Script EntraTeamsCheck -OnlyExternalAccess -Matrix

# Include Teams inventory and app policies
.\Invoke-EvilMist.ps1 -Script EntraTeamsCheck -IncludeTeamsInventory -IncludeAppPolicies -Matrix

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraTeamsCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraTeamsCheck-PS1.md](docs/EntraTeamsCheck-PS1.md)

**Key Features:**
- **External Access (Federation)** - Analyze who can communicate from outside organization
- **Guest Access Policies** - Guest user capabilities and permission settings
- **Meeting Policies** - Anonymous join, lobby bypass, recording settings
- **App Permission Policies** - Third-party and custom app access controls
- **Messaging Policies** - Chat and message feature settings
- **Teams Inventory** - Visibility, guest membership, and governance analysis
- **Client Configuration** - Teams client security settings
- **Risk Assessment** - CRITICAL/HIGH/MEDIUM/LOW classification with findings
- **Matrix View** - Compact tabular format for quick review
- **Export Options** - CSV/JSON with comprehensive configuration details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraTeamsCheck-PS1.md](docs/EntraTeamsCheck-PS1.md) | `scripts/powershell/Invoke-EntraTeamsCheck.ps1` |

---

### Azure Cross-Service Attack Path Analysis

Comprehensive cross-service Azure attack path analysis tool that identifies multi-hop attack paths spanning multiple Azure services. Reveals how access to one resource can lead to compromise of other resources across the Azure environment.

```powershell
# Perform comprehensive cross-service attack path analysis
.\Invoke-EvilMist.ps1 -Script EntraAzureAttackPathCheck

# Export results to CSV
.\Invoke-EvilMist.ps1 -Script EntraAzureAttackPathCheck -ExportPath "azure-attack-paths.csv"

# Show only critical attack paths in matrix view
.\Invoke-EvilMist.ps1 -Script EntraAzureAttackPathCheck -OnlyCritical -Matrix

# Show critical and high-risk paths
.\Invoke-EvilMist.ps1 -Script EntraAzureAttackPathCheck -OnlyHighRisk -Matrix

# Include inherited permission paths with deeper analysis
.\Invoke-EvilMist.ps1 -Script EntraAzureAttackPathCheck -IncludeInheritedPaths -MaxPathDepth 4

# Stealth mode scan
.\Invoke-EvilMist.ps1 -Script EntraAzureAttackPathCheck -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraAzureAttackPathCheck-PS1.md](docs/EntraAzureAttackPathCheck-PS1.md)

**Key Features:**
- **VM to Key Vault Paths** - Identify compute resources with managed identities that can access Key Vault secrets
- **App Service to Secrets** - Web applications with secret access via managed identities
- **Managed Identity Privilege Escalation** - Identities with critical roles enabling takeover
- **Storage Lateral Movement** - Weak storage security enabling data exfiltration or code injection
- **Custom Role Vulnerabilities** - Dangerous permission combinations in custom role definitions
- **Cross-Subscription Paths** - Access spanning multiple Azure subscriptions
- **Management Group Inheritance** - Permissions inherited from parent scopes
- **Risk Assessment** - CRITICAL/HIGH/MEDIUM/LOW classification with attack narratives
- **Matrix View** - Compact tabular format for quick review
- **Export Options** - CSV/JSON with comprehensive path details
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraAzureAttackPathCheck-PS1.md](docs/EntraAzureAttackPathCheck-PS1.md) | `scripts/powershell/Invoke-EntraAzureAttackPathCheck.ps1` |

---

### Consolidated Security Report Generator

Unified HTML security report generator that runs multiple EvilMist security checks and produces a comprehensive executive dashboard with risk assessment, remediation priorities, and trend analysis.

```powershell
# Generate report with core security checks (quick scan)
.\Invoke-EvilMist.ps1 -Script EntraReport -QuickScan

# Generate comprehensive security report with all checks
.\Invoke-EvilMist.ps1 -Script EntraReport -ComprehensiveScan -ExportPath "full-report.html"

# Generate report with specific checks
.\Invoke-EvilMist.ps1 -Script EntraReport -Checks MFA,Roles,ConditionalAccess,AttackPaths

# Generate report with all checks
.\Invoke-EvilMist.ps1 -Script EntraReport -Checks All -ExportPath "security-report.html"

# Trend comparison with previous baseline
.\Invoke-EvilMist.ps1 -Script EntraReport -ComprehensiveScan -BaselinePath "previous-report.json"

# Stealth mode scan with report
.\Invoke-EvilMist.ps1 -Script EntraReport -QuickScan -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraReport-PS1.md](docs/EntraReport-PS1.md)

**Key Features:**
- **Consolidated Reporting** - Run multiple security checks with a single command
- **Executive Dashboard** - Professional HTML report with security score (0-100)
- **Risk Severity Overview** - CRITICAL, HIGH, MEDIUM, LOW finding counts
- **Remediation Priority Matrix** - Prioritized actions (P1-P4) with recommended timelines
- **Trend Analysis** - Compare against baseline reports to track security improvements
- **Quick Scan Mode** - Core security checks (MFA, Roles, CA, Attack Paths, OAuth, PIM)
- **Comprehensive Scan** - All available security checks for full coverage
- **JSON Export** - Automatic baseline export for future comparisons
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraReport-PS1.md](docs/EntraReport-PS1.md) | `scripts/powershell/Invoke-EntraReport.ps1` |

---

### Compliance Assessment (CIS/NIST/SOC2/ISO27001/GDPR)

Comprehensive compliance assessment tool that evaluates Azure Entra ID security configuration against industry-standard frameworks including CIS Microsoft Azure Foundations Benchmark, NIST 800-53, SOC 2, ISO 27001, and GDPR.

```powershell
# Comprehensive compliance assessment against all frameworks
.\Invoke-EvilMist.ps1 -Script EntraComplianceCheck -Matrix

# CIS Azure Benchmark assessment
.\Invoke-EvilMist.ps1 -Script EntraComplianceCheck -Framework CIS -ExportPath "cis-compliance.csv"

# NIST 800-53 assessment with remediation guidance
.\Invoke-EvilMist.ps1 -Script EntraComplianceCheck -Framework NIST -IncludeRemediation

# Executive report with compliance score
.\Invoke-EvilMist.ps1 -Script EntraComplianceCheck -GenerateExecutiveReport -ExportPath "compliance-report.html"

# SOC 2 assessment showing only failed controls
.\Invoke-EvilMist.ps1 -Script EntraComplianceCheck -Framework SOC2 -OnlyFailed

# Filter by NIST control family (e.g., Access Control)
.\Invoke-EvilMist.ps1 -Script EntraComplianceCheck -Framework NIST -ControlFamily AC
```

📖 **Full documentation:** [EntraComplianceCheck-PS1.md](docs/EntraComplianceCheck-PS1.md)

**Key Features:**
- **Multi-Framework Mapping** - CIS Azure Benchmark, NIST 800-53, SOC 2, ISO 27001, GDPR
- **Compliance Scoring** - Overall compliance percentage with pass/fail breakdown
- **Control Family Filtering** - Filter by NIST families (AC, IA, AU, SI) or CIS sections
- **Severity Levels** - Critical, High, Medium, Low classification
- **Executive Reports** - Professional HTML reports with compliance dashboards
- **Remediation Guidance** - Detailed fix recommendations for failed controls
- **Evidence Collection** - Automatic evidence gathering for audit support
- **Multiple Export Formats** - CSV, JSON, HTML export options
- **Stealth Mode** - Configurable delays and jitter to avoid detection

| Version | Documentation | File |
|---------|---------------|------|
| PowerShell | [EntraComplianceCheck-PS1.md](docs/EntraComplianceCheck-PS1.md) | `scripts/powershell/Invoke-EntraComplianceCheck.ps1` |

---

## Documentation

| Document | Description |
|----------|-------------|
| [EntraRecon-PS1.md](docs/EntraRecon-PS1.md) | Full PowerShell script documentation including all parameters, features, and usage examples |
| [EntraRecon-PY.md](docs/EntraRecon-PY.md) | Full Python script documentation including authentication methods, stealth configuration, and examples |
| [EntraMFACheck-PS1.md](docs/EntraMFACheck-PS1.md) | MFA Security Check documentation including shared mailbox detection, sign-in tracking, and risk assessment |
| [EntraGuestCheck-PS1.md](docs/EntraGuestCheck-PS1.md) | Guest Account Enumeration documentation including guest domain extraction, invite tracking, and security analysis |
| [EntraAppAccess-PS1.md](docs/EntraAppAccess-PS1.md) | PowerShell & Graph CLI Access Check documentation including app access tracking, assignment dates, and privileged access analysis |
| [EntraRoleCheck-PS1.md](docs/EntraRoleCheck-PS1.md) | Privileged Role Check documentation including role enumeration, PIM assignment tracking, risk assessment, and security analysis |
| [EntraServicePrincipalCheck-PS1.md](docs/EntraServicePrincipalCheck-PS1.md) | Service Principal Security Check documentation including credential enumeration, expiration tracking, permission analysis, owner security, and risk assessment |
| [EntraConditionalAccessCheck-PS1.md](docs/EntraConditionalAccessCheck-PS1.md) | Conditional Access Policy Security Check documentation including policy enumeration, exclusion detection, MFA enforcement gaps, critical app coverage, and risk assessment |
| [EntraStaleAccountCheck-PS1.md](docs/EntraStaleAccountCheck-PS1.md) | Stale Account Check documentation including stale account detection, never-signed-in detection, license waste detection, password expiration tracking, and account hygiene analysis |
| [EntraDeviceCheck-PS1.md](docs/EntraDeviceCheck-PS1.md) | Device Trust and Compliance Check documentation including device enumeration, compliance status detection, BYOD detection, stale sign-in tracking, Intune compliance policies, and risk assessment |
| [EntraSSPRCheck-PS1.md](docs/EntraSSPRCheck-PS1.md) | Self-Service Password Reset Check documentation including SSPR status detection, registration method analysis, backup method detection, strong method classification, MFA correlation, and risk assessment |
| [EntraPasswordPolicyCheck-PS1.md](docs/EntraPasswordPolicyCheck-PS1.md) | Password Policy Security Check documentation including password expiration analysis, never expires detection, complexity requirements checking, weak policy identification, password age tracking, and risk assessment |
| [EntraLegacyAuthCheck-PS1.md](docs/EntraLegacyAuthCheck-PS1.md) | Legacy Authentication Check documentation including legacy protocol detection, sign-in log analysis, last usage tracking, protocol statistics, MFA correlation, and risk assessment |
| [EntraLicenseCheck-PS1.md](docs/EntraLicenseCheck-PS1.md) | License and SKU Analysis documentation including tenant SKU enumeration, user license assignment tracking, privileged license detection, unused license identification, and risk assessment |
| [EntraAdminUnitCheck-PS1.md](docs/EntraAdminUnitCheck-PS1.md) | Administrative Unit Security Check documentation including AU enumeration, scoped role assignment analysis, member enumeration, MFA status detection, risk assessment, and scoped admin access analysis |
| [EntraDirectorySyncCheck-PS1.md](docs/EntraDirectorySyncCheck-PS1.md) | Directory Sync Status Check documentation including sync status analysis, sync error detection, stale sync detection, sync conflict identification, sync scope analysis, and risk assessment |
| [EntraPowerPlatformCheck-PS1.md](docs/EntraPowerPlatformCheck-PS1.md) | Power Platform Enumeration documentation including Power Apps enumeration, Power Automate flow enumeration, sensitive connector detection, high-risk action identification, connector analysis, and risk assessment |
| [EntraGroupCheck-PS1.md](docs/EntraGroupCheck-PS1.md) | Group Security Analysis documentation including group enumeration, owner analysis with MFA status, no owner detection, excessive membership detection, role-assignable group detection, and risk assessment |
| [EntraApplicationCheck-PS1.md](docs/EntraApplicationCheck-PS1.md) | Application Registration Security Check documentation including application enumeration, credential analysis, expiration tracking, API permission analysis, owner security assessment, and risk assessment |
| [EntraAttackPathCheck-PS1.md](docs/EntraAttackPathCheck-PS1.md) | Attack Path Analysis documentation including privilege escalation paths, password reset delegations, transitive group memberships, shared mailbox access, risk assessment, and path complexity analysis |
| [EntraAzureRBACCheck-PS1.md](docs/EntraAzureRBACCheck-PS1.md) | Azure RBAC Role Assignment Audit & Drift Detection documentation including baseline export, drift detection, multi-subscription support, multi-tenant support, skip failed tenants, group member expansion, all users permissions matrix, PIM/JIT exclusion, ABAC condition mismatch detection, remediation instructions (Terraform/CLI/PowerShell), role assignment tracking, unauthorized change detection, and risk assessment |
| [EntraOAuthConsentCheck-PS1.md](docs/EntraOAuthConsentCheck-PS1.md) | OAuth Consent Grant Audit documentation including OAuth2PermissionGrant enumeration, admin vs user consent detection, dangerous permission identification, stale consent detection, third-party app analysis, sign-in activity correlation, and risk assessment for illicit consent grant detection |
| [EntraSignInRiskCheck-PS1.md](docs/EntraSignInRiskCheck-PS1.md) | Identity Protection Analysis documentation including risky user enumeration, risk level/state tracking, risk detection analysis, impossible travel detection, anonymous IP detection, password spray detection, leaked credentials detection, pattern analysis, timing analysis, and remediation guidance |
| [EntraPIMCheck-PS1.md](docs/EntraPIMCheck-PS1.md) | Privileged Identity Management (PIM) Configuration Audit documentation including JIT access configuration gaps, approval workflow analysis, MFA enforcement, justification requirements, notification configuration, permanent assignment detection, PIM for Groups, Access Reviews, and risk assessment |
| [EntraKeyVaultCheck-PS1.md](docs/EntraKeyVaultCheck-PS1.md) | Azure Key Vault Security Audit documentation including access model analysis (RBAC vs access policies), soft delete and purge protection status, network security audit (public access, firewall, VNet), private endpoint detection, overly permissive access detection, diagnostic logging verification, secret/certificate/key expiration tracking, and risk assessment |
| [EntraStorageAccountCheck-PS1.md](docs/EntraStorageAccountCheck-PS1.md) | Azure Storage Account Security Audit documentation including public blob container detection, HTTPS enforcement verification, shared key access analysis, network security audit (public access, firewall, VNet, private endpoints), data protection analysis (soft delete, versioning), key rotation tracking, cross-tenant replication detection, TLS version verification, infrastructure encryption check, diagnostic logging verification, and risk assessment |
| [EntraNetworkSecurityCheck-PS1.md](docs/EntraNetworkSecurityCheck-PS1.md) | Azure Network Security Audit documentation including NSG rules analysis, overly permissive rule detection (0.0.0.0/0, Any-Any), open management port detection (RDP, SSH, WinRM), Azure Bastion usage analysis, DDoS protection status, VNet peering security, subnet NSG coverage, NSG flow logs configuration, VPN/ExpressRoute gateway analysis, traffic analytics status, and risk assessment |
| [EntraManagedIdentityCheck-PS1.md](docs/EntraManagedIdentityCheck-PS1.md) | Azure Managed Identity Security Audit documentation including system-assigned vs user-assigned identity inventory, role assignment analysis, high-privilege identity detection (Owner, Contributor, UAA), critical role detection, cross-subscription access detection, unused identity identification, resource coverage (VMs, App Services, Function Apps), scope analysis, and risk assessment |
| [EntraExchangeCheck-PS1.md](docs/EntraExchangeCheck-PS1.md) | Exchange Online Security Audit documentation including inbox rule analysis, external forwarding detection, transport rules audit, mailbox delegation analysis, audit logging status, OWA policy analysis, client access rules, BEC indicator detection, suspicious rule detection, and risk assessment |
| [EntraSharePointCheck-PS1.md](docs/EntraSharePointCheck-PS1.md) | SharePoint Online Security Audit documentation including tenant sharing settings, anonymous link detection, site-level override detection, guest access analysis, OneDrive sharing configuration, sensitivity label coverage, default link analysis, link expiration policies, and risk assessment |
| [EntraTeamsCheck-PS1.md](docs/EntraTeamsCheck-PS1.md) | Microsoft Teams Security Audit documentation including external access (federation) settings, guest access policies, meeting policy analysis (anonymous join, lobby bypass), app permission policies, messaging policies, Teams inventory analysis, and risk assessment |
| [EntraAzureAttackPathCheck-PS1.md](docs/EntraAzureAttackPathCheck-PS1.md) | Azure Cross-Service Attack Path Analysis documentation including VM to Key Vault paths, managed identity privilege escalation, storage lateral movement, custom role vulnerabilities, cross-subscription paths, management group inheritance, attack narratives, and risk assessment |
| [EntraReport-PS1.md](docs/EntraReport-PS1.md) | Consolidated Security Report Generator documentation including multi-check execution, HTML executive dashboard, security score calculation, remediation priority matrix, trend analysis with baseline comparison, quick scan and comprehensive scan modes, and JSON baseline export |
| [EntraComplianceCheck-PS1.md](docs/EntraComplianceCheck-PS1.md) | Compliance Assessment documentation including CIS Azure Benchmark mapping, NIST 800-53 control mapping, SOC 2 Trust Service Criteria, ISO 27001 controls, GDPR indicators, compliance scoring, control family filtering, and executive reporting |

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

| Feature | Enumerate-EntraUsers | MFA Security Check | Guest Account Enumeration | Critical Admin Access Check | Privileged Role Check | Service Principal Check | Application Registration Check | Conditional Access Check | Administrative Unit Check | Stale Account Check | Device Trust Check | SSPR Check | Password Policy Check | Legacy Auth Check | License Check | Directory Sync Check | Power Platform Check | Group Security Check | Attack Path Analysis | Azure RBAC Check | OAuth Consent Check |
|---------|---------------------|-------------------|---------------------------|----------------------------|----------------------|------------------------|--------------------------|--------------------------|------------------------|---------------------|-------------------|-------------|---------------------|-------------------|--------------|---------------------|-------------------|-------------------|-------------------|-------------------|-------------------|
| **Purpose** | Comprehensive user enumeration | Focused MFA security audit | Guest access governance | Critical administrative access audit | Privileged role assignment audit | Service account security audit | Application registration security audit | Security policy gap analysis | Scoped admin access audit | Account hygiene audit | Device trust and compliance audit | SSPR configuration audit | Password policy security audit | Legacy authentication security audit | License and SKU analysis | Directory sync status and health audit | Power Platform enumeration and security audit | Group security analysis and governance | Attack path analysis - privilege escalation and lateral movement | Multi-tenant Azure RBAC baseline export and drift detection | OAuth consent grant audit - illicit consent detection |
| User Enumeration | 15+ methods | Standard method | Guest-focused | App assignment-based | Role assignment-based | Service principal-focused | | | | | | Legacy auth-focused | Sync-focused | ❌ |
| MFA Detection | Basic check | Advanced with method types | Advanced with method types | Advanced with method types | Advanced with method types | Owner MFA check | | | | | | Advanced with method types | ❌ | ❌ |
| Shared Mailbox Detection | ❌ | ✅ Automatic | ❌ (N/A for guests) | ❌ (N/A for app access) | ❌ (N/A for roles) | ❌ (N/A for SPs) | | | | | | ❌ (N/A for legacy auth) | ❌ | ❌ |
| Guest Domain Extraction | ❌ | ❌ | ✅ Automatic | ❌ | ❌ | ❌ | | | | | | ❌ | ❌ | ❌ |
| Invite Status Tracking | ❌ | ❌ | ✅ With acceptance dates | ❌ | ❌ | ❌ | | | | | | ❌ | ❌ | ❌ |
| App Access Tracking | ❌ | ❌ | ❌ | ✅ Multi-app coverage | ❌ | ❌ | | | | | | ❌ | ❌ | ❌ |
| Role Assignment Tracking | ❌ | ❌ | ❌ | ❌ | ✅ All directory roles | ❌ | | | | | | ❌ | ❌ | ✅ All Azure RBAC roles |
| PIM Assignment Tracking | ❌ | ❌ | ❌ | ❌ | ✅ Eligible & Active | ❌ | | | | | | ❌ | ❌ | ❌ |
| Credential Enumeration | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Secrets & certificates | ✅ Secrets & certificates | | | | | | ❌ | ❌ | ❌ |
| Credential Expiration Tracking | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Expired & expiring soon | ✅ Expired & expiring soon | | | | | | ❌ | ❌ | ❌ |
| Permission Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ High-risk & critical | ✅ High-risk & critical (API permissions) | | | | | | ❌ | ❌ | ✅ RBAC role permissions |
| Owner Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ With MFA status | ✅ With MFA status | ❌ | | | | | ❌ | ❌ | ✅ Group owners with MFA status | ❌ |
| Application Registration Enumeration | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Comprehensive | | | | | | ❌ | ❌ | ❌ |
| API Permission Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Delegated & application | | | | | | ❌ | ❌ | ❌ |
| Assignment Date Tracking | ❌ | ❌ | ✅ Invite dates | ✅ Assignment dates | ✅ Assignment dates & duration | ❌ | ❌ | | | | | ❌ | ❌ | ✅ Role assignment creation dates |
| Policy Exclusion Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Users, groups, roles, apps | | | | | ❌ | ❌ | ❌ |
| MFA Enforcement Gaps | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Policy-level analysis | | | | | ❌ | ❌ | ❌ |
| Critical App Coverage | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 10 critical apps | | | | | ❌ | ❌ | ❌ |
| Legacy Auth Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Policy targeting | | | | | ✅ 10 protocols | ❌ | ❌ |
| Legacy Protocol Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | | | | ✅ IMAP/POP3/SMTP/EAS/etc | ❌ | ❌ |
| Last Legacy Auth Usage | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | | | | ✅ Date/time tracking | ❌ | ❌ |
| Protocol Statistics | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | | | | ✅ Success/failure counts | ❌ | ❌ |
| Policy Conflict Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Redundant/conflicting | ❌ | ❌ | ❌ | | | ❌ | ❌ | ❌ |
| Administrative Unit Enumeration | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Comprehensive | ❌ | ❌ | ❌ | | | ❌ | ❌ | ❌ |
| Scoped Role Assignment Analysis | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ All scoped assignments | ❌ | ❌ | ❌ | | | ❌ | ❌ | ❌ |
| AU Member Enumeration | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Members and roles | ❌ | ❌ | ❌ | | | ❌ | ❌ | ❌ |
| Stale Account Detection | Limited | Limited | Limited | Limited | Limited | ❌ | ❌ | Limited | ✅ >90 days inactive | ❌ | | | Limited | ❌ | ❌ |
| Never Signed-In Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Account age analysis | ❌ | | | ❌ | ❌ | ❌ |
| License Waste Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Disabled with licenses | ❌ | | | ❌ | ❌ | ❌ |
| Password Expiration Tracking | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Expired passwords | ❌ | ❌ | ✅ Expiration analysis | ❌ | ❌ | ❌ |
| SSPR Status Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Enabled/Registered/Capable | ❌ | ❌ | ❌ | ❌ |
| SSPR Method Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Registration methods | ❌ | ❌ | ❌ | ❌ |
| Backup Method Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ No backup methods | ❌ | ❌ | ❌ | ❌ |
| Strong Method Classification | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Strong vs weak methods | ❌ | ❌ | ❌ | ❌ |
| Device Enumeration | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Comprehensive | ❌ | ❌ | ❌ | ❌ | ❌ |
| Compliance Status Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | ✅ Compliant/Non-compliant/Unknown | | | ❌ | ❌ | ❌ |
| BYOD Detection | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | ✅ Automatic | | | ❌ | ❌ | ❌ |
| Stale Sign-In Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | ✅ >90 days | ✅ >90 days | | | Limited | ❌ | ❌ |
| Intune Compliance Policies | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Full enumeration | | | ❌ | ❌ | ❌ |
| Device Trust Analysis | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Join types | | | ❌ | ❌ | ❌ |
| Management Status | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Managed/Unmanaged | | | ❌ | ❌ | ❌ |
| Last Sign-In Tracking | ✅ | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics | Limited (SP activity) | ❌ | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics | ❌ |
| Sign-In Capability Check | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Sync Status Detection | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Synced vs Cloud-Only | ❌ |
| Sync Error Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ All provisioning errors | ❌ |
| Stale Sync Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ >7 days since sync | ❌ |
| Sync Conflict Identification | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Duplicate attributes | ❌ |
| Sync Scope Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Basic configuration | ❌ |
| Tenant SKU Enumeration | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Full enumeration | ❌ | ❌ |
| License Assignment Tracking | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ All assignments | ❌ | ❌ |
| Privileged License Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ E5, P2, etc. | ❌ | ❌ |
| Unused License Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Disabled with licenses | ❌ | ❌ | ❌ | ❌ | ✅ Never signed in | ❌ | ❌ |
| License Usage Analytics | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Consumption stats | ❌ | ❌ | ❌ |
| Power Apps Enumeration | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Comprehensive | ❌ |
| Power Automate Flow Enumeration | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Comprehensive | ❌ |
| Sensitive Connector Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 30+ connectors | ❌ |
| High-Risk Action Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Delete/Create/Modify | ❌ |
| Connector Risk Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ CRITICAL/HIGH/MEDIUM/LOW | ❌ | ❌ |
| Group Enumeration | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Comprehensive (all types) | ❌ |
| No Owner Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Orphaned groups | ❌ |
| Excessive Membership Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ >100 or >500 members | ❌ |
| Role-Assignable Group Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ CRITICAL risk groups | ❌ |
| Group Type Analysis | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Security/M365/Distribution/Dynamic | ❌ |
| OAuth Consent Grant Enumeration | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ All OAuth2PermissionGrants |
| Admin vs User Consent Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Tenant-wide vs individual |
| Dangerous Permission Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Mail/Files/Directory access |
| Stale Consent Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Configurable threshold |
| Third-Party App Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Microsoft vs third-party |
| Publisher Verification | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Verified publisher status |
| Multi-Tenant Scanning | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ All accessible tenants | ❌ |
| Skip Failed Tenants | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Continue on MFA/CA failures | ❌ |
| Azure RBAC Baseline Export | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ JSON baseline | ❌ |
| Azure RBAC Drift Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ New/Removed/Modified assignments | ❌ |
| Multi-Subscription Support | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ All subscriptions across tenants | ❌ |
| Group Member Expansion | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Expand groups to show users | ❌ |
| All Users Permissions Matrix | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ User-centric permission view | ❌ |
| Scope Hierarchy Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Sub/RG/Resource | ❌ |
| PIM/JIT Exclusion | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Exclude time-bounded assignments | ❌ |
| ABAC Condition Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Condition mismatch drift | ❌ |
| Remediation Instructions | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Terraform/CLI/PowerShell | ❌ |
| Risk Level Assessment | Basic | Advanced (HIGH/MEDIUM/LOW) | Advanced (HIGH/MEDIUM/LOW) | Advanced (HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) |
| Activity Analytics | Limited | Detailed (stale/recent/never) | Detailed (stale/recent/never) | Detailed (stale/recent/never) | Detailed (stale/recent/never) | Basic (age-based) | Detailed (credential expiration/permission analysis) | Policy gap analysis | Detailed (scoped admin activity) | Detailed (stale indicators) | Detailed (stale/recent/never) | Detailed (stale/recent/never) | Detailed (password age/policy gaps) | Detailed (usage recency/protocol stats) | Detailed (license usage/unused tracking) | Detailed (sync health/error stats) | Detailed (resource/environment/owner stats) | Detailed (group type/owner/membership stats) | Detailed (attack path type/complexity/risk stats) | Detailed (drift type/role/tenant/subscription stats) | Detailed (consent type/permission/stale stats) |
| Matrix View | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Department Analysis | ✅ | ✅ With statistics | ✅ With statistics | ✅ With statistics | ✅ With statistics | ❌ | ❌ | ✅ With statistics | ✅ With statistics | ❌ | ✅ With statistics | ✅ With statistics | ✅ With statistics | ✅ With statistics | ✅ With statistics | ❌ | ❌ | ❌ | ❌ | ❌ |
| BloodHound Export | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| HTML Report | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CSV/JSON Export | ✅ | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ JSON baseline/drift report | ✅ Enhanced fields |
| Stealth Mode | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Best For** | Red team reconnaissance | MFA compliance audits | External user security | Privileged access audit | Privileged role governance | Service account security | Application registration security & credential management | Security policy gap analysis | Scoped admin access governance | Account hygiene & cleanup | Device trust and compliance | Password reset security | Password policy compliance | Legacy auth migration & security | License governance & cost optimization | Directory sync health & error tracking | Power Platform security & connector governance | Group security & governance | Attack path analysis & privilege escalation detection | Multi-tenant Azure RBAC governance & unauthorized access detection | OAuth consent security & illicit consent grant detection |

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

**MFA Security Check, Guest Account Enumeration, Critical Admin Access Check, Privileged Role Check, Service Principal Check, Application Registration Check, Conditional Access Check, Administrative Unit Check, Stale Account Check, Device Trust Check, SSPR Check, Password Policy Check, Legacy Auth Check, License Check, Directory Sync Check, Power Platform Check, and Group Security Check:** Require Microsoft Graph PowerShell SDK:

**Azure RBAC Check:** Requires Azure PowerShell modules:

```powershell
Install-Module Az -Scope CurrentUser
```

Or install individual modules:

```powershell
Install-Module Az.Accounts -Scope CurrentUser
Install-Module Az.Resources -Scope CurrentUser
```

**Other tools:**

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
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
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

## Script Authentication & Permissions Reference

This section provides a comprehensive matrix of authentication methods and API permissions required by each script in the toolkit.

### Authentication Methods by Script Category

All scripts support the same core authentication methods, with slight variations based on the target API:

#### Microsoft Graph Scripts (Entra ID)

| Parameter | Method | Description |
|-----------|--------|-------------|
| *(default)* | Interactive | `Connect-MgGraph` with interactive OAuth browser prompt |
| `-UseAzCliToken` | Azure CLI Token | Uses `az account get-access-token --resource https://graph.microsoft.com` |
| `-UseAzPowerShellToken` | Azure PowerShell Token | Uses `Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"` |

**Scripts:** EntraRecon, EntraMFACheck, EntraGuestCheck, EntraAppAccess, EntraRoleCheck, EntraServicePrincipalCheck, EntraConditionalAccessCheck, EntraAdminUnitCheck, EntraStaleAccountCheck, EntraDeviceCheck, EntraSSPRCheck, EntraPasswordPolicyCheck, EntraLegacyAuthCheck, EntraLicenseCheck, EntraDirectorySyncCheck, EntraPowerPlatformCheck, EntraGroupCheck, EntraApplicationCheck, EntraAttackPathCheck, EntraOAuthConsentCheck, EntraSignInRiskCheck, EntraPIMCheck, EntraComplianceCheck

#### Azure Resource Scripts (ARM)

| Parameter | Method | Description |
|-----------|--------|-------------|
| *(default)* | Interactive | `Connect-AzAccount` with interactive browser prompt |
| `-UseAzCliToken` | Azure CLI Token | Uses existing `az login` session |
| `-UseAzPowerShellToken` | Azure PowerShell Token | Uses existing `Connect-AzAccount` session |
| `-UseDeviceCode` | Device Code Flow | `Connect-AzAccount -UseDeviceAuthentication` for headless terminals |

**Scripts:** EntraAzureRBACCheck, EntraKeyVaultCheck, EntraStorageAccountCheck, EntraManagedIdentityCheck, EntraNetworkSecurityCheck, EntraAzureAttackPathCheck

#### Microsoft 365 Service Scripts

| Script | Module | Authentication |
|--------|--------|----------------|
| EntraExchangeCheck | ExchangeOnlineManagement | `Connect-ExchangeOnline` (requires Exchange Administrator role) |
| EntraSharePointCheck | Microsoft.Online.SharePoint.PowerShell | `Connect-SPOService` to SharePoint Admin URL (requires SharePoint Administrator role) |
| EntraTeamsCheck | MicrosoftTeams | `Connect-MicrosoftTeams` (requires Teams Administrator role) |

---

### Microsoft Graph Permission Scopes by Script

The following table shows the required and fallback scopes for each Microsoft Graph-based script. Fallback scopes are used when the user doesn't have permissions for the full required scope set.

| Script | Required Scopes | Fallback Scopes |
|--------|-----------------|-----------------|
| **Invoke-EntraApplicationCheck** | `Application.Read.All`, `Directory.Read.All`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All` | `Application.Read.All`, `Directory.Read.All`, `User.ReadBasic.All` |
| **Invoke-EntraRoleCheck** | `Directory.Read.All`, `RoleManagement.Read.Directory`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All` | `Directory.Read.All`, `RoleManagement.Read.Directory`, `User.ReadBasic.All` |
| **Invoke-EntraMFACheck** | `User.Read.All`, `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All` | `User.ReadBasic.All`, `UserAuthenticationMethod.Read.All` |
| **Invoke-EntraGroupCheck** | `Directory.Read.All`, `Group.Read.All`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All` | `Directory.Read.All`, `Group.Read.All`, `User.ReadBasic.All` |
| **Invoke-EntraGuestCheck** | `User.Read.All`, `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All` | `User.ReadBasic.All`, `UserAuthenticationMethod.Read.All` |
| **Invoke-EntraAdminUnitCheck** | `Directory.Read.All`, `AdministrativeUnit.Read.All`, `RoleManagement.Read.Directory`, `User.Read.All`, `UserAuthenticationMethod.Read.All` | `Directory.Read.All`, `AdministrativeUnit.Read.All`, `User.ReadBasic.All` |
| **Invoke-EntraConditionalAccessCheck** | `Policy.Read.All`, `Directory.Read.All`, `Application.Read.All`, `User.Read.All` | `Policy.Read.All`, `Directory.Read.All` |
| **Invoke-EntraDeviceCheck** | `Device.Read.All`, `Directory.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All` | `Device.Read.All`, `Directory.Read.All` |
| **Invoke-EntraDirectorySyncCheck** | `Directory.Read.All`, `User.Read.All`, `AuditLog.Read.All` | `Directory.Read.All`, `User.ReadBasic.All` |
| **Invoke-EntraAttackPathCheck** | `Directory.Read.All`, `Group.Read.All`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All` | `Directory.Read.All`, `Group.Read.All`, `User.ReadBasic.All` |
| **Invoke-EntraServicePrincipalCheck** | `Application.Read.All`, `Directory.Read.All`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All` | `Application.Read.All`, `Directory.Read.All`, `User.ReadBasic.All` |
| **Invoke-EntraPasswordPolicyCheck** | `User.Read.All`, `Directory.Read.All`, `AuditLog.Read.All` | `User.ReadBasic.All`, `Directory.Read.All` |
| **Invoke-EntraLicenseCheck** | `Directory.Read.All`, `User.Read.All` | `User.ReadBasic.All` |
| **Invoke-EntraLegacyAuthCheck** | `AuditLog.Read.All`, `Directory.Read.All`, `User.Read.All`, `UserAuthenticationMethod.Read.All` | `Directory.Read.All`, `User.ReadBasic.All` |
| **Invoke-EntraSSPRCheck** | `User.Read.All`, `UserAuthenticationMethod.Read.All`, `Reports.Read.All`, `AuditLog.Read.All` | `User.ReadBasic.All`, `Reports.Read.All` |
| **Invoke-EntraStaleAccountCheck** | `User.Read.All`, `Directory.Read.All`, `AuditLog.Read.All` | `User.ReadBasic.All`, `Directory.Read.All` |
| **Invoke-EntraAppAccess** | `Application.Read.All`, `Directory.Read.All`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All` | `Application.Read.All`, `Directory.Read.All`, `User.ReadBasic.All` |
| **Invoke-EntraPIMCheck** | `Directory.Read.All`, `User.Read.All`, `RoleManagement.Read.Directory`, `PrivilegedAccess.Read.AzureAD` | `Directory.Read.All`, `User.ReadBasic.All` |
| **Invoke-EntraOAuthConsentCheck** | `Application.Read.All`, `Directory.Read.All`, `User.Read.All`, `AuditLog.Read.All` | `Application.Read.All`, `Directory.Read.All`, `User.ReadBasic.All` |
| **Invoke-EntraSignInRiskCheck** | `IdentityRiskyUser.Read.All`, `IdentityRiskySignIn.Read.All`, `IdentityRiskDetection.Read.All`, `AuditLog.Read.All`, `User.Read.All`, `Directory.Read.All` | `IdentityRiskyUser.Read.All`, `IdentityRiskySignIn.Read.All`, `IdentityRiskDetection.Read.All` |
| **Invoke-EntraPowerPlatformCheck** | `User.Read.All`, `Directory.Read.All`, `Application.Read.All` | *(Power Platform API permissions via user context)* |
| **Invoke-EntraComplianceCheck** | `Directory.Read.All`, `Policy.Read.All`, `User.Read.All`, `Application.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `UserAuthenticationMethod.Read.All` | `Directory.Read.All`, `Policy.Read.All`, `User.ReadBasic.All` |

---

### Azure Resource Scripts - Required Permissions

These scripts use Azure PowerShell (`Az` module) and require Azure RBAC permissions rather than Microsoft Graph scopes:

| Script | Azure RBAC Permissions | Additional Graph Scopes |
|--------|------------------------|------------------------|
| **Invoke-EntraAzureRBACCheck** | Reader role across target subscriptions | `User.Read`, `Directory.Read.All`, `GroupMember.Read.All` |
| **Invoke-EntraKeyVaultCheck** | Reader on subscriptions, Key Vault Reader for secret enumeration | - |
| **Invoke-EntraStorageAccountCheck** | Reader on subscriptions, Storage Blob Data Reader for container enumeration | - |
| **Invoke-EntraManagedIdentityCheck** | Reader on subscriptions | `Directory.Read.All` for Graph queries |
| **Invoke-EntraNetworkSecurityCheck** | Reader on subscriptions for NSG/VNet enumeration | - |
| **Invoke-EntraAzureAttackPathCheck** | Reader on subscriptions, Key Vault Reader for access policy enumeration | - |

---

### Microsoft 365 Service Scripts - Required Permissions

| Script | Module | Required Roles/Permissions |
|--------|--------|---------------------------|
| **Invoke-EntraExchangeCheck** | ExchangeOnlineManagement | Exchange Administrator or equivalent. Required for: `Get-InboxRule`, `Get-TransportRule`, `Get-MailboxPermission`, `Get-Mailbox` |
| **Invoke-EntraSharePointCheck** | Microsoft.Online.SharePoint.PowerShell | SharePoint Administrator or equivalent. Required for: `Get-SPOTenant`, `Get-SPOSite`, sharing configuration cmdlets |
| **Invoke-EntraTeamsCheck** | MicrosoftTeams | Teams Administrator or equivalent. Required for: `Get-CsTenantFederationConfiguration`, `Get-CsTeamsMeetingPolicy`, `Get-CsTeamsClientConfiguration`, `Get-Team` |

---

### Most Commonly Required Scopes

The following Microsoft Graph scopes are most frequently required across the toolkit:

| Scope | Scripts Using | Purpose |
|-------|---------------|---------|
| `Directory.Read.All` | 21+ scripts | Read directory objects (users, groups, roles, settings) |
| `User.Read.All` | 19+ scripts | Read all user properties including sign-in activity |
| `AuditLog.Read.All` | 16+ scripts | Read sign-in logs, audit logs, activity reports |
| `UserAuthenticationMethod.Read.All` | 13+ scripts | Check MFA registration and authentication methods |
| `Application.Read.All` | 7 scripts | Read app registrations and service principals |
| `Group.Read.All` | 4 scripts | Read group memberships and properties |
| `RoleManagement.Read.Directory` | 5 scripts | Read directory role assignments and PIM configuration |
| `Policy.Read.All` | 3 scripts | Read Conditional Access policies and security defaults |
| `Device.Read.All` | 1 script | Read device registrations |
| `AdministrativeUnit.Read.All` | 1 script | Read Administrative Units |
| `PrivilegedAccess.Read.AzureAD` | 1 script | Read PIM role settings and assignments |
| `IdentityRiskyUser.Read.All` | 2 scripts | Read Identity Protection risky users |
| `IdentityRiskySignIn.Read.All` | 1 script | Read Identity Protection risky sign-ins |
| `IdentityRiskEvent.Read.All` | 2 scripts | Read Identity Protection risk events and detections |
| `Reports.Read.All` | 1 script | Read usage reports (SSPR) |
| `DeviceManagementManagedDevices.Read.All` | 1 script | Read Intune managed devices |
| `DeviceManagementConfiguration.Read.All` | 1 script | Read Intune compliance policies |

---

### Minimum Permission Set for Full Toolkit

To run all scripts with full functionality, the following consolidated permission set is recommended:

**Microsoft Graph (Delegated Permissions):**
```
Application.Read.All
AuditLog.Read.All
AdministrativeUnit.Read.All
Device.Read.All
DeviceManagementConfiguration.Read.All
DeviceManagementManagedDevices.Read.All
Directory.Read.All
Group.Read.All
GroupMember.Read.All
IdentityRiskDetection.Read.All
IdentityRiskySignIn.Read.All
IdentityRiskyUser.Read.All
Policy.Read.All
PrivilegedAccess.Read.AzureAD
Reports.Read.All
RoleManagement.Read.Directory
User.Read.All
UserAuthenticationMethod.Read.All
```

**Azure RBAC:**
- Reader role at subscription or management group level (for Azure resource scripts)
- Key Vault Reader (for EntraKeyVaultCheck with secret enumeration)
- Storage Blob Data Reader (for EntraStorageAccountCheck with container enumeration)

**Microsoft 365 Admin Roles:**
- Exchange Administrator (for EntraExchangeCheck)
- SharePoint Administrator (for EntraSharePointCheck)
- Teams Administrator (for EntraTeamsCheck)

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
