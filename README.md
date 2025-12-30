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

**Available scripts:** EntraRecon, EntraMFACheck, EntraGuestCheck, EntraAppAccess, EntraRoleCheck, EntraServicePrincipalCheck, EntraConditionalAccessCheck, EntraAdminUnitCheck, EntraStaleAccountCheck, EntraDeviceCheck, EntraSSPRCheck, EntraPasswordPolicyCheck, EntraLegacyAuthCheck, EntraLicenseCheck

### Enumerate-EntraUsers (PowerShell)

**Requirements:** PowerShell 7+

```powershell
# Using dispatcher (recommended)
.\Invoke-EvilMist.ps1 -Script EntraRecon

# Or directly from subfolder
.\scripts\powershell\Invoke-EntraRecon.ps1

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
.\scripts\powershell\Invoke-EntraGuestCheck.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraGuestCheck.ps1 -ExportPath "guest-accounts.csv"

# Show only guests without MFA in matrix view
.\scripts\powershell\Invoke-EntraGuestCheck.ps1 -Matrix -OnlyNoMFA

# Include disabled guests with stealth mode
.\scripts\powershell\Invoke-EntraGuestCheck.ps1 -IncludeDisabledGuests -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraGuestCheck-PS1.md](docs/EntraGuestCheck-PS1.md)

### Critical Administrative Access Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check users with critical administrative access (10 apps)
.\scripts\powershell\Invoke-EntraAppAccess.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -ExportPath "app-access.csv"

# Show only users without MFA in matrix view
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -Matrix -OnlyNoMFA

# Stealth mode scan
.\scripts\powershell\Invoke-EntraAppAccess.ps1 -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraAppAccess-PS1.md](docs/EntraAppAccess-PS1.md)

### Privileged Role Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check users with privileged directory roles
.\scripts\powershell\Invoke-EntraRoleCheck.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -ExportPath "privileged-roles.csv"

# Show only users without MFA in matrix view
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -Matrix -OnlyNoMFA

# Show only permanent (non-PIM) assignments
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -OnlyPermanent -ExportPath "permanent-admins.csv"

# Stealth mode scan
.\scripts\powershell\Invoke-EntraRoleCheck.ps1 -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraRoleCheck-PS1.md](docs/EntraRoleCheck-PS1.md)

### Service Principal Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Check all service principals and analyze security posture
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -ExportPath "service-principals.csv"

# Show only service principals with expired credentials in matrix view
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -Matrix -OnlyExpiredCredentials

# Show only high-permission service principals
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -OnlyHighPermission -ExportPath "high-perm-sp.csv"

# Stealth mode scan
.\scripts\powershell\Invoke-EntraServicePrincipalCheck.ps1 -EnableStealth -QuietStealth
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

### Conditional Access Policy Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Analyze all Conditional Access policies
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -ExportPath "ca-policies.csv"

# Show only policies with exclusions in matrix view
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -Matrix -OnlyWithExclusions

# Show only policies without MFA enforcement
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -OnlyMFAgaps -ExportPath "mfa-gaps.csv"

# Stealth mode scan
.\scripts\powershell\Invoke-EntraConditionalAccessCheck.ps1 -EnableStealth -QuietStealth
```

📖 **Full documentation:** [EntraConditionalAccessCheck-PS1.md](docs/EntraConditionalAccessCheck-PS1.md)

### Administrative Unit Security Check (PowerShell)

**Requirements:** PowerShell 7+, Microsoft.Graph modules

```powershell
# Analyze all Administrative Units and scoped role assignments
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -ExportPath "admin-units.csv"

# Show only scoped administrators without MFA in matrix view
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -Matrix -OnlyNoMFA

# Include disabled accounts
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -IncludeDisabledUsers -ExportPath "all-admins.csv"

# Stealth mode scan
.\scripts\powershell\Invoke-EntraAdminUnitCheck.ps1 -EnableStealth -QuietStealth
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
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -ExportPath "stale-accounts.csv"

# Include disabled accounts in matrix view
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -IncludeDisabledUsers -Matrix

# Stealth mode scan
.\scripts\powershell\Invoke-EntraStaleAccountCheck.ps1 -EnableStealth -QuietStealth
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
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -ExportPath "devices.csv"

# Show only non-compliant devices in matrix view
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -Matrix -OnlyNonCompliant

# Show only BYOD devices
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyBYOD -ExportPath "byod-devices.csv"

# Show only devices with stale sign-ins
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyStale -ExportPath "stale-devices.csv"

# Stealth mode scan
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -EnableStealth -QuietStealth
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
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -ExportPath "sspr-users.csv"

# Show only users without backup methods in matrix view
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -Matrix -OnlyNoBackup

# Include disabled users
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -IncludeDisabledUsers -ExportPath "all-sspr-users.csv"

# Stealth mode scan
.\scripts\powershell\Invoke-EntraSSPRCheck.ps1 -EnableStealth -QuietStealth
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
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -ExportPath "password-policies.csv"

# Show only users with weak password policies in matrix view
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -Matrix -OnlyWeakPolicies

# Show only users with password never expires
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -OnlyNeverExpires -ExportPath "never-expires.csv"

# Stealth mode scan
.\scripts\powershell\Invoke-EntraPasswordPolicyCheck.ps1 -EnableStealth -QuietStealth
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
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -ExportPath "legacy-auth.csv"

# Show only recent usage (last 30 days) in matrix view
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -Matrix -OnlyRecent

# Include disabled accounts
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -IncludeDisabledUsers -ExportPath "all-legacy-users.csv"

# Stealth mode scan
.\scripts\powershell\Invoke-EntraLegacyAuthCheck.ps1 -EnableStealth -QuietStealth
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
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1

# Export results to CSV
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -ExportPath "licenses.csv"

# Show only users with privileged licenses (E5, P2) in matrix view
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -Matrix -OnlyPrivilegedLicenses

# Show only unused license assignments
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -OnlyUnusedLicenses -ExportPath "unused-licenses.csv"

# Stealth mode scan
.\scripts\powershell\Invoke-EntraLicenseCheck.ps1 -EnableStealth -QuietStealth
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

| Feature | Enumerate-EntraUsers | MFA Security Check | Guest Account Enumeration | Critical Admin Access Check | Privileged Role Check | Service Principal Check | Conditional Access Check | Administrative Unit Check | Stale Account Check | Device Trust Check | SSPR Check | Password Policy Check | Legacy Auth Check | License Check |
|---------|---------------------|-------------------|---------------------------|----------------------------|----------------------|------------------------|--------------------------|------------------------|---------------------|-------------------|-------------|---------------------|-------------------|--------------|
| **Purpose** | Comprehensive user enumeration | Focused MFA security audit | Guest access governance | Critical administrative access audit | Privileged role assignment audit | Service account security audit | Security policy gap analysis | Scoped admin access audit | Account hygiene audit | Device trust and compliance audit | SSPR configuration audit | Password policy security audit | Legacy authentication security audit | License and SKU analysis |
| User Enumeration | 15+ methods | Standard method | Guest-focused | App assignment-based | Role assignment-based | Service principal-focused | | | | | | Legacy auth-focused |
| MFA Detection | Basic check | Advanced with method types | Advanced with method types | Advanced with method types | Advanced with method types | Owner MFA check | | | | | | Advanced with method types |
| Shared Mailbox Detection | ❌ | ✅ Automatic | ❌ (N/A for guests) | ❌ (N/A for app access) | ❌ (N/A for roles) | ❌ (N/A for SPs) | | | | | | ❌ (N/A for legacy auth) |
| Guest Domain Extraction | ❌ | ❌ | ✅ Automatic | ❌ | ❌ | ❌ | | | | | | ❌ |
| Invite Status Tracking | ❌ | ❌ | ✅ With acceptance dates | ❌ | ❌ | ❌ | | | | | | ❌ |
| App Access Tracking | ❌ | ❌ | ❌ | ✅ Multi-app coverage | ❌ | ❌ | | | | | | ❌ |
| Role Assignment Tracking | ❌ | ❌ | ❌ | ❌ | ✅ All directory roles | ❌ | | | | | | ❌ |
| PIM Assignment Tracking | ❌ | ❌ | ❌ | ❌ | ✅ Eligible & Active | ❌ | | | | | | ❌ |
| Credential Enumeration | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Secrets & certificates | | | | | | ❌ |
| Credential Expiration Tracking | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Expired & expiring soon | | | | | | ❌ |
| Permission Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ High-risk & critical | | | | | | ❌ |
| Owner Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ With MFA status | ❌ | | | | | ❌ |
| Assignment Date Tracking | ❌ | ❌ | ✅ Invite dates | ✅ Assignment dates | ✅ Assignment dates & duration | ❌ | ❌ | | | | | ❌ |
| Policy Exclusion Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Users, groups, roles, apps | | | | | ❌ |
| MFA Enforcement Gaps | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Policy-level analysis | | | | | ❌ |
| Critical App Coverage | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 10 critical apps | | | | | ❌ |
| Legacy Auth Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Policy targeting | | | | | ✅ 10 protocols |
| Legacy Protocol Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | | | | ✅ IMAP/POP3/SMTP/EAS/etc |
| Last Legacy Auth Usage | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | | | | ✅ Date/time tracking |
| Protocol Statistics | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | | | | ✅ Success/failure counts |
| Policy Conflict Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Redundant/conflicting | ❌ | ❌ | ❌ | | | ❌ |
| Administrative Unit Enumeration | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Comprehensive | ❌ | ❌ | ❌ | | | ❌ |
| Scoped Role Assignment Analysis | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ All scoped assignments | ❌ | ❌ | ❌ | | | ❌ |
| AU Member Enumeration | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Members and roles | ❌ | ❌ | ❌ | | | ❌ |
| Stale Account Detection | Limited | Limited | Limited | Limited | Limited | ❌ | ❌ | Limited | ✅ >90 days inactive | ❌ | | | Limited |
| Never Signed-In Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Account age analysis | ❌ | | | ❌ |
| License Waste Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Disabled with licenses | ❌ | | | ❌ |
| Password Expiration Tracking | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Expired passwords | ❌ | ❌ | ✅ Expiration analysis | ❌ |
| SSPR Status Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Enabled/Registered/Capable | ❌ | ❌ |
| SSPR Method Analysis | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Registration methods | ❌ | ❌ |
| Backup Method Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ No backup methods | ❌ | ❌ |
| Strong Method Classification | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Strong vs weak methods | ❌ | ❌ |
| Device Enumeration | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Comprehensive | ❌ | ❌ | ❌ |
| Compliance Status Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | ✅ Compliant/Non-compliant/Unknown | | | ❌ |
| BYOD Detection | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | ✅ Automatic | | | ❌ |
| Stale Sign-In Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | | ✅ >90 days | ✅ >90 days | | | Limited |
| Intune Compliance Policies | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Full enumeration | | | ❌ |
| Device Trust Analysis | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Join types | | | ❌ |
| Management Status | ✅ Basic | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Managed/Unmanaged | | | ❌ |
| Last Sign-In Tracking | ✅ | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics | Limited (SP activity) | ❌ | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics | ✅ With analytics |
| Sign-In Capability Check | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Tenant SKU Enumeration | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Full enumeration |
| License Assignment Tracking | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ All assignments |
| Privileged License Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ E5, P2, etc. |
| Unused License Detection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Disabled with licenses | ❌ | ❌ | ❌ | ❌ | ✅ Never signed in |
| License Usage Analytics | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Consumption stats |
| Risk Level Assessment | Basic | Advanced (HIGH/MEDIUM/LOW) | Advanced (HIGH/MEDIUM/LOW) | Advanced (HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) | Advanced (CRITICAL/HIGH/MEDIUM/LOW) |
| Activity Analytics | Limited | Detailed (stale/recent/never) | Detailed (stale/recent/never) | Detailed (stale/recent/never) | Detailed (stale/recent/never) | Basic (age-based) | Policy gap analysis | Detailed (scoped admin activity) | Detailed (stale indicators) | Detailed (stale/recent/never) | Detailed (stale/recent/never) | Detailed (password age/policy gaps) | Detailed (usage recency/protocol stats) | Detailed (license usage/unused tracking) |
| Matrix View | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Department Analysis | ✅ | ✅ With statistics | ✅ With statistics | ✅ With statistics | ✅ With statistics | ❌ | ❌ | ✅ With statistics | ✅ With statistics | ❌ | ✅ With statistics | ✅ With statistics | ✅ With statistics | ✅ With statistics |
| BloodHound Export | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| HTML Report | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CSV/JSON Export | ✅ | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields | ✅ Enhanced fields |
| Stealth Mode | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Best For** | Red team reconnaissance | MFA compliance audits | External user security | Privileged access audit | Privileged role governance | Service account security | Security policy gap analysis | Scoped admin access governance | Account hygiene & cleanup | Device trust and compliance | Password reset security | Password policy compliance | Legacy auth migration & security | License governance & cost optimization |

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

**MFA Security Check, Guest Account Enumeration, Critical Admin Access Check, Privileged Role Check, Service Principal Check, Conditional Access Check, Administrative Unit Check, Stale Account Check, Device Trust Check, SSPR Check, Password Policy Check, Legacy Auth Check, and License Check:** Require Microsoft Graph PowerShell SDK:

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
