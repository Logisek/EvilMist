# Invoke-EntraGuestCheck.ps1

## Overview

`Invoke-EntraGuestCheck.ps1` is a PowerShell 7+ script designed to enumerate and analyze Azure Entra ID guest user accounts. This tool is part of the EvilMist toolkit and helps security teams identify, analyze, and assess the security posture of guest accounts in their Azure AD tenant.

## Purpose

Guest accounts represent external users with access to organizational resources. This script helps:
- **Security Auditors**: Identify and analyze guest account configurations
- **Penetration Testers**: Discover potential weak points in external user access
- **IT Administrators**: Audit guest account compliance and security
- **Compliance Teams**: Generate reports for guest access governance

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Comprehensive Guest Analysis**: Detailed information about all guest accounts
- ✅ **Edge Case Detection**: Identifies external users with UserType='Member' (cross-tenant sync, converted guests)
- ✅ **Count Verification**: Validates results against Azure Entra ID reporting
- ✅ **MFA Status Detection**: Identifies guests without Multi-Factor Authentication
- ✅ **Last Sign-In Tracking**: Shows last login date/time and activity patterns
- ✅ **Guest Domain Extraction**: Identifies originating domains of guest users
- ✅ **Invite Status Tracking**: Shows accepted, pending, or expired invites
- ✅ **Risk Assessment**: Categorizes guests by risk level (HIGH/MEDIUM/LOW)
- ✅ **Activity Analytics**: Sign-in statistics, stale accounts, never-used invites
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only guests without MFA or include disabled accounts

## Requirements

### Prerequisites

1. **PowerShell 7+**
   - Download: https://aka.ms/powershell-release?tag=stable
   - The script will check and warn if older version is detected

2. **Microsoft Graph PowerShell SDK**
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```
   
   Or install individual modules:
   ```powershell
   Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
   Install-Module Microsoft.Graph.Users -Scope CurrentUser
   Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
   ```

### Required Permissions

The script requires the following Microsoft Graph API permissions:

- **Primary Scopes** (preferred):
  - `User.Read.All` - Read all user profiles
  - `UserAuthenticationMethod.Read.All` - Read authentication methods
  - `AuditLog.Read.All` - Read audit logs and sign-in activity (optional)

- **Fallback Scopes** (if full access unavailable):
  - `User.ReadBasic.All` - Read basic user info
  - `UserAuthenticationMethod.Read.All` - Read authentication methods

**Note**: If `AuditLog.Read.All` is not available, the script will automatically fall back to retrieving guests without sign-in activity data. All other features will continue to work normally.

## Usage

### Basic Usage

```powershell
# Simple scan of all enabled guest users
.\Invoke-EntraGuestCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\Invoke-EntraGuestCheck.ps1 -ExportPath "guest-accounts.csv"

# Export to JSON
.\Invoke-EntraGuestCheck.ps1 -ExportPath "guest-results.json"
```

### Include Disabled Guest Accounts

```powershell
# Scan all guest users including disabled accounts
.\Invoke-EntraGuestCheck.ps1 -IncludeDisabledGuests -ExportPath "all-guests.csv"
```

### Show Only Guests Without MFA

```powershell
# Filter to show only guests without MFA
.\Invoke-EntraGuestCheck.ps1 -OnlyNoMFA

# Matrix view with MFA filter
.\Invoke-EntraGuestCheck.ps1 -Matrix -OnlyNoMFA -ExportPath "guests-no-mfa.csv"
```

### Matrix Display

```powershell
# Display results in matrix/table format
.\Invoke-EntraGuestCheck.ps1 -Matrix

# Matrix view with export
.\Invoke-EntraGuestCheck.ps1 -Matrix -ExportPath "guest-matrix.csv"

# Matrix view with all options
.\Invoke-EntraGuestCheck.ps1 -Matrix -IncludeDisabledGuests -EnableStealth
```

### Specify Tenant

```powershell
# Target a specific tenant
.\Invoke-EntraGuestCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.csv"
```

### Use Existing Token

```powershell
# Use Azure CLI cached token
.\Invoke-EntraGuestCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached token
.\Invoke-EntraGuestCheck.ps1 -UseAzPowerShellToken
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms + 300ms jitter)
.\Invoke-EntraGuestCheck.ps1 -EnableStealth

# Custom stealth settings
.\Invoke-EntraGuestCheck.ps1 -RequestDelay 2 -RequestJitter 1

# Stealth mode without verbose output
.\Invoke-EntraGuestCheck.ps1 -EnableStealth -QuietStealth -ExportPath "guests.json"
```

### Combined Options

```powershell
# Full featured scan
.\Invoke-EntraGuestCheck.ps1 `
    -TenantId "your-tenant-id" `
    -IncludeDisabledGuests `
    -EnableStealth `
    -QuietStealth `
    -ExportPath "comprehensive-guest-audit.csv"

# Security-focused scan (high-risk guests only)
.\Invoke-EntraGuestCheck.ps1 `
    -OnlyNoMFA `
    -Matrix `
    -ExportPath "high-risk-guests.csv"
```

## Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `ExportPath` | String | Path to export results (CSV or JSON) | None |
| `TenantId` | String | Specific tenant ID to query | Current user's tenant |
| `UseAzCliToken` | Switch | Use Azure CLI cached token | False |
| `UseAzPowerShellToken` | Switch | Use Azure PowerShell cached token | False |
| `EnableStealth` | Switch | Enable stealth mode with defaults | False |
| `RequestDelay` | Double | Base delay between requests (0-60s) | 0 |
| `RequestJitter` | Double | Random jitter range (0-30s) | 0 |
| `MaxRetries` | Int | Max retries on throttling (1-10) | 3 |
| `QuietStealth` | Switch | Suppress stealth status messages | False |
| `IncludeDisabledGuests` | Switch | Include disabled guest accounts | False |
| `OnlyNoMFA` | Switch | Show only guests without MFA | False |
| `Matrix` | Switch | Display results in matrix/table format | False |

## Guest Account Analysis

### Information Collected

For each guest account, the script collects:

**Identity Information:**
- Display name and User Principal Name
- Email address
- Guest domain (originating organization)
- Company name

**Account Status:**
- Account enabled/disabled status
- Invite status (Accepted/Pending/Unknown)
- Sign-in capability assessment
- Creation date and account age

**Security Assessment:**
- MFA status and authentication methods
- Last sign-in date and activity type
- Days since last sign-in
- Risk level categorization

**Additional Details:**
- Job title and department
- License assignments
- Invite acceptance date
- Days since invite acceptance

### Guest Domain Extraction

The script automatically extracts the originating domain from guest UPNs:
- Format: `user_domain.com#EXT#@tenant.onmicrosoft.com`
- Extracted: `domain.com`
- Used for organization analysis and reporting

### Edge Case Detection

The script goes beyond standard `UserType='Guest'` filtering to detect:

**External users with UserType='Member'** - These edge cases include:
- Cross-tenant synchronized accounts
- Converted guest accounts (Guest → Member)
- B2B users with modified UserType

**Detection Indicators:**
- UPN contains `#EXT#` pattern
- Has `ExternalUserState` property
- External domain patterns in UPN

**Why This Matters:**
Standard Azure portal filtering only shows `UserType='Guest'`, but external users can exist with `UserType='Member'`. This script catches these edge cases to ensure complete visibility of all external access.

### Count Verification

After scanning, the script automatically verifies the results:

1. **Queries Azure Entra ID** for total Guest UserType count
2. **Compares with script results** to ensure completeness
3. **Reports discrepancies** if any users are missing
4. **Highlights edge cases** found (Member UserType with external indicators)

**Example Output:**
```
[*] Verifying guest account count...
[*] Azure reports 15 users with UserType='Guest'
[*] Script found:
    - Standard guests (UserType=Guest): 15
    - Edge case external users (UserType=Member): 2
    - Total captured: 17
[+] Guest count verified! All guests captured.
[!] IMPORTANT: Found 2 external users with UserType='Member'
    These are likely cross-tenant sync or converted guest accounts
```

### Invite Status

**Accepted**: Guest has accepted the invitation and can sign in
**PendingAcceptance**: Invitation sent but not yet accepted
**Unknown**: Status cannot be determined

### Risk Levels

- **HIGH**: Active guest account without MFA (immediate security risk)
- **MEDIUM**: Pending invites or limited access guests
- **LOW**: Guests with MFA enabled or disabled accounts

## MFA Detection

The script checks for the following MFA methods:

### Strong MFA Methods (MFA Enabled)
- **Phone Authentication** - SMS or voice call
- **Microsoft Authenticator App** - Push notifications or TOTP
- **FIDO2 Security Key** - Hardware security keys
- **Windows Hello for Business** - Biometric or PIN
- **Software OATH Tokens** - Time-based tokens

### Weak/Non-MFA Methods
- **Email Authentication** - Not considered strong MFA
- **Password Only** - No MFA configured

## Output

### Console Output

The script provides detailed console output including:
- Connection status and authentication details
- Progress indicators during scanning
- Summary statistics by risk level and MFA status
- Detailed guest account information
- Domain and invite status breakdowns

### Standard View vs Matrix View

**Standard View** (default):
- Detailed information for each guest
- Full field display with descriptions
- Better for thorough investigation
- Easier to read for small result sets

**Matrix View** (`-Matrix` parameter):
- Compact tabular format
- Quick visual scanning
- Additional analytics and summaries
- Better for large result sets
- Domain and invite status breakdowns
- Color-coded risk levels

### Matrix View

When using the `-Matrix` parameter, results are displayed in a formatted table with additional analytics:

**Matrix Table Columns:**
- Risk level (HIGH/MEDIUM/LOW)
- MFA status (Yes/No)
- Account status (Enabled/Disabled)
- Invite status (Accepted/Pending)
- User Principal Name
- Display Name
- Guest Domain
- Last Sign-In (with days ago)
- Company Name

**Additional Analytics:**
- Summary statistics by risk level
- MFA status breakdown
- Top guest domains (organizations)
- Invite status distribution
- Sign-in activity statistics (never/recent/stale)
- Color-coded rows for easy identification:
  - 🔴 RED: HIGH risk guests (active without MFA)
  - 🟡 YELLOW: MEDIUM risk guests (pending/limited)
  - 🟢 GREEN: LOW risk (MFA enabled/disabled)
  - 🔵 CYAN: Headers and separators

**Example Matrix Output:**
```
========================================================================================
MATRIX VIEW - GUEST ACCOUNTS
========================================================================================

Risk   MFA Status  Invite    User Principal Name                Display Name      Guest Domain      Last Sign-In
----   --- ------  ------    -------------------                ------------      ------------      ------------
HIGH   No  Enabled Accepted  john_contoso.com#EXT#@...         John Doe          contoso.com       5d ago
LOW    Yes Enabled Accepted  jane_partner.com#EXT#@...         Jane Smith        partner.com       Today
MEDIUM No  Enabled Pending   bob_vendor.com#EXT#@...           Bob Wilson        vendor.com        Never
LOW    No  Disabled Accepted old_user.com#EXT#@...             Old User          oldcorp.com       120d ago

[SUMMARY]
Total guest accounts found: 4
  - HIGH risk (active without MFA): 1
  - MEDIUM risk (pending/limited): 1
  - LOW risk (secure/disabled): 2

[MFA STATUS]
  With MFA enabled: 1
  Without MFA: 3

[TOP GUEST DOMAINS]
  contoso.com: 1
  partner.com: 1
  vendor.com: 1

[INVITE STATUS]
  Accepted: 3
  PendingAcceptance: 1

[SIGN-IN ACTIVITY]
  Never signed in: 1
  Recent (≤30 days): 2
  Stale (>90 days): 1
```

### Export Formats

#### CSV Export
```csv
DisplayName,UserPrincipalName,Email,GuestDomain,CompanyName,AccountEnabled,CanSignIn,InviteStatus,JobTitle,Department,CreatedDateTime,DaysOld,InviteAcceptedDate,DaysSinceAccepted,LastSignIn,LastSignInDisplay,DaysSinceLastSignIn,SignInType,MFAEnabled,AuthMethods,MethodCount,HasLicenses,LicenseCount,RiskLevel,UserType,IsEdgeCase,EdgeCaseIndicators
John Doe,john_contoso.com#EXT#@tenant.onmicrosoft.com,john@contoso.com,contoso.com,Contoso Corp,True,True,Accepted,Consultant,IT,2024-01-15,342,2024-01-16,341,2024-12-17,2024-12-17 10:30:00 (5 days ago),5,Interactive,False,Password Only,1,False,0,HIGH,Guest,False,
Jane Smith,jane_partner.com#EXT#@tenant.onmicrosoft.com,jane@partner.com,partner.com,Partner Corp,True,True,External (Converted/Synced),,Marketing,2023-06-10,560,,,2024-12-20,2024-12-20 14:00:00 (2 days ago),2,Interactive,True,Phone; Authenticator App,3,True,1,LOW,Member,True,UPN contains #EXT#; Has ExternalUserState
```

#### JSON Export
```json
[
  {
    "DisplayName": "John Doe",
    "UserPrincipalName": "john_contoso.com#EXT#@tenant.onmicrosoft.com",
    "Email": "john@contoso.com",
    "GuestDomain": "contoso.com",
    "CompanyName": "Contoso Corp",
    "AccountEnabled": true,
    "CanSignIn": true,
    "InviteStatus": "Accepted",
    "JobTitle": "Consultant",
    "Department": "IT",
    "CreatedDateTime": "2024-01-15T10:30:00Z",
    "DaysOld": 342,
    "InviteAcceptedDate": "2024-01-16T08:00:00Z",
    "DaysSinceAccepted": 341,
    "LastSignIn": "2024-12-17T10:30:00Z",
    "LastSignInDisplay": "2024-12-17 10:30:00 (5 days ago)",
    "DaysSinceLastSignIn": 5,
    "SignInType": "Interactive",
    "MFAEnabled": false,
    "AuthMethods": "Password Only",
    "MethodCount": 1,
    "HasLicenses": false,
    "LicenseCount": 0,
    "RiskLevel": "HIGH",
    "UserType": "Guest",
    "IsEdgeCase": false,
    "EdgeCaseIndicators": ""
  },
  {
    "DisplayName": "Jane Smith",
    "UserPrincipalName": "jane_partner.com#EXT#@tenant.onmicrosoft.com",
    "Email": "jane@partner.com",
    "GuestDomain": "partner.com",
    "CompanyName": "Partner Corp",
    "AccountEnabled": true,
    "CanSignIn": true,
    "InviteStatus": "External (Converted/Synced)",
    "JobTitle": null,
    "Department": "Marketing",
    "CreatedDateTime": "2023-06-10T08:00:00Z",
    "DaysOld": 560,
    "InviteAcceptedDate": null,
    "DaysSinceAccepted": -1,
    "LastSignIn": "2024-12-20T14:00:00Z",
    "LastSignInDisplay": "2024-12-20 14:00:00 (2 days ago)",
    "DaysSinceLastSignIn": 2,
    "SignInType": "Interactive",
    "MFAEnabled": true,
    "AuthMethods": "Phone, Authenticator App",
    "MethodCount": 3,
    "HasLicenses": true,
    "LicenseCount": 1,
    "RiskLevel": "LOW",
    "UserType": "Member",
    "IsEdgeCase": true,
    "EdgeCaseIndicators": "UPN contains #EXT#; Has ExternalUserState"
  }
]
```

## Stealth & Evasion

The script includes built-in stealth features to avoid detection:

### Stealth Mode Features
- **Request Delays**: Configurable delays between API calls
- **Random Jitter**: Randomized timing to appear more human
- **Retry Logic**: Automatic retry on throttling (429) responses
- **Quiet Mode**: Minimal output to reduce logging footprint

### Stealth Recommendations
```powershell
# Conservative stealth (slow but stealthy)
.\Invoke-EntraGuestCheck.ps1 -RequestDelay 3 -RequestJitter 2 -QuietStealth

# Moderate stealth (balanced)
.\Invoke-EntraGuestCheck.ps1 -EnableStealth -QuietStealth

# Fast scan (minimal stealth)
.\Invoke-EntraGuestCheck.ps1
```

## Authentication Methods

### 1. Interactive Authentication (Default)
```powershell
.\Invoke-EntraGuestCheck.ps1
```
- Opens browser for interactive login
- Uses current user's credentials
- Prompts for consent if needed

### 2. Azure CLI Token
```powershell
# Login with Azure CLI first
az login

# Run script with CLI token
.\Invoke-EntraGuestCheck.ps1 -UseAzCliToken
```

### 3. Azure PowerShell Token
```powershell
# Login with Azure PowerShell first
Connect-AzAccount

# Run script with PowerShell token
.\Invoke-EntraGuestCheck.ps1 -UseAzPowerShellToken
```

## Error Handling

The script includes comprehensive error handling:
- Module availability checks
- Authentication failures with fallback options
- API permission issues
- Network connectivity problems
- Graceful cleanup on exit

## Interpreting Results

### Understanding Guest Accounts

**What are Guest Accounts?**
Guest accounts represent external users invited to access organizational resources. They are identifiable by:
- UserType = "Guest"
- UPN format: `user_domain#EXT#@tenant.onmicrosoft.com`
- External user state tracking
- Different security considerations than member accounts

### Security Considerations

**High-Risk Indicators:**
- ❌ Guest accounts without MFA enabled
- ❌ Stale accounts with old last sign-in dates
- ❌ Accounts with excessive permissions
- ❌ Never-signed-in accounts with accepted invites

**Focus Your Remediation On:**
- 🔴 **HIGH Risk**: Active guests without MFA (require immediate action)
- 🟡 **MEDIUM Risk**: Pending invites or limited access (review and validate)
- 🟢 **LOW Risk**: Guests with MFA or disabled accounts (monitor)

### Sign-In Activity Insights

**Never Signed In:**
- Unused invitations
- Potential security gap (unmonitored access)
- Consider revoking unused invites

**Recent Sign-Ins (≤30 days):**
- Active guest users
- Highest priority for MFA enforcement
- Regular security review needed

**Stale Sign-Ins (>90 days):**
- Potentially dormant accounts
- Consider disabling or removing
- Review access permissions

### Guest Domain Analysis

Group guests by originating domain to:
- Identify partner organizations
- Assess organizational trust relationships
- Detect unusual or unexpected guest sources
- Plan bulk security policy changes per organization

## Limitations

- Requires appropriate Microsoft Graph API permissions
- Rate limiting may affect large tenants (use stealth mode)
- Some MFA methods may not be detectable with limited permissions
- Guest domain extraction is pattern-based (may not work for all UPN formats)
- Sign-in activity requires `AuditLog.Read.All` permission
- Edge case detection requires scanning all Member users (may be slower for large tenants)
- Count verification requires ConsistencyLevel eventual query support

**Note**: The script now handles edge cases automatically, including:
- ✅ External users with UserType='Member'
- ✅ Cross-tenant synchronized accounts
- ✅ Converted guest accounts
- ✅ Automatic count verification

## Security Considerations

⚠️ **Important**: This tool is designed for authorized security testing only.

### Responsible Use
- Only use on tenants where you have explicit permission
- Follow your organization's security policies
- Document all testing activities
- Report findings through proper channels

### Detection Risks
- API calls are logged in Azure AD audit logs
- High-frequency requests may trigger alerts
- Use stealth mode for less suspicious activity
- Consider running outside business hours

## Troubleshooting

### Module Not Found
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### Module Version Conflict
```powershell
# Uninstall all versions
Get-InstalledModule Microsoft.Graph* | Uninstall-Module -AllVersions -Force

# Reinstall latest version
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### Permission Denied
- Ensure your account has appropriate admin roles
- Request consent from Global Administrator
- Try with reduced scopes (fallback mode)

### Rate Limiting (429 Errors)
```powershell
# Use stealth mode to reduce rate
.\Invoke-EntraGuestCheck.ps1 -EnableStealth -MaxRetries 5
```

### "No guest users found"
- Verify the tenant has guest accounts
- Check filter parameters (try with `-IncludeDisabledGuests`)
- Verify permissions to read guest user data

## Examples

### Example 1: Basic Guest Audit
```powershell
# Scan all enabled guests and export results
.\Invoke-EntraGuestCheck.ps1 -ExportPath "guest-audit-$(Get-Date -Format 'yyyy-MM-dd').csv"
```

### Example 2: Security-Focused Scan
```powershell
# Find high-risk guests without MFA
.\Invoke-EntraGuestCheck.ps1 `
    -OnlyNoMFA `
    -Matrix `
    -ExportPath "high-risk-guests.csv"
```

### Example 3: Comprehensive Guest Analysis
```powershell
# Full tenant scan including disabled accounts
.\Invoke-EntraGuestCheck.ps1 `
    -IncludeDisabledGuests `
    -ExportPath "full-guest-inventory.json" `
    -EnableStealth
```

### Example 4: Stealth Penetration Test
```powershell
# Low-profile scan with maximum stealth
.\Invoke-EntraGuestCheck.ps1 `
    -UseAzCliToken `
    -RequestDelay 5 `
    -RequestJitter 3 `
    -QuietStealth `
    -ExportPath "pentest-guests.csv"
```

### Example 5: Multi-Tenant Assessment
```powershell
# Scan multiple tenants
$tenants = @("tenant1-id", "tenant2-id", "tenant3-id")

foreach ($tenant in $tenants) {
    .\Invoke-EntraGuestCheck.ps1 `
        -TenantId $tenant `
        -ExportPath "guests-$tenant.csv" `
        -EnableStealth
}
```

### Example 6: Quick Matrix Analysis
```powershell
# Quick visual analysis with matrix display
.\Invoke-EntraGuestCheck.ps1 -Matrix

# Matrix view showing only guests without MFA
.\Invoke-EntraGuestCheck.ps1 `
    -Matrix `
    -OnlyNoMFA `
    -ExportPath "guests-no-mfa-matrix.csv"
```

## Integration

### Import Results for Analysis
```powershell
# Load CSV results
$guests = Import-Csv "guest-accounts.csv"

# Filter high-risk guests
$highRisk = $guests | Where-Object { $_.RiskLevel -eq "HIGH" }

# Group by guest domain
$byDomain = $guests | Group-Object GuestDomain | Sort-Object Count -Descending

# Find stale accounts
$staleGuests = $guests | Where-Object { [int]$_.DaysSinceLastSignIn -gt 90 }

# Guests without MFA
$noMFA = $guests | Where-Object { $_.MFAEnabled -eq "False" }
```

### Automated Reporting
```powershell
# Schedule with Task Scheduler or cron
$date = Get-Date -Format "yyyy-MM-dd"
.\Invoke-EntraGuestCheck.ps1 -ExportPath "C:\Reports\Guest-Audit-$date.csv" -QuietStealth

# Email results (example)
Send-MailMessage -To "security@company.com" `
    -Subject "Guest Account Audit - $date" `
    -Body "See attached guest account audit results" `
    -Attachments "C:\Reports\Guest-Audit-$date.csv"
```

### Cross-Reference with Other Tools
```powershell
# Get guests without MFA
.\Invoke-EntraGuestCheck.ps1 -OnlyNoMFA -ExportPath "guests-no-mfa.csv"

# Get all users without MFA
.\Invoke-EntraMFACheck.ps1 -ExportPath "users-no-mfa.csv"

# Compare and analyze
$guestsNoMFA = Import-Csv "guests-no-mfa.csv"
$allNoMFA = Import-Csv "users-no-mfa.csv"

# Calculate percentage
$percentGuestsNoMFA = ($guestsNoMFA.Count / $allNoMFA.Count) * 100
Write-Host "Guests represent $percentGuestsNoMFA% of users without MFA"
```

## Use Cases

### 1. Guest Access Governance
- Identify all guest accounts
- Review guest permissions and access
- Ensure compliance with guest access policies
- Generate regular guest access reports

### 2. MFA Enforcement Campaign
- Find guests without MFA
- Prioritize high-risk accounts
- Track MFA adoption progress
- Validate policy enforcement

### 3. Stale Account Cleanup
- Identify guests who haven't signed in recently
- Find unused invitations
- Review and revoke unnecessary access
- Improve security posture

### 4. Partner Relationship Review
- Group guests by organization (domain)
- Assess partnership security controls
- Identify unusual guest sources
- Plan partner-specific security policies

### 5. Security Incident Response
- Quickly enumerate all guest accounts
- Identify potential compromise vectors
- Review recent guest activity
- Support forensic investigations

## Related Tools

- **Invoke-EntraMFACheck.ps1** - Check MFA status for all users (including guests)
- **Invoke-EntraRecon.ps1** - Comprehensive Entra ID enumeration
- **entra_recon.py** - Python version of Entra ID reconnaissance

## License

This tool is part of the EvilMist toolkit and is licensed under the GNU General Public License v3.0.

See [LICENSE](LICENSE) for full details.

## References

- [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/api/overview)
- [Azure AD B2B Guest User Access](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/what-is-b2b)
- [Authentication Methods in Azure AD](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods)
- [Guest Access Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/b2b-fundamentals)

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before testing any systems you do not own.

---

**EvilMist** | Cloud Penetration Testing Toolkit  
GitHub: [github.com/Logisek/EvilMist](https://github.com/Logisek/EvilMist)

