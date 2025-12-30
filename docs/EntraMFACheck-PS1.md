# Invoke-EntraMFACheck.ps1

## Overview

`Invoke-EntraMFACheck.ps1` is a PowerShell 7+ script designed to identify Azure Entra ID users who do not have Multi-Factor Authentication (MFA) enabled. This tool is part of the EvilMist toolkit and helps security teams identify potential security gaps in their Azure AD tenant.

## Purpose

In modern cloud environments, MFA is a critical security control. This script helps:
- **Security Auditors**: Identify users who lack proper MFA configuration
- **Penetration Testers**: Discover potential weak points in authentication
- **IT Administrators**: Audit MFA compliance across the organization
- **Compliance Teams**: Generate reports for security compliance requirements

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Comprehensive MFA Detection**: Checks multiple authentication method types
- ✅ **Last Sign-In Tracking**: Shows last login date/time and days since last activity
- ✅ **Sign-In Capability Check**: Identifies if accounts can actually sign in
- ✅ **Shared Mailbox Detection**: Automatically identifies shared mailbox accounts
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Detailed Reporting**: Risk levels, user details, and authentication methods
- ✅ **Current User Credentials**: Uses the authenticated user's domain setup

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

**Note**: If `AuditLog.Read.All` is not available, the script will automatically fall back to retrieving users without sign-in activity data. All other features will continue to work normally.

## Usage

### Basic Usage

```powershell
# Simple scan of all enabled users
.\scripts\powershell\Invoke-EntraMFACheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -ExportPath "no-mfa-users.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -ExportPath "results.json"
```

### Include Disabled Accounts

```powershell
# Scan all users including disabled accounts
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -IncludeDisabledUsers -ExportPath "all-users-no-mfa.csv"
```

### Matrix Display

```powershell
# Display results in matrix/table format
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -Matrix -ExportPath "results.csv"

# Matrix view with all options
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -Matrix -IncludeDisabledUsers -EnableStealth
```

### Specify Tenant

```powershell
# Target a specific tenant
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.csv"
```

### Use Existing Token

```powershell
# Use Azure CLI cached token
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached token
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -UseAzPowerShellToken
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms + 300ms jitter)
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -EnableStealth

# Custom stealth settings
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -RequestDelay 2 -RequestJitter 1

# Stealth mode without verbose output
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -EnableStealth -QuietStealth -ExportPath "results.json"
```

### Combined Options

```powershell
# Full featured scan
.\scripts\powershell\Invoke-EntraMFACheck.ps1 `
    -TenantId "your-tenant-id" `
    -IncludeDisabledUsers `
    -EnableStealth `
    -QuietStealth `
    -ExportPath "comprehensive-mfa-audit.csv"
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
| `IncludeDisabledUsers` | Switch | Include disabled accounts | False |
| `Matrix` | Switch | Display results in matrix/table format | False |

## New Features

### Last Sign-In Tracking

The script now displays:
- **Last Sign-In DateTime**: Exact date and time of last login
- **Days Since Last Sign-In**: How many days ago the account was last accessed
- **Sign-In Type**: Interactive vs Non-Interactive sign-ins
- **Activity Status**: Color-coded based on recency:
  - 🟢 **Green**: Recent activity (≤30 days)
  - 🟡 **Yellow**: Moderate inactivity (31-90 days)
  - 🔴 **Red**: Stale accounts (>90 days)
  - ⚫ **Gray**: Never signed in

### Sign-In Capability Detection

Determines if an account can actually sign in:
- Checks if account is enabled
- Verifies sign-in activity history
- Identifies blocked or restricted accounts

### Shared Mailbox Detection

Automatically identifies accounts associated with shared mailboxes:
- **Detection Criteria**:
  - Disabled accounts with email addresses
  - Accounts with mailboxes but no licenses
  - Name patterns matching shared resources
  - Multiple indicator confidence scoring

- **Confidence Levels**:
  - **High**: Multiple indicators present (2+)
  - **Medium**: Single indicator present
  - **Low/Unknown**: Insufficient data

- **Risk Adjustment**: Shared mailboxes are marked as LOW risk since they typically don't require MFA

**Note**: Shared mailboxes are expected to not have MFA enabled as they are accessed through licensed user accounts.

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
- Summary statistics
- Detailed user information for accounts without MFA
- Risk level indicators (HIGH/MEDIUM)

### Standard View vs Matrix View

**Standard View** (default):
- Detailed information for each user
- Full field display with descriptions
- Better for thorough investigation
- Easier to read for small result sets

**Matrix View** (`-Matrix` parameter):
- Compact tabular format
- Quick visual scanning
- Additional analytics and summaries
- Better for large result sets
- Department and method breakdowns
- Color-coded risk levels

### Matrix View

When using the `-Matrix` parameter, results are displayed in a formatted table with additional analytics:

**Matrix Table Columns:**
- Risk level (HIGH/MEDIUM/LOW)
- Account type (User/Guest/SharedMB)
- Account status (Enabled/Disabled)
- User Principal Name
- Display Name
- Last Sign-In (with days ago)
- Department
- Authentication Methods

**Additional Analytics:**
- Summary statistics by risk level
- Shared mailbox detection and count
- Top departments with users lacking MFA
- Breakdown by authentication method types
- Sign-in activity statistics (never/recent/stale)
- Color-coded rows for easy identification:
  - 🔴 RED: HIGH risk users (enabled accounts)
  - 🟡 YELLOW: MEDIUM risk users (disabled accounts)
  - ⚪ GRAY: LOW risk (shared mailboxes)
  - 🔵 CYAN: Headers and separators

**Example Matrix Output:**
```
====================================================================================
MATRIX VIEW - USERS WITHOUT MFA
====================================================================================

Risk   Type      Status    User Principal Name         Display Name    Last Sign-In  Department
----   ----      ------    -------------------         ------------    ------------  ----------
HIGH   User      Enabled   john.doe@example.com        John Doe        5d ago        IT
HIGH   User      Enabled   jane.smith@example.com      Jane Smith      Today         Sales
MEDIUM User      Disabled  old.user@example.com        Old User        120d ago      Marketing
LOW    SharedMB  Disabled  shared.conf@example.com     Conf Room 1     Never         -

[SUMMARY]
Total users without MFA: 4
  - HIGH risk (enabled users): 2
  - MEDIUM risk (disabled users): 1
  - LOW risk (shared mailboxes): 1

  Note: 1 suspected shared mailbox(es) detected

[TOP DEPARTMENTS]
  IT: 1
  Sales: 1

[AUTHENTICATION METHODS]
  Password Only: 4

[SIGN-IN ACTIVITY]
  Never signed in: 1
  Recent (≤30 days): 2
  Stale (>90 days): 1
```

### Risk Levels

- **HIGH**: Enabled user accounts without MFA (active security risk)
- **MEDIUM**: Disabled user accounts without MFA (potential future risk)
- **LOW**: Shared mailboxes or service accounts (expected behavior)

### Export Formats

#### CSV Export
```csv
DisplayName,UserPrincipalName,Email,AccountEnabled,CanSignIn,JobTitle,Department,CreatedDateTime,LastSignIn,LastSignInDisplay,DaysSinceLastSignIn,SignInType,AuthMethods,MethodCount,MFAEnabled,AccountType,IsSharedMailbox,SharedMailboxConfidence,RiskLevel
John Doe,john.doe@example.com,john.doe@example.com,True,True,Manager,IT,2023-01-15,2024-12-15,2024-12-15 10:30:00 (4 days ago),4,Interactive,Password Only,1,False,Regular User,False,,HIGH
Shared Room,shared.room@example.com,shared.room@example.com,False,False,,,2023-01-10,,,Never,,Password Only,1,False,Shared Mailbox (Suspected),True,High,LOW
```

#### JSON Export
```json
[
  {
    "DisplayName": "John Doe",
    "UserPrincipalName": "john.doe@example.com",
    "Email": "john.doe@example.com",
    "AccountEnabled": true,
    "CanSignIn": true,
    "JobTitle": "Manager",
    "Department": "IT",
    "CreatedDateTime": "2023-01-15T10:30:00Z",
    "LastSignIn": "2024-12-15T10:30:00Z",
    "LastSignInDisplay": "2024-12-15 10:30:00 (4 days ago)",
    "DaysSinceLastSignIn": 4,
    "SignInType": "Interactive",
    "AuthMethods": "Password Only",
    "MethodCount": 1,
    "MFAEnabled": false,
    "AccountType": "Regular User",
    "IsSharedMailbox": false,
    "SharedMailboxIndicators": "",
    "SharedMailboxConfidence": "",
    "RiskLevel": "HIGH",
    "UserType": "Member"
  },
  {
    "DisplayName": "Shared Room",
    "UserPrincipalName": "shared.room@example.com",
    "Email": "shared.room@example.com",
    "AccountEnabled": false,
    "CanSignIn": false,
    "JobTitle": null,
    "Department": null,
    "CreatedDateTime": "2023-01-10T08:00:00Z",
    "LastSignIn": null,
    "LastSignInDisplay": "Never signed in",
    "DaysSinceLastSignIn": -1,
    "SignInType": "Never",
    "AuthMethods": "Password Only",
    "MethodCount": 1,
    "MFAEnabled": false,
    "AccountType": "Shared Mailbox (Suspected)",
    "IsSharedMailbox": true,
    "SharedMailboxIndicators": "Disabled account with email; No licenses assigned; Name pattern match",
    "SharedMailboxConfidence": "High",
    "RiskLevel": "LOW",
    "UserType": "Member"
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
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -RequestDelay 3 -RequestJitter 2 -QuietStealth

# Moderate stealth (balanced)
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -EnableStealth -QuietStealth

# Fast scan (minimal stealth)
.\scripts\powershell\Invoke-EntraMFACheck.ps1
```

## Authentication Methods

### 1. Interactive Authentication (Default)
```powershell
.\scripts\powershell\Invoke-EntraMFACheck.ps1
```
- Opens browser for interactive login
- Uses current user's credentials
- Prompts for consent if needed

### 2. Azure CLI Token
```powershell
# Login with Azure CLI first
az login

# Run script with CLI token
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -UseAzCliToken
```

### 3. Azure PowerShell Token
```powershell
# Login with Azure PowerShell first
Connect-AzAccount

# Run script with PowerShell token
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -UseAzPowerShellToken
```

## Error Handling

The script includes comprehensive error handling:
- Module availability checks
- Authentication failures with fallback options
- API permission issues
- Network connectivity problems
- Graceful cleanup on exit

## Interpreting Results

### Understanding Shared Mailboxes

**What are Shared Mailboxes?**
Shared mailboxes are mailboxes that multiple users can access to read and send email. In Azure Entra ID, they appear as user accounts but:
- Typically have `accountEnabled = false`
- Don't have licenses assigned
- Are accessed through delegated permissions
- **Don't require MFA** as users sign in with their own credentials

**Why This Matters:**
Most accounts flagged as "no MFA" in shared mailbox scans are actually shared mailboxes, which is expected and not a security risk. The script now:
- Automatically detects shared mailboxes
- Marks them as **LOW** risk
- Provides confidence levels for identification
- Shows indicators used for detection

**Focus Your Remediation On:**
- 🔴 **HIGH Risk**: Regular enabled user accounts without MFA
- 🟡 **MEDIUM Risk**: Disabled user accounts that might be re-enabled
- ⚪ **LOW Risk**: Shared mailboxes (can usually be ignored)

### Sign-In Activity Insights

**Never Signed In:**
- Newly created accounts
- Service accounts
- Shared mailboxes
- Potentially dormant/unused accounts

**Recent Sign-Ins (≤30 days):**
- Active accounts - highest priority for MFA enablement
- Potential security risk if compromised

**Stale Sign-Ins (>90 days):**
- Consider disabling or reviewing
- Lower immediate risk but still a concern
- May indicate abandoned accounts

## Limitations

- Requires appropriate Microsoft Graph API permissions
- Rate limiting may affect large tenants (use stealth mode)
- Some MFA methods may not be detectable with limited permissions
- Guest users may have limited information available
- Shared mailbox detection is heuristic-based (uses multiple indicators)
- Sign-in activity requires `AuditLog.Read.All` permission

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
If you see an error like:
```
Could not load file or assembly 'Microsoft.Graph.Authentication, Version=2.24.0.0...'
Assembly with same name is already loaded
```

**Solution 1: Update all Graph modules to the same version**
```powershell
# Uninstall all versions
Get-InstalledModule Microsoft.Graph* | Uninstall-Module -AllVersions -Force

# Reinstall latest version
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

**Solution 2: Manual cleanup and reload**
```powershell
# Remove loaded modules
Get-Module Microsoft.Graph* | Remove-Module -Force

# Run the script again (it now handles module loading properly)
.\scripts\powershell\Invoke-EntraMFACheck.ps1
```

**Solution 3: Start fresh PowerShell session**
```powershell
# Close PowerShell and open a new session
# Then run the script
.\scripts\powershell\Invoke-EntraMFACheck.ps1
```

### Permission Denied
- Ensure your account has appropriate admin roles
- Request consent from Global Administrator
- Try with reduced scopes (fallback mode)

### Rate Limiting (429 Errors)
```powershell
# Use stealth mode to reduce rate
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -EnableStealth -MaxRetries 5
```

### Authentication Timeout
- Check network connectivity
- Verify tenant ID is correct
- Try alternative authentication method

### "Get-MgUser command not found"
```powershell
# Install the required modules
Install-Module Microsoft.Graph.Users -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force
```

## Examples

### Example 1: Basic Security Audit
```powershell
# Scan all enabled users and export results
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -ExportPath "mfa-audit-$(Get-Date -Format 'yyyy-MM-dd').csv"
```

### Example 2: Comprehensive Scan
```powershell
# Full tenant scan including disabled accounts
.\scripts\powershell\Invoke-EntraMFACheck.ps1 `
    -IncludeDisabledUsers `
    -ExportPath "full-mfa-audit.json" `
    -EnableStealth
```

### Example 3: Stealth Penetration Test
```powershell
# Low-profile scan with maximum stealth
.\scripts\powershell\Invoke-EntraMFACheck.ps1 `
    -UseAzCliToken `
    -RequestDelay 5 `
    -RequestJitter 3 `
    -QuietStealth `
    -ExportPath "pentest-results.csv"
```

### Example 4: Multi-Tenant Assessment
```powershell
# Scan multiple tenants
$tenants = @("tenant1-id", "tenant2-id", "tenant3-id")

foreach ($tenant in $tenants) {
    .\scripts\powershell\Invoke-EntraMFACheck.ps1 `
        -TenantId $tenant `
        -ExportPath "mfa-audit-$tenant.csv" `
        -EnableStealth
}
```

### Example 5: Matrix View for Quick Analysis
```powershell
# Quick visual analysis with matrix display
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -Matrix

# Matrix view with comprehensive scan
.\scripts\powershell\Invoke-EntraMFACheck.ps1 `
    -Matrix `
    -IncludeDisabledUsers `
    -ExportPath "full-matrix-report.csv"

# Stealth matrix scan for pentesting
.\scripts\powershell\Invoke-EntraMFACheck.ps1 `
    -UseAzCliToken `
    -Matrix `
    -EnableStealth `
    -QuietStealth `
    -ExportPath "pentest-matrix.json"
```

## Integration

### Import Results for Analysis
```powershell
# Load CSV results
$results = Import-Csv "no-mfa-users.csv"

# Filter high-risk users
$highRisk = $results | Where-Object { $_.RiskLevel -eq "HIGH" }

# Group by department
$byDept = $results | Group-Object Department | Sort-Object Count -Descending
```

### Automated Reporting
```powershell
# Schedule with Task Scheduler or cron
$date = Get-Date -Format "yyyy-MM-dd"
.\scripts\powershell\Invoke-EntraMFACheck.ps1 -ExportPath "C:\Reports\MFA-Audit-$date.csv" -QuietStealth

# Email results (example)
Send-MailMessage -To "security@company.com" `
    -Subject "MFA Audit - $date" `
    -Body "See attached MFA audit results" `
    -Attachments "C:\Reports\MFA-Audit-$date.csv"
```

## Related Tools

- **Invoke-EntraRecon.ps1** - Comprehensive Entra ID enumeration
- **entra_recon.py** - Python version of Entra ID reconnaissance

## License

This tool is part of the EvilMist toolkit and is licensed under the GNU General Public License v3.0.

See [LICENSE](LICENSE) for full details.

## References

- [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/api/overview)
- [Azure AD Authentication Methods](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods)
- [MFA Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks)

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before testing any systems you do not own.

---

**EvilMist** | Cloud Penetration Testing Toolkit  
GitHub: [github.com/Logisek/EvilMist](https://github.com/Logisek/EvilMist)

