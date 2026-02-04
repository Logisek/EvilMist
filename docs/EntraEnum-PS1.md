# Invoke-EntraEnum.ps1

## Overview

`Invoke-EntraEnum.ps1` is a PowerShell 7+ script for **unauthenticated** Azure/Entra ID enumeration and reconnaissance. This tool complements the authenticated `Invoke-EntraRecon.ps1` by performing passive/semi-passive enumeration using publicly accessible APIs and DNS queries without requiring any authentication tokens.

## Purpose

This script is designed for reconnaissance phases where authentication is not yet established:

- **Security Auditors**: Assess external exposure of Azure/Entra ID tenants
- **Penetration Testers**: Gather intelligence before authenticated testing
- **Red Teams**: Enumerate targets without triggering authentication logs
- **IT Administrators**: Verify public-facing tenant configuration

## Features

### Core Features
- **No Authentication Required**: Works without any Azure/Entra ID tokens or credentials
- **Tenant Discovery**: Retrieve tenant ID, name, region, and endpoints via azmap.dev and OpenID configuration
- **Domain Realm Analysis**: Identify if domain uses Azure AD (Managed) or Federation (ADFS, external IdP)
- **User Existence Checking**: Verify if email addresses exist using GetCredentialType API
- **DNS Reconnaissance**: Enumerate MX, SPF, TXT, CNAME, SRV, and Autodiscover records
- **Port Scanning**: Check common Azure-related ports (HTTPS, LDAP, Kerberos, RDP, etc.)

### New Advanced Features (v2.0)
- **OneDrive User Enumeration**: Completely silent user enumeration via OneDrive URLs
- **Federation Metadata**: Extract signing certificates and federation configuration
- **Seamless SSO Detection**: Detect Seamless SSO and Autologon endpoints
- **Azure Subdomain Enumeration**: Discover associated cloud resources (Storage, Key Vault, etc.)
- **Autodiscover V2**: Alternative user enumeration via Autodiscover JSON endpoints
- **Autodiscover V1**: Legacy Autodiscover XML enumeration
- **EWS Probe**: Exchange Web Services endpoint exposure checks
- **SharePoint / Teams Discovery**: Tenant roots and common site checks
- **Lync / Skype Discovery**: lyncdiscover and SIP endpoint probing
- **Enhanced Mail Security**: DMARC, DKIM, MTA-STS, BIMI, TLS-RPT analysis
- **Tenant ID Reversal**: Discover resources from tenant ID
- **OAuth Configuration Probe**: Enumerate accessible applications via error analysis

### General Features
- **Stealth Mode**: Configurable delays and jitter to avoid rate limiting
- **Export Options**: JSON and CSV export formats
- **Matrix View**: Table format for quick visual scanning

## Requirements

### Prerequisites

1. **PowerShell 7+**
   - Download: https://aka.ms/powershell-release?tag=stable
   - The script will check and warn if older version is detected

2. **No additional modules required**
   - Uses built-in cmdlets (`Invoke-WebRequest`, `Resolve-DnsName`, `System.Net.Sockets.TcpClient`)

### Network Requirements

- Outbound HTTPS (443) to:
  - `login.microsoftonline.com`
  - `azmap.dev`
  - `autodiscover-s.outlook.com`
  - `autodiscover.{domain}`
  - `autologon.microsoftazuread-sso.com`
  - `outlook.office365.com`
  - `outlook.office.com`
  - `lyncdiscover.{domain}`
  - `sip.{domain}`
  - `*.sharepoint.com` (OneDrive enumeration)
- Outbound DNS (53) for DNS reconnaissance
- Outbound TCP to target for port scanning

## Usage

### Basic Usage

```powershell
# Default enumeration (TenantInfo, DomainRealm, DnsEnum)
.\scripts\powershell\Invoke-EntraEnum.ps1 -Domain contoso.com

# Using dispatcher
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com
```

### Tenant Discovery Only

```powershell
# Get tenant information
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -TenantInfo
```

### User Enumeration

```powershell
# Check single email via GetCredentialType
.\Invoke-EvilMist.ps1 -Script EntraEnum -Email admin@contoso.com -UserEnum

# Check multiple emails
.\Invoke-EvilMist.ps1 -Script EntraEnum -Emails "user1@contoso.com","user2@contoso.com" -UserEnum

# Check from file (one email per line)
.\Invoke-EvilMist.ps1 -Script EntraEnum -EmailList users.txt -UserEnum

# Slower enumeration to avoid rate limiting
.\Invoke-EvilMist.ps1 -Script EntraEnum -EmailList users.txt -UserEnum -Throttle 2
```

### Silent User Enumeration (OneDrive)

```powershell
# Silent user enumeration via OneDrive - completely undetectable!
.\Invoke-EvilMist.ps1 -Script EntraEnum -EmailList users.txt -OneDriveEnum -TenantName contoso

# Combined with standard user enum for cross-validation
.\Invoke-EvilMist.ps1 -Script EntraEnum -EmailList users.txt -UserEnum -OneDriveEnum -TenantName contoso
```

### Federation and SSO Analysis

```powershell
# Check federation metadata and SSO configuration
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -FederationMeta -SeamlessSSO

# Federation metadata only (extract signing certificates)
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -FederationMeta
```

### Azure Subdomain Enumeration

```powershell
# Enumerate Azure subdomains for tenant
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -SubdomainEnum -TenantName contoso

# With custom wordlist for permutations
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -SubdomainEnum -TenantName contoso -WordList wordlist.txt
```

### Enhanced Mail Security Analysis

```powershell
# Full mail security analysis (DMARC, DKIM, MTA-STS, BIMI, TLS-RPT)
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -MailEnum
```

### OAuth Configuration Probe

```powershell
# Probe OAuth configuration and discover accessible applications
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -OAuthProbe
```

### Autodiscover V1 Enumeration

```powershell
# Legacy Autodiscover XML-based enumeration
.\Invoke-EvilMist.ps1 -Script EntraEnum -EmailList users.txt -AutodiscoverV1Enum
```

### Exchange Web Services (EWS) Probe

```powershell
# Probe EWS endpoints for exposure
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -EwsProbe
```

### SharePoint / Teams Discovery

```powershell
# Discover tenant roots and common SharePoint/Teams sites
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -SharePointEnum -TenantName contoso

# Use a custom SharePoint site wordlist
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -SharePointEnum -TenantName contoso -SharePointWordList sites.txt
```

### Lync / Skype Discovery

```powershell
# Probe Lync/Skype discovery endpoints
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -LyncProbe
```

### DNS Reconnaissance

```powershell
# DNS records only
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -DnsEnum
```

### Port Scanning

```powershell
# Scan default ports
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -PortScan

# Scan specific ports
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -PortScan -Ports 443,80,3389

# Custom timeout
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -PortScan -PortTimeout 2000
```

### Full Enumeration

```powershell
# Run all methods
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -All -TenantName contoso -EmailList users.txt

# All methods with export
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -All -ExportPath results.json
```

### Stealth Mode

```powershell
# Enable stealth with default settings (500ms + 300ms jitter)
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -All -EnableStealth

# Custom delay settings
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -All -RequestDelay 2 -RequestJitter 1

# Stealth without verbose output
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -All -EnableStealth -QuietStealth
```

### Export Results

```powershell
# Export to JSON
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -All -ExportPath results.json

# Export to CSV
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -All -ExportPath results.csv
```

### Matrix View

```powershell
# Display results in table format
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -All -Matrix
```

## Parameters

### Primary Input Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `Domain` | String | Target domain (e.g., contoso.com) | None |
| `Email` | String | Single email for user existence check | None |
| `Emails` | String[] | Array of emails for bulk enumeration | None |
| `EmailList` | String | Path to file with emails (one per line) | None |

### Core Method Switches

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `All` | Switch | Run all enumeration methods | False |
| `TenantInfo` | Switch | Tenant discovery (azmap.dev + OpenID) | False |
| `DomainRealm` | Switch | Domain namespace/federation info | False |
| `UserEnum` | Switch | User existence via GetCredentialType | False |
| `DnsEnum` | Switch | DNS reconnaissance | False |
| `PortScan` | Switch | TCP port scanning | False |

### New Method Switches

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `OneDriveEnum` | Switch | Silent user enumeration via OneDrive URLs | False |
| `FederationMeta` | Switch | Federation metadata and certificates | False |
| `SeamlessSSO` | Switch | Seamless SSO detection and Autologon | False |
| `SubdomainEnum` | Switch | Azure subdomain discovery | False |
| `AutodiscoverEnum` | Switch | User enumeration via Autodiscover V2 | False |
| `AutodiscoverV1Enum` | Switch | User enumeration via Autodiscover V1 | False |
| `EwsProbe` | Switch | Exchange Web Services endpoint probe | False |
| `SharePointEnum` | Switch | SharePoint/Teams discovery | False |
| `LyncProbe` | Switch | Lync/Skype discovery probe | False |
| `MailEnum` | Switch | Enhanced mail security analysis | False |
| `TenantReverse` | Switch | Resource discovery from tenant ID | False |
| `OAuthProbe` | Switch | OAuth configuration analysis | False |

### New Method Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `TenantName` | String | Override tenant name for OneDrive/subdomain/SharePoint enum | Extracted from domain |
| `WordList` | String | Custom wordlist for subdomain permutation | None |
| `SharePointWordList` | String | Custom wordlist for SharePoint site discovery | None |

### Stealth and Rate Limiting

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `EnableStealth` | Switch | Enable stealth mode with delays | False |
| `RequestDelay` | Double | Base delay in seconds (0-60) | 0 |
| `RequestJitter` | Double | Jitter range in seconds (0-30) | 0 |
| `Throttle` | Double | Delay between user enum requests (0.1-10) | 0.5 |
| `QuietStealth` | Switch | Suppress stealth status messages | False |

### Port Scan Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `Ports` | Int[] | Custom ports to scan | Default list |
| `PortTimeout` | Int | TCP timeout in milliseconds (100-30000) | 1000 |

### Output Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `ExportPath` | String | Export path (CSV or JSON) | None |
| `Matrix` | Switch | Display results in table format | False |

---

## Enumeration Methods Explained

### 1. Tenant Discovery (`-TenantInfo`)

Queries publicly accessible endpoints to retrieve tenant information:

**azmap.dev API:**
```
GET https://azmap.dev/api/tenant?domain={DOMAIN}&extract=true
```
Returns: Tenant ID, display name, country code

**OpenID Configuration:**
```
GET https://login.microsoftonline.com/{DOMAIN}/v2.0/.well-known/openid-configuration
```
Returns: Token endpoint, authorization endpoint, JWKS URI, issuer (contains tenant ID)

---

### 2. Domain Realm (`-DomainRealm`)

Determines authentication configuration:

```
GET https://login.microsoftonline.com/getuserrealm.srf?login=enum@{DOMAIN}&json=1
```

**NameSpaceType Values:**
- `Managed` - Azure AD handles authentication
- `Federated` - External Identity Provider (ADFS, Okta, etc.)

**Key Fields:**
- `AuthURL` - Federation server URL (if federated)
- `CloudInstanceName` - Azure cloud instance
- `FederationBrandName` - Federation brand name

---

### 3. User Enumeration (`-UserEnum`)

Checks if email addresses exist using the GetCredentialType API:

```
POST https://login.microsoftonline.com/common/GetCredentialType
Body: {"Username": "{EMAIL}", "isOtherIdpSupported": true, ...}
```

**IfExistsResult Codes:**
| Code | Meaning | Description |
|------|---------|-------------|
| 0 | Exists | Account exists (Azure as IdP) |
| 1 | Not Exist | User does not exist |
| 5 | Exists | Account exists (Federated IdP) |
| 6 | Exists | Account exists (External non-MS IdP) |

**Note:** This method may be rate-limited. Use `-Throttle` to add delays.

---

### 4. DNS Enumeration (`-DnsEnum`)

Queries DNS records using `Resolve-DnsName`:

| Record Type | Target | Purpose |
|-------------|--------|---------|
| CNAME | `{DOMAIN}` | CDN/proxy detection |
| CNAME | `autodiscover.{DOMAIN}` | Exchange/M365 autodiscover |
| CNAME | `lyncdiscover.{DOMAIN}` | Skype/Teams |
| TXT | `{DOMAIN}` | SPF, domain verification |
| MX | `{DOMAIN}` | Mail servers (M365 indicator) |
| SRV | `_ldap._tcp.{DOMAIN}` | LDAP services |
| SRV | `_kerberos._tcp.{DOMAIN}` | Kerberos services |
| SRV | `_sip._tls.{DOMAIN}` | SIP/Teams |

---

### 5. Port Scan (`-PortScan`)

TCP port scanning using `System.Net.Sockets.TcpClient`:

**Default Ports:**
| Port | Service | Significance |
|------|---------|--------------|
| 443 | HTTPS | Web services, Azure portals |
| 80 | HTTP | Redirect, legacy services |
| 389 | LDAP | Directory services |
| 636 | LDAPS | Secure LDAP |
| 88 | Kerberos | Hybrid/AADDS |
| 587 | SMTP/TLS | Email submission |
| 25 | SMTP | Mail server |
| 3389 | RDP | Remote Desktop |
| 445 | SMB | File sharing |

---

### 6. OneDrive User Enumeration (`-OneDriveEnum`) - NEW

**Completely undetectable** - No authentication attempts logged, no Terms of Service violations.

**Endpoint Pattern:**
```
HEAD https://{tenant}-my.sharepoint.com/personal/{username}_{domain_underscore}/_layouts/15/onedrive.aspx
```

**Response Codes:**
| Status | Meaning |
|--------|---------|
| 403/401 | User exists (valid OneDrive) |
| 404 | User does not exist |

**Advantages:**
- Silent/undetectable - no audit logs generated
- OneDrive created automatically for any user accessing M365 services
- No rate limiting concerns
- Cross-validates GetCredentialType results

**Requirements:**
- Requires `-TenantName` parameter (or extracted from domain)
- Requires email list (`-Email`, `-Emails`, or `-EmailList`)

---

### 7. Federation Metadata (`-FederationMeta`) - NEW

Retrieves federation metadata including signing certificates:

```
GET https://login.microsoftonline.com/{DOMAIN}/FederationMetadata/2007-06/FederationMetadata.xml
```

**Information Disclosed:**
- Public X.509 signing certificates
- Token issuance endpoints
- ADFS server configuration (if federated)
- Issuer information
- NameID formats supported
- Claim types defined

**Use Cases:**
- Identify ADFS presence
- Extract certificates for token forgery research
- Understand federation trust relationships

---

### 8. Seamless SSO Detection (`-SeamlessSSO`) - NEW

Detects Seamless SSO configuration via GetUserRealm:

```
GET https://login.microsoftonline.com/getuserrealm.srf?login=user@{DOMAIN}&json=1
```

**Key Field:** `DesktopSsoEnabled`

**When Seamless SSO is enabled:**
- User enumeration via Autologon is completely undetectable
- No audit logs generated
- More reliable than GetCredentialType

**Autologon Endpoint (if SSO enabled):**
```
POST https://autologon.microsoftazuread-sso.com/{TENANT}/winauth/trust/2005/usernamemixed
```

---

### 9. Azure Subdomain Enumeration (`-SubdomainEnum`) - NEW

Discovers associated cloud resources from domain/tenant name.

**Subdomain Patterns Checked:**

| Pattern | Service |
|---------|---------|
| `{tenant}.onmicrosoft.com` | Primary tenant domain |
| `{tenant}.sharepoint.com` | SharePoint |
| `{tenant}-my.sharepoint.com` | OneDrive |
| `{tenant}.blob.core.windows.net` | Azure Blob Storage |
| `{tenant}.file.core.windows.net` | Azure Files |
| `{tenant}.queue.core.windows.net` | Azure Queue |
| `{tenant}.table.core.windows.net` | Azure Table |
| `{tenant}.vault.azure.net` | Key Vault |
| `{tenant}.database.windows.net` | Azure SQL |
| `{tenant}.azurewebsites.net` | App Service |
| `{tenant}.scm.azurewebsites.net` | Kudu/Git deployment |
| `{tenant}.cloudapp.azure.com` | Cloud Services |
| `{tenant}.mail.protection.outlook.com` | Exchange Online Protection |
| `{tenant}.azurecr.io` | Container Registry |
| `{tenant}.redis.cache.windows.net` | Redis Cache |
| `{tenant}.servicebus.windows.net` | Service Bus |
| `{tenant}.azurefd.net` | Front Door |
| `{tenant}.b2clogin.com` | Azure AD B2C |
| `{tenant}.azure-api.net` | API Management |
| `{tenant}.trafficmanager.net` | Traffic Manager |
| `{tenant}.azurehdinsight.net` | HDInsight |
| `{tenant}.documents.azure.com` | Cosmos DB |
| `{tenant}.search.windows.net` | Cognitive Search |
| `{tenant}.cognitiveservices.azure.com` | Cognitive Services |

**Permutation Suffixes:**
Default: dev, prod, staging, test, uat, qa, backup, dr, internal, external, api, app, web, data, files, storage, cdn, static

Use `-WordList` for custom permutations.

---

### 10. Autodiscover V2 Enumeration (`-AutodiscoverEnum`) - NEW

Alternative user existence check via Autodiscover JSON endpoints:

```
GET https://autodiscover-s.outlook.com/autodiscover/autodiscover.json?Email={EMAIL}&Protocol=Autodiscoverv1
```

**Response Analysis:**
| Status | Meaning |
|--------|---------|
| 200 | User exists |
| 302 | User does not exist (redirect) |
| 401/403 | User exists (authentication required) |

---

### 11. Autodiscover V1 Enumeration (`-AutodiscoverV1Enum`) - NEW

Legacy Autodiscover XML-based enumeration against the tenant domain:

```
POST https://autodiscover.{DOMAIN}/autodiscover/autodiscover.xml
```

**Indicators:**
- `NoError` / success responses suggest a valid mailbox
- `InvalidUser` / `InvalidSmtpAddress` indicate invalid users
- Redirects provide tenant routing signals

---

### 12. Exchange Web Services Probe (`-EwsProbe`) - NEW

Checks common EWS endpoints for exposure:

```
https://outlook.office365.com/EWS/Exchange.asmx
https://outlook.office.com/EWS/Exchange.asmx
https://{DOMAIN}/EWS/Exchange.asmx
```

Status codes (200/401/403/302) indicate reachable endpoints.

---

### 13. SharePoint / Teams Discovery (`-SharePointEnum`) - NEW

Probes tenant roots and common SharePoint/Teams site paths:

- `https://{TENANT}.sharepoint.com`
- `https://{TENANT}-my.sharepoint.com`
- `https://{TENANT}.sharepoint.com/sites/{site}`
- `https://{TENANT}.sharepoint.com/teams/{site}`

Use `-SharePointWordList` to customize site names.

---

### 14. Lync / Skype Discovery (`-LyncProbe`) - NEW

Probes common Lync/Skype discovery endpoints:

- `https://lyncdiscover.{DOMAIN}`
- `https://lyncdiscoverinternal.{DOMAIN}`
- `https://sip.{DOMAIN}`

---

### 15. Enhanced Mail Security (`-MailEnum`) - NEW

Comprehensive mail security DNS record analysis:

| Record | DNS Query | Purpose |
|--------|-----------|---------|
| MX | `{DOMAIN}` | Mail servers, provider detection |
| SPF | `{DOMAIN}` (TXT) | Sender policy, spoofing protection |
| DMARC | `_dmarc.{DOMAIN}` | Domain authentication policy |
| DKIM | `selector._domainkey.{DOMAIN}` | Email signing keys |
| MTA-STS | `_mta-sts.{DOMAIN}` | Mail transport security |
| BIMI | `default._bimi.{DOMAIN}` | Brand indicator |
| TLS-RPT | `_smtp._tls.{DOMAIN}` | TLS reporting |

**DKIM Selectors Checked:**
- `selector1`, `selector2` (Microsoft 365)
- `google` (Google Workspace)
- `default`, `dkim`, `mail`, `k1`, `s1`, `s2`

**Provider Detection:**
- Exchange Online Protection
- Google Workspace
- Proofpoint
- Mimecast

---

### 16. Tenant ID Reversal (`-TenantReverse`) - NEW

Given a tenant ID, discover associated resources across Azure services:

**Endpoints Probed:**
- OpenID configuration by tenant ID
- Microsoft Graph tenant info endpoint
- Device code endpoint
- OAuth authorization endpoint (branding extraction)

**Information Retrieved:**
- OpenID configuration
- Default domain
- Available endpoints
- Tenant branding information

---

### 17. OAuth Configuration Probe (`-OAuthProbe`) - NEW

Enumerate OAuth configuration through error message analysis:

```
GET https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize?client_id={APP_ID}&response_type=code
```

**Well-Known Applications Tested:**
| App ID | Application |
|--------|-------------|
| 00000003-0000-0000-c000-000000000000 | Microsoft Graph |
| 00000002-0000-0000-c000-000000000000 | Azure AD Graph |
| 00000002-0000-0ff1-ce00-000000000000 | Office 365 Exchange Online |
| 00000003-0000-0ff1-ce00-000000000000 | Office 365 SharePoint Online |
| 797f4846-ba00-4fd7-ba43-dac1f8f63013 | Azure Service Management API |
| 1950a258-227b-4e31-a9cf-717495945fc2 | Microsoft Azure PowerShell |
| 04b07795-8ddb-461a-bbee-02f9e1bf7b46 | Microsoft Azure CLI |
| d3590ed6-52b3-4102-aeff-aad2292ab01c | Microsoft Office |
| 1fec8e78-bce4-4aaf-ab1b-5451cc387264 | Microsoft Teams |
| 9bc3ab49-b65d-410a-85ad-de819febfddc | Microsoft Planner |
| de8bc8b5-d9f9-48b1-a8ad-b748da725064 | Microsoft Graph Command Line Tools |
| c44b4083-3bb0-49c1-b47d-974e53cbdf3c | Azure Portal |
| 0000000c-0000-0000-c000-000000000000 | Microsoft App Access Panel |
| 5d661950-3475-41cd-a2c3-d671a3162bc1 | Microsoft Outlook |
| eb1cec80-a830-486e-b45b-f57094f163f9 | Microsoft OneDrive |
| 57fb890c-0dab-4253-a5e0-7188c88b2bb4 | SharePoint Online Client |

**Error Codes Analyzed:**
| Code | Meaning |
|------|---------|
| AADSTS700016 | Application not found in directory |
| AADSTS650057 | Invalid resource - app exists |
| AADSTS65001 | Consent required - app exists |
| AADSTS50011 | Reply URL mismatch - app exists |
| AADSTS90002 | Tenant not found |

---

## Output Formats

### Console Output

```
[*] Info (Cyan)
[+] Success/Found (Green)
[!] Warning (Yellow)
[-] Not Found (Gray)
[ERROR] Error (Red)
```

### JSON Export Structure

```json
{
  "ExportDate": "2024-01-15 14:30:00",
  "Summary": {
    "Domain": "contoso.com",
    "TenantId": "12345678-1234-1234-1234-123456789012",
    "TenantName": "contoso",
    "IsFederated": false,
    "UsersChecked": 10,
    "UsersExist": 3,
    "PortsScanned": 9,
    "PortsOpen": 2,
    "OneDriveUsersChecked": 10,
    "OneDriveUsersExist": 3,
    "SubdomainsChecked": 50,
    "SubdomainsFound": 8,
    "SeamlessSSOEnabled": true,
    "AutodiscoverV1Checked": 10,
    "AutodiscoverV1Exist": 3,
    "SharePointSitesChecked": 26,
    "SharePointSitesFound": 5,
    "SharePointPublicSites": 1,
    "EwsEndpointsFound": 2,
    "LyncEndpointsFound": 1
  },
  "TenantInfo": { ... },
  "DomainRealm": { ... },
  "UserEnumeration": [ ... ],
  "DnsRecords": { ... },
  "PortScan": [ ... ],
  "OneDriveEnum": [ ... ],
  "FederationMeta": { ... },
  "SeamlessSSO": { ... },
  "SubdomainEnum": [ ... ],
  "AutodiscoverV2": [ ... ],
  "AutodiscoverV1": [ ... ],
  "EwsProbe": [ ... ],
  "SharePointEnum": [ ... ],
  "LyncProbe": [ ... ],
  "MailEnum": { ... },
  "TenantReverse": { ... },
  "OAuthProbe": [ ... ]
}
```

---

## Security Considerations / OPSEC Notes

### Detection Risk Matrix

| Method | Detection Risk | Audit Logs | Notes |
|--------|----------------|------------|-------|
| TenantInfo | Very Low | No | Public API |
| DomainRealm | Very Low | No | Public API |
| DnsEnum | Very Low | No | Standard DNS queries |
| UserEnum | Medium | Possible | May be rate-limited |
| PortScan | Low-Medium | Possible | Standard TCP connections |
| **OneDriveEnum** | **None** | **No** | **Completely silent** |
| FederationMeta | Very Low | No | Standard browser behavior |
| **SeamlessSSO/Autologon** | **None** | **No** | **Explicitly undetectable** |
| SubdomainEnum | Very Low | No | DNS queries only |
| AutodiscoverEnum | Low | Minimal | May be monitored |
| AutodiscoverV1Enum | Low | Minimal | Legacy endpoint probing |
| EwsProbe | Low | Minimal | Endpoint exposure check |
| SharePointEnum | Low | Minimal | Public endpoint checks |
| LyncProbe | Low | Minimal | Endpoint discovery |
| MailEnum | Very Low | No | DNS queries only |
| TenantReverse | Low | Minimal | Standard API calls |
| OAuthProbe | Medium | Possible | May trigger alerts |

### Rate Limiting
- Microsoft may rate-limit GetCredentialType requests
- Use `-Throttle` parameter (default 0.5s) for user enumeration
- Enable `-EnableStealth` for additional delays with jitter
- OneDrive enumeration has no known rate limiting

### Recommendations

1. **For silent user enumeration**, prefer `-OneDriveEnum` over `-UserEnum`
2. Use stealth mode for large-scale enumeration
3. Distribute user enumeration over time
4. Consider using proxies for port scanning
5. Run `-SeamlessSSO` first - if enabled, Autologon enum is completely undetectable
6. This tool does NOT bypass any security controls

---

## Troubleshooting

### Common Issues

**"No tenant found" for TenantInfo:**
- Domain may not be registered with Azure AD
- Try alternative domains (e.g., company.onmicrosoft.com)

**User enumeration returns "Unknown" results:**
- API may be rate-limiting requests
- Increase `-Throttle` value
- Enable `-EnableStealth`
- Try `-OneDriveEnum` as alternative

**OneDrive enumeration failing:**
- Verify `-TenantName` is correct
- Tenant name is typically the part before `.onmicrosoft.com`
- Try the exact tenant name from Azure portal

**DNS queries fail:**
- Check network connectivity
- Verify DNS resolution is working
- Some DNS records may not exist

**Port scan shows all "Filtered":**
- Target may have firewall rules
- Increase `-PortTimeout` value
- Network may be blocking outbound connections

**Federation metadata not found:**
- Domain may be managed (not federated)
- Federation may use different protocol

### Debug Tips

```powershell
# Verbose stealth output
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -EnableStealth

# Increase throttle for user enum
.\Invoke-EvilMist.ps1 -Script EntraEnum -EmailList users.txt -UserEnum -Throttle 3

# Longer port timeout
.\Invoke-EvilMist.ps1 -Script EntraEnum -Domain contoso.com -PortScan -PortTimeout 5000

# Test OneDrive with explicit tenant name
.\Invoke-EvilMist.ps1 -Script EntraEnum -Email user@contoso.com -OneDriveEnum -TenantName contoso
```

---

## Related Tools

- **Invoke-EntraRecon.ps1** - Authenticated comprehensive Azure Entra ID enumeration
- **Invoke-EntraMFACheck.ps1** - Authenticated MFA status checking
- **AADInternals** - Comprehensive Azure AD toolkit
- **TeamFiltration** - O365 user enumeration and attacks
- **o365creeper** - Office 365 user enumeration
- **TrevorSpray** - O365 password spraying

---

## References

- AADInternals: https://aadinternals.com/
- TeamFiltration: https://github.com/Flangvik/TeamFiltration
- TrustedSec OneDrive Enum: https://trustedsec.com/blog/onedrive-to-enum-them-all
- NetSPI ATEAM: https://www.netspi.com/blog/technical-blog/cloud-pentesting/azure-resource-attribution-via-tenant-id-enumeration/
- HackTricks Azure: https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-unauthenticated-enum-and-initial-entry

---

## License

GNU General Public License v3.0

---

## Example Output

```
===============================================================================
██████████╗██╗   ██╗██╗██╗     ███╗   ███╗██╗███████╗████████╗
██╔════╝██║   ██║██║██║     ████╗ ████║██║██╔════╝╚══██╔══╝
█████╗  ██║   ██║██║██║     ██╔████╔██║██║███████╗   ██║
██╔══╝  ╚██╗ ██╔╝██║██║     ██║╚██╔╝██║██║╚════██║   ██║
███████╗ ╚████╔╝ ██║███████╗██║ ╚═╝ ██║██║███████║   ██║
╚══════╝  ╚═══╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝╚══════╝   ╚═╝

    Entra ID Unauthenticated Enumeration - EvilMist Toolkit
    https://logisek.com | info@logisek.com
    GNU General Public License v3.0

[*] Target: contoso.com

======================================================================
TENANT DISCOVERY
======================================================================
[*] Querying azmap.dev API...
[+] Tenant ID: 12345678-1234-1234-1234-123456789012
[+] Tenant Name: Contoso Inc
[+] Region: US
[*] Querying OpenID configuration...
[+] Token Endpoint: https://login.microsoftonline.com/.../oauth2/v2.0/token
[+] Authorization Endpoint: https://login.microsoftonline.com/.../oauth2/v2.0/authorize

======================================================================
DOMAIN REALM INFORMATION
======================================================================
[*] Querying getuserrealm.srf...
[+] Namespace Type: Managed
[+] Federation Status: Managed (Azure AD)
[+] Cloud Instance: microsoftonline.com

======================================================================
ONEDRIVE USER ENUMERATION (SILENT)
======================================================================
[*] Checking 3 email address(es) via OneDrive...
[*] Tenant: contoso
[!] This method is completely undetectable - no audit logs generated

[+] admin@contoso.com - EXISTS (Status: 403)
[+] user1@contoso.com - EXISTS (Status: 403)
[-] nonexistent@contoso.com - Does Not Exist (Status: 404)

[*] OneDrive enumeration complete: 2 of 3 exist

======================================================================
SEAMLESS SSO DETECTION
======================================================================
[*] Checking Seamless SSO configuration...
[+] Desktop SSO: ENABLED
[!] Seamless SSO enabled - Autologon enumeration may be possible
[+] Autologon Endpoint: https://autologon.microsoftazuread-sso.com/.../winauth/trust/2005/usernamemixed
[+] Autologon endpoint is reachable (Status: 200)

======================================================================
AZURE SUBDOMAIN ENUMERATION
======================================================================
[*] Checking Azure subdomains for tenant: contoso
[*] Core patterns: 26
[*] Permutations: 19

[+] contoso.onmicrosoft.com (Primary Tenant Domain)
[+] contoso.sharepoint.com (SharePoint)
[+] contoso-my.sharepoint.com (OneDrive)
[+] contoso.blob.core.windows.net (Azure Blob Storage)
[+] contoso.vault.azure.net (Key Vault)

[*] Subdomain enumeration complete: 5 of 50 found

======================================================================
ENHANCED MAIL SECURITY ENUMERATION
======================================================================
[*] Checking MX records...
[+] MX: contoso-com.mail.protection.outlook.com (Priority: 0) [Exchange Online]
[*] Checking SPF record...
[+] SPF: v=spf1 include:spf.protection.outlook.com -all
[*] Checking DMARC record...
[+] DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com
[*] Checking DKIM selectors...
[+] DKIM (selector1): Found
[+] DKIM (selector2): Found

[*] Security Analysis:
    - SPF includes Exchange Online
    - SPF: Hard fail (-all) - strict policy
    - DMARC: Reject policy - strict

======================================================================
ENUMERATION SUMMARY
======================================================================

  Target Domain:     contoso.com
  Tenant ID:         12345678-1234-1234-1234-123456789012
  Federated:         No (Azure AD Managed)
  OneDrive Checked:  3
  OneDrive Exist:    2
  Subdomains Checked: 50
  Subdomains Found:   5
  Seamless SSO:      ENABLED

[*] Enumeration completed. Total requests: 75
```
