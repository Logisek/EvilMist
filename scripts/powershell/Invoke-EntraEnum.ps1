<#
    This file is part of the toolkit EvilMist
    Copyright (C) 2025 Logisek
    https://github.com/Logisek/EvilMist

    EvilMist - a collection of scripts and utilities designed to support
    cloud penetration testing. The toolkit helps identify misconfigurations,
    assess privilege-escalation paths, and simulate attack techniques.
    EvilMist aims to streamline cloud-focused red-team workflows and improve
    the overall security posture of cloud infrastructures.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    For more see the file 'LICENSE' for copying permission.
#>

<#
.SYNOPSIS
    Unauthenticated Azure/Entra ID enumeration and reconnaissance.

.DESCRIPTION
    This script performs passive/semi-passive enumeration of Azure/Entra ID
    tenants using publicly accessible APIs and DNS queries. No authentication
    tokens are required.

    Enumeration methods include:
    - Tenant discovery (azmap.dev + OpenID configuration)
    - Domain realm/federation info
    - User existence via GetCredentialType
    - DNS reconnaissance (Autodiscover, MX, SPF, SRV records)
    - TCP port scanning for Azure-related services
    - Autodiscover V1/V2 user enumeration
    - Exchange Web Services (EWS) exposure probing
    - SharePoint/Teams site discovery
    - Lync/Skype discovery endpoint probing

.PARAMETER Domain
    Target domain for enumeration (e.g., logisek.com).

.PARAMETER Email
    Single email address for user existence check.

.PARAMETER Emails
    Array of email addresses for bulk user enumeration.

.PARAMETER EmailList
    Path to a file containing email addresses (one per line).

.PARAMETER All
    Run all enumeration methods.

.PARAMETER TenantInfo
    Perform tenant discovery (azmap.dev + OpenID configuration).

.PARAMETER DomainRealm
    Retrieve domain namespace and federation information.

.PARAMETER UserEnum
    Check user existence via GetCredentialType API.

.PARAMETER DnsEnum
    Perform DNS reconnaissance for the target domain.

.PARAMETER PortScan
    Perform TCP port scanning on the target domain.

.PARAMETER OneDriveEnum
    Check user existence via OneDrive personal site URLs.
    Completely undetectable - no audit logs generated.

.PARAMETER FederationMeta
    Retrieve federation metadata including signing certificates
    and token endpoints. Useful for identifying ADFS presence.

.PARAMETER SeamlessSSO
    Detect Seamless SSO configuration and Autologon endpoint.
    When enabled, user enumeration via Autologon is undetectable.

.PARAMETER SubdomainEnum
    Enumerate Azure subdomains associated with the tenant
    (SharePoint, Blob Storage, Key Vault, etc.).

.PARAMETER AutodiscoverEnum
    Check user existence via Autodiscover V2 JSON endpoints.

.PARAMETER AutodiscoverV1Enum
    Check user existence via legacy Autodiscover V1 XML endpoints.

.PARAMETER EwsProbe
    Probe Exchange Web Services (EWS) endpoints for exposure.

.PARAMETER SharePointEnum
    Discover SharePoint/Teams tenant and common site URLs.

.PARAMETER LyncProbe
    Probe Lync/Skype discovery endpoints for exposure.

.PARAMETER MailEnum
    Enhanced mail security analysis: DMARC, DKIM, MTA-STS,
    BIMI, TLS-RPT records.

.PARAMETER TenantReverse
    Given a tenant ID, discover associated resources and
    endpoints across Azure services.

.PARAMETER OAuthProbe
    Enumerate OAuth configuration through error message
    analysis of well-known application IDs.

.PARAMETER TenantName
    Override tenant name for subdomain, OneDrive, and SharePoint enumeration.
    If not specified, extracted from domain.

.PARAMETER WordList
    Path to custom wordlist for subdomain permutation.

.PARAMETER SharePointWordList
    Path to custom wordlist for SharePoint/Teams site discovery.

.PARAMETER EnableStealth
    Enable stealth mode with default delays and jitter.

.PARAMETER RequestDelay
    Base delay in seconds between requests (0-60). Default: 0

.PARAMETER RequestJitter
    Random jitter range in seconds to add/subtract from delay (0-30). Default: 0

.PARAMETER Throttle
    Delay in seconds between user enumeration requests (0.1-10). Default: 0.5

.PARAMETER QuietStealth
    Suppress stealth-related status messages.

.PARAMETER Ports
    Custom ports to scan (default: common Azure ports).

.PARAMETER PortTimeout
    TCP connection timeout in milliseconds (100-30000). Default: 1000

.PARAMETER ExportPath
    Path to export results (CSV or JSON based on extension).

.PARAMETER Matrix
    Display results in table/matrix format.

.EXAMPLE
    .\Invoke-EntraEnum.ps1 -Domain microsoft.com
    # Runs default enumeration (TenantInfo, DomainRealm, DnsEnum)

.EXAMPLE
    .\Invoke-EntraEnum.ps1 -Domain contoso.com -All
    # Runs all enumeration methods

.EXAMPLE
    .\Invoke-EntraEnum.ps1 -Email test@contoso.com -UserEnum
    # Checks if a single user exists

.EXAMPLE
    .\Invoke-EntraEnum.ps1 -EmailList users.txt -UserEnum -Throttle 1
    # Bulk user enumeration with 1 second delay

.EXAMPLE
    .\Invoke-EntraEnum.ps1 -Domain contoso.com -PortScan -Ports 443,80,3389
    # Scan specific ports

.EXAMPLE
    .\Invoke-EntraEnum.ps1 -Domain contoso.com -All -ExportPath results.json
    # Export all results to JSON

.EXAMPLE
    .\Invoke-EntraEnum.ps1 -EmailList users.txt -OneDriveEnum -TenantName contoso
    # Silent user enumeration via OneDrive (completely undetectable)

.EXAMPLE
    .\Invoke-EntraEnum.ps1 -Domain contoso.com -FederationMeta -SeamlessSSO
    # Check federation metadata and SSO configuration

.EXAMPLE
    .\Invoke-EntraEnum.ps1 -Domain contoso.com -SubdomainEnum -TenantName contoso
    # Enumerate Azure subdomains for tenant

.EXAMPLE
    .\Invoke-EntraEnum.ps1 -Domain contoso.com -MailEnum
    # Enhanced mail security analysis (DMARC, DKIM, MTA-STS, etc.)

.EXAMPLE
    .\Invoke-EntraEnum.ps1 -Domain contoso.com -OAuthProbe
    # Probe OAuth configuration and accessible applications
#>

param(
    # === PRIMARY INPUT ===
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [string]$Email,

    [Parameter(Mandatory = $false)]
    [string[]]$Emails,

    [Parameter(Mandatory = $false)]
    [string]$EmailList,

    # === METHOD SWITCHES ===
    [Parameter(Mandatory = $false)]
    [switch]$All,

    [Parameter(Mandatory = $false)]
    [switch]$TenantInfo,

    [Parameter(Mandatory = $false)]
    [switch]$DomainRealm,

    [Parameter(Mandatory = $false)]
    [switch]$UserEnum,

    [Parameter(Mandatory = $false)]
    [switch]$DnsEnum,

    [Parameter(Mandatory = $false)]
    [switch]$PortScan,

    # === NEW ENUMERATION METHODS ===
    [Parameter(Mandatory = $false)]
    [switch]$OneDriveEnum,

    [Parameter(Mandatory = $false)]
    [switch]$FederationMeta,

    [Parameter(Mandatory = $false)]
    [switch]$SeamlessSSO,

    [Parameter(Mandatory = $false)]
    [switch]$SubdomainEnum,

    [Parameter(Mandatory = $false)]
    [switch]$AutodiscoverEnum,

    [Parameter(Mandatory = $false)]
    [switch]$AutodiscoverV1Enum,

    [Parameter(Mandatory = $false)]
    [switch]$EwsProbe,

    [Parameter(Mandatory = $false)]
    [switch]$SharePointEnum,

    [Parameter(Mandatory = $false)]
    [switch]$LyncProbe,

    [Parameter(Mandatory = $false)]
    [switch]$MailEnum,

    [Parameter(Mandatory = $false)]
    [switch]$TenantReverse,

    [Parameter(Mandatory = $false)]
    [switch]$OAuthProbe,

    # === NEW METHOD PARAMETERS ===
    [Parameter(Mandatory = $false)]
    [string]$TenantName,

    [Parameter(Mandatory = $false)]
    [string]$WordList,

    [Parameter(Mandatory = $false)]
    [string]$SharePointWordList,

    # === RATE LIMITING / STEALTH ===
    [Parameter(Mandatory = $false)]
    [switch]$EnableStealth,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 60)]
    [double]$RequestDelay = 0,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 30)]
    [double]$RequestJitter = 0,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0.1, 10)]
    [double]$Throttle = 0.5,

    [Parameter(Mandatory = $false)]
    [switch]$QuietStealth,

    # === PORT SCAN SPECIFIC ===
    [Parameter(Mandatory = $false)]
    [int[]]$Ports,

    [Parameter(Mandatory = $false)]
    [ValidateRange(100, 30000)]
    [int]$PortTimeout = 1000,

    # === OUTPUT ===
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [Parameter(Mandatory = $false)]
    [switch]$Matrix
)

# PowerShell 7+ required
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] This script requires PowerShell 7 or later.' -ForegroundColor Red
    Write-Host ('Current version: PowerShell ' + $PSVersionTable.PSVersion.ToString()) -ForegroundColor Yellow
    Write-Host 'Download PowerShell 7: https://aka.ms/powershell-release?tag=stable' -ForegroundColor Cyan
    exit 1
}

$ErrorActionPreference = "Continue"

# ============================================================================
# RESULTS DATA STRUCTURE
# ============================================================================

$script:Results = @{
    TenantInfo = $null
    DomainRealm = $null
    UserEnumeration = @()
    DnsRecords = @{
        CNAME = @()
        Autodiscover = @()
        SPF = @()
        TXT = @()
        SRV = @()
        MX = @()
    }
    PortScan = @()
    # New method results
    OneDriveEnum = @()
    FederationMeta = $null
    SeamlessSSO = $null
    SubdomainEnum = @()
    AutodiscoverV2 = @()
    AutodiscoverV1 = @()
    EwsProbe = @()
    SharePointEnum = @()
    LyncProbe = @()
    MailEnum = $null
    TenantReverse = $null
    OAuthProbe = @()
    Summary = @{
        Domain = $null
        TenantId = $null
        TenantName = $null
        IsFederated = $null
        UsersChecked = 0
        UsersExist = 0
        PortsScanned = 0
        PortsOpen = 0
        # New summary fields
        OneDriveUsersChecked = 0
        OneDriveUsersExist = 0
        SubdomainsChecked = 0
        SubdomainsFound = 0
        SeamlessSSOEnabled = $null
        AutodiscoverV1Checked = 0
        AutodiscoverV1Exist = 0
        SharePointSitesChecked = 0
        SharePointSitesFound = 0
        SharePointPublicSites = 0
        EwsEndpointsFound = 0
        LyncEndpointsFound = 0
    }
}

# ============================================================================
# STEALTH CONFIGURATION
# ============================================================================

$script:StealthConfig = @{
    Enabled = $EnableStealth.IsPresent
    BaseDelay = $RequestDelay
    Jitter = $RequestJitter
    QuietMode = $QuietStealth.IsPresent
    RequestCount = 0
    LastRequestTime = $null
}

# If stealth is enabled but no delay specified, use sensible defaults
if ($EnableStealth.IsPresent -and $RequestDelay -eq 0) {
    $script:StealthConfig.BaseDelay = 0.5
    $script:StealthConfig.Jitter = 0.3
}

# Default ports for Azure/Entra ID related services
$script:DefaultPorts = @(
    @{ Port = 443;  Service = "HTTPS";    Description = "Web services / Azure portals" }
    @{ Port = 80;   Service = "HTTP";     Description = "HTTP redirect / legacy" }
    @{ Port = 389;  Service = "LDAP";     Description = "Directory services" }
    @{ Port = 636;  Service = "LDAPS";    Description = "Secure LDAP" }
    @{ Port = 88;   Service = "Kerberos"; Description = "Authentication (hybrid/AADDS)" }
    @{ Port = 587;  Service = "SMTP/TLS"; Description = "Email submission" }
    @{ Port = 25;   Service = "SMTP";     Description = "Mail server" }
    @{ Port = 3389; Service = "RDP";      Description = "Remote Desktop" }
    @{ Port = 445;  Service = "SMB";      Description = "File sharing" }
)

# ============================================================================
# BANNER
# ============================================================================

function Show-Banner {
    Write-Host ""

    $asciiArt = @"
███████╗██╗   ██╗██╗██╗     ███╗   ███╗██╗███████╗████████╗
██╔════╝██║   ██║██║██║     ████╗ ████║██║██╔════╝╚══██╔══╝
█████╗  ██║   ██║██║██║     ██╔████╔██║██║███████╗   ██║
██╔══╝  ╚██╗ ██╔╝██║██║     ██║╚██╔╝██║██║╚════██║   ██║
███████╗ ╚████╔╝ ██║███████╗██║ ╚═╝ ██║██║███████║   ██║
╚══════╝  ╚═══╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝╚══════╝   ╚═╝
"@

    Write-Host $asciiArt -ForegroundColor Magenta
    Write-Host "    Entra ID Unauthenticated Enumeration - EvilMist Toolkit" -ForegroundColor Yellow
    Write-Host "    https://logisek.com | info@logisek.com"
    Write-Host "    GNU General Public License v3.0"
    Write-Host ""
    Write-Host ""
}

# ============================================================================
# STEALTH FUNCTIONS
# ============================================================================

function Get-StealthDelay {
    $baseDelay = $script:StealthConfig.BaseDelay
    $jitter = $script:StealthConfig.Jitter

    if ($baseDelay -eq 0 -and $jitter -eq 0) {
        return 0
    }

    $jitterValue = 0
    if ($jitter -gt 0) {
        $jitterValue = (Get-Random -Minimum (-$jitter * 1000) -Maximum ($jitter * 1000)) / 1000
    }

    $totalDelay = [Math]::Max(0, $baseDelay + $jitterValue)
    return $totalDelay
}

function Invoke-StealthDelay {
    param(
        [string]$Context = ""
    )

    if (-not $script:StealthConfig.Enabled -and $script:StealthConfig.BaseDelay -eq 0) {
        return
    }

    $delay = Get-StealthDelay

    if ($delay -gt 0) {
        if (-not $script:StealthConfig.QuietMode -and $Context) {
            Write-Host "    [Stealth] Waiting $([Math]::Round($delay, 2))s before $Context..." -ForegroundColor DarkGray
        }
        Start-Sleep -Milliseconds ([int]($delay * 1000))
    }

    $script:StealthConfig.LastRequestTime = Get-Date
}

# ============================================================================
# HTTP HELPER FUNCTIONS
# ============================================================================

function Invoke-WebRequestSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [object]$Body = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers = @{},

        [Parameter(Mandatory = $false)]
        [string]$ContentType = "application/json",

        [Parameter(Mandatory = $false)]
        [string]$Context = "request"
    )

    Invoke-StealthDelay -Context $Context
    $script:StealthConfig.RequestCount++

    try {
        $params = @{
            Uri = $Uri
            Method = $Method
            Headers = $Headers
            ContentType = $ContentType
            UseBasicParsing = $true
            ErrorAction = "Stop"
        }

        if ($Body) {
            if ($Body -is [hashtable] -or $Body -is [PSCustomObject]) {
                $params.Body = ($Body | ConvertTo-Json -Compress)
            } else {
                $params.Body = $Body
            }
        }

        $response = Invoke-WebRequest @params
        return @{
            Success = $true
            StatusCode = $response.StatusCode
            Content = $response.Content
            Headers = $response.Headers
        }
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        return @{
            Success = $false
            StatusCode = $statusCode
            Error = $_.Exception.Message
            Content = $null
        }
    }
}

function Invoke-WebRequestDetailed {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [object]$Body = $null,

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers = @{},

        [Parameter(Mandatory = $false)]
        [string]$ContentType = "application/xml",

        [Parameter(Mandatory = $false)]
        [string]$Context = "request"
    )

    Invoke-StealthDelay -Context $Context
    $script:StealthConfig.RequestCount++

    try {
        $params = @{
            Uri = $Uri
            Method = $Method
            Headers = $Headers
            ContentType = $ContentType
            UseBasicParsing = $true
            ErrorAction = "Stop"
            MaximumRedirection = 0
        }

        if ($Body) {
            $params.Body = $Body
        }

        $response = Invoke-WebRequest @params
        return @{
            Success = $true
            StatusCode = $response.StatusCode
            Content = $response.Content
            Headers = $response.Headers
            Error = $null
        }
    }
    catch {
        $statusCode = $null
        $content = $null
        $responseHeaders = $null

        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            $responseHeaders = $_.Exception.Response.Headers
            try {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $content = $reader.ReadToEnd()
                $reader.Close()
            }
            catch {}
        }

        return @{
            Success = $false
            StatusCode = $statusCode
            Content = $content
            Headers = $responseHeaders
            Error = $_.Exception.Message
        }
    }
}

# ============================================================================
# USER ENUMERATION HELPER
# ============================================================================

function Get-IfExistsResultMeaning {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Code
    )

    switch ($Code) {
        0 { return @{ Exists = $true;  Description = "Exists (Azure IdP)" } }
        1 { return @{ Exists = $false; Description = "Does Not Exist" } }
        2 { return @{ Exists = $null;  Description = "Invalid Request" } }
        4 { return @{ Exists = $null;  Description = "Server Error" } }
        5 { return @{ Exists = $true;  Description = "Exists (Federated IdP)" } }
        6 { return @{ Exists = $true;  Description = "Exists (External non-MS IdP)" } }
        default { return @{ Exists = $null; Description = "Unknown ($Code)" } }
    }
}

# ============================================================================
# ENUMERATION FUNCTIONS
# ============================================================================

function Get-TenantInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "TENANT DISCOVERY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    $tenantInfo = [PSCustomObject]@{
        Domain = $Domain
        TenantId = $null
        TenantName = $null
        Region = $null
        TokenEndpoint = $null
        AuthorizationEndpoint = $null
        JwksUri = $null
        Issuer = $null
        AzmapData = $null
    }

    # Method 1: azmap.dev API
    Write-Host "[*] Querying azmap.dev API..." -ForegroundColor Cyan
    $azmapUrl = "https://azmap.dev/api/tenant?domain=$Domain&extract=true"
    $azmapResult = Invoke-WebRequestSafe -Uri $azmapUrl -Context "azmap.dev lookup"

    if ($azmapResult.Success) {
        try {
            $azmapData = $azmapResult.Content | ConvertFrom-Json
            $tenantInfo.AzmapData = $azmapData

            if ($azmapData.tenantId) {
                $tenantInfo.TenantId = $azmapData.tenantId
                Write-Host "[+] Tenant ID: $($azmapData.tenantId)" -ForegroundColor Green
            }
            if ($azmapData.displayName) {
                $tenantInfo.TenantName = $azmapData.displayName
                Write-Host "[+] Tenant Name: $($azmapData.displayName)" -ForegroundColor Green
            }
            if ($azmapData.countryCode) {
                $tenantInfo.Region = $azmapData.countryCode
                Write-Host "[+] Region: $($azmapData.countryCode)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[!] Failed to parse azmap.dev response" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[-] azmap.dev lookup failed: $($azmapResult.Error)" -ForegroundColor Gray
    }

    # Method 2: OpenID Configuration
    Write-Host "[*] Querying OpenID configuration..." -ForegroundColor Cyan
    $openIdUrl = "https://login.microsoftonline.com/$Domain/v2.0/.well-known/openid-configuration"
    $openIdResult = Invoke-WebRequestSafe -Uri $openIdUrl -Context "OpenID config"

    if ($openIdResult.Success) {
        try {
            $openIdData = $openIdResult.Content | ConvertFrom-Json

            $tenantInfo.TokenEndpoint = $openIdData.token_endpoint
            $tenantInfo.AuthorizationEndpoint = $openIdData.authorization_endpoint
            $tenantInfo.JwksUri = $openIdData.jwks_uri
            $tenantInfo.Issuer = $openIdData.issuer

            # Extract tenant ID from issuer URL if not already set
            if (-not $tenantInfo.TenantId -and $openIdData.issuer) {
                if ($openIdData.issuer -match '/([a-f0-9-]{36})/') {
                    $tenantInfo.TenantId = $Matches[1]
                    Write-Host "[+] Tenant ID (from issuer): $($tenantInfo.TenantId)" -ForegroundColor Green
                }
            }

            Write-Host "[+] Token Endpoint: $($openIdData.token_endpoint)" -ForegroundColor Green
            Write-Host "[+] Authorization Endpoint: $($openIdData.authorization_endpoint)" -ForegroundColor Green
            Write-Host "[+] JWKS URI: $($openIdData.jwks_uri)" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Failed to parse OpenID configuration" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[-] OpenID configuration lookup failed: $($openIdResult.Error)" -ForegroundColor Gray
    }

    # Update summary
    if ($tenantInfo.TenantId) {
        $script:Results.Summary.TenantId = $tenantInfo.TenantId
    }

    $script:Results.TenantInfo = $tenantInfo
    return $tenantInfo
}

function Get-DomainRealm {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "DOMAIN REALM INFORMATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    $realmInfo = [PSCustomObject]@{
        Domain = $Domain
        NameSpaceType = $null
        IsFederated = $null
        AuthURL = $null
        CloudInstanceName = $null
        FederationBrandName = $null
        DomainName = $null
        State = $null
    }

    Write-Host "[*] Querying getuserrealm.srf..." -ForegroundColor Cyan
    $realmUrl = "https://login.microsoftonline.com/getuserrealm.srf?login=enum@$Domain&json=1"
    $realmResult = Invoke-WebRequestSafe -Uri $realmUrl -Context "domain realm"

    if ($realmResult.Success) {
        try {
            $realmData = $realmResult.Content | ConvertFrom-Json

            $realmInfo.NameSpaceType = $realmData.NameSpaceType
            $realmInfo.DomainName = $realmData.DomainName
            $realmInfo.CloudInstanceName = $realmData.CloudInstanceName
            $realmInfo.FederationBrandName = $realmData.FederationBrandName
            $realmInfo.State = $realmData.State

            if ($realmData.AuthURL) {
                $realmInfo.AuthURL = $realmData.AuthURL
                $realmInfo.IsFederated = $true
            }
            else {
                $realmInfo.IsFederated = $false
            }

            # Display results
            Write-Host "[+] Namespace Type: $($realmInfo.NameSpaceType)" -ForegroundColor Green

            if ($realmInfo.IsFederated) {
                Write-Host "[+] Federation Status: FEDERATED" -ForegroundColor Yellow
                Write-Host "[+] Auth URL: $($realmInfo.AuthURL)" -ForegroundColor Green
            }
            else {
                Write-Host "[+] Federation Status: Managed (Azure AD)" -ForegroundColor Green
            }

            if ($realmInfo.CloudInstanceName) {
                Write-Host "[+] Cloud Instance: $($realmInfo.CloudInstanceName)" -ForegroundColor Green
            }
            if ($realmInfo.FederationBrandName) {
                Write-Host "[+] Federation Brand: $($realmInfo.FederationBrandName)" -ForegroundColor Green
            }
            if ($realmInfo.DomainName) {
                Write-Host "[+] Domain Name: $($realmInfo.DomainName)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[!] Failed to parse realm response" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[-] Domain realm lookup failed: $($realmResult.Error)" -ForegroundColor Gray
    }

    # Update summary
    $script:Results.Summary.IsFederated = $realmInfo.IsFederated
    $script:Results.DomainRealm = $realmInfo
    return $realmInfo
}

function Test-UserExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EmailAddress
    )

    $userResult = [PSCustomObject]@{
        Email = $EmailAddress
        Exists = $null
        IfExistsResult = $null
        ResultDescription = $null
        ThrottleStatus = $null
        Error = $null
    }

    $body = @{
        Username = $EmailAddress
        isOtherIdpSupported = $true
        checkPhones = $false
        isRemoteNGCSupported = $true
        isCookieBannerShown = $false
        isFidoSupported = $true
        originalRequest = ""
        country = "US"
        forceotclogin = $false
        isExternalFederationDisallowed = $false
        isRemoteConnectSupported = $false
        federationFlags = 0
        isSignup = $false
        flowToken = ""
        isAccessPassSupported = $true
    }

    $url = "https://login.microsoftonline.com/common/GetCredentialType"
    $result = Invoke-WebRequestSafe -Uri $url -Method "POST" -Body $body -Context "user check: $EmailAddress"

    if ($result.Success) {
        try {
            $data = $result.Content | ConvertFrom-Json

            if ($null -ne $data.IfExistsResult) {
                $userResult.IfExistsResult = $data.IfExistsResult
                $meaning = Get-IfExistsResultMeaning -Code $data.IfExistsResult
                $userResult.Exists = $meaning.Exists
                $userResult.ResultDescription = $meaning.Description
            }

            if ($data.ThrottleStatus -and $data.ThrottleStatus -ne 0) {
                $userResult.ThrottleStatus = $data.ThrottleStatus
            }
        }
        catch {
            $userResult.Error = "Failed to parse response"
        }
    }
    else {
        $userResult.Error = $result.Error
    }

    return $userResult
}

function Invoke-UserEnumeration {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$EmailAddresses
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "USER ENUMERATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    Write-Host "[*] Checking $($EmailAddresses.Count) email address(es)..." -ForegroundColor Cyan
    Write-Host "[*] Throttle delay: $Throttle seconds between requests" -ForegroundColor Gray
    Write-Host ""

    $results = @()
    $existCount = 0

    foreach ($email in $EmailAddresses) {
        $userResult = Test-UserExists -EmailAddress $email
        $results += $userResult

        # Display result
        if ($userResult.Exists -eq $true) {
            Write-Host "[+] $email - $($userResult.ResultDescription)" -ForegroundColor Green
            $existCount++
        }
        elseif ($userResult.Exists -eq $false) {
            Write-Host "[-] $email - $($userResult.ResultDescription)" -ForegroundColor Gray
        }
        else {
            Write-Host "[!] $email - $($userResult.ResultDescription)" -ForegroundColor Yellow
        }

        if ($userResult.ThrottleStatus) {
            Write-Host "    [!] Throttle detected (status: $($userResult.ThrottleStatus))" -ForegroundColor Yellow
        }

        if ($userResult.Error) {
            Write-Host "    [ERROR] $($userResult.Error)" -ForegroundColor Red
        }

        # Apply throttle delay between requests
        if ($EmailAddresses.IndexOf($email) -lt ($EmailAddresses.Count - 1)) {
            Start-Sleep -Milliseconds ([int]($Throttle * 1000))
        }
    }

    # Update summary
    $script:Results.Summary.UsersChecked = $EmailAddresses.Count
    $script:Results.Summary.UsersExist = $existCount
    $script:Results.UserEnumeration = $results

    Write-Host ""
    Write-Host "[*] User enumeration complete: $existCount of $($EmailAddresses.Count) exist" -ForegroundColor Cyan

    return $results
}

function Get-DnsRecords {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "DNS RECONNAISSANCE" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    $dnsResults = @{
        CNAME = @()
        Autodiscover = @()
        SPF = @()
        TXT = @()
        SRV = @()
        MX = @()
    }

    # CNAME lookup for main domain
    Write-Host "[*] Checking CNAME records for $Domain..." -ForegroundColor Cyan
    try {
        $cnameRecords = Resolve-DnsName -Name $Domain -Type CNAME -ErrorAction SilentlyContinue
        if ($cnameRecords) {
            foreach ($record in $cnameRecords) {
                if ($record.NameHost) {
                    $dnsResults.CNAME += [PSCustomObject]@{
                        Name = $record.Name
                        Target = $record.NameHost
                        Type = "CNAME"
                    }
                    Write-Host "[+] CNAME: $($record.Name) -> $($record.NameHost)" -ForegroundColor Green
                }
            }
        }
        else {
            Write-Host "[-] No CNAME records found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[-] CNAME lookup failed: $_" -ForegroundColor Gray
    }

    # Autodiscover CNAME
    Write-Host "[*] Checking Autodiscover records..." -ForegroundColor Cyan
    $autodiscoverNames = @("autodiscover.$Domain", "lyncdiscover.$Domain", "sip.$Domain")

    foreach ($autodiscoverName in $autodiscoverNames) {
        try {
            $records = Resolve-DnsName -Name $autodiscoverName -Type CNAME -ErrorAction SilentlyContinue
            if ($records) {
                foreach ($record in $records) {
                    if ($record.NameHost) {
                        $dnsResults.Autodiscover += [PSCustomObject]@{
                            Name = $record.Name
                            Target = $record.NameHost
                            Type = "CNAME"
                        }
                        Write-Host "[+] Autodiscover: $($record.Name) -> $($record.NameHost)" -ForegroundColor Green
                    }
                }
            }
        }
        catch {
            # Silently continue
        }
    }

    if ($dnsResults.Autodiscover.Count -eq 0) {
        Write-Host "[-] No Autodiscover records found" -ForegroundColor Gray
    }

    # TXT records (including SPF)
    Write-Host "[*] Checking TXT/SPF records..." -ForegroundColor Cyan
    try {
        $txtRecords = Resolve-DnsName -Name $Domain -Type TXT -ErrorAction SilentlyContinue
        if ($txtRecords) {
            foreach ($record in $txtRecords) {
                $strings = $record.Strings -join ""
                $txtEntry = [PSCustomObject]@{
                    Name = $record.Name
                    Value = $strings
                    Type = "TXT"
                }
                $dnsResults.TXT += $txtEntry

                if ($strings -match "v=spf1") {
                    $dnsResults.SPF += $txtEntry
                    Write-Host "[+] SPF: $strings" -ForegroundColor Green
                }
                elseif ($strings -match "MS=" -or $strings -match "microsoft" -or $strings -match "azure") {
                    Write-Host "[+] TXT (Microsoft): $strings" -ForegroundColor Green
                }
                else {
                    Write-Host "[+] TXT: $($strings.Substring(0, [Math]::Min(60, $strings.Length)))..." -ForegroundColor Gray
                }
            }
        }
        else {
            Write-Host "[-] No TXT records found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[-] TXT lookup failed: $_" -ForegroundColor Gray
    }

    # SRV records
    Write-Host "[*] Checking SRV records..." -ForegroundColor Cyan
    $srvNames = @(
        "_ldap._tcp.$Domain",
        "_kerberos._tcp.$Domain",
        "_autodiscover._tcp.$Domain",
        "_sip._tls.$Domain",
        "_sipfederationtls._tcp.$Domain"
    )

    foreach ($srvName in $srvNames) {
        try {
            $srvRecords = Resolve-DnsName -Name $srvName -Type SRV -ErrorAction SilentlyContinue
            if ($srvRecords) {
                foreach ($record in $srvRecords) {
                    if ($record.NameTarget) {
                        $dnsResults.SRV += [PSCustomObject]@{
                            Name = $record.Name
                            Target = $record.NameTarget
                            Port = $record.Port
                            Priority = $record.Priority
                            Weight = $record.Weight
                            Type = "SRV"
                        }
                        Write-Host "[+] SRV: $($record.Name) -> $($record.NameTarget):$($record.Port)" -ForegroundColor Green
                    }
                }
            }
        }
        catch {
            # Silently continue
        }
    }

    if ($dnsResults.SRV.Count -eq 0) {
        Write-Host "[-] No SRV records found" -ForegroundColor Gray
    }

    # MX records
    Write-Host "[*] Checking MX records..." -ForegroundColor Cyan
    try {
        $mxRecords = Resolve-DnsName -Name $Domain -Type MX -ErrorAction SilentlyContinue
        if ($mxRecords) {
            foreach ($record in $mxRecords) {
                if ($record.NameExchange) {
                    $dnsResults.MX += [PSCustomObject]@{
                        Name = $record.Name
                        Exchange = $record.NameExchange
                        Preference = $record.Preference
                        Type = "MX"
                    }
                    $o365Indicator = ""
                    if ($record.NameExchange -match "mail.protection.outlook.com") {
                        $o365Indicator = " (Office 365)"
                    }
                    Write-Host "[+] MX: $($record.NameExchange) (Priority: $($record.Preference))$o365Indicator" -ForegroundColor Green
                }
            }
        }
        else {
            Write-Host "[-] No MX records found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[-] MX lookup failed: $_" -ForegroundColor Gray
    }

    $script:Results.DnsRecords = $dnsResults
    return $dnsResults
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $false)]
        [int]$Timeout = 1000
    )

    $result = [PSCustomObject]@{
        Host = $HostName
        Port = $Port
        Status = "Unknown"
        ResponseTime = $null
    }

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        $asyncResult = $tcpClient.BeginConnect($HostName, $Port, $null, $null)
        $waitHandle = $asyncResult.AsyncWaitHandle

        if ($waitHandle.WaitOne($Timeout, $false)) {
            try {
                $tcpClient.EndConnect($asyncResult)
                $stopwatch.Stop()
                $result.Status = "Open"
                $result.ResponseTime = $stopwatch.ElapsedMilliseconds
            }
            catch {
                $result.Status = "Closed"
            }
        }
        else {
            $result.Status = "Filtered"
        }

        $tcpClient.Close()
    }
    catch {
        $result.Status = "Error"
    }

    return $result
}

function Invoke-PortScan {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [int[]]$CustomPorts = $null
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "PORT SCAN" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    # Determine which ports to scan
    $portsToScan = @()
    if ($CustomPorts -and $CustomPorts.Count -gt 0) {
        foreach ($port in $CustomPorts) {
            $portInfo = $script:DefaultPorts | Where-Object { $_.Port -eq $port }
            if ($portInfo) {
                $portsToScan += $portInfo
            }
            else {
                $portsToScan += @{ Port = $port; Service = "Custom"; Description = "User-specified" }
            }
        }
    }
    else {
        $portsToScan = $script:DefaultPorts
    }

    Write-Host "[*] Scanning $($portsToScan.Count) ports on $Domain..." -ForegroundColor Cyan
    Write-Host "[*] Timeout: $PortTimeout ms" -ForegroundColor Gray
    Write-Host ""

    $results = @()
    $openCount = 0

    foreach ($portInfo in $portsToScan) {
        $port = $portInfo.Port
        $service = $portInfo.Service
        $description = $portInfo.Description

        $scanResult = Test-TcpPort -HostName $Domain -Port $port -Timeout $PortTimeout

        $resultEntry = [PSCustomObject]@{
            Host = $Domain
            Port = $port
            Service = $service
            Description = $description
            Status = $scanResult.Status
            ResponseTime = $scanResult.ResponseTime
        }
        $results += $resultEntry

        # Display result
        switch ($scanResult.Status) {
            "Open" {
                $responseInfo = if ($scanResult.ResponseTime) { " ($($scanResult.ResponseTime)ms)" } else { "" }
                Write-Host "[+] Port $port ($service) - OPEN$responseInfo" -ForegroundColor Green
                $openCount++
            }
            "Closed" {
                Write-Host "[-] Port $port ($service) - Closed" -ForegroundColor Gray
            }
            "Filtered" {
                Write-Host "[!] Port $port ($service) - Filtered/Timeout" -ForegroundColor Yellow
            }
            default {
                Write-Host "[!] Port $port ($service) - $($scanResult.Status)" -ForegroundColor Yellow
            }
        }
    }

    # Update summary
    $script:Results.Summary.PortsScanned = $portsToScan.Count
    $script:Results.Summary.PortsOpen = $openCount
    $script:Results.PortScan = $results

    Write-Host ""
    Write-Host "[*] Port scan complete: $openCount of $($portsToScan.Count) ports open" -ForegroundColor Cyan

    return $results
}

# ============================================================================
# NEW ENUMERATION METHODS
# ============================================================================

# ----------------------------------------------------------------------------
# 1. OneDrive User Enumeration (-OneDriveEnum)
# Completely undetectable - No authentication attempts logged
# ----------------------------------------------------------------------------

function Test-OneDriveUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Email,

        [Parameter(Mandatory = $true)]
        [string]$TenantName
    )

    $userResult = [PSCustomObject]@{
        Email = $Email
        Exists = $null
        StatusCode = $null
        OneDrivePath = $null
        Error = $null
    }

    # Convert email to OneDrive path format: user@contoso.com -> user_contoso_com
    $userPath = $Email -replace '@', '_' -replace '\.', '_'
    $url = "https://$TenantName-my.sharepoint.com/personal/$userPath/_layouts/15/onedrive.aspx"
    $userResult.OneDrivePath = $url

    try {
        Invoke-StealthDelay -Context "OneDrive check: $Email"
        $script:StealthConfig.RequestCount++

        $response = Invoke-WebRequest -Uri $url -Method HEAD -ErrorAction Stop -UseBasicParsing
        $userResult.StatusCode = $response.StatusCode
        # 200 response means user exists and OneDrive is accessible (rare but possible)
        $userResult.Exists = $true
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        $userResult.StatusCode = $statusCode

        # 403/401 = User exists (OneDrive exists but access denied)
        # 404 = User does not exist
        if ($statusCode -eq 403 -or $statusCode -eq 401) {
            $userResult.Exists = $true
        }
        elseif ($statusCode -eq 404) {
            $userResult.Exists = $false
        }
        else {
            $userResult.Error = $_.Exception.Message
        }
    }

    return $userResult
}

function Invoke-OneDriveEnumeration {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$EmailAddresses,

        [Parameter(Mandatory = $true)]
        [string]$TenantName
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "ONEDRIVE USER ENUMERATION (SILENT)" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    Write-Host "[*] Checking $($EmailAddresses.Count) email address(es) via OneDrive..." -ForegroundColor Cyan
    Write-Host "[*] Tenant: $TenantName" -ForegroundColor Gray
    Write-Host "[!] This method is completely undetectable - no audit logs generated" -ForegroundColor Green
    Write-Host ""

    $results = @()
    $existCount = 0

    foreach ($email in $EmailAddresses) {
        $userResult = Test-OneDriveUser -Email $email -TenantName $TenantName
        $results += $userResult

        if ($userResult.Exists -eq $true) {
            Write-Host "[+] $email - EXISTS (Status: $($userResult.StatusCode))" -ForegroundColor Green
            $existCount++
        }
        elseif ($userResult.Exists -eq $false) {
            Write-Host "[-] $email - Does Not Exist (Status: $($userResult.StatusCode))" -ForegroundColor Gray
        }
        else {
            Write-Host "[!] $email - Unknown (Status: $($userResult.StatusCode))" -ForegroundColor Yellow
            if ($userResult.Error) {
                Write-Host "    Error: $($userResult.Error)" -ForegroundColor Red
            }
        }

        # Apply throttle delay between requests
        if ($EmailAddresses.IndexOf($email) -lt ($EmailAddresses.Count - 1)) {
            Start-Sleep -Milliseconds ([int]($Throttle * 1000))
        }
    }

    # Update summary
    $script:Results.Summary.OneDriveUsersChecked = $EmailAddresses.Count
    $script:Results.Summary.OneDriveUsersExist = $existCount
    $script:Results.OneDriveEnum = $results

    Write-Host ""
    Write-Host "[*] OneDrive enumeration complete: $existCount of $($EmailAddresses.Count) exist" -ForegroundColor Cyan

    return $results
}

# ----------------------------------------------------------------------------
# 2. Federation Metadata Retrieval (-FederationMeta)
# Retrieves public signing certificates and federation configuration
# ----------------------------------------------------------------------------

function Get-FederationMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "FEDERATION METADATA" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    $metadataResult = [PSCustomObject]@{
        Domain = $Domain
        EntityID = $null
        TokenEndpoints = @()
        SigningCertificates = @()
        EncryptionCertificates = @()
        NameIDFormats = @()
        ClaimTypes = @()
        IssuerInfo = $null
        ADFSServer = $null
        RawXml = $null
        Error = $null
    }

    $url = "https://login.microsoftonline.com/$Domain/FederationMetadata/2007-06/FederationMetadata.xml"
    Write-Host "[*] Fetching federation metadata from: $url" -ForegroundColor Cyan

    $result = Invoke-WebRequestSafe -Uri $url -Context "federation metadata"

    if ($result.Success) {
        try {
            # Clean the XML content - remove BOM and any leading/trailing whitespace
            $xmlContent = $result.Content
            if ($xmlContent -is [byte[]]) {
                $xmlContent = [System.Text.Encoding]::UTF8.GetString($xmlContent)
            }
            # Convert to string if needed and trim
            $xmlContent = [string]$xmlContent
            $xmlContent = $xmlContent.Trim()
            # Remove BOM if present (UTF-8 BOM: EF BB BF or Unicode BOM)
            if ($xmlContent.Length -gt 0 -and [int][char]$xmlContent[0] -eq 0xFEFF) {
                $xmlContent = $xmlContent.Substring(1)
            }
            # Ensure it starts with <?xml or <EntityDescriptor - find the actual XML start
            $xmlStartIndex = $xmlContent.IndexOf('<?xml')
            if ($xmlStartIndex -eq -1) {
                $xmlStartIndex = $xmlContent.IndexOf('<EntityDescriptor')
            }
            if ($xmlStartIndex -gt 0) {
                $xmlContent = $xmlContent.Substring($xmlStartIndex)
            }

            $metadataResult.RawXml = $xmlContent

            # Use XmlDocument with proper loading to handle complex federation metadata
            $metadata = New-Object System.Xml.XmlDocument
            $metadata.PreserveWhitespace = $false
            $metadata.LoadXml($xmlContent)

            # Extract EntityID
            if ($metadata.DocumentElement.GetAttribute("entityID")) {
                $metadataResult.EntityID = $metadata.DocumentElement.GetAttribute("entityID")
                Write-Host "[+] Entity ID: $($metadataResult.EntityID)" -ForegroundColor Green
            }

            # Extract certificates from various namespaces
            $nsManager = New-Object System.Xml.XmlNamespaceManager($metadata.NameTable)
            $nsManager.AddNamespace("md", "urn:oasis:names:tc:SAML:2.0:metadata")
            $nsManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#")
            $nsManager.AddNamespace("fed", "http://docs.oasis-open.org/wsfed/federation/200706")

            # Find all X509Certificate elements
            $certNodes = $metadata.SelectNodes("//ds:X509Certificate", $nsManager)
            if ($certNodes -and $certNodes.Count -gt 0) {
                Write-Host "[+] Found $($certNodes.Count) certificate(s)" -ForegroundColor Green
                $certIndex = 1
                foreach ($certNode in $certNodes) {
                    $certData = $certNode.InnerText.Trim()
                    if ($certData) {
                        try {
                            $certBytes = [System.Convert]::FromBase64String($certData)
                            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)

                            $certInfo = [PSCustomObject]@{
                                Index = $certIndex
                                Subject = $cert.Subject
                                Issuer = $cert.Issuer
                                Thumbprint = $cert.Thumbprint
                                NotBefore = $cert.NotBefore
                                NotAfter = $cert.NotAfter
                                SerialNumber = $cert.SerialNumber
                            }
                            $metadataResult.SigningCertificates += $certInfo

                            Write-Host "    [$certIndex] Subject: $($cert.Subject)" -ForegroundColor Gray
                            Write-Host "        Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
                            Write-Host "        Valid: $($cert.NotBefore.ToString('yyyy-MM-dd')) to $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
                        }
                        catch {
                            Write-Host "    [$certIndex] (Unable to parse certificate)" -ForegroundColor Yellow
                        }
                        $certIndex++
                    }
                }
            }

            # Extract token endpoints
            $passiveEndpoints = $metadata.SelectNodes("//fed:PassiveRequestorEndpoint//*[local-name()='Address']", $nsManager)
            if ($passiveEndpoints) {
                foreach ($endpoint in $passiveEndpoints) {
                    if ($endpoint.InnerText) {
                        $metadataResult.TokenEndpoints += $endpoint.InnerText
                        Write-Host "[+] Token Endpoint: $($endpoint.InnerText)" -ForegroundColor Green

                        # Check if this looks like an ADFS server
                        if ($endpoint.InnerText -match 'adfs' -or $endpoint.InnerText -match '/adfs/') {
                            $metadataResult.ADFSServer = $endpoint.InnerText
                            Write-Host "[!] ADFS Server Detected!" -ForegroundColor Yellow
                        }
                    }
                }
            }

            # Extract NameID formats
            $nameIdFormats = $metadata.SelectNodes("//md:NameIDFormat", $nsManager)
            if ($nameIdFormats) {
                foreach ($format in $nameIdFormats) {
                    if ($format.InnerText) {
                        $metadataResult.NameIDFormats += $format.InnerText
                    }
                }
                if ($metadataResult.NameIDFormats.Count -gt 0) {
                    Write-Host "[+] NameID Formats: $($metadataResult.NameIDFormats.Count) format(s) supported" -ForegroundColor Green
                }
            }

            # Extract claim types
            $claimTypes = $metadata.SelectNodes("//*[local-name()='ClaimType']/@Uri", $nsManager)
            if ($claimTypes) {
                foreach ($claim in $claimTypes) {
                    $metadataResult.ClaimTypes += $claim.Value
                }
                if ($metadataResult.ClaimTypes.Count -gt 0) {
                    Write-Host "[+] Claim Types: $($metadataResult.ClaimTypes.Count) claim type(s) defined" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Host "[!] Failed to parse federation metadata: $_" -ForegroundColor Yellow
            $metadataResult.Error = $_.Exception.Message
        }
    }
    else {
        Write-Host "[-] Federation metadata not available: $($result.Error)" -ForegroundColor Gray
        $metadataResult.Error = $result.Error
    }

    $script:Results.FederationMeta = $metadataResult
    return $metadataResult
}

# ----------------------------------------------------------------------------
# 3. Seamless SSO Detection (-SeamlessSSO)
# Enhanced GetUserRealm with DesktopSsoEnabled check + Autologon endpoint
# ----------------------------------------------------------------------------

function Get-SeamlessSSOStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "SEAMLESS SSO DETECTION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    $ssoResult = [PSCustomObject]@{
        Domain = $Domain
        DesktopSsoEnabled = $null
        CloudInstanceName = $null
        TenantBrandingInfo = $null
        AutologonEndpoint = $null
        AutologonAvailable = $null
        Error = $null
    }

    # Query GetUserRealm for DesktopSsoEnabled
    Write-Host "[*] Checking Seamless SSO configuration..." -ForegroundColor Cyan
    $realmUrl = "https://login.microsoftonline.com/getuserrealm.srf?login=user@$Domain&json=1"
    $realmResult = Invoke-WebRequestSafe -Uri $realmUrl -Context "seamless SSO check"

    if ($realmResult.Success) {
        try {
            $realmData = $realmResult.Content | ConvertFrom-Json

            $ssoResult.DesktopSsoEnabled = $realmData.DesktopSsoEnabled
            $ssoResult.CloudInstanceName = $realmData.CloudInstanceName
            $ssoResult.TenantBrandingInfo = $realmData.TenantBrandingInfo

            if ($realmData.DesktopSsoEnabled -eq $true) {
                Write-Host "[+] Desktop SSO: ENABLED" -ForegroundColor Green
                Write-Host "[!] Seamless SSO enabled - Autologon enumeration may be possible" -ForegroundColor Yellow

                # Construct and test Autologon endpoint
                $tenantId = $null
                if ($script:Results.Summary.TenantId) {
                    $tenantId = $script:Results.Summary.TenantId
                }
                elseif ($script:Results.TenantInfo -and $script:Results.TenantInfo.TenantId) {
                    $tenantId = $script:Results.TenantInfo.TenantId
                }

                if ($tenantId) {
                    $ssoResult.AutologonEndpoint = "https://autologon.microsoftazuread-sso.com/$tenantId/winauth/trust/2005/usernamemixed"
                    Write-Host "[+] Autologon Endpoint: $($ssoResult.AutologonEndpoint)" -ForegroundColor Green

                    # Test if endpoint responds
                    Write-Host "[*] Testing Autologon endpoint availability..." -ForegroundColor Cyan
                    $autologonTest = Invoke-WebRequestSafe -Uri $ssoResult.AutologonEndpoint -Method "GET" -Context "autologon test"

                    # Even error responses indicate the endpoint is available
                    if ($autologonTest.StatusCode -ne $null) {
                        $ssoResult.AutologonAvailable = $true
                        Write-Host "[+] Autologon endpoint is reachable (Status: $($autologonTest.StatusCode))" -ForegroundColor Green
                    }
                    else {
                        $ssoResult.AutologonAvailable = $false
                        Write-Host "[-] Autologon endpoint not reachable" -ForegroundColor Gray
                    }
                }
                else {
                    Write-Host "[!] Tenant ID not available - run -TenantInfo first to get Autologon endpoint" -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "[-] Desktop SSO: Disabled" -ForegroundColor Gray
                $ssoResult.DesktopSsoEnabled = $false
            }

            if ($realmData.CloudInstanceName) {
                Write-Host "[+] Cloud Instance: $($realmData.CloudInstanceName)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[!] Failed to parse SSO response: $_" -ForegroundColor Yellow
            $ssoResult.Error = $_.Exception.Message
        }
    }
    else {
        Write-Host "[-] SSO check failed: $($realmResult.Error)" -ForegroundColor Gray
        $ssoResult.Error = $realmResult.Error
    }

    # Update summary
    $script:Results.Summary.SeamlessSSOEnabled = $ssoResult.DesktopSsoEnabled
    $script:Results.SeamlessSSO = $ssoResult
    return $ssoResult
}

# ----------------------------------------------------------------------------
# 4. Azure Subdomain Enumeration (-SubdomainEnum)
# Discover associated cloud resources from domain/tenant name
# ----------------------------------------------------------------------------

function Get-AzureSubdomains {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantName,

        [Parameter(Mandatory = $false)]
        [string[]]$CustomWordlist = $null
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "AZURE SUBDOMAIN ENUMERATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    # Core Azure subdomain patterns
    $corePatterns = @(
        @{ Pattern = "{tenant}.onmicrosoft.com"; Service = "Primary Tenant Domain" }
        @{ Pattern = "{tenant}.sharepoint.com"; Service = "SharePoint" }
        @{ Pattern = "{tenant}-my.sharepoint.com"; Service = "OneDrive" }
        @{ Pattern = "{tenant}.blob.core.windows.net"; Service = "Azure Blob Storage" }
        @{ Pattern = "{tenant}.file.core.windows.net"; Service = "Azure Files" }
        @{ Pattern = "{tenant}.queue.core.windows.net"; Service = "Azure Queue" }
        @{ Pattern = "{tenant}.table.core.windows.net"; Service = "Azure Table" }
        @{ Pattern = "{tenant}.vault.azure.net"; Service = "Key Vault" }
        @{ Pattern = "{tenant}.database.windows.net"; Service = "Azure SQL" }
        @{ Pattern = "{tenant}.azurewebsites.net"; Service = "App Service" }
        @{ Pattern = "{tenant}.scm.azurewebsites.net"; Service = "Kudu/Git Deployment" }
        @{ Pattern = "{tenant}.cloudapp.net"; Service = "Cloud Services (Classic)" }
        @{ Pattern = "{tenant}.cloudapp.azure.com"; Service = "Cloud Services" }
        @{ Pattern = "{tenant}.mail.protection.outlook.com"; Service = "Exchange Online Protection" }
        @{ Pattern = "{tenant}.azurecr.io"; Service = "Container Registry" }
        @{ Pattern = "{tenant}.redis.cache.windows.net"; Service = "Redis Cache" }
        @{ Pattern = "{tenant}.servicebus.windows.net"; Service = "Service Bus" }
        @{ Pattern = "{tenant}.azurefd.net"; Service = "Front Door" }
        @{ Pattern = "{tenant}.b2clogin.com"; Service = "Azure AD B2C" }
        @{ Pattern = "{tenant}.azure-api.net"; Service = "API Management" }
        @{ Pattern = "{tenant}.trafficmanager.net"; Service = "Traffic Manager" }
        @{ Pattern = "{tenant}.azurehdinsight.net"; Service = "HDInsight" }
        @{ Pattern = "{tenant}.documents.azure.com"; Service = "Cosmos DB" }
        @{ Pattern = "{tenant}.search.windows.net"; Service = "Cognitive Search" }
        @{ Pattern = "{tenant}.cognitiveservices.azure.com"; Service = "Cognitive Services" }
    )

    # Permutation suffixes for variation discovery
    $permutations = @("", "dev", "prod", "staging", "test", "uat", "qa", "backup", "dr", "internal", "external", "api", "app", "web", "data", "files", "storage", "cdn", "static")

    # Load custom wordlist if provided
    if ($CustomWordlist) {
        $permutations += $CustomWordlist
    }

    Write-Host "[*] Checking Azure subdomains for tenant: $TenantName" -ForegroundColor Cyan
    Write-Host "[*] Core patterns: $($corePatterns.Count)" -ForegroundColor Gray
    Write-Host "[*] Permutations: $($permutations.Count)" -ForegroundColor Gray
    Write-Host ""

    $results = @()
    $foundCount = 0
    $checkedCount = 0

    # Check core patterns with tenant name
    foreach ($pattern in $corePatterns) {
        $subdomain = $pattern.Pattern -replace '\{tenant\}', $TenantName

        try {
            $dns = Resolve-DnsName -Name $subdomain -ErrorAction SilentlyContinue -DnsOnly
            $checkedCount++

            if ($dns) {
                $ipAddresses = ($dns | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress) -join ", "
                $cnameTargets = ($dns | Where-Object { $_.NameHost } | Select-Object -ExpandProperty NameHost) -join ", "

                $resultEntry = [PSCustomObject]@{
                    Subdomain = $subdomain
                    Service = $pattern.Service
                    Exists = $true
                    IPAddress = $ipAddresses
                    CNAME = $cnameTargets
                    RecordType = ($dns | Select-Object -First 1).Type
                }
                $results += $resultEntry
                $foundCount++

                $displayInfo = if ($ipAddresses) { "IP: $ipAddresses" } elseif ($cnameTargets) { "CNAME: $cnameTargets" } else { "" }
                Write-Host "[+] $subdomain ($($pattern.Service))" -ForegroundColor Green
                if ($displayInfo) {
                    Write-Host "    $displayInfo" -ForegroundColor Gray
                }
            }
        }
        catch {
            # DNS resolution failed - subdomain doesn't exist
        }
    }

    # Check permutations for key services
    $keyServices = @(
        @{ Pattern = "{name}.blob.core.windows.net"; Service = "Azure Blob Storage" }
        @{ Pattern = "{name}.azurewebsites.net"; Service = "App Service" }
        @{ Pattern = "{name}.vault.azure.net"; Service = "Key Vault" }
        @{ Pattern = "{name}.database.windows.net"; Service = "Azure SQL" }
    )

    Write-Host ""
    Write-Host "[*] Checking permutations for key services..." -ForegroundColor Cyan

    foreach ($permutation in $permutations) {
        if ([string]::IsNullOrEmpty($permutation)) { continue }

        $baseName = "$TenantName$permutation"

        foreach ($service in $keyServices) {
            $subdomain = $service.Pattern -replace '\{name\}', $baseName

            try {
                $dns = Resolve-DnsName -Name $subdomain -ErrorAction SilentlyContinue -DnsOnly
                $checkedCount++

                if ($dns) {
                    $ipAddresses = ($dns | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress) -join ", "

                    $resultEntry = [PSCustomObject]@{
                        Subdomain = $subdomain
                        Service = $service.Service
                        Exists = $true
                        IPAddress = $ipAddresses
                        CNAME = $null
                        RecordType = ($dns | Select-Object -First 1).Type
                    }
                    $results += $resultEntry
                    $foundCount++

                    Write-Host "[+] $subdomain ($($service.Service))" -ForegroundColor Green
                }
            }
            catch {
                # DNS resolution failed
            }
        }
    }

    # Update summary
    $script:Results.Summary.SubdomainsChecked = $checkedCount
    $script:Results.Summary.SubdomainsFound = $foundCount
    $script:Results.SubdomainEnum = $results

    Write-Host ""
    Write-Host "[*] Subdomain enumeration complete: $foundCount of $checkedCount found" -ForegroundColor Cyan

    return $results
}

# ----------------------------------------------------------------------------
# 5. Autodiscover V2 Enumeration (-AutodiscoverEnum)
# Check user existence via Autodiscover JSON endpoints
# ----------------------------------------------------------------------------

function Test-AutodiscoverUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Email
    )

    $userResult = [PSCustomObject]@{
        Email = $Email
        Exists = $null
        StatusCode = $null
        RedirectUrl = $null
        Error = $null
    }

    $url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.json?Email=$Email&Protocol=Autodiscoverv1"

    try {
        Invoke-StealthDelay -Context "Autodiscover check: $Email"
        $script:StealthConfig.RequestCount++

        # Use WebRequest with manual redirect handling
        $response = Invoke-WebRequest -Uri $url -Method GET -ErrorAction Stop -UseBasicParsing -MaximumRedirection 0
        $userResult.StatusCode = $response.StatusCode

        # 200 = User exists
        if ($response.StatusCode -eq 200) {
            $userResult.Exists = $true
        }
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        $userResult.StatusCode = $statusCode

        # 302 redirect = User does not exist or different handling
        # 200 = User exists
        if ($statusCode -eq 302) {
            $userResult.Exists = $false
            if ($_.Exception.Response.Headers -and $_.Exception.Response.Headers.Location) {
                $userResult.RedirectUrl = $_.Exception.Response.Headers.Location.ToString()
            }
        }
        elseif ($statusCode -eq 200) {
            $userResult.Exists = $true
        }
        elseif ($statusCode -eq 401 -or $statusCode -eq 403) {
            # Authentication required but endpoint exists
            $userResult.Exists = $true
        }
        else {
            $userResult.Error = $_.Exception.Message
        }
    }

    return $userResult
}

function Invoke-AutodiscoverEnumeration {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$EmailAddresses
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "AUTODISCOVER V2 USER ENUMERATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    Write-Host "[*] Checking $($EmailAddresses.Count) email address(es) via Autodiscover..." -ForegroundColor Cyan
    Write-Host "[*] Endpoint: autodiscover-s.outlook.com" -ForegroundColor Gray
    Write-Host ""

    $results = @()
    $existCount = 0

    foreach ($email in $EmailAddresses) {
        $userResult = Test-AutodiscoverUser -Email $email
        $results += $userResult

        if ($userResult.Exists -eq $true) {
            Write-Host "[+] $email - EXISTS (Status: $($userResult.StatusCode))" -ForegroundColor Green
            $existCount++
        }
        elseif ($userResult.Exists -eq $false) {
            Write-Host "[-] $email - Does Not Exist (Status: $($userResult.StatusCode))" -ForegroundColor Gray
        }
        else {
            Write-Host "[!] $email - Unknown (Status: $($userResult.StatusCode))" -ForegroundColor Yellow
            if ($userResult.Error) {
                Write-Host "    Error: $($userResult.Error)" -ForegroundColor Red
            }
        }

        # Apply throttle delay between requests
        if ($EmailAddresses.IndexOf($email) -lt ($EmailAddresses.Count - 1)) {
            Start-Sleep -Milliseconds ([int]($Throttle * 1000))
        }
    }

    $script:Results.AutodiscoverV2 = $results

    Write-Host ""
    Write-Host "[*] Autodiscover enumeration complete: $existCount of $($EmailAddresses.Count) exist" -ForegroundColor Cyan

    return $results
}

# ----------------------------------------------------------------------------
# 6. Autodiscover V1 Enumeration (-AutodiscoverV1Enum)
# Legacy XML endpoint behavior for user discovery
# ----------------------------------------------------------------------------

function Test-AutodiscoverV1User {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Email,

        [Parameter(Mandatory = $false)]
        [string]$Domain
    )

    $userResult = [PSCustomObject]@{
        Email = $Email
        Domain = $null
        Exists = $null
        StatusCode = $null
        RedirectUrl = $null
        ResultDescription = $null
        Error = $null
    }

    if (-not $Domain -and $Email -match '@(.+)$') {
        $Domain = $Matches[1]
    }

    if (-not $Domain) {
        $userResult.Error = "Domain not available for Autodiscover V1"
        return $userResult
    }

    $userResult.Domain = $Domain
    $url = "https://autodiscover.$Domain/autodiscover/autodiscover.xml"

    $xmlBody = @"
<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <EMailAddress>$Email</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
  </Request>
</Autodiscover>
"@

    $probeResult = Invoke-WebRequestDetailed -Uri $url -Method "POST" -Body $xmlBody -ContentType "text/xml; charset=utf-8" -Context "Autodiscover V1: $Email"
    $userResult.StatusCode = $probeResult.StatusCode

    if ($probeResult.Content) {
        $errorCode = $null
        $responseCode = $null
        $redirectAddr = $null
        $redirectUrl = $null

        if ($probeResult.Content -match '<ErrorCode>([^<]+)</ErrorCode>') {
            $errorCode = $Matches[1]
        }
        if ($probeResult.Content -match '<ResponseCode>([^<]+)</ResponseCode>') {
            $responseCode = $Matches[1]
        }
        if ($probeResult.Content -match '<RedirectAddr>([^<]+)</RedirectAddr>') {
            $redirectAddr = $Matches[1]
        }
        elseif ($probeResult.Content -match '<RedirectUrl>([^<]+)</RedirectUrl>') {
            $redirectUrl = $Matches[1]
        }

        if ($redirectAddr) {
            $userResult.RedirectUrl = $redirectAddr
            $userResult.Exists = $true
            $userResult.ResultDescription = "RedirectAddr"
        }
        elseif ($redirectUrl) {
            $userResult.RedirectUrl = $redirectUrl
            $userResult.ResultDescription = "RedirectUrl"
        }
        elseif ($errorCode -match 'InvalidUser|InvalidSmtpAddress') {
            $userResult.Exists = $false
            $userResult.ResultDescription = $errorCode
        }
        elseif ($errorCode -match 'NoError' -or $responseCode -match 'Success') {
            $userResult.Exists = $true
            $userResult.ResultDescription = if ($errorCode) { $errorCode } else { $responseCode }
        }
        elseif ($probeResult.StatusCode -eq 401 -or $probeResult.StatusCode -eq 403) {
            $userResult.ResultDescription = "Authentication required"
        }
    }
    else {
        if ($probeResult.StatusCode -eq 404) {
            $userResult.Exists = $false
            $userResult.ResultDescription = "Endpoint not found"
        }
        elseif ($probeResult.StatusCode -eq 401 -or $probeResult.StatusCode -eq 403) {
            $userResult.ResultDescription = "Authentication required"
        }
        elseif ($probeResult.Error) {
            $userResult.Error = $probeResult.Error
        }
    }

    return $userResult
}

function Invoke-AutodiscoverV1Enumeration {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$EmailAddresses,

        [Parameter(Mandatory = $false)]
        [string]$Domain
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "AUTODISCOVER V1 USER ENUMERATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    Write-Host "[*] Checking $($EmailAddresses.Count) email address(es) via Autodiscover V1..." -ForegroundColor Cyan
    Write-Host "[*] Endpoint: autodiscover.<domain>" -ForegroundColor Gray
    Write-Host ""

    $results = @()
    $existCount = 0

    foreach ($email in $EmailAddresses) {
        $userResult = Test-AutodiscoverV1User -Email $email -Domain $Domain
        $results += $userResult

        if ($userResult.Exists -eq $true) {
            $desc = if ($userResult.ResultDescription) { " ($($userResult.ResultDescription))" } else { "" }
            Write-Host "[+] $email - EXISTS (Status: $($userResult.StatusCode))$desc" -ForegroundColor Green
            $existCount++
        }
        elseif ($userResult.Exists -eq $false) {
            $desc = if ($userResult.ResultDescription) { " ($($userResult.ResultDescription))" } else { "" }
            Write-Host "[-] $email - Does Not Exist (Status: $($userResult.StatusCode))$desc" -ForegroundColor Gray
        }
        else {
            $desc = if ($userResult.ResultDescription) { " ($($userResult.ResultDescription))" } else { "" }
            Write-Host "[!] $email - Unknown (Status: $($userResult.StatusCode))$desc" -ForegroundColor Yellow
            if ($userResult.Error) {
                Write-Host "    Error: $($userResult.Error)" -ForegroundColor Red
            }
        }

        # Apply throttle delay between requests
        if ($EmailAddresses.IndexOf($email) -lt ($EmailAddresses.Count - 1)) {
            Start-Sleep -Milliseconds ([int]($Throttle * 1000))
        }
    }

    # Update summary
    $script:Results.Summary.AutodiscoverV1Checked = $EmailAddresses.Count
    $script:Results.Summary.AutodiscoverV1Exist = $existCount
    $script:Results.AutodiscoverV1 = $results

    Write-Host ""
    Write-Host "[*] Autodiscover V1 enumeration complete: $existCount of $($EmailAddresses.Count) exist" -ForegroundColor Cyan

    return $results
}

# ----------------------------------------------------------------------------
# 7. Exchange Web Services Probe (-EwsProbe)
# ----------------------------------------------------------------------------

function Invoke-EwsProbe {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Domain
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "EXCHANGE WEB SERVICES (EWS) PROBE" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    $endpoints = @(
        @{ Url = "https://outlook.office365.com/EWS/Exchange.asmx"; Name = "Outlook Office 365" }
        @{ Url = "https://outlook.office.com/EWS/Exchange.asmx"; Name = "Outlook Office" }
    )

    if ($Domain) {
        $endpoints += @{ Url = "https://$Domain/EWS/Exchange.asmx"; Name = "Domain Root" }
        $endpoints += @{ Url = "https://mail.$Domain/EWS/Exchange.asmx"; Name = "mail subdomain" }
        $endpoints += @{ Url = "https://ews.$Domain/EWS/Exchange.asmx"; Name = "ews subdomain" }
    }

    $results = @()
    $availableCount = 0

    foreach ($endpoint in $endpoints) {
        $probe = Invoke-WebRequestDetailed -Uri $endpoint.Url -Method "GET" -ContentType "text/xml" -Context "EWS probe"
        $statusCode = $probe.StatusCode
        $redirectUrl = $null

        if ($probe.Headers -and $probe.Headers.Location) {
            $redirectUrl = $probe.Headers.Location.ToString()
        }

        $available = $null
        $authRequired = $false

        if ($statusCode -in 200,301,302,307,308,401,403) {
            $available = $true
            if ($statusCode -in 401,403) {
                $authRequired = $true
            }
            $availableCount++
        }
        elseif ($statusCode -eq 404) {
            $available = $false
        }

        $resultEntry = [PSCustomObject]@{
            Name = $endpoint.Name
            Url = $endpoint.Url
            StatusCode = $statusCode
            Available = $available
            AuthRequired = $authRequired
            RedirectUrl = $redirectUrl
        }
        $results += $resultEntry

        if ($available -eq $true) {
            $authNote = if ($authRequired) { " (Auth Required)" } else { "" }
            Write-Host "[+] $($endpoint.Name): Available (Status: $statusCode)$authNote" -ForegroundColor Green
        }
        elseif ($available -eq $false) {
            Write-Host "[-] $($endpoint.Name): Not available (Status: $statusCode)" -ForegroundColor Gray
        }
        else {
            Write-Host "[!] $($endpoint.Name): Unknown (Status: $statusCode)" -ForegroundColor Yellow
        }
    }

    $script:Results.Summary.EwsEndpointsFound = $availableCount
    $script:Results.EwsProbe = $results

    Write-Host ""
    Write-Host "[*] EWS probe complete: $availableCount endpoint(s) available" -ForegroundColor Cyan

    return $results
}

# ----------------------------------------------------------------------------
# 8. SharePoint/Teams Discovery (-SharePointEnum)
# ----------------------------------------------------------------------------

function Invoke-SharePointDiscovery {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantName,

        [Parameter(Mandatory = $false)]
        [string[]]$CustomSites = $null
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "SHAREPOINT / TEAMS DISCOVERY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    if (-not $TenantName) {
        Write-Host "[!] SharePointEnum requires -TenantName or a domain to extract tenant name from" -ForegroundColor Yellow
        return $null
    }

    $defaultSites = @(
        "intranet", "portal", "hr", "finance", "it", "projects",
        "marketing", "sales", "support", "admin", "security", "dev"
    )

    $siteNames = $defaultSites
    if ($CustomSites -and $CustomSites.Count -gt 0) {
        $siteNames = $siteNames + $CustomSites
    }
    $siteNames = $siteNames | Select-Object -Unique

    $targets = @(
        @{ Url = "https://$TenantName.sharepoint.com"; Type = "TenantRoot"; Name = $TenantName }
        @{ Url = "https://$TenantName-my.sharepoint.com"; Type = "OneDriveRoot"; Name = "$TenantName-my" }
    )

    foreach ($site in $siteNames) {
        $targets += @{ Url = "https://$TenantName.sharepoint.com/sites/$site"; Type = "Site"; Name = $site }
        $targets += @{ Url = "https://$TenantName.sharepoint.com/teams/$site"; Type = "Team"; Name = $site }
    }

    $results = @()
    $checkedCount = 0
    $foundCount = 0
    $publicCount = 0

    foreach ($target in $targets) {
        $probe = Invoke-WebRequestDetailed -Uri $target.Url -Method "GET" -ContentType "text/html" -Context "SharePoint check"
        $statusCode = $probe.StatusCode
        $redirectUrl = $null

        if ($probe.Headers -and $probe.Headers.Location) {
            $redirectUrl = $probe.Headers.Location.ToString()
        }

        $exists = $null
        $publicAccess = $false

        if ($statusCode -in 200,301,302,307,308,401,403) {
            $exists = $true
            if ($statusCode -eq 200) {
                $publicAccess = $true
                $publicCount++
            }
            $foundCount++
        }
        elseif ($statusCode -eq 404) {
            $exists = $false
        }

        $resultEntry = [PSCustomObject]@{
            Url = $target.Url
            Type = $target.Type
            Name = $target.Name
            StatusCode = $statusCode
            Exists = $exists
            PublicAccess = $publicAccess
            RedirectUrl = $redirectUrl
        }
        $results += $resultEntry
        $checkedCount++

        if ($exists -eq $true) {
            $publicNote = if ($publicAccess) { " (Public)" } else { "" }
            Write-Host "[+] $($target.Url) - EXISTS (Status: $statusCode)$publicNote" -ForegroundColor Green
        }
        elseif ($exists -eq $false) {
            Write-Host "[-] $($target.Url) - Not Found (Status: $statusCode)" -ForegroundColor Gray
        }
        else {
            Write-Host "[!] $($target.Url) - Unknown (Status: $statusCode)" -ForegroundColor Yellow
        }
    }

    $script:Results.Summary.SharePointSitesChecked = $checkedCount
    $script:Results.Summary.SharePointSitesFound = $foundCount
    $script:Results.Summary.SharePointPublicSites = $publicCount
    $script:Results.SharePointEnum = $results

    Write-Host ""
    Write-Host "[*] SharePoint discovery complete: $foundCount of $checkedCount found ($publicCount public)" -ForegroundColor Cyan

    return $results
}

# ----------------------------------------------------------------------------
# 9. Lync/Skype Discovery (-LyncProbe)
# ----------------------------------------------------------------------------

function Invoke-LyncDiscovery {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "LYNC / SKYPE DISCOVERY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    $targets = @(
        @{ Url = "https://lyncdiscover.$Domain"; Name = "lyncdiscover" }
        @{ Url = "https://lyncdiscoverinternal.$Domain"; Name = "lyncdiscoverinternal" }
        @{ Url = "https://sip.$Domain"; Name = "sip" }
    )

    $results = @()
    $availableCount = 0

    foreach ($target in $targets) {
        $probe = Invoke-WebRequestDetailed -Uri $target.Url -Method "GET" -ContentType "application/json" -Context "Lync discovery"
        $statusCode = $probe.StatusCode
        $redirectUrl = $null

        if ($probe.Headers -and $probe.Headers.Location) {
            $redirectUrl = $probe.Headers.Location.ToString()
        }

        $available = $null

        if ($statusCode -in 200,301,302,307,308,401,403) {
            $available = $true
            $availableCount++
        }
        elseif ($statusCode -eq 404) {
            $available = $false
        }

        $resultEntry = [PSCustomObject]@{
            Url = $target.Url
            Name = $target.Name
            StatusCode = $statusCode
            Available = $available
            RedirectUrl = $redirectUrl
        }
        $results += $resultEntry

        if ($available -eq $true) {
            Write-Host "[+] $($target.Url) - Available (Status: $statusCode)" -ForegroundColor Green
        }
        elseif ($available -eq $false) {
            Write-Host "[-] $($target.Url) - Not Found (Status: $statusCode)" -ForegroundColor Gray
        }
        else {
            Write-Host "[!] $($target.Url) - Unknown (Status: $statusCode)" -ForegroundColor Yellow
        }
    }

    $script:Results.Summary.LyncEndpointsFound = $availableCount
    $script:Results.LyncProbe = $results

    Write-Host ""
    Write-Host "[*] Lync discovery complete: $availableCount endpoint(s) available" -ForegroundColor Cyan

    return $results
}

# ----------------------------------------------------------------------------
# 10. Enhanced Mail/DNS Checks (-MailEnum)
# Additional mail security DNS records: MTA-STS, DMARC, DKIM, BIMI
# ----------------------------------------------------------------------------

function Get-MailSecurityRecords {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "ENHANCED MAIL SECURITY ENUMERATION" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    $mailResult = [PSCustomObject]@{
        Domain = $Domain
        MX = @()
        SPF = $null
        DMARC = $null
        DKIM = @()
        MTASTS = $null
        MTASTSPolicy = $null
        BIMI = $null
        TLSRPT = $null
        IsExchangeOnline = $false
        Analysis = @()
    }

    # MX Records
    Write-Host "[*] Checking MX records..." -ForegroundColor Cyan
    try {
        $mxRecords = Resolve-DnsName -Name $Domain -Type MX -ErrorAction SilentlyContinue
        if ($mxRecords) {
            foreach ($mx in $mxRecords) {
                if ($mx.NameExchange) {
                    $mxEntry = [PSCustomObject]@{
                        Exchange = $mx.NameExchange
                        Preference = $mx.Preference
                    }
                    $mailResult.MX += $mxEntry

                    $indicator = ""
                    if ($mx.NameExchange -match "mail\.protection\.outlook\.com") {
                        $mailResult.IsExchangeOnline = $true
                        $indicator = " [Exchange Online]"
                    }
                    elseif ($mx.NameExchange -match "google\.com|googlemail\.com") {
                        $indicator = " [Google Workspace]"
                    }
                    elseif ($mx.NameExchange -match "pphosted\.com") {
                        $indicator = " [Proofpoint]"
                    }
                    elseif ($mx.NameExchange -match "mimecast") {
                        $indicator = " [Mimecast]"
                    }

                    Write-Host "[+] MX: $($mx.NameExchange) (Priority: $($mx.Preference))$indicator" -ForegroundColor Green
                }
            }
        }
        else {
            Write-Host "[-] No MX records found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[-] MX lookup failed: $_" -ForegroundColor Gray
    }

    # SPF Record
    Write-Host "[*] Checking SPF record..." -ForegroundColor Cyan
    try {
        $txtRecords = Resolve-DnsName -Name $Domain -Type TXT -ErrorAction SilentlyContinue
        foreach ($txt in $txtRecords) {
            $value = $txt.Strings -join ""
            if ($value -match "^v=spf1") {
                $mailResult.SPF = $value
                Write-Host "[+] SPF: $value" -ForegroundColor Green

                # Analyze SPF
                if ($value -match "include:spf\.protection\.outlook\.com") {
                    $mailResult.Analysis += "SPF includes Exchange Online"
                }
                if ($value -match "\-all$") {
                    $mailResult.Analysis += "SPF: Hard fail (-all) - strict policy"
                }
                elseif ($value -match "~all$") {
                    $mailResult.Analysis += "SPF: Soft fail (~all) - moderate policy"
                }
                elseif ($value -match "\?all$") {
                    $mailResult.Analysis += "SPF: Neutral (?all) - permissive policy"
                }
                break
            }
        }
        if (-not $mailResult.SPF) {
            Write-Host "[-] No SPF record found" -ForegroundColor Gray
            $mailResult.Analysis += "No SPF record - email spoofing possible"
        }
    }
    catch {
        Write-Host "[-] SPF lookup failed: $_" -ForegroundColor Gray
    }

    # DMARC Record
    Write-Host "[*] Checking DMARC record..." -ForegroundColor Cyan
    try {
        $dmarcRecords = Resolve-DnsName -Name "_dmarc.$Domain" -Type TXT -ErrorAction SilentlyContinue
        foreach ($txt in $dmarcRecords) {
            $value = $txt.Strings -join ""
            if ($value -match "^v=DMARC1") {
                $mailResult.DMARC = $value
                Write-Host "[+] DMARC: $value" -ForegroundColor Green

                # Analyze DMARC policy
                if ($value -match "p=reject") {
                    $mailResult.Analysis += "DMARC: Reject policy - strict"
                }
                elseif ($value -match "p=quarantine") {
                    $mailResult.Analysis += "DMARC: Quarantine policy - moderate"
                }
                elseif ($value -match "p=none") {
                    $mailResult.Analysis += "DMARC: None policy - monitoring only"
                }

                if ($value -match "rua=([^;]+)") {
                    $mailResult.Analysis += "DMARC reports sent to: $($Matches[1])"
                }
                break
            }
        }
        if (-not $mailResult.DMARC) {
            Write-Host "[-] No DMARC record found" -ForegroundColor Gray
            $mailResult.Analysis += "No DMARC record - email spoofing easier"
        }
    }
    catch {
        Write-Host "[-] DMARC lookup failed: $_" -ForegroundColor Gray
    }

    # DKIM Selectors (common ones)
    Write-Host "[*] Checking DKIM selectors..." -ForegroundColor Cyan
    $dkimSelectors = @(
        "selector1",        # Microsoft 365
        "selector2",        # Microsoft 365
        "google",           # Google Workspace
        "default",          # Common default
        "dkim",             # Common
        "mail",             # Common
        "k1",               # Mailchimp
        "s1",               # Common
        "s2"                # Common
    )

    foreach ($selector in $dkimSelectors) {
        try {
            $dkimRecord = Resolve-DnsName -Name "$selector._domainkey.$Domain" -Type TXT -ErrorAction SilentlyContinue
            if ($dkimRecord) {
                $value = $dkimRecord.Strings -join ""
                if ($value -match "v=DKIM1" -or $value -match "k=rsa") {
                    $dkimEntry = [PSCustomObject]@{
                        Selector = $selector
                        Record = $value.Substring(0, [Math]::Min(100, $value.Length)) + "..."
                    }
                    $mailResult.DKIM += $dkimEntry
                    Write-Host "[+] DKIM ($selector): Found" -ForegroundColor Green
                }
            }
        }
        catch {
            # Selector doesn't exist
        }
    }

    if ($mailResult.DKIM.Count -eq 0) {
        Write-Host "[-] No common DKIM selectors found" -ForegroundColor Gray
    }

    # MTA-STS Policy
    Write-Host "[*] Checking MTA-STS..." -ForegroundColor Cyan
    try {
        $mtastsRecord = Resolve-DnsName -Name "_mta-sts.$Domain" -Type TXT -ErrorAction SilentlyContinue
        if ($mtastsRecord) {
            $value = $mtastsRecord.Strings -join ""
            $mailResult.MTASTS = $value
            Write-Host "[+] MTA-STS Record: $value" -ForegroundColor Green

            # Try to fetch the actual policy
            $policyUrl = "https://mta-sts.$Domain/.well-known/mta-sts.txt"
            $policyResult = Invoke-WebRequestSafe -Uri $policyUrl -Context "MTA-STS policy"
            if ($policyResult.Success) {
                $mailResult.MTASTSPolicy = $policyResult.Content
                Write-Host "[+] MTA-STS Policy retrieved" -ForegroundColor Green
            }
        }
        else {
            Write-Host "[-] No MTA-STS record found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[-] MTA-STS lookup failed: $_" -ForegroundColor Gray
    }

    # BIMI Record
    Write-Host "[*] Checking BIMI record..." -ForegroundColor Cyan
    try {
        $bimiRecord = Resolve-DnsName -Name "default._bimi.$Domain" -Type TXT -ErrorAction SilentlyContinue
        if ($bimiRecord) {
            $value = $bimiRecord.Strings -join ""
            if ($value -match "v=BIMI1") {
                $mailResult.BIMI = $value
                Write-Host "[+] BIMI: $value" -ForegroundColor Green
            }
        }
        else {
            Write-Host "[-] No BIMI record found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[-] BIMI lookup failed: $_" -ForegroundColor Gray
    }

    # TLS-RPT Record
    Write-Host "[*] Checking TLS-RPT record..." -ForegroundColor Cyan
    try {
        $tlsrptRecord = Resolve-DnsName -Name "_smtp._tls.$Domain" -Type TXT -ErrorAction SilentlyContinue
        if ($tlsrptRecord) {
            $value = $tlsrptRecord.Strings -join ""
            if ($value -match "v=TLSRPTv1") {
                $mailResult.TLSRPT = $value
                Write-Host "[+] TLS-RPT: $value" -ForegroundColor Green
            }
        }
        else {
            Write-Host "[-] No TLS-RPT record found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[-] TLS-RPT lookup failed: $_" -ForegroundColor Gray
    }

    # Display analysis summary
    if ($mailResult.Analysis.Count -gt 0) {
        Write-Host ""
        Write-Host "[*] Security Analysis:" -ForegroundColor Yellow
        foreach ($finding in $mailResult.Analysis) {
            Write-Host "    - $finding" -ForegroundColor Gray
        }
    }

    $script:Results.MailEnum = $mailResult
    return $mailResult
}

# ----------------------------------------------------------------------------
# 11. Tenant ID Reversal (-TenantReverse)
# Given a tenant ID, discover associated resources across Azure services
# ----------------------------------------------------------------------------

function Get-TenantResources {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "TENANT ID RESOURCE DISCOVERY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    # Use stored tenant ID if not provided
    if (-not $TenantId) {
        if ($script:Results.Summary.TenantId) {
            $TenantId = $script:Results.Summary.TenantId
        }
        elseif ($script:Results.TenantInfo -and $script:Results.TenantInfo.TenantId) {
            $TenantId = $script:Results.TenantInfo.TenantId
        }
        else {
            Write-Host "[!] No Tenant ID available. Run -TenantInfo first or provide -TenantId" -ForegroundColor Yellow
            return $null
        }
    }

    $reverseResult = [PSCustomObject]@{
        TenantId = $TenantId
        OpenIDConfig = $null
        DefaultDomain = $null
        VerifiedDomains = @()
        GraphEndpoint = $null
        AzureADEndpoints = @()
        Error = $null
    }

    Write-Host "[*] Discovering resources for Tenant ID: $TenantId" -ForegroundColor Cyan

    # Query OpenID configuration with tenant ID
    Write-Host "[*] Querying OpenID configuration..." -ForegroundColor Cyan
    $openIdUrl = "https://login.microsoftonline.com/$TenantId/v2.0/.well-known/openid-configuration"
    $openIdResult = Invoke-WebRequestSafe -Uri $openIdUrl -Context "OpenID config by tenant ID"

    if ($openIdResult.Success) {
        try {
            $openIdData = $openIdResult.Content | ConvertFrom-Json
            $reverseResult.OpenIDConfig = $openIdData

            Write-Host "[+] OpenID Configuration retrieved" -ForegroundColor Green
            Write-Host "    Token Endpoint: $($openIdData.token_endpoint)" -ForegroundColor Gray
            Write-Host "    Issuer: $($openIdData.issuer)" -ForegroundColor Gray

            # Try to extract tenant domain from issuer
            if ($openIdData.issuer -match 'login\.microsoftonline\.com/([^/]+)') {
                $issuerTenant = $Matches[1]
                if ($issuerTenant -ne $TenantId -and $issuerTenant -match '\.') {
                    $reverseResult.DefaultDomain = $issuerTenant
                    Write-Host "[+] Default Domain: $issuerTenant" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Host "[!] Failed to parse OpenID config: $_" -ForegroundColor Yellow
        }
    }

    # Query Azure AD Graph endpoints (some may still work)
    Write-Host "[*] Probing Azure AD endpoints..." -ForegroundColor Cyan

    $endpoints = @(
        @{ Url = "https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='$TenantId')"; Name = "Graph Tenant Info" }
        @{ Url = "https://login.microsoftonline.com/$TenantId/.well-known/openid-configuration"; Name = "OpenID v1" }
        @{ Url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"; Name = "Device Code Endpoint" }
    )

    foreach ($endpoint in $endpoints) {
        $testResult = Invoke-WebRequestSafe -Uri $endpoint.Url -Context $endpoint.Name

        $endpointEntry = [PSCustomObject]@{
            Name = $endpoint.Name
            Url = $endpoint.Url
            Available = $testResult.Success -or ($testResult.StatusCode -and $testResult.StatusCode -ne 404)
            StatusCode = $testResult.StatusCode
        }
        $reverseResult.AzureADEndpoints += $endpointEntry

        if ($endpointEntry.Available) {
            Write-Host "[+] $($endpoint.Name): Available (Status: $($testResult.StatusCode))" -ForegroundColor Green
        }
        else {
            Write-Host "[-] $($endpoint.Name): Not available" -ForegroundColor Gray
        }
    }

    # Try to discover tenant display name via error messages
    Write-Host "[*] Attempting tenant name discovery via OAuth..." -ForegroundColor Cyan
    $oauthUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?client_id=00000000-0000-0000-0000-000000000000&response_type=code&scope=openid"
    $oauthResult = Invoke-WebRequestSafe -Uri $oauthUrl -Context "OAuth probe"

    if ($oauthResult.Content -and $oauthResult.Content -match 'data-tenant-branding-subtitle="([^"]+)"') {
        $brandingName = $Matches[1]
        Write-Host "[+] Tenant Branding Subtitle: $brandingName" -ForegroundColor Green
    }

    $script:Results.TenantReverse = $reverseResult
    return $reverseResult
}

# ----------------------------------------------------------------------------
# 12. OAuth Error Analysis (-OAuthProbe)
# Enumerate OAuth configuration through error message analysis
# ----------------------------------------------------------------------------

function Invoke-OAuthProbe {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [string]$Domain
    )

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "OAUTH CONFIGURATION PROBE" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    # Use stored tenant ID if not provided
    if (-not $TenantId -and -not $Domain) {
        if ($script:Results.Summary.TenantId) {
            $TenantId = $script:Results.Summary.TenantId
        }
        elseif ($script:Results.Summary.Domain) {
            $Domain = $script:Results.Summary.Domain
        }
        else {
            Write-Host "[!] No Tenant ID or Domain available. Run -TenantInfo first" -ForegroundColor Yellow
            return $null
        }
    }

    $tenant = if ($TenantId) { $TenantId } else { $Domain }

    $oauthResults = @()

    Write-Host "[*] Probing OAuth configuration for: $tenant" -ForegroundColor Cyan
    Write-Host ""

    # Test various well-known application IDs
    $wellKnownApps = @(
        @{ Id = "00000003-0000-0000-c000-000000000000"; Name = "Microsoft Graph" }
        @{ Id = "00000002-0000-0000-c000-000000000000"; Name = "Azure AD Graph (Deprecated)" }
        @{ Id = "00000002-0000-0ff1-ce00-000000000000"; Name = "Office 365 Exchange Online" }
        @{ Id = "00000003-0000-0ff1-ce00-000000000000"; Name = "Office 365 SharePoint Online" }
        @{ Id = "00000004-0000-0ff1-ce00-000000000000"; Name = "Skype for Business Online" }
        @{ Id = "797f4846-ba00-4fd7-ba43-dac1f8f63013"; Name = "Azure Service Management API" }
        @{ Id = "1950a258-227b-4e31-a9cf-717495945fc2"; Name = "Microsoft Azure PowerShell" }
        @{ Id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"; Name = "Microsoft Azure CLI" }
        @{ Id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"; Name = "Microsoft Office" }
        @{ Id = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"; Name = "Microsoft Teams" }
        @{ Id = "9bc3ab49-b65d-410a-85ad-de819febfddc"; Name = "Microsoft Planner" }
        @{ Id = "de8bc8b5-d9f9-48b1-a8ad-b748da725064"; Name = "Microsoft Graph Command Line Tools" }
        @{ Id = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"; Name = "Azure Portal" }
        @{ Id = "0000000c-0000-0000-c000-000000000000"; Name = "Microsoft App Access Panel" }
        @{ Id = "5d661950-3475-41cd-a2c3-d671a3162bc1"; Name = "Microsoft Outlook" }
        @{ Id = "eb1cec80-a830-486e-b45b-f57094f163f9"; Name = "Microsoft OneDrive" }
        @{ Id = "57fb890c-0dab-4253-a5e0-7188c88b2bb4"; Name = "SharePoint Online Client" }
    )

    # Test random GUIDs to see error message patterns
    $randomApps = @(
        @{ Id = [guid]::NewGuid().ToString(); Name = "Random App 1" }
        @{ Id = [guid]::NewGuid().ToString(); Name = "Random App 2" }
    )

    $allApps = $wellKnownApps + $randomApps

    Write-Host "[*] Testing $($wellKnownApps.Count) well-known applications + $($randomApps.Count) random GUIDs..." -ForegroundColor Cyan
    Write-Host ""

    foreach ($app in $allApps) {
        $url = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/authorize?client_id=$($app.Id)&response_type=code&scope=openid"

        Invoke-StealthDelay -Context "OAuth probe: $($app.Name)"
        $script:StealthConfig.RequestCount++

        try {
            $response = Invoke-WebRequest -Uri $url -Method GET -UseBasicParsing -ErrorAction Stop -MaximumRedirection 0
            $statusCode = $response.StatusCode
            $content = $response.Content
        }
        catch {
            $statusCode = $null
            $content = $null
            $errorMessage = $_.Exception.Message

            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                try {
                    $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                    $content = $reader.ReadToEnd()
                    $reader.Close()
                }
                catch {}
            }
        }

        $probeResult = [PSCustomObject]@{
            AppId = $app.Id
            AppName = $app.Name
            StatusCode = $statusCode
            AppExists = $null
            ErrorCode = $null
            ErrorMessage = $null
        }

        # Analyze response for error codes
        if ($content) {
            # Check for AADSTS error codes
            if ($content -match 'AADSTS(\d+)') {
                $probeResult.ErrorCode = "AADSTS$($Matches[1])"
            }

            # Analyze specific error patterns
            if ($content -match 'Application with identifier .* was not found') {
                $probeResult.AppExists = $false
                $probeResult.ErrorMessage = "Application not found in tenant"
            }
            elseif ($content -match 'AADSTS700016') {
                $probeResult.AppExists = $false
                $probeResult.ErrorMessage = "Application not found in directory"
            }
            elseif ($content -match 'AADSTS650057') {
                $probeResult.AppExists = $true
                $probeResult.ErrorMessage = "Invalid resource - app exists but resource config issue"
            }
            elseif ($content -match 'AADSTS65001') {
                $probeResult.AppExists = $true
                $probeResult.ErrorMessage = "User/admin consent required - app exists"
            }
            elseif ($content -match 'AADSTS50011') {
                $probeResult.AppExists = $true
                $probeResult.ErrorMessage = "Reply URL mismatch - app exists"
            }
            elseif ($content -match 'AADSTS90002') {
                $probeResult.AppExists = $null
                $probeResult.ErrorMessage = "Tenant not found"
            }
            elseif ($content -match 'redirect' -or $statusCode -eq 302) {
                $probeResult.AppExists = $true
                $probeResult.ErrorMessage = "App exists - redirect to consent/login"
            }
        }

        $oauthResults += $probeResult

        # Display result
        if ($probeResult.AppExists -eq $true) {
            Write-Host "[+] $($app.Name) ($($app.Id))" -ForegroundColor Green
            Write-Host "    Status: App exists - $($probeResult.ErrorMessage)" -ForegroundColor Gray
        }
        elseif ($probeResult.AppExists -eq $false) {
            Write-Host "[-] $($app.Name) ($($app.Id))" -ForegroundColor Gray
            Write-Host "    Status: Not found - $($probeResult.ErrorMessage)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "[!] $($app.Name) ($($app.Id))" -ForegroundColor Yellow
            if ($probeResult.ErrorCode) {
                Write-Host "    Error: $($probeResult.ErrorCode)" -ForegroundColor Yellow
            }
        }
    }

    # Summary
    $existingApps = $oauthResults | Where-Object { $_.AppExists -eq $true }
    Write-Host ""
    Write-Host "[*] OAuth probe complete: $($existingApps.Count) apps accessible in tenant" -ForegroundColor Cyan

    $script:Results.OAuthProbe = $oauthResults
    return $oauthResults
}

# ============================================================================
# OUTPUT FUNCTIONS
# ============================================================================

function Show-Summary {
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "ENUMERATION SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    $summary = $script:Results.Summary

    Write-Host ""
    Write-Host "  Target Domain:     $($summary.Domain)" -ForegroundColor White

    if ($summary.TenantId) {
        Write-Host "  Tenant ID:         $($summary.TenantId)" -ForegroundColor White
    }

    if ($null -ne $summary.IsFederated) {
        $fedStatus = if ($summary.IsFederated) { "Yes (External IdP)" } else { "No (Azure AD Managed)" }
        $fedColor = if ($summary.IsFederated) { "Yellow" } else { "Green" }
        Write-Host "  Federated:         $fedStatus" -ForegroundColor $fedColor
    }

    if ($summary.UsersChecked -gt 0) {
        Write-Host "  Users Checked:     $($summary.UsersChecked)" -ForegroundColor White
        Write-Host "  Users Exist:       $($summary.UsersExist)" -ForegroundColor Green
    }

    if ($summary.PortsScanned -gt 0) {
        Write-Host "  Ports Scanned:     $($summary.PortsScanned)" -ForegroundColor White
        Write-Host "  Ports Open:        $($summary.PortsOpen)" -ForegroundColor Green
    }

    # New method summaries
    if ($summary.OneDriveUsersChecked -gt 0) {
        Write-Host "  OneDrive Checked:  $($summary.OneDriveUsersChecked)" -ForegroundColor White
        Write-Host "  OneDrive Exist:    $($summary.OneDriveUsersExist)" -ForegroundColor Green
    }

    if ($summary.SubdomainsChecked -gt 0) {
        Write-Host "  Subdomains Checked: $($summary.SubdomainsChecked)" -ForegroundColor White
        Write-Host "  Subdomains Found:   $($summary.SubdomainsFound)" -ForegroundColor Green
    }

    if ($summary.AutodiscoverV1Checked -gt 0) {
        Write-Host "  Autodiscover V1 Checked: $($summary.AutodiscoverV1Checked)" -ForegroundColor White
        Write-Host "  Autodiscover V1 Exist:   $($summary.AutodiscoverV1Exist)" -ForegroundColor Green
    }

    if ($summary.SharePointSitesChecked -gt 0) {
        Write-Host "  SharePoint Checked: $($summary.SharePointSitesChecked)" -ForegroundColor White
        Write-Host "  SharePoint Found:   $($summary.SharePointSitesFound)" -ForegroundColor Green
        Write-Host "  SharePoint Public:  $($summary.SharePointPublicSites)" -ForegroundColor Yellow
    }

    if ($summary.EwsEndpointsFound -gt 0) {
        Write-Host "  EWS Endpoints:      $($summary.EwsEndpointsFound)" -ForegroundColor White
    }

    if ($summary.LyncEndpointsFound -gt 0) {
        Write-Host "  Lync Endpoints:     $($summary.LyncEndpointsFound)" -ForegroundColor White
    }

    if ($null -ne $summary.SeamlessSSOEnabled) {
        $ssoStatus = if ($summary.SeamlessSSOEnabled) { "ENABLED" } else { "Disabled" }
        $ssoColor = if ($summary.SeamlessSSOEnabled) { "Yellow" } else { "Gray" }
        Write-Host "  Seamless SSO:      $ssoStatus" -ForegroundColor $ssoColor
    }

    Write-Host ""
}

function Show-MatrixResults {
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "RESULTS MATRIX" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    # Tenant Info Matrix
    if ($script:Results.TenantInfo) {
        Write-Host "`nTenant Information:" -ForegroundColor Yellow
        Write-Host "-" * 50
        $tenantTable = @(
            [PSCustomObject]@{ Property = "Domain"; Value = $script:Results.TenantInfo.Domain }
            [PSCustomObject]@{ Property = "Tenant ID"; Value = $script:Results.TenantInfo.TenantId }
            [PSCustomObject]@{ Property = "Tenant Name"; Value = $script:Results.TenantInfo.TenantName }
            [PSCustomObject]@{ Property = "Region"; Value = $script:Results.TenantInfo.Region }
        ) | Where-Object { $_.Value }
        $tenantTable | Format-Table -AutoSize | Out-String | Write-Host
    }

    # Domain Realm Matrix
    if ($script:Results.DomainRealm) {
        Write-Host "Domain Realm:" -ForegroundColor Yellow
        Write-Host "-" * 50
        $realmTable = @(
            [PSCustomObject]@{ Property = "Namespace Type"; Value = $script:Results.DomainRealm.NameSpaceType }
            [PSCustomObject]@{ Property = "Federated"; Value = $script:Results.DomainRealm.IsFederated }
            [PSCustomObject]@{ Property = "Auth URL"; Value = $script:Results.DomainRealm.AuthURL }
            [PSCustomObject]@{ Property = "Cloud Instance"; Value = $script:Results.DomainRealm.CloudInstanceName }
        ) | Where-Object { $null -ne $_.Value }
        $realmTable | Format-Table -AutoSize | Out-String | Write-Host
    }

    # User Enumeration Matrix
    if ($script:Results.UserEnumeration.Count -gt 0) {
        Write-Host "User Enumeration Results:" -ForegroundColor Yellow
        Write-Host "-" * 50
        $userTable = $script:Results.UserEnumeration | Select-Object Email, Exists, ResultDescription
        $userTable | Format-Table -AutoSize | Out-String | Write-Host
    }

    # DNS Records Matrix
    $totalDnsRecords = $script:Results.DnsRecords.CNAME.Count +
                       $script:Results.DnsRecords.Autodiscover.Count +
                       $script:Results.DnsRecords.MX.Count +
                       $script:Results.DnsRecords.SRV.Count +
                       $script:Results.DnsRecords.TXT.Count

    if ($totalDnsRecords -gt 0) {
        Write-Host "DNS Records:" -ForegroundColor Yellow
        Write-Host "-" * 50

        if ($script:Results.DnsRecords.MX.Count -gt 0) {
            Write-Host "  MX Records:" -ForegroundColor Gray
            $script:Results.DnsRecords.MX | Format-Table Exchange, Preference -AutoSize | Out-String | Write-Host
        }

        if ($script:Results.DnsRecords.SPF.Count -gt 0) {
            Write-Host "  SPF Records:" -ForegroundColor Gray
            $script:Results.DnsRecords.SPF | ForEach-Object { Write-Host "    $($_.Value)" }
        }
    }

    # Port Scan Matrix
    if ($script:Results.PortScan.Count -gt 0) {
        Write-Host "`nPort Scan Results:" -ForegroundColor Yellow
        Write-Host "-" * 50
        $portTable = $script:Results.PortScan | Select-Object Port, Service, Status, ResponseTime
        $portTable | Format-Table -AutoSize | Out-String | Write-Host
    }

    # Autodiscover V2 Matrix
    if ($script:Results.AutodiscoverV2.Count -gt 0) {
        Write-Host "`nAutodiscover V2 Results:" -ForegroundColor Yellow
        Write-Host "-" * 50
        $autoV2Table = $script:Results.AutodiscoverV2 | Select-Object Email, Exists, StatusCode, RedirectUrl
        $autoV2Table | Format-Table -AutoSize | Out-String | Write-Host
    }

    # Autodiscover V1 Matrix
    if ($script:Results.AutodiscoverV1.Count -gt 0) {
        Write-Host "`nAutodiscover V1 Results:" -ForegroundColor Yellow
        Write-Host "-" * 50
        $autoV1Table = $script:Results.AutodiscoverV1 | Select-Object Email, Exists, StatusCode, ResultDescription, RedirectUrl
        $autoV1Table | Format-Table -AutoSize | Out-String | Write-Host
    }

    # SharePoint / Teams Discovery Matrix
    if ($script:Results.SharePointEnum.Count -gt 0) {
        Write-Host "`nSharePoint / Teams Discovery:" -ForegroundColor Yellow
        Write-Host "-" * 50
        $spTable = $script:Results.SharePointEnum | Select-Object Type, Name, StatusCode, Exists, PublicAccess, Url
        $spTable | Format-Table -AutoSize | Out-String | Write-Host
    }

    # EWS Probe Matrix
    if ($script:Results.EwsProbe.Count -gt 0) {
        Write-Host "`nEWS Endpoints:" -ForegroundColor Yellow
        Write-Host "-" * 50
        $ewsTable = $script:Results.EwsProbe | Select-Object Name, StatusCode, Available, AuthRequired, Url
        $ewsTable | Format-Table -AutoSize | Out-String | Write-Host
    }

    # Lync / Skype Discovery Matrix
    if ($script:Results.LyncProbe.Count -gt 0) {
        Write-Host "`nLync / Skype Discovery:" -ForegroundColor Yellow
        Write-Host "-" * 50
        $lyncTable = $script:Results.LyncProbe | Select-Object Name, StatusCode, Available, Url
        $lyncTable | Format-Table -AutoSize | Out-String | Write-Host
    }
}

function Export-Results {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $extension = [System.IO.Path]::GetExtension($Path).ToLower()

    # Prepare export data
    $exportData = @{
        ExportDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Summary = $script:Results.Summary
        TenantInfo = $script:Results.TenantInfo
        DomainRealm = $script:Results.DomainRealm
        UserEnumeration = $script:Results.UserEnumeration
        DnsRecords = $script:Results.DnsRecords
        PortScan = $script:Results.PortScan
        # New method results
        OneDriveEnum = $script:Results.OneDriveEnum
        FederationMeta = $script:Results.FederationMeta
        SeamlessSSO = $script:Results.SeamlessSSO
        SubdomainEnum = $script:Results.SubdomainEnum
        AutodiscoverV2 = $script:Results.AutodiscoverV2
        AutodiscoverV1 = $script:Results.AutodiscoverV1
        EwsProbe = $script:Results.EwsProbe
        SharePointEnum = $script:Results.SharePointEnum
        LyncProbe = $script:Results.LyncProbe
        MailEnum = $script:Results.MailEnum
        TenantReverse = $script:Results.TenantReverse
        OAuthProbe = $script:Results.OAuthProbe
    }

    try {
        switch ($extension) {
            ".json" {
                $exportData | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
                Write-Host "[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            ".csv" {
                # For CSV, export a flattened summary
                $csvData = @()

                # Add user enumeration results
                foreach ($user in $script:Results.UserEnumeration) {
                    $csvData += [PSCustomObject]@{
                        Type = "UserEnum"
                        Target = $user.Email
                        Result = $user.ResultDescription
                        Exists = $user.Exists
                    }
                }

                # Add port scan results
                foreach ($port in $script:Results.PortScan) {
                    $csvData += [PSCustomObject]@{
                        Type = "PortScan"
                        Target = "$($port.Host):$($port.Port)"
                        Result = $port.Status
                        Exists = ($port.Status -eq "Open")
                    }
                }

                # Add DNS records
                foreach ($mx in $script:Results.DnsRecords.MX) {
                    $csvData += [PSCustomObject]@{
                        Type = "DNS_MX"
                        Target = $mx.Exchange
                        Result = "Priority: $($mx.Preference)"
                        Exists = $true
                    }
                }

                # Add OneDrive enumeration results
                foreach ($user in $script:Results.OneDriveEnum) {
                    $csvData += [PSCustomObject]@{
                        Type = "OneDriveEnum"
                        Target = $user.Email
                        Result = "Status: $($user.StatusCode)"
                        Exists = $user.Exists
                    }
                }

                # Add subdomain enumeration results
                foreach ($subdomain in $script:Results.SubdomainEnum) {
                    $csvData += [PSCustomObject]@{
                        Type = "SubdomainEnum"
                        Target = $subdomain.Subdomain
                        Result = $subdomain.Service
                        Exists = $subdomain.Exists
                    }
                }

                # Add Autodiscover enumeration results
                foreach ($user in $script:Results.AutodiscoverV2) {
                    $csvData += [PSCustomObject]@{
                        Type = "AutodiscoverV2"
                        Target = $user.Email
                        Result = "Status: $($user.StatusCode)"
                        Exists = $user.Exists
                    }
                }

                # Add Autodiscover V1 enumeration results
                foreach ($user in $script:Results.AutodiscoverV1) {
                    $csvData += [PSCustomObject]@{
                        Type = "AutodiscoverV1"
                        Target = $user.Email
                        Result = "Status: $($user.StatusCode)"
                        Exists = $user.Exists
                    }
                }

                # Add SharePoint discovery results
                foreach ($site in $script:Results.SharePointEnum) {
                    $csvData += [PSCustomObject]@{
                        Type = "SharePointEnum"
                        Target = $site.Url
                        Result = "Status: $($site.StatusCode)"
                        Exists = $site.Exists
                    }
                }

                # Add EWS probe results
                foreach ($endpoint in $script:Results.EwsProbe) {
                    $csvData += [PSCustomObject]@{
                        Type = "EwsProbe"
                        Target = $endpoint.Url
                        Result = "Status: $($endpoint.StatusCode)"
                        Exists = $endpoint.Available
                    }
                }

                # Add Lync probe results
                foreach ($endpoint in $script:Results.LyncProbe) {
                    $csvData += [PSCustomObject]@{
                        Type = "LyncProbe"
                        Target = $endpoint.Url
                        Result = "Status: $($endpoint.StatusCode)"
                        Exists = $endpoint.Available
                    }
                }

                # Add OAuth probe results
                foreach ($app in $script:Results.OAuthProbe) {
                    $csvData += [PSCustomObject]@{
                        Type = "OAuthProbe"
                        Target = "$($app.AppName) ($($app.AppId))"
                        Result = $app.ErrorMessage
                        Exists = $app.AppExists
                    }
                }

                if ($csvData.Count -gt 0) {
                    $csvData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                }
                else {
                    # Export summary if no detailed data
                    $script:Results.Summary | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                }

                Write-Host "[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            default {
                # Default to JSON
                $jsonPath = $Path + ".json"
                $exportData | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
                Write-Host "[+] Results exported to JSON: $jsonPath" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "[ERROR] Failed to export results: $_" -ForegroundColor Red
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Show-Banner

    # Validate parameters
    $hasEmailInput = $Email -or $Emails -or $EmailList

    if (-not $Domain -and -not $hasEmailInput) {
        Write-Host "[ERROR] You must specify either -Domain or email input (-Email, -Emails, or -EmailList)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Usage examples:" -ForegroundColor Cyan
        Write-Host "  .\Invoke-EntraEnum.ps1 -Domain contoso.com" -ForegroundColor Gray
        Write-Host "  .\Invoke-EntraEnum.ps1 -Email user@contoso.com -UserEnum" -ForegroundColor Gray
        Write-Host "  .\Invoke-EntraEnum.ps1 -Domain contoso.com -All" -ForegroundColor Gray
        exit 1
    }

    # Extract domain from email if not provided
    if (-not $Domain -and $Email) {
        if ($Email -match '@(.+)$') {
            $Domain = $Matches[1]
            Write-Host "[*] Extracted domain from email: $Domain" -ForegroundColor Cyan
        }
    }

    # Load emails from file if specified
    $allEmails = @()
    if ($Email) {
        $allEmails += $Email
    }
    if ($Emails) {
        $allEmails += $Emails
    }
    if ($EmailList) {
        if (Test-Path $EmailList) {
            $fileEmails = Get-Content $EmailList | Where-Object { $_ -match '@' }
            $allEmails += $fileEmails
            Write-Host "[*] Loaded $($fileEmails.Count) emails from $EmailList" -ForegroundColor Cyan
        }
        else {
            Write-Host "[ERROR] Email list file not found: $EmailList" -ForegroundColor Red
            exit 1
        }
    }

    # Remove duplicates
    $allEmails = $allEmails | Select-Object -Unique

    # Auto-enable UserEnum if emails provided
    if ($allEmails.Count -gt 0 -and -not $UserEnum.IsPresent -and -not $All.IsPresent) {
        $UserEnum = [switch]::new($true)
    }

    # Determine which methods to run
    $runTenantInfo = $TenantInfo.IsPresent -or $All.IsPresent
    $runDomainRealm = $DomainRealm.IsPresent -or $All.IsPresent
    $runDnsEnum = $DnsEnum.IsPresent -or $All.IsPresent
    $runUserEnum = $UserEnum.IsPresent -or $All.IsPresent
    $runPortScan = $PortScan.IsPresent -or $All.IsPresent

    # New enumeration methods
    $runOneDriveEnum = $OneDriveEnum.IsPresent -or $All.IsPresent
    $runFederationMeta = $FederationMeta.IsPresent -or $All.IsPresent
    $runSeamlessSSO = $SeamlessSSO.IsPresent -or $All.IsPresent
    $runSubdomainEnum = $SubdomainEnum.IsPresent -or $All.IsPresent
    $runAutodiscoverEnum = $AutodiscoverEnum.IsPresent -or $All.IsPresent
    $runAutodiscoverV1Enum = $AutodiscoverV1Enum.IsPresent -or $All.IsPresent
    $runEwsProbe = $EwsProbe.IsPresent -or $All.IsPresent
    $runSharePointEnum = $SharePointEnum.IsPresent -or $All.IsPresent
    $runLyncProbe = $LyncProbe.IsPresent -or $All.IsPresent
    $runMailEnum = $MailEnum.IsPresent -or $All.IsPresent
    $runTenantReverse = $TenantReverse.IsPresent -or $All.IsPresent
    $runOAuthProbe = $OAuthProbe.IsPresent -or $All.IsPresent

    # Default behavior: if no methods specified and domain provided, run basic recon
    $noMethodsSpecified = -not $TenantInfo.IsPresent -and -not $DomainRealm.IsPresent -and -not $DnsEnum.IsPresent -and -not $UserEnum.IsPresent -and -not $PortScan.IsPresent -and -not $OneDriveEnum.IsPresent -and -not $FederationMeta.IsPresent -and -not $SeamlessSSO.IsPresent -and -not $SubdomainEnum.IsPresent -and -not $AutodiscoverEnum.IsPresent -and -not $AutodiscoverV1Enum.IsPresent -and -not $EwsProbe.IsPresent -and -not $SharePointEnum.IsPresent -and -not $LyncProbe.IsPresent -and -not $MailEnum.IsPresent -and -not $TenantReverse.IsPresent -and -not $OAuthProbe.IsPresent -and -not $All.IsPresent
    if ($noMethodsSpecified -and $Domain -and $allEmails.Count -eq 0) {
        $runTenantInfo = $true
        $runDomainRealm = $true
        $runDnsEnum = $true
    }

    # Determine tenant name for OneDrive/Subdomain enumeration
    $effectiveTenantName = $TenantName
    if (-not $effectiveTenantName -and $Domain) {
        # Try to extract tenant name from domain (before first dot, removing common prefixes)
        $effectiveTenantName = ($Domain -split '\.')[0]
    }

    # Load custom wordlist for subdomain enumeration
    $customWords = $null
    if ($WordList -and (Test-Path $WordList)) {
        $customWords = Get-Content $WordList | Where-Object { $_ -match '^\w+$' }
        Write-Host "[*] Loaded $($customWords.Count) words from custom wordlist" -ForegroundColor Cyan
    }

    # Load custom wordlist for SharePoint/Teams discovery
    $sharePointWords = $null
    if ($SharePointWordList -and (Test-Path $SharePointWordList)) {
        $sharePointWords = Get-Content $SharePointWordList | Where-Object { $_ -match '^[\w-]+$' }
        Write-Host "[*] Loaded $($sharePointWords.Count) SharePoint site names from custom wordlist" -ForegroundColor Cyan
    }

    # Update summary
    $script:Results.Summary.Domain = $Domain

    # Display configuration
    Write-Host "[*] Target: $Domain" -ForegroundColor Cyan
    if ($script:StealthConfig.Enabled) {
        Write-Host "[*] Stealth Mode: ENABLED (Delay: $($script:StealthConfig.BaseDelay)s, Jitter: +/- $($script:StealthConfig.Jitter)s)" -ForegroundColor Magenta
    }

    # Execute enumeration methods
    if ($runTenantInfo -and $Domain) {
        Get-TenantInfo -Domain $Domain | Out-Null
    }

    if ($runDomainRealm -and $Domain) {
        Get-DomainRealm -Domain $Domain | Out-Null
    }

    if ($runDnsEnum -and $Domain) {
        Get-DnsRecords -Domain $Domain | Out-Null
    }

    if ($runUserEnum -and $allEmails.Count -gt 0) {
        Invoke-UserEnumeration -EmailAddresses $allEmails | Out-Null
    }
    elseif ($runUserEnum -and $allEmails.Count -eq 0) {
        Write-Host "[!] UserEnum requested but no emails provided. Use -Email, -Emails, or -EmailList" -ForegroundColor Yellow
    }

    if ($runPortScan -and $Domain) {
        Invoke-PortScan -Domain $Domain -CustomPorts $Ports | Out-Null
    }

    # === NEW ENUMERATION METHODS ===

    # OneDrive User Enumeration (requires tenant name and emails)
    if ($runOneDriveEnum -and $allEmails.Count -gt 0) {
        if ($effectiveTenantName) {
            Invoke-OneDriveEnumeration -EmailAddresses $allEmails -TenantName $effectiveTenantName | Out-Null
        }
        else {
            Write-Host "[!] OneDriveEnum requires -TenantName or a domain to extract tenant name from" -ForegroundColor Yellow
        }
    }
    elseif ($runOneDriveEnum -and $allEmails.Count -eq 0) {
        Write-Host "[!] OneDriveEnum requested but no emails provided. Use -Email, -Emails, or -EmailList" -ForegroundColor Yellow
    }

    # Federation Metadata
    if ($runFederationMeta -and $Domain) {
        Get-FederationMetadata -Domain $Domain | Out-Null
    }

    # Seamless SSO Detection
    if ($runSeamlessSSO -and $Domain) {
        Get-SeamlessSSOStatus -Domain $Domain | Out-Null
    }

    # Azure Subdomain Enumeration
    if ($runSubdomainEnum) {
        if ($effectiveTenantName) {
            Get-AzureSubdomains -TenantName $effectiveTenantName -CustomWordlist $customWords | Out-Null
        }
        else {
            Write-Host "[!] SubdomainEnum requires -TenantName or a domain to extract tenant name from" -ForegroundColor Yellow
        }
    }

    # Autodiscover V2 User Enumeration
    if ($runAutodiscoverEnum -and $allEmails.Count -gt 0) {
        Invoke-AutodiscoverEnumeration -EmailAddresses $allEmails | Out-Null
    }
    elseif ($runAutodiscoverEnum -and $allEmails.Count -eq 0) {
        Write-Host "[!] AutodiscoverEnum requested but no emails provided. Use -Email, -Emails, or -EmailList" -ForegroundColor Yellow
    }

    # Autodiscover V1 User Enumeration (Legacy)
    if ($runAutodiscoverV1Enum -and $allEmails.Count -gt 0) {
        Invoke-AutodiscoverV1Enumeration -EmailAddresses $allEmails -Domain $Domain | Out-Null
    }
    elseif ($runAutodiscoverV1Enum -and $allEmails.Count -eq 0) {
        Write-Host "[!] AutodiscoverV1Enum requested but no emails provided. Use -Email, -Emails, or -EmailList" -ForegroundColor Yellow
    }

    # Exchange Web Services Probe
    if ($runEwsProbe) {
        Invoke-EwsProbe -Domain $Domain | Out-Null
    }

    # SharePoint / Teams Discovery
    if ($runSharePointEnum) {
        if ($effectiveTenantName) {
            Invoke-SharePointDiscovery -TenantName $effectiveTenantName -CustomSites $sharePointWords | Out-Null
        }
        else {
            Write-Host "[!] SharePointEnum requires -TenantName or a domain to extract tenant name from" -ForegroundColor Yellow
        }
    }

    # Lync / Skype Discovery
    if ($runLyncProbe -and $Domain) {
        Invoke-LyncDiscovery -Domain $Domain | Out-Null
    }
    elseif ($runLyncProbe -and -not $Domain) {
        Write-Host "[!] LyncProbe requires -Domain" -ForegroundColor Yellow
    }

    # Enhanced Mail Security Enumeration
    if ($runMailEnum -and $Domain) {
        Get-MailSecurityRecords -Domain $Domain | Out-Null
    }

    # Tenant ID Reversal
    if ($runTenantReverse) {
        Get-TenantResources | Out-Null
    }

    # OAuth Configuration Probe
    if ($runOAuthProbe) {
        Invoke-OAuthProbe -Domain $Domain | Out-Null
    }

    # Display results
    Show-Summary

    if ($Matrix.IsPresent) {
        Show-MatrixResults
    }

    # Export if requested
    if ($ExportPath) {
        Export-Results -Path $ExportPath
    }

    Write-Host "[*] Enumeration completed. Total requests: $($script:StealthConfig.RequestCount)" -ForegroundColor Green
    Write-Host ""
}

# Run main function
Main
