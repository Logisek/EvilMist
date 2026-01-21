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
    Audits SharePoint Online sharing settings to identify oversharing and external access risks.

.DESCRIPTION
    This script performs a comprehensive audit of SharePoint Online security to identify
    potential data exposure and oversharing risks including:
    - Tenant-level external sharing settings
    - Anonymous link policies and expiration settings
    - Site-level sharing overrides (more permissive than tenant)
    - Guest access to sensitive sites
    - OneDrive external sharing configuration
    - Sensitivity label coverage gaps
    - File and folder sharing settings
    - Default link types and permissions
    
    SharePoint Online security is critical for preventing data leakage and
    unauthorized external access. This script provides visibility into sharing
    configurations that could expose sensitive data.
    
    The script uses PnP PowerShell module for authentication and API access.

.PARAMETER ExportPath
    Optional path to export results (CSV or JSON based on extension).

.PARAMETER TenantId
    Optional Tenant ID. If not specified, uses the user's home tenant.

.PARAMETER AdminUrl
    SharePoint Admin URL (e.g., https://contoso-admin.sharepoint.com).
    If not specified, will attempt to auto-detect from tenant.

.PARAMETER UseAzCliToken
    Try to use Azure CLI cached token first.

.PARAMETER UseAzPowerShellToken
    Try to use Azure PowerShell cached token first.

.PARAMETER EnableStealth
    Enable stealth mode with default delays and jitter to avoid detection.

.PARAMETER RequestDelay
    Base delay in seconds between API requests (0-60). Default: 0

.PARAMETER RequestJitter
    Random jitter range in seconds to add/subtract from delay (0-30). Default: 0

.PARAMETER MaxRetries
    Maximum retries on throttling (429) responses (1-10). Default: 3

.PARAMETER QuietStealth
    Suppress stealth-related status messages.

.PARAMETER OnlyExternalSharing
    Show only sites with external sharing enabled.

.PARAMETER OnlyHighRisk
    Show only HIGH and CRITICAL risk findings.

.PARAMETER OnlyAnonymousLinks
    Show only sites that allow anonymous links.

.PARAMETER OnlyPermissiveOverrides
    Show only sites with sharing settings more permissive than tenant.

.PARAMETER IncludeSensitivityLabels
    Include sensitivity label configuration analysis.

.PARAMETER IncludeOneDrive
    Include OneDrive for Business sharing analysis.

.PARAMETER IncludeLinkSettings
    Include detailed default link type and permission analysis.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraSharePointCheck.ps1
    # Enumerate all SharePoint sharing configurations

.EXAMPLE
    .\Invoke-EntraSharePointCheck.ps1 -ExportPath "sharepoint-security.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraSharePointCheck.ps1 -OnlyAnonymousLinks -Matrix
    # Show only sites allowing anonymous links in matrix format

.EXAMPLE
    .\Invoke-EntraSharePointCheck.ps1 -OnlyPermissiveOverrides -Matrix
    # Show sites with sharing more permissive than tenant

.EXAMPLE
    .\Invoke-EntraSharePointCheck.ps1 -IncludeOneDrive -IncludeSensitivityLabels -Matrix
    # Include OneDrive and sensitivity label analysis

.EXAMPLE
    .\Invoke-EntraSharePointCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$AdminUrl,

    [Parameter(Mandatory = $false)]
    [switch]$UseAzCliToken,

    [Parameter(Mandatory = $false)]
    [switch]$UseAzPowerShellToken,

    # Stealth & Evasion Parameters
    [Parameter(Mandatory = $false)]
    [switch]$EnableStealth,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 60)]
    [double]$RequestDelay = 0,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 30)]
    [double]$RequestJitter = 0,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3,

    [Parameter(Mandatory = $false)]
    [switch]$QuietStealth,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyExternalSharing,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyHighRisk,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyAnonymousLinks,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyPermissiveOverrides,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeSensitivityLabels,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeOneDrive,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeLinkSettings,

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

# Sharing capability levels (ordered by permissiveness)
$script:SharingCapabilityLevels = @{
    "Disabled" = 0           # No external sharing
    "ExistingExternalUserSharingOnly" = 1  # Only existing guests
    "ExternalUserSharingOnly" = 2  # New and existing guests (no anonymous)
    "ExternalUserAndGuestSharing" = 3  # Guests and anonymous links
}

# Required Graph scopes for SharePoint access (READ-ONLY)
$script:RequiredScopes = @(
    "Sites.Read.All",
    "Organization.Read.All"
)

# Fallback scopes (minimal read access)
$script:FallbackScopes = @(
    "Sites.Read.All"
)

# Track state
$script:SPOModuleAvailable = $false
$script:TenantFindings = $null
$script:SiteFindings = @()
$script:OneDriveFindings = @()
$script:SensitivityLabelFindings = @()
$script:LinkSettingsFindings = @()
$script:TotalSitesScanned = 0
$script:TenantDomain = ""
$script:TenantSharingCapability = ""
$script:StealthConfig = @{
    Enabled = $false
    BaseDelay = 0
    JitterRange = 0
    MaxRetries = 3
    QuietMode = $false
}

# Banner
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
    Write-Host "    Entra ID SharePoint Check - Sharing Settings & External Access Audit" -ForegroundColor Yellow
    Write-Host "    https://logisek.com | info@logisek.com"
    Write-Host "    Part of EvilMist Toolkit | github.com/Logisek/EvilMist"
    Write-Host ""
    Write-Host ""
}

# Stealth delay function
function Invoke-StealthDelay {
    if ($script:StealthConfig.Enabled) {
        $delay = $script:StealthConfig.BaseDelay
        if ($script:StealthConfig.JitterRange -gt 0) {
            $jitter = Get-Random -Minimum (-$script:StealthConfig.JitterRange) -Maximum $script:StealthConfig.JitterRange
            $delay += $jitter
        }
        if ($delay -gt 0 -and -not $script:StealthConfig.QuietMode) {
            Write-Host "[STEALTH] Delaying $([math]::Round($delay, 3))s..." -ForegroundColor DarkGray
        }
        if ($delay -gt 0) {
            Start-Sleep -Seconds $delay
        }
    }
}

# Initialize stealth configuration
function Initialize-StealthConfig {
    if ($EnableStealth) {
        $script:StealthConfig.Enabled = $true
        $script:StealthConfig.BaseDelay = 0.5
        $script:StealthConfig.JitterRange = 0.3
        $script:StealthConfig.QuietMode = $QuietStealth
        Write-Host "[STEALTH] Enabled with default settings (500ms + 300ms jitter)" -ForegroundColor Yellow
    }
    
    if ($RequestDelay -gt 0) {
        $script:StealthConfig.Enabled = $true
        $script:StealthConfig.BaseDelay = $RequestDelay
    }
    
    if ($RequestJitter -gt 0) {
        $script:StealthConfig.JitterRange = $RequestJitter
    }
    
    $script:StealthConfig.MaxRetries = $MaxRetries
    $script:StealthConfig.QuietMode = $QuietStealth
}

# Check if required modules are installed
function Test-RequiredModules {
    Write-Host "[*] Checking required PowerShell modules..." -ForegroundColor Cyan
    
    $allModulesOk = $true
    
    # Check Microsoft Graph modules (for authentication and site enumeration)
    $graphModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Sites"
    )
    
    $missingGraphModules = @()
    foreach ($module in $graphModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missingGraphModules += $module
        }
    }
    
    if ($missingGraphModules.Count -gt 0) {
        Write-Host "[!] Missing Microsoft Graph modules:" -ForegroundColor Yellow
        $missingGraphModules | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
        Write-Host "`n[*] Installing missing Graph modules automatically..." -ForegroundColor Cyan
        
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $scope = if ($isAdmin) { "AllUsers" } else { "CurrentUser" }
        
        foreach ($module in $missingGraphModules) {
            Write-Host "[*] Installing $module (Scope: $scope)..." -ForegroundColor Cyan
            try {
                $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
                if ($psGallery -and $psGallery.InstallationPolicy -ne 'Trusted') {
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
                }
                
                Install-Module -Name $module -Scope $scope -AllowClobber -Force -ErrorAction Stop
                Write-Host "[+] Successfully installed $module" -ForegroundColor Green
            }
            catch {
                Write-Host "[ERROR] Failed to install $module : $_" -ForegroundColor Red
                $allModulesOk = $false
            }
        }
    }
    else {
        Write-Host "[+] Microsoft Graph modules are installed" -ForegroundColor Green
    }
    
    # Check Microsoft.Online.SharePoint.PowerShell module (SharePoint Admin)
    Write-Host "[*] Checking SharePoint Online Management Shell..." -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Online.SharePoint.PowerShell)) {
        Write-Host "[!] SharePoint Online Management Shell is not installed" -ForegroundColor Yellow
        Write-Host "`n[*] Installing Microsoft.Online.SharePoint.PowerShell module..." -ForegroundColor Cyan
        
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $scope = if ($isAdmin) { "AllUsers" } else { "CurrentUser" }
        
        try {
            $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($psGallery -and $psGallery.InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            }
            
            Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Scope $scope -AllowClobber -Force -ErrorAction Stop
            Write-Host "[+] Successfully installed SharePoint Online Management Shell" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Could not install SharePoint Management Shell: $_" -ForegroundColor Yellow
            Write-Host "[*] Continuing with Graph API only (limited functionality)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[+] SharePoint Online Management Shell is installed" -ForegroundColor Green
    }
    
    return $allModulesOk
}

# Initialize and import required modules
function Initialize-Modules {
    Write-Host "[*] Initializing required modules..." -ForegroundColor Cyan
    
    try {
        # Import Microsoft Graph Authentication first
        Write-Host "[*] Importing Microsoft.Graph.Authentication..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Authentication -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Microsoft.Graph.Sites..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Sites -Force -ErrorAction Stop
        
        # Import SharePoint Online Management Shell
        Write-Host "[*] Importing SharePoint Online Management Shell..." -ForegroundColor Cyan
        try {
            Import-Module Microsoft.Online.SharePoint.PowerShell -DisableNameChecking -Force -ErrorAction Stop
            $script:SPOModuleAvailable = $true
            Write-Host "[+] SharePoint Online module imported" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] SharePoint Online module not available, using Graph API only" -ForegroundColor Yellow
            $script:SPOModuleAvailable = $false
        }
        
        Write-Host "[+] Modules initialized successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to import modules: $_" -ForegroundColor Red
        return $false
    }
}

# Try to get token from Azure CLI
function Get-AzCliToken {
    param(
        [string]$Resource = "https://graph.microsoft.com"
    )
    try {
        Write-Host "[*] Attempting to use Azure CLI token..." -ForegroundColor Cyan
        $azToken = az account get-access-token --resource $Resource --query accessToken -o tsv 2>$null
        if ($azToken -and $azToken.Length -gt 0) {
            Write-Host "[+] Successfully retrieved Azure CLI token" -ForegroundColor Green
            return $azToken
        }
    }
    catch {
        Write-Host "[!] Failed to retrieve Azure CLI token" -ForegroundColor Yellow
    }
    return $null
}

# Try to get token from Azure PowerShell
function Get-AzPowerShellToken {
    param(
        [string]$Resource = "https://graph.microsoft.com"
    )
    try {
        Write-Host "[*] Attempting to use Azure PowerShell token..." -ForegroundColor Cyan
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($azContext) {
            $token = (Get-AzAccessToken -ResourceUrl $Resource -ErrorAction SilentlyContinue).Token
            if ($token) {
                Write-Host "[+] Successfully retrieved Azure PowerShell token" -ForegroundColor Green
                return $token
            }
        }
    }
    catch {
        Write-Host "[!] Failed to retrieve Azure PowerShell token" -ForegroundColor Yellow
    }
    return $null
}

# Connect to Microsoft Graph first
function Connect-GraphService {
    Write-Host "`n[*] Authenticating to Microsoft Graph..." -ForegroundColor Cyan
    
    # Check if already connected
    try {
        $context = Get-MgContext -ErrorAction Stop
        if ($context) {
            Write-Host "[+] Already connected to Microsoft Graph" -ForegroundColor Green
            Write-Host "[+] Tenant: $($context.TenantId)" -ForegroundColor Green
            Write-Host "[+] Account: $($context.Account)" -ForegroundColor Green
            return $true
        }
    }
    catch {
        # Not connected, continue to authenticate
    }
    
    # Try Azure CLI token if requested
    if ($UseAzCliToken) {
        $token = Get-AzCliToken -Resource "https://graph.microsoft.com"
        if ($token) {
            try {
                Connect-MgGraph -AccessToken (ConvertTo-SecureString $token -AsPlainText -Force) -NoWelcome
                Write-Host "[+] Connected using Azure CLI token" -ForegroundColor Green
                return $true
            }
            catch {
                Write-Host "[!] Failed to connect with Azure CLI token: $_" -ForegroundColor Yellow
            }
        }
    }
    
    # Try Azure PowerShell token if requested
    if ($UseAzPowerShellToken) {
        $token = Get-AzPowerShellToken -Resource "https://graph.microsoft.com"
        if ($token) {
            try {
                Connect-MgGraph -AccessToken (ConvertTo-SecureString $token -AsPlainText -Force) -NoWelcome
                Write-Host "[+] Connected using Azure PowerShell token" -ForegroundColor Green
                return $true
            }
            catch {
                Write-Host "[!] Failed to connect with Azure PowerShell token: $_" -ForegroundColor Yellow
            }
        }
    }
    
    # Interactive authentication
    try {
        $connectParams = @{
            Scopes = $script:RequiredScopes
            NoWelcome = $true
        }
        
        if ($TenantId) {
            $connectParams['TenantId'] = $TenantId
        }
        
        Write-Host "[*] Requesting scopes: $($script:RequiredScopes -join ', ')" -ForegroundColor Cyan
        Connect-MgGraph @connectParams -ErrorAction Stop
        
        $context = Get-MgContext
        Write-Host "[+] Connected to Microsoft Graph" -ForegroundColor Green
        Write-Host "[+] Tenant: $($context.TenantId)" -ForegroundColor Green
        Write-Host "[+] Account: $($context.Account)" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Host "[!] Failed with full scopes, trying fallback..." -ForegroundColor Yellow
        
        try {
            $connectParams = @{
                Scopes = $script:FallbackScopes
                NoWelcome = $true
            }
            if ($TenantId) {
                $connectParams['TenantId'] = $TenantId
            }
            
            Connect-MgGraph @connectParams -ErrorAction Stop
            Write-Host "[+] Connected with reduced permissions" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "[ERROR] Failed to connect to Microsoft Graph: $_" -ForegroundColor Red
            return $false
        }
    }
}

# Convert SharePoint URL to Admin URL if needed
function Convert-ToAdminUrl {
    param(
        [string]$Url
    )
    
    if ([string]::IsNullOrWhiteSpace($Url)) {
        return $null
    }
    
    # Clean up the URL
    $Url = $Url.Trim().TrimEnd('/')
    
    # Check if it's already an admin URL
    if ($Url -match '-admin\.sharepoint\.com') {
        return $Url
    }
    
    # Convert regular SharePoint URL to admin URL
    # Pattern: https://tenant.sharepoint.com -> https://tenant-admin.sharepoint.com
    if ($Url -match '^https://([^.]+)\.sharepoint\.com') {
        $tenant = $matches[1]
        $adminUrl = "https://$tenant-admin.sharepoint.com"
        Write-Host "[*] Converting to Admin URL: $adminUrl" -ForegroundColor Yellow
        return $adminUrl
    }
    
    # If it doesn't match expected patterns, return as-is
    return $Url
}

# Auto-detect SharePoint Admin URL from Graph context
function Get-SharePointAdminUrl {
    param(
        [string]$ProvidedUrl
    )
    
    if ($ProvidedUrl) {
        # Convert to admin URL if user provided regular URL
        return (Convert-ToAdminUrl -Url $ProvidedUrl)
    }
    
    Write-Host "[*] Auto-detecting SharePoint Admin URL from tenant..." -ForegroundColor Cyan
    
    $tenantName = $null
    
    # Method 1: Try to infer from Graph context account (most reliable)
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context -and $context.Account) {
            Write-Host "[*] Logged in as: $($context.Account)" -ForegroundColor Gray
            
            # Check for onmicrosoft.com domain
            if ($context.Account -match '@(.+)\.onmicrosoft\.com$') {
                $tenantName = $matches[1]
                Write-Host "[+] Detected tenant from onmicrosoft.com domain: $tenantName" -ForegroundColor Green
            }
            # For custom domains, extract the domain prefix as tenant name
            elseif ($context.Account -match '@([^.]+)\.') {
                # e.g., user@logisek.com -> logisek
                $tenantName = $matches[1]
                Write-Host "[+] Inferred tenant from custom domain: $tenantName" -ForegroundColor Green
            }
            elseif ($context.Account -match '@(.+)$') {
                # Fallback: use domain without TLD
                $domain = $matches[1]
                $tenantName = $domain -replace '\.[^.]+$', ''
                Write-Host "[+] Inferred tenant name: $tenantName" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "[!] Could not get Graph context: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Method 2: Try to get from organization info (if Method 1 didn't work)
    # Skip this - the Graph SDK has version conflicts, rely on Method 1 or prompt
    
    # If we found a tenant name, construct the admin URL
    if ($tenantName) {
        $adminUrl = "https://$tenantName-admin.sharepoint.com"
        Write-Host "[+] SharePoint Admin URL: $adminUrl" -ForegroundColor Green
        return $adminUrl
    }
    
    # Prompt user for tenant name if auto-detection failed
    Write-Host "[!] Could not auto-detect SharePoint Admin URL" -ForegroundColor Yellow
    Write-Host "[*] Please enter your SharePoint tenant name or URL" -ForegroundColor Cyan
    Write-Host "    Examples: 'contoso' or 'https://contoso.sharepoint.com'" -ForegroundColor Gray
    $manualInput = Read-Host "SharePoint tenant"
    
    if ([string]::IsNullOrWhiteSpace($manualInput)) {
        Write-Host "[ERROR] SharePoint URL is required" -ForegroundColor Red
        return $null
    }
    
    # Handle just tenant name input (e.g., "contoso")
    if ($manualInput -notmatch '\.') {
        $adminUrl = "https://$manualInput-admin.sharepoint.com"
        Write-Host "[*] Using Admin URL: $adminUrl" -ForegroundColor Cyan
        return $adminUrl
    }
    
    # Convert full URL to admin URL if needed
    return (Convert-ToAdminUrl -Url $manualInput)
}

# Connect to SharePoint Admin using SharePoint Online Management Shell (delegated auth)
function Connect-SharePointService {
    param(
        [string]$AdminUrl
    )
    
    Write-Host "`n[*] Connecting to SharePoint Online Admin..." -ForegroundColor Cyan
    Write-Host "[*] Admin URL: $AdminUrl" -ForegroundColor Gray
    
    # Extract tenant domain
    if ($AdminUrl -match 'https://(.+)-admin\.sharepoint\.com') {
        $script:TenantDomain = $matches[1]
    }
    
    # Check if SPO module is available
    if (-not $script:SPOModuleAvailable) {
        Write-Host "[!] SharePoint Online module not available" -ForegroundColor Yellow
        Write-Host "[*] Will use Microsoft Graph API for site enumeration (limited functionality)" -ForegroundColor Yellow
        return $true
    }
    
    # Check if already connected to SPO
    try {
        $spoContext = Get-SPOTenant -ErrorAction Stop
        if ($spoContext) {
            Write-Host "[+] Already connected to SharePoint Online Admin" -ForegroundColor Green
            return $true
        }
    }
    catch {
        # Not connected, continue to connect
    }
    
    # Connect to SharePoint Online Admin (uses browser-based delegated auth)
    Write-Host "[*] Initiating SharePoint Online authentication..." -ForegroundColor Cyan
    Write-Host "[*] A browser window will open for sign-in" -ForegroundColor Yellow
    
    try {
        # Connect-SPOService uses browser-based modern auth by default
        Connect-SPOService -Url $AdminUrl -ErrorAction Stop
        
        Write-Host "[+] Connected to SharePoint Online Admin" -ForegroundColor Green
        
        # Verify connection
        $tenant = Get-SPOTenant -ErrorAction SilentlyContinue
        if ($tenant) {
            Write-Host "[+] Tenant verified: $($script:TenantDomain)" -ForegroundColor Green
        }
        
        return $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Host "[!] SPO connection failed: $errorMessage" -ForegroundColor Yellow
        
        # If SPO fails, fall back to Graph API only
        Write-Host "[*] Falling back to Microsoft Graph API (limited functionality)" -ForegroundColor Yellow
        Write-Host "[*] Note: Tenant-level sharing settings will not be available" -ForegroundColor Yellow
        
        $script:SPOModuleAvailable = $false
        return $true
    }
}

# Get sharing capability description
function Get-SharingCapabilityDescription {
    param(
        [string]$Capability
    )
    
    switch ($Capability) {
        "Disabled" { return "No external sharing" }
        "ExistingExternalUserSharingOnly" { return "Existing guests only" }
        "ExternalUserSharingOnly" { return "New and existing guests" }
        "ExternalUserAndGuestSharing" { return "Anyone (anonymous links)" }
        default { return $Capability }
    }
}

# Get default link type description
function Get-DefaultLinkTypeDescription {
    param(
        [string]$LinkType
    )
    
    switch ($LinkType) {
        "None" { return "No default (user selects)" }
        "Direct" { return "Specific people" }
        "Internal" { return "Organization only" }
        "AnonymousAccess" { return "Anyone with link" }
        default { return $LinkType }
    }
}

# Check if site sharing is more permissive than tenant
function Test-SiteMorePermissive {
    param(
        [string]$TenantCapability,
        [string]$SiteCapability
    )
    
    $tenantLevel = $script:SharingCapabilityLevels[$TenantCapability]
    $siteLevel = $script:SharingCapabilityLevels[$SiteCapability]
    
    if ($null -eq $tenantLevel) { $tenantLevel = 0 }
    if ($null -eq $siteLevel) { $siteLevel = 0 }
    
    return $siteLevel -gt $tenantLevel
}

# Get tenant-level sharing settings
function Get-TenantSharingSettings {
    Write-Host "`n[*] Analyzing tenant-level sharing settings..." -ForegroundColor Cyan
    
    # Check if SPO module is available
    if (-not $script:SPOModuleAvailable) {
        Write-Host "[!] SharePoint Online module not available - skipping tenant settings" -ForegroundColor Yellow
        Write-Host "[*] Use Microsoft.Online.SharePoint.PowerShell for full functionality" -ForegroundColor Yellow
        
        # Return minimal info
        $script:TenantSharingCapability = "Unknown"
        $script:TenantFindings = [PSCustomObject]@{
            SharingCapability = "Unknown"
            SharingCapabilityDescription = "Unable to retrieve (SPO module required)"
            RiskLevel = "UNKNOWN"
            RiskReasons = "Tenant settings require SharePoint Online Management Shell"
            RiskReasonCount = 1
        }
        return $script:TenantFindings
    }
    
    try {
        Invoke-StealthDelay
        
        $tenant = Get-SPOTenant -ErrorAction Stop
        
        $script:TenantSharingCapability = $tenant.SharingCapability
        
        $riskLevel = "LOW"
        $riskReasons = @()
        
        # Assess tenant sharing capability
        switch ($tenant.SharingCapability) {
            "ExternalUserAndGuestSharing" {
                $riskLevel = "HIGH"
                $riskReasons += "Anonymous links (Anyone) allowed at tenant level"
            }
            "ExternalUserSharingOnly" {
                $riskLevel = "MEDIUM"
                $riskReasons += "External guest sharing allowed at tenant level"
            }
            "ExistingExternalUserSharingOnly" {
                $riskLevel = "LOW"
                $riskReasons += "Only existing external users can access"
            }
            "Disabled" {
                $riskLevel = "LOW"
                $riskReasons += "External sharing is disabled"
            }
        }
        
        # Check for permissive link settings
        if ($tenant.DefaultSharingLinkType -eq "AnonymousAccess") {
            if ($riskLevel -ne "HIGH") {
                $riskLevel = "HIGH"
            }
            $riskReasons += "Default link type is Anonymous"
        }
        
        # Check link expiration
        if ($tenant.RequireAnonymousLinksExpireInDays -eq 0 -or $null -eq $tenant.RequireAnonymousLinksExpireInDays) {
            if ($tenant.SharingCapability -eq "ExternalUserAndGuestSharing") {
                if ($riskLevel -eq "LOW") {
                    $riskLevel = "MEDIUM"
                }
                $riskReasons += "Anonymous links never expire"
            }
        }
        
        # Check file/folder link permissions
        if ($tenant.DefaultLinkPermission -eq "Edit") {
            $riskReasons += "Default link permission is Edit (not View)"
        }
        
        # Check OneDrive settings at tenant level
        $oneDriveSharing = $tenant.OneDriveSharingCapability
        if ($oneDriveSharing -eq "ExternalUserAndGuestSharing") {
            if ($riskLevel -ne "CRITICAL") {
                $riskLevel = "HIGH"
            }
            $riskReasons += "OneDrive allows anonymous links"
        }
        
        $tenantInfo = [PSCustomObject]@{
            # Basic Settings
            SharingCapability = $tenant.SharingCapability
            SharingCapabilityDescription = (Get-SharingCapabilityDescription -Capability $tenant.SharingCapability)
            
            # Link Settings
            DefaultSharingLinkType = $tenant.DefaultSharingLinkType
            DefaultLinkPermission = $tenant.DefaultLinkPermission
            RequireAnonymousLinksExpireInDays = $tenant.RequireAnonymousLinksExpireInDays
            
            # External Sharing Controls
            SharingDomainRestrictionMode = $tenant.SharingDomainRestrictionMode
            SharingAllowedDomainList = ($tenant.SharingAllowedDomainList -join ", ")
            SharingBlockedDomainList = ($tenant.SharingBlockedDomainList -join ", ")
            
            # Guest Access Controls
            ShowEveryoneClaim = $tenant.ShowEveryoneClaim
            ShowEveryoneExceptExternalUsersClaim = $tenant.ShowEveryoneExceptExternalUsersClaim
            PreventExternalUsersFromResharing = $tenant.PreventExternalUsersFromResharing
            ExternalUserExpirationRequired = $tenant.ExternalUserExpirationRequired
            ExternalUserExpireInDays = $tenant.ExternalUserExpireInDays
            
            # OneDrive Settings
            OneDriveSharingCapability = $tenant.OneDriveSharingCapability
            OneDriveSharingCapabilityDescription = (Get-SharingCapabilityDescription -Capability $tenant.OneDriveSharingCapability)
            
            # Access Control
            ConditionalAccessPolicy = $tenant.ConditionalAccessPolicy
            
            # File/Folder Settings
            FileAnonymousLinkType = $tenant.FileAnonymousLinkType
            FolderAnonymousLinkType = $tenant.FolderAnonymousLinkType
            
            # Risk Assessment
            RiskLevel = $riskLevel
            RiskReasons = ($riskReasons -join "; ")
            RiskReasonCount = $riskReasons.Count
        }
        
        $script:TenantFindings = $tenantInfo
        
        Write-Host "[+] Tenant sharing capability: $($tenant.SharingCapability)" -ForegroundColor Green
        
        return $tenantInfo
    }
    catch {
        Write-Host "[ERROR] Failed to get tenant settings: $_" -ForegroundColor Red
        return $null
    }
}

# Analyze individual site sharing settings
function Get-SiteSharingAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        $Site
    )
    
    $riskLevel = "LOW"
    $riskReasons = @()
    
    # Check if site sharing is more permissive than tenant
    $isMorePermissive = Test-SiteMorePermissive -TenantCapability $script:TenantSharingCapability -SiteCapability $Site.SharingCapability
    
    if ($isMorePermissive) {
        $riskLevel = "CRITICAL"
        $riskReasons += "Sharing more permissive than tenant default"
    }
    
    # Assess site sharing capability
    switch ($Site.SharingCapability) {
        "ExternalUserAndGuestSharing" {
            if ($riskLevel -ne "CRITICAL") {
                $riskLevel = "HIGH"
            }
            $riskReasons += "Anonymous links allowed"
        }
        "ExternalUserSharingOnly" {
            if ($riskLevel -eq "LOW") {
                $riskLevel = "MEDIUM"
            }
            $riskReasons += "External guest sharing enabled"
        }
    }
    
    # Check if it's a sensitive site (team site, communication site)
    $siteTemplate = $Site.Template
    $isSensitiveSite = $false
    
    if ($siteTemplate -like "*STS#3*" -or $siteTemplate -like "*GROUP#0*" -or $siteTemplate -like "*TEAMCHANNEL#0*") {
        $isSensitiveSite = $true
        if ($Site.SharingCapability -ne "Disabled" -and $Site.SharingCapability -ne "ExistingExternalUserSharingOnly") {
            $riskReasons += "Team site with external sharing"
        }
    }
    
    # Check for lack of sensitivity labels
    $hasSensitivityLabel = -not [string]::IsNullOrEmpty($Site.SensitivityLabel)
    if (-not $hasSensitivityLabel -and $Site.SharingCapability -eq "ExternalUserAndGuestSharing") {
        $riskReasons += "No sensitivity label with anonymous sharing"
    }
    
    # Check default link type at site level
    if ($Site.DefaultSharingLinkType -eq "AnonymousAccess") {
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
        $riskReasons += "Default link type is Anonymous"
    }
    
    # Check for disabled external access but allowing anonymous
    if ($Site.DisableSharingForNonOwnersStatus -eq $true) {
        $riskReasons += "Non-owners cannot share (good)"
    }
    
    $siteInfo = [PSCustomObject]@{
        # Site Info
        SiteUrl = $Site.Url
        SiteTitle = $Site.Title
        SiteTemplate = $Site.Template
        Owner = $Site.Owner
        
        # Sharing Settings
        SharingCapability = $Site.SharingCapability
        SharingCapabilityDescription = (Get-SharingCapabilityDescription -Capability $Site.SharingCapability)
        DefaultSharingLinkType = $Site.DefaultSharingLinkType
        DefaultLinkPermission = $Site.DefaultLinkPermission
        
        # Comparison
        IsMorePermissiveThanTenant = $isMorePermissive
        TenantSharingCapability = $script:TenantSharingCapability
        
        # Access Control
        DisableSharingForNonOwners = $Site.DisableSharingForNonOwnersStatus
        DisableCompanyWideSharingLinks = $Site.DisableCompanyWideSharingLinks
        
        # Labels & Classification
        SensitivityLabel = $Site.SensitivityLabel
        HasSensitivityLabel = $hasSensitivityLabel
        
        # Site Type
        IsSensitiveSite = $isSensitiveSite
        IsGroupConnected = ($siteTemplate -like "*GROUP#0*")
        
        # Storage
        StorageQuota = $Site.StorageQuota
        StorageUsed = $Site.StorageUsageCurrent
        
        # Risk Assessment
        RiskLevel = $riskLevel
        RiskReasons = ($riskReasons -join "; ")
        RiskReasonCount = $riskReasons.Count
    }
    
    return $siteInfo
}

# Get OneDrive sharing settings
function Get-OneDriveSharingAnalysis {
    Write-Host "`n[*] Analyzing OneDrive for Business sharing settings..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get OneDrive sites
        if (-not $script:SPOModuleAvailable) {
            Write-Host "[!] OneDrive analysis requires SharePoint Online Management Shell" -ForegroundColor Yellow
            return
        }
        
        $oneDriveSites = Get-SPOSite -IncludePersonalSite $true -Limit All -Filter "Url -like '-my.sharepoint.com/personal'" -ErrorAction Stop
        
        Write-Host "[+] Found $($oneDriveSites.Count) OneDrive site(s)" -ForegroundColor Green
        
        foreach ($site in $oneDriveSites) {
            Invoke-StealthDelay
            
            $riskLevel = "LOW"
            $riskReasons = @()
            
            # Assess sharing capability
            switch ($site.SharingCapability) {
                "ExternalUserAndGuestSharing" {
                    $riskLevel = "HIGH"
                    $riskReasons += "Anonymous links allowed"
                }
                "ExternalUserSharingOnly" {
                    $riskLevel = "MEDIUM"
                    $riskReasons += "External guest sharing enabled"
                }
            }
            
            # Check if more permissive than tenant
            $isMorePermissive = Test-SiteMorePermissive -TenantCapability $script:TenantSharingCapability -SiteCapability $site.SharingCapability
            if ($isMorePermissive) {
                $riskLevel = "CRITICAL"
                $riskReasons += "Sharing more permissive than tenant default"
            }
            
            # Extract user from OneDrive URL
            $owner = ""
            if ($site.Url -match '/personal/([^/]+)') {
                $owner = $matches[1] -replace '_', '@' -replace '_', '.'
            }
            
            $oneDriveInfo = [PSCustomObject]@{
                SiteUrl = $site.Url
                Owner = $owner
                SharingCapability = $site.SharingCapability
                SharingCapabilityDescription = (Get-SharingCapabilityDescription -Capability $site.SharingCapability)
                DefaultSharingLinkType = $site.DefaultSharingLinkType
                IsMorePermissiveThanTenant = $isMorePermissive
                StorageQuota = $site.StorageQuota
                StorageUsed = $site.StorageUsageCurrent
                RiskLevel = $riskLevel
                RiskReasons = ($riskReasons -join "; ")
            }
            
            # Apply filters
            if ($OnlyHighRisk -and $riskLevel -ne "HIGH" -and $riskLevel -ne "CRITICAL") {
                continue
            }
            
            if ($OnlyExternalSharing -and $site.SharingCapability -eq "Disabled") {
                continue
            }
            
            if ($OnlyAnonymousLinks -and $site.SharingCapability -ne "ExternalUserAndGuestSharing") {
                continue
            }
            
            if ($OnlyPermissiveOverrides -and -not $isMorePermissive) {
                continue
            }
            
            $script:OneDriveFindings += $oneDriveInfo
        }
        
        Write-Host "[+] OneDrive analysis complete" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing OneDrive: $_" -ForegroundColor Yellow
        Write-Host "[!] You may not have permission to view OneDrive sites" -ForegroundColor Yellow
    }
}

# Get sensitivity label settings
function Get-SensitivityLabelAnalysis {
    Write-Host "`n[*] Analyzing sensitivity label configuration..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Check for sites without sensitivity labels that have external sharing
        $sitesWithoutLabels = $script:SiteFindings | Where-Object { 
            -not $_.HasSensitivityLabel -and 
            $_.SharingCapability -ne "Disabled"
        }
        
        Write-Host "[+] Found $($sitesWithoutLabels.Count) site(s) without sensitivity labels that allow sharing" -ForegroundColor Yellow
        
        foreach ($site in $sitesWithoutLabels) {
            $riskLevel = "MEDIUM"
            $riskReasons = @("No sensitivity label applied")
            
            if ($site.SharingCapability -eq "ExternalUserAndGuestSharing") {
                $riskLevel = "HIGH"
                $riskReasons += "Anonymous sharing without label protection"
            }
            
            $labelInfo = [PSCustomObject]@{
                SiteUrl = $site.SiteUrl
                SiteTitle = $site.SiteTitle
                SharingCapability = $site.SharingCapability
                HasSensitivityLabel = $false
                SensitivityLabel = ""
                RiskLevel = $riskLevel
                RiskReasons = ($riskReasons -join "; ")
            }
            
            $script:SensitivityLabelFindings += $labelInfo
        }
        
        Write-Host "[+] Sensitivity label analysis complete" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing sensitivity labels: $_" -ForegroundColor Yellow
    }
}

# Main scanning function
function Start-SharePointSecurityScan {
    param(
        [string]$AdminUrl
    )
    
    Write-Host "`n[*] Starting SharePoint Online security scan..." -ForegroundColor Cyan
    
    try {
        # Get tenant-level settings first
        $tenantSettings = Get-TenantSharingSettings
        
        if (-not $tenantSettings) {
            Write-Host "[ERROR] Failed to retrieve tenant settings" -ForegroundColor Red
            return
        }
        
        # Get all sites
        Write-Host "`n[*] Retrieving SharePoint sites..." -ForegroundColor Cyan
        Invoke-StealthDelay
        
        $sites = @()
        
        if ($script:SPOModuleAvailable) {
            # Use SPO cmdlets (full functionality)
            $sites = Get-SPOSite -Limit All -ErrorAction Stop
        }
        else {
            # Fall back to direct REST API (bypasses all Graph SDK issues)
            Write-Host "[*] Using Microsoft Graph API for site enumeration..." -ForegroundColor Yellow
            
            try {
                # Get access token using Azure CLI or Az PowerShell (most reliable methods)
                $accessToken = $null
                
                # Try Azure CLI first (most reliable)
                try {
                    $cliOutput = az account get-access-token --resource "https://graph.microsoft.com" 2>$null
                    if ($cliOutput) {
                        $tokenResponse = $cliOutput | ConvertFrom-Json
                        if ($tokenResponse.accessToken) {
                            $accessToken = $tokenResponse.accessToken
                            Write-Host "[+] Using Azure CLI token" -ForegroundColor Green
                        }
                    }
                }
                catch {
                    Write-Host "[!] Azure CLI not available" -ForegroundColor Yellow
                }
                
                # Try Az PowerShell if CLI didn't work
                if (-not $accessToken) {
                    try {
                        # Az.Accounts 2.x returns Token as string, 3.x returns Token as SecureString
                        $azToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
                        
                        if ($azToken.Token -is [System.Security.SecureString]) {
                            # Convert SecureString to plain text (Az.Accounts 3.x)
                            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($azToken.Token)
                            $accessToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                        }
                        elseif ($azToken.Token) {
                            # Plain string token (Az.Accounts 2.x)
                            $accessToken = $azToken.Token
                        }
                        
                        if ($accessToken) {
                            Write-Host "[+] Using Az PowerShell token" -ForegroundColor Green
                        }
                    }
                    catch {
                        Write-Host "[!] Az PowerShell token failed: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
                
                
                if (-not $accessToken) {
                    throw "Could not obtain access token"
                }
                
                # Validate token format (should be a JWT with 3 parts)
                $tokenParts = $accessToken.Split('.')
                if ($tokenParts.Count -ne 3) {
                    Write-Host "[!] Token format invalid, trying device code flow..." -ForegroundColor Yellow
                    $accessToken = $null
                }
                
                # If token validation failed, use device code flow
                if (-not $accessToken) {
                    Write-Host "[*] Using device code authentication..." -ForegroundColor Cyan
                    
                    $clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph PowerShell
                    $tenantId = "common"
                    $scope = "https://graph.microsoft.com/Sites.Read.All https://graph.microsoft.com/Group.Read.All offline_access"
                    
                    $deviceCodeUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode"
                    $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
                    
                    $deviceCodeBody = @{
                        client_id = $clientId
                        scope = $scope
                    }
                    
                    $deviceCodeResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Body $deviceCodeBody -ContentType "application/x-www-form-urlencoded"
                    
                    Write-Host "`n$($deviceCodeResponse.message)" -ForegroundColor Yellow
                    
                    $tokenBody = @{
                        grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                        client_id = $clientId
                        device_code = $deviceCodeResponse.device_code
                    }
                    
                    $timeout = [DateTime]::Now.AddSeconds($deviceCodeResponse.expires_in)
                    $interval = $deviceCodeResponse.interval
                    
                    while ([DateTime]::Now -lt $timeout) {
                        Start-Sleep -Seconds $interval
                        try {
                            $tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                            $accessToken = $tokenResponse.access_token
                            Write-Host "[+] Authentication successful" -ForegroundColor Green
                            break
                        }
                        catch {
                            if ($_.Exception.Response.StatusCode -eq 400) {
                                # Still waiting for user
                                continue
                            }
                            throw
                        }
                    }
                }
                
                if (-not $accessToken) {
                    throw "Could not obtain access token after all methods"
                }
                
                # Now call Graph API with the token
                $headers = @{
                    "Authorization" = "Bearer $accessToken"
                    "Content-Type" = "application/json"
                }
                
                $allSites = @()
                
                # First, get the root site to find the tenant hostname
                Write-Host "[*] Getting root site..." -ForegroundColor Cyan
                $rootSite = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/root" -Headers $headers -ErrorAction Stop
                $hostname = $rootSite.siteCollection.hostname
                Write-Host "[+] SharePoint hostname: $hostname" -ForegroundColor Green
                
                # Search for all sites using search query (required to find sites)
                Write-Host "[*] Searching for all sites..." -ForegroundColor Cyan
                $uri = "https://graph.microsoft.com/v1.0/sites?search=*&`$top=999"
                
                try {
                    do {
                        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
                        
                        if ($response.value) {
                            $allSites += $response.value
                        }
                        
                        # Handle pagination
                        $uri = $response.'@odata.nextLink'
                    } while ($uri)
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    if ($errorMsg -match "403" -or $errorMsg -match "Forbidden" -or $errorMsg -match "accessDenied") {
                        Write-Host "[!] Token lacks Sites.Read.All permission - need to re-authenticate" -ForegroundColor Yellow
                        Write-Host "[*] Using device code flow for proper SharePoint permissions..." -ForegroundColor Cyan
                        
                        # Get new token with device code flow
                        $clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
                        $tenantId = "common"
                        $scope = "https://graph.microsoft.com/Sites.Read.All https://graph.microsoft.com/Group.Read.All offline_access"
                        
                        $deviceCodeUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode"
                        $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
                        
                        $deviceCodeBody = @{
                            client_id = $clientId
                            scope = $scope
                        }
                        
                        $deviceCodeResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Body $deviceCodeBody -ContentType "application/x-www-form-urlencoded"
                        
                        Write-Host "`n$($deviceCodeResponse.message)" -ForegroundColor Yellow
                        
                        $tokenBody = @{
                            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                            client_id = $clientId
                            device_code = $deviceCodeResponse.device_code
                        }
                        
                        $timeout = [DateTime]::Now.AddSeconds($deviceCodeResponse.expires_in)
                        $interval = $deviceCodeResponse.interval
                        
                        $newToken = $null
                        while ([DateTime]::Now -lt $timeout) {
                            Start-Sleep -Seconds $interval
                            try {
                                $tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                                $newToken = $tokenResponse.access_token
                                Write-Host "[+] Authentication successful" -ForegroundColor Green
                                break
                            }
                            catch {
                                if ($_.Exception.Response.StatusCode -eq 400) {
                                    continue
                                }
                                throw
                            }
                        }
                        
                        if (-not $newToken) {
                            throw "Failed to get token via device code flow"
                        }
                        
                        # Update headers with new token and retry
                        $headers = @{
                            "Authorization" = "Bearer $newToken"
                            "Content-Type" = "application/json"
                        }
                        
                        $uri = "https://graph.microsoft.com/v1.0/sites?search=*&`$top=999"
                        do {
                            $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
                            
                            if ($response.value) {
                                $allSites += $response.value
                            }
                            
                            $uri = $response.'@odata.nextLink'
                        } while ($uri)
                    }
                    else {
                        throw
                    }
                }
                
                # Also get sites from groups (Team sites)
                Write-Host "[*] Checking group sites..." -ForegroundColor Cyan
                try {
                    $groupsUri = "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c eq 'Unified')&`$select=id,displayName&`$top=999"
                    $groupsResponse = Invoke-RestMethod -Method GET -Uri $groupsUri -Headers $headers -ErrorAction SilentlyContinue
                    
                    if ($groupsResponse.value) {
                        foreach ($group in $groupsResponse.value) {
                            try {
                                $groupSiteUri = "https://graph.microsoft.com/v1.0/groups/$($group.id)/sites/root"
                                $groupSite = Invoke-RestMethod -Method GET -Uri $groupSiteUri -Headers $headers -ErrorAction SilentlyContinue
                                if ($groupSite -and ($allSites.id -notcontains $groupSite.id)) {
                                    $allSites += $groupSite
                                }
                            }
                            catch {
                                # Skip groups without sites
                            }
                        }
                    }
                }
                catch {
                    Write-Host "[!] Could not enumerate group sites: $($_.Exception.Message)" -ForegroundColor Yellow
                }
                
                Write-Host "[+] Retrieved $($allSites.Count) sites via Graph API" -ForegroundColor Green
                
                # Convert to compatible format
                foreach ($gs in $allSites) {
                    $sites += [PSCustomObject]@{
                        Url = $gs.webUrl
                        Title = $gs.displayName
                        Template = "Unknown"
                        Owner = ""
                        SharingCapability = "Unknown"
                        DefaultSharingLinkType = "Unknown"
                        DefaultLinkPermission = "Unknown"
                        DisableSharingForNonOwnersStatus = $false
                        DisableCompanyWideSharingLinks = $false
                        SensitivityLabel = ""
                        StorageQuota = 0
                        StorageUsageCurrent = 0
                    }
                }
            }
            catch {
                Write-Host "[ERROR] Graph API call failed: $($_.Exception.Message)" -ForegroundColor Red
                throw
            }
        }
        
        # Filter out OneDrive sites for separate analysis
        $spSites = $sites | Where-Object { $_.Url -notlike "*-my.sharepoint.com/personal*" -and $_.Url -notlike "*-my.sharepoint.com" }
        
        Write-Host "[+] Found $($spSites.Count) SharePoint site(s)" -ForegroundColor Green
        
        $script:TotalSitesScanned = $spSites.Count
        $progressCounter = 0
        
        foreach ($site in $spSites) {
            $progressCounter++
            
            # Progress indicator
            if ($progressCounter % 10 -eq 0 -or $progressCounter -eq $spSites.Count) {
                $percentComplete = [math]::Round(($progressCounter / $spSites.Count) * 100, 1)
                Write-Host "`r[*] Progress: $progressCounter/$($spSites.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
            }
            
            try {
                Invoke-StealthDelay
                
                # Analyze site
                $siteInfo = Get-SiteSharingAnalysis -Site $site
                
                # Apply filters
                if ($OnlyHighRisk -and $siteInfo.RiskLevel -ne "HIGH" -and $siteInfo.RiskLevel -ne "CRITICAL") {
                    continue
                }
                
                if ($OnlyExternalSharing -and $site.SharingCapability -eq "Disabled") {
                    continue
                }
                
                if ($OnlyAnonymousLinks -and $site.SharingCapability -ne "ExternalUserAndGuestSharing") {
                    continue
                }
                
                if ($OnlyPermissiveOverrides -and -not $siteInfo.IsMorePermissiveThanTenant) {
                    continue
                }
                
                $script:SiteFindings += $siteInfo
            }
            catch {
                Write-Host "`n[!] Error processing site $($site.Url): $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n[+] Site scan complete!" -ForegroundColor Green
        
        # Additional analyses if requested
        if ($IncludeOneDrive) {
            Get-OneDriveSharingAnalysis
        }
        
        if ($IncludeSensitivityLabels) {
            Get-SensitivityLabelAnalysis
        }
    }
    catch {
        Write-Host "`n[ERROR] Failed to scan sites: $_" -ForegroundColor Red
    }
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 160) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - SHAREPOINT ONLINE SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 160) -ForegroundColor Cyan
    
    # === TENANT SUMMARY ===
    if ($script:TenantFindings) {
        Write-Host "`n[TENANT SHARING SETTINGS]" -ForegroundColor Yellow
        Write-Host ("-" * 160) -ForegroundColor Cyan
        
        $riskColor = switch ($script:TenantFindings.RiskLevel) {
            "CRITICAL" { "Red" }
            "HIGH" { "Yellow" }
            "MEDIUM" { "Cyan" }
            default { "Green" }
        }
        
        Write-Host "  Sharing Capability: " -NoNewline -ForegroundColor White
        Write-Host $script:TenantFindings.SharingCapabilityDescription -ForegroundColor $riskColor
        
        Write-Host "  Default Link Type: " -NoNewline -ForegroundColor White
        Write-Host (Get-DefaultLinkTypeDescription -LinkType $script:TenantFindings.DefaultSharingLinkType) -ForegroundColor Gray
        
        Write-Host "  Default Link Permission: " -NoNewline -ForegroundColor White
        Write-Host $script:TenantFindings.DefaultLinkPermission -ForegroundColor Gray
        
        Write-Host "  Anonymous Link Expiration: " -NoNewline -ForegroundColor White
        if ($script:TenantFindings.RequireAnonymousLinksExpireInDays -gt 0) {
            Write-Host "$($script:TenantFindings.RequireAnonymousLinksExpireInDays) days" -ForegroundColor Green
        }
        else {
            Write-Host "Never expires" -ForegroundColor Yellow
        }
        
        Write-Host "  OneDrive Sharing: " -NoNewline -ForegroundColor White
        Write-Host $script:TenantFindings.OneDriveSharingCapabilityDescription -ForegroundColor Gray
        
        Write-Host "  Risk Level: " -NoNewline -ForegroundColor White
        Write-Host $script:TenantFindings.RiskLevel -ForegroundColor $riskColor
        
        if ($script:TenantFindings.RiskReasons) {
            Write-Host "  Risk Reasons: $($script:TenantFindings.RiskReasons)" -ForegroundColor DarkGray
        }
    }
    
    # === SITE SUMMARY ===
    if ($script:SiteFindings.Count -gt 0) {
        Write-Host "`n[SHAREPOINT SITES]" -ForegroundColor Yellow
        Write-Host ("-" * 160) -ForegroundColor Cyan
        
        # Sort by risk level
        $sortedSites = $script:SiteFindings | Sort-Object { 
            switch ($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }
        
        $matrixData = $sortedSites | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='Site Title';Expression={$_.SiteTitle}},
            @{Name='Sharing';Expression={$_.SharingCapabilityDescription}},
            @{Name='Override';Expression={if($_.IsMorePermissiveThanTenant){'YES'}else{'-'}}},
            @{Name='Anonymous';Expression={if($_.SharingCapability -eq 'ExternalUserAndGuestSharing'){'YES'}else{'-'}}},
            @{Name='Label';Expression={if($_.HasSensitivityLabel){'Yes'}else{'No'}}},
            @{Name='Group';Expression={if($_.IsGroupConnected){'Yes'}else{'-'}}},
            @{Name='URL';Expression={$_.SiteUrl}}
        
        # Use Format-List for detailed view to avoid truncation
        Write-Host "`nDetailed Site List:" -ForegroundColor Cyan
        foreach ($site in $sortedSites) {
            $color = switch ($site.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                default { "Green" }
            }
            Write-Host "`n  [$($site.RiskLevel)] $($site.SiteTitle)" -ForegroundColor $color
            Write-Host "      URL: $($site.SiteUrl)" -ForegroundColor Gray
            Write-Host "      Sharing: $($site.SharingCapabilityDescription) | Label: $(if($site.HasSensitivityLabel){'Yes'}else{'No'}) | Group: $(if($site.IsGroupConnected){'Yes'}else{'No'})" -ForegroundColor Gray
            if ($site.RiskReasons) {
                Write-Host "      Reasons: $($site.RiskReasons)" -ForegroundColor Gray
            }
        }
        
        Write-Host "`n`nSummary Table:" -ForegroundColor Cyan
        $matrixData | Format-Table -AutoSize -Wrap | Out-String | ForEach-Object {
            $lines = $_ -split "`n"
            foreach ($line in $lines) {
                if ($line -match '^\s*CRITICAL\s+') {
                    Write-Host $line -ForegroundColor Red
                }
                elseif ($line -match '^\s*HIGH\s+') {
                    Write-Host $line -ForegroundColor Yellow
                }
                elseif ($line -match '^\s*MEDIUM\s+') {
                    Write-Host $line -ForegroundColor Cyan
                }
                elseif ($line -match '^\s*LOW\s+') {
                    Write-Host $line -ForegroundColor Green
                }
                elseif ($line -match '^-+\s+-+' -or $line -match '^Risk\s+') {
                    Write-Host $line -ForegroundColor Cyan
                }
                else {
                    Write-Host $line -ForegroundColor White
                }
            }
        }
    }
    else {
        Write-Host "`n[SHAREPOINT SITES]" -ForegroundColor Yellow
        Write-Host "[+] No site findings matching criteria" -ForegroundColor Green
    }
    
    # === ONEDRIVE SUMMARY ===
    if ($script:OneDriveFindings.Count -gt 0) {
        Write-Host "`n[ONEDRIVE FOR BUSINESS]" -ForegroundColor Yellow
        Write-Host ("-" * 160) -ForegroundColor Cyan
        
        $sortedOneDrive = $script:OneDriveFindings | Sort-Object { 
            switch ($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        } | Select-Object -First 20
        
        $oneDriveMatrix = $sortedOneDrive | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='Owner';Expression={if($_.Owner.Length -gt 35){$_.Owner.Substring(0,32)+"..."}else{$_.Owner}}},
            @{Name='Sharing';Expression={$_.SharingCapabilityDescription}},
            @{Name='Override';Expression={if($_.IsMorePermissiveThanTenant){'YES'}else{'-'}}},
            @{Name='Storage Used';Expression={"$([math]::Round($_.StorageUsed/1024, 1)) GB"}}
        
        $oneDriveMatrix | Format-Table -AutoSize | Out-String | ForEach-Object {
            $lines = $_ -split "`n"
            foreach ($line in $lines) {
                if ($line -match '^\s*CRITICAL\s+') {
                    Write-Host $line -ForegroundColor Red
                }
                elseif ($line -match '^\s*HIGH\s+') {
                    Write-Host $line -ForegroundColor Yellow
                }
                else {
                    Write-Host $line -ForegroundColor White
                }
            }
        }
        
        if ($script:OneDriveFindings.Count -gt 20) {
            Write-Host "  ... and $($script:OneDriveFindings.Count - 20) more OneDrive site(s)" -ForegroundColor DarkGray
        }
    }
    
    # === SENSITIVITY LABELS ===
    if ($script:SensitivityLabelFindings.Count -gt 0) {
        Write-Host "`n[SITES WITHOUT SENSITIVITY LABELS]" -ForegroundColor Yellow
        Write-Host ("-" * 160) -ForegroundColor Cyan
        
        $labelMatrix = $script:SensitivityLabelFindings | Sort-Object { 
            switch ($_.RiskLevel) {
                "HIGH" { 0 }
                "MEDIUM" { 1 }
                default { 2 }
            }
        } | Select-Object -First 15 | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='Site';Expression={if($_.SiteTitle.Length -gt 30){$_.SiteTitle.Substring(0,27)+"..."}else{$_.SiteTitle}}},
            @{Name='Sharing';Expression={$_.SharingCapability}},
            @{Name='Reasons';Expression={$_.RiskReasons}}
        
        $labelMatrix | Format-Table -AutoSize | Out-String | ForEach-Object {
            $lines = $_ -split "`n"
            foreach ($line in $lines) {
                if ($line -match '^\s*HIGH\s+') {
                    Write-Host $line -ForegroundColor Yellow
                }
                else {
                    Write-Host $line -ForegroundColor White
                }
            }
        }
    }
    
    Write-Host "`n" + ("=" * 160) -ForegroundColor Cyan
    
    # === SUMMARY SECTION ===
    Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
    
    Write-Host "Total sites scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalSitesScanned -ForegroundColor Yellow
    
    Write-Host "Sites with findings: " -NoNewline -ForegroundColor White
    Write-Host $script:SiteFindings.Count -ForegroundColor $(if($script:SiteFindings.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:SiteFindings.Count -gt 0) {
        $criticalSites = ($script:SiteFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highSites = ($script:SiteFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumSites = ($script:SiteFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalSites -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highSites -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumSites -ForegroundColor Cyan
    }
    
    # Sharing summary
    $anonymousSites = ($script:SiteFindings | Where-Object { $_.SharingCapability -eq "ExternalUserAndGuestSharing" }).Count
    $permissiveOverrides = ($script:SiteFindings | Where-Object { $_.IsMorePermissiveThanTenant }).Count
    $noLabels = ($script:SiteFindings | Where-Object { -not $_.HasSensitivityLabel }).Count
    
    Write-Host "`n[SHARING ANALYSIS]" -ForegroundColor Cyan
    Write-Host "  Sites allowing anonymous links: " -NoNewline -ForegroundColor White
    Write-Host $anonymousSites -ForegroundColor $(if($anonymousSites -gt 0){"Red"}else{"Green"})
    Write-Host "  Sites with permissive overrides: " -NoNewline -ForegroundColor White
    Write-Host $permissiveOverrides -ForegroundColor $(if($permissiveOverrides -gt 0){"Red"}else{"Green"})
    Write-Host "  Sites without sensitivity labels: " -NoNewline -ForegroundColor White
    Write-Host $noLabels -ForegroundColor $(if($noLabels -gt 0){"Yellow"}else{"Green"})
    
    if ($script:OneDriveFindings.Count -gt 0) {
        $oneDriveAnonymous = ($script:OneDriveFindings | Where-Object { $_.SharingCapability -eq "ExternalUserAndGuestSharing" }).Count
        
        Write-Host "`n[ONEDRIVE ANALYSIS]" -ForegroundColor Cyan
        Write-Host "  OneDrive sites analyzed: " -NoNewline -ForegroundColor White
        Write-Host $script:OneDriveFindings.Count -ForegroundColor Yellow
        Write-Host "  OneDrive with anonymous links: " -NoNewline -ForegroundColor White
        Write-Host $oneDriveAnonymous -ForegroundColor $(if($oneDriveAnonymous -gt 0){"Red"}else{"Green"})
    }
    
    Write-Host ""
}

# Display standard results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    # Tenant settings
    if ($script:TenantFindings) {
        Write-Host "`n[TENANT SHARING SETTINGS]" -ForegroundColor Yellow
        
        $riskColor = switch ($script:TenantFindings.RiskLevel) {
            "CRITICAL" { "Red" }
            "HIGH" { "Yellow" }
            "MEDIUM" { "Cyan" }
            default { "Green" }
        }
        
        Write-Host "  Sharing Capability: $($script:TenantFindings.SharingCapabilityDescription)" -ForegroundColor Gray
        Write-Host "  Default Link Type: $(Get-DefaultLinkTypeDescription -LinkType $script:TenantFindings.DefaultSharingLinkType)" -ForegroundColor Gray
        Write-Host "  OneDrive Sharing: $($script:TenantFindings.OneDriveSharingCapabilityDescription)" -ForegroundColor Gray
        Write-Host "  Risk Level: " -NoNewline -ForegroundColor White
        Write-Host $script:TenantFindings.RiskLevel -ForegroundColor $riskColor
    }
    
    Write-Host "`nTotal sites scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalSitesScanned -ForegroundColor Yellow
    
    Write-Host "Sites with findings: " -NoNewline -ForegroundColor White
    Write-Host $script:SiteFindings.Count -ForegroundColor $(if($script:SiteFindings.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:SiteFindings.Count -gt 0) {
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "SITE DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        # Sort by risk level
        $sortedSites = $script:SiteFindings | Sort-Object { 
            switch ($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }
        
        foreach ($site in ($sortedSites | Select-Object -First 30)) {
            $riskColor = switch ($site.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($site.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host $site.SiteTitle -ForegroundColor White
            
            Write-Host "  URL: $($site.SiteUrl)" -ForegroundColor Gray
            Write-Host "  Sharing: $($site.SharingCapabilityDescription)" -ForegroundColor Gray
            
            if ($site.IsMorePermissiveThanTenant) {
                Write-Host "  [!] MORE PERMISSIVE than tenant default" -ForegroundColor Red
            }
            
            if (-not $site.HasSensitivityLabel) {
                Write-Host "  [!] No sensitivity label applied" -ForegroundColor Yellow
            }
            
            if ($site.RiskReasons) {
                Write-Host "  Risk Reasons: $($site.RiskReasons)" -ForegroundColor DarkGray
            }
        }
        
        if ($script:SiteFindings.Count -gt 30) {
            Write-Host "`n  ... and $($script:SiteFindings.Count - 30) more site(s)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
}

# Export results
function Export-Results {
    param(
        [string]$Path
    )
    
    if (-not $Path) {
        return
    }
    
    $totalFindings = $script:SiteFindings.Count + $script:OneDriveFindings.Count
    
    if ($totalFindings -eq 0 -and $null -eq $script:TenantFindings) {
        Write-Host "`n[*] No results to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        $basePath = [System.IO.Path]::GetDirectoryName($Path)
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        
        # Export tenant findings
        if ($script:TenantFindings) {
            $tenantPath = if ($basePath) { Join-Path $basePath "$baseName-tenant$extension" } else { "$baseName-tenant$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:TenantFindings | Export-Csv -Path $tenantPath -NoTypeInformation -Encoding UTF8
                    Write-Host "`n[+] Tenant settings exported to CSV: $tenantPath" -ForegroundColor Green
                }
                ".json" {
                    $script:TenantFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $tenantPath -Encoding UTF8
                    Write-Host "`n[+] Tenant settings exported to JSON: $tenantPath" -ForegroundColor Green
                }
                default {
                    $csvPath = [System.IO.Path]::ChangeExtension($tenantPath, ".csv")
                    $script:TenantFindings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                    Write-Host "`n[+] Tenant settings exported to CSV: $csvPath" -ForegroundColor Green
                }
            }
        }
        
        # Export site findings
        if ($script:SiteFindings.Count -gt 0) {
            $sitesPath = if ($basePath) { Join-Path $basePath "$baseName-sites$extension" } else { "$baseName-sites$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:SiteFindings | Export-Csv -Path $sitesPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Site findings exported to CSV: $sitesPath" -ForegroundColor Green
                }
                ".json" {
                    $script:SiteFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $sitesPath -Encoding UTF8
                    Write-Host "[+] Site findings exported to JSON: $sitesPath" -ForegroundColor Green
                }
                default {
                    $csvPath = [System.IO.Path]::ChangeExtension($sitesPath, ".csv")
                    $script:SiteFindings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Site findings exported to CSV: $csvPath" -ForegroundColor Green
                }
            }
        }
        
        # Export OneDrive findings
        if ($script:OneDriveFindings.Count -gt 0) {
            $oneDrivePath = if ($basePath) { Join-Path $basePath "$baseName-onedrive$extension" } else { "$baseName-onedrive$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:OneDriveFindings | Export-Csv -Path $oneDrivePath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] OneDrive findings exported to CSV: $oneDrivePath" -ForegroundColor Green
                }
                ".json" {
                    $script:OneDriveFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $oneDrivePath -Encoding UTF8
                    Write-Host "[+] OneDrive findings exported to JSON: $oneDrivePath" -ForegroundColor Green
                }
            }
        }
        
        # Export sensitivity label findings
        if ($script:SensitivityLabelFindings.Count -gt 0) {
            $labelPath = if ($basePath) { Join-Path $basePath "$baseName-labels$extension" } else { "$baseName-labels$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:SensitivityLabelFindings | Export-Csv -Path $labelPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Sensitivity label findings exported to CSV: $labelPath" -ForegroundColor Green
                }
                ".json" {
                    $script:SensitivityLabelFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $labelPath -Encoding UTF8
                    Write-Host "[+] Sensitivity label findings exported to JSON: $labelPath" -ForegroundColor Green
                }
            }
        }
    }
    catch {
        Write-Host "`n[ERROR] Failed to export results: $_" -ForegroundColor Red
    }
}

# Cleanup
function Invoke-Cleanup {
    Write-Host "`n[*] Cleaning up..." -ForegroundColor Cyan
    try {
        # Disconnect from SharePoint Online
        if ($script:SPOModuleAvailable) {
            Disconnect-SPOService -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Host "[+] Disconnected from SharePoint Online" -ForegroundColor Green
        # Disconnect from Microsoft Graph if connected
        try {
            $mgContext = Get-MgContext -ErrorAction SilentlyContinue
            if ($mgContext) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                Write-Host "[+] Disconnected from Microsoft Graph" -ForegroundColor Green
            }
        } catch { }
        # Disconnect from Azure PowerShell if connected
        if (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue) {
            if (Get-AzContext -ErrorAction SilentlyContinue) {
                Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
                Write-Host "[+] Disconnected from Azure PowerShell" -ForegroundColor Green
            }
        }
        # Clear Azure CLI token cache (logout)
        try {
            $azCliAccount = az account show 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($azCliAccount) {
                az logout 2>$null
                Write-Host "[+] Disconnected from Azure CLI" -ForegroundColor Green
            }
        } catch { }
    }
    catch {
        # Silent cleanup
    }
}

# Main execution
function Main {
    try {
        Show-Banner
        
        # Initialize stealth
        Initialize-StealthConfig
        
        # Check required modules
        if (-not (Test-RequiredModules)) {
            exit 1
        }
        
        # Initialize and import modules
        if (-not (Initialize-Modules)) {
            Write-Host "`n[ERROR] Failed to initialize modules. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Connect to Microsoft Graph first (for authentication)
        if (-not (Connect-GraphService)) {
            Write-Host "`n[ERROR] Failed to connect to Microsoft Graph. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Get or detect Admin URL
        $spAdminUrl = Get-SharePointAdminUrl -ProvidedUrl $AdminUrl
        if (-not $spAdminUrl) {
            Write-Host "`n[ERROR] SharePoint Admin URL is required. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Connect to SharePoint Online (using existing Graph auth context)
        if (-not (Connect-SharePointService -AdminUrl $spAdminUrl)) {
            Write-Host "`n[ERROR] Connection failed. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Start scan
        Start-SharePointSecurityScan -AdminUrl $spAdminUrl
        
        # Show results
        if ($Matrix) {
            Show-MatrixResults
        }
        else {
            Show-Results
        }
        
        # Export if requested
        if ($ExportPath) {
            Export-Results -Path $ExportPath
        }
        
        Write-Host "`n[*] SharePoint security check completed successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "`n[ERROR] An unexpected error occurred: $_" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
    }
    finally {
        Invoke-Cleanup
    }
}

# Run the script
Main
