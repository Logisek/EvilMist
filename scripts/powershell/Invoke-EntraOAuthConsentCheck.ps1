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
    Detects illicit OAuth consent grants and risky OAuth app permissions in Azure Entra ID.

.DESCRIPTION
    This script performs a comprehensive audit of OAuth consent grants to identify
    potential security risks including:
    - Enumerates all OAuth2PermissionGrants (delegated permissions)
    - Identifies admin consent vs user consent grants
    - Detects high-risk scopes (Mail.ReadWrite, Files.ReadWrite.All, User.ReadWrite.All)
    - Finds unused/stale consent grants (apps not used in 90+ days)
    - Identifies third-party apps with dangerous permissions
    - Cross-references with sign-in activity to detect dormant apps
    - Risk assessment: CRITICAL (admin consent + dangerous perms), HIGH (user consent + dangerous perms)
    
    OAuth consent grant attacks are a major attack vector used in phishing campaigns
    and for establishing persistent access to organizational data.
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.

.PARAMETER ExportPath
    Optional path to export results (CSV or JSON based on extension).

.PARAMETER TenantId
    Optional Tenant ID. If not specified, uses the user's home tenant.

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

.PARAMETER StaleDays
    Number of days without sign-in activity to consider a consent grant stale. Default: 90

.PARAMETER OnlyHighRisk
    Show only high-risk and critical consent grants.

.PARAMETER OnlyThirdParty
    Show only third-party (non-Microsoft) applications.

.PARAMETER OnlyStale
    Show only stale/unused consent grants.

.PARAMETER OnlyAdminConsent
    Show only admin consent (tenant-wide) grants.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraOAuthConsentCheck.ps1
    # Enumerate all OAuth consent grants and analyze security posture

.EXAMPLE
    .\Invoke-EntraOAuthConsentCheck.ps1 -ExportPath "consent-grants.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraOAuthConsentCheck.ps1 -OnlyHighRisk -Matrix
    # Display only high-risk consent grants in matrix format

.EXAMPLE
    .\Invoke-EntraOAuthConsentCheck.ps1 -OnlyThirdParty -OnlyAdminConsent
    # Show only third-party apps with admin consent

.EXAMPLE
    .\Invoke-EntraOAuthConsentCheck.ps1 -StaleDays 60 -OnlyStale
    # Show consent grants not used in the last 60 days

.EXAMPLE
    .\Invoke-EntraOAuthConsentCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

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
    [ValidateRange(1, 365)]
    [int]$StaleDays = 90,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyHighRisk,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyThirdParty,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyStale,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyAdminConsent,

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

# Dangerous permissions - highly sensitive scopes that can lead to data exfiltration or compromise
$script:DangerousPermissions = @(
    # Mail access - data exfiltration risk
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Read.Shared",
    "Mail.ReadWrite.Shared",
    "Mail.Send",
    "Mail.Send.Shared",
    "MailboxSettings.ReadWrite",
    
    # File access - data exfiltration risk
    "Files.Read.All",
    "Files.ReadWrite.All",
    "Sites.Read.All",
    "Sites.ReadWrite.All",
    "Sites.FullControl.All",
    
    # User/Directory access - identity theft/manipulation
    "User.ReadWrite.All",
    "User.Read.All",
    "Directory.Read.All",
    "Directory.ReadWrite.All",
    "Directory.AccessAsUser.All",
    
    # Contacts - social engineering data
    "Contacts.Read",
    "Contacts.ReadWrite",
    "Contacts.Read.Shared",
    
    # Calendar - reconnaissance
    "Calendars.Read",
    "Calendars.ReadWrite",
    "Calendars.Read.Shared",
    
    # Teams/Chat - data exfiltration
    "Chat.Read",
    "Chat.ReadWrite",
    "ChannelMessage.Read.All",
    "Team.ReadBasic.All",
    
    # Notes - sensitive data
    "Notes.Read.All",
    "Notes.ReadWrite.All"
)

# Critical permissions - can lead to full compromise
$script:CriticalPermissions = @(
    "Mail.ReadWrite",
    "Mail.ReadWrite.All",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "Sites.FullControl.All",
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Directory.AccessAsUser.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureAD"
)

# Known Microsoft tenant IDs and app publishers
$script:MicrosoftTenantIds = @(
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",  # Microsoft Services
    "72f988bf-86f1-41af-91ab-2d7cd011db47"   # Microsoft Corp
)

# Required scopes for OAuth consent checking
$script:RequiredScopes = @(
    "Directory.Read.All",
    "Application.Read.All",
    "DelegatedPermissionGrant.Read.All",
    "User.Read.All",
    "AuditLog.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Directory.Read.All",
    "Application.Read.All",
    "DelegatedPermissionGrant.Read.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:ConsentGrants = @()
$script:TotalGrantsScanned = 0
$script:ServicePrincipalCache = @{}
$script:UserCache = @{}
$script:ResourceCache = @{}
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
    Write-Host "    Entra ID OAuth Consent Check - Illicit Consent Grant Detection" -ForegroundColor Yellow
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

# Check if Microsoft.Graph module is installed
function Test-GraphModule {
    Write-Host "[*] Checking Microsoft.Graph PowerShell module..." -ForegroundColor Cyan
    
    $modules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Identity.SignIns"
    )
    
    $missingModules = @()
    foreach ($module in $modules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Host "[!] Missing required modules:" -ForegroundColor Yellow
        $missingModules | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
        Write-Host "`n[*] Installing missing modules automatically..." -ForegroundColor Cyan
        
        # Check if running as administrator for AllUsers scope
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $scope = if ($isAdmin) { "AllUsers" } else { "CurrentUser" }
        
        foreach ($module in $missingModules) {
            Write-Host "[*] Installing $module (Scope: $scope)..." -ForegroundColor Cyan
            try {
                # Set PSGallery as trusted if not already
                $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
                if ($psGallery -and $psGallery.InstallationPolicy -ne 'Trusted') {
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
                }
                
                Install-Module -Name $module -Scope $scope -AllowClobber -Force -ErrorAction Stop
                Write-Host "[+] Successfully installed $module" -ForegroundColor Green
            }
            catch {
                Write-Host "[ERROR] Failed to install $module : $_" -ForegroundColor Red
                Write-Host "[*] Try manually: Install-Module $module -Scope CurrentUser -Force" -ForegroundColor Yellow
                return $false
            }
        }
        Write-Host "[+] All modules installed successfully" -ForegroundColor Green
    }
    
    Write-Host "[+] All required modules are installed" -ForegroundColor Green
    return $true
}

# Initialize and import Graph modules properly
function Initialize-GraphModules {
    Write-Host "[*] Initializing Microsoft Graph modules..." -ForegroundColor Cyan
    
    try {
        # Remove any loaded Graph modules to avoid version conflicts
        $loadedModules = Get-Module Microsoft.Graph.* 
        if ($loadedModules) {
            Write-Host "[*] Cleaning up loaded Graph modules..." -ForegroundColor Yellow
            $loadedModules | ForEach-Object {
                Remove-Module $_.Name -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Import modules in the correct order (Authentication first)
        Write-Host "[*] Importing Microsoft.Graph.Authentication..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Authentication -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Microsoft.Graph.Applications..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Applications -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Microsoft.Graph.Users..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Users -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Microsoft.Graph.Identity.SignIns..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Identity.SignIns -Force -ErrorAction Stop
        
        Write-Host "[+] Modules imported successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to import modules: $_" -ForegroundColor Red
        Write-Host "[*] Try running: Update-Module Microsoft.Graph -Force" -ForegroundColor Yellow
        return $false
    }
}

# Try to get token from Azure CLI
function Get-AzCliToken {
    try {
        Write-Host "[*] Attempting to use Azure CLI token..." -ForegroundColor Cyan
        $azToken = az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv 2>$null
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
    try {
        Write-Host "[*] Attempting to use Azure PowerShell token..." -ForegroundColor Cyan
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($azContext) {
            $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction SilentlyContinue).Token
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

# Authenticate to Microsoft Graph
function Connect-GraphService {
    Write-Host "`n[*] Authenticating to Microsoft Graph..." -ForegroundColor Cyan
    
    # Try Azure CLI token if requested
    if ($UseAzCliToken) {
        $token = Get-AzCliToken
        if ($token) {
            try {
                Connect-MgGraph -AccessToken (ConvertTo-SecureString $token -AsPlainText -Force) -NoWelcome
                $script:AccessToken = $token
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
        $token = Get-AzPowerShellToken
        if ($token) {
            try {
                Connect-MgGraph -AccessToken (ConvertTo-SecureString $token -AsPlainText -Force) -NoWelcome
                $script:AccessToken = $token
                Write-Host "[+] Connected using Azure PowerShell token" -ForegroundColor Green
                return $true
            }
            catch {
                Write-Host "[!] Failed to connect with Azure PowerShell token: $_" -ForegroundColor Yellow
            }
        }
    }
    
    # Interactive authentication with required scopes
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
        $script:CurrentScopes = $context.Scopes
        
        Write-Host "[+] Connected to Microsoft Graph" -ForegroundColor Green
        Write-Host "[+] Tenant: $($context.TenantId)" -ForegroundColor Green
        Write-Host "[+] Account: $($context.Account)" -ForegroundColor Green
        Write-Host "[+] Scopes: $($context.Scopes -join ', ')" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Host "[!] Failed to connect to Microsoft Graph: $_" -ForegroundColor Red
        
        # Try with fallback scopes
        try {
            Write-Host "[*] Trying with reduced scopes..." -ForegroundColor Yellow
            $connectParams['Scopes'] = $script:FallbackScopes
            Connect-MgGraph @connectParams -ErrorAction Stop
            
            $context = Get-MgContext
            $script:CurrentScopes = $context.Scopes
            
            Write-Host "[+] Connected with reduced permissions" -ForegroundColor Green
            Write-Host "[!] Some features may be limited" -ForegroundColor Yellow
            
            return $true
        }
        catch {
            Write-Host "[ERROR] Authentication failed: $_" -ForegroundColor Red
            return $false
        }
    }
}

# Get cached or fetch service principal
function Get-CachedServicePrincipal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId
    )
    
    if ($script:ServicePrincipalCache.ContainsKey($ServicePrincipalId)) {
        return $script:ServicePrincipalCache[$ServicePrincipalId]
    }
    
    try {
        Invoke-StealthDelay
        $sp = Get-MgServicePrincipal -ServicePrincipalId $ServicePrincipalId -Property Id,AppId,DisplayName,AppOwnerOrganizationId,ServicePrincipalType,PublisherName,VerifiedPublisher -ErrorAction Stop
        $script:ServicePrincipalCache[$ServicePrincipalId] = $sp
        return $sp
    }
    catch {
        return $null
    }
}

# Get cached or fetch user
function Get-CachedUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId
    )
    
    if ($script:UserCache.ContainsKey($UserId)) {
        return $script:UserCache[$UserId]
    }
    
    try {
        Invoke-StealthDelay
        $user = Get-MgUser -UserId $UserId -Property Id,DisplayName,UserPrincipalName,SignInActivity -ErrorAction Stop
        $script:UserCache[$UserId] = $user
        return $user
    }
    catch {
        return $null
    }
}

# Get cached or fetch resource service principal (the API being accessed)
function Get-CachedResourceServicePrincipal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId
    )
    
    if ($script:ResourceCache.ContainsKey($ResourceId)) {
        return $script:ResourceCache[$ResourceId]
    }
    
    try {
        Invoke-StealthDelay
        $resource = Get-MgServicePrincipal -ServicePrincipalId $ResourceId -Property Id,AppId,DisplayName,OAuth2PermissionScopes -ErrorAction Stop
        $script:ResourceCache[$ResourceId] = $resource
        return $resource
    }
    catch {
        return $null
    }
}

# Check if application is from Microsoft
function Test-IsMicrosoftApp {
    param(
        [Parameter(Mandatory = $true)]
        $ServicePrincipal
    )
    
    if (-not $ServicePrincipal) {
        return $false
    }
    
    # Check publisher name
    $publisherName = $ServicePrincipal.PublisherName
    if ($publisherName -and ($publisherName -like "*Microsoft*" -or $publisherName -like "*Azure*")) {
        return $true
    }
    
    # Check verified publisher
    if ($ServicePrincipal.VerifiedPublisher -and $ServicePrincipal.VerifiedPublisher.DisplayName -like "*Microsoft*") {
        return $true
    }
    
    # Check app owner organization
    $appOwnerTenantId = $ServicePrincipal.AppOwnerOrganizationId
    if ($appOwnerTenantId -and $script:MicrosoftTenantIds -contains $appOwnerTenantId) {
        return $true
    }
    
    # Check for common Microsoft app patterns
    $displayName = $ServicePrincipal.DisplayName
    if ($displayName) {
        $microsoftPatterns = @(
            "Microsoft*",
            "Office 365*",
            "Azure*",
            "Windows*",
            "Dynamics*",
            "Power*",
            "SharePoint*",
            "Exchange*",
            "OneDrive*",
            "Teams*",
            "Outlook*",
            "Intune*",
            "Defender*",
            "Graph*"
        )
        
        foreach ($pattern in $microsoftPatterns) {
            if ($displayName -like $pattern) {
                return $true
            }
        }
    }
    
    return $false
}

# Resolve permission scope IDs to names
function Resolve-PermissionScopes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Scope,
        
        [Parameter(Mandatory = $false)]
        $ResourceServicePrincipal
    )
    
    # Scopes are space-separated permission strings
    $permissions = $Scope -split '\s+'
    
    $resolvedPermissions = @()
    $hasDangerous = $false
    $hasCritical = $false
    
    foreach ($perm in $permissions) {
        if ([string]::IsNullOrWhiteSpace($perm)) {
            continue
        }
        
        $resolvedPermissions += $perm
        
        # Check for dangerous permissions
        foreach ($dangerous in $script:DangerousPermissions) {
            if ($perm -eq $dangerous -or $perm -like "*$dangerous*") {
                $hasDangerous = $true
                break
            }
        }
        
        # Check for critical permissions
        foreach ($critical in $script:CriticalPermissions) {
            if ($perm -eq $critical -or $perm -like "*$critical*") {
                $hasCritical = $true
                break
            }
        }
    }
    
    return @{
        Permissions = $resolvedPermissions
        PermissionCount = $resolvedPermissions.Count
        HasDangerous = $hasDangerous
        HasCritical = $hasCritical
    }
}

# Get last sign-in for the consenting principal
function Get-ConsentPrincipalSignIn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId,
        
        [Parameter(Mandatory = $true)]
        [string]$ConsentType
    )
    
    # For user consent, check user's last sign-in
    if ($ConsentType -eq "Principal") {
        $user = Get-CachedUser -UserId $PrincipalId
        if ($user -and $user.SignInActivity) {
            $lastSignIn = $user.SignInActivity.LastSignInDateTime
            if ($lastSignIn) {
                $daysAgo = ([DateTime]::Now - [DateTime]$lastSignIn).Days
                return @{
                    LastSignIn = $lastSignIn
                    DaysAgo = $daysAgo
                    IsStale = $daysAgo -gt $StaleDays
                }
            }
        }
    }
    
    return @{
        LastSignIn = $null
        DaysAgo = -1
        IsStale = $false  # Can't determine staleness without sign-in data
    }
}

# Get service principal sign-in activity
function Get-ServicePrincipalSignInActivity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId
    )
    
    try {
        Invoke-StealthDelay
        
        # Try to get service principal sign-in activity from the service principal object
        # Note: Service principal sign-in activity requires premium license and is in beta
        $null = Get-MgServicePrincipal -ServicePrincipalId $ServicePrincipalId -Property Id,AppId,DisplayName -ErrorAction Stop
        
        # For now, return unknown status - future enhancement can add sign-in activity
        return @{
            LastSignIn = $null
            DaysAgo = -1
            IsStale = $false
            Status = "Unknown"
        }
    }
    catch {
        return @{
            LastSignIn = $null
            DaysAgo = -1
            IsStale = $false
            Status = "Error"
        }
    }
}

# Main scanning function
function Start-OAuthConsentScan {
    Write-Host "`n[*] Starting OAuth consent grant scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of consent grants..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get all OAuth2PermissionGrants (delegated permission grants)
        Write-Host "[*] Retrieving OAuth2 permission grants..." -ForegroundColor Cyan
        $grants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop
        
        Write-Host "[+] Found $($grants.Count) OAuth2 permission grant(s)" -ForegroundColor Green
        
        $script:TotalGrantsScanned = $grants.Count
        $progressCounter = 0
        
        foreach ($grant in $grants) {
            $progressCounter++
            
            # Progress indicator
            if ($progressCounter % 10 -eq 0 -or $progressCounter -eq $grants.Count) {
                $percentComplete = [math]::Round(($progressCounter / $grants.Count) * 100, 1)
                Write-Host "`r[*] Progress: $progressCounter/$($grants.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
            }
            
            try {
                # Get client service principal (the app that has consent)
                $clientSp = Get-CachedServicePrincipal -ServicePrincipalId $grant.ClientId
                
                if (-not $clientSp) {
                    continue
                }
                
                # Check if this is a Microsoft app
                $isMicrosoftApp = Test-IsMicrosoftApp -ServicePrincipal $clientSp
                
                # Filter: Only third-party apps
                if ($OnlyThirdParty -and $isMicrosoftApp) {
                    continue
                }
                
                # Determine consent type
                $consentType = if ($grant.ConsentType -eq "AllPrincipals") { "AdminConsent" } else { "UserConsent" }
                
                # Filter: Only admin consent
                if ($OnlyAdminConsent -and $consentType -ne "AdminConsent") {
                    continue
                }
                
                # Get resource service principal (the API being accessed)
                $resourceSp = Get-CachedResourceServicePrincipal -ResourceId $grant.ResourceId
                $resourceName = if ($resourceSp) { $resourceSp.DisplayName } else { "Unknown Resource" }
                
                # Resolve permission scopes
                $permissionInfo = Resolve-PermissionScopes -Scope $grant.Scope -ResourceServicePrincipal $resourceSp
                
                # Get consenting principal info
                $principalInfo = @{
                    PrincipalId = $null
                    PrincipalName = "All Users (Tenant-Wide)"
                    PrincipalType = "Tenant"
                }
                
                if ($grant.ConsentType -ne "AllPrincipals" -and $grant.PrincipalId) {
                    $user = Get-CachedUser -UserId $grant.PrincipalId
                    if ($user) {
                        $principalInfo = @{
                            PrincipalId = $user.Id
                            PrincipalName = $user.UserPrincipalName
                            PrincipalType = "User"
                        }
                    }
                    else {
                        $principalInfo = @{
                            PrincipalId = $grant.PrincipalId
                            PrincipalName = "Unknown User ($($grant.PrincipalId))"
                            PrincipalType = "User"
                        }
                    }
                }
                
                # Get sign-in activity
                $signInInfo = @{
                    LastSignIn = $null
                    DaysAgo = -1
                    IsStale = $false
                }
                
                if ($grant.PrincipalId) {
                    $signInInfo = Get-ConsentPrincipalSignIn -PrincipalId $grant.PrincipalId -ConsentType $grant.ConsentType
                }
                
                # Filter: Only stale
                if ($OnlyStale -and -not $signInInfo.IsStale -and $signInInfo.DaysAgo -ne -1) {
                    continue
                }
                
                # Determine risk level
                $riskLevel = "LOW"
                
                # CRITICAL: Admin consent + critical permissions + third-party app
                if ($consentType -eq "AdminConsent" -and $permissionInfo.HasCritical -and -not $isMicrosoftApp) {
                    $riskLevel = "CRITICAL"
                }
                # HIGH: Admin consent + dangerous permissions OR User consent + critical permissions
                elseif (($consentType -eq "AdminConsent" -and $permissionInfo.HasDangerous) -or 
                        ($consentType -eq "UserConsent" -and $permissionInfo.HasCritical)) {
                    $riskLevel = "HIGH"
                }
                # HIGH: Third-party app with dangerous permissions (user consent)
                elseif (-not $isMicrosoftApp -and $permissionInfo.HasDangerous) {
                    $riskLevel = "HIGH"
                }
                # MEDIUM: Any dangerous permissions or stale consent
                elseif ($permissionInfo.HasDangerous -or $signInInfo.IsStale) {
                    $riskLevel = "MEDIUM"
                }
                # MEDIUM: Third-party app with any permissions
                elseif (-not $isMicrosoftApp -and $permissionInfo.PermissionCount -gt 0) {
                    $riskLevel = "MEDIUM"
                }
                
                # Filter: Only high risk
                if ($OnlyHighRisk -and $riskLevel -ne "HIGH" -and $riskLevel -ne "CRITICAL") {
                    continue
                }
                
                # Build dangerous permissions list
                $dangerousPerms = @()
                foreach ($perm in $permissionInfo.Permissions) {
                    if ($script:DangerousPermissions -contains $perm -or $script:CriticalPermissions -contains $perm) {
                        $dangerousPerms += $perm
                    }
                }
                
                # Publisher information
                $publisherName = if ($clientSp.PublisherName) { $clientSp.PublisherName } 
                                 elseif ($clientSp.VerifiedPublisher.DisplayName) { $clientSp.VerifiedPublisher.DisplayName }
                                 else { "Unknown Publisher" }
                
                $grantInfo = [PSCustomObject]@{
                    AppDisplayName = $clientSp.DisplayName
                    AppId = $clientSp.AppId
                    ServicePrincipalId = $clientSp.Id
                    Publisher = $publisherName
                    IsMicrosoftApp = $isMicrosoftApp
                    AppType = if ($isMicrosoftApp) { "Microsoft" } else { "Third-Party" }
                    ConsentType = $consentType
                    ConsentTypeDisplay = if ($consentType -eq "AdminConsent") { "Admin Consent (Tenant-Wide)" } else { "User Consent" }
                    GrantedTo = $principalInfo.PrincipalName
                    GrantedToType = $principalInfo.PrincipalType
                    GrantedToId = $principalInfo.PrincipalId
                    ResourceName = $resourceName
                    ResourceId = $grant.ResourceId
                    PermissionCount = $permissionInfo.PermissionCount
                    Permissions = ($permissionInfo.Permissions -join ", ")
                    HasDangerousPermissions = $permissionInfo.HasDangerous
                    HasCriticalPermissions = $permissionInfo.HasCritical
                    DangerousPermissions = ($dangerousPerms -join ", ")
                    DangerousPermissionCount = $dangerousPerms.Count
                    LastSignIn = $signInInfo.LastSignIn
                    DaysSinceLastSignIn = $signInInfo.DaysAgo
                    IsStale = $signInInfo.IsStale
                    StaleStatus = if ($signInInfo.DaysAgo -eq -1) { "Unknown" } elseif ($signInInfo.IsStale) { "Stale ($($signInInfo.DaysAgo) days)" } else { "Active" }
                    GrantId = $grant.Id
                    RiskLevel = $riskLevel
                }
                
                $script:ConsentGrants += $grantInfo
            }
            catch {
                Write-Host "`n[!] Error processing grant $($grant.Id): $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n[+] Scan complete!" -ForegroundColor Green
    }
    catch {
        Write-Host "`n[ERROR] Failed to retrieve OAuth2 permission grants: $_" -ForegroundColor Red
    }
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - OAUTH CONSENT GRANT SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:ConsentGrants.Count -eq 0) {
        Write-Host "`n[!] No consent grants found matching the specified criteria." -ForegroundColor Yellow
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:ConsentGrants | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='App Type';Expression={$_.AppType}},
        @{Name='Application';Expression={$_.AppDisplayName}},
        @{Name='Consent Type';Expression={$_.ConsentType}},
        @{Name='Granted To';Expression={if($_.GrantedTo.Length -gt 30){$_.GrantedTo.Substring(0,27)+"..."}else{$_.GrantedTo}}},
        @{Name='Resource';Expression={$_.ResourceName}},
        @{Name='Perms';Expression={$_.PermissionCount}},
        @{Name='Dangerous';Expression={$_.DangerousPermissionCount}},
        @{Name='Status';Expression={$_.StaleStatus}}
    
    # Display as formatted table
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
    
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    # Summary statistics
    Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
    Write-Host "Total consent grants analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:ConsentGrants.Count -ForegroundColor Yellow
    
    $criticalRisk = ($script:ConsentGrants | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:ConsentGrants | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:ConsentGrants | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:ConsentGrants | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Cyan
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    # Consent type breakdown
    $adminConsent = ($script:ConsentGrants | Where-Object { $_.ConsentType -eq "AdminConsent" }).Count
    $userConsent = ($script:ConsentGrants | Where-Object { $_.ConsentType -eq "UserConsent" }).Count
    
    Write-Host "`n[CONSENT TYPES]" -ForegroundColor Cyan
    Write-Host "  Admin Consent (Tenant-Wide): " -NoNewline -ForegroundColor White
    Write-Host $adminConsent -ForegroundColor $(if($adminConsent -gt 0){"Yellow"}else{"Green"})
    Write-Host "  User Consent (Individual): " -NoNewline -ForegroundColor White
    Write-Host $userConsent -ForegroundColor White
    
    # App type breakdown
    $microsoftApps = ($script:ConsentGrants | Where-Object { $_.IsMicrosoftApp }).Count
    $thirdPartyApps = ($script:ConsentGrants | Where-Object { -not $_.IsMicrosoftApp }).Count
    
    Write-Host "`n[APPLICATION TYPES]" -ForegroundColor Cyan
    Write-Host "  Microsoft Apps: " -NoNewline -ForegroundColor White
    Write-Host $microsoftApps -ForegroundColor Green
    Write-Host "  Third-Party Apps: " -NoNewline -ForegroundColor White
    Write-Host $thirdPartyApps -ForegroundColor $(if($thirdPartyApps -gt 0){"Yellow"}else{"Green"})
    
    # Dangerous permissions
    $withDangerous = ($script:ConsentGrants | Where-Object { $_.HasDangerousPermissions }).Count
    $withCritical = ($script:ConsentGrants | Where-Object { $_.HasCriticalPermissions }).Count
    
    Write-Host "`n[DANGEROUS PERMISSIONS]" -ForegroundColor Cyan
    Write-Host "  With dangerous permissions: " -NoNewline -ForegroundColor White
    Write-Host $withDangerous -ForegroundColor $(if($withDangerous -gt 0){"Yellow"}else{"Green"})
    Write-Host "  With critical permissions: " -NoNewline -ForegroundColor White
    Write-Host $withCritical -ForegroundColor $(if($withCritical -gt 0){"Red"}else{"Green"})
    
    # Stale grants
    $staleGrants = ($script:ConsentGrants | Where-Object { $_.IsStale }).Count
    
    Write-Host "`n[STALE GRANTS]" -ForegroundColor Cyan
    Write-Host "  Stale/unused (>$StaleDays days): " -NoNewline -ForegroundColor White
    Write-Host $staleGrants -ForegroundColor $(if($staleGrants -gt 0){"Yellow"}else{"Green"})
    
    # Top third-party apps with dangerous permissions
    $riskyThirdParty = $script:ConsentGrants | Where-Object { -not $_.IsMicrosoftApp -and $_.HasDangerousPermissions } | 
                       Group-Object AppDisplayName | Sort-Object Count -Descending | Select-Object -First 5
    
    if ($riskyThirdParty.Count -gt 0) {
        Write-Host "`n[TOP RISKY THIRD-PARTY APPS]" -ForegroundColor Cyan
        foreach ($app in $riskyThirdParty) {
            Write-Host "  $($app.Name): " -NoNewline -ForegroundColor White
            Write-Host "$($app.Count) consent grant(s)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
}

# Display results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal consent grants scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalGrantsScanned -ForegroundColor Yellow
    
    Write-Host "Consent grants analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:ConsentGrants.Count -ForegroundColor $(if($script:ConsentGrants.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:ConsentGrants.Count -gt 0) {
        $criticalRisk = ($script:ConsentGrants | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:ConsentGrants | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:ConsentGrants | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:ConsentGrants | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "CONSENT GRANT DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:ConsentGrants | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] OAuth Consent: " -NoNewline -ForegroundColor $riskColor
            Write-Host "$($_.AppDisplayName) ($($_.AppType))" -ForegroundColor White
            
            Write-Host "  App ID: $($_.AppId)" -ForegroundColor Gray
            Write-Host "  Publisher: $($_.Publisher)" -ForegroundColor Gray
            
            Write-Host "  Consent Type: " -NoNewline -ForegroundColor Gray
            if ($_.ConsentType -eq "AdminConsent") {
                Write-Host "$($_.ConsentTypeDisplay)" -ForegroundColor Yellow
            }
            else {
                Write-Host "$($_.ConsentTypeDisplay)" -ForegroundColor White
            }
            
            Write-Host "  Granted To: $($_.GrantedTo)" -ForegroundColor Gray
            Write-Host "  Resource: $($_.ResourceName)" -ForegroundColor Gray
            
            Write-Host "  Permissions ($($_.PermissionCount)): " -NoNewline -ForegroundColor Gray
            Write-Host "$($_.Permissions)" -ForegroundColor DarkGray
            
            if ($_.HasDangerousPermissions) {
                Write-Host "  [!] DANGEROUS Permissions: " -NoNewline -ForegroundColor Red
                Write-Host $_.DangerousPermissions -ForegroundColor Red
            }
            
            if ($_.HasCriticalPermissions) {
                Write-Host "  [!] CRITICAL Permissions detected - potential for full compromise" -ForegroundColor Red
            }
            
            Write-Host "  Status: " -NoNewline -ForegroundColor Gray
            if ($_.IsStale) {
                Write-Host "$($_.StaleStatus)" -ForegroundColor Yellow
            }
            else {
                Write-Host "$($_.StaleStatus)" -ForegroundColor Green
            }
            
            if (-not $_.IsMicrosoftApp) {
                Write-Host "  [!] Third-Party Application - verify legitimacy" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[!] No consent grants found matching the specified criteria." -ForegroundColor Yellow
        Write-Host ("=" * 70) -ForegroundColor Cyan
    }
}

# Export results
function Export-Results {
    param(
        [string]$Path
    )
    
    if (-not $Path) {
        return
    }
    
    if ($script:ConsentGrants.Count -eq 0) {
        Write-Host "`n[*] No consent grants to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:ConsentGrants | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:ConsentGrants | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:ConsentGrants | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $csvPath" -ForegroundColor Green
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
        # Disconnect from Microsoft Graph
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] Disconnected from Microsoft Graph" -ForegroundColor Green
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
        if (-not (Test-GraphModule)) {
            exit 1
        }
        
        # Initialize and import modules properly
        if (-not (Initialize-GraphModules)) {
            Write-Host "`n[ERROR] Failed to initialize modules. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Authenticate
        if (-not (Connect-GraphService)) {
            Write-Host "`n[ERROR] Authentication failed. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Start scan
        Start-OAuthConsentScan
        
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
        
        Write-Host "`n[*] OAuth consent check completed successfully!" -ForegroundColor Green
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
