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
    Enumerates Azure Entra ID service principals and analyzes their security posture including credentials, permissions, and owners.

.DESCRIPTION
    This script queries Azure Entra ID to identify service principals (service accounts) and performs a comprehensive
    security audit including:
    - Enumerates service principals with credentials/secrets
    - Checks for expired credentials
    - Identifies high-permission service principals
    - Checks owners and their MFA status
    - Identifies unused/inactive service principals
    - Risk assessment based on permissions and credential age
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Information collected includes:
    - Service principal identification and status
    - Credential types (secrets, certificates) and expiration dates
    - App role assignments and permissions
    - Owner identification and MFA status
    - Last sign-in/usage activity
    - Risk assessment based on permissions and credential age

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

.PARAMETER IncludeDisabled
    Include disabled service principals in the results.

.PARAMETER OnlyWithCredentials
    Show only service principals with credentials/secrets.

.PARAMETER OnlyExpiredCredentials
    Show only service principals with expired credentials.

.PARAMETER OnlyHighPermission
    Show only service principals with high-risk permissions.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraServicePrincipalCheck.ps1
    # Query all service principals and analyze security posture

.EXAMPLE
    .\Invoke-EntraServicePrincipalCheck.ps1 -ExportPath "service-principals.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraServicePrincipalCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraServicePrincipalCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraServicePrincipalCheck.ps1 -OnlyExpiredCredentials -Matrix
    # Display only service principals with expired credentials in matrix format

.EXAMPLE
    .\Invoke-EntraServicePrincipalCheck.ps1 -OnlyHighPermission -ExportPath "high-risk-sp.csv"
    # Show only high-permission service principals and export
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
    [switch]$IncludeDisabled,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyWithCredentials,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyExpiredCredentials,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyHighPermission,

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

# High-risk permissions that indicate elevated privileges
$script:HighRiskPermissions = @(
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "Exchange.ManageAsApp",
    "full_access_as_app",
    "User.Export.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "Policy.ReadWrite.ConditionalAccess",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "PrivilegedAccess.ReadWrite.AzureResources"
)

# Critical permissions - highest risk
$script:CriticalPermissions = @(
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureAD"
)

# Required scopes for service principal checking
$script:RequiredScopes = @(
    "Application.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "AuditLog.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Application.Read.All",
    "Directory.Read.All",
    "User.ReadBasic.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:ServicePrincipals = @()
$script:TotalSPsScanned = 0
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
    Write-Host "    Entra ID Service Principal Check - High-Risk Service Accounts Audit" -ForegroundColor Yellow
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

# Get service principal owners
function Get-ServicePrincipalOwners {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId
    )
    
    try {
        Invoke-StealthDelay
        
        $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $ServicePrincipalId -All -ErrorAction Stop
        $userOwners = @()
        
        foreach ($owner in $owners) {
            if ($owner.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                $userOwners += $owner
            }
        }
        
        return $userOwners
    }
    catch {
        return @()
    }
}

# Get app registration credentials (secrets and certificates)
function Get-AppRegistrationCredentials {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppId
    )
    
    try {
        Invoke-StealthDelay
        
        # Get app registration by appId
        $app = Get-MgApplication -Filter "appId eq '$AppId'" -ErrorAction Stop
        
        if (-not $app) {
            return @{
                HasSecrets = $false
                HasCertificates = $false
                Secrets = @()
                Certificates = @()
                ExpiredSecrets = @()
                ExpiredCertificates = @()
                ExpiringSoonSecrets = @()
                ExpiringSoonCertificates = @()
            }
        }
        
        # Get password credentials (secrets)
        $secrets = @()
        $expiredSecrets = @()
        $expiringSoonSecrets = @()
        $now = Get-Date
        
        if ($app.PasswordCredentials) {
            foreach ($secret in $app.PasswordCredentials) {
                $endDate = [DateTime]$secret.EndDateTime
                $daysUntilExpiry = ($endDate - $now).Days
                
                $secretInfo = @{
                    KeyId = $secret.KeyId
                    Hint = $secret.Hint
                    EndDateTime = $secret.EndDateTime
                    DaysUntilExpiry = $daysUntilExpiry
                    IsExpired = $daysUntilExpiry -lt 0
                    IsExpiringSoon = $daysUntilExpiry -ge 0 -and $daysUntilExpiry -le 30
                }
                
                $secrets += $secretInfo
                
                if ($secretInfo.IsExpired) {
                    $expiredSecrets += $secretInfo
                }
                elseif ($secretInfo.IsExpiringSoon) {
                    $expiringSoonSecrets += $secretInfo
                }
            }
        }
        
        # Get key credentials (certificates)
        $certificates = @()
        $expiredCertificates = @()
        $expiringSoonCertificates = @()
        
        if ($app.KeyCredentials) {
            foreach ($cert in $app.KeyCredentials) {
                $endDate = [DateTime]$cert.EndDateTime
                $daysUntilExpiry = ($endDate - $now).Days
                
                $certInfo = @{
                    KeyId = $cert.KeyId
                    Usage = $cert.Usage
                    Type = $cert.Type
                    EndDateTime = $cert.EndDateTime
                    DaysUntilExpiry = $daysUntilExpiry
                    IsExpired = $daysUntilExpiry -lt 0
                    IsExpiringSoon = $daysUntilExpiry -ge 0 -and $daysUntilExpiry -le 30
                }
                
                $certificates += $certInfo
                
                if ($certInfo.IsExpired) {
                    $expiredCertificates += $certInfo
                }
                elseif ($certInfo.IsExpiringSoon) {
                    $expiringSoonCertificates += $certInfo
                }
            }
        }
        
        return @{
            HasSecrets = $secrets.Count -gt 0
            HasCertificates = $certificates.Count -gt 0
            Secrets = $secrets
            Certificates = $certificates
            ExpiredSecrets = $expiredSecrets
            ExpiredCertificates = $expiredCertificates
            ExpiringSoonSecrets = $expiringSoonSecrets
            ExpiringSoonCertificates = $expiringSoonCertificates
        }
    }
    catch {
        return @{
            HasSecrets = $false
            HasCertificates = $false
            Secrets = @()
            Certificates = @()
            ExpiredSecrets = @()
            ExpiredCertificates = @()
            ExpiringSoonSecrets = @()
            ExpiringSoonCertificates = @()
        }
    }
}

# Get app role assignments for service principal
function Get-ServicePrincipalAppRoleAssignments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId
    )
    
    try {
        Invoke-StealthDelay
        
        $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId -All -ErrorAction Stop
        
        $permissions = @()
        $hasHighRiskPerms = $false
        $hasCriticalPerms = $false
        
        foreach ($assignment in $assignments) {
            $resourceDisplayName = $assignment.ResourceDisplayName
            
            # Try to resolve permission name (simplified - in production you'd want a full mapping)
            $displayName = if ($resourceDisplayName) { "$resourceDisplayName" } else { "Unknown Resource" }
            
            $permissions += $displayName
            
            # Check for high-risk permissions (simplified check)
            foreach ($hrp in $script:HighRiskPermissions) {
                if ($displayName -like "*$hrp*") {
                    $hasHighRiskPerms = $true
                    break
                }
            }
            
            foreach ($cp in $script:CriticalPermissions) {
                if ($displayName -like "*$cp*") {
                    $hasCriticalPerms = $true
                    break
                }
            }
        }
        
        return @{
            Permissions = $permissions
            PermissionCount = $permissions.Count
            HasHighRiskPerms = $hasHighRiskPerms
            HasCriticalPerms = $hasCriticalPerms
        }
    }
    catch {
        return @{
            Permissions = @()
            PermissionCount = 0
            HasHighRiskPerms = $false
            HasCriticalPerms = $false
        }
    }
}

# Check if user has MFA enabled
function Test-UserMFA {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,
        
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    try {
        Invoke-StealthDelay
        
        # Get authentication methods for the user
        $authMethods = Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction Stop
        
        # Check for strong authentication methods
        $hasMFA = $false
        $mfaMethods = @()
        
        foreach ($method in $authMethods) {
            $methodType = $method.AdditionalProperties.'@odata.type'
            
            # Strong MFA methods
            switch ($methodType) {
                '#microsoft.graph.phoneAuthenticationMethod' {
                    $hasMFA = $true
                    $mfaMethods += "Phone"
                }
                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                    $hasMFA = $true
                    $mfaMethods += "Authenticator App"
                }
                '#microsoft.graph.fido2AuthenticationMethod' {
                    $hasMFA = $true
                    $mfaMethods += "FIDO2 Security Key"
                }
                '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                    $hasMFA = $true
                    $mfaMethods += "Windows Hello"
                }
                '#microsoft.graph.softwareOathAuthenticationMethod' {
                    $hasMFA = $true
                    $mfaMethods += "Software Token"
                }
                '#microsoft.graph.emailAuthenticationMethod' {
                    # Email is not considered strong MFA
                    $mfaMethods += "Email (weak)"
                }
                '#microsoft.graph.passwordAuthenticationMethod' {
                    # Just password, not MFA
                    $mfaMethods += "Password Only"
                }
            }
        }
        
        return @{
            HasMFA = $hasMFA
            Methods = $mfaMethods
            MethodCount = $authMethods.Count
        }
    }
    catch {
        # If we can't check auth methods, assume no MFA for security assessment
        Write-Host "[!] Unable to check MFA for $UserPrincipalName : $_" -ForegroundColor Yellow
        return @{
            HasMFA = $false
            Methods = @("Error checking methods")
            MethodCount = 0
        }
    }
}

# Get last sign-in information for service principal (if available)
function Get-ServicePrincipalSignInInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId
    )
    
    try {
        # Service principals don't have direct sign-in activity like users
        # We can check for recent token issuance or app usage
        # For now, return null - this could be enhanced with audit log queries
        return @{
            LastSignIn = $null
            SignInType = "N/A"
            DaysAgo = -1
            DisplayText = "Not available"
        }
    }
    catch {
        return @{
            LastSignIn = $null
            SignInType = "Unknown"
            DaysAgo = -1
            DisplayText = "Sign-in data unavailable"
        }
    }
}

# Main scanning function
function Start-ServicePrincipalScan {
    Write-Host "`n[*] Starting service principal scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of service principals..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get all service principals
        Write-Host "[*] Retrieving service principals..." -ForegroundColor Cyan
        $sps = Get-MgServicePrincipal -All -Property Id,AppId,DisplayName,ServicePrincipalType,AccountEnabled,AppOwnerOrganizationId,CreatedDateTime -ErrorAction Stop
        
        Write-Host "[+] Found $($sps.Count) service principal(s)" -ForegroundColor Green
        
        $script:TotalSPsScanned = $sps.Count
        $progressCounter = 0
        
        foreach ($sp in $sps) {
            $progressCounter++
            
            # Progress indicator
            if ($progressCounter % 10 -eq 0 -or $progressCounter -eq $sps.Count) {
                $percentComplete = [math]::Round(($progressCounter / $sps.Count) * 100, 1)
                Write-Host "`r[*] Progress: $progressCounter/$($sps.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
            }
            
            # Skip disabled if not included
            if (-not $IncludeDisabled -and -not $sp.AccountEnabled) {
                continue
            }
            
            try {
                # Get credentials
                $credentials = Get-AppRegistrationCredentials -AppId $sp.AppId
                
                # Filter: Only with credentials
                if ($OnlyWithCredentials -and -not $credentials.HasSecrets -and -not $credentials.HasCertificates) {
                    continue
                }
                
                # Filter: Only expired credentials
                if ($OnlyExpiredCredentials) {
                    if ($credentials.ExpiredSecrets.Count -eq 0 -and $credentials.ExpiredCertificates.Count -eq 0) {
                        continue
                    }
                }
                
                # Get app role assignments
                $appRoles = Get-ServicePrincipalAppRoleAssignments -ServicePrincipalId $sp.Id
                
                # Filter: Only high permission
                if ($OnlyHighPermission -and -not $appRoles.HasHighRiskPerms -and -not $appRoles.HasCriticalPerms) {
                    continue
                }
                
                # Get owners
                $owners = Get-ServicePrincipalOwners -ServicePrincipalId $sp.Id
                $ownerInfo = @()
                $ownersWithoutMFA = 0
                
                foreach ($owner in $owners) {
                    # Get UserPrincipalName - may need to retrieve full user object if not populated
                    $userPrincipalName = $owner.UserPrincipalName
                    if ([string]::IsNullOrWhiteSpace($userPrincipalName)) {
                        try {
                            Invoke-StealthDelay
                            $fullUser = Get-MgUser -UserId $owner.Id -Property UserPrincipalName,DisplayName -ErrorAction Stop
                            $userPrincipalName = $fullUser.UserPrincipalName
                            if ([string]::IsNullOrWhiteSpace($owner.DisplayName)) {
                                $owner.DisplayName = $fullUser.DisplayName
                            }
                        }
                        catch {
                            # If we can't get the user, skip MFA check but still count as owner
                            $userPrincipalName = "Unknown ($($owner.Id))"
                        }
                    }
                    
                    # Only check MFA if we have a valid UserPrincipalName
                    $ownerMFA = @{ HasMFA = $false }
                    if (-not [string]::IsNullOrWhiteSpace($userPrincipalName) -and $userPrincipalName -notlike "Unknown*") {
                        try {
                            $ownerMFA = Test-UserMFA -UserId $owner.Id -UserPrincipalName $userPrincipalName
                        }
                        catch {
                            # If MFA check fails, assume no MFA for security assessment
                            $ownerMFA = @{ HasMFA = $false }
                        }
                    }
                    
                    $ownerInfo += @{
                        Id = $owner.Id
                        UserPrincipalName = $userPrincipalName
                        DisplayName = if ($owner.DisplayName) { $owner.DisplayName } else { "Unknown" }
                        HasMFA = $ownerMFA.HasMFA
                    }
                    
                    if (-not $ownerMFA.HasMFA) {
                        $ownersWithoutMFA++
                    }
                }
                
                # Calculate days since creation
                $daysOld = -1
                if ($sp.CreatedDateTime) {
                    $daysOld = ([DateTime]::Now - [DateTime]$sp.CreatedDateTime).Days
                }
                
                # Determine risk level
                $riskLevel = "LOW"
                
                # CRITICAL: Has critical permissions AND expired credentials
                if ($appRoles.HasCriticalPerms -and ($credentials.ExpiredSecrets.Count -gt 0 -or $credentials.ExpiredCertificates.Count -gt 0)) {
                    $riskLevel = "CRITICAL"
                }
                # HIGH: Has high-risk permissions OR expired credentials OR owners without MFA
                elseif ($appRoles.HasHighRiskPerms -or $appRoles.HasCriticalPerms -or $credentials.ExpiredSecrets.Count -gt 0 -or $credentials.ExpiredCertificates.Count -gt 0 -or $ownersWithoutMFA -gt 0) {
                    $riskLevel = "HIGH"
                }
                # MEDIUM: Has credentials expiring soon OR has permissions
                elseif ($credentials.ExpiringSoonSecrets.Count -gt 0 -or $credentials.ExpiringSoonCertificates.Count -gt 0 -or $appRoles.PermissionCount -gt 0) {
                    $riskLevel = "MEDIUM"
                }
                
                # Build credential summary
                $credentialSummary = @()
                if ($credentials.HasSecrets) {
                    $credentialSummary += "$($credentials.Secrets.Count) secret(s)"
                    if ($credentials.ExpiredSecrets.Count -gt 0) {
                        $credentialSummary += "$($credentials.ExpiredSecrets.Count) expired"
                    }
                    if ($credentials.ExpiringSoonSecrets.Count -gt 0) {
                        $credentialSummary += "$($credentials.ExpiringSoonSecrets.Count) expiring soon"
                    }
                }
                if ($credentials.HasCertificates) {
                    $credentialSummary += "$($credentials.Certificates.Count) cert(s)"
                    if ($credentials.ExpiredCertificates.Count -gt 0) {
                        $credentialSummary += "$($credentials.ExpiredCertificates.Count) expired"
                    }
                    if ($credentials.ExpiringSoonCertificates.Count -gt 0) {
                        $credentialSummary += "$($credentials.ExpiringSoonCertificates.Count) expiring soon"
                    }
                }
                if ($credentialSummary.Count -eq 0) {
                    $credentialSummary = @("None")
                }
                
                $spInfo = [PSCustomObject]@{
                    DisplayName = $sp.DisplayName
                    AppId = $sp.AppId
                    ServicePrincipalId = $sp.Id
                    ServicePrincipalType = $sp.ServicePrincipalType
                    AccountEnabled = $sp.AccountEnabled
                    CreatedDateTime = $sp.CreatedDateTime
                    DaysOld = $daysOld
                    HasSecrets = $credentials.HasSecrets
                    HasCertificates = $credentials.HasCertificates
                    SecretCount = $credentials.Secrets.Count
                    CertificateCount = $credentials.Certificates.Count
                    ExpiredSecretsCount = $credentials.ExpiredSecrets.Count
                    ExpiredCertificatesCount = $credentials.ExpiredCertificates.Count
                    ExpiringSoonSecretsCount = $credentials.ExpiringSoonSecrets.Count
                    ExpiringSoonCertificatesCount = $credentials.ExpiringSoonCertificates.Count
                    CredentialSummary = ($credentialSummary -join ", ")
                    PermissionCount = $appRoles.PermissionCount
                    HasHighRiskPerms = $appRoles.HasHighRiskPerms
                    HasCriticalPerms = $appRoles.HasCriticalPerms
                    Permissions = ($appRoles.Permissions -join ", ")
                    OwnerCount = $owners.Count
                    OwnersWithoutMFA = $ownersWithoutMFA
                    OwnerDetails = ($ownerInfo | ForEach-Object { "$($_.UserPrincipalName) (MFA: $(if($_.HasMFA){'Yes'}else{'No'}))" }) -join "; "
                    RiskLevel = $riskLevel
                }
                
                $script:ServicePrincipals += $spInfo
            }
            catch {
                Write-Host "`n[!] Error processing service principal $($sp.DisplayName): $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n[+] Scan complete!" -ForegroundColor Green
    }
    catch {
        Write-Host "`n[ERROR] Failed to retrieve service principals: $_" -ForegroundColor Red
    }
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - SERVICE PRINCIPAL SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:ServicePrincipals.Count -eq 0) {
        Write-Host "`n[!] No service principals found matching the specified criteria." -ForegroundColor Yellow
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:ServicePrincipals | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}},
        @{Name='Display Name';Expression={$_.DisplayName}},
        @{Name='App ID';Expression={$_.AppId}},
        @{Name='Credentials';Expression={$_.CredentialSummary}},
        @{Name='Permissions';Expression={$_.PermissionCount}},
        @{Name='High Risk';Expression={if($_.HasHighRiskPerms){'Yes'}else{'No'}}},
        @{Name='Owners';Expression={$_.OwnerCount}},
        @{Name='Owners No MFA';Expression={$_.OwnersWithoutMFA}}
    
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
    Write-Host "Total service principals analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:ServicePrincipals.Count -ForegroundColor Yellow
    
    $criticalRisk = ($script:ServicePrincipals | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:ServicePrincipals | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:ServicePrincipals | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:ServicePrincipals | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Cyan
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    $withCredentials = ($script:ServicePrincipals | Where-Object { $_.HasSecrets -or $_.HasCertificates }).Count
    $withExpiredCredentials = ($script:ServicePrincipals | Where-Object { $_.ExpiredSecretsCount -gt 0 -or $_.ExpiredCertificatesCount -gt 0 }).Count
    $withHighPerms = ($script:ServicePrincipals | Where-Object { $_.HasHighRiskPerms -or $_.HasCriticalPerms }).Count
    $withOwnersNoMFA = ($script:ServicePrincipals | Where-Object { $_.OwnersWithoutMFA -gt 0 }).Count
    
    Write-Host "`n[CREDENTIALS]" -ForegroundColor Cyan
    Write-Host "  With credentials: " -NoNewline -ForegroundColor White
    Write-Host $withCredentials -ForegroundColor Yellow
    Write-Host "  With expired credentials: " -NoNewline -ForegroundColor White
    Write-Host $withExpiredCredentials -ForegroundColor Red
    Write-Host "  With expiring soon (≤30 days): " -NoNewline -ForegroundColor White
    Write-Host (($script:ServicePrincipals | Where-Object { $_.ExpiringSoonSecretsCount -gt 0 -or $_.ExpiringSoonCertificatesCount -gt 0 }).Count) -ForegroundColor Yellow
    
    Write-Host "`n[PERMISSIONS]" -ForegroundColor Cyan
    Write-Host "  With high-risk permissions: " -NoNewline -ForegroundColor White
    Write-Host $withHighPerms -ForegroundColor Yellow
    
    Write-Host "`n[OWNERS]" -ForegroundColor Cyan
    Write-Host "  With owners without MFA: " -NoNewline -ForegroundColor White
    Write-Host $withOwnersNoMFA -ForegroundColor Red
    
    Write-Host ""
}

# Display results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal service principals scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalSPsScanned -ForegroundColor Yellow
    
    Write-Host "Service principals analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:ServicePrincipals.Count -ForegroundColor $(if($script:ServicePrincipals.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:ServicePrincipals.Count -gt 0) {
        $criticalRisk = ($script:ServicePrincipals | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:ServicePrincipals | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:ServicePrincipals | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:ServicePrincipals | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "SERVICE PRINCIPAL DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:ServicePrincipals | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.DisplayName -ForegroundColor White
            
            Write-Host "  App ID: $($_.AppId)" -ForegroundColor Gray
            Write-Host "  Service Principal ID: $($_.ServicePrincipalId)" -ForegroundColor Gray
            Write-Host "  Type: $($_.ServicePrincipalType)" -ForegroundColor Gray
            
            Write-Host "  Account Status: " -NoNewline -ForegroundColor Gray
            if ($_.AccountEnabled) {
                Write-Host "Enabled" -ForegroundColor Green
            }
            else {
                Write-Host "Disabled" -ForegroundColor Yellow
            }
            
            Write-Host "  Credentials: $($_.CredentialSummary)" -ForegroundColor Gray
            if ($_.ExpiredSecretsCount -gt 0 -or $_.ExpiredCertificatesCount -gt 0) {
                Write-Host "  [!] EXPIRED CREDENTIALS DETECTED" -ForegroundColor Red
            }
            if ($_.ExpiringSoonSecretsCount -gt 0 -or $_.ExpiringSoonCertificatesCount -gt 0) {
                Write-Host "  [!] Credentials expiring soon (≤30 days)" -ForegroundColor Yellow
            }
            
            Write-Host "  Permissions: $($_.PermissionCount) assigned" -ForegroundColor Gray
            if ($_.HasCriticalPerms) {
                Write-Host "  [!] CRITICAL permissions detected" -ForegroundColor Red
            }
            elseif ($_.HasHighRiskPerms) {
                Write-Host "  [!] High-risk permissions detected" -ForegroundColor Yellow
            }
            if ($_.Permissions) {
                Write-Host "  Permission details: $($_.Permissions)" -ForegroundColor DarkGray
            }
            
            Write-Host "  Owners: $($_.OwnerCount)" -ForegroundColor Gray
            if ($_.OwnersWithoutMFA -gt 0) {
                Write-Host "  [!] $($_.OwnersWithoutMFA) owner(s) without MFA" -ForegroundColor Red
            }
            if ($_.OwnerDetails) {
                Write-Host "  Owner details: $($_.OwnerDetails)" -ForegroundColor DarkGray
            }
            
            Write-Host "  Created: $($_.CreatedDateTime) ($($_.DaysOld) days old)" -ForegroundColor Gray
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[!] No service principals found matching the specified criteria." -ForegroundColor Yellow
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
    
    if ($script:ServicePrincipals.Count -eq 0) {
        Write-Host "`n[*] No service principals to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:ServicePrincipals | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:ServicePrincipals | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:ServicePrincipals | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-ServicePrincipalScan
        
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
        
        Write-Host "`n[*] Service principal check completed successfully!" -ForegroundColor Green
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

