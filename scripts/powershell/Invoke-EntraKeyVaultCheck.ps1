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
    Comprehensive Azure Key Vault security audit for identifying misconfigurations that expose secrets.

.DESCRIPTION
    This script performs a deep analysis of Azure Key Vault security configurations to identify
    potential vulnerabilities and misconfigurations that could lead to secret exposure, 
    unauthorized access, or data exfiltration.
    
    Key features:
    - Access policies vs RBAC permission model analysis
    - Overly permissive access policies detection (all permissions granted)
    - Soft delete and purge protection status verification
    - Network restrictions audit (public access enabled)
    - Secrets/certificates/keys approaching expiration
    - High-privilege identities with Key Vault access
    - Diagnostic logging configuration check
    - Private endpoint usage verification
    - Firewall and VNet rules analysis
    
    The script uses Azure PowerShell authentication to query Key Vault configurations
    across all accessible subscriptions.

.PARAMETER ExportPath
    Optional path to export results (CSV or JSON based on extension).

.PARAMETER SubscriptionId
    Specific subscription ID(s) to scan. If not specified, scans all accessible subscriptions.

.PARAMETER TenantId
    Optional Tenant ID. If not specified, uses the user's home tenant.

.PARAMETER UseAzCliToken
    Use Azure CLI authentication.

.PARAMETER UseAzPowerShellToken
    Use Azure PowerShell authentication.

.PARAMETER UseDeviceCode
    Use device code authentication flow. Recommended for embedded terminals where the login popup may be hidden.

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

.PARAMETER OnlyCritical
    Show only Key Vaults with CRITICAL risk findings.

.PARAMETER OnlyPublicAccess
    Show only Key Vaults with public network access enabled.

.PARAMETER OnlyNoProtection
    Show only Key Vaults without soft delete or purge protection.

.PARAMETER IncludeSecrets
    Include secret enumeration and expiration analysis (requires additional permissions).

.PARAMETER IncludeCertificates
    Include certificate enumeration and expiration analysis (requires additional permissions).

.PARAMETER IncludeKeys
    Include key enumeration and expiration analysis (requires additional permissions).

.PARAMETER ExpirationDays
    Number of days to check for approaching secret/certificate/key expiration. Default: 30

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.PARAMETER SkipFailedTenants
    Continue processing even when authentication fails for some tenants (common in multi-tenant/guest scenarios).
    Suppresses MFA/Conditional Access warnings for tenants you can't access.

.EXAMPLE
    .\Invoke-EntraKeyVaultCheck.ps1
    # Perform comprehensive Key Vault security audit

.EXAMPLE
    .\Invoke-EntraKeyVaultCheck.ps1 -ExportPath "keyvault-audit.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraKeyVaultCheck.ps1 -OnlyCritical -Matrix
    # Display only critical findings in matrix format

.EXAMPLE
    .\Invoke-EntraKeyVaultCheck.ps1 -OnlyPublicAccess
    # Audit only Key Vaults with public access enabled

.EXAMPLE
    .\Invoke-EntraKeyVaultCheck.ps1 -IncludeSecrets -IncludeCertificates -ExpirationDays 90
    # Include secret/certificate expiration analysis with 90-day threshold

.EXAMPLE
    .\Invoke-EntraKeyVaultCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraKeyVaultCheck.ps1 -SkipFailedTenants -Matrix
    # Skip tenants with MFA/CA issues and show results in matrix format
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [switch]$UseAzCliToken,

    [Parameter(Mandatory = $false)]
    [switch]$UseAzPowerShellToken,

    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode,

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
    [switch]$OnlyCritical,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyPublicAccess,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyNoProtection,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecrets,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeCertificates,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeKeys,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$ExpirationDays = 30,

    [Parameter(Mandatory = $false)]
    [switch]$Matrix,

    [Parameter(Mandatory = $false)]
    [switch]$SkipFailedTenants
)

# PowerShell 7+ required
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] This script requires PowerShell 7 or later.' -ForegroundColor Red
    Write-Host ('Current version: PowerShell ' + $PSVersionTable.PSVersion.ToString()) -ForegroundColor Yellow
    Write-Host 'Download PowerShell 7: https://aka.ms/powershell-release?tag=stable' -ForegroundColor Cyan
    exit 1
}

$ErrorActionPreference = "Continue"

# High-risk Key Vault permissions that grant full access
$script:HighRiskSecretPermissions = @('all', 'get', 'list', 'set', 'delete', 'backup', 'restore', 'recover', 'purge')
$script:HighRiskKeyPermissions = @('all', 'get', 'list', 'create', 'delete', 'backup', 'restore', 'recover', 'purge', 'decrypt', 'encrypt', 'sign', 'verify', 'import', 'update')
$script:HighRiskCertificatePermissions = @('all', 'get', 'list', 'create', 'delete', 'backup', 'restore', 'recover', 'purge', 'import', 'update', 'managecontacts', 'manageissuers', 'getissuers', 'setissuers')

# Dangerous permission combinations
$script:DangerousSecretPerms = @('get', 'list')
$script:DangerousCryptoPerms = @('decrypt', 'sign', 'unwrapKey')

# Track state
$script:KeyVaultFindings = @()
$script:SecretFindings = @()
$script:CertificateFindings = @()
$script:KeyFindings = @()
$script:TotalKeyVaults = 0
$script:TotalSubscriptions = 0
$script:SkippedSubscriptions = @()
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
    Write-Host "    Azure Key Vault Security Audit" -ForegroundColor Yellow
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

# Check if required Az modules are installed
function Test-AzModules {
    Write-Host "[*] Checking Azure PowerShell modules..." -ForegroundColor Cyan
    
    $modules = @(
        "Az.Accounts",
        "Az.KeyVault",
        "Az.Resources",
        "Az.Monitor"
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

# Initialize and import Az modules
function Initialize-AzModules {
    Write-Host "[*] Initializing Azure PowerShell modules..." -ForegroundColor Cyan
    
    try {
        # Remove any loaded Az modules to avoid version conflicts
        $loadedModules = Get-Module Az.* 
        if ($loadedModules) {
            Write-Host "[*] Cleaning up loaded Az modules..." -ForegroundColor Yellow
            $loadedModules | ForEach-Object {
                Remove-Module $_.Name -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Import modules
        Write-Host "[*] Importing Az.Accounts..." -ForegroundColor Cyan
        Import-Module Az.Accounts -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.KeyVault..." -ForegroundColor Cyan
        Import-Module Az.KeyVault -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.Resources..." -ForegroundColor Cyan
        Import-Module Az.Resources -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.Monitor..." -ForegroundColor Cyan
        Import-Module Az.Monitor -Force -ErrorAction Stop
        
        Write-Host "[+] Modules imported successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to import modules: $_" -ForegroundColor Red
        Write-Host "[*] Try running: Update-Module Az -Force" -ForegroundColor Yellow
        return $false
    }
}

# Authenticate to Azure
function Connect-AzureService {
    Write-Host "`n[*] Authenticating to Azure..." -ForegroundColor Cyan
    
    # Check if already connected
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($context) {
        Write-Host "[+] Already connected to Azure" -ForegroundColor Green
        Write-Host "[+] Tenant: $($context.Tenant.Id)" -ForegroundColor Green
        Write-Host "[+] Account: $($context.Account.Id)" -ForegroundColor Green
        Write-Host "[+] Subscription: $($context.Subscription.Name)" -ForegroundColor Green
        return $true
    }
    
    # Device code authentication
    if ($UseDeviceCode) {
        try {
            Write-Host "[*] Using device code authentication..." -ForegroundColor Cyan
            $connectParams = @{
                UseDeviceAuthentication = $true
            }
            if ($TenantId) {
                $connectParams['TenantId'] = $TenantId
            }
            Connect-AzAccount @connectParams -ErrorAction Stop
            $context = Get-AzContext
            Write-Host "[+] Connected to Azure" -ForegroundColor Green
            Write-Host "[+] Tenant: $($context.Tenant.Id)" -ForegroundColor Green
            Write-Host "[+] Account: $($context.Account.Id)" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "[ERROR] Device code authentication failed: $_" -ForegroundColor Red
            return $false
        }
    }
    
    # Azure CLI token
    if ($UseAzCliToken) {
        try {
            Write-Host "[*] Attempting to use Azure CLI token..." -ForegroundColor Cyan
            Connect-AzAccount -UseDeviceAuthentication:$false -ErrorAction Stop
            $context = Get-AzContext
            Write-Host "[+] Connected using Azure CLI token" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "[!] Failed to use Azure CLI token, falling back to interactive..." -ForegroundColor Yellow
        }
    }
    
    # Interactive authentication
    try {
        $connectParams = @{}
        if ($TenantId) {
            $connectParams['TenantId'] = $TenantId
        }
        
        Connect-AzAccount @connectParams -ErrorAction Stop
        $context = Get-AzContext
        
        Write-Host "[+] Connected to Azure" -ForegroundColor Green
        Write-Host "[+] Tenant: $($context.Tenant.Id)" -ForegroundColor Green
        Write-Host "[+] Account: $($context.Account.Id)" -ForegroundColor Green
        Write-Host "[+] Subscription: $($context.Subscription.Name)" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Host "[ERROR] Authentication failed: $_" -ForegroundColor Red
        return $false
    }
}

# Get all accessible subscriptions
function Get-AccessibleSubscriptions {
    Write-Host "`n[*] Retrieving accessible subscriptions..." -ForegroundColor Cyan
    
    if ($SkipFailedTenants) {
        Write-Host "[*] SkipFailedTenants enabled - will suppress MFA/CA warnings" -ForegroundColor Yellow
    }
    
    try {
        Invoke-StealthDelay
        
        $subscriptions = @()
        
        if ($SubscriptionId -and $SubscriptionId.Count -gt 0) {
            foreach ($subId in $SubscriptionId) {
                $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                if ($sub) {
                    $subscriptions += $sub
                }
                else {
                    Write-Host "[!] Subscription $subId not found or not accessible" -ForegroundColor Yellow
                }
            }
        }
        else {
            # Suppress warnings when SkipFailedTenants is enabled
            if ($SkipFailedTenants) {
                $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
                if (-not $subscriptions) {
                    $subscriptions = @()
                }
            }
            else {
                $subscriptions = Get-AzSubscription -ErrorAction Stop
            }
        }
        
        # Filter out subscriptions we can't actually access
        $accessibleSubs = @()
        foreach ($sub in $subscriptions) {
            if ($sub.State -eq 'Enabled') {
                $accessibleSubs += $sub
            }
        }
        
        Write-Host "[+] Found $($accessibleSubs.Count) accessible subscription(s)" -ForegroundColor Green
        return $accessibleSubs
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve subscriptions: $_" -ForegroundColor Red
        return @()
    }
}

# Get Key Vaults in a subscription
function Get-SubscriptionKeyVaults {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        # Context is already set by the calling function
        # Get Key Vaults with warning suppression if needed
        if ($SkipFailedTenants) {
            $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
            if (-not $keyVaults) {
                $keyVaults = @()
            }
        }
        else {
            $keyVaults = Get-AzKeyVault -ErrorAction Stop
        }
        
        return $keyVaults
    }
    catch {
        if (-not $SkipFailedTenants) {
            Write-Host "[!] Failed to get Key Vaults in subscription $($Subscription.Name): $_" -ForegroundColor Yellow
        }
        return @()
    }
}

# Get detailed Key Vault configuration
function Get-KeyVaultDetails {
    param(
        [Parameter(Mandatory = $true)]
        $KeyVault
    )
    
    try {
        Invoke-StealthDelay
        
        $details = Get-AzKeyVault -VaultName $KeyVault.VaultName -ResourceGroupName $KeyVault.ResourceGroupName -ErrorAction Stop
        return $details
    }
    catch {
        Write-Host "[!] Failed to get details for Key Vault $($KeyVault.VaultName): $_" -ForegroundColor Yellow
        return $null
    }
}

# Get diagnostic settings for Key Vault
function Get-KeyVaultDiagnostics {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId
    )
    
    try {
        Invoke-StealthDelay
        
        $diagnostics = Get-AzDiagnosticSetting -ResourceId $ResourceId -ErrorAction SilentlyContinue
        return $diagnostics
    }
    catch {
        return $null
    }
}

# Get private endpoint connections for Key Vault
function Get-KeyVaultPrivateEndpoints {
    param(
        [Parameter(Mandatory = $true)]
        $KeyVaultDetails
    )
    
    try {
        # Private endpoint connections are in the properties
        if ($KeyVaultDetails.NetworkAcls -and $KeyVaultDetails.PrivateEndpointConnections) {
            return $KeyVaultDetails.PrivateEndpointConnections
        }
        return @()
    }
    catch {
        return @()
    }
}

# Get secrets approaching expiration
function Get-ExpiringSecrets {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,
        
        [Parameter(Mandatory = $true)]
        [int]$DaysThreshold
    )
    
    try {
        Invoke-StealthDelay
        
        $secrets = Get-AzKeyVaultSecret -VaultName $VaultName -ErrorAction SilentlyContinue
        $expiringSecrets = @()
        $now = Get-Date
        $thresholdDate = $now.AddDays($DaysThreshold)
        
        foreach ($secret in $secrets) {
            if ($secret.Expires -and $secret.Expires -lt $thresholdDate) {
                $daysUntilExpiry = ($secret.Expires - $now).Days
                $expiringSecrets += [PSCustomObject]@{
                    Name = $secret.Name
                    Expires = $secret.Expires
                    DaysUntilExpiry = $daysUntilExpiry
                    Enabled = $secret.Enabled
                    ContentType = $secret.ContentType
                    IsExpired = ($secret.Expires -lt $now)
                }
            }
        }
        
        return $expiringSecrets
    }
    catch {
        Write-Host "[!] Failed to get secrets for $VaultName (insufficient permissions)" -ForegroundColor Yellow
        return @()
    }
}

# Get certificates approaching expiration
function Get-ExpiringCertificates {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,
        
        [Parameter(Mandatory = $true)]
        [int]$DaysThreshold
    )
    
    try {
        Invoke-StealthDelay
        
        $certificates = Get-AzKeyVaultCertificate -VaultName $VaultName -ErrorAction SilentlyContinue
        $expiringCerts = @()
        $now = Get-Date
        $thresholdDate = $now.AddDays($DaysThreshold)
        
        foreach ($cert in $certificates) {
            if ($cert.Expires -and $cert.Expires -lt $thresholdDate) {
                $daysUntilExpiry = ($cert.Expires - $now).Days
                $expiringCerts += [PSCustomObject]@{
                    Name = $cert.Name
                    Expires = $cert.Expires
                    DaysUntilExpiry = $daysUntilExpiry
                    Enabled = $cert.Enabled
                    Thumbprint = $cert.Thumbprint
                    IsExpired = ($cert.Expires -lt $now)
                }
            }
        }
        
        return $expiringCerts
    }
    catch {
        Write-Host "[!] Failed to get certificates for $VaultName (insufficient permissions)" -ForegroundColor Yellow
        return @()
    }
}

# Get keys approaching expiration
function Get-ExpiringKeys {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,
        
        [Parameter(Mandatory = $true)]
        [int]$DaysThreshold
    )
    
    try {
        Invoke-StealthDelay
        
        $keys = Get-AzKeyVaultKey -VaultName $VaultName -ErrorAction SilentlyContinue
        $expiringKeys = @()
        $now = Get-Date
        $thresholdDate = $now.AddDays($DaysThreshold)
        
        foreach ($key in $keys) {
            if ($key.Expires -and $key.Expires -lt $thresholdDate) {
                $daysUntilExpiry = ($key.Expires - $now).Days
                $expiringKeys += [PSCustomObject]@{
                    Name = $key.Name
                    Expires = $key.Expires
                    DaysUntilExpiry = $daysUntilExpiry
                    Enabled = $key.Enabled
                    KeyType = $key.KeyType
                    KeySize = $key.KeySize
                    IsExpired = ($key.Expires -lt $now)
                }
            }
        }
        
        return $expiringKeys
    }
    catch {
        Write-Host "[!] Failed to get keys for $VaultName (insufficient permissions)" -ForegroundColor Yellow
        return @()
    }
}

# Analyze access policy permissions
function Analyze-AccessPolicies {
    param(
        [Parameter(Mandatory = $true)]
        $AccessPolicies
    )
    
    $findings = @()
    
    foreach ($policy in $AccessPolicies) {
        $policyFindings = @()
        $isOverlyPermissive = $false
        
        # Check secret permissions
        if ($policy.PermissionsToSecrets) {
            $secretPerms = $policy.PermissionsToSecrets
            if ($secretPerms -contains 'all') {
                $policyFindings += "Full secret permissions ('all')"
                $isOverlyPermissive = $true
            }
            elseif (($secretPerms | Where-Object { $_ -in $script:DangerousSecretPerms }).Count -eq $script:DangerousSecretPerms.Count) {
                # User has both get and list - can enumerate and read all secrets
                $policyFindings += "Has secret read access (get, list)"
            }
        }
        
        # Check key permissions
        if ($policy.PermissionsToKeys) {
            $keyPerms = $policy.PermissionsToKeys
            if ($keyPerms -contains 'all') {
                $policyFindings += "Full key permissions ('all')"
                $isOverlyPermissive = $true
            }
            elseif (($keyPerms | Where-Object { $_ -in $script:DangerousCryptoPerms }).Count -gt 0) {
                $policyFindings += "Dangerous cryptographic permissions: $($keyPerms | Where-Object { $_ -in $script:DangerousCryptoPerms } | Join-String -Separator ', ')"
            }
        }
        
        # Check certificate permissions
        if ($policy.PermissionsToCertificates) {
            $certPerms = $policy.PermissionsToCertificates
            if ($certPerms -contains 'all') {
                $policyFindings += "Full certificate permissions ('all')"
                $isOverlyPermissive = $true
            }
        }
        
        # Check for purge permission (dangerous)
        if (($policy.PermissionsToSecrets -contains 'purge') -or 
            ($policy.PermissionsToKeys -contains 'purge') -or 
            ($policy.PermissionsToCertificates -contains 'purge')) {
            $policyFindings += "Has PURGE permission (can permanently delete)"
            $isOverlyPermissive = $true
        }
        
        if ($policyFindings.Count -gt 0) {
            $findings += [PSCustomObject]@{
                ObjectId = $policy.ObjectId
                TenantId = $policy.TenantId
                ApplicationId = $policy.ApplicationId
                DisplayName = $policy.DisplayName
                SecretPermissions = ($policy.PermissionsToSecrets -join ", ")
                KeyPermissions = ($policy.PermissionsToKeys -join ", ")
                CertificatePermissions = ($policy.PermissionsToCertificates -join ", ")
                Findings = $policyFindings
                IsOverlyPermissive = $isOverlyPermissive
            }
        }
    }
    
    return $findings
}

# Analyze Key Vault for security issues
function Analyze-KeyVaultSecurity {
    param(
        [Parameter(Mandatory = $true)]
        $KeyVaultDetails,
        
        [Parameter(Mandatory = $true)]
        $Subscription,
        
        [Parameter(Mandatory = $false)]
        $Diagnostics,
        
        [Parameter(Mandatory = $false)]
        $ExpiringSecrets,
        
        [Parameter(Mandatory = $false)]
        $ExpiringCertificates,
        
        [Parameter(Mandatory = $false)]
        $ExpiringKeys
    )
    
    $findings = @()
    $riskLevel = "LOW"
    
    # Check permission model
    $usesRBAC = $KeyVaultDetails.EnableRbacAuthorization
    $usesAccessPolicies = ($KeyVaultDetails.AccessPolicies -and $KeyVaultDetails.AccessPolicies.Count -gt 0)
    
    if ($usesAccessPolicies -and -not $usesRBAC) {
        $findings += "Uses legacy access policy model instead of RBAC"
    }
    
    # Check soft delete (should be enabled)
    if (-not $KeyVaultDetails.EnableSoftDelete) {
        $findings += "Soft delete is DISABLED - secrets can be permanently deleted"
        $riskLevel = "HIGH"
    }
    
    # Check purge protection (should be enabled)
    if (-not $KeyVaultDetails.EnablePurgeProtection) {
        $findings += "Purge protection is DISABLED - deleted secrets can be purged immediately"
        if ($riskLevel -ne "CRITICAL") {
            $riskLevel = "HIGH"
        }
    }
    
    # Check network rules
    $networkRules = $KeyVaultDetails.NetworkAcls
    $publicAccess = $true
    $hasFirewallRules = $false
    $hasVNetRules = $false
    
    if ($networkRules) {
        if ($networkRules.DefaultAction -eq 'Deny') {
            $publicAccess = $false
        }
        
        if ($networkRules.IpAddressRanges -and $networkRules.IpAddressRanges.Count -gt 0) {
            $hasFirewallRules = $true
        }
        
        if ($networkRules.VirtualNetworkResourceIds -and $networkRules.VirtualNetworkResourceIds.Count -gt 0) {
            $hasVNetRules = $true
        }
        
        # Check if bypass allows Azure services
        if ($networkRules.Bypass -eq 'AzureServices') {
            $findings += "Network bypass allows 'AzureServices' - trusted MS services can bypass firewall"
        }
    }
    
    if ($publicAccess) {
        $findings += "Public network access is ENABLED (Default Action: Allow)"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check private endpoints
    $privateEndpoints = $KeyVaultDetails.PrivateEndpointConnections
    $hasPrivateEndpoint = ($privateEndpoints -and $privateEndpoints.Count -gt 0)
    
    if (-not $hasPrivateEndpoint -and $publicAccess) {
        $findings += "No private endpoints configured - relies on public access"
    }
    
    # Check diagnostic logging
    $hasLogging = $false
    $logsEnabled = @()
    
    if ($Diagnostics) {
        foreach ($setting in $Diagnostics) {
            if ($setting.Logs) {
                foreach ($log in $setting.Logs) {
                    if ($log.Enabled) {
                        $hasLogging = $true
                        $logsEnabled += $log.Category
                    }
                }
            }
        }
    }
    
    if (-not $hasLogging) {
        $findings += "Diagnostic logging is NOT configured"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Analyze access policies
    $accessPolicyFindings = @()
    $overlyPermissivePolicies = 0
    
    if ($usesAccessPolicies) {
        $policyAnalysis = Analyze-AccessPolicies -AccessPolicies $KeyVaultDetails.AccessPolicies
        $accessPolicyFindings = $policyAnalysis
        $overlyPermissivePolicies = ($policyAnalysis | Where-Object { $_.IsOverlyPermissive }).Count
        
        if ($overlyPermissivePolicies -gt 0) {
            $findings += "$overlyPermissivePolicies access policy(ies) with overly permissive permissions"
            if ($riskLevel -ne "CRITICAL") {
                $riskLevel = "HIGH"
            }
        }
    }
    
    # Check expiring items
    $expiredSecrets = ($ExpiringSecrets | Where-Object { $_.IsExpired }).Count
    $expiredCerts = ($ExpiringCertificates | Where-Object { $_.IsExpired }).Count
    $expiredKeys = ($ExpiringKeys | Where-Object { $_.IsExpired }).Count
    
    if ($expiredSecrets -gt 0) {
        $findings += "$expiredSecrets secret(s) have EXPIRED"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    if ($expiredCerts -gt 0) {
        $findings += "$expiredCerts certificate(s) have EXPIRED"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    if ($expiredKeys -gt 0) {
        $findings += "$expiredKeys key(s) have EXPIRED"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    $expiringSecretsCount = ($ExpiringSecrets | Where-Object { -not $_.IsExpired }).Count
    $expiringCertsCount = ($ExpiringCertificates | Where-Object { -not $_.IsExpired }).Count
    $expiringKeysCount = ($ExpiringKeys | Where-Object { -not $_.IsExpired }).Count
    
    if ($expiringSecretsCount -gt 0) {
        $findings += "$expiringSecretsCount secret(s) expiring within $ExpirationDays days"
    }
    
    if ($expiringCertsCount -gt 0) {
        $findings += "$expiringCertsCount certificate(s) expiring within $ExpirationDays days"
    }
    
    if ($expiringKeysCount -gt 0) {
        $findings += "$expiringKeysCount key(s) expiring within $ExpirationDays days"
    }
    
    # Determine final risk level for critical combinations
    if ((-not $KeyVaultDetails.EnableSoftDelete) -and (-not $KeyVaultDetails.EnablePurgeProtection) -and $publicAccess) {
        $riskLevel = "CRITICAL"
    }
    
    if ($overlyPermissivePolicies -gt 0 -and $publicAccess -and (-not $hasLogging)) {
        $riskLevel = "CRITICAL"
    }
    
    return [PSCustomObject]@{
        VaultName = $KeyVaultDetails.VaultName
        VaultUri = $KeyVaultDetails.VaultUri
        ResourceId = $KeyVaultDetails.ResourceId
        ResourceGroupName = $KeyVaultDetails.ResourceGroupName
        SubscriptionId = $Subscription.Id
        SubscriptionName = $Subscription.Name
        Location = $KeyVaultDetails.Location
        Sku = $KeyVaultDetails.Sku
        TenantId = $KeyVaultDetails.TenantId
        
        # Security Configuration
        EnableRbacAuthorization = $usesRBAC
        EnableSoftDelete = $KeyVaultDetails.EnableSoftDelete
        EnablePurgeProtection = $KeyVaultDetails.EnablePurgeProtection
        SoftDeleteRetentionDays = $KeyVaultDetails.SoftDeleteRetentionInDays
        
        # Network Configuration
        PublicNetworkAccess = $publicAccess
        NetworkDefaultAction = if ($networkRules) { $networkRules.DefaultAction } else { "Allow" }
        HasFirewallRules = $hasFirewallRules
        FirewallRulesCount = if ($networkRules -and $networkRules.IpAddressRanges) { $networkRules.IpAddressRanges.Count } else { 0 }
        HasVNetRules = $hasVNetRules
        VNetRulesCount = if ($networkRules -and $networkRules.VirtualNetworkResourceIds) { $networkRules.VirtualNetworkResourceIds.Count } else { 0 }
        NetworkBypass = if ($networkRules) { $networkRules.Bypass } else { "None" }
        HasPrivateEndpoint = $hasPrivateEndpoint
        PrivateEndpointCount = if ($privateEndpoints) { $privateEndpoints.Count } else { 0 }
        
        # Logging
        HasDiagnosticLogging = $hasLogging
        LogCategories = ($logsEnabled -join ", ")
        
        # Access Policies
        UsesAccessPolicies = $usesAccessPolicies
        AccessPolicyCount = if ($KeyVaultDetails.AccessPolicies) { $KeyVaultDetails.AccessPolicies.Count } else { 0 }
        OverlyPermissivePolicies = $overlyPermissivePolicies
        AccessPolicyFindings = $accessPolicyFindings
        
        # Expiration Tracking
        ExpiringSecretsCount = $expiringSecretsCount
        ExpiredSecretsCount = $expiredSecrets
        ExpiringCertificatesCount = $expiringCertsCount
        ExpiredCertificatesCount = $expiredCerts
        ExpiringKeysCount = $expiringKeysCount
        ExpiredKeysCount = $expiredKeys
        ExpiringSecrets = $ExpiringSecrets
        ExpiringCertificates = $ExpiringCertificates
        ExpiringKeys = $ExpiringKeys
        
        # Risk Assessment
        Findings = $findings
        FindingCount = $findings.Count
        RiskLevel = $riskLevel
        HasMisconfigurations = ($findings.Count -gt 0)
    }
}

# Main scanning function
function Start-KeyVaultScan {
    Write-Host "`n[*] Starting Key Vault security audit..." -ForegroundColor Cyan
    
    # Get subscriptions
    $subscriptions = Get-AccessibleSubscriptions
    
    if ($subscriptions.Count -eq 0) {
        Write-Host "[ERROR] No accessible subscriptions found. Cannot proceed." -ForegroundColor Red
        return
    }
    
    $script:TotalSubscriptions = $subscriptions.Count
    $progressCounter = 0
    
    foreach ($subscription in $subscriptions) {
        $progressCounter++
        Write-Host "`n[*] Scanning subscription $progressCounter/$($subscriptions.Count): $($subscription.Name)" -ForegroundColor Cyan
        
        # Verify we can set context for this subscription
        $contextSuccess = $false
        try {
            if ($SkipFailedTenants) {
                $ctx = Set-AzContext -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
                $contextSuccess = ($null -ne $ctx)
            }
            else {
                Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
                $contextSuccess = $true
            }
        }
        catch {
            $contextSuccess = $false
        }
        
        if (-not $contextSuccess) {
            if ($SkipFailedTenants) {
                Write-Host "[!] Skipped (unable to access tenant for this subscription)" -ForegroundColor Yellow
                $script:SkippedSubscriptions += $subscription.Name
            }
            else {
                Write-Host "[!] Failed to set context for subscription - check tenant access" -ForegroundColor Yellow
            }
            continue
        }
        
        # Get Key Vaults in this subscription
        $keyVaults = Get-SubscriptionKeyVaults -Subscription $subscription
        
        if ($keyVaults.Count -eq 0) {
            Write-Host "[*] No Key Vaults found in this subscription" -ForegroundColor Gray
            continue
        }
        
        Write-Host "[+] Found $($keyVaults.Count) Key Vault(s)" -ForegroundColor Green
        $script:TotalKeyVaults += $keyVaults.Count
        
        foreach ($keyVault in $keyVaults) {
            Write-Host "[*] Analyzing: $($keyVault.VaultName)..." -ForegroundColor Cyan
            
            # Get detailed configuration
            $details = Get-KeyVaultDetails -KeyVault $keyVault
            
            if (-not $details) {
                continue
            }
            
            # Get diagnostic settings
            $diagnostics = Get-KeyVaultDiagnostics -ResourceId $details.ResourceId
            
            # Get expiring items if requested
            $expiringSecrets = @()
            $expiringCerts = @()
            $expiringKeys = @()
            
            if ($IncludeSecrets) {
                $expiringSecrets = Get-ExpiringSecrets -VaultName $keyVault.VaultName -DaysThreshold $ExpirationDays
            }
            
            if ($IncludeCertificates) {
                $expiringCerts = Get-ExpiringCertificates -VaultName $keyVault.VaultName -DaysThreshold $ExpirationDays
            }
            
            if ($IncludeKeys) {
                $expiringKeys = Get-ExpiringKeys -VaultName $keyVault.VaultName -DaysThreshold $ExpirationDays
            }
            
            # Analyze security
            $finding = Analyze-KeyVaultSecurity -KeyVaultDetails $details -Subscription $subscription `
                -Diagnostics $diagnostics -ExpiringSecrets $expiringSecrets `
                -ExpiringCertificates $expiringCerts -ExpiringKeys $expiringKeys
            
            # Apply filters
            if ($OnlyCritical -and $finding.RiskLevel -ne "CRITICAL") {
                continue
            }
            
            if ($OnlyPublicAccess -and -not $finding.PublicNetworkAccess) {
                continue
            }
            
            if ($OnlyNoProtection -and $finding.EnableSoftDelete -and $finding.EnablePurgeProtection) {
                continue
            }
            
            $script:KeyVaultFindings += $finding
        }
    }
    
    Write-Host "`n[+] Key Vault scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - KEY VAULT SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:KeyVaultFindings.Count -eq 0) {
        Write-Host "`n[!] No Key Vault findings to display." -ForegroundColor Yellow
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:KeyVaultFindings | Sort-Object @{Expression={
        switch($_.RiskLevel) {
            "CRITICAL" { 0 }
            "HIGH" { 1 }
            "MEDIUM" { 2 }
            "LOW" { 3 }
            default { 4 }
        }
    }}, VaultName | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Vault';Expression={if($_.VaultName.Length -gt 30){$_.VaultName.Substring(0,27)+"..."}else{$_.VaultName}}},
        @{Name='Subscription';Expression={if($_.SubscriptionName.Length -gt 20){$_.SubscriptionName.Substring(0,17)+"..."}else{$_.SubscriptionName}}},
        @{Name='RBAC';Expression={if($_.EnableRbacAuthorization){"Yes"}else{"No"}}},
        @{Name='SoftDel';Expression={if($_.EnableSoftDelete){"Yes"}else{"No"}}},
        @{Name='Purge';Expression={if($_.EnablePurgeProtection){"Yes"}else{"No"}}},
        @{Name='Public';Expression={if($_.PublicNetworkAccess){"Yes"}else{"No"}}},
        @{Name='PvtEnd';Expression={if($_.HasPrivateEndpoint){"Yes"}else{"No"}}},
        @{Name='FW';Expression={if($_.HasFirewallRules){"Yes"}else{"No"}}},
        @{Name='Logs';Expression={if($_.HasDiagnosticLogging){"Yes"}else{"No"}}},
        @{Name='Policies';Expression={$_.AccessPolicyCount}},
        @{Name='Issues';Expression={$_.FindingCount}}
    
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
    Write-Host "Total subscriptions scanned: " -NoNewline -ForegroundColor White
    Write-Host ($script:TotalSubscriptions - $script:SkippedSubscriptions.Count) -ForegroundColor Yellow
    if ($script:SkippedSubscriptions.Count -gt 0) {
        Write-Host "Subscriptions skipped (auth failed): " -NoNewline -ForegroundColor White
        Write-Host $script:SkippedSubscriptions.Count -ForegroundColor Yellow
    }
    Write-Host "Total Key Vaults analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:KeyVaultFindings.Count -ForegroundColor Yellow
    
    $criticalRisk = ($script:KeyVaultFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:KeyVaultFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:KeyVaultFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:KeyVaultFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Cyan
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    # Configuration gaps
    $noSoftDelete = ($script:KeyVaultFindings | Where-Object { -not $_.EnableSoftDelete }).Count
    $noPurgeProtection = ($script:KeyVaultFindings | Where-Object { -not $_.EnablePurgeProtection }).Count
    $publicAccess = ($script:KeyVaultFindings | Where-Object { $_.PublicNetworkAccess }).Count
    $noPrivateEndpoint = ($script:KeyVaultFindings | Where-Object { -not $_.HasPrivateEndpoint }).Count
    $noLogging = ($script:KeyVaultFindings | Where-Object { -not $_.HasDiagnosticLogging }).Count
    $noRBAC = ($script:KeyVaultFindings | Where-Object { -not $_.EnableRbacAuthorization }).Count
    
    Write-Host "`n[CONFIGURATION GAPS]" -ForegroundColor Cyan
    Write-Host "  No soft delete: " -NoNewline -ForegroundColor White
    Write-Host $noSoftDelete -ForegroundColor $(if($noSoftDelete -gt 0){"Red"}else{"Green"})
    Write-Host "  No purge protection: " -NoNewline -ForegroundColor White
    Write-Host $noPurgeProtection -ForegroundColor $(if($noPurgeProtection -gt 0){"Red"}else{"Green"})
    Write-Host "  Public access enabled: " -NoNewline -ForegroundColor White
    Write-Host $publicAccess -ForegroundColor $(if($publicAccess -gt 0){"Yellow"}else{"Green"})
    Write-Host "  No private endpoint: " -NoNewline -ForegroundColor White
    Write-Host $noPrivateEndpoint -ForegroundColor $(if($noPrivateEndpoint -gt 0){"Yellow"}else{"Green"})
    Write-Host "  No diagnostic logging: " -NoNewline -ForegroundColor White
    Write-Host $noLogging -ForegroundColor $(if($noLogging -gt 0){"Yellow"}else{"Green"})
    Write-Host "  Using access policies (not RBAC): " -NoNewline -ForegroundColor White
    Write-Host $noRBAC -ForegroundColor $(if($noRBAC -gt 0){"Cyan"}else{"Green"})
    
    # Expiration summary (if applicable)
    if ($IncludeSecrets -or $IncludeCertificates -or $IncludeKeys) {
        $totalExpiredSecrets = ($script:KeyVaultFindings | Measure-Object -Property ExpiredSecretsCount -Sum).Sum
        $totalExpiringSecrets = ($script:KeyVaultFindings | Measure-Object -Property ExpiringSecretsCount -Sum).Sum
        $totalExpiredCerts = ($script:KeyVaultFindings | Measure-Object -Property ExpiredCertificatesCount -Sum).Sum
        $totalExpiringCerts = ($script:KeyVaultFindings | Measure-Object -Property ExpiringCertificatesCount -Sum).Sum
        $totalExpiredKeys = ($script:KeyVaultFindings | Measure-Object -Property ExpiredKeysCount -Sum).Sum
        $totalExpiringKeys = ($script:KeyVaultFindings | Measure-Object -Property ExpiringKeysCount -Sum).Sum
        
        Write-Host "`n[EXPIRATION SUMMARY]" -ForegroundColor Cyan
        if ($IncludeSecrets) {
            Write-Host "  Expired secrets: " -NoNewline -ForegroundColor White
            Write-Host $totalExpiredSecrets -ForegroundColor $(if($totalExpiredSecrets -gt 0){"Red"}else{"Green"})
            Write-Host "  Expiring secrets (within $ExpirationDays days): " -NoNewline -ForegroundColor White
            Write-Host $totalExpiringSecrets -ForegroundColor $(if($totalExpiringSecrets -gt 0){"Yellow"}else{"Green"})
        }
        if ($IncludeCertificates) {
            Write-Host "  Expired certificates: " -NoNewline -ForegroundColor White
            Write-Host $totalExpiredCerts -ForegroundColor $(if($totalExpiredCerts -gt 0){"Red"}else{"Green"})
            Write-Host "  Expiring certificates (within $ExpirationDays days): " -NoNewline -ForegroundColor White
            Write-Host $totalExpiringCerts -ForegroundColor $(if($totalExpiringCerts -gt 0){"Yellow"}else{"Green"})
        }
        if ($IncludeKeys) {
            Write-Host "  Expired keys: " -NoNewline -ForegroundColor White
            Write-Host $totalExpiredKeys -ForegroundColor $(if($totalExpiredKeys -gt 0){"Red"}else{"Green"})
            Write-Host "  Expiring keys (within $ExpirationDays days): " -NoNewline -ForegroundColor White
            Write-Host $totalExpiringKeys -ForegroundColor $(if($totalExpiringKeys -gt 0){"Yellow"}else{"Green"})
        }
    }
    
    Write-Host ""
}

# Display detailed results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal subscriptions scanned: " -NoNewline -ForegroundColor White
    Write-Host ($script:TotalSubscriptions - $script:SkippedSubscriptions.Count) -ForegroundColor Yellow
    if ($script:SkippedSubscriptions.Count -gt 0) {
        Write-Host "Subscriptions skipped (auth failed): " -NoNewline -ForegroundColor White
        Write-Host $script:SkippedSubscriptions.Count -ForegroundColor Yellow
    }
    Write-Host "Total Key Vaults analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:KeyVaultFindings.Count -ForegroundColor Yellow
    
    if ($script:KeyVaultFindings.Count -gt 0) {
        $criticalRisk = ($script:KeyVaultFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:KeyVaultFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:KeyVaultFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:KeyVaultFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "KEY VAULT SECURITY DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:KeyVaultFindings | Sort-Object @{Expression={
            switch($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }}, VaultName | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] Key Vault: " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.VaultName -ForegroundColor White
            
            Write-Host "  Subscription: $($_.SubscriptionName)" -ForegroundColor Gray
            Write-Host "  Resource Group: $($_.ResourceGroupName)" -ForegroundColor Gray
            Write-Host "  Location: $($_.Location)" -ForegroundColor Gray
            Write-Host "  Vault URI: $($_.VaultUri)" -ForegroundColor Gray
            
            # Security Configuration
            Write-Host "`n  [Security Configuration]" -ForegroundColor Cyan
            Write-Host "  RBAC Authorization: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.EnableRbacAuthorization){"Enabled"}else{"Disabled (using access policies)"}) -ForegroundColor $(if($_.EnableRbacAuthorization){"Green"}else{"Yellow"})
            
            Write-Host "  Soft Delete: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.EnableSoftDelete){"Enabled ($($_.SoftDeleteRetentionDays) days retention)"}else{"DISABLED"}) -ForegroundColor $(if($_.EnableSoftDelete){"Green"}else{"Red"})
            
            Write-Host "  Purge Protection: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.EnablePurgeProtection){"Enabled"}else{"DISABLED"}) -ForegroundColor $(if($_.EnablePurgeProtection){"Green"}else{"Red"})
            
            # Network Configuration
            Write-Host "`n  [Network Configuration]" -ForegroundColor Cyan
            Write-Host "  Public Network Access: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.PublicNetworkAccess){"ENABLED (Default: $($_.NetworkDefaultAction))"}else{"Disabled"}) -ForegroundColor $(if($_.PublicNetworkAccess){"Yellow"}else{"Green"})
            
            Write-Host "  Private Endpoints: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasPrivateEndpoint){"$($_.PrivateEndpointCount) configured"}else{"None"}) -ForegroundColor $(if($_.HasPrivateEndpoint){"Green"}else{"Yellow"})
            
            Write-Host "  Firewall Rules: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasFirewallRules){"$($_.FirewallRulesCount) IP rules"}else{"None"}) -ForegroundColor Gray
            
            Write-Host "  VNet Rules: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasVNetRules){"$($_.VNetRulesCount) VNet rules"}else{"None"}) -ForegroundColor Gray
            
            Write-Host "  Network Bypass: " -NoNewline -ForegroundColor Gray
            Write-Host $_.NetworkBypass -ForegroundColor $(if($_.NetworkBypass -eq "AzureServices"){"Yellow"}else{"Gray"})
            
            # Logging
            Write-Host "`n  [Logging]" -ForegroundColor Cyan
            Write-Host "  Diagnostic Logging: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasDiagnosticLogging){"Enabled - $($_.LogCategories)"}else{"NOT CONFIGURED"}) -ForegroundColor $(if($_.HasDiagnosticLogging){"Green"}else{"Yellow"})
            
            # Access Policies
            if ($_.UsesAccessPolicies) {
                Write-Host "`n  [Access Policies]" -ForegroundColor Cyan
                Write-Host "  Total Policies: $($_.AccessPolicyCount)" -ForegroundColor Gray
                Write-Host "  Overly Permissive: " -NoNewline -ForegroundColor Gray
                Write-Host $_.OverlyPermissivePolicies -ForegroundColor $(if($_.OverlyPermissivePolicies -gt 0){"Red"}else{"Green"})
                
                if ($_.AccessPolicyFindings.Count -gt 0) {
                    Write-Host "`n  [Access Policy Issues]" -ForegroundColor Red
                    foreach ($apFinding in $_.AccessPolicyFindings | Select-Object -First 5) {
                        Write-Host "    - ObjectId: $($apFinding.ObjectId)" -ForegroundColor Yellow
                        foreach ($issue in $apFinding.Findings) {
                            Write-Host "      * $issue" -ForegroundColor Yellow
                        }
                    }
                    if ($_.AccessPolicyFindings.Count -gt 5) {
                        Write-Host "    ... and $($_.AccessPolicyFindings.Count - 5) more" -ForegroundColor DarkGray
                    }
                }
            }
            
            # Expiration info
            if ($IncludeSecrets -or $IncludeCertificates -or $IncludeKeys) {
                $hasExpiration = ($_.ExpiredSecretsCount -gt 0) -or ($_.ExpiringSecretsCount -gt 0) -or 
                                 ($_.ExpiredCertificatesCount -gt 0) -or ($_.ExpiringCertificatesCount -gt 0) -or
                                 ($_.ExpiredKeysCount -gt 0) -or ($_.ExpiringKeysCount -gt 0)
                
                if ($hasExpiration) {
                    Write-Host "`n  [Expiration Status]" -ForegroundColor Cyan
                    if ($IncludeSecrets) {
                        Write-Host "  Secrets - Expired: $($_.ExpiredSecretsCount), Expiring: $($_.ExpiringSecretsCount)" -ForegroundColor $(if($_.ExpiredSecretsCount -gt 0){"Red"}elseif($_.ExpiringSecretsCount -gt 0){"Yellow"}else{"Green"})
                    }
                    if ($IncludeCertificates) {
                        Write-Host "  Certificates - Expired: $($_.ExpiredCertificatesCount), Expiring: $($_.ExpiringCertificatesCount)" -ForegroundColor $(if($_.ExpiredCertificatesCount -gt 0){"Red"}elseif($_.ExpiringCertificatesCount -gt 0){"Yellow"}else{"Green"})
                    }
                    if ($IncludeKeys) {
                        Write-Host "  Keys - Expired: $($_.ExpiredKeysCount), Expiring: $($_.ExpiringKeysCount)" -ForegroundColor $(if($_.ExpiredKeysCount -gt 0){"Red"}elseif($_.ExpiringKeysCount -gt 0){"Yellow"}else{"Green"})
                    }
                }
            }
            
            # Findings
            if ($_.Findings.Count -gt 0) {
                Write-Host "`n  [Findings]" -ForegroundColor Red
                foreach ($finding in $_.Findings) {
                    Write-Host "    - $finding" -ForegroundColor Yellow
                }
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[!] No Key Vault findings to display." -ForegroundColor Yellow
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
    
    if ($script:KeyVaultFindings.Count -eq 0) {
        Write-Host "`n[*] No Key Vault findings to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        # Prepare export data (flatten complex objects)
        $exportData = $script:KeyVaultFindings | Select-Object `
            VaultName, VaultUri, ResourceId, ResourceGroupName, SubscriptionId, SubscriptionName, Location, Sku, TenantId,
            EnableRbacAuthorization, EnableSoftDelete, EnablePurgeProtection, SoftDeleteRetentionDays,
            PublicNetworkAccess, NetworkDefaultAction, HasFirewallRules, FirewallRulesCount, HasVNetRules, VNetRulesCount, NetworkBypass,
            HasPrivateEndpoint, PrivateEndpointCount, HasDiagnosticLogging, LogCategories,
            UsesAccessPolicies, AccessPolicyCount, OverlyPermissivePolicies,
            ExpiringSecretsCount, ExpiredSecretsCount, ExpiringCertificatesCount, ExpiredCertificatesCount, ExpiringKeysCount, ExpiredKeysCount,
            @{Name='Findings';Expression={$_.Findings -join "; "}},
            FindingCount, RiskLevel, HasMisconfigurations
        
        switch ($extension) {
            ".csv" {
                $exportData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:KeyVaultFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        # Disconnect from Azure PowerShell
        if (Get-AzContext -ErrorAction SilentlyContinue) {
            Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[+] Disconnected from Azure PowerShell" -ForegroundColor Green
        }
        # Disconnect from Microsoft Graph if connected
        try {
            $mgContext = Get-MgContext -ErrorAction SilentlyContinue
            if ($mgContext) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                Write-Host "[+] Disconnected from Microsoft Graph" -ForegroundColor Green
            }
        } catch { }
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
    Write-Host "[+] Cleanup complete" -ForegroundColor Green
}

# Main execution
function Main {
    try {
        Show-Banner
        
        # Initialize stealth
        Initialize-StealthConfig
        
        # Check required modules
        if (-not (Test-AzModules)) {
            exit 1
        }
        
        # Initialize and import modules
        if (-not (Initialize-AzModules)) {
            Write-Host "`n[ERROR] Failed to initialize modules. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Authenticate
        if (-not (Connect-AzureService)) {
            Write-Host "`n[ERROR] Authentication failed. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Start scan
        Start-KeyVaultScan
        
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
        
        Write-Host "`n[*] Key Vault security check completed successfully!" -ForegroundColor Green
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
