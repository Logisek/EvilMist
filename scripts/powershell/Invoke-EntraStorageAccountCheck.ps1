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
    Comprehensive Azure Storage Account security audit for detecting exposed storage and data exfiltration risks.

.DESCRIPTION
    This script performs a deep analysis of Azure Storage Account security configurations to identify
    potential vulnerabilities and misconfigurations that could lead to data exposure, 
    unauthorized access, or data exfiltration.
    
    Key features:
    - Public blob container detection (anonymous access)
    - HTTPS-only enforcement verification
    - Shared key access vs Azure AD authentication analysis
    - Network rules and firewall configuration audit
    - SAS token configuration risk assessment
    - Blob versioning and soft delete status
    - Storage account key rotation age tracking
    - Cross-tenant replication settings analysis
    - Infrastructure encryption status
    - Minimum TLS version verification
    - Private endpoint configuration
    
    The script uses Azure PowerShell authentication to query Storage Account configurations
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
    Show only Storage Accounts with CRITICAL risk findings.

.PARAMETER OnlyPublicAccess
    Show only Storage Accounts with public access enabled or public containers.

.PARAMETER OnlyAnonymousContainers
    Show only Storage Accounts with containers allowing anonymous access.

.PARAMETER IncludeContainers
    Include blob container enumeration and anonymous access analysis (requires additional permissions).

.PARAMETER IncludeKeyAge
    Include storage account key age analysis and rotation status.

.PARAMETER KeyRotationDays
    Number of days to flag as warning for key rotation. Default: 90

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.PARAMETER SkipFailedTenants
    Continue processing even when authentication fails for some tenants (common in multi-tenant/guest scenarios).
    Suppresses MFA/Conditional Access warnings for tenants you can't access.

.EXAMPLE
    .\Invoke-EntraStorageAccountCheck.ps1
    # Perform comprehensive Storage Account security audit

.EXAMPLE
    .\Invoke-EntraStorageAccountCheck.ps1 -ExportPath "storage-audit.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraStorageAccountCheck.ps1 -OnlyCritical -Matrix
    # Display only critical findings in matrix format

.EXAMPLE
    .\Invoke-EntraStorageAccountCheck.ps1 -OnlyPublicAccess
    # Audit only Storage Accounts with public access enabled

.EXAMPLE
    .\Invoke-EntraStorageAccountCheck.ps1 -OnlyAnonymousContainers -IncludeContainers
    # Find all containers with anonymous access enabled

.EXAMPLE
    .\Invoke-EntraStorageAccountCheck.ps1 -IncludeKeyAge -KeyRotationDays 60 -Matrix
    # Include key rotation analysis with 60-day warning threshold

.EXAMPLE
    .\Invoke-EntraStorageAccountCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraStorageAccountCheck.ps1 -SkipFailedTenants -Matrix
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
    [switch]$OnlyAnonymousContainers,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeContainers,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeKeyAge,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$KeyRotationDays = 90,

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

# High-risk public access levels
$script:RiskyPublicAccessLevels = @('Blob', 'Container')

# Track state
$script:StorageFindings = @()
$script:ContainerFindings = @()
$script:TotalStorageAccounts = 0
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
    Write-Host "    Azure Storage Account Security Audit" -ForegroundColor Yellow
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
        "Az.Storage",
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
        
        Write-Host "[*] Importing Az.Storage..." -ForegroundColor Cyan
        Import-Module Az.Storage -Force -ErrorAction Stop
        
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

# Get Storage Accounts in a subscription
function Get-SubscriptionStorageAccounts {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        # Get Storage Accounts with warning suppression if needed
        if ($SkipFailedTenants) {
            $storageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
            if (-not $storageAccounts) {
                $storageAccounts = @()
            }
        }
        else {
            $storageAccounts = Get-AzStorageAccount -ErrorAction Stop
        }
        
        return $storageAccounts
    }
    catch {
        if (-not $SkipFailedTenants) {
            Write-Host "[!] Failed to get Storage Accounts in subscription $($Subscription.Name): $_" -ForegroundColor Yellow
        }
        return @()
    }
}

# Get blob containers for a storage account
function Get-StorageContainers {
    param(
        [Parameter(Mandatory = $true)]
        $StorageAccount
    )
    
    try {
        Invoke-StealthDelay
        
        # Get the storage context
        $context = $StorageAccount.Context
        
        if (-not $context) {
            # Try to create context using managed identity or current credentials
            $context = New-AzStorageContext -StorageAccountName $StorageAccount.StorageAccountName -UseConnectedAccount -ErrorAction Stop
        }
        
        $containers = Get-AzStorageContainer -Context $context -ErrorAction SilentlyContinue
        return $containers
    }
    catch {
        # May not have permission to list containers
        return @()
    }
}

# Get storage account key details
function Get-StorageKeyDetails {
    param(
        [Parameter(Mandatory = $true)]
        $StorageAccount
    )
    
    try {
        Invoke-StealthDelay
        
        $keys = Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -ErrorAction SilentlyContinue
        
        $keyDetails = @()
        foreach ($key in $keys) {
            $keyInfo = [PSCustomObject]@{
                KeyName = $key.KeyName
                CreationTime = $key.CreationTime
                Permissions = $key.Permissions
                DaysOld = if ($key.CreationTime) { ((Get-Date) - $key.CreationTime).Days } else { -1 }
            }
            $keyDetails += $keyInfo
        }
        
        return $keyDetails
    }
    catch {
        return @()
    }
}

# Get diagnostic settings for Storage Account
function Get-StorageDiagnostics {
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

# Analyze container public access
function Analyze-ContainerPublicAccess {
    param(
        [Parameter(Mandatory = $true)]
        $Containers
    )
    
    $findings = @()
    
    foreach ($container in $Containers) {
        $publicAccess = $container.PublicAccess
        
        if ($publicAccess -and $publicAccess -ne 'Off' -and $publicAccess -ne 'None') {
            $findings += [PSCustomObject]@{
                ContainerName = $container.Name
                PublicAccess = $publicAccess
                LastModified = $container.LastModified
                IsAnonymous = $true
                RiskLevel = if ($publicAccess -eq 'Container') { "CRITICAL" } else { "HIGH" }
            }
        }
    }
    
    return $findings
}

# Analyze Storage Account for security issues
function Analyze-StorageAccountSecurity {
    param(
        [Parameter(Mandatory = $true)]
        $StorageAccount,
        
        [Parameter(Mandatory = $true)]
        $Subscription,
        
        [Parameter(Mandatory = $false)]
        $Diagnostics,
        
        [Parameter(Mandatory = $false)]
        $ContainerFindings,
        
        [Parameter(Mandatory = $false)]
        $KeyDetails
    )
    
    $findings = @()
    $riskLevel = "LOW"
    
    # Check allow blob public access
    $allowBlobPublicAccess = $StorageAccount.AllowBlobPublicAccess
    if ($allowBlobPublicAccess -eq $true) {
        $findings += "Blob public access is ALLOWED (containers can be made public)"
        if ($riskLevel -ne "CRITICAL") {
            $riskLevel = "HIGH"
        }
    }
    
    # Check for anonymous containers
    $anonymousContainerCount = 0
    $containerAccessLevel = "N/A"
    if ($ContainerFindings -and $ContainerFindings.Count -gt 0) {
        $anonymousContainerCount = $ContainerFindings.Count
        $containerAccessLevel = ($ContainerFindings | ForEach-Object { $_.PublicAccess } | Select-Object -Unique) -join ", "
        $findings += "$anonymousContainerCount container(s) with ANONYMOUS access: $containerAccessLevel"
        $riskLevel = "CRITICAL"
    }
    
    # Check HTTPS only
    $httpsOnly = $StorageAccount.EnableHttpsTrafficOnly
    if (-not $httpsOnly) {
        $findings += "HTTPS-only is DISABLED - unencrypted HTTP traffic allowed"
        if ($riskLevel -ne "CRITICAL") {
            $riskLevel = "HIGH"
        }
    }
    
    # Check minimum TLS version
    $minTlsVersion = $StorageAccount.MinimumTlsVersion
    if (-not $minTlsVersion -or $minTlsVersion -lt "TLS1_2") {
        $findings += "Minimum TLS version is $minTlsVersion (should be TLS1_2 or higher)"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check shared key access
    $allowSharedKeyAccess = $StorageAccount.AllowSharedKeyAccess
    if ($allowSharedKeyAccess -ne $false) {
        $findings += "Shared key access is ENABLED (consider Azure AD authentication only)"
    }
    
    # Check network rules
    $networkRuleSet = $StorageAccount.NetworkRuleSet
    $publicNetworkAccess = $StorageAccount.PublicNetworkAccess
    $hasPublicAccess = $true
    $hasFirewallRules = $false
    $hasVNetRules = $false
    
    if ($publicNetworkAccess -eq 'Disabled') {
        $hasPublicAccess = $false
    }
    elseif ($networkRuleSet) {
        if ($networkRuleSet.DefaultAction -eq 'Deny') {
            $hasPublicAccess = $false
        }
        
        if ($networkRuleSet.IpRules -and $networkRuleSet.IpRules.Count -gt 0) {
            $hasFirewallRules = $true
        }
        
        if ($networkRuleSet.VirtualNetworkRules -and $networkRuleSet.VirtualNetworkRules.Count -gt 0) {
            $hasVNetRules = $true
        }
        
        if ($networkRuleSet.Bypass -and $networkRuleSet.Bypass -ne 'None') {
            $findings += "Network bypass allows: $($networkRuleSet.Bypass)"
        }
    }
    
    if ($hasPublicAccess) {
        $findings += "Public network access is ENABLED"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check private endpoints
    $privateEndpoints = $StorageAccount.PrivateEndpointConnections
    $hasPrivateEndpoint = ($privateEndpoints -and $privateEndpoints.Count -gt 0)
    
    if (-not $hasPrivateEndpoint -and $hasPublicAccess) {
        $findings += "No private endpoints configured - relies on public access"
    }
    
    # Check blob soft delete
    $blobServiceProperties = $null
    try {
        Invoke-StealthDelay
        $blobServiceProperties = Get-AzStorageBlobServiceProperty -ResourceGroupName $StorageAccount.ResourceGroupName -StorageAccountName $StorageAccount.StorageAccountName -ErrorAction SilentlyContinue
    }
    catch {
        # May not have permissions
    }
    
    $blobSoftDelete = $false
    $blobSoftDeleteDays = 0
    $containerSoftDelete = $false
    $containerSoftDeleteDays = 0
    $blobVersioning = $false
    
    if ($blobServiceProperties) {
        $blobSoftDelete = $blobServiceProperties.DeleteRetentionPolicy.Enabled
        $blobSoftDeleteDays = $blobServiceProperties.DeleteRetentionPolicy.Days
        $containerSoftDelete = $blobServiceProperties.ContainerDeleteRetentionPolicy.Enabled
        $containerSoftDeleteDays = $blobServiceProperties.ContainerDeleteRetentionPolicy.Days
        $blobVersioning = $blobServiceProperties.IsVersioningEnabled
        
        if (-not $blobSoftDelete) {
            $findings += "Blob soft delete is DISABLED - deleted blobs cannot be recovered"
        }
        
        if (-not $containerSoftDelete) {
            $findings += "Container soft delete is DISABLED - deleted containers cannot be recovered"
        }
        
        if (-not $blobVersioning) {
            $findings += "Blob versioning is DISABLED - no version history maintained"
        }
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
    
    # Check infrastructure encryption
    $infrastructureEncryption = $StorageAccount.Encryption.RequireInfrastructureEncryption
    if (-not $infrastructureEncryption) {
        $findings += "Infrastructure encryption (double encryption) is DISABLED"
    }
    
    # Check cross-tenant replication
    $allowCrossTenantReplication = $StorageAccount.AllowCrossTenantReplication
    if ($allowCrossTenantReplication -eq $true) {
        $findings += "Cross-tenant replication is ALLOWED - data can be replicated to other tenants"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check key rotation
    $oldestKeyAge = -1
    $keysNeedRotation = $false
    if ($KeyDetails -and $KeyDetails.Count -gt 0) {
        $oldestKeyAge = ($KeyDetails | Where-Object { $_.DaysOld -ge 0 } | Measure-Object -Property DaysOld -Maximum).Maximum
        if ($oldestKeyAge -gt $KeyRotationDays) {
            $findings += "Storage account keys are $oldestKeyAge days old (exceeds $KeyRotationDays day threshold)"
            $keysNeedRotation = $true
            if ($riskLevel -eq "LOW") {
                $riskLevel = "MEDIUM"
            }
        }
    }
    
    # Determine final risk level for critical combinations
    if ($anonymousContainerCount -gt 0) {
        $riskLevel = "CRITICAL"
    }
    
    if ($allowBlobPublicAccess -and $hasPublicAccess -and (-not $hasLogging)) {
        $riskLevel = "CRITICAL"
    }
    
    if ((-not $httpsOnly) -and $hasPublicAccess) {
        $riskLevel = "CRITICAL"
    }
    
    return [PSCustomObject]@{
        StorageAccountName = $StorageAccount.StorageAccountName
        ResourceId = $StorageAccount.Id
        ResourceGroupName = $StorageAccount.ResourceGroupName
        SubscriptionId = $Subscription.Id
        SubscriptionName = $Subscription.Name
        Location = $StorageAccount.Location
        Kind = $StorageAccount.Kind
        Sku = $StorageAccount.Sku.Name
        AccessTier = $StorageAccount.AccessTier
        CreationTime = $StorageAccount.CreationTime
        PrimaryEndpoints = $StorageAccount.PrimaryEndpoints
        
        # Security Configuration
        AllowBlobPublicAccess = $allowBlobPublicAccess
        EnableHttpsTrafficOnly = $httpsOnly
        MinimumTlsVersion = $minTlsVersion
        AllowSharedKeyAccess = $allowSharedKeyAccess
        AllowCrossTenantReplication = $allowCrossTenantReplication
        
        # Encryption
        InfrastructureEncryption = $infrastructureEncryption
        EncryptionKeySource = $StorageAccount.Encryption.KeySource
        
        # Network Configuration
        PublicNetworkAccess = $hasPublicAccess
        NetworkDefaultAction = if ($networkRuleSet) { $networkRuleSet.DefaultAction } else { "Allow" }
        HasFirewallRules = $hasFirewallRules
        FirewallRulesCount = if ($networkRuleSet -and $networkRuleSet.IpRules) { $networkRuleSet.IpRules.Count } else { 0 }
        HasVNetRules = $hasVNetRules
        VNetRulesCount = if ($networkRuleSet -and $networkRuleSet.VirtualNetworkRules) { $networkRuleSet.VirtualNetworkRules.Count } else { 0 }
        NetworkBypass = if ($networkRuleSet) { $networkRuleSet.Bypass } else { "None" }
        HasPrivateEndpoint = $hasPrivateEndpoint
        PrivateEndpointCount = if ($privateEndpoints) { $privateEndpoints.Count } else { 0 }
        
        # Data Protection
        BlobSoftDelete = $blobSoftDelete
        BlobSoftDeleteDays = $blobSoftDeleteDays
        ContainerSoftDelete = $containerSoftDelete
        ContainerSoftDeleteDays = $containerSoftDeleteDays
        BlobVersioning = $blobVersioning
        
        # Logging
        HasDiagnosticLogging = $hasLogging
        LogCategories = ($logsEnabled -join ", ")
        
        # Container Analysis
        AnonymousContainerCount = $anonymousContainerCount
        ContainerAccessLevel = $containerAccessLevel
        ContainerFindings = $ContainerFindings
        
        # Key Management
        KeysNeedRotation = $keysNeedRotation
        OldestKeyAge = $oldestKeyAge
        KeyDetails = $KeyDetails
        
        # Risk Assessment
        Findings = $findings
        FindingCount = $findings.Count
        RiskLevel = $riskLevel
        HasMisconfigurations = ($findings.Count -gt 0)
    }
}

# Main scanning function
function Start-StorageAccountScan {
    Write-Host "`n[*] Starting Storage Account security audit..." -ForegroundColor Cyan
    
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
        
        # Get Storage Accounts in this subscription
        $storageAccounts = Get-SubscriptionStorageAccounts -Subscription $subscription
        
        if ($storageAccounts.Count -eq 0) {
            Write-Host "[*] No Storage Accounts found in this subscription" -ForegroundColor Gray
            continue
        }
        
        Write-Host "[+] Found $($storageAccounts.Count) Storage Account(s)" -ForegroundColor Green
        $script:TotalStorageAccounts += $storageAccounts.Count
        
        foreach ($storageAccount in $storageAccounts) {
            Write-Host "[*] Analyzing: $($storageAccount.StorageAccountName)..." -ForegroundColor Cyan
            
            # Get diagnostic settings
            $diagnostics = Get-StorageDiagnostics -ResourceId $storageAccount.Id
            
            # Get containers if requested
            $containerFindings = @()
            if ($IncludeContainers) {
                $containers = Get-StorageContainers -StorageAccount $storageAccount
                if ($containers -and $containers.Count -gt 0) {
                    $containerFindings = Analyze-ContainerPublicAccess -Containers $containers
                }
            }
            
            # Get key details if requested
            $keyDetails = @()
            if ($IncludeKeyAge) {
                $keyDetails = Get-StorageKeyDetails -StorageAccount $storageAccount
            }
            
            # Analyze security
            $finding = Analyze-StorageAccountSecurity -StorageAccount $storageAccount -Subscription $subscription `
                -Diagnostics $diagnostics -ContainerFindings $containerFindings -KeyDetails $keyDetails
            
            # Apply filters
            if ($OnlyCritical -and $finding.RiskLevel -ne "CRITICAL") {
                continue
            }
            
            if ($OnlyPublicAccess -and -not $finding.PublicNetworkAccess -and -not $finding.AllowBlobPublicAccess) {
                continue
            }
            
            if ($OnlyAnonymousContainers -and $finding.AnonymousContainerCount -eq 0) {
                continue
            }
            
            $script:StorageFindings += $finding
        }
    }
    
    Write-Host "`n[+] Storage Account scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 200) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - STORAGE ACCOUNT SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 200) -ForegroundColor Cyan
    
    if ($script:StorageFindings.Count -eq 0) {
        Write-Host "`n[!] No Storage Account findings to display." -ForegroundColor Yellow
        Write-Host ("=" * 200) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:StorageFindings | Sort-Object @{Expression={
        switch($_.RiskLevel) {
            "CRITICAL" { 0 }
            "HIGH" { 1 }
            "MEDIUM" { 2 }
            "LOW" { 3 }
            default { 4 }
        }
    }}, StorageAccountName | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Storage Account';Expression={if($_.StorageAccountName.Length -gt 25){$_.StorageAccountName.Substring(0,22)+"..."}else{$_.StorageAccountName}}},
        @{Name='Subscription';Expression={if($_.SubscriptionName.Length -gt 18){$_.SubscriptionName.Substring(0,15)+"..."}else{$_.SubscriptionName}}},
        @{Name='HTTPS';Expression={if($_.EnableHttpsTrafficOnly){"Yes"}else{"No"}}},
        @{Name='TLS';Expression={$_.MinimumTlsVersion}},
        @{Name='PubBlob';Expression={if($_.AllowBlobPublicAccess){"Yes"}else{"No"}}},
        @{Name='PubNet';Expression={if($_.PublicNetworkAccess){"Yes"}else{"No"}}},
        @{Name='PvtEnd';Expression={if($_.HasPrivateEndpoint){"Yes"}else{"No"}}},
        @{Name='SoftDel';Expression={if($_.BlobSoftDelete){"Yes"}else{"No"}}},
        @{Name='Version';Expression={if($_.BlobVersioning){"Yes"}else{"No"}}},
        @{Name='Logs';Expression={if($_.HasDiagnosticLogging){"Yes"}else{"No"}}},
        @{Name='AnonCont';Expression={$_.AnonymousContainerCount}},
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
    
    Write-Host ("=" * 200) -ForegroundColor Cyan
    
    # Summary statistics
    Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
    Write-Host "Total subscriptions scanned: " -NoNewline -ForegroundColor White
    Write-Host ($script:TotalSubscriptions - $script:SkippedSubscriptions.Count) -ForegroundColor Yellow
    if ($script:SkippedSubscriptions.Count -gt 0) {
        Write-Host "Subscriptions skipped (auth failed): " -NoNewline -ForegroundColor White
        Write-Host $script:SkippedSubscriptions.Count -ForegroundColor Yellow
    }
    Write-Host "Total Storage Accounts analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:StorageFindings.Count -ForegroundColor Yellow
    
    $criticalRisk = ($script:StorageFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:StorageFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:StorageFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:StorageFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Cyan
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    # Configuration gaps
    $noHttps = ($script:StorageFindings | Where-Object { -not $_.EnableHttpsTrafficOnly }).Count
    $publicBlobAccess = ($script:StorageFindings | Where-Object { $_.AllowBlobPublicAccess }).Count
    $publicNetAccess = ($script:StorageFindings | Where-Object { $_.PublicNetworkAccess }).Count
    $noPrivateEndpoint = ($script:StorageFindings | Where-Object { -not $_.HasPrivateEndpoint }).Count
    $noSoftDelete = ($script:StorageFindings | Where-Object { -not $_.BlobSoftDelete }).Count
    $noVersioning = ($script:StorageFindings | Where-Object { -not $_.BlobVersioning }).Count
    $noLogging = ($script:StorageFindings | Where-Object { -not $_.HasDiagnosticLogging }).Count
    $anonymousContainers = ($script:StorageFindings | Where-Object { $_.AnonymousContainerCount -gt 0 }).Count
    
    Write-Host "`n[CONFIGURATION GAPS]" -ForegroundColor Cyan
    Write-Host "  HTTPS not enforced: " -NoNewline -ForegroundColor White
    Write-Host $noHttps -ForegroundColor $(if($noHttps -gt 0){"Red"}else{"Green"})
    Write-Host "  Allow blob public access: " -NoNewline -ForegroundColor White
    Write-Host $publicBlobAccess -ForegroundColor $(if($publicBlobAccess -gt 0){"Yellow"}else{"Green"})
    Write-Host "  Anonymous containers: " -NoNewline -ForegroundColor White
    Write-Host $anonymousContainers -ForegroundColor $(if($anonymousContainers -gt 0){"Red"}else{"Green"})
    Write-Host "  Public network access: " -NoNewline -ForegroundColor White
    Write-Host $publicNetAccess -ForegroundColor $(if($publicNetAccess -gt 0){"Yellow"}else{"Green"})
    Write-Host "  No private endpoint: " -NoNewline -ForegroundColor White
    Write-Host $noPrivateEndpoint -ForegroundColor $(if($noPrivateEndpoint -gt 0){"Yellow"}else{"Green"})
    Write-Host "  No blob soft delete: " -NoNewline -ForegroundColor White
    Write-Host $noSoftDelete -ForegroundColor $(if($noSoftDelete -gt 0){"Yellow"}else{"Green"})
    Write-Host "  No blob versioning: " -NoNewline -ForegroundColor White
    Write-Host $noVersioning -ForegroundColor $(if($noVersioning -gt 0){"Cyan"}else{"Green"})
    Write-Host "  No diagnostic logging: " -NoNewline -ForegroundColor White
    Write-Host $noLogging -ForegroundColor $(if($noLogging -gt 0){"Yellow"}else{"Green"})
    
    # Key rotation summary (if applicable)
    if ($IncludeKeyAge) {
        $keysNeedRotation = ($script:StorageFindings | Where-Object { $_.KeysNeedRotation }).Count
        Write-Host "`n[KEY ROTATION]" -ForegroundColor Cyan
        Write-Host "  Keys needing rotation (>$KeyRotationDays days): " -NoNewline -ForegroundColor White
        Write-Host $keysNeedRotation -ForegroundColor $(if($keysNeedRotation -gt 0){"Yellow"}else{"Green"})
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
    Write-Host "Total Storage Accounts analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:StorageFindings.Count -ForegroundColor Yellow
    
    if ($script:StorageFindings.Count -gt 0) {
        $criticalRisk = ($script:StorageFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:StorageFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:StorageFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:StorageFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "STORAGE ACCOUNT SECURITY DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:StorageFindings | Sort-Object @{Expression={
            switch($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }}, StorageAccountName | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] Storage Account: " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.StorageAccountName -ForegroundColor White
            
            Write-Host "  Subscription: $($_.SubscriptionName)" -ForegroundColor Gray
            Write-Host "  Resource Group: $($_.ResourceGroupName)" -ForegroundColor Gray
            Write-Host "  Location: $($_.Location)" -ForegroundColor Gray
            Write-Host "  Kind: $($_.Kind) | SKU: $($_.Sku)" -ForegroundColor Gray
            
            # Security Configuration
            Write-Host "`n  [Security Configuration]" -ForegroundColor Cyan
            Write-Host "  HTTPS Only: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.EnableHttpsTrafficOnly){"Enabled"}else{"DISABLED"}) -ForegroundColor $(if($_.EnableHttpsTrafficOnly){"Green"}else{"Red"})
            
            Write-Host "  Minimum TLS Version: " -NoNewline -ForegroundColor Gray
            Write-Host $_.MinimumTlsVersion -ForegroundColor $(if($_.MinimumTlsVersion -ge "TLS1_2"){"Green"}else{"Yellow"})
            
            Write-Host "  Allow Blob Public Access: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.AllowBlobPublicAccess){"ENABLED"}else{"Disabled"}) -ForegroundColor $(if($_.AllowBlobPublicAccess){"Yellow"}else{"Green"})
            
            Write-Host "  Shared Key Access: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.AllowSharedKeyAccess -ne $false){"Enabled"}else{"Disabled (Azure AD only)"}) -ForegroundColor $(if($_.AllowSharedKeyAccess -ne $false){"Cyan"}else{"Green"})
            
            Write-Host "  Cross-Tenant Replication: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.AllowCrossTenantReplication){"ENABLED"}else{"Disabled"}) -ForegroundColor $(if($_.AllowCrossTenantReplication){"Yellow"}else{"Green"})
            
            # Encryption
            Write-Host "`n  [Encryption]" -ForegroundColor Cyan
            Write-Host "  Infrastructure Encryption: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.InfrastructureEncryption){"Enabled (double encryption)"}else{"Standard encryption only"}) -ForegroundColor $(if($_.InfrastructureEncryption){"Green"}else{"Cyan"})
            
            Write-Host "  Encryption Key Source: $($_.EncryptionKeySource)" -ForegroundColor Gray
            
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
            Write-Host $_.NetworkBypass -ForegroundColor $(if($_.NetworkBypass -and $_.NetworkBypass -ne 'None'){"Yellow"}else{"Gray"})
            
            # Data Protection
            Write-Host "`n  [Data Protection]" -ForegroundColor Cyan
            Write-Host "  Blob Soft Delete: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.BlobSoftDelete){"Enabled ($($_.BlobSoftDeleteDays) days retention)"}else{"DISABLED"}) -ForegroundColor $(if($_.BlobSoftDelete){"Green"}else{"Yellow"})
            
            Write-Host "  Container Soft Delete: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.ContainerSoftDelete){"Enabled ($($_.ContainerSoftDeleteDays) days retention)"}else{"DISABLED"}) -ForegroundColor $(if($_.ContainerSoftDelete){"Green"}else{"Yellow"})
            
            Write-Host "  Blob Versioning: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.BlobVersioning){"Enabled"}else{"Disabled"}) -ForegroundColor $(if($_.BlobVersioning){"Green"}else{"Cyan"})
            
            # Logging
            Write-Host "`n  [Logging]" -ForegroundColor Cyan
            Write-Host "  Diagnostic Logging: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasDiagnosticLogging){"Enabled - $($_.LogCategories)"}else{"NOT CONFIGURED"}) -ForegroundColor $(if($_.HasDiagnosticLogging){"Green"}else{"Yellow"})
            
            # Anonymous Containers
            if ($_.AnonymousContainerCount -gt 0) {
                Write-Host "`n  [ANONYMOUS CONTAINERS - CRITICAL]" -ForegroundColor Red
                Write-Host "  Count: $($_.AnonymousContainerCount)" -ForegroundColor Red
                Write-Host "  Access Levels: $($_.ContainerAccessLevel)" -ForegroundColor Red
                if ($_.ContainerFindings) {
                    foreach ($cf in $_.ContainerFindings | Select-Object -First 5) {
                        Write-Host "    - $($cf.ContainerName): $($cf.PublicAccess) access" -ForegroundColor Yellow
                    }
                    if ($_.ContainerFindings.Count -gt 5) {
                        Write-Host "    ... and $($_.ContainerFindings.Count - 5) more" -ForegroundColor DarkGray
                    }
                }
            }
            
            # Key Rotation
            if ($IncludeKeyAge -and $_.OldestKeyAge -gt 0) {
                Write-Host "`n  [Key Rotation]" -ForegroundColor Cyan
                Write-Host "  Oldest Key Age: " -NoNewline -ForegroundColor Gray
                Write-Host "$($_.OldestKeyAge) days" -ForegroundColor $(if($_.KeysNeedRotation){"Yellow"}else{"Green"})
                Write-Host "  Needs Rotation: " -NoNewline -ForegroundColor Gray
                Write-Host $(if($_.KeysNeedRotation){"Yes (exceeds $KeyRotationDays days)"}else{"No"}) -ForegroundColor $(if($_.KeysNeedRotation){"Yellow"}else{"Green"})
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
        Write-Host "`n[!] No Storage Account findings to display." -ForegroundColor Yellow
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
    
    if ($script:StorageFindings.Count -eq 0) {
        Write-Host "`n[*] No Storage Account findings to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        # Prepare export data (flatten complex objects)
        $exportData = $script:StorageFindings | Select-Object `
            StorageAccountName, ResourceId, ResourceGroupName, SubscriptionId, SubscriptionName, Location, Kind, Sku, AccessTier, CreationTime,
            AllowBlobPublicAccess, EnableHttpsTrafficOnly, MinimumTlsVersion, AllowSharedKeyAccess, AllowCrossTenantReplication,
            InfrastructureEncryption, EncryptionKeySource,
            PublicNetworkAccess, NetworkDefaultAction, HasFirewallRules, FirewallRulesCount, HasVNetRules, VNetRulesCount, NetworkBypass,
            HasPrivateEndpoint, PrivateEndpointCount,
            BlobSoftDelete, BlobSoftDeleteDays, ContainerSoftDelete, ContainerSoftDeleteDays, BlobVersioning,
            HasDiagnosticLogging, LogCategories,
            AnonymousContainerCount, ContainerAccessLevel,
            KeysNeedRotation, OldestKeyAge,
            @{Name='Findings';Expression={$_.Findings -join "; "}},
            FindingCount, RiskLevel, HasMisconfigurations
        
        switch ($extension) {
            ".csv" {
                $exportData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:StorageFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
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
        Start-StorageAccountScan
        
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
        
        Write-Host "`n[*] Storage Account security check completed successfully!" -ForegroundColor Green
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
