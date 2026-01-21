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
    Identifies cross-service Azure attack paths for privilege escalation and lateral movement across Azure resources.

.DESCRIPTION
    This script performs comprehensive cross-service attack path analysis to identify potential
    privilege escalation paths that span multiple Azure services. Unlike the Entra-focused
    attack path check, this script analyzes how access to one Azure resource can lead to
    compromise of other resources.
    
    Key features:
    - VM Contributor to Key Vault secret access paths (VM can access KV via managed identity)
    - Storage account to compute lateral movement (access to storage can lead to VM compromise)
    - Managed identity privilege escalation (MI with high privileges on other resources)
    - Subscription/management group inheritance abuse (inherited permissions from parent scopes)
    - Custom role definition vulnerabilities (dangerous action combinations)
    - Cross-subscription attack paths (access spanning multiple subscriptions)
    - Service principal with secrets to resource access paths
    - RBAC inheritance exploitation opportunities
    
    Attack paths analyzed include:
    - Compute resources (VMs, VMSS, App Services, Functions) with managed identities accessing secrets
    - Storage accounts with public access or weak authentication leading to data exposure
    - Key Vaults accessible by compute resources or service principals
    - Custom roles with dangerous permission combinations
    - Subscription-wide permissions that enable lateral movement
    
    The script correlates permissions across Azure RBAC, Key Vault access policies,
    storage accounts, and managed identities to identify multi-hop attack paths.

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
    Show only CRITICAL risk attack paths.

.PARAMETER OnlyHighRisk
    Show only CRITICAL or HIGH risk attack paths.

.PARAMETER IncludeInheritedPaths
    Include attack paths that leverage inherited permissions from management groups.

.PARAMETER MaxPathDepth
    Maximum depth for multi-hop attack path analysis (1-5). Default: 3

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.PARAMETER SkipFailedTenants
    Continue processing even when authentication fails for some tenants (common in multi-tenant/guest scenarios).

.EXAMPLE
    .\Invoke-EntraAzureAttackPathCheck.ps1
    # Perform comprehensive cross-service attack path analysis

.EXAMPLE
    .\Invoke-EntraAzureAttackPathCheck.ps1 -ExportPath "azure-attack-paths.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraAzureAttackPathCheck.ps1 -OnlyCritical -Matrix
    # Display only critical attack paths in matrix format

.EXAMPLE
    .\Invoke-EntraAzureAttackPathCheck.ps1 -MaxPathDepth 4 -IncludeInheritedPaths
    # Deep analysis including inherited permission paths

.EXAMPLE
    .\Invoke-EntraAzureAttackPathCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraAzureAttackPathCheck.ps1 -SkipFailedTenants -Matrix
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
    [switch]$OnlyHighRisk,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeInheritedPaths,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 5)]
    [int]$MaxPathDepth = 3,

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

# High-privilege roles that enable attack paths
$script:HighPrivilegeRoles = @(
    'Owner',
    'Contributor',
    'User Access Administrator',
    'Role Based Access Control Administrator',
    'Virtual Machine Contributor',
    'Storage Account Contributor',
    'Storage Blob Data Owner',
    'Storage Blob Data Contributor',
    'Key Vault Administrator',
    'Key Vault Secrets Officer',
    'Key Vault Secrets User',
    'Key Vault Crypto Officer',
    'Key Vault Certificates Officer',
    'Azure Kubernetes Service Cluster Admin Role',
    'Azure Kubernetes Service RBAC Cluster Admin',
    'Logic App Contributor',
    'Automation Contributor',
    'Web Plan Contributor',
    'Website Contributor'
)

# Critical roles that grant extensive access
$script:CriticalRoles = @(
    'Owner',
    'User Access Administrator',
    'Role Based Access Control Administrator'
)

# Roles that can execute code on compute resources
$script:CodeExecutionRoles = @(
    'Owner',
    'Contributor',
    'Virtual Machine Contributor',
    'Virtual Machine Administrator Login',
    'Virtual Machine User Login',
    'Azure Kubernetes Service Cluster Admin Role',
    'Azure Kubernetes Service RBAC Cluster Admin',
    'Logic App Contributor',
    'Automation Contributor',
    'Website Contributor'
)

# Roles that can access secrets/keys
$script:SecretAccessRoles = @(
    'Owner',
    'Contributor',
    'Key Vault Administrator',
    'Key Vault Secrets Officer',
    'Key Vault Secrets User',
    'Key Vault Reader',
    'Key Vault Crypto Officer',
    'Key Vault Certificates Officer'
)

# Dangerous custom role actions
$script:DangerousActions = @(
    'Microsoft.Authorization/*/Write',
    'Microsoft.Authorization/roleAssignments/write',
    'Microsoft.Authorization/roleDefinitions/write',
    '*/write',
    '*/action',
    '*/delete',
    'Microsoft.Compute/virtualMachines/runCommand/action',
    'Microsoft.Compute/virtualMachines/extensions/*',
    'Microsoft.KeyVault/vaults/secrets/*',
    'Microsoft.Storage/storageAccounts/listKeys/action',
    'Microsoft.Resources/subscriptions/resourceGroups/write',
    'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action'
)

# Track state
$script:AttackPaths = @()
$script:TotalPathsFound = 0
$script:TotalSubscriptions = 0
$script:SkippedSubscriptions = @()
$script:AllRoleAssignments = @{}
$script:AllKeyVaults = @{}
$script:AllStorageAccounts = @{}
$script:AllManagedIdentities = @{}
$script:AllVMs = @{}
$script:AllAppServices = @{}
$script:AllCustomRoles = @{}
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
    Write-Host "    Azure Cross-Service Attack Path Analysis" -ForegroundColor Yellow
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
        "Az.Resources",
        "Az.KeyVault",
        "Az.Compute",
        "Az.Storage",
        "Az.Websites",
        "Az.ManagedServiceIdentity"
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
        
        Write-Host "[*] Importing Az.Resources..." -ForegroundColor Cyan
        Import-Module Az.Resources -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.KeyVault..." -ForegroundColor Cyan
        Import-Module Az.KeyVault -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.Compute..." -ForegroundColor Cyan
        Import-Module Az.Compute -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.Storage..." -ForegroundColor Cyan
        Import-Module Az.Storage -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.Websites..." -ForegroundColor Cyan
        Import-Module Az.Websites -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.ManagedServiceIdentity..." -ForegroundColor Cyan
        Import-Module Az.ManagedServiceIdentity -Force -ErrorAction Stop
        
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

# Get role assignments for a subscription
function Get-SubscriptionRoleAssignments {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        $roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$($Subscription.Id)" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        return $roleAssignments
    }
    catch {
        if (-not $SkipFailedTenants) {
            Write-Host "[!] Failed to get role assignments for subscription $($Subscription.Name): $_" -ForegroundColor Yellow
        }
        return @()
    }
}

# Get custom role definitions
function Get-CustomRoleDefinitions {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        $customRoles = Get-AzRoleDefinition -Custom -Scope "/subscriptions/$($Subscription.Id)" -ErrorAction SilentlyContinue
        return $customRoles
    }
    catch {
        return @()
    }
}

# Get Key Vaults in subscription
function Get-SubscriptionKeyVaults {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if (-not $keyVaults) {
            $keyVaults = @()
        }
        
        # Get detailed info for each KV
        $detailedKVs = @()
        foreach ($kv in $keyVaults) {
            $details = Get-AzKeyVault -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName -ErrorAction SilentlyContinue
            if ($details) {
                $detailedKVs += $details
            }
        }
        
        return $detailedKVs
    }
    catch {
        return @()
    }
}

# Get Storage Accounts in subscription
function Get-SubscriptionStorageAccounts {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        $storageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if (-not $storageAccounts) {
            $storageAccounts = @()
        }
        return $storageAccounts
    }
    catch {
        return @()
    }
}

# Get VMs with managed identities
function Get-VMsWithManagedIdentity {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        $vms = Get-AzVM -Status -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
        if (-not $vms) {
            $vms = @()
        }
        
        $vmsWithIdentity = @()
        foreach ($vm in $vms) {
            if ($vm.Identity) {
                $vmsWithIdentity += $vm
            }
        }
        
        return $vmsWithIdentity
    }
    catch {
        return @()
    }
}

# Get App Services with managed identities
function Get-AppServicesWithManagedIdentity {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        $webApps = Get-AzWebApp -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
        if (-not $webApps) {
            $webApps = @()
        }
        
        $appsWithIdentity = @()
        foreach ($app in $webApps) {
            if ($app.Identity) {
                $appsWithIdentity += $app
            }
        }
        
        return $appsWithIdentity
    }
    catch {
        return @()
    }
}

# Get user-assigned managed identities
function Get-UserAssignedManagedIdentities {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        $identities = Get-AzUserAssignedIdentity -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
        if (-not $identities) {
            $identities = @()
        }
        return $identities
    }
    catch {
        return @()
    }
}

# Get role assignments for a specific principal
function Get-RoleAssignmentsForPrincipal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId
    )
    
    $assignments = @()
    
    foreach ($subscriptionAssignments in $script:AllRoleAssignments.Values) {
        $matchingAssignments = $subscriptionAssignments | Where-Object { $_.ObjectId -eq $PrincipalId }
        if ($matchingAssignments) {
            $assignments += $matchingAssignments
        }
    }
    
    return $assignments
}

# Check if principal has Key Vault access
function Test-KeyVaultAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId,
        
        [Parameter(Mandatory = $true)]
        $KeyVaults
    )
    
    $accessibleKVs = @()
    
    foreach ($kv in $KeyVaults) {
        $hasAccess = $false
        $accessType = ""
        $permissions = @()
        
        # Check RBAC
        if ($kv.EnableRbacAuthorization) {
            $assignments = Get-RoleAssignmentsForPrincipal -PrincipalId $PrincipalId
            foreach ($assignment in $assignments) {
                # Check if scope covers this Key Vault
                if ($kv.ResourceId -like "$($assignment.Scope)*" -or $assignment.Scope -like "*$($kv.VaultName)*") {
                    if ($assignment.RoleDefinitionName -in $script:SecretAccessRoles) {
                        $hasAccess = $true
                        $accessType = "RBAC"
                        $permissions += $assignment.RoleDefinitionName
                    }
                }
            }
        }
        
        # Check Access Policies
        if ($kv.AccessPolicies) {
            foreach ($policy in $kv.AccessPolicies) {
                if ($policy.ObjectId -eq $PrincipalId) {
                    $hasAccess = $true
                    $accessType = "AccessPolicy"
                    if ($policy.PermissionsToSecrets) {
                        $permissions += "Secrets: $($policy.PermissionsToSecrets -join ',')"
                    }
                    if ($policy.PermissionsToKeys) {
                        $permissions += "Keys: $($policy.PermissionsToKeys -join ',')"
                    }
                    if ($policy.PermissionsToCertificates) {
                        $permissions += "Certs: $($policy.PermissionsToCertificates -join ',')"
                    }
                }
            }
        }
        
        if ($hasAccess) {
            $accessibleKVs += [PSCustomObject]@{
                VaultName = $kv.VaultName
                VaultUri = $kv.VaultUri
                ResourceId = $kv.ResourceId
                AccessType = $accessType
                Permissions = $permissions -join "; "
                HasSecretAccess = ($permissions -match "Secrets|Secret|all|get|list")
            }
        }
    }
    
    return $accessibleKVs
}

# Check if principal has Storage Account access
function Test-StorageAccountAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId,
        
        [Parameter(Mandatory = $true)]
        $StorageAccounts
    )
    
    $accessibleSAs = @()
    $assignments = Get-RoleAssignmentsForPrincipal -PrincipalId $PrincipalId
    
    foreach ($sa in $StorageAccounts) {
        $hasAccess = $false
        $accessType = ""
        $permissions = @()
        
        foreach ($assignment in $assignments) {
            # Check if scope covers this storage account
            if ($sa.Id -like "$($assignment.Scope)*" -or $assignment.Scope -eq "/subscriptions/$($sa.Id.Split('/')[2])") {
                if ($assignment.RoleDefinitionName -match "Storage|Owner|Contributor") {
                    $hasAccess = $true
                    $accessType = "RBAC"
                    $permissions += $assignment.RoleDefinitionName
                }
            }
        }
        
        if ($hasAccess) {
            $accessibleSAs += [PSCustomObject]@{
                StorageAccountName = $sa.StorageAccountName
                ResourceId = $sa.Id
                AccessType = $accessType
                Permissions = $permissions -join "; "
                AllowBlobPublicAccess = $sa.AllowBlobPublicAccess
                AllowSharedKeyAccess = $sa.AllowSharedKeyAccess
                EnableHttpsTrafficOnly = $sa.EnableHttpsTrafficOnly
            }
        }
    }
    
    return $accessibleSAs
}

# Analyze VM to Key Vault attack path
function Find-VMToKeyVaultPaths {
    param(
        [Parameter(Mandatory = $true)]
        $VM,
        
        [Parameter(Mandatory = $true)]
        $Subscription,
        
        [Parameter(Mandatory = $true)]
        $KeyVaults
    )
    
    $paths = @()
    
    if (-not $VM.Identity -or -not $VM.Identity.PrincipalId) {
        return $paths
    }
    
    $principalId = $VM.Identity.PrincipalId
    
    # Check what Key Vaults this VM's managed identity can access
    $accessibleKVs = Test-KeyVaultAccess -PrincipalId $principalId -KeyVaults $KeyVaults
    
    foreach ($kv in $accessibleKVs) {
        if ($kv.HasSecretAccess) {
            $riskLevel = "HIGH"
            
            # Determine if this is critical
            $vmRoles = Get-RoleAssignmentsForPrincipal -PrincipalId $principalId
            $hasCriticalRole = ($vmRoles | Where-Object { $_.RoleDefinitionName -in $script:CriticalRoles }).Count -gt 0
            
            if ($hasCriticalRole) {
                $riskLevel = "CRITICAL"
            }
            
            $paths += [PSCustomObject]@{
                AttackPathType = "VM to Key Vault Secret Access"
                AttackPathCategory = "Compute-to-Secrets"
                RiskLevel = $riskLevel
                PathComplexity = "Low"
                PathDepth = 1
                
                # Source (Initial Foothold)
                SourceType = "Virtual Machine"
                SourceName = $VM.Name
                SourceResourceId = $VM.Id
                SourceSubscription = $Subscription.Name
                SourceSubscriptionId = $Subscription.Id
                SourceResourceGroup = $VM.ResourceGroupName
                SourcePrincipalId = $principalId
                SourceIdentityType = $VM.Identity.Type
                
                # Target (Compromised Resource)
                TargetType = "Key Vault Secrets"
                TargetName = $kv.VaultName
                TargetResourceId = $kv.ResourceId
                TargetVaultUri = $kv.VaultUri
                
                # Path Details
                PathDescription = "VM '$($VM.Name)' has managed identity with $($kv.AccessType) access to Key Vault '$($kv.VaultName)'"
                AttackNarrative = "Attacker with VM access can use managed identity to retrieve secrets from Key Vault"
                Permissions = $kv.Permissions
                AccessMechanism = $kv.AccessType
                
                # Impact
                PotentialImpact = "Full access to secrets in Key Vault - may contain connection strings, API keys, certificates"
                RemediationGuidance = "Review and minimize managed identity permissions. Use just-in-time access for secrets."
            }
        }
    }
    
    return $paths
}

# Analyze App Service to Key Vault attack path
function Find-AppServiceToKeyVaultPaths {
    param(
        [Parameter(Mandatory = $true)]
        $AppService,
        
        [Parameter(Mandatory = $true)]
        $Subscription,
        
        [Parameter(Mandatory = $true)]
        $KeyVaults
    )
    
    $paths = @()
    
    if (-not $AppService.Identity -or -not $AppService.Identity.PrincipalId) {
        return $paths
    }
    
    $principalId = $AppService.Identity.PrincipalId
    
    # Check what Key Vaults this App Service's managed identity can access
    $accessibleKVs = Test-KeyVaultAccess -PrincipalId $principalId -KeyVaults $KeyVaults
    
    foreach ($kv in $accessibleKVs) {
        if ($kv.HasSecretAccess) {
            $riskLevel = "HIGH"
            
            $paths += [PSCustomObject]@{
                AttackPathType = "App Service to Key Vault Secret Access"
                AttackPathCategory = "Compute-to-Secrets"
                RiskLevel = $riskLevel
                PathComplexity = "Low"
                PathDepth = 1
                
                # Source
                SourceType = "App Service"
                SourceName = $AppService.Name
                SourceResourceId = $AppService.Id
                SourceSubscription = $Subscription.Name
                SourceSubscriptionId = $Subscription.Id
                SourceResourceGroup = $AppService.ResourceGroup
                SourcePrincipalId = $principalId
                SourceIdentityType = $AppService.Identity.Type
                
                # Target
                TargetType = "Key Vault Secrets"
                TargetName = $kv.VaultName
                TargetResourceId = $kv.ResourceId
                TargetVaultUri = $kv.VaultUri
                
                # Path Details
                PathDescription = "App Service '$($AppService.Name)' has managed identity with $($kv.AccessType) access to Key Vault '$($kv.VaultName)'"
                AttackNarrative = "Attacker who compromises App Service can use managed identity to retrieve secrets from Key Vault"
                Permissions = $kv.Permissions
                AccessMechanism = $kv.AccessType
                
                # Impact
                PotentialImpact = "Full access to secrets in Key Vault - may contain connection strings, API keys, certificates"
                RemediationGuidance = "Review and minimize managed identity permissions. Use Key Vault references in App Settings."
            }
        }
    }
    
    return $paths
}

# Analyze managed identity privilege escalation paths
function Find-ManagedIdentityPrivilegeEscalation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId,
        
        [Parameter(Mandatory = $true)]
        [string]$IdentityName,
        
        [Parameter(Mandatory = $true)]
        [string]$IdentityType,
        
        [Parameter(Mandatory = $true)]
        [string]$SourceResourceId,
        
        [Parameter(Mandatory = $true)]
        [string]$SourceResourceType,
        
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    $paths = @()
    
    # Get all role assignments for this identity
    $assignments = Get-RoleAssignmentsForPrincipal -PrincipalId $PrincipalId
    
    foreach ($assignment in $assignments) {
        # Check for high-privilege roles at subscription scope
        if ($assignment.RoleDefinitionName -in $script:CriticalRoles) {
            $scopeType = "Unknown"
            if ($assignment.Scope -match '^/subscriptions/[a-f0-9-]+$') {
                $scopeType = "Subscription"
            }
            elseif ($assignment.Scope -match '/resourceGroups/[^/]+$') {
                $scopeType = "ResourceGroup"
            }
            elseif ($assignment.Scope -match '/providers/Microsoft.Management/managementGroups/') {
                $scopeType = "ManagementGroup"
            }
            elseif ($assignment.Scope -eq '/') {
                $scopeType = "Root"
            }
            
            $riskLevel = "CRITICAL"
            
            $paths += [PSCustomObject]@{
                AttackPathType = "Managed Identity Privilege Escalation"
                AttackPathCategory = "PrivilegeEscalation"
                RiskLevel = $riskLevel
                PathComplexity = "Low"
                PathDepth = 1
                
                # Source
                SourceType = $SourceResourceType
                SourceName = $IdentityName
                SourceResourceId = $SourceResourceId
                SourceSubscription = $Subscription.Name
                SourceSubscriptionId = $Subscription.Id
                SourceResourceGroup = ($SourceResourceId -split '/')[4]
                SourcePrincipalId = $PrincipalId
                SourceIdentityType = $IdentityType
                
                # Target
                TargetType = "$scopeType-wide Access"
                TargetName = $assignment.Scope
                TargetResourceId = $assignment.Scope
                TargetVaultUri = $null
                
                # Path Details
                PathDescription = "Managed identity '$IdentityName' has $($assignment.RoleDefinitionName) role at $scopeType scope"
                AttackNarrative = "Attacker who compromises the compute resource can escalate privileges using managed identity's $($assignment.RoleDefinitionName) role"
                Permissions = $assignment.RoleDefinitionName
                AccessMechanism = "Azure RBAC"
                
                # Impact
                PotentialImpact = "Can assign roles to any identity, create backdoor accounts, access all resources at $scopeType scope"
                RemediationGuidance = "Remove $($assignment.RoleDefinitionName) from managed identity. Use least-privilege roles."
            }
        }
        
        # Check for code execution roles
        if ($assignment.RoleDefinitionName -in $script:CodeExecutionRoles) {
            $riskLevel = "HIGH"
            
            $paths += [PSCustomObject]@{
                AttackPathType = "Managed Identity Lateral Movement"
                AttackPathCategory = "LateralMovement"
                RiskLevel = $riskLevel
                PathComplexity = "Medium"
                PathDepth = 2
                
                # Source
                SourceType = $SourceResourceType
                SourceName = $IdentityName
                SourceResourceId = $SourceResourceId
                SourceSubscription = $Subscription.Name
                SourceSubscriptionId = $Subscription.Id
                SourceResourceGroup = ($SourceResourceId -split '/')[4]
                SourcePrincipalId = $PrincipalId
                SourceIdentityType = $IdentityType
                
                # Target
                TargetType = "Compute Resources"
                TargetName = "Resources at scope: $($assignment.Scope)"
                TargetResourceId = $assignment.Scope
                TargetVaultUri = $null
                
                # Path Details
                PathDescription = "Managed identity '$IdentityName' has $($assignment.RoleDefinitionName) role enabling code execution on other compute resources"
                AttackNarrative = "Attacker can use managed identity's $($assignment.RoleDefinitionName) role to execute code on other VMs/compute resources"
                Permissions = $assignment.RoleDefinitionName
                AccessMechanism = "Azure RBAC"
                
                # Impact
                PotentialImpact = "Lateral movement to other compute resources, access to additional managed identities"
                RemediationGuidance = "Restrict compute management roles to dedicated admin identities only."
            }
        }
    }
    
    return $paths
}

# Analyze custom role vulnerabilities
function Find-CustomRoleVulnerabilities {
    param(
        [Parameter(Mandatory = $true)]
        $CustomRole,
        
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    $paths = @()
    
    if (-not $CustomRole.Actions -and -not $CustomRole.DataActions) {
        return $paths
    }
    
    $allActions = @()
    if ($CustomRole.Actions) { $allActions += $CustomRole.Actions }
    if ($CustomRole.DataActions) { $allActions += $CustomRole.DataActions }
    
    $dangerousActionsFound = @()
    
    foreach ($action in $allActions) {
        foreach ($dangerous in $script:DangerousActions) {
            if ($action -like $dangerous) {
                $dangerousActionsFound += $action
            }
        }
    }
    
    if ($dangerousActionsFound.Count -gt 0) {
        # Check if this role is assigned to anyone
        $roleAssignments = $script:AllRoleAssignments[$Subscription.Id] | Where-Object { 
            $_.RoleDefinitionId -eq $CustomRole.Id -or $_.RoleDefinitionName -eq $CustomRole.Name
        }
        
        if ($roleAssignments -and $roleAssignments.Count -gt 0) {
            $riskLevel = "HIGH"
            
            # Critical if includes role assignment permissions
            if ($dangerousActionsFound -match "roleAssignments|roleDefinitions|Authorization/\*/Write") {
                $riskLevel = "CRITICAL"
            }
            
            $paths += [PSCustomObject]@{
                AttackPathType = "Custom Role Vulnerability"
                AttackPathCategory = "MisconfiguredRole"
                RiskLevel = $riskLevel
                PathComplexity = "Low"
                PathDepth = 1
                
                # Source
                SourceType = "Custom Role Definition"
                SourceName = $CustomRole.Name
                SourceResourceId = $CustomRole.Id
                SourceSubscription = $Subscription.Name
                SourceSubscriptionId = $Subscription.Id
                SourceResourceGroup = "N/A"
                SourcePrincipalId = "N/A"
                SourceIdentityType = "RoleDefinition"
                
                # Target
                TargetType = "Assigned Identities"
                TargetName = "$($roleAssignments.Count) principal(s) assigned"
                TargetResourceId = ($CustomRole.AssignableScopes -join ", ")
                TargetVaultUri = $null
                
                # Path Details
                PathDescription = "Custom role '$($CustomRole.Name)' contains dangerous permissions: $($dangerousActionsFound -join ', ')"
                AttackNarrative = "Any identity assigned this custom role can perform dangerous actions including: $($dangerousActionsFound -join ', ')"
                Permissions = $dangerousActionsFound -join "; "
                AccessMechanism = "Custom Role Definition"
                
                # Impact
                PotentialImpact = "Principals with this role can perform privileged actions that may lead to privilege escalation or data breach"
                RemediationGuidance = "Review and restrict dangerous actions in custom role definition. Use built-in roles where possible."
            }
        }
    }
    
    return $paths
}

# Analyze cross-subscription access paths
function Find-CrossSubscriptionPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId,
        
        [Parameter(Mandatory = $true)]
        [string]$PrincipalName,
        
        [Parameter(Mandatory = $true)]
        [string]$PrincipalType,
        
        [Parameter(Mandatory = $true)]
        [string]$HomeSubscriptionId,
        
        [Parameter(Mandatory = $true)]
        $HomeSubscription
    )
    
    $paths = @()
    
    # Get all role assignments for this principal
    $assignments = Get-RoleAssignmentsForPrincipal -PrincipalId $PrincipalId
    
    foreach ($assignment in $assignments) {
        # Extract subscription from scope
        if ($assignment.Scope -match '/subscriptions/([a-f0-9-]+)') {
            $targetSubId = $Matches[1]
            
            if ($targetSubId -ne $HomeSubscriptionId) {
                $riskLevel = "MEDIUM"
                
                if ($assignment.RoleDefinitionName -in $script:CriticalRoles) {
                    $riskLevel = "CRITICAL"
                }
                elseif ($assignment.RoleDefinitionName -in $script:HighPrivilegeRoles) {
                    $riskLevel = "HIGH"
                }
                
                $paths += [PSCustomObject]@{
                    AttackPathType = "Cross-Subscription Access"
                    AttackPathCategory = "CrossSubscription"
                    RiskLevel = $riskLevel
                    PathComplexity = "Medium"
                    PathDepth = 1
                    
                    # Source
                    SourceType = $PrincipalType
                    SourceName = $PrincipalName
                    SourceResourceId = "N/A"
                    SourceSubscription = $HomeSubscription.Name
                    SourceSubscriptionId = $HomeSubscriptionId
                    SourceResourceGroup = "N/A"
                    SourcePrincipalId = $PrincipalId
                    SourceIdentityType = $PrincipalType
                    
                    # Target
                    TargetType = "Different Subscription"
                    TargetName = "Subscription: $targetSubId"
                    TargetResourceId = $assignment.Scope
                    TargetVaultUri = $null
                    
                    # Path Details
                    PathDescription = "$PrincipalType '$PrincipalName' from subscription '$($HomeSubscription.Name)' has $($assignment.RoleDefinitionName) access to different subscription"
                    AttackNarrative = "Compromising this identity allows lateral movement to a different Azure subscription"
                    Permissions = $assignment.RoleDefinitionName
                    AccessMechanism = "Azure RBAC"
                    
                    # Impact
                    PotentialImpact = "Lateral movement across Azure subscriptions, potential access to sensitive resources in other subscriptions"
                    RemediationGuidance = "Review cross-subscription access. Limit to specific resource groups rather than subscription-wide."
                }
            }
        }
        
        # Check for management group scope
        if ($assignment.Scope -match '/providers/Microsoft.Management/managementGroups/') {
            $riskLevel = "HIGH"
            
            if ($assignment.RoleDefinitionName -in $script:CriticalRoles) {
                $riskLevel = "CRITICAL"
            }
            
            $paths += [PSCustomObject]@{
                AttackPathType = "Management Group Inheritance"
                AttackPathCategory = "InheritedAccess"
                RiskLevel = $riskLevel
                PathComplexity = "Low"
                PathDepth = 1
                
                # Source
                SourceType = $PrincipalType
                SourceName = $PrincipalName
                SourceResourceId = "N/A"
                SourceSubscription = $HomeSubscription.Name
                SourceSubscriptionId = $HomeSubscriptionId
                SourceResourceGroup = "N/A"
                SourcePrincipalId = $PrincipalId
                SourceIdentityType = $PrincipalType
                
                # Target
                TargetType = "Management Group"
                TargetName = $assignment.Scope
                TargetResourceId = $assignment.Scope
                TargetVaultUri = $null
                
                # Path Details
                PathDescription = "$PrincipalType '$PrincipalName' has $($assignment.RoleDefinitionName) access at Management Group scope, inheriting to all child subscriptions"
                AttackNarrative = "Management group access provides inherited permissions to all child subscriptions and resources"
                Permissions = $assignment.RoleDefinitionName
                AccessMechanism = "Azure RBAC Inheritance"
                
                # Impact
                PotentialImpact = "Access to all subscriptions under this management group, widespread lateral movement capability"
                RemediationGuidance = "Limit management group permissions to absolute necessity. Use subscription-level assignments where possible."
            }
        }
    }
    
    return $paths
}

# Analyze storage account lateral movement paths
function Find-StorageAccountLateralMovement {
    param(
        [Parameter(Mandatory = $true)]
        $StorageAccount,
        
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    $paths = @()
    
    # Check for public access or weak security settings
    $hasWeakSecurity = $false
    $weaknessDetails = @()
    
    if ($StorageAccount.AllowBlobPublicAccess) {
        $hasWeakSecurity = $true
        $weaknessDetails += "Public blob access enabled"
    }
    
    if ($StorageAccount.AllowSharedKeyAccess) {
        $hasWeakSecurity = $true
        $weaknessDetails += "Shared key access enabled"
    }
    
    if (-not $StorageAccount.EnableHttpsTrafficOnly) {
        $hasWeakSecurity = $true
        $weaknessDetails += "HTTP traffic allowed"
    }
    
    # Check network rules
    $hasPublicNetwork = $true
    if ($StorageAccount.NetworkRuleSet -and $StorageAccount.NetworkRuleSet.DefaultAction -eq 'Deny') {
        $hasPublicNetwork = $false
    }
    else {
        $weaknessDetails += "Public network access enabled"
    }
    
    # Get identities with storage access
    $assignments = $script:AllRoleAssignments[$Subscription.Id] | Where-Object {
        $_.Scope -like "*$($StorageAccount.StorageAccountName)*" -or
        $_.Scope -eq "/subscriptions/$($Subscription.Id)" -or
        $_.Scope -like "/subscriptions/$($Subscription.Id)/resourceGroups/$($StorageAccount.ResourceGroupName)*"
    }
    
    $storageAccessors = $assignments | Where-Object {
        $_.RoleDefinitionName -match "Storage|Owner|Contributor"
    }
    
    if ($hasWeakSecurity -and $storageAccessors.Count -gt 0) {
        $riskLevel = "MEDIUM"
        
        if ($hasPublicNetwork -and $StorageAccount.AllowBlobPublicAccess) {
            $riskLevel = "HIGH"
        }
        
        $paths += [PSCustomObject]@{
            AttackPathType = "Storage Account Weak Security"
            AttackPathCategory = "DataExfiltration"
            RiskLevel = $riskLevel
            PathComplexity = "Low"
            PathDepth = 1
            
            # Source
            SourceType = "Storage Account"
            SourceName = $StorageAccount.StorageAccountName
            SourceResourceId = $StorageAccount.Id
            SourceSubscription = $Subscription.Name
            SourceSubscriptionId = $Subscription.Id
            SourceResourceGroup = $StorageAccount.ResourceGroupName
            SourcePrincipalId = "N/A"
            SourceIdentityType = "Resource"
            
            # Target
            TargetType = "Storage Data"
            TargetName = $StorageAccount.StorageAccountName
            TargetResourceId = $StorageAccount.Id
            TargetVaultUri = $null
            
            # Path Details
            PathDescription = "Storage account '$($StorageAccount.StorageAccountName)' has security weaknesses: $($weaknessDetails -join ', ')"
            AttackNarrative = "Weak storage security settings may allow unauthorized data access or exfiltration"
            Permissions = "$($storageAccessors.Count) identities have storage access"
            AccessMechanism = "Storage API/Blob Access"
            
            # Impact
            PotentialImpact = "Data exfiltration, storage of malicious content, lateral movement via scripts/artifacts in storage"
            RemediationGuidance = "Disable public access, require HTTPS, use Azure AD auth instead of shared keys, restrict network access."
        }
    }
    
    return $paths
}

# Main scanning function
function Start-AttackPathScan {
    Write-Host "`n[*] Starting cross-service Azure attack path analysis..." -ForegroundColor Cyan
    Write-Host "[*] Maximum path depth: $MaxPathDepth" -ForegroundColor Cyan
    
    # Get subscriptions
    $subscriptions = Get-AccessibleSubscriptions
    
    if ($subscriptions.Count -eq 0) {
        Write-Host "[ERROR] No accessible subscriptions found. Cannot proceed." -ForegroundColor Red
        return
    }
    
    $script:TotalSubscriptions = $subscriptions.Count
    
    # Phase 1: Collect all resources and role assignments
    Write-Host "`n[*] Phase 1: Collecting resources and role assignments..." -ForegroundColor Cyan
    
    $progressCounter = 0
    foreach ($subscription in $subscriptions) {
        $progressCounter++
        Write-Host "`n[*] Collecting from subscription $progressCounter/$($subscriptions.Count): $($subscription.Name)" -ForegroundColor Cyan
        
        # Set context
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
        
        # Collect role assignments
        Write-Host "[*] Collecting role assignments..." -ForegroundColor Gray
        $roleAssignments = Get-SubscriptionRoleAssignments -Subscription $subscription
        $script:AllRoleAssignments[$subscription.Id] = $roleAssignments
        Write-Host "[+] Found $($roleAssignments.Count) role assignments" -ForegroundColor Green
        
        # Collect custom roles
        Write-Host "[*] Collecting custom role definitions..." -ForegroundColor Gray
        $customRoles = Get-CustomRoleDefinitions -Subscription $subscription
        $script:AllCustomRoles[$subscription.Id] = $customRoles
        Write-Host "[+] Found $($customRoles.Count) custom roles" -ForegroundColor Green
        
        # Collect Key Vaults
        Write-Host "[*] Collecting Key Vaults..." -ForegroundColor Gray
        $keyVaults = Get-SubscriptionKeyVaults -Subscription $subscription
        $script:AllKeyVaults[$subscription.Id] = $keyVaults
        Write-Host "[+] Found $($keyVaults.Count) Key Vaults" -ForegroundColor Green
        
        # Collect Storage Accounts
        Write-Host "[*] Collecting Storage Accounts..." -ForegroundColor Gray
        $storageAccounts = Get-SubscriptionStorageAccounts -Subscription $subscription
        $script:AllStorageAccounts[$subscription.Id] = $storageAccounts
        Write-Host "[+] Found $($storageAccounts.Count) Storage Accounts" -ForegroundColor Green
        
        # Collect VMs with managed identities
        Write-Host "[*] Collecting VMs with managed identities..." -ForegroundColor Gray
        $vmsWithIdentity = Get-VMsWithManagedIdentity -Subscription $subscription
        $script:AllVMs[$subscription.Id] = $vmsWithIdentity
        Write-Host "[+] Found $($vmsWithIdentity.Count) VMs with managed identities" -ForegroundColor Green
        
        # Collect App Services with managed identities
        Write-Host "[*] Collecting App Services with managed identities..." -ForegroundColor Gray
        $appServicesWithIdentity = Get-AppServicesWithManagedIdentity -Subscription $subscription
        $script:AllAppServices[$subscription.Id] = $appServicesWithIdentity
        Write-Host "[+] Found $($appServicesWithIdentity.Count) App Services with managed identities" -ForegroundColor Green
        
        # Collect user-assigned managed identities
        Write-Host "[*] Collecting user-assigned managed identities..." -ForegroundColor Gray
        $userAssignedIdentities = Get-UserAssignedManagedIdentities -Subscription $subscription
        $script:AllManagedIdentities[$subscription.Id] = $userAssignedIdentities
        Write-Host "[+] Found $($userAssignedIdentities.Count) user-assigned managed identities" -ForegroundColor Green
    }
    
    # Phase 2: Analyze attack paths
    Write-Host "`n[*] Phase 2: Analyzing attack paths..." -ForegroundColor Cyan
    
    $progressCounter = 0
    foreach ($subscription in $subscriptions) {
        $progressCounter++
        
        if ($subscription.Name -in $script:SkippedSubscriptions) {
            continue
        }
        
        Write-Host "`n[*] Analyzing subscription $progressCounter/$($subscriptions.Count): $($subscription.Name)" -ForegroundColor Cyan
        
        # Get resources for this subscription
        $keyVaults = $script:AllKeyVaults[$subscription.Id]
        $storageAccounts = $script:AllStorageAccounts[$subscription.Id]
        $vms = $script:AllVMs[$subscription.Id]
        $appServices = $script:AllAppServices[$subscription.Id]
        $customRoles = $script:AllCustomRoles[$subscription.Id]
        $managedIdentities = $script:AllManagedIdentities[$subscription.Id]
        
        # Analyze VM to Key Vault paths
        if ($vms -and $keyVaults) {
            Write-Host "[*] Analyzing VM to Key Vault attack paths..." -ForegroundColor Gray
            foreach ($vm in $vms) {
                $vmPaths = Find-VMToKeyVaultPaths -VM $vm -Subscription $subscription -KeyVaults $keyVaults
                $script:AttackPaths += $vmPaths
            }
        }
        
        # Analyze App Service to Key Vault paths
        if ($appServices -and $keyVaults) {
            Write-Host "[*] Analyzing App Service to Key Vault attack paths..." -ForegroundColor Gray
            foreach ($app in $appServices) {
                $appPaths = Find-AppServiceToKeyVaultPaths -AppService $app -Subscription $subscription -KeyVaults $keyVaults
                $script:AttackPaths += $appPaths
            }
        }
        
        # Analyze managed identity privilege escalation
        Write-Host "[*] Analyzing managed identity privilege escalation paths..." -ForegroundColor Gray
        
        # System-assigned on VMs
        foreach ($vm in $vms) {
            if ($vm.Identity -and $vm.Identity.PrincipalId) {
                $miPaths = Find-ManagedIdentityPrivilegeEscalation `
                    -PrincipalId $vm.Identity.PrincipalId `
                    -IdentityName "$($vm.Name) (System-Assigned)" `
                    -IdentityType "SystemAssigned" `
                    -SourceResourceId $vm.Id `
                    -SourceResourceType "Virtual Machine" `
                    -Subscription $subscription
                $script:AttackPaths += $miPaths
            }
        }
        
        # System-assigned on App Services
        foreach ($app in $appServices) {
            if ($app.Identity -and $app.Identity.PrincipalId) {
                $miPaths = Find-ManagedIdentityPrivilegeEscalation `
                    -PrincipalId $app.Identity.PrincipalId `
                    -IdentityName "$($app.Name) (System-Assigned)" `
                    -IdentityType "SystemAssigned" `
                    -SourceResourceId $app.Id `
                    -SourceResourceType "App Service" `
                    -Subscription $subscription
                $script:AttackPaths += $miPaths
            }
        }
        
        # User-assigned managed identities
        foreach ($mi in $managedIdentities) {
            $miPaths = Find-ManagedIdentityPrivilegeEscalation `
                -PrincipalId $mi.PrincipalId `
                -IdentityName $mi.Name `
                -IdentityType "UserAssigned" `
                -SourceResourceId $mi.Id `
                -SourceResourceType "User-Assigned Managed Identity" `
                -Subscription $subscription
            $script:AttackPaths += $miPaths
            
            # Cross-subscription paths
            $crossSubPaths = Find-CrossSubscriptionPaths `
                -PrincipalId $mi.PrincipalId `
                -PrincipalName $mi.Name `
                -PrincipalType "Managed Identity" `
                -HomeSubscriptionId $subscription.Id `
                -HomeSubscription $subscription
            $script:AttackPaths += $crossSubPaths
        }
        
        # Analyze custom role vulnerabilities
        if ($customRoles) {
            Write-Host "[*] Analyzing custom role vulnerabilities..." -ForegroundColor Gray
            foreach ($role in $customRoles) {
                $rolePaths = Find-CustomRoleVulnerabilities -CustomRole $role -Subscription $subscription
                $script:AttackPaths += $rolePaths
            }
        }
        
        # Analyze storage account lateral movement
        if ($storageAccounts) {
            Write-Host "[*] Analyzing storage account security..." -ForegroundColor Gray
            foreach ($sa in $storageAccounts) {
                $saPaths = Find-StorageAccountLateralMovement -StorageAccount $sa -Subscription $subscription
                $script:AttackPaths += $saPaths
            }
        }
        
        # Analyze inherited paths if requested
        if ($IncludeInheritedPaths) {
            Write-Host "[*] Analyzing inherited permission paths..." -ForegroundColor Gray
            $roleAssignments = $script:AllRoleAssignments[$subscription.Id]
            
            foreach ($assignment in $roleAssignments) {
                if ($assignment.ObjectType -match "ServicePrincipal|ManagedIdentity") {
                    $crossSubPaths = Find-CrossSubscriptionPaths `
                        -PrincipalId $assignment.ObjectId `
                        -PrincipalName $assignment.DisplayName `
                        -PrincipalType $assignment.ObjectType `
                        -HomeSubscriptionId $subscription.Id `
                        -HomeSubscription $subscription
                    $script:AttackPaths += $crossSubPaths
                }
            }
        }
    }
    
    # Apply filters
    if ($OnlyCritical) {
        $script:AttackPaths = $script:AttackPaths | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    }
    elseif ($OnlyHighRisk) {
        $script:AttackPaths = $script:AttackPaths | Where-Object { $_.RiskLevel -eq "CRITICAL" -or $_.RiskLevel -eq "HIGH" }
    }
    
    # Remove duplicates
    $script:AttackPaths = $script:AttackPaths | Sort-Object -Property @{Expression={$_.AttackPathType}}, @{Expression={$_.SourceName}}, @{Expression={$_.TargetName}} -Unique
    
    $script:TotalPathsFound = $script:AttackPaths.Count
    
    Write-Host "`n[+] Attack path analysis complete!" -ForegroundColor Green
    Write-Host "[+] Total attack paths identified: $($script:TotalPathsFound)" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 220) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - AZURE CROSS-SERVICE ATTACK PATH ANALYSIS" -ForegroundColor Cyan
    Write-Host ("=" * 220) -ForegroundColor Cyan
    
    if ($script:AttackPaths.Count -eq 0) {
        Write-Host "`n[+] No attack paths found matching the criteria." -ForegroundColor Green
        Write-Host ("=" * 220) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:AttackPaths | Sort-Object @{Expression={
        switch($_.RiskLevel) {
            "CRITICAL" { 0 }
            "HIGH" { 1 }
            "MEDIUM" { 2 }
            "LOW" { 3 }
            default { 4 }
        }
    }}, AttackPathType | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Path Type';Expression={if($_.AttackPathType.Length -gt 35){$_.AttackPathType.Substring(0,32)+"..."}else{$_.AttackPathType}}},
        @{Name='Category';Expression={$_.AttackPathCategory}},
        @{Name='Source';Expression={if($_.SourceName.Length -gt 30){$_.SourceName.Substring(0,27)+"..."}else{$_.SourceName}}},
        @{Name='Source Type';Expression={if($_.SourceType.Length -gt 20){$_.SourceType.Substring(0,17)+"..."}else{$_.SourceType}}},
        @{Name='Target';Expression={if($_.TargetName.Length -gt 30){$_.TargetName.Substring(0,27)+"..."}else{$_.TargetName}}},
        @{Name='Target Type';Expression={if($_.TargetType.Length -gt 20){$_.TargetType.Substring(0,17)+"..."}else{$_.TargetType}}},
        @{Name='Complexity';Expression={$_.PathComplexity}},
        @{Name='Depth';Expression={$_.PathDepth}}
    
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
    
    Write-Host ("=" * 220) -ForegroundColor Cyan
    
    # Summary statistics
    Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
    Write-Host "Total subscriptions scanned: " -NoNewline -ForegroundColor White
    Write-Host ($script:TotalSubscriptions - $script:SkippedSubscriptions.Count) -ForegroundColor Yellow
    if ($script:SkippedSubscriptions.Count -gt 0) {
        Write-Host "Subscriptions skipped (auth failed): " -NoNewline -ForegroundColor White
        Write-Host $script:SkippedSubscriptions.Count -ForegroundColor Yellow
    }
    Write-Host "Total attack paths identified: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalPathsFound -ForegroundColor Yellow
    
    $criticalRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "`n[RISK DISTRIBUTION]" -ForegroundColor Cyan
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Cyan
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    # Attack path categories
    $byCategory = $script:AttackPaths | Group-Object AttackPathCategory | Sort-Object Count -Descending
    if ($byCategory.Count -gt 0) {
        Write-Host "`n[ATTACK PATH CATEGORIES]" -ForegroundColor Cyan
        foreach ($cat in $byCategory) {
            Write-Host "  $($cat.Name): " -NoNewline -ForegroundColor White
            Write-Host $cat.Count -ForegroundColor Yellow
        }
    }
    
    # Top affected resources
    $bySource = $script:AttackPaths | Group-Object SourceName | Sort-Object Count -Descending | Select-Object -First 5
    if ($bySource.Count -gt 0) {
        Write-Host "`n[TOP AFFECTED RESOURCES]" -ForegroundColor Cyan
        foreach ($src in $bySource) {
            Write-Host "  $($src.Name): " -NoNewline -ForegroundColor White
            Write-Host "$($src.Count) attack path(s)" -ForegroundColor Yellow
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
    Write-Host "Total attack paths identified: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalPathsFound -ForegroundColor Yellow
    
    if ($script:AttackPaths.Count -gt 0) {
        $criticalRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "ATTACK PATH DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:AttackPaths | Sort-Object @{Expression={
            switch($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }}, AttackPathType | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host "$($_.AttackPathType)" -ForegroundColor White
            
            Write-Host "  Category: $($_.AttackPathCategory) | Complexity: $($_.PathComplexity) | Depth: $($_.PathDepth)" -ForegroundColor Gray
            
            # Source
            Write-Host "`n  [Source - Initial Foothold]" -ForegroundColor Cyan
            Write-Host "    Type: $($_.SourceType)" -ForegroundColor Gray
            Write-Host "    Name: $($_.SourceName)" -ForegroundColor Gray
            Write-Host "    Subscription: $($_.SourceSubscription)" -ForegroundColor Gray
            if ($_.SourceResourceGroup -and $_.SourceResourceGroup -ne "N/A") {
                Write-Host "    Resource Group: $($_.SourceResourceGroup)" -ForegroundColor Gray
            }
            if ($_.SourcePrincipalId -and $_.SourcePrincipalId -ne "N/A") {
                Write-Host "    Principal ID: $($_.SourcePrincipalId)" -ForegroundColor Gray
            }
            
            # Target
            Write-Host "`n  [Target - Compromised Resource]" -ForegroundColor Cyan
            Write-Host "    Type: $($_.TargetType)" -ForegroundColor Gray
            Write-Host "    Name: $($_.TargetName)" -ForegroundColor Gray
            if ($_.TargetVaultUri) {
                Write-Host "    Vault URI: $($_.TargetVaultUri)" -ForegroundColor Gray
            }
            
            # Path Details
            Write-Host "`n  [Attack Path]" -ForegroundColor $riskColor
            Write-Host "    Description: $($_.PathDescription)" -ForegroundColor Gray
            Write-Host "    Attack Narrative: $($_.AttackNarrative)" -ForegroundColor Yellow
            Write-Host "    Permissions: $($_.Permissions)" -ForegroundColor Gray
            Write-Host "    Access Mechanism: $($_.AccessMechanism)" -ForegroundColor Gray
            
            # Impact and Remediation
            Write-Host "`n  [Impact]" -ForegroundColor Red
            Write-Host "    $($_.PotentialImpact)" -ForegroundColor Yellow
            
            Write-Host "`n  [Remediation]" -ForegroundColor Green
            Write-Host "    $($_.RemediationGuidance)" -ForegroundColor Gray
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[+] No attack paths found matching the criteria." -ForegroundColor Green
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
    
    if ($script:AttackPaths.Count -eq 0) {
        Write-Host "`n[*] No attack paths to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:AttackPaths | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:AttackPaths | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:AttackPaths | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-AttackPathScan
        
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
        
        Write-Host "`n[*] Azure attack path analysis completed successfully!" -ForegroundColor Green
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
