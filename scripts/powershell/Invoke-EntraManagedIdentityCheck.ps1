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
    Comprehensive Azure Managed Identity security audit for identifying excessive permissions and security risks.

.DESCRIPTION
    This script performs a deep analysis of Azure Managed Identity configurations to identify
    potential vulnerabilities and security risks that could lead to privilege escalation,
    lateral movement, or unauthorized access.
    
    Key features:
    - System-assigned vs user-assigned managed identity inventory
    - Managed identity role assignment analysis (Azure RBAC)
    - High-privilege managed identity detection (Owner, Contributor, etc.)
    - Cross-subscription managed identity access detection
    - Unused managed identity identification
    - App Service/Function managed identity permission analysis
    - Virtual Machine managed identity enumeration
    - Container and AKS managed identity analysis
    - Federation and workload identity configuration review
    
    The script uses Azure PowerShell authentication to query managed identity configurations
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
    Show only Managed Identities with CRITICAL risk findings.

.PARAMETER OnlyHighPrivilege
    Show only Managed Identities with high-privilege role assignments (Owner, Contributor, User Access Administrator).

.PARAMETER OnlyCrossSubscription
    Show only Managed Identities with cross-subscription access.

.PARAMETER OnlyUnused
    Show only Managed Identities that appear to be unused (no recent sign-in activity).

.PARAMETER IncludeRoleDetails
    Include detailed role assignment information for each managed identity.

.PARAMETER UnusedDays
    Number of days without activity to flag a managed identity as potentially unused. Default: 90

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.PARAMETER SkipFailedTenants
    Continue processing even when authentication fails for some tenants (common in multi-tenant/guest scenarios).
    Suppresses MFA/Conditional Access warnings for tenants you can't access.

.EXAMPLE
    .\Invoke-EntraManagedIdentityCheck.ps1
    # Perform comprehensive Managed Identity security audit

.EXAMPLE
    .\Invoke-EntraManagedIdentityCheck.ps1 -ExportPath "managed-identity-audit.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraManagedIdentityCheck.ps1 -OnlyCritical -Matrix
    # Display only critical findings in matrix format

.EXAMPLE
    .\Invoke-EntraManagedIdentityCheck.ps1 -OnlyHighPrivilege -Matrix
    # Show only managed identities with high-privilege roles

.EXAMPLE
    .\Invoke-EntraManagedIdentityCheck.ps1 -OnlyCrossSubscription
    # Show only managed identities with cross-subscription access

.EXAMPLE
    .\Invoke-EntraManagedIdentityCheck.ps1 -OnlyUnused -UnusedDays 60
    # Find managed identities with no activity in the last 60 days

.EXAMPLE
    .\Invoke-EntraManagedIdentityCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraManagedIdentityCheck.ps1 -SkipFailedTenants -Matrix
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
    [switch]$OnlyHighPrivilege,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyCrossSubscription,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyUnused,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeRoleDetails,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$UnusedDays = 90,

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

# High-privilege roles that represent significant security risk
$script:HighPrivilegeRoles = @(
    'Owner',
    'Contributor',
    'User Access Administrator',
    'Role Based Access Control Administrator',
    'Virtual Machine Contributor',
    'Storage Account Contributor',
    'Storage Blob Data Owner',
    'Key Vault Administrator',
    'Key Vault Secrets Officer',
    'Key Vault Crypto Officer',
    'Azure Kubernetes Service Cluster Admin Role',
    'Azure Kubernetes Service RBAC Cluster Admin'
)

# Critical roles that warrant immediate attention
$script:CriticalRoles = @(
    'Owner',
    'User Access Administrator',
    'Role Based Access Control Administrator'
)

# Track state
$script:ManagedIdentityFindings = @()
$script:TotalManagedIdentities = 0
$script:TotalSystemAssigned = 0
$script:TotalUserAssigned = 0
$script:TotalSubscriptions = 0
$script:SkippedSubscriptions = @()
$script:AllRoleAssignments = @{}
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
    Write-Host "    Azure Managed Identity Security Audit" -ForegroundColor Yellow
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
        "Az.ManagedServiceIdentity",
        "Az.Compute",
        "Az.Websites",
        "Az.Functions"
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
        
        Write-Host "[*] Importing Az.ManagedServiceIdentity..." -ForegroundColor Cyan
        Import-Module Az.ManagedServiceIdentity -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.Compute..." -ForegroundColor Cyan
        Import-Module Az.Compute -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.Websites..." -ForegroundColor Cyan
        Import-Module Az.Websites -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.Functions..." -ForegroundColor Cyan
        Import-Module Az.Functions -Force -ErrorAction Stop
        
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

# Get all role assignments for a subscription
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

# Get user-assigned managed identities in a subscription
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
        if (-not $SkipFailedTenants) {
            Write-Host "[!] Failed to get user-assigned identities in subscription $($Subscription.Name): $_" -ForegroundColor Yellow
        }
        return @()
    }
}

# Get VMs with system-assigned managed identities
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
        if (-not $SkipFailedTenants) {
            Write-Host "[!] Failed to get VMs in subscription $($Subscription.Name): $_" -ForegroundColor Yellow
        }
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
        if (-not $SkipFailedTenants) {
            Write-Host "[!] Failed to get App Services in subscription $($Subscription.Name): $_" -ForegroundColor Yellow
        }
        return @()
    }
}

# Get Function Apps with managed identities
function Get-FunctionAppsWithManagedIdentity {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        # Get all resource groups first, then get function apps per RG
        $resourceGroups = Get-AzResourceGroup -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
        if (-not $resourceGroups) {
            return @()
        }
        
        $functionApps = @()
        foreach ($rg in $resourceGroups) {
            $apps = Get-AzFunctionApp -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
            if ($apps) {
                foreach ($app in $apps) {
                    if ($app.IdentityType -and $app.IdentityType -ne 'None') {
                        $functionApps += $app
                    }
                }
            }
        }
        
        return $functionApps
    }
    catch {
        if (-not $SkipFailedTenants) {
            Write-Host "[!] Failed to get Function Apps in subscription $($Subscription.Name): $_" -ForegroundColor Yellow
        }
        return @()
    }
}

# Get role assignments for a specific principal (managed identity)
function Get-RoleAssignmentsForPrincipal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId,
        
        [Parameter(Mandatory = $true)]
        $AllRoleAssignments
    )
    
    $assignments = @()
    
    foreach ($subscriptionAssignments in $AllRoleAssignments.Values) {
        $matchingAssignments = $subscriptionAssignments | Where-Object { $_.ObjectId -eq $PrincipalId }
        if ($matchingAssignments) {
            $assignments += $matchingAssignments
        }
    }
    
    return $assignments
}

# Check if identity has cross-subscription access
function Test-CrossSubscriptionAccess {
    param(
        [Parameter(Mandatory = $true)]
        $RoleAssignments,
        
        [Parameter(Mandatory = $true)]
        [string]$HomeSubscriptionId
    )
    
    $crossSubAccess = @()
    
    foreach ($assignment in $RoleAssignments) {
        $assignmentScope = $assignment.Scope
        
        # Extract subscription ID from scope
        if ($assignmentScope -match '/subscriptions/([a-f0-9-]+)') {
            $assignmentSubId = $Matches[1]
            if ($assignmentSubId -ne $HomeSubscriptionId) {
                $crossSubAccess += [PSCustomObject]@{
                    Scope = $assignment.Scope
                    RoleName = $assignment.RoleDefinitionName
                    SubscriptionId = $assignmentSubId
                }
            }
        }
        # Check for management group or root scope
        elseif ($assignmentScope -match '/providers/Microsoft.Management/managementGroups/' -or $assignmentScope -eq '/') {
            $crossSubAccess += [PSCustomObject]@{
                Scope = $assignment.Scope
                RoleName = $assignment.RoleDefinitionName
                SubscriptionId = "ManagementGroup/Root"
            }
        }
    }
    
    return $crossSubAccess
}

# Analyze managed identity for security issues
function Analyze-ManagedIdentitySecurity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId,
        
        [Parameter(Mandatory = $true)]
        [string]$IdentityName,
        
        [Parameter(Mandatory = $true)]
        [string]$IdentityType,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceType,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceId,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        $Subscription,
        
        [Parameter(Mandatory = $true)]
        $RoleAssignments,
        
        [Parameter(Mandatory = $false)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string]$Location
    )
    
    $findings = @()
    $riskLevel = "LOW"
    
    # Analyze role assignments
    $highPrivilegeRoles = @()
    $criticalRoles = @()
    $allRoleDetails = @()
    
    foreach ($assignment in $RoleAssignments) {
        $roleDetail = [PSCustomObject]@{
            RoleName = $assignment.RoleDefinitionName
            Scope = $assignment.Scope
            ScopeType = if ($assignment.Scope -match '/subscriptions/[^/]+$') { "Subscription" }
                        elseif ($assignment.Scope -match '/resourceGroups/[^/]+$') { "ResourceGroup" }
                        elseif ($assignment.Scope -match '/providers/Microsoft.Management/managementGroups/') { "ManagementGroup" }
                        elseif ($assignment.Scope -eq '/') { "Root" }
                        else { "Resource" }
            RoleDefinitionId = $assignment.RoleDefinitionId
        }
        $allRoleDetails += $roleDetail
        
        if ($assignment.RoleDefinitionName -in $script:HighPrivilegeRoles) {
            $highPrivilegeRoles += $assignment.RoleDefinitionName
        }
        
        if ($assignment.RoleDefinitionName -in $script:CriticalRoles) {
            $criticalRoles += $assignment.RoleDefinitionName
        }
    }
    
    # Check for critical roles
    if ($criticalRoles.Count -gt 0) {
        $findings += "Has CRITICAL role assignments: $($criticalRoles -join ', ')"
        $riskLevel = "CRITICAL"
    }
    
    # Check for high-privilege roles
    if ($highPrivilegeRoles.Count -gt 0 -and $riskLevel -ne "CRITICAL") {
        $findings += "Has high-privilege role assignments: $($highPrivilegeRoles -join ', ')"
        if ($riskLevel -ne "CRITICAL") {
            $riskLevel = "HIGH"
        }
    }
    
    # Check for cross-subscription access
    $crossSubAccess = Test-CrossSubscriptionAccess -RoleAssignments $RoleAssignments -HomeSubscriptionId $Subscription.Id
    $hasCrossSubAccess = ($crossSubAccess.Count -gt 0)
    
    if ($hasCrossSubAccess) {
        $crossSubScopes = ($crossSubAccess | ForEach-Object { $_.SubscriptionId } | Select-Object -Unique) -join ', '
        $findings += "Has CROSS-SUBSCRIPTION access to: $crossSubScopes"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check for management group or root level access
    $mgmtGroupAccess = $RoleAssignments | Where-Object { 
        $_.Scope -match '/providers/Microsoft.Management/managementGroups/' -or $_.Scope -eq '/'
    }
    
    if ($mgmtGroupAccess) {
        $findings += "Has MANAGEMENT GROUP or ROOT level access"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check for subscription-wide access
    $subWideAccess = $RoleAssignments | Where-Object { 
        $_.Scope -match '^/subscriptions/[a-f0-9-]+$'
    }
    
    if ($subWideAccess) {
        $subWideRoles = ($subWideAccess | ForEach-Object { $_.RoleDefinitionName } | Select-Object -Unique) -join ', '
        $findings += "Has subscription-wide access with roles: $subWideRoles"
    }
    
    # Check if identity has no role assignments (potentially unused or orphaned)
    $hasNoRoles = ($RoleAssignments.Count -eq 0)
    if ($hasNoRoles) {
        $findings += "No role assignments found (potentially unused or recently created)"
    }
    
    # Count role assignment scopes
    $subscriptionScopeCount = ($RoleAssignments | Where-Object { $_.Scope -match '^/subscriptions/[a-f0-9-]+$' }).Count
    $resourceGroupScopeCount = ($RoleAssignments | Where-Object { $_.Scope -match '/resourceGroups/[^/]+$' }).Count
    $resourceScopeCount = ($RoleAssignments | Where-Object { 
        $_.Scope -notmatch '^/subscriptions/[a-f0-9-]+$' -and 
        $_.Scope -notmatch '/resourceGroups/[^/]+$' -and
        $_.Scope -notmatch '/providers/Microsoft.Management/managementGroups/' -and
        $_.Scope -ne '/'
    }).Count
    
    # Determine if this is potentially high-value target
    $isHighValueTarget = ($criticalRoles.Count -gt 0) -or 
                         ($highPrivilegeRoles.Count -ge 2) -or 
                         ($hasCrossSubAccess -and $highPrivilegeRoles.Count -gt 0)
    
    if ($isHighValueTarget -and $riskLevel -ne "CRITICAL") {
        $riskLevel = "HIGH"
    }
    
    return [PSCustomObject]@{
        PrincipalId = $PrincipalId
        ClientId = $ClientId
        IdentityName = $IdentityName
        IdentityType = $IdentityType
        ResourceType = $ResourceType
        ResourceId = $ResourceId
        ResourceGroupName = $ResourceGroupName
        SubscriptionId = $Subscription.Id
        SubscriptionName = $Subscription.Name
        TenantId = $TenantId
        Location = $Location
        
        # Role Assignment Analysis
        RoleAssignmentCount = $RoleAssignments.Count
        HighPrivilegeRoleCount = $highPrivilegeRoles.Count
        CriticalRoleCount = $criticalRoles.Count
        HighPrivilegeRoles = ($highPrivilegeRoles | Select-Object -Unique) -join ", "
        CriticalRoles = ($criticalRoles | Select-Object -Unique) -join ", "
        
        # Scope Analysis
        SubscriptionScopeCount = $subscriptionScopeCount
        ResourceGroupScopeCount = $resourceGroupScopeCount
        ResourceScopeCount = $resourceScopeCount
        
        # Cross-subscription
        HasCrossSubscriptionAccess = $hasCrossSubAccess
        CrossSubscriptionCount = $crossSubAccess.Count
        CrossSubscriptionDetails = $crossSubAccess
        
        # Detailed role information
        AllRoleDetails = $allRoleDetails
        
        # Status
        HasNoRoles = $hasNoRoles
        IsHighValueTarget = $isHighValueTarget
        
        # Risk Assessment
        Findings = $findings
        FindingCount = $findings.Count
        RiskLevel = $riskLevel
        HasMisconfigurations = ($findings.Count -gt 0)
    }
}

# Main scanning function
function Start-ManagedIdentityScan {
    Write-Host "`n[*] Starting Managed Identity security audit..." -ForegroundColor Cyan
    
    # Get subscriptions
    $subscriptions = Get-AccessibleSubscriptions
    
    if ($subscriptions.Count -eq 0) {
        Write-Host "[ERROR] No accessible subscriptions found. Cannot proceed." -ForegroundColor Red
        return
    }
    
    $script:TotalSubscriptions = $subscriptions.Count
    
    # First pass: collect all role assignments across all subscriptions
    Write-Host "`n[*] Phase 1: Collecting role assignments across all subscriptions..." -ForegroundColor Cyan
    
    $progressCounter = 0
    foreach ($subscription in $subscriptions) {
        $progressCounter++
        Write-Host "[*] Collecting role assignments from subscription $progressCounter/$($subscriptions.Count): $($subscription.Name)" -ForegroundColor Cyan
        
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
        
        # Get role assignments for this subscription
        $roleAssignments = Get-SubscriptionRoleAssignments -Subscription $subscription
        $script:AllRoleAssignments[$subscription.Id] = $roleAssignments
        Write-Host "[+] Found $($roleAssignments.Count) role assignments" -ForegroundColor Green
    }
    
    # Second pass: enumerate managed identities and analyze
    Write-Host "`n[*] Phase 2: Enumerating and analyzing managed identities..." -ForegroundColor Cyan
    
    $progressCounter = 0
    foreach ($subscription in $subscriptions) {
        $progressCounter++
        
        if ($subscription.Name -in $script:SkippedSubscriptions) {
            continue
        }
        
        Write-Host "`n[*] Scanning subscription $progressCounter/$($subscriptions.Count): $($subscription.Name)" -ForegroundColor Cyan
        
        # Set context
        try {
            Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
        }
        catch {
            continue
        }
        
        # Get User-Assigned Managed Identities
        Write-Host "[*] Enumerating user-assigned managed identities..." -ForegroundColor Cyan
        $userAssignedIdentities = Get-UserAssignedManagedIdentities -Subscription $subscription
        
        foreach ($identity in $userAssignedIdentities) {
            $script:TotalUserAssigned++
            $script:TotalManagedIdentities++
            
            # Get role assignments for this identity
            $identityRoles = Get-RoleAssignmentsForPrincipal -PrincipalId $identity.PrincipalId -AllRoleAssignments $script:AllRoleAssignments
            
            # Analyze security
            $finding = Analyze-ManagedIdentitySecurity `
                -PrincipalId $identity.PrincipalId `
                -IdentityName $identity.Name `
                -IdentityType "UserAssigned" `
                -ResourceType "Microsoft.ManagedIdentity/userAssignedIdentities" `
                -ResourceId $identity.Id `
                -ResourceGroupName $identity.ResourceGroupName `
                -Subscription $subscription `
                -RoleAssignments $identityRoles `
                -ClientId $identity.ClientId `
                -TenantId $identity.TenantId `
                -Location $identity.Location
            
            # Apply filters
            if ($OnlyCritical -and $finding.RiskLevel -ne "CRITICAL") { continue }
            if ($OnlyHighPrivilege -and $finding.HighPrivilegeRoleCount -eq 0) { continue }
            if ($OnlyCrossSubscription -and -not $finding.HasCrossSubscriptionAccess) { continue }
            if ($OnlyUnused -and -not $finding.HasNoRoles) { continue }
            
            $script:ManagedIdentityFindings += $finding
        }
        
        Write-Host "[+] Found $($userAssignedIdentities.Count) user-assigned identities" -ForegroundColor Green
        
        # Get VMs with System-Assigned Managed Identities
        Write-Host "[*] Enumerating VMs with managed identities..." -ForegroundColor Cyan
        $vmsWithIdentity = Get-VMsWithManagedIdentity -Subscription $subscription
        
        foreach ($vm in $vmsWithIdentity) {
            if ($vm.Identity.Type -match 'SystemAssigned') {
                $script:TotalSystemAssigned++
                $script:TotalManagedIdentities++
                
                # Get role assignments for this identity
                $identityRoles = Get-RoleAssignmentsForPrincipal -PrincipalId $vm.Identity.PrincipalId -AllRoleAssignments $script:AllRoleAssignments
                
                # Analyze security
                $finding = Analyze-ManagedIdentitySecurity `
                    -PrincipalId $vm.Identity.PrincipalId `
                    -IdentityName "$($vm.Name) (System-Assigned)" `
                    -IdentityType "SystemAssigned" `
                    -ResourceType "Microsoft.Compute/virtualMachines" `
                    -ResourceId $vm.Id `
                    -ResourceGroupName $vm.ResourceGroupName `
                    -Subscription $subscription `
                    -RoleAssignments $identityRoles `
                    -TenantId $vm.Identity.TenantId `
                    -Location $vm.Location
                
                # Apply filters
                if ($OnlyCritical -and $finding.RiskLevel -ne "CRITICAL") { continue }
                if ($OnlyHighPrivilege -and $finding.HighPrivilegeRoleCount -eq 0) { continue }
                if ($OnlyCrossSubscription -and -not $finding.HasCrossSubscriptionAccess) { continue }
                if ($OnlyUnused -and -not $finding.HasNoRoles) { continue }
                
                $script:ManagedIdentityFindings += $finding
            }
            
            # Check for user-assigned identities on VM (already counted above, just note the association)
        }
        
        Write-Host "[+] Found $($vmsWithIdentity.Count) VMs with managed identities" -ForegroundColor Green
        
        # Get App Services with Managed Identities
        Write-Host "[*] Enumerating App Services with managed identities..." -ForegroundColor Cyan
        $appServicesWithIdentity = Get-AppServicesWithManagedIdentity -Subscription $subscription
        
        foreach ($app in $appServicesWithIdentity) {
            if ($app.Identity.Type -match 'SystemAssigned') {
                $script:TotalSystemAssigned++
                $script:TotalManagedIdentities++
                
                # Get role assignments for this identity
                $identityRoles = Get-RoleAssignmentsForPrincipal -PrincipalId $app.Identity.PrincipalId -AllRoleAssignments $script:AllRoleAssignments
                
                # Analyze security
                $finding = Analyze-ManagedIdentitySecurity `
                    -PrincipalId $app.Identity.PrincipalId `
                    -IdentityName "$($app.Name) (System-Assigned)" `
                    -IdentityType "SystemAssigned" `
                    -ResourceType "Microsoft.Web/sites" `
                    -ResourceId $app.Id `
                    -ResourceGroupName $app.ResourceGroup `
                    -Subscription $subscription `
                    -RoleAssignments $identityRoles `
                    -TenantId $app.Identity.TenantId `
                    -Location $app.Location
                
                # Apply filters
                if ($OnlyCritical -and $finding.RiskLevel -ne "CRITICAL") { continue }
                if ($OnlyHighPrivilege -and $finding.HighPrivilegeRoleCount -eq 0) { continue }
                if ($OnlyCrossSubscription -and -not $finding.HasCrossSubscriptionAccess) { continue }
                if ($OnlyUnused -and -not $finding.HasNoRoles) { continue }
                
                $script:ManagedIdentityFindings += $finding
            }
        }
        
        Write-Host "[+] Found $($appServicesWithIdentity.Count) App Services with managed identities" -ForegroundColor Green
        
        # Get Function Apps with Managed Identities
        Write-Host "[*] Enumerating Function Apps with managed identities..." -ForegroundColor Cyan
        $functionAppsWithIdentity = Get-FunctionAppsWithManagedIdentity -Subscription $subscription
        
        foreach ($app in $functionAppsWithIdentity) {
            if ($app.IdentityType -match 'SystemAssigned') {
                $script:TotalSystemAssigned++
                $script:TotalManagedIdentities++
                
                # Get role assignments for this identity - need to get principal ID from identity
                $principalId = $app.IdentityPrincipalId
                if ($principalId) {
                    $identityRoles = Get-RoleAssignmentsForPrincipal -PrincipalId $principalId -AllRoleAssignments $script:AllRoleAssignments
                    
                    # Analyze security
                    $finding = Analyze-ManagedIdentitySecurity `
                        -PrincipalId $principalId `
                        -IdentityName "$($app.Name) (System-Assigned)" `
                        -IdentityType "SystemAssigned" `
                        -ResourceType "Microsoft.Web/sites (Function)" `
                        -ResourceId $app.Id `
                        -ResourceGroupName $app.ResourceGroupName `
                        -Subscription $subscription `
                        -RoleAssignments $identityRoles `
                        -TenantId $app.IdentityTenantId `
                        -Location $app.Location
                    
                    # Apply filters
                    if ($OnlyCritical -and $finding.RiskLevel -ne "CRITICAL") { continue }
                    if ($OnlyHighPrivilege -and $finding.HighPrivilegeRoleCount -eq 0) { continue }
                    if ($OnlyCrossSubscription -and -not $finding.HasCrossSubscriptionAccess) { continue }
                    if ($OnlyUnused -and -not $finding.HasNoRoles) { continue }
                    
                    $script:ManagedIdentityFindings += $finding
                }
            }
        }
        
        Write-Host "[+] Found $($functionAppsWithIdentity.Count) Function Apps with managed identities" -ForegroundColor Green
    }
    
    Write-Host "`n[+] Managed Identity scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 200) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - MANAGED IDENTITY SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 200) -ForegroundColor Cyan
    
    if ($script:ManagedIdentityFindings.Count -eq 0) {
        Write-Host "`n[!] No Managed Identity findings to display." -ForegroundColor Yellow
        Write-Host ("=" * 200) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:ManagedIdentityFindings | Sort-Object @{Expression={
        switch($_.RiskLevel) {
            "CRITICAL" { 0 }
            "HIGH" { 1 }
            "MEDIUM" { 2 }
            "LOW" { 3 }
            default { 4 }
        }
    }}, IdentityName | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Identity';Expression={if($_.IdentityName.Length -gt 35){$_.IdentityName.Substring(0,32)+"..."}else{$_.IdentityName}}},
        @{Name='Type';Expression={$_.IdentityType}},
        @{Name='Resource';Expression={
            $resType = $_.ResourceType -replace 'Microsoft\.', '' -replace '/', '.'
            if($resType.Length -gt 25){$resType.Substring(0,22)+"..."}else{$resType}
        }},
        @{Name='Subscription';Expression={if($_.SubscriptionName.Length -gt 18){$_.SubscriptionName.Substring(0,15)+"..."}else{$_.SubscriptionName}}},
        @{Name='Roles';Expression={$_.RoleAssignmentCount}},
        @{Name='HighPriv';Expression={$_.HighPrivilegeRoleCount}},
        @{Name='Critical';Expression={$_.CriticalRoleCount}},
        @{Name='CrossSub';Expression={if($_.HasCrossSubscriptionAccess){"Yes"}else{"No"}}},
        @{Name='SubScope';Expression={$_.SubscriptionScopeCount}},
        @{Name='RGScope';Expression={$_.ResourceGroupScopeCount}},
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
    Write-Host "Total Managed Identities analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:ManagedIdentityFindings.Count -ForegroundColor Yellow
    Write-Host "  - System-Assigned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalSystemAssigned -ForegroundColor Yellow
    Write-Host "  - User-Assigned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalUserAssigned -ForegroundColor Yellow
    
    $criticalRisk = ($script:ManagedIdentityFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:ManagedIdentityFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:ManagedIdentityFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:ManagedIdentityFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "`n[RISK DISTRIBUTION]" -ForegroundColor Cyan
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Cyan
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    # Security concerns
    $withCriticalRoles = ($script:ManagedIdentityFindings | Where-Object { $_.CriticalRoleCount -gt 0 }).Count
    $withHighPrivRoles = ($script:ManagedIdentityFindings | Where-Object { $_.HighPrivilegeRoleCount -gt 0 }).Count
    $withCrossSub = ($script:ManagedIdentityFindings | Where-Object { $_.HasCrossSubscriptionAccess }).Count
    $withNoRoles = ($script:ManagedIdentityFindings | Where-Object { $_.HasNoRoles }).Count
    $withSubScope = ($script:ManagedIdentityFindings | Where-Object { $_.SubscriptionScopeCount -gt 0 }).Count
    
    Write-Host "`n[SECURITY CONCERNS]" -ForegroundColor Cyan
    Write-Host "  With critical roles (Owner, UAA, RBAC Admin): " -NoNewline -ForegroundColor White
    Write-Host $withCriticalRoles -ForegroundColor $(if($withCriticalRoles -gt 0){"Red"}else{"Green"})
    Write-Host "  With high-privilege roles: " -NoNewline -ForegroundColor White
    Write-Host $withHighPrivRoles -ForegroundColor $(if($withHighPrivRoles -gt 0){"Yellow"}else{"Green"})
    Write-Host "  With cross-subscription access: " -NoNewline -ForegroundColor White
    Write-Host $withCrossSub -ForegroundColor $(if($withCrossSub -gt 0){"Yellow"}else{"Green"})
    Write-Host "  With subscription-wide scope: " -NoNewline -ForegroundColor White
    Write-Host $withSubScope -ForegroundColor $(if($withSubScope -gt 0){"Cyan"}else{"Green"})
    Write-Host "  With no role assignments (unused?): " -NoNewline -ForegroundColor White
    Write-Host $withNoRoles -ForegroundColor $(if($withNoRoles -gt 0){"Cyan"}else{"Green"})
    
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
    Write-Host "Total Managed Identities analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:ManagedIdentityFindings.Count -ForegroundColor Yellow
    Write-Host "  - System-Assigned: $script:TotalSystemAssigned" -ForegroundColor Gray
    Write-Host "  - User-Assigned: $script:TotalUserAssigned" -ForegroundColor Gray
    
    if ($script:ManagedIdentityFindings.Count -gt 0) {
        $criticalRisk = ($script:ManagedIdentityFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:ManagedIdentityFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:ManagedIdentityFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:ManagedIdentityFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "MANAGED IDENTITY SECURITY DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:ManagedIdentityFindings | Sort-Object @{Expression={
            switch($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }}, IdentityName | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] Managed Identity: " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.IdentityName -ForegroundColor White
            
            Write-Host "  Principal ID: $($_.PrincipalId)" -ForegroundColor Gray
            if ($_.ClientId) {
                Write-Host "  Client ID: $($_.ClientId)" -ForegroundColor Gray
            }
            Write-Host "  Type: $($_.IdentityType)" -ForegroundColor Gray
            Write-Host "  Resource Type: $($_.ResourceType)" -ForegroundColor Gray
            Write-Host "  Subscription: $($_.SubscriptionName)" -ForegroundColor Gray
            Write-Host "  Resource Group: $($_.ResourceGroupName)" -ForegroundColor Gray
            if ($_.Location) {
                Write-Host "  Location: $($_.Location)" -ForegroundColor Gray
            }
            
            # Role Assignment Summary
            Write-Host "`n  [Role Assignments]" -ForegroundColor Cyan
            Write-Host "  Total Assignments: " -NoNewline -ForegroundColor Gray
            Write-Host $_.RoleAssignmentCount -ForegroundColor $(if($_.RoleAssignmentCount -eq 0){"Yellow"}else{"White"})
            
            if ($_.CriticalRoleCount -gt 0) {
                Write-Host "  Critical Roles: " -NoNewline -ForegroundColor Gray
                Write-Host "$($_.CriticalRoleCount) - $($_.CriticalRoles)" -ForegroundColor Red
            }
            
            if ($_.HighPrivilegeRoleCount -gt 0) {
                Write-Host "  High-Privilege Roles: " -NoNewline -ForegroundColor Gray
                Write-Host "$($_.HighPrivilegeRoleCount) - $($_.HighPrivilegeRoles)" -ForegroundColor Yellow
            }
            
            # Scope Analysis
            Write-Host "`n  [Scope Analysis]" -ForegroundColor Cyan
            Write-Host "  Subscription-wide scopes: $($_.SubscriptionScopeCount)" -ForegroundColor $(if($_.SubscriptionScopeCount -gt 0){"Yellow"}else{"Gray"})
            Write-Host "  Resource group scopes: $($_.ResourceGroupScopeCount)" -ForegroundColor Gray
            Write-Host "  Resource-level scopes: $($_.ResourceScopeCount)" -ForegroundColor Gray
            
            # Cross-subscription access
            if ($_.HasCrossSubscriptionAccess) {
                Write-Host "`n  [Cross-Subscription Access]" -ForegroundColor Yellow
                Write-Host "  This identity has access to $($_.CrossSubscriptionCount) scope(s) outside its home subscription!" -ForegroundColor Yellow
                if ($_.CrossSubscriptionDetails) {
                    foreach ($crossSub in $_.CrossSubscriptionDetails | Select-Object -First 5) {
                        Write-Host "    - $($crossSub.RoleName) at $($crossSub.Scope)" -ForegroundColor Yellow
                    }
                    if ($_.CrossSubscriptionDetails.Count -gt 5) {
                        Write-Host "    ... and $($_.CrossSubscriptionDetails.Count - 5) more" -ForegroundColor DarkGray
                    }
                }
            }
            
            # Detailed role information
            if ($IncludeRoleDetails -and $_.AllRoleDetails -and $_.AllRoleDetails.Count -gt 0) {
                Write-Host "`n  [All Role Assignments]" -ForegroundColor Cyan
                foreach ($role in $_.AllRoleDetails | Select-Object -First 10) {
                    $roleColor = if ($role.RoleName -in $script:CriticalRoles) { "Red" }
                                 elseif ($role.RoleName -in $script:HighPrivilegeRoles) { "Yellow" }
                                 else { "Gray" }
                    Write-Host "    - $($role.RoleName) [$($role.ScopeType)]" -ForegroundColor $roleColor
                    Write-Host "      Scope: $($role.Scope)" -ForegroundColor DarkGray
                }
                if ($_.AllRoleDetails.Count -gt 10) {
                    Write-Host "    ... and $($_.AllRoleDetails.Count - 10) more" -ForegroundColor DarkGray
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
        Write-Host "`n[!] No Managed Identity findings to display." -ForegroundColor Yellow
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
    
    if ($script:ManagedIdentityFindings.Count -eq 0) {
        Write-Host "`n[*] No Managed Identity findings to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        # Prepare export data (flatten complex objects)
        $exportData = $script:ManagedIdentityFindings | Select-Object `
            PrincipalId, ClientId, IdentityName, IdentityType, ResourceType, ResourceId, ResourceGroupName,
            SubscriptionId, SubscriptionName, TenantId, Location,
            RoleAssignmentCount, HighPrivilegeRoleCount, CriticalRoleCount,
            HighPrivilegeRoles, CriticalRoles,
            SubscriptionScopeCount, ResourceGroupScopeCount, ResourceScopeCount,
            HasCrossSubscriptionAccess, CrossSubscriptionCount,
            HasNoRoles, IsHighValueTarget,
            @{Name='Findings';Expression={$_.Findings -join "; "}},
            FindingCount, RiskLevel, HasMisconfigurations
        
        switch ($extension) {
            ".csv" {
                $exportData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:ManagedIdentityFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
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
        Start-ManagedIdentityScan
        
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
        
        Write-Host "`n[*] Managed Identity security check completed successfully!" -ForegroundColor Green
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
