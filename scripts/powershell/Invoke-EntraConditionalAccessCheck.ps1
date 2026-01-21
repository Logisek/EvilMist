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
    Analyzes Azure Entra ID Conditional Access policies to identify security gaps, exclusions, and misconfigurations.

.DESCRIPTION
    This script queries Azure Entra ID to enumerate all Conditional Access policies and performs a comprehensive
    security audit including:
    - Enumerates all CA policies and their configurations
    - Identifies policy exclusions (users, groups, roles, apps)
    - Detects MFA enforcement gaps
    - Checks for policies affecting critical applications
    - Identifies conflicting or redundant policies
    - Risk assessment based on coverage gaps and exclusions
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Information collected includes:
    - Policy identification and status
    - User/group/role/app exclusions
    - MFA enforcement status
    - Grant controls and conditions
    - Application coverage
    - Risk assessment based on gaps and exclusions

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
    Include disabled policies in the results.

.PARAMETER OnlyWithExclusions
    Show only policies with exclusions.

.PARAMETER OnlyMFAgaps
    Show only policies without MFA enforcement.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraConditionalAccessCheck.ps1
    # Analyze all Conditional Access policies

.EXAMPLE
    .\Invoke-EntraConditionalAccessCheck.ps1 -ExportPath "ca-policies.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraConditionalAccessCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraConditionalAccessCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraConditionalAccessCheck.ps1 -OnlyWithExclusions -Matrix
    # Display only policies with exclusions in matrix format

.EXAMPLE
    .\Invoke-EntraConditionalAccessCheck.ps1 -OnlyMFAgaps -ExportPath "mfa-gaps.csv"
    # Show only policies without MFA enforcement and export
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
    [switch]$OnlyWithExclusions,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyMFAgaps,

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

# Critical applications that should be protected by CA policies
$script:CriticalApps = @{
    "Microsoft Azure Management" = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
    "Office 365 Exchange Online" = "00000002-0000-0ff1-ce00-000000000000"
    "Office 365 SharePoint Online" = "00000003-0000-0ff1-ce00-000000000000"
    "Microsoft Graph" = "00000003-0000-0000-c000-000000000000"
    "Azure Portal" = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
    "Microsoft 365 Admin Portal" = "618dd325-23f6-4b6f-8380-4df78026e39b"
    "Azure AD PowerShell" = "1b730954-1685-4b74-9bfd-dac224a7b894"
    "Azure PowerShell" = "1950a258-227b-4e31-a9cf-717495945fc2"
    "Graph Command Line Tools" = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
    "MS-PIM" = "01fc33a7-78ba-4d2f-a4b7-768e336e890e"
}

# Required scopes for Conditional Access checking
$script:RequiredScopes = @(
    "Policy.Read.All",
    "Directory.Read.All",
    "Application.Read.All",
    "User.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Policy.Read.All",
    "Directory.Read.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:Policies = @()
$script:TotalPoliciesScanned = 0
$script:Exclusions = @{
    ExcludedUsers = @{}
    ExcludedGroups = @{}
    ExcludedRoles = @{}
    ExcludedApps = @{}
}
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
    Write-Host "    Entra ID Conditional Access Check - Security Policy Gap Analysis" -ForegroundColor Yellow
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

# Resolve user/group/role/app IDs to names
function Resolve-ExclusionName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,
        
        [Parameter(Mandatory = $true)]
        [string]$Type
    )
    
    try {
        Invoke-StealthDelay
        
        switch ($Type) {
            "User" {
                $user = Get-MgUser -UserId $Id -Property DisplayName,UserPrincipalName -ErrorAction SilentlyContinue
                if ($user) {
                    return "$($user.DisplayName) ($($user.UserPrincipalName))"
                }
            }
            "Group" {
                $group = Get-MgGroup -GroupId $Id -Property DisplayName -ErrorAction SilentlyContinue
                if ($group) {
                    return $group.DisplayName
                }
            }
            "Role" {
                $role = Get-MgDirectoryRole -DirectoryRoleId $Id -Property DisplayName -ErrorAction SilentlyContinue
                if ($role) {
                    return $role.DisplayName
                }
            }
            "Application" {
                $app = Get-MgApplication -ApplicationId $Id -Property DisplayName,AppId -ErrorAction SilentlyContinue
                if ($app) {
                    return "$($app.DisplayName) ($($app.AppId))"
                }
            }
        }
        
        return $Id
    }
    catch {
        return $Id
    }
}

# Get all Conditional Access policies
function Get-ConditionalAccessPolicies {
    Write-Host "`n[*] Retrieving Conditional Access policies..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        $policies = $response.value
        
        Write-Host "[+] Found $($policies.Count) Conditional Access policy/policies" -ForegroundColor Green
        
        return $policies
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve Conditional Access policies: $_" -ForegroundColor Red
        Write-Host "[!] Ensure you have Policy.Read.All permission" -ForegroundColor Yellow
        return @()
    }
}

# Analyze policy and extract details
function Analyze-Policy {
    param(
        [Parameter(Mandatory = $true)]
        $Policy
    )
    
    $conditions = $Policy.conditions
    $grantControls = $Policy.grantControls
    
    # Extract exclusions
    $usersCondition = $conditions.users
    $excludeUsers = @($usersCondition.excludeUsers)
    $excludeGroups = @($usersCondition.excludeGroups)
    $excludeRoles = @($usersCondition.excludeRoles)
    
    $appsCondition = $conditions.applications
    $excludeApps = @($appsCondition.excludeApplications)
    
    # Extract includes
    $includeUsers = @($usersCondition.includeUsers)
    $includeGroups = @($usersCondition.includeGroups)
    $includeRoles = @($usersCondition.includeRoles)
    $includeApps = @($appsCondition.includeApplications)
    
    # Check grant controls
    $builtInControls = @($grantControls.builtInControls)
    $mfaRequired = $builtInControls -contains "mfa"
    $requireCompliantDevice = $builtInControls -contains "compliantDevice"
    $requireHybridAzureADJoinedDevice = $builtInControls -contains "domainJoinedDevice"
    $requireApprovedClientApp = $builtInControls -contains "approvedApplication"
    $requireAppProtectionPolicy = $builtInControls -contains "applicationEnforcedRestrictions"
    $blocksAccess = $builtInControls -contains "block"
    
    # Check client app types
    $clientAppTypes = @($conditions.clientAppTypes)
    $targetsLegacyAuth = $clientAppTypes -contains "exchangeActiveSync" -or $clientAppTypes -contains "other"
    
    # Check locations
    $locations = $conditions.locations
    $excludeLocations = @($locations.excludeLocations)
    $includeLocations = @($locations.includeLocations)
    
    # Check platforms
    $platforms = $conditions.platforms
    $includePlatforms = @($platforms.includePlatforms)
    $excludePlatforms = @($platforms.excludePlatforms)
    
    # Determine risk level
    $riskLevel = "LOW"
    $riskReasons = @()
    
    # CRITICAL: Disabled policy OR no MFA requirement with exclusions
    if ($Policy.state -ne "enabled") {
        $riskLevel = "CRITICAL"
        $riskReasons += "Policy disabled"
    }
    elseif (-not $mfaRequired -and ($excludeUsers.Count -gt 0 -or $excludeGroups.Count -gt 0 -or $excludeRoles.Count -gt 0)) {
        $riskLevel = "CRITICAL"
        $riskReasons += "No MFA requirement with exclusions"
    }
    # HIGH: Exclusions present OR no MFA requirement OR targets legacy auth
    elseif ($excludeUsers.Count -gt 0 -or $excludeGroups.Count -gt 0 -or $excludeRoles.Count -gt 0 -or $excludeApps.Count -gt 0) {
        $riskLevel = "HIGH"
        $riskReasons += "Has exclusions ($($excludeUsers.Count) users, $($excludeGroups.Count) groups, $($excludeRoles.Count) roles, $($excludeApps.Count) apps)"
    }
    elseif (-not $mfaRequired) {
        $riskLevel = "HIGH"
        $riskReasons += "No MFA requirement"
    }
    elseif ($targetsLegacyAuth) {
        $riskLevel = "HIGH"
        $riskReasons += "Targets legacy authentication"
    }
    # MEDIUM: Limited coverage or weak controls
    elseif ($includeUsers.Count -eq 0 -and $includeGroups.Count -eq 0 -and $includeRoles.Count -eq 0) {
        $riskLevel = "MEDIUM"
        $riskReasons += "No user targeting (all users)"
    }
    elseif (-not $requireCompliantDevice -and -not $requireHybridAzureADJoinedDevice) {
        $riskLevel = "MEDIUM"
        $riskReasons += "No device requirement"
    }
    
    # Check critical app coverage
    $coversCriticalApps = $false
    $coveredCriticalApps = @()
    
    if ($includeApps.Count -eq 0) {
        # All apps included
        $coversCriticalApps = $true
        $coveredCriticalApps = @("All Applications")
    }
    else {
        foreach ($appId in $includeApps) {
            foreach ($appName in $script:CriticalApps.Keys) {
                if ($appId -eq $script:CriticalApps[$appName]) {
                    $coversCriticalApps = $true
                    $coveredCriticalApps += $appName
                }
            }
        }
    }
    
    # Build exclusion details
    $exclusionDetails = @()
    if ($excludeUsers.Count -gt 0) {
        $exclusionDetails += "$($excludeUsers.Count) user(s)"
    }
    if ($excludeGroups.Count -gt 0) {
        $exclusionDetails += "$($excludeGroups.Count) group(s)"
    }
    if ($excludeRoles.Count -gt 0) {
        $exclusionDetails += "$($excludeRoles.Count) role(s)"
    }
    if ($excludeApps.Count -gt 0) {
        $exclusionDetails += "$($excludeApps.Count) app(s)"
    }
    
    return @{
        Policy = $Policy
        RiskLevel = $riskLevel
        RiskReasons = ($riskReasons -join "; ")
        ExcludeUsers = $excludeUsers
        ExcludeGroups = $excludeGroups
        ExcludeRoles = $excludeRoles
        ExcludeApps = $excludeApps
        ExcludeUsersCount = $excludeUsers.Count
        ExcludeGroupsCount = $excludeGroups.Count
        ExcludeRolesCount = $excludeRoles.Count
        ExcludeAppsCount = $excludeApps.Count
        ExclusionSummary = if ($exclusionDetails.Count -gt 0) { ($exclusionDetails -join ", ") } else { "None" }
        IncludeUsers = $includeUsers
        IncludeGroups = $includeGroups
        IncludeRoles = $includeRoles
        IncludeApps = $includeApps
        IncludeUsersCount = $includeUsers.Count
        IncludeGroupsCount = $includeGroups.Count
        IncludeRolesCount = $includeRoles.Count
        IncludeAppsCount = $includeApps.Count
        MFARequired = $mfaRequired
        RequireCompliantDevice = $requireCompliantDevice
        RequireHybridAzureADJoinedDevice = $requireHybridAzureADJoinedDevice
        RequireApprovedClientApp = $requireApprovedClientApp
        RequireAppProtectionPolicy = $requireAppProtectionPolicy
        BlocksAccess = $blocksAccess
        TargetsLegacyAuth = $targetsLegacyAuth
        ClientAppTypes = ($clientAppTypes -join ", ")
        CoversCriticalApps = $coversCriticalApps
        CoveredCriticalApps = ($coveredCriticalApps -join ", ")
        ExcludeLocations = $excludeLocations
        ExcludeLocationsCount = $excludeLocations.Count
        IncludeLocations = $includeLocations
        IncludeLocationsCount = $includeLocations.Count
        IncludePlatforms = ($includePlatforms -join ", ")
        ExcludePlatforms = ($excludePlatforms -join ", ")
    }
}

# Main scanning function
function Start-ConditionalAccessScan {
    Write-Host "`n[*] Starting Conditional Access policy scan..." -ForegroundColor Cyan
    
    # Get all policies
    $rawPolicies = Get-ConditionalAccessPolicies
    
    if ($rawPolicies.Count -eq 0) {
        Write-Host "[!] No Conditional Access policies found" -ForegroundColor Yellow
        return
    }
    
    $script:TotalPoliciesScanned = $rawPolicies.Count
    $progressCounter = 0
    
    foreach ($policy in $rawPolicies) {
        $progressCounter++
        
        # Progress indicator
        if ($progressCounter % 5 -eq 0 -or $progressCounter -eq $rawPolicies.Count) {
            $percentComplete = [math]::Round(($progressCounter / $rawPolicies.Count) * 100, 1)
            Write-Host "`r[*] Progress: $progressCounter/$($rawPolicies.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
        }
        
        # Skip disabled if not included
        if (-not $IncludeDisabled -and $policy.state -ne "enabled") {
            continue
        }
        
        try {
            # Analyze policy
            $analysis = Analyze-Policy -Policy $policy
            
            # Filter: Only with exclusions
            if ($OnlyWithExclusions -and $analysis.ExcludeUsersCount -eq 0 -and $analysis.ExcludeGroupsCount -eq 0 -and $analysis.ExcludeRolesCount -eq 0 -and $analysis.ExcludeAppsCount -eq 0) {
                continue
            }
            
            # Filter: Only MFA gaps
            if ($OnlyMFAgaps -and $analysis.MFARequired) {
                continue
            }
            
            # Track exclusions globally
            foreach ($userId in $analysis.ExcludeUsers) {
                if (-not $script:Exclusions.ExcludedUsers.ContainsKey($userId)) {
                    $script:Exclusions.ExcludedUsers[$userId] = @()
                }
                $script:Exclusions.ExcludedUsers[$userId] += $policy.id
            }
            
            foreach ($groupId in $analysis.ExcludeGroups) {
                if (-not $script:Exclusions.ExcludedGroups.ContainsKey($groupId)) {
                    $script:Exclusions.ExcludedGroups[$groupId] = @()
                }
                $script:Exclusions.ExcludedGroups[$groupId] += $policy.id
            }
            
            foreach ($roleId in $analysis.ExcludeRoles) {
                if (-not $script:Exclusions.ExcludedRoles.ContainsKey($roleId)) {
                    $script:Exclusions.ExcludedRoles[$roleId] = @()
                }
                $script:Exclusions.ExcludedRoles[$roleId] += $policy.id
            }
            
            foreach ($appId in $analysis.ExcludeApps) {
                if (-not $script:Exclusions.ExcludedApps.ContainsKey($appId)) {
                    $script:Exclusions.ExcludedApps[$appId] = @()
                }
                $script:Exclusions.ExcludedApps[$appId] += $policy.id
            }
            
            # Build policy info object
            $policyInfo = [PSCustomObject]@{
                PolicyId = $policy.id
                DisplayName = $policy.displayName
                State = $policy.state
                CreatedDateTime = $policy.createdDateTime
                ModifiedDateTime = $policy.modifiedDateTime
                RiskLevel = $analysis.RiskLevel
                RiskReasons = $analysis.RiskReasons
                ExcludeUsersCount = $analysis.ExcludeUsersCount
                ExcludeGroupsCount = $analysis.ExcludeGroupsCount
                ExcludeRolesCount = $analysis.ExcludeRolesCount
                ExcludeAppsCount = $analysis.ExcludeAppsCount
                ExclusionSummary = $analysis.ExclusionSummary
                IncludeUsersCount = $analysis.IncludeUsersCount
                IncludeGroupsCount = $analysis.IncludeGroupsCount
                IncludeRolesCount = $analysis.IncludeRolesCount
                IncludeAppsCount = $analysis.IncludeAppsCount
                MFARequired = $analysis.MFARequired
                RequireCompliantDevice = $analysis.RequireCompliantDevice
                RequireHybridAzureADJoinedDevice = $analysis.RequireHybridAzureADJoinedDevice
                RequireApprovedClientApp = $analysis.RequireApprovedClientApp
                RequireAppProtectionPolicy = $analysis.RequireAppProtectionPolicy
                BlocksAccess = $analysis.BlocksAccess
                TargetsLegacyAuth = $analysis.TargetsLegacyAuth
                ClientAppTypes = $analysis.ClientAppTypes
                CoversCriticalApps = $analysis.CoversCriticalApps
                CoveredCriticalApps = $analysis.CoveredCriticalApps
                ExcludeLocationsCount = $analysis.ExcludeLocationsCount
                IncludeLocationsCount = $analysis.IncludeLocationsCount
                IncludePlatforms = $analysis.IncludePlatforms
                ExcludePlatforms = $analysis.ExcludePlatforms
            }
            
            $script:Policies += $policyInfo
        }
        catch {
            Write-Host "`n[!] Error processing policy $($policy.displayName): $_" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n[+] Scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - CONDITIONAL ACCESS POLICY SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:Policies.Count -eq 0) {
        Write-Host "`n[!] No policies found matching the specified criteria." -ForegroundColor Yellow
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:Policies | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Status';Expression={$_.State}},
        @{Name='Policy Name';Expression={$_.DisplayName}},
        @{Name='MFA';Expression={if($_.MFARequired){'Yes'}else{'No'}}},
        @{Name='Exclusions';Expression={$_.ExclusionSummary}},
        @{Name='Critical Apps';Expression={if($_.CoversCriticalApps){'Yes'}else{'No'}}},
        @{Name='Legacy Auth';Expression={if($_.TargetsLegacyAuth){'Yes'}else{'No'}}},
        @{Name='Blocks';Expression={if($_.BlocksAccess){'Yes'}else{'No'}}}
    
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
    Write-Host "Total policies analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:Policies.Count -ForegroundColor Yellow
    
    $criticalRisk = ($script:Policies | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:Policies | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:Policies | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:Policies | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Cyan
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    $withExclusions = ($script:Policies | Where-Object { $_.ExcludeUsersCount -gt 0 -or $_.ExcludeGroupsCount -gt 0 -or $_.ExcludeRolesCount -gt 0 -or $_.ExcludeAppsCount -gt 0 }).Count
    $withoutMFA = ($script:Policies | Where-Object { -not $_.MFARequired }).Count
    $disabled = ($script:Policies | Where-Object { $_.State -ne "enabled" }).Count
    $coversCriticalApps = ($script:Policies | Where-Object { $_.CoversCriticalApps }).Count
    
    Write-Host "`n[POLICY GAPS]" -ForegroundColor Cyan
    Write-Host "  Policies with exclusions: " -NoNewline -ForegroundColor White
    Write-Host $withExclusions -ForegroundColor Yellow
    Write-Host "  Policies without MFA requirement: " -NoNewline -ForegroundColor White
    Write-Host $withoutMFA -ForegroundColor Red
    Write-Host "  Disabled policies: " -NoNewline -ForegroundColor White
    Write-Host $disabled -ForegroundColor Yellow
    Write-Host "  Policies covering critical apps: " -NoNewline -ForegroundColor White
    Write-Host $coversCriticalApps -ForegroundColor $(if($coversCriticalApps -gt 0){"Green"}else{"Yellow"})
    
    # Exclusion summary
    $totalExcludedUsers = $script:Exclusions.ExcludedUsers.Count
    $totalExcludedGroups = $script:Exclusions.ExcludedGroups.Count
    $totalExcludedRoles = $script:Exclusions.ExcludedRoles.Count
    $totalExcludedApps = $script:Exclusions.ExcludedApps.Count
    
    if ($totalExcludedUsers -gt 0 -or $totalExcludedGroups -gt 0 -or $totalExcludedRoles -gt 0 -or $totalExcludedApps -gt 0) {
        Write-Host "`n[EXCLUSIONS SUMMARY]" -ForegroundColor Cyan
        Write-Host "  Unique excluded users: " -NoNewline -ForegroundColor White
        Write-Host $totalExcludedUsers -ForegroundColor Yellow
        Write-Host "  Unique excluded groups: " -NoNewline -ForegroundColor White
        Write-Host $totalExcludedGroups -ForegroundColor Yellow
        Write-Host "  Unique excluded roles: " -NoNewline -ForegroundColor White
        Write-Host $totalExcludedRoles -ForegroundColor Yellow
        Write-Host "  Unique excluded apps: " -NoNewline -ForegroundColor White
        Write-Host $totalExcludedApps -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# Display results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal policies scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalPoliciesScanned -ForegroundColor Yellow
    
    Write-Host "Policies analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:Policies.Count -ForegroundColor $(if($script:Policies.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:Policies.Count -gt 0) {
        $criticalRisk = ($script:Policies | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:Policies | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:Policies | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:Policies | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "POLICY DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:Policies | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.DisplayName -ForegroundColor White
            
            Write-Host "  Policy ID: $($_.PolicyId)" -ForegroundColor Gray
            Write-Host "  State: " -NoNewline -ForegroundColor Gray
            if ($_.State -eq "enabled") {
                Write-Host "Enabled" -ForegroundColor Green
            }
            else {
                Write-Host "Disabled" -ForegroundColor Yellow
            }
            
            if ($_.RiskReasons) {
                Write-Host "  Risk Reasons: $($_.RiskReasons)" -ForegroundColor $(if($_.RiskLevel -eq "CRITICAL"){"Red"}elseif($_.RiskLevel -eq "HIGH"){"Yellow"}else{"Gray"})
            }
            
            Write-Host "  MFA Required: " -NoNewline -ForegroundColor Gray
            if ($_.MFARequired) {
                Write-Host "Yes" -ForegroundColor Green
            }
            else {
                Write-Host "No" -ForegroundColor Red
            }
            
            if ($_.ExclusionSummary -ne "None") {
                Write-Host "  Exclusions: $($_.ExclusionSummary)" -ForegroundColor Yellow
            }
            
            Write-Host "  Includes: " -NoNewline -ForegroundColor Gray
            $includeParts = @()
            if ($_.IncludeUsersCount -gt 0) { $includeParts += "$($_.IncludeUsersCount) user(s)" }
            if ($_.IncludeGroupsCount -gt 0) { $includeParts += "$($_.IncludeGroupsCount) group(s)" }
            if ($_.IncludeRolesCount -gt 0) { $includeParts += "$($_.IncludeRolesCount) role(s)" }
            if ($_.IncludeAppsCount -gt 0) { $includeParts += "$($_.IncludeAppsCount) app(s)" }
            if ($includeParts.Count -eq 0) { $includeParts = @("All users") }
            Write-Host ($includeParts -join ", ") -ForegroundColor Gray
            
            if ($_.CoversCriticalApps) {
                Write-Host "  Covers Critical Apps: " -NoNewline -ForegroundColor Gray
                Write-Host $_.CoveredCriticalApps -ForegroundColor Green
            }
            
            if ($_.TargetsLegacyAuth) {
                Write-Host "  [!] Targets legacy authentication" -ForegroundColor Yellow
            }
            
            if ($_.BlocksAccess) {
                Write-Host "  Blocks Access: Yes" -ForegroundColor Red
            }
            
            if ($_.RequireCompliantDevice) {
                Write-Host "  Requires Compliant Device: Yes" -ForegroundColor Green
            }
            
            if ($_.RequireHybridAzureADJoinedDevice) {
                Write-Host "  Requires Hybrid Azure AD Joined Device: Yes" -ForegroundColor Green
            }
            
            if ($_.CreatedDateTime) {
                Write-Host "  Created: $($_.CreatedDateTime)" -ForegroundColor Gray
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[!] No policies found matching the specified criteria." -ForegroundColor Yellow
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
    
    if ($script:Policies.Count -eq 0) {
        Write-Host "`n[*] No policies to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:Policies | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:Policies | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:Policies | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-ConditionalAccessScan
        
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
        
        Write-Host "`n[*] Conditional Access check completed successfully!" -ForegroundColor Green
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

