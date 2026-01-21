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
    Enumerates Azure Entra ID tenant license SKUs and analyzes user license assignments for security and compliance.

.DESCRIPTION
    This script queries Azure Entra ID to identify tenant license SKUs and performs a comprehensive
    analysis of user license assignments including:
    - Enumerates all tenant license SKUs and their consumption
    - Checks user license assignments
    - Identifies privileged license users (E5, P2, etc.)
    - Checks for unused licenses (assigned but not used)
    - Risk assessment based on license privileges
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Information collected includes:
    - Tenant SKU identification and consumption
    - User license assignments and types
    - Privileged license detection (E5, P2, etc.)
    - Unused license identification
    - Risk assessment based on license privileges

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

.PARAMETER IncludeDisabledUsers
    Include disabled user accounts in the results.

.PARAMETER OnlyPrivilegedLicenses
    Show only users with privileged licenses (E5, P2, etc.).

.PARAMETER OnlyUnusedLicenses
    Show only unused license assignments.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraLicenseCheck.ps1
    # Query all license SKUs and user assignments

.EXAMPLE
    .\Invoke-EntraLicenseCheck.ps1 -ExportPath "licenses.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraLicenseCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraLicenseCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraLicenseCheck.ps1 -OnlyPrivilegedLicenses -Matrix
    # Display only users with privileged licenses in matrix format

.EXAMPLE
    .\Invoke-EntraLicenseCheck.ps1 -OnlyUnusedLicenses -ExportPath "unused-licenses.csv"
    # Show only unused license assignments and export
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
    [switch]$IncludeDisabledUsers,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyPrivilegedLicenses,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyUnusedLicenses,

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

# Privileged license SKU part numbers (E5, P2, etc.)
$script:PrivilegedLicenseSKUs = @(
    "ENTERPRISEPACK",           # E3
    "ENTERPRISEPREMIUM",        # E5
    "ENTERPRISEPREMIUM_NOPSTNCONF", # E5 without PSTN
    "M365_E5",                  # Microsoft 365 E5
    "M365_E5_COMPLIANCE",       # Microsoft 365 E5 Compliance
    "M365_E5_SECURITY",         # Microsoft 365 E5 Security
    "M365_F1",                  # Microsoft 365 F1
    "M365_F3",                  # Microsoft 365 F3
    "AAD_PREMIUM",              # Azure AD Premium P1
    "AAD_PREMIUM_P2",           # Azure AD Premium P2
    "AAD_PREMIUM_P2_EDU",       # Azure AD Premium P2 EDU
    "RIGHTSMANAGEMENT",         # Azure Information Protection
    "M365_ADVANCED_COMPLIANCE", # Advanced Compliance
    "M365_ADVANCED_THREAT_PROTECTION", # Advanced Threat Protection
    "M365_ADVANCED_SECURITY",   # Advanced Security
    "EMS",                      # Enterprise Mobility + Security
    "EMS_E5",                   # Enterprise Mobility + Security E5
    "INTUNE_A",                  # Intune
    "INTUNE_A_VL",              # Intune Volume License
    "POWER_BI_PRO",              # Power BI Pro
    "POWERAPPS_PER_USER",       # Power Apps per user
    "POWERAUTOMATE_PER_USER",   # Power Automate per user
    "PROJECT_PREMIUM",          # Project Premium
    "VISIO_PLAN2",              # Visio Plan 2
    "WIN_ENT_E5",               # Windows Enterprise E5
    "WIN_ENT_E3",                # Windows Enterprise E3
    "O365_E5",                  # Office 365 E5
    "O365_E3"                   # Office 365 E3
)

# License risk levels - CRITICAL licenses provide highest privileges
$script:LicenseRiskLevels = @{
    "ENTERPRISEPREMIUM" = "CRITICAL"
    "M365_E5" = "CRITICAL"
    "AAD_PREMIUM_P2" = "CRITICAL"
    "M365_E5_SECURITY" = "CRITICAL"
    "M365_E5_COMPLIANCE" = "CRITICAL"
    "EMS_E5" = "CRITICAL"
    "ENTERPRISEPACK" = "HIGH"
    "M365_E3" = "HIGH"
    "AAD_PREMIUM" = "HIGH"
    "EMS" = "HIGH"
    "O365_E5" = "HIGH"
    "O365_E3" = "HIGH"
    "M365_F3" = "MEDIUM"
    "M365_F1" = "MEDIUM"
    "INTUNE_A" = "MEDIUM"
    "POWER_BI_PRO" = "MEDIUM"
    "POWERAPPS_PER_USER" = "MEDIUM"
    "POWERAUTOMATE_PER_USER" = "MEDIUM"
}

# Required scopes for license checking
$script:RequiredScopes = @(
    "Organization.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Organization.Read.All",
    "Directory.Read.All",
    "User.ReadBasic.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:TenantSKUs = @()
$script:UserLicenseAssignments = @()
$script:TotalUsersScanned = 0
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
    Write-Host "    Entra ID License Check - License and SKU Analysis" -ForegroundColor Yellow
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
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Identity.DirectoryManagement"
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
        
        Write-Host "[*] Importing Microsoft.Graph.Users..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Users -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Microsoft.Graph.Identity.DirectoryManagement..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force -ErrorAction Stop
        
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

# Get license risk level
function Get-LicenseRiskLevel {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SkuPartNumber
    )
    
    if ($script:LicenseRiskLevels.ContainsKey($SkuPartNumber)) {
        return $script:LicenseRiskLevels[$SkuPartNumber]
    }
    
    # Check if it's a privileged license by pattern matching
    $skuUpper = $SkuPartNumber.ToUpper()
    if ($skuUpper -match "E5" -or $skuUpper -match "PREMIUM_P2" -or $skuUpper -match "ENTERPRISEPREMIUM") {
        return "CRITICAL"
    }
    elseif ($skuUpper -match "E3" -or $skuUpper -match "PREMIUM" -or $skuUpper -match "ENTERPRISEPACK") {
        return "HIGH"
    }
    elseif ($skuUpper -match "E1" -or $skuUpper -match "F1" -or $skuUpper -match "F3") {
        return "MEDIUM"
    }
    
    return "LOW"
}

# Check if license is privileged
function Test-PrivilegedLicense {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SkuPartNumber
    )
    
    $skuUpper = $SkuPartNumber.ToUpper()
    foreach ($privilegedSku in $script:PrivilegedLicenseSKUs) {
        if ($skuUpper -match $privilegedSku) {
            return $true
        }
    }
    return $false
}

# Get all tenant SKUs
function Get-TenantSKUs {
    Write-Host "`n[*] Retrieving tenant license SKUs..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/v1.0/subscribedSkus?`$select=id,skuId,skuPartNumber,appliesTo,capabilityStatus,consumedUnits,prepaidUnits,servicePlans"
        $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        foreach ($sku in $result.value) {
            $prepaid = $sku.prepaidUnits
            $enabledUnits = if ($prepaid) { $prepaid.enabled } else { 0 }
            $consumed = $sku.consumedUnits
            $available = $enabledUnits - $consumed
            
            $riskLevel = Get-LicenseRiskLevel -SkuPartNumber $sku.skuPartNumber
            $isPrivileged = Test-PrivilegedLicense -SkuPartNumber $sku.skuPartNumber
            
            $skuInfo = [PSCustomObject]@{
                SkuId = $sku.skuId
                SkuPartNumber = $sku.skuPartNumber
                CapabilityStatus = $sku.capabilityStatus
                EnabledUnits = $enabledUnits
                ConsumedUnits = $consumed
                AvailableUnits = $available
                UsagePercentage = if ($enabledUnits -gt 0) { [math]::Round(($consumed / $enabledUnits) * 100, 2) } else { 0 }
                IsPrivileged = $isPrivileged
                RiskLevel = $riskLevel
                ServicePlanCount = if ($sku.servicePlans) { $sku.servicePlans.Count } else { 0 }
            }
            
            $script:TenantSKUs += $skuInfo
        }
        
        Write-Host "[+] Found $($script:TenantSKUs.Count) license SKU(s)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve tenant SKUs: $_" -ForegroundColor Red
        return $false
    }
}

# Get last sign-in information
function Get-SignInInfo {
    param(
        [Parameter(Mandatory = $true)]
        $User
    )
    
    try {
        if ($User.SignInActivity) {
            $lastSignIn = $User.SignInActivity.LastSignInDateTime
            $lastNonInteractive = $User.SignInActivity.LastNonInteractiveSignInDateTime
            
            # Use the most recent sign-in
            $mostRecent = $null
            $signInType = "Never"
            
            if ($lastSignIn) {
                $mostRecent = [DateTime]$lastSignIn
                $signInType = "Interactive"
            }
            
            if ($lastNonInteractive) {
                $nonInteractiveDate = [DateTime]$lastNonInteractive
                if (-not $mostRecent -or $nonInteractiveDate -gt $mostRecent) {
                    $mostRecent = $nonInteractiveDate
                    $signInType = "Non-Interactive"
                }
            }
            
            if ($mostRecent) {
                $daysAgo = ([DateTime]::Now - $mostRecent).Days
                return @{
                    LastSignIn = $mostRecent
                    SignInType = $signInType
                    DaysAgo = $daysAgo
                    DisplayText = "$($mostRecent.ToString('yyyy-MM-dd HH:mm:ss')) ($daysAgo days ago)"
                }
            }
        }
        
        return @{
            LastSignIn = $null
            SignInType = "Never"
            DaysAgo = -1
            DisplayText = "Never signed in"
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
function Start-LicenseScan {
    Write-Host "`n[*] Starting license scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of users..." -ForegroundColor Cyan
    
    # Get tenant SKUs first
    if (-not (Get-TenantSKUs)) {
        return
    }
    
    # Build SKU mapping
    $skuMap = @{}
    foreach ($sku in $script:TenantSKUs) {
        $skuMap[$sku.SkuId] = $sku
    }
    
    # Get all users with licenses
    try {
        Invoke-StealthDelay
        
        Write-Host "`n[*] Retrieving users with license assignments..." -ForegroundColor Cyan
        
        $properties = @(
            'Id',
            'DisplayName',
            'UserPrincipalName',
            'AccountEnabled',
            'Mail',
            'JobTitle',
            'Department',
            'CreatedDateTime',
            'SignInActivity',
            'UserType',
            'AssignedLicenses'
        )
        
        $users = Get-MgUser -All -Property $properties -ErrorAction Stop
        $usersWithLicenses = $users | Where-Object { $_.AssignedLicenses.Count -gt 0 }
        
        Write-Host "[+] Found $($usersWithLicenses.Count) user(s) with license assignments" -ForegroundColor Green
        
        $script:TotalUsersScanned = $usersWithLicenses.Count
        $progressCounter = 0
        
        foreach ($user in $usersWithLicenses) {
            $progressCounter++
            
            # Progress indicator
            if ($progressCounter % 10 -eq 0 -or $progressCounter -eq $usersWithLicenses.Count) {
                $percentComplete = [math]::Round(($progressCounter / $usersWithLicenses.Count) * 100, 1)
                Write-Host "`r[*] Progress: $progressCounter/$($usersWithLicenses.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
            }
            
            # Skip disabled users if not included
            if (-not $IncludeDisabledUsers -and -not $user.AccountEnabled) {
                continue
            }
            
            # Process each assigned license
            foreach ($assignedLicense in $user.AssignedLicenses) {
                $skuId = $assignedLicense.SkuId
                $skuInfo = $skuMap[$skuId]
                
                if (-not $skuInfo) {
                    # SKU not found in tenant SKUs, skip
                    continue
                }
                
                # Check if filtering for privileged licenses only
                if ($OnlyPrivilegedLicenses -and -not $skuInfo.IsPrivileged) {
                    continue
                }
                
                # Get sign-in information
                $signInInfo = Get-SignInInfo -User $user
                
                # Check if license is unused (user never signed in)
                $isUnused = $signInInfo.DaysAgo -eq -1
                
                # Filter for unused licenses only if requested
                if ($OnlyUnusedLicenses -and -not $isUnused) {
                    continue
                }
                
                # Determine overall risk level
                $overallRisk = $skuInfo.RiskLevel
                
                # Elevate risk if user doesn't have MFA (we'll check this if available)
                # For now, focus on license-based risk
                
                # Elevate risk if unused license (waste)
                if ($isUnused -and $skuInfo.IsPrivileged) {
                    if ($overallRisk -eq "CRITICAL") {
                        $overallRisk = "CRITICAL"
                    }
                    elseif ($overallRisk -eq "HIGH") {
                        $overallRisk = "CRITICAL"
                    }
                    else {
                        $overallRisk = "HIGH"
                    }
                }
                
                # Calculate days since creation
                $daysOld = -1
                if ($user.CreatedDateTime) {
                    $daysOld = ([DateTime]::Now - [DateTime]$user.CreatedDateTime).Days
                }
                
                $licenseInfo = [PSCustomObject]@{
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    Email = $user.Mail
                    AccountEnabled = $user.AccountEnabled
                    UserType = $user.UserType
                    JobTitle = $user.JobTitle
                    Department = $user.Department
                    CreatedDateTime = $user.CreatedDateTime
                    DaysOld = $daysOld
                    SkuId = $skuId
                    SkuPartNumber = $skuInfo.SkuPartNumber
                    LicenseRiskLevel = $skuInfo.RiskLevel
                    IsPrivilegedLicense = $skuInfo.IsPrivileged
                    LastSignIn = $signInInfo.LastSignIn
                    LastSignInDisplay = $signInInfo.DisplayText
                    DaysSinceLastSignIn = $signInInfo.DaysAgo
                    SignInType = $signInInfo.SignInType
                    IsUnusedLicense = $isUnused
                    RiskLevel = $overallRisk
                }
                
                $script:UserLicenseAssignments += $licenseInfo
            }
        }
        
        Write-Host "`n[+] Scan complete!" -ForegroundColor Green
    }
    catch {
        Write-Host "`n[ERROR] Failed to retrieve user licenses: $_" -ForegroundColor Red
    }
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - LICENSE ASSIGNMENTS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:UserLicenseAssignments.Count -eq 0) {
        if ($OnlyPrivilegedLicenses) {
            Write-Host "`n[+] No users found with privileged licenses." -ForegroundColor Green
        }
        elseif ($OnlyUnusedLicenses) {
            Write-Host "`n[+] No unused license assignments found." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No license assignments found." -ForegroundColor Yellow
        }
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:UserLicenseAssignments | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='License Risk';Expression={$_.LicenseRiskLevel}},
        @{Name='Privileged';Expression={if($_.IsPrivilegedLicense){'Yes'}else{'No'}}},
        @{Name='Unused';Expression={if($_.IsUnusedLicense){'Yes'}else{'No'}}},
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}},
        @{Name='User Principal Name';Expression={$_.UserPrincipalName}},
        @{Name='Display Name';Expression={$_.DisplayName}},
        @{Name='License SKU';Expression={$_.SkuPartNumber}},
        @{Name='Last Sign-In';Expression={
            if($_.DaysSinceLastSignIn -eq -1){'Never'}
            elseif($_.DaysSinceLastSignIn -eq 0){'Today'}
            elseif($_.DaysSinceLastSignIn -eq 1){'Yesterday'}
            else{"$($_.DaysSinceLastSignIn)d ago"}
        }},
        @{Name='Department';Expression={if($_.Department){$_.Department}else{'-'}}}
    
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
    Write-Host "Total license assignments: " -NoNewline -ForegroundColor White
    Write-Host $script:UserLicenseAssignments.Count -ForegroundColor Yellow
    
    $uniqueUsers = ($script:UserLicenseAssignments | Select-Object -Unique UserPrincipalName).Count
    Write-Host "Unique users with licenses: " -NoNewline -ForegroundColor White
    Write-Host $uniqueUsers -ForegroundColor Yellow
    
    $criticalRisk = ($script:UserLicenseAssignments | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:UserLicenseAssignments | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:UserLicenseAssignments | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:UserLicenseAssignments | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Green
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Gray
    
    $privilegedLicenses = ($script:UserLicenseAssignments | Where-Object { $_.IsPrivilegedLicense -eq $true }).Count
    $unusedLicenses = ($script:UserLicenseAssignments | Where-Object { $_.IsUnusedLicense -eq $true }).Count
    
    Write-Host "`n[LICENSE TYPES]" -ForegroundColor Cyan
    Write-Host "  Privileged licenses: " -NoNewline -ForegroundColor White
    Write-Host $privilegedLicenses -ForegroundColor Yellow
    Write-Host "  Unused licenses: " -NoNewline -ForegroundColor White
    Write-Host $unusedLicenses -ForegroundColor Red
    
    # Group by license SKU
    $bySku = $script:UserLicenseAssignments | Group-Object SkuPartNumber | Sort-Object Count -Descending
    if ($bySku.Count -gt 0) {
        Write-Host "`n[LICENSES BY SKU]" -ForegroundColor Cyan
        $bySku | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Group by department
    $byDept = $script:UserLicenseAssignments | Where-Object { $_.Department } | Group-Object Department | Sort-Object Count -Descending
    if ($byDept.Count -gt 0) {
        Write-Host "`n[TOP DEPARTMENTS]" -ForegroundColor Cyan
        $byDept | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Sign-in activity statistics
    $neverSignedIn = ($script:UserLicenseAssignments | Where-Object { $_.DaysSinceLastSignIn -eq -1 }).Count
    $recentSignIn = ($script:UserLicenseAssignments | Where-Object { $_.DaysSinceLastSignIn -ge 0 -and $_.DaysSinceLastSignIn -le 30 }).Count
    $staleSignIn = ($script:UserLicenseAssignments | Where-Object { $_.DaysSinceLastSignIn -gt 90 }).Count
    
    if ($neverSignedIn -gt 0 -or $recentSignIn -gt 0 -or $staleSignIn -gt 0) {
        Write-Host "`n[SIGN-IN ACTIVITY]" -ForegroundColor Cyan
        if ($neverSignedIn -gt 0) {
            Write-Host "  Never signed in: " -NoNewline -ForegroundColor White
            Write-Host $neverSignedIn -ForegroundColor Gray
        }
        if ($recentSignIn -gt 0) {
            Write-Host "  Recent (≤30 days): " -NoNewline -ForegroundColor White
            Write-Host $recentSignIn -ForegroundColor Green
        }
        if ($staleSignIn -gt 0) {
            Write-Host "  Stale (>90 days): " -NoNewline -ForegroundColor White
            Write-Host $staleSignIn -ForegroundColor Red
        }
    }
    
    # Tenant SKU summary
    if ($script:TenantSKUs.Count -gt 0) {
        Write-Host "`n[TENANT SKU SUMMARY]" -ForegroundColor Cyan
        Write-Host "Total SKUs: " -NoNewline -ForegroundColor White
        Write-Host $script:TenantSKUs.Count -ForegroundColor Yellow
        
        $totalEnabled = ($script:TenantSKUs | Measure-Object -Property EnabledUnits -Sum).Sum
        $totalConsumed = ($script:TenantSKUs | Measure-Object -Property ConsumedUnits -Sum).Sum
        $totalAvailable = ($script:TenantSKUs | Measure-Object -Property AvailableUnits -Sum).Sum
        
        Write-Host "  Total enabled: " -NoNewline -ForegroundColor White
        Write-Host $totalEnabled -ForegroundColor Yellow
        Write-Host "  Total consumed: " -NoNewline -ForegroundColor White
        Write-Host $totalConsumed -ForegroundColor Yellow
        Write-Host "  Total available: " -NoNewline -ForegroundColor White
        Write-Host $totalAvailable -ForegroundColor $(if($totalAvailable -gt 0){"Yellow"}else{"Green"})
        
        $privilegedSkus = ($script:TenantSKUs | Where-Object { $_.IsPrivileged -eq $true })
        if ($privilegedSkus.Count -gt 0) {
            Write-Host "`n[PRIVILEGED SKUs]" -ForegroundColor Cyan
            foreach ($sku in $privilegedSkus) {
                Write-Host "  $($sku.SkuPartNumber): " -NoNewline -ForegroundColor White
                Write-Host "$($sku.ConsumedUnits)/$($sku.EnabledUnits) ($($sku.UsagePercentage)%)" -ForegroundColor Yellow
            }
        }
    }
    
    Write-Host ""
}

# Display results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal license assignments: " -NoNewline -ForegroundColor White
    Write-Host $script:UserLicenseAssignments.Count -ForegroundColor Yellow
    
    $uniqueUsers = ($script:UserLicenseAssignments | Select-Object -Unique UserPrincipalName).Count
    Write-Host "Unique users with licenses: " -NoNewline -ForegroundColor White
    Write-Host $uniqueUsers -ForegroundColor Yellow
    
    if ($script:UserLicenseAssignments.Count -gt 0) {
        $criticalRisk = ($script:UserLicenseAssignments | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:UserLicenseAssignments | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:UserLicenseAssignments | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:UserLicenseAssignments | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        $privilegedLicenses = ($script:UserLicenseAssignments | Where-Object { $_.IsPrivilegedLicense -eq $true }).Count
        $unusedLicenses = ($script:UserLicenseAssignments | Where-Object { $_.IsUnusedLicense -eq $true }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Green
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Gray
        
        Write-Host "`nLicense Types:" -ForegroundColor Cyan
        Write-Host "  - Privileged licenses: " -NoNewline -ForegroundColor White
        Write-Host $privilegedLicenses -ForegroundColor Yellow
        Write-Host "  - Unused licenses: " -NoNewline -ForegroundColor White
        Write-Host $unusedLicenses -ForegroundColor Red
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "LICENSE ASSIGNMENT DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:UserLicenseAssignments | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Green" }
                "LOW" { "Gray" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host "$($_.UserPrincipalName) - $($_.SkuPartNumber)" -ForegroundColor White
            
            Write-Host "  Display Name: $($_.DisplayName)" -ForegroundColor Gray
            Write-Host "  User Type: $($_.UserType)" -ForegroundColor Gray
            
            if ($_.Email) {
                Write-Host "  Email: $($_.Email)" -ForegroundColor Gray
            }
            if ($_.JobTitle) {
                Write-Host "  Job Title: $($_.JobTitle)" -ForegroundColor Gray
            }
            if ($_.Department) {
                Write-Host "  Department: $($_.Department)" -ForegroundColor Gray
            }
            
            Write-Host "  Account Status: " -NoNewline -ForegroundColor Gray
            if ($_.AccountEnabled) {
                Write-Host "Enabled" -ForegroundColor Green
            }
            else {
                Write-Host "Disabled" -ForegroundColor Yellow
            }
            
            Write-Host "  License SKU: " -NoNewline -ForegroundColor Gray
            Write-Host $_.SkuPartNumber -ForegroundColor Cyan
            Write-Host "  License Risk Level: " -NoNewline -ForegroundColor Gray
            Write-Host $_.LicenseRiskLevel -ForegroundColor $(switch($_.LicenseRiskLevel){"CRITICAL"{"Red"}"HIGH"{"Yellow"}default{"Green"}})
            
            Write-Host "  Privileged License: " -NoNewline -ForegroundColor Gray
            if ($_.IsPrivilegedLicense) {
                Write-Host "Yes" -ForegroundColor Yellow
            }
            else {
                Write-Host "No" -ForegroundColor Green
            }
            
            Write-Host "  Unused License: " -NoNewline -ForegroundColor Gray
            if ($_.IsUnusedLicense) {
                Write-Host "Yes" -ForegroundColor Red
            }
            else {
                Write-Host "No" -ForegroundColor Green
            }
            
            Write-Host "  Last Sign-In: " -NoNewline -ForegroundColor Gray
            if ($_.LastSignIn) {
                Write-Host $_.LastSignInDisplay -NoNewline -ForegroundColor $(if($_.DaysSinceLastSignIn -gt 90){"Red"}elseif($_.DaysSinceLastSignIn -gt 30){"Yellow"}else{"Green"})
                Write-Host " ($($_.SignInType))" -ForegroundColor DarkGray
            }
            else {
                Write-Host "Never signed in" -ForegroundColor DarkGray
            }
            
            Write-Host "  Created: $($_.CreatedDateTime) ($($_.DaysOld) days old)" -ForegroundColor Gray
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        if ($OnlyPrivilegedLicenses) {
            Write-Host "`n[+] No users found with privileged licenses." -ForegroundColor Green
        }
        elseif ($OnlyUnusedLicenses) {
            Write-Host "`n[+] No unused license assignments found." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No license assignments found." -ForegroundColor Yellow
        }
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
    
    if ($script:UserLicenseAssignments.Count -eq 0) {
        Write-Host "`n[*] No license assignments to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:UserLicenseAssignments | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:UserLicenseAssignments | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:UserLicenseAssignments | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-LicenseScan
        
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
        
        Write-Host "`n[*] License check completed successfully!" -ForegroundColor Green
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

