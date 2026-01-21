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
    Enumerates Azure Entra ID Administrative Units and analyzes scoped role assignments for security risks.

.DESCRIPTION
    This script queries Azure Entra ID to identify all Administrative Units and performs a comprehensive
    security audit including:
    - Enumerates all Administrative Units and their configurations
    - Checks scoped role assignments (who has admin access scoped to specific AUs)
    - Identifies AU members and their roles
    - Risk assessment based on scoped admin access and AU configuration
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Information collected includes:
    - Administrative Unit identification and configuration
    - Scoped role assignments (AU administrators)
    - AU member enumeration
    - Risk assessment based on scoped admin access
    - MFA status of scoped administrators
    - Last sign-in activity of administrators

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

.PARAMETER OnlyNoMFA
    Show only scoped administrators without MFA enabled.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraAdminUnitCheck.ps1
    # Query all Administrative Units and scoped role assignments

.EXAMPLE
    .\Invoke-EntraAdminUnitCheck.ps1 -ExportPath "admin-units.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraAdminUnitCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraAdminUnitCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraAdminUnitCheck.ps1 -OnlyNoMFA -Matrix
    # Display only scoped administrators without MFA in matrix format

.EXAMPLE
    .\Invoke-EntraAdminUnitCheck.ps1 -Matrix -ExportPath "results.csv"
    # Display results in matrix format and export
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
    [switch]$OnlyNoMFA,

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

# Role risk levels - CRITICAL roles are the most dangerous if compromised
$script:RoleRiskLevels = @{
    "Global Administrator" = "CRITICAL"
    "Privileged Role Administrator" = "CRITICAL"
    "Privileged Authentication Administrator" = "CRITICAL"
    "User Administrator" = "HIGH"
    "Groups Administrator" = "HIGH"
    "Authentication Administrator" = "HIGH"
    "Password Administrator" = "HIGH"
    "Helpdesk Administrator" = "HIGH"
    "Security Administrator" = "HIGH"
    "Compliance Administrator" = "HIGH"
    "Application Administrator" = "MEDIUM"
    "License Administrator" = "MEDIUM"
    "Billing Administrator" = "MEDIUM"
    "Directory Readers" = "LOW"
    "Directory Writers" = "LOW"
    "Guest Inviter" = "LOW"
}

# Required scopes for Administrative Unit checking
$script:RequiredScopes = @(
    "Directory.Read.All",
    "AdministrativeUnit.Read.All",
    "RoleManagement.Read.Directory",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Directory.Read.All",
    "AdministrativeUnit.Read.All",
    "User.ReadBasic.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:AdminUnits = @()
$script:ScopedAssignments = @()
$script:TotalAUsScanned = 0
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
    Write-Host "    Entra ID Administrative Unit Check - Scoped Admin Access Audit" -ForegroundColor Yellow
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
        "Microsoft.Graph.Identity.DirectoryManagement",
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
        
        Write-Host "[*] Importing Microsoft.Graph.Users..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Users -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Microsoft.Graph.Identity.DirectoryManagement..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force -ErrorAction Stop
        
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

# Get role risk level
function Get-RoleRiskLevel {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RoleName
    )
    
    if ($script:RoleRiskLevels.ContainsKey($RoleName)) {
        return $script:RoleRiskLevels[$RoleName]
    }
    return "MEDIUM"
}

# Get all Administrative Units
function Get-AdministrativeUnits {
    Write-Host "`n[*] Retrieving Administrative Units..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$select=id,displayName,description,visibility,membershipType,membershipRule,membershipRuleProcessingState,createdDateTime&`$top=999"
        $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        $adminUnits = @()
        foreach ($au in $result.value) {
            # Get member count
            $memberCount = 0
            try {
                Invoke-StealthDelay
                $countUri = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members/`$count"
                $countResponse = Invoke-MgGraphRequest -Method GET -Uri $countUri -Headers @{ "ConsistencyLevel" = "eventual" } -ErrorAction SilentlyContinue
                if ($countResponse -is [int]) {
                    $memberCount = $countResponse
                }
            }
            catch {
                # Try to count manually
                try {
                    Invoke-StealthDelay
                    $membersUri = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members?`$select=id&`$top=1"
                    $membersResult = Invoke-MgGraphRequest -Method GET -Uri $membersUri -ErrorAction SilentlyContinue
                    if ($membersResult.value) {
                        # If we got results, try to get count via pagination
                        $memberCount = -1  # Unknown, but has members
                    }
                }
                catch { }
            }
            
            $adminUnits += [PSCustomObject]@{
                Id = $au.id
                DisplayName = $au.displayName
                Description = $au.description
                Visibility = $au.visibility
                MembershipType = $au.membershipType
                MembershipRule = $au.membershipRule
                MembershipRuleProcessingState = $au.membershipRuleProcessingState
                MemberCount = $memberCount
                CreatedDateTime = $au.createdDateTime
            }
        }
        
        Write-Host "[+] Found $($adminUnits.Count) Administrative Unit(s)" -ForegroundColor Green
        return $adminUnits
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve Administrative Units: $_" -ForegroundColor Red
        Write-Host "[!] Ensure you have AdministrativeUnit.Read.All permission" -ForegroundColor Yellow
        return @()
    }
}

# Get scoped role assignments for Administrative Units
function Get-ScopedRoleAssignments {
    Write-Host "`n[*] Retrieving scoped role assignments..." -ForegroundColor Cyan
    
    $scopedAssignments = @()
    
    foreach ($au in $script:AdminUnits) {
        try {
            Invoke-StealthDelay
            
            $auId = $au.Id
            $auName = $au.DisplayName
            
            Write-Host "[*] Checking scoped roles for: $auName" -ForegroundColor Cyan
            
            $uri = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auId/scopedRoleMembers?`$expand=roleDefinition"
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            
            foreach ($assignment in $result.value) {
                $roleDef = $assignment.roleDefinition
                $roleName = if ($roleDef -and $roleDef.displayName) { $roleDef.displayName } else { "Unknown Role" }
                $roleId = $assignment.roleDefinitionId
                
                $principal = $assignment.roleMemberInfo
                $principalId = if ($principal) { $principal.id } else { "" }
                $principalName = if ($principal) { $principal.displayName } else { "" }
                $principalType = if ($principal) { $principal.'@odata.type' } else { "Unknown" }
                
                # Normalize principal type
                if ($principalType -eq '#microsoft.graph.user') {
                    $principalType = "User"
                }
                elseif ($principalType -eq '#microsoft.graph.group') {
                    $principalType = "Group"
                }
                elseif ($principalType -eq '#microsoft.graph.servicePrincipal') {
                    $principalType = "ServicePrincipal"
                }
                
                $scopedAssignments += [PSCustomObject]@{
                    AdminUnitId = $auId
                    AdminUnitName = $auName
                    AdminUnitVisibility = $au.Visibility
                    RoleDefinitionId = $roleId
                    RoleName = $roleName
                    PrincipalId = $principalId
                    PrincipalName = $principalName
                    PrincipalType = $principalType
                    AssignmentId = $assignment.id
                }
            }
            
            if ($result.value.Count -gt 0) {
                Write-Host "[+] Found $($result.value.Count) scoped role assignment(s) for $auName" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[!] Error retrieving scoped roles for $($au.DisplayName): $_" -ForegroundColor Yellow
        }
    }
    
    Write-Host "[+] Found $($scopedAssignments.Count) total scoped role assignment(s)" -ForegroundColor Green
    return $scopedAssignments
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

# Main scanning function
function Start-AdminUnitScan {
    Write-Host "`n[*] Starting Administrative Unit scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of AUs and assignments..." -ForegroundColor Cyan
    
    # Get Administrative Units
    $script:AdminUnits = Get-AdministrativeUnits
    
    if ($script:AdminUnits.Count -eq 0) {
        Write-Host "[!] No Administrative Units found in this tenant" -ForegroundColor Yellow
        return
    }
    
    $script:TotalAUsScanned = $script:AdminUnits.Count
    
    # Get scoped role assignments
    $rawAssignments = Get-ScopedRoleAssignments
    
    if ($rawAssignments.Count -eq 0) {
        Write-Host "[!] No scoped role assignments found" -ForegroundColor Yellow
        return
    }
    
    # Process assignments and enrich with user details
    $progressCounter = 0
    
    Write-Host "`n[*] Analyzing scoped role assignments..." -ForegroundColor Cyan
    Write-Host "[*] Found $($rawAssignments.Count) assignment(s) to analyze" -ForegroundColor Cyan
    
    foreach ($assignment in $rawAssignments) {
        $progressCounter++
        
        # Progress indicator
        if ($progressCounter % 5 -eq 0 -or $progressCounter -eq $rawAssignments.Count) {
            $percentComplete = [math]::Round(($progressCounter / $rawAssignments.Count) * 100, 1)
            Write-Host "`r[*] Progress: $progressCounter/$($rawAssignments.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
        }
        
        try {
            # Only process User principals (skip Groups and ServicePrincipals for now)
            if ($assignment.PrincipalType -ne "User") {
                # Still add to results but with limited info
                $roleRiskLevel = Get-RoleRiskLevel -RoleName $assignment.RoleName
                
                $assignmentInfo = [PSCustomObject]@{
                    AdminUnitId = $assignment.AdminUnitId
                    AdminUnitName = $assignment.AdminUnitName
                    AdminUnitVisibility = $assignment.AdminUnitVisibility
                    RoleDefinitionId = $assignment.RoleDefinitionId
                    RoleName = $assignment.RoleName
                    RoleRiskLevel = $roleRiskLevel
                    PrincipalId = $assignment.PrincipalId
                    PrincipalName = $assignment.PrincipalName
                    PrincipalType = $assignment.PrincipalType
                    PrincipalUPN = ""
                    DisplayName = $assignment.PrincipalName
                    AccountEnabled = $null
                    UserType = ""
                    JobTitle = ""
                    Department = ""
                    CreatedDateTime = $null
                    DaysOld = -1
                    LastSignIn = $null
                    LastSignInDisplay = "N/A (not a user)"
                    DaysSinceLastSignIn = -1
                    SignInType = "N/A"
                    MFAEnabled = $null
                    AuthMethods = ""
                    MethodCount = 0
                    RiskLevel = $roleRiskLevel
                }
                
                $script:ScopedAssignments += $assignmentInfo
                continue
            }
            
            # Get user details
            Invoke-StealthDelay
            
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
            
            $user = Get-MgUser -UserId $assignment.PrincipalId -Property $properties -ErrorAction Stop
            
            # Skip disabled users if not included
            if (-not $IncludeDisabledUsers -and -not $user.AccountEnabled) {
                continue
            }
            
            # Check MFA status
            $mfaStatus = Test-UserMFA -UserId $user.Id -UserPrincipalName $user.UserPrincipalName
            
            # Skip if OnlyNoMFA is set and user has MFA
            if ($OnlyNoMFA -and $mfaStatus.HasMFA) {
                continue
            }
            
            # Get sign-in information
            $signInInfo = Get-SignInInfo -User $user
            
            # Get role risk level
            $roleRiskLevel = Get-RoleRiskLevel -RoleName $assignment.RoleName
            
            # Determine overall risk level
            $overallRisk = $roleRiskLevel
            
            # Elevate risk if user doesn't have MFA
            if (-not $mfaStatus.HasMFA) {
                if ($overallRisk -eq "CRITICAL") {
                    $overallRisk = "CRITICAL"
                }
                elseif ($overallRisk -eq "HIGH") {
                    $overallRisk = "CRITICAL"
                }
                elseif ($overallRisk -eq "MEDIUM") {
                    $overallRisk = "HIGH"
                }
                else {
                    $overallRisk = "MEDIUM"
                }
            }
            
            # Calculate days since creation
            $daysOld = -1
            if ($user.CreatedDateTime) {
                $daysOld = ([DateTime]::Now - [DateTime]$user.CreatedDateTime).Days
            }
            
            $assignmentInfo = [PSCustomObject]@{
                AdminUnitId = $assignment.AdminUnitId
                AdminUnitName = $assignment.AdminUnitName
                AdminUnitVisibility = $assignment.AdminUnitVisibility
                RoleDefinitionId = $assignment.RoleDefinitionId
                RoleName = $assignment.RoleName
                RoleRiskLevel = $roleRiskLevel
                PrincipalId = $assignment.PrincipalId
                PrincipalName = $assignment.PrincipalName
                PrincipalType = $assignment.PrincipalType
                PrincipalUPN = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                Email = $user.Mail
                AccountEnabled = $user.AccountEnabled
                UserType = $user.UserType
                JobTitle = $user.JobTitle
                Department = $user.Department
                CreatedDateTime = $user.CreatedDateTime
                DaysOld = $daysOld
                LastSignIn = $signInInfo.LastSignIn
                LastSignInDisplay = $signInInfo.DisplayText
                DaysSinceLastSignIn = $signInInfo.DaysAgo
                SignInType = $signInInfo.SignInType
                MFAEnabled = $mfaStatus.HasMFA
                AuthMethods = ($mfaStatus.Methods -join ", ")
                MethodCount = $mfaStatus.MethodCount
                HasLicenses = ($user.AssignedLicenses.Count -gt 0)
                LicenseCount = $user.AssignedLicenses.Count
                RiskLevel = $overallRisk
            }
            
            $script:ScopedAssignments += $assignmentInfo
        }
        catch {
            Write-Host "`n[!] Error processing assignment $($assignment.PrincipalId): $_" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n[+] Scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - ADMINISTRATIVE UNIT SCOPED ROLE ASSIGNMENTS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:ScopedAssignments.Count -eq 0) {
        if ($OnlyNoMFA) {
            Write-Host "`n[+] All scoped administrators have MFA enabled." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No scoped role assignments found." -ForegroundColor Yellow
        }
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:ScopedAssignments | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Role Risk';Expression={$_.RoleRiskLevel}},
        @{Name='MFA';Expression={if($_.MFAEnabled -eq $null){'N/A'}elseif($_.MFAEnabled){'Yes'}else{'No'}}},
        @{Name='Type';Expression={$_.PrincipalType}},
        @{Name='Status';Expression={if($_.AccountEnabled -eq $null){'N/A'}elseif($_.AccountEnabled){'Enabled'}else{'Disabled'}}},
        @{Name='Admin Unit';Expression={$_.AdminUnitName}},
        @{Name='Role';Expression={$_.RoleName}},
        @{Name='Principal Name';Expression={$_.PrincipalName}},
        @{Name='User Principal Name';Expression={if($_.PrincipalUPN){$_.PrincipalUPN}else{'-'}}},
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
    Write-Host "Total Administrative Units: " -NoNewline -ForegroundColor White
    Write-Host $script:AdminUnits.Count -ForegroundColor Yellow
    
    Write-Host "Total scoped role assignments: " -NoNewline -ForegroundColor White
    Write-Host $script:ScopedAssignments.Count -ForegroundColor Yellow
    
    $uniqueUsers = ($script:ScopedAssignments | Where-Object { $_.PrincipalType -eq "User" } | Select-Object -Unique PrincipalId).Count
    Write-Host "Unique user administrators: " -NoNewline -ForegroundColor White
    Write-Host $uniqueUsers -ForegroundColor Yellow
    
    $criticalRisk = ($script:ScopedAssignments | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:ScopedAssignments | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:ScopedAssignments | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:ScopedAssignments | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Green
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Gray
    
    $userAssignments = $script:ScopedAssignments | Where-Object { $_.PrincipalType -eq "User" }
    $withMFA = ($userAssignments | Where-Object { $_.MFAEnabled -eq $true }).Count
    $withoutMFA = ($userAssignments | Where-Object { $_.MFAEnabled -eq $false }).Count
    
    Write-Host "`n[MFA STATUS]" -ForegroundColor Cyan
    Write-Host "  With MFA enabled: " -NoNewline -ForegroundColor White
    Write-Host $withMFA -ForegroundColor Green
    Write-Host "  Without MFA: " -NoNewline -ForegroundColor White
    Write-Host $withoutMFA -ForegroundColor Red
    
    # Group by Administrative Unit
    $byAU = $script:ScopedAssignments | Group-Object AdminUnitName | Sort-Object Count -Descending
    if ($byAU.Count -gt 0) {
        Write-Host "`n[ASSIGNMENTS BY ADMINISTRATIVE UNIT]" -ForegroundColor Cyan
        $byAU | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Group by role
    $byRole = $script:ScopedAssignments | Group-Object RoleName | Sort-Object Count -Descending
    if ($byRole.Count -gt 0) {
        Write-Host "`n[ASSIGNMENTS BY ROLE]" -ForegroundColor Cyan
        $byRole | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Group by department
    $byDept = $script:ScopedAssignments | Where-Object { $_.Department } | Group-Object Department | Sort-Object Count -Descending
    if ($byDept.Count -gt 0) {
        Write-Host "`n[TOP DEPARTMENTS]" -ForegroundColor Cyan
        $byDept | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Sign-in activity statistics
    $neverSignedIn = ($script:ScopedAssignments | Where-Object { $_.DaysSinceLastSignIn -eq -1 }).Count
    $recentSignIn = ($script:ScopedAssignments | Where-Object { $_.DaysSinceLastSignIn -ge 0 -and $_.DaysSinceLastSignIn -le 30 }).Count
    $staleSignIn = ($script:ScopedAssignments | Where-Object { $_.DaysSinceLastSignIn -gt 90 }).Count
    
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
    
    Write-Host ""
}

# Display results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal Administrative Units: " -NoNewline -ForegroundColor White
    Write-Host $script:AdminUnits.Count -ForegroundColor Yellow
    
    Write-Host "Total scoped role assignments: " -NoNewline -ForegroundColor White
    Write-Host $script:ScopedAssignments.Count -ForegroundColor Yellow
    
    if ($script:ScopedAssignments.Count -gt 0) {
        $criticalRisk = ($script:ScopedAssignments | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:ScopedAssignments | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:ScopedAssignments | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:ScopedAssignments | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Green
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Gray
        
        $userAssignments = $script:ScopedAssignments | Where-Object { $_.PrincipalType -eq "User" }
        $withMFA = ($userAssignments | Where-Object { $_.MFAEnabled -eq $true }).Count
        $withoutMFA = ($userAssignments | Where-Object { $_.MFAEnabled -eq $false }).Count
        
        Write-Host "`nMFA Status:" -ForegroundColor Cyan
        Write-Host "  - With MFA: " -NoNewline -ForegroundColor White
        Write-Host $withMFA -ForegroundColor Green
        Write-Host "  - Without MFA: " -NoNewline -ForegroundColor White
        Write-Host $withoutMFA -ForegroundColor Red
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "SCOPED ROLE ASSIGNMENT DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:ScopedAssignments | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Green" }
                "LOW" { "Gray" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host "$($_.AdminUnitName) - $($_.RoleName)" -ForegroundColor White
            
            Write-Host "  Principal Name: $($_.PrincipalName)" -ForegroundColor Gray
            Write-Host "  Principal Type: $($_.PrincipalType)" -ForegroundColor Gray
            
            if ($_.PrincipalUPN) {
                Write-Host "  User Principal Name: $($_.PrincipalUPN)" -ForegroundColor Gray
            }
            
            if ($_.DisplayName) {
                Write-Host "  Display Name: $($_.DisplayName)" -ForegroundColor Gray
            }
            
            if ($_.Email) {
                Write-Host "  Email: $($_.Email)" -ForegroundColor Gray
            }
            
            if ($_.JobTitle) {
                Write-Host "  Job Title: $($_.JobTitle)" -ForegroundColor Gray
            }
            
            if ($_.Department) {
                Write-Host "  Department: $($_.Department)" -ForegroundColor Gray
            }
            
            Write-Host "  Administrative Unit: $($_.AdminUnitName)" -ForegroundColor Cyan
            Write-Host "  AU Visibility: $($_.AdminUnitVisibility)" -ForegroundColor Gray
            Write-Host "  Role: " -NoNewline -ForegroundColor Gray
            Write-Host $_.RoleName -ForegroundColor Cyan
            Write-Host "  Role Risk Level: " -NoNewline -ForegroundColor Gray
            Write-Host $_.RoleRiskLevel -ForegroundColor $(switch($_.RoleRiskLevel){"CRITICAL"{"Red"}"HIGH"{"Yellow"}default{"Green"}})
            
            if ($_.AccountEnabled -ne $null) {
                Write-Host "  Account Status: " -NoNewline -ForegroundColor Gray
                if ($_.AccountEnabled) {
                    Write-Host "Enabled" -ForegroundColor Green
                }
                else {
                    Write-Host "Disabled" -ForegroundColor Yellow
                }
            }
            
            if ($_.MFAEnabled -ne $null) {
                Write-Host "  MFA Enabled: " -NoNewline -ForegroundColor Gray
                if ($_.MFAEnabled) {
                    Write-Host "Yes" -ForegroundColor Green
                }
                else {
                    Write-Host "No" -ForegroundColor Red
                }
                Write-Host "  Auth Methods: $($_.AuthMethods)" -ForegroundColor Gray
            }
            
            Write-Host "  Last Sign-In: " -NoNewline -ForegroundColor Gray
            if ($_.LastSignIn) {
                Write-Host $_.LastSignInDisplay -NoNewline -ForegroundColor $(if($_.DaysSinceLastSignIn -gt 90){"Red"}elseif($_.DaysSinceLastSignIn -gt 30){"Yellow"}else{"Green"})
                Write-Host " ($($_.SignInType))" -ForegroundColor DarkGray
            }
            else {
                Write-Host $_.LastSignInDisplay -ForegroundColor DarkGray
            }
            
            if ($_.CreatedDateTime) {
                Write-Host "  Created: $($_.CreatedDateTime) ($($_.DaysOld) days old)" -ForegroundColor Gray
            }
            
            if ($_.HasLicenses) {
                Write-Host "  Licenses: $($_.LicenseCount) assigned" -ForegroundColor Gray
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        if ($OnlyNoMFA) {
            Write-Host "`n[+] All scoped administrators have MFA enabled." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No scoped role assignments found." -ForegroundColor Yellow
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
    
    if ($script:ScopedAssignments.Count -eq 0) {
        Write-Host "`n[*] No scoped role assignments to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:ScopedAssignments | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:ScopedAssignments | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:ScopedAssignments | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-AdminUnitScan
        
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
        
        Write-Host "`n[*] Administrative Unit check completed successfully!" -ForegroundColor Green
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

