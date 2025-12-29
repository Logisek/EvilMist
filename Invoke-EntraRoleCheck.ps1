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
    Enumerates Azure Entra ID users with privileged directory roles and analyzes their security posture.

.DESCRIPTION
    This script queries Azure Entra ID to identify users with privileged directory roles including
    Global Administrators, Privileged Role Administrators, and other high-privilege roles.
    It provides comprehensive information about role assignments including MFA status, 
    assignment type (permanent vs PIM eligible/active), assignment duration, and last sign-in activity.
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Roles analyzed include:
    - Global Administrator (CRITICAL)
    - Privileged Role Administrator (CRITICAL)
    - Privileged Authentication Administrator (CRITICAL)
    - Exchange Administrator (HIGH)
    - SharePoint Administrator (HIGH)
    - Security Administrator (HIGH)
    - User Administrator (MEDIUM)
    - And all other directory roles
    
    Information collected includes:
    - User identification and role assignments
    - Assignment type (Active, PIM Eligible, PIM Active)
    - Assignment date and duration
    - MFA registration and authentication methods
    - Last sign-in date and activity patterns
    - Risk assessment based on role criticality and security posture

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
    Show only privileged users without MFA enabled.

.PARAMETER OnlyPermanent
    Show only permanent (non-PIM) role assignments.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraRoleCheck.ps1
    # Query all users with privileged roles

.EXAMPLE
    .\Invoke-EntraRoleCheck.ps1 -ExportPath "privileged-roles.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraRoleCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraRoleCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraRoleCheck.ps1 -OnlyNoMFA -Matrix
    # Display only privileged users without MFA in matrix format

.EXAMPLE
    .\Invoke-EntraRoleCheck.ps1 -OnlyPermanent -ExportPath "permanent-admins.csv"
    # Show only permanent role assignments and export

.EXAMPLE
    .\Invoke-EntraRoleCheck.ps1 -Matrix -ExportPath "results.csv"
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
    [switch]$OnlyPermanent,

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
    "Exchange Administrator" = "HIGH"
    "SharePoint Administrator" = "HIGH"
    "Security Administrator" = "HIGH"
    "Compliance Administrator" = "HIGH"
    "Application Administrator" = "HIGH"
    "Cloud Application Administrator" = "HIGH"
    "Hybrid Identity Administrator" = "HIGH"
    "Identity Governance Administrator" = "HIGH"
    "User Administrator" = "MEDIUM"
    "Helpdesk Administrator" = "MEDIUM"
    "License Administrator" = "MEDIUM"
    "Billing Administrator" = "MEDIUM"
    "Authentication Administrator" = "MEDIUM"
    "Groups Administrator" = "MEDIUM"
    "Directory Readers" = "LOW"
    "Directory Writers" = "LOW"
    "Guest Inviter" = "LOW"
}

# Required scopes for role checking
$script:RequiredScopes = @(
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "AuditLog.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
    "User.ReadBasic.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:PrivilegedUsers = @()
$script:TotalUsersScanned = 0
$script:RoleAssignments = @{}
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
    Write-Host "    Entra ID Role Check - Privileged Access Audit" -ForegroundColor Yellow
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
        Write-Host "`n[*] Install with:" -ForegroundColor Cyan
        Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor White
        Write-Host "    Or individually:" -ForegroundColor Cyan
        $missingModules | ForEach-Object { 
            Write-Host "    Install-Module $_ -Scope CurrentUser" -ForegroundColor White 
        }
        return $false
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

# Get all directory roles and their members
function Get-DirectoryRoles {
    Write-Host "`n[*] Retrieving directory roles and members..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get all directory roles
        $roles = Get-MgDirectoryRole -All -ErrorAction Stop
        Write-Host "[+] Found $($roles.Count) directory role(s)" -ForegroundColor Green
        
        $roleMembers = @{}
        
        foreach ($role in $roles) {
            try {
                Invoke-StealthDelay
                
                Write-Host "[*] Retrieving members for: $($role.DisplayName)" -ForegroundColor Cyan
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
                
                # Filter for user members only
                $userMembers = @()
                foreach ($member in $members) {
                    if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                        $userMembers += $member
                    }
                }
                
                if ($userMembers.Count -gt 0) {
                    $roleMembers[$role.Id] = @{
                        Role = $role
                        Members = $userMembers
                    }
                    Write-Host "[+] Found $($userMembers.Count) user member(s) in $($role.DisplayName)" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "[!] Error retrieving members for $($role.DisplayName): $_" -ForegroundColor Yellow
            }
        }
        
        return $roleMembers
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve directory roles: $_" -ForegroundColor Red
        return @{}
    }
}

# Get PIM eligible role assignments
function Get-PIMEligibleAssignments {
    Write-Host "`n[*] Retrieving PIM eligible role assignments..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?`$expand=principal&`$filter=principalType eq 'User'"
        $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        $eligibleAssignments = @()
        
        foreach ($schedule in $result.value) {
            $principal = $schedule.principal
            
            if ($principal.'@odata.type' -eq '#microsoft.graph.user') {
                $roleId = $schedule.roleDefinitionId
                
                # Get role name
                $roleName = "Unknown Role"
                try {
                    $roleUri = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$roleId'"
                    $roleResult = Invoke-MgGraphRequest -Method GET -Uri $roleUri -ErrorAction SilentlyContinue
                    if ($roleResult.value.Count -gt 0) {
                        $roleName = $roleResult.value[0].displayName
                    }
                }
                catch { }
                
                $eligibleAssignments += [PSCustomObject]@{
                    UserId = $principal.id
                    UserPrincipalName = $principal.userPrincipalName
                    DisplayName = $principal.displayName
                    RoleId = $roleId
                    RoleName = $roleName
                    AssignmentType = "PIM Eligible"
                    CreatedDateTime = $schedule.createdDateTime
                    StartDateTime = $schedule.startDateTime
                    EndDateTime = $schedule.endDateTime
                    ExpirationType = $schedule.expiration.type
                }
            }
        }
        
        Write-Host "[+] Found $($eligibleAssignments.Count) PIM eligible assignment(s)" -ForegroundColor Green
        return $eligibleAssignments
    }
    catch {
        Write-Host "[!] Failed to retrieve PIM eligible assignments: $_" -ForegroundColor Yellow
        Write-Host "[!] Note: PIM data requires RoleManagement.Read.Directory permission" -ForegroundColor Yellow
        return @()
    }
}

# Get PIM active role assignments
function Get-PIMActiveAssignments {
    Write-Host "`n[*] Retrieving PIM active role assignments..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentSchedules?`$expand=principal&`$filter=principalType eq 'User' and assignmentType eq 'Activated'"
        $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        $activeAssignments = @()
        
        foreach ($schedule in $result.value) {
            $principal = $schedule.principal
            
            if ($principal.'@odata.type' -eq '#microsoft.graph.user') {
                $roleId = $schedule.roleDefinitionId
                
                # Get role name
                $roleName = "Unknown Role"
                try {
                    $roleUri = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$roleId'"
                    $roleResult = Invoke-MgGraphRequest -Method GET -Uri $roleUri -ErrorAction SilentlyContinue
                    if ($roleResult.value.Count -gt 0) {
                        $roleName = $roleResult.value[0].displayName
                    }
                }
                catch { }
                
                $activeAssignments += [PSCustomObject]@{
                    UserId = $principal.id
                    UserPrincipalName = $principal.userPrincipalName
                    DisplayName = $principal.displayName
                    RoleId = $roleId
                    RoleName = $roleName
                    AssignmentType = "PIM Active"
                    CreatedDateTime = $schedule.createdDateTime
                    StartDateTime = $schedule.startDateTime
                    EndDateTime = $schedule.endDateTime
                }
            }
        }
        
        Write-Host "[+] Found $($activeAssignments.Count) PIM active assignment(s)" -ForegroundColor Green
        return $activeAssignments
    }
    catch {
        Write-Host "[!] Failed to retrieve PIM active assignments: $_" -ForegroundColor Yellow
        return @()
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
function Start-RoleScan {
    Write-Host "`n[*] Starting privileged role scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of role assignments..." -ForegroundColor Cyan
    
    # Get directory roles and members
    $roleMembers = Get-DirectoryRoles
    
    # Get PIM assignments
    $pimEligible = Get-PIMEligibleAssignments
    $pimActive = Get-PIMActiveAssignments
    
    # Track all unique users with their role assignments
    $allUserAssignments = @{}
    
    # Process permanent role assignments
    foreach ($roleId in $roleMembers.Keys) {
        $roleData = $roleMembers[$roleId]
        $role = $roleData.Role
        $members = $roleData.Members
        
        foreach ($member in $members) {
            $userId = $member.Id
            
            if (-not $allUserAssignments.ContainsKey($userId)) {
                $allUserAssignments[$userId] = @{
                    UserId = $userId
                    DisplayName = $member.AdditionalProperties.displayName
                    UserPrincipalName = $member.AdditionalProperties.userPrincipalName
                    Mail = $member.AdditionalProperties.mail
                    Roles = @()
                }
            }
            
            $allUserAssignments[$userId].Roles += [PSCustomObject]@{
                RoleName = $role.DisplayName
                RoleId = $role.Id
                AssignmentType = "Active"
                CreatedDateTime = $null
                StartDateTime = $null
                EndDateTime = $null
            }
        }
    }
    
    # Process PIM eligible assignments
    foreach ($assignment in $pimEligible) {
        $userId = $assignment.UserId
        
        if (-not $allUserAssignments.ContainsKey($userId)) {
            $allUserAssignments[$userId] = @{
                UserId = $userId
                DisplayName = $assignment.DisplayName
                UserPrincipalName = $assignment.UserPrincipalName
                Mail = $null
                Roles = @()
            }
        }
        
        $allUserAssignments[$userId].Roles += [PSCustomObject]@{
            RoleName = $assignment.RoleName
            RoleId = $assignment.RoleId
            AssignmentType = "PIM Eligible"
            CreatedDateTime = $assignment.CreatedDateTime
            StartDateTime = $assignment.StartDateTime
            EndDateTime = $assignment.EndDateTime
        }
    }
    
    # Process PIM active assignments
    foreach ($assignment in $pimActive) {
        $userId = $assignment.UserId
        
        if (-not $allUserAssignments.ContainsKey($userId)) {
            $allUserAssignments[$userId] = @{
                UserId = $userId
                DisplayName = $assignment.DisplayName
                UserPrincipalName = $assignment.UserPrincipalName
                Mail = $null
                Roles = @()
            }
        }
        
        $allUserAssignments[$userId].Roles += [PSCustomObject]@{
            RoleName = $assignment.RoleName
            RoleId = $assignment.RoleId
            AssignmentType = "PIM Active"
            CreatedDateTime = $assignment.CreatedDateTime
            StartDateTime = $assignment.StartDateTime
            EndDateTime = $assignment.EndDateTime
        }
    }
    
    if ($allUserAssignments.Count -eq 0) {
        Write-Host "[!] No users with privileged roles found" -ForegroundColor Yellow
        return
    }
    
    $script:TotalUsersScanned = $allUserAssignments.Count
    $progressCounter = 0
    
    Write-Host "`n[*] Analyzing users with privileged roles..." -ForegroundColor Cyan
    Write-Host "[*] Found $($allUserAssignments.Count) unique user(s) with role assignments" -ForegroundColor Cyan
    
    foreach ($userId in $allUserAssignments.Keys) {
        $progressCounter++
        
        # Progress indicator
        if ($progressCounter % 5 -eq 0 -or $progressCounter -eq $allUserAssignments.Count) {
            $percentComplete = [math]::Round(($progressCounter / $allUserAssignments.Count) * 100, 1)
            Write-Host "`r[*] Progress: $progressCounter/$($allUserAssignments.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
        }
        
        try {
            $userData = $allUserAssignments[$userId]
            
            # Skip disabled users if not included
            if (-not $IncludeDisabledUsers) {
                Invoke-StealthDelay
                $user = Get-MgUser -UserId $userId -Property AccountEnabled -ErrorAction SilentlyContinue
                if ($user -and -not $user.AccountEnabled) {
                    continue
                }
            }
            
            # Get full user details
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
            
            $user = Get-MgUser -UserId $userId -Property $properties -ErrorAction Stop
            
            # Check MFA status
            $mfaStatus = Test-UserMFA -UserId $user.Id -UserPrincipalName $user.UserPrincipalName
            
            # Skip if OnlyNoMFA is set and user has MFA
            if ($OnlyNoMFA -and $mfaStatus.HasMFA) {
                continue
            }
            
            # Get sign-in information
            $signInInfo = Get-SignInInfo -User $user
            
            # Process each role assignment for this user
            foreach ($roleAssignment in $userData.Roles) {
                # Skip if OnlyPermanent is set and this is a PIM assignment
                if ($OnlyPermanent -and $roleAssignment.AssignmentType -ne "Active") {
                    continue
                }
                
                $roleName = $roleAssignment.RoleName
                $roleRiskLevel = Get-RoleRiskLevel -RoleName $roleName
                
                # Calculate assignment duration
                $assignmentDuration = -1
                $assignmentDate = $null
                
                if ($roleAssignment.CreatedDateTime) {
                    $assignmentDate = [DateTime]$roleAssignment.CreatedDateTime
                    $assignmentDuration = ([DateTime]::Now - $assignmentDate).Days
                }
                elseif ($roleAssignment.StartDateTime) {
                    $assignmentDate = [DateTime]$roleAssignment.StartDateTime
                    $assignmentDuration = ([DateTime]::Now - $assignmentDate).Days
                }
                
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
                
                # Elevate risk if permanent assignment (vs PIM)
                if ($roleAssignment.AssignmentType -eq "Active" -and $roleRiskLevel -in @("CRITICAL", "HIGH")) {
                    if ($overallRisk -eq "CRITICAL") {
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
                
                $userInfo = [PSCustomObject]@{
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    Email = $user.Mail
                    AccountEnabled = $user.AccountEnabled
                    UserType = $user.UserType
                    JobTitle = $user.JobTitle
                    Department = $user.Department
                    CreatedDateTime = $user.CreatedDateTime
                    DaysOld = $daysOld
                    RoleName = $roleName
                    RoleId = $roleAssignment.RoleId
                    RoleRiskLevel = $roleRiskLevel
                    AssignmentType = $roleAssignment.AssignmentType
                    AssignmentDate = $assignmentDate
                    AssignmentDuration = $assignmentDuration
                    AssignmentEndDate = if ($roleAssignment.EndDateTime) { [DateTime]$roleAssignment.EndDateTime } else { $null }
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
                
                $script:PrivilegedUsers += $userInfo
            }
        }
        catch {
            Write-Host "`n[!] Error processing user $userId : $_" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n[+] Scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - PRIVILEGED ROLE ASSIGNMENTS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:PrivilegedUsers.Count -eq 0) {
        if ($OnlyNoMFA) {
            Write-Host "`n[+] All privileged users have MFA enabled." -ForegroundColor Green
        }
        elseif ($OnlyPermanent) {
            Write-Host "`n[+] No permanent role assignments found (all are PIM-managed)." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No privileged role assignments found." -ForegroundColor Yellow
        }
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:PrivilegedUsers | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Role Risk';Expression={$_.RoleRiskLevel}},
        @{Name='MFA';Expression={if($_.MFAEnabled){'Yes'}else{'No'}}},
        @{Name='Type';Expression={$_.AssignmentType}},
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}},
        @{Name='User Principal Name';Expression={$_.UserPrincipalName}},
        @{Name='Display Name';Expression={$_.DisplayName}},
        @{Name='Role';Expression={$_.RoleName}},
        @{Name='Last Sign-In';Expression={
            if($_.DaysSinceLastSignIn -eq -1){'Never'}
            elseif($_.DaysSinceLastSignIn -eq 0){'Today'}
            elseif($_.DaysSinceLastSignIn -eq 1){'Yesterday'}
            else{"$($_.DaysSinceLastSignIn)d ago"}
        }},
        @{Name='Duration';Expression={
            if($_.AssignmentDuration -eq -1){'-'}
            else{"$($_.AssignmentDuration)d"}
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
    Write-Host "Total role assignments: " -NoNewline -ForegroundColor White
    Write-Host $script:PrivilegedUsers.Count -ForegroundColor Yellow
    
    $uniqueUsers = ($script:PrivilegedUsers | Select-Object -Unique UserPrincipalName).Count
    Write-Host "Unique users with roles: " -NoNewline -ForegroundColor White
    Write-Host $uniqueUsers -ForegroundColor Yellow
    
    $criticalRisk = ($script:PrivilegedUsers | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:PrivilegedUsers | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:PrivilegedUsers | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:PrivilegedUsers | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Green
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Gray
    
    $withMFA = ($script:PrivilegedUsers | Where-Object { $_.MFAEnabled -eq $true }).Count
    $withoutMFA = ($script:PrivilegedUsers | Where-Object { $_.MFAEnabled -eq $false }).Count
    
    Write-Host "`n[MFA STATUS]" -ForegroundColor Cyan
    Write-Host "  With MFA enabled: " -NoNewline -ForegroundColor White
    Write-Host $withMFA -ForegroundColor Green
    Write-Host "  Without MFA: " -NoNewline -ForegroundColor White
    Write-Host $withoutMFA -ForegroundColor Red
    
    $permanent = ($script:PrivilegedUsers | Where-Object { $_.AssignmentType -eq "Active" }).Count
    $pimEligible = ($script:PrivilegedUsers | Where-Object { $_.AssignmentType -eq "PIM Eligible" }).Count
    $pimActive = ($script:PrivilegedUsers | Where-Object { $_.AssignmentType -eq "PIM Active" }).Count
    
    Write-Host "`n[ASSIGNMENT TYPES]" -ForegroundColor Cyan
    Write-Host "  Permanent (Active): " -NoNewline -ForegroundColor White
    Write-Host $permanent -ForegroundColor Yellow
    Write-Host "  PIM Eligible: " -NoNewline -ForegroundColor White
    Write-Host $pimEligible -ForegroundColor Cyan
    Write-Host "  PIM Active: " -NoNewline -ForegroundColor White
    Write-Host $pimActive -ForegroundColor Green
    
    # Group by role
    $byRole = $script:PrivilegedUsers | Group-Object RoleName | Sort-Object Count -Descending
    if ($byRole.Count -gt 0) {
        Write-Host "`n[USERS BY ROLE]" -ForegroundColor Cyan
        $byRole | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Group by department
    $byDept = $script:PrivilegedUsers | Where-Object { $_.Department } | Group-Object Department | Sort-Object Count -Descending
    if ($byDept.Count -gt 0) {
        Write-Host "`n[TOP DEPARTMENTS]" -ForegroundColor Cyan
        $byDept | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Sign-in activity statistics
    $neverSignedIn = ($script:PrivilegedUsers | Where-Object { $_.DaysSinceLastSignIn -eq -1 }).Count
    $recentSignIn = ($script:PrivilegedUsers | Where-Object { $_.DaysSinceLastSignIn -ge 0 -and $_.DaysSinceLastSignIn -le 30 }).Count
    $staleSignIn = ($script:PrivilegedUsers | Where-Object { $_.DaysSinceLastSignIn -gt 90 }).Count
    
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
    
    Write-Host "`nTotal role assignments: " -NoNewline -ForegroundColor White
    Write-Host $script:PrivilegedUsers.Count -ForegroundColor Yellow
    
    $uniqueUsers = ($script:PrivilegedUsers | Select-Object -Unique UserPrincipalName).Count
    Write-Host "Unique users with roles: " -NoNewline -ForegroundColor White
    Write-Host $uniqueUsers -ForegroundColor Yellow
    
    if ($script:PrivilegedUsers.Count -gt 0) {
        $criticalRisk = ($script:PrivilegedUsers | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:PrivilegedUsers | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:PrivilegedUsers | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:PrivilegedUsers | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        $withMFA = ($script:PrivilegedUsers | Where-Object { $_.MFAEnabled -eq $true }).Count
        $withoutMFA = ($script:PrivilegedUsers | Where-Object { $_.MFAEnabled -eq $false }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Green
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Gray
        
        Write-Host "`nMFA Status:" -ForegroundColor Cyan
        Write-Host "  - With MFA: " -NoNewline -ForegroundColor White
        Write-Host $withMFA -ForegroundColor Green
        Write-Host "  - Without MFA: " -NoNewline -ForegroundColor White
        Write-Host $withoutMFA -ForegroundColor Red
        
        $permanent = ($script:PrivilegedUsers | Where-Object { $_.AssignmentType -eq "Active" }).Count
        $pimEligible = ($script:PrivilegedUsers | Where-Object { $_.AssignmentType -eq "PIM Eligible" }).Count
        $pimActive = ($script:PrivilegedUsers | Where-Object { $_.AssignmentType -eq "PIM Active" }).Count
        
        Write-Host "`nAssignment Types:" -ForegroundColor Cyan
        Write-Host "  - Permanent (Active): " -NoNewline -ForegroundColor White
        Write-Host $permanent -ForegroundColor Yellow
        Write-Host "  - PIM Eligible: " -NoNewline -ForegroundColor White
        Write-Host $pimEligible -ForegroundColor Cyan
        Write-Host "  - PIM Active: " -NoNewline -ForegroundColor White
        Write-Host $pimActive -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "ROLE ASSIGNMENT DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:PrivilegedUsers | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Green" }
                "LOW" { "Gray" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host "$($_.UserPrincipalName) - $($_.RoleName)" -ForegroundColor White
            
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
            
            Write-Host "  Role: " -NoNewline -ForegroundColor Gray
            Write-Host $_.RoleName -ForegroundColor Cyan
            Write-Host "  Role Risk Level: " -NoNewline -ForegroundColor Gray
            Write-Host $_.RoleRiskLevel -ForegroundColor $(switch($_.RoleRiskLevel){"CRITICAL"{"Red"}"HIGH"{"Yellow"}default{"Green"}})
            
            Write-Host "  Assignment Type: " -NoNewline -ForegroundColor Gray
            $typeColor = switch($_.AssignmentType) {
                "Active" { "Yellow" }
                "PIM Eligible" { "Cyan" }
                "PIM Active" { "Green" }
                default { "White" }
            }
            Write-Host $_.AssignmentType -ForegroundColor $typeColor
            
            if ($_.AssignmentDate) {
                Write-Host "  Assignment Date: $($_.AssignmentDate) ($($_.AssignmentDuration) days ago)" -ForegroundColor Gray
            }
            if ($_.AssignmentEndDate) {
                Write-Host "  Assignment End Date: $($_.AssignmentEndDate)" -ForegroundColor Gray
            }
            
            Write-Host "  MFA Enabled: " -NoNewline -ForegroundColor Gray
            if ($_.MFAEnabled) {
                Write-Host "Yes" -ForegroundColor Green
            }
            else {
                Write-Host "No" -ForegroundColor Red
            }
            Write-Host "  Auth Methods: $($_.AuthMethods)" -ForegroundColor Gray
            
            Write-Host "  Last Sign-In: " -NoNewline -ForegroundColor Gray
            if ($_.LastSignIn) {
                Write-Host $_.LastSignInDisplay -NoNewline -ForegroundColor $(if($_.DaysSinceLastSignIn -gt 90){"Red"}elseif($_.DaysSinceLastSignIn -gt 30){"Yellow"}else{"Green"})
                Write-Host " ($($_.SignInType))" -ForegroundColor DarkGray
            }
            else {
                Write-Host "Never signed in" -ForegroundColor DarkGray
            }
            
            Write-Host "  Created: $($_.CreatedDateTime) ($($_.DaysOld) days old)" -ForegroundColor Gray
            
            if ($_.HasLicenses) {
                Write-Host "  Licenses: $($_.LicenseCount) assigned" -ForegroundColor Gray
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        if ($OnlyNoMFA) {
            Write-Host "`n[+] All privileged users have MFA enabled." -ForegroundColor Green
        }
        elseif ($OnlyPermanent) {
            Write-Host "`n[+] No permanent role assignments found (all are PIM-managed)." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No privileged role assignments found." -ForegroundColor Yellow
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
    
    if ($script:PrivilegedUsers.Count -eq 0) {
        Write-Host "`n[*] No role assignments to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:PrivilegedUsers | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:PrivilegedUsers | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:PrivilegedUsers | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] Disconnected from Microsoft Graph" -ForegroundColor Green
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
        Start-RoleScan
        
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
        
        Write-Host "`n[*] Privileged role check completed successfully!" -ForegroundColor Green
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

