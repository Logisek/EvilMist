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
    Analyzes Azure Entra ID attack paths including privilege escalation, password reset delegations, transitive group memberships, and shared mailbox access.

.DESCRIPTION
    This script performs comprehensive attack path analysis to identify potential privilege escalation paths,
    password reset delegations, transitive group memberships, and shared mailbox access patterns.
    It provides risk assessment based on discovered attack paths and helps security teams identify
    and remediate security vulnerabilities.
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Attack paths analyzed include:
    - Privilege escalation paths through role assignments and group memberships
    - Password reset delegations (users who can reset other users' passwords)
    - Transitive group memberships (indirect access to privileged groups)
    - Shared mailbox access (users with access to shared mailboxes)
    - Risk assessment based on attack path complexity and impact
    
    Information collected includes:
    - Attack path details and complexity
    - User identification and security posture
    - MFA status and authentication methods
    - Last sign-in activity
    - Risk assessment based on path criticality

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

.PARAMETER OnlyHighRisk
    Show only attack paths with CRITICAL or HIGH risk.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraAttackPathCheck.ps1
    # Analyze all attack paths

.EXAMPLE
    .\Invoke-EntraAttackPathCheck.ps1 -ExportPath "attack-paths.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraAttackPathCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraAttackPathCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraAttackPathCheck.ps1 -OnlyHighRisk -Matrix
    # Display only high-risk attack paths in matrix format

.EXAMPLE
    .\Invoke-EntraAttackPathCheck.ps1 -Matrix -ExportPath "results.csv"
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
    [switch]$OnlyHighRisk,

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

# Required scopes for attack path checking
$script:RequiredScopes = @(
    "Directory.Read.All",
    "Group.Read.All",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "RoleManagement.Read.Directory",
    "AuditLog.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Directory.Read.All",
    "Group.Read.All",
    "User.ReadBasic.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:AttackPaths = @()
$script:TotalPathsScanned = 0
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
    Write-Host "    Entra ID Attack Path Analysis - Privilege Escalation & Lateral Movement" -ForegroundColor Yellow
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
        "Microsoft.Graph.Groups",
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
        
        Write-Host "[*] Importing Microsoft.Graph.Groups..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Groups -Force -ErrorAction Stop
        
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

# Analyze privilege escalation paths
function Get-PrivilegeEscalationPaths {
    Write-Host "`n[*] Analyzing privilege escalation paths..." -ForegroundColor Cyan
    
    $paths = @()
    
    try {
        # Get all directory roles
        Invoke-StealthDelay
        $roles = Get-MgDirectoryRole -All -ErrorAction Stop
        Write-Host "[+] Found $($roles.Count) directory role(s)" -ForegroundColor Green
        
        # Get all groups
        Invoke-StealthDelay
        $allGroups = Get-MgGroup -All -Property Id,DisplayName,IsAssignableToRole,SecurityEnabled -ErrorAction Stop
        Write-Host "[+] Found $($allGroups.Count) group(s)" -ForegroundColor Green
        
        # Identify role-assignable groups
        $roleAssignableGroups = $allGroups | Where-Object { $_.IsAssignableToRole -eq $true }
        Write-Host "[+] Found $($roleAssignableGroups.Count) role-assignable group(s)" -ForegroundColor Yellow
        
        # Analyze each role-assignable group
        foreach ($group in $roleAssignableGroups) {
            try {
                Invoke-StealthDelay
                
                # Get transitive members
                $transitiveMembers = Get-MgGroupTransitiveMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
                $users = $transitiveMembers | Where-Object { 
                    $_.'@odata.type' -eq '#microsoft.graph.user' -or 
                    $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' 
                }
                
                foreach ($member in ($users | Select-Object -First 100)) {
                    try {
                        Invoke-StealthDelay
                        $user = Get-MgUser -UserId $member.Id -Property Id,DisplayName,UserPrincipalName,AccountEnabled,SignInActivity -ErrorAction Stop
                        
                        if (-not $IncludeDisabledUsers -and -not $user.AccountEnabled) {
                            continue
                        }
                        
                        $mfaStatus = Test-UserMFA -UserId $user.Id -UserPrincipalName $user.UserPrincipalName
                        $signInInfo = Get-SignInInfo -User $user
                        
                        # Determine risk level
                        $riskLevel = "CRITICAL"
                        if (-not $mfaStatus.HasMFA) {
                            $riskLevel = "CRITICAL"
                        }
                        elseif (-not $user.AccountEnabled) {
                            $riskLevel = "MEDIUM"
                        }
                        else {
                            $riskLevel = "HIGH"
                        }
                        
                        $paths += [PSCustomObject]@{
                            AttackPathType = "Privilege Escalation"
                            SourceUser = $user.UserPrincipalName
                            SourceDisplayName = $user.DisplayName
                            SourceUserId = $user.Id
                            TargetResource = $group.DisplayName
                            TargetResourceId = $group.Id
                            PathDescription = "User has transitive membership in role-assignable group"
                            PathComplexity = "Medium"
                            AccessType = "Transitive Group Membership"
                            RiskLevel = $riskLevel
                            MFAEnabled = $mfaStatus.HasMFA
                            AccountEnabled = $user.AccountEnabled
                            LastSignIn = $signInInfo.LastSignIn
                            DaysSinceLastSignIn = $signInInfo.DaysAgo
                        }
                    }
                    catch {
                        # Skip user if we can't process
                    }
                }
            }
            catch {
                Write-Host "[!] Error analyzing group $($group.DisplayName): $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "[+] Identified $($paths.Count) privilege escalation path(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing privilege escalation paths: $_" -ForegroundColor Yellow
    }
    
    return $paths
}

# Check password reset delegations
function Get-PasswordResetDelegations {
    Write-Host "`n[*] Checking password reset delegations..." -ForegroundColor Cyan
    
    $delegations = @()
    
    try {
        # Get users with User Administrator or Helpdesk Administrator roles
        $targetRoles = @("User Administrator", "Helpdesk Administrator", "Privileged Authentication Administrator")
        
        foreach ($roleName in $targetRoles) {
            try {
                Invoke-StealthDelay
                $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
                
                if ($role) {
                    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
                    $userMembers = $members | Where-Object { 
                        $_.'@odata.type' -eq '#microsoft.graph.user' -or 
                        $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' 
                    }
                    
                    foreach ($member in $userMembers) {
                        try {
                            Invoke-StealthDelay
                            $user = Get-MgUser -UserId $member.Id -Property Id,DisplayName,UserPrincipalName,AccountEnabled,SignInActivity -ErrorAction Stop
                            
                            if (-not $IncludeDisabledUsers -and -not $user.AccountEnabled) {
                                continue
                            }
                            
                            $mfaStatus = Test-UserMFA -UserId $user.Id -UserPrincipalName $user.UserPrincipalName
                            $signInInfo = Get-SignInInfo -User $user
                            
                            # Determine risk level
                            $riskLevel = "CRITICAL"
                            if (-not $mfaStatus.HasMFA) {
                                $riskLevel = "CRITICAL"
                            }
                            elseif (-not $user.AccountEnabled) {
                                $riskLevel = "MEDIUM"
                            }
                            else {
                                $riskLevel = "HIGH"
                            }
                            
                            $delegations += [PSCustomObject]@{
                                AttackPathType = "Password Reset Delegation"
                                SourceUser = $user.UserPrincipalName
                                SourceDisplayName = $user.DisplayName
                                SourceUserId = $user.Id
                                TargetResource = "All Users (via $roleName role)"
                                TargetResourceId = $role.Id
                                PathDescription = "User can reset passwords for all users via $roleName role"
                                PathComplexity = "Low"
                                AccessType = "Directory Role"
                                RiskLevel = $riskLevel
                                MFAEnabled = $mfaStatus.HasMFA
                                AccountEnabled = $user.AccountEnabled
                                LastSignIn = $signInInfo.LastSignIn
                                DaysSinceLastSignIn = $signInInfo.DaysAgo
                            }
                        }
                        catch {
                            # Skip user if we can't process
                        }
                    }
                }
            }
            catch {
                Write-Host "[!] Error checking role $roleName : $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "[+] Identified $($delegations.Count) password reset delegation(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error checking password reset delegations: $_" -ForegroundColor Yellow
    }
    
    return $delegations
}

# Analyze transitive group memberships
function Get-TransitiveGroupMemberships {
    Write-Host "`n[*] Analyzing transitive group memberships..." -ForegroundColor Cyan
    
    $memberships = @()
    
    try {
        # Get privileged groups (role-assignable or with privileged names)
        $privilegedGroupNames = @(
            "Global Administrator", "Privileged Role Administrator",
            "User Administrator", "Exchange Administrator",
            "Security Administrator", "Helpdesk Administrator"
        )
        
        Invoke-StealthDelay
        $allGroups = Get-MgGroup -All -Property Id,DisplayName,IsAssignableToRole,SecurityEnabled -ErrorAction Stop
        
        $privilegedGroups = $allGroups | Where-Object { 
            $_.IsAssignableToRole -eq $true -or
            ($privilegedGroupNames | Where-Object { $_.DisplayName -like "*$_*" })
        }
        
        Write-Host "[+] Found $($privilegedGroups.Count) privileged group(s)" -ForegroundColor Yellow
        
        foreach ($group in ($privilegedGroups | Select-Object -First 20)) {
            try {
                Invoke-StealthDelay
                
                # Get direct and transitive members
                $directMembers = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
                $transitiveMembers = Get-MgGroupTransitiveMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
                
                $directUsers = $directMembers | Where-Object { 
                    $_.'@odata.type' -eq '#microsoft.graph.user' -or 
                    $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' 
                }
                $transitiveUsers = $transitiveMembers | Where-Object { 
                    $_.'@odata.type' -eq '#microsoft.graph.user' -or 
                    $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' 
                }
                
                # Find indirect users (transitive but not direct)
                $directUserIds = $directUsers | ForEach-Object { $_.Id }
                $indirectUsers = $transitiveUsers | Where-Object { $_.Id -notin $directUserIds }
                
                foreach ($user in ($indirectUsers | Select-Object -First 50)) {
                    try {
                        Invoke-StealthDelay
                        $userInfo = Get-MgUser -UserId $user.Id -Property Id,DisplayName,UserPrincipalName,AccountEnabled,SignInActivity -ErrorAction Stop
                        
                        if (-not $IncludeDisabledUsers -and -not $userInfo.AccountEnabled) {
                            continue
                        }
                        
                        $mfaStatus = Test-UserMFA -UserId $userInfo.Id -UserPrincipalName $userInfo.UserPrincipalName
                        $signInInfo = Get-SignInInfo -User $userInfo
                        
                        # Determine risk level
                        $riskLevel = "HIGH"
                        if ($group.IsAssignableToRole) {
                            $riskLevel = "CRITICAL"
                        }
                        elseif (-not $mfaStatus.HasMFA) {
                            $riskLevel = "CRITICAL"
                        }
                        elseif (-not $userInfo.AccountEnabled) {
                            $riskLevel = "MEDIUM"
                        }
                        
                        $memberships += [PSCustomObject]@{
                            AttackPathType = "Transitive Group Membership"
                            SourceUser = $userInfo.UserPrincipalName
                            SourceDisplayName = $userInfo.DisplayName
                            SourceUserId = $userInfo.Id
                            TargetResource = $group.DisplayName
                            TargetResourceId = $group.Id
                            PathDescription = "User has indirect access to privileged group via nested membership"
                            PathComplexity = "Medium"
                            AccessType = "Transitive Membership"
                            RiskLevel = $riskLevel
                            MFAEnabled = $mfaStatus.HasMFA
                            AccountEnabled = $userInfo.AccountEnabled
                            LastSignIn = $signInInfo.LastSignIn
                            DaysSinceLastSignIn = $signInInfo.DaysAgo
                        }
                    }
                    catch {
                        # Skip user if we can't process
                    }
                }
            }
            catch {
                Write-Host "[!] Error analyzing group $($group.DisplayName): $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "[+] Identified $($memberships.Count) transitive membership path(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing transitive group memberships: $_" -ForegroundColor Yellow
    }
    
    return $memberships
}

# Check shared mailbox access
function Get-SharedMailboxAccess {
    Write-Host "`n[*] Checking shared mailbox access..." -ForegroundColor Cyan
    
    $mailboxAccess = @()
    
    try {
        # Get all users
        Invoke-StealthDelay
        $allUsers = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,Mail,AccountEnabled,AssignedLicenses,SignInActivity -ErrorAction Stop
        
        # Identify shared mailboxes (users without licenses or with shared mailbox indicators)
        $sharedIndicators = @("shared", "info@", "support@", "sales@", "hr@", "finance@", "admin@", "noreply@", "helpdesk@", "team@", "group@")
        $highValueIndicators = @("finance", "hr", "admin", "exec", "legal", "ceo", "cfo")
        
        $sharedMailboxes = @()
        foreach ($user in $allUsers) {
            $isShared = $false
            $mail = ($user.Mail, $user.UserPrincipalName | Where-Object { $_ } | Select-Object -First 1) -replace '\s+', ''
            
            # Check indicators
            foreach ($indicator in $sharedIndicators) {
                if ($mail -like "*$indicator*") {
                    $isShared = $true
                    break
                }
            }
            
            # Users without licenses might be shared mailboxes
            if (-not $user.AssignedLicenses -or $user.AssignedLicenses.Count -eq 0) {
                if ($user.Mail -or $user.UserPrincipalName) {
                    $isShared = $true
                }
            }
            
            if ($isShared) {
                $sharedMailboxes += $user
            }
        }
        
        Write-Host "[+] Found $($sharedMailboxes.Count) potential shared mailbox(es)" -ForegroundColor Yellow
        
        # For each shared mailbox, check who has access
        # Note: This is a simplified check - full mailbox permissions require Exchange Online PowerShell
        foreach ($mailbox in ($sharedMailboxes | Select-Object -First 50)) {
            try {
                # Check if mailbox is high-value
                $isHighValue = $false
                $mail = ($mailbox.Mail, $mailbox.UserPrincipalName | Where-Object { $_ } | Select-Object -First 1) -replace '\s+', ''
                foreach ($indicator in $highValueIndicators) {
                    if ($mail -like "*$indicator*") {
                        $isHighValue = $true
                        break
                    }
                }
                
                # Create entry for the shared mailbox itself
                $signInInfo = Get-SignInInfo -User $mailbox
                
                $mailboxAccess += [PSCustomObject]@{
                    AttackPathType = "Shared Mailbox Access"
                    SourceUser = $mailbox.UserPrincipalName
                    SourceDisplayName = $mailbox.DisplayName
                    SourceUserId = $mailbox.Id
                    TargetResource = "Shared Mailbox: $($mailbox.DisplayName)"
                    TargetResourceId = $mailbox.Id
                    PathDescription = "Shared mailbox identified (potential lateral movement target)"
                    PathComplexity = "Low"
                    AccessType = "Shared Mailbox"
                    RiskLevel = if ($isHighValue) { "HIGH" } else { "MEDIUM" }
                    MFAEnabled = $false  # Shared mailboxes typically don't have MFA
                    AccountEnabled = $mailbox.AccountEnabled
                    LastSignIn = $signInInfo.LastSignIn
                    DaysSinceLastSignIn = $signInInfo.DaysAgo
                }
            }
            catch {
                # Skip mailbox if we can't process
            }
        }
        
        Write-Host "[+] Identified $($mailboxAccess.Count) shared mailbox access path(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error checking shared mailbox access: $_" -ForegroundColor Yellow
        Write-Host "[!] Note: Full mailbox permissions require Exchange Online PowerShell" -ForegroundColor Yellow
    }
    
    return $mailboxAccess
}

# Main scanning function
function Start-AttackPathScan {
    Write-Host "`n[*] Starting attack path analysis..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the tenant size..." -ForegroundColor Cyan
    
    # Analyze different attack path types
    $privilegeEscalationPaths = Get-PrivilegeEscalationPaths
    $passwordResetDelegations = Get-PasswordResetDelegations
    $transitiveMemberships = Get-TransitiveGroupMemberships
    $sharedMailboxAccess = Get-SharedMailboxAccess
    
    # Combine all attack paths
    $script:AttackPaths = @()
    $script:AttackPaths += $privilegeEscalationPaths
    $script:AttackPaths += $passwordResetDelegations
    $script:AttackPaths += $transitiveMemberships
    $script:AttackPaths += $sharedMailboxAccess
    
    $script:TotalPathsScanned = $script:AttackPaths.Count
    
    # Filter if OnlyHighRisk is set
    if ($OnlyHighRisk) {
        $script:AttackPaths = $script:AttackPaths | Where-Object { 
            $_.RiskLevel -eq "CRITICAL" -or $_.RiskLevel -eq "HIGH" 
        }
    }
    
    Write-Host "`n[+] Attack path analysis complete!" -ForegroundColor Green
    Write-Host "[+] Total attack paths identified: $($script:AttackPaths.Count)" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - ATTACK PATH ANALYSIS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:AttackPaths.Count -eq 0) {
        if ($OnlyHighRisk) {
            Write-Host "`n[+] No high-risk attack paths found." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No attack paths found." -ForegroundColor Yellow
        }
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:AttackPaths | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Path Type';Expression={$_.AttackPathType}},
        @{Name='Source User';Expression={$_.SourceUser}},
        @{Name='Target Resource';Expression={$_.TargetResource}},
        @{Name='Complexity';Expression={$_.PathComplexity}},
        @{Name='MFA';Expression={if($_.MFAEnabled){'Yes'}else{'No'}}},
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}},
        @{Name='Last Sign-In';Expression={
            if($_.DaysSinceLastSignIn -eq -1){'Never'}
            elseif($_.DaysSinceLastSignIn -eq 0){'Today'}
            elseif($_.DaysSinceLastSignIn -eq 1){'Yesterday'}
            else{"$($_.DaysSinceLastSignIn)d ago"}
        }}
    
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
    Write-Host "Total attack paths: " -NoNewline -ForegroundColor White
    Write-Host $script:AttackPaths.Count -ForegroundColor Yellow
    
    $criticalRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    
    Write-Host "`n[RISK BREAKDOWN]" -ForegroundColor Cyan
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Green
    
    # Group by attack path type
    $byType = $script:AttackPaths | Group-Object AttackPathType | Sort-Object Count -Descending
    if ($byType.Count -gt 0) {
        Write-Host "`n[ATTACK PATHS BY TYPE]" -ForegroundColor Cyan
        $byType | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # MFA statistics
    $withMFA = ($script:AttackPaths | Where-Object { $_.MFAEnabled -eq $true }).Count
    $withoutMFA = ($script:AttackPaths | Where-Object { $_.MFAEnabled -eq $false }).Count
    
    Write-Host "`n[MFA STATUS]" -ForegroundColor Cyan
    Write-Host "  With MFA enabled: " -NoNewline -ForegroundColor White
    Write-Host $withMFA -ForegroundColor Green
    Write-Host "  Without MFA: " -NoNewline -ForegroundColor White
    Write-Host $withoutMFA -ForegroundColor Red
    
    Write-Host ""
}

# Display results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal attack paths identified: " -NoNewline -ForegroundColor White
    Write-Host $script:AttackPaths.Count -ForegroundColor Yellow
    
    if ($script:AttackPaths.Count -gt 0) {
        $criticalRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:AttackPaths | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "ATTACK PATH DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:AttackPaths | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host "$($_.AttackPathType): $($_.SourceUser)" -ForegroundColor White
            
            Write-Host "  Source User: $($_.SourceDisplayName) ($($_.SourceUser))" -ForegroundColor Gray
            Write-Host "  Target Resource: $($_.TargetResource)" -ForegroundColor Gray
            Write-Host "  Path Description: $($_.PathDescription)" -ForegroundColor Gray
            Write-Host "  Path Complexity: $($_.PathComplexity)" -ForegroundColor Gray
            Write-Host "  Access Type: $($_.AccessType)" -ForegroundColor Gray
            
            Write-Host "  Account Status: " -NoNewline -ForegroundColor Gray
            if ($_.AccountEnabled) {
                Write-Host "Enabled" -ForegroundColor Green
            }
            else {
                Write-Host "Disabled" -ForegroundColor Yellow
            }
            
            Write-Host "  MFA Enabled: " -NoNewline -ForegroundColor Gray
            if ($_.MFAEnabled) {
                Write-Host "Yes" -ForegroundColor Green
            }
            else {
                Write-Host "No" -ForegroundColor Red
            }
            
            Write-Host "  Last Sign-In: " -NoNewline -ForegroundColor Gray
            if ($_.LastSignIn) {
                $signInDate = [DateTime]$_.LastSignIn
                Write-Host "$($signInDate.ToString('yyyy-MM-dd HH:mm:ss')) ($($_.DaysSinceLastSignIn) days ago)" -ForegroundColor $(if($_.DaysSinceLastSignIn -gt 90){"Red"}elseif($_.DaysSinceLastSignIn -gt 30){"Yellow"}else{"Green"})
            }
            else {
                Write-Host "Never signed in" -ForegroundColor DarkGray
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        if ($OnlyHighRisk) {
            Write-Host "`n[+] No high-risk attack paths found." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No attack paths found." -ForegroundColor Yellow
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
        
        Write-Host "`n[*] Attack path analysis completed successfully!" -ForegroundColor Green
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

