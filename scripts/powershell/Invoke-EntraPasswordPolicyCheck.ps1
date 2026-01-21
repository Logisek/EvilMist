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
    Analyzes Azure Entra ID password policies to identify security gaps and weak configurations.

.DESCRIPTION
    This script queries Azure Entra ID to perform comprehensive password policy analysis:
    - Checks password expiration policies per user
    - Identifies users with "password never expires"
    - Checks password complexity requirements
    - Identifies users with weak password policies
    - Risk assessment based on policy strength
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Information collected includes:
    - User password policy settings
    - Password expiration status
    - Password complexity requirements
    - Last password change date
    - Password age and expiration risk
    - Risk assessment based on policy strength

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

.PARAMETER OnlyWeakPolicies
    Show only users with weak password policies.

.PARAMETER OnlyNeverExpires
    Show only users with password never expires.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraPasswordPolicyCheck.ps1
    # Analyze all password policies

.EXAMPLE
    .\Invoke-EntraPasswordPolicyCheck.ps1 -ExportPath "password-policies.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraPasswordPolicyCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraPasswordPolicyCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraPasswordPolicyCheck.ps1 -OnlyNeverExpires -Matrix
    # Display only users with password never expires in matrix format

.EXAMPLE
    .\Invoke-EntraPasswordPolicyCheck.ps1 -OnlyWeakPolicies -ExportPath "weak-policies.csv"
    # Show only users with weak password policies and export

.EXAMPLE
    .\Invoke-EntraPasswordPolicyCheck.ps1 -Matrix -ExportPath "results.csv"
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
    [switch]$OnlyWeakPolicies,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyNeverExpires,

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

# Required scopes for password policy checking
$script:RequiredScopes = @(
    "User.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "User.ReadBasic.All",
    "Directory.Read.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:PasswordPolicies = @()
$script:TotalUsersScanned = 0
$script:DirectoryPasswordPolicy = $null
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
    Write-Host "    Entra ID Password Policy Check - Password Security Analysis" -ForegroundColor Yellow
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

# Get directory-level password policy (if available)
function Get-DirectoryPasswordPolicy {
    Write-Host "`n[*] Retrieving directory password policy..." -ForegroundColor Cyan
    
    try {
        # Try to get password authentication method configuration
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy"
        $policy = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
        
        if ($policy) {
            Write-Host "[+] Retrieved directory password policy configuration" -ForegroundColor Green
            $script:DirectoryPasswordPolicy = $policy
            return $policy
        }
    }
    catch {
        Write-Host "[!] Could not retrieve directory password policy (may require additional permissions)" -ForegroundColor Yellow
    }
    
    return $null
}

# Analyze password policy for a user
function Analyze-PasswordPolicy {
    param(
        [Parameter(Mandatory = $true)]
        $User
    )
    
    $passwordPolicies = $User.PasswordPolicies
    $lastPwdChange = $User.LastPasswordChangeDateTime
    $passwordProfile = $User.PasswordProfile
    
    # Parse password policy flags
    $neverExpires = $false
    $strongPwdDisabled = $false
    $passwordPoliciesList = @()
    
    if ($passwordPolicies) {
        if ($passwordPolicies -like "*DisablePasswordExpiration*") {
            $neverExpires = $true
            $passwordPoliciesList += "DisablePasswordExpiration"
        }
        if ($passwordPolicies -like "*DisableStrongPassword*") {
            $strongPwdDisabled = $true
            $passwordPoliciesList += "DisableStrongPassword"
        }
        if ($passwordPolicies -like "*None*") {
            $passwordPoliciesList += "None"
        }
    }
    
    # Calculate password age
    $passwordAge = $null
    $daysSincePwdChange = -1
    $isExpired = $false
    $expiresInDays = -1
    
    if ($lastPwdChange) {
        try {
            $pwdDate = [DateTime]$lastPwdChange
            $passwordAge = $pwdDate
            $daysSincePwdChange = ([DateTime]::Now - $pwdDate).Days
            
            # Estimate expiration (assuming 90-day default, but this may vary)
            if (-not $neverExpires) {
                $estimatedExpirationDays = 90  # Default Azure AD password expiration
                $expiresInDays = $estimatedExpirationDays - $daysSincePwdChange
                
                if ($daysSincePwdChange -gt $estimatedExpirationDays) {
                    $isExpired = $true
                }
            }
        }
        catch {
            # Could not parse date
        }
    }
    
    # Determine risk level
    $riskLevel = "LOW"
    $riskReasons = @()
    
    # CRITICAL: Strong password disabled AND never expires
    if ($strongPwdDisabled -and $neverExpires) {
        $riskLevel = "CRITICAL"
        $riskReasons += "Strong password disabled + Never expires"
    }
    # HIGH: Strong password disabled OR never expires with old password
    elseif ($strongPwdDisabled) {
        $riskLevel = "HIGH"
        $riskReasons += "Strong password disabled"
    }
    elseif ($neverExpires) {
        $riskLevel = "HIGH"
        $riskReasons += "Password never expires"
    }
    elseif ($isExpired) {
        $riskLevel = "HIGH"
        $riskReasons += "Password expired ($daysSincePwdChange days old)"
    }
    # MEDIUM: Old password or approaching expiration
    elseif ($daysSincePwdChange -gt 365) {
        $riskLevel = "MEDIUM"
        $riskReasons += "Password >365 days old"
    }
    elseif ($expiresInDays -ge 0 -and $expiresInDays -le 7) {
        $riskLevel = "MEDIUM"
        $riskReasons += "Password expiring soon ($expiresInDays days)"
    }
    
    # Policy strength assessment
    $policyStrength = "Strong"
    if ($strongPwdDisabled) {
        $policyStrength = "Weak"
    }
    elseif ($neverExpires) {
        $policyStrength = "Moderate"
    }
    
    return @{
        NeverExpires = $neverExpires
        StrongPasswordDisabled = $strongPwdDisabled
        PasswordPolicies = ($passwordPoliciesList -join ", ")
        LastPasswordChange = $passwordAge
        DaysSincePasswordChange = $daysSincePwdChange
        IsExpired = $isExpired
        ExpiresInDays = $expiresInDays
        RiskLevel = $riskLevel
        RiskReasons = ($riskReasons -join "; ")
        PolicyStrength = $policyStrength
    }
}

# Main scanning function
function Start-PasswordPolicyScan {
    Write-Host "`n[*] Starting password policy scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of users..." -ForegroundColor Cyan
    
    # Get directory password policy
    Get-DirectoryPasswordPolicy
    
    # Get all users
    Write-Host "`n[*] Retrieving users from Azure Entra ID..." -ForegroundColor Cyan
    
    try {
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
            'PasswordPolicies',
            'LastPasswordChangeDateTime'
        )
        
        $filter = if (-not $IncludeDisabledUsers) { "accountEnabled eq true" } else { $null }
        
        if ($filter) {
            Write-Host "[*] Filtering: Enabled users only" -ForegroundColor Cyan
        }
        else {
            Write-Host "[*] Filtering: All users (including disabled)" -ForegroundColor Cyan
        }
        
        if ($filter) {
            $users = Get-MgUser -Filter $filter -All -Property $properties -ErrorAction Stop
        }
        else {
            $users = Get-MgUser -All -Property $properties -ErrorAction Stop
        }
        
        $allUsers = $users | ForEach-Object { $_ }
        $script:TotalUsersScanned = $allUsers.Count
        
        Write-Host "[+] Retrieved $($allUsers.Count) users" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve users: $_" -ForegroundColor Red
        Write-Host "[!] Note: LastPasswordChangeDateTime requires AuditLog.Read.All permission" -ForegroundColor Yellow
        
        # Try without LastPasswordChangeDateTime if it fails
        try {
            Write-Host "[*] Retrying without password change date..." -ForegroundColor Yellow
            $basicProperties = @('Id','DisplayName','UserPrincipalName','AccountEnabled','Mail','JobTitle','Department','CreatedDateTime','UserType','PasswordPolicies')
            
            if ($filter) {
                $users = Get-MgUser -Filter $filter -All -Property $basicProperties -ErrorAction Stop
            }
            else {
                $users = Get-MgUser -All -Property $basicProperties -ErrorAction Stop
            }
            
            $allUsers = $users | ForEach-Object { $_ }
            $script:TotalUsersScanned = $allUsers.Count
            Write-Host "[+] Retrieved $($allUsers.Count) users (without password change date)" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] Failed to retrieve users: $_" -ForegroundColor Red
            return
        }
    }
    
    if ($allUsers.Count -eq 0) {
        Write-Host "[!] No users found to scan" -ForegroundColor Yellow
        return
    }
    
    $progressCounter = 0
    
    Write-Host "`n[*] Analyzing password policies for each user..." -ForegroundColor Cyan
    
    foreach ($user in $allUsers) {
        $progressCounter++
        
        # Progress indicator
        if ($progressCounter % 10 -eq 0 -or $progressCounter -eq $allUsers.Count) {
            $percentComplete = [math]::Round(($progressCounter / $allUsers.Count) * 100, 1)
            Write-Host "`r[*] Progress: $progressCounter/$($allUsers.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
        }
        
        try {
            # Analyze password policy
            $analysis = Analyze-PasswordPolicy -User $user
            
            # Filter: Only weak policies
            if ($OnlyWeakPolicies -and $analysis.PolicyStrength -eq "Strong" -and -not $analysis.NeverExpires) {
                continue
            }
            
            # Filter: Only never expires
            if ($OnlyNeverExpires -and -not $analysis.NeverExpires) {
                continue
            }
            
            # Get sign-in information
            $signInInfo = Get-SignInInfo -User $user
            
            # Build policy info object
            $policyInfo = [PSCustomObject]@{
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Email = $user.Mail
                AccountEnabled = $user.AccountEnabled
                UserType = $user.UserType
                JobTitle = $user.JobTitle
                Department = $user.Department
                CreatedDateTime = $user.CreatedDateTime
                PasswordPolicies = $analysis.PasswordPolicies
                NeverExpires = $analysis.NeverExpires
                StrongPasswordDisabled = $analysis.StrongPasswordDisabled
                PolicyStrength = $analysis.PolicyStrength
                LastPasswordChange = $analysis.LastPasswordChange
                DaysSincePasswordChange = $analysis.DaysSincePasswordChange
                IsExpired = $analysis.IsExpired
                ExpiresInDays = $analysis.ExpiresInDays
                PasswordAgeDisplay = if ($analysis.NeverExpires) { "Never expires" } elseif ($analysis.DaysSincePasswordChange -ge 0) { "$($analysis.DaysSincePasswordChange) days old" } else { "Unknown" }
                LastSignIn = $signInInfo.LastSignIn
                LastSignInDisplay = $signInInfo.DisplayText
                DaysSinceLastSignIn = $signInInfo.DaysAgo
                SignInType = $signInInfo.SignInType
                RiskLevel = $analysis.RiskLevel
                RiskReasons = $analysis.RiskReasons
            }
            
            $script:PasswordPolicies += $policyInfo
        }
        catch {
            Write-Host "`n[!] Error processing user $($user.UserPrincipalName): $_" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n[+] Scan complete!" -ForegroundColor Green
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

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - PASSWORD POLICY SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:PasswordPolicies.Count -eq 0) {
        Write-Host "`n[+] All users have strong password policies configured." -ForegroundColor Green
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:PasswordPolicies | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Policy';Expression={$_.PolicyStrength}},
        @{Name='Never Expires';Expression={if($_.NeverExpires){'Yes'}else{'No'}}},
        @{Name='Strong Pwd';Expression={if($_.StrongPasswordDisabled){'Disabled'}else{'Enabled'}}},
        @{Name='User Principal Name';Expression={$_.UserPrincipalName}},
        @{Name='Display Name';Expression={$_.DisplayName}},
        @{Name='Password Age';Expression={$_.PasswordAgeDisplay}},
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
    Write-Host "Total users scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalUsersScanned -ForegroundColor Yellow
    Write-Host "Users with policy issues: " -NoNewline -ForegroundColor White
    Write-Host $script:PasswordPolicies.Count -ForegroundColor $(if($script:PasswordPolicies.Count -gt 0){"Yellow"}else{"Green"})
    
    $criticalRisk = ($script:PasswordPolicies | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:PasswordPolicies | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:PasswordPolicies | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:PasswordPolicies | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Cyan
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    $neverExpires = ($script:PasswordPolicies | Where-Object { $_.NeverExpires -eq $true }).Count
    $strongPwdDisabled = ($script:PasswordPolicies | Where-Object { $_.StrongPasswordDisabled -eq $true }).Count
    $expiredPasswords = ($script:PasswordPolicies | Where-Object { $_.IsExpired -eq $true }).Count
    $weakPolicies = ($script:PasswordPolicies | Where-Object { $_.PolicyStrength -eq "Weak" }).Count
    
    Write-Host "`n[PASSWORD POLICY GAPS]" -ForegroundColor Cyan
    Write-Host "  Users with password never expires: " -NoNewline -ForegroundColor White
    Write-Host $neverExpires -ForegroundColor Yellow
    Write-Host "  Users with strong password disabled: " -NoNewline -ForegroundColor White
    Write-Host $strongPwdDisabled -ForegroundColor Red
    Write-Host "  Users with expired passwords: " -NoNewline -ForegroundColor White
    Write-Host $expiredPasswords -ForegroundColor Red
    Write-Host "  Users with weak policies: " -NoNewline -ForegroundColor White
    Write-Host $weakPolicies -ForegroundColor Yellow
    
    # Group by department
    $byDept = $script:PasswordPolicies | Where-Object { $_.Department } | Group-Object Department | Sort-Object Count -Descending
    if ($byDept.Count -gt 0) {
        Write-Host "`n[TOP DEPARTMENTS WITH POLICY ISSUES]" -ForegroundColor Cyan
        $byDept | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Password age statistics
    $oldPasswords = ($script:PasswordPolicies | Where-Object { $_.DaysSincePasswordChange -gt 365 }).Count
    $recentPasswords = ($script:PasswordPolicies | Where-Object { $_.DaysSincePasswordChange -ge 0 -and $_.DaysSincePasswordChange -le 90 }).Count
    
    if ($oldPasswords -gt 0 -or $recentPasswords -gt 0) {
        Write-Host "`n[PASSWORD AGE]" -ForegroundColor Cyan
        if ($oldPasswords -gt 0) {
            Write-Host "  Passwords >365 days old: " -NoNewline -ForegroundColor White
            Write-Host $oldPasswords -ForegroundColor Red
        }
        if ($recentPasswords -gt 0) {
            Write-Host "  Passwords ≤90 days old: " -NoNewline -ForegroundColor White
            Write-Host $recentPasswords -ForegroundColor Green
        }
    }
    
    Write-Host ""
}

# Display results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal users scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalUsersScanned -ForegroundColor Yellow
    
    Write-Host "Users with policy issues: " -NoNewline -ForegroundColor White
    Write-Host $script:PasswordPolicies.Count -ForegroundColor $(if($script:PasswordPolicies.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:PasswordPolicies.Count -gt 0) {
        $criticalRisk = ($script:PasswordPolicies | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:PasswordPolicies | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:PasswordPolicies | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:PasswordPolicies | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "PASSWORD POLICY DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:PasswordPolicies | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.UserPrincipalName -ForegroundColor White
            
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
            
            if ($_.RiskReasons) {
                Write-Host "  Risk Reasons: $($_.RiskReasons)" -ForegroundColor $(if($_.RiskLevel -eq "CRITICAL"){"Red"}elseif($_.RiskLevel -eq "HIGH"){"Yellow"}else{"Gray"})
            }
            
            Write-Host "  Password Policy Strength: " -NoNewline -ForegroundColor Gray
            Write-Host $_.PolicyStrength -ForegroundColor $(if($_.PolicyStrength -eq "Weak"){"Red"}elseif($_.PolicyStrength -eq "Moderate"){"Yellow"}else{"Green"})
            
            Write-Host "  Password Never Expires: " -NoNewline -ForegroundColor Gray
            if ($_.NeverExpires) {
                Write-Host "Yes" -ForegroundColor Red
            }
            else {
                Write-Host "No" -ForegroundColor Green
            }
            
            Write-Host "  Strong Password: " -NoNewline -ForegroundColor Gray
            if ($_.StrongPasswordDisabled) {
                Write-Host "Disabled" -ForegroundColor Red
            }
            else {
                Write-Host "Enabled" -ForegroundColor Green
            }
            
            Write-Host "  Password Policies: $($_.PasswordPolicies)" -ForegroundColor Gray
            Write-Host "  Password Age: $($_.PasswordAgeDisplay)" -ForegroundColor Gray
            
            if ($_.LastPasswordChange) {
                Write-Host "  Last Password Change: $($_.LastPasswordChange) ($($_.DaysSincePasswordChange) days ago)" -ForegroundColor Gray
            }
            
            if ($_.IsExpired) {
                Write-Host "  [!] Password is EXPIRED" -ForegroundColor Red
            }
            elseif ($_.ExpiresInDays -ge 0 -and $_.ExpiresInDays -le 7) {
                Write-Host "  [!] Password expiring in $($_.ExpiresInDays) days" -ForegroundColor Yellow
            }
            
            Write-Host "  Last Sign-In: " -NoNewline -ForegroundColor Gray
            if ($_.LastSignIn) {
                Write-Host $_.LastSignInDisplay -NoNewline -ForegroundColor $(if($_.DaysSinceLastSignIn -gt 90){"Red"}elseif($_.DaysSinceLastSignIn -gt 30){"Yellow"}else{"Green"})
                Write-Host " ($($_.SignInType))" -ForegroundColor DarkGray
            }
            else {
                Write-Host "Never signed in" -ForegroundColor DarkGray
            }
            
            Write-Host "  Created: $($_.CreatedDateTime)" -ForegroundColor Gray
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[+] All users have strong password policies configured." -ForegroundColor Green
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
    
    if ($script:PasswordPolicies.Count -eq 0) {
        Write-Host "`n[*] No password policy issues to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:PasswordPolicies | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:PasswordPolicies | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:PasswordPolicies | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-PasswordPolicyScan
        
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
        
        Write-Host "`n[*] Password policy check completed successfully!" -ForegroundColor Green
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

