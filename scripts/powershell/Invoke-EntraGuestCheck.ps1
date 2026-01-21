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
    Enumerates Azure Entra ID guest accounts with detailed security information.

.DESCRIPTION
    This script queries Azure Entra ID to identify and analyze guest user accounts.
    It provides comprehensive information about guest users including their MFA status,
    last sign-in activity, account status, and potential security risks.
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Information collected includes:
    - Guest user identification and origin domain
    - MFA registration and authentication methods
    - Last sign-in date and activity patterns
    - Account status and permissions
    - Creation date and invite redemption status
    - Risk assessment based on activity and configuration

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

.PARAMETER IncludeDisabledGuests
    Include disabled guest accounts in the results.

.PARAMETER OnlyNoMFA
    Show only guest accounts without MFA enabled.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraGuestCheck.ps1
    # Query all enabled guest users

.EXAMPLE
    .\Invoke-EntraGuestCheck.ps1 -ExportPath "guest-accounts.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraGuestCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraGuestCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraGuestCheck.ps1 -IncludeDisabledGuests -ExportPath "all-guests.csv"
    # Include disabled guest accounts in the scan

.EXAMPLE
    .\Invoke-EntraGuestCheck.ps1 -Matrix -OnlyNoMFA
    # Display only guests without MFA in matrix format

.EXAMPLE
    .\Invoke-EntraGuestCheck.ps1 -Matrix -ExportPath "results.csv"
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
    [switch]$IncludeDisabledGuests,

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

# Required scopes for guest checking
$script:RequiredScopes = @(
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "AuditLog.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "User.ReadBasic.All",
    "UserAuthenticationMethod.Read.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:GuestAccounts = @()
$script:TotalGuestsScanned = 0
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
    Write-Host "    Entra ID Guest Check - Enumerate Guest Accounts" -ForegroundColor Yellow
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

# Check if user is external based on UPN patterns (edge case detection)
function Test-ExternalUser {
    param(
        [Parameter(Mandatory = $true)]
        $User
    )
    
    # Check for external user indicators even if UserType is "Member"
    $isExternal = $false
    $indicators = @()
    
    # Check for #EXT# in UPN (B2B invitation pattern)
    if ($User.UserPrincipalName -match '#EXT#') {
        $isExternal = $true
        $indicators += "UPN contains #EXT#"
    }
    
    # Check for ExternalUserState property (B2B specific)
    if ($User.ExternalUserState) {
        $isExternal = $true
        $indicators += "Has ExternalUserState"
    }
    
    # Check if UPN domain doesn't match tenant domain patterns
    if ($User.UserPrincipalName -match '_[^_]+\.[^_]+#EXT#') {
        $isExternal = $true
        $indicators += "External domain pattern in UPN"
    }
    
    return @{
        IsExternal = $isExternal
        Indicators = $indicators
    }
}

# Get all guest users including edge cases
function Get-AllGuestUsers {
    param(
        [bool]$IncludeDisabled = $false
    )
    
    Write-Host "`n[*] Retrieving guest and external users from Azure Entra ID..." -ForegroundColor Cyan
    
    try {
        $allGuests = @()
        
        # Build filter for guest users
        $filters = @("userType eq 'Guest'")
        if (-not $IncludeDisabled) {
            $filters += "accountEnabled eq true"
            Write-Host "[*] Filtering: Enabled guest users only" -ForegroundColor Cyan
        }
        else {
            Write-Host "[*] Filtering: All guest users (including disabled)" -ForegroundColor Cyan
        }
        
        $filter = $filters -join " and "
        
        # Properties to retrieve including sign-in activity
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
            'ExternalUserState',
            'ExternalUserStateChangeDateTime',
            'AssignedLicenses',
            'CompanyName'
        )
        
        # Get guest users with pagination
        Write-Host "[*] Retrieving standard guest user properties..." -ForegroundColor Cyan
        $users = Get-MgUser -Filter $filter -All -Property $properties -ErrorAction Stop
        
        $allGuests = $users | ForEach-Object { $_ }
        
        Write-Host "[+] Retrieved $($allGuests.Count) standard guest users (UserType=Guest)" -ForegroundColor Green
        
        # Check for edge case: External users with UserType="Member"
        Write-Host "[*] Checking for edge case external users (UserType=Member with external indicators)..." -ForegroundColor Cyan
        
        try {
            # Get all Member users to check for external patterns
            $memberFilter = if (-not $IncludeDisabled) { "userType eq 'Member' and accountEnabled eq true" } else { "userType eq 'Member'" }
            $memberUsers = Get-MgUser -Filter $memberFilter -All -Property $properties -ErrorAction Stop
            
            $edgeCaseExternals = @()
            foreach ($member in $memberUsers) {
                $externalCheck = Test-ExternalUser -User $member
                if ($externalCheck.IsExternal) {
                    $edgeCaseExternals += $member
                }
            }
            
            if ($edgeCaseExternals.Count -gt 0) {
                Write-Host "[!] Found $($edgeCaseExternals.Count) edge case external users (UserType=Member but has external indicators)" -ForegroundColor Yellow
                Write-Host "[*] Adding edge case users to results..." -ForegroundColor Cyan
                $allGuests += $edgeCaseExternals
            }
            else {
                Write-Host "[+] No edge case external users found" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[!] Could not check for edge case external users: $_" -ForegroundColor Yellow
        }
        
        Write-Host "[+] Total guest/external users retrieved: $($allGuests.Count)" -ForegroundColor Green
        return $allGuests
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve guest users: $_" -ForegroundColor Red
        Write-Host "[!] Note: SignInActivity requires AuditLog.Read.All permission" -ForegroundColor Yellow
        
        # Try without SignInActivity if it fails
        try {
            Write-Host "[*] Retrying without sign-in activity data..." -ForegroundColor Yellow
            $basicProperties = @('Id','DisplayName','UserPrincipalName','AccountEnabled','Mail','JobTitle','Department','CreatedDateTime','UserType','ExternalUserState','ExternalUserStateChangeDateTime','AssignedLicenses','CompanyName')
            
            $users = Get-MgUser -Filter $filter -All -Property $basicProperties -ErrorAction Stop
            $allGuests = $users | ForEach-Object { $_ }
            
            # Try edge case check with basic properties
            try {
                $memberFilter = if (-not $IncludeDisabled) { "userType eq 'Member' and accountEnabled eq true" } else { "userType eq 'Member'" }
                $memberUsers = Get-MgUser -Filter $memberFilter -All -Property $basicProperties -ErrorAction Stop
                
                foreach ($member in $memberUsers) {
                    $externalCheck = Test-ExternalUser -User $member
                    if ($externalCheck.IsExternal) {
                        $allGuests += $member
                    }
                }
            }
            catch {
                Write-Host "[!] Could not check for edge case external users" -ForegroundColor Yellow
            }
            
            Write-Host "[+] Retrieved $($allGuests.Count) guest/external users (without sign-in data)" -ForegroundColor Green
            return $allGuests
        }
        catch {
            Write-Host "[ERROR] Failed to retrieve guest users: $_" -ForegroundColor Red
            return @()
        }
    }
}

# Verify guest count against Azure Entra ID reporting
function Test-GuestCountVerification {
    Write-Host "`n[*] Verifying guest account count..." -ForegroundColor Cyan
    
    try {
        # Get total count of Guest UserType
        $guestTypeCount = (Get-MgUser -Filter "userType eq 'Guest'" -ConsistencyLevel eventual -Count guestCount -ErrorAction SilentlyContinue).Count
        
        if ($guestTypeCount -gt 0) {
            Write-Host "[*] Azure reports $guestTypeCount users with UserType='Guest'" -ForegroundColor Cyan
            
            # Compare with what we found
            $ourStandardGuests = ($script:GuestAccounts | Where-Object { $_.UserType -eq "Guest" }).Count
            $ourEdgeCaseGuests = ($script:GuestAccounts | Where-Object { $_.UserType -ne "Guest" }).Count
            
            Write-Host "[*] Script found:" -ForegroundColor Cyan
            Write-Host "    - Standard guests (UserType=Guest): $ourStandardGuests" -ForegroundColor Cyan
            if ($ourEdgeCaseGuests -gt 0) {
                Write-Host "    - Edge case external users (UserType=Member): $ourEdgeCaseGuests" -ForegroundColor Yellow
            }
            Write-Host "    - Total captured: $($script:GuestAccounts.Count)" -ForegroundColor Cyan
            
            # Verify match
            if ($ourStandardGuests -eq $guestTypeCount) {
                Write-Host "[+] Guest count verified! All guests captured." -ForegroundColor Green
            }
            elseif ($ourStandardGuests -lt $guestTypeCount) {
                $missing = $guestTypeCount - $ourStandardGuests
                Write-Host "[!] WARNING: $missing guest users may be missing (filter mismatch or permissions)" -ForegroundColor Yellow
            }
            else {
                Write-Host "[!] Count mismatch detected - this may be due to timing or permissions" -ForegroundColor Yellow
            }
            
            if ($ourEdgeCaseGuests -gt 0) {
                Write-Host "`n[!] IMPORTANT: Found $ourEdgeCaseGuests external users with UserType='Member'" -ForegroundColor Yellow
                Write-Host "    These are likely cross-tenant sync or converted guest accounts" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "[!] Could not retrieve guest count for verification" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Verification check unavailable: $_" -ForegroundColor Yellow
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

# Extract guest domain from UPN
function Get-GuestDomain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    try {
        # Guest UPN format: user_domain.com#EXT#@tenant.onmicrosoft.com
        if ($UserPrincipalName -match '#EXT#') {
            $parts = $UserPrincipalName -split '#EXT#'
            $guestPart = $parts[0]
            
            # Extract domain from guest part
            if ($guestPart -match '_([^_]+\.[^_]+)$') {
                return $matches[1]
            }
            elseif ($guestPart -match '@(.+)$') {
                return $matches[1]
            }
        }
        elseif ($UserPrincipalName -match '@(.+)$') {
            return $matches[1]
        }
        
        return "Unknown"
    }
    catch {
        return "Unknown"
    }
}

# Main scanning function
function Start-GuestScan {
    Write-Host "`n[*] Starting guest account scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of guest users..." -ForegroundColor Cyan
    
    $guests = Get-AllGuestUsers -IncludeDisabled $IncludeDisabledGuests
    
    if ($guests.Count -eq 0) {
        Write-Host "[!] No guest users found to scan" -ForegroundColor Yellow
        return
    }
    
    $script:TotalGuestsScanned = $guests.Count
    $progressCounter = 0
    
    Write-Host "`n[*] Analyzing guest accounts..." -ForegroundColor Cyan
    
    foreach ($guest in $guests) {
        $progressCounter++
        
        # Progress indicator
        if ($progressCounter % 10 -eq 0 -or $progressCounter -eq $guests.Count) {
            $percentComplete = [math]::Round(($progressCounter / $guests.Count) * 100, 1)
            Write-Host "`r[*] Progress: $progressCounter/$($guests.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
        }
        
        # Check MFA status
        $mfaStatus = Test-UserMFA -UserId $guest.Id -UserPrincipalName $guest.UserPrincipalName
        
        # Skip if OnlyNoMFA is set and user has MFA
        if ($OnlyNoMFA -and $mfaStatus.HasMFA) {
            continue
        }
        
        # Get sign-in information
        $signInInfo = Get-SignInInfo -User $guest
        
        # Extract guest domain
        $guestDomain = Get-GuestDomain -UserPrincipalName $guest.UserPrincipalName
        
        # Check if this is an edge case external user
        $externalCheck = Test-ExternalUser -User $guest
        $isEdgeCase = ($guest.UserType -ne "Guest" -and $externalCheck.IsExternal)
        
        # Determine invite status
        $inviteStatus = "Unknown"
        if ($guest.ExternalUserState) {
            $inviteStatus = $guest.ExternalUserState
        }
        elseif ($isEdgeCase) {
            # Edge case users may not have standard invite status
            $inviteStatus = "External (Converted/Synced)"
        }
        
        # Determine if sign-in is actually possible
        $canSignIn = $guest.AccountEnabled -and ($inviteStatus -eq "Accepted" -or $isEdgeCase)
        
        # Determine risk level
        $riskLevel = "MEDIUM"
        if ($guest.AccountEnabled -and ($inviteStatus -eq "Accepted" -or $isEdgeCase)) {
            if (-not $mfaStatus.HasMFA) {
                $riskLevel = "HIGH"  # Active guest without MFA
            }
            else {
                $riskLevel = "LOW"  # Active guest with MFA
            }
        }
        elseif (-not $guest.AccountEnabled) {
            $riskLevel = "LOW"  # Disabled guest
        }
        elseif ($inviteStatus -eq "PendingAcceptance") {
            $riskLevel = "MEDIUM"  # Pending invite
        }
        
        # Calculate days since creation
        $daysOld = -1
        if ($guest.CreatedDateTime) {
            $daysOld = ([DateTime]::Now - [DateTime]$guest.CreatedDateTime).Days
        }
        
        # Calculate days since invite acceptance
        $daysSinceAccepted = -1
        if ($guest.ExternalUserStateChangeDateTime) {
            $daysSinceAccepted = ([DateTime]::Now - [DateTime]$guest.ExternalUserStateChangeDateTime).Days
        }
        
        $guestInfo = [PSCustomObject]@{
            DisplayName = $guest.DisplayName
            UserPrincipalName = $guest.UserPrincipalName
            Email = $guest.Mail
            GuestDomain = $guestDomain
            CompanyName = $guest.CompanyName
            AccountEnabled = $guest.AccountEnabled
            CanSignIn = $canSignIn
            InviteStatus = $inviteStatus
            JobTitle = $guest.JobTitle
            Department = $guest.Department
            CreatedDateTime = $guest.CreatedDateTime
            DaysOld = $daysOld
            InviteAcceptedDate = $guest.ExternalUserStateChangeDateTime
            DaysSinceAccepted = $daysSinceAccepted
            LastSignIn = $signInInfo.LastSignIn
            LastSignInDisplay = $signInInfo.DisplayText
            DaysSinceLastSignIn = $signInInfo.DaysAgo
            SignInType = $signInInfo.SignInType
            MFAEnabled = $mfaStatus.HasMFA
            AuthMethods = ($mfaStatus.Methods -join ", ")
            MethodCount = $mfaStatus.MethodCount
            HasLicenses = ($guest.AssignedLicenses.Count -gt 0)
            LicenseCount = $guest.AssignedLicenses.Count
            RiskLevel = $riskLevel
            UserType = $guest.UserType
            IsEdgeCase = $isEdgeCase
            EdgeCaseIndicators = ($externalCheck.Indicators -join "; ")
        }
        
        $script:GuestAccounts += $guestInfo
    }
    
    Write-Host "`n[+] Scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - GUEST ACCOUNTS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:GuestAccounts.Count -eq 0) {
        if ($OnlyNoMFA) {
            Write-Host "`n[+] Excellent! All guest users have MFA enabled." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No guest accounts found." -ForegroundColor Yellow
        }
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:GuestAccounts | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='MFA';Expression={if($_.MFAEnabled){'Yes'}else{'No'}}},
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}},
        @{Name='Invite';Expression={
            switch($_.InviteStatus) {
                'Accepted' {'Accepted'}
                'PendingAcceptance' {'Pending'}
                default {$_.InviteStatus}
            }
        }},
        @{Name='User Principal Name';Expression={$_.UserPrincipalName}},
        @{Name='Display Name';Expression={$_.DisplayName}},
        @{Name='Guest Domain';Expression={$_.GuestDomain}},
        @{Name='Last Sign-In';Expression={
            if($_.DaysSinceLastSignIn -eq -1){'Never'}
            elseif($_.DaysSinceLastSignIn -eq 0){'Today'}
            elseif($_.DaysSinceLastSignIn -eq 1){'Yesterday'}
            else{"$($_.DaysSinceLastSignIn)d ago"}
        }},
        @{Name='Company';Expression={if($_.CompanyName){$_.CompanyName}else{'-'}}}
    
    # Display as formatted table
    $matrixData | Format-Table -AutoSize -Wrap | Out-String | ForEach-Object {
        $lines = $_ -split "`n"
        foreach ($line in $lines) {
            if ($line -match '^\s*HIGH\s+') {
                Write-Host $line -ForegroundColor Red
            }
            elseif ($line -match '^\s*MEDIUM\s+') {
                Write-Host $line -ForegroundColor Yellow
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
    Write-Host "Total guest/external accounts found: " -NoNewline -ForegroundColor White
    Write-Host $script:GuestAccounts.Count -ForegroundColor Yellow
    
    $standardGuests = ($script:GuestAccounts | Where-Object { $_.UserType -eq "Guest" }).Count
    $edgeCaseUsers = ($script:GuestAccounts | Where-Object { $_.IsEdgeCase -eq $true }).Count
    
    if ($edgeCaseUsers -gt 0) {
        Write-Host "  - Standard guests (UserType=Guest): " -NoNewline -ForegroundColor White
        Write-Host $standardGuests -ForegroundColor Cyan
        Write-Host "  - Edge case external (UserType=Member): " -NoNewline -ForegroundColor White
        Write-Host $edgeCaseUsers -ForegroundColor Yellow
    }
    
    $highRisk = ($script:GuestAccounts | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:GuestAccounts | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:GuestAccounts | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    $withMFA = ($script:GuestAccounts | Where-Object { $_.MFAEnabled -eq $true }).Count
    $withoutMFA = ($script:GuestAccounts | Where-Object { $_.MFAEnabled -eq $false }).Count
    
    Write-Host "  - HIGH risk (active without MFA): " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Red
    Write-Host "  - MEDIUM risk (pending/limited access): " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Yellow
    Write-Host "  - LOW risk (MFA enabled/disabled): " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    Write-Host "`n[MFA STATUS]" -ForegroundColor Cyan
    Write-Host "  With MFA enabled: " -NoNewline -ForegroundColor White
    Write-Host $withMFA -ForegroundColor Green
    Write-Host "  Without MFA: " -NoNewline -ForegroundColor White
    Write-Host $withoutMFA -ForegroundColor Red
    
    if ($edgeCaseUsers -gt 0) {
        Write-Host "`n[EDGE CASE EXTERNAL USERS DETECTED]" -ForegroundColor Magenta
        Write-Host "  Found $edgeCaseUsers external users with UserType='Member'" -ForegroundColor Yellow
        Write-Host "  These may be cross-tenant synced or converted guest accounts" -ForegroundColor DarkGray
        Write-Host "  Review these accounts carefully for proper security policies" -ForegroundColor DarkGray
    }
    
    # Group by guest domain
    $byDomain = $script:GuestAccounts | Where-Object { $_.GuestDomain -and $_.GuestDomain -ne "Unknown" } | 
        Group-Object GuestDomain | Sort-Object Count -Descending
    if ($byDomain.Count -gt 0) {
        Write-Host "`n[TOP GUEST DOMAINS]" -ForegroundColor Cyan
        $byDomain | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Invite status breakdown
    $byInvite = $script:GuestAccounts | Group-Object InviteStatus | Sort-Object Count -Descending
    if ($byInvite.Count -gt 0) {
        Write-Host "`n[INVITE STATUS]" -ForegroundColor Cyan
        $byInvite | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Sign-in activity statistics
    $neverSignedIn = ($script:GuestAccounts | Where-Object { $_.DaysSinceLastSignIn -eq -1 }).Count
    $recentSignIn = ($script:GuestAccounts | Where-Object { $_.DaysSinceLastSignIn -ge 0 -and $_.DaysSinceLastSignIn -le 30 }).Count
    $staleSignIn = ($script:GuestAccounts | Where-Object { $_.DaysSinceLastSignIn -gt 90 }).Count
    
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
    
    Write-Host "`nTotal guest accounts scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalGuestsScanned -ForegroundColor Yellow
    
    Write-Host "Guest/external accounts found: " -NoNewline -ForegroundColor White
    Write-Host $script:GuestAccounts.Count -ForegroundColor $(if($script:GuestAccounts.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:GuestAccounts.Count -gt 0) {
        $standardGuests = ($script:GuestAccounts | Where-Object { $_.UserType -eq "Guest" }).Count
        $edgeCaseUsers = ($script:GuestAccounts | Where-Object { $_.IsEdgeCase -eq $true }).Count
        
        if ($edgeCaseUsers -gt 0) {
            Write-Host "  - Standard guests (UserType=Guest): " -NoNewline -ForegroundColor White
            Write-Host $standardGuests -ForegroundColor Cyan
            Write-Host "  - Edge case external (UserType=Member): " -NoNewline -ForegroundColor White
            Write-Host $edgeCaseUsers -ForegroundColor Yellow
        }
        
        $highRisk = ($script:GuestAccounts | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:GuestAccounts | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:GuestAccounts | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        $withMFA = ($script:GuestAccounts | Where-Object { $_.MFAEnabled -eq $true }).Count
        $withoutMFA = ($script:GuestAccounts | Where-Object { $_.MFAEnabled -eq $false }).Count
        
        Write-Host "  - HIGH risk (active without MFA): " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Red
        Write-Host "  - MEDIUM risk (pending/limited): " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Yellow
        Write-Host "  - LOW risk (secure/disabled): " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`nMFA Status:" -ForegroundColor Cyan
        Write-Host "  - With MFA: " -NoNewline -ForegroundColor White
        Write-Host $withMFA -ForegroundColor Green
        Write-Host "  - Without MFA: " -NoNewline -ForegroundColor White
        Write-Host $withoutMFA -ForegroundColor Red
        
        if ($edgeCaseUsers -gt 0) {
            Write-Host "`nEdge Case External Users:" -ForegroundColor Magenta
            Write-Host "  Found $edgeCaseUsers external users with UserType='Member'" -ForegroundColor Yellow
            Write-Host "  (These may be cross-tenant synced or converted guest accounts)" -ForegroundColor DarkGray
        }
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "GUEST ACCOUNT DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:GuestAccounts | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)" -NoNewline -ForegroundColor $riskColor
            if ($_.IsEdgeCase) {
                Write-Host " - EDGE CASE EXTERNAL" -NoNewline -ForegroundColor Magenta
            }
            Write-Host "] " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.UserPrincipalName -ForegroundColor White
            
            Write-Host "  Display Name: $($_.DisplayName)" -ForegroundColor Gray
            Write-Host "  User Type: $($_.UserType)" -ForegroundColor Gray
            if ($_.IsEdgeCase) {
                Write-Host "  Edge Case Type: External user with Member UserType" -ForegroundColor Magenta
                Write-Host "  Indicators: $($_.EdgeCaseIndicators)" -ForegroundColor DarkMagenta
            }
            Write-Host "  Guest Domain: $($_.GuestDomain)" -ForegroundColor Gray
            
            if ($_.CompanyName) {
                Write-Host "  Company: $($_.CompanyName)" -ForegroundColor Gray
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
            
            Write-Host "  Account Status: " -NoNewline -ForegroundColor Gray
            if ($_.AccountEnabled) {
                Write-Host "Enabled" -NoNewline -ForegroundColor Green
                Write-Host " (Can Sign In: " -NoNewline -ForegroundColor Gray
                Write-Host $(if($_.CanSignIn){"Yes"}else{"No"}) -NoNewline -ForegroundColor $(if($_.CanSignIn){"Green"}else{"Yellow"})
                Write-Host ")" -ForegroundColor Gray
            }
            else {
                Write-Host "Disabled" -ForegroundColor Yellow
            }
            
            Write-Host "  Invite Status: " -NoNewline -ForegroundColor Gray
            $inviteColor = switch($_.InviteStatus) {
                "Accepted" { "Green" }
                "PendingAcceptance" { "Yellow" }
                default { "Gray" }
            }
            Write-Host $_.InviteStatus -ForegroundColor $inviteColor
            
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
            
            if ($_.InviteAcceptedDate) {
                Write-Host "  Invite Accepted: $($_.InviteAcceptedDate) ($($_.DaysSinceAccepted) days ago)" -ForegroundColor Gray
            }
            
            if ($_.HasLicenses) {
                Write-Host "  Licenses: $($_.LicenseCount) assigned" -ForegroundColor Gray
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        if ($OnlyNoMFA) {
            Write-Host "`n[+] Excellent! All guest users have MFA enabled." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No guest accounts found in the tenant." -ForegroundColor Yellow
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
    
    if ($script:GuestAccounts.Count -eq 0) {
        Write-Host "`n[*] No guest accounts to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:GuestAccounts | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:GuestAccounts | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:GuestAccounts | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-GuestScan
        
        # Verify counts
        Test-GuestCountVerification
        
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
        
        Write-Host "`n[*] Guest account check completed successfully!" -ForegroundColor Green
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


