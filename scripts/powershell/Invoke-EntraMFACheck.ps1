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
    Enumerates Azure Entra ID users with no MFA enabled.

.DESCRIPTION
    This script queries Azure Entra ID to identify users who do not have 
    Multi-Factor Authentication (MFA) enabled. It checks various MFA 
    registration methods and authentication methods to determine if a user 
    has MFA properly configured.
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Detection includes:
    - Users without MFA registration (isMfaRegistered)
    - Users without strong authentication methods
    - Users without phone/authenticator app configured
    - Users with password-only authentication

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

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraMFACheck.ps1
    # Query all enabled users without MFA

.EXAMPLE
    .\Invoke-EntraMFACheck.ps1 -ExportPath "no-mfa-users.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraMFACheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraMFACheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraMFACheck.ps1 -IncludeDisabledUsers -ExportPath "all-no-mfa.csv"
    # Include disabled accounts in the scan

.EXAMPLE
    .\Invoke-EntraMFACheck.ps1 -Matrix -ExportPath "results.csv"
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

# Required scopes for MFA checking
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
$script:UsersWithoutMFA = @()
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
    Write-Host "    Entra ID MFA Check - Identify Users Without MFA" -ForegroundColor Yellow
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

# Get all users
function Get-AllUsers {
    param(
        [bool]$IncludeDisabled = $false
    )
    
    Write-Host "`n[*] Retrieving users from Azure Entra ID..." -ForegroundColor Cyan
    
    try {
        $allUsers = @()
        $filter = if (-not $IncludeDisabled) { "accountEnabled eq true" } else { $null }
        
        if ($filter) {
            Write-Host "[*] Filtering: Enabled users only" -ForegroundColor Cyan
        }
        else {
            Write-Host "[*] Filtering: All users (including disabled)" -ForegroundColor Cyan
        }
        
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
            'AssignedLicenses'
        )
        
        # Get users with pagination
        Write-Host "[*] Retrieving user properties (including sign-in activity)..." -ForegroundColor Cyan
        if ($filter) {
            $users = Get-MgUser -Filter $filter -All -Property $properties -ErrorAction Stop
        }
        else {
            $users = Get-MgUser -All -Property $properties -ErrorAction Stop
        }
        
        $allUsers = $users | ForEach-Object { $_ }
        
        Write-Host "[+] Retrieved $($allUsers.Count) users" -ForegroundColor Green
        return $allUsers
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve users: $_" -ForegroundColor Red
        Write-Host "[!] Note: SignInActivity requires AuditLog.Read.All permission" -ForegroundColor Yellow
        
        # Try without SignInActivity if it fails
        try {
            Write-Host "[*] Retrying without sign-in activity data..." -ForegroundColor Yellow
            $basicProperties = @('Id','DisplayName','UserPrincipalName','AccountEnabled','Mail','JobTitle','Department','CreatedDateTime','UserType','AssignedLicenses')
            
            if ($filter) {
                $users = Get-MgUser -Filter $filter -All -Property $basicProperties -ErrorAction Stop
            }
            else {
                $users = Get-MgUser -All -Property $basicProperties -ErrorAction Stop
            }
            
            $allUsers = $users | ForEach-Object { $_ }
            Write-Host "[+] Retrieved $($allUsers.Count) users (without sign-in data)" -ForegroundColor Green
            return $allUsers
        }
        catch {
            Write-Host "[ERROR] Failed to retrieve users: $_" -ForegroundColor Red
            return @()
        }
    }
}

# Check if user is associated with a shared mailbox
function Test-SharedMailbox {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,
        
        [Parameter(Mandatory = $true)]
        $User
    )
    
    try {
        # Shared mailboxes typically have these characteristics:
        # 1. Account is disabled (accountEnabled = false)
        # 2. Has a mailbox but no licenses assigned
        # 3. UserType might be different
        
        $isSharedMailbox = $false
        $indicators = @()
        
        # Check if account is disabled but has mail
        if (-not $User.AccountEnabled -and $User.Mail) {
            $indicators += "Disabled account with email"
            $isSharedMailbox = $true
        }
        
        # Check if has mail but no licenses
        if ($User.Mail -and ($User.AssignedLicenses.Count -eq 0)) {
            $indicators += "No licenses assigned"
            $isSharedMailbox = $true
        }
        
        # Additional check: Try to get mailbox via Graph API
        # Shared mailboxes often have specific patterns in UPN or display name
        if ($User.UserPrincipalName -match "^(shared|mailbox|resource|room|equipment)" -or 
            $User.DisplayName -match "(shared|mailbox|resource|room|equipment)") {
            $indicators += "Name pattern match"
            $isSharedMailbox = $true
        }
        
        return @{
            IsSharedMailbox = $isSharedMailbox
            Indicators = $indicators
            Confidence = if ($indicators.Count -ge 2) { "High" } elseif ($indicators.Count -eq 1) { "Medium" } else { "Low" }
        }
    }
    catch {
        return @{
            IsSharedMailbox = $false
            Indicators = @()
            Confidence = "Unknown"
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

# Main scanning function
function Start-MFAScan {
    Write-Host "`n[*] Starting MFA scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of users..." -ForegroundColor Cyan
    
    $users = Get-AllUsers -IncludeDisabled $IncludeDisabledUsers
    
    if ($users.Count -eq 0) {
        Write-Host "[!] No users found to scan" -ForegroundColor Yellow
        return
    }
    
    $script:TotalUsersScanned = $users.Count
    $progressCounter = 0
    
    Write-Host "`n[*] Checking MFA status for each user..." -ForegroundColor Cyan
    
    foreach ($user in $users) {
        $progressCounter++
        
        # Progress indicator
        if ($progressCounter % 10 -eq 0 -or $progressCounter -eq $users.Count) {
            $percentComplete = [math]::Round(($progressCounter / $users.Count) * 100, 1)
            Write-Host "`r[*] Progress: $progressCounter/$($users.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
        }
        
        # Check MFA status
        $mfaStatus = Test-UserMFA -UserId $user.Id -UserPrincipalName $user.UserPrincipalName
        
        if (-not $mfaStatus.HasMFA) {
            # Get sign-in information
            $signInInfo = Get-SignInInfo -User $user
            
            # Check if shared mailbox
            $sharedMailboxInfo = Test-SharedMailbox -UserId $user.Id -User $user
            
            # Determine account type
            $accountType = if ($sharedMailboxInfo.IsSharedMailbox) {
                "Shared Mailbox (Suspected)"
            } elseif ($user.UserType -eq "Guest") {
                "Guest"
            } else {
                "Regular User"
            }
            
            # Determine if sign-in is actually possible
            $canSignIn = $user.AccountEnabled -and ($null -ne $signInInfo.LastSignIn -or $user.CreatedDateTime)
            
            # Adjust risk level based on sign-in capability and account type
            $riskLevel = "MEDIUM"
            if ($user.AccountEnabled -and -not $sharedMailboxInfo.IsSharedMailbox) {
                $riskLevel = "HIGH"
            } elseif ($sharedMailboxInfo.IsSharedMailbox) {
                $riskLevel = "LOW"  # Shared mailboxes are expected to not have MFA
            }
            
            $userInfo = [PSCustomObject]@{
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Email = $user.Mail
                AccountEnabled = $user.AccountEnabled
                CanSignIn = $canSignIn
                JobTitle = $user.JobTitle
                Department = $user.Department
                CreatedDateTime = $user.CreatedDateTime
                LastSignIn = $signInInfo.LastSignIn
                LastSignInDisplay = $signInInfo.DisplayText
                DaysSinceLastSignIn = $signInInfo.DaysAgo
                SignInType = $signInInfo.SignInType
                AuthMethods = ($mfaStatus.Methods -join ", ")
                MethodCount = $mfaStatus.MethodCount
                MFAEnabled = $false
                AccountType = $accountType
                IsSharedMailbox = $sharedMailboxInfo.IsSharedMailbox
                SharedMailboxIndicators = ($sharedMailboxInfo.Indicators -join "; ")
                SharedMailboxConfidence = $sharedMailboxInfo.Confidence
                RiskLevel = $riskLevel
                UserType = $user.UserType
            }
            
            $script:UsersWithoutMFA += $userInfo
        }
    }
    
    Write-Host "`n[+] Scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 170) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - USERS WITHOUT MFA" -ForegroundColor Cyan
    Write-Host ("=" * 170) -ForegroundColor Cyan
    
    if ($script:UsersWithoutMFA.Count -eq 0) {
        Write-Host "`n[+] Excellent! All users have MFA enabled." -ForegroundColor Green
        Write-Host ("=" * 170) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:UsersWithoutMFA | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Type';Expression={
            if($_.IsSharedMailbox){'SharedMB'}
            elseif($_.UserType -eq 'Guest'){'Guest'}
            else{'User'}
        }},
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}},
        @{Name='User Principal Name';Expression={$_.UserPrincipalName}},
        @{Name='Display Name';Expression={$_.DisplayName}},
        @{Name='Last Sign-In';Expression={
            if($_.DaysSinceLastSignIn -eq -1){'Never'}
            elseif($_.DaysSinceLastSignIn -eq 0){'Today'}
            elseif($_.DaysSinceLastSignIn -eq 1){'Yesterday'}
            else{"$($_.DaysSinceLastSignIn)d ago"}
        }},
        @{Name='Department';Expression={if($_.Department){$_.Department}else{'-'}}},
        @{Name='Auth Methods';Expression={$_.AuthMethods}}
    
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
                Write-Host $line -ForegroundColor Gray
            }
            elseif ($line -match '^-+\s+-+' -or $line -match '^Risk\s+') {
                Write-Host $line -ForegroundColor Cyan
            }
            else {
                Write-Host $line -ForegroundColor White
            }
        }
    }
    
    Write-Host ("=" * 170) -ForegroundColor Cyan
    
    # Summary statistics
    Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
    Write-Host "Total users without MFA: " -NoNewline -ForegroundColor White
    Write-Host $script:UsersWithoutMFA.Count -ForegroundColor Red
    
    $highRisk = ($script:UsersWithoutMFA | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:UsersWithoutMFA | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:UsersWithoutMFA | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    $sharedMailboxes = ($script:UsersWithoutMFA | Where-Object { $_.IsSharedMailbox -eq $true }).Count
    
    Write-Host "  - HIGH risk (enabled users): " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Red
    Write-Host "  - MEDIUM risk (disabled users): " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Yellow
    Write-Host "  - LOW risk (shared mailboxes): " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Gray
    
    if ($sharedMailboxes -gt 0) {
        Write-Host "`n[SHARED MAILBOXES DETECTED]" -ForegroundColor Cyan
        Write-Host "Suspected shared mailboxes: " -NoNewline -ForegroundColor White
        Write-Host $sharedMailboxes -ForegroundColor Gray
        Write-Host "  Note: Shared mailboxes typically don't require MFA" -ForegroundColor DarkGray
    }
    
    # Group by department
    $byDept = $script:UsersWithoutMFA | Where-Object { $_.Department } | Group-Object Department | Sort-Object Count -Descending
    if ($byDept.Count -gt 0) {
        Write-Host "`n[TOP DEPARTMENTS]" -ForegroundColor Cyan
        $byDept | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Group by auth methods
    $byMethod = $script:UsersWithoutMFA | Group-Object AuthMethods | Sort-Object Count -Descending
    if ($byMethod.Count -gt 0) {
        Write-Host "`n[AUTHENTICATION METHODS]" -ForegroundColor Cyan
        $byMethod | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Sign-in activity statistics
    $neverSignedIn = ($script:UsersWithoutMFA | Where-Object { $_.DaysSinceLastSignIn -eq -1 }).Count
    $recentSignIn = ($script:UsersWithoutMFA | Where-Object { $_.DaysSinceLastSignIn -ge 0 -and $_.DaysSinceLastSignIn -le 30 }).Count
    $staleSignIn = ($script:UsersWithoutMFA | Where-Object { $_.DaysSinceLastSignIn -gt 90 }).Count
    
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
    
    Write-Host "`nTotal users scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalUsersScanned -ForegroundColor Yellow
    
    Write-Host "Users WITHOUT MFA: " -NoNewline -ForegroundColor White
    Write-Host $script:UsersWithoutMFA.Count -ForegroundColor Red
    
    if ($script:UsersWithoutMFA.Count -gt 0) {
        $highRisk = ($script:UsersWithoutMFA | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:UsersWithoutMFA | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:UsersWithoutMFA | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        $sharedMailboxes = ($script:UsersWithoutMFA | Where-Object { $_.IsSharedMailbox -eq $true }).Count
        
        Write-Host "  - HIGH risk (enabled users): " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Red
        Write-Host "  - MEDIUM risk (disabled users): " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Yellow
        Write-Host "  - LOW risk (shared mailboxes): " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Gray
        
        if ($sharedMailboxes -gt 0) {
            Write-Host "`n  Note: $sharedMailboxes suspected shared mailbox(es) detected" -ForegroundColor DarkGray
        }
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "USERS WITHOUT MFA:" -ForegroundColor Red
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:UsersWithoutMFA | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                "LOW" { "Gray" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)" -NoNewline -ForegroundColor $riskColor
            if ($_.IsSharedMailbox) {
                Write-Host " - SHARED MAILBOX" -NoNewline -ForegroundColor Magenta
            }
            Write-Host "] " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.UserPrincipalName -ForegroundColor White
            
            Write-Host "  Display Name: $($_.DisplayName)" -ForegroundColor Gray
            Write-Host "  Account Type: $($_.AccountType)" -ForegroundColor Gray
            
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
            
            Write-Host "  Last Sign-In: " -NoNewline -ForegroundColor Gray
            if ($_.LastSignIn) {
                Write-Host $_.LastSignInDisplay -NoNewline -ForegroundColor $(if($_.DaysSinceLastSignIn -gt 90){"Red"}elseif($_.DaysSinceLastSignIn -gt 30){"Yellow"}else{"Green"})
                Write-Host " ($($_.SignInType))" -ForegroundColor DarkGray
            }
            else {
                Write-Host "Never signed in" -ForegroundColor DarkGray
            }
            
            Write-Host "  Auth Methods: $($_.AuthMethods)" -ForegroundColor Gray
            Write-Host "  Created: $($_.CreatedDateTime)" -ForegroundColor Gray
            
            if ($_.IsSharedMailbox) {
                Write-Host "  Shared Mailbox Confidence: $($_.SharedMailboxConfidence)" -ForegroundColor Magenta
                Write-Host "  Indicators: $($_.SharedMailboxIndicators)" -ForegroundColor DarkMagenta
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[+] Excellent! All users have MFA enabled." -ForegroundColor Green
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
    
    if ($script:UsersWithoutMFA.Count -eq 0) {
        Write-Host "`n[*] No users without MFA to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:UsersWithoutMFA | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:UsersWithoutMFA | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:UsersWithoutMFA | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-MFAScan
        
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
        
        Write-Host "`n[*] MFA check completed successfully!" -ForegroundColor Green
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

