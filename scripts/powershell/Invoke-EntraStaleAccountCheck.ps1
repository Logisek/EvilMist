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
    Identifies stale Azure Entra ID accounts and analyzes account hygiene.

.DESCRIPTION
    This script queries Azure Entra ID to identify stale accounts and account hygiene issues:
    - Accounts with no recent sign-in (>90 days)
    - Disabled accounts still assigned licenses
    - Accounts with expired passwords
    - Accounts never signed in
    - Risk assessment based on account age and inactivity
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.

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
    .\Invoke-EntraStaleAccountCheck.ps1
    # Identify all stale accounts

.EXAMPLE
    .\Invoke-EntraStaleAccountCheck.ps1 -ExportPath "stale-accounts.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraStaleAccountCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraStaleAccountCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraStaleAccountCheck.ps1 -IncludeDisabledUsers -Matrix
    # Include disabled accounts and display in matrix format

.EXAMPLE
    .\Invoke-EntraStaleAccountCheck.ps1 -Matrix -ExportPath "results.csv"
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

# Required scopes for stale account checking
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
$script:StaleAccounts = @()
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
    Write-Host "    Entra ID Stale Account Check - Account Hygiene Analysis" -ForegroundColor Yellow
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
        
        # Properties to retrieve including sign-in activity and password info
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
            'AssignedLicenses',
            'PasswordPolicies',
            'LastPasswordChangeDateTime',
            'PasswordProfile'
        )
        
        # Get users with pagination
        Write-Host "[*] Retrieving user properties (including sign-in activity and password info)..." -ForegroundColor Cyan
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
        
        # Fallback: try without SignInActivity
        try {
            Write-Host "[*] Retrying without sign-in activity data..." -ForegroundColor Yellow
            $properties = $properties | Where-Object { $_ -ne 'SignInActivity' }
            
            if ($filter) {
                $users = Get-MgUser -Filter $filter -All -Property $properties -ErrorAction Stop
            }
            else {
                $users = Get-MgUser -All -Property $properties -ErrorAction Stop
            }
            
            $allUsers = $users | ForEach-Object { $_ }
            Write-Host "[+] Retrieved $($allUsers.Count) users (without sign-in activity)" -ForegroundColor Yellow
            return $allUsers
        }
        catch {
            Write-Host "[ERROR] Failed to retrieve users: $_" -ForegroundColor Red
            return @()
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

# Get password expiration info
function Get-PasswordExpirationInfo {
    param(
        [Parameter(Mandatory = $true)]
        $User
    )
    
    try {
        $passwordPolicies = $User.PasswordPolicies
        $lastPwdChange = $User.LastPasswordChangeDateTime
        $passwordProfile = $User.PasswordProfile
        
        # Check if password never expires
        $neverExpires = $false
        if ($passwordPolicies) {
            $neverExpires = $passwordPolicies -like "*DisablePasswordExpiration*"
        }
        
        # Calculate password age
        $passwordAge = $null
        $daysSincePwdChange = -1
        $isExpired = $false
        
        if ($lastPwdChange) {
            try {
                $pwdDate = [DateTime]$lastPwdChange
                $passwordAge = $pwdDate
                $daysSincePwdChange = ([DateTime]::Now - $pwdDate).Days
                
                # Check if password is expired (assuming 90-day expiration policy)
                # Note: This is an estimate as we don't have the exact expiration policy
                if (-not $neverExpires -and $daysSincePwdChange -gt 90) {
                    $isExpired = $true
                }
            }
            catch {
                # Could not parse date
            }
        }
        
        return @{
            NeverExpires = $neverExpires
            LastPasswordChange = $passwordAge
            DaysSincePasswordChange = $daysSincePwdChange
            IsExpired = $isExpired
            PasswordAgeDisplay = if ($neverExpires) { "Never expires" } elseif ($passwordAge) { "$daysSincePwdChange days old" } else { "Unknown" }
        }
    }
    catch {
        return @{
            NeverExpires = $false
            LastPasswordChange = $null
            DaysSincePasswordChange = -1
            IsExpired = $false
            PasswordAgeDisplay = "Unknown"
        }
    }
}

# Determine risk level for stale account
function Get-StaleAccountRiskLevel {
    param(
        [Parameter(Mandatory = $true)]
        $AccountEnabled,
        [Parameter(Mandatory = $true)]
        $DaysSinceLastSignIn,
        [Parameter(Mandatory = $true)]
        $NeverSignedIn,
        [Parameter(Mandatory = $true)]
        $AccountAge,
        [Parameter(Mandatory = $true)]
        $HasLicenses,
        [Parameter(Mandatory = $true)]
        $PasswordExpired
    )
    
    $riskLevel = "LOW"
    $riskFactors = @()
    
    # CRITICAL: Disabled account with licenses
    if (-not $AccountEnabled -and $HasLicenses) {
        $riskLevel = "CRITICAL"
        $riskFactors += "Disabled account with licenses"
    }
    
    # HIGH: Never signed in and account is old
    if ($NeverSignedIn -and $AccountAge -gt 90) {
        if ($riskLevel -ne "CRITICAL") {
            $riskLevel = "HIGH"
        }
        $riskFactors += "Never signed in (account >90 days old)"
    }
    
    # HIGH: Stale account (>90 days inactive) with licenses
    if ($DaysSinceLastSignIn -gt 90 -and $HasLicenses) {
        if ($riskLevel -ne "CRITICAL") {
            $riskLevel = "HIGH"
        }
        $riskFactors += "Stale account (>90 days) with licenses"
    }
    
    # HIGH: Expired password
    if ($PasswordExpired) {
        if ($riskLevel -ne "CRITICAL") {
            $riskLevel = "HIGH"
        }
        $riskFactors += "Expired password"
    }
    
    # MEDIUM: Stale account (>90 days inactive)
    if ($DaysSinceLastSignIn -gt 90) {
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
        $riskFactors += "Stale account (>90 days inactive)"
    }
    
    # MEDIUM: Never signed in
    if ($NeverSignedIn) {
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
        $riskFactors += "Never signed in"
    }
    
    return @{
        RiskLevel = $riskLevel
        RiskFactors = $riskFactors
    }
}

# Scan for stale accounts
function Find-StaleAccounts {
    $users = Get-AllUsers -IncludeDisabled $IncludeDisabledUsers
    $script:TotalUsersScanned = $users.Count
    
    if ($users.Count -eq 0) {
        Write-Host "[!] No users found" -ForegroundColor Yellow
        return
    }
    
    Write-Host "`n[*] Analyzing accounts for stale indicators..." -ForegroundColor Cyan
    
    $progressCounter = 0
    
    foreach ($user in $users) {
        $progressCounter++
        
        # Progress indicator
        if ($progressCounter % 10 -eq 0 -or $progressCounter -eq $users.Count) {
            $percentComplete = [math]::Round(($progressCounter / $users.Count) * 100, 1)
            Write-Host "`r[*] Progress: $progressCounter/$($users.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
        }
        
        try {
            # Get sign-in information
            $signInInfo = Get-SignInInfo -User $user
            
            # Get password expiration info
            $passwordInfo = Get-PasswordExpirationInfo -User $user
            
            # Calculate account age
            $accountAge = -1
            if ($user.CreatedDateTime) {
                try {
                    $createdDate = [DateTime]$user.CreatedDateTime
                    $accountAge = ([DateTime]::Now - $createdDate).Days
                }
                catch {
                    # Could not parse date
                }
            }
            
            # Check for stale indicators
            $isStale = $false
            $staleReasons = @()
            
            # Stale: No sign-in for >90 days
            if ($signInInfo.DaysAgo -gt 90) {
                $isStale = $true
                $staleReasons += "No sign-in for $($signInInfo.DaysAgo) days"
            }
            
            # Stale: Never signed in
            if ($signInInfo.DaysAgo -eq -1 -and $signInInfo.SignInType -eq "Never") {
                $isStale = $true
                $staleReasons += "Never signed in"
            }
            
            # Stale: Disabled account with licenses
            if (-not $user.AccountEnabled -and $user.AssignedLicenses.Count -gt 0) {
                $isStale = $true
                $staleReasons += "Disabled account with $($user.AssignedLicenses.Count) license(s)"
            }
            
            # Stale: Expired password
            if ($passwordInfo.IsExpired) {
                $isStale = $true
                $staleReasons += "Expired password ($($passwordInfo.DaysSincePasswordChange) days old)"
            }
            
            # Only include accounts with stale indicators
            if ($isStale) {
                # Determine risk level
                $riskInfo = Get-StaleAccountRiskLevel `
                    -AccountEnabled $user.AccountEnabled `
                    -DaysSinceLastSignIn $signInInfo.DaysAgo `
                    -NeverSignedIn ($signInInfo.DaysAgo -eq -1) `
                    -AccountAge $accountAge `
                    -HasLicenses ($user.AssignedLicenses.Count -gt 0) `
                    -PasswordExpired $passwordInfo.IsExpired
                
                $userInfo = [PSCustomObject]@{
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    Email = $user.Mail
                    AccountEnabled = $user.AccountEnabled
                    UserType = $user.UserType
                    JobTitle = $user.JobTitle
                    Department = $user.Department
                    CreatedDateTime = $user.CreatedDateTime
                    AccountAgeDays = $accountAge
                    LastSignIn = $signInInfo.LastSignIn
                    LastSignInDisplay = $signInInfo.DisplayText
                    DaysSinceLastSignIn = $signInInfo.DaysAgo
                    SignInType = $signInInfo.SignInType
                    NeverSignedIn = ($signInInfo.DaysAgo -eq -1)
                    HasLicenses = ($user.AssignedLicenses.Count -gt 0)
                    LicenseCount = $user.AssignedLicenses.Count
                    PasswordNeverExpires = $passwordInfo.NeverExpires
                    LastPasswordChange = $passwordInfo.LastPasswordChange
                    DaysSincePasswordChange = $passwordInfo.DaysSincePasswordChange
                    PasswordExpired = $passwordInfo.IsExpired
                    PasswordAgeDisplay = $passwordInfo.PasswordAgeDisplay
                    StaleReasons = ($staleReasons -join "; ")
                    RiskLevel = $riskInfo.RiskLevel
                    RiskFactors = ($riskInfo.RiskFactors -join "; ")
                }
                
                $script:StaleAccounts += $userInfo
            }
        }
        catch {
            Write-Host "`n[!] Error processing user $($user.UserPrincipalName): $_" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n[+] Scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - STALE ACCOUNTS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:StaleAccounts.Count -eq 0) {
        Write-Host "`n[+] Excellent! No stale accounts found." -ForegroundColor Green
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:StaleAccounts | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}}, `
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}}, `
        @{Name='User Principal Name';Expression={$_.UserPrincipalName}}, `
        @{Name='Display Name';Expression={$_.DisplayName}}, `
        @{Name='Last Sign-In';Expression={
            if($_.DaysSinceLastSignIn -eq -1){'Never'}
            elseif($_.DaysSinceLastSignIn -eq 0){'Today'}
            elseif($_.DaysSinceLastSignIn -eq 1){'Yesterday'}
            else{"$($_.DaysSinceLastSignIn)d ago"}
        }}, `
        @{Name='Licenses';Expression={if($_.HasLicenses){$_.LicenseCount}else{'0'}}}, `
        @{Name='Password';Expression={$_.PasswordAgeDisplay}}, `
        @{Name='Stale Reason';Expression={$_.StaleReasons}}
    
    # Display as formatted table
    $matrixData | Format-Table -AutoSize -Wrap | Out-String | ForEach-Object {
        $lines = $_ -split "`n"
        foreach ($line in $lines) {
            if ($line -match '^\s*CRITICAL\s+') {
                Write-Host $line -ForegroundColor Red
            }
            elseif ($line -match '^\s*HIGH\s+') {
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
    
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    # Summary statistics
    Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
    Write-Host "Total stale accounts: " -NoNewline -ForegroundColor White
    Write-Host $script:StaleAccounts.Count -ForegroundColor Red
    
    $criticalRisk = ($script:StaleAccounts | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:StaleAccounts | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:StaleAccounts | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:StaleAccounts | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Red
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Yellow
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Gray
    
    # Stale indicators breakdown
    $neverSignedIn = ($script:StaleAccounts | Where-Object { $_.NeverSignedIn }).Count
    $staleSignIn = ($script:StaleAccounts | Where-Object { $_.DaysSinceLastSignIn -gt 90 }).Count
    $disabledWithLicenses = ($script:StaleAccounts | Where-Object { -not $_.AccountEnabled -and $_.HasLicenses }).Count
    $expiredPasswords = ($script:StaleAccounts | Where-Object { $_.PasswordExpired }).Count
    
    Write-Host "`n[STALE INDICATORS]" -ForegroundColor Cyan
    if ($neverSignedIn -gt 0) {
        Write-Host "  Never signed in: " -NoNewline -ForegroundColor White
        Write-Host $neverSignedIn -ForegroundColor Red
    }
    if ($staleSignIn -gt 0) {
        Write-Host "  No sign-in >90 days: " -NoNewline -ForegroundColor White
        Write-Host $staleSignIn -ForegroundColor Red
    }
    if ($disabledWithLicenses -gt 0) {
        Write-Host "  Disabled with licenses: " -NoNewline -ForegroundColor White
        Write-Host $disabledWithLicenses -ForegroundColor Red
    }
    if ($expiredPasswords -gt 0) {
        Write-Host "  Expired passwords: " -NoNewline -ForegroundColor White
        Write-Host $expiredPasswords -ForegroundColor Red
    }
    
    # Group by department
    $byDept = $script:StaleAccounts | Where-Object { $_.Department } | Group-Object Department | Sort-Object Count -Descending
    if ($byDept.Count -gt 0) {
        Write-Host "`n[TOP DEPARTMENTS]" -ForegroundColor Cyan
        $byDept | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
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
    
    Write-Host "Stale accounts found: " -NoNewline -ForegroundColor White
    Write-Host $script:StaleAccounts.Count -ForegroundColor Red
    
    if ($script:StaleAccounts.Count -gt 0) {
        $criticalRisk = ($script:StaleAccounts | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:StaleAccounts | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:StaleAccounts | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:StaleAccounts | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Red
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Yellow
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Gray
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "STALE ACCOUNTS:" -ForegroundColor Red
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:StaleAccounts | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                "LOW" { "Gray" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.UserPrincipalName -ForegroundColor White
            
            Write-Host "  Display Name: $($_.DisplayName)" -ForegroundColor Gray
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
            
            Write-Host "  Last Sign-In: " -NoNewline -ForegroundColor Gray
            if ($_.LastSignIn) {
                Write-Host $_.LastSignInDisplay -NoNewline -ForegroundColor $(if($_.DaysSinceLastSignIn -gt 90){"Red"}elseif($_.DaysSinceLastSignIn -gt 30){"Yellow"}else{"Green"})
                Write-Host " ($($_.SignInType))" -ForegroundColor DarkGray
            }
            else {
                Write-Host "Never signed in" -ForegroundColor Red
            }
            
            Write-Host "  Account Age: " -NoNewline -ForegroundColor Gray
            if ($_.AccountAgeDays -ge 0) {
                Write-Host "$($_.AccountAgeDays) days old" -ForegroundColor Gray
            }
            else {
                Write-Host "Unknown" -ForegroundColor DarkGray
            }
            
            Write-Host "  Licenses: " -NoNewline -ForegroundColor Gray
            if ($_.HasLicenses) {
                Write-Host "$($_.LicenseCount) assigned" -ForegroundColor $(if(-not $_.AccountEnabled){"Red"}else{"Yellow"})
            }
            else {
                Write-Host "None" -ForegroundColor Gray
            }
            
            Write-Host "  Password: " -NoNewline -ForegroundColor Gray
            Write-Host $_.PasswordAgeDisplay -ForegroundColor $(if($_.PasswordExpired){"Red"}elseif($_.PasswordNeverExpires){"Yellow"}else{"Gray"})
            
            Write-Host "  Stale Reasons: " -NoNewline -ForegroundColor Gray
            Write-Host $_.StaleReasons -ForegroundColor Yellow
            
            if ($_.RiskFactors) {
                Write-Host "  Risk Factors: " -NoNewline -ForegroundColor Gray
                Write-Host $_.RiskFactors -ForegroundColor Red
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[+] Excellent! No stale accounts found." -ForegroundColor Green
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
    
    if ($script:StaleAccounts.Count -eq 0) {
        Write-Host "`n[*] No stale accounts to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:StaleAccounts | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:StaleAccounts | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:StaleAccounts | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        
        # Initialize stealth config
        Initialize-StealthConfig
        
        # Check for required modules
        if (-not (Test-GraphModule)) {
            exit 1
        }
        
        # Initialize Graph modules
        if (-not (Initialize-GraphModules)) {
            exit 1
        }
        
        # Connect to Graph
        if (-not (Connect-GraphService)) {
            exit 1
        }
        
        # Find stale accounts
        Find-StaleAccounts
        
        # Display results
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
    }
    catch {
        Write-Host "`n[ERROR] An error occurred: $_" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }
    finally {
        Invoke-Cleanup
    }
}

# Run main function
Main

