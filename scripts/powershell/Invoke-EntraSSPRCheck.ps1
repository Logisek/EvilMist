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
    Enumerates Azure Entra ID users with Self-Service Password Reset (SSPR) enabled and analyzes their registration methods.

.DESCRIPTION
    This script queries Azure Entra ID to identify users who have Self-Service Password Reset (SSPR) enabled
    and analyzes their registration methods. It provides comprehensive information about SSPR configuration
    including registration status, enabled methods, backup methods, and risk assessment.
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Information collected includes:
    - SSPR registration status (isSsprRegistered, isSsprEnabled, isSsprCapable)
    - Registered authentication methods for SSPR
    - Backup method availability
    - Risk assessment based on SSPR configuration
    - User account details and last sign-in activity
    - MFA status correlation

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

.PARAMETER OnlyNoBackup
    Show only users without SSPR backup methods.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraSSPRCheck.ps1
    # Query all users with SSPR enabled

.EXAMPLE
    .\Invoke-EntraSSPRCheck.ps1 -ExportPath "sspr-users.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraSSPRCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraSSPRCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraSSPRCheck.ps1 -OnlyNoBackup -Matrix
    # Display only users without backup methods in matrix format

.EXAMPLE
    .\Invoke-EntraSSPRCheck.ps1 -Matrix -ExportPath "results.csv"
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
    [switch]$OnlyNoBackup,

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

# Required scopes for SSPR checking
$script:RequiredScopes = @(
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Reports.Read.All",
    "AuditLog.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "User.ReadBasic.All",
    "Reports.Read.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:SSPRUsers = @()
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
    Write-Host "    Entra ID SSPR Check - Self-Service Password Reset Analysis" -ForegroundColor Yellow
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

# Get SSPR registration details from reports endpoint
function Get-SSPRRegistrationDetails {
    Write-Host "`n[*] Retrieving SSPR registration details..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?`$top=999"
        $allRegistrations = @()
        
        do {
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            
            foreach ($reg in $result.value) {
                # Only include users with SSPR-related settings
                if ($reg.isSsprRegistered -or $reg.isSsprEnabled -or $reg.isSsprCapable) {
                    $allRegistrations += $reg
                }
            }
            
            $uri = $result.'@odata.nextLink'
            if ($uri) {
                Invoke-StealthDelay
            }
        } while ($uri)
        
        Write-Host "[+] Retrieved $($allRegistrations.Count) user(s) with SSPR configuration" -ForegroundColor Green
        return $allRegistrations
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve SSPR registration details: $_" -ForegroundColor Red
        Write-Host "[!] Note: Requires Reports.Read.All permission" -ForegroundColor Yellow
        return @()
    }
}

# Analyze SSPR methods and determine backup availability
function Get-SSPRMethodAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        $MethodsRegistered
    )
    
    $methods = @()
    $backupMethods = 0
    $strongMethods = 0
    $weakMethods = 0
    
    if ($MethodsRegistered -and $MethodsRegistered.Count -gt 0) {
        foreach ($method in $MethodsRegistered) {
            $methods += $method
            
            # Strong SSPR methods (phone, authenticator app)
            if ($method -in @("mobilePhone", "alternateMobilePhone", "officePhone", "email", "authenticatorApp")) {
                $strongMethods++
                $backupMethods++
            }
            # Weak methods (security questions)
            elseif ($method -eq "securityQuestions") {
                $weakMethods++
                $backupMethods++
            }
        }
    }
    
    $hasBackup = $backupMethods -ge 2
    $hasStrongBackup = $strongMethods -ge 2
    
    return @{
        Methods = $methods
        MethodsDisplay = ($methods -join ", ")
        MethodCount = $methods.Count
        BackupMethods = $backupMethods
        StrongMethods = $strongMethods
        WeakMethods = $weakMethods
        HasBackup = $hasBackup
        HasStrongBackup = $hasStrongBackup
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
            }
        }
        
        return @{
            HasMFA = $hasMFA
            Methods = $mfaMethods
            MethodCount = $authMethods.Count
        }
    }
    catch {
        Write-Host "[!] Unable to check MFA for $UserPrincipalName : $_" -ForegroundColor Yellow
        return @{
            HasMFA = $false
            Methods = @("Error checking methods")
            MethodCount = 0
        }
    }
}

# Main scanning function
function Start-SSPRScan {
    Write-Host "`n[*] Starting SSPR scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of users..." -ForegroundColor Cyan
    
    # Get SSPR registration details
    $ssprRegistrations = Get-SSPRRegistrationDetails
    
    if ($ssprRegistrations.Count -eq 0) {
        Write-Host "[!] No users with SSPR configuration found" -ForegroundColor Yellow
        return
    }
    
    $script:TotalUsersScanned = $ssprRegistrations.Count
    $progressCounter = 0
    
    Write-Host "`n[*] Analyzing SSPR configuration for each user..." -ForegroundColor Cyan
    
    foreach ($reg in $ssprRegistrations) {
        $progressCounter++
        
        # Progress indicator
        if ($progressCounter % 10 -eq 0 -or $progressCounter -eq $ssprRegistrations.Count) {
            $percentComplete = [math]::Round(($progressCounter / $ssprRegistrations.Count) * 100, 1)
            Write-Host "`r[*] Progress: $progressCounter/$($ssprRegistrations.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
        }
        
        try {
            $userId = $reg.id
            $userPrincipalName = $reg.userPrincipalName
            
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
            
            # Skip disabled users if not included
            if (-not $IncludeDisabledUsers -and -not $user.AccountEnabled) {
                continue
            }
            
            # Analyze SSPR methods
            $methodAnalysis = Get-SSPRMethodAnalysis -MethodsRegistered $reg.methodsRegistered
            
            # Skip if OnlyNoBackup is set and user has backup methods
            if ($OnlyNoBackup -and $methodAnalysis.HasBackup) {
                continue
            }
            
            # Check MFA status
            $mfaStatus = Test-UserMFA -UserId $user.Id -UserPrincipalName $user.UserPrincipalName
            
            # Get sign-in information
            $signInInfo = Get-SignInInfo -User $user
            
            # Determine risk level
            $riskLevel = "MEDIUM"
            
            if ($user.AccountEnabled) {
                if (-not $reg.isSsprRegistered -and $reg.isSsprEnabled) {
                    $riskLevel = "HIGH"  # Enabled but not registered
                }
                elseif (-not $methodAnalysis.HasBackup) {
                    $riskLevel = "HIGH"  # No backup methods
                }
                elseif (-not $methodAnalysis.HasStrongBackup) {
                    $riskLevel = "MEDIUM"  # Only weak backup methods
                }
                elseif (-not $mfaStatus.HasMFA) {
                    $riskLevel = "MEDIUM"  # SSPR configured but no MFA
                }
                else {
                    $riskLevel = "LOW"  # Properly configured
                }
            }
            else {
                $riskLevel = "LOW"  # Disabled user
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
                IsSSPRRegistered = $reg.isSsprRegistered
                IsSSPREnabled = $reg.isSsprEnabled
                IsSSPRCapable = $reg.isSsprCapable
                SSPRMethods = $methodAnalysis.MethodsDisplay
                SSPRMethodCount = $methodAnalysis.MethodCount
                BackupMethodCount = $methodAnalysis.BackupMethods
                StrongMethodCount = $methodAnalysis.StrongMethods
                WeakMethodCount = $methodAnalysis.WeakMethods
                HasBackupMethods = $methodAnalysis.HasBackup
                HasStrongBackup = $methodAnalysis.HasStrongBackup
                LastSignIn = $signInInfo.LastSignIn
                LastSignInDisplay = $signInInfo.DisplayText
                DaysSinceLastSignIn = $signInInfo.DaysAgo
                SignInType = $signInInfo.SignInType
                MFAEnabled = $mfaStatus.HasMFA
                MFAMethods = ($mfaStatus.Methods -join ", ")
                MFAMethodCount = $mfaStatus.MethodCount
                HasLicenses = ($user.AssignedLicenses.Count -gt 0)
                LicenseCount = $user.AssignedLicenses.Count
                RiskLevel = $riskLevel
            }
            
            $script:SSPRUsers += $userInfo
        }
        catch {
            Write-Host "`n[!] Error processing user $($reg.userPrincipalName) : $_" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n[+] Scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - USERS WITH SSPR ENABLED" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:SSPRUsers.Count -eq 0) {
        if ($OnlyNoBackup) {
            Write-Host "`n[+] All users with SSPR have backup methods configured." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No users with SSPR configuration found." -ForegroundColor Yellow
        }
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:SSPRUsers | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='SSPR';Expression={if($_.IsSSPREnabled){'Enabled'}else{'Disabled'}}},
        @{Name='Registered';Expression={if($_.IsSSPRRegistered){'Yes'}else{'No'}}},
        @{Name='Backup';Expression={if($_.HasBackupMethods){'Yes'}else{'No'}}},
        @{Name='MFA';Expression={if($_.MFAEnabled){'Yes'}else{'No'}}},
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}},
        @{Name='User Principal Name';Expression={$_.UserPrincipalName}},
        @{Name='Display Name';Expression={$_.DisplayName}},
        @{Name='SSPR Methods';Expression={$_.SSPRMethods}},
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
    Write-Host "Total users with SSPR: " -NoNewline -ForegroundColor White
    Write-Host $script:SSPRUsers.Count -ForegroundColor Yellow
    
    $highRisk = ($script:SSPRUsers | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:SSPRUsers | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:SSPRUsers | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - HIGH risk (no backup/enabled but not registered): " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Red
    Write-Host "  - MEDIUM risk (weak backup/no MFA): " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Yellow
    Write-Host "  - LOW risk (properly configured): " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    $enabled = ($script:SSPRUsers | Where-Object { $_.IsSSPREnabled -eq $true }).Count
    $registered = ($script:SSPRUsers | Where-Object { $_.IsSSPRRegistered -eq $true }).Count
    $withBackup = ($script:SSPRUsers | Where-Object { $_.HasBackupMethods -eq $true }).Count
    $withoutBackup = ($script:SSPRUsers | Where-Object { $_.HasBackupMethods -eq $false }).Count
    $withMFA = ($script:SSPRUsers | Where-Object { $_.MFAEnabled -eq $true }).Count
    $withoutMFA = ($script:SSPRUsers | Where-Object { $_.MFAEnabled -eq $false }).Count
    
    Write-Host "`n[SSPR STATUS]" -ForegroundColor Cyan
    Write-Host "  SSPR Enabled: " -NoNewline -ForegroundColor White
    Write-Host $enabled -ForegroundColor Yellow
    Write-Host "  SSPR Registered: " -NoNewline -ForegroundColor White
    Write-Host $registered -ForegroundColor Yellow
    Write-Host "  With Backup Methods: " -NoNewline -ForegroundColor White
    Write-Host $withBackup -ForegroundColor Green
    Write-Host "  Without Backup Methods: " -NoNewline -ForegroundColor White
    Write-Host $withoutBackup -ForegroundColor Red
    
    Write-Host "`n[MFA STATUS]" -ForegroundColor Cyan
    Write-Host "  With MFA enabled: " -NoNewline -ForegroundColor White
    Write-Host $withMFA -ForegroundColor Green
    Write-Host "  Without MFA: " -NoNewline -ForegroundColor White
    Write-Host $withoutMFA -ForegroundColor Red
    
    # Group by department
    $byDept = $script:SSPRUsers | Where-Object { $_.Department } | Group-Object Department | Sort-Object Count -Descending
    if ($byDept.Count -gt 0) {
        Write-Host "`n[TOP DEPARTMENTS]" -ForegroundColor Cyan
        $byDept | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Group by SSPR methods
    $byMethod = $script:SSPRUsers | Where-Object { $_.SSPRMethods } | Group-Object SSPRMethods | Sort-Object Count -Descending
    if ($byMethod.Count -gt 0) {
        Write-Host "`n[SSPR METHODS]" -ForegroundColor Cyan
        $byMethod | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Sign-in activity statistics
    $neverSignedIn = ($script:SSPRUsers | Where-Object { $_.DaysSinceLastSignIn -eq -1 }).Count
    $recentSignIn = ($script:SSPRUsers | Where-Object { $_.DaysSinceLastSignIn -ge 0 -and $_.DaysSinceLastSignIn -le 30 }).Count
    $staleSignIn = ($script:SSPRUsers | Where-Object { $_.DaysSinceLastSignIn -gt 90 }).Count
    
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
    
    Write-Host "Users with SSPR: " -NoNewline -ForegroundColor White
    Write-Host $script:SSPRUsers.Count -ForegroundColor $(if($script:SSPRUsers.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:SSPRUsers.Count -gt 0) {
        $highRisk = ($script:SSPRUsers | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:SSPRUsers | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:SSPRUsers | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        $withBackup = ($script:SSPRUsers | Where-Object { $_.HasBackupMethods -eq $true }).Count
        $withoutBackup = ($script:SSPRUsers | Where-Object { $_.HasBackupMethods -eq $false }).Count
        $withMFA = ($script:SSPRUsers | Where-Object { $_.MFAEnabled -eq $true }).Count
        $withoutMFA = ($script:SSPRUsers | Where-Object { $_.MFAEnabled -eq $false }).Count
        
        Write-Host "  - HIGH risk (no backup/enabled but not registered): " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Red
        Write-Host "  - MEDIUM risk (weak backup/no MFA): " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Yellow
        Write-Host "  - LOW risk (properly configured): " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`nSSPR Status:" -ForegroundColor Cyan
        Write-Host "  - With Backup Methods: " -NoNewline -ForegroundColor White
        Write-Host $withBackup -ForegroundColor Green
        Write-Host "  - Without Backup Methods: " -NoNewline -ForegroundColor White
        Write-Host $withoutBackup -ForegroundColor Red
        
        Write-Host "`nMFA Status:" -ForegroundColor Cyan
        Write-Host "  - With MFA: " -NoNewline -ForegroundColor White
        Write-Host $withMFA -ForegroundColor Green
        Write-Host "  - Without MFA: " -NoNewline -ForegroundColor White
        Write-Host $withoutMFA -ForegroundColor Red
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "USER DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:SSPRUsers | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
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
            
            Write-Host "  SSPR Enabled: " -NoNewline -ForegroundColor Gray
            if ($_.IsSSPREnabled) {
                Write-Host "Yes" -ForegroundColor Green
            }
            else {
                Write-Host "No" -ForegroundColor Yellow
            }
            
            Write-Host "  SSPR Registered: " -NoNewline -ForegroundColor Gray
            if ($_.IsSSPRRegistered) {
                Write-Host "Yes" -ForegroundColor Green
            }
            else {
                Write-Host "No" -ForegroundColor Red
            }
            
            Write-Host "  SSPR Methods ($($_.SSPRMethodCount)): $($_.SSPRMethods)" -ForegroundColor Gray
            Write-Host "  Backup Methods: " -NoNewline -ForegroundColor Gray
            if ($_.HasBackupMethods) {
                Write-Host "Yes ($($_.BackupMethodCount))" -ForegroundColor Green
            }
            else {
                Write-Host "No" -ForegroundColor Red
            }
            
            Write-Host "  Strong Backup Methods: " -NoNewline -ForegroundColor Gray
            if ($_.HasStrongBackup) {
                Write-Host "Yes ($($_.StrongMethodCount))" -ForegroundColor Green
            }
            else {
                Write-Host "No" -ForegroundColor Yellow
            }
            
            Write-Host "  MFA Enabled: " -NoNewline -ForegroundColor Gray
            if ($_.MFAEnabled) {
                Write-Host "Yes" -ForegroundColor Green
            }
            else {
                Write-Host "No" -ForegroundColor Red
            }
            Write-Host "  MFA Methods: $($_.MFAMethods)" -ForegroundColor Gray
            
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
        if ($OnlyNoBackup) {
            Write-Host "`n[+] All users with SSPR have backup methods configured." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No users with SSPR configuration found." -ForegroundColor Yellow
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
    
    if ($script:SSPRUsers.Count -eq 0) {
        Write-Host "`n[*] No users with SSPR to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:SSPRUsers | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:SSPRUsers | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:SSPRUsers | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-SSPRScan
        
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
        
        Write-Host "`n[*] SSPR check completed successfully!" -ForegroundColor Green
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

