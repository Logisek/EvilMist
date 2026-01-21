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
    Analyzes Azure Entra ID for legacy authentication usage and identifies security risks.

.DESCRIPTION
    This script queries Azure Entra ID to identify users and applications using legacy 
    authentication protocols. Legacy authentication bypasses modern security controls 
    like MFA and Conditional Access, making it a significant security risk.
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Legacy protocols detected include:
    - Exchange ActiveSync
    - IMAP4
    - POP3
    - SMTP (Authenticated)
    - MAPI Over HTTP
    - Autodiscover
    - Exchange Online PowerShell
    - Outlook Anywhere
    - Other legacy clients
    
    Information collected includes:
    - User identification and legacy protocol usage
    - Last legacy authentication date and time
    - Application/service principal using legacy auth
    - Sign-in success/failure status
    - Risk assessment based on usage patterns and recency
    - MFA status of users using legacy auth

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

.PARAMETER OnlyRecent
    Show only users with legacy auth in the last 30 days.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraLegacyAuthCheck.ps1
    # Analyze all legacy authentication usage

.EXAMPLE
    .\Invoke-EntraLegacyAuthCheck.ps1 -ExportPath "legacy-auth.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraLegacyAuthCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraLegacyAuthCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraLegacyAuthCheck.ps1 -OnlyRecent -Matrix
    # Display only recent legacy auth usage in matrix format

.EXAMPLE
    .\Invoke-EntraLegacyAuthCheck.ps1 -Matrix -ExportPath "results.csv"
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
    [switch]$OnlyRecent,

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

# Legacy authentication protocols to detect
$script:LegacyProtocols = @(
    "Exchange ActiveSync",
    "IMAP4",
    "POP3",
    "SMTP",
    "MAPI Over HTTP",
    "Autodiscover",
    "Exchange Online PowerShell",
    "Outlook Anywhere",
    "Other clients",
    "Authenticated SMTP"
)

# Required scopes for legacy auth checking
$script:RequiredScopes = @(
    "AuditLog.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Directory.Read.All",
    "User.ReadBasic.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:LegacyAuthUsers = @()
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
    Write-Host "    Entra ID Legacy Authentication Check - Legacy Protocol Security Audit" -ForegroundColor Yellow
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
        "Microsoft.Graph.Identity.SignIns",
        "Microsoft.Graph.Users"
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
        
        Write-Host "[*] Importing Microsoft.Graph.Users..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Users -Force -ErrorAction Stop
        
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
            Write-Host "[!] Some features may be limited (AuditLog.Read.All required for sign-in logs)" -ForegroundColor Yellow
            
            return $true
        }
        catch {
            Write-Host "[ERROR] Authentication failed: $_" -ForegroundColor Red
            return $false
        }
    }
}

# Get sign-in information for a user
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
                    $mfaMethods += "Email (weak)"
                }
                '#microsoft.graph.passwordAuthenticationMethod' {
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
        Write-Host "[!] Unable to check MFA for $UserPrincipalName : $_" -ForegroundColor Yellow
        return @{
            HasMFA = $false
            Methods = @("Error checking methods")
            MethodCount = 0
        }
    }
}

# Get legacy authentication sign-ins from audit logs
function Get-LegacyAuthSignIns {
    Write-Host "`n[*] Querying sign-in logs for legacy authentication protocols..." -ForegroundColor Cyan
    
    $legacySignIns = @{}
    $startDate = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    # Check if we have AuditLog.Read.All permission
    $hasAuditLogPermission = $script:CurrentScopes -contains "AuditLog.Read.All" -or 
                             $script:CurrentScopes -contains "AuditLog.Read.All"
    
    if (-not $hasAuditLogPermission) {
        Write-Host "[!] Warning: AuditLog.Read.All permission not available" -ForegroundColor Yellow
        Write-Host "[!] Cannot query sign-in logs. Some features will be limited." -ForegroundColor Yellow
        return $legacySignIns
    }
    
    $protocolCount = 0
    foreach ($protocol in $script:LegacyProtocols) {
        $protocolCount++
        Write-Host "[*] Checking protocol: $protocol ($protocolCount/$($script:LegacyProtocols.Count))" -ForegroundColor Cyan
        
        try {
            Invoke-StealthDelay
            
            # Query sign-in logs for this protocol
            $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=clientAppUsed eq '$protocol' and createdDateTime ge $startDate&`$top=999&`$orderby=createdDateTime desc"
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            
            if ($response -and $response.value) {
                $signInCount = $response.value.Count
                Write-Host "    [+] Found $signInCount sign-in(s) for $protocol" -ForegroundColor Green
                
                foreach ($signIn in $response.value) {
                    $userId = $signIn.userId
                    $userPrincipalName = $signIn.userPrincipalName
                    
                    if (-not $userId) {
                        continue
                    }
                    
                    # Track unique users and their most recent legacy auth
                    if (-not $legacySignIns.ContainsKey($userId)) {
                        $legacySignIns[$userId] = @{
                            UserId = $userId
                            UserPrincipalName = $userPrincipalName
                            Protocols = @()
                            LastLegacySignIn = $null
                            SignInCount = 0
                            SuccessfulSignIns = 0
                            FailedSignIns = 0
                            SignIns = @()
                        }
                    }
                    
                    $signInDateTime = [DateTime]$signIn.createdDateTime
                    $isSuccessful = ($signIn.status.errorCode -eq 0 -or $signIn.status.errorCode -eq $null)
                    
                    # Update most recent sign-in
                    if (-not $legacySignIns[$userId].LastLegacySignIn -or $signInDateTime -gt $legacySignIns[$userId].LastLegacySignIn) {
                        $legacySignIns[$userId].LastLegacySignIn = $signInDateTime
                    }
                    
                    # Track protocols
                    if ($legacySignIns[$userId].Protocols -notcontains $protocol) {
                        $legacySignIns[$userId].Protocols += $protocol
                    }
                    
                    # Track statistics
                    $legacySignIns[$userId].SignInCount++
                    if ($isSuccessful) {
                        $legacySignIns[$userId].SuccessfulSignIns++
                    }
                    else {
                        $legacySignIns[$userId].FailedSignIns++
                    }
                    
                    # Store sign-in details
                    $legacySignIns[$userId].SignIns += @{
                        Protocol = $protocol
                        DateTime = $signInDateTime
                        Success = $isSuccessful
                        Status = if ($isSuccessful) { "Success" } else { "Failed" }
                        ErrorCode = $signIn.status.errorCode
                        IPAddress = $signIn.ipAddress
                        Location = $signIn.location.city + ", " + $signIn.location.countryOrRegion
                    }
                }
            }
            else {
                Write-Host "    [-] No sign-ins found for $protocol" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "    [!] Error querying $protocol : $_" -ForegroundColor Yellow
        }
    }
    
    Write-Host "[+] Found $($legacySignIns.Count) unique user(s) with legacy authentication usage" -ForegroundColor Green
    return $legacySignIns
}

# Main scanning function
function Start-LegacyAuthScan {
    Write-Host "`n[*] Starting legacy authentication scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of sign-ins..." -ForegroundColor Cyan
    
    # Get legacy auth sign-ins
    $legacySignIns = Get-LegacyAuthSignIns
    
    if ($legacySignIns.Count -eq 0) {
        Write-Host "[!] No legacy authentication usage found in the last 90 days" -ForegroundColor Yellow
        return
    }
    
    $script:TotalUsersScanned = $legacySignIns.Count
    $progressCounter = 0
    
    Write-Host "`n[*] Analyzing users with legacy authentication usage..." -ForegroundColor Cyan
    
    foreach ($userId in $legacySignIns.Keys) {
        $progressCounter++
        $signInData = $legacySignIns[$userId]
        
        # Progress indicator
        if ($progressCounter % 5 -eq 0 -or $progressCounter -eq $legacySignIns.Count) {
            $percentComplete = [math]::Round(($progressCounter / $legacySignIns.Count) * 100, 1)
            Write-Host "`r[*] Progress: $progressCounter/$($legacySignIns.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
        }
        
        try {
            Invoke-StealthDelay
            
            # Get user details
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
                'UserType'
            )
            
            $user = Get-MgUser -UserId $userId -Property $properties -ErrorAction Stop
            
            # Skip disabled users if not included
            if (-not $IncludeDisabledUsers -and -not $user.AccountEnabled) {
                continue
            }
            
            # Filter: Only recent (last 30 days)
            if ($OnlyRecent) {
                $daysSinceLastLegacyAuth = ([DateTime]::Now - $signInData.LastLegacySignIn).Days
                if ($daysSinceLastLegacyAuth -gt 30) {
                    continue
                }
            }
            
            # Check MFA status
            $mfaStatus = Test-UserMFA -UserId $user.Id -UserPrincipalName $user.UserPrincipalName
            
            # Get sign-in information
            $signInInfo = Get-SignInInfo -User $user
            
            # Calculate days since last legacy auth
            $daysSinceLastLegacyAuth = ([DateTime]::Now - $signInData.LastLegacySignIn).Days
            
            # Determine risk level
            $riskLevel = "MEDIUM"
            $riskReasons = @()
            
            if ($user.AccountEnabled) {
                if (-not $mfaStatus.HasMFA) {
                    $riskLevel = "CRITICAL"
                    $riskReasons += "Active user without MFA using legacy auth"
                }
                elseif ($daysSinceLastLegacyAuth -le 7) {
                    $riskLevel = "HIGH"
                    $riskReasons += "Recent legacy auth usage (within 7 days)"
                }
                elseif ($daysSinceLastLegacyAuth -le 30) {
                    $riskLevel = "HIGH"
                    $riskReasons += "Recent legacy auth usage (within 30 days)"
                }
                else {
                    $riskLevel = "MEDIUM"
                    $riskReasons += "Legacy auth usage ($daysSinceLastLegacyAuth days ago)"
                }
            }
            else {
                $riskLevel = "LOW"
                $riskReasons += "Disabled account"
            }
            
            # Calculate account age
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
                LegacyProtocols = ($signInData.Protocols -join ", ")
                ProtocolCount = $signInData.Protocols.Count
                LastLegacySignIn = $signInData.LastLegacySignIn
                DaysSinceLastLegacyAuth = $daysSinceLastLegacyAuth
                LastLegacySignInDisplay = "$($signInData.LastLegacySignIn.ToString('yyyy-MM-dd HH:mm:ss')) ($daysSinceLastLegacyAuth days ago)"
                TotalLegacySignIns = $signInData.SignInCount
                SuccessfulLegacySignIns = $signInData.SuccessfulSignIns
                FailedLegacySignIns = $signInData.FailedSignIns
                LastSignIn = $signInInfo.LastSignIn
                LastSignInDisplay = $signInInfo.DisplayText
                DaysSinceLastSignIn = $signInInfo.DaysAgo
                SignInType = $signInInfo.SignInType
                MFAEnabled = $mfaStatus.HasMFA
                AuthMethods = ($mfaStatus.Methods -join ", ")
                MethodCount = $mfaStatus.MethodCount
                RiskLevel = $riskLevel
                RiskReasons = ($riskReasons -join "; ")
            }
            
            $script:LegacyAuthUsers += $userInfo
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
    Write-Host "MATRIX VIEW - LEGACY AUTHENTICATION USAGE" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:LegacyAuthUsers.Count -eq 0) {
        Write-Host "`n[+] No legacy authentication usage found matching the specified criteria." -ForegroundColor Green
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:LegacyAuthUsers | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='MFA';Expression={if($_.MFAEnabled){'Yes'}else{'No'}}},
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}},
        @{Name='User Principal Name';Expression={$_.UserPrincipalName}},
        @{Name='Display Name';Expression={$_.DisplayName}},
        @{Name='Protocols';Expression={$_.LegacyProtocols}},
        @{Name='Last Legacy Auth';Expression={
            if($_.DaysSinceLastLegacyAuth -eq 0){'Today'}
            elseif($_.DaysSinceLastLegacyAuth -eq 1){'Yesterday'}
            elseif($_.DaysSinceLastLegacyAuth -le 7){'This week'}
            elseif($_.DaysSinceLastLegacyAuth -le 30){'This month'}
            else{"$($_.DaysSinceLastLegacyAuth)d ago"}
        }},
        @{Name='Sign-Ins';Expression={$_.TotalLegacySignIns}},
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
    Write-Host "Total users with legacy auth usage: " -NoNewline -ForegroundColor White
    Write-Host $script:LegacyAuthUsers.Count -ForegroundColor Yellow
    
    $criticalRisk = ($script:LegacyAuthUsers | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:LegacyAuthUsers | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:LegacyAuthUsers | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:LegacyAuthUsers | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk (active without MFA): " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk (recent usage): " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk (older usage): " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Cyan
    Write-Host "  - LOW risk (disabled accounts): " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    $withMFA = ($script:LegacyAuthUsers | Where-Object { $_.MFAEnabled -eq $true }).Count
    $withoutMFA = ($script:LegacyAuthUsers | Where-Object { $_.MFAEnabled -eq $false }).Count
    
    Write-Host "`n[MFA STATUS]" -ForegroundColor Cyan
    Write-Host "  With MFA enabled: " -NoNewline -ForegroundColor White
    Write-Host $withMFA -ForegroundColor Green
    Write-Host "  Without MFA: " -NoNewline -ForegroundColor White
    Write-Host $withoutMFA -ForegroundColor Red
    
    # Group by protocol
    $byProtocol = @{}
    foreach ($user in $script:LegacyAuthUsers) {
        $protocols = $user.LegacyProtocols -split ", "
        foreach ($protocol in $protocols) {
            if (-not $byProtocol.ContainsKey($protocol)) {
                $byProtocol[$protocol] = 0
            }
            $byProtocol[$protocol]++
        }
    }
    
    if ($byProtocol.Count -gt 0) {
        Write-Host "`n[USERS BY PROTOCOL]" -ForegroundColor Cyan
        $byProtocol.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Value -ForegroundColor Yellow
        }
    }
    
    # Group by department
    $byDept = $script:LegacyAuthUsers | Where-Object { $_.Department } | Group-Object Department | Sort-Object Count -Descending
    if ($byDept.Count -gt 0) {
        Write-Host "`n[TOP DEPARTMENTS]" -ForegroundColor Cyan
        $byDept | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Usage recency statistics
    $recentUsage = ($script:LegacyAuthUsers | Where-Object { $_.DaysSinceLastLegacyAuth -le 7 }).Count
    $monthlyUsage = ($script:LegacyAuthUsers | Where-Object { $_.DaysSinceLastLegacyAuth -le 30 }).Count
    $oldUsage = ($script:LegacyAuthUsers | Where-Object { $_.DaysSinceLastLegacyAuth -gt 90 }).Count
    
    if ($recentUsage -gt 0 -or $monthlyUsage -gt 0 -or $oldUsage -gt 0) {
        Write-Host "`n[USAGE RECENCY]" -ForegroundColor Cyan
        if ($recentUsage -gt 0) {
            Write-Host "  Last 7 days: " -NoNewline -ForegroundColor White
            Write-Host $recentUsage -ForegroundColor Red
        }
        if ($monthlyUsage -gt 0) {
            Write-Host "  Last 30 days: " -NoNewline -ForegroundColor White
            Write-Host $monthlyUsage -ForegroundColor Yellow
        }
        if ($oldUsage -gt 0) {
            Write-Host "  >90 days ago: " -NoNewline -ForegroundColor White
            Write-Host $oldUsage -ForegroundColor Gray
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
    
    Write-Host "Users with legacy auth usage: " -NoNewline -ForegroundColor White
    Write-Host $script:LegacyAuthUsers.Count -ForegroundColor $(if($script:LegacyAuthUsers.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:LegacyAuthUsers.Count -gt 0) {
        $criticalRisk = ($script:LegacyAuthUsers | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:LegacyAuthUsers | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:LegacyAuthUsers | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:LegacyAuthUsers | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk (active without MFA): " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk (recent usage): " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk (older usage): " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Cyan
        Write-Host "  - LOW risk (disabled accounts): " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`nMFA Status:" -ForegroundColor Cyan
        $withMFA = ($script:LegacyAuthUsers | Where-Object { $_.MFAEnabled -eq $true }).Count
        $withoutMFA = ($script:LegacyAuthUsers | Where-Object { $_.MFAEnabled -eq $false }).Count
        Write-Host "  - With MFA: " -NoNewline -ForegroundColor White
        Write-Host $withMFA -ForegroundColor Green
        Write-Host "  - Without MFA: " -NoNewline -ForegroundColor White
        Write-Host $withoutMFA -ForegroundColor Red
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "USER DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:LegacyAuthUsers | ForEach-Object {
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
            
            Write-Host "  Legacy Protocols ($($_.ProtocolCount)): " -NoNewline -ForegroundColor Gray
            Write-Host $_.LegacyProtocols -ForegroundColor Cyan
            
            Write-Host "  Last Legacy Auth: " -NoNewline -ForegroundColor Gray
            Write-Host $_.LastLegacySignInDisplay -NoNewline -ForegroundColor $(if($_.DaysSinceLastLegacyAuth -le 7){"Red"}elseif($_.DaysSinceLastLegacyAuth -le 30){"Yellow"}else{"Gray"})
            Write-Host " ($($_.DaysSinceLastLegacyAuth) days ago)" -ForegroundColor DarkGray
            
            Write-Host "  Legacy Sign-In Statistics: " -NoNewline -ForegroundColor Gray
            Write-Host "$($_.TotalLegacySignIns) total ($($_.SuccessfulLegacySignIns) successful, $($_.FailedLegacySignIns) failed)" -ForegroundColor Gray
            
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
            
            if ($_.RiskReasons) {
                Write-Host "  Risk Reasons: $($_.RiskReasons)" -ForegroundColor $(if($_.RiskLevel -eq "CRITICAL"){"Red"}elseif($_.RiskLevel -eq "HIGH"){"Yellow"}else{"Gray"})
            }
            
            Write-Host "  Created: $($_.CreatedDateTime) ($($_.DaysOld) days old)" -ForegroundColor Gray
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[+] No legacy authentication usage found matching the specified criteria." -ForegroundColor Green
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
    
    if ($script:LegacyAuthUsers.Count -eq 0) {
        Write-Host "`n[*] No legacy auth usage to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:LegacyAuthUsers | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:LegacyAuthUsers | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:LegacyAuthUsers | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-LegacyAuthScan
        
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
        
        Write-Host "`n[*] Legacy authentication check completed successfully!" -ForegroundColor Green
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

