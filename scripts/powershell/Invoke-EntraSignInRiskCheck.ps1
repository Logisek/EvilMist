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
    Analyzes Azure AD Identity Protection signals, risky users, and suspicious sign-in patterns.

.DESCRIPTION
    This script performs a comprehensive analysis of Azure AD Identity Protection data to identify
    potential security risks including:
    - Enumerates risky users and their risk levels/states
    - Analyzes risky sign-ins with risk event types
    - Detects patterns: impossible travel, anonymous IPs, Tor, unfamiliar locations
    - Credential stuffing indicators (high failure rates)
    - Sign-in anomalies: unusual times, new devices, new locations
    - MFA bypass attempts
    - Risk trending over time
    
    Azure AD Identity Protection is a critical security feature that helps detect, investigate,
    and remediate identity-based risks. This script provides red/blue team visibility into
    these signals.
    
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

.PARAMETER DaysBack
    Number of days to look back for risky sign-ins and detections. Default: 30

.PARAMETER OnlyHighRisk
    Show only high-risk users and sign-ins.

.PARAMETER OnlyActive
    Show only users with active (not remediated) risk.

.PARAMETER IncludeRiskySignIns
    Include detailed risky sign-in analysis.

.PARAMETER IncludeRiskDetections
    Include risk detection events analysis.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraSignInRiskCheck.ps1
    # Enumerate all risky users and basic risk analysis

.EXAMPLE
    .\Invoke-EntraSignInRiskCheck.ps1 -ExportPath "risky-users.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraSignInRiskCheck.ps1 -OnlyHighRisk -Matrix
    # Display only high-risk users in matrix format

.EXAMPLE
    .\Invoke-EntraSignInRiskCheck.ps1 -IncludeRiskySignIns -DaysBack 7
    # Include risky sign-ins from the last 7 days

.EXAMPLE
    .\Invoke-EntraSignInRiskCheck.ps1 -IncludeRiskDetections -OnlyActive
    # Show only active risks with detection details

.EXAMPLE
    .\Invoke-EntraSignInRiskCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output
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
    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyHighRisk,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyActive,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeRiskySignIns,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeRiskDetections,

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

# Risk event type descriptions
$script:RiskEventTypes = @{
    # Real-time detections
    "anonymizedIPAddress" = @{
        Description = "Sign-in from anonymized IP address (VPN, Tor, etc.)"
        Severity = "HIGH"
        Category = "Anonymous Access"
    }
    "maliciousIPAddress" = @{
        Description = "Sign-in from known malicious IP address"
        Severity = "CRITICAL"
        Category = "Malicious Infrastructure"
    }
    "unfamiliarFeatures" = @{
        Description = "Sign-in with unfamiliar properties"
        Severity = "MEDIUM"
        Category = "Anomalous Behavior"
    }
    "malwareInfectedIPAddress" = @{
        Description = "Sign-in from malware-infected IP address"
        Severity = "CRITICAL"
        Category = "Malicious Infrastructure"
    }
    "suspiciousIPAddress" = @{
        Description = "Sign-in from suspicious IP address"
        Severity = "HIGH"
        Category = "Suspicious Activity"
    }
    "leakedCredentials" = @{
        Description = "User's credentials were found in a data breach"
        Severity = "CRITICAL"
        Category = "Credential Compromise"
    }
    "investigationsThreatIntelligence" = @{
        Description = "Sign-in flagged by Microsoft threat intelligence"
        Severity = "CRITICAL"
        Category = "Threat Intelligence"
    }
    "generic" = @{
        Description = "Generic risk detection"
        Severity = "MEDIUM"
        Category = "General"
    }
    "adminConfirmedUserCompromised" = @{
        Description = "Admin confirmed user compromised"
        Severity = "CRITICAL"
        Category = "Confirmed Compromise"
    }
    "mcasImpossibleTravel" = @{
        Description = "Impossible travel detected by Cloud App Security"
        Severity = "HIGH"
        Category = "Impossible Travel"
    }
    "mcasSuspiciousInboxManipulationRules" = @{
        Description = "Suspicious inbox rules detected by Cloud App Security"
        Severity = "CRITICAL"
        Category = "Email Compromise"
    }
    "investigationsThreatIntelligenceSigninLinked" = @{
        Description = "Sign-in linked to threat intelligence"
        Severity = "CRITICAL"
        Category = "Threat Intelligence"
    }
    "maliciousIPAddressValidCredentialsBlockedIP" = @{
        Description = "Valid credentials from blocked malicious IP"
        Severity = "CRITICAL"
        Category = "Credential Compromise"
    }
    # Offline detections
    "impossibleTravel" = @{
        Description = "Impossible travel (sign-ins from geographically distant locations)"
        Severity = "HIGH"
        Category = "Impossible Travel"
    }
    "newCountry" = @{
        Description = "Sign-in from new country/region"
        Severity = "MEDIUM"
        Category = "New Location"
    }
    "atypicalTravelPatterns" = @{
        Description = "Atypical travel patterns"
        Severity = "MEDIUM"
        Category = "Anomalous Behavior"
    }
    "passwordSpray" = @{
        Description = "Password spray attack detected"
        Severity = "CRITICAL"
        Category = "Credential Attack"
    }
    "anomalousToken" = @{
        Description = "Anomalous token usage"
        Severity = "HIGH"
        Category = "Token Abuse"
    }
    "tokenIssuerAnomaly" = @{
        Description = "Token issuer anomaly"
        Severity = "HIGH"
        Category = "Token Abuse"
    }
    "suspiciousBrowser" = @{
        Description = "Suspicious browser detected"
        Severity = "MEDIUM"
        Category = "Anomalous Behavior"
    }
    "riskyIPAddress" = @{
        Description = "Sign-in from risky IP address"
        Severity = "HIGH"
        Category = "Suspicious Activity"
    }
    "additionalRiskDetected" = @{
        Description = "Additional risk detected"
        Severity = "MEDIUM"
        Category = "General"
    }
    "userReportedSuspiciousActivity" = @{
        Description = "User reported suspicious activity"
        Severity = "HIGH"
        Category = "User Reported"
    }
    # Premium detections
    "nationStateIP" = @{
        Description = "Sign-in from nation-state actor IP"
        Severity = "CRITICAL"
        Category = "Nation State"
    }
    "anomalousUserActivity" = @{
        Description = "Anomalous user activity pattern"
        Severity = "HIGH"
        Category = "Anomalous Behavior"
    }
}

# Required scopes for Identity Protection
$script:RequiredScopes = @(
    "IdentityRiskyUser.Read.All",
    "IdentityRiskEvent.Read.All",
    "User.Read.All",
    "AuditLog.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "IdentityRiskyUser.Read.All",
    "User.Read.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:RiskyUsers = @()
$script:RiskySignIns = @()
$script:RiskDetections = @()
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
    Write-Host "    Entra ID Sign-In Risk Check - Identity Protection Analysis" -ForegroundColor Yellow
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
            Write-Host "[!] Some features may be limited (risk detections may not be available)" -ForegroundColor Yellow
            
            return $true
        }
        catch {
            Write-Host "[ERROR] Authentication failed: $_" -ForegroundColor Red
            return $false
        }
    }
}

# Get risk event type info
function Get-RiskEventInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RiskEventType
    )
    
    if ($script:RiskEventTypes.ContainsKey($RiskEventType)) {
        return $script:RiskEventTypes[$RiskEventType]
    }
    
    return @{
        Description = "Unknown risk event type: $RiskEventType"
        Severity = "MEDIUM"
        Category = "Unknown"
    }
}

# Map risk level to display values
function Get-RiskLevelDisplay {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RiskLevel
    )
    
    switch ($RiskLevel.ToLower()) {
        "high" { return @{ Display = "HIGH"; Color = "Red"; Priority = 3 } }
        "medium" { return @{ Display = "MEDIUM"; Color = "Yellow"; Priority = 2 } }
        "low" { return @{ Display = "LOW"; Color = "Cyan"; Priority = 1 } }
        "hidden" { return @{ Display = "HIDDEN"; Color = "DarkGray"; Priority = 0 } }
        "none" { return @{ Display = "NONE"; Color = "Green"; Priority = 0 } }
        default { return @{ Display = $RiskLevel.ToUpper(); Color = "Gray"; Priority = 1 } }
    }
}

# Map risk state to display values
function Get-RiskStateDisplay {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RiskState
    )
    
    switch ($RiskState.ToLower()) {
        "atrisk" { return @{ Display = "At Risk"; Color = "Red"; IsActive = $true } }
        "confirmedcompromised" { return @{ Display = "Confirmed Compromised"; Color = "Red"; IsActive = $true } }
        "remediated" { return @{ Display = "Remediated"; Color = "Green"; IsActive = $false } }
        "dismissed" { return @{ Display = "Dismissed"; Color = "Gray"; IsActive = $false } }
        "confirmedsafe" { return @{ Display = "Confirmed Safe"; Color = "Green"; IsActive = $false } }
        default { return @{ Display = $RiskState; Color = "Yellow"; IsActive = $true } }
    }
}

# Get risky users
function Get-RiskyUsersAnalysis {
    Write-Host "`n[*] Retrieving risky users..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get all risky users
        $riskyUsers = Get-MgRiskyUser -All -ErrorAction Stop
        
        if ($riskyUsers.Count -eq 0) {
            Write-Host "[+] No risky users found" -ForegroundColor Green
            return
        }
        
        Write-Host "[+] Found $($riskyUsers.Count) risky user(s)" -ForegroundColor Yellow
        
        $script:TotalUsersScanned = $riskyUsers.Count
        $progressCounter = 0
        
        foreach ($user in $riskyUsers) {
            $progressCounter++
            
            # Progress indicator
            if ($progressCounter % 10 -eq 0 -or $progressCounter -eq $riskyUsers.Count) {
                $percentComplete = [math]::Round(($progressCounter / $riskyUsers.Count) * 100, 1)
                Write-Host "`r[*] Progress: $progressCounter/$($riskyUsers.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
            }
            
            try {
                Invoke-StealthDelay
                
                # Get risk level and state display info
                $riskLevelInfo = Get-RiskLevelDisplay -RiskLevel $user.RiskLevel
                $riskStateInfo = Get-RiskStateDisplay -RiskState $user.RiskState
                
                # Filter: Only high risk
                if ($OnlyHighRisk -and $user.RiskLevel -ne "high") {
                    continue
                }
                
                # Filter: Only active
                if ($OnlyActive -and -not $riskStateInfo.IsActive) {
                    continue
                }
                
                # Get additional user details
                $userDetails = $null
                try {
                    Invoke-StealthDelay
                    $userDetails = Get-MgUser -UserId $user.UserPrincipalName -Property Id,DisplayName,UserPrincipalName,JobTitle,Department,AccountEnabled,SignInActivity -ErrorAction SilentlyContinue
                }
                catch {
                    # User might be deleted or inaccessible
                }
                
                # Get last sign-in
                $lastSignIn = $null
                $daysSinceSignIn = -1
                if ($userDetails -and $userDetails.SignInActivity) {
                    $lastSignIn = $userDetails.SignInActivity.LastSignInDateTime
                    if ($lastSignIn) {
                        $daysSinceSignIn = ([DateTime]::Now - [DateTime]$lastSignIn).Days
                    }
                }
                
                # Get risk detail
                $riskDetail = $user.RiskDetail
                if ([string]::IsNullOrEmpty($riskDetail)) {
                    $riskDetail = "No details available"
                }
                
                # Parse risk last updated
                $riskLastUpdated = $user.RiskLastUpdatedDateTime
                $daysSinceRiskUpdate = -1
                if ($riskLastUpdated) {
                    $daysSinceRiskUpdate = ([DateTime]::Now - [DateTime]$riskLastUpdated).Days
                }
                
                $userInfo = [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = if ($userDetails) { $userDetails.DisplayName } else { $user.UserDisplayName }
                    UserId = $user.Id
                    RiskLevel = $riskLevelInfo.Display
                    RiskState = $riskStateInfo.Display
                    RiskStateRaw = $user.RiskState
                    IsActive = $riskStateInfo.IsActive
                    RiskDetail = $riskDetail
                    RiskLastUpdated = $riskLastUpdated
                    DaysSinceRiskUpdate = $daysSinceRiskUpdate
                    AccountEnabled = if ($userDetails) { $userDetails.AccountEnabled } else { $null }
                    JobTitle = if ($userDetails) { $userDetails.JobTitle } else { $null }
                    Department = if ($userDetails) { $userDetails.Department } else { $null }
                    LastSignIn = $lastSignIn
                    DaysSinceLastSignIn = $daysSinceSignIn
                    RiskLevelPriority = $riskLevelInfo.Priority
                }
                
                $script:RiskyUsers += $userInfo
            }
            catch {
                Write-Host "`n[!] Error processing user $($user.UserPrincipalName): $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n[+] Risky user analysis complete" -ForegroundColor Green
    }
    catch {
        Write-Host "`n[ERROR] Failed to retrieve risky users: $_" -ForegroundColor Red
        Write-Host "[!] Note: IdentityRiskyUser.Read.All permission is required" -ForegroundColor Yellow
    }
}

# Get risky sign-ins
function Get-RiskySignInsAnalysis {
    if (-not $IncludeRiskySignIns) {
        return
    }
    
    Write-Host "`n[*] Retrieving risky sign-ins (last $DaysBack days)..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Calculate date filter
        $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        # Get risky sign-ins using the signIn logs with risk data
        # Note: Using the v1.0 endpoint for stability
        try {
            # First try to get risk detections which include sign-in related risks
            $riskDetections = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=activityDateTime ge $startDate&`$top=500" -Method GET -ErrorAction Stop
            
            if ($riskDetections.value.Count -eq 0) {
                Write-Host "[+] No risky sign-ins found in the last $DaysBack days" -ForegroundColor Green
                return
            }
            
            Write-Host "[+] Found $($riskDetections.value.Count) risk detection(s)" -ForegroundColor Yellow
            
            foreach ($detection in $riskDetections.value) {
                try {
                    # Get risk event info
                    $eventInfo = Get-RiskEventInfo -RiskEventType $detection.riskEventType
                    $riskLevelInfo = Get-RiskLevelDisplay -RiskLevel $detection.riskLevel
                    $riskStateInfo = Get-RiskStateDisplay -RiskState $detection.riskState
                    
                    # Filter: Only high risk
                    if ($OnlyHighRisk -and $detection.riskLevel -ne "high") {
                        continue
                    }
                    
                    # Filter: Only active
                    if ($OnlyActive -and -not $riskStateInfo.IsActive) {
                        continue
                    }
                    
                    # Parse location info
                    $location = "Unknown"
                    $city = ""
                    $country = ""
                    $ipAddress = $detection.ipAddress
                    
                    if ($detection.location) {
                        $city = $detection.location.city
                        $country = $detection.location.countryOrRegion
                        if ($city -and $country) {
                            $location = "$city, $country"
                        }
                        elseif ($country) {
                            $location = $country
                        }
                    }
                    
                    # Parse activity datetime
                    $activityTime = $detection.activityDateTime
                    $hourOfDay = -1
                    $isWeekend = $false
                    $isAfterHours = $false
                    
                    if ($activityTime) {
                        $dt = [DateTime]$activityTime
                        $hourOfDay = $dt.Hour
                        $isWeekend = $dt.DayOfWeek -eq "Saturday" -or $dt.DayOfWeek -eq "Sunday"
                        $isAfterHours = $hourOfDay -lt 6 -or $hourOfDay -gt 20
                    }
                    
                    $signInInfo = [PSCustomObject]@{
                        UserPrincipalName = $detection.userPrincipalName
                        DisplayName = $detection.userDisplayName
                        UserId = $detection.userId
                        RiskEventType = $detection.riskEventType
                        RiskEventDescription = $eventInfo.Description
                        RiskEventSeverity = $eventInfo.Severity
                        RiskEventCategory = $eventInfo.Category
                        RiskLevel = $riskLevelInfo.Display
                        RiskState = $riskStateInfo.Display
                        IsActive = $riskStateInfo.IsActive
                        RiskDetail = $detection.riskDetail
                        IPAddress = $ipAddress
                        Location = $location
                        City = $city
                        Country = $country
                        ActivityDateTime = $activityTime
                        HourOfDay = $hourOfDay
                        IsWeekend = $isWeekend
                        IsAfterHours = $isAfterHours
                        DetectedDateTime = $detection.detectedDateTime
                        DetectionTimingType = $detection.detectionTimingType
                        Source = $detection.source
                        TokenIssuerType = $detection.tokenIssuerType
                        CorrelationId = $detection.correlationId
                        RequestId = $detection.requestId
                        DetectionId = $detection.id
                        RiskLevelPriority = $riskLevelInfo.Priority
                    }
                    
                    $script:RiskySignIns += $signInInfo
                }
                catch {
                    Write-Host "[!] Error processing risk detection: $_" -ForegroundColor Yellow
                }
            }
            
            Write-Host "[+] Risky sign-in analysis complete" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Unable to retrieve risk detections: $_" -ForegroundColor Yellow
            Write-Host "[!] Note: IdentityRiskEvent.Read.All permission may be required" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "`n[ERROR] Failed to retrieve risky sign-ins: $_" -ForegroundColor Red
    }
}

# Get risk detections for detailed analysis
function Get-RiskDetectionsAnalysis {
    if (-not $IncludeRiskDetections) {
        return
    }
    
    Write-Host "`n[*] Analyzing risk detection patterns (last $DaysBack days)..." -ForegroundColor Cyan
    
    # Risk detections are already retrieved in Get-RiskySignInsAnalysis
    # This function provides additional pattern analysis
    
    if ($script:RiskySignIns.Count -eq 0) {
        Write-Host "[!] No risk detections to analyze" -ForegroundColor Yellow
        return
    }
    
    # Group detections by category for pattern analysis
    $byCategory = $script:RiskySignIns | Group-Object RiskEventCategory
    $byUser = $script:RiskySignIns | Group-Object UserPrincipalName
    $byCountry = $script:RiskySignIns | Where-Object { $_.Country } | Group-Object Country
    
    # Detect patterns
    Write-Host "[*] Analyzing detection patterns..." -ForegroundColor Cyan
    
    # Users with multiple different risk types (potential target)
    $multiRiskUsers = $byUser | Where-Object { 
        ($_.Group | Select-Object -Unique RiskEventType).Count -ge 2 
    }
    
    # After hours activity
    $afterHoursCount = ($script:RiskySignIns | Where-Object { $_.IsAfterHours }).Count
    
    # Weekend activity
    $weekendCount = ($script:RiskySignIns | Where-Object { $_.IsWeekend }).Count
    
    # Anonymous/Tor access
    $anonymousCount = ($script:RiskySignIns | Where-Object { $_.RiskEventType -eq "anonymizedIPAddress" }).Count
    
    # Impossible travel
    $impossibleTravelCount = ($script:RiskySignIns | Where-Object { $_.RiskEventType -like "*impossibleTravel*" -or $_.RiskEventType -like "*mcasImpossibleTravel*" }).Count
    
    # Password spray
    $passwordSprayCount = ($script:RiskySignIns | Where-Object { $_.RiskEventType -eq "passwordSpray" }).Count
    
    # Leaked credentials
    $leakedCredsCount = ($script:RiskySignIns | Where-Object { $_.RiskEventType -eq "leakedCredentials" }).Count
    
    Write-Host "[+] Pattern analysis complete" -ForegroundColor Green
    
    # Store pattern analysis
    $script:RiskPatterns = [PSCustomObject]@{
        TotalDetections = $script:RiskySignIns.Count
        UniqueUsers = $byUser.Count
        MultiRiskUserCount = $multiRiskUsers.Count
        MultiRiskUsers = ($multiRiskUsers | ForEach-Object { $_.Name }) -join ", "
        AfterHoursCount = $afterHoursCount
        WeekendCount = $weekendCount
        AnonymousAccessCount = $anonymousCount
        ImpossibleTravelCount = $impossibleTravelCount
        PasswordSprayCount = $passwordSprayCount
        LeakedCredentialsCount = $leakedCredsCount
        TopCategories = ($byCategory | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Count)" }) -join "; "
        TopCountries = ($byCountry | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Count)" }) -join "; "
    }
}

# Main scanning function
function Start-SignInRiskScan {
    Write-Host "`n[*] Starting Sign-In Risk analysis..." -ForegroundColor Cyan
    Write-Host "[*] Looking back $DaysBack days for risk data..." -ForegroundColor Cyan
    
    # Get risky users
    Get-RiskyUsersAnalysis
    
    # Get risky sign-ins (if requested)
    Get-RiskySignInsAnalysis
    
    # Analyze patterns (if requested)
    Get-RiskDetectionsAnalysis
    
    Write-Host "`n[+] Scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 160) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - IDENTITY PROTECTION RISK ANALYSIS" -ForegroundColor Cyan
    Write-Host ("=" * 160) -ForegroundColor Cyan
    
    # === RISKY USERS SECTION ===
    if ($script:RiskyUsers.Count -gt 0) {
        Write-Host "`n[RISKY USERS]" -ForegroundColor Yellow
        Write-Host ("-" * 160) -ForegroundColor Cyan
        
        # Sort by risk level priority (highest first)
        $sortedUsers = $script:RiskyUsers | Sort-Object -Property RiskLevelPriority -Descending
        
        $matrixData = $sortedUsers | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='State';Expression={$_.RiskState}},
            @{Name='Active';Expression={if($_.IsActive){'Yes'}else{'No'}}},
            @{Name='User Principal Name';Expression={if($_.UserPrincipalName.Length -gt 40){$_.UserPrincipalName.Substring(0,37)+"..."}else{$_.UserPrincipalName}}},
            @{Name='Display Name';Expression={if($_.DisplayName.Length -gt 25){$_.DisplayName.Substring(0,22)+"..."}else{$_.DisplayName}}},
            @{Name='Department';Expression={if($_.Department){if($_.Department.Length -gt 15){$_.Department.Substring(0,12)+"..."}else{$_.Department}}else{'-'}}},
            @{Name='Risk Updated';Expression={if($_.DaysSinceRiskUpdate -ge 0){"$($_.DaysSinceRiskUpdate)d ago"}else{'Unknown'}}},
            @{Name='Last Sign-In';Expression={if($_.DaysSinceLastSignIn -ge 0){"$($_.DaysSinceLastSignIn)d ago"}else{'Unknown'}}}
        
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
                    Write-Host $line -ForegroundColor Cyan
                }
                elseif ($line -match '^-+\s+-+' -or $line -match '^Risk\s+') {
                    Write-Host $line -ForegroundColor Cyan
                }
                else {
                    Write-Host $line -ForegroundColor White
                }
            }
        }
    }
    else {
        Write-Host "`n[RISKY USERS]" -ForegroundColor Yellow
        Write-Host "[+] No risky users found matching criteria" -ForegroundColor Green
    }
    
    # === RISKY SIGN-INS SECTION ===
    if ($script:RiskySignIns.Count -gt 0) {
        Write-Host "`n[RISK DETECTIONS / RISKY SIGN-INS]" -ForegroundColor Yellow
        Write-Host ("-" * 160) -ForegroundColor Cyan
        
        # Sort by risk level priority and date
        $sortedSignIns = $script:RiskySignIns | Sort-Object -Property RiskLevelPriority, ActivityDateTime -Descending | Select-Object -First 50
        
        $signInMatrix = $sortedSignIns | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='Category';Expression={if($_.RiskEventCategory.Length -gt 15){$_.RiskEventCategory.Substring(0,12)+"..."}else{$_.RiskEventCategory}}},
            @{Name='Event Type';Expression={if($_.RiskEventType.Length -gt 20){$_.RiskEventType.Substring(0,17)+"..."}else{$_.RiskEventType}}},
            @{Name='User';Expression={if($_.UserPrincipalName.Length -gt 30){$_.UserPrincipalName.Substring(0,27)+"..."}else{$_.UserPrincipalName}}},
            @{Name='IP Address';Expression={$_.IPAddress}},
            @{Name='Location';Expression={if($_.Location.Length -gt 20){$_.Location.Substring(0,17)+"..."}else{$_.Location}}},
            @{Name='Time';Expression={if($_.ActivityDateTime){([DateTime]$_.ActivityDateTime).ToString('MM/dd HH:mm')}else{'-'}}}
        
        $signInMatrix | Format-Table -AutoSize -Wrap | Out-String | ForEach-Object {
            $lines = $_ -split "`n"
            foreach ($line in $lines) {
                if ($line -match '^\s*HIGH\s+' -or $line -match '^\s*CRITICAL\s+') {
                    Write-Host $line -ForegroundColor Red
                }
                elseif ($line -match '^\s*MEDIUM\s+') {
                    Write-Host $line -ForegroundColor Yellow
                }
                elseif ($line -match '^\s*LOW\s+') {
                    Write-Host $line -ForegroundColor Cyan
                }
                elseif ($line -match '^-+\s+-+' -or $line -match '^Risk\s+') {
                    Write-Host $line -ForegroundColor Cyan
                }
                else {
                    Write-Host $line -ForegroundColor White
                }
            }
        }
        
        if ($script:RiskySignIns.Count -gt 50) {
            Write-Host "  ... and $($script:RiskySignIns.Count - 50) more detection(s)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "`n" + ("=" * 160) -ForegroundColor Cyan
    
    # === SUMMARY SECTION ===
    Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
    
    # Risky users summary
    Write-Host "Total risky users: " -NoNewline -ForegroundColor White
    Write-Host $script:RiskyUsers.Count -ForegroundColor $(if($script:RiskyUsers.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:RiskyUsers.Count -gt 0) {
        $highRiskUsers = ($script:RiskyUsers | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRiskUsers = ($script:RiskyUsers | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRiskUsers = ($script:RiskyUsers | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        $activeRiskUsers = ($script:RiskyUsers | Where-Object { $_.IsActive }).Count
        
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRiskUsers -ForegroundColor Red
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRiskUsers -ForegroundColor Yellow
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRiskUsers -ForegroundColor Cyan
        Write-Host "  - Active (not remediated): " -NoNewline -ForegroundColor White
        Write-Host $activeRiskUsers -ForegroundColor $(if($activeRiskUsers -gt 0){"Red"}else{"Green"})
    }
    
    # Risk detections summary
    if ($script:RiskySignIns.Count -gt 0) {
        Write-Host "`nTotal risk detections: " -NoNewline -ForegroundColor White
        Write-Host $script:RiskySignIns.Count -ForegroundColor Yellow
        
        $highRiskDetections = ($script:RiskySignIns | Where-Object { $_.RiskLevel -eq "HIGH" -or $_.RiskEventSeverity -eq "CRITICAL" }).Count
        $activeDetections = ($script:RiskySignIns | Where-Object { $_.IsActive }).Count
        
        Write-Host "  - HIGH/CRITICAL severity: " -NoNewline -ForegroundColor White
        Write-Host $highRiskDetections -ForegroundColor Red
        Write-Host "  - Active detections: " -NoNewline -ForegroundColor White
        Write-Host $activeDetections -ForegroundColor $(if($activeDetections -gt 0){"Red"}else{"Green"})
        
        # Category breakdown
        $byCategory = $script:RiskySignIns | Group-Object RiskEventCategory | Sort-Object Count -Descending | Select-Object -First 5
        if ($byCategory.Count -gt 0) {
            Write-Host "`n[TOP RISK CATEGORIES]" -ForegroundColor Cyan
            foreach ($cat in $byCategory) {
                Write-Host "  $($cat.Name): " -NoNewline -ForegroundColor White
                Write-Host $cat.Count -ForegroundColor Yellow
            }
        }
    }
    
    # Pattern analysis summary
    if ($script:RiskPatterns) {
        Write-Host "`n[RISK PATTERNS DETECTED]" -ForegroundColor Cyan
        
        if ($script:RiskPatterns.MultiRiskUserCount -gt 0) {
            Write-Host "  Users with multiple risk types: " -NoNewline -ForegroundColor White
            Write-Host $script:RiskPatterns.MultiRiskUserCount -ForegroundColor Red
        }
        
        if ($script:RiskPatterns.AnonymousAccessCount -gt 0) {
            Write-Host "  Anonymous/VPN access attempts: " -NoNewline -ForegroundColor White
            Write-Host $script:RiskPatterns.AnonymousAccessCount -ForegroundColor Yellow
        }
        
        if ($script:RiskPatterns.ImpossibleTravelCount -gt 0) {
            Write-Host "  Impossible travel detections: " -NoNewline -ForegroundColor White
            Write-Host $script:RiskPatterns.ImpossibleTravelCount -ForegroundColor Red
        }
        
        if ($script:RiskPatterns.PasswordSprayCount -gt 0) {
            Write-Host "  Password spray attacks: " -NoNewline -ForegroundColor White
            Write-Host $script:RiskPatterns.PasswordSprayCount -ForegroundColor Red
        }
        
        if ($script:RiskPatterns.LeakedCredentialsCount -gt 0) {
            Write-Host "  Leaked credentials detected: " -NoNewline -ForegroundColor White
            Write-Host $script:RiskPatterns.LeakedCredentialsCount -ForegroundColor Red
        }
        
        if ($script:RiskPatterns.AfterHoursCount -gt 0) {
            Write-Host "  After-hours activity: " -NoNewline -ForegroundColor White
            Write-Host $script:RiskPatterns.AfterHoursCount -ForegroundColor Yellow
        }
        
        if ($script:RiskPatterns.WeekendCount -gt 0) {
            Write-Host "  Weekend activity: " -NoNewline -ForegroundColor White
            Write-Host $script:RiskPatterns.WeekendCount -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
}

# Display results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    # === RISKY USERS SECTION ===
    Write-Host "`nRisky users found: " -NoNewline -ForegroundColor White
    Write-Host $script:RiskyUsers.Count -ForegroundColor $(if($script:RiskyUsers.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:RiskyUsers.Count -gt 0) {
        $highRiskUsers = ($script:RiskyUsers | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRiskUsers = ($script:RiskyUsers | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRiskUsers = ($script:RiskyUsers | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        $activeRiskUsers = ($script:RiskyUsers | Where-Object { $_.IsActive }).Count
        
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRiskUsers -ForegroundColor Red
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRiskUsers -ForegroundColor Yellow
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRiskUsers -ForegroundColor Cyan
        Write-Host "  - Active (not remediated): " -NoNewline -ForegroundColor White
        Write-Host $activeRiskUsers -ForegroundColor $(if($activeRiskUsers -gt 0){"Red"}else{"Green"})
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "RISKY USER DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        # Sort by risk level priority
        $sortedUsers = $script:RiskyUsers | Sort-Object -Property RiskLevelPriority -Descending
        
        foreach ($user in $sortedUsers) {
            $riskColor = switch ($user.RiskLevel) {
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                "LOW" { "Cyan" }
                default { "White" }
            }
            
            Write-Host "`n[$($user.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host $user.UserPrincipalName -ForegroundColor White
            
            Write-Host "  Display Name: $($user.DisplayName)" -ForegroundColor Gray
            Write-Host "  Risk State: " -NoNewline -ForegroundColor Gray
            
            if ($user.IsActive) {
                Write-Host "$($user.RiskState)" -ForegroundColor Red
            }
            else {
                Write-Host "$($user.RiskState)" -ForegroundColor Green
            }
            
            Write-Host "  Risk Detail: $($user.RiskDetail)" -ForegroundColor Gray
            
            if ($user.RiskLastUpdated) {
                Write-Host "  Risk Updated: $($user.RiskLastUpdated) ($($user.DaysSinceRiskUpdate) days ago)" -ForegroundColor Gray
            }
            
            if ($user.JobTitle) {
                Write-Host "  Job Title: $($user.JobTitle)" -ForegroundColor Gray
            }
            if ($user.Department) {
                Write-Host "  Department: $($user.Department)" -ForegroundColor Gray
            }
            
            Write-Host "  Account Status: " -NoNewline -ForegroundColor Gray
            if ($user.AccountEnabled -eq $true) {
                Write-Host "Enabled" -ForegroundColor Green
            }
            elseif ($user.AccountEnabled -eq $false) {
                Write-Host "Disabled" -ForegroundColor Yellow
            }
            else {
                Write-Host "Unknown" -ForegroundColor Gray
            }
            
            if ($user.DaysSinceLastSignIn -ge 0) {
                Write-Host "  Last Sign-In: $($user.DaysSinceLastSignIn) days ago" -ForegroundColor Gray
            }
            
            if ($user.IsActive) {
                Write-Host "  [!] ACTION REQUIRED: Risk is still active" -ForegroundColor Red
            }
        }
    }
    
    # === RISK DETECTIONS SECTION ===
    if ($script:RiskySignIns.Count -gt 0) {
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "RISK DETECTION DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        Write-Host "`nTotal risk detections: " -NoNewline -ForegroundColor White
        Write-Host $script:RiskySignIns.Count -ForegroundColor Yellow
        
        # Show top 20 detections
        $topDetections = $script:RiskySignIns | Sort-Object -Property RiskLevelPriority, ActivityDateTime -Descending | Select-Object -First 20
        
        foreach ($detection in $topDetections) {
            $severityColor = switch ($detection.RiskEventSeverity) {
                "CRITICAL" { "Red" }
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                "LOW" { "Cyan" }
                default { "White" }
            }
            
            Write-Host "`n[$($detection.RiskEventSeverity)] " -NoNewline -ForegroundColor $severityColor
            Write-Host "$($detection.RiskEventType)" -ForegroundColor White
            
            Write-Host "  User: $($detection.UserPrincipalName)" -ForegroundColor Gray
            Write-Host "  Description: $($detection.RiskEventDescription)" -ForegroundColor Gray
            Write-Host "  Category: $($detection.RiskEventCategory)" -ForegroundColor Gray
            Write-Host "  Risk Level: $($detection.RiskLevel)" -ForegroundColor Gray
            
            if ($detection.IPAddress) {
                Write-Host "  IP Address: $($detection.IPAddress)" -ForegroundColor Gray
            }
            if ($detection.Location -and $detection.Location -ne "Unknown") {
                Write-Host "  Location: $($detection.Location)" -ForegroundColor Gray
            }
            if ($detection.ActivityDateTime) {
                $dt = [DateTime]$detection.ActivityDateTime
                Write-Host "  Activity Time: $($dt.ToString('yyyy-MM-dd HH:mm:ss'))" -NoNewline -ForegroundColor Gray
                if ($detection.IsAfterHours) {
                    Write-Host " [AFTER HOURS]" -ForegroundColor Yellow
                }
                elseif ($detection.IsWeekend) {
                    Write-Host " [WEEKEND]" -ForegroundColor Yellow
                }
                else {
                    Write-Host ""
                }
            }
            
            Write-Host "  State: " -NoNewline -ForegroundColor Gray
            if ($detection.IsActive) {
                Write-Host "$($detection.RiskState)" -ForegroundColor Red
            }
            else {
                Write-Host "$($detection.RiskState)" -ForegroundColor Green
            }
        }
        
        if ($script:RiskySignIns.Count -gt 20) {
            Write-Host "`n  ... and $($script:RiskySignIns.Count - 20) more detection(s)" -ForegroundColor DarkGray
        }
    }
    
    # === PATTERN ANALYSIS SECTION ===
    if ($script:RiskPatterns) {
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "RISK PATTERN ANALYSIS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        Write-Host "`nUnique users with detections: " -NoNewline -ForegroundColor White
        Write-Host $script:RiskPatterns.UniqueUsers -ForegroundColor Yellow
        
        if ($script:RiskPatterns.MultiRiskUserCount -gt 0) {
            Write-Host "`n[!] USERS WITH MULTIPLE RISK TYPES: " -NoNewline -ForegroundColor Red
            Write-Host $script:RiskPatterns.MultiRiskUserCount -ForegroundColor Red
            Write-Host "    These users may be actively targeted" -ForegroundColor DarkGray
            if ($script:RiskPatterns.MultiRiskUsers) {
                Write-Host "    Users: $($script:RiskPatterns.MultiRiskUsers)" -ForegroundColor Yellow
            }
        }
        
        if ($script:RiskPatterns.AnonymousAccessCount -gt 0) {
            Write-Host "`n[!] Anonymous/VPN Access: " -NoNewline -ForegroundColor Yellow
            Write-Host "$($script:RiskPatterns.AnonymousAccessCount) attempts" -ForegroundColor Yellow
        }
        
        if ($script:RiskPatterns.ImpossibleTravelCount -gt 0) {
            Write-Host "[!] Impossible Travel: " -NoNewline -ForegroundColor Red
            Write-Host "$($script:RiskPatterns.ImpossibleTravelCount) detections" -ForegroundColor Red
        }
        
        if ($script:RiskPatterns.PasswordSprayCount -gt 0) {
            Write-Host "[!] Password Spray Attacks: " -NoNewline -ForegroundColor Red
            Write-Host "$($script:RiskPatterns.PasswordSprayCount) detected" -ForegroundColor Red
        }
        
        if ($script:RiskPatterns.LeakedCredentialsCount -gt 0) {
            Write-Host "[!] Leaked Credentials: " -NoNewline -ForegroundColor Red
            Write-Host "$($script:RiskPatterns.LeakedCredentialsCount) users affected" -ForegroundColor Red
        }
        
        Write-Host "`n[TIMING ANALYSIS]" -ForegroundColor Cyan
        Write-Host "  After-hours activity: " -NoNewline -ForegroundColor White
        Write-Host $script:RiskPatterns.AfterHoursCount -ForegroundColor $(if($script:RiskPatterns.AfterHoursCount -gt 0){"Yellow"}else{"Green"})
        Write-Host "  Weekend activity: " -NoNewline -ForegroundColor White
        Write-Host $script:RiskPatterns.WeekendCount -ForegroundColor $(if($script:RiskPatterns.WeekendCount -gt 0){"Yellow"}else{"Green"})
        
        if ($script:RiskPatterns.TopCategories) {
            Write-Host "`n[TOP RISK CATEGORIES]" -ForegroundColor Cyan
            Write-Host "  $($script:RiskPatterns.TopCategories)" -ForegroundColor Gray
        }
        
        if ($script:RiskPatterns.TopCountries) {
            Write-Host "`n[TOP SOURCE COUNTRIES]" -ForegroundColor Cyan
            Write-Host "  $($script:RiskPatterns.TopCountries)" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
}

# Export results
function Export-Results {
    param(
        [string]$Path
    )
    
    if (-not $Path) {
        return
    }
    
    if ($script:RiskyUsers.Count -eq 0 -and $script:RiskySignIns.Count -eq 0) {
        Write-Host "`n[*] No results to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        $basePath = [System.IO.Path]::GetDirectoryName($Path)
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        
        # Export risky users
        if ($script:RiskyUsers.Count -gt 0) {
            $usersPath = if ($basePath) { Join-Path $basePath "$baseName-users$extension" } else { "$baseName-users$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:RiskyUsers | Export-Csv -Path $usersPath -NoTypeInformation -Encoding UTF8
                    Write-Host "`n[+] Risky users exported to CSV: $usersPath" -ForegroundColor Green
                }
                ".json" {
                    $script:RiskyUsers | ConvertTo-Json -Depth 10 | Out-File -FilePath $usersPath -Encoding UTF8
                    Write-Host "`n[+] Risky users exported to JSON: $usersPath" -ForegroundColor Green
                }
                default {
                    $csvPath = [System.IO.Path]::ChangeExtension($usersPath, ".csv")
                    $script:RiskyUsers | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                    Write-Host "`n[+] Risky users exported to CSV: $csvPath" -ForegroundColor Green
                }
            }
        }
        
        # Export risk detections
        if ($script:RiskySignIns.Count -gt 0) {
            $detectionsPath = if ($basePath) { Join-Path $basePath "$baseName-detections$extension" } else { "$baseName-detections$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:RiskySignIns | Export-Csv -Path $detectionsPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Risk detections exported to CSV: $detectionsPath" -ForegroundColor Green
                }
                ".json" {
                    $script:RiskySignIns | ConvertTo-Json -Depth 10 | Out-File -FilePath $detectionsPath -Encoding UTF8
                    Write-Host "[+] Risk detections exported to JSON: $detectionsPath" -ForegroundColor Green
                }
                default {
                    $csvPath = [System.IO.Path]::ChangeExtension($detectionsPath, ".csv")
                    $script:RiskySignIns | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Risk detections exported to CSV: $csvPath" -ForegroundColor Green
                }
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
        Start-SignInRiskScan
        
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
        
        Write-Host "`n[*] Sign-In Risk check completed successfully!" -ForegroundColor Green
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
