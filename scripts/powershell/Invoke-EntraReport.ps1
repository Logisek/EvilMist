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
    Generates consolidated HTML security reports from EvilMist security checks.

.DESCRIPTION
    This script runs multiple EvilMist security checks and generates a unified HTML
    executive dashboard report. It provides:
    - Consolidated findings from multiple security checks
    - Risk assessment and trending over time (if baseline exists)
    - Remediation priority matrix
    - Executive summary dashboard
    - Detailed findings by category
    
    The script authenticates once and runs selected checks, aggregating results
    into a professional HTML report suitable for executive presentations and
    security assessments.

.PARAMETER Checks
    Comma-separated list of checks to run or 'All' for all checks.
    Available checks: MFA, Roles, ConditionalAccess, Groups, Applications,
    ServicePrincipals, AttackPaths, Guests, StaleAccounts, Devices, SSPR,
    PasswordPolicy, LegacyAuth, AdminUnits, OAuthConsent, SignInRisk, PIM,
    KeyVault, StorageAccount, NetworkSecurity, ManagedIdentity, Exchange,
    SharePoint, Teams, AzureAttackPath

.PARAMETER ExportPath
    Path to export the HTML report. Defaults to EvilMist-Report-{timestamp}.html

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

.PARAMETER BaselinePath
    Path to a previous report JSON for trend comparison.

.PARAMETER IncludeDisabledUsers
    Include disabled user accounts in the results.

.PARAMETER QuickScan
    Run a quick scan with core checks only (MFA, Roles, ConditionalAccess, AttackPaths).

.PARAMETER ComprehensiveScan
    Run all available checks for a comprehensive security assessment.

.EXAMPLE
    .\Invoke-EntraReport.ps1 -Checks All -ExportPath "security-report.html"
    # Run all checks and generate HTML report

.EXAMPLE
    .\Invoke-EntraReport.ps1 -Checks MFA,Roles,ConditionalAccess -ExportPath "core-report.html"
    # Run specific checks only

.EXAMPLE
    .\Invoke-EntraReport.ps1 -QuickScan -ExportPath "quick-report.html"
    # Run quick scan with core security checks

.EXAMPLE
    .\Invoke-EntraReport.ps1 -ComprehensiveScan -BaselinePath "previous-report.json"
    # Run comprehensive scan with trend comparison

.EXAMPLE
    .\Invoke-EntraReport.ps1 -Checks MFA,Roles -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$Checks = "MFA,Roles,ConditionalAccess",

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
    [string]$BaselinePath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabledUsers,

    [Parameter(Mandatory = $false)]
    [switch]$QuickScan,

    [Parameter(Mandatory = $false)]
    [switch]$ComprehensiveScan
)

# PowerShell 7+ required
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] This script requires PowerShell 7 or later.' -ForegroundColor Red
    Write-Host ('Current version: PowerShell ' + $PSVersionTable.PSVersion.ToString()) -ForegroundColor Yellow
    Write-Host 'Download PowerShell 7: https://aka.ms/powershell-release?tag=stable' -ForegroundColor Cyan
    exit 1
}

$ErrorActionPreference = "Continue"

# Available security checks and their categories
$script:AvailableChecks = @{
    # Identity Security
    "MFA" = @{ Script = "Invoke-EntraMFACheck.ps1"; Category = "Identity Security"; Description = "Multi-Factor Authentication Check"; Priority = 1 }
    "Roles" = @{ Script = "Invoke-EntraRoleCheck.ps1"; Category = "Access Control"; Description = "Privileged Role Assignment Check"; Priority = 1 }
    "ConditionalAccess" = @{ Script = "Invoke-EntraConditionalAccessCheck.ps1"; Category = "Access Control"; Description = "Conditional Access Policy Check"; Priority = 1 }
    "AttackPaths" = @{ Script = "Invoke-EntraAttackPathCheck.ps1"; Category = "Attack Analysis"; Description = "Attack Path Analysis"; Priority = 1 }
    
    # Access Control
    "Groups" = @{ Script = "Invoke-EntraGroupCheck.ps1"; Category = "Access Control"; Description = "Group Security Check"; Priority = 2 }
    "Applications" = @{ Script = "Invoke-EntraApplicationCheck.ps1"; Category = "Access Control"; Description = "Application Registration Check"; Priority = 2 }
    "ServicePrincipals" = @{ Script = "Invoke-EntraServicePrincipalCheck.ps1"; Category = "Access Control"; Description = "Service Principal Check"; Priority = 2 }
    "AdminUnits" = @{ Script = "Invoke-EntraAdminUnitCheck.ps1"; Category = "Access Control"; Description = "Administrative Unit Check"; Priority = 2 }
    "AppAccess" = @{ Script = "Invoke-EntraAppAccess.ps1"; Category = "Access Control"; Description = "Critical Administrative Access Check"; Priority = 1 }
    
    # Identity Hygiene
    "Guests" = @{ Script = "Invoke-EntraGuestCheck.ps1"; Category = "Identity Hygiene"; Description = "Guest Account Check"; Priority = 2 }
    "StaleAccounts" = @{ Script = "Invoke-EntraStaleAccountCheck.ps1"; Category = "Identity Hygiene"; Description = "Stale Account Check"; Priority = 2 }
    "SSPR" = @{ Script = "Invoke-EntraSSPRCheck.ps1"; Category = "Identity Security"; Description = "Self-Service Password Reset Check"; Priority = 3 }
    "PasswordPolicy" = @{ Script = "Invoke-EntraPasswordPolicyCheck.ps1"; Category = "Identity Security"; Description = "Password Policy Check"; Priority = 3 }
    "LegacyAuth" = @{ Script = "Invoke-EntraLegacyAuthCheck.ps1"; Category = "Identity Security"; Description = "Legacy Authentication Check"; Priority = 2 }
    
    # Configuration
    "Devices" = @{ Script = "Invoke-EntraDeviceCheck.ps1"; Category = "Configuration"; Description = "Device Trust Check"; Priority = 3 }
    "DirectorySync" = @{ Script = "Invoke-EntraDirectorySyncCheck.ps1"; Category = "Configuration"; Description = "Directory Sync Check"; Priority = 3 }
    "Licenses" = @{ Script = "Invoke-EntraLicenseCheck.ps1"; Category = "Configuration"; Description = "License Analysis"; Priority = 4 }
    
    # Advanced Security Checks
    "OAuthConsent" = @{ Script = "Invoke-EntraOAuthConsentCheck.ps1"; Category = "Access Control"; Description = "OAuth Consent Grant Audit"; Priority = 1 }
    "SignInRisk" = @{ Script = "Invoke-EntraSignInRiskCheck.ps1"; Category = "Identity Security"; Description = "Sign-In Risk Analysis"; Priority = 2 }
    "PIM" = @{ Script = "Invoke-EntraPIMCheck.ps1"; Category = "Access Control"; Description = "Privileged Identity Management Check"; Priority = 1 }
    
    # Azure Infrastructure
    "KeyVault" = @{ Script = "Invoke-EntraKeyVaultCheck.ps1"; Category = "Azure Infrastructure"; Description = "Key Vault Security Audit"; Priority = 2 }
    "StorageAccount" = @{ Script = "Invoke-EntraStorageAccountCheck.ps1"; Category = "Azure Infrastructure"; Description = "Storage Account Security Audit"; Priority = 2 }
    "NetworkSecurity" = @{ Script = "Invoke-EntraNetworkSecurityCheck.ps1"; Category = "Azure Infrastructure"; Description = "Network Security Audit"; Priority = 2 }
    "ManagedIdentity" = @{ Script = "Invoke-EntraManagedIdentityCheck.ps1"; Category = "Azure Infrastructure"; Description = "Managed Identity Audit"; Priority = 2 }
    "AzureRBAC" = @{ Script = "Invoke-EntraAzureRBACCheck.ps1"; Category = "Azure Infrastructure"; Description = "Azure RBAC Check"; Priority = 2 }
    "AzureAttackPath" = @{ Script = "Invoke-EntraAzureAttackPathCheck.ps1"; Category = "Attack Analysis"; Description = "Azure Attack Path Analysis"; Priority = 1 }
    
    # Microsoft 365
    "Exchange" = @{ Script = "Invoke-EntraExchangeCheck.ps1"; Category = "Microsoft 365"; Description = "Exchange Online Security"; Priority = 2 }
    "SharePoint" = @{ Script = "Invoke-EntraSharePointCheck.ps1"; Category = "Microsoft 365"; Description = "SharePoint Online Security"; Priority = 2 }
    "Teams" = @{ Script = "Invoke-EntraTeamsCheck.ps1"; Category = "Microsoft 365"; Description = "Microsoft Teams Security"; Priority = 3 }
    "PowerPlatform" = @{ Script = "Invoke-EntraPowerPlatformCheck.ps1"; Category = "Microsoft 365"; Description = "Power Platform Audit"; Priority = 3 }
}

# Quick scan checks (core security)
$script:QuickScanChecks = @("MFA", "Roles", "ConditionalAccess", "AttackPaths", "OAuthConsent", "PIM")

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:ReportData = @{
    GeneratedAt = Get-Date
    TenantId = $null
    TenantName = $null
    ChecksRun = @()
    Findings = @{}
    Summary = @{
        Critical = 0
        High = 0
        Medium = 0
        Low = 0
        Info = 0
        TotalFindings = 0
    }
    Categories = @{}
    Baseline = $null
}
$script:StealthConfig = @{
    Enabled = $false
    BaseDelay = 0
    JitterRange = 0
    MaxRetries = 3
    QuietMode = $false
}

# Required scopes for consolidated report (union of all check scopes)
$script:RequiredScopes = @(
    "Directory.Read.All",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "RoleManagement.Read.Directory",
    "Policy.Read.All",
    "Application.Read.All",
    "Group.Read.All",
    "AuditLog.Read.All"
)

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
    Write-Host "    Security Report Generator - Consolidated Assessment" -ForegroundColor Yellow
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
        
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $scope = if ($isAdmin) { "AllUsers" } else { "CurrentUser" }
        
        foreach ($module in $missingModules) {
            Write-Host "[*] Installing $module (Scope: $scope)..." -ForegroundColor Cyan
            try {
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
        $loadedModules = Get-Module Microsoft.Graph.* 
        if ($loadedModules) {
            Write-Host "[*] Cleaning up loaded Graph modules..." -ForegroundColor Yellow
            $loadedModules | ForEach-Object {
                Remove-Module $_.Name -Force -ErrorAction SilentlyContinue
            }
        }
        
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
        $script:ReportData.TenantId = $context.TenantId
        
        # Get tenant name
        try {
            $org = Get-MgOrganization -ErrorAction SilentlyContinue
            $script:ReportData.TenantName = $org.DisplayName
        }
        catch {
            $script:ReportData.TenantName = $context.TenantId
        }
        
        Write-Host "[+] Connected to Microsoft Graph" -ForegroundColor Green
        Write-Host "[+] Tenant: $($context.TenantId)" -ForegroundColor Green
        Write-Host "[+] Account: $($context.Account)" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Host "[ERROR] Authentication failed: $_" -ForegroundColor Red
        return $false
    }
}

# Parse checks parameter
function Get-ChecksToRun {
    $checksToRun = @()
    
    if ($QuickScan) {
        $checksToRun = $script:QuickScanChecks
        Write-Host "[*] Quick scan mode: Running core security checks" -ForegroundColor Cyan
    }
    elseif ($ComprehensiveScan) {
        $checksToRun = $script:AvailableChecks.Keys
        Write-Host "[*] Comprehensive scan mode: Running all available checks" -ForegroundColor Cyan
    }
    else {
        if ($Checks -eq "All") {
            $checksToRun = $script:AvailableChecks.Keys
        }
        else {
            $checksToRun = $Checks -split ',' | ForEach-Object { $_.Trim() }
        }
    }
    
    # Validate checks
    $validChecks = @()
    foreach ($check in $checksToRun) {
        if ($script:AvailableChecks.ContainsKey($check)) {
            $validChecks += $check
        }
        else {
            Write-Host "[!] Unknown check: $check (skipping)" -ForegroundColor Yellow
        }
    }
    
    # Sort by priority
    $validChecks = $validChecks | Sort-Object { $script:AvailableChecks[$_].Priority }
    
    return $validChecks
}

# Run MFA Check inline
function Invoke-MFACheckInline {
    Write-Host "[*] Running MFA Check..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # Get all enabled users
        $properties = @('Id', 'DisplayName', 'UserPrincipalName', 'AccountEnabled', 'UserType', 'Department', 'JobTitle', 'CreatedDateTime', 'SignInActivity')
        $users = Get-MgUser -Filter "accountEnabled eq true" -All -Property $properties -ErrorAction Stop
        
        $usersWithoutMFA = 0
        $totalUsers = $users.Count
        
        foreach ($user in $users) {
            Invoke-StealthDelay
            
            try {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                
                $hasMFA = $false
                $methods = @()
                
                foreach ($method in $authMethods) {
                    $methodType = $method.AdditionalProperties.'@odata.type'
                    switch ($methodType) {
                        '#microsoft.graph.phoneAuthenticationMethod' { $hasMFA = $true; $methods += "Phone" }
                        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { $hasMFA = $true; $methods += "Authenticator" }
                        '#microsoft.graph.fido2AuthenticationMethod' { $hasMFA = $true; $methods += "FIDO2" }
                        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' { $hasMFA = $true; $methods += "Windows Hello" }
                        '#microsoft.graph.softwareOathAuthenticationMethod' { $hasMFA = $true; $methods += "Software Token" }
                    }
                }
                
                if (-not $hasMFA) {
                    $usersWithoutMFA++
                    $riskLevel = if ($user.UserType -eq "Member") { "HIGH" } else { "MEDIUM" }
                    
                    $findings += [PSCustomObject]@{
                        Type = "UserWithoutMFA"
                        RiskLevel = $riskLevel
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        UserType = $user.UserType
                        Department = $user.Department
                        JobTitle = $user.JobTitle
                        AuthMethods = ($methods -join ", ")
                        Description = "User does not have MFA enabled"
                        Remediation = "Enable MFA for this user using security defaults or Conditional Access"
                    }
                }
            }
            catch {
                # Skip users where we can't check auth methods
            }
        }
        
        Write-Host "[+] MFA Check: Found $usersWithoutMFA users without MFA out of $totalUsers total" -ForegroundColor $(if ($usersWithoutMFA -gt 0) { "Yellow" } else { "Green" })
    }
    catch {
        Write-Host "[!] Error running MFA check: $_" -ForegroundColor Yellow
    }
    
    return $findings
}

# Run Role Check inline
function Invoke-RoleCheckInline {
    Write-Host "[*] Running Privileged Role Check..." -ForegroundColor Cyan
    
    $findings = @()
    
    # Role risk levels
    $roleRiskLevels = @{
        "Global Administrator" = "CRITICAL"
        "Privileged Role Administrator" = "CRITICAL"
        "Privileged Authentication Administrator" = "CRITICAL"
        "Exchange Administrator" = "HIGH"
        "SharePoint Administrator" = "HIGH"
        "Security Administrator" = "HIGH"
        "Application Administrator" = "HIGH"
        "Cloud Application Administrator" = "HIGH"
        "User Administrator" = "MEDIUM"
        "Helpdesk Administrator" = "MEDIUM"
    }
    
    try {
        $roles = Get-MgDirectoryRole -All -ErrorAction Stop
        
        foreach ($role in $roles) {
            Invoke-StealthDelay
            
            try {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
                
                $userMembers = $members | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' }
                
                foreach ($member in $userMembers) {
                    $riskLevel = if ($roleRiskLevels.ContainsKey($role.DisplayName)) { $roleRiskLevels[$role.DisplayName] } else { "MEDIUM" }
                    
                    # Check MFA for privileged users
                    $hasMFA = $false
                    try {
                        $authMethods = Get-MgUserAuthenticationMethod -UserId $member.Id -ErrorAction SilentlyContinue
                        foreach ($method in $authMethods) {
                            $methodType = $method.AdditionalProperties.'@odata.type'
                            if ($methodType -in @('#microsoft.graph.phoneAuthenticationMethod', '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod', '#microsoft.graph.fido2AuthenticationMethod')) {
                                $hasMFA = $true
                                break
                            }
                        }
                    }
                    catch { }
                    
                    # Elevate risk if no MFA
                    if (-not $hasMFA -and $riskLevel -eq "HIGH") { $riskLevel = "CRITICAL" }
                    if (-not $hasMFA -and $riskLevel -eq "MEDIUM") { $riskLevel = "HIGH" }
                    
                    $findings += [PSCustomObject]@{
                        Type = "PrivilegedRoleAssignment"
                        RiskLevel = $riskLevel
                        UserPrincipalName = $member.AdditionalProperties.userPrincipalName
                        DisplayName = $member.AdditionalProperties.displayName
                        RoleName = $role.DisplayName
                        HasMFA = $hasMFA
                        AssignmentType = "Active"
                        Description = "User has $($role.DisplayName) role" + $(if (-not $hasMFA) { " without MFA" } else { "" })
                        Remediation = if (-not $hasMFA) { "Enable MFA for this privileged user immediately" } else { "Consider implementing PIM for Just-In-Time access" }
                    }
                }
            }
            catch { }
        }
        
        Write-Host "[+] Role Check: Found $($findings.Count) privileged role assignments" -ForegroundColor $(if ($findings.Count -gt 0) { "Yellow" } else { "Green" })
    }
    catch {
        Write-Host "[!] Error running role check: $_" -ForegroundColor Yellow
    }
    
    return $findings
}

# Run Conditional Access Check inline
function Invoke-ConditionalAccessCheckInline {
    Write-Host "[*] Running Conditional Access Check..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        
        $enabledPolicies = $policies | Where-Object { $_.State -eq 'enabled' }
        $disabledPolicies = $policies | Where-Object { $_.State -ne 'enabled' }
        
        # Check for policies with exclusions
        foreach ($policy in $enabledPolicies) {
            Invoke-StealthDelay
            
            $hasUserExclusions = ($policy.Conditions.Users.ExcludeUsers.Count -gt 0) -or 
                                  ($policy.Conditions.Users.ExcludeGroups.Count -gt 0) -or
                                  ($policy.Conditions.Users.ExcludeRoles.Count -gt 0)
            
            $hasMFARequirement = $policy.GrantControls.BuiltInControls -contains 'mfa'
            
            if ($hasUserExclusions) {
                $excludedCount = $policy.Conditions.Users.ExcludeUsers.Count + 
                                 $policy.Conditions.Users.ExcludeGroups.Count + 
                                 $policy.Conditions.Users.ExcludeRoles.Count
                
                $findings += [PSCustomObject]@{
                    Type = "CAExclusion"
                    RiskLevel = if ($hasMFARequirement) { "HIGH" } else { "MEDIUM" }
                    PolicyName = $policy.DisplayName
                    PolicyId = $policy.Id
                    PolicyState = $policy.State
                    ExcludedUsers = $policy.Conditions.Users.ExcludeUsers.Count
                    ExcludedGroups = $policy.Conditions.Users.ExcludeGroups.Count
                    ExcludedRoles = $policy.Conditions.Users.ExcludeRoles.Count
                    RequiresMFA = $hasMFARequirement
                    Description = "Policy has $excludedCount exclusion(s)"
                    Remediation = "Review and minimize exclusions, especially for MFA-requiring policies"
                }
            }
        }
        
        # Check for missing MFA policies
        $mfaPolicies = $enabledPolicies | Where-Object { $_.GrantControls.BuiltInControls -contains 'mfa' }
        if ($mfaPolicies.Count -eq 0) {
            $findings += [PSCustomObject]@{
                Type = "NoMFAPolicy"
                RiskLevel = "CRITICAL"
                PolicyName = "N/A"
                PolicyId = "N/A"
                Description = "No Conditional Access policy requires MFA"
                Remediation = "Create a Conditional Access policy requiring MFA for all users"
            }
        }
        
        Write-Host "[+] CA Check: Found $($enabledPolicies.Count) enabled policies, $($findings.Count) findings" -ForegroundColor $(if ($findings.Count -gt 0) { "Yellow" } else { "Green" })
    }
    catch {
        Write-Host "[!] Error running CA check: $_" -ForegroundColor Yellow
    }
    
    return $findings
}

# Run Attack Path Check inline  
function Invoke-AttackPathCheckInline {
    Write-Host "[*] Running Attack Path Check..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        # Check for groups that can be used for privilege escalation
        $adminGroups = @("Global Administrators", "Privileged Role Administrators", "User Administrators")
        
        foreach ($groupName in $adminGroups) {
            Invoke-StealthDelay
            
            try {
                $groups = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
                
                foreach ($group in $groups) {
                    # Check if group has dynamic membership
                    if ($group.GroupTypes -contains "DynamicMembership") {
                        $findings += [PSCustomObject]@{
                            Type = "DynamicAdminGroup"
                            RiskLevel = "HIGH"
                            GroupName = $group.DisplayName
                            GroupId = $group.Id
                            Description = "Privileged group uses dynamic membership - could be exploited"
                            Remediation = "Review dynamic membership rules carefully or convert to static membership"
                        }
                    }
                    
                    # Check owners of privileged groups
                    $owners = Get-MgGroupOwner -GroupId $group.Id -All -ErrorAction SilentlyContinue
                    if ($owners.Count -gt 0) {
                        foreach ($owner in $owners) {
                            $findings += [PSCustomObject]@{
                                Type = "GroupOwnerPath"
                                RiskLevel = "MEDIUM"
                                GroupName = $group.DisplayName
                                GroupId = $group.Id
                                OwnerName = $owner.AdditionalProperties.displayName
                                OwnerId = $owner.Id
                                Description = "User can add members to privileged group"
                                Remediation = "Review if group ownership is necessary and restrict if possible"
                            }
                        }
                    }
                }
            }
            catch { }
        }
        
        Write-Host "[+] Attack Path Check: Found $($findings.Count) potential attack paths" -ForegroundColor $(if ($findings.Count -gt 0) { "Yellow" } else { "Green" })
    }
    catch {
        Write-Host "[!] Error running attack path check: $_" -ForegroundColor Yellow
    }
    
    return $findings
}

# Run Guest Check inline
function Invoke-GuestCheckInline {
    Write-Host "[*] Running Guest Account Check..." -ForegroundColor Cyan
    
    $findings = @()
    
    try {
        $guests = Get-MgUser -Filter "userType eq 'Guest'" -All -Property 'Id','DisplayName','UserPrincipalName','AccountEnabled','CreatedDateTime','SignInActivity' -ErrorAction Stop
        
        foreach ($guest in $guests) {
            Invoke-StealthDelay
            
            $createdDays = if ($guest.CreatedDateTime) { ([DateTime]::Now - [DateTime]$guest.CreatedDateTime).Days } else { -1 }
            $lastSignIn = $guest.SignInActivity.LastSignInDateTime
            $daysSinceSignIn = if ($lastSignIn) { ([DateTime]::Now - [DateTime]$lastSignIn).Days } else { -1 }
            
            $riskLevel = "LOW"
            $description = "Guest account"
            
            # Stale guest
            if ($daysSinceSignIn -gt 90 -or $daysSinceSignIn -eq -1) {
                $riskLevel = "MEDIUM"
                $description = "Stale guest account (no sign-in in 90+ days or never)"
            }
            
            # Check if guest has any roles
            try {
                $memberOf = Get-MgUserMemberOf -UserId $guest.Id -ErrorAction SilentlyContinue
                $hasRoles = $memberOf | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' }
                if ($hasRoles.Count -gt 0) {
                    $riskLevel = "HIGH"
                    $description = "Guest with privileged role assignments"
                }
            }
            catch { }
            
            if ($riskLevel -ne "LOW") {
                $findings += [PSCustomObject]@{
                    Type = "GuestAccount"
                    RiskLevel = $riskLevel
                    UserPrincipalName = $guest.UserPrincipalName
                    DisplayName = $guest.DisplayName
                    AccountEnabled = $guest.AccountEnabled
                    CreatedDaysAgo = $createdDays
                    DaysSinceSignIn = $daysSinceSignIn
                    Description = $description
                    Remediation = "Review guest access and remove if no longer needed"
                }
            }
        }
        
        Write-Host "[+] Guest Check: Found $($guests.Count) guests, $($findings.Count) require attention" -ForegroundColor $(if ($findings.Count -gt 0) { "Yellow" } else { "Green" })
    }
    catch {
        Write-Host "[!] Error running guest check: $_" -ForegroundColor Yellow
    }
    
    return $findings
}

# Run a security check and collect findings
function Invoke-SecurityCheck {
    param(
        [string]$CheckName
    )
    
    $findings = @()
    
    switch ($CheckName) {
        "MFA" { $findings = Invoke-MFACheckInline }
        "Roles" { $findings = Invoke-RoleCheckInline }
        "ConditionalAccess" { $findings = Invoke-ConditionalAccessCheckInline }
        "AttackPaths" { $findings = Invoke-AttackPathCheckInline }
        "Guests" { $findings = Invoke-GuestCheckInline }
        default {
            # For other checks, try to run the external script
            $checkInfo = $script:AvailableChecks[$CheckName]
            if ($checkInfo) {
                Write-Host "[*] Running $CheckName check (external script)..." -ForegroundColor Cyan
                # External scripts would be called here if needed
                # For now, mark as not implemented
                Write-Host "[!] ${CheckName}: External script execution not implemented in report mode" -ForegroundColor Yellow
            }
        }
    }
    
    return $findings
}

# Load baseline for comparison
function Import-Baseline {
    param(
        [string]$Path
    )
    
    if (-not $Path -or -not (Test-Path $Path)) {
        return $null
    }
    
    try {
        $baseline = Get-Content $Path -Raw | ConvertFrom-Json
        Write-Host "[+] Loaded baseline from: $Path" -ForegroundColor Green
        return $baseline
    }
    catch {
        Write-Host "[!] Failed to load baseline: $_" -ForegroundColor Yellow
        return $null
    }
}

# Generate HTML Report
function New-HTMLReport {
    param(
        [hashtable]$ReportData,
        [string]$OutputPath
    )
    
    # Count findings by severity
    $criticalCount = 0
    $highCount = 0
    $mediumCount = 0
    $lowCount = 0
    
    foreach ($category in $ReportData.Findings.Keys) {
        foreach ($finding in $ReportData.Findings[$category]) {
            switch ($finding.RiskLevel) {
                "CRITICAL" { $criticalCount++ }
                "HIGH" { $highCount++ }
                "MEDIUM" { $mediumCount++ }
                "LOW" { $lowCount++ }
            }
        }
    }
    
    $totalFindings = $criticalCount + $highCount + $mediumCount + $lowCount
    
    # Calculate security score (simple algorithm)
    $maxScore = 100
    $deductions = ($criticalCount * 10) + ($highCount * 5) + ($mediumCount * 2) + ($lowCount * 0.5)
    $securityScore = [math]::Max(0, [math]::Round($maxScore - $deductions))
    
    $scoreColor = if ($securityScore -ge 80) { "#28a745" } elseif ($securityScore -ge 60) { "#ffc107" } elseif ($securityScore -ge 40) { "#fd7e14" } else { "#dc3545" }
    $scoreLabel = if ($securityScore -ge 80) { "Good" } elseif ($securityScore -ge 60) { "Fair" } elseif ($securityScore -ge 40) { "Needs Improvement" } else { "Critical" }
    
    # Generate findings HTML by category
    $findingsHTML = ""
    
    foreach ($category in ($ReportData.Findings.Keys | Sort-Object)) {
        $categoryFindings = $ReportData.Findings[$category]
        if ($categoryFindings.Count -eq 0) { continue }
        
        $findingsHTML += @"
        <div class="category-section">
            <h3 class="category-title">$category</h3>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Risk</th>
                        <th>Type</th>
                        <th>Details</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($finding in ($categoryFindings | Sort-Object { 
            switch ($_.RiskLevel) { "CRITICAL" { 0 } "HIGH" { 1 } "MEDIUM" { 2 } "LOW" { 3 } default { 4 } }
        })) {
            $riskClass = switch ($finding.RiskLevel) {
                "CRITICAL" { "risk-critical" }
                "HIGH" { "risk-high" }
                "MEDIUM" { "risk-medium" }
                "LOW" { "risk-low" }
                default { "risk-info" }
            }
            
            $details = if ($finding.UserPrincipalName) { 
                "$($finding.Description)<br><strong>User:</strong> $($finding.UserPrincipalName)" 
            }
            elseif ($finding.PolicyName) {
                "$($finding.Description)<br><strong>Policy:</strong> $($finding.PolicyName)"
            }
            elseif ($finding.GroupName) {
                "$($finding.Description)<br><strong>Group:</strong> $($finding.GroupName)"
            }
            else { 
                $finding.Description 
            }
            
            $findingsHTML += @"
                    <tr>
                        <td><span class="risk-badge $riskClass">$($finding.RiskLevel)</span></td>
                        <td>$($finding.Type)</td>
                        <td>$details</td>
                        <td>$($finding.Remediation)</td>
                    </tr>
"@
        }
        
        $findingsHTML += @"
                </tbody>
            </table>
        </div>
"@
    }
    
    # Trend comparison if baseline exists
    $trendHTML = ""
    if ($ReportData.Baseline) {
        $baselineCritical = 0
        $baselineHigh = 0
        $baselineMedium = 0
        $baselineLow = 0
        
        foreach ($category in $ReportData.Baseline.Findings.Keys) {
            foreach ($finding in $ReportData.Baseline.Findings[$category]) {
                switch ($finding.RiskLevel) {
                    "CRITICAL" { $baselineCritical++ }
                    "HIGH" { $baselineHigh++ }
                    "MEDIUM" { $baselineMedium++ }
                    "LOW" { $baselineLow++ }
                }
            }
        }
        
        $criticalChange = $criticalCount - $baselineCritical
        $highChange = $highCount - $baselineHigh
        $mediumChange = $mediumCount - $baselineMedium
        $lowChange = $lowCount - $baselineLow
        
        $trendHTML = @"
        <div class="section">
            <h2>Trend Analysis</h2>
            <p>Comparison with baseline from $($ReportData.Baseline.GeneratedAt)</p>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-label">Critical Change</div>
                    <div class="stat-value" style="color: $(if ($criticalChange -le 0) { '#28a745' } else { '#dc3545' })">$(if ($criticalChange -gt 0) { '+' })$criticalChange</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">High Change</div>
                    <div class="stat-value" style="color: $(if ($highChange -le 0) { '#28a745' } else { '#fd7e14' })">$(if ($highChange -gt 0) { '+' })$highChange</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Medium Change</div>
                    <div class="stat-value" style="color: $(if ($mediumChange -le 0) { '#28a745' } else { '#ffc107' })">$(if ($mediumChange -gt 0) { '+' })$mediumChange</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Low Change</div>
                    <div class="stat-value" style="color: $(if ($lowChange -le 0) { '#28a745' } else { '#6c757d' })">$(if ($lowChange -gt 0) { '+' })$lowChange</div>
                </div>
            </div>
        </div>
"@
    }
    
    # Generate remediation priority matrix
    $priorityHTML = @"
        <div class="section">
            <h2>Remediation Priority Matrix</h2>
            <table class="priority-table">
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Risk Level</th>
                        <th>Count</th>
                        <th>Action Required</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="priority-badge priority-1">P1</span></td>
                        <td><span class="risk-badge risk-critical">CRITICAL</span></td>
                        <td>$criticalCount</td>
                        <td>Immediate action required - address within 24 hours</td>
                    </tr>
                    <tr>
                        <td><span class="priority-badge priority-2">P2</span></td>
                        <td><span class="risk-badge risk-high">HIGH</span></td>
                        <td>$highCount</td>
                        <td>High priority - address within 1 week</td>
                    </tr>
                    <tr>
                        <td><span class="priority-badge priority-3">P3</span></td>
                        <td><span class="risk-badge risk-medium">MEDIUM</span></td>
                        <td>$mediumCount</td>
                        <td>Medium priority - address within 1 month</td>
                    </tr>
                    <tr>
                        <td><span class="priority-badge priority-4">P4</span></td>
                        <td><span class="risk-badge risk-low">LOW</span></td>
                        <td>$lowCount</td>
                        <td>Low priority - address during regular maintenance</td>
                    </tr>
                </tbody>
            </table>
        </div>
"@
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EvilMist Security Report - $($ReportData.TenantName)</title>
    <style>
        :root {
            --primary-color: #6f42c1;
            --secondary-color: #563d7c;
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-color: #212529;
            --border-color: #dee2e6;
            --critical-color: #dc3545;
            --high-color: #fd7e14;
            --medium-color: #ffc107;
            --low-color: #6c757d;
            --success-color: #28a745;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        header .subtitle {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .meta-info {
            display: flex;
            gap: 30px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .meta-item {
            background: rgba(255, 255, 255, 0.1);
            padding: 10px 20px;
            border-radius: 5px;
        }
        
        .meta-label {
            font-size: 0.85em;
            opacity: 0.8;
        }
        
        .meta-value {
            font-weight: 600;
            font-size: 1.1em;
        }
        
        .section {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        
        .section h2 {
            color: var(--primary-color);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }
        
        .score-card {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        
        .score-circle {
            width: 180px;
            height: 180px;
            border-radius: 50%;
            background: conic-gradient($scoreColor 0deg, $scoreColor calc(3.6deg * $securityScore), #e9ecef calc(3.6deg * $securityScore));
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            position: relative;
        }
        
        .score-circle::before {
            content: '';
            width: 140px;
            height: 140px;
            background: white;
            border-radius: 50%;
            position: absolute;
        }
        
        .score-value {
            position: relative;
            z-index: 1;
            font-size: 3em;
            font-weight: bold;
            color: $scoreColor;
        }
        
        .score-label {
            font-size: 1.3em;
            color: $scoreColor;
            font-weight: 600;
        }
        
        .score-subtitle {
            color: var(--low-color);
            margin-top: 5px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }
        
        .stat-box {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            border-left: 4px solid var(--primary-color);
        }
        
        .stat-box.critical { border-left-color: var(--critical-color); }
        .stat-box.high { border-left-color: var(--high-color); }
        .stat-box.medium { border-left-color: var(--medium-color); }
        .stat-box.low { border-left-color: var(--low-color); }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: var(--low-color);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .findings-table, .priority-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        .findings-table th, .findings-table td,
        .priority-table th, .priority-table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        .findings-table th, .priority-table th {
            background: var(--bg-color);
            font-weight: 600;
            color: var(--primary-color);
        }
        
        .findings-table tr:hover, .priority-table tr:hover {
            background: var(--bg-color);
        }
        
        .risk-badge, .priority-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .risk-critical { background: var(--critical-color); color: white; }
        .risk-high { background: var(--high-color); color: white; }
        .risk-medium { background: var(--medium-color); color: #212529; }
        .risk-low { background: var(--low-color); color: white; }
        .risk-info { background: #17a2b8; color: white; }
        
        .priority-1 { background: var(--critical-color); color: white; }
        .priority-2 { background: var(--high-color); color: white; }
        .priority-3 { background: var(--medium-color); color: #212529; }
        .priority-4 { background: var(--low-color); color: white; }
        
        .category-section {
            margin-bottom: 30px;
        }
        
        .category-title {
            color: var(--secondary-color);
            margin-bottom: 15px;
            padding-left: 10px;
            border-left: 4px solid var(--primary-color);
        }
        
        footer {
            text-align: center;
            padding: 30px;
            color: var(--low-color);
            font-size: 0.9em;
        }
        
        footer a {
            color: var(--primary-color);
            text-decoration: none;
        }
        
        @media (max-width: 900px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .meta-info {
                flex-direction: column;
                gap: 10px;
            }
        }
        
        @media print {
            body { background: white; }
            .section { box-shadow: none; border: 1px solid var(--border-color); }
            header { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>EvilMist Security Report</h1>
            <p class="subtitle">Comprehensive Entra ID Security Assessment</p>
            <div class="meta-info">
                <div class="meta-item">
                    <div class="meta-label">Tenant</div>
                    <div class="meta-value">$($ReportData.TenantName)</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Tenant ID</div>
                    <div class="meta-value">$($ReportData.TenantId)</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Report Generated</div>
                    <div class="meta-value">$($ReportData.GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss'))</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Checks Performed</div>
                    <div class="meta-value">$($ReportData.ChecksRun.Count)</div>
                </div>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="score-card">
                <div class="score-circle">
                    <span class="score-value">$securityScore</span>
                </div>
                <div class="score-label">$scoreLabel</div>
                <div class="score-subtitle">Security Score</div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-box critical">
                    <div class="stat-value" style="color: var(--critical-color);">$criticalCount</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-box high">
                    <div class="stat-value" style="color: var(--high-color);">$highCount</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-box medium">
                    <div class="stat-value" style="color: var(--medium-color);">$mediumCount</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-box low">
                    <div class="stat-value" style="color: var(--low-color);">$lowCount</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value" style="color: var(--primary-color);">$totalFindings</div>
                    <div class="stat-label">Total Findings</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>This security assessment was performed on <strong>$($ReportData.TenantName)</strong> using the EvilMist Security Toolkit. 
            The assessment evaluated <strong>$($ReportData.ChecksRun.Count)</strong> security domains and identified 
            <strong>$totalFindings</strong> findings requiring attention.</p>
            
            <p style="margin-top: 15px;">
                <strong>Key Statistics:</strong>
            </p>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li><strong>$criticalCount</strong> critical findings requiring immediate attention</li>
                <li><strong>$highCount</strong> high-risk findings to address within one week</li>
                <li><strong>$mediumCount</strong> medium-risk findings for scheduled remediation</li>
                <li><strong>$lowCount</strong> low-risk findings for regular maintenance</li>
            </ul>
            
            <p style="margin-top: 15px;">
                <strong>Checks Performed:</strong> $($ReportData.ChecksRun -join ", ")
            </p>
        </div>
        
        $trendHTML
        
        $priorityHTML
        
        <div class="section">
            <h2>Detailed Findings</h2>
            $findingsHTML
        </div>
        
        <footer>
            <p>Generated by <a href="https://github.com/Logisek/EvilMist">EvilMist Security Toolkit</a></p>
            <p>https://logisek.com | info@logisek.com</p>
        </footer>
    </div>
</body>
</html>
"@
    
    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Host "[+] HTML report saved to: $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to save HTML report: $_" -ForegroundColor Red
        return $false
    }
}

# Export report data as JSON (for baseline comparison)
function Export-ReportJSON {
    param(
        [hashtable]$ReportData,
        [string]$OutputPath
    )
    
    $jsonPath = [System.IO.Path]::ChangeExtension($OutputPath, ".json")
    
    try {
        $ReportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
        Write-Host "[+] JSON data saved to: $jsonPath (can be used as baseline)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[!] Failed to save JSON data: $_" -ForegroundColor Yellow
        return $false
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
        
        # Set default export path
        if (-not $ExportPath) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $ExportPath = "EvilMist-Report-$timestamp.html"
        }
        
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
        
        # Parse checks to run
        $checksToRun = Get-ChecksToRun
        
        if ($checksToRun.Count -eq 0) {
            Write-Host "[ERROR] No valid checks specified. Use -Checks parameter or -QuickScan/-ComprehensiveScan" -ForegroundColor Red
            exit 1
        }
        
        Write-Host "`n[*] Running $($checksToRun.Count) security check(s)..." -ForegroundColor Cyan
        Write-Host "[*] Checks: $($checksToRun -join ', ')" -ForegroundColor Cyan
        
        # Load baseline if provided
        if ($BaselinePath) {
            $script:ReportData.Baseline = Import-Baseline -Path $BaselinePath
        }
        
        # Run each check
        foreach ($checkName in $checksToRun) {
            $checkInfo = $script:AvailableChecks[$checkName]
            $category = $checkInfo.Category
            
            Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
            Write-Host "[$checkName] $($checkInfo.Description)" -ForegroundColor Cyan
            Write-Host ("=" * 60) -ForegroundColor Cyan
            
            $findings = Invoke-SecurityCheck -CheckName $checkName
            
            if (-not $script:ReportData.Findings.ContainsKey($category)) {
                $script:ReportData.Findings[$category] = @()
            }
            
            $script:ReportData.Findings[$category] += $findings
            $script:ReportData.ChecksRun += $checkName
            
            # Update summary
            foreach ($finding in $findings) {
                switch ($finding.RiskLevel) {
                    "CRITICAL" { $script:ReportData.Summary.Critical++ }
                    "HIGH" { $script:ReportData.Summary.High++ }
                    "MEDIUM" { $script:ReportData.Summary.Medium++ }
                    "LOW" { $script:ReportData.Summary.Low++ }
                    default { $script:ReportData.Summary.Info++ }
                }
                $script:ReportData.Summary.TotalFindings++
            }
        }
        
        # Generate report
        Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
        Write-Host "GENERATING REPORT" -ForegroundColor Cyan
        Write-Host ("=" * 60) -ForegroundColor Cyan
        
        $script:ReportData.GeneratedAt = Get-Date
        
        New-HTMLReport -ReportData $script:ReportData -OutputPath $ExportPath
        Export-ReportJSON -ReportData $script:ReportData -OutputPath $ExportPath
        
        # Display summary
        Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
        Write-Host "ASSESSMENT SUMMARY" -ForegroundColor Cyan
        Write-Host ("=" * 60) -ForegroundColor Cyan
        
        Write-Host "`nTenant: $($script:ReportData.TenantName)" -ForegroundColor White
        Write-Host "Checks Run: $($script:ReportData.ChecksRun.Count)" -ForegroundColor White
        Write-Host "Total Findings: $($script:ReportData.Summary.TotalFindings)" -ForegroundColor White
        
        Write-Host "`n  CRITICAL: " -NoNewline -ForegroundColor White
        Write-Host $script:ReportData.Summary.Critical -ForegroundColor Red
        Write-Host "  HIGH: " -NoNewline -ForegroundColor White
        Write-Host $script:ReportData.Summary.High -ForegroundColor Yellow
        Write-Host "  MEDIUM: " -NoNewline -ForegroundColor White
        Write-Host $script:ReportData.Summary.Medium -ForegroundColor DarkYellow
        Write-Host "  LOW: " -NoNewline -ForegroundColor White
        Write-Host $script:ReportData.Summary.Low -ForegroundColor Gray
        
        Write-Host "`n[+] Report generated: $ExportPath" -ForegroundColor Green
        Write-Host "[*] Security report generation completed successfully!" -ForegroundColor Green
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
