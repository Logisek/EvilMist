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
    Enumerates Azure Entra ID users with access to PowerShell and Graph Command Line Tools.

.DESCRIPTION
    This script queries Azure Entra ID to identify users who have access to 
    PowerShell enterprise applications and Microsoft Graph Command Line Tools.
    It provides comprehensive information about user assignments including 
    MFA status, last sign-in activity, and assigned roles.
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Applications checked:
    - Azure Active Directory PowerShell
    - Microsoft Azure PowerShell
    - Microsoft Graph Command Line Tools
    - Graph Explorer
    - Azure CLI
    - Microsoft 365 Admin Portal
    - Azure Portal
    - Office 365 Exchange Online
    - Office 365 SharePoint Online
    - MS-PIM (Privileged Identity Management)
    
    Information collected includes:
    - User identification and authentication details
    - MFA registration and authentication methods
    - Last sign-in date and activity patterns
    - App role assignments and permissions
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

.PARAMETER IncludeDisabledUsers
    Include disabled user accounts in the results.

.PARAMETER OnlyNoMFA
    Show only users without MFA enabled.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraAppAccess.ps1
    # Query all users with PowerShell/Graph CLI access

.EXAMPLE
    .\Invoke-EntraAppAccess.ps1 -ExportPath "app-access.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraAppAccess.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraAppAccess.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraAppAccess.ps1 -OnlyNoMFA -Matrix
    # Display only users without MFA in matrix format

.EXAMPLE
    .\Invoke-EntraAppAccess.ps1 -Matrix -ExportPath "results.csv"
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

# Target PowerShell, API tools, and critical administrative applications
$script:TargetApps = @{
    # Development & API Tools
    "Azure AD PowerShell" = "1b730954-1685-4b74-9bfd-dac224a7b894"
    "Azure PowerShell" = "1950a258-227b-4e31-a9cf-717495945fc2"
    "Graph Command Line Tools" = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
    "Graph Explorer" = "de8bc8b5-d9f9-48b1-a8ad-b748da725064"
    "Azure CLI" = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    
    # Administrative Portals
    "Microsoft 365 Admin Portal" = "618dd325-23f6-4b6f-8380-4df78026e39b"
    "Azure Portal" = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
    
    # Core Microsoft 365 Services
    "Office 365 Exchange Online" = "00000002-0000-0ff1-ce00-000000000000"
    "Office 365 SharePoint Online" = "00000003-0000-0ff1-ce00-000000000000"
    
    # Security & Identity Management
    "MS-PIM" = "01fc33a7-78ba-4d2f-a4b7-768e336e890e"
}

# Required scopes for app access checking
$script:RequiredScopes = @(
    "Application.Read.All",
    "Directory.Read.All",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "AuditLog.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Application.Read.All",
    "Directory.Read.All",
    "User.ReadBasic.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:UsersWithAccess = @()
$script:ServicePrincipals = @{}
$script:TotalUsersScanned = 0
$script:DefaultAccessApps = @()
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
    Write-Host "    Entra ID App Access Check - Critical Administrative Access Audit" -ForegroundColor Yellow
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
        "Microsoft.Graph.Applications",
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
        
        Write-Host "[*] Importing Microsoft.Graph.Applications..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Applications -Force -ErrorAction Stop
        
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

# Get service principals for target applications
function Get-TargetServicePrincipals {
    Write-Host "`n[*] Locating target enterprise applications..." -ForegroundColor Cyan
    
    foreach ($appName in $script:TargetApps.Keys) {
        $appId = $script:TargetApps[$appName]
        
        try {
            Invoke-StealthDelay
            
            Write-Host "[*] Searching for: $appName (AppId: $appId)" -ForegroundColor Cyan
            $sp = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction Stop
            
            if ($sp) {
                $script:ServicePrincipals[$appName] = $sp
                Write-Host "[+] Found: $appName (Object ID: $($sp.Id))" -ForegroundColor Green
            }
            else {
                Write-Host "[!] Not found in tenant: $appName" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "[!] Error searching for $appName : $_" -ForegroundColor Yellow
        }
    }
    
    if ($script:ServicePrincipals.Count -eq 0) {
        Write-Host "[!] No target applications found in this tenant" -ForegroundColor Yellow
        return $false
    }
    
    Write-Host "[+] Found $($script:ServicePrincipals.Count) target application(s)" -ForegroundColor Green
    return $true
}

# Check if service principal requires user assignment
function Test-AppAssignmentRequired {
    param(
        [Parameter(Mandatory = $true)]
        $ServicePrincipal
    )
    
    try {
        # Check if AppRoleAssignmentRequired is set
        # If false or not set, all users have default access
        $assignmentRequired = $ServicePrincipal.AppRoleAssignmentRequired
        
        return $assignmentRequired
    }
    catch {
        # Default to checking assignments if we can't determine
        return $true
    }
}

# Get users with access to a service principal (explicit assignments only)
function Get-ServicePrincipalUsers {
    param(
        [Parameter(Mandatory = $true)]
        $ServicePrincipal,
        
        [Parameter(Mandatory = $true)]
        [string]$AppName
    )
    
    try {
        Invoke-StealthDelay
        
        # Check if user assignment is required
        $assignmentRequired = Test-AppAssignmentRequired -ServicePrincipal $ServicePrincipal
        
        Write-Host "[*] Retrieving user assignments for: $AppName" -ForegroundColor Cyan
        
        if (-not $assignmentRequired) {
            Write-Host "    [!] WARNING: Assignment NOT required - ALL tenant users have default access" -ForegroundColor Yellow
            Write-Host "    [*] Showing only users with explicit assignments (administrative/elevated access)" -ForegroundColor Yellow
        }
        
        # Get app role assignments (users explicitly assigned to the app)
        $assignments = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $ServicePrincipal.Id -All -ErrorAction Stop
        
        # Filter for user principals (not groups or service principals)
        $userAssignments = $assignments | Where-Object { $_.PrincipalType -eq "User" }
        
        if ($userAssignments.Count -eq 0 -and -not $assignmentRequired) {
            Write-Host "[!] No explicit assignments found (but all users have default access)" -ForegroundColor Yellow
        }
        elseif ($userAssignments.Count -eq 0) {
            Write-Host "[!] No user assignments found" -ForegroundColor Yellow
        }
        else {
            Write-Host "[+] Found $($userAssignments.Count) explicitly assigned user(s) for $AppName" -ForegroundColor Green
        }
        
        return @{
            Users = $userAssignments
            AllUsersHaveAccess = (-not $assignmentRequired)
            AssignmentRequired = $assignmentRequired
        }
    }
    catch {
        Write-Host "[!] Error retrieving users for $AppName : $_" -ForegroundColor Yellow
        return @{
            Users = @()
            AllUsersHaveAccess = $false
            AssignmentRequired = $true
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
function Start-AppAccessScan {
    Write-Host "`n[*] Starting app access scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of assignments..." -ForegroundColor Cyan
    
    # Get service principals for target apps
    if (-not (Get-TargetServicePrincipals)) {
        return
    }
    
    # For each target app, get assigned users
    $allUserIds = @{}  # Track unique users to avoid duplicates
    $script:DefaultAccessApps = @()  # Track which apps have default access (for warning)
    
    foreach ($appName in $script:ServicePrincipals.Keys) {
        $sp = $script:ServicePrincipals[$appName]
        $result = Get-ServicePrincipalUsers -ServicePrincipal $sp -AppName $appName
        
        $assignments = $result.Users
        $allUsersHaveAccess = $result.AllUsersHaveAccess
        
        # Track apps with default access for reporting
        if ($allUsersHaveAccess) {
            $script:DefaultAccessApps += $appName
        }
        
        # Only process explicitly assigned users
        foreach ($assignment in $assignments) {
            $userId = $assignment.PrincipalId
            
            # Track which apps this user has explicit access to
            if (-not $allUserIds.ContainsKey($userId)) {
                $allUserIds[$userId] = @{
                    Apps = @()
                    Assignment = $assignment
                }
            }
            
            $allUserIds[$userId].Apps += $appName
        }
    }
    
    if ($allUserIds.Count -eq 0) {
        Write-Host "[!] No user assignments found for target applications" -ForegroundColor Yellow
        return
    }
    
    # Report on default access apps
    if ($script:DefaultAccessApps.Count -gt 0) {
        Write-Host "`n[!] IMPORTANT: The following $($script:DefaultAccessApps.Count) app(s) have DEFAULT ACCESS:" -ForegroundColor Yellow
        foreach ($app in $script:DefaultAccessApps) {
            Write-Host "    - $app" -ForegroundColor Yellow
        }
        Write-Host "[!] This means ALL tenant users have basic access to these apps" -ForegroundColor Yellow
        Write-Host "[*] User list below shows only EXPLICIT ASSIGNMENTS (administrative/elevated access)" -ForegroundColor Cyan
        Write-Host "[*] Regular users with default access are NOT shown in this list" -ForegroundColor Cyan
    }
    
    $script:TotalUsersScanned = $allUserIds.Count
    $progressCounter = 0
    
    Write-Host "`n[*] Analyzing users with app access..." -ForegroundColor Cyan
    Write-Host "[*] Found $($allUserIds.Count) unique user(s) with access" -ForegroundColor Cyan
    
    foreach ($userId in $allUserIds.Keys) {
        $progressCounter++
        
        # Progress indicator
        if ($progressCounter % 5 -eq 0 -or $progressCounter -eq $allUserIds.Count) {
            $percentComplete = [math]::Round(($progressCounter / $allUserIds.Count) * 100, 1)
            Write-Host "`r[*] Progress: $progressCounter/$($allUserIds.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
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
                'UserType',
                'AssignedLicenses'
            )
            
            $user = Get-MgUser -UserId $userId -Property $properties -ErrorAction Stop
            
            # Skip disabled users if not included
            if (-not $IncludeDisabledUsers -and -not $user.AccountEnabled) {
                continue
            }
            
            # Check MFA status
            $mfaStatus = Test-UserMFA -UserId $user.Id -UserPrincipalName $user.UserPrincipalName
            
            # Skip if OnlyNoMFA is set and user has MFA
            if ($OnlyNoMFA -and $mfaStatus.HasMFA) {
                continue
            }
            
            # Get sign-in information
            $signInInfo = Get-SignInInfo -User $user
            
            # Get assignment details
            $apps = $allUserIds[$userId].Apps
            $assignment = $allUserIds[$userId].Assignment
            
            # Determine risk level
            $riskLevel = "MEDIUM"
            if ($user.AccountEnabled) {
                if (-not $mfaStatus.HasMFA) {
                    $riskLevel = "HIGH"  # Active user with PowerShell/CLI access without MFA
                }
                else {
                    $riskLevel = "LOW"  # Active user with MFA
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
            
            # Calculate days since assignment (only for explicit assignments)
            $daysSinceAssignment = -1
            if ($assignment.CreatedDateTime) {
                $daysSinceAssignment = ([DateTime]::Now - [DateTime]$assignment.CreatedDateTime).Days
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
                AssignedApps = ($apps -join ", ")
                AppCount = $apps.Count
                AssignmentDate = $assignment.CreatedDateTime
                DaysSinceAssignment = $daysSinceAssignment
                LastSignIn = $signInInfo.LastSignIn
                LastSignInDisplay = $signInInfo.DisplayText
                DaysSinceLastSignIn = $signInInfo.DaysAgo
                SignInType = $signInInfo.SignInType
                MFAEnabled = $mfaStatus.HasMFA
                AuthMethods = ($mfaStatus.Methods -join ", ")
                MethodCount = $mfaStatus.MethodCount
                HasLicenses = ($user.AssignedLicenses.Count -gt 0)
                LicenseCount = $user.AssignedLicenses.Count
                RiskLevel = $riskLevel
            }
            
            $script:UsersWithAccess += $userInfo
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
    Write-Host "MATRIX VIEW - USERS WITH CRITICAL ADMINISTRATIVE APPLICATION ACCESS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:UsersWithAccess.Count -eq 0) {
        if ($OnlyNoMFA) {
            Write-Host "`n[+] All users with app access have MFA enabled." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No users found with access to target applications." -ForegroundColor Yellow
        }
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:UsersWithAccess | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='MFA';Expression={if($_.MFAEnabled){'Yes'}else{'No'}}},
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}},
        @{Name='User Principal Name';Expression={$_.UserPrincipalName}},
        @{Name='Display Name';Expression={$_.DisplayName}},
        @{Name='Apps';Expression={$_.AssignedApps}},
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
    Write-Host "Total users with explicit assignments: " -NoNewline -ForegroundColor White
    Write-Host $script:UsersWithAccess.Count -ForegroundColor Yellow
    
    # Show apps with default access warning
    if ($script:DefaultAccessApps -and $script:DefaultAccessApps.Count -gt 0) {
        Write-Host "`n[!] Note: $($script:DefaultAccessApps.Count) app(s) have DEFAULT ACCESS (all users):" -ForegroundColor Yellow
        foreach ($app in $script:DefaultAccessApps) {
            Write-Host "    - $app" -ForegroundColor DarkYellow
        }
        Write-Host "  Regular users with default access are not shown in this list" -ForegroundColor DarkGray
    }
    
    $highRisk = ($script:UsersWithAccess | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:UsersWithAccess | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:UsersWithAccess | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    $withMFA = ($script:UsersWithAccess | Where-Object { $_.MFAEnabled -eq $true }).Count
    $withoutMFA = ($script:UsersWithAccess | Where-Object { $_.MFAEnabled -eq $false }).Count
    
    Write-Host "  - HIGH risk (active without MFA): " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Red
    Write-Host "  - MEDIUM risk (disabled/inactive): " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Yellow
    Write-Host "  - LOW risk (MFA enabled/disabled): " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    Write-Host "`n[MFA STATUS]" -ForegroundColor Cyan
    Write-Host "  With MFA enabled: " -NoNewline -ForegroundColor White
    Write-Host $withMFA -ForegroundColor Green
    Write-Host "  Without MFA: " -NoNewline -ForegroundColor White
    Write-Host $withoutMFA -ForegroundColor Red
    
    # Group by application
    $byApp = @{}
    foreach ($user in $script:UsersWithAccess) {
        $apps = $user.AssignedApps -split ", "
        foreach ($app in $apps) {
            if (-not $byApp.ContainsKey($app)) {
                $byApp[$app] = 0
            }
            $byApp[$app]++
        }
    }
    
    if ($byApp.Count -gt 0) {
        Write-Host "`n[USERS BY APPLICATION]" -ForegroundColor Cyan
        $byApp.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Value -ForegroundColor Yellow
        }
    }
    
    # Group by department
    $byDept = $script:UsersWithAccess | Where-Object { $_.Department } | Group-Object Department | Sort-Object Count -Descending
    if ($byDept.Count -gt 0) {
        Write-Host "`n[TOP DEPARTMENTS]" -ForegroundColor Cyan
        $byDept | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Sign-in activity statistics
    $neverSignedIn = ($script:UsersWithAccess | Where-Object { $_.DaysSinceLastSignIn -eq -1 }).Count
    $recentSignIn = ($script:UsersWithAccess | Where-Object { $_.DaysSinceLastSignIn -ge 0 -and $_.DaysSinceLastSignIn -le 30 }).Count
    $staleSignIn = ($script:UsersWithAccess | Where-Object { $_.DaysSinceLastSignIn -gt 90 }).Count
    
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
    
    Write-Host "`nTarget applications checked: " -NoNewline -ForegroundColor White
    Write-Host $script:ServicePrincipals.Count -ForegroundColor Yellow
    
    Write-Host "Users with app access: " -NoNewline -ForegroundColor White
    Write-Host $script:UsersWithAccess.Count -ForegroundColor $(if($script:UsersWithAccess.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:UsersWithAccess.Count -gt 0) {
        $highRisk = ($script:UsersWithAccess | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:UsersWithAccess | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:UsersWithAccess | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        $withMFA = ($script:UsersWithAccess | Where-Object { $_.MFAEnabled -eq $true }).Count
        $withoutMFA = ($script:UsersWithAccess | Where-Object { $_.MFAEnabled -eq $false }).Count
        
        Write-Host "  - HIGH risk (active without MFA): " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Red
        Write-Host "  - MEDIUM risk (disabled/inactive): " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Yellow
        Write-Host "  - LOW risk (secure/disabled): " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`nMFA Status:" -ForegroundColor Cyan
        Write-Host "  - With MFA: " -NoNewline -ForegroundColor White
        Write-Host $withMFA -ForegroundColor Green
        Write-Host "  - Without MFA: " -NoNewline -ForegroundColor White
        Write-Host $withoutMFA -ForegroundColor Red
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "USER DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:UsersWithAccess | ForEach-Object {
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
            
            Write-Host "  Assigned Apps ($($_.AppCount)): " -NoNewline -ForegroundColor Gray
            Write-Host $_.AssignedApps -ForegroundColor Cyan
            
            if ($_.AssignmentDate) {
                Write-Host "  Assignment Date: $($_.AssignmentDate) ($($_.DaysSinceAssignment) days ago)" -ForegroundColor Gray
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
            Write-Host "`n[+] All users with app access have MFA enabled." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No users found with access to target applications." -ForegroundColor Yellow
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
    
    if ($script:UsersWithAccess.Count -eq 0) {
        Write-Host "`n[*] No users with app access to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:UsersWithAccess | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:UsersWithAccess | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:UsersWithAccess | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-AppAccessScan
        
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
        
        Write-Host "`n[*] App access check completed successfully!" -ForegroundColor Green
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



