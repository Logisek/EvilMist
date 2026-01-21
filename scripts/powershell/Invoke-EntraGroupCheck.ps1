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
    Checks Azure Entra ID groups for security issues including owner analysis, MFA status, and excessive members.

.DESCRIPTION
    This script queries Azure Entra ID to enumerate all groups, analyze group owners and their MFA status,
    identify groups with no owners, check for groups with excessive members, and perform risk assessment
    based on group permissions and configuration.
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Information collected includes:
    - All groups in the tenant (security groups, Microsoft 365 groups, distribution groups)
    - Group owners and their MFA status
    - Groups with no owners (orphaned groups)
    - Groups with excessive members (>100 or >500)
    - Risk assessment based on group permissions (role-assignable, security-enabled, etc.)
    - Group type and configuration details

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

.PARAMETER OnlyNoOwners
    Show only groups with no owners.

.PARAMETER OnlyExcessiveMembers
    Show only groups with excessive members (>100).

.PARAMETER OnlyHighRisk
    Show only groups with CRITICAL or HIGH risk.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraGroupCheck.ps1
    # Check all groups for security issues

.EXAMPLE
    .\Invoke-EntraGroupCheck.ps1 -ExportPath "groups.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraGroupCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraGroupCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraGroupCheck.ps1 -OnlyNoOwners -Matrix
    # Display only groups with no owners in matrix format

.EXAMPLE
    .\Invoke-EntraGroupCheck.ps1 -OnlyExcessiveMembers -ExportPath "large-groups.csv"
    # Show only groups with excessive members and export
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
    [switch]$OnlyNoOwners,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyExcessiveMembers,

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

# Required scopes for group checking
$script:RequiredScopes = @(
    "Directory.Read.All",
    "Group.Read.All",
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
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
$script:GroupData = @()
$script:TotalGroupsScanned = 0
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
    Write-Host "    Entra ID Group Check - Group Security Analysis" -ForegroundColor Yellow
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

# Check if user has MFA enabled
function Test-UserMFA {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId
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
        # If we can't check auth methods, assume no MFA for security assessment
        return @{
            HasMFA = $false
            Methods = @("Error checking methods")
            MethodCount = 0
        }
    }
}

# Main scanning function
function Start-GroupScan {
    Write-Host "`n[*] Starting group security scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of groups..." -ForegroundColor Cyan
    
    try {
        # Get all groups
        Write-Host "`n[*] Retrieving all groups..." -ForegroundColor Cyan
        
        $selectFields = "id,displayName,description,groupTypes,securityEnabled,mailEnabled,isAssignableToRole,createdDateTime,onPremisesSyncEnabled,onPremisesSecurityIdentifier"
        
        $allGroups = @()
        $uri = "https://graph.microsoft.com/v1.0/groups?`$select=$selectFields&`$top=999"
        
        do {
            Invoke-StealthDelay
            
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $allGroups += $response.value
            
            if ($response.'@odata.nextLink') {
                $uri = $response.'@odata.nextLink'
                Write-Host "    Retrieved $($allGroups.Count) groups so far..." -ForegroundColor Gray
            }
            else {
                $uri = $null
            }
        } while ($uri)
        
        Write-Host "[+] Retrieved $($allGroups.Count) total groups" -ForegroundColor Green
        
        $script:TotalGroupsScanned = $allGroups.Count
        $progressCounter = 0
        
        Write-Host "`n[*] Analyzing groups and owners..." -ForegroundColor Cyan
        
        foreach ($group in $allGroups) {
            $progressCounter++
            
            # Progress indicator
            if ($progressCounter % 50 -eq 0 -or $progressCounter -eq $allGroups.Count) {
                $percentComplete = [math]::Round(($progressCounter / $allGroups.Count) * 100, 1)
                Write-Host "`r[*] Progress: $progressCounter/$($allGroups.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
            }
            
            try {
                Invoke-StealthDelay
                
                # Get group owners
                $owners = @()
                try {
                    $ownerResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/owners?`$select=id,displayName,userPrincipalName,mail" -ErrorAction Stop
                    $owners = $ownerResponse.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
                }
                catch {
                    # Some groups may not allow owner enumeration
                }
                
                # Get member count
                $memberCount = 0
                try {
                    Invoke-StealthDelay
                    $memberResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members/`$count" -Headers @{"ConsistencyLevel" = "eventual"} -ErrorAction SilentlyContinue
                    if ($memberResponse.'@odata.count' -ne $null) {
                        $memberCount = $memberResponse.'@odata.count'
                    }
                    else {
                        # Fallback: count members
                        $members = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members?`$top=1" -ErrorAction SilentlyContinue
                        if ($members.'@odata.nextLink') {
                            # Has more than 1 member, estimate or get full count
                            $allMembers = @()
                            $memberUri = "https://graph.microsoft.com/v1.0/groups/$($group.id)/members?`$top=999"
                            do {
                                Invoke-StealthDelay
                                $memberResp = Invoke-MgGraphRequest -Method GET -Uri $memberUri -ErrorAction SilentlyContinue
                                if ($memberResp.value) {
                                    $allMembers += $memberResp.value
                                }
                                $memberUri = $memberResp.'@odata.nextLink'
                            } while ($memberUri)
                            $memberCount = $allMembers.Count
                        }
                        else {
                            $memberCount = if ($members.value) { $members.value.Count } else { 0 }
                        }
                    }
                }
                catch {
                    # Member count unavailable
                }
                
                # Analyze owners
                $ownerInfo = @()
                $ownersWithoutMFA = 0
                $totalOwners = $owners.Count
                
                foreach ($owner in $owners) {
                    $mfaInfo = Test-UserMFA -UserId $owner.id
                    $ownerInfo += [PSCustomObject]@{
                        Id = $owner.id
                        DisplayName = $owner.displayName
                        UserPrincipalName = $owner.userPrincipalName
                        Mail = $owner.mail
                        HasMFA = $mfaInfo.HasMFA
                        MFAMethods = ($mfaInfo.Methods -join ", ")
                    }
                    
                    if (-not $mfaInfo.HasMFA) {
                        $ownersWithoutMFA++
                    }
                }
                
                # Determine group type
                $groupType = "Security"
                if ($group.groupTypes -contains "Unified") {
                    $groupType = "Microsoft 365"
                }
                elseif ($group.groupTypes -contains "DynamicMembership") {
                    $groupType = "Dynamic"
                }
                elseif (-not $group.securityEnabled -and $group.mailEnabled) {
                    $groupType = "Distribution"
                }
                
                # Determine risk level
                $riskLevel = "LOW"
                $riskFactors = @()
                
                # CRITICAL: Role-assignable groups
                if ($group.isAssignableToRole -eq $true) {
                    $riskLevel = "CRITICAL"
                    $riskFactors += "Role-assignable group"
                }
                # HIGH: Security groups with no owners
                elseif ($totalOwners -eq 0 -and $group.securityEnabled -eq $true) {
                    $riskLevel = "HIGH"
                    $riskFactors += "No owners"
                }
                # HIGH: Groups with excessive members (>500)
                elseif ($memberCount -gt 500) {
                    $riskLevel = "HIGH"
                    $riskFactors += "Excessive members ($memberCount)"
                }
                # HIGH: Security groups with owners without MFA
                elseif ($group.securityEnabled -eq $true -and $ownersWithoutMFA -gt 0 -and $totalOwners -gt 0) {
                    $riskLevel = "HIGH"
                    $riskFactors += "$ownersWithoutMFA owner(s) without MFA"
                }
                # MEDIUM: Groups with many members (>100)
                elseif ($memberCount -gt 100) {
                    $riskLevel = "MEDIUM"
                    $riskFactors += "Large membership ($memberCount)"
                }
                # MEDIUM: Groups with no owners (non-security)
                elseif ($totalOwners -eq 0) {
                    $riskLevel = "MEDIUM"
                    $riskFactors += "No owners"
                }
                # MEDIUM: Microsoft 365 groups with owners without MFA
                elseif ($group.groupTypes -contains "Unified" -and $ownersWithoutMFA -gt 0 -and $totalOwners -gt 0) {
                    $riskLevel = "MEDIUM"
                    $riskFactors += "$ownersWithoutMFA owner(s) without MFA"
                }
                
                # Skip if filters are applied
                if ($OnlyNoOwners -and $totalOwners -gt 0) {
                    continue
                }
                
                if ($OnlyExcessiveMembers -and $memberCount -le 100) {
                    continue
                }
                
                if ($OnlyHighRisk -and $riskLevel -ne "CRITICAL" -and $riskLevel -ne "HIGH") {
                    continue
                }
                
                $groupInfo = [PSCustomObject]@{
                    Id = $group.id
                    DisplayName = $group.displayName
                    Description = $group.description
                    GroupType = $groupType
                    SecurityEnabled = $group.securityEnabled
                    MailEnabled = $group.mailEnabled
                    IsAssignableToRole = $group.isAssignableToRole
                    CreatedDateTime = $group.createdDateTime
                    OnPremisesSyncEnabled = $group.onPremisesSyncEnabled
                    OnPremisesSecurityIdentifier = $group.onPremisesSecurityIdentifier
                    OwnerCount = $totalOwners
                    OwnersWithoutMFA = $ownersWithoutMFA
                    OwnerInfo = $ownerInfo
                    MemberCount = $memberCount
                    HasExcessiveMembers = ($memberCount -gt 100)
                    HasNoOwners = ($totalOwners -eq 0)
                    RiskLevel = $riskLevel
                    RiskFactors = ($riskFactors -join ", ")
                }
                
                $script:GroupData += $groupInfo
            }
            catch {
                Write-Host "`n[!] Error processing group $($group.displayName): $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n[+] Scan complete!" -ForegroundColor Green
    }
    catch {
        Write-Host "`n[ERROR] Failed to retrieve groups: $_" -ForegroundColor Red
        Write-Host "[!] Note: Requires Directory.Read.All and Group.Read.All permissions" -ForegroundColor Yellow
    }
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - GROUP SECURITY ANALYSIS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:GroupData.Count -eq 0) {
        if ($OnlyNoOwners) {
            Write-Host "`n[+] No groups with no owners found." -ForegroundColor Green
        }
        elseif ($OnlyExcessiveMembers) {
            Write-Host "`n[+] No groups with excessive members found." -ForegroundColor Green
        }
        elseif ($OnlyHighRisk) {
            Write-Host "`n[+] No high-risk groups found." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No group data found." -ForegroundColor Yellow
        }
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:GroupData | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Group Name';Expression={$_.DisplayName}},
        @{Name='Type';Expression={$_.GroupType}},
        @{Name='Owners';Expression={$_.OwnerCount}},
        @{Name='Owners w/o MFA';Expression={$_.OwnersWithoutMFA}},
        @{Name='Members';Expression={$_.MemberCount}},
        @{Name='Role-Assignable';Expression={if($_.IsAssignableToRole){'Yes'}else{'No'}}},
        @{Name='Risk Factors';Expression={if($_.RiskFactors){$_.RiskFactors}else{'-'}}}
    
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
    Write-Host "Total groups analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalGroupsScanned -ForegroundColor Yellow
    
    Write-Host "Groups in results: " -NoNewline -ForegroundColor White
    Write-Host $script:GroupData.Count -ForegroundColor Yellow
    
    $criticalRisk = ($script:GroupData | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:GroupData | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:GroupData | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:GroupData | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "`n[RISK BREAKDOWN]" -ForegroundColor Cyan
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Red
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Yellow
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    $groupsWithNoOwners = ($script:GroupData | Where-Object { $_.HasNoOwners -eq $true }).Count
    $groupsWithExcessiveMembers = ($script:GroupData | Where-Object { $_.HasExcessiveMembers -eq $true }).Count
    $roleAssignableGroups = ($script:GroupData | Where-Object { $_.IsAssignableToRole -eq $true }).Count
    $totalOwnersWithoutMFA = ($script:GroupData | ForEach-Object { $_.OwnersWithoutMFA } | Measure-Object -Sum).Sum
    
    Write-Host "`n[SECURITY METRICS]" -ForegroundColor Cyan
    Write-Host "  - Groups with no owners: " -NoNewline -ForegroundColor White
    Write-Host $groupsWithNoOwners -ForegroundColor $(if($groupsWithNoOwners -gt 0){"Red"}else{"Green"})
    
    Write-Host "  - Groups with excessive members (>100): " -NoNewline -ForegroundColor White
    Write-Host $groupsWithExcessiveMembers -ForegroundColor $(if($groupsWithExcessiveMembers -gt 0){"Yellow"}else{"Green"})
    
    Write-Host "  - Role-assignable groups: " -NoNewline -ForegroundColor White
    Write-Host $roleAssignableGroups -ForegroundColor $(if($roleAssignableGroups -gt 0){"Red"}else{"Green"})
    
    Write-Host "  - Total owners without MFA: " -NoNewline -ForegroundColor White
    Write-Host $totalOwnersWithoutMFA -ForegroundColor $(if($totalOwnersWithoutMFA -gt 0){"Red"}else{"Green"})
    
    # Group by type
    $byType = $script:GroupData | Group-Object GroupType | Sort-Object Count -Descending
    if ($byType.Count -gt 0) {
        Write-Host "`n[GROUPS BY TYPE]" -ForegroundColor Cyan
        $byType | ForEach-Object {
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
    
    Write-Host "`nTotal groups analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalGroupsScanned -ForegroundColor Yellow
    
    Write-Host "Groups in results: " -NoNewline -ForegroundColor White
    Write-Host $script:GroupData.Count -ForegroundColor Yellow
    
    if ($script:GroupData.Count -gt 0) {
        $criticalRisk = ($script:GroupData | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:GroupData | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:GroupData | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:GroupData | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Red
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Yellow
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "GROUP DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:GroupData | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.DisplayName -ForegroundColor White
            
            Write-Host "  Group Type: $($_.GroupType)" -ForegroundColor Gray
            Write-Host "  Group ID: $($_.Id)" -ForegroundColor Gray
            
            if ($_.Description) {
                Write-Host "  Description: $($_.Description)" -ForegroundColor Gray
            }
            
            Write-Host "  Security Enabled: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.SecurityEnabled){"Yes"}else{"No"}) -ForegroundColor $(if($_.SecurityEnabled){"Cyan"}else{"Gray"})
            
            Write-Host "  Mail Enabled: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.MailEnabled){"Yes"}else{"No"}) -ForegroundColor $(if($_.MailEnabled){"Cyan"}else{"Gray"})
            
            Write-Host "  Role-Assignable: " -NoNewline -ForegroundColor Gray
            if ($_.IsAssignableToRole) {
                Write-Host "Yes" -ForegroundColor Red
            }
            else {
                Write-Host "No" -ForegroundColor Green
            }
            
            Write-Host "  Created: $($_.CreatedDateTime)" -ForegroundColor Gray
            
            Write-Host "  Owners: " -NoNewline -ForegroundColor Gray
            if ($_.OwnerCount -eq 0) {
                Write-Host "None" -ForegroundColor Red
            }
            else {
                Write-Host "$($_.OwnerCount)" -ForegroundColor Yellow
                if ($_.OwnersWithoutMFA -gt 0) {
                    Write-Host "    Owners without MFA: $($_.OwnersWithoutMFA)" -ForegroundColor Red
                }
                
                foreach ($owner in $_.OwnerInfo) {
                    Write-Host "    - $($owner.DisplayName) ($($owner.UserPrincipalName))" -ForegroundColor Gray
                    Write-Host "      MFA: " -NoNewline -ForegroundColor DarkGray
                    if ($owner.HasMFA) {
                        Write-Host "Yes ($($owner.MFAMethods))" -ForegroundColor Green
                    }
                    else {
                        Write-Host "No" -ForegroundColor Red
                    }
                }
            }
            
            Write-Host "  Members: $($_.MemberCount)" -ForegroundColor Gray
            if ($_.HasExcessiveMembers) {
                Write-Host "    Warning: Excessive membership (>100 members)" -ForegroundColor Yellow
            }
            
            if ($_.RiskFactors) {
                Write-Host "  Risk Factors: $($_.RiskFactors)" -ForegroundColor $(if($_.RiskLevel -eq "HIGH" -or $_.RiskLevel -eq "CRITICAL"){"Red"}else{"Yellow"})
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        if ($OnlyNoOwners) {
            Write-Host "`n[+] No groups with no owners found." -ForegroundColor Green
        }
        elseif ($OnlyExcessiveMembers) {
            Write-Host "`n[+] No groups with excessive members found." -ForegroundColor Green
        }
        elseif ($OnlyHighRisk) {
            Write-Host "`n[+] No high-risk groups found." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No group data found." -ForegroundColor Yellow
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
    
    if ($script:GroupData.Count -eq 0) {
        Write-Host "`n[*] No group data to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        # Prepare data for export (flatten owner info)
        $exportData = $script:GroupData | ForEach-Object {
            $obj = [PSCustomObject]@{
                Id = $_.Id
                DisplayName = $_.DisplayName
                Description = $_.Description
                GroupType = $_.GroupType
                SecurityEnabled = $_.SecurityEnabled
                MailEnabled = $_.MailEnabled
                IsAssignableToRole = $_.IsAssignableToRole
                CreatedDateTime = $_.CreatedDateTime
                OnPremisesSyncEnabled = $_.OnPremisesSyncEnabled
                OnPremisesSecurityIdentifier = $_.OnPremisesSecurityIdentifier
                OwnerCount = $_.OwnerCount
                OwnersWithoutMFA = $_.OwnersWithoutMFA
                MemberCount = $_.MemberCount
                HasExcessiveMembers = $_.HasExcessiveMembers
                HasNoOwners = $_.HasNoOwners
                RiskLevel = $_.RiskLevel
                RiskFactors = $_.RiskFactors
            }
            
            # Add owner details as JSON string for CSV
            if ($_.OwnerInfo -and $_.OwnerInfo.Count -gt 0) {
                $obj | Add-Member -NotePropertyName "OwnerInfoJSON" -NotePropertyValue ($_.OwnerInfo | ConvertTo-Json -Compress) -Force
                $obj | Add-Member -NotePropertyName "OwnerNames" -NotePropertyValue (($_.OwnerInfo | ForEach-Object { $_.DisplayName }) -join "; ") -Force
                $obj | Add-Member -NotePropertyName "OwnerUPNs" -NotePropertyValue (($_.OwnerInfo | ForEach-Object { $_.UserPrincipalName }) -join "; ") -Force
            }
            else {
                $obj | Add-Member -NotePropertyName "OwnerInfoJSON" -NotePropertyValue $null -Force
                $obj | Add-Member -NotePropertyName "OwnerNames" -NotePropertyValue $null -Force
                $obj | Add-Member -NotePropertyName "OwnerUPNs" -NotePropertyValue $null -Force
            }
            
            $obj
        }
        
        switch ($extension) {
            ".csv" {
                $exportData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                # For JSON, include full owner info
                $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-GroupScan
        
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
        
        Write-Host "`n[*] Group security check completed successfully!" -ForegroundColor Green
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

