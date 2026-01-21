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
    Enumerates Power Apps and Power Automate flows with security risk assessment.

.DESCRIPTION
    This script queries Microsoft Power Platform to enumerate Power Apps and Power Automate
    flows, identify sensitive connectors, and assess security risks. It provides comprehensive
    information about Power Platform resources including owners, connectors, and risk levels.
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Microsoft Graph and Power Platform APIs.
    
    Information collected includes:
    - Power Apps enumeration with owner and sharing information
    - Power Automate flows enumeration with connector analysis
    - Sensitive connector detection (CRITICAL, HIGH, MEDIUM, LOW risk)
    - High-risk action identification in flows
    - Risk assessment based on connector types and configurations

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

.PARAMETER OnlyHighRisk
    Show only Power Apps/flows with HIGH or CRITICAL risk connectors.

.PARAMETER OnlySensitiveConnectors
    Show only flows/apps with sensitive connectors.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraPowerPlatformCheck.ps1
    # Enumerate all Power Apps and flows

.EXAMPLE
    .\Invoke-EntraPowerPlatformCheck.ps1 -ExportPath "power-platform.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraPowerPlatformCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraPowerPlatformCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraPowerPlatformCheck.ps1 -OnlyHighRisk -Matrix
    # Display only high-risk resources in matrix format

.EXAMPLE
    .\Invoke-EntraPowerPlatformCheck.ps1 -OnlySensitiveConnectors -ExportPath "sensitive.csv"
    # Show only resources with sensitive connectors and export
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
    [switch]$OnlyHighRisk,

    [Parameter(Mandatory = $false)]
    [switch]$OnlySensitiveConnectors,

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

# Power Platform API endpoints
$script:PowerAppsApiEndpoint = "https://api.powerapps.com"
$script:FlowApiEndpoint = "https://api.flow.microsoft.com"

# Sensitive connectors with risk levels
$script:SensitiveConnectors = @{
    # Data Storage & Databases
    "shared_sql" = @{ Name = "SQL Server"; Risk = "HIGH"; Category = "Database" }
    "shared_azuresqldb" = @{ Name = "Azure SQL Database"; Risk = "HIGH"; Category = "Database" }
    "shared_cosmosdb" = @{ Name = "Cosmos DB"; Risk = "HIGH"; Category = "Database" }
    "shared_azuretables" = @{ Name = "Azure Table Storage"; Risk = "MEDIUM"; Category = "Database" }
    "shared_azureblob" = @{ Name = "Azure Blob Storage"; Risk = "HIGH"; Category = "Storage" }
    "shared_azurefile" = @{ Name = "Azure File Storage"; Risk = "MEDIUM"; Category = "Storage" }
    "shared_amazons3" = @{ Name = "Amazon S3"; Risk = "HIGH"; Category = "Storage" }
    "shared_googlecloudstorage" = @{ Name = "Google Cloud Storage"; Risk = "HIGH"; Category = "Storage" }
    "shared_ftp" = @{ Name = "FTP"; Risk = "HIGH"; Category = "Storage" }
    "shared_sftp" = @{ Name = "SFTP"; Risk = "HIGH"; Category = "Storage" }
    # Microsoft 365 Services
    "shared_sharepointonline" = @{ Name = "SharePoint Online"; Risk = "HIGH"; Category = "M365" }
    "shared_onedriveforbusiness" = @{ Name = "OneDrive for Business"; Risk = "HIGH"; Category = "M365" }
    "shared_office365" = @{ Name = "Office 365 Outlook"; Risk = "MEDIUM"; Category = "M365" }
    "shared_teams" = @{ Name = "Microsoft Teams"; Risk = "MEDIUM"; Category = "M365" }
    "shared_excelonlinebusiness" = @{ Name = "Excel Online"; Risk = "MEDIUM"; Category = "M365" }
    # Identity & Access
    "shared_azuread" = @{ Name = "Azure Active Directory"; Risk = "CRITICAL"; Category = "Identity" }
    "shared_keyvault" = @{ Name = "Azure Key Vault"; Risk = "CRITICAL"; Category = "Secrets" }
    # External Communication
    "shared_sendgrid" = @{ Name = "SendGrid"; Risk = "HIGH"; Category = "Email" }
    "shared_smtp" = @{ Name = "SMTP"; Risk = "HIGH"; Category = "Email" }
    "shared_twiliosms" = @{ Name = "Twilio SMS"; Risk = "MEDIUM"; Category = "Communication" }
    "shared_slack" = @{ Name = "Slack"; Risk = "MEDIUM"; Category = "Communication" }
    # HTTP & Custom Code
    "shared_http" = @{ Name = "HTTP"; Risk = "CRITICAL"; Category = "Custom" }
    "shared_webcontents" = @{ Name = "HTTP with Azure AD"; Risk = "HIGH"; Category = "Custom" }
    "shared_azurefunctions" = @{ Name = "Azure Functions"; Risk = "HIGH"; Category = "Compute" }
    "shared_azurelogicapps" = @{ Name = "Azure Logic Apps"; Risk = "MEDIUM"; Category = "Compute" }
    "shared_custom" = @{ Name = "Custom Connector"; Risk = "HIGH"; Category = "Custom" }
    # Cloud Services
    "shared_azureautomation" = @{ Name = "Azure Automation"; Risk = "HIGH"; Category = "Automation" }
    "shared_azuredevops" = @{ Name = "Azure DevOps"; Risk = "HIGH"; Category = "DevOps" }
    "shared_github" = @{ Name = "GitHub"; Risk = "HIGH"; Category = "DevOps" }
    # CRM & ERP
    "shared_commondataservice" = @{ Name = "Dataverse"; Risk = "HIGH"; Category = "CRM" }
    "shared_dynamicscrmonline" = @{ Name = "Dynamics 365"; Risk = "HIGH"; Category = "CRM" }
    "shared_salesforce" = @{ Name = "Salesforce"; Risk = "HIGH"; Category = "CRM" }
    # ServiceNow
    "shared_servicenow" = @{ Name = "ServiceNow"; Risk = "HIGH"; Category = "ITSM" }
}

# High-risk actions in Power Automate flows
$script:HighRiskActions = @(
    "Delete", "Remove", "Terminate", "Disable", "Revoke", "Block",
    "Create", "Update", "Modify", "Change", "Set", "Grant", "Assign"
)

# Required scopes for Power Platform checking
$script:RequiredScopes = @(
    "Directory.Read.All",
    "User.Read.All"
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
$script:PowerAppsData = @()
$script:PowerAutomateFlowsData = @()
$script:TotalAppsScanned = 0
$script:TotalFlowsScanned = 0
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
    Write-Host "    Entra ID Power Platform Check - Power Apps & Power Automate Security Audit" -ForegroundColor Yellow
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
            Write-Host "[!] Some features may be limited" -ForegroundColor Yellow
            
            return $true
        }
        catch {
            Write-Host "[ERROR] Authentication failed: $_" -ForegroundColor Red
            return $false
        }
    }
}

# Get Power Platform access token using device code flow
function Get-PowerPlatformToken {
    param(
        [string]$Resource = "https://service.powerapps.com/"
    )
    
    # Check if we already have a cached token for this resource (check first to avoid re-auth)
    $cacheKey = "PowerPlatformToken_$Resource"
    if ($script:TokenCache -and $script:TokenCache.ContainsKey($cacheKey)) {
        $cachedToken = $script:TokenCache[$cacheKey]
        # Check if token is still valid (simple check - tokens last ~1 hour)
        if ($cachedToken.ExpiresOn -gt (Get-Date).AddMinutes(5)) {
            return $cachedToken.AccessToken
        }
    }
    
    # Try Azure CLI first if UseAzCliToken was specified
    if ($UseAzCliToken) {
        Write-Host "    [*] Trying Azure CLI token..." -ForegroundColor Gray
        try {
            # Check if Azure CLI is installed
            $azCliCheck = az --version 2>$null
            if (-not $azCliCheck) {
                Write-Host "    [!] Azure CLI not installed. Install from: https://aka.ms/installazurecliwindows" -ForegroundColor Yellow
            }
            else {
                # Check if already logged in
                $azAccount = az account show 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
                if (-not $azAccount) {
                    Write-Host "    [*] Azure CLI not logged in. Starting interactive login..." -ForegroundColor Cyan
                    az login
                    if ($LASTEXITCODE -ne 0) {
                        Write-Host "    [!] Azure CLI login failed" -ForegroundColor Red
                    }
                }
                
                # Try to get token
                $token = az account get-access-token --resource $Resource --query accessToken -o tsv 2>$null
                if ($token -and $token.Length -gt 0) {
                    Write-Host "    [+] Got token from Azure CLI" -ForegroundColor Green
                    # Cache it
                    if (-not $script:TokenCache) { $script:TokenCache = @{} }
                    $script:TokenCache[$cacheKey] = @{ AccessToken = $token; ExpiresOn = (Get-Date).AddMinutes(55) }
                    return $token
                }
                else {
                    Write-Host "    [!] Azure CLI: Failed to get token. Please try 'az login' manually." -ForegroundColor Yellow
                }
            }
        }
        catch {
            Write-Host "    [!] Azure CLI error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    # Try Azure PowerShell if UseAzPowerShellToken was specified
    if ($UseAzPowerShellToken) {
        Write-Host "    [*] Trying Azure PowerShell token..." -ForegroundColor Gray
        try {
            # Check if Az module is available
            if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
                Write-Host "    [*] Az.Accounts module not found. Installing..." -ForegroundColor Cyan
                try {
                    Install-Module Az.Accounts -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                    Write-Host "    [+] Az.Accounts module installed" -ForegroundColor Green
                }
                catch {
                    Write-Host "    [!] Failed to install Az.Accounts. Install manually with: Install-Module Az -Scope CurrentUser" -ForegroundColor Yellow
                }
            }
            
            # Import the module
            Import-Module Az.Accounts -ErrorAction SilentlyContinue
            
            # Check if already connected
            $azContext = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $azContext) {
                Write-Host "    [*] Azure PowerShell not connected. Starting interactive login..." -ForegroundColor Cyan
                try {
                    # Try to use the account from Graph context if available
                    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
                    if ($graphContext -and $graphContext.Account) {
                        Write-Host "    [*] Using account from Graph context: $($graphContext.Account)" -ForegroundColor Gray
                        # Get tenant from Graph context
                        $tenantId = if ($graphContext.TenantId) { $graphContext.TenantId } else { $null }
                        
                        if ($tenantId) {
                            Connect-AzAccount -TenantId $tenantId -AccountId $graphContext.Account -ErrorAction Stop
                        }
                        else {
                            Connect-AzAccount -AccountId $graphContext.Account -ErrorAction Stop
                        }
                        Write-Host "    [+] Azure PowerShell login successful" -ForegroundColor Green
                    }
                    else {
                        # Fallback to interactive login
                        Connect-AzAccount -ErrorAction Stop
                        Write-Host "    [+] Azure PowerShell login successful" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Host "    [!] Azure PowerShell login failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host "    [*] Falling back to interactive login..." -ForegroundColor Yellow
                    try {
                        Connect-AzAccount -ErrorAction Stop
                        Write-Host "    [+] Azure PowerShell login successful" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "    [!] Interactive login also failed" -ForegroundColor Red
                    }
                }
            }
            else {
                Write-Host "    [*] Found Az context for: $($azContext.Account.Id)" -ForegroundColor Gray
            }
            
            # Try to get token
            $azContext = Get-AzContext -ErrorAction Stop
            if ($azContext) {
                $tokenResult = Get-AzAccessToken -ResourceUrl $Resource -ErrorAction Stop
                if ($tokenResult -and $tokenResult.Token) {
                    Write-Host "    [+] Got token from Azure PowerShell" -ForegroundColor Green
                    # Cache it
                    if (-not $script:TokenCache) { $script:TokenCache = @{} }
                    $script:TokenCache[$cacheKey] = @{ AccessToken = $tokenResult.Token; ExpiresOn = $tokenResult.ExpiresOn }
                    return $tokenResult.Token
                }
                else {
                    Write-Host "    [!] Azure PowerShell: Failed to get token" -ForegroundColor Yellow
                }
            }
        }
        catch {
            Write-Host "    [!] Azure PowerShell error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    # Use device code flow for interactive authentication
    # Use Azure PowerShell public client ID (works for Power Platform)
    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"  # Microsoft Azure PowerShell
    
    # Get tenant from Graph context if available
    $tenant = "common"
    try {
        $context = Get-MgContext
        if ($context -and $context.TenantId) {
            $tenant = $context.TenantId
        }
    }
    catch { }
    
    # If we get here, need to use device code flow
    Write-Host "    [*] Using device code flow for Power Platform authentication..." -ForegroundColor Cyan
    
    # Step 1: Request device code
    $deviceCodeUrl = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/devicecode"
    $scope = "$Resource/.default offline_access"
    
    try {
        $deviceCodeBody = @{
            client_id = $clientId
            scope = $scope
        }
        
        $deviceCodeResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Body $deviceCodeBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        
        # Display the user code and instructions
        Write-Host ""
        Write-Host "    ╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "    ║  AUTHENTICATION REQUIRED FOR POWER PLATFORM                          ║" -ForegroundColor Yellow
        Write-Host "    ╠═══════════════════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
        Write-Host "    ║  1. Open a browser and go to: " -NoNewline -ForegroundColor Yellow
        Write-Host "https://microsoft.com/devicelogin" -NoNewline -ForegroundColor Cyan
        Write-Host "         ║" -ForegroundColor Yellow
        Write-Host "    ║  2. Enter the code: " -NoNewline -ForegroundColor Yellow
        Write-Host "$($deviceCodeResponse.user_code)" -NoNewline -ForegroundColor Green
        Write-Host "                                        ║" -ForegroundColor Yellow
        Write-Host "    ║  3. Sign in with your Azure AD account                                ║" -ForegroundColor Yellow
        Write-Host "    ╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    [*] Waiting for authentication..." -ForegroundColor Cyan
        
        # Step 2: Poll for token
        $tokenUrl = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"
        $interval = $deviceCodeResponse.interval
        $expiresIn = $deviceCodeResponse.expires_in
        $startTime = Get-Date
        
        while ((Get-Date) -lt $startTime.AddSeconds($expiresIn)) {
            Start-Sleep -Seconds $interval
            
            try {
                $tokenBody = @{
                    grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                    client_id = $clientId
                    device_code = $deviceCodeResponse.device_code
                }
                
                $tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                
                Write-Host "    [+] Authentication successful!" -ForegroundColor Green
                
                # Cache the token
                if (-not $script:TokenCache) {
                    $script:TokenCache = @{}
                }
                $script:TokenCache[$cacheKey] = @{
                    AccessToken = $tokenResponse.access_token
                    ExpiresOn = (Get-Date).AddSeconds($tokenResponse.expires_in)
                }
                
                return $tokenResponse.access_token
            }
            catch {
                $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($errorResponse.error -eq "authorization_pending") {
                    # User hasn't completed auth yet, keep polling
                    continue
                }
                elseif ($errorResponse.error -eq "slow_down") {
                    # Need to slow down polling
                    $interval += 5
                    continue
                }
                elseif ($errorResponse.error -eq "expired_token") {
                    Write-Host "    [!] Device code expired. Please try again." -ForegroundColor Red
                    return $null
                }
                else {
                    Write-Host "    [!] Authentication error: $($errorResponse.error_description)" -ForegroundColor Red
                    return $null
                }
            }
        }
        
        Write-Host "    [!] Authentication timed out." -ForegroundColor Red
        return $null
    }
    catch {
        Write-Host "    [!] Failed to start device code flow: $_" -ForegroundColor Red
        return $null
    }
}

# Token cache for Power Platform tokens
$script:TokenCache = @{}

# Enumerate Power Apps
function Get-PowerApps {
    Write-Host "`n[*] Enumerating Power Apps..." -ForegroundColor Cyan
    
    $allApps = @()
    
    # Get Power Platform access token
    $powerAppsToken = Get-PowerPlatformToken -Resource "https://service.powerapps.com/"
    if (-not $powerAppsToken) {
        Write-Host "    [!] Unable to get access token for Power Platform APIs" -ForegroundColor Yellow
        Write-Host "    [*] Power Platform enumeration requires:" -ForegroundColor Yellow
        Write-Host "        - Azure CLI: Run 'az login' first" -ForegroundColor Yellow
        Write-Host "        - OR Azure PowerShell: Run 'Connect-AzAccount' first" -ForegroundColor Yellow
        Write-Host "        - Power Platform Admin or Environment Maker permissions" -ForegroundColor Yellow
        return $allApps
    }
    
    $headers = @{
        "Authorization" = "Bearer $powerAppsToken"
        "Content-Type" = "application/json"
    }
    
    # Method 1: Try PowerApps Admin API
    Write-Host "    [*] Trying Power Apps Admin API..." -ForegroundColor Gray
    try {
        Invoke-StealthDelay
        
        # Get environments first
        $envUrl = "$($script:PowerAppsApiEndpoint)/providers/Microsoft.PowerApps/scopes/admin/environments?api-version=2016-11-01"
        $envResponse = Invoke-RestMethod -Method GET -Uri $envUrl -Headers $headers -ErrorAction Stop
        
        if ($envResponse -and $envResponse.value) {
            $environments = $envResponse.value
            Write-Host "    [+] Found $($environments.Count) Power Platform environments" -ForegroundColor Green
            
            foreach ($env in $environments) {
                $envName = $env.name
                $envDisplay = $env.properties.displayName
                
                # Get apps in this environment
                $appsUrl = "$($script:PowerAppsApiEndpoint)/providers/Microsoft.PowerApps/scopes/admin/environments/$envName/apps?api-version=2016-11-01"
                try {
                    Invoke-StealthDelay
                    $appsResponse = Invoke-RestMethod -Method GET -Uri $appsUrl -Headers $headers -ErrorAction SilentlyContinue
                    
                    if ($appsResponse -and $appsResponse.value) {
                        foreach ($app in $appsResponse.value) {
                            $props = $app.properties
                            
                            # Analyze connectors
                            $connectorsUsed = @()
                            $sensitiveConnectors = @()
                            
                            if ($props.connectionReferences) {
                                foreach ($connProp in ($props.connectionReferences.PSObject.Properties)) {
                                    $connInfo = $connProp.Value
                                    $connId = $connProp.Name
                                    $connType = if ($connInfo.id) { $connInfo.id.Split("/")[-1].ToLower() } else { $connId.ToLower() }
                                    $connName = if ($connInfo.displayName) { $connInfo.displayName } else { $connType }
                                    
                                    $connectorsUsed += [PSCustomObject]@{
                                        Id = $connType
                                        Name = $connName
                                        ConnectionId = $connInfo.connectionId
                                    }
                                    
                                    # Check if it's a sensitive connector
                                    if ($script:SensitiveConnectors.ContainsKey($connType)) {
                                        $sensitiveInfo = $script:SensitiveConnectors[$connType]
                                        $sensitiveConnectors += [PSCustomObject]@{
                                            ConnectorId = $connType
                                            DisplayName = $sensitiveInfo.Name
                                            Risk = $sensitiveInfo.Risk
                                            Category = $sensitiveInfo.Category
                                        }
                                    }
                                }
                            }
                            
                            # Determine risk level
                            $riskLevel = "LOW"
                            if ($sensitiveConnectors | Where-Object { $_.Risk -eq "CRITICAL" }) {
                                $riskLevel = "CRITICAL"
                            }
                            elseif ($sensitiveConnectors | Where-Object { $_.Risk -eq "HIGH" }) {
                                $riskLevel = "HIGH"
                            }
                            elseif ($sensitiveConnectors | Where-Object { $_.Risk -eq "MEDIUM" }) {
                                $riskLevel = "MEDIUM"
                            }
                            
                            $appInfo = [PSCustomObject]@{
                                ResourceType = "Power App"
                                Id = $app.name
                                DisplayName = $props.displayName
                                Environment = $envDisplay
                                EnvironmentId = $envName
                                Owner = $props.owner.displayName
                                OwnerEmail = $props.owner.email
                                OwnerId = $props.owner.id
                                CreatedTime = $props.createdTime
                                LastModifiedTime = $props.lastModifiedTime
                                AppType = $props.appType
                                Status = $props.status
                                ConnectorCount = $connectorsUsed.Count
                                Connectors = ($connectorsUsed | ForEach-Object { $_.Name }) -join ", "
                                HasSensitiveConnector = ($sensitiveConnectors.Count -gt 0)
                                SensitiveConnectorCount = $sensitiveConnectors.Count
                                SensitiveConnectors = ($sensitiveConnectors | ForEach-Object { "$($_.DisplayName) ($($_.Risk))" }) -join ", "
                                RiskLevel = $riskLevel
                                Source = "AdminAPI"
                            }
                            
                            # Try to get sharing information
                            $permissionsUrl = "$($script:PowerAppsApiEndpoint)/providers/Microsoft.PowerApps/scopes/admin/environments/$envName/apps/$($app.name)/permissions?api-version=2016-11-01"
                            try {
                                Invoke-StealthDelay
                                $permsResponse = Invoke-RestMethod -Method GET -Uri $permissionsUrl -Headers $headers -ErrorAction SilentlyContinue
                                if ($permsResponse -and $permsResponse.value) {
                                    $sharedUsers = @()
                                    $sharedGroups = @()
                                    foreach ($perm in $permsResponse.value) {
                                        $permProps = $perm.properties
                                        $principal = $permProps.principal
                                        
                                        if ($principal.type -eq "User") {
                                            $sharedUsers += "$($principal.displayName) ($($principal.email))"
                                        }
                                        elseif ($principal.type -eq "Group") {
                                            $sharedGroups += $principal.displayName
                                        }
                                    }
                                    $appInfo | Add-Member -NotePropertyName "SharedUsers" -NotePropertyValue ($sharedUsers -join "; ") -Force
                                    $appInfo | Add-Member -NotePropertyName "SharedGroups" -NotePropertyValue ($sharedGroups -join "; ") -Force
                                }
                            }
                            catch {
                                # Permissions endpoint may not be accessible
                            }
                            
                            $allApps += $appInfo
                        }
                    }
                }
                catch {
                    # Environment apps may not be accessible
                }
            }
            
            if ($allApps.Count -gt 0) {
                Write-Host "    [+] Found $($allApps.Count) Power Apps via Admin API" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "    [-] Admin API not accessible (requires Power Platform Admin role)" -ForegroundColor Yellow
    }
    
    # Method 2: Try user-scoped PowerApps API
    if ($allApps.Count -eq 0) {
        Write-Host "    [*] Trying user-scoped Power Apps API..." -ForegroundColor Gray
        try {
            Invoke-StealthDelay
            $userAppsUrl = "$($script:PowerAppsApiEndpoint)/providers/Microsoft.PowerApps/apps?api-version=2016-11-01"
            $userResponse = Invoke-RestMethod -Method GET -Uri $userAppsUrl -Headers $headers -ErrorAction Stop
            
            if ($userResponse -and $userResponse.value) {
                foreach ($app in $userResponse.value) {
                    $props = $app.properties
                    
                    # Analyze connectors
                    $connectorsUsed = @()
                    $sensitiveConnectors = @()
                    
                    if ($props.connectionReferences) {
                        foreach ($connProp in ($props.connectionReferences.PSObject.Properties)) {
                            $connInfo = $connProp.Value
                            $connId = $connProp.Name
                            $connType = if ($connInfo.id) { $connInfo.id.Split("/")[-1].ToLower() } else { $connId.ToLower() }
                            $connName = if ($connInfo.displayName) { $connInfo.displayName } else { $connType }
                            
                            $connectorsUsed += [PSCustomObject]@{
                                Id = $connType
                                Name = $connName
                                ConnectionId = $connInfo.connectionId
                            }
                            
                            if ($script:SensitiveConnectors.ContainsKey($connType)) {
                                $sensitiveInfo = $script:SensitiveConnectors[$connType]
                                $sensitiveConnectors += [PSCustomObject]@{
                                    ConnectorId = $connType
                                    DisplayName = $sensitiveInfo.Name
                                    Risk = $sensitiveInfo.Risk
                                    Category = $sensitiveInfo.Category
                                }
                            }
                        }
                    }
                    
                    $riskLevel = "LOW"
                    if ($sensitiveConnectors | Where-Object { $_.Risk -eq "CRITICAL" }) {
                        $riskLevel = "CRITICAL"
                    }
                    elseif ($sensitiveConnectors | Where-Object { $_.Risk -eq "HIGH" }) {
                        $riskLevel = "HIGH"
                    }
                    elseif ($sensitiveConnectors | Where-Object { $_.Risk -eq "MEDIUM" }) {
                        $riskLevel = "MEDIUM"
                    }
                    
                    $appInfo = [PSCustomObject]@{
                        ResourceType = "Power App"
                        Id = $app.name
                        DisplayName = $props.displayName
                        Environment = if ($props.environment) { $props.environment.name } else { "" }
                        EnvironmentId = if ($props.environment) { $props.environment.id } else { "" }
                        Owner = $props.owner.displayName
                        OwnerEmail = $props.owner.email
                        OwnerId = $props.owner.id
                        CreatedTime = $props.createdTime
                        LastModifiedTime = $props.lastModifiedTime
                        AppType = $props.appType
                        Status = $props.status
                        ConnectorCount = $connectorsUsed.Count
                        Connectors = ($connectorsUsed | ForEach-Object { $_.Name }) -join ", "
                        HasSensitiveConnector = ($sensitiveConnectors.Count -gt 0)
                        SensitiveConnectorCount = $sensitiveConnectors.Count
                        SensitiveConnectors = ($sensitiveConnectors | ForEach-Object { "$($_.DisplayName) ($($_.Risk))" }) -join ", "
                        RiskLevel = $riskLevel
                        Source = "UserAPI"
                    }
                    $allApps += $appInfo
                }
                
                if ($allApps.Count -gt 0) {
                    Write-Host "    [+] Found $($allApps.Count) Power Apps via User API" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Host "    [-] User API not accessible" -ForegroundColor Yellow
        }
    }
    
    if ($allApps.Count -eq 0) {
        Write-Host "    [!] No Power Apps found (you may not own any or lack permissions)" -ForegroundColor Yellow
        Write-Host "    Note: Requires Power Platform Admin or Environment Maker permissions" -ForegroundColor Gray
    }
    
    $script:TotalAppsScanned = $allApps.Count
    return $allApps
}

# Enumerate Power Automate flows
function Get-PowerAutomateFlows {
    Write-Host "`n[*] Enumerating Power Automate Flows..." -ForegroundColor Cyan
    
    $allFlows = @()
    
    # Get Power Automate access token
    $flowToken = Get-PowerPlatformToken -Resource "https://service.flow.microsoft.com/"
    if (-not $flowToken) {
        Write-Host "    [!] Unable to get access token for Power Automate APIs" -ForegroundColor Yellow
        Write-Host "    [*] Power Automate enumeration requires:" -ForegroundColor Yellow
        Write-Host "        - Azure CLI: Run 'az login' first" -ForegroundColor Yellow
        Write-Host "        - OR Azure PowerShell: Run 'Connect-AzAccount' first" -ForegroundColor Yellow
        Write-Host "        - Power Platform Admin or Environment Maker permissions" -ForegroundColor Yellow
        return $allFlows
    }
    
    $headers = @{
        "Authorization" = "Bearer $flowToken"
        "Content-Type" = "application/json"
    }
    
    # Method 1: Try Flow Admin API
    Write-Host "    [*] Trying Power Automate Admin API..." -ForegroundColor Gray
    try {
        Invoke-StealthDelay
        
        # Get environments
        $envUrl = "$($script:FlowApiEndpoint)/providers/Microsoft.ProcessSimple/scopes/admin/environments?api-version=2016-11-01"
        $envResponse = Invoke-RestMethod -Method GET -Uri $envUrl -Headers $headers -ErrorAction Stop
        
        if ($envResponse -and $envResponse.value) {
            $environments = $envResponse.value
            Write-Host "    [+] Found $($environments.Count) environments" -ForegroundColor Green
            
            foreach ($env in $environments) {
                $envName = $env.name
                $envDisplay = $env.properties.displayName
                
                # Get flows in this environment
                $flowsUrl = "$($script:FlowApiEndpoint)/providers/Microsoft.ProcessSimple/scopes/admin/environments/$envName/flows?api-version=2016-11-01"
                try {
                    Invoke-StealthDelay
                    $flowsResponse = Invoke-RestMethod -Method GET -Uri $flowsUrl -Headers $headers -ErrorAction SilentlyContinue
                    
                    if ($flowsResponse -and $flowsResponse.value) {
                        foreach ($flow in $flowsResponse.value) {
                            $props = $flow.properties
                            
                            # Extract connector information
                            $connectorsUsed = @()
                            $sensitiveConnectors = @()
                            
                            if ($props.connectionReferences) {
                                foreach ($connProp in ($props.connectionReferences.PSObject.Properties)) {
                                    $connInfo = $connProp.Value
                                    $connId = $connProp.Name
                                    $connType = if ($connInfo.id) { $connInfo.id.Split("/")[-1].ToLower() } else { $connId.ToLower() }
                                    $connName = if ($connInfo.displayName) { $connInfo.displayName } else { $connType }
                                    
                                    $connectorsUsed += [PSCustomObject]@{
                                        Id = $connType
                                        Name = $connName
                                        ConnectionId = $connInfo.connectionId
                                    }
                                    
                                    # Check if it's a sensitive connector
                                    if ($script:SensitiveConnectors.ContainsKey($connType)) {
                                        $sensitiveInfo = $script:SensitiveConnectors[$connType]
                                        $sensitiveConnectors += [PSCustomObject]@{
                                            ConnectorId = $connType
                                            DisplayName = $sensitiveInfo.Name
                                            Risk = $sensitiveInfo.Risk
                                            Category = $sensitiveInfo.Category
                                        }
                                    }
                                }
                            }
                            
                            # Check for high-risk actions in flow definition
                            $highRiskActions = @()
                            if ($props.definition -and $props.definition.actions) {
                                foreach ($action in ($props.definition.actions.PSObject.Properties)) {
                                    $actionName = $action.Name
                                    foreach ($riskAction in $script:HighRiskActions) {
                                        if ($actionName -like "*$riskAction*") {
                                            $highRiskActions += $actionName
                                            break
                                        }
                                    }
                                }
                            }
                            
                            # Determine overall risk level
                            $riskLevel = "LOW"
                            if ($sensitiveConnectors | Where-Object { $_.Risk -eq "CRITICAL" }) {
                                $riskLevel = "CRITICAL"
                            }
                            elseif ($sensitiveConnectors | Where-Object { $_.Risk -eq "HIGH" }) {
                                $riskLevel = "HIGH"
                            }
                            elseif ($sensitiveConnectors | Where-Object { $_.Risk -eq "MEDIUM" }) {
                                $riskLevel = "MEDIUM"
                            }
                            
                            # Elevate risk if high-risk actions found
                            if ($highRiskActions.Count -gt 0 -and $riskLevel -eq "LOW") {
                                $riskLevel = "MEDIUM"
                            }
                            elseif ($highRiskActions.Count -gt 0 -and $riskLevel -eq "MEDIUM") {
                                $riskLevel = "HIGH"
                            }
                            
                            $flowInfo = [PSCustomObject]@{
                                ResourceType = "Power Automate Flow"
                                Id = $flow.name
                                DisplayName = $props.displayName
                                Environment = $envDisplay
                                EnvironmentId = $envName
                                Owner = if ($props.creator) { $props.creator.userDisplayName } else { "Unknown" }
                                OwnerEmail = if ($props.creator) { $props.creator.userPrincipalName } else { "" }
                                OwnerId = if ($props.creator) { $props.creator.userId } else { "" }
                                CreatedTime = $props.createdTime
                                LastModifiedTime = $props.lastModifiedTime
                                State = $props.state
                                FlowType = if ($props.definitionSummary) { $props.definitionSummary.type } else { "" }
                                Triggers = if ($props.definitionSummary -and $props.definitionSummary.triggers) { ($props.definitionSummary.triggers | ForEach-Object { $_.type }) -join ", " } else { "" }
                                ConnectorCount = $connectorsUsed.Count
                                Connectors = ($connectorsUsed | ForEach-Object { $_.Name }) -join ", "
                                HasSensitiveConnector = ($sensitiveConnectors.Count -gt 0)
                                SensitiveConnectorCount = $sensitiveConnectors.Count
                                SensitiveConnectors = ($sensitiveConnectors | ForEach-Object { "$($_.DisplayName) ($($_.Risk))" }) -join ", "
                                HasHighRiskActions = ($highRiskActions.Count -gt 0)
                                HighRiskActions = ($highRiskActions -join ", ")
                                RiskLevel = $riskLevel
                                Source = "AdminAPI"
                            }
                            $allFlows += $flowInfo
                        }
                    }
                }
                catch {
                    # Environment flows may not be accessible
                }
            }
            
            if ($allFlows.Count -gt 0) {
                Write-Host "    [+] Found $($allFlows.Count) flows via Admin API" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "    [-] Admin API not accessible (requires Power Platform Admin role)" -ForegroundColor Yellow
    }
    
    # Method 2: Try user-scoped Flow API
    if ($allFlows.Count -eq 0) {
        Write-Host "    [*] Trying user-scoped Power Automate API..." -ForegroundColor Gray
        try {
            Invoke-StealthDelay
            $userFlowsUrl = "$($script:FlowApiEndpoint)/providers/Microsoft.ProcessSimple/flows?api-version=2016-11-01"
            $userResponse = Invoke-RestMethod -Method GET -Uri $userFlowsUrl -Headers $headers -ErrorAction Stop
            
            if ($userResponse -and $userResponse.value) {
                foreach ($flow in $userResponse.value) {
                    $props = $flow.properties
                    
                    # Extract connector information
                    $connectorsUsed = @()
                    $sensitiveConnectors = @()
                    
                    if ($props.connectionReferences) {
                        foreach ($connProp in ($props.connectionReferences.PSObject.Properties)) {
                            $connInfo = $connProp.Value
                            $connId = $connProp.Name
                            $connType = if ($connInfo.id) { $connInfo.id.Split("/")[-1].ToLower() } else { $connId.ToLower() }
                            $connName = if ($connInfo.displayName) { $connInfo.displayName } else { $connType }
                            
                            $connectorsUsed += [PSCustomObject]@{
                                Id = $connType
                                Name = $connName
                                ConnectionId = $connInfo.connectionId
                            }
                            
                            if ($script:SensitiveConnectors.ContainsKey($connType)) {
                                $sensitiveInfo = $script:SensitiveConnectors[$connType]
                                $sensitiveConnectors += [PSCustomObject]@{
                                    ConnectorId = $connType
                                    DisplayName = $sensitiveInfo.Name
                                    Risk = $sensitiveInfo.Risk
                                    Category = $sensitiveInfo.Category
                                }
                            }
                        }
                    }
                    
                    # Check for high-risk actions
                    $highRiskActions = @()
                    if ($props.definition -and $props.definition.actions) {
                        foreach ($action in ($props.definition.actions.PSObject.Properties)) {
                            $actionName = $action.Name
                            foreach ($riskAction in $script:HighRiskActions) {
                                if ($actionName -like "*$riskAction*") {
                                    $highRiskActions += $actionName
                                    break
                                }
                            }
                        }
                    }
                    
                    $riskLevel = "LOW"
                    if ($sensitiveConnectors | Where-Object { $_.Risk -eq "CRITICAL" }) {
                        $riskLevel = "CRITICAL"
                    }
                    elseif ($sensitiveConnectors | Where-Object { $_.Risk -eq "HIGH" }) {
                        $riskLevel = "HIGH"
                    }
                    elseif ($sensitiveConnectors | Where-Object { $_.Risk -eq "MEDIUM" }) {
                        $riskLevel = "MEDIUM"
                    }
                    
                    if ($highRiskActions.Count -gt 0 -and $riskLevel -eq "LOW") {
                        $riskLevel = "MEDIUM"
                    }
                    elseif ($highRiskActions.Count -gt 0 -and $riskLevel -eq "MEDIUM") {
                        $riskLevel = "HIGH"
                    }
                    
                    $flowInfo = [PSCustomObject]@{
                        ResourceType = "Power Automate Flow"
                        Id = $flow.name
                        DisplayName = $props.displayName
                        Environment = if ($props.environment) { $props.environment.name } else { "" }
                        EnvironmentId = if ($props.environment) { $props.environment.id } else { "" }
                        Owner = if ($props.creator) { $props.creator.userDisplayName } else { "Unknown" }
                        OwnerEmail = if ($props.creator) { $props.creator.userPrincipalName } else { "" }
                        OwnerId = if ($props.creator) { $props.creator.userId } else { "" }
                        CreatedTime = $props.createdTime
                        LastModifiedTime = $props.lastModifiedTime
                        State = $props.state
                        FlowType = if ($props.definitionSummary) { $props.definitionSummary.type } else { "" }
                        Triggers = if ($props.definitionSummary -and $props.definitionSummary.triggers) { ($props.definitionSummary.triggers | ForEach-Object { $_.type }) -join ", " } else { "" }
                        ConnectorCount = $connectorsUsed.Count
                        Connectors = ($connectorsUsed | ForEach-Object { $_.Name }) -join ", "
                        HasSensitiveConnector = ($sensitiveConnectors.Count -gt 0)
                        SensitiveConnectorCount = $sensitiveConnectors.Count
                        SensitiveConnectors = ($sensitiveConnectors | ForEach-Object { "$($_.DisplayName) ($($_.Risk))" }) -join ", "
                        HasHighRiskActions = ($highRiskActions.Count -gt 0)
                        HighRiskActions = ($highRiskActions -join ", ")
                        RiskLevel = $riskLevel
                        Source = "UserAPI"
                    }
                    $allFlows += $flowInfo
                }
                
                if ($allFlows.Count -gt 0) {
                    Write-Host "    [+] Found $($allFlows.Count) flows via User API" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Host "    [-] User API not accessible" -ForegroundColor Yellow
        }
    }
    
    if ($allFlows.Count -eq 0) {
        Write-Host "    [!] No Power Automate flows found (you may not own any or lack permissions)" -ForegroundColor Yellow
        Write-Host "    Note: Requires Power Platform Admin or Environment Maker permissions" -ForegroundColor Gray
    }
    
    $script:TotalFlowsScanned = $allFlows.Count
    return $allFlows
}

# Main scanning function
function Start-PowerPlatformScan {
    Write-Host "`n[*] Starting Power Platform scan..." -ForegroundColor Cyan
    
    # Enumerate Power Apps
    $script:PowerAppsData = Get-PowerApps
    
    # Enumerate Power Automate flows
    $script:PowerAutomateFlowsData = Get-PowerAutomateFlows
    
    Write-Host "`n[+] Scan complete!" -ForegroundColor Green
    Write-Host "[+] Power Apps found: $($script:PowerAppsData.Count)" -ForegroundColor Green
    Write-Host "[+] Power Automate flows found: $($script:PowerAutomateFlowsData.Count)" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - POWER PLATFORM RESOURCES" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    $allResources = @()
    $allResources += $script:PowerAppsData
    $allResources += $script:PowerAutomateFlowsData
    
    # Apply filters
    if ($OnlyHighRisk) {
        $allResources = $allResources | Where-Object { $_.RiskLevel -eq "CRITICAL" -or $_.RiskLevel -eq "HIGH" }
    }
    
    if ($OnlySensitiveConnectors) {
        $allResources = $allResources | Where-Object { $_.HasSensitiveConnector -eq $true }
    }
    
    if ($allResources.Count -eq 0) {
        Write-Host "`n[+] No resources found matching the specified filters." -ForegroundColor Green
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $allResources | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Type';Expression={$_.ResourceType}},
        @{Name='Display Name';Expression={$_.DisplayName}},
        @{Name='Environment';Expression={$_.Environment}},
        @{Name='Owner';Expression={$_.Owner}},
        @{Name='Connectors';Expression={if($_.ConnectorCount -gt 0){"$($_.ConnectorCount)"}else{'0'}}},
        @{Name='Sensitive Connectors';Expression={if($_.HasSensitiveConnector){$_.SensitiveConnectorCount}else{'0'}}},
        @{Name='High-Risk Actions';Expression={if($_.HasHighRiskActions){'Yes'}else{'No'}}},
        @{Name='Status';Expression={if($_.Status){$_.Status}elseif($_.State){$_.State}else{'-'}}}
    
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
    Write-Host "Total Power Apps analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalAppsScanned -ForegroundColor Yellow
    
    Write-Host "Total Power Automate flows analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalFlowsScanned -ForegroundColor Yellow
    
    Write-Host "Resources in results: " -NoNewline -ForegroundColor White
    Write-Host $allResources.Count -ForegroundColor Yellow
    
    $powerApps = ($allResources | Where-Object { $_.ResourceType -eq "Power App" }).Count
    $flows = ($allResources | Where-Object { $_.ResourceType -eq "Power Automate Flow" }).Count
    
    Write-Host "  - Power Apps: " -NoNewline -ForegroundColor White
    Write-Host $powerApps -ForegroundColor Cyan
    
    Write-Host "  - Power Automate Flows: " -NoNewline -ForegroundColor White
    Write-Host $flows -ForegroundColor Cyan
    
    $criticalRisk = ($allResources | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($allResources | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($allResources | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($allResources | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "`n[RISK BREAKDOWN]" -ForegroundColor Cyan
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Red
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Yellow
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    $withSensitive = ($allResources | Where-Object { $_.HasSensitiveConnector -eq $true }).Count
    Write-Host "`n[SECURITY METRICS]" -ForegroundColor Cyan
    Write-Host "  - Resources with sensitive connectors: " -NoNewline -ForegroundColor White
    Write-Host $withSensitive -ForegroundColor $(if($withSensitive -gt 0){"Red"}else{"Green"})
    
    $withHighRiskActions = ($allResources | Where-Object { $_.HasHighRiskActions -eq $true }).Count
    Write-Host "  - Flows with high-risk actions: " -NoNewline -ForegroundColor White
    Write-Host $withHighRiskActions -ForegroundColor $(if($withHighRiskActions -gt 0){"Yellow"}else{"Green"})
    
    # Group by environment
    $byEnvironment = $allResources | Where-Object { $_.Environment } | Group-Object Environment | Sort-Object Count -Descending
    if ($byEnvironment.Count -gt 0) {
        Write-Host "`n[RESOURCES BY ENVIRONMENT]" -ForegroundColor Cyan
        $byEnvironment | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Group by owner
    $byOwner = $allResources | Where-Object { $_.Owner -and $_.Owner -ne "Unknown" } | Group-Object Owner | Sort-Object Count -Descending
    if ($byOwner.Count -gt 0) {
        Write-Host "`n[TOP OWNERS]" -ForegroundColor Cyan
        $byOwner | Select-Object -First 10 | ForEach-Object {
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
    
    Write-Host "`nTotal Power Apps scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalAppsScanned -ForegroundColor Yellow
    
    Write-Host "Total Power Automate flows scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalFlowsScanned -ForegroundColor Yellow
    
    $allResources = @()
    $allResources += $script:PowerAppsData
    $allResources += $script:PowerAutomateFlowsData
    
    # Apply filters
    if ($OnlyHighRisk) {
        $allResources = $allResources | Where-Object { $_.RiskLevel -eq "CRITICAL" -or $_.RiskLevel -eq "HIGH" }
    }
    
    if ($OnlySensitiveConnectors) {
        $allResources = $allResources | Where-Object { $_.HasSensitiveConnector -eq $true }
    }
    
    Write-Host "Resources in results: " -NoNewline -ForegroundColor White
    Write-Host $allResources.Count -ForegroundColor Yellow
    
    if ($allResources.Count -gt 0) {
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "POWER PLATFORM RESOURCES:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $allResources | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host "$($_.ResourceType): $($_.DisplayName)" -ForegroundColor White
            
            Write-Host "  Environment: $($_.Environment)" -ForegroundColor Gray
            Write-Host "  Owner: $($_.Owner)" -ForegroundColor Gray
            if ($_.OwnerEmail) {
                Write-Host "  Owner Email: $($_.OwnerEmail)" -ForegroundColor Gray
            }
            
            if ($_.CreatedTime) {
                Write-Host "  Created: $($_.CreatedTime)" -ForegroundColor Gray
            }
            if ($_.LastModifiedTime) {
                Write-Host "  Last Modified: $($_.LastModifiedTime)" -ForegroundColor Gray
            }
            
            if ($_.Status) {
                Write-Host "  Status: $($_.Status)" -ForegroundColor Gray
            }
            elseif ($_.State) {
                Write-Host "  State: $($_.State)" -ForegroundColor Gray
            }
            
            Write-Host "  Connectors: " -NoNewline -ForegroundColor Gray
            Write-Host "$($_.ConnectorCount) connector(s)" -ForegroundColor $(if($_.ConnectorCount -gt 0){"Cyan"}else{"Gray"})
            
            if ($_.Connectors) {
                Write-Host "  Connector List: $($_.Connectors)" -ForegroundColor DarkGray
            }
            
            if ($_.HasSensitiveConnector) {
                Write-Host "  Sensitive Connectors: " -NoNewline -ForegroundColor Gray
                Write-Host "$($_.SensitiveConnectorCount) found" -ForegroundColor Red
                Write-Host "    $($_.SensitiveConnectors)" -ForegroundColor DarkRed
            }
            
            if ($_.HasHighRiskActions) {
                Write-Host "  High-Risk Actions: " -NoNewline -ForegroundColor Gray
                Write-Host "Yes" -ForegroundColor Yellow
                Write-Host "    $($_.HighRiskActions)" -ForegroundColor DarkYellow
            }
            
            if ($_.FlowType) {
                Write-Host "  Flow Type: $($_.FlowType)" -ForegroundColor Gray
            }
            if ($_.Triggers) {
                Write-Host "  Triggers: $($_.Triggers)" -ForegroundColor Gray
            }
            
            if ($_.SharedUsers) {
                Write-Host "  Shared Users: $($_.SharedUsers)" -ForegroundColor Gray
            }
            if ($_.SharedGroups) {
                Write-Host "  Shared Groups: $($_.SharedGroups)" -ForegroundColor Gray
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[+] No resources found matching the specified filters." -ForegroundColor Green
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
    
    $allResources = @()
    $allResources += $script:PowerAppsData
    $allResources += $script:PowerAutomateFlowsData
    
    # Apply filters
    if ($OnlyHighRisk) {
        $allResources = $allResources | Where-Object { $_.RiskLevel -eq "CRITICAL" -or $_.RiskLevel -eq "HIGH" }
    }
    
    if ($OnlySensitiveConnectors) {
        $allResources = $allResources | Where-Object { $_.HasSensitiveConnector -eq $true }
    }
    
    if ($allResources.Count -eq 0) {
        Write-Host "`n[*] No resources to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        # Prepare data for export
        $exportData = $allResources | ForEach-Object {
            [PSCustomObject]@{
                ResourceType = $_.ResourceType
                Id = $_.Id
                DisplayName = $_.DisplayName
                Environment = $_.Environment
                EnvironmentId = $_.EnvironmentId
                Owner = $_.Owner
                OwnerEmail = $_.OwnerEmail
                OwnerId = $_.OwnerId
                CreatedTime = $_.CreatedTime
                LastModifiedTime = $_.LastModifiedTime
                Status = $_.Status
                State = $_.State
                AppType = $_.AppType
                FlowType = $_.FlowType
                Triggers = $_.Triggers
                ConnectorCount = $_.ConnectorCount
                Connectors = $_.Connectors
                HasSensitiveConnector = $_.HasSensitiveConnector
                SensitiveConnectorCount = $_.SensitiveConnectorCount
                SensitiveConnectors = $_.SensitiveConnectors
                HasHighRiskActions = $_.HasHighRiskActions
                HighRiskActions = $_.HighRiskActions
                RiskLevel = $_.RiskLevel
                SharedUsers = $_.SharedUsers
                SharedGroups = $_.SharedGroups
                Source = $_.Source
            }
        }
        
        switch ($extension) {
            ".csv" {
                $exportData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
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
        Start-PowerPlatformScan
        
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
        
        Write-Host "`n[*] Power Platform check completed successfully!" -ForegroundColor Green
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

