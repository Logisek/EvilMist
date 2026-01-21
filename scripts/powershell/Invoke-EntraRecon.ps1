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
    Enumerates users from Azure Entra ID using ALL available fallback methods.

.DESCRIPTION
    This script includes ALL enumeration methods for restricted environments:
    - Direct /users endpoint
    - People API
    - Manager chain
    - Direct reports
    - Group membership
    - Microsoft Search API
    - Calendar attendees
    - Email recipients
    - OneDrive sharing
    - Teams rosters
    - Planner assignees
    - SharePoint profiles
    - Azure Resource Manager
    - Meeting rooms/resources

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

.EXAMPLE
    .\Enumerate-EntraUsers.ps1

.EXAMPLE
    .\Enumerate-EntraUsers.ps1 -ExportPath "users.csv"

.EXAMPLE
    .\Enumerate-EntraUsers.ps1 -TenantId "your-tenant-id" -UseAzCliToken

.EXAMPLE
    .\Enumerate-EntraUsers.ps1 -EnableStealth
    # Enables stealth mode with 500ms delay + 300ms jitter

.EXAMPLE
    .\Enumerate-EntraUsers.ps1 -RequestDelay 2 -RequestJitter 1
    # Custom delay: 2 seconds base + random jitter between -1 and +1 seconds

.EXAMPLE
    .\Enumerate-EntraUsers.ps1 -EnableStealth -QuietStealth -ExportPath "users.json"
    # Stealth mode without verbose output, export results
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
    [switch]$QuietStealth
)

# PowerShell 7+ required
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] This script requires PowerShell 7 or later.' -ForegroundColor Red
    Write-Host ('Current version: PowerShell ' + $PSVersionTable.PSVersion.ToString()) -ForegroundColor Yellow
    Write-Host 'Download PowerShell 7: https://aka.ms/powershell-release?tag=stable' -ForegroundColor Cyan
    exit 1
}

$ErrorActionPreference = "Continue"

# Scope hierarchy
$script:ScopesFull = @("User.Read.All", "User.ReadBasic.All")
$script:ScopesBasic = @("User.ReadBasic.All")
$script:ScopesMinimal = @("User.Read")

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:CurrentUserId = $null

# ============================================================================
# STEALTH & EVASION CONFIGURATION
# ============================================================================

# Stealth mode settings (can be overridden by parameters)
$script:StealthConfig = @{
    Enabled = $EnableStealth.IsPresent
    BaseDelay = $RequestDelay                    # Base delay between requests (seconds)
    Jitter = $RequestJitter                      # Random jitter range (seconds)
    MaxRetries = $MaxRetries                     # Max retries on throttling
    QuietMode = $QuietStealth.IsPresent          # Suppress stealth-related output
    RequestCount = 0                             # Track total requests made
    ThrottleCount = 0                            # Track throttle events
    LastRequestTime = $null                      # Track timing for rate limiting
}

# If stealth is enabled but no delay specified, use sensible defaults
if ($EnableStealth.IsPresent -and $RequestDelay -eq 0) {
    $script:StealthConfig.BaseDelay = 0.5        # 500ms default delay
    $script:StealthConfig.Jitter = 0.3           # 300ms jitter
}

# Power Platform API Endpoints
$script:PowerAppsApiEndpoint = "https://api.powerapps.com"
$script:FlowApiEndpoint = "https://api.flow.microsoft.com"
$script:BapApiEndpoint = "https://api.bap.microsoft.com"

# Sensitive connector types for Power Automate flows - potential data exfiltration/lateral movement
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

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

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
    Write-Host "    Entra ID Reconnaissance - EvilMist Toolkit" -ForegroundColor Yellow
    Write-Host "    https://logisek.com | info@logisek.com"
    Write-Host "    GNU General Public License v3.0"
    Write-Host ""
    Write-Host ""
}

# ============================================================================
# STEALTH & EVASION FUNCTIONS
# ============================================================================

function Get-StealthDelay {
    <#
    .SYNOPSIS
        Calculate delay with jitter for stealth operations.
    .DESCRIPTION
        Returns a delay value in seconds that includes the base delay plus
        a random jitter component to avoid predictable request patterns.
    #>
    
    $baseDelay = $script:StealthConfig.BaseDelay
    $jitter = $script:StealthConfig.Jitter
    
    if ($baseDelay -eq 0 -and $jitter -eq 0) {
        return 0
    }
    
    # Add random jitter (can be positive or negative)
    $jitterValue = 0
    if ($jitter -gt 0) {
        $jitterValue = (Get-Random -Minimum (-$jitter * 1000) -Maximum ($jitter * 1000)) / 1000
    }
    
    $totalDelay = [Math]::Max(0, $baseDelay + $jitterValue)
    return $totalDelay
}

function Invoke-StealthDelay {
    <#
    .SYNOPSIS
        Apply stealth delay before making a request.
    .DESCRIPTION
        Implements configurable delays with jitter to avoid detection patterns.
        Only applies delay if stealth mode is enabled or explicit delay is set.
    #>
    param(
        [switch]$Force,
        [string]$Context = ""
    )
    
    if (-not $script:StealthConfig.Enabled -and $script:StealthConfig.BaseDelay -eq 0) {
        return
    }
    
    $delay = Get-StealthDelay
    
    if ($delay -gt 0) {
        if (-not $script:StealthConfig.QuietMode -and $Context) {
            Write-Host "    [Stealth] Waiting $([Math]::Round($delay, 2))s before $Context..." -ForegroundColor DarkGray
        }
        Start-Sleep -Milliseconds ([int]($delay * 1000))
    }
    
    $script:StealthConfig.LastRequestTime = Get-Date
}

function Get-ThrottleRetryAfter {
    <#
    .SYNOPSIS
        Extract Retry-After value from response headers.
    .DESCRIPTION
        Parses the Retry-After header from Microsoft Graph API throttling responses.
        Returns the number of seconds to wait before retrying.
    #>
    param(
        [hashtable]$Headers,
        [int]$DefaultWait = 30
    )
    
    if ($Headers -and $Headers.ContainsKey('Retry-After')) {
        $retryAfter = $Headers['Retry-After']
        
        # Try to parse as integer (seconds)
        $seconds = 0
        if ([int]::TryParse($retryAfter, [ref]$seconds)) {
            return $seconds
        }
        
        # Try to parse as HTTP-date
        $dateTime = [DateTime]::MinValue
        if ([DateTime]::TryParse($retryAfter, [ref]$dateTime)) {
            $seconds = [int]([Math]::Ceiling(($dateTime - (Get-Date)).TotalSeconds))
            return [Math]::Max(1, $seconds)
        }
    }
    
    # Check for RateLimit-Reset header (Unix timestamp)
    if ($Headers -and $Headers.ContainsKey('RateLimit-Reset')) {
        $resetTime = $Headers['RateLimit-Reset']
        $unixTime = 0
        if ([long]::TryParse($resetTime, [ref]$unixTime)) {
            $resetDateTime = [DateTimeOffset]::FromUnixTimeSeconds($unixTime).LocalDateTime
            $seconds = [int]([Math]::Ceiling(($resetDateTime - (Get-Date)).TotalSeconds))
            return [Math]::Max(1, $seconds)
        }
    }
    
    return $DefaultWait
}

function Wait-ForThrottleReset {
    <#
    .SYNOPSIS
        Wait for throttle reset with countdown display.
    .DESCRIPTION
        Waits for the specified duration showing progress, used when
        Graph API returns 429 Too Many Requests.
    #>
    param(
        [int]$Seconds,
        [switch]$Quiet
    )
    
    $script:StealthConfig.ThrottleCount++
    
    if ($Quiet -or $script:StealthConfig.QuietMode) {
        Start-Sleep -Seconds $Seconds
        return
    }
    
    Write-Host "    [Throttle] Rate limited. Waiting $Seconds seconds..." -ForegroundColor Yellow
    
    for ($i = $Seconds; $i -gt 0; $i--) {
        Write-Progress -Activity "Throttled by Graph API" -Status "Waiting $i seconds..." -PercentComplete ((($Seconds - $i) / $Seconds) * 100)
        Start-Sleep -Seconds 1
    }
    
    Write-Progress -Activity "Throttled by Graph API" -Completed
    Write-Host "    [Throttle] Resuming operations..." -ForegroundColor Green
}

function Show-StealthStatus {
    <#
    .SYNOPSIS
        Display current stealth configuration and statistics.
    #>
    
    Write-Host "`n" -NoNewline
    Write-Host ("-" * 50) -ForegroundColor Gray
    Write-Host "STEALTH & EVASION STATUS" -ForegroundColor Magenta
    Write-Host ("-" * 50) -ForegroundColor Gray
    
    $status = if ($script:StealthConfig.Enabled) { "ENABLED" } else { "DISABLED" }
    $statusColor = if ($script:StealthConfig.Enabled) { "Green" } else { "Yellow" }
    
    Write-Host "  Stealth Mode:    " -NoNewline -ForegroundColor Cyan
    Write-Host $status -ForegroundColor $statusColor
    
    Write-Host "  Base Delay:      $($script:StealthConfig.BaseDelay)s" -ForegroundColor Cyan
    Write-Host "  Jitter Range:    +/- $($script:StealthConfig.Jitter)s" -ForegroundColor Cyan
    Write-Host "  Max Retries:     $($script:StealthConfig.MaxRetries)" -ForegroundColor Cyan
    Write-Host "  Quiet Mode:      $($script:StealthConfig.QuietMode)" -ForegroundColor Cyan
    
    if ($script:StealthConfig.RequestCount -gt 0) {
        Write-Host "`n  Requests Made:   $($script:StealthConfig.RequestCount)" -ForegroundColor Gray
        Write-Host "  Throttle Events: $($script:StealthConfig.ThrottleCount)" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 50) -ForegroundColor Gray
}

# ============================================================================
# USER HELPER FUNCTIONS
# ============================================================================

function Get-CurrentUserId {
    if ($script:CurrentUserId) {
        return $script:CurrentUserId
    }
    
    try {
        $context = Get-MgContext
        if ($context -and $context.Account) {
            $me = Get-MgUser -UserId $context.Account -ErrorAction SilentlyContinue
            if ($me -and $me.Id) {
                $script:CurrentUserId = $me.Id
                return $script:CurrentUserId
            }
        }
        
        $me = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/me" -ErrorAction SilentlyContinue
        if ($me -and $me.id) {
            $script:CurrentUserId = $me.id
            return $script:CurrentUserId
        }
    }
    catch {
        Write-Host "[!] Could not determine current user ID: $_" -ForegroundColor Yellow
    }
    
    return $null
}

function Invoke-GraphRequest {
    <#
    .SYNOPSIS
        Make a Graph API request with stealth features and throttle handling.
    .DESCRIPTION
        Wrapper for Invoke-MgGraphRequest that implements:
        - Configurable delays between requests
        - Random jitter to avoid detection patterns
        - Automatic retry on 429 (Too Many Requests)
        - Respects Retry-After headers from Graph API
    #>
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Body = $null,
        [switch]$SkipDelay,
        [string]$Context = "request"
    )
    
    # Apply stealth delay before request (unless skipped)
    if (-not $SkipDelay) {
        Invoke-StealthDelay -Context $Context
    }
    
    $script:StealthConfig.RequestCount++
    $retryCount = 0
    $maxRetries = $script:StealthConfig.MaxRetries
    
    while ($retryCount -le $maxRetries) {
        try {
            $response = $null
            $responseHeaders = @{}
            
            if ($Body) {
                $response = Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body -ErrorAction Stop -ResponseHeadersVariable responseHeaders
            }
            else {
                $response = Invoke-MgGraphRequest -Method $Method -Uri $Uri -ErrorAction Stop -ResponseHeadersVariable responseHeaders
            }
            
            return $response
        }
        catch {
            $statusCode = $null
            $retryAfter = 30
            
            # Extract status code from exception
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            elseif ($_.Exception.Message -match '(\d{3})') {
                $statusCode = [int]$Matches[1]
            }
            
            # Handle 429 Too Many Requests (throttling)
            if ($statusCode -eq 429) {
                if ($retryCount -ge $maxRetries) {
                    if (-not $script:StealthConfig.QuietMode) {
                        Write-Host "    [!] Max retries ($maxRetries) exceeded for throttling" -ForegroundColor Red
                    }
                    return $null
                }
                
                # Try to get Retry-After from response headers
                if ($_.Exception.Response.Headers) {
                    try {
                        $retryAfterHeader = $_.Exception.Response.Headers | Where-Object { $_.Key -eq 'Retry-After' }
                        if ($retryAfterHeader) {
                            $parsed = 0
                            if ([int]::TryParse($retryAfterHeader.Value, [ref]$parsed)) {
                                $retryAfter = $parsed
                            }
                        }
                    }
                    catch {
                        # Use default retry after
                    }
                }
                
                # Add jitter to retry delay to avoid thundering herd
                $jitterMs = Get-Random -Minimum 0 -Maximum 5000
                $totalWait = $retryAfter + ($jitterMs / 1000)
                
                Wait-ForThrottleReset -Seconds ([int][Math]::Ceiling($totalWait))
                
                $retryCount++
                continue
            }
            
            # Handle 503 Service Unavailable (temporary issues)
            if ($statusCode -eq 503) {
                if ($retryCount -lt $maxRetries) {
                    $backoffSeconds = [Math]::Pow(2, $retryCount) * 5  # Exponential backoff
                    if (-not $script:StealthConfig.QuietMode) {
                        Write-Host "    [!] Service unavailable. Backing off for $backoffSeconds seconds..." -ForegroundColor Yellow
                    }
                    Start-Sleep -Seconds $backoffSeconds
                    $retryCount++
                    continue
                }
            }
            
            # For other errors, don't retry
            return $null
        }
    }
    
    return $null
}

# Check if Microsoft.Graph module is installed
function Test-GraphModule {
    Write-Host "[*] Checking Microsoft.Graph PowerShell module..." -ForegroundColor Cyan
    
    $modules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Groups",
        "Microsoft.Graph.People",
        "Microsoft.Graph.Calendar",
        "Microsoft.Graph.Mail",
        "Microsoft.Graph.Files",
        "Microsoft.Graph.Teams",
        "Microsoft.Graph.Planner",
        "Microsoft.Graph.Sites",
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
        
        Write-Host "[+] Modules imported successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to import modules: $_" -ForegroundColor Red
        Write-Host "[*] Try running: Update-Module Microsoft.Graph -Force" -ForegroundColor Yellow
        return $false
    }
}

# ============================================================================
# AUTHENTICATION
# ============================================================================

function Get-AzCliToken {
    param([string]$Resource = "https://graph.microsoft.com")
    
    Write-Host "[*] Attempting to get token from Azure CLI..." -ForegroundColor Cyan
    
    try {
        $result = az account get-access-token --resource $Resource 2>$null | ConvertFrom-Json
        
        if ($result -and $result.accessToken) {
            Write-Host "[+] Successfully obtained token from Azure CLI" -ForegroundColor Green
            $script:CurrentAuthMethod = "AzureCLI"
            $script:AccessToken = $result.accessToken
            return $result.accessToken
        }
    }
    catch {
        Write-Host "[!] Azure CLI not available: $_" -ForegroundColor Yellow
    }
    
    return $null
}

function Get-AzPowerShellToken {
    Write-Host "[*] Attempting to get token from Azure PowerShell..." -ForegroundColor Cyan
    
    try {
        if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
            return $null
        }
        
        Import-Module Az.Accounts -ErrorAction Stop
        $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
        
        if ($token -and $token.Token) {
            Write-Host "[+] Successfully obtained token from Azure PowerShell" -ForegroundColor Green
            $script:CurrentAuthMethod = "AzurePowerShell"
            $script:AccessToken = $token.Token
            return $token.Token
        }
    }
    catch {
        Write-Host "[!] Azure PowerShell not available: $_" -ForegroundColor Yellow
    }
    
    return $null
}

function Connect-ToGraphWithFallback {
    param(
        [string]$Tenant,
        [array]$Scopes
    )
    
    Write-Host "[*] Attempting connection with scopes: $($Scopes -join ', ')..." -ForegroundColor Cyan
    
    $connectParams = @{
        Scopes = $Scopes
        NoWelcome = $true
    }
    
    if ($Tenant) {
        $connectParams.TenantId = $Tenant
    }
    
    try {
        Connect-MgGraph @connectParams -ErrorAction Stop
        $context = Get-MgContext
        Write-Host "[+] Connected as: $($context.Account)" -ForegroundColor Green
        Write-Host "    Tenant: $($context.TenantId)" -ForegroundColor Gray
        $script:CurrentScopes = $Scopes
        $script:CurrentAuthMethod = "MgGraph"
        
        $userId = Get-CurrentUserId
        if ($userId) {
            Write-Host "    User ID: $userId" -ForegroundColor Gray
        }
        
        return $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match "AADSTS65001|consent|permission") {
            Write-Host "[!] Consent denied for scopes: $($Scopes -join ', ')" -ForegroundColor Yellow
        }
        else {
            Write-Host "[!] Connection failed: $errorMessage" -ForegroundColor Yellow
        }
        return $false
    }
}

function Connect-ToGraph {
    param([string]$Tenant)

    Write-Host ("`n" + ("-" * 50)) -ForegroundColor Gray
    Write-Host "AUTHENTICATION STRATEGY" -ForegroundColor Cyan
    Write-Host ("-" * 50) -ForegroundColor Gray

    if ($UseAzCliToken) {
        $token = Get-AzCliToken
        if ($token) {
            try {
                Connect-MgGraph -AccessToken (ConvertTo-SecureString $token -AsPlainText -Force) -NoWelcome
                $script:CurrentUserId = $null
                Get-CurrentUserId | Out-Null
                return $true
            }
            catch {
                Write-Host "[!] Failed to use Azure CLI token: $_" -ForegroundColor Yellow
            }
        }
    }
    
    if ($UseAzPowerShellToken) {
        $token = Get-AzPowerShellToken
        if ($token) {
            try {
                Connect-MgGraph -AccessToken (ConvertTo-SecureString $token -AsPlainText -Force) -NoWelcome
                $script:CurrentUserId = $null
                Get-CurrentUserId | Out-Null
                return $true
            }
            catch {
                Write-Host "[!] Failed to use Azure PowerShell token: $_" -ForegroundColor Yellow
            }
        }
    }
    
    $scopeLevels = @(
        @{ Name = "Basic read"; Scopes = $script:ScopesBasic },
        @{ Name = "Full access"; Scopes = $script:ScopesFull },
        @{ Name = "Minimal"; Scopes = $script:ScopesMinimal }
    )
    
    foreach ($level in $scopeLevels) {
        Write-Host "`n[*] Trying: $($level.Name)" -ForegroundColor Cyan
        if (Connect-ToGraphWithFallback -Tenant $Tenant -Scopes $level.Scopes) {
            return $true
        }
    }
    
    Write-Host "`n[!] All authentication methods failed." -ForegroundColor Red
    return $false
}

# ============================================================================
# DIRECT ENUMERATION
# ============================================================================

function Get-EntraUsers {
    Write-Host "[*] Trying direct /users endpoint..." -ForegroundColor Cyan

    $properties = @(
        "Id", "DisplayName", "UserPrincipalName", "Mail",
        "GivenName", "Surname", "JobTitle", "Department",
        "OfficeLocation", "AccountEnabled", "UserType"
    )

    try {
        $users = Get-MgUser -All -Property $properties -ErrorAction Stop | Select-Object $properties
        Write-Host "[+] Found $($users.Count) users via direct endpoint" -ForegroundColor Green
        return $users
    }
    catch {
        Write-Host "[!] Direct endpoint: Access denied or error" -ForegroundColor Yellow
        return @()
    }
}

function Search-EntraUser {
    param([string]$SearchTerm)

    Write-Host "[*] Searching for '$SearchTerm'..." -ForegroundColor Cyan

    try {
        $filter = "startsWith(displayName,'$SearchTerm') or startsWith(mail,'$SearchTerm') or startsWith(userPrincipalName,'$SearchTerm')"
        $users = Get-MgUser -Filter $filter -Property DisplayName, UserPrincipalName, Mail, JobTitle, Department
        return $users
    }
    catch {
        Write-Host "[!] Search error: $_" -ForegroundColor Red
        return @()
    }
}

# ============================================================================
# BASIC ALTERNATIVE METHODS
# ============================================================================

function Get-PeopleApi {
    Write-Host "[*] Trying People API..." -ForegroundColor Cyan
    
    try {
        $userId = Get-CurrentUserId
        if (-not $userId) {
            Write-Host "[!] People API: Cannot get user ID" -ForegroundColor Yellow
            return @()
        }
        
        Import-Module Microsoft.Graph.People -ErrorAction SilentlyContinue
        $people = Get-MgUserPerson -UserId $userId -Top 1000 -ErrorAction Stop
        
        if ($people) {
            Write-Host "[+] Found $($people.Count) people via People API" -ForegroundColor Green
            
            $users = $people | ForEach-Object {
                [PSCustomObject]@{
                    Id = $_.Id
                    DisplayName = $_.DisplayName
                    UserPrincipalName = $_.UserPrincipalName
                    Mail = if ($_.ScoredEmailAddresses) { $_.ScoredEmailAddresses[0].Address } else { "" }
                    JobTitle = $_.JobTitle
                    Department = $_.Department
                    Source = "PeopleAPI"
                }
            }
            return $users
        }
    }
    catch {
        Write-Host "[!] People API: Access denied or error" -ForegroundColor Yellow
    }
    
    return @()
}

function Get-ManagerChain {
    Write-Host "[*] Trying manager chain..." -ForegroundColor Cyan
    
    $managers = @()
    $visited = @{}
    
    try {
        $currentId = Get-CurrentUserId
        if (-not $currentId) { return @() }
        
        while ($true) {
            try {
                $manager = Get-MgUserManager -UserId $currentId -ErrorAction Stop
                if (-not $manager -or $visited.ContainsKey($manager.Id)) { break }
                
                $visited[$manager.Id] = $true
                $managerDetails = Get-MgUser -UserId $manager.Id -ErrorAction SilentlyContinue
                
                if ($managerDetails) {
                    $managers += [PSCustomObject]@{
                        Id = $managerDetails.Id
                        DisplayName = $managerDetails.DisplayName
                        UserPrincipalName = $managerDetails.UserPrincipalName
                        Mail = $managerDetails.Mail
                        JobTitle = $managerDetails.JobTitle
                        Department = $managerDetails.Department
                        Source = "ManagerChain"
                    }
                }
                $currentId = $manager.Id
            }
            catch { break }
        }
        
        if ($managers.Count -gt 0) {
            Write-Host "[+] Found $($managers.Count) managers" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Manager chain: No results" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Manager chain: Error" -ForegroundColor Yellow
    }
    
    return $managers
}

function Get-DirectReportsUsers {
    Write-Host "[*] Trying direct reports..." -ForegroundColor Cyan
    
    try {
        $userId = Get-CurrentUserId
        if (-not $userId) { return @() }
        
        $reports = Get-MgUserDirectReport -UserId $userId -All -ErrorAction Stop
        
        if ($reports) {
            Write-Host "[+] Found $($reports.Count) direct reports" -ForegroundColor Green
            
            $users = $reports | ForEach-Object {
                $details = Get-MgUser -UserId $_.Id -ErrorAction SilentlyContinue
                if ($details) {
                    [PSCustomObject]@{
                        Id = $details.Id
                        DisplayName = $details.DisplayName
                        UserPrincipalName = $details.UserPrincipalName
                        Mail = $details.Mail
                        JobTitle = $details.JobTitle
                        Department = $details.Department
                        Source = "DirectReports"
                    }
                }
            }
            return $users
        }
    }
    catch {
        Write-Host "[!] Direct reports: Access denied" -ForegroundColor Yellow
    }
    
    return @()
}

function Get-GroupMembersUsers {
    Write-Host "[*] Trying group membership..." -ForegroundColor Cyan
    
    $allUsers = @()
    $seenUsers = @{}
    
    try {
        $userId = Get-CurrentUserId
        if (-not $userId) { return @() }
        
        Import-Module Microsoft.Graph.Groups -ErrorAction SilentlyContinue
        $memberships = Get-MgUserMemberOf -UserId $userId -All -ErrorAction Stop
        $groups = $memberships | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }
        
        Write-Host "    Found $($groups.Count) groups" -ForegroundColor Gray
        
        foreach ($group in $groups) {
            try {
                $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
                
                foreach ($member in $members) {
                    if ($member.'@odata.type' -eq '#microsoft.graph.user' -and -not $seenUsers.ContainsKey($member.Id)) {
                        $seenUsers[$member.Id] = $true
                        $userDetails = Get-MgUser -UserId $member.Id -ErrorAction SilentlyContinue
                        
                        if ($userDetails) {
                            $allUsers += [PSCustomObject]@{
                                Id = $userDetails.Id
                                DisplayName = $userDetails.DisplayName
                                UserPrincipalName = $userDetails.UserPrincipalName
                                Mail = $userDetails.Mail
                                JobTitle = $userDetails.JobTitle
                                Department = $userDetails.Department
                                Source = "GroupMember"
                            }
                        }
                    }
                }
            }
            catch { continue }
        }
        
        if ($allUsers.Count -gt 0) {
            Write-Host "[+] Found $($allUsers.Count) users via groups" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Group membership: No results" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Group membership: Error" -ForegroundColor Yellow
    }
    
    return $allUsers
}

# ============================================================================
# ADVANCED FALLBACK METHODS
# ============================================================================

function Get-UsersViaSearchApi {
    Write-Host "[*] Trying Microsoft Search API..." -ForegroundColor Cyan
    
    $allPeople = @()
    $seenIds = @{}
    
    $searchQueries = @("*", "a*", "b*", "c*", "d*", "e*")
    
    foreach ($query in $searchQueries) {
        try {
            $body = @{
                requests = @(
                    @{
                        entityTypes = @("person")
                        query = @{ queryString = $query }
                    }
                )
            }
            
            $result = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/search/query" -Method "POST" -Body $body
            
            if ($result -and $result.value) {
                foreach ($response in $result.value) {
                    $hits = $response.hitsContainers
                    foreach ($container in $hits) {
                        foreach ($hit in $container.hits) {
                            $resource = $hit.resource
                            $personId = $resource.id
                            if ($personId -and -not $seenIds.ContainsKey($personId)) {
                                $seenIds[$personId] = $true
                                $allPeople += [PSCustomObject]@{
                                    Id = $personId
                                    DisplayName = $resource.displayName
                                    UserPrincipalName = $resource.userPrincipalName
                                    Mail = if ($resource.emailAddresses) { $resource.emailAddresses[0].address } else { "" }
                                    JobTitle = $resource.jobTitle
                                    Department = $resource.department
                                    Source = "SearchAPI"
                                }
                            }
                        }
                    }
                }
            }
        }
        catch { continue }
    }
    
    if ($allPeople.Count -gt 0) {
        Write-Host "[+] Found $($allPeople.Count) people via Search API" -ForegroundColor Green
    }
    else {
        Write-Host "[!] Search API: No results" -ForegroundColor Yellow
    }
    
    return $allPeople
}

function Get-UsersFromCalendar {
    Write-Host "[*] Trying calendar attendees..." -ForegroundColor Cyan
    
    $allUsers = @()
    $seenEmails = @{}
    
    try {
        Import-Module Microsoft.Graph.Calendar -ErrorAction SilentlyContinue
        
        $userId = Get-CurrentUserId
        if (-not $userId) { return @() }
        
        $calEvents = Get-MgUserEvent -UserId $userId -Top 100 -ErrorAction Stop
        
        foreach ($calEvent in $calEvents) {
            # Organizer
            $orgEmail = $calEvent.Organizer.EmailAddress.Address
            if ($orgEmail -and -not $seenEmails.ContainsKey($orgEmail.ToLower())) {
                $seenEmails[$orgEmail.ToLower()] = $true
                $allUsers += [PSCustomObject]@{
                    DisplayName = $calEvent.Organizer.EmailAddress.Name
                    Mail = $orgEmail
                    UserPrincipalName = $orgEmail
                    Source = "Calendar"
                }
            }
            
            # Attendees
            foreach ($attendee in $calEvent.Attendees) {
                $attEmail = $attendee.EmailAddress.Address
                if ($attEmail -and -not $seenEmails.ContainsKey($attEmail.ToLower())) {
                    $seenEmails[$attEmail.ToLower()] = $true
                    $allUsers += [PSCustomObject]@{
                        DisplayName = $attendee.EmailAddress.Name
                        Mail = $attEmail
                        UserPrincipalName = $attEmail
                        Source = "Calendar"
                    }
                }
            }
        }
        
        if ($allUsers.Count -gt 0) {
            Write-Host "[+] Found $($allUsers.Count) users from calendar" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Calendar: No results" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Calendar: Access denied or error" -ForegroundColor Yellow
    }
    
    return $allUsers
}

function Get-UsersFromEmails {
    Write-Host "[*] Trying email recipients..." -ForegroundColor Cyan
    
    $allUsers = @()
    $seenEmails = @{}
    
    try {
        Import-Module Microsoft.Graph.Mail -ErrorAction SilentlyContinue
        
        $userId = Get-CurrentUserId
        if (-not $userId) { return @() }
        
        $messages = Get-MgUserMessage -UserId $userId -Top 100 -ErrorAction Stop
        
        foreach ($message in $messages) {
            # Sender
            $senderEmail = $message.From.EmailAddress.Address
            if ($senderEmail -and -not $seenEmails.ContainsKey($senderEmail.ToLower())) {
                $seenEmails[$senderEmail.ToLower()] = $true
                $allUsers += [PSCustomObject]@{
                    DisplayName = $message.From.EmailAddress.Name
                    Mail = $senderEmail
                    UserPrincipalName = $senderEmail
                    Source = "Email"
                }
            }
            
            # To recipients
            foreach ($recipient in $message.ToRecipients) {
                $recipEmail = $recipient.EmailAddress.Address
                if ($recipEmail -and -not $seenEmails.ContainsKey($recipEmail.ToLower())) {
                    $seenEmails[$recipEmail.ToLower()] = $true
                    $allUsers += [PSCustomObject]@{
                        DisplayName = $recipient.EmailAddress.Name
                        Mail = $recipEmail
                        UserPrincipalName = $recipEmail
                        Source = "Email"
                    }
                }
            }
            
            # CC recipients
            foreach ($recipient in $message.CcRecipients) {
                $recipEmail = $recipient.EmailAddress.Address
                if ($recipEmail -and -not $seenEmails.ContainsKey($recipEmail.ToLower())) {
                    $seenEmails[$recipEmail.ToLower()] = $true
                    $allUsers += [PSCustomObject]@{
                        DisplayName = $recipient.EmailAddress.Name
                        Mail = $recipEmail
                        UserPrincipalName = $recipEmail
                        Source = "Email"
                    }
                }
            }
        }
        
        if ($allUsers.Count -gt 0) {
            Write-Host "[+] Found $($allUsers.Count) users from email" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Email: No results" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Email: Access denied or error" -ForegroundColor Yellow
    }
    
    return $allUsers
}

function Get-UsersFromOneDrive {
    Write-Host "[*] Trying OneDrive sharing..." -ForegroundColor Cyan
    
    $allUsers = @()
    $seenEmails = @{}
    
    try {
        Import-Module Microsoft.Graph.Files -ErrorAction SilentlyContinue
        
        $userId = Get-CurrentUserId
        if (-not $userId) { return @() }
        
        $sharedItems = Get-MgUserDriveSharedWithMe -UserId $userId -ErrorAction Stop
        
        foreach ($item in $sharedItems) {
            $sharedBy = $item.RemoteItem.Shared.SharedBy.User
            if ($sharedBy -and $sharedBy.Email) {
                $email = $sharedBy.Email.ToLower()
                if (-not $seenEmails.ContainsKey($email)) {
                    $seenEmails[$email] = $true
                    $allUsers += [PSCustomObject]@{
                        Id = $sharedBy.Id
                        DisplayName = $sharedBy.DisplayName
                        Mail = $sharedBy.Email
                        UserPrincipalName = $sharedBy.Email
                        Source = "OneDrive"
                    }
                }
            }
        }
        
        if ($allUsers.Count -gt 0) {
            Write-Host "[+] Found $($allUsers.Count) users from OneDrive" -ForegroundColor Green
        }
        else {
            Write-Host "[!] OneDrive: No results" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] OneDrive: Access denied or error" -ForegroundColor Yellow
    }
    
    return $allUsers
}

function Get-UsersFromTeams {
    Write-Host "[*] Trying Teams rosters..." -ForegroundColor Cyan
    
    $allUsers = @()
    $seenIds = @{}
    
    try {
        Import-Module Microsoft.Graph.Teams -ErrorAction SilentlyContinue
        
        $userId = Get-CurrentUserId
        if (-not $userId) { return @() }
        
        $teams = Get-MgUserJoinedTeam -UserId $userId -ErrorAction Stop
        
        foreach ($team in $teams) {
            try {
                $members = Get-MgTeamMember -TeamId $team.Id -ErrorAction SilentlyContinue
                
                foreach ($member in $members) {
                    $memberId = $member.AdditionalProperties.userId
                    if ($memberId -and -not $seenIds.ContainsKey($memberId)) {
                        $seenIds[$memberId] = $true
                        $allUsers += [PSCustomObject]@{
                            Id = $memberId
                            DisplayName = $member.DisplayName
                            Mail = $member.AdditionalProperties.email
                            UserPrincipalName = $member.AdditionalProperties.email
                            Source = "Teams"
                        }
                    }
                }
            }
            catch { continue }
        }
        
        if ($allUsers.Count -gt 0) {
            Write-Host "[+] Found $($allUsers.Count) users from Teams" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Teams: No results" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Teams: Access denied or error" -ForegroundColor Yellow
    }
    
    return $allUsers
}

function Get-UsersFromPlanner {
    Write-Host "[*] Trying Planner tasks..." -ForegroundColor Cyan
    
    $allUsers = @()
    $seenIds = @{}
    
    try {
        Import-Module Microsoft.Graph.Planner -ErrorAction SilentlyContinue
        
        $userId = Get-CurrentUserId
        if (-not $userId) { return @() }
        
        $tasks = Get-MgUserPlannerTask -UserId $userId -ErrorAction Stop
        
        foreach ($task in $tasks) {
            # Assignees
            if ($task.Assignments) {
                foreach ($assigneeId in $task.Assignments.PSObject.Properties.Name) {
                    if ($assigneeId -and -not $seenIds.ContainsKey($assigneeId)) {
                        $seenIds[$assigneeId] = $true
                        $userDetails = Get-MgUser -UserId $assigneeId -ErrorAction SilentlyContinue
                        if ($userDetails) {
                            $allUsers += [PSCustomObject]@{
                                Id = $userDetails.Id
                                DisplayName = $userDetails.DisplayName
                                UserPrincipalName = $userDetails.UserPrincipalName
                                Mail = $userDetails.Mail
                                Source = "Planner"
                            }
                        }
                    }
                }
            }
        }
        
        if ($allUsers.Count -gt 0) {
            Write-Host "[+] Found $($allUsers.Count) users from Planner" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Planner: No results" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Planner: Access denied or error" -ForegroundColor Yellow
    }
    
    return $allUsers
}

function Get-UsersFromSharePoint {
    Write-Host "[*] Trying SharePoint profiles..." -ForegroundColor Cyan
    
    $allUsers = @()
    $seenIds = @{}
    
    try {
        Import-Module Microsoft.Graph.Sites -ErrorAction SilentlyContinue
        
        $site = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/sites/root"
        
        if ($site -and $site.id) {
            $siteId = $site.id.Split(",")[0]
            $permissions = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/sites/$siteId/permissions"
            
            if ($permissions -and $permissions.value) {
                foreach ($perm in $permissions.value) {
                    $user = $perm.grantedTo.user
                    if ($user -and $user.id -and -not $seenIds.ContainsKey($user.id)) {
                        $seenIds[$user.id] = $true
                        $allUsers += [PSCustomObject]@{
                            Id = $user.id
                            DisplayName = $user.displayName
                            Mail = $user.email
                            UserPrincipalName = $user.email
                            Source = "SharePoint"
                        }
                    }
                }
            }
        }
        
        if ($allUsers.Count -gt 0) {
            Write-Host "[+] Found $($allUsers.Count) users from SharePoint" -ForegroundColor Green
        }
        else {
            Write-Host "[!] SharePoint: No results" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] SharePoint: Access denied or error" -ForegroundColor Yellow
    }
    
    return $allUsers
}

function Get-UsersFromAzureRM {
    Write-Host "[*] Trying Azure Resource Manager..." -ForegroundColor Cyan
    
    $allUsers = @()
    $seenIds = @{}
    
    try {
        $armToken = Get-AzCliToken -Resource "https://management.azure.com"
        if (-not $armToken) {
            Write-Host "[!] ARM: Cannot get ARM token" -ForegroundColor Yellow
            return @()
        }
        
        $headers = @{
            "Authorization" = "Bearer $armToken"
            "Content-Type" = "application/json"
        }
        
        # Get subscriptions
        $subs = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" -Headers $headers -ErrorAction Stop
        
        foreach ($sub in $subs.value) {
            try {
                $roleAssignments = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$($sub.subscriptionId)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" -Headers $headers -ErrorAction SilentlyContinue
                
                foreach ($assignment in $roleAssignments.value) {
                    $principalId = $assignment.properties.principalId
                    $principalType = $assignment.properties.principalType
                    
                    if ($principalId -and $principalType -eq "User" -and -not $seenIds.ContainsKey($principalId)) {
                        $seenIds[$principalId] = $true
                        
                        # Try to resolve user via Graph
                        $userDetails = Get-MgUser -UserId $principalId -ErrorAction SilentlyContinue
                        if ($userDetails) {
                            $allUsers += [PSCustomObject]@{
                                Id = $userDetails.Id
                                DisplayName = $userDetails.DisplayName
                                UserPrincipalName = $userDetails.UserPrincipalName
                                Mail = $userDetails.Mail
                                Source = "AzureRM"
                            }
                        }
                        else {
                            $allUsers += [PSCustomObject]@{
                                Id = $principalId
                                DisplayName = ""
                                UserPrincipalName = ""
                                Mail = ""
                                Source = "AzureRM"
                            }
                        }
                    }
                }
            }
            catch { continue }
        }
        
        if ($allUsers.Count -gt 0) {
            Write-Host "[+] Found $($allUsers.Count) users from Azure RM" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Azure RM: No results" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Azure RM: Error - $_" -ForegroundColor Yellow
    }
    
    return $allUsers
}

function Get-RoomsAndResources {
    Write-Host "[*] Trying rooms/resources..." -ForegroundColor Cyan
    
    $allResources = @()
    $seenEmails = @{}
    
    try {
        # Room lists
        $roomLists = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/places/microsoft.graph.roomList"
        if ($roomLists -and $roomLists.value) {
            foreach ($roomList in $roomLists.value) {
                $email = $roomList.emailAddress
                if ($email -and -not $seenEmails.ContainsKey($email.ToLower())) {
                    $seenEmails[$email.ToLower()] = $true
                    $allResources += [PSCustomObject]@{
                        DisplayName = $roomList.displayName
                        Mail = $email
                        ResourceType = "RoomList"
                        Source = "Rooms"
                    }
                }
            }
        }
        
        # Rooms
        $rooms = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/places/microsoft.graph.room"
        if ($rooms -and $rooms.value) {
            foreach ($room in $rooms.value) {
                $email = $room.emailAddress
                if ($email -and -not $seenEmails.ContainsKey($email.ToLower())) {
                    $seenEmails[$email.ToLower()] = $true
                    $allResources += [PSCustomObject]@{
                        DisplayName = $room.displayName
                        Mail = $email
                        ResourceType = "Room"
                        Building = $room.building
                        Source = "Rooms"
                    }
                }
            }
        }
        
        if ($allResources.Count -gt 0) {
            Write-Host "[+] Found $($allResources.Count) rooms/resources" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Rooms: No results" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Rooms: Access denied or error" -ForegroundColor Yellow
    }
    
    return $allResources
}

function Get-UsersFromYammer {
    <#
    .SYNOPSIS
        Enumerate users from Yammer/Viva Engage communities.
    .DESCRIPTION
        Viva Engage communities backed by M365 Groups can be enumerated via Graph API.
        Also attempts direct Yammer REST API for legacy communities.
        Requires Group.Read.All or Community.Read.All permission.
    #>
    Write-Host "[*] Trying Yammer/Viva Engage community enumeration..." -ForegroundColor Cyan
    
    $allUsers = @()
    $seenIds = @{}
    
    try {
        # Method 1: Try to get Viva Engage communities via Graph API
        # Communities are M365 Groups with a specific resource provisioning option
        
        # First try to get groups with Yammer provisioning
        $yammerGroups = @()
        
        try {
            $groups = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c eq 'Unified')&`$select=id,displayName,mail,description,groupTypes,resourceProvisioningOptions&`$top=999"
            
            if ($groups -and $groups.value) {
                # Filter for Yammer-connected groups
                foreach ($group in $groups.value) {
                    $resourceOptions = $group.resourceProvisioningOptions
                    if ($resourceOptions -and ($resourceOptions -contains "YammerFeed" -or ($resourceOptions | Where-Object { $_ -like "*yammer*" }))) {
                        $yammerGroups += $group
                    }
                }
                
                # If no explicit Yammer groups found, try first 20 M365 groups
                if ($yammerGroups.Count -eq 0) {
                    $yammerGroups = $groups.value | Select-Object -First 20
                }
                
                Write-Host "[*] Found $($yammerGroups.Count) potential Viva Engage communities" -ForegroundColor Gray
                
                # Get members from each community
                foreach ($group in $yammerGroups) {
                    $groupId = $group.id
                    if (-not $groupId) { continue }
                    
                    try {
                        $members = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id,displayName,mail,userPrincipalName,jobTitle,department"
                        
                        if ($members -and $members.value) {
                            foreach ($member in $members.value) {
                                # Only include user objects
                                $odataType = $member.'@odata.type'
                                if ($odataType -eq '#microsoft.graph.user' -or -not $odataType) {
                                    $memberId = $member.id
                                    if ($memberId -and -not $seenIds.ContainsKey($memberId)) {
                                        $seenIds[$memberId] = $true
                                        $groupDisplayName = if ($group.displayName.Length -gt 20) { $group.displayName.Substring(0, 20) } else { $group.displayName }
                                        $allUsers += [PSCustomObject]@{
                                            Id = $memberId
                                            DisplayName = $member.displayName
                                            Mail = $member.mail
                                            UserPrincipalName = $member.userPrincipalName
                                            JobTitle = $member.jobTitle
                                            Department = $member.department
                                            Source = "Yammer-$groupDisplayName"
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch { continue }
                }
            }
        }
        catch {
            Write-Host "[!] Viva Engage Graph API: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Method 2: Try direct Yammer REST API (for legacy/standalone Yammer)
        try {
            $context = Get-MgContext
            if ($context -and $context.AccessToken) {
                $yammerHeaders = @{
                    "Authorization" = "Bearer $($context.AccessToken)"
                    "Content-Type" = "application/json"
                }
                
                $yammerResponse = Invoke-RestMethod -Uri "https://www.yammer.com/api/v1/users.json?page=1&per_page=50" -Headers $yammerHeaders -TimeoutSec 10 -ErrorAction SilentlyContinue
                
                if ($yammerResponse) {
                    Write-Host "[*] Yammer REST API returned $($yammerResponse.Count) users" -ForegroundColor Gray
                    foreach ($yammerUser in $yammerResponse) {
                        $userId = if ($yammerUser.guid) { $yammerUser.guid } else { $yammerUser.id }
                        $email = $yammerUser.email
                        
                        # Use email as dedup key for Yammer users
                        $dedupKey = if ($email) { $email.ToLower() } else { [string]$userId }
                        if ($dedupKey -and -not $seenIds.ContainsKey($dedupKey)) {
                            $seenIds[$dedupKey] = $true
                            $allUsers += [PSCustomObject]@{
                                Id = $yammerUser.guid
                                DisplayName = $yammerUser.full_name
                                Mail = $email
                                UserPrincipalName = $email
                                JobTitle = $yammerUser.job_title
                                Department = $yammerUser.department
                                Source = "Yammer-REST-API"
                            }
                        }
                    }
                }
            }
        }
        catch {
            if ($_.Exception.Message -like "*401*") {
                Write-Host "[!] Yammer REST API: Token not valid for Yammer (normal for Graph-only tokens)" -ForegroundColor Yellow
            }
            else {
                Write-Host "[!] Yammer REST API: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        # Method 3: Try to get users from user's Yammer groups via Graph
        try {
            $userId = Get-CurrentUserId
            if ($userId) {
                $myGroups = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/me/memberOf?`$select=id,displayName,resourceProvisioningOptions,groupTypes"
                
                if ($myGroups -and $myGroups.value) {
                    foreach ($group in $myGroups.value) {
                        $resourceOptions = $group.resourceProvisioningOptions
                        if ($resourceOptions -and $resourceOptions -contains "YammerFeed") {
                            $groupId = $group.id
                            if ($groupId) {
                                try {
                                    $members = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id,displayName,mail,userPrincipalName"
                                    
                                    if ($members -and $members.value) {
                                        foreach ($member in $members.value) {
                                            $memberId = $member.id
                                            if ($memberId -and -not $seenIds.ContainsKey($memberId)) {
                                                $seenIds[$memberId] = $true
                                                $allUsers += [PSCustomObject]@{
                                                    Id = $memberId
                                                    DisplayName = $member.displayName
                                                    Mail = $member.mail
                                                    UserPrincipalName = $member.userPrincipalName
                                                    Source = "Yammer-MyGroups"
                                                }
                                            }
                                        }
                                    }
                                }
                                catch { continue }
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "[!] Yammer MyGroups: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        if ($allUsers.Count -gt 0) {
            Write-Host "[+] Found $($allUsers.Count) users from Yammer/Viva Engage" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Yammer/Viva Engage: No users found or access denied" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Yammer/Viva Engage: Error - $_" -ForegroundColor Yellow
    }
    
    return $allUsers
}

# ============================================================================
# SECURITY ASSESSMENT FEATURES
# ============================================================================

function Get-UserMFAStatus {
    <#
    .SYNOPSIS
        Enumerate MFA status for all users using authentication methods.
    #>
    Write-Host "[*] Enumerating user MFA status..." -ForegroundColor Cyan
    Write-Host "    (This may take a while for large directories)" -ForegroundColor Gray
    
    $usersWithMFA = @()
    $mfaEnabled = 0
    $mfaDisabled = 0
    $checkFailed = 0
    
    try {
        # Get all users first
        $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Mail, UserType -ErrorAction Stop
        Write-Host "    Checking MFA status for $($users.Count) users..." -ForegroundColor Gray
        
        $counter = 0
        foreach ($user in $users) {
            $counter++
            
            try {
                # Get authentication methods for this user
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                
                $mfaMethods = @()
                $hasStrongMFA = $false
                
                foreach ($method in $authMethods) {
                    $methodType = $method.AdditionalProperties.'@odata.type'
                    
                    switch -Wildcard ($methodType) {
                        "*microsoftAuthenticator*" { $mfaMethods += "Authenticator App"; $hasStrongMFA = $true }
                        "*phoneAuthentication*" { $mfaMethods += "Phone"; $hasStrongMFA = $true }
                        "*fido2*" { $mfaMethods += "FIDO2 Key"; $hasStrongMFA = $true }
                        "*windowsHelloForBusiness*" { $mfaMethods += "Windows Hello"; $hasStrongMFA = $true }
                        "*softwareOath*" { $mfaMethods += "Software TOTP"; $hasStrongMFA = $true }
                        "*temporaryAccessPass*" { $mfaMethods += "Temp Access Pass" }
                        "*email*" { $mfaMethods += "Email" }
                        "*password*" { $mfaMethods += "Password" }
                    }
                }
                
                if ($hasStrongMFA) { $mfaEnabled++ } else { $mfaDisabled++ }
                
                $usersWithMFA += [PSCustomObject]@{
                    Id = $user.Id
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    Mail = $user.Mail
                    UserType = $user.UserType
                    HasMFA = $hasStrongMFA
                    MFAMethods = ($mfaMethods -join ", ")
                    RiskLevel = if ($hasStrongMFA) { "LOW" } else { "HIGH" }
                }
            }
            catch {
                $checkFailed++
                $usersWithMFA += [PSCustomObject]@{
                    Id = $user.Id
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    Mail = $user.Mail
                    UserType = $user.UserType
                    HasMFA = "Unknown"
                    MFAMethods = "Access Denied"
                    RiskLevel = "UNKNOWN"
                }
            }
            
            if ($counter % 50 -eq 0) {
                Write-Host "    Processed $counter/$($users.Count) users..." -ForegroundColor Gray
            }
        }
        
        Write-Host "`n[+] MFA Status Summary:" -ForegroundColor Green
        Write-Host "    - MFA Enabled: $mfaEnabled" -ForegroundColor Green
        Write-Host "    - MFA Disabled (HIGH RISK): $mfaDisabled" -ForegroundColor $(if ($mfaDisabled -gt 0) { "Red" } else { "Green" })
        Write-Host "    - Check Failed: $checkFailed" -ForegroundColor Yellow
    }
    catch {
        Write-Host "[!] MFA status check failed: $_" -ForegroundColor Red
    }
    
    return $usersWithMFA
}

function Get-MFARegistrationReport {
    <#
    .SYNOPSIS
        Alternative MFA check using reports endpoint.
    #>
    Write-Host "[*] Trying MFA registration report..." -ForegroundColor Cyan
    
    $registrations = @()
    
    try {
        $uri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails"
        $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        foreach ($reg in $result.value) {
            $registrations += [PSCustomObject]@{
                Id = $reg.id
                UserPrincipalName = $reg.userPrincipalName
                DisplayName = $reg.userDisplayName
                IsMfaRegistered = $reg.isMfaRegistered
                IsMfaCapable = $reg.isMfaCapable
                IsPasswordlessCapable = $reg.isPasswordlessCapable
                IsSsprRegistered = $reg.isSsprRegistered
                IsSsprEnabled = $reg.isSsprEnabled
                MethodsRegistered = ($reg.methodsRegistered -join ", ")
                RiskLevel = if ($reg.isMfaRegistered) { "LOW" } else { "HIGH" }
            }
        }
        
        # Handle pagination
        while ($result.'@odata.nextLink') {
            $result = Invoke-MgGraphRequest -Method GET -Uri $result.'@odata.nextLink' -ErrorAction Stop
            foreach ($reg in $result.value) {
                $registrations += [PSCustomObject]@{
                    Id = $reg.id
                    UserPrincipalName = $reg.userPrincipalName
                    DisplayName = $reg.userDisplayName
                    IsMfaRegistered = $reg.isMfaRegistered
                    IsMfaCapable = $reg.isMfaCapable
                    IsPasswordlessCapable = $reg.isPasswordlessCapable
                    IsSsprRegistered = $reg.isSsprRegistered
                    IsSsprEnabled = $reg.isSsprEnabled
                    MethodsRegistered = ($reg.methodsRegistered -join ", ")
                    RiskLevel = if ($reg.isMfaRegistered) { "LOW" } else { "HIGH" }
                }
            }
        }
        
        if ($registrations.Count -gt 0) {
            $mfaRegistered = ($registrations | Where-Object { $_.IsMfaRegistered -eq $true }).Count
            Write-Host "[+] Found $($registrations.Count) users" -ForegroundColor Green
            Write-Host "    - MFA Registered: $mfaRegistered" -ForegroundColor Green
            Write-Host "    - MFA Not Registered (HIGH RISK): $($registrations.Count - $mfaRegistered)" -ForegroundColor $(if (($registrations.Count - $mfaRegistered) -gt 0) { "Red" } else { "Green" })
        }
    }
    catch {
        Write-Host "[!] MFA report: Access denied or not available" -ForegroundColor Yellow
    }
    
    return $registrations
}

function Get-PrivilegedUsers {
    <#
    .SYNOPSIS
        Enumerate users with privileged Azure AD roles.
    #>
    Write-Host "[*] Enumerating privileged role assignments..." -ForegroundColor Cyan
    
    $privilegedRoles = @{
        "Global Administrator" = "CRITICAL"
        "Privileged Role Administrator" = "CRITICAL"
        "Privileged Authentication Administrator" = "CRITICAL"
        "Partner Tier2 Support" = "CRITICAL"
        "User Administrator" = "HIGH"
        "Exchange Administrator" = "HIGH"
        "SharePoint Administrator" = "HIGH"
        "Teams Administrator" = "HIGH"
        "Intune Administrator" = "HIGH"
        "Application Administrator" = "HIGH"
        "Cloud Application Administrator" = "HIGH"
        "Authentication Administrator" = "HIGH"
        "Password Administrator" = "HIGH"
        "Helpdesk Administrator" = "MEDIUM"
        "Security Administrator" = "HIGH"
        "Security Reader" = "LOW"
        "Conditional Access Administrator" = "HIGH"
        "Groups Administrator" = "MEDIUM"
        "License Administrator" = "LOW"
        "Directory Readers" = "LOW"
    }
    
    $privilegedUsers = @()
    $seenAssignments = @{}
    
    try {
        # Get all directory roles with members
        $roles = Get-MgDirectoryRole -ExpandProperty Members -ErrorAction Stop
        
        foreach ($role in $roles) {
            $roleName = $role.DisplayName
            $riskLevel = if ($privilegedRoles.ContainsKey($roleName)) { $privilegedRoles[$roleName] } else { "MEDIUM" }
            
            foreach ($member in $role.Members) {
                if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                    $assignmentKey = "$($member.Id)_$($role.Id)"
                    
                    if (-not $seenAssignments.ContainsKey($assignmentKey)) {
                        $seenAssignments[$assignmentKey] = $true
                        
                        $privilegedUsers += [PSCustomObject]@{
                            Id = $member.Id
                            DisplayName = $member.AdditionalProperties.displayName
                            UserPrincipalName = $member.AdditionalProperties.userPrincipalName
                            Mail = $member.AdditionalProperties.mail
                            Role = $roleName
                            RoleId = $role.Id
                            RiskLevel = $riskLevel
                            AssignmentType = "Active"
                        }
                    }
                }
            }
        }
        
        if ($privilegedUsers.Count -gt 0) {
            $critical = ($privilegedUsers | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
            $high = ($privilegedUsers | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
            
            Write-Host "[+] Found $($privilegedUsers.Count) privileged role assignments" -ForegroundColor Green
            Write-Host "    - CRITICAL: $critical" -ForegroundColor $(if ($critical -gt 0) { "Red" } else { "Green" })
            Write-Host "    - HIGH: $high" -ForegroundColor $(if ($high -gt 0) { "Yellow" } else { "Green" })
        }
    }
    catch {
        Write-Host "[!] Directory roles: $_" -ForegroundColor Yellow
    }
    
    # Check PIM eligible assignments
    Write-Host "[*] Checking PIM eligible role assignments..." -ForegroundColor Cyan
    
    try {
        $uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?`$expand=principal"
        $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        foreach ($schedule in $result.value) {
            $principal = $schedule.principal
            
            if ($principal.'@odata.type' -eq '#microsoft.graph.user') {
                $roleId = $schedule.roleDefinitionId
                $roleName = "Unknown Role"
                
                # Try to get role name
                try {
                    $roleUri = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$roleId'"
                    $roleResult = Invoke-MgGraphRequest -Method GET -Uri $roleUri -ErrorAction SilentlyContinue
                    if ($roleResult.value.Count -gt 0) {
                        $roleName = $roleResult.value[0].displayName
                    }
                }
                catch { }
                
                $riskLevel = if ($privilegedRoles.ContainsKey($roleName)) { $privilegedRoles[$roleName] } else { "MEDIUM" }
                $assignmentKey = "$($principal.id)_${roleId}_eligible"
                
                if (-not $seenAssignments.ContainsKey($assignmentKey)) {
                    $seenAssignments[$assignmentKey] = $true
                    
                    $privilegedUsers += [PSCustomObject]@{
                        Id = $principal.id
                        DisplayName = $principal.displayName
                        UserPrincipalName = $principal.userPrincipalName
                        Mail = $principal.mail
                        Role = $roleName
                        RoleId = $roleId
                        RiskLevel = $riskLevel
                        AssignmentType = "PIM Eligible"
                    }
                }
            }
        }
        
        $pimCount = ($privilegedUsers | Where-Object { $_.AssignmentType -eq "PIM Eligible" }).Count
        if ($pimCount -gt 0) {
            Write-Host "[+] Found $pimCount PIM eligible assignments" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[!] PIM eligibility: Access denied or not available" -ForegroundColor Yellow
    }
    
    return $privilegedUsers
}

function Get-GraphApiPermissionsMap {
    <#
    .SYNOPSIS
        Get Microsoft Graph API permission definitions to resolve IDs to names.
    #>
    $appRolesMap = @{}
    $delegatedScopesMap = @{}
    
    # Microsoft Graph service principal has this well-known appId
    $msGraphAppId = "00000003-0000-0000-c000-000000000000"
    
    try {
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '$msGraphAppId'" -Property AppRoles,Oauth2PermissionScopes -ErrorAction Stop
        
        if ($graphSp) {
            # Map app roles (application permissions)
            foreach ($role in $graphSp.AppRoles) {
                if ($role.Id -and $role.Value) {
                    $appRolesMap[$role.Id] = $role.Value
                }
            }
            
            # Map delegated scopes
            foreach ($scope in $graphSp.Oauth2PermissionScopes) {
                if ($scope.Id -and $scope.Value) {
                    $delegatedScopesMap[$scope.Id] = $scope.Value
                }
            }
        }
    }
    catch {
        Write-Host "[!] Could not fetch Graph permission definitions: $_" -ForegroundColor Yellow
    }
    
    return @{
        AppRoles = $appRolesMap
        DelegatedScopes = $delegatedScopesMap
        GraphSpId = $graphSp.Id
    }
}

function Get-ApplicationOwners {
    param([string]$AppObjectId)
    
    $owners = @()
    try {
        $appOwners = Get-MgApplicationOwner -ApplicationId $AppObjectId -ErrorAction SilentlyContinue
        foreach ($owner in $appOwners) {
            $ownerInfo = ""
            if ($owner.AdditionalProperties.userPrincipalName) {
                $ownerInfo = $owner.AdditionalProperties.userPrincipalName
            } elseif ($owner.AdditionalProperties.displayName) {
                $ownerInfo = $owner.AdditionalProperties.displayName
            } else {
                $ownerInfo = $owner.Id
            }
            if ($ownerInfo) { $owners += $ownerInfo }
        }
    }
    catch { }
    
    return $owners
}

function Get-ServicePrincipalOwners {
    param([string]$SpId)
    
    $owners = @()
    try {
        $spOwners = Get-MgServicePrincipalOwner -ServicePrincipalId $SpId -ErrorAction SilentlyContinue
        foreach ($owner in $spOwners) {
            $ownerInfo = ""
            if ($owner.AdditionalProperties.userPrincipalName) {
                $ownerInfo = $owner.AdditionalProperties.userPrincipalName
            } elseif ($owner.AdditionalProperties.displayName) {
                $ownerInfo = $owner.AdditionalProperties.displayName
            } else {
                $ownerInfo = $owner.Id
            }
            if ($ownerInfo) { $owners += $ownerInfo }
        }
    }
    catch { }
    
    return $owners
}

function Get-ApplicationsAndServicePrincipals {
    <#
    .SYNOPSIS
        Enumerate enterprise applications and service principals.
        
    .DESCRIPTION
        Features:
        - Lists enterprise applications and their owners
        - Enumerates service principals with high privileges
        - Finds app registrations with secrets/certificates
        - Identifies applications with delegated/application permissions to Graph API
    #>
    Write-Host "[*] Enumerating applications and service principals..." -ForegroundColor Cyan
    
    # High-risk permissions to flag (both delegated and application)
    $highRiskPermissions = @(
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All",
        "Application.ReadWrite.All",
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Mail.ReadWrite",
        "Mail.Send",
        "Files.ReadWrite.All",
        "Sites.ReadWrite.All",
        "Exchange.ManageAsApp",
        "full_access_as_app",
        "User.Export.All",
        "Directory.Read.All",
        "AuditLog.Read.All",
        "Policy.ReadWrite.ConditionalAccess",
        "PrivilegedAccess.ReadWrite.AzureAD",
        "PrivilegedAccess.ReadWrite.AzureResources"
    )
    
    # Critical permissions - highest risk
    $criticalPermissions = @(
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All",
        "Application.ReadWrite.All",
        "Directory.ReadWrite.All",
        "PrivilegedAccess.ReadWrite.AzureAD"
    )
    
    $msGraphAppId = "00000003-0000-0000-c000-000000000000"
    
    $results = @{
        Applications = @()
        ServicePrincipals = @()
        HighRiskApps = @()
        AppsWithCredentials = @()
        HighPrivilegeSPs = @()
    }
    
    # Get Graph API permission mappings
    Write-Host "[*] Loading Microsoft Graph permission definitions..." -ForegroundColor Cyan
    $permMaps = Get-GraphApiPermissionsMap
    $appRolesMap = $permMaps.AppRoles
    $delegatedScopesMap = $permMaps.DelegatedScopes
    Write-Host "    Loaded $($appRolesMap.Count) app roles, $($delegatedScopesMap.Count) delegated scopes" -ForegroundColor Gray
    
    # Get app registrations with owners
    Write-Host "[*] Getting app registrations..." -ForegroundColor Cyan
    try {
        $apps = Get-MgApplication -All -Property Id,AppId,DisplayName,CreatedDateTime,SignInAudience,PasswordCredentials,KeyCredentials,RequiredResourceAccess -ErrorAction Stop
        
        foreach ($app in $apps) {
            # Get owners for this app
            $owners = Get-ApplicationOwners -AppObjectId $app.Id
            
            # Analyze required permissions
            $requestedAppPerms = @()
            $requestedDelegatedPerms = @()
            $isHighRisk = $false
            $isCritical = $false
            
            foreach ($resource in $app.RequiredResourceAccess) {
                $resourceAppId = $resource.ResourceAppId
                $isGraph = $resourceAppId -eq $msGraphAppId
                
                foreach ($access in $resource.ResourceAccess) {
                    $permId = $access.Id
                    $permType = $access.Type  # "Role" = application, "Scope" = delegated
                    
                    # Resolve permission name
                    if ($isGraph) {
                        if ($permType -eq "Role") {
                            $permName = if ($appRolesMap.ContainsKey($permId)) { $appRolesMap[$permId] } else { "$($permId.ToString().Substring(0,8))..." }
                            $requestedAppPerms += $permName
                        } else {
                            $permName = if ($delegatedScopesMap.ContainsKey($permId)) { $delegatedScopesMap[$permId] } else { "$($permId.ToString().Substring(0,8))..." }
                            $requestedDelegatedPerms += $permName
                        }
                    } else {
                        $permName = "$($permId.ToString().Substring(0,8))..."
                        if ($permType -eq "Role") {
                            $requestedAppPerms += "[$($resourceAppId.ToString().Substring(0,8))]$permName"
                        } else {
                            $requestedDelegatedPerms += "[$($resourceAppId.ToString().Substring(0,8))]$permName"
                        }
                    }
                    
                    # Check for high-risk permissions
                    foreach ($hrp in $highRiskPermissions) {
                        if ($permName -like "*$hrp*") {
                            $isHighRisk = $true
                            break
                        }
                    }
                    foreach ($cp in $criticalPermissions) {
                        if ($permName -like "*$cp*") {
                            $isCritical = $true
                            break
                        }
                    }
                }
            }
            
            # Check for credentials
            $hasSecrets = $app.PasswordCredentials.Count -gt 0
            $hasCerts = $app.KeyCredentials.Count -gt 0
            
            # Get credential details
            $credentialDetails = @()
            foreach ($secret in $app.PasswordCredentials) {
                if ($secret.EndDateTime) {
                    $credentialDetails += "Secret($($secret.Hint)): $($secret.EndDateTime.ToString('yyyy-MM-dd'))"
                }
            }
            foreach ($cert in $app.KeyCredentials) {
                if ($cert.EndDateTime) {
                    $credentialDetails += "Cert($($cert.Usage)): $($cert.EndDateTime.ToString('yyyy-MM-dd'))"
                }
            }
            
            $appInfo = [PSCustomObject]@{
                Id = $app.Id
                AppId = $app.AppId
                DisplayName = $app.DisplayName
                CreatedDateTime = if ($app.CreatedDateTime) { $app.CreatedDateTime.ToString("yyyy-MM-dd") } else { "" }
                SignInAudience = $app.SignInAudience
                HasSecrets = $hasSecrets
                HasCertificates = $hasCerts
                CredentialDetails = ($credentialDetails | Select-Object -First 3) -join ", "
                Owners = ($owners | Select-Object -First 3) -join ", "
                OwnerCount = $owners.Count
                RequestedAppPermissions = ($requestedAppPerms | Select-Object -First 5) -join ", "
                RequestedDelegatedPermissions = ($requestedDelegatedPerms | Select-Object -First 5) -join ", "
                AppPermissionCount = $requestedAppPerms.Count
                DelegatedPermissionCount = $requestedDelegatedPerms.Count
                IsHighRisk = $isHighRisk
                IsCritical = $isCritical
            }
            
            $results.Applications += $appInfo
            
            if ($hasSecrets -or $hasCerts) {
                $results.AppsWithCredentials += $appInfo
            }
            
            if ($isHighRisk -or $isCritical) {
                $results.HighRiskApps += $appInfo
            }
        }
        
        Write-Host "    Found $($results.Applications.Count) app registrations" -ForegroundColor Gray
        Write-Host "    Apps with credentials: $($results.AppsWithCredentials.Count)" -ForegroundColor Gray
    }
    catch {
        Write-Host "[!] App registrations: $_" -ForegroundColor Yellow
    }
    
    # Get service principals (enterprise apps) with detailed permissions
    Write-Host "[*] Getting service principals (enterprise applications)..." -ForegroundColor Cyan
    try {
        $sps = Get-MgServicePrincipal -All -Property Id,AppId,DisplayName,ServicePrincipalType,AppOwnerOrganizationId,AccountEnabled,Tags -ErrorAction Stop
        
        foreach ($sp in $sps) {
            # Get owners for this service principal
            $owners = Get-ServicePrincipalOwners -SpId $sp.Id
            
            # Get APP ROLE ASSIGNMENTS (application permissions granted TO this SP)
            $grantedAppPermissions = @()
            $hasDangerousAppPerms = $false
            $isCritical = $false
            
            try {
                $roleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
                foreach ($role in $roleAssignments) {
                    $roleId = $role.AppRoleId
                    $resourceDisplayName = $role.ResourceDisplayName
                    
                    # Resolve permission name
                    $permName = if ($appRolesMap.ContainsKey($roleId)) { $appRolesMap[$roleId] } else { "$($roleId.ToString().Substring(0,8))..." }
                    
                    # Format: PermissionName (ResourceName)
                    if ($resourceDisplayName -and $resourceDisplayName -ne "Microsoft Graph") {
                        $grantedAppPermissions += "$permName ($($resourceDisplayName.Substring(0, [Math]::Min(15, $resourceDisplayName.Length))))"
                    } else {
                        $grantedAppPermissions += $permName
                    }
                    
                    # Check for high-risk
                    foreach ($hrp in $highRiskPermissions) {
                        if ($permName -like "*$hrp*") {
                            $hasDangerousAppPerms = $true
                            break
                        }
                    }
                    foreach ($cp in $criticalPermissions) {
                        if ($permName -like "*$cp*") {
                            $isCritical = $true
                            break
                        }
                    }
                }
            }
            catch { }
            
            # Get OAuth2 permission grants (delegated permissions consented for this SP)
            $delegatedPerms = @()
            $delegatedPermDetails = @()
            $hasDangerousDelegated = $false
            
            try {
                $grants = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
                foreach ($grant in $grants) {
                    $scope = $grant.Scope
                    $consentType = $grant.ConsentType  # AllPrincipals or Principal
                    
                    if ($scope) {
                        $perms = $scope.Split(" ")
                        $delegatedPerms += $perms
                        
                        # Check for admin consent (AllPrincipals = tenant-wide)
                        $consentLabel = if ($consentType -eq "AllPrincipals") { "[Admin]" } else { "[User]" }
                        foreach ($perm in $perms) {
                            $delegatedPermDetails += "$consentLabel$perm"
                            
                            # Check for high-risk
                            foreach ($hrp in $highRiskPermissions) {
                                if ($perm -like "*$hrp*") {
                                    $hasDangerousDelegated = $true
                                    break
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            
            # Determine overall risk
            $isHighRisk = $hasDangerousAppPerms -or $hasDangerousDelegated -or $isCritical
            
            # Determine risk level
            $riskLevel = "LOW"
            if ($hasDangerousDelegated) { $riskLevel = "MEDIUM" }
            if ($hasDangerousAppPerms) { $riskLevel = "HIGH" }
            if ($isCritical) { $riskLevel = "CRITICAL" }
            
            $spInfo = [PSCustomObject]@{
                Id = $sp.Id
                AppId = $sp.AppId
                DisplayName = $sp.DisplayName
                Type = $sp.ServicePrincipalType
                AccountEnabled = $sp.AccountEnabled
                AppOwnerOrganizationId = $sp.AppOwnerOrganizationId
                Tags = ($sp.Tags | Select-Object -First 3) -join ", "
                Owners = ($owners | Select-Object -First 3) -join ", "
                OwnerCount = $owners.Count
                GrantedAppPermissions = ($grantedAppPermissions | Select-Object -First 5) -join ", "
                AppPermissionCount = $grantedAppPermissions.Count
                DelegatedPermissions = ($delegatedPermDetails | Select-Object -First 5) -join ", "
                DelegatedPermissionCount = $delegatedPerms.Count
                IsHighRisk = $isHighRisk
                IsCritical = $isCritical
                RiskLevel = $riskLevel
            }
            
            $results.ServicePrincipals += $spInfo
            
            if ($isHighRisk) {
                $results.HighPrivilegeSPs += $spInfo
            }
        }
        
        Write-Host "    Found $($results.ServicePrincipals.Count) service principals" -ForegroundColor Gray
        Write-Host "    High-privilege service principals: $($results.HighPrivilegeSPs.Count)" -ForegroundColor $(if ($results.HighPrivilegeSPs.Count -gt 0) { "Red" } else { "Green" })
        Write-Host "    High-risk app registrations: $($results.HighRiskApps.Count)" -ForegroundColor $(if ($results.HighRiskApps.Count -gt 0) { "Red" } else { "Green" })
    }
    catch {
        Write-Host "[!] Service principals: $_" -ForegroundColor Yellow
    }
    
    return $results
}

function Get-StaleAccounts {
    param(
        [int]$DaysThreshold = 90
    )
    
    <#
    .SYNOPSIS
        Find accounts with no recent sign-in activity.
    #>
    Write-Host "[*] Finding stale accounts (no sign-in > $DaysThreshold days)..." -ForegroundColor Cyan
    
    $staleUsers = @()
    
    try {
        $uri = "https://graph.microsoft.com/beta/users?`$select=id,displayName,userPrincipalName,mail,userType,accountEnabled,signInActivity,createdDateTime&`$top=999"
        
        do {
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            
            foreach ($user in $result.value) {
                $signInActivity = $user.signInActivity
                $lastSignIn = $signInActivity.lastSignInDateTime
                $lastNonInteractive = $signInActivity.lastNonInteractiveSignInDateTime
                
                # Get most recent
                $latestSignIn = $null
                if ($lastSignIn) { $latestSignIn = $lastSignIn }
                if ($lastNonInteractive -and (!$latestSignIn -or $lastNonInteractive -gt $latestSignIn)) {
                    $latestSignIn = $lastNonInteractive
                }
                
                $isStale = $false
                $daysInactive = "Never"
                
                if ($latestSignIn) {
                    try {
                        $signInDate = [DateTime]::Parse($latestSignIn)
                        $daysInactive = ((Get-Date) - $signInDate).Days
                        $isStale = $daysInactive -gt $DaysThreshold
                    }
                    catch {
                        $isStale = $true
                        $daysInactive = "Unknown"
                    }
                }
                else {
                    $isStale = $true
                }
                
                if ($isStale) {
                    $riskLevel = if ($daysInactive -eq "Never") { "CRITICAL" } 
                                 elseif ($daysInactive -is [int] -and $daysInactive -gt 180) { "HIGH" }
                                 else { "MEDIUM" }
                    
                    # Format LastSignIn - handle both DateTime objects and strings
                    $lastSignInFormatted = "Never"
                    if ($latestSignIn) {
                        if ($latestSignIn -is [DateTime]) {
                            $lastSignInFormatted = $latestSignIn.ToString("yyyy-MM-dd")
                        } else {
                            $lastSignInFormatted = "$latestSignIn".Substring(0, [Math]::Min(10, "$latestSignIn".Length))
                        }
                    }
                    
                    # Format CreatedDateTime - handle both DateTime objects and strings
                    $createdFormatted = ""
                    if ($user.createdDateTime) {
                        if ($user.createdDateTime -is [DateTime]) {
                            $createdFormatted = $user.createdDateTime.ToString("yyyy-MM-dd")
                        } else {
                            $createdFormatted = "$($user.createdDateTime)".Substring(0, [Math]::Min(10, "$($user.createdDateTime)".Length))
                        }
                    }
                    
                    $staleUsers += [PSCustomObject]@{
                        Id = $user.id
                        DisplayName = $user.displayName
                        UserPrincipalName = $user.userPrincipalName
                        Mail = $user.mail
                        UserType = $user.userType
                        AccountEnabled = $user.accountEnabled
                        LastSignIn = $lastSignInFormatted
                        DaysInactive = $daysInactive
                        CreatedDateTime = $createdFormatted
                        RiskLevel = $riskLevel
                    }
                }
            }
            
            $uri = $result.'@odata.nextLink'
        } while ($uri)
        
        if ($staleUsers.Count -gt 0) {
            $enabledStale = ($staleUsers | Where-Object { $_.AccountEnabled -eq $true }).Count
            Write-Host "[+] Found $($staleUsers.Count) stale accounts" -ForegroundColor Green
            Write-Host "    - Still enabled (HIGH RISK): $enabledStale" -ForegroundColor $(if ($enabledStale -gt 0) { "Red" } else { "Green" })
            Write-Host "    - Disabled: $($staleUsers.Count - $enabledStale)" -ForegroundColor Gray
        }
        else {
            Write-Host "[!] No stale accounts found" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Sign-in activity: $_" -ForegroundColor Yellow
    }
    
    return $staleUsers
}

function Get-GuestUsers {
    <#
    .SYNOPSIS
        Enumerate guest/external users.
    #>
    Write-Host "[*] Enumerating guest users..." -ForegroundColor Cyan
    
    $guestUsers = @()
    
    try {
        $guests = Get-MgUser -Filter "userType eq 'Guest'" -All -Property Id, DisplayName, UserPrincipalName, Mail, CreatedDateTime, ExternalUserState, AccountEnabled -ErrorAction Stop
        
        foreach ($guest in $guests) {
            $upn = $guest.UserPrincipalName
            $externalDomain = ""
            
            if ($upn -match "#EXT#") {
                try {
                    $externalPart = $upn.Split("#EXT#")[0]
                    $externalDomain = $externalPart.Split("_")[-1]
                }
                catch { }
            }
            
            $guestUsers += [PSCustomObject]@{
                Id = $guest.Id
                DisplayName = $guest.DisplayName
                UserPrincipalName = $upn
                Mail = $guest.Mail
                ExternalDomain = $externalDomain
                ExternalUserState = $guest.ExternalUserState
                AccountEnabled = $guest.AccountEnabled
                CreatedDateTime = if ($guest.CreatedDateTime) { $guest.CreatedDateTime.ToString("yyyy-MM-dd") } else { "" }
                UserType = "Guest"
            }
        }
        
        if ($guestUsers.Count -gt 0) {
            $domains = $guestUsers | Group-Object -Property ExternalDomain | Sort-Object -Property Count -Descending
            Write-Host "[+] Found $($guestUsers.Count) guest users" -ForegroundColor Green
            Write-Host "    External domains: $($domains.Count)" -ForegroundColor Gray
            
            foreach ($domain in ($domains | Select-Object -First 5)) {
                Write-Host "      - $($domain.Name): $($domain.Count)" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "[!] No guest users found" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Guest users: $_" -ForegroundColor Yellow
    }
    
    return $guestUsers
}

function Get-UsersWithPasswordNeverExpires {
    <#
    .SYNOPSIS
        Find users with 'password never expires' setting.
    #>
    Write-Host "[*] Finding users with password never expires..." -ForegroundColor Cyan
    
    $usersNeverExpires = @()
    
    try {
        $uri = "https://graph.microsoft.com/beta/users?`$select=id,displayName,userPrincipalName,mail,userType,passwordProfile,passwordPolicies&`$top=999"
        
        do {
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            
            foreach ($user in $result.value) {
                $passwordPolicies = $user.passwordPolicies
                
                if ($passwordPolicies -and $passwordPolicies -like "*DisablePasswordExpiration*") {
                    $usersNeverExpires += [PSCustomObject]@{
                        Id = $user.id
                        DisplayName = $user.displayName
                        UserPrincipalName = $user.userPrincipalName
                        Mail = $user.mail
                        UserType = $user.userType
                        PasswordPolicies = $passwordPolicies
                        RiskLevel = "MEDIUM"
                    }
                }
            }
            
            $uri = $result.'@odata.nextLink'
        } while ($uri)
        
        if ($usersNeverExpires.Count -gt 0) {
            Write-Host "[+] Found $($usersNeverExpires.Count) users with password never expires" -ForegroundColor Green
        }
        else {
            Write-Host "[!] No users with password never expires" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Password policies: $_" -ForegroundColor Yellow
    }
    
    return $usersNeverExpires
}

# ============================================================================
# CREDENTIAL ATTACK SURFACE FEATURES
# ============================================================================

function Get-UserPasswordPolicies {
    <#
    .SYNOPSIS
        Enumerate comprehensive password policies per user.
        Identifies weak password configurations and policy gaps.
    #>
    Write-Host "[*] Enumerating password policies per user..." -ForegroundColor Cyan
    Write-Host "    (This may take a while for large directories)" -ForegroundColor Gray
    
    $userPolicies = @()
    
    try {
        # Get domain password policy settings first
        $uri = "https://graph.microsoft.com/beta/users?`$select=id,displayName,userPrincipalName,mail,userType,passwordPolicies,lastPasswordChangeDateTime,passwordProfile&`$top=999"
        
        do {
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            
            foreach ($user in $result.value) {
                $passwordPolicies = $user.passwordPolicies
                $lastPwdChange = $user.lastPasswordChangeDateTime
                $pwdProfile = $user.passwordProfile
                
                # Determine password policy settings
                $neverExpires = $false
                $strongPwdDisabled = $false
                
                if ($passwordPolicies) {
                    $neverExpires = $passwordPolicies -like "*DisablePasswordExpiration*"
                    $strongPwdDisabled = $passwordPolicies -like "*DisableStrongPassword*"
                }
                
                # Calculate days since last password change
                $daysSincePwdChange = "Unknown"
                if ($lastPwdChange) {
                    try {
                        $pwdDate = [DateTime]::Parse($lastPwdChange)
                        $daysSincePwdChange = ((Get-Date) - $pwdDate).Days
                    }
                    catch { }
                }
                
                # Determine risk level
                $riskLevel = "LOW"
                $riskFactors = @()
                
                if ($neverExpires) {
                    $riskFactors += "Password never expires"
                    $riskLevel = "MEDIUM"
                }
                if ($strongPwdDisabled) {
                    $riskFactors += "Strong password disabled"
                    $riskLevel = "HIGH"
                }
                if ($daysSincePwdChange -is [int] -and $daysSincePwdChange -gt 365) {
                    $riskFactors += "Password >365 days old"
                    if ($riskLevel -ne "HIGH") { $riskLevel = "MEDIUM" }
                }
                if ($daysSincePwdChange -is [int] -and $daysSincePwdChange -gt 730) {
                    $riskFactors += "Password >2 years old"
                    $riskLevel = "HIGH"
                }
                
                $userPolicies += [PSCustomObject]@{
                    Id = $user.id
                    DisplayName = $user.displayName
                    UserPrincipalName = $user.userPrincipalName
                    Mail = $user.mail
                    UserType = $user.userType
                    PasswordNeverExpires = $neverExpires
                    StrongPasswordDisabled = $strongPwdDisabled
                    LastPasswordChange = if ($lastPwdChange) { "$lastPwdChange".Substring(0, [Math]::Min(10, "$lastPwdChange".Length)) } else { "Unknown" }
                    DaysSincePasswordChange = $daysSincePwdChange
                    RiskFactors = ($riskFactors -join "; ")
                    RiskLevel = $riskLevel
                }
            }
            
            $uri = $result.'@odata.nextLink'
        } while ($uri)
        
        if ($userPolicies.Count -gt 0) {
            $highRisk = ($userPolicies | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
            $medRisk = ($userPolicies | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
            
            Write-Host "[+] Analyzed password policies for $($userPolicies.Count) users" -ForegroundColor Green
            Write-Host "    - HIGH risk: $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { "Red" } else { "Green" })
            Write-Host "    - MEDIUM risk: $medRisk" -ForegroundColor $(if ($medRisk -gt 0) { "Yellow" } else { "Green" })
        }
    }
    catch {
        Write-Host "[!] Password policy enumeration failed: $_" -ForegroundColor Yellow
    }
    
    return $userPolicies
}

function Get-SsprEnabledUsers {
    <#
    .SYNOPSIS
        Identify users with Self-Service Password Reset (SSPR) enabled.
        SSPR can be an attack vector if not properly secured.
    #>
    Write-Host "[*] Identifying users with SSPR enabled..." -ForegroundColor Cyan
    
    $ssprUsers = @()
    
    try {
        # Use the authentication methods registration report
        $uri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?`$top=999"
        
        do {
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            
            foreach ($reg in $result.value) {
                # Check SSPR status
                $isSsprRegistered = $reg.isSsprRegistered
                $isSsprEnabled = $reg.isSsprEnabled
                $isSsprCapable = $reg.isSsprCapable
                $methodsRegistered = $reg.methodsRegistered
                
                # Only include users with SSPR-related settings
                if ($isSsprRegistered -or $isSsprEnabled -or $isSsprCapable) {
                    # Check for weak SSPR methods
                    $weakMethods = @()
                    $strongMethods = @()
                    
                    foreach ($method in $methodsRegistered) {
                        switch -Wildcard ($method) {
                            "*email*" { $weakMethods += "Email" }
                            "*sms*" { $weakMethods += "SMS" }
                            "*securityQuestion*" { $weakMethods += "Security Questions" }
                            "*mobilePhone*" { $weakMethods += "Mobile Phone" }
                            "*officePhone*" { $weakMethods += "Office Phone" }
                            "*microsoftAuthenticator*" { $strongMethods += "Authenticator" }
                            "*fido*" { $strongMethods += "FIDO2" }
                            "*windowsHelloForBusiness*" { $strongMethods += "Windows Hello" }
                        }
                    }
                    
                    # Determine risk - users with only weak SSPR methods are at risk
                    $riskLevel = "LOW"
                    if ($isSsprEnabled -and $weakMethods.Count -gt 0 -and $strongMethods.Count -eq 0) {
                        $riskLevel = "HIGH"
                    }
                    elseif ($isSsprEnabled -and $weakMethods.Count -gt 0) {
                        $riskLevel = "MEDIUM"
                    }
                    
                    $ssprUsers += [PSCustomObject]@{
                        Id = $reg.id
                        UserPrincipalName = $reg.userPrincipalName
                        DisplayName = $reg.userDisplayName
                        IsSsprRegistered = $isSsprRegistered
                        IsSsprEnabled = $isSsprEnabled
                        IsSsprCapable = $isSsprCapable
                        WeakMethods = ($weakMethods -join ", ")
                        StrongMethods = ($strongMethods -join ", ")
                        AllMethods = ($methodsRegistered -join ", ")
                        RiskLevel = $riskLevel
                    }
                }
            }
            
            $uri = $result.'@odata.nextLink'
        } while ($uri)
        
        if ($ssprUsers.Count -gt 0) {
            $enabled = ($ssprUsers | Where-Object { $_.IsSsprEnabled -eq $true }).Count
            $highRisk = ($ssprUsers | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
            
            Write-Host "[+] Found $($ssprUsers.Count) users with SSPR configured" -ForegroundColor Green
            Write-Host "    - SSPR Enabled: $enabled" -ForegroundColor Gray
            Write-Host "    - HIGH risk (weak methods only): $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { "Red" } else { "Green" })
        }
        else {
            Write-Host "[!] No SSPR users found or access denied" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] SSPR enumeration failed: $_" -ForegroundColor Yellow
    }
    
    return $ssprUsers
}

function Get-LegacyAuthenticationUsers {
    <#
    .SYNOPSIS
        List users with legacy authentication allowed or used.
        Legacy auth bypasses MFA and is a significant security risk.
    #>
    Write-Host "[*] Checking for legacy authentication usage..." -ForegroundColor Cyan
    
    $legacyAuthUsers = @()
    
    try {
        # Method 1: Check sign-in logs for legacy auth protocols
        Write-Host "    Checking sign-in logs for legacy protocols..." -ForegroundColor Gray
        
        $legacyProtocols = @(
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
        
        # Query last 30 days of sign-ins with legacy protocols
        $startDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $seenUsers = @{}
        
        foreach ($protocol in $legacyProtocols) {
            try {
                $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=clientAppUsed eq '$protocol' and createdDateTime ge $startDate&`$top=100"
                $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
                
                if ($result -and $result.value) {
                    foreach ($signIn in $result.value) {
                        $userId = $signIn.userId
                        $userKey = "$userId`_$protocol"
                        
                        if (-not $seenUsers.ContainsKey($userKey)) {
                            $seenUsers[$userKey] = $true
                            
                            # Check if this user already in results
                            $existingUser = $legacyAuthUsers | Where-Object { $_.Id -eq $userId }
                            
                            if ($existingUser) {
                                # Update protocols list
                                if ($existingUser.LegacyProtocols -notlike "*$protocol*") {
                                    $existingUser.LegacyProtocols += ", $protocol"
                                }
                            }
                            else {
                                $legacyAuthUsers += [PSCustomObject]@{
                                    Id = $userId
                                    UserPrincipalName = $signIn.userPrincipalName
                                    DisplayName = $signIn.userDisplayName
                                    LegacyProtocols = $protocol
                                    LastLegacySignIn = if ($signIn.createdDateTime) { "$($signIn.createdDateTime)".Substring(0, 10) } else { "Unknown" }
                                    ClientApp = $signIn.clientAppUsed
                                    Status = if ($signIn.status.errorCode -eq 0) { "Success" } else { "Failed" }
                                    RiskLevel = "HIGH"
                                }
                            }
                        }
                    }
                }
            }
            catch { continue }
        }
        
        # Method 2: Check authentication strengths/policies for basic auth
        Write-Host "    Checking conditional access for legacy auth blocks..." -ForegroundColor Gray
        
        try {
            $policyUri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
            $policies = Invoke-MgGraphRequest -Method GET -Uri $policyUri -ErrorAction SilentlyContinue
            
            $legacyAuthBlocked = $false
            if ($policies -and $policies.value) {
                foreach ($policy in $policies.value) {
                    if ($policy.state -eq "enabled") {
                        $conditions = $policy.conditions
                        if ($conditions.clientAppTypes -contains "exchangeActiveSync" -or 
                            $conditions.clientAppTypes -contains "other") {
                            $controls = $policy.grantControls
                            if ($controls.builtInControls -contains "block") {
                                $legacyAuthBlocked = $true
                            }
                        }
                    }
                }
            }
            
            if (-not $legacyAuthBlocked) {
                Write-Host "    [!] WARNING: No CA policy blocking legacy authentication detected" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "    [!] Cannot check CA policies: Access denied" -ForegroundColor Yellow
        }
        
        if ($legacyAuthUsers.Count -gt 0) {
            $uniqueUsers = ($legacyAuthUsers | Select-Object -Unique Id).Count
            Write-Host "[+] Found $uniqueUsers users using legacy authentication (HIGH RISK)" -ForegroundColor Red
        }
        else {
            Write-Host "[+] No legacy authentication usage detected in last 30 days" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[!] Legacy auth check failed: $_" -ForegroundColor Yellow
    }
    
    return $legacyAuthUsers
}

function Get-UsersWithAppPasswords {
    <#
    .SYNOPSIS
        Find users with app passwords configured.
        App passwords bypass MFA and are a significant attack surface.
    #>
    Write-Host "[*] Finding users with app passwords configured..." -ForegroundColor Cyan
    Write-Host "    (App passwords bypass MFA - HIGH RISK)" -ForegroundColor Gray
    
    $usersWithAppPasswords = @()
    
    try {
        # Get all users first
        $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Mail, UserType -ErrorAction Stop
        Write-Host "    Checking app passwords for $($users.Count) users..." -ForegroundColor Gray
        
        $counter = 0
        foreach ($user in $users) {
            $counter++
            
            try {
                # Check for password authentication methods (includes app passwords)
                $uri = "https://graph.microsoft.com/beta/users/$($user.Id)/authentication/passwordMethods"
                $pwdMethods = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
                
                $hasAppPassword = $false
                $appPasswordCount = 0
                
                if ($pwdMethods -and $pwdMethods.value) {
                    foreach ($method in $pwdMethods.value) {
                        # App passwords have specific characteristics
                        if ($method.id -and $method.id -ne "28c10230-6103-485e-b985-444c60001490") {
                            # Default password has specific ID, others are app passwords
                            $hasAppPassword = $true
                            $appPasswordCount++
                        }
                    }
                }
                
                # Also check via beta endpoint for more details
                $authMethodsUri = "https://graph.microsoft.com/beta/users/$($user.Id)/authentication/methods"
                $allMethods = Invoke-MgGraphRequest -Method GET -Uri $authMethodsUri -ErrorAction SilentlyContinue
                
                if ($allMethods -and $allMethods.value) {
                    foreach ($method in $allMethods.value) {
                        $methodType = $method.'@odata.type'
                        if ($methodType -like "*passwordAuthenticationMethod*" -and $method.id -ne "28c10230-6103-485e-b985-444c60001490") {
                            $hasAppPassword = $true
                        }
                    }
                }
                
                if ($hasAppPassword) {
                    $usersWithAppPasswords += [PSCustomObject]@{
                        Id = $user.Id
                        DisplayName = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        Mail = $user.Mail
                        UserType = $user.UserType
                        HasAppPassword = $true
                        AppPasswordCount = $appPasswordCount
                        RiskLevel = "HIGH"
                        RiskReason = "App passwords bypass MFA"
                    }
                }
            }
            catch { continue }
            
            if ($counter % 100 -eq 0) {
                Write-Host "    Processed $counter/$($users.Count) users..." -ForegroundColor Gray
            }
        }
        
        # Alternative: Check via reports endpoint
        if ($usersWithAppPasswords.Count -eq 0) {
            Write-Host "    Trying alternative detection method..." -ForegroundColor Gray
            
            try {
                $uri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?`$filter=methodsRegistered/any(m:m eq 'appPassword')&`$top=999"
                $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
                
                if ($result -and $result.value) {
                    foreach ($reg in $result.value) {
                        if ($reg.methodsRegistered -contains "appPassword") {
                            $usersWithAppPasswords += [PSCustomObject]@{
                                Id = $reg.id
                                DisplayName = $reg.userDisplayName
                                UserPrincipalName = $reg.userPrincipalName
                                Mail = ""
                                UserType = ""
                                HasAppPassword = $true
                                AppPasswordCount = "Unknown"
                                RiskLevel = "HIGH"
                                RiskReason = "App passwords bypass MFA"
                            }
                        }
                    }
                }
            }
            catch { }
        }
        
        if ($usersWithAppPasswords.Count -gt 0) {
            Write-Host "[+] Found $($usersWithAppPasswords.Count) users with app passwords (HIGH RISK)" -ForegroundColor Red
        }
        else {
            Write-Host "[+] No users with app passwords detected" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[!] App password check failed: $_" -ForegroundColor Yellow
    }
    
    return $usersWithAppPasswords
}

function Invoke-CredentialAttackSurfaceAssessment {
    <#
    .SYNOPSIS
        Run all credential attack surface assessments.
    #>
    Write-Host ("`n" + ("=" * 70)) -ForegroundColor Cyan
    Write-Host "CREDENTIAL ATTACK SURFACE ASSESSMENT" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    $results = @{}
    
    Write-Host "`n[1/4] Password Policies..." -ForegroundColor Yellow
    $results.PasswordPolicies = Get-UserPasswordPolicies
    
    Write-Host "`n[2/4] SSPR Configuration..." -ForegroundColor Yellow
    $results.SSPR = Get-SsprEnabledUsers
    
    Write-Host "`n[3/4] Legacy Authentication..." -ForegroundColor Yellow
    $results.LegacyAuth = Get-LegacyAuthenticationUsers
    
    Write-Host "`n[4/4] App Passwords..." -ForegroundColor Yellow
    $results.AppPasswords = Get-UsersWithAppPasswords
    
    # Summary
    Write-Host ("`n" + ("=" * 70)) -ForegroundColor Cyan
    Write-Host "CREDENTIAL ATTACK SURFACE SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    $pwdHighRisk = ($results.PasswordPolicies | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $ssprHighRisk = ($results.SSPR | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $legacyAuthCount = $results.LegacyAuth.Count
    $appPwdCount = $results.AppPasswords.Count
    
    Write-Host "`n  Password policy HIGH risk:     $pwdHighRisk" -ForegroundColor $(if ($pwdHighRisk -gt 0) { "Red" } else { "Green" })
    Write-Host "  SSPR weak methods only:        $ssprHighRisk" -ForegroundColor $(if ($ssprHighRisk -gt 0) { "Red" } else { "Green" })
    Write-Host "  Legacy auth users:             $legacyAuthCount" -ForegroundColor $(if ($legacyAuthCount -gt 0) { "Red" } else { "Green" })
    Write-Host "  App password users:            $appPwdCount" -ForegroundColor $(if ($appPwdCount -gt 0) { "Red" } else { "Green" })
    
    Write-Host ("`n" + ("-" * 70)) -ForegroundColor Gray
    
    return $results
}

# ============================================================================
# CONDITIONAL ACCESS ANALYSIS
# ============================================================================

function Get-ConditionalAccessPolicies {
    <#
    .SYNOPSIS
        Enumerate all Conditional Access policies.
        Requires Policy.Read.All permission.
    #>
    Write-Host "[*] Enumerating Conditional Access policies..." -ForegroundColor Cyan
    
    $policies = @()
    
    try {
        $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        foreach ($policy in $response.value) {
            $conditions = $policy.conditions
            $grantControls = $policy.grantControls
            
            $riskLevel = "LOW"
            $riskReasons = @()
            
            # Check if policy is disabled
            if ($policy.state -ne "enabled") {
                $riskLevel = "MEDIUM"
                $riskReasons += "Policy disabled"
            }
            
            # Check for exclusions
            $usersCondition = $conditions.users
            $excludeUsers = @($usersCondition.excludeUsers)
            $excludeGroups = @($usersCondition.excludeGroups)
            
            if ($excludeUsers.Count -gt 0 -or $excludeGroups.Count -gt 0) {
                $riskReasons += "Has exclusions ($($excludeUsers.Count) users, $($excludeGroups.Count) groups)"
                if ($riskLevel -eq "LOW") { $riskLevel = "MEDIUM" }
            }
            
            # Check grant controls
            $builtInControls = @($grantControls.builtInControls)
            $mfaRequired = $builtInControls -contains "mfa"
            $blocksAccess = $builtInControls -contains "block"
            
            # Check client app types (legacy auth)
            $clientAppTypes = @($conditions.clientAppTypes)
            $targetsLegacy = ($clientAppTypes -contains "exchangeActiveSync" -or $clientAppTypes -contains "other")
            
            $policyInfo = [PSCustomObject]@{
                Id = $policy.id
                DisplayName = $policy.displayName
                State = $policy.state
                CreatedDateTime = $policy.createdDateTime
                ModifiedDateTime = $policy.modifiedDateTime
                MfaRequired = $mfaRequired
                BlocksAccess = $blocksAccess
                TargetsLegacyAuth = $targetsLegacy
                ExcludeUsersCount = $excludeUsers.Count
                ExcludeGroupsCount = $excludeGroups.Count
                RiskLevel = $riskLevel
                RiskReasons = ($riskReasons -join "; ")
            }
            
            $policies += $policyInfo
        }
        
        $enabledCount = ($policies | Where-Object { $_.State -eq "enabled" }).Count
        Write-Host "[+] Found $($policies.Count) CA policies ($enabledCount enabled)" -ForegroundColor Green
    }
    catch {
        if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
            Write-Host "[!] Access denied - Policy.Read.All permission required" -ForegroundColor Red
        }
        else {
            Write-Host "[!] Error enumerating CA policies: $_" -ForegroundColor Red
        }
    }
    
    return $policies
}

function Get-CAPolicyExclusions {
    <#
    .SYNOPSIS
        Identify users and groups excluded from Conditional Access policies.
        These exclusions are potential attack vectors.
    #>
    Write-Host "[*] Analyzing CA policy exclusions..." -ForegroundColor Cyan
    Write-Host "    (Exclusions are potential security gaps)" -ForegroundColor Gray
    
    $exclusions = @{
        ExcludedUsers = @()
        ExcludedGroups = @()
        ExcludedRoles = @()
        PoliciesWithExclusions = @()
    }
    
    try {
        $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        $allExcludedUserIds = @{}
        $allExcludedGroupIds = @{}
        $allExcludedRoleIds = @{}
        
        foreach ($policy in $response.value) {
            if ($policy.state -ne "enabled") { continue }
            
            $conditions = $policy.conditions
            $usersCondition = $conditions.users
            
            $excludeUsers = @($usersCondition.excludeUsers)
            $excludeGroups = @($usersCondition.excludeGroups)
            $excludeRoles = @($usersCondition.excludeRoles)
            
            if ($excludeUsers.Count -gt 0 -or $excludeGroups.Count -gt 0 -or $excludeRoles.Count -gt 0) {
                $exclusions.PoliciesWithExclusions += [PSCustomObject]@{
                    PolicyId = $policy.id
                    PolicyName = $policy.displayName
                    ExcludedUsers = $excludeUsers.Count
                    ExcludedGroups = $excludeGroups.Count
                    ExcludedRoles = $excludeRoles.Count
                }
                
                foreach ($userId in $excludeUsers) { $allExcludedUserIds[$userId] = $true }
                foreach ($groupId in $excludeGroups) { $allExcludedGroupIds[$groupId] = $true }
                foreach ($roleId in $excludeRoles) { $allExcludedRoleIds[$roleId] = $true }
            }
        }
        
        # Resolve excluded user details
        Write-Host "    Resolving excluded user identities..." -ForegroundColor Gray
        foreach ($userId in $allExcludedUserIds.Keys) {
            if ($userId -in @("GuestsOrExternalUsers", "All")) {
                $exclusions.ExcludedUsers += [PSCustomObject]@{
                    Id = $userId
                    DisplayName = $userId
                    UserPrincipalName = $userId
                    RiskLevel = if ($userId -eq "All") { "HIGH" } else { "MEDIUM" }
                }
                continue
            }
            
            try {
                $user = Get-MgUser -UserId $userId -Property Id,DisplayName,UserPrincipalName,Mail,JobTitle,Department -ErrorAction SilentlyContinue
                if ($user) {
                    $exclusions.ExcludedUsers += [PSCustomObject]@{
                        Id = $user.Id
                        DisplayName = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        Mail = $user.Mail
                        JobTitle = $user.JobTitle
                        Department = $user.Department
                        RiskLevel = "HIGH"
                        RiskReason = "Excluded from CA policies"
                    }
                }
            }
            catch {
                $exclusions.ExcludedUsers += [PSCustomObject]@{
                    Id = $userId
                    DisplayName = "Unable to resolve"
                    UserPrincipalName = $userId
                    RiskLevel = "HIGH"
                }
            }
        }
        
        # Resolve excluded group details
        Write-Host "    Resolving excluded group identities..." -ForegroundColor Gray
        foreach ($groupId in $allExcludedGroupIds.Keys) {
            try {
                $group = Get-MgGroup -GroupId $groupId -Property Id,DisplayName,Description -ErrorAction SilentlyContinue
                if ($group) {
                    $memberCount = 0
                    try {
                        $members = Get-MgGroupMember -GroupId $groupId -CountVariable memberCount -ErrorAction SilentlyContinue
                        $memberCount = $members.Count
                    } catch {}
                    
                    $exclusions.ExcludedGroups += [PSCustomObject]@{
                        Id = $group.Id
                        DisplayName = $group.DisplayName
                        Description = $group.Description
                        MemberCount = $memberCount
                        RiskLevel = if ($memberCount -gt 10) { "HIGH" } else { "MEDIUM" }
                        RiskReason = "Excluded from CA policies ($memberCount members)"
                    }
                }
            }
            catch {
                $exclusions.ExcludedGroups += [PSCustomObject]@{
                    Id = $groupId
                    DisplayName = "Unable to resolve"
                    RiskLevel = "HIGH"
                }
            }
        }
        
        # Resolve excluded roles
        Write-Host "    Resolving excluded role identities..." -ForegroundColor Gray
        foreach ($roleId in $allExcludedRoleIds.Keys) {
            try {
                $roleUri = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$roleId'"
                $roleResponse = Invoke-MgGraphRequest -Method GET -Uri $roleUri -ErrorAction SilentlyContinue
                
                if ($roleResponse.value.Count -gt 0) {
                    $role = $roleResponse.value[0]
                    $exclusions.ExcludedRoles += [PSCustomObject]@{
                        Id = $roleId
                        DisplayName = $role.displayName
                        RiskLevel = "CRITICAL"
                        RiskReason = "Admin role excluded from CA policies"
                    }
                }
                else {
                    $exclusions.ExcludedRoles += [PSCustomObject]@{
                        Id = $roleId
                        DisplayName = "Unknown role"
                        RiskLevel = "HIGH"
                    }
                }
            }
            catch {
                $exclusions.ExcludedRoles += [PSCustomObject]@{
                    Id = $roleId
                    DisplayName = "Unable to resolve"
                    RiskLevel = "HIGH"
                }
            }
        }
        
        Write-Host "[+] Found $($exclusions.ExcludedUsers.Count) excluded users, $($exclusions.ExcludedGroups.Count) excluded groups, $($exclusions.ExcludedRoles.Count) excluded roles" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing exclusions: $_" -ForegroundColor Red
    }
    
    return $exclusions
}

function Get-MFAEnforcementGaps {
    <#
    .SYNOPSIS
        Find gaps in MFA enforcement across CA policies.
        Identifies scenarios where MFA is not required.
    #>
    Write-Host "[*] Analyzing MFA enforcement gaps..." -ForegroundColor Cyan
    Write-Host "    (Finding scenarios where MFA is not enforced)" -ForegroundColor Gray
    
    $gaps = @{
        NoMfaPolicies = @()
        MfaPolicies = @()
        UsersWithoutMfaEnforcement = @()
        AppsWithoutMfa = @()
        Summary = @{}
    }
    
    try {
        $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        $enabledPolicies = $response.value | Where-Object { $_.state -eq "enabled" }
        Write-Host "    Analyzing $($enabledPolicies.Count) enabled CA policies..." -ForegroundColor Gray
        
        $allAppsRequiringMfa = @{}
        $allUsersRequiringMfa = @{}
        
        foreach ($policy in $enabledPolicies) {
            $conditions = $policy.conditions
            $grantControls = $policy.grantControls
            
            $builtInControls = @($grantControls.builtInControls)
            $mfaRequired = $builtInControls -contains "mfa"
            $blocksAccess = $builtInControls -contains "block"
            
            # Get target applications
            $appsCondition = $conditions.applications
            $includeApps = @($appsCondition.includeApplications)
            $excludeApps = @($appsCondition.excludeApplications)
            
            # Get target users
            $usersCondition = $conditions.users
            $includeUsers = @($usersCondition.includeUsers)
            $includeGroups = @($usersCondition.includeGroups)
            
            $policyInfo = [PSCustomObject]@{
                Id = $policy.id
                DisplayName = $policy.displayName
                MfaRequired = $mfaRequired
                TargetApps = $includeApps
                TargetUsers = $includeUsers
                TargetGroups = $includeGroups
                ExcludedApps = $excludeApps
            }
            
            if ($mfaRequired) {
                $gaps.MfaPolicies += $policyInfo
                if ($includeApps -contains "All") {
                    $allAppsRequiringMfa["All"] = $true
                }
                else {
                    foreach ($app in $includeApps) { $allAppsRequiringMfa[$app] = $true }
                }
                
                if ($includeUsers -contains "All") {
                    $allUsersRequiringMfa["All"] = $true
                }
                else {
                    foreach ($user in $includeUsers) { $allUsersRequiringMfa[$user] = $true }
                }
            }
            else {
                if (-not $blocksAccess) {
                    $policyInfo | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue "MEDIUM" -Force
                    $policyInfo | Add-Member -NotePropertyName "RiskReason" -NotePropertyValue "Policy allows access without MFA" -Force
                    $gaps.NoMfaPolicies += $policyInfo
                }
            }
        }
        
        # Check for apps without MFA requirement
        if (-not $allAppsRequiringMfa.ContainsKey("All")) {
            Write-Host "    Checking for apps without MFA enforcement..." -ForegroundColor Gray
            
            $criticalApps = @(
                @{ Id = "00000002-0000-0000-c000-000000000000"; Name = "Azure Active Directory Graph" },
                @{ Id = "00000003-0000-0000-c000-000000000000"; Name = "Microsoft Graph" },
                @{ Id = "00000002-0000-0ff1-ce00-000000000000"; Name = "Office 365 Exchange Online" },
                @{ Id = "00000003-0000-0ff1-ce00-000000000000"; Name = "Office 365 SharePoint Online" },
                @{ Id = "00000004-0000-0ff1-ce00-000000000000"; Name = "Skype for Business Online" },
                @{ Id = "797f4846-ba00-4fd7-ba43-dac1f8f63013"; Name = "Azure Service Management API" }
            )
            
            foreach ($app in $criticalApps) {
                if (-not $allAppsRequiringMfa.ContainsKey($app.Id)) {
                    $gaps.AppsWithoutMfa += [PSCustomObject]@{
                        Id = $app.Id
                        DisplayName = $app.Name
                        RiskLevel = "HIGH"
                        RiskReason = "Critical app may not require MFA"
                    }
                }
            }
        }
        
        # Check for privileged users without MFA coverage
        if (-not $allUsersRequiringMfa.ContainsKey("All")) {
            Write-Host "    Checking MFA coverage for privileged users..." -ForegroundColor Gray
            
            $privRoles = @(
                "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
                "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
                "29232cdf-9323-42fd-ade2-1d097af3e4de"   # Exchange Administrator
            )
            
            foreach ($roleTemplateId in $privRoles) {
                try {
                    $roleUri = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$roleTemplateId'"
                    $roleResponse = Invoke-MgGraphRequest -Method GET -Uri $roleUri -ErrorAction SilentlyContinue
                    
                    if ($roleResponse.value.Count -gt 0) {
                        $roleId = $roleResponse.value[0].id
                        $roleName = $roleResponse.value[0].displayName
                        
                        $membersUri = "https://graph.microsoft.com/v1.0/directoryRoles/$roleId/members"
                        $membersResponse = Invoke-MgGraphRequest -Method GET -Uri $membersUri -ErrorAction SilentlyContinue
                        
                        foreach ($member in $membersResponse.value) {
                            $memberId = $member.id
                            if ($memberId -and -not $allUsersRequiringMfa.ContainsKey($memberId)) {
                                $gaps.UsersWithoutMfaEnforcement += [PSCustomObject]@{
                                    Id = $memberId
                                    DisplayName = $member.displayName
                                    UserPrincipalName = $member.userPrincipalName
                                    Role = $roleName
                                    RiskLevel = "CRITICAL"
                                    RiskReason = "Privileged user may not have MFA enforced"
                                }
                            }
                        }
                    }
                }
                catch { continue }
            }
        }
        
        # Generate summary
        $gaps.Summary = @{
            TotalCAPolicies = $response.value.Count
            EnabledPolicies = $enabledPolicies.Count
            PoliciesWithMfa = $gaps.MfaPolicies.Count
            PoliciesWithoutMfa = $gaps.NoMfaPolicies.Count
            AppsWithoutMfaCoverage = $gaps.AppsWithoutMfa.Count
            PrivilegedUsersWithoutMfa = $gaps.UsersWithoutMfaEnforcement.Count
            MfaCoverage = if ($allUsersRequiringMfa.ContainsKey("All")) { "All users" } else { "Partial" }
        }
        
        Write-Host "[+] MFA Analysis Complete:" -ForegroundColor Green
        Write-Host "    - Policies with MFA: $($gaps.Summary.PoliciesWithMfa)" -ForegroundColor Gray
        Write-Host "    - Policies without MFA: $($gaps.Summary.PoliciesWithoutMfa)" -ForegroundColor Gray
        Write-Host "    - MFA Coverage: $($gaps.Summary.MfaCoverage)" -ForegroundColor Gray
        
        if ($gaps.UsersWithoutMfaEnforcement.Count -gt 0) {
            Write-Host "    - CRITICAL: $($gaps.UsersWithoutMfaEnforcement.Count) privileged users may not have MFA enforced!" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "[!] Error analyzing MFA gaps: $_" -ForegroundColor Red
    }
    
    return $gaps
}

function Show-CAPoliciesReport {
    param([array]$Policies)
    
    if ($Policies.Count -eq 0) {
        Write-Host "[!] No CA policies to display" -ForegroundColor Yellow
        return
    }
    
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Cyan
    Write-Host ("{0,60}" -f "CONDITIONAL ACCESS POLICIES") -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Cyan
    
    $enabled = ($Policies | Where-Object { $_.State -eq "enabled" }).Count
    $disabled = $Policies.Count - $enabled
    $mfaPolicies = ($Policies | Where-Object { $_.MfaRequired }).Count
    $blockingPolicies = ($Policies | Where-Object { $_.BlocksAccess }).Count
    
    Write-Host "`nTotal: $($Policies.Count) | Enabled: $enabled | Disabled: $disabled"
    Write-Host "MFA Required: $mfaPolicies | Blocking: $blockingPolicies"
    Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
    
    Write-Host ("{0,-40} {1,-10} {2,-5} {3,-6} {4,-11} {5,-12} {6,-8}" -f "Policy Name", "State", "MFA", "Block", "Excl Users", "Excl Groups", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 120) -ForegroundColor Gray
    
    $riskOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3 }
    $sortedPolicies = $Policies | Sort-Object { $riskOrder[$_.RiskLevel] }, { $_.State -ne "enabled" }
    
    foreach ($policy in $sortedPolicies) {
        $name = if ($policy.DisplayName.Length -gt 39) { $policy.DisplayName.Substring(0, 39) } else { $policy.DisplayName }
        $state = $policy.State
        $mfa = if ($policy.MfaRequired) { "Yes" } else { "No" }
        $block = if ($policy.BlocksAccess) { "Yes" } else { "No" }
        $exclUsers = $policy.ExcludeUsersCount
        $exclGroups = $policy.ExcludeGroupsCount
        $risk = $policy.RiskLevel
        
        $color = "White"
        if ($policy.State -ne "enabled") { $color = "Gray" }
        elseif ($risk -eq "HIGH") { $color = "Red" }
        elseif ($risk -eq "MEDIUM") { $color = "Yellow" }
        
        Write-Host ("{0,-40} {1,-10} {2,-5} {3,-6} {4,-11} {5,-12} {6,-8}" -f $name, $state, $mfa, $block, $exclUsers, $exclGroups, $risk) -ForegroundColor $color
    }
    
    Write-Host ("-" * 120) -ForegroundColor Gray
}

function Show-CAExclusionsReport {
    param([hashtable]$Exclusions)
    
    Write-Host ("`n" + ("=" * 110)) -ForegroundColor Cyan
    Write-Host ("{0,55}" -f "CONDITIONAL ACCESS EXCLUSIONS (SECURITY GAPS)") -ForegroundColor Cyan
    Write-Host ("=" * 110) -ForegroundColor Cyan
    
    $excludedUsers = $Exclusions.ExcludedUsers
    $excludedGroups = $Exclusions.ExcludedGroups
    $excludedRoles = $Exclusions.ExcludedRoles
    $policiesWithExcl = $Exclusions.PoliciesWithExclusions
    
    Write-Host "`nPolicies with exclusions: $($policiesWithExcl.Count)"
    Write-Host "Excluded users: $($excludedUsers.Count)"
    Write-Host "Excluded groups: $($excludedGroups.Count)"
    Write-Host "Excluded roles: $($excludedRoles.Count)"
    
    if ($excludedRoles.Count -gt 0) {
        Write-Host ("`n" + ("-" * 110)) -ForegroundColor Gray
        Write-Host "EXCLUDED ROLES (CRITICAL RISK):" -ForegroundColor Red
        Write-Host ("-" * 110) -ForegroundColor Gray
        Write-Host ("{0,-50} {1,-15} {2,-40}" -f "Role Name", "Risk Level", "Risk Reason") -ForegroundColor Yellow
        Write-Host ("-" * 110) -ForegroundColor Gray
        foreach ($role in $excludedRoles) {
            $name = if ($role.DisplayName.Length -gt 49) { $role.DisplayName.Substring(0, 49) } else { $role.DisplayName }
            $risk = $role.RiskLevel
            $reason = if ($role.RiskReason -and $role.RiskReason.Length -gt 39) { $role.RiskReason.Substring(0, 39) } else { $role.RiskReason }
            Write-Host ("{0,-50} {1,-15} {2,-40}" -f $name, $risk, $reason) -ForegroundColor Red
        }
    }
    
    if ($excludedUsers.Count -gt 0) {
        Write-Host ("`n" + ("-" * 110)) -ForegroundColor Gray
        Write-Host "EXCLUDED USERS:" -ForegroundColor Yellow
        Write-Host ("-" * 110) -ForegroundColor Gray
        Write-Host ("{0,-30} {1,-45} {2,-20} {3,-10}" -f "Display Name", "Email/UPN", "Department", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 110) -ForegroundColor Gray
        foreach ($user in ($excludedUsers | Select-Object -First 30)) {
            $name = if ($user.DisplayName -and $user.DisplayName.Length -gt 29) { $user.DisplayName.Substring(0, 29) } else { $user.DisplayName }
            $email = if ($user.UserPrincipalName -and $user.UserPrincipalName.Length -gt 44) { $user.UserPrincipalName.Substring(0, 44) } else { $user.UserPrincipalName }
            $dept = if ($user.Department -and $user.Department.Length -gt 19) { $user.Department.Substring(0, 19) } else { $user.Department }
            $risk = $user.RiskLevel
            Write-Host ("{0,-30} {1,-45} {2,-20} {3,-10}" -f $name, $email, $dept, $risk)
        }
        if ($excludedUsers.Count -gt 30) {
            Write-Host "    ... and $($excludedUsers.Count - 30) more" -ForegroundColor Gray
        }
    }
    
    if ($excludedGroups.Count -gt 0) {
        Write-Host ("`n" + ("-" * 110)) -ForegroundColor Gray
        Write-Host "EXCLUDED GROUPS:" -ForegroundColor Yellow
        Write-Host ("-" * 110) -ForegroundColor Gray
        Write-Host ("{0,-40} {1,-10} {2,-40} {3,-10}" -f "Group Name", "Members", "Description", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 110) -ForegroundColor Gray
        foreach ($group in ($excludedGroups | Select-Object -First 20)) {
            $name = if ($group.DisplayName -and $group.DisplayName.Length -gt 39) { $group.DisplayName.Substring(0, 39) } else { $group.DisplayName }
            $members = $group.MemberCount
            $desc = if ($group.Description -and $group.Description.Length -gt 39) { $group.Description.Substring(0, 39) } else { $group.Description }
            $risk = $group.RiskLevel
            Write-Host ("{0,-40} {1,-10} {2,-40} {3,-10}" -f $name, $members, $desc, $risk)
        }
        if ($excludedGroups.Count -gt 20) {
            Write-Host "    ... and $($excludedGroups.Count - 20) more" -ForegroundColor Gray
        }
    }
    
    Write-Host ("-" * 110) -ForegroundColor Gray
}

function Show-MFAGapsReport {
    param([hashtable]$Gaps)
    
    Write-Host ("`n" + ("=" * 110)) -ForegroundColor Cyan
    Write-Host ("{0,55}" -f "MFA ENFORCEMENT GAPS ANALYSIS") -ForegroundColor Cyan
    Write-Host ("=" * 110) -ForegroundColor Cyan
    
    $summary = $Gaps.Summary
    
    Write-Host "`nTotal CA Policies: $($summary.TotalCAPolicies)"
    Write-Host "Enabled Policies: $($summary.EnabledPolicies)"
    Write-Host "Policies with MFA: $($summary.PoliciesWithMfa)"
    Write-Host "Policies without MFA: $($summary.PoliciesWithoutMfa)"
    Write-Host "MFA Coverage: $($summary.MfaCoverage)"
    
    $usersWithoutMfa = $Gaps.UsersWithoutMfaEnforcement
    $appsWithoutMfa = $Gaps.AppsWithoutMfa
    $noMfaPolicies = $Gaps.NoMfaPolicies
    
    if ($usersWithoutMfa.Count -gt 0) {
        Write-Host ("`n" + ("-" * 110)) -ForegroundColor Gray
        Write-Host "PRIVILEGED USERS WITHOUT MFA ENFORCEMENT (CRITICAL):" -ForegroundColor Red
        Write-Host ("-" * 110) -ForegroundColor Gray
        Write-Host ("{0,-30} {1,-40} {2,-25} {3,-10}" -f "Display Name", "Email/UPN", "Role", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 110) -ForegroundColor Gray
        foreach ($user in $usersWithoutMfa) {
            $name = if ($user.DisplayName -and $user.DisplayName.Length -gt 29) { $user.DisplayName.Substring(0, 29) } else { $user.DisplayName }
            $email = if ($user.UserPrincipalName -and $user.UserPrincipalName.Length -gt 39) { $user.UserPrincipalName.Substring(0, 39) } else { $user.UserPrincipalName }
            $role = if ($user.Role -and $user.Role.Length -gt 24) { $user.Role.Substring(0, 24) } else { $user.Role }
            $risk = $user.RiskLevel
            Write-Host ("{0,-30} {1,-40} {2,-25} {3,-10}" -f $name, $email, $role, $risk) -ForegroundColor Red
        }
    }
    
    if ($appsWithoutMfa.Count -gt 0) {
        Write-Host ("`n" + ("-" * 110)) -ForegroundColor Gray
        Write-Host "CRITICAL APPS WITHOUT MFA COVERAGE:" -ForegroundColor Red
        Write-Host ("-" * 110) -ForegroundColor Gray
        Write-Host ("{0,-50} {1,-15} {2,-40}" -f "Application Name", "Risk Level", "Risk Reason") -ForegroundColor Yellow
        Write-Host ("-" * 110) -ForegroundColor Gray
        foreach ($app in $appsWithoutMfa) {
            $name = if ($app.DisplayName.Length -gt 49) { $app.DisplayName.Substring(0, 49) } else { $app.DisplayName }
            $risk = $app.RiskLevel
            $reason = if ($app.RiskReason.Length -gt 39) { $app.RiskReason.Substring(0, 39) } else { $app.RiskReason }
            Write-Host ("{0,-50} {1,-15} {2,-40}" -f $name, $risk, $reason) -ForegroundColor Yellow
        }
    }
    
    if ($noMfaPolicies.Count -gt 0) {
        Write-Host ("`n" + ("-" * 110)) -ForegroundColor Gray
        Write-Host "POLICIES WITHOUT MFA REQUIREMENT:" -ForegroundColor Yellow
        Write-Host ("-" * 110) -ForegroundColor Gray
        Write-Host ("{0,-50} {1,-30} {2,-10}" -f "Policy Name", "Target Apps", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 110) -ForegroundColor Gray
        foreach ($policy in ($noMfaPolicies | Select-Object -First 20)) {
            $name = if ($policy.DisplayName.Length -gt 49) { $policy.DisplayName.Substring(0, 49) } else { $policy.DisplayName }
            $apps = if ($policy.TargetApps) { ($policy.TargetApps | Select-Object -First 2) -join ", " } else { "N/A" }
            if ($apps.Length -gt 29) { $apps = $apps.Substring(0, 29) }
            $risk = $policy.RiskLevel
            Write-Host ("{0,-50} {1,-30} {2,-10}" -f $name, $apps, $risk)
        }
        if ($noMfaPolicies.Count -gt 20) {
            Write-Host "    ... and $($noMfaPolicies.Count - 20) more" -ForegroundColor Gray
        }
    }
    
    Write-Host ("-" * 110) -ForegroundColor Gray
}

function Invoke-FullCAAnalysis {
    Write-Host ("`n" + ("=" * 70)) -ForegroundColor Cyan
    Write-Host "CONDITIONAL ACCESS ANALYSIS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    $results = @{}
    
    Write-Host "`n[1/3] Enumerating CA Policies..." -ForegroundColor Yellow
    $results.Policies = Get-ConditionalAccessPolicies
    
    Write-Host "`n[2/3] Analyzing Exclusions..." -ForegroundColor Yellow
    $results.Exclusions = Get-CAPolicyExclusions
    
    Write-Host "`n[3/3] Analyzing MFA Gaps..." -ForegroundColor Yellow
    $results.MfaGaps = Get-MFAEnforcementGaps
    
    # Print summary
    Write-Host ("`n" + ("=" * 70)) -ForegroundColor Cyan
    Write-Host "CA ANALYSIS SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    $enabledPolicies = ($results.Policies | Where-Object { $_.State -eq "enabled" }).Count
    $exclUsers = $results.Exclusions.ExcludedUsers.Count
    $exclGroups = $results.Exclusions.ExcludedGroups.Count
    $exclRoles = $results.Exclusions.ExcludedRoles.Count
    $privUsersNoMfa = $results.MfaGaps.UsersWithoutMfaEnforcement.Count
    
    Write-Host "`n  Total CA Policies:             $($results.Policies.Count)"
    Write-Host "  Enabled Policies:              $enabledPolicies"
    Write-Host "  Excluded Users:                $exclUsers" -ForegroundColor $(if ($exclUsers -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Excluded Groups:               $exclGroups" -ForegroundColor $(if ($exclGroups -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Excluded Roles (CRITICAL):     $exclRoles" -ForegroundColor $(if ($exclRoles -gt 0) { "Red" } else { "Green" })
    Write-Host "  Priv Users w/o MFA (CRITICAL): $privUsersNoMfa" -ForegroundColor $(if ($privUsersNoMfa -gt 0) { "Red" } else { "Green" })
    
    Write-Host ("`n" + ("-" * 70)) -ForegroundColor Gray
    
    return $results
}

# ============================================================================
# DEVICE ENUMERATION FEATURES
# ============================================================================

function Get-AllDevices {
    <#
    .SYNOPSIS
        Enumerate all registered devices in Azure AD/Entra ID.
    #>
    Write-Host "[*] Enumerating all registered devices..." -ForegroundColor Cyan
    
    $allDevices = @()
    
    try {
        $devices = Get-MgDevice -All -Property Id,DisplayName,DeviceId,OperatingSystem,OperatingSystemVersion,TrustType,IsCompliant,IsManaged,ManagementType,DeviceOwnership,RegistrationDateTime,ApproximateLastSignInDateTime,AccountEnabled,Manufacturer,Model,EnrollmentType -ErrorAction Stop
        
        foreach ($device in $devices) {
            # Determine trust type (how device is joined)
            $trustType = $device.TrustType
            $joinType = switch ($trustType) {
                "AzureAd" { "Azure AD Joined" }
                "ServerAd" { "Hybrid Azure AD Joined" }
                "Workplace" { "Azure AD Registered (BYOD)" }
                default { "Unknown" }
            }
            
            # Determine device ownership
            $ownership = $device.DeviceOwnership
            $isBYOD = ($ownership -eq "Personal") -or ($trustType -eq "Workplace")
            
            # Determine compliance status
            $isCompliant = $device.IsCompliant
            $isManaged = $device.IsManaged
            
            # Determine risk level based on compliance and management
            $riskLevel = "LOW"
            $riskFactors = @()
            
            if ($isCompliant -eq $false) {
                $riskLevel = "HIGH"
                $riskFactors += "Non-compliant"
            } elseif ($null -eq $isCompliant) {
                $riskLevel = "MEDIUM"
                $riskFactors += "Compliance unknown"
            }
            
            if (-not $isManaged) {
                if ($riskLevel -eq "LOW") { $riskLevel = "MEDIUM" }
                $riskFactors += "Unmanaged"
            }
            
            if ($isBYOD) {
                if ($riskLevel -eq "LOW") { $riskLevel = "MEDIUM" }
                $riskFactors += "BYOD"
            }
            
            if (-not $device.AccountEnabled) {
                $riskFactors += "Disabled"
            }
            
            $allDevices += [PSCustomObject]@{
                Id = $device.Id
                DeviceId = $device.DeviceId
                DisplayName = $device.DisplayName
                OperatingSystem = $device.OperatingSystem
                OSVersion = $device.OperatingSystemVersion
                TrustType = $trustType
                JoinType = $joinType
                IsCompliant = $isCompliant
                IsManaged = $isManaged
                ManagementType = $device.ManagementType
                DeviceOwnership = $ownership
                IsBYOD = $isBYOD
                RegistrationDateTime = if ($device.RegistrationDateTime) { $device.RegistrationDateTime.ToString("yyyy-MM-dd") } else { "" }
                LastSignIn = if ($device.ApproximateLastSignInDateTime) { $device.ApproximateLastSignInDateTime.ToString("yyyy-MM-dd") } else { "" }
                AccountEnabled = $device.AccountEnabled
                Manufacturer = $device.Manufacturer
                Model = $device.Model
                EnrollmentType = $device.EnrollmentType
                RiskLevel = $riskLevel
                RiskFactors = ($riskFactors -join ", ")
            }
        }
        
        if ($allDevices.Count -gt 0) {
            $compliant = ($allDevices | Where-Object { $_.IsCompliant -eq $true }).Count
            $nonCompliant = ($allDevices | Where-Object { $_.IsCompliant -eq $false }).Count
            $unknown = ($allDevices | Where-Object { $null -eq $_.IsCompliant }).Count
            $byod = ($allDevices | Where-Object { $_.IsBYOD -eq $true }).Count
            $managed = ($allDevices | Where-Object { $_.IsManaged -eq $true }).Count
            
            Write-Host "[+] Found $($allDevices.Count) devices" -ForegroundColor Green
            Write-Host "    - Compliant: $compliant" -ForegroundColor Green
            Write-Host "    - Non-compliant (HIGH RISK): $nonCompliant" -ForegroundColor $(if ($nonCompliant -gt 0) { "Red" } else { "Green" })
            Write-Host "    - Compliance unknown: $unknown" -ForegroundColor Yellow
            Write-Host "    - BYOD/Personal: $byod" -ForegroundColor Yellow
            Write-Host "    - Managed: $managed" -ForegroundColor Gray
        } else {
            Write-Host "[!] No devices found or access denied" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Error enumerating devices: $_" -ForegroundColor Red
    }
    
    return $allDevices
}

function Get-UserDevices {
    <#
    .SYNOPSIS
        Get devices registered/owned by users.
    #>
    Write-Host "[*] Enumerating devices per user..." -ForegroundColor Cyan
    
    $userDevices = @()
    
    try {
        # Get all users first
        $users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName -ErrorAction Stop
        Write-Host "    Checking devices for $($users.Count) users..." -ForegroundColor Gray
        
        $counter = 0
        foreach ($user in $users) {
            $counter++
            
            $userId = $user.Id
            $userName = $user.DisplayName
            $userUPN = $user.UserPrincipalName
            
            # Get registered devices
            $regDevices = @()
            try {
                $regDevices = Get-MgUserRegisteredDevice -UserId $userId -Property Id,DisplayName,DeviceId,OperatingSystem,TrustType,IsCompliant,IsManaged,DeviceOwnership -ErrorAction SilentlyContinue
            } catch { }
            
            # Get owned devices
            $ownedDevices = @()
            try {
                $ownedDevices = Get-MgUserOwnedDevice -UserId $userId -Property Id,DisplayName,DeviceId,OperatingSystem,TrustType,IsCompliant,IsManaged,DeviceOwnership -ErrorAction SilentlyContinue
            } catch { }
            
            # Combine and deduplicate
            $seenDeviceIds = @{}
            $combinedDevices = @()
            
            foreach ($device in $regDevices) {
                $deviceId = $device.Id
                if ($deviceId -and -not $seenDeviceIds.ContainsKey($deviceId)) {
                    $seenDeviceIds[$deviceId] = $true
                    $device | Add-Member -NotePropertyName "Relationship" -NotePropertyValue "Registered" -Force
                    $combinedDevices += $device
                }
            }
            
            foreach ($device in $ownedDevices) {
                $deviceId = $device.Id
                if ($deviceId -and -not $seenDeviceIds.ContainsKey($deviceId)) {
                    $seenDeviceIds[$deviceId] = $true
                    $device | Add-Member -NotePropertyName "Relationship" -NotePropertyValue "Owned" -Force
                    $combinedDevices += $device
                } elseif ($deviceId -and $seenDeviceIds.ContainsKey($deviceId)) {
                    # Update existing to show both relationships
                    foreach ($d in $combinedDevices) {
                        if ($d.Id -eq $deviceId) {
                            $d.Relationship = "Registered & Owned"
                        }
                    }
                }
            }
            
            foreach ($device in $combinedDevices) {
                $trustType = $device.AdditionalProperties.trustType
                $ownership = $device.AdditionalProperties.deviceOwnership
                $isBYOD = ($ownership -eq "Personal") -or ($trustType -eq "Workplace")
                $isCompliant = $device.AdditionalProperties.isCompliant
                $isManaged = $device.AdditionalProperties.isManaged
                
                # Risk assessment
                $riskLevel = "LOW"
                $riskFactors = @()
                
                if ($isCompliant -eq $false) {
                    $riskLevel = "HIGH"
                    $riskFactors += "Non-compliant"
                } elseif ($null -eq $isCompliant) {
                    $riskLevel = "MEDIUM"
                    $riskFactors += "Unknown compliance"
                }
                
                if (-not $isManaged) {
                    if ($riskLevel -eq "LOW") { $riskLevel = "MEDIUM" }
                    $riskFactors += "Unmanaged"
                }
                
                if ($isBYOD) {
                    if ($riskLevel -eq "LOW") { $riskLevel = "MEDIUM" }
                    $riskFactors += "BYOD"
                }
                
                $userDevices += [PSCustomObject]@{
                    UserId = $userId
                    UserName = $userName
                    UserPrincipalName = $userUPN
                    DeviceId = $device.Id
                    DeviceName = $device.AdditionalProperties.displayName
                    OperatingSystem = $device.AdditionalProperties.operatingSystem
                    TrustType = $trustType
                    IsCompliant = $isCompliant
                    IsManaged = $isManaged
                    DeviceOwnership = $ownership
                    IsBYOD = $isBYOD
                    Relationship = $device.Relationship
                    RiskLevel = $riskLevel
                    RiskFactors = ($riskFactors -join ", ")
                }
            }
            
            # Progress indicator
            if ($counter % 100 -eq 0) {
                Write-Host "    Processed $counter/$($users.Count) users..." -ForegroundColor Gray
            }
        }
        
        if ($userDevices.Count -gt 0) {
            $uniqueUsers = ($userDevices | Select-Object -Property UserId -Unique).Count
            $uniqueDevices = ($userDevices | Select-Object -Property DeviceId -Unique).Count
            $byodDevices = ($userDevices | Where-Object { $_.IsBYOD -eq $true }).Count
            $nonCompliant = ($userDevices | Where-Object { $_.IsCompliant -eq $false }).Count
            
            Write-Host "[+] Found $uniqueDevices devices across $uniqueUsers users" -ForegroundColor Green
            Write-Host "    - BYOD devices: $byodDevices" -ForegroundColor Yellow
            Write-Host "    - Non-compliant: $nonCompliant" -ForegroundColor $(if ($nonCompliant -gt 0) { "Red" } else { "Green" })
        }
    }
    catch {
        Write-Host "[!] Error: $_" -ForegroundColor Red
    }
    
    return $userDevices
}

function Get-NonCompliantDevices {
    <#
    .SYNOPSIS
        Find all non-compliant devices - security risk focus.
    #>
    Write-Host "[*] Enumerating non-compliant devices..." -ForegroundColor Cyan
    
    $nonCompliantDevices = @()
    
    try {
        # Try filtering for non-compliant devices
        $devices = Get-MgDevice -Filter "isCompliant eq false" -Property Id,DisplayName,DeviceId,OperatingSystem,OperatingSystemVersion,TrustType,IsManaged,ManagementType,DeviceOwnership,ApproximateLastSignInDateTime,Manufacturer,Model -ErrorAction Stop
        
        foreach ($device in $devices) {
            $trustType = $device.TrustType
            $ownership = $device.DeviceOwnership
            $isBYOD = ($ownership -eq "Personal") -or ($trustType -eq "Workplace")
            
            $nonCompliantDevices += [PSCustomObject]@{
                Id = $device.Id
                DeviceId = $device.DeviceId
                DisplayName = $device.DisplayName
                OperatingSystem = $device.OperatingSystem
                OSVersion = $device.OperatingSystemVersion
                TrustType = $trustType
                IsManaged = $device.IsManaged
                ManagementType = $device.ManagementType
                DeviceOwnership = $ownership
                IsBYOD = $isBYOD
                LastSignIn = if ($device.ApproximateLastSignInDateTime) { $device.ApproximateLastSignInDateTime.ToString("yyyy-MM-dd") } else { "" }
                Manufacturer = $device.Manufacturer
                Model = $device.Model
                RiskLevel = "HIGH"
                RiskReason = "Device is non-compliant"
            }
        }
        
        if ($nonCompliantDevices.Count -gt 0) {
            Write-Host "[+] Found $($nonCompliantDevices.Count) non-compliant devices (HIGH RISK)" -ForegroundColor Red
            
            # Group by OS
            $osCounts = $nonCompliantDevices | Group-Object -Property OperatingSystem
            foreach ($os in ($osCounts | Sort-Object -Property Count -Descending)) {
                Write-Host "    - $($os.Name): $($os.Count)" -ForegroundColor Gray
            }
        } else {
            Write-Host "[+] No non-compliant devices found" -ForegroundColor Green
        }
    }
    catch {
        # Filter might not be supported, fall back to getting all
        Write-Host "    Filter not supported, fetching all devices..." -ForegroundColor Yellow
        $allDevices = Get-AllDevices
        $nonCompliantDevices = $allDevices | Where-Object { $_.IsCompliant -eq $false }
        
        if ($nonCompliantDevices.Count -gt 0) {
            Write-Host "[+] Found $($nonCompliantDevices.Count) non-compliant devices (HIGH RISK)" -ForegroundColor Red
        }
    }
    
    return $nonCompliantDevices
}

function Get-BYODDevices {
    <#
    .SYNOPSIS
        Find all BYOD (personal) devices enrolled in the organization.
    #>
    Write-Host "[*] Enumerating BYOD/personal devices..." -ForegroundColor Cyan
    
    $byodDevices = @()
    
    try {
        # Try filtering for personal/workplace devices
        $devices = Get-MgDevice -Filter "trustType eq 'Workplace'" -Property Id,DisplayName,DeviceId,OperatingSystem,OperatingSystemVersion,TrustType,IsCompliant,IsManaged,ManagementType,DeviceOwnership,RegistrationDateTime,ApproximateLastSignInDateTime,Manufacturer,Model -ErrorAction SilentlyContinue
        
        # Also try filtering by deviceOwnership (may not be supported)
        try {
            $personalDevices = Get-MgDevice -Filter "deviceOwnership eq 'Personal'" -Property Id,DisplayName,DeviceId,OperatingSystem,OperatingSystemVersion,TrustType,IsCompliant,IsManaged,ManagementType,DeviceOwnership,RegistrationDateTime,ApproximateLastSignInDateTime,Manufacturer,Model -ErrorAction SilentlyContinue
            $devices = @($devices) + @($personalDevices) | Sort-Object -Property Id -Unique
        } catch { }
        
        if (-not $devices -or $devices.Count -eq 0) {
            # Fall back to getting all and filtering locally
            Write-Host "    Filter not supported, fetching all devices..." -ForegroundColor Yellow
            $allDevices = Get-AllDevices
            $devices = $allDevices | Where-Object { $_.IsBYOD -eq $true }
            
            # Return already processed
            if ($devices.Count -gt 0) {
                Write-Host "[+] Found $($devices.Count) BYOD/personal devices" -ForegroundColor Green
            } else {
                Write-Host "[+] No BYOD/personal devices found" -ForegroundColor Green
            }
            return $devices
        }
        
        foreach ($device in $devices) {
            $trustType = $device.TrustType
            $ownership = $device.DeviceOwnership
            $isCompliant = $device.IsCompliant
            $isManaged = $device.IsManaged
            
            # Risk assessment for BYOD
            $riskLevel = "MEDIUM"  # BYOD is inherently medium risk
            $riskFactors = @("BYOD/Personal device")
            
            if ($isCompliant -eq $false) {
                $riskLevel = "HIGH"
                $riskFactors += "Non-compliant"
            } elseif ($null -eq $isCompliant) {
                $riskFactors += "Unknown compliance"
            }
            
            if (-not $isManaged) {
                $riskLevel = "HIGH"
                $riskFactors += "Unmanaged"
            }
            
            $byodDevices += [PSCustomObject]@{
                Id = $device.Id
                DeviceId = $device.DeviceId
                DisplayName = $device.DisplayName
                OperatingSystem = $device.OperatingSystem
                OSVersion = $device.OperatingSystemVersion
                TrustType = $trustType
                IsCompliant = $isCompliant
                IsManaged = $isManaged
                ManagementType = $device.ManagementType
                DeviceOwnership = $ownership
                IsBYOD = $true
                RegistrationDateTime = if ($device.RegistrationDateTime) { $device.RegistrationDateTime.ToString("yyyy-MM-dd") } else { "" }
                LastSignIn = if ($device.ApproximateLastSignInDateTime) { $device.ApproximateLastSignInDateTime.ToString("yyyy-MM-dd") } else { "" }
                Manufacturer = $device.Manufacturer
                Model = $device.Model
                RiskLevel = $riskLevel
                RiskFactors = ($riskFactors -join ", ")
            }
        }
        
        if ($byodDevices.Count -gt 0) {
            $compliant = ($byodDevices | Where-Object { $_.IsCompliant -eq $true }).Count
            $nonCompliant = ($byodDevices | Where-Object { $_.IsCompliant -eq $false }).Count
            $managed = ($byodDevices | Where-Object { $_.IsManaged -eq $true }).Count
            
            Write-Host "[+] Found $($byodDevices.Count) BYOD/personal devices" -ForegroundColor Green
            Write-Host "    - Compliant: $compliant" -ForegroundColor Green
            Write-Host "    - Non-compliant: $nonCompliant" -ForegroundColor $(if ($nonCompliant -gt 0) { "Red" } else { "Green" })
            Write-Host "    - Managed: $managed" -ForegroundColor Gray
            Write-Host "    - Unmanaged: $($byodDevices.Count - $managed)" -ForegroundColor Yellow
            
            # Group by OS
            Write-Host "    By Operating System:" -ForegroundColor Gray
            $osCounts = $byodDevices | Group-Object -Property OperatingSystem
            foreach ($os in ($osCounts | Sort-Object -Property Count -Descending)) {
                Write-Host "      - $($os.Name): $($os.Count)" -ForegroundColor Gray
            }
        } else {
            Write-Host "[+] No BYOD/personal devices found" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[!] Error: $_" -ForegroundColor Red
    }
    
    return $byodDevices
}

function Show-DevicesReport {
    param(
        [array]$Devices,
        [string]$Title = "DEVICE ENUMERATION REPORT"
    )
    
    Show-SecuritySummary -Data $Devices -Title $Title -ShowRisk
    
    Write-Host ("{0,-24} {1,-14} {2,-21} {3,-9} {4,-7} {5,-5} {6,-7}" -f "Device Name", "OS", "Join Type", "Compliant", "Managed", "BYOD", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    $riskOrder = @{ "HIGH" = 0; "MEDIUM" = 1; "LOW" = 2 }
    $sortedDevices = $Devices | Sort-Object { $riskOrder[$_.RiskLevel] }
    
    foreach ($device in ($sortedDevices | Select-Object -First 50)) {
        $name = if ($device.DisplayName) { $device.DisplayName.Substring(0, [Math]::Min(23, $device.DisplayName.Length)) } else { "" }
        $os = if ($device.OperatingSystem) { $device.OperatingSystem.Substring(0, [Math]::Min(13, $device.OperatingSystem.Length)) } else { "" }
        $joinType = if ($device.JoinType) { $device.JoinType.Substring(0, [Math]::Min(20, $device.JoinType.Length)) } elseif ($device.TrustType) { $device.TrustType.Substring(0, [Math]::Min(20, $device.TrustType.Length)) } else { "" }
        $compliant = if ($device.IsCompliant -eq $true) { "Yes" } elseif ($device.IsCompliant -eq $false) { "No" } else { "N/A" }
        $managed = if ($device.IsManaged) { "Yes" } else { "No" }
        $byod = if ($device.IsBYOD) { "Yes" } else { "No" }
        $risk = $device.RiskLevel
        
        Write-Host ("{0,-24} {1,-14} {2,-21} {3,-9} {4,-7} {5,-5} {6,-7}" -f $name, $os, $joinType, $compliant, $managed, $byod, $risk)
    }
    
    if ($Devices.Count -gt 50) {
        Write-Host "    ... and $($Devices.Count - 50) more devices" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 110) -ForegroundColor Gray
}

function Show-UserDevicesReport {
    param([array]$UserDevices)
    
    Show-SecuritySummary -Data $UserDevices -Title "USER DEVICE ASSOCIATIONS" -ShowRisk
    
    Write-Host ("{0,-29} {1,-21} {2,-11} {3,-9} {4,-5} {5,-14} {6,-7}" -f "User", "Device Name", "OS", "Compliant", "BYOD", "Relation", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    $riskOrder = @{ "HIGH" = 0; "MEDIUM" = 1; "LOW" = 2 }
    $sortedDevices = $UserDevices | Sort-Object { $riskOrder[$_.RiskLevel] }
    
    foreach ($entry in ($sortedDevices | Select-Object -First 50)) {
        $user = if ($entry.UserName) { $entry.UserName.Substring(0, [Math]::Min(28, $entry.UserName.Length)) } elseif ($entry.UserPrincipalName) { $entry.UserPrincipalName.Substring(0, [Math]::Min(28, $entry.UserPrincipalName.Length)) } else { "" }
        $device = if ($entry.DeviceName) { $entry.DeviceName.Substring(0, [Math]::Min(20, $entry.DeviceName.Length)) } else { "" }
        $os = if ($entry.OperatingSystem) { $entry.OperatingSystem.Substring(0, [Math]::Min(10, $entry.OperatingSystem.Length)) } else { "" }
        $compliant = if ($entry.IsCompliant -eq $true) { "Yes" } elseif ($entry.IsCompliant -eq $false) { "No" } else { "N/A" }
        $byod = if ($entry.IsBYOD) { "Yes" } else { "No" }
        $relation = if ($entry.Relationship) { $entry.Relationship.Substring(0, [Math]::Min(13, $entry.Relationship.Length)) } else { "" }
        $risk = $entry.RiskLevel
        
        Write-Host ("{0,-29} {1,-21} {2,-11} {3,-9} {4,-5} {5,-14} {6,-7}" -f $user, $device, $os, $compliant, $byod, $relation, $risk)
    }
    
    if ($UserDevices.Count -gt 50) {
        Write-Host "    ... and $($UserDevices.Count - 50) more entries" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 110) -ForegroundColor Gray
}

# ============================================================================
# INTUNE/ENDPOINT MANAGER ENUMERATION FEATURES
# ============================================================================

function Get-IntuneManagedDevices {
    <#
    .SYNOPSIS
        Enumerate all Intune managed devices.
        Uses /deviceManagement/managedDevices endpoint.
        Requires DeviceManagementManagedDevices.Read.All permission.
    #>
    Write-Host "[*] Enumerating Intune managed devices..." -ForegroundColor Cyan
    
    $managedDevices = @()
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,managedDeviceOwnerType,enrolledDateTime,lastSyncDateTime,operatingSystem,osVersion,complianceState,deviceEnrollmentType,managementAgent,manufacturer,model,serialNumber,userPrincipalName,userDisplayName,emailAddress,azureADRegistered,azureADDeviceId,deviceRegistrationState,isEncrypted,isSupervised,jailBroken,managementState&`$top=999"
        
        while ($uri) {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            
            foreach ($device in $response.value) {
                $complianceState = $device.complianceState
                $managementAgent = $device.managementAgent
                $ownerType = $device.managedDeviceOwnerType
                $isEncrypted = $device.isEncrypted
                $jailBroken = $device.jailBroken
                
                # Risk assessment
                $riskLevel = "LOW"
                $riskFactors = @()
                
                if ($complianceState -eq "noncompliant") {
                    $riskLevel = "HIGH"
                    $riskFactors += "Non-compliant"
                } elseif ($complianceState -in @("unknown", "configManager")) {
                    $riskLevel = "MEDIUM"
                    $riskFactors += "Compliance: $complianceState"
                }
                
                if (-not $isEncrypted) {
                    if ($riskLevel -eq "LOW") { $riskLevel = "MEDIUM" }
                    $riskFactors += "Not encrypted"
                }
                
                if ($jailBroken -eq "True") {
                    $riskLevel = "CRITICAL"
                    $riskFactors += "Jailbroken/rooted"
                }
                
                if ($ownerType -eq "personal") {
                    if ($riskLevel -eq "LOW") { $riskLevel = "MEDIUM" }
                    $riskFactors += "Personal device (BYOD)"
                }
                
                $managedDevices += [PSCustomObject]@{
                    Id = $device.id
                    DeviceName = $device.deviceName
                    UserPrincipalName = $device.userPrincipalName
                    UserDisplayName = $device.userDisplayName
                    OperatingSystem = $device.operatingSystem
                    OSVersion = $device.osVersion
                    ComplianceState = $complianceState
                    ManagementAgent = $managementAgent
                    OwnerType = $ownerType
                    EnrollmentType = $device.deviceEnrollmentType
                    EnrolledDateTime = if ($device.enrolledDateTime) { $device.enrolledDateTime.ToString("yyyy-MM-dd") } else { "" }
                    LastSyncDateTime = if ($device.lastSyncDateTime) { $device.lastSyncDateTime.ToString("yyyy-MM-dd HH:mm") } else { "" }
                    Manufacturer = $device.manufacturer
                    Model = $device.model
                    SerialNumber = $device.serialNumber
                    IsEncrypted = $isEncrypted
                    IsSupervised = $device.isSupervised
                    JailBroken = $jailBroken
                    AzureADRegistered = $device.azureADRegistered
                    AzureADDeviceId = $device.azureADDeviceId
                    ManagementState = $device.managementState
                    RiskLevel = $riskLevel
                    RiskFactors = if ($riskFactors.Count -gt 0) { $riskFactors -join ", " } else { "None" }
                }
            }
            
            $uri = $response.'@odata.nextLink'
        }
        
        if ($managedDevices.Count -gt 0) {
            $compliant = ($managedDevices | Where-Object { $_.ComplianceState -eq "compliant" }).Count
            $nonCompliant = ($managedDevices | Where-Object { $_.ComplianceState -eq "noncompliant" }).Count
            $personal = ($managedDevices | Where-Object { $_.OwnerType -eq "personal" }).Count
            $corporate = ($managedDevices | Where-Object { $_.OwnerType -eq "company" }).Count
            $encrypted = ($managedDevices | Where-Object { $_.IsEncrypted }).Count
            
            Write-Host "[+] Found $($managedDevices.Count) Intune managed devices" -ForegroundColor Green
            Write-Host "    - Compliant: $compliant" -ForegroundColor $(if ($compliant -gt 0) { "Green" } else { "Gray" })
            Write-Host "    - Non-compliant: $nonCompliant" -ForegroundColor $(if ($nonCompliant -gt 0) { "Red" } else { "Gray" })
            Write-Host "    - Corporate: $corporate" -ForegroundColor Gray
            Write-Host "    - Personal/BYOD: $personal" -ForegroundColor $(if ($personal -gt 0) { "Yellow" } else { "Gray" })
            Write-Host "    - Encrypted: $encrypted" -ForegroundColor Gray
            
            # Group by OS
            Write-Host "    By Operating System:" -ForegroundColor Gray
            $osCounts = $managedDevices | Group-Object -Property OperatingSystem | Sort-Object Count -Descending | Select-Object -First 5
            foreach ($os in $osCounts) {
                Write-Host "      - $($os.Name): $($os.Count)" -ForegroundColor Gray
            }
        } else {
            Write-Host "[!] No Intune managed devices found or access denied" -ForegroundColor Yellow
        }
    }
    catch {
        if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
            Write-Host "[!] Access denied. Requires DeviceManagementManagedDevices.Read.All permission" -ForegroundColor Red
        } else {
            Write-Host "[!] Error enumerating Intune devices: $_" -ForegroundColor Red
        }
    }
    
    return $managedDevices
}

function Get-IntuneCompliancePolicies {
    <#
    .SYNOPSIS
        Enumerate all Intune compliance policies.
        Uses /deviceManagement/deviceCompliancePolicies endpoint.
        Requires DeviceManagementConfiguration.Read.All permission.
    #>
    Write-Host "[*] Enumerating Intune compliance policies..." -ForegroundColor Cyan
    
    $policies = @()
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?`$expand=assignments&`$top=999"
        
        while ($uri) {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            
            foreach ($policy in $response.value) {
                $policyType = $policy.'@odata.type' -replace '#microsoft.graph.', ''
                $assignments = $policy.assignments
                
                # Analyze assignments
                $targetGroups = @()
                $includeAll = $false
                $excludeGroups = @()
                
                foreach ($assignment in $assignments) {
                    $target = $assignment.target
                    $targetType = $target.'@odata.type'
                    
                    if ($targetType -like "*allDevicesAssignmentTarget*") {
                        $includeAll = $true
                        $targetGroups += "All Devices"
                    } elseif ($targetType -like "*allLicensedUsersAssignmentTarget*") {
                        $includeAll = $true
                        $targetGroups += "All Users"
                    } elseif ($targetType -like "*groupAssignmentTarget*") {
                        $groupId = $target.groupId
                        $targetGroups += $groupId.Substring(0, [Math]::Min(8, $groupId.Length)) + "..."
                    } elseif ($targetType -like "*exclusionGroupAssignmentTarget*") {
                        $groupId = $target.groupId
                        $excludeGroups += $groupId.Substring(0, [Math]::Min(8, $groupId.Length)) + "..."
                    }
                }
                
                # Risk assessment
                $riskLevel = "LOW"
                $riskFactors = @()
                
                if ($assignments.Count -eq 0) {
                    $riskLevel = "MEDIUM"
                    $riskFactors += "Not assigned"
                }
                
                if ($excludeGroups.Count -gt 0) {
                    if ($riskLevel -eq "LOW") { $riskLevel = "MEDIUM" }
                    $riskFactors += "$($excludeGroups.Count) exclusions"
                }
                
                $policies += [PSCustomObject]@{
                    Id = $policy.id
                    DisplayName = $policy.displayName
                    Description = $policy.description
                    PolicyType = $policyType
                    CreatedDateTime = if ($policy.createdDateTime) { $policy.createdDateTime.ToString("yyyy-MM-dd") } else { "" }
                    LastModifiedDateTime = if ($policy.lastModifiedDateTime) { $policy.lastModifiedDateTime.ToString("yyyy-MM-dd") } else { "" }
                    Version = $policy.version
                    AssignmentCount = $assignments.Count
                    TargetGroups = if ($targetGroups.Count -gt 0) { $targetGroups -join ", " } else { "None" }
                    ExcludeGroups = if ($excludeGroups.Count -gt 0) { $excludeGroups -join ", " } else { "None" }
                    IncludeAllDevicesOrUsers = $includeAll
                    RiskLevel = $riskLevel
                    RiskFactors = if ($riskFactors.Count -gt 0) { $riskFactors -join ", " } else { "None" }
                }
            }
            
            $uri = $response.'@odata.nextLink'
        }
        
        if ($policies.Count -gt 0) {
            $assigned = ($policies | Where-Object { $_.AssignmentCount -gt 0 }).Count
            $unassigned = $policies.Count - $assigned
            
            Write-Host "[+] Found $($policies.Count) compliance policies" -ForegroundColor Green
            Write-Host "    - Assigned: $assigned" -ForegroundColor $(if ($assigned -gt 0) { "Green" } else { "Yellow" })
            Write-Host "    - Unassigned: $unassigned" -ForegroundColor $(if ($unassigned -gt 0) { "Yellow" } else { "Gray" })
            
            # Group by type
            Write-Host "    By Platform/Type:" -ForegroundColor Gray
            $typeCounts = $policies | Group-Object -Property PolicyType | Sort-Object Count -Descending
            foreach ($type in $typeCounts) {
                $simpleType = $type.Name -replace 'DeviceCompliancePolicy', '' -replace 'CompliancePolicy', ''
                if ($simpleType) {
                    Write-Host "      - $simpleType`: $($type.Count)" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "[!] No compliance policies found or access denied" -ForegroundColor Yellow
        }
    }
    catch {
        if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
            Write-Host "[!] Access denied. Requires DeviceManagementConfiguration.Read.All permission" -ForegroundColor Red
        } else {
            Write-Host "[!] Error enumerating compliance policies: $_" -ForegroundColor Red
        }
    }
    
    return $policies
}

function Get-IntuneConfigurationProfiles {
    <#
    .SYNOPSIS
        Enumerate all Intune device configuration profiles.
        Uses /deviceManagement/deviceConfigurations endpoint.
        Requires DeviceManagementConfiguration.Read.All permission.
    #>
    Write-Host "[*] Enumerating Intune configuration profiles..." -ForegroundColor Cyan
    
    $profiles = @()
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?`$expand=assignments&`$top=999"
        
        while ($uri) {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            
            foreach ($config in $response.value) {
                $configType = $config.'@odata.type' -replace '#microsoft.graph.', ''
                $assignments = $config.assignments
                
                # Analyze assignments
                $targetGroups = @()
                $includeAll = $false
                $excludeGroups = @()
                
                foreach ($assignment in $assignments) {
                    $target = $assignment.target
                    $targetType = $target.'@odata.type'
                    
                    if ($targetType -like "*allDevicesAssignmentTarget*") {
                        $includeAll = $true
                        $targetGroups += "All Devices"
                    } elseif ($targetType -like "*allLicensedUsersAssignmentTarget*") {
                        $includeAll = $true
                        $targetGroups += "All Users"
                    } elseif ($targetType -like "*groupAssignmentTarget*") {
                        $groupId = $target.groupId
                        $targetGroups += $groupId.Substring(0, [Math]::Min(8, $groupId.Length)) + "..."
                    } elseif ($targetType -like "*exclusionGroupAssignmentTarget*") {
                        $groupId = $target.groupId
                        $excludeGroups += $groupId.Substring(0, [Math]::Min(8, $groupId.Length)) + "..."
                    }
                }
                
                # Risk assessment
                $riskLevel = "LOW"
                $riskFactors = @()
                
                if ($assignments.Count -eq 0) {
                    $riskLevel = "MEDIUM"
                    $riskFactors += "Not assigned"
                }
                
                if ($excludeGroups.Count -gt 0) {
                    if ($riskLevel -eq "LOW") { $riskLevel = "MEDIUM" }
                    $riskFactors += "$($excludeGroups.Count) exclusions"
                }
                
                $profiles += [PSCustomObject]@{
                    Id = $config.id
                    DisplayName = $config.displayName
                    Description = $config.description
                    ConfigType = $configType
                    CreatedDateTime = if ($config.createdDateTime) { $config.createdDateTime.ToString("yyyy-MM-dd") } else { "" }
                    LastModifiedDateTime = if ($config.lastModifiedDateTime) { $config.lastModifiedDateTime.ToString("yyyy-MM-dd") } else { "" }
                    Version = $config.version
                    AssignmentCount = $assignments.Count
                    TargetGroups = if ($targetGroups.Count -gt 0) { $targetGroups -join ", " } else { "None" }
                    ExcludeGroups = if ($excludeGroups.Count -gt 0) { $excludeGroups -join ", " } else { "None" }
                    IncludeAllDevicesOrUsers = $includeAll
                    RiskLevel = $riskLevel
                    RiskFactors = if ($riskFactors.Count -gt 0) { $riskFactors -join ", " } else { "None" }
                }
            }
            
            $uri = $response.'@odata.nextLink'
        }
        
        if ($profiles.Count -gt 0) {
            $assigned = ($profiles | Where-Object { $_.AssignmentCount -gt 0 }).Count
            $unassigned = $profiles.Count - $assigned
            
            Write-Host "[+] Found $($profiles.Count) configuration profiles" -ForegroundColor Green
            Write-Host "    - Assigned: $assigned" -ForegroundColor $(if ($assigned -gt 0) { "Green" } else { "Yellow" })
            Write-Host "    - Unassigned: $unassigned" -ForegroundColor $(if ($unassigned -gt 0) { "Yellow" } else { "Gray" })
            
            # Group by type
            Write-Host "    By Profile Type:" -ForegroundColor Gray
            $typeCounts = $profiles | Group-Object -Property ConfigType | Sort-Object Count -Descending | Select-Object -First 5
            foreach ($type in $typeCounts) {
                $simpleType = $type.Name -replace 'Configuration', '' -replace 'DeviceConfiguration', ''
                Write-Host "      - $simpleType`: $($type.Count)" -ForegroundColor Gray
            }
        } else {
            Write-Host "[!] No configuration profiles found or access denied" -ForegroundColor Yellow
        }
    }
    catch {
        if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
            Write-Host "[!] Access denied. Requires DeviceManagementConfiguration.Read.All permission" -ForegroundColor Red
        } else {
            Write-Host "[!] Error enumerating configuration profiles: $_" -ForegroundColor Red
        }
    }
    
    return $profiles
}

function Get-IntuneDeviceAdministrators {
    <#
    .SYNOPSIS
        Enumerate Intune/Endpoint Manager role assignments (device administrators).
        Uses /deviceManagement/roleAssignments and /deviceManagement/roleDefinitions endpoints.
        Requires DeviceManagementRBAC.Read.All permission.
    #>
    Write-Host "[*] Enumerating Intune device administrators..." -ForegroundColor Cyan
    
    $administrators = @()
    $roleDefinitions = @{}
    
    # First get role definitions to map role IDs to names
    try {
        $roleDefResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions" -ErrorAction Stop
        
        foreach ($role in $roleDefResponse.value) {
            $roleDefinitions[$role.id] = @{
                DisplayName = $role.displayName
                Description = $role.description
                IsBuiltIn = $role.isBuiltIn
                Permissions = $role.permissions
            }
        }
        Write-Host "    Found $($roleDefinitions.Count) role definitions" -ForegroundColor Gray
    }
    catch {
        if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
            Write-Host "[!] Access denied. Requires DeviceManagementRBAC.Read.All permission" -ForegroundColor Red
            return $administrators
        }
        Write-Host "[!] Error getting role definitions: $_" -ForegroundColor Yellow
    }
    
    # Get role assignments
    try {
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/roleAssignments?`$expand=*&`$top=999"
        
        while ($uri) {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            
            foreach ($assignment in $response.value) {
                $roleDefId = if ($assignment.roleDefinition) { $assignment.roleDefinition.id } else { $assignment.roleDefinitionId }
                $roleInfo = $roleDefinitions[$roleDefId]
                $roleName = if ($roleInfo) { $roleInfo.DisplayName } else { $assignment.displayName }
                if (-not $roleName) { $roleName = "Unknown Role" }
                $isBuiltIn = if ($roleInfo) { $roleInfo.IsBuiltIn } else { $true }
                
                # Get scope members
                $scopeMembers = $assignment.scopeMembers
                $members = $assignment.members
                $resourceScopes = $assignment.resourceScopes
                
                # Risk assessment
                $riskLevel = "MEDIUM"
                $riskFactors = @()
                
                # High-privilege roles
                $highPrivRoles = @(
                    "Intune Administrator", "Intune Role Administrator",
                    "Endpoint Security Manager", "Policy and Profile Manager",
                    "Help Desk Operator", "Application Manager"
                )
                
                foreach ($highRole in $highPrivRoles) {
                    if ($roleName -like "*$highRole*") {
                        $riskLevel = "HIGH"
                        $riskFactors += "High-privilege role"
                        break
                    }
                }
                
                if (-not $isBuiltIn) {
                    $riskFactors += "Custom role"
                }
                
                # Check scope
                $scopeType = "All Devices"
                if ($resourceScopes -and $resourceScopes.Count -gt 0) {
                    $scopeType = "$($resourceScopes.Count) scope tags"
                    $riskFactors += "Scoped access"
                }
                
                $memberCount = if ($members) { $members.Count } elseif ($scopeMembers) { $scopeMembers.Count } else { 0 }
                $memberIds = @()
                if ($members) {
                    $memberIds = ($members | Select-Object -First 5 | ForEach-Object { $_.id })
                } elseif ($scopeMembers) {
                    $memberIds = ($scopeMembers | Select-Object -First 5 | ForEach-Object { $_.id })
                }
                
                $scopeNames = @("All")
                if ($resourceScopes) {
                    $scopeNames = $resourceScopes | ForEach-Object { if ($_.displayName) { $_.displayName } else { $_.id } }
                }
                
                $administrators += [PSCustomObject]@{
                    Id = $assignment.id
                    DisplayName = $assignment.displayName
                    Description = $assignment.description
                    RoleName = $roleName
                    RoleDefinitionId = $roleDefId
                    IsBuiltIn = $isBuiltIn
                    ScopeType = $scopeType
                    MemberCount = $memberCount
                    Members = $memberIds
                    ResourceScopes = $scopeNames
                    RiskLevel = $riskLevel
                    RiskFactors = if ($riskFactors.Count -gt 0) { $riskFactors -join ", " } else { "None" }
                }
            }
            
            $uri = $response.'@odata.nextLink'
        }
        
        if ($administrators.Count -gt 0) {
            $builtIn = ($administrators | Where-Object { $_.IsBuiltIn }).Count
            $custom = $administrators.Count - $builtIn
            $highRisk = ($administrators | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
            
            Write-Host "[+] Found $($administrators.Count) Intune role assignments" -ForegroundColor Green
            Write-Host "    - Built-in roles: $builtIn" -ForegroundColor Gray
            Write-Host "    - Custom roles: $custom" -ForegroundColor $(if ($custom -gt 0) { "Yellow" } else { "Gray" })
            Write-Host "    - High-privilege: $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { "Red" } else { "Gray" })
            
            # Group by role name
            Write-Host "    By Role:" -ForegroundColor Gray
            $roleCounts = $administrators | Group-Object -Property RoleName | Sort-Object Count -Descending | Select-Object -First 5
            foreach ($role in $roleCounts) {
                Write-Host "      - $($role.Name): $($role.Count)" -ForegroundColor Gray
            }
        } else {
            Write-Host "[!] No Intune role assignments found or access denied" -ForegroundColor Yellow
        }
    }
    catch {
        if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
            Write-Host "[!] Access denied. Requires DeviceManagementRBAC.Read.All permission" -ForegroundColor Red
        } else {
            Write-Host "[!] Error enumerating Intune administrators: $_" -ForegroundColor Red
        }
    }
    
    return $administrators
}

function Show-IntuneManagedDevicesReport {
    param([array]$Devices)
    
    Show-SecuritySummary -Data $Devices -Title "INTUNE MANAGED DEVICES" -ShowRisk
    
    Write-Host ("{0,-22} {1,-25} {2,-12} {3,-12} {4,-10} {5,-10} {6,-8}" -f "Device Name", "User", "OS", "Compliance", "Owner", "Encrypted", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    $riskOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3 }
    $sortedDevices = $Devices | Sort-Object { $riskOrder[$_.RiskLevel] }
    
    foreach ($device in ($sortedDevices | Select-Object -First 50)) {
        $name = if ($device.DeviceName) { $device.DeviceName.Substring(0, [Math]::Min(21, $device.DeviceName.Length)) } else { "" }
        $user = if ($device.UserPrincipalName) { $device.UserPrincipalName.Substring(0, [Math]::Min(24, $device.UserPrincipalName.Length)) } else { "" }
        $os = if ($device.OperatingSystem) { $device.OperatingSystem.Substring(0, [Math]::Min(11, $device.OperatingSystem.Length)) } else { "" }
        $compliance = if ($device.ComplianceState) { $device.ComplianceState.Substring(0, [Math]::Min(11, $device.ComplianceState.Length)) } else { "" }
        $owner = if ($device.OwnerType) { $device.OwnerType.Substring(0, [Math]::Min(9, $device.OwnerType.Length)) } else { "" }
        $encrypted = if ($device.IsEncrypted) { "Yes" } else { "No" }
        $risk = $device.RiskLevel
        
        $color = switch ($risk) {
            "CRITICAL" { "Magenta" }
            "HIGH" { "Red" }
            "MEDIUM" { "Yellow" }
            default { "White" }
        }
        
        Write-Host ("{0,-22} {1,-25} {2,-12} {3,-12} {4,-10} {5,-10} {6,-8}" -f $name, $user, $os, $compliance, $owner, $encrypted, $risk) -ForegroundColor $color
    }
    
    if ($Devices.Count -gt 50) {
        Write-Host "    ... and $($Devices.Count - 50) more devices" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 110) -ForegroundColor Gray
}

function Show-IntunePoliciesReport {
    param(
        [array]$Policies,
        [string]$Title = "INTUNE COMPLIANCE POLICIES"
    )
    
    Show-SecuritySummary -Data $Policies -Title $Title -ShowRisk
    
    Write-Host ("{0,-40} {1,-25} {2,-10} {3,-15} {4,-12} {5,-8}" -f "Policy Name", "Type", "Assigned", "Targets", "Exclusions", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 120) -ForegroundColor Gray
    
    $riskOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3 }
    $sortedPolicies = $Policies | Sort-Object { $riskOrder[$_.RiskLevel] }
    
    foreach ($policy in ($sortedPolicies | Select-Object -First 50)) {
        $name = if ($policy.DisplayName) { $policy.DisplayName.Substring(0, [Math]::Min(39, $policy.DisplayName.Length)) } else { "" }
        $pType = if ($policy.PolicyType) { $policy.PolicyType } elseif ($policy.ConfigType) { $policy.ConfigType } else { "" }
        $pType = $pType -replace 'DeviceCompliancePolicy', '' -replace 'DeviceConfiguration', '' -replace 'Configuration', ''
        $pType = if ($pType.Length -gt 24) { $pType.Substring(0, 24) } else { $pType }
        $assigned = $policy.AssignmentCount
        $targets = if ($policy.TargetGroups) { $policy.TargetGroups.Substring(0, [Math]::Min(14, $policy.TargetGroups.Length)) } else { "None" }
        $exclusions = if ($policy.ExcludeGroups) { $policy.ExcludeGroups.Substring(0, [Math]::Min(11, $policy.ExcludeGroups.Length)) } else { "None" }
        $risk = $policy.RiskLevel
        
        $color = switch ($risk) {
            "HIGH" { "Red" }
            "MEDIUM" { "Yellow" }
            default { "White" }
        }
        
        Write-Host ("{0,-40} {1,-25} {2,-10} {3,-15} {4,-12} {5,-8}" -f $name, $pType, $assigned, $targets, $exclusions, $risk) -ForegroundColor $color
    }
    
    if ($Policies.Count -gt 50) {
        Write-Host "    ... and $($Policies.Count - 50) more policies" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 120) -ForegroundColor Gray
}

function Show-IntuneAdministratorsReport {
    param([array]$Administrators)
    
    Show-SecuritySummary -Data $Administrators -Title "INTUNE DEVICE ADMINISTRATORS" -ShowRisk
    
    Write-Host ("{0,-30} {1,-30} {2,-10} {3,-20} {4,-8}" -f "Assignment Name", "Role", "Members", "Scope", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    $riskOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3 }
    $sortedAdmins = $Administrators | Sort-Object { $riskOrder[$_.RiskLevel] }
    
    foreach ($admin in ($sortedAdmins | Select-Object -First 50)) {
        $name = if ($admin.DisplayName) { $admin.DisplayName.Substring(0, [Math]::Min(29, $admin.DisplayName.Length)) } else { "" }
        $role = if ($admin.RoleName) { $admin.RoleName.Substring(0, [Math]::Min(29, $admin.RoleName.Length)) } else { "" }
        $members = $admin.MemberCount
        $scope = if ($admin.ResourceScopes) { ($admin.ResourceScopes -join ", ").Substring(0, [Math]::Min(19, ($admin.ResourceScopes -join ", ").Length)) } else { "All" }
        $risk = $admin.RiskLevel
        
        $color = switch ($risk) {
            "HIGH" { "Red" }
            "MEDIUM" { "Yellow" }
            default { "White" }
        }
        
        Write-Host ("{0,-30} {1,-30} {2,-10} {3,-20} {4,-8}" -f $name, $role, $members, $scope, $risk) -ForegroundColor $color
    }
    
    if ($Administrators.Count -gt 50) {
        Write-Host "    ... and $($Administrators.Count - 50) more assignments" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 110) -ForegroundColor Gray
}

# ============================================================================
# ADMINISTRATIVE UNIT ENUMERATION FEATURES
# ============================================================================

function Get-AdministrativeUnits {
    <#
    .SYNOPSIS
        Enumerate all Administrative Units in Azure AD/Entra ID.
    #>
    Write-Host "[*] Enumerating Administrative Units..." -ForegroundColor Cyan
    
    $adminUnits = @()
    
    try {
        $aus = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$select=id,displayName,description,visibility,membershipType,membershipRule,membershipRuleProcessingState&`$top=999" -ErrorAction Stop
        
        foreach ($au in $aus.value) {
            $auId = $au.id
            
            # Get member count
            $memberCount = 0
            try {
                $countResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auId/members/`$count" -Headers @{ "ConsistencyLevel" = "eventual" } -ErrorAction SilentlyContinue
                $memberCount = [int]$countResponse
            } catch {
                # Try to count manually
                try {
                    $members = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auId/members?`$select=id" -ErrorAction SilentlyContinue
                    $memberCount = $members.value.Count
                } catch { }
            }
            
            # Determine membership type
            $membershipType = if ($au.membershipType) { $au.membershipType } else { "Assigned" }
            $isDynamic = $membershipType -eq "Dynamic"
            
            # Determine visibility
            $visibility = if ($au.visibility) { $au.visibility } else { "Public" }
            $isHidden = $visibility -eq "HiddenMembership"
            
            # Risk assessment
            $riskLevel = "LOW"
            $riskFactors = @()
            
            if ($isHidden) {
                $riskLevel = "MEDIUM"
                $riskFactors += "Hidden membership"
            }
            
            if ($isDynamic) {
                $riskFactors += "Dynamic membership"
            }
            
            $adminUnits += [PSCustomObject]@{
                Id = $auId
                DisplayName = $au.displayName
                Description = $au.description
                Visibility = $visibility
                MembershipType = $membershipType
                MembershipRule = $au.membershipRule
                MembershipRuleProcessingState = $au.membershipRuleProcessingState
                MemberCount = $memberCount
                IsHidden = $isHidden
                IsDynamic = $isDynamic
                RiskLevel = $riskLevel
                RiskFactors = if ($riskFactors.Count -gt 0) { $riskFactors -join ", " } else { "None" }
            }
        }
        
        if ($adminUnits.Count -gt 0) {
            $hiddenCount = ($adminUnits | Where-Object { $_.IsHidden }).Count
            $dynamicCount = ($adminUnits | Where-Object { $_.IsDynamic }).Count
            $totalMembers = ($adminUnits | Measure-Object -Property MemberCount -Sum).Sum
            
            Write-Host "[+] Found $($adminUnits.Count) Administrative Units" -ForegroundColor Green
            Write-Host "    - Total members across all AUs: $totalMembers" -ForegroundColor Gray
            Write-Host "    - Hidden membership AUs: $hiddenCount" -ForegroundColor $(if ($hiddenCount -gt 0) { "Yellow" } else { "Gray" })
            Write-Host "    - Dynamic membership AUs: $dynamicCount" -ForegroundColor Gray
        } else {
            Write-Host "[!] No Administrative Units found or access denied" -ForegroundColor Yellow
        }
    }
    catch {
        if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
            Write-Host "[!] Access denied. Requires AdministrativeUnit.Read.All permission" -ForegroundColor Red
        } else {
            Write-Host "[!] Error enumerating Administrative Units: $_" -ForegroundColor Red
        }
    }
    
    return $adminUnits
}

function Get-AdminUnitMembers {
    <#
    .SYNOPSIS
        Get members of Administrative Units.
    #>
    param(
        [string]$AdminUnitId
    )
    
    $allMembers = @()
    
    # Get all AUs if not specified
    if ($AdminUnitId) {
        $auIds = @([PSCustomObject]@{ Id = $AdminUnitId; DisplayName = "Specified AU" })
    } else {
        Write-Host "[*] Retrieving members from all Administrative Units..." -ForegroundColor Cyan
        $aus = Get-AdministrativeUnits
        $auIds = $aus | ForEach-Object { [PSCustomObject]@{ Id = $_.Id; DisplayName = $_.DisplayName } }
    }
    
    foreach ($au in $auIds) {
        $auId = $au.Id
        $auName = $au.DisplayName
        
        try {
            $members = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auId/members?`$select=id,displayName,userPrincipalName,mail,userType,accountEnabled&`$top=999" -ErrorAction SilentlyContinue
            
            foreach ($member in $members.value) {
                $memberType = if ($member.'@odata.type') { $member.'@odata.type'.Replace("#microsoft.graph.", "") } else { "Unknown" }
                
                $allMembers += [PSCustomObject]@{
                    AdminUnitId = $auId
                    AdminUnitName = $auName
                    MemberId = $member.id
                    DisplayName = $member.displayName
                    UserPrincipalName = $member.userPrincipalName
                    Mail = $member.mail
                    MemberType = $memberType
                    UserType = $member.userType
                    AccountEnabled = if ($null -ne $member.accountEnabled) { $member.accountEnabled } else { $true }
                }
            }
        }
        catch {
            # Silently skip - might not have access to all AUs
        }
    }
    
    if ($allMembers.Count -gt 0) {
        $users = ($allMembers | Where-Object { $_.MemberType -eq "user" }).Count
        $groups = ($allMembers | Where-Object { $_.MemberType -eq "group" }).Count
        $devices = ($allMembers | Where-Object { $_.MemberType -eq "device" }).Count
        
        Write-Host "[+] Found $($allMembers.Count) total members across AUs" -ForegroundColor Green
        Write-Host "    - Users: $users" -ForegroundColor Gray
        Write-Host "    - Groups: $groups" -ForegroundColor Gray
        Write-Host "    - Devices: $devices" -ForegroundColor Gray
    }
    
    return $allMembers
}

function Get-ScopedRoleAssignments {
    <#
    .SYNOPSIS
        Get scoped role assignments for Administrative Units.
        Identifies who has admin privileges scoped to specific AUs.
    #>
    Write-Host "[*] Enumerating Scoped Role Assignments (AU Administrators)..." -ForegroundColor Cyan
    
    $scopedAdmins = @()
    
    # Get all administrative units first
    $aus = Get-AdministrativeUnits
    
    if ($aus.Count -eq 0) {
        return $scopedAdmins
    }
    
    Write-Host "    Checking scoped role assignments for $($aus.Count) AUs..." -ForegroundColor Gray
    
    foreach ($au in $aus) {
        $auId = $au.Id
        $auName = $au.DisplayName
        
        try {
            $scopedMembers = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auId/scopedRoleMembers?`$expand=roleDefinition" -ErrorAction SilentlyContinue
            
            foreach ($member in $scopedMembers.value) {
                $roleInfo = $member.roleDefinition
                $roleName = if ($roleInfo -and $roleInfo.displayName) { $roleInfo.displayName } else { "Unknown Role" }
                $roleId = $member.roleDefinitionId
                
                # Get the principal (admin) details
                $principalId = if ($member.roleMemberInfo) { $member.roleMemberInfo.id } else { "" }
                $principalName = if ($member.roleMemberInfo) { $member.roleMemberInfo.displayName } else { "" }
                
                # Try to get more details about the principal
                $principalType = "Unknown"
                $principalUPN = ""
                if ($principalId) {
                    try {
                        $userInfo = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$principalId`?`$select=userPrincipalName,userType" -ErrorAction SilentlyContinue
                        if ($userInfo) {
                            $principalUPN = $userInfo.userPrincipalName
                            $principalType = "User"
                        }
                    }
                    catch {
                        # Might be a group or service principal
                        try {
                            $groupInfo = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$principalId`?`$select=displayName" -ErrorAction SilentlyContinue
                            if ($groupInfo) {
                                $principalType = "Group"
                            }
                        }
                        catch { }
                    }
                }
                
                # Risk assessment based on role
                $riskLevel = "MEDIUM"  # Scoped admins are generally medium risk
                $riskFactors = @("Scoped admin privileges")
                
                # Check for sensitive roles
                $sensitiveRoles = @(
                    "User Administrator",
                    "Groups Administrator",
                    "Authentication Administrator",
                    "Password Administrator",
                    "Privileged Authentication Administrator",
                    "Helpdesk Administrator"
                )
                
                if ($sensitiveRoles | Where-Object { $roleName -like "*$_*" }) {
                    $riskLevel = "HIGH"
                    $riskFactors += "Sensitive role: $roleName"
                }
                
                $scopedAdmins += [PSCustomObject]@{
                    AdminUnitId = $auId
                    AdminUnitName = $auName
                    AdminUnitHidden = $au.IsHidden
                    RoleDefinitionId = $roleId
                    RoleName = $roleName
                    PrincipalId = $principalId
                    PrincipalName = $principalName
                    PrincipalType = $principalType
                    PrincipalUPN = $principalUPN
                    RiskLevel = $riskLevel
                    RiskFactors = $riskFactors -join ", "
                }
            }
        }
        catch {
            # Silently skip - might not have access to all AUs
        }
    }
    
    if ($scopedAdmins.Count -gt 0) {
        $uniqueAdmins = ($scopedAdmins | Select-Object -Property PrincipalId -Unique).Count
        $uniqueRoles = ($scopedAdmins | Select-Object -Property RoleName -Unique).Count
        $highRisk = ($scopedAdmins | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        
        Write-Host "[+] Found $($scopedAdmins.Count) scoped role assignments" -ForegroundColor Green
        Write-Host "    - Unique administrators: $uniqueAdmins" -ForegroundColor Gray
        Write-Host "    - Unique roles assigned: $uniqueRoles" -ForegroundColor Gray
        Write-Host "    - HIGH risk assignments: $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { "Red" } else { "Gray" })
        
        # Show role distribution
        Write-Host "    Role Distribution:" -ForegroundColor Gray
        $roleCounts = $scopedAdmins | Group-Object -Property RoleName | Sort-Object -Property Count -Descending | Select-Object -First 5
        foreach ($role in $roleCounts) {
            Write-Host "      - $($role.Name): $($role.Count)" -ForegroundColor Gray
        }
    } else {
        Write-Host "[+] No scoped role assignments found or access denied" -ForegroundColor Green
    }
    
    return $scopedAdmins
}

function Show-AdminUnitsReport {
    param([array]$AdminUnits)
    
    Show-SecuritySummary -Data $AdminUnits -Title "ADMINISTRATIVE UNITS ENUMERATION" -ShowRisk
    
    Write-Host ("{0,-29} {1,-11} {2,-9} {3,-9} {4,-17} {5,-7}" -f "AU Name", "Visibility", "Type", "Members", "Rule Processing", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    foreach ($au in ($AdminUnits | Select-Object -First 50)) {
        $name = if ($au.DisplayName) { $au.DisplayName.Substring(0, [Math]::Min(28, $au.DisplayName.Length)) } else { "" }
        $visibility = if ($au.Visibility) { $au.Visibility.Substring(0, [Math]::Min(10, $au.Visibility.Length)) } else { "" }
        $membershipType = if ($au.IsDynamic) { "Dynamic" } else { "Assigned" }
        $members = "$($au.MemberCount)"
        $ruleState = if ($au.MembershipRuleProcessingState) { $au.MembershipRuleProcessingState.Substring(0, [Math]::Min(16, $au.MembershipRuleProcessingState.Length)) } else { "N/A" }
        $risk = $au.RiskLevel
        
        Write-Host ("{0,-29} {1,-11} {2,-9} {3,-9} {4,-17} {5,-7}" -f $name, $visibility, $membershipType, $members, $ruleState, $risk)
    }
    
    if ($AdminUnits.Count -gt 50) {
        Write-Host "    ... and $($AdminUnits.Count - 50) more" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 110) -ForegroundColor Gray
}

function Show-AdminUnitMembersReport {
    param([array]$Members)
    
    Show-SecuritySummary -Data $Members -Title "ADMINISTRATIVE UNIT MEMBERS"
    
    Write-Host ("{0,-24} {1,-24} {2,-34} {3,-9} {4,-7}" -f "Admin Unit", "Member Name", "UPN/Email", "Type", "Enabled") -ForegroundColor Yellow
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    foreach ($member in ($Members | Select-Object -First 50)) {
        $auName = if ($member.AdminUnitName) { $member.AdminUnitName.Substring(0, [Math]::Min(23, $member.AdminUnitName.Length)) } else { "" }
        $name = if ($member.DisplayName) { $member.DisplayName.Substring(0, [Math]::Min(23, $member.DisplayName.Length)) } else { "" }
        $upn = if ($member.UserPrincipalName) { $member.UserPrincipalName.Substring(0, [Math]::Min(33, $member.UserPrincipalName.Length)) } elseif ($member.Mail) { $member.Mail.Substring(0, [Math]::Min(33, $member.Mail.Length)) } else { "" }
        $memberType = if ($member.MemberType) { $member.MemberType.Substring(0, [Math]::Min(8, $member.MemberType.Length)) } else { "" }
        $enabled = if ($member.AccountEnabled) { "Yes" } else { "No" }
        
        Write-Host ("{0,-24} {1,-24} {2,-34} {3,-9} {4,-7}" -f $auName, $name, $upn, $memberType, $enabled)
    }
    
    if ($Members.Count -gt 50) {
        Write-Host "    ... and $($Members.Count - 50) more" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 110) -ForegroundColor Gray
}

function Show-ScopedAdminsReport {
    param([array]$ScopedAdmins)
    
    Show-SecuritySummary -Data $ScopedAdmins -Title "SCOPED ROLE ASSIGNMENTS (AU ADMINISTRATORS)" -ShowRisk
    
    Write-Host ("{0,-21} {1,-27} {2,-21} {3,-24} {4,-7}" -f "Admin Unit", "Role", "Admin Name", "Admin UPN", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    $riskOrder = @{ "HIGH" = 0; "MEDIUM" = 1; "LOW" = 2 }
    $sortedAdmins = $ScopedAdmins | Sort-Object { $riskOrder[$_.RiskLevel] }
    
    foreach ($admin in ($sortedAdmins | Select-Object -First 50)) {
        $auName = if ($admin.AdminUnitName) { $admin.AdminUnitName.Substring(0, [Math]::Min(20, $admin.AdminUnitName.Length)) } else { "" }
        $role = if ($admin.RoleName) { $admin.RoleName.Substring(0, [Math]::Min(26, $admin.RoleName.Length)) } else { "" }
        $name = if ($admin.PrincipalName) { $admin.PrincipalName.Substring(0, [Math]::Min(20, $admin.PrincipalName.Length)) } else { "" }
        $upn = if ($admin.PrincipalUPN) { $admin.PrincipalUPN.Substring(0, [Math]::Min(23, $admin.PrincipalUPN.Length)) } else { "" }
        $risk = $admin.RiskLevel
        
        $color = if ($risk -eq "HIGH") { "Red" } elseif ($risk -eq "MEDIUM") { "Yellow" } else { "White" }
        Write-Host ("{0,-21} {1,-27} {2,-21} {3,-24} {4,-7}" -f $auName, $role, $name, $upn, $risk) -ForegroundColor $color
    }
    
    if ($ScopedAdmins.Count -gt 50) {
        Write-Host "    ... and $($ScopedAdmins.Count - 50) more" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 110) -ForegroundColor Gray
}

# ============================================================================
# LICENSE ENUMERATION FEATURES
# ============================================================================

# Microsoft 365 and Azure AD SKU mappings for common licenses
$script:LicenseSkuMap = @{
    # =========================
    # Azure AD / Entra ID Premium (P2 / P1)
    # =========================
    "AAD_PREMIUM" = @{ Name = "Microsoft Entra ID P1 (Azure AD Premium P1)"; Tier = "P1"; PrivilegeLevel = "MEDIUM" }
    "AAD_PREMIUM_P2" = @{ Name = "Microsoft Entra ID P2 (Azure AD Premium P2)"; Tier = "P2"; PrivilegeLevel = "HIGH" }
    "AAD_PREMIUM_P2_DOD" = @{ Name = "Microsoft Entra ID P2 (DoD)"; Tier = "P2"; PrivilegeLevel = "HIGH" }
    "AAD_PREMIUM_P2_GOV" = @{ Name = "Microsoft Entra ID P2 (Gov)"; Tier = "P2"; PrivilegeLevel = "HIGH" }

    # =========================
    # Microsoft 365 E5 (all variants)
    # =========================
    "M365_E5" = @{ Name = "Microsoft 365 E5"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "MICROSOFT365_E5" = @{ Name = "Microsoft 365 E5"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "SPE_E5" = @{ Name = "Microsoft 365 E5"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "SPE_E5_CALLINGCONF" = @{ Name = "Microsoft 365 E5 with Calling Minutes"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "SPE_E5_NOPSTNCONF" = @{ Name = "Microsoft 365 E5 (without Audio Conferencing)"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "SPE_E5_SLK" = @{ Name = "Microsoft 365 E5 (without Windows)"; Tier = "E5"; PrivilegeLevel = "HIGH" }

    # =========================
    # Microsoft 365 E5 Academic / A5 (E5 equivalent)
    # =========================
    "M365_A5" = @{ Name = "Microsoft 365 A5"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "SPE_E5_STUDENT" = @{ Name = "Microsoft 365 A5 (Student)"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "SPE_E5_FACULTY" = @{ Name = "Microsoft 365 A5 (Faculty)"; Tier = "E5"; PrivilegeLevel = "HIGH" }

    # =========================
    # Office 365 E5 (and A5 equivalent)
    # =========================
    "ENTERPRISEPREMIUM" = @{ Name = "Office 365 E5"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "ENTERPRISEPREMIUM_NOPSTNCONF" = @{ Name = "Office 365 E5 (without Audio Conferencing)"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "ENTERPRISEPREMIUM_GOV" = @{ Name = "Office 365 E5 (Government)"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "ENTERPRISEPREMIUM_FACULTY" = @{ Name = "Office 365 A5 (Faculty)"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "ENTERPRISEPREMIUM_STUDENT" = @{ Name = "Office 365 A5 (Student)"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "OFFICE365_E5" = @{ Name = "Office 365 E5"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "O365_E5" = @{ Name = "Office 365 E5"; Tier = "E5"; PrivilegeLevel = "HIGH" }

    # =========================
    # E5 Security & Compliance Add-ons
    # =========================
    "M365_E5_SECURITY" = @{ Name = "Microsoft 365 E5 Security"; Tier = "E5SEC"; PrivilegeLevel = "HIGH" }
    "IDENTITY_THREAT_PROTECTION" = @{ Name = "Microsoft 365 E5 Security"; Tier = "E5SEC"; PrivilegeLevel = "HIGH" }
    "M365_E5_COMPLIANCE" = @{ Name = "Microsoft 365 E5 Compliance"; Tier = "E5COMP"; PrivilegeLevel = "HIGH" }
    "INFORMATION_PROTECTION_COMPLIANCE" = @{ Name = "Microsoft 365 E5 Compliance"; Tier = "E5COMP"; PrivilegeLevel = "HIGH" }
    "COMMUNICATION_COMPLIANCE" = @{ Name = "Communication Compliance (E5)"; Tier = "E5COMP"; PrivilegeLevel = "HIGH" }
    "E_DISCOVERY_PREMIUM" = @{ Name = "Advanced eDiscovery (E5)"; Tier = "E5COMP"; PrivilegeLevel = "HIGH" }
    "RECORDS_MANAGEMENT_E5" = @{ Name = "Records Management (E5)"; Tier = "E5COMP"; PrivilegeLevel = "HIGH" }

    # =========================
    # EMS / Security (E5-level)
    # =========================
    "EMS_E5" = @{ Name = "Enterprise Mobility + Security E5"; Tier = "P2"; PrivilegeLevel = "HIGH" }
    "EMSPREMIUM" = @{ Name = "Enterprise Mobility + Security E5"; Tier = "P2"; PrivilegeLevel = "HIGH" }
    "EMS_E5_GOV" = @{ Name = "Enterprise Mobility + Security E5 (Gov)"; Tier = "P2"; PrivilegeLevel = "HIGH" }
    "EMS_E5_GCCHIGH" = @{ Name = "Enterprise Mobility + Security E5 (GCC High)"; Tier = "P2"; PrivilegeLevel = "HIGH" }

    # EMS E3 (P1-level)
    "EMS_E3" = @{ Name = "Enterprise Mobility + Security E3"; Tier = "P1"; PrivilegeLevel = "MEDIUM" }
    "EMSPREMIUM_GOV" = @{ Name = "Enterprise Mobility + Security E3 (Gov)"; Tier = "P1"; PrivilegeLevel = "MEDIUM" }

    # =========================
    # Defender (E5-level components)
    # =========================
    "MDE_PLAN2" = @{ Name = "Defender for Endpoint Plan 2"; Tier = "MDE2"; PrivilegeLevel = "HIGH" }
    "MDATP_XPLAT" = @{ Name = "Microsoft Defender for Endpoint"; Tier = "MDE"; PrivilegeLevel = "HIGH" }
    "MDO_PLAN2" = @{ Name = "Defender for Office 365 Plan 2"; Tier = "MDO2"; PrivilegeLevel = "HIGH" }
    "THREAT_INTELLIGENCE" = @{ Name = "Defender for Office 365 Plan 2"; Tier = "MDO2"; PrivilegeLevel = "HIGH" }
    "MCAS" = @{ Name = "Defender for Cloud Apps"; Tier = "P2"; PrivilegeLevel = "HIGH" }
    "M365_DEFENDER" = @{ Name = "Microsoft 365 Defender (XDR)"; Tier = "E5SEC"; PrivilegeLevel = "HIGH" }

    # =========================
    # Microsoft 365 E3 / Office 365 E3
    # =========================
    "SPE_E3" = @{ Name = "Microsoft 365 E3"; Tier = "E3"; PrivilegeLevel = "MEDIUM" }
    "ENTERPRISEPACK" = @{ Name = "Office 365 E3"; Tier = "E3"; PrivilegeLevel = "MEDIUM" }
    "ENTERPRISEPACK_USGOV_DOD" = @{ Name = "Office 365 E3 (DoD)"; Tier = "E3"; PrivilegeLevel = "MEDIUM" }
    "ENTERPRISEPACK_USGOV_GCCHIGH" = @{ Name = "Office 365 E3 (GCC High)"; Tier = "E3"; PrivilegeLevel = "MEDIUM" }

    # =========================
    # Frontline / Entry SKUs (Non-E5)
    # =========================
    "STANDARDPACK" = @{ Name = "Office 365 E1"; Tier = "E1"; PrivilegeLevel = "LOW" }
    "DESKLESSPACK" = @{ Name = "Office 365 F3"; Tier = "F3"; PrivilegeLevel = "LOW" }
    "M365_F1" = @{ Name = "Microsoft 365 F1"; Tier = "F1"; PrivilegeLevel = "LOW" }

    # =========================
    # Business SKUs
    # =========================
    "SPB" = @{ Name = "Microsoft 365 Business Premium"; Tier = "BP"; PrivilegeLevel = "MEDIUM" }
    "O365_BUSINESS_PREMIUM" = @{ Name = "Microsoft 365 Business Standard"; Tier = "BS"; PrivilegeLevel = "LOW" }

    # =========================
    # Developer
    # =========================
    "DEVELOPERPACK_E5" = @{ Name = "Microsoft 365 E5 Developer"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "DEVELOPERPACK" = @{ Name = "Office 365 E3 Developer"; Tier = "E3"; PrivilegeLevel = "MEDIUM" }

    # =========================
    # Information Protection
    # =========================
    "AIP_P1" = @{ Name = "Azure Information Protection P1"; Tier = "AIPP1"; PrivilegeLevel = "MEDIUM" }
    "AIP_P2" = @{ Name = "Azure Information Protection P2"; Tier = "AIPP2"; PrivilegeLevel = "HIGH" }

    # =========================
    # Power BI
    # =========================
    "POWER_BI_PRO" = @{ Name = "Power BI Pro"; Tier = "PBI"; PrivilegeLevel = "LOW" }
    "POWER_BI_PREMIUM" = @{ Name = "Power BI Premium (Per User)"; Tier = "PBIP"; PrivilegeLevel = "MEDIUM" }

    # =========================
    # Intune
    # =========================
    "INTUNE_A" = @{ Name = "Microsoft Intune"; Tier = "INTUNE"; PrivilegeLevel = "MEDIUM" }
    "INTUNE_P2" = @{ Name = "Microsoft Intune Plan 2"; Tier = "INTUNE2"; PrivilegeLevel = "HIGH" }
    "Microsoft_Intune_Suite" = @{ Name = "Microsoft Intune Suite"; Tier = "INTUNE_SUITE"; PrivilegeLevel = "HIGH" }

    # =========================
    # Microsoft 365 Business / EEA (no Teams)
    # =========================
    "Office_365_w/o_Teams_Bundle_Business_Premium" = @{ Name = "Microsoft 365 Business Premium EEA (no Teams)"; Tier = "BP_EEA"; PrivilegeLevel = "MEDIUM" }
    "O365_w/o_Teams_Bundle_M5" = @{ Name = "Microsoft 365 E5 EEA (no Teams)"; Tier = "E5_EEA"; PrivilegeLevel = "HIGH" }
    "O365_BUSINESS_ESSENTIALS" = @{ Name = "Microsoft 365 Business Basic"; Tier = "BB"; PrivilegeLevel = "LOW" }

    # =========================
    # Microsoft Teams (EEA / Essentials)
    # =========================
    "Microsoft_Teams_EEA_New" = @{ Name = "Microsoft Teams EEA"; Tier = "TEAMS_EEA"; PrivilegeLevel = "LOW" }
    "Teams_Ess" = @{ Name = "Microsoft Teams Essentials"; Tier = "TEAMS_ESS"; PrivilegeLevel = "LOW" }
    "TEAMS_ESSENTIALS_AAD" = @{ Name = "Microsoft Teams Essentials (AAD Identity)"; Tier = "TEAMS_ESS"; PrivilegeLevel = "LOW" }

    # =========================
    # Power Platform (Power Automate / Power Apps)
    # =========================
    "FLOW_FREE" = @{ Name = "Microsoft Power Automate Free"; Tier = "FLOW_FREE"; PrivilegeLevel = "LOW" }
    "POWERAUTOMATE_ATTENDED_RPA" = @{ Name = "Power Automate Premium"; Tier = "PA_PREMIUM"; PrivilegeLevel = "MEDIUM" }
    "POWERAPPS_DEV" = @{ Name = "Microsoft Power Apps for Developer"; Tier = "PA_DEV"; PrivilegeLevel = "LOW" }
    "POWERAPPS_VIRAL" = @{ Name = "Microsoft Power Apps Plan 2 Trial"; Tier = "PA_TRIAL"; PrivilegeLevel = "LOW" }

    # =========================
    # Power BI / Microsoft Fabric
    # =========================
    "POWER_BI_STANDARD" = @{ Name = "Microsoft Fabric (Free)"; Tier = "PBI_FREE"; PrivilegeLevel = "LOW" }
    "PBI_PREMIUM_PER_USER" = @{ Name = "Power BI Premium Per User"; Tier = "PBI_PPU"; PrivilegeLevel = "MEDIUM" }

    # =========================
    # Dynamics 365
    # =========================
    "DYN365_ENTERPRISE_SALES" = @{ Name = "Dynamics 365 Sales Enterprise Edition"; Tier = "DYN365_SALES"; PrivilegeLevel = "MEDIUM" }
    "Dynamics_365_Sales_Field_Service_and_Customer_Service_Partner_Sandbox" = @{ Name = "Dynamics 365 Sales, Field Service and Customer Service Partner Sandbox"; Tier = "DYN365_SANDBOX"; PrivilegeLevel = "LOW" }
    "Dynamics_365_Business_Central_Partner_Sandbox" = @{ Name = "Dynamics 365 Business Central Partner Sandbox"; Tier = "DYN365_BC_SANDBOX"; PrivilegeLevel = "LOW" }
    "Dynamics_365_Operations_Application_Partner_Sandbox" = @{ Name = "Dynamics 365 Operations Application Partner Sandbox"; Tier = "DYN365_OPS_SANDBOX"; PrivilegeLevel = "LOW" }
    "DYN365_BUSCENTRAL_PREMIUM" = @{ Name = "Dynamics 365 Business Central Premium"; Tier = "DYN365_BC_PREMIUM"; PrivilegeLevel = "MEDIUM" }
    "DYN365_ENTERPRISE_TEAM_MEMBERS" = @{ Name = "Dynamics 365 Team Members"; Tier = "DYN365_TM"; PrivilegeLevel = "LOW" }
    "DYN365_FINANCIALS_BUSINESS_SKU" = @{ Name = "Dynamics 365 for Financials Business Edition"; Tier = "DYN365_FIN"; PrivilegeLevel = "MEDIUM" }

    # =========================
    # Defender / Security Standalone
    # =========================
    "ADALLOM_STANDALONE" = @{ Name = "Microsoft Defender for Cloud Apps"; Tier = "MDCA"; PrivilegeLevel = "HIGH" }
    "ATP_ENTERPRISE" = @{ Name = "Microsoft Defender for Endpoint P2"; Tier = "MDE_P2"; PrivilegeLevel = "HIGH" }
    "DEFENDER_ENDPOINT_P2" = @{ Name = "Microsoft Defender for Endpoint P2"; Tier = "MDE_P2"; PrivilegeLevel = "HIGH" }

    # =========================
    # SharePoint Advanced Management
    # =========================
    "SharePoint_advanced_management_plan_1" = @{ Name = "SharePoint Advanced Management Plan 1"; Tier = "SPO_ADV"; PrivilegeLevel = "MEDIUM" }
    "SHAREPOINTENTERPRISE" = @{ Name = "SharePoint Online (Plan 2)"; Tier = "SPO_P2"; PrivilegeLevel = "LOW" }

    # =========================
    # Rights Management
    # =========================
    "RIGHTSMANAGEMENT_ADHOC" = @{ Name = "Rights Management Adhoc"; Tier = "RMS_ADHOC"; PrivilegeLevel = "LOW" }
    "RIGHTSMANAGEMENT" = @{ Name = "Azure Rights Management"; Tier = "RMS"; PrivilegeLevel = "LOW" }

    # =========================
    # Project / Visio / Planner
    # =========================
    "PROJECTPREMIUM" = @{ Name = "Planner and Project Plan 5"; Tier = "PROJECT_P5"; PrivilegeLevel = "LOW" }
    "PROJECTPROFESSIONAL" = @{ Name = "Project Plan 3"; Tier = "PROJECT_P3"; PrivilegeLevel = "LOW" }
    "VISIOCLIENT" = @{ Name = "Visio Online Plan 2"; Tier = "VISIO_P2"; PrivilegeLevel = "LOW" }
    "VISIO_PLAN1" = @{ Name = "Visio Online Plan 1"; Tier = "VISIO_P1"; PrivilegeLevel = "LOW" }

    # =========================
    # Windows 365 Cloud PC
    # =========================
    "CPC_E_8C_32GB_512GB" = @{ Name = "Windows 365 Enterprise (8vCPU/32GB/512GB)"; Tier = "W365_ENT"; PrivilegeLevel = "MEDIUM" }
    "CPC_E_4C_16GB_256GB" = @{ Name = "Windows 365 Enterprise (4vCPU/16GB/256GB)"; Tier = "W365_ENT"; PrivilegeLevel = "MEDIUM" }
    "CPC_E_2C_8GB_128GB" = @{ Name = "Windows 365 Enterprise (2vCPU/8GB/128GB)"; Tier = "W365_ENT"; PrivilegeLevel = "MEDIUM" }
}

# Known Microsoft License SKU GUIDs (for fallback when subscribedSkus API fails)
$script:LicenseGuidMap = @{
    # Microsoft 365 E5
    "06ebc4ee-1bb5-47dd-8120-11324bc54e06" = @{ Name = "Microsoft 365 E5"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "44575883-256e-4a79-9da4-ebe9acabe2b2" = @{ Name = "M365 E5 Developer"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "66b55226-6b4f-492c-910c-a3b7a3c9d993" = @{ Name = "M365 F5 Security+Compliance"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "a91fc4e0-65e5-4266-aa76-4f020c3f5e5a" = @{ Name = "M365 E5 (no Audio)"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    # Office 365 E5
    "c7df2760-2c81-4ef7-b578-5b5392b571df" = @{ Name = "Office 365 E5"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    "26d45bd9-adf1-46cd-a9e1-51e9a5524128" = @{ Name = "Office 365 E5 (no Audio)"; Tier = "E5"; PrivilegeLevel = "HIGH" }
    # Microsoft 365 E3
    "05e9a617-0261-4cee-bb44-138d3ef5d965" = @{ Name = "Microsoft 365 E3"; Tier = "E3"; PrivilegeLevel = "MEDIUM" }
    "c2ac2ee4-9bb1-47e4-8541-d689c7e83371" = @{ Name = "M365 E3 (500 seats)"; Tier = "E3"; PrivilegeLevel = "MEDIUM" }
    # Office 365 E3
    "6fd2c87f-b296-42f0-b197-1e91e994b900" = @{ Name = "Office 365 E3"; Tier = "E3"; PrivilegeLevel = "MEDIUM" }
    # Azure AD Premium P2 / Entra ID P2
    "eec0eb4f-6444-4f95-aba0-50c24d67f998" = @{ Name = "Azure AD Premium P2"; Tier = "P2"; PrivilegeLevel = "HIGH" }
    "84a661c4-e949-4bd2-a560-ed7766fcaf2b" = @{ Name = "Azure AD Premium P2"; Tier = "P2"; PrivilegeLevel = "HIGH" }
    # EMS E5
    "b05e124f-c7cc-45a0-a6aa-8cf78c946968" = @{ Name = "EMS E5"; Tier = "P2"; PrivilegeLevel = "HIGH" }
    # Azure AD Premium P1 / Entra ID P1
    "078d2b04-f1bd-4111-bbd4-b4b1b354cef4" = @{ Name = "Azure AD Premium P1"; Tier = "P1"; PrivilegeLevel = "MEDIUM" }
    # EMS E3
    "efccb6f7-5641-4e0e-bd10-b4976e1bf68e" = @{ Name = "EMS E3"; Tier = "P1"; PrivilegeLevel = "MEDIUM" }
    # Office 365 E1
    "18181a46-0d4e-45cd-891e-60aabd171b4e" = @{ Name = "Office 365 E1"; Tier = "E1"; PrivilegeLevel = "LOW" }
    
    # Microsoft 365 Business / EEA (no Teams)
    "a3f586b6-8cce-4d9b-99d6-55238397f77a" = @{ Name = "Microsoft 365 Business Premium EEA (no Teams)"; Tier = "BP_EEA"; PrivilegeLevel = "MEDIUM" }
    "3271cf8e-2be5-4a09-a549-70fd05baaa17" = @{ Name = "Microsoft 365 E5 EEA (no Teams)"; Tier = "E5_EEA"; PrivilegeLevel = "HIGH" }
    "3b555118-da6a-4418-894f-7df1e2096870" = @{ Name = "Microsoft 365 Business Basic"; Tier = "BB"; PrivilegeLevel = "LOW" }
    
    # Microsoft Teams (EEA / Essentials)
    "7e74bd05-2c47-404e-829a-ba95c66fe8e5" = @{ Name = "Microsoft Teams EEA"; Tier = "TEAMS_EEA"; PrivilegeLevel = "LOW" }
    "fde42873-30b6-436b-b361-21af5a6b84ae" = @{ Name = "Microsoft Teams Essentials"; Tier = "TEAMS_ESS"; PrivilegeLevel = "LOW" }
    
    # Power Platform (Power Automate / Power Apps)
    "f30db892-07e9-47e9-837c-80727f46fd3d" = @{ Name = "Microsoft Power Automate Free"; Tier = "FLOW_FREE"; PrivilegeLevel = "LOW" }
    "eda1941c-3c4f-4995-b5eb-e85a42175ab9" = @{ Name = "Power Automate Premium"; Tier = "PA_PREMIUM"; PrivilegeLevel = "MEDIUM" }
    "5b631642-bd26-49fe-bd20-1daaa972ef80" = @{ Name = "Microsoft Power Apps for Developer"; Tier = "PA_DEV"; PrivilegeLevel = "LOW" }
    
    # Power BI / Microsoft Fabric
    "a403ebcc-fae0-4ca2-8c8c-7a907fd6c235" = @{ Name = "Microsoft Fabric (Free)"; Tier = "PBI_FREE"; PrivilegeLevel = "LOW" }
    "c1d032e0-5619-4761-9b5c-75b6831e1711" = @{ Name = "Power BI Premium Per User"; Tier = "PBI_PPU"; PrivilegeLevel = "MEDIUM" }
    
    # Dynamics 365
    "1e1a282c-9c54-43a2-9310-98ef728faace" = @{ Name = "Dynamics 365 Sales Enterprise Edition"; Tier = "DYN365_SALES"; PrivilegeLevel = "MEDIUM" }
    "494721b8-1f30-4315-aba6-70ca169358d9" = @{ Name = "Dynamics 365 Sales, Field Service and Customer Service Partner Sandbox"; Tier = "DYN365_SANDBOX"; PrivilegeLevel = "LOW" }
    "ba6d0090-c4a5-44ee-902d-8d21b297b693" = @{ Name = "Dynamics 365 Business Central Partner Sandbox"; Tier = "DYN365_BC_SANDBOX"; PrivilegeLevel = "LOW" }
    "dd3d7238-2392-4177-a46d-753170e95f48" = @{ Name = "Dynamics 365 Operations Application Partner Sandbox"; Tier = "DYN365_OPS_SANDBOX"; PrivilegeLevel = "LOW" }
    "f991cecc-3f91-4cd0-a9a8-bf1c8167e029" = @{ Name = "Dynamics 365 Business Central Premium"; Tier = "DYN365_BC_PREMIUM"; PrivilegeLevel = "MEDIUM" }
    
    # Defender / Security Standalone
    "df845ce7-05f9-4894-b5f2-11bbfbcfd2b6" = @{ Name = "Microsoft Defender for Cloud Apps"; Tier = "MDCA"; PrivilegeLevel = "HIGH" }
    
    # Intune Suite
    "a929cd4d-8672-47c9-8664-159c1f322ba8" = @{ Name = "Microsoft Intune Suite"; Tier = "INTUNE_SUITE"; PrivilegeLevel = "HIGH" }
    
    # SharePoint Advanced Management
    "6ee9b90c-0a7a-46c4-bc96-6698aa3bf8d2" = @{ Name = "SharePoint Advanced Management Plan 1"; Tier = "SPO_ADV"; PrivilegeLevel = "MEDIUM" }
    
    # Rights Management
    "8c4ce438-32a7-4ac5-91a6-e22ae08d9c8b" = @{ Name = "Rights Management Adhoc"; Tier = "RMS_ADHOC"; PrivilegeLevel = "LOW" }
    
    # Project / Visio / Planner
    "09015f9f-377f-4538-bbb5-f75ceb09358a" = @{ Name = "Planner and Project Plan 5"; Tier = "PROJECT_P5"; PrivilegeLevel = "LOW" }
    "c5928f49-12ba-48f7-ada3-0d743a3601d5" = @{ Name = "Visio Online Plan 2"; Tier = "VISIO_P2"; PrivilegeLevel = "LOW" }
    
    # Windows 365 Cloud PC
    "9fb0ba5f-4825-4e84-b239-5167a3a5d4dc" = @{ Name = "Windows 365 Enterprise (8vCPU/32GB/512GB)"; Tier = "W365_ENT"; PrivilegeLevel = "MEDIUM" }
}

# SKUs that indicate high privilege capabilities
$script:HighPrivilegeFeatures = @{
    "E5" = @(
        "Advanced eDiscovery",
        "Defender for Endpoint",
        "Defender for Identity",
        "Information Protection",
        "Insider Risk Management"
    )
    "P2" = @(
        "Privileged Identity Management (PIM)",
        "Identity Protection (risky users/sign-ins)",
        "Access Reviews",
        "Entitlement Management",
        "Identity Governance"
    )
    "P1" = @(
        "Conditional Access",
        "MFA (Azure MFA)",
        "Self-Service Password Reset",
        "Group-based licensing"
    )
    "E5SEC" = @(
        "Microsoft 365 Defender",
        "Cloud App Security",
        "Safe Attachments",
        "Safe Links"
    )
}

function Get-SubscribedSkus {
    <#
    .SYNOPSIS
        Get all subscribed SKUs (licenses) in the tenant.
    .DESCRIPTION
        Enumerates license SKUs and identifies privilege levels.
        Requires Organization.Read.All or Directory.Read.All permission.
    #>
    Write-Host "[*] Enumerating Tenant License SKUs..." -ForegroundColor Cyan
    
    $tenantSkus = @()
    
    try {
        $skusResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/subscribedSkus?`$select=id,skuId,skuPartNumber,appliesTo,capabilityStatus,consumedUnits,prepaidUnits,servicePlans" -ErrorAction Stop
        
        foreach ($sku in $skusResponse.value) {
            $skuPart = $sku.skuPartNumber
            
            # Look up SKU info from mapping
            $skuInfo = if ($script:LicenseSkuMap.ContainsKey($skuPart)) {
                $script:LicenseSkuMap[$skuPart]
            } else {
                @{ Name = $skuPart; Tier = "Unknown"; PrivilegeLevel = "LOW" }
            }
            
            $prepaid = $sku.prepaidUnits
            $enabledUnits = if ($prepaid) { $prepaid.enabled } else { 0 }
            $consumed = $sku.consumedUnits
            
            # Get service plan names
            $servicePlans = $sku.servicePlans
            $enabledPlans = ($servicePlans | Where-Object { $_.provisioningStatus -eq "Success" } | Select-Object -First 5).servicePlanName
            
            $tenantSkus += [PSCustomObject]@{
                SkuId = $sku.skuId
                SkuPartNumber = $skuPart
                DisplayName = $skuInfo.Name
                Tier = $skuInfo.Tier
                PrivilegeLevel = $skuInfo.PrivilegeLevel
                CapabilityStatus = $sku.capabilityStatus
                EnabledUnits = $enabledUnits
                ConsumedUnits = $consumed
                AvailableUnits = if ($enabledUnits -and $consumed) { $enabledUnits - $consumed } else { 0 }
                ServicePlanCount = $servicePlans.Count
                EnabledServicePlans = if ($enabledPlans) { ($enabledPlans -join ", ").Substring(0, [Math]::Min(60, ($enabledPlans -join ", ").Length)) } else { "" }
                RiskLevel = if ($skuInfo.PrivilegeLevel -eq "HIGH") { "HIGH" } elseif ($skuInfo.PrivilegeLevel -eq "MEDIUM") { "MEDIUM" } else { "LOW" }
            }
        }
        
        if ($tenantSkus.Count -gt 0) {
            $highPriv = ($tenantSkus | Where-Object { $_.PrivilegeLevel -eq "HIGH" }).Count
            $e5Count = ($tenantSkus | Where-Object { $_.Tier -eq "E5" }).Count
            $p2Count = ($tenantSkus | Where-Object { $_.Tier -eq "P2" }).Count
            
            Write-Host "[+] Found $($tenantSkus.Count) subscribed SKUs" -ForegroundColor Green
            Write-Host "    - HIGH privilege SKUs: $highPriv" -ForegroundColor $(if ($highPriv -gt 0) { "Yellow" } else { "Gray" })
            Write-Host "    - E5 tier SKUs: $e5Count" -ForegroundColor $(if ($e5Count -gt 0) { "Yellow" } else { "Gray" })
            Write-Host "    - P2 tier SKUs: $p2Count" -ForegroundColor $(if ($p2Count -gt 0) { "Yellow" } else { "Gray" })
        } else {
            Write-Host "[!] No subscribed SKUs found or access denied" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Error fetching subscribed SKUs: $_" -ForegroundColor Red
        Write-Host "    Requires Organization.Read.All or Directory.Read.All permission" -ForegroundColor Gray
    }
    
    return $tenantSkus
}

function Get-UserLicenses {
    <#
    .SYNOPSIS
        Enumerate assigned licenses per user.
    .DESCRIPTION
        Identifies users with E5, P2, and other high-privilege licenses.
        Highlights guests and disabled accounts with premium licenses.
    #>
    Write-Host "[*] Enumerating User License Assignments..." -ForegroundColor Cyan
    
    $licensedUsers = @()
    
    try {
        # First get all subscribed SKUs for mapping
        $skuMap = @{}
        $skusResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/subscribedSkus?`$select=skuId,skuPartNumber" -ErrorAction SilentlyContinue
        if ($skusResponse) {
            foreach ($sku in $skusResponse.value) {
                $skuId = $sku.skuId
                $skuPart = $sku.skuPartNumber
                $skuMap[$skuId] = $skuPart
                # Debug: show E5-related SKUs found in tenant
                if ($skuPart -and ($skuPart.ToUpper() -match "E5" -or $skuPart.ToUpper() -match "ENTERPRISEPREMIUM")) {
                    Write-Host "    [DEBUG] Found E5 SKU: $skuPart (ID: $skuId)" -ForegroundColor Cyan
                }
            }
            if ($skuMap.Count -gt 0) {
                Write-Host "    Loaded $($skuMap.Count) SKU mappings from tenant" -ForegroundColor Gray
            } else {
                Write-Host "    [WARN] No SKU mappings loaded, will use GUID fallback" -ForegroundColor Yellow
            }
        } else {
            Write-Host "    [WARN] Could not load SKU mappings, will use GUID fallback" -ForegroundColor Yellow
        }
        
        # Get users with licenses using Graph SDK
        Write-Host "    Fetching licensed users..." -ForegroundColor Gray
        $users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,AssignedLicenses -ErrorAction Stop
        
        $usersWithLicenses = $users | Where-Object { $_.AssignedLicenses.Count -gt 0 }
        Write-Host "    Processing $($usersWithLicenses.Count) users with licenses..." -ForegroundColor Gray
        
        $counter = 0
        foreach ($user in $usersWithLicenses) {
            $counter++
            if ($counter % 100 -eq 0) {
                Write-Host "    Processed $counter/$($usersWithLicenses.Count) users..." -ForegroundColor Gray
            }
            
            $assignedLicenses = $user.AssignedLicenses
            
            # Parse license assignments
            $licenseNames = @()
            $licenseTiers = @()
            $privilegeLevels = @()
            $highPrivFeatures = @()
            
            foreach ($lic in $assignedLicenses) {
                $skuId = $lic.SkuId
                $skuPart = $skuMap[$skuId]
                $skuInfo = $null
                
                # Try to get SKU info from multiple sources
                if ($skuPart) {
                    # First try: exact match in LicenseSkuMap by part number
                    if ($script:LicenseSkuMap.ContainsKey($skuPart)) {
                        $skuInfo = $script:LicenseSkuMap[$skuPart]
                    }
                    
                    # Second try: pattern-based detection from part number
                    if (-not $skuInfo) {
                        $skuUpper = $skuPart.ToUpper()
                        # Detect E5 variants
                        $isE5 = ($skuUpper -match "_E5" -or $skuUpper -match "E5_" -or 
                                 $skuUpper.EndsWith("E5") -or $skuUpper -match "ENTERPRISEPREMIUM" -or
                                 $skuUpper -match "365E5" -or $skuUpper -match "365_E5" -or
                                 $skuUpper -match "M365E5" -or $skuUpper -match "O365E5")
                        
                        if ($isE5) {
                            $skuInfo = @{ Name = $skuPart; Tier = "E5"; PrivilegeLevel = "HIGH" }
                        }
                        # Detect P2 variants
                        elseif ($skuUpper -match "_P2" -or $skuUpper -match "P2_" -or 
                                $skuUpper.EndsWith("P2") -or $skuUpper -match "PREMIUM_P2" -or
                                ($skuUpper -match "EMS" -and $skuUpper -match "E5")) {
                            $skuInfo = @{ Name = $skuPart; Tier = "P2"; PrivilegeLevel = "HIGH" }
                        }
                        # Detect E3 variants
                        elseif ($skuUpper -match "_E3" -or $skuUpper -match "E3_" -or 
                                $skuUpper.EndsWith("E3") -or $skuUpper -match "ENTERPRISEPACK" -or
                                $skuUpper -match "365E3") {
                            $skuInfo = @{ Name = $skuPart; Tier = "E3"; PrivilegeLevel = "MEDIUM" }
                        }
                        # Detect P1 variants
                        elseif ($skuUpper -match "_P1" -or $skuUpper -match "P1_" -or 
                                $skuUpper.EndsWith("P1") -or $skuUpper -match "AAD_PREMIUM") {
                            $skuInfo = @{ Name = $skuPart; Tier = "P1"; PrivilegeLevel = "MEDIUM" }
                        }
                    }
                }
                
                # Third try: lookup by SKU GUID (fallback)
                if (-not $skuInfo -and $skuId) {
                    $skuIdLower = $skuId.ToLower()
                    if ($script:LicenseGuidMap.ContainsKey($skuIdLower)) {
                        $skuInfo = $script:LicenseGuidMap[$skuIdLower]
                    }
                }
                
                # Final fallback: unknown license
                if (-not $skuInfo) {
                    if ($skuPart) {
                        $skuInfo = @{ Name = $skuPart; Tier = "Unknown"; PrivilegeLevel = "LOW" }
                        Write-Host "    [DEBUG] Unrecognized SKU: $skuPart (ID: $skuId)" -ForegroundColor Yellow
                    } else {
                        $skuInfo = @{ Name = "SKU:$($skuId.Substring(0, [Math]::Min(8, $skuId.Length)))..."; Tier = "Unknown"; PrivilegeLevel = "LOW" }
                        Write-Host "    [DEBUG] Unknown SKU ID: $skuId" -ForegroundColor Yellow
                    }
                }
                
                $licenseNames += $skuInfo.Name
                if ($skuInfo.Tier -notin $licenseTiers) { $licenseTiers += $skuInfo.Tier }
                if ($skuInfo.PrivilegeLevel -notin $privilegeLevels) { $privilegeLevels += $skuInfo.PrivilegeLevel }
                
                # Check for high-privilege features
                if ($script:HighPrivilegeFeatures.ContainsKey($skuInfo.Tier)) {
                    $highPrivFeatures += $script:HighPrivilegeFeatures[$skuInfo.Tier]
                }
            }
            
            # Determine overall privilege level
            $overallPrivilege = if ("HIGH" -in $privilegeLevels) { "HIGH" } 
                              elseif ("MEDIUM" -in $privilegeLevels) { "MEDIUM" } 
                              else { "LOW" }
            
            # Risk assessment based on licenses
            $riskLevel = "LOW"
            $riskFactors = @()
            
            if ("E5" -in $licenseTiers -or "P2" -in $licenseTiers) {
                $riskLevel = "HIGH"
                $riskFactors += "Premium license (E5/P2)"
            }
            elseif ("P1" -in $licenseTiers -or "E3" -in $licenseTiers) {
                if ($riskLevel -eq "LOW") { $riskLevel = "MEDIUM" }
                $riskFactors += "Standard premium (E3/P1)"
            }
            
            # Check if disabled account has premium license
            if (-not $user.AccountEnabled -and $overallPrivilege -in @("HIGH", "MEDIUM")) {
                $riskFactors += "Disabled with premium"
            }
            
            # Check if guest has premium license
            if ($user.UserType -eq "Guest" -and $overallPrivilege -eq "HIGH") {
                $riskLevel = "HIGH"
                $riskFactors += "Guest with premium"
            }
            
            $licensedUsers += [PSCustomObject]@{
                Id = $user.Id
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Mail = $user.Mail
                AccountEnabled = $user.AccountEnabled
                UserType = $user.UserType
                LicenseCount = $assignedLicenses.Count
                Licenses = ($licenseNames | Select-Object -First 3) -join ", "
                LicenseTiers = ($licenseTiers | Sort-Object) -join ", "
                PrivilegeLevel = $overallPrivilege
                HasE5 = "E5" -in $licenseTiers
                HasP2 = "P2" -in $licenseTiers
                HasP1 = "P1" -in $licenseTiers
                HighPrivilegeFeatures = ($highPrivFeatures | Select-Object -First 5 -Unique) -join ", "
                RiskLevel = $riskLevel
                RiskFactors = if ($riskFactors.Count -gt 0) { $riskFactors -join ", " } else { "None" }
            }
        }
        
        if ($licensedUsers.Count -gt 0) {
            $highPriv = ($licensedUsers | Where-Object { $_.PrivilegeLevel -eq "HIGH" }).Count
            $e5Users = ($licensedUsers | Where-Object { $_.HasE5 }).Count
            $p2Users = ($licensedUsers | Where-Object { $_.HasP2 }).Count
            $guestsWithPremium = ($licensedUsers | Where-Object { $_.UserType -eq "Guest" -and $_.PrivilegeLevel -eq "HIGH" }).Count
            
            Write-Host "[+] Found $($licensedUsers.Count) licensed users" -ForegroundColor Green
            Write-Host "    - HIGH privilege licenses: $highPriv" -ForegroundColor $(if ($highPriv -gt 0) { "Yellow" } else { "Gray" })
            Write-Host "    - Users with E5: $e5Users" -ForegroundColor $(if ($e5Users -gt 0) { "Yellow" } else { "Gray" })
            Write-Host "    - Users with P2: $p2Users" -ForegroundColor $(if ($p2Users -gt 0) { "Yellow" } else { "Gray" })
            if ($guestsWithPremium -gt 0) {
                Write-Host "    - Guests with premium: $guestsWithPremium (RISK)" -ForegroundColor Red
            }
        } else {
            Write-Host "[!] No licensed users found or access denied" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[!] Error: $_" -ForegroundColor Red
    }
    
    return $licensedUsers
}

function Get-PrivilegedLicenseUsers {
    <#
    .SYNOPSIS
        Specifically enumerate users with E5 or P2 licenses.
    .DESCRIPTION
        Identifies users with elevated security/admin capabilities
        provided by premium licenses like E5 (Defender, eDiscovery)
        and P2 (PIM, Identity Protection).
    #>
    Write-Host "[*] Identifying Users with High-Privilege Licenses (E5/P2)..." -ForegroundColor Cyan
    
    $allLicensed = Get-UserLicenses
    
    # Filter for high-privilege users
    $privilegedUsers = $allLicensed | Where-Object { $_.HasE5 -or $_.HasP2 -or $_.PrivilegeLevel -eq "HIGH" }
    
    if ($privilegedUsers.Count -gt 0) {
        Write-Host "`n[+] $($privilegedUsers.Count) users with elevated license privileges:" -ForegroundColor Green
        
        # Categorize by feature access
        $pimUsers = ($privilegedUsers | Where-Object { $_.HasP2 }).Count
        $defenderUsers = ($privilegedUsers | Where-Object { $_.HasE5 }).Count
        
        if ($pimUsers -gt 0) {
            Write-Host "    - PIM-eligible users (P2): $pimUsers" -ForegroundColor Yellow
        }
        if ($defenderUsers -gt 0) {
            Write-Host "    - Advanced security features (E5): $defenderUsers" -ForegroundColor Yellow
        }
        
        # Identify concerning patterns
        $guestPrivileged = ($privilegedUsers | Where-Object { $_.UserType -eq "Guest" }).Count
        $disabledPrivileged = ($privilegedUsers | Where-Object { -not $_.AccountEnabled }).Count
        
        if ($guestPrivileged -gt 0) {
            Write-Host "    !!! Guests with E5/P2: $guestPrivileged" -ForegroundColor Red
        }
        if ($disabledPrivileged -gt 0) {
            Write-Host "    !!! Disabled accounts with E5/P2: $disabledPrivileged" -ForegroundColor Red
        }
    }
    
    return $privilegedUsers
}

function Show-TenantSkusReport {
    param([array]$Skus)
    
    Show-SecuritySummary -Data $Skus -Title "TENANT LICENSE SKUs REPORT" -ShowRisk
    
    Write-Host ("{0,-39} {1,-7} {2,-9} {3,-14} {4,-11}" -f "SKU Name", "Tier", "Privilege", "Used/Total", "Status") -ForegroundColor Yellow
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    # Sort by privilege level
    $privOrder = @{ "HIGH" = 0; "MEDIUM" = 1; "LOW" = 2 }
    $sortedSkus = $Skus | Sort-Object { $privOrder[$_.PrivilegeLevel] }
    
    foreach ($sku in ($sortedSkus | Select-Object -First 50)) {
        $name = if ($sku.DisplayName) { $sku.DisplayName.Substring(0, [Math]::Min(38, $sku.DisplayName.Length)) } elseif ($sku.SkuPartNumber) { $sku.SkuPartNumber.Substring(0, [Math]::Min(38, $sku.SkuPartNumber.Length)) } else { "" }
        $tier = if ($sku.Tier) { $sku.Tier.Substring(0, [Math]::Min(6, $sku.Tier.Length)) } else { "" }
        $priv = if ($sku.PrivilegeLevel) { $sku.PrivilegeLevel.Substring(0, [Math]::Min(8, $sku.PrivilegeLevel.Length)) } else { "LOW" }
        $usage = "$($sku.ConsumedUnits)/$($sku.EnabledUnits)"
        $status = if ($sku.CapabilityStatus) { $sku.CapabilityStatus.Substring(0, [Math]::Min(10, $sku.CapabilityStatus.Length)) } else { "" }
        
        $color = if ($priv -eq "HIGH") { "Yellow" } elseif ($priv -eq "MEDIUM") { "White" } else { "Gray" }
        Write-Host ("{0,-39} {1,-7} {2,-9} {3,-14} {4,-11}" -f $name, $tier, $priv, $usage, $status) -ForegroundColor $color
    }
    
    if ($Skus.Count -gt 50) {
        Write-Host "    ... and $($Skus.Count - 50) more SKUs" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    # Show high-privilege SKU summary
    $highPriv = $Skus | Where-Object { $_.PrivilegeLevel -eq "HIGH" }
    if ($highPriv.Count -gt 0) {
        Write-Host "`n!!! HIGH PRIVILEGE SKUs (enable admin/security features):" -ForegroundColor Red
        foreach ($sku in $highPriv) {
            $features = if ($script:HighPrivilegeFeatures.ContainsKey($sku.Tier)) {
                ($script:HighPrivilegeFeatures[$sku.Tier] | Select-Object -First 3) -join ", "
            } else { "" }
            if ($features) {
                Write-Host "   * $($sku.DisplayName): $features" -ForegroundColor Yellow
            }
        }
    }
}

function Show-UserLicensesReport {
    param([array]$Users)
    
    Show-SecuritySummary -Data $Users -Title "USER LICENSE ASSIGNMENTS" -ShowRisk
    
    Write-Host ("{0,-24} {1,-34} {2,-24} {3,-9} {4,-7} {5,-6}" -f "Display Name", "Email/UPN", "Licenses", "Tier", "Priv", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 115) -ForegroundColor Gray
    
    # Sort by privilege/risk
    $riskOrder = @{ "HIGH" = 0; "MEDIUM" = 1; "LOW" = 2 }
    $sortedUsers = $Users | Sort-Object { $riskOrder[$_.RiskLevel] }, { -$_.LicenseCount }
    
    foreach ($user in ($sortedUsers | Select-Object -First 50)) {
        $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(23, $user.DisplayName.Length)) } else { "" }
        $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(33, $user.UserPrincipalName.Length)) } elseif ($user.Mail) { $user.Mail.Substring(0, [Math]::Min(33, $user.Mail.Length)) } else { "" }
        $licenses = if ($user.Licenses) { $user.Licenses.Substring(0, [Math]::Min(23, $user.Licenses.Length)) } else { "" }
        $tiers = if ($user.LicenseTiers) { $user.LicenseTiers.Substring(0, [Math]::Min(8, $user.LicenseTiers.Length)) } else { "" }
        $priv = if ($user.PrivilegeLevel) { $user.PrivilegeLevel.Substring(0, [Math]::Min(6, $user.PrivilegeLevel.Length)) } else { "LOW" }
        $risk = $user.RiskLevel
        
        $color = if ($risk -eq "HIGH") { "Yellow" } elseif ($risk -eq "MEDIUM") { "White" } else { "Gray" }
        Write-Host ("{0,-24} {1,-34} {2,-24} {3,-9} {4,-7} {5,-6}" -f $name, $email, $licenses, $tiers, $priv, $risk) -ForegroundColor $color
    }
    
    if ($Users.Count -gt 50) {
        Write-Host "    ... and $($Users.Count - 50) more users" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 115) -ForegroundColor Gray
    
    # Show high-risk findings
    $highRisk = $Users | Where-Object { $_.RiskLevel -eq "HIGH" }
    if ($highRisk.Count -gt 0) {
        Write-Host "`n!!! $($highRisk.Count) HIGH RISK license assignments found" -ForegroundColor Red
        $guests = ($highRisk | Where-Object { $_.UserType -eq "Guest" }).Count
        if ($guests -gt 0) {
            Write-Host "   * $guests guests with premium licenses" -ForegroundColor Yellow
        }
        $disabled = ($highRisk | Where-Object { -not $_.AccountEnabled }).Count
        if ($disabled -gt 0) {
            Write-Host "   * $disabled disabled accounts with premium licenses" -ForegroundColor Yellow
        }
    }
}

function Show-PrivilegedLicenseUsersReport {
    param([array]$Users)
    
    Write-Host ("`n" + ("=" * 115)) -ForegroundColor Cyan
    Write-Host ("{0,58}" -f "USERS WITH E5/P2 PRIVILEGES (HIGH-PRIVILEGE LICENSES)") -ForegroundColor Cyan
    Write-Host ("=" * 115) -ForegroundColor Cyan
    
    if ($Users.Count -eq 0) {
        Write-Host "`nNo users with E5/P2 licenses found." -ForegroundColor Gray
        return
    }
    
    $e5Users = ($Users | Where-Object { $_.HasE5 }).Count
    $p2Users = ($Users | Where-Object { $_.HasP2 }).Count
    $bothUsers = ($Users | Where-Object { $_.HasE5 -and $_.HasP2 }).Count
    
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "  * Total high-privilege users: $($Users.Count)"
    Write-Host "  * Users with E5 (Defender, eDiscovery, etc.): $e5Users" -ForegroundColor $(if ($e5Users -gt 0) { "Yellow" } else { "Gray" })
    Write-Host "  * Users with P2 (PIM, Identity Protection): $p2Users" -ForegroundColor $(if ($p2Users -gt 0) { "Yellow" } else { "Gray" })
    Write-Host "  * Users with both E5 and P2: $bothUsers" -ForegroundColor $(if ($bothUsers -gt 0) { "Magenta" } else { "Gray" })
    
    Write-Host ("`n{0,-24} {1,-34} {2,-4} {3,-4} {4,-8} {5,-7} {6,-29}" -f "Display Name", "Email/UPN", "E5", "P2", "Enabled", "Type", "Features") -ForegroundColor Yellow
    Write-Host ("-" * 120) -ForegroundColor Gray
    
    foreach ($user in ($Users | Select-Object -First 50)) {
        $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(23, $user.DisplayName.Length)) } else { "" }
        $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(33, $user.UserPrincipalName.Length)) } else { "" }
        $hasE5 = if ($user.HasE5) { "Yes" } else { "No" }
        $hasP2 = if ($user.HasP2) { "Yes" } else { "No" }
        $enabled = if ($user.AccountEnabled) { "Yes" } else { "No" }
        $userType = if ($user.UserType) { $user.UserType.Substring(0, [Math]::Min(6, $user.UserType.Length)) } else { "Member" }
        $features = if ($user.HighPrivilegeFeatures) { $user.HighPrivilegeFeatures.Substring(0, [Math]::Min(28, $user.HighPrivilegeFeatures.Length)) } else { "" }
        
        $color = if (-not $user.AccountEnabled -or $user.UserType -eq "Guest") { "Red" } elseif ($user.HasE5 -and $user.HasP2) { "Magenta" } else { "White" }
        Write-Host ("{0,-24} {1,-34} {2,-4} {3,-4} {4,-8} {5,-7} {6,-29}" -f $name, $email, $hasE5, $hasP2, $enabled, $userType, $features) -ForegroundColor $color
    }
    
    if ($Users.Count -gt 50) {
        Write-Host "    ... and $($Users.Count - 50) more users" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 120) -ForegroundColor Gray
    
    # Security recommendations
    Write-Host "`nSecurity Considerations for E5/P2 Users:" -ForegroundColor Yellow
    Write-Host "   * E5 users can access advanced eDiscovery and may view sensitive data" -ForegroundColor Gray
    Write-Host "   * P2 users can potentially self-activate privileged roles via PIM" -ForegroundColor Gray
    Write-Host "   * Review if all assigned premium licenses are necessary" -ForegroundColor Gray
    Write-Host "   * Consider enabling PIM approval workflows for role activation" -ForegroundColor Gray
}

# ============================================================================
# DIRECTORY SYNC STATUS FUNCTIONS
# ============================================================================

function Get-DirectorySyncStatus {
    <#
    .SYNOPSIS
        Get directory sync status for all users.
        Identifies on-prem synced vs cloud-only users.
    #>
    
    Write-Host "`n[*] Analyzing directory sync status..." -ForegroundColor Cyan
    
    $results = @{
        SyncedUsers = @()
        CloudOnlyUsers = @()
        SyncErrors = @()
        Summary = @{}
    }
    
    try {
        # Get all users with sync-related properties
        $selectFields = "id,displayName,userPrincipalName,mail,accountEnabled,userType,onPremisesSyncEnabled,onPremisesDistinguishedName,onPremisesDomainName,onPremisesLastSyncDateTime,onPremisesSecurityIdentifier,onPremisesSamAccountName,onPremisesImmutableId,onPremisesProvisioningErrors"
        
        $allUsers = @()
        $uri = "https://graph.microsoft.com/v1.0/users?`$select=$selectFields&`$top=999"
        
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $allUsers += $response.value
            $uri = $response.'@odata.nextLink'
            
            if ($uri) {
                Write-Host "    Retrieved $($allUsers.Count) users so far..." -ForegroundColor Gray
            }
        } while ($uri)
        
        Write-Host "[+] Retrieved $($allUsers.Count) total users" -ForegroundColor Green
        
        # Categorize users
        foreach ($user in $allUsers) {
            $isSynced = $user.onPremisesSyncEnabled -eq $true -or $user.onPremisesImmutableId -or $user.onPremisesSecurityIdentifier
            $provErrors = $user.onPremisesProvisioningErrors
            
            $userInfo = [PSCustomObject]@{
                Id = $user.id
                DisplayName = $user.displayName
                UserPrincipalName = $user.userPrincipalName
                Mail = $user.mail
                AccountEnabled = $user.accountEnabled
                UserType = $user.userType
                OnPremisesSyncEnabled = $isSynced
                OnPremisesDomainName = $user.onPremisesDomainName
                OnPremisesSamAccountName = $user.onPremisesSamAccountName
                OnPremisesDistinguishedName = $user.onPremisesDistinguishedName
                OnPremisesLastSyncDateTime = $user.onPremisesLastSyncDateTime
                OnPremisesImmutableId = $user.onPremisesImmutableId
                OnPremisesSecurityIdentifier = $user.onPremisesSecurityIdentifier
                ProvisioningErrors = $provErrors
                SyncSource = if ($isSynced) { "On-Premises AD" } else { "Cloud-Only" }
                RiskLevel = "LOW"
                RiskFactors = ""
                DaysSinceLastSync = $null
            }
            
            # Determine risk level
            $riskFactors = @()
            
            if ($provErrors -and $provErrors.Count -gt 0) {
                $userInfo.RiskLevel = "HIGH"
                $riskFactors += "Sync errors"
            }
            
            if ($isSynced) {
                $results.SyncedUsers += $userInfo
                
                # Check for stale sync (no sync in 7+ days)
                if ($user.onPremisesLastSyncDateTime) {
                    try {
                        $lastSync = [DateTime]::Parse($user.onPremisesLastSyncDateTime)
                        $daysSince = ((Get-Date) - $lastSync).Days
                        $userInfo.DaysSinceLastSync = $daysSince
                        if ($daysSince -gt 7) {
                            if ($userInfo.RiskLevel -eq "LOW") { $userInfo.RiskLevel = "MEDIUM" }
                            $riskFactors += "Stale sync (${daysSince}d)"
                        }
                    }
                    catch { }
                }
            }
            else {
                $results.CloudOnlyUsers += $userInfo
            }
            
            $userInfo.RiskFactors = $riskFactors -join ", "
            
            if ($provErrors -and $provErrors.Count -gt 0) {
                $results.SyncErrors += $userInfo
            }
        }
        
        # Build summary
        $results.Summary = @{
            TotalUsers = $allUsers.Count
            SyncedUsers = $results.SyncedUsers.Count
            CloudOnlyUsers = $results.CloudOnlyUsers.Count
            UsersWithSyncErrors = $results.SyncErrors.Count
            SyncedPercentage = if ($allUsers.Count -gt 0) { [Math]::Round($results.SyncedUsers.Count / $allUsers.Count * 100, 1) } else { 0 }
            CloudOnlyPercentage = if ($allUsers.Count -gt 0) { [Math]::Round($results.CloudOnlyUsers.Count / $allUsers.Count * 100, 1) } else { 0 }
        }
    }
    catch {
        Write-Host "[!] Error getting directory sync status: $_" -ForegroundColor Red
    }
    
    return $results
}

function Get-DirectorySyncErrors {
    <#
    .SYNOPSIS
        Get users with directory sync errors.
    #>
    
    Write-Host "`n[*] Checking for directory sync errors..." -ForegroundColor Cyan
    
    $results = @()
    
    try {
        # Get all users with sync-related properties
        $selectFields = "id,displayName,userPrincipalName,mail,accountEnabled,onPremisesSyncEnabled,onPremisesProvisioningErrors,onPremisesDomainName,onPremisesLastSyncDateTime"
        
        $allUsers = @()
        $uri = "https://graph.microsoft.com/v1.0/users?`$select=$selectFields&`$top=999"
        
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $allUsers += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        # Filter for users with errors
        foreach ($user in $allUsers) {
            $provErrors = $user.onPremisesProvisioningErrors
            if (-not $provErrors -or $provErrors.Count -eq 0) { continue }
            
            $errorCategories = @()
            $errorDetails = @()
            
            foreach ($syncErr in $provErrors) {
                $category = if ($syncErr.category) { $syncErr.category } else { "Unknown" }
                $errorCategories += $category
                $errorDetails += [PSCustomObject]@{
                    Category = $category
                    Property = $syncErr.propertyCausingError
                    Value = $syncErr.value
                    OccurredDateTime = $syncErr.occurredDateTime
                }
            }
            
            $results += [PSCustomObject]@{
                Id = $user.id
                DisplayName = $user.displayName
                UserPrincipalName = $user.userPrincipalName
                Mail = $user.mail
                AccountEnabled = $user.accountEnabled
                OnPremisesSyncEnabled = $user.onPremisesSyncEnabled
                OnPremisesDomainName = $user.onPremisesDomainName
                OnPremisesLastSyncDateTime = $user.onPremisesLastSyncDateTime
                ErrorCount = $provErrors.Count
                ErrorCategories = ($errorCategories | Select-Object -Unique) -join ", "
                ErrorDetails = $errorDetails
                RiskLevel = "HIGH"
                RiskFactors = "$($provErrors.Count) sync error(s)"
            }
        }
        
        Write-Host "[+] Found $($results.Count) users with directory sync errors" -ForegroundColor $(if ($results.Count -gt 0) { "Yellow" } else { "Green" })
    }
    catch {
        Write-Host "[!] Error checking for sync errors: $_" -ForegroundColor Red
    }
    
    return $results
}

function Show-DirectorySyncStatusReport {
    param([hashtable]$SyncData)
    
    Write-Host ("`n" + ("=" * 115)) -ForegroundColor Cyan
    Write-Host ("{0,58}" -f "DIRECTORY SYNC STATUS REPORT") -ForegroundColor Cyan
    Write-Host ("=" * 115) -ForegroundColor Cyan
    
    $summary = $SyncData.Summary
    
    Write-Host "`nSYNC OVERVIEW:" -ForegroundColor Yellow
    Write-Host "   * Total Users: $($summary.TotalUsers)"
    Write-Host "   * On-Prem Synced: $($summary.SyncedUsers) ($($summary.SyncedPercentage)%)" -ForegroundColor $(if ($summary.SyncedUsers -gt 0) { "Cyan" } else { "Gray" })
    Write-Host "   * Cloud-Only: $($summary.CloudOnlyUsers) ($($summary.CloudOnlyPercentage)%)" -ForegroundColor $(if ($summary.CloudOnlyUsers -gt 0) { "Green" } else { "Gray" })
    Write-Host "   * Users with Sync Errors: $($summary.UsersWithSyncErrors)" -ForegroundColor $(if ($summary.UsersWithSyncErrors -gt 0) { "Red" } else { "Green" })
    
    # Show synced users
    $syncedUsers = $SyncData.SyncedUsers
    if ($syncedUsers.Count -gt 0) {
        Write-Host ("`n" + ("-" * 115)) -ForegroundColor Gray
        Write-Host ("{0,58}" -f "ON-PREMISES SYNCED USERS") -ForegroundColor Cyan
        Write-Host ("-" * 115) -ForegroundColor Gray
        Write-Host ("`n{0,-23} {1,-33} {2,-19} {3,-15} {4,-13} {5,-6}" -f "Display Name", "Email/UPN", "Domain", "SAM Account", "Last Sync", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 115) -ForegroundColor Gray
        
        foreach ($user in ($syncedUsers | Select-Object -First 50)) {
            $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(22, $user.DisplayName.Length)) } else { "N/A" }
            $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(32, $user.UserPrincipalName.Length)) } elseif ($user.Mail) { $user.Mail.Substring(0, [Math]::Min(32, $user.Mail.Length)) } else { "N/A" }
            $domain = if ($user.OnPremisesDomainName) { $user.OnPremisesDomainName.Substring(0, [Math]::Min(18, $user.OnPremisesDomainName.Length)) } else { "N/A" }
            $sam = if ($user.OnPremisesSamAccountName) { $user.OnPremisesSamAccountName.Substring(0, [Math]::Min(14, $user.OnPremisesSamAccountName.Length)) } else { "N/A" }
            $lastSync = if ($user.OnPremisesLastSyncDateTime) { "$($user.OnPremisesLastSyncDateTime)".Substring(0, [Math]::Min(12, "$($user.OnPremisesLastSyncDateTime)".Length)) } else { "Never" }
            $risk = $user.RiskLevel
            
            $color = if ($risk -eq "HIGH") { "Red" } elseif ($risk -eq "MEDIUM") { "Yellow" } else { "White" }
            Write-Host ("{0,-23} {1,-33} {2,-19} {3,-15} {4,-13} {5,-6}" -f $name, $email, $domain, $sam, $lastSync, $risk) -ForegroundColor $color
        }
        
        if ($syncedUsers.Count -gt 50) {
            Write-Host "    ... and $($syncedUsers.Count - 50) more synced users" -ForegroundColor Gray
        }
        Write-Host ("-" * 115) -ForegroundColor Gray
    }
    
    # Show cloud-only users
    $cloudUsers = $SyncData.CloudOnlyUsers
    if ($cloudUsers.Count -gt 0) {
        Write-Host ("`n" + ("-" * 115)) -ForegroundColor Gray
        Write-Host ("{0,58}" -f "CLOUD-ONLY USERS") -ForegroundColor Green
        Write-Host ("-" * 115) -ForegroundColor Gray
        Write-Host ("`n{0,-24} {1,-39} {2,-11} {3,-9} {4,-6}" -f "Display Name", "Email/UPN", "Type", "Enabled", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 100) -ForegroundColor Gray
        
        foreach ($user in ($cloudUsers | Select-Object -First 30)) {
            $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(23, $user.DisplayName.Length)) } else { "N/A" }
            $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(38, $user.UserPrincipalName.Length)) } elseif ($user.Mail) { $user.Mail.Substring(0, [Math]::Min(38, $user.Mail.Length)) } else { "N/A" }
            $userType = if ($user.UserType) { $user.UserType.Substring(0, [Math]::Min(10, $user.UserType.Length)) } else { "Member" }
            $enabled = if ($user.AccountEnabled) { "Yes" } else { "No" }
            $risk = $user.RiskLevel
            
            Write-Host ("{0,-24} {1,-39} {2,-11} {3,-9} {4,-6}" -f $name, $email, $userType, $enabled, $risk)
        }
        
        if ($cloudUsers.Count -gt 30) {
            Write-Host "    ... and $($cloudUsers.Count - 30) more cloud-only users" -ForegroundColor Gray
        }
        Write-Host ("-" * 100) -ForegroundColor Gray
    }
    
    # Show sync errors if any
    $syncErrors = $SyncData.SyncErrors
    if ($syncErrors.Count -gt 0) {
        Write-Host "`n!!! $($syncErrors.Count) USERS WITH DIRECTORY SYNC ERRORS:" -ForegroundColor Red
        foreach ($user in ($syncErrors | Select-Object -First 10)) {
            Write-Host "   * $($user.DisplayName) ($($user.UserPrincipalName))" -ForegroundColor Yellow
            foreach ($syncErr in ($user.ProvisioningErrors | Select-Object -First 2)) {
                $category = if ($syncErr.category) { $syncErr.category } else { "Unknown" }
                $prop = if ($syncErr.propertyCausingError) { $syncErr.propertyCausingError } else { "Unknown" }
                Write-Host "     - ${category}: $prop" -ForegroundColor Gray
            }
        }
    }
    
    # Security recommendations
    Write-Host "`nSecurity Considerations:" -ForegroundColor Yellow
    if ($summary.SyncedUsers -gt 0) {
        Write-Host "   * Synced accounts rely on on-premises AD security" -ForegroundColor Gray
        Write-Host "   * Ensure AD Connect is properly secured and monitored" -ForegroundColor Gray
        Write-Host "   * Review sync scope to ensure only necessary users are synced" -ForegroundColor Gray
    }
    if ($summary.CloudOnlyUsers -gt 0) {
        Write-Host "   * Cloud-only accounts should have strong MFA enforcement" -ForegroundColor Gray
        Write-Host "   * Consider Conditional Access policies for cloud-only identities" -ForegroundColor Gray
    }
    if ($summary.UsersWithSyncErrors -gt 0) {
        Write-Host "   !!! Resolve sync errors to prevent authentication issues" -ForegroundColor Red
    }
}

function Show-DirectorySyncErrorsReport {
    param([array]$Users)
    
    Write-Host ("`n" + ("=" * 115)) -ForegroundColor Cyan
    Write-Host ("{0,58}" -f "DIRECTORY SYNC ERRORS (HIGH RISK)") -ForegroundColor Red
    Write-Host ("=" * 115) -ForegroundColor Cyan
    
    if ($Users.Count -eq 0) {
        Write-Host "`n[OK] No directory sync errors found." -ForegroundColor Green
        return
    }
    
    Write-Host "`n!!! Found $($Users.Count) users with directory sync errors" -ForegroundColor Red
    
    # Group by error category
    $errorCategories = @{}
    foreach ($user in $Users) {
        foreach ($detail in $user.ErrorDetails) {
            $category = if ($detail.Category) { $detail.Category } else { "Unknown" }
            if (-not $errorCategories.ContainsKey($category)) {
                $errorCategories[$category] = 0
            }
            $errorCategories[$category]++
        }
    }
    
    Write-Host "`nError Categories:" -ForegroundColor Yellow
    foreach ($category in ($errorCategories.GetEnumerator() | Sort-Object Value -Descending)) {
        Write-Host "   * $($category.Key): $($category.Value)" -ForegroundColor Gray
    }
    
    Write-Host ("`n{0,-21} {1,-31} {2,-17} {3,-24} {4,-5} {5,-6}" -f "Display Name", "Email/UPN", "Domain", "Error Categories", "Errs", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 115) -ForegroundColor Gray
    
    foreach ($user in ($Users | Select-Object -First 50)) {
        $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(20, $user.DisplayName.Length)) } else { "N/A" }
        $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(30, $user.UserPrincipalName.Length)) } else { "N/A" }
        $domain = if ($user.OnPremisesDomainName) { $user.OnPremisesDomainName.Substring(0, [Math]::Min(16, $user.OnPremisesDomainName.Length)) } else { "N/A" }
        $categories = if ($user.ErrorCategories) { $user.ErrorCategories.Substring(0, [Math]::Min(23, $user.ErrorCategories.Length)) } else { "Unknown" }
        $errorCount = $user.ErrorCount
        $risk = $user.RiskLevel
        
        Write-Host ("{0,-21} {1,-31} {2,-17} {3,-24} {4,-5} {5,-6}" -f $name, $email, $domain, $categories, $errorCount, $risk) -ForegroundColor Red
    }
    
    if ($Users.Count -gt 50) {
        Write-Host "    ... and $($Users.Count - 50) more users with errors" -ForegroundColor Gray
    }
    
    Write-Host ("-" * 115) -ForegroundColor Gray
    
    # Show detailed errors for first few users
    Write-Host "`nDetailed Error Information:" -ForegroundColor Yellow
    foreach ($user in ($Users | Select-Object -First 5)) {
        Write-Host "`n   $($user.DisplayName) ($($user.UserPrincipalName))" -ForegroundColor Cyan
        foreach ($detail in ($user.ErrorDetails | Select-Object -First 3)) {
            Write-Host "      Category: $($detail.Category)" -ForegroundColor Gray
            Write-Host "      Property: $($detail.Property)" -ForegroundColor Gray
            if ($detail.Value) {
                $val = "$($detail.Value)".Substring(0, [Math]::Min(50, "$($detail.Value)".Length))
                Write-Host "      Value: $val" -ForegroundColor Gray
            }
            if ($detail.OccurredDateTime) {
                $dt = "$($detail.OccurredDateTime)".Substring(0, [Math]::Min(19, "$($detail.OccurredDateTime)".Length))
                Write-Host "      Occurred: $dt" -ForegroundColor Gray
            }
        }
    }
    
    # Recommendations
    Write-Host "`nRemediation Steps:" -ForegroundColor Yellow
    Write-Host "   1. Review error details in Azure AD Connect Health" -ForegroundColor Gray
    Write-Host "   2. Check on-premises AD attributes for conflicts" -ForegroundColor Gray
    Write-Host "   3. Verify UPN/ProxyAddress uniqueness across forest" -ForegroundColor Gray
    Write-Host "   4. Run AD Connect sync with verbose logging" -ForegroundColor Gray
    Write-Host "   5. Consider using IdFix tool to identify and fix issues" -ForegroundColor Gray
}

# ============================================================================
# ATTACK PATH ANALYSIS FUNCTIONS
# ============================================================================

function Get-GroupOwners {
    <#
    .SYNOPSIS
        Enumerate owners of all groups, focusing on privileged groups.
    #>
    Write-Host "`n[*] Enumerating group owners..." -ForegroundColor Cyan
    
    # List of privileged groups to focus on
    $privilegedGroupNames = @(
        "Global Administrators",
        "Privileged Role Administrators",
        "Security Administrators",
        "User Account Administrators",
        "Exchange Administrators",
        "SharePoint Administrators",
        "Teams Administrators",
        "Intune Administrators",
        "Application Administrators",
        "Cloud Application Administrators",
        "Conditional Access Administrators",
        "Password Administrators",
        "Authentication Administrators",
        "Helpdesk Administrators",
        "Groups Administrators",
        "Directory Writers",
        "Privileged Authentication Administrators"
    )
    
    $results = @{
        PrivilegedGroupOwners = @()
        AllGroupOwners = @()
        GroupsWithOwners = 0
        TotalGroups = 0
    }
    
    try {
        # Get all groups
        $groups = @()
        $uri = "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,description,groupTypes,securityEnabled,mailEnabled,isAssignableToRole&`$top=999"
        
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $groups += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        $results.TotalGroups = $groups.Count
        Write-Host "[+] Found $($groups.Count) groups" -ForegroundColor Green
        
        # Get owners for each group
        $groupCount = 0
        foreach ($group in $groups) {
            $groupCount++
            if ($groupCount % 50 -eq 0) {
                Write-Host "    Processing group $groupCount of $($groups.Count)..." -ForegroundColor Gray
            }
            
            try {
                $ownersUri = "https://graph.microsoft.com/v1.0/groups/$($group.id)/owners?`$select=id,displayName,userPrincipalName,mail"
                $ownersResponse = Invoke-MgGraphRequest -Method GET -Uri $ownersUri -ErrorAction SilentlyContinue
                
                if ($ownersResponse.value.Count -gt 0) {
                    $results.GroupsWithOwners++
                    
                    foreach ($owner in $ownersResponse.value) {
                        $isPrivilegedGroup = $privilegedGroupNames -contains $group.displayName -or 
                                            $group.isAssignableToRole -eq $true -or
                                            ($group.displayName -match "admin|privilege|security|global|exchange|sharepoint|teams|intune|password|helpdesk")
                        
                        $ownerInfo = [PSCustomObject]@{
                            GroupId = $group.id
                            GroupName = $group.displayName
                            GroupDescription = $group.description
                            IsRoleAssignable = $group.isAssignableToRole
                            IsSecurityGroup = $group.securityEnabled
                            OwnerId = $owner.id
                            OwnerDisplayName = $owner.displayName
                            OwnerUPN = $owner.userPrincipalName
                            OwnerMail = $owner.mail
                            IsPrivilegedGroup = $isPrivilegedGroup
                            RiskLevel = if ($isPrivilegedGroup) { "HIGH" } else { "LOW" }
                        }
                        
                        $results.AllGroupOwners += $ownerInfo
                        
                        if ($isPrivilegedGroup) {
                            $results.PrivilegedGroupOwners += $ownerInfo
                        }
                    }
                }
            }
            catch { }
        }
        
        Write-Host "[+] Found $($results.GroupsWithOwners) groups with owners" -ForegroundColor Green
        Write-Host "[+] Found $($results.PrivilegedGroupOwners.Count) owners of privileged groups" -ForegroundColor $(if ($results.PrivilegedGroupOwners.Count -gt 0) { "Yellow" } else { "Green" })
    }
    catch {
        Write-Host "[!] Error enumerating group owners: $_" -ForegroundColor Red
    }
    
    return $results
}

function Get-PasswordResetDelegations {
    <#
    .SYNOPSIS
        Identify users with password reset permissions (privileged escalation path).
    #>
    Write-Host "`n[*] Identifying password reset delegations..." -ForegroundColor Cyan
    
    # Roles that can reset passwords
    $passwordResetRoles = @{
        "Privileged Authentication Administrator" = "CRITICAL"  # Can reset any user including Global Admins
        "Authentication Administrator" = "HIGH"                 # Can reset non-admin users
        "Password Administrator" = "HIGH"                       # Can reset non-admin users
        "Helpdesk Administrator" = "MEDIUM"                     # Can reset some users
        "User Administrator" = "HIGH"                           # Can reset non-admin users
        "Global Administrator" = "CRITICAL"                     # Can do everything
    }
    
    $results = @{
        PasswordResetUsers = @()
        RoleCounts = @{}
    }
    
    try {
        # Get directory roles with members
        $roles = Get-MgDirectoryRole -ExpandProperty Members -ErrorAction Stop
        
        foreach ($role in $roles) {
            if ($passwordResetRoles.ContainsKey($role.DisplayName)) {
                $riskLevel = $passwordResetRoles[$role.DisplayName]
                
                foreach ($member in $role.Members) {
                    if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                        $results.PasswordResetUsers += [PSCustomObject]@{
                            UserId = $member.Id
                            DisplayName = $member.AdditionalProperties.displayName
                            UserPrincipalName = $member.AdditionalProperties.userPrincipalName
                            Mail = $member.AdditionalProperties.mail
                            Role = $role.DisplayName
                            RoleId = $role.Id
                            RiskLevel = $riskLevel
                            CanResetGlobalAdmins = ($role.DisplayName -in @("Privileged Authentication Administrator", "Global Administrator"))
                            AssignmentType = "Active"
                        }
                        
                        if (-not $results.RoleCounts.ContainsKey($role.DisplayName)) {
                            $results.RoleCounts[$role.DisplayName] = 0
                        }
                        $results.RoleCounts[$role.DisplayName]++
                    }
                }
            }
        }
        
        # Also check PIM eligible for password reset roles
        Write-Host "[*] Checking PIM eligible password reset delegations..." -ForegroundColor Cyan
        
        try {
            $pimUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?`$expand=principal"
            $pimResult = Invoke-MgGraphRequest -Method GET -Uri $pimUri -ErrorAction SilentlyContinue
            
            foreach ($schedule in $pimResult.value) {
                $principal = $schedule.principal
                
                if ($principal.'@odata.type' -eq '#microsoft.graph.user') {
                    $roleId = $schedule.roleDefinitionId
                    
                    # Get role name
                    try {
                        $roleUri = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$roleId'"
                        $roleResult = Invoke-MgGraphRequest -Method GET -Uri $roleUri -ErrorAction SilentlyContinue
                        $roleName = if ($roleResult.value.Count -gt 0) { $roleResult.value[0].displayName } else { "Unknown Role" }
                    }
                    catch { $roleName = "Unknown Role" }
                    
                    if ($passwordResetRoles.ContainsKey($roleName)) {
                        $results.PasswordResetUsers += [PSCustomObject]@{
                            UserId = $principal.id
                            DisplayName = $principal.displayName
                            UserPrincipalName = $principal.userPrincipalName
                            Mail = $principal.mail
                            Role = $roleName
                            RoleId = $roleId
                            RiskLevel = $passwordResetRoles[$roleName]
                            CanResetGlobalAdmins = ($roleName -in @("Privileged Authentication Administrator", "Global Administrator"))
                            AssignmentType = "PIM Eligible"
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "[!] PIM eligibility check failed: Access denied or not available" -ForegroundColor Yellow
        }
        
        $criticalCount = ($results.PasswordResetUsers | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highCount = ($results.PasswordResetUsers | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        
        Write-Host "[+] Found $($results.PasswordResetUsers.Count) users with password reset permissions" -ForegroundColor Green
        Write-Host "    - CRITICAL (can reset Global Admins): $criticalCount" -ForegroundColor $(if ($criticalCount -gt 0) { "Red" } else { "Green" })
        Write-Host "    - HIGH: $highCount" -ForegroundColor $(if ($highCount -gt 0) { "Yellow" } else { "Green" })
    }
    catch {
        Write-Host "[!] Error identifying password reset delegations: $_" -ForegroundColor Red
    }
    
    return $results
}

function Get-UsersWithGroupMembershipPrivileges {
    <#
    .SYNOPSIS
        Find users who can add members to privileged groups (privilege escalation path).
    #>
    Write-Host "`n[*] Analyzing group membership modification privileges..." -ForegroundColor Cyan
    
    $results = @{
        PrivilegedGroupManagers = @()
        AppsWithGroupWriteAll = @()
        RoleBasedGroupManagers = @()
    }
    
    # Roles that can modify group membership
    $groupManagementRoles = @{
        "Global Administrator" = "CRITICAL"
        "Privileged Role Administrator" = "CRITICAL"
        "Groups Administrator" = "HIGH"
        "User Administrator" = "HIGH"
        "Directory Writers" = "MEDIUM"
        "Intune Administrator" = "MEDIUM"
    }
    
    try {
        # 1. Check users with roles that allow group management
        Write-Host "[*] Checking role-based group management permissions..." -ForegroundColor Gray
        
        $roles = Get-MgDirectoryRole -ExpandProperty Members -ErrorAction Stop
        
        foreach ($role in $roles) {
            if ($groupManagementRoles.ContainsKey($role.DisplayName)) {
                $riskLevel = $groupManagementRoles[$role.DisplayName]
                
                foreach ($member in $role.Members) {
                    if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                        $results.RoleBasedGroupManagers += [PSCustomObject]@{
                            UserId = $member.Id
                            DisplayName = $member.AdditionalProperties.displayName
                            UserPrincipalName = $member.AdditionalProperties.userPrincipalName
                            Role = $role.DisplayName
                            RiskLevel = $riskLevel
                            PrivilegeType = "Role Assignment"
                            CanManageAllGroups = ($role.DisplayName -in @("Global Administrator", "Groups Administrator"))
                        }
                    }
                }
            }
        }
        
        Write-Host "[+] Found $($results.RoleBasedGroupManagers.Count) users with group management roles" -ForegroundColor Green
        
        # 2. Check applications with Group.ReadWrite.All or GroupMember.ReadWrite.All
        Write-Host "[*] Checking applications with group write permissions..." -ForegroundColor Gray
        
        $dangerousPermissions = @(
            "Group.ReadWrite.All",
            "GroupMember.ReadWrite.All",
            "Directory.ReadWrite.All"
        )
        
        # Get Graph service principal to resolve permission IDs
        $msGraphAppId = "00000003-0000-0000-c000-000000000000"
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '$msGraphAppId'" -Property Id,AppRoles -ErrorAction SilentlyContinue
        
        if ($graphSp) {
            $permissionIdMap = @{}
            foreach ($appRole in $graphSp.AppRoles) {
                if ($dangerousPermissions -contains $appRole.Value) {
                    $permissionIdMap[$appRole.Id] = $appRole.Value
                }
            }
            
            # Get all app role assignments to Graph API
            $sps = Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,AppRoleAssignments -ErrorAction SilentlyContinue
            
            foreach ($sp in $sps) {
                try {
                    $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
                    
                    $hasGroupWritePermission = $false
                    $grantedPermissions = @()
                    
                    foreach ($assignment in $assignments) {
                        if ($assignment.ResourceId -eq $graphSp.Id) {
                            if ($permissionIdMap.ContainsKey($assignment.AppRoleId)) {
                                $hasGroupWritePermission = $true
                                $grantedPermissions += $permissionIdMap[$assignment.AppRoleId]
                            }
                        }
                    }
                    
                    if ($hasGroupWritePermission) {
                        # Get owners of this app
                        $ownersList = @()
                        try {
                            $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
                            foreach ($owner in $owners) {
                                $ownersList += $owner.AdditionalProperties.userPrincipalName
                            }
                        }
                        catch { }
                        
                        $results.AppsWithGroupWriteAll += [PSCustomObject]@{
                            AppId = $sp.AppId
                            AppDisplayName = $sp.DisplayName
                            ServicePrincipalId = $sp.Id
                            GrantedPermissions = $grantedPermissions -join ", "
                            Owners = $ownersList -join ", "
                            RiskLevel = "HIGH"
                            PrivilegeType = "Application Permission"
                        }
                    }
                }
                catch { }
            }
        }
        
        Write-Host "[+] Found $($results.AppsWithGroupWriteAll.Count) apps with group write permissions" -ForegroundColor $(if ($results.AppsWithGroupWriteAll.Count -gt 0) { "Yellow" } else { "Green" })
        
        # 3. Get privileged group owners (from Get-GroupOwners function)
        Write-Host "[*] Getting privileged group owners..." -ForegroundColor Gray
        
        $groupOwnerResults = Get-GroupOwners
        $results.PrivilegedGroupManagers = $groupOwnerResults.PrivilegedGroupOwners
        
    }
    catch {
        Write-Host "[!] Error analyzing group membership privileges: $_" -ForegroundColor Red
    }
    
    return $results
}

function Get-AttackPathAnalysis {
    <#
    .SYNOPSIS
        Comprehensive attack path analysis for privilege escalation.
    #>
    Write-Host ("`n" + ("=" * 80)) -ForegroundColor Cyan
    Write-Host ("{0,45}" -f "ATTACK PATH ANALYSIS") -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "`nAnalyzing potential privilege escalation paths..." -ForegroundColor Yellow
    
    $results = @{
        GroupMembershipPrivileges = @{}
        PasswordResetDelegations = @{}
        GroupOwners = @{}
        PrivilegedRoleAssignments = @()
        AttackPaths = @()
    }
    
    # 1. Get users with group membership privileges
    $results.GroupMembershipPrivileges = Get-UsersWithGroupMembershipPrivileges
    
    # 2. Get password reset delegations
    $results.PasswordResetDelegations = Get-PasswordResetDelegations
    
    # 3. Get group owners
    $results.GroupOwners = Get-GroupOwners
    
    # 4. Get privileged role assignments (reuse existing function)
    Write-Host "`n[*] Getting privileged role assignments..." -ForegroundColor Cyan
    $results.PrivilegedRoleAssignments = Get-PrivilegedUsers
    
    # 5. Identify attack paths
    Write-Host "`n[*] Identifying attack paths..." -ForegroundColor Cyan
    
    # Attack Path 1: Group owners who can add members to privileged groups
    foreach ($owner in $results.GroupOwners.PrivilegedGroupOwners) {
        $results.AttackPaths += [PSCustomObject]@{
            PathType = "Group Ownership"
            SourceUser = $owner.OwnerUPN
            SourceUserId = $owner.OwnerId
            TargetResource = $owner.GroupName
            TargetResourceId = $owner.GroupId
            RiskLevel = "HIGH"
            Description = "User owns a privileged group and can add members"
            Remediation = "Review group ownership; consider role-assignable groups with PIM"
        }
    }
    
    # Attack Path 2: Users with password reset on privileged accounts
    $criticalResetUsers = $results.PasswordResetDelegations.PasswordResetUsers | Where-Object { $_.CanResetGlobalAdmins }
    foreach ($user in $criticalResetUsers) {
        $results.AttackPaths += [PSCustomObject]@{
            PathType = "Password Reset"
            SourceUser = $user.UserPrincipalName
            SourceUserId = $user.UserId
            TargetResource = "Global Administrators"
            TargetResourceId = $user.RoleId
            RiskLevel = "CRITICAL"
            Description = "User can reset passwords of Global Administrators via $($user.Role)"
            Remediation = "Limit Privileged Auth Admin role; use PIM with approval"
        }
    }
    
    # Attack Path 3: Apps with Group.ReadWrite.All
    foreach ($app in $results.GroupMembershipPrivileges.AppsWithGroupWriteAll) {
        $results.AttackPaths += [PSCustomObject]@{
            PathType = "Application Permission"
            SourceUser = if ($app.Owners) { $app.Owners } else { "No Owner" }
            SourceUserId = $app.ServicePrincipalId
            TargetResource = $app.AppDisplayName
            TargetResourceId = $app.AppId
            RiskLevel = "HIGH"
            Description = "Application has $($app.GrantedPermissions) - can modify any group membership"
            Remediation = "Review application permissions; use least privilege"
        }
    }
    
    # Count attack paths by type
    $pathCounts = $results.AttackPaths | Group-Object PathType
    
    Write-Host "`n[+] Attack Path Analysis Complete" -ForegroundColor Green
    Write-Host "    Total potential attack paths: $($results.AttackPaths.Count)" -ForegroundColor $(if ($results.AttackPaths.Count -gt 0) { "Yellow" } else { "Green" })
    foreach ($type in $pathCounts) {
        Write-Host "    - $($type.Name): $($type.Count)" -ForegroundColor Gray
    }
    
    return $results
}

function Show-AttackPathReport {
    param([hashtable]$Results)
    
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Cyan
    Write-Host ("{0,65}" -f "ATTACK PATH ANALYSIS REPORT") -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Cyan
    
    # Summary
    $totalPaths = $Results.AttackPaths.Count
    $criticalPaths = ($Results.AttackPaths | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highPaths = ($Results.AttackPaths | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    
    Write-Host "`nEXECUTIVE SUMMARY:" -ForegroundColor Yellow
    Write-Host "   Total Attack Paths Identified: $totalPaths" -ForegroundColor $(if ($totalPaths -gt 0) { "Yellow" } else { "Green" })
    Write-Host "   CRITICAL Risk Paths: $criticalPaths" -ForegroundColor $(if ($criticalPaths -gt 0) { "Red" } else { "Green" })
    Write-Host "   HIGH Risk Paths: $highPaths" -ForegroundColor $(if ($highPaths -gt 0) { "Yellow" } else { "Green" })
    
    # Password Reset Delegations
    if ($Results.PasswordResetDelegations.PasswordResetUsers.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host ("{0,65}" -f "PASSWORD RESET DELEGATIONS") -ForegroundColor Red
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        Write-Host "`n!!! Users who can reset passwords are high-value targets for privilege escalation" -ForegroundColor Yellow
        
        Write-Host ("`n{0,-22} {1,-33} {2,-33} {3,-10} {4,-11} {5,-8}" -f "Display Name", "Email/UPN", "Role", "Type", "Reset GA?", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        $sortedUsers = $Results.PasswordResetDelegations.PasswordResetUsers | Sort-Object { @{"CRITICAL"=0;"HIGH"=1;"MEDIUM"=2;"LOW"=3}[$_.RiskLevel] }
        
        foreach ($user in ($sortedUsers | Select-Object -First 30)) {
            $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(21, $user.DisplayName.Length)) } else { "N/A" }
            $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(32, $user.UserPrincipalName.Length)) } else { "N/A" }
            $role = if ($user.Role) { $user.Role.Substring(0, [Math]::Min(32, $user.Role.Length)) } else { "N/A" }
            $assignType = if ($user.AssignmentType) { $user.AssignmentType.Substring(0, [Math]::Min(9, $user.AssignmentType.Length)) } else { "Active" }
            $resetGA = if ($user.CanResetGlobalAdmins) { "YES" } else { "No" }
            
            $color = if ($user.RiskLevel -eq "CRITICAL") { "Red" } elseif ($user.RiskLevel -eq "HIGH") { "Yellow" } else { "White" }
            Write-Host ("{0,-22} {1,-33} {2,-33} {3,-10} {4,-11} {5,-8}" -f $name, $email, $role, $assignType, $resetGA, $user.RiskLevel) -ForegroundColor $color
        }
        
        if ($Results.PasswordResetDelegations.PasswordResetUsers.Count -gt 30) {
            Write-Host "    ... and $($Results.PasswordResetDelegations.PasswordResetUsers.Count - 30) more users" -ForegroundColor Gray
        }
        Write-Host ("-" * 120) -ForegroundColor Gray
    }
    
    # Privileged Group Owners
    if ($Results.GroupOwners.PrivilegedGroupOwners.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host ("{0,65}" -f "PRIVILEGED GROUP OWNERS") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        Write-Host "`n!!! These users can add members to privileged groups - potential privilege escalation" -ForegroundColor Yellow
        
        Write-Host ("`n{0,-23} {1,-35} {2,-35} {3,-10} {4,-8}" -f "Owner Name", "Owner UPN", "Group Name", "Role Grp?", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        foreach ($owner in ($Results.GroupOwners.PrivilegedGroupOwners | Select-Object -First 30)) {
            $name = if ($owner.OwnerDisplayName) { $owner.OwnerDisplayName.Substring(0, [Math]::Min(22, $owner.OwnerDisplayName.Length)) } else { "N/A" }
            $upn = if ($owner.OwnerUPN) { $owner.OwnerUPN.Substring(0, [Math]::Min(34, $owner.OwnerUPN.Length)) } else { "N/A" }
            $groupName = if ($owner.GroupName) { $owner.GroupName.Substring(0, [Math]::Min(34, $owner.GroupName.Length)) } else { "N/A" }
            $roleAssignable = if ($owner.IsRoleAssignable) { "Yes" } else { "No" }
            
            Write-Host ("{0,-23} {1,-35} {2,-35} {3,-10} {4,-8}" -f $name, $upn, $groupName, $roleAssignable, $owner.RiskLevel) -ForegroundColor $(if ($owner.IsRoleAssignable) { "Red" } else { "Yellow" })
        }
        
        if ($Results.GroupOwners.PrivilegedGroupOwners.Count -gt 30) {
            Write-Host "    ... and $($Results.GroupOwners.PrivilegedGroupOwners.Count - 30) more owners" -ForegroundColor Gray
        }
        Write-Host ("-" * 120) -ForegroundColor Gray
    }
    
    # Applications with Group Write Permissions
    if ($Results.GroupMembershipPrivileges.AppsWithGroupWriteAll.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host ("{0,65}" -f "APPLICATIONS WITH GROUP WRITE PERMISSIONS") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        Write-Host "`n!!! These applications can modify any group membership in the tenant" -ForegroundColor Yellow
        
        Write-Host ("`n{0,-30} {1,-38} {2,-28} {3,-18}" -f "App Name", "App ID", "Permissions", "Owners") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        foreach ($app in $Results.GroupMembershipPrivileges.AppsWithGroupWriteAll) {
            $name = if ($app.AppDisplayName) { $app.AppDisplayName.Substring(0, [Math]::Min(29, $app.AppDisplayName.Length)) } else { "N/A" }
            $appId = if ($app.AppId) { $app.AppId.Substring(0, [Math]::Min(37, $app.AppId.Length)) } else { "N/A" }
            $perms = if ($app.GrantedPermissions) { $app.GrantedPermissions.Substring(0, [Math]::Min(27, $app.GrantedPermissions.Length)) } else { "N/A" }
            $owners = if ($app.Owners) { $app.Owners.Substring(0, [Math]::Min(17, $app.Owners.Length)) } else { "None" }
            
            Write-Host ("{0,-30} {1,-38} {2,-28} {3,-18}" -f $name, $appId, $perms, $owners) -ForegroundColor Yellow
        }
        Write-Host ("-" * 120) -ForegroundColor Gray
    }
    
    # Role-Based Group Managers
    if ($Results.GroupMembershipPrivileges.RoleBasedGroupManagers.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host ("{0,65}" -f "USERS WITH GROUP MANAGEMENT ROLES") -ForegroundColor Cyan
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        Write-Host ("`n{0,-24} {1,-38} {2,-28} {3,-12} {4,-8}" -f "Display Name", "Email/UPN", "Role", "All Groups?", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 115) -ForegroundColor Gray
        
        foreach ($user in ($Results.GroupMembershipPrivileges.RoleBasedGroupManagers | Select-Object -First 25)) {
            $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(23, $user.DisplayName.Length)) } else { "N/A" }
            $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(37, $user.UserPrincipalName.Length)) } else { "N/A" }
            $role = if ($user.Role) { $user.Role.Substring(0, [Math]::Min(27, $user.Role.Length)) } else { "N/A" }
            $allGroups = if ($user.CanManageAllGroups) { "Yes" } else { "No" }
            
            $color = if ($user.RiskLevel -eq "CRITICAL") { "Red" } elseif ($user.RiskLevel -eq "HIGH") { "Yellow" } else { "White" }
            Write-Host ("{0,-24} {1,-38} {2,-28} {3,-12} {4,-8}" -f $name, $email, $role, $allGroups, $user.RiskLevel) -ForegroundColor $color
        }
        
        if ($Results.GroupMembershipPrivileges.RoleBasedGroupManagers.Count -gt 25) {
            Write-Host "    ... and $($Results.GroupMembershipPrivileges.RoleBasedGroupManagers.Count - 25) more users" -ForegroundColor Gray
        }
        Write-Host ("-" * 115) -ForegroundColor Gray
    }
    
    # Attack Paths Summary
    if ($Results.AttackPaths.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host ("{0,65}" -f "IDENTIFIED ATTACK PATHS") -ForegroundColor Red
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        Write-Host ("`n{0,-20} {1,-28} {2,-28} {3,-8} {4,-30}" -f "Path Type", "Source", "Target", "Risk", "Description") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        $sortedPaths = $Results.AttackPaths | Sort-Object { @{"CRITICAL"=0;"HIGH"=1;"MEDIUM"=2;"LOW"=3}[$_.RiskLevel] }
        
        foreach ($path in ($sortedPaths | Select-Object -First 25)) {
            $pathType = if ($path.PathType) { $path.PathType.Substring(0, [Math]::Min(19, $path.PathType.Length)) } else { "N/A" }
            $source = if ($path.SourceUser) { $path.SourceUser.Substring(0, [Math]::Min(27, $path.SourceUser.Length)) } else { "N/A" }
            $target = if ($path.TargetResource) { $path.TargetResource.Substring(0, [Math]::Min(27, $path.TargetResource.Length)) } else { "N/A" }
            $desc = if ($path.Description) { $path.Description.Substring(0, [Math]::Min(29, $path.Description.Length)) } else { "N/A" }
            
            $color = if ($path.RiskLevel -eq "CRITICAL") { "Red" } elseif ($path.RiskLevel -eq "HIGH") { "Yellow" } else { "White" }
            Write-Host ("{0,-20} {1,-28} {2,-28} {3,-8} {4,-30}" -f $pathType, $source, $target, $path.RiskLevel, $desc) -ForegroundColor $color
        }
        
        if ($Results.AttackPaths.Count -gt 25) {
            Write-Host "    ... and $($Results.AttackPaths.Count - 25) more attack paths" -ForegroundColor Gray
        }
        Write-Host ("-" * 120) -ForegroundColor Gray
    }
    
    # Recommendations
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Gray
    Write-Host "REMEDIATION RECOMMENDATIONS:" -ForegroundColor Yellow
    Write-Host "=" * 120 -ForegroundColor Gray
    
    Write-Host "`n1. Password Reset Delegations:" -ForegroundColor Cyan
    Write-Host "   - Limit users with Privileged Authentication Administrator role" -ForegroundColor Gray
    Write-Host "   - Use PIM with approval workflows for password reset roles" -ForegroundColor Gray
    Write-Host "   - Implement just-in-time access for authentication administrators" -ForegroundColor Gray
    
    Write-Host "`n2. Group Ownership:" -ForegroundColor Cyan
    Write-Host "   - Review and minimize privileged group owners" -ForegroundColor Gray
    Write-Host "   - Use role-assignable groups with PIM for privileged groups" -ForegroundColor Gray
    Write-Host "   - Implement access reviews for group owners" -ForegroundColor Gray
    
    Write-Host "`n3. Application Permissions:" -ForegroundColor Cyan
    Write-Host "   - Remove unnecessary Group.ReadWrite.All permissions" -ForegroundColor Gray
    Write-Host "   - Use more specific permissions where possible" -ForegroundColor Gray
    Write-Host "   - Ensure all high-privilege apps have assigned owners" -ForegroundColor Gray
    
    Write-Host "`n4. General:" -ForegroundColor Cyan
    Write-Host "   - Enable and monitor Conditional Access for privileged operations" -ForegroundColor Gray
    Write-Host "   - Configure Azure AD audit logs and alerts for privilege changes" -ForegroundColor Gray
    Write-Host "   - Regularly review privileged access using access reviews" -ForegroundColor Gray
}

# ============================================================================
# LATERAL MOVEMENT ANALYSIS FUNCTIONS
# ============================================================================

function Get-TransitiveGroupMemberships {
    <#
    .SYNOPSIS
        Map group nesting and transitive memberships.
        Identifies indirect group memberships that could be exploited for lateral movement.
    #>
    Write-Host "`n[*] Mapping transitive group memberships..." -ForegroundColor Cyan
    
    $results = @{
        UsersWithNestedAccess = @()
        PrivilegedGroupChains = @()
        DeeplyNestedGroups = @()
        TotalDirectMemberships = 0
        TotalTransitiveMemberships = 0
        MaxNestingDepth = 0
    }
    
    try {
        # Get privileged groups first
        $privilegedGroupNames = @(
            "Global Administrator", "Privileged Role Administrator",
            "User Administrator", "Exchange Administrator",
            "Security Administrator", "Helpdesk Administrator",
            "Password Administrator", "Authentication Administrator",
            "Privileged Authentication Administrator", "Cloud Application Administrator",
            "Application Administrator", "Intune Administrator",
            "Azure AD Joined Device Local Administrator", "Groups Administrator"
        )
        
        # Get all groups
        Write-Host "    Fetching all groups..." -ForegroundColor Gray
        $allGroups = @()
        try {
            $allGroups = Get-MgGroup -All -Property Id,DisplayName,SecurityEnabled,GroupTypes,IsAssignableToRole -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Error fetching groups: $_" -ForegroundColor Yellow
            return $results
        }
        
        Write-Host "    Found $($allGroups.Count) total groups" -ForegroundColor Gray
        
        # Identify privileged groups (role-assignable or matching names)
        $privilegedGroups = @()
        foreach ($group in $allGroups) {
            $isPrivileged = $group.IsAssignableToRole -or
                ($privilegedGroupNames | Where-Object { $group.DisplayName -like "*$_*" })
            
            if ($isPrivileged) {
                $privilegedGroups += [PSCustomObject]@{
                    Id = $group.Id
                    DisplayName = $group.DisplayName
                    IsRoleAssignable = $group.IsAssignableToRole
                }
            }
        }
        
        Write-Host "    Identified $($privilegedGroups.Count) privileged groups" -ForegroundColor Gray
        
        # For each privileged group, find transitive members
        foreach ($privGroup in ($privilegedGroups | Select-Object -First 20)) {
            $groupId = $privGroup.Id
            $groupName = $privGroup.DisplayName
            
            # Get direct members
            $directMembers = @()
            try {
                $directMembers = Get-MgGroupMember -GroupId $groupId -All -ErrorAction SilentlyContinue
            }
            catch { }
            
            # Get transitive members
            $transitiveMembers = @()
            try {
                $transitiveMembers = Get-MgGroupTransitiveMember -GroupId $groupId -All -ErrorAction SilentlyContinue
            }
            catch { }
            
            # Find nested groups (groups that are members)
            $nestedGroups = $directMembers | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' -or $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }
            $directUsers = $directMembers | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' -or $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' }
            $transitiveUsers = $transitiveMembers | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' -or $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' }
            
            # Users who have access through nesting (transitive but not direct)
            $directUserIds = $directUsers | ForEach-Object { $_.Id }
            $indirectUsers = $transitiveUsers | Where-Object { $_.Id -notin $directUserIds }
            
            $results.TotalDirectMemberships += $directUsers.Count
            $results.TotalTransitiveMemberships += $transitiveUsers.Count
            
            if ($nestedGroups.Count -gt 0) {
                $nestedGroupNames = @()
                foreach ($ng in ($nestedGroups | Select-Object -First 10)) {
                    try {
                        $ngInfo = Get-MgGroup -GroupId $ng.Id -ErrorAction SilentlyContinue
                        if ($ngInfo) { $nestedGroupNames += $ngInfo.DisplayName }
                    }
                    catch { }
                }
                
                $results.DeeplyNestedGroups += [PSCustomObject]@{
                    GroupName = $groupName
                    GroupId = $groupId
                    IsRoleAssignable = $privGroup.IsRoleAssignable
                    DirectUserCount = $directUsers.Count
                    TransitiveUserCount = $transitiveUsers.Count
                    NestedGroupCount = $nestedGroups.Count
                    NestedGroups = $nestedGroupNames
                    RiskLevel = if ($privGroup.IsRoleAssignable) { "HIGH" } else { "MEDIUM" }
                }
            }
            
            # Record users with indirect access to privileged groups
            foreach ($user in ($indirectUsers | Select-Object -First 50)) {
                try {
                    $userInfo = Get-MgUser -UserId $user.Id -Property DisplayName,UserPrincipalName -ErrorAction SilentlyContinue
                    if ($userInfo) {
                        $results.UsersWithNestedAccess += [PSCustomObject]@{
                            UserId = $user.Id
                            UserPrincipalName = $userInfo.UserPrincipalName
                            DisplayName = $userInfo.DisplayName
                            PrivilegedGroup = $groupName
                            AccessType = "Transitive"
                            RiskLevel = if ($privGroup.IsRoleAssignable) { "HIGH" } else { "MEDIUM" }
                        }
                    }
                }
                catch { }
            }
        }
        
        # Calculate nesting depth
        if ($results.DeeplyNestedGroups.Count -gt 0) {
            $results.MaxNestingDepth = ($results.DeeplyNestedGroups | Measure-Object -Property NestedGroupCount -Maximum).Maximum
        }
        
        Write-Host "[+] Transitive membership analysis complete" -ForegroundColor Green
        Write-Host "    Users with nested access to privileged groups: $($results.UsersWithNestedAccess.Count)" -ForegroundColor Gray
        Write-Host "    Groups with nested membership: $($results.DeeplyNestedGroups.Count)" -ForegroundColor Gray
        
    }
    catch {
        Write-Host "[!] Error mapping transitive memberships: $_" -ForegroundColor Red
    }
    
    return $results
}

function Get-SharedMailboxAccess {
    <#
    .SYNOPSIS
        Identify shared mailboxes and users with access to them.
        Shared mailboxes are often used for lateral movement as they may contain sensitive data.
    #>
    Write-Host "`n[*] Identifying shared mailbox access..." -ForegroundColor Cyan
    
    $results = @{
        SharedMailboxes = @()
        UsersWithSharedAccess = @()
        HighValueMailboxes = @()
        MailboxPermissions = @()
    }
    
    try {
        # Get users to filter for shared mailboxes
        Write-Host "    Fetching users to identify shared mailboxes..." -ForegroundColor Gray
        
        $allUsers = @()
        try {
            $allUsers = Get-MgUser -All -Property Id,DisplayName,Mail,UserPrincipalName,AccountEnabled,AssignedLicenses -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Error fetching users: $_" -ForegroundColor Yellow
            return $results
        }
        
        # Shared mailbox indicators
        $sharedIndicators = @("shared", "info@", "support@", "sales@", "hr@",
                              "finance@", "admin@", "noreply@", "helpdesk@",
                              "team@", "group@", "general@", "contact@")
        
        $highValueIndicators = @("finance", "hr", "admin", "exec", "legal", "ceo", "cfo")
        
        foreach ($user in $allUsers) {
            $isShared = $false
            $mail = ($user.Mail, $user.UserPrincipalName | Where-Object { $_ } | Select-Object -First 1) -replace '\s+', ''
            $displayName = $user.DisplayName -replace '\s+', ''
            
            # Check common shared mailbox indicators
            foreach ($indicator in $sharedIndicators) {
                if ($mail -like "*$indicator*" -or $displayName -like "*$indicator*") {
                    $isShared = $true
                    break
                }
            }
            
            # Users without licenses might be shared mailboxes
            if (-not $user.AssignedLicenses -or $user.AssignedLicenses.Count -eq 0) {
                $isShared = $true
            }
            
            if ($isShared) {
                $riskLevel = "HIGH"
                $isHighValue = $false
                foreach ($hv in $highValueIndicators) {
                    if ($mail -like "*$hv*") {
                        $riskLevel = "CRITICAL"
                        $isHighValue = $true
                        break
                    }
                }
                
                $mailboxInfo = [PSCustomObject]@{
                    Id = $user.Id
                    DisplayName = $user.DisplayName
                    Mail = $user.Mail
                    UserPrincipalName = $user.UserPrincipalName
                    AccountEnabled = $user.AccountEnabled
                    RiskLevel = $riskLevel
                }
                
                $results.SharedMailboxes += $mailboxInfo
                
                if ($isHighValue) {
                    $results.HighValueMailboxes += $mailboxInfo
                }
            }
        }
        
        Write-Host "    Found $($results.SharedMailboxes.Count) potential shared mailboxes" -ForegroundColor Gray
        
        # Try to get mailbox permissions for identified shared mailboxes
        Write-Host "    Checking mailbox delegate access..." -ForegroundColor Gray
        
        foreach ($mailbox in ($results.SharedMailboxes | Select-Object -First 15)) {
            try {
                $permissions = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$($mailbox.Id)/mailFolders/inbox/permissions" -ErrorAction SilentlyContinue
                
                if ($permissions -and $permissions.value) {
                    foreach ($perm in $permissions.value) {
                        if ($perm.isDefault) { continue }
                        
                        $grantee = $perm.grantedTo.user
                        $results.MailboxPermissions += [PSCustomObject]@{
                            MailboxName = $mailbox.DisplayName
                            MailboxEmail = $mailbox.Mail
                            DelegateId = $grantee.id
                            DelegateName = $grantee.displayName
                            DelegateEmail = $grantee.emailAddress
                            PermissionRole = $perm.role
                            RiskLevel = $mailbox.RiskLevel
                        }
                        
                        $results.UsersWithSharedAccess += [PSCustomObject]@{
                            UserId = $grantee.id
                            DisplayName = $grantee.displayName
                            Email = $grantee.emailAddress
                            MailboxAccess = $mailbox.Mail
                            PermissionRole = $perm.role
                        }
                    }
                }
            }
            catch { }
        }
        
        Write-Host "[+] Shared mailbox analysis complete" -ForegroundColor Green
        Write-Host "    Shared mailboxes: $($results.SharedMailboxes.Count)" -ForegroundColor Gray
        Write-Host "    High-value mailboxes: $($results.HighValueMailboxes.Count)" -ForegroundColor Gray
        Write-Host "    Mailbox permissions found: $($results.MailboxPermissions.Count)" -ForegroundColor Gray
        
    }
    catch {
        Write-Host "[!] Error identifying shared mailbox access: $_" -ForegroundColor Red
    }
    
    return $results
}

function Get-CalendarMailboxDelegations {
    <#
    .SYNOPSIS
        Find delegated calendar and mailbox permissions.
        These can be exploited for lateral movement and information gathering.
    #>
    Write-Host "`n[*] Finding delegated calendar and mailbox permissions..." -ForegroundColor Cyan
    
    $results = @{
        CalendarDelegates = @()
        MailboxDelegates = @()
        SendAsPermissions = @()
        SendOnBehalfPermissions = @()
        FullAccessDelegates = @()
        HighRiskDelegations = @()
    }
    
    try {
        # Get users to check for delegations
        Write-Host "    Fetching users to analyze..." -ForegroundColor Gray
        $usersToCheck = @()
        try {
            $usersToCheck = Get-MgUser -Filter "accountEnabled eq true" -Property Id,DisplayName,Mail,UserPrincipalName -Top 100 -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Error fetching users: $_" -ForegroundColor Yellow
            return $results
        }
        
        Write-Host "    Checking $($usersToCheck.Count) users for calendar delegations..." -ForegroundColor Gray
        
        foreach ($user in $usersToCheck) {
            $userId = $user.Id
            $userMail = if ($user.Mail) { $user.Mail } else { $user.UserPrincipalName }
            $userName = $user.DisplayName
            
            # Check calendar permissions
            try {
                $calPerms = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userId/calendar/calendarPermissions" -ErrorAction SilentlyContinue
                
                if ($calPerms -and $calPerms.value) {
                    foreach ($perm in $calPerms.value) {
                        # Skip default permissions
                        if ($perm.isDefault) { continue }
                        
                        $emailAddress = $perm.emailAddress
                        $delegateEmail = if ($emailAddress.address) { $emailAddress.address } else { "Unknown" }
                        $delegateName = if ($emailAddress.name) { $emailAddress.name } else { $delegateEmail }
                        $role = if ($perm.role) { $perm.role } else { "unknown" }
                        
                        # Determine risk level
                        $riskLevel = "LOW"
                        if ($role -in @("write", "delegateWithPrivateEventAccess", "delegateWithoutPrivateEventAccess")) {
                            $riskLevel = "MEDIUM"
                        }
                        if ($role -in @("write", "delegateWithPrivateEventAccess")) {
                            $riskLevel = "HIGH"
                        }
                        
                        $delegation = [PSCustomObject]@{
                            CalendarOwner = $userName
                            CalendarOwnerEmail = $userMail
                            DelegateName = $delegateName
                            DelegateEmail = $delegateEmail
                            PermissionRole = $role
                            AllowedRoles = $perm.allowedRoles
                            RiskLevel = $riskLevel
                        }
                        
                        $results.CalendarDelegates += $delegation
                        
                        if ($riskLevel -in @("HIGH", "CRITICAL")) {
                            $results.HighRiskDelegations += [PSCustomObject]@{
                                CalendarOwner = $userName
                                CalendarOwnerEmail = $userMail
                                DelegateName = $delegateName
                                DelegateEmail = $delegateEmail
                                PermissionRole = $role
                                DelegationType = "Calendar"
                                RiskLevel = $riskLevel
                            }
                        }
                    }
                }
            }
            catch { }
            
            # Check mailbox settings for delegates
            try {
                $mailboxSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userId/mailboxSettings" -ErrorAction SilentlyContinue
                
                if ($mailboxSettings) {
                    $delegatePerms = $mailboxSettings.delegateMeetingMessageDeliveryOptions
                    
                    if ($delegatePerms -and $delegatePerms -ne "sendToDelegateAndInformationToPrincipal") {
                        $results.MailboxDelegates += [PSCustomObject]@{
                            MailboxOwner = $userName
                            MailboxOwnerEmail = $userMail
                            DelegateDeliveryOption = $delegatePerms
                            RiskLevel = "MEDIUM"
                        }
                    }
                }
            }
            catch { }
            
            # Try to get send-on-behalf permissions (beta API)
            try {
                $sobData = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$userId`?`$select=grantSendOnBehalfTo" -ErrorAction SilentlyContinue
                
                if ($sobData -and $sobData.grantSendOnBehalfTo) {
                    foreach ($delegate in $sobData.grantSendOnBehalfTo) {
                        $results.SendOnBehalfPermissions += [PSCustomObject]@{
                            MailboxOwner = $userName
                            MailboxOwnerEmail = $userMail
                            DelegateId = $delegate.id
                            DelegateName = $delegate.displayName
                            DelegateEmail = $delegate.mail
                            PermissionType = "SendOnBehalf"
                            RiskLevel = "HIGH"
                        }
                        
                        $results.HighRiskDelegations += [PSCustomObject]@{
                            CalendarOwner = $userName
                            CalendarOwnerEmail = $userMail
                            DelegateName = $delegate.displayName
                            DelegateEmail = $delegate.mail
                            PermissionRole = "SendOnBehalf"
                            DelegationType = "Mailbox"
                            RiskLevel = "HIGH"
                        }
                    }
                }
            }
            catch { }
        }
        
        Write-Host "[+] Delegation analysis complete" -ForegroundColor Green
        Write-Host "    Calendar delegates found: $($results.CalendarDelegates.Count)" -ForegroundColor Gray
        Write-Host "    Mailbox delegates found: $($results.MailboxDelegates.Count)" -ForegroundColor Gray
        Write-Host "    Send-on-behalf permissions: $($results.SendOnBehalfPermissions.Count)" -ForegroundColor Gray
        Write-Host "    High-risk delegations: $($results.HighRiskDelegations.Count)" -ForegroundColor Gray
        
    }
    catch {
        Write-Host "[!] Error finding calendar/mailbox delegations: $_" -ForegroundColor Red
    }
    
    return $results
}

function Get-LateralMovementOpportunities {
    <#
    .SYNOPSIS
        Comprehensive lateral movement opportunity analysis.
        Combines all lateral movement vectors into a single assessment.
    #>
    Write-Host ("`n" + ("=" * 80)) -ForegroundColor Cyan
    Write-Host ("{0,45}" -f "LATERAL MOVEMENT OPPORTUNITY ANALYSIS") -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "`nAnalyzing potential lateral movement vectors..." -ForegroundColor Yellow
    
    $results = @{
        TransitiveMemberships = @{}
        SharedMailboxAccess = @{}
        CalendarMailboxDelegations = @{}
        LateralMovementPaths = @()
        Summary = @{
            TotalLateralPaths = 0
            CriticalPaths = 0
            HighPaths = 0
            MediumPaths = 0
        }
    }
    
    # 1. Get transitive group memberships
    Write-Host "`n--- Phase 1: Transitive Group Membership Analysis ---" -ForegroundColor Cyan
    $results.TransitiveMemberships = Get-TransitiveGroupMemberships
    
    # 2. Get shared mailbox access
    Write-Host "`n--- Phase 2: Shared Mailbox Access Analysis ---" -ForegroundColor Cyan
    $results.SharedMailboxAccess = Get-SharedMailboxAccess
    
    # 3. Get calendar/mailbox delegations
    Write-Host "`n--- Phase 3: Calendar/Mailbox Delegation Analysis ---" -ForegroundColor Cyan
    $results.CalendarMailboxDelegations = Get-CalendarMailboxDelegations
    
    # 4. Build lateral movement paths
    Write-Host "`n--- Phase 4: Building Lateral Movement Paths ---" -ForegroundColor Cyan
    
    # Path type 1: Transitive group access to privileged groups
    foreach ($user in $results.TransitiveMemberships.UsersWithNestedAccess) {
        $results.LateralMovementPaths += [PSCustomObject]@{
            PathType = "Transitive Group Membership"
            SourceUser = $user.UserPrincipalName
            SourceUserId = $user.UserId
            TargetResource = $user.PrivilegedGroup
            AccessMethod = "Nested Group Membership"
            RiskLevel = $user.RiskLevel
            Description = "User has indirect access to '$($user.PrivilegedGroup)' through group nesting"
            Remediation = "Flatten group structure or implement JIT access for privileged groups"
        }
    }
    
    # Path type 2: Shared mailbox access
    foreach ($perm in $results.SharedMailboxAccess.MailboxPermissions) {
        $results.LateralMovementPaths += [PSCustomObject]@{
            PathType = "Shared Mailbox Access"
            SourceUser = if ($perm.DelegateName) { $perm.DelegateName } else { $perm.DelegateEmail }
            SourceUserId = $perm.DelegateId
            TargetResource = $perm.MailboxEmail
            AccessMethod = "Mailbox Permission ($($perm.PermissionRole))"
            RiskLevel = $perm.RiskLevel
            Description = "User can access shared mailbox '$($perm.MailboxName)'"
            Remediation = "Review shared mailbox permissions; implement audit logging"
        }
    }
    
    # Path type 3: Calendar delegations
    foreach ($delegation in $results.CalendarMailboxDelegations.HighRiskDelegations) {
        $results.LateralMovementPaths += [PSCustomObject]@{
            PathType = "Calendar/Mailbox Delegation"
            SourceUser = if ($delegation.DelegateName) { $delegation.DelegateName } else { $delegation.DelegateEmail }
            SourceUserId = $null
            TargetResource = $delegation.CalendarOwnerEmail
            AccessMethod = "$($delegation.DelegationType) Delegation ($($delegation.PermissionRole))"
            RiskLevel = $delegation.RiskLevel
            Description = "User has delegated access to $($delegation.CalendarOwner)'s $($delegation.DelegationType)"
            Remediation = "Review delegation permissions; implement periodic access reviews"
        }
    }
    
    # Path type 4: Send-on-behalf permissions
    foreach ($perm in $results.CalendarMailboxDelegations.SendOnBehalfPermissions) {
        $results.LateralMovementPaths += [PSCustomObject]@{
            PathType = "Send-On-Behalf Permission"
            SourceUser = if ($perm.DelegateName) { $perm.DelegateName } else { $perm.DelegateEmail }
            SourceUserId = $perm.DelegateId
            TargetResource = $perm.MailboxOwnerEmail
            AccessMethod = "Send-On-Behalf"
            RiskLevel = "HIGH"
            Description = "User can send emails on behalf of $($perm.MailboxOwner)"
            Remediation = "Remove unnecessary send-on-behalf permissions"
        }
    }
    
    # Path type 5: Deeply nested groups (structural risk)
    foreach ($group in $results.TransitiveMemberships.DeeplyNestedGroups) {
        if ($group.NestedGroupCount -ge 2) {
            $results.LateralMovementPaths += [PSCustomObject]@{
                PathType = "Complex Group Nesting"
                SourceUser = "$($group.NestedGroupCount) nested groups"
                SourceUserId = $null
                TargetResource = $group.GroupName
                AccessMethod = "Multi-level Group Nesting"
                RiskLevel = if ($group.IsRoleAssignable) { "HIGH" } else { "MEDIUM" }
                Description = "Privileged group has $($group.NestedGroupCount) nested groups, $($group.TransitiveUserCount) transitive members"
                Remediation = "Simplify group structure; use direct assignments for privileged groups"
            }
        }
    }
    
    # Calculate summary
    $results.Summary.TotalLateralPaths = $results.LateralMovementPaths.Count
    $results.Summary.CriticalPaths = ($results.LateralMovementPaths | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $results.Summary.HighPaths = ($results.LateralMovementPaths | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $results.Summary.MediumPaths = ($results.LateralMovementPaths | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    
    Write-Host "`n[+] Lateral Movement Analysis Complete" -ForegroundColor Green
    Write-Host "    Total lateral movement paths: $($results.Summary.TotalLateralPaths)" -ForegroundColor $(if ($results.Summary.TotalLateralPaths -gt 0) { "Yellow" } else { "Green" })
    Write-Host "    CRITICAL risk paths: $($results.Summary.CriticalPaths)" -ForegroundColor $(if ($results.Summary.CriticalPaths -gt 0) { "Red" } else { "Green" })
    Write-Host "    HIGH risk paths: $($results.Summary.HighPaths)" -ForegroundColor $(if ($results.Summary.HighPaths -gt 0) { "Yellow" } else { "Green" })
    Write-Host "    MEDIUM risk paths: $($results.Summary.MediumPaths)" -ForegroundColor Gray
    
    return $results
}

function Show-TransitiveMembershipReport {
    param([hashtable]$Results)
    
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Cyan
    Write-Host ("{0,65}" -f "TRANSITIVE GROUP MEMBERSHIP ANALYSIS") -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Cyan
    
    # Summary
    Write-Host "`nSUMMARY:" -ForegroundColor Yellow
    Write-Host "   Total direct memberships: $($Results.TotalDirectMemberships)"
    Write-Host "   Total transitive memberships: $($Results.TotalTransitiveMemberships)"
    Write-Host "   Groups with nested membership: $($Results.DeeplyNestedGroups.Count)"
    Write-Host "   Users with indirect privileged access: $($Results.UsersWithNestedAccess.Count)"
    
    # Deeply nested groups
    if ($Results.DeeplyNestedGroups.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host ("{0,65}" -f "PRIVILEGED GROUPS WITH NESTED MEMBERSHIP") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        Write-Host ("`n{0,-34} {1,-7} {2,-7} {3,-7} {4,-9} {5,-39} {6,-7}" -f "Group Name", "Direct", "Trans.", "Nested", "Role Grp?", "Nested Groups", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        $sortedGroups = $Results.DeeplyNestedGroups | Sort-Object { @{"CRITICAL"=0;"HIGH"=1;"MEDIUM"=2}[$_.RiskLevel] }
        
        foreach ($group in ($sortedGroups | Select-Object -First 30)) {
            $name = if ($group.GroupName.Length -gt 33) { $group.GroupName.Substring(0, 33) } else { $group.GroupName }
            $direct = $group.DirectUserCount
            $transitive = $group.TransitiveUserCount
            $nested = $group.NestedGroupCount
            $roleAssignable = if ($group.IsRoleAssignable) { "Yes" } else { "No" }
            $nestedNames = ($group.NestedGroups | Select-Object -First 3) -join ", "
            if ($nestedNames.Length -gt 38) { $nestedNames = $nestedNames.Substring(0, 38) }
            
            $color = if ($group.RiskLevel -eq "HIGH") { "Yellow" } else { "White" }
            Write-Host ("{0,-34} {1,-7} {2,-7} {3,-7} {4,-9} {5,-39} {6,-7}" -f $name, $direct, $transitive, $nested, $roleAssignable, $nestedNames, $group.RiskLevel) -ForegroundColor $color
        }
        
        if ($Results.DeeplyNestedGroups.Count -gt 30) {
            Write-Host "    ... and $($Results.DeeplyNestedGroups.Count - 30) more groups" -ForegroundColor Gray
        }
        Write-Host ("-" * 120) -ForegroundColor Gray
    }
    
    # Users with indirect access
    if ($Results.UsersWithNestedAccess.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host ("{0,65}" -f "USERS WITH INDIRECT ACCESS TO PRIVILEGED GROUPS") -ForegroundColor Red
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        Write-Host "`n!!! These users have access to privileged groups through group nesting" -ForegroundColor Yellow
        
        Write-Host ("`n{0,-24} {1,-39} {2,-34} {3,-11} {4,-7}" -f "Display Name", "User Principal Name", "Privileged Group", "Access", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        $sortedUsers = $Results.UsersWithNestedAccess | Sort-Object { @{"CRITICAL"=0;"HIGH"=1;"MEDIUM"=2}[$_.RiskLevel] }
        
        foreach ($user in ($sortedUsers | Select-Object -First 40)) {
            $name = if ($user.DisplayName -and $user.DisplayName.Length -gt 23) { $user.DisplayName.Substring(0, 23) } else { $user.DisplayName }
            $upn = if ($user.UserPrincipalName -and $user.UserPrincipalName.Length -gt 38) { $user.UserPrincipalName.Substring(0, 38) } else { $user.UserPrincipalName }
            $privGroup = if ($user.PrivilegedGroup -and $user.PrivilegedGroup.Length -gt 33) { $user.PrivilegedGroup.Substring(0, 33) } else { $user.PrivilegedGroup }
            
            $color = if ($user.RiskLevel -eq "HIGH") { "Yellow" } else { "White" }
            Write-Host ("{0,-24} {1,-39} {2,-34} {3,-11} {4,-7}" -f $name, $upn, $privGroup, $user.AccessType, $user.RiskLevel) -ForegroundColor $color
        }
        
        if ($Results.UsersWithNestedAccess.Count -gt 40) {
            Write-Host "    ... and $($Results.UsersWithNestedAccess.Count - 40) more users" -ForegroundColor Gray
        }
        Write-Host ("-" * 120) -ForegroundColor Gray
    }
    
    # Recommendations
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Gray
    Write-Host "REMEDIATION RECOMMENDATIONS:" -ForegroundColor Yellow
    Write-Host ("=" * 120) -ForegroundColor Gray
    Write-Host "`n1. Simplify Group Structure:" -ForegroundColor Cyan
    Write-Host "   - Flatten nested groups where possible" -ForegroundColor Gray
    Write-Host "   - Use direct assignments for privileged group membership" -ForegroundColor Gray
    Write-Host "`n2. Implement Access Reviews:" -ForegroundColor Cyan
    Write-Host "   - Enable regular access reviews for privileged groups" -ForegroundColor Gray
    Write-Host "   - Review transitive memberships quarterly" -ForegroundColor Gray
}

function Show-SharedMailboxReport {
    param([hashtable]$Results)
    
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Cyan
    Write-Host ("{0,65}" -f "SHARED MAILBOX ACCESS ANALYSIS") -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Cyan
    
    # Summary
    Write-Host "`nSUMMARY:" -ForegroundColor Yellow
    Write-Host "   Shared mailboxes identified: $($Results.SharedMailboxes.Count)"
    Write-Host "   High-value mailboxes: $($Results.HighValueMailboxes.Count)"
    Write-Host "   Mailbox permissions found: $($Results.MailboxPermissions.Count)"
    Write-Host "   Users with shared access: $($Results.UsersWithSharedAccess.Count)"
    
    # High-value mailboxes
    if ($Results.HighValueMailboxes.Count -gt 0) {
        Write-Host ("`n" + ("-" * 100)) -ForegroundColor Gray
        Write-Host ("{0,55}" -f "HIGH-VALUE SHARED MAILBOXES") -ForegroundColor Red
        Write-Host ("-" * 100) -ForegroundColor Gray
        
        Write-Host "`n!!! These mailboxes may contain sensitive information" -ForegroundColor Yellow
        
        Write-Host ("`n{0,-29} {1,-49} {2,-9}" -f "Display Name", "Email Address", "Enabled") -ForegroundColor Yellow
        Write-Host ("-" * 100) -ForegroundColor Gray
        
        foreach ($mailbox in ($Results.HighValueMailboxes | Select-Object -First 20)) {
            $name = if ($mailbox.DisplayName -and $mailbox.DisplayName.Length -gt 28) { $mailbox.DisplayName.Substring(0, 28) } else { $mailbox.DisplayName }
            $email = if ($mailbox.Mail) { $mailbox.Mail } else { $mailbox.UserPrincipalName }
            if ($email -and $email.Length -gt 48) { $email = $email.Substring(0, 48) }
            $enabled = if ($mailbox.AccountEnabled) { "Yes" } else { "No" }
            
            Write-Host ("{0,-29} {1,-49} {2,-9}" -f $name, $email, $enabled) -ForegroundColor Red
        }
        Write-Host ("-" * 100) -ForegroundColor Gray
    }
    
    # All shared mailboxes
    if ($Results.SharedMailboxes.Count -gt 0) {
        Write-Host ("`n" + ("-" * 100)) -ForegroundColor Gray
        Write-Host ("{0,55}" -f "ALL SHARED MAILBOXES") -ForegroundColor Yellow
        Write-Host ("-" * 100) -ForegroundColor Gray
        
        Write-Host ("`n{0,-29} {1,-49} {2,-9} {3,-7}" -f "Display Name", "Email Address", "Enabled", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 100) -ForegroundColor Gray
        
        $sortedMailboxes = $Results.SharedMailboxes | Sort-Object { @{"CRITICAL"=0;"HIGH"=1;"MEDIUM"=2}[$_.RiskLevel] }
        
        foreach ($mailbox in ($sortedMailboxes | Select-Object -First 40)) {
            $name = if ($mailbox.DisplayName -and $mailbox.DisplayName.Length -gt 28) { $mailbox.DisplayName.Substring(0, 28) } else { $mailbox.DisplayName }
            $email = if ($mailbox.Mail) { $mailbox.Mail } else { $mailbox.UserPrincipalName }
            if ($email -and $email.Length -gt 48) { $email = $email.Substring(0, 48) }
            $enabled = if ($mailbox.AccountEnabled) { "Yes" } else { "No" }
            
            $color = if ($mailbox.RiskLevel -eq "CRITICAL") { "Red" } elseif ($mailbox.RiskLevel -eq "HIGH") { "Yellow" } else { "White" }
            Write-Host ("{0,-29} {1,-49} {2,-9} {3,-7}" -f $name, $email, $enabled, $mailbox.RiskLevel) -ForegroundColor $color
        }
        
        if ($Results.SharedMailboxes.Count -gt 40) {
            Write-Host "    ... and $($Results.SharedMailboxes.Count - 40) more mailboxes" -ForegroundColor Gray
        }
        Write-Host ("-" * 100) -ForegroundColor Gray
    }
}

function Show-CalendarDelegationReport {
    param([hashtable]$Results)
    
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Cyan
    Write-Host ("{0,65}" -f "CALENDAR & MAILBOX DELEGATION ANALYSIS") -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Cyan
    
    # Summary
    Write-Host "`nSUMMARY:" -ForegroundColor Yellow
    Write-Host "   Calendar delegates found: $($Results.CalendarDelegates.Count)"
    Write-Host "   Mailbox delegates found: $($Results.MailboxDelegates.Count)"
    Write-Host "   Send-on-behalf permissions: $($Results.SendOnBehalfPermissions.Count)"
    Write-Host "   High-risk delegations: $($Results.HighRiskDelegations.Count)"
    
    # High-risk delegations
    if ($Results.HighRiskDelegations.Count -gt 0) {
        Write-Host ("`n" + ("-" * 95)) -ForegroundColor Gray
        Write-Host ("{0,50}" -f "HIGH-RISK DELEGATIONS") -ForegroundColor Red
        Write-Host ("-" * 95) -ForegroundColor Gray
        
        Write-Host "`n!!! These delegations provide elevated access that could be exploited" -ForegroundColor Yellow
        
        Write-Host ("`n{0,-24} {1,-24} {2,-11} {3,-19} {4,-7}" -f "Owner", "Delegate", "Type", "Permission", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 95) -ForegroundColor Gray
        
        $sortedDelegations = $Results.HighRiskDelegations | Sort-Object { @{"CRITICAL"=0;"HIGH"=1;"MEDIUM"=2}[$_.RiskLevel] }
        
        foreach ($delegation in ($sortedDelegations | Select-Object -First 30)) {
            $owner = if ($delegation.CalendarOwner -and $delegation.CalendarOwner.Length -gt 23) { $delegation.CalendarOwner.Substring(0, 23) } else { $delegation.CalendarOwner }
            $delegate = if ($delegation.DelegateName) { $delegation.DelegateName } else { $delegation.DelegateEmail }
            if ($delegate -and $delegate.Length -gt 23) { $delegate = $delegate.Substring(0, 23) }
            $delType = if ($delegation.DelegationType -and $delegation.DelegationType.Length -gt 10) { $delegation.DelegationType.Substring(0, 10) } else { $delegation.DelegationType }
            $permission = if ($delegation.PermissionRole -and $delegation.PermissionRole.Length -gt 18) { $delegation.PermissionRole.Substring(0, 18) } else { $delegation.PermissionRole }
            
            $color = if ($delegation.RiskLevel -eq "HIGH") { "Yellow" } else { "White" }
            Write-Host ("{0,-24} {1,-24} {2,-11} {3,-19} {4,-7}" -f $owner, $delegate, $delType, $permission, $delegation.RiskLevel) -ForegroundColor $color
        }
        
        if ($Results.HighRiskDelegations.Count -gt 30) {
            Write-Host "    ... and $($Results.HighRiskDelegations.Count - 30) more delegations" -ForegroundColor Gray
        }
        Write-Host ("-" * 95) -ForegroundColor Gray
    }
    
    # Calendar delegates
    if ($Results.CalendarDelegates.Count -gt 0) {
        Write-Host ("`n" + ("-" * 95)) -ForegroundColor Gray
        Write-Host ("{0,50}" -f "CALENDAR DELEGATES") -ForegroundColor Yellow
        Write-Host ("-" * 95) -ForegroundColor Gray
        
        Write-Host ("`n{0,-29} {1,-29} {2,-24} {3,-7}" -f "Calendar Owner", "Delegate", "Permission Role", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 95) -ForegroundColor Gray
        
        foreach ($delegation in ($Results.CalendarDelegates | Select-Object -First 30)) {
            $owner = if ($delegation.CalendarOwner -and $delegation.CalendarOwner.Length -gt 28) { $delegation.CalendarOwner.Substring(0, 28) } else { $delegation.CalendarOwner }
            $delegate = if ($delegation.DelegateName) { $delegation.DelegateName } else { $delegation.DelegateEmail }
            if ($delegate -and $delegate.Length -gt 28) { $delegate = $delegate.Substring(0, 28) }
            $permission = if ($delegation.PermissionRole -and $delegation.PermissionRole.Length -gt 23) { $delegation.PermissionRole.Substring(0, 23) } else { $delegation.PermissionRole }
            
            Write-Host ("{0,-29} {1,-29} {2,-24} {3,-7}" -f $owner, $delegate, $permission, $delegation.RiskLevel)
        }
        
        if ($Results.CalendarDelegates.Count -gt 30) {
            Write-Host "    ... and $($Results.CalendarDelegates.Count - 30) more calendar delegates" -ForegroundColor Gray
        }
        Write-Host ("-" * 95) -ForegroundColor Gray
    }
    
    # Recommendations
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Gray
    Write-Host "REMEDIATION RECOMMENDATIONS:" -ForegroundColor Yellow
    Write-Host ("=" * 120) -ForegroundColor Gray
    Write-Host "`n1. Review Calendar Delegations:" -ForegroundColor Cyan
    Write-Host "   - Audit all calendar delegates with write or delegate access" -ForegroundColor Gray
    Write-Host "`n2. Mailbox Permissions:" -ForegroundColor Cyan
    Write-Host "   - Review send-on-behalf permissions for executive mailboxes" -ForegroundColor Gray
    Write-Host "   - Enable mailbox audit logging for all delegated mailboxes" -ForegroundColor Gray
}

function Show-LateralMovementReport {
    param([hashtable]$Results)
    
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Cyan
    Write-Host ("{0,65}" -f "LATERAL MOVEMENT OPPORTUNITY REPORT") -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Cyan
    
    # Executive Summary
    Write-Host "`nEXECUTIVE SUMMARY:" -ForegroundColor Yellow
    Write-Host "   Total Lateral Movement Paths: $($Results.Summary.TotalLateralPaths)" -ForegroundColor $(if ($Results.Summary.TotalLateralPaths -gt 0) { "Yellow" } else { "Green" })
    Write-Host "   CRITICAL Risk Paths: $($Results.Summary.CriticalPaths)" -ForegroundColor $(if ($Results.Summary.CriticalPaths -gt 0) { "Red" } else { "Green" })
    Write-Host "   HIGH Risk Paths: $($Results.Summary.HighPaths)" -ForegroundColor $(if ($Results.Summary.HighPaths -gt 0) { "Yellow" } else { "Green" })
    Write-Host "   MEDIUM Risk Paths: $($Results.Summary.MediumPaths)" -ForegroundColor Gray
    
    # Component summaries
    Write-Host "`nCOMPONENT BREAKDOWN:" -ForegroundColor Cyan
    Write-Host "   Transitive Group Memberships: $($Results.TransitiveMemberships.UsersWithNestedAccess.Count) indirect access paths"
    Write-Host "   Shared Mailbox Access: $($Results.SharedMailboxAccess.SharedMailboxes.Count) shared mailboxes"
    Write-Host "   Calendar/Mailbox Delegations: $($Results.CalendarMailboxDelegations.HighRiskDelegations.Count) high-risk delegations"
    
    # All lateral movement paths
    if ($Results.LateralMovementPaths.Count -gt 0) {
        Write-Host ("`n" + ("-" * 115)) -ForegroundColor Gray
        Write-Host ("{0,60}" -f "LATERAL MOVEMENT PATHS") -ForegroundColor Red
        Write-Host ("-" * 115) -ForegroundColor Gray
        
        Write-Host ("`n{0,-25} {1,-27} {2,-27} {3,-21} {4,-7}" -f "Path Type", "Source", "Target", "Method", "Risk") -ForegroundColor Yellow
        Write-Host ("-" * 115) -ForegroundColor Gray
        
        $sortedPaths = $Results.LateralMovementPaths | Sort-Object { @{"CRITICAL"=0;"HIGH"=1;"MEDIUM"=2;"LOW"=3}[$_.RiskLevel] }
        
        foreach ($path in ($sortedPaths | Select-Object -First 40)) {
            $pathType = if ($path.PathType -and $path.PathType.Length -gt 24) { $path.PathType.Substring(0, 24) } else { $path.PathType }
            $source = if ($path.SourceUser -and $path.SourceUser.Length -gt 26) { $path.SourceUser.Substring(0, 26) } else { $path.SourceUser }
            $target = if ($path.TargetResource -and $path.TargetResource.Length -gt 26) { $path.TargetResource.Substring(0, 26) } else { $path.TargetResource }
            $method = if ($path.AccessMethod -and $path.AccessMethod.Length -gt 20) { $path.AccessMethod.Substring(0, 20) } else { $path.AccessMethod }
            
            $color = if ($path.RiskLevel -eq "CRITICAL") { "Red" } elseif ($path.RiskLevel -eq "HIGH") { "Yellow" } else { "White" }
            Write-Host ("{0,-25} {1,-27} {2,-27} {3,-21} {4,-7}" -f $pathType, $source, $target, $method, $path.RiskLevel) -ForegroundColor $color
        }
        
        if ($Results.LateralMovementPaths.Count -gt 40) {
            Write-Host "    ... and $($Results.LateralMovementPaths.Count - 40) more lateral movement paths" -ForegroundColor Gray
        }
        Write-Host ("-" * 115) -ForegroundColor Gray
    }
    
    # Recommendations
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Gray
    Write-Host "REMEDIATION RECOMMENDATIONS:" -ForegroundColor Yellow
    Write-Host ("=" * 120) -ForegroundColor Gray
    
    Write-Host "`n1. Group Structure:" -ForegroundColor Cyan
    Write-Host "   - Flatten nested group hierarchies for privileged groups" -ForegroundColor Gray
    Write-Host "   - Use direct role assignments instead of nested groups" -ForegroundColor Gray
    
    Write-Host "`n2. Mailbox Security:" -ForegroundColor Cyan
    Write-Host "   - Audit all shared mailbox permissions" -ForegroundColor Gray
    Write-Host "   - Remove unnecessary mailbox access" -ForegroundColor Gray
    
    Write-Host "`n3. Delegation Review:" -ForegroundColor Cyan
    Write-Host "   - Review all calendar delegates with elevated permissions" -ForegroundColor Gray
    Write-Host "   - Audit send-on-behalf permissions for executive mailboxes" -ForegroundColor Gray
}

function Show-SecuritySummary {
    param(
        [array]$Data,
        [string]$Title,
        [switch]$ShowRisk
    )
    
    Write-Host ("`n" + ("=" * 110)) -ForegroundColor Cyan
    Write-Host ("{0,55}" -f $Title) -ForegroundColor Cyan
    Write-Host ("=" * 110) -ForegroundColor Cyan
    
    Write-Host "`nTotal items: $($Data.Count)"
    
    if ($ShowRisk -and $Data.Count -gt 0) {
        $riskCounts = $Data | Group-Object -Property RiskLevel
        Write-Host "`nRisk Distribution:"
        foreach ($risk in @("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")) {
            $count = ($riskCounts | Where-Object { $_.Name -eq $risk }).Count
            if ($count -gt 0) {
                $indicator = if ($risk -in @("CRITICAL", "HIGH")) { "!!!" } else { "" }
                Write-Host "  $indicator $risk`: $count" -ForegroundColor $(if ($risk -eq "CRITICAL") { "Red" } elseif ($risk -eq "HIGH") { "Yellow" } else { "Gray" })
            }
        }
    }
    
    Write-Host ("`n" + ("-" * 110)) -ForegroundColor Gray
}

function Show-MFAStatusReport {
    param([array]$Users)
    
    Show-SecuritySummary -Data $Users -Title "MFA STATUS REPORT" -ShowRisk
    
    Write-Host ("{0,-24} {1,-39} {2,-7} {3,-24} {4,-9}" -f "Display Name", "Email/UPN", "MFA", "Methods", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    $riskOrder = @{ "HIGH" = 0; "UNKNOWN" = 1; "LOW" = 2 }
    $sortedUsers = $Users | Sort-Object { $riskOrder[$_.RiskLevel] }
    
    foreach ($user in $sortedUsers) {
        $displayName = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(23, $user.DisplayName.Length)) } else { "" }
        $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(38, $user.UserPrincipalName.Length)) } elseif ($user.Mail) { $user.Mail.Substring(0, [Math]::Min(38, $user.Mail.Length)) } else { "" }
        $hasMFA = if ($user.HasMFA -eq $true) { "Yes" } elseif ($user.HasMFA -eq $false) { "No" } else { "?" }
        $methods = if ($user.MFAMethods) { $user.MFAMethods.Substring(0, [Math]::Min(23, $user.MFAMethods.Length)) } else { "" }
        $risk = $user.RiskLevel
        
        Write-Host ("{0,-24} {1,-39} {2,-7} {3,-24} {4,-9}" -f $displayName, $email, $hasMFA, $methods, $risk)
    }
    Write-Host ("-" * 110) -ForegroundColor Gray
}

function Show-PrivilegedUsersReport {
    param([array]$Users)
    
    Show-SecuritySummary -Data $Users -Title "PRIVILEGED ROLE ASSIGNMENTS" -ShowRisk
    
    Write-Host ("{0,-24} {1,-34} {2,-29} {3,-11} {4,-7}" -f "Display Name", "Email/UPN", "Role", "Type", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    $riskOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3 }
    $sortedUsers = $Users | Sort-Object { $riskOrder[$_.RiskLevel] }
    
    foreach ($user in $sortedUsers) {
        $displayName = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(23, $user.DisplayName.Length)) } else { "" }
        $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(33, $user.UserPrincipalName.Length)) } elseif ($user.Mail) { $user.Mail.Substring(0, [Math]::Min(33, $user.Mail.Length)) } else { "" }
        $role = if ($user.Role) { $user.Role.Substring(0, [Math]::Min(28, $user.Role.Length)) } else { "" }
        $type = if ($user.AssignmentType) { $user.AssignmentType.Substring(0, [Math]::Min(10, $user.AssignmentType.Length)) } else { "Active" }
        $risk = $user.RiskLevel
        
        Write-Host ("{0,-24} {1,-34} {2,-29} {3,-11} {4,-7}" -f $displayName, $email, $role, $type, $risk)
    }
    Write-Host ("-" * 110) -ForegroundColor Gray
}

function Show-AppsReport {
    param([hashtable]$Data)
    
    $apps = $Data.Applications
    $sps = $Data.ServicePrincipals
    $highRiskApps = $Data.HighRiskApps
    $highPrivilegeSPs = $Data.HighPrivilegeSPs
    $appsWithCreds = $Data.AppsWithCredentials
    
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Cyan
    Write-Host ("{0,60}" -f "APPLICATION & SERVICE PRINCIPAL REPORT") -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Cyan
    
    Write-Host "`nApp Registrations: $($apps.Count)"
    Write-Host "Service Principals (Enterprise Apps): $($sps.Count)"
    Write-Host "Apps with Credentials (secrets/certs): $($appsWithCreds.Count)"
    Write-Host "High-Risk App Registrations: $($highRiskApps.Count)" -ForegroundColor $(if ($highRiskApps.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "High-Privilege Service Principals: $($highPrivilegeSPs.Count)" -ForegroundColor $(if ($highPrivilegeSPs.Count -gt 0) { "Red" } else { "Green" })
    
    # HIGH-PRIVILEGE SERVICE PRINCIPALS (most dangerous - have granted permissions)
    if ($highPrivilegeSPs.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host "HIGH-PRIVILEGE SERVICE PRINCIPALS (with dangerous application permissions):" -ForegroundColor Red
        Write-Host ("-" * 120) -ForegroundColor Gray
        Write-Host ("{0,-29} {1,-9} {2,-44} {3,-32}" -f "Display Name", "Risk", "App Permissions", "Owners") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        # Sort by risk level
        $riskOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3 }
        $sortedSPs = $highPrivilegeSPs | Sort-Object { $riskOrder[$_.RiskLevel] }
        
        foreach ($sp in ($sortedSPs | Select-Object -First 25)) {
            $name = if ($sp.DisplayName) { $sp.DisplayName.Substring(0, [Math]::Min(28, $sp.DisplayName.Length)) } else { "" }
            $risk = if ($sp.RiskLevel) { $sp.RiskLevel.Substring(0, [Math]::Min(8, $sp.RiskLevel.Length)) } else { "" }
            $perms = if ($sp.GrantedAppPermissions) { $sp.GrantedAppPermissions.Substring(0, [Math]::Min(43, $sp.GrantedAppPermissions.Length)) } else { "None" }
            $owners = if ($sp.Owners) { $sp.Owners.Substring(0, [Math]::Min(31, $sp.Owners.Length)) } else { "None" }
            
            $riskColor = switch ($sp.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "DarkRed" }
                "MEDIUM" { "Yellow" }
                default { "White" }
            }
            Write-Host ("{0,-29} " -f $name) -NoNewline
            Write-Host ("{0,-9} " -f $risk) -NoNewline -ForegroundColor $riskColor
            Write-Host ("{0,-44} {1,-32}" -f $perms, $owners)
        }
        
        if ($highPrivilegeSPs.Count -gt 25) {
            Write-Host "    ... and $($highPrivilegeSPs.Count - 25) more high-privilege service principals" -ForegroundColor Gray
        }
    }
    
    # HIGH-RISK APP REGISTRATIONS (requesting dangerous permissions)
    if ($highRiskApps.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host "HIGH-RISK APP REGISTRATIONS (requesting dangerous permissions):" -ForegroundColor Red
        Write-Host ("-" * 120) -ForegroundColor Gray
        Write-Host ("{0,-29} {1,-11} {2,-39} {3,-34}" -f "Display Name", "Credentials", "App Permissions Requested", "Owners") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        foreach ($app in ($highRiskApps | Select-Object -First 20)) {
            $name = if ($app.DisplayName) { $app.DisplayName.Substring(0, [Math]::Min(28, $app.DisplayName.Length)) } else { "" }
            $credsType = @()
            if ($app.HasSecrets) { $credsType += "S" }
            if ($app.HasCertificates) { $credsType += "C" }
            $credsStr = if ($credsType.Count -gt 0) { "Yes($($credsType -join ','))" } else { "No" }
            $perms = if ($app.RequestedAppPermissions) { $app.RequestedAppPermissions.Substring(0, [Math]::Min(38, $app.RequestedAppPermissions.Length)) } else { "None" }
            $owners = if ($app.Owners) { $app.Owners.Substring(0, [Math]::Min(33, $app.Owners.Length)) } else { "None" }
            Write-Host ("{0,-29} {1,-11} {2,-39} {3,-34}" -f $name, $credsStr, $perms, $owners)
        }
        
        if ($highRiskApps.Count -gt 20) {
            Write-Host "    ... and $($highRiskApps.Count - 20) more high-risk apps" -ForegroundColor Gray
        }
    }
    
    # APP REGISTRATIONS WITH SECRETS/CERTIFICATES
    if ($appsWithCreds.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host "APP REGISTRATIONS WITH SECRETS/CERTIFICATES:" -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        Write-Host ("{0,-29} {1,-37} {2,-2} {3,-2} {4,-24} {5,-17}" -f "Display Name", "App ID", "S", "C", "Credential Expiry", "Owners") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        foreach ($app in ($appsWithCreds | Select-Object -First 25)) {
            $name = if ($app.DisplayName) { $app.DisplayName.Substring(0, [Math]::Min(28, $app.DisplayName.Length)) } else { "" }
            $appId = if ($app.AppId) { $app.AppId.Substring(0, [Math]::Min(36, $app.AppId.Length)) } else { "" }
            $secrets = if ($app.HasSecrets) { [char]0x2713 } else { "-" }
            $certs = if ($app.HasCertificates) { [char]0x2713 } else { "-" }
            $expires = if ($app.CredentialDetails) { $app.CredentialDetails.Substring(0, [Math]::Min(23, $app.CredentialDetails.Length)) } else { "N/A" }
            $owners = if ($app.Owners) { $app.Owners.Substring(0, [Math]::Min(16, $app.Owners.Length)) } else { "None" }
            Write-Host ("{0,-29} {1,-37} {2,-2} {3,-2} {4,-24} {5,-17}" -f $name, $appId, $secrets, $certs, $expires, $owners)
        }
        
        if ($appsWithCreds.Count -gt 25) {
            Write-Host "    ... and $($appsWithCreds.Count - 25) more apps with credentials" -ForegroundColor Gray
        }
    }
    
    # ENTERPRISE APPLICATIONS WITH OWNERS
    $spsWithOwners = $sps | Where-Object { $_.OwnerCount -gt 0 }
    if ($spsWithOwners.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host "ENTERPRISE APPLICATIONS WITH OWNERS:" -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        Write-Host ("{0,-34} {1,-14} {2,-34} {3,-31}" -f "Display Name", "Type", "App Permissions", "Owners") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        foreach ($sp in ($spsWithOwners | Select-Object -First 20)) {
            $name = if ($sp.DisplayName) { $sp.DisplayName.Substring(0, [Math]::Min(33, $sp.DisplayName.Length)) } else { "" }
            $spType = if ($sp.Type) { $sp.Type.Substring(0, [Math]::Min(13, $sp.Type.Length)) } else { "" }
            $perms = if ($sp.GrantedAppPermissions) { $sp.GrantedAppPermissions.Substring(0, [Math]::Min(33, $sp.GrantedAppPermissions.Length)) } else { "None" }
            $owners = if ($sp.Owners) { $sp.Owners.Substring(0, [Math]::Min(30, $sp.Owners.Length)) } else { "" }
            Write-Host ("{0,-34} {1,-14} {2,-34} {3,-31}" -f $name, $spType, $perms, $owners)
        }
        
        if ($spsWithOwners.Count -gt 20) {
            Write-Host "    ... and $($spsWithOwners.Count - 20) more" -ForegroundColor Gray
        }
    }
    
    # SERVICE PRINCIPALS WITH GRAPH API PERMISSIONS
    $spsWithGraphPerms = $sps | Where-Object { $_.AppPermissionCount -gt 0 -or $_.DelegatedPermissionCount -gt 0 }
    if ($spsWithGraphPerms.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host "SERVICE PRINCIPALS WITH GRAPH API PERMISSIONS:" -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        Write-Host ("{0,-27} {1,-5} {2,-5} {3,-39} {4,-34}" -f "Display Name", "App#", "Del#", "Application Permissions", "Delegated Permissions") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        # Sort by permission count
        $sortedByPerms = $spsWithGraphPerms | Sort-Object -Property AppPermissionCount -Descending
        
        foreach ($sp in ($sortedByPerms | Select-Object -First 25)) {
            $name = if ($sp.DisplayName) { $sp.DisplayName.Substring(0, [Math]::Min(26, $sp.DisplayName.Length)) } else { "" }
            $appCount = $sp.AppPermissionCount
            $delCount = $sp.DelegatedPermissionCount
            $appPerms = if ($sp.GrantedAppPermissions) { $sp.GrantedAppPermissions.Substring(0, [Math]::Min(38, $sp.GrantedAppPermissions.Length)) } else { "None" }
            $delPerms = if ($sp.DelegatedPermissions) { $sp.DelegatedPermissions.Substring(0, [Math]::Min(33, $sp.DelegatedPermissions.Length)) } else { "None" }
            Write-Host ("{0,-27} {1,-5} {2,-5} {3,-39} {4,-34}" -f $name, $appCount, $delCount, $appPerms, $delPerms)
        }
        
        if ($spsWithGraphPerms.Count -gt 25) {
            Write-Host "    ... and $($spsWithGraphPerms.Count - 25) more with Graph permissions" -ForegroundColor Gray
        }
    }
    
    Write-Host ("-" * 120) -ForegroundColor Gray
}

function Show-StaleAccountsReport {
    param([array]$Users)
    
    Show-SecuritySummary -Data $Users -Title "STALE ACCOUNTS REPORT" -ShowRisk
    
    Write-Host ("{0,-24} {1,-37} {2,-13} {3,-7} {4,-7} {5,-9}" -f "Display Name", "Email/UPN", "Last Sign-In", "Days", "Enabled", "Risk") -ForegroundColor Yellow
    Write-Host ("-" * 110) -ForegroundColor Gray
    
    $riskOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3 }
    $sortedUsers = $Users | Sort-Object { $riskOrder[$_.RiskLevel] }
    
    foreach ($user in $sortedUsers) {
        $displayName = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(23, $user.DisplayName.Length)) } else { "" }
        $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(36, $user.UserPrincipalName.Length)) } elseif ($user.Mail) { $user.Mail.Substring(0, [Math]::Min(36, $user.Mail.Length)) } else { "" }
        $lastSignIn = "$($user.LastSignIn)".Substring(0, [Math]::Min(12, "$($user.LastSignIn)".Length))
        $days = "$($user.DaysInactive)".Substring(0, [Math]::Min(6, "$($user.DaysInactive)".Length))
        $enabled = if ($user.AccountEnabled) { "Yes" } else { "No" }
        $risk = $user.RiskLevel
        
        Write-Host ("{0,-24} {1,-37} {2,-13} {3,-7} {4,-7} {5,-9}" -f $displayName, $email, $lastSignIn, $days, $enabled, $risk)
    }
    Write-Host ("-" * 110) -ForegroundColor Gray
}

function Invoke-FullSecurityAssessment {
    Write-Host ("`n" + ("=" * 70)) -ForegroundColor Cyan
    Write-Host "FULL SECURITY ASSESSMENT" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    $results = @{}
    
    Write-Host "`n[1/6] MFA Status..." -ForegroundColor Yellow
    $results.MFA = Get-UserMFAStatus
    if ($results.MFA.Count -eq 0) {
        $results.MFA = Get-MFARegistrationReport
    }
    
    Write-Host "`n[2/6] Privileged Roles..." -ForegroundColor Yellow
    $results.Privileged = Get-PrivilegedUsers
    
    Write-Host "`n[3/6] Applications..." -ForegroundColor Yellow
    $results.Apps = Get-ApplicationsAndServicePrincipals
    
    Write-Host "`n[4/6] Stale Accounts..." -ForegroundColor Yellow
    $results.Stale = Get-StaleAccounts
    
    Write-Host "`n[5/6] Guest Users..." -ForegroundColor Yellow
    $results.Guests = Get-GuestUsers
    
    Write-Host "`n[6/6] Password Policies..." -ForegroundColor Yellow
    $results.PwdNeverExpires = Get-UsersWithPasswordNeverExpires
    
    # Summary
    Write-Host ("`n" + ("=" * 70)) -ForegroundColor Cyan
    Write-Host "SECURITY ASSESSMENT SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    $mfaNoMFA = ($results.MFA | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $privCritical = ($results.Privileged | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $privHigh = ($results.Privileged | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $highRiskApps = $results.Apps.HighRiskApps.Count
    $staleEnabled = ($results.Stale | Where-Object { $_.AccountEnabled -eq $true }).Count
    
    Write-Host "`n  Users without MFA (HIGH RISK):     $mfaNoMFA" -ForegroundColor $(if ($mfaNoMFA -gt 0) { "Red" } else { "Green" })
    Write-Host "  CRITICAL privileged roles:         $privCritical" -ForegroundColor $(if ($privCritical -gt 0) { "Red" } else { "Green" })
    Write-Host "  HIGH privileged roles:             $privHigh" -ForegroundColor $(if ($privHigh -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  High-risk applications:            $highRiskApps" -ForegroundColor $(if ($highRiskApps -gt 0) { "Red" } else { "Green" })
    Write-Host "  Stale accounts (still enabled):    $staleEnabled" -ForegroundColor $(if ($staleEnabled -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Guest users:                       $($results.Guests.Count)"
    Write-Host "  Password never expires:            $($results.PwdNeverExpires.Count)"
    
    Write-Host ("`n" + ("-" * 70)) -ForegroundColor Gray
    
    return $results
}

# ============================================================================
# POWER PLATFORM ENUMERATION
# ============================================================================

function Get-PowerApps {
    <#
    .SYNOPSIS
        Enumerate Power Apps in the tenant with owner/user information.
    #>
    Write-Host "`n[*] Enumerating Power Apps..." -ForegroundColor Cyan
    
    $allApps = @()
    
    # Get access token for API calls
    $context = Get-MgContext
    if (-not $context) {
        Write-Host "    [-] No Graph context available" -ForegroundColor Yellow
        return $allApps
    }
    
    # Method 1: Try PowerApps Admin API
    Write-Host "    [*] Trying Power Apps Admin API..." -ForegroundColor Gray
    try {
        # Get environments first
        $envUrl = "$($script:PowerAppsApiEndpoint)/providers/Microsoft.PowerApps/scopes/admin/environments?api-version=2016-11-01"
        $envResponse = Invoke-MgGraphRequest -Method GET -Uri $envUrl -ErrorAction Stop
        
        if ($envResponse -and $envResponse.value) {
            $environments = $envResponse.value
            Write-Host "    [+] Found $($environments.Count) Power Platform environments" -ForegroundColor Green
            
            foreach ($env in $environments) {
                $envName = $env.name
                $envDisplay = $env.properties.displayName
                
                # Get apps in this environment
                $appsUrl = "$($script:PowerAppsApiEndpoint)/providers/Microsoft.PowerApps/scopes/admin/environments/$envName/apps?api-version=2016-11-01"
                try {
                    $appsResponse = Invoke-MgGraphRequest -Method GET -Uri $appsUrl -ErrorAction SilentlyContinue
                    
                    if ($appsResponse -and $appsResponse.value) {
                        foreach ($app in $appsResponse.value) {
                            $props = $app.properties
                            
                            $appInfo = [PSCustomObject]@{
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
                                SharedUsers = @()
                                SharedGroups = @()
                                ConnectorCount = if ($props.connectionReferences) { ($props.connectionReferences.PSObject.Properties).Count } else { 0 }
                                Connectors = if ($props.connectionReferences) { ($props.connectionReferences.PSObject.Properties).Name -join ", " } else { "" }
                                Source = "AdminAPI"
                            }
                            
                            # Try to get sharing information
                            $permissionsUrl = "$($script:PowerAppsApiEndpoint)/providers/Microsoft.PowerApps/scopes/admin/environments/$envName/apps/$($app.name)/permissions?api-version=2016-11-01"
                            try {
                                $permsResponse = Invoke-MgGraphRequest -Method GET -Uri $permissionsUrl -ErrorAction SilentlyContinue
                                if ($permsResponse -and $permsResponse.value) {
                                    foreach ($perm in $permsResponse.value) {
                                        $permProps = $perm.properties
                                        $principal = $permProps.principal
                                        
                                        if ($principal.type -eq "User") {
                                            $appInfo.SharedUsers += [PSCustomObject]@{
                                                DisplayName = $principal.displayName
                                                Email = $principal.email
                                                Id = $principal.id
                                                RoleName = $permProps.roleName
                                            }
                                        }
                                        elseif ($principal.type -eq "Group") {
                                            $appInfo.SharedGroups += [PSCustomObject]@{
                                                DisplayName = $principal.displayName
                                                Id = $principal.id
                                                RoleName = $permProps.roleName
                                            }
                                        }
                                    }
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
        Write-Host "    [-] Admin API access denied: $_" -ForegroundColor Yellow
    }
    
    # Method 2: Try user-scoped PowerApps API
    if ($allApps.Count -eq 0) {
        Write-Host "    [*] Trying user-scoped Power Apps API..." -ForegroundColor Gray
        try {
            $userAppsUrl = "$($script:PowerAppsApiEndpoint)/providers/Microsoft.PowerApps/apps?api-version=2016-11-01"
            $userResponse = Invoke-MgGraphRequest -Method GET -Uri $userAppsUrl -ErrorAction Stop
            
            if ($userResponse -and $userResponse.value) {
                foreach ($app in $userResponse.value) {
                    $props = $app.properties
                    
                    $appInfo = [PSCustomObject]@{
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
                        SharedUsers = @()
                        SharedGroups = @()
                        ConnectorCount = if ($props.connectionReferences) { ($props.connectionReferences.PSObject.Properties).Count } else { 0 }
                        Connectors = if ($props.connectionReferences) { ($props.connectionReferences.PSObject.Properties).Name -join ", " } else { "" }
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
            Write-Host "    [-] User API access denied: $_" -ForegroundColor Yellow
        }
    }
    
    # Method 3: Try Graph API for Power Platform metadata
    if ($allApps.Count -eq 0) {
        Write-Host "    [*] Trying Graph API for Power Platform metadata..." -ForegroundColor Gray
        try {
            $graphUrl = "https://graph.microsoft.com/beta/admin/powerPlatform/environments"
            $graphResponse = Invoke-MgGraphRequest -Method GET -Uri $graphUrl -ErrorAction Stop
            
            if ($graphResponse -and $graphResponse.value) {
                Write-Host "    [+] Found $($graphResponse.value.Count) environments via Graph API" -ForegroundColor Green
                foreach ($env in $graphResponse.value) {
                    $appInfo = [PSCustomObject]@{
                        Id = $env.id
                        DisplayName = "Environment: $($env.displayName)"
                        Environment = $env.displayName
                        EnvironmentId = $env.id
                        Owner = "N/A"
                        OwnerEmail = ""
                        OwnerId = ""
                        CreatedTime = $env.createdDateTime
                        LastModifiedTime = ""
                        AppType = "Environment"
                        Status = $env.status
                        SharedUsers = @()
                        SharedGroups = @()
                        ConnectorCount = 0
                        Connectors = ""
                        Source = "GraphAPI"
                    }
                    $allApps += $appInfo
                }
            }
        }
        catch {
            Write-Host "    [-] Graph API Power Platform access denied" -ForegroundColor Yellow
        }
    }
    
    if ($allApps.Count -eq 0) {
        Write-Host "    [!] No Power Apps found or access denied." -ForegroundColor Yellow
        Write-Host "    Note: Requires Power Platform Admin or Environment Maker permissions" -ForegroundColor Gray
    }
    
    return $allApps
}

function Get-PowerAutomateFlows {
    <#
    .SYNOPSIS
        Enumerate Power Automate flows and identify those with sensitive connectors.
    #>
    Write-Host "`n[*] Enumerating Power Automate Flows..." -ForegroundColor Cyan
    
    $allFlows = @()
    
    # Get access token for API calls
    $context = Get-MgContext
    if (-not $context) {
        Write-Host "    [-] No Graph context available" -ForegroundColor Yellow
        return $allFlows
    }
    
    # Method 1: Try Flow Admin API
    Write-Host "    [*] Trying Power Automate Admin API..." -ForegroundColor Gray
    try {
        # Get environments
        $envUrl = "$($script:FlowApiEndpoint)/providers/Microsoft.ProcessSimple/scopes/admin/environments?api-version=2016-11-01"
        $envResponse = Invoke-MgGraphRequest -Method GET -Uri $envUrl -ErrorAction Stop
        
        if ($envResponse -and $envResponse.value) {
            $environments = $envResponse.value
            Write-Host "    [+] Found $($environments.Count) environments" -ForegroundColor Green
            
            foreach ($env in $environments) {
                $envName = $env.name
                $envDisplay = $env.properties.displayName
                
                # Get flows in this environment
                $flowsUrl = "$($script:FlowApiEndpoint)/providers/Microsoft.ProcessSimple/scopes/admin/environments/$envName/flows?api-version=2016-11-01"
                try {
                    $flowsResponse = Invoke-MgGraphRequest -Method GET -Uri $flowsUrl -ErrorAction SilentlyContinue
                    
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
                            
                            $flowInfo = [PSCustomObject]@{
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
                                Connectors = $connectorsUsed
                                SensitiveConnectors = $sensitiveConnectors
                                RiskLevel = $riskLevel
                                HasSensitiveConnector = ($sensitiveConnectors.Count -gt 0)
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
        Write-Host "    [-] Admin API access denied: $_" -ForegroundColor Yellow
    }
    
    # Method 2: Try user-scoped Flow API
    if ($allFlows.Count -eq 0) {
        Write-Host "    [*] Trying user-scoped Power Automate API..." -ForegroundColor Gray
        try {
            $userFlowsUrl = "$($script:FlowApiEndpoint)/providers/Microsoft.ProcessSimple/flows?api-version=2016-11-01"
            $userResponse = Invoke-MgGraphRequest -Method GET -Uri $userFlowsUrl -ErrorAction Stop
            
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
                    
                    $flowInfo = [PSCustomObject]@{
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
                        Connectors = $connectorsUsed
                        SensitiveConnectors = $sensitiveConnectors
                        RiskLevel = $riskLevel
                        HasSensitiveConnector = ($sensitiveConnectors.Count -gt 0)
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
            Write-Host "    [-] User API access denied: $_" -ForegroundColor Yellow
        }
    }
    
    if ($allFlows.Count -eq 0) {
        Write-Host "    [!] No flows found or access denied." -ForegroundColor Yellow
        Write-Host "    Note: Requires Power Automate Admin or flow owner permissions" -ForegroundColor Gray
    }
    else {
        # Summary
        $sensitiveCount = ($allFlows | Where-Object { $_.HasSensitiveConnector }).Count
        if ($sensitiveCount -gt 0) {
            Write-Host "    [!] $sensitiveCount flows have sensitive connectors!" -ForegroundColor Yellow
        }
    }
    
    return $allFlows
}

function Show-PowerAppsReport {
    param([array]$Apps)
    
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Cyan
    Write-Host ("{0,60}" -f "POWER APPS ENUMERATION REPORT") -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Cyan
    
    if ($Apps.Count -eq 0) {
        Write-Host "`n[!] No Power Apps found or access denied." -ForegroundColor Yellow
        return
    }
    
    # Summary
    $uniqueOwners = ($Apps | Where-Object { $_.OwnerEmail } | Select-Object -ExpandProperty OwnerEmail -Unique).Count
    $environments = ($Apps | Where-Object { $_.Environment } | Select-Object -ExpandProperty Environment -Unique).Count
    $sharedApps = ($Apps | Where-Object { $_.SharedUsers.Count -gt 0 -or $_.SharedGroups.Count -gt 0 }).Count
    
    Write-Host "`n📊 SUMMARY:" -ForegroundColor Yellow
    Write-Host "   Total Power Apps: $($Apps.Count)"
    Write-Host "   Unique Environments: $environments"
    Write-Host "   Unique Owners: $uniqueOwners"
    Write-Host "   Shared Apps: $sharedApps"
    
    # Apps by environment
    Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
    Write-Host ("{0,60}" -f "POWER APPS BY ENVIRONMENT") -ForegroundColor Yellow
    Write-Host ("-" * 120) -ForegroundColor Gray
    
    Write-Host ("`n{0,-35} {1,-30} {2,-25} {3,-8} {4,-12}" -f "App Name", "Owner", "Environment", "Conns", "Status") -ForegroundColor Yellow
    Write-Host ("-" * 120) -ForegroundColor Gray
    
    foreach ($app in ($Apps | Select-Object -First 50)) {
        $name = if ($app.DisplayName) { $app.DisplayName.Substring(0, [Math]::Min(34, $app.DisplayName.Length)) } else { "N/A" }
        $owner = if ($app.Owner) { $app.Owner.Substring(0, [Math]::Min(29, $app.Owner.Length)) } elseif ($app.OwnerEmail) { $app.OwnerEmail.Substring(0, [Math]::Min(29, $app.OwnerEmail.Length)) } else { "N/A" }
        $env = if ($app.Environment) { $app.Environment.Substring(0, [Math]::Min(24, $app.Environment.Length)) } else { "N/A" }
        $conns = $app.ConnectorCount
        $status = if ($app.Status) { $app.Status.Substring(0, [Math]::Min(11, $app.Status.Length)) } else { "N/A" }
        
        Write-Host ("{0,-35} {1,-30} {2,-25} {3,-8} {4,-12}" -f $name, $owner, $env, $conns, $status)
    }
    
    if ($Apps.Count -gt 50) {
        Write-Host "    ... and $($Apps.Count - 50) more apps" -ForegroundColor Gray
    }
    
    # Shared apps
    $sharedAppsList = $Apps | Where-Object { $_.SharedUsers.Count -gt 0 -or $_.SharedGroups.Count -gt 0 }
    if ($sharedAppsList.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host ("{0,60}" -f "SHARED POWER APPS (Potential Data Access)") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        Write-Host ("`n{0,-30} {1,-25} {2,-35} {3,-28}" -f "App Name", "Owner", "Shared Users", "Shared Groups") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        foreach ($app in ($sharedAppsList | Select-Object -First 30)) {
            $name = if ($app.DisplayName) { $app.DisplayName.Substring(0, [Math]::Min(29, $app.DisplayName.Length)) } else { "N/A" }
            $owner = if ($app.Owner) { $app.Owner.Substring(0, [Math]::Min(24, $app.Owner.Length)) } else { "N/A" }
            
            $sharedUsers = if ($app.SharedUsers.Count -gt 0) {
                $userNames = ($app.SharedUsers | Select-Object -First 3 | ForEach-Object { $_.DisplayName.Substring(0, [Math]::Min(15, $_.DisplayName.Length)) }) -join ", "
                if ($app.SharedUsers.Count -gt 3) { $userNames += " +$($app.SharedUsers.Count - 3)" }
                $userNames.Substring(0, [Math]::Min(34, $userNames.Length))
            } else { "None" }
            
            $sharedGroups = if ($app.SharedGroups.Count -gt 0) {
                $groupNames = ($app.SharedGroups | Select-Object -First 2 | ForEach-Object { $_.DisplayName.Substring(0, [Math]::Min(12, $_.DisplayName.Length)) }) -join ", "
                if ($app.SharedGroups.Count -gt 2) { $groupNames += " +$($app.SharedGroups.Count - 2)" }
                $groupNames.Substring(0, [Math]::Min(27, $groupNames.Length))
            } else { "None" }
            
            Write-Host ("{0,-30} {1,-25} {2,-35} {3,-28}" -f $name, $owner, $sharedUsers, $sharedGroups)
        }
    }
    
    Write-Host ("-" * 120) -ForegroundColor Gray
    
    # Security Recommendations
    Write-Host "`n💡 SECURITY RECOMMENDATIONS:" -ForegroundColor Yellow
    Write-Host "   • Review app sharing permissions - overly shared apps increase data exposure" -ForegroundColor Gray
    Write-Host "   • Audit apps with HTTP/Custom connectors - potential data exfiltration vectors" -ForegroundColor Gray
    Write-Host "   • Verify app owners still require access" -ForegroundColor Gray
    Write-Host "   • Implement DLP policies to control connector usage" -ForegroundColor Gray
}

function Show-PowerAutomateFlowsReport {
    param([array]$Flows)
    
    Write-Host ("`n" + ("=" * 120)) -ForegroundColor Cyan
    Write-Host ("{0,60}" -f "POWER AUTOMATE FLOWS - SENSITIVE CONNECTOR ANALYSIS") -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Cyan
    
    if ($Flows.Count -eq 0) {
        Write-Host "`n[!] No Power Automate flows found or access denied." -ForegroundColor Yellow
        return
    }
    
    # Summary
    $sensitiveFlows = $Flows | Where-Object { $_.HasSensitiveConnector }
    $criticalFlows = $Flows | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    $highRiskFlows = $Flows | Where-Object { $_.RiskLevel -eq "HIGH" }
    $uniqueOwners = ($Flows | Where-Object { $_.OwnerEmail } | Select-Object -ExpandProperty OwnerEmail -Unique).Count
    
    Write-Host "`n📊 EXECUTIVE SUMMARY:" -ForegroundColor Yellow
    Write-Host "   Total Flows: $($Flows.Count)"
    Write-Host "   ⚠️  Flows with Sensitive Connectors: $($sensitiveFlows.Count)" -ForegroundColor $(if ($sensitiveFlows.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "   🔴 CRITICAL Risk Flows: $($criticalFlows.Count)" -ForegroundColor $(if ($criticalFlows.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "   🟠 HIGH Risk Flows: $($highRiskFlows.Count)" -ForegroundColor $(if ($highRiskFlows.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "   Unique Flow Owners: $uniqueOwners"
    
    # CRITICAL and HIGH risk flows first
    $highCriticalFlows = @($criticalFlows) + @($highRiskFlows)
    if ($highCriticalFlows.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host ("{0,60}" -f "🚨 HIGH/CRITICAL RISK FLOWS (Review Immediately)") -ForegroundColor Red
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        Write-Host ("`n{0,-30} {1,-25} {2,-10} {3,-52}" -f "Flow Name", "Owner", "Risk", "Sensitive Connectors") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        foreach ($flow in ($highCriticalFlows | Select-Object -First 30)) {
            $name = if ($flow.DisplayName) { $flow.DisplayName.Substring(0, [Math]::Min(29, $flow.DisplayName.Length)) } else { "N/A" }
            $owner = if ($flow.Owner) { $flow.Owner.Substring(0, [Math]::Min(24, $flow.Owner.Length)) } elseif ($flow.OwnerEmail) { $flow.OwnerEmail.Substring(0, [Math]::Min(24, $flow.OwnerEmail.Length)) } else { "N/A" }
            $risk = $flow.RiskLevel
            
            $connectors = ($flow.SensitiveConnectors | Select-Object -First 3 | ForEach-Object { "$($_.DisplayName)($($_.Risk))" }) -join ", "
            if ($flow.SensitiveConnectors.Count -gt 3) { $connectors += " +$($flow.SensitiveConnectors.Count - 3)" }
            $connectors = $connectors.Substring(0, [Math]::Min(51, $connectors.Length))
            
            $color = if ($risk -eq "CRITICAL") { "Red" } else { "Yellow" }
            $prefix = if ($risk -eq "CRITICAL") { "!!! " } else { "!  " }
            Write-Host ("{0}{1,-26} {2,-25} {3,-10} {4,-52}" -f $prefix, $name, $owner, $risk, $connectors) -ForegroundColor $color
        }
        
        if ($highCriticalFlows.Count -gt 30) {
            Write-Host "    ... and $($highCriticalFlows.Count - 30) more high-risk flows" -ForegroundColor Gray
        }
    }
    
    # Sensitive connector usage summary
    $connectorUsage = @{}
    foreach ($flow in $Flows) {
        foreach ($conn in $flow.SensitiveConnectors) {
            $connName = $conn.DisplayName
            if (-not $connectorUsage.ContainsKey($connName)) {
                $connectorUsage[$connName] = @{
                    Count = 0
                    Risk = $conn.Risk
                    Category = $conn.Category
                    Flows = @()
                }
            }
            $connectorUsage[$connName].Count++
            $connectorUsage[$connName].Flows += $flow.DisplayName
        }
    }
    
    if ($connectorUsage.Count -gt 0) {
        Write-Host ("`n" + ("-" * 120)) -ForegroundColor Gray
        Write-Host ("{0,60}" -f "SENSITIVE CONNECTOR USAGE SUMMARY") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        Write-Host ("`n{0,-35} {1,-15} {2,-10} {3,-12} {4,-45}" -f "Connector", "Category", "Risk", "Flow Count", "Example Flows") -ForegroundColor Yellow
        Write-Host ("-" * 120) -ForegroundColor Gray
        
        foreach ($entry in ($connectorUsage.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending)) {
            $connName = $entry.Key.Substring(0, [Math]::Min(34, $entry.Key.Length))
            $category = $entry.Value.Category.Substring(0, [Math]::Min(14, $entry.Value.Category.Length))
            $risk = $entry.Value.Risk.Substring(0, [Math]::Min(9, $entry.Value.Risk.Length))
            $count = $entry.Value.Count
            $examples = ($entry.Value.Flows | Select-Object -First 2) -join ", "
            if ($entry.Value.Flows.Count -gt 2) { $examples += " +$($entry.Value.Flows.Count - 2)" }
            $examples = $examples.Substring(0, [Math]::Min(44, $examples.Length))
            
            Write-Host ("{0,-35} {1,-15} {2,-10} {3,-12} {4,-45}" -f $connName, $category, $risk, $count, $examples)
        }
    }
    
    Write-Host ("-" * 120) -ForegroundColor Gray
    
    # Security Recommendations
    Write-Host "`n💡 SECURITY RECOMMENDATIONS:" -ForegroundColor Yellow
    Write-Host "   • Review CRITICAL risk flows immediately - HTTP/Key Vault/Azure AD connectors can exfiltrate data" -ForegroundColor Gray
    Write-Host "   • Audit flows with database connectors - potential for bulk data extraction" -ForegroundColor Gray
    Write-Host "   • Implement DLP policies to block/restrict sensitive connectors" -ForegroundColor Gray
    Write-Host "   • Review flow owners and ensure least privilege access" -ForegroundColor Gray
    Write-Host "   • Monitor flow run history for suspicious activity" -ForegroundColor Gray
    Write-Host "   • Consider implementing approval flows for sensitive operations" -ForegroundColor Gray
}

# ============================================================================
# ENUMERATION ORCHESTRATION
# ============================================================================

function Invoke-BasicEnumeration {
    Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
    Write-Host "BASIC ALTERNATIVE ENUMERATION" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    return @{
        People = Get-PeopleApi
        Managers = Get-ManagerChain
        DirectReports = Get-DirectReportsUsers
        GroupMembers = Get-GroupMembersUsers
    }
}

function Invoke-AdvancedEnumeration {
    Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
    Write-Host "ADVANCED FALLBACK ENUMERATION" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    return @{
        SearchAPI = Get-UsersViaSearchApi
        Calendar = Get-UsersFromCalendar
        Email = Get-UsersFromEmails
        OneDrive = Get-UsersFromOneDrive
        Teams = Get-UsersFromTeams
        Planner = Get-UsersFromPlanner
        SharePoint = Get-UsersFromSharePoint
        AzureRM = Get-UsersFromAzureRM
        Rooms = Get-RoomsAndResources
        Yammer = Get-UsersFromYammer
    }
}

function Invoke-FullEnumeration {
    Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
    Write-Host "FULL ENUMERATION - ALL METHODS" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    $results = @{
        Direct = Get-EntraUsers
    }
    
    $basicResults = Invoke-BasicEnumeration
    $advancedResults = Invoke-AdvancedEnumeration
    
    foreach ($key in $basicResults.Keys) { $results[$key] = $basicResults[$key] }
    foreach ($key in $advancedResults.Keys) { $results[$key] = $advancedResults[$key] }
    
    return $results
}

function Merge-UserResults {
    param([hashtable]$Results)
    
    $seenIds = @{}
    $seenEmails = @{}
    $merged = @()
    
    foreach ($method in $Results.Keys) {
        foreach ($user in $Results[$method]) {
            $userId = $user.Id
            $email = if ($user.Mail) { $user.Mail.ToLower() } elseif ($user.UserPrincipalName) { $user.UserPrincipalName.ToLower() } else { "" }
            
            if ($userId -and $seenIds.ContainsKey($userId)) { continue }
            if (-not $userId -and $email -and $seenEmails.ContainsKey($email)) { continue }
            
            if ($userId) { $seenIds[$userId] = $true }
            if ($email) { $seenEmails[$email] = $true }
            
            if (-not $user.Source) {
                $user | Add-Member -NotePropertyName "Source" -NotePropertyValue $method -Force
            }
            
            $merged += $user
        }
    }
    
    return $merged
}

# ============================================================================
# OUTPUT FUNCTIONS
# ============================================================================

function Show-UserSummary {
    param(
        [array]$Users,
        [switch]$ShowSource
    )

    Write-Host ("`n" + ("=" * 110)) -ForegroundColor Cyan
    Write-Host "                                    AZURE ENTRA ID USERS" -ForegroundColor Cyan
    Write-Host ("=" * 110) -ForegroundColor Cyan

    Write-Host "`nTotal users: $($Users.Count)"

    if ($ShowSource) {
        $sources = $Users | Group-Object -Property Source | Sort-Object -Property Count -Descending
        Write-Host "`nSources:"
        foreach ($source in $sources) {
            Write-Host "  - $($source.Name): $($source.Count)"
        }
    }

    Write-Host ("`n" + ("-" * 110)) -ForegroundColor Gray
    
    if ($ShowSource) {
        Write-Host ("{0,-26} {1,-40} {2,-16} {3,-16}" -f "Display Name", "Email/UPN", "Department", "Source") -ForegroundColor Yellow
    }
    else {
        Write-Host ("{0,-30} {1,-50} {2,-20}" -f "Display Name", "Email/UPN", "Department") -ForegroundColor Yellow
    }
    Write-Host ("-" * 110) -ForegroundColor Gray

    foreach ($user in $Users) {
        $displayName = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(25, $user.DisplayName.Length)) } else { "" }
        $email = if ($user.Mail) { $user.Mail } elseif ($user.UserPrincipalName) { $user.UserPrincipalName } else { "" }
        $email = $email.Substring(0, [Math]::Min(39, $email.Length))
        $dept = if ($user.Department) { $user.Department.Substring(0, [Math]::Min(15, $user.Department.Length)) } else { "" }
        $source = if ($user.Source) { $user.Source.Substring(0, [Math]::Min(15, $user.Source.Length)) } else { "Direct" }

        if ($ShowSource) {
            Write-Host ("{0,-26} {1,-40} {2,-16} {3,-16}" -f $displayName, $email, $dept, $source)
        }
        else {
            Write-Host ("{0,-30} {1,-50} {2,-20}" -f $displayName, $email, $dept)
        }
    }
    Write-Host ("-" * 110) -ForegroundColor Gray
}

function Export-Users {
    param(
        [array]$Users,
        [string]$Path
    )

    $extension = [System.IO.Path]::GetExtension($Path).ToLower()

    try {
        if ($extension -eq ".json") {
            $Users | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
        }
        else {
            if ($extension -ne ".csv") { $Path = "$Path.csv" }
            $Users | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        }
        Write-Host "[+] Exported to: $Path" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Export failed: $_" -ForegroundColor Red
    }
}

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================

# Risk scoring weights for different finding types
$script:RiskWeights = @{
    "CRITICAL" = 100
    "HIGH" = 75
    "MEDIUM" = 50
    "LOW" = 25
    "INFO" = 10
}

$script:FindingCategories = @{
    "mfa" = @{ Name = "MFA Status"; Icon = "🔐"; Description = "Multi-Factor Authentication status for users" }
    "privileged" = @{ Name = "Privileged Users"; Icon = "👑"; Description = "Users with elevated role assignments" }
    "apps" = @{ Name = "Applications"; Icon = "📱"; Description = "App registrations and service principals" }
    "stale" = @{ Name = "Stale Accounts"; Icon = "⏰"; Description = "Accounts with no recent sign-in activity" }
    "guests" = @{ Name = "Guest Users"; Icon = "👤"; Description = "External/guest user accounts" }
    "password_policy" = @{ Name = "Password Policies"; Icon = "🔑"; Description = "Password configuration issues" }
    "sspr" = @{ Name = "SSPR Users"; Icon = "🔄"; Description = "Self-Service Password Reset configuration" }
    "legacy_auth" = @{ Name = "Legacy Auth"; Icon = "⚠️"; Description = "Users with legacy authentication protocols" }
    "app_passwords" = @{ Name = "App Passwords"; Icon = "🔓"; Description = "Users with app passwords configured" }
    "ca_policies" = @{ Name = "CA Policies"; Icon = "📋"; Description = "Conditional Access policy analysis" }
    "ca_exclusions" = @{ Name = "CA Exclusions"; Icon = "🚫"; Description = "Users excluded from CA policies" }
    "mfa_gaps" = @{ Name = "MFA Gaps"; Icon = "🕳️"; Description = "Missing MFA enforcement scenarios" }
    "devices" = @{ Name = "Devices"; Icon = "💻"; Description = "Registered and managed devices" }
    "non_compliant" = @{ Name = "Non-Compliant"; Icon = "❌"; Description = "Devices failing compliance policies" }
    "byod" = @{ Name = "BYOD Devices"; Icon = "📲"; Description = "Personal/BYOD device enrollments" }
    "intune" = @{ Name = "Intune"; Icon = "🛡️"; Description = "Intune/Endpoint Manager configuration" }
    "admin_units" = @{ Name = "Admin Units"; Icon = "🏢"; Description = "Administrative unit assignments" }
    "licenses" = @{ Name = "Licenses"; Icon = "📜"; Description = "License assignments and privileged SKUs" }
    "sync_status" = @{ Name = "Directory Sync"; Icon = "🔄"; Description = "On-premises sync status" }
    "attack_paths" = @{ Name = "Attack Paths"; Icon = "🎯"; Description = "Privilege escalation paths" }
    "lateral_movement" = @{ Name = "Lateral Movement"; Icon = "↔️"; Description = "Lateral movement opportunities" }
    "power_platform" = @{ Name = "Power Platform"; Icon = "⚡"; Description = "Power Apps and Power Automate analysis" }
    "users" = @{ Name = "User Enumeration"; Icon = "👥"; Description = "Enumerated user accounts" }
}

function Get-RiskScore {
    <#
    .SYNOPSIS
        Calculate overall risk score based on findings.
    #>
    param(
        [hashtable]$Findings
    )
    
    $totalScore = 0
    $maxPossible = 0
    $breakdown = @()
    
    foreach ($category in $Findings.Keys) {
        $data = $Findings[$category]
        if ($null -eq $data) { continue }
        
        $categoryInfo = $script:FindingCategories[$category]
        if (-not $categoryInfo) {
            $categoryInfo = @{ Name = $category; Icon = "📊"; Description = "" }
        }
        
        # Handle different data types
        $items = @()
        if ($data -is [array]) {
            $items = $data
        }
        elseif ($data -is [hashtable]) {
            # For nested structures like apps_data
            foreach ($key in $data.Keys) {
                if ($data[$key] -is [array]) {
                    $items += $data[$key]
                }
            }
        }
        
        if ($items.Count -eq 0) { continue }
        
        $criticalCount = 0
        $highCount = 0
        $mediumCount = 0
        $lowCount = 0
        
        foreach ($item in $items) {
            if ($item -is [hashtable] -or $item -is [PSCustomObject]) {
                $risk = if ($item.RiskLevel) { $item.RiskLevel.ToString().ToUpper() } 
                        elseif ($item.riskLevel) { $item.riskLevel.ToString().ToUpper() }
                        elseif ($item.Risk) { $item.Risk.ToString().ToUpper() }
                        else { "INFO" }
                
                switch ($risk) {
                    "CRITICAL" { $criticalCount++ }
                    "HIGH" { $highCount++ }
                    "MEDIUM" { $mediumCount++ }
                    "LOW" { $lowCount++ }
                }
            }
        }
        
        $categoryScore = (
            $criticalCount * $script:RiskWeights["CRITICAL"] +
            $highCount * $script:RiskWeights["HIGH"] +
            $mediumCount * $script:RiskWeights["MEDIUM"] +
            $lowCount * $script:RiskWeights["LOW"]
        )
        
        $categoryMax = $items.Count * $script:RiskWeights["CRITICAL"]
        $maxPossible += $categoryMax
        $totalScore += $categoryScore
        
        $breakdown += @{
            Category = $category
            Name = $categoryInfo.Name
            Icon = $categoryInfo.Icon
            TotalItems = $items.Count
            Critical = $criticalCount
            High = $highCount
            Medium = $mediumCount
            Low = $lowCount
            Score = $categoryScore
            MaxScore = $categoryMax
        }
    }
    
    # Calculate percentage score
    $riskPercentage = if ($maxPossible -gt 0) { [math]::Round(($totalScore / $maxPossible) * 100, 1) } else { 0 }
    
    # Determine overall rating
    if ($riskPercentage -ge 75) {
        $rating = "CRITICAL"
        $ratingColor = "#dc3545"
    }
    elseif ($riskPercentage -ge 50) {
        $rating = "HIGH"
        $ratingColor = "#fd7e14"
    }
    elseif ($riskPercentage -ge 25) {
        $rating = "MEDIUM"
        $ratingColor = "#ffc107"
    }
    elseif ($riskPercentage -gt 0) {
        $rating = "LOW"
        $ratingColor = "#28a745"
    }
    else {
        $rating = "MINIMAL"
        $ratingColor = "#17a2b8"
    }
    
    return @{
        Score = $riskPercentage
        Rating = $rating
        RatingColor = $ratingColor
        TotalRawScore = $totalScore
        MaxPossible = $maxPossible
        Breakdown = $breakdown
    }
}

function Get-ExecutiveSummaryHtml {
    <#
    .SYNOPSIS
        Generate executive summary section for the HTML report.
    #>
    param(
        [hashtable]$Findings,
        [hashtable]$RiskScore,
        [hashtable]$TenantInfo
    )
    
    # Count key metrics
    $totalUsers = if ($Findings["users"]) { $Findings["users"].Count } else { 0 }
    $usersWithoutMfa = if ($Findings["mfa"]) { 
        ($Findings["mfa"] | Where-Object { -not $_.MfaEnabled -and -not $_.mfaEnabled }).Count 
    } else { 0 }
    $privilegedUsers = if ($Findings["privileged"]) { $Findings["privileged"].Count } else { 0 }
    
    $highRiskApps = 0
    if ($Findings["apps"] -and $Findings["apps"]["HighRiskApps"]) {
        $highRiskApps = $Findings["apps"]["HighRiskApps"].Count
    }
    
    $staleAccounts = if ($Findings["stale"]) { $Findings["stale"].Count } else { 0 }
    $guestUsers = if ($Findings["guests"]) { $Findings["guests"].Count } else { 0 }
    
    # Count critical/high findings
    $criticalFindings = 0
    $highFindings = 0
    foreach ($category in $Findings.Keys) {
        $data = $Findings[$category]
        if ($data -is [array]) {
            foreach ($item in $data) {
                $risk = if ($item.RiskLevel) { $item.RiskLevel.ToString().ToUpper() }
                        elseif ($item.riskLevel) { $item.riskLevel.ToString().ToUpper() }
                        else { "" }
                if ($risk -eq "CRITICAL") { $criticalFindings++ }
                elseif ($risk -eq "HIGH") { $highFindings++ }
            }
        }
    }
    
    $tenantName = if ($TenantInfo -and $TenantInfo.DisplayName) { $TenantInfo.DisplayName } else { "Unknown Tenant" }
    $tenantId = if ($TenantInfo -and $TenantInfo.TenantId) { $TenantInfo.TenantId } else { "N/A" }
    
    # Build key findings list
    $keyFindings = @()
    if ($usersWithoutMfa -gt 0) {
        $keyFindings += "<li><span class='badge bg-danger'>CRITICAL</span> $usersWithoutMfa users without MFA enabled</li>"
    }
    if ($highRiskApps -gt 0) {
        $keyFindings += "<li><span class='badge bg-danger'>HIGH</span> $highRiskApps high-risk application registrations</li>"
    }
    if ($privilegedUsers -gt 0) {
        $keyFindings += "<li><span class='badge bg-warning text-dark'>MEDIUM</span> $privilegedUsers users with privileged roles</li>"
    }
    if ($staleAccounts -gt 0) {
        $keyFindings += "<li><span class='badge bg-warning text-dark'>MEDIUM</span> $staleAccounts stale accounts (no recent sign-in)</li>"
    }
    if ($guestUsers -gt 0) {
        $keyFindings += "<li><span class='badge bg-info'>INFO</span> $guestUsers guest/external users</li>"
    }
    if ($keyFindings.Count -eq 0) {
        $keyFindings += "<li><span class='badge bg-success'>GOOD</span> No critical issues identified</li>"
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    return @"
    <div class="executive-summary">
        <div class="row">
            <div class="col-md-6">
                <h3>📊 Assessment Overview</h3>
                <table class="table table-sm">
                    <tr><th>Tenant Name</th><td>$tenantName</td></tr>
                    <tr><th>Tenant ID</th><td><code>$tenantId</code></td></tr>
                    <tr><th>Assessment Date</th><td>$timestamp</td></tr>
                    <tr><th>Total Users Analyzed</th><td>$totalUsers</td></tr>
                    <tr><th>Total Findings</th><td>$($criticalFindings + $highFindings) critical/high</td></tr>
                </table>
            </div>
            <div class="col-md-6">
                <h3>🎯 Risk Score</h3>
                <div class="risk-score-container">
                    <div class="risk-gauge" style="--score: $($RiskScore.Score); --color: $($RiskScore.RatingColor);">
                        <div class="risk-value">$($RiskScore.Score)</div>
                        <div class="risk-label">$($RiskScore.Rating)</div>
                    </div>
                </div>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-12">
                <h3>🔑 Key Findings</h3>
                <ul class="key-findings-list">
                    $($keyFindings -join "`n                    ")
                </ul>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-md-4">
                <div class="metric-card critical">
                    <div class="metric-value">$criticalFindings</div>
                    <div class="metric-label">Critical Findings</div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="metric-card high">
                    <div class="metric-value">$highFindings</div>
                    <div class="metric-label">High Findings</div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="metric-card info">
                    <div class="metric-value">$totalUsers</div>
                    <div class="metric-label">Users Analyzed</div>
                </div>
            </div>
        </div>
    </div>
"@
}

function Get-FindingsTableHtml {
    <#
    .SYNOPSIS
        Generate an HTML table for a specific category of findings.
    #>
    param(
        [string]$Category,
        [array]$Data,
        [string]$Title
    )
    
    if (-not $Data -or $Data.Count -eq 0) { return "" }
    
    $categoryInfo = $script:FindingCategories[$Category]
    if (-not $categoryInfo) {
        $categoryInfo = @{ Name = $Category; Icon = "📊"; Description = "" }
    }
    $displayTitle = if ($Title) { $Title } else { $categoryInfo.Name }
    
    # Get all unique keys from data
    $allKeys = @{}
    foreach ($item in ($Data | Select-Object -First 100)) {
        if ($item -is [PSCustomObject]) {
            $item.PSObject.Properties | ForEach-Object { $allKeys[$_.Name] = $true }
        }
        elseif ($item -is [hashtable]) {
            $item.Keys | ForEach-Object { $allKeys[$_] = $true }
        }
    }
    
    # Priority columns
    $priorityColumns = @("DisplayName", "displayName", "UserPrincipalName", "userPrincipalName", 
                         "Mail", "mail", "RiskLevel", "riskLevel", "Risk", "risk",
                         "RoleName", "roleName", "AppDisplayName", "appDisplayName", 
                         "Name", "name", "Id", "id")
    
    $columns = @()
    foreach ($col in $priorityColumns) {
        if ($allKeys.ContainsKey($col)) {
            $columns += $col
            $allKeys.Remove($col)
        }
    }
    
    # Add remaining columns (limit to 8 total)
    $remaining = @($allKeys.Keys | Select-Object -First ([Math]::Max(0, 8 - $columns.Count)))
    $columns += $remaining
    
    # Count risk levels
    $criticalCount = ($Data | Where-Object { 
        ($_.RiskLevel -eq "CRITICAL") -or ($_.riskLevel -eq "CRITICAL") -or ($_.Risk -eq "CRITICAL")
    }).Count
    $highCount = ($Data | Where-Object { 
        ($_.RiskLevel -eq "HIGH") -or ($_.riskLevel -eq "HIGH") -or ($_.Risk -eq "HIGH")
    }).Count
    $mediumCount = ($Data | Where-Object { 
        ($_.RiskLevel -eq "MEDIUM") -or ($_.riskLevel -eq "MEDIUM") -or ($_.Risk -eq "MEDIUM")
    }).Count
    $lowCount = ($Data | Where-Object { 
        ($_.RiskLevel -eq "LOW") -or ($_.riskLevel -eq "LOW") -or ($_.Risk -eq "LOW")
    }).Count
    
    # Build table header
    $headerCells = ($columns | ForEach-Object { 
        $colName = $_ -replace '([a-z])([A-Z])', '$1 $2'
        "<th>$colName</th>" 
    }) -join ""
    
    # Build table rows
    $rows = @()
    foreach ($item in $Data) {
        $risk = ""
        if ($item -is [PSCustomObject]) {
            $risk = if ($item.RiskLevel) { $item.RiskLevel.ToString().ToUpper() }
                    elseif ($item.riskLevel) { $item.riskLevel.ToString().ToUpper() }
                    elseif ($item.Risk) { $item.Risk.ToString().ToUpper() }
                    else { "INFO" }
        }
        elseif ($item -is [hashtable]) {
            $risk = if ($item["RiskLevel"]) { $item["RiskLevel"].ToString().ToUpper() }
                    elseif ($item["riskLevel"]) { $item["riskLevel"].ToString().ToUpper() }
                    elseif ($item["Risk"]) { $item["Risk"].ToString().ToUpper() }
                    else { "INFO" }
        }
        
        $riskClass = "risk-$($risk.ToLower())"
        
        $cells = @()
        foreach ($col in $columns) {
            $value = ""
            if ($item -is [PSCustomObject]) {
                $value = $item.$col
            }
            elseif ($item -is [hashtable]) {
                $value = $item[$col]
            }
            
            if ($null -eq $value) { $value = "-" }
            elseif ($value -is [array] -or $value -is [hashtable]) {
                $jsonVal = $value | ConvertTo-Json -Compress
                $value = if ($jsonVal.Length -gt 50) { $jsonVal.Substring(0, 47) + "..." } else { $jsonVal }
            }
            elseif ($value -is [bool]) {
                $value = if ($value) { "✓" } else { "✗" }
            }
            else {
                $value = $value.ToString()
                if ($value.Length -gt 50) { $value = $value.Substring(0, 47) + "..." }
            }
            
            # Special formatting for risk columns
            if ($col -in @("RiskLevel", "riskLevel", "Risk", "risk")) {
                $badgeClass = switch ($value.ToUpper()) {
                    "CRITICAL" { "bg-danger" }
                    "HIGH" { "bg-warning text-dark" }
                    "MEDIUM" { "bg-info" }
                    "LOW" { "bg-success" }
                    default { "bg-secondary" }
                }
                $value = "<span class='badge $badgeClass'>$value</span>"
            }
            
            # Escape HTML
            $value = $value -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'
            # But preserve badge HTML
            $value = $value -replace '&lt;span', '<span' -replace '&lt;/span&gt;', '</span>' -replace "&apos;", "'"
            
            $cells += "<td>$value</td>"
        }
        
        $rows += "<tr class='$riskClass'>$($cells -join '')</tr>"
    }
    
    return @"
    <div class="findings-section" id="section-$Category">
        <div class="section-header">
            <h3>$($categoryInfo.Icon) $displayTitle</h3>
            <p class="text-muted">$($categoryInfo.Description)</p>
            <div class="risk-badges">
                <span class="badge bg-danger">$criticalCount Critical</span>
                <span class="badge bg-warning text-dark">$highCount High</span>
                <span class="badge bg-info">$mediumCount Medium</span>
                <span class="badge bg-success">$lowCount Low</span>
                <span class="badge bg-secondary">$($Data.Count) Total</span>
            </div>
        </div>
        <div class="table-responsive">
            <table class="table table-striped table-hover findings-table">
                <thead>
                    <tr>$headerCells</tr>
                </thead>
                <tbody>
                    $($rows -join "`n                    ")
                </tbody>
            </table>
        </div>
    </div>
"@
}

function Get-ChartsSectionHtml {
    <#
    .SYNOPSIS
        Generate the charts section for the HTML report.
    #>
    param(
        [hashtable]$Findings,
        [hashtable]$RiskScore
    )
    
    $breakdown = $RiskScore.Breakdown
    
    $categoryLabels = ($breakdown | ForEach-Object { "`"$($_.Name)`"" }) -join ", "
    $criticalData = ($breakdown | ForEach-Object { $_.Critical }) -join ", "
    $highData = ($breakdown | ForEach-Object { $_.High }) -join ", "
    $mediumData = ($breakdown | ForEach-Object { $_.Medium }) -join ", "
    $lowData = ($breakdown | ForEach-Object { $_.Low }) -join ", "
    $totalItemsData = ($breakdown | ForEach-Object { $_.TotalItems }) -join ", "
    
    $totalCritical = ($breakdown | ForEach-Object { $_.Critical } | Measure-Object -Sum).Sum
    $totalHigh = ($breakdown | ForEach-Object { $_.High } | Measure-Object -Sum).Sum
    $totalMedium = ($breakdown | ForEach-Object { $_.Medium } | Measure-Object -Sum).Sum
    $totalLow = ($breakdown | ForEach-Object { $_.Low } | Measure-Object -Sum).Sum
    
    return @"
    <div class="charts-section">
        <div class="row">
            <div class="col-md-6">
                <div class="chart-container">
                    <h4>Risk Distribution by Category</h4>
                    <canvas id="riskDistributionChart"></canvas>
                </div>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <h4>Overall Risk Breakdown</h4>
                    <canvas id="riskPieChart"></canvas>
                </div>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-12">
                <div class="chart-container">
                    <h4>Findings by Category</h4>
                    <canvas id="findingsByCategoryChart"></canvas>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Risk Distribution Stacked Bar Chart
        const ctx1 = document.getElementById('riskDistributionChart').getContext('2d');
        new Chart(ctx1, {
            type: 'bar',
            data: {
                labels: [$categoryLabels],
                datasets: [
                    {
                        label: 'Critical',
                        data: [$criticalData],
                        backgroundColor: '#dc3545',
                        borderColor: '#dc3545',
                        borderWidth: 1
                    },
                    {
                        label: 'High',
                        data: [$highData],
                        backgroundColor: '#fd7e14',
                        borderColor: '#fd7e14',
                        borderWidth: 1
                    },
                    {
                        label: 'Medium',
                        data: [$mediumData],
                        backgroundColor: '#ffc107',
                        borderColor: '#ffc107',
                        borderWidth: 1
                    },
                    {
                        label: 'Low',
                        data: [$lowData],
                        backgroundColor: '#28a745',
                        borderColor: '#28a745',
                        borderWidth: 1
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    x: { stacked: true },
                    y: { stacked: true, beginAtZero: true }
                },
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
        
        // Risk Pie Chart
        const ctx2 = document.getElementById('riskPieChart').getContext('2d');
        new Chart(ctx2, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [$totalCritical, $totalHigh, $totalMedium, $totalLow],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
                    borderWidth: 2,
                    borderColor: '#1e1e2e'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
        
        // Findings by Category Bar Chart
        const ctx3 = document.getElementById('findingsByCategoryChart').getContext('2d');
        new Chart(ctx3, {
            type: 'bar',
            data: {
                labels: [$categoryLabels],
                datasets: [{
                    label: 'Total Findings',
                    data: [$totalItemsData],
                    backgroundColor: 'rgba(147, 112, 219, 0.7)',
                    borderColor: '#9370db',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    </script>
"@
}

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Generate an interactive HTML report with charts, risk scoring, and executive summary.
    
    .PARAMETER Findings
        Hashtable containing all assessment findings.
    
    .PARAMETER Filename
        Output filename for the HTML report.
    
    .PARAMETER TenantInfo
        Optional tenant information hashtable.
    
    .PARAMETER Title
        Report title.
    #>
    param(
        [hashtable]$Findings,
        [string]$Filename = "evilmist_report.html",
        [hashtable]$TenantInfo = $null,
        [string]$Title = "EvilMist Security Assessment Report"
    )
    
    # Calculate risk score
    $riskScore = Get-RiskScore -Findings $Findings
    
    # Generate navigation items and content sections
    $navItems = @()
    $contentSections = @()
    
    foreach ($category in $Findings.Keys) {
        $data = $Findings[$category]
        if (-not $data) { continue }
        
        $categoryInfo = $script:FindingCategories[$category]
        if (-not $categoryInfo) {
            $categoryInfo = @{ Name = $category; Icon = "📊"; Description = "" }
        }
        
        # Handle nested dict structures (like apps_data)
        if ($data -is [hashtable] -and $category -eq "apps") {
            $allApps = @()
            if ($data["Applications"]) {
                foreach ($app in $data["Applications"]) {
                    if ($app -is [hashtable]) { $app["Type"] = "Application" }
                    elseif ($app -is [PSCustomObject]) { $app | Add-Member -NotePropertyName "Type" -NotePropertyValue "Application" -Force }
                    $allApps += $app
                }
            }
            if ($data["ServicePrincipals"]) {
                foreach ($sp in $data["ServicePrincipals"]) {
                    if ($sp -is [hashtable]) { $sp["Type"] = "ServicePrincipal" }
                    elseif ($sp -is [PSCustomObject]) { $sp | Add-Member -NotePropertyName "Type" -NotePropertyValue "ServicePrincipal" -Force }
                    $allApps += $sp
                }
            }
            if ($data["HighRiskApps"]) {
                foreach ($hra in $data["HighRiskApps"]) {
                    if ($hra -is [hashtable]) { $hra["Type"] = "HighRiskApp" }
                    elseif ($hra -is [PSCustomObject]) { $hra | Add-Member -NotePropertyName "Type" -NotePropertyValue "HighRiskApp" -Force }
                    $allApps += $hra
                }
            }
            $data = $allApps
        }
        
        if ($data -is [array] -and $data.Count -gt 0) {
            $navItems += @"
                <a class="nav-link" href="#section-$category">
                    $($categoryInfo.Icon) $($categoryInfo.Name)
                    <span class="badge bg-secondary">$($data.Count)</span>
                </a>
"@
            $contentSections += Get-FindingsTableHtml -Category $category -Data $data
        }
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # HTML Template with modern dark theme
    $htmlTemplate = @"
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-purple: #8957e5;
            --accent-blue: #58a6ff;
            --border-color: #30363d;
        }
        
        body {
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        }
        
        .navbar {
            background: var(--bg-secondary) !important;
            border-bottom: 1px solid var(--border-color);
        }
        
        .sidebar {
            position: fixed;
            top: 56px;
            left: 0;
            bottom: 0;
            width: 280px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            overflow-y: auto;
            padding: 1rem;
        }
        
        .sidebar .nav-link {
            color: var(--text-secondary);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            margin-bottom: 0.25rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .sidebar .nav-link:hover {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }
        
        .main-content {
            margin-left: 280px;
            padding: 2rem;
        }
        
        .executive-summary {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }
        
        .risk-score-container {
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 1rem;
        }
        
        .risk-gauge {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: conic-gradient(
                var(--color) calc(var(--score) * 3.6deg),
                var(--bg-tertiary) calc(var(--score) * 3.6deg)
            );
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            position: relative;
        }
        
        .risk-gauge::before {
            content: '';
            position: absolute;
            width: 120px;
            height: 120px;
            background: var(--bg-secondary);
            border-radius: 50%;
        }
        
        .risk-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--color);
            position: relative;
            z-index: 1;
        }
        
        .risk-label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            position: relative;
            z-index: 1;
        }
        
        .metric-card {
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid var(--border-color);
        }
        
        .metric-card.critical {
            border-left: 4px solid #dc3545;
        }
        
        .metric-card.high {
            border-left: 4px solid #fd7e14;
        }
        
        .metric-card.info {
            border-left: 4px solid #58a6ff;
        }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--text-primary);
        }
        
        .metric-label {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }
        
        .key-findings-list {
            list-style: none;
            padding: 0;
        }
        
        .key-findings-list li {
            padding: 0.75rem;
            background: var(--bg-tertiary);
            border-radius: 6px;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .findings-section {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }
        
        .section-header {
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .section-header h3 {
            margin-bottom: 0.5rem;
        }
        
        .risk-badges {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        
        .findings-table {
            font-size: 0.875rem;
        }
        
        .findings-table th {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            white-space: nowrap;
        }
        
        .findings-table td {
            color: var(--text-secondary);
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .risk-critical {
            border-left: 3px solid #dc3545;
        }
        
        .risk-high {
            border-left: 3px solid #fd7e14;
        }
        
        .risk-medium {
            border-left: 3px solid #ffc107;
        }
        
        .risk-low {
            border-left: 3px solid #28a745;
        }
        
        .chart-container {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--border-color);
        }
        
        .chart-container h4 {
            margin-bottom: 1rem;
            color: var(--text-primary);
        }
        
        .charts-section {
            margin-bottom: 2rem;
        }
        
        .table-responsive {
            max-height: 500px;
            overflow-y: auto;
        }
        
        .badge {
            font-weight: 500;
        }
        
        @media print {
            .sidebar { display: none; }
            .main-content { margin-left: 0; }
        }
        
        @media (max-width: 992px) {
            .sidebar { display: none; }
            .main-content { margin-left: 0; }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark fixed-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <strong>🔮 EvilMist</strong> Security Assessment
            </a>
            <span class="navbar-text">
                Generated: $timestamp
            </span>
        </div>
    </nav>
    
    <div class="sidebar">
        <h6 class="text-uppercase text-muted mb-3">Navigation</h6>
        <nav class="nav flex-column">
            <a class="nav-link" href="#executive-summary">📊 Executive Summary</a>
            <a class="nav-link" href="#charts">📈 Charts & Analytics</a>
            <hr class="my-2">
            <h6 class="text-uppercase text-muted mb-2">Findings</h6>
            $($navItems -join "`n            ")
        </nav>
    </div>
    
    <main class="main-content" style="margin-top: 56px;">
        <section id="executive-summary">
            <h2 class="mb-4">Executive Summary</h2>
            $(Get-ExecutiveSummaryHtml -Findings $Findings -RiskScore $riskScore -TenantInfo $TenantInfo)
        </section>
        
        <section id="charts" class="mt-5">
            <h2 class="mb-4">Charts & Analytics</h2>
            $(Get-ChartsSectionHtml -Findings $Findings -RiskScore $riskScore)
        </section>
        
        <section id="detailed-findings" class="mt-5">
            <h2 class="mb-4">Detailed Findings</h2>
            $($contentSections -join "`n            ")
        </section>
        
        <footer class="mt-5 pt-4 border-top text-center text-muted">
            <p>Generated by <strong>EvilMist</strong> - Azure Entra ID Security Assessment Toolkit</p>
            <p>© 2025 Logisek - <a href="https://github.com/Logisek/EvilMist" target="_blank">GitHub</a></p>
        </footer>
    </main>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"@
    
    # Write the HTML file
    try {
        $htmlTemplate | Out-File -FilePath $Filename -Encoding UTF8
        Write-Host "[+] HTML report generated: $Filename" -ForegroundColor Green
        Write-Host "    Risk Score: $($riskScore.Score) ($($riskScore.Rating))" -ForegroundColor Cyan
        Write-Host "    Categories: $($riskScore.Breakdown.Count)" -ForegroundColor Gray
        
        # Offer to open in browser
        $openBrowser = Read-Host "`nOpen report in browser? (y/n) [y]"
        if ($openBrowser -ne 'n') {
            $fullPath = (Resolve-Path $Filename).Path
            Start-Process $fullPath
        }
    }
    catch {
        Write-Host "[!] Failed to generate report: $_" -ForegroundColor Red
    }
}

# ============================================================================
# BLOODHOUND / AZUREHOUND EXPORT FUNCTIONS
# ============================================================================

$script:BloodHoundVersion = 5  # BloodHound CE v5 JSON format

function Get-TenantInfo {
    <#
    .SYNOPSIS
        Get tenant/organization information for BloodHound metadata.
    #>
    
    $tenantInfo = @{
        TenantId = ""
        DisplayName = ""
        VerifiedDomains = @()
        DefaultDomain = ""
    }
    
    try {
        $org = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization" -ErrorAction Stop
        
        if ($org -and $org.value -and $org.value.Count -gt 0) {
            $orgData = $org.value[0]
            $tenantInfo.TenantId = $orgData.id
            $tenantInfo.DisplayName = $orgData.displayName
            
            foreach ($domain in $orgData.verifiedDomains) {
                if ($domain.name) {
                    $tenantInfo.VerifiedDomains += $domain.name
                    if ($domain.isDefault) {
                        $tenantInfo.DefaultDomain = $domain.name
                    }
                }
            }
        }
    }
    catch {
        Write-Host "[!] Error getting tenant info: $_" -ForegroundColor Yellow
        # Try to get tenant ID from context
        try {
            $context = Get-MgContext
            if ($context -and $context.TenantId) {
                $tenantInfo.TenantId = $context.TenantId
            }
        }
        catch { }
    }
    
    return $tenantInfo
}

function Convert-UsersToBloodHound {
    <#
    .SYNOPSIS
        Convert enumerated users to AzureHound-compatible format.
    #>
    param(
        [array]$Users,
        [string]$TenantId
    )
    
    $bhUsers = @()
    
    foreach ($user in $Users) {
        $userId = if ($user.Id) { $user.Id } elseif ($user.id) { $user.id } else { $null }
        if (-not $userId) { continue }
        
        $objectId = if ($TenantId) { "$userId@$TenantId" } else { $userId }
        
        $bhUser = @{
            ObjectId = $userId
            ObjectIdentifier = $objectId
            Kind = "AZUser"
            DisplayName = if ($user.DisplayName) { $user.DisplayName } elseif ($user.displayName) { $user.displayName } else { "" }
            UserPrincipalName = if ($user.UserPrincipalName) { $user.UserPrincipalName } elseif ($user.userPrincipalName) { $user.userPrincipalName } else { "" }
            Mail = if ($user.Mail) { $user.Mail } elseif ($user.mail) { $user.mail } else { "" }
            TenantId = $TenantId
            OnPremisesSecurityIdentifier = if ($user.OnPremisesSecurityIdentifier) { $user.OnPremisesSecurityIdentifier } else { "" }
            OnPremisesSamAccountName = if ($user.OnPremisesSamAccountName) { $user.OnPremisesSamAccountName } else { "" }
            OnPremisesSyncEnabled = if ($null -ne $user.OnPremisesSyncEnabled) { $user.OnPremisesSyncEnabled } else { $false }
            AccountEnabled = if ($null -ne $user.AccountEnabled) { $user.AccountEnabled } elseif ($null -ne $user.accountEnabled) { $user.accountEnabled } else { $true }
            UserType = if ($user.UserType) { $user.UserType } elseif ($user.userType) { $user.userType } else { "Member" }
            CreatedDateTime = if ($user.CreatedDateTime) { $user.CreatedDateTime.ToString() } else { "" }
            JobTitle = if ($user.JobTitle) { $user.JobTitle } elseif ($user.jobTitle) { $user.jobTitle } else { "" }
            Department = if ($user.Department) { $user.Department } elseif ($user.department) { $user.department } else { "" }
            Properties = @{
                displayname = if ($user.DisplayName) { $user.DisplayName } elseif ($user.displayName) { $user.displayName } else { "" }
                userprincipalname = if ($user.UserPrincipalName) { $user.UserPrincipalName } elseif ($user.userPrincipalName) { $user.userPrincipalName } else { "" }
                mail = if ($user.Mail) { $user.Mail } elseif ($user.mail) { $user.mail } else { "" }
                enabled = if ($null -ne $user.AccountEnabled) { $user.AccountEnabled } elseif ($null -ne $user.accountEnabled) { $user.accountEnabled } else { $true }
                usertype = if ($user.UserType) { $user.UserType } elseif ($user.userType) { $user.userType } else { "Member" }
                tenantid = $TenantId
                onpremisessyncenabled = if ($null -ne $user.OnPremisesSyncEnabled) { $user.OnPremisesSyncEnabled } else { $false }
            }
        }
        
        $bhUsers += $bhUser
    }
    
    return $bhUsers
}

function Convert-GroupsToBloodHound {
    <#
    .SYNOPSIS
        Fetch and convert groups to AzureHound-compatible format.
    #>
    param(
        [string]$TenantId
    )
    
    $bhGroups = @()
    $membershipEdges = @()
    
    Write-Host "[*] Collecting groups for BloodHound export..." -ForegroundColor Cyan
    
    try {
        $groups = Get-MgGroup -All -Property Id,DisplayName,Description,SecurityEnabled,MailEnabled,GroupTypes,IsAssignableToRole,OnPremisesSecurityIdentifier,OnPremisesSyncEnabled -ErrorAction Stop
        
        foreach ($group in $groups) {
            $groupId = $group.Id
            if (-not $groupId) { continue }
            
            $objectId = if ($TenantId) { "$groupId@$TenantId" } else { $groupId }
            
            # Determine group type
            $isDynamic = $group.GroupTypes -contains "DynamicMembership"
            $isUnified = $group.GroupTypes -contains "Unified"
            
            $bhGroup = @{
                ObjectId = $groupId
                ObjectIdentifier = $objectId
                Kind = "AZGroup"
                DisplayName = $group.DisplayName
                Description = $group.Description
                TenantId = $TenantId
                SecurityEnabled = $group.SecurityEnabled
                MailEnabled = $group.MailEnabled
                IsAssignableToRole = $group.IsAssignableToRole
                OnPremisesSecurityIdentifier = $group.OnPremisesSecurityIdentifier
                OnPremisesSyncEnabled = $group.OnPremisesSyncEnabled
                IsDynamicMembership = $isDynamic
                IsUnified = $isUnified
                Properties = @{
                    displayname = $group.DisplayName
                    description = $group.Description
                    securityenabled = $group.SecurityEnabled
                    isassignabletorole = $group.IsAssignableToRole
                    tenantid = $TenantId
                }
            }
            
            $bhGroups += $bhGroup
            
            # Get group members for relationship edges
            try {
                $members = Get-MgGroupMember -GroupId $groupId -Property Id,DisplayName -ErrorAction SilentlyContinue
                
                foreach ($member in $members) {
                    $memberId = $member.Id
                    $odataType = $member.AdditionalProperties.'@odata.type'
                    
                    # Determine member kind
                    $memberKind = switch -Wildcard ($odataType) {
                        "*user" { "AZUser" }
                        "*group" { "AZGroup" }
                        "*servicePrincipal" { "AZServicePrincipal" }
                        default { "Unknown" }
                    }
                    
                    if ($memberId) {
                        $membershipEdges += @{
                            SourceId = if ($TenantId) { "$memberId@$TenantId" } else { $memberId }
                            SourceKind = $memberKind
                            TargetId = $objectId
                            TargetKind = "AZGroup"
                            RelationType = "AZMemberOf"
                        }
                    }
                }
            }
            catch { }
        }
        
        Write-Host "    Collected $($bhGroups.Count) groups, $($membershipEdges.Count) membership edges" -ForegroundColor Gray
    }
    catch {
        Write-Host "[!] Error fetching groups: $_" -ForegroundColor Yellow
    }
    
    return @{
        Groups = $bhGroups
        Edges = $membershipEdges
    }
}

function Convert-DevicesToBloodHound {
    <#
    .SYNOPSIS
        Fetch and convert devices to AzureHound-compatible format.
    #>
    param(
        [string]$TenantId
    )
    
    $bhDevices = @()
    $ownershipEdges = @()
    
    Write-Host "[*] Collecting devices for BloodHound export..." -ForegroundColor Cyan
    
    try {
        $devices = Get-MgDevice -All -Property Id,DisplayName,DeviceId,OperatingSystem,OperatingSystemVersion,TrustType,IsCompliant,IsManaged,AccountEnabled,RegistrationDateTime,ApproximateLastSignInDateTime -ErrorAction Stop
        
        foreach ($device in $devices) {
            $deviceId = $device.Id
            if (-not $deviceId) { continue }
            
            $objectId = if ($TenantId) { "$deviceId@$TenantId" } else { $deviceId }
            
            # Map trust type to join type
            $deviceJoinType = switch ($device.TrustType) {
                "AzureAd" { "AzureADJoined" }
                "ServerAd" { "HybridAzureADJoined" }
                "Workplace" { "AzureADRegistered" }
                default { "Unknown" }
            }
            
            $bhDevice = @{
                ObjectId = $deviceId
                ObjectIdentifier = $objectId
                Kind = "AZDevice"
                DisplayName = $device.DisplayName
                DeviceId = $device.DeviceId
                TenantId = $TenantId
                OperatingSystem = $device.OperatingSystem
                OperatingSystemVersion = $device.OperatingSystemVersion
                TrustType = $device.TrustType
                DeviceJoinType = $deviceJoinType
                IsCompliant = $device.IsCompliant
                IsManaged = $device.IsManaged
                AccountEnabled = $device.AccountEnabled
                RegistrationDateTime = if ($device.RegistrationDateTime) { $device.RegistrationDateTime.ToString() } else { "" }
                ApproximateLastSignInDateTime = if ($device.ApproximateLastSignInDateTime) { $device.ApproximateLastSignInDateTime.ToString() } else { "" }
                Properties = @{
                    displayname = $device.DisplayName
                    operatingsystem = $device.OperatingSystem
                    trusttype = $device.TrustType
                    iscompliant = $device.IsCompliant
                    ismanaged = $device.IsManaged
                    tenantid = $TenantId
                }
            }
            
            $bhDevices += $bhDevice
            
            # Get device owners
            try {
                $owners = Get-MgDeviceRegisteredOwner -DeviceId $deviceId -Property Id -ErrorAction SilentlyContinue
                
                foreach ($owner in $owners) {
                    $ownerId = $owner.Id
                    if ($ownerId) {
                        $ownershipEdges += @{
                            SourceId = if ($TenantId) { "$ownerId@$TenantId" } else { $ownerId }
                            SourceKind = "AZUser"
                            TargetId = $objectId
                            TargetKind = "AZDevice"
                            RelationType = "AZOwns"
                        }
                    }
                }
            }
            catch { }
        }
        
        Write-Host "    Collected $($bhDevices.Count) devices, $($ownershipEdges.Count) ownership edges" -ForegroundColor Gray
    }
    catch {
        Write-Host "[!] Error fetching devices: $_" -ForegroundColor Yellow
    }
    
    return @{
        Devices = $bhDevices
        Edges = $ownershipEdges
    }
}

function Convert-AppsToBloodHound {
    <#
    .SYNOPSIS
        Fetch and convert applications and service principals to AzureHound-compatible format.
    #>
    param(
        [string]$TenantId
    )
    
    $bhApps = @()
    $bhSPs = @()
    $appEdges = @()
    
    Write-Host "[*] Collecting applications for BloodHound export..." -ForegroundColor Cyan
    
    # Get applications (app registrations)
    try {
        $apps = Get-MgApplication -All -Property Id,AppId,DisplayName,CreatedDateTime,SignInAudience,PasswordCredentials,KeyCredentials -ErrorAction Stop
        
        foreach ($app in $apps) {
            $appId = $app.Id
            if (-not $appId) { continue }
            
            $objectId = if ($TenantId) { "$appId@$TenantId" } else { $appId }
            
            # Check for credentials
            $hasSecrets = ($app.PasswordCredentials.Count -gt 0)
            $hasCerts = ($app.KeyCredentials.Count -gt 0)
            
            $bhApp = @{
                ObjectId = $appId
                ObjectIdentifier = $objectId
                Kind = "AZApp"
                DisplayName = $app.DisplayName
                AppId = $app.AppId
                TenantId = $TenantId
                CreatedDateTime = if ($app.CreatedDateTime) { $app.CreatedDateTime.ToString() } else { "" }
                SignInAudience = $app.SignInAudience
                HasSecrets = $hasSecrets
                HasCertificates = $hasCerts
                Properties = @{
                    displayname = $app.DisplayName
                    appid = $app.AppId
                    hassecrets = $hasSecrets
                    hascertificates = $hasCerts
                    tenantid = $TenantId
                }
            }
            
            $bhApps += $bhApp
            
            # Get app owners
            try {
                $owners = Get-MgApplicationOwner -ApplicationId $appId -Property Id -ErrorAction SilentlyContinue
                
                foreach ($owner in $owners) {
                    $ownerId = $owner.Id
                    if ($ownerId) {
                        $appEdges += @{
                            SourceId = if ($TenantId) { "$ownerId@$TenantId" } else { $ownerId }
                            SourceKind = "AZUser"
                            TargetId = $objectId
                            TargetKind = "AZApp"
                            RelationType = "AZOwns"
                        }
                    }
                }
            }
            catch { }
        }
        
        Write-Host "    Collected $($bhApps.Count) applications" -ForegroundColor Gray
    }
    catch {
        Write-Host "[!] Error fetching applications: $_" -ForegroundColor Yellow
    }
    
    # Get service principals
    Write-Host "[*] Collecting service principals for BloodHound export..." -ForegroundColor Cyan
    
    try {
        $sps = Get-MgServicePrincipal -All -Property Id,AppId,DisplayName,ServicePrincipalType,AppOwnerOrganizationId,AccountEnabled,Tags -ErrorAction Stop
        
        foreach ($sp in $sps) {
            $spId = $sp.Id
            if (-not $spId) { continue }
            
            $objectId = if ($TenantId) { "$spId@$TenantId" } else { $spId }
            
            # Determine if first-party
            $isFirstParty = ($sp.AppOwnerOrganizationId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a")  # Microsoft's tenant
            
            $bhSP = @{
                ObjectId = $spId
                ObjectIdentifier = $objectId
                Kind = "AZServicePrincipal"
                DisplayName = $sp.DisplayName
                AppId = $sp.AppId
                TenantId = $TenantId
                ServicePrincipalType = $sp.ServicePrincipalType
                AppOwnerOrganizationId = $sp.AppOwnerOrganizationId
                IsFirstParty = $isFirstParty
                AccountEnabled = $sp.AccountEnabled
                Tags = $sp.Tags
                Properties = @{
                    displayname = $sp.DisplayName
                    appid = $sp.AppId
                    serviceprincipaltype = $sp.ServicePrincipalType
                    isfirstparty = $isFirstParty
                    accountenabled = $sp.AccountEnabled
                    tenantid = $TenantId
                }
            }
            
            $bhSPs += $bhSP
            
            # Get SP owners
            try {
                $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $spId -Property Id -ErrorAction SilentlyContinue
                
                foreach ($owner in $owners) {
                    $ownerId = $owner.Id
                    if ($ownerId) {
                        $appEdges += @{
                            SourceId = if ($TenantId) { "$ownerId@$TenantId" } else { $ownerId }
                            SourceKind = "AZUser"
                            TargetId = $objectId
                            TargetKind = "AZServicePrincipal"
                            RelationType = "AZOwns"
                        }
                    }
                }
            }
            catch { }
        }
        
        Write-Host "    Collected $($bhSPs.Count) service principals, $($appEdges.Count) ownership edges" -ForegroundColor Gray
    }
    catch {
        Write-Host "[!] Error fetching service principals: $_" -ForegroundColor Yellow
    }
    
    return @{
        Applications = $bhApps
        ServicePrincipals = $bhSPs
        Edges = $appEdges
    }
}

function Convert-RolesToBloodHound {
    <#
    .SYNOPSIS
        Fetch and convert directory roles and role assignments to AzureHound-compatible format.
    #>
    param(
        [string]$TenantId
    )
    
    $bhRoles = @()
    $roleEdges = @()
    
    Write-Host "[*] Collecting directory roles for BloodHound export..." -ForegroundColor Cyan
    
    # Privileged roles list
    $privilegedRoles = @(
        "Global Administrator", "Privileged Role Administrator",
        "Privileged Authentication Administrator", "User Administrator",
        "Exchange Administrator", "Application Administrator",
        "Cloud Application Administrator", "Intune Administrator",
        "Security Administrator", "Password Administrator",
        "Authentication Administrator", "Helpdesk Administrator"
    )
    
    try {
        $roles = Get-MgDirectoryRole -ExpandProperty Members -ErrorAction Stop
        
        foreach ($role in $roles) {
            $roleId = $role.Id
            if (-not $roleId) { continue }
            
            $objectId = if ($TenantId) { "$roleId@$TenantId" } else { $roleId }
            $roleName = $role.DisplayName
            $isPrivileged = $privilegedRoles -contains $roleName
            
            $bhRole = @{
                ObjectId = $roleId
                ObjectIdentifier = $objectId
                Kind = "AZRole"
                DisplayName = $roleName
                Description = $role.Description
                RoleTemplateId = $role.RoleTemplateId
                TenantId = $TenantId
                IsPrivileged = $isPrivileged
                Properties = @{
                    displayname = $roleName
                    description = $role.Description
                    roletemplateid = $role.RoleTemplateId
                    isprivileged = $isPrivileged
                    tenantid = $TenantId
                }
            }
            
            $bhRoles += $bhRole
            
            # Create edges for role members
            foreach ($member in $role.Members) {
                $memberId = $member.Id
                $odataType = $member.AdditionalProperties.'@odata.type'
                
                if (-not $memberId) { continue }
                
                # Determine member kind
                $memberKind = switch -Wildcard ($odataType) {
                    "*user" { "AZUser" }
                    "*group" { "AZGroup" }
                    "*servicePrincipal" { "AZServicePrincipal" }
                    default { "Unknown" }
                }
                
                # Determine edge type based on role
                $edgeType = switch ($roleName) {
                    "Global Administrator" { "AZGlobalAdmin" }
                    "Privileged Role Administrator" { "AZPrivilegedRoleAdmin" }
                    "User Administrator" { "AZUserAdmin" }
                    "Application Administrator" { "AZAppAdmin" }
                    "Cloud Application Administrator" { "AZCloudAppAdmin" }
                    "Intune Administrator" { "AZIntuneAdmin" }
                    default { "AZHasRole" }
                }
                
                $roleEdges += @{
                    SourceId = if ($TenantId) { "$memberId@$TenantId" } else { $memberId }
                    SourceKind = $memberKind
                    TargetId = $objectId
                    TargetKind = "AZRole"
                    RelationType = $edgeType
                    RoleName = $roleName
                }
            }
        }
        
        Write-Host "    Collected $($bhRoles.Count) roles, $($roleEdges.Count) role assignment edges" -ForegroundColor Gray
    }
    catch {
        Write-Host "[!] Error fetching roles: $_" -ForegroundColor Yellow
    }
    
    return @{
        Roles = $bhRoles
        Edges = $roleEdges
    }
}

function New-TenantObject {
    <#
    .SYNOPSIS
        Create AzureHound tenant object.
    #>
    param(
        [hashtable]$TenantInfo
    )
    
    $tenantId = $TenantInfo.TenantId
    
    return @{
        ObjectId = $tenantId
        ObjectIdentifier = $tenantId
        Kind = "AZTenant"
        DisplayName = if ($TenantInfo.DisplayName) { $TenantInfo.DisplayName } else { "Unknown Tenant" }
        TenantId = $tenantId
        DefaultDomain = $TenantInfo.DefaultDomain
        VerifiedDomains = $TenantInfo.VerifiedDomains
        Properties = @{
            displayname = if ($TenantInfo.DisplayName) { $TenantInfo.DisplayName } else { "Unknown Tenant" }
            objectid = $tenantId
            tenantid = $tenantId
        }
    }
}

function Export-ToBloodHound {
    <#
    .SYNOPSIS
        Export all enumerated data to BloodHound/AzureHound-compatible JSON format.
        
    .DESCRIPTION
        Creates JSON files following AzureHound output structure for import into BloodHound CE.
        
    .PARAMETER Users
        Optional pre-enumerated users list. Will fetch if not provided.
        
    .PARAMETER BaseFilename
        Base filename for export files.
    #>
    param(
        [array]$Users = $null,
        [string]$BaseFilename = "azurehound_export"
    )
    
    Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
    Write-Host "BLOODHOUND / AZUREHOUND EXPORT" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    # Get tenant information
    Write-Host "[*] Getting tenant information..." -ForegroundColor Cyan
    $tenantInfo = Get-TenantInfo
    $tenantId = $tenantInfo.TenantId
    
    if ($tenantId) {
        Write-Host "    Tenant ID: $tenantId" -ForegroundColor Gray
        Write-Host "    Tenant Name: $($tenantInfo.DisplayName)" -ForegroundColor Gray
        Write-Host "    Default Domain: $($tenantInfo.DefaultDomain)" -ForegroundColor Gray
    }
    else {
        Write-Host "[!] Warning: Could not determine tenant ID. Export may be incomplete." -ForegroundColor Yellow
    }
    
    # Collect all data
    $allEdges = @()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # 1. Users
    Write-Host "`n[*] Processing users..." -ForegroundColor Cyan
    if (-not $Users -or $Users.Count -eq 0) {
        Write-Host "    Fetching users from directory..." -ForegroundColor Gray
        try {
            $Users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,Mail,AccountEnabled,UserType,CreatedDateTime,OnPremisesSyncEnabled,OnPremisesSecurityIdentifier,OnPremisesSamAccountName,JobTitle,Department -ErrorAction Stop
        }
        catch {
            Write-Host "[!] Error fetching users: $_" -ForegroundColor Yellow
            $Users = @()
        }
    }
    
    $bhUsers = Convert-UsersToBloodHound -Users $Users -TenantId $tenantId
    Write-Host "    Processed $($bhUsers.Count) users" -ForegroundColor Gray
    
    # 2. Groups
    $groupsResult = Convert-GroupsToBloodHound -TenantId $tenantId
    $bhGroups = $groupsResult.Groups
    $allEdges += $groupsResult.Edges
    
    # 3. Devices
    $devicesResult = Convert-DevicesToBloodHound -TenantId $tenantId
    $bhDevices = $devicesResult.Devices
    $allEdges += $devicesResult.Edges
    
    # 4. Applications and Service Principals
    $appsResult = Convert-AppsToBloodHound -TenantId $tenantId
    $bhApps = $appsResult.Applications
    $bhSPs = $appsResult.ServicePrincipals
    $allEdges += $appsResult.Edges
    
    # 5. Roles
    $rolesResult = Convert-RolesToBloodHound -TenantId $tenantId
    $bhRoles = $rolesResult.Roles
    $allEdges += $rolesResult.Edges
    
    # 6. Create tenant object
    $bhTenant = New-TenantObject -TenantInfo $tenantInfo
    
    # Export options
    Write-Host ("`n" + ("-" * 40)) -ForegroundColor Gray
    Write-Host "Export Options:" -ForegroundColor Yellow
    Write-Host "1. Single combined file (BloodHound CE compatible)"
    Write-Host "2. Separate files per object type (AzureHound style)"
    Write-Host "0. Cancel"
    
    $exportChoice = Read-Host "Select export format (0-2)"
    
    if ($exportChoice -eq "0") {
        Write-Host "[*] Export cancelled." -ForegroundColor Yellow
        return
    }
    
    # Get filename
    Write-Host "`nEnter filename (without extension, default: $BaseFilename):"
    Write-Host "Type 'cancel' to go back" -ForegroundColor Gray
    $userFilename = Read-Host "Filename"
    
    if ($userFilename.ToLower() -eq 'cancel') {
        Write-Host "[*] Export cancelled." -ForegroundColor Yellow
        return
    }
    
    if ($userFilename) { $BaseFilename = $userFilename }
    
    if ($exportChoice -eq "1") {
        # Single combined file - BloodHound CE format
        $combinedData = @{
            meta = @{
                methods = 0
                type = "azure"
                count = $bhUsers.Count + $bhGroups.Count + $bhDevices.Count + $bhApps.Count + $bhSPs.Count + $bhRoles.Count + 1
                version = $script:BloodHoundVersion
                collected = $timestamp
                tenantId = $tenantId
                tenantName = $tenantInfo.DisplayName
            }
            data = @{
                tenant = $bhTenant
                users = $bhUsers
                groups = $bhGroups
                devices = $bhDevices
                applications = $bhApps
                servicePrincipals = $bhSPs
                roles = $bhRoles
                relationships = $allEdges
            }
        }
        
        $outputFile = "${BaseFilename}_${timestamp}.json"
        
        try {
            $combinedData | ConvertTo-Json -Depth 20 | Out-File -FilePath $outputFile -Encoding UTF8
            
            Write-Host "`n[+] BloodHound export complete!" -ForegroundColor Green
            Write-Host "    File: $outputFile" -ForegroundColor Gray
            Write-Host "    Users: $($bhUsers.Count)" -ForegroundColor Gray
            Write-Host "    Groups: $($bhGroups.Count)" -ForegroundColor Gray
            Write-Host "    Devices: $($bhDevices.Count)" -ForegroundColor Gray
            Write-Host "    Applications: $($bhApps.Count)" -ForegroundColor Gray
            Write-Host "    Service Principals: $($bhSPs.Count)" -ForegroundColor Gray
            Write-Host "    Roles: $($bhRoles.Count)" -ForegroundColor Gray
            Write-Host "    Relationships: $($allEdges.Count)" -ForegroundColor Gray
        }
        catch {
            Write-Host "[!] Export failed: $_" -ForegroundColor Red
        }
    }
    elseif ($exportChoice -eq "2") {
        # Separate files per type - AzureHound style
        $outputDir = "${BaseFilename}_${timestamp}"
        
        try {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            
            # Export each type
            $exportFiles = @(
                @{ Name = "aztenants.json"; Data = @($bhTenant); Type = "tenants" }
                @{ Name = "azusers.json"; Data = $bhUsers; Type = "users" }
                @{ Name = "azgroups.json"; Data = $bhGroups; Type = "groups" }
                @{ Name = "azdevices.json"; Data = $bhDevices; Type = "devices" }
                @{ Name = "azapps.json"; Data = $bhApps; Type = "applications" }
                @{ Name = "azserviceprincipals.json"; Data = $bhSPs; Type = "serviceprincipals" }
                @{ Name = "azroles.json"; Data = $bhRoles; Type = "roles" }
                @{ Name = "azrelationships.json"; Data = $allEdges; Type = "relationships" }
            )
            
            foreach ($file in $exportFiles) {
                $fileData = @{
                    meta = @{
                        methods = 0
                        type = $file.Type
                        count = $file.Data.Count
                        version = $script:BloodHoundVersion
                        collected = $timestamp
                    }
                    data = $file.Data
                }
                
                $filePath = Join-Path $outputDir $file.Name
                $fileData | ConvertTo-Json -Depth 20 | Out-File -FilePath $filePath -Encoding UTF8
            }
            
            Write-Host "`n[+] AzureHound-style export complete!" -ForegroundColor Green
            Write-Host "    Directory: $outputDir/" -ForegroundColor Gray
            Write-Host "    Files created:" -ForegroundColor Gray
            foreach ($file in $exportFiles) {
                Write-Host "      - $($file.Name): $($file.Data.Count) objects" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "[!] Export failed: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "`n[*] Import into BloodHound:" -ForegroundColor Yellow
    Write-Host "    1. Open BloodHound CE"
    Write-Host "    2. Click 'Upload Data'"
    Write-Host "    3. Select the exported JSON file(s)"
    Write-Host "    4. Wait for data ingestion to complete"
    Write-Host "`n[*] Tip: Use Cypher queries to analyze attack paths!" -ForegroundColor Cyan
}

function Prompt-ExportResults {
    param(
        [array]$Data,
        [string]$DefaultFilename = "export"
    )
    
    if ($null -eq $Data -or $Data.Count -eq 0) {
        return
    }
    
    Write-Host "`nExport results? (y/n)" -ForegroundColor Cyan
    $exportChoice = Read-Host "Export"
    
    if ($exportChoice.ToLower() -eq 'y') {
        Write-Host "Enter filename (e.g. $DefaultFilename.csv or $DefaultFilename.json)"
        Write-Host "Type 'cancel' or press Enter to go back" -ForegroundColor Gray
        $exportFile = Read-Host "Filename"
        
        if ($exportFile -and $exportFile.ToLower() -ne 'cancel') {
            Export-Users -Users $Data -Path $exportFile
        }
        else {
            Write-Host "[*] Export cancelled." -ForegroundColor Yellow
        }
    }
}

function Show-Menu {
    Write-Host ("`n" + ("-" * 60)) -ForegroundColor Gray
    Write-Host 'ENUMERATION OPTIONS:' -ForegroundColor Yellow
    Write-Host ("-" * 60) -ForegroundColor Gray
    Write-Host '1.  Direct /users endpoint'
    Write-Host '2.  Search users by name'
    Write-Host '3.  Basic alternatives - People, Groups, Managers'
    Write-Host '4.  Advanced fallbacks - Calendar, Email, Teams, etc.'
    Write-Host '5.  FULL enumeration - ALL methods'
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'SECURITY ASSESSMENT:' -ForegroundColor Red
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '20. [HIGH] MFA Status Check' -ForegroundColor Red
    Write-Host '21. [HIGH] Privileged Role Enumeration' -ForegroundColor Red
    Write-Host '22. [HIGH] Applications and Service Principals' -ForegroundColor Red
    Write-Host '23. [MED]  Stale Accounts - no recent login' -ForegroundColor Yellow
    Write-Host '24. [MED]  Guest/External Users' -ForegroundColor Yellow
    Write-Host '25. [MED]  Password Never Expires' -ForegroundColor Yellow
    Write-Host '26. Full Security Assessment - all above' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'CREDENTIAL ATTACK SURFACE:' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '27. [HIGH] Password Policies per User' -ForegroundColor Red
    Write-Host '28. [HIGH] SSPR Enabled Users' -ForegroundColor Red
    Write-Host '29. [HIGH] Legacy Authentication Users' -ForegroundColor Red
    Write-Host '30. [HIGH] App Passwords Configured' -ForegroundColor Red
    Write-Host '31. Full Credential Attack Surface Assessment' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'CONDITIONAL ACCESS ANALYSIS:' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '32. [HIGH] Enumerate CA Policies' -ForegroundColor Red
    Write-Host '33. [HIGH] CA Policy Exclusions - Security Gaps' -ForegroundColor Red
    Write-Host '34. [HIGH] MFA Enforcement Gaps' -ForegroundColor Red
    Write-Host '35. Full CA Analysis - all above' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'DEVICE ENUMERATION:' -ForegroundColor Blue
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '36. [MED]  All Registered Devices' -ForegroundColor Yellow
    Write-Host '37. [HIGH] Non-Compliant Devices' -ForegroundColor Red
    Write-Host '38. [MED]  BYOD/Personal Devices' -ForegroundColor Yellow
    Write-Host '39. [MED]  Devices per User' -ForegroundColor Yellow
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'INTUNE/ENDPOINT MANAGER:' -ForegroundColor Blue
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '40. [HIGH] Intune Managed Devices' -ForegroundColor Red
    Write-Host '41. [HIGH] Intune Compliance Policies' -ForegroundColor Red
    Write-Host '42. [MED]  Intune Configuration Profiles' -ForegroundColor Yellow
    Write-Host '43. [HIGH] Intune Device Administrators' -ForegroundColor Red
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'ADMINISTRATIVE UNIT ENUMERATION:' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '44. [MED]  List Administrative Units' -ForegroundColor Yellow
    Write-Host '45. [HIGH] Scoped Role Assignments - AU Admins' -ForegroundColor Red
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'LICENSE INFORMATION:' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '46. [MED]  Tenant License SKUs' -ForegroundColor Yellow
    Write-Host '47. [HIGH] User License Assignments' -ForegroundColor Red
    Write-Host '48. [HIGH] E5/P2 Privileged Users - PIM/Defender access' -ForegroundColor Red
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'DIRECTORY SYNC STATUS:' -ForegroundColor Blue
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '49. [MED]  On-Prem Synced vs Cloud-Only Users' -ForegroundColor Yellow
    Write-Host '50. [HIGH] Directory Sync Errors' -ForegroundColor Red
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'ATTACK PATH ANALYSIS:' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '51. [CRIT] Full Attack Path Analysis' -ForegroundColor Red
    Write-Host '52. [HIGH] Password Reset Delegations' -ForegroundColor Red
    Write-Host '53. [HIGH] Privileged Group Owners' -ForegroundColor Red
    Write-Host '54. [HIGH] Group Membership Privileges' -ForegroundColor Red
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'POWER PLATFORM ENUMERATION:' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '55. [HIGH] Power Apps Enumeration - Owners/Users' -ForegroundColor Red
    Write-Host '56. [CRIT] Power Automate Flows - Sensitive Connectors' -ForegroundColor Red
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'LATERAL MOVEMENT ANALYSIS:' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '57. [CRIT] Full Lateral Movement Analysis' -ForegroundColor Red
    Write-Host '58. [HIGH] Transitive Group Memberships - Group Nesting' -ForegroundColor Red
    Write-Host '59. [HIGH] Shared Mailbox Access' -ForegroundColor Red
    Write-Host '60. [HIGH] Calendar/Mailbox Delegations' -ForegroundColor Red
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'BLOODHOUND / ATTACK PATH EXPORT:' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '61. [CRIT] Export to BloodHound/AzureHound Format' -ForegroundColor Red
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'HTML REPORT GENERATION:' -ForegroundColor Magenta
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '62. [NEW]  Generate Interactive HTML Report' -ForegroundColor Cyan
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host 'INDIVIDUAL ENUMERATION:' -ForegroundColor Gray
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '6.  People API'
    Write-Host '7.  Manager chain'
    Write-Host '8.  Group members'
    Write-Host '9.  Microsoft Search API'
    Write-Host '10. Calendar attendees'
    Write-Host '11. Email recipients'
    Write-Host '12. OneDrive sharing'
    Write-Host '13. Teams rosters'
    Write-Host '14. Planner assignees'
    Write-Host '15. SharePoint profiles'
    Write-Host '16. Azure Resource Manager'
    Write-Host '17. Meeting rooms/resources'
    Write-Host '18. Yammer/Viva Engage communities'
    Write-Host ("-" * 30) -ForegroundColor Gray
    Write-Host '19. Export users to file'
    Write-Host '99. Change authentication method'
    Write-Host '0.  Disconnect and exit'
    Write-Host ''
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

Show-Banner

# Check required modules
if (-not (Test-GraphModule)) {
    Write-Host "`n[ERROR] Required modules check failed. Exiting." -ForegroundColor Red
    exit 1
}

# Initialize and import modules properly
if (-not (Initialize-GraphModules)) {
    Write-Host "`n[ERROR] Failed to initialize modules. Exiting." -ForegroundColor Red
    exit 1
}

if (-not (Connect-ToGraph -Tenant $TenantId)) {
    Write-Host "`n[!] Authentication failed. Exiting." -ForegroundColor Red
    exit 1
}

# Display stealth status if enabled or configured
if ($script:StealthConfig.Enabled -or $script:StealthConfig.BaseDelay -gt 0) {
    Show-StealthStatus
}

# Non-interactive mode
if ($ExportPath) {
    Write-Host "`n[*] Running full enumeration for export..."
    $results = Invoke-FullEnumeration
    $allUsers = Merge-UserResults -Results $results
    
    if ($allUsers.Count -gt 0) {
        Write-Host "`n[+] Total unique users found: $($allUsers.Count)" -ForegroundColor Green
        Show-UserSummary -Users $allUsers -ShowSource
        Export-Users -Users $allUsers -Path $ExportPath
    }
    else {
        Write-Host "[!] No users found." -ForegroundColor Yellow
    }
    
    # Disconnect from all services
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
    exit 0
}

# Interactive mode
$allUsers = @()

while ($true) {
    Show-Menu
    $choice = Read-Host "Select option"

    switch ($choice) {
        "1" {
            $users = Get-EntraUsers
            if ($users.Count -gt 0) {
                $users | ForEach-Object { $_ | Add-Member -NotePropertyName "Source" -NotePropertyValue "Direct" -Force }
                $allUsers = $users
                Show-UserSummary -Users $users
            }
        }
        "2" {
            Write-Host "Enter search term (or 'cancel' to go back):" -ForegroundColor Gray
            $searchTerm = Read-Host "Search"
            if ($searchTerm -and $searchTerm.ToLower() -ne 'cancel') {
                $results = Search-EntraUser -SearchTerm $searchTerm
                if ($results.Count -gt 0) { Show-UserSummary -Users $results }
                else { Write-Host "[!] No users found." -ForegroundColor Yellow }
            }
        }
        "3" {
            $results = Invoke-BasicEnumeration
            $allUsers = Merge-UserResults -Results $results
            if ($allUsers.Count -gt 0) {
                Write-Host "`n[+] Total unique users: $($allUsers.Count)" -ForegroundColor Green
                Show-UserSummary -Users $allUsers -ShowSource
            }
        }
        "4" {
            $results = Invoke-AdvancedEnumeration
            $allUsers = Merge-UserResults -Results $results
            if ($allUsers.Count -gt 0) {
                Write-Host "`n[+] Total unique users: $($allUsers.Count)" -ForegroundColor Green
                Show-UserSummary -Users $allUsers -ShowSource
            }
        }
        "5" {
            $results = Invoke-FullEnumeration
            $allUsers = Merge-UserResults -Results $results
            Write-Host "`n[+] TOTAL UNIQUE USERS: $($allUsers.Count)" -ForegroundColor Green
            Show-UserSummary -Users $allUsers -ShowSource
        }
        "6" { $users = Get-PeopleApi; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "7" { $users = Get-ManagerChain; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "8" { $users = Get-GroupMembersUsers; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "9" { $users = Get-UsersViaSearchApi; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "10" { $users = Get-UsersFromCalendar; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "11" { $users = Get-UsersFromEmails; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "12" { $users = Get-UsersFromOneDrive; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "13" { $users = Get-UsersFromTeams; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "14" { $users = Get-UsersFromPlanner; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "15" { $users = Get-UsersFromSharePoint; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "16" { $users = Get-UsersFromAzureRM; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "17" { $resources = Get-RoomsAndResources; if ($resources) { Show-UserSummary -Users $resources -ShowSource } }
        "18" { $users = Get-UsersFromYammer; if ($users) { $allUsers = $users; Show-UserSummary -Users $users -ShowSource } }
        "19" {
            if ($allUsers.Count -eq 0) {
                Write-Host "[*] No users in memory. Running full enumeration..." -ForegroundColor Yellow
                $results = Invoke-FullEnumeration
                $allUsers = Merge-UserResults -Results $results
            }
            if ($allUsers.Count -gt 0) {
                Write-Host "[+] $($allUsers.Count) users ready for export" -ForegroundColor Green
                Write-Host 'Enter filename - e.g. users.csv or users.json'
                Write-Host "Type 'cancel' or press Enter to go back" -ForegroundColor Gray
                $exportFile = Read-Host "Filename"
                if ($exportFile -and $exportFile.ToLower() -ne 'cancel') { 
                    Export-Users -Users $allUsers -Path $exportFile 
                }
                else {
                    Write-Host "[*] Export cancelled." -ForegroundColor Yellow
                }
            }
        }
        # Security Assessment Options
        "20" {
            Write-Host "`n[*] Running MFA Status Check..." -ForegroundColor Cyan
            Write-Host "    (This may take a while for large directories)" -ForegroundColor Gray
            $mfaResults = Get-UserMFAStatus
            if ($mfaResults.Count -eq 0) {
                Write-Host "[*] Trying alternative MFA registration report..." -ForegroundColor Yellow
                $mfaResults = Get-MFARegistrationReport
            }
            if ($mfaResults.Count -gt 0) {
                Show-MFAStatusReport -Users $mfaResults
                Prompt-ExportResults -Data $mfaResults -DefaultFilename "mfa_status"
            }
            else {
                Write-Host "[!] MFA status check failed. Insufficient permissions." -ForegroundColor Red
            }
        }
        "21" {
            $privUsers = Get-PrivilegedUsers
            if ($privUsers.Count -gt 0) {
                Show-PrivilegedUsersReport -Users $privUsers
                Prompt-ExportResults -Data $privUsers -DefaultFilename "privileged_users"
            }
            else {
                Write-Host "[!] No privileged users found or access denied." -ForegroundColor Yellow
            }
        }
        "22" {
            $appsData = Get-ApplicationsAndServicePrincipals
            Show-AppsReport -Data $appsData
            # Combine all apps data for export
            $allAppsExport = @()
            if ($appsData.Applications) { $allAppsExport += $appsData.Applications | ForEach-Object { $_ | Add-Member -NotePropertyName "Type" -NotePropertyValue "Application" -Force -PassThru } }
            if ($appsData.ServicePrincipals) { $allAppsExport += $appsData.ServicePrincipals | ForEach-Object { $_ | Add-Member -NotePropertyName "Type" -NotePropertyValue "ServicePrincipal" -Force -PassThru } }
            if ($appsData.HighRiskApps) { $allAppsExport += $appsData.HighRiskApps | ForEach-Object { $_ | Add-Member -NotePropertyName "Type" -NotePropertyValue "HighRiskApp" -Force -PassThru } }
            Prompt-ExportResults -Data $allAppsExport -DefaultFilename "applications"
        }
        "23" {
            Write-Host "Enter days threshold (default 90):" -ForegroundColor Gray
            $daysInput = Read-Host "Days"
            $days = if ($daysInput) { [int]$daysInput } else { 90 }
            $stale = Get-StaleAccounts -DaysThreshold $days
            if ($stale.Count -gt 0) {
                Show-StaleAccountsReport -Users $stale
                Prompt-ExportResults -Data $stale -DefaultFilename "stale_accounts"
            }
            else {
                Write-Host "[!] No stale accounts found or access denied." -ForegroundColor Yellow
            }
        }
        "24" {
            $guests = Get-GuestUsers
            if ($guests.Count -gt 0) {
                Show-UserSummary -Users $guests
                Prompt-ExportResults -Data $guests -DefaultFilename "guest_users"
            }
            else {
                Write-Host "[!] No guest users found or access denied." -ForegroundColor Yellow
            }
        }
        "25" {
            $pwdUsers = Get-UsersWithPasswordNeverExpires
            if ($pwdUsers.Count -gt 0) {
                Show-SecuritySummary -Data $pwdUsers -Title "PASSWORD NEVER EXPIRES" -ShowRisk
                Write-Host ("{0,-29} {1,-44} {2,-24}" -f "Display Name", "Email/UPN", "Policy") -ForegroundColor Yellow
                Write-Host ("-" * 100) -ForegroundColor Gray
                foreach ($user in $pwdUsers) {
                    $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(28, $user.DisplayName.Length)) } else { "" }
                    $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(43, $user.UserPrincipalName.Length)) } else { "" }
                    $policy = if ($user.PasswordPolicies) { $user.PasswordPolicies.Substring(0, [Math]::Min(23, $user.PasswordPolicies.Length)) } else { "" }
                    Write-Host ("{0,-29} {1,-44} {2,-24}" -f $name, $email, $policy)
                }
                Write-Host ("-" * 100) -ForegroundColor Gray
                Prompt-ExportResults -Data $pwdUsers -DefaultFilename "password_never_expires"
            }
            else {
                Write-Host "[!] No users with password never expires or access denied." -ForegroundColor Yellow
            }
        }
        "26" {
            Write-Host "`nThis will run all security assessment checks:" -ForegroundColor Yellow
            Write-Host '  - MFA Status Check'
            Write-Host '  - Privileged Role Enumeration'
            Write-Host '  - Applications and Service Principals'
            Write-Host '  - Stale Accounts'
            Write-Host '  - Guest Users'
            Write-Host '  - Password Never Expires'
            Write-Host "`nThis may take several minutes for large directories." -ForegroundColor Gray
            $confirm = Read-Host "Continue? (y/n)"
            
            if ($confirm.ToLower() -eq 'y') {
                $securityResults = Invoke-FullSecurityAssessment
                # Combine all results for export
                $allSecurityExport = @()
                if ($securityResults.MFA) { $allSecurityExport += $securityResults.MFA | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "MFA" -Force -PassThru } }
                if ($securityResults.Privileged) { $allSecurityExport += $securityResults.Privileged | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Privileged" -Force -PassThru } }
                if ($securityResults.Stale) { $allSecurityExport += $securityResults.Stale | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Stale" -Force -PassThru } }
                if ($securityResults.Guests) { $allSecurityExport += $securityResults.Guests | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Guest" -Force -PassThru } }
                if ($securityResults.PasswordNeverExpires) { $allSecurityExport += $securityResults.PasswordNeverExpires | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "PasswordNeverExpires" -Force -PassThru } }
                Prompt-ExportResults -Data $allSecurityExport -DefaultFilename "security_assessment"
            }
        }
        # Credential Attack Surface Options
        "27" {
            $pwdPolicies = Get-UserPasswordPolicies
            if ($pwdPolicies.Count -gt 0) {
                Show-SecuritySummary -Data $pwdPolicies -Title "PASSWORD POLICIES PER USER" -ShowRisk
                Write-Host ("{0,-22} {1,-35} {2,-12} {3,-8} {4,-17} {5,-7}" -f "Display Name", "Email/UPN", "Last Change", "Days", "Risk Factors", "Risk") -ForegroundColor Yellow
                Write-Host ("-" * 110) -ForegroundColor Gray
                $riskOrder = @{ "HIGH" = 0; "MEDIUM" = 1; "LOW" = 2 }
                $sortedUsers = $pwdPolicies | Sort-Object { $riskOrder[$_.RiskLevel] }
                foreach ($user in ($sortedUsers | Select-Object -First 50)) {
                    $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(21, $user.DisplayName.Length)) } else { "" }
                    $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(34, $user.UserPrincipalName.Length)) } else { "" }
                    $lastChange = if ($user.LastPasswordChange) { "$($user.LastPasswordChange)".Substring(0, [Math]::Min(11, "$($user.LastPasswordChange)".Length)) } else { "" }
                    $days = "$($user.DaysSincePasswordChange)".Substring(0, [Math]::Min(7, "$($user.DaysSincePasswordChange)".Length))
                    $riskFactors = if ($user.RiskFactors) { $user.RiskFactors.Substring(0, [Math]::Min(16, $user.RiskFactors.Length)) } else { "" }
                    Write-Host ("{0,-22} {1,-35} {2,-12} {3,-8} {4,-17} {5,-7}" -f $name, $email, $lastChange, $days, $riskFactors, $user.RiskLevel)
                }
                if ($pwdPolicies.Count -gt 50) {
                    Write-Host "    ... and $($pwdPolicies.Count - 50) more" -ForegroundColor Gray
                }
                Write-Host ("-" * 110) -ForegroundColor Gray
                Prompt-ExportResults -Data $pwdPolicies -DefaultFilename "password_policies"
            }
            else {
                Write-Host "[!] Password policy check failed or access denied." -ForegroundColor Yellow
            }
        }
        "28" {
            $ssprUsers = Get-SsprEnabledUsers
            if ($ssprUsers.Count -gt 0) {
                Show-SecuritySummary -Data $ssprUsers -Title "SSPR ENABLED USERS" -ShowRisk
                Write-Host ("{0,-22} {1,-35} {2,-10} {3,-10} {4,-20} {5,-7}" -f "Display Name", "Email/UPN", "Registered", "Enabled", "Weak Methods", "Risk") -ForegroundColor Yellow
                Write-Host ("-" * 110) -ForegroundColor Gray
                $riskOrder = @{ "HIGH" = 0; "MEDIUM" = 1; "LOW" = 2 }
                $sortedUsers = $ssprUsers | Sort-Object { $riskOrder[$_.RiskLevel] }
                foreach ($user in ($sortedUsers | Select-Object -First 50)) {
                    $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(21, $user.DisplayName.Length)) } else { "" }
                    $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(34, $user.UserPrincipalName.Length)) } else { "" }
                    $registered = if ($user.IsSsprRegistered) { "Yes" } else { "No" }
                    $enabled = if ($user.IsSsprEnabled) { "Yes" } else { "No" }
                    $weakMethods = if ($user.WeakMethods) { $user.WeakMethods.Substring(0, [Math]::Min(19, $user.WeakMethods.Length)) } else { "" }
                    Write-Host ("{0,-22} {1,-35} {2,-10} {3,-10} {4,-20} {5,-7}" -f $name, $email, $registered, $enabled, $weakMethods, $user.RiskLevel)
                }
                if ($ssprUsers.Count -gt 50) {
                    Write-Host "    ... and $($ssprUsers.Count - 50) more" -ForegroundColor Gray
                }
                Write-Host ("-" * 110) -ForegroundColor Gray
                Prompt-ExportResults -Data $ssprUsers -DefaultFilename "sspr_users"
            }
            else {
                Write-Host "[!] SSPR check failed or access denied." -ForegroundColor Yellow
            }
        }
        "29" {
            $legacyUsers = Get-LegacyAuthenticationUsers
            if ($legacyUsers.Count -gt 0) {
                Show-SecuritySummary -Data $legacyUsers -Title "LEGACY AUTHENTICATION USERS (HIGH RISK)" -ShowRisk
                Write-Host ("{0,-22} {1,-35} {2,-25} {3,-12} {4,-7}" -f "Display Name", "Email/UPN", "Legacy Protocols", "Last Sign-In", "Risk") -ForegroundColor Yellow
                Write-Host ("-" * 110) -ForegroundColor Gray
                foreach ($user in ($legacyUsers | Select-Object -First 50)) {
                    $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(21, $user.DisplayName.Length)) } else { "" }
                    $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(34, $user.UserPrincipalName.Length)) } else { "" }
                    $protocols = if ($user.LegacyProtocols) { $user.LegacyProtocols.Substring(0, [Math]::Min(24, $user.LegacyProtocols.Length)) } else { "" }
                    $lastSignIn = if ($user.LastLegacySignIn) { "$($user.LastLegacySignIn)".Substring(0, [Math]::Min(11, "$($user.LastLegacySignIn)".Length)) } else { "" }
                    Write-Host ("{0,-22} {1,-35} {2,-25} {3,-12} {4,-7}" -f $name, $email, $protocols, $lastSignIn, $user.RiskLevel) -ForegroundColor Red
                }
                if ($legacyUsers.Count -gt 50) {
                    Write-Host "    ... and $($legacyUsers.Count - 50) more" -ForegroundColor Gray
                }
                Write-Host ("-" * 110) -ForegroundColor Gray
                Prompt-ExportResults -Data $legacyUsers -DefaultFilename "legacy_auth_users"
            }
            else {
                Write-Host "[+] No legacy authentication usage detected or access denied." -ForegroundColor Green
            }
        }
        "30" {
            $appPwdUsers = Get-UsersWithAppPasswords
            if ($appPwdUsers.Count -gt 0) {
                Show-SecuritySummary -Data $appPwdUsers -Title "USERS WITH APP PASSWORDS (HIGH RISK)" -ShowRisk
                Write-Host ("{0,-25} {1,-40} {2,-20} {3,-7}" -f "Display Name", "Email/UPN", "Risk Reason", "Risk") -ForegroundColor Yellow
                Write-Host ("-" * 100) -ForegroundColor Gray
                foreach ($user in $appPwdUsers) {
                    $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(24, $user.DisplayName.Length)) } else { "" }
                    $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(39, $user.UserPrincipalName.Length)) } else { "" }
                    $reason = if ($user.RiskReason) { $user.RiskReason.Substring(0, [Math]::Min(19, $user.RiskReason.Length)) } else { "" }
                    Write-Host ("{0,-25} {1,-40} {2,-20} {3,-7}" -f $name, $email, $reason, $user.RiskLevel) -ForegroundColor Red
                }
                Write-Host ("-" * 100) -ForegroundColor Gray
                Prompt-ExportResults -Data $appPwdUsers -DefaultFilename "app_password_users"
            }
            else {
                Write-Host "[+] No users with app passwords detected or access denied." -ForegroundColor Green
            }
        }
        "31" {
            Write-Host "`nThis will run all credential attack surface assessments:" -ForegroundColor Magenta
            Write-Host "  - Password Policies per User"
            Write-Host "  - SSPR Enabled Users"
            Write-Host "  - Legacy Authentication Users"
            Write-Host "  - App Passwords Configured"
            Write-Host "`nThis may take several minutes for large directories." -ForegroundColor Gray
            $confirm = Read-Host "Continue? (y/n)"
            
            if ($confirm.ToLower() -eq 'y') {
                $credResults = Invoke-CredentialAttackSurfaceAssessment
                # Combine all results for export
                $allCredExport = @()
                if ($credResults.PasswordPolicies) { $allCredExport += $credResults.PasswordPolicies | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "PasswordPolicy" -Force -PassThru } }
                if ($credResults.SSPR) { $allCredExport += $credResults.SSPR | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "SSPR" -Force -PassThru } }
                if ($credResults.LegacyAuth) { $allCredExport += $credResults.LegacyAuth | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "LegacyAuth" -Force -PassThru } }
                if ($credResults.AppPasswords) { $allCredExport += $credResults.AppPasswords | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "AppPasswords" -Force -PassThru } }
                Prompt-ExportResults -Data $allCredExport -DefaultFilename "credential_attack_surface"
            }
        }
        # Conditional Access Analysis Options
        "32" {
            $caPolicies = Get-ConditionalAccessPolicies
            if ($caPolicies.Count -gt 0) {
                Show-CAPoliciesReport -Policies $caPolicies
                Prompt-ExportResults -Data $caPolicies -DefaultFilename "ca_policies"
            }
            else {
                Write-Host "[!] CA policy enumeration failed or access denied." -ForegroundColor Yellow
                Write-Host "    Requires Policy.Read.All permission" -ForegroundColor Gray
            }
        }
        "33" {
            $caExclusions = Get-CAPolicyExclusions
            if ($caExclusions.ExcludedUsers.Count -gt 0 -or $caExclusions.ExcludedGroups.Count -gt 0 -or $caExclusions.ExcludedRoles.Count -gt 0) {
                Show-CAExclusionsReport -Exclusions $caExclusions
                # Combine exclusions for export
                $allExclusionsExport = @()
                if ($caExclusions.ExcludedUsers) { $allExclusionsExport += $caExclusions.ExcludedUsers | ForEach-Object { $_ | Add-Member -NotePropertyName "ExclusionType" -NotePropertyValue "User" -Force -PassThru } }
                if ($caExclusions.ExcludedGroups) { $allExclusionsExport += $caExclusions.ExcludedGroups | ForEach-Object { $_ | Add-Member -NotePropertyName "ExclusionType" -NotePropertyValue "Group" -Force -PassThru } }
                if ($caExclusions.ExcludedRoles) { $allExclusionsExport += $caExclusions.ExcludedRoles | ForEach-Object { $_ | Add-Member -NotePropertyName "ExclusionType" -NotePropertyValue "Role" -Force -PassThru } }
                Prompt-ExportResults -Data $allExclusionsExport -DefaultFilename "ca_exclusions"
            }
            else {
                Write-Host "[!] No CA exclusions found or access denied." -ForegroundColor Yellow
            }
        }
        "34" {
            $mfaGaps = Get-MFAEnforcementGaps
            if ($mfaGaps.Summary.Count -gt 0) {
                Show-MFAGapsReport -Gaps $mfaGaps
                Prompt-ExportResults -Data $mfaGaps.Summary -DefaultFilename "mfa_gaps"
            }
            else {
                Write-Host "[!] MFA gap analysis failed or access denied." -ForegroundColor Yellow
            }
        }
        "35" {
            Write-Host ("`n" + ("=" * 70)) -ForegroundColor Cyan
            Write-Host "FULL CONDITIONAL ACCESS ANALYSIS" -ForegroundColor Cyan
            Write-Host ("=" * 70) -ForegroundColor Cyan
            Write-Host "`nThis will run all CA analysis checks:" -ForegroundColor Yellow
            Write-Host "  - Enumerate all CA Policies"
            Write-Host "  - Identify excluded users/groups/roles"
            Write-Host "  - Find MFA enforcement gaps"
            Write-Host "`nRequires Policy.Read.All permission." -ForegroundColor Gray
            $confirm = Read-Host "Continue? (y/n)"
            
            if ($confirm.ToLower() -eq 'y') {
                $caResults = Invoke-FullCAAnalysis
                
                # Print detailed reports
                if ($caResults.Policies.Count -gt 0) {
                    Show-CAPoliciesReport -Policies $caResults.Policies
                }
                
                if ($caResults.Exclusions.ExcludedUsers.Count -gt 0 -or $caResults.Exclusions.ExcludedGroups.Count -gt 0 -or $caResults.Exclusions.ExcludedRoles.Count -gt 0) {
                    Show-CAExclusionsReport -Exclusions $caResults.Exclusions
                }
                
                if ($caResults.MfaGaps.Summary.Count -gt 0) {
                    Show-MFAGapsReport -Gaps $caResults.MfaGaps
                }
                
                # Combine all CA results for export
                $allCAExport = @()
                if ($caResults.Policies) { $allCAExport += $caResults.Policies | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Policy" -Force -PassThru } }
                if ($caResults.Exclusions.ExcludedUsers) { $allCAExport += $caResults.Exclusions.ExcludedUsers | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "ExcludedUser" -Force -PassThru } }
                if ($caResults.Exclusions.ExcludedGroups) { $allCAExport += $caResults.Exclusions.ExcludedGroups | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "ExcludedGroup" -Force -PassThru } }
                if ($caResults.MfaGaps.Summary) { $allCAExport += $caResults.MfaGaps.Summary | ForEach-Object { $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "MFAGap" -Force -PassThru } }
                Prompt-ExportResults -Data $allCAExport -DefaultFilename "ca_analysis"
            }
        }
        # Device Enumeration Options
        "36" {
            Write-Host "`n[*] Running All Devices Enumeration..." -ForegroundColor Cyan
            $devices = Get-AllDevices
            if ($devices.Count -gt 0) {
                Show-DevicesReport -Devices $devices -Title "ALL REGISTERED DEVICES"
                Prompt-ExportResults -Data $devices -DefaultFilename "all_devices"
            }
            else {
                Write-Host "[!] Device enumeration failed or access denied." -ForegroundColor Yellow
            }
        }
        "37" {
            Write-Host "`n[*] Running Non-Compliant Devices Check..." -ForegroundColor Cyan
            $nonCompliant = Get-NonCompliantDevices
            if ($nonCompliant.Count -gt 0) {
                Show-DevicesReport -Devices $nonCompliant -Title "NON-COMPLIANT DEVICES (HIGH RISK)"
                Prompt-ExportResults -Data $nonCompliant -DefaultFilename "non_compliant_devices"
            }
            else {
                Write-Host "[+] No non-compliant devices found or access denied." -ForegroundColor Green
            }
        }
        "38" {
            Write-Host "`n[*] Running BYOD/Personal Devices Enumeration..." -ForegroundColor Cyan
            $byod = Get-BYODDevices
            if ($byod.Count -gt 0) {
                Show-DevicesReport -Devices $byod -Title "BYOD/PERSONAL DEVICES"
                Prompt-ExportResults -Data $byod -DefaultFilename "byod_devices"
            }
            else {
                Write-Host "[+] No BYOD devices found or access denied." -ForegroundColor Green
            }
        }
        "39" {
            Write-Host "`n[*] Running Devices per User Enumeration..." -ForegroundColor Cyan
            Write-Host "    (This may take a while for large directories)" -ForegroundColor Gray
            $userDevices = Get-UserDevices
            if ($userDevices.Count -gt 0) {
                Show-UserDevicesReport -UserDevices $userDevices
                Prompt-ExportResults -Data $userDevices -DefaultFilename "user_devices"
            }
            else {
                Write-Host "[!] No user devices found or access denied." -ForegroundColor Yellow
            }
        }
        # Intune/Endpoint Manager Options
        "40" {
            Write-Host "`n[*] Running Intune Managed Devices Enumeration..." -ForegroundColor Cyan
            Write-Host "    (Requires DeviceManagementManagedDevices.Read.All permission)" -ForegroundColor Gray
            $intuneDevices = Get-IntuneManagedDevices
            if ($intuneDevices.Count -gt 0) {
                Show-IntuneManagedDevicesReport -Devices $intuneDevices
                Prompt-ExportResults -Data $intuneDevices -DefaultFilename "intune_devices"
            }
            else {
                Write-Host "[!] No Intune managed devices found or access denied." -ForegroundColor Yellow
                Write-Host "    Requires DeviceManagementManagedDevices.Read.All permission" -ForegroundColor Gray
            }
        }
        "41" {
            Write-Host "`n[*] Running Intune Compliance Policies Enumeration..." -ForegroundColor Cyan
            Write-Host "    (Requires DeviceManagementConfiguration.Read.All permission)" -ForegroundColor Gray
            $compliancePolicies = Get-IntuneCompliancePolicies
            if ($compliancePolicies.Count -gt 0) {
                Show-IntunePoliciesReport -Policies $compliancePolicies -Title "INTUNE COMPLIANCE POLICIES"
                Prompt-ExportResults -Data $compliancePolicies -DefaultFilename "intune_compliance_policies"
            }
            else {
                Write-Host "[!] No compliance policies found or access denied." -ForegroundColor Yellow
                Write-Host "    Requires DeviceManagementConfiguration.Read.All permission" -ForegroundColor Gray
            }
        }
        "42" {
            Write-Host "`n[*] Running Intune Configuration Profiles Enumeration..." -ForegroundColor Cyan
            Write-Host "    (Requires DeviceManagementConfiguration.Read.All permission)" -ForegroundColor Gray
            $configProfiles = Get-IntuneConfigurationProfiles
            if ($configProfiles.Count -gt 0) {
                Show-IntunePoliciesReport -Policies $configProfiles -Title "INTUNE CONFIGURATION PROFILES"
                Prompt-ExportResults -Data $configProfiles -DefaultFilename "intune_config_profiles"
            }
            else {
                Write-Host "[!] No configuration profiles found or access denied." -ForegroundColor Yellow
                Write-Host "    Requires DeviceManagementConfiguration.Read.All permission" -ForegroundColor Gray
            }
        }
        "43" {
            Write-Host "`n[*] Running Intune Device Administrators Enumeration..." -ForegroundColor Cyan
            Write-Host "    (Finding Intune RBAC role assignments)" -ForegroundColor Gray
            $intuneAdmins = Get-IntuneDeviceAdministrators
            if ($intuneAdmins.Count -gt 0) {
                Show-IntuneAdministratorsReport -Administrators $intuneAdmins
                Prompt-ExportResults -Data $intuneAdmins -DefaultFilename "intune_admins"
            }
            else {
                Write-Host "[!] No Intune role assignments found or access denied." -ForegroundColor Yellow
                Write-Host "    Requires DeviceManagementRBAC.Read.All permission" -ForegroundColor Gray
            }
        }
        # Administrative Unit Enumeration Options
        "44" {
            Write-Host "`n[*] Running Administrative Unit Enumeration..." -ForegroundColor Cyan
            $adminUnits = Get-AdministrativeUnits
            if ($adminUnits.Count -gt 0) {
                Show-AdminUnitsReport -AdminUnits $adminUnits
                
                # Ask if user wants to see members
                $seeMembers = Read-Host "`nView AU members? (y/n)"
                $allAUData = $adminUnits
                if ($seeMembers.ToLower() -eq 'y') {
                    $members = Get-AdminUnitMembers
                    if ($members.Count -gt 0) {
                        Show-AdminUnitMembersReport -Members $members
                        $allAUData = @()
                        $allAUData += $adminUnits | ForEach-Object { $_ | Add-Member -NotePropertyName "RecordType" -NotePropertyValue "AdminUnit" -Force -PassThru }
                        $allAUData += $members | ForEach-Object { $_ | Add-Member -NotePropertyName "RecordType" -NotePropertyValue "Member" -Force -PassThru }
                    }
                }
                Prompt-ExportResults -Data $allAUData -DefaultFilename "admin_units"
            }
            else {
                Write-Host "[!] No Administrative Units found or access denied." -ForegroundColor Yellow
                Write-Host "    Requires AdministrativeUnit.Read.All permission" -ForegroundColor Gray
            }
        }
        "45" {
            Write-Host "`n[*] Running Scoped Role Assignments Enumeration..." -ForegroundColor Cyan
            Write-Host "    (Identifying AU-scoped administrators)" -ForegroundColor Gray
            $scopedAdmins = Get-ScopedRoleAssignments
            if ($scopedAdmins.Count -gt 0) {
                Show-ScopedAdminsReport -ScopedAdmins $scopedAdmins
                Prompt-ExportResults -Data $scopedAdmins -DefaultFilename "scoped_role_assignments"
            }
            else {
                Write-Host "[!] No scoped role assignments found or access denied." -ForegroundColor Yellow
                Write-Host "    Requires RoleManagement.Read.All or AdministrativeUnit.Read.All permission" -ForegroundColor Gray
            }
        }
        # License Information Options
        "46" {
            Write-Host "`n[*] Running Tenant License SKUs Enumeration..." -ForegroundColor Cyan
            $tenantSkus = Get-SubscribedSkus
            if ($tenantSkus.Count -gt 0) {
                Show-TenantSkusReport -Skus $tenantSkus
                Prompt-ExportResults -Data $tenantSkus -DefaultFilename "tenant_licenses"
            }
            else {
                Write-Host "[!] No license SKUs found or access denied." -ForegroundColor Yellow
                Write-Host "    Requires Organization.Read.All or Directory.Read.All permission" -ForegroundColor Gray
            }
        }
        "47" {
            Write-Host "`n[*] Running User License Assignments Enumeration..." -ForegroundColor Cyan
            Write-Host "    (This may take a while for large directories)" -ForegroundColor Gray
            $licensedUsers = Get-UserLicenses
            if ($licensedUsers.Count -gt 0) {
                Show-UserLicensesReport -Users $licensedUsers
                Prompt-ExportResults -Data $licensedUsers -DefaultFilename "user_licenses"
            }
            else {
                Write-Host "[!] No licensed users found or access denied." -ForegroundColor Yellow
                Write-Host "    Requires User.Read.All permission" -ForegroundColor Gray
            }
        }
        "48" {
            Write-Host "`n[*] Running E5/P2 Privileged License Users Enumeration..." -ForegroundColor Cyan
            Write-Host "    (Identifying users with PIM, Defender, eDiscovery access)" -ForegroundColor Gray
            $privLicenseUsers = Get-PrivilegedLicenseUsers
            if ($privLicenseUsers.Count -gt 0) {
                Show-PrivilegedLicenseUsersReport -Users $privLicenseUsers
                Prompt-ExportResults -Data $privLicenseUsers -DefaultFilename "privileged_license_users"
            }
            else {
                Write-Host "[!] No users with E5/P2 licenses found or access denied." -ForegroundColor Yellow
            }
        }
        # Directory Sync Status Options
        "49" {
            Write-Host "`n[*] Running Directory Sync Status Analysis..." -ForegroundColor Cyan
            Write-Host "    (Identifying on-prem synced vs cloud-only users)" -ForegroundColor Gray
            $syncData = Get-DirectorySyncStatus
            if ($syncData.Summary.TotalUsers -gt 0) {
                Show-DirectorySyncStatusReport -SyncData $syncData
                # Combine sync data for export
                $allSyncExport = @()
                if ($syncData.SyncedUsers) { $allSyncExport += $syncData.SyncedUsers | ForEach-Object { $_ | Add-Member -NotePropertyName "SyncStatus" -NotePropertyValue "Synced" -Force -PassThru } }
                if ($syncData.CloudOnlyUsers) { $allSyncExport += $syncData.CloudOnlyUsers | ForEach-Object { $_ | Add-Member -NotePropertyName "SyncStatus" -NotePropertyValue "CloudOnly" -Force -PassThru } }
                Prompt-ExportResults -Data $allSyncExport -DefaultFilename "directory_sync_status"
            }
            else {
                Write-Host "[!] Directory sync status check failed or access denied." -ForegroundColor Yellow
                Write-Host "    Requires User.Read.All permission" -ForegroundColor Gray
            }
        }
        "50" {
            Write-Host "`n[*] Checking for Directory Sync Errors..." -ForegroundColor Cyan
            Write-Host "    (Finding users with provisioning/sync issues)" -ForegroundColor Gray
            $syncErrors = Get-DirectorySyncErrors
            if ($syncErrors.Count -gt 0) {
                Show-DirectorySyncErrorsReport -Users $syncErrors
                Prompt-ExportResults -Data $syncErrors -DefaultFilename "directory_sync_errors"
            }
            else {
                Write-Host "[+] No directory sync errors found." -ForegroundColor Green
                Write-Host "    (Or access denied - requires User.Read.All permission)" -ForegroundColor Gray
            }
        }
        # Attack Path Analysis Options
        "51" {
            Write-Host "`n[*] Running Full Attack Path Analysis..." -ForegroundColor Cyan
            Write-Host "    (Identifying privilege escalation paths)" -ForegroundColor Gray
            $attackPaths = Get-AttackPathAnalysis
            Show-AttackPathReport -Results $attackPaths
            # Combine attack path data for export
            $allAttackPathExport = @()
            if ($attackPaths.PasswordResetUsers) { $allAttackPathExport += $attackPaths.PasswordResetUsers | ForEach-Object { $_ | Add-Member -NotePropertyName "PathType" -NotePropertyValue "PasswordReset" -Force -PassThru } }
            if ($attackPaths.GroupOwners) { $allAttackPathExport += $attackPaths.GroupOwners | ForEach-Object { $_ | Add-Member -NotePropertyName "PathType" -NotePropertyValue "GroupOwner" -Force -PassThru } }
            if ($attackPaths.GroupManagers) { $allAttackPathExport += $attackPaths.GroupManagers | ForEach-Object { $_ | Add-Member -NotePropertyName "PathType" -NotePropertyValue "GroupManager" -Force -PassThru } }
            if ($attackPaths.AppsWithGroupWrite) { $allAttackPathExport += $attackPaths.AppsWithGroupWrite | ForEach-Object { $_ | Add-Member -NotePropertyName "PathType" -NotePropertyValue "AppGroupWrite" -Force -PassThru } }
            Prompt-ExportResults -Data $allAttackPathExport -DefaultFilename "attack_paths"
        }
        "52" {
            Write-Host "`n[*] Enumerating Password Reset Delegations..." -ForegroundColor Cyan
            Write-Host "    (Finding users who can reset passwords)" -ForegroundColor Gray
            $pwdResetResults = Get-PasswordResetDelegations
            if ($pwdResetResults.PasswordResetUsers.Count -gt 0) {
                Write-Host ("`n" + ("=" * 110)) -ForegroundColor Cyan
                Write-Host ("{0,55}" -f "PASSWORD RESET DELEGATIONS") -ForegroundColor Red
                Write-Host ("=" * 110) -ForegroundColor Cyan
                Write-Host ("`n{0,-22} {1,-33} {2,-33} {3,-10} {4,-8}" -f "Display Name", "Email/UPN", "Role", "Type", "Risk") -ForegroundColor Yellow
                Write-Host ("-" * 110) -ForegroundColor Gray
                foreach ($user in $pwdResetResults.PasswordResetUsers) {
                    $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(21, $user.DisplayName.Length)) } else { "N/A" }
                    $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(32, $user.UserPrincipalName.Length)) } else { "N/A" }
                    $role = if ($user.Role) { $user.Role.Substring(0, [Math]::Min(32, $user.Role.Length)) } else { "N/A" }
                    $assignType = $user.AssignmentType
                    $color = if ($user.RiskLevel -eq "CRITICAL") { "Red" } elseif ($user.RiskLevel -eq "HIGH") { "Yellow" } else { "White" }
                    Write-Host ("{0,-22} {1,-33} {2,-33} {3,-10} {4,-8}" -f $name, $email, $role, $assignType, $user.RiskLevel) -ForegroundColor $color
                }
                Write-Host ("-" * 110) -ForegroundColor Gray
                Prompt-ExportResults -Data $pwdResetResults.PasswordResetUsers -DefaultFilename "password_reset_delegations"
            }
            else {
                Write-Host "[!] No password reset delegations found or access denied." -ForegroundColor Yellow
            }
        }
        "53" {
            Write-Host "`n[*] Enumerating Privileged Group Owners..." -ForegroundColor Cyan
            Write-Host "    (Finding users who own privileged groups)" -ForegroundColor Gray
            $groupOwners = Get-GroupOwners
            if ($groupOwners.PrivilegedGroupOwners.Count -gt 0) {
                Write-Host ("`n" + ("=" * 110)) -ForegroundColor Cyan
                Write-Host ("{0,55}" -f "PRIVILEGED GROUP OWNERS") -ForegroundColor Yellow
                Write-Host ("=" * 110) -ForegroundColor Cyan
                Write-Host ("`n{0,-22} {1,-34} {2,-34} {3,-10} {4,-6}" -f "Owner Name", "Owner UPN", "Group Name", "Role Grp?", "Risk") -ForegroundColor Yellow
                Write-Host ("-" * 110) -ForegroundColor Gray
                foreach ($owner in $groupOwners.PrivilegedGroupOwners) {
                    $name = if ($owner.OwnerDisplayName) { $owner.OwnerDisplayName.Substring(0, [Math]::Min(21, $owner.OwnerDisplayName.Length)) } else { "N/A" }
                    $upn = if ($owner.OwnerUPN) { $owner.OwnerUPN.Substring(0, [Math]::Min(33, $owner.OwnerUPN.Length)) } else { "N/A" }
                    $groupName = if ($owner.GroupName) { $owner.GroupName.Substring(0, [Math]::Min(33, $owner.GroupName.Length)) } else { "N/A" }
                    $roleAssignable = if ($owner.IsRoleAssignable) { "Yes" } else { "No" }
                    Write-Host ("{0,-22} {1,-34} {2,-34} {3,-10} {4,-6}" -f $name, $upn, $groupName, $roleAssignable, $owner.RiskLevel) -ForegroundColor $(if ($owner.IsRoleAssignable) { "Red" } else { "Yellow" })
                }
                Write-Host ("-" * 110) -ForegroundColor Gray
                Prompt-ExportResults -Data $groupOwners.PrivilegedGroupOwners -DefaultFilename "privileged_group_owners"
            }
            else {
                Write-Host "[!] No privileged group owners found or access denied." -ForegroundColor Yellow
            }
        }
        "54" {
            Write-Host "`n[*] Analyzing Group Membership Privileges..." -ForegroundColor Cyan
            Write-Host "    (Finding users/apps that can modify group membership)" -ForegroundColor Gray
            $groupPrivs = Get-UsersWithGroupMembershipPrivileges
            
            # Show role-based managers
            if ($groupPrivs.RoleBasedGroupManagers.Count -gt 0) {
                Write-Host ("`n" + ("=" * 110)) -ForegroundColor Cyan
                Write-Host ("{0,55}" -f "USERS WITH GROUP MANAGEMENT ROLES") -ForegroundColor Cyan
                Write-Host ("=" * 110) -ForegroundColor Cyan
                Write-Host ("`n{0,-23} {1,-37} {2,-27} {3,-11} {4,-6}" -f "Display Name", "Email/UPN", "Role", "All Groups?", "Risk") -ForegroundColor Yellow
                Write-Host ("-" * 110) -ForegroundColor Gray
                foreach ($user in $groupPrivs.RoleBasedGroupManagers) {
                    $name = if ($user.DisplayName) { $user.DisplayName.Substring(0, [Math]::Min(22, $user.DisplayName.Length)) } else { "N/A" }
                    $email = if ($user.UserPrincipalName) { $user.UserPrincipalName.Substring(0, [Math]::Min(36, $user.UserPrincipalName.Length)) } else { "N/A" }
                    $role = if ($user.Role) { $user.Role.Substring(0, [Math]::Min(26, $user.Role.Length)) } else { "N/A" }
                    $allGroups = if ($user.CanManageAllGroups) { "Yes" } else { "No" }
                    $color = if ($user.RiskLevel -eq "CRITICAL") { "Red" } elseif ($user.RiskLevel -eq "HIGH") { "Yellow" } else { "White" }
                    Write-Host ("{0,-23} {1,-37} {2,-27} {3,-11} {4,-6}" -f $name, $email, $role, $allGroups, $user.RiskLevel) -ForegroundColor $color
                }
                Write-Host ("-" * 110) -ForegroundColor Gray
            }
            
            # Show apps with group write permissions
            if ($groupPrivs.AppsWithGroupWriteAll.Count -gt 0) {
                Write-Host ("`n" + ("=" * 110)) -ForegroundColor Cyan
                Write-Host ("{0,55}" -f "APPS WITH GROUP WRITE PERMISSIONS") -ForegroundColor Yellow
                Write-Host ("=" * 110) -ForegroundColor Cyan
                Write-Host ("`n{0,-29} {1,-37} {2,-27} {3,-12}" -f "App Name", "App ID", "Permissions", "Owners") -ForegroundColor Yellow
                Write-Host ("-" * 110) -ForegroundColor Gray
                foreach ($app in $groupPrivs.AppsWithGroupWriteAll) {
                    $name = if ($app.AppDisplayName) { $app.AppDisplayName.Substring(0, [Math]::Min(28, $app.AppDisplayName.Length)) } else { "N/A" }
                    $appId = if ($app.AppId) { $app.AppId.Substring(0, [Math]::Min(36, $app.AppId.Length)) } else { "N/A" }
                    $perms = if ($app.GrantedPermissions) { $app.GrantedPermissions.Substring(0, [Math]::Min(26, $app.GrantedPermissions.Length)) } else { "N/A" }
                    $owners = if ($app.Owners) { $app.Owners.Substring(0, [Math]::Min(11, $app.Owners.Length)) } else { "None" }
                    Write-Host ("{0,-29} {1,-37} {2,-27} {3,-12}" -f $name, $appId, $perms, $owners) -ForegroundColor Yellow
                }
                Write-Host ("-" * 110) -ForegroundColor Gray
            }
            
            if ($groupPrivs.RoleBasedGroupManagers.Count -eq 0 -and $groupPrivs.AppsWithGroupWriteAll.Count -eq 0) {
                Write-Host "[!] No group membership privileges found or access denied." -ForegroundColor Yellow
            }
            else {
                # Combine for export
                $allGroupPrivsExport = @()
                if ($groupPrivs.RoleBasedGroupManagers) { $allGroupPrivsExport += $groupPrivs.RoleBasedGroupManagers | ForEach-Object { $_ | Add-Member -NotePropertyName "PrivilegeType" -NotePropertyValue "RoleBasedManager" -Force -PassThru } }
                if ($groupPrivs.AppsWithGroupWriteAll) { $allGroupPrivsExport += $groupPrivs.AppsWithGroupWriteAll | ForEach-Object { $_ | Add-Member -NotePropertyName "PrivilegeType" -NotePropertyValue "AppWithGroupWrite" -Force -PassThru } }
                Prompt-ExportResults -Data $allGroupPrivsExport -DefaultFilename "group_membership_privileges"
            }
        }
        # Power Platform Enumeration Options
        "55" {
            Write-Host "`n[*] Running Power Apps Enumeration..." -ForegroundColor Cyan
            Write-Host "    (Enumerating Power Apps owners and users)" -ForegroundColor Gray
            Write-Host "    Requires Power Platform Admin or Environment Maker permissions" -ForegroundColor Gray
            $powerApps = Get-PowerApps
            if ($powerApps.Count -gt 0) {
                Show-PowerAppsReport -Apps $powerApps
                Prompt-ExportResults -Data $powerApps -DefaultFilename "power_apps"
            }
            else {
                Write-Host "[!] No Power Apps found or access denied." -ForegroundColor Yellow
                Write-Host "    Note: Requires Power Platform Admin or specific app permissions" -ForegroundColor Gray
            }
        }
        "56" {
            Write-Host "`n[*] Running Power Automate Flows Enumeration..." -ForegroundColor Cyan
            Write-Host "    (Finding flows with sensitive connectors)" -ForegroundColor Gray
            Write-Host "    Requires Power Platform Admin or flow owner permissions" -ForegroundColor Gray
            $flows = Get-PowerAutomateFlows
            if ($flows.Count -gt 0) {
                Show-PowerAutomateFlowsReport -Flows $flows
                Prompt-ExportResults -Data $flows -DefaultFilename "power_automate_flows"
            }
            else {
                Write-Host "[!] No Power Automate flows found or access denied." -ForegroundColor Yellow
                Write-Host "    Note: Requires Power Platform Admin or flow owner permissions" -ForegroundColor Gray
            }
        }
        # Lateral Movement Analysis Options
        "57" {
            Write-Host "`n[*] Running Full Lateral Movement Analysis..." -ForegroundColor Cyan
            Write-Host "    (Analyzing all lateral movement vectors)" -ForegroundColor Gray
            $lateralResults = Get-LateralMovementOpportunities
            Show-LateralMovementReport -Results $lateralResults
            # Combine lateral movement data for export
            $allLateralExport = @()
            if ($lateralResults.TransitiveGroups) { $allLateralExport += $lateralResults.TransitiveGroups | ForEach-Object { $_ | Add-Member -NotePropertyName "MovementType" -NotePropertyValue "TransitiveGroup" -Force -PassThru } }
            if ($lateralResults.SharedMailboxes) { $allLateralExport += $lateralResults.SharedMailboxes | ForEach-Object { $_ | Add-Member -NotePropertyName "MovementType" -NotePropertyValue "SharedMailbox" -Force -PassThru } }
            if ($lateralResults.CalendarDelegations) { $allLateralExport += $lateralResults.CalendarDelegations | ForEach-Object { $_ | Add-Member -NotePropertyName "MovementType" -NotePropertyValue "CalendarDelegation" -Force -PassThru } }
            Prompt-ExportResults -Data $allLateralExport -DefaultFilename "lateral_movement"
        }
        "58" {
            Write-Host "`n[*] Mapping Transitive Group Memberships..." -ForegroundColor Cyan
            Write-Host "    (Identifying group nesting and indirect access)" -ForegroundColor Gray
            $transResults = Get-TransitiveGroupMemberships
            Show-TransitiveMembershipReport -Results $transResults
            if ($transResults.NestedGroups -or $transResults.TransitiveMembers) {
                $allTransExport = @()
                if ($transResults.NestedGroups) { $allTransExport += $transResults.NestedGroups | ForEach-Object { $_ | Add-Member -NotePropertyName "RecordType" -NotePropertyValue "NestedGroup" -Force -PassThru } }
                if ($transResults.TransitiveMembers) { $allTransExport += $transResults.TransitiveMembers | ForEach-Object { $_ | Add-Member -NotePropertyName "RecordType" -NotePropertyValue "TransitiveMember" -Force -PassThru } }
                Prompt-ExportResults -Data $allTransExport -DefaultFilename "transitive_group_memberships"
            }
        }
        "59" {
            Write-Host "`n[*] Analyzing Shared Mailbox Access..." -ForegroundColor Cyan
            Write-Host "    (Finding shared mailboxes and permissions)" -ForegroundColor Gray
            $mailboxResults = Get-SharedMailboxAccess
            Show-SharedMailboxReport -Results $mailboxResults
            if ($mailboxResults.SharedMailboxes -or $mailboxResults.Permissions) {
                $allMailboxExport = @()
                if ($mailboxResults.SharedMailboxes) { $allMailboxExport += $mailboxResults.SharedMailboxes | ForEach-Object { $_ | Add-Member -NotePropertyName "RecordType" -NotePropertyValue "SharedMailbox" -Force -PassThru } }
                if ($mailboxResults.Permissions) { $allMailboxExport += $mailboxResults.Permissions | ForEach-Object { $_ | Add-Member -NotePropertyName "RecordType" -NotePropertyValue "Permission" -Force -PassThru } }
                Prompt-ExportResults -Data $allMailboxExport -DefaultFilename "shared_mailbox_access"
            }
        }
        "60" {
            Write-Host "`n[*] Analyzing Calendar/Mailbox Delegations..." -ForegroundColor Cyan
            Write-Host "    (Finding delegated permissions)" -ForegroundColor Gray
            $delegationResults = Get-CalendarMailboxDelegations
            Show-CalendarDelegationReport -Results $delegationResults
            if ($delegationResults.Delegations) {
                Prompt-ExportResults -Data $delegationResults.Delegations -DefaultFilename "calendar_mailbox_delegations"
            }
        }
        # BloodHound / AzureHound Export
        "61" {
            Write-Host "`n[*] Running BloodHound/AzureHound Export..." -ForegroundColor Cyan
            Write-Host "    (Collecting Users, Groups, Devices, Apps, Roles)" -ForegroundColor Gray
            # Use existing allUsers if available
            if ($allUsers -and $allUsers.Count -gt 0) {
                Export-ToBloodHound -Users $allUsers
            }
            else {
                Export-ToBloodHound
            }
        }
        # HTML Report Generation
        "62" {
            Write-Host ("`n" + ("=" * 70)) -ForegroundColor Cyan
            Write-Host "INTERACTIVE HTML REPORT GENERATION" -ForegroundColor Cyan
            Write-Host ("=" * 70) -ForegroundColor Cyan
            Write-Host "`nThis will generate a comprehensive HTML report with:" -ForegroundColor Yellow
            Write-Host "  - Executive Summary with key findings"
            Write-Host "  - Risk scoring and visualizations"
            Write-Host "  - Interactive charts (using Chart.js)"
            Write-Host "  - Detailed findings tables"
            Write-Host "`nWhat data would you like to include?" -ForegroundColor Yellow
            Write-Host "1. Run full security assessment and generate report"
            Write-Host "2. Use existing collected data (if available)"
            Write-Host "0. Cancel"
            
            $reportChoice = Read-Host "`nSelect option (0-2)"
            
            if ($reportChoice -eq "0") {
                Write-Host "[*] Report generation cancelled." -ForegroundColor Yellow
            }
            elseif ($reportChoice -in @("1", "2")) {
                # Collect findings
                $reportFindings = @{}
                
                if ($reportChoice -eq "1") {
                    # Run full assessment
                    Write-Host "`n[*] Running full security assessment..." -ForegroundColor Cyan
                    
                    # Users
                    if ($allUsers -and $allUsers.Count -gt 0) {
                        $reportFindings["users"] = $allUsers
                    }
                    else {
                        Write-Host "`n[1/10] Enumerating users..." -ForegroundColor Gray
                        $results = Invoke-FullEnumeration
                        $allUsers = Merge-UserResults -Results $results
                        $reportFindings["users"] = $allUsers
                    }
                    
                    # MFA Status
                    Write-Host "`n[2/10] Checking MFA status..." -ForegroundColor Gray
                    $mfaResults = Get-UserMFAStatus
                    if (-not $mfaResults -or $mfaResults.Count -eq 0) {
                        $mfaResults = Get-MFARegistrationReport
                    }
                    $reportFindings["mfa"] = if ($mfaResults) { $mfaResults } else { @() }
                    
                    # Privileged Users
                    Write-Host "`n[3/10] Enumerating privileged users..." -ForegroundColor Gray
                    $privUsers = Get-PrivilegedUsers
                    $reportFindings["privileged"] = if ($privUsers) { $privUsers } else { @() }
                    
                    # Applications
                    Write-Host "`n[4/10] Analyzing applications..." -ForegroundColor Gray
                    $appsData = Get-ApplicationsAndServicePrincipals
                    $reportFindings["apps"] = if ($appsData) { $appsData } else { @{} }
                    
                    # Stale Accounts
                    Write-Host "`n[5/10] Finding stale accounts..." -ForegroundColor Gray
                    $stale = Get-StaleAccounts -DaysThreshold 90
                    $reportFindings["stale"] = if ($stale) { $stale } else { @() }
                    
                    # Guest Users
                    Write-Host "`n[6/10] Enumerating guest users..." -ForegroundColor Gray
                    $guests = Get-GuestUsers
                    $reportFindings["guests"] = if ($guests) { $guests } else { @() }
                    
                    # CA Policies
                    Write-Host "`n[7/10] Analyzing Conditional Access..." -ForegroundColor Gray
                    $caPolicies = Get-ConditionalAccessPolicies
                    $reportFindings["ca_policies"] = if ($caPolicies) { $caPolicies } else { @() }
                    
                    # Password Policies
                    Write-Host "`n[8/10] Checking password policies..." -ForegroundColor Gray
                    $pwdPolicies = Get-UserPasswordPolicies
                    $reportFindings["password_policy"] = if ($pwdPolicies) { $pwdPolicies } else { @() }
                    
                    # Devices
                    Write-Host "`n[9/10] Enumerating devices..." -ForegroundColor Gray
                    $devices = Get-AllDevices
                    $reportFindings["devices"] = if ($devices) { $devices } else { @() }
                    
                    # Non-Compliant Devices
                    Write-Host "`n[10/10] Checking device compliance..." -ForegroundColor Gray
                    $nonCompliant = Get-NonCompliantDevices
                    $reportFindings["non_compliant"] = if ($nonCompliant) { $nonCompliant } else { @() }
                }
                elseif ($reportChoice -eq "2") {
                    # Use existing data
                    if ($allUsers -and $allUsers.Count -gt 0) {
                        $reportFindings["users"] = $allUsers
                    }
                    Write-Host "[*] Using existing collected data..." -ForegroundColor Yellow
                    Write-Host "    Note: Only data from previous operations will be included." -ForegroundColor Gray
                }
                
                # Get tenant info
                $tenantInfo = Get-TenantInfo
                
                # Generate report
                if ($reportFindings.Keys.Count -gt 0) {
                    Write-Host "`nEnter report filename (without extension, default: evilmist_report):"
                    Write-Host "Type 'cancel' to go back" -ForegroundColor Gray
                    $reportFilename = Read-Host "Filename"
                    
                    if ($reportFilename.ToLower() -eq 'cancel') {
                        Write-Host "[*] Report generation cancelled." -ForegroundColor Yellow
                    }
                    else {
                        if (-not $reportFilename) { $reportFilename = "evilmist_report" }
                        if (-not $reportFilename.EndsWith('.html')) { $reportFilename += '.html' }
                        
                        Export-HtmlReport -Findings $reportFindings -Filename $reportFilename -TenantInfo $tenantInfo -Title "EvilMist Security Assessment Report"
                    }
                }
                else {
                    Write-Host "[!] No data collected. Run some assessments first." -ForegroundColor Yellow
                }
            }
        }
        "99" {
            # Change authentication method - hidden option (use 99 to avoid conflict with Security Assessment menu items)
            Write-Host "`n[*] Disconnecting current session..." -ForegroundColor Yellow
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
            Write-Host "[*] Returning to authentication selection..." -ForegroundColor Cyan
            
            # Re-run authentication
            if (-not (Connect-ToGraph)) {
                Write-Host "[!] Authentication failed. Exiting." -ForegroundColor Red
                exit 1
            }
            Write-Host "[+] Successfully reconnected!" -ForegroundColor Green
        }
        "0" {
            Write-Host "`n[*] Disconnecting..." -ForegroundColor Yellow
            # Disconnect from all services
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
            Write-Host "[+] Goodbye!" -ForegroundColor Green
            exit 0
        }
        default { Write-Host "[!] Invalid option." -ForegroundColor Red }
    }
}
