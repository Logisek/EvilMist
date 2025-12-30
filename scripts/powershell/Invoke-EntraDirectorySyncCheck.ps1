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
    Checks Azure Entra ID directory sync status, errors, conflicts, and scope.

.DESCRIPTION
    This script queries Azure Entra ID to analyze directory synchronization status,
    enumerate sync errors, identify sync conflicts, and check sync scope and filters.
    It provides comprehensive information about on-premises synced users vs cloud-only
    users, sync health, and configuration issues.
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Information collected includes:
    - Directory sync status (synced vs cloud-only users)
    - Sync errors and provisioning issues
    - Sync conflicts and duplicate attributes
    - Last sync timestamps and stale sync detection
    - Sync scope and filter configuration
    - Risk assessment based on sync health and errors

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

.PARAMETER OnlySyncErrors
    Show only users with sync errors.

.PARAMETER OnlyStaleSync
    Show only users with stale sync (>7 days since last sync).

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraDirectorySyncCheck.ps1
    # Check directory sync status for all users

.EXAMPLE
    .\Invoke-EntraDirectorySyncCheck.ps1 -ExportPath "sync-status.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraDirectorySyncCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraDirectorySyncCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraDirectorySyncCheck.ps1 -OnlySyncErrors -Matrix
    # Display only users with sync errors in matrix format

.EXAMPLE
    .\Invoke-EntraDirectorySyncCheck.ps1 -OnlyStaleSync -ExportPath "stale-sync.csv"
    # Show only stale sync users and export
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
    [switch]$OnlySyncErrors,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyStaleSync,

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

# Required scopes for directory sync checking
$script:RequiredScopes = @(
    "Directory.Read.All",
    "User.Read.All",
    "AuditLog.Read.All"
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
$script:SyncStatusData = @()
$script:TotalUsersScanned = 0
$script:SyncConfiguration = $null
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
    Write-Host "    Entra ID Directory Sync Check - Sync Status & Health Audit" -ForegroundColor Yellow
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
        "Microsoft.Graph.Identity.DirectoryManagement"
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
        
        Write-Host "[*] Importing Microsoft.Graph.Identity.DirectoryManagement..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force -ErrorAction Stop
        
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

# Get directory sync configuration
function Get-SyncConfiguration {
    Write-Host "`n[*] Checking directory sync configuration..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Try to get directory sync configuration via Graph API
        # Note: Full sync configuration may require Azure AD Connect PowerShell module
        # We'll check for basic indicators via Graph API
        
        $config = @{
            SyncEnabled = $false
            LastSyncTime = $null
            SyncErrors = 0
            ConfigurationAvailable = $false
        }
        
        # Check if there are any synced users (indicates sync is configured)
        $syncedUsersUri = "https://graph.microsoft.com/v1.0/users?`$filter=onPremisesSyncEnabled eq true&`$top=1&`$count=true"
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $syncedUsersUri -ErrorAction Stop
            if ($response.'@odata.count' -gt 0) {
                $config.SyncEnabled = $true
                $config.ConfigurationAvailable = $true
            }
        }
        catch {
            # Filter may not be supported, try without filter
        }
        
        # Get organization details for sync info
        try {
            Invoke-StealthDelay
            $org = Get-MgOrganization -ErrorAction SilentlyContinue
            if ($org) {
                $config.OrganizationId = $org.Id
                $config.OrganizationName = $org.DisplayName
            }
        }
        catch { }
        
        Write-Host "[+] Directory sync configuration check complete" -ForegroundColor Green
        return $config
    }
    catch {
        Write-Host "[!] Unable to retrieve sync configuration: $_" -ForegroundColor Yellow
        return @{
            SyncEnabled = $null
            LastSyncTime = $null
            SyncErrors = 0
            ConfigurationAvailable = $false
        }
    }
}

# Main scanning function
function Start-SyncScan {
    Write-Host "`n[*] Starting directory sync scan..." -ForegroundColor Cyan
    Write-Host "[*] This may take a while depending on the number of users..." -ForegroundColor Cyan
    
    # Get sync configuration
    $script:SyncConfiguration = Get-SyncConfiguration
    
    # Get all users with sync-related properties
    Write-Host "`n[*] Retrieving users with sync information..." -ForegroundColor Cyan
    
    try {
        $selectFields = "id,displayName,userPrincipalName,mail,accountEnabled,userType,onPremisesSyncEnabled,onPremisesDistinguishedName,onPremisesDomainName,onPremisesLastSyncDateTime,onPremisesSecurityIdentifier,onPremisesSamAccountName,onPremisesImmutableId,onPremisesProvisioningErrors"
        
        $allUsers = @()
        $uri = "https://graph.microsoft.com/v1.0/users?`$select=$selectFields&`$top=999"
        
        do {
            Invoke-StealthDelay
            
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $allUsers += $response.value
            
            if ($response.'@odata.nextLink') {
                $uri = $response.'@odata.nextLink'
                Write-Host "    Retrieved $($allUsers.Count) users so far..." -ForegroundColor Gray
            }
            else {
                $uri = $null
            }
        } while ($uri)
        
        Write-Host "[+] Retrieved $($allUsers.Count) total users" -ForegroundColor Green
        
        $script:TotalUsersScanned = $allUsers.Count
        $progressCounter = 0
        
        Write-Host "`n[*] Analyzing sync status for each user..." -ForegroundColor Cyan
        
        foreach ($user in $allUsers) {
            $progressCounter++
            
            # Progress indicator
            if ($progressCounter % 50 -eq 0 -or $progressCounter -eq $allUsers.Count) {
                $percentComplete = [math]::Round(($progressCounter / $allUsers.Count) * 100, 1)
                Write-Host "`r[*] Progress: $progressCounter/$($allUsers.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
            }
            
            # Skip disabled users if not included
            if (-not $IncludeDisabledUsers -and -not $user.accountEnabled) {
                continue
            }
            
            # Determine if user is synced
            $isSynced = $user.onPremisesSyncEnabled -eq $true -or $user.onPremisesImmutableId -or $user.onPremisesSecurityIdentifier
            
            # Get provisioning errors
            $provErrors = $user.onPremisesProvisioningErrors
            $hasErrors = $provErrors -and $provErrors.Count -gt 0
            
            # Skip if OnlySyncErrors is set and user has no errors
            if ($OnlySyncErrors -and -not $hasErrors) {
                continue
            }
            
            # Calculate days since last sync
            $daysSinceLastSync = $null
            $lastSyncDate = $null
            if ($user.onPremisesLastSyncDateTime) {
                try {
                    $lastSyncDate = [DateTime]$user.onPremisesLastSyncDateTime
                    $daysSinceLastSync = ([DateTime]::Now - $lastSyncDate).Days
                }
                catch { }
            }
            
            # Skip if OnlyStaleSync is set and sync is not stale
            if ($OnlyStaleSync) {
                if (-not $isSynced -or $null -eq $daysSinceLastSync -or $daysSinceLastSync -le 7) {
                    continue
                }
            }
            
            # Parse provisioning errors
            $errorCategories = @()
            $errorDetails = @()
            $errorCount = 0
            
            if ($hasErrors) {
                $errorCount = $provErrors.Count
                foreach ($syncErr in $provErrors) {
                    $category = if ($syncErr.category) { $syncErr.category } else { "Unknown" }
                    if ($category -notin $errorCategories) {
                        $errorCategories += $category
                    }
                    $errorDetails += [PSCustomObject]@{
                        Category = $category
                        Property = $syncErr.propertyCausingError
                        Value = $syncErr.value
                        OccurredDateTime = $syncErr.occurredDateTime
                        ErrorCode = $syncErr.errorCode
                    }
                }
            }
            
            # Determine risk level
            $riskLevel = "LOW"
            $riskFactors = @()
            
            if ($hasErrors) {
                $riskLevel = "HIGH"
                $riskFactors += "$errorCount sync error(s)"
            }
            elseif ($isSynced -and $null -ne $daysSinceLastSync) {
                if ($daysSinceLastSync -gt 7) {
                    $riskLevel = "MEDIUM"
                    $riskFactors += "Stale sync ($daysSinceLastSync days)"
                }
                elseif ($daysSinceLastSync -gt 30) {
                    $riskLevel = "HIGH"
                    $riskFactors += "Very stale sync ($daysSinceLastSync days)"
                }
            }
            
            # Determine sync source
            $syncSource = if ($isSynced) { "On-Premises AD" } else { "Cloud-Only" }
            
            $userInfo = [PSCustomObject]@{
                DisplayName = $user.displayName
                UserPrincipalName = $user.userPrincipalName
                Email = $user.mail
                AccountEnabled = $user.accountEnabled
                UserType = $user.userType
                SyncSource = $syncSource
                OnPremisesSyncEnabled = $isSynced
                OnPremisesDomainName = $user.onPremisesDomainName
                OnPremisesSamAccountName = $user.onPremisesSamAccountName
                OnPremisesDistinguishedName = $user.onPremisesDistinguishedName
                OnPremisesLastSyncDateTime = $lastSyncDate
                DaysSinceLastSync = $daysSinceLastSync
                OnPremisesImmutableId = $user.onPremisesImmutableId
                OnPremisesSecurityIdentifier = $user.onPremisesSecurityIdentifier
                HasSyncErrors = $hasErrors
                ErrorCount = $errorCount
                ErrorCategories = ($errorCategories -join ", ")
                ErrorDetails = $errorDetails
                RiskLevel = $riskLevel
                RiskFactors = ($riskFactors -join ", ")
            }
            
            $script:SyncStatusData += $userInfo
        }
        
        Write-Host "`n[+] Scan complete!" -ForegroundColor Green
    }
    catch {
        Write-Host "`n[ERROR] Failed to retrieve users: $_" -ForegroundColor Red
        Write-Host "[!] Note: Requires Directory.Read.All and User.Read.All permissions" -ForegroundColor Yellow
    }
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - DIRECTORY SYNC STATUS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:SyncStatusData.Count -eq 0) {
        if ($OnlySyncErrors) {
            Write-Host "`n[+] No users with sync errors found." -ForegroundColor Green
        }
        elseif ($OnlyStaleSync) {
            Write-Host "`n[+] No users with stale sync found." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No sync data found." -ForegroundColor Yellow
        }
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:SyncStatusData | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Source';Expression={$_.SyncSource}},
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}},
        @{Name='User Principal Name';Expression={$_.UserPrincipalName}},
        @{Name='Display Name';Expression={$_.DisplayName}},
        @{Name='Domain';Expression={if($_.OnPremisesDomainName){$_.OnPremisesDomainName}else{'-'}}},
        @{Name='Last Sync';Expression={
            if($null -eq $_.DaysSinceLastSync){'-'}
            elseif($_.DaysSinceLastSync -eq 0){'Today'}
            elseif($_.DaysSinceLastSync -eq 1){'Yesterday'}
            else{"$($_.DaysSinceLastSync)d ago"}
        }},
        @{Name='Errors';Expression={if($_.HasSyncErrors){"$($_.ErrorCount)"}else{'0'}}},
        @{Name='Error Categories';Expression={if($_.ErrorCategories){$_.ErrorCategories}else{'-'}}}
    
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
    Write-Host "Total users analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalUsersScanned -ForegroundColor Yellow
    
    Write-Host "Users in results: " -NoNewline -ForegroundColor White
    Write-Host $script:SyncStatusData.Count -ForegroundColor Yellow
    
    $syncedUsers = ($script:SyncStatusData | Where-Object { $_.OnPremisesSyncEnabled -eq $true }).Count
    $cloudOnlyUsers = ($script:SyncStatusData | Where-Object { $_.OnPremisesSyncEnabled -eq $false }).Count
    $usersWithErrors = ($script:SyncStatusData | Where-Object { $_.HasSyncErrors -eq $true }).Count
    $staleSyncUsers = ($script:SyncStatusData | Where-Object { $null -ne $_.DaysSinceLastSync -and $_.DaysSinceLastSync -gt 7 }).Count
    
    Write-Host "  - Synced from On-Premises: " -NoNewline -ForegroundColor White
    Write-Host $syncedUsers -ForegroundColor Cyan
    
    Write-Host "  - Cloud-Only: " -NoNewline -ForegroundColor White
    Write-Host $cloudOnlyUsers -ForegroundColor Green
    
    Write-Host "  - Users with Sync Errors: " -NoNewline -ForegroundColor White
    Write-Host $usersWithErrors -ForegroundColor $(if($usersWithErrors -gt 0){"Red"}else{"Green"})
    
    Write-Host "  - Stale Sync (>7 days): " -NoNewline -ForegroundColor White
    Write-Host $staleSyncUsers -ForegroundColor $(if($staleSyncUsers -gt 0){"Yellow"}else{"Green"})
    
    $criticalRisk = ($script:SyncStatusData | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:SyncStatusData | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:SyncStatusData | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:SyncStatusData | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "`n[RISK BREAKDOWN]" -ForegroundColor Cyan
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Red
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Yellow
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    # Group by domain
    $byDomain = $script:SyncStatusData | Where-Object { $_.OnPremisesDomainName } | Group-Object OnPremisesDomainName | Sort-Object Count -Descending
    if ($byDomain.Count -gt 0) {
        Write-Host "`n[USERS BY DOMAIN]" -ForegroundColor Cyan
        $byDomain | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Group by error category
    $byErrorCategory = $script:SyncStatusData | Where-Object { $_.ErrorCategories } | Group-Object ErrorCategories | Sort-Object Count -Descending
    if ($byErrorCategory.Count -gt 0) {
        Write-Host "`n[ERROR CATEGORIES]" -ForegroundColor Cyan
        $byErrorCategory | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Red
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
    
    Write-Host "Users in results: " -NoNewline -ForegroundColor White
    Write-Host $script:SyncStatusData.Count -ForegroundColor Yellow
    
    if ($script:SyncStatusData.Count -gt 0) {
        $syncedUsers = ($script:SyncStatusData | Where-Object { $_.OnPremisesSyncEnabled -eq $true }).Count
        $cloudOnlyUsers = ($script:SyncStatusData | Where-Object { $_.OnPremisesSyncEnabled -eq $false }).Count
        $usersWithErrors = ($script:SyncStatusData | Where-Object { $_.HasSyncErrors -eq $true }).Count
        $staleSyncUsers = ($script:SyncStatusData | Where-Object { $null -ne $_.DaysSinceLastSync -and $_.DaysSinceLastSync -gt 7 }).Count
        
        Write-Host "  - Synced from On-Premises: " -NoNewline -ForegroundColor White
        Write-Host $syncedUsers -ForegroundColor Cyan
        
        Write-Host "  - Cloud-Only: " -NoNewline -ForegroundColor White
        Write-Host $cloudOnlyUsers -ForegroundColor Green
        
        Write-Host "  - Users with Sync Errors: " -NoNewline -ForegroundColor White
        Write-Host $usersWithErrors -ForegroundColor $(if($usersWithErrors -gt 0){"Red"}else{"Green"})
        
        Write-Host "  - Stale Sync (>7 days): " -NoNewline -ForegroundColor White
        Write-Host $staleSyncUsers -ForegroundColor $(if($staleSyncUsers -gt 0){"Yellow"}else{"Green"})
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "SYNC STATUS DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:SyncStatusData | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.UserPrincipalName -ForegroundColor White
            
            Write-Host "  Display Name: $($_.DisplayName)" -ForegroundColor Gray
            Write-Host "  Sync Source: " -NoNewline -ForegroundColor Gray
            Write-Host $_.SyncSource -ForegroundColor $(if($_.OnPremisesSyncEnabled){"Cyan"}else{"Green"})
            
            if ($_.OnPremisesDomainName) {
                Write-Host "  On-Premises Domain: $($_.OnPremisesDomainName)" -ForegroundColor Gray
            }
            if ($_.OnPremisesSamAccountName) {
                Write-Host "  SAM Account Name: $($_.OnPremisesSamAccountName)" -ForegroundColor Gray
            }
            if ($_.OnPremisesDistinguishedName) {
                Write-Host "  Distinguished Name: $($_.OnPremisesDistinguishedName)" -ForegroundColor Gray
            }
            
            Write-Host "  Account Status: " -NoNewline -ForegroundColor Gray
            if ($_.AccountEnabled) {
                Write-Host "Enabled" -ForegroundColor Green
            }
            else {
                Write-Host "Disabled" -ForegroundColor Yellow
            }
            
            if ($_.OnPremisesLastSyncDateTime) {
                Write-Host "  Last Sync: " -NoNewline -ForegroundColor Gray
                Write-Host "$($_.OnPremisesLastSyncDateTime.ToString('yyyy-MM-dd HH:mm:ss'))" -NoNewline -ForegroundColor $(if($_.DaysSinceLastSync -gt 7){"Yellow"}elseif($_.DaysSinceLastSync -gt 30){"Red"}else{"Green"})
                if ($null -ne $_.DaysSinceLastSync) {
                    Write-Host " ($($_.DaysSinceLastSync) days ago)" -ForegroundColor DarkGray
                }
            }
            else {
                Write-Host "  Last Sync: Never" -ForegroundColor DarkGray
            }
            
            if ($_.HasSyncErrors) {
                Write-Host "  Sync Errors: " -NoNewline -ForegroundColor Gray
                Write-Host "$($_.ErrorCount) error(s)" -ForegroundColor Red
                Write-Host "  Error Categories: $($_.ErrorCategories)" -ForegroundColor Red
                
                if ($_.ErrorDetails -and $_.ErrorDetails.Count -gt 0) {
                    Write-Host "  Error Details:" -ForegroundColor DarkRed
                    foreach ($errorDetail in $_.ErrorDetails) {
                        Write-Host "    - Category: $($errorDetail.Category)" -ForegroundColor DarkRed
                        if ($errorDetail.Property) {
                            Write-Host "      Property: $($errorDetail.Property)" -ForegroundColor DarkRed
                        }
                        if ($errorDetail.Value) {
                            Write-Host "      Value: $($errorDetail.Value)" -ForegroundColor DarkRed
                        }
                        if ($errorDetail.OccurredDateTime) {
                            Write-Host "      Occurred: $($errorDetail.OccurredDateTime)" -ForegroundColor DarkRed
                        }
                    }
                }
            }
            else {
                Write-Host "  Sync Errors: None" -ForegroundColor Green
            }
            
            if ($_.RiskFactors) {
                Write-Host "  Risk Factors: $($_.RiskFactors)" -ForegroundColor $(if($_.RiskLevel -eq "HIGH" -or $_.RiskLevel -eq "CRITICAL"){"Red"}else{"Yellow"})
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        if ($OnlySyncErrors) {
            Write-Host "`n[+] No users with sync errors found." -ForegroundColor Green
        }
        elseif ($OnlyStaleSync) {
            Write-Host "`n[+] No users with stale sync found." -ForegroundColor Green
        }
        else {
            Write-Host "`n[!] No sync data found." -ForegroundColor Yellow
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
    
    if ($script:SyncStatusData.Count -eq 0) {
        Write-Host "`n[*] No sync data to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        # Prepare data for export (flatten error details)
        $exportData = $script:SyncStatusData | ForEach-Object {
            $obj = [PSCustomObject]@{
                DisplayName = $_.DisplayName
                UserPrincipalName = $_.UserPrincipalName
                Email = $_.Email
                AccountEnabled = $_.AccountEnabled
                UserType = $_.UserType
                SyncSource = $_.SyncSource
                OnPremisesSyncEnabled = $_.OnPremisesSyncEnabled
                OnPremisesDomainName = $_.OnPremisesDomainName
                OnPremisesSamAccountName = $_.OnPremisesSamAccountName
                OnPremisesDistinguishedName = $_.OnPremisesDistinguishedName
                OnPremisesLastSyncDateTime = $_.OnPremisesLastSyncDateTime
                DaysSinceLastSync = $_.DaysSinceLastSync
                OnPremisesImmutableId = $_.OnPremisesImmutableId
                OnPremisesSecurityIdentifier = $_.OnPremisesSecurityIdentifier
                HasSyncErrors = $_.HasSyncErrors
                ErrorCount = $_.ErrorCount
                ErrorCategories = $_.ErrorCategories
                RiskLevel = $_.RiskLevel
                RiskFactors = $_.RiskFactors
            }
            
            # Add error details as JSON string for CSV
            if ($_.ErrorDetails -and $_.ErrorDetails.Count -gt 0) {
                $obj | Add-Member -NotePropertyName "ErrorDetailsJSON" -NotePropertyValue ($_.ErrorDetails | ConvertTo-Json -Compress) -Force
            }
            else {
                $obj | Add-Member -NotePropertyName "ErrorDetailsJSON" -NotePropertyValue $null -Force
            }
            
            $obj
        }
        
        switch ($extension) {
            ".csv" {
                $exportData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                # For JSON, include full error details
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
        Start-SyncScan
        
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
        
        Write-Host "`n[*] Directory sync check completed successfully!" -ForegroundColor Green
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

