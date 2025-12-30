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
    Analyzes Azure Entra ID registered devices to identify security risks, compliance gaps, and device trust issues.

.DESCRIPTION
    This script queries Azure Entra ID to enumerate all registered devices and performs a comprehensive
    security audit including:
    - Enumerates all registered devices and their configurations
    - Identifies non-compliant devices
    - Detects BYOD/personal devices
    - Identifies devices with stale sign-ins
    - Checks Intune compliance policies
    - Risk assessment based on device trust, compliance, and management status
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.
    
    Information collected includes:
    - Device identification and trust type
    - Compliance status and management state
    - Device ownership (Corporate vs Personal)
    - Last sign-in activity and registration dates
    - Operating system and hardware details
    - Risk assessment based on compliance gaps and trust issues

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

.PARAMETER IncludeDisabled
    Include disabled devices in the results.

.PARAMETER OnlyNonCompliant
    Show only non-compliant devices.

.PARAMETER OnlyBYOD
    Show only BYOD/personal devices.

.PARAMETER OnlyStale
    Show only devices with stale sign-ins (>90 days).

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraDeviceCheck.ps1
    # Analyze all registered devices

.EXAMPLE
    .\Invoke-EntraDeviceCheck.ps1 -ExportPath "devices.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraDeviceCheck.ps1 -TenantId "your-tenant-id" -ExportPath "results.json"
    # Specify tenant and export to JSON

.EXAMPLE
    .\Invoke-EntraDeviceCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraDeviceCheck.ps1 -OnlyNonCompliant -Matrix
    # Display only non-compliant devices in matrix format

.EXAMPLE
    .\Invoke-EntraDeviceCheck.ps1 -OnlyBYOD -ExportPath "byod-devices.csv"
    # Show only BYOD devices and export
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
    [switch]$IncludeDisabled,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyNonCompliant,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyBYOD,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyStale,

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

# Required scopes for device checking
$script:RequiredScopes = @(
    "Device.Read.All",
    "Directory.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Device.Read.All",
    "Directory.Read.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:Devices = @()
$script:TotalDevicesScanned = 0
$script:CompliancePolicies = @()
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
    Write-Host "    Entra ID Device Check - Device Trust and Compliance Analysis" -ForegroundColor Yellow
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
            Write-Host "[!] Some features may be limited (Intune compliance policies may not be available)" -ForegroundColor Yellow
            
            return $true
        }
        catch {
            Write-Host "[ERROR] Authentication failed: $_" -ForegroundColor Red
            return $false
        }
    }
}

# Get Intune compliance policies
function Get-IntuneCompliancePolicies {
    Write-Host "`n[*] Retrieving Intune compliance policies..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?`$expand=assignments&`$top=999"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        $policies = $response.value
        
        if ($policies.Count -gt 0) {
            Write-Host "[+] Found $($policies.Count) compliance policy/policies" -ForegroundColor Green
            
            foreach ($policy in $policies) {
                $script:CompliancePolicies += @{
                    Id = $policy.id
                    DisplayName = $policy.displayName
                    Description = $policy.description
                    CreatedDateTime = $policy.createdDateTime
                    LastModifiedDateTime = $policy.lastModifiedDateTime
                    Assignments = $policy.assignments
                }
            }
        }
        else {
            Write-Host "[!] No compliance policies found" -ForegroundColor Yellow
        }
        
        return $true
    }
    catch {
        if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
            Write-Host "[!] Access denied. Requires DeviceManagementConfiguration.Read.All permission" -ForegroundColor Yellow
            Write-Host "[!] Continuing without Intune compliance policy data" -ForegroundColor Yellow
        }
        else {
            Write-Host "[!] Failed to retrieve compliance policies: $_" -ForegroundColor Yellow
        }
        return $false
    }
}

# Analyze device and extract details
function Analyze-Device {
    param(
        [Parameter(Mandatory = $true)]
        $Device
    )
    
    # Determine trust type (how device is joined)
    $trustType = $Device.TrustType
    $joinType = switch ($trustType) {
        "AzureAd" { "Azure AD Joined" }
        "ServerAd" { "Hybrid Azure AD Joined" }
        "Workplace" { "Azure AD Registered (BYOD)" }
        default { "Unknown" }
    }
    
    # Determine device ownership
    $ownership = $Device.DeviceOwnership
    $isBYOD = ($ownership -eq "Personal") -or ($trustType -eq "Workplace")
    
    # Determine compliance status
    $isCompliant = $Device.IsCompliant
    $isManaged = $Device.IsManaged
    
    # Calculate days since last sign-in
    $daysSinceLastSignIn = -1
    $isStale = $false
    if ($Device.ApproximateLastSignInDateTime) {
        $lastSignIn = [DateTime]$Device.ApproximateLastSignInDateTime
        $daysSinceLastSignIn = ([DateTime]::Now - $lastSignIn).Days
        $isStale = $daysSinceLastSignIn -gt 90
    }
    
    # Calculate days since registration
    $daysSinceRegistration = -1
    if ($Device.RegistrationDateTime) {
        $registrationDate = [DateTime]$Device.RegistrationDateTime
        $daysSinceRegistration = ([DateTime]::Now - $registrationDate).Days
    }
    
    # Determine risk level
    $riskLevel = "LOW"
    $riskReasons = @()
    
    # CRITICAL: Non-compliant device
    if ($isCompliant -eq $false) {
        $riskLevel = "CRITICAL"
        $riskReasons += "Non-compliant"
    }
    # HIGH: Compliance unknown OR unmanaged device OR stale sign-in
    elseif ($null -eq $isCompliant) {
        $riskLevel = "HIGH"
        $riskReasons += "Compliance unknown"
    }
    elseif (-not $isManaged) {
        $riskLevel = "HIGH"
        $riskReasons += "Unmanaged device"
    }
    elseif ($isStale) {
        $riskLevel = "HIGH"
        $riskReasons += "Stale sign-in ($daysSinceLastSignIn days)"
    }
    # MEDIUM: BYOD device OR disabled device
    elseif ($isBYOD) {
        $riskLevel = "MEDIUM"
        $riskReasons += "BYOD/Personal device"
    }
    elseif (-not $Device.AccountEnabled) {
        $riskLevel = "MEDIUM"
        $riskReasons += "Disabled device"
    }
    
    return @{
        Device = $Device
        RiskLevel = $riskLevel
        RiskReasons = ($riskReasons -join "; ")
        TrustType = $trustType
        JoinType = $joinType
        IsCompliant = $isCompliant
        IsManaged = $isManaged
        DeviceOwnership = $ownership
        IsBYOD = $isBYOD
        DaysSinceLastSignIn = $daysSinceLastSignIn
        IsStale = $isStale
        DaysSinceRegistration = $daysSinceRegistration
        ManagementType = $Device.ManagementType
    }
}

# Main scanning function
function Start-DeviceScan {
    Write-Host "`n[*] Starting device scan..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get all devices
        $properties = @(
            'Id',
            'DisplayName',
            'DeviceId',
            'OperatingSystem',
            'OperatingSystemVersion',
            'TrustType',
            'IsCompliant',
            'IsManaged',
            'ManagementType',
            'DeviceOwnership',
            'RegistrationDateTime',
            'ApproximateLastSignInDateTime',
            'AccountEnabled',
            'Manufacturer',
            'Model',
            'EnrollmentType'
        )
        
        Write-Host "[*] Retrieving all registered devices..." -ForegroundColor Cyan
        $rawDevices = Get-MgDevice -All -Property $properties -ErrorAction Stop
        
        if ($rawDevices.Count -eq 0) {
            Write-Host "[!] No devices found" -ForegroundColor Yellow
            return
        }
        
        $script:TotalDevicesScanned = $rawDevices.Count
        Write-Host "[+] Found $($rawDevices.Count) registered device(s)" -ForegroundColor Green
        
        $progressCounter = 0
        
        foreach ($device in $rawDevices) {
            $progressCounter++
            
            # Progress indicator
            if ($progressCounter % 50 -eq 0 -or $progressCounter -eq $rawDevices.Count) {
                $percentComplete = [math]::Round(($progressCounter / $rawDevices.Count) * 100, 1)
                Write-Host "`r[*] Progress: $progressCounter/$($rawDevices.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
            }
            
            # Skip disabled if not included
            if (-not $IncludeDisabled -and -not $device.AccountEnabled) {
                continue
            }
            
            try {
                # Analyze device
                $analysis = Analyze-Device -Device $device
                
                # Filter: Only non-compliant
                if ($OnlyNonCompliant -and $analysis.IsCompliant -ne $false) {
                    continue
                }
                
                # Filter: Only BYOD
                if ($OnlyBYOD -and -not $analysis.IsBYOD) {
                    continue
                }
                
                # Filter: Only stale
                if ($OnlyStale -and -not $analysis.IsStale) {
                    continue
                }
                
                # Build device info object
                $deviceInfo = [PSCustomObject]@{
                    DeviceId = $device.DeviceId
                    DisplayName = $device.DisplayName
                    OperatingSystem = $device.OperatingSystem
                    OSVersion = $device.OperatingSystemVersion
                    TrustType = $analysis.TrustType
                    JoinType = $analysis.JoinType
                    IsCompliant = $analysis.IsCompliant
                    IsManaged = $analysis.IsManaged
                    ManagementType = $device.ManagementType
                    DeviceOwnership = $analysis.DeviceOwnership
                    IsBYOD = $analysis.IsBYOD
                    RegistrationDateTime = $device.RegistrationDateTime
                    DaysSinceRegistration = $analysis.DaysSinceRegistration
                    ApproximateLastSignInDateTime = $device.ApproximateLastSignInDateTime
                    DaysSinceLastSignIn = $analysis.DaysSinceLastSignIn
                    IsStale = $analysis.IsStale
                    AccountEnabled = $device.AccountEnabled
                    Manufacturer = $device.Manufacturer
                    Model = $device.Model
                    EnrollmentType = $device.EnrollmentType
                    RiskLevel = $analysis.RiskLevel
                    RiskReasons = $analysis.RiskReasons
                }
                
                $script:Devices += $deviceInfo
            }
            catch {
                Write-Host "`n[!] Error processing device $($device.DisplayName): $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n[+] Scan complete!" -ForegroundColor Green
        
        # Try to get Intune compliance policies if permissions allow
        Get-IntuneCompliancePolicies | Out-Null
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve devices: $_" -ForegroundColor Red
        Write-Host "[!] Ensure you have Device.Read.All permission" -ForegroundColor Yellow
    }
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - DEVICE TRUST AND COMPLIANCE ANALYSIS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:Devices.Count -eq 0) {
        Write-Host "`n[!] No devices found matching the specified criteria." -ForegroundColor Yellow
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:Devices | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Compliant';Expression={
            if($null -eq $_.IsCompliant){'Unknown'}
            elseif($_.IsCompliant){'Yes'}
            else{'No'}
        }},
        @{Name='Managed';Expression={if($_.IsManaged){'Yes'}else{'No'}}},
        @{Name='BYOD';Expression={if($_.IsBYOD){'Yes'}else{'No'}}},
        @{Name='Join Type';Expression={$_.JoinType}},
        @{Name='Device Name';Expression={$_.DisplayName}},
        @{Name='OS';Expression={$_.OperatingSystem}},
        @{Name='Last Sign-In';Expression={
            if($_.DaysSinceLastSignIn -eq -1){'Never'}
            elseif($_.DaysSinceLastSignIn -eq 0){'Today'}
            elseif($_.DaysSinceLastSignIn -eq 1){'Yesterday'}
            elseif($_.DaysSinceLastSignIn -gt 90){'Stale'}
            else{"$($_.DaysSinceLastSignIn)d ago"}
        }},
        @{Name='Status';Expression={if($_.AccountEnabled){'Enabled'}else{'Disabled'}}}
    
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
    Write-Host "Total devices analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:Devices.Count -ForegroundColor Yellow
    
    $criticalRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Cyan
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    $compliant = ($script:Devices | Where-Object { $_.IsCompliant -eq $true }).Count
    $nonCompliant = ($script:Devices | Where-Object { $_.IsCompliant -eq $false }).Count
    $complianceUnknown = ($script:Devices | Where-Object { $null -eq $_.IsCompliant }).Count
    $managed = ($script:Devices | Where-Object { $_.IsManaged -eq $true }).Count
    $unmanaged = ($script:Devices | Where-Object { $_.IsManaged -eq $false }).Count
    $byod = ($script:Devices | Where-Object { $_.IsBYOD -eq $true }).Count
    $stale = ($script:Devices | Where-Object { $_.IsStale -eq $true }).Count
    $disabled = ($script:Devices | Where-Object { $_.AccountEnabled -eq $false }).Count
    
    Write-Host "`n[COMPLIANCE STATUS]" -ForegroundColor Cyan
    Write-Host "  Compliant: " -NoNewline -ForegroundColor White
    Write-Host $compliant -ForegroundColor Green
    Write-Host "  Non-compliant: " -NoNewline -ForegroundColor White
    Write-Host $nonCompliant -ForegroundColor Red
    Write-Host "  Compliance unknown: " -NoNewline -ForegroundColor White
    Write-Host $complianceUnknown -ForegroundColor Yellow
    
    Write-Host "`n[MANAGEMENT STATUS]" -ForegroundColor Cyan
    Write-Host "  Managed: " -NoNewline -ForegroundColor White
    Write-Host $managed -ForegroundColor Green
    Write-Host "  Unmanaged: " -NoNewline -ForegroundColor White
    Write-Host $unmanaged -ForegroundColor Yellow
    
    Write-Host "`n[DEVICE TYPES]" -ForegroundColor Cyan
    Write-Host "  BYOD/Personal: " -NoNewline -ForegroundColor White
    Write-Host $byod -ForegroundColor Yellow
    Write-Host "  Corporate: " -NoNewline -ForegroundColor White
    Write-Host ($script:Devices.Count - $byod) -ForegroundColor Green
    
    Write-Host "`n[JOIN TYPES]" -ForegroundColor Cyan
    $azureAdJoined = ($script:Devices | Where-Object { $_.TrustType -eq "AzureAd" }).Count
    $hybridJoined = ($script:Devices | Where-Object { $_.TrustType -eq "ServerAd" }).Count
    $registered = ($script:Devices | Where-Object { $_.TrustType -eq "Workplace" }).Count
    Write-Host "  Azure AD Joined: " -NoNewline -ForegroundColor White
    Write-Host $azureAdJoined -ForegroundColor Green
    Write-Host "  Hybrid Azure AD Joined: " -NoNewline -ForegroundColor White
    Write-Host $hybridJoined -ForegroundColor Green
    Write-Host "  Azure AD Registered (BYOD): " -NoNewline -ForegroundColor White
    Write-Host $registered -ForegroundColor Yellow
    
    Write-Host "`n[ACTIVITY STATUS]" -ForegroundColor Cyan
    Write-Host "  Stale sign-ins (>90 days): " -NoNewline -ForegroundColor White
    Write-Host $stale -ForegroundColor Red
    Write-Host "  Disabled devices: " -NoNewline -ForegroundColor White
    Write-Host $disabled -ForegroundColor Yellow
    
    # Intune compliance policies summary
    if ($script:CompliancePolicies.Count -gt 0) {
        Write-Host "`n[INTUNE COMPLIANCE POLICIES]" -ForegroundColor Cyan
        Write-Host "  Total policies: " -NoNewline -ForegroundColor White
        Write-Host $script:CompliancePolicies.Count -ForegroundColor Yellow
        Write-Host "  (Use detailed view to see policy assignments)" -ForegroundColor DarkGray
    }
    
    Write-Host ""
}

# Display results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal devices scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalDevicesScanned -ForegroundColor Yellow
    
    Write-Host "Devices analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:Devices.Count -ForegroundColor $(if($script:Devices.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:Devices.Count -gt 0) {
        $criticalRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "DEVICE DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:Devices | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.DisplayName -ForegroundColor White
            
            Write-Host "  Device ID: $($_.DeviceId)" -ForegroundColor Gray
            Write-Host "  Operating System: $($_.OperatingSystem) $($_.OSVersion)" -ForegroundColor Gray
            Write-Host "  Join Type: $($_.JoinType)" -ForegroundColor Gray
            
            Write-Host "  Compliance Status: " -NoNewline -ForegroundColor Gray
            if ($null -eq $_.IsCompliant) {
                Write-Host "Unknown" -ForegroundColor Yellow
            }
            elseif ($_.IsCompliant) {
                Write-Host "Compliant" -ForegroundColor Green
            }
            else {
                Write-Host "Non-compliant" -ForegroundColor Red
            }
            
            Write-Host "  Managed: " -NoNewline -ForegroundColor Gray
            if ($_.IsManaged) {
                Write-Host "Yes" -ForegroundColor Green
            }
            else {
                Write-Host "No" -ForegroundColor Yellow
            }
            
            Write-Host "  Device Ownership: $($_.DeviceOwnership)" -ForegroundColor Gray
            if ($_.IsBYOD) {
                Write-Host "  [!] BYOD/Personal Device" -ForegroundColor Yellow
            }
            
            if ($_.RiskReasons) {
                Write-Host "  Risk Reasons: $($_.RiskReasons)" -ForegroundColor $(if($_.RiskLevel -eq "CRITICAL"){"Red"}elseif($_.RiskLevel -eq "HIGH"){"Yellow"}else{"Gray"})
            }
            
            Write-Host "  Management Type: $($_.ManagementType)" -ForegroundColor Gray
            
            if ($_.RegistrationDateTime) {
                Write-Host "  Registered: $($_.RegistrationDateTime) ($($_.DaysSinceRegistration) days ago)" -ForegroundColor Gray
            }
            
            Write-Host "  Last Sign-In: " -NoNewline -ForegroundColor Gray
            if ($_.ApproximateLastSignInDateTime) {
                Write-Host "$($_.ApproximateLastSignInDateTime) " -NoNewline -ForegroundColor $(if($_.IsStale){"Red"}elseif($_.DaysSinceLastSignIn -gt 30){"Yellow"}else{"Green"})
                if ($_.DaysSinceLastSignIn -ge 0) {
                    Write-Host "($($_.DaysSinceLastSignIn) days ago)" -ForegroundColor $(if($_.IsStale){"Red"}elseif($_.DaysSinceLastSignIn -gt 30){"Yellow"}else{"Green"})
                }
            }
            else {
                Write-Host "Never signed in" -ForegroundColor DarkGray
            }
            
            Write-Host "  Account Status: " -NoNewline -ForegroundColor Gray
            if ($_.AccountEnabled) {
                Write-Host "Enabled" -ForegroundColor Green
            }
            else {
                Write-Host "Disabled" -ForegroundColor Yellow
            }
            
            if ($_.Manufacturer) {
                Write-Host "  Manufacturer: $($_.Manufacturer)" -ForegroundColor Gray
            }
            if ($_.Model) {
                Write-Host "  Model: $($_.Model)" -ForegroundColor Gray
            }
            if ($_.EnrollmentType) {
                Write-Host "  Enrollment Type: $($_.EnrollmentType)" -ForegroundColor Gray
            }
        }
        
        # Show Intune compliance policies if available
        if ($script:CompliancePolicies.Count -gt 0) {
            Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
            Write-Host "INTUNE COMPLIANCE POLICIES:" -ForegroundColor Cyan
            Write-Host ("-" * 70) -ForegroundColor Cyan
            
            foreach ($policy in $script:CompliancePolicies) {
                Write-Host "`n  Policy: $($policy.DisplayName)" -ForegroundColor Cyan
                if ($policy.Description) {
                    Write-Host "    Description: $($policy.Description)" -ForegroundColor Gray
                }
                Write-Host "    Created: $($policy.CreatedDateTime)" -ForegroundColor Gray
                Write-Host "    Last Modified: $($policy.LastModifiedDateTime)" -ForegroundColor Gray
                if ($policy.Assignments -and $policy.Assignments.Count -gt 0) {
                    Write-Host "    Assignments: $($policy.Assignments.Count)" -ForegroundColor Gray
                }
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[!] No devices found matching the specified criteria." -ForegroundColor Yellow
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
    
    if ($script:Devices.Count -eq 0) {
        Write-Host "`n[*] No devices to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        switch ($extension) {
            ".csv" {
                $script:Devices | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $exportData = @{
                    Devices = $script:Devices
                    CompliancePolicies = $script:CompliancePolicies
                    Summary = @{
                        TotalDevicesScanned = $script:TotalDevicesScanned
                        TotalDevicesAnalyzed = $script:Devices.Count
                        CriticalRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
                        HighRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
                        MediumRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
                        LowRisk = ($script:Devices | Where-Object { $_.RiskLevel -eq "LOW" }).Count
                        NonCompliant = ($script:Devices | Where-Object { $_.IsCompliant -eq $false }).Count
                        BYOD = ($script:Devices | Where-Object { $_.IsBYOD -eq $true }).Count
                        Stale = ($script:Devices | Where-Object { $_.IsStale -eq $true }).Count
                    }
                }
                $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                # Default to CSV if no recognized extension
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:Devices | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        Start-DeviceScan
        
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
        
        Write-Host "`n[*] Device check completed successfully!" -ForegroundColor Green
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

