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
    Comprehensive Azure Network Security audit for identifying network misconfigurations enabling lateral movement.

.DESCRIPTION
    This script performs a deep analysis of Azure network security configurations to identify
    potential vulnerabilities and misconfigurations that could lead to unauthorized access,
    lateral movement, or exposure of critical resources.
    
    Key features:
    - NSG rules analysis (overly permissive: 0.0.0.0/0, Any-Any)
    - Open management ports detection (RDP 3389, SSH 22, WinRM 5985/5986)
    - Azure Bastion usage vs direct RDP/SSH analysis
    - DDoS protection status verification
    - Private endpoints vs public endpoints audit
    - VNet peering security analysis
    - ExpressRoute/VPN gateway configuration check
    - Application Security Groups (ASG) analysis
    - Network Watcher and flow logs status
    
    The script uses Azure PowerShell authentication to query network configurations
    across all accessible subscriptions.

.PARAMETER ExportPath
    Optional path to export results (CSV or JSON based on extension).

.PARAMETER SubscriptionId
    Specific subscription ID(s) to scan. If not specified, scans all accessible subscriptions.

.PARAMETER TenantId
    Optional Tenant ID. If not specified, uses the user's home tenant.

.PARAMETER UseAzCliToken
    Use Azure CLI authentication.

.PARAMETER UseAzPowerShellToken
    Use Azure PowerShell authentication.

.PARAMETER UseDeviceCode
    Use device code authentication flow. Recommended for embedded terminals where the login popup may be hidden.

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

.PARAMETER OnlyCritical
    Show only resources with CRITICAL risk findings.

.PARAMETER OnlyOpenPorts
    Show only NSGs with open management ports (RDP, SSH, WinRM).

.PARAMETER OnlyPublicAccess
    Show only resources with public access enabled.

.PARAMETER SkipNSGs
    Skip Network Security Group analysis (NSGs are analyzed by default).

.PARAMETER IncludeVNets
    Include Virtual Network analysis including peerings.

.PARAMETER IncludeGateways
    Include VPN/ExpressRoute gateway analysis.

.PARAMETER IncludeBastion
    Include Azure Bastion analysis.

.PARAMETER IncludeDDoS
    Include DDoS protection status analysis.

.PARAMETER IncludeFlowLogs
    Include NSG flow logs configuration analysis.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.PARAMETER SkipFailedTenants
    Continue processing even when authentication fails for some tenants (common in multi-tenant/guest scenarios).
    Suppresses MFA/Conditional Access warnings for tenants you can't access.

.EXAMPLE
    .\Invoke-EntraNetworkSecurityCheck.ps1
    # Perform comprehensive Network Security audit

.EXAMPLE
    .\Invoke-EntraNetworkSecurityCheck.ps1 -ExportPath "network-audit.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraNetworkSecurityCheck.ps1 -OnlyCritical -Matrix
    # Display only critical findings in matrix format

.EXAMPLE
    .\Invoke-EntraNetworkSecurityCheck.ps1 -OnlyOpenPorts
    # Audit only NSGs with open management ports

.EXAMPLE
    .\Invoke-EntraNetworkSecurityCheck.ps1 -IncludeBastion -IncludeGateways -Matrix
    # Include Bastion and gateway analysis

.EXAMPLE
    .\Invoke-EntraNetworkSecurityCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output

.EXAMPLE
    .\Invoke-EntraNetworkSecurityCheck.ps1 -SkipFailedTenants -Matrix
    # Skip tenants with MFA/CA issues and show results in matrix format
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [switch]$UseAzCliToken,

    [Parameter(Mandatory = $false)]
    [switch]$UseAzPowerShellToken,

    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode,

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
    [switch]$OnlyCritical,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyOpenPorts,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyPublicAccess,

    [Parameter(Mandatory = $false)]
    [switch]$SkipNSGs,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeVNets,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeGateways,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeBastion,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDDoS,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeFlowLogs,

    [Parameter(Mandatory = $false)]
    [switch]$Matrix,

    [Parameter(Mandatory = $false)]
    [switch]$SkipFailedTenants
)

# PowerShell 7+ required
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] This script requires PowerShell 7 or later.' -ForegroundColor Red
    Write-Host ('Current version: PowerShell ' + $PSVersionTable.PSVersion.ToString()) -ForegroundColor Yellow
    Write-Host 'Download PowerShell 7: https://aka.ms/powershell-release?tag=stable' -ForegroundColor Cyan
    exit 1
}

$ErrorActionPreference = "Continue"

# High-risk ports for management access
$script:ManagementPorts = @{
    22 = "SSH"
    23 = "Telnet"
    3389 = "RDP"
    5985 = "WinRM HTTP"
    5986 = "WinRM HTTPS"
    135 = "RPC"
    139 = "NetBIOS"
    445 = "SMB"
    1433 = "SQL Server"
    3306 = "MySQL"
    5432 = "PostgreSQL"
    27017 = "MongoDB"
}

# Commonly exposed sensitive ports
$script:SensitivePorts = @{
    80 = "HTTP"
    443 = "HTTPS"
    21 = "FTP"
    25 = "SMTP"
    53 = "DNS"
    8080 = "HTTP Proxy"
    8443 = "HTTPS Alt"
}

# Track state
$script:NSGFindings = @()
$script:VNetFindings = @()
$script:GatewayFindings = @()
$script:BastionFindings = @()
$script:DDoSFindings = @()
$script:TotalNSGs = 0
$script:TotalVNets = 0
$script:TotalSubscriptions = 0
$script:SkippedSubscriptions = @()
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
    Write-Host "    Azure Network Security Audit" -ForegroundColor Yellow
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

# Check if required Az modules are installed
function Test-AzModules {
    Write-Host "[*] Checking Azure PowerShell modules..." -ForegroundColor Cyan
    
    $modules = @(
        "Az.Accounts",
        "Az.Network",
        "Az.Resources"
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

# Initialize and import Az modules
function Initialize-AzModules {
    Write-Host "[*] Initializing Azure PowerShell modules..." -ForegroundColor Cyan
    
    try {
        # Remove any loaded Az modules to avoid version conflicts
        $loadedModules = Get-Module Az.* 
        if ($loadedModules) {
            Write-Host "[*] Cleaning up loaded Az modules..." -ForegroundColor Yellow
            $loadedModules | ForEach-Object {
                Remove-Module $_.Name -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Import modules
        Write-Host "[*] Importing Az.Accounts..." -ForegroundColor Cyan
        Import-Module Az.Accounts -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.Network..." -ForegroundColor Cyan
        Import-Module Az.Network -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.Resources..." -ForegroundColor Cyan
        Import-Module Az.Resources -Force -ErrorAction Stop
        
        Write-Host "[+] Modules imported successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to import modules: $_" -ForegroundColor Red
        Write-Host "[*] Try running: Update-Module Az -Force" -ForegroundColor Yellow
        return $false
    }
}

# Authenticate to Azure
function Connect-AzureService {
    Write-Host "`n[*] Authenticating to Azure..." -ForegroundColor Cyan
    
    # Check if already connected
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($context) {
        Write-Host "[+] Already connected to Azure" -ForegroundColor Green
        Write-Host "[+] Tenant: $($context.Tenant.Id)" -ForegroundColor Green
        Write-Host "[+] Account: $($context.Account.Id)" -ForegroundColor Green
        Write-Host "[+] Subscription: $($context.Subscription.Name)" -ForegroundColor Green
        return $true
    }
    
    # Device code authentication
    if ($UseDeviceCode) {
        try {
            Write-Host "[*] Using device code authentication..." -ForegroundColor Cyan
            $connectParams = @{
                UseDeviceAuthentication = $true
            }
            if ($TenantId) {
                $connectParams['TenantId'] = $TenantId
            }
            Connect-AzAccount @connectParams -ErrorAction Stop
            $context = Get-AzContext
            Write-Host "[+] Connected to Azure" -ForegroundColor Green
            Write-Host "[+] Tenant: $($context.Tenant.Id)" -ForegroundColor Green
            Write-Host "[+] Account: $($context.Account.Id)" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "[ERROR] Device code authentication failed: $_" -ForegroundColor Red
            return $false
        }
    }
    
    # Azure CLI token
    if ($UseAzCliToken) {
        try {
            Write-Host "[*] Attempting to use Azure CLI token..." -ForegroundColor Cyan
            Connect-AzAccount -UseDeviceAuthentication:$false -ErrorAction Stop
            $context = Get-AzContext
            Write-Host "[+] Connected using Azure CLI token" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "[!] Failed to use Azure CLI token, falling back to interactive..." -ForegroundColor Yellow
        }
    }
    
    # Interactive authentication
    try {
        $connectParams = @{}
        if ($TenantId) {
            $connectParams['TenantId'] = $TenantId
        }
        
        Connect-AzAccount @connectParams -ErrorAction Stop
        $context = Get-AzContext
        
        Write-Host "[+] Connected to Azure" -ForegroundColor Green
        Write-Host "[+] Tenant: $($context.Tenant.Id)" -ForegroundColor Green
        Write-Host "[+] Account: $($context.Account.Id)" -ForegroundColor Green
        Write-Host "[+] Subscription: $($context.Subscription.Name)" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Host "[ERROR] Authentication failed: $_" -ForegroundColor Red
        return $false
    }
}

# Get all accessible subscriptions
function Get-AccessibleSubscriptions {
    Write-Host "`n[*] Retrieving accessible subscriptions..." -ForegroundColor Cyan
    
    if ($SkipFailedTenants) {
        Write-Host "[*] SkipFailedTenants enabled - will suppress MFA/CA warnings" -ForegroundColor Yellow
    }
    
    try {
        Invoke-StealthDelay
        
        $subscriptions = @()
        
        if ($SubscriptionId -and $SubscriptionId.Count -gt 0) {
            foreach ($subId in $SubscriptionId) {
                $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                if ($sub) {
                    $subscriptions += $sub
                }
                else {
                    Write-Host "[!] Subscription $subId not found or not accessible" -ForegroundColor Yellow
                }
            }
        }
        else {
            # Suppress warnings when SkipFailedTenants is enabled
            if ($SkipFailedTenants) {
                $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
                if (-not $subscriptions) {
                    $subscriptions = @()
                }
            }
            else {
                $subscriptions = Get-AzSubscription -ErrorAction Stop
            }
        }
        
        # Filter out subscriptions we can't actually access
        $accessibleSubs = @()
        foreach ($sub in $subscriptions) {
            if ($sub.State -eq 'Enabled') {
                $accessibleSubs += $sub
            }
        }
        
        Write-Host "[+] Found $($accessibleSubs.Count) accessible subscription(s)" -ForegroundColor Green
        return $accessibleSubs
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve subscriptions: $_" -ForegroundColor Red
        return @()
    }
}

# Get Network Security Groups in a subscription
function Get-SubscriptionNSGs {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        if ($SkipFailedTenants) {
            $nsgs = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
            if (-not $nsgs) {
                $nsgs = @()
            }
        }
        else {
            $nsgs = Get-AzNetworkSecurityGroup -ErrorAction Stop
        }
        
        return $nsgs
    }
    catch {
        if (-not $SkipFailedTenants) {
            Write-Host "[!] Failed to get NSGs in subscription $($Subscription.Name): $_" -ForegroundColor Yellow
        }
        return @()
    }
}

# Get Virtual Networks in a subscription
function Get-SubscriptionVNets {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        if ($SkipFailedTenants) {
            $vnets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
            if (-not $vnets) {
                $vnets = @()
            }
        }
        else {
            $vnets = Get-AzVirtualNetwork -ErrorAction Stop
        }
        
        return $vnets
    }
    catch {
        if (-not $SkipFailedTenants) {
            Write-Host "[!] Failed to get VNets in subscription $($Subscription.Name): $_" -ForegroundColor Yellow
        }
        return @()
    }
}

# Get VPN/ExpressRoute Gateways
function Get-SubscriptionGateways {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        $gateways = @()
        
        # Get VPN Gateways
        $vpnGateways = Get-AzVirtualNetworkGateway -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
        if ($vpnGateways) {
            $gateways += $vpnGateways | ForEach-Object {
                [PSCustomObject]@{
                    Gateway = $_
                    Type = "VPN"
                }
            }
        }
        
        # Get ExpressRoute Gateways
        $erGateways = Get-AzExpressRouteCircuit -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
        if ($erGateways) {
            $gateways += $erGateways | ForEach-Object {
                [PSCustomObject]@{
                    Gateway = $_
                    Type = "ExpressRoute"
                }
            }
        }
        
        return $gateways
    }
    catch {
        return @()
    }
}

# Get Azure Bastion hosts
function Get-SubscriptionBastions {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        $bastions = Get-AzBastion -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
        if (-not $bastions) {
            $bastions = @()
        }
        
        return $bastions
    }
    catch {
        return @()
    }
}

# Get DDoS Protection Plans
function Get-SubscriptionDDoSPlans {
    param(
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    try {
        Invoke-StealthDelay
        
        $ddosPlans = Get-AzDdosProtectionPlan -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
        if (-not $ddosPlans) {
            $ddosPlans = @()
        }
        
        return $ddosPlans
    }
    catch {
        return @()
    }
}

# Get NSG Flow Logs
function Get-NSGFlowLogs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NSGResourceId
    )
    
    try {
        Invoke-StealthDelay
        
        # Extract resource group and NSG name from resource ID
        $parts = $NSGResourceId -split '/'
        $resourceGroup = $parts[4]
        
        # Get Network Watcher in the same region
        $networkWatchers = Get-AzNetworkWatcher -ErrorAction SilentlyContinue
        
        foreach ($watcher in $networkWatchers) {
            $flowLogs = Get-AzNetworkWatcherFlowLog -NetworkWatcher $watcher -ErrorAction SilentlyContinue | Where-Object {
                $_.TargetResourceId -eq $NSGResourceId
            }
            if ($flowLogs) {
                return $flowLogs
            }
        }
        
        return $null
    }
    catch {
        return $null
    }
}

# Analyze NSG rules for security issues
function Analyze-NSGRules {
    param(
        [Parameter(Mandatory = $true)]
        $NSG
    )
    
    $findings = @()
    $riskyRules = @()
    $openManagementPorts = @()
    $anyToAnyRules = @()
    $internetInboundRules = @()
    
    # Combine default and custom rules
    $allRules = @()
    if ($NSG.SecurityRules) {
        $allRules += $NSG.SecurityRules
    }
    if ($NSG.DefaultSecurityRules) {
        $allRules += $NSG.DefaultSecurityRules
    }
    
    foreach ($rule in $NSG.SecurityRules) {
        # Check for inbound allow rules
        if ($rule.Direction -eq "Inbound" -and $rule.Access -eq "Allow") {
            
            # Check source address
            $sourceIsAny = $false
            $sourceIsInternet = $false
            
            if ($rule.SourceAddressPrefix -eq "*" -or $rule.SourceAddressPrefix -eq "0.0.0.0/0") {
                $sourceIsAny = $true
            }
            if ($rule.SourceAddressPrefix -eq "Internet" -or $sourceIsAny) {
                $sourceIsInternet = $true
            }
            if ($rule.SourceAddressPrefixes) {
                foreach ($prefix in $rule.SourceAddressPrefixes) {
                    if ($prefix -eq "*" -or $prefix -eq "0.0.0.0/0") {
                        $sourceIsAny = $true
                        $sourceIsInternet = $true
                    }
                }
            }
            
            # Check destination address
            $destIsAny = $false
            if ($rule.DestinationAddressPrefix -eq "*" -or $rule.DestinationAddressPrefix -eq "0.0.0.0/0") {
                $destIsAny = $true
            }
            if ($rule.DestinationAddressPrefixes) {
                foreach ($prefix in $rule.DestinationAddressPrefixes) {
                    if ($prefix -eq "*" -or $prefix -eq "0.0.0.0/0") {
                        $destIsAny = $true
                    }
                }
            }
            
            # Check for any-to-any rules
            $protocolIsAny = ($rule.Protocol -eq "*")
            $portIsAny = ($rule.DestinationPortRange -eq "*")
            
            if ($sourceIsAny -and $destIsAny -and $protocolIsAny -and $portIsAny) {
                $anyToAnyRules += [PSCustomObject]@{
                    RuleName = $rule.Name
                    Priority = $rule.Priority
                    Source = $rule.SourceAddressPrefix
                    Destination = $rule.DestinationAddressPrefix
                    Port = $rule.DestinationPortRange
                    Protocol = $rule.Protocol
                }
            }
            
            # Track internet inbound rules
            if ($sourceIsInternet) {
                $internetInboundRules += [PSCustomObject]@{
                    RuleName = $rule.Name
                    Priority = $rule.Priority
                    Port = if ($rule.DestinationPortRange) { $rule.DestinationPortRange } else { ($rule.DestinationPortRanges -join ", ") }
                    Protocol = $rule.Protocol
                }
            }
            
            # Check for management ports
            $portsToCheck = @()
            
            # Get all port values to check - handle both single value and array
            $allPortValues = @()
            
            try {
                if ($rule.DestinationPortRange) {
                    # DestinationPortRange can be a single string or array
                    if ($rule.DestinationPortRange -is [System.Collections.IEnumerable] -and $rule.DestinationPortRange -isnot [string]) {
                        foreach ($p in $rule.DestinationPortRange) {
                            $allPortValues += $p.ToString()
                        }
                    }
                    else {
                        $allPortValues += $rule.DestinationPortRange.ToString()
                    }
                }
                
                if ($rule.DestinationPortRanges) {
                    foreach ($p in $rule.DestinationPortRanges) {
                        $allPortValues += $p.ToString()
                    }
                }
            }
            catch {
                # If we can't parse port ranges, skip this rule
                $allPortValues = @()
            }
            
            # Check if any port is wildcard
            if ($allPortValues -contains "*" -or $portIsAny) {
                # All ports are open
                $portsToCheck = @($script:ManagementPorts.Keys)
            }
            else {
                # Parse each port value
                foreach ($portValue in $allPortValues) {
                    try {
                        $pv = $portValue.ToString().Trim()
                        
                        if ([string]::IsNullOrWhiteSpace($pv) -or $pv -eq "*") {
                            continue
                        }
                        
                        if ($pv -match '^(\d+)-(\d+)$') {
                            # Port range (e.g., "80-443")
                            $rangeStart = [int]$matches[1]
                            $rangeEnd = [int]$matches[2]
                            foreach ($mgmtPort in $script:ManagementPorts.Keys) {
                                if ($mgmtPort -ge $rangeStart -and $mgmtPort -le $rangeEnd) {
                                    $portsToCheck += $mgmtPort
                                }
                            }
                        }
                        elseif ($pv -match '^\d+$') {
                            # Single port number
                            $portsToCheck += [int]$pv
                        }
                        # Ignore non-numeric values like service tags
                    }
                    catch {
                        # Skip unparseable port values
                        continue
                    }
                }
            }
            
            foreach ($port in $portsToCheck) {
                if ($script:ManagementPorts.ContainsKey($port) -and $sourceIsInternet) {
                    $openManagementPorts += [PSCustomObject]@{
                        Port = $port
                        Service = $script:ManagementPorts[$port]
                        RuleName = $rule.Name
                        Priority = $rule.Priority
                        Source = $rule.SourceAddressPrefix
                    }
                }
            }
        }
    }
    
    # Build findings
    if ($anyToAnyRules.Count -gt 0) {
        $findings += "CRITICAL: $($anyToAnyRules.Count) Any-to-Any inbound rule(s) detected"
    }
    
    if ($openManagementPorts.Count -gt 0) {
        $uniquePorts = ($openManagementPorts | Select-Object -ExpandProperty Service -Unique) -join ", "
        $findings += "CRITICAL: Open management ports from Internet: $uniquePorts"
    }
    
    if ($internetInboundRules.Count -gt 0) {
        $findings += "WARNING: $($internetInboundRules.Count) rule(s) allow inbound from Internet"
    }
    
    return [PSCustomObject]@{
        Findings = $findings
        RiskyRules = $riskyRules
        OpenManagementPorts = $openManagementPorts
        AnyToAnyRules = $anyToAnyRules
        InternetInboundRules = $internetInboundRules
        HasOpenManagementPorts = ($openManagementPorts.Count -gt 0)
        HasAnyToAny = ($anyToAnyRules.Count -gt 0)
    }
}

# Analyze NSG for security issues
function Analyze-NSGSecurity {
    param(
        [Parameter(Mandatory = $true)]
        $NSG,
        
        [Parameter(Mandatory = $true)]
        $Subscription,
        
        [Parameter(Mandatory = $false)]
        $FlowLogs
    )
    
    $findings = @()
    $riskLevel = "LOW"
    
    # Analyze security rules
    $ruleAnalysis = Analyze-NSGRules -NSG $NSG
    
    if ($ruleAnalysis.HasAnyToAny) {
        $findings += "CRITICAL: Any-to-Any inbound rules allow unrestricted access"
        $riskLevel = "CRITICAL"
    }
    
    if ($ruleAnalysis.HasOpenManagementPorts) {
        $findings += "CRITICAL: Management ports (RDP/SSH/WinRM) open to Internet"
        if ($riskLevel -ne "CRITICAL") {
            $riskLevel = "CRITICAL"
        }
    }
    
    if ($ruleAnalysis.InternetInboundRules.Count -gt 0) {
        $findings += "$($ruleAnalysis.InternetInboundRules.Count) rules allow inbound from Internet"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check if NSG is associated with subnets/NICs
    $associatedSubnets = @()
    $associatedNICs = @()
    
    if ($NSG.Subnets) {
        $associatedSubnets = $NSG.Subnets | ForEach-Object { $_.Id }
    }
    
    if ($NSG.NetworkInterfaces) {
        $associatedNICs = $NSG.NetworkInterfaces | ForEach-Object { $_.Id }
    }
    
    $isAssociated = ($associatedSubnets.Count -gt 0) -or ($associatedNICs.Count -gt 0)
    
    if (-not $isAssociated) {
        $findings += "NSG is not associated with any subnet or NIC"
    }
    
    # Check flow logs
    $hasFlowLogs = $false
    $flowLogsEnabled = $false
    $trafficAnalyticsEnabled = $false
    
    if ($FlowLogs) {
        $hasFlowLogs = $true
        $flowLogsEnabled = $FlowLogs.Enabled
        if ($FlowLogs.FlowAnalyticsConfiguration -and $FlowLogs.FlowAnalyticsConfiguration.NetworkWatcherFlowAnalyticsConfiguration) {
            $trafficAnalyticsEnabled = $FlowLogs.FlowAnalyticsConfiguration.NetworkWatcherFlowAnalyticsConfiguration.Enabled
        }
    }
    
    if (-not $hasFlowLogs) {
        $findings += "NSG flow logs are NOT configured"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    elseif (-not $flowLogsEnabled) {
        $findings += "NSG flow logs are configured but DISABLED"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    return [PSCustomObject]@{
        NSGName = $NSG.Name
        ResourceId = $NSG.Id
        ResourceGroupName = $NSG.ResourceGroupName
        SubscriptionId = $Subscription.Id
        SubscriptionName = $Subscription.Name
        Location = $NSG.Location
        ProvisioningState = $NSG.ProvisioningState
        
        # Association
        IsAssociated = $isAssociated
        AssociatedSubnetCount = $associatedSubnets.Count
        AssociatedNICCount = $associatedNICs.Count
        AssociatedSubnets = ($associatedSubnets | ForEach-Object { ($_ -split '/')[-1] }) -join ", "
        
        # Rules Analysis
        TotalRules = if ($NSG.SecurityRules) { $NSG.SecurityRules.Count } else { 0 }
        DefaultRules = if ($NSG.DefaultSecurityRules) { $NSG.DefaultSecurityRules.Count } else { 0 }
        HasOpenManagementPorts = $ruleAnalysis.HasOpenManagementPorts
        OpenManagementPortsCount = $ruleAnalysis.OpenManagementPorts.Count
        OpenManagementPorts = $ruleAnalysis.OpenManagementPorts
        HasAnyToAny = $ruleAnalysis.HasAnyToAny
        AnyToAnyRulesCount = $ruleAnalysis.AnyToAnyRules.Count
        AnyToAnyRules = $ruleAnalysis.AnyToAnyRules
        InternetInboundRulesCount = $ruleAnalysis.InternetInboundRules.Count
        InternetInboundRules = $ruleAnalysis.InternetInboundRules
        
        # Flow Logs
        HasFlowLogs = $hasFlowLogs
        FlowLogsEnabled = $flowLogsEnabled
        TrafficAnalyticsEnabled = $trafficAnalyticsEnabled
        
        # Risk Assessment
        Findings = $findings
        FindingCount = $findings.Count
        RiskLevel = $riskLevel
        HasMisconfigurations = ($findings.Count -gt 0)
    }
}

# Analyze VNet for security issues
function Analyze-VNetSecurity {
    param(
        [Parameter(Mandatory = $true)]
        $VNet,
        
        [Parameter(Mandatory = $true)]
        $Subscription,
        
        [Parameter(Mandatory = $false)]
        $DDoSPlans
    )
    
    $findings = @()
    $riskLevel = "LOW"
    
    # Check DDoS protection
    $hasDDoSProtection = $false
    $ddosPlanId = $null
    
    if ($VNet.DdosProtectionPlan) {
        $hasDDoSProtection = $true
        $ddosPlanId = $VNet.DdosProtectionPlan.Id
    }
    elseif ($VNet.EnableDdosProtection) {
        $hasDDoSProtection = $true
    }
    
    if (-not $hasDDoSProtection) {
        $findings += "DDoS Protection is NOT enabled"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check VNet peerings
    $peerings = @()
    $crossTenantPeerings = @()
    $allowGatewayTransit = @()
    $useRemoteGateways = @()
    
    if ($VNet.VirtualNetworkPeerings) {
        foreach ($peering in $VNet.VirtualNetworkPeerings) {
            $peeringInfo = [PSCustomObject]@{
                Name = $peering.Name
                PeeringState = $peering.PeeringState
                RemoteVNet = if ($peering.RemoteVirtualNetwork) { ($peering.RemoteVirtualNetwork.Id -split '/')[-1] } else { "Unknown" }
                AllowVirtualNetworkAccess = $peering.AllowVirtualNetworkAccess
                AllowForwardedTraffic = $peering.AllowForwardedTraffic
                AllowGatewayTransit = $peering.AllowGatewayTransit
                UseRemoteGateways = $peering.UseRemoteGateways
            }
            $peerings += $peeringInfo
            
            # Check for potentially risky configurations
            if ($peering.AllowGatewayTransit) {
                $allowGatewayTransit += $peering.Name
            }
            if ($peering.UseRemoteGateways) {
                $useRemoteGateways += $peering.Name
            }
            
            # Check for cross-tenant peering (remote VNet in different tenant)
            if ($peering.RemoteVirtualNetwork -and $peering.RemoteVirtualNetwork.Id) {
                $remoteSubId = ($peering.RemoteVirtualNetwork.Id -split '/')[2]
                if ($remoteSubId -ne $Subscription.Id) {
                    $crossTenantPeerings += $peering.Name
                }
            }
        }
    }
    
    if ($crossTenantPeerings.Count -gt 0) {
        $findings += "Cross-subscription VNet peerings: $($crossTenantPeerings -join ', ')"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    if ($allowGatewayTransit.Count -gt 0) {
        $findings += "Gateway transit enabled on peerings: $($allowGatewayTransit -join ', ')"
    }
    
    # Analyze subnets
    $subnetsWithNSG = 0
    $subnetsWithoutNSG = 0
    $gatewaySubnet = $false
    $bastionSubnet = $false
    
    if ($VNet.Subnets) {
        foreach ($subnet in $VNet.Subnets) {
            if ($subnet.Name -eq "GatewaySubnet") {
                $gatewaySubnet = $true
            }
            elseif ($subnet.Name -eq "AzureBastionSubnet") {
                $bastionSubnet = $true
            }
            else {
                if ($subnet.NetworkSecurityGroup) {
                    $subnetsWithNSG++
                }
                else {
                    $subnetsWithoutNSG++
                }
            }
        }
    }
    
    if ($subnetsWithoutNSG -gt 0) {
        $findings += "$subnetsWithoutNSG subnet(s) without NSG protection"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check for service endpoints
    $serviceEndpoints = @()
    if ($VNet.Subnets) {
        foreach ($subnet in $VNet.Subnets) {
            if ($subnet.ServiceEndpoints) {
                foreach ($endpoint in $subnet.ServiceEndpoints) {
                    if ($serviceEndpoints -notcontains $endpoint.Service) {
                        $serviceEndpoints += $endpoint.Service
                    }
                }
            }
        }
    }
    
    # Check for private endpoints
    $privateEndpointCount = 0
    if ($VNet.Subnets) {
        foreach ($subnet in $VNet.Subnets) {
            if ($subnet.PrivateEndpoints) {
                $privateEndpointCount += $subnet.PrivateEndpoints.Count
            }
        }
    }
    
    return [PSCustomObject]@{
        VNetName = $VNet.Name
        ResourceId = $VNet.Id
        ResourceGroupName = $VNet.ResourceGroupName
        SubscriptionId = $Subscription.Id
        SubscriptionName = $Subscription.Name
        Location = $VNet.Location
        AddressSpace = ($VNet.AddressSpace.AddressPrefixes -join ", ")
        
        # DDoS Protection
        HasDDoSProtection = $hasDDoSProtection
        DDoSPlanId = $ddosPlanId
        
        # Subnets
        TotalSubnets = if ($VNet.Subnets) { $VNet.Subnets.Count } else { 0 }
        SubnetsWithNSG = $subnetsWithNSG
        SubnetsWithoutNSG = $subnetsWithoutNSG
        HasGatewaySubnet = $gatewaySubnet
        HasBastionSubnet = $bastionSubnet
        
        # Peerings
        PeeringCount = $peerings.Count
        Peerings = $peerings
        CrossSubscriptionPeerings = $crossTenantPeerings.Count
        AllowGatewayTransitCount = $allowGatewayTransit.Count
        
        # Service/Private Endpoints
        ServiceEndpoints = ($serviceEndpoints -join ", ")
        ServiceEndpointCount = $serviceEndpoints.Count
        PrivateEndpointCount = $privateEndpointCount
        
        # Risk Assessment
        Findings = $findings
        FindingCount = $findings.Count
        RiskLevel = $riskLevel
        HasMisconfigurations = ($findings.Count -gt 0)
    }
}

# Analyze Bastion for security
function Analyze-BastionSecurity {
    param(
        [Parameter(Mandatory = $true)]
        $Bastion,
        
        [Parameter(Mandatory = $true)]
        $Subscription
    )
    
    $findings = @()
    $riskLevel = "LOW"
    
    # Check Bastion SKU
    $sku = $Bastion.Sku.Name
    $isBasicSku = ($sku -eq "Basic")
    
    if ($isBasicSku) {
        $findings += "Using Basic SKU - limited security features"
    }
    
    # Check if native client support is enabled (security consideration)
    $nativeClientEnabled = $false
    if ($Bastion.EnableNativeClient) {
        $nativeClientEnabled = $true
        $findings += "Native client support is enabled"
    }
    
    # Check IP-based connection (less secure than portal)
    $ipBasedConnectionEnabled = $false
    if ($Bastion.EnableIpConnect) {
        $ipBasedConnectionEnabled = $true
        $findings += "IP-based connection is enabled"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check shareable link (can be a security risk)
    $shareableLinkEnabled = $false
    if ($Bastion.EnableShareableLink) {
        $shareableLinkEnabled = $true
        $findings += "Shareable links are enabled (potential security risk)"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    return [PSCustomObject]@{
        BastionName = $Bastion.Name
        ResourceId = $Bastion.Id
        ResourceGroupName = $Bastion.ResourceGroupName
        SubscriptionId = $Subscription.Id
        SubscriptionName = $Subscription.Name
        Location = $Bastion.Location
        Sku = $sku
        
        # Features
        NativeClientEnabled = $nativeClientEnabled
        IpBasedConnectionEnabled = $ipBasedConnectionEnabled
        ShareableLinkEnabled = $shareableLinkEnabled
        
        # DNS
        DnsName = $Bastion.DnsName
        
        # Risk Assessment
        Findings = $findings
        FindingCount = $findings.Count
        RiskLevel = $riskLevel
        HasMisconfigurations = ($findings.Count -gt 0)
    }
}

# Check if VNets have Bastion protection
function Get-VNetBastionStatus {
    param(
        [Parameter(Mandatory = $true)]
        $VNets,
        
        [Parameter(Mandatory = $true)]
        $Bastions
    )
    
    $vnetBastionMap = @{}
    
    foreach ($bastion in $Bastions) {
        # Get the VNet from Bastion's IP configuration
        if ($bastion.IpConfigurations) {
            foreach ($ipConfig in $bastion.IpConfigurations) {
                if ($ipConfig.Subnet -and $ipConfig.Subnet.Id) {
                    $vnetId = ($ipConfig.Subnet.Id -split '/subnets/')[0]
                    $vnetName = ($vnetId -split '/')[-1]
                    $vnetBastionMap[$vnetName] = $bastion.Name
                }
            }
        }
    }
    
    return $vnetBastionMap
}

# Main scanning function
function Start-NetworkSecurityScan {
    Write-Host "`n[*] Starting Network Security audit..." -ForegroundColor Cyan
    
    # Get subscriptions
    $subscriptions = Get-AccessibleSubscriptions
    
    if ($subscriptions.Count -eq 0) {
        Write-Host "[ERROR] No accessible subscriptions found. Cannot proceed." -ForegroundColor Red
        return
    }
    
    $script:TotalSubscriptions = $subscriptions.Count
    $progressCounter = 0
    
    foreach ($subscription in $subscriptions) {
        $progressCounter++
        Write-Host "`n[*] Scanning subscription $progressCounter/$($subscriptions.Count): $($subscription.Name)" -ForegroundColor Cyan
        
        # Verify we can set context for this subscription
        $contextSuccess = $false
        try {
            if ($SkipFailedTenants) {
                $ctx = Set-AzContext -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 2>$null
                $contextSuccess = ($null -ne $ctx)
            }
            else {
                Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
                $contextSuccess = $true
            }
        }
        catch {
            $contextSuccess = $false
        }
        
        if (-not $contextSuccess) {
            if ($SkipFailedTenants) {
                Write-Host "[!] Skipped (unable to access tenant for this subscription)" -ForegroundColor Yellow
                $script:SkippedSubscriptions += $subscription.Name
            }
            else {
                Write-Host "[!] Failed to set context for subscription - check tenant access" -ForegroundColor Yellow
            }
            continue
        }
        
        # Get DDoS plans for VNet analysis
        $ddosPlans = @()
        if ($IncludeDDoS -or $IncludeVNets) {
            $ddosPlans = Get-SubscriptionDDoSPlans -Subscription $subscription
            if ($ddosPlans.Count -gt 0) {
                Write-Host "[+] Found $($ddosPlans.Count) DDoS Protection Plan(s)" -ForegroundColor Green
                foreach ($plan in $ddosPlans) {
                    $script:DDoSFindings += [PSCustomObject]@{
                        PlanName = $plan.Name
                        ResourceId = $plan.Id
                        ResourceGroupName = $plan.ResourceGroupName
                        SubscriptionId = $subscription.Id
                        SubscriptionName = $subscription.Name
                        Location = $plan.Location
                        ProvisioningState = $plan.ProvisioningState
                        VirtualNetworksCount = if ($plan.VirtualNetworks) { $plan.VirtualNetworks.Count } else { 0 }
                    }
                }
            }
        }
        
        # Get Bastion hosts for VNet analysis
        $bastions = @()
        if ($IncludeBastion -or $IncludeVNets) {
            $bastions = Get-SubscriptionBastions -Subscription $subscription
            if ($bastions.Count -gt 0) {
                Write-Host "[+] Found $($bastions.Count) Azure Bastion host(s)" -ForegroundColor Green
                foreach ($bastion in $bastions) {
                    $bastionFinding = Analyze-BastionSecurity -Bastion $bastion -Subscription $subscription
                    $script:BastionFindings += $bastionFinding
                }
            }
        }
        
        # Scan NSGs (enabled by default unless -SkipNSGs is specified)
        if (-not $SkipNSGs) {
            $nsgs = Get-SubscriptionNSGs -Subscription $subscription
            
            if ($nsgs.Count -eq 0) {
                Write-Host "[*] No NSGs found in this subscription" -ForegroundColor Gray
            }
            else {
                Write-Host "[+] Found $($nsgs.Count) Network Security Group(s)" -ForegroundColor Green
                $script:TotalNSGs += $nsgs.Count
                
                foreach ($nsg in $nsgs) {
                    Write-Host "[*] Analyzing NSG: $($nsg.Name)..." -ForegroundColor Cyan
                    
                    # Get flow logs if requested
                    $flowLogs = $null
                    if ($IncludeFlowLogs) {
                        $flowLogs = Get-NSGFlowLogs -NSGResourceId $nsg.Id
                    }
                    
                    # Analyze security
                    try {
                        $finding = Analyze-NSGSecurity -NSG $nsg -Subscription $subscription -FlowLogs $flowLogs
                        
                        if ($null -eq $finding) {
                            Write-Host "[!] Warning: No finding returned for NSG $($nsg.Name)" -ForegroundColor Yellow
                            continue
                        }
                        
                        Write-Host "    Risk: $($finding.RiskLevel), Rules: $($finding.TotalRules), Findings: $($finding.FindingCount)" -ForegroundColor Gray
                        
                        # Apply filters
                        if ($OnlyCritical -and $finding.RiskLevel -ne "CRITICAL") {
                            Write-Host "    Skipped (not CRITICAL)" -ForegroundColor DarkGray
                            continue
                        }
                        
                        if ($OnlyOpenPorts -and -not $finding.HasOpenManagementPorts) {
                            Write-Host "    Skipped (no open management ports)" -ForegroundColor DarkGray
                            continue
                        }
                        
                        $script:NSGFindings += $finding
                    }
                    catch {
                        Write-Host "[!] Error analyzing NSG $($nsg.Name): $_" -ForegroundColor Red
                    }
                }
            }
        }
        
        # Scan VNets
        if ($IncludeVNets) {
            $vnets = Get-SubscriptionVNets -Subscription $subscription
            
            if ($vnets.Count -eq 0) {
                Write-Host "[*] No VNets found in this subscription" -ForegroundColor Gray
            }
            else {
                Write-Host "[+] Found $($vnets.Count) Virtual Network(s)" -ForegroundColor Green
                $script:TotalVNets += $vnets.Count
                
                # Get VNet-Bastion mapping
                $vnetBastionMap = Get-VNetBastionStatus -VNets $vnets -Bastions $bastions
                
                foreach ($vnet in $vnets) {
                    Write-Host "[*] Analyzing VNet: $($vnet.Name)..." -ForegroundColor Cyan
                    
                    # Analyze security
                    $finding = Analyze-VNetSecurity -VNet $vnet -Subscription $subscription -DDoSPlans $ddosPlans
                    
                    # Add Bastion protection status
                    $finding | Add-Member -NotePropertyName "HasBastionProtection" -NotePropertyValue ($vnetBastionMap.ContainsKey($vnet.Name))
                    $finding | Add-Member -NotePropertyName "BastionName" -NotePropertyValue $(if ($vnetBastionMap.ContainsKey($vnet.Name)) { $vnetBastionMap[$vnet.Name] } else { $null })
                    
                    # Apply filters
                    if ($OnlyCritical -and $finding.RiskLevel -ne "CRITICAL") {
                        continue
                    }
                    
                    $script:VNetFindings += $finding
                }
            }
        }
        
        # Scan Gateways
        if ($IncludeGateways) {
            $gateways = Get-SubscriptionGateways -Subscription $subscription
            
            if ($gateways.Count -gt 0) {
                Write-Host "[+] Found $($gateways.Count) Gateway(s)" -ForegroundColor Green
                
                foreach ($gwItem in $gateways) {
                    $gw = $gwItem.Gateway
                    $gwType = $gwItem.Type
                    
                    $gwFinding = [PSCustomObject]@{
                        GatewayName = $gw.Name
                        ResourceId = $gw.Id
                        ResourceGroupName = $gw.ResourceGroupName
                        SubscriptionId = $subscription.Id
                        SubscriptionName = $subscription.Name
                        Location = $gw.Location
                        GatewayType = $gwType
                        Sku = if ($gw.Sku) { $gw.Sku.Name } else { "N/A" }
                        VpnType = if ($gw.VpnType) { $gw.VpnType } else { "N/A" }
                        EnableBgp = if ($gw.EnableBgp) { $gw.EnableBgp } else { $false }
                        ActiveActive = if ($gw.ActiveActive) { $gw.ActiveActive } else { $false }
                        ProvisioningState = $gw.ProvisioningState
                    }
                    
                    $script:GatewayFindings += $gwFinding
                }
            }
        }
    }
    
    Write-Host "`n[+] Network Security scan complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 200) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - NETWORK SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 200) -ForegroundColor Cyan
    
    # NSG Matrix
    if ($script:NSGFindings.Count -gt 0) {
        Write-Host "`n[NSG SECURITY MATRIX]" -ForegroundColor Cyan
        Write-Host ("-" * 180) -ForegroundColor Cyan
        
        $nsgMatrixData = $script:NSGFindings | Sort-Object @{Expression={
            switch($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }}, NSGName | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='NSG Name';Expression={if($_.NSGName.Length -gt 30){$_.NSGName.Substring(0,27)+"..."}else{$_.NSGName}}},
            @{Name='Subscription';Expression={if($_.SubscriptionName.Length -gt 18){$_.SubscriptionName.Substring(0,15)+"..."}else{$_.SubscriptionName}}},
            @{Name='Associated';Expression={if($_.IsAssociated){"Yes"}else{"No"}}},
            @{Name='Rules';Expression={$_.TotalRules}},
            @{Name='OpenMgmt';Expression={if($_.HasOpenManagementPorts){"YES"}else{"No"}}},
            @{Name='MgmtPorts';Expression={$_.OpenManagementPortsCount}},
            @{Name='AnyToAny';Expression={if($_.HasAnyToAny){"YES"}else{"No"}}},
            @{Name='InetInbound';Expression={$_.InternetInboundRulesCount}},
            @{Name='FlowLogs';Expression={if($_.FlowLogsEnabled){"Yes"}elseif($_.HasFlowLogs){"Disabled"}else{"No"}}},
            @{Name='Issues';Expression={$_.FindingCount}}
        
        $nsgMatrixData | Format-Table -AutoSize -Wrap | Out-String | ForEach-Object {
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
    }
    
    # VNet Matrix
    if ($script:VNetFindings.Count -gt 0) {
        Write-Host "`n[VNET SECURITY MATRIX]" -ForegroundColor Cyan
        Write-Host ("-" * 180) -ForegroundColor Cyan
        
        $vnetMatrixData = $script:VNetFindings | Sort-Object @{Expression={
            switch($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }}, VNetName | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='VNet Name';Expression={if($_.VNetName.Length -gt 25){$_.VNetName.Substring(0,22)+"..."}else{$_.VNetName}}},
            @{Name='Subscription';Expression={if($_.SubscriptionName.Length -gt 15){$_.SubscriptionName.Substring(0,12)+"..."}else{$_.SubscriptionName}}},
            @{Name='Subnets';Expression={$_.TotalSubnets}},
            @{Name='NoNSG';Expression={$_.SubnetsWithoutNSG}},
            @{Name='DDoS';Expression={if($_.HasDDoSProtection){"Yes"}else{"No"}}},
            @{Name='Bastion';Expression={if($_.HasBastionProtection){"Yes"}else{"No"}}},
            @{Name='Peerings';Expression={$_.PeeringCount}},
            @{Name='CrossSub';Expression={$_.CrossSubscriptionPeerings}},
            @{Name='SvcEndpts';Expression={$_.ServiceEndpointCount}},
            @{Name='PvtEndpts';Expression={$_.PrivateEndpointCount}},
            @{Name='Issues';Expression={$_.FindingCount}}
        
        $vnetMatrixData | Format-Table -AutoSize -Wrap | Out-String | ForEach-Object {
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
    }
    
    # Bastion findings
    if ($script:BastionFindings.Count -gt 0) {
        Write-Host "`n[AZURE BASTION HOSTS]" -ForegroundColor Cyan
        Write-Host ("-" * 100) -ForegroundColor Cyan
        
        $script:BastionFindings | Format-Table -Property BastionName, SubscriptionName, Location, Sku, NativeClientEnabled, ShareableLinkEnabled, RiskLevel -AutoSize | Out-String | Write-Host
    }
    
    # Gateway findings
    if ($script:GatewayFindings.Count -gt 0) {
        Write-Host "`n[VPN/EXPRESSROUTE GATEWAYS]" -ForegroundColor Cyan
        Write-Host ("-" * 100) -ForegroundColor Cyan
        
        $script:GatewayFindings | Format-Table -Property GatewayName, GatewayType, SubscriptionName, Location, Sku, VpnType, EnableBgp -AutoSize | Out-String | Write-Host
    }
    
    Write-Host ("=" * 200) -ForegroundColor Cyan
    
    # Summary statistics
    Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
    Write-Host "Total subscriptions scanned: " -NoNewline -ForegroundColor White
    Write-Host ($script:TotalSubscriptions - $script:SkippedSubscriptions.Count) -ForegroundColor Yellow
    if ($script:SkippedSubscriptions.Count -gt 0) {
        Write-Host "Subscriptions skipped (auth failed): " -NoNewline -ForegroundColor White
        Write-Host $script:SkippedSubscriptions.Count -ForegroundColor Yellow
    }
    
    if ($script:NSGFindings.Count -gt 0) {
        Write-Host "`nNSG Analysis:" -ForegroundColor Cyan
        Write-Host "  Total NSGs analyzed: " -NoNewline -ForegroundColor White
        Write-Host $script:NSGFindings.Count -ForegroundColor Yellow
        
        $criticalNSG = ($script:NSGFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highNSG = ($script:NSGFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumNSG = ($script:NSGFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowNSG = ($script:NSGFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalNSG -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highNSG -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumNSG -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowNSG -ForegroundColor Green
        
        # NSG-specific stats
        $openMgmtPorts = ($script:NSGFindings | Where-Object { $_.HasOpenManagementPorts }).Count
        $anyToAny = ($script:NSGFindings | Where-Object { $_.HasAnyToAny }).Count
        $noFlowLogs = ($script:NSGFindings | Where-Object { -not $_.FlowLogsEnabled }).Count
        $unassociated = ($script:NSGFindings | Where-Object { -not $_.IsAssociated }).Count
        
        Write-Host "`n[NSG SECURITY GAPS]" -ForegroundColor Cyan
        Write-Host "  Open management ports (RDP/SSH/WinRM): " -NoNewline -ForegroundColor White
        Write-Host $openMgmtPorts -ForegroundColor $(if($openMgmtPorts -gt 0){"Red"}else{"Green"})
        Write-Host "  Any-to-Any rules: " -NoNewline -ForegroundColor White
        Write-Host $anyToAny -ForegroundColor $(if($anyToAny -gt 0){"Red"}else{"Green"})
        Write-Host "  Flow logs not enabled: " -NoNewline -ForegroundColor White
        Write-Host $noFlowLogs -ForegroundColor $(if($noFlowLogs -gt 0){"Yellow"}else{"Green"})
        Write-Host "  Unassociated NSGs: " -NoNewline -ForegroundColor White
        Write-Host $unassociated -ForegroundColor $(if($unassociated -gt 0){"Cyan"}else{"Green"})
    }
    
    if ($script:VNetFindings.Count -gt 0) {
        Write-Host "`nVNet Analysis:" -ForegroundColor Cyan
        Write-Host "  Total VNets analyzed: " -NoNewline -ForegroundColor White
        Write-Host $script:VNetFindings.Count -ForegroundColor Yellow
        
        $noDDoS = ($script:VNetFindings | Where-Object { -not $_.HasDDoSProtection }).Count
        $noBastion = ($script:VNetFindings | Where-Object { -not $_.HasBastionProtection }).Count
        $subnetsNoNSG = ($script:VNetFindings | Measure-Object -Property SubnetsWithoutNSG -Sum).Sum
        
        Write-Host "`n[VNET SECURITY GAPS]" -ForegroundColor Cyan
        Write-Host "  VNets without DDoS Protection: " -NoNewline -ForegroundColor White
        Write-Host $noDDoS -ForegroundColor $(if($noDDoS -gt 0){"Yellow"}else{"Green"})
        Write-Host "  VNets without Bastion: " -NoNewline -ForegroundColor White
        Write-Host $noBastion -ForegroundColor $(if($noBastion -gt 0){"Yellow"}else{"Green"})
        Write-Host "  Total subnets without NSG: " -NoNewline -ForegroundColor White
        Write-Host $subnetsNoNSG -ForegroundColor $(if($subnetsNoNSG -gt 0){"Yellow"}else{"Green"})
    }
    
    if ($script:BastionFindings.Count -gt 0) {
        Write-Host "`nAzure Bastion hosts: " -NoNewline -ForegroundColor Cyan
        Write-Host $script:BastionFindings.Count -ForegroundColor Yellow
    }
    
    if ($script:GatewayFindings.Count -gt 0) {
        Write-Host "VPN/ExpressRoute gateways: " -NoNewline -ForegroundColor Cyan
        Write-Host $script:GatewayFindings.Count -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# Display detailed results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal subscriptions scanned: " -NoNewline -ForegroundColor White
    Write-Host ($script:TotalSubscriptions - $script:SkippedSubscriptions.Count) -ForegroundColor Yellow
    if ($script:SkippedSubscriptions.Count -gt 0) {
        Write-Host "Subscriptions skipped (auth failed): " -NoNewline -ForegroundColor White
        Write-Host $script:SkippedSubscriptions.Count -ForegroundColor Yellow
    }
    
    # NSG Results
    if ($script:NSGFindings.Count -gt 0) {
        Write-Host "`nTotal NSGs analyzed: " -NoNewline -ForegroundColor White
        Write-Host $script:NSGFindings.Count -ForegroundColor Yellow
        
        $criticalNSG = ($script:NSGFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highNSG = ($script:NSGFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumNSG = ($script:NSGFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowNSG = ($script:NSGFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalNSG -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highNSG -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumNSG -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowNSG -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "NSG SECURITY DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:NSGFindings | Sort-Object @{Expression={
            switch($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }}, NSGName | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] NSG: " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.NSGName -ForegroundColor White
            
            Write-Host "  Subscription: $($_.SubscriptionName)" -ForegroundColor Gray
            Write-Host "  Resource Group: $($_.ResourceGroupName)" -ForegroundColor Gray
            Write-Host "  Location: $($_.Location)" -ForegroundColor Gray
            
            # Association
            Write-Host "`n  [Association]" -ForegroundColor Cyan
            Write-Host "  Associated: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.IsAssociated){"Yes (Subnets: $($_.AssociatedSubnetCount), NICs: $($_.AssociatedNICCount))"}else{"NOT ASSOCIATED"}) -ForegroundColor $(if($_.IsAssociated){"Green"}else{"Yellow"})
            if ($_.AssociatedSubnets) {
                Write-Host "  Subnets: $($_.AssociatedSubnets)" -ForegroundColor Gray
            }
            
            # Rules Analysis
            Write-Host "`n  [Rules Analysis]" -ForegroundColor Cyan
            Write-Host "  Total Rules: $($_.TotalRules) custom, $($_.DefaultRules) default" -ForegroundColor Gray
            
            Write-Host "  Open Management Ports: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasOpenManagementPorts){"YES - $($_.OpenManagementPortsCount) port(s)"}else{"No"}) -ForegroundColor $(if($_.HasOpenManagementPorts){"Red"}else{"Green"})
            
            if ($_.OpenManagementPorts -and $_.OpenManagementPorts.Count -gt 0) {
                foreach ($port in $_.OpenManagementPorts | Select-Object -First 5) {
                    Write-Host "    - Port $($port.Port) ($($port.Service)) via rule '$($port.RuleName)'" -ForegroundColor Yellow
                }
                if ($_.OpenManagementPorts.Count -gt 5) {
                    Write-Host "    ... and $($_.OpenManagementPorts.Count - 5) more" -ForegroundColor DarkGray
                }
            }
            
            Write-Host "  Any-to-Any Rules: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasAnyToAny){"YES - $($_.AnyToAnyRulesCount) rule(s)"}else{"No"}) -ForegroundColor $(if($_.HasAnyToAny){"Red"}else{"Green"})
            
            Write-Host "  Internet Inbound Rules: " -NoNewline -ForegroundColor Gray
            Write-Host $_.InternetInboundRulesCount -ForegroundColor $(if($_.InternetInboundRulesCount -gt 0){"Yellow"}else{"Green"})
            
            # Flow Logs
            Write-Host "`n  [Flow Logs]" -ForegroundColor Cyan
            Write-Host "  Flow Logs Configured: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasFlowLogs){"Yes"}else{"NO"}) -ForegroundColor $(if($_.HasFlowLogs){"Green"}else{"Yellow"})
            if ($_.HasFlowLogs) {
                Write-Host "  Flow Logs Enabled: " -NoNewline -ForegroundColor Gray
                Write-Host $(if($_.FlowLogsEnabled){"Yes"}else{"DISABLED"}) -ForegroundColor $(if($_.FlowLogsEnabled){"Green"}else{"Yellow"})
                Write-Host "  Traffic Analytics: " -NoNewline -ForegroundColor Gray
                Write-Host $(if($_.TrafficAnalyticsEnabled){"Enabled"}else{"Disabled"}) -ForegroundColor $(if($_.TrafficAnalyticsEnabled){"Green"}else{"Cyan"})
            }
            
            # Findings
            if ($_.Findings.Count -gt 0) {
                Write-Host "`n  [Findings]" -ForegroundColor Red
                foreach ($finding in $_.Findings) {
                    Write-Host "    - $finding" -ForegroundColor Yellow
                }
            }
        }
    }
    
    # VNet Results
    if ($script:VNetFindings.Count -gt 0) {
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "VNET SECURITY DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:VNetFindings | Sort-Object @{Expression={
            switch($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }}, VNetName | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] VNet: " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.VNetName -ForegroundColor White
            
            Write-Host "  Subscription: $($_.SubscriptionName)" -ForegroundColor Gray
            Write-Host "  Resource Group: $($_.ResourceGroupName)" -ForegroundColor Gray
            Write-Host "  Location: $($_.Location)" -ForegroundColor Gray
            Write-Host "  Address Space: $($_.AddressSpace)" -ForegroundColor Gray
            
            # Protection
            Write-Host "`n  [Protection]" -ForegroundColor Cyan
            Write-Host "  DDoS Protection: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasDDoSProtection){"Enabled"}else{"NOT ENABLED"}) -ForegroundColor $(if($_.HasDDoSProtection){"Green"}else{"Yellow"})
            Write-Host "  Bastion Host: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasBastionProtection){"Yes ($($_.BastionName))"}else{"NOT CONFIGURED"}) -ForegroundColor $(if($_.HasBastionProtection){"Green"}else{"Yellow"})
            
            # Subnets
            Write-Host "`n  [Subnets]" -ForegroundColor Cyan
            Write-Host "  Total Subnets: $($_.TotalSubnets)" -ForegroundColor Gray
            Write-Host "  Subnets with NSG: " -NoNewline -ForegroundColor Gray
            Write-Host $_.SubnetsWithNSG -ForegroundColor Green
            Write-Host "  Subnets without NSG: " -NoNewline -ForegroundColor Gray
            Write-Host $_.SubnetsWithoutNSG -ForegroundColor $(if($_.SubnetsWithoutNSG -gt 0){"Yellow"}else{"Green"})
            Write-Host "  Gateway Subnet: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasGatewaySubnet){"Yes"}else{"No"}) -ForegroundColor Gray
            Write-Host "  Bastion Subnet: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.HasBastionSubnet){"Yes"}else{"No"}) -ForegroundColor Gray
            
            # Peerings
            if ($_.PeeringCount -gt 0) {
                Write-Host "`n  [Peerings]" -ForegroundColor Cyan
                Write-Host "  Total Peerings: $($_.PeeringCount)" -ForegroundColor Gray
                Write-Host "  Cross-Subscription: $($_.CrossSubscriptionPeerings)" -ForegroundColor $(if($_.CrossSubscriptionPeerings -gt 0){"Yellow"}else{"Gray"})
                foreach ($peering in $_.Peerings | Select-Object -First 3) {
                    Write-Host "    - $($peering.Name) -> $($peering.RemoteVNet) (State: $($peering.PeeringState))" -ForegroundColor Gray
                }
                if ($_.Peerings.Count -gt 3) {
                    Write-Host "    ... and $($_.Peerings.Count - 3) more" -ForegroundColor DarkGray
                }
            }
            
            # Endpoints
            Write-Host "`n  [Endpoints]" -ForegroundColor Cyan
            Write-Host "  Service Endpoints: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.ServiceEndpointCount -gt 0){"$($_.ServiceEndpointCount) ($($_.ServiceEndpoints))"}else{"None"}) -ForegroundColor Gray
            Write-Host "  Private Endpoints: $($_.PrivateEndpointCount)" -ForegroundColor Gray
            
            # Findings
            if ($_.Findings.Count -gt 0) {
                Write-Host "`n  [Findings]" -ForegroundColor Red
                foreach ($finding in $_.Findings) {
                    Write-Host "    - $finding" -ForegroundColor Yellow
                }
            }
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
    
    $totalFindings = $script:NSGFindings.Count + $script:VNetFindings.Count + $script:BastionFindings.Count + $script:GatewayFindings.Count
    
    if ($totalFindings -eq 0) {
        Write-Host "`n[*] No findings to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        # Combine all findings for export
        $allFindings = @{
            NSGs = $script:NSGFindings | Select-Object * -ExcludeProperty OpenManagementPorts, AnyToAnyRules, InternetInboundRules | ForEach-Object {
                $_ | Add-Member -NotePropertyName "OpenMgmtPortsList" -NotePropertyValue (($script:NSGFindings | Where-Object { $_.NSGName -eq $_.NSGName }).OpenManagementPorts | ForEach-Object { "$($_.Port) ($($_.Service))" }) -join "; " -PassThru -Force
            }
            VNets = $script:VNetFindings | Select-Object * -ExcludeProperty Peerings
            Bastions = $script:BastionFindings
            Gateways = $script:GatewayFindings
            DDoSPlans = $script:DDoSFindings
        }
        
        switch ($extension) {
            ".csv" {
                # Export NSGs to CSV (primary export)
                $nsgExport = $script:NSGFindings | Select-Object `
                    NSGName, ResourceId, ResourceGroupName, SubscriptionId, SubscriptionName, Location,
                    IsAssociated, AssociatedSubnetCount, AssociatedNICCount, AssociatedSubnets,
                    TotalRules, DefaultRules, HasOpenManagementPorts, OpenManagementPortsCount,
                    HasAnyToAny, AnyToAnyRulesCount, InternetInboundRulesCount,
                    HasFlowLogs, FlowLogsEnabled, TrafficAnalyticsEnabled,
                    @{Name='Findings';Expression={$_.Findings -join "; "}},
                    FindingCount, RiskLevel, HasMisconfigurations
                
                $nsgExport | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] NSG results exported to CSV: $Path" -ForegroundColor Green
                
                # Export VNets to separate file if present
                if ($script:VNetFindings.Count -gt 0) {
                    $vnetPath = [System.IO.Path]::ChangeExtension($Path, "vnets.csv")
                    $vnetExport = $script:VNetFindings | Select-Object `
                        VNetName, ResourceId, ResourceGroupName, SubscriptionId, SubscriptionName, Location, AddressSpace,
                        HasDDoSProtection, TotalSubnets, SubnetsWithNSG, SubnetsWithoutNSG,
                        HasGatewaySubnet, HasBastionSubnet, HasBastionProtection, BastionName,
                        PeeringCount, CrossSubscriptionPeerings, ServiceEndpointCount, PrivateEndpointCount,
                        @{Name='Findings';Expression={$_.Findings -join "; "}},
                        FindingCount, RiskLevel
                    
                    $vnetExport | Export-Csv -Path $vnetPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] VNet results exported to CSV: $vnetPath" -ForegroundColor Green
                }
            }
            ".json" {
                $allFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            default {
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $script:NSGFindings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
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
        # Disconnect from Azure PowerShell
        if (Get-AzContext -ErrorAction SilentlyContinue) {
            Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[+] Disconnected from Azure PowerShell" -ForegroundColor Green
        }
        # Disconnect from Microsoft Graph if connected
        try {
            $mgContext = Get-MgContext -ErrorAction SilentlyContinue
            if ($mgContext) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                Write-Host "[+] Disconnected from Microsoft Graph" -ForegroundColor Green
            }
        } catch { }
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
    Write-Host "[+] Cleanup complete" -ForegroundColor Green
}

# Main execution
function Main {
    try {
        Show-Banner
        
        # Initialize stealth
        Initialize-StealthConfig
        
        # Check required modules
        if (-not (Test-AzModules)) {
            exit 1
        }
        
        # Initialize and import modules
        if (-not (Initialize-AzModules)) {
            Write-Host "`n[ERROR] Failed to initialize modules. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Authenticate
        if (-not (Connect-AzureService)) {
            Write-Host "`n[ERROR] Authentication failed. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Start scan
        Start-NetworkSecurityScan
        
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
        
        Write-Host "`n[*] Network Security check completed successfully!" -ForegroundColor Green
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
