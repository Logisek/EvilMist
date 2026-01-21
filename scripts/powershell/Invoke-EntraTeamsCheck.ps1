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
    Audits Microsoft Teams collaboration security settings to identify risks.

.DESCRIPTION
    This script performs a comprehensive audit of Microsoft Teams security to identify
    potential security risks including:
    - External access (federation) settings
    - Guest access policies
    - Unmanaged Teams (shadow IT)
    - App permission policies
    - Meeting policies (anonymous join, lobby bypass)
    - Private channel creation policies
    - Messaging policies
    - Teams client configuration
    
    Microsoft Teams security is critical for preventing data leakage, unauthorized
    collaboration, and external access risks. This script provides red/blue team
    visibility into Teams-based attack vectors.
    
    The script uses Microsoft Teams PowerShell module for API access.

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
    Show only HIGH and CRITICAL risk findings.

.PARAMETER OnlyExternalAccess
    Show only external access and federation findings.

.PARAMETER OnlyGuestAccess
    Show only guest access related findings.

.PARAMETER OnlyMeetingRisks
    Show only meeting policy risks (anonymous join, lobby bypass).

.PARAMETER IncludeTeamsInventory
    Include full Teams inventory enumeration.

.PARAMETER IncludeAppPolicies
    Include Teams app permission policies analysis.

.PARAMETER IncludeMessagingPolicies
    Include messaging policies analysis.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraTeamsCheck.ps1
    # Enumerate all Teams security configurations

.EXAMPLE
    .\Invoke-EntraTeamsCheck.ps1 -ExportPath "teams-security.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraTeamsCheck.ps1 -OnlyExternalAccess -Matrix
    # Show only external access findings in matrix format

.EXAMPLE
    .\Invoke-EntraTeamsCheck.ps1 -OnlyMeetingRisks -Matrix
    # Show only meeting policy risks

.EXAMPLE
    .\Invoke-EntraTeamsCheck.ps1 -IncludeTeamsInventory -IncludeAppPolicies -Matrix
    # Include Teams inventory and app policies

.EXAMPLE
    .\Invoke-EntraTeamsCheck.ps1 -EnableStealth -QuietStealth
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
    [switch]$OnlyHighRisk,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyExternalAccess,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyGuestAccess,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyMeetingRisks,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeTeamsInventory,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeAppPolicies,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeMessagingPolicies,

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

# Track state
$script:TenantSettings = $null
$script:ExternalAccessFindings = @()
$script:GuestAccessFindings = @()
$script:MeetingPolicyFindings = @()
$script:AppPolicyFindings = @()
$script:MessagingPolicyFindings = @()
$script:TeamInventoryFindings = @()
$script:ClientConfigFindings = @()
$script:TenantDomain = ""
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
    Write-Host "    Entra ID Teams Check - Collaboration Security Audit" -ForegroundColor Yellow
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

# Check if MicrosoftTeams module is installed
function Test-TeamsModule {
    Write-Host "[*] Checking MicrosoftTeams PowerShell module..." -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
        Write-Host "[!] MicrosoftTeams module is not installed" -ForegroundColor Yellow
        Write-Host "`n[*] Installing MicrosoftTeams module automatically..." -ForegroundColor Cyan
        
        # Check if running as administrator for AllUsers scope
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $scope = if ($isAdmin) { "AllUsers" } else { "CurrentUser" }
        
        try {
            # Set PSGallery as trusted if not already
            $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($psGallery -and $psGallery.InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            }
            
            Install-Module -Name MicrosoftTeams -Scope $scope -AllowClobber -Force -ErrorAction Stop
            Write-Host "[+] Successfully installed MicrosoftTeams" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] Failed to install MicrosoftTeams: $_" -ForegroundColor Red
            Write-Host "[*] Try manually: Install-Module MicrosoftTeams -Scope CurrentUser -Force" -ForegroundColor Yellow
            return $false
        }
    }
    
    Write-Host "[+] MicrosoftTeams module is installed" -ForegroundColor Green
    return $true
}

# Initialize and import Teams module
function Initialize-TeamsModule {
    Write-Host "[*] Initializing MicrosoftTeams module..." -ForegroundColor Cyan
    
    try {
        # Remove any loaded Teams modules to avoid conflicts
        $loadedModules = Get-Module MicrosoftTeams
        if ($loadedModules) {
            Write-Host "[*] Cleaning up loaded Teams modules..." -ForegroundColor Yellow
            $loadedModules | ForEach-Object {
                Remove-Module $_.Name -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Import the module
        Write-Host "[*] Importing MicrosoftTeams..." -ForegroundColor Cyan
        Import-Module MicrosoftTeams -Force -ErrorAction Stop
        
        Write-Host "[+] Module imported successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to import module: $_" -ForegroundColor Red
        Write-Host "[*] Try running: Update-Module MicrosoftTeams -Force" -ForegroundColor Yellow
        return $false
    }
}

# Connect to Microsoft Teams
function Connect-TeamsService {
    Write-Host "`n[*] Connecting to Microsoft Teams..." -ForegroundColor Cyan
    
    try {
        # Check if already connected
        try {
            $existingSession = Get-CsTenant -ErrorAction Stop
            if ($existingSession) {
                Write-Host "[+] Already connected to Microsoft Teams" -ForegroundColor Green
                Write-Host "[+] Tenant: $($existingSession.DisplayName)" -ForegroundColor Green
                $script:TenantDomain = $existingSession.DisplayName
                return $true
            }
        }
        catch {
            # Not connected, continue to connect
        }
        
        # Connect to Teams
        Write-Host "[*] Initiating Teams authentication..." -ForegroundColor Cyan
        
        $connectParams = @{}
        
        if ($TenantId) {
            $connectParams['TenantId'] = $TenantId
        }
        
        # Try Azure CLI token if requested
        if ($UseAzCliToken) {
            try {
                Write-Host "[*] Attempting to use Azure CLI token..." -ForegroundColor Cyan
                $azToken = az account get-access-token --resource https://api.interfaces.records.teams.microsoft.com --query accessToken -o tsv 2>$null
                if ($azToken -and $azToken.Length -gt 0) {
                    Write-Host "[+] Retrieved Azure CLI token" -ForegroundColor Green
                    Write-Host "[!] Teams module requires interactive auth - using token for verification only" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "[!] Failed to retrieve Azure CLI token" -ForegroundColor Yellow
            }
        }
        
        Connect-MicrosoftTeams @connectParams -ErrorAction Stop
        
        # Verify connection
        $tenant = Get-CsTenant -ErrorAction SilentlyContinue
        if ($tenant) {
            $script:TenantDomain = $tenant.DisplayName
            Write-Host "[+] Connected to Microsoft Teams" -ForegroundColor Green
            Write-Host "[+] Tenant: $($tenant.DisplayName)" -ForegroundColor Green
            Write-Host "[+] Tenant ID: $($tenant.TenantId)" -ForegroundColor Green
            return $true
        }
        
        Write-Host "[+] Connected to Microsoft Teams" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to connect to Microsoft Teams: $_" -ForegroundColor Red
        Write-Host "[*] Make sure you have the necessary permissions:" -ForegroundColor Yellow
        Write-Host "    - Teams Administrator or Global Administrator role" -ForegroundColor Yellow
        Write-Host "    - Or appropriate RBAC permissions for reading Teams configurations" -ForegroundColor Yellow
        return $false
    }
}

# Analyze tenant federation (external access) settings
function Get-ExternalAccessAnalysis {
    Write-Host "`n[*] Analyzing external access (federation) settings..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get tenant federation configuration
        $federationConfig = Get-CsTenantFederationConfiguration -ErrorAction Stop
        
        $riskLevel = "LOW"
        $riskReasons = @()
        
        # Analyze external access settings
        if ($federationConfig.AllowFederatedUsers -eq $true) {
            if ($null -eq $federationConfig.AllowedDomains -or $federationConfig.AllowedDomains.AllowedDomain.Count -eq 0) {
                # Federation open to all domains
                $riskLevel = "HIGH"
                $riskReasons += "Federation open to ALL external domains"
            }
            else {
                $riskLevel = "MEDIUM"
                $riskReasons += "Federation enabled with allowed domain list"
            }
        }
        
        # Check blocked domains
        $blockedDomainsCount = 0
        if ($federationConfig.BlockedDomains -and $federationConfig.BlockedDomains.Count -gt 0) {
            $blockedDomainsCount = $federationConfig.BlockedDomains.Count
        }
        
        # Check Teams/Skype consumer access
        if ($federationConfig.AllowTeamsConsumer -eq $true) {
            if ($riskLevel -ne "HIGH") {
                $riskLevel = "HIGH"
            }
            $riskReasons += "Teams consumer (personal accounts) access enabled"
        }
        
        if ($federationConfig.AllowPublicUsers -eq $true) {
            if ($riskLevel -ne "HIGH") {
                $riskLevel = "HIGH"
            }
            $riskReasons += "Skype consumer (public users) access enabled"
        }
        
        # Check anonymous join settings
        if ($federationConfig.AllowTeamsConsumerInbound -eq $true) {
            $riskReasons += "Inbound Teams consumer communications allowed"
        }
        
        $federationInfo = [PSCustomObject]@{
            ConfigType = "TenantFederation"
            AllowFederatedUsers = $federationConfig.AllowFederatedUsers
            AllowTeamsConsumer = $federationConfig.AllowTeamsConsumer
            AllowTeamsConsumerInbound = $federationConfig.AllowTeamsConsumerInbound
            AllowPublicUsers = $federationConfig.AllowPublicUsers
            AllowedDomainsCount = if ($federationConfig.AllowedDomains) { $federationConfig.AllowedDomains.AllowedDomain.Count } else { 0 }
            AllowedDomains = if ($federationConfig.AllowedDomains) { ($federationConfig.AllowedDomains.AllowedDomain.Domain -join ", ") } else { "All (Open)" }
            BlockedDomainsCount = $blockedDomainsCount
            BlockedDomains = if ($federationConfig.BlockedDomains) { ($federationConfig.BlockedDomains.Domain -join ", ") } else { "None" }
            SharedSipAddressSpace = $federationConfig.SharedSipAddressSpace
            TreatDiscoveredPartnersAsUnverified = $federationConfig.TreatDiscoveredPartnersAsUnverified
            RiskLevel = $riskLevel
            RiskReasons = ($riskReasons -join "; ")
            RiskReasonCount = $riskReasons.Count
        }
        
        $script:ExternalAccessFindings += $federationInfo
        
        Write-Host "[+] External access analysis complete" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing external access: $_" -ForegroundColor Yellow
    }
}

# Analyze guest access settings
function Get-GuestAccessAnalysis {
    Write-Host "`n[*] Analyzing guest access settings..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get Teams client configuration for guest settings
        $clientConfig = Get-CsTeamsClientConfiguration -ErrorAction Stop
        
        $riskLevel = "LOW"
        $riskReasons = @()
        
        # Analyze guest access settings
        if ($clientConfig.AllowGuestUser -eq $true) {
            $riskLevel = "MEDIUM"
            $riskReasons += "Guest access enabled for Teams"
        }
        
        # Check if guest can access files
        if ($clientConfig.AllowDropBox -eq $true -or $clientConfig.AllowBox -eq $true -or 
            $clientConfig.AllowGoogleDrive -eq $true -or $clientConfig.AllowShareFile -eq $true) {
            $riskReasons += "Third-party cloud storage integration enabled"
        }
        
        # Check resource account settings
        if ($clientConfig.AllowResourceAccountSendMessage -eq $true) {
            $riskReasons += "Resource accounts can send messages"
        }
        
        $guestInfo = [PSCustomObject]@{
            ConfigType = "TeamsClientConfiguration"
            AllowGuestUser = $clientConfig.AllowGuestUser
            AllowDropBox = $clientConfig.AllowDropBox
            AllowBox = $clientConfig.AllowBox
            AllowGoogleDrive = $clientConfig.AllowGoogleDrive
            AllowShareFile = $clientConfig.AllowShareFile
            AllowEgnyte = $clientConfig.AllowEgnyte
            AllowOrganizationTab = $clientConfig.AllowOrganizationTab
            AllowSkypeBusinessInterop = $clientConfig.AllowSkypeBusinessInterop
            AllowResourceAccountSendMessage = $clientConfig.AllowResourceAccountSendMessage
            ContentPin = $clientConfig.ContentPin
            ResourceAccountContentAccess = $clientConfig.ResourceAccountContentAccess
            RiskLevel = $riskLevel
            RiskReasons = ($riskReasons -join "; ")
            RiskReasonCount = $riskReasons.Count
        }
        
        $script:GuestAccessFindings += $guestInfo
        $script:ClientConfigFindings += $guestInfo
        
        # Get guest messaging configuration
        Invoke-StealthDelay
        
        try {
            $guestMsgConfig = Get-CsTeamsGuestMessagingConfiguration -ErrorAction SilentlyContinue
            
            if ($guestMsgConfig) {
                $guestMsgRiskLevel = "LOW"
                $guestMsgRiskReasons = @()
                
                if ($guestMsgConfig.AllowUserEditMessage -eq $true) {
                    $guestMsgRiskReasons += "Guests can edit messages"
                }
                
                if ($guestMsgConfig.AllowUserDeleteMessage -eq $true) {
                    $guestMsgRiskReasons += "Guests can delete messages"
                }
                
                if ($guestMsgConfig.AllowUserChat -eq $true) {
                    $guestMsgRiskReasons += "Guests can start chats"
                }
                
                if ($guestMsgConfig.AllowGiphy -eq $true -or $guestMsgConfig.AllowMemes -eq $true -or 
                    $guestMsgConfig.AllowStickers -eq $true) {
                    $guestMsgRiskReasons += "Guests can use giphy/memes/stickers"
                }
                
                if ($guestMsgRiskReasons.Count -gt 2) {
                    $guestMsgRiskLevel = "MEDIUM"
                }
                
                $guestMsgInfo = [PSCustomObject]@{
                    ConfigType = "GuestMessagingConfiguration"
                    AllowUserEditMessage = $guestMsgConfig.AllowUserEditMessage
                    AllowUserDeleteMessage = $guestMsgConfig.AllowUserDeleteMessage
                    AllowUserChat = $guestMsgConfig.AllowUserChat
                    AllowGiphy = $guestMsgConfig.AllowGiphy
                    GiphyRatingType = $guestMsgConfig.GiphyRatingType
                    AllowMemes = $guestMsgConfig.AllowMemes
                    AllowStickers = $guestMsgConfig.AllowStickers
                    AllowImmersiveReader = $guestMsgConfig.AllowImmersiveReader
                    RiskLevel = $guestMsgRiskLevel
                    RiskReasons = ($guestMsgRiskReasons -join "; ")
                    RiskReasonCount = $guestMsgRiskReasons.Count
                }
                
                $script:GuestAccessFindings += $guestMsgInfo
            }
        }
        catch {
            Write-Host "[!] Could not get guest messaging configuration" -ForegroundColor Yellow
        }
        
        # Get guest calling configuration
        Invoke-StealthDelay
        
        try {
            $guestCallConfig = Get-CsTeamsGuestCallingConfiguration -ErrorAction SilentlyContinue
            
            if ($guestCallConfig) {
                $guestCallRiskLevel = "LOW"
                $guestCallRiskReasons = @()
                
                if ($guestCallConfig.AllowPrivateCalling -eq $true) {
                    $guestCallRiskReasons += "Guests can make private calls"
                    $guestCallRiskLevel = "MEDIUM"
                }
                
                $guestCallInfo = [PSCustomObject]@{
                    ConfigType = "GuestCallingConfiguration"
                    AllowPrivateCalling = $guestCallConfig.AllowPrivateCalling
                    RiskLevel = $guestCallRiskLevel
                    RiskReasons = ($guestCallRiskReasons -join "; ")
                    RiskReasonCount = $guestCallRiskReasons.Count
                }
                
                $script:GuestAccessFindings += $guestCallInfo
            }
        }
        catch {
            Write-Host "[!] Could not get guest calling configuration" -ForegroundColor Yellow
        }
        
        # Get guest meeting configuration
        Invoke-StealthDelay
        
        try {
            $guestMeetingConfig = Get-CsTeamsGuestMeetingConfiguration -ErrorAction SilentlyContinue
            
            if ($guestMeetingConfig) {
                $guestMeetingRiskLevel = "LOW"
                $guestMeetingRiskReasons = @()
                
                if ($guestMeetingConfig.AllowIPVideo -eq $true) {
                    $guestMeetingRiskReasons += "Guests can use video"
                }
                
                if ($guestMeetingConfig.ScreenSharingMode -eq "EntireScreen") {
                    $guestMeetingRiskReasons += "Guests can share entire screen"
                    $guestMeetingRiskLevel = "MEDIUM"
                }
                
                if ($guestMeetingConfig.AllowMeetNow -eq $true) {
                    $guestMeetingRiskReasons += "Guests can start Meet Now"
                }
                
                $guestMeetingInfo = [PSCustomObject]@{
                    ConfigType = "GuestMeetingConfiguration"
                    AllowIPVideo = $guestMeetingConfig.AllowIPVideo
                    ScreenSharingMode = $guestMeetingConfig.ScreenSharingMode
                    AllowMeetNow = $guestMeetingConfig.AllowMeetNow
                    RiskLevel = $guestMeetingRiskLevel
                    RiskReasons = ($guestMeetingRiskReasons -join "; ")
                    RiskReasonCount = $guestMeetingRiskReasons.Count
                }
                
                $script:GuestAccessFindings += $guestMeetingInfo
            }
        }
        catch {
            Write-Host "[!] Could not get guest meeting configuration" -ForegroundColor Yellow
        }
        
        Write-Host "[+] Guest access analysis complete" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing guest access: $_" -ForegroundColor Yellow
    }
}

# Analyze meeting policies
function Get-MeetingPolicyAnalysis {
    Write-Host "`n[*] Analyzing meeting policies..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get all meeting policies
        $meetingPolicies = Get-CsTeamsMeetingPolicy -ErrorAction Stop
        
        Write-Host "[+] Found $($meetingPolicies.Count) meeting policy(ies)" -ForegroundColor Green
        
        foreach ($policy in $meetingPolicies) {
            $riskLevel = "LOW"
            $riskReasons = @()
            
            # Check anonymous join settings
            if ($policy.AllowAnonymousUsersToJoinMeeting -eq $true) {
                $riskLevel = "HIGH"
                $riskReasons += "Anonymous users can join meetings"
            }
            
            # Check lobby bypass
            if ($policy.AutoAdmittedUsers -eq "Everyone" -or $policy.AutoAdmittedUsers -eq "EveryoneInCompanyExcludingGuests") {
                if ($policy.AllowAnonymousUsersToJoinMeeting -eq $true) {
                    $riskLevel = "CRITICAL"
                    $riskReasons += "Lobby bypass enabled with anonymous join"
                }
                else {
                    if ($riskLevel -ne "HIGH" -and $riskLevel -ne "CRITICAL") {
                        $riskLevel = "MEDIUM"
                    }
                    $riskReasons += "Lobby bypass: $($policy.AutoAdmittedUsers)"
                }
            }
            
            # Check anonymous user start meeting
            if ($policy.AllowAnonymousUsersToStartMeeting -eq $true) {
                $riskLevel = "CRITICAL"
                $riskReasons += "Anonymous users can START meetings"
            }
            
            # Check dial-in bypass
            if ($policy.AllowPSTNUsersToBypassLobby -eq $true) {
                $riskReasons += "PSTN users bypass lobby"
            }
            
            # Check recording settings
            if ($policy.AllowCloudRecording -eq $true) {
                if ($policy.AllowRecordingStorageOutsideRegion -eq $true) {
                    $riskReasons += "Recording storage outside region allowed"
                }
            }
            
            # Check transcription
            if ($policy.AllowTranscription -eq $true) {
                $riskReasons += "Transcription enabled"
            }
            
            # Check screen sharing
            if ($policy.ScreenSharingMode -eq "EntireScreen") {
                $riskReasons += "Entire screen sharing allowed"
            }
            
            # Check who can present
            if ($policy.DesignatedPresenterRoleMode -eq "Everyone" -or $policy.DesignatedPresenterRoleMode -eq "EveryoneUserOverride") {
                $riskReasons += "Anyone can present: $($policy.DesignatedPresenterRoleMode)"
            }
            
            # Check external participant control
            if ($policy.AllowExternalParticipantGiveRequestControl -eq $true) {
                $riskReasons += "External participants can request control"
            }
            
            # Check Meet Now in channels
            if ($policy.AllowMeetNow -eq $true -and $policy.AllowChannelMeetingScheduling -eq $true) {
                $riskReasons += "Meet Now and channel meetings enabled"
            }
            
            # Check watermark
            if ($policy.AllowWatermarkForCameraVideo -eq $false -and $policy.AllowWatermarkForScreenSharing -eq $false) {
                if ($riskLevel -eq "LOW") {
                    $riskLevel = "LOW"  # Not a risk, just noting
                }
            }
            
            $policyInfo = [PSCustomObject]@{
                PolicyName = $policy.Identity
                IsGlobal = ($policy.Identity -eq "Global")
                Description = $policy.Description
                
                # Anonymous Access
                AllowAnonymousUsersToJoinMeeting = $policy.AllowAnonymousUsersToJoinMeeting
                AllowAnonymousUsersToStartMeeting = $policy.AllowAnonymousUsersToStartMeeting
                
                # Lobby Settings
                AutoAdmittedUsers = $policy.AutoAdmittedUsers
                AllowPSTNUsersToBypassLobby = $policy.AllowPSTNUsersToBypassLobby
                
                # Recording/Transcription
                AllowCloudRecording = $policy.AllowCloudRecording
                AllowRecordingStorageOutsideRegion = $policy.AllowRecordingStorageOutsideRegion
                AllowTranscription = $policy.AllowTranscription
                
                # Screen Sharing
                ScreenSharingMode = $policy.ScreenSharingMode
                AllowExternalParticipantGiveRequestControl = $policy.AllowExternalParticipantGiveRequestControl
                
                # Presenter Settings
                DesignatedPresenterRoleMode = $policy.DesignatedPresenterRoleMode
                
                # Meeting Features
                AllowMeetNow = $policy.AllowMeetNow
                AllowChannelMeetingScheduling = $policy.AllowChannelMeetingScheduling
                AllowPrivateMeetingScheduling = $policy.AllowPrivateMeetingScheduling
                
                # Watermarks
                AllowWatermarkForCameraVideo = $policy.AllowWatermarkForCameraVideo
                AllowWatermarkForScreenSharing = $policy.AllowWatermarkForScreenSharing
                
                # Live Events
                AllowBroadcastScheduling = $policy.AllowBroadcastScheduling
                
                # Risk Assessment
                RiskLevel = $riskLevel
                RiskReasons = ($riskReasons -join "; ")
                RiskReasonCount = $riskReasons.Count
            }
            
            # Apply filters
            if ($OnlyHighRisk -and $riskLevel -ne "HIGH" -and $riskLevel -ne "CRITICAL") {
                continue
            }
            
            if ($OnlyMeetingRisks -and $riskReasons.Count -eq 0) {
                continue
            }
            
            $script:MeetingPolicyFindings += $policyInfo
        }
        
        Write-Host "[+] Meeting policy analysis complete" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing meeting policies: $_" -ForegroundColor Yellow
    }
}

# Analyze app permission policies
function Get-AppPolicyAnalysis {
    Write-Host "`n[*] Analyzing app permission policies..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get app permission policies
        $appPermPolicies = Get-CsTeamsAppPermissionPolicy -ErrorAction Stop
        
        Write-Host "[+] Found $($appPermPolicies.Count) app permission policy(ies)" -ForegroundColor Green
        
        foreach ($policy in $appPermPolicies) {
            $riskLevel = "LOW"
            $riskReasons = @()
            
            # Check default app types
            if ($policy.DefaultCatalogAppsType -eq "AllowedAppList") {
                $riskReasons += "Microsoft apps: Only allowed list"
            }
            elseif ($policy.DefaultCatalogAppsType -eq "BlockedAppList") {
                $riskReasons += "Microsoft apps: All except blocked"
            }
            
            # Check global catalog (third-party) apps
            if ($policy.GlobalCatalogAppsType -eq "AllowedAppList") {
                $riskReasons += "Third-party apps: Only allowed list"
            }
            elseif ($policy.GlobalCatalogAppsType -eq "BlockedAppList") {
                $riskLevel = "MEDIUM"
                $riskReasons += "Third-party apps: All except blocked (broad access)"
            }
            
            # Check private (custom) apps
            if ($policy.PrivateCatalogAppsType -eq "AllowedAppList") {
                $riskReasons += "Custom apps: Only allowed list"
            }
            elseif ($policy.PrivateCatalogAppsType -eq "BlockedAppList") {
                $riskLevel = "MEDIUM"
                $riskReasons += "Custom apps: All except blocked (broad access)"
            }
            
            $policyInfo = [PSCustomObject]@{
                PolicyName = $policy.Identity
                IsGlobal = ($policy.Identity -eq "Global")
                Description = $policy.Description
                DefaultCatalogAppsType = $policy.DefaultCatalogAppsType
                DefaultCatalogApps = ($policy.DefaultCatalogApps -join ", ")
                GlobalCatalogAppsType = $policy.GlobalCatalogAppsType
                GlobalCatalogApps = ($policy.GlobalCatalogApps -join ", ")
                PrivateCatalogAppsType = $policy.PrivateCatalogAppsType
                PrivateCatalogApps = ($policy.PrivateCatalogApps -join ", ")
                RiskLevel = $riskLevel
                RiskReasons = ($riskReasons -join "; ")
                RiskReasonCount = $riskReasons.Count
            }
            
            # Apply filters
            if ($OnlyHighRisk -and $riskLevel -ne "HIGH" -and $riskLevel -ne "CRITICAL") {
                continue
            }
            
            $script:AppPolicyFindings += $policyInfo
        }
        
        # Get app setup policies
        Invoke-StealthDelay
        
        try {
            $appSetupPolicies = Get-CsTeamsAppSetupPolicy -ErrorAction SilentlyContinue
            
            if ($appSetupPolicies) {
                Write-Host "[+] Found $($appSetupPolicies.Count) app setup policy(ies)" -ForegroundColor Green
                
                foreach ($policy in $appSetupPolicies) {
                    $riskLevel = "LOW"
                    $riskReasons = @()
                    
                    if ($policy.AllowUserPinning -eq $true) {
                        $riskReasons += "User app pinning allowed"
                    }
                    
                    if ($policy.AllowSideloading -eq $true) {
                        $riskLevel = "HIGH"
                        $riskReasons += "App sideloading enabled"
                    }
                    
                    $setupInfo = [PSCustomObject]@{
                        PolicyName = $policy.Identity
                        PolicyType = "AppSetupPolicy"
                        IsGlobal = ($policy.Identity -eq "Global")
                        Description = $policy.Description
                        AllowUserPinning = $policy.AllowUserPinning
                        AllowSideloading = $policy.AllowSideloading
                        PinnedAppBarApps = ($policy.PinnedAppBarApps.Id -join ", ")
                        PinnedMessageBarApps = ($policy.PinnedMessageBarApps.Id -join ", ")
                        RiskLevel = $riskLevel
                        RiskReasons = ($riskReasons -join "; ")
                        RiskReasonCount = $riskReasons.Count
                    }
                    
                    $script:AppPolicyFindings += $setupInfo
                }
            }
        }
        catch {
            Write-Host "[!] Could not get app setup policies" -ForegroundColor Yellow
        }
        
        Write-Host "[+] App policy analysis complete" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing app policies: $_" -ForegroundColor Yellow
    }
}

# Analyze messaging policies
function Get-MessagingPolicyAnalysis {
    Write-Host "`n[*] Analyzing messaging policies..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $messagingPolicies = Get-CsTeamsMessagingPolicy -ErrorAction Stop
        
        Write-Host "[+] Found $($messagingPolicies.Count) messaging policy(ies)" -ForegroundColor Green
        
        foreach ($policy in $messagingPolicies) {
            $riskLevel = "LOW"
            $riskReasons = @()
            
            # Check URL preview
            if ($policy.AllowUrlPreviews -eq $true) {
                $riskReasons += "URL previews enabled"
            }
            
            # Check user translation
            if ($policy.AllowUserTranslation -eq $true) {
                $riskReasons += "User translation enabled"
            }
            
            # Check immersive reader
            if ($policy.AllowImmersiveReader -eq $true) {
                $riskReasons += "Immersive reader enabled"
            }
            
            # Check priority notifications
            if ($policy.AllowPriorityMessages -eq $true) {
                $riskReasons += "Priority notifications enabled"
            }
            
            # Check message editing/deletion
            if ($policy.AllowUserEditMessage -eq $true -and $policy.AllowUserDeleteMessage -eq $true) {
                $riskReasons += "Users can edit and delete messages"
            }
            
            # Check chat permissions
            if ($policy.AllowUserChat -eq $true) {
                $riskReasons += "User chat enabled"
            }
            
            # Check owner delete
            if ($policy.AllowOwnerDeleteMessage -eq $true) {
                $riskReasons += "Owners can delete any message"
            }
            
            # Check read receipts
            if ($policy.ReadReceiptsEnabledType -eq "UserPreference") {
                $riskReasons += "Read receipts: User preference"
            }
            
            # Check Giphy usage
            if ($policy.AllowGiphy -eq $true) {
                if ($policy.GiphyRatingType -eq "NoRestriction") {
                    $riskLevel = "MEDIUM"
                    $riskReasons += "Giphy enabled with NO content restrictions"
                }
                else {
                    $riskReasons += "Giphy enabled: $($policy.GiphyRatingType)"
                }
            }
            
            $policyInfo = [PSCustomObject]@{
                PolicyName = $policy.Identity
                IsGlobal = ($policy.Identity -eq "Global")
                Description = $policy.Description
                
                # Chat Settings
                AllowUserChat = $policy.AllowUserChat
                AllowUserEditMessage = $policy.AllowUserEditMessage
                AllowUserDeleteMessage = $policy.AllowUserDeleteMessage
                AllowOwnerDeleteMessage = $policy.AllowOwnerDeleteMessage
                
                # Content Settings
                AllowUrlPreviews = $policy.AllowUrlPreviews
                AllowGiphy = $policy.AllowGiphy
                GiphyRatingType = $policy.GiphyRatingType
                AllowMemes = $policy.AllowMemes
                AllowStickers = $policy.AllowStickers
                
                # Features
                AllowImmersiveReader = $policy.AllowImmersiveReader
                AllowUserTranslation = $policy.AllowUserTranslation
                AllowPriorityMessages = $policy.AllowPriorityMessages
                
                # Read Receipts
                ReadReceiptsEnabledType = $policy.ReadReceiptsEnabledType
                
                # Channels
                AllowSmartReply = $policy.AllowSmartReply
                
                # Risk Assessment
                RiskLevel = $riskLevel
                RiskReasons = ($riskReasons -join "; ")
                RiskReasonCount = $riskReasons.Count
            }
            
            # Apply filters
            if ($OnlyHighRisk -and $riskLevel -ne "HIGH" -and $riskLevel -ne "CRITICAL") {
                continue
            }
            
            $script:MessagingPolicyFindings += $policyInfo
        }
        
        Write-Host "[+] Messaging policy analysis complete" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing messaging policies: $_" -ForegroundColor Yellow
    }
}

# Analyze Teams inventory
function Get-TeamsInventoryAnalysis {
    Write-Host "`n[*] Analyzing Teams inventory..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get all Teams
        $teams = Get-Team -ErrorAction Stop
        
        Write-Host "[+] Found $($teams.Count) Team(s)" -ForegroundColor Green
        
        $publicTeamsCount = 0
        $archivedTeamsCount = 0
        
        foreach ($team in $teams) {
            $riskLevel = "LOW"
            $riskReasons = @()
            
            # Check visibility
            if ($team.Visibility -eq "Public") {
                $publicTeamsCount++
                $riskLevel = "MEDIUM"
                $riskReasons += "Public Team - anyone in org can join"
            }
            
            # Check if archived
            if ($team.Archived -eq $true) {
                $archivedTeamsCount++
                $riskReasons += "Team is archived"
            }
            
            # Get team details for additional analysis
            try {
                Invoke-StealthDelay
                
                $teamDetails = Get-Team -GroupId $team.GroupId -ErrorAction SilentlyContinue
                
                if ($teamDetails) {
                    # Check guest settings
                    if ($teamDetails.AllowGuestCreateUpdateChannels -eq $true) {
                        $riskLevel = "HIGH"
                        $riskReasons += "Guests can create/update channels"
                    }
                    
                    if ($teamDetails.AllowGuestDeleteChannels -eq $true) {
                        $riskLevel = "HIGH"
                        $riskReasons += "Guests can delete channels"
                    }
                    
                    # Check member settings
                    if ($teamDetails.AllowCreateUpdateChannels -eq $true -and 
                        $teamDetails.AllowDeleteChannels -eq $true -and
                        $teamDetails.AllowCreateUpdateRemoveTabs -eq $true -and
                        $teamDetails.AllowCreateUpdateRemoveConnectors -eq $true) {
                        $riskReasons += "Members have full channel permissions"
                    }
                    
                    if ($teamDetails.AllowAddRemoveApps -eq $true) {
                        $riskReasons += "Members can add/remove apps"
                    }
                }
            }
            catch {
                # Skip detailed analysis for this team
            }
            
            # Get member/owner count
            $memberCount = 0
            $ownerCount = 0
            $guestCount = 0
            
            try {
                $members = Get-TeamUser -GroupId $team.GroupId -ErrorAction SilentlyContinue
                if ($members) {
                    $memberCount = ($members | Where-Object { $_.Role -eq "member" }).Count
                    $ownerCount = ($members | Where-Object { $_.Role -eq "owner" }).Count
                    $guestCount = ($members | Where-Object { $_.Role -eq "guest" }).Count
                    
                    if ($guestCount -gt 0) {
                        $riskReasons += "$guestCount guest member(s)"
                        if ($riskLevel -eq "LOW") {
                            $riskLevel = "MEDIUM"
                        }
                    }
                    
                    if ($ownerCount -eq 1) {
                        $riskReasons += "Single owner - governance risk"
                    }
                }
            }
            catch {
                # Skip member analysis
            }
            
            $teamInfo = [PSCustomObject]@{
                DisplayName = $team.DisplayName
                GroupId = $team.GroupId
                Description = $team.Description
                Visibility = $team.Visibility
                IsArchived = $team.Archived
                MailNickName = $team.MailNickName
                
                # Membership
                MemberCount = $memberCount
                OwnerCount = $ownerCount
                GuestCount = $guestCount
                
                # Guest Permissions (if available)
                AllowGuestCreateUpdateChannels = if ($team.AllowGuestCreateUpdateChannels) { $team.AllowGuestCreateUpdateChannels } else { "N/A" }
                AllowGuestDeleteChannels = if ($team.AllowGuestDeleteChannels) { $team.AllowGuestDeleteChannels } else { "N/A" }
                
                # Member Permissions
                AllowCreateUpdateChannels = if ($team.AllowCreateUpdateChannels) { $team.AllowCreateUpdateChannels } else { "N/A" }
                AllowDeleteChannels = if ($team.AllowDeleteChannels) { $team.AllowDeleteChannels } else { "N/A" }
                AllowAddRemoveApps = if ($team.AllowAddRemoveApps) { $team.AllowAddRemoveApps } else { "N/A" }
                
                # Risk Assessment
                RiskLevel = $riskLevel
                RiskReasons = ($riskReasons -join "; ")
                RiskReasonCount = $riskReasons.Count
            }
            
            # Apply filters
            if ($OnlyHighRisk -and $riskLevel -ne "HIGH" -and $riskLevel -ne "CRITICAL") {
                continue
            }
            
            $script:TeamInventoryFindings += $teamInfo
        }
        
        Write-Host "[+] Teams inventory analysis complete" -ForegroundColor Green
        Write-Host "    Public Teams: $publicTeamsCount" -ForegroundColor Yellow
        Write-Host "    Archived Teams: $archivedTeamsCount" -ForegroundColor Yellow
    }
    catch {
        Write-Host "[!] Error analyzing Teams inventory: $_" -ForegroundColor Yellow
        Write-Host "[!] You may not have permission to enumerate Teams" -ForegroundColor Yellow
    }
}

# Main scanning function
function Start-TeamsSecurityScan {
    Write-Host "`n[*] Starting Microsoft Teams security scan..." -ForegroundColor Cyan
    
    try {
        # Get tenant settings
        Write-Host "[*] Retrieving tenant configuration..." -ForegroundColor Cyan
        Invoke-StealthDelay
        
        try {
            $tenant = Get-CsTenant -ErrorAction SilentlyContinue
            if ($tenant) {
                $script:TenantSettings = [PSCustomObject]@{
                    DisplayName = $tenant.DisplayName
                    TenantId = $tenant.TenantId
                    SipDomain = $tenant.SipDomain
                    IsCoexistenceMaster = $tenant.IsCoexistenceMaster
                    TeamsUpgradeOverridePolicy = $tenant.TeamsUpgradeOverridePolicy
                }
            }
        }
        catch {
            Write-Host "[!] Could not retrieve tenant settings" -ForegroundColor Yellow
        }
        
        # Analyze external access (federation)
        if (-not $OnlyGuestAccess -and -not $OnlyMeetingRisks) {
            Get-ExternalAccessAnalysis
        }
        
        # Analyze guest access
        if (-not $OnlyExternalAccess -and -not $OnlyMeetingRisks) {
            Get-GuestAccessAnalysis
        }
        
        # Analyze meeting policies
        if (-not $OnlyExternalAccess -and -not $OnlyGuestAccess) {
            Get-MeetingPolicyAnalysis
        }
        
        # Analyze app policies if requested
        if ($IncludeAppPolicies) {
            Get-AppPolicyAnalysis
        }
        
        # Analyze messaging policies if requested
        if ($IncludeMessagingPolicies) {
            Get-MessagingPolicyAnalysis
        }
        
        # Analyze Teams inventory if requested
        if ($IncludeTeamsInventory) {
            Get-TeamsInventoryAnalysis
        }
        
        Write-Host "`n[+] Teams security scan complete!" -ForegroundColor Green
    }
    catch {
        Write-Host "`n[ERROR] Failed to scan Teams configuration: $_" -ForegroundColor Red
    }
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 140) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - MICROSOFT TEAMS SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 140) -ForegroundColor Cyan
    
    # === TENANT INFO ===
    if ($script:TenantSettings) {
        Write-Host "`n[TENANT INFORMATION]" -ForegroundColor Yellow
        Write-Host ("-" * 140) -ForegroundColor Cyan
        Write-Host "  Tenant Name: $($script:TenantSettings.DisplayName)" -ForegroundColor White
        Write-Host "  Tenant ID: $($script:TenantSettings.TenantId)" -ForegroundColor Gray
    }
    
    # === EXTERNAL ACCESS ===
    if ($script:ExternalAccessFindings.Count -gt 0) {
        Write-Host "`n[EXTERNAL ACCESS (FEDERATION)]" -ForegroundColor Yellow
        Write-Host ("-" * 140) -ForegroundColor Cyan
        
        foreach ($finding in $script:ExternalAccessFindings) {
            $riskColor = switch ($finding.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                default { "Green" }
            }
            
            Write-Host "  [$($finding.RiskLevel)] External Access Configuration" -ForegroundColor $riskColor
            Write-Host "      Federation Enabled: $($finding.AllowFederatedUsers)" -ForegroundColor Gray
            Write-Host "      Teams Consumer: $($finding.AllowTeamsConsumer)" -ForegroundColor Gray
            Write-Host "      Skype Consumer: $($finding.AllowPublicUsers)" -ForegroundColor Gray
            Write-Host "      Allowed Domains: $($finding.AllowedDomains)" -ForegroundColor Gray
            if ($finding.RiskReasons) {
                Write-Host "      Risk Reasons: $($finding.RiskReasons)" -ForegroundColor DarkGray
            }
        }
    }
    
    # === GUEST ACCESS ===
    if ($script:GuestAccessFindings.Count -gt 0) {
        Write-Host "`n[GUEST ACCESS SETTINGS]" -ForegroundColor Yellow
        Write-Host ("-" * 140) -ForegroundColor Cyan
        
        $sortedGuest = $script:GuestAccessFindings | Sort-Object { 
            switch ($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }
        
        foreach ($finding in $sortedGuest) {
            $riskColor = switch ($finding.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                default { "Green" }
            }
            
            Write-Host "  [$($finding.RiskLevel)] $($finding.ConfigType)" -ForegroundColor $riskColor
            if ($finding.RiskReasons) {
                Write-Host "      Risk Reasons: $($finding.RiskReasons)" -ForegroundColor DarkGray
            }
        }
    }
    
    # === MEETING POLICIES ===
    if ($script:MeetingPolicyFindings.Count -gt 0) {
        Write-Host "`n[MEETING POLICIES]" -ForegroundColor Yellow
        Write-Host ("-" * 140) -ForegroundColor Cyan
        
        $sortedPolicies = $script:MeetingPolicyFindings | Sort-Object { 
            switch ($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }
        
        $matrixData = $sortedPolicies | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='Policy';Expression={if($_.PolicyName.Length -gt 25){$_.PolicyName.Substring(0,22)+"..."}else{$_.PolicyName}}},
            @{Name='AnonJoin';Expression={if($_.AllowAnonymousUsersToJoinMeeting){'YES'}else{'-'}}},
            @{Name='AnonStart';Expression={if($_.AllowAnonymousUsersToStartMeeting){'YES'}else{'-'}}},
            @{Name='LobbyBypass';Expression={$_.AutoAdmittedUsers}},
            @{Name='Recording';Expression={if($_.AllowCloudRecording){'ON'}else{'OFF'}}},
            @{Name='Global';Expression={if($_.IsGlobal){'Yes'}else{'-'}}}
        
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
    }
    
    # === APP POLICIES ===
    if ($script:AppPolicyFindings.Count -gt 0) {
        Write-Host "`n[APP PERMISSION POLICIES]" -ForegroundColor Yellow
        Write-Host ("-" * 140) -ForegroundColor Cyan
        
        foreach ($finding in $script:AppPolicyFindings) {
            $riskColor = switch ($finding.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                default { "Green" }
            }
            
            Write-Host "  [$($finding.RiskLevel)] $($finding.PolicyName)" -ForegroundColor $riskColor
            if ($finding.RiskReasons) {
                Write-Host "      $($finding.RiskReasons)" -ForegroundColor DarkGray
            }
        }
    }
    
    # === MESSAGING POLICIES ===
    if ($script:MessagingPolicyFindings.Count -gt 0) {
        Write-Host "`n[MESSAGING POLICIES]" -ForegroundColor Yellow
        Write-Host ("-" * 140) -ForegroundColor Cyan
        
        foreach ($finding in ($script:MessagingPolicyFindings | Select-Object -First 10)) {
            $riskColor = switch ($finding.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                default { "Green" }
            }
            
            Write-Host "  [$($finding.RiskLevel)] $($finding.PolicyName)" -ForegroundColor $riskColor
            if ($finding.RiskReasons) {
                Write-Host "      $($finding.RiskReasons)" -ForegroundColor DarkGray
            }
        }
    }
    
    # === TEAMS INVENTORY ===
    if ($script:TeamInventoryFindings.Count -gt 0) {
        Write-Host "`n[TEAMS INVENTORY]" -ForegroundColor Yellow
        Write-Host ("-" * 140) -ForegroundColor Cyan
        
        $sortedTeams = $script:TeamInventoryFindings | Sort-Object { 
            switch ($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        } | Select-Object -First 20
        
        $teamsMatrix = $sortedTeams | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='Team Name';Expression={if($_.DisplayName.Length -gt 30){$_.DisplayName.Substring(0,27)+"..."}else{$_.DisplayName}}},
            @{Name='Visibility';Expression={$_.Visibility}},
            @{Name='Members';Expression={$_.MemberCount}},
            @{Name='Owners';Expression={$_.OwnerCount}},
            @{Name='Guests';Expression={$_.GuestCount}},
            @{Name='Archived';Expression={if($_.IsArchived){'Yes'}else{'-'}}}
        
        $teamsMatrix | Format-Table -AutoSize -Wrap | Out-String | ForEach-Object {
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
                else {
                    Write-Host $line -ForegroundColor White
                }
            }
        }
        
        if ($script:TeamInventoryFindings.Count -gt 20) {
            Write-Host "  ... and $($script:TeamInventoryFindings.Count - 20) more team(s)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "`n" + ("=" * 140) -ForegroundColor Cyan
    
    # === SUMMARY SECTION ===
    Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
    
    # External Access Summary
    if ($script:ExternalAccessFindings.Count -gt 0) {
        $extCritical = ($script:ExternalAccessFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $extHigh = ($script:ExternalAccessFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        
        Write-Host "`n[EXTERNAL ACCESS]" -ForegroundColor Cyan
        Write-Host "  CRITICAL findings: $extCritical" -ForegroundColor $(if($extCritical -gt 0){"Red"}else{"Green"})
        Write-Host "  HIGH findings: $extHigh" -ForegroundColor $(if($extHigh -gt 0){"Yellow"}else{"Green"})
    }
    
    # Meeting Policies Summary
    if ($script:MeetingPolicyFindings.Count -gt 0) {
        $mtgCritical = ($script:MeetingPolicyFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $mtgHigh = ($script:MeetingPolicyFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mtgMedium = ($script:MeetingPolicyFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $anonJoinEnabled = ($script:MeetingPolicyFindings | Where-Object { $_.AllowAnonymousUsersToJoinMeeting -eq $true }).Count
        
        Write-Host "`n[MEETING POLICIES]" -ForegroundColor Cyan
        Write-Host "  Total policies: $($script:MeetingPolicyFindings.Count)" -ForegroundColor White
        Write-Host "  CRITICAL risk: $mtgCritical" -ForegroundColor $(if($mtgCritical -gt 0){"Red"}else{"Green"})
        Write-Host "  HIGH risk: $mtgHigh" -ForegroundColor $(if($mtgHigh -gt 0){"Yellow"}else{"Green"})
        Write-Host "  MEDIUM risk: $mtgMedium" -ForegroundColor $(if($mtgMedium -gt 0){"Cyan"}else{"Green"})
        Write-Host "  Anonymous join enabled: $anonJoinEnabled" -ForegroundColor $(if($anonJoinEnabled -gt 0){"Yellow"}else{"Green"})
    }
    
    # Guest Access Summary
    if ($script:GuestAccessFindings.Count -gt 0) {
        $guestHigh = ($script:GuestAccessFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $guestMedium = ($script:GuestAccessFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        
        Write-Host "`n[GUEST ACCESS]" -ForegroundColor Cyan
        Write-Host "  HIGH risk: $guestHigh" -ForegroundColor $(if($guestHigh -gt 0){"Yellow"}else{"Green"})
        Write-Host "  MEDIUM risk: $guestMedium" -ForegroundColor $(if($guestMedium -gt 0){"Cyan"}else{"Green"})
    }
    
    # Teams Inventory Summary
    if ($script:TeamInventoryFindings.Count -gt 0) {
        $publicTeams = ($script:TeamInventoryFindings | Where-Object { $_.Visibility -eq "Public" }).Count
        $teamsWithGuests = ($script:TeamInventoryFindings | Where-Object { $_.GuestCount -gt 0 }).Count
        
        Write-Host "`n[TEAMS INVENTORY]" -ForegroundColor Cyan
        Write-Host "  Total Teams: $($script:TeamInventoryFindings.Count)" -ForegroundColor White
        Write-Host "  Public Teams: $publicTeams" -ForegroundColor $(if($publicTeams -gt 0){"Yellow"}else{"Green"})
        Write-Host "  Teams with Guests: $teamsWithGuests" -ForegroundColor $(if($teamsWithGuests -gt 0){"Yellow"}else{"Green"})
    }
    
    Write-Host ""
}

# Display standard results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    # External Access
    if ($script:ExternalAccessFindings.Count -gt 0) {
        Write-Host "`n[EXTERNAL ACCESS (FEDERATION)]" -ForegroundColor Yellow
        
        foreach ($finding in $script:ExternalAccessFindings) {
            $riskColor = switch ($finding.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                default { "Green" }
            }
            
            Write-Host "`n[$($finding.RiskLevel)] $($finding.ConfigType)" -ForegroundColor $riskColor
            Write-Host "  Federation Enabled: $($finding.AllowFederatedUsers)" -ForegroundColor Gray
            Write-Host "  Teams Consumer: $($finding.AllowTeamsConsumer)" -ForegroundColor Gray
            Write-Host "  Skype Consumer: $($finding.AllowPublicUsers)" -ForegroundColor Gray
            Write-Host "  Allowed Domains: $($finding.AllowedDomains)" -ForegroundColor Gray
            
            if ($finding.RiskReasons) {
                Write-Host "  Risk Reasons: $($finding.RiskReasons)" -ForegroundColor DarkGray
            }
        }
    }
    
    # Meeting Policies
    if ($script:MeetingPolicyFindings.Count -gt 0) {
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "MEETING POLICIES:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $sortedPolicies = $script:MeetingPolicyFindings | Sort-Object { 
            switch ($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }
        
        foreach ($policy in $sortedPolicies) {
            $riskColor = switch ($policy.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($policy.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host $policy.PolicyName -ForegroundColor White
            
            Write-Host "  Anonymous Join: $($policy.AllowAnonymousUsersToJoinMeeting)" -ForegroundColor Gray
            Write-Host "  Anonymous Start: $($policy.AllowAnonymousUsersToStartMeeting)" -ForegroundColor Gray
            Write-Host "  Auto-Admitted: $($policy.AutoAdmittedUsers)" -ForegroundColor Gray
            Write-Host "  Recording: $($policy.AllowCloudRecording)" -ForegroundColor Gray
            
            if ($policy.RiskReasons) {
                Write-Host "  Risk Reasons: $($policy.RiskReasons)" -ForegroundColor DarkGray
            }
        }
    }
    
    # Guest Access
    if ($script:GuestAccessFindings.Count -gt 0) {
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "GUEST ACCESS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        foreach ($finding in $script:GuestAccessFindings) {
            $riskColor = switch ($finding.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                default { "Green" }
            }
            
            Write-Host "`n[$($finding.RiskLevel)] $($finding.ConfigType)" -ForegroundColor $riskColor
            if ($finding.RiskReasons) {
                Write-Host "  Risk Reasons: $($finding.RiskReasons)" -ForegroundColor DarkGray
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
    
    $totalFindings = $script:ExternalAccessFindings.Count + $script:GuestAccessFindings.Count + 
                     $script:MeetingPolicyFindings.Count + $script:AppPolicyFindings.Count +
                     $script:MessagingPolicyFindings.Count + $script:TeamInventoryFindings.Count
    
    if ($totalFindings -eq 0) {
        Write-Host "`n[*] No results to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        $basePath = [System.IO.Path]::GetDirectoryName($Path)
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        
        # Export external access findings
        if ($script:ExternalAccessFindings.Count -gt 0) {
            $extPath = if ($basePath) { Join-Path $basePath "$baseName-externalaccess$extension" } else { "$baseName-externalaccess$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:ExternalAccessFindings | Export-Csv -Path $extPath -NoTypeInformation -Encoding UTF8
                    Write-Host "`n[+] External access exported to CSV: $extPath" -ForegroundColor Green
                }
                ".json" {
                    $script:ExternalAccessFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $extPath -Encoding UTF8
                    Write-Host "`n[+] External access exported to JSON: $extPath" -ForegroundColor Green
                }
                default {
                    $csvPath = [System.IO.Path]::ChangeExtension($extPath, ".csv")
                    $script:ExternalAccessFindings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                    Write-Host "`n[+] External access exported to CSV: $csvPath" -ForegroundColor Green
                }
            }
        }
        
        # Export meeting policy findings
        if ($script:MeetingPolicyFindings.Count -gt 0) {
            $mtgPath = if ($basePath) { Join-Path $basePath "$baseName-meetingpolicies$extension" } else { "$baseName-meetingpolicies$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:MeetingPolicyFindings | Export-Csv -Path $mtgPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Meeting policies exported to CSV: $mtgPath" -ForegroundColor Green
                }
                ".json" {
                    $script:MeetingPolicyFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $mtgPath -Encoding UTF8
                    Write-Host "[+] Meeting policies exported to JSON: $mtgPath" -ForegroundColor Green
                }
            }
        }
        
        # Export guest access findings
        if ($script:GuestAccessFindings.Count -gt 0) {
            $guestPath = if ($basePath) { Join-Path $basePath "$baseName-guestaccess$extension" } else { "$baseName-guestaccess$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:GuestAccessFindings | Export-Csv -Path $guestPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Guest access exported to CSV: $guestPath" -ForegroundColor Green
                }
                ".json" {
                    $script:GuestAccessFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $guestPath -Encoding UTF8
                    Write-Host "[+] Guest access exported to JSON: $guestPath" -ForegroundColor Green
                }
            }
        }
        
        # Export app policy findings
        if ($script:AppPolicyFindings.Count -gt 0) {
            $appPath = if ($basePath) { Join-Path $basePath "$baseName-apppolicies$extension" } else { "$baseName-apppolicies$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:AppPolicyFindings | Export-Csv -Path $appPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] App policies exported to CSV: $appPath" -ForegroundColor Green
                }
                ".json" {
                    $script:AppPolicyFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $appPath -Encoding UTF8
                    Write-Host "[+] App policies exported to JSON: $appPath" -ForegroundColor Green
                }
            }
        }
        
        # Export messaging policy findings
        if ($script:MessagingPolicyFindings.Count -gt 0) {
            $msgPath = if ($basePath) { Join-Path $basePath "$baseName-messagingpolicies$extension" } else { "$baseName-messagingpolicies$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:MessagingPolicyFindings | Export-Csv -Path $msgPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Messaging policies exported to CSV: $msgPath" -ForegroundColor Green
                }
                ".json" {
                    $script:MessagingPolicyFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $msgPath -Encoding UTF8
                    Write-Host "[+] Messaging policies exported to JSON: $msgPath" -ForegroundColor Green
                }
            }
        }
        
        # Export Teams inventory
        if ($script:TeamInventoryFindings.Count -gt 0) {
            $teamsPath = if ($basePath) { Join-Path $basePath "$baseName-teamsinventory$extension" } else { "$baseName-teamsinventory$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:TeamInventoryFindings | Export-Csv -Path $teamsPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Teams inventory exported to CSV: $teamsPath" -ForegroundColor Green
                }
                ".json" {
                    $script:TeamInventoryFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $teamsPath -Encoding UTF8
                    Write-Host "[+] Teams inventory exported to JSON: $teamsPath" -ForegroundColor Green
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
        # Disconnect from Microsoft Teams
        Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] Disconnected from Microsoft Teams" -ForegroundColor Green
        # Disconnect from Microsoft Graph if connected
        try {
            $mgContext = Get-MgContext -ErrorAction SilentlyContinue
            if ($mgContext) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                Write-Host "[+] Disconnected from Microsoft Graph" -ForegroundColor Green
            }
        } catch { }
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
        if (-not (Test-TeamsModule)) {
            exit 1
        }
        
        # Initialize and import modules
        if (-not (Initialize-TeamsModule)) {
            Write-Host "`n[ERROR] Failed to initialize modules. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Connect to Microsoft Teams
        if (-not (Connect-TeamsService)) {
            Write-Host "`n[ERROR] Connection failed. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Start scan
        Start-TeamsSecurityScan
        
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
        
        Write-Host "`n[*] Teams security check completed successfully!" -ForegroundColor Green
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
