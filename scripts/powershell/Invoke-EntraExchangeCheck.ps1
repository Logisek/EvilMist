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
    Detects mail-based attack vectors and data exfiltration risks in Exchange Online.

.DESCRIPTION
    This script performs a comprehensive audit of Exchange Online security to identify
    potential security risks including:
    - Inbox rules forwarding to external addresses (data exfiltration)
    - Transport rules analysis (mail flow rules)
    - Auto-forwarding settings
    - Mailbox delegation and permissions
    - Mailbox audit logging status
    - OWA (Outlook Web App) policies
    - Client access rules
    - SMTP forwarding configuration
    
    Exchange Online security is critical for preventing data exfiltration and
    detecting business email compromise (BEC) attacks. This script provides
    red/blue team visibility into mail-based attack vectors.
    
    The script uses Exchange Online PowerShell module for authentication
    and API access.

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

.PARAMETER OnlyExternalForwarding
    Show only mailboxes with external forwarding configured.

.PARAMETER OnlyHighRisk
    Show only HIGH and CRITICAL risk findings.

.PARAMETER OnlySuspiciousRules
    Show only suspicious inbox rules (forwarding, deleting, redirecting).

.PARAMETER OnlyNoAudit
    Show only mailboxes without audit logging enabled.

.PARAMETER IncludeTransportRules
    Include transport (mail flow) rules analysis.

.PARAMETER IncludeClientAccess
    Include client access rules analysis.

.PARAMETER IncludeOWAPolicies
    Include OWA (Outlook Web App) policies analysis.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraExchangeCheck.ps1
    # Enumerate all Exchange security configurations

.EXAMPLE
    .\Invoke-EntraExchangeCheck.ps1 -ExportPath "exchange-security.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraExchangeCheck.ps1 -OnlyExternalForwarding -Matrix
    # Show only mailboxes with external forwarding in matrix format

.EXAMPLE
    .\Invoke-EntraExchangeCheck.ps1 -OnlySuspiciousRules
    # Show only suspicious inbox rules

.EXAMPLE
    .\Invoke-EntraExchangeCheck.ps1 -IncludeTransportRules -IncludeClientAccess -Matrix
    # Include transport rules and client access rules

.EXAMPLE
    .\Invoke-EntraExchangeCheck.ps1 -EnableStealth -QuietStealth
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
    [switch]$OnlyExternalForwarding,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyHighRisk,

    [Parameter(Mandatory = $false)]
    [switch]$OnlySuspiciousRules,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyNoAudit,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeTransportRules,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeClientAccess,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeOWAPolicies,

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

# Suspicious rule action patterns - indicates potential data exfiltration
$script:SuspiciousRuleActions = @(
    "ForwardTo",
    "ForwardAsAttachmentTo",
    "RedirectTo",
    "DeleteMessage",
    "MoveToFolder"  # Moving to obscure folders to hide emails
)

# Suspicious rule conditions - attacker trying to hide their activity
$script:SuspiciousRuleConditions = @(
    "SubjectContains",
    "SubjectOrBodyContains",
    "FromAddressContains",
    "HasAttachment",
    "SentTo"
)

# Known malicious keywords in rule names (common BEC patterns)
$script:SuspiciousRuleNames = @(
    "invoice",
    "payment",
    "wire",
    "transfer",
    "urgent",
    "confidential",
    "bank",
    "update",
    "verify",
    "account"
)

# External domain patterns that may indicate exfiltration
$script:SuspiciousDomainPatterns = @(
    "*.onmicrosoft.com",
    "*.outlook.com",
    "*.gmail.com",
    "*.yahoo.com",
    "*.hotmail.com",
    "*.protonmail.com",
    "*.proton.me"
)

# Track state
$script:MailboxFindings = @()
$script:InboxRuleFindings = @()
$script:TransportRuleFindings = @()
$script:DelegationFindings = @()
$script:ClientAccessFindings = @()
$script:OWAPolicyFindings = @()
$script:TotalMailboxesScanned = 0
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
    Write-Host "    Entra ID Exchange Check - Mail Security & Data Exfiltration Detection" -ForegroundColor Yellow
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

# Check if ExchangeOnlineManagement module is installed
function Test-ExchangeModule {
    Write-Host "[*] Checking ExchangeOnlineManagement PowerShell module..." -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Host "[!] ExchangeOnlineManagement module is not installed" -ForegroundColor Yellow
        Write-Host "`n[*] Installing ExchangeOnlineManagement module automatically..." -ForegroundColor Cyan
        
        # Check if running as administrator for AllUsers scope
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $scope = if ($isAdmin) { "AllUsers" } else { "CurrentUser" }
        
        try {
            # Set PSGallery as trusted if not already
            $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($psGallery -and $psGallery.InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            }
            
            Install-Module -Name ExchangeOnlineManagement -Scope $scope -AllowClobber -Force -ErrorAction Stop
            Write-Host "[+] Successfully installed ExchangeOnlineManagement" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERROR] Failed to install ExchangeOnlineManagement: $_" -ForegroundColor Red
            Write-Host "[*] Try manually: Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force" -ForegroundColor Yellow
            return $false
        }
    }
    
    Write-Host "[+] ExchangeOnlineManagement module is installed" -ForegroundColor Green
    return $true
}

# Initialize and import Exchange module
function Initialize-ExchangeModule {
    Write-Host "[*] Initializing ExchangeOnlineManagement module..." -ForegroundColor Cyan
    
    try {
        # Remove any loaded Exchange modules to avoid conflicts
        $loadedModules = Get-Module ExchangeOnlineManagement
        if ($loadedModules) {
            Write-Host "[*] Cleaning up loaded Exchange modules..." -ForegroundColor Yellow
            $loadedModules | ForEach-Object {
                Remove-Module $_.Name -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Import the module
        Write-Host "[*] Importing ExchangeOnlineManagement..." -ForegroundColor Cyan
        Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
        
        Write-Host "[+] Module imported successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to import module: $_" -ForegroundColor Red
        Write-Host "[*] Try running: Update-Module ExchangeOnlineManagement -Force" -ForegroundColor Yellow
        return $false
    }
}

# Connect to Exchange Online
function Connect-ExchangeService {
    Write-Host "`n[*] Connecting to Exchange Online..." -ForegroundColor Cyan
    
    try {
        # Check if already connected
        $existingSession = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if ($existingSession) {
            Write-Host "[+] Already connected to Exchange Online" -ForegroundColor Green
            Write-Host "[+] Organization: $($existingSession.Organization)" -ForegroundColor Green
            $script:TenantDomain = $existingSession.Organization
            return $true
        }
        
        # Connect parameters
        $connectParams = @{
            ShowBanner = $false
        }
        
        if ($TenantId) {
            # Try to use organization name from tenant ID
            $connectParams['Organization'] = $TenantId
        }
        
        # Try Azure CLI token if requested
        if ($UseAzCliToken) {
            try {
                Write-Host "[*] Attempting to use Azure CLI token..." -ForegroundColor Cyan
                $azToken = az account get-access-token --resource https://outlook.office365.com --query accessToken -o tsv 2>$null
                if ($azToken -and $azToken.Length -gt 0) {
                    Write-Host "[+] Successfully retrieved Azure CLI token" -ForegroundColor Green
                    # Exchange Online module doesn't directly support access tokens in older versions
                    # Try connecting with certificate-based auth or interactive
                    Write-Host "[!] Azure CLI token obtained, but Exchange Online requires interactive auth" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "[!] Failed to retrieve Azure CLI token" -ForegroundColor Yellow
            }
        }
        
        # Connect interactively
        Write-Host "[*] Initiating interactive authentication..." -ForegroundColor Cyan
        Connect-ExchangeOnline @connectParams -ErrorAction Stop
        
        # Get connection info
        $connectionInfo = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if ($connectionInfo) {
            $script:TenantDomain = $connectionInfo.Organization
            Write-Host "[+] Connected to Exchange Online" -ForegroundColor Green
            Write-Host "[+] Organization: $($connectionInfo.Organization)" -ForegroundColor Green
            Write-Host "[+] User: $($connectionInfo.UserPrincipalName)" -ForegroundColor Green
            return $true
        }
        
        Write-Host "[+] Connected to Exchange Online" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to connect to Exchange Online: $_" -ForegroundColor Red
        Write-Host "[*] Make sure you have the necessary permissions:" -ForegroundColor Yellow
        Write-Host "    - Exchange Administrator or Global Administrator role" -ForegroundColor Yellow
        Write-Host "    - Or appropriate RBAC permissions for reading mailbox configurations" -ForegroundColor Yellow
        return $false
    }
}

# Check if email address is external to the tenant
function Test-IsExternalAddress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EmailAddress
    )
    
    if ([string]::IsNullOrWhiteSpace($EmailAddress)) {
        return $false
    }
    
    # Extract domain from email
    if ($EmailAddress -match '@(.+)$') {
        $domain = $matches[1].ToLower()
        
        # Check against tenant domain
        if ($script:TenantDomain -and $domain -eq $script:TenantDomain.ToLower()) {
            return $false
        }
        
        # Check if it's part of the accepted domains
        try {
            $acceptedDomains = Get-AcceptedDomain -ErrorAction SilentlyContinue
            if ($acceptedDomains) {
                foreach ($acceptedDomain in $acceptedDomains) {
                    if ($domain -eq $acceptedDomain.DomainName.ToLower()) {
                        return $false
                    }
                }
            }
        }
        catch {
            # If we can't get accepted domains, assume external if not matching tenant
        }
        
        return $true
    }
    
    return $false
}

# Analyze inbox rules for a mailbox
function Get-MailboxInboxRulesAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MailboxIdentity,
        
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    try {
        Invoke-StealthDelay
        
        $inboxRules = Get-InboxRule -Mailbox $MailboxIdentity -ErrorAction Stop
        
        $ruleFindings = @()
        
        foreach ($rule in $inboxRules) {
            $isSuspicious = $false
            $suspiciousReasons = @()
            $externalTargets = @()
            $riskLevel = "LOW"
            
            # Check for forwarding to external addresses
            if ($rule.ForwardTo) {
                foreach ($target in $rule.ForwardTo) {
                    $targetAddress = $target.ToString()
                    if (Test-IsExternalAddress -EmailAddress $targetAddress) {
                        $isSuspicious = $true
                        $externalTargets += $targetAddress
                        $suspiciousReasons += "ForwardTo external: $targetAddress"
                        $riskLevel = "CRITICAL"
                    }
                }
            }
            
            # Check for forwarding as attachment to external addresses
            if ($rule.ForwardAsAttachmentTo) {
                foreach ($target in $rule.ForwardAsAttachmentTo) {
                    $targetAddress = $target.ToString()
                    if (Test-IsExternalAddress -EmailAddress $targetAddress) {
                        $isSuspicious = $true
                        $externalTargets += $targetAddress
                        $suspiciousReasons += "ForwardAsAttachment external: $targetAddress"
                        $riskLevel = "CRITICAL"
                    }
                }
            }
            
            # Check for redirect to external addresses
            if ($rule.RedirectTo) {
                foreach ($target in $rule.RedirectTo) {
                    $targetAddress = $target.ToString()
                    if (Test-IsExternalAddress -EmailAddress $targetAddress) {
                        $isSuspicious = $true
                        $externalTargets += $targetAddress
                        $suspiciousReasons += "RedirectTo external: $targetAddress"
                        $riskLevel = "CRITICAL"
                    }
                }
            }
            
            # Check for delete message action (hiding emails)
            if ($rule.DeleteMessage -eq $true) {
                $isSuspicious = $true
                $suspiciousReasons += "DeleteMessage enabled"
                if ($riskLevel -ne "CRITICAL") {
                    $riskLevel = "HIGH"
                }
            }
            
            # Check for suspicious keywords in rule name
            $ruleName = $rule.Name.ToLower()
            foreach ($keyword in $script:SuspiciousRuleNames) {
                if ($ruleName -like "*$keyword*") {
                    $isSuspicious = $true
                    $suspiciousReasons += "Suspicious keyword in name: $keyword"
                    if ($riskLevel -eq "LOW") {
                        $riskLevel = "MEDIUM"
                    }
                    break
                }
            }
            
            # Check if rule was created by someone other than the mailbox owner
            if ($rule.RuleIdentity -and $rule.RuleIdentity -notlike "*$UserPrincipalName*") {
                $suspiciousReasons += "Potentially created by different user"
                if ($riskLevel -eq "LOW") {
                    $riskLevel = "MEDIUM"
                }
            }
            
            # Check for hidden rules (moving to obscure folders)
            if ($rule.MoveToFolder -and $rule.MoveToFolder -like "*RSS*" -or $rule.MoveToFolder -like "*Archive*" -or $rule.MoveToFolder -like "*Junk*") {
                $isSuspicious = $true
                $suspiciousReasons += "Moving to hidden/obscure folder: $($rule.MoveToFolder)"
                if ($riskLevel -eq "LOW") {
                    $riskLevel = "MEDIUM"
                }
            }
            
            # Check if rule applies to all messages (broad scope)
            $hasNoConditions = $true
            if ($rule.SubjectContainsWords -or $rule.SubjectOrBodyContainsWords -or $rule.FromAddressContainsWords -or 
                $rule.From -or $rule.SentTo -or $rule.HasAttachment) {
                $hasNoConditions = $false
            }
            
            if ($hasNoConditions -and ($rule.ForwardTo -or $rule.RedirectTo -or $rule.DeleteMessage)) {
                $suspiciousReasons += "Rule applies to ALL messages (no conditions)"
                if ($riskLevel -eq "LOW" -or $riskLevel -eq "MEDIUM") {
                    $riskLevel = "HIGH"
                }
            }
            
            # Build actions list
            $actions = @()
            if ($rule.ForwardTo) { $actions += "Forward" }
            if ($rule.ForwardAsAttachmentTo) { $actions += "ForwardAsAttachment" }
            if ($rule.RedirectTo) { $actions += "Redirect" }
            if ($rule.DeleteMessage) { $actions += "Delete" }
            if ($rule.MoveToFolder) { $actions += "Move" }
            if ($rule.MarkAsRead) { $actions += "MarkAsRead" }
            if ($rule.StopProcessingRules) { $actions += "StopProcessing" }
            
            # Build conditions list
            $conditions = @()
            if ($rule.SubjectContainsWords) { $conditions += "Subject: $($rule.SubjectContainsWords -join ', ')" }
            if ($rule.SubjectOrBodyContainsWords) { $conditions += "SubjectOrBody: $($rule.SubjectOrBodyContainsWords -join ', ')" }
            if ($rule.FromAddressContainsWords) { $conditions += "FromAddress: $($rule.FromAddressContainsWords -join ', ')" }
            if ($rule.From) { $conditions += "From: $($rule.From -join ', ')" }
            if ($rule.SentTo) { $conditions += "SentTo: $($rule.SentTo -join ', ')" }
            if ($rule.HasAttachment) { $conditions += "HasAttachment" }
            
            $ruleInfo = [PSCustomObject]@{
                MailboxIdentity = $MailboxIdentity
                UserPrincipalName = $UserPrincipalName
                RuleName = $rule.Name
                RuleIdentity = $rule.RuleIdentity
                RulePriority = $rule.Priority
                RuleEnabled = $rule.Enabled
                IsSuspicious = $isSuspicious
                SuspiciousReasons = ($suspiciousReasons -join "; ")
                HasExternalForwarding = ($externalTargets.Count -gt 0)
                ExternalTargets = ($externalTargets -join ", ")
                ExternalTargetCount = $externalTargets.Count
                Actions = ($actions -join ", ")
                ActionCount = $actions.Count
                Conditions = ($conditions -join "; ")
                ConditionCount = $conditions.Count
                HasNoConditions = $hasNoConditions
                ForwardTo = ($rule.ForwardTo -join ", ")
                RedirectTo = ($rule.RedirectTo -join ", ")
                DeleteMessage = $rule.DeleteMessage
                MoveToFolder = $rule.MoveToFolder
                StopProcessingRules = $rule.StopProcessingRules
                RiskLevel = $riskLevel
            }
            
            # Apply filters
            if ($OnlySuspiciousRules -and -not $isSuspicious) {
                continue
            }
            
            if ($OnlyHighRisk -and $riskLevel -ne "HIGH" -and $riskLevel -ne "CRITICAL") {
                continue
            }
            
            $ruleFindings += $ruleInfo
        }
        
        return $ruleFindings
    }
    catch {
        Write-Host "[!] Error getting inbox rules for $MailboxIdentity : $_" -ForegroundColor Yellow
        return @()
    }
}

# Get mailbox forwarding configuration
function Get-MailboxForwardingAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        $Mailbox
    )
    
    $forwardingInfo = @{
        HasForwarding = $false
        ForwardingAddress = $null
        ForwardingSmtpAddress = $null
        DeliverToMailboxAndForward = $false
        IsExternalForwarding = $false
        ForwardingRiskLevel = "NONE"
    }
    
    # Check ForwardingAddress (internal forwarding)
    if ($Mailbox.ForwardingAddress) {
        $forwardingInfo.HasForwarding = $true
        $forwardingInfo.ForwardingAddress = $Mailbox.ForwardingAddress
        $forwardingInfo.DeliverToMailboxAndForward = $Mailbox.DeliverToMailboxAndForward
        $forwardingInfo.ForwardingRiskLevel = "MEDIUM"
    }
    
    # Check ForwardingSMTPAddress (external forwarding)
    if ($Mailbox.ForwardingSmtpAddress) {
        $forwardingInfo.HasForwarding = $true
        $smtpAddress = $Mailbox.ForwardingSmtpAddress.ToString()
        if ($smtpAddress -match 'smtp:(.+)$') {
            $smtpAddress = $matches[1]
        }
        $forwardingInfo.ForwardingSmtpAddress = $smtpAddress
        $forwardingInfo.DeliverToMailboxAndForward = $Mailbox.DeliverToMailboxAndForward
        
        if (Test-IsExternalAddress -EmailAddress $smtpAddress) {
            $forwardingInfo.IsExternalForwarding = $true
            $forwardingInfo.ForwardingRiskLevel = "CRITICAL"
        }
        else {
            $forwardingInfo.ForwardingRiskLevel = "MEDIUM"
        }
    }
    
    return $forwardingInfo
}

# Get mailbox delegation/permissions
function Get-MailboxDelegationAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MailboxIdentity,
        
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    $delegationFindings = @()
    
    try {
        Invoke-StealthDelay
        
        # Get mailbox permissions (Full Access)
        $permissions = Get-MailboxPermission -Identity $MailboxIdentity -ErrorAction Stop | 
                       Where-Object { $_.User -ne "NT AUTHORITY\SELF" -and $_.IsInherited -eq $false }
        
        foreach ($perm in $permissions) {
            $delegateUser = $perm.User.ToString()
            $riskLevel = "LOW"
            
            # Check if delegate is external
            $isExternal = Test-IsExternalAddress -EmailAddress $delegateUser
            if ($isExternal) {
                $riskLevel = "HIGH"
            }
            
            # Full Access is high risk
            if ($perm.AccessRights -contains "FullAccess") {
                if ($riskLevel -ne "HIGH") {
                    $riskLevel = "MEDIUM"
                }
            }
            
            $delegationInfo = [PSCustomObject]@{
                MailboxIdentity = $MailboxIdentity
                UserPrincipalName = $UserPrincipalName
                DelegateUser = $delegateUser
                DelegateType = "MailboxPermission"
                AccessRights = ($perm.AccessRights -join ", ")
                IsInherited = $perm.IsInherited
                IsExternal = $isExternal
                RiskLevel = $riskLevel
            }
            
            $delegationFindings += $delegationInfo
        }
        
        Invoke-StealthDelay
        
        # Get Send-As permissions
        $sendAsPermissions = Get-RecipientPermission -Identity $MailboxIdentity -ErrorAction SilentlyContinue | 
                             Where-Object { $_.Trustee -ne "NT AUTHORITY\SELF" }
        
        foreach ($perm in $sendAsPermissions) {
            $delegateUser = $perm.Trustee.ToString()
            $riskLevel = "MEDIUM"  # SendAs is always at least medium risk
            
            # Check if delegate is external
            $isExternal = Test-IsExternalAddress -EmailAddress $delegateUser
            if ($isExternal) {
                $riskLevel = "HIGH"
            }
            
            $delegationInfo = [PSCustomObject]@{
                MailboxIdentity = $MailboxIdentity
                UserPrincipalName = $UserPrincipalName
                DelegateUser = $delegateUser
                DelegateType = "SendAs"
                AccessRights = ($perm.AccessRights -join ", ")
                IsInherited = $perm.IsInherited
                IsExternal = $isExternal
                RiskLevel = $riskLevel
            }
            
            $delegationFindings += $delegationInfo
        }
        
        Invoke-StealthDelay
        
        # Get Send-On-Behalf permissions from mailbox
        $mailbox = Get-Mailbox -Identity $MailboxIdentity -ErrorAction SilentlyContinue
        if ($mailbox -and $mailbox.GrantSendOnBehalfTo) {
            foreach ($delegate in $mailbox.GrantSendOnBehalfTo) {
                $delegateUser = $delegate.ToString()
                $riskLevel = "LOW"
                
                # Check if delegate is external
                $isExternal = Test-IsExternalAddress -EmailAddress $delegateUser
                if ($isExternal) {
                    $riskLevel = "MEDIUM"
                }
                
                $delegationInfo = [PSCustomObject]@{
                    MailboxIdentity = $MailboxIdentity
                    UserPrincipalName = $UserPrincipalName
                    DelegateUser = $delegateUser
                    DelegateType = "SendOnBehalf"
                    AccessRights = "SendOnBehalf"
                    IsInherited = $false
                    IsExternal = $isExternal
                    RiskLevel = $riskLevel
                }
                
                $delegationFindings += $delegationInfo
            }
        }
    }
    catch {
        Write-Host "[!] Error getting delegation for $MailboxIdentity : $_" -ForegroundColor Yellow
    }
    
    return $delegationFindings
}

# Get transport rules (mail flow rules)
function Get-TransportRulesAnalysis {
    Write-Host "`n[*] Analyzing transport rules (mail flow rules)..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $transportRules = Get-TransportRule -ErrorAction Stop
        
        Write-Host "[+] Found $($transportRules.Count) transport rule(s)" -ForegroundColor Green
        
        foreach ($rule in $transportRules) {
            $isSuspicious = $false
            $suspiciousReasons = @()
            $riskLevel = "LOW"
            
            # Check for external forwarding/redirect actions
            if ($rule.BlindCopyTo -or $rule.CopyTo -or $rule.RedirectMessageTo) {
                $targets = @()
                if ($rule.BlindCopyTo) { $targets += $rule.BlindCopyTo }
                if ($rule.CopyTo) { $targets += $rule.CopyTo }
                if ($rule.RedirectMessageTo) { $targets += $rule.RedirectMessageTo }
                
                foreach ($target in $targets) {
                    if (Test-IsExternalAddress -EmailAddress $target.ToString()) {
                        $isSuspicious = $true
                        $suspiciousReasons += "External forwarding: $target"
                        $riskLevel = "CRITICAL"
                    }
                }
            }
            
            # Check for message modification actions
            if ($rule.RemoveHeader -or $rule.SetHeaderName) {
                $isSuspicious = $true
                $suspiciousReasons += "Message header modification"
                if ($riskLevel -eq "LOW") {
                    $riskLevel = "MEDIUM"
                }
            }
            
            # Check for rule that deletes messages
            if ($rule.DeleteMessage -eq $true) {
                $isSuspicious = $true
                $suspiciousReasons += "Deletes messages"
                $riskLevel = "HIGH"
            }
            
            # Check for bypass of spam/security filters
            if ($rule.SetSCL -eq -1 -or $rule.SetHeaderValue -like "*bypass*") {
                $isSuspicious = $true
                $suspiciousReasons += "Bypasses spam filtering"
                $riskLevel = "HIGH"
            }
            
            # Check for broad scope (applies to all messages)
            $hasConditions = $rule.Conditions -and $rule.Conditions.Count -gt 0
            if (-not $hasConditions -and $rule.State -eq "Enabled") {
                $suspiciousReasons += "Applies to ALL messages (no conditions)"
                if ($riskLevel -eq "LOW") {
                    $riskLevel = "MEDIUM"
                }
            }
            
            # Build actions list
            $actions = @()
            if ($rule.BlindCopyTo) { $actions += "BCC: $($rule.BlindCopyTo -join ', ')" }
            if ($rule.CopyTo) { $actions += "CC: $($rule.CopyTo -join ', ')" }
            if ($rule.RedirectMessageTo) { $actions += "Redirect: $($rule.RedirectMessageTo -join ', ')" }
            if ($rule.DeleteMessage) { $actions += "Delete" }
            if ($rule.ModerateMessageByUser) { $actions += "Moderate" }
            if ($rule.SetSCL) { $actions += "SetSCL: $($rule.SetSCL)" }
            if ($rule.AddToRecipients) { $actions += "AddToRecipients" }
            if ($rule.PrependSubject) { $actions += "PrependSubject" }
            if ($rule.ApplyHtmlDisclaimerLocation) { $actions += "AddDisclaimer" }
            
            $ruleInfo = [PSCustomObject]@{
                RuleName = $rule.Name
                RuleGuid = $rule.Guid
                RulePriority = $rule.Priority
                RuleState = $rule.State
                RuleMode = $rule.Mode
                IsSuspicious = $isSuspicious
                SuspiciousReasons = ($suspiciousReasons -join "; ")
                HasConditions = $hasConditions
                Actions = ($actions -join "; ")
                ActionCount = $actions.Count
                BlindCopyTo = ($rule.BlindCopyTo -join ", ")
                CopyTo = ($rule.CopyTo -join ", ")
                RedirectMessageTo = ($rule.RedirectMessageTo -join ", ")
                DeleteMessage = $rule.DeleteMessage
                Comments = $rule.Comments
                WhenChanged = $rule.WhenChanged
                RiskLevel = $riskLevel
            }
            
            # Apply filters
            if ($OnlyHighRisk -and $riskLevel -ne "HIGH" -and $riskLevel -ne "CRITICAL") {
                continue
            }
            
            $script:TransportRuleFindings += $ruleInfo
        }
        
        Write-Host "[+] Transport rule analysis complete" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing transport rules: $_" -ForegroundColor Yellow
        Write-Host "[!] You may not have permission to view transport rules" -ForegroundColor Yellow
    }
}

# Get OWA policies
function Get-OWAPoliciesAnalysis {
    Write-Host "`n[*] Analyzing OWA (Outlook Web App) policies..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $owaPolicies = Get-OwaMailboxPolicy -ErrorAction Stop
        
        Write-Host "[+] Found $($owaPolicies.Count) OWA policy(ies)" -ForegroundColor Green
        
        foreach ($policy in $owaPolicies) {
            $riskLevel = "LOW"
            $securityIssues = @()
            
            # Check for insecure settings
            if ($policy.DirectFileAccessOnPublicComputersEnabled -eq $true) {
                $securityIssues += "Direct file access on public computers enabled"
                $riskLevel = "MEDIUM"
            }
            
            if ($policy.DirectFileAccessOnPrivateComputersEnabled -eq $true) {
                $securityIssues += "Direct file access on private computers enabled"
                if ($riskLevel -eq "LOW") {
                    $riskLevel = "LOW"  # This is more acceptable
                }
            }
            
            if ($policy.WacViewingOnPublicComputersEnabled -eq $true -and $policy.WacEditingEnabled -eq $true) {
                $securityIssues += "Office Online editing on public computers enabled"
                if ($riskLevel -eq "LOW") {
                    $riskLevel = "MEDIUM"
                }
            }
            
            # Check if external images are allowed
            if ($policy.DisplayPhotosEnabled -eq $true -and $policy.SetPhotoEnabled -eq $true) {
                $securityIssues += "Photo upload/display enabled"
            }
            
            # Check for LinkedIn/Facebook integration
            if ($policy.LinkedInEnabled -eq $true) {
                $securityIssues += "LinkedIn integration enabled"
            }
            
            if ($policy.FacebookEnabled -eq $true) {
                $securityIssues += "Facebook integration enabled"
            }
            
            $policyInfo = [PSCustomObject]@{
                PolicyName = $policy.Name
                PolicyIdentity = $policy.Identity
                IsDefault = $policy.IsDefault
                DirectFileAccessPublic = $policy.DirectFileAccessOnPublicComputersEnabled
                DirectFileAccessPrivate = $policy.DirectFileAccessOnPrivateComputersEnabled
                WacViewingPublic = $policy.WacViewingOnPublicComputersEnabled
                WacViewingPrivate = $policy.WacViewingOnPrivateComputersEnabled
                WacEditingEnabled = $policy.WacEditingEnabled
                ForceWacViewingFirstOnPublic = $policy.ForceWacViewingFirstOnPublicComputers
                ForceWacViewingFirstOnPrivate = $policy.ForceWacViewingFirstOnPrivateComputers
                LinkedInEnabled = $policy.LinkedInEnabled
                FacebookEnabled = $policy.FacebookEnabled
                ExternalImageProxyEnabled = $policy.ExternalImageProxyEnabled
                SecurityIssues = ($securityIssues -join "; ")
                SecurityIssueCount = $securityIssues.Count
                RiskLevel = $riskLevel
            }
            
            $script:OWAPolicyFindings += $policyInfo
        }
        
        Write-Host "[+] OWA policy analysis complete" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing OWA policies: $_" -ForegroundColor Yellow
    }
}

# Get client access rules (deprecated but may still exist)
function Get-ClientAccessRulesAnalysis {
    Write-Host "`n[*] Analyzing client access rules..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Note: Client Access Rules are being deprecated in favor of Conditional Access
        $clientAccessRules = Get-ClientAccessRule -ErrorAction SilentlyContinue
        
        if (-not $clientAccessRules -or $clientAccessRules.Count -eq 0) {
            Write-Host "[*] No client access rules found (may be using Conditional Access instead)" -ForegroundColor Yellow
            return
        }
        
        Write-Host "[+] Found $($clientAccessRules.Count) client access rule(s)" -ForegroundColor Green
        
        foreach ($rule in $clientAccessRules) {
            $riskLevel = "LOW"
            $concerns = @()
            
            # Check if rule allows broad access
            if ($rule.Action -eq "AllowAccess" -and -not $rule.AnyOfClientIPAddressesOrRanges) {
                $concerns += "Allows access without IP restrictions"
                $riskLevel = "MEDIUM"
            }
            
            # Check if rule blocks important protocols
            if ($rule.Action -eq "DenyAccess" -and $rule.AnyOfProtocols -contains "OutlookWebApp") {
                $concerns += "Blocks OWA access"
            }
            
            $ruleInfo = [PSCustomObject]@{
                RuleName = $rule.Name
                RuleIdentity = $rule.Identity
                RulePriority = $rule.Priority
                RuleEnabled = $rule.Enabled
                Action = $rule.Action
                Protocols = ($rule.AnyOfProtocols -join ", ")
                AuthenticationTypes = ($rule.AnyOfAuthenticationTypes -join ", ")
                IPRanges = ($rule.AnyOfClientIPAddressesOrRanges -join ", ")
                ExceptIPRanges = ($rule.ExceptAnyOfClientIPAddressesOrRanges -join ", ")
                Scope = $rule.Scope
                Concerns = ($concerns -join "; ")
                RiskLevel = $riskLevel
            }
            
            $script:ClientAccessFindings += $ruleInfo
        }
        
        Write-Host "[+] Client access rule analysis complete" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Error analyzing client access rules: $_" -ForegroundColor Yellow
        Write-Host "[!] Client Access Rules may not be available in your tenant" -ForegroundColor Yellow
    }
}

# Main scanning function
function Start-ExchangeSecurityScan {
    Write-Host "`n[*] Starting Exchange Online security scan..." -ForegroundColor Cyan
    
    try {
        # Get all mailboxes
        Write-Host "[*] Retrieving mailboxes..." -ForegroundColor Cyan
        Invoke-StealthDelay
        
        $mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
        
        Write-Host "[+] Found $($mailboxes.Count) mailbox(es)" -ForegroundColor Green
        
        $script:TotalMailboxesScanned = $mailboxes.Count
        $progressCounter = 0
        
        foreach ($mailbox in $mailboxes) {
            $progressCounter++
            
            # Progress indicator
            if ($progressCounter % 10 -eq 0 -or $progressCounter -eq $mailboxes.Count) {
                $percentComplete = [math]::Round(($progressCounter / $mailboxes.Count) * 100, 1)
                Write-Host "`r[*] Progress: $progressCounter/$($mailboxes.Count) ($percentComplete%)" -NoNewline -ForegroundColor Cyan
            }
            
            try {
                Invoke-StealthDelay
                
                # Get forwarding configuration
                $forwardingInfo = Get-MailboxForwardingAnalysis -Mailbox $mailbox
                
                # Filter: Only external forwarding
                if ($OnlyExternalForwarding -and -not $forwardingInfo.IsExternalForwarding) {
                    # Still need to check inbox rules for external forwarding
                    $inboxRules = Get-MailboxInboxRulesAnalysis -MailboxIdentity $mailbox.Identity -UserPrincipalName $mailbox.UserPrincipalName
                    $hasExternalRuleForwarding = ($inboxRules | Where-Object { $_.HasExternalForwarding }).Count -gt 0
                    
                    if (-not $hasExternalRuleForwarding) {
                        continue
                    }
                }
                
                # Get audit logging status
                $auditEnabled = $mailbox.AuditEnabled
                $auditLogAgeLimit = $mailbox.AuditLogAgeLimit
                
                # Filter: Only no audit
                if ($OnlyNoAudit -and $auditEnabled) {
                    continue
                }
                
                # Determine overall risk level
                $riskLevel = "LOW"
                $riskReasons = @()
                
                if ($forwardingInfo.IsExternalForwarding) {
                    $riskLevel = "CRITICAL"
                    $riskReasons += "External SMTP forwarding configured"
                }
                elseif ($forwardingInfo.HasForwarding) {
                    $riskLevel = "MEDIUM"
                    $riskReasons += "Internal forwarding configured"
                }
                
                if (-not $auditEnabled) {
                    if ($riskLevel -eq "LOW") {
                        $riskLevel = "MEDIUM"
                    }
                    $riskReasons += "Audit logging disabled"
                }
                
                # Get inbox rules
                $inboxRules = Get-MailboxInboxRulesAnalysis -MailboxIdentity $mailbox.Identity -UserPrincipalName $mailbox.UserPrincipalName
                
                $criticalRules = ($inboxRules | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
                $highRules = ($inboxRules | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
                $suspiciousRules = ($inboxRules | Where-Object { $_.IsSuspicious }).Count
                $externalForwardingRules = ($inboxRules | Where-Object { $_.HasExternalForwarding }).Count
                
                if ($criticalRules -gt 0) {
                    $riskLevel = "CRITICAL"
                    $riskReasons += "$criticalRules critical inbox rule(s)"
                }
                elseif ($highRules -gt 0) {
                    if ($riskLevel -ne "CRITICAL") {
                        $riskLevel = "HIGH"
                    }
                    $riskReasons += "$highRules high-risk inbox rule(s)"
                }
                
                if ($externalForwardingRules -gt 0) {
                    if ($riskLevel -ne "CRITICAL") {
                        $riskLevel = "CRITICAL"
                    }
                    $riskReasons += "$externalForwardingRules rule(s) forward externally"
                }
                
                # Get delegation info
                $delegations = Get-MailboxDelegationAnalysis -MailboxIdentity $mailbox.Identity -UserPrincipalName $mailbox.UserPrincipalName
                $externalDelegations = ($delegations | Where-Object { $_.IsExternal }).Count
                $highRiskDelegations = ($delegations | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
                
                if ($externalDelegations -gt 0) {
                    if ($riskLevel -eq "LOW") {
                        $riskLevel = "HIGH"
                    }
                    $riskReasons += "$externalDelegations external delegation(s)"
                }
                
                # Filter: Only high risk
                if ($OnlyHighRisk -and $riskLevel -ne "HIGH" -and $riskLevel -ne "CRITICAL") {
                    continue
                }
                
                $mailboxInfo = [PSCustomObject]@{
                    DisplayName = $mailbox.DisplayName
                    UserPrincipalName = $mailbox.UserPrincipalName
                    PrimarySmtpAddress = $mailbox.PrimarySmtpAddress
                    MailboxType = $mailbox.RecipientTypeDetails
                    
                    # Forwarding
                    HasForwarding = $forwardingInfo.HasForwarding
                    ForwardingAddress = $forwardingInfo.ForwardingAddress
                    ForwardingSmtpAddress = $forwardingInfo.ForwardingSmtpAddress
                    IsExternalForwarding = $forwardingInfo.IsExternalForwarding
                    DeliverToMailboxAndForward = $forwardingInfo.DeliverToMailboxAndForward
                    ForwardingRiskLevel = $forwardingInfo.ForwardingRiskLevel
                    
                    # Audit
                    AuditEnabled = $auditEnabled
                    AuditLogAgeLimit = $auditLogAgeLimit
                    
                    # Inbox Rules Summary
                    TotalInboxRules = $inboxRules.Count
                    SuspiciousRules = $suspiciousRules
                    ExternalForwardingRules = $externalForwardingRules
                    CriticalRules = $criticalRules
                    HighRiskRules = $highRules
                    
                    # Delegations Summary
                    TotalDelegations = $delegations.Count
                    ExternalDelegations = $externalDelegations
                    HighRiskDelegations = $highRiskDelegations
                    
                    # Overall Risk
                    RiskLevel = $riskLevel
                    RiskReasons = ($riskReasons -join "; ")
                    RiskReasonCount = $riskReasons.Count
                }
                
                $script:MailboxFindings += $mailboxInfo
                $script:InboxRuleFindings += $inboxRules
                $script:DelegationFindings += $delegations
            }
            catch {
                Write-Host "`n[!] Error processing mailbox $($mailbox.UserPrincipalName): $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n[+] Mailbox scan complete!" -ForegroundColor Green
        
        # Additional analyses if requested
        if ($IncludeTransportRules) {
            Get-TransportRulesAnalysis
        }
        
        if ($IncludeOWAPolicies) {
            Get-OWAPoliciesAnalysis
        }
        
        if ($IncludeClientAccess) {
            Get-ClientAccessRulesAnalysis
        }
    }
    catch {
        Write-Host "`n[ERROR] Failed to scan mailboxes: $_" -ForegroundColor Red
    }
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 160) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - EXCHANGE ONLINE SECURITY AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 160) -ForegroundColor Cyan
    
    # === MAILBOX SUMMARY ===
    if ($script:MailboxFindings.Count -gt 0) {
        Write-Host "`n[MAILBOX SUMMARY]" -ForegroundColor Yellow
        Write-Host ("-" * 160) -ForegroundColor Cyan
        
        # Sort by risk level
        $sortedMailboxes = $script:MailboxFindings | Sort-Object { 
            switch ($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }
        
        $matrixData = $sortedMailboxes | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='Type';Expression={$_.MailboxType}},
            @{Name='User';Expression={if($_.UserPrincipalName.Length -gt 35){$_.UserPrincipalName.Substring(0,32)+"..."}else{$_.UserPrincipalName}}},
            @{Name='ExtFwd';Expression={if($_.IsExternalForwarding){'YES'}else{'-'}}},
            @{Name='Rules';Expression={$_.TotalInboxRules}},
            @{Name='Suspicious';Expression={$_.SuspiciousRules}},
            @{Name='ExtFwdRules';Expression={$_.ExternalForwardingRules}},
            @{Name='Delegates';Expression={$_.TotalDelegations}},
            @{Name='Audit';Expression={if($_.AuditEnabled){'ON'}else{'OFF'}}}
        
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
    else {
        Write-Host "`n[MAILBOX SUMMARY]" -ForegroundColor Yellow
        Write-Host "[+] No mailbox findings matching criteria" -ForegroundColor Green
    }
    
    # === SUSPICIOUS INBOX RULES ===
    $suspiciousRules = $script:InboxRuleFindings | Where-Object { $_.IsSuspicious -or $_.HasExternalForwarding }
    if ($suspiciousRules.Count -gt 0) {
        Write-Host "`n[SUSPICIOUS INBOX RULES]" -ForegroundColor Yellow
        Write-Host ("-" * 160) -ForegroundColor Cyan
        
        $ruleMatrix = $suspiciousRules | Sort-Object { 
            switch ($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        } | Select-Object -First 30 | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='Mailbox';Expression={if($_.UserPrincipalName.Length -gt 25){$_.UserPrincipalName.Substring(0,22)+"..."}else{$_.UserPrincipalName}}},
            @{Name='Rule Name';Expression={if($_.RuleName.Length -gt 25){$_.RuleName.Substring(0,22)+"..."}else{$_.RuleName}}},
            @{Name='ExtFwd';Expression={if($_.HasExternalForwarding){'YES'}else{'-'}}},
            @{Name='External Targets';Expression={if($_.ExternalTargets.Length -gt 35){$_.ExternalTargets.Substring(0,32)+"..."}else{$_.ExternalTargets}}},
            @{Name='Actions';Expression={$_.Actions}},
            @{Name='Enabled';Expression={if($_.RuleEnabled){'Yes'}else{'No'}}}
        
        $ruleMatrix | Format-Table -AutoSize -Wrap | Out-String | ForEach-Object {
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
        
        if ($suspiciousRules.Count -gt 30) {
            Write-Host "  ... and $($suspiciousRules.Count - 30) more suspicious rule(s)" -ForegroundColor DarkGray
        }
    }
    
    # === TRANSPORT RULES ===
    if ($script:TransportRuleFindings.Count -gt 0) {
        Write-Host "`n[TRANSPORT RULES (MAIL FLOW RULES)]" -ForegroundColor Yellow
        Write-Host ("-" * 160) -ForegroundColor Cyan
        
        $transportMatrix = $script:TransportRuleFindings | Sort-Object { 
            switch ($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        } | Select-Object `
            @{Name='Risk';Expression={$_.RiskLevel}},
            @{Name='Rule Name';Expression={if($_.RuleName.Length -gt 30){$_.RuleName.Substring(0,27)+"..."}else{$_.RuleName}}},
            @{Name='State';Expression={$_.RuleState}},
            @{Name='Priority';Expression={$_.RulePriority}},
            @{Name='Suspicious';Expression={if($_.IsSuspicious){'YES'}else{'-'}}},
            @{Name='Actions';Expression={if($_.Actions.Length -gt 50){$_.Actions.Substring(0,47)+"..."}else{$_.Actions}}}
        
        $transportMatrix | Format-Table -AutoSize -Wrap | Out-String | ForEach-Object {
            $lines = $_ -split "`n"
            foreach ($line in $lines) {
                if ($line -match '^\s*CRITICAL\s+') {
                    Write-Host $line -ForegroundColor Red
                }
                elseif ($line -match '^\s*HIGH\s+') {
                    Write-Host $line -ForegroundColor Yellow
                }
                else {
                    Write-Host $line -ForegroundColor White
                }
            }
        }
    }
    
    Write-Host "`n" + ("=" * 160) -ForegroundColor Cyan
    
    # === SUMMARY SECTION ===
    Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
    
    Write-Host "Total mailboxes scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalMailboxesScanned -ForegroundColor Yellow
    
    Write-Host "Mailboxes with findings: " -NoNewline -ForegroundColor White
    Write-Host $script:MailboxFindings.Count -ForegroundColor $(if($script:MailboxFindings.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:MailboxFindings.Count -gt 0) {
        $criticalMailboxes = ($script:MailboxFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highMailboxes = ($script:MailboxFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumMailboxes = ($script:MailboxFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalMailboxes -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highMailboxes -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumMailboxes -ForegroundColor Cyan
    }
    
    # External forwarding summary
    $externalForwarding = ($script:MailboxFindings | Where-Object { $_.IsExternalForwarding }).Count
    $externalRuleForwarding = ($script:MailboxFindings | Where-Object { $_.ExternalForwardingRules -gt 0 }).Count
    
    Write-Host "`n[FORWARDING ANALYSIS]" -ForegroundColor Cyan
    Write-Host "  Mailboxes with external SMTP forwarding: " -NoNewline -ForegroundColor White
    Write-Host $externalForwarding -ForegroundColor $(if($externalForwarding -gt 0){"Red"}else{"Green"})
    Write-Host "  Mailboxes with external forwarding rules: " -NoNewline -ForegroundColor White
    Write-Host $externalRuleForwarding -ForegroundColor $(if($externalRuleForwarding -gt 0){"Red"}else{"Green"})
    
    # Audit logging summary
    $noAudit = ($script:MailboxFindings | Where-Object { -not $_.AuditEnabled }).Count
    
    Write-Host "`n[AUDIT LOGGING]" -ForegroundColor Cyan
    Write-Host "  Mailboxes without audit logging: " -NoNewline -ForegroundColor White
    Write-Host $noAudit -ForegroundColor $(if($noAudit -gt 0){"Yellow"}else{"Green"})
    
    # Inbox rules summary
    $totalRules = $script:InboxRuleFindings.Count
    $suspiciousRuleCount = ($script:InboxRuleFindings | Where-Object { $_.IsSuspicious }).Count
    $externalFwdRuleCount = ($script:InboxRuleFindings | Where-Object { $_.HasExternalForwarding }).Count
    
    Write-Host "`n[INBOX RULES]" -ForegroundColor Cyan
    Write-Host "  Total inbox rules scanned: " -NoNewline -ForegroundColor White
    Write-Host $totalRules -ForegroundColor Yellow
    Write-Host "  Suspicious rules: " -NoNewline -ForegroundColor White
    Write-Host $suspiciousRuleCount -ForegroundColor $(if($suspiciousRuleCount -gt 0){"Yellow"}else{"Green"})
    Write-Host "  Rules forwarding externally: " -NoNewline -ForegroundColor White
    Write-Host $externalFwdRuleCount -ForegroundColor $(if($externalFwdRuleCount -gt 0){"Red"}else{"Green"})
    
    # Delegation summary
    $totalDelegations = $script:DelegationFindings.Count
    $externalDelegations = ($script:DelegationFindings | Where-Object { $_.IsExternal }).Count
    
    Write-Host "`n[DELEGATIONS]" -ForegroundColor Cyan
    Write-Host "  Total delegations: " -NoNewline -ForegroundColor White
    Write-Host $totalDelegations -ForegroundColor Yellow
    Write-Host "  External delegations: " -NoNewline -ForegroundColor White
    Write-Host $externalDelegations -ForegroundColor $(if($externalDelegations -gt 0){"Yellow"}else{"Green"})
    
    # Transport rules summary
    if ($script:TransportRuleFindings.Count -gt 0) {
        $suspiciousTransport = ($script:TransportRuleFindings | Where-Object { $_.IsSuspicious }).Count
        
        Write-Host "`n[TRANSPORT RULES]" -ForegroundColor Cyan
        Write-Host "  Total transport rules: " -NoNewline -ForegroundColor White
        Write-Host $script:TransportRuleFindings.Count -ForegroundColor Yellow
        Write-Host "  Suspicious transport rules: " -NoNewline -ForegroundColor White
        Write-Host $suspiciousTransport -ForegroundColor $(if($suspiciousTransport -gt 0){"Yellow"}else{"Green"})
    }
    
    Write-Host ""
}

# Display standard results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal mailboxes scanned: " -NoNewline -ForegroundColor White
    Write-Host $script:TotalMailboxesScanned -ForegroundColor Yellow
    
    Write-Host "Mailboxes with findings: " -NoNewline -ForegroundColor White
    Write-Host $script:MailboxFindings.Count -ForegroundColor $(if($script:MailboxFindings.Count -gt 0){"Yellow"}else{"Green"})
    
    if ($script:MailboxFindings.Count -gt 0) {
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "MAILBOX DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        # Sort by risk level
        $sortedMailboxes = $script:MailboxFindings | Sort-Object { 
            switch ($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }
        
        foreach ($mailbox in $sortedMailboxes) {
            $riskColor = switch ($mailbox.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($mailbox.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host $mailbox.UserPrincipalName -ForegroundColor White
            
            Write-Host "  Display Name: $($mailbox.DisplayName)" -ForegroundColor Gray
            Write-Host "  Mailbox Type: $($mailbox.MailboxType)" -ForegroundColor Gray
            
            # Forwarding
            if ($mailbox.HasForwarding) {
                if ($mailbox.IsExternalForwarding) {
                    Write-Host "  [!] EXTERNAL Forwarding: " -NoNewline -ForegroundColor Red
                    Write-Host $mailbox.ForwardingSmtpAddress -ForegroundColor Red
                }
                else {
                    Write-Host "  Forwarding: " -NoNewline -ForegroundColor Yellow
                    Write-Host "$($mailbox.ForwardingAddress)" -ForegroundColor Yellow
                }
                Write-Host "  Deliver to Mailbox AND Forward: $($mailbox.DeliverToMailboxAndForward)" -ForegroundColor Gray
            }
            
            # Audit
            Write-Host "  Audit Logging: " -NoNewline -ForegroundColor Gray
            if ($mailbox.AuditEnabled) {
                Write-Host "Enabled" -ForegroundColor Green
            }
            else {
                Write-Host "DISABLED" -ForegroundColor Yellow
            }
            
            # Inbox Rules
            if ($mailbox.TotalInboxRules -gt 0) {
                Write-Host "  Inbox Rules: $($mailbox.TotalInboxRules) (Suspicious: $($mailbox.SuspiciousRules), External Forwarding: $($mailbox.ExternalForwardingRules))" -ForegroundColor Gray
            }
            
            # Delegations
            if ($mailbox.TotalDelegations -gt 0) {
                Write-Host "  Delegations: $($mailbox.TotalDelegations) (External: $($mailbox.ExternalDelegations))" -ForegroundColor Gray
            }
            
            # Risk Reasons
            if ($mailbox.RiskReasons) {
                Write-Host "  Risk Reasons: $($mailbox.RiskReasons)" -ForegroundColor DarkGray
            }
        }
    }
    
    # Show suspicious inbox rules
    $suspiciousRules = $script:InboxRuleFindings | Where-Object { $_.IsSuspicious -or $_.HasExternalForwarding }
    if ($suspiciousRules.Count -gt 0) {
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "SUSPICIOUS INBOX RULES:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        foreach ($rule in ($suspiciousRules | Select-Object -First 20)) {
            $riskColor = switch ($rule.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                default { "White" }
            }
            
            Write-Host "`n[$($rule.RiskLevel)] " -NoNewline -ForegroundColor $riskColor
            Write-Host "$($rule.RuleName)" -ForegroundColor White
            Write-Host "  Mailbox: $($rule.UserPrincipalName)" -ForegroundColor Gray
            Write-Host "  Actions: $($rule.Actions)" -ForegroundColor Gray
            
            if ($rule.HasExternalForwarding) {
                Write-Host "  [!] External Targets: $($rule.ExternalTargets)" -ForegroundColor Red
            }
            
            if ($rule.SuspiciousReasons) {
                Write-Host "  Reasons: $($rule.SuspiciousReasons)" -ForegroundColor DarkGray
            }
        }
        
        if ($suspiciousRules.Count -gt 20) {
            Write-Host "`n  ... and $($suspiciousRules.Count - 20) more suspicious rule(s)" -ForegroundColor DarkGray
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
    
    $totalFindings = $script:MailboxFindings.Count + $script:InboxRuleFindings.Count + $script:TransportRuleFindings.Count
    
    if ($totalFindings -eq 0) {
        Write-Host "`n[*] No results to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        $basePath = [System.IO.Path]::GetDirectoryName($Path)
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        
        # Export mailbox findings
        if ($script:MailboxFindings.Count -gt 0) {
            $mailboxPath = if ($basePath) { Join-Path $basePath "$baseName-mailboxes$extension" } else { "$baseName-mailboxes$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:MailboxFindings | Export-Csv -Path $mailboxPath -NoTypeInformation -Encoding UTF8
                    Write-Host "`n[+] Mailbox findings exported to CSV: $mailboxPath" -ForegroundColor Green
                }
                ".json" {
                    $script:MailboxFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $mailboxPath -Encoding UTF8
                    Write-Host "`n[+] Mailbox findings exported to JSON: $mailboxPath" -ForegroundColor Green
                }
                default {
                    $csvPath = [System.IO.Path]::ChangeExtension($mailboxPath, ".csv")
                    $script:MailboxFindings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                    Write-Host "`n[+] Mailbox findings exported to CSV: $csvPath" -ForegroundColor Green
                }
            }
        }
        
        # Export inbox rule findings
        if ($script:InboxRuleFindings.Count -gt 0) {
            $rulesPath = if ($basePath) { Join-Path $basePath "$baseName-inboxrules$extension" } else { "$baseName-inboxrules$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:InboxRuleFindings | Export-Csv -Path $rulesPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Inbox rules exported to CSV: $rulesPath" -ForegroundColor Green
                }
                ".json" {
                    $script:InboxRuleFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $rulesPath -Encoding UTF8
                    Write-Host "[+] Inbox rules exported to JSON: $rulesPath" -ForegroundColor Green
                }
                default {
                    $csvPath = [System.IO.Path]::ChangeExtension($rulesPath, ".csv")
                    $script:InboxRuleFindings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Inbox rules exported to CSV: $csvPath" -ForegroundColor Green
                }
            }
        }
        
        # Export transport rule findings
        if ($script:TransportRuleFindings.Count -gt 0) {
            $transportPath = if ($basePath) { Join-Path $basePath "$baseName-transportrules$extension" } else { "$baseName-transportrules$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:TransportRuleFindings | Export-Csv -Path $transportPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Transport rules exported to CSV: $transportPath" -ForegroundColor Green
                }
                ".json" {
                    $script:TransportRuleFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $transportPath -Encoding UTF8
                    Write-Host "[+] Transport rules exported to JSON: $transportPath" -ForegroundColor Green
                }
            }
        }
        
        # Export delegation findings
        if ($script:DelegationFindings.Count -gt 0) {
            $delegationPath = if ($basePath) { Join-Path $basePath "$baseName-delegations$extension" } else { "$baseName-delegations$extension" }
            
            switch ($extension) {
                ".csv" {
                    $script:DelegationFindings | Export-Csv -Path $delegationPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Delegations exported to CSV: $delegationPath" -ForegroundColor Green
                }
                ".json" {
                    $script:DelegationFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $delegationPath -Encoding UTF8
                    Write-Host "[+] Delegations exported to JSON: $delegationPath" -ForegroundColor Green
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
        # Disconnect from Exchange Online
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] Disconnected from Exchange Online" -ForegroundColor Green
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
        if (-not (Test-ExchangeModule)) {
            exit 1
        }
        
        # Initialize and import modules
        if (-not (Initialize-ExchangeModule)) {
            Write-Host "`n[ERROR] Failed to initialize modules. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Connect to Exchange Online
        if (-not (Connect-ExchangeService)) {
            Write-Host "`n[ERROR] Connection failed. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Start scan
        Start-ExchangeSecurityScan
        
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
        
        Write-Host "`n[*] Exchange security check completed successfully!" -ForegroundColor Green
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
