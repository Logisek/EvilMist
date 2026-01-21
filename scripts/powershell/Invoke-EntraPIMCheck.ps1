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
    Comprehensive Privileged Identity Management (PIM) configuration audit for Azure Entra ID.

.DESCRIPTION
    This script performs a deep analysis of Azure AD Privileged Identity Management (PIM) 
    configuration to identify security gaps and misconfigurations. PIM is critical for 
    implementing Just-In-Time (JIT) privileged access and reducing standing admin exposure.
    
    Key features:
    - JIT access configuration gaps (max activation duration, approval requirements)
    - Eligible role assignments without proper activation requirements
    - PIM alerts and notifications configuration audit
    - Approval workflow gaps (no approvers configured)
    - Eligible vs active role timing analysis
    - PIM for Groups analysis
    - Access reviews configuration audit
    - Break-glass account PIM exemptions detection
    - Permanent vs eligible assignment analysis
    
    The script uses the current user's credentials and domain setup to 
    authenticate with Azure Entra ID via Microsoft Graph PowerShell SDK.

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

.PARAMETER OnlyCritical
    Show only roles with CRITICAL risk findings.

.PARAMETER OnlyHighPrivilege
    Show only high-privilege roles (Global Admin, Privileged Role Admin, etc.).

.PARAMETER OnlyMisconfigurations
    Show only roles with configuration gaps or misconfigurations.

.PARAMETER IncludeGroups
    Include PIM for Groups analysis.

.PARAMETER IncludeAccessReviews
    Include Access Reviews configuration analysis.

.PARAMETER MaxActivationHours
    Maximum recommended activation duration in hours (1-24). Default: 8
    Roles with longer activation windows are flagged.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraPIMCheck.ps1
    # Perform comprehensive PIM configuration audit

.EXAMPLE
    .\Invoke-EntraPIMCheck.ps1 -ExportPath "pim-audit.csv"
    # Export results to CSV file

.EXAMPLE
    .\Invoke-EntraPIMCheck.ps1 -OnlyCritical -Matrix
    # Display only critical findings in matrix format

.EXAMPLE
    .\Invoke-EntraPIMCheck.ps1 -OnlyHighPrivilege -MaxActivationHours 2
    # Audit high-privilege roles with strict 2-hour activation limit

.EXAMPLE
    .\Invoke-EntraPIMCheck.ps1 -IncludeGroups -IncludeAccessReviews
    # Include PIM for Groups and Access Reviews in the audit

.EXAMPLE
    .\Invoke-EntraPIMCheck.ps1 -EnableStealth -QuietStealth
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
    [switch]$OnlyCritical,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyHighPrivilege,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyMisconfigurations,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeGroups,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeAccessReviews,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 24)]
    [int]$MaxActivationHours = 8,

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

# High-privilege roles that require strict PIM configuration
$script:HighPrivilegeRoles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Hybrid Identity Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Identity Governance Administrator",
    "Intune Administrator",
    "Azure DevOps Administrator",
    "Compliance Administrator"
)

# Critical roles that should have strictest controls
$script:CriticalRoles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator"
)

# Recommended PIM settings
$script:RecommendedSettings = @{
    MaxActivationDurationHours = 8    # Maximum activation window (recommended: 1-8 hours)
    RequireApproval = $true           # Approval should be required for critical roles
    RequireJustification = $true      # Always require justification for activation
    RequireMFA = $true                # MFA should be required for activation
    RequireTicketInfo = $false        # Ticket info requirement (optional but recommended)
    NotifyOnActivation = $true        # Admins should be notified on activation
    NotifyOnAssignment = $true        # Admins should be notified on new assignments
}

# Required scopes for PIM checking
$script:RequiredScopes = @(
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
    "RoleManagement.Read.All",
    "PrivilegedAccess.Read.AzureAD",
    "User.Read.All",
    "Group.Read.All",
    "AccessReview.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
    "RoleManagement.Read.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:PIMFindings = @()
$script:RoleSettings = @{}
$script:EligibleAssignments = @()
$script:ActiveAssignments = @()
$script:GroupPIMFindings = @()
$script:AccessReviewFindings = @()
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
    Write-Host "    Entra ID PIM Check - Privileged Identity Management Audit" -ForegroundColor Yellow
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
        "Microsoft.Graph.Identity.Governance",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Groups",
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
        
        Write-Host "[*] Importing Microsoft.Graph.Identity.Governance..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Identity.Governance -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Microsoft.Graph.Users..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Users -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Microsoft.Graph.Groups..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Groups -Force -ErrorAction Stop
        
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

# Get all role definitions
function Get-RoleDefinitions {
    Write-Host "`n[*] Retrieving role definitions..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
        $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        $roles = @{}
        foreach ($role in $result.value) {
            $roles[$role.id] = @{
                Id = $role.id
                DisplayName = $role.displayName
                Description = $role.description
                IsBuiltIn = $role.isBuiltIn
                IsEnabled = $role.isEnabled
                TemplateId = $role.templateId
            }
        }
        
        Write-Host "[+] Found $($roles.Count) role definition(s)" -ForegroundColor Green
        return $roles
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve role definitions: $_" -ForegroundColor Red
        return @{}
    }
}

# Get PIM role settings for a specific role
function Get-PIMRoleSettings {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RoleDefinitionId
    )
    
    try {
        Invoke-StealthDelay
        
        # Use the unified role management policy assignments API
        $uri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleDefinitionId'"
        $policyAssignment = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        
        if ($policyAssignment.value.Count -gt 0) {
            $policyId = $policyAssignment.value[0].policyId
            
            # Get the actual policy rules
            Invoke-StealthDelay
            $policyUri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$policyId/rules"
            $policyRules = Invoke-MgGraphRequest -Method GET -Uri $policyUri -ErrorAction Stop
            
            # Parse settings from rules
            $settings = @{
                PolicyId = $policyId
                MaxActivationDuration = "PT8H"  # Default
                MaxActivationDurationHours = 8
                RequireApproval = $false
                Approvers = @()
                RequireJustification = $false
                RequireMFA = $false
                RequireTicketInfo = $false
                NotifyOnEligibleAssignment = $false
                NotifyOnActiveAssignment = $false
                NotifyOnActivation = $false
                NotificationRecipients = @()
                EnablementRules = @()
            }
            
            foreach ($rule in $policyRules.value) {
                switch ($rule.'@odata.type') {
                    '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule' {
                        if ($rule.id -eq 'Expiration_EndUser_Assignment') {
                            $settings.MaxActivationDuration = $rule.maximumDuration
                            # Parse ISO 8601 duration
                            if ($rule.maximumDuration -match 'PT(\d+)H') {
                                $settings.MaxActivationDurationHours = [int]$matches[1]
                            }
                            elseif ($rule.maximumDuration -match 'PT(\d+)M') {
                                $settings.MaxActivationDurationHours = [math]::Ceiling([int]$matches[1] / 60)
                            }
                        }
                    }
                    '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule' {
                        if ($rule.setting.isApprovalRequired) {
                            $settings.RequireApproval = $true
                            if ($rule.setting.approvalStages) {
                                foreach ($stage in $rule.setting.approvalStages) {
                                    foreach ($approver in $stage.primaryApprovers) {
                                        $settings.Approvers += @{
                                            Type = $approver.'@odata.type'
                                            Id = $approver.id
                                            Description = $approver.description
                                        }
                                    }
                                }
                            }
                        }
                    }
                    '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule' {
                        $settings.EnablementRules = $rule.enabledRules
                        if ($rule.enabledRules -contains 'Justification') {
                            $settings.RequireJustification = $true
                        }
                        if ($rule.enabledRules -contains 'MultiFactorAuthentication') {
                            $settings.RequireMFA = $true
                        }
                        if ($rule.enabledRules -contains 'Ticketing') {
                            $settings.RequireTicketInfo = $true
                        }
                    }
                    '#microsoft.graph.unifiedRoleManagementPolicyNotificationRule' {
                        if ($rule.notificationType -eq 'Email') {
                            switch ($rule.id) {
                                'Notification_Admin_EndUser_Assignment' { $settings.NotifyOnActivation = $rule.isDefaultRecipientsEnabled }
                                'Notification_Admin_Admin_Eligibility' { $settings.NotifyOnEligibleAssignment = $rule.isDefaultRecipientsEnabled }
                                'Notification_Admin_Admin_Assignment' { $settings.NotifyOnActiveAssignment = $rule.isDefaultRecipientsEnabled }
                            }
                            if ($rule.notificationRecipients) {
                                $settings.NotificationRecipients += $rule.notificationRecipients
                            }
                        }
                    }
                }
            }
            
            return $settings
        }
        
        return $null
    }
    catch {
        Write-Host "[!] Failed to get PIM settings for role $RoleDefinitionId : $_" -ForegroundColor Yellow
        return $null
    }
}

# Get eligible role assignments
function Get-EligibleRoleAssignments {
    Write-Host "`n[*] Retrieving eligible role assignments..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$expand=principal"
        $allAssignments = @()
        
        do {
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $allAssignments += $result.value
            $uri = $result.'@odata.nextLink'
            
            if ($uri) {
                Invoke-StealthDelay
            }
        } while ($uri)
        
        Write-Host "[+] Found $($allAssignments.Count) eligible role assignment(s)" -ForegroundColor Green
        return $allAssignments
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve eligible assignments: $_" -ForegroundColor Red
        return @()
    }
}

# Get active role assignments (permanent + activated)
function Get-ActiveRoleAssignments {
    Write-Host "`n[*] Retrieving active role assignments..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?`$expand=principal"
        $allAssignments = @()
        
        do {
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $allAssignments += $result.value
            $uri = $result.'@odata.nextLink'
            
            if ($uri) {
                Invoke-StealthDelay
            }
        } while ($uri)
        
        Write-Host "[+] Found $($allAssignments.Count) active role assignment(s)" -ForegroundColor Green
        return $allAssignments
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve active assignments: $_" -ForegroundColor Red
        return @()
    }
}

# Get PIM alerts
function Get-PIMAlerts {
    Write-Host "`n[*] Retrieving PIM alerts..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/assignmentScheduleInstances"
        $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
        
        if ($result -and $result.value) {
            Write-Host "[+] Found $($result.value.Count) PIM alert(s)" -ForegroundColor Green
            return $result.value
        }
        
        return @()
    }
    catch {
        Write-Host "[!] PIM alerts retrieval requires additional permissions" -ForegroundColor Yellow
        return @()
    }
}

# Analyze PIM settings for a role and generate findings
function Analyze-RolePIMSettings {
    param(
        [Parameter(Mandatory = $true)]
        $RoleDefinition,
        
        [Parameter(Mandatory = $true)]
        $Settings,
        
        [Parameter(Mandatory = $true)]
        $EligibleCount,
        
        [Parameter(Mandatory = $true)]
        $ActiveCount,
        
        [Parameter(Mandatory = $false)]
        $EligibleAssignments = @(),
        
        [Parameter(Mandatory = $false)]
        $ActiveAssignments = @()
    )
    
    $roleName = $RoleDefinition.DisplayName
    $isHighPrivilege = $script:HighPrivilegeRoles -contains $roleName
    $isCritical = $script:CriticalRoles -contains $roleName
    
    # Collect findings
    $findings = @()
    $riskLevel = "LOW"
    
    # Check max activation duration
    if ($Settings.MaxActivationDurationHours -gt $MaxActivationHours) {
        $findings += "Max activation duration is $($Settings.MaxActivationDurationHours) hours (recommended: $MaxActivationHours hours or less)"
        if ($isCritical) {
            $riskLevel = "CRITICAL"
        }
        elseif ($isHighPrivilege) {
            $riskLevel = "HIGH"
        }
        else {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check approval requirement
    if (-not $Settings.RequireApproval) {
        $findings += "Approval is NOT required for activation"
        if ($isCritical) {
            $riskLevel = "CRITICAL"
        }
        elseif ($isHighPrivilege -and $riskLevel -ne "CRITICAL") {
            $riskLevel = "HIGH"
        }
    }
    elseif ($Settings.Approvers.Count -eq 0) {
        $findings += "Approval required but NO approvers configured"
        if ($isCritical) {
            $riskLevel = "CRITICAL"
        }
        elseif ($isHighPrivilege -and $riskLevel -ne "CRITICAL") {
            $riskLevel = "HIGH"
        }
    }
    
    # Check justification requirement
    if (-not $Settings.RequireJustification) {
        $findings += "Justification is NOT required for activation"
        if ($isCritical -and $riskLevel -ne "CRITICAL") {
            $riskLevel = "HIGH"
        }
        elseif ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check MFA requirement
    if (-not $Settings.RequireMFA) {
        $findings += "MFA is NOT required for activation"
        if ($isCritical) {
            $riskLevel = "CRITICAL"
        }
        elseif ($isHighPrivilege -and $riskLevel -ne "CRITICAL") {
            $riskLevel = "HIGH"
        }
        elseif ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check notifications
    if (-not $Settings.NotifyOnActivation) {
        $findings += "Admin notification on activation is DISABLED"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Check for permanent assignments (break-glass accounts may be exceptions)
    $permanentCount = ($ActiveAssignments | Where-Object { $_.assignmentType -eq 'Assigned' }).Count
    if ($permanentCount -gt 0) {
        $findings += "$permanentCount permanent (non-PIM) assignment(s) exist"
        if ($isCritical -and $permanentCount -gt 2) {
            if ($riskLevel -ne "CRITICAL") {
                $riskLevel = "HIGH"
            }
        }
        elseif ($isHighPrivilege -and $permanentCount -gt 2) {
            if ($riskLevel -eq "LOW") {
                $riskLevel = "MEDIUM"
            }
        }
    }
    
    # Check for too many eligible users
    if ($EligibleCount -gt 5 -and $isCritical) {
        $findings += "$EligibleCount users are eligible for this critical role (recommended: 2-5 for critical roles)"
        if ($riskLevel -eq "LOW") {
            $riskLevel = "MEDIUM"
        }
    }
    
    # Determine principal information
    $eligiblePrincipals = @()
    foreach ($assignment in $EligibleAssignments) {
        $principalInfo = @{
            Id = $assignment.principalId
            Type = if ($assignment.principal.'@odata.type') { $assignment.principal.'@odata.type'.Replace('#microsoft.graph.', '') } else { "Unknown" }
            DisplayName = if ($assignment.principal.displayName) { $assignment.principal.displayName } else { "Unknown" }
            StartDateTime = $assignment.startDateTime
            EndDateTime = $assignment.endDateTime
            MemberType = $assignment.memberType
        }
        $eligiblePrincipals += $principalInfo
    }
    
    $activePrincipals = @()
    foreach ($assignment in $ActiveAssignments) {
        $principalInfo = @{
            Id = $assignment.principalId
            Type = if ($assignment.principal.'@odata.type') { $assignment.principal.'@odata.type'.Replace('#microsoft.graph.', '') } else { "Unknown" }
            DisplayName = if ($assignment.principal.displayName) { $assignment.principal.displayName } else { "Unknown" }
            AssignmentType = $assignment.assignmentType
            StartDateTime = $assignment.startDateTime
            EndDateTime = $assignment.endDateTime
            MemberType = $assignment.memberType
        }
        $activePrincipals += $principalInfo
    }
    
    return [PSCustomObject]@{
        RoleId = $RoleDefinition.Id
        RoleName = $roleName
        RoleDescription = $RoleDefinition.Description
        IsBuiltIn = $RoleDefinition.IsBuiltIn
        IsHighPrivilege = $isHighPrivilege
        IsCritical = $isCritical
        MaxActivationDurationHours = $Settings.MaxActivationDurationHours
        MaxActivationDuration = $Settings.MaxActivationDuration
        RequireApproval = $Settings.RequireApproval
        ApproverCount = $Settings.Approvers.Count
        Approvers = ($Settings.Approvers | ForEach-Object { $_.Description }) -join ", "
        RequireJustification = $Settings.RequireJustification
        RequireMFA = $Settings.RequireMFA
        RequireTicketInfo = $Settings.RequireTicketInfo
        NotifyOnActivation = $Settings.NotifyOnActivation
        NotifyOnEligibleAssignment = $Settings.NotifyOnEligibleAssignment
        NotifyOnActiveAssignment = $Settings.NotifyOnActiveAssignment
        EligibleCount = $EligibleCount
        ActiveCount = $ActiveCount
        PermanentCount = $permanentCount
        EligiblePrincipals = $eligiblePrincipals
        ActivePrincipals = $activePrincipals
        Findings = $findings
        FindingCount = $findings.Count
        RiskLevel = $riskLevel
        HasMisconfigurations = ($findings.Count -gt 0)
    }
}

# Get PIM for Groups assignments
function Get-PIMGroupAssignments {
    Write-Host "`n[*] Retrieving PIM for Groups assignments..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Get groups enabled for PIM
        $uri = "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$expand=group,principal"
        $eligibleGroups = @()
        
        do {
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
            if ($result -and $result.value) {
                $eligibleGroups += $result.value
            }
            $uri = $result.'@odata.nextLink'
            
            if ($uri) {
                Invoke-StealthDelay
            }
        } while ($uri)
        
        Write-Host "[+] Found $($eligibleGroups.Count) PIM for Groups eligible assignment(s)" -ForegroundColor Green
        return $eligibleGroups
    }
    catch {
        Write-Host "[!] PIM for Groups requires Azure AD Premium P2 license" -ForegroundColor Yellow
        return @()
    }
}

# Get Access Reviews
function Get-AccessReviews {
    Write-Host "`n[*] Retrieving Access Reviews..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        $uri = "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions"
        $reviews = @()
        
        do {
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
            if ($result -and $result.value) {
                $reviews += $result.value
            }
            $uri = $result.'@odata.nextLink'
            
            if ($uri) {
                Invoke-StealthDelay
            }
        } while ($uri)
        
        Write-Host "[+] Found $($reviews.Count) access review definition(s)" -ForegroundColor Green
        return $reviews
    }
    catch {
        Write-Host "[!] Access Reviews require Azure AD Premium P2 license" -ForegroundColor Yellow
        return @()
    }
}

# Analyze Access Reviews for PIM roles
function Analyze-AccessReviews {
    param(
        [Parameter(Mandatory = $true)]
        $Reviews,
        
        [Parameter(Mandatory = $true)]
        $RoleDefinitions
    )
    
    $findings = @()
    
    # Get role IDs
    $roleIds = $RoleDefinitions.Keys
    
    # Check which critical roles have access reviews
    $rolesWithReviews = @{}
    
    foreach ($review in $Reviews) {
        if ($review.scope.'@odata.type' -eq '#microsoft.graph.accessReviewQueryScope') {
            # Check if this review covers directory roles
            if ($review.scope.query -like "*directoryRoles*" -or $review.scope.query -like "*roleManagement*") {
                # Extract role ID from query if possible
                if ($review.scope.query -match "roleDefinitionId eq '([^']+)'") {
                    $rolesWithReviews[$matches[1]] = $review
                }
                else {
                    # Generic role review
                    $rolesWithReviews["generic"] = $review
                }
            }
        }
    }
    
    # Check critical roles for access review coverage
    foreach ($roleId in $roleIds) {
        $role = $RoleDefinitions[$roleId]
        $roleName = $role.DisplayName
        
        if ($script:CriticalRoles -contains $roleName) {
            if (-not $rolesWithReviews.ContainsKey($roleId) -and -not $rolesWithReviews.ContainsKey("generic")) {
                $findings += [PSCustomObject]@{
                    Type = "MissingAccessReview"
                    RoleName = $roleName
                    RoleId = $roleId
                    Description = "Critical role '$roleName' does not have an Access Review configured"
                    RiskLevel = "HIGH"
                }
            }
        }
        elseif ($script:HighPrivilegeRoles -contains $roleName) {
            if (-not $rolesWithReviews.ContainsKey($roleId) -and -not $rolesWithReviews.ContainsKey("generic")) {
                $findings += [PSCustomObject]@{
                    Type = "MissingAccessReview"
                    RoleName = $roleName
                    RoleId = $roleId
                    Description = "High-privilege role '$roleName' does not have an Access Review configured"
                    RiskLevel = "MEDIUM"
                }
            }
        }
    }
    
    return $findings
}

# Main scanning function
function Start-PIMScan {
    Write-Host "`n[*] Starting PIM configuration audit..." -ForegroundColor Cyan
    Write-Host "[*] Recommended max activation duration: $MaxActivationHours hours" -ForegroundColor Cyan
    
    # Get role definitions
    $roleDefinitions = Get-RoleDefinitions
    
    if ($roleDefinitions.Count -eq 0) {
        Write-Host "[ERROR] No role definitions found. Cannot proceed." -ForegroundColor Red
        return
    }
    
    # Get assignments
    $eligibleAssignments = Get-EligibleRoleAssignments
    $activeAssignments = Get-ActiveRoleAssignments
    
    # Group assignments by role
    $eligibleByRole = @{}
    $activeByRole = @{}
    
    foreach ($assignment in $eligibleAssignments) {
        $roleId = $assignment.roleDefinitionId
        if (-not $eligibleByRole.ContainsKey($roleId)) {
            $eligibleByRole[$roleId] = @()
        }
        $eligibleByRole[$roleId] += $assignment
    }
    
    foreach ($assignment in $activeAssignments) {
        $roleId = $assignment.roleDefinitionId
        if (-not $activeByRole.ContainsKey($roleId)) {
            $activeByRole[$roleId] = @()
        }
        $activeByRole[$roleId] += $assignment
    }
    
    # Analyze each role with assignments
    $rolesWithAssignments = @()
    $rolesWithAssignments += $eligibleByRole.Keys
    $rolesWithAssignments += $activeByRole.Keys
    $rolesWithAssignments = $rolesWithAssignments | Select-Object -Unique
    
    $progressCounter = 0
    $totalRoles = $rolesWithAssignments.Count
    
    Write-Host "`n[*] Analyzing PIM settings for $totalRoles role(s) with assignments..." -ForegroundColor Cyan
    
    foreach ($roleId in $rolesWithAssignments) {
        $progressCounter++
        
        if (-not $roleDefinitions.ContainsKey($roleId)) {
            continue
        }
        
        $roleDef = $roleDefinitions[$roleId]
        $roleName = $roleDef.DisplayName
        
        # Apply filters
        if ($OnlyHighPrivilege -and -not ($script:HighPrivilegeRoles -contains $roleName)) {
            continue
        }
        
        # Progress indicator
        if ($progressCounter % 5 -eq 0 -or $progressCounter -eq $totalRoles) {
            $percentComplete = [math]::Round(($progressCounter / $totalRoles) * 100, 1)
            Write-Host "`r[*] Progress: $progressCounter/$totalRoles ($percentComplete%)" -NoNewline -ForegroundColor Cyan
        }
        
        # Get PIM settings for this role
        $settings = Get-PIMRoleSettings -RoleDefinitionId $roleId
        
        if ($settings) {
            $eligibleForRole = if ($eligibleByRole.ContainsKey($roleId)) { $eligibleByRole[$roleId] } else { @() }
            $activeForRole = if ($activeByRole.ContainsKey($roleId)) { $activeByRole[$roleId] } else { @() }
            
            $finding = Analyze-RolePIMSettings -RoleDefinition $roleDef -Settings $settings `
                -EligibleCount $eligibleForRole.Count -ActiveCount $activeForRole.Count `
                -EligibleAssignments $eligibleForRole -ActiveAssignments $activeForRole
            
            # Apply remaining filters
            if ($OnlyCritical -and $finding.RiskLevel -ne "CRITICAL") {
                continue
            }
            
            if ($OnlyMisconfigurations -and -not $finding.HasMisconfigurations) {
                continue
            }
            
            $script:PIMFindings += $finding
        }
    }
    
    Write-Host "`n[+] PIM role analysis complete!" -ForegroundColor Green
    
    # PIM for Groups (if requested)
    if ($IncludeGroups) {
        $groupAssignments = Get-PIMGroupAssignments
        
        foreach ($assignment in $groupAssignments) {
            $script:GroupPIMFindings += [PSCustomObject]@{
                GroupId = $assignment.groupId
                GroupName = if ($assignment.group) { $assignment.group.displayName } else { "Unknown" }
                PrincipalId = $assignment.principalId
                PrincipalName = if ($assignment.principal) { $assignment.principal.displayName } else { "Unknown" }
                PrincipalType = if ($assignment.principal.'@odata.type') { $assignment.principal.'@odata.type'.Replace('#microsoft.graph.', '') } else { "Unknown" }
                AccessType = $assignment.accessId
                StartDateTime = $assignment.startDateTime
                EndDateTime = $assignment.endDateTime
                MemberType = $assignment.memberType
                Status = $assignment.status
            }
        }
    }
    
    # Access Reviews (if requested)
    if ($IncludeAccessReviews) {
        $accessReviews = Get-AccessReviews
        $script:AccessReviewFindings = Analyze-AccessReviews -Reviews $accessReviews -RoleDefinitions $roleDefinitions
    }
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - PIM CONFIGURATION AUDIT" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:PIMFindings.Count -eq 0) {
        Write-Host "`n[!] No PIM configuration findings to display." -ForegroundColor Yellow
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display
    $matrixData = $script:PIMFindings | Sort-Object @{Expression={
        switch($_.RiskLevel) {
            "CRITICAL" { 0 }
            "HIGH" { 1 }
            "MEDIUM" { 2 }
            "LOW" { 3 }
            default { 4 }
        }
    }}, RoleName | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Role';Expression={if($_.RoleName.Length -gt 35){$_.RoleName.Substring(0,32)+"..."}else{$_.RoleName}}},
        @{Name='Critical';Expression={if($_.IsCritical){"Yes"}else{"No"}}},
        @{Name='MaxHrs';Expression={$_.MaxActivationDurationHours}},
        @{Name='Approval';Expression={if($_.RequireApproval){"Yes"}else{"No"}}},
        @{Name='MFA';Expression={if($_.RequireMFA){"Yes"}else{"No"}}},
        @{Name='Justify';Expression={if($_.RequireJustification){"Yes"}else{"No"}}},
        @{Name='Notify';Expression={if($_.NotifyOnActivation){"Yes"}else{"No"}}},
        @{Name='Eligible';Expression={$_.EligibleCount}},
        @{Name='Active';Expression={$_.ActiveCount}},
        @{Name='Perm';Expression={$_.PermanentCount}},
        @{Name='Issues';Expression={$_.FindingCount}}
    
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
    Write-Host "Total roles analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:PIMFindings.Count -ForegroundColor Yellow
    
    $criticalRisk = ($script:PIMFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
    $highRisk = ($script:PIMFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($script:PIMFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($script:PIMFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalRisk -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highRisk -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumRisk -ForegroundColor Cyan
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowRisk -ForegroundColor Green
    
    # Configuration gaps
    $noApproval = ($script:PIMFindings | Where-Object { -not $_.RequireApproval }).Count
    $noMFA = ($script:PIMFindings | Where-Object { -not $_.RequireMFA }).Count
    $noJustification = ($script:PIMFindings | Where-Object { -not $_.RequireJustification }).Count
    $noNotification = ($script:PIMFindings | Where-Object { -not $_.NotifyOnActivation }).Count
    $longActivation = ($script:PIMFindings | Where-Object { $_.MaxActivationDurationHours -gt $MaxActivationHours }).Count
    
    Write-Host "`n[CONFIGURATION GAPS]" -ForegroundColor Cyan
    Write-Host "  No approval required: " -NoNewline -ForegroundColor White
    Write-Host $noApproval -ForegroundColor $(if($noApproval -gt 0){"Red"}else{"Green"})
    Write-Host "  No MFA required: " -NoNewline -ForegroundColor White
    Write-Host $noMFA -ForegroundColor $(if($noMFA -gt 0){"Red"}else{"Green"})
    Write-Host "  No justification required: " -NoNewline -ForegroundColor White
    Write-Host $noJustification -ForegroundColor $(if($noJustification -gt 0){"Yellow"}else{"Green"})
    Write-Host "  No activation notification: " -NoNewline -ForegroundColor White
    Write-Host $noNotification -ForegroundColor $(if($noNotification -gt 0){"Yellow"}else{"Green"})
    Write-Host "  Long activation window (>$($MaxActivationHours)h): " -NoNewline -ForegroundColor White
    Write-Host $longActivation -ForegroundColor $(if($longActivation -gt 0){"Yellow"}else{"Green"})
    
    # Assignment summary
    $totalEligible = ($script:PIMFindings | Measure-Object -Property EligibleCount -Sum).Sum
    $totalActive = ($script:PIMFindings | Measure-Object -Property ActiveCount -Sum).Sum
    $totalPermanent = ($script:PIMFindings | Measure-Object -Property PermanentCount -Sum).Sum
    
    Write-Host "`n[ASSIGNMENT SUMMARY]" -ForegroundColor Cyan
    Write-Host "  Total eligible assignments: " -NoNewline -ForegroundColor White
    Write-Host $totalEligible -ForegroundColor Green
    Write-Host "  Total active assignments: " -NoNewline -ForegroundColor White
    Write-Host $totalActive -ForegroundColor Yellow
    Write-Host "  Total permanent assignments: " -NoNewline -ForegroundColor White
    Write-Host $totalPermanent -ForegroundColor $(if($totalPermanent -gt 0){"Yellow"}else{"Green"})
    
    # Critical role details
    $criticalRoles = $script:PIMFindings | Where-Object { $_.IsCritical }
    if ($criticalRoles.Count -gt 0) {
        Write-Host "`n[CRITICAL ROLES]" -ForegroundColor Cyan
        foreach ($role in $criticalRoles) {
            Write-Host "  $($role.RoleName): " -NoNewline -ForegroundColor White
            Write-Host "$($role.EligibleCount) eligible, $($role.ActiveCount) active, $($role.PermanentCount) permanent" -ForegroundColor $(if($role.RiskLevel -eq "CRITICAL"){"Red"}elseif($role.RiskLevel -eq "HIGH"){"Yellow"}else{"Green"})
        }
    }
    
    # Group PIM findings (if applicable)
    if ($script:GroupPIMFindings.Count -gt 0) {
        Write-Host "`n[PIM FOR GROUPS]" -ForegroundColor Cyan
        Write-Host "  Total group eligibility assignments: " -NoNewline -ForegroundColor White
        Write-Host $script:GroupPIMFindings.Count -ForegroundColor Yellow
    }
    
    # Access Review findings (if applicable)
    if ($script:AccessReviewFindings.Count -gt 0) {
        Write-Host "`n[ACCESS REVIEW GAPS]" -ForegroundColor Cyan
        foreach ($finding in $script:AccessReviewFindings) {
            Write-Host "  [$($finding.RiskLevel)] " -NoNewline -ForegroundColor $(if($finding.RiskLevel -eq "HIGH"){"Yellow"}else{"Cyan"})
            Write-Host $finding.Description -ForegroundColor White
        }
    }
    
    Write-Host ""
}

# Display detailed results
function Show-Results {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    
    Write-Host "`nTotal roles analyzed: " -NoNewline -ForegroundColor White
    Write-Host $script:PIMFindings.Count -ForegroundColor Yellow
    
    if ($script:PIMFindings.Count -gt 0) {
        $criticalRisk = ($script:PIMFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
        $highRisk = ($script:PIMFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
        $mediumRisk = ($script:PIMFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
        $lowRisk = ($script:PIMFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
        
        Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
        Write-Host $criticalRisk -ForegroundColor Red
        Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
        Write-Host $highRisk -ForegroundColor Yellow
        Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
        Write-Host $mediumRisk -ForegroundColor Cyan
        Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
        Write-Host $lowRisk -ForegroundColor Green
        
        Write-Host "`n" + ("-" * 70) -ForegroundColor Cyan
        Write-Host "PIM CONFIGURATION DETAILS:" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        $script:PIMFindings | Sort-Object @{Expression={
            switch($_.RiskLevel) {
                "CRITICAL" { 0 }
                "HIGH" { 1 }
                "MEDIUM" { 2 }
                "LOW" { 3 }
                default { 4 }
            }
        }}, RoleName | ForEach-Object {
            $riskColor = switch ($_.RiskLevel) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                "MEDIUM" { "Cyan" }
                "LOW" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n[$($_.RiskLevel)] PIM Gap: " -NoNewline -ForegroundColor $riskColor
            Write-Host $_.RoleName -ForegroundColor White
            
            if ($_.IsCritical) {
                Write-Host "  [!] CRITICAL ROLE - requires strictest controls" -ForegroundColor Red
            }
            elseif ($_.IsHighPrivilege) {
                Write-Host "  [!] HIGH-PRIVILEGE ROLE" -ForegroundColor Yellow
            }
            
            Write-Host "  Role ID: $($_.RoleId)" -ForegroundColor Gray
            Write-Host "  Built-in: $($_.IsBuiltIn)" -ForegroundColor Gray
            
            # Assignment counts
            Write-Host "  Eligible Users: " -NoNewline -ForegroundColor Gray
            Write-Host $_.EligibleCount -ForegroundColor Cyan
            Write-Host "  Active Assignments: " -NoNewline -ForegroundColor Gray
            Write-Host $_.ActiveCount -ForegroundColor Yellow
            Write-Host "  Permanent Assignments: " -NoNewline -ForegroundColor Gray
            Write-Host $_.PermanentCount -ForegroundColor $(if($_.PermanentCount -gt 0){"Yellow"}else{"Green"})
            
            # Configuration settings
            Write-Host "`n  [Configuration]" -ForegroundColor Cyan
            Write-Host "  Max Activation: " -NoNewline -ForegroundColor Gray
            $activationColor = if ($_.MaxActivationDurationHours -gt $MaxActivationHours) { "Yellow" } else { "Green" }
            Write-Host "$($_.MaxActivationDurationHours) hours (recommended: $MaxActivationHours hours)" -ForegroundColor $activationColor
            
            Write-Host "  Approval Required: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.RequireApproval){"Yes (Approvers: $($_.ApproverCount))"}else{"No"}) -ForegroundColor $(if($_.RequireApproval){"Green"}else{"Red"})
            
            Write-Host "  Justification Required: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.RequireJustification){"Yes"}else{"No"}) -ForegroundColor $(if($_.RequireJustification){"Green"}else{"Yellow"})
            
            Write-Host "  MFA Required: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.RequireMFA){"Yes"}else{"No"}) -ForegroundColor $(if($_.RequireMFA){"Green"}else{"Red"})
            
            Write-Host "  Notification on Activation: " -NoNewline -ForegroundColor Gray
            Write-Host $(if($_.NotifyOnActivation){"Yes"}else{"No"}) -ForegroundColor $(if($_.NotifyOnActivation){"Green"}else{"Yellow"})
            
            # Findings
            if ($_.Findings.Count -gt 0) {
                Write-Host "`n  [Findings]" -ForegroundColor Red
                foreach ($finding in $_.Findings) {
                    Write-Host "    - $finding" -ForegroundColor Yellow
                }
            }
            
            # Show eligible principals for critical/high-privilege roles
            if (($_.IsCritical -or $_.IsHighPrivilege) -and $_.EligiblePrincipals.Count -gt 0) {
                Write-Host "`n  [Eligible Principals]" -ForegroundColor Cyan
                foreach ($principal in $_.EligiblePrincipals | Select-Object -First 5) {
                    Write-Host "    - $($principal.DisplayName) ($($principal.Type))" -ForegroundColor Gray
                }
                if ($_.EligiblePrincipals.Count -gt 5) {
                    Write-Host "    ... and $($_.EligiblePrincipals.Count - 5) more" -ForegroundColor DarkGray
                }
            }
        }
        
        Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[!] No PIM configuration findings to display." -ForegroundColor Yellow
        Write-Host ("=" * 70) -ForegroundColor Cyan
    }
    
    # Group PIM findings
    if ($script:GroupPIMFindings.Count -gt 0) {
        Write-Host "`n[PIM FOR GROUPS - ELIGIBLE ASSIGNMENTS]" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        foreach ($assignment in $script:GroupPIMFindings | Select-Object -First 10) {
            Write-Host "  Group: $($assignment.GroupName)" -ForegroundColor White
            Write-Host "    Principal: $($assignment.PrincipalName) ($($assignment.PrincipalType))" -ForegroundColor Gray
            Write-Host "    Access Type: $($assignment.AccessType)" -ForegroundColor Gray
            Write-Host "    Member Type: $($assignment.MemberType)" -ForegroundColor Gray
            Write-Host ""
        }
        
        if ($script:GroupPIMFindings.Count -gt 10) {
            Write-Host "  ... and $($script:GroupPIMFindings.Count - 10) more" -ForegroundColor DarkGray
        }
    }
    
    # Access Review findings
    if ($script:AccessReviewFindings.Count -gt 0) {
        Write-Host "`n[ACCESS REVIEW GAPS]" -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor Cyan
        
        foreach ($finding in $script:AccessReviewFindings) {
            $riskColor = if ($finding.RiskLevel -eq "HIGH") { "Yellow" } else { "Cyan" }
            Write-Host "  [$($finding.RiskLevel)] $($finding.Description)" -ForegroundColor $riskColor
        }
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
    
    if ($script:PIMFindings.Count -eq 0) {
        Write-Host "`n[*] No PIM findings to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        # Prepare export data (flatten complex objects)
        $exportData = $script:PIMFindings | Select-Object `
            RoleId, RoleName, RoleDescription, IsBuiltIn, IsHighPrivilege, IsCritical,
            MaxActivationDurationHours, MaxActivationDuration, RequireApproval, ApproverCount, Approvers,
            RequireJustification, RequireMFA, RequireTicketInfo, NotifyOnActivation,
            NotifyOnEligibleAssignment, NotifyOnActiveAssignment,
            EligibleCount, ActiveCount, PermanentCount,
            @{Name='Findings';Expression={$_.Findings -join "; "}},
            FindingCount, RiskLevel, HasMisconfigurations,
            @{Name='EligiblePrincipals';Expression={($_.EligiblePrincipals | ForEach-Object { $_.DisplayName }) -join "; "}},
            @{Name='ActivePrincipals';Expression={($_.ActivePrincipals | ForEach-Object { $_.DisplayName }) -join "; "}}
        
        switch ($extension) {
            ".csv" {
                $exportData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $script:PIMFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
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
        Start-PIMScan
        
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
        
        Write-Host "`n[*] PIM configuration check completed successfully!" -ForegroundColor Green
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
