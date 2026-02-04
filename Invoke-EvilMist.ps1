<#
.SYNOPSIS
    EvilMist Script Dispatcher - Execute any EvilMist PowerShell script from the root directory.

.DESCRIPTION
    This dispatcher script allows you to execute any EvilMist PowerShell script from the root
    directory without navigating into subfolders. You can either specify a script name directly
    or use interactive mode to select from available scripts.

.PARAMETER Script
    Name of the script to execute (without .ps1 extension).
    Available scripts:
    - EntraEnum
    - EntraRecon
    - EntraMFACheck
    - EntraGuestCheck
    - EntraAppAccess
    - EntraRoleCheck
    - EntraServicePrincipalCheck
    - EntraConditionalAccessCheck
    - EntraAdminUnitCheck
    - EntraStaleAccountCheck
    - EntraDeviceCheck
    - EntraSSPRCheck
    - EntraPasswordPolicyCheck
    - EntraLegacyAuthCheck
    - EntraLicenseCheck
    - EntraDirectorySyncCheck
    - EntraPowerPlatformCheck
    - EntraAttackPathCheck
    - EntraAzureRBACCheck
    - EntraOAuthConsentCheck
    - EntraSignInRiskCheck
    - EntraPIMCheck
    - EntraKeyVaultCheck
    - EntraStorageAccountCheck
    - EntraNetworkSecurityCheck
    - EntraManagedIdentityCheck
    - EntraExchangeCheck
    - EntraSharePointCheck
    - EntraTeamsCheck
    - EntraAzureAttackPathCheck
    - EntraReport
    - EntraComplianceCheck

.PARAMETER List
    List all available scripts and exit.

.EXAMPLE
    .\Invoke-EvilMist.ps1 -Script EntraRecon -ExportPath "users.csv"
    
.EXAMPLE
    .\Invoke-EvilMist.ps1 -Script EntraMFACheck -Matrix -OnlyNoMFA
    
.EXAMPLE
    .\Invoke-EvilMist.ps1
    # Interactive mode - shows menu to select script
    
.EXAMPLE
    .\Invoke-EvilMist.ps1 -List
    # Lists all available scripts
#>

# PowerShell 7+ required
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] This script requires PowerShell 7 or later.' -ForegroundColor Red
    Write-Host ('Current version: PowerShell ' + $PSVersionTable.PSVersion.ToString()) -ForegroundColor Yellow
    Write-Host 'Download PowerShell 7: https://aka.ms/powershell-release?tag=stable' -ForegroundColor Cyan
    exit 1
}

# NO param() block - this allows any parameters to pass through without validation
# We parse $args manually to extract -Script and -List, and pass everything else to the target script

# Define available scripts mapping
$AvailableScripts = @{
    'EntraEnum' = 'Invoke-EntraEnum.ps1'
    'EntraRecon' = 'Invoke-EntraRecon.ps1'
    'EntraMFACheck' = 'Invoke-EntraMFACheck.ps1'
    'EntraGuestCheck' = 'Invoke-EntraGuestCheck.ps1'
    'EntraAppAccess' = 'Invoke-EntraAppAccess.ps1'
    'EntraRoleCheck' = 'Invoke-EntraRoleCheck.ps1'
    'EntraServicePrincipalCheck' = 'Invoke-EntraServicePrincipalCheck.ps1'
    'EntraConditionalAccessCheck' = 'Invoke-EntraConditionalAccessCheck.ps1'
    'EntraAdminUnitCheck' = 'Invoke-EntraAdminUnitCheck.ps1'
    'EntraStaleAccountCheck' = 'Invoke-EntraStaleAccountCheck.ps1'
    'EntraDeviceCheck' = 'Invoke-EntraDeviceCheck.ps1'
    'EntraSSPRCheck' = 'Invoke-EntraSSPRCheck.ps1'
    'EntraPasswordPolicyCheck' = 'Invoke-EntraPasswordPolicyCheck.ps1'
    'EntraLegacyAuthCheck' = 'Invoke-EntraLegacyAuthCheck.ps1'
    'EntraLicenseCheck' = 'Invoke-EntraLicenseCheck.ps1'
    'EntraDirectorySyncCheck' = 'Invoke-EntraDirectorySyncCheck.ps1'
    'EntraPowerPlatformCheck' = 'Invoke-EntraPowerPlatformCheck.ps1'
    'EntraGroupCheck' = 'Invoke-EntraGroupCheck.ps1'
    'EntraApplicationCheck' = 'Invoke-EntraApplicationCheck.ps1'
    'EntraAttackPathCheck' = 'Invoke-EntraAttackPathCheck.ps1'
    'EntraAzureRBACCheck' = 'Invoke-EntraAzureRBACCheck.ps1'
    'EntraOAuthConsentCheck' = 'Invoke-EntraOAuthConsentCheck.ps1'
    'EntraSignInRiskCheck' = 'Invoke-EntraSignInRiskCheck.ps1'
    'EntraPIMCheck' = 'Invoke-EntraPIMCheck.ps1'
    'EntraKeyVaultCheck' = 'Invoke-EntraKeyVaultCheck.ps1'
    'EntraStorageAccountCheck' = 'Invoke-EntraStorageAccountCheck.ps1'
    'EntraNetworkSecurityCheck' = 'Invoke-EntraNetworkSecurityCheck.ps1'
    'EntraManagedIdentityCheck' = 'Invoke-EntraManagedIdentityCheck.ps1'
    'EntraExchangeCheck' = 'Invoke-EntraExchangeCheck.ps1'
    'EntraSharePointCheck' = 'Invoke-EntraSharePointCheck.ps1'
    'EntraTeamsCheck' = 'Invoke-EntraTeamsCheck.ps1'
    'EntraAzureAttackPathCheck' = 'Invoke-EntraAzureAttackPathCheck.ps1'
    'EntraReport' = 'Invoke-EntraReport.ps1'
    'EntraComplianceCheck' = 'Invoke-EntraComplianceCheck.ps1'
}

# Script descriptions for display
$ScriptDescriptions = @{
    'EntraEnum' = 'Unauthenticated Azure/Entra ID enumeration and reconnaissance'
    'EntraRecon' = 'Comprehensive Azure Entra ID user enumeration and security assessment'
    'EntraMFACheck' = 'Identify users without Multi-Factor Authentication (MFA)'
    'EntraGuestCheck' = 'Guest account enumeration and security analysis'
    'EntraAppAccess' = 'Critical administrative application access check'
    'EntraRoleCheck' = 'Privileged directory role assignment check'
    'EntraServicePrincipalCheck' = 'Service principal security check'
    'EntraConditionalAccessCheck' = 'Conditional Access policy security check'
    'EntraAdminUnitCheck' = 'Administrative Unit security check'
    'EntraStaleAccountCheck' = 'Stale account and account hygiene check'
    'EntraDeviceCheck' = 'Device trust and compliance check'
    'EntraSSPRCheck' = 'Self-Service Password Reset check'
    'EntraPasswordPolicyCheck' = 'Password policy security check'
    'EntraLegacyAuthCheck' = 'Legacy authentication usage check'
    'EntraLicenseCheck' = 'License and SKU analysis'
    'EntraDirectorySyncCheck' = 'Directory sync status and health check'
    'EntraPowerPlatformCheck' = 'Power Platform enumeration and security audit'
    'EntraGroupCheck' = 'Group security analysis and governance'
    'EntraApplicationCheck' = 'Application registration security check'
    'EntraAttackPathCheck' = 'Attack path analysis - privilege escalation and lateral movement'
    'EntraAzureRBACCheck' = 'Azure RBAC role assignment audit and drift detection'
    'EntraOAuthConsentCheck' = 'OAuth consent grant audit - detect illicit consent attacks'
    'EntraSignInRiskCheck' = 'Identity Protection analysis - risky users and sign-in risk detection'
    'EntraPIMCheck' = 'Privileged Identity Management (PIM) configuration audit'
    'EntraKeyVaultCheck' = 'Azure Key Vault security audit - secrets exposure and misconfiguration'
    'EntraStorageAccountCheck' = 'Azure Storage Account security audit - exposed storage and data exfiltration risks'
    'EntraNetworkSecurityCheck' = 'Azure Network Security audit - NSG rules, open ports, lateral movement paths'
    'EntraManagedIdentityCheck' = 'Azure Managed Identity audit - excessive permissions and security risks'
    'EntraExchangeCheck' = 'Exchange Online security audit - inbox rules, forwarding, mail flow analysis'
    'EntraSharePointCheck' = 'SharePoint Online security audit - sharing settings, external access, oversharing risks'
    'EntraTeamsCheck' = 'Microsoft Teams security audit - external access, guest policies, meeting security'
    'EntraAzureAttackPathCheck' = 'Cross-service Azure attack path analysis - VM to Key Vault, privilege escalation, lateral movement'
    'EntraReport' = 'Consolidated HTML security report generator - executive dashboard and remediation matrix'
    'EntraComplianceCheck' = 'Compliance assessment with CIS/NIST/SOC2/ISO27001/GDPR benchmark mapping'
}

function Show-AvailableScripts {
    Write-Host "`nAvailable EvilMist Scripts:" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    $index = 1
    foreach ($scriptName in ($AvailableScripts.Keys | Sort-Object)) {
        $desc = $ScriptDescriptions[$scriptName]
        Write-Host "[$index] $scriptName" -ForegroundColor Yellow
        Write-Host "    $desc" -ForegroundColor Gray
        $index++
    }
    Write-Host ""
}

function Show-InteractiveMenu {
    Clear-Host
    Write-Host "`n===============================================================" -ForegroundColor Cyan
    Write-Host "           EvilMist Script Dispatcher                      " -ForegroundColor White
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Show-AvailableScripts
    
    Write-Host "Enter script number or name (or 'q' to quit): " -NoNewline -ForegroundColor Green
    $selection = Read-Host
    
    if ($selection -eq 'q' -or $selection -eq 'Q') {
        Write-Host "`nExiting..." -ForegroundColor Yellow
        return $null
    }
    
    # Try to parse as number
    if ([int]::TryParse($selection, [ref]$null)) {
        $scriptList = $AvailableScripts.Keys | Sort-Object
        $selectedIndex = [int]$selection - 1
        if ($selectedIndex -ge 0 -and $selectedIndex -lt $scriptList.Count) {
            return $scriptList[$selectedIndex]
        }
    }
    
    # Try to match by name (case-insensitive, partial match)
    $matchedScript = $AvailableScripts.Keys | Where-Object { 
        $_ -like "*$selection*" -or $_ -eq $selection 
    } | Select-Object -First 1
    
    if ($matchedScript) {
        return $matchedScript
    }
    
    Write-Host "`nInvalid selection. Please try again." -ForegroundColor Red
    Start-Sleep -Seconds 2
    return Show-InteractiveMenu
}

# Parse arguments manually from $args
# This allows us to capture -Script and -List while passing everything else through
$Script = $null
$List = $false
$PassthroughArgs = @()

for ($i = 0; $i -lt $args.Count; $i++) {
    $arg = $args[$i]
    
    if ($arg -eq '-Script' -or $arg -eq '/Script') {
        # Next argument is the script name
        if ($i + 1 -lt $args.Count) {
            $Script = $args[$i + 1]
            $i++  # Skip the next argument since we consumed it
        }
    }
    elseif ($arg -eq '-List' -or $arg -eq '/List') {
        $List = $true
    }
    elseif ($arg -match '^-Script:(.+)$' -or $arg -match '^/Script:(.+)$') {
        # Handle -Script:Value syntax
        $Script = $matches[1]
    }
    else {
        # Pass through to target script
        $PassthroughArgs += $arg
    }
}

# Main execution
$ScriptsPath = Join-Path $PSScriptRoot "scripts\powershell"

if (-not (Test-Path $ScriptsPath)) {
    Write-Error "Scripts directory not found at: $ScriptsPath"
    exit 1
}

# Handle -List parameter
if ($List) {
    Show-AvailableScripts
    exit 0
}

# If no script specified, show interactive menu
if ([string]::IsNullOrWhiteSpace($Script)) {
    $Script = Show-InteractiveMenu
    if (-not $Script) {
        exit 0
    }
}

# Validate script name
if (-not $AvailableScripts.ContainsKey($Script)) {
    Write-Error "Unknown script: $Script"
    Write-Host "`nUse -List to see all available scripts." -ForegroundColor Yellow
    exit 1
}

# Get the actual script filename
$ScriptFileName = $AvailableScripts[$Script]
$ScriptPath = Join-Path $ScriptsPath $ScriptFileName

if (-not (Test-Path $ScriptPath)) {
    Write-Error "Script not found at: $ScriptPath"
    exit 1
}

# Display which script is being executed
Write-Host "`nExecuting: $Script" -ForegroundColor Green
Write-Host "Description: $($ScriptDescriptions[$Script])" -ForegroundColor Gray
Write-Host "Path: $ScriptPath" -ForegroundColor Gray
Write-Host ""

# Execute the script with passthrough arguments
if ($PassthroughArgs.Count -gt 0) {
    & $ScriptPath @PassthroughArgs
}
else {
    & $ScriptPath
}
