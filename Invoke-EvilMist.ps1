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

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Script,
    
    [Parameter()]
    [switch]$List
)

# Define available scripts mapping
$AvailableScripts = @{
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
}

# Script descriptions for display
$ScriptDescriptions = @{
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
    Write-Host "`n" -NoNewline
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║" -NoNewline -ForegroundColor Cyan
    Write-Host "           EvilMist Script Dispatcher                      " -NoNewline -ForegroundColor White
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
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

# Execute the script with all remaining parameters passed through
& $ScriptPath @args

