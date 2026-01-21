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
    Maps and monitors Azure RBAC role assignments across all tenants and subscriptions with drift detection.

.DESCRIPTION
    This script provides Azure RBAC role assignment auditing and drift detection:
    
    Export Mode - Maps and exports existing role assignments to JSON (desired state)
    DriftDetect Mode - Compares current Azure state against baseline to detect changes
    
    By default, the script will automatically scan ALL accessible tenants and subscriptions
    unless you specify a specific -TenantId or -SubscriptionId parameter.

.PARAMETER Mode
    Operation mode: 'Export' or 'DriftDetect'. Default: Export

.PARAMETER ExportPath
    Path to export baseline JSON or drift report.

.PARAMETER BaselinePath
    Path to baseline JSON file (required for DriftDetect mode).

.PARAMETER SubscriptionId
    Specific subscription ID(s) to scan. If not specified, scans all accessible subscriptions in all tenants.

.PARAMETER TenantId
    Optional Tenant ID. If not specified, scans all accessible tenants automatically.

.PARAMETER UseAzCliToken
    Use Azure CLI authentication.

.PARAMETER UseAzPowerShellToken
    Use Azure PowerShell authentication.

.PARAMETER UseDeviceCode
    Use device code authentication flow. Recommended for embedded terminals where the login popup may be hidden.

.PARAMETER EnableStealth
    Enable stealth mode with delays.

.PARAMETER RequestDelay
    Base delay in seconds between API requests (0-60). Default: 0

.PARAMETER RequestJitter
    Random jitter range in seconds (0-30). Default: 0

.PARAMETER MaxRetries
    Maximum retries on throttling (1-10). Default: 3

.PARAMETER QuietStealth
    Suppress stealth-related messages.

.PARAMETER IncludeInherited
    Include inherited role assignments.

.PARAMETER Matrix
    Display results in matrix/table format.

.PARAMETER SkipFailedTenants
    Continue processing even when authentication fails for some tenants (common in multi-tenant/guest scenarios).

.PARAMETER ShowAllUsersPermissions
    Display a matrix showing all users and their permissions across the subscription(s).

.PARAMETER ExpandGroupMembers
    Expand group memberships to show all users who have Azure access through group membership.
    Requires Directory.Read.All or GroupMember.Read.All permissions in Microsoft Graph.

.PARAMETER ExcludePIM
    Exclude PIM (Privileged Identity Management) and JIT (Just-In-Time) role assignments from export and drift detection.
    These are time-bounded assignments that have an expiration date set via Azure PIM.
    Useful when you want to focus on permanent assignments only and ignore temporary elevated access.

.EXAMPLE
    .\Invoke-EntraAzureRBACCheck.ps1 -Mode Export -ExportPath "rbac-baseline.json"

.EXAMPLE
    .\Invoke-EntraAzureRBACCheck.ps1 -Mode DriftDetect -BaselinePath "rbac-baseline.json" -Matrix

.EXAMPLE
    .\Invoke-EntraAzureRBACCheck.ps1 -Mode Export -UseDeviceCode
    # Use device code authentication (recommended for embedded terminals like VS Code/Cursor)
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Export', 'DriftDetect')]
    [string]$Mode = 'Export',

    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [Parameter(Mandatory = $false)]
    [string]$BaselinePath,

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
    [switch]$IncludeInherited,

    [Parameter(Mandatory = $false)]
    [switch]$Matrix,

    [Parameter(Mandatory = $false)]
    [switch]$SkipFailedTenants,

    [Parameter(Mandatory = $false)]
    [switch]$ShowAllUsersPermissions,

    [Parameter(Mandatory = $false)]
    [switch]$ExpandGroupMembers,

    [Parameter(Mandatory = $false)]
    [switch]$ExcludePIM
)

# PowerShell 7+ required
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] This script requires PowerShell 7 or later.' -ForegroundColor Red
    Write-Host ('Current version: PowerShell ' + $PSVersionTable.PSVersion.ToString()) -ForegroundColor Yellow
    Write-Host 'Download PowerShell 7: https://aka.ms/powershell-release?tag=stable' -ForegroundColor Cyan
    exit 1
}

$ErrorActionPreference = "Continue"

# Required scopes for Microsoft Graph authentication
# GroupMember.Read.All is needed for -ExpandGroupMembers feature
$script:RequiredScopes = @(
    "User.Read",
    "Directory.Read.All",
    "GroupMember.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "User.Read"
)

# Track authenticated tenants to avoid re-authentication prompts
$script:AuthenticatedTenants = @{}

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:RoleAssignments = @()
$script:BaselineAssignments = @()
$script:DriftResults = @{
    NewAssignments = @()
    RemovedAssignments = @()
    ModifiedAssignments = @()
    ConditionMismatchAssignments = @()
    NewGroupMembers = @()
    RemovedGroupMembers = @()
}
$script:TotalSubscriptions = 0
$script:TotalAssignments = 0
$script:DriftScanInfo = @{}
$script:ExpandedGroupMembers = @{}
$script:BaselineExpandedAssignments = @()
$script:BaselineExpandedGroups = @{}
$script:BaselineHasExpandedGroups = $false
$script:StealthConfig = @{
    Enabled = $false
    BaseDelay = 0
    JitterRange = 0
    MaxRetries = 3
    QuietMode = $false
}

# PIM/JIT exclusion tracking
$script:PIMAssignmentIds = @{}
$script:ExcludedPIMCount = 0

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
    Write-Host "    Azure RBAC Role Assignment Audit & Drift Detection" -ForegroundColor Yellow
    Write-Host "    https://logisek.com | info@logisek.com"
    Write-Host "    Part of EvilMist Toolkit | github.com/Logisek/EvilMist"
    Write-Host ""
    Write-Host ""
}

function Show-RequiredPermissions {
    <#
    .SYNOPSIS
        Displays the required permissions for this script to work properly.
    #>
    Write-Host "[*] Required Permissions:" -ForegroundColor Cyan
    Write-Host "    Azure RBAC:" -ForegroundColor White
    Write-Host "      - Microsoft.Authorization/roleAssignments/read (Reader role or higher)" -ForegroundColor Gray
    Write-Host "      - Subscription-level access for each subscription to scan" -ForegroundColor Gray
    Write-Host "    Microsoft Graph:" -ForegroundColor White
    Write-Host "      - User.Read (for authentication)" -ForegroundColor Gray
    Write-Host "      - Directory.Read.All (optional, for resolving principal names)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "[*] If you see 'Access Denied' errors:" -ForegroundColor Yellow
    Write-Host "    1. Request 'Reader' role on the subscription(s) you want to audit" -ForegroundColor Gray
    Write-Host "    2. Or use 'Security Reader' for security-focused access" -ForegroundColor Gray
    Write-Host "    3. For cross-tenant access, ensure you're a guest in the target tenant" -ForegroundColor Gray
    Write-Host ""
}

function Get-PIMRoleAssignments {
    <#
    .SYNOPSIS
        Retrieves PIM (Privileged Identity Management) role assignment schedule instances.
    .DESCRIPTION
        Fetches active PIM/JIT role assignments that have time-bound access (EndDateTime set).
        These are assignments created through Azure PIM with an expiration date.
    .PARAMETER Scope
        The scope to query for PIM assignments (e.g., /subscriptions/{id}).
    .OUTPUTS
        Hashtable of RoleAssignmentId -> PIM assignment details for assignments with EndDateTime.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Scope
    )
    
    $pimAssignments = @{}
    
    try {
        Invoke-StealthDelay
        
        # Get-AzRoleAssignmentScheduleInstance returns active PIM role assignments
        # These are time-bounded assignments created through Azure PIM
        $scheduleInstances = Get-AzRoleAssignmentScheduleInstance -Scope $Scope -ErrorAction SilentlyContinue
        
        if ($scheduleInstances) {
            foreach ($instance in $scheduleInstances) {
                # Only track assignments that have an end date (time-bounded/JIT)
                if ($instance.EndDateTime) {
                    # Extract the role assignment ID to match against regular assignments
                    # The RoleAssignmentScheduleInstanceName contains the assignment identifier
                    $assignmentId = $instance.RoleAssignmentScheduleId
                    
                    # Also try to match by the underlying role assignment ID if available
                    if ($instance.OriginRoleAssignmentId) {
                        $pimAssignments[$instance.OriginRoleAssignmentId] = @{
                            PrincipalId = $instance.PrincipalId
                            RoleDefinitionId = $instance.RoleDefinitionId
                            Scope = $instance.Scope
                            StartDateTime = $instance.StartDateTime
                            EndDateTime = $instance.EndDateTime
                            AssignmentType = $instance.AssignmentType
                            MemberType = $instance.MemberType
                        }
                    }
                    
                    # Also store by schedule ID for backup matching
                    if ($assignmentId) {
                        $pimAssignments[$assignmentId] = @{
                            PrincipalId = $instance.PrincipalId
                            RoleDefinitionId = $instance.RoleDefinitionId
                            Scope = $instance.Scope
                            StartDateTime = $instance.StartDateTime
                            EndDateTime = $instance.EndDateTime
                            AssignmentType = $instance.AssignmentType
                            MemberType = $instance.MemberType
                        }
                    }
                    
                    # Store by a composite key for more reliable matching
                    $compositeKey = "$($instance.PrincipalId)|$($instance.RoleDefinitionId)|$($instance.Scope)"
                    $pimAssignments[$compositeKey] = @{
                        PrincipalId = $instance.PrincipalId
                        RoleDefinitionId = $instance.RoleDefinitionId
                        Scope = $instance.Scope
                        StartDateTime = $instance.StartDateTime
                        EndDateTime = $instance.EndDateTime
                        AssignmentType = $instance.AssignmentType
                        MemberType = $instance.MemberType
                    }
                }
            }
        }
    }
    catch {
        # PIM might not be available or licensed - silently continue
        # This is expected in environments without Azure AD P2/PIM
        if ($_.Exception.Message -notmatch 'not found|not available|not licensed|403|Forbidden') {
            Write-Verbose "PIM query warning: $($_.Exception.Message)"
        }
    }
    
    return $pimAssignments
}

function Test-IsPIMAssignment {
    <#
    .SYNOPSIS
        Checks if a role assignment is a PIM/JIT time-bounded assignment.
    .PARAMETER Assignment
        The role assignment object to check.
    .PARAMETER PIMAssignments
        Hashtable of known PIM assignments from Get-PIMRoleAssignments.
    .OUTPUTS
        Boolean indicating if this is a PIM assignment.
    #>
    param(
        [Parameter(Mandatory = $true)]
        $Assignment,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$PIMAssignments
    )
    
    # Check by assignment ID
    if ($PIMAssignments.ContainsKey($Assignment.RoleAssignmentId)) {
        return $true
    }
    
    # Check by composite key (PrincipalId|RoleDefinitionId|Scope)
    $compositeKey = "$($Assignment.ObjectId)|$($Assignment.RoleDefinitionId)|$($Assignment.Scope)"
    if ($PIMAssignments.ContainsKey($compositeKey)) {
        return $true
    }
    
    return $false
}

function Get-RemediationInstructions {
    <#
    .SYNOPSIS
        Generates remediation instructions for a drift issue.
    .DESCRIPTION
        Creates actionable remediation snippets including Terraform import blocks,
        JSON entries for terraform.tfvars.json, and workflow instructions.
    .PARAMETER DriftItem
        The drift result object containing assignment details.
    .PARAMETER DriftType
        The type of drift (NEW_ASSIGNMENT, REMOVED_ASSIGNMENT, MODIFIED_ASSIGNMENT, CONDITION_MISMATCH).
    .OUTPUTS
        PSCustomObject with Remediation instructions.
    #>
    param(
        [Parameter(Mandatory = $true)]
        $DriftItem,
        
        [Parameter(Mandatory = $true)]
        [string]$DriftType
    )
    
    $remediation = [PSCustomObject]@{
        ImportBlock = $null
        VarFileEntry = $null
        AzureCLI = $null
        PowerShell = $null
        Instructions = $null
    }
    
    # Generate a safe resource name for Terraform from the assignment
    $safeResourceName = ($DriftItem.PrincipalDisplayName -replace '[^a-zA-Z0-9_]', '_').ToLower()
    if ([string]::IsNullOrEmpty($safeResourceName)) {
        $safeResourceName = "assignment_" + ($DriftItem.AssignmentId -replace '.*/', '')
    }
    $safeResourceName = $safeResourceName.Substring(0, [Math]::Min(50, $safeResourceName.Length))
    
    switch ($DriftType) {
        "NEW_ASSIGNMENT" {
            # For new assignments, provide instructions to add to Terraform
            $remediation.ImportBlock = @"
# Import existing role assignment to Terraform state
import {
  to = azurerm_role_assignment.$safeResourceName
  id = "$($DriftItem.AssignmentId)"
}
"@
            
            $remediation.VarFileEntry = @{
                resource_name = $safeResourceName
                scope = $DriftItem.Scope
                role_definition_name = $DriftItem.RoleName
                principal_id = $DriftItem.PrincipalId
                principal_display_name = $DriftItem.PrincipalDisplayName
                principal_sign_in_name = $DriftItem.PrincipalSignInName
                principal_type = $DriftItem.PrincipalType
            }
            
            $remediation.AzureCLI = "az role assignment list --assignee `"$($DriftItem.PrincipalId)`" --scope `"$($DriftItem.Scope)`" --role `"$($DriftItem.RoleName)`""
            
            $remediation.PowerShell = "Get-AzRoleAssignment -ObjectId `"$($DriftItem.PrincipalId)`" -Scope `"$($DriftItem.Scope)`" -RoleDefinitionName `"$($DriftItem.RoleName)`""
            
            $remediation.Instructions = @"
NEW ASSIGNMENT DETECTED: $($DriftItem.PrincipalDisplayName) was granted $($DriftItem.RoleName)

To add to Terraform:
1. Add the import block above to your import.tf file
2. Add the variable entry to terraform.tfvars.json
3. Run: terraform plan -generate-config-out=generated.tf
4. Review generated configuration and merge into your main.tf
5. Run: terraform apply
6. Commit changes and create PR

To REMOVE if unauthorized:
  PowerShell: Remove-AzRoleAssignment -ObjectId "$($DriftItem.PrincipalId)" -Scope "$($DriftItem.Scope)" -RoleDefinitionName "$($DriftItem.RoleName)"
  Azure CLI: az role assignment delete --assignee "$($DriftItem.PrincipalId)" --scope "$($DriftItem.Scope)" --role "$($DriftItem.RoleName)"
"@
        }
        
        "REMOVED_ASSIGNMENT" {
            $remediation.VarFileEntry = @{
                resource_name = $safeResourceName
                scope = $DriftItem.Scope
                role_definition_name = $DriftItem.RoleName
                principal_id = $DriftItem.PrincipalId
                principal_display_name = $DriftItem.PrincipalDisplayName
                principal_type = $DriftItem.PrincipalType
                status = "REMOVED - needs restoration or removal from baseline"
            }
            
            $remediation.PowerShell = "New-AzRoleAssignment -ObjectId `"$($DriftItem.PrincipalId)`" -Scope `"$($DriftItem.Scope)`" -RoleDefinitionName `"$($DriftItem.RoleName)`""
            
            $remediation.AzureCLI = "az role assignment create --assignee `"$($DriftItem.PrincipalId)`" --scope `"$($DriftItem.Scope)`" --role `"$($DriftItem.RoleName)`""
            
            $remediation.Instructions = @"
REMOVED ASSIGNMENT DETECTED: $($DriftItem.PrincipalDisplayName) lost $($DriftItem.RoleName)

To RESTORE if removal was unauthorized:
  PowerShell: $($remediation.PowerShell)
  Azure CLI: $($remediation.AzureCLI)

To UPDATE BASELINE if removal was intentional:
1. Re-export baseline: .\Invoke-EntraAzureRBACCheck.ps1 -Mode Export -ExportPath "new-baseline.json"
2. Review and commit the new baseline
3. Remove the old assignment from your Terraform configuration
"@
        }
        
        "CONDITION_MISMATCH" {
            $remediation.VarFileEntry = @{
                resource_name = $safeResourceName
                scope = $DriftItem.Scope
                role_definition_name = $DriftItem.RoleName
                principal_id = $DriftItem.PrincipalId
                principal_display_name = $DriftItem.PrincipalDisplayName
                condition_baseline = $DriftItem.ConditionBaseline
                condition_current = $DriftItem.ConditionCurrent
                condition_version_baseline = $DriftItem.ConditionVersionBaseline
                condition_version_current = $DriftItem.ConditionVersionCurrent
            }
            
            $remediation.PowerShell = @"
# Get current assignment details
`$assignment = Get-AzRoleAssignment -ObjectId "$($DriftItem.PrincipalId)" -Scope "$($DriftItem.Scope)" -RoleDefinitionName "$($DriftItem.RoleName)"

# Update condition (restore baseline condition)
Set-AzRoleAssignment -InputObject `$assignment -Condition '$($DriftItem.ConditionBaseline)' -ConditionVersion '$($DriftItem.ConditionVersionBaseline)'
"@
            
            $remediation.Instructions = @"
CONDITION MISMATCH DETECTED: $($DriftItem.PrincipalDisplayName) - $($DriftItem.RoleName)
Issue: $($DriftItem.Issue)

Baseline Condition: $(if ($DriftItem.ConditionBaseline) { $DriftItem.ConditionBaseline } else { "[none]" })
Current Condition: $(if ($DriftItem.ConditionCurrent) { $DriftItem.ConditionCurrent } else { "[none]" })

WARNING: Removing or modifying ABAC conditions can grant broader access than intended.

To RESTORE baseline condition:
$($remediation.PowerShell)

To UPDATE BASELINE if change was intentional:
1. Re-export baseline with current conditions
2. Update Terraform configuration with new condition
3. Commit and create PR
"@
        }
        
        "MODIFIED_ASSIGNMENT" {
            $remediation.VarFileEntry = @{
                resource_name = $safeResourceName
                scope = $DriftItem.Scope
                role_definition_name = $DriftItem.RoleName
                principal_id = $DriftItem.PrincipalId
                principal_display_name = $DriftItem.PrincipalDisplayName
                changes = $DriftItem.Changes
            }
            
            $remediation.Instructions = @"
MODIFIED ASSIGNMENT DETECTED: $($DriftItem.PrincipalDisplayName) - $($DriftItem.RoleName)
Changes: $($DriftItem.Changes)

To INVESTIGATE:
  PowerShell: Get-AzRoleAssignment -ObjectId "$($DriftItem.PrincipalId)" | Format-List *
  
To UPDATE BASELINE if change was intentional:
1. Re-export baseline: .\Invoke-EntraAzureRBACCheck.ps1 -Mode Export
2. Compare changes and commit new baseline
"@
        }
        
        "NEW_GROUP_MEMBER" {
            $remediation.VarFileEntry = @{
                group_name = $DriftItem.GroupName
                group_id = $DriftItem.GroupId
                group_roles = $DriftItem.GroupRoles
                principal_id = $DriftItem.PrincipalId
                principal_display_name = $DriftItem.PrincipalDisplayName
                principal_sign_in_name = $DriftItem.PrincipalSignInName
                principal_type = $DriftItem.PrincipalType
            }
            
            $remediation.PowerShell = "Remove-AzADGroupMember -GroupObjectId `"$($DriftItem.GroupId)`" -MemberObjectId `"$($DriftItem.PrincipalId)`""
            
            $remediation.AzureCLI = "az ad group member remove --group `"$($DriftItem.GroupId)`" --member-id `"$($DriftItem.PrincipalId)`""
            
            $remediation.Instructions = @"
NEW GROUP MEMBER DETECTED: $($DriftItem.PrincipalDisplayName) added to $($DriftItem.GroupName)
Group Roles: $($DriftItem.GroupRoles)

This user now has Azure RBAC access through group membership.

To REMOVE if unauthorized:
  PowerShell: $($remediation.PowerShell)
  Azure CLI: $($remediation.AzureCLI)

To UPDATE BASELINE if addition was authorized:
1. Re-export baseline with -ExpandGroupMembers: .\Invoke-EntraAzureRBACCheck.ps1 -Mode Export -ExpandGroupMembers
2. Review and commit the new baseline

To INVESTIGATE group membership:
  PowerShell: Get-AzADGroupMember -GroupObjectId "$($DriftItem.GroupId)" | Select-Object DisplayName, UserPrincipalName, Id
"@
        }
        
        "REMOVED_GROUP_MEMBER" {
            $remediation.VarFileEntry = @{
                group_name = $DriftItem.GroupName
                group_id = $DriftItem.GroupId
                group_roles = $DriftItem.GroupRoles
                principal_id = $DriftItem.PrincipalId
                principal_display_name = $DriftItem.PrincipalDisplayName
                principal_sign_in_name = $DriftItem.PrincipalSignInName
                principal_type = $DriftItem.PrincipalType
                status = "REMOVED - needs restoration or baseline update"
            }
            
            $remediation.PowerShell = "Add-AzADGroupMember -TargetGroupObjectId `"$($DriftItem.GroupId)`" -MemberObjectId `"$($DriftItem.PrincipalId)`""
            
            $remediation.AzureCLI = "az ad group member add --group `"$($DriftItem.GroupId)`" --member-id `"$($DriftItem.PrincipalId)`""
            
            $remediation.Instructions = @"
REMOVED GROUP MEMBER DETECTED: $($DriftItem.PrincipalDisplayName) removed from $($DriftItem.GroupName)
Group Roles: $($DriftItem.GroupRoles)

This user lost Azure RBAC access through group membership removal.

To RESTORE if removal was unauthorized:
  PowerShell: $($remediation.PowerShell)
  Azure CLI: $($remediation.AzureCLI)

To UPDATE BASELINE if removal was authorized:
1. Re-export baseline with -ExpandGroupMembers: .\Invoke-EntraAzureRBACCheck.ps1 -Mode Export -ExpandGroupMembers
2. Review and commit the new baseline
"@
        }
        
        default {
            $remediation.Instructions = "Review this drift issue and take appropriate action based on your organization's policies."
        }
    }
    
    return $remediation
}

function Get-GroupMembersRecursive {
    <#
    .SYNOPSIS
        Retrieves all members of a group, including nested group members.
    .PARAMETER GroupId
        The Object ID of the group to expand.
    .PARAMETER GroupDisplayName
        The display name of the group (for logging).
    .PARAMETER Depth
        Current recursion depth (to prevent infinite loops).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,
        
        [Parameter(Mandatory = $false)]
        [string]$GroupDisplayName = "Unknown",
        
        [Parameter(Mandatory = $false)]
        [int]$Depth = 0
    )
    
    # Prevent infinite recursion
    if ($Depth -gt 5) {
        Write-Host "      [!] Max nesting depth reached for group $GroupDisplayName" -ForegroundColor Yellow
        return @()
    }
    
    # Check if we've already expanded this group
    if ($script:ExpandedGroupMembers.ContainsKey($GroupId)) {
        return $script:ExpandedGroupMembers[$GroupId]
    }
    
    $allMembers = @()
    
    try {
        Invoke-StealthDelay
        
        # Use Microsoft Graph to get group members
        $members = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop
        
        foreach ($member in $members) {
            $memberType = $member.AdditionalProperties.'@odata.type'
            
            if ($memberType -eq '#microsoft.graph.user') {
                # It's a user - add to the list
                $userInfo = [PSCustomObject]@{
                    PrincipalId = $member.Id
                    PrincipalType = "User"
                    PrincipalDisplayName = $member.AdditionalProperties.displayName
                    PrincipalSignInName = $member.AdditionalProperties.userPrincipalName
                    MemberOfGroup = $GroupDisplayName
                    MemberOfGroupId = $GroupId
                }
                $allMembers += $userInfo
            }
            elseif ($memberType -eq '#microsoft.graph.group') {
                # It's a nested group - recurse
                $nestedGroupName = $member.AdditionalProperties.displayName
                Write-Host "      [*] Found nested group: $nestedGroupName" -ForegroundColor Gray
                $nestedMembers = Get-GroupMembersRecursive -GroupId $member.Id -GroupDisplayName $nestedGroupName -Depth ($Depth + 1)
                $allMembers += $nestedMembers
            }
            elseif ($memberType -eq '#microsoft.graph.servicePrincipal') {
                # It's a service principal
                $spInfo = [PSCustomObject]@{
                    PrincipalId = $member.Id
                    PrincipalType = "ServicePrincipal"
                    PrincipalDisplayName = $member.AdditionalProperties.displayName
                    PrincipalSignInName = $member.AdditionalProperties.appId
                    MemberOfGroup = $GroupDisplayName
                    MemberOfGroupId = $GroupId
                }
                $allMembers += $spInfo
            }
        }
        
        # Cache the results
        $script:ExpandedGroupMembers[$GroupId] = $allMembers
    }
    catch {
        Write-Host "      [!] Failed to expand group $GroupDisplayName : $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    return $allMembers
}

function Expand-GroupMembersInAssignments {
    <#
    .SYNOPSIS
        Expands all group-based role assignments to show individual members.
    #>
    
    if ($script:RoleAssignments.Count -eq 0) {
        Write-Host "[!] No role assignments to expand" -ForegroundColor Yellow
        return
    }
    
    # Find all unique groups with role assignments
    $groupAssignments = $script:RoleAssignments | Where-Object { $_.PrincipalType -eq 'Group' }
    $uniqueGroups = $groupAssignments | Select-Object -Property PrincipalId, PrincipalDisplayName -Unique
    
    if ($uniqueGroups.Count -eq 0) {
        Write-Host "[*] No group-based role assignments found" -ForegroundColor Gray
        return
    }
    
    Write-Host "`n[*] Expanding $($uniqueGroups.Count) group(s) to show member details..." -ForegroundColor Cyan
    
    $expandedAssignments = @()
    $groupCounter = 0
    
    foreach ($group in $uniqueGroups) {
        $groupCounter++
        Write-Host "  [$groupCounter/$($uniqueGroups.Count)] Expanding group: $($group.PrincipalDisplayName)" -ForegroundColor Cyan
        
        $members = Get-GroupMembersRecursive -GroupId $group.PrincipalId -GroupDisplayName $group.PrincipalDisplayName
        
        if ($members.Count -eq 0) {
            Write-Host "      [*] No members found or unable to expand" -ForegroundColor Gray
            continue
        }
        
        Write-Host "      [+] Found $($members.Count) member(s)" -ForegroundColor Green
        
        # For each group assignment, create expanded entries for each member
        $groupRoleAssignments = $script:RoleAssignments | Where-Object { $_.PrincipalId -eq $group.PrincipalId }
        
        foreach ($assignment in $groupRoleAssignments) {
            foreach ($member in $members) {
                $expandedAssignment = [PSCustomObject]@{
                    AssignmentId = $assignment.AssignmentId
                    AssignmentName = $assignment.AssignmentName
                    TenantId = $assignment.TenantId
                    TenantName = $assignment.TenantName
                    SubscriptionId = $assignment.SubscriptionId
                    SubscriptionName = $assignment.SubscriptionName
                    Scope = $assignment.Scope
                    ScopeType = $assignment.ScopeType
                    RoleDefinitionName = $assignment.RoleDefinitionName
                    RoleDefinitionId = $assignment.RoleDefinitionId
                    PrincipalId = $member.PrincipalId
                    PrincipalType = $member.PrincipalType
                    PrincipalDisplayName = $member.PrincipalDisplayName
                    PrincipalSignInName = $member.PrincipalSignInName
                    InheritedFromGroup = $assignment.PrincipalDisplayName
                    InheritedFromGroupId = $assignment.PrincipalId
                    Condition = $assignment.Condition
                    ConditionVersion = $assignment.ConditionVersion
                    CanDelegate = $assignment.CanDelegate
                    CreatedOn = $assignment.CreatedOn
                    UpdatedOn = $assignment.UpdatedOn
                    CreatedBy = $assignment.CreatedBy
                    UpdatedBy = $assignment.UpdatedBy
                    ExportTimestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                }
                $expandedAssignments += $expandedAssignment
            }
        }
    }
    
    # Add expanded assignments to the role assignments
    if ($expandedAssignments.Count -gt 0) {
        $script:RoleAssignments += $expandedAssignments
        Write-Host "`n[+] Added $($expandedAssignments.Count) expanded group member assignment(s)" -ForegroundColor Green
        Write-Host "[+] Total assignments now: $($script:RoleAssignments.Count)" -ForegroundColor Green
    }
}

function Export-ExpandedGroupMembers {
    <#
    .SYNOPSIS
        Exports the expanded group membership data to a JSON file.
    #>
    param([string]$Path)
    
    if ($script:ExpandedGroupMembers.Count -eq 0) {
        Write-Host "[!] No expanded group data to export" -ForegroundColor Yellow
        return
    }
    
    if (-not $Path) {
        $baseName = if ($ExportPath) { 
            [System.IO.Path]::GetFileNameWithoutExtension($ExportPath) 
        } else { 
            "azure-rbac-baseline" 
        }
        $Path = "$baseName-expanded-groups.json"
    }
    
    try {
        # Get all assignments including expanded ones
        $expandedAssignments = $script:RoleAssignments | Where-Object { $_.InheritedFromGroup }
        $directAssignments = $script:RoleAssignments | Where-Object { -not $_.InheritedFromGroup }
        
        $exportData = @{
            ExportDate = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Summary = @{
                TotalGroups = $script:ExpandedGroupMembers.Count
                TotalExpandedMembers = ($script:ExpandedGroupMembers.Values | ForEach-Object { $_ }).Count
                TotalExpandedAssignments = $expandedAssignments.Count
                DirectAssignments = $directAssignments.Count
            }
            ExpandedGroups = $script:ExpandedGroupMembers.Keys | ForEach-Object {
                $groupId = $_
                $members = $script:ExpandedGroupMembers[$groupId]
                $groupAssignment = $script:RoleAssignments | Where-Object { $_.PrincipalId -eq $groupId -and $_.PrincipalType -eq 'Group' } | Select-Object -First 1
                
                [PSCustomObject]@{
                    GroupId = $groupId
                    GroupName = $groupAssignment.PrincipalDisplayName
                    MemberCount = $members.Count
                    Members = $members
                    Roles = ($script:RoleAssignments | Where-Object { $_.PrincipalId -eq $groupId -and $_.PrincipalType -eq 'Group' } | Select-Object RoleDefinitionName, SubscriptionName, Scope -Unique)
                }
            }
            AllAssignmentsWithExpansion = $script:RoleAssignments
        }
        
        $exportData | ConvertTo-Json -Depth 15 | Out-File -FilePath $Path -Encoding UTF8
        Write-Host "`n[+] Expanded group data exported to: $Path" -ForegroundColor Green
        Write-Host "[*] Total size: $([math]::Round((Get-Item $Path).Length / 1KB, 2)) KB" -ForegroundColor Cyan
    }
    catch {
        Write-Host "[ERROR] Failed to export expanded group data: $_" -ForegroundColor Red
    }
}

function Show-ExpandedGroupsMatrix {
    <#
    .SYNOPSIS
        Displays a matrix view of groups and their members with Azure access.
    #>
    
    Write-Host "`n" + ("=" * 120) -ForegroundColor Cyan
    Write-Host "EXPANDED GROUP MEMBERSHIP MATRIX" -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Cyan
    
    if ($script:ExpandedGroupMembers.Count -eq 0) {
        Write-Host "`n[!] No groups were expanded" -ForegroundColor Yellow
        return
    }
    
    # Get all group assignments
    $groupAssignments = $script:RoleAssignments | Where-Object { $_.PrincipalType -eq 'Group' }
    $uniqueGroups = $groupAssignments | Select-Object -Property PrincipalId, PrincipalDisplayName -Unique
    
    foreach ($group in $uniqueGroups) {
        $groupId = $group.PrincipalId
        $groupName = $group.PrincipalDisplayName
        
        # Get roles assigned to this group
        $groupRoles = $groupAssignments | Where-Object { $_.PrincipalId -eq $groupId }
        
        Write-Host "`n" + ("-" * 100) -ForegroundColor Magenta
        Write-Host "[GROUP] $groupName" -ForegroundColor Magenta
        Write-Host "  Group ID: $groupId" -ForegroundColor DarkGray
        Write-Host ""
        
        # Show roles
        Write-Host "  ROLES:" -ForegroundColor Yellow
        $groupRoles | Select-Object RoleDefinitionName, SubscriptionName, ScopeType -Unique | ForEach-Object {
            $roleColor = if ($_.RoleDefinitionName -match "Owner|User Access Administrator|Contributor") { "Red" } else { "Green" }
            Write-Host "    - $($_.RoleDefinitionName) on $($_.SubscriptionName) [$($_.ScopeType)]" -ForegroundColor $roleColor
        }
        
        # Show members
        if ($script:ExpandedGroupMembers.ContainsKey($groupId)) {
            $members = $script:ExpandedGroupMembers[$groupId]
            Write-Host "`n  MEMBERS ($($members.Count)):" -ForegroundColor Cyan
            
            $users = $members | Where-Object { $_.PrincipalType -eq 'User' }
            $sps = $members | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' }
            
            if ($users.Count -gt 0) {
                Write-Host "    Users:" -ForegroundColor White
                foreach ($user in $users) {
                    Write-Host "      - $($user.PrincipalDisplayName)" -ForegroundColor Cyan -NoNewline
                    if ($user.PrincipalSignInName) {
                        Write-Host " ($($user.PrincipalSignInName))" -ForegroundColor Gray
                    } else {
                        Write-Host ""
                    }
                }
            }
            
            if ($sps.Count -gt 0) {
                Write-Host "    Service Principals:" -ForegroundColor White
                foreach ($sp in $sps) {
                    Write-Host "      - $($sp.PrincipalDisplayName)" -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "`n  MEMBERS: Unable to expand (permission denied or empty group)" -ForegroundColor Yellow
        }
    }
    
    # Summary
    Write-Host "`n" + ("-" * 100) -ForegroundColor Cyan
    Write-Host "[SUMMARY]" -ForegroundColor Cyan
    
    $totalExpandedUsers = ($script:ExpandedGroupMembers.Values | ForEach-Object { $_ } | Where-Object { $_.PrincipalType -eq 'User' }).Count
    $totalExpandedSPs = ($script:ExpandedGroupMembers.Values | ForEach-Object { $_ } | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' }).Count
    
    Write-Host "  Groups expanded: $($script:ExpandedGroupMembers.Count)" -ForegroundColor White
    Write-Host "  Total users in groups: $totalExpandedUsers" -ForegroundColor Cyan
    Write-Host "  Total service principals in groups: $totalExpandedSPs" -ForegroundColor Yellow
    Write-Host ""
}

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
        "Az.Accounts",
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
        
        Write-Host "[*] Importing Az.Accounts..." -ForegroundColor Cyan
        Import-Module Az.Accounts -Force -ErrorAction Stop
        
        Write-Host "[*] Importing Az.Resources..." -ForegroundColor Cyan
        Import-Module Az.Resources -Force -ErrorAction Stop
        
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
        
        # Use device code authentication if requested (avoids WAM popup issues in embedded terminals)
        if ($UseDeviceCode) {
            $connectParams['UseDeviceCode'] = $true
            Write-Host "[*] Using device code authentication flow" -ForegroundColor Yellow
            Write-Host "[*] A code will be displayed - open a browser and enter it at https://microsoft.com/devicelogin" -ForegroundColor Yellow
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
            Write-Host "[*] TIP: Try running with -UseDeviceCode to avoid WAM popup issues" -ForegroundColor Yellow
            return $false
        }
    }
}

# Connect to Azure Resource Manager using Graph context
function Connect-AzureService {
    Write-Host "`n[*] Connecting to Azure Resource Manager..." -ForegroundColor Cyan
    
    # Check if already connected to Azure
    $existingContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($existingContext -and $existingContext.Account) {
        Write-Host "[+] Already connected to Azure" -ForegroundColor Green
        Write-Host "[+] Account: $($existingContext.Account.Id)" -ForegroundColor Green
        Write-Host "[+] Tenant: $($existingContext.Tenant.Id)" -ForegroundColor Green
        Write-Host "[+] Subscription: $($existingContext.Subscription.Name)" -ForegroundColor Green
        return $true
    }
    
    # Get Graph context to use same account
    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    
    try {
        $azConnectParams = @{
            ErrorAction = 'Stop'
        }
        
        # Use device code authentication if requested
        if ($UseDeviceCode) {
            $azConnectParams['UseDeviceAuthentication'] = $true
            Write-Host "[*] Using device code authentication for Azure" -ForegroundColor Yellow
        }
        
        if ($graphContext -and $graphContext.Account) {
            Write-Host "[*] Using account from Graph context: $($graphContext.Account)" -ForegroundColor Gray
            $tenantId = if ($graphContext.TenantId) { $graphContext.TenantId } else { $TenantId }
            
            if ($tenantId) {
                $azConnectParams['TenantId'] = $tenantId
            }
        }
        elseif ($TenantId) {
            $azConnectParams['TenantId'] = $TenantId
        }
        
        Connect-AzAccount @azConnectParams
        
        $context = Get-AzContext
        
        if (-not $context) {
            throw "No Azure context available after authentication"
        }
        
        Write-Host "[+] Connected to Azure" -ForegroundColor Green
        Write-Host "[+] Tenant: $($context.Tenant.Id)" -ForegroundColor Green
        Write-Host "[+] Account: $($context.Account.Id)" -ForegroundColor Green
        Write-Host "[+] Subscription: $($context.Subscription.Name)" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Host "[!] Azure login failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "[*] Falling back to interactive login..." -ForegroundColor Yellow
        
        try {
            $fallbackParams = @{ ErrorAction = 'Stop' }
            if ($UseDeviceCode) {
                $fallbackParams['UseDeviceAuthentication'] = $true
            }
            Connect-AzAccount @fallbackParams
            
            $context = Get-AzContext
            Write-Host "[+] Connected to Azure" -ForegroundColor Green
            Write-Host "[+] Tenant: $($context.Tenant.Id)" -ForegroundColor Green
            Write-Host "[+] Account: $($context.Account.Id)" -ForegroundColor Green
            Write-Host "[+] Subscription: $($context.Subscription.Name)" -ForegroundColor Green
            
            return $true
        }
        catch {
            Write-Host "[ERROR] Authentication failed: $_" -ForegroundColor Red
            Write-Host "[*] TIP: Try running with -UseDeviceCode to avoid WAM popup issues" -ForegroundColor Yellow
            return $false
        }
    }
}

function Get-AzureTenants {
    Write-Host "`n[*] Retrieving accessible tenants..." -ForegroundColor Cyan
    try {
        Invoke-StealthDelay
        $tenants = Get-AzTenant -ErrorAction Stop
        Write-Host "[+] Found $($tenants.Count) tenant(s)" -ForegroundColor Green
        foreach ($tenant in $tenants) {
            Write-Host "    - $($tenant.Name) ($($tenant.Id))" -ForegroundColor Gray
        }
        return $tenants
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve tenants: $_" -ForegroundColor Red
        return @()
    }
}

function Switch-ToTenant {
    <#
    .SYNOPSIS
        Safely switches Azure context to a specific tenant with proper authentication handling.
    .DESCRIPTION
        Attempts to switch to a tenant using Set-AzContext first. If that fails due to
        authentication issues, it falls back to Connect-AzAccount for proper re-authentication.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetTenantId,
        [string]$TenantName = $TargetTenantId
    )
    
    # Check if we've already authenticated to this tenant in this session
    if ($script:AuthenticatedTenants.ContainsKey($TargetTenantId)) {
        Write-Host "[*] Using cached authentication for tenant $TenantName" -ForegroundColor Gray
    }
    
    $previousWarningPreference = $WarningPreference
    $WarningPreference = 'SilentlyContinue'
    
    try {
        # First, try simple context switch
        $context = Set-AzContext -TenantId $TargetTenantId -ErrorAction Stop -WarningAction SilentlyContinue
        
        if ($context -and $context.Tenant.Id -eq $TargetTenantId) {
            $script:AuthenticatedTenants[$TargetTenantId] = $true
            $WarningPreference = $previousWarningPreference
            Write-Host "[+] Switched to tenant: $TenantName" -ForegroundColor Green
            return @{ Success = $true; Context = $context; RequiresReauth = $false }
        }
        
        throw "Context switch did not result in expected tenant"
    }
    catch {
        $errorMsg = $_.Exception.Message
        $WarningPreference = $previousWarningPreference
        
        # Check if this is an authentication issue that requires re-login
        if ($errorMsg -match 'User interaction is required|multi-factor authentication|MFA|Conditional Access|AADSTS\d+|token|expired|refresh') {
            Write-Host "[*] Tenant requires fresh authentication: $TenantName" -ForegroundColor Yellow
            
            # Try to re-authenticate to this specific tenant
            try {
                $connectParams = @{
                    TenantId = $TargetTenantId
                    ErrorAction = 'Stop'
                }
                
                if ($UseDeviceCode) {
                    $connectParams['UseDeviceAuthentication'] = $true
                    Write-Host "[*] Please complete device code authentication for tenant: $TenantName" -ForegroundColor Yellow
                }
                
                $null = Connect-AzAccount @connectParams
                $context = Get-AzContext
                
                if ($context -and $context.Tenant.Id -eq $TargetTenantId) {
                    $script:AuthenticatedTenants[$TargetTenantId] = $true
                    Write-Host "[+] Re-authenticated and switched to tenant: $TenantName" -ForegroundColor Green
                    return @{ Success = $true; Context = $context; RequiresReauth = $true }
                }
                
                throw "Re-authentication did not result in expected tenant context"
            }
            catch {
                Write-Host "[!] Failed to authenticate to tenant $TenantName : $($_.Exception.Message)" -ForegroundColor Yellow
                return @{ Success = $false; Error = $_.Exception.Message; RequiresReauth = $true }
            }
        }
        else {
            Write-Host "[!] Failed to switch to tenant $TenantName : $errorMsg" -ForegroundColor Yellow
            return @{ Success = $false; Error = $errorMsg; RequiresReauth = $false }
        }
    }
}

function Switch-ToSubscription {
    <#
    .SYNOPSIS
        Safely switches Azure context to a specific subscription with validation.
    .DESCRIPTION
        Switches to a subscription and validates that we have proper access before proceeding.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetSubscriptionId,
        [Parameter(Mandatory = $true)]
        [string]$TargetTenantId,
        [string]$SubscriptionName = $TargetSubscriptionId
    )
    
    $previousWarningPreference = $WarningPreference
    $WarningPreference = 'SilentlyContinue'
    
    try {
        $context = Set-AzContext -SubscriptionId $TargetSubscriptionId -TenantId $TargetTenantId -ErrorAction Stop -WarningAction SilentlyContinue
        
        $WarningPreference = $previousWarningPreference
        
        if (-not $context) {
            return @{ Success = $false; Error = "Set-AzContext returned null" }
        }
        
        # Validate we're in the right context
        if ($context.Subscription.Id -ne $TargetSubscriptionId) {
            return @{ Success = $false; Error = "Context subscription mismatch" }
        }
        
        Write-Host "[+] Switched to subscription: $SubscriptionName" -ForegroundColor Green
        return @{ Success = $true; Context = $context }
    }
    catch {
        $WarningPreference = $previousWarningPreference
        $errorMsg = $_.Exception.Message
        
        # Categorize the error for better handling
        if ($errorMsg -match 'valid tenant|valid subscription|does not exist|could not be found|not found') {
            return @{ 
                Success = $false
                Error = $errorMsg
                ErrorType = "NotFound"
                Recoverable = $false
            }
        }
        elseif ($errorMsg -match 'User interaction is required|multi-factor authentication|MFA|Conditional Access|AADSTS') {
            return @{
                Success = $false
                Error = $errorMsg
                ErrorType = "AuthRequired"
                Recoverable = $true
            }
        }
        elseif ($errorMsg -match 'authorization|permission|forbidden|access denied|AuthorizationFailed') {
            return @{
                Success = $false
                Error = $errorMsg
                ErrorType = "AccessDenied"
                Recoverable = $false
            }
        }
        else {
            return @{
                Success = $false
                Error = $errorMsg
                ErrorType = "Unknown"
                Recoverable = $false
            }
        }
    }
}

function Test-SubscriptionReadAccess {
    <#
    .SYNOPSIS
        Tests if the current context has read access to role assignments in the subscription.
    .DESCRIPTION
        Performs a lightweight test to verify we can read role assignments before attempting
        the full enumeration.
    #>
    param(
        [string]$SubscriptionName = "current subscription"
    )
    
    try {
        # Try to get just one role assignment to test access
        $null = Get-AzRoleAssignment -ErrorAction Stop | Select-Object -First 1
        return @{ HasAccess = $true }
    }
    catch {
        $errorMsg = $_.Exception.Message
        
        if ($errorMsg -match 'AuthorizationFailed|does not have authorization|permission') {
            Write-Host "[!] Insufficient permissions in $SubscriptionName" -ForegroundColor Yellow
            Write-Host "    Required: Microsoft.Authorization/roleAssignments/read" -ForegroundColor Gray
            Write-Host "    You need at least 'Reader' role on the subscription" -ForegroundColor Gray
            return @{ 
                HasAccess = $false
                Error = "Missing Microsoft.Authorization/roleAssignments/read permission"
                Suggestion = "Request 'Reader' role on this subscription"
            }
        }
        elseif ($errorMsg -match 'throttl|rate limit|too many requests|429') {
            Write-Host "[!] Rate limited - waiting before retry..." -ForegroundColor Yellow
            Start-Sleep -Seconds 30
            return @{ HasAccess = $true; Throttled = $true }
        }
        else {
            return @{ HasAccess = $false; Error = $errorMsg }
        }
    }
}

function Get-AzureSubscriptions {
    param([string]$ForTenantId)
    
    Write-Host "`n[*] Retrieving accessible subscriptions..." -ForegroundColor Cyan
    if ($ForTenantId) {
        Write-Host "[*] For tenant: $ForTenantId" -ForegroundColor Cyan
    }
    
    try {
        Invoke-StealthDelay
        if ($SubscriptionId -and $SubscriptionId.Count -gt 0) {
            Write-Host "[*] Using specified subscription(s): $($SubscriptionId -join ', ')" -ForegroundColor Cyan
            $subscriptions = @()
            foreach ($subId in $SubscriptionId) {
                $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction Stop
                if ($sub) { $subscriptions += $sub }
            }
        }
        else {
            if ($ForTenantId) {
                $subscriptions = Get-AzSubscription -TenantId $ForTenantId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                
                # Double-check: filter to only subscriptions that actually belong to this tenant
                # This prevents issues when Get-AzSubscription returns subscriptions from multiple tenants
                if ($subscriptions) {
                    $filteredSubs = $subscriptions | Where-Object { $_.TenantId -eq $ForTenantId }
                    if ($filteredSubs.Count -ne $subscriptions.Count) {
                        $skippedCount = $subscriptions.Count - $filteredSubs.Count
                        Write-Host "[*] Filtered out $skippedCount subscription(s) belonging to other tenants" -ForegroundColor Gray
                    }
                    $subscriptions = $filteredSubs
                }
            }
            else {
                $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }
        }
        
        if (-not $subscriptions) {
            $subscriptions = @()
        }
        
        Write-Host "[+] Found $($subscriptions.Count) subscription(s)" -ForegroundColor Green
        return $subscriptions
    }
    catch {
        if ($SkipFailedTenants) {
            Write-Host "[!] Skipping tenant due to error: $($_.Exception.Message)" -ForegroundColor Yellow
            return @()
        }
        Write-Host "[ERROR] Failed to retrieve subscriptions: $_" -ForegroundColor Red
        return @()
    }
}

function Get-AccessibleSubscriptionsForCurrentTenant {
    <#
    .SYNOPSIS
        Gets subscriptions only for the currently authenticated tenant to avoid cross-tenant auth issues.
    #>
    Write-Host "`n[*] Retrieving subscriptions for current tenant only..." -ForegroundColor Cyan
    
    try {
        $currentContext = Get-AzContext -ErrorAction Stop
        if (-not $currentContext) {
            Write-Host "[!] No Azure context available" -ForegroundColor Yellow
            return @()
        }
        
        $currentTenantId = $currentContext.Tenant.Id
        Write-Host "[*] Current tenant: $currentTenantId" -ForegroundColor Gray
        
        # Get subscriptions only for the current tenant to avoid cross-tenant auth failures
        $subscriptions = Get-AzSubscription -TenantId $currentTenantId -ErrorAction Stop -WarningAction SilentlyContinue
        
        Write-Host "[+] Found $($subscriptions.Count) subscription(s) in current tenant" -ForegroundColor Green
        return $subscriptions
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve subscriptions: $_" -ForegroundColor Red
        return @()
    }
}

function Get-ScopeType {
    param([string]$Scope)
    if ($Scope -match '^/subscriptions/[^/]+$') { return "Subscription" }
    elseif ($Scope -match '/resourceGroups/[^/]+$') { return "ResourceGroup" }
    elseif ($Scope -match '/providers/') { return "Resource" }
    elseif ($Scope -eq '/') { return "ManagementGroup" }
    else { return "Other" }
}

function Export-RoleAssignments {
    Write-Host "`n[*] Starting role assignment export..." -ForegroundColor Cyan
    
    # Determine which tenants to process
    $tenantsToProcess = @()
    $skippedTenants = @()
    
    if ($TenantId) {
        Write-Host "[*] Using specified tenant: $TenantId" -ForegroundColor Cyan
        $tenantsToProcess += @{ Id = $TenantId; Name = $TenantId }
    }
    else {
        Write-Host "[*] Scanning all accessible tenants..." -ForegroundColor Cyan
        Write-Host "[*] TIP: Use -TenantId to target a specific tenant and avoid cross-tenant auth issues" -ForegroundColor Gray
        $allTenants = Get-AzureTenants
        if ($allTenants.Count -eq 0) {
            Write-Host "[!] No tenants found" -ForegroundColor Yellow
            return
        }
        $tenantsToProcess = $allTenants
    }
    
    $allAssignments = @()
    $totalSubscriptionsProcessed = 0
    $tenantCounter = 0
    
    # Track all processed tenants and subscriptions for export
    $processedTenants = @()
    $processedSubscriptions = @()
    
    foreach ($tenant in $tenantsToProcess) {
        $tenantCounter++
        Write-Host "`n" + ("=" * 80) -ForegroundColor Magenta
        Write-Host "[*] Processing Tenant $tenantCounter/$($tenantsToProcess.Count): $($tenant.Name) ($($tenant.Id))" -ForegroundColor Magenta
        Write-Host ("=" * 80) -ForegroundColor Magenta
        
        try {
            # Switch to this tenant with proper authentication handling
            Invoke-StealthDelay
            
            $tenantSwitch = Switch-ToTenant -TargetTenantId $tenant.Id -TenantName $tenant.Name
            
            if (-not $tenantSwitch.Success) {
                $skippedTenants += @{ Id = $tenant.Id; Name = $tenant.Name; Reason = $tenantSwitch.Error }
                if ($SkipFailedTenants) {
                    Write-Host "[*] Skipping tenant (use -TenantId to target this specific tenant)" -ForegroundColor Gray
                    continue
                }
                else {
                    Write-Host "[!] Use -SkipFailedTenants to continue with other tenants" -ForegroundColor Yellow
                    throw $tenantSwitch.Error
                }
            }
            
            # Track this tenant as processed
            $tenantInfo = [PSCustomObject]@{
                TenantId = $tenant.Id
                TenantName = $tenant.Name
                ProcessedAt = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            }
            $processedTenants += $tenantInfo
            
            $subscriptions = Get-AzureSubscriptions -ForTenantId $tenant.Id
            
            if ($subscriptions.Count -eq 0) {
                Write-Host "[*] No Azure subscriptions accessible in tenant $($tenant.Name)" -ForegroundColor Gray
                Write-Host "    (This is normal if you're a guest user without Azure RBAC access)" -ForegroundColor DarkGray
                continue
            }
            
            $totalSubscriptionsProcessed += $subscriptions.Count
            $progressCounter = 0
            
            foreach ($subscription in $subscriptions) {
                $progressCounter++
                Write-Host "`n[*] Processing subscription $progressCounter/$($subscriptions.Count): $($subscription.Name)" -ForegroundColor Cyan
                Write-Host "    Subscription ID: $($subscription.Id)" -ForegroundColor Gray
                
                try {
                    Invoke-StealthDelay
                    
                    # Use the subscription's actual TenantId if available, otherwise use the loop's tenant
                    $subscriptionTenantId = if ($subscription.TenantId) { $subscription.TenantId } else { $tenant.Id }
                    
                    # If the subscription belongs to a different tenant, skip it (it will be processed when we iterate to that tenant)
                    if ($subscriptionTenantId -ne $tenant.Id) {
                        Write-Host "[*] Subscription belongs to different tenant ($subscriptionTenantId), skipping..." -ForegroundColor Gray
                        continue
                    }
                    
                    # Switch to subscription with validation
                    $subSwitch = Switch-ToSubscription -TargetSubscriptionId $subscription.Id -TargetTenantId $subscriptionTenantId -SubscriptionName $subscription.Name
                    
                    if (-not $subSwitch.Success) {
                        if ($subSwitch.ErrorType -eq "NotFound") {
                            Write-Host "[!] Subscription not accessible: $($subscription.Name)" -ForegroundColor Yellow
                            Write-Host "    Error: $($subSwitch.Error)" -ForegroundColor Gray
                        }
                        elseif ($subSwitch.ErrorType -eq "AuthRequired") {
                            Write-Host "[!] Subscription requires re-authentication: $($subscription.Name)" -ForegroundColor Yellow
                        }
                        elseif ($subSwitch.ErrorType -eq "AccessDenied") {
                            Write-Host "[!] Access denied to subscription: $($subscription.Name)" -ForegroundColor Yellow
                            Write-Host "    You may need Reader role on this subscription" -ForegroundColor Gray
                        }
                        else {
                            Write-Host "[!] Failed to switch to subscription: $($subSwitch.Error)" -ForegroundColor Yellow
                        }
                        continue
                    }
                    
                    # Test if we have read access to role assignments
                    $accessTest = Test-SubscriptionReadAccess -SubscriptionName $subscription.Name
                    if (-not $accessTest.HasAccess) {
                        Write-Host "[!] Cannot read role assignments in $($subscription.Name)" -ForegroundColor Yellow
                        if ($accessTest.Suggestion) {
                            Write-Host "    Suggestion: $($accessTest.Suggestion)" -ForegroundColor Gray
                        }
                        continue
                    }
                    
                    Write-Host "[*] Retrieving role assignments..." -ForegroundColor Cyan
                    Invoke-StealthDelay
                    $assignments = Get-AzRoleAssignment -IncludeClassicAdministrators:$false -ErrorAction Stop
                    if (-not $IncludeInherited) {
                        $assignments = $assignments | Where-Object { $_.Scope -notmatch '/providers/Microsoft.Management/managementGroups/' }
                    }
                    
                    $excludedPIMCountThisSub = 0
                    
                    # Filter out PIM/JIT assignments if requested
                    if ($ExcludePIM) {
                        Write-Host "[*] Checking for PIM/JIT assignments to exclude..." -ForegroundColor Cyan
                        $subscriptionScope = "/subscriptions/$($subscription.Id)"
                        $pimAssignments = Get-PIMRoleAssignments -Scope $subscriptionScope
                        
                        if ($pimAssignments.Count -gt 0) {
                            # Store PIM assignments for reference
                            foreach ($key in $pimAssignments.Keys) {
                                $script:PIMAssignmentIds[$key] = $pimAssignments[$key]
                            }
                            
                            # Filter out PIM assignments
                            $filteredAssignments = @()
                            foreach ($assignment in $assignments) {
                                if (-not (Test-IsPIMAssignment -Assignment $assignment -PIMAssignments $pimAssignments)) {
                                    $filteredAssignments += $assignment
                                }
                                else {
                                    $excludedPIMCountThisSub++
                                    $script:ExcludedPIMCount++
                                }
                            }
                            $assignments = $filteredAssignments
                            
                            if ($excludedPIMCountThisSub -gt 0) {
                                Write-Host "[*] Excluded $excludedPIMCountThisSub PIM/JIT assignment(s)" -ForegroundColor Yellow
                            }
                        }
                    }
                    
                    Write-Host "[+] Found $($assignments.Count) role assignment(s)$(if ($excludedPIMCountThisSub -gt 0) { " (after excluding $excludedPIMCountThisSub PIM)" })" -ForegroundColor Green
                    
                    # Track this subscription as processed
                    $subscriptionInfo = [PSCustomObject]@{
                        SubscriptionId = $subscription.Id
                        SubscriptionName = $subscription.Name
                        TenantId = $tenant.Id
                        TenantName = $tenant.Name
                        State = $subscription.State
                        RoleAssignmentCount = $assignments.Count
                        ExcludedPIMCount = $excludedPIMCountThisSub
                        ProcessedAt = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                    }
                    $processedSubscriptions += $subscriptionInfo
                    
                    foreach ($assignment in $assignments) {
                        $assignmentData = [PSCustomObject]@{
                            AssignmentId = $assignment.RoleAssignmentId
                            AssignmentName = $assignment.RoleAssignmentName
                            TenantId = $tenant.Id
                            TenantName = $tenant.Name
                            SubscriptionId = $subscription.Id
                            SubscriptionName = $subscription.Name
                            Scope = $assignment.Scope
                            ScopeType = Get-ScopeType -Scope $assignment.Scope
                            RoleDefinitionName = $assignment.RoleDefinitionName
                            RoleDefinitionId = $assignment.RoleDefinitionId
                            PrincipalId = $assignment.ObjectId
                            PrincipalType = $assignment.ObjectType
                            PrincipalDisplayName = $assignment.DisplayName
                            PrincipalSignInName = $assignment.SignInName
                            Condition = $assignment.Condition
                            ConditionVersion = $assignment.ConditionVersion
                            CanDelegate = $assignment.CanDelegate
                            CreatedOn = $assignment.CreatedOn
                            UpdatedOn = $assignment.UpdatedOn
                            CreatedBy = $assignment.CreatedBy
                            UpdatedBy = $assignment.UpdatedBy
                            ExportTimestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                        }
                        $allAssignments += $assignmentData
                        $script:RoleAssignments += $assignmentData
                    }
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    
                    # Handle errors during role assignment retrieval
                    if ($errorMsg -match 'AuthorizationFailed|does not have authorization|permission|forbidden') {
                        Write-Host "[!] Insufficient permissions to read role assignments in $($subscription.Name)" -ForegroundColor Yellow
                        Write-Host "    Required permission: Microsoft.Authorization/roleAssignments/read" -ForegroundColor Gray
                        Write-Host "    Request 'Reader' role on this subscription to fix this" -ForegroundColor Gray
                    }
                    elseif ($errorMsg -match 'throttl|rate limit|too many requests|429') {
                        Write-Host "[!] Rate limited on $($subscription.Name) - consider using -EnableStealth" -ForegroundColor Yellow
                    }
                    else {
                        Write-Host "[!] Error processing subscription $($subscription.Name): $errorMsg" -ForegroundColor Yellow
                    }
                    # Always continue to next subscription on error
                    continue
                }
            }
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-Host "[!] Error processing tenant $($tenant.Name): $errorMsg" -ForegroundColor Yellow
            $skippedTenants += @{ Id = $tenant.Id; Name = $tenant.Name; Reason = $errorMsg }
            if ($SkipFailedTenants) {
                continue
            }
        }
    }
    
    # Report skipped tenants
    if ($skippedTenants.Count -gt 0) {
        Write-Host "`n[!] Skipped $($skippedTenants.Count) tenant(s) due to authentication issues:" -ForegroundColor Yellow
        foreach ($st in $skippedTenants) {
            Write-Host "    - $($st.Name) ($($st.Id)): $($st.Reason)" -ForegroundColor Yellow
        }
        Write-Host "[*] To access these tenants, authenticate directly:" -ForegroundColor Cyan
        Write-Host "    Connect-AzAccount -TenantId <TenantId>" -ForegroundColor Gray
    }
    
    $script:TotalSubscriptions = $totalSubscriptionsProcessed
    $script:TotalAssignments = $allAssignments.Count
    
    Write-Host "`n" + ("=" * 80) -ForegroundColor Green
    Write-Host "[+] Export Summary" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host "[+] Total tenants processed: $($tenantsToProcess.Count)" -ForegroundColor Green
    Write-Host "[+] Total subscriptions processed: $totalSubscriptionsProcessed" -ForegroundColor Green
    Write-Host "[+] Total role assignments collected: $script:TotalAssignments" -ForegroundColor Green
    if ($ExcludePIM -and $script:ExcludedPIMCount -gt 0) {
        Write-Host "[*] PIM/JIT assignments excluded: $($script:ExcludedPIMCount)" -ForegroundColor Yellow
    }
    
    $exportFile = if ($ExportPath) { $ExportPath } else { "azure-rbac-baseline.json" }
    try {
        # Calculate scope-level statistics
        $scopeStats = @{
            SubscriptionLevel = ($allAssignments | Where-Object { $_.ScopeType -eq 'Subscription' }).Count
            ResourceGroupLevel = ($allAssignments | Where-Object { $_.ScopeType -eq 'ResourceGroup' }).Count
            ResourceLevel = ($allAssignments | Where-Object { $_.ScopeType -eq 'Resource' }).Count
            ManagementGroupLevel = ($allAssignments | Where-Object { $_.ScopeType -eq 'ManagementGroup' }).Count
            Other = ($allAssignments | Where-Object { $_.ScopeType -eq 'Other' }).Count
        }
        
        # Calculate principal type statistics
        $principalStats = @{
            Users = ($allAssignments | Where-Object { $_.PrincipalType -eq 'User' }).Count
            Groups = ($allAssignments | Where-Object { $_.PrincipalType -eq 'Group' }).Count
            ServicePrincipals = ($allAssignments | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' }).Count
            Other = ($allAssignments | Where-Object { $_.PrincipalType -notin @('User', 'Group', 'ServicePrincipal') }).Count
        }
        
        # Calculate high-privilege role statistics
        $highPrivilegeStats = @{
            Owners = ($allAssignments | Where-Object { $_.RoleDefinitionName -eq 'Owner' }).Count
            Contributors = ($allAssignments | Where-Object { $_.RoleDefinitionName -eq 'Contributor' }).Count
            UserAccessAdministrators = ($allAssignments | Where-Object { $_.RoleDefinitionName -eq 'User Access Administrator' }).Count
        }
        
        # Expand group members if requested - do this BEFORE building export data
        $expandedGroupData = $null
        $expandedAssignmentsList = @()
        if ($ExpandGroupMembers) {
            Write-Host "`n[*] Expanding group memberships for baseline..." -ForegroundColor Cyan
            
            # Find all unique groups with role assignments
            $groupAssignments = $allAssignments | Where-Object { $_.PrincipalType -eq 'Group' }
            $uniqueGroups = $groupAssignments | Select-Object -Property PrincipalId, PrincipalDisplayName -Unique
            
            if ($uniqueGroups.Count -gt 0) {
                Write-Host "[*] Found $($uniqueGroups.Count) group(s) to expand" -ForegroundColor Cyan
                
                $expandedGroupData = @{}
                $groupCounter = 0
                
                foreach ($group in $uniqueGroups) {
                    $groupCounter++
                    Write-Host "  [$groupCounter/$($uniqueGroups.Count)] Expanding: $($group.PrincipalDisplayName)" -ForegroundColor Gray
                    
                    $members = Get-GroupMembersRecursive -GroupId $group.PrincipalId -GroupDisplayName $group.PrincipalDisplayName
                    
                    if ($members.Count -gt 0) {
                        Write-Host "      [+] Found $($members.Count) member(s)" -ForegroundColor Green
                        
                        # Store expanded group data
                        $expandedGroupData[$group.PrincipalId] = @{
                            GroupId = $group.PrincipalId
                            GroupName = $group.PrincipalDisplayName
                            Members = $members
                        }
                        
                        # Also populate script-level variable for Show-ExpandedGroupsMatrix
                        $script:ExpandedGroupMembers[$group.PrincipalId] = $members
                        
                        # Create expanded assignments for each member
                        $groupRoleAssignments = $allAssignments | Where-Object { $_.PrincipalId -eq $group.PrincipalId }
                        foreach ($assignment in $groupRoleAssignments) {
                            foreach ($member in $members) {
                                $expandedAssignment = [PSCustomObject]@{
                                    AssignmentId = "$($assignment.AssignmentId)_$($member.PrincipalId)"
                                    OriginalAssignmentId = $assignment.AssignmentId
                                    TenantId = $assignment.TenantId
                                    TenantName = $assignment.TenantName
                                    SubscriptionId = $assignment.SubscriptionId
                                    SubscriptionName = $assignment.SubscriptionName
                                    Scope = $assignment.Scope
                                    ScopeType = $assignment.ScopeType
                                    RoleDefinitionName = $assignment.RoleDefinitionName
                                    RoleDefinitionId = $assignment.RoleDefinitionId
                                    PrincipalId = $member.PrincipalId
                                    PrincipalType = $member.PrincipalType
                                    PrincipalDisplayName = $member.PrincipalDisplayName
                                    PrincipalSignInName = $member.PrincipalSignInName
                                    InheritedFromGroup = $group.PrincipalDisplayName
                                    InheritedFromGroupId = $group.PrincipalId
                                    IsExpandedMember = $true
                                    ExportTimestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                                }
                                $expandedAssignmentsList += $expandedAssignment
                            }
                        }
                    }
                    else {
                        Write-Host "      [*] No members found or unable to expand" -ForegroundColor Gray
                    }
                }
                
                Write-Host "[+] Expanded $($expandedAssignmentsList.Count) inherited assignments from groups" -ForegroundColor Green
            }
            else {
                Write-Host "[*] No group-based role assignments found to expand" -ForegroundColor Gray
            }
        }
        
        # Build comprehensive export data with all tenant and subscription details
        $exportData = @{
            ExportDate = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            ExportVersion = "2.3"
            Summary = @{
                TotalTenants = $processedTenants.Count
                TotalSubscriptions = $script:TotalSubscriptions
                TotalAssignments = $script:TotalAssignments
                TotalExpandedAssignments = $expandedAssignmentsList.Count
                SkippedTenants = $skippedTenants.Count
                IncludeInherited = $IncludeInherited.IsPresent
                IncludesExpandedGroups = ($ExpandGroupMembers -and $expandedGroupData -and $expandedGroupData.Count -gt 0)
                ExcludePIM = $ExcludePIM.IsPresent
                ExcludedPIMAssignments = $script:ExcludedPIMCount
            }
            ScopeStatistics = $scopeStats
            PrincipalStatistics = $principalStats
            HighPrivilegeRoles = $highPrivilegeStats
            Tenants = $processedTenants
            Subscriptions = $processedSubscriptions
            SkippedTenants = $skippedTenants | ForEach-Object {
                [PSCustomObject]@{
                    TenantId = $_.Id
                    TenantName = $_.Name
                    Reason = $_.Reason
                }
            }
            RoleAssignments = $allAssignments
            ExpandedGroupAssignments = if ($expandedAssignmentsList.Count -gt 0) { $expandedAssignmentsList } else { @() }
            ExpandedGroups = if ($expandedGroupData) { 
                $expandedGroupData.Values | ForEach-Object {
                    [PSCustomObject]@{
                        GroupId = $_.GroupId
                        GroupName = $_.GroupName
                        MemberCount = $_.Members.Count
                        Members = $_.Members
                    }
                }
            } else { @() }
        }
        $exportData | ConvertTo-Json -Depth 15 | Out-File -FilePath $exportFile -Encoding UTF8
        Write-Host "[+] Baseline exported to: $exportFile" -ForegroundColor Green
        Write-Host "[*] Total size: $([math]::Round((Get-Item $exportFile).Length / 1KB, 2)) KB" -ForegroundColor Cyan
        
        # Display exported content summary
        Write-Host "`n[*] Export Contents:" -ForegroundColor Cyan
        Write-Host "    - Tenants: $($processedTenants.Count)" -ForegroundColor Gray
        foreach ($t in $processedTenants) {
            Write-Host "      * $($t.TenantName) ($($t.TenantId))" -ForegroundColor Gray
        }
        Write-Host "    - Subscriptions: $($processedSubscriptions.Count)" -ForegroundColor Gray
        foreach ($s in $processedSubscriptions) {
            Write-Host "      * $($s.SubscriptionName) ($($s.SubscriptionId)) - $($s.RoleAssignmentCount) assignments" -ForegroundColor Gray
        }
        Write-Host "    - Role Assignments: $($allAssignments.Count)" -ForegroundColor Gray
        
        # Display scope breakdown
        Write-Host "`n[*] Assignments by Scope:" -ForegroundColor Cyan
        Write-Host "    - Subscription Level: $($scopeStats.SubscriptionLevel)" -ForegroundColor Gray
        Write-Host "    - Resource Group Level: $($scopeStats.ResourceGroupLevel)" -ForegroundColor Gray
        Write-Host "    - Resource Level: $($scopeStats.ResourceLevel)" -ForegroundColor Gray
        if ($scopeStats.ManagementGroupLevel -gt 0) {
            Write-Host "    - Management Group Level: $($scopeStats.ManagementGroupLevel)" -ForegroundColor Gray
        }
        
        # Display principal breakdown
        Write-Host "`n[*] Assignments by Principal Type:" -ForegroundColor Cyan
        Write-Host "    - Users: $($principalStats.Users)" -ForegroundColor Gray
        Write-Host "    - Groups: $($principalStats.Groups)" -ForegroundColor Gray
        Write-Host "    - Service Principals: $($principalStats.ServicePrincipals)" -ForegroundColor Gray
        
        # Display high-privilege roles
        if (($highPrivilegeStats.Owners + $highPrivilegeStats.Contributors + $highPrivilegeStats.UserAccessAdministrators) -gt 0) {
            Write-Host "`n[!] High-Privilege Role Assignments:" -ForegroundColor Yellow
            if ($highPrivilegeStats.Owners -gt 0) {
                Write-Host "    - Owner: $($highPrivilegeStats.Owners)" -ForegroundColor Red
            }
            if ($highPrivilegeStats.Contributors -gt 0) {
                Write-Host "    - Contributor: $($highPrivilegeStats.Contributors)" -ForegroundColor Yellow
            }
            if ($highPrivilegeStats.UserAccessAdministrators -gt 0) {
                Write-Host "    - User Access Administrator: $($highPrivilegeStats.UserAccessAdministrators)" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "[ERROR] Failed to export baseline: $_" -ForegroundColor Red
    }
}

function Import-Baseline {
    param([string]$Path)
    Write-Host "`n[*] Loading baseline from: $Path" -ForegroundColor Cyan
    if (-not (Test-Path $Path)) {
        Write-Host "[ERROR] Baseline file not found: $Path" -ForegroundColor Red
        return $false
    }
    try {
        $baselineData = Get-Content -Path $Path -Raw | ConvertFrom-Json
        if (-not $baselineData.RoleAssignments) {
            Write-Host "[ERROR] Invalid baseline file format" -ForegroundColor Red
            return $false
        }
        $script:BaselineAssignments = $baselineData.RoleAssignments
        Write-Host "[+] Baseline loaded: $($script:BaselineAssignments.Count) direct assignments" -ForegroundColor Green
        Write-Host "[+] Baseline date: $($baselineData.ExportDate)" -ForegroundColor Green
        
        # Check for expanded group data (v2.1+ format)
        if ($baselineData.Summary.IncludesExpandedGroups -eq $true) {
            $script:BaselineHasExpandedGroups = $true
            Write-Host "[+] Baseline includes expanded group memberships" -ForegroundColor Green
            
            # Load expanded assignments
            if ($baselineData.ExpandedGroupAssignments -and $baselineData.ExpandedGroupAssignments.Count -gt 0) {
                $script:BaselineExpandedAssignments = $baselineData.ExpandedGroupAssignments
                Write-Host "[+] Loaded $($script:BaselineExpandedAssignments.Count) expanded group member assignments" -ForegroundColor Green
            }
            
            # Load expanded group details
            if ($baselineData.ExpandedGroups -and $baselineData.ExpandedGroups.Count -gt 0) {
                foreach ($group in $baselineData.ExpandedGroups) {
                    $script:BaselineExpandedGroups[$group.GroupId] = @{
                        GroupId = $group.GroupId
                        GroupName = $group.GroupName
                        MemberCount = $group.MemberCount
                        Members = $group.Members
                    }
                }
                Write-Host "[+] Loaded $($script:BaselineExpandedGroups.Count) expanded groups" -ForegroundColor Green
                
                # Show group summary
                Write-Host "[*] Groups in baseline:" -ForegroundColor Cyan
                foreach ($g in $baselineData.ExpandedGroups) {
                    Write-Host "    - $($g.GroupName): $($g.MemberCount) member(s)" -ForegroundColor Gray
                }
            }
        }
        else {
            $script:BaselineHasExpandedGroups = $false
            Write-Host "[*] Baseline does not include expanded group memberships" -ForegroundColor Yellow
            Write-Host "[*] To track group membership changes, re-export with -ExpandGroupMembers" -ForegroundColor Yellow
        }
        
        # Display baseline summary if available (v2.0+ format)
        if ($baselineData.ExportVersion -match "^2\." -and $baselineData.Summary) {
            Write-Host "[+] Baseline version: $($baselineData.ExportVersion)" -ForegroundColor Green
            Write-Host "[+] Tenants in baseline: $($baselineData.Summary.TotalTenants)" -ForegroundColor Green
            Write-Host "[+] Subscriptions in baseline: $($baselineData.Summary.TotalSubscriptions)" -ForegroundColor Green
            
            # Show tenant details
            if ($baselineData.Tenants -and $baselineData.Tenants.Count -gt 0) {
                Write-Host "[*] Baseline tenants:" -ForegroundColor Cyan
                foreach ($t in $baselineData.Tenants) {
                    Write-Host "    - $($t.TenantName) ($($t.TenantId))" -ForegroundColor Gray
                }
            }
            
            # Show subscription details
            if ($baselineData.Subscriptions -and $baselineData.Subscriptions.Count -gt 0) {
                Write-Host "[*] Baseline subscriptions:" -ForegroundColor Cyan
                foreach ($s in $baselineData.Subscriptions) {
                    Write-Host "    - $($s.SubscriptionName) ($($s.SubscriptionId)) - $($s.RoleAssignmentCount) assignments" -ForegroundColor Gray
                }
            }
        }
        else {
            # Legacy format (v1.0)
            Write-Host "[*] Baseline format: Legacy (v1.0)" -ForegroundColor Yellow
            if ($baselineData.TotalTenants) {
                Write-Host "[+] Tenants in baseline: $($baselineData.TotalTenants)" -ForegroundColor Green
            }
            if ($baselineData.TotalSubscriptions) {
                Write-Host "[+] Subscriptions in baseline: $($baselineData.TotalSubscriptions)" -ForegroundColor Green
            }
        }
        
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to load baseline: $_" -ForegroundColor Red
        return $false
    }
}

function Invoke-DriftDetection {
    Write-Host "`n[*] Starting drift detection..." -ForegroundColor Cyan
    Write-Host "[*] Comparing current Azure RBAC state against baseline..." -ForegroundColor Cyan
    
    # Determine which tenants to process
    $tenantsToProcess = @()
    if ($TenantId) {
        Write-Host "[*] Using specified tenant: $TenantId" -ForegroundColor Cyan
        $tenantsToProcess += @{ Id = $TenantId; Name = $TenantId }
    }
    else {
        Write-Host "[*] Scanning all accessible tenants..." -ForegroundColor Cyan
        $allTenants = Get-AzureTenants
        if ($allTenants.Count -eq 0) {
            Write-Host "[!] No tenants found" -ForegroundColor Yellow
            return
        }
        $tenantsToProcess = $allTenants
    }
    
    $currentAssignments = @()
    $tenantCounter = 0
    $totalSubscriptionsScanned = 0
    $processedTenantsForDrift = @()
    $processedSubscriptionsForDrift = @()
    
    foreach ($tenant in $tenantsToProcess) {
        $tenantCounter++
        Write-Host "`n" + ("=" * 80) -ForegroundColor Magenta
        Write-Host "[*] Processing Tenant $tenantCounter/$($tenantsToProcess.Count): $($tenant.Name) ($($tenant.Id))" -ForegroundColor Magenta
        Write-Host ("=" * 80) -ForegroundColor Magenta
        
        try {
            # Switch to the tenant context with proper authentication handling
            Invoke-StealthDelay
            
            $tenantSwitch = Switch-ToTenant -TargetTenantId $tenant.Id -TenantName $tenant.Name
            
            if (-not $tenantSwitch.Success) {
                if ($SkipFailedTenants) {
                    Write-Host "[!] Skipping tenant due to error: $($tenantSwitch.Error)" -ForegroundColor Yellow
                    continue
                }
                throw $tenantSwitch.Error
            }
            
            # Track processed tenant
            $processedTenantsForDrift += @{ Id = $tenant.Id; Name = $tenant.Name }
            
            $subscriptions = Get-AzureSubscriptions -ForTenantId $tenant.Id
            
            if ($subscriptions.Count -eq 0) {
                Write-Host "[*] No Azure subscriptions accessible in tenant $($tenant.Name)" -ForegroundColor Gray
                Write-Host "    (This is normal if you're a guest user without Azure RBAC access)" -ForegroundColor DarkGray
                continue
            }
            
            $totalSubscriptionsScanned += $subscriptions.Count
            $progressCounter = 0
            
            foreach ($subscription in $subscriptions) {
                $progressCounter++
                Write-Host "`n[*] Processing subscription $progressCounter/$($subscriptions.Count): $($subscription.Name)" -ForegroundColor Cyan
                Write-Host "    Subscription ID: $($subscription.Id)" -ForegroundColor Gray
                
                try {
                    Invoke-StealthDelay
                    
                    # Use the subscription's actual TenantId if available, otherwise use the loop's tenant
                    $subscriptionTenantId = if ($subscription.TenantId) { $subscription.TenantId } else { $tenant.Id }
                    
                    # If the subscription belongs to a different tenant, skip it (it will be processed when we iterate to that tenant)
                    if ($subscriptionTenantId -ne $tenant.Id) {
                        Write-Host "[*] Subscription belongs to different tenant ($subscriptionTenantId), skipping..." -ForegroundColor Gray
                        continue
                    }
                    
                    # Switch to subscription with validation
                    $subSwitch = Switch-ToSubscription -TargetSubscriptionId $subscription.Id -TargetTenantId $subscriptionTenantId -SubscriptionName $subscription.Name
                    
                    if (-not $subSwitch.Success) {
                        if ($subSwitch.ErrorType -eq "NotFound") {
                            Write-Host "[!] Subscription not accessible: $($subscription.Name)" -ForegroundColor Yellow
                        }
                        elseif ($subSwitch.ErrorType -eq "AuthRequired") {
                            Write-Host "[!] Subscription requires re-authentication: $($subscription.Name)" -ForegroundColor Yellow
                        }
                        elseif ($subSwitch.ErrorType -eq "AccessDenied") {
                            Write-Host "[!] Access denied to subscription: $($subscription.Name)" -ForegroundColor Yellow
                        }
                        else {
                            Write-Host "[!] Failed to switch to subscription: $($subSwitch.Error)" -ForegroundColor Yellow
                        }
                        continue
                    }
                    
                    # Test if we have read access to role assignments
                    $accessTest = Test-SubscriptionReadAccess -SubscriptionName $subscription.Name
                    if (-not $accessTest.HasAccess) {
                        Write-Host "[!] Cannot read role assignments in $($subscription.Name)" -ForegroundColor Yellow
                        if ($accessTest.Suggestion) {
                            Write-Host "    Suggestion: $($accessTest.Suggestion)" -ForegroundColor Gray
                        }
                        continue
                    }
                    
                    Invoke-StealthDelay
                    
                    # Get ALL role assignments at ALL scopes (subscription, resource group, resource)
                    $assignments = Get-AzRoleAssignment -IncludeClassicAdministrators:$false -ErrorAction Stop
                    if (-not $IncludeInherited) {
                        $assignments = $assignments | Where-Object { $_.Scope -notmatch '/providers/Microsoft.Management/managementGroups/' }
                    }
                    
                    $excludedPIMCountThisSub = 0
                    
                    # Filter out PIM/JIT assignments if requested
                    if ($ExcludePIM) {
                        Write-Host "[*] Checking for PIM/JIT assignments to exclude..." -ForegroundColor Cyan
                        $subscriptionScope = "/subscriptions/$($subscription.Id)"
                        $pimAssignments = Get-PIMRoleAssignments -Scope $subscriptionScope
                        
                        if ($pimAssignments.Count -gt 0) {
                            # Store PIM assignments for reference
                            foreach ($key in $pimAssignments.Keys) {
                                $script:PIMAssignmentIds[$key] = $pimAssignments[$key]
                            }
                            
                            # Filter out PIM assignments
                            $filteredAssignments = @()
                            foreach ($assignment in $assignments) {
                                if (-not (Test-IsPIMAssignment -Assignment $assignment -PIMAssignments $pimAssignments)) {
                                    $filteredAssignments += $assignment
                                }
                                else {
                                    $excludedPIMCountThisSub++
                                    $script:ExcludedPIMCount++
                                }
                            }
                            $assignments = $filteredAssignments
                            
                            if ($excludedPIMCountThisSub -gt 0) {
                                Write-Host "[*] Excluded $excludedPIMCountThisSub PIM/JIT assignment(s)" -ForegroundColor Yellow
                            }
                        }
                    }
                    
                    Write-Host "[+] Found $($assignments.Count) current assignment(s) at all scopes$(if ($excludedPIMCountThisSub -gt 0) { " (after excluding $excludedPIMCountThisSub PIM)" })" -ForegroundColor Green
                    
                    # Track subscription
                    $processedSubscriptionsForDrift += @{
                        SubscriptionId = $subscription.Id
                        SubscriptionName = $subscription.Name
                        TenantId = $tenant.Id
                        AssignmentCount = $assignments.Count
                        ExcludedPIMCount = $excludedPIMCountThisSub
                    }
                    
                    foreach ($assignment in $assignments) {
                        $currentAssignments += [PSCustomObject]@{
                            AssignmentId = $assignment.RoleAssignmentId
                            AssignmentName = $assignment.RoleAssignmentName
                            TenantId = $tenant.Id
                            TenantName = $tenant.Name
                            SubscriptionId = $subscription.Id
                            SubscriptionName = $subscription.Name
                            Scope = $assignment.Scope
                            ScopeType = Get-ScopeType -Scope $assignment.Scope
                            RoleDefinitionName = $assignment.RoleDefinitionName
                            RoleDefinitionId = $assignment.RoleDefinitionId
                            PrincipalId = $assignment.ObjectId
                            PrincipalType = $assignment.ObjectType
                            PrincipalDisplayName = $assignment.DisplayName
                            PrincipalSignInName = $assignment.SignInName
                            Condition = $assignment.Condition
                            ConditionVersion = $assignment.ConditionVersion
                            CreatedOn = $assignment.CreatedOn
                            UpdatedOn = $assignment.UpdatedOn
                        }
                    }
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    
                    # Handle errors during role assignment retrieval
                    if ($errorMsg -match 'AuthorizationFailed|does not have authorization|permission|forbidden') {
                        Write-Host "[!] Insufficient permissions to read role assignments in $($subscription.Name)" -ForegroundColor Yellow
                        Write-Host "    Required permission: Microsoft.Authorization/roleAssignments/read" -ForegroundColor Gray
                        Write-Host "    Request 'Reader' role on this subscription to fix this" -ForegroundColor Gray
                    }
                    elseif ($errorMsg -match 'throttl|rate limit|too many requests|429') {
                        Write-Host "[!] Rate limited on $($subscription.Name) - consider using -EnableStealth" -ForegroundColor Yellow
                    }
                    else {
                        Write-Host "[!] Error processing subscription $($subscription.Name): $errorMsg" -ForegroundColor Yellow
                    }
                    # Always continue to next subscription on error
                    continue
                }
            }
        }
        catch {
            Write-Host "[!] Error processing tenant $($tenant.Name): $_" -ForegroundColor Yellow
            if ($SkipFailedTenants) { continue }
        }
    }
    
    # Summary of what was scanned
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "[*] Current State Scan Complete" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "[+] Tenants scanned: $($processedTenantsForDrift.Count)" -ForegroundColor Green
    Write-Host "[+] Subscriptions scanned: $totalSubscriptionsScanned" -ForegroundColor Green
    Write-Host "[+] Current role assignments found: $($currentAssignments.Count)" -ForegroundColor Green
    if ($ExcludePIM -and $script:ExcludedPIMCount -gt 0) {
        Write-Host "[*] PIM/JIT assignments excluded: $($script:ExcludedPIMCount)" -ForegroundColor Yellow
    }
    
    # Store for export
    $script:DriftScanInfo = @{
        TenantsScanned = $processedTenantsForDrift
        SubscriptionsScanned = $processedSubscriptionsForDrift
        TotalCurrentAssignments = $currentAssignments.Count
        ExcludePIM = $ExcludePIM.IsPresent
        ExcludedPIMAssignments = $script:ExcludedPIMCount
        ScanTimestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    }
    Write-Host "`n[*] Analyzing drift..." -ForegroundColor Cyan
    Write-Host "[*] Current: $($currentAssignments.Count) | Baseline: $($script:BaselineAssignments.Count)" -ForegroundColor Cyan
    $baselineHash = @{}
    foreach ($b in $script:BaselineAssignments) { $baselineHash[$b.AssignmentId] = $b }
    $currentHash = @{}
    foreach ($c in $currentAssignments) { $currentHash[$c.AssignmentId] = $c }
    
    # Find new assignments
    Write-Host "[*] Checking for new assignments..." -ForegroundColor Cyan
    foreach ($current in $currentAssignments) {
        if (-not $baselineHash.ContainsKey($current.AssignmentId)) {
            $risk = if ($current.RoleDefinitionName -match "Owner|Contributor|Administrator") { "CRITICAL" } else { "HIGH" }
            $driftItem = [PSCustomObject]@{
                DriftType = "NEW_ASSIGNMENT"
                RiskLevel = $risk
                TenantName = $current.TenantName
                TenantId = $current.TenantId
                SubscriptionName = $current.SubscriptionName
                Scope = $current.Scope
                ScopeType = $current.ScopeType
                RoleName = $current.RoleDefinitionName
                PrincipalId = $current.PrincipalId
                PrincipalType = $current.PrincipalType
                PrincipalDisplayName = $current.PrincipalDisplayName
                PrincipalSignInName = $current.PrincipalSignInName
                AssignmentId = $current.AssignmentId
                Issue = "New role assignment detected - not in baseline"
                Recommendation = "Review and verify this assignment was authorized"
                Remediation = $null
            }
            $driftItem.Remediation = Get-RemediationInstructions -DriftItem $driftItem -DriftType "NEW_ASSIGNMENT"
            $script:DriftResults.NewAssignments += $driftItem
        }
    }
    
    # Find removed assignments
    Write-Host "[*] Checking for removed assignments..." -ForegroundColor Cyan
    foreach ($baseline in $script:BaselineAssignments) {
        if (-not $currentHash.ContainsKey($baseline.AssignmentId)) {
            $risk = if ($baseline.RoleDefinitionName -match "Owner|Contributor|Administrator") { "HIGH" } else { "MEDIUM" }
            $driftItem = [PSCustomObject]@{
                DriftType = "REMOVED_ASSIGNMENT"
                RiskLevel = $risk
                TenantName = $baseline.TenantName
                TenantId = $baseline.TenantId
                SubscriptionName = $baseline.SubscriptionName
                Scope = $baseline.Scope
                ScopeType = $baseline.ScopeType
                RoleName = $baseline.RoleDefinitionName
                PrincipalId = $baseline.PrincipalId
                PrincipalType = $baseline.PrincipalType
                PrincipalDisplayName = $baseline.PrincipalDisplayName
                PrincipalSignInName = $baseline.PrincipalSignInName
                AssignmentId = $baseline.AssignmentId
                Issue = "Role assignment removed since baseline"
                Recommendation = "Verify this removal was authorized"
                Remediation = $null
            }
            $driftItem.Remediation = Get-RemediationInstructions -DriftItem $driftItem -DriftType "REMOVED_ASSIGNMENT"
            $script:DriftResults.RemovedAssignments += $driftItem
        }
    }
    
    # Find modified assignments
    Write-Host "[*] Checking for modified assignments..." -ForegroundColor Cyan
    foreach ($current in $currentAssignments) {
        if ($baselineHash.ContainsKey($current.AssignmentId)) {
            $baseline = $baselineHash[$current.AssignmentId]
            $changes = @()
            if ($current.Scope -ne $baseline.Scope) { $changes += "Scope changed" }
            if ($current.RoleDefinitionName -ne $baseline.RoleDefinitionName) { $changes += "Role changed" }
            if ($current.PrincipalId -ne $baseline.PrincipalId) { $changes += "Principal changed" }
            if ($changes.Count -gt 0) {
                $risk = if ($current.RoleDefinitionName -match "Owner|Contributor|Administrator") { "CRITICAL" } else { "HIGH" }
                $driftItem = [PSCustomObject]@{
                    DriftType = "MODIFIED_ASSIGNMENT"
                    RiskLevel = $risk
                    TenantName = $current.TenantName
                    TenantId = $current.TenantId
                    SubscriptionName = $current.SubscriptionName
                    Scope = $current.Scope
                    ScopeType = $current.ScopeType
                    RoleName = $current.RoleDefinitionName
                    PrincipalId = $current.PrincipalId
                    PrincipalType = $current.PrincipalType
                    PrincipalDisplayName = $current.PrincipalDisplayName
                    PrincipalSignInName = $current.PrincipalSignInName
                    AssignmentId = $current.AssignmentId
                    Changes = ($changes -join "; ")
                    Issue = "Role assignment modified since baseline"
                    Recommendation = "Review these changes"
                    Remediation = $null
                }
                $driftItem.Remediation = Get-RemediationInstructions -DriftItem $driftItem -DriftType "MODIFIED_ASSIGNMENT"
                $script:DriftResults.ModifiedAssignments += $driftItem
            }
        }
    }
    
    # Find ABAC condition mismatches (separate from other modifications)
    Write-Host "[*] Checking for ABAC condition mismatches..." -ForegroundColor Cyan
    foreach ($current in $currentAssignments) {
        if ($baselineHash.ContainsKey($current.AssignmentId)) {
            $baseline = $baselineHash[$current.AssignmentId]
            
            # Normalize null/empty conditions for comparison
            $currentCondition = if ([string]::IsNullOrWhiteSpace($current.Condition)) { $null } else { $current.Condition.Trim() }
            $baselineCondition = if ([string]::IsNullOrWhiteSpace($baseline.Condition)) { $null } else { $baseline.Condition.Trim() }
            $currentConditionVersion = if ([string]::IsNullOrWhiteSpace($current.ConditionVersion)) { $null } else { $current.ConditionVersion }
            $baselineConditionVersion = if ([string]::IsNullOrWhiteSpace($baseline.ConditionVersion)) { $null } else { $baseline.ConditionVersion }
            
            # Check for condition mismatch
            $conditionChanged = $currentCondition -ne $baselineCondition
            $versionChanged = $currentConditionVersion -ne $baselineConditionVersion
            
            if ($conditionChanged -or $versionChanged) {
                # Determine change type for issue description
                $changeDescription = if ($baselineCondition -and -not $currentCondition) {
                    "ABAC condition removed"
                } elseif (-not $baselineCondition -and $currentCondition) {
                    "ABAC condition added"
                } elseif ($conditionChanged) {
                    "ABAC condition modified"
                } else {
                    "ABAC condition version changed"
                }
                
                # ABAC condition changes are high risk as they can grant broader access
                $risk = if ($current.RoleDefinitionName -match "Owner|Contributor|Administrator") { "CRITICAL" } else { "HIGH" }
                
                $driftItem = [PSCustomObject]@{
                    DriftType = "CONDITION_MISMATCH"
                    RiskLevel = $risk
                    TenantName = $current.TenantName
                    TenantId = $current.TenantId
                    SubscriptionName = $current.SubscriptionName
                    Scope = $current.Scope
                    ScopeType = $current.ScopeType
                    RoleName = $current.RoleDefinitionName
                    PrincipalId = $current.PrincipalId
                    PrincipalType = $current.PrincipalType
                    PrincipalDisplayName = $current.PrincipalDisplayName
                    PrincipalSignInName = $current.PrincipalSignInName
                    AssignmentId = $current.AssignmentId
                    ConditionBaseline = $baselineCondition
                    ConditionCurrent = $currentCondition
                    ConditionVersionBaseline = $baselineConditionVersion
                    ConditionVersionCurrent = $currentConditionVersion
                    Issue = $changeDescription
                    Recommendation = "Review ABAC condition change - removing or modifying conditions can grant broader access"
                    Remediation = $null
                }
                $driftItem.Remediation = Get-RemediationInstructions -DriftItem $driftItem -DriftType "CONDITION_MISMATCH"
                $script:DriftResults.ConditionMismatchAssignments += $driftItem
            }
        }
    }
    
    # Check for group membership drift if baseline has expanded groups
    if ($script:BaselineHasExpandedGroups -and $script:BaselineExpandedGroups.Count -gt 0) {
        Write-Host "`n[*] Checking for group membership changes..." -ForegroundColor Cyan
        Write-Host "[*] Baseline has $($script:BaselineExpandedGroups.Count) expanded group(s)" -ForegroundColor Gray
        
        # Get current group memberships
        $currentGroupAssignments = $currentAssignments | Where-Object { $_.PrincipalType -eq 'Group' }
        $uniqueCurrentGroups = $currentGroupAssignments | Select-Object -Property PrincipalId, PrincipalDisplayName -Unique
        
        Write-Host "[*] Current state has $($uniqueCurrentGroups.Count) group(s) with role assignments" -ForegroundColor Gray
        
        foreach ($group in $uniqueCurrentGroups) {
            $groupId = $group.PrincipalId
            $groupName = $group.PrincipalDisplayName
            
            # Get current members of this group
            Write-Host "  [*] Expanding current group: $groupName" -ForegroundColor Gray
            $currentMembers = Get-GroupMembersRecursive -GroupId $groupId -GroupDisplayName $groupName
            
            if ($script:BaselineExpandedGroups.ContainsKey($groupId)) {
                # Group exists in baseline - compare memberships
                $baselineMembers = $script:BaselineExpandedGroups[$groupId].Members
                
                # Create hash sets for comparison
                $baselineMemberIds = @{}
                foreach ($m in $baselineMembers) { $baselineMemberIds[$m.PrincipalId] = $m }
                
                $currentMemberIds = @{}
                foreach ($m in $currentMembers) { $currentMemberIds[$m.PrincipalId] = $m }
                
                # Find new members (in current but not in baseline)
                foreach ($member in $currentMembers) {
                    if (-not $baselineMemberIds.ContainsKey($member.PrincipalId)) {
                        # Get the roles this group has to determine risk
                        $groupRoles = $currentGroupAssignments | Where-Object { $_.PrincipalId -eq $groupId }
                        $hasHighPrivRole = $groupRoles | Where-Object { $_.RoleDefinitionName -match "Owner|Contributor|Administrator" }
                        $risk = if ($hasHighPrivRole) { "CRITICAL" } else { "HIGH" }
                        $roleNames = ($groupRoles | Select-Object -ExpandProperty RoleDefinitionName -Unique) -join ", "
                        
                        $driftItem = [PSCustomObject]@{
                            DriftType = "NEW_GROUP_MEMBER"
                            RiskLevel = $risk
                            GroupName = $groupName
                            GroupId = $groupId
                            GroupRoles = $roleNames
                            PrincipalId = $member.PrincipalId
                            PrincipalType = $member.PrincipalType
                            PrincipalDisplayName = $member.PrincipalDisplayName
                            PrincipalSignInName = $member.PrincipalSignInName
                            Issue = "New user added to group with Azure RBAC access"
                            Recommendation = "Verify this user was authorized to be added to this privileged group"
                            Remediation = $null
                        }
                        $driftItem.Remediation = Get-RemediationInstructions -DriftItem $driftItem -DriftType "NEW_GROUP_MEMBER"
                        $script:DriftResults.NewGroupMembers += $driftItem
                        Write-Host "    [!] NEW member in $groupName : $($member.PrincipalDisplayName)" -ForegroundColor Yellow
                    }
                }
                
                # Find removed members (in baseline but not in current)
                foreach ($member in $baselineMembers) {
                    if (-not $currentMemberIds.ContainsKey($member.PrincipalId)) {
                        $groupRoles = $currentGroupAssignments | Where-Object { $_.PrincipalId -eq $groupId }
                        $hasHighPrivRole = $groupRoles | Where-Object { $_.RoleDefinitionName -match "Owner|Contributor|Administrator" }
                        $risk = if ($hasHighPrivRole) { "HIGH" } else { "MEDIUM" }
                        $roleNames = ($groupRoles | Select-Object -ExpandProperty RoleDefinitionName -Unique) -join ", "
                        
                        $driftItem = [PSCustomObject]@{
                            DriftType = "REMOVED_GROUP_MEMBER"
                            RiskLevel = $risk
                            GroupName = $groupName
                            GroupId = $groupId
                            GroupRoles = $roleNames
                            PrincipalId = $member.PrincipalId
                            PrincipalType = $member.PrincipalType
                            PrincipalDisplayName = $member.PrincipalDisplayName
                            PrincipalSignInName = $member.PrincipalSignInName
                            Issue = "User removed from group with Azure RBAC access"
                            Recommendation = "Verify this removal was authorized"
                            Remediation = $null
                        }
                        $driftItem.Remediation = Get-RemediationInstructions -DriftItem $driftItem -DriftType "REMOVED_GROUP_MEMBER"
                        $script:DriftResults.RemovedGroupMembers += $driftItem
                        Write-Host "    [!] REMOVED member from $groupName : $($member.PrincipalDisplayName)" -ForegroundColor Yellow
                    }
                }
            }
            else {
                # Group is new (not in baseline) - all members are new
                Write-Host "    [*] Group $groupName is new (not in baseline)" -ForegroundColor Gray
            }
        }
        
        # Check for groups that were removed entirely
        foreach ($baselineGroupId in $script:BaselineExpandedGroups.Keys) {
            $stillExists = $uniqueCurrentGroups | Where-Object { $_.PrincipalId -eq $baselineGroupId }
            if (-not $stillExists) {
                $baselineGroup = $script:BaselineExpandedGroups[$baselineGroupId]
                Write-Host "  [!] Group removed from Azure RBAC: $($baselineGroup.GroupName)" -ForegroundColor Yellow
            }
        }
        
        Write-Host "[+] Group membership drift check complete" -ForegroundColor Green
        Write-Host "[*] New members: $($script:DriftResults.NewGroupMembers.Count) | Removed members: $($script:DriftResults.RemovedGroupMembers.Count)" -ForegroundColor $(if(($script:DriftResults.NewGroupMembers.Count + $script:DriftResults.RemovedGroupMembers.Count) -gt 0){"Yellow"}else{"Green"})
    }
    elseif ($script:BaselineExpandedGroups.Count -eq 0 -and $script:BaselineHasExpandedGroups) {
        Write-Host "`n[*] Baseline has no expanded groups - skipping group membership drift check" -ForegroundColor Gray
    }
    else {
        Write-Host "`n[*] Baseline was not exported with -ExpandGroupMembers - skipping group membership drift check" -ForegroundColor Gray
        Write-Host "[*] To track group membership changes, re-export baseline with -ExpandGroupMembers" -ForegroundColor Yellow
    }
    
    $total = $script:DriftResults.NewAssignments.Count + $script:DriftResults.RemovedAssignments.Count + $script:DriftResults.ModifiedAssignments.Count + $script:DriftResults.ConditionMismatchAssignments.Count + $script:DriftResults.NewGroupMembers.Count + $script:DriftResults.RemovedGroupMembers.Count
    $membershipDrift = $script:DriftResults.NewGroupMembers.Count + $script:DriftResults.RemovedGroupMembers.Count
    $conditionDrift = $script:DriftResults.ConditionMismatchAssignments.Count
    
    Write-Host "`n[+] Drift analysis complete!" -ForegroundColor Green
    Write-Host "[*] Direct Assignments - New: $($script:DriftResults.NewAssignments.Count) | Removed: $($script:DriftResults.RemovedAssignments.Count) | Modified: $($script:DriftResults.ModifiedAssignments.Count)" -ForegroundColor $(if(($script:DriftResults.NewAssignments.Count + $script:DriftResults.RemovedAssignments.Count + $script:DriftResults.ModifiedAssignments.Count) -gt 0){"Yellow"}else{"Green"})
    if ($conditionDrift -gt 0) {
        Write-Host "[*] ABAC Conditions - Mismatched: $conditionDrift" -ForegroundColor Yellow
    }
    if ($script:BaselineHasExpandedGroups) {
        Write-Host "[*] Group Membership - New members: $($script:DriftResults.NewGroupMembers.Count) | Removed members: $($script:DriftResults.RemovedGroupMembers.Count)" -ForegroundColor $(if($membershipDrift -gt 0){"Yellow"}else{"Green"})
    }
    Write-Host "[*] Total drift issues: $total" -ForegroundColor $(if($total -gt 0){"Red"}else{"Green"})
}

function Show-DriftMatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - DRIFT DETECTION RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    $allDrift = @()
    $allDrift += $script:DriftResults.NewAssignments
    $allDrift += $script:DriftResults.RemovedAssignments
    $allDrift += $script:DriftResults.ModifiedAssignments
    $allDrift += $script:DriftResults.ConditionMismatchAssignments
    $allDrift += $script:DriftResults.NewGroupMembers
    $allDrift += $script:DriftResults.RemovedGroupMembers

    if ($allDrift.Count -eq 0) {
        Write-Host "`n[+] No drift detected! Current state matches baseline." -ForegroundColor Green
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display with formatted columns
    $matrixData = $allDrift | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Type';Expression={$_.DriftType}},
        @{Name='Tenant';Expression={if($_.TenantName.Length -gt 20){$_.TenantName.Substring(0,17)+'...'}else{$_.TenantName}}},
        @{Name='Subscription';Expression={if($_.SubscriptionName.Length -gt 25){$_.SubscriptionName.Substring(0,22)+'...'}else{$_.SubscriptionName}}},
        @{Name='Role';Expression={$_.RoleName}},
        @{Name='Principal Type';Expression={$_.PrincipalType}},
        @{Name='Principal';Expression={if($_.PrincipalDisplayName.Length -gt 30){$_.PrincipalDisplayName.Substring(0,27)+'...'}else{$_.PrincipalDisplayName}}},
        @{Name='Scope Type';Expression={$_.ScopeType}},
        @{Name='Issue';Expression={$_.Issue}}
    
    # Display as formatted table with color coding
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
    Write-Host "Total drift issues: " -NoNewline -ForegroundColor White
    Write-Host $allDrift.Count -ForegroundColor Red
    
    $criticalCount = ($allDrift | Where-Object { $_.RiskLevel -eq 'CRITICAL' }).Count
    $highCount = ($allDrift | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
    $mediumCount = ($allDrift | Where-Object { $_.RiskLevel -eq 'MEDIUM' }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalCount -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highCount -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumCount -ForegroundColor Green
    
    # Drift type breakdown
    Write-Host "`n[DRIFT TYPES]" -ForegroundColor Cyan
    Write-Host "  New assignments: " -NoNewline -ForegroundColor White
    Write-Host $script:DriftResults.NewAssignments.Count -ForegroundColor Yellow
    Write-Host "  Removed assignments: " -NoNewline -ForegroundColor White
    Write-Host $script:DriftResults.RemovedAssignments.Count -ForegroundColor Yellow
    Write-Host "  Modified assignments: " -NoNewline -ForegroundColor White
    Write-Host $script:DriftResults.ModifiedAssignments.Count -ForegroundColor Yellow
    Write-Host "  Condition mismatches: " -NoNewline -ForegroundColor White
    Write-Host $script:DriftResults.ConditionMismatchAssignments.Count -ForegroundColor Yellow
    if ($script:DriftResults.NewGroupMembers.Count -gt 0 -or $script:DriftResults.RemovedGroupMembers.Count -gt 0) {
        Write-Host "  New group members: " -NoNewline -ForegroundColor White
        Write-Host $script:DriftResults.NewGroupMembers.Count -ForegroundColor Yellow
        Write-Host "  Removed group members: " -NoNewline -ForegroundColor White
        Write-Host $script:DriftResults.RemovedGroupMembers.Count -ForegroundColor Yellow
    }
    
    # Group by subscription
    $bySubscription = $allDrift | Group-Object SubscriptionName | Sort-Object Count -Descending
    if ($bySubscription.Count -gt 0) {
        Write-Host "`n[DRIFT BY SUBSCRIPTION]" -ForegroundColor Cyan
        $bySubscription | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Group by role
    $byRole = $allDrift | Group-Object RoleName | Sort-Object Count -Descending
    if ($byRole.Count -gt 0) {
        Write-Host "`n[DRIFT BY ROLE]" -ForegroundColor Cyan
        $byRole | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Group by principal type
    $byPrincipalType = $allDrift | Group-Object PrincipalType | Sort-Object Count -Descending
    if ($byPrincipalType.Count -gt 0) {
        Write-Host "`n[DRIFT BY PRINCIPAL TYPE]" -ForegroundColor Cyan
        $byPrincipalType | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
}

function Show-DriftResults {
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "SCAN RESULTS - DRIFT DETECTION" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    
    $allDrift = @()
    $allDrift += $script:DriftResults.NewAssignments
    $allDrift += $script:DriftResults.RemovedAssignments
    $allDrift += $script:DriftResults.ModifiedAssignments
    $allDrift += $script:DriftResults.ConditionMismatchAssignments
    $allDrift += $script:DriftResults.NewGroupMembers
    $allDrift += $script:DriftResults.RemovedGroupMembers

    if ($allDrift.Count -eq 0) {
        Write-Host "`n[+] No drift detected! Current state matches baseline." -ForegroundColor Green
        Write-Host ("=" * 80) -ForegroundColor Cyan
        return
    }
    
    Write-Host "`nTotal drift issues: $($allDrift.Count)" -ForegroundColor Red
    Write-Host "  New: $($script:DriftResults.NewAssignments.Count)" -ForegroundColor Yellow
    Write-Host "  Removed: $($script:DriftResults.RemovedAssignments.Count)" -ForegroundColor Yellow
    Write-Host "  Modified: $($script:DriftResults.ModifiedAssignments.Count)" -ForegroundColor Yellow
    Write-Host "  Condition Mismatch: $($script:DriftResults.ConditionMismatchAssignments.Count)" -ForegroundColor Yellow
    
    Write-Host "`n" + ("-" * 80) -ForegroundColor Cyan
    
    foreach ($drift in $allDrift) {
        $color = switch ($drift.RiskLevel) { "CRITICAL" { "Red" } "HIGH" { "Yellow" } default { "Green" } }
        Write-Host "`n[$($drift.RiskLevel)] $($drift.DriftType)" -ForegroundColor $color
        Write-Host "  Tenant: $($drift.TenantName) ($($drift.TenantId))" -ForegroundColor Gray
        Write-Host "  Subscription: $($drift.SubscriptionName)" -ForegroundColor Gray
        Write-Host "  Role: $($drift.RoleName)" -ForegroundColor Gray
        Write-Host "  Principal: $($drift.PrincipalDisplayName) ($($drift.PrincipalType))" -ForegroundColor Gray
        if ($drift.PrincipalSignInName) {
            Write-Host "  Sign-in Name: $($drift.PrincipalSignInName)" -ForegroundColor Gray
        }
        Write-Host "  Scope: $($drift.ScopeType)" -ForegroundColor Gray
        Write-Host "  Issue: $($drift.Issue)" -ForegroundColor $color
        
        # Show condition details for CONDITION_MISMATCH
        if ($drift.DriftType -eq "CONDITION_MISMATCH") {
            Write-Host "  Condition (Baseline): $(if ($drift.ConditionBaseline) { $drift.ConditionBaseline.Substring(0, [Math]::Min(80, $drift.ConditionBaseline.Length)) + '...' } else { '[none]' })" -ForegroundColor Gray
            Write-Host "  Condition (Current): $(if ($drift.ConditionCurrent) { $drift.ConditionCurrent.Substring(0, [Math]::Min(80, $drift.ConditionCurrent.Length)) + '...' } else { '[none]' })" -ForegroundColor Gray
        }
        
        Write-Host "  Recommendation: $($drift.Recommendation)" -ForegroundColor Cyan
    }
    
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
}

# Display role assignments in matrix format (for Export mode with -Matrix)
function Show-ExportMatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "MATRIX VIEW - AZURE RBAC ROLE ASSIGNMENTS" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:RoleAssignments.Count -eq 0) {
        Write-Host "`n[!] No role assignments found." -ForegroundColor Yellow
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Determine risk level for each assignment
    $assignmentsWithRisk = $script:RoleAssignments | ForEach-Object {
        $risk = if ($_.RoleDefinitionName -match "Owner|User Access Administrator") { "CRITICAL" }
                elseif ($_.RoleDefinitionName -match "Contributor|Administrator") { "HIGH" }
                elseif ($_.RoleDefinitionName -match "Write|Delete|Modify") { "MEDIUM" }
                else { "LOW" }
        $_ | Add-Member -NotePropertyName 'RiskLevel' -NotePropertyValue $risk -PassThru
    }
    
    # Create matrix display with formatted columns
    $matrixData = $assignmentsWithRisk | Select-Object `
        @{Name='Risk';Expression={$_.RiskLevel}},
        @{Name='Role';Expression={$_.RoleDefinitionName}},
        @{Name='Principal Type';Expression={$_.PrincipalType}},
        @{Name='Principal';Expression={if($_.PrincipalDisplayName.Length -gt 30){$_.PrincipalDisplayName.Substring(0,27)+'...'}else{$_.PrincipalDisplayName}}},
        @{Name='Subscription';Expression={if($_.SubscriptionName.Length -gt 25){$_.SubscriptionName.Substring(0,22)+'...'}else{$_.SubscriptionName}}},
        @{Name='Scope Type';Expression={$_.ScopeType}},
        @{Name='Tenant';Expression={if($_.TenantName.Length -gt 20){$_.TenantName.Substring(0,17)+'...'}else{$_.TenantName}}}
    
    # Display as formatted table with color coding
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
                Write-Host $line -ForegroundColor Green
            }
            elseif ($line -match '^\s*LOW\s+') {
                Write-Host $line -ForegroundColor Gray
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
    Write-Host "Total role assignments: " -NoNewline -ForegroundColor White
    Write-Host $script:RoleAssignments.Count -ForegroundColor Yellow
    
    $uniquePrincipals = ($script:RoleAssignments | Select-Object -Unique PrincipalId).Count
    Write-Host "Unique principals: " -NoNewline -ForegroundColor White
    Write-Host $uniquePrincipals -ForegroundColor Yellow
    
    $criticalCount = ($assignmentsWithRisk | Where-Object { $_.RiskLevel -eq 'CRITICAL' }).Count
    $highCount = ($assignmentsWithRisk | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
    $mediumCount = ($assignmentsWithRisk | Where-Object { $_.RiskLevel -eq 'MEDIUM' }).Count
    $lowCount = ($assignmentsWithRisk | Where-Object { $_.RiskLevel -eq 'LOW' }).Count
    
    Write-Host "  - CRITICAL risk: " -NoNewline -ForegroundColor White
    Write-Host $criticalCount -ForegroundColor Red
    Write-Host "  - HIGH risk: " -NoNewline -ForegroundColor White
    Write-Host $highCount -ForegroundColor Yellow
    Write-Host "  - MEDIUM risk: " -NoNewline -ForegroundColor White
    Write-Host $mediumCount -ForegroundColor Green
    Write-Host "  - LOW risk: " -NoNewline -ForegroundColor White
    Write-Host $lowCount -ForegroundColor Gray
    
    # Principal type breakdown
    $userCount = ($script:RoleAssignments | Where-Object { $_.PrincipalType -eq 'User' }).Count
    $groupCount = ($script:RoleAssignments | Where-Object { $_.PrincipalType -eq 'Group' }).Count
    $spCount = ($script:RoleAssignments | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' }).Count
    
    Write-Host "`n[PRINCIPAL TYPES]" -ForegroundColor Cyan
    Write-Host "  Users: " -NoNewline -ForegroundColor White
    Write-Host $userCount -ForegroundColor Cyan
    Write-Host "  Groups: " -NoNewline -ForegroundColor White
    Write-Host $groupCount -ForegroundColor Green
    Write-Host "  Service Principals: " -NoNewline -ForegroundColor White
    Write-Host $spCount -ForegroundColor Yellow
    
    # Scope breakdown
    $subScope = ($script:RoleAssignments | Where-Object { $_.ScopeType -eq 'Subscription' }).Count
    $rgScope = ($script:RoleAssignments | Where-Object { $_.ScopeType -eq 'ResourceGroup' }).Count
    $resScope = ($script:RoleAssignments | Where-Object { $_.ScopeType -eq 'Resource' }).Count
    
    Write-Host "`n[SCOPE LEVELS]" -ForegroundColor Cyan
    Write-Host "  Subscription level: " -NoNewline -ForegroundColor White
    Write-Host $subScope -ForegroundColor Yellow
    Write-Host "  Resource Group level: " -NoNewline -ForegroundColor White
    Write-Host $rgScope -ForegroundColor Yellow
    Write-Host "  Resource level: " -NoNewline -ForegroundColor White
    Write-Host $resScope -ForegroundColor Yellow
    
    # Top roles
    $byRole = $script:RoleAssignments | Group-Object RoleDefinitionName | Sort-Object Count -Descending
    if ($byRole.Count -gt 0) {
        Write-Host "`n[TOP ROLES]" -ForegroundColor Cyan
        $byRole | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # Subscriptions
    $bySubscription = $script:RoleAssignments | Group-Object SubscriptionName | Sort-Object Count -Descending
    if ($bySubscription.Count -gt 0) {
        Write-Host "`n[ASSIGNMENTS BY SUBSCRIPTION]" -ForegroundColor Cyan
        $bySubscription | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): " -NoNewline -ForegroundColor White
            Write-Host $_.Count -ForegroundColor Yellow
        }
    }
    
    # High-privilege warnings
    $owners = $script:RoleAssignments | Where-Object { $_.RoleDefinitionName -eq 'Owner' }
    $uaaAdmins = $script:RoleAssignments | Where-Object { $_.RoleDefinitionName -eq 'User Access Administrator' }
    
    if ($owners.Count -gt 0 -or $uaaAdmins.Count -gt 0) {
        Write-Host "`n[!] HIGH-PRIVILEGE WARNINGS" -ForegroundColor Red
        if ($owners.Count -gt 0) {
            Write-Host "  Owner role assignments: $($owners.Count)" -ForegroundColor Red
        }
        if ($uaaAdmins.Count -gt 0) {
            Write-Host "  User Access Administrator assignments: $($uaaAdmins.Count)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
}

function Export-DriftResults {
    param([string]$Path)
    if (-not $Path) { $Path = "azure-rbac-drift-report.json" }
    $allDrift = @()
    $allDrift += $script:DriftResults.NewAssignments
    $allDrift += $script:DriftResults.RemovedAssignments
    $allDrift += $script:DriftResults.ModifiedAssignments
    $allDrift += $script:DriftResults.ConditionMismatchAssignments
    $allDrift += $script:DriftResults.NewGroupMembers
    $allDrift += $script:DriftResults.RemovedGroupMembers

    # Always export the drift report (even if no drift detected - to confirm the check was run)
    try {
        $driftReport = @{
            ReportDate = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            ReportVersion = "2.3"
            BaselineFile = $BaselinePath
            DriftDetected = ($allDrift.Count -gt 0)
            Summary = @{
                TotalDriftIssues = $allDrift.Count
                NewAssignments = $script:DriftResults.NewAssignments.Count
                RemovedAssignments = $script:DriftResults.RemovedAssignments.Count
                ModifiedAssignments = $script:DriftResults.ModifiedAssignments.Count
                ConditionMismatchAssignments = $script:DriftResults.ConditionMismatchAssignments.Count
                NewGroupMembers = $script:DriftResults.NewGroupMembers.Count
                RemovedGroupMembers = $script:DriftResults.RemovedGroupMembers.Count
                CriticalIssues = ($allDrift | Where-Object { $_.RiskLevel -eq 'CRITICAL' }).Count
                HighIssues = ($allDrift | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
                MediumIssues = ($allDrift | Where-Object { $_.RiskLevel -eq 'MEDIUM' }).Count
                BaselineHadExpandedGroups = $script:BaselineHasExpandedGroups
                ExcludePIM = $ExcludePIM.IsPresent
                ExcludedPIMAssignments = $script:ExcludedPIMCount
            }
            ScanInfo = $script:DriftScanInfo
            BaselineInfo = @{
                TotalBaselineAssignments = $script:BaselineAssignments.Count
                TotalBaselineExpandedAssignments = $script:BaselineExpandedAssignments.Count
                TotalBaselineExpandedGroups = $script:BaselineExpandedGroups.Count
            }
            DirectAssignmentDrift = @{
                NewAssignments = $script:DriftResults.NewAssignments
                RemovedAssignments = $script:DriftResults.RemovedAssignments
                ModifiedAssignments = $script:DriftResults.ModifiedAssignments
            }
            ConditionDrift = @{
                ConditionMismatchAssignments = $script:DriftResults.ConditionMismatchAssignments
            }
            GroupMembershipDrift = @{
                NewMembers = $script:DriftResults.NewGroupMembers
                RemovedMembers = $script:DriftResults.RemovedGroupMembers
            }
        }
        
        $driftReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
        Write-Host "`n[+] Drift report exported to: $Path" -ForegroundColor Green
        Write-Host "[*] Total size: $([math]::Round((Get-Item $Path).Length / 1KB, 2)) KB" -ForegroundColor Cyan
        
        if ($allDrift.Count -eq 0) {
            Write-Host "[+] No drift detected - current state matches baseline!" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Drift detected - $($allDrift.Count) issue(s) found. Review the report." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "`n[ERROR] Failed to export: $_" -ForegroundColor Red
    }
}

function Show-AllUsersPermissionsMatrix {
    <#
    .SYNOPSIS
        Displays a matrix view of all principals and their role assignments across subscriptions.
    #>
    Write-Host "`n" + ("=" * 120) -ForegroundColor Cyan
    Write-Host "ALL USERS/PRINCIPALS PERMISSIONS MATRIX" -ForegroundColor Cyan
    Write-Host ("=" * 120) -ForegroundColor Cyan
    
    if ($script:RoleAssignments.Count -eq 0) {
        Write-Host "`n[!] No role assignments found to display" -ForegroundColor Yellow
        return
    }
    
    # Group assignments by principal for a user-centric view
    $principalGroups = $script:RoleAssignments | Group-Object -Property PrincipalId
    
    Write-Host "`n[+] Found $($principalGroups.Count) unique principal(s) with role assignments" -ForegroundColor Green
    Write-Host ""
    
    # Sort by principal type and display name
    $sortedGroups = $principalGroups | Sort-Object { 
        $first = $_.Group | Select-Object -First 1
        "$($first.PrincipalType)-$($first.PrincipalDisplayName)"
    }
    
    foreach ($group in $sortedGroups) {
        $firstAssignment = $group.Group | Select-Object -First 1
        $principalType = $firstAssignment.PrincipalType
        $principalName = if ($firstAssignment.PrincipalDisplayName) { $firstAssignment.PrincipalDisplayName } else { "[Unknown]" }
        $principalSignIn = $firstAssignment.PrincipalSignInName
        $principalId = $firstAssignment.PrincipalId
        
        # Color code by principal type
        $typeColor = switch ($principalType) {
            "User" { "Cyan" }
            "Group" { "Green" }
            "ServicePrincipal" { "Yellow" }
            default { "White" }
        }
        
        Write-Host ("-" * 100) -ForegroundColor DarkGray
        Write-Host "[$principalType] " -ForegroundColor $typeColor -NoNewline
        Write-Host "$principalName" -ForegroundColor White -NoNewline
        if ($principalSignIn) {
            Write-Host " ($principalSignIn)" -ForegroundColor Gray -NoNewline
        }
        Write-Host ""
        Write-Host "  Principal ID: $principalId" -ForegroundColor DarkGray
        Write-Host ""
        
        # Group by subscription for this principal
        $subGroups = $group.Group | Group-Object -Property SubscriptionName
        
        foreach ($subGroup in $subGroups) {
            $subName = $subGroup.Name
            Write-Host "  Subscription: $subName" -ForegroundColor Gray
            
            # List roles for this subscription
            foreach ($assignment in $subGroup.Group) {
                $roleName = $assignment.RoleDefinitionName
                $scope = $assignment.Scope
                $scopeType = $assignment.ScopeType
                
                # Color high-privilege roles
                $roleColor = if ($roleName -match "Owner|User Access Administrator|Contributor") { "Red" } 
                             elseif ($roleName -match "Administrator|Privileged") { "Yellow" }
                             else { "Green" }
                
                # Shorten scope for display
                $displayScope = switch ($scopeType) {
                    "Subscription" { "[Subscription]" }
                    "ResourceGroup" { 
                        if ($scope -match '/resourceGroups/([^/]+)') { "[RG: $($Matches[1])]" } else { "[ResourceGroup]" }
                    }
                    "Resource" {
                        if ($scope -match '/providers/[^/]+/([^/]+)/([^/]+)') { "[$($Matches[1]): $($Matches[2])]" } else { "[Resource]" }
                    }
                    default { "[$scopeType]" }
                }
                
                Write-Host "    - " -NoNewline
                Write-Host "$roleName" -ForegroundColor $roleColor -NoNewline
                Write-Host " $displayScope" -ForegroundColor DarkGray
            }
        }
        Write-Host ""
    }
    
    # Summary statistics
    Write-Host ("-" * 100) -ForegroundColor DarkGray
    Write-Host "`n[SUMMARY]" -ForegroundColor Cyan
    
    $userCount = ($script:RoleAssignments | Where-Object { $_.PrincipalType -eq 'User' } | Select-Object -Unique PrincipalId).Count
    $groupCount = ($script:RoleAssignments | Where-Object { $_.PrincipalType -eq 'Group' } | Select-Object -Unique PrincipalId).Count
    $spCount = ($script:RoleAssignments | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' } | Select-Object -Unique PrincipalId).Count
    
    Write-Host "  Total Principals: $($principalGroups.Count)" -ForegroundColor White
    Write-Host "    Users: $userCount" -ForegroundColor Cyan
    Write-Host "    Groups: $groupCount" -ForegroundColor Green
    Write-Host "    Service Principals: $spCount" -ForegroundColor Yellow
    Write-Host ""
    
    # High-privilege role summary
    $highPrivRoles = $script:RoleAssignments | Where-Object { 
        $_.RoleDefinitionName -match "Owner|User Access Administrator|Contributor" 
    }
    
    if ($highPrivRoles.Count -gt 0) {
        Write-Host "[!] HIGH-PRIVILEGE ROLE ASSIGNMENTS:" -ForegroundColor Red
        $highPrivRoles | Group-Object RoleDefinitionName | ForEach-Object {
            Write-Host "    $($_.Name): $($_.Count) assignment(s)" -ForegroundColor Red
        }
        Write-Host ""
        
        # List principals with Owner role
        $owners = $highPrivRoles | Where-Object { $_.RoleDefinitionName -eq 'Owner' }
        if ($owners.Count -gt 0) {
            Write-Host "[!] Principals with Owner role:" -ForegroundColor Red
            $owners | Select-Object -Unique PrincipalDisplayName, PrincipalType, SubscriptionName | ForEach-Object {
                Write-Host "    - $($_.PrincipalDisplayName) ($($_.PrincipalType)) on $($_.SubscriptionName)" -ForegroundColor Yellow
            }
        }
    }
}

function Invoke-Cleanup {
    Write-Host "`n[*] Cleaning up..." -ForegroundColor Cyan
    try {
        # Disconnect from Azure PowerShell
        if (Get-AzContext -ErrorAction SilentlyContinue) {
            Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[+] Disconnected from Azure PowerShell" -ForegroundColor Green
        }
        # Disconnect from Microsoft Graph
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

function Main {
    try {
        Show-Banner
        
        # Show required permissions info
        Show-RequiredPermissions
        
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
        
        # Authenticate to Microsoft Graph
        if (-not (Connect-GraphService)) {
            Write-Host "`n[ERROR] Authentication failed. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Connect to Azure Resource Manager
        if (-not (Connect-AzureService)) {
            Write-Host "`n[ERROR] Azure connection failed. Exiting." -ForegroundColor Red
            exit 1
        }
        
        if ($Mode -eq 'Export') {
            Write-Host "`n[*] Mode: Export role assignments to baseline JSON" -ForegroundColor Cyan
            if ($SkipFailedTenants) {
                Write-Host "[*] SkipFailedTenants: Enabled - will continue on authentication failures" -ForegroundColor Gray
            }
            Export-RoleAssignments

            # Show expanded group matrix if requested (expansion is now done during export)
            if ($ExpandGroupMembers) {
                # Group expansion is done during Export-RoleAssignments, just show the matrix
                Show-ExpandedGroupsMatrix
            }

            # Show results in matrix format if requested
            if ($Matrix) {
                Show-ExportMatrixResults
            }

            # Show all users permissions matrix if requested
            if ($ShowAllUsersPermissions) {
                Show-AllUsersPermissionsMatrix
            }

            Write-Host "`n[*] Export completed successfully!" -ForegroundColor Green
        }
        elseif ($Mode -eq 'DriftDetect') {
            Write-Host "`n[*] Mode: Drift detection against baseline JSON" -ForegroundColor Cyan
            if (-not $BaselinePath) {
                Write-Host "[ERROR] -BaselinePath is required for DriftDetect mode" -ForegroundColor Red
                exit 1
            }
            if (-not (Import-Baseline -Path $BaselinePath)) { exit 1 }
            Invoke-DriftDetection
            if ($Matrix) { Show-DriftMatrixResults } else { Show-DriftResults }
            Export-DriftResults -Path $ExportPath
            Write-Host "`n[*] Drift detection completed!" -ForegroundColor Green
        }
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
