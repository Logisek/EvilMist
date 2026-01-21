# Invoke-EntraManagedIdentityCheck.ps1

## Overview

`Invoke-EntraManagedIdentityCheck.ps1` is a PowerShell script that performs a comprehensive security audit of Azure Managed Identities. Managed identities are a critical attack vector as they provide automated credential management for Azure resources, often with overly permissive access.

## Purpose

This script analyzes managed identity configurations to identify security gaps and excessive permissions, including:

- **Identity inventory** - System-assigned vs user-assigned managed identities
- **Role assignment analysis** - Azure RBAC permissions for each identity
- **High-privilege detection** - Identities with Owner, Contributor, User Access Administrator
- **Cross-subscription access** - Identities with permissions beyond their home subscription
- **Unused identity detection** - Managed identities with no role assignments
- **Resource type coverage** - VMs, App Services, Function Apps, and more

## Attack Scenario Context

### Why Managed Identity Security Matters

Managed identity misconfigurations can lead to:
1. **Privilege escalation** - Attackers compromising a resource gain the identity's permissions
2. **Lateral movement** - Cross-subscription access enables pivot to other environments
3. **Credential-free persistence** - No passwords to rotate, access persists until identity is removed
4. **Data exfiltration** - Storage, Key Vault, database access via identity permissions
5. **Infrastructure control** - Owner/Contributor roles enable resource modification

### Red Team Value

- Identify VMs/App Services with high-privilege managed identities (compromise resource = gain identity)
- Find cross-subscription access paths for lateral movement
- Discover identities with Owner/User Access Administrator for privilege escalation
- Locate function apps with sensitive permissions (often less monitored)
- Map attack paths from compute resources to secrets/data

### Blue Team Value

- Audit managed identity permissions against least-privilege principle
- Identify overly permissive role assignments (subscription-wide Contributor, etc.)
- Detect unused identities that should be cleaned up
- Track cross-subscription access for security boundary enforcement
- Ensure critical roles are justified and documented
- Support compliance requirements for identity access management

## Prerequisites

- PowerShell 7.0 or later
- Azure PowerShell modules (automatically installed if missing):
  - Az.Accounts
  - Az.Resources
  - Az.ManagedServiceIdentity
  - Az.Compute
  - Az.Websites
  - Az.Functions
- Appropriate Azure RBAC permissions:
  - `Reader` role on subscription(s) for resource enumeration
  - `Microsoft.Authorization/roleAssignments/read` for role assignment analysis

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ExportPath` | String | None | Path to export results (CSV or JSON based on extension) |
| `-SubscriptionId` | String[] | None | Specific subscription ID(s) to scan. Scans all if not specified |
| `-TenantId` | String | None | Optional Tenant ID. Uses user's home tenant if not specified |
| `-UseAzCliToken` | Switch | False | Use Azure CLI authentication |
| `-UseAzPowerShellToken` | Switch | False | Use Azure PowerShell authentication |
| `-UseDeviceCode` | Switch | False | Use device code authentication (recommended for embedded terminals) |
| `-EnableStealth` | Switch | False | Enable stealth mode with default delays and jitter |
| `-RequestDelay` | Double | 0 | Base delay in seconds between API requests (0-60) |
| `-RequestJitter` | Double | 0 | Random jitter range in seconds (0-30) |
| `-MaxRetries` | Int | 3 | Maximum retries on throttling (429) responses (1-10) |
| `-QuietStealth` | Switch | False | Suppress stealth-related status messages |
| `-OnlyCritical` | Switch | False | Show only identities with CRITICAL risk findings |
| `-OnlyHighPrivilege` | Switch | False | Show only identities with high-privilege roles |
| `-OnlyCrossSubscription` | Switch | False | Show only identities with cross-subscription access |
| `-OnlyUnused` | Switch | False | Show only identities with no role assignments |
| `-IncludeRoleDetails` | Switch | False | Include detailed role assignment information |
| `-UnusedDays` | Int | 90 | Days without activity to flag as potentially unused (1-365) |
| `-Matrix` | Switch | False | Display results in matrix/table format |
| `-SkipFailedTenants` | Switch | False | Continue on tenant auth failures (MFA/CA), suppresses warnings |

## Usage Examples

### Basic Scan

```powershell
# Perform comprehensive Managed Identity security audit
.\Invoke-EntraManagedIdentityCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\Invoke-EntraManagedIdentityCheck.ps1 -ExportPath "managed-identity-audit.csv"

# Export to JSON
.\Invoke-EntraManagedIdentityCheck.ps1 -ExportPath "managed-identity-audit.json"
```

### Filtered Scans

```powershell
# Show only critical findings in matrix format
.\Invoke-EntraManagedIdentityCheck.ps1 -OnlyCritical -Matrix

# Show only identities with high-privilege roles
.\Invoke-EntraManagedIdentityCheck.ps1 -OnlyHighPrivilege -Matrix

# Show only identities with cross-subscription access
.\Invoke-EntraManagedIdentityCheck.ps1 -OnlyCrossSubscription

# Find unused managed identities
.\Invoke-EntraManagedIdentityCheck.ps1 -OnlyUnused
```

### Detailed Analysis

```powershell
# Include full role assignment details
.\Invoke-EntraManagedIdentityCheck.ps1 -IncludeRoleDetails -Matrix

# Focus on specific subscription
.\Invoke-EntraManagedIdentityCheck.ps1 -SubscriptionId "your-subscription-id" -IncludeRoleDetails
```

### Multi-Tenant Scenarios

```powershell
# Skip tenants with MFA/Conditional Access issues (common for guest accounts)
.\Invoke-EntraManagedIdentityCheck.ps1 -SkipFailedTenants -Matrix

# Scan specific subscription in specific tenant
.\Invoke-EntraManagedIdentityCheck.ps1 -TenantId "your-tenant-id" -SubscriptionId "your-sub-id"
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraManagedIdentityCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraManagedIdentityCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Alternative Authentication

```powershell
# Use device code authentication
.\Invoke-EntraManagedIdentityCheck.ps1 -UseDeviceCode

# Specify subscription
.\Invoke-EntraManagedIdentityCheck.ps1 -SubscriptionId "your-subscription-id"

# Specify tenant
.\Invoke-EntraManagedIdentityCheck.ps1 -TenantId "your-tenant-id"
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraManagedIdentityCheck -Matrix

# With export
.\Invoke-EvilMist.ps1 -Script EntraManagedIdentityCheck -ExportPath "results.csv" -OnlyCritical
```

## Risk Levels

The script categorizes managed identity findings into four risk levels:

### CRITICAL

- Identity has Owner, User Access Administrator, or RBAC Administrator role
- Identity has subscription-wide critical role with cross-subscription access
- Multiple high-risk factors combined (high privilege + cross-subscription + wide scope)

### HIGH

- Identity has high-privilege roles (Contributor, VM Contributor, Storage Account Contributor, etc.)
- Identity has multiple high-privilege role assignments
- Identity is flagged as a high-value target for attackers

### MEDIUM

- Identity has cross-subscription access
- Identity has management group or root level access
- Identity has subscription-wide access with standard roles

### LOW

- Identity follows least-privilege principle
- Role assignments are resource-scoped
- No concerning permission patterns detected

## High-Privilege Roles Monitored

The script specifically tracks these high-risk roles:

### Critical Roles (Highest Risk)
- Owner
- User Access Administrator
- Role Based Access Control Administrator

### High-Privilege Roles
- Contributor
- Virtual Machine Contributor
- Storage Account Contributor
- Storage Blob Data Owner
- Key Vault Administrator
- Key Vault Secrets Officer
- Key Vault Crypto Officer
- Azure Kubernetes Service Cluster Admin Role
- Azure Kubernetes Service RBAC Cluster Admin

## Resource Types Scanned

| Resource Type | Identity Types Detected |
|--------------|------------------------|
| User-Assigned Managed Identities | User-Assigned |
| Virtual Machines | System-Assigned, User-Assigned |
| App Services (Web Apps) | System-Assigned, User-Assigned |
| Function Apps | System-Assigned, User-Assigned |

## Output Fields

| Field | Description |
|-------|-------------|
| PrincipalId | Object ID of the managed identity |
| ClientId | Application/Client ID of the identity |
| IdentityName | Display name of the identity |
| IdentityType | SystemAssigned or UserAssigned |
| ResourceType | Azure resource type hosting the identity |
| ResourceId | Full Azure resource ID |
| ResourceGroupName | Resource group containing the resource |
| SubscriptionId | Azure subscription ID |
| SubscriptionName | Azure subscription name |
| RoleAssignmentCount | Total number of role assignments |
| HighPrivilegeRoleCount | Count of high-privilege role assignments |
| CriticalRoleCount | Count of critical role assignments |
| HighPrivilegeRoles | List of high-privilege roles assigned |
| CriticalRoles | List of critical roles assigned |
| HasCrossSubscriptionAccess | Whether identity has access outside home subscription |
| CrossSubscriptionCount | Number of cross-subscription role assignments |
| Findings | List of security issues found |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |

## Sample Output

### Standard Output

```
[CRITICAL] Managed Identity: prod-webapp (System-Assigned)
  Principal ID: 12345678-1234-1234-1234-123456789012
  Type: SystemAssigned
  Resource Type: Microsoft.Web/sites
  Subscription: Production
  Resource Group: rg-production
  Location: eastus

  [Role Assignments]
  Total Assignments: 4
  Critical Roles: 1 - Owner
  High-Privilege Roles: 2 - Contributor, Storage Blob Data Owner

  [Scope Analysis]
  Subscription-wide scopes: 2
  Resource group scopes: 1
  Resource-level scopes: 1

  [Cross-Subscription Access]
  This identity has access to 1 scope(s) outside its home subscription!
    - Contributor at /subscriptions/87654321-4321-4321-4321-210987654321

  [Findings]
    - Has CRITICAL role assignments: Owner
    - Has high-privilege role assignments: Contributor, Storage Blob Data Owner
    - Has CROSS-SUBSCRIPTION access to: 87654321-4321-4321-4321-210987654321
    - Has subscription-wide access with roles: Owner, Contributor
```

### Matrix Output

```
=================================================================================================================================
MATRIX VIEW - MANAGED IDENTITY SECURITY AUDIT
=================================================================================================================================

Risk      Identity                              Type           Resource                    Subscription     Roles HighPriv Critical CrossSub SubScope Issues
----      --------                              ----           --------                    ------------     ----- -------- -------- -------- -------- ------
CRITICAL  prod-webapp (System-Assigned)         SystemAssigned Web.sites                   Production       4     2        1        Yes      2        4
HIGH      data-processor                        UserAssigned   ManagedIdentity.userAs...   Production       3     2        0        No       1        2
MEDIUM    staging-vm (System-Assigned)          SystemAssigned Compute.virtualMachines     Staging          2     0        0        Yes      0        2
LOW       log-processor                         UserAssigned   ManagedIdentity.userAs...   Production       1     0        0        No       0        0

=================================================================================================================================

[SUMMARY]
Total subscriptions scanned: 3
Total Managed Identities analyzed: 12
  - System-Assigned: 8
  - User-Assigned: 4
  - CRITICAL risk: 1
  - HIGH risk: 2
  - MEDIUM risk: 3
  - LOW risk: 6

[SECURITY CONCERNS]
  With critical roles (Owner, UAA, RBAC Admin): 1
  With high-privilege roles: 3
  With cross-subscription access: 2
  With subscription-wide scope: 4
  With no role assignments (unused?): 1
```

## Remediation Recommendations

### For CRITICAL/HIGH Risk Findings

1. **Review critical role assignments** - Determine if Owner/User Access Administrator is necessary
   ```powershell
   # Check who assigned the role
   Get-AzRoleAssignment -ObjectId "principal-id" | Select-Object RoleDefinitionName, Scope, CreatedOn
   ```

2. **Reduce to least privilege** - Replace broad roles with specific permissions
   ```powershell
   # Example: Replace Contributor with specific role
   Remove-AzRoleAssignment -ObjectId "principal-id" -RoleDefinitionName "Contributor" -Scope "/subscriptions/xxx"
   New-AzRoleAssignment -ObjectId "principal-id" -RoleDefinitionName "Storage Blob Data Reader" -Scope "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Storage/storageAccounts/xxx"
   ```

3. **Limit cross-subscription access** - Remove unnecessary cross-subscription permissions
   ```powershell
   # List cross-subscription assignments
   Get-AzRoleAssignment -ObjectId "principal-id" | Where-Object { $_.Scope -notmatch "subscription-id" }
   ```

### For MEDIUM Risk Findings

1. **Scope down permissions** - Move from subscription-wide to resource group or resource level
2. **Document justification** - Ensure cross-subscription access is documented and approved
3. **Set up monitoring** - Alert on sensitive operations by managed identities

### For Unused Identities

1. **Verify identity is not needed**
   ```powershell
   # Check sign-in logs (requires Azure AD Premium)
   Get-AzureADAuditSignInLogs -Filter "appId eq 'client-id'"
   ```

2. **Remove unused identities**
   ```powershell
   # For user-assigned identity
   Remove-AzUserAssignedIdentity -ResourceGroupName "rg-name" -Name "identity-name"
   
   # For system-assigned identity on VM
   Update-AzVM -ResourceGroupName "rg-name" -VM $vm -IdentityType None
   ```

## Attack Path Examples

### Scenario 1: VM to Key Vault Secrets

```
Attacker → Compromises VM with RCE → Uses system-assigned managed identity 
→ Identity has Key Vault Secrets User role → Extracts database credentials 
→ Accesses production database
```

**Detection**: Look for VMs with Key Vault access roles

### Scenario 2: Function App to Subscription Control

```
Attacker → Finds vulnerable Function App → Uses system-assigned identity 
→ Identity has Contributor at subscription scope → Deploys crypto miner VMs 
→ Creates persistence mechanisms
```

**Detection**: Look for compute resources with subscription-wide Contributor

### Scenario 3: Cross-Subscription Lateral Movement

```
Attacker → Compromises low-value dev app → Uses managed identity 
→ Identity has cross-subscription access to production → Pivots to production 
→ Accesses production data
```

**Detection**: Look for identities with HasCrossSubscriptionAccess = true

## Related Scripts

- `Invoke-EntraAzureRBACCheck.ps1` - Azure RBAC role assignment audit and drift detection
- `Invoke-EntraAttackPathCheck.ps1` - Attack path analysis
- `Invoke-EntraServicePrincipalCheck.ps1` - Service principal security analysis
- `Invoke-EntraKeyVaultCheck.ps1` - Key Vault security audit
- `Invoke-EntraRoleCheck.ps1` - Entra ID directory role analysis

## References

- [Microsoft: What are managed identities for Azure resources?](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)
- [Microsoft: Managed identity best practices](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/managed-identity-best-practice-recommendations)
- [Microsoft: Azure RBAC best practices](https://docs.microsoft.com/en-us/azure/role-based-access-control/best-practices)
- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [MITRE ATT&CK: Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK: Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
