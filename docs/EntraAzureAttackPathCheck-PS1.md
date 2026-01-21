# Invoke-EntraAzureAttackPathCheck.ps1

## Overview

`Invoke-EntraAzureAttackPathCheck.ps1` is a PowerShell script that performs comprehensive cross-service Azure attack path analysis. Unlike the Entra-focused attack path check, this script identifies multi-hop attack paths that span multiple Azure services, revealing how access to one resource can lead to compromise of other resources across the Azure environment.

## Purpose

This script analyzes cross-service relationships and permissions to identify attack paths including:

- **VM to Key Vault secrets access** - Compute resources with managed identities that can access Key Vault secrets
- **App Service to Key Vault paths** - Web applications with secret access via managed identities
- **Managed identity privilege escalation** - Identities with critical roles enabling takeover
- **Storage account lateral movement** - Weak storage security enabling data exfiltration or code injection
- **Custom role vulnerabilities** - Dangerous permission combinations in custom role definitions
- **Cross-subscription attack paths** - Access spanning multiple Azure subscriptions
- **Management group inheritance abuse** - Permissions inherited from parent scopes

## Attack Scenario Context

### Why Cross-Service Attack Path Analysis Matters

Azure environments are complex ecosystems where resources interact through identity-based access. A single misconfiguration can create attack paths that span:

1. **Compute → Secrets**: VM compromise leads to Key Vault secret access
2. **Secrets → Data**: Database credentials in Key Vault enable data breach
3. **Identity → Control**: Managed identity with Owner role enables full environment takeover
4. **Storage → Compute**: Scripts/artifacts in storage can compromise VMs that access them
5. **Subscription → Subscription**: Cross-subscription access enables lateral movement

### Red Team Value

- Identify the highest-value attack paths from initial foothold to crown jewels
- Map managed identity to Key Vault secret paths (common misconfiguration)
- Find custom roles with dangerous permission combinations
- Discover cross-subscription pivot opportunities
- Prioritize attack paths by complexity and impact
- Identify storage accounts that can be leveraged for lateral movement

### Blue Team Value

- Comprehensive visibility into cross-service attack surfaces
- Risk-prioritized remediation guidance
- Detection of overly permissive managed identities
- Custom role security review
- Cross-subscription access audit for security boundary enforcement
- Storage security posture assessment

## Prerequisites

- PowerShell 7.0 or later
- Azure PowerShell modules (automatically installed if missing):
  - Az.Accounts
  - Az.Resources
  - Az.KeyVault
  - Az.Compute
  - Az.Storage
  - Az.Websites
  - Az.ManagedServiceIdentity
- Appropriate Azure RBAC permissions:
  - `Reader` role on subscription(s) for resource enumeration
  - `Microsoft.Authorization/roleAssignments/read` for role assignment analysis
  - Key Vault access for access policy enumeration (or RBAC read on Key Vaults)

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
| `-OnlyCritical` | Switch | False | Show only CRITICAL risk attack paths |
| `-OnlyHighRisk` | Switch | False | Show only CRITICAL or HIGH risk attack paths |
| `-IncludeInheritedPaths` | Switch | False | Include attack paths leveraging inherited permissions |
| `-MaxPathDepth` | Int | 3 | Maximum depth for multi-hop attack path analysis (1-5) |
| `-Matrix` | Switch | False | Display results in matrix/table format |
| `-SkipFailedTenants` | Switch | False | Continue on tenant auth failures (MFA/CA), suppresses warnings |

## Usage Examples

### Basic Scan

```powershell
# Perform comprehensive cross-service attack path analysis
.\Invoke-EntraAzureAttackPathCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\Invoke-EntraAzureAttackPathCheck.ps1 -ExportPath "azure-attack-paths.csv"

# Export to JSON
.\Invoke-EntraAzureAttackPathCheck.ps1 -ExportPath "azure-attack-paths.json"
```

### Filtered Scans

```powershell
# Show only critical attack paths in matrix format
.\Invoke-EntraAzureAttackPathCheck.ps1 -OnlyCritical -Matrix

# Show only critical and high-risk paths
.\Invoke-EntraAzureAttackPathCheck.ps1 -OnlyHighRisk -Matrix

# Include inherited permission paths with deeper analysis
.\Invoke-EntraAzureAttackPathCheck.ps1 -IncludeInheritedPaths -MaxPathDepth 4
```

### Targeted Analysis

```powershell
# Scan specific subscription
.\Invoke-EntraAzureAttackPathCheck.ps1 -SubscriptionId "your-subscription-id" -Matrix

# Scan multiple subscriptions
.\Invoke-EntraAzureAttackPathCheck.ps1 -SubscriptionId "sub1-id","sub2-id" -Matrix
```

### Multi-Tenant Scenarios

```powershell
# Skip tenants with MFA/Conditional Access issues
.\Invoke-EntraAzureAttackPathCheck.ps1 -SkipFailedTenants -Matrix

# Scan specific tenant
.\Invoke-EntraAzureAttackPathCheck.ps1 -TenantId "your-tenant-id" -Matrix
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraAzureAttackPathCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraAzureAttackPathCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Alternative Authentication

```powershell
# Use device code authentication (recommended for embedded terminals)
.\Invoke-EntraAzureAttackPathCheck.ps1 -UseDeviceCode
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraAzureAttackPathCheck -Matrix

# With export
.\Invoke-EvilMist.ps1 -Script EntraAzureAttackPathCheck -ExportPath "results.csv" -OnlyCritical
```

## Risk Levels

The script categorizes attack paths into four risk levels:

### CRITICAL

- Managed identity has Owner, User Access Administrator, or RBAC Administrator role
- Attack path leads directly to credential access with critical permissions
- Custom role with role assignment write permissions
- Management group or root level access paths

### HIGH

- Compute resource (VM, App Service) can access Key Vault secrets
- Managed identity with high-privilege roles (Contributor, VM Contributor, etc.)
- Cross-subscription access with high-privilege roles
- Storage account with weak security accessible by multiple identities

### MEDIUM

- Cross-subscription access with standard roles
- Storage account security weaknesses
- Managed identity lateral movement capability
- Inherited permission paths

### LOW

- Limited scope attack paths
- Resource-level access only
- Well-scoped permissions

## Attack Path Categories

| Category | Description |
|----------|-------------|
| Compute-to-Secrets | VM/App Service with managed identity accessing Key Vault secrets |
| PrivilegeEscalation | Managed identity with critical roles enabling takeover |
| LateralMovement | Ability to execute code on other compute resources |
| CrossSubscription | Access spanning multiple Azure subscriptions |
| InheritedAccess | Permissions inherited from management groups |
| MisconfiguredRole | Custom role with dangerous permission combinations |
| DataExfiltration | Storage account security weaknesses enabling data access |

## Output Fields

| Field | Description |
|-------|-------------|
| AttackPathType | Type of attack path identified |
| AttackPathCategory | Category grouping for the attack path |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |
| PathComplexity | Low, Medium, or High complexity |
| PathDepth | Number of hops in the attack path |
| SourceType | Type of initial resource (VM, App Service, etc.) |
| SourceName | Name of the source resource |
| SourceResourceId | Full Azure resource ID of source |
| SourceSubscription | Subscription containing the source |
| SourcePrincipalId | Object ID of the managed identity |
| TargetType | Type of target resource |
| TargetName | Name of the target resource |
| TargetResourceId | Full Azure resource ID of target |
| PathDescription | Human-readable path description |
| AttackNarrative | Description of how attack would proceed |
| Permissions | Permissions enabling the attack path |
| PotentialImpact | Description of impact if exploited |
| RemediationGuidance | Recommended remediation steps |

## Sample Output

### Standard Output

```
[CRITICAL] Managed Identity Privilege Escalation
  Category: PrivilegeEscalation | Complexity: Low | Depth: 1

  [Source - Initial Foothold]
    Type: Virtual Machine
    Name: prod-webapp-vm (System-Assigned)
    Subscription: Production
    Resource Group: rg-production
    Principal ID: 12345678-1234-1234-1234-123456789012

  [Target - Compromised Resource]
    Type: Subscription-wide Access
    Name: /subscriptions/87654321-4321-4321-4321-210987654321

  [Attack Path]
    Description: Managed identity 'prod-webapp-vm (System-Assigned)' has Owner role at Subscription scope
    Attack Narrative: Attacker who compromises the compute resource can escalate privileges using managed identity's Owner role
    Permissions: Owner
    Access Mechanism: Azure RBAC

  [Impact]
    Can assign roles to any identity, create backdoor accounts, access all resources at Subscription scope

  [Remediation]
    Remove Owner from managed identity. Use least-privilege roles.

----------------------------------------------------------------------

[HIGH] VM to Key Vault Secret Access
  Category: Compute-to-Secrets | Complexity: Low | Depth: 1

  [Source - Initial Foothold]
    Type: Virtual Machine
    Name: api-server-01
    Subscription: Production
    Resource Group: rg-api
    Principal ID: 11111111-1111-1111-1111-111111111111

  [Target - Compromised Resource]
    Type: Key Vault Secrets
    Name: kv-production-secrets
    Vault URI: https://kv-production-secrets.vault.azure.net/

  [Attack Path]
    Description: VM 'api-server-01' has managed identity with RBAC access to Key Vault 'kv-production-secrets'
    Attack Narrative: Attacker with VM access can use managed identity to retrieve secrets from Key Vault
    Permissions: Key Vault Secrets User
    Access Mechanism: RBAC

  [Impact]
    Full access to secrets in Key Vault - may contain connection strings, API keys, certificates

  [Remediation]
    Review and minimize managed identity permissions. Use just-in-time access for secrets.
```

### Matrix Output

```
===========================================================================================================
MATRIX VIEW - AZURE CROSS-SERVICE ATTACK PATH ANALYSIS
===========================================================================================================

Risk      Path Type                             Category            Source                          Source Type          Target                          Complexity Depth
----      ---------                             --------            ------                          -----------          ------                          ---------- -----
CRITICAL  Managed Identity Privilege Escala...  PrivilegeEscalation prod-webapp-vm (System-Ass...   Virtual Machine      /subscriptions/87654321-43...   Low        1
CRITICAL  Custom Role Vulnerability             MisconfiguredRole   CustomDevOpsRole                Custom Role Defin... 5 principal(s) assigned         Low        1
HIGH      VM to Key Vault Secret Access         Compute-to-Secrets  api-server-01                   Virtual Machine      kv-production-secrets           Low        1
HIGH      App Service to Key Vault Secret...    Compute-to-Secrets  webapp-frontend                 App Service          kv-app-secrets                  Low        1
MEDIUM    Cross-Subscription Access             CrossSubscription   data-processor                  Managed Identity     Subscription: 11111111-11...    Medium     1
MEDIUM    Storage Account Weak Security         DataExfiltration    stproddata01                    Storage Account      stproddata01                    Low        1

===========================================================================================================

[SUMMARY]
Total subscriptions scanned: 3
Total attack paths identified: 15

[RISK DISTRIBUTION]
  - CRITICAL risk: 2
  - HIGH risk: 4
  - MEDIUM risk: 6
  - LOW risk: 3

[ATTACK PATH CATEGORIES]
  Compute-to-Secrets: 5
  PrivilegeEscalation: 3
  CrossSubscription: 3
  DataExfiltration: 2
  MisconfiguredRole: 2

[TOP AFFECTED RESOURCES]
  prod-webapp-vm (System-Assigned): 3 attack path(s)
  api-server-01: 2 attack path(s)
  data-processor: 2 attack path(s)
```

## Attack Path Examples

### Scenario 1: VM to Key Vault to Database

```
Attacker → Exploits RCE on VM → Uses system-assigned managed identity 
→ Identity has Key Vault Secrets User role → Retrieves SQL connection string 
→ Connects to production database → Exfiltrates sensitive data
```

**Detection**: Look for "VM to Key Vault Secret Access" paths

### Scenario 2: Managed Identity Privilege Escalation

```
Attacker → Compromises low-privilege App Service → Uses managed identity 
→ Identity has Owner role at subscription scope → Assigns themselves Contributor 
→ Creates persistence via additional service principals → Full environment control
```

**Detection**: Look for "Managed Identity Privilege Escalation" with CRITICAL risk

### Scenario 3: Custom Role Exploitation

```
Attacker → Gains access to developer account → Account has CustomDevOpsRole 
→ Role includes Microsoft.Authorization/roleAssignments/write → Creates new Owner assignment 
→ Escalates to full control
```

**Detection**: Look for "Custom Role Vulnerability" paths

### Scenario 4: Cross-Subscription Lateral Movement

```
Attacker → Compromises development workload → Uses managed identity 
→ Identity has Contributor in production subscription → Pivots to production 
→ Deploys malicious resources → Accesses production data
```

**Detection**: Look for "Cross-Subscription Access" paths with HIGH risk

### Scenario 5: Storage to Compute Lateral Movement

```
Attacker → Gains storage account access → Modifies startup scripts stored in blob 
→ VM mounts storage at boot → Executes attacker's script → VM compromise
```

**Detection**: Look for storage accounts with weak security AND compute resources with access

## Remediation Recommendations

### For CRITICAL Attack Paths

1. **Remove Owner/UAA from managed identities**
   ```powershell
   # Find the assignment
   Get-AzRoleAssignment -ObjectId "principal-id" | Where-Object { $_.RoleDefinitionName -eq "Owner" }
   
   # Remove Owner role
   Remove-AzRoleAssignment -ObjectId "principal-id" -RoleDefinitionName "Owner" -Scope "/subscriptions/xxx"
   ```

2. **Review custom roles with dangerous actions**
   ```powershell
   # List custom roles
   Get-AzRoleDefinition -Custom
   
   # Check for dangerous actions
   (Get-AzRoleDefinition -Name "CustomRole").Actions | Where-Object { $_ -match "Authorization" }
   ```

3. **Restrict management group assignments**
   - Move to subscription-level assignments
   - Use Azure Policy to prevent broad assignments

### For HIGH Attack Paths (Compute to Secrets)

1. **Minimize Key Vault access**
   ```powershell
   # Use specific secret access instead of full access
   # Replace Key Vault Secrets Officer with specific secret policies
   ```

2. **Implement Key Vault firewall**
   ```powershell
   # Restrict network access
   Update-AzKeyVaultNetworkRuleSet -VaultName "kv-name" -DefaultAction Deny
   ```

3. **Use managed identity Key Vault references** for App Services instead of storing secrets in app settings

### For Cross-Subscription Paths

1. **Review and document cross-subscription access**
2. **Limit to specific resource groups** instead of subscription-wide
3. **Implement subscription isolation** for sensitive workloads

### For Storage Security Issues

1. **Disable public blob access**
   ```powershell
   Set-AzStorageAccount -ResourceGroupName "rg" -Name "storage" -AllowBlobPublicAccess $false
   ```

2. **Require Azure AD authentication**
   ```powershell
   Set-AzStorageAccount -ResourceGroupName "rg" -Name "storage" -AllowSharedKeyAccess $false
   ```

3. **Enable HTTPS only**
4. **Configure network restrictions**

## Related Scripts

- `Invoke-EntraAttackPathCheck.ps1` - Entra ID-focused attack path analysis
- `Invoke-EntraManagedIdentityCheck.ps1` - Managed identity security audit
- `Invoke-EntraAzureRBACCheck.ps1` - Azure RBAC role assignment audit
- `Invoke-EntraKeyVaultCheck.ps1` - Key Vault security audit
- `Invoke-EntraStorageAccountCheck.ps1` - Storage account security audit
- `Invoke-EntraServicePrincipalCheck.ps1` - Service principal security analysis

## References

- [Microsoft: What are managed identities for Azure resources?](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)
- [Microsoft: Azure Key Vault security](https://docs.microsoft.com/en-us/azure/key-vault/general/security-features)
- [Microsoft: Azure RBAC best practices](https://docs.microsoft.com/en-us/azure/role-based-access-control/best-practices)
- [Microsoft: Azure storage security guide](https://docs.microsoft.com/en-us/azure/storage/blobs/security-recommendations)
- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [MITRE ATT&CK: Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK: Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/)
- [MITRE ATT&CK: Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004/)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
