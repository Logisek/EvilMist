# Invoke-EntraKeyVaultCheck.ps1

## Overview

`Invoke-EntraKeyVaultCheck.ps1` is a PowerShell script that performs a comprehensive security audit of Azure Key Vault configurations. Key Vault is critical for securely storing secrets, keys, and certificates, making it a high-value target for attackers.

## Purpose

This script analyzes Key Vault configurations to identify security gaps and misconfigurations, including:

- **Access model analysis** - RBAC vs legacy access policies
- **Protection settings** - Soft delete and purge protection status
- **Network security** - Public access, firewall rules, VNet integration
- **Private endpoints** - Private connectivity configuration
- **Overly permissive access** - Excessive permissions in access policies
- **Diagnostic logging** - Audit logging configuration
- **Secret/certificate/key expiration** - Items approaching or past expiration

## Attack Scenario Context

### Why Key Vault Security Matters

Key Vault misconfigurations can lead to:
1. **Secret exposure** - Attackers accessing connection strings, API keys, passwords
2. **Lateral movement** - Using extracted credentials to pivot to other services
3. **Data exfiltration** - Accessing encryption keys to decrypt sensitive data
4. **Persistence** - Adding their own secrets/certificates for future access
5. **Destruction** - Purging secrets if purge protection is disabled

### Red Team Value

- Identify Key Vaults with public network access (accessible from internet)
- Find Key Vaults without soft delete/purge protection (can permanently destroy secrets)
- Discover overly permissive access policies granting full secret access
- Identify expired or soon-to-expire credentials that may not be rotated
- Find Key Vaults without logging (activities harder to detect)
- Extract secrets if permissions allow (connection strings, API keys)

### Blue Team Value

- Audit Key Vault configurations against security best practices
- Ensure soft delete and purge protection are enabled
- Verify network restrictions are properly configured
- Confirm diagnostic logging is enabled for audit trails
- Identify access policy permissions that need tightening
- Track secret/certificate expiration for rotation planning
- Enforce RBAC over legacy access policies

## Prerequisites

- PowerShell 7.0 or later
- Azure PowerShell modules (automatically installed if missing):
  - Az.Accounts
  - Az.KeyVault
  - Az.Resources
  - Az.Monitor
- Appropriate Azure RBAC permissions:
  - `Reader` role on subscription(s) for Key Vault enumeration
  - `Key Vault Reader` for detailed configuration access
  - `Key Vault Secrets User` (optional) for secret expiration analysis
  - `Key Vault Certificates Officer` (optional) for certificate expiration analysis
  - `Key Vault Crypto User` (optional) for key expiration analysis

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
| `-OnlyCritical` | Switch | False | Show only Key Vaults with CRITICAL risk findings |
| `-OnlyPublicAccess` | Switch | False | Show only Key Vaults with public network access enabled |
| `-OnlyNoProtection` | Switch | False | Show only Key Vaults without soft delete or purge protection |
| `-IncludeSecrets` | Switch | False | Include secret expiration analysis (requires permissions) |
| `-IncludeCertificates` | Switch | False | Include certificate expiration analysis (requires permissions) |
| `-IncludeKeys` | Switch | False | Include key expiration analysis (requires permissions) |
| `-ExpirationDays` | Int | 30 | Days threshold for expiration warnings (1-365) |
| `-Matrix` | Switch | False | Display results in matrix/table format |
| `-SkipFailedTenants` | Switch | False | Continue on tenant auth failures (MFA/CA), suppresses warnings |

## Usage Examples

### Basic Scan

```powershell
# Perform comprehensive Key Vault security audit
.\Invoke-EntraKeyVaultCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\Invoke-EntraKeyVaultCheck.ps1 -ExportPath "keyvault-audit.csv"

# Export to JSON
.\Invoke-EntraKeyVaultCheck.ps1 -ExportPath "keyvault-audit.json"
```

### Filtered Scans

```powershell
# Show only critical findings in matrix format
.\Invoke-EntraKeyVaultCheck.ps1 -OnlyCritical -Matrix

# Audit only Key Vaults with public access enabled
.\Invoke-EntraKeyVaultCheck.ps1 -OnlyPublicAccess -Matrix

# Show only Key Vaults without protection
.\Invoke-EntraKeyVaultCheck.ps1 -OnlyNoProtection
```

### Expiration Analysis

```powershell
# Include secret and certificate expiration with 90-day threshold
.\Invoke-EntraKeyVaultCheck.ps1 -IncludeSecrets -IncludeCertificates -ExpirationDays 90

# Full expiration analysis
.\Invoke-EntraKeyVaultCheck.ps1 -IncludeSecrets -IncludeCertificates -IncludeKeys -ExpirationDays 60 -Matrix
```

### Multi-Tenant Scenarios

```powershell
# Skip tenants with MFA/Conditional Access issues (common for guest accounts)
.\Invoke-EntraKeyVaultCheck.ps1 -SkipFailedTenants -Matrix

# Scan specific subscription in specific tenant
.\Invoke-EntraKeyVaultCheck.ps1 -TenantId "your-tenant-id" -SubscriptionId "your-sub-id"
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraKeyVaultCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraKeyVaultCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Alternative Authentication

```powershell
# Use device code authentication
.\Invoke-EntraKeyVaultCheck.ps1 -UseDeviceCode

# Specify subscription
.\Invoke-EntraKeyVaultCheck.ps1 -SubscriptionId "your-subscription-id"

# Specify tenant
.\Invoke-EntraKeyVaultCheck.ps1 -TenantId "your-tenant-id"
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraKeyVaultCheck -Matrix

# With export
.\Invoke-EvilMist.ps1 -Script EntraKeyVaultCheck -ExportPath "results.csv" -OnlyCritical
```

## Risk Levels

The script categorizes Key Vault findings into four risk levels:

### CRITICAL

- No soft delete AND no purge protection AND public access enabled
- Overly permissive access policies AND public access AND no logging
- Multiple critical security controls missing simultaneously

### HIGH

- Soft delete disabled (secrets can be permanently deleted immediately)
- Purge protection disabled (deleted secrets can be purged)
- Overly permissive access policies (full permissions granted)

### MEDIUM

- Public network access enabled (accessible from internet)
- No diagnostic logging configured
- Expired secrets/certificates/keys
- Using legacy access policies instead of RBAC

### LOW

- Properly configured Key Vaults with minor deviations
- Network bypass allows Azure services (may be intentional)
- Items approaching expiration (within threshold)

## Security Checks Performed

### Protection Settings

| Check | Risk | Description |
|-------|------|-------------|
| Soft Delete | HIGH | Deleted items retained for recovery period |
| Purge Protection | HIGH | Prevents immediate permanent deletion |
| Retention Period | INFO | Days deleted items are retained |

### Network Security

| Check | Risk | Description |
|-------|------|-------------|
| Public Access | MEDIUM | Key Vault accessible from public internet |
| Default Action | INFO | Allow vs Deny for network access |
| Firewall Rules | INFO | IP-based access restrictions |
| VNet Rules | INFO | Virtual network-based restrictions |
| Private Endpoints | INFO | Private connectivity configuration |
| Network Bypass | INFO | Azure services bypass setting |

### Access Control

| Check | Risk | Description |
|-------|------|-------------|
| RBAC vs Access Policies | MEDIUM | Using modern RBAC or legacy policies |
| Overly Permissive Policies | HIGH | Policies with 'all' or dangerous permissions |
| Purge Permission | HIGH | Ability to permanently delete |
| Dangerous Crypto Permissions | MEDIUM | Decrypt, sign, unwrapKey |

### Logging

| Check | Risk | Description |
|-------|------|-------------|
| Diagnostic Logging | MEDIUM | Audit logging configuration |
| Log Categories | INFO | Which log types are enabled |

### Expiration

| Check | Risk | Description |
|-------|------|-------------|
| Expired Items | MEDIUM | Secrets/certs/keys past expiration |
| Expiring Items | LOW | Items approaching expiration threshold |

## Output Fields

| Field | Description |
|-------|-------------|
| VaultName | Name of the Key Vault |
| VaultUri | URI of the Key Vault |
| ResourceId | Full Azure resource ID |
| ResourceGroupName | Resource group containing the vault |
| SubscriptionId | Azure subscription ID |
| SubscriptionName | Azure subscription name |
| Location | Azure region |
| Sku | Key Vault SKU (Standard/Premium) |
| EnableRbacAuthorization | Whether RBAC is used (vs access policies) |
| EnableSoftDelete | Soft delete status |
| EnablePurgeProtection | Purge protection status |
| SoftDeleteRetentionDays | Retention period for deleted items |
| PublicNetworkAccess | Whether public access is enabled |
| HasPrivateEndpoint | Whether private endpoints are configured |
| HasFirewallRules | Whether IP firewall rules exist |
| HasDiagnosticLogging | Whether audit logging is configured |
| AccessPolicyCount | Number of access policies |
| OverlyPermissivePolicies | Count of overly permissive policies |
| ExpiringSecretsCount | Secrets expiring within threshold |
| ExpiredSecretsCount | Secrets past expiration |
| Findings | List of security issues found |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |

## Sample Output

### Standard Output

```
[CRITICAL] Key Vault: production-secrets
  Subscription: Production
  Resource Group: rg-production
  Location: eastus
  Vault URI: https://production-secrets.vault.azure.net/

  [Security Configuration]
  RBAC Authorization: Disabled (using access policies)
  Soft Delete: DISABLED
  Purge Protection: DISABLED

  [Network Configuration]
  Public Network Access: ENABLED (Default: Allow)
  Private Endpoints: None
  Firewall Rules: None
  VNet Rules: None
  Network Bypass: AzureServices

  [Logging]
  Diagnostic Logging: NOT CONFIGURED

  [Access Policies]
  Total Policies: 5
  Overly Permissive: 2

  [Access Policy Issues]
    - ObjectId: abc123...
      * Full secret permissions ('all')
      * Has PURGE permission (can permanently delete)

  [Findings]
    - Uses legacy access policy model instead of RBAC
    - Soft delete is DISABLED - secrets can be permanently deleted
    - Purge protection is DISABLED - deleted secrets can be purged immediately
    - Public network access is ENABLED (Default Action: Allow)
    - No private endpoints configured - relies on public access
    - Diagnostic logging is NOT configured
    - 2 access policy(ies) with overly permissive permissions
```

### Matrix Output

```
====================================================================================================
MATRIX VIEW - KEY VAULT SECURITY AUDIT
====================================================================================================

Risk      Vault                          Subscription         RBAC SoftDel Purge Public PvtEnd FW   Logs Policies Issues
----      -----                          ------------         ---- ------- ----- ------ ------ --   ---- -------- ------
CRITICAL  production-secrets             Production           No   No      No    Yes    No     No   No   5        7
HIGH      staging-keyvault               Staging              No   Yes     No    Yes    No     No   No   3        4
MEDIUM    dev-keyvault                   Development          Yes  Yes     Yes   Yes    No     Yes  No   0        2
LOW       backup-vault                   Production           Yes  Yes     Yes   No     Yes    Yes  Yes  0        0

====================================================================================================

[SUMMARY]
Total subscriptions scanned: 3
Total Key Vaults analyzed: 4
  - CRITICAL risk: 1
  - HIGH risk: 1
  - MEDIUM risk: 1
  - LOW risk: 1

[CONFIGURATION GAPS]
  No soft delete: 1
  No purge protection: 2
  Public access enabled: 3
  No private endpoint: 3
  No diagnostic logging: 3
  Using access policies (not RBAC): 2
```

## Remediation Recommendations

### For CRITICAL/HIGH Risk Findings

1. **Enable soft delete** - Protects against accidental/malicious deletion
   ```powershell
   Update-AzKeyVault -VaultName "vault-name" -EnableSoftDelete
   ```

2. **Enable purge protection** - Prevents immediate permanent deletion
   ```powershell
   Update-AzKeyVault -VaultName "vault-name" -EnablePurgeProtection
   ```

3. **Restrict network access** - Disable public access, use private endpoints
   ```powershell
   Update-AzKeyVault -VaultName "vault-name" -PublicNetworkAccess "Disabled"
   ```

4. **Enable RBAC** - Migrate from access policies to RBAC
   ```powershell
   Update-AzKeyVault -VaultName "vault-name" -EnableRbacAuthorization $true
   ```

### For MEDIUM Risk Findings

1. **Configure diagnostic logging** - Enable audit logs
   ```powershell
   Set-AzDiagnosticSetting -ResourceId "/subscriptions/.../keyVaults/vault-name" `
     -Enabled $true -Category "AuditEvent"
   ```

2. **Review access policies** - Remove unnecessary permissions, especially 'all' and 'purge'

3. **Configure firewall rules** - Restrict access to known IP ranges

4. **Rotate expired secrets** - Update applications and rotate credentials

### Network Security

1. **Use private endpoints** - Access Key Vault through private network
2. **Configure VNet rules** - Restrict access to specific virtual networks
3. **Enable firewall** - Allow only known IP addresses
4. **Review bypass settings** - Ensure Azure services bypass is intentional

### Access Control Best Practices

1. **Use RBAC over access policies** - More granular, Azure-native
2. **Principle of least privilege** - Grant only required permissions
3. **Avoid 'all' permissions** - Explicitly grant needed permissions
4. **Remove purge permissions** - Unless absolutely required
5. **Regular access reviews** - Periodically audit who has access

## Related Scripts

- `Invoke-EntraAzureRBACCheck.ps1` - Azure RBAC role assignment audit
- `Invoke-EntraServicePrincipalCheck.ps1` - Service principal security analysis
- `Invoke-EntraApplicationCheck.ps1` - Application registration security check
- `Invoke-EntraAttackPathCheck.ps1` - Attack path analysis

## References

- [Microsoft: Azure Key Vault security overview](https://docs.microsoft.com/en-us/azure/key-vault/general/security-overview)
- [Microsoft: Key Vault soft-delete overview](https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview)
- [Microsoft: Configure Key Vault firewalls and VNets](https://docs.microsoft.com/en-us/azure/key-vault/general/network-security)
- [Microsoft: Key Vault RBAC guide](https://docs.microsoft.com/en-us/azure/key-vault/general/rbac-guide)
- [CIS Azure Foundations Benchmark - Key Vault](https://www.cisecurity.org/benchmark/azure)
- [MITRE ATT&CK: Unsecured Credentials (T1552)](https://attack.mitre.org/techniques/T1552/)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
