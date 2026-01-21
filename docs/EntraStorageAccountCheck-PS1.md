# Invoke-EntraStorageAccountCheck.ps1

## Overview

`Invoke-EntraStorageAccountCheck.ps1` is a PowerShell script that performs a comprehensive security audit of Azure Storage Account configurations. Storage accounts are critical for data storage in Azure, making them high-value targets for data exfiltration and unauthorized access.

## Purpose

This script analyzes Storage Account configurations to identify security gaps and misconfigurations, including:

- **Public blob containers** - Anonymous access to blob data
- **HTTPS enforcement** - Unencrypted HTTP traffic allowed
- **Shared key access** - Storage account keys vs Azure AD authentication
- **Network security** - Public access, firewall rules, VNet integration
- **Private endpoints** - Private connectivity configuration
- **Data protection** - Blob soft delete, container soft delete, versioning
- **Key rotation** - Storage account key age tracking
- **Cross-tenant replication** - Data replication to other tenants
- **Diagnostic logging** - Audit logging configuration

## Attack Scenario Context

### Why Storage Account Security Matters

Storage Account misconfigurations can lead to:
1. **Data exposure** - Anonymous blob access exposes sensitive files publicly
2. **Data exfiltration** - Extracting data through exposed containers or compromised keys
3. **Lateral movement** - Using connection strings to pivot to other services
4. **Ransomware** - Encrypting or deleting blobs if soft delete is disabled
5. **Persistence** - Creating hidden containers for command & control
6. **Man-in-the-middle** - Intercepting data if HTTPS is not enforced

### Red Team Value

- Identify storage accounts with anonymous blob containers (public data exposure)
- Find storage accounts without HTTPS enforcement (credential interception)
- Discover shared key access enabled (key theft via config files)
- Identify storage accounts with public network access (remotely accessible)
- Find accounts without soft delete (permanent data destruction possible)
- Track old storage keys for password spray or brute force attempts
- Identify cross-tenant replication (data exfiltration paths)

### Blue Team Value

- Audit storage configurations against security best practices
- Ensure no containers have anonymous access
- Verify HTTPS-only and TLS 1.2+ enforcement
- Confirm network restrictions are properly configured
- Verify diagnostic logging is enabled for audit trails
- Track key rotation for compliance requirements
- Enforce Azure AD authentication over shared keys
- Monitor cross-tenant replication settings

## Prerequisites

- PowerShell 7.0 or later
- Azure PowerShell modules (automatically installed if missing):
  - Az.Accounts
  - Az.Storage
  - Az.Resources
  - Az.Monitor
- Appropriate Azure RBAC permissions:
  - `Reader` role on subscription(s) for storage account enumeration
  - `Storage Blob Data Reader` (optional) for container enumeration
  - `Storage Account Key Operator` (optional) for key age analysis

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
| `-OnlyCritical` | Switch | False | Show only Storage Accounts with CRITICAL risk findings |
| `-OnlyPublicAccess` | Switch | False | Show only Storage Accounts with public access or public blob setting |
| `-OnlyAnonymousContainers` | Switch | False | Show only Storage Accounts with containers allowing anonymous access |
| `-IncludeContainers` | Switch | False | Include blob container enumeration (requires permissions) |
| `-IncludeKeyAge` | Switch | False | Include storage account key age analysis |
| `-KeyRotationDays` | Int | 90 | Days threshold for key rotation warnings (1-365) |
| `-Matrix` | Switch | False | Display results in matrix/table format |
| `-SkipFailedTenants` | Switch | False | Continue on tenant auth failures (MFA/CA), suppresses warnings |

## Usage Examples

### Basic Scan

```powershell
# Perform comprehensive Storage Account security audit
.\Invoke-EntraStorageAccountCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\Invoke-EntraStorageAccountCheck.ps1 -ExportPath "storage-audit.csv"

# Export to JSON
.\Invoke-EntraStorageAccountCheck.ps1 -ExportPath "storage-audit.json"
```

### Filtered Scans

```powershell
# Show only critical findings in matrix format
.\Invoke-EntraStorageAccountCheck.ps1 -OnlyCritical -Matrix

# Audit only Storage Accounts with public access enabled
.\Invoke-EntraStorageAccountCheck.ps1 -OnlyPublicAccess -Matrix

# Find all containers with anonymous access
.\Invoke-EntraStorageAccountCheck.ps1 -OnlyAnonymousContainers -IncludeContainers
```

### Container and Key Analysis

```powershell
# Include container enumeration for anonymous access detection
.\Invoke-EntraStorageAccountCheck.ps1 -IncludeContainers -Matrix

# Include key rotation analysis with 60-day threshold
.\Invoke-EntraStorageAccountCheck.ps1 -IncludeKeyAge -KeyRotationDays 60

# Full analysis with containers and key age
.\Invoke-EntraStorageAccountCheck.ps1 -IncludeContainers -IncludeKeyAge -Matrix
```

### Multi-Tenant Scenarios

```powershell
# Skip tenants with MFA/Conditional Access issues (common for guest accounts)
.\Invoke-EntraStorageAccountCheck.ps1 -SkipFailedTenants -Matrix

# Scan specific subscription in specific tenant
.\Invoke-EntraStorageAccountCheck.ps1 -TenantId "your-tenant-id" -SubscriptionId "your-sub-id"
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraStorageAccountCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraStorageAccountCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Alternative Authentication

```powershell
# Use device code authentication
.\Invoke-EntraStorageAccountCheck.ps1 -UseDeviceCode

# Specify subscription
.\Invoke-EntraStorageAccountCheck.ps1 -SubscriptionId "your-subscription-id"

# Specify tenant
.\Invoke-EntraStorageAccountCheck.ps1 -TenantId "your-tenant-id"
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraStorageAccountCheck -Matrix

# With export
.\Invoke-EvilMist.ps1 -Script EntraStorageAccountCheck -ExportPath "results.csv" -OnlyCritical
```

## Risk Levels

The script categorizes Storage Account findings into four risk levels:

### CRITICAL

- Containers with anonymous access (Blob or Container level public access)
- Public blob access allowed AND public network access AND no logging
- HTTPS not enforced AND public network access

### HIGH

- HTTPS traffic not enforced (unencrypted data in transit)
- Allow blob public access enabled at storage account level
- TLS version below 1.2

### MEDIUM

- Public network access enabled
- No diagnostic logging configured
- Cross-tenant replication allowed
- Keys older than rotation threshold
- No blob soft delete enabled

### LOW

- Properly configured storage accounts with minor deviations
- Network bypass configured (may be intentional)
- Shared key access enabled (common but not ideal)
- No blob versioning (data protection gap)

## Security Checks Performed

### Transport Security

| Check | Risk | Description |
|-------|------|-------------|
| HTTPS Only | HIGH | Enforces encrypted transport for all traffic |
| Minimum TLS Version | MEDIUM | TLS 1.2+ required for security |

### Access Control

| Check | Risk | Description |
|-------|------|-------------|
| Allow Blob Public Access | HIGH | Storage account-level setting for public containers |
| Anonymous Containers | CRITICAL | Containers with Blob or Container public access |
| Shared Key Access | LOW | Allow storage key authentication vs Azure AD only |
| Cross-Tenant Replication | MEDIUM | Allow data replication to other tenants |

### Network Security

| Check | Risk | Description |
|-------|------|-------------|
| Public Network Access | MEDIUM | Storage account accessible from public internet |
| Default Action | INFO | Allow vs Deny for network access |
| Firewall Rules | INFO | IP-based access restrictions |
| VNet Rules | INFO | Virtual network-based restrictions |
| Private Endpoints | INFO | Private connectivity configuration |
| Network Bypass | INFO | Azure services bypass setting |

### Data Protection

| Check | Risk | Description |
|-------|------|-------------|
| Blob Soft Delete | MEDIUM | Deleted blobs retained for recovery |
| Container Soft Delete | MEDIUM | Deleted containers retained for recovery |
| Blob Versioning | LOW | Maintain version history of blobs |
| Infrastructure Encryption | INFO | Double encryption at rest |

### Key Management

| Check | Risk | Description |
|-------|------|-------------|
| Key Age | MEDIUM | Days since storage keys were rotated |
| Keys Need Rotation | MEDIUM | Keys older than threshold |

### Logging

| Check | Risk | Description |
|-------|------|-------------|
| Diagnostic Logging | MEDIUM | Audit logging configuration |
| Log Categories | INFO | Which log types are enabled |

## Output Fields

| Field | Description |
|-------|-------------|
| StorageAccountName | Name of the Storage Account |
| ResourceId | Full Azure resource ID |
| ResourceGroupName | Resource group containing the storage account |
| SubscriptionId | Azure subscription ID |
| SubscriptionName | Azure subscription name |
| Location | Azure region |
| Kind | Storage account kind (StorageV2, BlobStorage, etc.) |
| Sku | Storage account SKU (Standard_LRS, Premium_LRS, etc.) |
| AllowBlobPublicAccess | Whether blob public access is allowed |
| EnableHttpsTrafficOnly | Whether HTTPS is enforced |
| MinimumTlsVersion | Minimum TLS version required |
| AllowSharedKeyAccess | Whether storage key auth is allowed |
| PublicNetworkAccess | Whether public access is enabled |
| HasPrivateEndpoint | Whether private endpoints are configured |
| BlobSoftDelete | Whether blob soft delete is enabled |
| BlobVersioning | Whether blob versioning is enabled |
| AnonymousContainerCount | Count of containers with anonymous access |
| KeysNeedRotation | Whether keys exceed rotation threshold |
| OldestKeyAge | Age of oldest storage key in days |
| Findings | List of security issues found |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |

## Sample Output

### Standard Output

```
[CRITICAL] Storage Account: publicdata12345
  Subscription: Production
  Resource Group: rg-production
  Location: eastus
  Kind: StorageV2 | SKU: Standard_LRS

  [Security Configuration]
  HTTPS Only: Enabled
  Minimum TLS Version: TLS1_2
  Allow Blob Public Access: ENABLED
  Shared Key Access: Enabled
  Cross-Tenant Replication: Disabled

  [Encryption]
  Infrastructure Encryption: Standard encryption only
  Encryption Key Source: Microsoft.Storage

  [Network Configuration]
  Public Network Access: ENABLED (Default: Allow)
  Private Endpoints: None
  Firewall Rules: None
  VNet Rules: None
  Network Bypass: AzureServices

  [Data Protection]
  Blob Soft Delete: DISABLED
  Container Soft Delete: DISABLED
  Blob Versioning: Disabled

  [Logging]
  Diagnostic Logging: NOT CONFIGURED

  [ANONYMOUS CONTAINERS - CRITICAL]
  Count: 2
  Access Levels: Container, Blob
    - public-files: Container access
    - uploads: Blob access

  [Findings]
    - Blob public access is ALLOWED (containers can be made public)
    - 2 container(s) with ANONYMOUS access: Container, Blob
    - Public network access is ENABLED
    - No private endpoints configured - relies on public access
    - Blob soft delete is DISABLED - deleted blobs cannot be recovered
    - Container soft delete is DISABLED - deleted containers cannot be recovered
    - Blob versioning is DISABLED - no version history maintained
    - Diagnostic logging is NOT configured
```

### Matrix Output

```
========================================================================================================================
MATRIX VIEW - STORAGE ACCOUNT SECURITY AUDIT
========================================================================================================================

Risk      Storage Account           Subscription         HTTPS TLS       PubBlob PubNet PvtEnd SoftDel Version Logs AnonCont Issues
----      ---------------           ------------         ----- ---       ------- ------ ------ ------- ------- ---- -------- ------
CRITICAL  publicdata12345           Production           Yes   TLS1_2    Yes     Yes    No     No      No      No   2        8
HIGH      devstorageacct            Development          No    TLS1_0    Yes     Yes    No     No      No      No   0        6
MEDIUM    internaldata              Production           Yes   TLS1_2    No      Yes    No     Yes     No      No   0        3
LOW       securestorage             Production           Yes   TLS1_2    No      No     Yes    Yes     Yes     Yes  0        0

========================================================================================================================

[SUMMARY]
Total subscriptions scanned: 2
Total Storage Accounts analyzed: 4
  - CRITICAL risk: 1
  - HIGH risk: 1
  - MEDIUM risk: 1
  - LOW risk: 1

[CONFIGURATION GAPS]
  HTTPS not enforced: 1
  Allow blob public access: 2
  Anonymous containers: 1
  Public network access: 3
  No private endpoint: 3
  No blob soft delete: 2
  No blob versioning: 3
  No diagnostic logging: 3
```

## Remediation Recommendations

### For CRITICAL Risk Findings

1. **Remove anonymous container access** - Set all containers to private
   ```powershell
   Set-AzStorageContainerAcl -Name "container-name" -Permission Off -Context $context
   ```

2. **Disable blob public access** - Prevent any containers from being made public
   ```powershell
   Set-AzStorageAccount -ResourceGroupName "rg-name" -Name "storage-name" -AllowBlobPublicAccess $false
   ```

3. **Enforce HTTPS** - Require encrypted transport
   ```powershell
   Set-AzStorageAccount -ResourceGroupName "rg-name" -Name "storage-name" -EnableHttpsTrafficOnly $true
   ```

### For HIGH Risk Findings

1. **Set minimum TLS version** - Require TLS 1.2 or higher
   ```powershell
   Set-AzStorageAccount -ResourceGroupName "rg-name" -Name "storage-name" -MinimumTlsVersion TLS1_2
   ```

2. **Disable shared key access** - Force Azure AD authentication
   ```powershell
   Set-AzStorageAccount -ResourceGroupName "rg-name" -Name "storage-name" -AllowSharedKeyAccess $false
   ```

### For MEDIUM Risk Findings

1. **Restrict network access** - Disable public access, use private endpoints
   ```powershell
   Set-AzStorageAccount -ResourceGroupName "rg-name" -Name "storage-name" -PublicNetworkAccess Disabled
   ```

2. **Enable blob soft delete** - Protect against accidental/malicious deletion
   ```powershell
   Enable-AzStorageBlobDeleteRetentionPolicy -ResourceGroupName "rg-name" -StorageAccountName "storage-name" -RetentionDays 7
   ```

3. **Enable container soft delete** - Protect container deletion
   ```powershell
   Enable-AzStorageContainerDeleteRetentionPolicy -ResourceGroupName "rg-name" -StorageAccountName "storage-name" -RetentionDays 7
   ```

4. **Configure diagnostic logging** - Enable audit logs
   ```powershell
   Set-AzDiagnosticSetting -ResourceId "/subscriptions/.../storageAccounts/storage-name" `
     -Enabled $true -Category "StorageRead","StorageWrite","StorageDelete"
   ```

5. **Rotate storage keys** - Regenerate old access keys
   ```powershell
   New-AzStorageAccountKey -ResourceGroupName "rg-name" -Name "storage-name" -KeyName "key1"
   ```

6. **Disable cross-tenant replication** - Prevent data replication to other tenants
   ```powershell
   Set-AzStorageAccount -ResourceGroupName "rg-name" -Name "storage-name" -AllowCrossTenantReplication $false
   ```

### Network Security Best Practices

1. **Use private endpoints** - Access storage through private network
2. **Configure VNet rules** - Restrict access to specific virtual networks
3. **Enable firewall** - Allow only known IP addresses
4. **Review bypass settings** - Ensure Azure services bypass is intentional

### Data Protection Best Practices

1. **Enable blob versioning** - Maintain version history for recovery
2. **Use immutable storage** - Prevent modification of critical data
3. **Enable infrastructure encryption** - Double encryption at rest
4. **Implement lifecycle management** - Automate data retention

## Related Scripts

- `Invoke-EntraKeyVaultCheck.ps1` - Azure Key Vault security audit
- `Invoke-EntraAzureRBACCheck.ps1` - Azure RBAC role assignment audit
- `Invoke-EntraServicePrincipalCheck.ps1` - Service principal security analysis
- `Invoke-EntraAttackPathCheck.ps1` - Attack path analysis

## References

- [Microsoft: Azure Storage security overview](https://docs.microsoft.com/en-us/azure/storage/common/storage-security-guide)
- [Microsoft: Prevent anonymous public read access](https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent)
- [Microsoft: Configure Azure Storage firewalls and VNets](https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security)
- [Microsoft: Data protection overview](https://docs.microsoft.com/en-us/azure/storage/blobs/data-protection-overview)
- [CIS Azure Foundations Benchmark - Storage](https://www.cisecurity.org/benchmark/azure)
- [MITRE ATT&CK: Data from Cloud Storage Object (T1530)](https://attack.mitre.org/techniques/T1530/)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
