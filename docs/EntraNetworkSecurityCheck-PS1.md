# Invoke-EntraNetworkSecurityCheck.ps1

## Overview

`Invoke-EntraNetworkSecurityCheck.ps1` is a PowerShell script that performs a comprehensive security audit of Azure network configurations. Network misconfigurations are a primary vector for lateral movement, unauthorized access, and data exfiltration in cloud environments.

## Purpose

This script analyzes network security configurations to identify security gaps and misconfigurations, including:

- **NSG Rules Analysis** - Overly permissive rules (0.0.0.0/0, Any-Any)
- **Open Management Ports** - RDP (3389), SSH (22), WinRM (5985/5986) exposed to Internet
- **Azure Bastion Usage** - Direct RDP/SSH vs secure Bastion access
- **DDoS Protection** - Protection plan status on VNets
- **Private Endpoints** - Private connectivity vs public endpoints
- **VNet Peering Security** - Cross-subscription peerings and gateway transit
- **ExpressRoute/VPN** - Gateway configuration analysis
- **NSG Flow Logs** - Audit logging and traffic analytics

## Attack Scenario Context

### Why Network Security Matters

Network misconfigurations can lead to:
1. **Unauthorized access** - Open management ports allow direct attacks
2. **Lateral movement** - Overly permissive NSGs enable pivot between resources
3. **Data exfiltration** - Missing network controls allow data to leave the network
4. **DDoS attacks** - Unprotected resources are vulnerable to availability attacks
5. **Reconnaissance** - Open ports provide attack surface enumeration
6. **Man-in-the-middle** - Insecure network paths can be intercepted

### Red Team Value

- Identify NSGs with open management ports (RDP/SSH/WinRM) from Internet
- Find Any-to-Any rules that allow unrestricted access
- Discover VNets without Bastion (direct remote access possible)
- Identify cross-subscription peerings (pivot paths)
- Find subnets without NSG protection
- Locate VPN/ExpressRoute gateways for on-premises access
- Identify missing flow logs (reduced detection capability)

### Blue Team Value

- Audit NSG rules against security best practices
- Ensure no management ports are exposed to Internet
- Verify DDoS protection is enabled on critical VNets
- Confirm Azure Bastion is used for remote access
- Verify NSG flow logs are enabled for audit trails
- Monitor VNet peering configurations
- Enforce subnet-level NSG protection

## Prerequisites

- PowerShell 7.0 or later
- Azure PowerShell modules (automatically installed if missing):
  - Az.Accounts
  - Az.Network
  - Az.Resources
- Appropriate Azure RBAC permissions:
  - `Reader` role on subscription(s) for network resource enumeration
  - `Network Contributor` (optional) for detailed NSG analysis

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
| `-OnlyCritical` | Switch | False | Show only resources with CRITICAL risk findings |
| `-OnlyOpenPorts` | Switch | False | Show only NSGs with open management ports |
| `-OnlyPublicAccess` | Switch | False | Show only resources with public access enabled |
| `-SkipNSGs` | Switch | False | Skip Network Security Group analysis (NSGs analyzed by default) |
| `-IncludeVNets` | Switch | False | Include Virtual Network analysis including peerings |
| `-IncludeGateways` | Switch | False | Include VPN/ExpressRoute gateway analysis |
| `-IncludeBastion` | Switch | False | Include Azure Bastion analysis |
| `-IncludeDDoS` | Switch | False | Include DDoS protection status analysis |
| `-IncludeFlowLogs` | Switch | False | Include NSG flow logs configuration analysis |
| `-Matrix` | Switch | False | Display results in matrix/table format |
| `-SkipFailedTenants` | Switch | False | Continue on tenant auth failures (MFA/CA), suppresses warnings |

## Usage Examples

### Basic Scan

```powershell
# Perform comprehensive Network Security audit (NSGs only by default)
.\Invoke-EntraNetworkSecurityCheck.ps1

# Full network security scan with all components
.\Invoke-EntraNetworkSecurityCheck.ps1 -IncludeVNets -IncludeBastion -IncludeGateways -IncludeDDoS
```

### Export Results

```powershell
# Export to CSV
.\Invoke-EntraNetworkSecurityCheck.ps1 -ExportPath "network-audit.csv"

# Export to JSON
.\Invoke-EntraNetworkSecurityCheck.ps1 -ExportPath "network-audit.json"
```

### Filtered Scans

```powershell
# Show only critical findings in matrix format
.\Invoke-EntraNetworkSecurityCheck.ps1 -OnlyCritical -Matrix

# Find all NSGs with open management ports
.\Invoke-EntraNetworkSecurityCheck.ps1 -OnlyOpenPorts -Matrix

# Show only resources with public access
.\Invoke-EntraNetworkSecurityCheck.ps1 -OnlyPublicAccess -IncludeVNets
```

### VNet and Bastion Analysis

```powershell
# Analyze VNets with Bastion status
.\Invoke-EntraNetworkSecurityCheck.ps1 -IncludeVNets -IncludeBastion -Matrix

# Full VNet analysis with DDoS protection status
.\Invoke-EntraNetworkSecurityCheck.ps1 -IncludeVNets -IncludeDDoS -Matrix

# Include gateway analysis for on-prem connectivity
.\Invoke-EntraNetworkSecurityCheck.ps1 -IncludeVNets -IncludeGateways
```

### Flow Logs and Compliance

```powershell
# Include NSG flow logs analysis
.\Invoke-EntraNetworkSecurityCheck.ps1 -IncludeFlowLogs -Matrix

# Full compliance-focused audit
.\Invoke-EntraNetworkSecurityCheck.ps1 -IncludeVNets -IncludeFlowLogs -IncludeDDoS -ExportPath "compliance-audit.json"
```

### Multi-Tenant Scenarios

```powershell
# Skip tenants with MFA/Conditional Access issues
.\Invoke-EntraNetworkSecurityCheck.ps1 -SkipFailedTenants -Matrix

# Scan specific subscription
.\Invoke-EntraNetworkSecurityCheck.ps1 -SubscriptionId "your-sub-id" -IncludeVNets
```

### Stealth Mode

```powershell
# Run in stealth mode with minimal output
.\Invoke-EntraNetworkSecurityCheck.ps1 -EnableStealth -QuietStealth

# Custom timing for evasion
.\Invoke-EntraNetworkSecurityCheck.ps1 -RequestDelay 2 -RequestJitter 1
```

### Alternative Authentication

```powershell
# Use device code authentication
.\Invoke-EntraNetworkSecurityCheck.ps1 -UseDeviceCode

# Specify tenant
.\Invoke-EntraNetworkSecurityCheck.ps1 -TenantId "your-tenant-id"
```

### Using Dispatcher

```powershell
# Via main dispatcher
.\Invoke-EvilMist.ps1 -Script EntraNetworkSecurityCheck -Matrix

# With export
.\Invoke-EvilMist.ps1 -Script EntraNetworkSecurityCheck -ExportPath "results.csv" -OnlyCritical
```

## Risk Levels

The script categorizes network findings into four risk levels:

### CRITICAL

- NSG rules with Any-to-Any inbound access (Source: *, Destination: *, Port: *, Protocol: *)
- Management ports (RDP/SSH/WinRM) open to Internet (0.0.0.0/0)
- Multiple critical misconfigurations combined

### HIGH

- Management ports open from broad IP ranges
- Missing NSG on subnets with Internet-facing resources
- Overly permissive service endpoint configurations

### MEDIUM

- Public network access enabled without compensating controls
- NSG flow logs not configured
- DDoS protection not enabled
- VNets without Bastion protection
- Cross-subscription VNet peerings
- Subnets without NSG protection

### LOW

- Properly configured networks with minor deviations
- Unassociated NSGs (may be intentional templates)
- Network bypass settings (may be intentional)
- NSG flow logs disabled (configured but off)

## Security Checks Performed

### NSG Security Checks

| Check | Risk | Description |
|-------|------|-------------|
| Any-to-Any Rules | CRITICAL | Inbound rules allowing all traffic from any source |
| Open RDP (3389) | CRITICAL | RDP exposed to Internet |
| Open SSH (22) | CRITICAL | SSH exposed to Internet |
| Open WinRM (5985/5986) | CRITICAL | WinRM exposed to Internet |
| Open Telnet (23) | CRITICAL | Telnet exposed to Internet |
| Open SMB (445) | CRITICAL | SMB exposed to Internet |
| Open RPC (135) | HIGH | RPC exposed to Internet |
| Open Database Ports | HIGH | SQL/MySQL/PostgreSQL/MongoDB exposed |
| Internet Inbound Rules | MEDIUM | Any rules allowing inbound from Internet |
| NSG Not Associated | LOW | NSG exists but not attached to subnet/NIC |
| Flow Logs Not Configured | MEDIUM | No flow logging for traffic analysis |
| Traffic Analytics Disabled | LOW | Flow logs without analytics |

### VNet Security Checks

| Check | Risk | Description |
|-------|------|-------------|
| No DDoS Protection | MEDIUM | VNet not protected by DDoS plan |
| No Bastion Host | MEDIUM | VNet without Azure Bastion for secure access |
| Subnets Without NSG | MEDIUM | Subnets lacking network security groups |
| Cross-Subscription Peering | MEDIUM | Peerings to VNets in other subscriptions |
| Gateway Transit Enabled | LOW | Gateway transit on peerings (may be intentional) |

### Bastion Security Checks

| Check | Risk | Description |
|-------|------|-------------|
| Basic SKU | LOW | Limited security features compared to Standard |
| Shareable Links Enabled | MEDIUM | Potential for link sharing outside organization |
| IP-Based Connection | MEDIUM | Less secure than portal-based connection |
| Native Client Enabled | LOW | May bypass some security controls |

## Output Fields

### NSG Findings

| Field | Description |
|-------|-------------|
| NSGName | Name of the Network Security Group |
| ResourceId | Full Azure resource ID |
| ResourceGroupName | Resource group containing the NSG |
| SubscriptionId | Azure subscription ID |
| SubscriptionName | Azure subscription name |
| Location | Azure region |
| IsAssociated | Whether NSG is attached to subnet/NIC |
| TotalRules | Count of custom security rules |
| HasOpenManagementPorts | Whether management ports are exposed |
| OpenManagementPortsCount | Count of exposed management ports |
| HasAnyToAny | Whether Any-to-Any rules exist |
| InternetInboundRulesCount | Count of rules allowing Internet inbound |
| HasFlowLogs | Whether flow logs are configured |
| FlowLogsEnabled | Whether flow logs are enabled |
| RiskLevel | CRITICAL, HIGH, MEDIUM, or LOW |

### VNet Findings

| Field | Description |
|-------|-------------|
| VNetName | Name of the Virtual Network |
| AddressSpace | IP address ranges |
| HasDDoSProtection | Whether DDoS protection is enabled |
| TotalSubnets | Count of subnets |
| SubnetsWithNSG | Subnets with NSG attached |
| SubnetsWithoutNSG | Subnets lacking NSG |
| HasBastionSubnet | Whether AzureBastionSubnet exists |
| HasBastionProtection | Whether Bastion host is deployed |
| PeeringCount | Number of VNet peerings |
| CrossSubscriptionPeerings | Peerings to other subscriptions |
| ServiceEndpointCount | Count of service endpoints |
| PrivateEndpointCount | Count of private endpoints |

## Sample Output

### Standard Output

```
[CRITICAL] NSG: web-tier-nsg
  Subscription: Production
  Resource Group: rg-production
  Location: eastus

  [Association]
  Associated: Yes (Subnets: 2, NICs: 0)
  Subnets: web-subnet, api-subnet

  [Rules Analysis]
  Total Rules: 8 custom, 6 default
  Open Management Ports: YES - 2 port(s)
    - Port 3389 (RDP) via rule 'AllowRDP'
    - Port 22 (SSH) via rule 'AllowSSH'
  Any-to-Any Rules: No
  Internet Inbound Rules: 3

  [Flow Logs]
  Flow Logs Configured: NO

  [Findings]
    - CRITICAL: Management ports (RDP/SSH/WinRM) open to Internet
    - 3 rules allow inbound from Internet
    - NSG flow logs are NOT configured
```

### Matrix Output

```
========================================================================================================================
MATRIX VIEW - NETWORK SECURITY AUDIT
========================================================================================================================

[NSG SECURITY MATRIX]
------------------------------------------------------------------------------------------------------------------------
Risk      NSG Name                       Subscription         Associated Rules OpenMgmt MgmtPorts AnyToAny InetInbound FlowLogs Issues
----      --------                       ------------         ---------- ----- -------- --------- -------- ----------- -------- ------
CRITICAL  web-tier-nsg                   Production           Yes        8     YES      2         No       3           No       3
HIGH      app-tier-nsg                   Production           Yes        6     No       0         No       2           Disabled 2
MEDIUM    db-tier-nsg                    Production           Yes        4     No       0         No       0           No       1
LOW       template-nsg                   Development          No         2     No       0         No       0           Yes      0

========================================================================================================================

[SUMMARY]
Total subscriptions scanned: 2
NSG Analysis:
  Total NSGs analyzed: 4
  - CRITICAL risk: 1
  - HIGH risk: 1
  - MEDIUM risk: 1
  - LOW risk: 1

[NSG SECURITY GAPS]
  Open management ports (RDP/SSH/WinRM): 1
  Any-to-Any rules: 0
  Flow logs not enabled: 3
  Unassociated NSGs: 1
```

## Remediation Recommendations

### For CRITICAL Risk Findings

1. **Remove Any-to-Any inbound rules** - Replace with specific IP/port rules
   ```powershell
   Remove-AzNetworkSecurityRuleConfig -Name "AllowAll" -NetworkSecurityGroup $nsg
   ```

2. **Restrict management ports** - Use Azure Bastion instead of direct access
   ```powershell
   # Remove open RDP rule
   Remove-AzNetworkSecurityRuleConfig -Name "AllowRDP" -NetworkSecurityGroup $nsg
   $nsg | Set-AzNetworkSecurityGroup
   ```

3. **Deploy Azure Bastion** - For secure remote access
   ```powershell
   New-AzBastion -ResourceGroupName "rg-name" -Name "bastion-name" `
     -VirtualNetworkName "vnet-name" -PublicIpAddressName "bastion-pip"
   ```

### For HIGH Risk Findings

1. **Restrict source IP ranges** - Use specific IPs instead of 0.0.0.0/0
   ```powershell
   $rule = Get-AzNetworkSecurityRuleConfig -Name "AllowSSH" -NetworkSecurityGroup $nsg
   $rule.SourceAddressPrefix = "10.0.0.0/8"
   $nsg | Set-AzNetworkSecurityGroup
   ```

2. **Implement Just-In-Time access** - Use Azure Security Center JIT
3. **Use Azure Firewall** - For centralized network security

### For MEDIUM Risk Findings

1. **Enable NSG flow logs** - For traffic visibility
   ```powershell
   Set-AzNetworkWatcherFlowLog -NetworkWatcher $nw -TargetResourceId $nsg.Id `
     -StorageId $storageAccount.Id -Enabled $true
   ```

2. **Enable DDoS Protection** - On production VNets
   ```powershell
   $ddosPlan = Get-AzDdosProtectionPlan -ResourceGroupName "rg-name" -Name "ddos-plan"
   $vnet.DdosProtectionPlan = $ddosPlan
   $vnet | Set-AzVirtualNetwork
   ```

3. **Apply NSGs to all subnets** - Except GatewaySubnet
   ```powershell
   $subnet = Get-AzVirtualNetworkSubnetConfig -Name "subnet-name" -VirtualNetwork $vnet
   $subnet.NetworkSecurityGroup = $nsg
   $vnet | Set-AzVirtualNetwork
   ```

4. **Enable Traffic Analytics** - For advanced insights
   ```powershell
   Set-AzNetworkWatcherFlowLog -NetworkWatcher $nw -TargetResourceId $nsg.Id `
     -EnableTrafficAnalytics $true -TrafficAnalyticsInterval 10
   ```

### Network Security Best Practices

1. **Use Azure Bastion** - Never expose RDP/SSH directly to Internet
2. **Implement Zero Trust** - Use private endpoints and service endpoints
3. **Segment networks** - Use NSGs to microsegment workloads
4. **Enable logging** - Flow logs on all NSGs with Traffic Analytics
5. **Review peerings** - Audit cross-subscription/tenant peerings regularly
6. **Use Azure Firewall** - For centralized egress filtering
7. **Enable DDoS Protection** - Standard plan for production workloads

## Management Port Reference

| Port | Service | Risk if Exposed |
|------|---------|-----------------|
| 22 | SSH | Remote command execution |
| 23 | Telnet | Unencrypted remote access |
| 135 | RPC | Windows service exploitation |
| 139 | NetBIOS | Legacy Windows attacks |
| 445 | SMB | Ransomware, EternalBlue |
| 3389 | RDP | BlueKeep, credential attacks |
| 5985 | WinRM HTTP | PowerShell remoting |
| 5986 | WinRM HTTPS | PowerShell remoting |
| 1433 | SQL Server | Database attacks |
| 3306 | MySQL | Database attacks |
| 5432 | PostgreSQL | Database attacks |
| 27017 | MongoDB | NoSQL injection |

## Related Scripts

- `Invoke-EntraAzureRBACCheck.ps1` - Azure RBAC role assignment audit
- `Invoke-EntraKeyVaultCheck.ps1` - Azure Key Vault security audit
- `Invoke-EntraStorageAccountCheck.ps1` - Azure Storage security audit
- `Invoke-EntraAttackPathCheck.ps1` - Attack path analysis

## References

- [Microsoft: Azure network security best practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices)
- [Microsoft: Azure Bastion](https://docs.microsoft.com/en-us/azure/bastion/bastion-overview)
- [Microsoft: NSG flow logs](https://docs.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview)
- [Microsoft: Azure DDoS Protection](https://docs.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview)
- [CIS Azure Foundations Benchmark - Networking](https://www.cisecurity.org/benchmark/azure)
- [MITRE ATT&CK: Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
- [MITRE ATT&CK: Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

## License

This script is part of the EvilMist toolkit and is distributed under the GNU General Public License v3.0.

## Author

Logisek - https://logisek.com
