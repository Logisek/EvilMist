# Invoke-EntraPowerPlatformCheck.ps1

## Overview

`Invoke-EntraPowerPlatformCheck.ps1` is a PowerShell 7+ script designed to enumerate and analyze Power Apps and Power Automate flows in Microsoft Power Platform, identify sensitive connectors, detect high-risk actions, and assess security risks. This tool is part of the EvilMist toolkit and helps security teams identify Power Platform resources with security concerns in their tenant.

## Purpose

Power Platform resources (Power Apps and Power Automate flows) can access sensitive data and perform privileged operations. This script helps:
- **Security Auditors**: Identify Power Platform resources with sensitive connectors and high-risk actions
- **Penetration Testers**: Discover potential data exfiltration and privilege escalation vectors
- **IT Administrators**: Audit Power Platform security posture and connector usage
- **Compliance Teams**: Generate reports for Power Platform governance and risk assessment

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports device code flow (default), Azure CLI (auto-login), and Azure PowerShell (auto-login with Graph context account)
- ✅ **Automatic Authentication**: Automatically runs `az login` or `Connect-AzAccount` when respective flags are used
- ✅ **Power Apps Enumeration**: Enumerates all Power Apps with owner and sharing information
- ✅ **Power Automate Flow Enumeration**: Enumerates all flows with connector and action analysis
- ✅ **Sensitive Connector Detection**: Identifies 30+ sensitive connectors (CRITICAL, HIGH, MEDIUM, LOW risk)
- ✅ **High-Risk Action Detection**: Identifies flows with high-risk actions (Delete, Create, Modify, etc.)
- ✅ **Risk Assessment**: Categorizes resources by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **Connector Analysis**: Analyzes connector usage and categorizes by risk level
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only high-risk resources or resources with sensitive connectors

## Sensitive Connectors

The script identifies sensitive connectors across multiple categories:

### CRITICAL Risk Connectors

- **Azure Active Directory** - Full directory access and user management
- **Azure Key Vault** - Access to secrets, keys, and certificates
- **HTTP** - Custom HTTP requests to any endpoint (potential data exfiltration)

### HIGH Risk Connectors

**Databases:**
- SQL Server
- Azure SQL Database
- Cosmos DB

**Storage:**
- Azure Blob Storage
- Amazon S3
- Google Cloud Storage
- FTP/SFTP

**Microsoft 365:**
- SharePoint Online
- OneDrive for Business

**Email:**
- SendGrid
- SMTP

**Custom Code:**
- HTTP with Azure AD
- Azure Functions
- Custom Connector

**Cloud Services:**
- Azure Automation
- Azure DevOps
- GitHub

**CRM & ERP:**
- Dataverse
- Dynamics 365
- Salesforce
- ServiceNow

### MEDIUM Risk Connectors

- Azure Table Storage
- Azure File Storage
- Office 365 Outlook
- Microsoft Teams
- Excel Online
- Twilio SMS
- Slack
- Azure Logic Apps

## High-Risk Actions

The script identifies Power Automate flows with high-risk actions that could:
- **Delete** resources or data
- **Remove** access or permissions
- **Terminate** processes or sessions
- **Disable** accounts or services
- **Revoke** permissions or access
- **Block** users or resources
- **Create** new resources or accounts
- **Update/Modify** critical configurations
- **Change** security settings
- **Set** permissions or access levels
- **Grant** elevated privileges
- **Assign** roles or permissions

## Requirements

### Prerequisites

1. **PowerShell 7+**
   - Download: https://aka.ms/powershell-release?tag=stable
   - The script will check and warn if older version is detected

2. **Microsoft Graph PowerShell SDK**
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```
   
   Or install individual modules:
   ```powershell
   Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
   Install-Module Microsoft.Graph.Users -Scope CurrentUser
   ```

3. **Power Platform Permissions**
   - Power Platform Admin role, OR
   - Environment Maker role in target environments
   - Note: User-scoped enumeration may work with limited permissions

4. **Power Platform Authentication** (Optional but Recommended)
   - **Azure CLI** (optional): Install from https://aka.ms/installazurecliwindows - script will auto-login
   - **Azure PowerShell** (optional): Install with `Install-Module Az -Scope CurrentUser` - script will auto-login
   - **Default**: Script uses device code flow (browser authentication) - no additional tools needed

### Required Permissions

The script requires the following Microsoft Graph API permissions:

- **Primary Scopes** (preferred):
  - `Directory.Read.All` - Read directory data
  - `User.Read.All` - Read all user profiles

- **Fallback Scopes** (if full access unavailable):
  - `Directory.Read.All` - Read directory data
  - `User.ReadBasic.All` - Read basic user info

**Note**: Power Platform enumeration requires separate authentication for Power Platform APIs (different resource than Graph API). The script automatically handles this:

- **Default**: Uses device code flow - you'll be prompted to authenticate via browser
- **Azure CLI**: Use `-UseAzCliToken` - script automatically runs `az login` if needed
- **Azure PowerShell**: Use `-UseAzPowerShellToken` - script automatically runs `Connect-AzAccount` if needed (uses same account as Graph auth)

You still need Power Platform Admin or Environment Maker permissions to enumerate all resources. Without admin permissions, the script will fall back to user-scoped APIs (shows only your own resources).

## Usage

### Basic Usage

```powershell
# Enumerate all Power Apps and Power Automate flows
# Will prompt for browser authentication (device code flow) if needed
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1
```

**Note**: The script will automatically prompt you to authenticate via browser for Power Platform APIs. Follow the on-screen instructions to complete authentication.

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -ExportPath "power-platform.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -ExportPath "power-platform.json"
```

### Show Only High-Risk Resources

```powershell
# Filter to show only CRITICAL and HIGH risk resources
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -OnlyHighRisk

# Matrix view with high-risk filter
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -OnlyHighRisk -Matrix
```

### Show Only Resources with Sensitive Connectors

```powershell
# Filter to show only resources with sensitive connectors
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -OnlySensitiveConnectors

# Export sensitive resources
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -OnlySensitiveConnectors -ExportPath "sensitive.csv"
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

The script supports multiple authentication methods for Power Platform APIs:

**Device Code Flow (Default):**
- Automatically prompts for browser-based authentication
- No pre-setup required
- Works with any Azure AD account

```powershell
# Default - uses device code flow automatically
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1
```

**Azure CLI (Automatic Login):**
- Automatically runs `az login` if not already authenticated
- Uses cached credentials if available
- Requires Azure CLI installed

```powershell
# Will automatically login if needed
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -UseAzCliToken
```

**Azure PowerShell (Automatic Login):**
- Automatically runs `Connect-AzAccount` if not already authenticated
- Uses account from Graph context if available (no account selection prompt)
- Automatically installs Az.Accounts module if missing
- Requires Az module installed

```powershell
# Will automatically login if needed, uses same account as Graph auth
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -UseAzPowerShellToken
```

**Specify Tenant:**
```powershell
# Specify tenant for authentication
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all resources, with export
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -Matrix -ExportPath "full-audit.csv"

# Security focus: high-risk resources only
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -OnlyHighRisk -Matrix -ExportPath "high-risk.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
```

## Parameters

### General Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-ExportPath` | String | Path to export results (CSV or JSON based on extension) | None |
| `-TenantId` | String | Optional Tenant ID. Uses home tenant if not specified | None |
| `-UseAzCliToken` | Switch | Use Azure CLI for authentication (automatically runs `az login` if needed) | False |
| `-UseAzPowerShellToken` | Switch | Use Azure PowerShell for authentication (automatically runs `Connect-AzAccount` if needed, uses Graph context account) | False |
| `-OnlyHighRisk` | Switch | Show only resources with CRITICAL or HIGH risk | False |
| `-OnlySensitiveConnectors` | Switch | Show only resources with sensitive connectors | False |
| `-Matrix` | Switch | Display results in matrix/table format | False |

### Stealth & Evasion Parameters

| Parameter | Type | Range | Description | Default |
|-----------|------|-------|-------------|---------|
| `-EnableStealth` | Switch | - | Enable stealth mode with default delays (500ms + 300ms jitter) | False |
| `-RequestDelay` | Double | 0-60 | Base delay in seconds between API requests | 0 |
| `-RequestJitter` | Double | 0-30 | Random jitter range in seconds (+/-) | 0 |
| `-MaxRetries` | Int | 1-10 | Maximum retries on throttling (429) responses | 3 |
| `-QuietStealth` | Switch | - | Suppress stealth-related status messages | False |

## Output

### Standard Output

The script provides detailed information about each Power Platform resource:

```
[CRITICAL] Power Automate Flow: Data Exfiltration Flow
  Environment: Production
  Owner: John Admin
  Owner Email: john.admin@company.com
  Created: 2024-01-15T10:30:00Z
  Last Modified: 2024-12-20T14:23:45Z
  State: Started
  Flow Type: Automated
  Triggers: When an HTTP request is received
  Connectors: 3 connector(s)
  Connector List: HTTP, Azure Blob Storage, SharePoint Online
  Sensitive Connectors: 3 found
    HTTP (CRITICAL), Azure Blob Storage (HIGH), SharePoint Online (HIGH)
  High-Risk Actions: Yes
    DeleteFile, CreateFile, UpdateFile
```

### Matrix Output (with `-Matrix`)

```
Risk      Type                  Display Name              Environment    Owner         Connectors  Sensitive Connectors  High-Risk Actions  Status
----      ----                  -----------              -----------    -----         ----------  --------------------  -----------------  ------
CRITICAL  Power Automate Flow   Data Exfiltration Flow   Production     John Admin    3          3                     Yes                Started
HIGH      Power App             Customer Data App        Production     Jane User     2          2                     No                 Published
MEDIUM    Power Automate Flow   Email Notification       Development    Bob Dev        1          1                     No                 Started
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total Power Apps analyzed: 45
Total Power Automate flows analyzed: 123
Resources in results: 168
  - Power Apps: 45
  - Power Automate Flows: 123

[RISK BREAKDOWN]
  - CRITICAL risk: 5
  - HIGH risk: 23
  - MEDIUM risk: 45
  - LOW risk: 95

[SECURITY METRICS]
  - Resources with sensitive connectors: 73
  - Flows with high-risk actions: 28

[RESOURCES BY ENVIRONMENT]
  Production: 89
  Development: 52
  Test: 27

[TOP OWNERS]
  John Admin: 23
  Jane User: 18
  Bob Developer: 15
```

## Risk Levels

The script assigns risk levels based on connector types and actions:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Resource uses CRITICAL risk connectors (Azure AD, Key Vault, HTTP) | Red | **IMMEDIATE ACTION REQUIRED**: Review and restrict access |
| **HIGH** | Resource uses HIGH risk connectors (SQL, Storage, SharePoint) OR has high-risk actions | Red | **URGENT REVIEW**: Assess business justification and restrict if unnecessary |
| **MEDIUM** | Resource uses MEDIUM risk connectors (Teams, Outlook, Logic Apps) | Yellow | **REVIEW**: Monitor usage and ensure proper access controls |
| **LOW** | Resource uses only standard/low-risk connectors | Green | **MONITOR**: Acceptable risk, regular review recommended |

### Risk Assessment Logic

```
IF resource uses CRITICAL connector:
    RISK = CRITICAL
ELSE IF resource uses HIGH connector:
    RISK = HIGH
ELSE IF resource uses MEDIUM connector:
    RISK = MEDIUM
ELSE IF resource has high-risk actions:
    RISK = MEDIUM (or HIGH if already MEDIUM)
ELSE:
    RISK = LOW
```

## Security Considerations

### Why Power Platform Security Matters

Power Apps and Power Automate flows can:
- **Access sensitive data**: SQL databases, SharePoint sites, OneDrive files, email
- **Exfiltrate data**: HTTP connectors can send data to external endpoints
- **Modify critical systems**: Create/update/delete resources in Azure, M365, and other services
- **Escalate privileges**: Azure AD connector can modify users and groups
- **Bypass security controls**: Custom connectors and HTTP requests may bypass network restrictions
- **Persist access**: Create service principals, app registrations, or hidden access paths

### High-Risk Scenarios

1. **CRITICAL Risk Resources** (CRITICAL)
   - Flows using Azure AD connector can modify users, groups, and roles
   - Flows using Key Vault connector can access secrets and certificates
   - HTTP connectors can exfiltrate data to any external endpoint
   - **Action**: Immediate review and restriction

2. **Data Exfiltration Flows** (HIGH)
   - Flows that read from SharePoint/OneDrive and send via HTTP/SMTP
   - Flows that query databases and export data
   - **Action**: Review business justification and monitor data access

3. **Unmanaged Custom Connectors** (HIGH)
   - Custom connectors may have undocumented capabilities
   - May bypass standard security controls
   - **Action**: Review and document all custom connectors

4. **Stale or Abandoned Resources** (MEDIUM)
   - Resources created by former employees
   - Resources not modified in 90+ days
   - **Action**: Review and archive or delete unused resources

5. **Overly Permissive Sharing** (MEDIUM)
   - Power Apps shared with entire organization
   - Flows accessible by multiple users without justification
   - **Action**: Review sharing permissions and apply least privilege

### Best Practices

1. **Regular Audits**: Run monthly to track Power Platform resource changes
2. **Connector Governance**: Restrict sensitive connectors to approved users
3. **Least Privilege**: Limit sharing and access to necessary users only
4. **Monitor Activity**: Track flow execution and data access patterns
5. **Document Business Justification**: Maintain records of why sensitive connectors are needed
6. **Review High-Risk Actions**: Audit flows with delete/create/modify capabilities
7. **Environment Segregation**: Use separate environments for production and development
8. **Data Loss Prevention**: Implement DLP policies to prevent data exfiltration

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track Power Platform resource changes
2. **Risk Prioritization**: Focus on CRITICAL and HIGH risk resources first
3. **Connector Governance**: Implement approval process for sensitive connectors
4. **Monitor Activity**: Track flow execution and data access patterns
5. **Document Business Justification**: Maintain records of why sensitive connectors are needed

### For Penetration Testers

1. **Initial Reconnaissance**: Identify Power Platform resources with sensitive connectors
2. **Target Selection**: Prioritize CRITICAL and HIGH risk resources
3. **Data Exfiltration**: Look for flows that read sensitive data and send externally
4. **Privilege Escalation**: Identify flows using Azure AD connector for privilege escalation
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify connector usage aligns with business needs
3. **Trend Analysis**: Compare results over time to track risk trends
4. **Remediation Tracking**: Monitor reduction in high-risk resources
5. **Access Reviews**: Use reports for quarterly Power Platform access certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- ResourceType, Id, DisplayName
- Environment, EnvironmentId
- Owner, OwnerEmail, OwnerId
- CreatedTime, LastModifiedTime
- Status, State, AppType, FlowType, Triggers
- ConnectorCount, Connectors
- HasSensitiveConnector, SensitiveConnectorCount, SensitiveConnectors
- HasHighRiskActions, HighRiskActions
- RiskLevel
- SharedUsers, SharedGroups
- Source

### JSON Export

Structured format for automation:
```json
[
  {
    "ResourceType": "Power Automate Flow",
    "DisplayName": "Data Exfiltration Flow",
    "Environment": "Production",
    "Owner": "John Admin",
    "OwnerEmail": "john.admin@company.com",
    "ConnectorCount": 3,
    "Connectors": "HTTP, Azure Blob Storage, SharePoint Online",
    "HasSensitiveConnector": true,
    "SensitiveConnectorCount": 3,
    "SensitiveConnectors": "HTTP (CRITICAL), Azure Blob Storage (HIGH), SharePoint Online (HIGH)",
    "HasHighRiskActions": true,
    "HighRiskActions": "DeleteFile, CreateFile, UpdateFile",
    "RiskLevel": "CRITICAL"
  }
]
```

## Troubleshooting

### Common Issues

#### 1. "No Power Apps found or access denied"

**Cause**: Insufficient Power Platform permissions.

**Solution**: 
- Ensure you have Power Platform Admin or Environment Maker role
- Try user-scoped enumeration (may work with limited permissions)
- Verify access token has Power Platform API permissions

#### 2. "Admin API access denied"

**Cause**: User doesn't have Power Platform Admin permissions.

**Solution**:
- Script will automatically try user-scoped API
- Request Power Platform Admin role if needed
- Or request Environment Maker role for specific environments

#### 3. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1
# Accept permission consent when prompted
```

#### 4. Module Import Failures

**Cause**: Missing or outdated Microsoft.Graph modules.

**Solution**:
```powershell
# Update all Graph modules
Update-Module Microsoft.Graph -Force

# Or reinstall
Uninstall-Module Microsoft.Graph -AllVersions
Install-Module Microsoft.Graph -Scope CurrentUser
```

#### 5. Slow Performance

**Cause**: Large number of resources or throttling.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -OnlyHighRisk
```

#### 6. Token Issues with Power Platform APIs

**Cause**: Power Platform APIs require separate authentication (different resource than Graph API).

**Solution**:
- **Default**: Script uses device code flow automatically - just follow the browser prompt
- **Azure CLI**: Use `-UseAzCliToken` - script will automatically run `az login` if needed
- **Azure PowerShell**: Use `-UseAzPowerShellToken` - script will automatically run `Connect-AzAccount` if needed
- Ensure you're authenticated to the correct tenant
- The script automatically uses your Graph context account when using `-UseAzPowerShellToken` (no account selection prompt)

#### 7. "Unable to get access token for Power Platform APIs"

**Cause**: Authentication failed or no authentication method available.

**Solution**:
- **Device Code Flow (Default)**: Just run the script - it will prompt for browser authentication
- **Azure CLI**: Install Azure CLI and use `-UseAzCliToken` flag
- **Azure PowerShell**: Install Az module (`Install-Module Az -Scope CurrentUser`) and use `-UseAzPowerShellToken` flag
- The script will automatically handle login for both Azure CLI and Azure PowerShell

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all Power Platform resources
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all resources, risk levels, and connector details.

### Example 2: High-Risk Resource Detection

```powershell
# Find resources with CRITICAL or HIGH risk
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -OnlyHighRisk -Matrix

# Review output, then remediate
```

**Use Case**: Identify immediate security risks for remediation.

### Example 3: Sensitive Connector Audit

```powershell
# Find all resources using sensitive connectors
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -OnlySensitiveConnectors -ExportPath "sensitive-connectors.csv"

# Review and document business justification
```

**Use Case**: Audit connector usage and ensure proper governance.

### Example 4: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using Azure CLI (automatically logs in if needed)
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"

# Or use Azure PowerShell (uses same account as Graph auth)
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -UseAzPowerShellToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of high-value targets during engagement. Both methods automatically handle authentication.

### Example 5: Compliance Reporting

```powershell
# Monthly audit with export
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track resource changes and risk trends over time.

### Example 6: Multi-Tenant Assessment

```powershell
# Scan specific tenant
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -TenantId "customer-tenant-id" -ExportPath "customer-power-platform.csv"

# Repeat for each tenant
```

**Use Case**: MSP or consulting engagement across multiple tenants.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\PowerPlatform_$date.csv"
    
    C:\Tools\Invoke-EntraPowerPlatformCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if critical resources found
    $results = Import-Csv $path
    $critical = $results | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    
    if ($critical.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($critical.Count) critical Power Platform resources found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyPowerPlatformCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Power Platform Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "power_platform_resource"
        severity = $_.RiskLevel
        resource_type = $_.ResourceType
        display_name = $_.DisplayName
        owner = $_.OwnerEmail
        sensitive_connectors = $_.SensitiveConnectorCount
        high_risk_actions = $_.HasHighRiskActions
    }
}

$siemEvents | ConvertTo-Json | Out-File "siem_formatted.json"
```

### PowerShell Remoting

```powershell
# Run remotely on jump box or admin workstation
$session = New-PSSession -ComputerName "admin-server.company.com"

Invoke-Command -Session $session -ScriptBlock {
    cd C:\Tools
    .\scripts\powershell\Invoke-EntraPowerPlatformCheck.ps1 -Matrix -ExportPath "C:\Reports\power-platform.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\power-platform.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Power Apps enumeration with connector analysis
- Power Automate flow enumeration with action analysis
- Sensitive connector detection (30+ connectors)
- High-risk action detection
- Risk assessment framework (CRITICAL/HIGH/MEDIUM/LOW)
- Matrix view and export capabilities
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive resource analytics

## License

This script is part of the EvilMist toolkit.

**Copyright (C) 2025 Logisek**

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See the LICENSE file for more details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

Visit: https://github.com/Logisek/EvilMist

## Support

For questions, issues, or feature requests:
- GitHub Issues: https://github.com/Logisek/EvilMist/issues
- Email: info@logisek.com
- Website: https://logisek.com

## Related Tools

- **Invoke-EntraRecon.ps1**: Comprehensive Azure AD reconnaissance
- **Invoke-EntraAppAccess.ps1**: Critical administrative application access check
- **Invoke-EntraServicePrincipalCheck.ps1**: Service principal security check

---

