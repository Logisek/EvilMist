# Invoke-EntraDeviceCheck.ps1

## Overview

`Invoke-EntraDeviceCheck.ps1` is a PowerShell 7+ script designed to analyze Azure Entra ID registered devices to identify security risks, compliance gaps, and device trust issues. This tool is part of the EvilMist toolkit and helps security teams assess device trust, compliance status, and identify potential security risks from unmanaged or non-compliant devices.

## Purpose

Device trust and compliance are critical security controls that ensure only trusted, compliant devices can access organizational resources. This script helps:
- **Security Auditors**: Identify non-compliant devices and security risks
- **Penetration Testers**: Discover unmanaged devices and BYOD devices that may be vulnerable
- **IT Administrators**: Audit device compliance and management status
- **Compliance Teams**: Generate reports for device governance and compliance

## Features

- ✅ **PowerShell 7+ Compatible**: Modern PowerShell for cross-platform support
- ✅ **Multiple Authentication Methods**: Supports Azure CLI, Azure PowerShell, and interactive auth
- ✅ **Comprehensive Device Enumeration**: Enumerates all registered devices in the tenant
- ✅ **Compliance Status Detection**: Identifies compliant, non-compliant, and unknown compliance devices
- ✅ **BYOD Detection**: Automatically identifies personal/BYOD devices
- ✅ **Stale Sign-In Detection**: Identifies devices with stale sign-ins (>90 days)
- ✅ **Device Trust Analysis**: Analyzes join types (Azure AD Joined, Hybrid Joined, Registered)
- ✅ **Management Status**: Identifies managed vs unmanaged devices
- ✅ **Intune Compliance Policies**: Enumerates Intune compliance policies and assignments
- ✅ **Risk Assessment**: Categorizes devices by risk level (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ **Activity Analytics**: Sign-in statistics, stale devices, registration dates
- ✅ **Stealth Mode**: Configurable delays and jitter to avoid detection
- ✅ **Export Options**: CSV and JSON export formats
- ✅ **Matrix View**: Table format with analytics for quick visual scanning
- ✅ **Filtering Options**: Show only non-compliant, BYOD, or stale devices

## Device Trust Types Analyzed

The script analyzes devices based on their trust type and join method:

### Azure AD Joined
- Devices directly joined to Azure AD
- Typically corporate-owned devices
- Full device management capabilities
- **Risk Level**: LOW (when compliant and managed)

### Hybrid Azure AD Joined
- Devices joined to on-premises AD and synced to Azure AD
- Typically corporate-managed devices
- Requires on-premises infrastructure
- **Risk Level**: LOW (when compliant and managed)

### Azure AD Registered (BYOD)
- Personal devices registered with Azure AD
- Bring Your Own Device (BYOD) scenario
- Limited management capabilities
- **Risk Level**: MEDIUM to HIGH (depending on compliance)

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
   Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
   ```

### Required Permissions

The script requires the following Microsoft Graph API permissions:

- **Primary Scopes** (preferred):
  - `Device.Read.All` - Read all devices
  - `Directory.Read.All` - Read directory data
  - `DeviceManagementManagedDevices.Read.All` - Read Intune managed devices (optional)
  - `DeviceManagementConfiguration.Read.All` - Read Intune compliance policies (optional)

- **Fallback Scopes** (if full access unavailable):
  - `Device.Read.All` - Read all devices
  - `Directory.Read.All` - Read directory data

**Note**: If `DeviceManagementConfiguration.Read.All` is not available, the script will continue without Intune compliance policy data. All other features will work normally.

## Usage

### Basic Usage

```powershell
# Simple scan of all devices
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1
```

### Export Results

```powershell
# Export to CSV
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -ExportPath "devices.csv"

# Export to JSON
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -ExportPath "device-results.json"
```

### Include Disabled Devices

```powershell
# Scan all devices including disabled ones
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -IncludeDisabled -ExportPath "all-devices.csv"
```

### Show Only Non-Compliant Devices

```powershell
# Filter to show only non-compliant devices
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyNonCompliant

# Matrix view with non-compliant filter
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyNonCompliant -Matrix
```

### Show Only BYOD Devices

```powershell
# Filter to show only BYOD/personal devices
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyBYOD

# Export BYOD devices
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyBYOD -ExportPath "byod-devices.csv"
```

### Show Only Stale Devices

```powershell
# Filter to show only devices with stale sign-ins (>90 days)
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyStale

# Matrix view with stale filter
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyStale -Matrix
```

### Matrix View

```powershell
# Display results in compact matrix format
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -Matrix

# Matrix view with export
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -Matrix -ExportPath "results.csv"
```

### Alternative Authentication Methods

```powershell
# Use Azure CLI cached credentials
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -UseAzCliToken

# Use Azure PowerShell cached credentials
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -UseAzPowerShellToken

# Specify tenant
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -TenantId "your-tenant-id"
```

### Stealth Mode

```powershell
# Enable stealth mode with default settings (500ms delay + 300ms jitter)
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -EnableStealth

# Stealth mode with minimal output
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -EnableStealth -QuietStealth

# Custom delay and jitter
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -RequestDelay 1.5 -RequestJitter 0.5

# Maximum stealth with custom retry
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -EnableStealth -MaxRetries 5 -QuietStealth
```

### Advanced Combinations

```powershell
# Comprehensive audit: all devices, all statuses, with export
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -IncludeDisabled -Matrix -ExportPath "full-audit.csv"

# Security focus: high-risk devices only (non-compliant)
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyNonCompliant -Matrix -ExportPath "high-risk-devices.csv"

# BYOD audit with export
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyBYOD -Matrix -ExportPath "byod-audit.csv"

# Stale device cleanup preparation
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyStale -ExportPath "stale-devices.csv"

# Stealth reconnaissance with Azure CLI token
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "recon.json"
```

## Parameters

### General Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-ExportPath` | String | Path to export results (CSV or JSON based on extension) | None |
| `-TenantId` | String | Optional Tenant ID. Uses home tenant if not specified | None |
| `-UseAzCliToken` | Switch | Try to use Azure CLI cached token first | False |
| `-UseAzPowerShellToken` | Switch | Try to use Azure PowerShell cached token first | False |
| `-IncludeDisabled` | Switch | Include disabled devices in results | False |
| `-OnlyNonCompliant` | Switch | Show only non-compliant devices | False |
| `-OnlyBYOD` | Switch | Show only BYOD/personal devices | False |
| `-OnlyStale` | Switch | Show only devices with stale sign-ins (>90 days) | False |
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

The script provides detailed information about each device:

```
[CRITICAL] LAPTOP-ABC123
  Device ID: abc12345-6789-0123-4567-890123456789
  Operating System: Windows 10.0.19045
  Join Type: Azure AD Joined
  Compliance Status: Non-compliant
  Managed: Yes
  Device Ownership: Company
  Risk Reasons: Non-compliant
  Management Type: Intune
  Registered: 2024-01-15T10:30:00Z (342 days ago)
  Last Sign-In: 2024-12-20 14:23:45 (3 days ago)
  Account Status: Enabled
  Manufacturer: Dell Inc.
  Model: Latitude 5520
  Enrollment Type: WindowsAutopilot
```

### Matrix Output (with `-Matrix`)

```
Risk      Compliant  Managed  BYOD  Join Type              Device Name      OS        Last Sign-In  Status
----      ---------  -------  ----  ---------              ------------    --        ------------  ------
CRITICAL  No         Yes      No    Azure AD Joined        LAPTOP-ABC123   Windows   3d ago        Enabled
HIGH      Unknown    No       No    Azure AD Registered     PHONE-XYZ789    Android   120d ago      Enabled
MEDIUM    Yes        No       Yes   Azure AD Registered     TABLET-DEF456   iOS       5d ago        Enabled
LOW       Yes        Yes      No    Hybrid Azure AD Joined DESKTOP-GHI789  Windows   1d ago        Enabled
```

### Summary Statistics

The script provides comprehensive statistics:

```
[SUMMARY]
Total devices analyzed: 150
  - CRITICAL risk: 5
  - HIGH risk: 12
  - MEDIUM risk: 25
  - LOW risk: 108

[COMPLIANCE STATUS]
  Compliant: 120
  Non-compliant: 5
  Compliance unknown: 25

[MANAGEMENT STATUS]
  Managed: 130
  Unmanaged: 20

[DEVICE TYPES]
  BYOD/Personal: 35
  Corporate: 115

[JOIN TYPES]
  Azure AD Joined: 80
  Hybrid Azure AD Joined: 35
  Azure AD Registered (BYOD): 35

[ACTIVITY STATUS]
  Stale sign-ins (>90 days): 8
  Disabled devices: 3

[INTUNE COMPLIANCE POLICIES]
  Total policies: 5
  (Use detailed view to see policy assignments)
```

## Risk Levels

The script assigns risk levels based on device compliance, management status, and activity:

| Risk Level | Criteria | Color | Recommendation |
|------------|----------|-------|----------------|
| **CRITICAL** | Non-compliant device | Red | **IMMEDIATE ACTION REQUIRED**: Remediate compliance issues or remove device |
| **HIGH** | Compliance unknown OR unmanaged device OR stale sign-in (>90 days) | Yellow | **REVIEW REQUIRED**: Investigate and remediate |
| **MEDIUM** | BYOD device OR disabled device | Cyan | **MONITOR**: May require policy review |
| **LOW** | Compliant, managed, active device | Green | **ACCEPTABLE**: No action required |

### Risk Assessment Logic

```
IF device is non-compliant:
    RISK = CRITICAL (Security risk - device may not meet security requirements)
ELSE IF compliance unknown OR unmanaged OR stale sign-in:
    RISK = HIGH (Security concern - needs investigation)
ELSE IF BYOD device OR disabled:
    RISK = MEDIUM (May require policy review)
ELSE:
    RISK = LOW (Compliant, managed, active device)
```

## Security Considerations

### Why Device Trust Matters

Devices are a critical attack surface in modern organizations:
- **Credential Theft**: Compromised devices can steal credentials and tokens
- **Data Exfiltration**: Unmanaged devices may not have data protection controls
- **Compliance Violations**: Non-compliant devices may violate security policies
- **Lateral Movement**: Compromised devices can be used to access other resources
- **Privilege Escalation**: Devices with elevated access can be exploited

### High-Risk Scenarios

1. **Non-Compliant Devices** (CRITICAL Risk)
   - Devices failing compliance policies
   - May not have required security controls (encryption, antivirus, etc.)
   - Can be blocked by Conditional Access policies
   - Immediate remediation required

2. **Unmanaged Devices** (HIGH Risk)
   - Devices not managed by Intune or other MDM
   - Cannot enforce security policies
   - Cannot remotely wipe or manage
   - May not be visible to security teams

3. **BYOD Devices** (MEDIUM Risk)
   - Personal devices accessing corporate resources
   - May not be subject to same security controls
   - User privacy concerns limit management capabilities
   - Requires careful policy balancing

4. **Stale Devices** (HIGH Risk)
   - Devices not used for 90+ days
   - May indicate abandoned or compromised devices
   - Should be reviewed and potentially removed
   - May have outdated security configurations

5. **Compliance Unknown** (HIGH Risk)
   - Devices where compliance status cannot be determined
   - May indicate policy misconfiguration
   - Requires investigation to determine actual status

### Device Trust Best Practices

1. **Enforce Device Compliance**: Use Conditional Access to require compliant devices
2. **Manage All Devices**: Enroll all corporate devices in Intune or MDM
3. **Monitor BYOD**: Implement app protection policies for BYOD devices
4. **Regular Audits**: Review device inventory regularly and remove stale devices
5. **Policy Enforcement**: Ensure compliance policies are properly assigned and enforced

## Best Practices

### For Security Teams

1. **Regular Audits**: Run monthly to track device compliance and management status
2. **Remediation**: Prioritize CRITICAL and HIGH risk devices for immediate action
3. **Policy Review**: Ensure Intune compliance policies are properly configured
4. **Stale Device Cleanup**: Review and remove devices with stale sign-ins
5. **BYOD Governance**: Implement clear policies for personal device access

### For Penetration Testers

1. **Initial Reconnaissance**: Identify unmanaged and non-compliant devices
2. **Target Selection**: Focus on HIGH and CRITICAL risk devices
3. **Attack Surface**: Unmanaged devices may have weaker security controls
4. **Lateral Movement**: Compromised devices can be used for further access
5. **Stealth Operations**: Use `-EnableStealth` to avoid detection

### For Compliance

1. **Documentation**: Export results regularly for audit trails
2. **Policy Alignment**: Verify device compliance aligns with security policies
3. **Trend Analysis**: Compare results over time to track improvements
4. **Remediation Tracking**: Monitor compliance rates and device management adoption
5. **Access Reviews**: Use reports for quarterly device access certification

## Export Formats

### CSV Export

Includes all fields for analysis:
- DeviceId, DisplayName, OperatingSystem, OSVersion
- TrustType, JoinType, IsCompliant, IsManaged
- ManagementType, DeviceOwnership, IsBYOD
- RegistrationDateTime, DaysSinceRegistration
- ApproximateLastSignInDateTime, DaysSinceLastSignIn, IsStale
- AccountEnabled, Manufacturer, Model, EnrollmentType
- RiskLevel, RiskReasons

### JSON Export

Structured format for automation:
```json
{
  "Devices": [
    {
      "DeviceId": "abc12345-6789-0123-4567-890123456789",
      "DisplayName": "LAPTOP-ABC123",
      "OperatingSystem": "Windows",
      "OSVersion": "10.0.19045",
      "TrustType": "AzureAd",
      "JoinType": "Azure AD Joined",
      "IsCompliant": false,
      "IsManaged": true,
      "IsBYOD": false,
      "RiskLevel": "CRITICAL",
      "RiskReasons": "Non-compliant",
      "DaysSinceLastSignIn": 3,
      "IsStale": false
    }
  ],
  "CompliancePolicies": [
    {
      "Id": "policy-id",
      "DisplayName": "Windows Compliance Policy",
      "Assignments": []
    }
  ],
  "Summary": {
    "TotalDevicesScanned": 150,
    "TotalDevicesAnalyzed": 150,
    "CriticalRisk": 5,
    "HighRisk": 12,
    "MediumRisk": 25,
    "LowRisk": 108,
    "NonCompliant": 5,
    "BYOD": 35,
    "Stale": 8
  }
}
```

## Troubleshooting

### Common Issues

#### 1. "No devices found"

**Cause**: No devices registered in the tenant or insufficient permissions.

**Solution**: 
- Verify you have `Device.Read.All` permission
- Check if devices exist in Azure AD portal
- Ensure devices are actually registered (not just Intune enrolled)

#### 2. "Access denied" for Intune compliance policies

**Cause**: Insufficient permissions for Intune data.

**Solution**:
```powershell
# The script will continue without Intune data
# To get Intune compliance policies, ensure you have:
# DeviceManagementConfiguration.Read.All permission
```

#### 3. Permission Errors

**Cause**: Insufficient Graph API permissions.

**Solution**:
```powershell
# Disconnect and reconnect with proper scopes
Disconnect-MgGraph
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1
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

**Cause**: Large number of devices or throttling.

**Solution**:
```powershell
# Use stealth mode to handle throttling
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -EnableStealth -MaxRetries 5

# Or reduce load with filtering
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyNonCompliant
```

## Examples

### Example 1: Basic Security Audit

```powershell
# Identify all devices and their compliance status
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -Matrix -ExportPath "audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

**Output**: CSV file with all devices, risk levels, and compliance status.

### Example 2: Non-Compliant Device Detection

```powershell
# Find all non-compliant devices
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyNonCompliant -Matrix

# Review output, then remediate
```

**Use Case**: Identify immediate security risks for remediation.

### Example 3: BYOD Audit

```powershell
# Audit all BYOD/personal devices
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyBYOD -Matrix -ExportPath "byod-audit.csv"
```

**Use Case**: Review personal device access and compliance.

### Example 4: Stale Device Cleanup

```powershell
# Find devices with stale sign-ins for cleanup
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -OnlyStale -ExportPath "stale-devices.csv"

# Review and remove unused devices
```

**Use Case**: Identify and remove abandoned or compromised devices.

### Example 5: Compliance Reporting

```powershell
# Monthly audit including disabled devices
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -IncludeDisabled -Matrix -ExportPath "compliance_report.csv"

# Compare with previous month's report
```

**Use Case**: Track device compliance and management over time.

### Example 6: Penetration Test Reconnaissance

```powershell
# Stealth mode scan using existing Azure CLI token
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -UseAzCliToken -EnableStealth -QuietStealth -ExportPath "targets.json"
```

**Use Case**: Silent enumeration of device attack surface during engagement.

## Advanced Usage

### Scripted Automation

```powershell
# Schedule weekly scans
$scheduledScript = {
    $date = Get-Date -Format "yyyy-MM-dd"
    $path = "C:\SecurityAudits\DeviceCheck_$date.csv"
    
    C:\Tools\Invoke-EntraDeviceCheck.ps1 -Matrix -ExportPath $path
    
    # Send alert if critical devices found
    $results = Import-Csv $path
    $critical = $results | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    
    if ($critical.Count -gt 0) {
        Send-MailMessage -To "security@company.com" `
            -Subject "ALERT: $($critical.Count) critical risk devices found" `
            -Body "Review attached report." `
            -Attachments $path `
            -SmtpServer "smtp.company.com"
    }
}

# Create scheduled task (run as admin)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\Scripts\WeeklyDeviceCheck.ps1"
Register-ScheduledTask -TaskName "Weekly Device Audit" -Trigger $trigger -Action $action
```

### Integration with SIEM

```powershell
# Export JSON for SIEM ingestion
.\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -ExportPath "siem_feed.json"

# Post-process for your SIEM format
$results = Get-Content "siem_feed.json" | ConvertFrom-Json

$siemEvents = $results.Devices | ForEach-Object {
    @{
        timestamp = (Get-Date).ToString("o")
        event_type = "azure_device_check"
        severity = $_.RiskLevel
        device_id = $_.DeviceId
        device_name = $_.DisplayName
        is_compliant = $_.IsCompliant
        is_managed = $_.IsManaged
        is_byod = $_.IsBYOD
        days_since_signin = $_.DaysSinceLastSignIn
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
    .\scripts\powershell\Invoke-EntraDeviceCheck.ps1 -Matrix -ExportPath "C:\Reports\devices.csv"
}

# Retrieve results
Copy-Item -FromSession $session -Path "C:\Reports\devices.csv" -Destination ".\local_copy.csv"

Remove-PSSession $session
```

## Change Log

### Version 1.0 (Initial Release)
- Initial implementation
- Device enumeration and compliance analysis
- BYOD detection and stale sign-in tracking
- Intune compliance policy enumeration
- Risk assessment and matrix view
- Stealth mode with configurable delays
- Multiple authentication methods
- Comprehensive device analytics

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
- **Invoke-EntraMFACheck.ps1**: MFA compliance audit
- **Invoke-EntraGuestCheck.ps1**: Guest account security analysis
- **Invoke-EntraAppAccess.ps1**: Critical administrative access audit
- **Invoke-EntraRoleCheck.ps1**: Privileged role assignment audit
- **Invoke-EntraServicePrincipalCheck.ps1**: Service principal security audit
- **Invoke-EntraConditionalAccessCheck.ps1**: Conditional Access policy security audit

---

