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
    Performs Azure Entra ID compliance assessment with CIS/NIST benchmark mapping.

.DESCRIPTION
    This script performs a comprehensive compliance assessment of Azure Entra ID configuration
    and maps findings to industry-standard compliance frameworks including:
    
    - CIS Microsoft Azure Foundations Benchmark (v2.0/v2.1)
    - NIST 800-53 Rev 5 Security Controls
    - SOC 2 Type II Trust Service Criteria
    - ISO 27001:2022 Controls
    - GDPR Compliance Indicators
    
    The script evaluates security configurations against these frameworks and generates
    detailed compliance reports with control mappings, gap analysis, and remediation guidance.
    
    Assessment areas include:
    - Identity and Access Management (MFA, roles, permissions)
    - Conditional Access and Zero Trust controls
    - Application and Service Principal security
    - Password and authentication policies
    - Logging and monitoring configuration
    - Data protection and privacy controls

.PARAMETER ExportPath
    Optional path to export results (CSV, JSON, or HTML based on extension).

.PARAMETER TenantId
    Optional Tenant ID. If not specified, uses the user's home tenant.

.PARAMETER UseAzCliToken
    Try to use Azure CLI cached token first.

.PARAMETER UseAzPowerShellToken
    Try to use Azure PowerShell cached token first.

.PARAMETER EnableStealth
    Enable stealth mode with default delays and jitter to avoid detection.

.PARAMETER RequestDelay
    Base delay in seconds between API requests (0-60). Default: 0

.PARAMETER RequestJitter
    Random jitter range in seconds to add/subtract from delay (0-30). Default: 0

.PARAMETER MaxRetries
    Maximum retries on throttling (429) responses (1-10). Default: 3

.PARAMETER QuietStealth
    Suppress stealth-related status messages.

.PARAMETER Framework
    Compliance framework to focus on: CIS, NIST, SOC2, ISO27001, GDPR, or All. Default: All

.PARAMETER ControlFamily
    Filter by control family (e.g., "AC" for Access Control in NIST, "1" for CIS section 1)

.PARAMETER OnlyFailed
    Show only failed/non-compliant controls.

.PARAMETER OnlyPassed
    Show only passed/compliant controls.

.PARAMETER MinimumSeverity
    Minimum severity level to report: Critical, High, Medium, Low. Default: Low

.PARAMETER IncludeRemediation
    Include detailed remediation steps in the output.

.PARAMETER GenerateExecutiveReport
    Generate an executive summary report with compliance scores.

.PARAMETER Matrix
    Display results in a matrix/table format for easier analysis.

.EXAMPLE
    .\Invoke-EntraComplianceCheck.ps1
    # Perform comprehensive compliance assessment against all frameworks

.EXAMPLE
    .\Invoke-EntraComplianceCheck.ps1 -Framework CIS -ExportPath "cis-compliance.csv"
    # Assess against CIS benchmark and export to CSV

.EXAMPLE
    .\Invoke-EntraComplianceCheck.ps1 -Framework NIST -ControlFamily AC -Matrix
    # Assess NIST Access Control family in matrix format

.EXAMPLE
    .\Invoke-EntraComplianceCheck.ps1 -OnlyFailed -GenerateExecutiveReport -ExportPath "report.html"
    # Generate executive report showing only failed controls

.EXAMPLE
    .\Invoke-EntraComplianceCheck.ps1 -Framework SOC2 -IncludeRemediation -ExportPath "soc2-gaps.json"
    # SOC 2 assessment with remediation guidance

.EXAMPLE
    .\Invoke-EntraComplianceCheck.ps1 -EnableStealth -QuietStealth
    # Run in stealth mode with minimal output
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [switch]$UseAzCliToken,

    [Parameter(Mandatory = $false)]
    [switch]$UseAzPowerShellToken,

    # Stealth & Evasion Parameters
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
    [ValidateSet("CIS", "NIST", "SOC2", "ISO27001", "GDPR", "All")]
    [string]$Framework = "All",

    [Parameter(Mandatory = $false)]
    [string]$ControlFamily,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyFailed,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyPassed,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Critical", "High", "Medium", "Low")]
    [string]$MinimumSeverity = "Low",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeRemediation,

    [Parameter(Mandatory = $false)]
    [switch]$GenerateExecutiveReport,

    [Parameter(Mandatory = $false)]
    [switch]$Matrix
)

# PowerShell 7+ required
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] This script requires PowerShell 7 or later.' -ForegroundColor Red
    Write-Host ('Current version: PowerShell ' + $PSVersionTable.PSVersion.ToString()) -ForegroundColor Yellow
    Write-Host 'Download PowerShell 7: https://aka.ms/powershell-release?tag=stable' -ForegroundColor Cyan
    exit 1
}

$ErrorActionPreference = "Continue"

# Severity ranking for filtering
$script:SeverityRank = @{
    "Critical" = 4
    "High" = 3
    "Medium" = 2
    "Low" = 1
}

# Compliance Control Mappings Database
# Maps each security check to relevant compliance framework controls
$script:ComplianceControls = @(
    # === MFA Controls ===
    @{
        Id = "IAM-MFA-001"
        Title = "Require MFA for all users"
        Description = "Multi-factor authentication should be required for all user accounts to reduce the risk of credential theft."
        Category = "Identity and Access Management"
        CheckType = "MFA"
        Severity = "Critical"
        CIS = @{ Control = "1.1.1"; Version = "2.0"; Description = "Ensure Security Defaults is enabled or MFA is enforced" }
        NIST = @{ Control = "IA-2(1)"; Family = "IA"; Description = "Identification and Authentication: Multi-factor Authentication to Privileged Accounts" }
        SOC2 = @{ Criteria = "CC6.1"; Category = "Logical and Physical Access Controls"; Description = "The entity implements logical access security measures" }
        ISO27001 = @{ Control = "A.5.15"; Description = "Access control - Identification and authentication" }
        GDPR = @{ Article = "32"; Description = "Security of processing - appropriate technical measures" }
        Remediation = "Enable MFA for all users through Conditional Access policies or Security Defaults. Use Azure AD Identity Protection for risk-based MFA."
    },
    @{
        Id = "IAM-MFA-002"
        Title = "Require MFA for privileged accounts"
        Description = "Privileged accounts (admins, Global Administrators) must have MFA enforced."
        Category = "Identity and Access Management"
        CheckType = "MFA-Privileged"
        Severity = "Critical"
        CIS = @{ Control = "1.1.2"; Version = "2.0"; Description = "Ensure MFA is enabled for all users in administrative roles" }
        NIST = @{ Control = "IA-2(1)"; Family = "IA"; Description = "Multi-factor Authentication to Privileged Accounts" }
        SOC2 = @{ Criteria = "CC6.1"; Category = "Logical and Physical Access Controls"; Description = "Privileged access requires stronger authentication" }
        ISO27001 = @{ Control = "A.8.2"; Description = "Privileged access rights" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Create a Conditional Access policy requiring MFA for all directory roles. Use Azure AD Privileged Identity Management for just-in-time access."
    },
    @{
        Id = "IAM-MFA-003"
        Title = "Require MFA for guest users"
        Description = "Guest users accessing organizational resources should be required to use MFA."
        Category = "Identity and Access Management"
        CheckType = "MFA-Guest"
        Severity = "High"
        CIS = @{ Control = "1.1.3"; Version = "2.0"; Description = "Ensure MFA is enabled for all guest users" }
        NIST = @{ Control = "IA-8(4)"; Family = "IA"; Description = "Identification and Authentication - Use of PIV-I Credentials" }
        SOC2 = @{ Criteria = "CC6.3"; Category = "Logical and Physical Access Controls"; Description = "External parties are properly authenticated" }
        ISO27001 = @{ Control = "A.5.19"; Description = "Information security in supplier relationships" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Create a Conditional Access policy targeting guest users requiring MFA. Configure cross-tenant access settings appropriately."
    },
    
    # === Conditional Access Controls ===
    @{
        Id = "IAM-CA-001"
        Title = "Block legacy authentication protocols"
        Description = "Legacy authentication protocols (POP, IMAP, SMTP) should be blocked as they don't support MFA."
        Category = "Identity and Access Management"
        CheckType = "LegacyAuth"
        Severity = "Critical"
        CIS = @{ Control = "1.1.4"; Version = "2.0"; Description = "Ensure legacy authentication is blocked" }
        NIST = @{ Control = "IA-2(12)"; Family = "IA"; Description = "Acceptance of PIV Credentials from Other Agencies" }
        SOC2 = @{ Criteria = "CC6.6"; Category = "Logical and Physical Access Controls"; Description = "Secure system authentication" }
        ISO27001 = @{ Control = "A.8.5"; Description = "Secure authentication" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Create a Conditional Access policy blocking legacy authentication. Monitor sign-in logs for legacy auth usage before blocking."
    },
    @{
        Id = "IAM-CA-002"
        Title = "Require Conditional Access policies"
        Description = "Conditional Access policies should be implemented to enforce access controls based on conditions."
        Category = "Identity and Access Management"
        CheckType = "ConditionalAccess"
        Severity = "High"
        CIS = @{ Control = "1.2.1"; Version = "2.0"; Description = "Ensure Conditional Access policies are enabled" }
        NIST = @{ Control = "AC-2(1)"; Family = "AC"; Description = "Account Management - Automated Account Management" }
        SOC2 = @{ Criteria = "CC6.1"; Category = "Logical and Physical Access Controls"; Description = "Logical access security measures" }
        ISO27001 = @{ Control = "A.5.18"; Description = "Access rights" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Implement Conditional Access policies for user sign-in, privileged access, and application access. Use templates for common scenarios."
    },
    @{
        Id = "IAM-CA-003"
        Title = "Block high-risk sign-ins"
        Description = "Sign-ins identified as high-risk by Azure AD Identity Protection should be blocked."
        Category = "Identity and Access Management"
        CheckType = "RiskPolicy"
        Severity = "High"
        CIS = @{ Control = "1.2.2"; Version = "2.0"; Description = "Ensure sign-in risk policy is enabled" }
        NIST = @{ Control = "SI-4"; Family = "SI"; Description = "System Monitoring" }
        SOC2 = @{ Criteria = "CC7.2"; Category = "System Operations"; Description = "Monitor system components" }
        ISO27001 = @{ Control = "A.8.16"; Description = "Monitoring activities" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Enable Azure AD Identity Protection sign-in risk policy. Configure to block high-risk sign-ins and require MFA for medium-risk."
    },
    @{
        Id = "IAM-CA-004"
        Title = "Block high-risk users"
        Description = "Users identified as high-risk by Azure AD Identity Protection should be blocked or remediated."
        Category = "Identity and Access Management"
        CheckType = "UserRiskPolicy"
        Severity = "High"
        CIS = @{ Control = "1.2.3"; Version = "2.0"; Description = "Ensure user risk policy is enabled" }
        NIST = @{ Control = "AC-2(13)"; Family = "AC"; Description = "Disable Accounts for High-Risk Individuals" }
        SOC2 = @{ Criteria = "CC7.2"; Category = "System Operations"; Description = "Anomaly detection and response" }
        ISO27001 = @{ Control = "A.8.16"; Description = "Monitoring activities" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Enable Azure AD Identity Protection user risk policy. Configure to require password change for high-risk users."
    },
    
    # === Privileged Access Controls ===
    @{
        Id = "IAM-PA-001"
        Title = "Limit Global Administrator count"
        Description = "The number of Global Administrators should be minimized (recommended: 2-5)."
        Category = "Privileged Access"
        CheckType = "GlobalAdminCount"
        Severity = "Critical"
        CIS = @{ Control = "1.3"; Version = "2.0"; Description = "Ensure fewer than 5 Global Administrators" }
        NIST = @{ Control = "AC-6(5)"; Family = "AC"; Description = "Least Privilege - Privileged Accounts" }
        SOC2 = @{ Criteria = "CC6.2"; Category = "Logical and Physical Access Controls"; Description = "Restrict access to privileged functions" }
        ISO27001 = @{ Control = "A.8.2"; Description = "Privileged access rights" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Reduce Global Administrator count. Use PIM for eligible assignments. Assign more specific roles where possible."
    },
    @{
        Id = "IAM-PA-002"
        Title = "Enable Privileged Identity Management"
        Description = "PIM should be used for just-in-time privileged access with approval workflows."
        Category = "Privileged Access"
        CheckType = "PIM"
        Severity = "Critical"
        CIS = @{ Control = "1.4"; Version = "2.0"; Description = "Ensure PIM is used to manage privileged access" }
        NIST = @{ Control = "AC-2(7)"; Family = "AC"; Description = "Privileged User Accounts" }
        SOC2 = @{ Criteria = "CC6.2"; Category = "Logical and Physical Access Controls"; Description = "Time-limited privileged access" }
        ISO27001 = @{ Control = "A.8.2"; Description = "Privileged access rights" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Enable Azure AD PIM. Convert permanent admin assignments to eligible. Configure approval and MFA requirements."
    },
    @{
        Id = "IAM-PA-003"
        Title = "Configure PIM approval for critical roles"
        Description = "Critical roles (Global Admin, Privileged Role Admin) should require approval for activation."
        Category = "Privileged Access"
        CheckType = "PIM-Approval"
        Severity = "High"
        CIS = @{ Control = "1.4.1"; Version = "2.0"; Description = "Ensure PIM requires approval for critical roles" }
        NIST = @{ Control = "AC-6(1)"; Family = "AC"; Description = "Authorize Access to Security Functions" }
        SOC2 = @{ Criteria = "CC6.2"; Category = "Logical and Physical Access Controls"; Description = "Approval for privileged access" }
        ISO27001 = @{ Control = "A.8.2"; Description = "Privileged access rights" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Configure PIM role settings to require approval for Global Administrator and other critical roles."
    },
    
    # === Password Policy Controls ===
    @{
        Id = "IAM-PWD-001"
        Title = "Disable password expiration"
        Description = "NIST guidelines recommend disabling periodic password expiration in favor of compromised password detection."
        Category = "Password Policy"
        CheckType = "PasswordExpiration"
        Severity = "Medium"
        CIS = @{ Control = "1.5"; Version = "2.0"; Description = "Ensure password expiration policy follows NIST guidelines" }
        NIST = @{ Control = "IA-5(1)"; Family = "IA"; Description = "Password-Based Authentication" }
        SOC2 = @{ Criteria = "CC6.1"; Category = "Logical and Physical Access Controls"; Description = "Password management" }
        ISO27001 = @{ Control = "A.5.17"; Description = "Authentication information" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Set password expiration to 'never expire' in Azure AD. Enable Azure AD Password Protection for compromised password detection."
    },
    @{
        Id = "IAM-PWD-002"
        Title = "Enable banned password list"
        Description = "Azure AD Password Protection should be enabled to prevent common and organization-specific weak passwords."
        Category = "Password Policy"
        CheckType = "BannedPasswords"
        Severity = "High"
        CIS = @{ Control = "1.5.1"; Version = "2.0"; Description = "Ensure custom banned password list is configured" }
        NIST = @{ Control = "IA-5(1)"; Family = "IA"; Description = "Password-Based Authentication" }
        SOC2 = @{ Criteria = "CC6.1"; Category = "Logical and Physical Access Controls"; Description = "Password strength requirements" }
        ISO27001 = @{ Control = "A.5.17"; Description = "Authentication information" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Enable Azure AD Password Protection. Add organization-specific terms to the custom banned password list."
    },
    @{
        Id = "IAM-PWD-003"
        Title = "Configure Self-Service Password Reset"
        Description = "SSPR should be enabled with proper security controls (MFA, security questions)."
        Category = "Password Policy"
        CheckType = "SSPR"
        Severity = "Medium"
        CIS = @{ Control = "1.5.2"; Version = "2.0"; Description = "Ensure SSPR is enabled and properly configured" }
        NIST = @{ Control = "IA-5(1)"; Family = "IA"; Description = "Password-Based Authentication" }
        SOC2 = @{ Criteria = "CC6.1"; Category = "Logical and Physical Access Controls"; Description = "Password reset controls" }
        ISO27001 = @{ Control = "A.5.17"; Description = "Authentication information" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Enable SSPR for all users. Require at least 2 authentication methods. Enable notification on password reset."
    },
    
    # === Application Security Controls ===
    @{
        Id = "APP-SEC-001"
        Title = "Restrict user consent for applications"
        Description = "Users should not be able to consent to applications accessing organizational data without admin approval."
        Category = "Application Security"
        CheckType = "UserConsent"
        Severity = "High"
        CIS = @{ Control = "2.1"; Version = "2.0"; Description = "Ensure users cannot consent to applications" }
        NIST = @{ Control = "AC-6"; Family = "AC"; Description = "Least Privilege" }
        SOC2 = @{ Criteria = "CC6.7"; Category = "Logical and Physical Access Controls"; Description = "Third-party access management" }
        ISO27001 = @{ Control = "A.5.19"; Description = "Information security in supplier relationships" }
        GDPR = @{ Article = "28"; Description = "Processor - data processing agreements" }
        Remediation = "Configure user consent settings to require admin approval. Set 'Users can consent to apps' to 'No' or use consent workflow."
    },
    @{
        Id = "APP-SEC-002"
        Title = "Review high-privilege application permissions"
        Description = "Applications with high-privilege Graph API permissions should be reviewed and justified."
        Category = "Application Security"
        CheckType = "AppPermissions"
        Severity = "High"
        CIS = @{ Control = "2.2"; Version = "2.0"; Description = "Review applications with high-privilege permissions" }
        NIST = @{ Control = "AC-6(10)"; Family = "AC"; Description = "Prohibit Non-Privileged Users from Executing Privileged Functions" }
        SOC2 = @{ Criteria = "CC6.1"; Category = "Logical and Physical Access Controls"; Description = "Application access controls" }
        ISO27001 = @{ Control = "A.8.9"; Description = "Configuration management" }
        GDPR = @{ Article = "25"; Description = "Data protection by design and by default" }
        Remediation = "Review applications with Mail.ReadWrite.All, Files.ReadWrite.All, User.ReadWrite.All permissions. Remove unnecessary permissions."
    },
    @{
        Id = "APP-SEC-003"
        Title = "Remove stale application credentials"
        Description = "Application credentials (secrets, certificates) that have not been used should be removed."
        Category = "Application Security"
        CheckType = "StaleAppCredentials"
        Severity = "Medium"
        CIS = @{ Control = "2.3"; Version = "2.0"; Description = "Ensure stale application credentials are removed" }
        NIST = @{ Control = "IA-5(6)"; Family = "IA"; Description = "Credential Protection" }
        SOC2 = @{ Criteria = "CC6.1"; Category = "Logical and Physical Access Controls"; Description = "Credential management" }
        ISO27001 = @{ Control = "A.5.17"; Description = "Authentication information" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Review and remove unused application secrets and certificates. Implement secret rotation policies."
    },
    @{
        Id = "APP-SEC-004"
        Title = "Monitor OAuth consent grants"
        Description = "Existing OAuth consent grants should be reviewed for illicit consent attacks."
        Category = "Application Security"
        CheckType = "OAuthConsent"
        Severity = "Critical"
        CIS = @{ Control = "2.4"; Version = "2.0"; Description = "Review OAuth consent grants regularly" }
        NIST = @{ Control = "AC-6"; Family = "AC"; Description = "Least Privilege" }
        SOC2 = @{ Criteria = "CC6.7"; Category = "Logical and Physical Access Controls"; Description = "Third-party access oversight" }
        ISO27001 = @{ Control = "A.5.19"; Description = "Information security in supplier relationships" }
        GDPR = @{ Article = "28"; Description = "Processor" }
        Remediation = "Review OAuth2PermissionGrants regularly. Remove unused or suspicious consent grants. Investigate admin consent grants."
    },
    
    # === Guest Access Controls ===
    @{
        Id = "IAM-GUEST-001"
        Title = "Restrict guest invitations"
        Description = "Guest invitation settings should be restricted to admins or specific users."
        Category = "External Identity"
        CheckType = "GuestInvitations"
        Severity = "Medium"
        CIS = @{ Control = "3.1"; Version = "2.0"; Description = "Ensure guest invitation settings are restricted" }
        NIST = @{ Control = "AC-2"; Family = "AC"; Description = "Account Management" }
        SOC2 = @{ Criteria = "CC6.3"; Category = "Logical and Physical Access Controls"; Description = "External user access" }
        ISO27001 = @{ Control = "A.5.19"; Description = "Information security in supplier relationships" }
        GDPR = @{ Article = "28"; Description = "Processor" }
        Remediation = "Configure External Collaboration Settings to restrict who can invite guests. Set to 'Admins only' or 'Specific admin roles'."
    },
    @{
        Id = "IAM-GUEST-002"
        Title = "Review stale guest accounts"
        Description = "Guest accounts that have not signed in recently should be reviewed and removed."
        Category = "External Identity"
        CheckType = "StaleGuests"
        Severity = "Medium"
        CIS = @{ Control = "3.2"; Version = "2.0"; Description = "Ensure stale guest accounts are removed" }
        NIST = @{ Control = "AC-2(3)"; Family = "AC"; Description = "Disable Accounts" }
        SOC2 = @{ Criteria = "CC6.2"; Category = "Logical and Physical Access Controls"; Description = "Account lifecycle management" }
        ISO27001 = @{ Control = "A.5.18"; Description = "Access rights" }
        GDPR = @{ Article = "5"; Description = "Principles relating to processing - storage limitation" }
        Remediation = "Review guest accounts with no recent sign-in activity. Remove guests that are no longer needed. Implement Access Reviews."
    },
    @{
        Id = "IAM-GUEST-003"
        Title = "Restrict guest access to directory"
        Description = "Guests should have limited access to enumerate directory objects."
        Category = "External Identity"
        CheckType = "GuestDirectoryAccess"
        Severity = "Medium"
        CIS = @{ Control = "3.3"; Version = "2.0"; Description = "Ensure guest access is restricted" }
        NIST = @{ Control = "AC-3"; Family = "AC"; Description = "Access Enforcement" }
        SOC2 = @{ Criteria = "CC6.1"; Category = "Logical and Physical Access Controls"; Description = "Minimum necessary access" }
        ISO27001 = @{ Control = "A.5.15"; Description = "Access control" }
        GDPR = @{ Article = "25"; Description = "Data protection by design" }
        Remediation = "Configure external collaboration settings to restrict guest access to directory. Set guest access to 'Restricted'."
    },
    
    # === Logging and Monitoring Controls ===
    @{
        Id = "LOG-MON-001"
        Title = "Enable diagnostic logging"
        Description = "Azure AD diagnostic logs should be exported to SIEM or Log Analytics."
        Category = "Logging and Monitoring"
        CheckType = "DiagnosticLogs"
        Severity = "High"
        CIS = @{ Control = "5.1"; Version = "2.0"; Description = "Ensure diagnostic logging is enabled" }
        NIST = @{ Control = "AU-6"; Family = "AU"; Description = "Audit Record Review, Analysis, and Reporting" }
        SOC2 = @{ Criteria = "CC7.2"; Category = "System Operations"; Description = "Security event monitoring" }
        ISO27001 = @{ Control = "A.8.15"; Description = "Logging" }
        GDPR = @{ Article = "30"; Description = "Records of processing activities" }
        Remediation = "Configure Azure AD diagnostic settings to export SignInLogs, AuditLogs to Log Analytics or SIEM."
    },
    @{
        Id = "LOG-MON-002"
        Title = "Configure sign-in log retention"
        Description = "Sign-in logs should be retained for at least 90 days for security investigations."
        Category = "Logging and Monitoring"
        CheckType = "LogRetention"
        Severity = "Medium"
        CIS = @{ Control = "5.2"; Version = "2.0"; Description = "Ensure log retention is configured" }
        NIST = @{ Control = "AU-11"; Family = "AU"; Description = "Audit Record Retention" }
        SOC2 = @{ Criteria = "CC7.2"; Category = "System Operations"; Description = "Log retention" }
        ISO27001 = @{ Control = "A.8.15"; Description = "Logging" }
        GDPR = @{ Article = "30"; Description = "Records of processing activities" }
        Remediation = "Configure Azure AD log export to Log Analytics with appropriate retention. Consider Azure AD P2 for 30-day built-in retention."
    },
    @{
        Id = "LOG-MON-003"
        Title = "Enable Security Alerts"
        Description = "Azure AD Identity Protection and Defender for Cloud Apps alerts should be configured."
        Category = "Logging and Monitoring"
        CheckType = "SecurityAlerts"
        Severity = "High"
        CIS = @{ Control = "5.3"; Version = "2.0"; Description = "Ensure security alerting is enabled" }
        NIST = @{ Control = "SI-4"; Family = "SI"; Description = "System Monitoring" }
        SOC2 = @{ Criteria = "CC7.3"; Category = "System Operations"; Description = "Security incident response" }
        ISO27001 = @{ Control = "A.8.16"; Description = "Monitoring activities" }
        GDPR = @{ Article = "33"; Description = "Notification of a personal data breach" }
        Remediation = "Enable Azure AD Identity Protection. Configure alerts for risky users, risky sign-ins. Integrate with incident response."
    },
    
    # === Data Protection Controls ===
    @{
        Id = "DATA-PROT-001"
        Title = "Enable Security Defaults or Conditional Access"
        Description = "Either Security Defaults or comprehensive Conditional Access policies should be enabled."
        Category = "Data Protection"
        CheckType = "SecurityDefaults"
        Severity = "Critical"
        CIS = @{ Control = "1.1"; Version = "2.0"; Description = "Ensure Security Defaults or CA is enabled" }
        NIST = @{ Control = "AC-17"; Family = "AC"; Description = "Remote Access" }
        SOC2 = @{ Criteria = "CC6.1"; Category = "Logical and Physical Access Controls"; Description = "Baseline security controls" }
        ISO27001 = @{ Control = "A.8.1"; Description = "User endpoint devices" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Enable Security Defaults for basic protection, or implement Conditional Access policies for more granular control."
    },
    @{
        Id = "DATA-PROT-002"
        Title = "Restrict Azure Portal access"
        Description = "Azure Portal and Azure AD admin center access should be restricted through Conditional Access."
        Category = "Data Protection"
        CheckType = "AdminPortalAccess"
        Severity = "Medium"
        CIS = @{ Control = "1.21"; Version = "2.0"; Description = "Ensure Azure Portal access is restricted" }
        NIST = @{ Control = "AC-6(5)"; Family = "AC"; Description = "Privileged Accounts" }
        SOC2 = @{ Criteria = "CC6.2"; Category = "Logical and Physical Access Controls"; Description = "Admin access controls" }
        ISO27001 = @{ Control = "A.8.2"; Description = "Privileged access rights" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Create Conditional Access policy requiring MFA and compliant device for Azure Portal access."
    },
    
    # === Device Security Controls ===
    @{
        Id = "DEV-SEC-001"
        Title = "Require compliant or hybrid-joined devices"
        Description = "Access to organizational resources should require device compliance or hybrid Azure AD join."
        Category = "Device Security"
        CheckType = "DeviceCompliance"
        Severity = "High"
        CIS = @{ Control = "4.1"; Version = "2.0"; Description = "Ensure device compliance is required" }
        NIST = @{ Control = "AC-19"; Family = "AC"; Description = "Access Control for Mobile Devices" }
        SOC2 = @{ Criteria = "CC6.6"; Category = "Logical and Physical Access Controls"; Description = "Device management" }
        ISO27001 = @{ Control = "A.8.1"; Description = "User endpoint devices" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Create Conditional Access policy requiring device to be compliant or hybrid Azure AD joined."
    },
    @{
        Id = "DEV-SEC-002"
        Title = "Enable device registration restrictions"
        Description = "Device registration should be restricted to prevent unauthorized devices from joining Azure AD."
        Category = "Device Security"
        CheckType = "DeviceRegistration"
        Severity = "Medium"
        CIS = @{ Control = "4.2"; Version = "2.0"; Description = "Ensure device registration is restricted" }
        NIST = @{ Control = "IA-3"; Family = "IA"; Description = "Device Identification and Authentication" }
        SOC2 = @{ Criteria = "CC6.6"; Category = "Logical and Physical Access Controls"; Description = "Device registration controls" }
        ISO27001 = @{ Control = "A.8.1"; Description = "User endpoint devices" }
        GDPR = @{ Article = "32"; Description = "Security of processing" }
        Remediation = "Configure device settings to restrict device registration. Require admin approval for device joining."
    }
)

# Required scopes for compliance checking
$script:RequiredScopes = @(
    "Directory.Read.All",
    "Policy.Read.All",
    "User.Read.All",
    "Application.Read.All",
    "AuditLog.Read.All",
    "RoleManagement.Read.Directory",
    "IdentityRiskyUser.Read.All",
    "IdentityRiskEvent.Read.All",
    "UserAuthenticationMethod.Read.All"
)

# Fallback scopes if full access not available
$script:FallbackScopes = @(
    "Directory.Read.All",
    "Policy.Read.All",
    "User.ReadBasic.All"
)

# Track state
$script:CurrentAuthMethod = "MgGraph"
$script:CurrentScopes = @()
$script:AccessToken = $null
$script:ComplianceResults = @()
$script:TenantInfo = $null
$script:StealthConfig = @{
    Enabled = $false
    BaseDelay = 0
    JitterRange = 0
    MaxRetries = 3
    QuietMode = $false
}

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
    Write-Host "    Compliance Check - CIS/NIST/SOC2/ISO27001/GDPR Mapping" -ForegroundColor Yellow
    Write-Host "    https://logisek.com | info@logisek.com"
    Write-Host "    Part of EvilMist Toolkit | github.com/Logisek/EvilMist"
    Write-Host ""
    Write-Host ""
}

# Stealth delay function
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

# Initialize stealth configuration
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
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Identity.SignIns",
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Microsoft.Graph.Applications",
        "Microsoft.Graph.Identity.Governance",
        "Microsoft.Graph.Reports"
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
        
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $scope = if ($isAdmin) { "AllUsers" } else { "CurrentUser" }
        
        foreach ($module in $missingModules) {
            Write-Host "[*] Installing $module (Scope: $scope)..." -ForegroundColor Cyan
            try {
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

# Initialize and import Graph modules
function Initialize-GraphModules {
    Write-Host "[*] Initializing Microsoft Graph modules..." -ForegroundColor Cyan
    
    try {
        # Check if modules are already loaded and working
        $authModule = Get-Module Microsoft.Graph.Authentication
        if ($authModule) {
            Write-Host "[+] Microsoft.Graph.Authentication already loaded (v$($authModule.Version))" -ForegroundColor Green
        }
        else {
            Write-Host "[*] Importing Microsoft.Graph.Authentication..." -ForegroundColor Cyan
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        }
        
        # Import other modules without forcing removal
        $modulesToImport = @(
            "Microsoft.Graph.Users",
            "Microsoft.Graph.Identity.SignIns",
            "Microsoft.Graph.Identity.DirectoryManagement",
            "Microsoft.Graph.Applications",
            "Microsoft.Graph.Identity.Governance",
            "Microsoft.Graph.Reports"
        )
        
        foreach ($moduleName in $modulesToImport) {
            $module = Get-Module $moduleName
            if (-not $module) {
                Write-Host "[*] Importing $moduleName..." -ForegroundColor Cyan
                Import-Module $moduleName -ErrorAction Stop
            }
            else {
                Write-Host "[+] $moduleName already loaded" -ForegroundColor Green
            }
        }
        
        Write-Host "[+] Modules initialized successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to import modules: $_" -ForegroundColor Red
        Write-Host "[*] Try running the following commands to fix module issues:" -ForegroundColor Yellow
        Write-Host "    Disconnect-MgGraph" -ForegroundColor Yellow
        Write-Host "    Remove-Module Microsoft.Graph.* -Force" -ForegroundColor Yellow
        Write-Host "    Update-Module Microsoft.Graph -Force" -ForegroundColor Yellow
        return $false
    }
}

# Validate that a string looks like a valid JWT token
function Test-JwtToken {
    param([string]$Token)
    
    if ([string]::IsNullOrWhiteSpace($Token)) {
        return $false
    }
    
    # JWT tokens have 3 parts separated by dots
    $parts = $Token.Split('.')
    if ($parts.Count -ne 3) {
        return $false
    }
    
    # Each part should be base64url encoded (alphanumeric + - and _)
    foreach ($part in $parts) {
        if ($part -notmatch '^[A-Za-z0-9_-]+$') {
            return $false
        }
    }
    
    return $true
}

# Get a valid access token for Graph API calls
function Get-GraphAccessToken {
    # First check if we already have a valid stored token
    if ($script:AccessToken -and (Test-JwtToken $script:AccessToken)) {
        return $script:AccessToken
    }
    
    $token = $null
    
    # Method 1: Try Azure CLI
    try {
        $cliResult = az account get-access-token --resource https://graph.microsoft.com 2>$null | ConvertFrom-Json
        if ($cliResult -and $cliResult.accessToken) {
            $token = $cliResult.accessToken
            if (Test-JwtToken $token) {
                $script:AccessToken = $token
                return $token
            }
        }
    }
    catch { }
    
    # Method 2: Try Azure PowerShell
    try {
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($azContext) {
            $azToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction SilentlyContinue
            if ($azToken -and $azToken.Token) {
                $token = $azToken.Token
                if (Test-JwtToken $token) {
                    $script:AccessToken = $token
                    return $token
                }
            }
        }
    }
    catch { }
    
    return $null
}

# Track if SDK has failed due to type loading error
$script:SdkFailed = $false

# Graph API call - uses Invoke-MgGraphRequest, falls back to REST if SDK fails
function Invoke-GraphApiRequest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{}
    )
    
    try {
        Invoke-StealthDelay
        
        # Check if we have a stored token (from -UseAzCliToken or -UseAzPowerShellToken or auto-acquired)
        if ($script:AccessToken -and (Test-JwtToken $script:AccessToken)) {
            # Use Invoke-RestMethod with our token
            $requestHeaders = @{
                "Authorization" = "Bearer $($script:AccessToken)"
                "Content-Type" = "application/json"
            }
            
            # Merge any additional headers
            foreach ($key in $Headers.Keys) {
                $requestHeaders[$key] = $Headers[$key]
            }
            
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $requestHeaders -ErrorAction Stop
            return $response
        }
        elseif (-not $script:SdkFailed) {
            # Try Invoke-MgGraphRequest (same as other EvilMist scripts)
            try {
                $mgHeaders = @{}
                foreach ($key in $Headers.Keys) {
                    $mgHeaders[$key] = $Headers[$key]
                }
                
                if ($mgHeaders.Count -gt 0) {
                    $response = Invoke-MgGraphRequest -Method $Method -Uri $Uri -Headers $mgHeaders -ErrorAction Stop
                }
                else {
                    $response = Invoke-MgGraphRequest -Method $Method -Uri $Uri -ErrorAction Stop
                }
                return $response
            }
            catch {
                # Check if this is the known SDK type loading error
                if ($_.Exception.Message -like "*AzureIdentityAccessTokenProvider*" -or 
                    $_.Exception.Message -like "*Could not load type*Microsoft.Graph*") {
                    
                    $script:SdkFailed = $true
                    Write-Host "[!] Graph SDK type loading error detected - attempting Azure CLI fallback..." -ForegroundColor Yellow
                    
                    # Try to get a token from Azure CLI
                    try {
                        $cliResult = az account get-access-token --resource https://graph.microsoft.com 2>$null | ConvertFrom-Json
                        if ($cliResult -and $cliResult.accessToken -and (Test-JwtToken $cliResult.accessToken)) {
                            $script:AccessToken = $cliResult.accessToken
                            Write-Host "[+] Acquired Azure CLI token - using REST API mode" -ForegroundColor Green
                            
                            # Retry with the token
                            return Invoke-GraphApiRequest -Uri $Uri -Method $Method -Headers $Headers
                        }
                    }
                    catch { }
                    
                    # If Azure CLI failed, provide instructions
                    Write-Host "[!] SDK fix required. Run these commands in a new PowerShell window:" -ForegroundColor Red
                    Write-Host "    Disconnect-MgGraph" -ForegroundColor Yellow
                    Write-Host "    Get-Module Microsoft.Graph.* | Remove-Module -Force" -ForegroundColor Yellow
                    Write-Host "    Uninstall-Module Microsoft.Graph -AllVersions -Force" -ForegroundColor Yellow
                    Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor Yellow
                    Write-Host "" -ForegroundColor Yellow
                    Write-Host "[!] Or use Azure CLI: az login && .\Invoke-EvilMist.ps1 -Script EntraComplianceCheck -UseAzCliToken" -ForegroundColor Cyan
                    throw "Graph SDK type loading error - please fix module versions or use -UseAzCliToken"
                }
                throw $_
            }
        }
        else {
            throw "Graph SDK failed and no valid access token available. Use -UseAzCliToken parameter."
        }
    }
    catch {
        throw $_
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
    
    # Interactive authentication with required scopes (same pattern as other EvilMist scripts)
    try {
        $connectParams = @{
            Scopes = $script:RequiredScopes
            NoWelcome = $true
        }
        
        if ($TenantId) {
            $connectParams['TenantId'] = $TenantId
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
            return $false
        }
    }
}

# Get tenant information
function Get-TenantInfo {
    Write-Host "`n[*] Retrieving tenant information..." -ForegroundColor Cyan
    
    try {
        Invoke-StealthDelay
        
        # Try using Get-MgContext first (doesn't require additional API call)
        $context = Get-MgContext
        if ($context) {
            $script:TenantInfo = @{
                TenantId = $context.TenantId
                DisplayName = $context.TenantId  # Will be updated if we can get org info
                VerifiedDomains = "Unknown"
            }
            
            # Try to get org details
            try {
                $org = Get-MgOrganization -ErrorAction Stop
                if ($org) {
                    $script:TenantInfo.DisplayName = $org.DisplayName
                    $defaultDomain = $org.VerifiedDomains | Where-Object { $_.IsDefault } | Select-Object -First 1
                    if ($defaultDomain) {
                        $script:TenantInfo.VerifiedDomains = $defaultDomain.Name
                    }
                }
            }
            catch {
                # Use tenant ID as display name if org info unavailable
                Write-Host "[!] Could not retrieve organization details, using tenant ID" -ForegroundColor Yellow
            }
            
            Write-Host "[+] Tenant: $($script:TenantInfo.DisplayName) ($($script:TenantInfo.TenantId))" -ForegroundColor Green
            return $true
        }
        else {
            throw "No Graph context available"
        }
    }
    catch {
        Write-Host "[!] Failed to retrieve tenant information: $_" -ForegroundColor Yellow
        $context = Get-MgContext
        $script:TenantInfo = @{
            TenantId = if ($context) { $context.TenantId } else { "Unknown" }
            DisplayName = if ($context) { $context.TenantId } else { "Unknown" }
            VerifiedDomains = "Unknown"
        }
        return $false
    }
}

# Check MFA configuration
function Test-MFAConfiguration {
    Write-Host "[*] Checking MFA configuration..." -ForegroundColor Cyan
    
    $mfaEnabled = $false
    $mfaMethod = "None"
    $securityDefaultsEnabled = $false
    $caPolicies = @()
    $mfaPolicies = @()
    
    try {
        # Check for Security Defaults using REST API
        try {
            $securityDefaults = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
            if ($securityDefaults -and $securityDefaults.isEnabled) {
                $securityDefaultsEnabled = $true
                $mfaEnabled = $true
                $mfaMethod = "Security Defaults"
            }
        }
        catch {
            Write-Host "[!] Unable to check Security Defaults (may require additional permissions)" -ForegroundColor Yellow
        }
        
        # Check Conditional Access policies for MFA using REST API
        try {
            $caResult = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            $caPolicies = $caResult.value
            
            if ($caPolicies) {
                # Check for MFA-requiring CA policies
                $mfaPolicies = @($caPolicies | Where-Object { 
                    $_.grantControls.builtInControls -contains "mfa" -and 
                    $_.state -eq "enabled"
                })
                
                if ($mfaPolicies.Count -gt 0) {
                    $mfaEnabled = $true
                    if (-not $securityDefaultsEnabled) {
                        $mfaMethod = "Conditional Access ($($mfaPolicies.Count) policies)"
                    }
                }
            }
        }
        catch {
            Write-Host "[!] Unable to retrieve Conditional Access policies" -ForegroundColor Yellow
        }
        
        return @{
            MFAEnabled = $mfaEnabled
            Method = $mfaMethod
            SecurityDefaultsEnabled = $securityDefaultsEnabled
            CAMFAPolicies = $mfaPolicies
            TotalCAPolicies = if ($caPolicies) { @($caPolicies).Count } else { 0 }
        }
    }
    catch {
        Write-Host "[!] Error checking MFA configuration: $_" -ForegroundColor Yellow
        return @{
            MFAEnabled = $false
            Method = "Error"
            SecurityDefaultsEnabled = $false
            CAMFAPolicies = @()
            TotalCAPolicies = 0
        }
    }
}

# Check Legacy Authentication configuration
function Test-LegacyAuthConfiguration {
    Write-Host "[*] Checking legacy authentication configuration..." -ForegroundColor Cyan
    
    $legacyAuthBlocked = $false
    $blockingPolicies = @()
    $securityDefaultsBlocks = $false
    
    try {
        # Check CA policies for legacy auth block using REST API
        try {
            $caResult = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            $caPolicies = $caResult.value
            
            foreach ($policy in $caPolicies) {
                if ($policy.state -eq "enabled" -and 
                    $policy.conditions.clientAppTypes -contains "other" -and
                    $policy.grantControls.builtInControls -contains "block") {
                    $legacyAuthBlocked = $true
                    $blockingPolicies += $policy.displayName
                }
                # Also check for exchangeActiveSync and other legacy protocols
                if ($policy.state -eq "enabled" -and 
                    ($policy.conditions.clientAppTypes -contains "exchangeActiveSync" -or
                     $policy.conditions.clientAppTypes -contains "other") -and
                    $policy.grantControls.builtInControls -contains "block") {
                    $legacyAuthBlocked = $true
                    if ($blockingPolicies -notcontains $policy.displayName) {
                        $blockingPolicies += $policy.displayName
                    }
                }
            }
        }
        catch {
            Write-Host "[!] Unable to retrieve Conditional Access policies for legacy auth check" -ForegroundColor Yellow
        }
        
        # Also check Security Defaults (blocks legacy auth)
        try {
            $securityDefaults = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
            if ($securityDefaults -and $securityDefaults.isEnabled) {
                $securityDefaultsBlocks = $true
                $legacyAuthBlocked = $true
            }
        }
        catch {
            # Security defaults check failed, continue
        }
        
        return @{
            LegacyAuthBlocked = $legacyAuthBlocked
            BlockingPolicies = $blockingPolicies
            SecurityDefaultsBlocks = $securityDefaultsBlocks
        }
    }
    catch {
        Write-Host "[!] Error checking legacy auth configuration: $_" -ForegroundColor Yellow
        return @{
            LegacyAuthBlocked = $false
            BlockingPolicies = @()
            SecurityDefaultsBlocks = $false
        }
    }
}

# Check Global Administrator count
function Test-GlobalAdminCount {
    Write-Host "[*] Checking Global Administrator count..." -ForegroundColor Cyan
    
    try {
        # Get Global Administrator role using REST API
        $roleResult = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=displayName eq 'Global Administrator'"
        
        if ($roleResult.value.Count -eq 0) {
            Write-Host "[!] Global Administrator role not activated in directory" -ForegroundColor Yellow
            return @{
                GlobalAdminCount = 0
                Compliant = $true
                Members = @()
                RecommendedRange = "2-5"
            }
        }
        
        $globalAdminRole = $roleResult.value[0]
        
        # Get members using REST API
        $membersResult = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($globalAdminRole.id)/members"
        
        # Filter for user members only
        $userMembers = @($membersResult.value | Where-Object { 
            $_.'@odata.type' -eq '#microsoft.graph.user'
        })
        
        $count = $userMembers.Count
        
        return @{
            GlobalAdminCount = $count
            Compliant = ($count -ge 2 -and $count -le 5)
            Members = $userMembers | ForEach-Object {
                [PSCustomObject]@{
                    displayName = $_.displayName
                    userPrincipalName = $_.userPrincipalName
                }
            }
            RecommendedRange = "2-5"
        }
    }
    catch {
        Write-Host "[!] Error checking Global Admin count: $_" -ForegroundColor Yellow
        return @{
            GlobalAdminCount = -1
            Compliant = $false
            Members = @()
            RecommendedRange = "2-5"
        }
    }
}

# Check PIM configuration
function Test-PIMConfiguration {
    Write-Host "[*] Checking PIM configuration..." -ForegroundColor Cyan
    
    $pimEnabled = $false
    $eligibleCount = 0
    $globalAdminSettings = $null
    
    try {
        # Check for PIM-managed roles using REST API (beta endpoint)
        try {
            $pimResult = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules"
            $eligibleCount = $pimResult.value.Count
            $pimEnabled = $eligibleCount -gt 0
        }
        catch {
            Write-Host "[!] PIM check - unable to access PIM data (may require Azure AD P2)" -ForegroundColor Yellow
        }
        
        return @{
            PIMEnabled = $pimEnabled
            EligibleAssignments = $eligibleCount
            GlobalAdminSettings = $globalAdminSettings
        }
    }
    catch {
        Write-Host "[!] Error checking PIM configuration: $_" -ForegroundColor Yellow
        return @{
            PIMEnabled = $false
            EligibleAssignments = 0
            GlobalAdminSettings = $null
        }
    }
}

# Check user consent settings
function Test-UserConsentSettings {
    Write-Host "[*] Checking user consent settings..." -ForegroundColor Cyan
    
    try {
        # Use REST API to get authorization policy
        $authPolicy = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        
        $userConsentEnabled = $true
        
        if ($authPolicy.defaultUserRolePermissions) {
            # Check permission grant policies
            $permissionPolicies = $authPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
            if ($null -eq $permissionPolicies -or $permissionPolicies.Count -eq 0) {
                $userConsentEnabled = $false
            }
            # Also check if consent is explicitly blocked
            if ($permissionPolicies -contains "ManagePermissionGrantsForSelf.microsoft-user-default-legacy") {
                $userConsentEnabled = $true
            }
            elseif ($permissionPolicies.Count -eq 0) {
                $userConsentEnabled = $false
            }
        }
        
        return @{
            UserConsentEnabled = $userConsentEnabled
            AdminConsentWorkflow = $authPolicy.defaultUserRolePermissions.allowedToCreateApps
            GuestInviteSettings = $authPolicy.allowInvitesFrom
        }
    }
    catch {
        Write-Host "[!] Error checking user consent settings: $_" -ForegroundColor Yellow
        return @{
            UserConsentEnabled = $true  # Assume less secure if we can't check
            AdminConsentWorkflow = $null
            GuestInviteSettings = $null
        }
    }
}

# Check guest access settings
function Test-GuestAccessSettings {
    Write-Host "[*] Checking guest access settings..." -ForegroundColor Cyan
    
    try {
        # Use REST API to get authorization policy
        $authPolicy = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        
        # Get guest count using REST API
        $guestCount = -1
        try {
            $guestResult = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$count=true&`$top=1" -Headers @{"ConsistencyLevel"="eventual"}
            if ($guestResult.'@odata.count') {
                $guestCount = $guestResult.'@odata.count'
            }
            elseif ($guestResult.value) {
                # Fallback: if count not available, just report that guests exist
                $guestCount = $guestResult.value.Count
            }
        }
        catch {
            Write-Host "[!] Unable to count guest users" -ForegroundColor Yellow
        }
        
        return @{
            AllowInvitesFrom = $authPolicy.allowInvitesFrom
            GuestUserRoleId = $authPolicy.guestUserRoleId
            GuestCount = $guestCount
            GuestsRestricted = ($authPolicy.guestUserRoleId -eq "2af84b1e-32c8-42b7-82bc-daa82404023b")  # Restricted guest access
        }
    }
    catch {
        Write-Host "[!] Error checking guest access settings: $_" -ForegroundColor Yellow
        return @{
            AllowInvitesFrom = "Unknown"
            GuestUserRoleId = $null
            GuestCount = -1
            GuestsRestricted = $false
        }
    }
}

# Check password policy
function Test-PasswordPolicy {
    Write-Host "[*] Checking password policy..." -ForegroundColor Cyan
    
    try {
        # Check organization domains using REST API
        $domainsResult = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/domains"
        $domains = $domainsResult.value
        
        # Check for banned password list - look for Azure AD Password Protection
        $bannedPasswordListEnabled = $false
        try {
            # Try to check directory settings for password protection
            $settingsResult = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/beta/settings"
            if ($settingsResult.value) {
                $passwordSettings = $settingsResult.value | Where-Object { 
                    $_.displayName -like "*Password*" -or $_.templateId -eq "5cf42378-d67d-4f36-ba46-e8b86229381d"
                }
                if ($passwordSettings) {
                    $bannedPasswordListEnabled = $true
                }
            }
        }
        catch {
            # Password protection settings may require additional permissions
        }
        
        return @{
            DomainCount = @($domains).Count
            BannedPasswordListEnabled = $bannedPasswordListEnabled
            Domains = $domains | Select-Object id, isDefault
        }
    }
    catch {
        Write-Host "[!] Error checking password policy: $_" -ForegroundColor Yellow
        return @{
            DomainCount = 0
            BannedPasswordListEnabled = $false
            Domains = @()
        }
    }
}

# Check SSPR configuration
function Test-SSPRConfiguration {
    Write-Host "[*] Checking SSPR configuration..." -ForegroundColor Cyan
    
    try {
        # Check SSPR policy using REST API
        $ssprEnabled = $false
        $policy = $null
        
        try {
            $policy = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
            
            # Check if any authentication methods are enabled
            if ($policy.authenticationMethodConfigurations) {
                foreach ($method in $policy.authenticationMethodConfigurations) {
                    if ($method.state -eq "enabled") {
                        $ssprEnabled = $true
                        break
                    }
                }
            }
        }
        catch {
            Write-Host "[!] Unable to retrieve authentication methods policy" -ForegroundColor Yellow
        }
        
        return @{
            SSPREnabled = $ssprEnabled
            AuthenticationMethodsPolicy = $policy
        }
    }
    catch {
        Write-Host "[!] Error checking SSPR configuration: $_" -ForegroundColor Yellow
        return @{
            SSPREnabled = $false
            AuthenticationMethodsPolicy = $null
        }
    }
}

# Check diagnostic settings
function Test-DiagnosticSettings {
    Write-Host "[*] Checking diagnostic logging configuration..." -ForegroundColor Cyan
    
    try {
        # Check if audit logs are accessible using REST API
        $loggingEnabled = $false
        $logsAccessible = $false
        
        try {
            $auditResult = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=1"
            $logsAccessible = $true
            $loggingEnabled = ($auditResult.value.Count -gt 0)
        }
        catch {
            # Audit log access might require specific permissions
            Write-Host "[!] Unable to access audit logs (may require AuditLog.Read.All permission)" -ForegroundColor Yellow
        }
        
        return @{
            AuditLoggingEnabled = $loggingEnabled
            LogsAccessible = $logsAccessible
        }
    }
    catch {
        Write-Host "[!] Error checking diagnostic settings: $_" -ForegroundColor Yellow
        return @{
            AuditLoggingEnabled = $false
            LogsAccessible = $false
        }
    }
}

# Check device settings
function Test-DeviceSettings {
    Write-Host "[*] Checking device registration settings..." -ForegroundColor Cyan
    
    try {
        # Try to get device registration policy using REST API
        $azureADJoinEnabled = $null
        $azureADRegistrationEnabled = $null
        $mfaConfig = $null
        
        try {
            $policy = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/policies/deviceRegistrationPolicy"
            if ($policy) {
                $azureADJoinEnabled = $policy.azureADJoin.isAdminConfigurable
                $azureADRegistrationEnabled = $policy.azureADRegistration.isAdminConfigurable
                $mfaConfig = $policy.multiFactorAuthConfiguration
            }
        }
        catch {
            Write-Host "[!] Unable to retrieve device registration policy" -ForegroundColor Yellow
        }
        
        return @{
            AzureADJoinEnabled = $azureADJoinEnabled
            AzureADRegistrationEnabled = $azureADRegistrationEnabled
            MultiFactorAuthConfiguration = $mfaConfig
        }
    }
    catch {
        Write-Host "[!] Error checking device settings: $_" -ForegroundColor Yellow
        return @{
            AzureADJoinEnabled = $null
            AzureADRegistrationEnabled = $null
            MultiFactorAuthConfiguration = $null
        }
    }
}

# Check risk policies
function Test-RiskPolicies {
    Write-Host "[*] Checking Identity Protection risk policies..." -ForegroundColor Cyan
    
    try {
        $signInRiskPolicies = @()
        $userRiskPolicies = @()
        
        try {
            # Check Conditional Access policies for risk-based controls using REST API
            $caResult = Invoke-GraphApiRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            $caPolicies = $caResult.value
            
            $signInRiskPolicies = @($caPolicies | Where-Object { 
                $_.conditions.signInRiskLevels -and $_.state -eq "enabled"
            })
            
            $userRiskPolicies = @($caPolicies | Where-Object { 
                $_.conditions.userRiskLevels -and $_.state -eq "enabled"
            })
        }
        catch {
            Write-Host "[!] Unable to retrieve risk policies from Conditional Access" -ForegroundColor Yellow
        }
        
        return @{
            SignInRiskPolicyEnabled = ($signInRiskPolicies.Count -gt 0)
            UserRiskPolicyEnabled = ($userRiskPolicies.Count -gt 0)
            SignInRiskPolicies = $signInRiskPolicies
            UserRiskPolicies = $userRiskPolicies
        }
    }
    catch {
        Write-Host "[!] Error checking risk policies: $_" -ForegroundColor Yellow
        return @{
            SignInRiskPolicyEnabled = $false
            UserRiskPolicyEnabled = $false
            SignInRiskPolicies = @()
            UserRiskPolicies = @()
        }
    }
}

# Evaluate a compliance control
function Test-ComplianceControl {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Control,
        [Parameter(Mandatory = $true)]
        [hashtable]$CheckResults
    )
    
    $result = @{
        Id = $Control.Id
        Title = $Control.Title
        Description = $Control.Description
        Category = $Control.Category
        Severity = $Control.Severity
        CheckType = $Control.CheckType
        Status = "Unknown"
        Details = ""
        Evidence = @()
        CIS = $Control.CIS
        NIST = $Control.NIST
        SOC2 = $Control.SOC2
        ISO27001 = $Control.ISO27001
        GDPR = $Control.GDPR
        Remediation = $Control.Remediation
    }
    
    switch ($Control.CheckType) {
        "MFA" {
            if ($CheckResults.MFA.MFAEnabled) {
                $result.Status = "Pass"
                $result.Details = "MFA is enabled via $($CheckResults.MFA.Method)"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "MFA is not enforced for all users"
            }
            $result.Evidence += "Security Defaults: $($CheckResults.MFA.SecurityDefaultsEnabled)"
            $result.Evidence += "CA MFA Policies: $($CheckResults.MFA.CAMFAPolicies.Count)"
        }
        "MFA-Privileged" {
            # Check if there are CA policies specifically for admins
            $adminMFAPolicies = $CheckResults.MFA.CAMFAPolicies | Where-Object { 
                $_.conditions.users.includeRoles -or $_.displayName -match "admin|privileged"
            }
            if ($adminMFAPolicies.Count -gt 0 -or $CheckResults.MFA.SecurityDefaultsEnabled) {
                $result.Status = "Pass"
                $result.Details = "MFA is enforced for privileged accounts"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "No specific MFA policy for privileged accounts detected"
            }
        }
        "MFA-Guest" {
            $guestMFAPolicies = $CheckResults.MFA.CAMFAPolicies | Where-Object { 
                $_.conditions.users.includeGuestsOrExternalUsers -or 
                $_.displayName -match "guest|external"
            }
            if ($guestMFAPolicies.Count -gt 0 -or $CheckResults.MFA.SecurityDefaultsEnabled) {
                $result.Status = "Pass"
                $result.Details = "MFA is enforced for guest users"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "No MFA policy for guest users detected"
            }
        }
        "LegacyAuth" {
            if ($CheckResults.LegacyAuth.LegacyAuthBlocked) {
                $result.Status = "Pass"
                $result.Details = "Legacy authentication is blocked"
                if ($CheckResults.LegacyAuth.BlockingPolicies.Count -gt 0) {
                    $result.Evidence += "Blocking policies: $($CheckResults.LegacyAuth.BlockingPolicies -join ', ')"
                }
            }
            else {
                $result.Status = "Fail"
                $result.Details = "Legacy authentication is not blocked"
            }
        }
        "ConditionalAccess" {
            if ($CheckResults.MFA.TotalCAPolicies -gt 0) {
                $result.Status = "Pass"
                $result.Details = "$($CheckResults.MFA.TotalCAPolicies) Conditional Access policies configured"
            }
            else {
                if ($CheckResults.MFA.SecurityDefaultsEnabled) {
                    $result.Status = "Pass"
                    $result.Details = "Security Defaults is enabled (provides baseline CA-like protection)"
                }
                else {
                    $result.Status = "Fail"
                    $result.Details = "No Conditional Access policies configured"
                }
            }
        }
        "RiskPolicy" {
            if ($CheckResults.RiskPolicies.SignInRiskPolicyEnabled) {
                $result.Status = "Pass"
                $result.Details = "Sign-in risk policy is enabled"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "Sign-in risk policy is not enabled"
            }
        }
        "UserRiskPolicy" {
            if ($CheckResults.RiskPolicies.UserRiskPolicyEnabled) {
                $result.Status = "Pass"
                $result.Details = "User risk policy is enabled"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "User risk policy is not enabled"
            }
        }
        "GlobalAdminCount" {
            if ($CheckResults.GlobalAdmins.Compliant) {
                $result.Status = "Pass"
                $result.Details = "$($CheckResults.GlobalAdmins.GlobalAdminCount) Global Administrators (recommended: 2-5)"
            }
            else {
                if ($CheckResults.GlobalAdmins.GlobalAdminCount -lt 2) {
                    $result.Status = "Fail"
                    $result.Details = "Only $($CheckResults.GlobalAdmins.GlobalAdminCount) Global Administrator(s) - minimum 2 recommended for redundancy"
                }
                else {
                    $result.Status = "Fail"
                    $result.Details = "$($CheckResults.GlobalAdmins.GlobalAdminCount) Global Administrators - maximum 5 recommended"
                }
            }
            $result.Evidence += $CheckResults.GlobalAdmins.Members | ForEach-Object { "$($_.displayName) ($($_.userPrincipalName))" }
        }
        "PIM" {
            if ($CheckResults.PIM.PIMEnabled) {
                $result.Status = "Pass"
                $result.Details = "PIM is enabled with $($CheckResults.PIM.EligibleAssignments) eligible assignments"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "PIM is not enabled or has no eligible assignments"
            }
        }
        "PIM-Approval" {
            # This requires more detailed PIM settings check
            if ($CheckResults.PIM.PIMEnabled -and $CheckResults.PIM.GlobalAdminSettings) {
                $result.Status = "Manual Review"
                $result.Details = "PIM is enabled - manual review of approval settings recommended"
            }
            elseif ($CheckResults.PIM.PIMEnabled) {
                $result.Status = "Manual Review"
                $result.Details = "PIM is enabled but settings could not be retrieved"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "PIM is not enabled"
            }
        }
        "PasswordExpiration" {
            # NIST recommends no password expiration
            $result.Status = "Manual Review"
            $result.Details = "Password expiration policy requires manual review in Azure AD portal"
        }
        "BannedPasswords" {
            if ($CheckResults.PasswordPolicy.BannedPasswordListEnabled) {
                $result.Status = "Pass"
                $result.Details = "Banned password list is configured"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "Banned password list is not configured"
            }
        }
        "SSPR" {
            if ($CheckResults.SSPR.SSPREnabled) {
                $result.Status = "Pass"
                $result.Details = "Self-Service Password Reset is enabled"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "Self-Service Password Reset is not enabled"
            }
        }
        "UserConsent" {
            if (-not $CheckResults.UserConsent.UserConsentEnabled) {
                $result.Status = "Pass"
                $result.Details = "User consent for applications is restricted"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "Users can consent to applications accessing organizational data"
            }
        }
        "AppPermissions" {
            $result.Status = "Manual Review"
            $result.Details = "Application permissions require manual review"
        }
        "StaleAppCredentials" {
            $result.Status = "Manual Review"
            $result.Details = "Application credential age requires manual review"
        }
        "OAuthConsent" {
            $result.Status = "Manual Review"
            $result.Details = "OAuth consent grants require manual review"
        }
        "GuestInvitations" {
            $inviteSettings = $CheckResults.GuestAccess.AllowInvitesFrom
            if ($inviteSettings -eq "adminsAndGuestInviters" -or $inviteSettings -eq "none") {
                $result.Status = "Pass"
                $result.Details = "Guest invitations are restricted ($inviteSettings)"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "Guest invitation settings may be too permissive ($inviteSettings)"
            }
        }
        "StaleGuests" {
            if ($CheckResults.GuestAccess.GuestCount -ge 0) {
                $result.Status = "Manual Review"
                $result.Details = "$($CheckResults.GuestAccess.GuestCount) guest accounts - review for stale accounts"
            }
            else {
                $result.Status = "Unknown"
                $result.Details = "Could not retrieve guest account count"
            }
        }
        "GuestDirectoryAccess" {
            if ($CheckResults.GuestAccess.GuestsRestricted) {
                $result.Status = "Pass"
                $result.Details = "Guest directory access is restricted"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "Guest directory access is not restricted"
            }
        }
        "DiagnosticLogs" {
            if ($CheckResults.Diagnostics.AuditLoggingEnabled) {
                $result.Status = "Pass"
                $result.Details = "Audit logging is enabled and accessible"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "Audit logging could not be verified"
            }
        }
        "LogRetention" {
            $result.Status = "Manual Review"
            $result.Details = "Log retention configuration requires manual verification in Azure Portal"
        }
        "SecurityAlerts" {
            if ($CheckResults.RiskPolicies.SignInRiskPolicyEnabled -or $CheckResults.RiskPolicies.UserRiskPolicyEnabled) {
                $result.Status = "Pass"
                $result.Details = "Identity Protection risk policies are configured"
            }
            else {
                $result.Status = "Fail"
                $result.Details = "Identity Protection risk policies are not configured"
            }
        }
        "SecurityDefaults" {
            if ($CheckResults.MFA.SecurityDefaultsEnabled -or $CheckResults.MFA.TotalCAPolicies -gt 0) {
                $result.Status = "Pass"
                if ($CheckResults.MFA.SecurityDefaultsEnabled) {
                    $result.Details = "Security Defaults is enabled"
                }
                else {
                    $result.Details = "Conditional Access policies are configured (Security Defaults alternative)"
                }
            }
            else {
                $result.Status = "Fail"
                $result.Details = "Neither Security Defaults nor Conditional Access is configured"
            }
        }
        "AdminPortalAccess" {
            $result.Status = "Manual Review"
            $result.Details = "Azure Portal access restrictions require manual review"
        }
        "DeviceCompliance" {
            $result.Status = "Manual Review"
            $result.Details = "Device compliance requirements need manual verification in Conditional Access"
        }
        "DeviceRegistration" {
            if ($CheckResults.DeviceSettings.AzureADJoinEnabled -ne $null) {
                $result.Status = "Pass"
                $result.Details = "Device registration settings are configured"
            }
            else {
                $result.Status = "Manual Review"
                $result.Details = "Device registration settings require manual review"
            }
        }
        default {
            $result.Status = "Unknown"
            $result.Details = "Check type not implemented: $($Control.CheckType)"
        }
    }
    
    return $result
}

# Run compliance assessment
function Start-ComplianceAssessment {
    Write-Host "`n[*] Starting compliance assessment..." -ForegroundColor Cyan
    Write-Host "[*] Gathering configuration data..." -ForegroundColor Cyan
    
    # Gather all check results
    $checkResults = @{
        MFA = Test-MFAConfiguration
        LegacyAuth = Test-LegacyAuthConfiguration
        GlobalAdmins = Test-GlobalAdminCount
        PIM = Test-PIMConfiguration
        UserConsent = Test-UserConsentSettings
        GuestAccess = Test-GuestAccessSettings
        PasswordPolicy = Test-PasswordPolicy
        SSPR = Test-SSPRConfiguration
        Diagnostics = Test-DiagnosticSettings
        DeviceSettings = Test-DeviceSettings
        RiskPolicies = Test-RiskPolicies
    }
    
    Write-Host "`n[*] Evaluating compliance controls..." -ForegroundColor Cyan
    
    $minimumSeverityRank = $script:SeverityRank[$MinimumSeverity]
    
    foreach ($control in $script:ComplianceControls) {
        # Filter by framework if specified
        if ($Framework -ne "All") {
            $hasFramework = $false
            switch ($Framework) {
                "CIS" { $hasFramework = $control.CIS -ne $null }
                "NIST" { $hasFramework = $control.NIST -ne $null }
                "SOC2" { $hasFramework = $control.SOC2 -ne $null }
                "ISO27001" { $hasFramework = $control.ISO27001 -ne $null }
                "GDPR" { $hasFramework = $control.GDPR -ne $null }
            }
            if (-not $hasFramework) {
                continue
            }
        }
        
        # Filter by control family if specified
        if ($ControlFamily) {
            $matchesFamily = $false
            switch ($Framework) {
                "CIS" { $matchesFamily = $control.CIS -and $control.CIS.Control -like "$ControlFamily*" }
                "NIST" { $matchesFamily = $control.NIST -and $control.NIST.Family -eq $ControlFamily }
                default { $matchesFamily = $control.Id -like "*$ControlFamily*" }
            }
            if (-not $matchesFamily) {
                continue
            }
        }
        
        # Filter by severity
        $controlSeverityRank = $script:SeverityRank[$control.Severity]
        if ($controlSeverityRank -lt $minimumSeverityRank) {
            continue
        }
        
        # Evaluate the control
        $result = Test-ComplianceControl -Control $control -CheckResults $checkResults
        
        # Filter by pass/fail status
        if ($OnlyFailed -and $result.Status -eq "Pass") {
            continue
        }
        if ($OnlyPassed -and $result.Status -ne "Pass") {
            continue
        }
        
        $script:ComplianceResults += $result
    }
    
    Write-Host "[+] Compliance assessment complete!" -ForegroundColor Green
}

# Display results in matrix format
function Show-MatrixResults {
    Write-Host "`n" + ("=" * 180) -ForegroundColor Cyan
    Write-Host "COMPLIANCE ASSESSMENT MATRIX" -ForegroundColor Cyan
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    if ($script:ComplianceResults.Count -eq 0) {
        Write-Host "`n[!] No compliance controls matched the filter criteria." -ForegroundColor Yellow
        Write-Host ("=" * 180) -ForegroundColor Cyan
        return
    }
    
    # Create matrix display based on framework
    $matrixData = $script:ComplianceResults | Select-Object `
        @{Name='Status';Expression={$_.Status}},
        @{Name='Severity';Expression={$_.Severity}},
        @{Name='Control ID';Expression={$_.Id}},
        @{Name='CIS';Expression={if($_.CIS){$_.CIS.Control}else{'-'}}},
        @{Name='NIST';Expression={if($_.NIST){$_.NIST.Control}else{'-'}}},
        @{Name='SOC2';Expression={if($_.SOC2){$_.SOC2.Criteria}else{'-'}}},
        @{Name='Title';Expression={if($_.Title.Length -gt 45){"$($_.Title.Substring(0,42))..."}else{$_.Title}}},
        @{Name='Details';Expression={if($_.Details.Length -gt 70){"$($_.Details.Substring(0,67))..."}else{$_.Details}}}
    
    # Display as formatted table with color coding
    $matrixData | Format-Table -AutoSize -Wrap | Out-String | ForEach-Object {
        $lines = $_ -split "`n"
        foreach ($line in $lines) {
            if ($line -match '^\s*Fail\s+') {
                Write-Host $line -ForegroundColor Red
            }
            elseif ($line -match '^\s*Pass\s+') {
                Write-Host $line -ForegroundColor Green
            }
            elseif ($line -match '^\s*Manual Review\s+') {
                Write-Host $line -ForegroundColor Yellow
            }
            elseif ($line -match '^-+\s+-+' -or $line -match '^Status\s+') {
                Write-Host $line -ForegroundColor Cyan
            }
            else {
                Write-Host $line -ForegroundColor White
            }
        }
    }
    
    Write-Host ("=" * 180) -ForegroundColor Cyan
    
    # Summary statistics
    Show-ComplianceSummary
}

# Display detailed results
function Show-DetailedResults {
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "COMPLIANCE ASSESSMENT RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    
    if ($script:ComplianceResults.Count -eq 0) {
        Write-Host "`n[!] No compliance controls matched the filter criteria." -ForegroundColor Yellow
        Write-Host ("=" * 80) -ForegroundColor Cyan
        return
    }
    
    # Group by category
    $byCategory = $script:ComplianceResults | Group-Object Category
    
    foreach ($category in $byCategory) {
        Write-Host "`n" + ("-" * 80) -ForegroundColor Cyan
        Write-Host "$($category.Name)" -ForegroundColor Cyan
        Write-Host ("-" * 80) -ForegroundColor Cyan
        
        foreach ($result in $category.Group) {
            $statusColor = switch ($result.Status) {
                "Pass" { "Green" }
                "Fail" { "Red" }
                "Manual Review" { "Yellow" }
                default { "Gray" }
            }
            
            $severityColor = switch ($result.Severity) {
                "Critical" { "Red" }
                "High" { "Yellow" }
                "Medium" { "Cyan" }
                default { "Gray" }
            }
            
            Write-Host "`n[$($result.Status)] " -NoNewline -ForegroundColor $statusColor
            Write-Host "$($result.Id) - $($result.Title)" -ForegroundColor White
            
            Write-Host "  Severity: " -NoNewline -ForegroundColor Gray
            Write-Host $result.Severity -ForegroundColor $severityColor
            
            Write-Host "  Details: $($result.Details)" -ForegroundColor Gray
            
            # Show framework mappings
            if ($result.CIS) {
                Write-Host "  CIS: $($result.CIS.Control) - $($result.CIS.Description)" -ForegroundColor DarkCyan
            }
            if ($result.NIST) {
                Write-Host "  NIST: $($result.NIST.Control) ($($result.NIST.Family)) - $($result.NIST.Description)" -ForegroundColor DarkCyan
            }
            if ($result.SOC2) {
                Write-Host "  SOC2: $($result.SOC2.Criteria) - $($result.SOC2.Description)" -ForegroundColor DarkCyan
            }
            if ($result.ISO27001) {
                Write-Host "  ISO27001: $($result.ISO27001.Control) - $($result.ISO27001.Description)" -ForegroundColor DarkCyan
            }
            if ($result.GDPR) {
                Write-Host "  GDPR: Article $($result.GDPR.Article) - $($result.GDPR.Description)" -ForegroundColor DarkCyan
            }
            
            # Show evidence if available
            if ($result.Evidence.Count -gt 0) {
                Write-Host "  Evidence:" -ForegroundColor Gray
                foreach ($evidence in $result.Evidence) {
                    Write-Host "    - $evidence" -ForegroundColor DarkGray
                }
            }
            
            # Show remediation if requested and status is Fail
            if ($IncludeRemediation -and $result.Status -eq "Fail" -and $result.Remediation) {
                Write-Host "  Remediation: $($result.Remediation)" -ForegroundColor Magenta
            }
        }
    }
    
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    
    # Summary statistics
    Show-ComplianceSummary
}

# Show compliance summary
function Show-ComplianceSummary {
    Write-Host "`n[COMPLIANCE SUMMARY]" -ForegroundColor Cyan
    
    $total = $script:ComplianceResults.Count
    $passed = ($script:ComplianceResults | Where-Object { $_.Status -eq "Pass" }).Count
    $failed = ($script:ComplianceResults | Where-Object { $_.Status -eq "Fail" }).Count
    $manualReview = ($script:ComplianceResults | Where-Object { $_.Status -eq "Manual Review" }).Count
    $unknown = ($script:ComplianceResults | Where-Object { $_.Status -eq "Unknown" }).Count
    
    Write-Host "Total Controls Assessed: " -NoNewline -ForegroundColor White
    Write-Host $total -ForegroundColor Yellow
    
    Write-Host "  - Passed: " -NoNewline -ForegroundColor White
    Write-Host $passed -ForegroundColor Green
    
    Write-Host "  - Failed: " -NoNewline -ForegroundColor White
    Write-Host $failed -ForegroundColor Red
    
    Write-Host "  - Manual Review: " -NoNewline -ForegroundColor White
    Write-Host $manualReview -ForegroundColor Yellow
    
    Write-Host "  - Unknown: " -NoNewline -ForegroundColor White
    Write-Host $unknown -ForegroundColor Gray
    
    if ($total -gt 0) {
        $complianceScore = [math]::Round(($passed / ($passed + $failed)) * 100, 1)
        Write-Host "`nCompliance Score: " -NoNewline -ForegroundColor White
        $scoreColor = if ($complianceScore -ge 80) { "Green" } elseif ($complianceScore -ge 60) { "Yellow" } else { "Red" }
        Write-Host "$complianceScore%" -ForegroundColor $scoreColor
        Write-Host "(Excludes Manual Review items)" -ForegroundColor Gray
    }
    
    # Severity breakdown
    Write-Host "`n[BY SEVERITY]" -ForegroundColor Cyan
    $bySeverity = $script:ComplianceResults | Where-Object { $_.Status -eq "Fail" } | Group-Object Severity
    
    $critical = ($bySeverity | Where-Object { $_.Name -eq "Critical" }).Count
    $high = ($bySeverity | Where-Object { $_.Name -eq "High" }).Count
    $medium = ($bySeverity | Where-Object { $_.Name -eq "Medium" }).Count
    $low = ($bySeverity | Where-Object { $_.Name -eq "Low" }).Count
    
    Write-Host "  Failed - Critical: " -NoNewline -ForegroundColor White
    Write-Host $(if($critical){$critical}else{0}) -ForegroundColor Red
    
    Write-Host "  Failed - High: " -NoNewline -ForegroundColor White
    Write-Host $(if($high){$high}else{0}) -ForegroundColor Yellow
    
    Write-Host "  Failed - Medium: " -NoNewline -ForegroundColor White
    Write-Host $(if($medium){$medium}else{0}) -ForegroundColor Cyan
    
    Write-Host "  Failed - Low: " -NoNewline -ForegroundColor White
    Write-Host $(if($low){$low}else{0}) -ForegroundColor Gray
    
    # Framework breakdown
    if ($Framework -eq "All") {
        Write-Host "`n[BY FRAMEWORK - Failed Controls]" -ForegroundColor Cyan
        
        $failedResults = $script:ComplianceResults | Where-Object { $_.Status -eq "Fail" }
        
        $cisFailures = ($failedResults | Where-Object { $_.CIS }).Count
        $nistFailures = ($failedResults | Where-Object { $_.NIST }).Count
        $soc2Failures = ($failedResults | Where-Object { $_.SOC2 }).Count
        $isoFailures = ($failedResults | Where-Object { $_.ISO27001 }).Count
        $gdprFailures = ($failedResults | Where-Object { $_.GDPR }).Count
        
        Write-Host "  CIS Azure Benchmark: $cisFailures" -ForegroundColor Yellow
        Write-Host "  NIST 800-53: $nistFailures" -ForegroundColor Yellow
        Write-Host "  SOC 2: $soc2Failures" -ForegroundColor Yellow
        Write-Host "  ISO 27001: $isoFailures" -ForegroundColor Yellow
        Write-Host "  GDPR: $gdprFailures" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# Generate executive report
function Show-ExecutiveReport {
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "EXECUTIVE COMPLIANCE REPORT" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    
    Write-Host "`nOrganization: $($script:TenantInfo.DisplayName)" -ForegroundColor White
    Write-Host "Tenant ID: $($script:TenantInfo.TenantId)" -ForegroundColor Gray
    Write-Host "Assessment Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "Framework(s): $Framework" -ForegroundColor Gray
    
    $total = $script:ComplianceResults.Count
    $passed = ($script:ComplianceResults | Where-Object { $_.Status -eq "Pass" }).Count
    $failed = ($script:ComplianceResults | Where-Object { $_.Status -eq "Fail" }).Count
    
    if ($total -gt 0 -and ($passed + $failed) -gt 0) {
        $complianceScore = [math]::Round(($passed / ($passed + $failed)) * 100, 1)
        
        Write-Host "`n" + ("-" * 40) -ForegroundColor Cyan
        Write-Host "OVERALL COMPLIANCE SCORE" -ForegroundColor Cyan
        Write-Host ("-" * 40) -ForegroundColor Cyan
        
        $scoreBar = ""
        $filledChars = [math]::Floor($complianceScore / 5)
        for ($i = 0; $i -lt 20; $i++) {
            if ($i -lt $filledChars) { $scoreBar += "#" }
            else { $scoreBar += "-" }
        }
        
        $scoreColor = if ($complianceScore -ge 80) { "Green" } elseif ($complianceScore -ge 60) { "Yellow" } else { "Red" }
        Write-Host "`n[$scoreBar] " -NoNewline -ForegroundColor $scoreColor
        Write-Host "$complianceScore%" -ForegroundColor $scoreColor
        
        Write-Host "`n$passed of $($passed + $failed) controls passed" -ForegroundColor Gray
    }
    
    # Priority remediation items
    $criticalFailed = $script:ComplianceResults | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "Critical" }
    $highFailed = $script:ComplianceResults | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "High" }
    
    if ($criticalFailed.Count -gt 0 -or $highFailed.Count -gt 0) {
        Write-Host "`n" + ("-" * 40) -ForegroundColor Cyan
        Write-Host "PRIORITY REMEDIATION ITEMS" -ForegroundColor Cyan
        Write-Host ("-" * 40) -ForegroundColor Cyan
        
        if ($criticalFailed.Count -gt 0) {
            Write-Host "`n[CRITICAL - Immediate Action Required]" -ForegroundColor Red
            foreach ($item in $criticalFailed) {
                Write-Host "  - $($item.Title)" -ForegroundColor Red
                Write-Host "    $($item.Details)" -ForegroundColor Gray
            }
        }
        
        if ($highFailed.Count -gt 0) {
            Write-Host "`n[HIGH - Action Required Soon]" -ForegroundColor Yellow
            foreach ($item in $highFailed) {
                Write-Host "  - $($item.Title)" -ForegroundColor Yellow
                Write-Host "    $($item.Details)" -ForegroundColor Gray
            }
        }
    }
    
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
}

# Export results
function Export-Results {
    param(
        [string]$Path
    )
    
    if (-not $Path) {
        return
    }
    
    if ($script:ComplianceResults.Count -eq 0) {
        Write-Host "`n[*] No compliance results to export" -ForegroundColor Yellow
        return
    }
    
    try {
        $extension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        # Prepare export data
        $exportData = $script:ComplianceResults | ForEach-Object {
            [PSCustomObject]@{
                Id = $_.Id
                Title = $_.Title
                Category = $_.Category
                Severity = $_.Severity
                Status = $_.Status
                Details = $_.Details
                CIS_Control = if ($_.CIS) { $_.CIS.Control } else { "" }
                CIS_Description = if ($_.CIS) { $_.CIS.Description } else { "" }
                NIST_Control = if ($_.NIST) { $_.NIST.Control } else { "" }
                NIST_Family = if ($_.NIST) { $_.NIST.Family } else { "" }
                NIST_Description = if ($_.NIST) { $_.NIST.Description } else { "" }
                SOC2_Criteria = if ($_.SOC2) { $_.SOC2.Criteria } else { "" }
                SOC2_Category = if ($_.SOC2) { $_.SOC2.Category } else { "" }
                SOC2_Description = if ($_.SOC2) { $_.SOC2.Description } else { "" }
                ISO27001_Control = if ($_.ISO27001) { $_.ISO27001.Control } else { "" }
                ISO27001_Description = if ($_.ISO27001) { $_.ISO27001.Description } else { "" }
                GDPR_Article = if ($_.GDPR) { $_.GDPR.Article } else { "" }
                GDPR_Description = if ($_.GDPR) { $_.GDPR.Description } else { "" }
                Evidence = ($_.Evidence -join "; ")
                Remediation = $_.Remediation
            }
        }
        
        switch ($extension) {
            ".csv" {
                $exportData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $Path" -ForegroundColor Green
            }
            ".json" {
                $jsonExport = @{
                    TenantInfo = $script:TenantInfo
                    AssessmentDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    Framework = $Framework
                    Results = $script:ComplianceResults
                    Summary = @{
                        Total = $script:ComplianceResults.Count
                        Passed = ($script:ComplianceResults | Where-Object { $_.Status -eq "Pass" }).Count
                        Failed = ($script:ComplianceResults | Where-Object { $_.Status -eq "Fail" }).Count
                        ManualReview = ($script:ComplianceResults | Where-Object { $_.Status -eq "Manual Review" }).Count
                    }
                }
                $jsonExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
                Write-Host "`n[+] Results exported to JSON: $Path" -ForegroundColor Green
            }
            ".html" {
                Export-HTMLReport -Path $Path -Data $exportData
                Write-Host "`n[+] Results exported to HTML: $Path" -ForegroundColor Green
            }
            default {
                $csvPath = [System.IO.Path]::ChangeExtension($Path, ".csv")
                $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Host "`n[+] Results exported to CSV: $csvPath" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "`n[ERROR] Failed to export results: $_" -ForegroundColor Red
    }
}

# Export HTML report
function Export-HTMLReport {
    param(
        [string]$Path,
        $Data
    )
    
    $total = $script:ComplianceResults.Count
    $passed = ($script:ComplianceResults | Where-Object { $_.Status -eq "Pass" }).Count
    $failed = ($script:ComplianceResults | Where-Object { $_.Status -eq "Fail" }).Count
    $complianceScore = if (($passed + $failed) -gt 0) { [math]::Round(($passed / ($passed + $failed)) * 100, 1) } else { 0 }
    
    $scoreClass = if ($complianceScore -ge 80) { "score-good" } elseif ($complianceScore -ge 60) { "score-medium" } else { "score-bad" }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EvilMist Compliance Report - $($script:TenantInfo.DisplayName)</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-green: #238636;
            --accent-red: #da3633;
            --accent-yellow: #d29922;
            --accent-cyan: #58a6ff;
            --border-color: #30363d;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        h1, h2, h3 {
            color: var(--text-primary);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: var(--accent-cyan);
            border: none;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        
        .card h3 {
            margin: 0;
            border: none;
            font-size: 14px;
            color: var(--text-secondary);
        }
        
        .card .value {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .score-good { color: var(--accent-green); }
        .score-medium { color: var(--accent-yellow); }
        .score-bad { color: var(--accent-red); }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        th {
            background-color: var(--bg-primary);
            color: var(--accent-cyan);
            font-weight: 600;
        }
        
        tr:hover {
            background-color: var(--bg-primary);
        }
        
        .status-pass { color: var(--accent-green); font-weight: bold; }
        .status-fail { color: var(--accent-red); font-weight: bold; }
        .status-review { color: var(--accent-yellow); font-weight: bold; }
        
        .severity-critical { background-color: rgba(218, 54, 51, 0.2); }
        .severity-high { background-color: rgba(210, 153, 34, 0.2); }
        .severity-medium { background-color: rgba(88, 166, 255, 0.1); }
        
        .framework-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            margin: 2px;
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
        }
        
        footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>EvilMist Compliance Report</h1>
            <p>Tenant: $($script:TenantInfo.DisplayName) ($($script:TenantInfo.TenantId))</p>
            <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Framework: $Framework</p>
        </div>
        
        <div class="summary-cards">
            <div class="card">
                <h3>COMPLIANCE SCORE</h3>
                <div class="value $scoreClass">$complianceScore%</div>
            </div>
            <div class="card">
                <h3>TOTAL CONTROLS</h3>
                <div class="value" style="color: var(--accent-cyan);">$total</div>
            </div>
            <div class="card">
                <h3>PASSED</h3>
                <div class="value score-good">$passed</div>
            </div>
            <div class="card">
                <h3>FAILED</h3>
                <div class="value score-bad">$failed</div>
            </div>
        </div>
        
        <h2>Compliance Control Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Control</th>
                    <th>Title</th>
                    <th>Frameworks</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($result in $script:ComplianceResults) {
        $statusClass = switch ($result.Status) {
            "Pass" { "status-pass" }
            "Fail" { "status-fail" }
            default { "status-review" }
        }
        
        $severityClass = switch ($result.Severity) {
            "Critical" { "severity-critical" }
            "High" { "severity-high" }
            "Medium" { "severity-medium" }
            default { "" }
        }
        
        $frameworks = @()
        if ($result.CIS) { $frameworks += "<span class='framework-badge'>CIS $($result.CIS.Control)</span>" }
        if ($result.NIST) { $frameworks += "<span class='framework-badge'>NIST $($result.NIST.Control)</span>" }
        if ($result.SOC2) { $frameworks += "<span class='framework-badge'>SOC2 $($result.SOC2.Criteria)</span>" }
        if ($result.ISO27001) { $frameworks += "<span class='framework-badge'>ISO $($result.ISO27001.Control)</span>" }
        if ($result.GDPR) { $frameworks += "<span class='framework-badge'>GDPR Art.$($result.GDPR.Article)</span>" }
        
        $html += @"
                <tr class="$severityClass">
                    <td class="$statusClass">$($result.Status)</td>
                    <td>$($result.Severity)</td>
                    <td>$($result.Id)</td>
                    <td>$($result.Title)</td>
                    <td>$($frameworks -join '')</td>
                    <td>$($result.Details)</td>
                </tr>
"@
    }

    $html += @"
            </tbody>
        </table>
        
        <footer>
            <p>Generated by EvilMist Toolkit | https://github.com/Logisek/EvilMist</p>
            <p>https://logisek.com | info@logisek.com</p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $Path -Encoding UTF8
}

# Cleanup
function Invoke-Cleanup {
    Write-Host "`n[*] Cleaning up..." -ForegroundColor Cyan
    try {
        # Disconnect from Microsoft Graph
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] Disconnected from Microsoft Graph" -ForegroundColor Green
        # Disconnect from Azure PowerShell if connected
        if (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue) {
            if (Get-AzContext -ErrorAction SilentlyContinue) {
                Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
                Write-Host "[+] Disconnected from Azure PowerShell" -ForegroundColor Green
            }
        }
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
}

# Main execution
function Main {
    try {
        Show-Banner
        
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
        
        # Authenticate
        if (-not (Connect-GraphService)) {
            Write-Host "`n[ERROR] Authentication failed. Exiting." -ForegroundColor Red
            exit 1
        }
        
        # Get tenant info
        Get-TenantInfo
        
        # Run compliance assessment
        Start-ComplianceAssessment
        
        # Show results
        if ($GenerateExecutiveReport) {
            Show-ExecutiveReport
        }
        
        if ($Matrix) {
            Show-MatrixResults
        }
        else {
            Show-DetailedResults
        }
        
        # Export if requested
        if ($ExportPath) {
            Export-Results -Path $ExportPath
        }
        
        Write-Host "`n[*] Compliance check completed successfully!" -ForegroundColor Green
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
