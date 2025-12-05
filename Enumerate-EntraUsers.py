"""
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
"""

import json
import os
import signal
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, List, Dict

try:
    import msal
    import requests
except ImportError:
    print("Required packages not installed. Run:")
    print("    pip install msal requests")
    sys.exit(1)

# Optional: azure-identity for additional auth methods
try:
    from azure.identity import (
        DefaultAzureCredential,
        AzureCliCredential,
        VisualStudioCodeCredential,
        SharedTokenCacheCredential,
        InteractiveBrowserCredential,
    )
    AZURE_IDENTITY_AVAILABLE = True
except ImportError:
    AZURE_IDENTITY_AVAILABLE = False

# Microsoft Apps JSON URL for extended app IDs
MICROSOFT_APPS_JSON_URL = "https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json"
MICROSOFT_APPS_LOCAL_FILE = "MicrosoftApps.json"

# Default top 10 Microsoft first-party app IDs (often pre-consented in tenants)
# These are prioritized for authentication attempts
DEFAULT_APP_IDS = {
    "graph_powershell": ("14d82eec-204b-4c2f-b7e8-296a70dab67e", "Microsoft Graph PowerShell"),
    "graph_explorer": ("de8bc8b5-d9f9-48b1-a8ad-b748da725064", "Graph Explorer"),
    "office": ("d3590ed6-52b3-4102-aeff-aad2292ab01c", "Microsoft Office"),
    "teams": ("1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Microsoft Teams"),
    "azure_cli": ("04b07795-8ddb-461a-bbee-02f9e1bf7b46", "Azure CLI"),
    "azure_powershell": ("1950a258-227b-4e31-a9cf-717495945fc2", "Azure PowerShell"),
    "outlook": ("00000002-0000-0ff1-ce00-000000000000", "Office 365 Exchange Online"),
    "sharepoint": ("00000003-0000-0ff1-ce00-000000000000", "Office 365 SharePoint Online"),
    "azure_portal": ("c44b4083-3bb0-49c1-b47d-974e53cbdf3c", "Azure Portal"),
    "intune": ("0000000a-0000-0000-c000-000000000000", "Microsoft Intune"),
}

# Legacy KNOWN_APP_IDS for backward compatibility (maps to app ID only)
KNOWN_APP_IDS = {key: value[0] for key, value in DEFAULT_APP_IDS.items()}

# Extended app IDs loaded from Microsoft Apps JSON (populated at runtime)
EXTENDED_APP_IDS: Dict[str, str] = {}  # {app_id: app_display_name}

PUBLIC_CLIENT_APP_ID = KNOWN_APP_IDS["graph_powershell"]

GRAPH_API_ENDPOINT = "https://graph.microsoft.com/v1.0"
GRAPH_BETA_ENDPOINT = "https://graph.microsoft.com/beta"

# Power Platform API Endpoints
POWERAPPS_API_ENDPOINT = "https://api.powerapps.com"
FLOW_API_ENDPOINT = "https://api.flow.microsoft.com"
BAP_API_ENDPOINT = "https://api.bap.microsoft.com"

# Power Platform resource for token acquisition
POWERAPPS_RESOURCE = "https://service.powerapps.com/"

# Sensitive connector types for Power Automate flows - potential data exfiltration/lateral movement
SENSITIVE_CONNECTORS = {
    # Data Storage & Databases
    "shared_sql": {"name": "SQL Server", "risk": "HIGH", "category": "Database"},
    "shared_azuresqldb": {"name": "Azure SQL Database", "risk": "HIGH", "category": "Database"},
    "shared_cosmosdb": {"name": "Cosmos DB", "risk": "HIGH", "category": "Database"},
    "shared_azuretables": {"name": "Azure Table Storage", "risk": "MEDIUM", "category": "Database"},
    "shared_azureblob": {"name": "Azure Blob Storage", "risk": "HIGH", "category": "Storage"},
    "shared_azurefile": {"name": "Azure File Storage", "risk": "MEDIUM", "category": "Storage"},
    "shared_amazons3": {"name": "Amazon S3", "risk": "HIGH", "category": "Storage"},
    "shared_googlecloudstorage": {"name": "Google Cloud Storage", "risk": "HIGH", "category": "Storage"},
    "shared_ftp": {"name": "FTP", "risk": "HIGH", "category": "Storage"},
    "shared_sftp": {"name": "SFTP", "risk": "HIGH", "category": "Storage"},
    # Microsoft 365 Services
    "shared_sharepointonline": {"name": "SharePoint Online", "risk": "HIGH", "category": "M365"},
    "shared_onedriveforbusiness": {"name": "OneDrive for Business", "risk": "HIGH", "category": "M365"},
    "shared_office365": {"name": "Office 365 Outlook", "risk": "MEDIUM", "category": "M365"},
    "shared_teams": {"name": "Microsoft Teams", "risk": "MEDIUM", "category": "M365"},
    "shared_excelonlinebusiness": {"name": "Excel Online", "risk": "MEDIUM", "category": "M365"},
    # Identity & Access
    "shared_azuread": {"name": "Azure Active Directory", "risk": "CRITICAL", "category": "Identity"},
    "shared_keyvault": {"name": "Azure Key Vault", "risk": "CRITICAL", "category": "Secrets"},
    # External Communication
    "shared_sendgrid": {"name": "SendGrid", "risk": "HIGH", "category": "Email"},
    "shared_smtp": {"name": "SMTP", "risk": "HIGH", "category": "Email"},
    "shared_twiliosms": {"name": "Twilio SMS", "risk": "MEDIUM", "category": "Communication"},
    "shared_slack": {"name": "Slack", "risk": "MEDIUM", "category": "Communication"},
    # HTTP & Custom Code
    "shared_http": {"name": "HTTP", "risk": "CRITICAL", "category": "Custom"},
    "shared_webcontents": {"name": "HTTP with Azure AD", "risk": "HIGH", "category": "Custom"},
    "shared_azurefunctions": {"name": "Azure Functions", "risk": "HIGH", "category": "Compute"},
    "shared_azurelogicapps": {"name": "Azure Logic Apps", "risk": "MEDIUM", "category": "Compute"},
    "shared_custom": {"name": "Custom Connector", "risk": "HIGH", "category": "Custom"},
    # Cloud Services
    "shared_azureautomation": {"name": "Azure Automation", "risk": "HIGH", "category": "Automation"},
    "shared_azuredevops": {"name": "Azure DevOps", "risk": "HIGH", "category": "DevOps"},
    "shared_github": {"name": "GitHub", "risk": "HIGH", "category": "DevOps"},
    # CRM & ERP
    "shared_commondataservice": {"name": "Dataverse", "risk": "HIGH", "category": "CRM"},
    "shared_dynamicscrmonline": {"name": "Dynamics 365", "risk": "HIGH", "category": "CRM"},
    "shared_salesforce": {"name": "Salesforce", "risk": "HIGH", "category": "CRM"},
    # ServiceNow
    "shared_servicenow": {"name": "ServiceNow", "risk": "HIGH", "category": "ITSM"},
}

# Scenario 1: Scope hierarchy - start with lower privilege, fallback as needed
SCOPES_FULL = ["User.Read.All", "User.ReadBasic.All"]  # Full access
SCOPES_BASIC = ["User.ReadBasic.All"]                   # Lower privilege (often allowed)
SCOPES_MINIMAL = ["User.Read"]                          # Minimal - only own profile

# Current active scopes (will be set during auth)
CURRENT_SCOPES = SCOPES_BASIC  # Default to lower privilege

# Request timeout in seconds (allows Ctrl+C to interrupt)
REQUEST_TIMEOUT = 30

# Authentication timeout in seconds for browser-based interactive flows
# If authentication doesn't complete within this time, user can choose to retry
AUTH_TIMEOUT = 120  # 2 minutes - enough time for browser auth but not infinite wait

# Global cancellation flag for long-running operations
_operation_cancelled = threading.Event()

# ============================================================================
# STEALTH & EVASION CONFIGURATION
# ============================================================================

import random
import time
from dataclasses import dataclass, field
from typing import Callable

@dataclass
class StealthConfig:
    """Configuration for stealth and evasion features."""
    enabled: bool = False              # Master switch for stealth mode
    base_delay: float = 0.0            # Base delay between requests (seconds)
    jitter: float = 0.0                # Random jitter range (seconds)
    max_retries: int = 3               # Max retries on throttling
    quiet_mode: bool = False           # Suppress stealth-related output
    request_count: int = 0             # Track total requests made
    throttle_count: int = 0            # Track throttle events
    last_request_time: float = 0.0     # Track timing for rate limiting

# Global stealth configuration instance
_stealth_config = StealthConfig()

def get_stealth_config() -> StealthConfig:
    """Get the current stealth configuration."""
    return _stealth_config

def set_stealth_config(
    enabled: bool = None,
    base_delay: float = None,
    jitter: float = None,
    max_retries: int = None,
    quiet_mode: bool = None
) -> None:
    """Update stealth configuration settings."""
    global _stealth_config
    if enabled is not None:
        _stealth_config.enabled = enabled
        # Set sensible defaults when enabling stealth without explicit values
        if enabled and _stealth_config.base_delay == 0:
            _stealth_config.base_delay = 0.5  # 500ms default
            _stealth_config.jitter = 0.3      # 300ms jitter
    if base_delay is not None:
        _stealth_config.base_delay = max(0.0, min(60.0, base_delay))
    if jitter is not None:
        _stealth_config.jitter = max(0.0, min(30.0, jitter))
    if max_retries is not None:
        _stealth_config.max_retries = max(1, min(10, max_retries))
    if quiet_mode is not None:
        _stealth_config.quiet_mode = quiet_mode

def reset_stealth_stats() -> None:
    """Reset stealth statistics counters."""
    _stealth_config.request_count = 0
    _stealth_config.throttle_count = 0

def get_stealth_delay() -> float:
    """
    Calculate delay with jitter for stealth operations.
    Returns delay value in seconds including base delay plus random jitter.
    """
    config = _stealth_config
    if config.base_delay == 0 and config.jitter == 0:
        return 0.0
    
    # Add random jitter (can be positive or negative)
    jitter_value = 0.0
    if config.jitter > 0:
        jitter_value = random.uniform(-config.jitter, config.jitter)
    
    total_delay = max(0.0, config.base_delay + jitter_value)
    return total_delay

def apply_stealth_delay(context: str = "") -> None:
    """
    Apply stealth delay before making a request.
    Implements configurable delays with jitter to avoid detection patterns.
    """
    config = _stealth_config
    if not config.enabled and config.base_delay == 0:
        return
    
    delay = get_stealth_delay()
    if delay > 0:
        if not config.quiet_mode and context:
            print(f"    [Stealth] Waiting {delay:.2f}s before {context}...")
        time.sleep(delay)
    
    config.last_request_time = time.time()

def get_retry_after_seconds(response: requests.Response, default: int = 30) -> int:
    """
    Extract Retry-After value from response headers.
    Returns the number of seconds to wait before retrying.
    """
    headers = response.headers
    
    # Check Retry-After header
    retry_after = headers.get('Retry-After')
    if retry_after:
        # Try to parse as integer (seconds)
        try:
            return int(retry_after)
        except ValueError:
            pass
        
        # Try to parse as HTTP-date
        try:
            from email.utils import parsedate_to_datetime
            retry_date = parsedate_to_datetime(retry_after)
            seconds = (retry_date - datetime.now(retry_date.tzinfo)).total_seconds()
            return max(1, int(seconds))
        except (ValueError, TypeError):
            pass
    
    # Check RateLimit-Reset header (Unix timestamp)
    rate_limit_reset = headers.get('RateLimit-Reset')
    if rate_limit_reset:
        try:
            reset_time = int(rate_limit_reset)
            seconds = reset_time - int(time.time())
            return max(1, seconds)
        except ValueError:
            pass
    
    return default

def wait_for_throttle_reset(seconds: int, quiet: bool = False) -> None:
    """
    Wait for throttle reset with countdown display.
    Used when Graph API returns 429 Too Many Requests.
    """
    _stealth_config.throttle_count += 1
    
    if quiet or _stealth_config.quiet_mode:
        time.sleep(seconds)
        return
    
    print(f"    [Throttle] Rate limited. Waiting {seconds} seconds...")
    
    for i in range(seconds, 0, -1):
        print(f"\r    [Throttle] Resuming in {i}s...  ", end="", flush=True)
        time.sleep(1)
    
    print(f"\r    [Throttle] Resuming operations...   ")

def show_stealth_status() -> None:
    """Display current stealth configuration and statistics."""
    config = _stealth_config
    
    print("\n" + "-" * 50)
    print("STEALTH & EVASION STATUS")
    print("-" * 50)
    
    status = "ENABLED" if config.enabled else "DISABLED"
    status_color = "\033[92m" if config.enabled else "\033[93m"  # Green/Yellow
    reset_color = "\033[0m"
    
    print(f"  Stealth Mode:    {status_color}{status}{reset_color}")
    print(f"  Base Delay:      {config.base_delay}s")
    print(f"  Jitter Range:    +/- {config.jitter}s")
    print(f"  Max Retries:     {config.max_retries}")
    print(f"  Quiet Mode:      {config.quiet_mode}")
    
    if config.request_count > 0:
        print(f"\n  Requests Made:   {config.request_count}")
        print(f"  Throttle Events: {config.throttle_count}")
    
    print("-" * 50)


def reset_cancellation():
    """Reset the cancellation flag before starting a new operation."""
    _operation_cancelled.clear()


def request_cancellation():
    """Signal that the current operation should be cancelled."""
    _operation_cancelled.set()


def is_cancelled() -> bool:
    """Check if the current operation has been cancelled."""
    return _operation_cancelled.is_set()


def get_microsoft_apps_file_info() -> Optional[datetime]:
    """
    Get the last modified datetime of the local Microsoft Apps JSON file.
    Returns None if the file doesn't exist.
    """
    local_path = Path(MICROSOFT_APPS_LOCAL_FILE)
    if local_path.exists():
        mtime = local_path.stat().st_mtime
        return datetime.fromtimestamp(mtime)
    return None


def download_microsoft_apps_json(force: bool = False) -> bool:
    """
    Download the Microsoft Apps JSON from the remote URL.
    Shows the last update time and asks for user confirmation.
    
    Args:
        force: If True, skip confirmation prompt
        
    Returns:
        True if download was successful, False otherwise
    """
    local_path = Path(MICROSOFT_APPS_LOCAL_FILE)
    
    print("\n" + "=" * 60)
    print("MICROSOFT APPS DATABASE UPDATE")
    print("=" * 60)
    print(f"Source: {MICROSOFT_APPS_JSON_URL}")
    print(f"Local file: {local_path.absolute()}")
    
    # Check if file exists and show last modified time
    file_modified = get_microsoft_apps_file_info()
    if file_modified:
        print(f"\nLast local update: {file_modified.strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print("\nNo local file found. A fresh download is recommended.")
    
    # Ask for confirmation unless forced
    if not force:
        print("\nThis will download the latest Microsoft Apps database")
        print("containing thousands of known Microsoft first-party App IDs.")
        confirm = input("\nProceed with download? (y/n): ").strip().lower()
        if confirm not in ('y', 'yes'):
            print("[*] Download cancelled.")
            return False
    
    # Perform download
    print("\n[*] Downloading Microsoft Apps JSON...")
    try:
        response = requests.get(MICROSOFT_APPS_JSON_URL, timeout=30)
        response.raise_for_status()
        
        # Write to local file
        with open(local_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        # Get new file info
        new_modified = get_microsoft_apps_file_info()
        print(f"[+] Download successful!")
        print(f"[+] File saved: {local_path.absolute()}")
        if new_modified:
            print(f"[+] Updated at: {new_modified.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Parse and show count
        apps = parse_microsoft_apps_json()
        if apps:
            print(f"[+] Loaded {len(apps)} Microsoft App IDs")
        
        return True
        
    except requests.exceptions.Timeout:
        print("[!] Download timed out. Please try again later.")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[!] Download failed: {e}")
        return False
    except IOError as e:
        print(f"[!] Failed to save file: {e}")
        return False


def parse_microsoft_apps_json() -> Dict[str, str]:
    """
    Parse the local Microsoft Apps JSON file and extract App IDs.
    
    Returns:
        Dictionary mapping AppId to AppDisplayName
    """
    global EXTENDED_APP_IDS
    
    local_path = Path(MICROSOFT_APPS_LOCAL_FILE)
    if not local_path.exists():
        return {}
    
    try:
        with open(local_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Parse JSON array and build dictionary
        app_dict = {}
        for app in data:
            app_id = app.get("AppId", "")
            app_name = app.get("AppDisplayName", "Unknown")
            if app_id:
                app_dict[app_id] = app_name
        
        # Update global extended app IDs
        EXTENDED_APP_IDS = app_dict
        return app_dict
        
    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse Microsoft Apps JSON: {e}")
        return {}
    except IOError as e:
        print(f"[!] Failed to read Microsoft Apps JSON: {e}")
        return {}


def load_extended_app_ids() -> Dict[str, str]:
    """
    Load extended app IDs from the local JSON file if it exists.
    This is called at startup to populate EXTENDED_APP_IDS.
    
    Returns:
        Dictionary mapping AppId to AppDisplayName
    """
    if Path(MICROSOFT_APPS_LOCAL_FILE).exists():
        return parse_microsoft_apps_json()
    return {}


def get_all_available_app_ids() -> List[Tuple[str, str]]:
    """
    Get a combined list of all available app IDs.
    Default app IDs come first (top 10), then extended app IDs from JSON.
    
    Returns:
        List of (app_id, app_name) tuples, with defaults first
    """
    result = []
    seen_ids = set()
    
    # Add default app IDs first (in order)
    for key in ["graph_powershell", "graph_explorer", "office", "teams", 
                "azure_cli", "azure_powershell", "outlook", "sharepoint", 
                "azure_portal", "intune"]:
        if key in DEFAULT_APP_IDS:
            app_id, app_name = DEFAULT_APP_IDS[key]
            result.append((app_id, app_name))
            seen_ids.add(app_id)
    
    # Add extended app IDs (excluding duplicates)
    for app_id, app_name in EXTENDED_APP_IDS.items():
        if app_id not in seen_ids:
            result.append((app_id, app_name))
            seen_ids.add(app_id)
    
    return result


def make_api_request(url: str, headers: dict, method: str = "GET", 
                     json_data: dict = None, timeout: int = REQUEST_TIMEOUT,
                     skip_delay: bool = False, context: str = "request") -> Optional[requests.Response]:
    """
    Make an API request with timeout, cancellation, and stealth support.
    
    Features:
    - Configurable delays between requests with jitter
    - Automatic retry on 429 (Too Many Requests) with Retry-After handling
    - Exponential backoff on 503 Service Unavailable
    - Respects Graph API throttling headers
    
    Returns None if cancelled or on unrecoverable error.
    """
    if is_cancelled():
        return None
    
    config = _stealth_config
    
    # Apply stealth delay before request (unless skipped)
    if not skip_delay:
        apply_stealth_delay(context)
    
    config.request_count += 1
    retry_count = 0
    max_retries = config.max_retries
    
    while retry_count <= max_retries:
        if is_cancelled():
            return None
        
        try:
            response = None
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, json=json_data, timeout=timeout)
            elif method.upper() == "PATCH":
                response = requests.patch(url, headers=headers, json=json_data, timeout=timeout)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers, timeout=timeout)
            else:
                return None
            
            # Handle 429 Too Many Requests (throttling)
            if response.status_code == 429:
                if retry_count >= max_retries:
                    if not config.quiet_mode:
                        print(f"    [!] Max retries ({max_retries}) exceeded for throttling")
                    return response  # Return response so caller can handle
                
                # Get retry delay from headers
                retry_after = get_retry_after_seconds(response, default=30)
                
                # Add jitter to retry delay
                jitter_ms = random.randint(0, 5000)
                total_wait = retry_after + (jitter_ms / 1000)
                
                wait_for_throttle_reset(int(total_wait))
                
                retry_count += 1
                continue
            
            # Handle 503 Service Unavailable (temporary issues)
            if response.status_code == 503:
                if retry_count < max_retries:
                    backoff_seconds = (2 ** retry_count) * 5  # Exponential backoff
                    if not config.quiet_mode:
                        print(f"    [!] Service unavailable. Backing off for {backoff_seconds} seconds...")
                    time.sleep(backoff_seconds)
                    retry_count += 1
                    continue
            
            # Return response for all other status codes
            return response
            
        except requests.exceptions.Timeout:
            if not config.quiet_mode:
                print(f"    Request timed out after {timeout}s")
            return None
        except requests.exceptions.RequestException as e:
            if not is_cancelled() and not config.quiet_mode:
                print(f"    Request error: {e}")
            return None
    
    return None


def run_with_cancel_support(func, *args, **kwargs):
    """
    Run a function with Ctrl+C cancellation support.
    Returns the function result or None if cancelled.
    """
    reset_cancellation()
    print("    (Press Ctrl+C to cancel this operation)")
    
    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        request_cancellation()
        print("\n[!] Operation cancelled by user.")
        return None


def get_token_from_az_cli() -> Optional[str]:
    """
    Scenario 4: Try using Azure CLI's cached token if available.
    Azure CLI often has broader pre-consented permissions.
    """
    print("[*] Attempting to get token from Azure CLI...")
    
    try:
        result = subprocess.run(
            ["az", "account", "get-access-token", "--resource", "https://graph.microsoft.com"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            token_data = json.loads(result.stdout)
            access_token = token_data.get("accessToken")
            if access_token:
                print("[+] Successfully obtained token from Azure CLI")
                try:
                    expires_on = token_data.get("expiresOn", "Unknown")
                    print(f"    Token expires: {expires_on}")
                except:
                    pass
                return access_token
        else:
            print(f"[!] Azure CLI error: {result.stderr.strip()}")
    except FileNotFoundError:
        print("[!] Azure CLI not found. Install with: https://aka.ms/installazurecli")
    except subprocess.TimeoutExpired:
        print("[!] Azure CLI timed out")
    except json.JSONDecodeError:
        print("[!] Failed to parse Azure CLI response")
    except Exception as e:
        print(f"[!] Azure CLI error: {e}")
    
    return None


def get_token_from_az_powershell() -> Optional[str]:
    """
    Alternative: Try using Azure PowerShell's cached token.
    """
    print("[*] Attempting to get token from Azure PowerShell...")
    
    try:
        for pwsh in ["pwsh", "powershell"]:
            try:
                # Suppress warnings and only output the token
                ps_command = """
                    $WarningPreference = 'SilentlyContinue'
                    $ProgressPreference = 'SilentlyContinue'
                    (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -WarningAction SilentlyContinue).Token
                """
                result = subprocess.run(
                    [pwsh, "-NoProfile", "-Command", ps_command],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    # Extract only the token (last non-empty line, should be JWT)
                    lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
                    # Find the JWT token (starts with eyJ)
                    token = None
                    for line in reversed(lines):
                        if line.startswith('eyJ') and len(line) > 100:
                            token = line
                            break
                    
                    if not token and lines:
                        # Fallback: take the last line if it looks like a token
                        token = lines[-1]
                    
                    if token and len(token) > 100 and not token.startswith('WARNING'):
                        print(f"[+] Successfully obtained token from Azure PowerShell ({pwsh})")
                        return token
            except FileNotFoundError:
                continue
            except Exception:
                continue
                
    except Exception as e:
        print(f"[!] Azure PowerShell error: {e}")
    
    return None


def get_arm_token_from_az_cli() -> Optional[str]:
    """
    Get Azure Resource Manager token for ARM API calls.
    """
    try:
        result = subprocess.run(
            ["az", "account", "get-access-token", "--resource", "https://management.azure.com"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            token_data = json.loads(result.stdout)
            return token_data.get("accessToken")
    except:
        pass
    return None


def get_token_from_environment() -> Optional[str]:
    """
    Check for token in environment variables.
    Useful when token is obtained externally or in CI/CD pipelines.
    """
    print("[*] Checking environment variables for token...")
    
    env_vars = [
        "GRAPH_ACCESS_TOKEN",
        "AZURE_ACCESS_TOKEN",
        "ACCESS_TOKEN",
        "BEARER_TOKEN",
    ]
    
    for var in env_vars:
        token = os.environ.get(var)
        if token and len(token) > 100:
            print(f"[+] Found token in ${var}")
            return token
    
    return None


def get_token_from_default_credential() -> Optional[str]:
    """
    Use Azure Identity DefaultAzureCredential - chains multiple auth methods:
    - Environment variables
    - Managed Identity (Azure VM, App Service, Functions)
    - Azure CLI
    - Azure PowerShell
    - Visual Studio Code
    - Interactive browser (fallback)
    """
    if not AZURE_IDENTITY_AVAILABLE:
        print("[!] azure-identity not installed. Run: pip install azure-identity")
        return None
    
    print("[*] Trying DefaultAzureCredential (chains multiple methods)...")
    
    try:
        credential = DefaultAzureCredential()
        token = credential.get_token("https://graph.microsoft.com/.default")
        if token and token.token:
            print("[+] Successfully obtained token via DefaultAzureCredential")
            return token.token
    except Exception as e:
        print(f"[!] DefaultAzureCredential failed: {str(e)[:100]}")
    
    return None


def get_token_from_shared_cache() -> Optional[str]:
    """
    Try to get token from Windows shared token cache.
    This can find tokens cached by other Microsoft apps (Office, Teams, etc.)
    """
    if not AZURE_IDENTITY_AVAILABLE:
        return None
    
    print("[*] Checking shared token cache (Office/Teams/VS cached tokens)...")
    
    try:
        credential = SharedTokenCacheCredential()
        token = credential.get_token("https://graph.microsoft.com/.default")
        if token and token.token:
            print("[+] Found token in shared cache")
            return token.token
    except Exception as e:
        if "No cached token" not in str(e):
            print(f"[!] Shared cache: {str(e)[:80]}")
    
    return None


def get_token_from_vscode() -> Optional[str]:
    """
    Try to get token from VS Code Azure extension cache.
    Works if user has Azure extension installed and logged in.
    """
    if not AZURE_IDENTITY_AVAILABLE:
        return None
    
    print("[*] Checking VS Code Azure extension cache...")
    
    try:
        credential = VisualStudioCodeCredential()
        token = credential.get_token("https://graph.microsoft.com/.default")
        if token and token.token:
            print("[+] Found token from VS Code")
            return token.token
    except Exception as e:
        if "No token" not in str(e):
            print(f"[!] VS Code: {str(e)[:80]}")
    
    return None


def get_token_from_wam_broker() -> Optional[str]:
    """
    Windows Web Account Manager (WAM) Broker authentication.
    Uses Windows' built-in authentication broker for SSO.
    Works with Windows Hello, cached Windows credentials.
    """
    print("[*] Trying Windows WAM Broker (Windows SSO)...")
    
    try:
        # MSAL supports WAM on Windows
        app = msal.PublicClientApplication(
            PUBLIC_CLIENT_APP_ID,
            authority="https://login.microsoftonline.com/common",
        )
        
        # Try to get token silently using WAM
        # This requires MSAL 1.20+ with broker support
        accounts = app.get_accounts()
        if accounts:
            result = app.acquire_token_silent(
                scopes=["https://graph.microsoft.com/.default"],
                account=accounts[0],
            )
            if result and "access_token" in result:
                print("[+] Got token via WAM broker")
                return result["access_token"]
    except Exception as e:
        print(f"[!] WAM broker: {str(e)[:80]}")
    
    return None


def get_token_from_managed_identity() -> Optional[str]:
    """
    Azure Managed Identity - works when running on Azure resources:
    - Azure VMs
    - Azure App Service
    - Azure Functions
    - Azure Container Instances
    - Azure Kubernetes Service
    """
    print("[*] Checking for Managed Identity (Azure VM/App Service)...")
    
    # Check if running in Azure
    azure_endpoints = [
        "http://169.254.169.254/metadata/identity/oauth2/token",  # VM
        os.environ.get("IDENTITY_ENDPOINT"),  # App Service
    ]
    
    for endpoint in azure_endpoints:
        if not endpoint:
            continue
        try:
            params = {
                "api-version": "2019-08-01",
                "resource": "https://graph.microsoft.com"
            }
            headers = {"Metadata": "true"}
            
            # For App Service, add secret header
            secret = os.environ.get("IDENTITY_HEADER")
            if secret:
                headers["X-IDENTITY-HEADER"] = secret
            
            response = requests.get(endpoint, params=params, headers=headers, timeout=5)
            
            if response.status_code == 200:
                token = response.json().get("access_token")
                if token:
                    print("[+] Got token via Managed Identity")
                    return token
        except Exception:
            continue
    
    return None


def get_token_manual_input() -> Optional[str]:
    """
    Allow user to manually paste a token obtained elsewhere.
    Useful for tokens obtained via:
    - Browser DevTools (Network tab)
    - Burp Suite intercept
    - Other tools like TokenTactics, ROADtools
    """
    print("\n" + "=" * 60)
    print("MANUAL TOKEN INPUT")
    print("=" * 60)
    print("\nPaste an access token obtained from another source.")
    print("(e.g., from browser DevTools, Burp Suite, or other tools)")
    print("\nPress Enter twice when done, or type 'skip' to skip.\n")
    
    lines = []
    try:
        while True:
            line = input()
            if line.lower() == 'skip':
                return None
            if not line and lines:
                break
            if line:
                lines.append(line)
    except (EOFError, KeyboardInterrupt):
        return None
    
    token = ''.join(lines).strip()
    
    if token and len(token) > 100:
        # Basic validation - check if it looks like a JWT
        if token.startswith("eyJ"):
            print("[+] Token accepted (JWT format detected)")
            return token
        else:
            print("[!] Warning: Token doesn't look like a JWT, but trying anyway...")
            return token
    
    return None


def get_token_from_refresh_token(refresh_token: str, tenant_id: str = "common") -> Optional[str]:
    """
    Exchange a refresh token for an access token.
    Refresh tokens can be obtained from various sources.
    """
    print("[*] Exchanging refresh token for access token...")
    
    try:
        app = msal.PublicClientApplication(
            PUBLIC_CLIENT_APP_ID,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
        )
        
        result = app.acquire_token_by_refresh_token(
            refresh_token,
            scopes=["https://graph.microsoft.com/.default"]
        )
        
        if result and "access_token" in result:
            print("[+] Successfully exchanged refresh token")
            return result["access_token"]
        else:
            error = result.get("error_description", "Unknown error")
            print(f"[!] Refresh token exchange failed: {error[:100]}")
    except Exception as e:
        print(f"[!] Refresh token error: {e}")
    
    return None


def try_authenticate_with_scopes(
    tenant_id: str, 
    scopes: list, 
    use_device_code: bool = False,
    timeout: int = AUTH_TIMEOUT
) -> Tuple[Optional[str], list, bool]:
    """
    Scenario 2: Try authentication with specific scopes, return token and actual scopes.
    Includes timeout handling for interactive browser authentication.
    
    Args:
        tenant_id: The tenant ID or 'common'
        scopes: List of scopes to request
        use_device_code: Whether to use device code flow instead of interactive browser
        timeout: Timeout in seconds for browser authentication (default: AUTH_TIMEOUT)
        
    Returns:
        Tuple of (access_token, scopes, timed_out):
        - (token, scopes, False) if successful
        - (None, [], False) if failed (e.g., permission denied)
        - (None, [], True) if timed out (should not retry with different scopes)
    """
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    
    app = msal.PublicClientApplication(
        PUBLIC_CLIENT_APP_ID,
        authority=authority,
    )
    
    accounts = app.get_accounts()
    if accounts:
        print(f"[*] Found cached account: {accounts[0]['username']}")
        result = app.acquire_token_silent(scopes, account=accounts[0])
        if result and "access_token" in result:
            print("[+] Using cached token")
            return result["access_token"], scopes, False
    
    if use_device_code:
        flow = app.initiate_device_flow(scopes=scopes)
        if "user_code" not in flow:
            return None, [], False
        
        print("\n" + "=" * 60)
        print("DEVICE CODE AUTHENTICATION")
        print("=" * 60)
        print(f"\n{flow['message']}\n")
        print("=" * 60)
        
        try:
            webbrowser.open(flow["verification_uri"])
        except Exception:
            pass
        
        result = app.acquire_token_by_device_flow(flow)
    else:
        print("[*] Opening browser for authentication...")
        print(f"    Requesting scopes: {', '.join(scopes)}")
        print(f"    Timeout: {timeout} seconds (Ctrl+C to abort)")
        print()
        
        # Use threading with daemon thread to allow timeout without blocking
        # Daemon threads are killed when main program exits
        result_container = {"result": None, "error": None, "done": False}
        
        def do_interactive_auth():
            try:
                result_container["result"] = app.acquire_token_interactive(
                    scopes=scopes,
                    prompt="select_account",
                )
            except Exception as e:
                result_container["error"] = e
            finally:
                result_container["done"] = True
        
        auth_thread = threading.Thread(target=do_interactive_auth, daemon=True)
        auth_thread.start()
        auth_thread.join(timeout=timeout)
        
        if not result_container["done"]:
            # Thread is still running - timed out
            print(f"\n[!] Authentication timed out after {timeout} seconds.")
            print("[!] The browser window may still be open - you can close it.")
            return None, [], True  # True = timed out, don't retry with other scopes
        
        if result_container["error"]:
            print(f"\n[!] Authentication error: {result_container['error']}")
            return None, [], True
        
        result = result_container["result"]
    
    if result and "access_token" in result:
        username = result.get('id_token_claims', {}).get('preferred_username', 'Unknown')
        print(f"[+] Authenticated as: {username}")
        return result["access_token"], scopes, False
    else:
        error = result.get('error', 'Unknown') if result else 'Unknown'
        error_desc = result.get('error_description', '') if result else ''
        print(f"[!] Auth failed with scopes {scopes}: {error}")
        if error_desc:
            print(f"    {error_desc[:200]}")
        return None, [], False


def get_access_token_with_fallback(tenant_id: str = "common", use_device_code: bool = False) -> Tuple[Optional[str], list]:
    """
    Scenario 2: Authentication with graceful fallback through multiple methods.
    Tries methods in order of least user interaction to most.
    """
    global CURRENT_SCOPES
    
    print("\n" + "-" * 50)
    print("AUTHENTICATION STRATEGY (Auto-Fallback)")
    print("-" * 50)
    
    # 1. Check environment variables first (no interaction)
    env_token = get_token_from_environment()
    if env_token:
        CURRENT_SCOPES = ["Environment"]
        return env_token, ["Environment"]
    
    # 2. Try Azure CLI (already logged in)
    cli_token = get_token_from_az_cli()
    if cli_token:
        CURRENT_SCOPES = ["AzureCLI"]
        return cli_token, ["AzureCLI"]
    
    # 3. Try Azure PowerShell (already logged in)
    ps_token = get_token_from_az_powershell()
    if ps_token:
        CURRENT_SCOPES = ["AzurePowerShell"]
        return ps_token, ["AzurePowerShell"]
    
    # 4. Try Managed Identity (Azure VMs/App Service)
    mi_token = get_token_from_managed_identity()
    if mi_token:
        CURRENT_SCOPES = ["ManagedIdentity"]
        return mi_token, ["ManagedIdentity"]
    
    # 5. Try shared token cache (Office/Teams cached tokens)
    cache_token = get_token_from_shared_cache()
    if cache_token:
        CURRENT_SCOPES = ["SharedCache"]
        return cache_token, ["SharedCache"]
    
    # 6. Try VS Code Azure extension
    vscode_token = get_token_from_vscode()
    if vscode_token:
        CURRENT_SCOPES = ["VSCode"]
        return vscode_token, ["VSCode"]
    
    # 7. Try DefaultAzureCredential (chains multiple methods)
    default_token = get_token_from_default_credential()
    if default_token:
        CURRENT_SCOPES = ["DefaultCredential"]
        return default_token, ["DefaultCredential"]
    
    # 8. Try WAM broker (Windows SSO)
    wam_token = get_token_from_wam_broker()
    if wam_token:
        CURRENT_SCOPES = ["WAMBroker"]
        return wam_token, ["WAMBroker"]
    
    # 9. Fall back to MSAL interactive/device code with scope fallback
    scope_levels = [
        ("Full access", SCOPES_BASIC),
        ("Read all users", SCOPES_FULL),
        ("Minimal (own profile only)", SCOPES_MINIMAL),
    ]
    
    print("\n[*] Trying MSAL authentication with fallback scopes...")
    
    for level_name, scopes in scope_levels:
        print(f"\n[*] Trying: {level_name} ({', '.join(scopes)})")
        
        token, actual_scopes, timed_out = try_authenticate_with_scopes(tenant_id, scopes, use_device_code)
        
        if token:
            CURRENT_SCOPES = actual_scopes
            return token, actual_scopes
        
        # If authentication timed out or had a critical error, don't try more scopes
        # The problem is with the auth method itself, not the scope permissions
        if timed_out:
            print("\n[!] Stopping scope fallback - authentication method not responding.")
            break
    
    return None, []


def get_access_token_interactive(tenant_id: str = "common") -> Optional[str]:
    """Acquire access token using interactive browser authentication with fallback."""
    token, _ = get_access_token_with_fallback(tenant_id, use_device_code=False)
    return token


def get_access_token_device_code(tenant_id: str = "common") -> Optional[str]:
    """Acquire access token using device code flow with fallback."""
    token, _ = get_access_token_with_fallback(tenant_id, use_device_code=True)
    return token


def try_all_app_ids_auth(tenant_id: str = "common", use_device_code: bool = False) -> Optional[str]:
    """
    Try authentication with all available app IDs until one succeeds.
    Starts with default top 10 apps, then tries all extended apps from Microsoft Apps JSON.
    
    Args:
        tenant_id: The tenant ID or 'common'
        use_device_code: Whether to use device code flow instead of interactive browser
        
    Returns:
        Access token if authentication succeeds, None otherwise
    """
    global PUBLIC_CLIENT_APP_ID
    
    # Load extended app IDs
    load_extended_app_ids()
    
    # Get all available app IDs (defaults first, then extended)
    all_apps = get_all_available_app_ids()
    
    if not all_apps:
        print("[!] No app IDs available. Download Microsoft Apps database first.")
        return None
    
    total_apps = len(all_apps)
    print("\n" + "=" * 60)
    print("AUTO-TRY ALL APP IDS")
    print("=" * 60)
    print(f"[*] Will try {total_apps} app IDs until authentication succeeds")
    print(f"[*] Tenant: {tenant_id}")
    print(f"[*] Method: {'Device Code' if use_device_code else 'Interactive Browser'}")
    print("[*] Press Ctrl+C to abort at any time")
    print("=" * 60)
    
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scopes = ["User.Read"]  # Minimal scope for initial auth attempt
    
    tried = 0
    for app_id, app_name in all_apps:
        tried += 1
        
        # Check for cancellation
        if is_cancelled():
            print("\n[!] Auto-try cancelled by user.")
            return None
        
        # Truncate long app names for display
        display_name = app_name[:40] + "..." if len(app_name) > 40 else app_name
        print(f"\n[{tried}/{total_apps}] Trying: {display_name}")
        print(f"         App ID: {app_id}")
        
        try:
            app = msal.PublicClientApplication(
                app_id,
                authority=authority,
            )
            
            if use_device_code:
                # Device code flow
                flow = app.initiate_device_flow(scopes=scopes)
                if "user_code" not in flow:
                    print(f"         [-] Failed to initiate device flow")
                    continue
                
                print(f"\n         Device Code: {flow.get('user_code', 'N/A')}")
                print(f"         URL: {flow.get('verification_uri', 'N/A')}")
                print("         Waiting for user authentication...")
                
                result = app.acquire_token_by_device_flow(flow)
            else:
                # Interactive browser flow with timeout using daemon thread
                print(f"         Opening browser... (timeout: {AUTH_TIMEOUT}s)")
                
                result_container = {"result": None, "error": None, "done": False}
                
                def do_interactive_auth():
                    try:
                        result_container["result"] = app.acquire_token_interactive(
                            scopes=scopes,
                            prompt="select_account",
                        )
                    except Exception as e:
                        result_container["error"] = e
                    finally:
                        result_container["done"] = True
                
                auth_thread = threading.Thread(target=do_interactive_auth, daemon=True)
                auth_thread.start()
                auth_thread.join(timeout=AUTH_TIMEOUT)
                
                if not result_container["done"]:
                    print(f"         [-] Timed out after {AUTH_TIMEOUT}s")
                    continue
                
                if result_container["error"]:
                    print(f"         [-] Auth error: {str(result_container['error'])[:60]}")
                    continue
                
                result = result_container["result"]
            
            if result and "access_token" in result:
                username = result.get('id_token_claims', {}).get('preferred_username', 'Unknown')
                PUBLIC_CLIENT_APP_ID = app_id
                
                print("\n" + "=" * 60)
                print("[+] AUTHENTICATION SUCCESSFUL!")
                print("=" * 60)
                print(f"[+] App: {app_name}")
                print(f"[+] App ID: {app_id}")
                print(f"[+] User: {username}")
                print("=" * 60)
                
                return result["access_token"]
            elif result:
                error = result.get('error', 'Unknown')
                error_desc = result.get('error_description', '')[:100]
                print(f"         [-] Failed: {error}")
                if error_desc:
                    print(f"             {error_desc}")
            # If result is None (from timeout), we already printed the message above
                    
        except KeyboardInterrupt:
            print("\n\n[!] Auto-try interrupted by user.")
            return None
        except Exception as e:
            print(f"         [-] Error: {str(e)[:80]}")
            continue
    
    print("\n" + "=" * 60)
    print("[!] AUTHENTICATION FAILED")
    print("=" * 60)
    print(f"[!] Tried {tried} app IDs without success.")
    print("[*] Possible reasons:")
    print("    - Conditional Access policies blocking all apps")
    print("    - User not authorized for any of the apps")
    print("    - Tenant has strict app consent requirements")
    print("=" * 60)
    
    return None


def make_graph_request(access_token: str, url: str, method: str = "GET", 
                       data: dict = None, headers_extra: dict = None,
                       skip_delay: bool = False, context: str = "Graph API") -> Optional[dict]:
    """
    Helper function to make Graph API requests with stealth and throttling support.
    
    Features:
    - Configurable delays with jitter to avoid detection patterns
    - Automatic retry on 429 (throttling) with Retry-After handling
    - Exponential backoff on 503 Service Unavailable
    
    Returns parsed JSON response or None on error.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    if headers_extra:
        headers.update(headers_extra)
    
    # Use make_api_request for stealth and throttle handling
    response = make_api_request(
        url=url,
        headers=headers,
        method=method,
        json_data=data,
        skip_delay=skip_delay,
        context=context
    )
    
    if response is None:
        return None
    
    if response.status_code == 200:
        try:
            return response.json()
        except ValueError:
            return None
    elif response.status_code == 403:
        return None
    else:
        return None


def get_users(access_token: str, select_fields: Optional[list] = None) -> list:
    """
    Enumerate users from Azure Entra ID via direct /users endpoint.
    
    Uses stealth-aware request handling with configurable delays,
    jitter, and automatic throttle handling.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    if select_fields is None:
        select_fields = [
            "id", "displayName", "userPrincipalName", "mail",
            "givenName", "surname", "jobTitle", "department",
            "officeLocation", "userType",
        ]

    select_param = ",".join(select_fields)
    url = f"{GRAPH_API_ENDPOINT}/users?$select={select_param}&$top=999"

    all_users = []
    page_num = 1

    while url:
        # Use stealth-aware request function
        response = make_api_request(
            url=url,
            headers=headers,
            method="GET",
            context=f"users page {page_num}"
        )
        
        if response is None:
            # Request failed or was cancelled
            break

        if response.status_code == 200:
            data = response.json()
            users = data.get("value", [])
            all_users.extend(users)
            url = data.get("@odata.nextLink")
            page_num += 1
        elif response.status_code == 403:
            print("[!] Access denied for /users endpoint.")
            break
        elif response.status_code == 429:
            # Throttling already handled by make_api_request, but exceeded retries
            print("[!] Throttled - max retries exceeded.")
            break
        else:
            print(f"[!] Error: {response.status_code}")
            break

    return all_users


def get_current_user(access_token: str) -> Optional[dict]:
    """Get information about the currently signed-in user."""
    return make_graph_request(access_token, f"{GRAPH_API_ENDPOINT}/me")


def search_users(access_token: str, search_term: str) -> list:
    """Search for users by name or email."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "ConsistencyLevel": "eventual",
    }

    url = f'{GRAPH_API_ENDPOINT}/users?$search="displayName:{search_term}" OR "mail:{search_term}"&$top=25'

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json().get("value", [])
    return []


# ============================================================================
# BASIC ALTERNATIVE ENUMERATION METHODS
# ============================================================================

def get_people(access_token: str, top: int = 1000) -> list:
    """Use People API - often less restricted than /users."""
    print("[*] Trying People API...")
    
    url = f"{GRAPH_API_ENDPOINT}/me/people?$top={top}"
    result = make_graph_request(access_token, url)
    
    if result:
        people = result.get("value", [])
        if people:
            print(f"[+] Found {len(people)} people via People API")
            return people
    
    print("[!] People API: No results or access denied")
    return []


def get_manager_chain(access_token: str) -> list:
    """Enumerate users via manager chain."""
    print("[*] Trying manager chain enumeration...")
    
    managers = []
    url = f"{GRAPH_API_ENDPOINT}/me/manager"
    visited = set()
    
    while url:
        result = make_graph_request(access_token, url)
        if not result:
            break
            
        manager_id = result.get("id")
        if not manager_id or manager_id in visited:
            break
            
        visited.add(manager_id)
        managers.append(result)
        url = f"{GRAPH_API_ENDPOINT}/users/{manager_id}/manager"
    
    if managers:
        print(f"[+] Found {len(managers)} managers in hierarchy")
    else:
        print("[!] Manager chain: No results or access denied")
    
    return managers


def get_direct_reports(access_token: str, user_id: str = "me") -> list:
    """Get direct reports of a user."""
    print("[*] Trying direct reports enumeration...")
    
    url = f"{GRAPH_API_ENDPOINT}/{user_id}/directReports"
    result = make_graph_request(access_token, url)
    
    if result:
        reports = result.get("value", [])
        if reports:
            print(f"[+] Found {len(reports)} direct reports")
            return reports
    
    print("[!] Direct reports: No results or access denied")
    return []


def get_group_members(access_token: str) -> list:
    """Enumerate users via group membership."""
    print("[*] Trying group membership enumeration...")
    
    groups_url = f"{GRAPH_API_ENDPOINT}/me/memberOf"
    result = make_graph_request(access_token, groups_url)
    
    if not result:
        print("[!] Group membership: Access denied")
        return []
    
    all_users = []
    seen_users = set()
    memberships = result.get("value", [])
    
    for membership in memberships:
        obj_type = membership.get("@odata.type", "")
        obj_id = membership.get("id")
        
        if "#microsoft.graph.group" in obj_type and obj_id:
            members_url = f"{GRAPH_API_ENDPOINT}/groups/{obj_id}/members?$top=999"
            members_result = make_graph_request(access_token, members_url)
            
            if members_result:
                for member in members_result.get("value", []):
                    member_id = member.get("id")
                    if member_id and member_id not in seen_users:
                        if "#microsoft.graph.user" in member.get("@odata.type", ""):
                            seen_users.add(member_id)
                            all_users.append(member)
    
    if all_users:
        print(f"[+] Found {len(all_users)} users via group membership")
    else:
        print("[!] Group membership: No users found")
    
    return all_users


# ============================================================================
# ADVANCED FALLBACK METHODS
# ============================================================================

def get_users_via_search_api(access_token: str) -> list:
    """
    Use Microsoft Search API to find people.
    Often has different permission requirements than direct user enumeration.
    """
    print("[*] Trying Microsoft Search API...")
    
    url = f"{GRAPH_API_ENDPOINT}/search/query"
    
    # Search for all people
    search_queries = [
        {"entityTypes": ["person"], "query": {"queryString": "*"}},
        {"entityTypes": ["person"], "query": {"queryString": "a*"}},
        {"entityTypes": ["person"], "query": {"queryString": "b*"}},
        {"entityTypes": ["person"], "query": {"queryString": "c*"}},
    ]
    
    all_people = []
    seen_ids = set()
    
    for search_request in search_queries:
        data = {"requests": [search_request]}
        result = make_graph_request(access_token, url, method="POST", data=data)
        
        if result and "value" in result:
            for response in result["value"]:
                hits = response.get("hitsContainers", [])
                for container in hits:
                    for hit in container.get("hits", []):
                        resource = hit.get("resource", {})
                        person_id = resource.get("id")
                        if person_id and person_id not in seen_ids:
                            seen_ids.add(person_id)
                            all_people.append({
                                "id": person_id,
                                "displayName": resource.get("displayName", ""),
                                "userPrincipalName": resource.get("userPrincipalName", ""),
                                "mail": resource.get("emailAddresses", [{}])[0].get("address", "") if resource.get("emailAddresses") else "",
                                "jobTitle": resource.get("jobTitle", ""),
                                "department": resource.get("department", ""),
                            })
    
    if all_people:
        print(f"[+] Found {len(all_people)} people via Search API")
    else:
        print("[!] Search API: No results or access denied")
    
    return all_people


def get_users_from_calendar(access_token: str) -> list:
    """
    Extract users from calendar events (meeting attendees).
    Requires Calendars.Read permission.
    """
    print("[*] Trying calendar attendees enumeration...")
    
    # Get events from the default calendar (no CalendarId needed)
    url = f"{GRAPH_API_ENDPOINT}/me/events?$top=100&$select=attendees,organizer"
    
    all_users = []
    seen_emails = set()
    
    while url:
        result = make_graph_request(access_token, url)
        if not result:
            break
        
        events = result.get("value", [])
        for event in events:
            # Get organizer
            organizer = event.get("organizer", {}).get("emailAddress", {})
            org_email = organizer.get("address", "").lower()
            if org_email and org_email not in seen_emails:
                seen_emails.add(org_email)
                all_users.append({
                    "displayName": organizer.get("name", ""),
                    "mail": org_email,
                    "userPrincipalName": org_email,
                })
            
            # Get attendees
            for attendee in event.get("attendees", []):
                email_addr = attendee.get("emailAddress", {})
                att_email = email_addr.get("address", "").lower()
                if att_email and att_email not in seen_emails:
                    seen_emails.add(att_email)
                    all_users.append({
                        "displayName": email_addr.get("name", ""),
                        "mail": att_email,
                        "userPrincipalName": att_email,
                    })
        
        url = result.get("@odata.nextLink")
    
    if all_users:
        print(f"[+] Found {len(all_users)} users from calendar events")
    else:
        print("[!] Calendar: No results or access denied")
    
    return all_users


def get_users_from_emails(access_token: str) -> list:
    """
    Extract users from email messages (senders and recipients).
    Requires Mail.Read permission.
    """
    print("[*] Trying email recipients enumeration...")
    
    # Get recent messages
    url = f"{GRAPH_API_ENDPOINT}/me/messages?$top=100&$select=from,toRecipients,ccRecipients"
    
    all_users = []
    seen_emails = set()
    
    while url:
        result = make_graph_request(access_token, url)
        if not result:
            break
        
        messages = result.get("value", [])
        for message in messages:
            # Get sender
            sender = message.get("from", {}).get("emailAddress", {})
            sender_email = sender.get("address", "").lower()
            if sender_email and sender_email not in seen_emails:
                seen_emails.add(sender_email)
                all_users.append({
                    "displayName": sender.get("name", ""),
                    "mail": sender_email,
                    "userPrincipalName": sender_email,
                })
            
            # Get To recipients
            for recipient in message.get("toRecipients", []):
                email_addr = recipient.get("emailAddress", {})
                recip_email = email_addr.get("address", "").lower()
                if recip_email and recip_email not in seen_emails:
                    seen_emails.add(recip_email)
                    all_users.append({
                        "displayName": email_addr.get("name", ""),
                        "mail": recip_email,
                        "userPrincipalName": recip_email,
                    })
            
            # Get CC recipients
            for recipient in message.get("ccRecipients", []):
                email_addr = recipient.get("emailAddress", {})
                recip_email = email_addr.get("address", "").lower()
                if recip_email and recip_email not in seen_emails:
                    seen_emails.add(recip_email)
                    all_users.append({
                        "displayName": email_addr.get("name", ""),
                        "mail": recip_email,
                        "userPrincipalName": recip_email,
                    })
        
        url = result.get("@odata.nextLink")
    
    if all_users:
        print(f"[+] Found {len(all_users)} users from email messages")
    else:
        print("[!] Email: No results or access denied")
    
    return all_users


def get_users_from_onedrive_sharing(access_token: str) -> list:
    """
    Extract users from OneDrive shared files.
    Requires Files.Read permission.
    """
    print("[*] Trying OneDrive sharing enumeration...")
    
    url = f"{GRAPH_API_ENDPOINT}/me/drive/sharedWithMe"
    
    all_users = []
    seen_emails = set()
    
    result = make_graph_request(access_token, url)
    if not result:
        print("[!] OneDrive: Access denied")
        return []
    
    items = result.get("value", [])
    for item in items:
        # Get shared by user
        shared_by = item.get("remoteItem", {}).get("shared", {}).get("sharedBy", {}).get("user", {})
        if shared_by:
            email = shared_by.get("email", "").lower()
            if email and email not in seen_emails:
                seen_emails.add(email)
                all_users.append({
                    "displayName": shared_by.get("displayName", ""),
                    "mail": email,
                    "userPrincipalName": email,
                    "id": shared_by.get("id", ""),
                })
        
        # Get created by
        created_by = item.get("createdBy", {}).get("user", {})
        if created_by:
            email = created_by.get("email", "").lower()
            if email and email not in seen_emails:
                seen_emails.add(email)
                all_users.append({
                    "displayName": created_by.get("displayName", ""),
                    "mail": email,
                    "userPrincipalName": email,
                    "id": created_by.get("id", ""),
                })
    
    if all_users:
        print(f"[+] Found {len(all_users)} users from OneDrive sharing")
    else:
        print("[!] OneDrive: No shared items found")
    
    return all_users


def get_users_from_teams(access_token: str) -> list:
    """
    Enumerate users from Teams memberships.
    Requires Team.ReadBasic.All or TeamMember.Read.All permission.
    """
    print("[*] Trying Teams roster enumeration...")
    
    # First get user's joined teams
    teams_url = f"{GRAPH_API_ENDPOINT}/me/joinedTeams"
    teams_result = make_graph_request(access_token, teams_url)
    
    if not teams_result:
        print("[!] Teams: Access denied or no teams")
        return []
    
    all_users = []
    seen_ids = set()
    teams = teams_result.get("value", [])
    
    for team in teams:
        team_id = team.get("id")
        if not team_id:
            continue
        
        # Get team members
        members_url = f"{GRAPH_API_ENDPOINT}/teams/{team_id}/members"
        members_result = make_graph_request(access_token, members_url)
        
        if members_result:
            for member in members_result.get("value", []):
                user_id = member.get("userId")
                if user_id and user_id not in seen_ids:
                    seen_ids.add(user_id)
                    all_users.append({
                        "id": user_id,
                        "displayName": member.get("displayName", ""),
                        "mail": member.get("email", ""),
                        "userPrincipalName": member.get("email", ""),
                    })
    
    if all_users:
        print(f"[+] Found {len(all_users)} users from Teams")
    else:
        print("[!] Teams: No members found")
    
    return all_users


def get_users_from_planner(access_token: str) -> list:
    """
    Extract users from Planner tasks (assignees).
    Requires Tasks.Read permission.
    """
    print("[*] Trying Planner tasks enumeration...")
    
    # Get user's tasks
    url = f"{GRAPH_API_ENDPOINT}/me/planner/tasks"
    
    all_users = []
    seen_ids = set()
    
    result = make_graph_request(access_token, url)
    if not result:
        print("[!] Planner: Access denied")
        return []
    
    tasks = result.get("value", [])
    for task in tasks:
        # Get assigned users
        assignments = task.get("assignments", {})
        for user_id in assignments.keys():
            if user_id and user_id not in seen_ids:
                seen_ids.add(user_id)
                # Try to get user details
                user_url = f"{GRAPH_API_ENDPOINT}/users/{user_id}"
                user_result = make_graph_request(access_token, user_url)
                if user_result:
                    all_users.append(user_result)
                else:
                    all_users.append({"id": user_id})
        
        # Get created by
        created_by = task.get("createdBy", {}).get("user", {})
        if created_by:
            user_id = created_by.get("id")
            if user_id and user_id not in seen_ids:
                seen_ids.add(user_id)
                user_url = f"{GRAPH_API_ENDPOINT}/users/{user_id}"
                user_result = make_graph_request(access_token, user_url)
                if user_result:
                    all_users.append(user_result)
    
    if all_users:
        print(f"[+] Found {len(all_users)} users from Planner")
    else:
        print("[!] Planner: No results")
    
    return all_users


def get_users_from_sharepoint_profiles(access_token: str) -> list:
    """
    Try to enumerate users via SharePoint User Profile API.
    This is a legacy API that sometimes has different permissions.
    """
    print("[*] Trying SharePoint profiles enumeration...")
    
    # Try to get the SharePoint root site
    site_url = f"{GRAPH_API_ENDPOINT}/sites/root"
    site_result = make_graph_request(access_token, site_url)
    
    if not site_result:
        print("[!] SharePoint: Cannot access root site")
        return []
    
    # Try to get site users
    site_id = site_result.get("id", "").split(",")[0]
    if site_id:
        # Get site users/permissions
        users_url = f"{GRAPH_API_ENDPOINT}/sites/{site_id}/permissions"
        users_result = make_graph_request(access_token, users_url)
        
        if users_result:
            all_users = []
            seen_ids = set()
            
            for perm in users_result.get("value", []):
                granted_to = perm.get("grantedTo", {})
                user = granted_to.get("user", {})
                if user:
                    user_id = user.get("id")
                    if user_id and user_id not in seen_ids:
                        seen_ids.add(user_id)
                        all_users.append({
                            "id": user_id,
                            "displayName": user.get("displayName", ""),
                            "mail": user.get("email", ""),
                            "userPrincipalName": user.get("email", ""),
                        })
            
            if all_users:
                print(f"[+] Found {len(all_users)} users from SharePoint")
                return all_users
    
    print("[!] SharePoint: No users found")
    return []


def get_users_from_azure_rm(access_token: str) -> list:
    """
    Enumerate users via Azure Resource Manager role assignments.
    Requires ARM token and Reader access to subscriptions.
    """
    print("[*] Trying Azure Resource Manager enumeration...")
    
    # Need ARM token, not Graph token
    arm_token = get_arm_token_from_az_cli()
    if not arm_token:
        print("[!] ARM: Cannot get ARM token (need Azure CLI logged in)")
        return []
    
    headers = {
        "Authorization": f"Bearer {arm_token}",
        "Content-Type": "application/json",
    }
    
    all_users = []
    seen_ids = set()
    
    try:
        # Get subscriptions
        subs_url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
        subs_response = requests.get(subs_url, headers=headers)
        
        if subs_response.status_code != 200:
            print("[!] ARM: Cannot list subscriptions")
            return []
        
        subscriptions = subs_response.json().get("value", [])
        
        for sub in subscriptions:
            sub_id = sub.get("subscriptionId")
            if not sub_id:
                continue
            
            # Get role assignments for this subscription
            role_url = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
            role_response = requests.get(role_url, headers=headers)
            
            if role_response.status_code == 200:
                assignments = role_response.json().get("value", [])
                
                for assignment in assignments:
                    props = assignment.get("properties", {})
                    principal_id = props.get("principalId")
                    principal_type = props.get("principalType", "")
                    
                    if principal_id and principal_id not in seen_ids:
                        if principal_type.lower() == "user":
                            seen_ids.add(principal_id)
                            # Try to resolve user details via Graph
                            user_url = f"{GRAPH_API_ENDPOINT}/users/{principal_id}"
                            user_result = make_graph_request(access_token, user_url)
                            if user_result:
                                all_users.append(user_result)
                            else:
                                all_users.append({"id": principal_id, "principalType": "User"})
        
        if all_users:
            print(f"[+] Found {len(all_users)} users from Azure RM")
        else:
            print("[!] ARM: No user role assignments found")
            
    except Exception as e:
        print(f"[!] ARM error: {e}")
    
    return all_users


def get_room_lists_and_rooms(access_token: str) -> list:
    """
    Enumerate meeting rooms and room lists - can reveal org structure.
    """
    print("[*] Trying room/resource enumeration...")
    
    all_resources = []
    seen_emails = set()
    
    # Get room lists
    room_lists_url = f"{GRAPH_API_ENDPOINT}/places/microsoft.graph.roomList"
    room_lists_result = make_graph_request(access_token, room_lists_url)
    
    if room_lists_result:
        for room_list in room_lists_result.get("value", []):
            email = room_list.get("emailAddress", "").lower()
            if email and email not in seen_emails:
                seen_emails.add(email)
                all_resources.append({
                    "displayName": room_list.get("displayName", ""),
                    "mail": email,
                    "resourceType": "RoomList",
                })
    
    # Get rooms
    rooms_url = f"{GRAPH_API_ENDPOINT}/places/microsoft.graph.room"
    rooms_result = make_graph_request(access_token, rooms_url)
    
    if rooms_result:
        for room in rooms_result.get("value", []):
            email = room.get("emailAddress", "").lower()
            if email and email not in seen_emails:
                seen_emails.add(email)
                all_resources.append({
                    "displayName": room.get("displayName", ""),
                    "mail": email,
                    "resourceType": "Room",
                    "building": room.get("building", ""),
                    "floorNumber": room.get("floorNumber", ""),
                })
    
    if all_resources:
        print(f"[+] Found {len(all_resources)} rooms/resources")
    else:
        print("[!] Rooms: No results or access denied")
    
    return all_resources


def get_users_from_yammer(access_token: str) -> list:
    """
    Enumerate users from Yammer/Viva Engage communities.
    Viva Engage communities backed by M365 Groups can be enumerated via Graph API.
    Also attempts direct Yammer REST API for legacy communities.
    Requires Group.Read.All or Community.Read.All permission.
    """
    print("[*] Trying Yammer/Viva Engage community enumeration...")
    
    all_users = []
    seen_ids = set()
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    # Method 1: Try to get Viva Engage communities via Graph API
    # Communities are M365 Groups with a specific resource provisioning option
    try:
        # First, try the communities endpoint (newer Viva Engage)
        communities_url = f"{GRAPH_API_ENDPOINT}/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team') or groupTypes/any(c:c eq 'Unified')&$select=id,displayName,mail,description,groupTypes,resourceProvisioningOptions&$top=999"
        
        communities_response = requests.get(communities_url, headers=headers)
        
        if communities_response.status_code == 200:
            communities_data = communities_response.json()
            groups = communities_data.get("value", [])
            
            # Filter for Yammer-connected groups (check for Yammer resource provisioning)
            yammer_groups = []
            for group in groups:
                resource_options = group.get("resourceProvisioningOptions", [])
                # Yammer communities typically have "YammerFeed" in resourceProvisioningOptions
                if "YammerFeed" in resource_options or any("yammer" in str(opt).lower() for opt in resource_options):
                    yammer_groups.append(group)
            
            # If no explicit Yammer groups found, try all Unified groups (M365 groups)
            if not yammer_groups:
                # Get all M365 Groups as potential Viva Engage communities
                unified_url = f"{GRAPH_API_ENDPOINT}/groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=id,displayName,mail&$top=100"
                unified_response = requests.get(unified_url, headers=headers)
                if unified_response.status_code == 200:
                    yammer_groups = unified_response.json().get("value", [])[:20]  # Limit to first 20 groups
            
            print(f"[*] Found {len(yammer_groups)} potential Viva Engage communities")
            
            # Get members from each community
            for group in yammer_groups:
                group_id = group.get("id")
                if not group_id:
                    continue
                
                # Get group members
                members_url = f"{GRAPH_API_ENDPOINT}/groups/{group_id}/members?$select=id,displayName,mail,userPrincipalName,jobTitle,department"
                members_response = requests.get(members_url, headers=headers)
                
                if members_response.status_code == 200:
                    members = members_response.json().get("value", [])
                    for member in members:
                        # Only include user objects (not groups or service principals)
                        odata_type = member.get("@odata.type", "")
                        if "#microsoft.graph.user" in odata_type or not odata_type:
                            user_id = member.get("id")
                            if user_id and user_id not in seen_ids:
                                seen_ids.add(user_id)
                                all_users.append({
                                    "id": user_id,
                                    "displayName": member.get("displayName", ""),
                                    "mail": member.get("mail", ""),
                                    "userPrincipalName": member.get("userPrincipalName", ""),
                                    "jobTitle": member.get("jobTitle", ""),
                                    "department": member.get("department", ""),
                                    "source": f"Yammer-{group.get('displayName', 'Community')[:20]}",
                                })
        else:
            print(f"[!] Viva Engage Graph API: {communities_response.status_code}")
    except Exception as e:
        print(f"[!] Viva Engage Graph API error: {e}")
    
    # Method 2: Try direct Yammer REST API (for legacy/standalone Yammer)
    try:
        # Get Yammer network users (requires Yammer API access)
        yammer_url = "https://www.yammer.com/api/v1/users.json?page=1&per_page=50"
        yammer_headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        
        yammer_response = requests.get(yammer_url, headers=yammer_headers, timeout=10)
        
        if yammer_response.status_code == 200:
            yammer_users = yammer_response.json()
            if isinstance(yammer_users, list):
                print(f"[*] Yammer REST API returned {len(yammer_users)} users")
                for yammer_user in yammer_users:
                    user_id = yammer_user.get("guid") or yammer_user.get("id")
                    email = yammer_user.get("email", "")
                    
                    # Use email as dedup key for Yammer users (may not have AAD ID)
                    dedup_key = email.lower() if email else str(user_id)
                    if dedup_key and dedup_key not in seen_ids:
                        seen_ids.add(dedup_key)
                        all_users.append({
                            "id": yammer_user.get("guid", ""),
                            "displayName": yammer_user.get("full_name", ""),
                            "mail": email,
                            "userPrincipalName": email,
                            "jobTitle": yammer_user.get("job_title", ""),
                            "department": yammer_user.get("department", ""),
                            "source": "Yammer-REST-API",
                        })
        elif yammer_response.status_code == 401:
            print("[!] Yammer REST API: Token not valid for Yammer (normal for Graph-only tokens)")
        else:
            print(f"[!] Yammer REST API: {yammer_response.status_code}")
    except requests.exceptions.Timeout:
        print("[!] Yammer REST API: Timeout (Yammer may not be accessible)")
    except Exception as e:
        print(f"[!] Yammer REST API error: {e}")
    
    # Method 3: Try to get users from Yammer groups via Graph
    try:
        # Get groups that the current user is part of with Yammer provisioning
        my_groups_url = f"{GRAPH_API_ENDPOINT}/me/memberOf?$select=id,displayName,resourceProvisioningOptions,groupTypes"
        my_groups_response = requests.get(my_groups_url, headers=headers)
        
        if my_groups_response.status_code == 200:
            my_groups = my_groups_response.json().get("value", [])
            for group in my_groups:
                resource_options = group.get("resourceProvisioningOptions", [])
                if "YammerFeed" in resource_options:
                    group_id = group.get("id")
                    if group_id:
                        members_url = f"{GRAPH_API_ENDPOINT}/groups/{group_id}/members?$select=id,displayName,mail,userPrincipalName"
                        members_response = requests.get(members_url, headers=headers)
                        
                        if members_response.status_code == 200:
                            for member in members_response.json().get("value", []):
                                user_id = member.get("id")
                                if user_id and user_id not in seen_ids:
                                    seen_ids.add(user_id)
                                    all_users.append({
                                        "id": user_id,
                                        "displayName": member.get("displayName", ""),
                                        "mail": member.get("mail", ""),
                                        "userPrincipalName": member.get("userPrincipalName", ""),
                                        "source": "Yammer-MyGroups",
                                    })
    except Exception as e:
        print(f"[!] Yammer MyGroups error: {e}")
    
    if all_users:
        print(f"[+] Found {len(all_users)} users from Yammer/Viva Engage")
    else:
        print("[!] Yammer/Viva Engage: No users found or access denied")
    
    return all_users


# ============================================================================
# SECURITY ASSESSMENT FEATURES
# ============================================================================

def get_user_mfa_status(access_token: str) -> list:
    """
    Enumerate MFA status for all users.
    Uses the authentication methods endpoint to check MFA registration.
    Critical for identifying accounts vulnerable to password-only attacks.
    """
    print("[*] Enumerating user MFA status...")
    
    users_with_mfa_status = []
    
    # First get all users
    users_url = f"{GRAPH_API_ENDPOINT}/users?$select=id,displayName,userPrincipalName,mail,userType&$top=999"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    all_users = []
    url = users_url
    
    while url:
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                all_users.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
            else:
                print(f"[!] Error fetching users: {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    print(f"    Checking MFA status for {len(all_users)} users...")
    
    mfa_enabled_count = 0
    mfa_disabled_count = 0
    check_failed_count = 0
    
    for i, user in enumerate(all_users):
        user_id = user.get("id")
        if not user_id:
            continue
        
        # Check authentication methods
        auth_methods_url = f"{GRAPH_API_ENDPOINT}/users/{user_id}/authentication/methods"
        
        try:
            response = requests.get(auth_methods_url, headers=headers)
            
            mfa_methods = []
            has_strong_mfa = False
            
            if response.status_code == 200:
                methods = response.json().get("value", [])
                
                for method in methods:
                    method_type = method.get("@odata.type", "")
                    
                    # Check for strong MFA methods
                    if "microsoftAuthenticator" in method_type:
                        mfa_methods.append("Authenticator App")
                        has_strong_mfa = True
                    elif "phoneAuthentication" in method_type:
                        mfa_methods.append("Phone")
                        has_strong_mfa = True
                    elif "fido2" in method_type:
                        mfa_methods.append("FIDO2 Key")
                        has_strong_mfa = True
                    elif "windowsHelloForBusiness" in method_type:
                        mfa_methods.append("Windows Hello")
                        has_strong_mfa = True
                    elif "softwareOath" in method_type:
                        mfa_methods.append("Software TOTP")
                        has_strong_mfa = True
                    elif "temporaryAccessPass" in method_type:
                        mfa_methods.append("Temp Access Pass")
                    elif "email" in method_type:
                        mfa_methods.append("Email")
                    elif "password" in method_type:
                        mfa_methods.append("Password")
                
                if has_strong_mfa:
                    mfa_enabled_count += 1
                else:
                    mfa_disabled_count += 1
                
                users_with_mfa_status.append({
                    "id": user_id,
                    "displayName": user.get("displayName", ""),
                    "userPrincipalName": user.get("userPrincipalName", ""),
                    "mail": user.get("mail", ""),
                    "userType": user.get("userType", ""),
                    "hasMFA": has_strong_mfa,
                    "mfaMethods": ", ".join(mfa_methods) if mfa_methods else "None",
                    "riskLevel": "LOW" if has_strong_mfa else "HIGH",
                })
            else:
                check_failed_count += 1
                users_with_mfa_status.append({
                    "id": user_id,
                    "displayName": user.get("displayName", ""),
                    "userPrincipalName": user.get("userPrincipalName", ""),
                    "mail": user.get("mail", ""),
                    "userType": user.get("userType", ""),
                    "hasMFA": "Unknown",
                    "mfaMethods": "Access Denied",
                    "riskLevel": "UNKNOWN",
                })
        except Exception:
            check_failed_count += 1
            continue
        
        # Progress indicator
        if (i + 1) % 50 == 0:
            print(f"    Processed {i + 1}/{len(all_users)} users...")
    
    print(f"\n[+] MFA Status Summary:")
    print(f"    - MFA Enabled: {mfa_enabled_count}")
    print(f"    - MFA Disabled (HIGH RISK): {mfa_disabled_count}")
    print(f"    - Check Failed: {check_failed_count}")
    
    return users_with_mfa_status


def get_user_mfa_registration_details(access_token: str) -> list:
    """
    Alternative MFA check using reports/authenticationMethods endpoint.
    Works when individual user auth methods access is restricted.
    """
    print("[*] Trying MFA registration report...")
    
    # Try the beta endpoint for auth method registration
    url = f"{GRAPH_BETA_ENDPOINT}/reports/authenticationMethods/userRegistrationDetails?$top=999"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    all_registrations = []
    
    while url:
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                registrations = data.get("value", [])
                
                for reg in registrations:
                    all_registrations.append({
                        "id": reg.get("id", ""),
                        "userPrincipalName": reg.get("userPrincipalName", ""),
                        "displayName": reg.get("userDisplayName", ""),
                        "isMfaRegistered": reg.get("isMfaRegistered", False),
                        "isMfaCapable": reg.get("isMfaCapable", False),
                        "isPasswordlessCapable": reg.get("isPasswordlessCapable", False),
                        "isSsprRegistered": reg.get("isSsprRegistered", False),
                        "isSsprEnabled": reg.get("isSsprEnabled", False),
                        "isSsprCapable": reg.get("isSsprCapable", False),
                        "methodsRegistered": ", ".join(reg.get("methodsRegistered", [])),
                        "riskLevel": "LOW" if reg.get("isMfaRegistered") else "HIGH",
                    })
                
                url = data.get("@odata.nextLink")
            else:
                print(f"[!] Report endpoint: {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    if all_registrations:
        mfa_registered = sum(1 for r in all_registrations if r.get("isMfaRegistered"))
        print(f"[+] Found {len(all_registrations)} users")
        print(f"    - MFA Registered: {mfa_registered}")
        print(f"    - MFA Not Registered (HIGH RISK): {len(all_registrations) - mfa_registered}")
    else:
        print("[!] MFA report: Access denied or no data")
    
    return all_registrations


def get_privileged_users(access_token: str) -> list:
    """
    Enumerate users with privileged Azure AD roles.
    Critical for identifying high-value targets in attacks.
    """
    print("[*] Enumerating privileged role assignments...")
    
    # High-privilege roles to look for
    privileged_roles = {
        "Global Administrator": "CRITICAL",
        "Privileged Role Administrator": "CRITICAL", 
        "Privileged Authentication Administrator": "CRITICAL",
        "Partner Tier2 Support": "CRITICAL",
        "User Administrator": "HIGH",
        "Exchange Administrator": "HIGH",
        "SharePoint Administrator": "HIGH",
        "Teams Administrator": "HIGH",
        "Intune Administrator": "HIGH",
        "Application Administrator": "HIGH",
        "Cloud Application Administrator": "HIGH",
        "Authentication Administrator": "HIGH",
        "Password Administrator": "HIGH",
        "Helpdesk Administrator": "MEDIUM",
        "Security Administrator": "HIGH",
        "Security Reader": "LOW",
        "Conditional Access Administrator": "HIGH",
        "Groups Administrator": "MEDIUM",
        "License Administrator": "LOW",
        "Directory Readers": "LOW",
    }
    
    privileged_users = []
    seen_assignments = set()
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    # Get all directory roles
    roles_url = f"{GRAPH_API_ENDPOINT}/directoryRoles?$expand=members"
    
    try:
        response = requests.get(roles_url, headers=headers)
        
        if response.status_code == 200:
            roles = response.json().get("value", [])
            
            for role in roles:
                role_name = role.get("displayName", "")
                role_id = role.get("id", "")
                risk_level = privileged_roles.get(role_name, "MEDIUM")
                
                members = role.get("members", [])
                
                for member in members:
                    if "#microsoft.graph.user" in member.get("@odata.type", ""):
                        member_id = member.get("id")
                        assignment_key = f"{member_id}_{role_id}"
                        
                        if assignment_key not in seen_assignments:
                            seen_assignments.add(assignment_key)
                            privileged_users.append({
                                "id": member_id,
                                "displayName": member.get("displayName", ""),
                                "userPrincipalName": member.get("userPrincipalName", ""),
                                "mail": member.get("mail", ""),
                                "role": role_name,
                                "roleId": role_id,
                                "riskLevel": risk_level,
                                "assignmentType": "Active",
                            })
            
            if privileged_users:
                print(f"[+] Found {len(privileged_users)} privileged role assignments")
                
                # Count by risk level
                critical = sum(1 for u in privileged_users if u["riskLevel"] == "CRITICAL")
                high = sum(1 for u in privileged_users if u["riskLevel"] == "HIGH")
                
                print(f"    - CRITICAL: {critical}")
                print(f"    - HIGH: {high}")
        else:
            print(f"[!] Directory roles: {response.status_code}")
            
    except Exception as e:
        print(f"[!] Error: {e}")
    
    # Also check PIM eligible assignments (beta API)
    print("[*] Checking PIM eligible role assignments...")
    
    pim_url = f"{GRAPH_BETA_ENDPOINT}/roleManagement/directory/roleEligibilitySchedules?$expand=principal"
    
    try:
        response = requests.get(pim_url, headers=headers)
        
        if response.status_code == 200:
            schedules = response.json().get("value", [])
            
            for schedule in schedules:
                principal = schedule.get("principal", {})
                
                if principal.get("@odata.type") == "#microsoft.graph.user":
                    role_id = schedule.get("roleDefinitionId", "")
                    
                    # Get role name
                    role_url = f"{GRAPH_API_ENDPOINT}/directoryRoles?$filter=roleTemplateId eq '{role_id}'"
                    role_response = requests.get(role_url, headers=headers)
                    role_name = "Unknown Role"
                    
                    if role_response.status_code == 200:
                        role_data = role_response.json().get("value", [])
                        if role_data:
                            role_name = role_data[0].get("displayName", "Unknown")
                    
                    risk_level = privileged_roles.get(role_name, "MEDIUM")
                    
                    assignment_key = f"{principal.get('id')}_{role_id}_eligible"
                    
                    if assignment_key not in seen_assignments:
                        seen_assignments.add(assignment_key)
                        privileged_users.append({
                            "id": principal.get("id", ""),
                            "displayName": principal.get("displayName", ""),
                            "userPrincipalName": principal.get("userPrincipalName", ""),
                            "mail": principal.get("mail", ""),
                            "role": role_name,
                            "roleId": role_id,
                            "riskLevel": risk_level,
                            "assignmentType": "PIM Eligible",
                        })
            
            pim_count = sum(1 for u in privileged_users if u.get("assignmentType") == "PIM Eligible")
            if pim_count > 0:
                print(f"[+] Found {pim_count} PIM eligible assignments")
        else:
            print(f"[!] PIM eligibility: Access denied or not available")
            
    except Exception as e:
        print(f"[!] PIM check failed: {e}")
    
    return privileged_users


def get_graph_api_permissions_map(access_token: str) -> Tuple[dict, dict]:
    """
    Get Microsoft Graph API permission definitions to resolve IDs to names.
    Returns (app_roles_map, delegated_scopes_map) - both ID -> name mappings.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    app_roles_map = {}
    delegated_scopes_map = {}
    
    # Microsoft Graph service principal has this well-known appId
    ms_graph_app_id = "00000003-0000-0000-c000-000000000000"
    
    try:
        # Get Microsoft Graph service principal
        url = f"{GRAPH_API_ENDPOINT}/servicePrincipals?$filter=appId eq '{ms_graph_app_id}'&$select=appRoles,oauth2PermissionScopes"
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("value"):
                graph_sp = data["value"][0]
                
                # Map app roles (application permissions)
                for role in graph_sp.get("appRoles", []):
                    role_id = role.get("id", "")
                    role_name = role.get("value", "")
                    if role_id and role_name:
                        app_roles_map[role_id] = role_name
                
                # Map delegated scopes
                for scope in graph_sp.get("oauth2PermissionScopes", []):
                    scope_id = scope.get("id", "")
                    scope_name = scope.get("value", "")
                    if scope_id and scope_name:
                        delegated_scopes_map[scope_id] = scope_name
    except Exception as e:
        print(f"[!] Could not fetch Graph permission definitions: {e}")
    
    return app_roles_map, delegated_scopes_map


def get_application_owners(access_token: str, app_id: str) -> list:
    """Get owners of an application registration."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    owners = []
    try:
        url = f"{GRAPH_API_ENDPOINT}/applications/{app_id}/owners?$select=id,displayName,userPrincipalName"
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            for owner in response.json().get("value", []):
                owner_info = owner.get("userPrincipalName") or owner.get("displayName") or owner.get("id", "")
                if owner_info:
                    owners.append(owner_info)
    except:
        pass
    
    return owners


def get_service_principal_owners(access_token: str, sp_id: str) -> list:
    """Get owners of a service principal (enterprise app)."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    owners = []
    try:
        url = f"{GRAPH_API_ENDPOINT}/servicePrincipals/{sp_id}/owners?$select=id,displayName,userPrincipalName"
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            for owner in response.json().get("value", []):
                owner_info = owner.get("userPrincipalName") or owner.get("displayName") or owner.get("id", "")
                if owner_info:
                    owners.append(owner_info)
    except:
        pass
    
    return owners


def get_applications_and_service_principals(access_token: str) -> dict:
    """
    Enumerate enterprise applications and service principals.
    Identifies OAuth attack surface and over-privileged applications.
    
    Features:
    - Lists enterprise applications and their owners
    - Enumerates service principals with high privileges
    - Finds app registrations with secrets/certificates
    - Identifies applications with delegated/application permissions to Graph API
    """
    print("[*] Enumerating applications and service principals...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    results = {
        "applications": [],
        "service_principals": [],
        "high_risk_apps": [],
        "apps_with_credentials": [],
        "high_privilege_sps": [],
    }
    
    # High-risk permissions to flag (both delegated and application)
    high_risk_permissions = [
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All",
        "Application.ReadWrite.All",
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Mail.ReadWrite",
        "Mail.Send",
        "Files.ReadWrite.All",
        "Sites.ReadWrite.All",
        "Exchange.ManageAsApp",
        "full_access_as_app",
        "User.Export.All",
        "Directory.Read.All",
        "AuditLog.Read.All",
        "Policy.ReadWrite.ConditionalAccess",
        "PrivilegedAccess.ReadWrite.AzureAD",
        "PrivilegedAccess.ReadWrite.AzureResources",
    ]
    
    # Critical permissions - highest risk
    critical_permissions = [
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All", 
        "Application.ReadWrite.All",
        "Directory.ReadWrite.All",
        "PrivilegedAccess.ReadWrite.AzureAD",
    ]
    
    # Get Graph API permission mappings to resolve IDs to names
    print("[*] Loading Microsoft Graph permission definitions...")
    app_roles_map, delegated_scopes_map = get_graph_api_permissions_map(access_token)
    print(f"    Loaded {len(app_roles_map)} app roles, {len(delegated_scopes_map)} delegated scopes")
    
    # Microsoft Graph service principal ID (needed for permission resolution)
    ms_graph_sp_id = None
    ms_graph_app_id = "00000003-0000-0000-c000-000000000000"
    try:
        url = f"{GRAPH_API_ENDPOINT}/servicePrincipals?$filter=appId eq '{ms_graph_app_id}'&$select=id"
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            if data.get("value"):
                ms_graph_sp_id = data["value"][0].get("id")
    except:
        pass
    
    # Get application registrations with owners
    print("[*] Getting app registrations...")
    apps_url = f"{GRAPH_API_ENDPOINT}/applications?$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess&$top=999"
    
    while apps_url:
        try:
            response = requests.get(apps_url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                apps = data.get("value", [])
                
                for app in apps:
                    app_id_obj = app.get("id", "")
                    
                    # Get owners for this app
                    owners = get_application_owners(access_token, app_id_obj)
                    
                    # Analyze required permissions
                    requested_app_perms = []  # Application permissions (Role type)
                    requested_delegated_perms = []  # Delegated permissions (Scope type)
                    is_high_risk = False
                    is_critical = False
                    
                    for resource in app.get("requiredResourceAccess", []):
                        resource_app_id = resource.get("resourceAppId", "")
                        is_graph = resource_app_id == ms_graph_app_id
                        
                        for access in resource.get("resourceAccess", []):
                            perm_id = access.get("id", "")
                            perm_type = access.get("type", "")  # "Role" = application, "Scope" = delegated
                            
                            # Resolve permission name
                            if is_graph:
                                if perm_type == "Role":
                                    perm_name = app_roles_map.get(perm_id, perm_id[:8] + "...")
                                    requested_app_perms.append(perm_name)
                                else:
                                    perm_name = delegated_scopes_map.get(perm_id, perm_id[:8] + "...")
                                    requested_delegated_perms.append(perm_name)
                            else:
                                perm_name = perm_id[:8] + "..."
                                if perm_type == "Role":
                                    requested_app_perms.append(f"[{resource_app_id[:8]}]{perm_name}")
                                else:
                                    requested_delegated_perms.append(f"[{resource_app_id[:8]}]{perm_name}")
                            
                            # Check for high-risk permissions
                            for hrp in high_risk_permissions:
                                if hrp.lower() in perm_name.lower():
                                    is_high_risk = True
                                    break
                            for cp in critical_permissions:
                                if cp.lower() in perm_name.lower():
                                    is_critical = True
                                    break
                    
                    # Check for credentials
                    has_secrets = len(app.get("passwordCredentials", [])) > 0
                    has_certificates = len(app.get("keyCredentials", [])) > 0
                    
                    # Get secret/certificate expiration info
                    credential_details = []
                    for secret in app.get("passwordCredentials", []):
                        end_date = secret.get("endDateTime", "")
                        hint = secret.get("hint", "")
                        if end_date:
                            credential_details.append(f"Secret({hint}): {end_date[:10]}")
                    for cert in app.get("keyCredentials", []):
                        end_date = cert.get("endDateTime", "")
                        usage = cert.get("usage", "")
                        if end_date:
                            credential_details.append(f"Cert({usage}): {end_date[:10]}")
                    
                    app_info = {
                        "id": app_id_obj,
                        "appId": app.get("appId", ""),
                        "displayName": app.get("displayName", ""),
                        "createdDateTime": app.get("createdDateTime", "")[:10] if app.get("createdDateTime") else "",
                        "signInAudience": app.get("signInAudience", ""),
                        "hasSecrets": has_secrets,
                        "hasCertificates": has_certificates,
                        "credentialDetails": ", ".join(credential_details[:3]) if credential_details else "None",
                        "owners": ", ".join(owners[:3]) if owners else "None",
                        "ownerCount": len(owners),
                        "requestedAppPermissions": ", ".join(requested_app_perms[:5]) if requested_app_perms else "None",
                        "requestedDelegatedPermissions": ", ".join(requested_delegated_perms[:5]) if requested_delegated_perms else "None",
                        "appPermissionCount": len(requested_app_perms),
                        "delegatedPermissionCount": len(requested_delegated_perms),
                        "isHighRisk": is_high_risk,
                        "isCritical": is_critical,
                    }
                    
                    results["applications"].append(app_info)
                    
                    if has_secrets or has_certificates:
                        results["apps_with_credentials"].append(app_info)
                    
                    if is_high_risk or is_critical:
                        results["high_risk_apps"].append(app_info)
                
                apps_url = data.get("@odata.nextLink")
            else:
                print(f"[!] App registrations: {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error getting apps: {e}")
            break
    
    print(f"    Found {len(results['applications'])} app registrations")
    print(f"    Apps with credentials: {len(results['apps_with_credentials'])}")
    
    # Get service principals (enterprise apps) with detailed permissions
    print("[*] Getting service principals (enterprise applications)...")
    sp_url = f"{GRAPH_API_ENDPOINT}/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,tags&$top=999"
    
    while sp_url:
        try:
            response = requests.get(sp_url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                sps = data.get("value", [])
                
                for sp in sps:
                    sp_id = sp.get("id", "")
                    
                    # Get owners for this service principal
                    owners = get_service_principal_owners(access_token, sp_id)
                    
                    # Get APP ROLE ASSIGNMENTS (application permissions granted TO this SP)
                    granted_app_permissions = []
                    has_dangerous_app_perms = False
                    is_critical = False
                    
                    try:
                        roles_url = f"{GRAPH_API_ENDPOINT}/servicePrincipals/{sp_id}/appRoleAssignments"
                        roles_response = requests.get(roles_url, headers=headers, timeout=REQUEST_TIMEOUT)
                        if roles_response.status_code == 200:
                            roles_data = roles_response.json().get("value", [])
                            for role in roles_data:
                                role_id = role.get("appRoleId", "")
                                resource_display_name = role.get("resourceDisplayName", "")
                                
                                # Resolve permission name
                                perm_name = app_roles_map.get(role_id, role_id[:8] + "...")
                                
                                # Format: PermissionName (ResourceName)
                                if resource_display_name and resource_display_name != "Microsoft Graph":
                                    granted_app_permissions.append(f"{perm_name} ({resource_display_name[:15]})")
                                else:
                                    granted_app_permissions.append(perm_name)
                                
                                # Check for high-risk
                                for hrp in high_risk_permissions:
                                    if hrp.lower() in perm_name.lower():
                                        has_dangerous_app_perms = True
                                        break
                                for cp in critical_permissions:
                                    if cp.lower() in perm_name.lower():
                                        is_critical = True
                                        break
                    except:
                        pass
                    
                    # Get OAuth2 permission grants (delegated permissions consented for this SP)
                    delegated_perms = []
                    delegated_perm_details = []
                    has_dangerous_delegated = False
                    
                    try:
                        grants_url = f"{GRAPH_API_ENDPOINT}/servicePrincipals/{sp_id}/oauth2PermissionGrants"
                        grants_response = requests.get(grants_url, headers=headers, timeout=REQUEST_TIMEOUT)
                        if grants_response.status_code == 200:
                            grants = grants_response.json().get("value", [])
                            for grant in grants:
                                scope = grant.get("scope", "")
                                consent_type = grant.get("consentType", "")  # AllPrincipals or Principal
                                
                                if scope:
                                    perms = scope.split()
                                    delegated_perms.extend(perms)
                                    
                                    # Check for admin consent (AllPrincipals = tenant-wide)
                                    consent_label = "[Admin]" if consent_type == "AllPrincipals" else "[User]"
                                    for perm in perms:
                                        delegated_perm_details.append(f"{consent_label}{perm}")
                                        
                                        # Check for high-risk
                                        for hrp in high_risk_permissions:
                                            if hrp.lower() in perm.lower():
                                                has_dangerous_delegated = True
                                                break
                    except:
                        pass
                    
                    # Determine overall risk
                    is_high_risk = has_dangerous_app_perms or has_dangerous_delegated or is_critical
                    
                    # Determine risk level
                    risk_level = "LOW"
                    if has_dangerous_delegated:
                        risk_level = "MEDIUM"
                    if has_dangerous_app_perms:
                        risk_level = "HIGH"
                    if is_critical:
                        risk_level = "CRITICAL"
                    
                    sp_info = {
                        "id": sp_id,
                        "appId": sp.get("appId", ""),
                        "displayName": sp.get("displayName", ""),
                        "type": sp.get("servicePrincipalType", ""),
                        "accountEnabled": sp.get("accountEnabled", True),
                        "appOwnerOrganizationId": sp.get("appOwnerOrganizationId", ""),
                        "tags": ", ".join(sp.get("tags", [])[:3]) if sp.get("tags") else "None",
                        "owners": ", ".join(owners[:3]) if owners else "None",
                        "ownerCount": len(owners),
                        "grantedAppPermissions": ", ".join(granted_app_permissions[:5]) if granted_app_permissions else "None",
                        "appPermissionCount": len(granted_app_permissions),
                        "delegatedPermissions": ", ".join(delegated_perm_details[:5]) if delegated_perm_details else "None",
                        "delegatedPermissionCount": len(delegated_perms),
                        "isHighRisk": is_high_risk,
                        "isCritical": is_critical,
                        "riskLevel": risk_level,
                    }
                    
                    results["service_principals"].append(sp_info)
                    
                    if is_high_risk:
                        results["high_privilege_sps"].append(sp_info)
                
                sp_url = data.get("@odata.nextLink")
            else:
                print(f"[!] Service principals: {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error getting SPs: {e}")
            break
    
    print(f"    Found {len(results['service_principals'])} service principals")
    print(f"    High-privilege service principals: {len(results['high_privilege_sps'])}")
    print(f"    High-risk app registrations: {len(results['high_risk_apps'])}")
    
    return results


def get_stale_accounts(access_token: str, days_threshold: int = 90) -> list:
    """
    Find accounts with no recent sign-in activity.
    Stale accounts are often targets for compromise.
    """
    print(f"[*] Finding stale accounts (no sign-in > {days_threshold} days)...")
    
    from datetime import datetime, timedelta, timezone
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    stale_users = []
    
    # Use beta endpoint for sign-in activity
    url = f"{GRAPH_BETA_ENDPOINT}/users?$select=id,displayName,userPrincipalName,mail,userType,accountEnabled,signInActivity,createdDateTime&$top=999"
    
    threshold_date = datetime.now(timezone.utc) - timedelta(days=days_threshold)
    
    while url:
        try:
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                users = data.get("value", [])
                
                for user in users:
                    sign_in_activity = user.get("signInActivity", {})
                    last_sign_in = sign_in_activity.get("lastSignInDateTime")
                    last_non_interactive = sign_in_activity.get("lastNonInteractiveSignInDateTime")
                    
                    # Get the most recent sign-in
                    latest_sign_in = None
                    if last_sign_in:
                        latest_sign_in = last_sign_in
                    if last_non_interactive:
                        if not latest_sign_in or last_non_interactive > latest_sign_in:
                            latest_sign_in = last_non_interactive
                    
                    is_stale = False
                    days_inactive = "Never"
                    
                    if latest_sign_in:
                        try:
                            sign_in_date = datetime.fromisoformat(latest_sign_in.replace("Z", "+00:00"))
                            days_inactive = (datetime.now(timezone.utc) - sign_in_date).days
                            is_stale = days_inactive > days_threshold
                        except:
                            is_stale = True
                            days_inactive = "Unknown"
                    else:
                        # No sign-in activity recorded
                        is_stale = True
                    
                    if is_stale:
                        risk_level = "CRITICAL" if days_inactive == "Never" else (
                            "HIGH" if isinstance(days_inactive, int) and days_inactive > 180 else "MEDIUM"
                        )
                        
                        stale_users.append({
                            "id": user.get("id", ""),
                            "displayName": user.get("displayName", ""),
                            "userPrincipalName": user.get("userPrincipalName", ""),
                            "mail": user.get("mail", ""),
                            "userType": user.get("userType", ""),
                            "accountEnabled": user.get("accountEnabled", True),
                            "lastSignIn": latest_sign_in[:10] if latest_sign_in else "Never",
                            "daysInactive": days_inactive,
                            "createdDateTime": user.get("createdDateTime", "")[:10] if user.get("createdDateTime") else "",
                            "riskLevel": risk_level,
                        })
                
                url = data.get("@odata.nextLink")
            else:
                print(f"[!] Sign-in activity: {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    if stale_users:
        enabled_stale = sum(1 for u in stale_users if u.get("accountEnabled", True))
        print(f"[+] Found {len(stale_users)} stale accounts")
        print(f"    - Still enabled (HIGH RISK): {enabled_stale}")
        print(f"    - Disabled: {len(stale_users) - enabled_stale}")
    else:
        print("[!] No stale accounts found or access denied")
    
    return stale_users


def get_guest_users(access_token: str) -> list:
    """
    Enumerate guest/external users.
    Guest accounts can be attack vectors from partner organizations.
    """
    print("[*] Enumerating guest users...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    guest_users = []
    
    url = f"{GRAPH_API_ENDPOINT}/users?$filter=userType eq 'Guest'&$select=id,displayName,userPrincipalName,mail,createdDateTime,externalUserState,accountEnabled&$top=999"
    
    while url:
        try:
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                guests = data.get("value", [])
                
                for guest in guests:
                    # Extract external domain
                    upn = guest.get("userPrincipalName", "")
                    external_domain = ""
                    if "#EXT#" in upn:
                        # Format: user_domain.com#EXT#@tenant.onmicrosoft.com
                        try:
                            external_part = upn.split("#EXT#")[0]
                            external_domain = external_part.split("_")[-1]
                        except:
                            pass
                    
                    guest_users.append({
                        "id": guest.get("id", ""),
                        "displayName": guest.get("displayName", ""),
                        "userPrincipalName": upn,
                        "mail": guest.get("mail", ""),
                        "externalDomain": external_domain,
                        "externalUserState": guest.get("externalUserState", ""),
                        "accountEnabled": guest.get("accountEnabled", True),
                        "createdDateTime": guest.get("createdDateTime", "")[:10] if guest.get("createdDateTime") else "",
                        "userType": "Guest",
                    })
                
                url = data.get("@odata.nextLink")
            else:
                print(f"[!] Guest users: {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    if guest_users:
        # Group by domain
        domains = {}
        for guest in guest_users:
            domain = guest.get("externalDomain", "Unknown")
            domains[domain] = domains.get(domain, 0) + 1
        
        print(f"[+] Found {len(guest_users)} guest users")
        print(f"    External domains: {len(domains)}")
        
        # Show top domains
        sorted_domains = sorted(domains.items(), key=lambda x: -x[1])[:5]
        for domain, count in sorted_domains:
            print(f"      - {domain}: {count}")
    else:
        print("[!] No guest users found or access denied")
    
    return guest_users


def get_users_with_password_never_expires(access_token: str) -> list:
    """
    Find users with 'password never expires' setting.
    These accounts are higher risk as passwords are never forced to rotate.
    """
    print("[*] Finding users with password never expires...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    users_never_expires = []
    
    # Use beta endpoint for password profile
    url = f"{GRAPH_BETA_ENDPOINT}/users?$select=id,displayName,userPrincipalName,mail,userType,passwordProfile,passwordPolicies&$top=999"
    
    while url:
        try:
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                users = data.get("value", [])
                
                for user in users:
                    password_policies = user.get("passwordPolicies", "") or ""
                    
                    if "DisablePasswordExpiration" in password_policies:
                        users_never_expires.append({
                            "id": user.get("id", ""),
                            "displayName": user.get("displayName", ""),
                            "userPrincipalName": user.get("userPrincipalName", ""),
                            "mail": user.get("mail", ""),
                            "userType": user.get("userType", ""),
                            "passwordPolicies": password_policies,
                            "riskLevel": "MEDIUM",
                        })
                
                url = data.get("@odata.nextLink")
            else:
                print(f"[!] Password policies: {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    if users_never_expires:
        print(f"[+] Found {len(users_never_expires)} users with password never expires")
    else:
        print("[!] No users with password never expires or access denied")
    
    return users_never_expires


# ============================================================================
# CREDENTIAL ATTACK SURFACE FEATURES
# ============================================================================

def get_user_password_policies(access_token: str) -> list:
    """
    Enumerate comprehensive password policies per user.
    Identifies weak password configurations and policy gaps.
    """
    print("[*] Enumerating password policies per user...")
    print("    (This may take a while for large directories)")
    
    from datetime import datetime, timezone
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    user_policies = []
    page_count = 0
    
    # Get users with password-related fields
    url = f"{GRAPH_BETA_ENDPOINT}/users?$select=id,displayName,userPrincipalName,mail,userType,passwordPolicies,lastPasswordChangeDateTime,passwordProfile&$top=999"
    
    while url and not is_cancelled():
        try:
            response = make_api_request(url, headers)
            
            if response is None:
                if is_cancelled():
                    break
                break
            
            if response.status_code == 200:
                data = response.json()
                users = data.get("value", [])
                page_count += 1
                
                for user in users:
                    password_policies = user.get("passwordPolicies", "") or ""
                    last_pwd_change = user.get("lastPasswordChangeDateTime")
                    
                    # Determine password policy settings
                    never_expires = "DisablePasswordExpiration" in password_policies
                    strong_pwd_disabled = "DisableStrongPassword" in password_policies
                    
                    # Calculate days since last password change
                    days_since_pwd_change = "Unknown"
                    if last_pwd_change:
                        try:
                            pwd_date = datetime.fromisoformat(last_pwd_change.replace("Z", "+00:00"))
                            days_since_pwd_change = (datetime.now(timezone.utc) - pwd_date).days
                        except:
                            pass
                    
                    # Determine risk level
                    risk_level = "LOW"
                    risk_factors = []
                    
                    if never_expires:
                        risk_factors.append("Password never expires")
                        risk_level = "MEDIUM"
                    if strong_pwd_disabled:
                        risk_factors.append("Strong password disabled")
                        risk_level = "HIGH"
                    if isinstance(days_since_pwd_change, int) and days_since_pwd_change > 365:
                        risk_factors.append("Password >365 days old")
                        if risk_level != "HIGH":
                            risk_level = "MEDIUM"
                    if isinstance(days_since_pwd_change, int) and days_since_pwd_change > 730:
                        risk_factors.append("Password >2 years old")
                        risk_level = "HIGH"
                    
                    user_policies.append({
                        "id": user.get("id", ""),
                        "displayName": user.get("displayName", ""),
                        "userPrincipalName": user.get("userPrincipalName", ""),
                        "mail": user.get("mail", ""),
                        "userType": user.get("userType", ""),
                        "passwordNeverExpires": never_expires,
                        "strongPasswordDisabled": strong_pwd_disabled,
                        "lastPasswordChange": last_pwd_change[:10] if last_pwd_change else "Unknown",
                        "daysSincePasswordChange": days_since_pwd_change,
                        "riskFactors": "; ".join(risk_factors),
                        "riskLevel": risk_level,
                    })
                
                url = data.get("@odata.nextLink")
                if url and page_count % 5 == 0:
                    print(f"    Processed {page_count} pages ({len(user_policies)} users)...")
            else:
                print(f"[!] Password policies: {response.status_code}")
                break
        except Exception as e:
            if not is_cancelled():
                print(f"[!] Error: {e}")
            break
    
    if is_cancelled():
        print("[!] Operation was cancelled - partial results returned")
    elif user_policies:
        high_risk = sum(1 for u in user_policies if u.get("riskLevel") == "HIGH")
        med_risk = sum(1 for u in user_policies if u.get("riskLevel") == "MEDIUM")
        
        print(f"[+] Analyzed password policies for {len(user_policies)} users")
        print(f"    - HIGH risk: {high_risk}")
        print(f"    - MEDIUM risk: {med_risk}")
    
    return user_policies


def get_sspr_enabled_users(access_token: str) -> list:
    """
    Identify users with Self-Service Password Reset (SSPR) enabled.
    SSPR can be an attack vector if not properly secured.
    """
    print("[*] Identifying users with SSPR enabled...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    sspr_users = []
    page_count = 0
    
    # Use the authentication methods registration report
    url = f"{GRAPH_BETA_ENDPOINT}/reports/authenticationMethods/userRegistrationDetails?$top=999"
    
    while url and not is_cancelled():
        try:
            response = make_api_request(url, headers)
            
            if response is None:
                if is_cancelled():
                    break
                break
            
            if response.status_code == 200:
                data = response.json()
                registrations = data.get("value", [])
                page_count += 1
                
                for reg in registrations:
                    is_sspr_registered = reg.get("isSsprRegistered", False)
                    is_sspr_enabled = reg.get("isSsprEnabled", False)
                    is_sspr_capable = reg.get("isSsprCapable", False)
                    methods_registered = reg.get("methodsRegistered", [])
                    
                    # Only include users with SSPR-related settings
                    if is_sspr_registered or is_sspr_enabled or is_sspr_capable:
                        # Check for weak SSPR methods
                        weak_methods = []
                        strong_methods = []
                        
                        for method in methods_registered:
                            method_lower = method.lower()
                            if "email" in method_lower:
                                weak_methods.append("Email")
                            elif "sms" in method_lower:
                                weak_methods.append("SMS")
                            elif "securityquestion" in method_lower:
                                weak_methods.append("Security Questions")
                            elif "mobilephone" in method_lower:
                                weak_methods.append("Mobile Phone")
                            elif "officephone" in method_lower:
                                weak_methods.append("Office Phone")
                            elif "microsoftauthenticator" in method_lower:
                                strong_methods.append("Authenticator")
                            elif "fido" in method_lower:
                                strong_methods.append("FIDO2")
                            elif "windowshello" in method_lower:
                                strong_methods.append("Windows Hello")
                        
                        # Determine risk - users with only weak SSPR methods are at risk
                        risk_level = "LOW"
                        if is_sspr_enabled and weak_methods and not strong_methods:
                            risk_level = "HIGH"
                        elif is_sspr_enabled and weak_methods:
                            risk_level = "MEDIUM"
                        
                        sspr_users.append({
                            "id": reg.get("id", ""),
                            "userPrincipalName": reg.get("userPrincipalName", ""),
                            "displayName": reg.get("userDisplayName", ""),
                            "isSsprRegistered": is_sspr_registered,
                            "isSsprEnabled": is_sspr_enabled,
                            "isSsprCapable": is_sspr_capable,
                            "weakMethods": ", ".join(weak_methods),
                            "strongMethods": ", ".join(strong_methods),
                            "allMethods": ", ".join(methods_registered),
                            "riskLevel": risk_level,
                        })
                
                url = data.get("@odata.nextLink")
                if url and page_count % 5 == 0:
                    print(f"    Processed {page_count} pages ({len(sspr_users)} SSPR users)...")
            else:
                print(f"[!] SSPR report: {response.status_code}")
                break
        except Exception as e:
            if not is_cancelled():
                print(f"[!] Error: {e}")
            break
    
    if is_cancelled():
        print("[!] Operation was cancelled - partial results returned")
    elif sspr_users:
        enabled = sum(1 for u in sspr_users if u.get("isSsprEnabled"))
        high_risk = sum(1 for u in sspr_users if u.get("riskLevel") == "HIGH")
        
        print(f"[+] Found {len(sspr_users)} users with SSPR configured")
        print(f"    - SSPR Enabled: {enabled}")
        print(f"    - HIGH risk (weak methods only): {high_risk}")
    else:
        print("[!] No SSPR users found or access denied")
    
    return sspr_users


def get_legacy_authentication_users(access_token: str) -> list:
    """
    List users with legacy authentication allowed or used.
    Legacy auth bypasses MFA and is a significant security risk.
    """
    print("[*] Checking for legacy authentication usage...")
    
    from datetime import datetime, timedelta, timezone
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    legacy_auth_users = []
    
    # Legacy authentication protocols to check
    legacy_protocols = [
        "Exchange ActiveSync",
        "IMAP4",
        "POP3",
        "SMTP",
        "MAPI Over HTTP",
        "Autodiscover",
        "Exchange Online PowerShell",
        "Outlook Anywhere",
        "Other clients",
        "Authenticated SMTP",
    ]
    
    # Query last 30 days of sign-ins with legacy protocols
    print("    Checking sign-in logs for legacy protocols...")
    start_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    seen_users = set()
    
    for i, protocol in enumerate(legacy_protocols):
        # Check for cancellation between protocols
        if is_cancelled():
            print(f"    Cancelled after checking {i}/{len(legacy_protocols)} protocols")
            break
            
        try:
            url = f"{GRAPH_BETA_ENDPOINT}/auditLogs/signIns?$filter=clientAppUsed eq '{protocol}' and createdDateTime ge {start_date}&$top=100"
            response = make_api_request(url, headers)
            
            if response is None:
                if is_cancelled():
                    break
                continue
            
            if response.status_code == 200:
                sign_ins = response.json().get("value", [])
                
                for sign_in in sign_ins:
                    user_id = sign_in.get("userId")
                    user_key = f"{user_id}_{protocol}"
                    
                    if user_key not in seen_users:
                        seen_users.add(user_key)
                        
                        # Check if user already in results
                        existing_user = next((u for u in legacy_auth_users if u.get("id") == user_id), None)
                        
                        if existing_user:
                            # Update protocols list
                            if protocol not in existing_user.get("legacyProtocols", ""):
                                existing_user["legacyProtocols"] += f", {protocol}"
                        else:
                            created_dt = sign_in.get("createdDateTime", "")
                            legacy_auth_users.append({
                                "id": user_id,
                                "userPrincipalName": sign_in.get("userPrincipalName", ""),
                                "displayName": sign_in.get("userDisplayName", ""),
                                "legacyProtocols": protocol,
                                "lastLegacySignIn": created_dt[:10] if created_dt else "Unknown",
                                "clientApp": sign_in.get("clientAppUsed", ""),
                                "status": "Success" if sign_in.get("status", {}).get("errorCode") == 0 else "Failed",
                                "riskLevel": "HIGH",
                            })
        except Exception:
            continue
    
    # Check conditional access for legacy auth blocks (only if not cancelled)
    if not is_cancelled():
        print("    Checking conditional access for legacy auth blocks...")
        try:
            policy_url = f"{GRAPH_BETA_ENDPOINT}/identity/conditionalAccess/policies"
            response = make_api_request(policy_url, headers)
            
            legacy_auth_blocked = False
            if response and response.status_code == 200:
                policies = response.json().get("value", [])
                
                for policy in policies:
                    if policy.get("state") == "enabled":
                        conditions = policy.get("conditions", {})
                        client_app_types = conditions.get("clientAppTypes", [])
                        
                        if "exchangeActiveSync" in client_app_types or "other" in client_app_types:
                            controls = policy.get("grantControls", {})
                            if "block" in controls.get("builtInControls", []):
                                legacy_auth_blocked = True
            
            if not legacy_auth_blocked:
                print("    [!] WARNING: No CA policy blocking legacy authentication detected")
        except Exception:
            print("    [!] Cannot check CA policies: Access denied")
    
    if is_cancelled():
        print("[!] Operation was cancelled - partial results returned")
    elif legacy_auth_users:
        unique_users = len(set(u.get("id") for u in legacy_auth_users))
        print(f"[+] Found {unique_users} users using legacy authentication (HIGH RISK)")
    else:
        print("[+] No legacy authentication usage detected in last 30 days")
    
    return legacy_auth_users


def get_users_with_app_passwords(access_token: str) -> list:
    """
    Find users with app passwords configured.
    App passwords bypass MFA and are a significant attack surface.
    """
    print("[*] Finding users with app passwords configured...")
    print("    (App passwords bypass MFA - HIGH RISK)")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    users_with_app_passwords = []
    
    # Method 1: Check via authentication methods registration report
    try:
        url = f"{GRAPH_BETA_ENDPOINT}/reports/authenticationMethods/userRegistrationDetails?$top=999"
        page_count = 0
        
        while url and not is_cancelled():
            response = make_api_request(url, headers)
            
            if response is None:
                if is_cancelled():
                    break
                break
            
            if response.status_code == 200:
                data = response.json()
                registrations = data.get("value", [])
                page_count += 1
                
                for reg in registrations:
                    methods_registered = reg.get("methodsRegistered", [])
                    
                    # Check if user has app passwords
                    has_app_password = False
                    for method in methods_registered:
                        if "apppassword" in method.lower() or "app password" in method.lower():
                            has_app_password = True
                            break
                    
                    if has_app_password:
                        users_with_app_passwords.append({
                            "id": reg.get("id", ""),
                            "displayName": reg.get("userDisplayName", ""),
                            "userPrincipalName": reg.get("userPrincipalName", ""),
                            "mail": "",
                            "userType": "",
                            "hasAppPassword": True,
                            "appPasswordCount": "Unknown",
                            "riskLevel": "HIGH",
                            "riskReason": "App passwords bypass MFA",
                        })
                
                url = data.get("@odata.nextLink")
                if url and page_count % 5 == 0:
                    print(f"    Processed {page_count} pages...")
            else:
                print(f"    Registration report: {response.status_code}")
                break
    except Exception as e:
        if not is_cancelled():
            print(f"    Error checking registration report: {e}")
    
    # Method 2: If no results, try checking individual users' authentication methods
    if not users_with_app_passwords and not is_cancelled():
        print("    Trying alternative detection method...")
        
        try:
            # Get all users first
            users_url = f"{GRAPH_API_ENDPOINT}/users?$select=id,displayName,userPrincipalName,mail&$top=999"
            users_response = make_api_request(users_url, headers)
            
            if users_response and users_response.status_code == 200:
                users = users_response.json().get("value", [])
                print(f"    Checking authentication methods for {len(users)} users...")
                
                for i, user in enumerate(users):
                    # Check for cancellation in the loop
                    if is_cancelled():
                        print(f"    Cancelled after checking {i}/{len(users)} users")
                        break
                    
                    user_id = user.get("id")
                    
                    try:
                        # Check password methods
                        pwd_methods_url = f"{GRAPH_BETA_ENDPOINT}/users/{user_id}/authentication/passwordMethods"
                        pwd_response = make_api_request(pwd_methods_url, headers)
                        
                        if pwd_response is None:
                            if is_cancelled():
                                break
                            continue
                        
                        if pwd_response.status_code == 200:
                            pwd_methods = pwd_response.json().get("value", [])
                            
                            # Default password has ID 28c10230-6103-485e-b985-444c60001490
                            # Other password methods are app passwords
                            app_pwd_count = 0
                            for method in pwd_methods:
                                if method.get("id") != "28c10230-6103-485e-b985-444c60001490":
                                    app_pwd_count += 1
                            
                            if app_pwd_count > 0:
                                users_with_app_passwords.append({
                                    "id": user_id,
                                    "displayName": user.get("displayName", ""),
                                    "userPrincipalName": user.get("userPrincipalName", ""),
                                    "mail": user.get("mail", ""),
                                    "userType": "",
                                    "hasAppPassword": True,
                                    "appPasswordCount": app_pwd_count,
                                    "riskLevel": "HIGH",
                                    "riskReason": "App passwords bypass MFA",
                                })
                    except Exception:
                        continue
                    
                    # Progress indicator
                    if (i + 1) % 100 == 0:
                        print(f"    Processed {i + 1}/{len(users)} users...")
        except Exception as e:
            if not is_cancelled():
                print(f"    Error: {e}")
    
    if is_cancelled():
        print("[!] Operation was cancelled - partial results returned")
    elif users_with_app_passwords:
        print(f"[+] Found {len(users_with_app_passwords)} users with app passwords (HIGH RISK)")
    else:
        print("[+] No users with app passwords detected")
    
    return users_with_app_passwords


def print_credential_attack_surface_report(pwd_policies: list, sspr_users: list, 
                                           legacy_auth: list, app_passwords: list) -> None:
    """Print a comprehensive credential attack surface report."""
    print("\n" + "=" * 70)
    print(f"{'CREDENTIAL ATTACK SURFACE SUMMARY':^70}")
    print("=" * 70)
    
    pwd_high_risk = sum(1 for u in pwd_policies if u.get("riskLevel") == "HIGH")
    sspr_high_risk = sum(1 for u in sspr_users if u.get("riskLevel") == "HIGH")
    legacy_count = len(legacy_auth)
    app_pwd_count = len(app_passwords)
    
    print(f"\n  Password policy HIGH risk:     {pwd_high_risk}")
    print(f"  SSPR weak methods only:        {sspr_high_risk}")
    print(f"  Legacy auth users:             {legacy_count}")
    print(f"  App password users:            {app_pwd_count}")
    
    print("\n" + "-" * 70)


# ============================================================================
# CONDITIONAL ACCESS ANALYSIS
# ============================================================================

def get_conditional_access_policies(access_token: str) -> list:
    """
    Enumerate all Conditional Access policies.
    Requires Policy.Read.All permission.
    """
    print("[*] Enumerating Conditional Access policies...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    policies = []
    
    try:
        url = f"{GRAPH_BETA_ENDPOINT}/identity/conditionalAccess/policies"
        
        while url and not is_cancelled():
            response = make_api_request(url, headers)
            
            if response is None:
                if is_cancelled():
                    break
                print("[!] Cannot enumerate CA policies - access denied or not available")
                return []
            
            if response.status_code == 200:
                data = response.json()
                
                for policy in data.get("value", []):
                    policy_info = {
                        "id": policy.get("id", ""),
                        "displayName": policy.get("displayName", ""),
                        "state": policy.get("state", ""),
                        "createdDateTime": policy.get("createdDateTime", ""),
                        "modifiedDateTime": policy.get("modifiedDateTime", ""),
                        "conditions": policy.get("conditions", {}),
                        "grantControls": policy.get("grantControls", {}),
                        "sessionControls": policy.get("sessionControls", {}),
                    }
                    
                    # Analyze policy for risk
                    risk_level = "LOW"
                    risk_reasons = []
                    
                    conditions = policy.get("conditions") or {}
                    grant_controls = policy.get("grantControls") or {}
                    
                    # Check if policy is disabled
                    if policy.get("state") != "enabled":
                        risk_level = "MEDIUM"
                        risk_reasons.append("Policy disabled")
                    
                    # Check for all users exclusions
                    users_cond = conditions.get("users") or {}
                    exclude_users = users_cond.get("excludeUsers") or []
                    exclude_groups = users_cond.get("excludeGroups") or []
                    
                    if exclude_users or exclude_groups:
                        risk_reasons.append(f"Has exclusions ({len(exclude_users)} users, {len(exclude_groups)} groups)")
                        if risk_level == "LOW":
                            risk_level = "MEDIUM"
                    
                    # Check grant controls
                    builtin_controls = grant_controls.get("builtInControls") or []
                    
                    # Check if MFA is required
                    mfa_required = "mfa" in builtin_controls
                    
                    # Check client app types (legacy auth)
                    client_app_types = conditions.get("clientAppTypes") or []
                    targets_legacy = "exchangeActiveSync" in client_app_types or "other" in client_app_types
                    
                    # Check if it blocks access
                    blocks_access = "block" in builtin_controls
                    
                    policy_info["mfaRequired"] = mfa_required
                    policy_info["blocksAccess"] = blocks_access
                    policy_info["targetsLegacyAuth"] = targets_legacy
                    policy_info["excludeUsersCount"] = len(exclude_users)
                    policy_info["excludeGroupsCount"] = len(exclude_groups)
                    policy_info["riskLevel"] = risk_level
                    policy_info["riskReasons"] = "; ".join(risk_reasons) if risk_reasons else "None"
                    
                    policies.append(policy_info)
                
                url = data.get("@odata.nextLink")
            elif response.status_code == 403:
                print("[!] Access denied - Policy.Read.All permission required")
                return []
            else:
                print(f"[!] Error: HTTP {response.status_code}")
                return []
    except Exception as e:
        print(f"[!] Error enumerating CA policies: {e}")
        return []
    
    if is_cancelled():
        print("[!] Operation was cancelled - partial results returned")
    elif policies:
        enabled_count = sum(1 for p in policies if p.get("state") == "enabled")
        print(f"[+] Found {len(policies)} CA policies ({enabled_count} enabled)")
    else:
        print("[+] No Conditional Access policies found")
    
    return policies


def get_ca_policy_exclusions(access_token: str) -> dict:
    """
    Identify users and groups excluded from Conditional Access policies.
    These exclusions are potential attack vectors.
    """
    print("[*] Analyzing CA policy exclusions...")
    print("    (Exclusions are potential security gaps)")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    exclusions = {
        "excluded_users": [],
        "excluded_groups": [],
        "excluded_roles": [],
        "policies_with_exclusions": [],
    }
    
    try:
        # Get all CA policies
        url = f"{GRAPH_BETA_ENDPOINT}/identity/conditionalAccess/policies"
        response = make_api_request(url, headers)
        
        if response is None or response.status_code != 200:
            print("[!] Cannot access CA policies")
            return exclusions
        
        policies = response.json().get("value", [])
        
        # Track unique exclusions
        all_excluded_user_ids = set()
        all_excluded_group_ids = set()
        all_excluded_role_ids = set()
        
        for policy in policies:
            if is_cancelled():
                break
            
            if policy.get("state") != "enabled":
                continue
            
            conditions = policy.get("conditions") or {}
            users_condition = conditions.get("users") or {}
            
            exclude_users = users_condition.get("excludeUsers") or []
            exclude_groups = users_condition.get("excludeGroups") or []
            exclude_roles = users_condition.get("excludeRoles") or []
            
            if exclude_users or exclude_groups or exclude_roles:
                exclusions["policies_with_exclusions"].append({
                    "policyId": policy.get("id"),
                    "policyName": policy.get("displayName"),
                    "excludedUsers": len(exclude_users),
                    "excludedGroups": len(exclude_groups),
                    "excludedRoles": len(exclude_roles),
                })
                
                all_excluded_user_ids.update(exclude_users)
                all_excluded_group_ids.update(exclude_groups)
                all_excluded_role_ids.update(exclude_roles)
        
        # Resolve excluded user details
        print("    Resolving excluded user identities...")
        for user_id in all_excluded_user_ids:
            if is_cancelled():
                break
            if user_id in ["GuestsOrExternalUsers", "All"]:
                exclusions["excluded_users"].append({
                    "id": user_id,
                    "displayName": user_id,
                    "userPrincipalName": user_id,
                    "riskLevel": "HIGH" if user_id == "All" else "MEDIUM",
                })
                continue
            
            try:
                user_url = f"{GRAPH_API_ENDPOINT}/users/{user_id}?$select=id,displayName,userPrincipalName,mail,jobTitle,department"
                user_response = make_api_request(user_url, headers)
                
                if user_response and user_response.status_code == 200:
                    user_data = user_response.json()
                    exclusions["excluded_users"].append({
                        "id": user_data.get("id", user_id),
                        "displayName": user_data.get("displayName", "Unknown"),
                        "userPrincipalName": user_data.get("userPrincipalName", ""),
                        "mail": user_data.get("mail", ""),
                        "jobTitle": user_data.get("jobTitle", ""),
                        "department": user_data.get("department", ""),
                        "riskLevel": "HIGH",
                        "riskReason": "Excluded from CA policies",
                    })
            except Exception:
                exclusions["excluded_users"].append({
                    "id": user_id,
                    "displayName": "Unable to resolve",
                    "userPrincipalName": user_id,
                    "riskLevel": "HIGH",
                })
        
        # Resolve excluded group details
        print("    Resolving excluded group identities...")
        for group_id in all_excluded_group_ids:
            if is_cancelled():
                break
            
            try:
                group_url = f"{GRAPH_API_ENDPOINT}/groups/{group_id}?$select=id,displayName,description,membershipRule"
                group_response = make_api_request(group_url, headers)
                
                if group_response and group_response.status_code == 200:
                    group_data = group_response.json()
                    
                    # Get member count
                    members_url = f"{GRAPH_API_ENDPOINT}/groups/{group_id}/members/$count"
                    member_count = 0
                    try:
                        headers_count = headers.copy()
                        headers_count["ConsistencyLevel"] = "eventual"
                        members_response = make_api_request(members_url, headers_count)
                        if members_response and members_response.status_code == 200:
                            member_count = int(members_response.text)
                    except:
                        pass
                    
                    exclusions["excluded_groups"].append({
                        "id": group_data.get("id", group_id),
                        "displayName": group_data.get("displayName", "Unknown"),
                        "description": group_data.get("description", ""),
                        "memberCount": member_count,
                        "riskLevel": "HIGH" if member_count > 10 else "MEDIUM",
                        "riskReason": f"Excluded from CA policies ({member_count} members)",
                    })
            except Exception:
                exclusions["excluded_groups"].append({
                    "id": group_id,
                    "displayName": "Unable to resolve",
                    "riskLevel": "HIGH",
                })
        
        # Resolve excluded roles
        print("    Resolving excluded role identities...")
        for role_id in all_excluded_role_ids:
            if is_cancelled():
                break
            
            try:
                role_url = f"{GRAPH_API_ENDPOINT}/directoryRoles?$filter=roleTemplateId eq '{role_id}'"
                role_response = make_api_request(role_url, headers)
                
                if role_response and role_response.status_code == 200:
                    roles = role_response.json().get("value", [])
                    if roles:
                        role_data = roles[0]
                        exclusions["excluded_roles"].append({
                            "id": role_id,
                            "displayName": role_data.get("displayName", "Unknown"),
                            "riskLevel": "CRITICAL",
                            "riskReason": "Admin role excluded from CA policies",
                        })
                    else:
                        exclusions["excluded_roles"].append({
                            "id": role_id,
                            "displayName": "Unknown role",
                            "riskLevel": "HIGH",
                        })
            except Exception:
                exclusions["excluded_roles"].append({
                    "id": role_id,
                    "displayName": "Unable to resolve",
                    "riskLevel": "HIGH",
                })
    
    except Exception as e:
        print(f"[!] Error analyzing exclusions: {e}")
    
    if is_cancelled():
        print("[!] Operation was cancelled - partial results returned")
    else:
        print(f"[+] Found {len(exclusions['excluded_users'])} excluded users, "
              f"{len(exclusions['excluded_groups'])} excluded groups, "
              f"{len(exclusions['excluded_roles'])} excluded roles")
    
    return exclusions


def get_mfa_enforcement_gaps(access_token: str) -> dict:
    """
    Find gaps in MFA enforcement across CA policies.
    Identifies scenarios where MFA is not required.
    """
    print("[*] Analyzing MFA enforcement gaps...")
    print("    (Finding scenarios where MFA is not enforced)")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    gaps = {
        "no_mfa_policies": [],
        "mfa_policies": [],
        "users_without_mfa_enforcement": [],
        "apps_without_mfa": [],
        "locations_without_mfa": [],
        "summary": {},
    }
    
    try:
        # Get all CA policies
        url = f"{GRAPH_BETA_ENDPOINT}/identity/conditionalAccess/policies"
        response = make_api_request(url, headers)
        
        if response is None or response.status_code != 200:
            print("[!] Cannot access CA policies")
            return gaps
        
        policies = response.json().get("value", [])
        enabled_policies = [p for p in policies if p.get("state") == "enabled"]
        
        print(f"    Analyzing {len(enabled_policies)} enabled CA policies...")
        
        # Analyze each policy
        all_apps_requiring_mfa = set()
        all_users_requiring_mfa = set()
        
        for policy in enabled_policies:
            if is_cancelled():
                break
            
            conditions = policy.get("conditions") or {}
            grant_controls = policy.get("grantControls") or {}
            
            builtin_controls = grant_controls.get("builtInControls") or []
            mfa_required = "mfa" in builtin_controls
            
            # Get target applications
            apps_condition = conditions.get("applications") or {}
            include_apps = apps_condition.get("includeApplications") or []
            exclude_apps = apps_condition.get("excludeApplications") or []
            
            # Get target users
            users_condition = conditions.get("users") or {}
            include_users = users_condition.get("includeUsers") or []
            include_groups = users_condition.get("includeGroups") or []
            
            policy_info = {
                "id": policy.get("id"),
                "displayName": policy.get("displayName"),
                "mfaRequired": mfa_required,
                "targetApps": include_apps,
                "targetUsers": include_users,
                "targetGroups": include_groups,
                "excludedApps": exclude_apps,
            }
            
            if mfa_required:
                gaps["mfa_policies"].append(policy_info)
                if "All" in include_apps:
                    all_apps_requiring_mfa.add("All")
                else:
                    all_apps_requiring_mfa.update(include_apps)
                
                if "All" in include_users:
                    all_users_requiring_mfa.add("All")
                else:
                    all_users_requiring_mfa.update(include_users)
            else:
                # Policy without MFA - check if it could be a gap
                blocks_access = "block" in builtin_controls
                if not blocks_access:
                    policy_info["riskLevel"] = "MEDIUM"
                    policy_info["riskReason"] = "Policy allows access without MFA"
                    gaps["no_mfa_policies"].append(policy_info)
        
        # Check for apps without MFA requirement
        if not is_cancelled() and "All" not in all_apps_requiring_mfa:
            print("    Checking for apps without MFA enforcement...")
            
            # Get high-value apps that should have MFA
            critical_apps = [
                ("00000002-0000-0000-c000-000000000000", "Azure Active Directory Graph"),
                ("00000003-0000-0000-c000-000000000000", "Microsoft Graph"),
                ("00000002-0000-0ff1-ce00-000000000000", "Office 365 Exchange Online"),
                ("00000003-0000-0ff1-ce00-000000000000", "Office 365 SharePoint Online"),
                ("00000004-0000-0ff1-ce00-000000000000", "Skype for Business Online"),
                ("797f4846-ba00-4fd7-ba43-dac1f8f63013", "Azure Service Management API"),
            ]
            
            for app_id, app_name in critical_apps:
                if app_id not in all_apps_requiring_mfa:
                    gaps["apps_without_mfa"].append({
                        "id": app_id,
                        "displayName": app_name,
                        "riskLevel": "HIGH",
                        "riskReason": "Critical app may not require MFA",
                    })
        
        # Check for users without any MFA policy
        if not is_cancelled() and "All" not in all_users_requiring_mfa:
            print("    Checking MFA coverage for privileged users...")
            
            # Get privileged role members and check if they're covered
            priv_roles = [
                "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
                "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
                "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
            ]
            
            for role_template_id in priv_roles:
                if is_cancelled():
                    break
                
                try:
                    role_url = f"{GRAPH_API_ENDPOINT}/directoryRoles?$filter=roleTemplateId eq '{role_template_id}'"
                    role_response = make_api_request(role_url, headers)
                    
                    if role_response and role_response.status_code == 200:
                        roles = role_response.json().get("value", [])
                        for role in roles:
                            role_id = role.get("id")
                            members_url = f"{GRAPH_API_ENDPOINT}/directoryRoles/{role_id}/members"
                            members_response = make_api_request(members_url, headers)
                            
                            if members_response and members_response.status_code == 200:
                                members = members_response.json().get("value", [])
                                for member in members:
                                    member_id = member.get("id")
                                    if member_id and member_id not in all_users_requiring_mfa:
                                        gaps["users_without_mfa_enforcement"].append({
                                            "id": member_id,
                                            "displayName": member.get("displayName", "Unknown"),
                                            "userPrincipalName": member.get("userPrincipalName", ""),
                                            "role": role.get("displayName", "Unknown"),
                                            "riskLevel": "CRITICAL",
                                            "riskReason": f"Privileged user may not have MFA enforced",
                                        })
                except Exception:
                    continue
        
        # Generate summary
        gaps["summary"] = {
            "total_ca_policies": len(policies),
            "enabled_policies": len(enabled_policies),
            "policies_with_mfa": len(gaps["mfa_policies"]),
            "policies_without_mfa": len(gaps["no_mfa_policies"]),
            "apps_without_mfa_coverage": len(gaps["apps_without_mfa"]),
            "privileged_users_without_mfa": len(gaps["users_without_mfa_enforcement"]),
            "mfa_coverage": "All users" if "All" in all_users_requiring_mfa else "Partial",
        }
        
    except Exception as e:
        print(f"[!] Error analyzing MFA gaps: {e}")
    
    if is_cancelled():
        print("[!] Operation was cancelled - partial results returned")
    else:
        summary = gaps.get("summary", {})
        print(f"[+] MFA Analysis Complete:")
        print(f"    - Policies with MFA: {summary.get('policies_with_mfa', 0)}")
        print(f"    - Policies without MFA: {summary.get('policies_without_mfa', 0)}")
        print(f"    - MFA Coverage: {summary.get('mfa_coverage', 'Unknown')}")
        
        if gaps["users_without_mfa_enforcement"]:
            print(f"    - CRITICAL: {len(gaps['users_without_mfa_enforcement'])} privileged users may not have MFA enforced!")
    
    return gaps


def print_ca_policies_report(policies: list) -> None:
    """Print Conditional Access policies report."""
    if not policies:
        print("[!] No CA policies to display")
        return
    
    print("\n" + "=" * 120)
    print(f"{'CONDITIONAL ACCESS POLICIES':^120}")
    print("=" * 120)
    
    enabled = sum(1 for p in policies if p.get("state") == "enabled")
    disabled = len(policies) - enabled
    mfa_policies = sum(1 for p in policies if p.get("mfaRequired"))
    blocking_policies = sum(1 for p in policies if p.get("blocksAccess"))
    
    print(f"\nTotal: {len(policies)} | Enabled: {enabled} | Disabled: {disabled}")
    print(f"MFA Required: {mfa_policies} | Blocking: {blocking_policies}")
    print("\n" + "-" * 120)
    
    print(f"{'Policy Name':<40} {'State':<10} {'MFA':<5} {'Block':<6} {'Excl Users':<11} {'Excl Groups':<12} {'Risk':<8}")
    print("-" * 120)
    
    # Sort by risk level then by state
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_policies = sorted(policies, key=lambda x: (risk_order.get(x.get("riskLevel", "LOW"), 3), x.get("state") != "enabled"))
    
    for policy in sorted_policies:
        name = (policy.get("displayName") or "N/A")[:39]
        state = policy.get("state", "N/A")[:9]
        mfa = "Yes" if policy.get("mfaRequired") else "No"
        block = "Yes" if policy.get("blocksAccess") else "No"
        excl_users = str(policy.get("excludeUsersCount", 0))
        excl_groups = str(policy.get("excludeGroupsCount", 0))
        risk = policy.get("riskLevel", "")
        
        color_code = ""
        if policy.get("state") != "enabled":
            color_code = "\033[90m"  # Gray for disabled
        elif risk == "HIGH":
            color_code = "\033[91m"  # Red
        elif risk == "MEDIUM":
            color_code = "\033[93m"  # Yellow
        
        print(f"{name:<40} {state:<10} {mfa:<5} {block:<6} {excl_users:<11} {excl_groups:<12} {risk:<8}")
    
    print("-" * 120)


def print_ca_exclusions_report(exclusions: dict) -> None:
    """Print CA policy exclusions report."""
    print("\n" + "=" * 110)
    print(f"{'CONDITIONAL ACCESS EXCLUSIONS (SECURITY GAPS)':^110}")
    print("=" * 110)
    
    excluded_users = exclusions.get("excluded_users", [])
    excluded_groups = exclusions.get("excluded_groups", [])
    excluded_roles = exclusions.get("excluded_roles", [])
    policies_with_excl = exclusions.get("policies_with_exclusions", [])
    
    print(f"\nPolicies with exclusions: {len(policies_with_excl)}")
    print(f"Excluded users: {len(excluded_users)}")
    print(f"Excluded groups: {len(excluded_groups)}")
    print(f"Excluded roles: {len(excluded_roles)}")
    
    if excluded_roles:
        print("\n" + "-" * 110)
        print("EXCLUDED ROLES (CRITICAL RISK):")
        print("-" * 110)
        print(f"{'Role Name':<50} {'Risk Level':<15} {'Risk Reason':<40}")
        print("-" * 110)
        for role in excluded_roles:
            name = (role.get("displayName") or "Unknown")[:49]
            risk = role.get("riskLevel", "")
            reason = (role.get("riskReason") or "")[:39]
            print(f"{name:<50} {risk:<15} {reason:<40}")
    
    if excluded_users:
        print("\n" + "-" * 110)
        print("EXCLUDED USERS:")
        print("-" * 110)
        print(f"{'Display Name':<30} {'Email/UPN':<45} {'Department':<20} {'Risk':<10}")
        print("-" * 110)
        for user in excluded_users[:30]:
            name = (user.get("displayName") or "N/A")[:29]
            email = (user.get("userPrincipalName") or "N/A")[:44]
            dept = (user.get("department") or "")[:19]
            risk = user.get("riskLevel", "")
            print(f"{name:<30} {email:<45} {dept:<20} {risk:<10}")
        if len(excluded_users) > 30:
            print(f"    ... and {len(excluded_users) - 30} more")
    
    if excluded_groups:
        print("\n" + "-" * 110)
        print("EXCLUDED GROUPS:")
        print("-" * 110)
        print(f"{'Group Name':<40} {'Members':<10} {'Description':<40} {'Risk':<10}")
        print("-" * 110)
        for group in excluded_groups[:20]:
            name = (group.get("displayName") or "Unknown")[:39]
            members = str(group.get("memberCount", "?"))[:9]
            desc = (group.get("description") or "")[:39]
            risk = group.get("riskLevel", "")
            print(f"{name:<40} {members:<10} {desc:<40} {risk:<10}")
        if len(excluded_groups) > 20:
            print(f"    ... and {len(excluded_groups) - 20} more")
    
    print("-" * 110)


def print_mfa_gaps_report(gaps: dict) -> None:
    """Print MFA enforcement gaps report."""
    print("\n" + "=" * 110)
    print(f"{'MFA ENFORCEMENT GAPS ANALYSIS':^110}")
    print("=" * 110)
    
    summary = gaps.get("summary", {})
    
    print(f"\nTotal CA Policies: {summary.get('total_ca_policies', 0)}")
    print(f"Enabled Policies: {summary.get('enabled_policies', 0)}")
    print(f"Policies with MFA: {summary.get('policies_with_mfa', 0)}")
    print(f"Policies without MFA: {summary.get('policies_without_mfa', 0)}")
    print(f"MFA Coverage: {summary.get('mfa_coverage', 'Unknown')}")
    
    users_without_mfa = gaps.get("users_without_mfa_enforcement", [])
    apps_without_mfa = gaps.get("apps_without_mfa", [])
    no_mfa_policies = gaps.get("no_mfa_policies", [])
    
    if users_without_mfa:
        print("\n" + "-" * 110)
        print("PRIVILEGED USERS WITHOUT MFA ENFORCEMENT (CRITICAL):")
        print("-" * 110)
        print(f"{'Display Name':<30} {'Email/UPN':<40} {'Role':<25} {'Risk':<10}")
        print("-" * 110)
        for user in users_without_mfa:
            name = (user.get("displayName") or "N/A")[:29]
            email = (user.get("userPrincipalName") or "N/A")[:39]
            role = (user.get("role") or "")[:24]
            risk = user.get("riskLevel", "")
            print(f"{name:<30} {email:<40} {role:<25} {risk:<10}")
    
    if apps_without_mfa:
        print("\n" + "-" * 110)
        print("CRITICAL APPS WITHOUT MFA COVERAGE:")
        print("-" * 110)
        print(f"{'Application Name':<50} {'Risk Level':<15} {'Risk Reason':<40}")
        print("-" * 110)
        for app in apps_without_mfa:
            name = (app.get("displayName") or "Unknown")[:49]
            risk = app.get("riskLevel", "")
            reason = (app.get("riskReason") or "")[:39]
            print(f"{name:<50} {risk:<15} {reason:<40}")
    
    if no_mfa_policies:
        print("\n" + "-" * 110)
        print("POLICIES WITHOUT MFA REQUIREMENT:")
        print("-" * 110)
        print(f"{'Policy Name':<50} {'Target Apps':<30} {'Risk':<10}")
        print("-" * 110)
        for policy in no_mfa_policies[:20]:
            name = (policy.get("displayName") or "N/A")[:49]
            apps = policy.get("targetApps", [])
            apps_str = (", ".join(apps[:2]) if apps else "N/A")[:29]
            risk = policy.get("riskLevel", "")
            print(f"{name:<50} {apps_str:<30} {risk:<10}")
        if len(no_mfa_policies) > 20:
            print(f"    ... and {len(no_mfa_policies) - 20} more")
    
    print("-" * 110)


def run_full_ca_analysis(access_token: str) -> dict:
    """Run comprehensive Conditional Access analysis."""
    print("\n" + "=" * 70)
    print("CONDITIONAL ACCESS ANALYSIS")
    print("=" * 70)
    
    results = {}
    
    print("\n[1/3] Enumerating CA Policies...")
    results["policies"] = get_conditional_access_policies(access_token)
    
    if not is_cancelled():
        print("\n[2/3] Analyzing Exclusions...")
        results["exclusions"] = get_ca_policy_exclusions(access_token)
    
    if not is_cancelled():
        print("\n[3/3] Analyzing MFA Gaps...")
        results["mfa_gaps"] = get_mfa_enforcement_gaps(access_token)
    
    # Print summary
    print("\n" + "=" * 70)
    print("CA ANALYSIS SUMMARY")
    print("=" * 70)
    
    policies = results.get("policies", [])
    exclusions = results.get("exclusions", {})
    mfa_gaps = results.get("mfa_gaps", {})
    
    enabled_policies = sum(1 for p in policies if p.get("state") == "enabled")
    excl_users = len(exclusions.get("excluded_users", []))
    excl_groups = len(exclusions.get("excluded_groups", []))
    excl_roles = len(exclusions.get("excluded_roles", []))
    priv_users_no_mfa = len(mfa_gaps.get("users_without_mfa_enforcement", []))
    
    print(f"\n  Total CA Policies:             {len(policies)}")
    print(f"  Enabled Policies:              {enabled_policies}")
    print(f"  Excluded Users:                {excl_users}")
    print(f"  Excluded Groups:               {excl_groups}")
    print(f"  Excluded Roles (CRITICAL):     {excl_roles}")
    print(f"  Priv Users w/o MFA (CRITICAL): {priv_users_no_mfa}")
    
    print("\n" + "-" * 70)
    
    return results


# ============================================================================
# DEVICE ENUMERATION FEATURES
# ============================================================================

def get_all_devices(access_token: str) -> list:
    """
    Enumerate all registered devices in Azure AD/Entra ID.
    Returns comprehensive device information including compliance status.
    """
    print("[*] Enumerating all registered devices...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    all_devices = []
    
    # Select all relevant device properties
    select_props = "id,displayName,deviceId,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,managementType,deviceOwnership,registrationDateTime,approximateLastSignInDateTime,accountEnabled,manufacturer,model,enrollmentType"
    url = f"{GRAPH_API_ENDPOINT}/devices?$select={select_props}&$top=999"
    
    while url:
        try:
            response = make_api_request(url, headers)
            
            if response and response.status_code == 200:
                data = response.json()
                devices = data.get("value", [])
                
                for device in devices:
                    # Determine trust type (how device is joined)
                    trust_type = device.get("trustType", "Unknown")
                    join_type = "Unknown"
                    if trust_type == "AzureAd":
                        join_type = "Azure AD Joined"
                    elif trust_type == "ServerAd":
                        join_type = "Hybrid Azure AD Joined"
                    elif trust_type == "Workplace":
                        join_type = "Azure AD Registered (BYOD)"
                    
                    # Determine device ownership
                    ownership = device.get("deviceOwnership", "Unknown")
                    is_byod = ownership == "Personal" or trust_type == "Workplace"
                    
                    # Determine compliance status
                    is_compliant = device.get("isCompliant")
                    is_managed = device.get("isManaged", False)
                    
                    # Determine risk level based on compliance and management
                    risk_level = "LOW"
                    risk_factors = []
                    
                    if is_compliant == False:
                        risk_level = "HIGH"
                        risk_factors.append("Non-compliant")
                    elif is_compliant is None:
                        risk_level = "MEDIUM"
                        risk_factors.append("Compliance unknown")
                    
                    if not is_managed:
                        if risk_level == "LOW":
                            risk_level = "MEDIUM"
                        risk_factors.append("Unmanaged")
                    
                    if is_byod:
                        if risk_level == "LOW":
                            risk_level = "MEDIUM"
                        risk_factors.append("BYOD")
                    
                    if not device.get("accountEnabled", True):
                        risk_factors.append("Disabled")
                    
                    all_devices.append({
                        "id": device.get("id", ""),
                        "deviceId": device.get("deviceId", ""),
                        "displayName": device.get("displayName", ""),
                        "operatingSystem": device.get("operatingSystem", ""),
                        "osVersion": device.get("operatingSystemVersion", ""),
                        "trustType": trust_type,
                        "joinType": join_type,
                        "isCompliant": is_compliant,
                        "isManaged": is_managed,
                        "managementType": device.get("managementType", ""),
                        "deviceOwnership": ownership,
                        "isBYOD": is_byod,
                        "registrationDateTime": str(device.get("registrationDateTime", ""))[:10],
                        "lastSignIn": str(device.get("approximateLastSignInDateTime", ""))[:10],
                        "accountEnabled": device.get("accountEnabled", True),
                        "manufacturer": device.get("manufacturer", ""),
                        "model": device.get("model", ""),
                        "enrollmentType": device.get("enrollmentType", ""),
                        "riskLevel": risk_level,
                        "riskFactors": ", ".join(risk_factors) if risk_factors else "None",
                    })
                
                url = data.get("@odata.nextLink")
            else:
                if response:
                    print(f"[!] Devices endpoint: {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error enumerating devices: {e}")
            break
    
    if all_devices:
        compliant = sum(1 for d in all_devices if d.get("isCompliant") == True)
        non_compliant = sum(1 for d in all_devices if d.get("isCompliant") == False)
        unknown = sum(1 for d in all_devices if d.get("isCompliant") is None)
        byod = sum(1 for d in all_devices if d.get("isBYOD"))
        managed = sum(1 for d in all_devices if d.get("isManaged"))
        
        print(f"[+] Found {len(all_devices)} devices")
        print(f"    - Compliant: {compliant}")
        print(f"    - Non-compliant (HIGH RISK): {non_compliant}")
        print(f"    - Compliance unknown: {unknown}")
        print(f"    - BYOD/Personal: {byod}")
        print(f"    - Managed: {managed}")
    else:
        print("[!] No devices found or access denied")
    
    return all_devices


def get_user_devices(access_token: str, user_id: str = None) -> list:
    """
    Get devices registered/owned by a specific user or all users.
    Uses both registeredDevices and ownedDevices endpoints.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    user_devices = []
    
    # If no user specified, get devices for all users
    if not user_id:
        print("[*] Enumerating devices per user...")
        
        # First get all users
        users_url = f"{GRAPH_API_ENDPOINT}/users?$select=id,displayName,userPrincipalName&$top=999"
        all_users = []
        
        while users_url:
            response = make_api_request(users_url, headers)
            if response and response.status_code == 200:
                data = response.json()
                all_users.extend(data.get("value", []))
                users_url = data.get("@odata.nextLink")
            else:
                break
        
        print(f"    Checking devices for {len(all_users)} users...")
        
        for i, user in enumerate(all_users):
            if is_cancelled():
                print(f"    Cancelled after {i}/{len(all_users)} users")
                break
            
            uid = user.get("id")
            user_name = user.get("displayName", "")
            user_upn = user.get("userPrincipalName", "")
            
            # Get registered devices
            reg_devices = []
            reg_url = f"{GRAPH_API_ENDPOINT}/users/{uid}/registeredDevices?$select=id,displayName,deviceId,operatingSystem,trustType,isCompliant,isManaged,deviceOwnership"
            
            try:
                response = make_api_request(reg_url, headers)
                if response and response.status_code == 200:
                    reg_devices = response.json().get("value", [])
            except:
                pass
            
            # Get owned devices
            owned_devices = []
            owned_url = f"{GRAPH_API_ENDPOINT}/users/{uid}/ownedDevices?$select=id,displayName,deviceId,operatingSystem,trustType,isCompliant,isManaged,deviceOwnership"
            
            try:
                response = make_api_request(owned_url, headers)
                if response and response.status_code == 200:
                    owned_devices = response.json().get("value", [])
            except:
                pass
            
            # Combine and deduplicate
            seen_device_ids = set()
            combined_devices = []
            
            for device in reg_devices:
                device_id = device.get("id")
                if device_id and device_id not in seen_device_ids:
                    seen_device_ids.add(device_id)
                    device["relationship"] = "Registered"
                    combined_devices.append(device)
            
            for device in owned_devices:
                device_id = device.get("id")
                if device_id and device_id not in seen_device_ids:
                    seen_device_ids.add(device_id)
                    device["relationship"] = "Owned"
                    combined_devices.append(device)
                elif device_id in seen_device_ids:
                    # Update existing to show both relationships
                    for d in combined_devices:
                        if d.get("id") == device_id:
                            d["relationship"] = "Registered & Owned"
            
            for device in combined_devices:
                trust_type = device.get("trustType", "Unknown")
                ownership = device.get("deviceOwnership", "Unknown")
                is_byod = ownership == "Personal" or trust_type == "Workplace"
                is_compliant = device.get("isCompliant")
                is_managed = device.get("isManaged", False)
                
                # Risk assessment
                risk_level = "LOW"
                risk_factors = []
                
                if is_compliant == False:
                    risk_level = "HIGH"
                    risk_factors.append("Non-compliant")
                elif is_compliant is None:
                    risk_level = "MEDIUM"
                    risk_factors.append("Unknown compliance")
                
                if not is_managed:
                    if risk_level == "LOW":
                        risk_level = "MEDIUM"
                    risk_factors.append("Unmanaged")
                
                if is_byod:
                    if risk_level == "LOW":
                        risk_level = "MEDIUM"
                    risk_factors.append("BYOD")
                
                user_devices.append({
                    "userId": uid,
                    "userName": user_name,
                    "userPrincipalName": user_upn,
                    "deviceId": device.get("id", ""),
                    "deviceName": device.get("displayName", ""),
                    "operatingSystem": device.get("operatingSystem", ""),
                    "trustType": trust_type,
                    "isCompliant": is_compliant,
                    "isManaged": is_managed,
                    "deviceOwnership": ownership,
                    "isBYOD": is_byod,
                    "relationship": device.get("relationship", ""),
                    "riskLevel": risk_level,
                    "riskFactors": ", ".join(risk_factors) if risk_factors else "None",
                })
            
            # Progress indicator
            if (i + 1) % 100 == 0:
                print(f"    Processed {i + 1}/{len(all_users)} users...")
        
        if user_devices:
            unique_users = len(set(d.get("userId") for d in user_devices))
            unique_devices = len(set(d.get("deviceId") for d in user_devices))
            byod_devices = sum(1 for d in user_devices if d.get("isBYOD"))
            non_compliant = sum(1 for d in user_devices if d.get("isCompliant") == False)
            
            print(f"[+] Found {unique_devices} devices across {unique_users} users")
            print(f"    - BYOD devices: {byod_devices}")
            print(f"    - Non-compliant: {non_compliant}")
    
    return user_devices


def get_non_compliant_devices(access_token: str) -> list:
    """
    Find all non-compliant devices - security risk focus.
    """
    print("[*] Enumerating non-compliant devices...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    non_compliant_devices = []
    
    # Try filtering for non-compliant devices
    url = f"{GRAPH_API_ENDPOINT}/devices?$filter=isCompliant eq false&$select=id,displayName,deviceId,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,managementType,deviceOwnership,approximateLastSignInDateTime,manufacturer,model&$top=999"
    
    while url:
        try:
            response = make_api_request(url, headers)
            
            if response and response.status_code == 200:
                data = response.json()
                devices = data.get("value", [])
                
                for device in devices:
                    trust_type = device.get("trustType", "Unknown")
                    ownership = device.get("deviceOwnership", "Unknown")
                    is_byod = ownership == "Personal" or trust_type == "Workplace"
                    
                    non_compliant_devices.append({
                        "id": device.get("id", ""),
                        "deviceId": device.get("deviceId", ""),
                        "displayName": device.get("displayName", ""),
                        "operatingSystem": device.get("operatingSystem", ""),
                        "osVersion": device.get("operatingSystemVersion", ""),
                        "trustType": trust_type,
                        "isManaged": device.get("isManaged", False),
                        "managementType": device.get("managementType", ""),
                        "deviceOwnership": ownership,
                        "isBYOD": is_byod,
                        "lastSignIn": str(device.get("approximateLastSignInDateTime", ""))[:10],
                        "manufacturer": device.get("manufacturer", ""),
                        "model": device.get("model", ""),
                        "riskLevel": "HIGH",
                        "riskReason": "Device is non-compliant",
                    })
                
                url = data.get("@odata.nextLink")
            elif response and response.status_code == 400:
                # Filter not supported, fall back to getting all and filtering
                print("    Filter not supported, fetching all devices...")
                all_devices = get_all_devices(access_token)
                non_compliant_devices = [d for d in all_devices if d.get("isCompliant") == False]
                break
            else:
                if response:
                    print(f"[!] Non-compliant devices: {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    if non_compliant_devices:
        print(f"[+] Found {len(non_compliant_devices)} non-compliant devices (HIGH RISK)")
        
        # Group by OS
        os_counts = {}
        for d in non_compliant_devices:
            os_name = d.get("operatingSystem", "Unknown")
            os_counts[os_name] = os_counts.get(os_name, 0) + 1
        
        for os_name, count in sorted(os_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"    - {os_name}: {count}")
    else:
        print("[+] No non-compliant devices found")
    
    return non_compliant_devices


def get_byod_devices(access_token: str) -> list:
    """
    Find all BYOD (personal) devices enrolled in the organization.
    These are higher risk as they are not corporate-owned.
    """
    print("[*] Enumerating BYOD/personal devices...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    byod_devices = []
    
    # Try filtering for personal devices
    # Workplace trust type indicates Azure AD Registered (typically BYOD)
    url = f"{GRAPH_API_ENDPOINT}/devices?$filter=trustType eq 'Workplace' or deviceOwnership eq 'Personal'&$select=id,displayName,deviceId,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,managementType,deviceOwnership,registrationDateTime,approximateLastSignInDateTime,manufacturer,model&$top=999"
    
    filter_supported = True
    
    while url:
        try:
            response = make_api_request(url, headers)
            
            if response and response.status_code == 200:
                data = response.json()
                devices = data.get("value", [])
                
                for device in devices:
                    trust_type = device.get("trustType", "Unknown")
                    ownership = device.get("deviceOwnership", "Unknown")
                    is_compliant = device.get("isCompliant")
                    is_managed = device.get("isManaged", False)
                    
                    # Risk assessment for BYOD
                    risk_level = "MEDIUM"  # BYOD is inherently medium risk
                    risk_factors = ["BYOD/Personal device"]
                    
                    if is_compliant == False:
                        risk_level = "HIGH"
                        risk_factors.append("Non-compliant")
                    elif is_compliant is None:
                        risk_factors.append("Unknown compliance")
                    
                    if not is_managed:
                        risk_level = "HIGH"
                        risk_factors.append("Unmanaged")
                    
                    byod_devices.append({
                        "id": device.get("id", ""),
                        "deviceId": device.get("deviceId", ""),
                        "displayName": device.get("displayName", ""),
                        "operatingSystem": device.get("operatingSystem", ""),
                        "osVersion": device.get("operatingSystemVersion", ""),
                        "trustType": trust_type,
                        "isCompliant": is_compliant,
                        "isManaged": is_managed,
                        "managementType": device.get("managementType", ""),
                        "deviceOwnership": ownership,
                        "registrationDateTime": str(device.get("registrationDateTime", ""))[:10],
                        "lastSignIn": str(device.get("approximateLastSignInDateTime", ""))[:10],
                        "manufacturer": device.get("manufacturer", ""),
                        "model": device.get("model", ""),
                        "riskLevel": risk_level,
                        "riskFactors": ", ".join(risk_factors),
                    })
                
                url = data.get("@odata.nextLink")
            elif response and response.status_code == 400:
                # Filter not supported
                print("    Filter not supported, fetching all devices...")
                filter_supported = False
                break
            else:
                if response:
                    print(f"[!] BYOD devices: {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    # If filter wasn't supported, get all and filter locally
    if not filter_supported:
        all_devices = get_all_devices(access_token)
        byod_devices = [d for d in all_devices if d.get("isBYOD")]
    
    if byod_devices:
        compliant = sum(1 for d in byod_devices if d.get("isCompliant") == True)
        non_compliant = sum(1 for d in byod_devices if d.get("isCompliant") == False)
        managed = sum(1 for d in byod_devices if d.get("isManaged"))
        
        print(f"[+] Found {len(byod_devices)} BYOD/personal devices")
        print(f"    - Compliant: {compliant}")
        print(f"    - Non-compliant: {non_compliant}")
        print(f"    - Managed: {managed}")
        print(f"    - Unmanaged: {len(byod_devices) - managed}")
        
        # Group by OS
        os_counts = {}
        for d in byod_devices:
            os_name = d.get("operatingSystem", "Unknown")
            os_counts[os_name] = os_counts.get(os_name, 0) + 1
        
        print("    By Operating System:")
        for os_name, count in sorted(os_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"      - {os_name}: {count}")
    else:
        print("[+] No BYOD/personal devices found")
    
    return byod_devices


def print_devices_report(devices: list, title: str = "DEVICE ENUMERATION REPORT") -> None:
    """Print a formatted device report."""
    print_security_summary(devices, title)
    
    print(f"{'Device Name':<25} {'OS':<15} {'Join Type':<22} {'Compliant':<10} {'Managed':<8} {'BYOD':<6} {'Risk':<8}")
    print("-" * 110)
    
    # Sort by risk level
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_devices = sorted(devices, key=lambda x: risk_order.get(x.get("riskLevel", "LOW"), 3))
    
    for device in sorted_devices[:50]:
        name = (device.get("displayName") or "N/A")[:24]
        os_name = (device.get("operatingSystem") or "N/A")[:14]
        join_type = (device.get("joinType") or device.get("trustType") or "N/A")[:21]
        compliant = "Yes" if device.get("isCompliant") == True else ("No" if device.get("isCompliant") == False else "N/A")
        managed = "Yes" if device.get("isManaged") else "No"
        byod = "Yes" if device.get("isBYOD") else "No"
        risk = device.get("riskLevel", "")
        
        print(f"{name:<25} {os_name:<15} {join_type:<22} {compliant:<10} {managed:<8} {byod:<6} {risk:<8}")
    
    if len(devices) > 50:
        print(f"    ... and {len(devices) - 50} more devices")
    
    print("-" * 110)


def print_user_devices_report(user_devices: list) -> None:
    """Print a report of devices per user."""
    print_security_summary(user_devices, "USER DEVICE ASSOCIATIONS")
    
    print(f"{'User':<30} {'Device Name':<22} {'OS':<12} {'Compliant':<10} {'BYOD':<6} {'Relation':<15} {'Risk':<8}")
    print("-" * 110)
    
    # Sort by risk level
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_devices = sorted(user_devices, key=lambda x: risk_order.get(x.get("riskLevel", "LOW"), 3))
    
    for entry in sorted_devices[:50]:
        user = (entry.get("userName") or entry.get("userPrincipalName") or "N/A")[:29]
        device = (entry.get("deviceName") or "N/A")[:21]
        os_name = (entry.get("operatingSystem") or "N/A")[:11]
        compliant = "Yes" if entry.get("isCompliant") == True else ("No" if entry.get("isCompliant") == False else "N/A")
        byod = "Yes" if entry.get("isBYOD") else "No"
        relation = (entry.get("relationship") or "N/A")[:14]
        risk = entry.get("riskLevel", "")
        
        print(f"{user:<30} {device:<22} {os_name:<12} {compliant:<10} {byod:<6} {relation:<15} {risk:<8}")
    
    if len(user_devices) > 50:
        print(f"    ... and {len(user_devices) - 50} more entries")
    
    print("-" * 110)


# ============================================================================
# INTUNE/ENDPOINT MANAGER ENUMERATION FEATURES
# ============================================================================

def get_intune_managed_devices(access_token: str) -> list:
    """
    Enumerate all Intune managed devices.
    Uses /deviceManagement/managedDevices endpoint.
    Requires DeviceManagementManagedDevices.Read.All permission.
    """
    print("[*] Enumerating Intune managed devices...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    managed_devices = []
    
    # Get all managed devices from Intune
    url = f"{GRAPH_API_ENDPOINT}/deviceManagement/managedDevices?$select=id,deviceName,managedDeviceOwnerType,enrolledDateTime,lastSyncDateTime,operatingSystem,osVersion,complianceState,deviceEnrollmentType,managementAgent,manufacturer,model,serialNumber,userPrincipalName,userDisplayName,emailAddress,azureADRegistered,azureADDeviceId,deviceRegistrationState,isEncrypted,isSupervised,jailBroken,managementState&$top=999"
    
    while url:
        if is_cancelled():
            break
        
        try:
            response = make_api_request(url, headers)
            
            if response and response.status_code == 200:
                data = response.json()
                devices = data.get("value", [])
                
                for device in devices:
                    compliance_state = device.get("complianceState", "unknown")
                    management_agent = device.get("managementAgent", "unknown")
                    owner_type = device.get("managedDeviceOwnerType", "unknown")
                    is_encrypted = device.get("isEncrypted", False)
                    jail_broken = device.get("jailBroken", "unknown")
                    
                    # Risk assessment
                    risk_level = "LOW"
                    risk_factors = []
                    
                    if compliance_state == "noncompliant":
                        risk_level = "HIGH"
                        risk_factors.append("Non-compliant")
                    elif compliance_state in ["unknown", "configManager"]:
                        risk_level = "MEDIUM"
                        risk_factors.append(f"Compliance: {compliance_state}")
                    
                    if not is_encrypted:
                        if risk_level == "LOW":
                            risk_level = "MEDIUM"
                        risk_factors.append("Not encrypted")
                    
                    if jail_broken == "True":
                        risk_level = "CRITICAL"
                        risk_factors.append("Jailbroken/rooted")
                    
                    if owner_type == "personal":
                        if risk_level == "LOW":
                            risk_level = "MEDIUM"
                        risk_factors.append("Personal device (BYOD)")
                    
                    managed_devices.append({
                        "id": device.get("id", ""),
                        "deviceName": device.get("deviceName", ""),
                        "userPrincipalName": device.get("userPrincipalName", ""),
                        "userDisplayName": device.get("userDisplayName", ""),
                        "operatingSystem": device.get("operatingSystem", ""),
                        "osVersion": device.get("osVersion", ""),
                        "complianceState": compliance_state,
                        "managementAgent": management_agent,
                        "ownerType": owner_type,
                        "enrollmentType": device.get("deviceEnrollmentType", ""),
                        "enrolledDateTime": str(device.get("enrolledDateTime", ""))[:10],
                        "lastSyncDateTime": str(device.get("lastSyncDateTime", ""))[:16].replace("T", " "),
                        "manufacturer": device.get("manufacturer", ""),
                        "model": device.get("model", ""),
                        "serialNumber": device.get("serialNumber", ""),
                        "isEncrypted": is_encrypted,
                        "isSupervised": device.get("isSupervised", False),
                        "jailBroken": jail_broken,
                        "azureADRegistered": device.get("azureADRegistered", False),
                        "azureADDeviceId": device.get("azureADDeviceId", ""),
                        "managementState": device.get("managementState", ""),
                        "riskLevel": risk_level,
                        "riskFactors": ", ".join(risk_factors) if risk_factors else "None",
                    })
                
                url = data.get("@odata.nextLink")
            elif response and response.status_code == 403:
                print("[!] Access denied. Requires DeviceManagementManagedDevices.Read.All permission")
                break
            else:
                if response:
                    print(f"[!] Error: HTTP {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    if managed_devices:
        compliant = sum(1 for d in managed_devices if d.get("complianceState") == "compliant")
        non_compliant = sum(1 for d in managed_devices if d.get("complianceState") == "noncompliant")
        personal = sum(1 for d in managed_devices if d.get("ownerType") == "personal")
        corporate = sum(1 for d in managed_devices if d.get("ownerType") == "company")
        encrypted = sum(1 for d in managed_devices if d.get("isEncrypted"))
        
        print(f"[+] Found {len(managed_devices)} Intune managed devices")
        print(f"    - Compliant: {compliant}")
        print(f"    - Non-compliant: {non_compliant}")
        print(f"    - Corporate: {corporate}")
        print(f"    - Personal/BYOD: {personal}")
        print(f"    - Encrypted: {encrypted}")
        
        # Group by OS
        os_counts = {}
        for d in managed_devices:
            os_name = d.get("operatingSystem", "Unknown")
            os_counts[os_name] = os_counts.get(os_name, 0) + 1
        
        print("    By Operating System:")
        for os_name, count in sorted(os_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"      - {os_name}: {count}")
    else:
        print("[!] No Intune managed devices found or access denied")
    
    return managed_devices


def get_intune_compliance_policies(access_token: str) -> list:
    """
    Enumerate all Intune compliance policies.
    Uses /deviceManagement/deviceCompliancePolicies endpoint.
    Requires DeviceManagementConfiguration.Read.All permission.
    """
    print("[*] Enumerating Intune compliance policies...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    policies = []
    
    # Get all compliance policies
    url = f"{GRAPH_API_ENDPOINT}/deviceManagement/deviceCompliancePolicies?$expand=assignments&$top=999"
    
    while url:
        if is_cancelled():
            break
        
        try:
            response = make_api_request(url, headers)
            
            if response and response.status_code == 200:
                data = response.json()
                policy_list = data.get("value", [])
                
                for policy in policy_list:
                    policy_type = policy.get("@odata.type", "").replace("#microsoft.graph.", "")
                    assignments = policy.get("assignments", [])
                    
                    # Analyze assignments
                    target_groups = []
                    include_all = False
                    exclude_groups = []
                    
                    for assignment in assignments:
                        target = assignment.get("target", {})
                        target_type = target.get("@odata.type", "")
                        
                        if "allDevicesAssignmentTarget" in target_type:
                            include_all = True
                            target_groups.append("All Devices")
                        elif "allLicensedUsersAssignmentTarget" in target_type:
                            include_all = True
                            target_groups.append("All Users")
                        elif "groupAssignmentTarget" in target_type:
                            group_id = target.get("groupId", "")
                            target_groups.append(group_id[:8] + "...")
                        elif "exclusionGroupAssignmentTarget" in target_type:
                            group_id = target.get("groupId", "")
                            exclude_groups.append(group_id[:8] + "...")
                    
                    # Risk assessment
                    risk_level = "LOW"
                    risk_factors = []
                    
                    if not assignments:
                        risk_level = "MEDIUM"
                        risk_factors.append("Not assigned")
                    
                    if exclude_groups:
                        if risk_level == "LOW":
                            risk_level = "MEDIUM"
                        risk_factors.append(f"{len(exclude_groups)} exclusions")
                    
                    policies.append({
                        "id": policy.get("id", ""),
                        "displayName": policy.get("displayName", ""),
                        "description": policy.get("description", ""),
                        "policyType": policy_type,
                        "createdDateTime": str(policy.get("createdDateTime", ""))[:10],
                        "lastModifiedDateTime": str(policy.get("lastModifiedDateTime", ""))[:10],
                        "version": policy.get("version", 0),
                        "assignmentCount": len(assignments),
                        "targetGroups": ", ".join(target_groups) if target_groups else "None",
                        "excludeGroups": ", ".join(exclude_groups) if exclude_groups else "None",
                        "includeAllDevicesOrUsers": include_all,
                        "riskLevel": risk_level,
                        "riskFactors": ", ".join(risk_factors) if risk_factors else "None",
                    })
                
                url = data.get("@odata.nextLink")
            elif response and response.status_code == 403:
                print("[!] Access denied. Requires DeviceManagementConfiguration.Read.All permission")
                break
            else:
                if response:
                    print(f"[!] Error: HTTP {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    if policies:
        assigned = sum(1 for p in policies if p.get("assignmentCount", 0) > 0)
        unassigned = len(policies) - assigned
        
        print(f"[+] Found {len(policies)} compliance policies")
        print(f"    - Assigned: {assigned}")
        print(f"    - Unassigned: {unassigned}")
        
        # Group by type
        type_counts = {}
        for p in policies:
            p_type = p.get("policyType", "Unknown")
            type_counts[p_type] = type_counts.get(p_type, 0) + 1
        
        print("    By Platform/Type:")
        for p_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            # Simplify the type name
            simple_type = p_type.replace("DeviceCompliancePolicy", "").replace("CompliancePolicy", "")
            if simple_type:
                print(f"      - {simple_type}: {count}")
    else:
        print("[!] No compliance policies found or access denied")
    
    return policies


def get_intune_configuration_profiles(access_token: str) -> list:
    """
    Enumerate all Intune device configuration profiles.
    Uses /deviceManagement/deviceConfigurations endpoint.
    Requires DeviceManagementConfiguration.Read.All permission.
    """
    print("[*] Enumerating Intune configuration profiles...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    profiles = []
    
    # Get all device configurations
    url = f"{GRAPH_API_ENDPOINT}/deviceManagement/deviceConfigurations?$expand=assignments&$top=999"
    
    while url:
        if is_cancelled():
            break
        
        try:
            response = make_api_request(url, headers)
            
            if response and response.status_code == 200:
                data = response.json()
                config_list = data.get("value", [])
                
                for config in config_list:
                    config_type = config.get("@odata.type", "").replace("#microsoft.graph.", "")
                    assignments = config.get("assignments", [])
                    
                    # Analyze assignments
                    target_groups = []
                    include_all = False
                    exclude_groups = []
                    
                    for assignment in assignments:
                        target = assignment.get("target", {})
                        target_type = target.get("@odata.type", "")
                        
                        if "allDevicesAssignmentTarget" in target_type:
                            include_all = True
                            target_groups.append("All Devices")
                        elif "allLicensedUsersAssignmentTarget" in target_type:
                            include_all = True
                            target_groups.append("All Users")
                        elif "groupAssignmentTarget" in target_type:
                            group_id = target.get("groupId", "")
                            target_groups.append(group_id[:8] + "...")
                        elif "exclusionGroupAssignmentTarget" in target_type:
                            group_id = target.get("groupId", "")
                            exclude_groups.append(group_id[:8] + "...")
                    
                    # Risk assessment
                    risk_level = "LOW"
                    risk_factors = []
                    
                    if not assignments:
                        risk_level = "MEDIUM"
                        risk_factors.append("Not assigned")
                    
                    if exclude_groups:
                        if risk_level == "LOW":
                            risk_level = "MEDIUM"
                        risk_factors.append(f"{len(exclude_groups)} exclusions")
                    
                    profiles.append({
                        "id": config.get("id", ""),
                        "displayName": config.get("displayName", ""),
                        "description": config.get("description", ""),
                        "configType": config_type,
                        "createdDateTime": str(config.get("createdDateTime", ""))[:10],
                        "lastModifiedDateTime": str(config.get("lastModifiedDateTime", ""))[:10],
                        "version": config.get("version", 0),
                        "assignmentCount": len(assignments),
                        "targetGroups": ", ".join(target_groups) if target_groups else "None",
                        "excludeGroups": ", ".join(exclude_groups) if exclude_groups else "None",
                        "includeAllDevicesOrUsers": include_all,
                        "riskLevel": risk_level,
                        "riskFactors": ", ".join(risk_factors) if risk_factors else "None",
                    })
                
                url = data.get("@odata.nextLink")
            elif response and response.status_code == 403:
                print("[!] Access denied. Requires DeviceManagementConfiguration.Read.All permission")
                break
            else:
                if response:
                    print(f"[!] Error: HTTP {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    if profiles:
        assigned = sum(1 for p in profiles if p.get("assignmentCount", 0) > 0)
        unassigned = len(profiles) - assigned
        
        print(f"[+] Found {len(profiles)} configuration profiles")
        print(f"    - Assigned: {assigned}")
        print(f"    - Unassigned: {unassigned}")
        
        # Group by type
        type_counts = {}
        for p in profiles:
            p_type = p.get("configType", "Unknown")
            type_counts[p_type] = type_counts.get(p_type, 0) + 1
        
        print("    By Profile Type:")
        for p_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            # Simplify the type name
            simple_type = p_type.replace("Configuration", "").replace("DeviceConfiguration", "")
            print(f"      - {simple_type}: {count}")
    else:
        print("[!] No configuration profiles found or access denied")
    
    return profiles


def get_intune_device_administrators(access_token: str) -> list:
    """
    Enumerate Intune/Endpoint Manager role assignments (device administrators).
    Uses /deviceManagement/roleAssignments and /deviceManagement/roleDefinitions endpoints.
    Requires DeviceManagementRBAC.Read.All permission.
    """
    print("[*] Enumerating Intune device administrators...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    administrators = []
    role_definitions = {}
    
    # First get role definitions to map role IDs to names
    role_def_url = f"{GRAPH_API_ENDPOINT}/deviceManagement/roleDefinitions"
    
    try:
        response = make_api_request(role_def_url, headers)
        if response and response.status_code == 200:
            roles = response.json().get("value", [])
            for role in roles:
                role_definitions[role.get("id", "")] = {
                    "displayName": role.get("displayName", ""),
                    "description": role.get("description", ""),
                    "isBuiltIn": role.get("isBuiltIn", False),
                    "permissions": role.get("permissions", []),
                }
            print(f"    Found {len(role_definitions)} role definitions")
        elif response and response.status_code == 403:
            print("[!] Access denied. Requires DeviceManagementRBAC.Read.All permission")
            return administrators
    except Exception as e:
        print(f"[!] Error getting role definitions: {e}")
    
    # Get role assignments
    url = f"{GRAPH_API_ENDPOINT}/deviceManagement/roleAssignments?$expand=*&$top=999"
    
    while url:
        if is_cancelled():
            break
        
        try:
            response = make_api_request(url, headers)
            
            if response and response.status_code == 200:
                data = response.json()
                assignments = data.get("value", [])
                
                for assignment in assignments:
                    role_def_id = assignment.get("roleDefinition", {}).get("id", "") or assignment.get("roleDefinitionId", "")
                    role_info = role_definitions.get(role_def_id, {})
                    role_name = role_info.get("displayName", assignment.get("displayName", "Unknown Role"))
                    is_built_in = role_info.get("isBuiltIn", True)
                    
                    # Get scope members (principals assigned to this role)
                    scope_members = assignment.get("scopeMembers", [])
                    members = assignment.get("members", [])
                    resource_scopes = assignment.get("resourceScopes", [])
                    
                    # Risk assessment
                    risk_level = "MEDIUM"
                    risk_factors = []
                    
                    # High-privilege roles
                    high_priv_roles = [
                        "Intune Administrator", "Intune Role Administrator",
                        "Endpoint Security Manager", "Policy and Profile Manager",
                        "Help Desk Operator", "Application Manager"
                    ]
                    
                    if any(r.lower() in role_name.lower() for r in high_priv_roles):
                        risk_level = "HIGH"
                        risk_factors.append("High-privilege role")
                    
                    if not is_built_in:
                        risk_factors.append("Custom role")
                    
                    # Check scope
                    scope_type = "All Devices"
                    if resource_scopes:
                        scope_type = f"{len(resource_scopes)} scope tags"
                        risk_factors.append("Scoped access")
                    
                    administrators.append({
                        "id": assignment.get("id", ""),
                        "displayName": assignment.get("displayName", ""),
                        "description": assignment.get("description", ""),
                        "roleName": role_name,
                        "roleDefinitionId": role_def_id,
                        "isBuiltIn": is_built_in,
                        "scopeType": scope_type,
                        "memberCount": len(members) if members else len(scope_members),
                        "members": [m.get("id", "") for m in (members or scope_members)][:5],  # First 5 member IDs
                        "resourceScopes": [r.get("displayName", r.get("id", "")) for r in resource_scopes] if resource_scopes else ["All"],
                        "riskLevel": risk_level,
                        "riskFactors": ", ".join(risk_factors) if risk_factors else "None",
                    })
                
                url = data.get("@odata.nextLink")
            elif response and response.status_code == 403:
                print("[!] Access denied. Requires DeviceManagementRBAC.Read.All permission")
                break
            else:
                if response:
                    print(f"[!] Error: HTTP {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    if administrators:
        built_in = sum(1 for a in administrators if a.get("isBuiltIn"))
        custom = len(administrators) - built_in
        high_risk = sum(1 for a in administrators if a.get("riskLevel") == "HIGH")
        
        print(f"[+] Found {len(administrators)} Intune role assignments")
        print(f"    - Built-in roles: {built_in}")
        print(f"    - Custom roles: {custom}")
        print(f"    - High-privilege: {high_risk}")
        
        # Group by role name
        role_counts = {}
        for a in administrators:
            role = a.get("roleName", "Unknown")
            role_counts[role] = role_counts.get(role, 0) + 1
        
        print("    By Role:")
        for role, count in sorted(role_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"      - {role}: {count}")
    else:
        print("[!] No Intune role assignments found or access denied")
    
    return administrators


def print_intune_devices_report(devices: list) -> None:
    """Print Intune managed devices report."""
    print_security_summary(devices, "INTUNE MANAGED DEVICES")
    
    print(f"{'Device Name':<22} {'User':<25} {'OS':<12} {'Compliance':<12} {'Owner':<10} {'Encrypted':<10} {'Risk':<8}")
    print("-" * 110)
    
    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_devices = sorted(devices, key=lambda x: risk_order.get(x.get("riskLevel", "LOW"), 3))
    
    for device in sorted_devices[:50]:
        name = (device.get("deviceName") or "N/A")[:21]
        user = (device.get("userPrincipalName") or "N/A")[:24]
        os_name = (device.get("operatingSystem") or "N/A")[:11]
        compliance = (device.get("complianceState") or "N/A")[:11]
        owner = (device.get("ownerType") or "N/A")[:9]
        encrypted = "Yes" if device.get("isEncrypted") else "No"
        risk = device.get("riskLevel", "")
        
        print(f"{name:<22} {user:<25} {os_name:<12} {compliance:<12} {owner:<10} {encrypted:<10} {risk:<8}")
    
    if len(devices) > 50:
        print(f"    ... and {len(devices) - 50} more devices")
    
    print("-" * 110)


def print_intune_policies_report(policies: list, title: str = "INTUNE COMPLIANCE POLICIES") -> None:
    """Print Intune policies report."""
    print_security_summary(policies, title)
    
    print(f"{'Policy Name':<40} {'Type':<25} {'Assigned':<10} {'Targets':<15} {'Exclusions':<12} {'Risk':<8}")
    print("-" * 120)
    
    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_policies = sorted(policies, key=lambda x: risk_order.get(x.get("riskLevel", "LOW"), 3))
    
    for policy in sorted_policies[:50]:
        name = (policy.get("displayName") or "N/A")[:39]
        p_type = (policy.get("policyType") or policy.get("configType") or "N/A")
        # Simplify type name
        p_type = p_type.replace("DeviceCompliancePolicy", "").replace("DeviceConfiguration", "").replace("Configuration", "")[:24]
        assigned = str(policy.get("assignmentCount", 0))
        targets = (policy.get("targetGroups") or "None")[:14]
        exclusions = (policy.get("excludeGroups") or "None")[:11]
        risk = policy.get("riskLevel", "")
        
        print(f"{name:<40} {p_type:<25} {assigned:<10} {targets:<15} {exclusions:<12} {risk:<8}")
    
    if len(policies) > 50:
        print(f"    ... and {len(policies) - 50} more policies")
    
    print("-" * 120)


def print_intune_administrators_report(administrators: list) -> None:
    """Print Intune device administrators report."""
    print_security_summary(administrators, "INTUNE DEVICE ADMINISTRATORS")
    
    print(f"{'Assignment Name':<30} {'Role':<30} {'Members':<10} {'Scope':<20} {'Risk':<8}")
    print("-" * 110)
    
    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_admins = sorted(administrators, key=lambda x: risk_order.get(x.get("riskLevel", "LOW"), 3))
    
    for admin in sorted_admins[:50]:
        name = (admin.get("displayName") or "N/A")[:29]
        role = (admin.get("roleName") or "N/A")[:29]
        members = str(admin.get("memberCount", 0))
        scope = (", ".join(admin.get("resourceScopes", ["All"])) or "All")[:19]
        risk = admin.get("riskLevel", "")
        
        print(f"{name:<30} {role:<30} {members:<10} {scope:<20} {risk:<8}")
    
    if len(administrators) > 50:
        print(f"    ... and {len(administrators) - 50} more assignments")
    
    print("-" * 110)


# ============================================================================
# ADMINISTRATIVE UNIT ENUMERATION FEATURES
# ============================================================================

def get_administrative_units(access_token: str) -> list:
    """
    Enumerate all Administrative Units in Azure AD/Entra ID.
    Returns comprehensive AU information including members and scoped admins.
    """
    print("[*] Enumerating Administrative Units...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    admin_units = []
    
    # Get all administrative units
    url = f"{GRAPH_API_ENDPOINT}/directory/administrativeUnits?$select=id,displayName,description,visibility,membershipType,membershipRule,membershipRuleProcessingState&$top=999"
    
    while url:
        if is_cancelled():
            break
            
        try:
            response = make_api_request(url, headers)
            
            if response and response.status_code == 200:
                data = response.json()
                aus = data.get("value", [])
                
                for au in aus:
                    au_id = au.get("id", "")
                    
                    # Get member count
                    member_count = 0
                    members_url = f"{GRAPH_API_ENDPOINT}/directory/administrativeUnits/{au_id}/members/$count"
                    try:
                        count_headers = headers.copy()
                        count_headers["ConsistencyLevel"] = "eventual"
                        count_response = make_api_request(members_url, count_headers)
                        if count_response and count_response.status_code == 200:
                            member_count = int(count_response.text)
                    except:
                        pass
                    
                    # Determine membership type
                    membership_type = au.get("membershipType", "Assigned")
                    is_dynamic = membership_type == "Dynamic"
                    
                    # Determine visibility
                    visibility = au.get("visibility", "Public")
                    is_hidden = visibility == "HiddenMembership"
                    
                    # Risk assessment
                    risk_level = "LOW"
                    risk_factors = []
                    
                    if is_hidden:
                        risk_level = "MEDIUM"
                        risk_factors.append("Hidden membership")
                    
                    if is_dynamic:
                        risk_factors.append("Dynamic membership")
                    
                    admin_units.append({
                        "id": au_id,
                        "displayName": au.get("displayName", ""),
                        "description": au.get("description", ""),
                        "visibility": visibility,
                        "membershipType": membership_type,
                        "membershipRule": au.get("membershipRule", ""),
                        "membershipRuleProcessingState": au.get("membershipRuleProcessingState", ""),
                        "memberCount": member_count,
                        "isHidden": is_hidden,
                        "isDynamic": is_dynamic,
                        "riskLevel": risk_level,
                        "riskFactors": ", ".join(risk_factors) if risk_factors else "None",
                    })
                
                url = data.get("@odata.nextLink")
            elif response and response.status_code == 403:
                print("[!] Access denied. Requires AdministrativeUnit.Read.All permission")
                break
            else:
                if response:
                    print(f"[!] Administrative Units: {response.status_code}")
                break
        except Exception as e:
            print(f"[!] Error enumerating Administrative Units: {e}")
            break
    
    if admin_units:
        hidden_count = sum(1 for au in admin_units if au.get("isHidden"))
        dynamic_count = sum(1 for au in admin_units if au.get("isDynamic"))
        total_members = sum(au.get("memberCount", 0) for au in admin_units)
        
        print(f"[+] Found {len(admin_units)} Administrative Units")
        print(f"    - Total members across all AUs: {total_members}")
        print(f"    - Hidden membership AUs: {hidden_count}")
        print(f"    - Dynamic membership AUs: {dynamic_count}")
    else:
        print("[!] No Administrative Units found or access denied")
    
    return admin_units


def get_admin_unit_members(access_token: str, admin_unit_id: str = None) -> list:
    """
    Get members of Administrative Units.
    If admin_unit_id is None, retrieves members for all AUs.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    all_members = []
    
    # Get all AUs if not specified
    if admin_unit_id:
        au_ids = [{"id": admin_unit_id, "displayName": "Specified AU"}]
    else:
        print("[*] Retrieving members from all Administrative Units...")
        aus = get_administrative_units(access_token)
        au_ids = [{"id": au["id"], "displayName": au["displayName"]} for au in aus]
    
    for au in au_ids:
        if is_cancelled():
            break
            
        au_id = au["id"]
        au_name = au["displayName"]
        
        url = f"{GRAPH_API_ENDPOINT}/directory/administrativeUnits/{au_id}/members?$select=id,displayName,userPrincipalName,mail,userType,accountEnabled&$top=999"
        
        while url:
            if is_cancelled():
                break
                
            try:
                response = make_api_request(url, headers)
                
                if response and response.status_code == 200:
                    data = response.json()
                    members = data.get("value", [])
                    
                    for member in members:
                        member_type = member.get("@odata.type", "").replace("#microsoft.graph.", "")
                        
                        all_members.append({
                            "adminUnitId": au_id,
                            "adminUnitName": au_name,
                            "memberId": member.get("id", ""),
                            "displayName": member.get("displayName", ""),
                            "userPrincipalName": member.get("userPrincipalName", ""),
                            "mail": member.get("mail", ""),
                            "memberType": member_type,
                            "userType": member.get("userType", ""),
                            "accountEnabled": member.get("accountEnabled", True),
                        })
                    
                    url = data.get("@odata.nextLink")
                else:
                    break
            except Exception as e:
                print(f"    [!] Error getting members for AU {au_name}: {e}")
                break
    
    if all_members:
        # Group by AU
        au_member_counts = {}
        for m in all_members:
            au_name = m.get("adminUnitName", "Unknown")
            au_member_counts[au_name] = au_member_counts.get(au_name, 0) + 1
        
        users = sum(1 for m in all_members if m.get("memberType") == "user")
        groups = sum(1 for m in all_members if m.get("memberType") == "group")
        devices = sum(1 for m in all_members if m.get("memberType") == "device")
        
        print(f"[+] Found {len(all_members)} total members across AUs")
        print(f"    - Users: {users}")
        print(f"    - Groups: {groups}")
        print(f"    - Devices: {devices}")
    
    return all_members


def get_scoped_role_assignments(access_token: str) -> list:
    """
    Get scoped role assignments for Administrative Units.
    Identifies who has admin privileges scoped to specific AUs.
    """
    print("[*] Enumerating Scoped Role Assignments (AU Administrators)...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    scoped_admins = []
    
    # Get all administrative units first
    aus = get_administrative_units(access_token)
    
    if not aus:
        return scoped_admins
    
    print(f"    Checking scoped role assignments for {len(aus)} AUs...")
    
    for au in aus:
        if is_cancelled():
            break
            
        au_id = au["id"]
        au_name = au["displayName"]
        
        # Get scoped role members for this AU
        url = f"{GRAPH_API_ENDPOINT}/directory/administrativeUnits/{au_id}/scopedRoleMembers?$expand=roleDefinition"
        
        try:
            response = make_api_request(url, headers)
            
            if response and response.status_code == 200:
                data = response.json()
                scoped_members = data.get("value", [])
                
                for member in scoped_members:
                    role_info = member.get("roleDefinition", {})
                    role_name = role_info.get("displayName", "Unknown Role")
                    role_id = member.get("roleDefinitionId", "")
                    
                    # Get the principal (admin) details
                    principal_id = member.get("roleMemberInfo", {}).get("id", "")
                    principal_name = member.get("roleMemberInfo", {}).get("displayName", "")
                    
                    # Try to get more details about the principal
                    principal_type = "Unknown"
                    principal_upn = ""
                    if principal_id:
                        try:
                            user_url = f"{GRAPH_API_ENDPOINT}/users/{principal_id}?$select=userPrincipalName,userType"
                            user_response = make_api_request(user_url, headers)
                            if user_response and user_response.status_code == 200:
                                user_data = user_response.json()
                                principal_upn = user_data.get("userPrincipalName", "")
                                principal_type = "User"
                        except:
                            # Might be a group or service principal
                            try:
                                group_url = f"{GRAPH_API_ENDPOINT}/groups/{principal_id}?$select=displayName"
                                group_response = make_api_request(group_url, headers)
                                if group_response and group_response.status_code == 200:
                                    principal_type = "Group"
                            except:
                                pass
                    
                    # Risk assessment based on role
                    risk_level = "MEDIUM"  # Scoped admins are generally medium risk
                    risk_factors = ["Scoped admin privileges"]
                    
                    # Check for sensitive roles
                    sensitive_roles = [
                        "User Administrator",
                        "Groups Administrator", 
                        "Authentication Administrator",
                        "Password Administrator",
                        "Privileged Authentication Administrator",
                        "Helpdesk Administrator"
                    ]
                    
                    if any(role in role_name for role in sensitive_roles):
                        risk_level = "HIGH"
                        risk_factors.append(f"Sensitive role: {role_name}")
                    
                    scoped_admins.append({
                        "adminUnitId": au_id,
                        "adminUnitName": au_name,
                        "adminUnitHidden": au.get("isHidden", False),
                        "roleDefinitionId": role_id,
                        "roleName": role_name,
                        "principalId": principal_id,
                        "principalName": principal_name,
                        "principalType": principal_type,
                        "principalUPN": principal_upn,
                        "riskLevel": risk_level,
                        "riskFactors": ", ".join(risk_factors),
                    })
                    
        except Exception as e:
            # Silently skip - might not have access to all AUs
            pass
    
    if scoped_admins:
        # Summarize findings
        unique_admins = len(set(a.get("principalId") for a in scoped_admins))
        unique_roles = len(set(a.get("roleName") for a in scoped_admins))
        high_risk = sum(1 for a in scoped_admins if a.get("riskLevel") == "HIGH")
        
        print(f"[+] Found {len(scoped_admins)} scoped role assignments")
        print(f"    - Unique administrators: {unique_admins}")
        print(f"    - Unique roles assigned: {unique_roles}")
        print(f"    - HIGH risk assignments: {high_risk}")
        
        # Show role distribution
        role_counts = {}
        for a in scoped_admins:
            role = a.get("roleName", "Unknown")
            role_counts[role] = role_counts.get(role, 0) + 1
        
        print("    Role Distribution:")
        for role, count in sorted(role_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"      - {role}: {count}")
    else:
        print("[+] No scoped role assignments found or access denied")
    
    return scoped_admins


# ============================================================================
# LICENSE ENUMERATION FEATURES
# ============================================================================

# Microsoft 365 and Azure AD SKU mappings for common licenses
LICENSE_SKU_MAP = {
    # =========================
    # Azure AD / Entra ID Premium (P2 / P1)
    # =========================
    "AAD_PREMIUM": {"name": "Microsoft Entra ID P1 (Azure AD Premium P1)", "tier": "P1", "privilegeLevel": "MEDIUM"},
    "AAD_PREMIUM_P2": {"name": "Microsoft Entra ID P2 (Azure AD Premium P2)", "tier": "P2", "privilegeLevel": "HIGH"},
    "AAD_PREMIUM_P2_DOD": {"name": "Azure AD Premium P2 (DoD)", "tier": "P2", "privilegeLevel": "HIGH"},
    "AAD_PREMIUM_P2_GOV": {"name": "Azure AD Premium P2 (Gov)", "tier": "P2", "privilegeLevel": "HIGH"},

    # =========================
    # Microsoft 365 E5 (all variants)
    # =========================
    "M365_E5": {"name": "Microsoft 365 E5", "tier": "E5", "privilegeLevel": "HIGH"},
    "MICROSOFT365_E5": {"name": "Microsoft 365 E5", "tier": "E5", "privilegeLevel": "HIGH"},
    "SPE_E5": {"name": "Microsoft 365 E5", "tier": "E5", "privilegeLevel": "HIGH"},
    "SPE_E5_CALLINGCONF": {"name": "Microsoft 365 E5 with Calling Minutes", "tier": "E5", "privilegeLevel": "HIGH"},
    "SPE_E5_NOPSTNCONF": {"name": "Microsoft 365 E5 (without Audio Conferencing)", "tier": "E5", "privilegeLevel": "HIGH"},
    "SPE_E5_SLK": {"name": "Microsoft 365 E5 (without Windows)", "tier": "E5", "privilegeLevel": "HIGH"},

    # =========================
    # Microsoft 365 E5 Academic / A5 (E5 equivalent)
    # =========================
    "M365_A5": {"name": "Microsoft 365 A5", "tier": "E5", "privilegeLevel": "HIGH"},
    "SPE_E5_STUDENT": {"name": "Microsoft 365 A5 (Student)", "tier": "E5", "privilegeLevel": "HIGH"},
    "SPE_E5_FACULTY": {"name": "Microsoft 365 A5 (Faculty)", "tier": "E5", "privilegeLevel": "HIGH"},

    # =========================
    # Office 365 E5 (and A5 equivalent)
    # =========================
    "ENTERPRISEPREMIUM": {"name": "Office 365 E5", "tier": "E5", "privilegeLevel": "HIGH"},
    "ENTERPRISEPREMIUM_NOPSTNCONF": {"name": "Office 365 E5 (without Audio Conferencing)", "tier": "E5", "privilegeLevel": "HIGH"},
    "ENTERPRISEPREMIUM_GOV": {"name": "Office 365 E5 (Government)", "tier": "E5", "privilegeLevel": "HIGH"},
    "ENTERPRISEPREMIUM_FACULTY": {"name": "Office 365 A5 (Faculty)", "tier": "E5", "privilegeLevel": "HIGH"},
    "ENTERPRISEPREMIUM_STUDENT": {"name": "Office 365 A5 (Student)", "tier": "E5", "privilegeLevel": "HIGH"},
    "OFFICE365_E5": {"name": "Office 365 E5", "tier": "E5", "privilegeLevel": "HIGH"},
    "O365_E5": {"name": "Office 365 E5", "tier": "E5", "privilegeLevel": "HIGH"},

    # =========================
    # E5 Security & Compliance Add-ons
    # =========================
    "M365_E5_SECURITY": {"name": "Microsoft 365 E5 Security", "tier": "E5SEC", "privilegeLevel": "HIGH"},
    "IDENTITY_THREAT_PROTECTION": {"name": "Microsoft 365 E5 Security", "tier": "E5SEC", "privilegeLevel": "HIGH"},
    "M365_E5_COMPLIANCE": {"name": "Microsoft 365 E5 Compliance", "tier": "E5COMP", "privilegeLevel": "HIGH"},
    "INFORMATION_PROTECTION_COMPLIANCE": {"name": "Microsoft 365 E5 Compliance", "tier": "E5COMP", "privilegeLevel": "HIGH"},
    "COMMUNICATION_COMPLIANCE": {"name": "Communication Compliance (E5)", "tier": "E5COMP", "privilegeLevel": "HIGH"},
    "E_DISCOVERY_PREMIUM": {"name": "Advanced eDiscovery (E5)", "tier": "E5COMP", "privilegeLevel": "HIGH"},
    "RECORDS_MANAGEMENT_E5": {"name": "Records Management (E5)", "tier": "E5COMP", "privilegeLevel": "HIGH"},

    # =========================
    # EMS / Security (E5-level)
    # =========================
    "EMS_E5": {"name": "Enterprise Mobility + Security E5", "tier": "P2", "privilegeLevel": "HIGH"},
    "EMSPREMIUM": {"name": "Enterprise Mobility + Security E5", "tier": "P2", "privilegeLevel": "HIGH"},
    "EMS_E5_GOV": {"name": "Enterprise Mobility + Security E5 (Gov)", "tier": "P2", "privilegeLevel": "HIGH"},
    "EMS_E5_GCCHIGH": {"name": "Enterprise Mobility + Security E5 (GCC High)", "tier": "P2", "privilegeLevel": "HIGH"},

    # EMS E3 (P1-level)
    "EMS_E3": {"name": "Enterprise Mobility + Security E3", "tier": "P1", "privilegeLevel": "MEDIUM"},
    "EMSPREMIUM_GOV": {"name": "Enterprise Mobility + Security E3 (Gov)", "tier": "P1", "privilegeLevel": "MEDIUM"},

    # =========================
    # Defender (E5-level components)
    # =========================
    "MDE_PLAN2": {"name": "Defender for Endpoint Plan 2", "tier": "MDE2", "privilegeLevel": "HIGH"},
    "MDATP_XPLAT": {"name": "Microsoft Defender for Endpoint", "tier": "MDE", "privilegeLevel": "HIGH"},
    "MDO_PLAN2": {"name": "Defender for Office 365 Plan 2", "tier": "MDO2", "privilegeLevel": "HIGH"},
    "THREAT_INTELLIGENCE": {"name": "Defender for Office 365 Plan 2", "tier": "MDO2", "privilegeLevel": "HIGH"},
    "MCAS": {"name": "Defender for Cloud Apps", "tier": "P2", "privilegeLevel": "HIGH"},
    "M365_DEFENDER": {"name": "Microsoft 365 Defender (XDR)", "tier": "E5SEC", "privilegeLevel": "HIGH"},

    # =========================
    # Microsoft 365 E3 / Office 365 E3
    # =========================
    "SPE_E3": {"name": "Microsoft 365 E3", "tier": "E3", "privilegeLevel": "MEDIUM"},
    "ENTERPRISEPACK": {"name": "Office 365 E3", "tier": "E3", "privilegeLevel": "MEDIUM"},
    "ENTERPRISEPACK_USGOV_DOD": {"name": "Office 365 E3 (DoD)", "tier": "E3", "privilegeLevel": "MEDIUM"},
    "ENTERPRISEPACK_USGOV_GCCHIGH": {"name": "Office 365 E3 (GCC High)", "tier": "E3", "privilegeLevel": "MEDIUM"},

    # =========================
    # Frontline / Entry SKUs (Non-E5)
    # =========================
    "STANDARDPACK": {"name": "Office 365 E1", "tier": "E1", "privilegeLevel": "LOW"},
    "DESKLESSPACK": {"name": "Office 365 F3", "tier": "F3", "privilegeLevel": "LOW"},
    "M365_F1": {"name": "Microsoft 365 F1", "tier": "F1", "privilegeLevel": "LOW"},

    # =========================
    # Business SKUs
    # =========================
    "SPB": {"name": "Microsoft 365 Business Premium", "tier": "BP", "privilegeLevel": "MEDIUM"},
    "O365_BUSINESS_PREMIUM": {"name": "Microsoft 365 Business Standard", "tier": "BS", "privilegeLevel": "LOW"},

    # =========================
    # Developer
    # =========================
    "DEVELOPERPACK_E5": {"name": "Microsoft 365 E5 Developer", "tier": "E5", "privilegeLevel": "HIGH"},
    "DEVELOPERPACK": {"name": "Office 365 E3 Developer", "tier": "E3", "privilegeLevel": "MEDIUM"},

    # =========================
    # Information Protection
    # =========================
    "AIP_P1": {"name": "Azure Information Protection P1", "tier": "AIPP1", "privilegeLevel": "MEDIUM"},
    "AIP_P2": {"name": "Azure Information Protection P2", "tier": "AIPP2", "privilegeLevel": "HIGH"},

    # =========================
    # Power BI
    # =========================
    "POWER_BI_PRO": {"name": "Power BI Pro", "tier": "PBI", "privilegeLevel": "LOW"},
    "POWER_BI_PREMIUM": {"name": "Power BI Premium (Per User)", "tier": "PBIP", "privilegeLevel": "MEDIUM"},

    # =========================
    # Intune
    # =========================
    "INTUNE_A": {"name": "Microsoft Intune", "tier": "INTUNE", "privilegeLevel": "MEDIUM"},
    "INTUNE_P2": {"name": "Microsoft Intune Plan 2", "tier": "INTUNE2", "privilegeLevel": "HIGH"},
    "Microsoft_Intune_Suite": {"name": "Microsoft Intune Suite", "tier": "INTUNE_SUITE", "privilegeLevel": "HIGH"},

    # =========================
    # Microsoft 365 Business / EEA (no Teams)
    # =========================
    "Office_365_w/o_Teams_Bundle_Business_Premium": {"name": "Microsoft 365 Business Premium EEA (no Teams)", "tier": "BP_EEA", "privilegeLevel": "MEDIUM"},
    "O365_w/o_Teams_Bundle_M5": {"name": "Microsoft 365 E5 EEA (no Teams)", "tier": "E5_EEA", "privilegeLevel": "HIGH"},
    "O365_BUSINESS_ESSENTIALS": {"name": "Microsoft 365 Business Basic", "tier": "BB", "privilegeLevel": "LOW"},

    # =========================
    # Microsoft Teams (EEA / Essentials)
    # =========================
    "Microsoft_Teams_EEA_New": {"name": "Microsoft Teams EEA", "tier": "TEAMS_EEA", "privilegeLevel": "LOW"},
    "Teams_Ess": {"name": "Microsoft Teams Essentials", "tier": "TEAMS_ESS", "privilegeLevel": "LOW"},
    "TEAMS_ESSENTIALS_AAD": {"name": "Microsoft Teams Essentials (AAD Identity)", "tier": "TEAMS_ESS", "privilegeLevel": "LOW"},

    # =========================
    # Power Platform (Power Automate / Power Apps)
    # =========================
    "FLOW_FREE": {"name": "Microsoft Power Automate Free", "tier": "FLOW_FREE", "privilegeLevel": "LOW"},
    "POWERAUTOMATE_ATTENDED_RPA": {"name": "Power Automate Premium", "tier": "PA_PREMIUM", "privilegeLevel": "MEDIUM"},
    "POWERAPPS_DEV": {"name": "Microsoft Power Apps for Developer", "tier": "PA_DEV", "privilegeLevel": "LOW"},
    "POWERAPPS_VIRAL": {"name": "Microsoft Power Apps Plan 2 Trial", "tier": "PA_TRIAL", "privilegeLevel": "LOW"},

    # =========================
    # Power BI / Microsoft Fabric
    # =========================
    "POWER_BI_STANDARD": {"name": "Microsoft Fabric (Free)", "tier": "PBI_FREE", "privilegeLevel": "LOW"},
    "PBI_PREMIUM_PER_USER": {"name": "Power BI Premium Per User", "tier": "PBI_PPU", "privilegeLevel": "MEDIUM"},

    # =========================
    # Dynamics 365
    # =========================
    "DYN365_ENTERPRISE_SALES": {"name": "Dynamics 365 Sales Enterprise Edition", "tier": "DYN365_SALES", "privilegeLevel": "MEDIUM"},
    "Dynamics_365_Sales_Field_Service_and_Customer_Service_Partner_Sandbox": {"name": "Dynamics 365 Sales, Field Service and Customer Service Partner Sandbox", "tier": "DYN365_SANDBOX", "privilegeLevel": "LOW"},
    "Dynamics_365_Business_Central_Partner_Sandbox": {"name": "Dynamics 365 Business Central Partner Sandbox", "tier": "DYN365_BC_SANDBOX", "privilegeLevel": "LOW"},
    "Dynamics_365_Operations_Application_Partner_Sandbox": {"name": "Dynamics 365 Operations Application Partner Sandbox", "tier": "DYN365_OPS_SANDBOX", "privilegeLevel": "LOW"},
    "DYN365_BUSCENTRAL_PREMIUM": {"name": "Dynamics 365 Business Central Premium", "tier": "DYN365_BC_PREMIUM", "privilegeLevel": "MEDIUM"},
    "DYN365_ENTERPRISE_TEAM_MEMBERS": {"name": "Dynamics 365 Team Members", "tier": "DYN365_TM", "privilegeLevel": "LOW"},
    "DYN365_FINANCIALS_BUSINESS_SKU": {"name": "Dynamics 365 for Financials Business Edition", "tier": "DYN365_FIN", "privilegeLevel": "MEDIUM"},

    # =========================
    # Defender / Security Standalone
    # =========================
    "ADALLOM_STANDALONE": {"name": "Microsoft Defender for Cloud Apps", "tier": "MDCA", "privilegeLevel": "HIGH"},
    "ATP_ENTERPRISE": {"name": "Microsoft Defender for Endpoint P2", "tier": "MDE_P2", "privilegeLevel": "HIGH"},
    "DEFENDER_ENDPOINT_P2": {"name": "Microsoft Defender for Endpoint P2", "tier": "MDE_P2", "privilegeLevel": "HIGH"},

    # =========================
    # SharePoint Advanced Management
    # =========================
    "SharePoint_advanced_management_plan_1": {"name": "SharePoint Advanced Management Plan 1", "tier": "SPO_ADV", "privilegeLevel": "MEDIUM"},
    "SHAREPOINTENTERPRISE": {"name": "SharePoint Online (Plan 2)", "tier": "SPO_P2", "privilegeLevel": "LOW"},

    # =========================
    # Rights Management
    # =========================
    "RIGHTSMANAGEMENT_ADHOC": {"name": "Rights Management Adhoc", "tier": "RMS_ADHOC", "privilegeLevel": "LOW"},
    "RIGHTSMANAGEMENT": {"name": "Azure Rights Management", "tier": "RMS", "privilegeLevel": "LOW"},

    # =========================
    # Project / Visio / Planner
    # =========================
    "PROJECTPREMIUM": {"name": "Planner and Project Plan 5", "tier": "PROJECT_P5", "privilegeLevel": "LOW"},
    "PROJECTPROFESSIONAL": {"name": "Project Plan 3", "tier": "PROJECT_P3", "privilegeLevel": "LOW"},
    "VISIOCLIENT": {"name": "Visio Online Plan 2", "tier": "VISIO_P2", "privilegeLevel": "LOW"},
    "VISIO_PLAN1": {"name": "Visio Online Plan 1", "tier": "VISIO_P1", "privilegeLevel": "LOW"},

    # =========================
    # Windows 365 Cloud PC
    # =========================
    "CPC_E_8C_32GB_512GB": {"name": "Windows 365 Enterprise (8vCPU/32GB/512GB)", "tier": "W365_ENT", "privilegeLevel": "MEDIUM"},
    "CPC_E_4C_16GB_256GB": {"name": "Windows 365 Enterprise (4vCPU/16GB/256GB)", "tier": "W365_ENT", "privilegeLevel": "MEDIUM"},
    "CPC_E_2C_8GB_128GB": {"name": "Windows 365 Enterprise (2vCPU/8GB/128GB)", "tier": "W365_ENT", "privilegeLevel": "MEDIUM"},
}

# Known Microsoft License SKU GUIDs (for fallback when subscribedSkus API fails)
# These are constant Microsoft GUIDs for common licenses
LICENSE_GUID_MAP = {
    # Microsoft 365 E5
    "06ebc4ee-1bb5-47dd-8120-11324bc54e06": {"name": "Microsoft 365 E5", "tier": "E5", "privilegeLevel": "HIGH"},
    "44575883-256e-4a79-9da4-ebe9acabe2b2": {"name": "Microsoft 365 E5 Developer", "tier": "E5", "privilegeLevel": "HIGH"},
    "66b55226-6b4f-492c-910c-a3b7a3c9d993": {"name": "Microsoft 365 F5 Security + Compliance", "tier": "E5", "privilegeLevel": "HIGH"},
    "a91fc4e0-65e5-4266-aa76-4f020c3f5e5a": {"name": "Microsoft 365 E5 (without Audio Conferencing)", "tier": "E5", "privilegeLevel": "HIGH"},
    # Office 365 E5  
    "c7df2760-2c81-4ef7-b578-5b5392b571df": {"name": "Office 365 E5", "tier": "E5", "privilegeLevel": "HIGH"},
    "26d45bd9-adf1-46cd-a9e1-51e9a5524128": {"name": "Office 365 E5 (without Audio Conferencing)", "tier": "E5", "privilegeLevel": "HIGH"},
    # Microsoft 365 E3
    "05e9a617-0261-4cee-bb44-138d3ef5d965": {"name": "Microsoft 365 E3", "tier": "E3", "privilegeLevel": "MEDIUM"},
    "c2ac2ee4-9bb1-47e4-8541-d689c7e83371": {"name": "Microsoft 365 E3 (500 seats min)_HUB", "tier": "E3", "privilegeLevel": "MEDIUM"},
    # Office 365 E3
    "6fd2c87f-b296-42f0-b197-1e91e994b900": {"name": "Office 365 E3", "tier": "E3", "privilegeLevel": "MEDIUM"},
    # Azure AD Premium P2 / Entra ID P2
    "eec0eb4f-6444-4f95-aba0-50c24d67f998": {"name": "Azure AD Premium P2", "tier": "P2", "privilegeLevel": "HIGH"},
    "84a661c4-e949-4bd2-a560-ed7766fcaf2b": {"name": "Azure AD Premium P2 (Standalone)", "tier": "P2", "privilegeLevel": "HIGH"},
    # EMS E5
    "b05e124f-c7cc-45a0-a6aa-8cf78c946968": {"name": "Enterprise Mobility + Security E5", "tier": "P2", "privilegeLevel": "HIGH"},
    # Azure AD Premium P1 / Entra ID P1
    "078d2b04-f1bd-4111-bbd4-b4b1b354cef4": {"name": "Azure AD Premium P1", "tier": "P1", "privilegeLevel": "MEDIUM"},
    # EMS E3
    "efccb6f7-5641-4e0e-bd10-b4976e1bf68e": {"name": "Enterprise Mobility + Security E3", "tier": "P1", "privilegeLevel": "MEDIUM"},
    # Office 365 E1
    "18181a46-0d4e-45cd-891e-60aabd171b4e": {"name": "Office 365 E1", "tier": "E1", "privilegeLevel": "LOW"},
    
    # Microsoft 365 Business / EEA (no Teams)
    "a3f586b6-8cce-4d9b-99d6-55238397f77a": {"name": "Microsoft 365 Business Premium EEA (no Teams)", "tier": "BP_EEA", "privilegeLevel": "MEDIUM"},
    "3271cf8e-2be5-4a09-a549-70fd05baaa17": {"name": "Microsoft 365 E5 EEA (no Teams)", "tier": "E5_EEA", "privilegeLevel": "HIGH"},
    "3b555118-da6a-4418-894f-7df1e2096870": {"name": "Microsoft 365 Business Basic", "tier": "BB", "privilegeLevel": "LOW"},
    
    # Microsoft Teams (EEA / Essentials)
    "7e74bd05-2c47-404e-829a-ba95c66fe8e5": {"name": "Microsoft Teams EEA", "tier": "TEAMS_EEA", "privilegeLevel": "LOW"},
    "fde42873-30b6-436b-b361-21af5a6b84ae": {"name": "Microsoft Teams Essentials", "tier": "TEAMS_ESS", "privilegeLevel": "LOW"},
    
    # Power Platform (Power Automate / Power Apps)
    "f30db892-07e9-47e9-837c-80727f46fd3d": {"name": "Microsoft Power Automate Free", "tier": "FLOW_FREE", "privilegeLevel": "LOW"},
    "eda1941c-3c4f-4995-b5eb-e85a42175ab9": {"name": "Power Automate Premium", "tier": "PA_PREMIUM", "privilegeLevel": "MEDIUM"},
    "5b631642-bd26-49fe-bd20-1daaa972ef80": {"name": "Microsoft Power Apps for Developer", "tier": "PA_DEV", "privilegeLevel": "LOW"},
    
    # Power BI / Microsoft Fabric
    "a403ebcc-fae0-4ca2-8c8c-7a907fd6c235": {"name": "Microsoft Fabric (Free)", "tier": "PBI_FREE", "privilegeLevel": "LOW"},
    "c1d032e0-5619-4761-9b5c-75b6831e1711": {"name": "Power BI Premium Per User", "tier": "PBI_PPU", "privilegeLevel": "MEDIUM"},
    
    # Dynamics 365
    "1e1a282c-9c54-43a2-9310-98ef728faace": {"name": "Dynamics 365 Sales Enterprise Edition", "tier": "DYN365_SALES", "privilegeLevel": "MEDIUM"},
    "494721b8-1f30-4315-aba6-70ca169358d9": {"name": "Dynamics 365 Sales, Field Service and Customer Service Partner Sandbox", "tier": "DYN365_SANDBOX", "privilegeLevel": "LOW"},
    "ba6d0090-c4a5-44ee-902d-8d21b297b693": {"name": "Dynamics 365 Business Central Partner Sandbox", "tier": "DYN365_BC_SANDBOX", "privilegeLevel": "LOW"},
    "dd3d7238-2392-4177-a46d-753170e95f48": {"name": "Dynamics 365 Operations Application Partner Sandbox", "tier": "DYN365_OPS_SANDBOX", "privilegeLevel": "LOW"},
    "f991cecc-3f91-4cd0-a9a8-bf1c8167e029": {"name": "Dynamics 365 Business Central Premium", "tier": "DYN365_BC_PREMIUM", "privilegeLevel": "MEDIUM"},
    
    # Defender / Security Standalone
    "df845ce7-05f9-4894-b5f2-11bbfbcfd2b6": {"name": "Microsoft Defender for Cloud Apps", "tier": "MDCA", "privilegeLevel": "HIGH"},
    
    # Intune Suite
    "a929cd4d-8672-47c9-8664-159c1f322ba8": {"name": "Microsoft Intune Suite", "tier": "INTUNE_SUITE", "privilegeLevel": "HIGH"},
    
    # SharePoint Advanced Management
    "6ee9b90c-0a7a-46c4-bc96-6698aa3bf8d2": {"name": "SharePoint Advanced Management Plan 1", "tier": "SPO_ADV", "privilegeLevel": "MEDIUM"},
    
    # Rights Management
    "8c4ce438-32a7-4ac5-91a6-e22ae08d9c8b": {"name": "Rights Management Adhoc", "tier": "RMS_ADHOC", "privilegeLevel": "LOW"},
    
    # Project / Visio / Planner
    "09015f9f-377f-4538-bbb5-f75ceb09358a": {"name": "Planner and Project Plan 5", "tier": "PROJECT_P5", "privilegeLevel": "LOW"},
    "c5928f49-12ba-48f7-ada3-0d743a3601d5": {"name": "Visio Online Plan 2", "tier": "VISIO_P2", "privilegeLevel": "LOW"},
    
    # Windows 365 Cloud PC
    "9fb0ba5f-4825-4e84-b239-5167a3a5d4dc": {"name": "Windows 365 Enterprise (8vCPU/32GB/512GB)", "tier": "W365_ENT", "privilegeLevel": "MEDIUM"},
}

# SKUs that indicate high privilege capabilities
HIGH_PRIVILEGE_FEATURES = {
    "E5": [
        "Advanced eDiscovery",
        "Defender for Endpoint",
        "Defender for Identity",
        "Information Protection",
        "Insider Risk Management",
        "Communication Compliance",
        "Advanced Audit",
        "Auto-labeling"
    ],
    "P2": [
        "Privileged Identity Management (PIM)",
        "Identity Protection (risky users/sign-ins)",
        "Access Reviews",
        "Entitlement Management",
        "Identity Governance"
    ],
    "P1": [
        "Conditional Access",
        "MFA (Azure MFA)",
        "Self-Service Password Reset",
        "Group-based licensing",
        "Cloud App Discovery"
    ],
    "E5SEC": [
        "Microsoft 365 Defender",
        "Cloud App Security",
        "Safe Attachments",
        "Safe Links",
        "Threat Investigation"
    ]
}


def get_subscribed_skus(access_token: str) -> list:
    """
    Get all subscribed SKUs (licenses) in the tenant.
    Requires Organization.Read.All or Directory.Read.All permission.
    """
    print("[*] Enumerating Tenant License SKUs...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    tenant_skus = []
    url = f"{GRAPH_API_ENDPOINT}/subscribedSkus?$select=id,skuId,skuPartNumber,appliesTo,capabilityStatus,consumedUnits,prepaidUnits,servicePlans"
    
    try:
        response = make_api_request(url, headers)
        
        if response and response.status_code == 200:
            data = response.json()
            skus = data.get("value", [])
            
            for sku in skus:
                sku_part = sku.get("skuPartNumber", "")
                sku_info = LICENSE_SKU_MAP.get(sku_part, {
                    "name": sku_part,
                    "tier": "Unknown",
                    "privilegeLevel": "LOW"
                })
                
                prepaid = sku.get("prepaidUnits", {})
                enabled_units = prepaid.get("enabled", 0)
                consumed = sku.get("consumedUnits", 0)
                
                # Get service plans
                service_plans = sku.get("servicePlans", [])
                enabled_plans = [sp.get("servicePlanName", "") for sp in service_plans 
                                if sp.get("provisioningStatus") == "Success"]
                
                tenant_skus.append({
                    "skuId": sku.get("skuId", ""),
                    "skuPartNumber": sku_part,
                    "displayName": sku_info["name"],
                    "tier": sku_info["tier"],
                    "privilegeLevel": sku_info["privilegeLevel"],
                    "capabilityStatus": sku.get("capabilityStatus", ""),
                    "enabledUnits": enabled_units,
                    "consumedUnits": consumed,
                    "availableUnits": enabled_units - consumed if enabled_units and consumed else 0,
                    "servicePlanCount": len(service_plans),
                    "enabledServicePlans": ", ".join(enabled_plans[:5]) + ("..." if len(enabled_plans) > 5 else ""),
                })
            
            if tenant_skus:
                high_priv = sum(1 for s in tenant_skus if s["privilegeLevel"] == "HIGH")
                e5_count = sum(1 for s in tenant_skus if s["tier"] == "E5")
                p2_count = sum(1 for s in tenant_skus if s["tier"] == "P2")
                
                print(f"[+] Found {len(tenant_skus)} subscribed SKUs")
                print(f"    - HIGH privilege SKUs: {high_priv}")
                print(f"    - E5 tier SKUs: {e5_count}")
                print(f"    - P2 tier SKUs: {p2_count}")
            else:
                print("[!] No subscribed SKUs found or access denied")
                
        elif response and response.status_code == 403:
            print("[!] Access denied. Requires Organization.Read.All or Directory.Read.All permission")
        else:
            print(f"[!] Error fetching subscribed SKUs: {response.status_code if response else 'No response'}")
    
    except Exception as e:
        print(f"[!] Error: {str(e)}")
    
    return tenant_skus


def get_user_licenses(access_token: str) -> list:
    """
    Enumerate assigned licenses per user.
    Identifies users with E5, P2, and other high-privilege licenses.
    """
    print("[*] Enumerating User License Assignments...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    licensed_users = []
    
    # First get all subscribed SKUs for mapping
    sku_map = {}
    sku_url = f"{GRAPH_API_ENDPOINT}/subscribedSkus?$select=skuId,skuPartNumber"
    try:
        response = make_api_request(sku_url, headers)
        if response and response.status_code == 200:
            for sku in response.json().get("value", []):
                sku_id = sku.get("skuId")
                sku_part = sku.get("skuPartNumber", "")
                sku_map[sku_id] = sku_part
                # Debug: show E5-related SKUs found in tenant
                if sku_part and ("E5" in sku_part.upper() or "ENTERPRISEPREMIUM" in sku_part.upper()):
                    print(f"    [DEBUG] Found E5 SKU: {sku_part} (ID: {sku_id})")
        if sku_map:
            print(f"    Loaded {len(sku_map)} SKU mappings from tenant")
        else:
            print("    [WARN] No SKU mappings loaded, will use GUID fallback")
    except Exception as e:
        print(f"    [WARN] Could not load SKU mappings: {e}")
    
    # Get users with assigned licenses
    url = f"{GRAPH_API_ENDPOINT}/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,assignedLicenses,licenseAssignmentStates&$filter=assignedLicenses/$count ne 0&$count=true&$top=999"
    
    try:
        all_users = []
        headers_count = headers.copy()
        headers_count["ConsistencyLevel"] = "eventual"
        
        while url:
            if is_cancelled():
                break
                
            response = requests.get(url, headers=headers_count)
            
            if response.status_code == 200:
                data = response.json()
                users = data.get("value", [])
                all_users.extend(users)
                url = data.get("@odata.nextLink")
            else:
                # Try without filter
                if "$filter" in url:
                    print("    Trying alternative method (no filter)...")
                    url = f"{GRAPH_API_ENDPOINT}/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,assignedLicenses&$top=999"
                    continue
                break
        
        print(f"    Processing {len(all_users)} users with licenses...")
        
        for user in all_users:
            if is_cancelled():
                break
            
            user_id = user.get("id")
            assigned_licenses = user.get("assignedLicenses", [])
            
            if not assigned_licenses:
                continue
            
            # Parse license assignments
            license_names = []
            license_tiers = set()
            privilege_levels = set()
            high_priv_features = []
            
            for lic in assigned_licenses:
                sku_id = lic.get("skuId", "")
                sku_part = sku_map.get(sku_id, "")
                sku_info = None
                
                # Try to get SKU info from multiple sources
                if sku_part:
                    # First try: exact match in LICENSE_SKU_MAP by part number
                    sku_info = LICENSE_SKU_MAP.get(sku_part)
                    
                    # Second try: pattern-based detection from part number
                    if not sku_info:
                        sku_upper = sku_part.upper()
                        # Detect E5 variants - check various E5 patterns
                        # Patterns: _E5, E5_, ends with E5, ENTERPRISEPREMIUM, or contains E5 followed by non-digit
                        is_e5 = (
                            "_E5" in sku_upper or 
                            "E5_" in sku_upper or 
                            sku_upper.endswith("E5") or 
                            "ENTERPRISEPREMIUM" in sku_upper or
                            "365E5" in sku_upper or
                            "365_E5" in sku_upper or
                            "M365E5" in sku_upper or
                            "O365E5" in sku_upper
                        )
                        if is_e5:
                            sku_info = {"name": sku_part, "tier": "E5", "privilegeLevel": "HIGH"}
                        # Detect P2 variants
                        elif "_P2" in sku_upper or "P2_" in sku_upper or sku_upper.endswith("P2") or "PREMIUM_P2" in sku_upper or ("EMS" in sku_upper and "E5" in sku_upper):
                            sku_info = {"name": sku_part, "tier": "P2", "privilegeLevel": "HIGH"}
                        # Detect E3 variants
                        elif "_E3" in sku_upper or "E3_" in sku_upper or sku_upper.endswith("E3") or "ENTERPRISEPACK" in sku_upper or "365E3" in sku_upper:
                            sku_info = {"name": sku_part, "tier": "E3", "privilegeLevel": "MEDIUM"}
                        # Detect P1 variants
                        elif "_P1" in sku_upper or "P1_" in sku_upper or sku_upper.endswith("P1") or "AAD_PREMIUM" in sku_upper:
                            sku_info = {"name": sku_part, "tier": "P1", "privilegeLevel": "MEDIUM"}
                
                # Third try: lookup by SKU GUID (fallback when subscribedSkus API didn't return the SKU)
                if not sku_info and sku_id:
                    sku_info = LICENSE_GUID_MAP.get(sku_id.lower())
                
                # Final fallback: unknown license
                if not sku_info:
                    if sku_part:
                        sku_info = {"name": sku_part, "tier": "Unknown", "privilegeLevel": "LOW"}
                        print(f"    [DEBUG] Unrecognized SKU: {sku_part} (ID: {sku_id}) - add to LICENSE_SKU_MAP if E5/P2")
                    else:
                        sku_info = {"name": f"SKU:{sku_id[:8]}...", "tier": "Unknown", "privilegeLevel": "LOW"}
                        print(f"    [DEBUG] Unknown SKU ID: {sku_id} - add to LICENSE_GUID_MAP if E5/P2")
                
                license_names.append(sku_info["name"])
                license_tiers.add(sku_info["tier"])
                privilege_levels.add(sku_info["privilegeLevel"])
                
                # Check for high-privilege features
                tier = sku_info["tier"]
                if tier in HIGH_PRIVILEGE_FEATURES:
                    high_priv_features.extend(HIGH_PRIVILEGE_FEATURES[tier])
            
            # Determine overall privilege level
            if "HIGH" in privilege_levels:
                overall_privilege = "HIGH"
            elif "MEDIUM" in privilege_levels:
                overall_privilege = "MEDIUM"
            else:
                overall_privilege = "LOW"
            
            # Risk assessment based on licenses
            risk_level = "LOW"
            risk_factors = []
            
            if "E5" in license_tiers or "P2" in license_tiers:
                risk_level = "HIGH"
                risk_factors.append("Premium license (E5/P2)")
            elif "P1" in license_tiers or "E3" in license_tiers:
                if risk_level == "LOW":
                    risk_level = "MEDIUM"
                risk_factors.append("Standard premium (E3/P1)")
            
            # Check if disabled account has premium license
            if not user.get("accountEnabled", True) and overall_privilege in ["HIGH", "MEDIUM"]:
                risk_factors.append("Disabled account with premium license")
            
            # Check if guest has premium license
            if user.get("userType") == "Guest" and overall_privilege == "HIGH":
                risk_level = "HIGH"
                risk_factors.append("Guest with premium license")
            
            licensed_users.append({
                "id": user_id,
                "displayName": user.get("displayName", ""),
                "userPrincipalName": user.get("userPrincipalName", ""),
                "mail": user.get("mail", ""),
                "accountEnabled": user.get("accountEnabled", True),
                "userType": user.get("userType", "Member"),
                "licenseCount": len(assigned_licenses),
                "licenses": ", ".join(license_names[:3]) + ("..." if len(license_names) > 3 else ""),
                "licenseTiers": ", ".join(sorted(license_tiers)),
                "privilegeLevel": overall_privilege,
                "hasE5": "E5" in license_tiers,
                "hasP2": "P2" in license_tiers,
                "hasP1": "P1" in license_tiers,
                "highPrivilegeFeatures": list(set(high_priv_features))[:5],
                "riskLevel": risk_level,
                "riskFactors": ", ".join(risk_factors) if risk_factors else "None",
            })
        
        if licensed_users:
            high_priv = sum(1 for u in licensed_users if u["privilegeLevel"] == "HIGH")
            e5_users = sum(1 for u in licensed_users if u["hasE5"])
            p2_users = sum(1 for u in licensed_users if u["hasP2"])
            guests_with_premium = sum(1 for u in licensed_users if u["userType"] == "Guest" and u["privilegeLevel"] == "HIGH")
            
            print(f"[+] Found {len(licensed_users)} licensed users")
            print(f"    - HIGH privilege licenses: {high_priv}")
            print(f"    - Users with E5: {e5_users}")
            print(f"    - Users with P2: {p2_users}")
            if guests_with_premium > 0:
                print(f"    - Guests with premium licenses: {guests_with_premium} (RISK)")
        else:
            print("[!] No licensed users found or access denied")
    
    except Exception as e:
        print(f"[!] Error: {str(e)}")
    
    return licensed_users


def get_privileged_license_users(access_token: str) -> list:
    """
    Specifically enumerate users with E5 or P2 licenses 
    that provide elevated security/admin capabilities.
    """
    print("[*] Identifying Users with High-Privilege Licenses (E5/P2)...")
    
    all_licensed = get_user_licenses(access_token)
    
    # Filter for high-privilege users
    privileged_users = [
        user for user in all_licensed 
        if user["hasE5"] or user["hasP2"] or user["privilegeLevel"] == "HIGH"
    ]
    
    if privileged_users:
        print(f"\n[+] {len(privileged_users)} users with elevated license privileges:")
        
        # Categorize by feature access
        pim_users = [u for u in privileged_users if u["hasP2"]]
        defender_users = [u for u in privileged_users if u["hasE5"]]
        
        if pim_users:
            print(f"    - PIM-eligible users (P2): {len(pim_users)}")
        if defender_users:
            print(f"    - Advanced security features (E5): {len(defender_users)}")
            
        # Identify concerning patterns
        guest_privileged = [u for u in privileged_users if u["userType"] == "Guest"]
        disabled_privileged = [u for u in privileged_users if not u["accountEnabled"]]
        
        if guest_privileged:
            print(f"    ⚠️  Guests with E5/P2: {len(guest_privileged)}")
        if disabled_privileged:
            print(f"    ⚠️  Disabled accounts with E5/P2: {len(disabled_privileged)}")
    
    return privileged_users


def print_tenant_skus_report(skus: list) -> None:
    """Print a formatted tenant SKUs report."""
    print_security_summary(skus, "TENANT LICENSE SKUs REPORT")
    
    print(f"{'SKU Name':<40} {'Tier':<8} {'Privilege':<10} {'Used/Total':<15} {'Status':<12}")
    print("-" * 110)
    
    # Sort by privilege level
    priv_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_skus = sorted(skus, key=lambda x: priv_order.get(x.get("privilegeLevel", "LOW"), 3))
    
    for sku in sorted_skus[:50]:
        name = (sku.get("displayName") or sku.get("skuPartNumber") or "N/A")[:39]
        tier = (sku.get("tier") or "N/A")[:7]
        priv = (sku.get("privilegeLevel") or "LOW")[:9]
        used = sku.get("consumedUnits", 0)
        total = sku.get("enabledUnits", 0)
        usage = f"{used}/{total}"[:14]
        status = (sku.get("capabilityStatus") or "")[:11]
        
        print(f"{name:<40} {tier:<8} {priv:<10} {usage:<15} {status:<12}")
    
    if len(skus) > 50:
        print(f"    ... and {len(skus) - 50} more SKUs")
    
    print("-" * 110)
    
    # Show high-privilege SKU summary
    high_priv = [s for s in skus if s.get("privilegeLevel") == "HIGH"]
    if high_priv:
        print("\n⚠️  HIGH PRIVILEGE SKUs (enable admin/security features):")
        for sku in high_priv:
            features = HIGH_PRIVILEGE_FEATURES.get(sku.get("tier", ""), [])
            if features:
                print(f"   • {sku['displayName']}: {', '.join(features[:3])}")


def print_user_licenses_report(users: list) -> None:
    """Print a formatted user licenses report."""
    print_security_summary(users, "USER LICENSE ASSIGNMENTS")
    
    print(f"{'Display Name':<25} {'Email/UPN':<35} {'Licenses':<25} {'Tier':<10} {'Priv':<8} {'Risk':<7}")
    print("-" * 115)
    
    # Sort by privilege/risk
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_users = sorted(users, key=lambda x: (
        risk_order.get(x.get("riskLevel", "LOW"), 3),
        -x.get("licenseCount", 0)
    ))
    
    for user in sorted_users[:50]:
        name = (user.get("displayName") or "N/A")[:24]
        email = (user.get("userPrincipalName") or user.get("mail") or "N/A")[:34]
        licenses = (user.get("licenses") or "N/A")[:24]
        tiers = (user.get("licenseTiers") or "N/A")[:9]
        priv = (user.get("privilegeLevel") or "LOW")[:7]
        risk = user.get("riskLevel", "")
        
        print(f"{name:<25} {email:<35} {licenses:<25} {tiers:<10} {priv:<8} {risk:<7}")
    
    if len(users) > 50:
        print(f"    ... and {len(users) - 50} more users")
    
    print("-" * 115)
    
    # Show high-risk findings
    high_risk = [u for u in users if u.get("riskLevel") == "HIGH"]
    if high_risk:
        print(f"\n⚠️  {len(high_risk)} HIGH RISK license assignments found")
        guests = [u for u in high_risk if u.get("userType") == "Guest"]
        if guests:
            print(f"   • {len(guests)} guests with premium licenses")
        disabled = [u for u in high_risk if not u.get("accountEnabled")]
        if disabled:
            print(f"   • {len(disabled)} disabled accounts with premium licenses")


def print_privileged_license_users_report(users: list) -> None:
    """Print report for users with E5/P2 privileges."""
    print("\n" + "=" * 115)
    print(f"{'USERS WITH E5/P2 PRIVILEGES (HIGH-PRIVILEGE LICENSES)':^115}")
    print("=" * 115)
    
    if not users:
        print("\nNo users with E5/P2 licenses found.")
        return
    
    e5_users = [u for u in users if u.get("hasE5")]
    p2_users = [u for u in users if u.get("hasP2")]
    both = [u for u in users if u.get("hasE5") and u.get("hasP2")]
    
    print(f"\nSummary:")
    print(f"  • Total high-privilege users: {len(users)}")
    print(f"  • Users with E5 (Defender, eDiscovery, etc.): {len(e5_users)}")
    print(f"  • Users with P2 (PIM, Identity Protection): {len(p2_users)}")
    print(f"  • Users with both E5 and P2: {len(both)}")
    
    print(f"\n{'Display Name':<25} {'Email/UPN':<35} {'E5':<5} {'P2':<5} {'Enabled':<9} {'Type':<8} {'Features':<30}")
    print("-" * 120)
    
    for user in users[:50]:
        name = (user.get("displayName") or "N/A")[:24]
        email = (user.get("userPrincipalName") or "N/A")[:34]
        has_e5 = "Yes" if user.get("hasE5") else "No"
        has_p2 = "Yes" if user.get("hasP2") else "No"
        enabled = "Yes" if user.get("accountEnabled", True) else "No"
        user_type = (user.get("userType") or "Member")[:7]
        features = ", ".join(user.get("highPrivilegeFeatures", [])[:2])[:29]
        
        print(f"{name:<25} {email:<35} {has_e5:<5} {has_p2:<5} {enabled:<9} {user_type:<8} {features:<30}")
    
    if len(users) > 50:
        print(f"    ... and {len(users) - 50} more users")
    
    print("-" * 120)
    
    # Security recommendations
    print("\n📋 Security Considerations for E5/P2 Users:")
    print("   • E5 users can access advanced eDiscovery and may view sensitive data")
    print("   • P2 users can potentially self-activate privileged roles via PIM")
    print("   • Review if all assigned premium licenses are necessary")
    print("   • Consider enabling PIM approval workflows for role activation")


# ============================================================================
# DIRECTORY SYNC STATUS FUNCTIONS
# ============================================================================


def get_directory_sync_status(access_token: str) -> dict:
    """
    Get directory sync status for all users.
    Identifies on-prem synced vs cloud-only users.
    """
    print("\n[*] Analyzing directory sync status...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    results = {
        "synced_users": [],
        "cloud_only_users": [],
        "sync_errors": [],
        "summary": {}
    }
    
    # Get all users with sync-related properties
    select_fields = "id,displayName,userPrincipalName,mail,accountEnabled,userType,onPremisesSyncEnabled,onPremisesDistinguishedName,onPremisesDomainName,onPremisesLastSyncDateTime,onPremisesSecurityIdentifier,onPremisesSamAccountName,onPremisesImmutableId,onPremisesProvisioningErrors,dirSyncEnabled"
    
    url = f"{GRAPH_API_ENDPOINT}/users?$select={select_fields}&$top=999"
    all_users = []
    
    while url:
        if is_cancelled():
            break
            
        response = make_api_request(url, headers)
        if not response or response.status_code != 200:
            # Try beta endpoint if v1.0 fails
            if not all_users:
                url = f"{GRAPH_BETA_ENDPOINT}/users?$select={select_fields}&$top=999"
                response = make_api_request(url, headers)
                if not response or response.status_code != 200:
                    print(f"[!] Failed to get users: {response.status_code if response else 'No response'}")
                    return results
            else:
                break
        
        data = response.json()
        users = data.get("value", [])
        all_users.extend(users)
        
        url = data.get("@odata.nextLink")
        if url:
            print(f"    Retrieved {len(all_users)} users so far...")
    
    print(f"[+] Retrieved {len(all_users)} total users")
    
    # Categorize users
    for user in all_users:
        is_synced = user.get("onPremisesSyncEnabled", False) or user.get("dirSyncEnabled", False)
        has_on_prem_id = bool(user.get("onPremisesImmutableId") or user.get("onPremisesSecurityIdentifier"))
        prov_errors = user.get("onPremisesProvisioningErrors", [])
        
        user_info = {
            "id": user.get("id"),
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
            "mail": user.get("mail"),
            "accountEnabled": user.get("accountEnabled", True),
            "userType": user.get("userType", "Member"),
            "onPremisesSyncEnabled": is_synced or has_on_prem_id,
            "onPremisesDomainName": user.get("onPremisesDomainName"),
            "onPremisesSamAccountName": user.get("onPremisesSamAccountName"),
            "onPremisesDistinguishedName": user.get("onPremisesDistinguishedName"),
            "onPremisesLastSyncDateTime": user.get("onPremisesLastSyncDateTime"),
            "onPremisesImmutableId": user.get("onPremisesImmutableId"),
            "onPremisesSecurityIdentifier": user.get("onPremisesSecurityIdentifier"),
            "provisioningErrors": prov_errors,
            "syncSource": "On-Premises AD" if (is_synced or has_on_prem_id) else "Cloud-Only"
        }
        
        # Determine risk level
        risk_level = "LOW"
        risk_factors = []
        
        if prov_errors:
            risk_level = "HIGH"
            risk_factors.append("Sync errors")
        
        if is_synced or has_on_prem_id:
            results["synced_users"].append(user_info)
            
            # Check for stale sync (no sync in 7+ days)
            if user.get("onPremisesLastSyncDateTime"):
                try:
                    from datetime import datetime, timedelta
                    last_sync = user.get("onPremisesLastSyncDateTime", "").replace("Z", "+00:00")
                    if last_sync:
                        sync_date = datetime.fromisoformat(last_sync)
                        days_since_sync = (datetime.now(sync_date.tzinfo) - sync_date).days
                        user_info["daysSinceLastSync"] = days_since_sync
                        if days_since_sync > 7:
                            risk_level = "MEDIUM" if risk_level == "LOW" else risk_level
                            risk_factors.append(f"Stale sync ({days_since_sync}d)")
                except:
                    pass
        else:
            results["cloud_only_users"].append(user_info)
        
        user_info["riskLevel"] = risk_level
        user_info["riskFactors"] = ", ".join(risk_factors) if risk_factors else ""
        
        if prov_errors:
            error_info = user_info.copy()
            error_info["errors"] = prov_errors
            results["sync_errors"].append(error_info)
    
    # Build summary
    results["summary"] = {
        "totalUsers": len(all_users),
        "syncedUsers": len(results["synced_users"]),
        "cloudOnlyUsers": len(results["cloud_only_users"]),
        "usersWithSyncErrors": len(results["sync_errors"]),
        "syncedPercentage": round(len(results["synced_users"]) / len(all_users) * 100, 1) if all_users else 0,
        "cloudOnlyPercentage": round(len(results["cloud_only_users"]) / len(all_users) * 100, 1) if all_users else 0
    }
    
    return results


def get_directory_sync_errors(access_token: str) -> list:
    """
    Get users with directory sync errors.
    """
    print("\n[*] Checking for directory sync errors...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    results = []
    
    # Try beta endpoint for more detailed error information
    # Filter for users with provisioning errors
    select_fields = "id,displayName,userPrincipalName,mail,accountEnabled,onPremisesSyncEnabled,onPremisesProvisioningErrors,onPremisesDomainName,onPremisesLastSyncDateTime"
    
    # First try to get users with errors directly
    url = f"{GRAPH_BETA_ENDPOINT}/users?$select={select_fields}&$filter=onPremisesProvisioningErrors/any(e:e/category ne null)&$top=999"
    
    response = make_api_request(url, headers)
    
    # If filter fails, fall back to getting all users and filtering locally
    if not response or response.status_code != 200:
        print("    Direct filter not supported, scanning all users...")
        url = f"{GRAPH_API_ENDPOINT}/users?$select={select_fields}&$top=999"
        all_users = []
        
        while url:
            if is_cancelled():
                break
                
            response = make_api_request(url, headers)
            if not response or response.status_code != 200:
                break
            
            data = response.json()
            users = data.get("value", [])
            all_users.extend(users)
            url = data.get("@odata.nextLink")
        
        # Filter for users with errors
        for user in all_users:
            prov_errors = user.get("onPremisesProvisioningErrors", [])
            if prov_errors:
                results.append(user)
    else:
        data = response.json()
        results = data.get("value", [])
        
        # Handle pagination
        next_link = data.get("@odata.nextLink")
        while next_link:
            if is_cancelled():
                break
            response = make_api_request(next_link, headers)
            if response and response.status_code == 200:
                data = response.json()
                results.extend(data.get("value", []))
                next_link = data.get("@odata.nextLink")
            else:
                break
    
    # Process results
    processed_results = []
    for user in results:
        prov_errors = user.get("onPremisesProvisioningErrors", [])
        if not prov_errors:
            continue
            
        error_categories = []
        error_details = []
        
        for error in prov_errors:
            category = error.get("category", "Unknown")
            value = error.get("propertyCausingError", "Unknown property")
            error_value = error.get("value", "")
            occurred_time = error.get("occurredDateTime", "")
            
            error_categories.append(category)
            error_details.append({
                "category": category,
                "property": value,
                "value": error_value,
                "occurredDateTime": occurred_time
            })
        
        processed_user = {
            "id": user.get("id"),
            "displayName": user.get("displayName"),
            "userPrincipalName": user.get("userPrincipalName"),
            "mail": user.get("mail"),
            "accountEnabled": user.get("accountEnabled", True),
            "onPremisesSyncEnabled": user.get("onPremisesSyncEnabled", False),
            "onPremisesDomainName": user.get("onPremisesDomainName"),
            "onPremisesLastSyncDateTime": user.get("onPremisesLastSyncDateTime"),
            "errorCount": len(prov_errors),
            "errorCategories": ", ".join(set(error_categories)),
            "errorDetails": error_details,
            "riskLevel": "HIGH",
            "riskFactors": f"{len(prov_errors)} sync error(s)"
        }
        processed_results.append(processed_user)
    
    print(f"[+] Found {len(processed_results)} users with directory sync errors")
    return processed_results


def print_directory_sync_status_report(sync_data: dict) -> None:
    """Print a formatted directory sync status report."""
    print("\n" + "=" * 115)
    print(f"{'DIRECTORY SYNC STATUS REPORT':^115}")
    print("=" * 115)
    
    summary = sync_data.get("summary", {})
    
    print(f"\n📊 SYNC OVERVIEW:")
    print(f"   • Total Users: {summary.get('totalUsers', 0)}")
    print(f"   • On-Prem Synced: {summary.get('syncedUsers', 0)} ({summary.get('syncedPercentage', 0)}%)")
    print(f"   • Cloud-Only: {summary.get('cloudOnlyUsers', 0)} ({summary.get('cloudOnlyPercentage', 0)}%)")
    print(f"   • Users with Sync Errors: {summary.get('usersWithSyncErrors', 0)}")
    
    # Show synced users
    synced_users = sync_data.get("synced_users", [])
    if synced_users:
        print(f"\n{'─' * 115}")
        print(f"{'ON-PREMISES SYNCED USERS':^115}")
        print(f"{'─' * 115}")
        print(f"\n{'Display Name':<24} {'Email/UPN':<34} {'Domain':<20} {'SAM Account':<16} {'Last Sync':<14} {'Risk':<7}")
        print("-" * 115)
        
        for user in synced_users[:50]:
            name = (user.get("displayName") or "N/A")[:23]
            email = (user.get("userPrincipalName") or user.get("mail") or "N/A")[:33]
            domain = (user.get("onPremisesDomainName") or "N/A")[:19]
            sam = (user.get("onPremisesSamAccountName") or "N/A")[:15]
            
            last_sync = user.get("onPremisesLastSyncDateTime", "")
            if last_sync:
                last_sync = last_sync[:10]  # Just the date
            else:
                last_sync = "Never"
            
            risk = user.get("riskLevel", "LOW")
            print(f"{name:<24} {email:<34} {domain:<20} {sam:<16} {last_sync:<14} {risk:<7}")
        
        if len(synced_users) > 50:
            print(f"    ... and {len(synced_users) - 50} more synced users")
        print("-" * 115)
    
    # Show cloud-only users
    cloud_users = sync_data.get("cloud_only_users", [])
    if cloud_users:
        print(f"\n{'─' * 115}")
        print(f"{'CLOUD-ONLY USERS':^115}")
        print(f"{'─' * 115}")
        print(f"\n{'Display Name':<25} {'Email/UPN':<40} {'Type':<12} {'Enabled':<10} {'Risk':<7}")
        print("-" * 100)
        
        for user in cloud_users[:30]:
            name = (user.get("displayName") or "N/A")[:24]
            email = (user.get("userPrincipalName") or user.get("mail") or "N/A")[:39]
            user_type = (user.get("userType") or "Member")[:11]
            enabled = "Yes" if user.get("accountEnabled", True) else "No"
            risk = user.get("riskLevel", "LOW")
            
            print(f"{name:<25} {email:<40} {user_type:<12} {enabled:<10} {risk:<7}")
        
        if len(cloud_users) > 30:
            print(f"    ... and {len(cloud_users) - 30} more cloud-only users")
        print("-" * 100)
    
    # Show sync errors if any
    sync_errors = sync_data.get("sync_errors", [])
    if sync_errors:
        print(f"\n⚠️  {len(sync_errors)} USERS WITH DIRECTORY SYNC ERRORS:")
        for user in sync_errors[:10]:
            print(f"   • {user.get('displayName')} ({user.get('userPrincipalName')})")
            for error in user.get("provisioningErrors", [])[:2]:
                category = error.get("category", "Unknown")
                prop = error.get("propertyCausingError", "Unknown")
                print(f"     - {category}: {prop}")
    
    # Security recommendations
    print("\n📋 Security Considerations:")
    if summary.get("syncedUsers", 0) > 0:
        print("   • Synced accounts rely on on-premises AD security")
        print("   • Ensure AD Connect is properly secured and monitored")
        print("   • Review sync scope to ensure only necessary users are synced")
    if summary.get("cloudOnlyUsers", 0) > 0:
        print("   • Cloud-only accounts should have strong MFA enforcement")
        print("   • Consider Conditional Access policies for cloud-only identities")
    if summary.get("usersWithSyncErrors", 0) > 0:
        print("   ⚠️  Resolve sync errors to prevent authentication issues")


def print_directory_sync_errors_report(users: list) -> None:
    """Print a formatted directory sync errors report."""
    print("\n" + "=" * 115)
    print(f"{'DIRECTORY SYNC ERRORS (HIGH RISK)':^115}")
    print("=" * 115)
    
    if not users:
        print("\n✅ No directory sync errors found.")
        return
    
    print(f"\n⚠️  Found {len(users)} users with directory sync errors")
    
    # Group by error category
    error_categories = {}
    for user in users:
        for detail in user.get("errorDetails", []):
            category = detail.get("category", "Unknown")
            if category not in error_categories:
                error_categories[category] = 0
            error_categories[category] += 1
    
    print("\nError Categories:")
    for category, count in sorted(error_categories.items(), key=lambda x: -x[1]):
        print(f"   • {category}: {count}")
    
    print(f"\n{'Display Name':<22} {'Email/UPN':<32} {'Domain':<18} {'Error Categories':<25} {'Errors':<6} {'Risk':<7}")
    print("-" * 115)
    
    for user in users[:50]:
        name = (user.get("displayName") or "N/A")[:21]
        email = (user.get("userPrincipalName") or "N/A")[:31]
        domain = (user.get("onPremisesDomainName") or "N/A")[:17]
        categories = (user.get("errorCategories") or "Unknown")[:24]
        error_count = str(user.get("errorCount", 0))
        risk = user.get("riskLevel", "HIGH")
        
        print(f"{name:<22} {email:<32} {domain:<18} {categories:<25} {error_count:<6} {risk:<7}")
    
    if len(users) > 50:
        print(f"    ... and {len(users) - 50} more users with errors")
    
    print("-" * 115)
    
    # Show detailed errors for first few users
    print("\n📋 Detailed Error Information:")
    for user in users[:5]:
        print(f"\n   {user.get('displayName')} ({user.get('userPrincipalName')})")
        for detail in user.get("errorDetails", [])[:3]:
            print(f"      Category: {detail.get('category', 'Unknown')}")
            print(f"      Property: {detail.get('property', 'Unknown')}")
            if detail.get("value"):
                print(f"      Value: {detail.get('value')[:50]}")
            if detail.get("occurredDateTime"):
                print(f"      Occurred: {detail.get('occurredDateTime')[:19]}")
    
    # Recommendations
    print("\n🔧 Remediation Steps:")
    print("   1. Review error details in Azure AD Connect Health")
    print("   2. Check on-premises AD attributes for conflicts")
    print("   3. Verify UPN/ProxyAddress uniqueness across forest")
    print("   4. Run AD Connect sync with verbose logging")
    print("   5. Consider using IdFix tool to identify and fix issues")


# ============================================================================
# ATTACK PATH ANALYSIS FUNCTIONS
# ============================================================================


def get_group_owners(access_token: str) -> dict:
    """
    Enumerate owners of all groups, focusing on privileged groups.
    Identifies potential privilege escalation paths through group ownership.
    """
    print("\n[*] Enumerating group owners...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # List of privileged groups to focus on
    privileged_group_names = [
        "Global Administrators",
        "Privileged Role Administrators",
        "Security Administrators",
        "User Account Administrators",
        "Exchange Administrators",
        "SharePoint Administrators",
        "Teams Administrators",
        "Intune Administrators",
        "Application Administrators",
        "Cloud Application Administrators",
        "Conditional Access Administrators",
        "Password Administrators",
        "Authentication Administrators",
        "Helpdesk Administrators",
        "Groups Administrators",
        "Directory Writers",
        "Privileged Authentication Administrators"
    ]
    
    results = {
        "privileged_group_owners": [],
        "all_group_owners": [],
        "groups_with_owners": 0,
        "total_groups": 0
    }
    
    try:
        # Get all groups
        url = f"{GRAPH_API_ENDPOINT}/groups?$select=id,displayName,description,groupTypes,securityEnabled,mailEnabled,isAssignableToRole&$top=999"
        all_groups = []
        
        while url:
            if is_cancelled():
                break
            response = make_api_request(url, headers)
            if response and response.status_code == 200:
                data = response.json()
                all_groups.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
            else:
                break
        
        results["total_groups"] = len(all_groups)
        print(f"[+] Found {len(all_groups)} groups")
        
        # Get owners for each group
        group_count = 0
        for group in all_groups:
            if is_cancelled():
                break
            group_count += 1
            if group_count % 50 == 0:
                print(f"    Processing group {group_count} of {len(all_groups)}...")
            
            try:
                owners_url = f"{GRAPH_API_ENDPOINT}/groups/{group.get('id')}/owners?$select=id,displayName,userPrincipalName,mail"
                owners_response = make_api_request(owners_url, headers)
                
                if owners_response and owners_response.status_code == 200:
                    owners = owners_response.json().get("value", [])
                    
                    if owners:
                        results["groups_with_owners"] += 1
                        
                        for owner in owners:
                            group_name = group.get("displayName", "")
                            is_privileged_group = (
                                group_name in privileged_group_names or
                                group.get("isAssignableToRole", False) or
                                any(keyword in group_name.lower() for keyword in ["admin", "privilege", "security", "global", "exchange", "sharepoint", "teams", "intune", "password", "helpdesk"])
                            )
                            
                            owner_info = {
                                "groupId": group.get("id"),
                                "groupName": group_name,
                                "groupDescription": group.get("description"),
                                "isRoleAssignable": group.get("isAssignableToRole", False),
                                "isSecurityGroup": group.get("securityEnabled", False),
                                "ownerId": owner.get("id"),
                                "ownerDisplayName": owner.get("displayName"),
                                "ownerUPN": owner.get("userPrincipalName"),
                                "ownerMail": owner.get("mail"),
                                "isPrivilegedGroup": is_privileged_group,
                                "riskLevel": "HIGH" if is_privileged_group else "LOW"
                            }
                            
                            results["all_group_owners"].append(owner_info)
                            
                            if is_privileged_group:
                                results["privileged_group_owners"].append(owner_info)
            except:
                pass
        
        print(f"[+] Found {results['groups_with_owners']} groups with owners")
        print(f"[+] Found {len(results['privileged_group_owners'])} owners of privileged groups")
        
    except Exception as e:
        print(f"[!] Error enumerating group owners: {e}")
    
    return results


def get_password_reset_delegations(access_token: str) -> dict:
    """
    Identify users with password reset permissions (privilege escalation path).
    """
    print("\n[*] Identifying password reset delegations...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Roles that can reset passwords
    password_reset_roles = {
        "Privileged Authentication Administrator": "CRITICAL",  # Can reset any user including Global Admins
        "Authentication Administrator": "HIGH",                 # Can reset non-admin users
        "Password Administrator": "HIGH",                       # Can reset non-admin users
        "Helpdesk Administrator": "MEDIUM",                     # Can reset some users
        "User Administrator": "HIGH",                           # Can reset non-admin users
        "Global Administrator": "CRITICAL"                      # Can do everything
    }
    
    results = {
        "password_reset_users": [],
        "role_counts": {}
    }
    
    try:
        # Get directory roles with members
        url = f"{GRAPH_API_ENDPOINT}/directoryRoles?$expand=members"
        response = make_api_request(url, headers)
        
        if response and response.status_code == 200:
            roles = response.json().get("value", [])
            
            for role in roles:
                role_name = role.get("displayName", "")
                
                if role_name in password_reset_roles:
                    risk_level = password_reset_roles[role_name]
                    
                    for member in role.get("members", []):
                        if "#microsoft.graph.user" in member.get("@odata.type", ""):
                            results["password_reset_users"].append({
                                "userId": member.get("id"),
                                "displayName": member.get("displayName"),
                                "userPrincipalName": member.get("userPrincipalName"),
                                "mail": member.get("mail"),
                                "role": role_name,
                                "roleId": role.get("id"),
                                "riskLevel": risk_level,
                                "canResetGlobalAdmins": role_name in ["Privileged Authentication Administrator", "Global Administrator"],
                                "assignmentType": "Active"
                            })
                            
                            if role_name not in results["role_counts"]:
                                results["role_counts"][role_name] = 0
                            results["role_counts"][role_name] += 1
        
        # Also check PIM eligible for password reset roles
        print("[*] Checking PIM eligible password reset delegations...")
        
        try:
            pim_url = f"{GRAPH_BETA_ENDPOINT}/roleManagement/directory/roleEligibilitySchedules?$expand=principal"
            pim_response = make_api_request(pim_url, headers)
            
            if pim_response and pim_response.status_code == 200:
                schedules = pim_response.json().get("value", [])
                
                for schedule in schedules:
                    principal = schedule.get("principal", {})
                    
                    if principal.get("@odata.type") == "#microsoft.graph.user":
                        role_id = schedule.get("roleDefinitionId", "")
                        
                        # Get role name
                        role_url = f"{GRAPH_API_ENDPOINT}/directoryRoles?$filter=roleTemplateId eq '{role_id}'"
                        role_response = make_api_request(role_url, headers)
                        role_name = "Unknown Role"
                        
                        if role_response and role_response.status_code == 200:
                            role_data = role_response.json().get("value", [])
                            if role_data:
                                role_name = role_data[0].get("displayName", "Unknown")
                        
                        if role_name in password_reset_roles:
                            results["password_reset_users"].append({
                                "userId": principal.get("id"),
                                "displayName": principal.get("displayName"),
                                "userPrincipalName": principal.get("userPrincipalName"),
                                "mail": principal.get("mail"),
                                "role": role_name,
                                "roleId": role_id,
                                "riskLevel": password_reset_roles[role_name],
                                "canResetGlobalAdmins": role_name in ["Privileged Authentication Administrator", "Global Administrator"],
                                "assignmentType": "PIM Eligible"
                            })
        except Exception as e:
            print(f"[!] PIM eligibility check failed: {e}")
        
        critical_count = sum(1 for u in results["password_reset_users"] if u.get("riskLevel") == "CRITICAL")
        high_count = sum(1 for u in results["password_reset_users"] if u.get("riskLevel") == "HIGH")
        
        print(f"[+] Found {len(results['password_reset_users'])} users with password reset permissions")
        print(f"    - CRITICAL (can reset Global Admins): {critical_count}")
        print(f"    - HIGH: {high_count}")
        
    except Exception as e:
        print(f"[!] Error identifying password reset delegations: {e}")
    
    return results


def get_users_with_group_membership_privileges(access_token: str) -> dict:
    """
    Find users who can add members to privileged groups (privilege escalation path).
    """
    print("\n[*] Analyzing group membership modification privileges...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    results = {
        "privileged_group_managers": [],
        "apps_with_group_write_all": [],
        "role_based_group_managers": []
    }
    
    # Roles that can modify group membership
    group_management_roles = {
        "Global Administrator": "CRITICAL",
        "Privileged Role Administrator": "CRITICAL",
        "Groups Administrator": "HIGH",
        "User Administrator": "HIGH",
        "Directory Writers": "MEDIUM",
        "Intune Administrator": "MEDIUM"
    }
    
    try:
        # 1. Check users with roles that allow group management
        print("[*] Checking role-based group management permissions...")
        
        url = f"{GRAPH_API_ENDPOINT}/directoryRoles?$expand=members"
        response = make_api_request(url, headers)
        
        if response and response.status_code == 200:
            roles = response.json().get("value", [])
            
            for role in roles:
                role_name = role.get("displayName", "")
                
                if role_name in group_management_roles:
                    risk_level = group_management_roles[role_name]
                    
                    for member in role.get("members", []):
                        if "#microsoft.graph.user" in member.get("@odata.type", ""):
                            results["role_based_group_managers"].append({
                                "userId": member.get("id"),
                                "displayName": member.get("displayName"),
                                "userPrincipalName": member.get("userPrincipalName"),
                                "role": role_name,
                                "riskLevel": risk_level,
                                "privilegeType": "Role Assignment",
                                "canManageAllGroups": role_name in ["Global Administrator", "Groups Administrator"]
                            })
        
        print(f"[+] Found {len(results['role_based_group_managers'])} users with group management roles")
        
        # 2. Check applications with Group.ReadWrite.All or GroupMember.ReadWrite.All
        print("[*] Checking applications with group write permissions...")
        
        dangerous_permissions = [
            "Group.ReadWrite.All",
            "GroupMember.ReadWrite.All",
            "Directory.ReadWrite.All"
        ]
        
        # Get Graph service principal to resolve permission IDs
        ms_graph_app_id = "00000003-0000-0000-c000-000000000000"
        graph_sp_url = f"{GRAPH_API_ENDPOINT}/servicePrincipals?$filter=appId eq '{ms_graph_app_id}'&$select=id,appRoles"
        graph_sp_response = make_api_request(graph_sp_url, headers)
        
        if graph_sp_response and graph_sp_response.status_code == 200:
            graph_sp_data = graph_sp_response.json().get("value", [])
            
            if graph_sp_data:
                graph_sp = graph_sp_data[0]
                graph_sp_id = graph_sp.get("id")
                
                # Build permission ID map
                permission_id_map = {}
                for app_role in graph_sp.get("appRoles", []):
                    if app_role.get("value") in dangerous_permissions:
                        permission_id_map[app_role.get("id")] = app_role.get("value")
                
                # Get all service principals
                sps_url = f"{GRAPH_API_ENDPOINT}/servicePrincipals?$select=id,displayName,appId&$top=999"
                all_sps = []
                
                while sps_url:
                    if is_cancelled():
                        break
                    sp_response = make_api_request(sps_url, headers)
                    if sp_response and sp_response.status_code == 200:
                        sp_data = sp_response.json()
                        all_sps.extend(sp_data.get("value", []))
                        sps_url = sp_data.get("@odata.nextLink")
                    else:
                        break
                
                # Check each SP for dangerous permissions
                for sp in all_sps:
                    if is_cancelled():
                        break
                    try:
                        assignments_url = f"{GRAPH_API_ENDPOINT}/servicePrincipals/{sp.get('id')}/appRoleAssignments"
                        assignments_response = make_api_request(assignments_url, headers)
                        
                        if assignments_response and assignments_response.status_code == 200:
                            assignments = assignments_response.json().get("value", [])
                            
                            has_group_write_permission = False
                            granted_permissions = []
                            
                            for assignment in assignments:
                                if assignment.get("resourceId") == graph_sp_id:
                                    app_role_id = assignment.get("appRoleId")
                                    if app_role_id in permission_id_map:
                                        has_group_write_permission = True
                                        granted_permissions.append(permission_id_map[app_role_id])
                            
                            if has_group_write_permission:
                                # Get owners of this app
                                owners_list = []
                                try:
                                    owners_url = f"{GRAPH_API_ENDPOINT}/servicePrincipals/{sp.get('id')}/owners?$select=userPrincipalName"
                                    owners_response = make_api_request(owners_url, headers)
                                    if owners_response and owners_response.status_code == 200:
                                        for owner in owners_response.json().get("value", []):
                                            owners_list.append(owner.get("userPrincipalName", ""))
                                except:
                                    pass
                                
                                results["apps_with_group_write_all"].append({
                                    "appId": sp.get("appId"),
                                    "appDisplayName": sp.get("displayName"),
                                    "servicePrincipalId": sp.get("id"),
                                    "grantedPermissions": ", ".join(granted_permissions),
                                    "owners": ", ".join(owners_list) if owners_list else "None",
                                    "riskLevel": "HIGH",
                                    "privilegeType": "Application Permission"
                                })
                    except:
                        pass
        
        print(f"[+] Found {len(results['apps_with_group_write_all'])} apps with group write permissions")
        
        # 3. Get privileged group owners
        print("[*] Getting privileged group owners...")
        
        group_owner_results = get_group_owners(access_token)
        results["privileged_group_managers"] = group_owner_results.get("privileged_group_owners", [])
        
    except Exception as e:
        print(f"[!] Error analyzing group membership privileges: {e}")
    
    return results


def get_attack_path_analysis(access_token: str) -> dict:
    """
    Comprehensive attack path analysis for privilege escalation.
    """
    print("\n" + "=" * 80)
    print(f"{'ATTACK PATH ANALYSIS':^80}")
    print("=" * 80)
    print("\nAnalyzing potential privilege escalation paths...")
    
    results = {
        "group_membership_privileges": {},
        "password_reset_delegations": {},
        "group_owners": {},
        "privileged_role_assignments": [],
        "attack_paths": []
    }
    
    # 1. Get users with group membership privileges
    results["group_membership_privileges"] = get_users_with_group_membership_privileges(access_token)
    
    # 2. Get password reset delegations
    results["password_reset_delegations"] = get_password_reset_delegations(access_token)
    
    # 3. Get group owners (already called in group membership privileges)
    results["group_owners"] = get_group_owners(access_token)
    
    # 4. Get privileged role assignments (reuse existing function)
    print("\n[*] Getting privileged role assignments...")
    results["privileged_role_assignments"] = get_privileged_users(access_token)
    
    # 5. Identify attack paths
    print("\n[*] Identifying attack paths...")
    
    # Attack Path 1: Group owners who can add members to privileged groups
    for owner in results["group_owners"].get("privileged_group_owners", []):
        results["attack_paths"].append({
            "pathType": "Group Ownership",
            "sourceUser": owner.get("ownerUPN"),
            "sourceUserId": owner.get("ownerId"),
            "targetResource": owner.get("groupName"),
            "targetResourceId": owner.get("groupId"),
            "riskLevel": "HIGH",
            "description": "User owns a privileged group and can add members",
            "remediation": "Review group ownership; consider role-assignable groups with PIM"
        })
    
    # Attack Path 2: Users with password reset on privileged accounts
    critical_reset_users = [u for u in results["password_reset_delegations"].get("password_reset_users", []) if u.get("canResetGlobalAdmins")]
    for user in critical_reset_users:
        results["attack_paths"].append({
            "pathType": "Password Reset",
            "sourceUser": user.get("userPrincipalName"),
            "sourceUserId": user.get("userId"),
            "targetResource": "Global Administrators",
            "targetResourceId": user.get("roleId"),
            "riskLevel": "CRITICAL",
            "description": f"User can reset passwords of Global Administrators via {user.get('role')}",
            "remediation": "Limit Privileged Auth Admin role; use PIM with approval"
        })
    
    # Attack Path 3: Apps with Group.ReadWrite.All
    for app in results["group_membership_privileges"].get("apps_with_group_write_all", []):
        results["attack_paths"].append({
            "pathType": "Application Permission",
            "sourceUser": app.get("owners", "No Owner"),
            "sourceUserId": app.get("servicePrincipalId"),
            "targetResource": app.get("appDisplayName"),
            "targetResourceId": app.get("appId"),
            "riskLevel": "HIGH",
            "description": f"Application has {app.get('grantedPermissions')} - can modify any group membership",
            "remediation": "Review application permissions; use least privilege"
        })
    
    # Count attack paths by type
    path_types = {}
    for path in results["attack_paths"]:
        pt = path.get("pathType", "Unknown")
        path_types[pt] = path_types.get(pt, 0) + 1
    
    print(f"\n[+] Attack Path Analysis Complete")
    print(f"    Total potential attack paths: {len(results['attack_paths'])}")
    for pt, count in path_types.items():
        print(f"    - {pt}: {count}")
    
    return results


def print_attack_path_report(results: dict) -> None:
    """Print a formatted attack path analysis report."""
    print("\n" + "=" * 120)
    print(f"{'ATTACK PATH ANALYSIS REPORT':^120}")
    print("=" * 120)
    
    # Summary
    total_paths = len(results.get("attack_paths", []))
    critical_paths = sum(1 for p in results.get("attack_paths", []) if p.get("riskLevel") == "CRITICAL")
    high_paths = sum(1 for p in results.get("attack_paths", []) if p.get("riskLevel") == "HIGH")
    
    print("\n📊 EXECUTIVE SUMMARY:")
    print(f"   Total Attack Paths Identified: {total_paths}")
    print(f"   ⚠️  CRITICAL Risk Paths: {critical_paths}")
    print(f"   ⚠️  HIGH Risk Paths: {high_paths}")
    
    # Password Reset Delegations
    pwd_reset_users = results.get("password_reset_delegations", {}).get("password_reset_users", [])
    if pwd_reset_users:
        print(f"\n{'─' * 120}")
        print(f"{'🔑 PASSWORD RESET DELEGATIONS':^120}")
        print(f"{'─' * 120}")
        
        print("\n!!! Users who can reset passwords are high-value targets for privilege escalation")
        
        print(f"\n{'Display Name':<23} {'Email/UPN':<34} {'Role':<34} {'Type':<11} {'Reset GA?':<10} {'Risk':<8}")
        print("-" * 120)
        
        sorted_users = sorted(pwd_reset_users, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("riskLevel", "LOW"), 4))
        
        for user in sorted_users[:30]:
            name = (user.get("displayName") or "N/A")[:22]
            email = (user.get("userPrincipalName") or "N/A")[:33]
            role = (user.get("role") or "N/A")[:33]
            assign_type = (user.get("assignmentType") or "Active")[:10]
            reset_ga = "YES" if user.get("canResetGlobalAdmins") else "No"
            risk = user.get("riskLevel", "")
            
            print(f"{name:<23} {email:<34} {role:<34} {assign_type:<11} {reset_ga:<10} {risk:<8}")
        
        if len(pwd_reset_users) > 30:
            print(f"    ... and {len(pwd_reset_users) - 30} more users")
        print("-" * 120)
    
    # Privileged Group Owners
    priv_group_owners = results.get("group_owners", {}).get("privileged_group_owners", [])
    if priv_group_owners:
        print(f"\n{'─' * 120}")
        print(f"{'👥 PRIVILEGED GROUP OWNERS':^120}")
        print(f"{'─' * 120}")
        
        print("\n!!! These users can add members to privileged groups - potential privilege escalation")
        
        print(f"\n{'Owner Name':<24} {'Owner UPN':<36} {'Group Name':<36} {'Role Grp?':<10} {'Risk':<8}")
        print("-" * 120)
        
        for owner in priv_group_owners[:30]:
            name = (owner.get("ownerDisplayName") or "N/A")[:23]
            upn = (owner.get("ownerUPN") or "N/A")[:35]
            group_name = (owner.get("groupName") or "N/A")[:35]
            role_assignable = "Yes" if owner.get("isRoleAssignable") else "No"
            risk = owner.get("riskLevel", "")
            
            print(f"{name:<24} {upn:<36} {group_name:<36} {role_assignable:<10} {risk:<8}")
        
        if len(priv_group_owners) > 30:
            print(f"    ... and {len(priv_group_owners) - 30} more owners")
        print("-" * 120)
    
    # Applications with Group Write Permissions
    apps_with_perms = results.get("group_membership_privileges", {}).get("apps_with_group_write_all", [])
    if apps_with_perms:
        print(f"\n{'─' * 120}")
        print(f"{'🔐 APPLICATIONS WITH GROUP WRITE PERMISSIONS':^120}")
        print(f"{'─' * 120}")
        
        print("\n!!! These applications can modify any group membership in the tenant")
        
        print(f"\n{'App Name':<31} {'App ID':<39} {'Permissions':<29} {'Owners':<18}")
        print("-" * 120)
        
        for app in apps_with_perms:
            name = (app.get("appDisplayName") or "N/A")[:30]
            app_id = (app.get("appId") or "N/A")[:38]
            perms = (app.get("grantedPermissions") or "N/A")[:28]
            owners = (app.get("owners") or "None")[:17]
            
            print(f"{name:<31} {app_id:<39} {perms:<29} {owners:<18}")
        print("-" * 120)
    
    # Role-Based Group Managers
    role_managers = results.get("group_membership_privileges", {}).get("role_based_group_managers", [])
    if role_managers:
        print(f"\n{'─' * 120}")
        print(f"{'👤 USERS WITH GROUP MANAGEMENT ROLES':^120}")
        print(f"{'─' * 120}")
        
        print(f"\n{'Display Name':<25} {'Email/UPN':<39} {'Role':<29} {'All Groups?':<12} {'Risk':<8}")
        print("-" * 115)
        
        for user in role_managers[:25]:
            name = (user.get("displayName") or "N/A")[:24]
            email = (user.get("userPrincipalName") or "N/A")[:38]
            role = (user.get("role") or "N/A")[:28]
            all_groups = "Yes" if user.get("canManageAllGroups") else "No"
            risk = user.get("riskLevel", "")
            
            print(f"{name:<25} {email:<39} {role:<29} {all_groups:<12} {risk:<8}")
        
        if len(role_managers) > 25:
            print(f"    ... and {len(role_managers) - 25} more users")
        print("-" * 115)
    
    # Attack Paths Summary
    attack_paths = results.get("attack_paths", [])
    if attack_paths:
        print(f"\n{'─' * 120}")
        print(f"{'⚡ IDENTIFIED ATTACK PATHS':^120}")
        print(f"{'─' * 120}")
        
        print(f"\n{'Path Type':<21} {'Source':<29} {'Target':<29} {'Risk':<9} {'Description':<30}")
        print("-" * 120)
        
        sorted_paths = sorted(attack_paths, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("riskLevel", "LOW"), 4))
        
        for path in sorted_paths[:25]:
            path_type = (path.get("pathType") or "N/A")[:20]
            source = (path.get("sourceUser") or "N/A")[:28]
            target = (path.get("targetResource") or "N/A")[:28]
            risk = path.get("riskLevel", "")
            desc = (path.get("description") or "N/A")[:29]
            
            print(f"{path_type:<21} {source:<29} {target:<29} {risk:<9} {desc:<30}")
        
        if len(attack_paths) > 25:
            print(f"    ... and {len(attack_paths) - 25} more attack paths")
        print("-" * 120)
    
    # Recommendations
    print("\n" + "=" * 120)
    print("🔧 REMEDIATION RECOMMENDATIONS:")
    print("=" * 120)
    
    print("\n1. Password Reset Delegations:")
    print("   - Limit users with Privileged Authentication Administrator role")
    print("   - Use PIM with approval workflows for password reset roles")
    print("   - Implement just-in-time access for authentication administrators")
    
    print("\n2. Group Ownership:")
    print("   - Review and minimize privileged group owners")
    print("   - Use role-assignable groups with PIM for privileged groups")
    print("   - Implement access reviews for group owners")
    
    print("\n3. Application Permissions:")
    print("   - Remove unnecessary Group.ReadWrite.All permissions")
    print("   - Use more specific permissions where possible")
    print("   - Ensure all high-privilege apps have assigned owners")
    
    print("\n4. General:")
    print("   - Enable and monitor Conditional Access for privileged operations")
    print("   - Configure Azure AD audit logs and alerts for privilege changes")
    print("   - Regularly review privileged access using access reviews")


# ============================================================================
# LATERAL MOVEMENT ANALYSIS FUNCTIONS
# ============================================================================

def get_transitive_group_memberships(access_token: str, target_user_id: str = None) -> dict:
    """
    Map group nesting and transitive memberships.
    Identifies indirect group memberships that could be exploited for lateral movement.
    
    Requires: GroupMember.Read.All or Directory.Read.All
    """
    print("\n[*] Mapping transitive group memberships...")
    
    results = {
        "users_with_nested_access": [],
        "privileged_group_chains": [],
        "deeply_nested_groups": [],
        "total_direct_memberships": 0,
        "total_transitive_memberships": 0,
        "max_nesting_depth": 0
    }
    
    headers = {"Authorization": f"Bearer {access_token}"}
    
    try:
        # Get privileged groups first
        privileged_group_names = [
            "Global Administrator", "Privileged Role Administrator", 
            "User Administrator", "Exchange Administrator",
            "Security Administrator", "Helpdesk Administrator",
            "Password Administrator", "Authentication Administrator",
            "Privileged Authentication Administrator", "Cloud Application Administrator",
            "Application Administrator", "Intune Administrator",
            "Azure AD Joined Device Local Administrator", "Groups Administrator"
        ]
        
        # Get all groups with select for efficiency
        print("    Fetching all groups...")
        groups_url = f"{GRAPH_API_ENDPOINT}/groups?$select=id,displayName,securityEnabled,groupTypes,isAssignableToRole&$top=999"
        all_groups = []
        
        while groups_url:
            if is_cancelled():
                return results
            response = make_api_request(groups_url, headers)
            if not response or response.status_code != 200:
                break
            data = response.json()
            all_groups.extend(data.get("value", []))
            groups_url = data.get("@odata.nextLink")
        
        print(f"    Found {len(all_groups)} total groups")
        
        # Identify privileged groups (role-assignable or matching names)
        privileged_groups = []
        for group in all_groups:
            is_privileged = (
                group.get("isAssignableToRole") or
                any(priv_name.lower() in (group.get("displayName") or "").lower() 
                    for priv_name in privileged_group_names)
            )
            if is_privileged:
                privileged_groups.append({
                    "id": group.get("id"),
                    "displayName": group.get("displayName"),
                    "isRoleAssignable": group.get("isAssignableToRole", False)
                })
        
        print(f"    Identified {len(privileged_groups)} privileged groups")
        
        # For each privileged group, find transitive members
        for priv_group in privileged_groups[:20]:  # Limit to top 20 to avoid rate limiting
            if is_cancelled():
                return results
                
            group_id = priv_group.get("id")
            group_name = priv_group.get("displayName")
            
            # Get direct members
            direct_url = f"{GRAPH_API_ENDPOINT}/groups/{group_id}/members?$select=id,displayName,userPrincipalName,@odata.type&$top=999"
            direct_response = make_api_request(direct_url, headers)
            direct_members = []
            if direct_response and direct_response.status_code == 200:
                direct_members = direct_response.json().get("value", [])
            
            # Get transitive members
            transitive_url = f"{GRAPH_API_ENDPOINT}/groups/{group_id}/transitiveMembers?$select=id,displayName,userPrincipalName,@odata.type&$top=999"
            transitive_response = make_api_request(transitive_url, headers)
            transitive_members = []
            if transitive_response and transitive_response.status_code == 200:
                transitive_members = transitive_response.json().get("value", [])
            
            # Find nested groups (groups that are members)
            nested_groups = [m for m in direct_members if m.get("@odata.type") == "#microsoft.graph.group"]
            direct_users = [m for m in direct_members if m.get("@odata.type") == "#microsoft.graph.user"]
            transitive_users = [m for m in transitive_members if m.get("@odata.type") == "#microsoft.graph.user"]
            
            # Users who have access through nesting (transitive but not direct)
            direct_user_ids = {u.get("id") for u in direct_users}
            indirect_users = [u for u in transitive_users if u.get("id") not in direct_user_ids]
            
            results["total_direct_memberships"] += len(direct_users)
            results["total_transitive_memberships"] += len(transitive_users)
            
            if nested_groups:
                results["deeply_nested_groups"].append({
                    "groupName": group_name,
                    "groupId": group_id,
                    "isRoleAssignable": priv_group.get("isRoleAssignable"),
                    "directUserCount": len(direct_users),
                    "transitiveUserCount": len(transitive_users),
                    "nestedGroupCount": len(nested_groups),
                    "nestedGroups": [g.get("displayName") for g in nested_groups[:10]],
                    "riskLevel": "HIGH" if priv_group.get("isRoleAssignable") else "MEDIUM"
                })
            
            # Record users with indirect access to privileged groups
            for user in indirect_users[:50]:  # Limit per group
                results["users_with_nested_access"].append({
                    "userId": user.get("id"),
                    "userPrincipalName": user.get("userPrincipalName"),
                    "displayName": user.get("displayName"),
                    "privilegedGroup": group_name,
                    "accessType": "Transitive",
                    "riskLevel": "HIGH" if priv_group.get("isRoleAssignable") else "MEDIUM"
                })
        
        # Calculate nesting depth for deeply nested groups
        if results["deeply_nested_groups"]:
            max_nested = max(g.get("nestedGroupCount", 0) for g in results["deeply_nested_groups"])
            results["max_nesting_depth"] = max_nested
        
        print(f"[+] Transitive membership analysis complete")
        print(f"    Users with nested access to privileged groups: {len(results['users_with_nested_access'])}")
        print(f"    Groups with nested membership: {len(results['deeply_nested_groups'])}")
        
    except Exception as e:
        print(f"[!] Error mapping transitive memberships: {e}")
    
    return results


def get_shared_mailbox_access(access_token: str) -> dict:
    """
    Identify shared mailboxes and users with access to them.
    Shared mailboxes are often used for lateral movement as they may contain sensitive data.
    
    Requires: Mail.Read, MailboxSettings.Read, or User.Read.All
    """
    print("\n[*] Identifying shared mailbox access...")
    
    results = {
        "shared_mailboxes": [],
        "users_with_shared_access": [],
        "high_value_mailboxes": [],
        "mailbox_permissions": []
    }
    
    headers = {"Authorization": f"Bearer {access_token}"}
    
    try:
        # Get shared mailboxes - they have recipientTypeDetails = SharedMailbox
        # Use filter for shared mailboxes (assignedLicenses is empty and mail is set)
        print("    Fetching shared mailboxes...")
        
        # Method 1: Try to get shared mailboxes via users endpoint with filter
        # Shared mailboxes typically don't have licenses assigned
        users_url = f"{GRAPH_API_ENDPOINT}/users?$filter=mailboxSettings/userPurpose eq 'shared'&$select=id,displayName,mail,userPrincipalName&$top=999"
        response = make_api_request(users_url, headers)
        
        if not response or response.status_code != 200:
            # Fallback: Get all users and filter by naming convention or properties
            print("    Primary method unavailable, using fallback method...")
            users_url = f"{GRAPH_API_ENDPOINT}/users?$select=id,displayName,mail,userPrincipalName,accountEnabled,assignedLicenses&$top=999"
            response = make_api_request(users_url, headers)
        
        shared_mailboxes = []
        if response and response.status_code == 200:
            users = response.json().get("value", [])
            # Filter potential shared mailboxes (no licenses, naming conventions)
            for user in users:
                is_shared = False
                mail = (user.get("mail") or user.get("userPrincipalName") or "").lower()
                display_name = (user.get("displayName") or "").lower()
                
                # Check common shared mailbox indicators
                shared_indicators = ["shared", "info@", "support@", "sales@", "hr@", 
                                   "finance@", "admin@", "noreply@", "helpdesk@",
                                   "team@", "group@", "general@", "contact@"]
                
                if any(indicator in mail or indicator in display_name for indicator in shared_indicators):
                    is_shared = True
                
                # Users without licenses might be shared mailboxes
                if not user.get("assignedLicenses"):
                    is_shared = True
                
                if is_shared:
                    risk_level = "HIGH"
                    if any(hv in mail for hv in ["finance", "hr", "admin", "exec", "legal", "ceo", "cfo"]):
                        risk_level = "CRITICAL"
                        results["high_value_mailboxes"].append(user)
                    
                    shared_mailboxes.append({
                        "id": user.get("id"),
                        "displayName": user.get("displayName"),
                        "mail": user.get("mail") or user.get("userPrincipalName"),
                        "accountEnabled": user.get("accountEnabled", True),
                        "riskLevel": risk_level
                    })
        
        results["shared_mailboxes"] = shared_mailboxes
        print(f"    Found {len(shared_mailboxes)} potential shared mailboxes")
        
        # Try to get mailbox permissions for identified shared mailboxes
        # This requires Exchange Online permissions via Graph
        print("    Checking mailbox delegate access...")
        
        for mailbox in shared_mailboxes[:15]:  # Limit to avoid rate limiting
            if is_cancelled():
                return results
            
            mailbox_id = mailbox.get("id")
            
            # Try to get mail folder permissions (inbox delegates)
            permissions_url = f"{GRAPH_API_ENDPOINT}/users/{mailbox_id}/mailFolders/inbox/permissions"
            perms_response = make_api_request(permissions_url, headers)
            
            if perms_response and perms_response.status_code == 200:
                permissions = perms_response.json().get("value", [])
                for perm in permissions:
                    if perm.get("isDefault", False):
                        continue  # Skip default permissions
                    
                    grantee = perm.get("grantedTo", {}).get("user", {})
                    results["mailbox_permissions"].append({
                        "mailboxName": mailbox.get("displayName"),
                        "mailboxEmail": mailbox.get("mail"),
                        "delegateId": grantee.get("id"),
                        "delegateName": grantee.get("displayName"),
                        "delegateEmail": grantee.get("emailAddress"),
                        "permissionRole": perm.get("role"),
                        "riskLevel": mailbox.get("riskLevel", "MEDIUM")
                    })
                    
                    results["users_with_shared_access"].append({
                        "userId": grantee.get("id"),
                        "displayName": grantee.get("displayName"),
                        "email": grantee.get("emailAddress"),
                        "mailboxAccess": mailbox.get("mail"),
                        "permissionRole": perm.get("role")
                    })
        
        print(f"[+] Shared mailbox analysis complete")
        print(f"    Shared mailboxes: {len(results['shared_mailboxes'])}")
        print(f"    High-value mailboxes: {len(results['high_value_mailboxes'])}")
        print(f"    Mailbox permissions found: {len(results['mailbox_permissions'])}")
        
    except Exception as e:
        print(f"[!] Error identifying shared mailbox access: {e}")
    
    return results


def get_calendar_mailbox_delegations(access_token: str) -> dict:
    """
    Find delegated calendar and mailbox permissions.
    These can be exploited for lateral movement and information gathering.
    
    Requires: Calendars.Read, MailboxSettings.Read
    """
    print("\n[*] Finding delegated calendar and mailbox permissions...")
    
    results = {
        "calendar_delegates": [],
        "mailbox_delegates": [],
        "send_as_permissions": [],
        "send_on_behalf_permissions": [],
        "full_access_delegates": [],
        "high_risk_delegations": []
    }
    
    headers = {"Authorization": f"Bearer {access_token}"}
    
    try:
        # Get users to check for delegations
        print("    Fetching users to analyze...")
        users_url = f"{GRAPH_API_ENDPOINT}/users?$select=id,displayName,mail,userPrincipalName&$filter=accountEnabled eq true&$top=100"
        response = make_api_request(users_url, headers)
        
        users_to_check = []
        if response and response.status_code == 200:
            users_to_check = response.json().get("value", [])
        
        print(f"    Checking {len(users_to_check)} users for calendar delegations...")
        
        for user in users_to_check:
            if is_cancelled():
                return results
            
            user_id = user.get("id")
            user_mail = user.get("mail") or user.get("userPrincipalName")
            user_name = user.get("displayName")
            
            # Check calendar permissions
            calendar_url = f"{GRAPH_API_ENDPOINT}/users/{user_id}/calendar/calendarPermissions"
            cal_response = make_api_request(calendar_url, headers)
            
            if cal_response and cal_response.status_code == 200:
                cal_perms = cal_response.json().get("value", [])
                for perm in cal_perms:
                    # Skip default organization permission
                    if perm.get("isDefault", False):
                        continue
                    
                    email_address = perm.get("emailAddress", {})
                    delegate_email = email_address.get("address", "Unknown")
                    delegate_name = email_address.get("name", delegate_email)
                    role = perm.get("role", "unknown")
                    
                    # Determine risk level
                    risk_level = "LOW"
                    if role in ["write", "delegateWithPrivateEventAccess", "delegateWithoutPrivateEventAccess"]:
                        risk_level = "MEDIUM"
                    if role in ["write", "delegateWithPrivateEventAccess"]:
                        risk_level = "HIGH"
                    
                    delegation = {
                        "calendarOwner": user_name,
                        "calendarOwnerEmail": user_mail,
                        "delegateName": delegate_name,
                        "delegateEmail": delegate_email,
                        "permissionRole": role,
                        "allowedRoles": perm.get("allowedRoles", []),
                        "riskLevel": risk_level
                    }
                    
                    results["calendar_delegates"].append(delegation)
                    
                    if risk_level in ["HIGH", "CRITICAL"]:
                        results["high_risk_delegations"].append({
                            **delegation,
                            "delegationType": "Calendar"
                        })
            
            # Check mailbox settings for delegates
            mailbox_settings_url = f"{GRAPH_API_ENDPOINT}/users/{user_id}/mailboxSettings"
            mailbox_response = make_api_request(mailbox_settings_url, headers)
            
            if mailbox_response and mailbox_response.status_code == 200:
                mailbox_settings = mailbox_response.json()
                delegate_permissions = mailbox_settings.get("delegateMeetingMessageDeliveryOptions")
                
                if delegate_permissions and delegate_permissions != "sendToDelegateAndInformationToPrincipal":
                    results["mailbox_delegates"].append({
                        "mailboxOwner": user_name,
                        "mailboxOwnerEmail": user_mail,
                        "delegateDeliveryOption": delegate_permissions,
                        "riskLevel": "MEDIUM"
                    })
            
            # Try to get send-on-behalf permissions (beta API)
            send_on_behalf_url = f"{GRAPH_BETA_ENDPOINT}/users/{user_id}?$select=grantSendOnBehalfTo"
            sob_response = make_api_request(send_on_behalf_url, headers)
            
            if sob_response and sob_response.status_code == 200:
                sob_data = sob_response.json()
                send_on_behalf = sob_data.get("grantSendOnBehalfTo", [])
                
                for delegate in send_on_behalf:
                    results["send_on_behalf_permissions"].append({
                        "mailboxOwner": user_name,
                        "mailboxOwnerEmail": user_mail,
                        "delegateId": delegate.get("id"),
                        "delegateName": delegate.get("displayName"),
                        "delegateEmail": delegate.get("mail"),
                        "permissionType": "SendOnBehalf",
                        "riskLevel": "HIGH"
                    })
                    
                    results["high_risk_delegations"].append({
                        "calendarOwner": user_name,
                        "calendarOwnerEmail": user_mail,
                        "delegateName": delegate.get("displayName"),
                        "delegateEmail": delegate.get("mail"),
                        "permissionRole": "SendOnBehalf",
                        "delegationType": "Mailbox",
                        "riskLevel": "HIGH"
                    })
        
        print(f"[+] Delegation analysis complete")
        print(f"    Calendar delegates found: {len(results['calendar_delegates'])}")
        print(f"    Mailbox delegates found: {len(results['mailbox_delegates'])}")
        print(f"    Send-on-behalf permissions: {len(results['send_on_behalf_permissions'])}")
        print(f"    High-risk delegations: {len(results['high_risk_delegations'])}")
        
    except Exception as e:
        print(f"[!] Error finding calendar/mailbox delegations: {e}")
    
    return results


def get_lateral_movement_opportunities(access_token: str) -> dict:
    """
    Comprehensive lateral movement opportunity analysis.
    Combines all lateral movement vectors into a single assessment.
    
    This function identifies:
    - Transitive group memberships that provide indirect access
    - Shared mailbox access that could be exploited
    - Calendar/mailbox delegations for information gathering
    - Cross-tenant trust relationships
    - Application consent grants that allow impersonation
    """
    print("\n" + "=" * 80)
    print(f"{'LATERAL MOVEMENT OPPORTUNITY ANALYSIS':^80}")
    print("=" * 80)
    print("\nAnalyzing potential lateral movement vectors...")
    
    results = {
        "transitive_memberships": {},
        "shared_mailbox_access": {},
        "calendar_mailbox_delegations": {},
        "lateral_movement_paths": [],
        "summary": {
            "total_lateral_paths": 0,
            "critical_paths": 0,
            "high_paths": 0,
            "medium_paths": 0
        }
    }
    
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # 1. Get transitive group memberships
    print("\n--- Phase 1: Transitive Group Membership Analysis ---")
    results["transitive_memberships"] = get_transitive_group_memberships(access_token)
    
    # 2. Get shared mailbox access
    print("\n--- Phase 2: Shared Mailbox Access Analysis ---")
    results["shared_mailbox_access"] = get_shared_mailbox_access(access_token)
    
    # 3. Get calendar/mailbox delegations
    print("\n--- Phase 3: Calendar/Mailbox Delegation Analysis ---")
    results["calendar_mailbox_delegations"] = get_calendar_mailbox_delegations(access_token)
    
    # 4. Build lateral movement paths
    print("\n--- Phase 4: Building Lateral Movement Paths ---")
    
    # Path type 1: Transitive group access to privileged groups
    for user in results["transitive_memberships"].get("users_with_nested_access", []):
        path = {
            "pathType": "Transitive Group Membership",
            "sourceUser": user.get("userPrincipalName"),
            "sourceUserId": user.get("userId"),
            "targetResource": user.get("privilegedGroup"),
            "accessMethod": "Nested Group Membership",
            "riskLevel": user.get("riskLevel", "MEDIUM"),
            "description": f"User has indirect access to '{user.get('privilegedGroup')}' through group nesting",
            "remediation": "Flatten group structure or implement JIT access for privileged groups"
        }
        results["lateral_movement_paths"].append(path)
    
    # Path type 2: Shared mailbox access
    for perm in results["shared_mailbox_access"].get("mailbox_permissions", []):
        path = {
            "pathType": "Shared Mailbox Access",
            "sourceUser": perm.get("delegateName") or perm.get("delegateEmail"),
            "sourceUserId": perm.get("delegateId"),
            "targetResource": perm.get("mailboxEmail"),
            "accessMethod": f"Mailbox Permission ({perm.get('permissionRole')})",
            "riskLevel": perm.get("riskLevel", "MEDIUM"),
            "description": f"User can access shared mailbox '{perm.get('mailboxName')}'",
            "remediation": "Review shared mailbox permissions; implement audit logging"
        }
        results["lateral_movement_paths"].append(path)
    
    # Path type 3: Calendar delegations
    for delegation in results["calendar_mailbox_delegations"].get("high_risk_delegations", []):
        path = {
            "pathType": "Calendar/Mailbox Delegation",
            "sourceUser": delegation.get("delegateName") or delegation.get("delegateEmail"),
            "sourceUserId": None,
            "targetResource": delegation.get("calendarOwnerEmail"),
            "accessMethod": f"{delegation.get('delegationType')} Delegation ({delegation.get('permissionRole')})",
            "riskLevel": delegation.get("riskLevel", "MEDIUM"),
            "description": f"User has delegated access to {delegation.get('calendarOwner')}'s {delegation.get('delegationType', 'calendar')}",
            "remediation": "Review delegation permissions; implement periodic access reviews"
        }
        results["lateral_movement_paths"].append(path)
    
    # Path type 4: Send-on-behalf permissions
    for perm in results["calendar_mailbox_delegations"].get("send_on_behalf_permissions", []):
        path = {
            "pathType": "Send-On-Behalf Permission",
            "sourceUser": perm.get("delegateName") or perm.get("delegateEmail"),
            "sourceUserId": perm.get("delegateId"),
            "targetResource": perm.get("mailboxOwnerEmail"),
            "accessMethod": "Send-On-Behalf",
            "riskLevel": "HIGH",
            "description": f"User can send emails on behalf of {perm.get('mailboxOwner')}",
            "remediation": "Remove unnecessary send-on-behalf permissions"
        }
        results["lateral_movement_paths"].append(path)
    
    # Path type 5: Deeply nested groups (structural risk)
    for group in results["transitive_memberships"].get("deeply_nested_groups", []):
        if group.get("nestedGroupCount", 0) >= 2:
            path = {
                "pathType": "Complex Group Nesting",
                "sourceUser": f"{group.get('nestedGroupCount')} nested groups",
                "sourceUserId": None,
                "targetResource": group.get("groupName"),
                "accessMethod": "Multi-level Group Nesting",
                "riskLevel": "HIGH" if group.get("isRoleAssignable") else "MEDIUM",
                "description": f"Privileged group has {group.get('nestedGroupCount')} nested groups, {group.get('transitiveUserCount')} transitive members",
                "remediation": "Simplify group structure; use direct assignments for privileged groups"
            }
            results["lateral_movement_paths"].append(path)
    
    # Calculate summary
    results["summary"]["total_lateral_paths"] = len(results["lateral_movement_paths"])
    results["summary"]["critical_paths"] = sum(1 for p in results["lateral_movement_paths"] if p.get("riskLevel") == "CRITICAL")
    results["summary"]["high_paths"] = sum(1 for p in results["lateral_movement_paths"] if p.get("riskLevel") == "HIGH")
    results["summary"]["medium_paths"] = sum(1 for p in results["lateral_movement_paths"] if p.get("riskLevel") == "MEDIUM")
    
    print(f"\n[+] Lateral Movement Analysis Complete")
    print(f"    Total lateral movement paths: {results['summary']['total_lateral_paths']}")
    print(f"    CRITICAL risk paths: {results['summary']['critical_paths']}")
    print(f"    HIGH risk paths: {results['summary']['high_paths']}")
    print(f"    MEDIUM risk paths: {results['summary']['medium_paths']}")
    
    return results


def print_transitive_membership_report(results: dict) -> None:
    """Print a formatted transitive group membership report."""
    print("\n" + "=" * 120)
    print(f"{'TRANSITIVE GROUP MEMBERSHIP ANALYSIS':^120}")
    print("=" * 120)
    
    # Summary
    print(f"\n📊 SUMMARY:")
    print(f"   Total direct memberships: {results.get('total_direct_memberships', 0)}")
    print(f"   Total transitive memberships: {results.get('total_transitive_memberships', 0)}")
    print(f"   Groups with nested membership: {len(results.get('deeply_nested_groups', []))}")
    print(f"   Users with indirect privileged access: {len(results.get('users_with_nested_access', []))}")
    
    # Deeply nested groups
    nested_groups = results.get("deeply_nested_groups", [])
    if nested_groups:
        print(f"\n{'─' * 120}")
        print(f"{'🔗 PRIVILEGED GROUPS WITH NESTED MEMBERSHIP':^120}")
        print(f"{'─' * 120}")
        
        print(f"\n{'Group Name':<35} {'Direct':<8} {'Trans.':<8} {'Nested':<8} {'Role Grp?':<10} {'Nested Groups':<40} {'Risk':<8}")
        print("-" * 120)
        
        sorted_groups = sorted(nested_groups, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x.get("riskLevel", "LOW"), 3))
        
        for group in sorted_groups[:30]:
            name = (group.get("groupName") or "N/A")[:34]
            direct = str(group.get("directUserCount", 0))[:7]
            transitive = str(group.get("transitiveUserCount", 0))[:7]
            nested_count = str(group.get("nestedGroupCount", 0))[:7]
            role_assignable = "Yes" if group.get("isRoleAssignable") else "No"
            nested_names = ", ".join(group.get("nestedGroups", [])[:3])[:39]
            risk = group.get("riskLevel", "")
            
            print(f"{name:<35} {direct:<8} {transitive:<8} {nested_count:<8} {role_assignable:<10} {nested_names:<40} {risk:<8}")
        
        if len(nested_groups) > 30:
            print(f"    ... and {len(nested_groups) - 30} more groups")
        print("-" * 120)
    
    # Users with indirect access
    users_with_access = results.get("users_with_nested_access", [])
    if users_with_access:
        print(f"\n{'─' * 120}")
        print(f"{'👤 USERS WITH INDIRECT ACCESS TO PRIVILEGED GROUPS':^120}")
        print(f"{'─' * 120}")
        
        print("\n!!! These users have access to privileged groups through group nesting")
        
        print(f"\n{'Display Name':<25} {'User Principal Name':<40} {'Privileged Group':<35} {'Access':<12} {'Risk':<8}")
        print("-" * 120)
        
        sorted_users = sorted(users_with_access, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x.get("riskLevel", "LOW"), 3))
        
        for user in sorted_users[:40]:
            name = (user.get("displayName") or "N/A")[:24]
            upn = (user.get("userPrincipalName") or "N/A")[:39]
            priv_group = (user.get("privilegedGroup") or "N/A")[:34]
            access_type = (user.get("accessType") or "Direct")[:11]
            risk = user.get("riskLevel", "")
            
            print(f"{name:<25} {upn:<40} {priv_group:<35} {access_type:<12} {risk:<8}")
        
        if len(users_with_access) > 40:
            print(f"    ... and {len(users_with_access) - 40} more users")
        print("-" * 120)
    
    # Recommendations
    print("\n" + "=" * 120)
    print("🔧 REMEDIATION RECOMMENDATIONS:")
    print("=" * 120)
    print("\n1. Simplify Group Structure:")
    print("   - Flatten nested groups where possible")
    print("   - Use direct assignments for privileged group membership")
    print("   - Avoid role-assignable groups being members of other groups")
    print("\n2. Implement Access Reviews:")
    print("   - Enable regular access reviews for privileged groups")
    print("   - Review transitive memberships quarterly")
    print("\n3. Use Privileged Identity Management (PIM):")
    print("   - Require just-in-time activation for privileged group membership")
    print("   - Implement approval workflows for group access")


def print_shared_mailbox_report(results: dict) -> None:
    """Print a formatted shared mailbox access report."""
    print("\n" + "=" * 120)
    print(f"{'SHARED MAILBOX ACCESS ANALYSIS':^120}")
    print("=" * 120)
    
    # Summary
    print(f"\n📊 SUMMARY:")
    print(f"   Shared mailboxes identified: {len(results.get('shared_mailboxes', []))}")
    print(f"   High-value mailboxes: {len(results.get('high_value_mailboxes', []))}")
    print(f"   Mailbox permissions found: {len(results.get('mailbox_permissions', []))}")
    print(f"   Users with shared access: {len(results.get('users_with_shared_access', []))}")
    
    # High-value mailboxes
    high_value = results.get("high_value_mailboxes", [])
    if high_value:
        print(f"\n{'─' * 120}")
        print(f"{'⚠️  HIGH-VALUE SHARED MAILBOXES':^120}")
        print(f"{'─' * 120}")
        
        print("\n!!! These mailboxes may contain sensitive information")
        
        print(f"\n{'Display Name':<30} {'Email Address':<50} {'Enabled':<10} {'Risk':<8}")
        print("-" * 100)
        
        for mailbox in high_value[:20]:
            name = (mailbox.get("displayName") or "N/A")[:29]
            email = (mailbox.get("mail") or mailbox.get("userPrincipalName") or "N/A")[:49]
            enabled = "Yes" if mailbox.get("accountEnabled", True) else "No"
            
            print(f"{name:<30} {email:<50} {enabled:<10} CRITICAL")
        print("-" * 100)
    
    # All shared mailboxes
    shared_mailboxes = results.get("shared_mailboxes", [])
    if shared_mailboxes:
        print(f"\n{'─' * 120}")
        print(f"{'📬 ALL SHARED MAILBOXES':^120}")
        print(f"{'─' * 120}")
        
        print(f"\n{'Display Name':<30} {'Email Address':<50} {'Enabled':<10} {'Risk':<8}")
        print("-" * 100)
        
        sorted_mailboxes = sorted(shared_mailboxes, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x.get("riskLevel", "LOW"), 3))
        
        for mailbox in sorted_mailboxes[:40]:
            name = (mailbox.get("displayName") or "N/A")[:29]
            email = (mailbox.get("mail") or "N/A")[:49]
            enabled = "Yes" if mailbox.get("accountEnabled", True) else "No"
            risk = mailbox.get("riskLevel", "")
            
            print(f"{name:<30} {email:<50} {enabled:<10} {risk:<8}")
        
        if len(shared_mailboxes) > 40:
            print(f"    ... and {len(shared_mailboxes) - 40} more mailboxes")
        print("-" * 100)
    
    # Mailbox permissions
    permissions = results.get("mailbox_permissions", [])
    if permissions:
        print(f"\n{'─' * 120}")
        print(f"{'🔑 MAILBOX DELEGATE PERMISSIONS':^120}")
        print(f"{'─' * 120}")
        
        print(f"\n{'Mailbox':<30} {'Delegate':<30} {'Permission':<20} {'Risk':<8}")
        print("-" * 90)
        
        for perm in permissions[:30]:
            mailbox = (perm.get("mailboxName") or perm.get("mailboxEmail") or "N/A")[:29]
            delegate = (perm.get("delegateName") or perm.get("delegateEmail") or "N/A")[:29]
            permission = (perm.get("permissionRole") or "N/A")[:19]
            risk = perm.get("riskLevel", "")
            
            print(f"{mailbox:<30} {delegate:<30} {permission:<20} {risk:<8}")
        
        if len(permissions) > 30:
            print(f"    ... and {len(permissions) - 30} more permissions")
        print("-" * 90)


def print_calendar_delegation_report(results: dict) -> None:
    """Print a formatted calendar/mailbox delegation report."""
    print("\n" + "=" * 120)
    print(f"{'CALENDAR & MAILBOX DELEGATION ANALYSIS':^120}")
    print("=" * 120)
    
    # Summary
    print(f"\n📊 SUMMARY:")
    print(f"   Calendar delegates found: {len(results.get('calendar_delegates', []))}")
    print(f"   Mailbox delegates found: {len(results.get('mailbox_delegates', []))}")
    print(f"   Send-on-behalf permissions: {len(results.get('send_on_behalf_permissions', []))}")
    print(f"   High-risk delegations: {len(results.get('high_risk_delegations', []))}")
    
    # High-risk delegations
    high_risk = results.get("high_risk_delegations", [])
    if high_risk:
        print(f"\n{'─' * 120}")
        print(f"{'⚠️  HIGH-RISK DELEGATIONS':^120}")
        print(f"{'─' * 120}")
        
        print("\n!!! These delegations provide elevated access that could be exploited")
        
        print(f"\n{'Owner':<25} {'Delegate':<25} {'Type':<12} {'Permission':<20} {'Risk':<8}")
        print("-" * 95)
        
        sorted_delegations = sorted(high_risk, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x.get("riskLevel", "LOW"), 3))
        
        for delegation in sorted_delegations[:30]:
            owner = (delegation.get("calendarOwner") or "N/A")[:24]
            delegate = (delegation.get("delegateName") or delegation.get("delegateEmail") or "N/A")[:24]
            del_type = (delegation.get("delegationType") or "N/A")[:11]
            permission = (delegation.get("permissionRole") or "N/A")[:19]
            risk = delegation.get("riskLevel", "")
            
            print(f"{owner:<25} {delegate:<25} {del_type:<12} {permission:<20} {risk:<8}")
        
        if len(high_risk) > 30:
            print(f"    ... and {len(high_risk) - 30} more delegations")
        print("-" * 95)
    
    # Calendar delegates
    cal_delegates = results.get("calendar_delegates", [])
    if cal_delegates:
        print(f"\n{'─' * 120}")
        print(f"{'📅 CALENDAR DELEGATES':^120}")
        print(f"{'─' * 120}")
        
        print(f"\n{'Calendar Owner':<30} {'Delegate':<30} {'Permission Role':<25} {'Risk':<8}")
        print("-" * 95)
        
        for delegation in cal_delegates[:30]:
            owner = (delegation.get("calendarOwner") or "N/A")[:29]
            delegate = (delegation.get("delegateName") or delegation.get("delegateEmail") or "N/A")[:29]
            permission = (delegation.get("permissionRole") or "N/A")[:24]
            risk = delegation.get("riskLevel", "")
            
            print(f"{owner:<30} {delegate:<30} {permission:<25} {risk:<8}")
        
        if len(cal_delegates) > 30:
            print(f"    ... and {len(cal_delegates) - 30} more calendar delegates")
        print("-" * 95)
    
    # Send-on-behalf permissions
    sob_perms = results.get("send_on_behalf_permissions", [])
    if sob_perms:
        print(f"\n{'─' * 120}")
        print(f"{'📧 SEND-ON-BEHALF PERMISSIONS':^120}")
        print(f"{'─' * 120}")
        
        print("\n!!! These users can send emails impersonating the mailbox owner")
        
        print(f"\n{'Mailbox Owner':<30} {'Delegate':<30} {'Delegate Email':<35}")
        print("-" * 95)
        
        for perm in sob_perms[:20]:
            owner = (perm.get("mailboxOwner") or "N/A")[:29]
            delegate = (perm.get("delegateName") or "N/A")[:29]
            delegate_email = (perm.get("delegateEmail") or "N/A")[:34]
            
            print(f"{owner:<30} {delegate:<30} {delegate_email:<35}")
        
        if len(sob_perms) > 20:
            print(f"    ... and {len(sob_perms) - 20} more send-on-behalf permissions")
        print("-" * 95)
    
    # Recommendations
    print("\n" + "=" * 120)
    print("🔧 REMEDIATION RECOMMENDATIONS:")
    print("=" * 120)
    print("\n1. Review Calendar Delegations:")
    print("   - Audit all calendar delegates with write or delegate access")
    print("   - Remove unnecessary calendar sharing permissions")
    print("\n2. Mailbox Permissions:")
    print("   - Review send-on-behalf permissions for executive mailboxes")
    print("   - Enable mailbox audit logging for all delegated mailboxes")
    print("\n3. Monitoring:")
    print("   - Alert on new delegation assignments")
    print("   - Monitor mailbox access patterns for anomalies")


def print_lateral_movement_report(results: dict) -> None:
    """Print a comprehensive lateral movement opportunity report."""
    print("\n" + "=" * 120)
    print(f"{'LATERAL MOVEMENT OPPORTUNITY REPORT':^120}")
    print("=" * 120)
    
    # Executive Summary
    summary = results.get("summary", {})
    print(f"\n📊 EXECUTIVE SUMMARY:")
    print(f"   Total Lateral Movement Paths: {summary.get('total_lateral_paths', 0)}")
    print(f"   ⚠️  CRITICAL Risk Paths: {summary.get('critical_paths', 0)}")
    print(f"   ⚠️  HIGH Risk Paths: {summary.get('high_paths', 0)}")
    print(f"   MEDIUM Risk Paths: {summary.get('medium_paths', 0)}")
    
    # Component summaries
    trans_memberships = results.get("transitive_memberships", {})
    shared_mailbox = results.get("shared_mailbox_access", {})
    delegations = results.get("calendar_mailbox_delegations", {})
    
    print(f"\n📋 COMPONENT BREAKDOWN:")
    print(f"   Transitive Group Memberships: {len(trans_memberships.get('users_with_nested_access', []))} indirect access paths")
    print(f"   Shared Mailbox Access: {len(shared_mailbox.get('shared_mailboxes', []))} shared mailboxes")
    print(f"   Calendar/Mailbox Delegations: {len(delegations.get('high_risk_delegations', []))} high-risk delegations")
    
    # All lateral movement paths
    paths = results.get("lateral_movement_paths", [])
    if paths:
        print(f"\n{'─' * 120}")
        print(f"{'⚡ LATERAL MOVEMENT PATHS':^120}")
        print(f"{'─' * 120}")
        
        print(f"\n{'Path Type':<26} {'Source':<28} {'Target':<28} {'Method':<22} {'Risk':<8}")
        print("-" * 115)
        
        sorted_paths = sorted(paths, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("riskLevel", "LOW"), 4))
        
        for path in sorted_paths[:40]:
            path_type = (path.get("pathType") or "N/A")[:25]
            source = (path.get("sourceUser") or "N/A")[:27]
            target = (path.get("targetResource") or "N/A")[:27]
            method = (path.get("accessMethod") or "N/A")[:21]
            risk = path.get("riskLevel", "")
            
            print(f"{path_type:<26} {source:<28} {target:<28} {method:<22} {risk:<8}")
        
        if len(paths) > 40:
            print(f"    ... and {len(paths) - 40} more lateral movement paths")
        print("-" * 115)
    
    # Remediation Recommendations
    print("\n" + "=" * 120)
    print("🔧 REMEDIATION RECOMMENDATIONS:")
    print("=" * 120)
    
    print("\n1. Group Structure:")
    print("   - Flatten nested group hierarchies for privileged groups")
    print("   - Use direct role assignments instead of nested groups")
    print("   - Implement role-assignable groups with PIM for sensitive groups")
    
    print("\n2. Mailbox Security:")
    print("   - Audit all shared mailbox permissions")
    print("   - Remove unnecessary mailbox access")
    print("   - Enable mailbox auditing for sensitive mailboxes")
    
    print("\n3. Delegation Review:")
    print("   - Review all calendar delegates with elevated permissions")
    print("   - Audit send-on-behalf permissions for executive mailboxes")
    print("   - Implement access reviews for delegated permissions")
    
    print("\n4. Monitoring:")
    print("   - Enable Azure AD audit logs for group membership changes")
    print("   - Monitor for anomalous mailbox access patterns")
    print("   - Alert on new high-privilege delegations")


def print_admin_units_report(admin_units: list) -> None:
    """Print a formatted Administrative Units report."""
    print_security_summary(admin_units, "ADMINISTRATIVE UNITS ENUMERATION")
    
    print(f"{'AU Name':<30} {'Visibility':<12} {'Type':<10} {'Members':<10} {'Rule Processing':<18} {'Risk':<8}")
    print("-" * 110)
    
    for au in admin_units[:50]:
        name = (au.get("displayName") or "N/A")[:29]
        visibility = (au.get("visibility") or "N/A")[:11]
        membership_type = "Dynamic" if au.get("isDynamic") else "Assigned"
        members = str(au.get("memberCount", 0))[:9]
        rule_state = (au.get("membershipRuleProcessingState") or "N/A")[:17]
        risk = au.get("riskLevel", "")
        
        print(f"{name:<30} {visibility:<12} {membership_type:<10} {members:<10} {rule_state:<18} {risk:<8}")
    
    if len(admin_units) > 50:
        print(f"    ... and {len(admin_units) - 50} more")
    
    print("-" * 110)


def print_admin_unit_members_report(members: list) -> None:
    """Print a formatted AU members report."""
    print_security_summary(members, "ADMINISTRATIVE UNIT MEMBERS")
    
    print(f"{'Admin Unit':<25} {'Member Name':<25} {'UPN/Email':<35} {'Type':<10} {'Enabled':<8}")
    print("-" * 110)
    
    for member in members[:50]:
        au_name = (member.get("adminUnitName") or "N/A")[:24]
        name = (member.get("displayName") or "N/A")[:24]
        upn = (member.get("userPrincipalName") or member.get("mail") or "N/A")[:34]
        member_type = (member.get("memberType") or "N/A")[:9]
        enabled = "Yes" if member.get("accountEnabled", True) else "No"
        
        print(f"{au_name:<25} {name:<25} {upn:<35} {member_type:<10} {enabled:<8}")
    
    if len(members) > 50:
        print(f"    ... and {len(members) - 50} more")
    
    print("-" * 110)


def print_scoped_admins_report(scoped_admins: list) -> None:
    """Print a formatted scoped administrators report."""
    print_security_summary(scoped_admins, "SCOPED ROLE ASSIGNMENTS (AU ADMINISTRATORS)")
    
    print(f"{'Admin Unit':<22} {'Role':<28} {'Admin Name':<22} {'Admin UPN':<25} {'Risk':<8}")
    print("-" * 110)
    
    # Sort by risk level
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_admins = sorted(scoped_admins, key=lambda x: risk_order.get(x.get("riskLevel", "LOW"), 3))
    
    for admin in sorted_admins[:50]:
        au_name = (admin.get("adminUnitName") or "N/A")[:21]
        role = (admin.get("roleName") or "N/A")[:27]
        name = (admin.get("principalName") or "N/A")[:21]
        upn = (admin.get("principalUPN") or "N/A")[:24]
        risk = admin.get("riskLevel", "")
        
        print(f"{au_name:<22} {role:<28} {name:<22} {upn:<25} {risk:<8}")
    
    if len(scoped_admins) > 50:
        print(f"    ... and {len(scoped_admins) - 50} more")
    
    print("-" * 110)


def print_security_summary(data: list, title: str, show_risk: bool = True) -> None:
    """Print a formatted security assessment summary."""
    print("\n" + "=" * 110)
    print(f"{title:^110}")
    print("=" * 110)
    print(f"\nTotal items: {len(data)}\n")
    
    if show_risk and data:
        risk_counts = {}
        for item in data:
            risk = item.get("riskLevel", "UNKNOWN")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        print("Risk Distribution:")
        for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            if risk in risk_counts:
                color_indicator = "!!!" if risk in ["CRITICAL", "HIGH"] else ""
                print(f"  {color_indicator} {risk}: {risk_counts[risk]}")
    
    print("\n" + "-" * 110)


def print_mfa_status_report(users: list) -> None:
    """Print MFA status report with risk indicators."""
    print_security_summary(users, "MFA STATUS REPORT")
    
    print(f"{'Display Name':<25} {'Email/UPN':<40} {'MFA':<8} {'Methods':<25} {'Risk':<10}")
    print("-" * 110)
    
    # Sort by risk level
    risk_order = {"HIGH": 0, "UNKNOWN": 1, "LOW": 2}
    sorted_users = sorted(users, key=lambda x: risk_order.get(x.get("riskLevel", "UNKNOWN"), 3))
    
    for user in sorted_users:
        display_name = (user.get("displayName") or "N/A")[:24]
        email = (user.get("userPrincipalName") or user.get("mail") or "N/A")[:39]
        has_mfa = "Yes" if user.get("hasMFA") == True else ("No" if user.get("hasMFA") == False else "?")
        methods = (user.get("mfaMethods") or "")[:24]
        risk = user.get("riskLevel", "")
        
        print(f"{display_name:<25} {email:<40} {has_mfa:<8} {methods:<25} {risk:<10}")
    
    print("-" * 110)


def print_privileged_users_report(users: list) -> None:
    """Print privileged users report."""
    print_security_summary(users, "PRIVILEGED ROLE ASSIGNMENTS")
    
    print(f"{'Display Name':<25} {'Email/UPN':<35} {'Role':<30} {'Type':<12} {'Risk':<8}")
    print("-" * 110)
    
    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_users = sorted(users, key=lambda x: risk_order.get(x.get("riskLevel", "MEDIUM"), 4))
    
    for user in sorted_users:
        display_name = (user.get("displayName") or "N/A")[:24]
        email = (user.get("userPrincipalName") or user.get("mail") or "N/A")[:34]
        role = (user.get("role") or "N/A")[:29]
        assign_type = (user.get("assignmentType") or "Active")[:11]
        risk = user.get("riskLevel", "")
        
        print(f"{display_name:<25} {email:<35} {role:<30} {assign_type:<12} {risk:<8}")
    
    print("-" * 110)


def print_apps_report(data: dict) -> None:
    """Print applications and service principals report."""
    apps = data.get("applications", [])
    sps = data.get("service_principals", [])
    high_risk_apps = data.get("high_risk_apps", [])
    high_privilege_sps = data.get("high_privilege_sps", [])
    apps_with_creds = data.get("apps_with_credentials", [])
    
    print("\n" + "=" * 120)
    print(f"{'APPLICATION & SERVICE PRINCIPAL REPORT':^120}")
    print("=" * 120)
    
    print(f"\nApp Registrations: {len(apps)}")
    print(f"Service Principals (Enterprise Apps): {len(sps)}")
    print(f"Apps with Credentials (secrets/certs): {len(apps_with_creds)}")
    print(f"High-Risk App Registrations: {len(high_risk_apps)}")
    print(f"High-Privilege Service Principals: {len(high_privilege_sps)}")
    
    # HIGH-PRIVILEGE SERVICE PRINCIPALS (most dangerous - have granted permissions)
    if high_privilege_sps:
        print("\n" + "-" * 120)
        print("⚠️  HIGH-PRIVILEGE SERVICE PRINCIPALS (with dangerous application permissions):")
        print("-" * 120)
        print(f"{'Display Name':<30} {'Risk':<10} {'App Permissions':<45} {'Owners':<33}")
        print("-" * 120)
        
        # Sort by risk level
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_sps = sorted(high_privilege_sps, key=lambda x: risk_order.get(x.get("riskLevel", "LOW"), 4))
        
        for sp in sorted_sps[:25]:
            name = (sp.get("displayName") or "N/A")[:29]
            risk = (sp.get("riskLevel") or "N/A")[:9]
            perms = (sp.get("grantedAppPermissions") or "None")[:44]
            owners = (sp.get("owners") or "None")[:32]
            print(f"{name:<30} {risk:<10} {perms:<45} {owners:<33}")
        
        if len(high_privilege_sps) > 25:
            print(f"    ... and {len(high_privilege_sps) - 25} more high-privilege service principals")
    
    # HIGH-RISK APP REGISTRATIONS (requesting dangerous permissions)
    if high_risk_apps:
        print("\n" + "-" * 120)
        print("⚠️  HIGH-RISK APP REGISTRATIONS (requesting dangerous permissions):")
        print("-" * 120)
        print(f"{'Display Name':<30} {'Credentials':<12} {'App Permissions Requested':<40} {'Owners':<35}")
        print("-" * 120)
        
        for app in high_risk_apps[:20]:
            name = (app.get("displayName") or "N/A")[:29]
            creds = "Yes" if (app.get("hasSecrets") or app.get("hasCertificates")) else "No"
            creds_type = []
            if app.get("hasSecrets"):
                creds_type.append("S")
            if app.get("hasCertificates"):
                creds_type.append("C")
            creds_str = f"{creds}({','.join(creds_type)})" if creds_type else "No"
            perms = (app.get("requestedAppPermissions") or "None")[:39]
            owners = (app.get("owners") or "None")[:34]
            print(f"{name:<30} {creds_str:<12} {perms:<40} {owners:<35}")
        
        if len(high_risk_apps) > 20:
            print(f"    ... and {len(high_risk_apps) - 20} more high-risk apps")
    
    # APP REGISTRATIONS WITH SECRETS/CERTIFICATES
    if apps_with_creds:
        print("\n" + "-" * 120)
        print("APP REGISTRATIONS WITH SECRETS/CERTIFICATES:")
        print("-" * 120)
        print(f"{'Display Name':<30} {'App ID':<38} {'S':<3} {'C':<3} {'Credential Expiry':<25} {'Owners':<18}")
        print("-" * 120)
        
        for app in apps_with_creds[:25]:
            name = (app.get("displayName") or "N/A")[:29]
            app_id = (app.get("appId") or "N/A")[:37]
            secrets = "✓" if app.get("hasSecrets") else "-"
            certs = "✓" if app.get("hasCertificates") else "-"
            expires = (app.get("credentialDetails") or "N/A")[:24]
            owners = (app.get("owners") or "None")[:17]
            print(f"{name:<30} {app_id:<38} {secrets:<3} {certs:<3} {expires:<25} {owners:<18}")
        
        if len(apps_with_creds) > 25:
            print(f"    ... and {len(apps_with_creds) - 25} more apps with credentials")
    
    # ENTERPRISE APPLICATIONS WITH OWNERS (helpful for persistence/targeting)
    apps_with_owners = [s for s in sps if s.get("ownerCount", 0) > 0]
    if apps_with_owners:
        print("\n" + "-" * 120)
        print("ENTERPRISE APPLICATIONS WITH OWNERS:")
        print("-" * 120)
        print(f"{'Display Name':<35} {'Type':<15} {'App Permissions':<35} {'Owners':<32}")
        print("-" * 120)
        
        for sp in apps_with_owners[:20]:
            name = (sp.get("displayName") or "N/A")[:34]
            sp_type = (sp.get("type") or "N/A")[:14]
            perms = (sp.get("grantedAppPermissions") or "None")[:34]
            owners = (sp.get("owners") or "None")[:31]
            print(f"{name:<35} {sp_type:<15} {perms:<35} {owners:<32}")
        
        if len(apps_with_owners) > 20:
            print(f"    ... and {len(apps_with_owners) - 20} more")
    
    # APPLICATIONS WITH GRAPH API PERMISSIONS (both delegated and application)
    sps_with_graph_perms = [s for s in sps if s.get("appPermissionCount", 0) > 0 or s.get("delegatedPermissionCount", 0) > 0]
    if sps_with_graph_perms:
        print("\n" + "-" * 120)
        print("SERVICE PRINCIPALS WITH GRAPH API PERMISSIONS:")
        print("-" * 120)
        print(f"{'Display Name':<28} {'App Perms':<6} {'Delegated':<6} {'Application Permissions':<40} {'Delegated Permissions':<35}")
        print("-" * 120)
        
        # Sort by permission count
        sorted_by_perms = sorted(sps_with_graph_perms, key=lambda x: x.get("appPermissionCount", 0), reverse=True)
        
        for sp in sorted_by_perms[:25]:
            name = (sp.get("displayName") or "N/A")[:27]
            app_count = str(sp.get("appPermissionCount", 0))[:5]
            del_count = str(sp.get("delegatedPermissionCount", 0))[:5]
            app_perms = (sp.get("grantedAppPermissions") or "None")[:39]
            del_perms = (sp.get("delegatedPermissions") or "None")[:34]
            print(f"{name:<28} {app_count:<6} {del_count:<6} {app_perms:<40} {del_perms:<35}")
        
        if len(sps_with_graph_perms) > 25:
            print(f"    ... and {len(sps_with_graph_perms) - 25} more with Graph permissions")
    
    print("-" * 120)


def print_stale_accounts_report(users: list) -> None:
    """Print stale accounts report."""
    print_security_summary(users, "STALE ACCOUNTS REPORT")
    
    print(f"{'Display Name':<25} {'Email/UPN':<38} {'Last Sign-In':<14} {'Days':<8} {'Enabled':<8} {'Risk':<10}")
    print("-" * 110)
    
    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_users = sorted(users, key=lambda x: risk_order.get(x.get("riskLevel", "MEDIUM"), 4))
    
    for user in sorted_users:
        display_name = (user.get("displayName") or "N/A")[:24]
        email = (user.get("userPrincipalName") or user.get("mail") or "N/A")[:37]
        last_sign_in = str(user.get("lastSignIn", "Never"))[:13]
        days = str(user.get("daysInactive", "N/A"))[:7]
        enabled = "Yes" if user.get("accountEnabled", True) else "No"
        risk = user.get("riskLevel", "")
        
        print(f"{display_name:<25} {email:<38} {last_sign_in:<14} {days:<8} {enabled:<8} {risk:<10}")
    
    print("-" * 110)


# ============================================================================
# POWER PLATFORM ENUMERATION
# ============================================================================

def get_power_platform_token(graph_token: str) -> Optional[str]:
    """
    Attempt to acquire a token for Power Platform APIs.
    Uses the Graph token to try exchanging for Power Platform access.
    
    Note: This may require additional consent for Power Platform scopes.
    In many tenants, the same token works for basic Power Platform enumeration.
    """
    # First try using the Graph token directly (works in many scenarios)
    # The Power Platform APIs accept Graph tokens for basic operations
    return graph_token


def get_power_apps(access_token: str) -> list:
    """
    Enumerate Power Apps in the tenant.
    Returns apps with owner/user information for security assessment.
    
    Attempts multiple API endpoints for maximum coverage.
    """
    print("\n[*] Enumerating Power Apps...")
    
    all_apps = []
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Method 1: Try PowerApps Admin API (requires admin permissions)
    print("    [*] Trying Power Apps Admin API...")
    try:
        # Get environments first
        env_url = f"{POWERAPPS_API_ENDPOINT}/providers/Microsoft.PowerApps/scopes/admin/environments?api-version=2016-11-01"
        env_response = requests.get(env_url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if env_response.status_code == 200:
            environments = env_response.json().get("value", [])
            print(f"    [+] Found {len(environments)} Power Platform environments")
            
            for env in environments:
                env_name = env.get("name", "")
                env_display = env.get("properties", {}).get("displayName", env_name)
                
                # Get apps in this environment
                apps_url = f"{POWERAPPS_API_ENDPOINT}/providers/Microsoft.PowerApps/scopes/admin/environments/{env_name}/apps?api-version=2016-11-01"
                apps_response = requests.get(apps_url, headers=headers, timeout=REQUEST_TIMEOUT)
                
                if apps_response.status_code == 200:
                    apps = apps_response.json().get("value", [])
                    for app in apps:
                        props = app.get("properties", {})
                        app_info = {
                            "id": app.get("name", ""),
                            "displayName": props.get("displayName", "Unknown"),
                            "environment": env_display,
                            "environmentId": env_name,
                            "owner": props.get("owner", {}).get("displayName", "Unknown"),
                            "ownerEmail": props.get("owner", {}).get("email", ""),
                            "ownerId": props.get("owner", {}).get("id", ""),
                            "createdTime": props.get("createdTime", ""),
                            "lastModifiedTime": props.get("lastModifiedTime", ""),
                            "appType": props.get("appType", ""),
                            "status": props.get("status", ""),
                            "sharedUsers": [],
                            "sharedGroups": [],
                            "connectorCount": len(props.get("connectionReferences", {})),
                            "connectors": list(props.get("connectionReferences", {}).keys()),
                            "source": "AdminAPI"
                        }
                        
                        # Try to get sharing information
                        permissions_url = f"{POWERAPPS_API_ENDPOINT}/providers/Microsoft.PowerApps/scopes/admin/environments/{env_name}/apps/{app.get('name')}/permissions?api-version=2016-11-01"
                        try:
                            perms_response = requests.get(permissions_url, headers=headers, timeout=REQUEST_TIMEOUT)
                            if perms_response.status_code == 200:
                                permissions = perms_response.json().get("value", [])
                                for perm in permissions:
                                    perm_props = perm.get("properties", {})
                                    principal = perm_props.get("principal", {})
                                    perm_type = principal.get("type", "")
                                    
                                    if perm_type == "User":
                                        app_info["sharedUsers"].append({
                                            "displayName": principal.get("displayName", ""),
                                            "email": principal.get("email", ""),
                                            "id": principal.get("id", ""),
                                            "roleName": perm_props.get("roleName", "")
                                        })
                                    elif perm_type == "Group":
                                        app_info["sharedGroups"].append({
                                            "displayName": principal.get("displayName", ""),
                                            "id": principal.get("id", ""),
                                            "roleName": perm_props.get("roleName", "")
                                        })
                        except:
                            pass
                        
                        all_apps.append(app_info)
                        
            if all_apps:
                print(f"    [+] Found {len(all_apps)} Power Apps via Admin API")
        else:
            print(f"    [-] Admin API access denied (HTTP {env_response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"    [-] Admin API failed: {e}")
    except Exception as e:
        print(f"    [-] Error with Admin API: {e}")
    
    # Method 2: Try user-scoped PowerApps API (works for apps user has access to)
    if not all_apps:
        print("    [*] Trying user-scoped Power Apps API...")
        try:
            user_apps_url = f"{POWERAPPS_API_ENDPOINT}/providers/Microsoft.PowerApps/apps?api-version=2016-11-01"
            user_response = requests.get(user_apps_url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if user_response.status_code == 200:
                apps = user_response.json().get("value", [])
                for app in apps:
                    props = app.get("properties", {})
                    app_info = {
                        "id": app.get("name", ""),
                        "displayName": props.get("displayName", "Unknown"),
                        "environment": props.get("environment", {}).get("name", ""),
                        "environmentId": props.get("environment", {}).get("id", ""),
                        "owner": props.get("owner", {}).get("displayName", "Unknown"),
                        "ownerEmail": props.get("owner", {}).get("email", ""),
                        "ownerId": props.get("owner", {}).get("id", ""),
                        "createdTime": props.get("createdTime", ""),
                        "lastModifiedTime": props.get("lastModifiedTime", ""),
                        "appType": props.get("appType", ""),
                        "status": props.get("status", ""),
                        "sharedUsers": [],
                        "sharedGroups": [],
                        "connectorCount": len(props.get("connectionReferences", {})),
                        "connectors": list(props.get("connectionReferences", {}).keys()),
                        "source": "UserAPI"
                    }
                    all_apps.append(app_info)
                    
                if all_apps:
                    print(f"    [+] Found {len(all_apps)} Power Apps via User API")
            else:
                print(f"    [-] User API access denied (HTTP {user_response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"    [-] User API failed: {e}")
        except Exception as e:
            print(f"    [-] Error with User API: {e}")
    
    # Method 3: Try via Graph API for Power Platform (limited info)
    if not all_apps:
        print("    [*] Trying Graph API for Power Platform metadata...")
        try:
            # Try getting Power Platform environment info via Graph
            graph_url = f"{GRAPH_BETA_ENDPOINT}/admin/powerPlatform/environments"
            graph_response = requests.get(graph_url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if graph_response.status_code == 200:
                envs = graph_response.json().get("value", [])
                print(f"    [+] Found {len(envs)} environments via Graph API")
                # Note: This endpoint provides limited app details
                for env in envs:
                    app_info = {
                        "id": env.get("id", ""),
                        "displayName": f"Environment: {env.get('displayName', 'Unknown')}",
                        "environment": env.get("displayName", ""),
                        "environmentId": env.get("id", ""),
                        "owner": "N/A",
                        "ownerEmail": "",
                        "ownerId": "",
                        "createdTime": env.get("createdDateTime", ""),
                        "lastModifiedTime": "",
                        "appType": "Environment",
                        "status": env.get("status", ""),
                        "sharedUsers": [],
                        "sharedGroups": [],
                        "connectorCount": 0,
                        "connectors": [],
                        "source": "GraphAPI"
                    }
                    all_apps.append(app_info)
            else:
                print(f"    [-] Graph API Power Platform access denied (HTTP {graph_response.status_code})")
        except:
            print("    [-] Graph API Power Platform not accessible")
    
    if not all_apps:
        print("    [!] No Power Apps found or access denied.")
        print("    Note: Requires Power Platform Admin or Environment Maker permissions")
    
    return all_apps


def get_power_automate_flows(access_token: str) -> list:
    """
    Enumerate Power Automate flows and identify those with sensitive connectors.
    Returns flows with risk assessment based on connectors used.
    """
    print("\n[*] Enumerating Power Automate Flows...")
    
    all_flows = []
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Method 1: Try Flow Admin API
    print("    [*] Trying Power Automate Admin API...")
    try:
        # Get environments
        env_url = f"{FLOW_API_ENDPOINT}/providers/Microsoft.ProcessSimple/scopes/admin/environments?api-version=2016-11-01"
        env_response = requests.get(env_url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if env_response.status_code == 200:
            environments = env_response.json().get("value", [])
            print(f"    [+] Found {len(environments)} environments")
            
            for env in environments:
                env_name = env.get("name", "")
                env_display = env.get("properties", {}).get("displayName", env_name)
                
                # Get flows in this environment
                flows_url = f"{FLOW_API_ENDPOINT}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{env_name}/flows?api-version=2016-11-01"
                flows_response = requests.get(flows_url, headers=headers, timeout=REQUEST_TIMEOUT)
                
                if flows_response.status_code == 200:
                    flows = flows_response.json().get("value", [])
                    for flow in flows:
                        props = flow.get("properties", {})
                        
                        # Extract connector information
                        connectors_used = []
                        sensitive_connectors = []
                        connection_refs = props.get("connectionReferences", {})
                        
                        for conn_id, conn_info in connection_refs.items():
                            conn_type = conn_info.get("id", "").split("/")[-1].lower() if conn_info.get("id") else conn_id.lower()
                            conn_name = conn_info.get("displayName", conn_type)
                            connectors_used.append({
                                "id": conn_type,
                                "name": conn_name,
                                "connectionId": conn_info.get("connectionId", "")
                            })
                            
                            # Check if it's a sensitive connector
                            if conn_type in SENSITIVE_CONNECTORS:
                                sensitive_info = SENSITIVE_CONNECTORS[conn_type]
                                sensitive_connectors.append({
                                    "connectorId": conn_type,
                                    "displayName": sensitive_info["name"],
                                    "risk": sensitive_info["risk"],
                                    "category": sensitive_info["category"]
                                })
                        
                        # Determine overall risk level
                        risk_level = "LOW"
                        if any(c["risk"] == "CRITICAL" for c in sensitive_connectors):
                            risk_level = "CRITICAL"
                        elif any(c["risk"] == "HIGH" for c in sensitive_connectors):
                            risk_level = "HIGH"
                        elif any(c["risk"] == "MEDIUM" for c in sensitive_connectors):
                            risk_level = "MEDIUM"
                        
                        flow_info = {
                            "id": flow.get("name", ""),
                            "displayName": props.get("displayName", "Unknown"),
                            "environment": env_display,
                            "environmentId": env_name,
                            "owner": props.get("creator", {}).get("userDisplayName", "Unknown"),
                            "ownerEmail": props.get("creator", {}).get("userPrincipalName", ""),
                            "ownerId": props.get("creator", {}).get("userId", ""),
                            "createdTime": props.get("createdTime", ""),
                            "lastModifiedTime": props.get("lastModifiedTime", ""),
                            "state": props.get("state", ""),
                            "flowType": props.get("definitionSummary", {}).get("type", ""),
                            "triggers": [t.get("type", "") for t in props.get("definitionSummary", {}).get("triggers", [])],
                            "connectorCount": len(connectors_used),
                            "connectors": connectors_used,
                            "sensitiveConnectors": sensitive_connectors,
                            "riskLevel": risk_level,
                            "hasSensitiveConnector": len(sensitive_connectors) > 0,
                            "source": "AdminAPI"
                        }
                        all_flows.append(flow_info)
                        
            if all_flows:
                print(f"    [+] Found {len(all_flows)} flows via Admin API")
        else:
            print(f"    [-] Admin API access denied (HTTP {env_response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"    [-] Admin API failed: {e}")
    except Exception as e:
        print(f"    [-] Error with Admin API: {e}")
    
    # Method 2: Try user-scoped Flow API
    if not all_flows:
        print("    [*] Trying user-scoped Power Automate API...")
        try:
            user_flows_url = f"{FLOW_API_ENDPOINT}/providers/Microsoft.ProcessSimple/flows?api-version=2016-11-01"
            user_response = requests.get(user_flows_url, headers=headers, timeout=REQUEST_TIMEOUT)
            
            if user_response.status_code == 200:
                flows = user_response.json().get("value", [])
                for flow in flows:
                    props = flow.get("properties", {})
                    
                    # Extract connector information
                    connectors_used = []
                    sensitive_connectors = []
                    connection_refs = props.get("connectionReferences", {})
                    
                    for conn_id, conn_info in connection_refs.items():
                        conn_type = conn_info.get("id", "").split("/")[-1].lower() if conn_info.get("id") else conn_id.lower()
                        conn_name = conn_info.get("displayName", conn_type)
                        connectors_used.append({
                            "id": conn_type,
                            "name": conn_name,
                            "connectionId": conn_info.get("connectionId", "")
                        })
                        
                        if conn_type in SENSITIVE_CONNECTORS:
                            sensitive_info = SENSITIVE_CONNECTORS[conn_type]
                            sensitive_connectors.append({
                                "connectorId": conn_type,
                                "displayName": sensitive_info["name"],
                                "risk": sensitive_info["risk"],
                                "category": sensitive_info["category"]
                            })
                    
                    risk_level = "LOW"
                    if any(c["risk"] == "CRITICAL" for c in sensitive_connectors):
                        risk_level = "CRITICAL"
                    elif any(c["risk"] == "HIGH" for c in sensitive_connectors):
                        risk_level = "HIGH"
                    elif any(c["risk"] == "MEDIUM" for c in sensitive_connectors):
                        risk_level = "MEDIUM"
                    
                    flow_info = {
                        "id": flow.get("name", ""),
                        "displayName": props.get("displayName", "Unknown"),
                        "environment": props.get("environment", {}).get("name", ""),
                        "environmentId": props.get("environment", {}).get("id", ""),
                        "owner": props.get("creator", {}).get("userDisplayName", "Unknown"),
                        "ownerEmail": props.get("creator", {}).get("userPrincipalName", ""),
                        "ownerId": props.get("creator", {}).get("userId", ""),
                        "createdTime": props.get("createdTime", ""),
                        "lastModifiedTime": props.get("lastModifiedTime", ""),
                        "state": props.get("state", ""),
                        "flowType": props.get("definitionSummary", {}).get("type", ""),
                        "triggers": [t.get("type", "") for t in props.get("definitionSummary", {}).get("triggers", [])],
                        "connectorCount": len(connectors_used),
                        "connectors": connectors_used,
                        "sensitiveConnectors": sensitive_connectors,
                        "riskLevel": risk_level,
                        "hasSensitiveConnector": len(sensitive_connectors) > 0,
                        "source": "UserAPI"
                    }
                    all_flows.append(flow_info)
                    
                if all_flows:
                    print(f"    [+] Found {len(all_flows)} flows via User API")
            else:
                print(f"    [-] User API access denied (HTTP {user_response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"    [-] User API failed: {e}")
        except Exception as e:
            print(f"    [-] Error with User API: {e}")
    
    if not all_flows:
        print("    [!] No flows found or access denied.")
        print("    Note: Requires Power Automate Admin or flow owner permissions")
    else:
        # Summary
        sensitive_count = sum(1 for f in all_flows if f.get("hasSensitiveConnector"))
        if sensitive_count > 0:
            print(f"    [!] {sensitive_count} flows have sensitive connectors!")
    
    return all_flows


def print_power_apps_report(apps: list) -> None:
    """Print Power Apps enumeration report."""
    print("\n" + "=" * 120)
    print(f"{'POWER APPS ENUMERATION REPORT':^120}")
    print("=" * 120)
    
    if not apps:
        print("\n[!] No Power Apps found or access denied.")
        return
    
    # Summary
    unique_owners = set(a.get("ownerEmail") for a in apps if a.get("ownerEmail"))
    environments = set(a.get("environment") for a in apps if a.get("environment"))
    shared_apps = [a for a in apps if a.get("sharedUsers") or a.get("sharedGroups")]
    
    print("\n📊 SUMMARY:")
    print(f"   Total Power Apps: {len(apps)}")
    print(f"   Unique Environments: {len(environments)}")
    print(f"   Unique Owners: {len(unique_owners)}")
    print(f"   Shared Apps: {len(shared_apps)}")
    
    # Apps by environment
    print(f"\n{'─' * 120}")
    print(f"{'POWER APPS BY ENVIRONMENT':^120}")
    print(f"{'─' * 120}")
    
    print(f"\n{'App Name':<35} {'Owner':<30} {'Environment':<25} {'Connectors':<8} {'Status':<12}")
    print("-" * 120)
    
    for app in apps[:50]:
        name = (app.get("displayName") or "N/A")[:34]
        owner = (app.get("owner") or app.get("ownerEmail") or "N/A")[:29]
        env = (app.get("environment") or "N/A")[:24]
        conns = str(app.get("connectorCount", 0))
        status = (app.get("status") or "N/A")[:11]
        
        print(f"{name:<35} {owner:<30} {env:<25} {conns:<8} {status:<12}")
    
    if len(apps) > 50:
        print(f"    ... and {len(apps) - 50} more apps")
    
    # Apps with sharing
    if shared_apps:
        print(f"\n{'─' * 120}")
        print(f"{'SHARED POWER APPS (Potential Data Access)':^120}")
        print(f"{'─' * 120}")
        
        print(f"\n{'App Name':<30} {'Owner':<25} {'Shared Users':<35} {'Shared Groups':<28}")
        print("-" * 120)
        
        for app in shared_apps[:30]:
            name = (app.get("displayName") or "N/A")[:29]
            owner = (app.get("owner") or "N/A")[:24]
            
            shared_users_list = app.get("sharedUsers", [])
            shared_users = ", ".join([u.get("displayName", u.get("email", ""))[:15] for u in shared_users_list[:3]])
            if len(shared_users_list) > 3:
                shared_users += f" +{len(shared_users_list)-3}"
            shared_users = shared_users[:34] if shared_users else "None"
            
            shared_groups_list = app.get("sharedGroups", [])
            shared_groups = ", ".join([g.get("displayName", "")[:12] for g in shared_groups_list[:2]])
            if len(shared_groups_list) > 2:
                shared_groups += f" +{len(shared_groups_list)-2}"
            shared_groups = shared_groups[:27] if shared_groups else "None"
            
            print(f"{name:<30} {owner:<25} {shared_users:<35} {shared_groups:<28}")
    
    # Unique owners list
    if unique_owners:
        print(f"\n{'─' * 120}")
        print(f"{'POWER APP OWNERS':^120}")
        print(f"{'─' * 120}")
        
        # Group by owner
        owner_apps = {}
        for app in apps:
            owner_email = app.get("ownerEmail") or app.get("owner") or "Unknown"
            if owner_email not in owner_apps:
                owner_apps[owner_email] = []
            owner_apps[owner_email].append(app.get("displayName", "Unknown"))
        
        print(f"\n{'Owner':<45} {'App Count':<12} {'Apps':<60}")
        print("-" * 120)
        
        for owner, app_list in sorted(owner_apps.items(), key=lambda x: len(x[1]), reverse=True)[:25]:
            owner_display = owner[:44]
            count = len(app_list)
            apps_display = ", ".join(app_list[:3])[:57]
            if len(app_list) > 3:
                apps_display += f" +{len(app_list)-3}"
            
            print(f"{owner_display:<45} {count:<12} {apps_display:<60}")
    
    print("-" * 120)
    
    # Security Recommendations
    print("\n💡 SECURITY RECOMMENDATIONS:")
    print("   • Review app sharing permissions - overly shared apps increase data exposure")
    print("   • Audit apps with HTTP/Custom connectors - potential data exfiltration vectors")
    print("   • Verify app owners still require access")
    print("   • Implement DLP policies to control connector usage")


def print_power_automate_flows_report(flows: list) -> None:
    """Print Power Automate Flows enumeration report with sensitive connector analysis."""
    print("\n" + "=" * 120)
    print(f"{'POWER AUTOMATE FLOWS - SENSITIVE CONNECTOR ANALYSIS':^120}")
    print("=" * 120)
    
    if not flows:
        print("\n[!] No Power Automate flows found or access denied.")
        return
    
    # Summary
    sensitive_flows = [f for f in flows if f.get("hasSensitiveConnector")]
    critical_flows = [f for f in flows if f.get("riskLevel") == "CRITICAL"]
    high_risk_flows = [f for f in flows if f.get("riskLevel") == "HIGH"]
    unique_owners = set(f.get("ownerEmail") for f in flows if f.get("ownerEmail"))
    
    print("\n📊 EXECUTIVE SUMMARY:")
    print(f"   Total Flows: {len(flows)}")
    print(f"   ⚠️  Flows with Sensitive Connectors: {len(sensitive_flows)}")
    print(f"   🔴 CRITICAL Risk Flows: {len(critical_flows)}")
    print(f"   🟠 HIGH Risk Flows: {len(high_risk_flows)}")
    print(f"   Unique Flow Owners: {len(unique_owners)}")
    
    # CRITICAL and HIGH risk flows first
    if critical_flows or high_risk_flows:
        print(f"\n{'─' * 120}")
        print(f"{'🚨 HIGH/CRITICAL RISK FLOWS (Review Immediately)':^120}")
        print(f"{'─' * 120}")
        
        print(f"\n{'Flow Name':<30} {'Owner':<25} {'Risk':<10} {'Sensitive Connectors':<52}")
        print("-" * 120)
        
        for flow in (critical_flows + high_risk_flows)[:30]:
            name = (flow.get("displayName") or "N/A")[:29]
            owner = (flow.get("owner") or flow.get("ownerEmail") or "N/A")[:24]
            risk = flow.get("riskLevel", "N/A")
            
            sensitive = flow.get("sensitiveConnectors", [])
            connectors = ", ".join([f"{c['displayName']}({c['risk']})" for c in sensitive[:3]])[:51]
            if len(sensitive) > 3:
                connectors += f" +{len(sensitive)-3}"
            
            color_prefix = "!!! " if risk == "CRITICAL" else "!  "
            print(f"{color_prefix}{name:<26} {owner:<25} {risk:<10} {connectors:<52}")
        
        if len(critical_flows) + len(high_risk_flows) > 30:
            print(f"    ... and {len(critical_flows) + len(high_risk_flows) - 30} more high-risk flows")
    
    # All flows with any sensitive connectors
    if sensitive_flows:
        print(f"\n{'─' * 120}")
        print(f"{'ALL FLOWS WITH SENSITIVE CONNECTORS':^120}")
        print(f"{'─' * 120}")
        
        print(f"\n{'Flow Name':<28} {'Owner':<23} {'State':<10} {'Risk':<8} {'Connectors':<48}")
        print("-" * 120)
        
        for flow in sensitive_flows[:50]:
            name = (flow.get("displayName") or "N/A")[:27]
            owner = (flow.get("owner") or flow.get("ownerEmail") or "N/A")[:22]
            state = (flow.get("state") or "N/A")[:9]
            risk = flow.get("riskLevel", "N/A")[:7]
            
            sensitive = flow.get("sensitiveConnectors", [])
            connectors = ", ".join([c['displayName'] for c in sensitive[:4]])[:47]
            if len(sensitive) > 4:
                connectors += f" +{len(sensitive)-4}"
            
            print(f"{name:<28} {owner:<23} {state:<10} {risk:<8} {connectors:<48}")
        
        if len(sensitive_flows) > 50:
            print(f"    ... and {len(sensitive_flows) - 50} more flows with sensitive connectors")
    
    # Sensitive connector usage summary
    connector_usage = {}
    for flow in flows:
        for conn in flow.get("sensitiveConnectors", []):
            conn_name = conn.get("displayName", "Unknown")
            if conn_name not in connector_usage:
                connector_usage[conn_name] = {
                    "count": 0,
                    "risk": conn.get("risk", ""),
                    "category": conn.get("category", ""),
                    "flows": []
                }
            connector_usage[conn_name]["count"] += 1
            connector_usage[conn_name]["flows"].append(flow.get("displayName", "Unknown"))
    
    if connector_usage:
        print(f"\n{'─' * 120}")
        print(f"{'SENSITIVE CONNECTOR USAGE SUMMARY':^120}")
        print(f"{'─' * 120}")
        
        print(f"\n{'Connector':<35} {'Category':<15} {'Risk':<10} {'Flow Count':<12} {'Example Flows':<45}")
        print("-" * 120)
        
        for conn_name, data in sorted(connector_usage.items(), key=lambda x: x[1]["count"], reverse=True):
            name = conn_name[:34]
            category = data["category"][:14]
            risk = data["risk"][:9]
            count = str(data["count"])
            examples = ", ".join(data["flows"][:2])[:42]
            if len(data["flows"]) > 2:
                examples += f" +{len(data['flows'])-2}"
            
            print(f"{name:<35} {category:<15} {risk:<10} {count:<12} {examples:<45}")
    
    # Flow owners with sensitive flows
    if sensitive_flows:
        print(f"\n{'─' * 120}")
        print(f"{'FLOW OWNERS WITH SENSITIVE CONNECTORS':^120}")
        print(f"{'─' * 120}")
        
        owner_sensitive = {}
        for flow in sensitive_flows:
            owner = flow.get("ownerEmail") or flow.get("owner") or "Unknown"
            if owner not in owner_sensitive:
                owner_sensitive[owner] = {"critical": 0, "high": 0, "medium": 0, "flows": []}
            
            risk = flow.get("riskLevel", "").lower()
            if risk in owner_sensitive[owner]:
                owner_sensitive[owner][risk] += 1
            owner_sensitive[owner]["flows"].append(flow.get("displayName", "Unknown"))
        
        print(f"\n{'Owner':<40} {'Critical':<10} {'High':<10} {'Medium':<10} {'Total Flows':<12}")
        print("-" * 85)
        
        for owner, data in sorted(owner_sensitive.items(), key=lambda x: x[1]["critical"] + x[1]["high"], reverse=True)[:20]:
            owner_display = owner[:39]
            critical = str(data["critical"])
            high = str(data["high"])
            medium = str(data["medium"])
            total = str(len(data["flows"]))
            
            print(f"{owner_display:<40} {critical:<10} {high:<10} {medium:<10} {total:<12}")
    
    print("-" * 120)
    
    # Security Recommendations
    print("\n💡 SECURITY RECOMMENDATIONS:")
    print("   • Review CRITICAL risk flows immediately - HTTP/Key Vault/Azure AD connectors can exfiltrate data")
    print("   • Audit flows with database connectors - potential for bulk data extraction")
    print("   • Implement DLP policies to block/restrict sensitive connectors")
    print("   • Review flow owners and ensure least privilege access")
    print("   • Monitor flow run history for suspicious activity")
    print("   • Consider implementing approval flows for sensitive operations")


# ============================================================================
# ENUMERATION ORCHESTRATION
# ============================================================================

def enumerate_basic_methods(access_token: str) -> dict:
    """Run basic alternative enumeration methods."""
    print("\n" + "=" * 60)
    print("BASIC ALTERNATIVE ENUMERATION")
    print("=" * 60)
    
    results = {
        "people": get_people(access_token),
        "managers": get_manager_chain(access_token),
        "direct_reports": get_direct_reports(access_token),
        "group_members": get_group_members(access_token),
    }
    
    return results


def enumerate_advanced_methods(access_token: str) -> dict:
    """Run advanced fallback enumeration methods."""
    print("\n" + "=" * 60)
    print("ADVANCED FALLBACK ENUMERATION")
    print("=" * 60)
    
    results = {
        "search_api": get_users_via_search_api(access_token),
        "calendar": get_users_from_calendar(access_token),
        "email": get_users_from_emails(access_token),
        "onedrive": get_users_from_onedrive_sharing(access_token),
        "teams": get_users_from_teams(access_token),
        "planner": get_users_from_planner(access_token),
        "sharepoint": get_users_from_sharepoint_profiles(access_token),
        "azure_rm": get_users_from_azure_rm(access_token),
        "rooms": get_room_lists_and_rooms(access_token),
        "yammer": get_users_from_yammer(access_token),
    }
    
    return results


def enumerate_all_methods(access_token: str) -> dict:
    """Run all enumeration methods."""
    print("\n" + "=" * 60)
    print("FULL ENUMERATION - ALL METHODS")
    print("=" * 60)
    
    # Direct endpoint first
    print("\n[*] Trying direct /users endpoint...")
    direct_users = get_users(access_token)
    if direct_users:
        print(f"[+] Found {len(direct_users)} users via direct endpoint")
    
    # Basic methods
    basic_results = enumerate_basic_methods(access_token)
    
    # Advanced methods
    advanced_results = enumerate_advanced_methods(access_token)
    
    # Combine all
    all_results = {"direct": direct_users}
    all_results.update(basic_results)
    all_results.update(advanced_results)
    
    return all_results


def merge_user_results(results: dict) -> list:
    """Merge users from all enumeration methods, deduplicating by ID or email."""
    seen_ids = set()
    seen_emails = set()
    merged = []
    
    for method, users in results.items():
        for user in users:
            user_id = user.get("id")
            email = (user.get("mail") or user.get("userPrincipalName") or "").lower()
            
            # Check if already seen by ID
            if user_id and user_id in seen_ids:
                continue
            
            # Check if already seen by email (for users without ID)
            if not user_id and email and email in seen_emails:
                continue
            
            if user_id:
                seen_ids.add(user_id)
            if email:
                seen_emails.add(email)
            
            # Normalize the user object
            normalized = {
                "id": user_id or "",
                "displayName": user.get("displayName") or user.get("givenName", "") or "",
                "userPrincipalName": user.get("userPrincipalName") or email or "",
                "mail": user.get("mail") or email or "",
                "jobTitle": user.get("jobTitle", "") or "",
                "department": user.get("department", "") or "",
                "source": method,
            }
            
            # Handle People API email format
            if not normalized["mail"] and user.get("scoredEmailAddresses"):
                emails = user.get("scoredEmailAddresses", [])
                if emails and isinstance(emails, list):
                    normalized["mail"] = emails[0].get("address", "")
            
            merged.append(normalized)
    
    return merged


def print_user_summary(users: list, show_source: bool = False) -> None:
    """Print a formatted summary of users."""
    print("\n" + "=" * 110)
    print(f"{'AZURE ENTRA ID USERS':^110}")
    print("=" * 110)
    print(f"\nTotal users found: {len(users)}\n")

    user_types = {}
    sources = {}
    for user in users:
        user_type = user.get("userType", "Unknown")
        user_types[user_type] = user_types.get(user_type, 0) + 1
        
        source = user.get("source", "direct")
        sources[source] = sources.get(source, 0) + 1

    if any(ut != "Unknown" for ut in user_types.keys()):
        print("User Types:")
        for user_type, count in user_types.items():
            print(f"  - {user_type}: {count}")
    
    if show_source and len(sources) > 0:
        print("\nSources:")
        for source, count in sorted(sources.items(), key=lambda x: -x[1]):
            print(f"  - {source}: {count}")

    print("\n" + "-" * 110)
    header = f"{'Display Name':<28} {'Email/UPN':<42} {'Department':<18}"
    if show_source:
        header += f" {'Source':<18}"
    print(header)
    print("-" * 110)

    for user in users:
        display_name = (user.get("displayName") or "N/A")[:27]
        email = (user.get("mail") or user.get("userPrincipalName") or "N/A")[:41]
        department = (user.get("department") or "")[:17]
        
        line = f"{display_name:<28} {email:<42} {department:<18}"
        if show_source:
            source = (user.get("source", "direct") or "direct")[:17]
            line += f" {source:<18}"
        print(line)

    print("-" * 110)


def export_to_json(users: list, filename: str = "entra_users.json") -> None:
    """Export users to JSON file."""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, default=str)
    print(f"[+] Exported to: {filename}")


# ============================================================================
# HTML REPORT GENERATION
# ============================================================================

# Risk scoring weights for different finding types
RISK_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 10
}

FINDING_CATEGORIES = {
    "mfa": {"name": "MFA Status", "icon": "🔐", "description": "Multi-Factor Authentication status for users"},
    "privileged": {"name": "Privileged Users", "icon": "👑", "description": "Users with elevated role assignments"},
    "apps": {"name": "Applications", "icon": "📱", "description": "App registrations and service principals"},
    "stale": {"name": "Stale Accounts", "icon": "⏰", "description": "Accounts with no recent sign-in activity"},
    "guests": {"name": "Guest Users", "icon": "👤", "description": "External/guest user accounts"},
    "password_policy": {"name": "Password Policies", "icon": "🔑", "description": "Password configuration issues"},
    "sspr": {"name": "SSPR Users", "icon": "🔄", "description": "Self-Service Password Reset configuration"},
    "legacy_auth": {"name": "Legacy Auth", "icon": "⚠️", "description": "Users with legacy authentication protocols"},
    "app_passwords": {"name": "App Passwords", "icon": "🔓", "description": "Users with app passwords configured"},
    "ca_policies": {"name": "CA Policies", "icon": "📋", "description": "Conditional Access policy analysis"},
    "ca_exclusions": {"name": "CA Exclusions", "icon": "🚫", "description": "Users excluded from CA policies"},
    "mfa_gaps": {"name": "MFA Gaps", "icon": "🕳️", "description": "Missing MFA enforcement scenarios"},
    "devices": {"name": "Devices", "icon": "💻", "description": "Registered and managed devices"},
    "non_compliant": {"name": "Non-Compliant", "icon": "❌", "description": "Devices failing compliance policies"},
    "byod": {"name": "BYOD Devices", "icon": "📲", "description": "Personal/BYOD device enrollments"},
    "intune": {"name": "Intune", "icon": "🛡️", "description": "Intune/Endpoint Manager configuration"},
    "admin_units": {"name": "Admin Units", "icon": "🏢", "description": "Administrative unit assignments"},
    "licenses": {"name": "Licenses", "icon": "📜", "description": "License assignments and privileged SKUs"},
    "sync_status": {"name": "Directory Sync", "icon": "🔄", "description": "On-premises sync status"},
    "attack_paths": {"name": "Attack Paths", "icon": "🎯", "description": "Privilege escalation paths"},
    "lateral_movement": {"name": "Lateral Movement", "icon": "↔️", "description": "Lateral movement opportunities"},
    "power_platform": {"name": "Power Platform", "icon": "⚡", "description": "Power Apps and Power Automate analysis"},
    "users": {"name": "User Enumeration", "icon": "👥", "description": "Enumerated user accounts"},
}


def calculate_risk_score(findings: dict) -> dict:
    """
    Calculate overall risk score based on findings.
    Returns a dict with score, rating, and breakdown.
    """
    total_score = 0
    max_possible = 0
    breakdown = []
    
    for category, data in findings.items():
        if not data:
            continue
            
        category_info = FINDING_CATEGORIES.get(category, {"name": category, "icon": "📊"})
        
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            # For nested structures like apps_data
            items = []
            for key, value in data.items():
                if isinstance(value, list):
                    items.extend(value)
        else:
            continue
        
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for item in items:
            if isinstance(item, dict):
                risk = item.get("riskLevel", item.get("risk", "INFO")).upper()
                if risk == "CRITICAL":
                    critical_count += 1
                elif risk == "HIGH":
                    high_count += 1
                elif risk == "MEDIUM":
                    medium_count += 1
                elif risk == "LOW":
                    low_count += 1
        
        category_score = (
            critical_count * RISK_WEIGHTS["CRITICAL"] +
            high_count * RISK_WEIGHTS["HIGH"] +
            medium_count * RISK_WEIGHTS["MEDIUM"] +
            low_count * RISK_WEIGHTS["LOW"]
        )
        
        if len(items) > 0:
            category_max = len(items) * RISK_WEIGHTS["CRITICAL"]
            max_possible += category_max
            total_score += category_score
            
            breakdown.append({
                "category": category,
                "name": category_info["name"],
                "icon": category_info["icon"],
                "total_items": len(items),
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "score": category_score,
                "max_score": category_max
            })
    
    # Calculate percentage score (0-100, inverted so lower is better)
    if max_possible > 0:
        risk_percentage = (total_score / max_possible) * 100
    else:
        risk_percentage = 0
    
    # Determine overall rating
    if risk_percentage >= 75:
        rating = "CRITICAL"
        rating_color = "#dc3545"
    elif risk_percentage >= 50:
        rating = "HIGH"
        rating_color = "#fd7e14"
    elif risk_percentage >= 25:
        rating = "MEDIUM"
        rating_color = "#ffc107"
    elif risk_percentage > 0:
        rating = "LOW"
        rating_color = "#28a745"
    else:
        rating = "MINIMAL"
        rating_color = "#17a2b8"
    
    return {
        "score": round(risk_percentage, 1),
        "rating": rating,
        "rating_color": rating_color,
        "total_raw_score": total_score,
        "max_possible": max_possible,
        "breakdown": breakdown
    }


def generate_executive_summary(findings: dict, risk_score: dict, tenant_info: dict = None) -> str:
    """Generate executive summary section for the HTML report."""
    
    # Count key metrics
    total_users = 0
    users_without_mfa = 0
    privileged_users = 0
    high_risk_apps = 0
    stale_accounts = 0
    guest_users = 0
    critical_findings = 0
    high_findings = 0
    
    if findings.get("users"):
        total_users = len(findings["users"])
    
    if findings.get("mfa"):
        users_without_mfa = sum(1 for u in findings["mfa"] if not u.get("mfaEnabled", True))
    
    if findings.get("privileged"):
        privileged_users = len(findings["privileged"])
    
    if findings.get("apps"):
        apps_data = findings["apps"]
        if isinstance(apps_data, dict):
            high_risk_apps = len(apps_data.get("high_risk_apps", []))
    
    if findings.get("stale"):
        stale_accounts = len(findings["stale"])
    
    if findings.get("guests"):
        guest_users = len(findings["guests"])
    
    # Count critical/high findings across all categories
    for category, data in findings.items():
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    risk = item.get("riskLevel", item.get("risk", "")).upper()
                    if risk == "CRITICAL":
                        critical_findings += 1
                    elif risk == "HIGH":
                        high_findings += 1
    
    tenant_name = tenant_info.get("displayName", "Unknown Tenant") if tenant_info else "Unknown Tenant"
    tenant_id = tenant_info.get("tenantId", "N/A") if tenant_info else "N/A"
    
    key_findings = []
    if users_without_mfa > 0:
        key_findings.append(f"<li><span class='badge bg-danger'>CRITICAL</span> {users_without_mfa} users without MFA enabled</li>")
    if high_risk_apps > 0:
        key_findings.append(f"<li><span class='badge bg-danger'>HIGH</span> {high_risk_apps} high-risk application registrations</li>")
    if privileged_users > 0:
        key_findings.append(f"<li><span class='badge bg-warning text-dark'>MEDIUM</span> {privileged_users} users with privileged roles</li>")
    if stale_accounts > 0:
        key_findings.append(f"<li><span class='badge bg-warning text-dark'>MEDIUM</span> {stale_accounts} stale accounts (no recent sign-in)</li>")
    if guest_users > 0:
        key_findings.append(f"<li><span class='badge bg-info'>INFO</span> {guest_users} guest/external users</li>")
    
    if not key_findings:
        key_findings.append("<li><span class='badge bg-success'>GOOD</span> No critical issues identified</li>")
    
    return f'''
    <div class="executive-summary">
        <div class="row">
            <div class="col-md-6">
                <h3>📊 Assessment Overview</h3>
                <table class="table table-sm">
                    <tr><th>Tenant Name</th><td>{tenant_name}</td></tr>
                    <tr><th>Tenant ID</th><td><code>{tenant_id}</code></td></tr>
                    <tr><th>Assessment Date</th><td>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</td></tr>
                    <tr><th>Total Users Analyzed</th><td>{total_users}</td></tr>
                    <tr><th>Total Findings</th><td>{critical_findings + high_findings} critical/high</td></tr>
                </table>
            </div>
            <div class="col-md-6">
                <h3>🎯 Risk Score</h3>
                <div class="risk-score-container">
                    <div class="risk-gauge" style="--score: {risk_score['score']}; --color: {risk_score['rating_color']};">
                        <div class="risk-value">{risk_score['score']}</div>
                        <div class="risk-label">{risk_score['rating']}</div>
                    </div>
                </div>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-12">
                <h3>🔑 Key Findings</h3>
                <ul class="key-findings-list">
                    {''.join(key_findings)}
                </ul>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-md-4">
                <div class="metric-card critical">
                    <div class="metric-value">{critical_findings}</div>
                    <div class="metric-label">Critical Findings</div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="metric-card high">
                    <div class="metric-value">{high_findings}</div>
                    <div class="metric-label">High Findings</div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="metric-card info">
                    <div class="metric-value">{total_users}</div>
                    <div class="metric-label">Users Analyzed</div>
                </div>
            </div>
        </div>
    </div>
    '''


def generate_findings_table(category: str, data: list, title: str = None) -> str:
    """Generate an HTML table for a specific category of findings."""
    
    if not data:
        return ""
    
    category_info = FINDING_CATEGORIES.get(category, {"name": category, "icon": "📊", "description": ""})
    display_title = title or category_info["name"]
    
    # Determine columns based on data structure
    if data and isinstance(data[0], dict):
        # Get all unique keys from all items
        all_keys = set()
        for item in data[:100]:  # Sample first 100 items
            all_keys.update(item.keys())
        
        # Priority columns
        priority_columns = ["displayName", "userPrincipalName", "mail", "riskLevel", "risk", 
                          "roleName", "appDisplayName", "name", "id"]
        
        columns = []
        for col in priority_columns:
            if col in all_keys:
                columns.append(col)
                all_keys.discard(col)
        
        # Add remaining columns (limit to 8 total)
        remaining = list(all_keys)[:max(0, 8 - len(columns))]
        columns.extend(remaining)
    else:
        return ""
    
    # Count risk levels
    critical_count = sum(1 for item in data if item.get("riskLevel", item.get("risk", "")).upper() == "CRITICAL")
    high_count = sum(1 for item in data if item.get("riskLevel", item.get("risk", "")).upper() == "HIGH")
    medium_count = sum(1 for item in data if item.get("riskLevel", item.get("risk", "")).upper() == "MEDIUM")
    low_count = sum(1 for item in data if item.get("riskLevel", item.get("risk", "")).upper() == "LOW")
    
    # Build table header
    header_cells = "".join([f"<th>{col.replace('_', ' ').title()}</th>" for col in columns])
    
    # Build table rows
    rows = []
    for item in data:
        risk = item.get("riskLevel", item.get("risk", "INFO")).upper()
        risk_class = f"risk-{risk.lower()}"
        
        cells = []
        for col in columns:
            value = item.get(col, "")
            if isinstance(value, (list, dict)):
                value = json.dumps(value)[:50] + "..." if len(json.dumps(value)) > 50 else json.dumps(value)
            elif isinstance(value, bool):
                value = "✓" if value else "✗"
            elif value is None:
                value = "-"
            else:
                value = str(value)[:50]
            
            # Special formatting for risk columns
            if col in ["riskLevel", "risk"]:
                badge_class = {
                    "CRITICAL": "bg-danger",
                    "HIGH": "bg-warning text-dark",
                    "MEDIUM": "bg-info",
                    "LOW": "bg-success",
                }.get(value.upper(), "bg-secondary")
                value = f'<span class="badge {badge_class}">{value}</span>'
            
            cells.append(f"<td>{value}</td>")
        
        rows.append(f'<tr class="{risk_class}">{"".join(cells)}</tr>')
    
    return f'''
    <div class="findings-section" id="section-{category}">
        <div class="section-header">
            <h3>{category_info["icon"]} {display_title}</h3>
            <p class="text-muted">{category_info["description"]}</p>
            <div class="risk-badges">
                <span class="badge bg-danger">{critical_count} Critical</span>
                <span class="badge bg-warning text-dark">{high_count} High</span>
                <span class="badge bg-info">{medium_count} Medium</span>
                <span class="badge bg-success">{low_count} Low</span>
                <span class="badge bg-secondary">{len(data)} Total</span>
            </div>
        </div>
        <div class="table-responsive">
            <table class="table table-striped table-hover findings-table">
                <thead>
                    <tr>{header_cells}</tr>
                </thead>
                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>
        </div>
    </div>
    '''


def generate_charts_section(findings: dict, risk_score: dict) -> str:
    """Generate the charts section for the HTML report."""
    
    # Prepare data for risk distribution chart
    breakdown = risk_score.get("breakdown", [])
    
    category_labels = json.dumps([b["name"] for b in breakdown])
    critical_data = json.dumps([b["critical"] for b in breakdown])
    high_data = json.dumps([b["high"] for b in breakdown])
    medium_data = json.dumps([b["medium"] for b in breakdown])
    low_data = json.dumps([b["low"] for b in breakdown])
    
    # Prepare data for findings pie chart
    total_critical = sum(b["critical"] for b in breakdown)
    total_high = sum(b["high"] for b in breakdown)
    total_medium = sum(b["medium"] for b in breakdown)
    total_low = sum(b["low"] for b in breakdown)
    
    return f'''
    <div class="charts-section">
        <div class="row">
            <div class="col-md-6">
                <div class="chart-container">
                    <h4>Risk Distribution by Category</h4>
                    <canvas id="riskDistributionChart"></canvas>
                </div>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <h4>Overall Risk Breakdown</h4>
                    <canvas id="riskPieChart"></canvas>
                </div>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-12">
                <div class="chart-container">
                    <h4>Findings by Category</h4>
                    <canvas id="findingsByCategoryChart"></canvas>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Risk Distribution Stacked Bar Chart
        const ctx1 = document.getElementById('riskDistributionChart').getContext('2d');
        new Chart(ctx1, {{
            type: 'bar',
            data: {{
                labels: {category_labels},
                datasets: [
                    {{
                        label: 'Critical',
                        data: {critical_data},
                        backgroundColor: '#dc3545',
                        borderColor: '#dc3545',
                        borderWidth: 1
                    }},
                    {{
                        label: 'High',
                        data: {high_data},
                        backgroundColor: '#fd7e14',
                        borderColor: '#fd7e14',
                        borderWidth: 1
                    }},
                    {{
                        label: 'Medium',
                        data: {medium_data},
                        backgroundColor: '#ffc107',
                        borderColor: '#ffc107',
                        borderWidth: 1
                    }},
                    {{
                        label: 'Low',
                        data: {low_data},
                        backgroundColor: '#28a745',
                        borderColor: '#28a745',
                        borderWidth: 1
                    }}
                ]
            }},
            options: {{
                responsive: true,
                scales: {{
                    x: {{ stacked: true }},
                    y: {{ stacked: true, beginAtZero: true }}
                }},
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // Risk Pie Chart
        const ctx2 = document.getElementById('riskPieChart').getContext('2d');
        new Chart(ctx2, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{total_critical}, {total_high}, {total_medium}, {total_low}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
                    borderWidth: 2,
                    borderColor: '#1e1e2e'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // Findings by Category Bar Chart
        const ctx3 = document.getElementById('findingsByCategoryChart').getContext('2d');
        new Chart(ctx3, {{
            type: 'bar',
            data: {{
                labels: {category_labels},
                datasets: [{{
                    label: 'Total Findings',
                    data: {json.dumps([b["total_items"] for b in breakdown])},
                    backgroundColor: 'rgba(147, 112, 219, 0.7)',
                    borderColor: '#9370db',
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});
    </script>
    '''


def generate_html_report(
    findings: dict,
    filename: str = "evilmist_report.html",
    tenant_info: dict = None,
    title: str = "EvilMist Security Assessment Report"
) -> None:
    """
    Generate an interactive HTML report with charts, risk scoring, and executive summary.
    
    Args:
        findings: Dictionary containing all assessment findings
        filename: Output filename for the HTML report
        tenant_info: Optional tenant information dictionary
        title: Report title
    """
    
    # Calculate risk score
    risk_score = calculate_risk_score(findings)
    
    # Generate navigation items and content sections
    nav_items = []
    content_sections = []
    
    for category, data in findings.items():
        if not data:
            continue
            
        category_info = FINDING_CATEGORIES.get(category, {"name": category, "icon": "📊", "description": ""})
        
        # Handle nested dict structures (like apps_data)
        if isinstance(data, dict) and category == "apps":
            # Flatten apps data
            all_apps = []
            if data.get("applications"):
                for app in data["applications"]:
                    app["type"] = "Application"
                    all_apps.append(app)
            if data.get("service_principals"):
                for sp in data["service_principals"]:
                    sp["type"] = "ServicePrincipal"
                    all_apps.append(sp)
            if data.get("high_risk_apps"):
                for hra in data["high_risk_apps"]:
                    hra["type"] = "HighRiskApp"
                    all_apps.append(hra)
            data = all_apps
        
        if isinstance(data, list) and len(data) > 0:
            nav_items.append(f'''
                <a class="nav-link" href="#section-{category}">
                    {category_info["icon"]} {category_info["name"]} 
                    <span class="badge bg-secondary">{len(data)}</span>
                </a>
            ''')
            content_sections.append(generate_findings_table(category, data))
    
    # HTML Template with modern dark theme
    html_template = f'''<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-purple: #8957e5;
            --accent-blue: #58a6ff;
            --border-color: #30363d;
        }}
        
        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        }}
        
        .navbar {{
            background: var(--bg-secondary) !important;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .sidebar {{
            position: fixed;
            top: 56px;
            left: 0;
            bottom: 0;
            width: 280px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            overflow-y: auto;
            padding: 1rem;
        }}
        
        .sidebar .nav-link {{
            color: var(--text-secondary);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            margin-bottom: 0.25rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .sidebar .nav-link:hover {{
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }}
        
        .main-content {{
            margin-left: 280px;
            padding: 2rem;
        }}
        
        .executive-summary {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }}
        
        .risk-score-container {{
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 1rem;
        }}
        
        .risk-gauge {{
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: conic-gradient(
                var(--color) calc(var(--score) * 3.6deg),
                var(--bg-tertiary) calc(var(--score) * 3.6deg)
            );
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            position: relative;
        }}
        
        .risk-gauge::before {{
            content: '';
            position: absolute;
            width: 120px;
            height: 120px;
            background: var(--bg-secondary);
            border-radius: 50%;
        }}
        
        .risk-value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--color);
            position: relative;
            z-index: 1;
        }}
        
        .risk-label {{
            font-size: 0.875rem;
            color: var(--text-secondary);
            position: relative;
            z-index: 1;
        }}
        
        .metric-card {{
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid var(--border-color);
        }}
        
        .metric-card.critical {{
            border-left: 4px solid #dc3545;
        }}
        
        .metric-card.high {{
            border-left: 4px solid #fd7e14;
        }}
        
        .metric-card.info {{
            border-left: 4px solid #58a6ff;
        }}
        
        .metric-value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--text-primary);
        }}
        
        .metric-label {{
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
        
        .key-findings-list {{
            list-style: none;
            padding: 0;
        }}
        
        .key-findings-list li {{
            padding: 0.75rem;
            background: var(--bg-tertiary);
            border-radius: 6px;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .findings-section {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }}
        
        .section-header {{
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .section-header h3 {{
            margin-bottom: 0.5rem;
        }}
        
        .risk-badges {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}
        
        .findings-table {{
            font-size: 0.875rem;
        }}
        
        .findings-table th {{
            background: var(--bg-tertiary);
            color: var(--text-primary);
            white-space: nowrap;
        }}
        
        .findings-table td {{
            color: var(--text-secondary);
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        
        .risk-critical {{
            border-left: 3px solid #dc3545;
        }}
        
        .risk-high {{
            border-left: 3px solid #fd7e14;
        }}
        
        .risk-medium {{
            border-left: 3px solid #ffc107;
        }}
        
        .risk-low {{
            border-left: 3px solid #28a745;
        }}
        
        .chart-container {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--border-color);
        }}
        
        .chart-container h4 {{
            margin-bottom: 1rem;
            color: var(--text-primary);
        }}
        
        .charts-section {{
            margin-bottom: 2rem;
        }}
        
        .table-responsive {{
            max-height: 500px;
            overflow-y: auto;
        }}
        
        .badge {{
            font-weight: 500;
        }}
        
        @media print {{
            .sidebar {{ display: none; }}
            .main-content {{ margin-left: 0; }}
        }}
        
        @media (max-width: 992px) {{
            .sidebar {{ display: none; }}
            .main-content {{ margin-left: 0; }}
        }}
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark fixed-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <strong>🔮 EvilMist</strong> Security Assessment
            </a>
            <span class="navbar-text">
                Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </span>
        </div>
    </nav>
    
    <div class="sidebar">
        <h6 class="text-uppercase text-muted mb-3">Navigation</h6>
        <nav class="nav flex-column">
            <a class="nav-link" href="#executive-summary">📊 Executive Summary</a>
            <a class="nav-link" href="#charts">📈 Charts & Analytics</a>
            <hr class="my-2">
            <h6 class="text-uppercase text-muted mb-2">Findings</h6>
            {"".join(nav_items)}
        </nav>
    </div>
    
    <main class="main-content" style="margin-top: 56px;">
        <section id="executive-summary">
            <h2 class="mb-4">Executive Summary</h2>
            {generate_executive_summary(findings, risk_score, tenant_info)}
        </section>
        
        <section id="charts" class="mt-5">
            <h2 class="mb-4">Charts & Analytics</h2>
            {generate_charts_section(findings, risk_score)}
        </section>
        
        <section id="detailed-findings" class="mt-5">
            <h2 class="mb-4">Detailed Findings</h2>
            {"".join(content_sections)}
        </section>
        
        <footer class="mt-5 pt-4 border-top text-center text-muted">
            <p>Generated by <strong>EvilMist</strong> - Azure Entra ID Security Assessment Toolkit</p>
            <p>© 2025 Logisek - <a href="https://github.com/Logisek/EvilMist" target="_blank">GitHub</a></p>
        </footer>
    </main>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>'''
    
    # Write the HTML file
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_template)
    
    print(f"[+] HTML report generated: {filename}")
    print(f"    Risk Score: {risk_score['score']} ({risk_score['rating']})")
    print(f"    Categories: {len(risk_score['breakdown'])}")
    
    # Offer to open in browser
    try:
        open_browser = input("\nOpen report in browser? (y/n) [y]: ").strip().lower()
        if open_browser != 'n':
            webbrowser.open(f"file://{os.path.abspath(filename)}")
    except (KeyboardInterrupt, EOFError):
        pass


def prompt_export_results(data: list, default_filename: str = "export") -> None:
    """Prompt user to export results to file."""
    if not data:
        return
    
    print("\nExport results? (y/n)")
    try:
        export_choice = input("Export: ").strip().lower()
        
        if export_choice == 'y':
            print(f"Enter filename (e.g., {default_filename}.csv or {default_filename}.json)")
            print("Type 'cancel' or press Enter to go back")
            export_file = input("Filename: ").strip()
            
            if export_file and export_file.lower() != 'cancel':
                if export_file.endswith('.json'):
                    export_to_json(data, export_file)
                elif export_file.endswith('.csv'):
                    export_to_csv(data, export_file)
                else:
                    # Default to CSV
                    export_to_csv(data, f"{export_file}.csv")
            else:
                print("[*] Export cancelled.")
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Export cancelled.")


def export_to_csv(users: list, filename: str = "entra_users.csv") -> None:
    """Export users to CSV file."""
    if not users:
        print("[!] No data to export.")
        return
    
    # Get all unique keys
    all_keys = set()
    for user in users:
        if isinstance(user, dict):
            all_keys.update(user.keys())
    
    # Sort keys for consistent output
    fieldnames = sorted(list(all_keys))
    
    import csv
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for user in users:
            # Convert any nested structures to strings
            row = {}
            for key, value in user.items():
                if isinstance(value, (list, dict)):
                    row[key] = json.dumps(value)
                else:
                    row[key] = value
            writer.writerow(row)
    
    print(f"[+] Exported to: {filename}")


# ============================================================================
# BLOODHOUND / AZUREHOUND EXPORT FUNCTIONS
# ============================================================================

BLOODHOUND_VERSION = 5  # BloodHound CE v5 JSON format


def get_tenant_info(access_token: str) -> dict:
    """
    Get tenant/organization information for BloodHound metadata.
    Returns tenant ID, display name, and verified domains.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    tenant_info = {
        "tenantId": "",
        "displayName": "",
        "verifiedDomains": [],
        "defaultDomain": "",
    }
    
    try:
        # Get organization details
        url = f"{GRAPH_API_ENDPOINT}/organization"
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("value"):
                org = data["value"][0]
                tenant_info["tenantId"] = org.get("id", "")
                tenant_info["displayName"] = org.get("displayName", "")
                
                # Get verified domains
                domains = org.get("verifiedDomains", [])
                for domain in domains:
                    domain_name = domain.get("name", "")
                    if domain_name:
                        tenant_info["verifiedDomains"].append(domain_name)
                        if domain.get("isDefault"):
                            tenant_info["defaultDomain"] = domain_name
    except Exception as e:
        print(f"[!] Error getting tenant info: {e}")
        # Try to extract tenant ID from token
        try:
            import base64
            # JWT token structure: header.payload.signature
            payload = access_token.split('.')[1]
            # Add padding if needed
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            decoded = json.loads(base64.b64decode(payload))
            tenant_info["tenantId"] = decoded.get("tid", "")
        except:
            pass
    
    return tenant_info


def convert_users_to_bloodhound(users: list, tenant_id: str) -> list:
    """
    Convert enumerated users to AzureHound-compatible format.
    Returns list of AZUser objects for BloodHound.
    """
    bh_users = []
    
    for user in users:
        user_id = user.get("id", "")
        if not user_id:
            continue
        
        # Build object identifier (format: ObjectID@TenantID)
        object_id = f"{user_id}@{tenant_id}" if tenant_id else user_id
        
        # Determine if user is privileged based on available data
        is_privileged = False
        if user.get("role") or user.get("roles"):
            is_privileged = True
        
        bh_user = {
            "ObjectId": user_id,
            "ObjectIdentifier": object_id,
            "Kind": "AZUser",
            "DisplayName": user.get("displayName", ""),
            "UserPrincipalName": user.get("userPrincipalName", ""),
            "Mail": user.get("mail", ""),
            "TenantId": tenant_id,
            "OnPremisesSecurityIdentifier": user.get("onPremisesSecurityIdentifier", ""),
            "OnPremisesSamAccountName": user.get("onPremisesSamAccountName", ""),
            "OnPremisesSyncEnabled": user.get("onPremisesSyncEnabled", False),
            "AccountEnabled": user.get("accountEnabled", True),
            "UserType": user.get("userType", "Member"),
            "CreatedDateTime": str(user.get("createdDateTime", "")),
            "JobTitle": user.get("jobTitle", ""),
            "Department": user.get("department", ""),
            "OfficeLocation": user.get("officeLocation", ""),
            "MFAEnabled": user.get("mfaEnabled", user.get("isMfaRegistered", None)),
            "PasswordPolicies": user.get("passwordPolicies", ""),
            "LastPasswordChangeDateTime": str(user.get("lastPasswordChangeDateTime", "")),
            "Properties": {
                "displayname": user.get("displayName", ""),
                "userprincipalname": user.get("userPrincipalName", ""),
                "mail": user.get("mail", ""),
                "enabled": user.get("accountEnabled", True),
                "usertype": user.get("userType", "Member"),
                "tenantid": tenant_id,
                "onpremisessyncenabled": user.get("onPremisesSyncEnabled", False),
            },
        }
        
        bh_users.append(bh_user)
    
    return bh_users


def convert_groups_to_bloodhound(access_token: str, tenant_id: str) -> Tuple[list, list]:
    """
    Fetch and convert groups to AzureHound-compatible format.
    Returns (groups_list, membership_edges_list).
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    bh_groups = []
    membership_edges = []
    
    print("[*] Collecting groups for BloodHound export...")
    
    # Fetch all groups
    url = f"{GRAPH_API_ENDPOINT}/groups?$select=id,displayName,description,securityEnabled,mailEnabled,groupTypes,isAssignableToRole,onPremisesSecurityIdentifier,onPremisesSyncEnabled&$top=999"
    
    while url:
        try:
            response = make_api_request(url, headers)
            if not response or response.status_code != 200:
                break
                
            data = response.json()
            groups = data.get("value", [])
            
            for group in groups:
                group_id = group.get("id", "")
                if not group_id:
                    continue
                
                object_id = f"{group_id}@{tenant_id}" if tenant_id else group_id
                
                # Determine group type
                group_types = group.get("groupTypes", [])
                is_dynamic = "DynamicMembership" in group_types
                is_unified = "Unified" in group_types
                
                bh_group = {
                    "ObjectId": group_id,
                    "ObjectIdentifier": object_id,
                    "Kind": "AZGroup",
                    "DisplayName": group.get("displayName", ""),
                    "Description": group.get("description", ""),
                    "TenantId": tenant_id,
                    "SecurityEnabled": group.get("securityEnabled", False),
                    "MailEnabled": group.get("mailEnabled", False),
                    "IsAssignableToRole": group.get("isAssignableToRole", False),
                    "OnPremisesSecurityIdentifier": group.get("onPremisesSecurityIdentifier", ""),
                    "OnPremisesSyncEnabled": group.get("onPremisesSyncEnabled", False),
                    "IsDynamicMembership": is_dynamic,
                    "IsUnified": is_unified,
                    "Properties": {
                        "displayname": group.get("displayName", ""),
                        "description": group.get("description", ""),
                        "securityenabled": group.get("securityEnabled", False),
                        "isassignabletorole": group.get("isAssignableToRole", False),
                        "tenantid": tenant_id,
                    },
                }
                
                bh_groups.append(bh_group)
                
                # Get group members for relationship edges
                try:
                    members_url = f"{GRAPH_API_ENDPOINT}/groups/{group_id}/members?$select=id,displayName,@odata.type"
                    members_resp = make_api_request(members_url, headers)
                    
                    if members_resp and members_resp.status_code == 200:
                        members_data = members_resp.json()
                        for member in members_data.get("value", []):
                            member_id = member.get("id", "")
                            odata_type = member.get("@odata.type", "")
                            
                            # Determine member kind
                            if "#microsoft.graph.user" in odata_type:
                                member_kind = "AZUser"
                            elif "#microsoft.graph.group" in odata_type:
                                member_kind = "AZGroup"
                            elif "#microsoft.graph.servicePrincipal" in odata_type:
                                member_kind = "AZServicePrincipal"
                            else:
                                member_kind = "Unknown"
                            
                            if member_id:
                                membership_edges.append({
                                    "SourceId": f"{member_id}@{tenant_id}",
                                    "SourceKind": member_kind,
                                    "TargetId": object_id,
                                    "TargetKind": "AZGroup",
                                    "RelationType": "AZMemberOf",
                                })
                except Exception:
                    pass
            
            url = data.get("@odata.nextLink")
            
        except Exception as e:
            print(f"[!] Error fetching groups: {e}")
            break
    
    print(f"    Collected {len(bh_groups)} groups, {len(membership_edges)} membership edges")
    return bh_groups, membership_edges


def convert_devices_to_bloodhound(access_token: str, tenant_id: str) -> Tuple[list, list]:
    """
    Fetch and convert devices to AzureHound-compatible format.
    Returns (devices_list, ownership_edges_list).
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    bh_devices = []
    ownership_edges = []
    
    print("[*] Collecting devices for BloodHound export...")
    
    url = f"{GRAPH_API_ENDPOINT}/devices?$select=id,displayName,deviceId,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,accountEnabled,registrationDateTime,approximateLastSignInDateTime&$top=999"
    
    while url:
        try:
            response = make_api_request(url, headers)
            if not response or response.status_code != 200:
                break
                
            data = response.json()
            devices = data.get("value", [])
            
            for device in devices:
                device_id = device.get("id", "")
                if not device_id:
                    continue
                
                object_id = f"{device_id}@{tenant_id}" if tenant_id else device_id
                
                # Map trust type to join type
                trust_type = device.get("trustType", "")
                device_join_type = "Unknown"
                if trust_type == "AzureAd":
                    device_join_type = "AzureADJoined"
                elif trust_type == "ServerAd":
                    device_join_type = "HybridAzureADJoined"
                elif trust_type == "Workplace":
                    device_join_type = "AzureADRegistered"
                
                bh_device = {
                    "ObjectId": device_id,
                    "ObjectIdentifier": object_id,
                    "Kind": "AZDevice",
                    "DisplayName": device.get("displayName", ""),
                    "DeviceId": device.get("deviceId", ""),
                    "TenantId": tenant_id,
                    "OperatingSystem": device.get("operatingSystem", ""),
                    "OperatingSystemVersion": device.get("operatingSystemVersion", ""),
                    "TrustType": trust_type,
                    "DeviceJoinType": device_join_type,
                    "IsCompliant": device.get("isCompliant"),
                    "IsManaged": device.get("isManaged", False),
                    "AccountEnabled": device.get("accountEnabled", True),
                    "RegistrationDateTime": str(device.get("registrationDateTime", "")),
                    "ApproximateLastSignInDateTime": str(device.get("approximateLastSignInDateTime", "")),
                    "Properties": {
                        "displayname": device.get("displayName", ""),
                        "operatingsystem": device.get("operatingSystem", ""),
                        "trusttype": trust_type,
                        "iscompliant": device.get("isCompliant"),
                        "ismanaged": device.get("isManaged", False),
                        "tenantid": tenant_id,
                    },
                }
                
                bh_devices.append(bh_device)
                
                # Get device owners for ownership edges
                try:
                    owners_url = f"{GRAPH_API_ENDPOINT}/devices/{device_id}/registeredOwners?$select=id,displayName,@odata.type"
                    owners_resp = make_api_request(owners_url, headers)
                    
                    if owners_resp and owners_resp.status_code == 200:
                        owners_data = owners_resp.json()
                        for owner in owners_data.get("value", []):
                            owner_id = owner.get("id", "")
                            if owner_id:
                                ownership_edges.append({
                                    "SourceId": f"{owner_id}@{tenant_id}",
                                    "SourceKind": "AZUser",
                                    "TargetId": object_id,
                                    "TargetKind": "AZDevice",
                                    "RelationType": "AZOwns",
                                })
                except Exception:
                    pass
            
            url = data.get("@odata.nextLink")
            
        except Exception as e:
            print(f"[!] Error fetching devices: {e}")
            break
    
    print(f"    Collected {len(bh_devices)} devices, {len(ownership_edges)} ownership edges")
    return bh_devices, ownership_edges


def convert_apps_to_bloodhound(access_token: str, tenant_id: str) -> Tuple[list, list, list]:
    """
    Fetch and convert applications and service principals to AzureHound-compatible format.
    Returns (apps_list, service_principals_list, edges_list).
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    bh_apps = []
    bh_sps = []
    app_edges = []
    
    print("[*] Collecting applications for BloodHound export...")
    
    # Get applications (app registrations)
    url = f"{GRAPH_API_ENDPOINT}/applications?$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials&$top=999"
    
    while url:
        try:
            response = make_api_request(url, headers)
            if not response or response.status_code != 200:
                break
                
            data = response.json()
            apps = data.get("value", [])
            
            for app in apps:
                app_id = app.get("id", "")
                if not app_id:
                    continue
                
                object_id = f"{app_id}@{tenant_id}" if tenant_id else app_id
                
                # Check for credentials
                has_secrets = len(app.get("passwordCredentials", [])) > 0
                has_certs = len(app.get("keyCredentials", [])) > 0
                
                bh_app = {
                    "ObjectId": app_id,
                    "ObjectIdentifier": object_id,
                    "Kind": "AZApp",
                    "DisplayName": app.get("displayName", ""),
                    "AppId": app.get("appId", ""),
                    "TenantId": tenant_id,
                    "CreatedDateTime": str(app.get("createdDateTime", "")),
                    "SignInAudience": app.get("signInAudience", ""),
                    "HasSecrets": has_secrets,
                    "HasCertificates": has_certs,
                    "Properties": {
                        "displayname": app.get("displayName", ""),
                        "appid": app.get("appId", ""),
                        "hassecrets": has_secrets,
                        "hascertificates": has_certs,
                        "tenantid": tenant_id,
                    },
                }
                
                bh_apps.append(bh_app)
                
                # Get app owners
                try:
                    owners_url = f"{GRAPH_API_ENDPOINT}/applications/{app_id}/owners?$select=id,displayName,@odata.type"
                    owners_resp = make_api_request(owners_url, headers)
                    
                    if owners_resp and owners_resp.status_code == 200:
                        for owner in owners_resp.json().get("value", []):
                            owner_id = owner.get("id", "")
                            if owner_id:
                                app_edges.append({
                                    "SourceId": f"{owner_id}@{tenant_id}",
                                    "SourceKind": "AZUser",
                                    "TargetId": object_id,
                                    "TargetKind": "AZApp",
                                    "RelationType": "AZOwns",
                                })
                except Exception:
                    pass
            
            url = data.get("@odata.nextLink")
            
        except Exception as e:
            print(f"[!] Error fetching apps: {e}")
            break
    
    print(f"    Collected {len(bh_apps)} applications")
    
    # Get service principals
    print("[*] Collecting service principals for BloodHound export...")
    
    sp_url = f"{GRAPH_API_ENDPOINT}/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,tags&$top=999"
    
    while sp_url:
        try:
            response = make_api_request(sp_url, headers)
            if not response or response.status_code != 200:
                break
                
            data = response.json()
            sps = data.get("value", [])
            
            for sp in sps:
                sp_id = sp.get("id", "")
                if not sp_id:
                    continue
                
                object_id = f"{sp_id}@{tenant_id}" if tenant_id else sp_id
                
                # Determine if it's a first-party app
                app_owner_org = sp.get("appOwnerOrganizationId", "")
                is_first_party = app_owner_org == "f8cdef31-a31e-4b4a-93e4-5f571e91255a"  # Microsoft's tenant ID
                
                bh_sp = {
                    "ObjectId": sp_id,
                    "ObjectIdentifier": object_id,
                    "Kind": "AZServicePrincipal",
                    "DisplayName": sp.get("displayName", ""),
                    "AppId": sp.get("appId", ""),
                    "TenantId": tenant_id,
                    "ServicePrincipalType": sp.get("servicePrincipalType", ""),
                    "AppOwnerOrganizationId": app_owner_org,
                    "IsFirstParty": is_first_party,
                    "AccountEnabled": sp.get("accountEnabled", True),
                    "Tags": sp.get("tags", []),
                    "Properties": {
                        "displayname": sp.get("displayName", ""),
                        "appid": sp.get("appId", ""),
                        "serviceprincipaltype": sp.get("servicePrincipalType", ""),
                        "isfirstparty": is_first_party,
                        "accountenabled": sp.get("accountEnabled", True),
                        "tenantid": tenant_id,
                    },
                }
                
                bh_sps.append(bh_sp)
                
                # Get SP owners
                try:
                    owners_url = f"{GRAPH_API_ENDPOINT}/servicePrincipals/{sp_id}/owners?$select=id,displayName,@odata.type"
                    owners_resp = make_api_request(owners_url, headers)
                    
                    if owners_resp and owners_resp.status_code == 200:
                        for owner in owners_resp.json().get("value", []):
                            owner_id = owner.get("id", "")
                            if owner_id:
                                app_edges.append({
                                    "SourceId": f"{owner_id}@{tenant_id}",
                                    "SourceKind": "AZUser",
                                    "TargetId": object_id,
                                    "TargetKind": "AZServicePrincipal",
                                    "RelationType": "AZOwns",
                                })
                except Exception:
                    pass
            
            sp_url = data.get("@odata.nextLink")
            
        except Exception as e:
            print(f"[!] Error fetching service principals: {e}")
            break
    
    print(f"    Collected {len(bh_sps)} service principals, {len(app_edges)} ownership edges")
    return bh_apps, bh_sps, app_edges


def convert_roles_to_bloodhound(access_token: str, tenant_id: str) -> Tuple[list, list]:
    """
    Fetch and convert directory roles and role assignments to AzureHound-compatible format.
    Returns (roles_list, role_assignment_edges_list).
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    bh_roles = []
    role_edges = []
    
    print("[*] Collecting directory roles for BloodHound export...")
    
    # Get directory roles with members
    url = f"{GRAPH_API_ENDPOINT}/directoryRoles?$expand=members"
    
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            roles = response.json().get("value", [])
            
            for role in roles:
                role_id = role.get("id", "")
                if not role_id:
                    continue
                
                object_id = f"{role_id}@{tenant_id}" if tenant_id else role_id
                role_template_id = role.get("roleTemplateId", "")
                role_name = role.get("displayName", "")
                
                # Determine if this is a privileged role
                privileged_roles = [
                    "Global Administrator", "Privileged Role Administrator",
                    "Privileged Authentication Administrator", "User Administrator",
                    "Exchange Administrator", "Application Administrator",
                    "Cloud Application Administrator", "Intune Administrator",
                    "Security Administrator", "Password Administrator",
                    "Authentication Administrator", "Helpdesk Administrator"
                ]
                is_privileged = role_name in privileged_roles
                
                bh_role = {
                    "ObjectId": role_id,
                    "ObjectIdentifier": object_id,
                    "Kind": "AZRole",
                    "DisplayName": role_name,
                    "Description": role.get("description", ""),
                    "RoleTemplateId": role_template_id,
                    "TenantId": tenant_id,
                    "IsPrivileged": is_privileged,
                    "Properties": {
                        "displayname": role_name,
                        "description": role.get("description", ""),
                        "roletemplateid": role_template_id,
                        "isprivileged": is_privileged,
                        "tenantid": tenant_id,
                    },
                }
                
                bh_roles.append(bh_role)
                
                # Create edges for role members
                members = role.get("members", [])
                for member in members:
                    member_id = member.get("id", "")
                    odata_type = member.get("@odata.type", "")
                    
                    if not member_id:
                        continue
                    
                    # Determine member kind
                    if "#microsoft.graph.user" in odata_type:
                        member_kind = "AZUser"
                    elif "#microsoft.graph.group" in odata_type:
                        member_kind = "AZGroup"
                    elif "#microsoft.graph.servicePrincipal" in odata_type:
                        member_kind = "AZServicePrincipal"
                    else:
                        member_kind = "Unknown"
                    
                    # Determine edge type based on role
                    if role_name == "Global Administrator":
                        edge_type = "AZGlobalAdmin"
                    elif role_name == "Privileged Role Administrator":
                        edge_type = "AZPrivilegedRoleAdmin"
                    elif role_name == "User Administrator":
                        edge_type = "AZUserAdmin"
                    elif role_name == "Application Administrator":
                        edge_type = "AZAppAdmin"
                    elif role_name == "Cloud Application Administrator":
                        edge_type = "AZCloudAppAdmin"
                    elif role_name == "Intune Administrator":
                        edge_type = "AZIntuneAdmin"
                    else:
                        edge_type = "AZHasRole"
                    
                    role_edges.append({
                        "SourceId": f"{member_id}@{tenant_id}",
                        "SourceKind": member_kind,
                        "TargetId": object_id,
                        "TargetKind": "AZRole",
                        "RelationType": edge_type,
                        "RoleName": role_name,
                    })
                    
    except Exception as e:
        print(f"[!] Error fetching roles: {e}")
    
    print(f"    Collected {len(bh_roles)} roles, {len(role_edges)} role assignment edges")
    return bh_roles, role_edges


def create_tenant_object(tenant_info: dict) -> dict:
    """Create AzureHound tenant object."""
    tenant_id = tenant_info.get("tenantId", "")
    
    return {
        "ObjectId": tenant_id,
        "ObjectIdentifier": tenant_id,
        "Kind": "AZTenant",
        "DisplayName": tenant_info.get("displayName", "Unknown Tenant"),
        "TenantId": tenant_id,
        "DefaultDomain": tenant_info.get("defaultDomain", ""),
        "VerifiedDomains": tenant_info.get("verifiedDomains", []),
        "Properties": {
            "displayname": tenant_info.get("displayName", "Unknown Tenant"),
            "objectid": tenant_id,
            "tenantid": tenant_id,
        },
    }


def export_to_bloodhound(access_token: str, users: list = None, filename: str = "azurehound_export") -> None:
    """
    Export all enumerated data to BloodHound/AzureHound-compatible JSON format.
    Creates multiple JSON files following AzureHound output structure.
    
    Args:
        access_token: Valid MS Graph access token
        users: Optional pre-enumerated users list (will fetch if None)
        filename: Base filename for export (will add suffixes and extension)
    """
    print("\n" + "=" * 60)
    print("BLOODHOUND / AZUREHOUND EXPORT")
    print("=" * 60)
    
    # Get tenant information
    print("[*] Getting tenant information...")
    tenant_info = get_tenant_info(access_token)
    tenant_id = tenant_info.get("tenantId", "")
    
    if tenant_id:
        print(f"    Tenant ID: {tenant_id}")
        print(f"    Tenant Name: {tenant_info.get('displayName', 'Unknown')}")
        print(f"    Default Domain: {tenant_info.get('defaultDomain', 'Unknown')}")
    else:
        print("[!] Warning: Could not determine tenant ID. Export may be incomplete.")
    
    # Collect all data
    all_edges = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 1. Users
    print("\n[*] Processing users...")
    if users is None:
        # Fetch users if not provided
        print("    Fetching users from directory...")
        users = []
        headers = {"Authorization": f"Bearer {access_token}"}
        url = f"{GRAPH_API_ENDPOINT}/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,onPremisesSyncEnabled,onPremisesSecurityIdentifier,onPremisesSamAccountName,jobTitle,department,officeLocation,passwordPolicies,lastPasswordChangeDateTime&$top=999"
        
        while url:
            try:
                response = make_api_request(url, headers)
                if response and response.status_code == 200:
                    data = response.json()
                    users.extend(data.get("value", []))
                    url = data.get("@odata.nextLink")
                else:
                    break
            except Exception:
                break
    
    bh_users = convert_users_to_bloodhound(users, tenant_id)
    print(f"    Processed {len(bh_users)} users")
    
    # 2. Groups
    bh_groups, group_edges = convert_groups_to_bloodhound(access_token, tenant_id)
    all_edges.extend(group_edges)
    
    # 3. Devices
    bh_devices, device_edges = convert_devices_to_bloodhound(access_token, tenant_id)
    all_edges.extend(device_edges)
    
    # 4. Applications and Service Principals
    bh_apps, bh_sps, app_edges = convert_apps_to_bloodhound(access_token, tenant_id)
    all_edges.extend(app_edges)
    
    # 5. Roles
    bh_roles, role_edges = convert_roles_to_bloodhound(access_token, tenant_id)
    all_edges.extend(role_edges)
    
    # 6. Create tenant object
    bh_tenant = create_tenant_object(tenant_info)
    
    # Export options
    print("\n" + "-" * 40)
    print("Export Options:")
    print("1. Single combined file (BloodHound CE compatible)")
    print("2. Separate files per object type (AzureHound style)")
    print("0. Cancel")
    
    export_choice = input("Select export format (0-2): ").strip()
    
    if export_choice == "0":
        print("[*] Export cancelled.")
        return
    
    # Get filename
    print(f"\nEnter filename (without extension, default: {filename}):")
    print("Type 'cancel' to go back")
    user_filename = input("Filename: ").strip()
    
    if user_filename.lower() == 'cancel':
        print("[*] Export cancelled.")
        return
    
    filename = user_filename or filename
    
    if export_choice == "1":
        # Single combined file - BloodHound CE format
        combined_data = {
            "meta": {
                "methods": 0,
                "type": "azure",
                "count": len(bh_users) + len(bh_groups) + len(bh_devices) + len(bh_apps) + len(bh_sps) + len(bh_roles) + 1,
                "version": BLOODHOUND_VERSION,
                "collected": timestamp,
                "tenantId": tenant_id,
                "tenantName": tenant_info.get("displayName", ""),
            },
            "data": {
                "tenant": bh_tenant,
                "users": bh_users,
                "groups": bh_groups,
                "devices": bh_devices,
                "applications": bh_apps,
                "servicePrincipals": bh_sps,
                "roles": bh_roles,
                "relationships": all_edges,
            },
        }
        
        output_file = f"{filename}_{timestamp}.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(combined_data, f, indent=2, default=str)
        
        print(f"\n[+] BloodHound export complete!")
        print(f"    File: {output_file}")
        print(f"    Users: {len(bh_users)}")
        print(f"    Groups: {len(bh_groups)}")
        print(f"    Devices: {len(bh_devices)}")
        print(f"    Applications: {len(bh_apps)}")
        print(f"    Service Principals: {len(bh_sps)}")
        print(f"    Roles: {len(bh_roles)}")
        print(f"    Relationships: {len(all_edges)}")
        
    elif export_choice == "2":
        # Separate files per type - AzureHound style
        output_dir = f"{filename}_{timestamp}"
        os.makedirs(output_dir, exist_ok=True)
        
        # Export each type
        export_files = [
            ("aztenants.json", [bh_tenant], "tenants"),
            ("azusers.json", bh_users, "users"),
            ("azgroups.json", bh_groups, "groups"),
            ("azdevices.json", bh_devices, "devices"),
            ("azapps.json", bh_apps, "applications"),
            ("azserviceprincipals.json", bh_sps, "serviceprincipals"),
            ("azroles.json", bh_roles, "roles"),
            ("azrelationships.json", all_edges, "relationships"),
        ]
        
        for file_name, data_list, data_type in export_files:
            file_data = {
                "meta": {
                    "methods": 0,
                    "type": data_type,
                    "count": len(data_list),
                    "version": BLOODHOUND_VERSION,
                    "collected": timestamp,
                },
                "data": data_list,
            }
            
            file_path = os.path.join(output_dir, file_name)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(file_data, f, indent=2, default=str)
        
        print(f"\n[+] AzureHound-style export complete!")
        print(f"    Directory: {output_dir}/")
        print(f"    Files created:")
        for file_name, data_list, _ in export_files:
            print(f"      - {file_name}: {len(data_list)} objects")
    
    print("\n[*] Import into BloodHound:")
    print("    1. Open BloodHound CE")
    print("    2. Click 'Upload Data'")
    print("    3. Select the exported JSON file(s)")
    print("    4. Wait for data ingestion to complete")
    print("\n[*] Tip: Use Cypher queries to analyze attack paths!")


def export_to_csv(users: list, filename: str = "entra_users.csv") -> None:
    """Export users to CSV file."""
    import csv

    if not users:
        return

    fieldnames = set()
    for user in users:
        fieldnames.update(user.keys())
    fieldnames = sorted(fieldnames)

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(users)

    print(f"[+] Exported to: {filename}")


def prompt_export_results(data: list, default_filename: str = "export") -> None:
    """Prompt user to export results after displaying them."""
    if not data:
        return
    
    print("\nExport results? (y/n)")
    export_choice = input("Export: ").strip().lower()
    
    if export_choice == 'y':
        print(f"\nExport format:")
        print("0. Cancel (go back)")
        print("1. JSON")
        print("2. CSV")
        print("3. Both")
        fmt = input("Select (0-3): ").strip()
        
        if fmt == "0":
            print("[*] Export cancelled.")
            return
        
        print(f"Enter filename (without extension, default: {default_filename})")
        print("Type 'cancel' to go back")
        filename = input("Filename: ").strip()
        
        if filename.lower() == 'cancel':
            print("[*] Export cancelled.")
            return
        
        filename = filename or default_filename
        
        if fmt == "1":
            export_to_json(data, f"{filename}.json")
        elif fmt == "2":
            export_to_csv(data, f"{filename}.csv")
        elif fmt == "3":
            export_to_json(data, f"{filename}.json")
            export_to_csv(data, f"{filename}.csv")
        else:
            print("[!] Invalid format selection.")


def select_app_id() -> Optional[str]:
    """
    Let user select which app ID to use for authentication.
    Returns None to go back, "AUTO_TRY_ALL" for auto-fallback mode.
    """
    global PUBLIC_CLIENT_APP_ID
    
    # Load extended app IDs if available
    load_extended_app_ids()
    
    # Show file info if available
    file_modified = get_microsoft_apps_file_info()
    extended_count = len(EXTENDED_APP_IDS)
    
    print("\n" + "=" * 60)
    print("SELECT AUTHENTICATION APP")
    print("=" * 60)
    
    if file_modified:
        print(f"[i] Microsoft Apps DB: {extended_count} apps (updated: {file_modified.strftime('%Y-%m-%d %H:%M')})")
    else:
        print("[i] Microsoft Apps DB: Not downloaded. Use option 12 to download.")
    
    print("\n0.  << Go back to auth method selection")
    print("-" * 60)
    print("TOP 10 PRE-CONSENTED APPS (High Success Rate):")
    print("-" * 60)
    
    # Top 10 default apps
    app_keys = ["graph_powershell", "graph_explorer", "office", "teams", 
                "azure_cli", "azure_powershell", "outlook", "sharepoint", 
                "azure_portal", "intune"]
    
    for i, key in enumerate(app_keys, 1):
        app_id, app_name = DEFAULT_APP_IDS[key]
        recommended = " (recommended)" if key == "graph_powershell" else ""
        print(f"{i:2}.  {app_name}{recommended}")
    
    print("-" * 60)
    print("EXTENDED OPTIONS:")
    print("-" * 60)
    if extended_count > 0:
        print(f"11. AUTO-TRY ALL ({extended_count} apps) - Tries each app until auth succeeds")
    else:
        print("11. AUTO-TRY ALL - Download Microsoft Apps DB first (option 12)")
    print("12. Download/Update Microsoft Apps Database")
    print("13. Enter custom App ID")
    
    max_choice = 13
    choice = input(f"\nSelect (0-{max_choice}): ").strip()
    
    if choice == "0":
        return None  # Signal to go back
    
    # Map choices 1-10 to default app keys
    app_map = {str(i+1): key for i, key in enumerate(app_keys)}
    
    if choice in app_map:
        app_id, app_name = DEFAULT_APP_IDS[app_map[choice]]
        print(f"\n[*] Selected: {app_name}")
        return app_id
    
    elif choice == "11":
        # Auto-try all app IDs
        if extended_count == 0:
            print("\n[!] Microsoft Apps database not found.")
            print("[*] Please download it first using option 12.")
            input("\nPress Enter to continue...")
            return select_app_id()  # Re-show menu
        return "AUTO_TRY_ALL"
    
    elif choice == "12":
        # Download/Update Microsoft Apps JSON
        download_microsoft_apps_json()
        input("\nPress Enter to continue...")
        return select_app_id()  # Re-show menu after download
    
    elif choice == "13":
        print("\n" + "-" * 50)
        print("To create your own public client app:")
        print("1. Go to Azure Portal > Entra ID > App registrations")
        print("2. New registration > Name it anything")
        print("3. Set 'Supported account types' to your org only")
        print("4. Redirect URI: Public client > http://localhost")
        print("5. Copy the Application (client) ID")
        print("-" * 50)
        custom_id = input("\nEnter your App ID: ").strip()
        if custom_id:
            return custom_id
        return select_app_id()  # Re-show menu if empty
    
    else:
        # Invalid choice, default to graph_powershell
        print("\n[!] Invalid choice. Using Microsoft Graph PowerShell.")
        return KNOWN_APP_IDS["graph_powershell"]


def select_auth_method() -> str:
    """Let user select authentication method."""
    print("\nAuthentication method:")
    print("0. Exit")
    print("-" * 40)
    print("QUICK OPTIONS:")
    print("1. Interactive browser (recommended)")
    print("2. Device code (for remote/headless sessions)")
    print("3. Auto-detect (try ALL methods automatically)")
    print("-" * 40)
    print("SPECIFIC METHODS:")
    print("4. Azure CLI token (if 'az login' done)")
    print("5. Azure PowerShell token (if 'Connect-AzAccount' done)")
    print("6. Shared token cache (Office/Teams cached tokens)")
    print("7. VS Code Azure extension")
    print("8. Managed Identity (Azure VM/App Service)")
    print("9. Environment variable (GRAPH_ACCESS_TOKEN)")
    print("10. Manual token input (paste from elsewhere)")
    print("11. Refresh token exchange")
    
    return input("\nSelect (0-11): ").strip()


def configure_stealth_settings():
    """Interactive configuration for stealth and evasion settings."""
    print("\n" + "=" * 60)
    print("STEALTH & EVASION CONFIGURATION")
    print("=" * 60)
    
    # Show current status
    show_stealth_status()
    
    print("\nOptions:")
    print("1. Toggle stealth mode (on/off)")
    print("2. Set base delay (seconds)")
    print("3. Set jitter range (seconds)")
    print("4. Set max retries for throttling")
    print("5. Toggle quiet mode")
    print("6. Reset to defaults")
    print("7. Preset: Aggressive (fast, low stealth)")
    print("8. Preset: Balanced (moderate delays)")
    print("9. Preset: Paranoid (slow, maximum stealth)")
    print("0. Back to main menu")
    
    choice = input("\nSelect option (0-9): ").strip()
    
    config = _stealth_config
    
    if choice == "1":
        new_state = not config.enabled
        set_stealth_config(enabled=new_state)
        state_str = "ENABLED" if new_state else "DISABLED"
        print(f"\n[+] Stealth mode {state_str}")
        if new_state:
            print(f"    Base delay: {config.base_delay}s, Jitter: +/-{config.jitter}s")
    
    elif choice == "2":
        try:
            delay = float(input("Enter base delay in seconds (0-60): ").strip())
            set_stealth_config(base_delay=delay)
            print(f"[+] Base delay set to {config.base_delay}s")
        except ValueError:
            print("[!] Invalid value. Please enter a number.")
    
    elif choice == "3":
        try:
            jitter = float(input("Enter jitter range in seconds (0-30): ").strip())
            set_stealth_config(jitter=jitter)
            print(f"[+] Jitter range set to +/-{config.jitter}s")
        except ValueError:
            print("[!] Invalid value. Please enter a number.")
    
    elif choice == "4":
        try:
            retries = int(input("Enter max retries (1-10): ").strip())
            set_stealth_config(max_retries=retries)
            print(f"[+] Max retries set to {config.max_retries}")
        except ValueError:
            print("[!] Invalid value. Please enter an integer.")
    
    elif choice == "5":
        new_state = not config.quiet_mode
        set_stealth_config(quiet_mode=new_state)
        state_str = "ENABLED" if new_state else "DISABLED"
        print(f"[+] Quiet mode {state_str}")
    
    elif choice == "6":
        # Reset to defaults
        set_stealth_config(enabled=False, base_delay=0.0, jitter=0.0, max_retries=3, quiet_mode=False)
        reset_stealth_stats()
        print("[+] Stealth settings reset to defaults")
    
    elif choice == "7":
        # Aggressive preset - fast with minimal delays
        set_stealth_config(enabled=True, base_delay=0.1, jitter=0.05, max_retries=2, quiet_mode=True)
        print("[+] Aggressive preset applied:")
        print("    Delay: 0.1s, Jitter: +/-0.05s, Retries: 2, Quiet: ON")
    
    elif choice == "8":
        # Balanced preset - moderate stealth
        set_stealth_config(enabled=True, base_delay=0.5, jitter=0.3, max_retries=3, quiet_mode=False)
        print("[+] Balanced preset applied:")
        print("    Delay: 0.5s, Jitter: +/-0.3s, Retries: 3, Quiet: OFF")
    
    elif choice == "9":
        # Paranoid preset - maximum stealth
        set_stealth_config(enabled=True, base_delay=2.0, jitter=1.5, max_retries=5, quiet_mode=False)
        print("[+] Paranoid preset applied:")
        print("    Delay: 2.0s, Jitter: +/-1.5s, Retries: 5, Quiet: OFF")
    
    elif choice == "0":
        return
    
    else:
        print("[!] Invalid option")


def show_menu():
    """Display the main menu."""
    print("\n" + "-" * 60)
    print("ENUMERATION OPTIONS:")
    print("-" * 60)
    print("1.  Direct /users endpoint")
    print("2.  Search users by name")
    print("3.  Basic alternatives (People API, Groups, Manager chain)")
    print("4.  Advanced fallbacks (Calendar, Email, Teams, etc.)")
    print("5.  FULL enumeration (ALL methods)")
    print("-" * 30)
    print("SECURITY ASSESSMENT:")
    print("-" * 30)
    print("20. [HIGH] MFA Status Check")
    print("21. [HIGH] Privileged Role Enumeration")
    print("22. [HIGH] Applications & Service Principals")
    print("23. [MED]  Stale Accounts (no recent login)")
    print("24. [MED]  Guest/External Users")
    print("25. [MED]  Password Never Expires")
    print("26. Full Security Assessment (all above)")
    print("-" * 30)
    print("CREDENTIAL ATTACK SURFACE:")
    print("-" * 30)
    print("27. [HIGH] Password Policies per User")
    print("28. [HIGH] SSPR Enabled Users")
    print("29. [HIGH] Legacy Authentication Users")
    print("30. [HIGH] App Passwords Configured")
    print("31. Full Credential Attack Surface Assessment")
    print("-" * 30)
    print("CONDITIONAL ACCESS ANALYSIS:")
    print("-" * 30)
    print("32. [HIGH] Enumerate CA Policies")
    print("33. [HIGH] CA Policy Exclusions (Security Gaps)")
    print("34. [HIGH] MFA Enforcement Gaps")
    print("35. Full CA Analysis (all above)")
    print("-" * 30)
    print("DEVICE ENUMERATION:")
    print("-" * 30)
    print("36. [MED]  All Registered Devices")
    print("37. [HIGH] Non-Compliant Devices")
    print("38. [MED]  BYOD/Personal Devices")
    print("39. [MED]  Devices per User")
    print("-" * 30)
    print("INTUNE/ENDPOINT MANAGER:")
    print("-" * 30)
    print("40. [HIGH] Intune Managed Devices")
    print("41. [HIGH] Intune Compliance Policies")
    print("42. [MED]  Intune Configuration Profiles")
    print("43. [HIGH] Intune Device Administrators")
    print("-" * 30)
    print("ADMINISTRATIVE UNIT ENUMERATION:")
    print("-" * 30)
    print("44. [MED]  List Administrative Units")
    print("45. [HIGH] Scoped Role Assignments (AU Admins)")
    print("-" * 30)
    print("LICENSE INFORMATION:")
    print("-" * 30)
    print("46. [MED]  Tenant License SKUs")
    print("47. [HIGH] User License Assignments")
    print("48. [HIGH] E5/P2 Privileged Users (PIM/Defender access)")
    print("-" * 30)
    print("DIRECTORY SYNC STATUS:")
    print("-" * 30)
    print("49. [MED]  On-Prem Synced vs Cloud-Only Users")
    print("50. [HIGH] Directory Sync Errors")
    print("-" * 30)
    print("ATTACK PATH ANALYSIS:")
    print("-" * 30)
    print("51. [CRIT] Full Attack Path Analysis")
    print("52. [HIGH] Password Reset Delegations")
    print("53. [HIGH] Privileged Group Owners")
    print("54. [HIGH] Group Membership Privileges")
    print("-" * 30)
    print("POWER PLATFORM ENUMERATION:")
    print("-" * 30)
    print("55. [HIGH] Power Apps Enumeration (Owners/Users)")
    print("56. [CRIT] Power Automate Flows (Sensitive Connectors)")
    print("-" * 30)
    print("LATERAL MOVEMENT ANALYSIS:")
    print("-" * 30)
    print("57. [CRIT] Full Lateral Movement Analysis")
    print("58. [HIGH] Transitive Group Memberships (Group Nesting)")
    print("59. [HIGH] Shared Mailbox Access")
    print("60. [HIGH] Calendar/Mailbox Delegations")
    print("-" * 30)
    print("BLOODHOUND / ATTACK PATH EXPORT:")
    print("-" * 30)
    print("61. [CRIT] Export to BloodHound/AzureHound Format")
    print("-" * 30)
    print("HTML REPORT GENERATION:")
    print("-" * 30)
    print("62. [NEW]  Generate Interactive HTML Report")
    print("-" * 30)
    print("INDIVIDUAL ENUMERATION:")
    print("-" * 30)
    print("6.  People API")
    print("7.  Manager chain")
    print("8.  Group members")
    print("9.  Microsoft Search API")
    print("10. Calendar attendees")
    print("11. Email recipients")
    print("12. OneDrive sharing")
    print("13. Teams rosters")
    print("14. Planner assignees")
    print("15. SharePoint profiles")
    print("16. Azure Resource Manager")
    print("17. Meeting rooms/resources")
    print("18. Yammer/Viva Engage communities")
    print("-" * 30)
    print("19. Export users to file")
    print("-" * 30)
    print("98. Configure stealth settings")
    print("99. Change authentication method")
    print("0.  Exit")
    print("")


def main():
    print("\n" + "=" * 70)
    print("Azure Entra ID User Enumeration")
    print("=" * 70)
    print("\nThis script includes ALL fallback methods for restricted environments.")
    print("It will try multiple enumeration techniques until one succeeds.")
    print("No app secrets required!\n")

    global PUBLIC_CLIENT_APP_ID
    
    access_token = None
    
    # Authentication loop with go-back support
    while access_token is None:
        try:
            auth_method = select_auth_method()
        except (KeyboardInterrupt, EOFError):
            print("\n\n[!] Interrupted. Exiting...")
            return
        
        # Exit option
        if auth_method == "0":
            print("\nGoodbye!")
            return
        
        try:
            # Auto-detect: try all methods automatically
            if auth_method == "3":
                print("\nTenant ID (press Enter for 'common' to auto-detect):")
                tenant = input("Tenant ID: ").strip() or "common"
                access_token, _ = get_access_token_with_fallback(tenant, use_device_code=False)
            
            # Specific method: Azure CLI
            elif auth_method == "4":
                access_token = get_token_from_az_cli()
            
            # Specific method: Azure PowerShell
            elif auth_method == "5":
                access_token = get_token_from_az_powershell()
            
            # Specific method: Shared token cache
            elif auth_method == "6":
                access_token = get_token_from_shared_cache()
            
            # Specific method: VS Code
            elif auth_method == "7":
                access_token = get_token_from_vscode()
            
            # Specific method: Managed Identity
            elif auth_method == "8":
                access_token = get_token_from_managed_identity()
            
            # Specific method: Environment variable
            elif auth_method == "9":
                access_token = get_token_from_environment()
                if not access_token:
                    print("\n[!] Set one of these environment variables:")
                    print("    - GRAPH_ACCESS_TOKEN")
                    print("    - AZURE_ACCESS_TOKEN")
                    print("    - ACCESS_TOKEN")
            
            # Specific method: Manual token input
            elif auth_method == "10":
                access_token = get_token_manual_input()
            
            # Specific method: Refresh token exchange
            elif auth_method == "11":
                print("\nPaste refresh token (from ROADtools, TokenTactics, etc.):")
                refresh_token = input("Refresh Token: ").strip()
                if refresh_token:
                    print("\nTenant ID (press Enter for 'common'):")
                    tenant = input("Tenant ID: ").strip() or "common"
                    access_token = get_token_from_refresh_token(refresh_token, tenant)
            
            # Interactive browser or device code with app selection
            elif auth_method in ("1", "2"):
                selected_app = select_app_id()
                if selected_app is None:
                    # User chose to go back
                    continue
                
                print("\nTenant ID (press Enter for 'common' to auto-detect):")
                tenant = input("Tenant ID: ").strip() or "common"
                
                # Check if user selected AUTO_TRY_ALL mode
                if selected_app == "AUTO_TRY_ALL":
                    use_device_code = (auth_method == "2")
                    access_token = try_all_app_ids_auth(tenant, use_device_code)
                else:
                    PUBLIC_CLIENT_APP_ID = selected_app
                    print(f"\n[*] Using App ID: {PUBLIC_CLIENT_APP_ID}")
                    
                    if auth_method == "2":
                        access_token = get_access_token_device_code(tenant)
                    else:
                        access_token = get_access_token_interactive(tenant)
            
            else:
                print("[!] Invalid option. Please try again.")
                continue
        
        except (KeyboardInterrupt, EOFError):
            print("\n\n[!] Interrupted during authentication. Exiting...")
            return
        
        # If authentication failed, ask if user wants to try again
        if access_token is None:
            print("\n" + "-" * 50)
            print("[!] Authentication failed or timed out.")
            print("-" * 50)
            print("You can:")
            print("  1. Try a different App ID (some apps work better than others)")
            print("  2. Try a different authentication method")
            print("  3. Use device code flow if browser auth keeps failing")
            print("  4. Check if the app is blocked or requires admin consent")
            print("-" * 50)
            try:
                retry = input("\nTry another method? (y/n) [y]: ").strip().lower()
                if retry == 'n':
                    print("\nGoodbye!")
                    return
                # Default to yes if user just presses Enter
            except (KeyboardInterrupt, EOFError):
                print("\n\nGoodbye!")
                return

    print("\n[*] Getting current user info...")
    me = get_current_user(access_token)
    if me:
        print(f"[+] Signed in as: {me.get('displayName')} ({me.get('userPrincipalName')})")

    all_users = []

    while True:
        try:
            show_menu()
            option = input("Select option: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n[!] Interrupted. Exiting...")
            break

        if option == "1":
            print("\n[*] Enumerating users via /users endpoint...")
            users = get_users(access_token)
            if users:
                for u in users:
                    u["source"] = "direct"
                all_users = users
                print_user_summary(users)
            else:
                print("[!] No users found. Try other methods.")

        elif option == "2":
            search_term = input("Search term (or 'cancel' to go back): ").strip()
            if search_term and search_term.lower() != 'cancel':
                print(f"\n[*] Searching for '{search_term}'...")
                results = search_users(access_token, search_term)
                if results:
                    print_user_summary(results)
                else:
                    print("[!] No users found.")

        elif option == "3":
            results = enumerate_basic_methods(access_token)
            all_users = merge_user_results(results)
            if all_users:
                print(f"\n[+] Total unique users: {len(all_users)}")
                print_user_summary(all_users, show_source=True)
            else:
                print("\n[!] No users found via basic methods.")

        elif option == "4":
            results = enumerate_advanced_methods(access_token)
            all_users = merge_user_results(results)
            if all_users:
                print(f"\n[+] Total unique users: {len(all_users)}")
                print_user_summary(all_users, show_source=True)
            else:
                print("\n[!] No users found via advanced methods.")

        elif option == "5":
            results = enumerate_all_methods(access_token)
            all_users = merge_user_results(results)
            print(f"\n[+] TOTAL UNIQUE USERS FOUND: {len(all_users)}")
            print_user_summary(all_users, show_source=True)

        elif option == "6":
            users = get_people(access_token)
            if users:
                for u in users:
                    u["source"] = "people"
                all_users = merge_user_results({"people": users})
                print_user_summary(all_users, show_source=True)

        elif option == "7":
            users = get_manager_chain(access_token)
            if users:
                for u in users:
                    u["source"] = "managers"
                all_users = merge_user_results({"managers": users})
                print_user_summary(all_users, show_source=True)

        elif option == "8":
            users = get_group_members(access_token)
            if users:
                for u in users:
                    u["source"] = "groups"
                all_users = merge_user_results({"groups": users})
                print_user_summary(all_users, show_source=True)

        elif option == "9":
            users = get_users_via_search_api(access_token)
            if users:
                for u in users:
                    u["source"] = "search"
                all_users = merge_user_results({"search": users})
                print_user_summary(all_users, show_source=True)

        elif option == "10":
            users = get_users_from_calendar(access_token)
            if users:
                for u in users:
                    u["source"] = "calendar"
                all_users = merge_user_results({"calendar": users})
                print_user_summary(all_users, show_source=True)

        elif option == "11":
            users = get_users_from_emails(access_token)
            if users:
                for u in users:
                    u["source"] = "email"
                all_users = merge_user_results({"email": users})
                print_user_summary(all_users, show_source=True)

        elif option == "12":
            users = get_users_from_onedrive_sharing(access_token)
            if users:
                for u in users:
                    u["source"] = "onedrive"
                all_users = merge_user_results({"onedrive": users})
                print_user_summary(all_users, show_source=True)

        elif option == "13":
            users = get_users_from_teams(access_token)
            if users:
                for u in users:
                    u["source"] = "teams"
                all_users = merge_user_results({"teams": users})
                print_user_summary(all_users, show_source=True)

        elif option == "14":
            users = get_users_from_planner(access_token)
            if users:
                for u in users:
                    u["source"] = "planner"
                all_users = merge_user_results({"planner": users})
                print_user_summary(all_users, show_source=True)

        elif option == "15":
            users = get_users_from_sharepoint_profiles(access_token)
            if users:
                for u in users:
                    u["source"] = "sharepoint"
                all_users = merge_user_results({"sharepoint": users})
                print_user_summary(all_users, show_source=True)

        elif option == "16":
            users = get_users_from_azure_rm(access_token)
            if users:
                for u in users:
                    u["source"] = "azure_rm"
                all_users = merge_user_results({"azure_rm": users})
                print_user_summary(all_users, show_source=True)

        elif option == "17":
            resources = get_room_lists_and_rooms(access_token)
            if resources:
                for r in resources:
                    r["source"] = "rooms"
                print_user_summary(resources, show_source=True)

        elif option == "18":
            users = get_users_from_yammer(access_token)
            if users:
                all_users = merge_user_results({"yammer": users})
                print_user_summary(all_users, show_source=True)

        # Security Assessment Options
        elif option == "20":
            print("\n[*] Running MFA Status Check...")
            print("    (This may take a while for large directories)")
            mfa_results = get_user_mfa_status(access_token)
            if not mfa_results:
                print("[*] Trying alternative MFA registration report...")
                mfa_results = get_user_mfa_registration_details(access_token)
            if mfa_results:
                print_mfa_status_report(mfa_results)
                prompt_export_results(mfa_results, "mfa_status")
            else:
                print("[!] MFA status check failed. Insufficient permissions.")

        elif option == "21":
            priv_users = get_privileged_users(access_token)
            if priv_users:
                print_privileged_users_report(priv_users)
                prompt_export_results(priv_users, "privileged_users")
            else:
                print("[!] No privileged users found or access denied.")

        elif option == "22":
            apps_data = get_applications_and_service_principals(access_token)
            print_apps_report(apps_data)
            # Combine all apps data for export
            all_apps_export = []
            if apps_data.get("applications"):
                for app in apps_data["applications"]:
                    app["type"] = "Application"
                    all_apps_export.append(app)
            if apps_data.get("service_principals"):
                for sp in apps_data["service_principals"]:
                    sp["type"] = "ServicePrincipal"
                    all_apps_export.append(sp)
            if apps_data.get("high_risk_apps"):
                for hra in apps_data["high_risk_apps"]:
                    hra["type"] = "HighRiskApp"
                    all_apps_export.append(hra)
            prompt_export_results(all_apps_export, "applications")

        elif option == "23":
            print("Enter days threshold (default 90):")
            try:
                days_input = input("Days: ").strip()
                days = int(days_input) if days_input else 90
            except ValueError:
                days = 90
            stale = get_stale_accounts(access_token, days)
            if stale:
                print_stale_accounts_report(stale)
                prompt_export_results(stale, "stale_accounts")
            else:
                print("[!] No stale accounts found or access denied.")

        elif option == "24":
            guests = get_guest_users(access_token)
            if guests:
                print_user_summary(guests, show_source=False)
                prompt_export_results(guests, "guest_users")
            else:
                print("[!] No guest users found or access denied.")

        elif option == "25":
            pwd_users = get_users_with_password_never_expires(access_token)
            if pwd_users:
                print_security_summary(pwd_users, "PASSWORD NEVER EXPIRES")
                print(f"{'Display Name':<30} {'Email/UPN':<45} {'Policy':<25}")
                print("-" * 100)
                for user in pwd_users:
                    name = (user.get("displayName") or "N/A")[:29]
                    email = (user.get("userPrincipalName") or "N/A")[:44]
                    policy = (user.get("passwordPolicies") or "N/A")[:24]
                    print(f"{name:<30} {email:<45} {policy:<25}")
                print("-" * 100)
                prompt_export_results(pwd_users, "password_never_expires")
            else:
                print("[!] No users with password never expires or access denied.")

        elif option == "26":
            print("\n" + "=" * 70)
            print("FULL SECURITY ASSESSMENT")
            print("=" * 70)
            print("\nThis will run all security assessment checks:")
            print("  - MFA Status Check")
            print("  - Privileged Role Enumeration")
            print("  - Applications & Service Principals")
            print("  - Stale Accounts")
            print("  - Guest Users")
            print("  - Password Never Expires")
            print("\nThis may take several minutes for large directories.")
            confirm = input("\nContinue? (y/n): ").strip().lower()
            
            if confirm == 'y':
                security_results = {}
                
                print("\n[1/6] MFA Status...")
                mfa_results = get_user_mfa_status(access_token)
                if not mfa_results:
                    mfa_results = get_user_mfa_registration_details(access_token)
                security_results["mfa"] = mfa_results
                
                print("\n[2/6] Privileged Roles...")
                security_results["privileged"] = get_privileged_users(access_token)
                
                print("\n[3/6] Applications...")
                security_results["apps"] = get_applications_and_service_principals(access_token)
                
                print("\n[4/6] Stale Accounts...")
                security_results["stale"] = get_stale_accounts(access_token)
                
                print("\n[5/6] Guest Users...")
                security_results["guests"] = get_guest_users(access_token)
                
                print("\n[6/6] Password Policies...")
                security_results["pwd_never_expires"] = get_users_with_password_never_expires(access_token)
                
                # Print summary
                print("\n" + "=" * 70)
                print("SECURITY ASSESSMENT SUMMARY")
                print("=" * 70)
                
                mfa_no_mfa = sum(1 for u in security_results.get("mfa", []) if u.get("riskLevel") == "HIGH")
                priv_critical = sum(1 for u in security_results.get("privileged", []) if u.get("riskLevel") == "CRITICAL")
                priv_high = sum(1 for u in security_results.get("privileged", []) if u.get("riskLevel") == "HIGH")
                high_risk_apps = len(security_results.get("apps", {}).get("high_risk_apps", []))
                stale_enabled = sum(1 for u in security_results.get("stale", []) if u.get("accountEnabled", True))
                
                print(f"\n  Users without MFA (HIGH RISK):     {mfa_no_mfa}")
                print(f"  CRITICAL privileged roles:         {priv_critical}")
                print(f"  HIGH privileged roles:             {priv_high}")
                print(f"  High-risk applications:            {high_risk_apps}")
                print(f"  Stale accounts (still enabled):    {stale_enabled}")
                print(f"  Guest users:                       {len(security_results.get('guests', []))}")
                print(f"  Password never expires:            {len(security_results.get('pwd_never_expires', []))}")
                
                print("\n" + "-" * 70)
                # Combine all results for export
                all_security_export = []
                for item in security_results.get("mfa", []):
                    item["category"] = "MFA"
                    all_security_export.append(item)
                for item in security_results.get("privileged", []):
                    item["category"] = "Privileged"
                    all_security_export.append(item)
                for item in security_results.get("stale", []):
                    item["category"] = "Stale"
                    all_security_export.append(item)
                for item in security_results.get("guests", []):
                    item["category"] = "Guest"
                    all_security_export.append(item)
                for item in security_results.get("pwd_never_expires", []):
                    item["category"] = "PasswordNeverExpires"
                    all_security_export.append(item)
                prompt_export_results(all_security_export, "security_assessment")

        # Credential Attack Surface Options
        elif option == "27":
            pwd_policies = run_with_cancel_support(get_user_password_policies, access_token)
            if pwd_policies:
                print_security_summary(pwd_policies, "PASSWORD POLICIES PER USER")
                print(f"{'Display Name':<22} {'Email/UPN':<35} {'Last Change':<12} {'Days':<8} {'Risk Factors':<17} {'Risk':<7}")
                print("-" * 110)
                
                # Sort by risk level
                risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
                sorted_users = sorted(pwd_policies, key=lambda x: risk_order.get(x.get("riskLevel", "LOW"), 3))
                
                for user in sorted_users[:50]:
                    name = (user.get("displayName") or "N/A")[:21]
                    email = (user.get("userPrincipalName") or "N/A")[:34]
                    last_change = str(user.get("lastPasswordChange") or "Unknown")[:11]
                    days = str(user.get("daysSincePasswordChange") or "N/A")[:7]
                    risk_factors = (user.get("riskFactors") or "")[:16]
                    risk = user.get("riskLevel", "")
                    print(f"{name:<22} {email:<35} {last_change:<12} {days:<8} {risk_factors:<17} {risk:<7}")
                
                if len(pwd_policies) > 50:
                    print(f"    ... and {len(pwd_policies) - 50} more")
                print("-" * 110)
                prompt_export_results(pwd_policies, "password_policies")
            else:
                print("[!] Password policy check failed or access denied.")

        elif option == "28":
            sspr_users = run_with_cancel_support(get_sspr_enabled_users, access_token)
            if sspr_users:
                print_security_summary(sspr_users, "SSPR ENABLED USERS")
                print(f"{'Display Name':<22} {'Email/UPN':<35} {'Registered':<10} {'Enabled':<10} {'Weak Methods':<20} {'Risk':<7}")
                print("-" * 110)
                
                # Sort by risk level
                risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
                sorted_users = sorted(sspr_users, key=lambda x: risk_order.get(x.get("riskLevel", "LOW"), 3))
                
                for user in sorted_users[:50]:
                    name = (user.get("displayName") or "N/A")[:21]
                    email = (user.get("userPrincipalName") or "N/A")[:34]
                    registered = "Yes" if user.get("isSsprRegistered") else "No"
                    enabled = "Yes" if user.get("isSsprEnabled") else "No"
                    weak_methods = (user.get("weakMethods") or "")[:19]
                    risk = user.get("riskLevel", "")
                    print(f"{name:<22} {email:<35} {registered:<10} {enabled:<10} {weak_methods:<20} {risk:<7}")
                
                if len(sspr_users) > 50:
                    print(f"    ... and {len(sspr_users) - 50} more")
                print("-" * 110)
                prompt_export_results(sspr_users, "sspr_users")
            else:
                print("[!] SSPR check failed or access denied.")

        elif option == "29":
            legacy_users = run_with_cancel_support(get_legacy_authentication_users, access_token)
            if legacy_users:
                print_security_summary(legacy_users, "LEGACY AUTHENTICATION USERS (HIGH RISK)")
                print(f"{'Display Name':<22} {'Email/UPN':<35} {'Legacy Protocols':<25} {'Last Sign-In':<12} {'Risk':<7}")
                print("-" * 110)
                
                for user in legacy_users[:50]:
                    name = (user.get("displayName") or "N/A")[:21]
                    email = (user.get("userPrincipalName") or "N/A")[:34]
                    protocols = (user.get("legacyProtocols") or "")[:24]
                    last_sign_in = str(user.get("lastLegacySignIn") or "Unknown")[:11]
                    risk = user.get("riskLevel", "")
                    print(f"{name:<22} {email:<35} {protocols:<25} {last_sign_in:<12} {risk:<7}")
                
                if len(legacy_users) > 50:
                    print(f"    ... and {len(legacy_users) - 50} more")
                print("-" * 110)
                prompt_export_results(legacy_users, "legacy_auth_users")
            else:
                print("[+] No legacy authentication usage detected or access denied.")

        elif option == "30":
            app_pwd_users = run_with_cancel_support(get_users_with_app_passwords, access_token)
            if app_pwd_users:
                print_security_summary(app_pwd_users, "USERS WITH APP PASSWORDS (HIGH RISK)")
                print(f"{'Display Name':<25} {'Email/UPN':<40} {'Risk Reason':<20} {'Risk':<7}")
                print("-" * 100)
                
                for user in app_pwd_users:
                    name = (user.get("displayName") or "N/A")[:24]
                    email = (user.get("userPrincipalName") or "N/A")[:39]
                    reason = (user.get("riskReason") or "")[:19]
                    risk = user.get("riskLevel", "")
                    print(f"{name:<25} {email:<40} {reason:<20} {risk:<7}")
                
                print("-" * 100)
                prompt_export_results(app_pwd_users, "app_password_users")
            else:
                print("[+] No users with app passwords detected or access denied.")

        elif option == "31":
            print("\n" + "=" * 70)
            print("CREDENTIAL ATTACK SURFACE ASSESSMENT")
            print("=" * 70)
            print("\nThis will run all credential attack surface assessments:")
            print("  - Password Policies per User")
            print("  - SSPR Enabled Users")
            print("  - Legacy Authentication Users")
            print("  - App Passwords Configured")
            print("\nThis may take several minutes for large directories.")
            print("(Press Ctrl+C at any time to cancel)")
            confirm = input("\nContinue? (y/n): ").strip().lower()
            
            if confirm == 'y':
                cred_results = {}
                reset_cancellation()
                
                try:
                    print("\n[1/4] Password Policies...")
                    cred_results["pwd_policies"] = get_user_password_policies(access_token)
                    
                    if not is_cancelled():
                        print("\n[2/4] SSPR Configuration...")
                        cred_results["sspr"] = get_sspr_enabled_users(access_token)
                    
                    if not is_cancelled():
                        print("\n[3/4] Legacy Authentication...")
                        cred_results["legacy_auth"] = get_legacy_authentication_users(access_token)
                    
                    if not is_cancelled():
                        print("\n[4/4] App Passwords...")
                        cred_results["app_passwords"] = get_users_with_app_passwords(access_token)
                except KeyboardInterrupt:
                    request_cancellation()
                    print("\n[!] Assessment cancelled by user.")
                
                # Print summary (even partial results)
                if cred_results:
                    print_credential_attack_surface_report(
                        cred_results.get("pwd_policies", []),
                        cred_results.get("sspr", []),
                        cred_results.get("legacy_auth", []),
                        cred_results.get("app_passwords", [])
                    )
                    if is_cancelled():
                        print("[!] Note: Results may be incomplete due to cancellation.")
                    # Combine all results for export
                    all_cred_export = []
                    for item in cred_results.get("pwd_policies", []):
                        item["category"] = "PasswordPolicy"
                        all_cred_export.append(item)
                    for item in cred_results.get("sspr", []):
                        item["category"] = "SSPR"
                        all_cred_export.append(item)
                    for item in cred_results.get("legacy_auth", []):
                        item["category"] = "LegacyAuth"
                        all_cred_export.append(item)
                    for item in cred_results.get("app_passwords", []):
                        item["category"] = "AppPasswords"
                        all_cred_export.append(item)
                    prompt_export_results(all_cred_export, "credential_attack_surface")

        # Conditional Access Analysis Options
        elif option == "32":
            ca_policies = run_with_cancel_support(get_conditional_access_policies, access_token)
            if ca_policies:
                print_ca_policies_report(ca_policies)
                prompt_export_results(ca_policies, "ca_policies")
            else:
                print("[!] CA policy enumeration failed or access denied.")
                print("    Requires Policy.Read.All permission")

        elif option == "33":
            ca_exclusions = run_with_cancel_support(get_ca_policy_exclusions, access_token)
            if ca_exclusions and (ca_exclusions.get("excluded_users") or 
                                  ca_exclusions.get("excluded_groups") or 
                                  ca_exclusions.get("excluded_roles")):
                print_ca_exclusions_report(ca_exclusions)
                # Combine exclusions for export
                all_exclusions_export = []
                for item in ca_exclusions.get("excluded_users", []):
                    item["exclusionType"] = "User"
                    all_exclusions_export.append(item)
                for item in ca_exclusions.get("excluded_groups", []):
                    item["exclusionType"] = "Group"
                    all_exclusions_export.append(item)
                for item in ca_exclusions.get("excluded_roles", []):
                    item["exclusionType"] = "Role"
                    all_exclusions_export.append(item)
                prompt_export_results(all_exclusions_export, "ca_exclusions")
            else:
                print("[!] No CA exclusions found or access denied.")

        elif option == "34":
            mfa_gaps = run_with_cancel_support(get_mfa_enforcement_gaps, access_token)
            if mfa_gaps and mfa_gaps.get("summary"):
                print_mfa_gaps_report(mfa_gaps)
                prompt_export_results(mfa_gaps.get("summary", []), "mfa_gaps")
            else:
                print("[!] MFA gap analysis failed or access denied.")

        elif option == "35":
            print("\n" + "=" * 70)
            print("FULL CONDITIONAL ACCESS ANALYSIS")
            print("=" * 70)
            print("\nThis will run all CA analysis checks:")
            print("  - Enumerate all CA Policies")
            print("  - Identify excluded users/groups/roles")
            print("  - Find MFA enforcement gaps")
            print("\nRequires Policy.Read.All permission.")
            print("(Press Ctrl+C at any time to cancel)")
            confirm = input("\nContinue? (y/n): ").strip().lower()
            
            if confirm == 'y':
                reset_cancellation()
                try:
                    ca_results = run_full_ca_analysis(access_token)
                    
                    # Print detailed reports
                    if ca_results.get("policies"):
                        print_ca_policies_report(ca_results["policies"])
                    
                    if ca_results.get("exclusions"):
                        print_ca_exclusions_report(ca_results["exclusions"])
                    
                    if ca_results.get("mfa_gaps"):
                        print_mfa_gaps_report(ca_results["mfa_gaps"])
                    
                    if is_cancelled():
                        print("[!] Note: Results may be incomplete due to cancellation.")
                    
                    # Combine all CA results for export
                    all_ca_export = []
                    for item in ca_results.get("policies", []):
                        item["category"] = "Policy"
                        all_ca_export.append(item)
                    if ca_results.get("exclusions"):
                        for item in ca_results["exclusions"].get("excluded_users", []):
                            item["category"] = "ExcludedUser"
                            all_ca_export.append(item)
                        for item in ca_results["exclusions"].get("excluded_groups", []):
                            item["category"] = "ExcludedGroup"
                            all_ca_export.append(item)
                    if ca_results.get("mfa_gaps"):
                        for item in ca_results["mfa_gaps"].get("summary", []):
                            item["category"] = "MFAGap"
                            all_ca_export.append(item)
                    prompt_export_results(all_ca_export, "ca_analysis")
                except KeyboardInterrupt:
                    request_cancellation()
                    print("\n[!] Analysis cancelled by user.")

        # Device Enumeration Options
        elif option == "36":
            print("\n[*] Running All Devices Enumeration...")
            devices = get_all_devices(access_token)
            if devices:
                print_devices_report(devices, "ALL REGISTERED DEVICES")
                prompt_export_results(devices, "all_devices")
            else:
                print("[!] Device enumeration failed or access denied.")

        elif option == "37":
            print("\n[*] Running Non-Compliant Devices Check...")
            non_compliant = get_non_compliant_devices(access_token)
            if non_compliant:
                print_devices_report(non_compliant, "NON-COMPLIANT DEVICES (HIGH RISK)")
                prompt_export_results(non_compliant, "non_compliant_devices")
            else:
                print("[+] No non-compliant devices found or access denied.")

        elif option == "38":
            print("\n[*] Running BYOD/Personal Devices Enumeration...")
            byod = get_byod_devices(access_token)
            if byod:
                print_devices_report(byod, "BYOD/PERSONAL DEVICES")
                prompt_export_results(byod, "byod_devices")
            else:
                print("[+] No BYOD devices found or access denied.")

        elif option == "39":
            print("\n[*] Running Devices per User Enumeration...")
            print("    (This may take a while for large directories)")
            reset_cancellation()
            try:
                user_devices = get_user_devices(access_token)
                if user_devices:
                    print_user_devices_report(user_devices)
                    prompt_export_results(user_devices, "user_devices")
                else:
                    print("[!] No user devices found or access denied.")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        # Intune/Endpoint Manager Options
        elif option == "40":
            print("\n[*] Running Intune Managed Devices Enumeration...")
            print("    (Requires DeviceManagementManagedDevices.Read.All permission)")
            reset_cancellation()
            try:
                intune_devices = get_intune_managed_devices(access_token)
                if intune_devices:
                    print_intune_devices_report(intune_devices)
                    prompt_export_results(intune_devices, "intune_devices")
                else:
                    print("[!] No Intune managed devices found or access denied.")
                    print("    Requires DeviceManagementManagedDevices.Read.All permission")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        elif option == "41":
            print("\n[*] Running Intune Compliance Policies Enumeration...")
            print("    (Requires DeviceManagementConfiguration.Read.All permission)")
            reset_cancellation()
            try:
                compliance_policies = get_intune_compliance_policies(access_token)
                if compliance_policies:
                    print_intune_policies_report(compliance_policies, "INTUNE COMPLIANCE POLICIES")
                    prompt_export_results(compliance_policies, "intune_compliance_policies")
                else:
                    print("[!] No compliance policies found or access denied.")
                    print("    Requires DeviceManagementConfiguration.Read.All permission")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        elif option == "42":
            print("\n[*] Running Intune Configuration Profiles Enumeration...")
            print("    (Requires DeviceManagementConfiguration.Read.All permission)")
            reset_cancellation()
            try:
                config_profiles = get_intune_configuration_profiles(access_token)
                if config_profiles:
                    print_intune_policies_report(config_profiles, "INTUNE CONFIGURATION PROFILES")
                    prompt_export_results(config_profiles, "intune_config_profiles")
                else:
                    print("[!] No configuration profiles found or access denied.")
                    print("    Requires DeviceManagementConfiguration.Read.All permission")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        elif option == "43":
            print("\n[*] Running Intune Device Administrators Enumeration...")
            print("    (Finding Intune RBAC role assignments)")
            reset_cancellation()
            try:
                intune_admins = get_intune_device_administrators(access_token)
                if intune_admins:
                    print_intune_administrators_report(intune_admins)
                    prompt_export_results(intune_admins, "intune_admins")
                else:
                    print("[!] No Intune role assignments found or access denied.")
                    print("    Requires DeviceManagementRBAC.Read.All permission")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        # Administrative Unit Enumeration Options
        elif option == "44":
            print("\n[*] Running Administrative Unit Enumeration...")
            reset_cancellation()
            try:
                admin_units = get_administrative_units(access_token)
                if admin_units:
                    print_admin_units_report(admin_units)
                    
                    # Ask if user wants to see members
                    all_au_data = admin_units
                    see_members = input("\nView AU members? (y/n): ").strip().lower()
                    if see_members == 'y':
                        members = get_admin_unit_members(access_token)
                        if members:
                            print_admin_unit_members_report(members)
                            all_au_data = []
                            for item in admin_units:
                                item["recordType"] = "AdminUnit"
                                all_au_data.append(item)
                            for item in members:
                                item["recordType"] = "Member"
                                all_au_data.append(item)
                    prompt_export_results(all_au_data, "admin_units")
                else:
                    print("[!] No Administrative Units found or access denied.")
                    print("    Requires AdministrativeUnit.Read.All permission")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        elif option == "45":
            print("\n[*] Running Scoped Role Assignments Enumeration...")
            print("    (Identifying AU-scoped administrators)")
            reset_cancellation()
            try:
                scoped_admins = get_scoped_role_assignments(access_token)
                if scoped_admins:
                    print_scoped_admins_report(scoped_admins)
                    prompt_export_results(scoped_admins, "scoped_role_assignments")
                else:
                    print("[!] No scoped role assignments found or access denied.")
                    print("    Requires RoleManagement.Read.All or AdministrativeUnit.Read.All permission")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        # License Information Options
        elif option == "46":
            print("\n[*] Running Tenant License SKUs Enumeration...")
            reset_cancellation()
            try:
                tenant_skus = get_subscribed_skus(access_token)
                if tenant_skus:
                    print_tenant_skus_report(tenant_skus)
                    prompt_export_results(tenant_skus, "tenant_licenses")
                else:
                    print("[!] No license SKUs found or access denied.")
                    print("    Requires Organization.Read.All or Directory.Read.All permission")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        elif option == "47":
            print("\n[*] Running User License Assignments Enumeration...")
            print("    (This may take a while for large directories)")
            reset_cancellation()
            try:
                licensed_users = get_user_licenses(access_token)
                if licensed_users:
                    print_user_licenses_report(licensed_users)
                    prompt_export_results(licensed_users, "user_licenses")
                else:
                    print("[!] No licensed users found or access denied.")
                    print("    Requires User.Read.All permission")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        elif option == "48":
            print("\n[*] Running E5/P2 Privileged License Users Enumeration...")
            print("    (Identifying users with PIM, Defender, eDiscovery access)")
            reset_cancellation()
            try:
                priv_license_users = get_privileged_license_users(access_token)
                if priv_license_users:
                    print_privileged_license_users_report(priv_license_users)
                    prompt_export_results(priv_license_users, "privileged_license_users")
                else:
                    print("[!] No users with E5/P2 licenses found or access denied.")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        # Directory Sync Status Options
        elif option == "49":
            print("\n[*] Running Directory Sync Status Analysis...")
            print("    (Identifying on-prem synced vs cloud-only users)")
            reset_cancellation()
            try:
                sync_data = get_directory_sync_status(access_token)
                if sync_data and sync_data.get("summary", {}).get("totalUsers", 0) > 0:
                    print_directory_sync_status_report(sync_data)
                    # Combine sync data for export
                    all_sync_export = []
                    for item in sync_data.get("syncedUsers", []):
                        item["syncStatus"] = "Synced"
                        all_sync_export.append(item)
                    for item in sync_data.get("cloudOnlyUsers", []):
                        item["syncStatus"] = "CloudOnly"
                        all_sync_export.append(item)
                    prompt_export_results(all_sync_export, "directory_sync_status")
                else:
                    print("[!] Directory sync status check failed or access denied.")
                    print("    Requires User.Read.All permission")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        elif option == "50":
            print("\n[*] Checking for Directory Sync Errors...")
            print("    (Finding users with provisioning/sync issues)")
            reset_cancellation()
            try:
                sync_errors = get_directory_sync_errors(access_token)
                if sync_errors:
                    print_directory_sync_errors_report(sync_errors)
                    prompt_export_results(sync_errors, "directory_sync_errors")
                else:
                    print("[+] No directory sync errors found.")
                    print("    (Or access denied - requires User.Read.All permission)")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Check cancelled by user.")

        # Attack Path Analysis Options
        elif option == "51":
            print("\n[*] Running Full Attack Path Analysis...")
            print("    (Identifying privilege escalation paths)")
            reset_cancellation()
            try:
                attack_paths = get_attack_path_analysis(access_token)
                print_attack_path_report(attack_paths)
                # Combine attack path data for export
                all_attack_path_export = []
                for item in attack_paths.get("password_reset_users", []):
                    item["pathType"] = "PasswordReset"
                    all_attack_path_export.append(item)
                for item in attack_paths.get("group_owners", []):
                    item["pathType"] = "GroupOwner"
                    all_attack_path_export.append(item)
                for item in attack_paths.get("group_managers", []):
                    item["pathType"] = "GroupManager"
                    all_attack_path_export.append(item)
                for item in attack_paths.get("apps_with_group_write", []):
                    item["pathType"] = "AppGroupWrite"
                    all_attack_path_export.append(item)
                prompt_export_results(all_attack_path_export, "attack_paths")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Analysis cancelled by user.")

        elif option == "52":
            print("\n[*] Enumerating Password Reset Delegations...")
            print("    (Finding users who can reset passwords)")
            reset_cancellation()
            try:
                pwd_reset_results = get_password_reset_delegations(access_token)
                if pwd_reset_results.get("password_reset_users"):
                    print("\n" + "=" * 110)
                    print(f"{'PASSWORD RESET DELEGATIONS':^110}")
                    print("=" * 110)
                    print(f"\n{'Display Name':<23} {'Email/UPN':<34} {'Role':<34} {'Type':<10} {'Risk':<8}")
                    print("-" * 110)
                    for user in pwd_reset_results["password_reset_users"]:
                        name = (user.get("displayName") or "N/A")[:22]
                        email = (user.get("userPrincipalName") or "N/A")[:33]
                        role = (user.get("role") or "N/A")[:33]
                        assign_type = (user.get("assignmentType") or "Active")[:9]
                        risk = user.get("riskLevel", "")
                        print(f"{name:<23} {email:<34} {role:<34} {assign_type:<10} {risk:<8}")
                    print("-" * 110)
                    prompt_export_results(pwd_reset_results["password_reset_users"], "password_reset_delegations")
                else:
                    print("[!] No password reset delegations found or access denied.")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        elif option == "53":
            print("\n[*] Enumerating Privileged Group Owners...")
            print("    (Finding users who own privileged groups)")
            reset_cancellation()
            try:
                group_owners = get_group_owners(access_token)
                if group_owners.get("privileged_group_owners"):
                    print("\n" + "=" * 110)
                    print(f"{'PRIVILEGED GROUP OWNERS':^110}")
                    print("=" * 110)
                    print(f"\n{'Owner Name':<23} {'Owner UPN':<35} {'Group Name':<35} {'Role Grp?':<10} {'Risk':<7}")
                    print("-" * 110)
                    for owner in group_owners["privileged_group_owners"]:
                        name = (owner.get("ownerDisplayName") or "N/A")[:22]
                        upn = (owner.get("ownerUPN") or "N/A")[:34]
                        group_name = (owner.get("groupName") or "N/A")[:34]
                        role_assignable = "Yes" if owner.get("isRoleAssignable") else "No"
                        risk = owner.get("riskLevel", "")
                        print(f"{name:<23} {upn:<35} {group_name:<35} {role_assignable:<10} {risk:<7}")
                    print("-" * 110)
                    prompt_export_results(group_owners["privileged_group_owners"], "privileged_group_owners")
                else:
                    print("[!] No privileged group owners found or access denied.")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        elif option == "54":
            print("\n[*] Analyzing Group Membership Privileges...")
            print("    (Finding users/apps that can modify group membership)")
            reset_cancellation()
            try:
                group_privs = get_users_with_group_membership_privileges(access_token)
                
                # Show role-based managers
                if group_privs.get("role_based_group_managers"):
                    print("\n" + "=" * 110)
                    print(f"{'USERS WITH GROUP MANAGEMENT ROLES':^110}")
                    print("=" * 110)
                    print(f"\n{'Display Name':<24} {'Email/UPN':<38} {'Role':<28} {'All Groups?':<12} {'Risk':<7}")
                    print("-" * 110)
                    for user in group_privs["role_based_group_managers"]:
                        name = (user.get("displayName") or "N/A")[:23]
                        email = (user.get("userPrincipalName") or "N/A")[:37]
                        role = (user.get("role") or "N/A")[:27]
                        all_groups = "Yes" if user.get("canManageAllGroups") else "No"
                        risk = user.get("riskLevel", "")
                        print(f"{name:<24} {email:<38} {role:<28} {all_groups:<12} {risk:<7}")
                    print("-" * 110)
                
                # Show apps with group write permissions
                if group_privs.get("apps_with_group_write_all"):
                    print("\n" + "=" * 110)
                    print(f"{'APPS WITH GROUP WRITE PERMISSIONS':^110}")
                    print("=" * 110)
                    print(f"\n{'App Name':<30} {'App ID':<38} {'Permissions':<28} {'Owners':<12}")
                    print("-" * 110)
                    for app in group_privs["apps_with_group_write_all"]:
                        name = (app.get("appDisplayName") or "N/A")[:29]
                        app_id = (app.get("appId") or "N/A")[:37]
                        perms = (app.get("grantedPermissions") or "N/A")[:27]
                        owners = (app.get("owners") or "None")[:11]
                        print(f"{name:<30} {app_id:<38} {perms:<28} {owners:<12}")
                    print("-" * 110)
                
                if not group_privs.get("role_based_group_managers") and not group_privs.get("apps_with_group_write_all"):
                    print("[!] No group membership privileges found or access denied.")
                else:
                    # Combine for export
                    all_group_privs_export = []
                    for item in group_privs.get("role_based_group_managers", []):
                        item["privilegeType"] = "RoleBasedManager"
                        all_group_privs_export.append(item)
                    for item in group_privs.get("apps_with_group_write_all", []):
                        item["privilegeType"] = "AppWithGroupWrite"
                        all_group_privs_export.append(item)
                    prompt_export_results(all_group_privs_export, "group_membership_privileges")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Analysis cancelled by user.")

        # Power Platform Enumeration Options
        elif option == "55":
            print("\n[*] Running Power Apps Enumeration...")
            print("    (Enumerating Power Apps owners and users)")
            print("    Requires Power Platform Admin or Environment Maker permissions")
            reset_cancellation()
            try:
                power_apps = get_power_apps(access_token)
                if power_apps:
                    print_power_apps_report(power_apps)
                    prompt_export_results(power_apps, "power_apps")
                else:
                    print("[!] No Power Apps found or access denied.")
                    print("    Note: Requires Power Platform Admin or specific app permissions")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        elif option == "56":
            print("\n[*] Running Power Automate Flows Enumeration...")
            print("    (Finding flows with sensitive connectors)")
            print("    Requires Power Platform Admin or flow owner permissions")
            reset_cancellation()
            try:
                flows = get_power_automate_flows(access_token)
                if flows:
                    print_power_automate_flows_report(flows)
                    prompt_export_results(flows, "power_automate_flows")
                else:
                    print("[!] No Power Automate flows found or access denied.")
                    print("    Note: Requires Power Platform Admin or flow owner permissions")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Enumeration cancelled by user.")

        # Lateral Movement Analysis Options
        elif option == "57":
            print("\n[*] Running Full Lateral Movement Analysis...")
            print("    (Analyzing all lateral movement vectors)")
            reset_cancellation()
            try:
                lateral_results = get_lateral_movement_opportunities(access_token)
                print_lateral_movement_report(lateral_results)
                # Combine lateral movement data for export
                all_lateral_export = []
                for item in lateral_results.get("transitive_groups", []):
                    item["movementType"] = "TransitiveGroup"
                    all_lateral_export.append(item)
                for item in lateral_results.get("shared_mailboxes", []):
                    item["movementType"] = "SharedMailbox"
                    all_lateral_export.append(item)
                for item in lateral_results.get("calendar_delegations", []):
                    item["movementType"] = "CalendarDelegation"
                    all_lateral_export.append(item)
                prompt_export_results(all_lateral_export, "lateral_movement")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Analysis cancelled by user.")

        elif option == "58":
            print("\n[*] Mapping Transitive Group Memberships...")
            print("    (Identifying group nesting and indirect access)")
            reset_cancellation()
            try:
                trans_results = get_transitive_group_memberships(access_token)
                print_transitive_membership_report(trans_results)
                # Combine for export
                all_trans_export = []
                for item in trans_results.get("nested_groups", []):
                    item["recordType"] = "NestedGroup"
                    all_trans_export.append(item)
                for item in trans_results.get("transitive_members", []):
                    item["recordType"] = "TransitiveMember"
                    all_trans_export.append(item)
                if all_trans_export:
                    prompt_export_results(all_trans_export, "transitive_group_memberships")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Analysis cancelled by user.")

        elif option == "59":
            print("\n[*] Analyzing Shared Mailbox Access...")
            print("    (Finding shared mailboxes and permissions)")
            reset_cancellation()
            try:
                mailbox_results = get_shared_mailbox_access(access_token)
                print_shared_mailbox_report(mailbox_results)
                # Combine for export
                all_mailbox_export = []
                for item in mailbox_results.get("shared_mailboxes", []):
                    item["recordType"] = "SharedMailbox"
                    all_mailbox_export.append(item)
                for item in mailbox_results.get("permissions", []):
                    item["recordType"] = "Permission"
                    all_mailbox_export.append(item)
                if all_mailbox_export:
                    prompt_export_results(all_mailbox_export, "shared_mailbox_access")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Analysis cancelled by user.")

        elif option == "60":
            print("\n[*] Analyzing Calendar/Mailbox Delegations...")
            print("    (Finding delegated permissions)")
            reset_cancellation()
            try:
                delegation_results = get_calendar_mailbox_delegations(access_token)
                print_calendar_delegation_report(delegation_results)
                if delegation_results.get("delegations"):
                    prompt_export_results(delegation_results["delegations"], "calendar_mailbox_delegations")
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Analysis cancelled by user.")

        # BloodHound / AzureHound Export
        elif option == "61":
            print("\n[*] Running BloodHound/AzureHound Export...")
            print("    (Collecting Users, Groups, Devices, Apps, Roles)")
            reset_cancellation()
            try:
                # Use existing all_users if available
                export_to_bloodhound(access_token, users=all_users if all_users else None)
            except KeyboardInterrupt:
                request_cancellation()
                print("\n[!] Export cancelled by user.")

        # HTML Report Generation
        elif option == "62":
            print("\n" + "=" * 70)
            print("INTERACTIVE HTML REPORT GENERATION")
            print("=" * 70)
            print("\nThis will generate a comprehensive HTML report with:")
            print("  - Executive Summary with key findings")
            print("  - Risk scoring and visualizations")
            print("  - Interactive charts (using Chart.js)")
            print("  - Detailed findings tables")
            print("\nWhat data would you like to include?")
            print("1. Run full security assessment and generate report")
            print("2. Use existing collected data (if available)")
            print("0. Cancel")
            
            report_choice = input("\nSelect option (0-2): ").strip()
            
            if report_choice == "0":
                print("[*] Report generation cancelled.")
            elif report_choice in ("1", "2"):
                # Collect findings
                report_findings = {}
                
                if report_choice == "1":
                    # Run full assessment
                    print("\n[*] Running full security assessment...")
                    reset_cancellation()
                    try:
                        # Users
                        if all_users:
                            report_findings["users"] = all_users
                        else:
                            print("\n[1/10] Enumerating users...")
                            results = enumerate_all_methods(access_token)
                            all_users = merge_user_results(results)
                            report_findings["users"] = all_users
                        
                        # MFA Status
                        if not is_cancelled():
                            print("\n[2/10] Checking MFA status...")
                            mfa_results = get_user_mfa_status(access_token)
                            if not mfa_results:
                                mfa_results = get_user_mfa_registration_details(access_token)
                            report_findings["mfa"] = mfa_results or []
                        
                        # Privileged Users
                        if not is_cancelled():
                            print("\n[3/10] Enumerating privileged users...")
                            report_findings["privileged"] = get_privileged_users(access_token) or []
                        
                        # Applications
                        if not is_cancelled():
                            print("\n[4/10] Analyzing applications...")
                            report_findings["apps"] = get_applications_and_service_principals(access_token) or {}
                        
                        # Stale Accounts
                        if not is_cancelled():
                            print("\n[5/10] Finding stale accounts...")
                            report_findings["stale"] = get_stale_accounts(access_token) or []
                        
                        # Guest Users
                        if not is_cancelled():
                            print("\n[6/10] Enumerating guest users...")
                            report_findings["guests"] = get_guest_users(access_token) or []
                        
                        # CA Policies
                        if not is_cancelled():
                            print("\n[7/10] Analyzing Conditional Access...")
                            report_findings["ca_policies"] = get_conditional_access_policies(access_token) or []
                        
                        # Password Policies
                        if not is_cancelled():
                            print("\n[8/10] Checking password policies...")
                            report_findings["password_policy"] = get_user_password_policies(access_token) or []
                        
                        # Devices
                        if not is_cancelled():
                            print("\n[9/10] Enumerating devices...")
                            report_findings["devices"] = get_all_devices(access_token) or []
                        
                        # Non-Compliant Devices
                        if not is_cancelled():
                            print("\n[10/10] Checking device compliance...")
                            report_findings["non_compliant"] = get_non_compliant_devices(access_token) or []
                        
                    except KeyboardInterrupt:
                        request_cancellation()
                        print("\n[!] Assessment interrupted - generating report with collected data...")
                
                elif report_choice == "2":
                    # Use existing data
                    if all_users:
                        report_findings["users"] = all_users
                    print("[*] Using existing collected data...")
                    print("    Note: Only data from previous operations will be included.")
                
                # Get tenant info
                tenant_info = get_tenant_info(access_token)
                
                # Generate report
                if report_findings:
                    print("\nEnter report filename (without extension, default: evilmist_report):")
                    print("Type 'cancel' to go back")
                    report_filename = input("Filename: ").strip()
                    
                    if report_filename.lower() == 'cancel':
                        print("[*] Report generation cancelled.")
                    else:
                        report_filename = report_filename or "evilmist_report"
                        if not report_filename.endswith('.html'):
                            report_filename += '.html'
                        
                        generate_html_report(
                            findings=report_findings,
                            filename=report_filename,
                            tenant_info=tenant_info,
                            title="EvilMist Security Assessment Report"
                        )
                else:
                    print("[!] No data collected. Run some assessments first.")

        elif option == "19":
            if not all_users:
                print("\n[*] No users in memory. Running full enumeration first...")
                results = enumerate_all_methods(access_token)
                all_users = merge_user_results(results)
                
            if all_users:
                print(f"\n[+] {len(all_users)} users ready for export")
                print("\nExport format:")
                print("0. Cancel (go back)")
                print("1. JSON")
                print("2. CSV")
                print("3. Both")
                fmt = input("Select (0-3): ").strip()
                
                if fmt == "0":
                    continue
                
                filename = input("Filename (without extension, or 'cancel' to go back): ").strip()
                if filename.lower() == 'cancel':
                    continue
                filename = filename or "entra_users"
                
                if fmt == "1":
                    export_to_json(all_users, f"{filename}.json")
                elif fmt == "2":
                    export_to_csv(all_users, f"{filename}.csv")
                elif fmt == "3":
                    export_to_json(all_users, f"{filename}.json")
                    export_to_csv(all_users, f"{filename}.csv")
            else:
                print("[!] No users to export.")

        elif option == "98":
            # Configure stealth settings
            configure_stealth_settings()

        elif option == "99":
            # Change authentication method - return to auth selection
            print("\n[*] Returning to authentication selection...")
            return main()  # Restart main function

        elif option == "0":
            print("\nGoodbye!")
            break

        else:
            print("[!] Invalid option.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user (Ctrl+C). Exiting...")
        sys.exit(0)
