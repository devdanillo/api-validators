#!/usr/bin/env python3
"""
Microsoft Defender API Credential Validator (Elastic Integration)
Validates Azure AD app registration credentials for Elastic M365 Defender Integration

SECURE CREDENTIAL HANDLING:
  Method 1 (Recommended): Environment variables
    export AZURE_CLIENT_ID="your-client-id"
    export AZURE_CLIENT_SECRET="your-client-secret"
    export AZURE_TENANT_ID="your-tenant-id"
  
  Method 2: Interactive prompt (will ask for credentials)
    Just run the script and it will prompt you

Required Permissions (for Elastic M365 Defender Integration):
  - Microsoft Graph: SecurityIncident.Read.All (Application)
  - Microsoft Graph: SecurityIncident.ReadWrite.All (Delegated)
  - Microsoft Graph: User.Read (Delegated)

This integration uses Microsoft Graph Security v1.0 REST API to collect alerts and incidents.
"""

import sys
import json
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime

try:
    import requests
except ImportError:
    print("ERROR: requests library not installed")
    print("Install with: pip install requests")
    sys.exit(1)

# ============================================================================
# CONFIGURATION
# ============================================================================

REQUEST_TIMEOUT = 30
VERIFY_SSL = True

# ============================================================================
# REQUIRED PERMISSIONS (Based on Elastic M365 Defender Integration)
# ============================================================================

REQUIRED_PERMISSIONS = {
    'Microsoft Graph': {
        'SecurityIncident.Read.All': 'Application',
        'SecurityIncident.ReadWrite.All': 'Delegated',
        'User.Read': 'Delegated',
    }
}

# API endpoints to test (Graph Security API)
API_ENDPOINTS = {
    'graph_security_alerts': 'https://graph.microsoft.com/v1.0/security/alerts_v2',
    'graph_security_incidents': 'https://graph.microsoft.com/v1.0/security/incidents',
}

# ============================================================================
# CREDENTIAL LOADING FUNCTIONS
# ============================================================================

def load_credentials_from_env() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Load credentials from environment variables"""
    import os
    
    client_id = os.getenv('AZURE_CLIENT_ID')
    client_secret = os.getenv('AZURE_CLIENT_SECRET')
    tenant_id = os.getenv('AZURE_TENANT_ID')
    
    if all([client_id, client_secret, tenant_id]):
        print("Loaded credentials from environment variables")
        return client_id, client_secret, tenant_id
    
    return None, None, None

def prompt_for_credentials() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Interactively prompt user for credentials"""
    print("\n" + "=" * 70)
    print("CREDENTIAL CONFIGURATION")
    print("=" * 70)
    print("\nNo credentials found in environment variables.")
    print("Please provide your Azure AD app registration credentials.\n")
    
    try:
        client_id = input("Client ID (Application ID): ").strip()
        if not client_id:
            print("ERROR: Client ID cannot be empty")
            return None, None, None
        
        client_secret = input("Client Secret (Secret Value): ").strip()
        if not client_secret:
            print("ERROR: Client Secret cannot be empty")
            return None, None, None
        
        tenant_id = input("Tenant ID (Directory ID): ").strip()
        if not tenant_id:
            print("ERROR: Tenant ID cannot be empty")
            return None, None, None
        
        return client_id, client_secret, tenant_id
    
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        return None, None, None

def load_credentials() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Load credentials using environment or prompt"""
    client_id, client_secret, tenant_id = load_credentials_from_env()
    
    if not all([client_id, client_secret, tenant_id]):
        print("Checking for credentials in environment...")
        client_id, client_secret, tenant_id = prompt_for_credentials()
    
    return client_id, client_secret, tenant_id

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def mask_sensitive_data(data: str, show_chars: int = 4) -> str:
    """Mask sensitive data, showing only first/last few characters"""
    if not data or len(data) <= show_chars * 2:
        return '*' * 8
    return f"{data[:show_chars]}...{data[-show_chars:]}"

def validate_guid_format(guid: str, field_name: str) -> Tuple[bool, Optional[str]]:
    """Validate GUID/UUID format"""
    guid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    
    if not guid:
        return False, f"{field_name} is empty"
    
    if not re.match(guid_pattern, guid):
        return False, f"{field_name} is not a valid GUID format"
    
    return True, None

def validate_secret_format(secret: str) -> Tuple[bool, Optional[str]]:
    """Validate client secret format"""
    if not secret:
        return False, "Client secret is empty"
    
    if len(secret) < 10:
        return False, "Client secret appears too short (should be 30+ characters)"
    
    # Check if it looks like a Secret ID instead of Secret Value
    if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}', secret):
        return False, "This looks like a Secret ID, not a Secret Value. Please use the Secret Value (usually contains ~ or special characters)"
    
    return True, None

# ============================================================================
# MAIN VALIDATOR CLASS
# ============================================================================

class DefenderAPIValidator:
    """Validates Microsoft Defender API credentials for Elastic M365 Defender Integration"""
    
    def __init__(self, client_id: str, client_secret: str, tenant_id: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.graph_token = None
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.validation_steps_passed = 0
        self.total_validation_steps = 4
    
    def _log_step(self, step_num: int, message: str):
        """Log a validation step"""
        print(f"\n[{step_num}/{self.total_validation_steps}] {message}")
    
    def _log_success(self, message: str):
        """Log a success message"""
        print(f"[PASS] {message}")
        self.validation_steps_passed += 1
    
    def _log_error(self, message: str):
        """Log and store an error message"""
        print(f"[FAIL] {message}")
        self.errors.append(message)
    
    def _log_warning(self, message: str):
        """Log and store a warning message"""
        print(f"[WARN] {message}")
        self.warnings.append(message)
    
    def validate_credential_format(self) -> bool:
        """Validate the format of provided credentials"""
        self._log_step(1, "Validating credential format...")
        
        all_valid = True
        
        # Validate Client ID (GUID format)
        is_valid, error = validate_guid_format(self.client_id, "Client ID")
        if not is_valid:
            self._log_error(error)
            all_valid = False
        else:
            print(f"  Client ID: {mask_sensitive_data(self.client_id)}")
        
        # Validate Tenant ID (GUID format)
        is_valid, error = validate_guid_format(self.tenant_id, "Tenant ID")
        if not is_valid:
            self._log_error(error)
            all_valid = False
        else:
            print(f"  Tenant ID: {mask_sensitive_data(self.tenant_id)}")
        
        # Validate Client Secret
        is_valid, error = validate_secret_format(self.client_secret)
        if not is_valid:
            self._log_error(error)
            all_valid = False
        else:
            has_special = any(c in self.client_secret for c in '~!@#$%^&*')
            print(f"  Client Secret: {mask_sensitive_data(self.client_secret)} (length: {len(self.client_secret)})")
            if has_special:
                print(f"  Secret contains special characters (expected)")
            else:
                self._log_warning("Secret doesn't contain typical special characters (~, !, etc.)")
        
        if all_valid:
            self._log_success("Credential format is valid")
            return True
        
        return False
    
    def authenticate_and_get_token(self) -> bool:
        """Authenticate with Azure AD and retrieve Microsoft Graph token"""
        self._log_step(2, "Authenticating with Azure AD (Microsoft Graph scope)...")
        
        token_url = f'https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token'
        print(f"  Token endpoint: {token_url}")
        
        data = {
            'client_id': self.client_id,
            'scope': 'https://graph.microsoft.com/.default',
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }
        
        try:
            response = requests.post(token_url, data=data, timeout=REQUEST_TIMEOUT, verify=VERIFY_SSL)
            
            if response.status_code == 200:
                token_data = response.json()
                self.graph_token = token_data.get('access_token')
                
                if self.graph_token:
                    self._log_success("Authentication successful")
                    print(f"  Token type: {token_data.get('token_type', 'N/A')}")
                    print(f"  Expires in: {token_data.get('expires_in', 'N/A')} seconds")
                    print(f"  Scope: Microsoft Graph API")
                    return True
                else:
                    self._log_error("No access token in response")
                    return False
            
            elif response.status_code == 400:
                error_data = response.json()
                error_code = error_data.get('error', 'unknown')
                error_desc = error_data.get('error_description', 'No description')
                
                self._log_error(f"Authentication failed: {error_code}")
                print(f"  Description: {error_desc}")
                
                if 'AADSTS7000215' in error_desc or 'invalid' in error_code.lower():
                    print("\nLikely cause: Invalid CLIENT_SECRET")
                    print("  - Verify the secret hasn't expired")
                    print("  - Ensure you copied the Secret VALUE (not Secret ID)")
                    print("  - Check for extra spaces or characters")
                elif 'AADSTS700016' in error_desc:
                    print("\nLikely cause: Invalid CLIENT_ID or TENANT_ID")
                    print("  - Verify the Application (client) ID")
                    print("  - Verify the Directory (tenant) ID")
                
                return False
            
            elif response.status_code == 401:
                self._log_error(f"Unauthorized: {response.text}")
                print("\nCheck your TENANT_ID is correct")
                return False
            
            else:
                self._log_error(f"Authentication failed (HTTP {response.status_code})")
                print(f"  Response: {response.text}")
                return False
        
        except requests.exceptions.Timeout:
            self._log_error("Request timed out")
            print("  Check your network connection")
            return False
        except requests.exceptions.ConnectionError:
            self._log_error("Connection failed")
            print("  Check network connectivity and firewall settings")
            return False
        except Exception as e:
            self._log_error(f"Unexpected error: {type(e).__name__}: {str(e)}")
            return False
    
    def test_graph_security_alerts(self) -> bool:
        """Test access to Microsoft Graph Security Alerts API"""
        self._log_step(3, "Testing Microsoft Graph Security Alerts API...")
        
        if not self.graph_token:
            self._log_error("No Graph API token available")
            return False
        
        headers = {'Authorization': f'Bearer {self.graph_token}'}
        
        try:
            # Test alerts endpoint with top 5 results
            response = requests.get(
                API_ENDPOINTS['graph_security_alerts'] + '?$top=5',
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=VERIFY_SSL
            )
            
            if response.status_code == 200:
                data = response.json()
                alert_count = len(data.get('value', []))
                self._log_success(f"Graph Security Alerts API accessible ({alert_count} alerts retrieved)")
                
                if alert_count > 0:
                    first_alert = data['value'][0]
                    print(f"  Sample alert: {first_alert.get('title', 'N/A')}")
                    print(f"  Severity: {first_alert.get('severity', 'N/A')}")
                else:
                    print("  No alerts currently present (this is normal)")
                
                return True
            
            elif response.status_code == 403:
                self._log_error("Access Forbidden - Missing required Graph permissions")
                print("\nRequired Microsoft Graph Permission:")
                print("  - SecurityIncident.Read.All (Application)")
                print("\nTo fix:")
                print("  1. Azure Portal > App Registrations > Your App")
                print("  2. API permissions > Add permission")
                print("  3. Microsoft Graph > Application permissions")
                print("  4. Select SecurityIncident.Read.All")
                print("  5. Grant admin consent")
                return False
            
            elif response.status_code == 401:
                self._log_error("Unauthorized - Token may be invalid")
                return False
            
            else:
                self._log_error(f"API Error (HTTP {response.status_code})")
                print(f"  Response: {response.text[:200]}")
                return False
        
        except Exception as e:
            self._log_error(f"Error testing Graph Security Alerts: {type(e).__name__}: {str(e)}")
            return False
    
    def test_graph_security_incidents(self) -> bool:
        """Test access to Microsoft Graph Security Incidents API"""
        self._log_step(4, "Testing Microsoft Graph Security Incidents API...")
        
        if not self.graph_token:
            self._log_error("No Graph API token available")
            return False
        
        headers = {'Authorization': f'Bearer {self.graph_token}'}
        
        try:
            # Test incidents endpoint with top 5 results
            response = requests.get(
                API_ENDPOINTS['graph_security_incidents'] + '?$top=5',
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=VERIFY_SSL
            )
            
            if response.status_code == 200:
                data = response.json()
                incident_count = len(data.get('value', []))
                self._log_success(f"Graph Security Incidents API accessible ({incident_count} incidents retrieved)")
                
                if incident_count > 0:
                    first_incident = data['value'][0]
                    print(f"  Sample incident: {first_incident.get('displayName', 'N/A')}")
                    print(f"  Status: {first_incident.get('status', 'N/A')}")
                    print(f"  Severity: {first_incident.get('severity', 'N/A')}")
                else:
                    print("  No incidents currently present (this is normal)")
                
                return True
            
            elif response.status_code == 403:
                self._log_error("Access Forbidden - Missing required Graph permissions")
                print("\nRequired Microsoft Graph Permissions:")
                print("  - SecurityIncident.Read.All (Application)")
                print("  - SecurityIncident.ReadWrite.All (Delegated)")
                print("  - User.Read (Delegated)")
                print("\nTo fix:")
                print("  1. Azure Portal > App Registrations > Your App")
                print("  2. API permissions > Add permission")
                print("  3. Microsoft Graph > Select both Application and Delegated permissions")
                print("  4. Add all three permissions listed above")
                print("  5. Grant admin consent")
                return False
            
            elif response.status_code == 401:
                self._log_error("Unauthorized - Token may be invalid")
                return False
            
            else:
                self._log_error(f"API Error (HTTP {response.status_code})")
                print(f"  Response: {response.text[:200]}")
                return False
        
        except Exception as e:
            self._log_error(f"Error testing Graph Security Incidents: {type(e).__name__}: {str(e)}")
            return False
    
    def run_all_validations(self) -> bool:
        """Execute all validation steps"""
        print("=" * 70)
        print("Microsoft Defender API Validator")
        print("Elastic M365 Defender Integration - Credential & Permission Check")
        print("=" * 70)
        
        all_passed = True
        
        # Run validations in sequence
        if not self.validate_credential_format():
            all_passed = False
        elif not self.authenticate_and_get_token():
            all_passed = False
        else:
            # Test both Graph Security APIs
            if not self.test_graph_security_alerts():
                all_passed = False
            
            if not self.test_graph_security_incidents():
                all_passed = False
        
        self._print_summary(all_passed)
        
        return all_passed
    
    def _print_summary(self, success: bool):
        """Print validation summary"""
        print("\n" + "=" * 70)
        print("VALIDATION SUMMARY")
        print("=" * 70)
        
        print(f"\nSteps passed: {self.validation_steps_passed}/{self.total_validation_steps}")
        
        if self.warnings:
            print(f"\n[WARN] WARNINGS ({len(self.warnings)}):")
            for i, warning in enumerate(self.warnings, 1):
                print(f"  {i}. {warning}")
        
        if self.errors:
            print(f"\n[FAIL] ERRORS ({len(self.errors)}):")
            for i, error in enumerate(self.errors, 1):
                print(f"  {i}. {error}")
            print("\n[FAIL] VALIDATION FAILED - Please fix the errors above")
            
            print("\nREQUIRED PERMISSIONS (Microsoft Graph):")
            print("  - SecurityIncident.Read.All (Application)")
            print("  - SecurityIncident.ReadWrite.All (Delegated)")
            print("  - User.Read (Delegated)")
            
            print("\nQUICK FIX CHECKLIST:")
            print("  1. Verify Client ID, Client Secret, and Tenant ID are correct")
            print("  2. Ensure you used Secret VALUE (not Secret ID)")
            print("  3. Add Microsoft Graph permissions in Azure Portal")
            print("  4. Click 'Grant admin consent' for all permissions")
            print("  5. Wait 5-10 minutes for permissions to propagate")
        else:
            print("\n[PASS] SUCCESS - All required validations passed!")
            print("Your Microsoft Defender API credentials are properly configured")
            print("for Elastic M365 Defender Integration.")
            print("\nThis integration uses Microsoft Graph Security v1.0 REST API")
            print("to collect alerts and incidents from Microsoft Defender XDR.")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main() -> int:
    """Main execution function"""
    
    print("=" * 70)
    print("Microsoft Defender API Validator")
    print("Elastic M365 Defender Integration")
    print("=" * 70)
    print("\nThis script validates credentials for Elastic's M365 Defender integration.")
    print("It tests Microsoft Graph Security API permissions only.\n")
    print("Credential loading methods:")
    print("1. Environment variables: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID")
    print("2. Interactive prompt (safest - no credentials in shell history)")
    print("=" * 70)
    
    # Load credentials
    client_id, client_secret, tenant_id = load_credentials()
    
    if not all([client_id, client_secret, tenant_id]):
        print("\n[FAIL] Failed to load credentials. Exiting.")
        return 1
    
    # Display configuration (masked)
    print("\n" + "=" * 70)
    print("CONFIGURATION LOADED")
    print("=" * 70)
    print(f"Client ID: {mask_sensitive_data(client_id)}")
    print(f"Tenant ID: {mask_sensitive_data(tenant_id)}")
    print(f"Client Secret: {mask_sensitive_data(client_secret)} (length: {len(client_secret)})")
    print("=" * 70)
    
    # Run validation
    try:
        validator = DefenderAPIValidator(client_id, client_secret, tenant_id)
        success = validator.run_all_validations()
        return 0 if success else 1
    
    except KeyboardInterrupt:
        print("\n\n[WARN] Validation interrupted by user")
        return 130
    
    except Exception as e:
        print(f"\n\n[FAIL] Unexpected error during validation: {type(e).__name__}: {str(e)}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
