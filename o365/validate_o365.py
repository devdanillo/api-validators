#!/usr/bin/env python3
"""
Office 365 Management API Credential Validator
Tests O365 credentials for Elastic integration - works for any tenant type
"""

import requests
import json
import sys
import time
from typing import Dict, List, Tuple, Optional
from datetime import datetime

class Color:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

class O365Validator:
    """Validator for Office 365 Management API credentials"""
    
    # API Configuration
    LOGIN_URL = "https://login.microsoftonline.com"
    MANAGE_URL = "https://manage.office.com"
    API_VERSION = "v1.0"
    
    # Content types for Elastic integration
    CONTENT_TYPES = [
        "Audit.AzureActiveDirectory",
        "Audit.Exchange", 
        "Audit.SharePoint",
        "Audit.General",
        "DLP.All"
    ]
    
    # Minimum required for Elastic to work
    MINIMUM_REQUIRED = ["Audit.General"]  # At least one audit type needed
    
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, tenant_domain: str = None):
        """
        Initialize validator with credentials
        
        Args:
            tenant_id: Azure AD tenant ID (GUID)
            client_id: Application (client) ID
            client_secret: Client secret value
            tenant_domain: Optional tenant domain (e.g., contoso.onmicrosoft.com)
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_domain = tenant_domain
        self.access_token = None
        self.token_expiry = None
        self.working_content_types = []
        self.missing_content_types = []
        
    def print_header(self, text: str):
        """Print formatted section header"""
        print(f"\n{Color.BOLD}{Color.CYAN}{'='*70}{Color.END}")
        print(f"{Color.BOLD}{Color.CYAN}{text}{Color.END}")
        print(f"{Color.BOLD}{Color.CYAN}{'='*70}{Color.END}\n")
    
    def print_success(self, text: str):
        """Print success message"""
        print(f"{Color.GREEN}[+] {text}{Color.END}")
    
    def print_error(self, text: str):
        """Print error message"""
        print(f"{Color.RED}[x] {text}{Color.END}")
    
    def print_warning(self, text: str):
        """Print warning message"""
        print(f"{Color.YELLOW}[!] {text}{Color.END}")
    
    def print_info(self, text: str):
        """Print info message"""
        print(f"{Color.BLUE}[i] {text}{Color.END}")
    
    def validate_input(self) -> Tuple[bool, List[str]]:
        """
        Validate input credentials format
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Validate tenant_id (GUID format)
        if not self.tenant_id or len(self.tenant_id.strip()) == 0:
            errors.append("Tenant ID is empty")
        elif len(self.tenant_id) != 36:
            errors.append("Tenant ID should be 36 characters (GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
        elif self.tenant_id.count('-') != 4:
            errors.append("Tenant ID should be in GUID format with 4 hyphens")
            
        # Validate client_id (should be GUID format)
        if not self.client_id or len(self.client_id.strip()) == 0:
            errors.append("Client ID is empty")
        elif len(self.client_id) != 36:
            errors.append("Client ID should be 36 characters (GUID format)")
        elif self.client_id.count('-') != 4:
            errors.append("Client ID should be in GUID format with 4 hyphens")
            
        # Validate client_secret
        if not self.client_secret or len(self.client_secret.strip()) == 0:
            errors.append("Client secret is empty")
        elif len(self.client_secret) < 10:
            errors.append("Client secret appears too short (usually 30+ characters)")
            
        # Validate tenant_domain if provided
        if self.tenant_domain:
            if not '.' in self.tenant_domain:
                errors.append("Tenant domain should contain a dot (e.g., contoso.onmicrosoft.com)")
            
        return (len(errors) == 0, errors)
    
    def get_access_token(self) -> Tuple[bool, str]:
        """
        Obtain access token using client credentials flow
        
        Returns:
            Tuple of (success, message)
        """
        try:
            token_url = f"{self.LOGIN_URL}/{self.tenant_id}/oauth2/v2.0/token"
            
            # Prepare token request
            data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': 'https://manage.office.com/.default',
                'grant_type': 'client_credentials'
            }
            
            self.print_info(f"Requesting token from tenant: {self.tenant_id}")
            
            response = requests.post(token_url, data=data, timeout=30)
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data.get('access_token')
                expires_in = token_data.get('expires_in', 3600)
                self.token_expiry = time.time() + expires_in
                
                # Parse token to show roles/scopes
                import base64
                try:
                    parts = self.access_token.split('.')
                    if len(parts) == 3:
                        payload = parts[1]
                        payload += '=' * (4 - len(payload) % 4)
                        decoded = base64.b64decode(payload)
                        token_info = json.loads(decoded)
                        
                        roles = token_info.get('roles', [])
                        if roles:
                            self.print_info(f"Granted permissions: {', '.join(roles)}")
                        else:
                            self.print_warning("No roles found in token - check API permissions")
                        
                except Exception as e:
                    self.print_warning(f"Could not parse token: {str(e)}")
                
                return (True, "Successfully obtained access token")
            else:
                error_data = response.json() if response.content else {}
                error_code = error_data.get('error', 'unknown')
                error_msg = error_data.get('error_description', response.text)
                
                # Provide helpful error messages
                if 'AADSTS700016' in error_msg:
                    return (False, f"Application not found in tenant. Verify:\n  1. Tenant ID is correct\n  2. App is registered in this tenant\n  3. For multi-tenant apps, admin consent has been granted")
                elif 'AADSTS7000215' in error_msg:
                    return (False, "Invalid client secret. Generate a new secret in Azure Portal.")
                elif 'AADSTS50034' in error_msg:
                    return (False, "Tenant not found. Verify Tenant ID is correct.")
                else:
                    return (False, f"Authentication failed ({error_code}): {error_msg}")
                
        except requests.exceptions.Timeout:
            return (False, "Request timed out - check network connectivity")
        except requests.exceptions.ConnectionError:
            return (False, "Connection error - check internet connectivity")
        except Exception as e:
            return (False, f"Unexpected error: {str(e)}")
    
    def _api_request(self, endpoint: str, method: str = "GET", data: dict = None) -> Tuple[bool, any, str]:
        """
        Make authenticated API request
        
        Args:
            endpoint: API endpoint path
            method: HTTP method (GET, POST, etc)
            data: Optional request body data
            
        Returns:
            Tuple of (success, response_data, message)
        """
        if not self.access_token:
            return (False, None, "No access token available")
        
        url = f"{self.MANAGE_URL}/api/{self.API_VERSION}/{self.tenant_id}{endpoint}"
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=30)
            elif method == "POST":
                response = requests.post(url, headers=headers, json=data, timeout=30)
            else:
                return (False, None, f"Unsupported HTTP method: {method}")
            
            if response.status_code in [200, 201]:
                try:
                    return (True, response.json(), f"Success")
                except json.JSONDecodeError:
                    return (True, None, f"Success (no JSON response)")
            elif response.status_code == 204:
                return (True, None, "Success")
            else:
                error_msg = response.text
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', {}).get('message', response.text)
                except:
                    pass
                return (False, None, f"API error ({response.status_code}): {error_msg}")
                
        except requests.exceptions.Timeout:
            return (False, None, "Request timed out")
        except Exception as e:
            return (False, None, f"Request failed: {str(e)}")
    
    def test_list_subscriptions(self) -> Tuple[bool, str, Optional[List[str]]]:
        """
        Test listing current subscriptions
        
        Returns:
            Tuple of (success, message, list_of_active_content_types)
        """
        success, data, msg = self._api_request("/activity/feed/subscriptions/list")
        
        if success:
            if data:
                active_types = [sub.get('contentType') for sub in data if sub.get('status') == 'enabled']
                return (True, f"Found {len(data)} subscription(s)", active_types)
            else:
                return (True, "No existing subscriptions", [])
        else:
            return (False, msg, None)
    
    def test_start_subscription(self, content_type: str) -> Tuple[bool, str]:
        """
        Test starting a subscription for a content type
        
        Args:
            content_type: Content type to subscribe to
            
        Returns:
            Tuple of (success, message)
        """
        endpoint = f"/activity/feed/subscriptions/start?contentType={content_type}"
        success, data, msg = self._api_request(endpoint, method="POST")
        
        if success:
            return (True, "Available")
        elif "already exists" in msg.lower() or "already enabled" in msg.lower():
            # Subscription already exists = GOOD! It's working!
            return (True, "Available (already subscribed)")
        elif "403" in msg or "AF20024" in msg:
            # AF20024 = content type not enabled for tenant
            return (False, "Not available in tenant")
        else:
            return (False, f"Error: {msg}")
    
    def test_list_content(self, content_type: str) -> Tuple[bool, str, int]:
        """
        Test listing available content for a content type
        
        Args:
            content_type: Content type to query
            
        Returns:
            Tuple of (success, message, content_blob_count)
        """
        endpoint = f"/activity/feed/subscriptions/content?contentType={content_type}"
        success, data, msg = self._api_request(endpoint)
        
        if success:
            blob_count = len(data) if data else 0
            if blob_count > 0:
                return (True, f"Has {blob_count} content blob(s)", blob_count)
            else:
                return (True, "No content yet (normal for new subscriptions)", 0)
        else:
            return (False, msg, 0)
    
    def run_validation(self) -> bool:
        """
        Run complete validation workflow
        
        Returns:
            True if minimum requirements met, False otherwise
        """
        all_critical_passed = True
        
        # Header
        self.print_header("Office 365 Management API Credential Validator")
        print(f"Tenant ID: {self.tenant_id}")
        if self.tenant_domain:
            print(f"Tenant Domain: {self.tenant_domain}")
        print(f"Client ID: {self.client_id}")
        print(f"Testing at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Test 1: Input Validation
        self.print_header("Test 1: Credential Format Validation")
        is_valid, errors = self.validate_input()
        if is_valid:
            self.print_success("Credential format is valid")
        else:
            self.print_error("Credential format validation failed:")
            for error in errors:
                print(f"  - {error}")
            all_critical_passed = False
            return all_critical_passed
        
        # Test 2: Authentication
        self.print_header("Test 2: Authentication & Token Retrieval")
        success, msg = self.get_access_token()
        if success:
            self.print_success(msg)
        else:
            self.print_error(msg)
            all_critical_passed = False
            return all_critical_passed
        
        # Test 3: List Subscriptions
        self.print_header("Test 3: API Connectivity Test")
        success, msg, active_types = self.test_list_subscriptions()
        if success:
            self.print_success(f"API connectivity confirmed - {msg}")
            if active_types:
                self.print_info(f"Already subscribed to: {', '.join(active_types)}")
        else:
            self.print_error(f"API connectivity failed: {msg}")
            all_critical_passed = False
            return all_critical_passed
        
        # Test 4: Test Each Content Type
        self.print_header("Test 4: Content Type Availability")
        print("Testing which Office 365 workloads are accessible...\n")
        
        content_results = {}
        
        for content_type in self.CONTENT_TYPES:
            # Check if already subscribed (from Test 3)
            if active_types and content_type in active_types:
                content_results[content_type] = True
                workload = content_type.replace("Audit.", "").replace("DLP.", "")
                self.print_success(f"{workload:25} Available (already subscribed)")
                self.working_content_types.append(content_type)
            else:
                # Try to start subscription
                success, msg = self.test_start_subscription(content_type)
                content_results[content_type] = success
                
                # Format output with workload name
                workload = content_type.replace("Audit.", "").replace("DLP.", "")
                
                if success:
                    self.print_success(f"{workload:25} {msg}")
                    self.working_content_types.append(content_type)
                else:
                    self.print_warning(f"{workload:25} {msg}")
                    self.missing_content_types.append(content_type)
        
        # Test 5: Check for Content (optional, just informational)
        self.print_header("Test 5: Content Availability Check")
        print("Checking if audit logs are available (informational only)...\n")
        
        has_any_content = False
        for content_type in self.working_content_types:
            success, msg, count = self.test_list_content(content_type)
            workload = content_type.replace("Audit.", "").replace("DLP.", "")
            
            if success and count > 0:
                self.print_info(f"{workload:25} {msg}")
                has_any_content = True
            elif success:
                self.print_info(f"{workload:25} {msg}")
        
        if not has_any_content:
            self.print_info("\nNo content blobs available yet - this is NORMAL for:")
            print("  - Newly created subscriptions (can take up to 12 hours)")
            print("  - Tenants with low activity")
            print("  - Content types just enabled")
        
        # Summary
        self.print_header("Validation Summary")
        
        # Check if minimum requirements met
        has_minimum = any(ct in self.working_content_types for ct in self.MINIMUM_REQUIRED)
        has_any_working = len(self.working_content_types) > 0
        
        print(f"\n{Color.BOLD}Working Content Types ({len(self.working_content_types)}):{Color.END}")
        if self.working_content_types:
            for ct in self.working_content_types:
                workload = ct.replace("Audit.", "").replace("DLP.", "")
                print(f"  {Color.GREEN}[+]{Color.END} {workload}")
        else:
            print(f"  {Color.RED}None{Color.END}")
        
        print(f"\n{Color.BOLD}Unavailable Content Types ({len(self.missing_content_types)}):{Color.END}")
        if self.missing_content_types:
            for ct in self.missing_content_types:
                workload = ct.replace("Audit.", "").replace("DLP.", "")
                print(f"  {Color.YELLOW}[!]{Color.END} {workload} (not enabled/licensed in tenant)")
        else:
            print(f"  {Color.GREEN}All content types available!{Color.END}")
        
        # Final verdict
        print()
        if has_any_working:
            self.print_success("[+] Credentials are VALID")
            self.print_success(f"[+] Integration can access {len(self.working_content_types)} workload(s)")
            
            if self.missing_content_types:
                print()
                self.print_info("IMPORTANT NOTES:")
                for ct in self.missing_content_types:
                    workload = ct.replace("Audit.", "").replace("DLP.", "")
                    if workload == "SharePoint":
                        print(f"  - {workload}: This is OK if client doesn't use SharePoint")
                    elif workload == "All":
                        print(f"  - DLP: This is OK if client doesn't have DLP licensing")
                    else:
                        print(f"  - {workload}: Verify this workload is licensed/enabled")
            
            print(f"\n{Color.GREEN}{Color.BOLD}STATUS: READY FOR ELASTIC INTEGRATION{Color.END}\n")
            return True
        else:
            self.print_error("[x] NO CONTENT TYPES AVAILABLE")
            self.print_error("[x] Cannot proceed with integration")
            print("\nPossible causes:")
            print("  - API permissions not granted (need ActivityFeed.Read)")
            print("  - Admin consent not granted for application")
            print("  - Audit logging not enabled in tenant")
            print(f"\n{Color.RED}{Color.BOLD}STATUS: NOT READY - FIX REQUIRED{Color.END}\n")
            return False


def main():
    """Main execution function"""
    
    print(f"{Color.BOLD}{Color.MAGENTA}")
    print("+======================================================================+")
    print("|     Office 365 Management API Credential Validator                  |")
    print("|     For Elastic O365 Integration                                    |")
    print("+======================================================================+")
    print(Color.END)
    
    # Get credentials
    print(f"\n{Color.BOLD}Enter Office 365 credentials to validate:{Color.END}\n")
    
    tenant_id = input("Tenant ID (GUID): ").strip()
    client_id = input("Client ID (Application ID): ").strip()
    client_secret = input("Client Secret: ").strip()
    
    tenant_domain_input = input("Tenant Domain (optional, press Enter to skip): ").strip()
    tenant_domain = tenant_domain_input if tenant_domain_input else None
    
    # Run validation
    validator = O365Validator(tenant_id, client_id, client_secret, tenant_domain)
    success = validator.run_validation()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
