#!/usr/bin/env python3
"""
Sophos Central API Credential Validator
Tests Sophos Central SIEM credentials for Elastic integration
"""

import requests
import json
import sys
from typing import Dict, Tuple, Optional
from datetime import datetime, timedelta

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

class SophosValidator:
    """Validator for Sophos Central SIEM API credentials"""
    
    # API Configuration
    AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token"
    WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"
    
    def __init__(self, client_id: str, client_secret: str, tenant_id: str):
        """
        Initialize validator with credentials
        
        Args:
            client_id: Sophos API Client ID
            client_secret: Sophos API Client Secret
            tenant_id: Tenant ID (required)
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.access_token = None
        self.api_host = None  # Will be discovered from whoami
        self.request_url = None  # Full API URL
        self.tenant_info = {}
        
    def print_header(self, text: str):
        """Print formatted section header"""
        print(f"\n{Color.BOLD}{Color.CYAN}{'='*70}{Color.END}")
        print(f"{Color.BOLD}{Color.CYAN}{text}{Color.END}")
        print(f"{Color.BOLD}{Color.CYAN}{'='*70}{Color.END}\n")
    
    def print_success(self, text: str):
        """Print success message"""
        print(f"{Color.GREEN}[PASS] {text}{Color.END}")
    
    def print_error(self, text: str):
        """Print error message"""
        print(f"{Color.RED}[FAIL] {text}{Color.END}")
    
    def print_warning(self, text: str):
        """Print warning message"""
        print(f"{Color.YELLOW}[WARN] {text}{Color.END}")
    
    def print_info(self, text: str):
        """Print info message"""
        print(f"{Color.BLUE}[INFO] {text}{Color.END}")
    
    def validate_input(self) -> Tuple[bool, list]:
        """
        Validate input credentials format
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Validate client_id
        if not self.client_id or len(self.client_id.strip()) == 0:
            errors.append("Client ID is empty")
        elif len(self.client_id) < 20:
            errors.append("Client ID appears too short (usually 30+ characters)")
            
        # Validate client_secret
        if not self.client_secret or len(self.client_secret.strip()) == 0:
            errors.append("Client secret is empty")
        elif len(self.client_secret) < 20:
            errors.append("Client secret appears too short (usually 30+ characters)")
            
        # Validate tenant_id (required)
        if not self.tenant_id or len(self.tenant_id.strip()) == 0:
            errors.append("Tenant ID is required")
        elif len(self.tenant_id) != 36 or self.tenant_id.count('-') != 4:
            errors.append("Tenant ID should be in GUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
            
        return (len(errors) == 0, errors)
    
    def get_access_token(self) -> Tuple[bool, str]:
        """
        Obtain OAuth2 access token
        
        Returns:
            Tuple of (success, message)
        """
        try:
            data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': 'token'
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            self.print_info(f"Requesting OAuth token from Sophos ID service...")
            
            response = requests.post(
                self.AUTH_URL,
                data=data,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data.get('access_token')
                token_type = token_data.get('token_type', 'Bearer')
                expires_in = token_data.get('expires_in', 0)
                
                if not self.access_token:
                    return (False, "No access token in response")
                
                self.print_info(f"Token type: {token_type}, expires in: {expires_in}s")
                return (True, "Successfully obtained OAuth token")
            else:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('error_description', 
                                         error_data.get('message', response.text))
                
                if response.status_code == 400:
                    return (False, f"Invalid credentials: {error_msg}")
                elif response.status_code == 401:
                    return (False, f"Authentication failed: {error_msg}")
                else:
                    return (False, f"Token request failed ({response.status_code}): {error_msg}")
                    
        except requests.exceptions.Timeout:
            return (False, "Request timed out - check network connectivity")
        except requests.exceptions.ConnectionError:
            return (False, "Connection error - check internet connectivity")
        except Exception as e:
            return (False, f"Unexpected error: {str(e)}")
    
    def get_tenant_info(self) -> Tuple[bool, str]:
        """
        Call whoami endpoint to get tenant information and API host
        
        Returns:
            Tuple of (success, message)
        """
        if not self.access_token:
            return (False, "No access token available")
        
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}'
            }
            
            self.print_info("Calling /whoami to discover tenant information...")
            
            response = requests.get(
                self.WHOAMI_URL,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Debug: Print response keys
                self.print_info(f"Response keys: {list(data.keys())}")
                
                # Extract tenant info
                self.tenant_info = data
                
                # Verify tenant ID matches
                discovered_tenant_id = data.get('id')
                if discovered_tenant_id and discovered_tenant_id != self.tenant_id:
                    self.print_warning(f"Tenant ID mismatch: provided={self.tenant_id}, discovered={discovered_tenant_id}")
                
                # Get API host from apiHosts.dataRegion
                api_hosts = data.get('apiHosts', {})
                raw_url = api_hosts.get('dataRegion') or data.get('apiHost') or data.get('dataRegion')
                
                if raw_url:
                    # Parse URL to extract just the hostname
                    from urllib.parse import urlparse
                    
                    # Store the full URL for display
                    self.request_url = raw_url
                    
                    # Extract hostname
                    if raw_url.startswith('http'):
                        parsed = urlparse(raw_url)
                        self.api_host = parsed.netloc
                    else:
                        self.api_host = raw_url
                
                self.print_info(f"Tenant ID: {self.tenant_id}")
                self.print_info(f"ID Type: {data.get('idType')}")
                self.print_info(f"Request URL: {self.request_url}")
                self.print_info(f"API Host: {self.api_host}")
                
                # Check for regional data center info
                if 'region' in data:
                    self.print_info(f"Region: {data.get('region')}")
                
                if not self.api_host:
                    self.print_warning("Could not find API host in whoami response")
                    self.print_info(f"Full response: {json.dumps(data, indent=2)}")
                    return (False, "API host not found in whoami response")
                
                return (True, "Successfully retrieved tenant information")
            else:
                error_msg = response.text
                try:
                    error_data = response.json()
                    error_msg = error_data.get('message', response.text)
                except:
                    pass
                
                if response.status_code == 401:
                    return (False, "Unauthorized - token may be invalid")
                else:
                    return (False, f"Whoami request failed ({response.status_code}): {error_msg}")
                    
        except requests.exceptions.Timeout:
            return (False, "Request timed out")
        except Exception as e:
            return (False, f"Request failed: {str(e)}")
    
    def test_alerts_endpoint(self) -> Tuple[bool, str, int]:
        """
        Test SIEM alerts endpoint
        
        Returns:
            Tuple of (success, message, alert_count)
        """
        if not self.access_token or not self.api_host:
            return (False, "Missing access token or API host", 0)
        
        try:
            # Build URL using discovered API host
            url = f"https://{self.api_host}/siem/v1/alerts"
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'X-Tenant-ID': self.tenant_id
            }
            
            # Request last 24 hours of data (Sophos limit)
            params = {
                'limit': 200  # Minimum required by Sophos API
            }
            
            self.print_info("Testing alerts endpoint...")
            
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                alerts = data.get('items', [])
                has_more = data.get('has_more', False)
                
                alert_count = len(alerts)
                
                if alert_count > 0:
                    return (True, f"Retrieved {alert_count} alert(s)", alert_count)
                else:
                    return (True, "Endpoint accessible (no alerts in last 24h)", 0)
                    
            elif response.status_code == 403:
                return (False, "Access denied - check API permissions (need 'Service Principal Forensics' role)", 0)
            elif response.status_code == 401:
                return (False, "Unauthorized - token may have expired", 0)
            else:
                error_msg = response.text
                try:
                    error_data = response.json()
                    error_msg = error_data.get('message', response.text)
                except:
                    pass
                return (False, f"API error ({response.status_code}): {error_msg}", 0)
                
        except requests.exceptions.Timeout:
            return (False, "Request timed out", 0)
        except Exception as e:
            return (False, f"Request failed: {str(e)}", 0)
    
    def test_events_endpoint(self) -> Tuple[bool, str, int]:
        """
        Test SIEM events endpoint
        
        Returns:
            Tuple of (success, message, event_count)
        """
        if not self.access_token or not self.api_host:
            return (False, "Missing access token or API host", 0)
        
        try:
            # Build URL using discovered API host
            url = f"https://{self.api_host}/siem/v1/events"
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'X-Tenant-ID': self.tenant_id
            }
            
            # Request last 24 hours of data
            params = {
                'limit': 200  # Minimum required by Sophos API
            }
            
            self.print_info("Testing events endpoint...")
            
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                events = data.get('items', [])
                has_more = data.get('has_more', False)
                
                event_count = len(events)
                
                if event_count > 0:
                    return (True, f"Retrieved {event_count} event(s)", event_count)
                else:
                    return (True, "Endpoint accessible (no events in last 24h)", 0)
                    
            elif response.status_code == 403:
                return (False, "Access denied - check API permissions", 0)
            elif response.status_code == 401:
                return (False, "Unauthorized - token may have expired", 0)
            else:
                error_msg = response.text
                try:
                    error_data = response.json()
                    error_msg = error_data.get('message', response.text)
                except:
                    pass
                return (False, f"API error ({response.status_code}): {error_msg}", 0)
                
        except requests.exceptions.Timeout:
            return (False, "Request timed out", 0)
        except Exception as e:
            return (False, f"Request failed: {str(e)}", 0)
    
    def run_validation(self) -> bool:
        """
        Run complete validation workflow
        
        Returns:
            True if all critical tests pass, False otherwise
        """
        all_passed = True
        
        # Header
        self.print_header("Sophos Central SIEM API Credential Validator")
        print(f"Client ID: {self.client_id[:20]}...")
        if self.tenant_id:
            print(f"Tenant ID: {self.tenant_id}")
        print(f"Testing at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Test 1: Input Validation
        self.print_header("Test 1: Credential Format Validation")
        is_valid, errors = self.validate_input()
        if is_valid:
            self.print_success("Credential format is valid")
        else:
            self.print_error("Credential format validation failed:")
            for error in errors:
                print(f"  • {error}")
            all_passed = False
            return all_passed
        
        # Test 2: OAuth Authentication
        self.print_header("Test 2: OAuth2 Authentication")
        success, msg = self.get_access_token()
        if success:
            self.print_success(msg)
        else:
            self.print_error(msg)
            self.print_info("Verify:")
            self.print_info("  • Client ID and Secret are correct")
            self.print_info("  • Credentials created with 'Service Principal Forensics' role")
            all_passed = False
            return all_passed
        
        # Test 3: Tenant Discovery (whoami)
        self.print_header("Test 3: Tenant Information Discovery")
        success, msg = self.get_tenant_info()
        if success:
            self.print_success(msg)
        else:
            self.print_error(msg)
            all_passed = False
            return all_passed
        
        # Test 4: Alerts Endpoint
        self.print_header("Test 4: SIEM Alerts Endpoint")
        success, msg, alert_count = self.test_alerts_endpoint()
        if success:
            self.print_success(f"Alerts endpoint accessible - {msg}")
            if alert_count > 0:
                self.print_info(f"Sample data available: {alert_count} alerts found")
        else:
            self.print_error(f"Alerts endpoint failed: {msg}")
            all_passed = False
        
        # Test 5: Events Endpoint
        self.print_header("Test 5: SIEM Events Endpoint")
        success, msg, event_count = self.test_events_endpoint()
        if success:
            self.print_success(f"Events endpoint accessible - {msg}")
            if event_count > 0:
                self.print_info(f"Sample data available: {event_count} events found")
        else:
            self.print_error(f"Events endpoint failed: {msg}")
            all_passed = False
        
        # Summary
        self.print_header("Validation Summary")
        
        print(f"\n{Color.BOLD}Tenant Information:{Color.END}")
        print(f"  Tenant ID: {self.tenant_id}")
        print(f"  Request URL: {self.request_url}")
        print(f"  API Host: {self.api_host}")
        print(f"  ID Type: {self.tenant_info.get('idType', 'unknown')}")
        
        print(f"\n{Color.BOLD}SIEM API Endpoints:{Color.END}")
        print(f"  Alerts: {'[PASS] Working' if success else '[FAIL] Failed'}")
        print(f"  Events: {'[PASS] Working' if success else '[FAIL] Failed'}")
        
        # Final verdict
        print()
        if all_passed:
            self.print_success("[PASS] All tests PASSED")
            self.print_success("[PASS] Credentials are valid for Elastic Sophos Central integration")
            
            print(f"\n{Color.BOLD}Configuration for Elastic:{Color.END}")
            print(f"  Client ID: {self.client_id}")
            print(f"  Client Secret: [hidden]")
            print(f"  Tenant ID: {self.tenant_id}")
            print(f"  Request URL: {self.request_url}")
            print(f"  Token URL: https://id.sophos.com")
            
            print(f"\n{Color.GREEN}{Color.BOLD}STATUS: READY FOR ELASTIC INTEGRATION{Color.END}\n")
            
            if alert_count == 0 and event_count == 0:
                self.print_info("NOTE: No recent alerts/events found (last 24h)")
                self.print_info("This is normal for new/inactive environments")
                self.print_info("Elastic will still collect data as it's generated")
            
            return True
        else:
            self.print_error("[FAIL] Some tests FAILED")
            self.print_error("[FAIL] Cannot proceed with integration")
            
            print(f"\n{Color.BOLD}Common Issues:{Color.END}")
            print("  • Credentials not created with 'Service Principal Forensics' role")
            print("  • Client ID or Secret incorrect")
            print("  • API permissions not granted")
            print("  • Credentials expired or revoked")
            
            print(f"\n{Color.RED}{Color.BOLD}STATUS: NOT READY - FIX REQUIRED{Color.END}\n")
            return False


def main():
    """Main execution function"""
    
    print(f"{Color.BOLD}{Color.MAGENTA}")
    print("+======================================================================+")
    print("|     Sophos Central SIEM API Credential Validator                    |")
    print("|     For Elastic Sophos Central Integration                          |")
    print("+======================================================================+")
    print(Color.END)
    
    # Get credentials
    print(f"\n{Color.BOLD}Enter Sophos Central credentials to validate:{Color.END}\n")
    
    client_id = input("Client ID: ").strip()
    client_secret = input("Client Secret: ").strip()
    tenant_id = input("Tenant ID: ").strip()
    
    # Run validation
    validator = SophosValidator(client_id, client_secret, tenant_id)
    success = validator.run_validation()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
