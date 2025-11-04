#!/usr/bin/env python3
"""
Google Workspace Reports API Credential Validator
ArmorPoint Integration - validates service account and admin access

USAGE:
  Method 1: Environment variables
    export GOOGLE_SERVICE_ACCOUNT_JSON="/path/to/service-account.json"
    export GOOGLE_DELEGATED_ADMIN="admin@yourdomain.com"
    python validate_google_workspace.py
  
  Method 2: Interactive (script will prompt)
    python validate_google_workspace.py
  
  Method 3: Paste JSON directly when prompted
    python validate_google_workspace.py

VALIDATES:
  1. Service account JSON structure
  2. Delegated admin email (must be admin, NOT service account)
  3. Admin SDK API is enabled
  4. Domain-wide delegation with audit.readonly scope
  5. Can fetch audit logs from key applications
"""

import json
import sys
import os
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime, timedelta

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
    from google.auth.exceptions import GoogleAuthError
except ImportError as e:
    print(f"[ERROR] Required Google libraries not installed: {e}")
    print("Install with: pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client")
    sys.exit(1)


# Required scope for ArmorPoint Integration
REQUIRED_SCOPE = 'https://www.googleapis.com/auth/admin.reports.audit.readonly'

# Applications that can be audited
AUDIT_APPS = [
    'access_transparency', 'admin', 'calendar', 'chat', 'context_aware_access',
    'device', 'drive', 'gcp', 'groups', 'groups_enterprise', 'login',
    'meet', 'rules', 'saml', 'token', 'user_accounts'
]

REQUIRED_SA_FIELDS = [
    'type', 'project_id', 'private_key_id', 'private_key',
    'client_email', 'client_id', 'token_uri'
]


def print_header(text):
    print(f"\n{'=' * 70}")
    print(f" {text}")
    print(f"{'=' * 70}")


def print_result(test_name, passed, message):
    status = "[PASS]" if passed else "[FAIL]"
    print(f"{status} {test_name}")
    print(f"      {message}")
    return passed


def validate_email(email):
    """Check if email format is valid"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_private_key(private_key):
    """Check if private key format is valid"""
    if not private_key or len(private_key.strip()) < 100:
        return False, "Private key is empty or too short"
    
    if not private_key.strip().startswith('-----BEGIN PRIVATE KEY-----'):
        return False, "Private key must start with '-----BEGIN PRIVATE KEY-----'"
    
    if not private_key.strip().endswith('-----END PRIVATE KEY-----'):
        return False, "Private key must end with '-----END PRIVATE KEY-----'"
    
    return True, None


def load_json_from_file(file_path):
    """Load JSON from file"""
    try:
        path = Path(file_path).expanduser().resolve()
        
        if not path.exists():
            print(f"[ERROR] File not found: {path}")
            return None
        
        with path.open('r') as f:
            data = json.load(f)
        
        print(f"[INFO] Loaded service account from: {path}")
        return data
        
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON: {e}")
        return None
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}")
        return None


def load_json_from_env():
    """Load JSON from environment variables"""
    json_path = os.getenv('GOOGLE_SERVICE_ACCOUNT_JSON')
    if json_path:
        return load_json_from_file(json_path)
    
    # Try individual env vars
    project_id = os.getenv('GOOGLE_PROJECT_ID')
    private_key = os.getenv('GOOGLE_PRIVATE_KEY')
    client_email = os.getenv('GOOGLE_CLIENT_EMAIL')
    client_id = os.getenv('GOOGLE_CLIENT_ID')
    
    if all([project_id, private_key, client_email, client_id]):
        return {
            "type": "service_account",
            "project_id": project_id,
            "private_key_id": os.getenv('GOOGLE_PRIVATE_KEY_ID', 'auto-generated'),
            "private_key": private_key,
            "client_email": client_email,
            "client_id": client_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
        }
    
    return None


def prompt_for_json():
    """Interactively get service account JSON"""
    print("\n" + "=" * 70)
    print("SERVICE ACCOUNT JSON INPUT")
    print("=" * 70)
    print("\nChoose input method:")
    print("  1. Provide file path")
    print("  2. Paste JSON content directly")
    
    while True:
        try:
            choice = input("\nSelect (1 or 2): ").strip()
            
            if choice == '1':
                file_path = input("\nService account JSON file path: ").strip()
                if not file_path:
                    print("[ERROR] File path required")
                    continue
                
                data = load_json_from_file(file_path)
                if data:
                    return data
                
                retry = input("\nTry again? (y/n): ").strip().lower()
                if retry != 'y':
                    return None
            
            elif choice == '2':
                print("\nPaste your JSON content below.")
                print("Press Enter, then Ctrl+D (Linux/Mac) or Ctrl+Z (Windows) when done.")
                print("-" * 70)
                
                lines = []
                print("\nPaste here:")
                try:
                    while True:
                        lines.append(input())
                except EOFError:
                    pass
                
                json_content = '\n'.join(lines)
                if not json_content.strip():
                    print("[ERROR] No content provided")
                    continue
                
                try:
                    data = json.loads(json_content)
                    print("[INFO] Successfully parsed JSON")
                    return data
                except json.JSONDecodeError as e:
                    print(f"[ERROR] Invalid JSON: {e}")
                    retry = input("\nTry again? (y/n): ").strip().lower()
                    if retry != 'y':
                        return None
            
            else:
                print("[ERROR] Invalid choice. Enter 1 or 2.")
        
        except KeyboardInterrupt:
            print("\n\nCancelled by user")
            return None


def get_delegated_admin():
    """Get delegated admin email"""
    delegated_admin = os.getenv('GOOGLE_DELEGATED_ADMIN')
    if delegated_admin:
        return delegated_admin
    
    print("\n" + "=" * 70)
    print("DELEGATED ADMINISTRATOR EMAIL")
    print("=" * 70)
    print("\nEnter the Google Workspace administrator email.")
    print("This must be your ADMIN account, NOT the service account email.")
    
    while True:
        try:
            email = input("\nAdministrator email: ").strip()
            
            if not email:
                print("[ERROR] Email required")
                continue
            
            if not validate_email(email):
                print("[ERROR] Invalid email format")
                continue
            
            if email.endswith('.gserviceaccount.com'):
                print("[ERROR] This looks like a service account email.")
                print("         You need to use your Google Workspace admin email instead.")
                continue
            
            return email
        
        except KeyboardInterrupt:
            print("\n\nCancelled by user")
            return None


def validate_credentials(service_account_data, delegated_admin):
    """Run all validation checks"""
    
    print_header("Google Workspace Reports API Validator")
    print(f"Delegated Admin: {delegated_admin}")
    print(f"Service Account: {service_account_data.get('client_email', 'N/A')}")
    print(f"Project ID: {service_account_data.get('project_id', 'N/A')}")
    
    results = []
    
    # STEP 1: Validate service account structure
    print("\n[1/5] Validating service account structure...")
    try:
        missing = [f for f in REQUIRED_SA_FIELDS if f not in service_account_data]
        if missing:
            results.append(print_result(
                "Service Account Structure",
                False,
                f"Missing fields: {', '.join(missing)}"
            ))
            return False
        
        if service_account_data.get('type') != 'service_account':
            results.append(print_result(
                "Service Account Structure",
                False,
                f"Invalid type: {service_account_data.get('type')}"
            ))
            return False
        
        client_email = service_account_data.get('client_email', '')
        if not validate_email(client_email):
            results.append(print_result(
                "Service Account Structure",
                False,
                f"Invalid client_email: {client_email}"
            ))
            return False
        
        is_valid, error = validate_private_key(service_account_data.get('private_key', ''))
        if not is_valid:
            results.append(print_result(
                "Service Account Structure",
                False,
                f"Invalid private key: {error}"
            ))
            return False
        
        results.append(print_result(
            "Service Account Structure",
            True,
            "All required fields present and valid"
        ))
    
    except Exception as e:
        results.append(print_result(
            "Service Account Structure",
            False,
            f"Error: {e}"
        ))
        return False
    
    # STEP 2: Validate delegated admin email
    print("\n[2/5] Validating delegated administrator...")
    try:
        if not validate_email(delegated_admin):
            results.append(print_result(
                "Delegated Admin",
                False,
                f"Invalid email format: {delegated_admin}"
            ))
            return False
        
        service_email = service_account_data.get('client_email', '')
        if delegated_admin == service_email:
            results.append(print_result(
                "Delegated Admin",
                False,
                "Delegated admin MUST be admin account, NOT service account email"
            ))
            print(f"      Service Account: {service_email}")
            print(f"      You provided: {delegated_admin}")
            print(f"      Use your Google Workspace admin email instead")
            return False
        
        results.append(print_result(
            "Delegated Admin",
            True,
            f"Valid administrator email: {delegated_admin}"
        ))
    
    except Exception as e:
        results.append(print_result(
            "Delegated Admin",
            False,
            f"Error: {e}"
        ))
        return False
    
    # STEP 3: Create credentials
    print("\n[3/5] Creating credentials with Reports API scope...")
    try:
        credentials = service_account.Credentials.from_service_account_info(
            service_account_data,
            scopes=[REQUIRED_SCOPE]
        )
        
        if not credentials:
            results.append(print_result(
                "Credentials Creation",
                False,
                "Failed to create credentials object"
            ))
            return False
        
        results.append(print_result(
            "Credentials Creation",
            True,
            f"Credentials created with scope: {REQUIRED_SCOPE}"
        ))
    
    except Exception as e:
        results.append(print_result(
            "Credentials Creation",
            False,
            f"Error: {e}"
        ))
        return False
    
    # STEP 4: Test domain-wide delegation
    print("\n[4/5] Testing domain-wide delegation...")
    try:
        delegated_creds = credentials.with_subject(delegated_admin)
        service = build('admin', 'reports_v1', credentials=delegated_creds)
        
        start_time = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        
        request = service.activities().list(
            userKey='all',
            applicationName='login',
            startTime=start_time,
            maxResults=1
        )
        result = request.execute(num_retries=3)
        
        results.append(print_result(
            "Domain-Wide Delegation",
            True,
            "Successfully authenticated and accessed Reports API"
        ))
        
        activities = result.get('items', [])
        if activities:
            print(f"      Retrieved login audit data from last 7 days")
    
    except HttpError as e:
        error_msg = _parse_http_error(e)
        
        if e.resp.status == 403:
            results.append(print_result(
                "Domain-Wide Delegation",
                False,
                "Not authorized - domain-wide delegation not configured"
            ))
            print("\n      TO FIX:")
            print("      1. Go to admin.google.com")
            print("      2. Security > API Controls > Manage Domain Wide Delegation")
            print("      3. Add new or edit existing:")
            print(f"         Client ID: {service_account_data.get('client_id')}")
            print(f"         Scope: {REQUIRED_SCOPE}")
            print("      4. Click Authorize")
            print("      5. Wait 5-10 minutes for propagation")
            return False
        
        elif e.resp.status == 404:
            results.append(print_result(
                "Domain-Wide Delegation",
                False,
                f"Admin user not found: {delegated_admin}"
            ))
            return False
        
        else:
            results.append(print_result(
                "Domain-Wide Delegation",
                False,
                f"HTTP {e.resp.status}: {error_msg}"
            ))
            return False
    
    except Exception as e:
        results.append(print_result(
            "Domain-Wide Delegation",
            False,
            f"Error: {e}"
        ))
        return False
    
    # STEP 5: Test audit log access for key applications
    print("\n[5/5] Testing audit log access for key applications...")
    try:
        delegated_creds = credentials.with_subject(delegated_admin)
        service = build('admin', 'reports_v1', credentials=delegated_creds)
        
        # Test critical apps
        test_apps = ['login', 'admin', 'drive', 'token', 'user_accounts']
        start_time = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        
        successful = []
        failed = []
        
        for app in test_apps:
            try:
                request = service.activities().list(
                    userKey='all',
                    applicationName=app,
                    startTime=start_time,
                    maxResults=1
                )
                result = request.execute(num_retries=2)
                successful.append(app)
            
            except HttpError as e:
                if e.resp.status == 404:
                    # 404 is OK - just means no data for that app
                    successful.append(app)
                else:
                    failed.append(app)
        
        if len(successful) >= 3:
            results.append(print_result(
                "Audit Log Access",
                True,
                f"Successfully accessed {len(successful)}/{len(test_apps)} audit applications"
            ))
            print(f"      Working: {', '.join(successful)}")
            if failed:
                print(f"      Note: {', '.join(failed)} failed (may have no data)")
        else:
            results.append(print_result(
                "Audit Log Access",
                False,
                f"Only {len(successful)}/{len(test_apps)} applications accessible"
            ))
            return False
    
    except Exception as e:
        results.append(print_result(
            "Audit Log Access",
            False,
            f"Error: {e}"
        ))
        return False
    
    # SUMMARY
    print_header("Validation Summary")
    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"\nTests Passed: {passed}/{total}")
    
    if passed == total:
        print("\n[SUCCESS] All validations passed!")
        print("Your credentials are properly configured for ArmorPoint integration.")
        print("\nConfiguration Summary:")
        print(f"  Required Scope: {REQUIRED_SCOPE}")
        print(f"  API: Admin SDK API (includes Reports API)")
        print(f"  Delegated Admin: {delegated_admin}")
        print(f"  Service Account: {service_account_data.get('client_email')}")
        return True
    else:
        print("\n[FAILED] Some validations failed.")
        print("Review the errors above and fix configuration.")
        return False


def _parse_http_error(error):
    """Extract error message from HttpError"""
    try:
        error_details = json.loads(error.content.decode('utf-8'))
        return error_details.get('error', {}).get('message', str(error))
    except:
        return str(error)


def main():
    print("=" * 70)
    print("Google Workspace Reports API Validator")
    print("ArmorPoint Integration")
    print("=" * 70)
    
    # Load service account JSON
    print("\n[INFO] Loading service account credentials...")
    service_account_data = load_json_from_env()
    
    if not service_account_data:
        print("[INFO] No credentials in environment, using interactive mode")
        service_account_data = prompt_for_json()
    
    if not service_account_data:
        print("\n[ERROR] Failed to load service account credentials")
        return 1
    
    # Get delegated admin email
    delegated_admin = get_delegated_admin()
    if not delegated_admin:
        print("\n[ERROR] Failed to get delegated administrator email")
        return 1
    
    # Validate
    try:
        success = validate_credentials(service_account_data, delegated_admin)
        return 0 if success else 1
    
    except KeyboardInterrupt:
        print("\n\nValidation cancelled by user")
        return 1
    
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
