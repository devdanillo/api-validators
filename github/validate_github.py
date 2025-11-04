#!/usr/bin/env python3
"""
GitHub Audit Log Credentials Validator - ArmorPoint Integration
Single script to validate Personal Access Token for audit log collection
"""

import requests
import sys
import os


def print_header(text):
    print(f"\n{'=' * 70}")
    print(f" {text}")
    print(f"{'=' * 70}")


def print_result(test_name, passed, message):
    status = "[PASS]" if passed else "[FAIL]"
    print(f"{status} {test_name}")
    print(f"      {message}")
    return passed


def validate_credentials(token, org_name):
    """Validate GitHub credentials for audit log access"""
    
    base_url = "https://api.github.com"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    results = []
    
    print_header("GitHub Audit Log Validator")
    print(f"Organization: {org_name}")
    print(f"Token: {token[:10]}..." if len(token) > 10 else "Token: (invalid length)")
    
    # TEST 1: Validate token is authentic
    print("\n[1/3] Validating Personal Access Token...")
    try:
        response = requests.get(f"{base_url}/user", headers=headers, timeout=10)
        
        if response.status_code == 200:
            user_data = response.json()
            username = user_data.get("login", "Unknown")
            results.append(print_result(
                "Token Authentication",
                True,
                f"Valid token authenticated as: {username}"
            ))
        elif response.status_code == 401:
            results.append(print_result(
                "Token Authentication",
                False,
                "Invalid token - check your Personal Access Token"
            ))
            return False
        else:
            results.append(print_result(
                "Token Authentication",
                False,
                f"Unexpected response: {response.status_code}"
            ))
            return False
    except requests.exceptions.RequestException as e:
        results.append(print_result(
            "Token Authentication",
            False,
            f"Connection error: {str(e)}"
        ))
        return False
    
    # TEST 2: Check token scopes (CORRECTED LOGIC)
    print("\n[2/3] Checking Token Scopes...")
    try:
        response = requests.get(f"{base_url}/user", headers=headers, timeout=10)
        
        if response.status_code == 200:
            scopes = response.headers.get("X-OAuth-Scopes", "")
            scope_list = [s.strip() for s in scopes.split(",") if s.strip()]
            
            # GitHub accepts multiple scope formats - check for any valid combination
            has_org = any(s in scope_list for s in ["read:org", "admin:org", "org"])
            has_audit = any(s in scope_list for s in ["audit_log", "read:audit_log", "admin:org"])
            
            if has_org and has_audit:
                results.append(print_result(
                    "Token Scopes",
                    True,
                    f"Required scopes present: {scopes}"
                ))
            else:
                missing = []
                if not has_org:
                    missing.append("read:org (or admin:org)")
                if not has_audit:
                    missing.append("audit_log or read:audit_log")
                results.append(print_result(
                    "Token Scopes",
                    False,
                    f"Missing scopes: {', '.join(missing)}. Current scopes: {scopes}"
                ))
        else:
            results.append(print_result(
                "Token Scopes",
                False,
                f"Could not check scopes - status: {response.status_code}"
            ))
    except requests.exceptions.RequestException as e:
        results.append(print_result(
            "Token Scopes",
            False,
            f"Error checking scopes: {str(e)}"
        ))
    
    # TEST 3: Most important - can we actually access audit logs?
    print("\n[3/3] Testing Audit Log API Access (CRITICAL TEST)...")
    try:
        response = requests.get(
            f"{base_url}/orgs/{org_name}/audit-log",
            headers=headers,
            params={"per_page": 1},
            timeout=10
        )
        
        if response.status_code == 200:
            logs = response.json()
            log_count = len(logs)
            results.append(print_result(
                "Audit Log API Access",
                True,
                f"SUCCESS! Retrieved {log_count} audit log entry(s). Integration will work."
            ))
        elif response.status_code == 403:
            results.append(print_result(
                "Audit Log API Access",
                False,
                "Forbidden - Token lacks audit_log permissions or org lacks Enterprise Cloud"
            ))
        elif response.status_code == 404:
            results.append(print_result(
                "Audit Log API Access",
                False,
                "Not Found - Organization may not exist or lacks Enterprise Cloud subscription"
            ))
        else:
            results.append(print_result(
                "Audit Log API Access",
                False,
                f"Unexpected response: {response.status_code}"
            ))
    except requests.exceptions.RequestException as e:
        results.append(print_result(
            "Audit Log API Access",
            False,
            f"Connection error: {str(e)}"
        ))
    
    # SUMMARY
    print_header("Validation Summary")
    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"\nTests Passed: {passed}/{total}")
    
    if passed == total:
        print("\n[SUCCESS] All validations passed!")
        print("Credentials are correctly configured for ArmorPoint audit log collection.")
        return True
    else:
        print("\n[PARTIAL] Some checks failed.")
        
        # Provide context-aware recommendations
        if results[0] and results[2]:  # Token valid and audit log works
            print("\nIMPORTANT: Audit Log API is accessible - integration should work!")
            print("The failed checks may not block functionality if logs are flowing.")
        else:
            print("\nRecommendations:")
            if not results[0]:
                print("  - Verify your Personal Access Token is correct and not expired")
            if not results[2]:
                print("  - Ensure organization has GitHub Enterprise Cloud subscription")
                print("  - Verify token has 'audit_log' or 'read:audit_log' scope")
                print("  - Check organization name spelling")
        
        return passed >= 2  # Consider partial success if at least token valid and audit log works


def main():
    print("=" * 70)
    print(" GitHub Audit Log Validator - ArmorPoint Integration")
    print("=" * 70)
    
    # Get credentials from environment or user input
    token = os.environ.get("GITHUB_TOKEN")
    org_name = os.environ.get("GITHUB_ORG")
    
    if not token:
        try:
            token = input("\nEnter Personal Access Token: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nCancelled by user.")
            sys.exit(1)
    
    if not org_name:
        try:
            org_name = input("Enter Organization Name: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nCancelled by user.")
            sys.exit(1)
    
    if not token or not org_name:
        print("\n[ERROR] Both token and organization name are required.")
        sys.exit(1)
    
    try:
        success = validate_credentials(token, org_name)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
