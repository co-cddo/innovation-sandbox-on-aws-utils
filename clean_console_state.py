#!/usr/bin/env python3
"""
Clean AWS Console state from Innovation Sandbox pool accounts.

When ISB recycles sandbox accounts using aws-nuke, the AWS Management Console
state (recently visited services, favorites, dashboard, theme, locale) is not
cleaned up. This is because console state is stored by the Console Control
Service (CCS), an undocumented internal AWS service that stores per-principal
user preference data outside the account's resource plane.

This script:
  1. Discovers sandbox accounts from the AWS Organizations OU structure
  2. Gets SSO role credentials for each ISB permission set on each account
  3. Calls the CCS APIs to reset console state for that principal

Uses the NDX/orgManagement profile for Organizations API.
Uses cached SSO access token for SSO role credential acquisition.

Note: CCS state is per-caller (keyed on full assumed-role ARN including session
name). This script cleans state for the SSO principal running it. Each user who
has accessed the console on these accounts would need to run it separately, or
the script needs to be run with credentials for each user's SSO session.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

import boto3

try:
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials
except ImportError:
    print("❌ botocore is required. Install with: pip install botocore", file=sys.stderr)
    sys.exit(1)

import urllib.request
import urllib.error

# ── Configuration ────────────────────────────────────────────────────────────

SSO_REGION = "us-west-2"
SSO_START_URL = "https://d-9267e1e371.awsapps.com/start"
ORG_PROFILE = "NDX/orgManagement"

# ISB account pool OU structure (children of ndx_InnovationSandboxAccountPool)
TARGET_OUS = {
    "Available":  "ou-2laj-oihxgbtr",
    "CleanUp":    "ou-2laj-x3o8lbk8",
    "Quarantine": "ou-2laj-mmagoake",
}

# ISB SSO permission sets provisioned to sandbox accounts
ISB_ROLE_NAMES = [
    "ndx_IsbUsersPS",
    "ndx_IsbAdminsPS",
    "ndx_IsbManagersPS",
]

# Console settings to delete (all known CCS setting names)
CCS_SETTINGS_TO_DELETE = [
    "recentsConsole",
    "recentsConsoleOptOutState",
    "favoritesConsole",
    "favoriteBarDisplay",
    "favoritesBarIconSize",
    "defaultRegion",
    "locale",
    "colorTheme",
]

# Subset to check when reading current state
CCS_SETTINGS_TO_CHECK = [
    "recentsConsole",
    "favoritesConsole",
    "defaultRegion",
    "locale",
    "colorTheme",
]

DASHBOARD_ID = "console-home-unified"


# ── SSO Authentication ───────────────────────────────────────────────────────

def check_sso_session(profile_name):
    """Check if SSO session is valid for the given profile."""
    try:
        session = boto3.Session(profile_name=profile_name)
        sts = session.client("sts")
        sts.get_caller_identity()
        return True
    except Exception:
        return False


def ensure_sso_login(profile_name):
    """Ensure SSO login for the given profile, only prompting if needed."""
    if check_sso_session(profile_name):
        print(f"  ✅ {profile_name} - session valid")
        return

    print(f"  🔐 {profile_name} - logging in...")
    result = subprocess.run(
        ["aws", "sso", "login", "--profile", profile_name],
        capture_output=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"❌ SSO login failed for profile {profile_name}")
    print(f"  ✅ {profile_name} - login successful")


def find_sso_access_token():
    """Find a valid SSO access token from the AWS CLI cache."""
    from datetime import datetime, timezone

    cache_dir = Path.home() / ".aws" / "sso" / "cache"
    if not cache_dir.exists():
        return None

    best_token = None
    best_expiry = None

    for f in cache_dir.glob("*.json"):
        try:
            data = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue

        if data.get("startUrl") != SSO_START_URL:
            continue
        if "accessToken" not in data or "expiresAt" not in data:
            continue

        expiry_str = data["expiresAt"].replace("Z", "+00:00")
        try:
            expiry = datetime.fromisoformat(expiry_str)
        except ValueError:
            continue

        if expiry <= datetime.now(timezone.utc):
            continue

        if best_expiry is None or expiry > best_expiry:
            best_token = data["accessToken"]
            best_expiry = expiry

    return best_token


# ── Organizations ────────────────────────────────────────────────────────────

def list_accounts_in_ou(session, ou_id):
    """List all accounts in an OU, handling pagination."""
    client = session.client("organizations")
    accounts = []
    paginator = client.get_paginator("list_accounts_for_parent")
    for page in paginator.paginate(ParentId=ou_id):
        accounts.extend(page["Accounts"])
    return accounts


# ── SSO Role Credentials ────────────────────────────────────────────────────

def list_sso_roles(sso_client, access_token, account_id):
    """List SSO roles available on an account for the current user."""
    try:
        response = sso_client.list_account_roles(
            accountId=account_id,
            accessToken=access_token,
        )
        return [r["roleName"] for r in response.get("roleList", [])]
    except Exception:
        return []


def get_sso_role_credentials(sso_client, access_token, account_id, role_name):
    """Get temporary credentials for an SSO role on an account."""
    try:
        response = sso_client.get_role_credentials(
            accountId=account_id,
            roleName=role_name,
            accessToken=access_token,
        )
        rc = response["roleCredentials"]
        return Credentials(rc["accessKeyId"], rc["secretAccessKey"], rc["sessionToken"])
    except Exception:
        return None


# ── Console Control Service (CCS) API ────────────────────────────────────────

def ccs_request(creds, operation, body):
    """Make a signed request to the Console Control Service.

    CCS is an undocumented AWS service that stores console UI preferences.
    All endpoints: POST https://{region}.ccs.console.api.aws/{operation}
    SigV4 signed with service name 'console-control'.
    """
    url = f"https://{SSO_REGION}.ccs.console.api.aws/{operation}"
    payload = json.dumps(body)

    req = AWSRequest(method="POST", url=url, data=payload, headers={"Content-Type": "application/json"})
    SigV4Auth(creds, "console-control", SSO_REGION).add_auth(req)

    httpreq = urllib.request.Request(url, data=payload.encode(), headers=dict(req.headers), method="POST")
    try:
        resp = urllib.request.urlopen(httpreq)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"CCS {operation} returned {e.code}: {body_text}")


def get_caller_settings(creds):
    """Read current console settings for the authenticated principal."""
    return ccs_request(creds, "GetCallerSettings", {"settingNames": CCS_SETTINGS_TO_CHECK})


def delete_caller_settings(creds):
    """Delete all known console settings for the authenticated principal."""
    return ccs_request(creds, "UpdateCallerSettings", {"deleteSettingNames": CCS_SETTINGS_TO_DELETE})


def delete_caller_dashboard(creds):
    """Delete the console home dashboard for the authenticated principal."""
    return ccs_request(creds, "DeleteCallerDashboard", {"dashboardId": DASHBOARD_ID})


def has_console_state(settings_response):
    """Check if a GetCallerSettings response contains any stored state."""
    for scope_data in settings_response.get("settingsByScope", {}).values():
        if scope_data:
            return True
    return False


def summarise_state(settings_response):
    """Return a short description of what console state exists."""
    parts = []
    for scope_data in settings_response.get("settingsByScope", {}).values():
        for key, val in scope_data.items():
            if key == "recentsConsole":
                items = val.get("value", [])
                parts.append(f"{len(items)} recent services")
            elif key == "favoritesConsole":
                items = val.get("value", [])
                parts.append(f"{len(items)} favorites")
            else:
                parts.append(key)
    return ", ".join(parts) if parts else "unknown state"


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Clean AWS Console state from Innovation Sandbox pool accounts"
    )
    parser.add_argument(
        "--ou", nargs="+", choices=list(TARGET_OUS.keys()),
        help=f"OUs to target (default: all of {', '.join(TARGET_OUS.keys())})",
    )
    parser.add_argument("--account", help="Clean a specific account ID only")
    parser.add_argument("--dry-run", action="store_true", help="Check state without making changes")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full settings detail")
    args = parser.parse_args()

    target_ous = {name: TARGET_OUS[name] for name in args.ou} if args.ou else TARGET_OUS

    # ── Step 1: SSO Authentication ──────────────────────────────────────────
    print("=" * 60)
    print("🔑 STEP 1: AWS SSO Authentication")
    print("=" * 60)
    ensure_sso_login(ORG_PROFILE)

    sso_token = find_sso_access_token()
    if not sso_token:
        print("  ❌ No valid SSO access token found in cache")
        print(f"     Run: aws sso login --profile {ORG_PROFILE}")
        sys.exit(1)
    print("  ✅ SSO access token found")

    org_session = boto3.Session(profile_name=ORG_PROFILE)
    sso_client = org_session.client("sso")

    # ── Step 2: Discover accounts ───────────────────────────────────────────
    print(f"\n{'='*60}")
    print("📋 STEP 2: Discover sandbox accounts from OU structure")
    print("=" * 60)

    accounts = {}  # {account_id: (name, ou_name)}
    for ou_name, ou_id in target_ous.items():
        ou_accounts = list_accounts_in_ou(org_session, ou_id)
        for acct in ou_accounts:
            acct_id = acct["Id"]
            if args.account and acct_id != args.account:
                continue
            accounts[acct_id] = (acct.get("Name", ""), ou_name)
        print(f"  {ou_name}: {len(ou_accounts)} account(s)")

    if args.account and args.account not in accounts:
        print(f"\n  ❌ Account {args.account} not found in target OUs ({', '.join(target_ous.keys())})")
        sys.exit(1)

    if not accounts:
        print("  ℹ️  No accounts found in target OUs")
        sys.exit(0)

    print(f"\n📊 {len(accounts)} account(s) to process:\n")
    print(f"{'Account ID':<15} {'Name':<12} {'OU'}")
    print("-" * 45)
    for acct_id, (name, ou_name) in sorted(accounts.items()):
        print(f"{acct_id:<15} {name:<12} {ou_name}")

    # ── Step 3: Clean console state ─────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"🧹 STEP 3: Clean console state")
    print("=" * 60)

    total_cleaned = 0
    total_already_clean = 0
    total_errors = 0

    for account_id, (name, ou_name) in sorted(accounts.items()):
        print(f"\n  {'─'*56}")
        print(f"  📦 {account_id}  {name}  ({ou_name})")
        print(f"  {'─'*56}")

        # Discover which SSO roles are available on this account
        available_roles = list_sso_roles(sso_client, sso_token, account_id)
        isb_roles = [r for r in ISB_ROLE_NAMES if r in available_roles]

        if not isb_roles:
            print(f"     ⚠️  No ISB SSO roles available (found: {available_roles or 'none'})")
            total_errors += 1
            continue

        for role_name in isb_roles:
            print(f"\n     🔐 {role_name}")

            creds = get_sso_role_credentials(sso_client, sso_token, account_id, role_name)
            if not creds:
                print(f"        ❌ Could not get credentials")
                total_errors += 1
                continue

            try:
                settings = get_caller_settings(creds)
            except RuntimeError as e:
                print(f"        ❌ Error reading settings: {e}")
                total_errors += 1
                continue

            if not has_console_state(settings):
                print(f"        ✅ Already clean")
                total_already_clean += 1
                continue

            print(f"        📊 {summarise_state(settings)}")

            if args.verbose:
                print(f"        {json.dumps(settings, indent=8)}")

            if args.dry_run:
                print(f"        ℹ️  [DRY RUN] Would delete settings and dashboard")
                continue

            # Delete settings
            try:
                delete_caller_settings(creds)
                print(f"        🗑️  Deleted settings")
            except RuntimeError as e:
                print(f"        ❌ Error deleting settings: {e}")
                total_errors += 1

            # Delete dashboard
            try:
                delete_caller_dashboard(creds)
                print(f"        🗑️  Deleted dashboard")
            except RuntimeError as e:
                print(f"        ❌ Error deleting dashboard: {e}")
                total_errors += 1

            # Verify
            try:
                after = get_caller_settings(creds)
                if has_console_state(after):
                    print(f"        ⚠️  State still present after cleanup")
                    total_errors += 1
                else:
                    print(f"        ✅ Verified clean")
                    total_cleaned += 1
            except RuntimeError:
                print(f"        ℹ️  Could not verify (non-fatal)")
                total_cleaned += 1

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    if args.dry_run:
        print("📊 Summary (dry run)")
    else:
        print("📊 Summary")
    print("=" * 60)
    print(f"  Accounts:       {len(accounts)}")
    print(f"  Cleaned:        {total_cleaned}")
    print(f"  Already clean:  {total_already_clean}")
    print(f"  Errors:         {total_errors}")

    if total_errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
