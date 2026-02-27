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
  2. Temporarily assigns the current user to each ISB permission set on each
     account (ndx_IsbUsersPS is normally only assigned during active leases)
  3. Gets SSO role credentials for each permission set
  4. Calls the CCS APIs to reset console state for that principal
  5. Removes the temporary permission set assignments

Uses the NDX/orgManagement profile for Organizations and SSO Admin APIs.
Uses cached SSO access token for SSO role credential acquisition.

Note: CCS state is per-caller (keyed on full assumed-role ARN including session
name). This script cleans state for the SSO principal running it. Each user who
has accessed the console on these accounts would need to run it separately, or
the script needs to be run with credentials for each user's SSO session.
"""

import argparse
import base64
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
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
SSO_INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-79078bb87a820e72"
SSO_IDENTITY_STORE_ID = "d-9267e1e371"
ORG_PROFILE = "NDX/orgManagement"

# ISB account pool OU structure (children of ndx_InnovationSandboxAccountPool)
TARGET_OUS = {
    "Available":  "ou-2laj-oihxgbtr",
    "CleanUp":    "ou-2laj-x3o8lbk8",
    "Quarantine": "ou-2laj-mmagoake",
}

# ISB SSO permission sets provisioned to sandbox accounts
ALL_PERMISSION_SETS = {
    "ndx_IsbUsersPS":    "arn:aws:sso:::permissionSet/ssoins-79078bb87a820e72/ps-79074793b1df1a84",
    "ndx_IsbAdminsPS":   "arn:aws:sso:::permissionSet/ssoins-79078bb87a820e72/ps-790724a4fad3095f",
    "ndx_IsbManagersPS": "arn:aws:sso:::permissionSet/ssoins-79078bb87a820e72/ps-7907c6dd36e49882",
}

# Default: only clean the user-facing permission set (fastest, covers the common case)
DEFAULT_PERMISSION_SETS = ["ndx_IsbUsersPS"]

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

# ISB Hub profile for querying lease data via Lambda
ISB_HUB_PROFILE = "NDX/InnovationSandboxHub"
ISB_API_BASE_URL = "https://1ewlxhaey6.execute-api.us-west-2.amazonaws.com/prod/"
ISB_JWT_SECRET_PATH = "/InnovationSandbox/ndx/Auth/JwtSecret"
LEASES_LAMBDA = "ISB-LeasesLambdaFunction-ndx"

# Cache for tracking which accounts have already been cleaned
CACHE_DIR = Path.home() / ".cache" / "clean-console-state"
CACHE_FILE = CACHE_DIR / "cache.json"


# ── Cache ─────────────────────────────────────────────────────────────────────

def load_cache():
    """Load the cleaning cache from disk."""
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_cache(cache):
    """Save the cleaning cache to disk."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n")


def clear_cache():
    """Remove the cache file."""
    if CACHE_FILE.exists():
        CACHE_FILE.unlink()
        print(f"  🗑️  Cache cleared: {CACHE_FILE}")
    else:
        print(f"  ℹ️  No cache file found: {CACHE_FILE}")


def update_cache(cache, account_id, permission_sets):
    """Mark an account as cleaned in the cache."""
    now = datetime.now(timezone.utc).isoformat()
    existing = cache.get(account_id, {})
    existing_psets = set(existing.get("permission_sets", []))
    existing_psets.update(permission_sets)
    cache[account_id] = {
        "cleaned_at": now,
        "permission_sets": sorted(existing_psets),
    }


# ── ISB Lease Query ──────────────────────────────────────────────────────────

def create_mock_jwt():
    """Create a mock JWT token for direct Lambda invocation.

    The Lambda only decodes the JWT (doesn't verify signature), so we can
    create an unsigned token with the required user structure.
    """
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "user": {
            "email": "admin@innovation-sandbox.local",
            "roles": ["Admin"],
        }
    }

    def b64_encode(data):
        return base64.urlsafe_b64encode(
            json.dumps(data).encode()
        ).rstrip(b'=').decode()

    return f"{b64_encode(header)}.{b64_encode(payload)}."


def get_isb_leases(verbose=False):
    """Query the ISB leases Lambda to get all leases."""
    hub_session = boto3.Session(profile_name=ISB_HUB_PROFILE)
    lambda_client = hub_session.client('lambda')
    mock_token = create_mock_jwt()

    event = {
        "httpMethod": "GET",
        "path": "/leases",
        "headers": {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {mock_token}",
        },
        "requestContext": {},
        "queryStringParameters": None,
        "pathParameters": None,
    }

    response = lambda_client.invoke(
        FunctionName=LEASES_LAMBDA,
        InvocationType='RequestResponse',
        Payload=json.dumps(event),
    )

    response_payload = json.loads(response['Payload'].read().decode('utf-8'))

    if response.get('FunctionError'):
        raise RuntimeError(f"Lambda error: {response_payload}")

    status_code = response_payload.get('statusCode', 0)
    body_str = response_payload.get('body', '{}')
    body = json.loads(body_str) if body_str else {}

    if verbose:
        print(f"  🔍 Leases API response (HTTP {status_code}):")
        print(f"     {json.dumps(body, indent=6)[:2000]}")

    if status_code != 200:
        raise RuntimeError(f"ISB leases API returned HTTP {status_code}: {body}")

    return body


def get_last_lease_times(body):
    """Return dict of account_id -> most recent lease creation time (ISO string).

    Handles various ISB response shapes:
      - {"data": [{"accountId": ..., "createdDate": ...}, ...]}
      - {"data": {"leases": [...]}}
      - [{"accountId": ..., "createdDate": ...}, ...]
    """
    # Extract the lease list from whichever shape the API returns
    leases = []
    if isinstance(body, list):
        leases = body
    elif isinstance(body, dict):
        data = body.get('data', body)
        if isinstance(data, list):
            leases = data
        elif isinstance(data, dict):
            # Try common nested keys
            for key in ('leases', 'items', 'results'):
                if isinstance(data.get(key), list):
                    leases = data[key]
                    break
            else:
                # data dict might be a single lease or keyed by account
                leases = list(data.values()) if data else []

    last_times = {}
    for lease in leases:
        if not isinstance(lease, dict):
            continue
        account_id = lease.get('accountId') or lease.get('awsAccountId', '')
        lease_date = (
            lease.get('createdDate')
            or lease.get('startDate')
            or lease.get('lastModifiedDate', '')
        )
        if not account_id or not lease_date:
            continue

        if account_id not in last_times or lease_date > last_times[account_id]:
            last_times[account_id] = lease_date

    return last_times


def account_needs_cleaning(account_id, cache, last_lease_times, permission_sets_requested):
    """Check if an account needs cleaning based on cache and lease data.

    Returns (needs_cleaning: bool, reason: str)
    """
    cached = cache.get(account_id)
    if not cached:
        return True, "not in cache"

    cleaned_at = cached.get("cleaned_at", "")
    cached_psets = set(cached.get("permission_sets", []))

    # If we're cleaning permission sets not previously cached, need to clean
    if not set(permission_sets_requested).issubset(cached_psets):
        new_psets = set(permission_sets_requested) - cached_psets
        return True, f"new permission sets: {', '.join(sorted(new_psets))}"

    # If there's a lease issued after our last clean, need to clean
    last_lease = last_lease_times.get(account_id)
    if last_lease and last_lease > cleaned_at:
        return True, f"lease since last clean ({last_lease[:19]})"

    if not last_lease:
        return False, f"no leases found, cleaned {cleaned_at[:19]}"

    return False, f"cleaned {cleaned_at[:19]}, last lease {last_lease[:19]}"


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


def get_current_sso_user_id(session):
    """Get the Identity Store user ID for the current SSO user."""
    # Get the current user's email from STS
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    # ARN format: arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/EMAIL
    arn = identity["Arn"]
    email = arn.split("/")[-1]

    ids = session.client("identitystore")
    response = ids.list_users(
        IdentityStoreId=SSO_IDENTITY_STORE_ID,
        Filters=[{"AttributePath": "UserName", "AttributeValue": email}],
    )
    users = response.get("Users", [])
    if not users:
        raise RuntimeError(f"❌ Could not find SSO user for {email}")
    return users[0]["UserId"], email


# ── Organizations ────────────────────────────────────────────────────────────

def list_accounts_in_ou(session, ou_id):
    """List all accounts in an OU, handling pagination."""
    client = session.client("organizations")
    accounts = []
    paginator = client.get_paginator("list_accounts_for_parent")
    for page in paginator.paginate(ParentId=ou_id):
        accounts.extend(page["Accounts"])
    return accounts


# ── SSO Permission Set Assignment ────────────────────────────────────────────

def create_account_assignment(sso_admin, account_id, permission_set_arn, user_id):
    """Create a temporary SSO permission set assignment for a user on an account."""
    try:
        response = sso_admin.create_account_assignment(
            InstanceArn=SSO_INSTANCE_ARN,
            TargetId=account_id,
            TargetType="AWS_ACCOUNT",
            PermissionSetArn=permission_set_arn,
            PrincipalType="USER",
            PrincipalId=user_id,
        )
        request_id = response["AccountAssignmentCreationStatus"]["RequestId"]
        # Wait for the assignment to complete
        while True:
            status = sso_admin.describe_account_assignment_creation_status(
                InstanceArn=SSO_INSTANCE_ARN,
                AccountAssignmentCreationRequestId=request_id,
            )["AccountAssignmentCreationStatus"]
            if status["Status"] == "SUCCEEDED":
                return True
            elif status["Status"] == "FAILED":
                reason = status.get("FailureReason", "unknown")
                print(f"        ⚠️  Assignment failed: {reason}")
                return False
            time.sleep(1)
    except sso_admin.exceptions.ConflictException:
        # Already assigned
        return True
    except Exception as e:
        print(f"        ⚠️  Could not assign: {e}")
        return False


def delete_account_assignment(sso_admin, account_id, permission_set_arn, user_id):
    """Remove an SSO permission set assignment for a user on an account."""
    try:
        response = sso_admin.delete_account_assignment(
            InstanceArn=SSO_INSTANCE_ARN,
            TargetId=account_id,
            TargetType="AWS_ACCOUNT",
            PermissionSetArn=permission_set_arn,
            PrincipalType="USER",
            PrincipalId=user_id,
        )
        request_id = response["AccountAssignmentDeletionStatus"]["RequestId"]
        while True:
            status = sso_admin.describe_account_assignment_deletion_status(
                InstanceArn=SSO_INSTANCE_ARN,
                AccountAssignmentDeletionRequestId=request_id,
            )["AccountAssignmentDeletionStatus"]
            if status["Status"] in ("SUCCEEDED", "FAILED"):
                return status["Status"] == "SUCCEEDED"
            time.sleep(1)
    except Exception as e:
        print(f"        ⚠️  Could not remove assignment: {e}")
        return False


def check_account_assignment(sso_admin, account_id, permission_set_arn, user_id):
    """Check if a user already has a permission set assignment on an account."""
    try:
        response = sso_admin.list_account_assignments(
            InstanceArn=SSO_INSTANCE_ARN,
            AccountId=account_id,
            PermissionSetArn=permission_set_arn,
        )
        for assignment in response.get("AccountAssignments", []):
            if assignment.get("PrincipalId") == user_id:
                return True
        return False
    except Exception:
        return False


# ── SSO Role Credentials ────────────────────────────────────────────────────

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
        resp_body = resp.read()
        if resp_body:
            return json.loads(resp_body)
        return {}
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

def get_sso_role_credentials_with_retry(sso_client, access_token, account_id, role_name, retries=5):
    """Get SSO role credentials, retrying for newly-created assignments that need propagation."""
    for attempt in range(retries):
        creds = get_sso_role_credentials(sso_client, access_token, account_id, role_name)
        if creds:
            return creds
        if attempt < retries - 1:
            wait = 2 ** attempt  # 1, 2, 4, 8, 16s
            total_waited = sum(2 ** i for i in range(attempt + 1))
            print(f"        ⏳ Waiting for assignment to propagate ({total_waited}s)...")
            time.sleep(wait)
    return None


def clean_role(sso_client, sso_token, account_id, role_name, dry_run, verbose, newly_assigned=False):
    """Clean console state for a single role on a single account.

    Returns: "cleaned", "already_clean", or "error"
    """
    if newly_assigned:
        creds = get_sso_role_credentials_with_retry(sso_client, sso_token, account_id, role_name)
    else:
        creds = get_sso_role_credentials(sso_client, sso_token, account_id, role_name)
    if not creds:
        print(f"        ❌ Could not get credentials")
        return "error"

    try:
        settings = get_caller_settings(creds)
    except RuntimeError as e:
        print(f"        ❌ Error reading settings: {e}")
        return "error"

    if not has_console_state(settings):
        print(f"        ✅ Already clean")
        return "already_clean"

    print(f"        📊 {summarise_state(settings)}")

    if verbose:
        print(f"        {json.dumps(settings, indent=8)}")

    if dry_run:
        print(f"        ℹ️  [DRY RUN] Would delete settings and dashboard")
        return "already_clean"  # count as no-op for summary

    # Delete settings
    try:
        delete_caller_settings(creds)
        print(f"        🗑️  Deleted settings")
    except RuntimeError as e:
        print(f"        ❌ Error deleting settings: {e}")
        return "error"

    # Delete dashboard
    try:
        delete_caller_dashboard(creds)
        print(f"        🗑️  Deleted dashboard")
    except RuntimeError as e:
        print(f"        ❌ Error deleting dashboard: {e}")
        return "error"

    # Verify
    try:
        after = get_caller_settings(creds)
        if has_console_state(after):
            print(f"        ⚠️  State still present after cleanup")
            return "error"
        else:
            print(f"        ✅ Verified clean")
            return "cleaned"
    except RuntimeError:
        print(f"        ℹ️  Could not verify (non-fatal)")
        return "cleaned"


def main():
    parser = argparse.ArgumentParser(
        description="Clean AWS Console state from Innovation Sandbox pool accounts"
    )
    parser.add_argument(
        "--ou", nargs="+", choices=list(TARGET_OUS.keys()),
        help=f"OUs to target (default: all of {', '.join(TARGET_OUS.keys())})",
    )
    parser.add_argument("--account", help="Clean a specific account ID only")
    parser.add_argument("--all-roles", action="store_true",
                        help="Clean all ISB permission sets (default: only ndx_IsbUsersPS)")
    parser.add_argument("--dry-run", action="store_true", help="Check state without making changes")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full settings detail")
    parser.add_argument("--clear-cache", action="store_true",
                        help="Clear the cleaning cache and exit")
    parser.add_argument("--no-cache", action="store_true",
                        help="Ignore the cache for this run (clean all accounts)")
    args = parser.parse_args()

    if args.clear_cache:
        clear_cache()
        sys.exit(0)

    target_ous = {name: TARGET_OUS[name] for name in args.ou} if args.ou else TARGET_OUS
    if args.all_roles:
        permission_sets = ALL_PERMISSION_SETS
    else:
        permission_sets = {k: ALL_PERMISSION_SETS[k] for k in DEFAULT_PERMISSION_SETS}

    use_cache = not args.no_cache

    # ── Step 1: SSO Authentication ──────────────────────────────────────────
    print("=" * 60)
    print("🔑 STEP 1: AWS SSO Authentication")
    print("=" * 60)
    ensure_sso_login(ORG_PROFILE)
    ensure_sso_login(ISB_HUB_PROFILE)

    sso_token = find_sso_access_token()
    if not sso_token:
        print("  ❌ No valid SSO access token found in cache")
        print(f"     Run: aws sso login --profile {ORG_PROFILE}")
        sys.exit(1)
    print("  ✅ SSO access token found")

    org_session = boto3.Session(profile_name=ORG_PROFILE)
    sso_client = org_session.client("sso")
    sso_admin = org_session.client("sso-admin")

    # Get current user's identity store ID for permission set assignment
    user_id, user_email = get_current_sso_user_id(org_session)
    print(f"  👤 {user_email} ({user_id})")

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

    print(f"\n📊 {len(accounts)} account(s) found")

    # ── Step 2.5: Query lease data and check cache ─────────────────────────
    print(f"\n{'='*60}")
    print("📅 STEP 2.5: Check lease history and cache")
    print("=" * 60)

    cache = load_cache() if use_cache else {}
    last_lease_times = {}
    pset_names = list(permission_sets.keys())

    try:
        print("  📡 Querying ISB lease data...")
        leases_body = get_isb_leases(verbose=args.verbose)
        last_lease_times = get_last_lease_times(leases_body)
        print(f"  ✅ Found lease data for {len(last_lease_times)} account(s)")
    except Exception as e:
        print(f"  ⚠️  Could not query leases: {e}")
        print(f"  ℹ️  Proceeding without lease data (will clean all accounts)")

    if use_cache and cache:
        print(f"  📁 Cache: {len(cache)} account(s) from {CACHE_FILE}")
    elif use_cache:
        print(f"  📁 Cache: empty")
    else:
        print(f"  📁 Cache: disabled (--no-cache)")

    # Determine which accounts need cleaning
    accounts_to_clean = {}
    total_skipped = 0
    print(f"\n{'Account ID':<15} {'Name':<12} {'OU':<12} {'Status'}")
    print("-" * 65)
    for acct_id, (name, ou_name) in sorted(accounts.items()):
        if use_cache:
            needs_cleaning, reason = account_needs_cleaning(
                acct_id, cache, last_lease_times, pset_names
            )
        else:
            needs_cleaning, reason = True, "cache disabled"

        if needs_cleaning:
            accounts_to_clean[acct_id] = (name, ou_name)
            print(f"{acct_id:<15} {name:<12} {ou_name:<12} 🔄 {reason}")
        else:
            total_skipped += 1
            print(f"{acct_id:<15} {name:<12} {ou_name:<12} ⏭️  skip: {reason}")

    if not accounts_to_clean:
        print(f"\n  ✅ All {len(accounts)} account(s) already clean — nothing to do")
        sys.exit(0)

    print(f"\n📊 {len(accounts_to_clean)} to clean, {total_skipped} skipped")

    # ── Step 3: Clean console state ─────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"🧹 STEP 3: Clean console state")
    print("=" * 60)

    total_cleaned = 0
    total_already_clean = 0
    total_errors = 0

    for account_id, (name, ou_name) in sorted(accounts_to_clean.items()):
        print(f"\n  {'─'*56}")
        print(f"  📦 {account_id}  {name}  ({ou_name})")
        print(f"  {'─'*56}")

        # Track temp assignments for this account so we always clean up
        account_temp_assignments = []
        account_had_error = False

        try:
            for role_name, ps_arn in permission_sets.items():
                print(f"\n     🔐 {role_name}")

                # Check if we already have this assignment
                already_assigned = check_account_assignment(sso_admin, account_id, ps_arn, user_id)
                newly_assigned = False

                if not already_assigned:
                    if args.dry_run:
                        print(f"        ℹ️  Would temporarily assign {role_name}")
                    else:
                        print(f"        📌 Temporarily assigning...")
                        if create_account_assignment(sso_admin, account_id, ps_arn, user_id):
                            print(f"        📌 Assigned")
                            account_temp_assignments.append((ps_arn, role_name))
                            newly_assigned = True
                        else:
                            total_errors += 1
                            account_had_error = True
                            continue

                result = clean_role(sso_client, sso_token, account_id, role_name, args.dry_run, args.verbose, newly_assigned)
                if result == "cleaned":
                    total_cleaned += 1
                elif result == "already_clean":
                    total_already_clean += 1
                else:
                    total_errors += 1
                    account_had_error = True

        except Exception as e:
            print(f"\n     ❌ Unexpected error: {e}")
            total_errors += 1
            account_had_error = True

        finally:
            # Always remove temporary assignments for this account
            for ps_arn, ps_name in account_temp_assignments:
                if delete_account_assignment(sso_admin, account_id, ps_arn, user_id):
                    print(f"        🗑️  Removed {ps_name}")
                else:
                    print(f"        ⚠️  Failed to remove {ps_name} — clean up manually")

            # Update cache if account was processed without errors
            if not account_had_error and not args.dry_run:
                update_cache(cache, account_id, pset_names)
                save_cache(cache)

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    if args.dry_run:
        print("📊 Summary (dry run)")
    else:
        print("📊 Summary")
    print("=" * 60)
    print(f"  Accounts:       {len(accounts)}")
    print(f"  Skipped (cache):{total_skipped:>3}")
    print(f"  Cleaned:        {total_cleaned}")
    print(f"  Already clean:  {total_already_clean}")
    print(f"  Errors:         {total_errors}")
    if use_cache:
        print(f"  Cache:          {CACHE_FILE}")

    if total_errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
