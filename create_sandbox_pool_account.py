#!/usr/bin/env python3
"""
List AWS Organization accounts that start with 'pool-' and create the next one(s).
Uses the NDX/orgManagement profile for Organizations API.
Uses NDX/InnovationSandboxHub profile for Secrets Manager access.

Requires environment variables:
  ISB_API_BASE_URL      - Innovation Sandbox API Gateway base URL
  ISB_JWT_SECRET_PATH   - Secrets Manager path for JWT signing secret
"""

import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import boto3

# Target OU where Innovation Sandbox moves accounts after cleanup
SANDBOX_READY_OU = "ou-2laj-oihxgbtr"
ENTRY_OU = "ou-2laj-2by9v0sr"
ROOT_ID = None  # Will be populated at runtime
_root_id_lock = threading.Lock()

# Custom billing view ARN for tracking pool account costs
BILLING_VIEW_ARN = "arn:aws:billing::955063685555:billingview/custom-466e2613-e09b-4787-a93a-736f0fb1564b"

# Lock for billing view read-modify-write operations
_billing_lock = threading.Lock()


def check_sso_session(profile_name):
    """Check if SSO session is valid for the given profile."""
    try:
        session = boto3.Session(profile_name=profile_name)
        sts = session.client('sts')
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


def sign_jwt(payload, secret, expires_in_seconds=3600):
    """Sign a JWT with HS256 algorithm.

    Mirrors the TypeScript signJwt() in @co-cddo/isb-client.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    full_payload = {**payload, "iat": now, "exp": now + expires_in_seconds}

    def b64url_encode(data):
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()

    encoded_header = b64url_encode(header)
    encoded_payload = b64url_encode(full_payload)
    signing_input = f"{encoded_header}.{encoded_payload}"

    signature = hmac.new(
        secret.encode(),
        signing_input.encode(),
        hashlib.sha256
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def fetch_jwt_secret(session, secret_path):
    """Fetch JWT signing secret from AWS Secrets Manager."""
    client = session.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_path)
    secret = response.get('SecretString')
    if not secret:
        raise RuntimeError("JWT secret is empty")
    return secret


def get_all_accounts(session):
    """Retrieve all accounts from AWS Organizations with pagination."""
    client = session.client('organizations')
    accounts = []
    paginator = client.get_paginator('list_accounts')

    for page in paginator.paginate():
        accounts.extend(page['Accounts'])

    return accounts


def get_next_pool_number(pool_accounts):
    """Find the highest pool number and return the next one."""
    max_number = 0
    pattern = re.compile(r'^pool-(\d{3})$')

    for acc in pool_accounts:
        match = pattern.match(acc['Name'])
        if match:
            number = int(match.group(1))
            if number > max_number:
                max_number = number

    return max_number + 1


def create_pool_account(session, account_name, email, label=""):
    """Create a new AWS account in the organization."""
    p = f"{label} " if label else ""
    client = session.client('organizations')

    response = client.create_account(
        Email=email,
        AccountName=account_name,
    )

    request_id = response['CreateAccountStatus']['Id']
    print(f"{p}   Request ID: {request_id}")

    # Poll for completion
    while True:
        status_response = client.describe_create_account_status(
            CreateAccountRequestId=request_id
        )
        status = status_response['CreateAccountStatus']

        if status['State'] == 'SUCCEEDED':
            print(f"\r{p}   ✅ Account created: {status['AccountId']}{' ' * 20}")
            return status['AccountId']
        elif status['State'] == 'FAILED':
            print(f"\r{p}   ❌ Failed: {status.get('FailureReason', 'Unknown')}{' ' * 20}")
            return None
        else:
            print(f"\r{p}   ⏳ {status['State']}...", end="", flush=True)
            time.sleep(5)


def get_root_id(session):
    """Get the organization root ID."""
    global ROOT_ID
    with _root_id_lock:
        if ROOT_ID is None:
            client = session.client('organizations')
            roots = client.list_roots()['Roots']
            ROOT_ID = roots[0]['Id']
    return ROOT_ID


def move_account_to_ou(session, account_id, destination_ou_id, source_parent_id=None, label=""):
    """Move an account to a specific OU."""
    p = f"{label} " if label else ""
    client = session.client('organizations')

    # If source not provided, get current parent
    if source_parent_id is None:
        source_parent_id = get_account_ou(session, account_id)

    print(f"{p}   📍 From: {source_parent_id}")
    print(f"{p}   📍 To:   {destination_ou_id}")

    client.move_account(
        AccountId=account_id,
        SourceParentId=source_parent_id,
        DestinationParentId=destination_ou_id,
    )

    print(f"{p}   ✅ Move complete")


def get_account_ou(session, account_id):
    """Get the OU that an account is currently in."""
    client = session.client('organizations')
    response = client.list_parents(ChildId=account_id)
    if response['Parents']:
        return response['Parents'][0]['Id']
    return None


def add_account_to_billing_view(session, account_id, label=""):
    """Add an account to the custom billing view.

    Uses read-modify-write pattern since there's no incremental add API.
    Continues with warning on failure (non-blocking).
    """
    p = f"{label} " if label else ""
    try:
        billing_client = session.client('billing')

        # Get current billing view
        print(f"{p}   📊 Fetching current billing view...")
        response = billing_client.get_billing_view(arn=BILLING_VIEW_ARN)
        billing_view = response['billingView']

        # Get existing accounts from the filter expression
        data_filter = billing_view.get('dataFilterExpression', {})
        dimensions = data_filter.get('dimensions', {})
        existing_accounts = dimensions.get('values', [])

        # Check if account already exists
        if account_id in existing_accounts:
            print(f"{p}   ℹ️  Account {account_id} already in billing view")
            return True

        # Add new account
        updated_accounts = existing_accounts + [account_id]
        print(f"{p}   📝 Adding account (total will be {len(updated_accounts)} accounts)")

        # Update billing view
        billing_client.update_billing_view(
            arn=BILLING_VIEW_ARN,
            dataFilterExpression={
                'dimensions': {
                    'key': 'LINKED_ACCOUNT',
                    'values': updated_accounts
                }
            }
        )

        print(f"{p}   ✅ Added account to billing view")
        return True

    except Exception as e:
        print(f"{p}   ⚠️  Warning: Failed to add account to billing view: {e}")
        print(f"{p}   ℹ️  Continuing with remaining steps...")
        return False


def tag_account(session, account_id, label=""):
    """Tag an account with do-not-separate."""
    p = f"{label} " if label else ""
    client = session.client('organizations')
    client.tag_resource(
        ResourceId=account_id,
        Tags=[{'Key': 'do-not-separate', 'Value': ''}],
    )
    print(f"{p}   ✅ Tagged with do-not-separate")


def wait_for_ou_move(session, account_id, target_ou, check_interval=5, max_wait=3600, label=""):
    """Wait for an account to be moved to the target OU.

    Args:
        session: boto3 session
        account_id: AWS account ID to monitor
        target_ou: Target OU ID to wait for
        check_interval: Seconds between checks (default 5)
        max_wait: Maximum seconds to wait (default 3600 = 1 hour)
        label: Optional prefix for log output
    """
    p = f"{label} " if label else ""
    print(f"{p}⏳ Waiting for Innovation Sandbox cleanup...")
    print(f"{p}   Target OU: {target_ou}")

    waited = 0
    while waited < max_wait:
        current_ou = get_account_ou(session, account_id)
        if current_ou == target_ou:
            print(f"\r{p}   ✅ Account moved to target OU after {format_duration(waited)}!{' ' * 20}")
            return True

        # Update single line with carriage return
        print(f"\r{p}   ⏳ Current OU: {current_ou} | Elapsed: {format_duration(waited)}", end="", flush=True)
        time.sleep(check_interval)
        waited += check_interval

    print(f"\r{p}   ❌ Timeout after {format_duration(max_wait)}{' ' * 30}")
    return False


def register_with_innovation_sandbox(account_id, label=""):
    """Register the account with Innovation Sandbox via API Gateway."""
    p = f"{label} " if label else ""
    api_base_url = os.environ.get("ISB_API_BASE_URL")
    jwt_secret_path = os.environ.get("ISB_JWT_SECRET_PATH")

    if not api_base_url or not jwt_secret_path:
        print(f"{p}   ❌ ISB_API_BASE_URL and ISB_JWT_SECRET_PATH environment variables must be set")
        return False

    # Fetch JWT secret from Secrets Manager (uses InnovationSandboxHub profile)
    hub_session = boto3.Session(profile_name='NDX/InnovationSandboxHub')
    print(f"{p}   🔑 Fetching JWT secret...")
    jwt_secret = fetch_jwt_secret(hub_session, jwt_secret_path)

    # Sign a proper HS256 JWT
    token = sign_jwt(
        {"user": {"email": "admin@innovation-sandbox.local", "roles": ["Admin"]}},
        jwt_secret,
    )

    # POST to API Gateway
    url = f"{api_base_url.rstrip('/')}/accounts"
    body = json.dumps({"awsAccountId": account_id}).encode()

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )

    print(f"{p}   🎯 Account: {account_id}")
    print(f"{p}   🌐 API: {url}")
    print(f"{p}   ⏳ Registering...", end="", flush=True)

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            status_code = response.status
            response_body = json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        status_code = e.code
        try:
            response_body = json.loads(e.read().decode())
        except Exception:
            response_body = {}

    if status_code == 201 and response_body.get("status") == "success":
        print(f"\r{p}   ✅ Registered successfully!{' ' * 20}")
        data = response_body.get("data", {})
        print(f"{p}   📄 Status: {data.get('status', 'unknown')}")
        return True
    else:
        print(f"\r{p}   ❌ Registration failed (HTTP {status_code}){' ' * 20}")
        print(f"{p}   Response: {json.dumps(response_body, indent=2)}")
        return False


def format_duration(seconds):
    """Format seconds into a human-readable duration."""
    minutes, secs = divmod(int(seconds), 60)
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def recover_account(session, account_id):
    """Recover a partially provisioned account.

    Returns:
        True if recovery can proceed, False if account is in invalid state.
    """
    root_id = get_root_id(session)
    current_ou = get_account_ou(session, account_id)

    print(f"   📍 Current location: {current_ou}")

    if current_ou == root_id:
        print("   ℹ️  Account is in root - will move to Entry OU and register")
        print(f"\n{'='*60}")
        print(f"📦 Moving to Entry OU")
        print(f"{'='*60}")
        move_account_to_ou(session, account_id, ENTRY_OU, source_parent_id=root_id)
        return True

    elif current_ou == ENTRY_OU:
        print("   ℹ️  Account is in Entry OU - will register with Innovation Sandbox")
        return True

    else:
        print(f"\n   ❌ ERROR: Account is not in root ({root_id}) or Entry OU ({ENTRY_OU})")
        print(f"   Current OU: {current_ou}")
        print("   Cannot recover - account may already be processed or in an unexpected state")
        return False


def provision_account(session, account_name, email, label=""):
    """Provision a single pool account: create, move, tag, register, and wait.

    Returns (account_name, account_id) on success, (account_name, None) on failure.
    """
    p = f"{label} " if label else ""

    try:
        print(f"\n{p}{'='*60}")
        print(f"{p}🆕 Create account: {account_name}")
        print(f"{p}{'='*60}")
        print(f"{p}   Account name: {account_name}")
        print(f"{p}   Email: {email}")

        account_id = create_pool_account(session, account_name, email, label=label)
        if not account_id:
            print(f"\n{p}❌ Account creation failed for {account_name}")
            return (account_name, None)

        print(f"\n{p}{'='*60}")
        print(f"{p}📦 Move to Entry OU: {account_name}")
        print(f"{p}{'='*60}")
        root_id = get_root_id(session)
        move_account_to_ou(session, account_id, ENTRY_OU, source_parent_id=root_id, label=label)

        print(f"\n{p}{'='*60}")
        print(f"{p}💰 Add to Billing View: {account_name}")
        print(f"{p}{'='*60}")
        with _billing_lock:
            add_account_to_billing_view(session, account_id, label=label)

        print(f"\n{p}{'='*60}")
        print(f"{p}🏷️  Tag Account: {account_name}")
        print(f"{p}{'='*60}")
        tag_account(session, account_id, label=label)

        print(f"\n{p}{'='*60}")
        print(f"{p}📝 Register with Innovation Sandbox: {account_name}")
        print(f"{p}{'='*60}")
        register_with_innovation_sandbox(account_id, label=label)

        print(f"\n{p}{'='*60}")
        print(f"{p}🧹 Wait for cleanup: {account_name}")
        print(f"{p}{'='*60}")
        wait_for_ou_move(session, account_id, SANDBOX_READY_OU, label=label)

        return (account_name, account_id)

    except Exception as e:
        print(f"\n{p}❌ Error provisioning {account_name}: {e}")
        return (account_name, None)


def main():
    parser = argparse.ArgumentParser(
        description="Create and register pool accounts for Innovation Sandbox"
    )
    parser.add_argument(
        "account_id",
        nargs="?",
        help="Optional: AWS account ID to recover (for fixing partial errors)"
    )
    parser.add_argument(
        "--num",
        type=int,
        default=1,
        help="Number of accounts to create in parallel (default: 1)"
    )
    args = parser.parse_args()

    if args.account_id and args.num > 1:
        print("❌ Cannot use --num with recovery mode (account_id argument)")
        sys.exit(1)

    if args.num < 1:
        print("❌ --num must be at least 1")
        sys.exit(1)

    start_time = time.time()

    # SSO login for both profiles
    print("=" * 60)
    print("🔑 AWS SSO Authentication")
    print("=" * 60)
    ensure_sso_login("NDX/orgManagement")
    ensure_sso_login("NDX/InnovationSandboxHub")

    # Create session with the specified profile
    session = boto3.Session(profile_name='NDX/orgManagement')

    if args.account_id:
        # Recovery mode - fix a partially provisioned account
        account_id = args.account_id
        print(f"\n{'='*60}")
        print(f"🔧 RECOVERY MODE: Processing existing account {account_id}")
        print(f"{'='*60}")

        if not recover_account(session, account_id):
            print("\n❌ Recovery failed - exiting")
            sys.exit(1)

        # Add to billing view for recovered accounts
        print(f"\n{'='*60}")
        print(f"💰 Add to Billing View")
        print(f"{'='*60}")
        add_account_to_billing_view(session, account_id)

        print(f"\n{'='*60}")
        print(f"🏷️  Tag Account")
        print(f"{'='*60}")
        tag_account(session, account_id)

        print(f"\n{'='*60}")
        print(f"📝 Register with Innovation Sandbox")
        print(f"{'='*60}")
        register_with_innovation_sandbox(account_id)

        print(f"\n{'='*60}")
        print(f"🧹 Wait for Innovation Sandbox cleanup")
        print(f"{'='*60}")
        wait_for_ou_move(session, account_id, SANDBOX_READY_OU)

        end_time = time.time()
        total_duration = end_time - start_time

        print(f"\n{'='*60}")
        print(f"🎉 COMPLETE")
        print(f"{'='*60}")
        print(f"   Account: {account_id}")
        print(f"   ⏱️  Total time: {format_duration(total_duration)}")

    else:
        # Normal mode - create new account(s)
        print(f"\n{'='*60}")
        print("📋 List existing pool accounts")
        print("=" * 60)
        print("Fetching accounts from AWS Organizations...")
        all_accounts = get_all_accounts(session)

        # Filter accounts starting with 'pool-'
        pool_accounts = [
            acc for acc in all_accounts
            if acc['Name'].startswith('pool-')
        ]

        print(f"\n📊 Found {len(pool_accounts)} accounts starting with 'pool-':\n")
        print(f"{'Account ID':<15} {'Name':<40} {'Status':<12} {'Email'}")
        print("-" * 100)

        for acc in sorted(pool_accounts, key=lambda x: x['Name']):
            print(f"{acc['Id']:<15} {acc['Name']:<40} {acc['Status']:<12} {acc['Email']}")

        print(f"\n   Total: {len(pool_accounts)} pool accounts")

        # Calculate next pool number(s)
        next_number = get_next_pool_number(pool_accounts)

        # Build list of accounts to create
        accounts_to_create = []
        for i in range(args.num):
            num = next_number + i
            name = f"pool-{num:03d}"
            email = f"ndx-try-provider+gds-ndx-try-aws-{name}@dsit.gov.uk"
            accounts_to_create.append((name, email))

        if args.num == 1:
            # Single account - provision directly (no label prefix)
            name, email = accounts_to_create[0]
            result = provision_account(session, name, email)
            results = [result]
        else:
            # Multiple accounts - provision in parallel
            print(f"\n{'='*60}")
            print(f"🚀 Creating {args.num} accounts in parallel")
            print(f"{'='*60}")
            for name, email in accounts_to_create:
                print(f"   {name} ({email})")

            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.num) as executor:
                futures = {}
                for name, email in accounts_to_create:
                    # Each thread gets its own boto3 session for thread safety
                    thread_session = boto3.Session(profile_name='NDX/orgManagement')
                    future = executor.submit(
                        provision_account, thread_session, name, email, label=f"[{name}]"
                    )
                    futures[future] = name

                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())

        # Summary
        end_time = time.time()
        total_duration = end_time - start_time

        print(f"\n{'='*60}")
        print(f"🎉 COMPLETE")
        print(f"{'='*60}")
        succeeded = 0
        failed = 0
        for name, account_id in sorted(results):
            if account_id:
                print(f"   ✅ {name}: {account_id}")
                succeeded += 1
            else:
                print(f"   ❌ {name}: FAILED")
                failed += 1
        if args.num > 1:
            print(f"\n   📊 {succeeded}/{args.num} succeeded", end="")
            if failed:
                print(f", {failed} failed", end="")
            print()
        print(f"   ⏱️  Total time: {format_duration(total_duration)}")


if __name__ == '__main__':
    main()
