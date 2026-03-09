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
import concurrent.futures
import json
import os
import random
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import boto3
import botocore.exceptions

from isb_common import (
    SSO_START_URL,
    check_sso_token_valid,
    ensure_sso_login,
    sign_jwt,
    fetch_jwt_secret,
    format_duration,
)

# Target OU where Innovation Sandbox moves accounts after cleanup
SANDBOX_READY_OU = "ou-2laj-oihxgbtr"
ENTRY_OU = "ou-2laj-2by9v0sr"

POOL_OUS = {
    "Active":     "ou-2laj-sre4rnjs",
    "Available":  "ou-2laj-oihxgbtr",
    "CleanUp":    "ou-2laj-x3o8lbk8",
    "Entry":      "ou-2laj-2by9v0sr",
    "Exit":       "ou-2laj-s1t02mrz",
    "Frozen":     "ou-2laj-jpffue7g",
    "Quarantine": "ou-2laj-mmagoake",
}
ROOT_ID = None  # Will be populated at runtime
_root_id_lock = threading.Lock()

# StackSet that deploys SandboxAccountRole into pool accounts
SANDBOX_STACKSET_NAME = "Isb-ndx-SandboxAccountResources"

# Custom billing view ARN for tracking pool account costs
BILLING_VIEW_ARN = "arn:aws:billing::955063685555:billingview/custom-466e2613-e09b-4787-a93a-736f0fb1564b"

# Lock for billing view read-modify-write operations
_billing_lock = threading.Lock()

# Thread-safe SSO token refresh coordination
_sso_refresh_lock = threading.Lock()

# Auth error codes that indicate SSO token expiry
AUTH_ERROR_CODES = {
    'ExpiredTokenException',
    'UnauthorizedSSOTokenError',
    'InvalidIdentityToken',
}


# ── Thread-safe SSO session management ────────────────────────────────────────

def wait_for_sso_refresh(profile_name):
    """Thread-safe SSO token refresh. Only one thread triggers login; others wait."""
    with _sso_refresh_lock:
        # After acquiring lock, check if another thread already refreshed
        if check_sso_token_valid():
            return True

        print(f"\n{'='*60}")
        print(f"🔐 SSO token expired — please re-authenticate in your browser...")
        print(f"{'='*60}")

        subprocess.run(
            ["aws", "sso", "login", "--profile", profile_name],
            capture_output=False,
        )

        # Poll until valid (max 5 minutes)
        deadline = time.time() + 300
        while time.time() < deadline:
            if check_sso_token_valid():
                print("   ✅ SSO token refreshed successfully")
                return True
            time.sleep(3)

        raise RuntimeError("SSO token refresh timed out after 5 minutes")


def ensure_session(profile_name):
    """Get a boto3 session, refreshing SSO token if needed."""
    if not check_sso_token_valid():
        wait_for_sso_refresh(profile_name)
    return boto3.Session(profile_name=profile_name)


# ── Account operations ───────────────────────────────────────────────────────

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


def _retry_with_backoff(func, label="", max_retries=8, base_delay=2, profile_name=None):
    """Call func() with exponential backoff on throttling, with SSO token refresh on auth errors."""
    p = f"{label} " if label else ""
    attempt = 0
    auth_retries = 0
    while True:
        try:
            return func()
        except (botocore.exceptions.SSOTokenLoadError, botocore.exceptions.UnauthorizedSSOTokenError) as e:
            if profile_name and auth_retries < 3:
                auth_retries += 1
                print(f"\r{p}   🔐 SSO token error, refreshing...", flush=True)
                wait_for_sso_refresh(profile_name)
                continue
            raise
        except Exception as e:
            error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')

            if error_code in AUTH_ERROR_CODES and profile_name and auth_retries < 3:
                auth_retries += 1
                print(f"\r{p}   🔐 SSO token error ({error_code}), refreshing...", flush=True)
                wait_for_sso_refresh(profile_name)
                continue

            if error_code in ('TooManyRequestsException', 'Throttling', 'ConcurrentModificationException') and attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                print(f"\r{p}   ⏳ Rate limited, retrying in {delay:.0f}s (attempt {attempt + 1}/{max_retries})...", end="", flush=True)
                time.sleep(delay)
                attempt += 1
                continue

            raise


def create_pool_account(session, account_name, email, label="", profile_name=None):
    """Create a new AWS account in the organization."""
    p = f"{label} " if label else ""
    client = session.client('organizations')

    response = _retry_with_backoff(
        lambda: client.create_account(Email=email, AccountName=account_name),
        label=label,
        profile_name=profile_name,
    )

    request_id = response['CreateAccountStatus']['Id']
    print(f"{p}   Request ID: {request_id}")

    # Poll for completion
    while True:
        status_response = _retry_with_backoff(
            lambda: client.describe_create_account_status(CreateAccountRequestId=request_id),
            label=label,
            profile_name=profile_name,
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


def move_account_to_ou(session, account_id, destination_ou_id, source_parent_id=None, label="", profile_name=None):
    """Move an account to a specific OU."""
    p = f"{label} " if label else ""
    client = session.client('organizations')

    # If source not provided, get current parent
    if source_parent_id is None:
        source_parent_id = get_account_ou(session, account_id, profile_name=profile_name)

    print(f"{p}   📍 From: {source_parent_id}")
    print(f"{p}   📍 To:   {destination_ou_id}")

    _retry_with_backoff(
        lambda: client.move_account(
            AccountId=account_id,
            SourceParentId=source_parent_id,
            DestinationParentId=destination_ou_id,
        ),
        label=label,
        profile_name=profile_name,
    )

    print(f"{p}   ✅ Move complete")


def get_account_ou(session, account_id, label="", profile_name=None):
    """Get the OU that an account is currently in."""
    client = session.client('organizations')
    response = _retry_with_backoff(
        lambda: client.list_parents(ChildId=account_id),
        label=label,
        profile_name=profile_name,
    )
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


def wait_for_stackset_role(session, account_id, check_interval=10, max_wait=300, label="", profile_name=None):
    """Wait for the SandboxAccountResources StackSet to deploy to an account.

    The StackSet auto-deploys when accounts enter the pool OU (which contains
    Entry OU). This function polls until the stack instance reaches CURRENT
    status, meaning the SandboxAccountRole is ready.

    The account must already be in the Entry OU (or another child of the pool
    OU) before calling this function.
    """
    p = f"{label} " if label else ""
    cf = session.client('cloudformation')

    waited = 0
    while waited < max_wait:
        try:
            response = cf.list_stack_instances(
                StackSetName=SANDBOX_STACKSET_NAME,
                StackInstanceAccount=account_id,
            )
            instances = response.get('Summaries', [])
            if instances:
                inst = instances[0]
                status = inst['Status']
                if status == 'CURRENT':
                    print(f"\r{p}   ✅ StackSet deployed (SandboxAccountRole ready){' ' * 20}")
                    return True
                print(f"\r{p}   ⏳ StackSet status: {status} | Elapsed: {format_duration(waited)}", end="", flush=True)
            else:
                print(f"\r{p}   ⏳ Waiting for StackSet instance... | Elapsed: {format_duration(waited)}", end="", flush=True)
        except (botocore.exceptions.SSOTokenLoadError, botocore.exceptions.UnauthorizedSSOTokenError):
            if profile_name:
                print(f"\r{p}   🔐 SSO token error, refreshing...", flush=True)
                wait_for_sso_refresh(profile_name)
                session = ensure_session(profile_name)
                cf = session.client('cloudformation')
                continue
            raise
        except Exception as e:
            error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
            if error_code in AUTH_ERROR_CODES and profile_name:
                print(f"\r{p}   🔐 SSO token error ({error_code}), refreshing...", flush=True)
                wait_for_sso_refresh(profile_name)
                session = ensure_session(profile_name)
                cf = session.client('cloudformation')
                continue
            print(f"\r{p}   ⏳ Waiting for StackSet... ({e}) | Elapsed: {format_duration(waited)}", end="", flush=True)

        time.sleep(check_interval)
        waited += check_interval

    print(f"\r{p}   ❌ Timeout waiting for StackSet deployment after {format_duration(max_wait)}{' ' * 20}")
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


def wait_for_ou_move(session, account_id, target_ou, check_interval=5, max_wait=3600, label="", profile_name=None):
    """Wait for an account to be moved to the target OU.

    Args:
        session: boto3 session
        account_id: AWS account ID to monitor
        target_ou: Target OU ID to wait for
        check_interval: Seconds between checks (default 5)
        max_wait: Maximum seconds to wait (default 3600 = 1 hour)
        label: Optional prefix for log output
        profile_name: Optional AWS profile for SSO token refresh
    """
    p = f"{label} " if label else ""
    print(f"{p}⏳ Waiting for Innovation Sandbox cleanup...")
    print(f"{p}   Target OU: {target_ou}")

    waited = 0
    while waited < max_wait:
        current_ou = get_account_ou(session, account_id, label=label, profile_name=profile_name)
        if current_ou == target_ou:
            print(f"\r{p}   ✅ Account moved to target OU after {format_duration(waited)}!{' ' * 20}")
            return True

        # Update single line with carriage return
        print(f"\r{p}   ⏳ Current OU: {current_ou} | Elapsed: {format_duration(waited)}", end="", flush=True)
        time.sleep(check_interval)
        waited += check_interval

    print(f"\r{p}   ❌ Timeout after {format_duration(max_wait)}{' ' * 30}")
    return False


def register_with_innovation_sandbox(account_id, api_base_url, jwt_secret, label=""):
    """Register the account with Innovation Sandbox via API Gateway."""
    p = f"{label} " if label else ""

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


def print_pool_summary(session):
    """Print account counts for each OU in the sandbox pool."""
    client = session.client('organizations')
    total = 0
    for name, ou_id in POOL_OUS.items():
        count = 0
        paginator = client.get_paginator('list_accounts_for_parent')
        for page in paginator.paginate(ParentId=ou_id):
            count += len(page['Accounts'])
        total += count
        print(f"   {name:<12} {count:>3}")
    print(f"   {'Total':<12} {total:>3}")


def deploy_scps():
    """Dispatch the SCP Terraform workflow and wait for completion.

    Triggers the terraform.yaml workflow in co-cddo/ndx-try-aws-scp with
    action=apply to update SCPs for any new pool accounts.
    """
    repo = "co-cddo/ndx-try-aws-scp"
    workflow = "terraform.yaml"

    # Get latest run ID before dispatch so we can find the new one
    result = subprocess.run(
        ["gh", "run", "list", "-R", repo, "-w", workflow, "-L", "1",
         "--json", "databaseId"],
        capture_output=True, text=True,
    )
    prev_run_id = 0
    if result.returncode == 0:
        runs = json.loads(result.stdout)
        if runs:
            prev_run_id = runs[0]["databaseId"]

    # Dispatch the workflow
    print("   🚀 Dispatching SCP deployment...")
    result = subprocess.run(
        ["gh", "workflow", "run", workflow, "-R", repo, "-f", "action=apply"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"   ❌ Failed to dispatch workflow: {result.stderr.strip()}")
        return False

    # Poll for the new run to appear
    print("   ⏳ Waiting for workflow run to start...")
    run_id = None
    for _ in range(30):
        time.sleep(2)
        result = subprocess.run(
            ["gh", "run", "list", "-R", repo, "-w", workflow, "-L", "1",
             "--json", "databaseId,status"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            runs = json.loads(result.stdout)
            if runs and runs[0]["databaseId"] > prev_run_id:
                run_id = runs[0]["databaseId"]
                break

    if not run_id:
        print("   ❌ Could not find workflow run after dispatch")
        return False

    print(f"   📋 Run ID: {run_id}")
    print(f"   🔗 https://github.com/{repo}/actions/runs/{run_id}")

    # Poll until complete, auto-approving environment gates
    approved = False
    while True:
        result = subprocess.run(
            ["gh", "run", "view", str(run_id), "-R", repo,
             "--json", "status,conclusion,jobs"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            time.sleep(10)
            continue

        run_info = json.loads(result.stdout)
        status = run_info["status"]
        conclusion = run_info.get("conclusion", "")

        if status == "completed":
            if conclusion == "success":
                print(f"\r   ✅ SCP deployment completed successfully!{' ' * 20}")
                return True
            else:
                print(f"\r   ❌ SCP deployment failed: {conclusion}{' ' * 20}")
                return False

        # Check if any job is waiting for environment approval
        if not approved:
            waiting_jobs = [
                j for j in run_info.get("jobs", [])
                if j.get("status") == "waiting"
            ]
            if waiting_jobs:
                print("\r   🔓 Approving environment deployment...", end="", flush=True)
                dep_result = subprocess.run(
                    ["gh", "api",
                     f"repos/{repo}/actions/runs/{run_id}/pending_deployments",
                     "--jq", ".[].environment.id"],
                    capture_output=True, text=True,
                )
                if dep_result.returncode == 0 and dep_result.stdout.strip():
                    env_id = int(dep_result.stdout.strip())
                    approve_result = subprocess.run(
                        ["gh", "api",
                         f"repos/{repo}/actions/runs/{run_id}/pending_deployments",
                         "-X", "POST", "--input", "-"],
                        input=json.dumps({
                            "environment_ids": [env_id],
                            "state": "approved",
                            "comment": "Auto-approved by pool account provisioning",
                        }),
                        capture_output=True, text=True,
                    )
                    if approve_result.returncode == 0:
                        print(f"\r   ✅ Environment approved{' ' * 30}")
                        approved = True
                    else:
                        print(f"\r   ⚠️  Approval failed: {approve_result.stderr.strip()}{' ' * 20}")

        print(f"\r   ⏳ {status}...", end="", flush=True)
        time.sleep(10)


def recover_account(session, account_id, profile_name=None):
    """Recover a partially provisioned account by moving it to Entry OU.

    Moves the account to Entry OU from wherever it currently is. This
    triggers StackSet auto-deployment of the SandboxAccountRole.
    """
    current_ou = get_account_ou(session, account_id, profile_name=profile_name)

    print(f"   📍 Current location: {current_ou}")

    if current_ou == ENTRY_OU:
        print("   ℹ️  Account is already in Entry OU")
    else:
        print(f"\n{'='*60}")
        print(f"📦 Moving to Entry OU")
        print(f"{'='*60}")
        move_account_to_ou(session, account_id, ENTRY_OU, source_parent_id=current_ou, profile_name=profile_name)


def provision_account(profile_name, account_name, email, api_base_url, jwt_secret, label=""):
    """Provision a single pool account: create, move, tag, register, and wait.

    Uses ensure_session() at each major step so credentials are refreshed
    automatically if the SSO token expires during long-running provisioning.

    Returns (account_name, account_id) on success, (account_name, None) on failure.
    """
    p = f"{label} " if label else ""

    try:
        print(f"\n{p}{'='*60}")
        print(f"{p}🆕 Create account: {account_name}")
        print(f"{p}{'='*60}")
        print(f"{p}   Account name: {account_name}")
        print(f"{p}   Email: {email}")

        session = ensure_session(profile_name)
        account_id = create_pool_account(session, account_name, email, label=label, profile_name=profile_name)
        if not account_id:
            print(f"\n{p}❌ Account creation failed for {account_name}")
            return (account_name, None)

        print(f"\n{p}{'='*60}")
        print(f"{p}📦 Move to Entry OU: {account_name}")
        print(f"{p}{'='*60}")
        session = ensure_session(profile_name)
        root_id = get_root_id(session)
        move_account_to_ou(session, account_id, ENTRY_OU, source_parent_id=root_id, label=label, profile_name=profile_name)

        print(f"\n{p}{'='*60}")
        print(f"{p}⏳ Wait for SandboxAccountRole (StackSet): {account_name}")
        print(f"{p}{'='*60}")
        session = ensure_session(profile_name)
        if not wait_for_stackset_role(session, account_id, label=label, profile_name=profile_name):
            print(f"\n{p}❌ StackSet deployment timed out for {account_name}")
            return (account_name, None)

        print(f"\n{p}{'='*60}")
        print(f"{p}💰 Add to Billing View: {account_name}")
        print(f"{p}{'='*60}")
        session = ensure_session(profile_name)
        with _billing_lock:
            add_account_to_billing_view(session, account_id, label=label)

        print(f"\n{p}{'='*60}")
        print(f"{p}🏷️  Tag Account: {account_name}")
        print(f"{p}{'='*60}")
        session = ensure_session(profile_name)
        tag_account(session, account_id, label=label)

        print(f"\n{p}{'='*60}")
        print(f"{p}📝 Register with Innovation Sandbox: {account_name}")
        print(f"{p}{'='*60}")
        register_with_innovation_sandbox(account_id, api_base_url, jwt_secret, label=label)

        print(f"\n{p}{'='*60}")
        print(f"{p}🧹 Wait for cleanup: {account_name}")
        print(f"{p}{'='*60}")
        session = ensure_session(profile_name)
        wait_for_ou_move(session, account_id, SANDBOX_READY_OU, label=label, profile_name=profile_name)

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

    org_profile = 'NDX/orgManagement'
    hub_profile = 'NDX/InnovationSandboxHub'

    # Create initial session (will be refreshed via ensure_session as needed)
    session = ensure_session(org_profile)

    # Pre-fetch ISB registration config (shared across all threads)
    api_base_url = os.environ.get("ISB_API_BASE_URL")
    jwt_secret_path = os.environ.get("ISB_JWT_SECRET_PATH")
    if not api_base_url or not jwt_secret_path:
        print("❌ ISB_API_BASE_URL and ISB_JWT_SECRET_PATH environment variables must be set")
        sys.exit(1)

    hub_session = ensure_session(hub_profile)
    print("\n🔑 Fetching JWT secret...")
    jwt_secret = fetch_jwt_secret(hub_session, jwt_secret_path)
    print("   ✅ JWT secret ready")

    if args.account_id:
        # Recovery mode - fix a partially provisioned account
        account_id = args.account_id
        print(f"\n{'='*60}")
        print(f"🔧 RECOVERY MODE: Processing existing account {account_id}")
        print(f"{'='*60}")

        session = ensure_session(org_profile)
        recover_account(session, account_id, profile_name=org_profile)

        print(f"\n{'='*60}")
        print(f"⏳ Wait for SandboxAccountRole (StackSet)")
        print(f"{'='*60}")
        session = ensure_session(org_profile)
        if not wait_for_stackset_role(session, account_id, profile_name=org_profile):
            print("\n❌ StackSet deployment timed out - exiting")
            sys.exit(1)

        # Add to billing view for recovered accounts
        print(f"\n{'='*60}")
        print(f"💰 Add to Billing View")
        print(f"{'='*60}")
        session = ensure_session(org_profile)
        add_account_to_billing_view(session, account_id)

        print(f"\n{'='*60}")
        print(f"🏷️  Tag Account")
        print(f"{'='*60}")
        session = ensure_session(org_profile)
        tag_account(session, account_id)

        print(f"\n{'='*60}")
        print(f"📝 Register with Innovation Sandbox")
        print(f"{'='*60}")
        register_with_innovation_sandbox(account_id, api_base_url, jwt_secret)

        print(f"\n{'='*60}")
        print(f"🧹 Wait for Innovation Sandbox cleanup")
        print(f"{'='*60}")
        session = ensure_session(org_profile)
        wait_for_ou_move(session, account_id, SANDBOX_READY_OU, profile_name=org_profile)

        print(f"\n{'='*60}")
        print(f"🛡️  Deploy SCPs")
        print(f"{'='*60}")
        deploy_scps()

        end_time = time.time()
        total_duration = end_time - start_time

        print(f"\n{'='*60}")
        print(f"🎉 COMPLETE")
        print(f"{'='*60}")
        print(f"   Account: {account_id}")
        print(f"   ⏱️  Total time: {format_duration(total_duration)}")

        print(f"\n{'='*60}")
        print(f"📊 Pool account summary")
        print(f"{'='*60}")
        session = ensure_session(org_profile)
        print_pool_summary(session)

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
            result = provision_account(org_profile, name, email, api_base_url, jwt_secret)
            results = [result]
        else:
            # Multiple accounts - provision in parallel
            print(f"\n{'='*60}")
            print(f"🚀 Creating {args.num} accounts in parallel")
            print(f"{'='*60}")
            for name, email in accounts_to_create:
                print(f"   {name} ({email})")

            results = []
            max_parallel = min(args.num, 5)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_parallel) as executor:
                futures = {}
                for i, (name, email) in enumerate(accounts_to_create):
                    # Stagger submissions to avoid Organizations API rate limits
                    if i > 0:
                        time.sleep(5)
                    # Each thread calls ensure_session() internally for thread safety
                    future = executor.submit(
                        provision_account, org_profile, name, email,
                        api_base_url, jwt_secret, label=f"[{name}]"
                    )
                    futures[future] = name

                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())

        # Deploy SCPs if any accounts succeeded
        succeeded = sum(1 for _, aid in results if aid)
        if succeeded > 0:
            print(f"\n{'='*60}")
            print(f"🛡️  Deploy SCPs")
            print(f"{'='*60}")
            deploy_scps()

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

        print(f"\n{'='*60}")
        print(f"📊 Pool account summary")
        print(f"{'='*60}")
        session = ensure_session(org_profile)
        print_pool_summary(session)


if __name__ == '__main__':
    main()
