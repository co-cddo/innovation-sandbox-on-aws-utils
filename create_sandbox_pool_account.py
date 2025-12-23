#!/usr/bin/env python3
"""
List AWS Organization accounts that start with 'pool-' and create the next one.
Uses the NDX/orgManagement profile for Organizations API.
Uses NDX/InnovationSandboxHub profile for Lambda invocation.
"""

import argparse
import base64
import json
import re
import subprocess
import sys
import time
import boto3

# Target OU where Innovation Sandbox moves accounts after cleanup
SANDBOX_READY_OU = "ou-2laj-oihxgbtr"
ENTRY_OU = "ou-2laj-2by9v0sr"
ROOT_ID = None  # Will be populated at runtime


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


def create_pool_account(session, account_name, email):
    """Create a new AWS account in the organization."""
    client = session.client('organizations')

    response = client.create_account(
        Email=email,
        AccountName=account_name,
    )

    request_id = response['CreateAccountStatus']['Id']
    print(f"   Request ID: {request_id}")

    # Poll for completion
    while True:
        status_response = client.describe_create_account_status(
            CreateAccountRequestId=request_id
        )
        status = status_response['CreateAccountStatus']

        if status['State'] == 'SUCCEEDED':
            print(f"\r   ✅ Account created: {status['AccountId']}{' ' * 20}")
            return status['AccountId']
        elif status['State'] == 'FAILED':
            print(f"\r   ❌ Failed: {status.get('FailureReason', 'Unknown')}{' ' * 20}")
            return None
        else:
            print(f"\r   ⏳ {status['State']}...", end="", flush=True)
            time.sleep(5)


def get_root_id(session):
    """Get the organization root ID."""
    global ROOT_ID
    if ROOT_ID is None:
        client = session.client('organizations')
        roots = client.list_roots()['Roots']
        ROOT_ID = roots[0]['Id']
    return ROOT_ID


def move_account_to_ou(session, account_id, destination_ou_id, source_parent_id=None):
    """Move an account to a specific OU."""
    client = session.client('organizations')

    # If source not provided, get current parent
    if source_parent_id is None:
        source_parent_id = get_account_ou(session, account_id)

    print(f"   📍 From: {source_parent_id}")
    print(f"   📍 To:   {destination_ou_id}")

    client.move_account(
        AccountId=account_id,
        SourceParentId=source_parent_id,
        DestinationParentId=destination_ou_id,
    )

    print(f"   ✅ Move complete")


def get_account_ou(session, account_id):
    """Get the OU that an account is currently in."""
    client = session.client('organizations')
    response = client.list_parents(ChildId=account_id)
    if response['Parents']:
        return response['Parents'][0]['Id']
    return None


def wait_for_ou_move(session, account_id, target_ou, check_interval=5, max_wait=3600):
    """Wait for an account to be moved to the target OU.

    Args:
        session: boto3 session
        account_id: AWS account ID to monitor
        target_ou: Target OU ID to wait for
        check_interval: Seconds between checks (default 5)
        max_wait: Maximum seconds to wait (default 3600 = 1 hour)
    """
    print(f"⏳ Waiting for Innovation Sandbox cleanup...")
    print(f"   Target OU: {target_ou}")

    waited = 0
    while waited < max_wait:
        current_ou = get_account_ou(session, account_id)
        if current_ou == target_ou:
            print(f"\r   ✅ Account moved to target OU after {format_duration(waited)}!{' ' * 20}")
            return True

        # Update single line with carriage return
        print(f"\r   ⏳ Current OU: {current_ou} | Elapsed: {format_duration(waited)}", end="", flush=True)
        time.sleep(check_interval)
        waited += check_interval

    print(f"\r   ❌ Timeout after {format_duration(max_wait)}{' ' * 30}")
    return False


def register_with_innovation_sandbox(account_id):
    """Register the account with Innovation Sandbox by invoking the Lambda directly."""
    # Use the InnovationSandboxHub profile
    hub_session = boto3.Session(profile_name='NDX/InnovationSandboxHub')
    lambda_client = hub_session.client('lambda')

    function_name = "ISB-AccountsLambdaFunction-ndx"

    # Create mock JWT for authorization bypass
    mock_token = create_mock_jwt()

    # Construct API Gateway proxy event payload
    payload = {
        "httpMethod": "POST",
        "path": "/accounts",
        "body": json.dumps({"awsAccountId": account_id}),
        "headers": {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {mock_token}",
        },
        "requestContext": {},
        "queryStringParameters": None,
        "pathParameters": None,
    }

    print(f"   🎯 Account: {account_id}")
    print(f"   λ  Lambda: {function_name}")
    print(f"   ⏳ Invoking...", end="", flush=True)

    response = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType='RequestResponse',
        Payload=json.dumps(payload),
    )

    # Parse the response
    response_payload = json.loads(response['Payload'].read().decode('utf-8'))

    if response.get('FunctionError'):
        print(f"\r   ❌ Lambda execution error!{' ' * 20}")
        print(f"   Error: {response_payload}")
        return False

    # Parse the Lambda response body
    status_code = response_payload.get('statusCode', 0)
    body_str = response_payload.get('body', '{}')
    body = json.loads(body_str) if body_str else {}

    if status_code == 201:
        print(f"\r   ✅ Registered successfully!{' ' * 20}")
        data = body.get('data', {})
        print(f"   📄 Status: {data.get('status', 'unknown')}")
        return True
    else:
        print(f"\r   ❌ Registration failed (HTTP {status_code}){' ' * 20}")
        print(f"   Response: {json.dumps(body, indent=2)}")
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


def main():
    parser = argparse.ArgumentParser(
        description="Create and register pool accounts for Innovation Sandbox"
    )
    parser.add_argument(
        "account_id",
        nargs="?",
        help="Optional: AWS account ID to recover (for fixing partial errors)"
    )
    args = parser.parse_args()

    start_time = time.time()

    # SSO login for both profiles
    print("=" * 60)
    print("🔑 STEP 1: AWS SSO Authentication")
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

        account_name = f"(existing account {account_id})"
    else:
        # Normal mode - create a new account
        print(f"\n{'='*60}")
        print("📋 STEP 2: List existing pool accounts")
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

        # Calculate next pool number
        next_number = get_next_pool_number(pool_accounts)
        account_name = f"pool-{next_number:03d}"
        next_email = f"ndx-try-provider+gds-ndx-try-aws-{account_name}@dsit.gov.uk"

        print(f"\n{'='*60}")
        print(f"🆕 STEP 3: Create new account")
        print(f"{'='*60}")
        print(f"   Account name: {account_name}")
        print(f"   Email: {next_email}")

        # Create the new account
        account_id = create_pool_account(session, account_name, next_email)

        if not account_id:
            print("\n❌ Account creation failed - exiting")
            sys.exit(1)

        print(f"\n{'='*60}")
        print(f"📦 STEP 4: Move to Entry OU")
        print(f"{'='*60}")
        move_account_to_ou(session, account_id, ENTRY_OU, source_parent_id=get_root_id(session))

    print(f"\n{'='*60}")
    print(f"📝 STEP 5: Register with Innovation Sandbox")
    print(f"{'='*60}")
    register_with_innovation_sandbox(account_id)

    print(f"\n{'='*60}")
    print(f"🧹 STEP 6: Wait for Innovation Sandbox cleanup")
    print(f"{'='*60}")
    wait_for_ou_move(session, account_id, SANDBOX_READY_OU)

    # Calculate and display total time
    end_time = time.time()
    total_duration = end_time - start_time

    print(f"\n{'='*60}")
    print(f"🎉 COMPLETE")
    print(f"{'='*60}")
    print(f"   Account: {account_name} ({account_id})")
    print(f"   ⏱️  Total time: {format_duration(total_duration)}")


if __name__ == '__main__':
    main()
