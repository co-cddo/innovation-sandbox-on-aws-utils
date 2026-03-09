#!/usr/bin/env python3
"""
Force-release quarantined Innovation Sandbox accounts.

Tags accounts with 'do-not-separate', moves them from Quarantine to Entry OU,
and re-registers with the ISB API to trigger a cleanup retry.

Uses the NDX/orgManagement profile for Organizations API.
Uses NDX/InnovationSandboxHub profile for Secrets Manager + ISB API.

Usage:
  ./force_release_account.py 123456789012
  ./force_release_account.py 123456789012 987654321098
  ./force_release_account.py --all
"""

import argparse
import json
import sys

import boto3

from isb_common import (
    ORG_PROFILE,
    ISB_HUB_PROFILE,
    ensure_sso_login,
    get_signed_token,
    make_isb_api_request,
)

POOL_OU = "ou-2laj-4dyae1oa"
ACTIVE_OU = "ou-2laj-sre4rnjs"


# ── Account operations ───────────────────────────────────────────────────────

def list_pool_accounts(org_client, parent_ou=POOL_OU, exclude_ous=None):
    """Recursively list all accounts under the pool OU, excluding specified OUs."""
    if exclude_ous is None:
        exclude_ous = {ACTIVE_OU}

    if parent_ou in exclude_ous:
        return []

    accounts = []

    # List accounts directly in this OU
    paginator = org_client.get_paginator("list_accounts_for_parent")
    for page in paginator.paginate(ParentId=parent_ou):
        accounts.extend(page["Accounts"])

    # Recurse into child OUs
    ou_paginator = org_client.get_paginator("list_organizational_units_for_parent")
    for page in ou_paginator.paginate(ParentId=parent_ou):
        for child_ou in page["OrganizationalUnits"]:
            accounts.extend(list_pool_accounts(org_client, child_ou["Id"], exclude_ous))

    return accounts


def tag_account(org_client, account_id):
    """Tag an account with do-not-separate."""
    org_client.tag_resource(
        ResourceId=account_id,
        Tags=[{"Key": "do-not-separate", "Value": ""}],
    )


def retry_cleanup(token, account_id):
    """Trigger a cleanup retry for an account via the ISB API."""
    return make_isb_api_request("POST", f"/accounts/{account_id}/retryCleanup", token)


def process_account(org_client, token, account_id, name=""):
    """Force-release a single account: tag and trigger cleanup retry."""
    label = f"{account_id} ({name})" if name else account_id
    print(f"\n  ── {label} ──")

    # Tag
    print(f"  🏷️  Tagging do-not-separate...", end="", flush=True)
    try:
        tag_account(org_client, account_id)
        print(f"\r  🏷️  Tagged do-not-separate    ")
    except Exception as e:
        print(f"\r  ❌ Tag failed: {e}         ")
        return False

    # Trigger cleanup retry
    print(f"  🔄 Triggering cleanup...", end="", flush=True)
    status, body = retry_cleanup(token, account_id)
    if status == 200:
        print(f"\r  🔄 Cleanup triggered      ")
        return True
    else:
        errors = body.get("data", body).get("errors", [])
        msg = errors[0].get("message", str(body)) if errors else str(body)
        print(f"\r  ❌ Cleanup retry failed (HTTP {status}): {msg}")
        return False


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Force-release quarantined Innovation Sandbox accounts"
    )
    parser.add_argument(
        "account_ids",
        nargs="*",
        help="AWS account ID(s) to force-release",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Process all quarantined accounts",
    )
    args = parser.parse_args()

    if not args.all and not args.account_ids:
        parser.error("provide one or more account IDs, or use --all")

    # ── Step 1: SSO Authentication ───────────────────────────────────────
    print("=" * 60)
    print("🔑 STEP 1: AWS SSO Authentication")
    print("=" * 60)
    ensure_sso_login(ORG_PROFILE)
    ensure_sso_login(ISB_HUB_PROFILE)

    org_session = boto3.Session(profile_name=ORG_PROFILE)
    org_client = org_session.client("organizations")

    hub_session = boto3.Session(profile_name=ISB_HUB_PROFILE)

    # ── Step 2: Sign JWT ─────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("🔑 STEP 2: Sign JWT")
    print("=" * 60)
    print("  🔑 Fetching JWT secret...")
    token = get_signed_token(hub_session)
    print("  ✅ JWT signed")

    # ── Step 3: Resolve accounts ─────────────────────────────────────────
    print(f"\n{'='*60}")
    print("📋 STEP 3: Resolve accounts")
    print("=" * 60)

    if args.all:
        print("  🔍 Listing accounts in pool OU (excluding Active)...")
        pool_accounts = list_pool_accounts(org_client)
        if not pool_accounts:
            print("  ℹ️  No accounts found")
            sys.exit(0)
        accounts = [(a["Id"], a.get("Name", "")) for a in pool_accounts]
        print(f"  📊 Found {len(accounts)} account(s):")
        for account_id, name in accounts:
            print(f"     {account_id} {name}")
    else:
        accounts = [(aid, "") for aid in args.account_ids]
        print(f"  📋 {len(accounts)} account(s) specified")

    # ── Step 4: Process accounts ─────────────────────────────────────────
    print(f"\n{'='*60}")
    print("🔄 STEP 4: Force-release accounts")
    print("=" * 60)

    succeeded = 0
    failed = 0

    for account_id, name in accounts:
        if process_account(org_client, token, account_id, name):
            succeeded += 1
        else:
            failed += 1

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("📊 Summary")
    print("=" * 60)
    print(f"  Succeeded: {succeeded}")
    print(f"  Failed:    {failed}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
