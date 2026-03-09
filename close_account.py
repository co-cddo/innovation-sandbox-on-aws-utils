#!/usr/bin/env python3
"""
Eject and close Innovation Sandbox accounts permanently.

Decommissions quarantined ISB accounts (where aws-nuke cleanup failed) by:
  1. Ejecting from ISB (deletes ISB's record and moves account to Exit OU)
  2. Closing the AWS account via Organizations API

Supports two modes:
  - Explicit: close specific account IDs
  - Quarantined: auto-discover and close accounts quarantined for >2 days

Uses the NDX/orgManagement profile for Organizations API.
Uses NDX/InnovationSandboxHub profile for Secrets Manager + ISB API.

Usage:
  ./close_account.py 123456789012
  ./close_account.py 123456789012 987654321098
  ./close_account.py --quarantined
  ./close_account.py --quarantined --limit=3
  ./close_account.py --quarantined --dry-run
"""

import argparse
import sys
import time

import boto3
import botocore.exceptions

from isb_common import (
    ORG_PROFILE,
    ISB_HUB_PROFILE,
    ensure_sso_login,
    get_signed_token,
    make_isb_api_request,
    format_duration,
)

from create_sandbox_pool_account import (
    ensure_session,
    wait_for_ou_move,
    POOL_OUS,
)

from clean_console_state import (
    list_accounts_in_ou,
)

from datetime import datetime, timezone

# ── Constants ────────────────────────────────────────────────────────────────

EXIT_OU = POOL_OUS["Exit"]            # ou-2laj-s1t02mrz
QUARANTINE_OU = POOL_OUS["Quarantine"]  # ou-2laj-mmagoake
QUARANTINE_AGE_DAYS = 2


# ── Lease query ───────────────────────────────────────────────────────────────

def get_leases(token):
    """Fetch all leases via the ISB API using a signed token."""
    status, body = make_isb_api_request("GET", "/leases", token)
    if status != 200:
        raise RuntimeError(f"ISB leases API returned HTTP {status}: {body}")
    return body


# ── Account operations ───────────────────────────────────────────────────────

def eject_account(token, account_id):
    """Eject an account from ISB via the API.

    Returns (ok, skipped, msg).
    - ok=True: account ejected successfully
    - skipped=True: account in CleanUp state (HTTP 409)
    - both False: unexpected error
    """
    status, body = make_isb_api_request("POST", f"/accounts/{account_id}/eject", token)
    if status == 200:
        return True, False, "Ejected"
    elif status == 409:
        msg = "Account in CleanUp state — skipping eject"
        errors = body.get("data", body).get("errors", [])
        if errors:
            msg = errors[0].get("message", msg)
        return False, True, msg
    else:
        errors = body.get("data", body).get("errors", [])
        msg = errors[0].get("message", str(body)) if errors else str(body)
        return False, False, f"HTTP {status}: {msg}"


def close_aws_account(session, account_id, profile_name=None):
    """Close an AWS account via Organizations API.

    Returns (ok, quota_hit, msg).
    - ok=True: account closed
    - quota_hit=True: close quota exceeded (ConstraintViolationException)
    - both False: other error
    """
    client = session.client("organizations")
    try:
        client.close_account(AccountId=account_id)
        return True, False, "Account closed"
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        if code == "ConstraintViolationException":
            return False, True, f"Quota exceeded: {message}"
        if code == "AccountAlreadyClosedException":
            return True, False, "Account already closed"
        return False, False, f"{code}: {message}"
    except Exception as e:
        return False, False, str(e)


def wait_for_exit_ou(session, account_id, profile_name=None):
    """Wait for an account to arrive in the Exit OU after ejection."""
    return wait_for_ou_move(
        session, account_id,
        target_ou=EXIT_OU,
        check_interval=5,
        max_wait=600,
        profile_name=profile_name,
    )


def get_quarantine_ages(leases_body):
    """Extract quarantine age in days for each account from ISB lease data.

    Uses lastModifiedDate (reflects lease termination time, best proxy for
    quarantine entry) falling back to createdDate.

    Returns {account_id: age_in_days}.
    """
    # Extract leases list from response
    leases = []
    if isinstance(leases_body, list):
        leases = leases_body
    elif isinstance(leases_body, dict):
        data = leases_body.get("data", leases_body)
        if isinstance(data, list):
            leases = data
        elif isinstance(data, dict):
            for key in ("leases", "items", "results"):
                if isinstance(data.get(key), list):
                    leases = data[key]
                    break

    ages = {}
    now = datetime.now(timezone.utc)
    for lease in leases:
        if not isinstance(lease, dict):
            continue
        account_id = lease.get("accountId") or lease.get("awsAccountId", "")
        if not account_id:
            continue

        # Prefer lastModifiedDate as it reflects when the lease was terminated
        date_str = lease.get("lastModifiedDate") or lease.get("createdDate", "")
        if not date_str:
            continue

        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            age_days = (now - dt).total_seconds() / 86400
        except (ValueError, TypeError):
            continue

        # Keep the most recent date per account (multiple leases possible)
        if account_id not in ages or age_days < ages[account_id]:
            ages[account_id] = age_days

    return ages


def process_account(session, token, account_id, name, already_in_exit, dry_run, profile_name=None):
    """Orchestrate eject → wait for Exit OU → close for a single account.

    Returns "closed", "skipped", "failed", or "quota".
    """
    label = f"{account_id} ({name})" if name else account_id
    print(f"\n  ── {label} ──")

    if dry_run:
        if already_in_exit:
            print(f"  ℹ️  [DRY RUN] Would close account (already in Exit OU)")
        else:
            print(f"  ℹ️  [DRY RUN] Would eject from ISB, wait for Exit OU, then close")
        return "closed"  # count as success for dry-run summary

    # Step 1: Eject (unless already in Exit OU)
    if not already_in_exit:
        print(f"  🚀 Ejecting from ISB...", end="", flush=True)
        ok, skipped, msg = eject_account(token, account_id)
        if ok:
            print(f"\r  🚀 Ejected from ISB       ")
        elif skipped:
            print(f"\r  ⏭️  {msg}       ")
            return "skipped"
        else:
            print(f"\r  ❌ Eject failed: {msg}       ")
            return "failed"

        # Step 2: Wait for Exit OU
        print(f"  ⏳ Waiting for Exit OU...")
        session = ensure_session(profile_name or ORG_PROFILE)
        if not wait_for_exit_ou(session, account_id, profile_name=profile_name or ORG_PROFILE):
            print(f"  ❌ Timeout waiting for Exit OU")
            return "failed"
    else:
        print(f"  ℹ️  Already in Exit OU — skipping eject")

    # Step 3: Close
    print(f"  🔒 Closing account...", end="", flush=True)
    session = ensure_session(profile_name or ORG_PROFILE)
    ok, quota_hit, msg = close_aws_account(session, account_id, profile_name=profile_name or ORG_PROFILE)
    if ok:
        print(f"\r  🔒 Account closed         ")
        return "closed"
    elif quota_hit:
        print(f"\r  ⚠️  {msg}       ")
        return "quota"
    else:
        print(f"\r  ❌ Close failed: {msg}       ")
        return "failed"


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Eject and close Innovation Sandbox accounts permanently"
    )
    parser.add_argument(
        "account_ids",
        nargs="*",
        help="AWS account ID(s) to close",
    )
    parser.add_argument(
        "--quarantined", action="store_true",
        help=f"Auto-process accounts quarantined for >{QUARANTINE_AGE_DAYS} days",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Max accounts to process (with --quarantined)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview without making changes",
    )
    args = parser.parse_args()

    if not args.quarantined and not args.account_ids:
        parser.error("provide one or more account IDs, or use --quarantined")

    if args.limit is not None and not args.quarantined:
        parser.error("--limit can only be used with --quarantined")

    start_time = time.time()

    # ── Step 1: SSO Authentication ───────────────────────────────────────
    print("=" * 60)
    print("🔑 STEP 1: AWS SSO Authentication")
    print("=" * 60)
    ensure_sso_login(ORG_PROFILE)
    ensure_sso_login(ISB_HUB_PROFILE)

    org_session = boto3.Session(profile_name=ORG_PROFILE)
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

    counts = {"closed": 0, "skipped": 0, "failed": 0, "quota": 0}

    if args.quarantined:
        # ── Quarantined mode ──────────────────────────────────────────────

        # 3a: Check Exit OU for leftover accounts from previous runs
        print("  🔍 Checking Exit OU for leftover accounts...")
        exit_accounts = list_accounts_in_ou(org_session, EXIT_OU)
        if exit_accounts:
            print(f"  📦 Found {len(exit_accounts)} leftover account(s) in Exit OU:")
            for acct in exit_accounts:
                print(f"     {acct['Id']} {acct.get('Name', '')}")

            print(f"\n{'='*60}")
            print("🔒 STEP 3a: Close leftover Exit OU accounts")
            print("=" * 60)
            for acct in exit_accounts:
                result = process_account(
                    org_session, token, acct["Id"], acct.get("Name", ""),
                    already_in_exit=True, dry_run=args.dry_run,
                    profile_name=ORG_PROFILE,
                )
                counts[result] += 1
                if result == "quota":
                    print("\n  ⚠️  Close quota hit — stopping")
                    break
        else:
            print("  ✅ Exit OU is empty")

        # 3b: List Quarantine OU accounts
        print(f"\n  🔍 Listing Quarantine OU accounts...")
        quarantine_accounts = list_accounts_in_ou(org_session, QUARANTINE_OU)
        if not quarantine_accounts:
            print("  ✅ No quarantined accounts")
            if sum(counts.values()) == 0:
                print("\n  ℹ️  Nothing to do")
                sys.exit(0)
        else:
            print(f"  📦 Found {len(quarantine_accounts)} quarantined account(s)")

            # 3c: Get lease data and compute ages
            print("  📡 Querying ISB lease data...")
            ages = {}
            try:
                leases_body = get_leases(token)
                ages = get_quarantine_ages(leases_body)
                print(f"  ✅ Lease data for {len(ages)} account(s)")
            except Exception as e:
                print(f"  ⚠️  Could not query leases: {e}")
                print(f"  ℹ️  Proceeding without age data")

            # 3d: Filter to old-enough accounts, sort oldest first
            eligible = []
            too_young = []
            for acct in quarantine_accounts:
                acct_id = acct["Id"]
                age = ages.get(acct_id)
                if age is not None and age < QUARANTINE_AGE_DAYS:
                    too_young.append((acct, age))
                else:
                    # Include if age >= threshold OR age unknown
                    eligible.append((acct, age))

            # Sort: known ages (oldest first), then unknown ages
            eligible.sort(key=lambda x: (x[1] is None, -(x[1] or 0)))

            # Apply limit
            if args.limit is not None:
                eligible = eligible[:args.limit]

            # Print table
            print(f"\n  {'Account ID':<15} {'Name':<12} {'Age':>10}  Status")
            print(f"  {'-'*55}")
            for acct, age in eligible:
                age_str = f"{age:.1f} days" if age is not None else "unknown"
                print(f"  {acct['Id']:<15} {acct.get('Name', ''):<12} {age_str:>10}  ✅ eligible")
            for acct, age in too_young:
                print(f"  {acct['Id']:<15} {acct.get('Name', ''):<12} {age:.1f} days  ⏭️  too recent")

            if not eligible:
                print(f"\n  ℹ️  No accounts old enough (>{QUARANTINE_AGE_DAYS} days)")
            else:
                print(f"\n  📊 {len(eligible)} eligible, {len(too_young)} too recent")

                # ── Step 4: Process quarantined accounts ──────────────────
                print(f"\n{'='*60}")
                print("🔄 STEP 4: Process accounts")
                print("=" * 60)

                for acct, age in eligible:
                    result = process_account(
                        org_session, token, acct["Id"], acct.get("Name", ""),
                        already_in_exit=False, dry_run=args.dry_run,
                        profile_name=ORG_PROFILE,
                    )
                    counts[result] += 1
                    if result == "quota":
                        print("\n  ⚠️  Close quota hit — stopping")
                        break

    else:
        # ── Explicit mode ─────────────────────────────────────────────────
        print(f"  📋 {len(args.account_ids)} account(s) specified")

        print(f"\n{'='*60}")
        print("🔄 STEP 4: Process accounts")
        print("=" * 60)

        for account_id in args.account_ids:
            result = process_account(
                org_session, token, account_id, "",
                already_in_exit=False, dry_run=args.dry_run,
                profile_name=ORG_PROFILE,
            )
            counts[result] += 1

    # ── Summary ──────────────────────────────────────────────────────────
    end_time = time.time()

    print(f"\n{'='*60}")
    if args.dry_run:
        print("📊 Summary (dry run)")
    else:
        print("📊 Summary")
    print("=" * 60)
    print(f"  Closed:    {counts['closed']}")
    print(f"  Skipped:   {counts['skipped']}")
    print(f"  Failed:    {counts['failed']}")
    if counts["quota"]:
        print(f"  Quota hit: {counts['quota']}")
    print(f"  ⏱️  Total time: {format_duration(end_time - start_time)}")

    if counts["failed"] > 0 or counts["quota"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
