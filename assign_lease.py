#!/usr/bin/env python3
"""
Assign a lease from an Innovation Sandbox lease template.

Uses the NDX/orgManagement profile for STS identity.
Uses NDX/InnovationSandboxHub profile for Secrets Manager access.

Usage:
  ./assign_lease.py council-chatbot
  ./assign_lease.py --user=chris@example.com council-chatbot
"""

import argparse
import base64
import configparser
import json
import subprocess
import sys
import time

import boto3

from isb_common import (
    SSO_REGION,
    SSO_START_URL,
    ORG_PROFILE,
    ISB_HUB_PROFILE,
    ACTIVE_STATUSES,
    check_sso_token_valid,
    ensure_sso_login,
    find_sso_access_token,
    get_signed_token,
    make_isb_api_request,
    get_current_user_email,
    format_duration,
)


# ── SSO role readiness ────────────────────────────────────────────────────────

def wait_for_sso_role(account_id, role_name="ndx_IsbUsersPS", max_wait=30, interval=3):
    """Poll until the SSO role is accessible on the account, or timeout."""
    access_token = find_sso_access_token()
    if not access_token:
        print(f"  ⚠️  No SSO access token found, skipping role check")
        return False

    sso = boto3.client("sso", region_name=SSO_REGION)
    start = time.time()

    while True:
        elapsed = time.time() - start
        try:
            sso.get_role_credentials(
                accountId=account_id,
                roleName=role_name,
                accessToken=access_token,
            )
            print(f"\r  ✅ Role {role_name} ready on {account_id}{' ' * 20}")
            return True
        except Exception:
            if elapsed >= max_wait:
                print(f"\r  ⚠️  Role not available after {int(elapsed)}s, skipping console{' ' * 20}")
                return False
            print(f"\r  ⏳ Waiting for role assignment to propagate... ({int(elapsed)}s)", end="", flush=True)
            time.sleep(interval)


# ── Lease template resolution ────────────────────────────────────────────────

def resolve_lease_template(token, template_name):
    """Find a lease template by name (case-insensitive), paginating through all results.

    Returns the template dict or raises on not-found / ambiguous match.
    """
    matches = []
    page_identifier = None

    while True:
        params = {}
        if page_identifier:
            params["pageIdentifier"] = page_identifier

        status, body = make_isb_api_request("GET", "/leaseTemplates", token, query_params=params)
        if status != 200:
            raise RuntimeError(f"Failed to list lease templates (HTTP {status}): {body}")

        # Response is wrapped: {"status": "success", "data": {"result": [...]}}
        data = body.get("data", body)
        results = data.get("result", [])
        for tmpl in results:
            if tmpl.get("name", "").lower() == template_name.lower():
                matches.append(tmpl)

        page_identifier = data.get("nextPageIdentifier")
        if not page_identifier:
            break

    if not matches:
        raise RuntimeError(f"Lease template '{template_name}' not found")
    if len(matches) > 1:
        raise RuntimeError(f"Ambiguous: found {len(matches)} templates matching '{template_name}'")

    return matches[0]


# ── AWS config profile management ────────────────────────────────────────────

def update_aws_config_profiles(account_id):
    """Create/update NDX/SandboxUser and NDX/SandboxAdmin profiles in ~/.aws/config."""
    from pathlib import Path

    config_path = Path.home() / ".aws" / "config"
    config = configparser.ConfigParser()
    config.optionxform = str  # preserve case

    if config_path.exists():
        config.read(str(config_path))

    profiles = {
        "NDX/SandboxUser": "ndx_IsbUsersPS",
        "NDX/SandboxAdmin": "ndx_IsbAdminsPS",
    }

    for profile_name, role_name in profiles.items():
        profile_section = f"profile {profile_name}"
        sso_section = f"sso-session {profile_name}"

        config[profile_section] = {
            "sso_session": profile_name,
            "sso_account_id": account_id,
            "sso_role_name": role_name,
            "region": "us-east-1",
        }

        config[sso_section] = {
            "sso_start_url": SSO_START_URL,
            "sso_region": SSO_REGION,
            "sso_registration_scopes": "sso:account:access",
        }

    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w") as f:
        config.write(f)

    print(f"  ✅ Updated {config_path}")
    for profile_name in profiles:
        print(f"     - {profile_name}")


def sso_login_sandbox_profiles():
    """Run aws sso login for the sandbox profiles if needed."""
    if check_sso_token_valid():
        try:
            session = boto3.Session(profile_name="NDX/SandboxUser")
            session.client("sts").get_caller_identity()
            print(f"  ✅ SSO session valid")
            return
        except Exception:
            pass
    for profile_name in ("NDX/SandboxUser", "NDX/SandboxAdmin"):
        print(f"  🔐 {profile_name} - logging in...")
        result = subprocess.run(
            ["aws", "sso", "login", "--profile", profile_name],
            capture_output=False,
        )
        if result.returncode != 0:
            print(f"  ⚠️  SSO login failed for {profile_name} (non-fatal)")
        else:
            print(f"  ✅ {profile_name} - login successful")


# ── List templates ────────────────────────────────────────────────────────────

def list_templates():
    """Authenticate, fetch all templates, and print a table."""
    ensure_sso_login(ISB_HUB_PROFILE)

    hub_session = boto3.Session(profile_name=ISB_HUB_PROFILE)
    token = get_signed_token(hub_session)

    templates = []
    page_identifier = None
    while True:
        params = {}
        if page_identifier:
            params["pageIdentifier"] = page_identifier
        status, body = make_isb_api_request("GET", "/leaseTemplates", token, query_params=params)
        if status != 200:
            raise RuntimeError(f"Failed to list lease templates (HTTP {status}): {body}")
        data = body.get("data", body)
        templates.extend(data.get("result", []))
        page_identifier = data.get("nextPageIdentifier")
        if not page_identifier:
            break

    if not templates:
        print("No lease templates found.")
        return

    def fmt_duration(hours):
        if hours is None:
            return "-"
        if hours < 24:
            return f"{hours}h"
        days = hours / 24
        return f"{days:.0f}d" if days == int(days) else f"{days:.1f}d"

    rows = []
    for t in sorted(templates, key=lambda t: t.get("name", "")):
        rows.append((
            t.get("name", ""),
            t.get("blueprintName") or "-",
            t.get("visibility", ""),
            f"${t['maxSpend']}" if t.get("maxSpend") is not None else "-",
            fmt_duration(t.get("leaseDurationInHours")),
        ))

    headers = ("Name", "Blueprint", "Visibility", "Budget", "Duration")
    widths = [max(len(h), max(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)

    print(fmt.format(*headers))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows:
        print(fmt.format(*row))


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Assign a lease from an Innovation Sandbox lease template"
    )
    parser.add_argument(
        "template",
        nargs="?",
        default="empty-sandbox",
        help="Lease template name (case-insensitive, default: empty-sandbox)",
    )
    parser.add_argument(
        "--user",
        help="Email of user to assign the lease to (default: current SSO user)",
    )
    parser.add_argument(
        "--list-templates", action="store_true",
        help="List available lease templates and exit",
    )
    args = parser.parse_args()

    if args.list_templates:
        list_templates()
        sys.exit(0)

    self_service = args.user is None

    # ── Step 1: SSO Authentication ───────────────────────────────────────
    print("=" * 60)
    print("🔑 STEP 1: AWS SSO Authentication")
    print("=" * 60)
    ensure_sso_login(ORG_PROFILE)
    ensure_sso_login(ISB_HUB_PROFILE)

    # ── Step 2: Resolve user ─────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("👤 STEP 2: Resolve user")
    print("=" * 60)

    org_session = boto3.Session(profile_name=ORG_PROFILE)

    if self_service:
        user_email = get_current_user_email(org_session)
        print(f"  📧 {user_email} (self)")
    else:
        user_email = args.user
        print(f"  📧 {user_email} (specified)")

    # ── Step 3: Sign JWT ─────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("🔑 STEP 3: Sign JWT")
    print("=" * 60)

    hub_session = boto3.Session(profile_name=ISB_HUB_PROFILE)
    print("  🔑 Fetching JWT secret...")
    token = get_signed_token(hub_session, email=user_email)
    print(f"  ✅ JWT signed as {user_email}")

    # ── Step 4: Resolve lease template ───────────────────────────────────
    print(f"\n{'='*60}")
    print(f"📋 STEP 4: Resolve lease template")
    print("=" * 60)

    print(f"  🔍 Looking up '{args.template}'...")
    template = resolve_lease_template(token, args.template)
    print(f"  ✅ Found: {template['name']}")
    print(f"     UUID: {template['uuid']}")
    if template.get('description'):
        print(f"     Description: {template['description']}")

    # ── Step 5: Create lease ─────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("📝 STEP 5: Create lease")
    print("=" * 60)

    lease_body = {
        "leaseTemplateUuid": template["uuid"],
        "userEmail": user_email,
    }
    print(f"  ⏳ Creating lease...", end="", flush=True)

    status, response = make_isb_api_request("POST", "/leases", token, body=lease_body)

    if status != 201:
        print(f"\r  ❌ Failed to create lease (HTTP {status}){' ' * 20}")
        print(f"  Response: {json.dumps(response, indent=2)}")
        sys.exit(1)

    # Response is wrapped: {"status": "success", "data": {...lease...}}
    lease = response.get("data", response)
    lease_uuid = lease.get("uuid", "unknown")
    lease_id = lease.get("leaseId", "")
    if not lease_id:
        # Construct leaseId (base64-encoded composite key used by the API)
        lease_id = base64.b64encode(
            json.dumps({"userEmail": user_email, "uuid": lease_uuid}, separators=(',', ':')).encode()
        ).decode()
    account_id = lease.get("awsAccountId", "")
    lease_status = lease.get("status", "unknown")

    print(f"\r  ✅ Lease created{' ' * 30}")
    print(f"     UUID: {lease_uuid}")
    print(f"     Status: {lease_status}")
    if account_id:
        print(f"     Account: {account_id}")

    # ── Step 5b: Wait for provisioning if needed ─────────────────────────
    if lease_status == "Provisioning":
        print(f"\n{'='*60}")
        print("⏳ STEP 5b: Wait for provisioning")
        print("=" * 60)

        start_wait = time.time()
        check_interval = 5
        max_wait = 1800  # 30 minutes

        while True:
            elapsed = time.time() - start_wait
            if elapsed > max_wait:
                print(f"\r  ❌ Timeout after {format_duration(elapsed)}{' ' * 30}")
                sys.exit(1)

            time.sleep(check_interval)
            elapsed = time.time() - start_wait

            poll_status, poll_response = make_isb_api_request(
                "GET", f"/leases/{lease_id}", token,
            )

            if poll_status != 200:
                print(f"\r  ⏳ Provisioning... | Elapsed: {format_duration(elapsed)} (poll error: HTTP {poll_status})", end="", flush=True)
                continue

            poll_lease = poll_response.get("data", poll_response)
            lease_status = poll_lease.get("status", "unknown")
            account_id = poll_lease.get("awsAccountId", "") or account_id

            if lease_status == "Provisioning":
                print(f"\r  ⏳ Provisioning... | Elapsed: {format_duration(elapsed)}", end="", flush=True)
            elif lease_status == "Active":
                print(f"\r  ✅ Provisioning complete after {format_duration(elapsed)}{' ' * 20}")
                if account_id:
                    print(f"     Account: {account_id}")
                break
            else:
                print(f"\r  ⚠️  Unexpected status: {lease_status} after {format_duration(elapsed)}{' ' * 20}")
                break

    # ── Step 6: Configure SSO profiles (self-service only) ───────────────
    if self_service and account_id:
        print(f"\n{'='*60}")
        print("🔧 STEP 6: Configure AWS SSO profiles")
        print("=" * 60)

        update_aws_config_profiles(account_id)

        print(f"\n{'='*60}")
        print("🔐 STEP 7: SSO login for sandbox profiles")
        print("=" * 60)

        sso_login_sandbox_profiles()

        # Wait for role assignment to propagate before opening console
        print(f"\n{'='*60}")
        print("⏳ STEP 8: Wait for role assignment")
        print("=" * 60)

        if wait_for_sso_role(account_id):
            import webbrowser
            console_url = f"{SSO_START_URL}#/console?account_id={account_id}&role_name=ndx_IsbUsersPS"
            print(f"\n  🌐 Opening console: {console_url}")
            webbrowser.open(console_url)

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("🎉 COMPLETE")
    print("=" * 60)
    print(f"  User:     {user_email}")
    print(f"  Template: {template['name']}")
    if account_id:
        print(f"  Account:  {account_id}")
    print(f"  Lease:    {lease_uuid}")
    if self_service and account_id:
        print(f"\n  AWS CLI profiles:")
        print(f"    aws --profile NDX/SandboxUser  ...   # {account_id} (ndx_IsbUsersPS)")
        print(f"    aws --profile NDX/SandboxAdmin ...   # {account_id} (ndx_IsbAdminsPS)")


if __name__ == "__main__":
    main()
