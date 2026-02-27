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
import hashlib
import hmac
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

import boto3

# ── Configuration ────────────────────────────────────────────────────────────

SSO_REGION = "us-west-2"
SSO_START_URL = "https://d-9267e1e371.awsapps.com/start"
ORG_PROFILE = "NDX/orgManagement"
ISB_HUB_PROFILE = "NDX/InnovationSandboxHub"
ISB_API_BASE_URL = "https://1ewlxhaey6.execute-api.us-west-2.amazonaws.com/prod/"
ISB_JWT_SECRET_PATH = "/InnovationSandbox/ndx/Auth/JwtSecret"

ACTIVE_STATUSES = {"Active", "Frozen", "Provisioning", "PendingApproval"}


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


# ── JWT ──────────────────────────────────────────────────────────────────────

def sign_jwt(payload, secret, expires_in_seconds=3600):
    """Sign a JWT with HS256 algorithm."""
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


def get_signed_token(session, email):
    """Fetch the JWT secret and return a signed token for the given user."""
    jwt_secret = fetch_jwt_secret(session, ISB_JWT_SECRET_PATH)
    return sign_jwt(
        {"user": {"email": email, "roles": ["Admin"]}},
        jwt_secret,
    )


# ── ISB API ──────────────────────────────────────────────────────────────────

def make_isb_api_request(method, path, token, body=None, query_params=None):
    """Make an HTTP request to the ISB API Gateway.

    Returns (status_code, response_body_dict).
    """
    url = f"{ISB_API_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    if query_params:
        qs = "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in query_params.items() if v is not None)
        if qs:
            url = f"{url}?{qs}"

    data = json.dumps(body).encode() if body else None

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method=method,
    )

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

    return status_code, response_body


# ── User identity ────────────────────────────────────────────────────────────

def get_current_user_email(session):
    """Get the current user's email from STS caller identity."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    # ARN format: arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/EMAIL
    arn = identity["Arn"]
    return arn.split("/")[-1]


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
            "region": SSO_REGION,
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
    """Run aws sso login for the sandbox profiles."""
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
    token = get_signed_token(hub_session, "admin@innovation-sandbox.local")

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
    token = get_signed_token(hub_session, user_email)
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
    account_id = lease.get("awsAccountId", "")
    lease_status = lease.get("status", "unknown")

    print(f"\r  ✅ Lease created{' ' * 30}")
    print(f"     UUID: {lease_uuid}")
    print(f"     Status: {lease_status}")
    if account_id:
        print(f"     Account: {account_id}")

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

        # Open console in browser
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


if __name__ == "__main__":
    main()
