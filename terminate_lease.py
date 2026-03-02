#!/usr/bin/env python3
"""
Terminate all active Innovation Sandbox leases for a user.

Uses the NDX/orgManagement profile for STS identity.
Uses NDX/InnovationSandboxHub profile for Secrets Manager access.

Usage:
  ./terminate_lease.py
  ./terminate_lease.py --user=chris@example.com
"""

import argparse
import base64
import hashlib
import hmac
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

from datetime import datetime, timezone
from pathlib import Path

import boto3

# ── Configuration ────────────────────────────────────────────────────────────

SSO_START_URL = "https://d-9267e1e371.awsapps.com/start"
ORG_PROFILE = "NDX/orgManagement"
ISB_HUB_PROFILE = "NDX/InnovationSandboxHub"
ISB_API_BASE_URL = "https://1ewlxhaey6.execute-api.us-west-2.amazonaws.com/prod/"
ISB_JWT_SECRET_PATH = "/InnovationSandbox/ndx/Auth/JwtSecret"

ACTIVE_STATUSES = {"Active", "Frozen", "Provisioning", "PendingApproval"}


# ── SSO Authentication ───────────────────────────────────────────────────────

def check_sso_token_valid():
    """Check if a valid (non-expired) SSO access token exists in the local cache."""
    cache_dir = Path.home() / ".aws" / "sso" / "cache"
    if not cache_dir.exists():
        return False
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
        if expiry > datetime.now(timezone.utc):
            return True
    return False


def ensure_sso_login(profile_name):
    """Ensure SSO login, only prompting if the cached token is expired or missing."""
    if check_sso_token_valid():
        print(f"  ✅ SSO session valid")
        return

    print(f"  🔐 SSO token expired, logging in...")
    result = subprocess.run(
        ["aws", "sso", "login", "--profile", profile_name],
        capture_output=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"❌ SSO login failed for profile {profile_name}")
    print(f"  ✅ SSO login successful")


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


def get_signed_token(session):
    """Fetch the JWT secret and return a signed admin token."""
    jwt_secret = fetch_jwt_secret(session, ISB_JWT_SECRET_PATH)
    return sign_jwt(
        {"user": {"email": "admin@innovation-sandbox.local", "roles": ["Admin"]}},
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


# ── Lease operations ─────────────────────────────────────────────────────────

def get_active_leases(token, user_email, verbose=False):
    """Fetch all active leases for a user, paginating through results."""
    active_leases = []
    all_leases = []
    page_identifier = None

    while True:
        params = {"userEmail": user_email}
        if page_identifier:
            params["pageIdentifier"] = page_identifier

        status, body = make_isb_api_request("GET", "/leases", token, query_params=params)

        if verbose:
            print(f"  🔍 GET /leases (HTTP {status}):")
            # Safely truncate — avoid cutting inside unicode escapes
            try:
                dumped = json.dumps(body, indent=2, ensure_ascii=True)
                if len(dumped) > 2000:
                    dumped = dumped[:2000] + "\n     ... (truncated)"
                print(f"     {dumped}")
            except Exception as e:
                print(f"     (could not serialize response: {e})")

        if status != 200:
            raise RuntimeError(f"Failed to list leases (HTTP {status}): {body}")

        # Response is wrapped: {"status": "success", "data": {"result": [...]}}
        data = body.get("data", body)
        results = data.get("result", [])
        all_leases.extend(results)
        for lease in results:
            if lease.get("status") in ACTIVE_STATUSES:
                active_leases.append(lease)

        page_identifier = data.get("nextPageIdentifier")
        if not page_identifier:
            break

    if verbose and all_leases:
        statuses = {}
        for l in all_leases:
            s = l.get("status", "unknown")
            statuses[s] = statuses.get(s, 0) + 1
        print(f"  📊 Total leases returned: {len(all_leases)}, by status: {statuses}")
        if all_leases:
            print(f"  📋 First lease keys: {list(all_leases[0].keys())}")

    return active_leases


def terminate_lease(token, lease_id):
    """Terminate a single lease by leaseId (Base64-encoded)."""
    encoded_id = urllib.request.quote(lease_id, safe="+=")
    status, body = make_isb_api_request("POST", f"/leases/{encoded_id}/terminate", token)
    return status == 200, status, body


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Terminate all active Innovation Sandbox leases for a user"
    )
    parser.add_argument(
        "--user",
        help="Email of user whose leases to terminate (default: current SSO user)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show raw API responses for debugging",
    )
    args = parser.parse_args()

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

    if args.user:
        user_email = args.user
        print(f"  📧 {user_email} (specified)")
    else:
        user_email = get_current_user_email(org_session)
        print(f"  📧 {user_email} (self)")

    # ── Step 3: Sign JWT ─────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("🔑 STEP 3: Sign JWT")
    print("=" * 60)

    hub_session = boto3.Session(profile_name=ISB_HUB_PROFILE)
    print("  🔑 Fetching JWT secret...")
    token = get_signed_token(hub_session)
    print("  ✅ JWT signed")

    # ── Step 4: Fetch active leases ──────────────────────────────────────
    print(f"\n{'='*60}")
    print("📋 STEP 4: Fetch active leases")
    print("=" * 60)

    print(f"  🔍 Querying leases for {user_email}...")
    active_leases = get_active_leases(token, user_email, verbose=args.verbose)

    if not active_leases:
        print(f"  ℹ️  No active leases found for {user_email}")
        sys.exit(0)

    print(f"\n  📊 Found {len(active_leases)} active lease(s):\n")
    print(f"  {'UUID':<38} {'Account':<14} {'Template':<30} {'Status':<16} {'Start Date'}")
    print(f"  {'-'*38} {'-'*14} {'-'*30} {'-'*16} {'-'*24}")
    for lease in active_leases:
        print(
            f"  {lease.get('uuid', ''):<38} "
            f"{lease.get('awsAccountId', ''):<14} "
            f"{lease.get('originalLeaseTemplateName', ''):<30} "
            f"{lease.get('status', ''):<16} "
            f"{lease.get('startDate', '')}"
        )

    # ── Step 5: Terminate leases ─────────────────────────────────────────
    print(f"\n{'='*60}")
    print("🗑️  STEP 5: Terminate leases")
    print("=" * 60)

    terminated = 0
    failed = 0

    for lease in active_leases:
        lease_uuid = lease.get("uuid", "")
        lease_id = lease.get("leaseId", "")
        account_id = lease.get("awsAccountId", "")
        template_name = lease.get("originalLeaseTemplateName", "")

        print(f"  ⏳ Terminating {lease_uuid[:8]}... ({template_name}, {account_id})", end="", flush=True)
        ok, status, body = terminate_lease(token, lease_id)

        if ok:
            print(f"\r  ✅ Terminated {lease_uuid[:8]}... ({template_name}, {account_id}){' ' * 10}")
            terminated += 1
        else:
            print(f"\r  ❌ Failed {lease_uuid[:8]}... (HTTP {status}){' ' * 20}")
            print(f"     Response: {json.dumps(body, indent=2)}")
            failed += 1

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("📊 Summary")
    print("=" * 60)
    print(f"  User:       {user_email}")
    print(f"  Terminated: {terminated}")
    print(f"  Failed:     {failed}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
