"""
Shared utilities for Innovation Sandbox scripts.

Provides SSO authentication, JWT signing, ISB API access, and common helpers.
"""

import base64
import hashlib
import hmac
import json
import subprocess
import time
import urllib.error
import urllib.request

from datetime import datetime, timezone
from pathlib import Path

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


def find_sso_access_token():
    """Find a valid SSO access token from the AWS CLI cache.

    Returns the token string with the latest expiry, or None.
    """
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


def sso_login(profile_name):
    """Run ``aws sso login`` for the given profile. Raises on failure."""
    result = subprocess.run(
        ["aws", "sso", "login", "--profile", profile_name],
        capture_output=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"❌ SSO login failed for profile {profile_name}")


def ensure_sso_login(profile_name):
    """Ensure SSO login, only prompting if the cached token is expired or missing."""
    if check_sso_token_valid():
        print(f"  ✅ SSO session valid")
        return

    print(f"  🔐 SSO token expired, logging in...")
    sso_login(profile_name)
    print(f"  ✅ SSO login successful")


# ── JWT ──────────────────────────────────────────────────────────────────────

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


def fetch_jwt_secret(session, secret_path=ISB_JWT_SECRET_PATH):
    """Fetch JWT signing secret from AWS Secrets Manager."""
    client = session.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_path)
    secret = response.get('SecretString')
    if not secret:
        raise RuntimeError("JWT secret is empty")
    return secret


def get_signed_token(session, email=None, profile_name=ISB_HUB_PROFILE):
    """Fetch the JWT secret and return a signed token.

    If *email* is provided, the token is signed for that user.
    Otherwise an admin token is returned.

    If the SSO token has expired server-side, automatically re-authenticates
    and retries once.
    """
    if email:
        payload = {"user": {"email": email, "roles": ["Admin"]}}
    else:
        payload = {"user": {"email": "admin@innovation-sandbox.local", "roles": ["Admin"]}}

    try:
        jwt_secret = fetch_jwt_secret(session)
    except Exception as e:
        if "expired" in str(e).lower() and "token" in str(e).lower():
            print("  🔐 SSO token expired server-side, re-authenticating...")
            sso_login(profile_name)
            session = boto3.Session(profile_name=profile_name)
            jwt_secret = fetch_jwt_secret(session)
        else:
            raise

    return sign_jwt(payload, jwt_secret)


# ── ISB API ──────────────────────────────────────────────────────────────────

def make_isb_api_request(method, path, token, body=None, query_params=None):
    """Make an HTTP request to the ISB API Gateway.

    Returns (status_code, response_body_dict).
    """
    url = f"{ISB_API_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    if query_params:
        qs = "&".join(
            f"{k}={urllib.request.quote(str(v))}"
            for k, v in query_params.items()
            if v is not None
        )
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


# ── Utilities ────────────────────────────────────────────────────────────────

def format_duration(seconds):
    """Format seconds into a human-readable duration."""
    minutes, secs = divmod(int(seconds), 60)
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"
