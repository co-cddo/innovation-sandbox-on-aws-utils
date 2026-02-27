#!/usr/bin/env python3
"""
Create a user in AWS Identity Center and add them to the ndx_IsbUsersGroup.

Uses the NDX/orgManagement profile for Identity Store API access.
"""

import argparse
import subprocess
import sys

import boto3

# ── Configuration ────────────────────────────────────────────────────────────

SSO_REGION = "us-west-2"
ORG_PROFILE = "NDX/orgManagement"
GROUP_NAME = "ndx_IsbUsersGroup"


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


def get_identity_store_id(session):
    """Get the Identity Store ID from the SSO Admin instance."""
    sso_admin = session.client('sso-admin', region_name=SSO_REGION)
    paginator = sso_admin.get_paginator('list_instances')
    for page in paginator.paginate():
        for instance in page['Instances']:
            return instance['IdentityStoreId']
    raise RuntimeError("❌ No SSO instance found")


def find_group(identity_store, identity_store_id, group_name):
    """Find a group by display name in the Identity Store."""
    resp = identity_store.list_groups(
        IdentityStoreId=identity_store_id,
        Filters=[{
            'AttributePath': 'DisplayName',
            'AttributeValue': group_name,
        }],
    )
    groups = resp.get('Groups', [])
    if not groups:
        raise RuntimeError(f"❌ Group '{group_name}' not found in Identity Store")
    return groups[0]['GroupId']


def check_existing_user(identity_store, identity_store_id, username):
    """Check if a user already exists by username."""
    resp = identity_store.list_users(
        IdentityStoreId=identity_store_id,
        Filters=[{
            'AttributePath': 'UserName',
            'AttributeValue': username,
        }],
    )
    users = resp.get('Users', [])
    return users[0] if users else None


def create_user(identity_store, identity_store_id, firstname, lastname, email, display_name):
    """Create a user in the Identity Store."""
    resp = identity_store.create_user(
        IdentityStoreId=identity_store_id,
        UserName=email,
        Name={
            'GivenName': firstname,
            'FamilyName': lastname,
        },
        DisplayName=display_name,
        Emails=[{
            'Value': email,
            'Type': 'work',
            'Primary': True,
        }],
    )
    return resp['UserId']


def add_user_to_group(identity_store, identity_store_id, group_id, user_id):
    """Add a user to a group in the Identity Store."""
    identity_store.create_group_membership(
        IdentityStoreId=identity_store_id,
        GroupId=group_id,
        MemberId={'UserId': user_id},
    )


def main():
    parser = argparse.ArgumentParser(
        description="Create a user in AWS Identity Center and add to ndx_IsbUsersGroup.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python create_user.py --firstname=John --lastname=\"O'Donnel\" --email=\"foo@bar.com\"",
    )
    parser.add_argument("--firstname", required=True, help="User's first name")
    parser.add_argument("--lastname", required=True, help="User's last name")
    parser.add_argument("--email", required=True, help="User's email address")
    parser.add_argument("--displayname", help="Display name (default: 'firstname lastname')")

    args = parser.parse_args()

    display_name = args.displayname or f"{args.firstname} {args.lastname}"

    # ── Step 1: SSO Authentication ───────────────────────────────────────
    print(f"\n{'='*60}")
    print("🔑 STEP 1: AWS SSO Authentication")
    print("=" * 60)
    ensure_sso_login(ORG_PROFILE)

    session = boto3.Session(profile_name=ORG_PROFILE)

    # ── Step 2: Resolve Identity Store and Group ─────────────────────────
    print(f"\n{'='*60}")
    print("📋 STEP 2: Resolve Identity Store")
    print("=" * 60)

    identity_store_id = get_identity_store_id(session)
    print(f"   Identity Store: {identity_store_id}")

    identity_store = session.client('identitystore', region_name=SSO_REGION)

    group_id = find_group(identity_store, identity_store_id, GROUP_NAME)
    print(f"   Group: {GROUP_NAME} ({group_id})")

    # ── Step 3: Create User ──────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("👤 STEP 3: Create user")
    print("=" * 60)
    print(f"   First name:    {args.firstname}")
    print(f"   Last name:     {args.lastname}")
    print(f"   Email:         {args.email}")
    print(f"   Display name:  {display_name}")

    existing = check_existing_user(identity_store, identity_store_id, args.email)
    if existing:
        print(f"\n   ⚠️  User already exists: {existing['UserId']}")
        user_id = existing['UserId']
    else:
        user_id = create_user(
            identity_store, identity_store_id,
            args.firstname, args.lastname, args.email, display_name,
        )
        print(f"\n   ✅ User created: {user_id}")

    # ── Step 4: Add to Group ─────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"👥 STEP 4: Add to {GROUP_NAME}")
    print("=" * 60)

    try:
        add_user_to_group(identity_store, identity_store_id, group_id, user_id)
        print(f"   ✅ Added to group")
    except identity_store.exceptions.ConflictException:
        print(f"   ⚠️  Already a member of group")

    # ── Done ─────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("🎉 COMPLETE")
    print("=" * 60)
    print(f"   User:    {display_name} ({args.email})")
    print(f"   User ID: {user_id}")
    print(f"   Group:   {GROUP_NAME}")


if __name__ == '__main__':
    main()
