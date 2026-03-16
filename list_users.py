#!/usr/bin/env python3
"""
List users in AWS Identity Center, with optional wildcard filtering.

Uses the NDX/orgManagement profile for Identity Store API access.
Supports glob-style patterns like "*@amazon.co.uk" or "*@*.gov.uk".
"""

import argparse
import fnmatch
import sys

import boto3

from isb_common import (
    SSO_REGION,
    ORG_PROFILE,
    ensure_sso_login,
)

GROUP_NAME = "ndx_IsbUsersGroup"
PREAPPROVED_GROUP_NAME = "ndx-IsbPreapprovedGroup"


def get_identity_store_id(session):
    """Get the Identity Store ID from the SSO Admin instance."""
    sso_admin = session.client('sso-admin', region_name=SSO_REGION)
    paginator = sso_admin.get_paginator('list_instances')
    for page in paginator.paginate():
        for instance in page['Instances']:
            return instance['IdentityStoreId']
    raise RuntimeError("No SSO instance found")


def get_all_users(identity_store, identity_store_id):
    """Fetch all users from the Identity Store, handling pagination."""
    users = []
    paginator = identity_store.get_paginator('list_users')
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        users.extend(page.get('Users', []))
    return users


def get_group_members(identity_store, identity_store_id, group_id):
    """Fetch all member user IDs for a group."""
    member_ids = set()
    paginator = identity_store.get_paginator('list_group_memberships')
    for page in paginator.paginate(
        IdentityStoreId=identity_store_id,
        GroupId=group_id,
    ):
        for membership in page.get('GroupMemberships', []):
            member_id = membership.get('MemberId', {}).get('UserId')
            if member_id:
                member_ids.add(member_id)
    return member_ids


def find_group_id(identity_store, identity_store_id, group_name):
    """Find a group by display name, returning None if not found."""
    resp = identity_store.list_groups(
        IdentityStoreId=identity_store_id,
        Filters=[{
            'AttributePath': 'DisplayName',
            'AttributeValue': group_name,
        }],
    )
    groups = resp.get('Groups', [])
    return groups[0]['GroupId'] if groups else None


def main():
    parser = argparse.ArgumentParser(
        description="List users in AWS Identity Center.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python list_users.py                          # list all ISB users\n"
               "  python list_users.py '*@amazon.co.uk'         # all amazon.co.uk users\n"
               "  python list_users.py '*@*.gov.uk'             # all .gov.uk users\n"
               "  python list_users.py 'john*'                  # usernames starting with john\n"
               "  python list_users.py --all                    # list ALL Identity Center users\n"
               "  python list_users.py --all '*@amazon.co.uk'   # filter across all users",
    )
    parser.add_argument("pattern", nargs="?", default=None,
                        help="Glob pattern to filter usernames (e.g. '*@amazon.co.uk')")
    parser.add_argument("--all", action="store_true",
                        help="List all Identity Center users, not just ISB group members")
    parser.add_argument("--groups", action="store_true",
                        help="Show group membership (ISB users, pre-approved)")

    args = parser.parse_args()

    # ── SSO Authentication ────────────────────────────────────────────
    ensure_sso_login(ORG_PROFILE)
    session = boto3.Session(profile_name=ORG_PROFILE)
    identity_store_id = get_identity_store_id(session)
    identity_store = session.client('identitystore', region_name=SSO_REGION)

    # ── Resolve groups ────────────────────────────────────────────────
    isb_group_id = find_group_id(identity_store, identity_store_id, GROUP_NAME)
    preapproved_group_id = find_group_id(identity_store, identity_store_id, PREAPPROVED_GROUP_NAME)

    isb_members = set()
    preapproved_members = set()

    if not args.all or args.groups:
        if isb_group_id:
            isb_members = get_group_members(identity_store, identity_store_id, isb_group_id)
        if preapproved_group_id:
            preapproved_members = get_group_members(identity_store, identity_store_id, preapproved_group_id)

    # ── Fetch users ───────────────────────────────────────────────────
    all_users = get_all_users(identity_store, identity_store_id)

    # Filter to ISB group members unless --all
    if not args.all:
        all_users = [u for u in all_users if u['UserId'] in isb_members]

    # Apply wildcard filter
    if args.pattern:
        pattern = args.pattern.lower()
        all_users = [u for u in all_users if fnmatch.fnmatch(u.get('UserName', '').lower(), pattern)]

    # Sort by username
    all_users.sort(key=lambda u: u.get('UserName', '').lower())

    # ── Output ────────────────────────────────────────────────────────
    if not all_users:
        scope = "Identity Center" if args.all else GROUP_NAME
        if args.pattern:
            print(f"No users matching '{args.pattern}' in {scope}")
        else:
            print(f"No users found in {scope}")
        sys.exit(0)

    show_groups = args.groups or not args.all

    # Calculate column widths
    name_width = max(len(u.get('DisplayName', '') or '') for u in all_users)
    name_width = max(name_width, 4)  # minimum "Name" header
    email_width = max(len(u.get('UserName', '') or '') for u in all_users)
    email_width = max(email_width, 5)  # minimum "Email" header

    # Header
    header = f"  {'Email':<{email_width}}  {'Name':<{name_width}}"
    if show_groups:
        header += "  Groups"
    print(header)
    print(f"  {'-' * email_width}  {'-' * name_width}", end="")
    if show_groups:
        print(f"  {'-' * 20}", end="")
    print()

    # Rows
    for user in all_users:
        email = user.get('UserName', '')
        display_name = user.get('DisplayName', '') or ''
        line = f"  {email:<{email_width}}  {display_name:<{name_width}}"

        if show_groups:
            user_groups = []
            if user['UserId'] in isb_members:
                user_groups.append("isb")
            if user['UserId'] in preapproved_members:
                user_groups.append("preapproved")
            line += f"  {', '.join(user_groups)}"

        print(line)

    # Summary
    scope = "Identity Center" if args.all else GROUP_NAME
    if args.pattern:
        print(f"\n  {len(all_users)} user(s) matching '{args.pattern}' in {scope}")
    else:
        print(f"\n  {len(all_users)} user(s) in {scope}")


if __name__ == '__main__':
    main()
