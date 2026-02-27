# Innovation Sandbox on AWS — Utilities

Utilities for managing AWS Innovation Sandbox pool accounts.

## Prerequisites

- Python 3.x
- AWS CLI configured with SSO profiles:
  - `NDX/orgManagement` - Access to AWS Organizations
  - `NDX/InnovationSandboxHub` - Access to Secrets Manager (JWT signing secret)
- Access to the Innovation Sandbox AWS Organization
- Environment variables:
  - `ISB_API_BASE_URL` - Innovation Sandbox API Gateway base URL
  - `ISB_JWT_SECRET_PATH` - Secrets Manager path for JWT signing secret

## Setup

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install boto3
```

---

## create_sandbox_pool_account.py

Automates the creation and registration of new pool accounts.

### Usage

```bash
source venv/bin/activate
export ISB_API_BASE_URL="https://your-isb-api-gateway-url"
export ISB_JWT_SECRET_PATH="your/jwt-secret-path"
python create_sandbox_pool_account.py
```

### Recover a partially provisioned account

If account creation failed partway through, you can resume by providing the account ID:

```bash
source venv/bin/activate
export ISB_API_BASE_URL="https://your-isb-api-gateway-url"
export ISB_JWT_SECRET_PATH="your/jwt-secret-path"
python create_sandbox_pool_account.py 123456789012
```

The script will check the account's current location:
- **In root**: Moves to Entry OU, then registers with Innovation Sandbox
- **In Entry OU**: Registers with Innovation Sandbox
- **Elsewhere**: Returns an error (account may already be processed)

## What it does

The script performs the following steps:

1. **🔑 SSO Authentication** - Validates existing sessions, only prompts for login if needed
2. **📋 List existing accounts** - Finds all `pool-NNN` accounts in the organization
3. **🆕 Create new account** - Creates the next sequential pool account (e.g., `pool-009`)
4. **📦 Move to Entry OU** - Moves the account to `ou-2laj-2by9v0sr` (Entry OU)
5. **💰 Add to Billing View** - Adds the account to the custom billing view for cost tracking
6. **📝 Register with Innovation Sandbox** - Calls the ISB API Gateway to register the account
7. **🧹 Wait for cleanup** - Polls until the account is moved to `ou-2laj-oihxgbtr` (Ready OU)
8. **🎉 Report** - Displays total time taken

## Account naming

- Account names follow the pattern `pool-NNN` (e.g., `pool-001`, `pool-002`)
- Email addresses use the format: `ndx-try-provider+gds-ndx-try-aws-pool-NNN@dsit.gov.uk`

## Configuration

The following environment variables are required:

| Variable | Description |
|----------|-------------|
| `ISB_API_BASE_URL` | Innovation Sandbox API Gateway base URL |
| `ISB_JWT_SECRET_PATH` | Secrets Manager path for JWT signing secret |

The following constants can be modified in the script:

| Constant | Value | Description |
|----------|-------|-------------|
| `ENTRY_OU` | `ou-2laj-2by9v0sr` | OU where new accounts are placed for registration |
| `SANDBOX_READY_OU` | `ou-2laj-oihxgbtr` | OU where accounts are moved after cleanup |
| `BILLING_VIEW_ARN` | `arn:aws:billing::955063685555:billingview/custom-...` | Custom billing view for cost tracking |
| `check_interval` | `5` seconds | How often to check for OU move |
| `max_wait` | `3600` seconds (1 hour) | Maximum time to wait for cleanup |

### How it works

The script authenticates to the Innovation Sandbox API Gateway using a properly signed HS256 JWT. The JWT signing secret is fetched from AWS Secrets Manager using the `NDX/InnovationSandboxHub` SSO profile, then used to sign a token with Admin privileges for the `POST /accounts` API call.

### Example output

```
============================================================
🔑 STEP 1: AWS SSO Authentication
============================================================
  ✅ NDX/orgManagement - session valid
  ✅ NDX/InnovationSandboxHub - session valid

============================================================
📋 STEP 2: List existing pool accounts
============================================================
Fetching accounts from AWS Organizations...

📊 Found 8 accounts starting with 'pool-':

Account ID      Name                                     Status       Email
----------------------------------------------------------------------------------------------------
449788867583    pool-001                                 ACTIVE       ndx-try-provider+gds-ndx-try-aws-pool-001@dsit.gov.uk
...

   Total: 8 pool accounts

============================================================
🆕 STEP 3: Create new account
============================================================
   Account name: pool-009
   Email: ndx-try-provider+gds-ndx-try-aws-pool-009@dsit.gov.uk
   Request ID: car-abc123...
   ✅ Account created: 123456789012

============================================================
📦 STEP 4: Move to Entry OU
============================================================
   📍 From: r-2laj
   📍 To:   ou-2laj-2by9v0sr
   ✅ Move complete

============================================================
💰 STEP 4.5: Add to Billing View
============================================================
   📊 Fetching current billing view...
   📝 Adding account (total will be 9 accounts)
   ✅ Added account to billing view

============================================================
📝 STEP 5: Register with Innovation Sandbox
============================================================
   🔑 Fetching JWT secret...
   🎯 Account: 123456789012
   🌐 API: https://your-isb-api-gateway-url/accounts
   ✅ Registered successfully!
   📄 Status: CleanUp

============================================================
🧹 STEP 6: Wait for Innovation Sandbox cleanup
============================================================
⏳ Waiting for Innovation Sandbox cleanup...
   Target OU: ou-2laj-oihxgbtr
   ✅ Account moved to target OU after 8m 45s!

============================================================
🎉 COMPLETE
============================================================
   Account: pool-009 (123456789012)
   ⏱️  Total time: 12m 34s
```

---

## create_user.py

Creates a user in AWS Identity Center and adds them to the `ndx_IsbUsersGroup` group.

### Usage

```bash
source venv/bin/activate

# Create a user
python create_user.py --firstname=John --lastname="O'Donnel" --email="foo@bar.com"

# Create a user with a custom display name
python create_user.py --firstname=Jane --lastname=Doe --email="jane@example.com" --displayname="Dr Jane Doe"
```

| Argument | Required | Description |
|----------|----------|-------------|
| `--firstname` | Yes | User's first name |
| `--lastname` | Yes | User's last name |
| `--email` | Yes | User's email address (also used as username) |
| `--displayname` | No | Display name (defaults to `firstname lastname`) |

### What it does

1. **🔑 SSO Authentication** — Validates existing session, prompts for login if needed
2. **📋 Resolve Identity Store** — Discovers the Identity Store ID and locates the `ndx_IsbUsersGroup` group
3. **👤 Create user** — Creates the user in Identity Center (skips if they already exist)
4. **👥 Add to group** — Adds the user to `ndx_IsbUsersGroup` (skips if already a member)

### Example output

```
============================================================
🔑 STEP 1: AWS SSO Authentication
============================================================
  ✅ NDX/orgManagement - session valid

============================================================
📋 STEP 2: Resolve Identity Store
============================================================
   Identity Store: d-9267e1e371
   Group: ndx_IsbUsersGroup (a8412370-2051-702a-84d1-6688eeee30fa)

============================================================
👤 STEP 3: Create user
============================================================
   First name:    Chris
   Last name:     Nesbitt-Smith
   Email:         chris.nesbitt-smith@dsit.gov.uk
   Display name:  Chris Nesbitt-Smith

   ✅ User created: b82193a0-f051-70ea-dc76-b1fefef4114b

============================================================
👥 STEP 4: Add to ndx_IsbUsersGroup
============================================================
   ✅ Added to group

============================================================
🎉 COMPLETE
============================================================
   User:    Chris Nesbitt-Smith (chris.nesbitt-smith@dsit.gov.uk)
   User ID: b82193a0-f051-70ea-dc76-b1fefef4114b
   Group:   ndx_IsbUsersGroup
```

---

## clean_console_state.py

Cleans up AWS Console state (recently visited services, favorites, dashboard, theme, locale) from recycled sandbox accounts.

### Background

When ISB recycles sandbox accounts using `aws-nuke`, the AWS Management Console state is not cleaned up. This is because console state is stored by the Console Control Service (CCS), an undocumented internal AWS service that stores per-principal user preference data outside the account's resource plane — `aws-nuke` has no visibility of it.

This means new sandbox tenants see the previous user's recently visited services, favorited services, dashboard layout, and theme preferences.

### What it cleans

| Setting | Description |
|---------|-------------|
| `recentsConsole` | Recently visited services |
| `recentsConsoleOptOutState` | Whether user opted out of recents tracking |
| `favoritesConsole` | Favorited services |
| `favoriteBarDisplay` | Whether favorites bar is shown |
| `favoritesBarIconSize` | Icon size in favorites bar |
| `defaultRegion` | Default region picker |
| `locale` | Language preference |
| `colorTheme` | Light/dark theme |

It also resets the Console Home dashboard layout (`console-home-unified`).

### Usage

```bash
source venv/bin/activate

# Preview what would be cleaned (no changes made)
python clean_console_state.py --dry-run

# Clean all accounts in Available, CleanUp, and Quarantine OUs
python clean_console_state.py

# Clean only accounts in a specific OU
python clean_console_state.py --ou Available

# Clean a specific account
python clean_console_state.py --account 680464296760

# Show full settings detail
python clean_console_state.py --dry-run --verbose
```

### How it works

1. Discovers sandbox accounts by listing accounts in the ISB Organizations OUs (Available, CleanUp, Quarantine)
2. For each account, discovers which ISB SSO permission sets are provisioned (`ndx_IsbUsersPS`, `ndx_IsbAdminsPS`, `ndx_IsbManagersPS`)
3. Gets temporary credentials for each SSO role using the cached SSO access token
4. Calls the CCS `UpdateCallerSettings` API with `deleteSettingNames` to clear all console preferences
5. Calls the CCS `DeleteCallerDashboard` API to reset the dashboard layout
6. Verifies the cleanup by reading settings back

### Limitations

CCS state is **per-caller** — keyed on the full assumed-role ARN including session name (e.g. `arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_ndx_IsbAdminsPS_abc123/user@example.com`). This script cleans state for the SSO principal running it. To clean state for other users who have accessed the console, it would need to be run with each user's SSO credentials.

### Example output

```
============================================================
🔑 STEP 1: AWS SSO Authentication
============================================================
  ✅ NDX/orgManagement - session valid
  ✅ SSO access token found

============================================================
📋 STEP 2: Discover sandbox accounts from OU structure
============================================================
  Available: 4 account(s)
  CleanUp: 0 account(s)
  Quarantine: 8 account(s)

📊 12 account(s) to process:

Account ID      Name         OU
---------------------------------------------
023138541607    pool-010     Available
107721656289    pool-011     Available
221792773038    pool-008     Quarantine
...

============================================================
🧹 STEP 3: Clean console state
============================================================

  ────────────────────────────────────────────────────────
  📦 221792773038  pool-008  (Quarantine)
  ────────────────────────────────────────────────────────

     🔐 ndx_IsbAdminsPS
        📊 3 recent services
        🗑️  Deleted settings
        🗑️  Deleted dashboard
        ✅ Verified clean

  ────────────────────────────────────────────────────────
  📦 023138541607  pool-010  (Available)
  ────────────────────────────────────────────────────────

     🔐 ndx_IsbAdminsPS
        ✅ Already clean

============================================================
📊 Summary
============================================================
  Accounts:       12
  Cleaned:        8
  Already clean:  4
  Errors:         0
```
