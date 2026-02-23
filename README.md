# Innovation Sandbox Pool Account Creator

Automates the creation and registration of new pool accounts for AWS Innovation Sandbox.

## Prerequisites

- Python 3.x
- AWS CLI configured with SSO profile:
  - `NDX/orgManagement` - Access to AWS Organizations
- Access to the Innovation Sandbox AWS Organization
- Access to AWS Secrets Manager (for JWT signing secret)

## Setup

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install boto3
```

## Usage

### Create a new pool account

```bash
source venv/bin/activate
python create_sandbox_pool_account.py
```

### Recover a partially provisioned account

If account creation failed partway through, you can resume by providing the account ID:

```bash
source venv/bin/activate
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

The following constants can be modified in the script:

| Constant | Value | Description |
|----------|-------|-------------|
| `ENTRY_OU` | `ou-2laj-2by9v0sr` | OU where new accounts are placed for registration |
| `SANDBOX_READY_OU` | `ou-2laj-oihxgbtr` | OU where accounts are moved after cleanup |
| `BILLING_VIEW_ARN` | `arn:aws:billing::955063685555:billingview/custom-...` | Custom billing view for cost tracking |
| `check_interval` | `5` seconds | How often to check for OU move |
| `max_wait` | `3600` seconds (1 hour) | Maximum time to wait for cleanup |

The following can be configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ISB_API_BASE_URL` | `https://1ewlxhaey6.execute-api.us-west-2.amazonaws.com/prod` | Innovation Sandbox API Gateway base URL |
| `ISB_JWT_SECRET_PATH` | `/InnovationSandbox/ndx/Auth/JwtSecret` | Secrets Manager path for JWT signing secret |

## How it works

The script registers accounts with Innovation Sandbox by calling the HTTP API Gateway endpoint (`POST /accounts`) with a signed HS256 JWT token. The JWT signing secret is fetched from AWS Secrets Manager and the token is signed using Python's `hmac` + `hashlib` (no external JWT library needed).

## Example output

```
============================================================
🔑 STEP 1: AWS SSO Authentication
============================================================
  ✅ NDX/orgManagement - session valid

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
   🌐 API: POST https://1ewlxhaey6.execute-api.us-west-2.amazonaws.com/prod/accounts
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
