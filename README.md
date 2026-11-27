# Amii VPN Panel

A private AmneziaWG operations panel with one administrator and isolated,
administrator-created user accounts. The Next.js app is the public-facing
frontend/BFF; the FastAPI agent is intended to run behind HTTPS on the VPS. The
agent reads the existing `lapeace-monitor` JSON output and does not keep a
separate accounting file. Account records and the optional dynamic-IP registry
use Cloudflare Durable Object persistent storage; neither uses Vercel memory or
the function filesystem.

## Project layout

```text
web/                  Next.js App Router, TypeScript, Tailwind and UI primitives
  app/                Dashboard, login and authenticated API routes
  components/         Terminal-style responsive interface
  lib/                Session signing, account types and shared UI utilities
  scripts/            Password hash helper
agent/                Read-only FastAPI telemetry agent and tests
cloudflare/           Dynamic SSH registry Worker and persistent Durable Object
deploy/               Deployment templates and instructions
```

## Safety status

The agent reads `MONITOR_STATE_FILE` (default
`/opt/lapeace/data/usage.json`) and never writes to that file. It does not
independently query AWG for dashboard telemetry or calculate peer accounting.
Peer public keys are reduced to fingerprints/opaque IDs; endpoint and
preshared-key fields are not returned. The AWG dump parser remains for isolated
parser validation only. The agent does not modify AWG, WARP, routes, NAT,
firewall rules, or traffic control.

Admin sign-in uses an environment-configured scrypt password hash. The admin
can create, suspend, reactivate, update, and delete user accounts, each mapped
to one existing peer. User sessions can only retrieve their own daily usage,
configured daily quota, and current upload/download rates; they cannot access
peer identifiers, the peer table, server totals, account management, or
Dynamic SSH controls. Account credentials are hashed before persistent storage.
Login attempts are rate-limited and account/admin events are retained for up to
three days. Quotas, speeds, connection limits, and time windows are advisory
display settings only; they do not enforce or change VPN access.

The Dynamic SSH Manager is a separate, opt-in feature. It detects the request
address only from Cloudflare's `CF-Connecting-IP`, authenticates the existing
admin HMAC session, and stores registry records in a Durable Object. Its VPS
poller is disabled by default and uses a separate bearer token. If enabled, it
executes only the fixed `warp-cli tunnel ip add/remove <validated-ip>` command
arguments; there is no arbitrary command API. It never replaces the complete
WARP exclusion list. Protected exclusions are not hard-coded; enabling the
poller requires an explicit confirmation that the complete manual and
AWG-endpoint exclusion inventory is present in `DYNAMIC_IP_PROTECTED`.

Peer creation, pause/resume, revocation, and client configuration export return
HTTP 501 and are disabled in the UI. Do not enable them until the existing AWG
configuration/persistence mechanism and the desired operational behavior have
been inspected and reviewed. Speed limits and daily-limit enforcement are not
implemented. No feature is represented as operational until it has been tested
against the actual VPS setup.

## Local development

1. Install Node.js 20.9 or later and Python 3.11 or later.
2. From the project root, change to `web/` and run `npm install`.
3. While in `web/`, generate an admin password hash. In PowerShell, run:

   ```powershell
   $password = Read-Host "Panel passphrase" -AsSecureString
   $plain = [System.Net.NetworkCredential]::new("", $password).Password
   $plain | npm run hash-password
   Remove-Variable plain, password
   ```

   Copy the printed `scrypt:...` value to `PANEL_ADMIN_PASSWORD_HASH`. Do not
   commit it.
4. Create `.env.local` from `.env.example`; set the admin ID, password hash, and
   a `PANEL_SESSION_SECRET` of at least 32 random bytes. Generate random values
   with `node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"`.
   Set the agent URL/token only after the adapter has been safely deployed. The
   password hash helper prints only a hash; it does not persist the password.
5. From `web/`, run `npm run dev`. The dashboard login is at
   `http://localhost:3000/login`. The agent must be separately configured for
   telemetry; no sample or fabricated usage values are shown.

The agent development dependencies and focused tests can be run in `agent/` with:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

For Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

## Vercel and VPS deployment

Deployment must wait until monitor JSON access, its exact schema, service
permissions, and the HTTPS path from Vercel have been verified. No SSH or VPS
credentials belong in Vercel.

### Vercel

1. Import the repository and set the Vercel project **Root Directory** to `web`.
2. Add `lapeace.amii.lol` under **Settings → Domains** and apply the DNS records
   Vercel specifies. Confirm HTTPS is active before allowing sign-in.
3. Add these environment variables in Vercel project settings:
   - `PANEL_ADMIN_ID`
   - `PANEL_ADMIN_PASSWORD_HASH`
   - `PANEL_SESSION_SECRET` (unique random value, at least 32 bytes)
   - `AGENT_BASE_URL` (HTTPS URL for the agent, never an IP-only plaintext URL)
   - `AGENT_API_TOKEN` (same high-entropy token configured on the VPS)
   - `ACCOUNT_STORE_API_URL` (Cloudflare Worker account-store route,
     `https://lapeace.amii.lol/api/account-store`)
   - `ACCOUNT_STORE_TOKEN` (high-entropy server-to-server bearer secret; also
     configured as a Cloudflare Worker secret)
4. Deploy, verify the HTTPS login, invalid-password rejection, session cookie flags,
   logout, and failure display when the agent is unavailable.
5. Apply edge rate limiting to `/api/auth/login` and restrict panel access further
   (for example, an IP allowlist) if your administrator network has stable egress
   addresses.

### Authenticated first release

The login, account, and telemetry flow is:

```text
Browser → same-origin Next.js route handler on Vercel
        → Cloudflare Worker at /api/account-store*
        → existing DYNAMIC_IP_REGISTRY Durable Object
        → account records and auth-version state

Vercel → HTTPS VPS agent (only for dashboard telemetry)
```

The Worker is named `lapeace-dynamic-ssh`. `cloudflare/wrangler.toml` binds
`DYNAMIC_IP_REGISTRY` to the existing `DynamicIpRegistry` class, whose stable
object name is `lapeace-dynamic-ip-registry`. The v1 SQLite Durable Object
migration remains unchanged. Account records use separate storage-key prefixes
in that same object; there is no D1 database and no replacement or reset of the
Dynamic SSH object. The Worker has custom routes for
`lapeace.amii.lol/api/account-store*`, `lapeace.amii.lol/api/dynamic-ssh*`, and
`lapeace.amii.lol/health`. Its `workers_dev = false` configuration means the
intended production URL is the custom domain, not a `workers.dev` URL.

The default account-store URL in `web/.env.example`,
`https://lapeace.amii.lol/api/account-store`, is correct for the current
`accountStoreFetch()` implementation: it appends paths such as
`internal/session/validate`, and the Cloudflare route matches that prefix.
This is conditional on Cloudflare routing that hostname/path to the deployed
Worker and the domain being proxied through the configured Cloudflare zone.
Neither the live Worker route nor Vercel's production environment can be
verified from this repository. Vercel communicates with the account Worker
server-to-server through Next.js code; browser JavaScript receives neither the
account-store URL token nor the VPS agent token. Account API requests do not
need CORS. Dynamic SSH browser routes are same-origin and use origin checks.

All application settings below are read at runtime (server-side). Vercel
environment changes require a new Vercel deployment before the running
deployment sees them. Never prefix these with `NEXT_PUBLIC_`.

| Variable | Required | Where / format | Purpose |
| --- | --- | --- | --- |
| `PANEL_ADMIN_ID` | Yes | Vercel and Cloudflare Worker; exact existing administrator ID | Admin login and Worker session identity check. |
| `PANEL_ADMIN_PASSWORD_HASH` | Yes | Vercel only; `scrypt:<32 hex salt>:<128 hex digest>` | Admin password verifier; never store the plaintext password. |
| `PANEL_SESSION_SECRET` | Yes | Same random value in Vercel and Cloudflare Worker; at least 32 bytes | HMAC session signing and Worker verification. Rotating it invalidates every session. |
| `AGENT_BASE_URL` | For telemetry | Vercel only; HTTPS URL; loopback HTTP is allowed for local development | Read-only VPS agent endpoint. Not needed for login/account CRUD. |
| `AGENT_API_TOKEN` | For telemetry | Vercel only; high-entropy bearer token matching the agent | Authenticates server-side snapshot requests. Not needed for login/account CRUD. |
| `ACCOUNT_STORE_API_URL` | Yes | Vercel only; `https://lapeace.amii.lol/api/account-store` | Base URL for the server-side account Worker client. |
| `ACCOUNT_STORE_TOKEN` | Yes | Same high-entropy value in Vercel and Cloudflare Worker; at least 32 characters | Bearer authentication for account-store requests. |

Additional Worker configuration actually referenced by source:

- `DYNAMIC_SYNC_TOKEN` is a Cloudflare Worker secret only when the VPS Dynamic
  SSH poller is enabled. It must match the value already configured for that
  agent. Do not rotate or change the VPS value as part of this release.
- `REGISTRATION_SOURCE` is a non-secret Worker variable already defined in
  `cloudflare/wrangler.toml`.
- `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` are GitHub Actions
  deployment secrets, not Worker runtime secrets.
- `NODE_ENV` is supplied by Vercel. It controls the `Secure` cookie flag.

The session cookie is host-only, `HttpOnly`, `SameSite=Strict`, `Path=/`, and
`Secure` in production. Sessions expire after 12 hours. Every protected Next.js
request verifies the signature and checks the account's live status and
`authVersion` in the Durable Object. Disabling/deleting a user or resetting that
user's password invalidates old sessions. Logout increments the corresponding
auth version (all sessions for that single administrator or user are invalidated).
Changing the administrator password hash should be accompanied by rotating
`PANEL_SESSION_SECRET` in Vercel and Cloudflare, which invalidates all old
signed sessions. If the account store is unavailable, protected requests fail
closed.

#### First administrator setup

The administrator is environment-configured, not a row in the user-account
store. This avoids duplicate bootstrap accounts and never creates or resets a
password automatically. Set `PANEL_ADMIN_ID` to the existing administrator's
exact ID (the example uses `ami_nope`); do not change it to a new identity
without approval.

1. To preserve the current administrator credential, use that existing
   passphrase with the generator below and configure its hash in Vercel. Only
   choose a new passphrase if an administrator password rotation is intended;
   that changes the credential used to sign in. From `web/` in PowerShell, put
   the generated hash directly on the clipboard so it is not printed:

   ```powershell
   $secure = Read-Host "Administrator passphrase" -AsSecureString
   $plain = [System.Net.NetworkCredential]::new("", $secure).Password
   $hash = $plain | node .\scripts\hash-password.mjs
   Set-Clipboard -Value $hash
   Remove-Variable secure, plain, hash
   ```

   Paste the hash into the Vercel `PANEL_ADMIN_PASSWORD_HASH` secret field.
   The generator rejects passwords shorter than 12 characters. Do not put
   either value in chat, source control, or `.env.example`.
2. Generate a 48-byte session key locally without printing it:

   ```powershell
   $secret = node -e "process.stdout.write(require('node:crypto').randomBytes(48).toString('base64url'))"
   Set-Clipboard -Value $secret
   Remove-Variable secret
   ```

   Paste the same value into Vercel and the Cloudflare Worker secret
   `PANEL_SESSION_SECRET`. Clear the clipboard after configuration.
3. Configure `PANEL_ADMIN_ID` and the matching `PANEL_SESSION_SECRET` in
   Cloudflare, plus the required `ACCOUNT_STORE_TOKEN`. Configure the matching
   `ACCOUNT_STORE_API_URL` and `ACCOUNT_STORE_TOKEN` in Vercel. Configure
   `DYNAMIC_SYNC_TOKEN` only if the existing poller is already configured with
   a matching value.
4. Configure `AGENT_BASE_URL` and `AGENT_API_TOKEN` in Vercel only if the
   telemetry agent is reachable over the approved HTTPS path. No VPS changes
   are required for login or account management; user telemetry requires the
   existing read-only agent.

The first successful deployment is the bootstrap; there is no one-time seed
command. To verify the administrator, visit `https://lapeace.amii.lol/login`,
sign in with the configured ID and passphrase, refresh the dashboard, then
sign out. Never put the passphrase or hash in a command-line argument.

#### Cloudflare setup and deployment

No Durable Object binding or migration changes are required for accounts. Keep
the current class, binding, object name, migration tag, and SQLite storage. Set
the secrets in the Cloudflare account (each command prompts for its value):

```sh
cd cloudflare
npm ci
npm run typecheck
npm test
npx wrangler secret put PANEL_ADMIN_ID
npx wrangler secret put PANEL_SESSION_SECRET
npx wrangler secret put ACCOUNT_STORE_TOKEN
npx wrangler secret put DYNAMIC_SYNC_TOKEN
npx wrangler deploy
```

Use the matching values already configured in Vercel; for
`DYNAMIC_SYNC_TOKEN`, use the existing agent value rather than changing the VPS.
If the poller is disabled and no existing sync token is available, omit that
secret; its endpoints fail closed with 401. Run deployment only after reviewing
the diff and authorizing release. Do not run `wrangler deploy` from the
repository root; the configuration is `cloudflare/wrangler.toml`.

Safe post-deployment checks (these reveal only status codes, not account data):

```sh
curl --silent --show-error https://lapeace.amii.lol/health
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  https://lapeace.amii.lol/api/account-store/internal/accounts
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  --header 'Authorization: Bearer intentionally-invalid' \
  https://lapeace.amii.lol/api/account-store/internal/accounts
```

Expected results are `{"status":"ok"}` for health and `401` for both
unauthenticated and invalid-token account calls. To check a configured token
without placing it in shell history or printing response data:

```sh
read -s ACCOUNT_STORE_TOKEN
printf '\n'
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  --header "Authorization: Bearer ${ACCOUNT_STORE_TOKEN}" \
  https://lapeace.amii.lol/api/account-store/internal/accounts
unset ACCOUNT_STORE_TOKEN
```

The authenticated check should return `200`. Do not enable shell tracing or
print the token.

#### GitHub deployment workflow

`.github/workflows/cloudflare-worker.yml` runs Worker typecheck/tests on pull
requests and pushes to `main`. It does not deploy automatically. A manual
`workflow_dispatch` from `main` runs tests first, then deploys from `cloudflare/`
through the GitHub `production` environment. Configure that environment with
required reviewers and the secrets `CLOUDFLARE_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID`. Scope the API token to the minimum Worker script,
route, and Durable Object migration permissions Wrangler requires. Runtime
Worker secrets remain configured in Cloudflare and are never placed in the
workflow. Vercel continues to deploy the frontend through its existing GitHub
integration; the Vercel project root must be `web/` and its build command is
`npm run build`.

#### Post-deployment end-to-end checklist

Run these checks manually after deployment; local build/test results do not
prove production configuration:

1. Visit `https://lapeace.amii.lol`; an unauthenticated request to `/` should
   redirect to `/login`. `/login` itself remains public.
2. Log in as the configured administrator, refresh, and confirm the session
   persists; then log out and verify the old cookie no longer authorizes API
   requests.
3. As administrator, create a standard user assigned to a known existing peer.
4. Log out and sign in as that user. Confirm only their daily usage, quota, and
   upload/download rates appear.
5. As that user, request `/api/accounts`, `/api/accounts/audit`, and
   `/api/panel/snapshot`; expect authorization failure or not-found. Change
   account/peer IDs in requests and confirm no other account's data is returned.
6. Suspend the user and confirm their old session is rejected on the next page
   or API request. Reset their password and confirm prior sessions are rejected.
   Delete the user and confirm the same.
7. Verify an expired session is redirected to login and logout clears the
   cookie.
8. As administrator, verify Dynamic SSH registration/status and the existing
   dashboard/agent telemetry. If the agent is unavailable, login and account
   management can still work, but telemetry is not verified.
9. Confirm the VPS monitor, AWG, WARP, routes, firewall, peer configuration,
   and services were not changed.

Until these live checks are run, mark production login, cookies, account
revocation, Worker route reachability, Dynamic SSH continuity, and VPS
telemetry as **NOT VERIFIED**.

### Ubuntu VPS agent — read-only stage only

The agent is a separate, read-only adapter for the existing `lapeace-monitor`.
Do not install or run it until the monitor JSON schema and read permissions have
been verified on the server. Keep the existing monitor service and its files
unchanged. The intended listener is loopback only; Vercel needs a separately
approved HTTPS reverse-proxy or private-tunnel path to reach it. Never expose
the FastAPI listener directly to the public Internet.

1. Verify the existing monitor JSON schema, path, atomic-write behavior, and
   `lapeace-monitor` service identity. Do not share private keys, preshared keys,
   tokens, or endpoint details in diagnostics.
2. Run the adapter under a dedicated unprivileged identity. Grant it read and
   directory-traversal access to the monitor JSON only; do not grant write access
   to `/opt/lapeace/data/usage.json` or to AWG/WARP configuration.
3. Install `agent/requirements.txt` in an isolated virtual environment. Set
   `PANEL_API_TOKEN` to a random secret of at least 32 bytes,
   `MONITOR_STATE_FILE=/opt/lapeace/data/usage.json`, and `AWG_INTERFACE=awg0`
   (used as the interface label in the response; the adapter does not query AWG).
4. Start exactly one Uvicorn worker bound to `127.0.0.1` only:

   ```sh
   .venv/bin/uvicorn app:app --host 127.0.0.1 --port 8765 --workers 1
   ```

   Supply the environment variables through the approved service manager. Put
   the listener behind HTTPS with authentication
   and network restrictions; the agent itself also checks the bearer token on
   every endpoint. Do not enable public access to its OpenAPI/docs endpoints.
5. Configure the Vercel variables above with the HTTPS agent URL and matching
   API token. Compare the adapter response to a sanitized monitor snapshot,
   verify upload/download direction and IST daily totals, and verify the source
   JSON hash and modification time are unchanged after repeated reads.
6. Keep peer operations disabled until their persistence-safe implementation,
   backup/rollback strategy, traffic-control scope, and tests are agreed and
   verified for this exact server.

The telemetry path has no shell or subprocess execution and there is no
arbitrary command endpoint. The separately gated Dynamic SSH poller executes
only the fixed per-IP WARP commands described below. Neither component runs
`awg`, `tc`, `ip`, firewall tools, service restarts, or changes routes/NAT.

## Monitor JSON adapter mapping

The adapter accepts snapshot peers as a list, a `snapshot.peers` list/map, or a
peer-keyed map. Each peer record must contain `public_key`, `ips`,
`upload_bytes`, `download_bytes`, `latest_handshake`, `upload_mbps`,
`download_mbps`, `connected`, `daily_upload_bytes`, and
`daily_download_bytes`. `daily_usage` accepts either date → peer → counters or
peer → date → counters, with `upload_bytes`/`download_bytes` values.

The existing API response shape is retained: client upload maps to `rxBytes`
and `rxBps`; client download maps to `txBytes` and `txBps`. Mbps is converted to
bytes per second using `1 Mbps = 125,000 bytes/second`. Daily history sums the
monitor's existing per-peer daily upload/download values by date. The adapter
does not recalculate usage from raw counters. `last_sample` is returned as
`sampledAt`; naive timestamps are interpreted as Asia/Kolkata.

## Dynamic SSH Manager — local implementation, not deployed

### Architecture and changed files

```text
Browser → Cloudflare Worker on /api/dynamic-ssh*
        → admin cookie verified with the same HMAC key as Next.js
        → persistent Cloudflare Durable Object registry

FastAPI agent → authenticated registry poll every 10 seconds
              → strict IPv4/timestamp validation
              → fixed single-IP warp-cli add/remove operation
              → separate local managed-IP state and backup
```

Only these project files are involved:

- `web/components/dashboard.tsx` — authenticated dashboard section and register
  button; it sends no browser-supplied IP value.
- `cloudflare/src/worker.ts`, `cloudflare/src/core.ts`,
  `cloudflare/wrangler.toml`, `cloudflare/package.json`, and
  `cloudflare/tsconfig.json` — edge IP detection, session verification,
  persistent registry, service-token routes, Worker route configuration, and
  test scripts.
- `cloudflare/tests/core.test.mjs` — focused validation of session, address,
  expiry, and duplicate-registration behavior.
- `agent/dynamic_ssh.py`, `agent/app.py` — optional poller and its lifecycle;
  the existing monitor adapter and monitor JSON are unchanged.
- `agent/test_dynamic_ssh.py`, `agent/.env.example` — synchronization tests
  and opt-in settings.
- `README.md` and `deploy/README.md` — architecture, setup, rollback, safety
  gates, and deployment blockers.

The Cloudflare Worker handles the same-origin API endpoints directly, so no
Vercel API route is added for these paths. Cloudflare must proxy
`lapeace.amii.lol`; the Worker route in `cloudflare/wrangler.toml` is scoped to
`/api/dynamic-ssh*`. No CORS allowance is enabled. Registration POSTs must have
the same origin and a valid signed admin cookie. The browser never supplies the
authoritative IP.

### Secrets and persistence

Set these as **Cloudflare Worker secrets**, not in source control:

- `PANEL_ADMIN_ID` — must exactly match Vercel's admin ID.
- `PANEL_SESSION_SECRET` — must exactly match Vercel's session-signing secret
  (at least 32 bytes); this lets the Worker verify, not mint, the existing
  admin cookie.
- `DYNAMIC_SYNC_TOKEN` — independent random token of at least 32 characters;
  also set the identical value in the poller environment.
- `ACCOUNT_STORE_TOKEN` — independent random token of at least 32 characters;
  also set the identical value in Vercel. It protects account CRUD, login
  lookup, rate-limit, and audit-store routes from browser access.

`REGISTRATION_SOURCE` is a non-secret Worker variable. Dynamic-IP synchronization
adds no Vercel variables; the account-store variables are described below.
Registry records and the last
synchronization report persist in a Durable Object. They are not stored in
Vercel memory, its ephemeral filesystem, or the read-only monitor JSON.

The agent environment adds:

- `DYNAMIC_SSH_ENABLED=false` — poller starts only when explicitly true.
- `DYNAMIC_REGISTRY_API_URL` and `DYNAMIC_SYNC_STATUS_URL` — authenticated
  Worker endpoints.
- `DYNAMIC_SYNC_TOKEN` — same secret as the Worker.
- `DYNAMIC_IP_STATE_FILE` — separate local managed-exclusion state file; the
  default is `/var/lib/lapeace-agent/dynamic-ssh-managed.json`.
- `DYNAMIC_IP_PROTECTED` — comma-separated complete inventory of manual,
  AWG-endpoint, and otherwise protected exclusions. The project contains no
  hard-coded protected IP addresses; supply the current inventory locally.
- `DYNAMIC_IP_PROTECTED_INVENTORY_CONFIRMED=false` — must be explicitly set to
  `true` before the poller will make any API or WARP calls.

The last setting is a fail-closed deployment gate, not a way to discover
exclusions. The complete current manual exclusion inventory and the behavior of
`warp-cli tunnel ip add` for an already-present address have **not** been
verified on the VPS. Do not confirm the inventory or enable the poller until
those facts are checked by the administrator. The agent only removes an IP
whose address appears in its own managed-state file and whose registry record
is explicitly expired; absence from the API never causes removal. The monitor
and `/opt/lapeace/data/usage.json` are not written or restructured.

### Local checks and deployment outline

From `cloudflare/`, run `npm ci`, `npm run typecheck`, and `npm test`. Do not run
`wrangler deploy` until the implementation and VPS ownership concerns have
been reviewed. For an eventual deployment, configure the Durable Object binding
and scoped Worker route through Cloudflare, then set all listed Worker secrets
and deploy the Worker. Keep Vercel's existing login/session secrets
unchanged so the Worker can verify the same cookie.

For the eventual Worker setup, from `cloudflare/`:

```sh
npm ci
npm run typecheck
npm test
npx wrangler secret put PANEL_ADMIN_ID
npx wrangler secret put PANEL_SESSION_SECRET
npx wrangler secret put DYNAMIC_SYNC_TOKEN
npx wrangler secret put ACCOUNT_STORE_TOKEN
npx wrangler deploy
```

The secret commands prompt for values. Use the exact Vercel admin ID/session
secret, and set each bearer token to its matching Vercel or agent value.
Deployment is intentionally not performed as part of this local implementation.

The user-account feature is also local-only until the Worker secret is
configured and deployed. Generate an admin password hash locally with
`npm run hash-password` from `web/`; set only the resulting hash as
`PANEL_ADMIN_PASSWORD_HASH` in Vercel. Do not put an admin password or hash in
the repository. Set the same `ACCOUNT_STORE_TOKEN` as a Vercel environment
variable and Cloudflare Worker secret before testing account creation/login.

The admin account-management UI is available only in the signed admin session.
Creation validates usernames, passwords, peer IDs, and policy values; an
existing peer can be assigned to only one portal account. Deleting a portal
account does not revoke or alter its AWG peer. User-facing telemetry is reduced
server-side to the assigned peer's daily byte total, upload/download rates,
sample time, and configured daily quota. A malformed agent response is rejected.
The account store never sends password hashes to the browser.

### Multi-user portal — local implementation, not deployed

The Next.js app remains the authentication boundary for browser requests:

```text
Admin browser → Next.js signed session → admin-only /api/accounts*
                                     → ACCOUNT_STORE_TOKEN
                                     → Cloudflare Worker → Durable Object

User browser  → Next.js signed session → GET /api/panel/summary
                                     → assigned-account lookup
                                     → authenticated read-only VPS snapshot
                                     → sanitized per-peer response
```

The worker's `/api/account-store*` route accepts only the independent bearer
secret used by the Next.js server. It stores account records in the existing
Durable Object, including an scrypt hash, one assigned opaque peer ID,
administrator notes, status, and advisory policy fields. The browser receives
neither the account-store token nor password hashes. There is no user
registration route; account creation and administration require an admin
session and same-origin writes. Login attempts are limited to five per
normalized identifier per 15-minute window. The audit view prunes entries
older than three days.

User sessions can request only their assigned peer's daily total, current
upload/download speeds, sample timestamp, and daily quota. They cannot request
raw VPS snapshots, peer identifiers/IPs, global metrics, account lists, audit
events, or dynamic-IP management. Suspended or deleted accounts are rejected
when the user summary is requested. The user-facing portal explicitly labels
quotas and usage as informational; policy values do not enforce traffic or VPN
access.

The changed account-related files include:

- `web/lib/session.ts`, `web/lib/account-store.ts`, and `web/lib/accounts.ts`
  — signed role claims, scrypt verification, server-only store client, and
  shared record types.
- `web/app/api/auth/login/route.ts` — admin and user login through the
  persistent account store.
- `web/app/api/accounts/route.ts`,
  `web/app/api/accounts/[accountId]/route.ts`, and
  `web/app/api/accounts/audit/route.ts` — admin-only account and audit APIs.
- `web/app/api/panel/[...segments]/route.ts` — admin proxy allowlist and the
  user-only sanitized telemetry endpoint.
- `web/components/admin-accounts.tsx` and `web/components/dashboard.tsx` —
  account management and role-separated dashboards.
- `cloudflare/src/accounts.ts`, `cloudflare/src/worker.ts`, and
  `cloudflare/tests/accounts.test.mjs` — account validation, persistence,
  login throttling, audit retention, and focused validation tests.

Before deploying this feature, configure `ACCOUNT_STORE_API_URL` and
`ACCOUNT_STORE_TOKEN` in Vercel, and set the matching `ACCOUNT_STORE_TOKEN` as a
Cloudflare Worker secret. Keep `PANEL_ADMIN_PASSWORD_HASH` in Vercel only.
`PANEL_SESSION_SECRET` must match between Vercel and Cloudflare for the existing
Dynamic SSH admin-session verification. Do not
deploy until account creation, admin/user login, role separation, suspend,
delete, rate limiting, and the privacy of the user summary have been verified
in a non-production environment.

Run account Worker checks from `cloudflare/` with:

```sh
npm run typecheck
npm test
```

On the VPS, configure the agent process with the environment variables above,
but keep both opt-in settings false until the protected exclusion inventory,
`warp-cli` permissions/semantics, state-file owner/mode, and rollback plan are
verified. Do not modify the existing `lapeace-monitor` service or its JSON data.
No systemd unit is supplied because the current host service configuration
and correct privilege model have not been inspected. Use one poller instance
only.

If a WARP add command's outcome is uncertain, the agent preserves a
`pending_add` marker and refuses to retry it automatically. Reconcile that IP
against the actual WARP configuration and local state before resuming polling.

Rollback is fail-safe: first disable `DYNAMIC_SSH_ENABLED` for the Dynamic SSH
agent process so it stops polling; this retains the local state and current
WARP exclusions. Disable or remove only the scoped Cloudflare Worker route if
the web API needs to be withdrawn. Do not flush WARP exclusions or delete the
Durable Object/local state during rollback. Any removal of individual
agent-managed entries must be an explicit, reviewed operation using the state
file as the ownership record.

### Test/safety status and blockers

Automated tests cover pure Worker session/address/expiry/registration logic and
the agent's mocked polling, validation, expiry, retry/idempotency, protected-IP,
API/authentication failure, and command-failure behavior. They do not prove
Cloudflare production routing, Durable Object persistence after a deployment,
or real `warp-cli` behavior. A local Wrangler integration run exercised
authenticated registration/re-registration, unauthenticated rejection, private
IP rejection, poll/status routes, and persistence across a Worker restart. No
VPS was contacted and no Worker was deployed.

Before enabling/deploying, verify:

1. The full current manual and AWG endpoint exclusion inventory and add every
   protected entry to `DYNAMIC_IP_PROTECTED`.
2. Whether `warp-cli tunnel ip add <address>` fails or succeeds for an address
   already excluded manually. Without this, an existing unlisted exclusion
   could be claimed as feature-managed and later removed.
3. The exact local process identity and permissions needed for `warp-cli`, and
   secure ownership/mode for the state directory. Do not assume root is
   required or safe.
4. The Worker route and Durable Object migration on a non-production test
   domain/account, then separately verify the HTTPS/proxy topology for
   `lapeace.amii.lol`.
