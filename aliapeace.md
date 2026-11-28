# Per-account VPN usage changes

## What changed

- New accounts capture their assigned peer’s current upload/download counters and telemetry timestamp as an accounting baseline.
- Existing accounts receive a safe baseline on their first current-day telemetry request. Earlier traffic is not charged; WireGuard counters and monitor history are not reset.
- Daily usage is calculated in the `Asia/Kolkata` calendar day. Monthly upload, download, and combined usage use the current IST calendar month.
- Peer reassignment closes the previous assignment period with final counters and starts a new period. The account store prevents duplicate peer assignments and retains prior assignment history.
- The agent API exposes sanitized per-peer daily history. Incomplete history or missing peer telemetry is reported as unavailable instead of zero.
- The user dashboard displays today’s total, upload and download, monthly total, separate daily/monthly quota and remaining amounts, sample time in IST, and consistent binary units. Quotas remain informational only.

## Validation

- Next.js typecheck and production build passed.
- Cloudflare Worker typecheck and tests passed (10 tests).
- Accounting tests passed (9 tests).
- Agent tests passed (21 tests).

## Deployment

Changes are on local branch `fix/account-vpn-usage`; nothing was committed, pushed, or deployed. Deploy the updated agent adapter first, then the Cloudflare Worker from `cloudflare/` with `npm run deploy`, then the reviewed Vercel app with Root Directory `web`. No Durable Object migration is required. Existing accounts migrate lazily; no traffic before their new baseline is backfilled. The live VPS, `monitor.py`, `usage.json`, AWG/WARP, routing, firewall, and networking services were not changed.
