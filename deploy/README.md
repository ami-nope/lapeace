# Deployment notes

See the root [README](../README.md) for the Vercel and read-only VPS adapter
instructions, plus the Dynamic SSH Manager architecture, environment variables,
rollback, safety gates, and deployment blockers.

No VPS systemd unit, reverse-proxy configuration, or WARP command has been
applied. The Dynamic SSH poller is disabled by default. Do not enable it until
the complete protected-exclusion inventory and `warp-cli` permission/duplicate
behavior have been verified on the target VPS.
