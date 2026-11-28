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

Accounting commit `316fb38` was merged into and pushed to `main` as `e2c3c81`. No deployment was performed. Existing accounts migrate lazily; traffic before their baseline is not backfilled. No Durable Object migration is required.

## Changed files

### VPS agent

- `agent/app.py` — sanitized per-peer daily counters/history in the read-only snapshot API.
- `agent/test_app.py` — telemetry API tests; this test file is not deployed to the VPS.

### Cloudflare Worker

- `cloudflare/src/accounts.ts`
- `cloudflare/src/worker.ts`
- `cloudflare/tests/accounts.test.mjs`

### Vercel website

- `web/app/api/accounts/route.ts`
- `web/app/api/accounts/[accountId]/route.ts`
- `web/app/api/panel/[...segments]/route.ts`
- `web/components/admin-accounts.tsx`
- `web/components/dashboard.tsx`
- `web/lib/agent-usage.ts`
- `web/lib/usage-accounting.ts`
- `web/package.json`
- `web/tests/usage-accounting.test.mjs`

### Documentation

- `README.md`
- `aliapeace.md`

## Complete VPS-agent diff

The only runtime file to copy to the VPS is `agent/app.py`. The test changes below stay in the repository.

```diff
diff --git a/agent/app.py b/agent/app.py
index 331fa82..50d52c4 100644
--- a/agent/app.py
+++ b/agent/app.py
@@ -19,7 +19,7 @@ from dynamic_ssh import dynamic_sync_loop

 INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
 FINGERPRINT_BYTES = 8
-HISTORY_DAYS = 14
+HISTORY_DAYS = 31
 IST = ZoneInfo("Asia/Kolkata")

 @asynccontextmanager
@@ -285,6 +285,8 @@ def _peer_output(record: dict[str, Any]) -> dict[str, Any]:
         "txBps": download_mbps * 1_000_000 / 8,
         "handshakeAt": _handshake_timestamp(record["latest_handshake"]),
         "todayBytes": daily_upload_bytes + daily_download_bytes,
+        "dailyUploadBytes": daily_upload_bytes,
+        "dailyDownloadBytes": daily_download_bytes,
     }


@@ -305,8 +307,11 @@ def _usage_counts(value: Any) -> tuple[int, int]:
     )


-def _history(daily_usage: dict[str, Any]) -> list[dict[str, Any]]:
-    totals: dict[str, dict[str, int]] = {}
+def _peer_usage_history(
+    daily_usage: dict[str, Any],
+) -> tuple[dict[str, dict[str, dict[str, int]]], set[str]]:
+    usage_by_peer: dict[str, dict[str, dict[str, int]]] = {}
+    dates: set[str] = set()
     for outer_key, outer_value in daily_usage.items():
         if not isinstance(outer_key, str) or not isinstance(outer_value, dict):
             raise ValueError("Monitor daily usage has an invalid entry.")
@@ -317,37 +322,83 @@ def _history(daily_usage: dict[str, Any]) -> list[dict[str, Any]]:
         except ValueError:
             is_date_key = False

-        entries = (
-            [(outer_key, peer_usage) for peer_usage in outer_value.values()]
-            if is_date_key
-            else [
-                (day, usage)
+        if is_date_key:
+            entries = [
+                (peer_key, outer_key, usage)
+                for peer_key, usage in outer_value.items()
+            ]
+        else:
+            entries = [
+                (outer_key, day, usage)
                 for day, usage in outer_value.items()
                 if isinstance(day, str)
             ]
-        )
-        for day, usage in entries:
+
+        for public_key, day, usage in entries:
             try:
                 date.fromisoformat(day)
             except ValueError as error:
                 if is_date_key:
                     raise ValueError("Monitor daily usage contains an invalid date.") from error
                 continue
+            if not isinstance(public_key, str):
+                raise ValueError("Monitor daily usage contains an invalid peer key.")
+            fingerprint(public_key)
             upload, download = _usage_counts(usage)
-            day_total = totals.setdefault(day, {"rxBytes": 0, "txBytes": 0})
-            day_total["rxBytes"] += upload
-            day_total["txBytes"] += download
+            dates.add(day)
+            peer_id = hashlib.sha256(public_key.encode("utf-8")).hexdigest()
+            usage_by_peer.setdefault(peer_id, {})[day] = {
+                "uploadBytes": upload,
+                "downloadBytes": download,
+            }
+    return usage_by_peer, dates

-    days = sorted(totals)[-HISTORY_DAYS:]
-    return [{"date": day, **totals[day]} for day in days]
+
+def _history(
+    usage_by_peer: dict[str, dict[str, dict[str, int]]],
+    dates: set[str],
+) -> list[dict[str, Any]]:
+    days = sorted(dates)[-HISTORY_DAYS:]
+    result: list[dict[str, Any]] = []
+    for day in days:
+        result.append({
+            "date": day,
+            "rxBytes": sum(
+                peer_days.get(day, {}).get("uploadBytes", 0)
+                for peer_days in usage_by_peer.values()
+            ),
+            "txBytes": sum(
+                peer_days.get(day, {}).get("downloadBytes", 0)
+                for peer_days in usage_by_peer.values()
+            ),
+        })
+    return result


 def build_dashboard_snapshot(document: dict[str, Any], interface_name: str) -> dict[str, Any]:
     try:
         source_peers = _snapshot_records(document["snapshot"])
         peers = [_peer_output(record) for record in source_peers]
-        history = _history(document["daily_usage"])
         sampled_at = _sample_time(document["last_sample"])
+        usage_by_peer, history_dates = _peer_usage_history(document["daily_usage"])
+        sampled_date = datetime.fromisoformat(sampled_at).astimezone(IST).date().isoformat()
+        if source_peers:
+            history_dates.add(sampled_date)
+        for peer, record in zip(peers, source_peers):
+            peer_days = usage_by_peer.setdefault(peer["id"], {})
+            peer_days[sampled_date] = {
+                "uploadBytes": peer["dailyUploadBytes"],
+                "downloadBytes": peer["dailyDownloadBytes"],
+            }
+            peer["usageHistory"] = [
+                {
+                    "date": day,
+                    **peer_days[day],
+                }
+                for day in sorted(history_dates)[-HISTORY_DAYS:]
+                if day in peer_days
+            ]
+        history = _history(usage_by_peer, history_dates)
     except (KeyError, TypeError, ValueError, OverflowError) as error:
         raise HTTPException(
             status_code=503, detail="Monitor state contains invalid telemetry."
@@ -365,6 +416,8 @@ def build_dashboard_snapshot(document: dict[str, Any], interface_name: str) -> d
         "interface": interface,
         "sampledAt": sampled_at,
         "peers": peers,
+        "historyStartDate": history[0]["date"] if history else None,
+        "historyEndDate": history[-1]["date"] if history else None,
         "history": history,
     }

diff --git a/agent/test_app.py b/agent/test_app.py
index cd5a684..2041643 100644
--- a/agent/test_app.py
+++ b/agent/test_app.py
@@ -1,4 +1,5 @@
 import base64
+from datetime import date, timedelta
 import json

 import pytest
@@ -134,6 +135,15 @@ def test_adapter_maps_multiple_peers_without_reversing_directions_and_does_not_w
     assert first["rxBps"] == pytest.approx(100_000)
     assert first["txBps"] == pytest.approx(200_000)
     assert first["todayBytes"] == 240
+    assert first["dailyUploadBytes"] == 80
+    assert first["dailyDownloadBytes"] == 160
+    assert first["usageHistory"] == [
+        {
+            "date": IST_DATE,
+            "uploadBytes": 80,
+            "downloadBytes": 160,
+        }
+    ]
     assert first["handshakeAt"] == 1795780800
     assert first["status"] == "connected"
     assert second["rxBytes"] == 240
@@ -145,6 +155,8 @@ def test_adapter_maps_multiple_peers_without_reversing_directions_and_does_not_w
     assert result["history"] == [
         {"date": IST_DATE, "rxBytes": 104, "txBytes": 208}
     ]
+    assert result["historyStartDate"] == IST_DATE
+    assert result["historyEndDate"] == IST_DATE
     assert public_key(12) not in response.text
     assert "must-not-be-exposed" not in response.text
     assert "198.51.100.10" not in response.text
@@ -221,6 +233,40 @@ def test_daily_usage_accepts_peer_keyed_history(tmp_path, monkeypatch):
     ]


+def test_snapshot_exposes_per_peer_month_history_without_public_keys(
+    tmp_path, monkeypatch
+):
+    peer = peer_snapshot(12, daily_upload=999, daily_download=300)
+    document = monitor_document([peer])
+    start = date.fromisoformat(IST_DATE) - timedelta(days=34)
+    document["daily_usage"] = {
+        peer["public_key"]: {
+            (start + timedelta(days=offset)).isoformat(): {
+                "upload_bytes": offset,
+                "download_bytes": offset * 2,
+            }
+            for offset in range(35)
+        }
+    }
+    path = tmp_path / "usage.json"
+    path.write_text(json.dumps(document), encoding="utf-8")
+    client, headers = authenticated_client(monkeypatch, path)
+
+    response = client.get("/api/v1/snapshot", headers=headers)
+
+    assert response.status_code == 200
+    result = response.json()
+    assert result["historyStartDate"] == "2026-10-28"
+    assert result["historyEndDate"] == IST_DATE
+    assert len(result["peers"][0]["usageHistory"]) == 31
+    assert result["peers"][0]["usageHistory"][-1] == {
+        "date": IST_DATE,
+        "uploadBytes": 999,
+        "downloadBytes": 300,
+    }
+    assert peer["public_key"] not in response.text
+
+
 def test_agent_operations_require_auth_and_mutations_stay_disabled(monkeypatch):
     monkeypatch.setenv("PANEL_API_TOKEN", TOKEN)
     client = TestClient(app)
```

## Windows PowerShell: push the feature branch

Commit `316fb38` already exists locally and is included in pushed `main`; no second commit is needed. The following pushes that same commit as a feature branch. Do not use `git add -A`: unrelated pre-existing `.gitignore` and Cloudflare config changes are intentionally unstaged.

```powershell
Set-Location C:\Users\amiya\Downloads\LaPeace
git switch fix/account-vpn-usage
git log -1 --oneline
git push -u origin fix/account-vpn-usage
```

## VPS: update only the adapter

These commands have not been run against the VPS. First confirm the unit really runs `/opt/lapeace/agent-app/app.py` (or imports `app:app` from that directory) and identify its configured loopback port. Stop if the unit points elsewhere. The documented default is `127.0.0.1:8765`; use the port shown by the actual unit.

From Windows PowerShell, replace the placeholder with the verified SSH destination:

```powershell
Set-Location C:\Users\amiya\Downloads\LaPeace
$Vps = 'USER@YOUR_VPS'
scp .\agent\app.py "${Vps}:/tmp/lapeace-agent-app.py"
```

On the VPS, inspect the unit and current file before changing anything:

```sh
sudo systemctl is-active lapeace-agent
sudo systemctl show lapeace-agent -p FragmentPath -p ExecStart -p User -p Group --no-pager
sudo stat -c '%U:%G %a %n' /opt/lapeace/agent-app/app.py
test -r /tmp/lapeace-agent-app.py
```

Only continue if those results confirm the expected service and app path. The following backs up the old adapter, installs only `app.py` with the existing ownership/mode, syntax-checks it, atomically replaces the file, and restarts only `lapeace-agent`:

```sh
set -eu
SERVICE=lapeace-agent
APP=/opt/lapeace/agent-app/app.py
INCOMING=/tmp/lapeace-agent-app.py
BACKUP="${APP}.pre-usage-$(date -u +%Y%m%dT%H%M%SZ)"
OWNER=$(stat -c '%u' "$APP")
GROUP=$(stat -c '%g' "$APP")
MODE=$(stat -c '%a' "$APP")

sudo cp -a "$APP" "$BACKUP"
sudo install -o "$OWNER" -g "$GROUP" -m "$MODE" "$INCOMING" "${APP}.new"
if ! sudo python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "${APP}.new"; then
  sudo rm -f "${APP}.new"
  exit 1
fi
sudo mv -f "${APP}.new" "$APP"
printf 'Backup saved as %s\n' "$BACKUP"
sudo systemctl restart "$SERVICE"
sudo systemctl is-active "$SERVICE"
sudo systemctl --no-pager --full status "$SERVICE"
```

If restart or verification fails, restore the printed backup path and restart only that unit:

```sh
sudo cp -a /opt/lapeace/agent-app/app.py.pre-usage-TIMESTAMP /opt/lapeace/agent-app/app.py
sudo systemctl restart lapeace-agent
sudo systemctl is-active lapeace-agent
```

For the API check, set `AGENT_URL` to the verified loopback URL. The token is entered without echo and is not placed in shell history. This prints only summary metadata, not peer identifiers:

```sh
AGENT_URL=http://127.0.0.1:8765/api/v1/snapshot
read -r -s -p 'Agent API token: ' PANEL_API_TOKEN; printf '\n'
export PANEL_API_TOKEN
python3 - "$AGENT_URL" <<'PY'
import json, os, sys
from urllib.request import Request, urlopen

request = Request(
    sys.argv[1],
    headers={"Authorization": "Bearer " + os.environ["PANEL_API_TOKEN"]},
)
with urlopen(request, timeout=8) as response:
    data = json.load(response)
required = {"sampledAt", "historyStartDate", "historyEndDate", "peers"}
assert required.issubset(data), "snapshot lacks required history metadata"
for peer in data["peers"]:
    assert {"dailyUploadBytes", "dailyDownloadBytes", "usageHistory"}.issubset(peer)
    for day in peer["usageHistory"]:
        assert {"date", "uploadBytes", "downloadBytes"}.issubset(day)
print(
    "OK: sampledAt={}, history={}..{}, peers={}".format(
        data["sampledAt"], data["historyStartDate"], data["historyEndDate"],
        len(data["peers"]),
    )
)
PY
RESULT=$?
unset PANEL_API_TOKEN
test "$RESULT" -eq 0
```

## Safety scope

No code changes to `monitor.py`, `usage.json`, AWG, WARP, firewall rules, routing, or other system services are required. The adapter reads the existing monitor data only; the sole service restart above is `lapeace-agent`. Monthly reporting requires the existing monitor history to cover the needed month; if it does not, the website reports telemetry unavailable rather than fabricating a total. No VPS command or deployment has been executed by this assistant.
