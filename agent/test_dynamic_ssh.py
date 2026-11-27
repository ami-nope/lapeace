import asyncio
import json
import subprocess
from datetime import datetime, timedelta, timezone

import httpx

from dynamic_ssh import sync_once


TOKEN = "dynamic-sync-token-that-is-at-least-32-characters"
NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
REGISTRY_URL = "https://lapeace.amii.lol/api/dynamic-ssh/sync/registry"
STATUS_URL = "https://lapeace.amii.lol/api/dynamic-ssh/sync/status"


def registry_record(ip, last_used, status):
    return {
        "ip": ip,
        "firstRegisteredAt": (last_used - timedelta(days=1)).isoformat(),
        "lastUsedAt": last_used.isoformat(),
        "registrationSource": "cloudflare-edge",
        "status": status,
    }


def registry(records, generated_at=NOW):
    return {
        "version": 1,
        "generatedAt": generated_at.isoformat(),
        "records": records,
    }


def make_client(payload, status_code=200, status_reports=None):
    reports = status_reports if status_reports is not None else []

    def handler(request):
        assert request.headers.get("authorization") == f"Bearer {TOKEN}"
        if request.method == "GET" and request.url.path.endswith("/registry"):
            return httpx.Response(status_code, json=payload)
        if request.method == "POST" and request.url.path.endswith("/status"):
            reports.append(json.loads(request.content))
            return httpx.Response(200, json={"accepted": True})
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), reports


def run_sync(client, **kwargs):
    async def execute():
        try:
            return await sync_once(client, now=NOW, **kwargs)
        finally:
            await client.aclose()

    return asyncio.run(execute())


def configure(monkeypatch, path):
    monkeypatch.setenv("DYNAMIC_SYNC_TOKEN", TOKEN)
    monkeypatch.setenv("DYNAMIC_REGISTRY_API_URL", REGISTRY_URL)
    monkeypatch.setenv("DYNAMIC_SYNC_STATUS_URL", STATUS_URL)
    monkeypatch.setenv("DYNAMIC_IP_PROTECTED", "9.9.9.9")
    monkeypatch.setenv("DYNAMIC_IP_PROTECTED_INVENTORY_CONFIRMED", "true")
    return path


def success_command(calls):
    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "added", "")

    return run


def test_sync_adds_active_ip_and_removes_only_expired_managed_ip(
    tmp_path, monkeypatch
):
    path = configure(monkeypatch, tmp_path / "dynamic.json")
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "managed_ips": {
                    "1.1.1.1": {
                        "addedAt": (NOW - timedelta(days=20)).isoformat(),
                        "registrationSource": "cloudflare-edge",
                    }
                },
                "pending_add": {},
                "pending_remove": {},
            }
        ),
        encoding="utf-8",
    )
    payload = registry(
        [
            registry_record("8.8.8.8", NOW - timedelta(hours=1), "active"),
            registry_record("1.1.1.1", NOW - timedelta(days=16), "expired"),
        ]
    )
    client, reports = make_client(payload)
    calls = []

    result = run_sync(client, state_path=path, command_runner=success_command(calls))

    assert result == {
        "status": "ok",
        "added": 1,
        "removed": 1,
        "message": "Dynamic IP synchronization completed.",
    }
    assert calls == [
        ["warp-cli", "tunnel", "ip", "add", "8.8.8.8"],
        ["warp-cli", "tunnel", "ip", "remove", "1.1.1.1"],
    ]
    state = json.loads(path.read_text(encoding="utf-8"))
    assert set(state["managed_ips"]) == {"8.8.8.8"}
    assert state["pending_add"] == {}
    assert state["pending_remove"] == {}
    assert (tmp_path / "dynamic.json.bak").exists()
    assert reports[-1]["status"] == "ok"


def test_duplicate_poll_does_not_repeat_add(tmp_path, monkeypatch):
    path = configure(monkeypatch, tmp_path / "dynamic.json")
    payload = registry(
        [registry_record("8.8.8.8", NOW - timedelta(hours=1), "active")]
    )
    calls = []
    runner = success_command(calls)

    first_client, _ = make_client(payload)
    first = run_sync(first_client, state_path=path, command_runner=runner)
    second_client, _ = make_client(payload)
    second = run_sync(second_client, state_path=path, command_runner=runner)

    assert first["added"] == 1
    assert second["added"] == 0
    assert calls == [["warp-cli", "tunnel", "ip", "add", "8.8.8.8"]]


def test_api_unavailable_retains_state_and_runs_no_warp_command(tmp_path, monkeypatch):
    path = configure(monkeypatch, tmp_path / "dynamic.json")
    original = b'{"version":1,"managed_ips":{},"pending_add":{},"pending_remove":{}}'
    path.write_bytes(original)
    client, reports = make_client({}, status_code=503)
    calls = []

    result = run_sync(client, state_path=path, command_runner=success_command(calls))

    assert result["status"] == "error"
    assert result["added"] == result["removed"] == 0
    assert calls == []
    assert path.read_bytes() == original
    assert reports[-1]["status"] == "error"


def test_unconfirmed_protected_inventory_fails_closed_before_api_or_warp(
    tmp_path, monkeypatch
):
    path = configure(monkeypatch, tmp_path / "dynamic.json")
    monkeypatch.setenv("DYNAMIC_IP_PROTECTED_INVENTORY_CONFIRMED", "false")
    client, _ = make_client(registry([]))
    calls = []

    result = run_sync(client, state_path=path, command_runner=success_command(calls))

    assert result["status"] == "error"
    assert "inventory is not confirmed" in result["message"]
    assert calls == []
    assert not path.exists()


def test_missing_protected_inventory_fails_closed_before_api_or_warp(
    tmp_path, monkeypatch
):
    path = configure(monkeypatch, tmp_path / "dynamic.json")
    monkeypatch.setenv("DYNAMIC_IP_PROTECTED", "")
    client, reports = make_client(registry([]))
    calls = []

    result = run_sync(client, state_path=path, command_runner=success_command(calls))

    assert result["status"] == "error"
    assert "inventory is not configured" in result["message"]
    assert calls == []
    assert reports == []
    assert not path.exists()


def test_authentication_failure_makes_no_warp_changes(tmp_path, monkeypatch):
    path = configure(monkeypatch, tmp_path / "dynamic.json")
    client, reports = make_client({}, status_code=401)
    calls = []

    result = run_sync(client, state_path=path, command_runner=success_command(calls))

    assert result["status"] == "error"
    assert calls == []
    assert not path.exists()
    assert reports[-1]["status"] == "error"


def test_invalid_registry_address_rejects_entire_update(tmp_path, monkeypatch):
    path = configure(monkeypatch, tmp_path / "dynamic.json")
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "managed_ips": {},
                "pending_add": {},
                "pending_remove": {},
            }
        ),
        encoding="utf-8",
    )
    original = path.read_bytes()
    payload = registry(
        [
            registry_record("8.8.8.8", NOW - timedelta(hours=1), "active"),
            registry_record("10.0.0.2", NOW - timedelta(hours=1), "active"),
        ]
    )
    client, _ = make_client(payload)
    calls = []

    result = run_sync(client, state_path=path, command_runner=success_command(calls))

    assert result["status"] == "error"
    assert calls == []
    assert path.read_bytes() == original


def test_protected_manual_exclusions_are_never_added_or_removed(tmp_path, monkeypatch):
    path = configure(monkeypatch, tmp_path / "dynamic.json")
    monkeypatch.setenv("DYNAMIC_IP_PROTECTED", "8.8.8.8,1.1.1.1")
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "managed_ips": {
                    "8.8.8.8": {
                        "addedAt": (NOW - timedelta(days=20)).isoformat(),
                        "registrationSource": "old-state",
                    },
                    "1.1.1.1": {
                        "addedAt": (NOW - timedelta(days=20)).isoformat(),
                        "registrationSource": "old-state",
                    },
                },
                "pending_add": {},
                "pending_remove": {},
            }
        ),
        encoding="utf-8",
    )
    payload = registry(
        [
            registry_record("8.8.8.8", NOW - timedelta(days=16), "expired"),
            registry_record("1.1.1.1", NOW - timedelta(days=16), "expired"),
        ]
    )
    client, _ = make_client(payload)
    calls = []

    result = run_sync(client, state_path=path, command_runner=success_command(calls))

    assert result["status"] == "ok"
    assert result["removed"] == 0
    assert calls == []
    state = json.loads(path.read_text(encoding="utf-8"))
    assert len(state["managed_ips"]) == 2


def test_fifteen_days_is_not_expired_but_more_than_fifteen_days_is():
    from dynamic_ssh import validate_registry

    exactly_fifteen_days = registry_record(
        "8.8.8.8", NOW - timedelta(days=15), "active"
    )
    over_fifteen_days = registry_record(
        "1.1.1.1", NOW - timedelta(days=15, seconds=1), "expired"
    )

    records = validate_registry(
        registry([exactly_fifteen_days, over_fifteen_days]), NOW
    )

    assert [record["status"] for record in records] == ["active", "expired"]


def test_warp_failure_keeps_managed_registry_and_reports_degraded(
    tmp_path, monkeypatch
):
    path = configure(monkeypatch, tmp_path / "dynamic.json")
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "managed_ips": {},
                "pending_add": {},
                "pending_remove": {},
            }
        ),
        encoding="utf-8",
    )
    payload = registry(
        [registry_record("8.8.8.8", NOW - timedelta(hours=1), "active")]
    )
    client, reports = make_client(payload)
    calls = []

    def failing_command(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1, "", "failure")

    result = run_sync(client, state_path=path, command_runner=failing_command)

    assert result["status"] == "degraded"
    assert calls == [["warp-cli", "tunnel", "ip", "add", "8.8.8.8"]]
    state = json.loads(path.read_text(encoding="utf-8"))
    assert state["managed_ips"] == {}
    assert "8.8.8.8" in state["pending_add"]
    assert reports[-1]["status"] == "degraded"


def test_uncertain_pending_add_is_not_retried_automatically(tmp_path, monkeypatch):
    path = configure(monkeypatch, tmp_path / "dynamic.json")
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "managed_ips": {},
                "pending_add": {
                    "8.8.8.8": {"requestedAt": (NOW - timedelta(minutes=1)).isoformat()}
                },
                "pending_remove": {},
            }
        ),
        encoding="utf-8",
    )
    client, reports = make_client(
        registry([registry_record("8.8.8.8", NOW, "active")])
    )
    calls = []

    result = run_sync(client, state_path=path, command_runner=success_command(calls))

    assert result["status"] == "degraded"
    assert "uncertain outcome" in result["message"]
    assert calls == []
    assert "8.8.8.8" in json.loads(path.read_text(encoding="utf-8"))["pending_add"]
    assert reports[-1]["status"] == "degraded"


def test_registry_rejects_duplicate_ips_before_any_warp_command(tmp_path, monkeypatch):
    path = configure(monkeypatch, tmp_path / "dynamic.json")
    payload = registry(
        [
            registry_record("8.8.8.8", NOW - timedelta(hours=1), "active"),
            registry_record("8.8.8.8", NOW - timedelta(hours=1), "active"),
        ]
    )
    client, _ = make_client(payload)
    calls = []

    result = run_sync(client, state_path=path, command_runner=success_command(calls))

    assert result["status"] == "error"
    assert calls == []
    assert not path.exists()
