import asyncio
import ipaddress
import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import httpx

POLL_INTERVAL_SECONDS = 10
REQUEST_TIMEOUT_SECONDS = 5
COMMAND_TIMEOUT_SECONDS = 10
EXPIRATION_AGE = timedelta(days=15)
STATE_VERSION = 1

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


class SyncFailure(Exception):
    pass


def _utc_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise SyncFailure(f"Registry {field} is invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SyncFailure(f"Registry {field} is invalid.") from error
    if parsed.tzinfo is None:
        raise SyncFailure(f"Registry {field} must include a timezone.")
    return parsed.astimezone(timezone.utc)


def validate_public_ipv4(value: Any) -> str:
    if not isinstance(value, str):
        raise SyncFailure("Registry contains a non-string IP address.")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise SyncFailure("Registry contains an invalid IP address.") from error
    if not isinstance(parsed, ipaddress.IPv4Address) or not parsed.is_global:
        raise SyncFailure("Registry contains a non-public IPv4 address.")
    return str(parsed)


def validate_registry(payload: Any, now: datetime) -> list[dict[str, Any]]:
    if (
        not isinstance(payload, dict)
        or payload.get("version") != 1
        or not isinstance(payload.get("generatedAt"), str)
        or not isinstance(payload.get("records"), list)
    ):
        raise SyncFailure("Registry response has an invalid format.")

    generated_at = _utc_datetime(payload["generatedAt"], "generation time")
    if generated_at > now + timedelta(minutes=5):
        raise SyncFailure("Registry response is from the future.")

    records: list[dict[str, Any]] = []
    seen_ips: set[str] = set()
    for record in payload["records"]:
        if not isinstance(record, dict):
            raise SyncFailure("Registry contains an invalid record.")
        ip = validate_public_ipv4(record.get("ip"))
        if ip in seen_ips:
            raise SyncFailure("Registry contains duplicate IP addresses.")
        seen_ips.add(ip)

        first_registered = _utc_datetime(
            record.get("firstRegisteredAt"), "first registration time"
        )
        last_used = _utc_datetime(record.get("lastUsedAt"), "last-used time")
        if last_used < first_registered or last_used > now + timedelta(minutes=5):
            raise SyncFailure("Registry contains invalid registration timestamps.")
        source = record.get("registrationSource")
        if not isinstance(source, str) or not source or len(source) > 80:
            raise SyncFailure("Registry contains an invalid registration source.")

        expired = now - last_used > EXPIRATION_AGE
        expected_status = "expired" if expired else "active"
        if record.get("status") != expected_status:
            raise SyncFailure("Registry expiration status does not match its timestamp.")
        records.append(
            {
                "ip": ip,
                "firstRegisteredAt": first_registered.isoformat(),
                "lastUsedAt": last_used.isoformat(),
                "registrationSource": source,
                "status": expected_status,
            }
        )
    return records


def _empty_state() -> dict[str, Any]:
    return {"version": STATE_VERSION, "managed_ips": {}, "pending_add": {}, "pending_remove": {}}


def _read_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty_state()
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SyncFailure("Local managed-IP state is unavailable or malformed.") from error
    if (
        not isinstance(state, dict)
        or state.get("version") != STATE_VERSION
        or not isinstance(state.get("managed_ips"), dict)
        or not isinstance(state.get("pending_add"), dict)
        or not isinstance(state.get("pending_remove"), dict)
    ):
        raise SyncFailure("Local managed-IP state has an invalid format.")
    for section in ("managed_ips", "pending_add", "pending_remove"):
        for address in state[section]:
            validate_public_ipv4(address)
    return state


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".dynamic-ssh-", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as file:
            os.fchmod(file.fileno(), 0o600)
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _save_state(path: Path, state: dict[str, Any]) -> None:
    encoded = json.dumps(state, separators=(",", ":"), sort_keys=True).encode("utf-8")
    try:
        if path.exists():
            previous = path.read_bytes()
            _atomic_write(path.with_suffix(path.suffix + ".bak"), previous)
        _atomic_write(path, encoded)
    except OSError as error:
        raise SyncFailure("Could not persist managed-IP state.") from error


def _protected_ips() -> set[str]:
    configured = os.environ.get("DYNAMIC_IP_PROTECTED", "")
    protected: set[str] = set()
    for value in configured.split(","):
        address = value.strip()
        if address:
            protected.add(validate_public_ipv4(address))
    if not protected:
        raise SyncFailure("Protected exclusion inventory is not configured.")
    return protected


def _run_warp_command(
    action: str,
    address: str,
    command_runner: CommandRunner,
) -> None:
    if action not in {"add", "remove"}:
        raise SyncFailure("Invalid WARP operation.")
    validate_public_ipv4(address)
    try:
        result = command_runner(
            ["warp-cli", "tunnel", "ip", action, address],
            check=False,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SyncFailure(f"WARP {action} command could not be completed.") from error
    if result.returncode != 0:
        raise SyncFailure(f"WARP {action} command failed.")


async def _post_report(
    client: httpx.AsyncClient,
    url: str,
    token: str,
    report: dict[str, Any],
) -> None:
    try:
        await client.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json=report,
        )
    except httpx.HTTPError:
        return


async def sync_once(
    client: httpx.AsyncClient | None = None,
    *,
    now: datetime | None = None,
    state_path: Path | None = None,
    command_runner: CommandRunner | None = None,
) -> dict[str, Any]:
    registry_url = os.environ.get(
        "DYNAMIC_REGISTRY_API_URL",
        "https://lapeace.amii.lol/api/dynamic-ssh/sync/registry",
    )
    status_url = os.environ.get(
        "DYNAMIC_SYNC_STATUS_URL",
        "https://lapeace.amii.lol/api/dynamic-ssh/sync/status",
    )
    token = os.environ.get("DYNAMIC_SYNC_TOKEN", "")
    path = state_path or Path(
        os.environ.get(
            "DYNAMIC_IP_STATE_FILE",
            "/var/lib/lapeace-agent/dynamic-ssh-managed.json",
        )
    )
    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    runner = command_runner or subprocess.run
    if os.environ.get("DYNAMIC_IP_PROTECTED_INVENTORY_CONFIRMED", "").lower() != "true":
        return {
            "status": "error",
            "added": 0,
            "removed": 0,
            "message": "Complete protected-exclusion inventory is not confirmed.",
        }
    try:
        protected = _protected_ips()
    except SyncFailure as error:
        return {
            "status": "error",
            "added": 0,
            "removed": 0,
            "message": str(error),
        }
    if len(token) < 32:
        return {"status": "error", "added": 0, "removed": 0, "message": "Sync token is not configured."}

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS, verify=True)
    added = 0
    removed = 0
    result: dict[str, Any]
    try:
        try:
            response = await http.get(
                registry_url,
                headers={"Authorization": f"Bearer {token}"},
            )
            if response.status_code != 200:
                raise SyncFailure(f"Registry returned HTTP {response.status_code}.")
            records = validate_registry(response.json(), current_time)
            state = _read_state(path)
        except (httpx.HTTPError, ValueError, SyncFailure) as error:
            result = {
                "status": "error",
                "added": 0,
                "removed": 0,
                "message": str(error)[:240],
            }
            await _post_report(http, status_url, token, result)
            return result

        if state["pending_add"]:
            result = {
                "status": "degraded",
                "added": 0,
                "removed": 0,
                "message": "A previous WARP add has an uncertain outcome; reconcile local state before retrying.",
            }
            await _post_report(http, status_url, token, result)
            return result

        if not path.exists():
            try:
                _save_state(path, state)
            except SyncFailure as error:
                result = {"status": "error", "added": 0, "removed": 0, "message": str(error)}
                await _post_report(http, status_url, token, result)
                return result

        by_ip = {record["ip"]: record for record in records}
        try:
            for record in records:
                address = record["ip"]
                if record["status"] != "active" or address in protected:
                    continue
                if address in state["managed_ips"]:
                    continue

                state["pending_add"].setdefault(
                    address, {"requestedAt": current_time.isoformat()}
                )
                _save_state(path, state)
                _run_warp_command("add", address, runner)
                state["managed_ips"][address] = {
                    "addedAt": current_time.isoformat(),
                    "registrationSource": record["registrationSource"],
                }
                state["pending_add"].pop(address, None)
                state["pending_remove"].pop(address, None)
                _save_state(path, state)
                added += 1

            for address in list(state["managed_ips"]):
                record = by_ip.get(address)
                if (
                    record is None
                    or record["status"] != "expired"
                    or address in protected
                ):
                    continue

                state["pending_remove"].setdefault(
                    address, {"requestedAt": current_time.isoformat()}
                )
                _save_state(path, state)
                _run_warp_command("remove", address, runner)
                state["managed_ips"].pop(address, None)
                state["pending_remove"].pop(address, None)
                _save_state(path, state)
                removed += 1
        except SyncFailure as error:
            result = {
                "status": "degraded",
                "added": added,
                "removed": removed,
                "message": str(error)[:240],
            }
            await _post_report(http, status_url, token, result)
            return result

        result = {
            "status": "ok",
            "added": added,
            "removed": removed,
            "message": "Dynamic IP synchronization completed.",
        }
        await _post_report(http, status_url, token, result)
        return result
    finally:
        if owns_client:
            await http.aclose()


async def dynamic_sync_loop() -> None:
    while True:
        await sync_once()
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
