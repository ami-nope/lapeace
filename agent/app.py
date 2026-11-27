import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib
import hmac
import json
import math
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from dynamic_ssh import dynamic_sync_loop

INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
FINGERPRINT_BYTES = 8
HISTORY_DAYS = 14
IST = ZoneInfo("Asia/Kolkata")

@asynccontextmanager
async def lifespan(application: FastAPI):
    task = None
    if os.environ.get("DYNAMIC_SSH_ENABLED", "").lower() == "true":
        task = asyncio.create_task(dynamic_sync_loop())
        application.state.dynamic_sync_task = task
    try:
        yield
    finally:
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


app = FastAPI(
    title="Amii VPN Agent",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


class AddPeerRequest(BaseModel):
    label: str = Field(min_length=1, max_length=48, pattern=r"^[A-Za-z0-9 _.-]+$")
    daily_limit_bytes: int | None = Field(default=None, ge=1)
    upload_limit_bps: int | None = Field(default=None, ge=1)
    download_limit_bps: int | None = Field(default=None, ge=1)


def settings() -> tuple[str, Path, str]:
    token = os.environ.get("PANEL_API_TOKEN", "")
    interface = os.environ.get("AWG_INTERFACE", "awg0")
    monitor_file = Path(
        os.environ.get("MONITOR_STATE_FILE", "/opt/lapeace/data/usage.json")
    )
    if len(token) < 32:
        raise HTTPException(status_code=503, detail="Agent API token is not configured.")
    if not INTERFACE_PATTERN.fullmatch(interface):
        raise HTTPException(status_code=503, detail="Configured interface name is invalid.")
    return token, monitor_file, interface


def require_token(authorization: str | None = Header(default=None)) -> None:
    token, _, _ = settings()
    supplied = ""
    if authorization and authorization.startswith("Bearer "):
        supplied = authorization[7:]
    if not hmac.compare_digest(supplied, token):
        raise HTTPException(status_code=401, detail="Authentication required.")


def fingerprint(public_key: str) -> str:
    try:
        raw_key = base64.b64decode(public_key, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("Invalid public key in peer snapshot.") from error
    if len(raw_key) != 32:
        raise ValueError("Unexpected public key length in peer snapshot.")
    return hashlib.sha256(raw_key).hexdigest()[: FINGERPRINT_BYTES * 2]


def parse_awg_dump(output: str, now: int | None = None) -> list[dict[str, Any]]:
    sampled_at = int(datetime.now(timezone.utc).timestamp()) if now is None else now
    lines = output.splitlines()
    if not lines or len(lines[0].split("\t")) < 4:
        raise ValueError("AWG returned an empty interface dump.")

    peers: list[dict[str, Any]] = []
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            raise ValueError("AWG returned an incomplete peer record.")
        public_key, _preshared_key, _endpoint, allowed_ips = fields[:4]
        try:
            handshake_at = int(fields[4])
            rx_bytes = int(fields[5])
            tx_bytes = int(fields[6])
        except ValueError as error:
            raise ValueError("AWG returned invalid peer counters.") from error

        peers.append(
            {
                "id": hashlib.sha256(public_key.encode("ascii")).hexdigest(),
                "fingerprint": fingerprint(public_key),
                "allowedIps": [item for item in allowed_ips.split(",") if item],
                "status": (
                    "connected"
                    if handshake_at > 0
                    and sampled_at - handshake_at
                    <= int(os.environ.get("HANDSHAKE_FRESH_SECONDS", "180"))
                    else "idle"
                ),
                "handshakeAt": handshake_at or None,
                "rxBytes": rx_bytes,
                "txBytes": tx_bytes,
            }
        )
    return peers


def _read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as monitor_file:
            document = json.load(monitor_file)
    except FileNotFoundError as error:
        raise HTTPException(status_code=503, detail="Monitor state file is missing.") from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=503, detail="Monitor state file is unavailable or malformed."
        ) from error

    if not isinstance(document, dict):
        raise HTTPException(status_code=503, detail="Monitor state has an invalid format.")
    required = {"version", "last_sample", "peers", "daily_usage", "snapshot"}
    if not required.issubset(document):
        raise HTTPException(status_code=503, detail="Monitor state is missing required fields.")
    if not isinstance(document["peers"], (dict, list)):
        raise HTTPException(status_code=503, detail="Monitor peer counters have an invalid format.")
    if not isinstance(document["daily_usage"], dict):
        raise HTTPException(status_code=503, detail="Monitor daily usage has an invalid format.")
    return document


def _sample_time(value: Any) -> str:
    if isinstance(value, bool):
        raise ValueError("Invalid monitor sample time.")
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError("Invalid monitor sample time.")
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    if not isinstance(value, str) or not value:
        raise ValueError("Invalid monitor sample time.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Invalid monitor sample time.") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=IST)
    return parsed.isoformat()


def _snapshot_records(snapshot: Any) -> list[dict[str, Any]]:
    if isinstance(snapshot, list):
        records = [(None, item) for item in snapshot]
    elif isinstance(snapshot, dict):
        if "peers" in snapshot:
            peers = snapshot["peers"]
            if isinstance(peers, list):
                records = [(None, item) for item in peers]
            elif isinstance(peers, dict):
                records = list(peers.items())
            else:
                raise ValueError("Monitor snapshot peers have an invalid format.")
        elif not snapshot:
            records = []
        elif "public_key" in snapshot:
            records = [(None, snapshot)]
        else:
            records = list(snapshot.items())
    else:
        raise ValueError("Monitor snapshot has an invalid format.")

    result: list[dict[str, Any]] = []
    for key, record in records:
        if not isinstance(record, dict):
            raise ValueError("Monitor snapshot contains an invalid peer.")
        peer = dict(record)
        if "public_key" not in peer and isinstance(key, str):
            peer["public_key"] = key
        result.append(peer)
    return result


def _number(value: Any, field: str, *, integer: bool = False) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Invalid monitor peer field: {field}.")
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"Invalid monitor peer field: {field}.")
    if integer and not isinstance(value, int):
        raise ValueError(f"Invalid monitor peer field: {field}.")
    return value


def _handshake_timestamp(value: Any) -> int | None:
    if value is None or value == 0:
        return None
    if isinstance(value, bool):
        raise ValueError("Invalid latest handshake.")
    if isinstance(value, (int, float)):
        if not math.isfinite(value) or value < 0:
            raise ValueError("Invalid latest handshake.")
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as error:
                raise ValueError("Invalid latest handshake.") from error
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=IST)
            return int(parsed.timestamp())
    raise ValueError("Invalid latest handshake.")


def _peer_output(record: dict[str, Any]) -> dict[str, Any]:
    required = {
        "public_key",
        "ips",
        "upload_bytes",
        "download_bytes",
        "latest_handshake",
        "upload_mbps",
        "download_mbps",
        "connected",
        "daily_upload_bytes",
        "daily_download_bytes",
    }
    if not required.issubset(record):
        raise ValueError("Monitor snapshot peer is missing required fields.")
    public_key = record["public_key"]
    if not isinstance(public_key, str) or not public_key:
        raise ValueError("Monitor snapshot peer has an invalid public key.")

    ips = record["ips"]
    if isinstance(ips, str):
        allowed_ips = [item.strip() for item in ips.split(",") if item.strip()]
    elif isinstance(ips, list) and all(isinstance(item, str) for item in ips):
        allowed_ips = ips
    else:
        raise ValueError("Monitor snapshot peer has invalid IP information.")

    connected = record["connected"]
    if not isinstance(connected, bool):
        raise ValueError("Monitor snapshot peer has an invalid connection status.")

    upload_bytes = int(_number(record["upload_bytes"], "upload_bytes", integer=True))
    download_bytes = int(_number(record["download_bytes"], "download_bytes", integer=True))
    upload_mbps = float(_number(record["upload_mbps"], "upload_mbps"))
    download_mbps = float(_number(record["download_mbps"], "download_mbps"))
    daily_upload_bytes = int(
        _number(record["daily_upload_bytes"], "daily_upload_bytes", integer=True)
    )
    daily_download_bytes = int(
        _number(record["daily_download_bytes"], "daily_download_bytes", integer=True)
    )

    return {
        "id": hashlib.sha256(public_key.encode("utf-8")).hexdigest(),
        "fingerprint": fingerprint(public_key),
        "allowedIps": allowed_ips,
        "status": "connected" if connected else "idle",
        "rxBytes": upload_bytes,
        "txBytes": download_bytes,
        "rxBps": upload_mbps * 1_000_000 / 8,
        "txBps": download_mbps * 1_000_000 / 8,
        "handshakeAt": _handshake_timestamp(record["latest_handshake"]),
        "todayBytes": daily_upload_bytes + daily_download_bytes,
    }


def _usage_counts(value: Any) -> tuple[int, int]:
    if not isinstance(value, dict):
        raise ValueError("Monitor daily usage entry has an invalid format.")
    upload = value.get(
        "upload_bytes", value.get("daily_upload_bytes", value.get("upload"))
    )
    download = value.get(
        "download_bytes", value.get("daily_download_bytes", value.get("download"))
    )
    if upload is None or download is None:
        raise ValueError("Monitor daily usage entry is missing upload/download counters.")
    return (
        int(_number(upload, "daily upload", integer=True)),
        int(_number(download, "daily download", integer=True)),
    )


def _history(daily_usage: dict[str, Any]) -> list[dict[str, Any]]:
    totals: dict[str, dict[str, int]] = {}
    for outer_key, outer_value in daily_usage.items():
        if not isinstance(outer_key, str) or not isinstance(outer_value, dict):
            raise ValueError("Monitor daily usage has an invalid entry.")

        try:
            date.fromisoformat(outer_key)
            is_date_key = True
        except ValueError:
            is_date_key = False

        entries = (
            [(outer_key, peer_usage) for peer_usage in outer_value.values()]
            if is_date_key
            else [
                (day, usage)
                for day, usage in outer_value.items()
                if isinstance(day, str)
            ]
        )
        for day, usage in entries:
            try:
                date.fromisoformat(day)
            except ValueError as error:
                if is_date_key:
                    raise ValueError("Monitor daily usage contains an invalid date.") from error
                continue
            upload, download = _usage_counts(usage)
            day_total = totals.setdefault(day, {"rxBytes": 0, "txBytes": 0})
            day_total["rxBytes"] += upload
            day_total["txBytes"] += download

    days = sorted(totals)[-HISTORY_DAYS:]
    return [{"date": day, **totals[day]} for day in days]


def build_dashboard_snapshot(document: dict[str, Any], interface_name: str) -> dict[str, Any]:
    try:
        source_peers = _snapshot_records(document["snapshot"])
        peers = [_peer_output(record) for record in source_peers]
        history = _history(document["daily_usage"])
        sampled_at = _sample_time(document["last_sample"])
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        raise HTTPException(
            status_code=503, detail="Monitor state contains invalid telemetry."
        ) from error

    interface = {
        "name": interface_name,
        "status": "online",
        "rxBytes": sum(peer["rxBytes"] for peer in peers),
        "txBytes": sum(peer["txBytes"] for peer in peers),
        "rxBps": sum(peer["rxBps"] for peer in peers),
        "txBps": sum(peer["txBps"] for peer in peers),
    }
    return {
        "interface": interface,
        "sampledAt": sampled_at,
        "peers": peers,
        "history": history,
    }


def authenticated(_: None = Depends(require_token)) -> None:
    return None


@app.get("/api/v1/snapshot", dependencies=[Depends(authenticated)])
def snapshot() -> dict[str, Any]:
    _, monitor_path, interface = settings()
    document = _read_json(monitor_path)
    return build_dashboard_snapshot(document, interface)


@app.get("/api/v1/events", dependencies=[Depends(authenticated)])
def events() -> list[dict[str, Any]]:
    return []


@app.post("/api/v1/clients", dependencies=[Depends(authenticated)])
def add_client(_: AddPeerRequest) -> None:
    raise HTTPException(
        status_code=501,
        detail="Peer creation is disabled pending inspection of existing AWG persistence.",
    )


@app.post("/api/v1/clients/{client_id}/pause", dependencies=[Depends(authenticated)])
def pause_client(client_id: str) -> None:
    validate_client_id(client_id)
    raise HTTPException(
        status_code=501,
        detail="Peer pause is disabled pending inspection of existing AWG persistence.",
    )


@app.post("/api/v1/clients/{client_id}/resume", dependencies=[Depends(authenticated)])
def resume_client(client_id: str) -> None:
    validate_client_id(client_id)
    raise HTTPException(
        status_code=501,
        detail="Peer resume is disabled pending inspection of existing AWG persistence.",
    )


@app.delete("/api/v1/clients/{client_id}", dependencies=[Depends(authenticated)])
def revoke_client(client_id: str) -> None:
    validate_client_id(client_id)
    raise HTTPException(
        status_code=501,
        detail="Peer revocation is disabled pending inspection of existing AWG persistence.",
    )


@app.get("/api/v1/clients/{client_id}/config", dependencies=[Depends(authenticated)])
def client_config(client_id: str) -> None:
    validate_client_id(client_id)
    raise HTTPException(
        status_code=501,
        detail="Configuration export is disabled until peer provisioning is implemented.",
    )


def validate_client_id(client_id: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{64}", client_id):
        raise HTTPException(status_code=400, detail="Invalid peer identifier.")


@app.middleware("http")
async def no_store_and_no_server_errors(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
