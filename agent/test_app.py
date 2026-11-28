import base64
from datetime import date, timedelta
import json

import pytest
from fastapi.testclient import TestClient

from app import app, parse_awg_dump


TOKEN = "test-agent-token-that-is-at-least-32-characters"
IST_DATE = "2026-11-27"


def public_key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode("ascii")


def peer_snapshot(
    seed: int,
    *,
    upload: int = 0,
    download: int = 0,
    upload_mbps: float = 0,
    download_mbps: float = 0,
    daily_upload: int = 0,
    daily_download: int = 0,
    connected: bool = False,
) -> dict:
    return {
        "public_key": public_key(seed),
        "ips": [f"10.8.0.{seed}/32"],
        "upload_bytes": upload,
        "download_bytes": download,
        "latest_handshake": 1795780800 if connected else 0,
        "upload_mbps": upload_mbps,
        "download_mbps": download_mbps,
        "connected": connected,
        "daily_upload_bytes": daily_upload,
        "daily_download_bytes": daily_download,
        "endpoint": "198.51.100.10:51820",
        "preshared_key": "must-not-be-exposed",
    }


def monitor_document(snapshot_peers: list[dict] | None = None) -> dict:
    snapshot_peers = [] if snapshot_peers is None else snapshot_peers
    return {
        "version": 1,
        "last_sample": "2026-11-27T18:14:10+05:30",
        "peers": {},
        "daily_usage": {
            IST_DATE: {
                peer["public_key"]: {
                    "upload_bytes": peer["daily_upload_bytes"],
                    "download_bytes": peer["daily_download_bytes"],
                }
                for peer in snapshot_peers
            }
        },
        "snapshot": {"peers": snapshot_peers},
    }


def authenticated_client(monkeypatch, state_path):
    monkeypatch.setenv("PANEL_API_TOKEN", TOKEN)
    monkeypatch.setenv("MONITOR_STATE_FILE", str(state_path))
    return TestClient(app), {"Authorization": f"Bearer {TOKEN}"}


def test_dump_parser_reads_allowed_ips_from_field_four():
    pub = public_key(12)
    output = "\t".join(["private-key", public_key(13), "51820", "off"])
    output += "\n" + "\t".join(
        [
            pub,
            "preshared-secret",
            "203.0.113.8:51820",
            "10.8.0.12/32,fd00::12/128",
            "1795780800",
            "120",
            "40",
            "0",
        ]
    )

    peers = parse_awg_dump(output, now=1795780810)

    assert peers[0]["allowedIps"] == ["10.8.0.12/32", "fd00::12/128"]
    assert peers[0]["rxBytes"] == 120
    assert peers[0]["txBytes"] == 40
    assert "preshared-secret" not in json.dumps(peers)
    assert "203.0.113.8" not in json.dumps(peers)


def test_adapter_maps_multiple_peers_without_reversing_directions_and_does_not_write(
    tmp_path, monkeypatch
):
    path = tmp_path / "usage.json"
    document = monitor_document(
        [
            peer_snapshot(
                12,
                upload=800,
                download=1600,
                upload_mbps=0.8,
                download_mbps=1.6,
                daily_upload=80,
                daily_download=160,
                connected=True,
            ),
            peer_snapshot(
                14,
                upload=240,
                download=480,
                upload_mbps=0.24,
                download_mbps=0.48,
                daily_upload=24,
                daily_download=48,
            ),
        ]
    )
    original = json.dumps(document, separators=(",", ":")).encode()
    path.write_bytes(original)
    before = path.stat()
    client, headers = authenticated_client(monkeypatch, path)

    response = client.get("/api/v1/snapshot", headers=headers)

    assert response.status_code == 200
    result = response.json()
    first, second = result["peers"]
    assert first["rxBytes"] == 800
    assert first["txBytes"] == 1600
    assert first["rxBps"] == pytest.approx(100_000)
    assert first["txBps"] == pytest.approx(200_000)
    assert first["todayBytes"] == 240
    assert first["dailyUploadBytes"] == 80
    assert first["dailyDownloadBytes"] == 160
    assert first["usageHistory"] == [
        {
            "date": IST_DATE,
            "uploadBytes": 80,
            "downloadBytes": 160,
        }
    ]
    assert first["handshakeAt"] == 1795780800
    assert first["status"] == "connected"
    assert second["rxBytes"] == 240
    assert second["txBytes"] == 480
    assert result["interface"]["rxBytes"] == 1040
    assert result["interface"]["txBytes"] == 2080
    assert result["interface"]["rxBps"] == pytest.approx(130_000)
    assert result["interface"]["txBps"] == pytest.approx(260_000)
    assert result["history"] == [
        {"date": IST_DATE, "rxBytes": 104, "txBytes": 208}
    ]
    assert result["historyStartDate"] == IST_DATE
    assert result["historyEndDate"] == IST_DATE
    assert public_key(12) not in response.text
    assert "must-not-be-exposed" not in response.text
    assert "198.51.100.10" not in response.text
    assert path.read_bytes() == original
    after = path.stat()
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns


def test_adapter_accepts_empty_peers(tmp_path, monkeypatch):
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(monitor_document()), encoding="utf-8")
    client, headers = authenticated_client(monkeypatch, path)

    response = client.get("/api/v1/snapshot", headers=headers)

    assert response.status_code == 200
    assert response.json()["peers"] == []
    assert response.json()["interface"]["rxBytes"] == 0
    assert response.json()["history"] == []


def test_missing_monitor_file_returns_service_unavailable(tmp_path, monkeypatch):
    client, headers = authenticated_client(monkeypatch, tmp_path / "missing.json")

    response = client.get("/api/v1/snapshot", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == "Monitor state file is missing."


def test_malformed_monitor_file_returns_service_unavailable(tmp_path, monkeypatch):
    path = tmp_path / "usage.json"
    path.write_text('{"snapshot":', encoding="utf-8")
    client, headers = authenticated_client(monkeypatch, path)

    response = client.get("/api/v1/snapshot", headers=headers)

    assert response.status_code == 503
    assert "malformed" in response.json()["detail"]


def test_invalid_peer_snapshot_returns_service_unavailable(tmp_path, monkeypatch):
    path = tmp_path / "usage.json"
    document = monitor_document([peer_snapshot(12)])
    del document["snapshot"]["peers"][0]["upload_bytes"]
    path.write_text(json.dumps(document), encoding="utf-8")
    client, headers = authenticated_client(monkeypatch, path)

    response = client.get("/api/v1/snapshot", headers=headers)

    assert response.status_code == 503


def test_daily_usage_accepts_peer_keyed_history(tmp_path, monkeypatch):
    peer = peer_snapshot(12, daily_upload=80, daily_download=160)
    document = monitor_document([peer])
    document["daily_usage"] = {
        peer["public_key"]: {
            "2026-11-26": {"upload_bytes": 40, "download_bytes": 60},
            IST_DATE: {"upload_bytes": 80, "download_bytes": 160},
        }
    }
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    client, headers = authenticated_client(monkeypatch, path)

    response = client.get("/api/v1/snapshot", headers=headers)

    assert response.status_code == 200
    assert response.json()["history"] == [
        {"date": "2026-11-26", "rxBytes": 40, "txBytes": 60},
        {"date": IST_DATE, "rxBytes": 80, "txBytes": 160},
    ]


def test_snapshot_exposes_per_peer_month_history_without_public_keys(
    tmp_path, monkeypatch
):
    peer = peer_snapshot(12, daily_upload=999, daily_download=300)
    document = monitor_document([peer])
    start = date.fromisoformat(IST_DATE) - timedelta(days=34)
    document["daily_usage"] = {
        peer["public_key"]: {
            (start + timedelta(days=offset)).isoformat(): {
                "upload_bytes": offset,
                "download_bytes": offset * 2,
            }
            for offset in range(35)
        }
    }
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    client, headers = authenticated_client(monkeypatch, path)

    response = client.get("/api/v1/snapshot", headers=headers)

    assert response.status_code == 200
    result = response.json()
    assert result["historyStartDate"] == "2026-10-28"
    assert result["historyEndDate"] == IST_DATE
    assert len(result["peers"][0]["usageHistory"]) == 31
    assert result["peers"][0]["usageHistory"][-1] == {
        "date": IST_DATE,
        "uploadBytes": 999,
        "downloadBytes": 300,
    }
    assert peer["public_key"] not in response.text


def test_agent_operations_require_auth_and_unconfigured_peer_ops_fail_closed(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("PANEL_API_TOKEN", TOKEN)
    monkeypatch.setenv("AWG_SERVER_ENDPOINT", "vpn.example.test:51820")
    monkeypatch.setenv("AWG_CONFIG_FILE", str(tmp_path / "missing-awg.conf"))
    monkeypatch.setenv("AWG_CLIENT_STATE_FILE", str(tmp_path / "clients.json"))
    client = TestClient(app)

    assert client.get("/api/v1/events").status_code == 401
    assert client.post("/api/v1/clients", json={"label": "phone"}).status_code == 401

    headers = {"Authorization": f"Bearer {TOKEN}"}
    assert client.get("/api/v1/events", headers=headers).json() == []
    assert (
        client.post(
            "/api/v1/clients",
            json={"label": "phone"},
            headers=headers,
        ).status_code == 503
    )
    assert client.post("/api/v1/exec", headers=headers).status_code == 404


def test_peer_lifecycle_endpoints_require_authentication(monkeypatch):
    monkeypatch.setenv("PANEL_API_TOKEN", TOKEN)
    client = TestClient(app)
    client_id = "a" * 64

    responses = [
        client.post("/api/v1/clients", json={"label": "phone"}),
        client.post(f"/api/v1/clients/{client_id}/pause"),
        client.post(f"/api/v1/clients/{client_id}/resume"),
        client.post(f"/api/v1/clients/{client_id}/regenerate"),
        client.delete(f"/api/v1/clients/{client_id}"),
        client.get(f"/api/v1/clients/{client_id}/config"),
        client.get(f"/api/v1/clients/{client_id}/config/qr"),
    ]

    assert [response.status_code for response in responses] == [401] * 7


def test_peer_lifecycle_routes_return_downloadable_config_and_qr(monkeypatch):
    monkeypatch.setenv("PANEL_API_TOKEN", TOKEN)
    client_id = "a" * 64

    class StubManager:
        def create(self, label):
            return {
                "clientId": "b" * 64,
                "label": label,
                "address": "10.66.67.3/32",
                "status": "active",
            }

        def pause(self, value):
            return {"clientId": value, "status": "paused"}

        def resume(self, value):
            return {"clientId": value, "status": "active"}

        def regenerate(self, value):
            return {
                "clientId": "b" * 64,
                "previousClientId": value,
                "address": "10.66.67.3/32",
                "status": "active",
            }

        def revoke(self, value):
            return {"clientId": value, "status": "revoked"}

        def client_config(self, value):
            assert value == client_id
            return "[Interface]\nPrivateKey = client-only\n"

        def client_qr_svg(self, value):
            assert value == client_id
            return b"<svg/>"

    monkeypatch.setattr("app.awg_peer_manager", StubManager)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {TOKEN}"}

    created = client.post(
        "/api/v1/clients",
        json={"label": "phone"},
        headers=headers,
    )
    limited = client.post(
        "/api/v1/clients",
        json={"label": "phone", "upload_limit_bps": 1000},
        headers=headers,
    )
    download = client.get(
        f"/api/v1/clients/{client_id}/config",
        headers=headers,
    )
    qr = client.get(
        f"/api/v1/clients/{client_id}/config/qr",
        headers=headers,
    )

    assert created.status_code == 201
    assert created.json()["label"] == "phone"
    assert limited.status_code == 400
    assert "not implemented" in limited.json()["detail"]
    assert download.status_code == 200
    assert download.headers["content-disposition"].endswith(
        f'lapeace-{client_id}.conf"'
    )
    assert "PrivateKey = client-only" in download.text
    assert qr.status_code == 200
    assert qr.headers["content-type"].startswith("image/svg+xml")
    assert qr.content == b"<svg/>"
