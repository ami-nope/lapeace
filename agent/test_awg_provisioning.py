import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from awg_provisioning import (
    AWGClientConflict,
    AWGClientNotFound,
    AWGPeerManager,
    AWGProvisioningError,
)


def encoded_key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode("ascii")


SERVER_PRIVATE = encoded_key(1)
SERVER_PUBLIC = encoded_key(2)
EXISTING_PUBLIC = encoded_key(3)
CLIENT_PRIVATE_KEYS = [encoded_key(4), encoded_key(5), encoded_key(6)]
CLIENT_PUBLIC_KEYS = [encoded_key(7), encoded_key(8), encoded_key(9)]
EXISTING_PRESHARED_KEY = encoded_key(10)


def config_text() -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {SERVER_PRIVATE}\n"
        "Address = 10.66.67.1/24\n"
        "ListenPort = 51820\n"
        "Jc = 4\n"
        "Jmin = 40\n"
        "Jmax = 80\n"
        "S1 = 0\n"
        "S2 = 0\n"
        "H1 = 123456789\n"
        "PostUp = preserve-this-routing-rule\n"
        "PostDown = preserve-this-other-rule\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {EXISTING_PUBLIC}\n"
        f"PresharedKey = {EXISTING_PRESHARED_KEY}\n"
        "AllowedIPs = 10.66.67.2/32\n"
        "Endpoint = 203.0.113.8:51820\n"
        "PersistentKeepalive = 25\n"
    )


class FakeAWG:
    def __init__(self) -> None:
        self.runtime = {EXISTING_PUBLIC: "10.66.67.2/32"}
        self.generated = 0
        self.calls: list[list[str]] = []
        self.invocations: list[tuple[list[str], dict]] = []
        self.fail_next_add = False
        self.public_by_private = {
            SERVER_PRIVATE: SERVER_PUBLIC,
            **dict(zip(CLIENT_PRIVATE_KEYS, CLIENT_PUBLIC_KEYS)),
        }

    def __call__(self, arguments: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        self.calls.append(arguments)
        self.invocations.append((arguments, kwargs))
        if arguments == ["awg", "genkey"]:
            private_key = CLIENT_PRIVATE_KEYS[self.generated]
            self.generated += 1
            return subprocess.CompletedProcess(arguments, 0, private_key + "\n", "")
        if arguments == ["awg", "pubkey"]:
            public_key = self.public_by_private[kwargs["input"].strip()]
            return subprocess.CompletedProcess(arguments, 0, public_key + "\n", "")
        if arguments == ["awg", "show", "awg0", "dump"]:
            peers = [
                "\t".join(
                    [public_key, "(none)", "(none)", allowed_ips, "0", "0", "0", "off"]
                )
                for public_key, allowed_ips in self.runtime.items()
            ]
            dump = "\t".join([SERVER_PRIVATE, "51820", "off", ""]) + "\n"
            if peers:
                dump += "\n".join(peers) + "\n"
            return subprocess.CompletedProcess(arguments, 0, dump, "")
        if arguments[:4] == ["awg", "set", "awg0", "peer"]:
            public_key = arguments[4]
            if arguments[-1] == "remove":
                self.runtime.pop(public_key, None)
                return subprocess.CompletedProcess(arguments, 0, "", "")
            if self.fail_next_add:
                self.fail_next_add = False
                return subprocess.CompletedProcess(arguments, 1, "", "injected test failure")
            self.runtime[public_key] = arguments[-1]
            return subprocess.CompletedProcess(arguments, 0, "", "")
        raise AssertionError(f"Unexpected command: {arguments}")


def make_manager(tmp_path: Path, runner: FakeAWG) -> AWGPeerManager:
    config = tmp_path / "awg0.conf"
    config.write_text(config_text(), encoding="utf-8")
    return AWGPeerManager(
        config_path=config,
        state_path=tmp_path / "state" / "clients.json",
        interface="awg0",
        server_endpoint="vpn.example.test:51820",
        command_runner=runner,
    )


def test_key_generation_and_unique_ipv4_allocation_preserve_existing_config(tmp_path):
    runner = FakeAWG()
    manager = make_manager(tmp_path, runner)
    original_config = manager.config_path.read_bytes()

    first = manager.create("phone")
    second = manager.create("laptop")

    assert first["address"] == "10.66.67.3/32"
    assert second["address"] == "10.66.67.4/32"
    assert first["clientId"] == hashlib.sha256(
        CLIENT_PUBLIC_KEYS[0].encode("ascii")
    ).hexdigest()
    config = manager.config_path.read_text(encoding="utf-8")
    assert config.startswith(original_config.decode("utf-8").replace("\r\n", "\n"))
    assert f"PrivateKey = {SERVER_PRIVATE}" in config
    assert f"PresharedKey = {EXISTING_PRESHARED_KEY}" in config
    assert "PostUp = preserve-this-routing-rule" in config
    assert "PostDown = preserve-this-other-rule" in config
    assert all(call[0] == "awg" for call in runner.calls)
    assert all(call[1] != "set" or call[2] == "awg0" for call in runner.calls)
    assert all(kwargs["shell"] is False for _, kwargs in runner.invocations)


def test_client_config_and_qr_expose_only_the_new_client_key(tmp_path):
    runner = FakeAWG()
    manager = make_manager(tmp_path, runner)
    created = manager.create("phone")

    config = manager.client_config(created["clientId"])
    assert f"PrivateKey = {CLIENT_PRIVATE_KEYS[0]}" in config
    assert f"PublicKey = {SERVER_PUBLIC}" in config
    assert "Address = 10.66.67.3/32" in config
    assert "Endpoint = vpn.example.test:51820" in config
    assert "Jc = 4" in config
    assert "H1 = 123456789" in config
    assert SERVER_PRIVATE not in config
    assert EXISTING_PRESHARED_KEY not in config
    assert "PostUp" not in config

    svg = manager.client_qr_svg(created["clientId"])
    assert b"<svg" in svg
    assert CLIENT_PRIVATE_KEYS[0].encode("ascii") not in svg


def test_pause_resume_and_revoke_update_runtime_config_and_private_state(tmp_path):
    runner = FakeAWG()
    manager = make_manager(tmp_path, runner)
    created = manager.create("phone")
    client_id = created["clientId"]
    original_peer = f"PublicKey = {CLIENT_PUBLIC_KEYS[0]}"

    assert manager.pause(client_id) == {"clientId": client_id, "status": "paused"}
    assert original_peer not in manager.config_path.read_text(encoding="utf-8")
    assert CLIENT_PUBLIC_KEYS[0] not in runner.runtime
    with pytest.raises(AWGClientConflict):
        manager.client_config(client_id)

    assert manager.resume(client_id) == {"clientId": client_id, "status": "active"}
    assert original_peer in manager.config_path.read_text(encoding="utf-8")
    assert runner.runtime[CLIENT_PUBLIC_KEYS[0]] == "10.66.67.3/32"

    assert manager.revoke(client_id) == {"clientId": client_id, "status": "revoked"}
    assert original_peer not in manager.config_path.read_text(encoding="utf-8")
    assert CLIENT_PUBLIC_KEYS[0] not in runner.runtime
    state = json.loads(manager.state_path.read_text(encoding="utf-8"))
    assert state["clients"] == {}
    with pytest.raises(AWGClientNotFound):
        manager.client_config(client_id)


def test_regeneration_replaces_key_and_retains_address(tmp_path):
    runner = FakeAWG()
    manager = make_manager(tmp_path, runner)
    created = manager.create("phone")

    regenerated = manager.regenerate(created["clientId"])

    assert regenerated["previousClientId"] == created["clientId"]
    assert regenerated["clientId"] != created["clientId"]
    assert regenerated["address"] == created["address"]
    assert regenerated["status"] == "active"
    assert created["clientId"] not in json.loads(
        manager.state_path.read_text(encoding="utf-8")
    )["clients"]
    assert regenerated["clientId"] in json.loads(
        manager.state_path.read_text(encoding="utf-8")
    )["clients"]
    assert CLIENT_PUBLIC_KEYS[0] not in runner.runtime
    assert runner.runtime[CLIENT_PUBLIC_KEYS[1]] == created["address"]
    config = manager.client_config(regenerated["clientId"])
    assert f"PrivateKey = {CLIENT_PRIVATE_KEYS[1]}" in config


def test_regeneration_runtime_failure_restores_old_key_and_persistence(tmp_path):
    runner = FakeAWG()
    manager = make_manager(tmp_path, runner)
    created = manager.create("phone")
    original_config = manager.config_path.read_bytes()
    original_state = manager.state_path.read_bytes()
    runner.fail_next_add = True

    with pytest.raises(
        AWGProvisioningError,
        match="file and runtime changes were rolled back",
    ):
        manager.regenerate(created["clientId"])

    assert manager.config_path.read_bytes() == original_config
    assert manager.state_path.read_bytes() == original_state
    assert runner.runtime[CLIENT_PUBLIC_KEYS[0]] == "10.66.67.3/32"
    assert CLIENT_PUBLIC_KEYS[1] not in runner.runtime


def test_runtime_failure_rolls_config_and_state_back(tmp_path):
    runner = FakeAWG()
    manager = make_manager(tmp_path, runner)
    original_config = manager.config_path.read_bytes()
    runner.fail_next_add = True

    with pytest.raises(
        AWGProvisioningError,
        match="file and runtime changes were rolled back",
    ):
        manager.create("phone")

    assert manager.config_path.read_bytes() == original_config
    assert not manager.state_path.exists()
    assert runner.runtime == {EXISTING_PUBLIC: "10.66.67.2/32"}


def test_state_persistence_failure_restores_config_before_runtime_change(
    tmp_path, monkeypatch
):
    runner = FakeAWG()
    manager = make_manager(tmp_path, runner)
    original_config = manager.config_path.read_bytes()
    original_writer = manager._atomic_write

    def fail_state_write(path, content, **kwargs):
        if path == manager.state_path and content:
            raise AWGProvisioningError("Injected state persistence failure.")
        return original_writer(path, content, **kwargs)

    monkeypatch.setattr(manager, "_atomic_write", fail_state_write)

    with pytest.raises(
        AWGProvisioningError,
        match="file and runtime changes were rolled back",
    ):
        manager.create("phone")

    assert manager.config_path.read_bytes() == original_config
    assert not manager.state_path.exists()
    assert runner.runtime == {EXISTING_PUBLIC: "10.66.67.2/32"}
    assert not any(command[:2] == ["awg", "set"] for command in runner.calls)


def test_invalid_label_and_invalid_endpoint_do_not_execute_commands(tmp_path):
    runner = FakeAWG()
    manager = make_manager(tmp_path, runner)

    with pytest.raises(AWGProvisioningError):
        manager.create("phone; rm -rf /")
    assert runner.calls == []

    with pytest.raises(AWGProvisioningError):
        AWGPeerManager(
            config_path=tmp_path / "awg0.conf",
            state_path=tmp_path / "clients.json",
            interface="awg0",
            server_endpoint="vpn.example.test:51820\n; touch /tmp/x",
            command_runner=runner,
        )
    assert runner.calls == []


def test_state_file_is_private_on_posix(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permission bits are not available on this platform.")
    manager = make_manager(tmp_path, FakeAWG())

    manager.create("phone")

    assert stat.S_IMODE(manager.state_path.stat().st_mode) == 0o600


def test_generated_peer_config_never_contains_existing_peer_secrets(tmp_path):
    runner = FakeAWG()
    manager = make_manager(tmp_path, runner)
    created = manager.create("phone")
    exported = manager.client_config(created["clientId"])

    assert EXISTING_PUBLIC not in exported
    assert EXISTING_PRESHARED_KEY not in exported
    assert SERVER_PRIVATE not in exported
