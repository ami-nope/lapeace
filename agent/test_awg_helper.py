import json
import socket
import struct

import pytest

import awg_provisioning as provisioning
from awg_helper import AWGProvisioningError, _dispatch, _handle_connection


class StubManager:
    def list_clients(self):
        return [
            {
                "clientId": "a" * 64,
                "label": "phone",
                "address": "10.66.67.3/32",
                "status": "active",
            }
        ]

    def create(self, label):
        return {"clientId": "a" * 64, "label": label}


def test_helper_allows_only_explicit_operations_and_fields():
    manager = StubManager()

    assert _dispatch(manager, {"operation": "list"})[0]["address"] == "10.66.67.3/32"
    assert _dispatch(manager, {"operation": "create", "label": "phone"})["label"] == "phone"
    with pytest.raises(AWGProvisioningError, match="Unsupported"):
        _dispatch(manager, {"operation": "exec", "command": "id"})
    with pytest.raises(AWGProvisioningError, match="fields"):
        _dispatch(manager, {"operation": "list", "path": "/etc/shadow"})
    with pytest.raises(AWGProvisioningError, match="fields"):
        _dispatch(
            manager,
            {
                "operation": "create",
                "label": "phone",
                "publicKey": "attacker-controlled",
                "address": "10.66.67.4/32",
            },
        )


def test_helper_validates_client_id_and_label_before_dispatch():
    manager = StubManager()

    with pytest.raises(AWGProvisioningError, match="label"):
        _dispatch(manager, {"operation": "create", "label": "bad/label"})
    with pytest.raises(AWGProvisioningError, match="identifier"):
        _dispatch(manager, {"operation": "pause", "clientId": "../../etc/passwd"})


def test_helper_rejects_connections_from_other_uids(monkeypatch):
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)

    class Connection:
        def getsockopt(self, level, option, size):
            assert level == socket.SOL_SOCKET
            assert option == socket.SO_PEERCRED
            assert size == struct.calcsize("3i")
            return struct.pack("3i", 10, 2001, 2001)

        def recv(self, _size):
            raise AssertionError("Unauthorized peers must not send requests.")

        def sendall(self, _data):
            raise AssertionError("Unauthorized peers must not receive responses.")

    _handle_connection(Connection(), StubManager(), allowed_uid=2000)


def test_helper_returns_validation_error_for_authorized_invalid_operation(monkeypatch):
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)

    class Connection:
        response = None

        def getsockopt(self, _level, _option, _size):
            return struct.pack("3i", 10, 2000, 2000)

        def recv(self, _size):
            return b'{"operation":"exec","command":"id"}\n'

        def sendall(self, value):
            self.response = json.loads(value)

    connection = Connection()
    _handle_connection(connection, StubManager(), allowed_uid=2000)

    assert connection.response == {
        "ok": False,
        "code": "error",
        "error": "Unsupported helper operation.",
    }


def test_unprivileged_client_uses_fixed_unix_stream_and_allowlisted_request(monkeypatch):
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    sent = {}
    response = json.dumps(
        {"ok": True, "result": [{"clientId": "a" * 64, "label": "phone",
                                 "address": "10.66.67.3/32", "status": "active"}]}
    ).encode() + b"\n"

    class Connection:
        def settimeout(self, timeout):
            assert timeout == provisioning.HELPER_TIMEOUT_SECONDS

        def connect(self, path):
            assert path == provisioning.HELPER_SOCKET_PATH

        def sendall(self, data):
            sent["request"] = json.loads(data)

        def recv(self, _size):
            nonlocal response
            data, response = response, b""
            return data

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    def socket_factory(family, kind):
        assert family == socket.AF_UNIX
        assert kind == socket.SOCK_STREAM
        return Connection()

    monkeypatch.setattr(provisioning.socket, "socket", socket_factory)

    clients = provisioning.AWGPeerClient().list_clients()

    assert clients[0]["address"] == "10.66.67.3/32"
    assert sent["request"] == {"operation": "list"}
