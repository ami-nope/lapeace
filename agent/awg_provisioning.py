"""Unprivileged client for the root-owned AWG helper daemon."""

import base64
import json
import re
import socket


HELPER_SOCKET_PATH = "/run/lapeace-awg/helper.sock"
MAX_FRAME_BYTES = 262_144
HELPER_TIMEOUT_SECONDS = 20
CLIENT_ID_PATTERN = re.compile(r"^[a-f0-9]{64}$")
LABEL_PATTERN = re.compile(r"^[A-Za-z0-9 _.-]{1,48}$")


class AWGProvisioningError(Exception):
    pass


class AWGClientNotFound(AWGProvisioningError):
    pass


class AWGClientConflict(AWGProvisioningError):
    pass


def _read_frame(connection: socket.socket) -> dict:
    data = bytearray()
    while len(data) <= MAX_FRAME_BYTES:
        chunk = connection.recv(min(4096, MAX_FRAME_BYTES + 1 - len(data)))
        if not chunk:
            raise AWGProvisioningError("AWG helper closed the connection unexpectedly.")
        data.extend(chunk)
        newline = data.find(b"\n")
        if newline >= 0:
            if data[newline + 1 :].strip():
                raise AWGProvisioningError("AWG helper returned an invalid response frame.")
            if newline > MAX_FRAME_BYTES:
                break
            try:
                payload = json.loads(data[:newline])
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise AWGProvisioningError("AWG helper returned invalid JSON.") from error
            if not isinstance(payload, dict):
                raise AWGProvisioningError("AWG helper returned an invalid response.")
            return payload
    raise AWGProvisioningError("AWG helper response is too large.")


class AWGPeerClient:
    """Keep the existing API-facing interface while delegating all AWG access."""

    def _request(self, operation: str, **fields):
        request = {"operation": operation, **fields}
        try:
            encoded = json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n"
        except (TypeError, ValueError) as error:
            raise AWGProvisioningError("Invalid AWG helper request.") from error
        if len(encoded) > MAX_FRAME_BYTES:
            raise AWGProvisioningError("AWG helper request is too large.")
        if not hasattr(socket, "AF_UNIX") or not hasattr(socket, "SOCK_STREAM"):
            raise AWGProvisioningError("Unix domain sockets are unavailable on this platform.")

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(HELPER_TIMEOUT_SECONDS)
                connection.connect(HELPER_SOCKET_PATH)
                connection.sendall(encoded)
                response = _read_frame(connection)
        except (OSError, TimeoutError) as error:
            raise AWGProvisioningError("AWG helper is unavailable.") from error

        if response.get("ok") is True and "result" in response:
            return response["result"]
        if response.get("ok") is False:
            message = response.get("error")
            message = message if isinstance(message, str) else "AWG helper request failed."
            if response.get("code") == "not_found":
                raise AWGClientNotFound(message)
            if response.get("code") == "conflict":
                raise AWGClientConflict(message)
            raise AWGProvisioningError(message)
        raise AWGProvisioningError("AWG helper returned an invalid response.")

    @staticmethod
    def _validate_client_id(client_id: str) -> None:
        if not isinstance(client_id, str) or not CLIENT_ID_PATTERN.fullmatch(client_id):
            raise AWGProvisioningError("Invalid client identifier.")

    def create(self, label: str) -> dict[str, str]:
        if not isinstance(label, str) or not LABEL_PATTERN.fullmatch(label):
            raise AWGProvisioningError("Client label contains invalid characters.")
        result = self._request("create", label=label)
        if not isinstance(result, dict):
            raise AWGProvisioningError("AWG helper returned an invalid create result.")
        return result

    def list_clients(self) -> list[dict[str, str]]:
        result = self._request("list")
        if (
            not isinstance(result, list)
            or not all(
                isinstance(client, dict)
                and isinstance(client.get("clientId"), str)
                and CLIENT_ID_PATTERN.fullmatch(client["clientId"])
                and isinstance(client.get("label"), str)
                and isinstance(client.get("address"), str)
                and isinstance(client.get("status"), str)
                and not ({"privateKey", "publicKey"} & client.keys())
                for client in result
            )
        ):
            raise AWGProvisioningError("AWG helper returned invalid peer data.")
        return result

    def pause(self, client_id: str) -> dict[str, str]:
        self._validate_client_id(client_id)
        return self._request("pause", clientId=client_id)

    def resume(self, client_id: str) -> dict[str, str]:
        self._validate_client_id(client_id)
        return self._request("resume", clientId=client_id)

    def revoke(self, client_id: str) -> dict[str, str]:
        self._validate_client_id(client_id)
        return self._request("revoke", clientId=client_id)

    def regenerate(self, client_id: str) -> dict[str, str]:
        self._validate_client_id(client_id)
        return self._request("regenerate", clientId=client_id)

    def client_config(self, client_id: str) -> str:
        self._validate_client_id(client_id)
        result = self._request("client_config", clientId=client_id)
        if not isinstance(result, str):
            raise AWGProvisioningError("AWG helper returned an invalid client config.")
        return result

    def client_qr_svg(self, client_id: str) -> bytes:
        self._validate_client_id(client_id)
        result = self._request("client_qr_svg", clientId=client_id)
        if not isinstance(result, str):
            raise AWGProvisioningError("AWG helper returned an invalid QR image.")
        try:
            return base64.b64decode(result, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise AWGProvisioningError("AWG helper returned an invalid QR image.") from error
