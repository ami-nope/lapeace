import base64
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import threading
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit


COMMAND_TIMEOUT_SECONDS = 10
STATE_VERSION = 1
CLIENT_ID_PATTERN = re.compile(r"^[a-f0-9]{64}$")
LABEL_PATTERN = re.compile(r"^[A-Za-z0-9 _.-]{1,48}$")
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
OBFUSCATION_OPTIONS = {"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"}
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
AWGNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

try:
    import fcntl
except ImportError:
    fcntl = None


class AWGProvisioningError(Exception):
    pass


class AWGClientNotFound(AWGProvisioningError):
    pass


class AWGClientConflict(AWGProvisioningError):
    pass


@dataclass(frozen=True)
class Section:
    name: str
    start: int
    end: int
    lines: tuple[str, ...]


def _client_id(public_key: str) -> str:
    return hashlib.sha256(public_key.encode("ascii")).hexdigest()


def _validate_key(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AWGProvisioningError(f"{field} is not valid base64.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise AWGProvisioningError(f"{field} is not valid base64.") from error
    if len(decoded) != 32:
        raise AWGProvisioningError(f"{field} must encode 32 bytes.")
    return base64.b64encode(decoded).decode("ascii")


def _sections(text: str) -> tuple[list[str], list[Section]]:
    lines = text.splitlines(keepends=True)
    headers: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^\s*\[([A-Za-z]+)\]\s*(?:[#;].*)?(?:\r?\n)?$", line)
        if match:
            headers.append((index, match.group(1).lower()))
    if not headers or headers[0][1] != "interface":
        raise AWGProvisioningError("AWG config has no leading [Interface] section.")
    if sum(name == "interface" for _, name in headers) != 1:
        raise AWGProvisioningError("AWG config must contain exactly one [Interface].")

    preamble = lines[: headers[0][0]]
    sections = [
        Section(
            name=name,
            start=start,
            end=headers[position + 1][0] if position + 1 < len(headers) else len(lines),
            lines=tuple(
                lines[
                    start : headers[position + 1][0]
                    if position + 1 < len(headers)
                    else len(lines)
                ]
            ),
        )
        for position, (start, name) in enumerate(headers)
    ]
    return preamble, sections


def _assignments(section: Section) -> dict[str, list[tuple[str, str]]]:
    result: dict[str, list[tuple[str, str]]] = {}
    for line in section.lines[1:]:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            result.setdefault(key.lower(), []).append((key, value))
    return result


def _one_value(values: dict[str, list[tuple[str, str]]], name: str) -> str:
    matches = values.get(name.lower(), [])
    if len(matches) != 1:
        raise AWGProvisioningError(f"AWG config must contain one {name} value.")
    return matches[0][1]


def _allowed_networks(value: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    for item in value.split(","):
        candidate = item.strip()
        if not candidate:
            raise AWGProvisioningError("AWG AllowedIPs contains an empty entry.")
        try:
            networks.append(ipaddress.ip_network(candidate, strict=False))
        except ValueError as error:
            raise AWGProvisioningError("AWG AllowedIPs contains an invalid network.") from error
    return networks


def _config_peers(sections: list[Section]) -> dict[str, list[AWGNetwork]]:
    peers: dict[str, list[AWGNetwork]] = {}
    for section in sections:
        if section.name != "peer":
            continue
        values = _assignments(section)
        public_key = _validate_key(_one_value(values, "publickey"), "Peer public key")
        key_id = _client_id(public_key)
        if key_id in peers:
            raise AWGProvisioningError("AWG config contains a duplicate peer key.")
        peers[key_id] = _allowed_networks(_one_value(values, "allowedips"))
    return peers


def _replace_sections(
    preamble: list[str], sections: list[Section], replacements: dict[int, tuple[str, ...]], removed: set[int]
) -> str:
    lines = list(preamble)
    for index, section in enumerate(sections):
        if index in removed:
            continue
        lines.extend(replacements.get(index, section.lines))
    return "".join(lines)


def _append_peer(text: str, public_key: str, address: str) -> str:
    newline = "\r\n" if "\r\n" in text else "\n"
    prefix = text
    if prefix and not prefix.endswith(("\n", "\r")):
        prefix += newline
    if prefix and not prefix.endswith(newline + newline):
        prefix += newline
    return (
        prefix
        + "[Peer]"
        + newline
        + f"PublicKey = {public_key}"
        + newline
        + f"AllowedIPs = {address}/32"
        + newline
    )


def _remove_peer(text: str, public_key: str) -> str:
    preamble, sections = _sections(text)
    matches = []
    for index, section in enumerate(sections):
        if section.name != "peer":
            continue
        values = _assignments(section)
        peer_key = _validate_key(_one_value(values, "publickey"), "Peer public key")
        if peer_key == public_key:
            matches.append(index)
    if len(matches) != 1:
        raise AWGProvisioningError("Managed peer does not have exactly one config entry.")
    return _replace_sections(preamble, sections, {}, {matches[0]})


def _runtime_peers(output: str) -> dict[str, list[AWGNetwork]]:
    lines = output.splitlines()
    if not lines or len(lines[0].split("\t")) < 4:
        raise AWGProvisioningError("AWG returned an invalid interface dump.")
    peers: dict[str, list[AWGNetwork]] = {}
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            raise AWGProvisioningError("AWG returned an incomplete peer record.")
        key = _validate_key(fields[0], "Runtime peer key")
        key_id = _client_id(key)
        if key_id in peers:
            raise AWGProvisioningError("AWG returned duplicate peer keys.")
        peers[key_id] = _allowed_networks(fields[3])
    return peers


def _parse_endpoint(value: str) -> str:
    if not isinstance(value, str) or not value or any(char in value for char in "\r\n\t ;"):
        raise AWGProvisioningError("AWG_SERVER_ENDPOINT must be host:port.")
    try:
        parsed = urlsplit(f"udp://{value}")
        port = parsed.port
    except ValueError as error:
        raise AWGProvisioningError("AWG_SERVER_ENDPOINT must be host:port.") from error
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1 <= port <= 65535
    ):
        raise AWGProvisioningError("AWG_SERVER_ENDPOINT must be host:port.")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if (
            len(parsed.hostname) > 253
            or not re.fullmatch(
                r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*",
                parsed.hostname,
            )
        ):
            raise AWGProvisioningError("AWG_SERVER_ENDPOINT has an invalid hostname.")
    return value


def _validated_csv_ips(value: str, field: str, *, networks: bool) -> str:
    if not isinstance(value, str) or not value:
        raise AWGProvisioningError(f"{field} must contain at least one value.")
    result = []
    for item in value.split(","):
        candidate = item.strip()
        if not candidate or any(char in candidate for char in "\r\n\t"):
            raise AWGProvisioningError(f"{field} contains an invalid value.")
        try:
            parsed = (
                ipaddress.ip_network(candidate, strict=False)
                if networks
                else ipaddress.ip_address(candidate)
            )
        except ValueError as error:
            raise AWGProvisioningError(f"{field} contains an invalid value.") from error
        result.append(str(parsed))
    if len(result) != len(set(result)):
        raise AWGProvisioningError(f"{field} contains a duplicate value.")
    return ", ".join(result)


def _validate_label(value: str) -> str:
    if not isinstance(value, str) or not LABEL_PATTERN.fullmatch(value):
        raise AWGProvisioningError("Client label contains unsupported characters.")
    return value


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AWGPeerManager:
    def __init__(
        self,
        config_path: Path,
        state_path: Path,
        interface: str,
        server_endpoint: str,
        *,
        client_allowed_ips: str = "0.0.0.0/0",
        client_dns: str = "1.1.1.1",
        command_runner: CommandRunner | None = None,
    ) -> None:
        if not INTERFACE_PATTERN.fullmatch(interface):
            raise AWGProvisioningError("Configured interface name is invalid.")
        self.config_path = Path(config_path)
        self.state_path = Path(state_path)
        if self.config_path.resolve() == self.state_path.resolve():
            raise AWGProvisioningError("AWG config and client state paths must differ.")
        self.interface = interface
        self.server_endpoint = _parse_endpoint(server_endpoint)
        self.client_allowed_ips = _validated_csv_ips(
            client_allowed_ips, "AWG_CLIENT_ALLOWED_IPS", networks=True
        )
        self.client_dns = _validated_csv_ips(client_dns, "AWG_CLIENT_DNS", networks=False)
        self.command_runner = command_runner or subprocess.run
        self._thread_lock = threading.RLock()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._thread_lock:
            self.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            lock_path = self.state_path.with_suffix(self.state_path.suffix + ".lock")
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(lock_path, flags, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def _run(self, arguments: list[str], *, input_text: str | None = None) -> str:
        try:
            result = self.command_runner(
                arguments,
                check=False,
                capture_output=True,
                text=True,
                input=input_text,
                timeout=COMMAND_TIMEOUT_SECONDS,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AWGProvisioningError("AmneziaWG command could not be completed.") from error
        if result.returncode != 0:
            raise AWGProvisioningError("AmneziaWG command failed.")
        return result.stdout.strip()

    def _read_config(self) -> tuple[str, os.stat_result]:
        try:
            metadata = self.config_path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise AWGProvisioningError("AWG config path must be a regular file.")
            content = self.config_path.read_bytes().decode("utf-8")
        except AWGProvisioningError:
            raise
        except (OSError, UnicodeDecodeError) as error:
            raise AWGProvisioningError("AWG config is unavailable or invalid UTF-8.") from error
        return content, metadata

    def _read_state(self) -> tuple[dict[str, Any], bytes | None, os.stat_result | None]:
        try:
            metadata = self.state_path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise AWGProvisioningError("AWG client state path must be a regular file.")
            content = self.state_path.read_bytes()
        except FileNotFoundError:
            return {"version": STATE_VERSION, "clients": {}}, None, None
        except AWGProvisioningError:
            raise
        except OSError as error:
            raise AWGProvisioningError("AWG client state is unavailable.") from error
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AWGProvisioningError("AWG client state permissions must be 0600.")
        try:
            state = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AWGProvisioningError("AWG client state is malformed.") from error
        if (
            not isinstance(state, dict)
            or state.get("version") != STATE_VERSION
            or not isinstance(state.get("clients"), dict)
        ):
            raise AWGProvisioningError("AWG client state has an invalid format.")
        addresses: set[str] = set()
        for client_id, record in state["clients"].items():
            if (
                not isinstance(client_id, str)
                or not CLIENT_ID_PATTERN.fullmatch(client_id)
                or not isinstance(record, dict)
                or not isinstance(record.get("label"), str)
                or not LABEL_PATTERN.fullmatch(record["label"])
                or record.get("status") not in {"active", "paused"}
            ):
                raise AWGProvisioningError("AWG client state contains an invalid record.")
            public_key = _validate_key(record.get("publicKey", ""), "Client public key")
            _validate_key(record.get("privateKey", ""), "Client private key")
            if _client_id(public_key) != client_id:
                raise AWGProvisioningError("AWG client state has a mismatched client ID.")
            try:
                address = ipaddress.ip_address(record.get("address", ""))
            except ValueError as error:
                raise AWGProvisioningError("AWG client state has an invalid address.") from error
            if not isinstance(address, ipaddress.IPv4Address):
                raise AWGProvisioningError("AWG client state address must be IPv4.")
            if str(address) in addresses:
                raise AWGProvisioningError("AWG client state contains duplicate addresses.")
            addresses.add(str(address))
        return state, content, metadata

    def _runtime(self) -> dict[str, list[AWGNetwork]]:
        return _runtime_peers(self._run(["awg", "show", self.interface, "dump"]))

    def _config_parts(
        self, content: str
    ) -> tuple[list[str], list[Section], dict[str, list[AWGNetwork]], dict[str, list[tuple[str, str]]]]:
        preamble, sections = _sections(content)
        interfaces = [section for section in sections if section.name == "interface"]
        if len(interfaces) != 1:
            raise AWGProvisioningError("AWG config must contain exactly one [Interface].")
        interface_values = _assignments(interfaces[0])
        _validate_key(_one_value(interface_values, "privatekey"), "Server private key")
        address_values = interface_values.get("address", [])
        if len(address_values) != 1:
            raise AWGProvisioningError("AWG config must contain one interface Address.")
        interface_addresses = []
        for candidate in address_values[0][1].split(","):
            try:
                address = ipaddress.ip_interface(candidate.strip())
            except ValueError as error:
                raise AWGProvisioningError("AWG interface Address is invalid.") from error
            if isinstance(address, ipaddress.IPv4Interface):
                interface_addresses.append(address)
        if not interface_addresses:
            raise AWGProvisioningError("AWG config requires an IPv4 interface Address.")
        peers = _config_peers(sections)
        return preamble, sections, peers, interface_values

    def _validate_sync(
        self,
        state: dict[str, Any],
        config_peers: dict[str, list[AWGNetwork]],
        runtime_peers: dict[str, list[AWGNetwork]],
        interface_values: dict[str, list[tuple[str, str]]],
    ) -> None:
        interface_networks = [
            address.network
            for value in _one_value(interface_values, "address").split(",")
            for address in [ipaddress.ip_interface(value.strip())]
            if isinstance(address, ipaddress.IPv4Interface)
        ]
        for client_id, record in state["clients"].items():
            in_config = client_id in config_peers
            in_runtime = client_id in runtime_peers
            address = ipaddress.ip_address(record["address"])
            if not any(address in network for network in interface_networks):
                raise AWGClientConflict("Managed peer address is outside the AWG subnet.")
            if any(
                address in network
                for other_id, networks in config_peers.items()
                if other_id != client_id
                for network in networks
            ) or any(
                address in network
                for other_id, networks in runtime_peers.items()
                if other_id != client_id
                for network in networks
            ):
                raise AWGClientConflict("Managed peer address overlaps another peer.")
            if record["status"] == "active":
                if (
                    not in_config
                    or not in_runtime
                    or not any(address in network for network in config_peers[client_id])
                    or not any(address in network for network in runtime_peers[client_id])
                ):
                    raise AWGClientConflict("Managed peer state does not match AWG.")
            elif in_config or in_runtime:
                raise AWGClientConflict("Paused peer is still present in AWG.")

    def _allocate_address(
        self,
        interface_values: dict[str, list[tuple[str, str]]],
        config_peers: dict[str, list[AWGNetwork]],
        runtime_peers: dict[str, list[AWGNetwork]],
        state: dict[str, Any],
    ) -> str:
        addresses = [
            ipaddress.ip_interface(item.strip())
            for item in _one_value(interface_values, "address").split(",")
        ]
        networks = [address.network for address in addresses if isinstance(address, ipaddress.IPv4Interface)]
        if not networks:
            raise AWGProvisioningError("AWG config has no IPv4 client subnet.")
        reserved_networks = [
            network
            for peers in (config_peers, runtime_peers)
            for peer_networks in peers.values()
            for network in peer_networks
            if isinstance(network, ipaddress.IPv4Network)
        ]
        reserved_addresses = {
            ipaddress.ip_address(record["address"])
            for record in state["clients"].values()
        }
        for interface_address in addresses:
            if isinstance(interface_address, ipaddress.IPv4Interface):
                reserved_addresses.add(interface_address.ip)
        for network in networks:
            for candidate in network.hosts():
                if candidate in reserved_addresses:
                    continue
                if any(candidate in reserved for reserved in reserved_networks):
                    continue
                if any(candidate in other and other != network for other in networks):
                    continue
                return str(candidate)
        raise AWGProvisioningError("No unused IPv4 address is available in AWG config.")

    def _gen_keypair(self) -> tuple[str, str]:
        private_key = _validate_key(self._run(["awg", "genkey"]), "Generated private key")
        public_key = _validate_key(
            self._run(["awg", "pubkey"], input_text=private_key + "\n"),
            "Generated public key",
        )
        return private_key, public_key

    def _atomic_write(
        self,
        path: Path,
        content: bytes,
        *,
        mode: int,
        previous_stat: os.stat_result | None = None,
    ) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = -1
        temporary_name = ""
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            if os.name == "posix":
                os.fchmod(descriptor, mode)
                if previous_stat is not None:
                    current_stat = os.fstat(descriptor)
                    if (current_stat.st_uid, current_stat.st_gid) != (
                        previous_stat.st_uid,
                        previous_stat.st_gid,
                    ):
                        os.fchown(descriptor, previous_stat.st_uid, previous_stat.st_gid)
            else:
                os.chmod(temporary_name, mode)
            with os.fdopen(descriptor, "wb") as file:
                descriptor = -1
                file.write(content)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary_name, path)
            temporary_name = ""
            if os.name == "posix":
                directory_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except OSError as error:
            raise AWGProvisioningError(f"Could not atomically update {path.name}.") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_name and os.path.exists(temporary_name):
                os.unlink(temporary_name)

    def _restore_file(
        self,
        path: Path,
        original: bytes | None,
        previous_stat: os.stat_result | None,
        *,
        mode: int,
    ) -> None:
        if original is None:
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                raise AWGProvisioningError("Could not roll back AWG client state.") from error
            return
        self._atomic_write(path, original, mode=mode, previous_stat=previous_stat)

    def _commit(
        self,
        *,
        config_before: bytes,
        config_stat: os.stat_result,
        config_after: str,
        state_before: bytes | None,
        state_stat: os.stat_result | None,
        state_after: dict[str, Any],
        runtime_steps: list[tuple[list[str], list[str]]],
    ) -> None:
        completed_rollbacks: list[list[str]] = []
        try:
            self._atomic_write(
                self.config_path,
                config_after.encode("utf-8"),
                mode=stat.S_IMODE(config_stat.st_mode),
                previous_stat=config_stat,
            )
            self._atomic_write(
                self.state_path,
                json.dumps(state_after, separators=(",", ":"), sort_keys=True).encode("utf-8"),
                mode=0o600,
                previous_stat=state_stat,
            )
            for command, rollback in runtime_steps:
                completed_rollbacks.append(rollback)
                self._run(command)
        except Exception as error:
            rollback_failed = False
            for command in reversed(completed_rollbacks):
                try:
                    self._run(command)
                except AWGProvisioningError:
                    rollback_failed = True
            try:
                self._restore_file(
                    self.config_path,
                    config_before,
                    config_stat,
                    mode=stat.S_IMODE(config_stat.st_mode),
                )
                self._restore_file(
                    self.state_path,
                    state_before,
                    state_stat,
                    mode=0o600,
                )
            except AWGProvisioningError:
                rollback_failed = True
            if rollback_failed:
                raise AWGProvisioningError(
                    "Peer operation failed and rollback was incomplete; inspect AWG config and runtime."
                ) from error
            raise AWGProvisioningError(
                "Peer operation failed; file and runtime changes were rolled back."
            ) from error

    def _snapshot(self) -> tuple[
        str,
        os.stat_result,
        dict[str, Any],
        bytes | None,
        os.stat_result | None,
        dict[str, list[AWGNetwork]],
        dict[str, list[AWGNetwork]],
        list[str],
        list[Section],
        dict[str, list[tuple[str, str]]],
    ]:
        config, config_stat = self._read_config()
        state, state_bytes, state_stat = self._read_state()
        preamble, sections, config_peers, interface_values = self._config_parts(config)
        runtime_peers = self._runtime()
        self._validate_sync(state, config_peers, runtime_peers, interface_values)
        return (
            config,
            config_stat,
            state,
            state_bytes,
            state_stat,
            config_peers,
            runtime_peers,
            preamble,
            sections,
            interface_values,
        )

    def create(self, label: str) -> dict[str, str]:
        label = _validate_label(label)
        with self._locked():
            (
                config,
                config_stat,
                state,
                state_bytes,
                state_stat,
                config_peers,
                runtime_peers,
                _preamble,
                _sections_list,
                interface_values,
            ) = self._snapshot()
            private_key, public_key = self._gen_keypair()
            client_id = _client_id(public_key)
            if client_id in config_peers or client_id in state["clients"]:
                raise AWGClientConflict("Generated peer key already exists.")
            address = self._allocate_address(
                interface_values, config_peers, runtime_peers, state
            )
            next_state = json.loads(json.dumps(state))
            next_state["clients"][client_id] = {
                "label": label,
                "publicKey": public_key,
                "privateKey": private_key,
                "address": address,
                "status": "active",
                "createdAt": _iso_now(),
            }
            config_after = _append_peer(config, public_key, address)
            self._commit(
                config_before=config.encode("utf-8"),
                config_stat=config_stat,
                config_after=config_after,
                state_before=state_bytes,
                state_stat=state_stat,
                state_after=next_state,
                runtime_steps=[
                    (
                        [
                            "awg", "set", self.interface, "peer", public_key,
                            "allowed-ips", f"{address}/32",
                        ],
                        ["awg", "set", self.interface, "peer", public_key, "remove"],
                    )
                ],
            )
            return {
                "clientId": client_id,
                "label": label,
                "address": f"{address}/32",
                "status": "active",
            }

    def _client(self, client_id: str, state: dict[str, Any]) -> dict[str, Any]:
        if not CLIENT_ID_PATTERN.fullmatch(client_id):
            raise AWGProvisioningError("Invalid client identifier.")
        record = state["clients"].get(client_id)
        if record is None:
            raise AWGClientNotFound("Managed client was not found.")
        return record

    def pause(self, client_id: str) -> dict[str, str]:
        with self._locked():
            (
                config, config_stat, state, state_bytes, state_stat,
                _config_peers, _runtime_peers_map, _preamble, _sections_list, _values,
            ) = self._snapshot()
            record = self._client(client_id, state)
            if record["status"] == "paused":
                raise AWGClientConflict("Client is already paused.")
            next_state = json.loads(json.dumps(state))
            next_state["clients"][client_id]["status"] = "paused"
            next_state["clients"][client_id]["updatedAt"] = _iso_now()
            config_after = _remove_peer(config, record["publicKey"])
            self._commit(
                config_before=config.encode("utf-8"),
                config_stat=config_stat,
                config_after=config_after,
                state_before=state_bytes,
                state_stat=state_stat,
                state_after=next_state,
                runtime_steps=[
                    (
                        ["awg", "set", self.interface, "peer", record["publicKey"], "remove"],
                        [
                            "awg", "set", self.interface, "peer", record["publicKey"],
                            "allowed-ips", f"{record['address']}/32",
                        ],
                    )
                ],
            )
            return {"clientId": client_id, "status": "paused"}

    def resume(self, client_id: str) -> dict[str, str]:
        with self._locked():
            (
                config, config_stat, state, state_bytes, state_stat,
                config_peers, _runtime_peers_map, _preamble, _sections_list, _values,
            ) = self._snapshot()
            record = self._client(client_id, state)
            if record["status"] == "active":
                raise AWGClientConflict("Client is already active.")
            address = ipaddress.ip_address(record["address"])
            if any(
                address in network
                for networks in config_peers.values()
                for network in networks
            ):
                raise AWGClientConflict("Paused client address is no longer available.")
            next_state = json.loads(json.dumps(state))
            next_state["clients"][client_id]["status"] = "active"
            next_state["clients"][client_id]["updatedAt"] = _iso_now()
            config_after = _append_peer(config, record["publicKey"], record["address"])
            self._commit(
                config_before=config.encode("utf-8"),
                config_stat=config_stat,
                config_after=config_after,
                state_before=state_bytes,
                state_stat=state_stat,
                state_after=next_state,
                runtime_steps=[
                    (
                        [
                            "awg", "set", self.interface, "peer", record["publicKey"],
                            "allowed-ips", f"{record['address']}/32",
                        ],
                        ["awg", "set", self.interface, "peer", record["publicKey"], "remove"],
                    )
                ],
            )
            return {"clientId": client_id, "status": "active"}

    def revoke(self, client_id: str) -> dict[str, str]:
        with self._locked():
            (
                config, config_stat, state, state_bytes, state_stat,
                _config_peers, _runtime_peers_map, _preamble, _sections_list, _values,
            ) = self._snapshot()
            record = self._client(client_id, state)
            next_state = json.loads(json.dumps(state))
            del next_state["clients"][client_id]
            config_after = (
                _remove_peer(config, record["publicKey"])
                if record["status"] == "active"
                else config
            )
            runtime_steps = (
                [
                    (
                        ["awg", "set", self.interface, "peer", record["publicKey"], "remove"],
                        [
                            "awg", "set", self.interface, "peer", record["publicKey"],
                            "allowed-ips", f"{record['address']}/32",
                        ],
                    )
                ]
                if record["status"] == "active"
                else []
            )
            self._commit(
                config_before=config.encode("utf-8"),
                config_stat=config_stat,
                config_after=config_after,
                state_before=state_bytes,
                state_stat=state_stat,
                state_after=next_state,
                runtime_steps=runtime_steps,
            )
            return {"clientId": client_id, "status": "revoked"}

    def regenerate(self, client_id: str) -> dict[str, str]:
        with self._locked():
            (
                config, config_stat, state, state_bytes, state_stat,
                _config_peers, _runtime_peers_map, _preamble, _sections_list, _values,
            ) = self._snapshot()
            record = self._client(client_id, state)
            private_key, public_key = self._gen_keypair()
            new_id = _client_id(public_key)
            if new_id == client_id or new_id in state["clients"]:
                raise AWGClientConflict("Generated peer key already exists.")
            next_state = json.loads(json.dumps(state))
            del next_state["clients"][client_id]
            next_state["clients"][new_id] = {
                "label": record["label"],
                "publicKey": public_key,
                "privateKey": private_key,
                "address": record["address"],
                "status": record["status"],
                "createdAt": record.get("createdAt", _iso_now()),
                "updatedAt": _iso_now(),
            }
            if record["status"] == "active":
                config_after = _append_peer(
                    _remove_peer(config, record["publicKey"]),
                    public_key,
                    record["address"],
                )
                runtime_steps = [
                    (
                        ["awg", "set", self.interface, "peer", record["publicKey"], "remove"],
                        [
                            "awg", "set", self.interface, "peer", record["publicKey"],
                            "allowed-ips", f"{record['address']}/32",
                        ],
                    ),
                    (
                        [
                            "awg", "set", self.interface, "peer", public_key,
                            "allowed-ips", f"{record['address']}/32",
                        ],
                        ["awg", "set", self.interface, "peer", public_key, "remove"],
                    ),
                ]
            else:
                config_after = config
                runtime_steps = []
            self._commit(
                config_before=config.encode("utf-8"),
                config_stat=config_stat,
                config_after=config_after,
                state_before=state_bytes,
                state_stat=state_stat,
                state_after=next_state,
                runtime_steps=runtime_steps,
            )
            return {
                "clientId": new_id,
                "previousClientId": client_id,
                "address": f"{record['address']}/32",
                "status": record["status"],
            }

    def client_config(self, client_id: str) -> str:
        with self._locked():
            config, _metadata = self._read_config()
            state, _state_bytes, _state_stat = self._read_state()
            record = self._client(client_id, state)
            if record["status"] != "active":
                raise AWGClientConflict("Resume this client before exporting its config.")
            _preamble, sections, config_peers, values = self._config_parts(config)
            address = ipaddress.ip_address(record["address"])
            if (
                client_id not in config_peers
                or not any(address in network for network in config_peers[client_id])
            ):
                raise AWGClientConflict("Managed peer does not match AWG config.")
            interface_sections = [section for section in sections if section.name == "interface"]
            if len(interface_sections) != 1:
                raise AWGProvisioningError("AWG config must contain exactly one [Interface].")
            server_private = _validate_key(
                _one_value(values, "privatekey"), "Server private key"
            )
            server_public = _validate_key(
                self._run(["awg", "pubkey"], input_text=server_private + "\n"),
                "Server public key",
            )
            lines = [
                "[Interface]",
                f"PrivateKey = {record['privateKey']}",
                f"Address = {record['address']}/32",
                f"DNS = {self.client_dns}",
            ]
            for key, entries in values.items():
                if key in OBFUSCATION_OPTIONS:
                    if len(entries) != 1:
                        raise AWGProvisioningError("AWG config has duplicate obfuscation values.")
                    original_key, value = entries[0]
                    if not re.fullmatch(r"[0-9]{1,10}", value) or int(value) > 4294967295:
                        raise AWGProvisioningError(
                            "AWG config has an invalid obfuscation value."
                        )
                    lines.append(f"{original_key} = {value}")
            lines.extend(
                [
                    "",
                    "[Peer]",
                    f"PublicKey = {server_public}",
                    f"AllowedIPs = {self.client_allowed_ips}",
                    f"Endpoint = {self.server_endpoint}",
                    "PersistentKeepalive = 25",
                    "",
                ]
            )
            return "\n".join(lines)

    def client_qr_svg(self, client_id: str) -> bytes:
        try:
            import qrcode
            from qrcode.image.svg import SvgPathImage
            from io import BytesIO

            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=5,
                border=4,
            )
            qr.add_data(self.client_config(client_id))
            qr.make(fit=True)
            image = qr.make_image(image_factory=SvgPathImage)
            output = BytesIO()
            image.save(output)
            return output.getvalue()
        except AWGProvisioningError:
            raise
        except Exception as error:
            raise AWGProvisioningError("Could not generate the client QR code.") from error
