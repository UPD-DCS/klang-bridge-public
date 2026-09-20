"""Persistent localhost broker for the authenticated browser bridge.

The broker deliberately contains no KLang compiler and never executes source.
It owns two local transports, one authenticated browser attachment, and a
single serialized operation queue.  A browser bridge implementation can be
provided independently by the frontend; tests can attach a protocol-speaking
fake browser over the same WebSocket boundary.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import queue
import secrets
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit, urlunsplit

from .contract import (
    PINNED_ARTIFACT_SHA256,
    PINNED_ARTIFACT_SIZE_BYTES,
    COMPILER_OPTIONS,
    IR_MODES,
    PINNED_KLANG_COMMIT,
    PINNED_KLANG_VERSION,
    SUPPORTED_DIALECTS,
)
from .paths import (
    BrokerState,
    Endpoint,
    RuntimePaths,
    RuntimeStateError,
)
from .protocol import (
    BRIDGE_AUTH_REQUEST_ID,
    BRIDGE_ERROR_CODES,
    BRIDGE_HANDSHAKE_REQUEST_ID,
    BRIDGE_MAX_MESSAGE_BYTES,
    BRIDGE_OPERATIONS,
    BRIDGE_READY_REQUEST_ID,
    MAX_INPUT_BYTES,
    Envelope,
    JsonFramer,
    PeerDisconnected,
    ProtocolError,
    make_envelope,
)
from .websocket import (
    LoopbackWebSocketServer,
    WebSocketConnection,
    WebSocketError,
    WebSocketProtocolError,
)

DEFAULT_ORIGIN = "https://klang.upd-dcs.work"
DEFAULT_TOKEN_TTL_SECONDS = 120.0
DEFAULT_OPERATION_TIMEOUT_SECONDS = 30.0
DEFAULT_CONTROL_TIMEOUT_SECONDS = 5.0
DEFAULT_BRIDGE_AUTH_TIMEOUT_SECONDS = 10.0
# Cold Pyodide/compiler bootstrap can legitimately exceed the short protocol
# authentication window. Keep handshake/auth bounded, but allow readiness to
# settle within the same budget exposed by the native connect command.
BRIDGE_READY_TIMEOUT_SECONDS = 120.0
EXPECTED_PYODIDE_VERSION = "0.27.2"


class BrokerError(RuntimeError):
    """A broker lifecycle or transport operation failed."""

    code = "client-broker"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        self.code = code or type(self).code
        super().__init__(message)


class BrokerNotReadyError(BrokerError):
    code = "client-disconnected"


class BridgeError(BrokerError):
    code = "execution-failed"


@dataclass(frozen=True)
class BrokerConfig:
    paths: RuntimePaths
    origin: str = DEFAULT_ORIGIN
    token_ttl_seconds: float = DEFAULT_TOKEN_TTL_SECONDS
    operation_timeout_seconds: float = DEFAULT_OPERATION_TIMEOUT_SECONDS
    bridge_auth_timeout_seconds: float = DEFAULT_BRIDGE_AUTH_TIMEOUT_SECONDS
    bridge_ready_timeout_seconds: float = BRIDGE_READY_TIMEOUT_SECONDS
    expected_manifest: Path | None = None

    def __post_init__(self) -> None:
        parsed = urlsplit(self.origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("origin must be an HTTP(S) origin without path, query, or fragment")
        if (
            self.token_ttl_seconds <= 0
            or self.operation_timeout_seconds <= 0
            or self.bridge_auth_timeout_seconds <= 0
            or self.bridge_ready_timeout_seconds <= 0
        ):
            raise ValueError("broker timeouts must be positive")


@dataclass
class _BootstrapToken:
    value: str
    expires_at_monotonic: float
    expires_at_wall: float
    consumed: bool = False


@dataclass
class _Operation:
    request_id: str
    owner_id: str
    operation: str
    payload: dict[str, Any]
    timeout: float
    done: threading.Event = field(default_factory=threading.Event)
    result: dict[str, Any] | None = None
    error: BrokerError | None = None
    cancelled: bool = False
    on_event: Callable[[str, Mapping[str, Any]], None] | None = None


class _ControlSession:
    def __init__(self, sock: socket.socket, session_id: str) -> None:
        self.sock = sock
        self.session_id = session_id
        self.framer = JsonFramer(sock)
        self.send_lock = threading.Lock()
        self.closed = threading.Event()
        self.monitor_stop = threading.Event()
        self.monitor_thread: threading.Thread | None = None

    def send(self, message_type: str, request_id: str, payload: Mapping[str, Any] | None = None) -> None:
        if self.closed.is_set():
            raise PeerDisconnected("control client is disconnected")
        with self.send_lock:
            self.framer.send(make_envelope(message_type, request_id, payload))

    def start_disconnect_monitor(self, callback: Callable[[], None]) -> None:
        if self.monitor_thread is not None:
            return
        self.monitor_thread = threading.Thread(
            target=self._monitor_disconnect,
            args=(callback,),
            name="klang-web-control-monitor",
            daemon=True,
        )
        self.monitor_thread.start()

    def stop_disconnect_monitor(self) -> None:
        self.monitor_stop.set()
        thread = self.monitor_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1)
        self.monitor_thread = None

    def _monitor_disconnect(self, callback: Callable[[], None]) -> None:
        while not self.monitor_stop.wait(0.1):
            try:
                readable, _, _ = select.select([self.sock], [], [], 0.1)
            except (OSError, ValueError):
                readable = [self.sock]
            if not readable:
                continue
            try:
                peek_flags = socket.MSG_PEEK | getattr(socket, "MSG_DONTWAIT", 0)
                peek = self.sock.recv(1, peek_flags)
            except BlockingIOError:
                continue
            except OSError:
                peek = b""
            if not peek:
                self.closed.set()
                callback()
                return

    def close(self) -> None:
        self.closed.set()
        self.monitor_stop.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class _BridgeAttachment:
    def __init__(self, connection: WebSocketConnection) -> None:
        self.connection = connection
        self.send_lock = threading.Lock()
        self.ready = threading.Event()
        self.closed = threading.Event()
        self.metadata: dict[str, Any] = {}

    def send(self, message_type: str, request_id: str, payload: Mapping[str, Any] | None = None) -> None:
        if self.closed.is_set():
            raise PeerDisconnected("browser bridge is disconnected")
        message = make_envelope(message_type, request_id, payload)
        with self.send_lock:
            self.connection.send_json(message)

    def close(self) -> None:
        self.closed.set()
        try:
            self.connection.close()
        except OSError:
            pass


class PersistentBroker:
    """Own a persistent control listener and one browser bridge listener."""

    def __init__(
        self,
        paths: RuntimePaths | None = None,
        *,
        origin: str = DEFAULT_ORIGIN,
        token_ttl_seconds: float = DEFAULT_TOKEN_TTL_SECONDS,
        operation_timeout_seconds: float = DEFAULT_OPERATION_TIMEOUT_SECONDS,
        bridge_auth_timeout_seconds: float = DEFAULT_BRIDGE_AUTH_TIMEOUT_SECONDS,
        bridge_ready_timeout_seconds: float = BRIDGE_READY_TIMEOUT_SECONDS,
        expected_manifest: str | Path | None = None,
        control_port: int = 0,
        websocket_port: int = 0,
    ) -> None:
        runtime_paths = paths or RuntimePaths.from_environment()
        self.config = BrokerConfig(
            runtime_paths,
            origin=origin,
            token_ttl_seconds=token_ttl_seconds,
            operation_timeout_seconds=operation_timeout_seconds,
            bridge_auth_timeout_seconds=bridge_auth_timeout_seconds,
            bridge_ready_timeout_seconds=bridge_ready_timeout_seconds,
            expected_manifest=Path(expected_manifest) if expected_manifest is not None else None,
        )
        self.control_port = control_port
        self.websocket_port = websocket_port
        self._lock = runtime_paths.lock
        self._state_lock = threading.RLock()
        self._state: BrokerState | None = None
        self._secret: str | None = None
        self._control_listener: socket.socket | None = None
        self._websocket_server: LoopbackWebSocketServer | None = None
        self._control_thread: threading.Thread | None = None
        self._operation_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._started = False
        self._bridge: _BridgeAttachment | None = None
        self._bootstrap: _BootstrapToken | None = None
        self._used_token_digests: dict[str, float] = {}
        self._sessions: dict[str, _ControlSession] = {}
        self._pending: dict[str, _Operation] = {}
        self._queued: dict[str, _Operation] = {}
        self._operation_queue: queue.Queue[_Operation | None] = queue.Queue()
        self._expected_artifact = self._read_expected_artifact()

    @property
    def paths(self) -> RuntimePaths:
        return self.config.paths

    @property
    def state(self) -> BrokerState | None:
        with self._state_lock:
            return self._state

    @property
    def control_endpoint(self) -> Endpoint:
        if self._control_listener is None:
            raise BrokerError("broker is not started")
        return Endpoint("127.0.0.1", int(self._control_listener.getsockname()[1]))

    @property
    def websocket_endpoint(self) -> Endpoint:
        if self._websocket_server is None:
            raise BrokerError("broker is not started")
        return Endpoint("127.0.0.1", self._websocket_server.port)

    def start(self) -> "PersistentBroker":
        with self._state_lock:
            if self._started:
                return self
            self._stop = threading.Event()
            self._operation_queue = queue.Queue()
        self.paths.ensure_root()
        self._lock.acquire(recover_stale=True)
        try:
            self._secret = self.paths.write_secret()
            self._control_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._control_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._control_listener.bind(("127.0.0.1", self.control_port))
            self._control_listener.listen(8)
            self._control_listener.settimeout(0.25)
            self._websocket_server = LoopbackWebSocketServer(
                self._on_websocket_connection,
                expected_origin=self.config.origin,
                host="127.0.0.1",
                port=self.websocket_port,
                max_bytes=BRIDGE_MAX_MESSAGE_BYTES,
            ).start()
            self._state = BrokerState(
                pid=os.getpid(),
                control=self.control_endpoint,
                websocket=self.websocket_endpoint,
                origin=self.config.origin,
                state="starting",
                generation=0,
                started_at=time.time(),
                artifact=self._expected_artifact,
            )
            self._publish_state("disconnected")
            self._started = True
            self._control_thread = threading.Thread(
                target=self._control_accept_loop,
                name="klang-web-control",
                daemon=True,
            )
            self._control_thread.start()
            self._operation_thread = threading.Thread(
                target=self._operation_loop,
                name="klang-web-operations",
                daemon=True,
            )
            self._operation_thread.start()
            return self
        except BaseException:
            self._close_listeners()
            self.paths.remove_state()
            self.paths.remove_secret()
            self._lock.release()
            raise

    def serve_forever(self) -> None:
        if not self._started:
            self.start()
        while not self._stop.wait(0.5):
            self._expire_bootstrap()

    def stop(self, *, remove_state: bool = True) -> None:
        with self._state_lock:
            if not self._started and self._state is None:
                if remove_state:
                    self.paths.remove_state()
                    self.paths.remove_secret()
                return
            self._stop.set()
            self._publish_state("stopping")
            pending = list(self._pending.values()) + list(self._queued.values())
            for operation in pending:
                operation.cancelled = True
                operation.error = BrokerError("broker is shutting down")
                operation.done.set()
            self._pending.clear()
            self._queued.clear()
            self._operation_queue.put(None)
            bridge = self._bridge
            self._bridge = None
            sessions = list(self._sessions.values())
            self._sessions.clear()
        if bridge is not None:
            bridge.close()
        for session in sessions:
            session.close()
        self._close_listeners()
        for thread in (self._control_thread, self._operation_thread):
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=1)
        with self._state_lock:
            self._started = False
            self._state = None
            self._bootstrap = None
            self._used_token_digests.clear()
        if remove_state:
            self.paths.remove_state()
            self.paths.remove_secret()
        self._lock.release()

    def status_payload(self) -> dict[str, Any]:
        self._expire_bootstrap()
        with self._state_lock:
            state = self._state
            bridge = self._bridge
            bootstrap = self._bootstrap
            if state is None:
                return {
                    "status": "disconnected",
                    "state": "disconnected",
                    "attached": False,
                    "generation": 0,
                }
            payload: dict[str, Any] = {
                "status": state.state,
                "state": state.state,
                "pid": state.pid,
                "control": state.control.as_dict(),
                "websocket": state.websocket.as_dict(),
                "origin": state.origin,
                "protocolVersion": state.protocol_version,
                "attached": bridge is not None,
                "ready": bool(bridge is not None and bridge.ready.is_set()),
                "generation": state.generation,
                "workerGeneration": state.generation,
            }
            if state.artifact is not None:
                payload["artifact"] = dict(state.artifact)
                payload["compilerCommit"] = state.artifact.get("klangCommit")
                payload["artifactHash"] = state.artifact.get("sha256")
            if bridge is not None:
                payload.update(
                    {
                        "workerVersion": bridge.metadata.get("workerVersion"),
                        "pyodideVersion": bridge.metadata.get("pyodideVersion"),
                    }
                )
            if bootstrap is not None and not bootstrap.consumed:
                payload["bootstrapExpiresAt"] = bootstrap.expires_at_wall
            return payload

    def request_connect(self) -> dict[str, Any]:
        """Return readiness or a one-time bridge URL for the caller to open."""

        self._require_started()
        self._expire_bootstrap()
        with self._state_lock:
            if self._bridge is not None and self._bridge.ready.is_set():
                return self.status_payload()
            if self._bootstrap is None:
                token = secrets.token_urlsafe(32)
                self._bootstrap = _BootstrapToken(
                    token,
                    time.monotonic() + self.config.token_ttl_seconds,
                    time.time() + self.config.token_ttl_seconds,
                )
            self._publish_state("bootstrapping")
            bootstrap = self._bootstrap
            assert bootstrap is not None
            return {
                "status": "bootstrapping",
                "state": "bootstrapping",
                "ready": False,
                "attached": self._bridge is not None,
                "bridgeUrl": self._bridge_url(bootstrap.value),
                "expiresAt": bootstrap.expires_at_wall,
                "websocket": self.websocket_endpoint.as_dict(),
                "origin": self.config.origin,
            }

    def connect(self) -> dict[str, Any]:
        return self.request_connect()

    def status(self) -> dict[str, Any]:
        return self.status_payload()

    def disconnect(self) -> dict[str, Any]:
        return self.request_dispose(owner_id="broker", shutdown=True)

    def submit_operation(
        self,
        *,
        owner_id: str,
        request_id: str,
        operation: str,
        payload: Mapping[str, Any],
        timeout: float | None = None,
        on_event: Callable[[str, Mapping[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        self._require_started()
        if operation not in BRIDGE_OPERATIONS:
            raise BrokerError(f"unsupported bridge operation: {operation}")
        if not request_id:
            raise BrokerError("operation requestId is required")
        with self._state_lock:
            if self._bridge is None or not self._bridge.ready.is_set():
                raise BrokerNotReadyError("No ready browser bridge. Run `klangb connect` first.")
            if request_id in self._pending or request_id in self._queued:
                raise BrokerError("duplicate operation requestId")
            effective_timeout = timeout if timeout is not None else self.config.operation_timeout_seconds
            if effective_timeout <= 0:
                raise BrokerError("operation timeout must be positive")
            item = _Operation(
                request_id=request_id,
                owner_id=owner_id,
                operation=operation,
                payload=dict(payload),
                timeout=effective_timeout,
                on_event=on_event,
            )
            self._queued[request_id] = item
            self._operation_queue.put(item)
        if not item.done.wait(item.timeout + 1.0):
            item.cancelled = True
            self._request_bridge_stop(request_id)
            raise BrokerError("browser operation timed out", code="client-timeout")
        if item.error is not None:
            raise item.error
        return item.result or {}

    def submit_stdin(self, *, owner_id: str, input_request_id: str, line: str | None, eof: bool = False) -> dict[str, Any]:
        self._require_started()
        if not input_request_id:
            raise BrokerError("stdin request id is required", code="client-protocol")
        if line is not None and len(line.encode("utf-8")) > MAX_INPUT_BYTES:
            raise BrokerError("stdin line exceeds the input limit", code="client-protocol")
        with self._state_lock:
            bridge = self._bridge
            if bridge is None or not bridge.ready.is_set():
                raise BrokerNotReadyError("browser bridge is disconnected")
        # v1 represents EOF as an empty final line; stdin requests themselves
        # carry the browser-generated inputRequestId when one is available.
        del eof
        payload: dict[str, Any] = {"line": line if line is not None else ""}
        if input_request_id:
            payload["inputRequestId"] = input_request_id
        try:
            bridge.send("stdin", input_request_id or "stdin-" + uuid.uuid4().hex, payload)
        except (PeerDisconnected, WebSocketError, OSError) as error:
            raise BrokerNotReadyError("browser bridge is disconnected") from error
        return {"accepted": True, "inputRequestId": input_request_id}

    def request_stop(self, *, owner_id: str, request_id: str | None = None) -> dict[str, Any]:
        del owner_id
        with self._state_lock:
            active = next(
                (operation for operation in self._pending.values() if request_id is None or operation.request_id == request_id),
                None,
            )
        if active is None:
            return {"accepted": False, "reason": "no-active-operation"}
        self._request_bridge_stop(active.request_id)
        return {"accepted": True, "requestId": active.request_id}

    def request_dispose(self, *, owner_id: str, shutdown: bool = False) -> dict[str, Any]:
        del owner_id
        with self._state_lock:
            bridge = self._bridge
            ready = bridge is not None and bridge.ready.is_set()
        if bridge is not None and ready:
            try:
                bridge.send("dispose", "dispose-" + uuid.uuid4().hex, {})
            except (PeerDisconnected, WebSocketError, OSError):
                pass
        if shutdown:
            threading.Thread(target=self.stop, name="klang-web-shutdown", daemon=True).start()
        return {"disposed": True, "status": "stopping" if shutdown else "disconnected"}

    def cancel_owner(self, owner_id: str) -> None:
        with self._state_lock:
            active: list[_Operation] = []
            for operation in list(self._pending.values()):
                if operation.owner_id != owner_id:
                    continue
                active.append(operation)
                operation.cancelled = True
                operation.error = BrokerNotReadyError("control client disconnected")
                operation.done.set()
                self._pending.pop(operation.request_id, None)
            for operation in list(self._queued.values()):
                if operation.owner_id != owner_id:
                    continue
                operation.cancelled = True
                operation.error = BrokerNotReadyError("control client disconnected")
                operation.done.set()
                self._queued.pop(operation.request_id, None)
            bridge = self._bridge
        # Send Stop after releasing the broker lock; WebSocket writers can
        # synchronously encounter the browser's close path.
        if bridge is not None:
            for operation in active:
                self._request_bridge_stop(operation.request_id)

    def _require_started(self) -> None:
        if not self._started:
            raise BrokerError("broker is not started")

    def _read_expected_artifact(self) -> dict[str, Any] | None:
        manifest = self.config.expected_manifest
        if manifest is None:
            return {
                "klangVersion": PINNED_KLANG_VERSION,
                "klangCommit": PINNED_KLANG_COMMIT,
                "sha256": PINNED_ARTIFACT_SHA256,
                "sizeBytes": PINNED_ARTIFACT_SIZE_BYTES,
                "supportedDialects": list(SUPPORTED_DIALECTS),
            }
        try:
            value = json.loads(manifest.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise BrokerError("packaged compiler manifest is malformed")
            artifact = value.get("artifact")
            if not isinstance(artifact, dict):
                raise BrokerError("packaged compiler manifest is malformed")
            expected = {
                "klangVersion": value.get("klangVersion"),
                "klangCommit": value.get("klangCommit"),
                "sha256": artifact.get("sha256"),
                "sizeBytes": artifact.get("sizeBytes"),
                "supportedDialects": value.get("supportedDialects"),
            }
            if expected != {
                "klangVersion": PINNED_KLANG_VERSION,
                "klangCommit": PINNED_KLANG_COMMIT,
                "sha256": PINNED_ARTIFACT_SHA256,
                "sizeBytes": PINNED_ARTIFACT_SIZE_BYTES,
                "supportedDialects": list(SUPPORTED_DIALECTS),
            }:
                raise BrokerError("packaged compiler manifest does not match the pinned contract")
            return expected
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise BrokerError("could not read packaged compiler manifest") from error

    def _publish_state(self, state_name: str) -> None:
        with self._state_lock:
            if self._state is None:
                return
            current = self._state
            self._state = BrokerState(
                pid=current.pid,
                control=current.control,
                websocket=current.websocket,
                origin=current.origin,
                state=state_name,
                protocol_version=current.protocol_version,
                generation=current.generation,
                started_at=current.started_at,
                artifact=current.artifact,
            )
            try:
                self.paths.write_state(self._state)
            except OSError as error:
                raise BrokerError("could not publish broker state") from error

    def _publish_ready(self, metadata: dict[str, Any]) -> None:
        with self._state_lock:
            if self._state is None:
                return
            generation = int(metadata["workerGeneration"])
            current = self._state
            self._state = BrokerState(
                pid=current.pid,
                control=current.control,
                websocket=current.websocket,
                origin=current.origin,
                state="ready",
                protocol_version=current.protocol_version,
                generation=generation,
                started_at=current.started_at,
                artifact=current.artifact,
            )
            self.paths.write_state(self._state)

    def _bridge_url(self, token: str) -> str:
        parsed = urlsplit(self.config.origin)
        base = urlunsplit((parsed.scheme, parsed.netloc, "/bridge", "", ""))
        return f"{base}#port={self.websocket_endpoint.port}&token={token}"

    def _expire_bootstrap(self) -> None:
        with self._state_lock:
            bootstrap = self._bootstrap
            if bootstrap is not None and not bootstrap.consumed and time.monotonic() >= bootstrap.expires_at_monotonic:
                self._bootstrap = None
                if self._bridge is None and self._state is not None:
                    self._publish_state("bootstrap-failed")
            now = time.monotonic()
            self._used_token_digests = {
                digest: expiry for digest, expiry in self._used_token_digests.items() if expiry > now
            }

    def _consume_token(self, token: str) -> str:
        self._expire_bootstrap()
        with self._state_lock:
            bootstrap = self._bootstrap
            digest = hmac.new(b"klang-web-token", token.encode("utf-8"), "sha256").hexdigest()
            if digest in self._used_token_digests:
                return "replayed"
            if bootstrap is None:
                return "expired"
            if not hmac.compare_digest(bootstrap.value, token):
                return "incorrect"
            if time.monotonic() >= bootstrap.expires_at_monotonic:
                self._bootstrap = None
                self._publish_state("bootstrap-failed")
                return "expired"
            bootstrap.consumed = True
            self._used_token_digests[digest] = time.monotonic() + self.config.token_ttl_seconds
            self._bootstrap = None
            return "ok"

    def _on_websocket_connection(self, connection: WebSocketConnection) -> None:
        attachment: _BridgeAttachment | None = None
        try:
            # The browser starts with a protocol/client negotiation before the
            # one-time token is accepted.  Keeping these phases explicit makes
            # an authenticated socket impossible to reach by skipping a step.
            raw = connection.recv_json(timeout=self.config.bridge_auth_timeout_seconds)
            if raw is None:
                return
            handshake = Envelope.from_value(raw, channel="bridge")
            if handshake.type != "handshake" or handshake.request_id != BRIDGE_HANDSHAKE_REQUEST_ID:
                self._send_bridge_error(connection, handshake.request_id, "invalid-request", "bridge handshake is required")
                return
            connection.send_json(
                make_envelope(
                    "handshake-ack",
                    handshake.request_id,
                    {"acceptedVersion": 1, "server": "klang-web-broker"},
                )
            )

            raw = connection.recv_json(timeout=self.config.bridge_auth_timeout_seconds)
            if raw is None:
                return
            authenticate = Envelope.from_value(raw, channel="bridge")
            if authenticate.type != "authenticate" or authenticate.request_id != BRIDGE_AUTH_REQUEST_ID:
                self._send_bridge_error(connection, authenticate.request_id, "invalid-request", "bridge authentication is required")
                return
            token = authenticate.payload.get("token")
            assert isinstance(token, str)
            with self._state_lock:
                if self._bridge is not None:
                    self._send_bridge_error(connection, authenticate.request_id, "busy", "a browser bridge is already attached")
                    return
            token_status = self._consume_token(token)
            if token_status != "ok":
                code = "authentication-expired" if token_status == "expired" else "authentication-failed"
                self._send_bridge_error(connection, authenticate.request_id, code, "bridge authentication failed")
                return
            with self._state_lock:
                if self._bridge is not None:
                    self._send_bridge_error(connection, authenticate.request_id, "busy", "a browser bridge is already attached")
                    return
                attachment = _BridgeAttachment(connection)
                self._bridge = attachment
                self._publish_state("bootstrapping")
            attachment.send("authenticated", authenticate.request_id, {"authenticated": True})

            # Runtime bootstrap is intentionally longer than handshake and
            # token-authentication timeouts: Pyodide and the compiler artifact
            # may take tens of seconds on a cold headless browser.
            raw = connection.recv_json(timeout=self.config.bridge_ready_timeout_seconds)
            if raw is None:
                return
            ready = Envelope.from_value(raw, channel="bridge")
            if ready.type != "ready" or ready.request_id != BRIDGE_READY_REQUEST_ID:
                self._send_bridge_error(connection, ready.request_id, "invalid-request", "browser runtime readiness is required")
                return
            metadata = self._validate_ready_metadata(ready.payload)
            attachment.metadata = metadata
            attachment.ready.set()
            self._publish_ready(metadata)
            attachment.send("ready-ack", ready.request_id, self._ready_status_payload(metadata))

            while not self._stop.is_set():
                raw_message = connection.recv_json(timeout=None)
                if raw_message is None:
                    break
                message = Envelope.from_value(raw_message, channel="bridge")
                self._handle_bridge_message(attachment, message)
        except socket.timeout:
            if attachment is not None:
                self._mark_bootstrap_failed()
        except (ProtocolError, WebSocketProtocolError) as error:
            try:
                code = error.code if isinstance(error, ProtocolError) and error.code in BRIDGE_ERROR_CODES else "invalid-envelope"
                self._send_bridge_error(connection, "protocol", code, str(error))
            except Exception:
                pass
            if attachment is not None:
                self._mark_bootstrap_failed()
        except BridgeError as error:
            if attachment is not None:
                try:
                    self._send_bridge_error(connection, "protocol", "worker-failed", str(error), retryable=True)
                except Exception:
                    pass
                self._mark_bootstrap_failed()
        except (PeerDisconnected, WebSocketError, OSError):
            pass
        finally:
            if attachment is not None:
                self._detach_bridge(attachment)

    def _send_bridge_error(
        self,
        connection: WebSocketConnection,
        request_id: str,
        code: str,
        message: str,
        *,
        retryable: bool | None = None,
    ) -> None:
        payload: dict[str, Any] = {"code": code, "message": message}
        if retryable is not None:
            payload["retryable"] = retryable
        try:
            connection.send_json(make_envelope("error", request_id, payload))
        finally:
            try:
                connection.send_close(1008, "Bridge protocol error.")
            except Exception:
                pass

    def _reject_bridge(self, connection: WebSocketConnection, close_code: int, message: str) -> None:
        try:
            connection.send_close(close_code, message)
        except Exception:
            pass

    def _ready_status_payload(self, metadata: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "state": "ready",
            "ready": True,
            "workerGeneration": metadata["workerGeneration"],
            "workerVersion": metadata["workerVersion"],
            "pyodideVersion": metadata["pyodideVersion"],
            "artifact": metadata["artifact"],
        }

    def _mark_bootstrap_failed(self) -> None:
        with self._state_lock:
            if self._state is not None and (self._bridge is None or not self._bridge.ready.is_set()):
                self._publish_state("bootstrap-failed")

    def _detach_bridge(self, attachment: _BridgeAttachment) -> None:
        with self._state_lock:
            if self._bridge is not attachment:
                return
            self._bridge = None
            for operation in list(self._pending.values()):
                operation.error = BrokerNotReadyError("browser bridge disconnected")
                operation.done.set()
            self._pending.clear()
            if self._state is not None and not self._stop.is_set():
                self._publish_state("bootstrap-failed" if not attachment.ready.is_set() else "disconnected")
        attachment.closed.set()

    def _validate_ready_metadata(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        artifact = payload.get("artifact")
        if not isinstance(artifact, dict):
            raise BridgeError("bridge readiness did not include artifact metadata")
        if artifact.get("klangVersion") != PINNED_KLANG_VERSION:
            raise BridgeError("bridge compiler version does not match the pinned contract")
        if artifact.get("klangCommit") != PINNED_KLANG_COMMIT:
            raise BridgeError("bridge compiler commit does not match the pinned contract")
        if artifact.get("supportedDialects") != list(SUPPORTED_DIALECTS):
            raise BridgeError("bridge dialect catalog does not match the pinned contract")
        expected = self._expected_artifact
        if expected is not None:
            for key in ("sha256", "sizeBytes"):
                if artifact.get(key) != expected.get(key):
                    raise BridgeError(f"bridge artifact {key} does not match the packaged artifact")
        generation = payload.get("workerGeneration")
        worker_version = payload.get("workerVersion")
        pyodide_version = payload.get("pyodideVersion")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
            raise BridgeError("bridge readiness workerGeneration is invalid")
        if not isinstance(worker_version, str) or not worker_version:
            raise BridgeError("bridge readiness worker version is missing")
        if not isinstance(pyodide_version, str) or not pyodide_version:
            raise BridgeError("bridge readiness Pyodide version is missing")
        if pyodide_version != EXPECTED_PYODIDE_VERSION:
            raise BridgeError("bridge Pyodide version does not match the packaged runtime")
        contract = payload.get("contract")
        if contract is not None:
            self._validate_contract_metadata(contract, artifact)
        for key in ("cliContract", "compilerContract", "contract"):
            nested = artifact.get(key)
            if isinstance(nested, dict):
                self._validate_contract_metadata(nested, artifact)
        return {
            "workerGeneration": generation,
            "workerVersion": worker_version,
            "pyodideVersion": pyodide_version,
            "artifact": dict(artifact),
            **({"contract": dict(contract)} if isinstance(contract, dict) else {}),
        }

    def _validate_contract_metadata(
        self,
        contract: Mapping[str, Any],
        artifact: Mapping[str, Any],
    ) -> None:
        if contract.get("klangCommit") not in {None, PINNED_KLANG_COMMIT}:
            raise BridgeError("bridge compiler contract commit does not match the pinned artifact")
        contract_hash = contract.get("artifactSha256", contract.get("compilerArtifactHash"))
        if contract_hash is not None and contract_hash != artifact.get("sha256"):
            raise BridgeError("bridge compiler contract hash does not match the pinned artifact")
        if "schemaVersion" in contract and contract["schemaVersion"] != 1:
            raise BridgeError("bridge compiler contract schema is unsupported")
        if "dialects" in contract and contract["dialects"] != list(SUPPORTED_DIALECTS):
            raise BridgeError("bridge compiler contract dialects do not match the pinned contract")
        if "irModes" in contract and contract["irModes"] != list(IR_MODES):
            raise BridgeError("bridge compiler contract IR modes do not match the pinned contract")
        if "options" in contract and contract["options"] != list(COMPILER_OPTIONS):
            raise BridgeError("bridge compiler contract options do not match the pinned contract")

    def _handle_bridge_message(self, attachment: _BridgeAttachment, message: Envelope) -> None:
        if message.type in {"result", "error"}:
            if message.type == "result":
                result_payload = message.payload.get("result")
                if isinstance(result_payload, dict):
                    self._finish_operation(message.request_id, result=result_payload)
                else:
                    # Status/stop/dispose acknowledgements are useful to the
                    # native control caller even when they contain no RunResult.
                    self._finish_operation(message.request_id, result=dict(message.payload))
            else:
                code = message.payload.get("code", "execution-failed")
                detail = message.payload.get("message", "The browser bridge rejected the operation.")
                safe_code = code if isinstance(code, str) and code in BRIDGE_ERROR_CODES else "execution-failed"
                self._finish_operation(message.request_id, error=BridgeError(f"{code}: {detail}", code=safe_code))
        elif message.type == "status":
            self._handle_bridge_status(attachment, message.payload)
        elif message.type in {"output", "compiler-output", "stdin-request", "diagnostic", "mutation", "resource-limit"}:
            self._relay_bridge_event(attachment, message)

    def _handle_bridge_status(self, attachment: _BridgeAttachment, payload: Mapping[str, Any]) -> None:
        status = payload.get("state")
        if status == "ready":
            # A status message can complete readiness in implementations that
            # replay it after the ready acknowledgement was lost. Revalidate
            # metadata on later ready announcements as well so artifact drift
            # cannot silently become executable.
            metadata = self._validate_status_ready_metadata(payload)
            attachment.metadata = metadata
            attachment.ready.set()
            self._publish_ready(metadata)
        elif status in {"loading", "busy", "resetting", "failed", "disconnected"}:
            if status != "busy":
                attachment.ready.clear()
            with self._state_lock:
                if self._state is not None:
                    next_state = "bootstrap-failed" if status == "failed" else (
                        "bootstrapping" if status in {"loading", "resetting"} else (
                            "ready" if status == "busy" else "disconnected"
                        )
                    )
                    self._publish_state(next_state)
            if status in {"failed", "disconnected"}:
                with self._state_lock:
                    for operation in list(self._pending.values()):
                        operation.error = BrokerNotReadyError("browser bridge disconnected")
                        operation.done.set()
                    self._pending.clear()

    def _validate_status_ready_metadata(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        metadata = {
            "artifact": payload.get("artifact"),
            "pyodideVersion": payload.get("pyodideVersion"),
            "workerVersion": payload.get("workerVersion"),
            "workerGeneration": payload.get("workerGeneration"),
        }
        return self._validate_ready_metadata(metadata)

    def _relay_bridge_event(self, attachment: _BridgeAttachment, message: Envelope) -> None:
        with self._state_lock:
            operation = self._pending.get(message.request_id)
            sessions = [self._sessions.get(operation.owner_id)] if operation is not None else []
        if operation is not None and operation.on_event is not None:
            operation.on_event(message.type, message.payload)
        for session in sessions:
            if session is None:
                continue
            event_type = "control-input-request" if message.type == "stdin-request" else "control-output"
            try:
                session.send(event_type, message.request_id, {"event": message.type, **message.payload})
            except (PeerDisconnected, OSError):
                pass

    def _finish_operation(
        self,
        request_id: str,
        *,
        result: dict[str, Any] | None = None,
        error: BrokerError | None = None,
    ) -> None:
        with self._state_lock:
            operation = self._pending.pop(request_id, None)
            if operation is None:
                return
            operation.result = result
            operation.error = error
            operation.done.set()

    def _request_bridge_stop(self, request_id: str) -> None:
        with self._state_lock:
            bridge = self._bridge
        if bridge is None:
            return
        try:
            # The v1 browser protocol models Stop as a direct operation request;
            # its correlation is the request id, while its payload is empty.
            bridge.send("stop", request_id, {})
        except (PeerDisconnected, WebSocketError, OSError):
            pass

    def _operation_loop(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._operation_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if item is None:
                return
            with self._state_lock:
                self._queued.pop(item.request_id, None)
            if item.cancelled:
                item.done.set()
                continue
            with self._state_lock:
                bridge = self._bridge
                if bridge is None or not bridge.ready.is_set():
                    item.error = BrokerNotReadyError("browser bridge is disconnected")
                    item.done.set()
                    continue
                self._pending[item.request_id] = item
            try:
                bridge.send(item.operation, item.request_id, self._bridge_operation_payload(item))
            except (PeerDisconnected, WebSocketError, OSError) as error:
                self._finish_operation(item.request_id, error=BrokerNotReadyError("browser bridge is disconnected"))
                continue
            if not item.done.wait(item.timeout):
                self._request_bridge_stop(item.request_id)
                self._finish_operation(item.request_id, error=BrokerError("browser operation timed out", code="client-timeout"))

    def _bridge_operation_payload(self, item: _Operation) -> dict[str, Any]:
        if item.operation in {"compile", "run"}:
            snapshot = item.payload.get("snapshot")
            if not isinstance(snapshot, dict):
                raise BrokerError("bridge operation is missing its snapshot", code="client-protocol")
            return {"snapshot": snapshot}
        if item.operation == "emit-ir":
            snapshot = item.payload.get("snapshot")
            mode = item.payload.get("mode")
            if not isinstance(snapshot, dict) or mode not in {"default", "typed", "spans"}:
                raise BrokerError("bridge IR operation is missing its snapshot or mode", code="client-protocol")
            return {"snapshot": snapshot, "mode": mode}
        if item.operation == "stdin":
            return {key: value for key, value in item.payload.items() if key in {"line", "inputRequestId"}}
        return {}

    def _control_accept_loop(self) -> None:
        listener = self._control_listener
        if listener is None:
            return
        while not self._stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(
                target=self._control_session,
                args=(client,),
                name="klang-web-control-client",
                daemon=True,
            )
            thread.start()

    def _control_session(self, sock: socket.socket) -> None:
        session = _ControlSession(sock, uuid.uuid4().hex)
        with self._state_lock:
            self._sessions[session.session_id] = session
        try:
            auth = session.framer.receive_envelope(timeout=DEFAULT_CONTROL_TIMEOUT_SECONDS, channel="control")
            if auth.type != "control-auth":
                session.send("control-error", auth.request_id, {"code": "client-authentication", "message": "control authentication is required"})
                return
            supplied = auth.payload.get("secret")
            if not isinstance(supplied, str) or self._secret is None or not hmac.compare_digest(supplied, self._secret):
                session.send("control-error", auth.request_id, {"code": "client-authentication", "message": "control authentication failed"})
                return
            session.send("control-authenticated", auth.request_id, {"protocolVersion": 1})
            sock.settimeout(None)
            session.start_disconnect_monitor(lambda: self.cancel_owner(session.session_id))
            while not self._stop.is_set() and not session.closed.is_set():
                message = session.framer.receive_envelope(channel="control")
                response = self._dispatch_control(session, message)
                if response is not None:
                    response_type, payload = response
                    session.send(response_type, message.request_id, payload)
        except socket.timeout:
            pass
        except (PeerDisconnected, ConnectionError, OSError):
            pass
        except ProtocolError as error:
            try:
                session.send("control-error", "protocol", {"code": "client-protocol", "message": str(error)})
            except Exception:
                pass
        finally:
            session.stop_disconnect_monitor()
            session.closed.set()
            with self._state_lock:
                self._sessions.pop(session.session_id, None)
            self.cancel_owner(session.session_id)
            session.close()

    def _dispatch_control(self, session: _ControlSession, message: Envelope) -> tuple[str, dict[str, Any]] | None:
        try:
            if message.type == "control-status":
                return "control-result", self.status_payload()
            if message.type == "control-connect":
                return "control-result", self.request_connect()
            if message.type == "control-ping":
                return "control-pong", {"status": self.status_payload().get("status")}
            if message.type == "control-operation":
                operation = message.payload.get("operation")
                if not isinstance(operation, str):
                    raise BrokerError("control operation is missing")
                payload = dict(message.payload)
                payload.pop("operation", None)
                result = self.submit_operation(
                    owner_id=session.session_id,
                    request_id=message.request_id,
                    operation=operation,
                    payload=payload,
                    on_event=lambda event, value: None,
                )
                return "control-result", result
            if message.type == "control-stdin":
                input_request_id = message.payload["inputRequestId"]
                line = message.payload.get("line")
                eof = bool(message.payload.get("eof", False))
                return "control-result", self.submit_stdin(owner_id=session.session_id, input_request_id=input_request_id, line=line if isinstance(line, str) else None, eof=eof)
            if message.type == "control-stop":
                request_id = message.payload.get("requestId")
                return "control-result", self.request_stop(owner_id=session.session_id, request_id=request_id if isinstance(request_id, str) else None)
            if message.type in {"control-dispose", "control-disconnect", "control-shutdown"}:
                shutdown = message.type != "control-dispose"
                result = self.request_dispose(owner_id=session.session_id, shutdown=shutdown)
                return "control-result", result
            if message.type == "control-accepted":
                raise ProtocolError("control-accepted is a response, not a request")
            raise ProtocolError("unsupported control message")
        except BrokerError as error:
            return "control-error", {"code": error.code, "message": str(error)}
        except (KeyError, TypeError, ValueError) as error:
            return "control-error", {"code": "client-protocol", "message": str(error)}

    def _close_listeners(self) -> None:
        listener = self._control_listener
        self._control_listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        server = self._websocket_server
        self._websocket_server = None
        if server is not None:
            server.close()


def spawn_detached_broker(
    paths: RuntimePaths,
    *,
    origin: str = DEFAULT_ORIGIN,
    python_executable: str | None = None,
    extra_environment: Mapping[str, str] | None = None,
) -> subprocess.Popen[bytes]:
    """Start a broker process without tying its lifetime to the CLI process."""

    executable = python_executable or sys.executable
    command = [
        executable,
        "-m",
        "klang_web.broker",
        "--serve",
        "--runtime-dir",
        str(paths.root),
        "--origin",
        origin,
    ]
    environment = os.environ.copy()
    environment["KLANG_WEB_RUNTIME_DIR"] = str(paths.root)
    if extra_environment:
        environment.update(extra_environment)
    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "env": environment,
        "close_fds": os.name != "nt",
    }
    if os.name == "nt":
        detached = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
        new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        kwargs["creationflags"] = detached | new_group
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(command, **kwargs)


def _run_server(args: argparse.Namespace) -> int:
    paths = RuntimePaths(Path(args.runtime_dir).expanduser().resolve())
    broker = PersistentBroker(paths, origin=args.origin)
    shutting_down = threading.Event()

    def stop_handler(signum: int, frame: Any) -> None:
        del signum, frame
        if not shutting_down.is_set():
            shutting_down.set()
            broker.stop()

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_handler)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, stop_handler)
    try:
        broker.serve_forever()
    finally:
        broker.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="klangb-broker")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--runtime-dir", required=False)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN)
    args = parser.parse_args(argv)
    if not args.serve:
        parser.error("the broker is an internal command; use klangb")
    if not args.runtime_dir:
        parser.error("--runtime-dir is required")
    return _run_server(args)


# Public vocabulary aliases keep the lifecycle core easy to discover without
# introducing a second broker implementation.
Broker = PersistentBroker


if __name__ == "__main__":
    raise SystemExit(main())
