"""Native control client, broker discovery, and CLI-facing operation helpers."""

from __future__ import annotations

import os
import signal
import socket
import threading
import subprocess
import sys
import time
import uuid
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .broker import DEFAULT_ORIGIN, spawn_detached_broker
from .paths import RuntimePaths, RuntimeStateError
from .protocol import (
    MAX_FRAME_BYTES,
    Envelope,
    JsonFramer,
    PeerDisconnected,
    ProtocolError,
    make_envelope,
)
from .snapshot import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    SourceSnapshot,
    atomic_write_text,
    discover_snapshot,
)

CLIENT_EXIT_STATUS = 3
BROKER_START_TIMEOUT_SECONDS = 8.0
BRIDGE_READY_TIMEOUT_SECONDS = 120.0
POLL_INTERVAL_SECONDS = 0.1


class ClientError(RuntimeError):
    """An error in the native client/broker boundary, not the KLang program."""

    def __init__(self, message: str, *, code: str = "client-broker", exit_code: int = CLIENT_EXIT_STATUS) -> None:
        self.code = code
        self.exit_code = exit_code
        super().__init__(message)


class RemoteBridgeError(ClientError):
    code = "execution-failed"


@dataclass(frozen=True)
class ClientStatus:
    status: str
    detail: Mapping[str, Any]


class ControlClient:
    """Authenticated length-prefixed client for one broker control socket."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        secret: str,
        max_bytes: int | None = None,
        paths: RuntimePaths | None = None,
    ) -> None:
        self.sock = sock
        self.secret = secret
        self.paths = paths
        self.framer = JsonFramer(sock, max_bytes=max_bytes or MAX_FRAME_BYTES)
        self._send_lock = threading.Lock()
        self._closed = False

    @classmethod
    def open(
        cls,
        paths: RuntimePaths,
        *,
        timeout: float = 5.0,
    ) -> "ControlClient":
        try:
            state = paths.read_state()
            if state is None:
                raise ClientError("No browser broker is running. Run `klangb connect` first.", code="client-disconnected")
            secret = paths.read_secret()
            sock = socket.create_connection((state.control.host, state.control.port), timeout=timeout)
        except ClientError:
            raise
        except (OSError, RuntimeStateError) as error:
            raise ClientError("The browser broker is unavailable. Run `klangb connect`.", code="client-disconnected") from error
        client = cls(sock, secret=secret, paths=paths)
        try:
            client._authenticate(timeout=timeout)
        except BaseException:
            client.close()
            raise
        return client

    def _authenticate(self, *, timeout: float) -> None:
        request_id = "auth-" + uuid.uuid4().hex
        self._send("control-auth", request_id, {"secret": self.secret})
        response = self._receive_until(request_id, timeout=timeout)
        if response.type != "control-authenticated":
            raise ClientError("The browser broker rejected control authentication.", code="client-authentication")

    def request(
        self,
        message_type: str,
        payload: Mapping[str, Any] | None = None,
        *,
        request_id: str | None = None,
        timeout: float = 30.0,
        on_event: Callable[[Envelope], None] | None = None,
    ) -> dict[str, Any]:
        if self._closed:
            raise ClientError("The browser broker connection is closed.", code="client-disconnected")
        correlation_id = request_id or ("request-" + uuid.uuid4().hex)
        self._send(message_type, correlation_id, payload or {})
        response = self._receive_until(correlation_id, timeout=timeout, on_event=on_event)
        if response.type == "control-error":
            code = response.payload.get("code", "client-broker")
            message = response.payload.get("message", "The browser broker rejected the request.")
            if not isinstance(code, str):
                code = "client-broker"
            if not isinstance(message, str):
                message = "The browser broker rejected the request."
            raise ClientError(message, code=code)
        return dict(response.payload)

    def status(self, *, timeout: float = 5.0) -> dict[str, Any]:
        return self.request("control-status", timeout=timeout)

    def connect_bridge(self, *, timeout: float = 5.0) -> dict[str, Any]:
        return self.request("control-connect", timeout=timeout)

    connect = connect_bridge

    def operation(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        request_id: str | None = None,
        timeout: float = 30.0,
        on_event: Callable[[Envelope], None] | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "control-operation",
            {"operation": operation, **dict(payload)},
            request_id=request_id,
            timeout=timeout,
            on_event=on_event,
        )

    def compile(
        self,
        payload: Mapping[str, Any],
        *,
        request_id: str | None = None,
        timeout: float = 30.0,
        on_event: Callable[[Envelope], None] | None = None,
    ) -> dict[str, Any]:
        return self.operation("compile", payload, request_id=request_id, timeout=timeout, on_event=on_event)

    def emit_ir(
        self,
        payload: Mapping[str, Any],
        *,
        request_id: str | None = None,
        timeout: float = 30.0,
        on_event: Callable[[Envelope], None] | None = None,
    ) -> dict[str, Any]:
        return self.operation("emit-ir", payload, request_id=request_id, timeout=timeout, on_event=on_event)

    def run(
        self,
        payload: Mapping[str, Any],
        *,
        request_id: str | None = None,
        timeout: float = 30.0,
        on_event: Callable[[Envelope], None] | None = None,
    ) -> dict[str, Any]:
        return self.operation("run", payload, request_id=request_id, timeout=timeout, on_event=on_event)

    def dispose(self) -> dict[str, Any]:
        return self.operation("dispose", {}, timeout=5.0)

    def send_stdin(self, input_request_id: str, line: str | None = None, *, eof: bool = False) -> None:
        request_id = "stdin-" + uuid.uuid4().hex
        payload: dict[str, Any] = {"inputRequestId": input_request_id, "eof": eof}
        if line is not None:
            payload["line"] = line
        self._send_on_independent_connection("control-stdin", request_id, payload)

    def stop(self, request_id: str | None = None) -> dict[str, Any]:
        payload = {"requestId": request_id} if request_id is not None else {}
        if self.paths is None:
            return self.request("control-stop", payload, timeout=5.0)
        independent = ControlClient.open(self.paths, timeout=1.0)
        try:
            return independent.request("control-stop", payload, timeout=5.0)
        finally:
            independent.close()

    def request_stop_now(self, request_id: str) -> None:
        """Send Stop without recursively reading the response from a SIGINT handler."""

        self._send_on_independent_connection(
            "control-stop", "stop-" + uuid.uuid4().hex, {"requestId": request_id}
        )

    def disconnect(self) -> dict[str, Any]:
        return self.request("control-disconnect", timeout=5.0)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def _send_on_independent_connection(
        self,
        message_type: str,
        request_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        if self.paths is None:
            self._send(message_type, request_id, payload)
            return
        independent = ControlClient.open(self.paths, timeout=1.0)
        try:
            independent._send(message_type, request_id, payload)
        finally:
            independent.close()

    def _send(self, message_type: str, request_id: str, payload: Mapping[str, Any]) -> None:
        if self._closed:
            raise ClientError("The browser broker connection is closed.", code="client-disconnected")
        message = make_envelope(message_type, request_id, payload)
        try:
            with self._send_lock:
                self.framer.send(message)
        except (OSError, PeerDisconnected) as error:
            self._closed = True
            raise ClientError("The browser broker disconnected.", code="client-disconnected") from error

    def _receive_until(
        self,
        request_id: str,
        *,
        timeout: float,
        on_event: Callable[[Envelope], None] | None = None,
    ) -> Envelope:
        old_timeout = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            while True:
                try:
                    message = self.framer.receive_envelope(channel="control")
                except socket.timeout as error:
                    raise ClientError("Timed out waiting for the browser bridge.", code="client-timeout") from error
                except (PeerDisconnected, OSError, ProtocolError) as error:
                    self._closed = True
                    raise ClientError("The browser broker disconnected.", code="client-disconnected") from error
                if message.type in {"control-output", "control-input-request"}:
                    if on_event is not None:
                        on_event(message)
                    continue
                if message.request_id != request_id:
                    # A response for a fire-and-forget stdin message or a stale
                    # request cannot satisfy this operation.  Keep reading so
                    # correlation remains explicit rather than positional.
                    continue
                return message
        finally:
            if not self._closed:
                self.sock.settimeout(old_timeout)


class BrokerManager:
    """Find, start, recover, and stop the one per-user broker."""

    def __init__(
        self,
        paths: RuntimePaths | None = None,
        *,
        origin: str | None = None,
        spawn: Callable[..., subprocess.Popen[Any]] = spawn_detached_broker,
        opener: Callable[[str], Any] = webbrowser.open,
    ) -> None:
        self.paths = paths or RuntimePaths.from_environment()
        configured_origin = os.environ.get("KLANG_WEB_ORIGIN") or self.paths.configured_origin()
        self.origin = origin or configured_origin or DEFAULT_ORIGIN
        self.spawn = spawn
        self.opener = opener

    def open_existing_control(self, *, timeout: float = 5.0) -> ControlClient:
        """Open only an already-running broker; compiler operations never bootstrap one."""

        try:
            state = self.paths.read_state()
        except RuntimeStateError as error:
            raise ClientError("Broker state is stale. Run `klangb connect`.", code="client-disconnected") from error
        if state is None or self.paths.probe(state) == "stale":
            raise ClientError("No ready browser bridge. Run `klangb connect` first.", code="client-disconnected")
        try:
            return ControlClient.open(self.paths, timeout=timeout)
        except ClientError as error:
            raise ClientError("No ready browser bridge. Run `klangb connect` first.", code="client-disconnected") from error

    def open_control(self, *, timeout: float = BROKER_START_TIMEOUT_SECONDS) -> ControlClient:
        deadline = time.monotonic() + timeout
        last_error: BaseException | None = None
        try:
            state = self.paths.read_state()
        except RuntimeStateError:
            state = None
        if state is not None and self.paths.probe(state) in {"ready", "disconnected", "bootstrapping", "bootstrap-failed", "starting"}:
            try:
                return ControlClient.open(self.paths, timeout=min(5.0, max(0.1, deadline - time.monotonic())))
            except ClientError as error:
                last_error = error
        if state is not None:
            self.paths.recover_stale()
        try:
            self.spawn(self.paths, origin=self.origin)
        except (OSError, TypeError) as error:
            raise ClientError("Could not start the browser broker.", code="client-broker") from error
        while time.monotonic() < deadline:
            try:
                state = self.paths.read_state()
                if state is not None and self.paths.endpoint_is_open(state.control, timeout=0.1):
                    try:
                        return ControlClient.open(self.paths, timeout=1.0)
                    except ClientError as error:
                        last_error = error
            except RuntimeStateError as error:
                last_error = error
            time.sleep(POLL_INTERVAL_SECONDS)
        if last_error is not None:
            raise ClientError("The browser broker did not become ready.", code="client-broker") from last_error
        raise ClientError("The browser broker did not become ready.", code="client-broker")

    def connect(self, *, timeout: float = BRIDGE_READY_TIMEOUT_SECONDS) -> dict[str, Any]:
        control = self.open_control()
        try:
            bootstrap = control.connect_bridge(timeout=5.0)
            if bootstrap.get("ready") is True or bootstrap.get("status") == "ready":
                return bootstrap
            bridge_url = bootstrap.get("bridgeUrl")
            if not isinstance(bridge_url, str) or not bridge_url:
                raise ClientError("The broker could not create a browser bridge bootstrap.", code="client-broker")
            try:
                opened = self.opener(bridge_url)
                if opened is False:
                    raise ClientError("Could not open the browser bridge page.", code="client-broker")
            except ClientError:
                raise
            except Exception as error:
                raise ClientError("Could not open the browser bridge page.", code="client-broker") from error
            deadline = time.monotonic() + timeout
            last: dict[str, Any] = bootstrap
            while time.monotonic() < deadline:
                time.sleep(POLL_INTERVAL_SECONDS)
                try:
                    last = control.status(timeout=min(5.0, max(0.1, deadline - time.monotonic())))
                except ClientError as error:
                    raise ClientError("The browser bridge disconnected while bootstrapping.", code="client-disconnected") from error
                if last.get("status") == "ready" and last.get("ready") is True:
                    return last
                if last.get("status") == "bootstrap-failed":
                    raise ClientError("The browser bridge failed to become ready.", code="client-broker")
            raise ClientError("Timed out waiting for the browser Worker/Pyodide bridge.", code="client-timeout")
        finally:
            control.close()

    def status(self) -> ClientStatus:
        try:
            state = self.paths.read_state()
        except RuntimeStateError as error:
            return ClientStatus("stale", {"status": "stale", "message": str(error)})
        if state is None:
            return ClientStatus("disconnected", {"status": "disconnected"})
        observed = self.paths.probe(state)
        if observed == "stale":
            return ClientStatus("stale", {"status": "stale", "pid": state.pid})
        try:
            control = ControlClient.open(self.paths, timeout=1.0)
        except ClientError:
            return ClientStatus("stale", {"status": "stale", "pid": state.pid})
        try:
            payload = control.status(timeout=2.0)
            return ClientStatus(str(payload.get("status", observed)), payload)
        except ClientError as error:
            return ClientStatus("stale", {"status": "stale", "message": str(error)})
        finally:
            control.close()

    def disconnect(self) -> None:
        try:
            state = self.paths.read_state()
        except RuntimeStateError:
            state = None
        if state is not None and self.paths.probe(state) != "stale":
            try:
                control = ControlClient.open(self.paths, timeout=1.0)
            except ClientError:
                control = None
            if control is not None:
                try:
                    control.disconnect()
                except ClientError:
                    pass
                finally:
                    control.close()
        deadline = time.monotonic() + 2.0
        while self.paths.state_file.exists() and time.monotonic() < deadline:
            time.sleep(POLL_INTERVAL_SECONDS)
        self.paths.remove_state()
        self.paths.remove_secret()
        self.paths.lock.release_if_unowned_or_stale()


@dataclass(frozen=True)
class OperationPayload:
    snapshot: SourceSnapshot
    dialect: str
    arguments: tuple[str, ...] = ()
    stdin: str = ""
    interactive_stdin: bool = False
    mode: str | None = None

    def as_dict(self) -> dict[str, Any]:
        limits = {
            "wallTimeMs": 10_000,
            "maxInputBytes": 262_144,
            "maxOutputBytes": 1_048_576,
            "maxFileCount": DEFAULT_MAX_FILES,
            "maxFileBytes": DEFAULT_MAX_FILE_BYTES,
        }
        stdin = {"preloaded": self.stdin, "interactive": self.interactive_stdin}
        settings = {
            "dialect": self.dialect,
            "inference": False,
            "arguments": list(self.arguments),
            "stdin": stdin,
        }
        return {
            "snapshot": {
                "rootPath": self.snapshot.root_path,
                "files": [item.as_dict() for item in self.snapshot.files],
                "settings": settings,
                "limits": limits,
            },
            "dialect": self.dialect,
            "arguments": list(self.arguments),
            "stdin": stdin,
            "limits": limits,
            **({"mode": self.mode} if self.mode is not None else {}),
        }


def read_redirected_stdin(stream: Any = None) -> tuple[str, bool]:
    """Read finite stdin without changing terminal mode; leave TTY input live."""

    source = stream if stream is not None else sys.stdin
    try:
        interactive = bool(source.isatty())
    except (AttributeError, OSError):
        interactive = False
    if interactive:
        return "", True
    try:
        value = source.read()
    except (OSError, UnicodeError) as error:
        raise ClientError("Could not read standard input.", code="client-broker") from error
    if not isinstance(value, str):
        raise ClientError("Standard input must be UTF-8 text.", code="client-broker")
    if len(value.encode("utf-8")) > 262_144:
        raise ClientError("Standard input exceeds the browser input limit.", code="client-local-file")
    return value, False
