"""A deliberately small RFC 6455 loopback WebSocket implementation.

Only the browser bridge's required surface is implemented: HTTP Upgrade, text
messages, client masking, close, ping/pong, bounded frames, and no negotiated
extensions. Binary frames, compressed frames, invalid fragmentation sequences,
and subprotocol negotiation are rejected explicitly rather than being
interpreted loosely; fragmented text is accumulated within the message bound.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http
import secrets
import socket
import struct
import threading
from dataclasses import dataclass
from typing import Any, Callable, Final, Mapping
from urllib.parse import urlsplit

from .protocol import BRIDGE_MAX_MESSAGE_BYTES, decode_json, encode_json

MAX_HANDSHAKE_BYTES: Final[int] = 16 * 1024
MAX_WEBSOCKET_MESSAGE_BYTES: Final[int] = BRIDGE_MAX_MESSAGE_BYTES
HANDSHAKE_TIMEOUT_SECONDS: Final[float] = 5.0


class WebSocketError(ConnectionError):
    """Base class for WebSocket transport errors."""


class WebSocketHandshakeError(WebSocketError):
    """The HTTP Upgrade request was not acceptable."""


class WebSocketProtocolError(WebSocketError):
    """A frame violated the supported RFC 6455 subset."""


class WebSocketMessageTooLarge(WebSocketProtocolError):
    """A text message exceeded the configured message limit."""


@dataclass(frozen=True)
class WebSocketFrame:
    fin: bool
    opcode: int
    payload: bytes
    masked: bool


@dataclass(frozen=True)
class HandshakeRequest:
    method: str
    target: str
    headers: Mapping[str, str]


def _header_tokens(value: str) -> set[str]:
    return {part.strip().casefold() for part in value.split(",") if part.strip()}


def _bad_request(sock: socket.socket, status: int, reason: str) -> None:
    body = (reason + "\n").encode("utf-8", errors="replace")
    response = (
        f"HTTP/1.1 {status} {http.HTTPStatus(status).phrase}\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii") + body
    try:
        sock.sendall(response)
    except OSError:
        pass


def _read_handshake(sock: socket.socket, *, max_bytes: int = MAX_HANDSHAKE_BYTES) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        if len(data) >= max_bytes:
            raise WebSocketHandshakeError("WebSocket handshake headers exceed the limit")
        chunk = sock.recv(min(4096, max_bytes - len(data)))
        if not chunk:
            raise WebSocketHandshakeError("peer disconnected during WebSocket handshake")
        data.extend(chunk)
    end = data.index(b"\r\n\r\n") + 4
    if end > max_bytes:
        raise WebSocketHandshakeError("WebSocket handshake headers exceed the limit")
    # A browser Upgrade request cannot carry a body.  Refuse bytes after the
    # header terminator instead of leaving an ambiguous first frame buffered.
    if len(data) != end:
        raise WebSocketHandshakeError("unexpected bytes after WebSocket handshake")
    return bytes(data[:end])


def parse_handshake(data: bytes) -> HandshakeRequest:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise WebSocketHandshakeError("WebSocket handshake is not ASCII") from error
    lines = text.split("\r\n")
    if len(lines) < 2 or not lines[-2:] == ["", ""]:
        raise WebSocketHandshakeError("malformed WebSocket handshake")
    request_line = lines[0].split(" ")
    if len(request_line) != 3 or request_line[2] != "HTTP/1.1":
        raise WebSocketHandshakeError("WebSocket handshake must use HTTP/1.1")
    method, target, _ = request_line
    headers: dict[str, str] = {}
    for line in lines[1:-2]:
        if not line or ":" not in line:
            raise WebSocketHandshakeError("malformed WebSocket header")
        name, value = line.split(":", 1)
        normalized = name.strip().casefold()
        if not normalized or normalized in headers:
            raise WebSocketHandshakeError("duplicate or empty WebSocket header")
        headers[normalized] = value.strip()
    return HandshakeRequest(method, target, headers)


def _validate_handshake(request: HandshakeRequest, *, expected_origin: str) -> str:
    if request.method != "GET":
        raise WebSocketHandshakeError("WebSocket handshake must use GET")
    target = urlsplit(request.target)
    if target.scheme or target.netloc or target.path not in {"", "/", "/bridge"}:
        raise WebSocketHandshakeError("unsupported WebSocket request path")
    if target.query:
        # Bootstrap credentials belong in the bridge fragment and are never
        # sent in this request.  Refuse query credentials if a non-browser
        # client attempts to put them on the wire.
        raise WebSocketHandshakeError("WebSocket query parameters are unsupported")
    headers = request.headers
    if not headers.get("host"):
        raise WebSocketHandshakeError("Host header is required")
    if headers.get("upgrade", "").casefold() != "websocket":
        raise WebSocketHandshakeError("WebSocket Upgrade header is required")
    if "upgrade" not in _header_tokens(headers.get("connection", "")):
        raise WebSocketHandshakeError("Connection: Upgrade is required")
    if headers.get("sec-websocket-version") != "13":
        raise WebSocketHandshakeError("only WebSocket version 13 is supported")
    origin = headers.get("origin")
    if origin != expected_origin:
        raise WebSocketHandshakeError("WebSocket Origin is not allowed")
    # Browser WebSocket implementations commonly offer permessage-deflate
    # and do not expose a switch to suppress that offer.  Accept the offer but
    # deliberately omit Sec-WebSocket-Extensions from the 101 response: no
    # extension is negotiated, and all frames remain uncompressed/plain.
    if headers.get("sec-websocket-protocol", ""):
        raise WebSocketHandshakeError("WebSocket subprotocols are unsupported")
    key = headers.get("sec-websocket-key")
    if key is None:
        raise WebSocketHandshakeError("Sec-WebSocket-Key is required")
    try:
        decoded = base64.b64decode(key, validate=True)
    except (ValueError, binascii.Error) as error:
        raise WebSocketHandshakeError("Sec-WebSocket-Key is invalid") from error
    if len(decoded) != 16:
        raise WebSocketHandshakeError("Sec-WebSocket-Key is invalid")
    return key


def perform_server_handshake(
    sock: socket.socket,
    *,
    expected_origin: str,
    timeout: float = HANDSHAKE_TIMEOUT_SECONDS,
) -> HandshakeRequest:
    """Validate and complete a browser WebSocket Upgrade request."""

    old_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        request = parse_handshake(_read_handshake(sock))
        key = _validate_handshake(request, expected_origin=expected_origin)
        accept = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()
        ).decode("ascii")
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode("ascii")
        sock.sendall(response)
        return request
    except WebSocketHandshakeError:
        raise
    except (OSError, ValueError) as error:
        raise WebSocketHandshakeError("WebSocket handshake failed") from error
    finally:
        sock.settimeout(old_timeout)


def encode_frame(
    payload: bytes | str,
    *,
    opcode: int = 0x1,
    fin: bool = True,
    mask: bool = False,
    mask_key: bytes | None = None,
) -> bytes:
    """Encode one RFC 6455 frame for tests and transport writers."""

    if isinstance(payload, str):
        try:
            data = payload.encode("utf-8")
        except UnicodeEncodeError as error:
            raise WebSocketProtocolError("text payload is not valid UTF-8") from error
    else:
        data = bytes(payload)
    if len(data) > MAX_WEBSOCKET_MESSAGE_BYTES:
        raise WebSocketMessageTooLarge("WebSocket payload exceeds the message limit")
    if opcode in {0x8, 0x9, 0xA} and (not fin or len(data) > 125):
        raise WebSocketProtocolError("WebSocket control frames must be final and <= 125 bytes")
    if not 0 <= opcode <= 0xF:
        raise ValueError("invalid WebSocket opcode")
    first = (0x80 if fin else 0) | opcode
    mask_bit = 0x80 if mask else 0
    length = len(data)
    if length < 126:
        header = bytes((first, mask_bit | length))
    elif length <= 0xFFFF:
        header = bytes((first, mask_bit | 126)) + struct.pack(">H", length)
    else:
        header = bytes((first, mask_bit | 127)) + struct.pack(">Q", length)
    if not mask:
        return header + data
    key = mask_key or secrets.token_bytes(4)
    if len(key) != 4:
        raise ValueError("WebSocket mask key must contain four bytes")
    masked = bytes(data[index] ^ key[index % 4] for index in range(len(data)))
    return header + key + masked


def recv_frame(
    sock: socket.socket,
    *,
    max_bytes: int = MAX_WEBSOCKET_MESSAGE_BYTES,
    require_masked: bool = True,
) -> WebSocketFrame:
    """Read one frame, enforcing masks, RSV/opcode, and control-frame rules.

    Fragment sequencing is enforced by ``WebSocketConnection.recv_text`` so
    control frames can legally interleave with a fragmented text message.
    """

    first_two = _read_exact(sock, 2)
    first, second = first_two
    fin = bool(first & 0x80)
    if first & 0x70:
        raise WebSocketProtocolError("WebSocket RSV bits are unsupported")
    opcode = first & 0x0F
    if opcode not in {0x0, 0x1, 0x2, 0x8, 0x9, 0xA}:
        raise WebSocketProtocolError("WebSocket opcode is unsupported")
    masked = bool(second & 0x80)
    if require_masked and not masked:
        raise WebSocketProtocolError("client WebSocket frames must be masked")
    length_code = second & 0x7F
    if length_code < 126:
        length = length_code
    elif length_code == 126:
        length = struct.unpack(">H", _read_exact(sock, 2))[0]
    else:
        raw_length = struct.unpack(">Q", _read_exact(sock, 8))[0]
        if raw_length & (1 << 63):
            raise WebSocketProtocolError("WebSocket payload length has the high bit set")
        length = raw_length
    if length > max_bytes:
        raise WebSocketMessageTooLarge(f"WebSocket payload exceeds {max_bytes} bytes")
    if opcode in {0x8, 0x9, 0xA} and (not fin or length > 125):
        raise WebSocketProtocolError("WebSocket control frames must be final and <= 125 bytes")
    mask_key = _read_exact(sock, 4) if masked else b""
    data = _read_exact(sock, length)
    if masked:
        payload = bytes(data[index] ^ mask_key[index % 4] for index in range(length))
    else:
        payload = data
    return WebSocketFrame(fin, opcode, payload, masked)


def _read_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = sock.recv(remaining)
        except (ConnectionResetError, BrokenPipeError) as error:
            raise WebSocketError("peer disconnected") from error
        if not chunk:
            raise WebSocketError("peer disconnected")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class WebSocketConnection:
    """Thread-safe text WebSocket connection after the HTTP Upgrade."""

    def __init__(self, sock: socket.socket, *, max_bytes: int = MAX_WEBSOCKET_MESSAGE_BYTES) -> None:
        self.sock = sock
        self.max_bytes = max_bytes
        self._send_lock = threading.Lock()
        self._closed = False

    def send_frame(self, payload: bytes | str, *, opcode: int = 0x1) -> None:
        with self._send_lock:
            if self._closed:
                raise WebSocketError("WebSocket is closed")
            try:
                self.sock.sendall(_bounded_frame(payload, opcode=opcode, max_bytes=self.max_bytes))
            except (BrokenPipeError, ConnectionResetError, OSError) as error:
                self._closed = True
                raise WebSocketError("peer disconnected while sending") from error

    def send_text(self, text: str) -> None:
        self.send_frame(text, opcode=0x1)

    def send_json(self, value: Mapping[str, Any]) -> None:
        data = encode_json(value, max_bytes=self.max_bytes)
        self.send_frame(data, opcode=0x1)

    def send_ping(self, payload: bytes = b"") -> None:
        self.send_frame(payload, opcode=0x9)

    def send_pong(self, payload: bytes = b"") -> None:
        self.send_frame(payload, opcode=0xA)

    def send_close(self, code: int = 1000, reason: str = "") -> None:
        if not 1000 <= code <= 4999 or code in {1004, 1005, 1006, 1015}:
            raise ValueError("invalid WebSocket close code")
        reason_bytes = reason.encode("utf-8")
        if len(reason_bytes) > 123:
            raise ValueError("WebSocket close reason is too long")
        with self._send_lock:
            if self._closed:
                return
            try:
                self.sock.sendall(encode_frame(struct.pack(">H", code) + reason_bytes, opcode=0x8))
            except OSError:
                pass
            self._closed = True

    def recv_frame(self) -> WebSocketFrame:
        if self._closed:
            raise WebSocketError("WebSocket is closed")
        return recv_frame(self.sock, max_bytes=self.max_bytes)

    def recv_text(self, *, timeout: float | None = None) -> str | None:
        old_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        fragments: list[bytes] = []
        fragment_bytes = 0
        fragmented = False
        try:
            while True:
                frame = self.recv_frame()
                if frame.opcode == 0x9:
                    # RFC 6455 permits control frames between fragments.
                    self.send_pong(frame.payload)
                    continue
                if frame.opcode == 0xA:
                    continue
                if frame.opcode == 0x8:
                    _validate_close_payload(frame.payload)
                    self._reply_to_close(frame.payload)
                    return None
                if frame.opcode == 0x2:
                    self.send_close(1003, "Binary messages are unsupported.")
                    raise WebSocketProtocolError("binary WebSocket messages are unsupported")
                if frame.opcode == 0x1:
                    if fragmented:
                        raise WebSocketProtocolError("a new data frame interrupted fragmented text")
                    if frame.fin:
                        data = frame.payload
                    else:
                        fragments = [frame.payload]
                        fragment_bytes = len(frame.payload)
                        fragmented = True
                        if fragment_bytes > self.max_bytes:
                            raise WebSocketMessageTooLarge("WebSocket message exceeds the message limit")
                        continue
                elif frame.opcode == 0x0:
                    if not fragmented:
                        raise WebSocketProtocolError("text continuation has no initial data frame")
                    fragment_bytes += len(frame.payload)
                    if fragment_bytes > self.max_bytes:
                        raise WebSocketMessageTooLarge("WebSocket message exceeds the message limit")
                    fragments.append(frame.payload)
                    if not frame.fin:
                        continue
                    data = b"".join(fragments)
                    fragmented = False
                    fragments = []
                else:
                    raise WebSocketProtocolError("unsupported WebSocket data frame")
                try:
                    return data.decode("utf-8", errors="strict")
                except UnicodeDecodeError as error:
                    self.send_close(1007, "Invalid UTF-8 text.")
                    raise WebSocketProtocolError("WebSocket text is not valid UTF-8") from error
        except socket.timeout:
            raise
        except WebSocketMessageTooLarge:
            if not self._closed:
                try:
                    self.send_close(1009, "WebSocket message is too large.")
                except Exception:
                    pass
            raise
        except WebSocketProtocolError:
            if not self._closed:
                try:
                    self.send_close(1002, "Unsupported WebSocket frame.")
                except Exception:
                    pass
            raise
        except WebSocketError:
            self._closed = True
            raise
        finally:
            if timeout is not None:
                self.sock.settimeout(old_timeout)

    def recv_json(self, *, timeout: float | None = None) -> Any | None:
        text = self.recv_text(timeout=timeout)
        if text is None:
            return None
        try:
            return decode_json(text.encode("utf-8"), max_bytes=self.max_bytes)
        except ValueError:
            self.send_close(1007, "Invalid JSON.")
            raise WebSocketProtocolError("WebSocket text is not valid JSON")

    def close(self) -> None:
        self.send_close()
        try:
            self.sock.close()
        except OSError:
            pass

    def _reply_to_close(self, payload: bytes) -> None:
        if len(payload) == 1:
            self.send_close(1002, "Malformed close frame.")
            raise WebSocketProtocolError("close frame contains one byte")
        if not self._closed:
            with self._send_lock:
                try:
                    self.sock.sendall(encode_frame(payload, opcode=0x8))
                except OSError:
                    pass
            self._closed = True


def _validate_close_payload(payload: bytes) -> None:
    if not payload:
        return
    if len(payload) == 1:
        raise WebSocketProtocolError("close frame contains one byte")
    code = struct.unpack(">H", payload[:2])[0]
    if not 1000 <= code <= 4999 or code in {1004, 1005, 1006, 1015}:
        raise WebSocketProtocolError("close frame contains an invalid code")
    try:
        payload[2:].decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise WebSocketProtocolError("close reason is not valid UTF-8") from error


# ``encode_frame`` intentionally has no max_bytes argument; this alias keeps
# the send path's limit check explicit without duplicating framing logic.
def _bounded_frame(
    payload: bytes | str,
    *,
    opcode: int,
    max_bytes: int,
    mask: bool = False,
    mask_key: bytes | None = None,
) -> bytes:
    if isinstance(payload, str):
        size = len(payload.encode("utf-8"))
    else:
        size = len(payload)
    if size > max_bytes:
        raise WebSocketMessageTooLarge("WebSocket payload exceeds the message limit")
    return encode_frame(payload, opcode=opcode, mask=mask, mask_key=mask_key)


class WebSocketClientConnection:
    """Minimal browser-like client used by protocol tests and diagnostics."""

    def __init__(self, sock: socket.socket, *, max_bytes: int = MAX_WEBSOCKET_MESSAGE_BYTES) -> None:
        self.sock = sock
        self.max_bytes = max_bytes
        self._send_lock = threading.Lock()
        self._closed = False

    def send_frame(self, payload: bytes | str, *, opcode: int = 0x1) -> None:
        with self._send_lock:
            if self._closed:
                raise WebSocketError("WebSocket is closed")
            try:
                self.sock.sendall(
                    _bounded_frame(
                        payload,
                        opcode=opcode,
                        max_bytes=self.max_bytes,
                        mask=True,
                        mask_key=secrets.token_bytes(4),
                    )
                )
            except OSError as error:
                self._closed = True
                raise WebSocketError("peer disconnected while sending") from error

    def send_text(self, text: str) -> None:
        self.send_frame(text, opcode=0x1)

    def send_json(self, value: Mapping[str, Any]) -> None:
        self.send_frame(encode_json(value, max_bytes=self.max_bytes), opcode=0x1)

    def send_close(self, code: int = 1000, reason: str = "") -> None:
        if not 1000 <= code <= 4999 or code in {1004, 1005, 1006, 1015}:
            raise ValueError("invalid WebSocket close code")
        reason_bytes = reason.encode("utf-8")
        if len(reason_bytes) > 123:
            raise ValueError("WebSocket close reason is too long")
        with self._send_lock:
            if self._closed:
                return
            try:
                self.sock.sendall(
                    encode_frame(
                        struct.pack(">H", code) + reason_bytes,
                        opcode=0x8,
                        mask=True,
                        mask_key=secrets.token_bytes(4),
                    )
                )
            except OSError:
                pass
            self._closed = True

    def recv_frame(self) -> WebSocketFrame:
        return recv_frame(self.sock, max_bytes=self.max_bytes, require_masked=False)

    def recv_text(self, *, timeout: float | None = None) -> str | None:
        old_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        fragments: list[bytes] = []
        fragment_bytes = 0
        fragmented = False
        try:
            while True:
                frame = self.recv_frame()
                if frame.opcode == 0x9:
                    self.send_frame(frame.payload, opcode=0xA)
                    continue
                if frame.opcode == 0xA:
                    continue
                if frame.opcode == 0x8:
                    _validate_close_payload(frame.payload)
                    self._closed = True
                    return None
                if frame.opcode == 0x2:
                    self.send_close(1003, "Binary messages are unsupported.")
                    raise WebSocketProtocolError("binary WebSocket messages are unsupported")
                if frame.opcode == 0x1:
                    if fragmented:
                        raise WebSocketProtocolError("a new data frame interrupted fragmented text")
                    if frame.fin:
                        data = frame.payload
                    else:
                        fragments = [frame.payload]
                        fragment_bytes = len(frame.payload)
                        fragmented = True
                        if fragment_bytes > self.max_bytes:
                            raise WebSocketMessageTooLarge("WebSocket message exceeds the message limit")
                        continue
                elif frame.opcode == 0x0:
                    if not fragmented:
                        raise WebSocketProtocolError("text continuation has no initial data frame")
                    fragment_bytes += len(frame.payload)
                    if fragment_bytes > self.max_bytes:
                        raise WebSocketMessageTooLarge("WebSocket message exceeds the message limit")
                    fragments.append(frame.payload)
                    if not frame.fin:
                        continue
                    data = b"".join(fragments)
                    fragmented = False
                    fragments = []
                else:
                    raise WebSocketProtocolError("unsupported WebSocket data frame")
                try:
                    return data.decode("utf-8", errors="strict")
                except UnicodeDecodeError as error:
                    self.send_close(1007, "Invalid UTF-8 text.")
                    raise WebSocketProtocolError("WebSocket text is not valid UTF-8") from error
        except socket.timeout:
            raise
        except WebSocketMessageTooLarge:
            if not self._closed:
                try:
                    self.send_close(1009, "WebSocket message is too large.")
                except Exception:
                    pass
            raise
        except WebSocketProtocolError:
            if not self._closed:
                try:
                    self.send_close(1002, "Unsupported WebSocket frame.")
                except Exception:
                    pass
            raise
        finally:
            if timeout is not None:
                self.sock.settimeout(old_timeout)

    def recv_json(self, *, timeout: float | None = None) -> Any | None:
        text = self.recv_text(timeout=timeout)
        if text is None:
            return None
        try:
            return decode_json(text.encode("utf-8"), max_bytes=self.max_bytes)
        except ValueError as error:
            self.send_close(1007, "Invalid JSON.")
            raise WebSocketProtocolError("WebSocket text is not valid JSON") from error

    def close(self) -> None:
        self.send_close()
        try:
            self.sock.close()
        except OSError:
            pass


def connect_websocket(
    url: str,
    *,
    origin: str,
    timeout: float = HANDSHAKE_TIMEOUT_SECONDS,
    max_bytes: int = MAX_WEBSOCKET_MESSAGE_BYTES,
    extensions: str | None = None,
) -> WebSocketClientConnection:
    """Connect to a loopback ``ws://`` endpoint without third-party packages."""

    parsed = urlsplit(url)
    if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise WebSocketHandshakeError("browser bridge client only permits loopback ws://")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/", "/bridge"}:
        raise WebSocketHandshakeError("unsupported WebSocket client URL")
    if parsed.port is None:
        raise WebSocketHandshakeError("WebSocket client URL has no port")
    host_header = parsed.netloc
    sock = socket.create_connection(("127.0.0.1", parsed.port), timeout=timeout)
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    request_path = parsed.path or "/"
    request = (
        f"GET {request_path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        + (f"Sec-WebSocket-Extensions: {extensions}\r\n" if extensions else "")
        + f"Origin: {origin}\r\n\r\n"
    ).encode("ascii")
    try:
        sock.sendall(request)
        response = _read_handshake(sock)
        lines = response.decode("ascii").split("\r\n")
        status = lines[0].split(" ", 2)
        if len(status) != 3 or status[1] != "101":
            raise WebSocketHandshakeError("WebSocket server rejected the Upgrade")
        headers: dict[str, str] = {}
        for line in lines[1:-2]:
            if ":" not in line:
                raise WebSocketHandshakeError("malformed WebSocket Upgrade response")
            name, value = line.split(":", 1)
            headers[name.casefold()] = value.strip()
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        if headers.get("sec-websocket-accept") != expected:
            raise WebSocketHandshakeError("WebSocket accept key is invalid")
        if headers.get("sec-websocket-extensions"):
            raise WebSocketHandshakeError("unsupported WebSocket extension was negotiated")
        return WebSocketClientConnection(sock, max_bytes=max_bytes)
    except BaseException:
        sock.close()
        raise


class LoopbackWebSocketServer:
    """A small threaded listener bound only to an IPv4 loopback address."""

    def __init__(
        self,
        on_connection: Callable[[WebSocketConnection], None],
        *,
        expected_origin: str,
        host: str = "127.0.0.1",
        port: int = 0,
        max_bytes: int = MAX_WEBSOCKET_MESSAGE_BYTES,
        handshake_timeout: float = HANDSHAKE_TIMEOUT_SECONDS,
    ) -> None:
        if host not in {"127.0.0.1", "localhost"}:
            raise ValueError("the browser bridge must bind to loopback")
        self.on_connection = on_connection
        self.expected_origin = expected_origin
        self.host = "127.0.0.1" if host == "localhost" else host
        self.max_bytes = max_bytes
        self.handshake_timeout = handshake_timeout
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, port))
        self._listener.listen(16)
        self._listener.settimeout(0.25)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._connections: set[socket.socket] = set()
        self._connections_lock = threading.Lock()

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._listener.getsockname()[:2]
        return str(host), int(port)

    @property
    def port(self) -> int:
        return self.address[1]

    def start(self) -> "LoopbackWebSocketServer":
        if self._thread is not None:
            return self
        self._thread = threading.Thread(target=self._accept_loop, name="klang-web-ws", daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        with self._connections_lock:
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=1)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._connections_lock:
                self._connections.add(client)
            thread = threading.Thread(
                target=self._handle_connection,
                args=(client,),
                name="klang-web-ws-client",
                daemon=True,
            )
            thread.start()

    def _handle_connection(self, sock: socket.socket) -> None:
        connection: WebSocketConnection | None = None
        try:
            perform_server_handshake(
                sock,
                expected_origin=self.expected_origin,
                timeout=self.handshake_timeout,
            )
            connection = WebSocketConnection(sock, max_bytes=self.max_bytes)
            self.on_connection(connection)
        except WebSocketHandshakeError as error:
            _bad_request(sock, 403 if "Origin" in str(error) else 400, str(error))
        except (WebSocketError, OSError):
            pass
        except Exception:
            # A bridge callback is an application boundary; never let an
            # unexpected callback exception terminate the accept loop.
            pass
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
            else:
                try:
                    sock.close()
                except OSError:
                    pass
            with self._connections_lock:
                self._connections.discard(sock)

    def __enter__(self) -> "LoopbackWebSocketServer":
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def recv_server_frame(
    sock: socket.socket,
    *,
    max_bytes: int = MAX_WEBSOCKET_MESSAGE_BYTES,
) -> WebSocketFrame:
    """Read a server-to-client frame (server frames are normally unmasked)."""

    return recv_frame(sock, max_bytes=max_bytes, require_masked=False)


# Friendly aliases for callers/tests that use the protocol vocabulary.
WebSocketServer = LoopbackWebSocketServer
