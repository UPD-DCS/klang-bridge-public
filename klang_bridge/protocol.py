"""Versioned bounded JSON envelopes for native control and browser bridge IPC."""

from __future__ import annotations

import json
import math
import socket
import struct
import threading
import re
from dataclasses import dataclass
from typing import Any, Callable, Final, Mapping

PROTOCOL_VERSION: Final[int] = 1
BRIDGE_PROTOCOL_VERSION: Final[int] = PROTOCOL_VERSION
BRIDGE_CLIENT_NAME: Final[str] = "klang-web-browser"
BRIDGE_AUTH_REQUEST_ID: Final[str] = "bridge-authenticate"
BRIDGE_HANDSHAKE_REQUEST_ID: Final[str] = "bridge-handshake"
BRIDGE_READY_REQUEST_ID: Final[str] = "bridge-ready"
# A source snapshot is capped at 2 MiB; framing leaves room for its JSON
# envelope, settings, and provenance metadata.
MAX_FRAME_BYTES: Final[int] = 4 * 1024 * 1024
BRIDGE_MAX_MESSAGE_BYTES: Final[int] = 1_048_576
MAX_REQUEST_ID_BYTES: Final[int] = 96
MAX_TYPE_BYTES: Final[int] = 64
MAX_TOKEN_BYTES: Final[int] = 512
MAX_INPUT_BYTES: Final[int] = 262_144
MAX_JSON_DEPTH: Final[int] = 32
REQUEST_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]{1,96}$")
TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]+$")
KLANG_VERSION_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)

# These names are deliberately explicit rather than allowing arbitrary RPC
# methods to cross either local boundary.
CONTROL_MESSAGE_TYPES: Final[frozenset[str]] = frozenset(
    {
        "control-auth",
        "control-status",
        "control-connect",
        "control-disconnect",
        "control-operation",
        "control-stdin",
        "control-stop",
        "control-dispose",
        "control-shutdown",
        "control-ping",
        "control-authenticated",
        "control-result",
        "control-accepted",
        "control-error",
        "control-output",
        "control-input-request",
        "control-pong",
    }
)
BRIDGE_MESSAGE_TYPES: Final[frozenset[str]] = frozenset(
    {
        "handshake",
        "handshake-ack",
        "authenticate",
        "authenticated",
        "ready",
        "ready-ack",
        "compile",
        "emit-ir",
        "run",
        "stdin",
        "stop",
        "status",
        "dispose",
        "result",
        "error",
        "output",
        "compiler-output",
        "stdin-request",
        "diagnostic",
        "mutation",
        "resource-limit",
    }
)
MESSAGE_TYPES: Final[frozenset[str]] = CONTROL_MESSAGE_TYPES | BRIDGE_MESSAGE_TYPES

CONTROL_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"status", "connect", "disconnect", "compile", "emit-ir", "run", "stdin", "stop", "dispose", "shutdown"}
)
BRIDGE_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"compile", "emit-ir", "run", "stdin", "stop", "dispose", "status"}
)
CLIENT_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "client-usage",
        "client-protocol",
        "client-local-file",
        "client-disconnected",
        "client-not-ready",
        "client-timeout",
        "client-authentication",
        "client-broker",
        "client-cancelled",
    }
)
BRIDGE_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "invalid-envelope",
        "invalid-request",
        "message-too-large",
        "protocol-mismatch",
        "unknown-message",
        "authentication-failed",
        "authentication-expired",
        "not-authenticated",
        "bridge-not-ready",
        "busy",
        "disconnected",
        "worker-failed",
        "execution-failed",
        "invalid-snapshot",
        "invalid-input",
        "disposed",
        "loopback-permission",
    }
)


class ProtocolError(ValueError):
    """A malformed, oversized, unsupported, or schema-invalid message."""

    def __init__(self, message: str, *, code: str = "client-protocol") -> None:
        self.code = code
        super().__init__(message)


class FrameTooLarge(ProtocolError):
    """A length-prefixed JSON frame exceeded the configured boundary."""


class PeerDisconnected(ConnectionError):
    """The peer closed the socket before a complete frame arrived."""


@dataclass(frozen=True)
class Envelope:
    protocol_version: int
    request_id: str
    type: str
    payload: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "protocolVersion": self.protocol_version,
            "requestId": self.request_id,
            "type": self.type,
            "payload": self.payload,
        }

    @classmethod
    def from_value(cls, value: Any, *, channel: str | None = None) -> "Envelope":
        if not isinstance(value, dict):
            raise ProtocolError("message envelope must be an object")
        expected = {"protocolVersion", "requestId", "type", "payload"}
        unknown = set(value) - expected
        missing = expected - set(value)
        if unknown:
            raise ProtocolError(f"message envelope has unknown fields: {sorted(unknown)!r}")
        if missing:
            raise ProtocolError(f"message envelope is missing fields: {sorted(missing)!r}")
        version = value["protocolVersion"]
        if type(version) is not int or version != PROTOCOL_VERSION:
            raise ProtocolError(
                "unsupported protocol version",
                code="protocol-mismatch" if channel == "bridge" else "client-protocol",
            )
        request_id = value["requestId"]
        if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id):
            raise ProtocolError("requestId must contain 1-96 safe characters")
        try:
            request_id_bytes = len(request_id.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as error:
            raise ProtocolError("requestId is not valid UTF-8 text") from error
        if request_id_bytes > MAX_REQUEST_ID_BYTES:
            raise ProtocolError("requestId exceeds the protocol limit")
        message_type = value["type"]
        if not isinstance(message_type, str) or not message_type:
            raise ProtocolError("message type must be non-empty text")
        try:
            type_bytes = len(message_type.encode("utf-8", errors="strict"))
        except UnicodeEncodeError as error:
            raise ProtocolError("message type is not valid UTF-8 text") from error
        if type_bytes > MAX_TYPE_BYTES:
            raise ProtocolError("message type exceeds the protocol limit")
        if message_type not in MESSAGE_TYPES:
            raise ProtocolError(
                f"unknown message type: {message_type}",
                code="unknown-message" if channel == "bridge" else "client-protocol",
            )
        if channel == "control" and message_type not in CONTROL_MESSAGE_TYPES:
            raise ProtocolError("browser message sent on the control channel")
        if channel == "bridge" and message_type not in BRIDGE_MESSAGE_TYPES:
            raise ProtocolError("control message sent on the browser channel")
        payload = value["payload"]
        if not isinstance(payload, dict):
            raise ProtocolError("message payload must be an object")
        _validate_depth(payload)
        _validate_message_payload(message_type, payload)
        return cls(version, request_id, message_type, payload)


class _DuplicateKey(ValueError):
    pass


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _validate_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ProtocolError("JSON payload exceeds nesting limit")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError("JSON object keys must be text")
            _validate_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_depth(item, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ProtocolError("JSON numbers must be finite")


def encode_json(value: Mapping[str, Any], *, max_bytes: int = MAX_FRAME_BYTES) -> bytes:
    """Encode strict UTF-8 JSON with deterministic compact separators."""

    try:
        _validate_depth(value)
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        if isinstance(error, ProtocolError):
            raise
        raise ProtocolError(f"message is not valid JSON: {error}") from error
    if len(encoded) > max_bytes:
        raise FrameTooLarge(f"JSON frame exceeds {max_bytes} bytes")
    return encoded


def decode_json(data: bytes, *, max_bytes: int = MAX_FRAME_BYTES) -> Any:
    if len(data) > max_bytes:
        raise FrameTooLarge(f"JSON frame exceeds {max_bytes} bytes")
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError) as error:
        raise ProtocolError(f"message is not valid UTF-8 JSON: {error}") from error
    _validate_depth(value)
    return value


def encode_envelope(
    message_type: str,
    request_id: str,
    payload: Mapping[str, Any] | None = None,
    *,
    max_bytes: int = MAX_FRAME_BYTES,
) -> bytes:
    envelope = make_envelope(message_type, request_id, payload)
    return encode_json(envelope, max_bytes=max_bytes)


def make_envelope(
    message_type: str,
    request_id: str,
    payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if payload is None:
        payload = {}
    envelope = {
        "protocolVersion": PROTOCOL_VERSION,
        "requestId": request_id,
        "type": message_type,
        "payload": dict(payload),
    }
    # Validate before a caller puts the message on the wire.
    Envelope.from_value(envelope)
    return envelope


def decode_envelope(data: bytes, *, channel: str | None = None) -> Envelope:
    return Envelope.from_value(decode_json(data), channel=channel)


def validate_envelope(value: Any, *, channel: str | None = None) -> Envelope:
    """Validate an already-decoded envelope at either authenticated channel."""

    return Envelope.from_value(value, channel=channel)


parse_envelope = decode_envelope


def _strict_payload(payload: Mapping[str, Any], allowed: set[str], message_type: str) -> None:
    unknown = set(payload) - allowed
    if unknown:
        raise ProtocolError(f"{message_type} payload has unknown fields: {sorted(unknown)!r}")


def _text(payload: Mapping[str, Any], key: str, message_type: str, *, required: bool = True) -> str | None:
    if key not in payload:
        if required:
            raise ProtocolError(f"{message_type} payload is missing {key!r}")
        return None
    value = payload[key]
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{message_type} payload field {key!r} must be non-empty text")
    return value


def _operation_payload(payload: Mapping[str, Any], message_type: str) -> None:
    _strict_payload(
        payload,
        {"operation", "arguments", "snapshot", "stdin", "limits", "metadata", "dialect", "mode"},
        message_type,
    )
    operation = payload.get("operation")
    if not isinstance(operation, str) or operation not in BRIDGE_OPERATIONS:
        raise ProtocolError(f"{message_type} has an unsupported operation")
    for key in ("arguments", "snapshot", "stdin", "limits", "metadata"):
        if key in payload and not isinstance(payload[key], (dict, list, str, int, bool, type(None))):
            raise ProtocolError(f"{message_type} payload field {key!r} has an invalid shape")
    if "dialect" in payload and (not isinstance(payload["dialect"], str) or not payload["dialect"]):
        raise ProtocolError(f"{message_type} dialect must be non-empty text")
    if "mode" in payload and payload["mode"] not in {None, "default", "typed", "spans"}:
        raise ProtocolError(f"{message_type} IR mode is invalid")


_CONTROL_RESULT_FIELDS: Final[set[str]] = {
    "requestId",
    "operation",
    "status",
    "state",
    "ready",
    "attached",
    "pid",
    "control",
    "websocket",
    "origin",
    "protocolVersion",
    "generation",
    "workerGeneration",
    "workerVersion",
    "pyodideVersion",
    "artifact",
    "bridgeUrl",
    "expiresAt",
    "bootstrapExpiresAt",
    "totalBytes",
    "compilerCommit",
    "artifactHash",
    "mode",
    "dialect",
    "exitCode",
    "stdout",
    "stderr",
    "generated",
    "generatedPython",
    "compileOutput",
    "compilerOutput",
    "diagnostics",
    "runtimeFailure",
    "mutations",
    "resourceLimit",
    "stdin",
    "files",
    "output",
    "accepted",
    "inputRequestId",
    "disposed",
    "message",
}


def _validate_result_payload(payload: Mapping[str, Any], message_type: str) -> None:
    _strict_payload(payload, _CONTROL_RESULT_FIELDS, message_type)
    for key in (
        "stdout",
        "stderr",
        "generated",
        "generatedPython",
        "compileOutput",
        "output",
        "message",
    ):
        if key in payload and not isinstance(payload[key], str):
            raise ProtocolError(f"{message_type} field {key!r} must be text")
    for key in ("diagnostics", "mutations", "files"):
        if key in payload and not isinstance(payload[key], (list, dict)):
            raise ProtocolError(f"{message_type} field {key!r} has an invalid shape")
    if "exitCode" in payload and payload["exitCode"] is not None and (
        not isinstance(payload["exitCode"], int) or isinstance(payload["exitCode"], bool)
    ):
        raise ProtocolError(f"{message_type} exitCode is invalid")
    if "status" in payload and not isinstance(payload["status"], (str, dict)):
        raise ProtocolError(f"{message_type} status has an invalid shape")
    if "dialect" in payload and not isinstance(payload["dialect"], str):
        raise ProtocolError(f"{message_type} dialect must be text")


def _validate_bridge_status_payload(payload: Mapping[str, Any], message_type: str) -> None:
    _strict_payload(
        payload,
        {"state", "ready", "workerGeneration", "workerVersion", "pyodideVersion", "artifact", "message"},
        message_type,
    )
    state = payload.get("state")
    if state not in {"loading", "ready", "busy", "resetting", "failed", "disconnected"}:
        raise ProtocolError(f"{message_type} state is invalid")
    ready = payload.get("ready")
    generation = payload.get("workerGeneration")
    if not isinstance(ready, bool):
        raise ProtocolError(f"{message_type} ready must be boolean")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
        raise ProtocolError(f"{message_type} workerGeneration is invalid")
    for key in ("workerVersion", "pyodideVersion", "message"):
        if key in payload and payload[key] is not None and not isinstance(payload[key], str):
            raise ProtocolError(f"{message_type} field {key!r} must be text")
    if "artifact" in payload and payload["artifact"] is not None:
        if not isinstance(payload["artifact"], dict):
            raise ProtocolError(f"{message_type} artifact is invalid")
        _validate_artifact(payload["artifact"], message_type)
    if state == "ready":
        if not ready or not isinstance(payload.get("workerVersion"), str) or not payload["workerVersion"]:
            raise ProtocolError(f"{message_type} ready status is missing worker metadata")
        if not isinstance(payload.get("pyodideVersion"), str) or not payload["pyodideVersion"]:
            raise ProtocolError(f"{message_type} ready status is missing Pyodide metadata")
        if not isinstance(payload.get("artifact"), dict):
            raise ProtocolError(f"{message_type} ready status is missing artifact metadata")


def _validate_bridge_result_payload(payload: Mapping[str, Any], message_type: str) -> None:
    _strict_payload(payload, {"operation", "result", "accepted", "status", "disposed"}, message_type)
    operation = payload.get("operation")
    if operation not in BRIDGE_OPERATIONS:
        raise ProtocolError(f"{message_type} operation is invalid")
    if "accepted" in payload and payload["accepted"] is not True:
        raise ProtocolError(f"{message_type} accepted must be true")
    if "disposed" in payload and payload["disposed"] is not True:
        raise ProtocolError(f"{message_type} disposed must be true")
    if "status" in payload:
        if not isinstance(payload["status"], dict):
            raise ProtocolError(f"{message_type} status is invalid")
        _validate_bridge_status_payload(payload["status"], message_type)
    if "result" in payload and not isinstance(payload["result"], dict):
        raise ProtocolError(f"{message_type} result must be an object")


def _validate_compiler_output_payload(payload: Mapping[str, Any], message_type: str) -> None:
    _strict_payload(payload, {"output"}, message_type)
    output = payload.get("output")
    if not isinstance(output, dict):
        raise ProtocolError(f"{message_type} output must be an object")
    kind = output.get("kind")
    if kind == "python":
        _strict_payload(output, {"kind", "text"}, f"{message_type} output")
        if not isinstance(output.get("text"), str):
            raise ProtocolError(f"{message_type} Python output must be text")
    elif kind == "ir":
        _strict_payload(output, {"kind", "mode", "text"}, f"{message_type} output")
        if output.get("mode") not in {"default", "typed", "spans"} or not isinstance(output.get("text"), str):
            raise ProtocolError(f"{message_type} IR output is invalid")
    else:
        raise ProtocolError(f"{message_type} output kind is invalid")


def _request_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not REQUEST_ID_PATTERN.fullmatch(value):
        raise ProtocolError(f"{label} must contain 1-96 safe characters")
    return value


def _validate_snapshot(value: Any, message_type: str) -> None:
    if not isinstance(value, dict):
        raise ProtocolError(f"{message_type} snapshot must be an object")
    _strict_payload(value, {"rootPath", "files", "settings", "limits"}, f"{message_type} snapshot")
    root_path = value.get("rootPath")
    files = value.get("files")
    settings = value.get("settings")
    limits = value.get("limits")
    if not isinstance(root_path, str) or not root_path:
        raise ProtocolError(f"{message_type} snapshot rootPath is invalid")
    if not isinstance(files, list) or not isinstance(settings, dict) or not isinstance(limits, dict):
        raise ProtocolError(f"{message_type} snapshot fields are invalid")
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "text"}:
            raise ProtocolError(f"{message_type} snapshot file is invalid")
        if not isinstance(item["path"], str) or not isinstance(item["text"], str):
            raise ProtocolError(f"{message_type} snapshot file fields are invalid")


def _validate_output_payload(payload: Mapping[str, Any], message_type: str) -> None:
    _strict_payload(payload, {"stream", "chunk", "sequence"}, message_type)
    if payload.get("stream") not in {"stdout", "stderr"}:
        raise ProtocolError(f"{message_type} stream is invalid")
    if not isinstance(payload.get("chunk"), str):
        raise ProtocolError(f"{message_type} chunk must be text")
    sequence = payload.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise ProtocolError(f"{message_type} sequence is invalid")


def _validate_message_payload(message_type: str, payload: Mapping[str, Any]) -> None:
    if message_type == "control-auth":
        _strict_payload(payload, {"secret"}, message_type)
        _text(payload, "secret", message_type)
    elif message_type in {"control-status", "control-connect", "control-disconnect", "control-dispose", "control-shutdown", "control-ping"}:
        _strict_payload(payload, {"origin", "timeout", "wait", "openBrowser"}, message_type)
    elif message_type == "control-operation":
        _operation_payload(payload, message_type)
    elif message_type == "control-stdin":
        _strict_payload(payload, {"inputRequestId", "line", "eof"}, message_type)
        _text(payload, "inputRequestId", message_type)
        if "line" not in payload and payload.get("eof") is not True:
            raise ProtocolError("control-stdin requires line or eof")
        if "line" in payload and not isinstance(payload["line"], str):
            raise ProtocolError("control-stdin line must be text")
        if isinstance(payload.get("line"), str) and len(payload["line"].encode("utf-8")) > MAX_INPUT_BYTES:
            raise ProtocolError("control-stdin line exceeds the input limit")
        if "eof" in payload and not isinstance(payload["eof"], bool):
            raise ProtocolError("control-stdin eof must be boolean")
    elif message_type == "control-stop":
        _strict_payload(payload, {"requestId"}, message_type)
        _text(payload, "requestId", message_type, required=False)
    elif message_type == "control-authenticated":
        _strict_payload(payload, {"protocolVersion"}, message_type)
        if payload.get("protocolVersion") != PROTOCOL_VERSION:
            raise ProtocolError("control authentication protocol mismatch")
    elif message_type in {"control-result", "control-accepted"}:
        _validate_result_payload(payload, message_type)
    elif message_type == "control-error":
        _strict_payload(payload, {"code", "message", "diagnostics"}, message_type)
        _text(payload, "code", message_type)
        _text(payload, "message", message_type)
        if "diagnostics" in payload and not isinstance(payload["diagnostics"], list):
            raise ProtocolError("control-error diagnostics must be a list")
    elif message_type == "control-output":
        _strict_payload(
            payload,
            {
                "event",
                "generated",
                "output",
                "stream",
                "chunk",
                "sequence",
                "inputRequestId",
                "prompt",
                "eof",
                "diagnostic",
                "mutation",
                "report",
            },
            message_type,
        )
        _text(payload, "event", message_type)
    elif message_type == "control-input-request":
        _strict_payload(payload, {"event", "inputRequestId", "prompt"}, message_type)
        _text(payload, "inputRequestId", message_type)
    elif message_type == "control-pong":
        _strict_payload(payload, {"status"}, message_type)
    elif message_type == "handshake":
        _strict_payload(payload, {"client", "supportedVersions"}, message_type)
        if payload.get("client") != BRIDGE_CLIENT_NAME:
            raise ProtocolError("unsupported bridge client")
        versions = payload.get("supportedVersions")
        if versions != [PROTOCOL_VERSION]:
            raise ProtocolError("bridge protocol versions do not match")
    elif message_type == "handshake-ack":
        _strict_payload(payload, {"acceptedVersion", "server"}, message_type)
        if payload.get("acceptedVersion") != PROTOCOL_VERSION or payload.get("server") != "klang-web-broker":
            raise ProtocolError("invalid bridge handshake acknowledgement")
    elif message_type == "authenticate":
        _strict_payload(payload, {"token"}, message_type)
        token = _text(payload, "token", message_type)
        if token is not None and (len(token.encode("utf-8")) > MAX_TOKEN_BYTES or not TOKEN_PATTERN.fullmatch(token)):
            raise ProtocolError("bridge authentication token is invalid")
    elif message_type == "authenticated":
        _strict_payload(payload, {"authenticated"}, message_type)
        if payload.get("authenticated") is not True:
            raise ProtocolError("bridge authentication acknowledgement is invalid")
    elif message_type == "ready":
        _strict_payload(payload, {"artifact", "pyodideVersion", "workerVersion", "workerGeneration", "contract"}, message_type)
        artifact = payload.get("artifact")
        if not isinstance(artifact, dict):
            raise ProtocolError("bridge-ready artifact must be an object")
        _validate_artifact(artifact, message_type)
        _text(payload, "pyodideVersion", message_type)
        _text(payload, "workerVersion", message_type)
        generation = payload.get("workerGeneration")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
            raise ProtocolError("bridge-ready workerGeneration is invalid")
        if "contract" in payload and not isinstance(payload["contract"], dict):
            raise ProtocolError("bridge-ready contract must be an object")
    elif message_type in {"ready-ack", "status"}:
        if not payload:
            if message_type == "ready-ack":
                raise ProtocolError("ready-ack status is missing")
        else:
            _validate_bridge_status_payload(payload, message_type)
    elif message_type in {"compile", "run"}:
        _strict_payload(payload, {"snapshot"}, message_type)
        _validate_snapshot(payload.get("snapshot"), message_type)
    elif message_type == "emit-ir":
        _strict_payload(payload, {"snapshot", "mode"}, message_type)
        _validate_snapshot(payload.get("snapshot"), message_type)
        if payload.get("mode") not in {"default", "typed", "spans"}:
            raise ProtocolError("emit-ir mode is invalid")
    elif message_type == "stdin":
        _strict_payload(payload, {"line", "inputRequestId"}, message_type)
        if not isinstance(payload.get("line"), str):
            raise ProtocolError("stdin line must be text")
        if len(payload["line"].encode("utf-8")) > MAX_INPUT_BYTES:
            raise ProtocolError("stdin line exceeds the input limit")
        if "inputRequestId" in payload and payload["inputRequestId"] is not None:
            _request_id(payload["inputRequestId"], "stdin inputRequestId")
    elif message_type in {"stop", "dispose"}:
        _strict_payload(payload, set(), message_type)
    elif message_type == "result":
        _validate_bridge_result_payload(payload, message_type)
    elif message_type == "error":
        _strict_payload(payload, {"code", "message", "retryable"}, message_type)
        code = payload.get("code")
        if code not in BRIDGE_ERROR_CODES:
            raise ProtocolError("bridge error code is invalid")
        _text(payload, "message", message_type)
        if "retryable" in payload and not isinstance(payload["retryable"], bool):
            raise ProtocolError("bridge error retryable must be boolean")
    elif message_type == "output":
        _validate_output_payload(payload, message_type)
    elif message_type == "compiler-output":
        _validate_compiler_output_payload(payload, message_type)
    elif message_type == "stdin-request":
        _strict_payload(payload, {"inputRequestId", "prompt"}, message_type)
        _request_id(payload.get("inputRequestId"), "stdin-request inputRequestId")
        if "prompt" in payload and not isinstance(payload["prompt"], str):
            raise ProtocolError("stdin-request prompt must be text")
    elif message_type == "diagnostic":
        _strict_payload(payload, {"diagnostic"}, message_type)
        if not isinstance(payload.get("diagnostic"), dict):
            raise ProtocolError("diagnostic payload must be an object")
    elif message_type == "mutation":
        _strict_payload(payload, {"mutation"}, message_type)
        if not isinstance(payload.get("mutation"), dict):
            raise ProtocolError("mutation payload must be an object")
    elif message_type == "resource-limit":
        _strict_payload(payload, {"report"}, message_type)
        if not isinstance(payload.get("report"), dict):
            raise ProtocolError("resource-limit payload must be an object")


def _validate_artifact(artifact: Mapping[str, Any], message_type: str) -> None:
    allowed = {
        "klangVersion",
        "klangCommit",
        "sha256",
        "sizeBytes",
        "supportedDialects",
        "cliContract",
        "compilerContract",
        "contract",
    }
    _strict_payload(artifact, allowed, f"{message_type} artifact")
    _text(artifact, "klangVersion", f"{message_type} artifact")
    if not KLANG_VERSION_PATTERN.fullmatch(artifact["klangVersion"]):
        raise ProtocolError(f"{message_type} artifact semantic version is invalid")
    _text(artifact, "klangCommit", f"{message_type} artifact")
    digest = artifact.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ProtocolError(f"{message_type} artifact hash is invalid")
    size = artifact.get("sizeBytes")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ProtocolError(f"{message_type} artifact size is invalid")
    dialects = artifact.get("supportedDialects")
    if not isinstance(dialects, list) or not all(isinstance(item, str) for item in dialects):
        raise ProtocolError(f"{message_type} artifact dialect catalog is invalid")
    for key in ("cliContract", "compilerContract", "contract"):
        if key in artifact and not isinstance(artifact[key], dict):
            raise ProtocolError(f"{message_type} artifact {key} is invalid")


class JsonFramer:
    """A 4-byte big-endian length-prefixed UTF-8 JSON transport."""

    HEADER_BYTES: Final[int] = 4
    MAX_FRAME_BYTES: Final[int] = MAX_FRAME_BYTES

    def __init__(self, sock: socket.socket, *, max_bytes: int = MAX_FRAME_BYTES) -> None:
        if max_bytes <= 0 or max_bytes > 0xFFFFFFFF:
            raise ValueError("max_bytes is outside the framing range")
        self.sock = sock
        self.max_bytes = max_bytes
        self._send_lock = threading.Lock()

    def send(self, value: Mapping[str, Any] | bytes) -> None:
        payload = value if isinstance(value, bytes) else encode_json(value, max_bytes=self.max_bytes)
        if len(payload) > self.max_bytes:
            raise FrameTooLarge(f"JSON frame exceeds {self.max_bytes} bytes")
        if isinstance(value, bytes):
            # Validate caller-provided encoded bytes too; the control channel is
            # always UTF-8 JSON rather than an opaque binary pipe.
            decode_json(payload, max_bytes=self.max_bytes)
        packet = struct.pack(">I", len(payload)) + payload
        with self._send_lock:
            _send_all(self.sock, packet)

    def send_envelope(self, message_type: str, request_id: str, payload: Mapping[str, Any] | None = None) -> None:
        self.send(encode_envelope(message_type, request_id, payload, max_bytes=self.max_bytes))

    def receive_bytes(self, *, timeout: float | None = None) -> bytes:
        old_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            header = _read_exact(self.sock, self.HEADER_BYTES)
            (length,) = struct.unpack(">I", header)
            if length > self.max_bytes:
                raise FrameTooLarge(f"JSON frame exceeds {self.max_bytes} bytes")
            return _read_exact(self.sock, length)
        finally:
            if timeout is not None:
                self.sock.settimeout(old_timeout)

    def receive(self, *, timeout: float | None = None) -> Any:
        return decode_json(self.receive_bytes(timeout=timeout), max_bytes=self.max_bytes)

    def receive_envelope(self, *, timeout: float | None = None, channel: str | None = None) -> Envelope:
        return Envelope.from_value(self.receive(timeout=timeout), channel=channel)


def _send_all(sock: socket.socket, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            sent = sock.send(view)
        except (BrokenPipeError, ConnectionResetError) as error:
            raise PeerDisconnected("peer disconnected while sending") from error
        if sent == 0:
            raise PeerDisconnected("peer disconnected while sending")
        view = view[sent:]


def _read_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = sock.recv(remaining)
        except (ConnectionResetError, BrokenPipeError) as error:
            raise PeerDisconnected("peer disconnected while receiving") from error
        if not chunk:
            raise PeerDisconnected("peer disconnected before a complete frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# Naming aliases for integrations that call this boundary a frame codec.
FrameCodec = JsonFramer
LengthPrefixedJson = JsonFramer


@dataclass(frozen=True)
class RequestCorrelation:
    """Small request-id helper used by clients and broker tests."""

    request_id: str
    response_type: str

    def matches(self, envelope: Envelope) -> bool:
        return envelope.request_id == self.request_id and envelope.type == self.response_type
