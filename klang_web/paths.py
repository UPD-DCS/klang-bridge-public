"""Private per-user broker state, endpoint probing, and startup locking."""

from __future__ import annotations

import configparser
import errno
import json
import os
import secrets
import shutil
import socket
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

RUNTIME_ENV = "KLANG_WEB_RUNTIME_DIR"
STATE_FILE_NAME = "broker.state.json"
SECRET_FILE_NAME = "broker.secret"
LOCK_DIR_NAME = "broker.lock"
CONFIG_FILE_NAME = "config.ini"
STATE_SCHEMA_VERSION = 1


class RuntimeStateError(ValueError):
    """The on-disk broker state is malformed or unsafe."""


class LockHeldError(RuntimeError):
    """Another broker owns the runtime lock."""


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int

    def __post_init__(self) -> None:
        if self.host not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeStateError("broker endpoints must be loopback")
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise RuntimeStateError("broker endpoint port is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {"host": self.host, "port": self.port}


@dataclass(frozen=True)
class BrokerState:
    """The non-secret state published by a broker."""

    pid: int
    control: Endpoint
    websocket: Endpoint
    origin: str
    state: str = "disconnected"
    protocol_version: int = 1
    generation: int = 0
    started_at: float = 0.0
    artifact: Mapping[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schemaVersion": STATE_SCHEMA_VERSION,
            "pid": self.pid,
            "control": self.control.as_dict(),
            "websocket": self.websocket.as_dict(),
            "origin": self.origin,
            "state": self.state,
            "protocolVersion": self.protocol_version,
            "generation": self.generation,
            "startedAt": self.started_at,
        }
        if self.artifact is not None:
            value["artifact"] = dict(self.artifact)
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BrokerState":
        _strict_keys(
            value,
            {
                "schemaVersion",
                "pid",
                "control",
                "websocket",
                "origin",
                "state",
                "protocolVersion",
                "generation",
                "startedAt",
                "artifact",
            },
            "broker state",
        )
        if value.get("schemaVersion") != STATE_SCHEMA_VERSION or isinstance(value.get("schemaVersion"), bool):
            raise RuntimeStateError("unsupported broker state schema")
        pid = value.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise RuntimeStateError("broker state PID is invalid")
        control = _endpoint(value.get("control"))
        websocket = _endpoint(value.get("websocket"))
        origin = value.get("origin")
        state = value.get("state")
        protocol = value.get("protocolVersion")
        generation = value.get("generation")
        started_at = value.get("startedAt")
        if not isinstance(origin, str) or not origin:
            raise RuntimeStateError("broker state origin is invalid")
        parsed_origin = urlsplit(origin)
        if (
            parsed_origin.scheme not in {"http", "https"}
            or not parsed_origin.netloc
            or parsed_origin.path not in {"", "/"}
            or parsed_origin.query
            or parsed_origin.fragment
        ):
            raise RuntimeStateError("broker state origin is invalid")
        if not isinstance(state, str) or state not in {
            "starting",
            "disconnected",
            "bootstrapping",
            "ready",
            "stale",
            "bootstrap-failed",
            "stopping",
        }:
            raise RuntimeStateError("broker state status is invalid")
        if type(protocol) is not int or protocol != 1:
            raise RuntimeStateError("unsupported broker protocol version")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
            raise RuntimeStateError("broker generation is invalid")
        if not isinstance(started_at, (int, float)) or isinstance(started_at, bool):
            raise RuntimeStateError("broker start time is invalid")
        artifact = value.get("artifact")
        if artifact is not None and not isinstance(artifact, dict):
            raise RuntimeStateError("broker artifact metadata is invalid")
        return cls(
            pid=pid,
            control=control,
            websocket=websocket,
            origin=origin,
            state=state,
            protocol_version=protocol,
            generation=generation,
            started_at=float(started_at),
            artifact=artifact,
        )


def _strict_keys(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise RuntimeStateError(f"{label} has unknown fields: {sorted(unknown)!r}")


def _endpoint(value: Any) -> Endpoint:
    if not isinstance(value, dict):
        raise RuntimeStateError("broker endpoint must be an object")
    _strict_keys(value, {"host", "port"}, "broker endpoint")
    host = value.get("host")
    port = value.get("port")
    if not isinstance(host, str):
        raise RuntimeStateError("broker endpoint host is invalid")
    return Endpoint(host, port)  # type: ignore[arg-type]


def _chmod_private(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        # Windows does not implement Unix permission bits.  The ACL remains
        # per-user for the default local application directory there.
        if os.name != "nt":
            raise


@dataclass(frozen=True)
class RuntimePaths:
    """Names and creation policy for one user's broker runtime directory."""

    root: Path

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> "RuntimePaths":
        env = os.environ if environ is None else environ
        explicit = env.get(RUNTIME_ENV)
        if explicit:
            root = Path(explicit).expanduser()
        elif os.name == "nt":
            local_app_data = env.get("LOCALAPPDATA")
            root = (
                Path(local_app_data).expanduser() / "KLang Web"
                if local_app_data
                else Path.home() / "AppData" / "Local" / "KLang Web"
            )
        else:
            xdg_runtime = env.get("XDG_RUNTIME_DIR")
            if xdg_runtime:
                root = Path(xdg_runtime).expanduser() / "klang-web"
            elif sys.platform == "darwin":
                root = Path.home() / "Library" / "Application Support" / "KLang Web"
            else:
                xdg_state = env.get("XDG_STATE_HOME")
                root = (
                    Path(xdg_state).expanduser() / "klang-web"
                    if xdg_state
                    else Path.home() / ".local" / "state" / "klang-web"
                )
        return cls(root.resolve())

    @property
    def state_file(self) -> Path:
        return self.root / STATE_FILE_NAME

    @property
    def state_path(self) -> Path:
        return self.state_file

    @property
    def secret_file(self) -> Path:
        return self.root / SECRET_FILE_NAME

    @property
    def secret_path(self) -> Path:
        return self.secret_file

    @property
    def config_file(self) -> Path:
        return self.root / CONFIG_FILE_NAME

    @property
    def lock_dir(self) -> Path:
        return self.root / LOCK_DIR_NAME

    @property
    def lock_path(self) -> Path:
        return self.lock_dir

    @property
    def runtime_dir(self) -> Path:
        return self.root

    def ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        _chmod_private(self.root, 0o700)

    def configured_origin(self) -> str | None:
        """Read the optional non-secret bridge origin from the per-user config."""

        if not self.config_file.is_file():
            return None
        parser = configparser.ConfigParser()
        try:
            parser.read(self.config_file, encoding="utf-8")
        except (configparser.Error, OSError, UnicodeError) as error:
            raise RuntimeStateError(f"could not read broker config: {self.config_file}") from error
        value = parser.get("bridge", "origin", fallback="").strip()
        return value or None

    def read_state(self) -> BrokerState | None:
        try:
            if os.name != "nt" and self.state_file.stat().st_mode & 0o077:
                raise RuntimeStateError("broker state permissions are too broad")
            raw = self.state_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError) as error:
            raise RuntimeStateError(f"could not read broker state: {self.state_file}") from error
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RuntimeStateError(f"broker state is not valid JSON: {self.state_file}") from error
        if not isinstance(value, dict):
            raise RuntimeStateError("broker state must be an object")
        return BrokerState.from_dict(value)

    def write_state(self, state: BrokerState) -> None:
        self.ensure_root()
        _atomic_write_json(self.state_file, state.as_dict())

    def remove_state(self) -> None:
        _unlink_quiet(self.state_file)

    def read_secret(self) -> str:
        try:
            if os.name != "nt" and self.secret_file.stat().st_mode & 0o077:
                raise RuntimeStateError("broker control secret permissions are too broad")
            value = self.secret_file.read_text(encoding="ascii")
        except (FileNotFoundError, OSError) as error:
            raise RuntimeStateError("broker control secret is unavailable") from error
        value = value.rstrip("\n")
        if not value or len(value) > 256 or any(character.isspace() for character in value):
            raise RuntimeStateError("broker control secret is invalid")
        return value

    def write_secret(self, secret: str | None = None) -> str:
        value = secret or secrets.token_urlsafe(32)
        if not value or any(character.isspace() for character in value):
            raise ValueError("secret must be non-empty non-whitespace text")
        self.ensure_root()
        _atomic_write_text(self.secret_file, value + "\n", mode=0o600)
        _chmod_private(self.secret_file, 0o600)
        return value

    def remove_secret(self) -> None:
        _unlink_quiet(self.secret_file)

    def remove_all(self) -> None:
        self.remove_state()
        self.remove_secret()
        self.lock.release_if_owned()

    @property
    def lock(self) -> "BrokerLock":
        return BrokerLock(self)

    def endpoint_is_open(self, endpoint: Endpoint, timeout: float = 0.25) -> bool:
        try:
            with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout):
                return True
        except OSError:
            return False

    def pid_is_alive(self, pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError as error:
            if error.errno == errno.ESRCH:
                return False
            return False
        return True

    def probe(self, state: BrokerState | None = None, timeout: float = 0.25) -> str:
        """Classify runtime state without trusting stale endpoint metadata."""

        try:
            current = state if state is not None else self.read_state()
        except RuntimeStateError:
            return "stale"
        if current is None:
            return "disconnected"
        if not self.pid_is_alive(current.pid):
            return "stale"
        if not self.endpoint_is_open(current.control, timeout):
            return "stale"
        return current.state

    def recover_stale(self) -> bool:
        """Remove state/lock only when the recorded broker cannot be reached."""

        try:
            state = self.read_state()
        except RuntimeStateError:
            state = None
        if state is not None and self.pid_is_alive(state.pid) and self.endpoint_is_open(state.control):
            return False
        self.remove_state()
        self.remove_secret()
        self.lock.release_if_unowned_or_stale()
        return True


class BrokerLock:
    """An atomic directory lock owned by the broker process."""

    def __init__(self, paths: RuntimePaths) -> None:
        self.paths = paths
        self._owned = False
        self._owner = secrets.token_hex(16)

    def acquire(self, *, recover_stale: bool = True) -> None:
        self.paths.ensure_root()
        try:
            self.paths.lock_dir.mkdir()
        except FileExistsError:
            if recover_stale and self.paths.recover_stale():
                try:
                    self.paths.lock_dir.mkdir()
                except FileExistsError as error:
                    raise LockHeldError("another klang-web broker owns the runtime lock") from error
            else:
                raise LockHeldError("another klang-web broker owns the runtime lock")
        except OSError as error:
            raise RuntimeStateError(f"could not create broker lock: {self.paths.lock_dir}") from error
        try:
            _atomic_write_json(self.paths.lock_dir / "owner.json", {"pid": os.getpid(), "owner": self._owner})
            self._owned = True
        except BaseException:
            _rmtree_quiet(self.paths.lock_dir)
            raise

    def release(self) -> None:
        if not self._owned:
            return
        owner_file = self.paths.lock_dir / "owner.json"
        try:
            raw = json.loads(owner_file.read_text(encoding="utf-8"))
            if raw.get("owner") != self._owner:
                return
        except (OSError, ValueError, AttributeError):
            return
        _rmtree_quiet(self.paths.lock_dir)
        self._owned = False

    def release_if_owned(self) -> None:
        self.release()

    def release_if_unowned_or_stale(self) -> None:
        """Best-effort stale-lock cleanup, never remove a live owner's lock."""

        owner_file = self.paths.lock_dir / "owner.json"
        try:
            raw = json.loads(owner_file.read_text(encoding="utf-8"))
            pid = raw.get("pid")
        except (FileNotFoundError, OSError, ValueError, AttributeError):
            pid = None
        if isinstance(pid, int) and self.paths.pid_is_alive(pid):
            return
        _rmtree_quiet(self.paths.lock_dir)

    def __enter__(self) -> "BrokerLock":
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


def _atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        _chmod_private(temporary, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _chmod_private(path, mode)
    except BaseException:
        _unlink_quiet(temporary)
        raise


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    _atomic_write_text(path, json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def _unlink_quiet(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _rmtree_quiet(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass
