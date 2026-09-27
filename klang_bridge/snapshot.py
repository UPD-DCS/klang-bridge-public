"""Safe local source snapshots and atomic generated-output writes."""

from __future__ import annotations

import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator

DEFAULT_MAX_FILE_BYTES = 262_144
DEFAULT_MAX_FILES = 100
DEFAULT_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_MAX_PATH_BYTES = 512

_INCLUDE_KEYWORD = "include"
_DRIVE_QUALIFIED = re.compile(r"^[A-Za-z]:")


class LocalSnapshotError(ValueError):
    """A source snapshot cannot be safely transferred to the browser."""

    code = "client-local-file"


@dataclass(frozen=True)
class SnapshotFile:
    path: str
    text: str

    @property
    def utf8_bytes(self) -> int:
        return len(self.text.encode("utf-8"))

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "text": self.text}


@dataclass(frozen=True)
class SourceSnapshot:
    root_path: str
    files: tuple[SnapshotFile, ...]
    total_bytes: int

    def as_dict(self) -> dict[str, object]:
        return {
            "rootPath": self.root_path,
            "files": [item.as_dict() for item in self.files],
            "totalBytes": self.total_bytes,
        }


def _contains_control(value: str) -> bool:
    return any(ord(character) <= 0x1F or ord(character) == 0x7F for character in value)


def normalize_logical_path(value: str, *, max_path_bytes: int = DEFAULT_MAX_PATH_BYTES) -> str:
    """Normalize a project identity without consulting the host filesystem."""

    if not isinstance(value, str):
        raise LocalSnapshotError("project paths must be text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise LocalSnapshotError("project path is not valid UTF-8") from error
    value = value.replace("\\", "/")
    if value.startswith("/") or _DRIVE_QUALIFIED.match(value):
        raise LocalSnapshotError("host-absolute and drive-qualified paths are not allowed")
    segments: list[str] = []
    for segment in value.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            if not segments:
                raise LocalSnapshotError("project path traverses outside the project root")
            segments.pop()
            continue
        if _contains_control(segment):
            raise LocalSnapshotError("project path contains a control character")
        segments.append(segment)
    if not segments:
        raise LocalSnapshotError("project path must identify a file")
    normalized = "/".join(segments)
    if len(normalized.encode("utf-8")) > max_path_bytes:
        raise LocalSnapshotError("project path exceeds the path limit")
    return normalized


def _read_regular_text(path: Path, *, max_file_bytes: int) -> str:
    _reject_unsafe_entry(path)
    try:
        size = path.stat().st_size
    except OSError as error:
        raise LocalSnapshotError(f"cannot inspect source file: {path.name}") from error
    if size > max_file_bytes:
        raise LocalSnapshotError(f"source file exceeds {max_file_bytes} UTF-8 bytes: {path.name}")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise LocalSnapshotError(f"cannot read source file: {path.name}") from error
    if len(raw) > max_file_bytes:
        raise LocalSnapshotError(f"source file exceeds {max_file_bytes} UTF-8 bytes: {path.name}")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise LocalSnapshotError(f"source file is not valid UTF-8: {path.name}") from error


def _reject_symlink_components(path: Path) -> None:
    """Reject a symlink anywhere in a local source path."""

    for candidate in (path, *path.parents):
        try:
            if stat.S_ISLNK(candidate.lstat().st_mode):
                raise LocalSnapshotError("symbolic links are not allowed in source snapshots")
        except FileNotFoundError:
            continue
        except OSError as error:
            raise LocalSnapshotError("cannot inspect source path") from error
        if candidate.parent == candidate:
            break


def _reject_unsafe_entry(path: Path) -> None:
    try:
        entry = path.lstat()
    except OSError as error:
        raise LocalSnapshotError(f"source file does not exist: {path}") from error
    if stat.S_ISLNK(entry.st_mode):
        raise LocalSnapshotError(f"symbolic links are not allowed in source snapshots: {path.name}")
    if not stat.S_ISREG(entry.st_mode):
        raise LocalSnapshotError(f"source path is not a regular file: {path.name}")


def _ensure_contained(candidate: Path, project_root: Path) -> Path:
    # Inspect the lexical path before resolving it.  Resolving first would hide
    # an in-root symlink whose target happens to remain in the project.
    try:
        lexical = candidate.absolute()
        lexical.relative_to(project_root)
    except (OSError, ValueError) as error:
        raise LocalSnapshotError("included source escapes the project root") from error
    current = project_root
    for part in lexical.relative_to(project_root).parts:
        current = current / part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise LocalSnapshotError("symbolic links are not allowed in source snapshots")
        except FileNotFoundError:
            break
        except OSError as error:
            raise LocalSnapshotError("cannot inspect included source path") from error
    try:
        resolved = lexical.resolve(strict=False)
        resolved.relative_to(project_root)
    except (OSError, ValueError) as error:
        raise LocalSnapshotError("included source escapes the project root") from error
    return resolved


def _decode_klang_string(raw: str) -> str:
    chars: list[str] = []
    index = 0
    escapes = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}
    while index < len(raw):
        character = raw[index]
        if character != "\\":
            chars.append(character)
            index += 1
            continue
        index += 1
        if index >= len(raw):
            raise LocalSnapshotError("include path contains an incomplete escape")
        escaped = raw[index]
        chars.append(escapes.get(escaped, escaped))
        index += 1
    return "".join(chars)


def iter_include_requests(source: str) -> Iterator[tuple[str, int, int]]:
    """Yield canonical ``include "path";`` directives outside comments/strings.

    The scanner intentionally recognizes only the Stage 2 include form.  It
    does not attempt to parse the entire language; syntax errors remain the
    browser compiler's responsibility.  Line/column are retained for local
    diagnostics and future protocol adapters.
    """

    index = 0
    line = 1
    column = 1
    length = len(source)

    def advance(character: str) -> None:
        nonlocal line, column
        if character == "\n":
            line += 1
            column = 1
        else:
            column += 1

    while index < length:
        character = source[index]
        if character == "#":
            while index < length and source[index] != "\n":
                advance(source[index])
                index += 1
            continue
        if character == '"':
            advance(character)
            index += 1
            escaped = False
            while index < length:
                current = source[index]
                advance(current)
                index += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    break
            continue
        if character.isalpha() or character == "_":
            start = index
            start_line, start_column = line, column
            while index < length and (source[index].isalnum() or source[index] == "_"):
                advance(source[index])
                index += 1
            word = source[start:index]
            if word != _INCLUDE_KEYWORD:
                continue
            # Whitespace between the keyword, literal, and semicolon is
            # accepted exactly as the lexer accepts inline whitespace.
            while index < length and source[index] in " \t\r\n":
                advance(source[index])
                index += 1
            if index >= length or source[index] != '"':
                continue
            advance(source[index])
            index += 1
            raw_chars: list[str] = []
            escaped = False
            closed = False
            while index < length:
                current = source[index]
                advance(current)
                index += 1
                if escaped:
                    raw_chars.append("\\")
                    raw_chars.append(current)
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    closed = True
                    break
                else:
                    raw_chars.append(current)
            if not closed:
                raise LocalSnapshotError("unterminated include path literal")
            whitespace_start = index
            while index < length and source[index] in " \t\r\n":
                advance(source[index])
                index += 1
            if index >= length or source[index] != ";":
                # It is an invalid source construct, not a source-closure
                # directive.  Let the compiler report it rather than guessing.
                index = whitespace_start
                continue
            advance(source[index])
            index += 1
            yield _decode_klang_string("".join(raw_chars)), start_line, start_column
            continue
        advance(character)
        index += 1


def _resolve_include(
    including: str,
    requested: str,
    *,
    project_root: Path,
    max_path_bytes: int,
) -> tuple[str, Path]:
    requested_normalized = requested.replace("\\", "/")
    if requested_normalized.startswith("/") or _DRIVE_QUALIFIED.match(requested_normalized):
        raise LocalSnapshotError("include path must stay inside the project root")
    # Resolve the logical path with the same slash/traversal policy as the
    # browser virtual filesystem.
    base = PurePosixPath(including).parent
    logical = normalize_logical_path(str(base / requested_normalized), max_path_bytes=max_path_bytes)
    candidate = _ensure_contained(project_root / Path(*logical.split("/")), project_root)
    return logical, candidate


def discover_snapshot(
    input_path: str | Path,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_path_bytes: int = DEFAULT_MAX_PATH_BYTES,
) -> SourceSnapshot:
    """Read the root and deterministic recursive include closure."""

    source_path = Path(input_path).expanduser()
    try:
        # ``abspath`` normalizes dot segments without following symlinks, so
        # the lexical path can be audited before resolving its project root.
        absolute_input = Path(os.path.abspath(str(source_path)))
    except OSError as error:
        raise LocalSnapshotError("cannot resolve input path") from error
    _reject_symlink_components(absolute_input)
    if not absolute_input.exists():
        raise LocalSnapshotError(f"input source does not exist: {input_path}")
    try:
        project_root = absolute_input.parent.resolve(strict=True)
    except OSError as error:
        raise LocalSnapshotError("input project directory is unavailable") from error
    _reject_unsafe_entry(absolute_input)
    root_logical = normalize_logical_path(absolute_input.name, max_path_bytes=max_path_bytes)

    collected: list[SnapshotFile] = []
    by_logical: set[str] = set()
    visiting: set[str] = set()
    total_bytes = 0

    def visit(logical: str, path: Path) -> None:
        nonlocal total_bytes
        if logical in visiting:
            raise LocalSnapshotError(f"include cycle detected at {logical}")
        if logical in by_logical:
            return
        if len(collected) >= max_files:
            raise LocalSnapshotError(f"source snapshot exceeds {max_files} files")
        visiting.add(logical)
        text = _read_regular_text(path, max_file_bytes=max_file_bytes)
        encoded_size = len(text.encode("utf-8"))
        if total_bytes + encoded_size > max_total_bytes:
            raise LocalSnapshotError(f"source snapshot exceeds {max_total_bytes} UTF-8 bytes")
        by_logical.add(logical)
        collected.append(SnapshotFile(logical, text))
        total_bytes += encoded_size
        for requested, _line, _column in iter_include_requests(text):
            included_logical, included_path = _resolve_include(
                logical,
                requested,
                project_root=project_root,
                max_path_bytes=max_path_bytes,
            )
            visit(included_logical, included_path)
        visiting.remove(logical)

    visit(root_logical, absolute_input)
    return SourceSnapshot(root_logical, tuple(collected), total_bytes)


def atomic_write_text(path: str | Path, text: str) -> None:
    """Replace a generated output atomically with exact UTF-8 bytes."""

    if not isinstance(text, str):
        raise TypeError("generated output must be text")
    try:
        encoded = text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise LocalSnapshotError("generated output is not valid UTF-8") from error
    destination = Path(path).expanduser()
    parent = destination.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise LocalSnapshotError(f"cannot create output directory: {parent}") from error
    temporary_name: str | None = None
    try:
        fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=parent)
        temporary = Path(temporary_name)
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary_name = None
        if os.name != "nt":
            # Generated source is intentionally private-by-default only while
            # being replaced; make a normal source file readable afterwards.
            os.chmod(destination, 0o644)
        try:
            directory_fd = os.open(parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            except OSError:
                pass
            finally:
                os.close(directory_fd)
    except OSError as error:
        raise LocalSnapshotError(f"cannot atomically write output: {destination}") from error
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


# Names used by clients that prefer the vocabulary from the OpenSpec.
LocalFileError = LocalSnapshotError
Snapshot = SourceSnapshot
create_snapshot = discover_snapshot
discover_source_snapshot = discover_snapshot
write_output_atomic = atomic_write_text
atomic_write_output = atomic_write_text
