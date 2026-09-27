"""Protocol-1 compiler capabilities used at the native boundary."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Mapping, Sequence

from .protocol import KLANG_VERSION_PATTERN

SUPPORTED_DIALECTS: Final[tuple[str, ...]] = (
    "func-dynamic",
    "lazy",
    "func-stlc",
    "func-hm",
    "decl-dynamic",
    "decl-hm",
    "rel-dynamic",
    "rel-hm",
    "dataflow-dynamic",
    "dataflow-hm",
    "state-dynamic",
    "state-hm",
    "message-dynamic",
    "message-hm",
)
IR_MODES: Final[tuple[str, ...]] = ("default", "typed", "spans")
COMPILER_OPTIONS: Final[tuple[str, ...]] = (
    "--run",
    "--emit-ir",
    "--emit-ir=typed",
    "--emit-ir=spans",
    "-d",
    "--dialect",
    "-o",
    "--output",
)
COMPILER_CONTRACT_SCHEMA_VERSION: Final[int] = 1
ARTIFACT_MANIFEST_SCHEMA_VERSION: Final[int] = 1


class ContractError(ValueError):
    """Raised when compiler metadata is malformed or incompatible."""


def require_capabilities(
    value: object,
    required: Sequence[str],
    field: str,
) -> tuple[str, ...]:
    """Validate one advertised capability catalog and require the native subset."""

    if not isinstance(value, (list, tuple)) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ContractError(f"{field} must be a list of non-empty strings")
    catalog = tuple(value)
    if len(catalog) != len(set(catalog)):
        raise ContractError(f"{field} contains duplicate entries")
    missing = [item for item in required if item not in catalog]
    if missing:
        raise ContractError(f"{field} is missing required capabilities: {missing!r}")
    return catalog


@dataclass(frozen=True)
class CompilerContract:
    """Compiler capabilities advertised by one protocol-1 browser host."""

    supported_dialects: tuple[str, ...] = SUPPORTED_DIALECTS
    ir_modes: tuple[str, ...] = IR_MODES
    options: tuple[str, ...] = COMPILER_OPTIONS
    schema_version: int = COMPILER_CONTRACT_SCHEMA_VERSION
    requires_explicit_dialect: bool = True
    default_dialect: str | None = None
    default_output: str = "input-basename.py"
    run_alias: str = "run"

    def __post_init__(self) -> None:
        require_capabilities(self.supported_dialects, SUPPORTED_DIALECTS, "compiler dialects")
        require_capabilities(self.ir_modes, IR_MODES, "compiler IR modes")
        require_capabilities(self.options, COMPILER_OPTIONS, "compiler options")
        if self.default_dialect is not None:
            raise ContractError("the native compiler contract does not infer a default dialect")
        if type(self.schema_version) is not int or self.schema_version != COMPILER_CONTRACT_SCHEMA_VERSION:
            raise ContractError("unsupported compiler contract schema")


def default_compiler_contract() -> CompilerContract:
    return CompilerContract()


def _contract_value(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    """Get the compiler contract while requiring all supplied aliases to agree."""

    values: list[Mapping[str, Any]] = []
    for key in ("compilerContract", "cliContract", "contract"):
        candidate = manifest.get(key)
        if candidate is not None:
            if not isinstance(candidate, dict):
                raise ContractError(f"artifact manifest {key} must be an object")
            values.append(candidate)
    if not values:
        raise ContractError("artifact manifest has no compiler contract")
    first = values[0]
    if any(candidate != first for candidate in values[1:]):
        raise ContractError("artifact manifest compiler contract aliases disagree")
    return first


def _validate_provenance(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    version = manifest.get("klangVersion")
    if not isinstance(version, str) or not KLANG_VERSION_PATTERN.fullmatch(version):
        raise ContractError("artifact manifest KLang version is invalid")
    commit = manifest.get("klangCommit")
    if not isinstance(commit, str) or not commit:
        raise ContractError("artifact manifest KLang commit is invalid")
    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict):
        raise ContractError("artifact manifest has no artifact metadata")
    digest = artifact.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ContractError("artifact manifest hash is invalid")
    size = artifact.get("sizeBytes")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ContractError("artifact manifest size is invalid")
    return artifact


def contract_from_manifest(manifest: Mapping[str, Any]) -> CompilerContract:
    """Validate compatible compiler capabilities embedded in an artifact manifest."""

    if manifest.get("schemaVersion") != ARTIFACT_MANIFEST_SCHEMA_VERSION or isinstance(
        manifest.get("schemaVersion"), bool
    ):
        raise ContractError("unsupported artifact manifest schema")
    _validate_provenance(manifest)
    top_level_dialects = require_capabilities(
        manifest.get("supportedDialects"), SUPPORTED_DIALECTS, "artifact dialect catalog"
    )

    raw = _contract_value(manifest)
    allowed = {"schemaVersion", "dialects", "irModes", "options"}
    unknown = set(raw) - allowed
    if unknown:
        raise ContractError(f"compiler contract has unknown fields: {sorted(unknown)!r}")
    if raw.get("schemaVersion") != COMPILER_CONTRACT_SCHEMA_VERSION or isinstance(
        raw.get("schemaVersion"), bool
    ):
        raise ContractError("unsupported compiler contract schema")
    dialects = require_capabilities(raw.get("dialects"), SUPPORTED_DIALECTS, "compiler dialects")
    if set(dialects) != set(top_level_dialects):
        raise ContractError("artifact and compiler contract dialect catalogs disagree")
    ir_modes = require_capabilities(raw.get("irModes"), IR_MODES, "compiler IR modes")
    options = require_capabilities(raw.get("options"), COMPILER_OPTIONS, "compiler options")
    return CompilerContract(
        supported_dialects=dialects,
        ir_modes=ir_modes,
        options=options,
    )


def load_compiler_contract(
    manifest_path: str | Path | None = None,
    *,
    verify_artifact: bool = True,
) -> CompilerContract:
    """Load compatible compiler capabilities and optionally verify local artifact bytes."""

    if manifest_path is None:
        return default_compiler_contract()
    path = Path(manifest_path)
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ContractError(f"artifact manifest does not exist: {path}") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"could not read artifact manifest: {path}") from error
    if not isinstance(manifest, dict):
        raise ContractError("artifact manifest must be an object")
    contract = contract_from_manifest(manifest)
    if verify_artifact:
        artifact_entry = manifest["artifact"]
        relative = artifact_entry.get("path")
        if not isinstance(relative, str) or Path(relative).name != relative:
            raise ContractError("artifact manifest path must be a file in its manifest directory")
        artifact_path = path.parent / relative
        if not artifact_path.is_file():
            raise ContractError(f"compiler artifact does not exist: {artifact_path}")
        artifact_bytes = artifact_path.read_bytes()
        if artifact_entry.get("sha256") != hashlib.sha256(artifact_bytes).hexdigest():
            raise ContractError("compiler artifact hash does not match its manifest")
        if artifact_entry.get("sizeBytes") != len(artifact_bytes):
            raise ContractError("compiler artifact size does not match its manifest")
    return contract


def manifest_compiler_contract() -> dict[str, Any]:
    """Return the JSON-compatible capabilities used by build tooling."""

    return {
        "schemaVersion": COMPILER_CONTRACT_SCHEMA_VERSION,
        "dialects": list(SUPPORTED_DIALECTS),
        "irModes": list(IR_MODES),
        "options": list(COMPILER_OPTIONS),
    }


# Transitional spelling retained for callers that used the first draft.
manifest_cli_contract = manifest_compiler_contract
