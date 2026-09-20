"""The pinned Stage 2 compiler contract used at the native boundary."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Mapping

PINNED_KLANG_VERSION: Final[str] = "0.3.1"
PINNED_KLANG_COMMIT: Final[str] = "3cb5dba21600302b701640c5554117564632c51c"
PINNED_ARTIFACT_SHA256: Final[str] = "2b890be20e4ad4ef693f8384c72c63814abe4de11fd4d51d3c42dbbd16c8e10a"
PINNED_ARTIFACT_SIZE_BYTES: Final[int] = 4_048_156
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


@dataclass(frozen=True)
class CompilerContract:
    """Public compiler options and provenance for one browser artifact."""

    klang_commit: str = PINNED_KLANG_COMMIT
    supported_dialects: tuple[str, ...] = SUPPORTED_DIALECTS
    ir_modes: tuple[str, ...] = IR_MODES
    options: tuple[str, ...] = COMPILER_OPTIONS
    schema_version: int = COMPILER_CONTRACT_SCHEMA_VERSION
    requires_explicit_dialect: bool = True
    default_dialect: str | None = None
    default_output: str = "input-basename.py"
    run_alias: str = "run"

    def __post_init__(self) -> None:
        if self.klang_commit != PINNED_KLANG_COMMIT:
            raise ContractError("compiler contract is not tied to the pinned KLang commit")
        if self.supported_dialects != SUPPORTED_DIALECTS:
            raise ContractError("compiler contract dialect catalog is not the Stage 2 catalog")
        if self.ir_modes != IR_MODES:
            raise ContractError("compiler contract IR modes are not the Stage 2 modes")
        if self.options != COMPILER_OPTIONS:
            raise ContractError("compiler contract options do not match Stage 2")
        if self.default_dialect is not None:
            raise ContractError("Stage 2 does not infer a default dialect")
        if type(self.schema_version) is not int or self.schema_version != COMPILER_CONTRACT_SCHEMA_VERSION:
            raise ContractError("unsupported compiler contract schema")


class ContractError(ValueError):
    """Raised when packaged compiler metadata is malformed or mismatched."""


def default_compiler_contract() -> CompilerContract:
    return CompilerContract()


def _require_string_tuple(mapping: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = mapping.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ContractError(f"compiler contract field {key!r} must be a string list")
    return tuple(value)


def _contract_value(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    """Get the generated compiler contract, accepting transitional field names."""

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


def contract_from_manifest(manifest: Mapping[str, Any]) -> CompilerContract:
    """Validate the generated compiler contract embedded in an artifact manifest."""

    if manifest.get("schemaVersion") != ARTIFACT_MANIFEST_SCHEMA_VERSION or isinstance(
        manifest.get("schemaVersion"), bool
    ):
        raise ContractError("unsupported artifact manifest schema")
    if manifest.get("klangVersion") != PINNED_KLANG_VERSION:
        raise ContractError("artifact manifest does not identify the pinned KLang version")
    if manifest.get("klangCommit") != PINNED_KLANG_COMMIT:
        raise ContractError("artifact manifest does not identify the pinned KLang commit")
    if manifest.get("supportedDialects") != list(SUPPORTED_DIALECTS):
        raise ContractError("artifact manifest dialect catalog is not the Stage 2 catalog")

    raw = _contract_value(manifest)
    allowed = {"schemaVersion", "dialects", "irModes", "options"}
    unknown = set(raw) - allowed
    if unknown:
        raise ContractError(f"compiler contract has unknown fields: {sorted(unknown)!r}")
    if raw.get("schemaVersion") != COMPILER_CONTRACT_SCHEMA_VERSION or isinstance(
        raw.get("schemaVersion"), bool
    ):
        raise ContractError("unsupported compiler contract schema")
    if raw.get("dialects") != list(SUPPORTED_DIALECTS):
        raise ContractError("compiler contract dialect catalog is not the Stage 2 catalog")
    if raw.get("irModes") != list(IR_MODES):
        raise ContractError("compiler contract IR catalog is not the Stage 2 catalog")
    if raw.get("options") != list(COMPILER_OPTIONS):
        raise ContractError("compiler contract option list does not match Stage 2")
    return CompilerContract(
        klang_commit=PINNED_KLANG_COMMIT,
        supported_dialects=_require_string_tuple({"dialects": raw["dialects"]}, "dialects"),
        ir_modes=_require_string_tuple(raw, "irModes"),
        options=_require_string_tuple(raw, "options"),
    )


def load_compiler_contract(
    manifest_path: str | Path | None = None,
    *,
    verify_artifact: bool = True,
) -> CompilerContract:
    """Load and validate packaged compiler metadata.

    ``manifest_path`` is injectable for tests and alternate installations.  An
    installed wheels use the pinned built-in contract by default; an explicit
    manifest path can provide artifact metadata for a compatible browser host
    or an integration test.
    """

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
        artifact_entry = manifest.get("artifact")
        if not isinstance(artifact_entry, dict):
            raise ContractError("artifact manifest has no artifact metadata")
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
    """Return the JSON-compatible generated contract used by build tooling."""

    return {
        "schemaVersion": COMPILER_CONTRACT_SCHEMA_VERSION,
        "dialects": list(SUPPORTED_DIALECTS),
        "irModes": list(IR_MODES),
        "options": list(COMPILER_OPTIONS),
    }


# Transitional spelling retained for callers that used the first draft.
manifest_cli_contract = manifest_compiler_contract
