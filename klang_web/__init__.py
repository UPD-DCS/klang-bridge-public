"""Native client and persistent localhost broker for KLang Web.

The package intentionally contains no compiler or Python execution engine.  It
only validates the pinned command contract, transfers bounded source snapshots,
and talks to the browser bridge over authenticated local transports.
"""

from .contract import (
    COMPILER_OPTIONS,
    IR_MODES,
    PINNED_ARTIFACT_SHA256,
    PINNED_ARTIFACT_SIZE_BYTES,
    PINNED_KLANG_COMMIT,
    PINNED_KLANG_VERSION,
    SUPPORTED_DIALECTS,
    CompilerContract,
    load_compiler_contract,
)
from .parser import CompilerArguments, UsageError, parse_cli_arguments, parse_compiler_arguments

__all__ = [
    "Broker",
    "BrokerManager",
    "ClientError",
    "COMPILER_OPTIONS",
    "CompilerArguments",
    "ControlClient",
    "CompilerContract",
    "IR_MODES",
    "PINNED_ARTIFACT_SHA256",
    "PINNED_ARTIFACT_SIZE_BYTES",
    "PINNED_KLANG_COMMIT",
    "PINNED_KLANG_VERSION",
    "SUPPORTED_DIALECTS",
    "UsageError",
    "load_compiler_contract",
    "parse_cli_arguments",
    "parse_compiler_arguments",
]

__version__ = "0.1.0"


def __getattr__(name: str):
    """Lazily expose transport classes without importing broker at package startup."""

    if name in {"Broker", "PersistentBroker"}:
        from .broker import Broker, PersistentBroker

        return Broker if name == "Broker" else PersistentBroker
    if name in {"BrokerManager", "ClientError", "ControlClient"}:
        from .client import BrokerManager, ClientError, ControlClient

        return {"BrokerManager": BrokerManager, "ClientError": ClientError, "ControlClient": ControlClient}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
