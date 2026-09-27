"""Canonical Stage 2 argument parsing for the native client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Sequence

from .contract import IR_MODES, SUPPORTED_DIALECTS

USAGE_PREFIX: Final[str] = (
    "[--version] [--run] [--emit-ir|--emit-ir=typed|--emit-ir=spans] "
    "(--dialect|-d) DIALECT INPUT [-o OUTPUT]"
)


class UsageError(ValueError):
    """The canonical compiler parser rejected an invocation."""

    exit_code: Final[int] = 2

    def __init__(self, *, prog: str = "klangb") -> None:
        self.prog = prog
        super().__init__(self.usage())

    def usage(self) -> str:
        return usage_text(self.prog)


@dataclass(frozen=True)
class CompilerArguments:
    """The normalized subset of the pinned Stage 2 CLI configuration."""

    run: bool
    emit_ir: str | None
    dialect: str
    input_path: str
    output_path: str | None

    @property
    def is_ir(self) -> bool:
        return self.emit_ir is not None

    @property
    def ir_mode(self) -> str | None:
        return self.emit_ir

    @property
    def effective_output_name(self) -> str:
        return default_output_name(self.input_path)


def usage_text(prog: str = "klangb") -> str:
    """Render the Stage 2 usage contract, ending with a newline."""

    return (
        f"usage: {prog} {USAGE_PREFIX}\n"
        "  DIALECT: "
        + " | ".join(SUPPORTED_DIALECTS)
        + "\n"
        "  IR modes: --emit-ir | --emit-ir=typed | --emit-ir=spans (prints KIR to stdout)\n"
    )


def _invalid(prog: str) -> UsageError:
    return UsageError(prog=prog)


def _is_flag(value: str) -> bool:
    # This deliberately matches the Stage 2 source contract: every string
    # beginning with '-' is treated as an option, including the lone '-'.
    return bool(value) and value[0] == "-"


def parse_compiler_arguments(
    argv: Sequence[str],
    *,
    prog: str = "klangb",
) -> CompilerArguments:
    """Parse exactly the pinned Stage 2 options.

    The canonical parser accepts options in any order and treats a repeated
    ``--run`` as idempotent.  Dialect, output, IR mode, and input are each
    single-assignment.  It intentionally has no ``--`` terminator, short
    clustered options, inferred dialect, or alternate flags.
    """

    run = False
    emit_ir: str | None = None
    dialect: str | None = None
    input_path: str | None = None
    output_path: str | None = None
    index = 0
    args = list(argv)

    def need_value() -> str:
        nonlocal index
        index += 1
        if index >= len(args):
            raise _invalid(prog)
        value = args[index]
        if _is_flag(value):
            raise _invalid(prog)
        return value

    while index < len(args):
        token = args[index]
        if token == "--run":
            run = True
        elif token == "--emit-ir":
            if emit_ir is not None:
                raise _invalid(prog)
            emit_ir = "default"
        elif token == "--emit-ir=typed":
            if emit_ir is not None:
                raise _invalid(prog)
            emit_ir = "typed"
        elif token == "--emit-ir=spans":
            if emit_ir is not None:
                raise _invalid(prog)
            emit_ir = "spans"
        elif token in ("-d", "--dialect"):
            if dialect is not None:
                raise _invalid(prog)
            value = need_value()
            if value not in SUPPORTED_DIALECTS:
                raise _invalid(prog)
            dialect = value
        elif token in ("-o", "--output"):
            if output_path is not None:
                raise _invalid(prog)
            # The canonical implementation permits an empty output string;
            # it is equivalent to omission in its final configuration step.
            value = need_value()
            output_path = value or None
        elif _is_flag(token):
            raise _invalid(prog)
        else:
            # Stage 2 uses an empty string as the missing-input sentinel, so
            # an explicitly empty positional can be overwritten by a later
            # positional before final validation.
            if input_path not in (None, ""):
                raise _invalid(prog)
            input_path = token
        index += 1

    if not input_path or dialect is None:
        raise _invalid(prog)
    if emit_ir is not None and (run or output_path is not None):
        raise _invalid(prog)
    if emit_ir is not None and emit_ir not in IR_MODES:
        raise _invalid(prog)
    return CompilerArguments(run, emit_ir, dialect, input_path, output_path)


def parse_cli_arguments(
    argv: Sequence[str],
    *,
    prog: str = "klangb",
) -> CompilerArguments:
    """Parse the native compiler command, including the ``run`` meta-alias."""

    args = list(argv)
    if args and args[0] == "run":
        return parse_compiler_arguments(("--run", *args[1:]), prog=prog)
    return parse_compiler_arguments(args, prog=prog)


def default_output_name(input_path: str) -> str:
    """Return Stage 2's basename output name, including its dot-file quirk."""

    slash = -1
    for index, character in enumerate(input_path):
        if character == "/":
            slash = index
    start = slash + 1
    dot = -1
    for index in range(start, len(input_path)):
        if input_path[index] == ".":
            dot = index
    end = dot if dot > slash else len(input_path)
    return input_path[start:end] + ".py"


# Compact aliases for callers that use the canonical compiler terminology.
parse_args = parse_cli_arguments
parse_compiler_args = parse_compiler_arguments
default_output = default_output_name
