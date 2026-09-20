"""``klangb`` command-line entry point."""

from __future__ import annotations

import signal
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Sequence, TextIO

from .client import (
    CLIENT_EXIT_STATUS,
    BRIDGE_READY_TIMEOUT_SECONDS,
    BrokerManager,
    ClientError,
    OperationPayload,
    read_redirected_stdin,
)
from .parser import CompilerArguments, UsageError, default_output_name, parse_cli_arguments, usage_text
from .snapshot import LocalSnapshotError, atomic_write_text, discover_snapshot


def _print_error(message: str, stream: TextIO) -> None:
    print(message, file=stream)


def _format_diagnostic(diagnostic: object) -> str:
    if not isinstance(diagnostic, dict):
        return str(diagnostic)
    message = diagnostic.get("message")
    if not isinstance(message, str):
        return str(diagnostic)
    location = diagnostic.get("location")
    if isinstance(location, dict):
        path = location.get("path")
        line = location.get("line")
        column = location.get("column")
        if isinstance(path, str) and isinstance(line, int) and isinstance(column, int):
            return f"{path}:{line}:{column}: {message}"
    return message


def _result_exit_code(result: dict[str, Any]) -> int:
    status = result.get("status")
    if status == "success":
        return 0
    if status == "cancelled":
        return 130
    if status == "timed-out":
        return 124
    exit_code = result.get("exitCode")
    if isinstance(exit_code, int) and 0 <= exit_code <= 255:
        return exit_code or 1
    return 1


def _write_stream(stream: TextIO, value: object) -> None:
    if isinstance(value, str) and value:
        stream.write(value)
        stream.flush()


def _unstreamed_suffix(final_text: str, streamed_text: str) -> str:
    if not streamed_text:
        return final_text
    if final_text == streamed_text:
        return ""
    if final_text.startswith(streamed_text):
        return final_text[len(streamed_text) :]
    return final_text


def _render_result(result: dict[str, Any], *, stdout: TextIO, stderr: TextIO) -> None:
    _write_stream(stdout, result.get("stdout"))
    stderr_value = result.get("stderr")
    if isinstance(stderr_value, str) and stderr_value:
        _write_stream(stderr, stderr_value)
        return
    diagnostics = result.get("diagnostics")
    if isinstance(diagnostics, list):
        rendered = "\n".join(_format_diagnostic(item) for item in diagnostics)
        if rendered:
            _write_stream(stderr, rendered + ("\n" if not rendered.endswith("\n") else ""))
    runtime_failure = result.get("runtimeFailure")
    if isinstance(runtime_failure, dict) and isinstance(runtime_failure.get("message"), str):
        message = runtime_failure["message"]
        _write_stream(stderr, message + ("\n" if not message.endswith("\n") else ""))


def _input_for_run(stdin: TextIO) -> tuple[str, bool]:
    return read_redirected_stdin(stdin)


def execute_compiler(
    arguments: CompilerArguments,
    *,
    manager: BrokerManager,
    stdout: TextIO,
    stderr: TextIO,
    stdin: TextIO,
) -> int:
    """Validate/read local files before contacting the browser, then execute one operation."""

    try:
        snapshot = discover_snapshot(arguments.input_path)
    except LocalSnapshotError as error:
        _print_error(f"client-local-file: {error}", stderr)
        return CLIENT_EXIT_STATUS

    preloaded_stdin = ""
    interactive_stdin = False
    if arguments.run:
        try:
            preloaded_stdin, interactive_stdin = _input_for_run(stdin)
        except ClientError as error:
            _print_error(f"{error.code}: {error}", stderr)
            return error.exit_code

    payload = OperationPayload(
        snapshot=snapshot,
        dialect=arguments.dialect,
        stdin=preloaded_stdin,
        interactive_stdin=interactive_stdin,
        mode=arguments.emit_ir,
    ).as_dict()
    output_path: Path | None = None
    if arguments.emit_ir is None:
        if arguments.run:
            if arguments.output_path is not None:
                output_path = Path(arguments.output_path).expanduser()
        else:
            output_path = (
                Path(arguments.output_path).expanduser()
                if arguments.output_path is not None
                else Path.cwd() / default_output_name(arguments.input_path)
            )
    output_error: LocalSnapshotError | None = None
    streamed_stdout: list[str] = []
    streamed_stderr: list[str] = []

    try:
        try:
            control = manager.open_existing_control()
        except ClientError as error:
            if not arguments.run or error.code != "client-disconnected":
                raise
            manager.connect()
            control = manager.open_existing_control()
    except ClientError as error:
        _print_error(f"{error.code}: {error}", stderr)
        return error.exit_code

    request_id = "operation-" + uuid.uuid4().hex
    interrupted = False
    old_handler: Any = None

    def on_interrupt(signum: int, frame: Any) -> None:
        del signum, frame
        nonlocal interrupted
        if interrupted:
            # A second interrupt is allowed to stop waiting locally, but do not
            # terminate the persistent broker or run source on this machine.
            raise KeyboardInterrupt
        interrupted = True
        try:
            control.request_stop_now(request_id)
        except ClientError:
            pass

    def on_event(message: Any) -> None:
        nonlocal output_error
        message_type = getattr(message, "type", None)
        event = getattr(message, "payload", {})
        if message_type == "control-output" and isinstance(event, dict):
            event_name = event.get("event")
            if event_name == "output":
                stream = event.get("stream")
                chunk = event.get("chunk")
                if stream == "stdout" and isinstance(chunk, str):
                    streamed_stdout.append(chunk)
                    _write_stream(stdout, chunk)
                elif stream == "stderr" and isinstance(chunk, str):
                    streamed_stderr.append(chunk)
                    _write_stream(stderr, chunk)
            if event_name == "compiler-output":
                compiler_output = event.get("output")
                generated_event = (
                    compiler_output.get("text")
                    if isinstance(compiler_output, dict) and compiler_output.get("kind") == "python"
                    else None
                )
                if output_path is not None and isinstance(generated_event, str):
                    try:
                        atomic_write_text(output_path, generated_event)
                    except LocalSnapshotError as error:
                        output_error = error
        if message_type == "control-input-request":
            input_request_id = event.get("inputRequestId") if isinstance(event, dict) else None
            if not isinstance(input_request_id, str):
                return
            try:
                if interactive_stdin:
                    line = stdin.readline()
                    if line == "":
                        control.send_stdin(input_request_id, eof=True)
                    else:
                        control.send_stdin(input_request_id, line.rstrip("\n"))
                else:
                    control.send_stdin(input_request_id, eof=True)
            except (OSError, ClientError):
                pass

    try:
        if hasattr(signal, "SIGINT") and threading.current_thread() is threading.main_thread():
            old_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, on_interrupt)
        result = control.operation(
            "emit-ir" if arguments.emit_ir is not None else ("run" if arguments.run else "compile"),
            payload,
            request_id=request_id,
            timeout=BRIDGE_READY_TIMEOUT_SECONDS,
            on_event=on_event,
        )
    except KeyboardInterrupt:
        _print_error("client-cancelled: operation interrupted.", stderr)
        return 130
    except ClientError as error:
        _print_error(f"{error.code}: {error}", stderr)
        return error.exit_code
    finally:
        if old_handler is not None:
            signal.signal(signal.SIGINT, old_handler)
        control.close()

    generated: str | None = None
    compiler_output = result.get("compilerOutput")
    if isinstance(compiler_output, dict) and compiler_output.get("kind") == "python":
        candidate = compiler_output.get("text")
        if isinstance(candidate, str):
            generated = candidate
    # Compile output can arrive in the final RunResult.compilerOutput or as a
    # direct compiler-output event before a long-running run settles.
    if output_error is not None:
        _print_error(f"client-local-file: {output_error}", stderr)
        return CLIENT_EXIT_STATUS
    if output_path is not None and isinstance(generated, str) and result.get("status") != "compile-failure":
        try:
            atomic_write_text(output_path, generated)
        except LocalSnapshotError as error:
            _print_error(f"client-local-file: {error}", stderr)
            return CLIENT_EXIT_STATUS

    final_result = dict(result)
    streamed_out = "".join(streamed_stdout)
    streamed_err = "".join(streamed_stderr)
    final_stdout = result.get("stdout")
    final_stderr = result.get("stderr")
    if isinstance(final_stdout, str):
        final_result["stdout"] = _unstreamed_suffix(final_stdout, streamed_out)
    if isinstance(final_stderr, str):
        final_result["stderr"] = _unstreamed_suffix(final_stderr, streamed_err)
    _render_result(final_result, stdout=stdout, stderr=stderr)
    if interrupted:
        return 130
    return _result_exit_code(result)


def _render_status(status: ClientStatus, stream: TextIO) -> int:
    detail = status.detail
    if status.status == "ready":
        print("Connected", file=stream)
        print("Runtime: ready", file=stream)
        generation = detail.get("workerGeneration", detail.get("generation"))
        if isinstance(generation, int):
            print(f"Worker generation: {generation}", file=stream)
        pyodide = detail.get("pyodideVersion")
        if isinstance(pyodide, str):
            print(f"Pyodide: {pyodide}", file=stream)
        commit = detail.get("compilerCommit", detail.get("klangCommit"))
        if isinstance(commit, str):
            print(f"KLang: {commit}", file=stream)
        return 0
    if status.status == "disconnected":
        print("Disconnected", file=stream)
    elif status.status == "stale":
        print("Stale broker state", file=stream)
    elif status.status == "bootstrap-failed":
        print("Browser bridge bootstrap failed", file=stream)
    else:
        print(f"Runtime: {status.status}", file=stream)
    return CLIENT_EXIT_STATUS


def main(
    argv: Sequence[str] | None = None,
    *,
    manager: BrokerManager | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    stdin: TextIO | None = None,
) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    input_stream = stdin or sys.stdin
    broker_manager = manager or BrokerManager()

    if args and args[0] in {"connect", "status", "disconnect"}:
        command = args[0]
        if len(args) != 1:
            _print_error(usage_text(), err)
            return 2
        try:
            if command == "connect":
                broker_manager.connect()
                _print_error("Connected.", out)
                return 0
            if command == "status":
                status = broker_manager.status()
                return _render_status(status, out)
            broker_manager.disconnect()
            _print_error("Disconnected.", out)
            return 0
        except ClientError as error:
            _print_error(f"{error.code}: {error}", err)
            return error.exit_code

    try:
        compiler_arguments = parse_cli_arguments(args)
    except UsageError as error:
        _print_error(error.usage(), err)
        return error.exit_code
    return execute_compiler(
        compiler_arguments,
        manager=broker_manager,
        stdout=out,
        stderr=err,
        stdin=input_stream,
    )


if __name__ == "__main__":
    raise SystemExit(main())
