# `klangb` native bridge

`klangb` is a Python 3.12+ standard-library-only native client. It never
runs generated Python and it never uploads source to a public HTTP server. A
persistent per-user broker transfers a bounded source snapshot to an
authenticated compatible browser bridge, where the browser-hosted KLang
compiler and Worker execute it. This repository does not require a KLang-web
checkout or package its browser compiler artifact.

Install an editable checkout with:

```sh
python3 -m pip install -e .
```

The console entry point is `klangb`.

## Commands

```sh
klangb connect
klangb status
klangb disconnect
klangb --dialect func-dynamic program.kl
klangb run --dialect func-hm program.kl
klangb --emit-ir=typed --dialect func-hm program.kl
klangb --run --dialect func-dynamic program.kl -o generated.py
```

The compiler vocabulary is the pinned Stage 2 contract: an explicit `-d` or
`--dialect`, one input path, optional `--run`, one of the three IR modes, and
`-o`/`--output` for generated Python. There is no inferred dialect and no
native compiler fallback. Normal compilation writes the default
`<input-basename>.py` in the current directory; IR never writes a Python file.

`status` reports `ready`, `disconnected`, `stale`, `bootstrapping`, or
`bootstrap-failed`. `connect` is idempotent and opens the configured
`KLANG_WEB_ORIGIN` bridge URL (default `https://klang.upd-dcs.work`) only when a
ready authenticated bridge is not already attached. `disconnect` is an
idempotent best-effort runtime disposal and broker shutdown.

## Local boundary and security

Runtime state defaults to the per-user runtime/state directory and can be
isolated for tests with `KLANG_WEB_RUNTIME_DIR`. An optional `config.ini` in
that directory can set the non-secret origin:

```ini
[bridge]
origin = https://klang.example
```

`KLANG_WEB_ORIGIN` overrides the config file, which overrides the
`https://klang.upd-dcs.work` default. Set either override to
`http://127.0.0.1:5174` for local development. The broker stores its control
secret in a private file, binds both listeners to `127.0.0.1`, and uses a
length-prefixed UTF-8 JSON control channel. The browser side uses a minimal
RFC 6455 text WebSocket channel. It requires:

- exact configured `Origin`;
- protocol version `1`;
- a cryptographically random, one-time fragment bootstrap token sent again in
  the first authenticated JSON message;
- masked client text frames; and
- bounded messages with no negotiated extensions or binary frames; fragmented
  text is accumulated, while invalid/interleaved data fragments are rejected;
  the broker ignores the browser's default permessage-deflate offer and never
  sets RSV bits.

Tokens are not written to state or logs. State files contain endpoint, PID,
protocol, status, generation, and artifact identity only. The browser bridge
must report KLang version `0.3.1`, the pinned commit
`3cb5dba21600302b701640c5554117564632c51c`, the exact artifact hash/size, all
14 dialects (including `lazy`), Worker version, Pyodide version, and generation before operations
are accepted.

## Protocol envelope and vectors

Every message is an object with exactly these fields:

```json
{
  "protocolVersion": 1,
  "requestId": "request-1",
  "type": "control-operation",
  "payload": {
    "operation": "compile",
    "snapshot": { "rootPath": "main.kl", "files": [] },
    "dialect": "func-dynamic"
  }
}
```

The native channel starts with `control-auth` and a private `secret`, followed
by `control-connect`, `control-status`, `control-operation`, `control-stdin`,
`control-stop`, or a lifecycle request. The browser channel starts with
`handshake` (`client: "klang-web-browser"`, `supportedVersions: [1]`), receives
`handshake-ack`, sends `authenticate`, receives `authenticated`, sends `ready`,
and receives `ready-ack`. Handshake/token authentication uses a short timeout;
cold Worker/Pyodide readiness is allowed up to 120 seconds. After readiness,
broker requests use direct
`compile`, `emit-ir`, `run`, `stdin`, `stop`, `status`, and `dispose` types.
Results use correlated `result` payloads with `{operation,result}`; stream and
lifecycle events use direct `output`, `compiler-output`, `stdin-request`,
`diagnostic`, `mutation`, `resource-limit`, `status`, and `error` messages.
The `compiler-output` event carries `{output:{kind:"python"|"ir",mode?,text}}`,
and final `RunResult.compilerOutput` is authoritative. Native control frames
are capped at 4 MiB and browser messages at 1 MiB. A Python compiler-output
event lets the native client atomically write `--run -o` output before a long
run settles. Unknown envelope fields/types, duplicate JSON keys, invalid
UTF-8, non-finite numbers, version mismatches, and oversized frames are
rejected.

Client failures use a separate `client-*`/`bridge-*` namespace and exit status
`3`; KLang compile/runtime outcomes retain their own result status and exit
code. A first SIGINT requests browser Stop and returns `130` after settlement;
the broker remains alive.
