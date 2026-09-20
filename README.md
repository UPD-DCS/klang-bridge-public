# KLang native browser bridge

`klangb` is a Python 3.12+ standard-library-only client and local broker for a browser-hosted KLang runtime. The browser compiles and runs programs; the native client does not execute generated Python or send source to a public HTTP server.

This repository is an automatically published installation mirror. Install it directly from GitHub:

```sh
python3 -m pip install "git+https://github.com/UPD-DCS/klang-bridge-public.git"
```

Alternatively, install it with [uv](https://docs.astral.sh/uv/):

```sh
uv tool install "git+https://github.com/UPD-DCS/klang-bridge-public.git"
```

## Use

```sh
klangb connect
klangb status
klangb --dialect func-dynamic program.kl
klangb run --dialect func-hm program.kl
klangb --emit-ir=typed --dialect func-hm program.kl
klangb disconnect
```

`connect` uses `http://127.0.0.1:5174` by default. Set `KLANG_WEB_ORIGIN` to use another compatible browser host:

```sh
KLANG_WEB_ORIGIN=https://klang.example klangb connect
```

Compilation and execution require a compatible browser host. See the [bridge guide](docs/klang-web-bridge.md) for configuration and troubleshooting, the [protocol](docs/bridge-protocol.md) for integration details, and the [compatibility vectors](docs/bridge-protocol-vectors.json) for examples.
