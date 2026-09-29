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
klangb connect --manual
klangb status
klangb --dialect func-dynamic program.kl
klangb --dialect pure-dynamic program.kl
klangb run --dialect pure-hm program.kl
klangb --emit-ir=typed --dialect func-hm program.kl
klangb disconnect
```

`connect` uses `https://klang.upd-dcs.work` by default. Use
`klangb connect --manual` to print the one-time bridge URL instead of opening a
browser automatically; the command waits for you to open that URL and for the
bridge to become ready. Set `KLANG_BRIDGE_ORIGIN` to use another compatible browser
host, including the local server for development:

```sh
KLANG_BRIDGE_ORIGIN=https://klang.example klangb connect
```

A `run` command automatically connects to a compatible browser host when needed; ordinary compilation still requires an existing connection. Browser compatibility follows protocol version and required compiler capabilities, so KLang and Pyodide upgrades do not require a lockstep `klangb` release. Exact runtime provenance remains available through `klangb status` for diagnostics.

See the [bridge guide](docs/klang-bridge.md) for configuration and troubleshooting, the [protocol](docs/bridge-protocol.md) for integration details, and the [compatibility vectors](docs/bridge-protocol-vectors.json) for examples.
