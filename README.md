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

## Usage

1. `klangb connect` _(wait for the process to exit with `Connected.` message)_
1. _(optional; for troubleshooting)_ `klangb status`
1. `klangb run -d func-dynamic path/to/program.kl` _(while connected)_
1. `klangb disconnect` _(when done)_
```

Alternatively, you may run `klang run ...` directly; `klangb connect` will be executed automatically if the bridge is not yet connected.

Your browser will open a KLang tab upon running `klangb connect` and may display a prompt to allow the site to access local services on your machine; click `Allow` to enable the KLang web IDE to communicate with the local `klangb` process.

Do **not** close the opened KLang tab while you are using `klangb`.
