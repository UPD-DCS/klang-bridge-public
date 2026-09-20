# Browser bridge protocol

The browser bridge uses protocol version `1` and a bounded UTF-8 JSON envelope:

```json
{ "protocolVersion": 1, "requestId": "...", "type": "...", "payload": {} }
```

The browser opens `ws://127.0.0.1:<port>` using `port` and the one-time URL-fragment `token` from `/bridge#port=<port>&token=<token>`. The fragment is never sent as an HTTP query parameter.

The connection sequence is:

1. browser sends `handshake` with `client: "klang-web-browser"` and `supportedVersions: [1]`;
2. broker replies `handshake-ack`;
3. browser sends `authenticate` with the fragment token;
4. broker replies `authenticated` and the browser waits for the existing Worker/Pyodide bootstrap;
5. browser sends `ready` with artifact commit/hash, Pyodide version, Worker version, and generation;
6. broker replies `ready-ack` with a `ready` status.

After readiness, the broker sends `compile`, `emit-ir`, `run`, `stdin`, `stop`, `status`, or `dispose` requests. The browser responds with correlated `result` or `error` envelopes. Stream and lifecycle notifications use `output`, `compiler-output`, `stdin-request`, `diagnostic`, `mutation`, `resource-limit`, and `status` messages. Readiness rejects a non-pinned compiler commit, artifact hash/catalog mismatch, incompatible generated contract, missing Pyodide/Worker metadata, or invalid Worker generation metadata.

Messages are rejected for malformed JSON, unknown fields/types, unsupported protocol versions, invalid request IDs, invalid tokens, invalid snapshots, or a payload larger than `1 MiB`. The browser never puts source in a public HTTP request; source is carried only in authenticated loopback bridge messages and then passed to the existing browser Worker lifecycle.
