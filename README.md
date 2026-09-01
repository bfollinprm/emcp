# emcp — an MCP client for Emacs with HTTPS + OAuth 2.1

A Model Context Protocol client targeting spec revision **2026-07-28**
natively, with fallback to the initialize-handshake eras
(2025-11-25 / 2025-06-18 / 2025-03-26) and the deprecated 2024-11-05
HTTP+SSE transport.

HTTP runs over a curl subprocess per request, so HTTPS uses the system
trust store, HTTP/2 works, and cancelling a request is killing its
process — which is exactly the Streamable HTTP cancellation signal
(closing the response stream).

## Requirements

- Emacs 29.1+ (built-in `json-parse-string`, `string-search`)
- `curl` on PATH (present by default on macOS and most Linux distros)

## Usage

```elisp
(require 'emcp)

;; HTTPS server with OAuth (the browser flow runs automatically on 401):
(setq conn (emcp-connect :name "github" :url "https://api.example.com/mcp"))

;; Static bearer token instead of OAuth:
(setq conn (emcp-connect :url "https://mcp.example.com/mcp"
                         :auth-token (lambda () (my-fetch-token))))

;; stdio server:
(setq conn (emcp-connect :name "fs" :command "mcp-server-filesystem"
                         :args '("/tmp") :roots '("/tmp")))

(emcp-tools-list conn)
(emcp-tools-call conn "get_weather" '((location . "Seattle, WA")))
(emcp-prompts-list conn)
(emcp-resources-read conn "file:///etc/hosts")
(emcp-close conn)
```

Handlers for server-initiated interactions (delivered as MRTR
`input_required` results on modern servers, or JSON-RPC requests on
legacy ones):

```elisp
(emcp-connect
 :url "https://mcp.example.com/mcp"
 :elicitation-handler (lambda (conn params) ...)   ; return ElicitResult alist
 :sampling-handler    (lambda (conn params) ...)   ; return CreateMessageResult
 :on-notification     (lambda (method params) ...))
```

OAuth configuration is optional; with none, the client discovers
everything and uses Dynamic Client Registration:

```elisp
:oauth (:client-id "pre-registered-id"        ; optional
        :client-secret "..."                  ; optional
        :client-metadata-url "https://me.example/client.json" ; CIMD
        :scopes "files:read"                  ; optional
        :issuer "https://as.example.com")     ; pin one of the offered ASes
```

## Spec compliance (client requirements, 2026-07-28)

| Area | Status |
|---|---|
| Streamable HTTP: per-request POST, `Accept` both types, JSON + SSE responses | ✅ |
| `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` headers | ✅ |
| `Mcp-Name`/`Mcp-Param-*` Base64 sentinel value encoding | ✅ |
| `x-mcp-header` mirroring; invalid tool definitions rejected from `tools/list` | ✅ |
| `HeaderMismatch` (-32020) → refresh `tools/list`, retry once | ✅ |
| Stateless `_meta` (protocolVersion / clientInfo / clientCapabilities) | ✅ |
| `server/discover` probe + era detection (modern → initialize → HTTP+SSE) | ✅ |
| MRTR: `input_required`, `inputRequests` fulfilment, `requestState` echo, fresh ids | ✅ |
| `resultType` absent (legacy) treated as `"complete"` | ✅ |
| Cancellation by closing the request stream (kill the returned process) | ✅ |
| `subscriptions/listen` long-lived stream | ⚠️ implemented; opt-in params shape is best-effort against the published schema |
| Legacy sessions (`Mcp-Session-Id`, DELETE on close) | ✅ |
| 2024-11-05 HTTP+SSE fallback (`endpoint` event, POST + global stream) | ⚠️ implemented, unit-tested pieces; no end-to-end test |
| SSE resumability (`Last-Event-ID`) | n/a (removed in 2026-07-28) |
| Roots / Sampling / Logging | supported for legacy servers; deprecated in 2026-07-28 |

## OAuth 2.1 compliance

| Requirement | Status |
|---|---|
| 401 → `WWW-Authenticate` parsing; well-known PRM fallback (path form, then root) | ✅ |
| RFC 8414 + OIDC discovery, path-insertion before path-appending, issuer validation | ✅ |
| PKCE S256 (verifier from /dev/urandom) | ✅ |
| `resource` (RFC 8707) on authorization and token requests, canonical URI | ✅ |
| `iss` validation (RFC 9207) before code redemption, exact string compare | ✅ |
| `state` parameter | ✅ |
| Loopback redirect listener on 127.0.0.1 (RFC 8252) | ✅ |
| Client ID Metadata Documents (`:client-metadata-url`) / pre-registered / DCR with `application_type: native` | ✅ |
| Credentials keyed per issuer; tokens keyed per canonical resource | ✅ |
| Refresh tokens (with `resource`), expiry slack, refresh-token retention | ✅ |
| Step-up on 403 `insufficient_scope` with scope union, bounded retries | ✅ |
| Bearer token only in the `Authorization` header, never in URLs | ✅ |

Token storage: `~/.emacs.d/emcp-oauth.plstore`, created `0600`,
unencrypted by default. Set `emcp-oauth-use-secret-storage` to `t`
(and configure `plstore-encrypt-to`) for GPG-encrypted storage.

## Development

```
make compile      # byte-compile with warnings-as-errors
make unit         # pure-function tests (PKCE vectors, header encoding, SSE, schema walking, ...)
make integration  # end-to-end against an in-Emacs fake HTTP server and a Python stdio server
make test         # both
```

The integration suite exercises: modern happy path with header
mirroring asserted on the wire, MRTR round trip with `requestState`
echo, legacy initialize fallback with session headers, the complete
OAuth flow (PRM discovery → AS metadata → DCR → PKCE → loopback
redirect → token exchange → authenticated retry → persisted tokens),
and both stdio eras.

## Known limitations

- `subscriptions/listen` opt-in parameter shape and the modern
  `clientCapabilities` key set are written against the spec prose, not
  the JSON schema; verify against a real 2026-07-28 server.
- The 2024-11-05 HTTP+SSE fallback lacks an end-to-end test.
- No `tasks` extension, no OpenTelemetry `_meta` propagation, no
  `ttlMs`/`cacheScope` caching (clients MAY cache; we refetch).
- Elicitation URL mode is handled via `browse-url` + confirm only.
- Dynamically registered clients pin the loopback redirect port from
  the first authorization; ASes that ignore RFC 8252 §7.3 (variable
  loopback ports) may reject later re-authorizations. Delete the
  `client:<issuer>` entry from the plstore to re-register.
- The process handle returned by `emcp-request-async` is the initial
  request; if an OAuth retry replaces it, killing the original handle
  no longer cancels the live request.

## License

GPL-3.0-or-later.
