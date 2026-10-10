# MCP connector audit

Offline audit against the Streamable HTTP and OAuth authorization contracts
described in the brief. No network or hosted-client verification was performed.

| Contract | Baseline | Evidence and gap |
| --- | --- | --- |
| Streamable HTTP POST | Have | `internal/mcpbridge/bridge.go:ServeHTTP`, `handlePOST` handle requests, notifications and JSON responses. `writeMCPResponse` emits finite SSE responses. |
| Optional standalone GET/SSE | Have | `Bridge.ServeHTTP` returns 405 for GET, which is the permitted unsupported-stream response. No unsolicited stream or resumability is implemented. |
| Session IDs | Partial | `validSession` / `ensureSessionID` use one global session, prevent a second legacy client from initializing, and DELETE does not invalidate it. Modern requests in `modern.go:validateProtocolRequest` are sessionless. |
| OAuth 2.1 authorization code with PKCE | Missing | `internal/host/auth.go:getAuthFromTunnelBearer` accepts tunn account and endpoint tokens; GitHub login is upstream identity authentication, not an MCP authorization server. |
| RFC 8414 authorization server metadata | Missing | `internal/host/proxy.go:createHandler` has no OAuth metadata route. |
| RFC 9728 protected resource metadata | Missing | `internal/host/webproxy.go:proxyToLocal` returns a bare bearer challenge without `resource_metadata`. |
| RFC 7591 dynamic client registration | Missing | No remote MCP client registry or registration endpoint exists. |
| Audience-bound access tokens | Partial | `internal/host/metering.go:grantBearer` and `internal/metering/store.go:Resolve` bind manual grants to owner + tunnel. MCP OAuth does not issue them or validate the resource parameter. Account JWTs are broader credentials. |
| Email login + explicit MCP consent | Partial | `internal/host/magiclink.go` implements one-use email login. Its return path is `/account`; no client/tunnel consent exists. |
| Connected-client listing + revocation | Partial | The existing metering API lists/revokes manual grants. No OAuth client identity or consent management exists. |
| Metering + audit | Have | `internal/host/metering.go:ingressMeter` records admission, byte charges and completion in the durable ledger, including rejected requests. |
| CLI connector URL | Partial | `main.go:runMCP` and `internal/client/serve.go` publish `/mcp`, but describe manual token use and require `--` for stdio commands. |

Implementation and verification results will be recorded below as they land.
