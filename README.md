# denycase

Fail-closed Go test helpers for multi-tenant BOLA/IDOR deny cases.

You pass an `http.Handler` and a case that must be denied. If the handler allows the request (or leaks the other tenant's fields), the test fails. There is no network and no policy engine.

```go
denycase.MustDeny(t, denycase.Case{
    Name:      "cross-tenant read",
    Principal: denycase.Principal{Tenant: "B", ID: "user-b"},
    Request:   denycase.Request{Method: http.MethodGet, Path: "/invoices/" + invoiceA},
    Expect:    denycase.Denied(),
}, handler)
```

By default the principal is injected as `X-Denycase-Tenant` and `X-Denycase-Principal`. Both fields are required on that path. Set `ApplyPrincipal` to match how your app actually authenticates.

v0.1 ships the helper and the three case *kinds* (`cross_tenant`, `missing_owner`, `relation_mismatch`). The fixture corpus is still empty.

## Not this project

- Hadrian, Authz0, VardrGate, Autorize: live scanners
- ExploitSpec: YAML replay of a proven HTTP exploit
- Casbin, Cedar, OPA, OpenFGA, SpiceDB, Warden, go-authorization: policy engines

See [COMPARABLES.md](COMPARABLES.md) and [docs/threat-model.md](docs/threat-model.md).

## Status

Pre-corpus skeleton. API may change before `v0.1.0`.

```
go test ./...
```
