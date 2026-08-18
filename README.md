# denycase

Fail-closed Go test helpers for multi-tenant BOLA/IDOR deny cases.

You pass an `http.Handler` and a case that must be denied. If the handler allows the request, the test fails. `BodyMustNot` is optional: those bytes must not appear in the body or in Location, Content-Location, Content-Disposition, or Set-Cookie. Other response headers are not scanned unless you list their names in `HeaderMustNot`. There is no network and no policy engine.

```go
denycase.MustDeny(t, denycase.Case{
    Name:      "cross-tenant read",
    Principal: denycase.Principal{Tenant: "B", ID: "user-b"},
    Request:   denycase.Request{Method: http.MethodGet, Path: "/invoices/" + invoiceA},
    Expect:    denycase.Denied(),
}, handler)
```

By default the principal is injected as `X-Denycase-Tenant` and `X-Denycase-Principal`. `Principal.Tenant` and `Principal.ID` are always required, including when you set `ApplyPrincipal`. `ApplyPrincipal` must change Header, URL, Host, or Context. If `Request.Header` already has the value the callback would write, put that value in one place only.

`BodyMustNot` is matched byte-exact in the response body and in the values of Location / Content-Location / Content-Disposition / Set-Cookie. `HeaderMustNot` is extra header *names* (not needles) to scan for those same bytes. It requires `BodyMustNot`. A listed name that is not on the response is a no-op. Percent-encoding is not decoded.

`Request.Method` must be an RFC 9110 method (`GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `CONNECT`, `OPTIONS`, `TRACE`, `PATCH`), exact case. Paths may contain non-ASCII. Spaces, controls, non-printable runes (NBSP, NEL), and a few invisible letter fillers are rejected. Encode spaces as `%20`.

v0.1 ships the helper and the three case *kinds* (`cross_tenant`, `missing_owner`, `relation_mismatch`). The fixture corpus is still empty.

## Breaking before v0.1.0

These used to be valid cases and now fail:

- `HeaderMustNot` without `BodyMustNot`
- `ApplyPrincipal` set and a zero or blank `Principal`
- `ApplyPrincipal` that does not change Header, URL, Host, or Context
- `Request.Method` that is not an RFC 9110 method (`get`, `GETT`, WebDAV, …)
- `Request.Path` or `Principal` containing a space, control, or invisible character
- `Request.Header` names that are not RFC 7230 tokens
- `BodyMustNot` set with a non-identity `Content-Encoding` or a non-`chunked`/`identity` `Transfer-Encoding`

These used to fail and now pass unless you list the header in `HeaderMustNot`:

- A leak only in `ETag` or `Link` (dropped from the default scan list)
- A leak only in a response header *name* (names are never scanned)

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
