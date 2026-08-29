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

`Request.Method` must be an RFC 9110 method (`GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `CONNECT`, `OPTIONS`, `TRACE`, `PATCH`), exact case. Paths may contain non-ASCII. Spaces, controls, non-printable runes, default-ignorable characters, and U+2800 are rejected. That includes ZERO WIDTH JOINER and variation selectors (U+FE0F), so multi-person emoji and the ordinary emoji-style heart (U+2764 U+FE0F) are rejected even when the rest of the path is valid; percent-encode them. A principal may contain internal spaces (`Acme Corp`).

`Corpus()` returns five `Fixture` values against a toy invoice (`inv-a` owned by `tenant-A` / `user-a`): `cross_tenant` GET and PUT, `missing_owner` GET with a colliding owner id (tenant-B / `user-a`), and `relation_mismatch` same-tenant non-owner GET and PUT. Copy a case and change Principal, Path, `BodyMustNot`, and `HeaderMustNot` to match your handler. On writes, set Body and Header too. Set Status if your handler denies with 404. Reads are owner-scoped.

## Breaking before v0.1.0

These used to be valid cases and now fail:

- `Corpus` as an exported variable; it is now the function `Corpus()`
- `HeaderMustNot` without `BodyMustNot`
- `ApplyPrincipal` set and a zero or blank `Principal`
- `ApplyPrincipal` that does not change Header, URL, Host, or Context
- `Request.Method` that is not an RFC 9110 method (`get`, `GETT`, WebDAV, …)
- `Request.Path` containing a space, control, or invisible character; `Principal` with leading/trailing whitespace or an invisible rune
- `Request.Header` names that are not RFC 7230 tokens
- `BodyMustNot` set with a non-identity `Content-Encoding` or a non-`chunked`/`identity` `Transfer-Encoding`

These used to fail and now pass unless you list the header in `HeaderMustNot`:

- A leak only in `ETag`, `Link`, `Refresh`, `WWW-Authenticate`, or `X-Accel-Redirect` (not in the default scan list)
- A leak only in a response header *name* (names are never scanned)
- A case-folded leak (`TENANT-A` vs needle `tenant-A`); matching is byte-exact
- A header set after `WriteHeader` with no `Trailer` declaration (not on the wire)

## Not this project

- Hadrian, Authz0, VardrGate, Autorize: live scanners
- ExploitSpec: YAML replay of a proven HTTP exploit
- Casbin, Cedar, OPA, OpenFGA, SpiceDB, Warden, go-authorization: policy engines

See [COMPARABLES.md](COMPARABLES.md) and [docs/threat-model.md](docs/threat-model.md).

## Status

Helper plus a small fixture pack. API may change before `v0.1.0`.

```
go test ./...
```
