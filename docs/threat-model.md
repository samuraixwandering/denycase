# Threat model (v0.1)

Scope: a Go test helper that runs deny cases against an in-process `http.Handler`.
Date: 2026-08-18.

## Assets

- The application's object-level authorization: tenant A must not read, write, or list tenant B's objects.
- The test's fail-closed property: a passing test must not mean "we did not notice an allow."

## Actors

- **App author** writing `go test` beside a handler. Trusted to point denycase at their own handler.
- **CI** running those tests. No network.
- **Contributor** adding fixtures later. Not trusted to add live targets or exploit payloads.

## In-scope failures (what MustDeny is for)

1. **Cross-tenant IDOR / BOLA (CWE-639).** Caller swaps an object id (or tenant id) and the handler returns another tenant's record.
2. **Missing owner / tenant predicate (CWE-862).** Handler loads by request id with no owner or tenant check.
3. **Relation mismatch.** Principal is in the right tenant but is not allowed this action on this object (wrong role, not owner, not member).

JWT metadata (`alg=none`, algorithm confusion) is noted for later. It is not in v0.1.

## Out of scope

- Finding bugs on a running URL (Hadrian, Authz0, VardrGate, Autorize).
- Replaying a proven HTTP exploit as YAML (ExploitSpec).
- Being the app's policy engine (Casbin, Cedar, OPA, OpenFGA, SpiceDB, Warden, go-authorization).
- Authenticating the principal. denycase only *labels* the request (default headers or `ApplyPrincipal`).
- Third-party scanning, exploit payloads, or using GitHub as attack infrastructure.

## Trust boundary

`MustDeny` is called from a test. The handler and the Case are both supplied by the test author. There is no parser of untrusted fixture files in v0.1. When a file corpus lands, treat fixture files as test data from the same repo, not as input from the internet.

## Fail-closed rules

- Default expect is HTTP 403.
- `Expect.Status` may only be 403 or 404. 401, 429, 2xx, and 5xx in that list are invalid.
- A 2xx or 5xx response fails the test.
- 404 fails unless the case lists 404 in `Expect.Status`. There is no hide-existence helper yet; 403 vs 404 as an enumeration oracle is not tested.
- If `BodyMustNot` is set, a deny that still contains a foreign field in the raw body fails (byte-exact). The same needles are checked in the *values* of Location, Content-Location, Content-Disposition, and Set-Cookie (headers and trailers). Those four are the only defaults. Every other response header is unscanned unless listed in `HeaderMustNot`.
- `HeaderMustNot` is a list of header names, not needles. It requires `BodyMustNot`. Names must be RFC 7230 tokens. Header *names* on the response are never scanned; a leak that exists only as a name (`X-Tenant-A-Region`) is not expressible. A listed name that is absent from the response is a no-op: the check does not run and the test does not fail.
- An empty needle or empty / non-token `HeaderMustNot` name is invalid.
- Byte-exact also applies to the four default headers. Percent-encoding (`tenant%2DA`), `filename*`, and `http.SetCookie` sanitizing are not decoded. Short needles can match structured values such as a `Set-Cookie` `Expires` date.
- `httptest` and the HTTP server drop forbidden trailer names (`Content-Type`, `Cache-Control`, `Authorization`, …). Those are not scanned as trailers. The same name set via `http.TrailerPrefix` is scanned.
- Header leaks are checked on the flushed wire snapshot (`Result().Header`). Trailer leaks are checked on declared / `Trailer:`-prefixed late writes and on `Result().Trailer`. A name that leaks in both is reported once, as a header. Post-commit non-trailer header mutations are ignored. The body is always scanned as raw bytes. If an encoding gate also fires, the encoding line is listed first, then any body hits, then headers/trailers.
- If `BodyMustNot` is set and any `Content-Encoding` or `Transfer-Encoding` token on the wire header, or on a `Trailer:`-prefixed key, is not identity/`chunked` as required, the test fails. A declared `Trailer: Content-Encoding` or `Trailer: Transfer-Encoding` is dropped by httptest (`badTrailer`); the prefix is the only trailer route for those names. The library does not decode gzip. JSON `\u003c` / `\u003e` / `\u0026` are not unescaped; needles must match the bytes the handler wrote.
- `Principal.Tenant` and `Principal.ID` are always required, including when `ApplyPrincipal` is set. Leading or trailing whitespace, C0/DEL, non-printable runes, default-ignorable code points, and U+2800 are rejected. Internal spaces (`Acme Corp`) are allowed. Anonymous deny is out of scope (authn, not BOLA).
- `ApplyPrincipal` is compared on Header, URL, Host, and Context only. Everything else is ignored. A no-op, a write to a cloned request, or `Set` of a value already on the request is invalid; put a preset auth header in one place only.
- `Request.Method` must be an RFC 9110 method, exact case. `Request.Path` may be non-ASCII; space, C0/DEL, invalid UTF-8, non-printable runes, default-ignorable code points, and U+2800 are rejected. Encode spaces as `%20`. `Request.Header` names must be RFC 7230 tokens. Request header *values* are not validated.

## Residual risk

- Default header injection (`X-Denycase-Tenant`) is not real auth. Tests that forget `ApplyPrincipal` only prove the handler reads those headers.
- A handler that returns 403 with an empty body but still performed the write is not caught in v0.1 (no mutation verify).
- An empty `Corpus` means authors must write their own cases until the fixture pack exists.
- A compressed body is scanned as raw bytes. A leak that exists only after decompression is not detected.
- `ApplyPrincipal` that sets a typo'd auth header still mutates the request, so the case can pass on an anonymous 403. denycase cannot know the app's auth header. Setting `TLS` or `RemoteAddr` only is treated as a no-op.
- Only Location, Content-Location, Content-Disposition, and Set-Cookie are scanned by default. `ETag`, `Link`, `Refresh`, `WWW-Authenticate`, `X-Accel-Redirect`, `X-Owner`, and every other header are unscanned unless listed in `HeaderMustNot`.
- A leak that exists only as a header name is not expressible. `HeaderMustNot` still only reads values. A typo in a listed name (`X-Ownr`, or a needle used as a name) scans nothing and the test stays green.
- A handler panic is a failed test, not a silent allow. `MustDeny` does not recover: `testing` repanics, the process exits, later cases in the same run do not execute, and `Case.Name` is not in the output.
- A wrong-but-legal method (`POST` on a GET-only handler) is still a vacuous 403. denycase does not pair the deny with an allow request.
