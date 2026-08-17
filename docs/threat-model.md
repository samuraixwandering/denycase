# Threat model (v0.1)

Scope: a Go test helper that runs deny cases against an in-process `http.Handler`.
Date: 2026-08-17.

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
- 2xx is a failed test.
- 5xx is a failed test (the handler did not deny; it broke).
- 404 is a failed test unless `Expect.HideExistence` is set.
- If `BodyMustNot` is set, a 403 that still contains a foreign field fails.

## Residual risk

- Default header injection (`X-Denycase-Tenant`) is not real auth. Tests that forget `ApplyPrincipal` only prove the handler reads those headers.
- A handler that returns 403 with an empty body but still performed the write is not caught in v0.1 (no mutation verify).
- An empty `Corpus` means authors must write their own cases until the fixture pack exists.
