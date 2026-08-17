# Comparables

Kill-test: uniqueness dies if a public Go module is importable in `go test`, ships handler-level or httptest DENY fixtures for multi-tenant IDOR/BOLA, does not require adopting that module as the PDP, and is not only a live scanner or YAML-over-HTTP CLI.

Last check: 2026-08-17. Re-run before tagging v0.1.0.

| Project | Job | Kill? |
|---|---|---|
| praetorian-inc/hadrian | Live OpenAPI/role BOLA scanner | No. Network DAST. |
| pazent/exploitspec | YAML HTTP replay of a proven exploit | No. Running target; API is under `internal/`. Re-check at next tag. |
| VardrSec/VardrGate | Live HTTP expected-decision tester | No. `cmd/` against a running API. |
| primeop/Authorization-Testing-Framework | YAML identities over live HTTP | No. Same shape as ExploitSpec. |
| hahwul/authz0, Autorize, OWASP ASTF | Live / Burp BOLA | No. |
| open-policy-agent, openfga, authzed, cerbos, osohq, casbin, cedar-go, xraph/warden | PDP Check/Enforce | No. Deny tests require adopting the engine. |
| faustbrian/go-authorization/authorizationtest | Fixtures for that engine's `Decide()` | No. It is the PDP. |
| dpup/prefab/.../authztest | Generated gRPC demo | No. |
| bartventer/gorm-multitenancy drivertest | DB factory conformance | No. |
| gosec, CodeQL Go, Semgrep CE Go | SAST | No public Get-by-ID-without-tenant rule. Semgrep Pro is not inspectable. |

We are not those projects. Do not add a scan command, a policy language, or a YAML-over-HTTP runner.
