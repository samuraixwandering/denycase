// Package denycase is a fail-closed helper for multi-tenant BOLA/IDOR tests.
//
// It is not a scanner and not a policy engine. You pass an http.Handler
// (usually from httptest) and a Case that must be denied. If the handler
// allows the request, the test fails.
package denycase

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	// HeaderTenant is the default tenant injection header.
	HeaderTenant = "X-Denycase-Tenant"
	// HeaderPrincipal is the default principal-id injection header.
	HeaderPrincipal = "X-Denycase-Principal"
)

// Kind names a shipped deny situation. The corpus itself is still empty.
type Kind string

const (
	KindCrossTenant      Kind = "cross_tenant"
	KindMissingOwner     Kind = "missing_owner"
	KindRelationMismatch Kind = "relation_mismatch"
)

// Principal is who the request claims to be. denycase does not authenticate.
type Principal struct {
	Tenant string
	ID     string
}

// Request is the HTTP call to run against the handler.
type Request struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// Expect is what a deny looks like. Empty Status defaults to 403.
// HideExistence also accepts 404. BodyMustNot fails the test if any
// substring appears in the response (foreign object fields, other tenant ids).
type Expect struct {
	Status        []int
	HideExistence bool
	BodyMustNot   []string
}

// Denied is the default expect: HTTP 403.
func Denied() Expect {
	return Expect{Status: []int{http.StatusForbidden}}
}

// Case is one deny scenario.
type Case struct {
	Name      string
	Principal Principal
	Request   Request
	Expect    Expect
	// ApplyPrincipal writes the principal onto the request. If nil, denycase
	// sets HeaderTenant and HeaderPrincipal. Wire this to your real auth
	// (session, JWT, context) in application tests.
	ApplyPrincipal func(*http.Request, Principal)
}

// Fixture is a named deny situation plus its Case. Week 1 ships the type only.
type Fixture struct {
	Kind Kind
	Case Case
}

// Corpus is the shipped deny cases. Empty until the fixture pack lands.
var Corpus []Fixture

// MustDeny runs c against h and fails t if the handler does not deny.
func MustDeny(t testing.TB, c Case, h http.Handler) {
	t.Helper()
	if err := c.validate(); err != nil {
		t.Fatalf("denycase: invalid case: %v", err)
		return
	}
	if h == nil {
		t.Fatal("denycase: handler is nil")
		return
	}

	exp := c.Expect.normalized()

	var body io.Reader
	if len(c.Request.Body) > 0 {
		body = bytes.NewReader(c.Request.Body)
	}
	req := httptest.NewRequest(c.Request.Method, c.Request.Path, body)
	if c.Request.Header != nil {
		req.Header = c.Request.Header.Clone()
	}
	if c.ApplyPrincipal != nil {
		c.ApplyPrincipal(req, c.Principal)
	} else {
		applyDefaultPrincipal(req, c.Principal)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("denycase: read body: %v", err)
		return
	}

	if !containsStatus(exp.Status, res.StatusCode) {
		t.Fatalf("denycase: %s: status %d, want one of %v (fail closed)", c.Name, res.StatusCode, exp.Status)
		return
	}
	for _, needle := range exp.BodyMustNot {
		if needle != "" && bytes.Contains(got, []byte(needle)) {
			t.Fatalf("denycase: %s: response leaked %q", c.Name, needle)
			return
		}
	}
}

func applyDefaultPrincipal(req *http.Request, p Principal) {
	if p.Tenant != "" {
		req.Header.Set(HeaderTenant, p.Tenant)
	}
	if p.ID != "" {
		req.Header.Set(HeaderPrincipal, p.ID)
	}
}

func (c Case) validate() error {
	if c.Name == "" {
		return fmt.Errorf("Name is required")
	}
	if c.Request.Method == "" {
		return fmt.Errorf("Request.Method is required")
	}
	if c.Request.Path == "" {
		return fmt.Errorf("Request.Path is required")
	}
	return nil
}

func (e Expect) normalized() Expect {
	out := e
	if len(out.Status) == 0 {
		out.Status = []int{http.StatusForbidden}
	}
	if out.HideExistence && !containsStatus(out.Status, http.StatusNotFound) {
		out.Status = append(out.Status, http.StatusNotFound)
	}
	return out
}

func containsStatus(have []int, want int) bool {
	for _, s := range have {
		if s == want {
			return true
		}
	}
	return false
}
