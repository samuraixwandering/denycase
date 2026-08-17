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
	"slices"
	"strings"
	"testing"
	"unicode"
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

func (p Principal) zero() bool {
	return p.Tenant == "" && p.ID == ""
}

// Request is the HTTP call to run against the handler.
type Request struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// Expect is what a deny looks like. Empty Status defaults to 403.
// Only 4xx codes are allowed; 2xx and 5xx cannot be a deny.
// BodyMustNot fails the test if any substring appears in the raw
// response body or in any response header value.
type Expect struct {
	Status      []int
	BodyMustNot []string
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
	req, err := newTestRequest(c.Request.Method, c.Request.Path, body)
	if err != nil {
		t.Fatalf("denycase: %s: %v", c.Name, err)
		return
	}
	copyHeaders(req.Header, c.Request.Header)
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
		if needle == "" {
			t.Fatalf("denycase: %s: BodyMustNot contains an empty needle", c.Name)
			return
		}
		if bytes.Contains(got, []byte(needle)) {
			t.Fatalf("denycase: %s: response leaked %q", c.Name, needle)
			return
		}
		if headerContains(res.Header, needle) {
			t.Fatalf("denycase: %s: response header leaked %q", c.Name, needle)
			return
		}
	}
}

func newTestRequest(method, path string, body io.Reader) (req *http.Request, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("invalid request %s %s: %v", method, path, rec)
		}
	}()
	return httptest.NewRequest(method, path, body), nil
}

func copyHeaders(dst, src http.Header) {
	if src == nil {
		return
	}
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
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

func headerContains(h http.Header, needle string) bool {
	for _, vs := range h {
		for _, v := range vs {
			if strings.Contains(v, needle) {
				return true
			}
		}
	}
	return false
}

func (c Case) validate() error {
	if c.Name == "" {
		return fmt.Errorf("Name is required")
	}
	if err := validateMethod(c.Request.Method); err != nil {
		return err
	}
	if err := validatePath(c.Request.Path); err != nil {
		return err
	}
	if c.ApplyPrincipal == nil && c.Principal.zero() {
		return fmt.Errorf("Principal.Tenant or Principal.ID is required when ApplyPrincipal is nil")
	}
	for _, s := range c.Expect.Status {
		if s < 400 || s > 499 {
			return fmt.Errorf("Expect.Status %d is not 4xx", s)
		}
	}
	return nil
}

func validateMethod(method string) error {
	if method == "" {
		return fmt.Errorf("Request.Method is required")
	}
	for _, r := range method {
		if unicode.IsSpace(r) {
			return fmt.Errorf("Request.Method %q contains whitespace", method)
		}
	}
	return nil
}

func validatePath(path string) error {
	if path == "" {
		return fmt.Errorf("Request.Path is required")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("Request.Path %q must start with /", path)
	}
	return nil
}

func (e Expect) normalized() Expect {
	out := e
	if len(out.Status) == 0 {
		out.Status = []int{http.StatusForbidden}
		return out
	}
	out.Status = slices.Clone(e.Status)
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
