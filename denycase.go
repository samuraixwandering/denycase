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

// leakHeaderNames are response headers whose values are scanned for BodyMustNot.
// Content-Type and other stdlib defaults are not in this list.
var leakHeaderNames = []string{
	"Location",
	"Content-Location",
	"ETag",
	"Link",
}

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
// Status may only be 403 or 404. BodyMustNot fails the test if any
// substring appears in the raw response body, in the values of
// Location / Content-Location / ETag / Link (headers or trailers),
// or in any header or trailer name.
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
	// sets HeaderTenant and HeaderPrincipal and requires both Principal
	// fields. Wire this to your real auth (session, JWT, context) in
	// application tests.
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
	if len(exp.BodyMustNot) > 0 {
		if enc := res.Header.Get("Content-Encoding"); encodedBody(enc) {
			t.Fatalf("denycase: %s: BodyMustNot set but Content-Encoding is %q", c.Name, enc)
			return
		}
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
		if leakContains(res.Header, res.Trailer, needle) {
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
	req.Header.Set(HeaderTenant, p.Tenant)
	req.Header.Set(HeaderPrincipal, p.ID)
}

func encodedBody(enc string) bool {
	return enc != "" && !strings.EqualFold(enc, "identity")
}

func leakContains(headers, trailers http.Header, needle string) bool {
	if namesContain(headers, needle) || namesContain(trailers, needle) {
		return true
	}
	if valuesContain(trailers, needle) {
		return true
	}
	for _, name := range leakHeaderNames {
		for _, v := range headers.Values(name) {
			if strings.Contains(v, needle) {
				return true
			}
		}
		for _, v := range trailers.Values(name) {
			if strings.Contains(v, needle) {
				return true
			}
		}
	}
	return false
}

func namesContain(h http.Header, needle string) bool {
	for name := range h {
		if strings.Contains(name, needle) {
			return true
		}
	}
	return false
}

func valuesContain(h http.Header, needle string) bool {
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
	if err := validateRequestHeaders(c.Request.Header); err != nil {
		return err
	}
	if c.ApplyPrincipal == nil {
		if c.Principal.Tenant == "" || c.Principal.ID == "" {
			return fmt.Errorf("Principal.Tenant and Principal.ID are required when ApplyPrincipal is nil")
		}
	}
	for _, s := range c.Expect.Status {
		if !allowedDenyStatus(s) {
			return fmt.Errorf("Expect.Status %d is not 403 or 404", s)
		}
	}
	return nil
}

func validateRequestHeaders(h http.Header) error {
	if h == nil {
		return nil
	}
	seen := make(map[string]string, len(h))
	for k := range h {
		can := http.CanonicalHeaderKey(k)
		if prev, ok := seen[can]; ok && prev != k {
			return fmt.Errorf("Request.Header has duplicate keys %q and %q", prev, k)
		}
		seen[can] = k
	}
	return nil
}

func allowedDenyStatus(s int) bool {
	return s == http.StatusForbidden || s == http.StatusNotFound
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
