// Package denycase is a fail-closed helper for multi-tenant BOLA/IDOR tests.
//
// It is not a scanner and not a policy engine. You pass an http.Handler
// (usually from httptest) and a Case that must be denied. If the handler
// allows the request, the test fails.
package denycase

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const (
	// HeaderTenant is the default tenant injection header.
	HeaderTenant = "X-Denycase-Tenant"
	// HeaderPrincipal is the default principal-id injection header.
	HeaderPrincipal = "X-Denycase-Principal"
)

// defaultLeakHeaders are response headers whose values are scanned for
// BodyMustNot needles when BodyMustNot is set. They are specified to
// carry a resource identity (redirect, filename, cookie). Every other
// response header is unscanned unless listed in Expect.HeaderMustNot.
var defaultLeakHeaders = []string{
	"Location",
	"Content-Location",
	"Content-Disposition",
	"Set-Cookie",
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
// Status may only be 403 or 404.
type Expect struct {
	Status []int
	// BodyMustNot is a list of substrings that must not appear in the
	// raw response body (byte-exact). The same needles are checked in
	// the values of Location, Content-Location, Content-Disposition,
	// and Set-Cookie (headers and trailers). Percent-encoding and
	// cookie sanitizing are not decoded.
	BodyMustNot []string
	// HeaderMustNot is extra response header names whose values are
	// scanned for BodyMustNot needles. It is not a list of needles
	// and it requires BodyMustNot. Names must be valid header tokens.
	HeaderMustNot []string
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
	// sets HeaderTenant and HeaderPrincipal. Principal.Tenant and
	// Principal.ID are always required. Wire this to your real auth
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
	headerNames := leakNames(exp.HeaderMustNot)

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

	if !slices.Contains(exp.Status, res.StatusCode) {
		t.Fatalf("denycase: %s: status %d, want one of %v (fail closed)", c.Name, res.StatusCode, exp.Status)
		return
	}
	for _, needle := range exp.BodyMustNot {
		if name, ok := valuesContain(res.Header, headerNames, needle); ok {
			t.Fatalf("denycase: %s: response header %s leaked %q", c.Name, name, needle)
			return
		}
		if name, ok := valuesContain(res.Trailer, headerNames, needle); ok {
			t.Fatalf("denycase: %s: response trailer %s leaked %q", c.Name, name, needle)
			return
		}
	}
	if len(exp.BodyMustNot) > 0 {
		if enc, ok := nonIdentityEncoding(res.Header); ok {
			t.Fatalf("denycase: %s: BodyMustNot set but Content-Encoding is %q", c.Name, enc)
			return
		}
	}
	for _, needle := range exp.BodyMustNot {
		if bytes.Contains(got, []byte(needle)) {
			t.Fatalf("denycase: %s: response leaked %q", c.Name, needle)
			return
		}
	}
}

func newTestRequest(method, path string, body io.Reader) (req *http.Request, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("invalid request %q %q: %v", method, path, rec)
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

func nonIdentityEncoding(h http.Header) (string, bool) {
	for k, vs := range h {
		if http.CanonicalHeaderKey(k) != "Content-Encoding" {
			continue
		}
		for _, v := range vs {
			if v != "" && !strings.EqualFold(v, "identity") {
				return v, true
			}
		}
	}
	return "", false
}

func leakNames(extra []string) []string {
	return append(append([]string(nil), defaultLeakHeaders...), extra...)
}

// valuesContain reports whether any header in names has a value containing
// needle. It ranges the map so a non-canonical key still matches. The
// returned name is the matching map keys as written, sorted.
// httptest.Result builds trailers with canonical keys, so non-canonical
// trailer keys do not occur there.
func valuesContain(h http.Header, names []string, needle string) (string, bool) {
	want := make(map[string]struct{}, len(names))
	for _, n := range names {
		want[http.CanonicalHeaderKey(n)] = struct{}{}
	}
	var hits []string
	for k, vs := range h {
		if _, ok := want[http.CanonicalHeaderKey(k)]; !ok {
			continue
		}
		for _, v := range vs {
			if strings.Contains(v, needle) {
				hits = append(hits, k)
				break
			}
		}
	}
	if len(hits) == 0 {
		return "", false
	}
	slices.Sort(hits)
	return strings.Join(hits, ", "), true
}

func (c Case) validate() error {
	if c.Name == "" {
		return errors.New("Name is required")
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
	if c.Principal.Tenant == "" || c.Principal.ID == "" {
		return errors.New("Principal.Tenant and Principal.ID are required")
	}
	for _, s := range c.Expect.Status {
		if s != http.StatusForbidden && s != http.StatusNotFound {
			return fmt.Errorf("Expect.Status %d is not 403 or 404", s)
		}
	}
	for _, needle := range c.Expect.BodyMustNot {
		if needle == "" {
			return errors.New("BodyMustNot contains an empty needle")
		}
	}
	for _, name := range c.Expect.HeaderMustNot {
		if err := validateHeaderName(name); err != nil {
			return err
		}
	}
	if len(c.Expect.HeaderMustNot) > 0 && len(c.Expect.BodyMustNot) == 0 {
		return errors.New("HeaderMustNot requires BodyMustNot")
	}
	return nil
}

func validateRequestHeaders(h http.Header) error {
	if h == nil {
		return nil
	}
	seen := make(map[string]string, len(h))
	for k := range h {
		if !validHeaderToken(k) {
			return fmt.Errorf("Request.Header name %q is not a valid header token", k)
		}
		can := http.CanonicalHeaderKey(k)
		if prev, ok := seen[can]; ok {
			keys := []string{prev, k}
			slices.Sort(keys)
			return fmt.Errorf("Request.Header has duplicate keys %q and %q", keys[0], keys[1])
		}
		seen[can] = k
	}
	return nil
}

func validateMethod(method string) error {
	if method == "" {
		return errors.New("Request.Method is required")
	}
	if !validHeaderToken(method) {
		return fmt.Errorf("Request.Method %q is not a valid token", method)
	}
	return nil
}

func validatePath(path string) error {
	if path == "" {
		return errors.New("Request.Path is required")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("Request.Path %q must start with /", path)
	}
	if !printableASCII(path) {
		return fmt.Errorf("Request.Path %q contains a non-printable ASCII byte", path)
	}
	return nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

func validateHeaderName(name string) error {
	if name == "" {
		return errors.New("HeaderMustNot contains an empty name")
	}
	if !validHeaderToken(name) {
		return fmt.Errorf("HeaderMustNot name %q is not a valid header token", name)
	}
	return nil
}

// validHeaderToken reports whether s is an RFC 7230 token (tchar only).
func validHeaderToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
			c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
			c == '^' || c == '_' || c == '`' || c == '|' || c == '~':
		default:
			return false
		}
	}
	return true
}

func (e Expect) normalized() Expect {
	out := e
	out.Status = slices.Clone(e.Status)
	out.BodyMustNot = slices.Clone(e.BodyMustNot)
	out.HeaderMustNot = slices.Clone(e.HeaderMustNot)
	if len(out.Status) == 0 {
		out.Status = []int{http.StatusForbidden}
	}
	return out
}
