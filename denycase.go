// Package denycase is a fail-closed helper for multi-tenant BOLA/IDOR tests.
//
// It is not a scanner and not a policy engine. You pass an http.Handler
// (usually from httptest) and a Case that must be denied. If the handler
// allows the request, the test fails.
package denycase

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
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

// rfc9110Methods is the RFC 9110 method set, case-sensitive.
var rfc9110Methods = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodHead:    {},
	http.MethodPost:    {},
	http.MethodPut:     {},
	http.MethodDelete:  {},
	http.MethodConnect: {},
	http.MethodOptions: {},
	http.MethodTrace:   {},
	http.MethodPatch:   {},
}

var compressedTE = map[string]struct{}{
	"gzip":     {},
	"deflate":  {},
	"compress": {},
	"br":       {},
	"zstd":     {},
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
	// sets HeaderTenant and HeaderPrincipal. The callback must modify the
	// request (headers, URL, Host, or Context). Principal.Tenant and
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
		t.Fatalf("denycase: %q: %v", c.Name, err)
		return
	}
	copyHeaders(req.Header, c.Request.Header)
	if c.ApplyPrincipal != nil {
		before := snapshotRequest(req)
		c.ApplyPrincipal(req, c.Principal)
		if !requestChanged(before, req) {
			t.Fatalf("denycase: %q: ApplyPrincipal did not modify the request", c.Name)
			return
		}
	} else {
		applyDefaultPrincipal(req, c.Principal)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// Scan the live recorder map. Result() snapshots headers at first write
	// and looks up declared trailers by canonical key, so a late
	// non-canonical assignment never appears on res.Header or res.Trailer.
	live := rec.Header()
	res := rec.Result()
	defer res.Body.Close()
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("denycase: %q: read body: %v", c.Name, err)
		return
	}

	if !slices.Contains(exp.Status, res.StatusCode) {
		t.Fatalf("denycase: %q: status %d, want one of %v (fail closed)", c.Name, res.StatusCode, exp.Status)
		return
	}

	var findings []string
	for _, needle := range exp.BodyMustNot {
		if name, ok := valuesContain(live, headerNames, needle); ok {
			findings = append(findings, fmt.Sprintf("response header %s leaked %q", name, needle))
		}
		if name, ok := valuesContain(res.Trailer, headerNames, needle); ok {
			findings = append(findings, fmt.Sprintf("response trailer %s leaked %q", name, needle))
		}
	}
	encoded := false
	if len(exp.BodyMustNot) > 0 {
		if msg, ok := encodingProblem(live, res.Trailer); ok {
			findings = append(findings, msg)
			encoded = true
		}
	}
	if !encoded {
		for _, needle := range exp.BodyMustNot {
			if bytes.Contains(got, []byte(needle)) {
				findings = append(findings, fmt.Sprintf("response leaked %q", needle))
			}
		}
	}
	if len(findings) > 0 {
		t.Fatalf("denycase: %q: %s", c.Name, strings.Join(findings, "; "))
		return
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

type requestSnapshot struct {
	header http.Header
	url    string
	host   string
	ctx    context.Context
}

func snapshotRequest(req *http.Request) requestSnapshot {
	urlStr := ""
	if req.URL != nil {
		urlStr = req.URL.String()
	}
	return requestSnapshot{
		header: req.Header.Clone(),
		url:    urlStr,
		host:   req.Host,
		ctx:    req.Context(),
	}
}

func requestChanged(before requestSnapshot, req *http.Request) bool {
	if req.Host != before.host || req.Context() != before.ctx {
		return true
	}
	urlStr := ""
	if req.URL != nil {
		urlStr = req.URL.String()
	}
	if urlStr != before.url {
		return true
	}
	return !headerEqual(before.header, req.Header)
}

func headerEqual(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, vs := range a {
		ovs, ok := b[k]
		if !ok || !slices.Equal(vs, ovs) {
			return false
		}
	}
	return true
}

func encodingProblem(header, trailer http.Header) (string, bool) {
	var parts []string
	if v, ok := nonIdentityContentEncoding(header); ok {
		parts = append(parts, fmt.Sprintf("Content-Encoding is %q", v))
	}
	if v, ok := compressedTransferEncoding(header); ok {
		parts = append(parts, fmt.Sprintf("Transfer-Encoding is %q", v))
	}
	if v, ok := nonIdentityContentEncoding(trailer); ok {
		parts = append(parts, fmt.Sprintf("trailer Content-Encoding is %q", v))
	}
	if len(parts) == 0 {
		return "", false
	}
	return "BodyMustNot set but " + strings.Join(parts, " and "), true
}

func nonIdentityContentEncoding(h http.Header) (string, bool) {
	var found []string
	for k, vs := range h {
		if http.CanonicalHeaderKey(k) != "Content-Encoding" {
			continue
		}
		for _, v := range vs {
			for _, part := range splitHeaderList(v) {
				if !strings.EqualFold(part, "identity") {
					found = append(found, part)
				}
			}
		}
	}
	if len(found) == 0 {
		return "", false
	}
	slices.Sort(found)
	return strings.Join(found, ", "), true
}

func compressedTransferEncoding(h http.Header) (string, bool) {
	var found []string
	for k, vs := range h {
		if http.CanonicalHeaderKey(k) != "Transfer-Encoding" {
			continue
		}
		for _, v := range vs {
			for _, part := range splitHeaderList(v) {
				if _, ok := compressedTE[strings.ToLower(part)]; ok {
					found = append(found, part)
				}
			}
		}
	}
	if len(found) == 0 {
		return "", false
	}
	slices.Sort(found)
	return strings.Join(found, ", "), true
}

func splitHeaderList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if i := strings.IndexByte(part, ';'); i >= 0 {
			part = strings.TrimSpace(part[:i])
		}
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func leakNames(extra []string) []string {
	return append(append([]string(nil), defaultLeakHeaders...), extra...)
}

// valuesContain reports whether any header in names has a value containing
// needle. It ranges the map so a non-canonical key still matches. The
// returned name is the matching map keys as written, sorted.
//
// httptest.Result looks up declared trailers by canonical key and drops a
// raw key such as ["location"]. Scan the recorder's live map for those;
// res.Trailer only sees TrailerPrefix and canonical declared names.
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
	if strings.TrimSpace(c.Principal.Tenant) == "" || strings.TrimSpace(c.Principal.ID) == "" {
		return errors.New("Principal.Tenant and Principal.ID are required")
	}
	if err := validatePrincipalValue("Tenant", c.Principal.Tenant); err != nil {
		return err
	}
	if err := validatePrincipalValue("ID", c.Principal.ID); err != nil {
		return err
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
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if !validHeaderToken(k) {
			return fmt.Errorf("Request.Header name %q is not a valid header token", k)
		}
	}
	groups := make(map[string][]string, len(keys))
	for _, k := range keys {
		can := http.CanonicalHeaderKey(k)
		groups[can] = append(groups[can], k)
	}
	var dups []string
	for can, names := range groups {
		if len(names) > 1 {
			dups = append(dups, can)
		}
	}
	if len(dups) == 0 {
		return nil
	}
	slices.Sort(dups)
	names := groups[dups[0]]
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return fmt.Errorf("Request.Header has duplicate keys %s", strings.Join(quoted, " and "))
}

func validateMethod(method string) error {
	if method == "" {
		return errors.New("Request.Method is required")
	}
	if !validHeaderToken(method) {
		return fmt.Errorf("Request.Method %q is not a valid token", method)
	}
	if _, ok := rfc9110Methods[method]; !ok {
		return fmt.Errorf("Request.Method %q is not an RFC 9110 method", method)
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
	if err := rejectHiddenPathBytes(path); err != nil {
		return err
	}
	return nil
}

func rejectHiddenPathBytes(path string) error {
	for i := 0; i < len(path); i++ {
		if path[i] <= 0x20 || path[i] == 0x7f {
			return fmt.Errorf("Request.Path %q contains a space, control, or format character", path)
		}
	}
	if !utf8.ValidString(path) {
		return fmt.Errorf("Request.Path %q contains a space, control, or format character", path)
	}
	for _, r := range path {
		if unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("Request.Path %q contains a space, control, or format character", path)
		}
	}
	return nil
}

func validatePrincipalValue(field, v string) error {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return fmt.Errorf("Principal.%s %q contains a space, control, or format character", field, v)
		}
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("Principal.%s %q contains a space, control, or format character", field, v)
	}
	for _, r := range v {
		if unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("Principal.%s %q contains a space, control, or format character", field, v)
		}
	}
	return nil
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
