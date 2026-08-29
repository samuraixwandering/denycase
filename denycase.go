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
	"maps"
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

const maxFindings = 8

const trailerPrefix = "trailer:"

// Kind names a shipped deny situation.
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
	// sets HeaderTenant and HeaderPrincipal. Only Header, URL, Host, and
	// Context are compared; everything else is ignored. Principal.Tenant
	// and Principal.ID are always required. If Request.Header already has
	// the value the callback would write, put that value in one place only.
	ApplyPrincipal func(*http.Request, Principal)
}

// Fixture is a Kind plus a Case.
type Fixture struct {
	Kind Kind
	Case Case
}

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
		t.Fatalf("denycase: %q: %v", c.Name, err)
		return
	}
	copyHeaders(req.Header, c.Request.Header)
	if c.ApplyPrincipal != nil {
		before := snapshotRequest(req)
		c.ApplyPrincipal(req, c.Principal)
		if !requestChanged(before, req) {
			t.Fatalf("denycase: %q: %s", c.Name, applyPrincipalUnchangedMsg)
			return
		}
	} else {
		applyDefaultPrincipal(req, c.Principal)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// res.Header is the flushed wire snapshot. live still holds late
	// trailer writes that Result() drops when the map key is not canonical.
	// Scan wire headers plus late trailers only; post-commit non-trailer
	// mutations are not on the wire.
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
	if len(exp.BodyMustNot) > 0 {
		encMsg, encoded := encodingProblem(res.Header, live, res.Trailer)
		if encoded {
			findings = append(findings, encMsg)
		}
		for _, needle := range exp.BodyMustNot {
			if bytes.Contains(got, []byte(needle)) {
				findings = append(findings, fmt.Sprintf("response leaked %q", needle))
			}
		}
		headerNames := leakNames(exp.HeaderMustNot)
		want := leakWant(headerNames)
		trailers := declaredTrailers(res.Header, live)
		for _, needle := range exp.BodyMustNot {
			hdr, hok := headerLeaks(res.Header, want, needle)
			trl, tok := trailerLeaks(live, want, res.Trailer, trailers, needle)
			if hok {
				findings = append(findings, fmt.Sprintf("response header %s leaked %q", hdr, needle))
				trl = dropNamedIn(trl, hdr)
				tok = trl != ""
			}
			if tok {
				findings = append(findings, fmt.Sprintf("response trailer %s leaked %q", trl, needle))
			}
		}
	}
	if len(findings) > 0 {
		t.Fatalf("denycase: %q: %s", c.Name, formatFindings(findings))
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
	return maps.EqualFunc(a, b, slices.Equal[[]string])
}

const applyPrincipalUnchangedMsg = "ApplyPrincipal did not change Header, URL, Host, or Context (if your callback writes a value Request.Header already has, put it in one place only; writing to a cloned request is also a no-op)"

func encodingProblem(header, live, trailer http.Header) (string, bool) {
	var parts []string
	if v, ok := nonIdentityContentEncoding(header); ok {
		parts = append(parts, fmt.Sprintf("Content-Encoding is %q", v))
	}
	if v, ok := compressedTransferEncoding(header); ok {
		parts = append(parts, fmt.Sprintf("Transfer-Encoding is %q", v))
	}
	if v, ok := trailerContentEncoding(live, trailer); ok {
		parts = append(parts, fmt.Sprintf("trailer Content-Encoding is %q", v))
	}
	if v, ok := trailerTransferEncoding(live, trailer); ok {
		parts = append(parts, fmt.Sprintf("trailer Transfer-Encoding is %q", v))
	}
	if len(parts) == 0 {
		return "", false
	}
	return "BodyMustNot set but " + strings.Join(parts, " and "), true
}

func trailerContentEncoding(live, trailer http.Header) (string, bool) {
	var found []string
	collectCE := func(k string, vs []string) {
		if leakKey(k) != "Content-Encoding" {
			return
		}
		for _, v := range vs {
			for _, part := range splitHeaderList(v) {
				if !strings.EqualFold(part, "identity") {
					found = append(found, part)
				}
			}
		}
	}
	for k, vs := range trailer {
		collectCE(k, vs)
	}
	for k, vs := range live {
		if hasTrailerPrefix(k) {
			collectCE(k, vs)
		}
	}
	return joinUnique(found)
}

func trailerTransferEncoding(live, trailer http.Header) (string, bool) {
	var found []string
	collectTE := func(k string, vs []string) {
		if leakKey(k) != "Transfer-Encoding" {
			return
		}
		for _, v := range vs {
			for _, part := range splitHeaderList(v) {
				low := strings.ToLower(part)
				if low != "chunked" && low != "identity" {
					found = append(found, part)
				}
			}
		}
	}
	for k, vs := range trailer {
		collectTE(k, vs)
	}
	for k, vs := range live {
		if hasTrailerPrefix(k) {
			collectTE(k, vs)
		}
	}
	return joinUnique(found)
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
	return joinUnique(found)
}

func compressedTransferEncoding(h http.Header) (string, bool) {
	var found []string
	for k, vs := range h {
		if http.CanonicalHeaderKey(k) != "Transfer-Encoding" {
			continue
		}
		for _, v := range vs {
			for _, part := range splitHeaderList(v) {
				low := strings.ToLower(part)
				if low != "chunked" && low != "identity" {
					found = append(found, part)
				}
			}
		}
	}
	return joinUnique(found)
}

func joinUnique(found []string) (string, bool) {
	if len(found) == 0 {
		return "", false
	}
	slices.Sort(found)
	found = slices.Compact(found)
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

func leakWant(names []string) map[string]struct{} {
	want := make(map[string]struct{}, len(names))
	for _, n := range names {
		want[http.CanonicalHeaderKey(n)] = struct{}{}
	}
	return want
}

func hasTrailerPrefix(k string) bool {
	return len(k) >= len(trailerPrefix) && strings.EqualFold(k[:len(trailerPrefix)], trailerPrefix)
}

func leakKey(k string) string {
	if hasTrailerPrefix(k) {
		return http.CanonicalHeaderKey(k[len(trailerPrefix):])
	}
	return http.CanonicalHeaderKey(k)
}

func declaredTrailers(wire, live http.Header) map[string]struct{} {
	out := make(map[string]struct{})
	addDecl := func(h http.Header) {
		for k, vs := range h {
			if leakKey(k) != "Trailer" {
				continue
			}
			for _, v := range vs {
				for _, part := range splitHeaderList(v) {
					out[http.CanonicalHeaderKey(part)] = struct{}{}
				}
			}
		}
	}
	addDecl(wire)
	addDecl(live)
	for k := range live {
		if hasTrailerPrefix(k) {
			out[leakKey(k)] = struct{}{}
		}
	}
	return out
}

func containsNeedle(vs []string, needle string) bool {
	for _, v := range vs {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

func headerLeaks(wire http.Header, want map[string]struct{}, needle string) (string, bool) {
	var hits []string
	for k, vs := range wire {
		can := leakKey(k)
		if _, ok := want[can]; !ok {
			continue
		}
		if containsNeedle(vs, needle) {
			hits = append(hits, k)
		}
	}
	return joinUnique(hits)
}

// trailerLeaks walks live and result the same way; those two Headers
// are interchangeable. want is the leak-name set and trailers is the
// declared/prefixed trailer set. Do not swap the maps: a prefixed
// name outside the leak list would then report as a leak.
func trailerLeaks(live http.Header, want map[string]struct{}, result http.Header, trailers map[string]struct{}, needle string) (string, bool) {
	seen := make(map[string]string)
	consider := func(k string, vs []string) {
		can := leakKey(k)
		if _, ok := want[can]; !ok {
			return
		}
		if _, isT := trailers[can]; !isT && !hasTrailerPrefix(k) {
			return
		}
		if !containsNeedle(vs, needle) {
			return
		}
		display := k
		if hasTrailerPrefix(k) {
			display = k[len(trailerPrefix):]
		}
		if prev, ok := seen[can]; !ok || display < prev {
			seen[can] = display
		}
	}
	for k, vs := range result {
		consider(k, vs)
	}
	for k, vs := range live {
		consider(k, vs)
	}
	var hits []string
	for _, d := range seen {
		hits = append(hits, d)
	}
	return joinUnique(hits)
}

func dropNamedIn(trl, hdr string) string {
	if trl == "" || hdr == "" {
		return trl
	}
	have := make(map[string]struct{})
	for _, p := range strings.Split(hdr, ", ") {
		have[leakKey(p)] = struct{}{}
	}
	var keep []string
	for _, p := range strings.Split(trl, ", ") {
		if _, ok := have[leakKey(p)]; !ok {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, ", ")
}

func formatFindings(findings []string) string {
	if len(findings) <= maxFindings {
		return strings.Join(findings, "; ")
	}
	return strings.Join(findings[:maxFindings], "; ") + fmt.Sprintf("; and %d more", len(findings)-maxFindings)
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
	var parts []string
	for _, can := range dups {
		names := groups[can]
		quoted := make([]string, len(names))
		for i, n := range names {
			quoted[i] = fmt.Sprintf("%q", n)
		}
		parts = append(parts, strings.Join(quoted, " and "))
	}
	return fmt.Errorf("Request.Header has duplicate keys %s", strings.Join(parts, "; "))
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
	return rejectHiddenText("Request.Path", path, true)
}

func validatePrincipalValue(field, v string) error {
	if strings.TrimSpace(v) != v {
		return fmt.Errorf("Principal.%s %q has leading or trailing whitespace", field, v)
	}
	return rejectHiddenText("Principal."+field, v, false)
}

func rejectHiddenText(what, s string, rejectSpace bool) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x7f || c < 0x20 || (rejectSpace && c <= 0x20) {
			return fmt.Errorf("%s %q contains a space, control, or invisible character", what, s)
		}
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s %q contains a space, control, or invisible character", what, s)
	}
	for _, r := range s {
		if hiddenRune(r) {
			return fmt.Errorf("%s %q contains a space, control, or invisible character", what, s)
		}
	}
	return nil
}

func hiddenRune(r rune) bool {
	if !unicode.IsPrint(r) {
		return true
	}
	if unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) {
		return true
	}
	if unicode.Is(unicode.Variation_Selector, r) {
		return true
	}
	return r == '\u2800'
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

func cloneExpect(e Expect) Expect {
	out := e
	out.Status = slices.Clone(e.Status)
	out.BodyMustNot = slices.Clone(e.BodyMustNot)
	out.HeaderMustNot = slices.Clone(e.HeaderMustNot)
	return out
}

func (e Expect) normalized() Expect {
	out := cloneExpect(e)
	if len(out.Status) == 0 {
		out.Status = []int{http.StatusForbidden}
	}
	return out
}
