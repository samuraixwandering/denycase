package denycase

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func denyOK(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "forbidden", http.StatusForbidden)
}

func TestMustDenyPassesOnForbidden(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderTenant) != "B" || r.Header.Get(HeaderPrincipal) != "user-b" {
			t.Fatalf("principal headers: tenant=%q id=%q", r.Header.Get(HeaderTenant), r.Header.Get(HeaderPrincipal))
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "cross-tenant read",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Denied(),
	}, h)
}

func TestMustDenyFailsOnAllow(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tenant":"A","secret":"x"}`))
	})
	got := runMustDeny(t, Case{
		Name:      "cross-tenant read",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Denied(),
	}, h)
	if !got.failed || !strings.Contains(got.msg, "status 200") {
		t.Fatalf("want status 200 fail, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
	}
}

func TestMustDenyFailsOnServerError(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	got := runMustDeny(t, Case{
		Name:      "handler exploded",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Denied(),
	}, h)
	if !got.failed || !strings.Contains(got.msg, "status 500") {
		t.Fatalf("want status 500 fail, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
	}
}

func TestMustDenyFailsOnNotFound(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	got := runMustDeny(t, Case{
		Name:      "missing",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Denied(),
	}, h)
	if !got.failed || !strings.Contains(got.msg, "status 404") {
		t.Fatalf("want status 404 fail, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
	}
}

func TestMustDenyPassesOnExplicit404(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	MustDeny(t, Case{
		Name:      "explicit 404",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Expect{Status: []int{http.StatusNotFound}},
	}, h)
}

func TestMustDenyFailsOnBodyLeak(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"owner":"tenant-A"}`, http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "deny but leak",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response leaked "tenant-A"`) {
		t.Fatalf("want body leak, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyFailsOnHeaderLeak(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/invoices/tenant-A")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "location leak",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header Location leaked "tenant-A"`) {
		t.Fatalf("want Location leak, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyIgnoresUnnamedCustomHeader(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Owner", "tenant-A")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "x-owner not in scope",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if got.failed {
		t.Fatalf("unnamed X-Owner should pass, got msg=%q panic=%v", got.msg, got.panic)
	}
}

func TestMustDenyFailsOnNamedCustomHeader(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Owner", "tenant-A")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "x-owner named",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:        []int{http.StatusForbidden},
			BodyMustNot:   []string{"tenant-A"},
			HeaderMustNot: []string{"X-Owner"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header X-Owner leaked "tenant-A"`) {
		t.Fatalf("want named X-Owner leak, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyIgnoresShortNeedleInMiddlewareHeaders(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=31536000")
		w.Header().Set("X-Request-Id", "req-7f42ab")
		w.Header().Set("Server", "nginx/1.21.4")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "invoice 42",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/42"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"42"},
		},
	}, h)
}

func TestMustDenyFailsOnDispositionLeak(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="tenant-A-invoice.pdf"`)
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "filename leak",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header Content-Disposition leaked "tenant-A"`) {
		t.Fatalf("want Content-Disposition leak, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyFailsOnTrailerLeak(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "Location")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden\n"))
		w.Header().Set("Location", "/invoices/tenant-A")
	})
	got := runMustDeny(t, Case{
		Name:      "trailer leak",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response trailer Location leaked "tenant-A"`) {
		t.Fatalf("want trailer leak, got failed=%v msg=%q", got.failed, got.msg)
	}
	if strings.Contains(got.msg, "response header") {
		t.Fatalf("declared trailer should not also be a header leak: %q", got.msg)
	}
}

func TestMustDenyRejectsEmptyHeaderMustNot(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "empty header name",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:        []int{http.StatusForbidden},
			BodyMustNot:   []string{"tenant-A"},
			HeaderMustNot: []string{""},
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "empty name") {
		t.Fatalf("want empty HeaderMustNot validate, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsEmptyBodyMustNotNeedle(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "empty needle",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{""},
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "empty needle") {
		t.Fatalf("want empty-needle validate, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
	}
}

func TestMustDenyRejectsEncodedBody(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "gzip",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Content-Encoding") {
		t.Fatalf("want Content-Encoding fail, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsInvalidCase(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/x"},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "Name is required") {
		t.Fatalf("want Name validate, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsStatus200(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "allowlisted 200",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Expect{Status: []int{http.StatusOK}},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "not 403 or 404") {
		t.Fatalf("want status validate, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsStatus401(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "auth-layer",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Expect{Status: []int{http.StatusUnauthorized}},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "not 403 or 404") {
		t.Fatalf("want 401 rejected, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsZeroPrincipal(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:    "anon",
		Request: Request{Method: http.MethodGet, Path: "/invoices/a"},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "Principal.Tenant and Principal.ID") {
		t.Fatalf("want principal validate, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsPartialPrincipal(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "id only",
		Principal: Principal{ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "Principal.Tenant and Principal.ID") {
		t.Fatalf("want both principal fields, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyNilHandler(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "n",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/x"},
	}, nil)
	if !got.failed || !strings.Contains(got.msg, "handler is nil") {
		t.Fatalf("want nil handler, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyApplyPrincipal(t *testing.T) {
	t.Parallel()
	var gotID string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = r.Header.Get("Authorization")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "jwt-shaped",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		ApplyPrincipal: func(r *http.Request, p Principal) {
			r.Header.Set("Authorization", "Bearer "+p.ID)
		},
	}, h)
	if gotID != "Bearer user-b" {
		t.Fatalf("ApplyPrincipal: got %q", gotID)
	}
}

func TestMustDenyRejectsNoopApplyPrincipal(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "noop",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		ApplyPrincipal: func(*http.Request, Principal) {
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "did not change Header, URL, Host, or Context") {
		t.Fatalf("want no-op ApplyPrincipal reject, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsApplyPrincipalLocalCopy(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "local copy",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		ApplyPrincipal: func(r *http.Request, p Principal) {
			c := r.Clone(r.Context())
			c.Header.Set("Authorization", "Bearer "+p.ID)
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "did not change Header, URL, Host, or Context") {
		t.Fatalf("want local-copy ApplyPrincipal reject, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsZeroPrincipalWithApplyPrincipal(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:    "anon bearer",
		Request: Request{Method: http.MethodGet, Path: "/invoices/a"},
		ApplyPrincipal: func(r *http.Request, p Principal) {
			r.Header.Set("Authorization", "Bearer "+p.ID)
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "Principal.Tenant and Principal.ID") {
		t.Fatalf("want principal required with ApplyPrincipal, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyCanonicalizesRequestHeaders(t *testing.T) {
	t.Parallel()
	var got string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "lowercase auth header",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request: Request{
			Method: http.MethodGet,
			Path:   "/invoices/a",
			Header: http.Header{"authorization": []string{"Bearer user-b"}},
		},
	}, h)
	if got != "Bearer user-b" {
		t.Fatalf("canonical Authorization: got %q", got)
	}
}

func TestMustDenyRejectsDuplicateCanonicalHeaders(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "dup",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request: Request{
			Method: http.MethodGet,
			Path:   "/invoices/a",
			Header: http.Header{
				"authorization": []string{"Bearer a"},
				"Authorization": []string{"Bearer b"},
			},
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, `duplicate keys "Authorization" and "authorization"`) {
		t.Fatalf("want sorted duplicate-key validate, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyDoesNotMutateCallerStatus(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	status := []int{http.StatusNotFound}
	body := []string{"tenant-A"}
	hdrs := []string{"X-Owner"}
	MustDeny(t, Case{
		Name:      "owned slice",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Expect{Status: status, BodyMustNot: body, HeaderMustNot: hdrs},
	}, h)
	if len(status) != 1 || status[0] != http.StatusNotFound || body[0] != "tenant-A" || hdrs[0] != "X-Owner" {
		t.Fatalf("caller Expect slices were mutated: status=%v body=%v hdrs=%v", status, body, hdrs)
	}
}

func TestNormalizedClonesExpectSlices(t *testing.T) {
	t.Parallel()
	status := []int{http.StatusForbidden}
	body := []string{"tenant-A"}
	hdrs := []string{"X-Owner"}
	got := Expect{Status: status, BodyMustNot: body, HeaderMustNot: hdrs}.normalized()
	got.Status[0] = http.StatusNotFound
	got.BodyMustNot[0] = "mutated"
	got.HeaderMustNot[0] = "X-Other"
	if status[0] != http.StatusForbidden || body[0] != "tenant-A" || hdrs[0] != "X-Owner" {
		t.Fatalf("normalized aliased caller slices: status=%v body=%v hdrs=%v", status, body, hdrs)
	}
}

func TestMustDenyRejectsPathWithoutSlash(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "bad path",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "invoices/a"},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "must start with /") {
		t.Fatalf("want path validate, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsNonPrintablePath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		path string
	}{
		{"space", "/invoices/42 "},
		{"nul", "/invoices/42\x00"},
		{"del", "/invoices/42\x7f"},
		{"zwsp", "/invoices/42\u200b"},
		{"invalid-utf8", "/invoices/42\x85"},
		{"nel", "/invoices/42\u0085"},
		{"nbsp", "/invoices/\u00a0a"},
		{"braille", "/invoices/42\u2800"},
		{"jungseong", "/invoices/42\u1160"},
		{"cgj", "/invoices/42\u034f"},
		{"vs16", "/invoices/42\ufe0f"},
		{"vs-supp", "/invoices/42\U000e0100"},
		{"crlf", "/a HTTP/1.0\r\nX-Injected: yes\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := runMustDeny(t, Case{
				Name:      "inject",
				Principal: Principal{Tenant: "B", ID: "user-b"},
				Request:   Request{Method: http.MethodGet, Path: tc.path},
			}, http.HandlerFunc(denyOK))
			if !got.failed || !strings.Contains(got.msg, "space, control, or invisible character") {
				t.Fatalf("path %q: want hidden-byte reject, got failed=%v msg=%q", tc.path, got.failed, got.msg)
			}
		})
	}
}

func TestMustDenyRejectsInvalidMethod(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"GET\x00", "GET\x7f", "GET;", "G(E)T", "GET "} {
		t.Run(fmt.Sprintf("%q", method), func(t *testing.T) {
			t.Parallel()
			got := runMustDeny(t, Case{
				Name:      "bad method",
				Principal: Principal{Tenant: "B", ID: "user-b"},
				Request:   Request{Method: method, Path: "/invoices/a"},
			}, http.HandlerFunc(denyOK))
			if !got.failed || !strings.Contains(got.msg, "Request.Method") || !strings.Contains(got.msg, "not a valid token") {
				t.Fatalf("method %q: want token reject, got failed=%v msg=%q", method, got.failed, got.msg)
			}
		})
	}
}

func TestMustDenyRejectsNonRFC9110Method(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"get", "Get", "GETT", "FOO_BAR", "%", "a~b"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			got := runMustDeny(t, Case{
				Name:      "odd method",
				Principal: Principal{Tenant: "B", ID: "user-b"},
				Request:   Request{Method: method, Path: "/invoices/a"},
			}, http.HandlerFunc(denyOK))
			if !got.failed || !strings.Contains(got.msg, "Request.Method") || !strings.Contains(got.msg, "not an RFC 9110 method") {
				t.Fatalf("method %q: want RFC 9110 reject, got failed=%v msg=%q", method, got.failed, got.msg)
			}
		})
	}
}

func TestMustDenyAcceptsNonASCIIPath(t *testing.T) {
	t.Parallel()
	MustDeny(t, Case{
		Name:      "cafe",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/facturas/café"},
	}, http.HandlerFunc(denyOK))
}

func TestMustDenyRejectsHeaderMustNotWithoutBodyMustNot(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "header only",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:        []int{http.StatusForbidden},
			HeaderMustNot: []string{"X-Owner"},
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "HeaderMustNot requires BodyMustNot") {
		t.Fatalf("want pair reject, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsInvalidHeaderMustNotBeforePairing(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "bad name no needles",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:        []int{http.StatusForbidden},
			HeaderMustNot: []string{"X-Owner:"},
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "not a valid header token") {
		t.Fatalf("want token reject before pairing, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsEmptyHeaderMustNotBeforePairing(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "empty name no needles",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:        []int{http.StatusForbidden},
			HeaderMustNot: []string{""},
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "empty name") {
		t.Fatalf("want empty-name reject before pairing, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsInvalidHeaderMustNotName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"X-Owner, X-Tenant", "x owner", " ", "X-Owner:", "\tX-Owner"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := runMustDeny(t, Case{
				Name:      "bad header name",
				Principal: Principal{Tenant: "B", ID: "user-b"},
				Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
				Expect: Expect{
					Status:        []int{http.StatusForbidden},
					BodyMustNot:   []string{"tenant-A"},
					HeaderMustNot: []string{name},
				},
			}, http.HandlerFunc(denyOK))
			if !got.failed || !strings.Contains(got.msg, "HeaderMustNot") || !strings.Contains(got.msg, "not a valid header token") {
				t.Fatalf("name %q: want token reject, got failed=%v msg=%q", name, got.failed, got.msg)
			}
		})
	}
}

func TestMustDenyFailsOnEachDefaultLeakHeader(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Location", "Content-Location", "Content-Disposition", "Set-Cookie"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(name, "prefix-tenant-A-suffix")
				http.Error(w, "forbidden", http.StatusForbidden)
			})
			got := runMustDeny(t, Case{
				Name:      name + " leak",
				Principal: Principal{Tenant: "B", ID: "user-b"},
				Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
				Expect: Expect{
					Status:      []int{http.StatusForbidden},
					BodyMustNot: []string{"tenant-A"},
				},
			}, h)
			want := fmt.Sprintf("response header %s leaked %q", name, "tenant-A")
			if !got.failed || !strings.Contains(got.msg, want) {
				t.Fatalf("want %s, got failed=%v msg=%q", want, got.failed, got.msg)
			}
		})
	}
}

func TestDefaultLeakHeadersOmitNoiseHeaders(t *testing.T) {
	t.Parallel()
	want := []string{"Location", "Content-Location", "Content-Disposition", "Set-Cookie"}
	if !slices.Equal(defaultLeakHeaders, want) {
		t.Fatalf("defaultLeakHeaders = %v, want %v", defaultLeakHeaders, want)
	}
	banned := map[string]struct{}{
		"Content-Type":   {},
		"Date":           {},
		"Content-Length": {},
	}
	for _, name := range defaultLeakHeaders {
		if _, ok := banned[name]; ok {
			t.Fatalf("%s must not be in defaultLeakHeaders", name)
		}
	}
}

func TestMustDenyFailsOnNonCanonicalDefaultHeader(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header()["location"] = []string{"/invoices/tenant-A"}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "raw location",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header location leaked "tenant-A"`) {
		t.Fatalf("want raw location leak, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyFailsOnNonCanonicalNamedHeader(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header()["x-owner"] = []string{"tenant-A"}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "raw x-owner",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:        []int{http.StatusForbidden},
			BodyMustNot:   []string{"tenant-A"},
			HeaderMustNot: []string{"X-Owner"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header x-owner leaked "tenant-A"`) {
		t.Fatalf("want raw x-owner leak, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsNonCanonicalGzip(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header()["content-encoding"] = []string{"gzip"}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "raw gzip",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Content-Encoding") {
		t.Fatalf("want non-canonical gzip fail, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyReportsHeaderLeakAlongsideEncodingGate(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Location", "/invoices/tenant-A")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "gzip and location",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	enc := strings.Index(got.msg, "Content-Encoding")
	loc := strings.Index(got.msg, `response header Location leaked "tenant-A"`)
	if !got.failed || enc < 0 || loc < 0 || enc > loc {
		t.Fatalf("want encoding then Location, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyReportsSortedHeaderLeaks(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/invoices/tenant-A")
		w.Header().Set("Content-Location", "/invoices/tenant-A")
		w.Header().Set("Set-Cookie", "owner=tenant-A")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "two locations",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header Content-Location, Location, Set-Cookie leaked "tenant-A"`) {
		t.Fatalf("want sorted header names, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyDefaultPrincipalWinsOverRequestHeader(t *testing.T) {
	t.Parallel()
	var gotTenant string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant = r.Header.Get(HeaderTenant)
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "injected A",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request: Request{
			Method: http.MethodGet,
			Path:   "/invoices/a",
			Header: http.Header{HeaderTenant: []string{"A"}},
		},
	}, h)
	if gotTenant != "B" {
		t.Fatalf("default principal should Set-win, got tenant %q", gotTenant)
	}
}

func TestMustDenyRejectsInvalidRequestHeaderName(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "smuggled name",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request: Request{
			Method: http.MethodGet,
			Path:   "/invoices/a",
			Header: http.Header{"X-Fine: x\r\nX-Evil": []string{"1"}},
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "not a valid header token") {
		t.Fatalf("want request header name reject, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyAcceptsUnderscoreHeaderMustNot(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header()["X_Owner"] = []string{"tenant-A"}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "x_owner token",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:        []int{http.StatusForbidden},
			BodyMustNot:   []string{"tenant-A"},
			HeaderMustNot: []string{"X_Owner"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header X_Owner leaked "tenant-A"`) {
		t.Fatalf("want X_Owner leak, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyPassesIdentityContentEncoding(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "IDENTITY")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "identity fold",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
}

func TestMustDenyPassesRepeatedIdentityContentEncoding(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "identity, identity")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "identity list",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
}

func TestMustDenyRejectsTransferEncodingGzip(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Transfer-Encoding", "gzip")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "te gzip",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Transfer-Encoding") || !strings.Contains(got.msg, "gzip") {
		t.Fatalf("want TE gzip fail, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsTrailerContentEncoding(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(http.TrailerPrefix+"Content-Encoding", "gzip")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "trailer gzip",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Content-Encoding") {
		t.Fatalf("want trailer CE fail, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyFailsOnRawLateTrailerLocation(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "Location")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden\n"))
		w.Header()["location"] = []string{"/invoices/tenant-A"}
	})
	got := runMustDeny(t, Case{
		Name:      "raw trailer",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response trailer location leaked "tenant-A"`) {
		t.Fatalf("want late trailer location leak, got failed=%v msg=%q", got.failed, got.msg)
	}
	if strings.Contains(got.msg, "response header") {
		t.Fatalf("declared trailer should not also be a header leak: %q", got.msg)
	}
}

func TestMustDenyReportsHeaderAndBodyLeaksTogether(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="invoices-2015.pdf"`)
		http.Error(w, `{"owner":"tenant-A"}`, http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "both leaks",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"2015", "tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `Content-Disposition leaked "2015"`) || !strings.Contains(got.msg, `response leaked "tenant-A"`) {
		t.Fatalf("want both leaks, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsEmptyRequestHeaderName(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "empty header key",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request: Request{
			Method: http.MethodGet,
			Path:   "/invoices/a",
			Header: http.Header{"": []string{"1"}},
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "Request.Header name") || !strings.Contains(got.msg, "not a valid header token") {
		t.Fatalf("want empty request header name reject, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsBadPercentEscape(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "bad escape",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/%zz"},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, `invalid request "GET" "/%zz"`) {
		t.Fatalf("want recover quoted message, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
	}
}

func TestMustDenyRejectsWhitespacePrincipal(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "blank tenant",
		Principal: Principal{Tenant: " ", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "Principal.Tenant and Principal.ID") {
		t.Fatalf("want whitespace principal reject, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsControlPrincipal(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "crlf tenant",
		Principal: Principal{Tenant: "B\r\nX-Admin: 1", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "Principal.Tenant") || !strings.Contains(got.msg, "space, control, or invisible character") {
		t.Fatalf("want control principal reject, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestExpectFieldCount(t *testing.T) {
	t.Parallel()
	if n := reflect.TypeOf(Expect{}).NumField(); n != 3 {
		t.Fatalf("Expect has %d fields; update normalized() clones", n)
	}
}

func TestMustDenyFailsOnLateScrubbedHeader(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Location", "/invoices/42?owner=tenant-A")
		http.Error(w, "forbidden", http.StatusForbidden)
		w.Header().Del("Content-Location")
	})
	got := runMustDeny(t, Case{
		Name:      "late del",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header Content-Location leaked "tenant-A"`) {
		t.Fatalf("want wire snapshot leak, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyIgnoresLateHeaderWithoutTrailer(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
		w.Header().Set("Content-Location", "/invoices/tenant-A")
	})
	got := runMustDeny(t, Case{
		Name:      "late set",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if got.failed {
		t.Fatalf("post-commit non-trailer should be ignored, got msg=%q", got.msg)
	}
}

func TestMustDenyIgnoresUnlistedPrefixedTrailer(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(http.TrailerPrefix+"X-Random", "/x/tenant-A")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "unlisted trailer",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if got.failed {
		t.Fatalf("prefixed trailer outside the leak list should pass, got msg=%q", got.msg)
	}
}

func TestMustDenyFailsOnLowercaseTrailerPrefix(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden\n"))
		w.Header()["trailer:location"] = []string{"/x/tenant-A"}
	})
	got := runMustDeny(t, Case{
		Name:      "lc prefix",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response trailer location leaked "tenant-A"`) {
		t.Fatalf("want lowercase trailer prefix leak, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyFailsOnLateDeletedContentEncoding(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte{0x1f, 0x8b})
		w.Header().Del("Content-Encoding")
	})
	got := runMustDeny(t, Case{
		Name:      "late del ce",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Content-Encoding") {
		t.Fatalf("want flushed CE gate, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyHonestGzipDoesNotReportBodyNeedle(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"owner":"tenant-A"}`))
	_ = zw.Close()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(buf.Bytes())
	})
	got := runMustDeny(t, Case{
		Name:      "real gzip",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Content-Encoding") {
		t.Fatalf("want encoding gate, got failed=%v msg=%q", got.failed, got.msg)
	}
	// We do not decode, so a real gzip body must not yield a clear needle.
	if strings.Contains(got.msg, "response leaked") {
		t.Fatalf("real gzip must not contain a clear needle: %q", got.msg)
	}
}

func TestMustDenyReportsBodyWhenEncodingClaimIsPlaintext(t *testing.T) {
	t.Parallel()
	for _, enc := range []string{"gzip", "br", "deflate", "zstd", "compress"} {
		t.Run(enc, func(t *testing.T) {
			t.Parallel()
			h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", enc)
				http.Error(w, `{"owner":"tenant-A"}`, http.StatusForbidden)
			})
			got := runMustDeny(t, Case{
				Name:      "fake " + enc,
				Principal: Principal{Tenant: "B", ID: "user-b"},
				Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
				Expect: Expect{
					Status:      []int{http.StatusForbidden},
					BodyMustNot: []string{"tenant-A"},
				},
			}, h)
			if !got.failed || !strings.Contains(got.msg, "Content-Encoding") || !strings.Contains(got.msg, `response leaked "tenant-A"`) {
				t.Fatalf("want encoding and plaintext body leak, got failed=%v msg=%q", got.failed, got.msg)
			}
		})
	}
}

func TestMustDenyRejectsTransferEncodingXGzip(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Transfer-Encoding", "x-gzip")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "x-gzip",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Transfer-Encoding") || !strings.Contains(got.msg, "x-gzip") {
		t.Fatalf("want x-gzip fail, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsGzipWithQValue(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Transfer-Encoding", "gzip;q=1.0")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "gzip q",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Transfer-Encoding") {
		t.Fatalf("want gzip;q=1.0 fail, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyPassesIdentityWithQValue(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "identity;q=1")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "identity q",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
}

func TestMustDenyRejectsTrailingSpacePrincipal(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "spaced tenant",
		Principal: Principal{Tenant: "B ", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "Principal.Tenant") || !strings.Contains(got.msg, "leading or trailing whitespace") {
		t.Fatalf("want trailing-space principal reject, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsNBSPPrincipal(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "nbsp tenant",
		Principal: Principal{Tenant: "B\u00a0x", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "Principal.Tenant") || !strings.Contains(got.msg, "invisible character") {
		t.Fatalf("want NBSP principal reject, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsVariationSelectorPrincipal(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "vs tenant",
		Principal: Principal{Tenant: "B\ufe0f", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "Principal.Tenant") || !strings.Contains(got.msg, "invisible character") {
		t.Fatalf("want VS principal reject, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyApplyPrincipalSignals(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	for _, tc := range []struct {
		name string
		fn   func(*http.Request, Principal)
	}{
		{"header", func(r *http.Request, p Principal) {
			r.Header.Set("Authorization", "Bearer "+p.ID)
		}},
		{"url", func(r *http.Request, _ Principal) {
			r.URL.RawQuery = "as=b"
		}},
		{"host", func(r *http.Request, _ Principal) {
			r.Host = "app.example"
		}},
		{"context", func(r *http.Request, p Principal) {
			*r = *r.WithContext(context.WithValue(r.Context(), struct{}{}, p.ID))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			MustDeny(t, Case{
				Name:           tc.name,
				Principal:      Principal{Tenant: "B", ID: "user-b"},
				Request:        Request{Method: http.MethodGet, Path: "/invoices/a"},
				ApplyPrincipal: tc.fn,
			}, h)
		})
	}
}

func TestMustDenyApplyPrincipalReplacesStaleHeader(t *testing.T) {
	t.Parallel()
	var got string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "replace stale",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request: Request{
			Method: http.MethodGet,
			Path:   "/invoices/a",
			Header: http.Header{"Authorization": []string{"Bearer stale"}},
		},
		ApplyPrincipal: func(r *http.Request, p Principal) {
			r.Header.Set("Authorization", "Bearer "+p.ID)
		},
	}, h)
	if got != "Bearer user-b" {
		t.Fatalf("stale header not replaced: %q", got)
	}
}

func TestMustDenyAcceptsAllRFC9110Methods(t *testing.T) {
	t.Parallel()
	for _, method := range []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodConnect, http.MethodOptions,
		http.MethodTrace, http.MethodPatch,
	} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			MustDeny(t, Case{
				Name:      method,
				Principal: Principal{Tenant: "B", ID: "user-b"},
				Request:   Request{Method: method, Path: "/invoices/a"},
			}, http.HandlerFunc(denyOK))
		})
	}
}

func TestMustDenyFailsOnDeclaredLocationBeforeWrite(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "Location")
		w.Header().Set("Location", "/invoices/tenant-A")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "declared wire",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header Location leaked "tenant-A"`) {
		t.Fatalf("want wire Location, got failed=%v msg=%q", got.failed, got.msg)
	}
	if strings.Contains(got.msg, "response trailer") {
		t.Fatalf("same-name trailer should be suppressed: %q", got.msg)
	}
}

func TestMustDenyFailsOnDeclaredLocationThenLateDel(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/x/tenant-A")
		w.Header().Set("Trailer", "Location")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden\n"))
		w.Header().Del("Location")
	})
	got := runMustDeny(t, Case{
		Name:      "late del declared",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header Location leaked "tenant-A"`) {
		t.Fatalf("want snapshot Location after late Del, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyFailsOnPostCommitTrailerDeclaration(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/x/tenant-A")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden\n"))
		w.Header().Del("Location")
		w.Header().Set("Trailer", "Location")
	})
	got := runMustDeny(t, Case{
		Name:      "late trailer decl",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header Location leaked "tenant-A"`) {
		t.Fatalf("want wire Location despite late Trailer, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyFailsOnForbiddenTrailerNameAsHeader(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "Cache-Control")
		w.Header().Set("Cache-Control", "private, x-tenant-A")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "cc header",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:        []int{http.StatusForbidden},
			BodyMustNot:   []string{"tenant-A"},
			HeaderMustNot: []string{"Cache-Control"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response header Cache-Control leaked "tenant-A"`) {
		t.Fatalf("want Cache-Control header leak, got failed=%v msg=%q", got.failed, got.msg)
	}
	if strings.Contains(got.msg, "response trailer") {
		t.Fatalf("forbidden trailer name should not be labelled trailer: %q", got.msg)
	}
}

func TestMustDenyIgnoresCleanDefaultHeaders(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/login")
		w.Header().Set("Set-Cookie", "sid=abc; Path=/")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "no needle",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if got.failed {
		t.Fatalf("clean Location/Set-Cookie should pass, got msg=%q", got.msg)
	}
}

func TestMustDenyFailsOnMixedCaseTrailerPrefix(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden\n"))
		w.Header()["TRAILER:location"] = []string{"/x/tenant-A"}
	})
	got := runMustDeny(t, Case{
		Name:      "TRAILER prefix",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `response trailer`) || !strings.Contains(got.msg, `leaked "tenant-A"`) {
		t.Fatalf("want TRAILER:location leak, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsPrefixedTrailerGzip(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(http.TrailerPrefix+"Content-Encoding", "gzip")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "lc trailer ce",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Content-Encoding") {
		t.Fatalf("want trailer:content-encoding gate, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyAcceptsSpacedPrincipal(t *testing.T) {
	t.Parallel()
	MustDeny(t, Case{
		Name:      "acme",
		Principal: Principal{Tenant: "Acme Corp", ID: "user b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
	}, http.HandlerFunc(denyOK))
}

func TestMustDenyApplyPrincipalAlreadyHadValue(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "preset same",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request: Request{
			Method: http.MethodGet,
			Path:   "/invoices/a",
			Header: http.Header{"Authorization": []string{"Bearer user-b"}},
		},
		ApplyPrincipal: func(r *http.Request, p Principal) {
			r.Header.Set("Authorization", "Bearer "+p.ID)
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "put it in one place only") {
		t.Fatalf("want one-place-only message, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyPassesTransferEncodingIdentity(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Transfer-Encoding", "identity")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "te identity",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
}

func TestMustDenyDedupsEncodingTokens(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip, gzip")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "dup gzip",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `Content-Encoding is "gzip"`) || strings.Contains(got.msg, "gzip, gzip") {
		t.Fatalf("want deduped gzip, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenySortsEncodingTokens(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip, br")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "sort enc",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, `Content-Encoding is "br, gzip"`) {
		t.Fatalf("want sorted encodings, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyCapsFindings(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "n1 n2 n3 n4 n5 n6 n7 n8 n9", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "many needles",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8", "n9"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "and 1 more") {
		t.Fatalf("want findings cap, got failed=%v msg=%q", got.failed, got.msg)
	}
	if strings.Contains(got.msg, `leaked "n9"`) {
		t.Fatalf("ninth body leak should be elided: %q", got.msg)
	}
}

func TestMustDenyCapsFindingsKeepsEncoding(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Set-Cookie", "a-tenant=1; b-tenant=1; c-tenant=1; d-tenant=1; e-tenant=1; f-tenant=1; g-tenant=1; h-tenant=1; i-tenant=1; j-tenant=1")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	needles := []string{"a-tenant", "b-tenant", "c-tenant", "d-tenant", "e-tenant", "f-tenant", "g-tenant", "h-tenant", "i-tenant", "j-tenant"}
	got := runMustDeny(t, Case{
		Name:      "cap enc",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: needles,
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Content-Encoding") || !strings.Contains(got.msg, "and 3 more") {
		t.Fatalf("want encoding line under cap, got failed=%v msg=%q", got.failed, got.msg)
	}
	if strings.Contains(got.msg, `leaked "j-tenant"`) {
		t.Fatalf("elided header leak should be absent: %q", got.msg)
	}
}

func TestMustDenyRejectsPrefixedTrailerTransferEncoding(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(http.TrailerPrefix+"Transfer-Encoding", "gzip")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "trailer te",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Transfer-Encoding") {
		t.Fatalf("want trailer Transfer-Encoding gate, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyPassesTrailerTransferEncodingIdentity(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(http.TrailerPrefix+"Transfer-Encoding", "identity")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "trailer te identity",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
}

func TestMustDenyRejectsTwoDuplicateHeaderGroups(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "two dups",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request: Request{
			Method: http.MethodGet,
			Path:   "/invoices/a",
			Header: http.Header{
				"X-Owner":  []string{"a"},
				"x-owner":  []string{"b"},
				"X-Tenant": []string{"c"},
				"x-tenant": []string{"d"},
			},
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "X-Owner") || !strings.Contains(got.msg, "X-Tenant") {
		t.Fatalf("want both duplicate groups, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyRejectsAddedGzipAfterIdentity(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Content-Encoding", "identity")
		w.Header().Add("Content-Encoding", "gzip")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	got := runMustDeny(t, Case{
		Name:      "identity then gzip",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !got.failed || !strings.Contains(got.msg, "Content-Encoding") || !strings.Contains(got.msg, "gzip") {
		t.Fatalf("want gzip after identity fail, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyHandlerPanicEscapes(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("handler boom")
	})
	got := runMustDeny(t, Case{
		Name:      "panic",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
	}, h)
	if got.panic == nil {
		t.Fatalf("panic was swallowed: failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestCorpusEmptyAndKindsStable(t *testing.T) {
	t.Parallel()
	if len(Corpus) != 0 {
		t.Fatalf("Corpus should be empty until the fixture pack: got %d", len(Corpus))
	}
	if KindCrossTenant != "cross_tenant" || KindMissingOwner != "missing_owner" || KindRelationMismatch != "relation_mismatch" {
		t.Fatal("Kind constants changed")
	}
}

type denyRun struct {
	failed bool
	msg    string
	panic  any
}

func runMustDeny(t *testing.T, c Case, h http.Handler) denyRun {
	t.Helper()
	p := &probeT{TB: t}
	done := make(chan struct{})
	var panicVal any
	go func() {
		defer close(done)
		defer func() {
			if rec := recover(); rec != nil {
				panicVal = rec
				p.failed = true
			}
		}()
		MustDeny(p, c, h)
	}()
	<-done
	return denyRun{failed: p.failed, msg: p.msg, panic: panicVal}
}

type probeT struct {
	testing.TB
	failed bool
	msg    string
}

func (p *probeT) Helper() {}

func (p *probeT) Failed() bool { return p.failed }

func (p *probeT) Fail() { p.failed = true }

func (p *probeT) Error(args ...any) {
	p.failed = true
	p.msg = fmt.Sprint(args...)
}

func (p *probeT) Errorf(format string, args ...any) {
	p.failed = true
	p.msg = fmt.Sprintf(format, args...)
}

func (p *probeT) Fatal(args ...any) {
	p.failed = true
	p.msg = fmt.Sprint(args...)
	runtime.Goexit()
}

func (p *probeT) Fatalf(format string, args ...any) {
	p.failed = true
	p.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func (p *probeT) FailNow() {
	p.failed = true
	runtime.Goexit()
}
