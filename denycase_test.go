package denycase

import (
	"fmt"
	"net/http"
	"runtime"
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
	if !mustDenyFailed(t, Case{
		Name:      "cross-tenant read",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Denied(),
	}, h) {
		t.Fatal("MustDeny accepted a 200; fail-closed is broken")
	}
}

func TestMustDenyFailsOnServerError(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	if !mustDenyFailed(t, Case{
		Name:      "handler exploded",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Denied(),
	}, h) {
		t.Fatal("MustDeny accepted a 500")
	}
}

func TestMustDenyFailsOnNotFound(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	if !mustDenyFailed(t, Case{
		Name:      "missing",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Denied(),
	}, h) {
		t.Fatal("MustDeny accepted a 404 without Status 404")
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
	if !got.failed || !strings.Contains(got.msg, `response header leaked "tenant-A"`) {
		t.Fatalf("want Location leak, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyIgnoresUnnamedCustomHeader(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Owner", "tenant-A")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	MustDeny(t, Case{
		Name:      "x-owner not in scope",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
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
	if !got.failed || !strings.Contains(got.msg, `response header leaked "tenant-A"`) {
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
	if !got.failed || !strings.Contains(got.msg, `response header leaked "tenant-A"`) {
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
	if !got.failed || !strings.Contains(got.msg, `response trailer leaked "tenant-A"`) {
		t.Fatalf("want trailer leak, got failed=%v msg=%q", got.failed, got.msg)
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
			HeaderMustNot: []string{""},
		},
	}, http.HandlerFunc(denyOK))
	if !got.failed || !strings.Contains(got.msg, "HeaderMustNot") {
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
	if !got.failed || !strings.Contains(got.msg, "duplicate keys") {
		t.Fatalf("want duplicate-key validate, got failed=%v msg=%q", got.failed, got.msg)
	}
}

func TestMustDenyDoesNotMutateCallerStatus(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	status := []int{http.StatusNotFound}
	MustDeny(t, Case{
		Name:      "owned slice",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Expect{Status: status},
	}, h)
	if len(status) != 1 || status[0] != http.StatusNotFound {
		t.Fatalf("caller Status was mutated: %v", status)
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

func TestMustDenyContainsHandlerPanic(t *testing.T) {
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
		t.Fatalf("panic escaped or was dropped: failed=%v msg=%q", got.failed, got.msg)
	}
	if !got.failed {
		t.Fatal("contained panic was not treated as a failed MustDeny")
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

func mustDenyFailed(t *testing.T, c Case, h http.Handler) bool {
	t.Helper()
	got := runMustDeny(t, c, h)
	if got.panic != nil {
		t.Fatalf("handler panicked: %v", got.panic)
	}
	return got.failed
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
