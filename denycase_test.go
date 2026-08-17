package denycase

import (
	"fmt"
	"net/http"
	"runtime"
	"testing"
)

func TestMustDenyPassesOnForbidden(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderTenant) != "B" {
			t.Fatalf("tenant header: got %q", r.Header.Get(HeaderTenant))
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
	if !mustDenyFailed(t, Case{
		Name:      "deny but leak",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h) {
		t.Fatal("MustDeny accepted a 403 that leaked the other tenant")
	}
}

func TestMustDenyFailsOnHeaderLeak(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/invoices/tenant-A")
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	if !mustDenyFailed(t, Case{
		Name:      "location leak",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h) {
		t.Fatal("MustDeny accepted a Location that named the other tenant")
	}
}

func TestMustDenyRejectsEmptyBodyMustNotNeedle(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	if !mustDenyFailed(t, Case{
		Name:      "empty needle",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{""},
		},
	}, h) {
		t.Fatal("MustDeny skipped an empty BodyMustNot needle")
	}
}

func TestMustDenyRejectsInvalidCase(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if !mustDenyFailed(t, Case{
		Principal: Principal{Tenant: "B"},
		Request:   Request{Method: http.MethodGet, Path: "/x"},
	}, h) {
		t.Fatal("MustDeny accepted a case with no Name")
	}
}

func TestMustDenyRejectsStatus200(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if !mustDenyFailed(t, Case{
		Name:      "allowlisted 200",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Expect{Status: []int{http.StatusOK}},
	}, h) {
		t.Fatal("MustDeny accepted Expect.Status 200")
	}
}

func TestMustDenyRejectsZeroPrincipal(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if !mustDenyFailed(t, Case{
		Name:    "anon",
		Request: Request{Method: http.MethodGet, Path: "/invoices/a"},
	}, h) {
		t.Fatal("MustDeny accepted an empty Principal with no ApplyPrincipal")
	}
}

func TestMustDenyNilHandler(t *testing.T) {
	t.Parallel()
	if !mustDenyFailed(t, Case{
		Name:      "n",
		Principal: Principal{ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/x"},
	}, nil) {
		t.Fatal("MustDeny accepted a nil handler")
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
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if !mustDenyFailed(t, Case{
		Name:      "bad path",
		Principal: Principal{Tenant: "B"},
		Request:   Request{Method: http.MethodGet, Path: "invoices/a"},
	}, h) {
		t.Fatal("MustDeny accepted a path without a leading /")
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

func mustDenyFailed(t *testing.T, c Case, h http.Handler) bool {
	t.Helper()
	p := &probeT{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		MustDeny(p, c, h)
	}()
	<-done
	return p.failed
}

type probeT struct {
	testing.TB
	failed bool
}

func (p *probeT) Helper() {}

func (p *probeT) Fail() { p.failed = true }

func (p *probeT) Error(args ...any) { p.failed = true }

func (p *probeT) Errorf(format string, args ...any) {
	p.failed = true
	_ = fmt.Sprintf(format, args...)
}

func (p *probeT) Fatal(args ...any) {
	p.failed = true
	runtime.Goexit()
}

func (p *probeT) Fatalf(format string, args ...any) {
	p.failed = true
	runtime.Goexit()
}

func (p *probeT) FailNow() {
	p.failed = true
	runtime.Goexit()
}
