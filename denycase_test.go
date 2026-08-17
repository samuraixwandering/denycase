package denycase

import (
	"fmt"
	"net/http"
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
	probe := &probeT{TB: t}
	MustDeny(probe, Case{
		Name:      "cross-tenant read",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Denied(),
	}, h)
	if !probe.failed {
		t.Fatal("MustDeny accepted a 200; fail-closed is broken")
	}
}

func TestMustDenyFailsOnBodyLeak(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"owner":"tenant-A"}`, http.StatusForbidden)
	})
	probe := &probeT{TB: t}
	MustDeny(probe, Case{
		Name:      "deny but leak",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"tenant-A"},
		},
	}, h)
	if !probe.failed {
		t.Fatal("MustDeny accepted a 403 that leaked the other tenant")
	}
}

func TestMustDenyHideExistenceAccepts404(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	MustDeny(t, Case{
		Name:      "hidden object",
		Principal: Principal{Tenant: "B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/a"},
		Expect:    Expect{HideExistence: true},
	}, h)
}

func TestMustDenyRejectsInvalidCase(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	probe := &probeT{TB: t}
	MustDeny(probe, Case{
		Request: Request{Method: http.MethodGet, Path: "/x"},
	}, h)
	if !probe.failed {
		t.Fatal("MustDeny accepted a case with no Name")
	}
}

func TestMustDenyNilHandler(t *testing.T) {
	t.Parallel()
	probe := &probeT{TB: t}
	MustDeny(probe, Case{
		Name:    "n",
		Request: Request{Method: http.MethodGet, Path: "/x"},
	}, nil)
	if !probe.failed {
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

func TestCorpusEmptyAndKindsStable(t *testing.T) {
	t.Parallel()
	if len(Corpus) != 0 {
		t.Fatalf("Corpus should be empty until the fixture pack: got %d", len(Corpus))
	}
	want := []Kind{KindCrossTenant, KindMissingOwner, KindRelationMismatch}
	if KindCrossTenant != "cross_tenant" || KindMissingOwner != "missing_owner" || KindRelationMismatch != "relation_mismatch" {
		t.Fatalf("Kind constants changed: %v", want)
	}
}

type probeT struct {
	testing.TB
	failed bool
}

func (p *probeT) Helper() {}

func (p *probeT) Fatal(args ...any) {
	p.failed = true
}

func (p *probeT) Fatalf(format string, args ...any) {
	p.failed = true
	_ = fmt.Sprintf(format, args...)
}
