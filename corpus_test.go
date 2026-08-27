package denycase

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

type invoice struct {
	id, tenant, owner, secret string
}

var demoInvoices = map[string]invoice{
	"inv-a": {id: "inv-a", tenant: "tenant-A", owner: "user-a", secret: "secret-a"},
	"inv-b": {id: "inv-b", tenant: "tenant-B", owner: "user-b", secret: "secret-b"},
}

func invoiceFrom(r *http.Request) (invoice, bool) {
	id, ok := strings.CutPrefix(r.URL.Path, "/invoices/")
	if !ok || id == "" || strings.Contains(id, "/") {
		return invoice{}, false
	}
	inv, ok := demoInvoices[id]
	return inv, ok
}

func writeInvoice(w http.ResponseWriter, inv invoice) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"id":"%s","tenant":"%s","owner":"%s","secret":"%s"}`, inv.id, inv.tenant, inv.owner, inv.secret)
}

// demoHandler is a tiny invoice store used to prove Corpus. checkTenant
// requires HeaderTenant to match the record. checkOwner requires
// HeaderPrincipal to match the record owner on reads and writes.
func demoHandler(checkTenant, checkOwner bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inv, ok := invoiceFrom(r)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		tenant := r.Header.Get(HeaderTenant)
		pid := r.Header.Get(HeaderPrincipal)
		if checkTenant && inv.tenant != tenant {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if checkOwner && inv.owner != pid {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		writeInvoice(w, inv)
	})
}

func allowAll(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"tenant":"tenant-A","owner":"user-a","secret":"secret-a"}`))
}

func TestCorpusShape(t *testing.T) {
	t.Parallel()
	if KindCrossTenant != "cross_tenant" || KindMissingOwner != "missing_owner" || KindRelationMismatch != "relation_mismatch" {
		t.Fatal("Kind constants changed")
	}
	got := Corpus()
	if len(got) != 4 {
		t.Fatalf("Corpus() len %d, want 4; update README", len(got))
	}
	seenName := make(map[string]struct{}, len(got))
	seenReq := make(map[string]struct{}, len(got))
	have := map[Kind]int{}
	xtGet, xtPut := false, false
	for i, f := range got {
		switch f.Kind {
		case KindCrossTenant, KindMissingOwner, KindRelationMismatch:
		default:
			t.Errorf("Corpus()[%d] unknown kind %q", i, f.Kind)
		}
		have[f.Kind]++
		if f.Kind == KindCrossTenant {
			switch f.Case.Request.Method {
			case http.MethodGet:
				xtGet = true
			case http.MethodPut:
				xtPut = true
			}
		}
		if f.Case.Name == "" {
			t.Errorf("Corpus()[%d] empty name", i)
			continue
		}
		if _, ok := seenName[f.Case.Name]; ok {
			t.Errorf("duplicate name %q", f.Case.Name)
		}
		seenName[f.Case.Name] = struct{}{}
		reqKey := f.Case.Request.Method + "\x00" + f.Case.Request.Path + "\x00" + f.Case.Principal.Tenant + "\x00" + f.Case.Principal.ID
		if _, ok := seenReq[reqKey]; ok {
			t.Errorf("duplicate request %s %s as %s/%s", f.Case.Request.Method, f.Case.Request.Path, f.Case.Principal.Tenant, f.Case.Principal.ID)
		}
		seenReq[reqKey] = struct{}{}
		if len(f.Case.Expect.BodyMustNot) == 0 {
			t.Errorf("%q has no BodyMustNot", f.Case.Name)
		}
	}
	for _, k := range []Kind{KindCrossTenant, KindMissingOwner, KindRelationMismatch} {
		if have[k] == 0 {
			t.Errorf("missing kind %s", k)
		}
	}
	if !xtGet || !xtPut {
		t.Error("want a cross-tenant GET and PUT")
	}
}

func TestCorpusReturnsIndependentCopies(t *testing.T) {
	t.Parallel()
	a := Corpus()
	if len(a) == 0 || len(a[0].Case.Expect.BodyMustNot) == 0 {
		t.Fatal("empty corpus")
	}
	orig := a[0].Case.Expect.BodyMustNot[0]
	a[0].Case.Expect.BodyMustNot[0] = "mutated"
	a[0].Case.Expect.BodyMustNot = append(a[0].Case.Expect.BodyMustNot, "extra")
	for i := range a {
		if a[i].Case.Request.Header != nil {
			a[i].Case.Request.Header.Set("Content-Type", "mutated")
			break
		}
	}
	b := Corpus()
	if b[0].Case.Expect.BodyMustNot[0] != orig {
		t.Fatalf("needle %q became %q", orig, b[0].Case.Expect.BodyMustNot[0])
	}
	if slices.Contains(b[0].Case.Expect.BodyMustNot, "extra") {
		t.Fatal("append leaked into Corpus()")
	}
	for _, f := range b {
		if f.Case.Request.Header == nil {
			continue
		}
		if f.Case.Request.Header.Get("Content-Type") == "mutated" {
			t.Fatal("header mutation leaked into Corpus()")
		}
	}
}

func TestCorpusPassesOnTenantHandler(t *testing.T) {
	t.Parallel()
	h := demoHandler(true, true)
	for _, f := range Corpus() {
		t.Run(f.Case.Name, func(t *testing.T) {
			t.Parallel()
			MustDeny(t, f.Case, h)
		})
	}
}

func TestCorpusRejectsAllow(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(allowAll)
	for _, f := range Corpus() {
		t.Run(f.Case.Name, func(t *testing.T) {
			t.Parallel()
			got := runMustDeny(t, f.Case, h)
			if !got.failed || !strings.Contains(got.msg, "status 200") {
				t.Fatalf("want status 200 fail, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
			}
		})
	}
}

func TestCorpusRejectsForbiddenLeak(t *testing.T) {
	t.Parallel()
	for _, f := range Corpus() {
		t.Run(f.Case.Name, func(t *testing.T) {
			t.Parallel()
			for _, needle := range f.Case.Expect.BodyMustNot {
				t.Run(needle, func(t *testing.T) {
					t.Parallel()
					h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						http.Error(w, needle, http.StatusForbidden)
					})
					got := runMustDeny(t, f.Case, h)
					if !got.failed || !strings.Contains(got.msg, "leaked") || !strings.Contains(got.msg, needle) {
						t.Fatalf("want leak of %q, got failed=%v msg=%q panic=%v", needle, got.failed, got.msg, got.panic)
					}
				})
			}
		})
	}
}

func TestCorpusLookupByIDWithoutTenantFails(t *testing.T) {
	t.Parallel()
	h := demoHandler(false, false)
	for _, f := range Corpus() {
		t.Run(f.Case.Name, func(t *testing.T) {
			t.Parallel()
			got := runMustDeny(t, f.Case, h)
			if !got.failed || !strings.Contains(got.msg, "status 200") {
				t.Fatalf("lookup-by-id should allow, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
			}
		})
	}
}

func TestCorpusTenantOnlyAllowsSameTenantNonOwner(t *testing.T) {
	t.Parallel()
	h := demoHandler(true, false)
	for _, f := range Corpus() {
		t.Run(f.Case.Name, func(t *testing.T) {
			t.Parallel()
			switch f.Kind {
			case KindCrossTenant:
				MustDeny(t, f.Case, h)
			case KindMissingOwner, KindRelationMismatch:
				got := runMustDeny(t, f.Case, h)
				if !got.failed || !strings.Contains(got.msg, "status 200") {
					t.Fatalf("tenant-only should allow, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
				}
			default:
				t.Fatalf("unexpected kind %q", f.Kind)
			}
		})
	}
}

func TestCorpusOwnerReadIsNotDenied(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "owner read control",
		Principal: Principal{Tenant: "tenant-A", ID: "user-a"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/inv-a"},
		Expect:    denied("secret-a"),
	}, demoHandler(true, true))
	if !got.failed || !strings.Contains(got.msg, "status 200") {
		t.Fatalf("owner read should be 200, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
	}
}

func TestCorpusOwnerWriteIsNotDenied(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "owner write control",
		Principal: Principal{Tenant: "tenant-A", ID: "user-a"},
		Request:   jsonWrite(http.MethodPut, "/invoices/inv-a"),
		Expect:    denied("secret-a"),
	}, demoHandler(true, true))
	if !got.failed || !strings.Contains(got.msg, "status 200") {
		t.Fatalf("owner write should be 200, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
	}
}

func TestCorpusTenantBReadIsNotDenied(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "tenant-B read control",
		Principal: Principal{Tenant: "tenant-B", ID: "user-b"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/inv-b"},
		Expect:    denied("secret-b"),
	}, demoHandler(true, true))
	if !got.failed || !strings.Contains(got.msg, "status 200") {
		t.Fatalf("tenant-B read of inv-b should be 200, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
	}
}

func TestCorpusOwnerWithoutTenantAllowsCollidingID(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "colliding owner id",
		Principal: Principal{Tenant: "tenant-B", ID: "user-a"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/inv-a"},
		Expect:    denied("secret-a", "tenant-A"),
	}, demoHandler(false, true))
	if !got.failed || !strings.Contains(got.msg, "status 200") {
		t.Fatalf("owner-only check should allow tenant-B/user-a, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
	}
}
