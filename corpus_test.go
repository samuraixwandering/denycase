package denycase

import (
	"fmt"
	"net/http"
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
// requires HeaderTenant to match the record. checkOwner applies to writes
// only: GET may succeed for any principal in the tenant.
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
		write := r.Method != http.MethodGet && r.Method != http.MethodHead
		if checkOwner && write && inv.owner != pid {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		writeInvoice(w, inv)
	})
}

func leakyForbidden(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, `{"tenant":"tenant-A","owner":"user-a","secret":"secret-a"}`, http.StatusForbidden)
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
	if len(Corpus) == 0 {
		t.Fatal("Corpus is empty")
	}
	seen := make(map[string]struct{}, len(Corpus))
	have := map[Kind]int{}
	for i, f := range Corpus {
		switch f.Kind {
		case KindCrossTenant, KindMissingOwner, KindRelationMismatch:
		default:
			t.Errorf("Corpus[%d] unknown kind %q", i, f.Kind)
		}
		have[f.Kind]++
		if f.Case.Name == "" {
			t.Errorf("Corpus[%d] empty name", i)
			continue
		}
		if _, ok := seen[f.Case.Name]; ok {
			t.Errorf("duplicate name %q", f.Case.Name)
		}
		seen[f.Case.Name] = struct{}{}
		if len(f.Case.Expect.BodyMustNot) == 0 {
			t.Errorf("%q has no BodyMustNot", f.Case.Name)
		}
	}
	for _, k := range []Kind{KindCrossTenant, KindMissingOwner, KindRelationMismatch} {
		if have[k] == 0 {
			t.Errorf("missing kind %s", k)
		}
	}
	if have[KindCrossTenant] < 2 {
		t.Error("want a cross-tenant read and write")
	}
}

func TestCorpusPassesOnTenantHandler(t *testing.T) {
	t.Parallel()
	h := demoHandler(true, true)
	for _, f := range Corpus {
		MustDeny(t, f.Case, h)
	}
}

func TestCorpusRejectsAllow(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(allowAll)
	for _, f := range Corpus {
		got := runMustDeny(t, f.Case, h)
		if !got.failed || !strings.Contains(got.msg, "status 200") {
			t.Errorf("%q: want status 200 fail, got failed=%v msg=%q panic=%v", f.Case.Name, got.failed, got.msg, got.panic)
		}
	}
}

func TestCorpusRejectsForbiddenLeak(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(leakyForbidden)
	for _, f := range Corpus {
		got := runMustDeny(t, f.Case, h)
		if !got.failed || !strings.Contains(got.msg, "leaked") {
			t.Errorf("%q: want leak fail, got failed=%v msg=%q panic=%v", f.Case.Name, got.failed, got.msg, got.panic)
		}
	}
}

func TestCorpusLookupByIDWithoutTenantFails(t *testing.T) {
	t.Parallel()
	h := demoHandler(false, false)
	for _, f := range Corpus {
		if f.Kind != KindMissingOwner && f.Kind != KindCrossTenant {
			continue
		}
		got := runMustDeny(t, f.Case, h)
		if !got.failed || !strings.Contains(got.msg, "status 200") {
			t.Errorf("%q: lookup-by-id should allow, got failed=%v msg=%q panic=%v", f.Case.Name, got.failed, got.msg, got.panic)
		}
	}
}

func TestCorpusNonOwnerWriteWithoutOwnerCheckFails(t *testing.T) {
	t.Parallel()
	h := demoHandler(true, false)
	for _, f := range Corpus {
		if f.Kind != KindRelationMismatch {
			MustDeny(t, f.Case, h)
			continue
		}
		got := runMustDeny(t, f.Case, h)
		if !got.failed || !strings.Contains(got.msg, "status 200") {
			t.Errorf("%q: tenant-only write should allow, got failed=%v msg=%q panic=%v", f.Case.Name, got.failed, got.msg, got.panic)
		}
	}
}

func TestCorpusOwnerReadIsNotDenied(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "owner read control",
		Principal: Principal{Tenant: "tenant-A", ID: "user-a"},
		Request:   Request{Method: http.MethodGet, Path: "/invoices/inv-a"},
		Expect: Expect{
			Status:      []int{http.StatusForbidden},
			BodyMustNot: []string{"secret-a"},
		},
	}, demoHandler(true, true))
	if !got.failed || !strings.Contains(got.msg, "status 200") {
		t.Fatalf("owner read should be 200, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
	}
}
