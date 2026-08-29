package denycase

import (
	"bytes"
	"fmt"
	"io"
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

func invoiceJSON(inv invoice) string {
	return fmt.Sprintf(`{"id":"%s","tenant":"%s","owner":"%s","secret":"%s"}`, inv.id, inv.tenant, inv.owner, inv.secret)
}

func writeInvoice(w http.ResponseWriter, inv invoice) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, invoiceJSON(inv))
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
	if len(got) != 5 {
		t.Fatalf("Corpus() len %d, want 5; update README", len(got))
	}
	seenName := make(map[string]struct{}, len(got))
	seenReq := make(map[string]struct{}, len(got))
	have := map[Kind]int{}
	xtGet, xtPut := false, false
	relGet, relPut := false, false
	moGet := false
	for i, f := range got {
		switch f.Kind {
		case KindCrossTenant, KindMissingOwner, KindRelationMismatch:
		default:
			t.Errorf("Corpus()[%d] unknown kind %q", i, f.Kind)
		}
		have[f.Kind]++
		switch f.Kind {
		case KindCrossTenant:
			switch f.Case.Request.Method {
			case http.MethodGet:
				xtGet = true
			case http.MethodPut:
				xtPut = true
			}
		case KindRelationMismatch:
			switch f.Case.Request.Method {
			case http.MethodGet:
				relGet = true
			case http.MethodPut:
				relPut = true
			}
		case KindMissingOwner:
			if f.Case.Request.Method == http.MethodGet {
				moGet = true
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
		if !slices.Equal(f.Case.Expect.Status, []int{http.StatusForbidden}) {
			t.Errorf("%q Status %v, want [403]", f.Case.Name, f.Case.Expect.Status)
		}
		hasUserA := slices.Contains(f.Case.Expect.BodyMustNot, "user-a")
		if f.Case.Principal.ID == "user-a" {
			if hasUserA {
				t.Errorf("%q caller is user-a; user-a needle would false-fail", f.Case.Name)
			}
		} else if f.Case.Principal.Tenant == "tenant-B" && !hasUserA {
			t.Errorf("%q tenant-B caller missing user-a needle", f.Case.Name)
		}
		if f.Case.Request.Header == nil {
			t.Errorf("%q Header is nil", f.Case.Name)
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
	if !relGet || !relPut {
		t.Error("want a relation_mismatch GET and PUT")
	}
	if !moGet {
		t.Error("want a missing_owner GET")
	}
}

func TestCorpusReturnsIndependentCopies(t *testing.T) {
	t.Parallel()
	a := Corpus()
	if len(a) < 2 {
		t.Fatal("empty corpus")
	}
	var put *Case
	for i := range a {
		if len(a[i].Case.Request.Body) > 0 && a[i].Case.Request.Header != nil && len(a[i].Case.Request.Header["Content-Type"]) > 0 {
			put = &a[i].Case
			break
		}
	}
	if put == nil || len(a[0].Case.Expect.BodyMustNot) == 0 || len(a[0].Case.Expect.Status) == 0 {
		t.Fatal("need a GET with needles/status and a PUT with body/header")
	}
	origNeedle := a[0].Case.Expect.BodyMustNot[0]
	origStatus := a[0].Case.Expect.Status[0]
	origBody := put.Request.Body[0]
	origCT := put.Request.Header["Content-Type"][0]
	a[0].Case.Expect.BodyMustNot[0] = "mutated"
	a[0].Case.Expect.Status[0] = http.StatusNotFound
	put.Request.Body[0] ^= 0xff
	put.Request.Header["Content-Type"][0] = "x"

	b := Corpus()
	if b[0].Case.Expect.BodyMustNot[0] != origNeedle {
		t.Fatalf("BodyMustNot %q became %q", origNeedle, b[0].Case.Expect.BodyMustNot[0])
	}
	if b[0].Case.Expect.Status[0] != origStatus {
		t.Fatalf("Status %d became %d", origStatus, b[0].Case.Expect.Status[0])
	}
	var putB *Case
	for i := range b {
		if len(b[i].Case.Request.Body) > 0 && b[i].Case.Request.Header != nil && len(b[i].Case.Request.Header["Content-Type"]) > 0 {
			putB = &b[i].Case
			break
		}
	}
	if putB == nil {
		t.Fatal("PUT missing after clone")
	}
	if putB.Request.Body[0] != origBody {
		t.Fatalf("Body[0] %q became %q", origBody, putB.Request.Body[0])
	}
	if putB.Request.Header["Content-Type"][0] != origCT {
		t.Fatalf("Content-Type %q became %q", origCT, putB.Request.Header["Content-Type"][0])
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

func TestCorpusRejectsForbiddenRecordLeak(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inv, ok := invoiceFrom(r)
		if !ok {
			inv = demoInvoices["inv-a"]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, invoiceJSON(inv))
	})
	for _, f := range Corpus() {
		t.Run(f.Case.Name, func(t *testing.T) {
			t.Parallel()
			got := runMustDeny(t, f.Case, h)
			if !got.failed || !strings.Contains(got.msg, "leaked") {
				t.Fatalf("want record leak, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
			}
		})
	}
}

func TestCorpusWriteSendsJSONBody(t *testing.T) {
	t.Parallel()
	var want []byte
	var wantCT string
	for _, f := range Corpus() {
		if f.Case.Request.Method == http.MethodPut {
			want = slices.Clone(f.Case.Request.Body)
			wantCT = f.Case.Request.Header.Get("Content-Type")
			break
		}
	}
	if len(want) == 0 || wantCT == "" {
		t.Fatal("no PUT fixture with body and Content-Type")
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(got, want) || r.Header.Get("Content-Type") != wantCT {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	for _, f := range Corpus() {
		if f.Case.Request.Method != http.MethodPut {
			continue
		}
		t.Run(f.Case.Name, func(t *testing.T) {
			t.Parallel()
			MustDeny(t, f.Case, h)
		})
	}
}

func TestCorpusAllowsWhenNoChecks(t *testing.T) {
	t.Parallel()
	h := demoHandler(false, false)
	for _, f := range Corpus() {
		t.Run(f.Case.Name, func(t *testing.T) {
			t.Parallel()
			got := runMustDeny(t, f.Case, h)
			if !got.failed || !strings.Contains(got.msg, "status 200") {
				t.Fatalf("no-check handler should allow (paths must hit records), got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
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
			case KindCrossTenant, KindMissingOwner:
				MustDeny(t, f.Case, h)
			case KindRelationMismatch:
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

func TestCorpusWriteOnlyOwnerAllowsNonOwnerRead(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inv, ok := invoiceFrom(r)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if inv.tenant != r.Header.Get(HeaderTenant) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		write := r.Method != http.MethodGet && r.Method != http.MethodHead
		if write && inv.owner != r.Header.Get(HeaderPrincipal) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		writeInvoice(w, inv)
	})
	for _, f := range Corpus() {
		t.Run(f.Case.Name, func(t *testing.T) {
			t.Parallel()
			if f.Kind == KindRelationMismatch && f.Case.Request.Method == http.MethodGet {
				got := runMustDeny(t, f.Case, h)
				if !got.failed || !strings.Contains(got.msg, "status 200") {
					t.Fatalf("non-owner read should be 200, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
				}
				return
			}
			MustDeny(t, f.Case, h)
		})
	}
}

func TestCorpusOwnerReadIsNotDenied(t *testing.T) {
	t.Parallel()
	got := runMustDeny(t, Case{
		Name:      "owner read control",
		Principal: Principal{Tenant: "tenant-A", ID: "user-a"},
		Request:   getReq("/invoices/inv-a"),
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
		Request:   getReq("/invoices/inv-b"),
		Expect:    denied("secret-b"),
	}, demoHandler(true, true))
	if !got.failed || !strings.Contains(got.msg, "status 200") {
		t.Fatalf("tenant-B read of inv-b should be 200, got failed=%v msg=%q panic=%v", got.failed, got.msg, got.panic)
	}
}

func TestCorpusOwnerWithoutTenantAllowsCollidingID(t *testing.T) {
	t.Parallel()
	h := demoHandler(false, true)
	n := 0
	for _, f := range Corpus() {
		if f.Kind != KindMissingOwner {
			continue
		}
		n++
		got := runMustDeny(t, f.Case, h)
		if !got.failed || !strings.Contains(got.msg, "status 200") {
			t.Fatalf("%q: owner-only check should allow colliding id, got failed=%v msg=%q panic=%v", f.Case.Name, got.failed, got.msg, got.panic)
		}
	}
	if n == 0 {
		t.Fatal("no missing_owner fixture")
	}
}
