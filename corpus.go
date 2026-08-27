package denycase

import (
	"bytes"
	"net/http"
	"slices"
)

func denied(needles ...string) Expect {
	e := Denied()
	e.BodyMustNot = needles
	return e
}

func jsonWrite(method, path string) Request {
	return Request{
		Method: method,
		Path:   path,
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   []byte(`{"note":"updated"}`),
	}
}

var corpus = []Fixture{
	{
		Kind: KindCrossTenant,
		Case: Case{
			Name:      "cross-tenant read",
			Principal: Principal{Tenant: "tenant-B", ID: "user-b"},
			Request:   Request{Method: http.MethodGet, Path: "/invoices/inv-a"},
			Expect:    denied("tenant-A", "secret-a", "user-a"),
		},
	},
	{
		Kind: KindCrossTenant,
		Case: Case{
			Name:      "cross-tenant write",
			Principal: Principal{Tenant: "tenant-B", ID: "user-b"},
			Request:   jsonWrite(http.MethodPut, "/invoices/inv-a"),
			Expect:    denied("tenant-A", "secret-a", "user-a"),
		},
	},
	{
		Kind: KindMissingOwner,
		Case: Case{
			Name:      "non-owner read",
			Principal: Principal{Tenant: "tenant-A", ID: "user-c"},
			Request:   Request{Method: http.MethodGet, Path: "/invoices/inv-a"},
			Expect:    denied("secret-a", "user-a"),
		},
	},
	{
		Kind: KindRelationMismatch,
		Case: Case{
			Name:      "non-owner write",
			Principal: Principal{Tenant: "tenant-A", ID: "user-c"},
			Request:   jsonWrite(http.MethodPut, "/invoices/inv-a"),
			Expect:    denied("secret-a", "user-a"),
		},
	},
}

// Corpus returns a copy of the shipped deny cases for a toy invoice resource:
// inv-a belongs to tenant-A / user-a; user-c is in tenant-A but not the owner;
// user-b is in tenant-B. Copy a case and change Principal, Path, BodyMustNot,
// and on writes Body and Header, to match the handler under test. Set Status
// if the handler denies with 404.
func Corpus() []Fixture {
	out := make([]Fixture, len(corpus))
	for i, f := range corpus {
		out[i] = Fixture{Kind: f.Kind, Case: cloneCase(f.Case)}
	}
	return out
}

func cloneCase(c Case) Case {
	out := c
	out.Expect.Status = slices.Clone(c.Expect.Status)
	out.Expect.BodyMustNot = slices.Clone(c.Expect.BodyMustNot)
	out.Expect.HeaderMustNot = slices.Clone(c.Expect.HeaderMustNot)
	out.Request.Body = bytes.Clone(c.Request.Body)
	out.Request.Header = c.Request.Header.Clone()
	return out
}
