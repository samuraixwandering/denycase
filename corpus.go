package denycase

import "net/http"

// Corpus is the shipped deny cases for a toy invoice resource:
// inv-a belongs to tenant-A / user-a; user-c is in tenant-A but not the owner;
// user-b is in tenant-B. Copy a case and change Principal, Path, and
// BodyMustNot to match the handler under test. Do not mutate Corpus.
var Corpus = []Fixture{
	{
		Kind: KindCrossTenant,
		Case: Case{
			Name:      "cross-tenant read",
			Principal: Principal{Tenant: "tenant-B", ID: "user-b"},
			Request:   Request{Method: http.MethodGet, Path: "/invoices/inv-a"},
			Expect: Expect{
				Status:      []int{http.StatusForbidden},
				BodyMustNot: []string{"tenant-A", "secret-a"},
			},
		},
	},
	{
		Kind: KindCrossTenant,
		Case: Case{
			Name:      "cross-tenant write",
			Principal: Principal{Tenant: "tenant-B", ID: "user-b"},
			Request:   Request{Method: http.MethodPut, Path: "/invoices/inv-a"},
			Expect: Expect{
				Status:      []int{http.StatusForbidden},
				BodyMustNot: []string{"tenant-A", "secret-a"},
			},
		},
	},
	{
		// Same HTTP as cross-tenant read. The kind is CWE-862: load by id, no tenant predicate.
		Kind: KindMissingOwner,
		Case: Case{
			Name:      "get by id without tenant",
			Principal: Principal{Tenant: "tenant-B", ID: "user-b"},
			Request:   Request{Method: http.MethodGet, Path: "/invoices/inv-a"},
			Expect: Expect{
				Status:      []int{http.StatusForbidden},
				BodyMustNot: []string{"tenant-A", "secret-a"},
			},
		},
	},
	{
		Kind: KindRelationMismatch,
		Case: Case{
			Name:      "non-owner write",
			Principal: Principal{Tenant: "tenant-A", ID: "user-c"},
			Request:   Request{Method: http.MethodPut, Path: "/invoices/inv-a"},
			Expect: Expect{
				Status:      []int{http.StatusForbidden},
				BodyMustNot: []string{"secret-a", "user-a"},
			},
		},
	},
}
