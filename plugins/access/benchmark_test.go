package access_test

import (
	"testing"

	"github.com/BladiCreator/go-modular-auth/plugins/access"
)

func BenchmarkRole_HasPermission(b *testing.B) {
	role := access.NewRole("bench_role", access.Statements{
		"project": {"create", "read", "update", "delete"},
		"user":    {"create", "read", "update", "delete"},
	}, true)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = role.HasPermission("project", "update")
	}
}

func BenchmarkRole_Authorize_SingleAction(b *testing.B) {
	role := access.NewRole("bench_role", access.Statements{
		"project": {"create", "read", "update", "delete"},
		"user":    {"create", "read", "update", "delete"},
	}, true)
	req := access.Req("project", "update")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = role.Authorize(req)
	}
}

func BenchmarkRole_Authorize_MultiResource_AND(b *testing.B) {
	role := access.NewRole("bench_role", access.Statements{
		"res1": {"act1", "act2"},
		"res2": {"act1", "act2"},
		"res3": {"act1", "act2"},
		"res4": {"act1", "act2"},
		"res5": {"act1", "act2"},
	}, true)

	req := access.NewAuthorizeRequest().
		Require("res1", "act1").
		Require("res2", "act2").
		Require("res3", "act1").
		Require("res4", "act2").
		Require("res5", "act1").
		Build()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = role.Authorize(req, access.ConnectorAND)
	}
}

func BenchmarkRole_Authorize_MultiResource_OR(b *testing.B) {
	role := access.NewRole("bench_role", access.Statements{
		"res1": {"act1"},
		"res2": {"act1"},
		"res3": {"act1"},
	}, true)

	req := access.NewAuthorizeRequest().
		Require("unknown1", "act1").
		Require("unknown2", "act1").
		Require("res3", "act1").
		Build()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = role.Authorize(req, access.ConnectorOR)
	}
}

func BenchmarkRole_Authorize_Wildcard(b *testing.B) {
	role := access.NewRole("superadmin", access.Statements{
		"*": {"*"},
	}, true)
	req := access.Req("anything", "any_action")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = role.Authorize(req)
	}
}

func BenchmarkAccessControl_AuthorizeRoles_Multi(b *testing.B) {
	ac := access.CreateAccessControl(nil)
	ac.MustNewRole("role_a", access.Statements{"res1": {"act1", "act2"}})
	ac.MustNewRole("role_b", access.Statements{"res2": {"act1", "act2"}})
	ac.MustNewRole("role_c", access.Statements{"res3": {"act1", "act2"}})

	roles := []string{"role_a", "role_b", "role_c"}
	req := access.Req("res2", "act1")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ac.AuthorizeRoles(roles, req)
	}
}
