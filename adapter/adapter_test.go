package adapter_test

import (
	"testing"

	"github.com/BladiCreator/go-modular-auth/adapter"
)

func TestConditions(t *testing.T) {
	c1 := adapter.Eq("email", "test@example.com")
	if c1.Field != "email" || c1.Operator != adapter.OpEq || c1.Value != "test@example.com" {
		t.Errorf("unexpected Eq condition: %+v", c1)
	}

	c2 := adapter.Ne("status", "revoked")
	if c2.Operator != adapter.OpNe {
		t.Errorf("unexpected Ne operator: %v", c2.Operator)
	}

	c3 := adapter.In("role", "admin", "owner")
	if c3.Operator != adapter.OpIn {
		t.Errorf("unexpected In operator: %v", c3.Operator)
	}

	c4 := adapter.IsNull("used_at")
	if c4.Operator != adapter.OpIsNull || c4.Value != nil {
		t.Errorf("unexpected IsNull condition: %+v", c4)
	}

	c5 := adapter.IsNotNull("used_at")
	if c5.Operator != adapter.OpIsNotNull {
		t.Errorf("unexpected IsNotNull condition: %+v", c5)
	}
}
