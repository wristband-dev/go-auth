package goauth

import "testing"

// mockValueQuerier implements ValueQuerier for testing QuerierValueResolver.
type mockValueQuerier struct {
	values map[string]string
}

func (m *mockValueQuerier) Query(key string, defaultValue ...string) string {
	if val, ok := m.values[key]; ok {
		return val
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return ""
}

func TestQuerierValueResolver_Get(t *testing.T) {
	querier := &mockValueQuerier{values: map[string]string{
		"code":        "auth-code-123",
		"tenant_name": "acme",
	}}
	resolver := QuerierValueResolver{Querier: querier}

	if got := resolver.Get("code"); got != "auth-code-123" {
		t.Errorf("Expected %q, got %q", "auth-code-123", got)
	}
	if got := resolver.Get("tenant_name"); got != "acme" {
		t.Errorf("Expected %q, got %q", "acme", got)
	}
	if got := resolver.Get("missing"); got != "" {
		t.Errorf("Expected empty string for missing key, got %q", got)
	}
}

func TestQuerierValueResolver_Has(t *testing.T) {
	querier := &mockValueQuerier{values: map[string]string{
		"code": "abc",
	}}
	resolver := QuerierValueResolver{Querier: querier}

	if !resolver.Has("code") {
		t.Error("Expected Has(\"code\") to return true")
	}
	if resolver.Has("missing") {
		t.Error("Expected Has(\"missing\") to return false")
	}
}
