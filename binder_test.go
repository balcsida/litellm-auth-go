package litellmauth

import (
	"net/http"
	"strings"
	"testing"
)

func TestHeaderBinders(t *testing.T) {
	tests := []struct {
		name   string
		new    func() (Binder, error)
		header string
		want   string
	}{
		{
			name: "bearer",
			new: func() (Binder, error) {
				return NewBearerHeader("Authorization")
			},
			header: "Authorization",
			want:   "Bearer sk-key",
		},
		{
			name: "raw",
			new: func() (Binder, error) {
				return NewRawHeader("X-API-Key")
			},
			header: "X-API-Key",
			want:   "sk-key",
		},
		{
			name: "prefixed",
			new: func() (Binder, error) {
				return NewPrefixedHeader("Authorization", "token")
			},
			header: "Authorization",
			want:   "token sk-key",
		},
		{
			name: "mcp",
			new: func() (Binder, error) {
				return NewMCPBearerHeader("github")
			},
			header: "X-Mcp-Github-Authorization",
			want:   "Bearer sk-key",
		},
		{
			name: "a2a",
			new: func() (Binder, error) {
				return NewA2ABearerHeader("research-agent")
			},
			header: "X-A2a-Research-Agent-Authorization",
			want:   "Bearer sk-key",
		},
	}

	credential := Credential{
		Key: "sk-key", AuthMethod: AuthMethodStatic, NonExpiring: true,
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binder, err := test.new()
			if err != nil {
				t.Fatal(err)
			}
			request, _ := http.NewRequest(http.MethodGet, "https://proxy.example.com", nil)
			if err := binder.Bind(request, credential); err != nil {
				t.Fatal(err)
			}
			if got := request.Header.Get(test.header); got != test.want {
				t.Fatalf("header = %q, want %q", got, test.want)
			}
		})
	}
}

func TestHeaderBinderRejectsInvalidInputsWithoutLeakingKey(t *testing.T) {
	for _, create := range []func() (Binder, error){
		func() (Binder, error) { return NewBearerHeader("Bad\nHeader") },
		func() (Binder, error) { return NewPrefixedHeader("Authorization", "bad prefix") },
		func() (Binder, error) { return NewMCPBearerHeader("../bad") },
		func() (Binder, error) { return NewA2ABearerHeader("") },
	} {
		if _, err := create(); err == nil {
			t.Fatal("binder constructor accepted invalid input")
		}
	}

	binder, err := NewBearerHeader("Authorization")
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://proxy.example.com", nil)
	err = binder.Bind(request, Credential{
		Key: "secret token", AuthMethod: AuthMethodStatic, NonExpiring: true,
	})
	if err == nil || strings.Contains(err.Error(), "secret token") {
		t.Fatalf("Bind() error = %v", err)
	}
}
