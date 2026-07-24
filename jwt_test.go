package litellmauth

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func TestCredentialFreshUsesJWTExpiryWithClockSkew(t *testing.T) {
	now := time.Unix(1_784_800_000, 0)

	for _, test := range []struct {
		name  string
		exp   float64
		fresh bool
	}{
		{name: "outside skew", exp: float64(now.Unix() + 31), fresh: true},
		{name: "at skew", exp: float64(now.Unix() + 30), fresh: false},
		{name: "inside skew", exp: float64(now.Unix() + 29), fresh: false},
		{name: "fractional expiry", exp: float64(now.Unix()) + 30.5, fresh: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			credential := Credential{Key: jwtWithPayload(fmt.Sprintf(`{"exp":%v}`, test.exp))}
			if got := credential.Fresh(now); got != test.fresh {
				t.Fatalf("Fresh() = %v, want %v", got, test.fresh)
			}
		})
	}
}

func TestCredentialFreshValidJWTExpiryWinsOverTimestamp(t *testing.T) {
	now := time.Unix(1_784_800_000, 0)

	for _, credential := range []Credential{
		{Key: jwtWithPayload(fmt.Sprintf(`{"exp":%d}`, now.Unix()+60))},
		{Key: jwtWithPayload(fmt.Sprintf(`{"exp":%d}`, now.Unix()+60)), IssuedAt: now.Add(time.Hour)},
		{Key: jwtWithPayload(fmt.Sprintf(`{"exp":%d}`, now.Unix()+60)), IssuedAt: now.Add(-48 * time.Hour)},
	} {
		if !credential.Fresh(now) {
			t.Fatalf("Fresh() = false for %#v", credential)
		}
	}
}

func TestCredentialFreshFallsBackToTimestamp(t *testing.T) {
	now := time.Unix(1_784_800_000, 0)

	for _, test := range []struct {
		name      string
		key       string
		issuedAt  time.Time
		wantFresh bool
	}{
		{name: "opaque token", key: "sk-key", issuedAt: now.Add(-time.Hour), wantFresh: true},
		{name: "malformed JWT", key: "a.not-base64.b", issuedAt: now.Add(-time.Hour), wantFresh: true},
		{name: "missing exp", key: jwtWithPayload(`{"sub":"user"}`), issuedAt: now.Add(-time.Hour), wantFresh: true},
		{name: "string exp", key: jwtWithPayload(`{"exp":"never"}`), issuedAt: now.Add(-time.Hour), wantFresh: true},
		{name: "expired", key: "sk-key", issuedAt: now.Add(-24 * time.Hour), wantFresh: false},
		{name: "missing timestamp", key: "sk-key", wantFresh: false},
		{name: "future timestamp", key: "sk-key", issuedAt: now.Add(time.Second), wantFresh: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			credential := Credential{Key: test.key, IssuedAt: test.issuedAt}
			if got := credential.Fresh(now); got != test.wantFresh {
				t.Fatalf("Fresh() = %v, want %v", got, test.wantFresh)
			}
		})
	}
}

func TestCredentialAuthorizationHeaderValidatesKey(t *testing.T) {
	for _, test := range []struct {
		name string
		key  string
		want string
	}{
		{name: "valid", key: "sk-key", want: "Bearer sk-key"},
		{name: "empty"},
		{name: "ASCII space", key: "sk key"},
		{name: "Unicode space", key: "sk\u00a0key"},
		{name: "control", key: "sk\x00key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := (Credential{Key: test.key}).AuthorizationHeader(); got != test.want {
				t.Fatalf("AuthorizationHeader() = %q, want %q", got, test.want)
			}
		})
	}
}

func jwtWithPayload(payload string) string {
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}
