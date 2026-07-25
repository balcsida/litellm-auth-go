package litellmauth

import (
	"encoding/base64"
	"errors"
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

func TestCredentialFreshHonorsExpiresAt(t *testing.T) {
	now := time.Unix(1_784_800_000, 0)
	for _, test := range []struct {
		name       string
		credential Credential
		fresh      bool
	}{
		{
			name:       "explicit fresh",
			credential: Credential{Key: "sk-key", ExpiresAt: now.Add(31 * time.Second)},
			fresh:      true,
		},
		{
			name: "explicit stale overrides JWT",
			credential: Credential{
				Key:       jwtWithPayload(fmt.Sprintf(`{"exp":%d}`, now.Add(time.Hour).Unix())),
				ExpiresAt: now.Add(30 * time.Second),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.credential.Fresh(now); got != test.fresh {
				t.Fatalf("Fresh() = %v, want %v", got, test.fresh)
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

func TestCredentialFreshnessByAuthenticationMethod(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		credential Credential
		fresh      bool
	}{
		{
			name:       "legacy SSO fallback",
			credential: Credential{Key: "sk-legacy", IssuedAt: now.Add(-time.Hour)},
			fresh:      true,
		},
		{
			name: "explicit SSO fallback",
			credential: Credential{
				Key: "sk-sso", AuthMethod: AuthMethodLiteLLMSSO,
				IssuedAt: now.Add(-time.Hour),
			},
			fresh: true,
		},
		{
			name: "non-expiring static",
			credential: Credential{
				Key: "sk-static", AuthMethod: AuthMethodStatic, NonExpiring: true,
			},
			fresh: true,
		},
		{
			name: "generic unknown expiry",
			credential: Credential{
				Key: "sk-env", AuthMethod: AuthMethodEnvironment,
			},
			fresh: false,
		},
		{
			name: "generic explicit expiry",
			credential: Credential{
				Key: "sk-file", AuthMethod: AuthMethodFile,
				ExpiresAt: now.Add(time.Hour),
			},
			fresh: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.credential.Fresh(now); got != test.fresh {
				t.Fatalf("Fresh() = %v, want %v", got, test.fresh)
			}
		})
	}
}

func TestCredentialExpiryUsesEarliestKnownDeadline(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	jwtExpiryTime := now.Add(time.Hour)
	credential := Credential{
		Key:        jwtWithPayload(fmt.Sprintf(`{"exp":%d}`, jwtExpiryTime.Unix())),
		AuthMethod: AuthMethodExec,
		ExpiresAt:  now.Add(2 * time.Hour),
	}
	if got := credential.Expiry(); !got.Equal(jwtExpiryTime) {
		t.Fatalf("Expiry() = %s, want %s", got, jwtExpiryTime)
	}
}

func TestCredentialValidateRejectsAmbiguousLifetime(t *testing.T) {
	if err := (Credential{
		Key: "sk-env", AuthMethod: AuthMethodEnvironment,
	}).Validate(); !errors.Is(err, ErrCredentialExpiryUnknown) {
		t.Fatalf("Validate() error = %v", err)
	}

	jwt := jwtWithPayload(`{"exp":4102444800}`)
	if err := (Credential{
		Key: jwt, AuthMethod: AuthMethodStatic, NonExpiring: true,
	}).Validate(); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Validate() error = %v", err)
	}

	if err := (Credential{
		Key: "sk-key", AuthMethod: AuthMethodStatic, NonExpiring: true,
		Scopes: []string{"bad\nscope"},
	}).Validate(); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Validate() control-character error = %v", err)
	}
}

func jwtWithPayload(payload string) string {
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}
