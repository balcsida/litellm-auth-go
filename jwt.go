package litellmauth

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	credentialLifetime  = 24 * time.Hour
	credentialClockSkew = 30 * time.Second
)

// Fresh reports whether c is valid at now, with a small expiry safety margin.
func (c Credential) Fresh(now time.Time) bool {
	expiresAt := c.Expiry()
	if expiresAt.IsZero() {
		return false
	}
	if !c.IssuedAt.IsZero() && c.IssuedAt.After(now) {
		if _, ok := jwtExpiry(c.Key); !ok {
			return false
		}
	}
	return now.Add(credentialClockSkew).Before(expiresAt)
}

// Expiry returns the explicit, JWT, or compatibility expiry for c.
func (c Credential) Expiry() time.Time {
	if !c.ExpiresAt.IsZero() {
		return c.ExpiresAt
	}
	if expiresAt, ok := jwtExpiry(c.Key); ok {
		return expiresAt
	}
	if c.IssuedAt.IsZero() {
		return time.Time{}
	}
	return c.IssuedAt.Add(credentialLifetime)
}

// AuthorizationHeader returns c as a valid Bearer authorization header.
func (c Credential) AuthorizationHeader() string {
	if c.Key == "" || containsKeySpaceOrControl(c.Key) {
		return ""
	}
	return "Bearer " + c.Key
}

func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Expires json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Expires == "" {
		return time.Time{}, false
	}
	value, err := strconv.ParseFloat(string(claims.Expires), 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) || value < math.MinInt64 || value > math.MaxInt64 {
		return time.Time{}, false
	}
	seconds, fraction := math.Modf(value)
	return time.Unix(int64(seconds), int64(fraction*float64(time.Second))), true
}

func containsKeySpaceOrControl(key string) bool {
	return strings.IndexFunc(key, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0
}
