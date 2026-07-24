package tokenstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	litellmauth "github.com/balcsida/litellm-auth-go"
)

func TestFileStoreSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "token.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	issuedAt := time.Unix(1_784_800_000, 123_000_000)
	want := litellmauth.Credential{
		BaseURL:             "HTTPS://GATEWAY.EXAMPLE.COM:443/proxy///",
		Key:                 "sk-key",
		UserID:              "user@example.com",
		TeamID:              "team-1",
		TeamAlias:           "Engineering",
		Teams:               []litellmauth.Team{{ID: "team-1", Alias: "Engineering"}, {ID: "team-2", Alias: "Support"}},
		AttributionMetadata: map[string]any{"department": "Engineering", "active": true, "score": float64(1)},
		IssuedAt:            issuedAt,
	}
	if err := store.Save(context.Background(), want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	for _, secretField := range []string{"poll_secret", "Session", "session"} {
		if strings.Contains(string(raw), secretField) {
			t.Fatalf("saved JSON contains %q: %s", secretField, raw)
		}
	}
	var saved map[string]any
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("saved JSON is invalid: %v", err)
	}
	if saved["base_url"] != "https://gateway.example.com/proxy" ||
		saved["user_email"] != "unknown" ||
		saved["user_role"] != "cli" ||
		saved["auth_header_name"] != "Authorization" ||
		saved["jwt_token"] != "" ||
		saved["timestamp"] != 1_784_800_000.123 {
		t.Fatalf("saved compatibility fields = %#v", saved)
	}
	if _, ok := saved["expires_at"]; ok {
		t.Fatalf("saved incompatible expires_at field: %#v", saved)
	}
	if got := saved["teams"].([]any); len(got) != 2 || got[0] != "team-1" || got[1] != "team-2" {
		t.Fatalf("saved teams = %#v", got)
	}
	if saved["team_alias"] != "Engineering" {
		t.Fatalf("saved team_alias = %#v", saved["team_alias"])
	}

	explicit, _ := url.Parse("https://gateway.example.com:443/proxy/")
	got, err := store.Load(context.Background(), explicit)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.BaseURL != "https://gateway.example.com/proxy" || got.Key != want.Key || got.UserID != want.UserID || got.TeamID != want.TeamID || got.TeamAlias != want.TeamAlias {
		t.Fatalf("Load() scalar fields differ")
	}
	if !got.IssuedAt.Equal(want.IssuedAt) {
		t.Fatalf("IssuedAt = %s, want %s", got.IssuedAt, want.IssuedAt)
	}
	if wantExpiry := want.IssuedAt.Add(24 * time.Hour); !got.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("ExpiresAt = %s, want %s", got.ExpiresAt, wantExpiry)
	}
	if len(got.Teams) != 2 || got.Teams[1] != want.Teams[1] {
		t.Fatalf("Teams = %#v, want %#v", got.Teams, want.Teams)
	}
	if got.AttributionMetadata["department"] != "Engineering" {
		t.Fatalf("AttributionMetadata = %#v", got.AttributionMetadata)
	}
}

func TestFileStoreLoadOriginBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	writeTokenFile(t, path, `{"base_url":"HTTP://EXAMPLE.COM:80/full/path///","key":"sk-key","timestamp":1784800000}`)

	for _, raw := range []string{
		"http://example.com/full/path",
		"HTTP://EXAMPLE.COM:80/full/path/",
	} {
		explicit, _ := url.Parse(raw)
		if _, err := store.Load(context.Background(), explicit); err != nil {
			t.Fatalf("Load(%q) error = %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://example.com",
		"http://example.com/full/other",
		"https://example.com/full/path",
	} {
		explicit, _ := url.Parse(raw)
		if _, err := store.Load(context.Background(), explicit); !errors.Is(err, litellmauth.ErrOriginMismatch) {
			t.Fatalf("Load(%q) error = %v, want ErrOriginMismatch", raw, err)
		}
	}
}

func TestFileStoreLoadLegacyAndUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	writeTokenFile(t, path, `{
		"key":"sk-key",
		"timestamp":1784800000.125,
		"team_id":"team-1",
		"teams":["team-1"],
		"team_alias":"Engineering",
		"team_details":[{"team_id":"team-1","team_alias":"Engineering"}],
		"future_field":{"anything":true}
	}`)

	got, err := store.Load(context.Background(), nil)
	if err != nil {
		t.Fatalf("Load(nil) error = %v", err)
	}
	if got.BaseURL != "" || got.TeamAlias != "Engineering" || len(got.Teams) != 1 || got.Teams[0] != (litellmauth.Team{ID: "team-1", Alias: "Engineering"}) {
		t.Fatalf("Load(nil) = %#v", got)
	}
	explicit, _ := url.Parse("https://gateway.example.com")
	if _, err := store.Load(context.Background(), explicit); !errors.Is(err, litellmauth.ErrOriginMismatch) {
		t.Fatalf("Load(explicit) error = %v, want ErrOriginMismatch", err)
	}
}

func TestFileStoreLoadTimestampVariants(t *testing.T) {
	now := time.Unix(1_784_800_100, 0)
	for _, test := range []struct {
		name      string
		body      string
		issuedAt  time.Time
		wantFresh bool
	}{
		{name: "missing", body: `{"key":"sk-key"}`},
		{name: "zero", body: `{"key":"sk-key","timestamp":0}`},
		{name: "fractional", body: `{"key":"sk-key","timestamp":1784800000.125}`, issuedAt: time.Unix(1_784_800_000, 125_000_000), wantFresh: true},
		{name: "future", body: `{"key":"sk-key","timestamp":1784800101}`, issuedAt: now.Add(time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token.json")
			store, _ := NewFileStore(path)
			writeTokenFile(t, path, test.body)
			got, err := store.Load(context.Background(), nil)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if !got.IssuedAt.Equal(test.issuedAt) || got.Fresh(now) != test.wantFresh {
				t.Fatalf("IssuedAt = %s, Fresh() = %v", got.IssuedAt, got.Fresh(now))
			}
		})
	}
}

func TestFileStoreLoadPopulatesJWTExpiry(t *testing.T) {
	expiresAt := time.Unix(1_784_803_600, 0)
	token := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1784803600}`)) + ".signature"
	path := filepath.Join(t.TempDir(), "token.json")
	store, _ := NewFileStore(path)
	writeTokenFile(t, path, `{"key":"`+token+`","timestamp":1784800000}`)

	got, err := store.Load(context.Background(), nil)
	if err != nil || !got.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("Load() = %#v, %v; expiry want %s", got, err, expiresAt)
	}
}

func TestFileStoreRejectsMalformedFiles(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: `{"key":`},
		{name: "trailing JSON", body: `{"key":"sk-key"} {}`},
		{name: "empty key", body: `{"key":""}`},
		{name: "key whitespace", body: `{"key":"sk key"}`},
		{name: "key Unicode whitespace", body: `{"key":"sk\u00a0key"}`},
		{name: "key control", body: `{"key":"sk\u0000key"}`},
		{name: "metadata null", body: `{"key":"sk-key","attribution_metadata":null}`},
		{name: "metadata nested", body: `{"key":"sk-key","attribution_metadata":{"nested":{}}}`},
		{name: "invalid base URL", body: `{"base_url":"https://user@example.com","key":"sk-key"}`},
		{name: "base URL query", body: `{"base_url":"https://example.com?x=1","key":"sk-key"}`},
		{name: "null timestamp", body: `{"key":"sk-key","timestamp":null}`},
		{name: "invalid timestamp", body: `{"key":"sk-key","timestamp":"today"}`},
		{name: "invalid teams", body: `{"key":"sk-key","teams":[1]}`},
		{name: "invalid team details", body: `{"key":"sk-key","team_details":[{"team_alias":"Missing ID"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token.json")
			store, _ := NewFileStore(path)
			writeTokenFile(t, path, test.body)
			if _, err := store.Load(context.Background(), nil); !errors.Is(err, litellmauth.ErrProtocol) {
				t.Fatalf("Load() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestFileStoreRejectsCredentialKeyInMetadata(t *testing.T) {
	t.Run("load", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token.json")
		store, _ := NewFileStore(path)
		writeTokenFile(t, path, `{"key":"secret-key","user_id":"user-secret-key"}`)

		if _, err := store.Load(context.Background(), nil); !errors.Is(err, litellmauth.ErrProtocol) {
			t.Fatalf("Load() error = %v, want ErrProtocol", err)
		}
	})

	t.Run("load metadata key", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token.json")
		store, _ := NewFileStore(path)
		writeTokenFile(t, path, `{"key":"secret-key","attribution_metadata":{"field-secret-key":"department"}}`)

		if _, err := store.Load(context.Background(), nil); !errors.Is(err, litellmauth.ErrProtocol) {
			t.Fatalf("Load() error = %v, want ErrProtocol", err)
		}
	})

	t.Run("save", func(t *testing.T) {
		path := filepath.Join(privateTempDir(t), "token.json")
		store, _ := NewFileStore(path)
		credential := validCredential("secret-key")
		credential.AttributionMetadata = map[string]any{"department": "dept-secret-key"}

		if err := store.Save(context.Background(), credential); !errors.Is(err, litellmauth.ErrProtocol) {
			t.Fatalf("Save() error = %v, want ErrProtocol", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Save() wrote unsafe credential: %v", err)
		}
	})

	t.Run("save metadata key", func(t *testing.T) {
		path := filepath.Join(privateTempDir(t), "token.json")
		store, _ := NewFileStore(path)
		credential := validCredential("secret-key")
		credential.AttributionMetadata = map[string]any{"field-secret-key": "department"}

		if err := store.Save(context.Background(), credential); !errors.Is(err, litellmauth.ErrProtocol) {
			t.Fatalf("Save() error = %v, want ErrProtocol", err)
		}
	})
}

func TestFileStoreRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	store, _ := NewFileStore(path)
	writeTokenFile(t, path, `{"key":"sk-key","padding":"`+strings.Repeat("x", 1<<20)+`"}`)

	if _, err := store.Load(context.Background(), nil); !errors.Is(err, litellmauth.ErrProtocol) {
		t.Fatalf("Load() error = %v, want ErrProtocol", err)
	}
}

func TestFileStoreMissingDoesNotCreateDirectories(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	store, _ := NewFileStore(filepath.Join(dir, "token.json"))

	if _, err := store.Load(context.Background(), nil); !errors.Is(err, litellmauth.ErrNoCredential) {
		t.Fatalf("Load() error = %v, want ErrNoCredential", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load() created directory: %v", err)
	}
}

func TestFileStoreSaveSetsPrivateModes(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("Unix permission semantics")
	}
	dir := filepath.Join(t.TempDir(), "credentials")
	path := filepath.Join(dir, "token.json")
	store, _ := NewFileStore(path)
	if err := store.Save(context.Background(), validCredential("old")); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	dirInfo, _ := os.Stat(dir)
	fileInfo, _ := os.Stat(path)
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode = %o, want 700", got)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 600", got)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background(), nil); !errors.Is(err, litellmauth.ErrProtocol) {
		t.Fatalf("Load() insecure file error = %v, want ErrProtocol", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Load(context.Background(), nil); err != nil || got.Key != "old" {
		t.Fatalf("Load() from Python-compatible directory = %#v, %v", got, err)
	}
}

func TestFileStoreAtomicReplacementNeverExposesPartialJSON(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "token.json")
	store, _ := NewFileStore(path)
	if err := store.Save(context.Background(), validCredential("old")); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	ready := make(chan struct{})
	errs := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		firstRead := true
		for {
			select {
			case <-stop:
				return
			default:
				credential, err := store.Load(context.Background(), nil)
				if err != nil {
					select {
					case errs <- err:
					default:
					}
					return
				}
				if credential.Key != "old" && credential.Key != "new" {
					select {
					case errs <- errors.New("reader observed invalid credential JSON"):
					default:
					}
					return
				}
				if firstRead {
					close(ready)
					firstRead = false
				}
			}
		}
	}()
	<-ready
	if err := store.Save(context.Background(), validCredential("new")); err != nil {
		t.Fatal(err)
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
}

func TestFileStoreCleansTempFilesAfterFailure(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "token.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	store, _ := NewFileStore(path)
	if err := store.Save(context.Background(), validCredential("new")); err == nil {
		t.Fatal("Save() error = nil")
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".token.json.tmp-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files = %v, error = %v", matches, err)
	}
}

func TestFileStoreHonorsCanceledContext(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "token.json")
	store, _ := NewFileStore(path)
	if err := store.Save(context.Background(), validCredential("old")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := store.Load(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Load() error = %v, want context.Canceled", err)
	}
	if err := store.Save(ctx, validCredential("new")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Save() error = %v, want context.Canceled", err)
	}
	got, err := store.Load(context.Background(), nil)
	if err != nil || got.Key != "old" {
		t.Fatalf("canceled Save changed credential: %#v, %v", got, err)
	}
	if err := store.Delete(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete() error = %v, want context.Canceled", err)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".token.json.tmp-*"))
	if len(matches) != 0 {
		t.Fatalf("canceled operations left temporary files: %v", matches)
	}
}

func TestFileStoreDeleteIsIdempotent(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "token.json")
	store, _ := NewFileStore(path)
	if err := store.Save(context.Background(), validCredential("old")); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background()); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if err := store.Delete(context.Background()); err != nil {
		t.Fatalf("second Delete() error = %v", err)
	}
}

func TestNewFileStoreDefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	store, err := NewFileStore("")
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	if want := filepath.Join(home, ".litellm", "token.json"); store.path != want {
		t.Fatalf("path = %q, want %q", store.path, want)
	}
}

func TestFileStoreSaveAcceptsSafeExistingDirectoryMode(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("Unix permission semantics")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	store, _ := NewFileStore(filepath.Join(dir, "token.json"))
	if err := store.Save(context.Background(), validCredential("key")); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("Save() changed directory mode to %o", got)
	}
	fileInfo, err := os.Stat(filepath.Join(dir, "token.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("saved file mode = %o, want 600", got)
	}
}

func TestFileStoreRejectsWritableDirectoryModes(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("Unix permission semantics")
	}
	for _, mode := range []os.FileMode{0o770, 0o777} {
		t.Run(mode.String(), func(t *testing.T) {
			loadPath := filepath.Join(t.TempDir(), "load", "token.json")
			writeTokenFile(t, loadPath, `{"key":"sk-key"}`)
			if err := os.Chmod(filepath.Dir(loadPath), mode); err != nil {
				t.Fatal(err)
			}
			loadStore, _ := NewFileStore(loadPath)
			if _, err := loadStore.Load(context.Background(), nil); !errors.Is(err, litellmauth.ErrProtocol) {
				t.Fatalf("Load() error = %v, want ErrProtocol", err)
			}

			saveDir := filepath.Join(t.TempDir(), "save")
			if err := os.Mkdir(saveDir, mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(saveDir, mode); err != nil {
				t.Fatal(err)
			}
			saveStore, _ := NewFileStore(filepath.Join(saveDir, "token.json"))
			if err := saveStore.Save(context.Background(), validCredential("key")); !errors.Is(err, litellmauth.ErrProtocol) {
				t.Fatalf("Save() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestFileStoreSatisfiesStore(t *testing.T) {
	var _ Store = (*FileStore)(nil)
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeTokenFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func validCredential(key string) litellmauth.Credential {
	return litellmauth.Credential{
		BaseURL:  "https://gateway.example.com/proxy",
		Key:      key,
		UserID:   "user@example.com",
		IssuedAt: time.Unix(1_784_800_000, 0),
	}
}
