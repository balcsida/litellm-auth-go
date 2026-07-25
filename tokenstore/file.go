package tokenstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	litellmauth "github.com/balcsida/litellm-auth-go"
	"github.com/balcsida/litellm-auth-go/internal/baseurl"
)

const maxCredentialFileSize = 1 << 20

// Store persists LiteLLM credentials.
type Store interface {
	// Load returns a credential, optionally requiring explicitBaseURL to match.
	Load(context.Context, *url.URL) (litellmauth.Credential, error)
	// Save securely persists a credential.
	Save(context.Context, litellmauth.Credential) error
	// Delete removes the persisted credential.
	Delete(context.Context) error
}

// FileStore securely persists one credential file.
type FileStore struct {
	path string
}

type diskCredential struct {
	BaseURL             string                 `json:"base_url"`
	Key                 string                 `json:"key"`
	AuthMethod          litellmauth.AuthMethod `json:"auth_method,omitempty"`
	TokenType           string                 `json:"token_type,omitempty"`
	Issuer              string                 `json:"issuer,omitempty"`
	Subject             string                 `json:"subject,omitempty"`
	Scopes              []string               `json:"scopes,omitempty"`
	ExpiresAt           string                 `json:"expires_at,omitempty"`
	NonExpiring         bool                   `json:"non_expiring,omitempty"`
	UserID              string                 `json:"user_id"`
	Timestamp           json.RawMessage        `json:"timestamp"`
	TeamID              string                 `json:"team_id"`
	Teams               json.RawMessage        `json:"teams"`
	TeamAlias           string                 `json:"team_alias"`
	TeamDetails         json.RawMessage        `json:"team_details"`
	AttributionMetadata json.RawMessage        `json:"attribution_metadata"`
}

type savedCredential struct {
	BaseURL             string                 `json:"base_url"`
	Key                 string                 `json:"key"`
	AuthMethod          litellmauth.AuthMethod `json:"auth_method,omitempty"`
	TokenType           string                 `json:"token_type,omitempty"`
	Issuer              string                 `json:"issuer,omitempty"`
	Subject             string                 `json:"subject,omitempty"`
	Scopes              []string               `json:"scopes,omitempty"`
	ExpiresAt           string                 `json:"expires_at,omitempty"`
	NonExpiring         bool                   `json:"non_expiring,omitempty"`
	UserID              string                 `json:"user_id"`
	UserEmail           string                 `json:"user_email"`
	UserRole            string                 `json:"user_role"`
	AuthHeaderName      string                 `json:"auth_header_name"`
	JWTToken            string                 `json:"jwt_token"`
	Timestamp           json.Number            `json:"timestamp"`
	TeamID              string                 `json:"team_id"`
	Teams               []string               `json:"teams"`
	TeamAlias           string                 `json:"team_alias,omitempty"`
	TeamDetails         []teamDetail           `json:"team_details,omitempty"`
	AttributionMetadata map[string]any         `json:"attribution_metadata"`
}

type teamDetail struct {
	TeamID    string `json:"team_id"`
	TeamAlias string `json:"team_alias,omitempty"`
}

// NewFileStore creates a FileStore. An empty path uses ~/.litellm/token.json.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, errors.New("resolve LiteLLM credential path")
		}
		path = filepath.Join(home, ".litellm", "token.json")
	}
	return &FileStore{path: filepath.Clean(path)}, nil
}

// Load returns the stored credential and verifies explicitBaseURL when non-nil.
func (s *FileStore) Load(ctx context.Context, explicitBaseURL *url.URL) (litellmauth.Credential, error) {
	if err := ctx.Err(); err != nil {
		return litellmauth.Credential{}, err
	}
	file, err := openCredentialFile(ctx, s.path)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return litellmauth.Credential{}, err
	}
	if errors.Is(err, os.ErrNotExist) {
		return litellmauth.Credential{}, litellmauth.ErrNoCredential
	}
	if err != nil {
		return litellmauth.Credential{}, errors.New("read stored LiteLLM credential")
	}
	defer file.Close()
	if err := checkPrivateModes(file, filepath.Dir(s.path)); err != nil {
		return litellmauth.Credential{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialFileSize+1))
	if err != nil {
		return litellmauth.Credential{}, errors.New("read stored LiteLLM credential")
	}
	if err := ctx.Err(); err != nil {
		return litellmauth.Credential{}, err
	}
	if len(data) > maxCredentialFileSize {
		return litellmauth.Credential{}, invalidFile()
	}

	var stored diskCredential
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(&stored); err != nil {
		return litellmauth.Credential{}, invalidFile()
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return litellmauth.Credential{}, invalidFile()
	}
	credential, err := stored.credential()
	if err != nil {
		return litellmauth.Credential{}, err
	}
	if explicitBaseURL != nil {
		explicit, err := baseurl.Normalize(explicitBaseURL.String())
		if err != nil {
			return litellmauth.Credential{}, invalidFile()
		}
		if credential.BaseURL == "" || credential.BaseURL != explicit.String() {
			return litellmauth.Credential{}, litellmauth.ErrOriginMismatch
		}
	}
	return credential, nil
}

// Save writes credential with private file permissions.
func (s *FileStore) Save(ctx context.Context, credential litellmauth.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	saved, err := credentialForSave(credential)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := preparePrivateDirectory(dir); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return errors.New("write stored LiteLLM credential")
	}
	tempPath := file.Name()
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		_ = os.Remove(tempPath)
	}()
	if unixPermissions() {
		if err := file.Chmod(0o600); err != nil {
			return errors.New("secure stored LiteLLM credential")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(saved); err != nil {
		return invalidFile()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync stored LiteLLM credential")
	}
	if err := file.Close(); err != nil {
		closed = true
		return errors.New("close stored LiteLLM credential")
	}
	closed = true
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := replaceCredentialFile(ctx, tempPath, s.path); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return errors.New("replace stored LiteLLM credential")
	}
	if err := syncDirectory(dir); err != nil {
		return errors.New("sync LiteLLM credential directory")
	}
	return nil
}

// Delete removes the credential file and succeeds when it is already absent.
func (s *FileStore) Delete(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := os.Remove(s.path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errors.New("delete stored LiteLLM credential")
}

func (d diskCredential) credential() (litellmauth.Credential, error) {
	credential := litellmauth.Credential{
		Key:         d.Key,
		UserID:      d.UserID,
		TeamID:      d.TeamID,
		TeamAlias:   d.TeamAlias,
		AuthMethod:  d.AuthMethod,
		TokenType:   d.TokenType,
		Issuer:      d.Issuer,
		Subject:     d.Subject,
		Scopes:      append([]string(nil), d.Scopes...),
		NonExpiring: d.NonExpiring,
	}
	if credential.AuthorizationHeader() == "" {
		return litellmauth.Credential{}, invalidFile()
	}
	if d.BaseURL != "" {
		normalized, err := baseurl.Normalize(d.BaseURL)
		if err != nil {
			return litellmauth.Credential{}, invalidFile()
		}
		credential.BaseURL = normalized.String()
	}
	var err error
	if credential.IssuedAt, err = parseTimestamp(d.Timestamp); err != nil {
		return litellmauth.Credential{}, invalidFile()
	}
	if d.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339Nano, d.ExpiresAt)
		if err != nil {
			return litellmauth.Credential{}, invalidFile()
		}
		credential.ExpiresAt = expiresAt
	} else {
		credential.ExpiresAt = credential.Expiry()
	}
	if credential.Teams, err = parseTeams(d.Teams, d.TeamDetails, d.TeamID, d.TeamAlias); err != nil {
		return litellmauth.Credential{}, invalidFile()
	}
	if credential.AttributionMetadata, err = parseMetadata(d.AttributionMetadata); err != nil {
		return litellmauth.Credential{}, invalidFile()
	}
	if err := credential.Validate(); err != nil {
		if !(errors.Is(err, litellmauth.ErrCredentialExpiryUnknown) &&
			credential.AuthMethod == "") {
			return litellmauth.Credential{}, err
		}
	}
	if credentialMetadataContainsKey(credential) {
		return litellmauth.Credential{}, invalidFile()
	}
	return credential, nil
}

func credentialForSave(credential litellmauth.Credential) (savedCredential, error) {
	if credential.BaseURL == "" {
		return savedCredential{}, invalidFile()
	}
	if credential.AuthMethod == "" && credential.NonExpiring {
		return savedCredential{}, litellmauth.ErrInvalidCredential
	}
	if err := credential.Validate(); err != nil {
		return savedCredential{}, err
	}
	normalized, err := baseurl.Normalize(credential.BaseURL)
	if err != nil {
		return savedCredential{}, invalidFile()
	}
	if _, err := parseMetadataValue(credential.AttributionMetadata); err != nil {
		return savedCredential{}, invalidFile()
	}
	if credentialMetadataContainsKey(credential) {
		return savedCredential{}, invalidFile()
	}
	saved := savedCredential{
		BaseURL:             normalized.String(),
		Key:                 credential.Key,
		AuthMethod:          credential.AuthMethod,
		TokenType:           credential.TokenType,
		Issuer:              credential.Issuer,
		Subject:             credential.Subject,
		Scopes:              append([]string(nil), credential.Scopes...),
		NonExpiring:         credential.NonExpiring,
		UserID:              credential.UserID,
		UserEmail:           "unknown",
		UserRole:            "cli",
		AuthHeaderName:      "Authorization",
		JWTToken:            "",
		Timestamp:           timestampNumber(credential.IssuedAt),
		TeamID:              credential.TeamID,
		Teams:               make([]string, 0, len(credential.Teams)),
		AttributionMetadata: credential.AttributionMetadata,
	}
	if !credential.ExpiresAt.IsZero() {
		saved.ExpiresAt = credential.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	if saved.AttributionMetadata == nil {
		saved.AttributionMetadata = map[string]any{}
	}
	for _, team := range credential.Teams {
		if team.ID == "" {
			return savedCredential{}, invalidFile()
		}
		saved.Teams = append(saved.Teams, team.ID)
		saved.TeamDetails = append(saved.TeamDetails, teamDetail{TeamID: team.ID, TeamAlias: team.Alias})
	}
	if credential.TeamAlias != "" {
		saved.TeamAlias = credential.TeamAlias
	}
	return saved, nil
}

func credentialMetadataContainsKey(credential litellmauth.Credential) bool {
	containsKey := func(value string) bool {
		return credential.Key != "" && strings.Contains(value, credential.Key)
	}
	if containsKey(credential.BaseURL) || containsKey(credential.UserID) ||
		containsKey(credential.TeamID) || containsKey(credential.TeamAlias) ||
		containsKey(string(credential.AuthMethod)) || containsKey(credential.TokenType) ||
		containsKey(credential.Issuer) || containsKey(credential.Subject) {
		return true
	}
	for _, scope := range credential.Scopes {
		if containsKey(scope) {
			return true
		}
	}
	for _, team := range credential.Teams {
		if containsKey(team.ID) || containsKey(team.Alias) {
			return true
		}
	}
	for name, value := range credential.AttributionMetadata {
		if containsKey(name) {
			return true
		}
		if text, ok := value.(string); ok && containsKey(text) {
			return true
		}
	}
	return false
}

func parseTimestamp(raw json.RawMessage) (time.Time, error) {
	if len(raw) == 0 {
		return time.Time{}, nil
	}
	if string(raw) == "null" {
		return time.Time{}, errors.New("timestamp must be numeric")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return time.Time{}, err
	}
	number, ok := value.(json.Number)
	if !ok {
		return time.Time{}, errors.New("timestamp must be numeric")
	}
	return numberTimestamp(string(number))
}

func timestampNumber(value time.Time) json.Number {
	if value.IsZero() {
		return "0"
	}
	seconds, nanoseconds := value.Unix(), value.Nanosecond()
	if nanoseconds == 0 {
		return json.Number(strconv.FormatInt(seconds, 10))
	}
	if seconds >= 0 {
		return json.Number(strconv.FormatInt(seconds, 10) + "." + strings.TrimRight(fmt.Sprintf("%09d", nanoseconds), "0"))
	}
	return json.Number("-" + strconv.FormatInt(-(seconds+1), 10) + "." + strings.TrimRight(fmt.Sprintf("%09d", int(time.Second)-nanoseconds), "0"))
}

func numberTimestamp(raw string) (time.Time, error) {
	if strings.ContainsAny(raw, "eE") {
		value, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsInf(value, 0) || math.IsNaN(value) || value <= float64(math.MinInt64) || value >= float64(math.MaxInt64) {
			return time.Time{}, errors.New("invalid timestamp")
		}
		if value == 0 {
			return time.Time{}, nil
		}
		seconds, fraction := math.Modf(value)
		return time.Unix(int64(seconds), int64(math.Round(fraction*float64(time.Second)))), nil
	}
	parts := strings.SplitN(raw, ".", 2)
	seconds, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, errors.New("invalid timestamp")
	}
	if len(parts) == 1 {
		if seconds == 0 {
			return time.Time{}, nil
		}
		return time.Unix(seconds, 0), nil
	}
	fraction := parts[1]
	if len(fraction) > 9 {
		fraction = fraction[:9]
	}
	nanoseconds, err := strconv.ParseInt(fraction+strings.Repeat("0", 9-len(fraction)), 10, 64)
	if err != nil {
		return time.Time{}, errors.New("invalid timestamp")
	}
	if strings.HasPrefix(raw, "-") {
		nanoseconds = -nanoseconds
	}
	if seconds == math.MinInt64 && nanoseconds < 0 {
		return time.Time{}, errors.New("invalid timestamp")
	}
	if seconds == 0 && nanoseconds == 0 {
		return time.Time{}, nil
	}
	return time.Unix(seconds, nanoseconds), nil
}

func parseTeams(teamsRaw, detailsRaw json.RawMessage, selectedID, selectedAlias string) ([]litellmauth.Team, error) {
	teams := make([]litellmauth.Team, 0)
	byID := make(map[string]int)
	add := func(id, alias string) error {
		if id == "" {
			return errors.New("empty team ID")
		}
		if index, ok := byID[id]; ok {
			if teams[index].Alias == "" {
				teams[index].Alias = alias
			}
			return nil
		}
		byID[id] = len(teams)
		teams = append(teams, litellmauth.Team{ID: id, Alias: alias})
		return nil
	}
	if len(teamsRaw) != 0 && string(teamsRaw) != "null" {
		var ids []string
		if err := json.Unmarshal(teamsRaw, &ids); err != nil {
			return nil, err
		}
		for _, id := range ids {
			if err := add(id, ""); err != nil {
				return nil, err
			}
		}
	}
	if len(detailsRaw) != 0 && string(detailsRaw) != "null" {
		var details []struct {
			TeamID    string `json:"team_id"`
			ID        string `json:"id"`
			TeamAlias string `json:"team_alias"`
			Alias     string `json:"alias"`
		}
		if err := json.Unmarshal(detailsRaw, &details); err != nil {
			return nil, err
		}
		for _, detail := range details {
			id, alias := detail.TeamID, detail.TeamAlias
			if id == "" {
				id = detail.ID
			}
			if alias == "" {
				alias = detail.Alias
			}
			if err := add(id, alias); err != nil {
				return nil, err
			}
		}
	}
	if index, ok := byID[selectedID]; ok && teams[index].Alias == "" {
		teams[index].Alias = selectedAlias
	}
	return teams, nil
}

func parseMetadata(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil || metadata == nil {
		return nil, errors.New("invalid attribution metadata")
	}
	return parseMetadataValue(metadata)
}

func parseMetadataValue(metadata map[string]any) (map[string]any, error) {
	for _, value := range metadata {
		switch value := value.(type) {
		case string, bool:
		case float64:
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return nil, errors.New("invalid attribution metadata")
			}
		default:
			return nil, errors.New("invalid attribution metadata")
		}
	}
	return metadata, nil
}

func preparePrivateDirectory(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return errors.New("create LiteLLM credential directory")
		}
		info, err = os.Stat(path)
	}
	if err != nil || !info.IsDir() {
		return errors.New("create LiteLLM credential directory")
	}
	if unixPermissions() && !safeDirectoryMode(info.Mode()) {
		return invalidFile()
	}
	return nil
}

func checkPrivateModes(file *os.File, dir string) error {
	if !unixPermissions() {
		return nil
	}
	fileInfo, err := file.Stat()
	if err != nil || fileInfo.Mode().Perm() != 0o600 {
		return invalidFile()
	}
	dirInfo, err := os.Stat(dir)
	if err != nil || !safeDirectoryMode(dirInfo.Mode()) {
		return invalidFile()
	}
	return nil
}

func safeDirectoryMode(mode os.FileMode) bool { return mode.Perm()&0o022 == 0 }

func syncDirectory(path string) error {
	if !unixPermissions() {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func unixPermissions() bool {
	return runtime.GOOS != "windows" && runtime.GOOS != "plan9"
}

func invalidFile() error {
	return fmt.Errorf("%w: stored credential", litellmauth.ErrProtocol)
}
