package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/H0n3yb0t/OpencodeProxy/internal/cryptox"
	"golang.org/x/crypto/argon2"
)

var ErrAlreadyInitialized = errors.New("instance is already initialized")

type Secrets struct {
	AccessKey   string `json:"access_key"`
	RecoveryKey string `json:"recovery_key"`
}

type diskState struct {
	Version           int                `json:"version"`
	MasterKey         string             `json:"master_key"`
	AdminPasswordHash string             `json:"admin_password_hash"`
	ProxyTokenHash    string             `json:"proxy_token_hash"`
	UnifiedAccess     bool               `json:"unified_access,omitempty"`
	ClientTokens      []clientTokenState `json:"client_tokens,omitempty"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
}

type ClientToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type ProxyPrincipal struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type proxyPrincipalContextKey struct{}

func WithProxyPrincipal(ctx context.Context, principal ProxyPrincipal) context.Context {
	return context.WithValue(ctx, proxyPrincipalContextKey{}, principal)
}

func ProxyPrincipalFromContext(ctx context.Context) ProxyPrincipal {
	if principal, ok := ctx.Value(proxyPrincipalContextKey{}).(ProxyPrincipal); ok {
		return principal
	}
	return ProxyPrincipal{ID: "master", Name: "主访问密钥", Kind: "master"}
}

type clientTokenState struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
}

type Manager struct {
	mu     sync.RWMutex
	path   string
	state  *diskState
	cipher *cryptox.Cipher
}

func Open(path string, legacyMasterKey []byte, legacyAdminPassword, legacyProxyToken string) (*Manager, error) {
	m := &Manager{path: path}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &m.state); err != nil {
			return nil, fmt.Errorf("decode instance identity: %w", err)
		}
		if err := m.loadCipher(); err != nil {
			return nil, err
		}
		return m, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read instance identity: %w", err)
	}
	if len(legacyMasterKey) == 0 && legacyAdminPassword == "" && legacyProxyToken == "" {
		return m, nil
	}
	if len(legacyMasterKey) != 32 || legacyAdminPassword == "" || legacyProxyToken == "" {
		return nil, errors.New("legacy MASTER_KEY, ADMIN_PASSWORD and PROXY_TOKEN must be supplied together")
	}
	adminHash, err := hashPassword(legacyAdminPassword)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	m.state = &diskState{
		Version:           1,
		MasterKey:         base64.StdEncoding.EncodeToString(legacyMasterKey),
		AdminPasswordHash: adminHash,
		ProxyTokenHash:    tokenHash(legacyProxyToken),
		UnifiedAccess:     legacyAdminPassword == legacyProxyToken,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := m.loadCipher(); err != nil {
		return nil, err
	}
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Initialized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state != nil && m.cipher != nil
}

func (m *Manager) Initialize() (Secrets, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != nil {
		return Secrets{}, ErrAlreadyInitialized
	}
	master, err := randomBytes(32)
	if err != nil {
		return Secrets{}, err
	}
	accessRaw, err := randomBytes(32)
	if err != nil {
		return Secrets{}, err
	}
	accessKey := "opm_" + base64.RawURLEncoding.EncodeToString(accessRaw)
	adminHash, err := hashPassword(accessKey)
	if err != nil {
		return Secrets{}, err
	}
	now := time.Now().UTC()
	m.state = &diskState{
		Version:           1,
		MasterKey:         base64.StdEncoding.EncodeToString(master),
		AdminPasswordHash: adminHash,
		ProxyTokenHash:    tokenHash(accessKey),
		UnifiedAccess:     true,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	cipher, err := cryptox.New(master)
	if err != nil {
		m.state = nil
		return Secrets{}, err
	}
	m.cipher = cipher
	if err := m.persistLocked(); err != nil {
		m.state, m.cipher = nil, nil
		return Secrets{}, err
	}
	return Secrets{AccessKey: accessKey, RecoveryKey: m.state.MasterKey}, nil
}

func (m *Manager) VerifyAdmin(password string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state == nil {
		return false
	}
	return verifyPassword(password, m.state.AdminPasswordHash)
}

func (m *Manager) VerifyProxy(token string) bool {
	_, ok := m.AuthenticateProxy(token)
	return ok
}

func (m *Manager) AuthenticateProxy(token string) (ProxyPrincipal, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state == nil {
		return ProxyPrincipal{}, false
	}
	got := sha256.Sum256([]byte(token))
	if hashMatches(got[:], m.state.ProxyTokenHash) {
		return ProxyPrincipal{ID: "master", Name: "主访问密钥", Kind: "master"}, true
	}
	for _, client := range m.state.ClientTokens {
		if hashMatches(got[:], client.TokenHash) {
			return ProxyPrincipal{ID: client.ID, Name: client.Name, Kind: "client"}, true
		}
	}
	return ProxyPrincipal{}, false
}

func hashMatches(got []byte, encoded string) bool {
	want, err := hex.DecodeString(encoded)
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

func (m *Manager) Encrypt(plaintext string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cipher == nil {
		return nil, errors.New("instance setup is required")
	}
	return m.cipher.Encrypt(plaintext)
}

func (m *Manager) Decrypt(ciphertext []byte) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cipher == nil {
		return "", errors.New("instance setup is required")
	}
	return m.cipher.Decrypt(ciphertext)
}

func (m *Manager) RotateAccessKey(requested string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return "", errors.New("instance setup is required")
	}
	accessKey := strings.TrimSpace(requested)
	if accessKey == "" {
		raw, err := randomBytes(32)
		if err != nil {
			return "", err
		}
		accessKey = "opm_" + base64.RawURLEncoding.EncodeToString(raw)
	}
	if len([]rune(accessKey)) < 16 || len([]rune(accessKey)) > 256 {
		return "", errors.New("access key must contain 16 to 256 characters")
	}
	adminHash, err := hashPassword(accessKey)
	if err != nil {
		return "", err
	}
	oldAdminHash, oldProxyHash, oldUnified, oldUpdated := m.state.AdminPasswordHash, m.state.ProxyTokenHash, m.state.UnifiedAccess, m.state.UpdatedAt
	m.state.AdminPasswordHash = adminHash
	m.state.ProxyTokenHash = tokenHash(accessKey)
	m.state.UnifiedAccess = true
	m.state.UpdatedAt = time.Now().UTC()
	if err := m.persistLocked(); err != nil {
		m.state.AdminPasswordHash, m.state.ProxyTokenHash, m.state.UnifiedAccess, m.state.UpdatedAt = oldAdminHash, oldProxyHash, oldUnified, oldUpdated
		return "", err
	}
	return accessKey, nil
}

func (m *Manager) UnifiedAccessEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state != nil && m.state.UnifiedAccess
}

func (m *Manager) IssueClientToken(name string) (ClientToken, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return ClientToken{}, "", errors.New("instance setup is required")
	}
	if len(m.state.ClientTokens) >= 100 {
		return ClientToken{}, "", errors.New("client token limit reached")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "OpenCode client"
	}
	nameRunes := []rune(name)
	if len(nameRunes) > 80 {
		name = string(nameRunes[:80])
	}
	raw, err := randomBytes(32)
	if err != nil {
		return ClientToken{}, "", err
	}
	idRaw, err := randomBytes(12)
	if err != nil {
		return ClientToken{}, "", err
	}
	token := "opc_" + base64.RawURLEncoding.EncodeToString(raw)
	client := clientTokenState{
		ID:        hex.EncodeToString(idRaw),
		Name:      name,
		TokenHash: tokenHash(token),
		CreatedAt: time.Now().UTC(),
	}
	previous := append([]clientTokenState(nil), m.state.ClientTokens...)
	previousUpdatedAt := m.state.UpdatedAt
	m.state.ClientTokens = append(m.state.ClientTokens, client)
	m.state.UpdatedAt = client.CreatedAt
	if err := m.persistLocked(); err != nil {
		m.state.ClientTokens = previous
		m.state.UpdatedAt = previousUpdatedAt
		return ClientToken{}, "", err
	}
	return ClientToken{ID: client.ID, Name: client.Name, CreatedAt: client.CreatedAt}, token, nil
}

func (m *Manager) ListClientTokens() []ClientToken {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state == nil || len(m.state.ClientTokens) == 0 {
		return []ClientToken{}
	}
	result := make([]ClientToken, len(m.state.ClientTokens))
	for i, client := range m.state.ClientTokens {
		result[i] = ClientToken{ID: client.ID, Name: client.Name, CreatedAt: client.CreatedAt}
	}
	return result
}

func (m *Manager) RenameClientToken(id, name string) (ClientToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 80 {
		return ClientToken{}, errors.New("client name must contain 1 to 80 characters")
	}
	for index := range m.state.ClientTokens {
		if m.state.ClientTokens[index].ID != id {
			continue
		}
		previousName, previousUpdatedAt := m.state.ClientTokens[index].Name, m.state.UpdatedAt
		m.state.ClientTokens[index].Name = name
		m.state.UpdatedAt = time.Now().UTC()
		if err := m.persistLocked(); err != nil {
			m.state.ClientTokens[index].Name = previousName
			m.state.UpdatedAt = previousUpdatedAt
			return ClientToken{}, err
		}
		client := m.state.ClientTokens[index]
		return ClientToken{ID: client.ID, Name: client.Name, CreatedAt: client.CreatedAt}, nil
	}
	return ClientToken{}, os.ErrNotExist
}

func (m *Manager) RevokeClientToken(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return errors.New("instance setup is required")
	}
	index := -1
	for i := range m.state.ClientTokens {
		if m.state.ClientTokens[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return os.ErrNotExist
	}
	previous := append([]clientTokenState(nil), m.state.ClientTokens...)
	previousUpdatedAt := m.state.UpdatedAt
	m.state.ClientTokens = append(m.state.ClientTokens[:index], m.state.ClientTokens[index+1:]...)
	m.state.UpdatedAt = time.Now().UTC()
	if err := m.persistLocked(); err != nil {
		m.state.ClientTokens = previous
		m.state.UpdatedAt = previousUpdatedAt
		return err
	}
	return nil
}

func (m *Manager) loadCipher() error {
	master, err := base64.StdEncoding.DecodeString(m.state.MasterKey)
	if err != nil || len(master) != 32 {
		return errors.New("instance master key is invalid")
	}
	cipher, err := cryptox.New(master)
	if err != nil {
		return err
	}
	m.cipher = cipher
	return nil
}

func (m *Manager) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(m.path), ".instance-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, m.path); err != nil {
		return err
	}
	return os.Chmod(m.path, 0o600)
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	_, err := rand.Read(value)
	return value, err
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func hashPassword(password string) (string, error) {
	salt, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	const memory, iterations, parallelism, keyLength = uint32(64 * 1024), uint32(3), uint8(1), uint32(32)
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iterations, parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false
	}
	memory64, err1 := strconv.ParseUint(strings.TrimPrefix(params[0], "m="), 10, 32)
	iterations64, err2 := strconv.ParseUint(strings.TrimPrefix(params[1], "t="), 10, 32)
	parallelism64, err3 := strconv.ParseUint(strings.TrimPrefix(params[2], "p="), 10, 8)
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(iterations64), uint32(memory64), uint8(parallelism64), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
