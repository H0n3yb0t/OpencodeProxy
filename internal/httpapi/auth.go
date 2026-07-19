package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

const sessionCookie = "keypool_session"

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	password [32]byte
}

func newSessionStore(password string) *sessionStore {
	return &sessionStore{sessions: make(map[string]time.Time), password: sha256.Sum256([]byte(password))}
}

func (s *sessionStore) checkPassword(password string) bool {
	got := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(got[:], s.password[:]) == 1
}

func (s *sessionStore) create() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(12 * time.Hour)
	s.mu.Unlock()
	return token
}

func (s *sessionStore) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.sessions[token]
	if !ok || time.Now().After(expires) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func (a *API) adminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil || !a.sessions.valid(cookie.Value) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "admin authentication required"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "cross-origin request rejected"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) proxyAuth(next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(a.cfg.BootstrapToken))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if token == "" {
			token = r.Header.Get("X-Api-Key")
		}
		got := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"message": "Invalid proxy token", "type": "authentication_error"}})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	wantHTTP := "http://" + r.Host
	wantHTTPS := "https://" + r.Host
	return origin == wantHTTP || origin == wantHTTPS
}
