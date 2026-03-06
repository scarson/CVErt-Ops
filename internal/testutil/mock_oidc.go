// ABOUTME: Mock OIDC Identity Provider for integration testing SSO flows.
// ABOUTME: Serves discovery, JWKS, and token endpoints; issues real RSA-signed ID tokens.
package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MockOIDC is a configurable OIDC identity provider for tests.
type MockOIDC struct {
	Server     *httptest.Server
	Sub        string // subject claim in issued ID tokens
	Email      string // email claim in issued ID tokens
	ClientID   string // expected client_id in audience
	privateKey *rsa.PrivateKey
	mu         sync.Mutex
	nextNonce  string
}

// SetNonce configures the nonce claim for the next ID token issued by the mock.
func (m *MockOIDC) SetNonce(nonce string) {
	m.mu.Lock()
	m.nextNonce = nonce
	m.mu.Unlock()
}

func (m *MockOIDC) getNonce() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nextNonce
}

// NewMockOIDC creates a mock OIDC server that serves:
//   - GET /.well-known/openid-configuration
//   - POST /token — exchanges code for tokens (returns RSA-signed ID token)
//   - GET /keys — JWKS endpoint with the test RSA public key
func NewMockOIDC(t *testing.T) *MockOIDC {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	mock := &MockOIDC{
		privateKey: privateKey,
		Sub:        "sso-test-sub-001",
		Email:      "sso-user@example.com",
		ClientID:   "test-sso-client",
	}
	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		baseURL := "http://" + r.Host
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G104: test mock
				"issuer":                                baseURL,
				"authorization_endpoint":                baseURL + "/authorize",
				"token_endpoint":                        baseURL + "/token",
				"jwks_uri":                              baseURL + "/keys",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			pub := &mock.privateKey.PublicKey
			n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G104: test mock
				"keys": []map[string]any{
					{"kty": "RSA", "kid": "sso-test-key", "use": "sig", "alg": "RS256", "n": n, "e": e},
				},
			})
		case "/token":
			nonce := mock.getNonce()
			claims := jwt.MapClaims{
				"iss":   baseURL,
				"sub":   mock.Sub,
				"email": mock.Email,
				"aud":   jwt.ClaimStrings{mock.ClientID},
				"exp":   jwt.NewNumericDate(time.Now().Add(time.Hour)),
				"iat":   jwt.NewNumericDate(time.Now()),
				"nonce": nonce,
			}
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			tok.Header["kid"] = "sso-test-key"
			idTokenStr, signErr := tok.SignedString(mock.privateKey)
			if signErr != nil {
				http.Error(w, "sign id token: "+signErr.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G104: test mock
				"access_token": "mock_access_token",
				"token_type":   "bearer",
				"id_token":     idTokenStr,
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(mock.Server.Close)
	return mock
}
