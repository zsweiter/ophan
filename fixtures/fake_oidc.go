package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	defaultIssuer     = "http://localhost:8081"
	defaultRefreshTok = "test-refresh-token"
	keyID             = "fake-oidc-key"
)

var privateKey ed25519.PrivateKey

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

type Discovery struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint,omitempty"` // Requerido para flujos de login/UI
	TokenEndpoint                    string   `json:"token_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`              // ¡OBLIGATORIO! Ej: ["code", "id_token", "token"]
	SubjectTypesSupported            []string `json:"subject_types_supported"`               // ¡OBLIGATORIO! Ej: ["public"]
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"` // Corregido el tag JSON exacto

	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"` // Para PKCE (ej: ["S256", "plain"])
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func main() {
	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		issuer = defaultIssuer
	}

	var err error
	_, privateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Error al generar clave Ed25519: %v", err)
	}

	// Usamos NewServeMux con soporte para métodos HTTP (Go 1.22+)
	mux := http.NewServeMux()

	// Endpoints GET
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Discovery{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/authorize",
			TokenEndpoint:         issuer + "/token",
			JWKSURI:               issuer + "/jwks",

			ResponseTypesSupported:           []string{"code", "token", "id_token"},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"EdDSA"},

			GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
			ScopesSupported:                   []string{"openid", "profile", "email"},
			ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "email", "roles"},
			CodeChallengeMethodsSupported:     []string{"S256"},
		})
	})

	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Discovery{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/authorize",
			TokenEndpoint:         issuer + "/token",
			JWKSURI:               issuer + "/jwks",

			ResponseTypesSupported:           []string{"code", "token", "id_token"},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"EdDSA"},

			GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
			ScopesSupported:                   []string{"openid", "profile", "email"},
			ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "email", "roles"},
			CodeChallengeMethodsSupported:     []string{"S256"},
		})
	})

	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, JWKS{
			Keys: []JWK{
				publicJWK(),
			},
		})
	})

	// Endpoint POST exclusivo para /token
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			oauthError(w, "invalid_request", "invalid form body")
			return
		}

		grantType := r.Form.Get("grant_type")
		if grantType != "refresh_token" {
			oauthError(
				w,
				"unsupported_grant_type",
				"only 'refresh_token' grant_type is supported by this mock server",
			)
			return
		}

		refreshToken := r.Form.Get("refresh_token")
		if refreshToken != defaultRefreshTok {
			oauthError(
				w,
				"invalid_grant",
				"invalid or expired refresh token",
			)
			return
		}

		accessToken, err := createAccessToken(issuer)
		if err != nil {
			oauthError(w, "server_error", err.Error())
			return
		}

		writeJSON(w, TokenResponse{
			AccessToken:  accessToken,
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: defaultRefreshTok,
		})
	})

	// Generar un token inicial de prueba para imprimir en logs
	accessToken, err := createAccessToken(issuer)
	if err != nil {
		log.Fatalf("Error creando access token inicial: %+v", err)
	}

	log.Println("=== Fake OIDC Server Listo ===")
	log.Printf("Listening on :8081")
	log.Printf("Issuer URL:    %s", issuer)
	log.Printf("Refresh Token: %s", defaultRefreshTok)
	log.Printf("Test JWT:      %s", accessToken)
	log.Println("==============================")

	loggedMux := RequestSummaryLogger(mux)

	if err := http.ListenAndServe(":8081", loggedMux); err != nil {
		log.Fatalf("Error iniciando servidor: %v", err)
	}
}

func createAccessToken(issuer string) (string, error) {
	header := map[string]any{
		"alg": "EdDSA",
		"typ": "JWT",
		"kid": keyID,
	}

	now := time.Now()

	payload := map[string]any{
		"iss":       issuer,
		"sub":       "test-user",
		"aud":       "https://frontend.com",
		"iat":       now.Unix(),
		"exp":       now.Add(time.Minute * 10).Unix(),
		"scope":     "openid profile email",
		"client_id": "test-client",
		"email":     "test@example.com",
		"roles":     []string{"user"},
	}

	enc := base64.RawURLEncoding

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	signingInput := enc.EncodeToString(headerJSON) +
		"." +
		enc.EncodeToString(payloadJSON)

	signature := ed25519.Sign(
		privateKey,
		[]byte(signingInput),
	)

	return signingInput + "." + enc.EncodeToString(signature), nil
}

func publicJWK() JWK {
	return JWK{
		Kty: "OKP",
		Use: "sig",
		Alg: "EdDSA",
		Kid: keyID,
		Crv: "Ed25519",
		X: base64.RawURLEncoding.EncodeToString(
			privateKey.Public().(ed25519.PublicKey),
		),
	}
}

func oauthError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func RequestSummaryLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapper := &responseWriterWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(wrapper, r)

		duration := time.Since(start)

		log.Printf("[HTTP] %s %s -> %d %s | %s",
			r.Method,
			r.URL.Path,
			wrapper.statusCode,
			http.StatusText(wrapper.statusCode),
			duration,
		)
	})
}
