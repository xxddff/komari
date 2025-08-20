package api

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/config"
)

type CloudflareAccessClaims struct {
	Aud   interface{} `json:"aud"` // 可以是字符串或字符串数组
	Email string      `json:"email"`
	Exp   int64       `json:"exp"`
	Iat   int64       `json:"iat"`
	Iss   string      `json:"iss"`
	Sub   string      `json:"sub"`
}

type CloudflareAccessPublicKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type CloudflareAccessCerts struct {
	Keys []CloudflareAccessPublicKey `json:"keys"`
}

// CloudflareAccessMiddleware validates Cloudflare Access JWT tokens
func CloudflareAccessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := config.Get()
		if err != nil || !cfg.CloudflareAccessEnabled {
			c.Next()
			return
		}

		// Get JWT from header or cookie
		token := c.GetHeader("Cf-Access-Jwt-Assertion")
		if token == "" {
			// 如果请求头中没有，尝试从 cookie 中获取
			token, _ = c.Cookie("CF_Authorization")
		}
		if token == "" {
			c.Next()
			return
		}

		// Validate JWT
		claims, err := ValidateCloudflareAccessJWT(token, cfg.CloudflareAccessTeamName, cfg.CloudflareAccessAudience)
		if err != nil {
			c.Next()
			return
		}

		// Try to get user by Cloudflare Access email
		user, err := accounts.GetUserByCloudflareAccess(claims.Email)
		if err != nil {
			// User not found, create a new one
			user, err = accounts.CreateCloudflareAccessUser(claims.Email, claims.Sub)
			if err != nil {
				c.Next()
				return
			}
		}

		// Create session
		session, err := accounts.CreateSession(user.UUID, 2592000, c.Request.UserAgent(), c.ClientIP(), "cloudflare_access")
		if err != nil {
			c.Next()
			return
		}

		// Set session cookie and context
		c.SetCookie("session_token", session, 2592000, "/", "", false, true)
		c.Set("session", session)
		c.Set("uuid", user.UUID)
		c.Set("cloudflare_access_user", true)

		c.Next()
	}
}

func ValidateCloudflareAccessJWT(tokenString, teamName, audience string) (*CloudflareAccessClaims, error) {
	// Parse JWT header to get kid
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %v", err)
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %v", err)
	}

	// Get public key from Cloudflare
	publicKey, err := getCloudflareAccessPublicKey(teamName, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	// Verify signature
	if err := verifyJWTSignature(tokenString, publicKey); err != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %v", err)
	}

	// Decode and validate claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT claims: %v", err)
	}

	var claims CloudflareAccessClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %v", err)
	}

	// Validate claims
	now := time.Now().Unix()
	if claims.Exp < now {
		return nil, fmt.Errorf("JWT token expired")
	}

	// 验证 audience（可能是字符串或字符串数组）
	if !validateAudience(claims.Aud, audience) {
		return nil, fmt.Errorf("invalid audience")
	}

	expectedIssuer := fmt.Sprintf("https://%s.cloudflareaccess.com", teamName)
	if claims.Iss != expectedIssuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	return &claims, nil
}

func getCloudflareAccessPublicKey(teamName, kid string) (*rsa.PublicKey, error) {
	certsURL := fmt.Sprintf("https://%s.cloudflareaccess.com/cdn-cgi/access/certs", teamName)
	
	resp, err := http.Get(certsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certs: %v", err)
	}
	defer resp.Body.Close()

	var certs CloudflareAccessCerts
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return nil, fmt.Errorf("failed to decode certs: %v", err)
	}

	// Find the key with matching kid
	for _, key := range certs.Keys {
		if key.Kid == kid {
			return parseRSAPublicKey(key.N, key.E)
		}
	}

	return nil, fmt.Errorf("public key not found for kid: %s", kid)
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %v", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %v", err)
	}

	// Convert bytes to big.Int
	n := new(big.Int).SetBytes(nBytes)
	
	// Convert e bytes to int
	e := 0
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

func verifyJWTSignature(tokenString string, publicKey *rsa.PublicKey) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Create signing string
	signingString := parts[0] + "." + parts[1]
	
	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	// Verify signature using RSA-SHA256
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sha256Hash([]byte(signingString)), signature)
}

func sha256Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// validateAudience 验证 audience 字段（支持字符串或字符串数组）
func validateAudience(audClaim interface{}, expectedAudience string) bool {
	switch aud := audClaim.(type) {
	case string:
		return aud == expectedAudience
	case []interface{}:
		for _, a := range aud {
			if str, ok := a.(string); ok && str == expectedAudience {
				return true
			}
		}
		return false
	case []string:
		for _, a := range aud {
			if a == expectedAudience {
				return true
			}
		}
		return false
	default:
		return false
	}
}