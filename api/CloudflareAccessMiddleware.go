package api

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"

	"github.com/gin-gonic/gin"
)

// CloudflareAccessMiddleware 处理 Cloudflare Access 认证
func CloudflareAccessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 检查是否启用了 Cloudflare Access
		cfAccessEnabled := strings.ToLower(os.Getenv("KOMARI_CF_ACCESS_ENABLED")) == "true"
		if !cfAccessEnabled {
			c.Next()
			return
		}

		// 获取 Cloudflare Access JWT token
		jwtToken := c.GetHeader("Cf-Access-Jwt-Assertion")
		
		// 如果没有 JWT token，继续正常流程
		if jwtToken == "" {
			c.Next()
			return
		}

		// 验证 JWT token
		claims, err := validateCloudflareJWT(jwtToken)
		if err != nil {
			log.Printf("Cloudflare Access: JWT validation failed: %v", err)
			c.Next()
			return
		}

		// 检查是否已经有有效的 session
		if session, err := c.Cookie("session_token"); err == nil {
			if _, err := accounts.GetSession(session); err == nil {
				// 已经有有效session，更新最后活动时间并继续
				accounts.UpdateLatest(session, c.Request.UserAgent(), c.ClientIP())
				c.Next()
				return
			}
		}

		// 尝试根据邮箱获取用户
		uuid, err := getUserByEmail(claims.Email)
		if err != nil {
			log.Printf("Cloudflare Access: Failed to get user for email %s: %v", claims.Email, err)
			c.Next()
			return
		}

		// 创建新的 session
		session, err := accounts.CreateSession(uuid, 2592000, c.Request.UserAgent(), c.ClientIP(), "cloudflare_access")
		if err != nil {
			log.Printf("Cloudflare Access: Failed to create session for user %s: %v", uuid, err)
			c.Next()
			return
		}

		// 设置 session cookie
		c.SetCookie("session_token", session, 2592000, "/", "", false, true)
		
		// 记录审计日志
		auditlog.Log(c.ClientIP(), uuid, "logged in (Cloudflare Access)", "login")
		
		log.Printf("Cloudflare Access: User %s automatically logged in via JWT", claims.Email)
		
		c.Next()
	}
}

// getUserByEmail 根据邮箱获取用户
func getUserByEmail(email string) (string, error) {
	// 获取默认管理员邮箱配置
	adminEmail := os.Getenv("KOMARI_CF_ACCESS_ADMIN_EMAIL")
	
	// CloudFlare Access登入邮箱匹配
	if adminEmail != "" && strings.ToLower(email) == strings.ToLower(adminEmail) {
		// 获取第一个用户（默认管理员）
		db := dbcore.GetDBInstance()
		var user models.User
		err := db.First(&user).Error
		if err != nil {
			return "", err
		}
		return user.UUID, nil
	}
	
	// 对于非管理员邮箱，或空
	// 不允许自动登入
	if adminEmail == "" || strings.ToLower(email) != strings.ToLower(adminEmail) {
		log.Printf("Cloudflare Access: Email %s is not configured as admin email", email)
		return "", &UnauthorizedError{Message: "Email not authorized for access"}
	}
	
	return "", &UnauthorizedError{Message: "No admin user found"}
}

// UnauthorizedError 自定义错误类型
type UnauthorizedError struct {
	Message string
}

func (e *UnauthorizedError) Error() string {
	return e.Message
}

// CloudflareAccessClaims JWT claims 结构
type CloudflareAccessClaims struct {
	Aud           []string               `json:"aud"`
	Email         string                 `json:"email"`
	Exp           int64                  `json:"exp"`
	Iat           int64                  `json:"iat"`
	Nbf           int64                  `json:"nbf"`
	Iss           string                 `json:"iss"`
	Type          string                 `json:"type"`
	IdentityNonce string                 `json:"identity_nonce"`
	Sub           string                 `json:"sub"`
	Custom        map[string]interface{} `json:"custom"`
	Country       string                 `json:"country"`
}

// JWTHeader JWT 头部结构
type JWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// CloudflareJWKS Cloudflare 公钥集合
type CloudflareJWKS struct {
	Keys []CloudflareJWK `json:"keys"`
}

// CloudflareJWK Cloudflare 公钥
type CloudflareJWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// validateCloudflareJWT 验证 Cloudflare Access JWT token
func validateCloudflareJWT(token string) (*CloudflareAccessClaims, error) {
	// 分割 JWT token
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// 解析头部
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %v", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %v", err)
	}

	// 解析 payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %v", err)
	}

	var claims CloudflareAccessClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %v", err)
	}

	// 验证 issuer
	teamName := os.Getenv("KOMARI_CF_ACCESS_TEAM_NAME")
	if teamName == "" {
		return nil, fmt.Errorf("KOMARI_CF_ACCESS_TEAM_NAME environment variable not set")
	}
	expectedIssuer := fmt.Sprintf("https://%s.cloudflareaccess.com", teamName)
	if claims.Iss != expectedIssuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", expectedIssuer, claims.Iss)
	}

	// 验证 audience
	expectedAudience := os.Getenv("KOMARI_CF_ACCESS_AUDIENCE")
	if expectedAudience == "" {
		return nil, fmt.Errorf("KOMARI_CF_ACCESS_AUDIENCE environment variable not set")
	}
	
	audienceValid := false
	for _, aud := range claims.Aud {
		if aud == expectedAudience {
			audienceValid = true
			break
		}
	}
	if !audienceValid {
		return nil, fmt.Errorf("invalid audience: expected %s, got %v", expectedAudience, claims.Aud)
	}

	// 验证时间
	now := time.Now().Unix()
	if claims.Exp < now {
		return nil, fmt.Errorf("token expired")
	}
	if claims.Nbf > now {
		return nil, fmt.Errorf("token not yet valid")
	}

	// 获取 Cloudflare 公钥并验证签名
	if err := verifyJWTSignature(token, header.Kid, claims.Iss); err != nil {
		return nil, fmt.Errorf("signature verification failed: %v", err)
	}

	return &claims, nil
}

// verifyJWTSignature 验证 JWT 签名
func verifyJWTSignature(token, kid, issuer string) error {
	// 获取 JWKS URL
	jwksURL := strings.Replace(issuer, "https://", "https://", 1) + "/cdn-cgi/access/certs"
	
	// 获取公钥
	publicKey, err := getCloudflarePublicKey(jwksURL, kid)
	if err != nil {
		return fmt.Errorf("failed to get public key: %v", err)
	}

	// 分割 token
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// 创建签名数据
	signatureData := parts[0] + "." + parts[1]
	
	// 解码签名
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	// 计算哈希
	hash := sha256.Sum256([]byte(signatureData))

	// 验证签名
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	return nil
}

// getCloudflarePublicKey 从 Cloudflare JWKS 获取公钥
func getCloudflarePublicKey(jwksURL, kid string) (*rsa.PublicKey, error) {
	// 发起 HTTP 请求获取 JWKS
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request failed with status: %d", resp.StatusCode)
	}

	var jwks CloudflareJWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %v", err)
	}

	// 查找匹配的密钥
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return jwkToRSAPublicKey(&key)
		}
	}

	return nil, fmt.Errorf("key with kid %s not found", kid)
}

// jwkToRSAPublicKey 将 JWK 转换为 RSA 公钥
func jwkToRSAPublicKey(jwk *CloudflareJWK) (*rsa.PublicKey, error) {
	// 解码 n (modulus)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %v", err)
	}

	// 解码 e (exponent)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %v", err)
	}

	// 创建 RSA 公钥
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	return publicKey, nil
}
