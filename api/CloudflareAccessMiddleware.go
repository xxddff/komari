package api

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
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

		// 先检查是否已经有有效的 session，避免不必要的 JWT 验证
		if session, err := c.Cookie("session_token"); err == nil {
			if _, err := accounts.GetSession(session); err == nil {
				// 已经有有效session，更新最后活动时间并继续
				accounts.UpdateLatest(session, c.Request.UserAgent(), c.ClientIP())
				c.Next()
				return
			}
		}

		// 只有在没有有效 session 时才验证 JWT token
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		
		claims, err := validateCloudflareJWT(ctx, jwtToken)
		if err != nil {
			log.Printf("Cloudflare Access: JWT validation failed: %v", err)
			c.Next()
			return
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
		return "", fmt.Errorf("Email not authorized for access")
	}
	
	// 这里实际上不会到达，但为了编译通过
	return "", fmt.Errorf("No admin user found")
}


// CloudflareAccessClaims JWT claims 结构
type CloudflareAccessClaims struct {
	Email string `json:"email"`
}

// validateCloudflareJWT 验证 Cloudflare Access JWT token
func validateCloudflareJWT(ctx context.Context, token string) (*CloudflareAccessClaims, error) {
	// 获取环境变量
	teamName := os.Getenv("KOMARI_CF_ACCESS_TEAM_NAME")
	if teamName == "" {
		return nil, fmt.Errorf("KOMARI_CF_ACCESS_TEAM_NAME environment variable not set")
	}
	
	audience := os.Getenv("KOMARI_CF_ACCESS_AUDIENCE")
	if audience == "" {
		return nil, fmt.Errorf("KOMARI_CF_ACCESS_AUDIENCE environment variable not set")
	}

	// 构建验证器
	teamDomain := fmt.Sprintf("https://%s.cloudflareaccess.com", teamName)
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", teamDomain)

	config := &oidc.Config{
		ClientID: audience,
	}

	keySet := oidc.NewRemoteKeySet(ctx, certsURL)
	verifier := oidc.NewVerifier(teamDomain, keySet, config)

	// 验证 JWT token
	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %v", err)
	}

	// 解析 claims
	var claims CloudflareAccessClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %v", err)
	}

	return &claims, nil
}
