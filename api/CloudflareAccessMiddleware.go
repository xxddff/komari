package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/database/config"
	"github.com/komari-monitor/komari/database"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/utils/oauth/cloudflare"
	"github.com/komari-monitor/komari/utils/oauth/factory"
)

// CloudflareAccessMiddleware 处理 Cloudflare Access 认证
func CloudflareAccessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从数据库获取配置
		cfg, err := config.Get()
		if err != nil {
			log.Printf("Cloudflare Access: Failed to get config: %v", err)
			c.Next()
			return
		}

		// 检查是否启用了 Cloudflare Access 且配置为 cloudflare 提供商
		if !cfg.OAuthEnabled || cfg.OAuthProvider != "cloudflare" {
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

		// 获取 Cloudflare Access 提供商配置
		provider, err := getCloudflareProvider()
		if err != nil {
			log.Printf("Cloudflare Access: Failed to get provider: %v", err)
			c.Next()
			return
		}
		
		// 从数据库加载配置
		err = loadCloudflareConfig(provider)
		if err != nil {
			log.Printf("Cloudflare Access: Failed to load config: %v", err)
			c.Next()
			return
		}

		// 只有在没有有效 session 时才验证 JWT token
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		
		claims, err := provider.ValidateJWT(ctx, jwtToken)
		if err != nil {
			log.Printf("Cloudflare Access: JWT validation failed: %v", err)
			c.Next()
			return
		}

		// 尝试根据邮箱获取或创建用户绑定
		uuid, err := getOrCreateUserByEmail(claims.Email)
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

// getCloudflareProvider 获取 Cloudflare Access 提供商实例
func getCloudflareProvider() (*cloudflare.CloudflareAccess, error) {
	constructor, exists := factory.GetConstructor("cloudflare")
	if !exists {
		return nil, fmt.Errorf("cloudflare provider not found")
	}
	
	provider := constructor().(*cloudflare.CloudflareAccess)
	return provider, nil
}

// getOrCreateUserByEmail 根据邮箱获取用户，如果是通过 Cloudflare Access 认证的用户，自动创建绑定
func getOrCreateUserByEmail(email string) (string, error) {
	// 生成 SSO ID
	ssoID := fmt.Sprintf("cloudflare_%s", email)
	
	// 尝试通过 SSO ID 获取用户
	user, err := accounts.GetUserBySSO(ssoID)
	if err == nil {
		// 用户已存在，返回 UUID
		return user.UUID, nil
	}
	
	// 用户不存在，需要先有管理员账户才能自动绑定
	// 获取第一个用户（默认管理员）
	db := dbcore.GetDBInstance()
	var adminUser models.User
	err = db.First(&adminUser).Error
	if err != nil {
		return "", fmt.Errorf("no admin user found, please create an admin account first")
	}
	
	// 自动为管理员绑定 Cloudflare Access 账户
	err = accounts.BindingExternalAccount(adminUser.UUID, ssoID)
	if err != nil {
		return "", fmt.Errorf("failed to bind external account: %v", err)
	}
	
	log.Printf("Cloudflare Access: Auto-bound email %s to admin account %s", email, adminUser.UUID)
	return adminUser.UUID, nil
}

// loadCloudflareConfig 从数据库加载 Cloudflare Access 配置
func loadCloudflareConfig(provider *cloudflare.CloudflareAccess) error {
	cfConfig, err := database.GetOidcConfigByName("cloudflare")
	if err != nil {
		return fmt.Errorf("cloudflare config not found: %v", err)
	}
	
	if cfConfig.Addition == "" {
		return fmt.Errorf("cloudflare config is empty")
	}
	
	// 解析配置
	err = json.Unmarshal([]byte(cfConfig.Addition), &provider.Addition)
	if err != nil {
		return fmt.Errorf("failed to parse cloudflare config: %v", err)
	}
	
	if provider.Addition.TeamName == "" || provider.Addition.Audience == "" {
		return fmt.Errorf("cloudflare config incomplete: team_name and audience are required")
	}
	
	return nil
}
