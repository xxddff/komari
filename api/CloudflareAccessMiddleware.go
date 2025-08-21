package api

import (
	"log"
	"os"
	"strings"

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

		// 获取 Cloudflare Access 提供的用户信息
		userEmail := c.GetHeader("Cf-Access-Authenticated-User-Email")
		
		// 如果没有 Cloudflare Access 头信息，继续正常流程
		if userEmail == "" {
			c.Next()
			return
		}

		// 验证是否为受信任的域名（可选的额外安全检查）
		trustedDomain := os.Getenv("KOMARI_CF_ACCESS_TRUSTED_DOMAIN")
		if trustedDomain != "" {
			cfAccessAudience := c.GetHeader("Cf-Access-Audience")
			if cfAccessAudience != trustedDomain {
				log.Printf("Cloudflare Access: Untrusted domain. Expected: %s, Got: %s", trustedDomain, cfAccessAudience)
				c.Next()
				return
			}
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

		// 尝试根据邮箱获取或创建用户
		uuid, err := getOrCreateUserByEmail(userEmail)
		if err != nil {
			log.Printf("Cloudflare Access: Failed to get or create user for email %s: %v", userEmail, err)
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
		
		log.Printf("Cloudflare Access: User %s automatically logged in", userEmail)
		
		c.Next()
	}
}

// getOrCreateUserByEmail 根据邮箱获取或创建用户
func getOrCreateUserByEmail(email string) (string, error) {
	// 获取默认管理员邮箱配置
	adminEmail := os.Getenv("KOMARI_CF_ACCESS_ADMIN_EMAIL")
	
	// 如果是配置的管理员邮箱，查找现有的管理员账户
	if adminEmail != "" && strings.ToLower(email) == strings.ToLower(adminEmail) {
		// 由于 Komari 是单用户系统，获取第一个用户（默认管理员）
		db := dbcore.GetDBInstance()
		var user models.User
		err := db.First(&user).Error
		if err != nil {
			return "", err
		}
		return user.UUID, nil
	}
	
	// 对于非管理员邮箱，由于 Komari 是单用户系统，
	// 这里可以选择拒绝访问或者也绑定到管理员账户
	// 为了安全起见，只有配置的管理员邮箱才能自动登录
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
