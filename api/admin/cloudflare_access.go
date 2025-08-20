package admin

import (
	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/api"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/database/config"
)

// BindCloudflareAccess 绑定 Cloudflare Access 账户
func BindCloudflareAccess(c *gin.Context) {
	cfg, err := config.Get()
	if err != nil || !cfg.CloudflareAccessEnabled {
		api.RespondError(c, 400, "Cloudflare Access is not enabled")
		return
	}

	// 获取当前用户
	session, _ := c.Cookie("session_token")
	user, err := accounts.GetUserBySession(session)
	if err != nil {
		api.RespondError(c, 500, "No user found: "+err.Error())
		return
	}

	// 获取 Cloudflare Access JWT (从请求头或 cookie)
	token := c.GetHeader("Cf-Access-Jwt-Assertion")
	if token == "" {
		// 如果请求头中没有，尝试从 cookie 中获取
		token, _ = c.Cookie("CF_Authorization")
	}
	if token == "" {
		api.RespondError(c, 400, "No Cloudflare Access token found. Please access this page through Cloudflare Access.")
		return
	}

	// 验证 JWT
	claims, err := api.ValidateCloudflareAccessJWT(token, cfg.CloudflareAccessTeamName, cfg.CloudflareAccessAudience)
	if err != nil {
		api.RespondError(c, 400, "Invalid Cloudflare Access token: "+err.Error())
		return
	}

	// 绑定 Cloudflare Access
	err = accounts.BindCloudflareAccess(user.UUID, claims.Email)
	if err != nil {
		api.RespondError(c, 500, "Failed to bind Cloudflare Access: "+err.Error())
		return
	}

	auditlog.Log(c.ClientIP(), user.UUID, "bound Cloudflare Access account: "+claims.Email, "login")
	api.RespondSuccess(c, gin.H{"message": "Cloudflare Access account bound successfully"})
}

// UnbindCloudflareAccess 解绑 Cloudflare Access 账户
func UnbindCloudflareAccess(c *gin.Context) {
	// 获取当前用户
	session, _ := c.Cookie("session_token")
	user, err := accounts.GetUserBySession(session)
	if err != nil {
		api.RespondError(c, 500, "No user found: "+err.Error())
		return
	}

	// 检查用户是否绑定了 Cloudflare Access
	if user.SSOType != "cloudflare_access" {
		api.RespondError(c, 400, "No Cloudflare Access account is bound to this user")
		return
	}

	// 解绑 Cloudflare Access
	err = accounts.UnbindCloudflareAccess(user.UUID)
	if err != nil {
		api.RespondError(c, 500, "Failed to unbind Cloudflare Access: "+err.Error())
		return
	}

	auditlog.Log(c.ClientIP(), user.UUID, "unbound Cloudflare Access account", "login")
	api.RespondSuccess(c, gin.H{"message": "Cloudflare Access account unbound successfully"})
}

// GetCloudflareAccessStatus 获取 Cloudflare Access 绑定状态
func GetCloudflareAccessStatus(c *gin.Context) {
	cfg, err := config.Get()
	if err != nil {
		api.RespondError(c, 500, "Failed to get config: "+err.Error())
		return
	}

	// 获取当前用户
	session, _ := c.Cookie("session_token")
	user, err := accounts.GetUserBySession(session)
	if err != nil {
		api.RespondError(c, 500, "No user found: "+err.Error())
		return
	}

	// 检查是否有 Cloudflare Access JWT (从请求头或 cookie)
	token := c.GetHeader("Cf-Access-Jwt-Assertion")
	if token == "" {
		// 如果请求头中没有，尝试从 cookie 中获取
		token, _ = c.Cookie("CF_Authorization")
	}
	var currentAccessEmail string
	if token != "" && cfg.CloudflareAccessEnabled {
		claims, err := api.ValidateCloudflareAccessJWT(token, cfg.CloudflareAccessTeamName, cfg.CloudflareAccessAudience)
		if err == nil {
			currentAccessEmail = claims.Email
		}
	}

	status := gin.H{
		"enabled":              cfg.CloudflareAccessEnabled,
		"bound":                user.SSOType == "cloudflare_access",
		"bound_email":          "",
		"current_access_email": currentAccessEmail,
		"can_bind":             cfg.CloudflareAccessEnabled && currentAccessEmail != "",
	}

	if user.SSOType == "cloudflare_access" {
		status["bound_email"] = user.SSOID
	}

	api.RespondSuccess(c, status)
}