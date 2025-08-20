package api

import (
	"net/http"

	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/config"

	"github.com/gin-gonic/gin"
)

func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// API key authentication
		apiKey := c.GetHeader("Authorization")
		if isApiKeyValid(apiKey) {
			c.Set("api_key", apiKey)
			c.Next()
			return
		}

		// Cloudflare Access authentication
		if uuid, session := tryCloudflareAccessAuth(c); uuid != "" {
			c.Set("session", session)
			c.Set("uuid", uuid)
			c.Next()
			return
		}

		// session-based authentication
		session, err := c.Cookie("session_token")
		if err != nil {
			RespondError(c, http.StatusUnauthorized, "Unauthorized.")
			c.Abort()
			return
		}

		// Komari is a single user system
		uuid, err := accounts.GetSession(session)
		if err != nil {
			RespondError(c, http.StatusUnauthorized, "Unauthorized.")
			c.Abort()
			return
		}
		accounts.UpdateLatest(session, c.Request.UserAgent(), c.ClientIP())
		// 将 session 和 用户 UUID 传递到后续处理器
		c.Set("session", session)
		c.Set("uuid", uuid)

		c.Next()
	}
}

func tryCloudflareAccessAuth(c *gin.Context) (uuid, session string) {
	cfg, err := config.Get()
	if err != nil || !cfg.CloudflareAccessEnabled {
		return "", ""
	}

	// Get JWT from header
	token := c.GetHeader("Cf-Access-Jwt-Assertion")
	if token == "" {
		return "", ""
	}

	// Validate JWT
	claims, err := ValidateCloudflareAccessJWT(token, cfg.CloudflareAccessTeamName, cfg.CloudflareAccessAudience)
	if err != nil {
		return "", ""
	}

	// Try to get user by Cloudflare Access email
	user, err := accounts.GetUserByCloudflareAccess(claims.Email)
	if err != nil {
		return "", ""
	}

	// Check if user has an active session
	sessions, err := accounts.GetUserSessions(user.UUID)
	if err != nil || len(sessions) == 0 {
		// Create new session
		session, err := accounts.CreateSession(user.UUID, 2592000, c.Request.UserAgent(), c.ClientIP(), "cloudflare_access")
		if err != nil {
			return "", ""
		}
		c.SetCookie("session_token", session, 2592000, "/", "", false, true)
		return user.UUID, session
	}

	// Use existing session
	return user.UUID, sessions[0].Session
}
