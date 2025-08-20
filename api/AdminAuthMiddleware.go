package api

import (
	"log"
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

	// Get JWT from header or cookie
	token := c.GetHeader("Cf-Access-Jwt-Assertion")
	if token == "" {
		// 如果请求头中没有，尝试从 cookie 中获取
		token, _ = c.Cookie("CF_Authorization")
	}
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
		log.Printf("DEBUG: User not found for email %s, creating new user: %v", claims.Email, err)
		// User not found, create a new one
		user, err = accounts.CreateCloudflareAccessUser(claims.Email, claims.Sub)
		if err != nil {
			log.Printf("DEBUG: Failed to create user: %v", err)
			return "", ""
		}
		log.Printf("DEBUG: Created new user with UUID: %s", user.UUID)
	} else {
		log.Printf("DEBUG: Found existing user with UUID: %s", user.UUID)
	}

	// Check if user has an active session
	sessions, err := accounts.GetUserSessions(user.UUID)
	if err != nil {
		log.Printf("DEBUG: Error getting user sessions: %v", err)
	}
	log.Printf("DEBUG: Found %d existing sessions for user %s", len(sessions), user.UUID)
	
	if err != nil || len(sessions) == 0 {
		// Create new session
		log.Printf("DEBUG: Creating new session for user %s", user.UUID)
		session, err := accounts.CreateSession(user.UUID, 2592000, c.Request.UserAgent(), c.ClientIP(), "cloudflare_access")
		if err != nil {
			log.Printf("DEBUG: Failed to create session: %v", err)
			return "", ""
		}
		log.Printf("DEBUG: Created new session: %s", session)
		c.SetCookie("session_token", session, 2592000, "/", "", false, true)
		return user.UUID, session
	}

	// Use existing session
	log.Printf("DEBUG: Using existing session: %s", sessions[0].Session)
	return user.UUID, sessions[0].Session
}
