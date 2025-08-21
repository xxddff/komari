package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/stretchr/testify/assert"
)

func TestCloudflareAccessMiddleware(t *testing.T) {
	// 设置测试模式
	gin.SetMode(gin.TestMode)
	
	// 创建测试用户
	accounts.CreateAccount("testuser", "testpassword")
	defer accounts.DeleteAccountByUsername("testuser")
	defer accounts.DeleteAllSessions()

	tests := []struct {
		name                string
		cfAccessEnabled     string
		adminEmail          string
		teamName            string
		audience            string
		jwtToken            string
		existingSession     string
		expectedStatusCode  int
		expectedSetCookie   bool
	}{
		{
			name:               "CF Access disabled - should continue normally",
			cfAccessEnabled:    "false",
			jwtToken:           "valid-jwt-token",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false,
		},
		{
			name:               "No JWT token - should continue normally",
			cfAccessEnabled:    "true",
			adminEmail:         "admin@test.com",
			teamName:           "test-team",
			audience:           "test-audience",
			jwtToken:           "",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false,
		},
		{
			name:               "Valid existing session - should skip JWT validation",
			cfAccessEnabled:    "true",
			adminEmail:         "admin@test.com",
			teamName:           "test-team",
			audience:           "test-audience",
			jwtToken:           "valid-jwt-token",
			existingSession:    "valid-session",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false,
		},
		{
			name:               "Valid JWT with admin email - should create session (will fail JWT validation but continue)",
			cfAccessEnabled:    "true",
			adminEmail:         "admin@test.com",
			teamName:           "test-team",
			audience:           "test-audience",
			jwtToken:           "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFkbWluQHRlc3QuY29tIn0.fake-signature",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false, // Will be false because JWT validation will fail in test
		},
		{
			name:               "Valid JWT with non-admin email - should continue normally",
			cfAccessEnabled:    "true",
			adminEmail:         "admin@test.com",
			teamName:           "test-team",
			audience:           "test-audience",
			jwtToken:           "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXJAdGVzdC5jb20ifQ.fake-signature",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false,
		},
		{
			name:               "Invalid JWT token - should continue normally",
			cfAccessEnabled:    "true",
			adminEmail:         "admin@test.com",
			teamName:           "test-team",
			audience:           "test-audience",
			jwtToken:           "invalid-jwt-token",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false,
		},
		{
			name:               "Missing team name - should continue normally",
			cfAccessEnabled:    "true",
			adminEmail:         "admin@test.com",
			teamName:           "",
			audience:           "test-audience",
			jwtToken:           "valid-jwt-token",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false,
		},
		{
			name:               "Missing audience - should continue normally",
			cfAccessEnabled:    "true",
			adminEmail:         "admin@test.com",
			teamName:           "test-team",
			audience:           "",
			jwtToken:           "valid-jwt-token",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置环境变量
			os.Setenv("KOMARI_CF_ACCESS_ENABLED", tt.cfAccessEnabled)
			os.Setenv("KOMARI_CF_ACCESS_ADMIN_EMAIL", tt.adminEmail)
			os.Setenv("KOMARI_CF_ACCESS_TEAM_NAME", tt.teamName)
			os.Setenv("KOMARI_CF_ACCESS_AUDIENCE", tt.audience)
			
			defer func() {
				os.Unsetenv("KOMARI_CF_ACCESS_ENABLED")
				os.Unsetenv("KOMARI_CF_ACCESS_ADMIN_EMAIL")
				os.Unsetenv("KOMARI_CF_ACCESS_TEAM_NAME")
				os.Unsetenv("KOMARI_CF_ACCESS_AUDIENCE")
			}()

			// 创建测试路由
			router := gin.New()
			router.Use(CloudflareAccessMiddleware())
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// 创建测试请求
			req, _ := http.NewRequest("GET", "/test", nil)
			
			// 设置 JWT token header
			if tt.jwtToken != "" {
				req.Header.Set("Cf-Access-Jwt-Assertion", tt.jwtToken)
			}

			// 设置现有 session cookie
			if tt.existingSession != "" {
				// 创建一个有效的 session
				uuid, _ := accounts.CheckPassword("testuser", "testpassword")
				session, _ := accounts.CreateSession(uuid, 3600, "test-agent", "127.0.0.1", "test")
				req.AddCookie(&http.Cookie{
					Name:  "session_token",
					Value: session,
				})
			}

			// 创建响应记录器
			w := httptest.NewRecorder()

			// 执行请求
			router.ServeHTTP(w, req)

			// 断言状态码
			assert.Equal(t, tt.expectedStatusCode, w.Code)

			// 检查是否设置了 session cookie
			cookies := w.Result().Cookies()
			sessionCookieSet := false
			for _, cookie := range cookies {
				if cookie.Name == "session_token" && cookie.Value != "" {
					sessionCookieSet = true
					break
				}
			}
			assert.Equal(t, tt.expectedSetCookie, sessionCookieSet)

			// 解析响应体
			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response["message"])
		})
	}
}

func TestGetUserByEmail(t *testing.T) {
	// 创建测试用户
	accounts.CreateAccount("testuser", "testpassword")
	defer accounts.DeleteAccountByUsername("testuser")

	tests := []struct {
		name        string
		email       string
		adminEmail  string
		expectError bool
		errorType   string
	}{
		{
			name:        "Valid admin email - should return user UUID",
			email:       "admin@test.com",
			adminEmail:  "admin@test.com",
			expectError: false,
		},
		{
			name:        "Case insensitive admin email - should return user UUID",
			email:       "ADMIN@TEST.COM",
			adminEmail:  "admin@test.com",
			expectError: false,
		},
		{
			name:        "Non-admin email - should return error",
			email:       "user@test.com",
			adminEmail:  "admin@test.com",
			expectError: true,
			errorType:   "Email not authorized for access",
		},
		{
			name:        "Empty admin email config - should return error",
			email:       "admin@test.com",
			adminEmail:  "",
			expectError: true,
			errorType:   "Email not authorized for access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置环境变量
			os.Setenv("KOMARI_CF_ACCESS_ADMIN_EMAIL", tt.adminEmail)
			defer os.Unsetenv("KOMARI_CF_ACCESS_ADMIN_EMAIL")

			// 调用函数
			uuid, err := getUserByEmail(tt.email)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != "" {
					assert.Contains(t, err.Error(), tt.errorType)
				}
				assert.Empty(t, uuid)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, uuid)
			}
		})
	}
}

func TestValidateCloudflareJWT(t *testing.T) {
	tests := []struct {
		name        string
		teamName    string
		audience    string
		token       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Missing team name - should return error",
			teamName:    "",
			audience:    "test-audience",
			token:       "test-token",
			expectError: true,
			errorMsg:    "KOMARI_CF_ACCESS_TEAM_NAME environment variable not set",
		},
		{
			name:        "Missing audience - should return error",
			teamName:    "test-team",
			audience:    "",
			token:       "test-token",
			expectError: true,
			errorMsg:    "KOMARI_CF_ACCESS_AUDIENCE environment variable not set",
		},
		{
			name:        "Invalid token format - should return error",
			teamName:    "test-team",
			audience:    "test-audience",
			token:       "invalid-token",
			expectError: true,
			errorMsg:    "token verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置环境变量
			os.Setenv("KOMARI_CF_ACCESS_TEAM_NAME", tt.teamName)
			os.Setenv("KOMARI_CF_ACCESS_AUDIENCE", tt.audience)
			
			defer func() {
				os.Unsetenv("KOMARI_CF_ACCESS_TEAM_NAME")
				os.Unsetenv("KOMARI_CF_ACCESS_AUDIENCE")
			}()

			// 创建上下文
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// 调用函数
			claims, err := validateCloudflareJWT(ctx, tt.token)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, claims)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
			}
		})
	}
}

func TestLogoutWithCloudflareAccess(t *testing.T) {
	// 设置测试模式
	gin.SetMode(gin.TestMode)
	
	// 创建测试用户和 session
	accounts.CreateAccount("testuser", "testpassword")
	uuid, _ := accounts.CheckPassword("testuser", "testpassword")
	session, _ := accounts.CreateSession(uuid, 3600, "test-agent", "127.0.0.1", "test")
	
	defer func() {
		accounts.DeleteAccountByUsername("testuser")
		accounts.DeleteAllSessions()
	}()

	tests := []struct {
		name               string
		cfAccessEnabled    string
		teamName           string
		expectedStatusCode int
		expectedLocation   string
	}{
		{
			name:               "CF Access disabled - should redirect to root",
			cfAccessEnabled:    "false",
			teamName:           "",
			expectedStatusCode: http.StatusFound,
			expectedLocation:   "/",
		},
		{
			name:               "CF Access enabled without team name - should redirect to root",
			cfAccessEnabled:    "true",
			teamName:           "",
			expectedStatusCode: http.StatusFound,
			expectedLocation:   "/",
		},
		{
			name:               "CF Access enabled with team name - should redirect to CF logout",
			cfAccessEnabled:    "true",
			teamName:           "test-team",
			expectedStatusCode: http.StatusFound,
			expectedLocation:   "https://test-team.cloudflareaccess.com/cdn-cgi/access/logout?returnTo=http%3A%2F%2Fexample.com%2F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置环境变量
			os.Setenv("KOMARI_CF_ACCESS_ENABLED", tt.cfAccessEnabled)
			os.Setenv("KOMARI_CF_ACCESS_TEAM_NAME", tt.teamName)
			
			defer func() {
				os.Unsetenv("KOMARI_CF_ACCESS_ENABLED")
				os.Unsetenv("KOMARI_CF_ACCESS_TEAM_NAME")
			}()

			// 创建测试路由
			router := gin.New()
			router.POST("/logout", Logout)

			// 创建测试请求
			req, _ := http.NewRequest("POST", "/logout", nil)
			req.Host = "example.com"
			req.AddCookie(&http.Cookie{
				Name:  "session_token",
				Value: session,
			})

			// 创建响应记录器
			w := httptest.NewRecorder()

			// 执行请求
			router.ServeHTTP(w, req)

			// 断言状态码
			assert.Equal(t, tt.expectedStatusCode, w.Code)

			// 断言重定向位置
			location := w.Header().Get("Location")
			assert.Equal(t, tt.expectedLocation, location)

			// 检查 session cookie 是否被清除
			cookies := w.Result().Cookies()
			sessionCookieCleared := false
			for _, cookie := range cookies {
				if cookie.Name == "session_token" && cookie.Value == "" && cookie.MaxAge == -1 {
					sessionCookieCleared = true
					break
				}
			}
			assert.True(t, sessionCookieCleared, "Session cookie should be cleared")
		})
	}
}

