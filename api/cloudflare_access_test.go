package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/accounts"
	"github.com/komari-monitor/komari/database/config"
	"github.com/komari-monitor/komari/database"
	"github.com/komari-monitor/komari/database/models"
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
		oauthEnabled        bool
		oauthProvider       string
		cloudflareConfig    *models.OidcProvider
		jwtToken            string
		existingSession     string
		expectedStatusCode  int
		expectedSetCookie   bool
	}{
		{
			name:               "OAuth disabled - should continue normally",
			oauthEnabled:       false,
			oauthProvider:      "github",
			jwtToken:           "valid-jwt-token",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false,
		},
		{
			name:               "OAuth enabled but not cloudflare provider - should continue normally",
			oauthEnabled:       true,
			oauthProvider:      "github",
			jwtToken:           "valid-jwt-token",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false,
		},
		{
			name:               "No JWT token - should continue normally",
			oauthEnabled:       true,
			oauthProvider:      "cloudflare",
			cloudflareConfig: &models.OidcProvider{
				Name:     "cloudflare",
				Addition: `{"team_name":"test-team","audience":"test-audience"}`,
			},
			jwtToken:           "",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false,
		},
		{
			name:               "Cloudflare config not found - should continue normally",
			oauthEnabled:       true,
			oauthProvider:      "cloudflare",
			cloudflareConfig:   nil,
			jwtToken:           "valid-jwt-token",
			expectedStatusCode: http.StatusOK,
			expectedSetCookie:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 设置配置
			cfg := map[string]interface{}{
				"o_auth_enabled":  tt.oauthEnabled,
				"o_auth_provider": tt.oauthProvider,
			}
			config.Update(cfg)
			
			// 设置 Cloudflare 配置
			if tt.cloudflareConfig != nil {
				database.SaveOidcConfig(tt.cloudflareConfig)
				defer func() {
					// 清理测试数据
					// 这里可以添加清理逻辑
				}()
			}

			// 创建测试请求
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/test", nil)
			
			if tt.jwtToken != "" {
				c.Request.Header.Set("Cf-Access-Jwt-Assertion", tt.jwtToken)
			}
			
			if tt.existingSession != "" {
				c.Request.Header.Set("Cookie", "session_token="+tt.existingSession)
			}

			// 创建中间件并执行
			middleware := CloudflareAccessMiddleware()
			middleware(c)

			// 验证结果
			assert.Equal(t, tt.expectedStatusCode, w.Code)
			
			if tt.expectedSetCookie {
				cookies := w.Header().Get("Set-Cookie")
				assert.Contains(t, cookies, "session_token")
			}
		})
	}
}

func TestGetOrCreateUserByEmail(t *testing.T) {
	// 创建测试用户
	accounts.CreateAccount("testuser", "testpassword")
	defer accounts.DeleteAccountByUsername("testuser")

	tests := []struct {
		name        string
		email       string
		expectError bool
	}{
		{
			name:        "Valid email - should create binding",
			email:       "test@example.com",
			expectError: false,
		},
		{
			name:        "Same email again - should return existing binding",
			email:       "test@example.com",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uuid, err := getOrCreateUserByEmail(tt.email)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, uuid)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, uuid)
			}
		})
	}
}