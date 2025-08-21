package cloudflare

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/komari-monitor/komari/utils/oauth/factory"
	"github.com/patrickmn/go-cache"
)

func (cf *CloudflareAccess) GetName() string {
	return "cloudflare"
}

func (cf *CloudflareAccess) GetConfiguration() factory.Configuration {
	return &cf.Addition
}

func (cf *CloudflareAccess) GetAuthorizationURL(redirectURI string) (string, string) {
	// Cloudflare Access 不需要传统的OAuth授权流程
	// 用户通过Cloudflare Access认证后，JWT会自动包含在请求头中
	// 这里返回一个特殊的URL，表示需要通过Cloudflare Access认证
	state := "cloudflare_access_direct"
	return fmt.Sprintf("%s?cloudflare_access=true", redirectURI), state
}

func (cf *CloudflareAccess) OnCallback(ctx context.Context, state string, query map[string]string, callbackURI string) (factory.OidcCallback, error) {
	// 对于Cloudflare Access，我们不在这里处理回调
	// 实际的认证在中间件中通过JWT验证完成
	// 这个方法主要用于兼容OAuth接口
	return factory.OidcCallback{}, fmt.Errorf("Cloudflare Access authentication should be handled by middleware")
}

func (cf *CloudflareAccess) Init() error {
	cf.stateCache = cache.New(time.Minute*5, time.Minute*10)
	return nil
}

func (cf *CloudflareAccess) Destroy() error {
	if cf.stateCache != nil {
		cf.stateCache.Flush()
	}
	return nil
}

// validateCloudflareJWT 验证 Cloudflare Access JWT token
func (cf *CloudflareAccess) ValidateJWT(ctx context.Context, token string) (*CloudflareAccessClaims, error) {
	if cf.Addition.TeamName == "" {
		return nil, fmt.Errorf("team name not configured")
	}
	
	if cf.Addition.Audience == "" {
		return nil, fmt.Errorf("audience not configured")
	}

	// 构建验证器
	teamDomain := fmt.Sprintf("https://%s.cloudflareaccess.com", cf.Addition.TeamName)
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", teamDomain)

	config := &oidc.Config{
		ClientID: cf.Addition.Audience,
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

var _ factory.IOidcProvider = (*CloudflareAccess)(nil)