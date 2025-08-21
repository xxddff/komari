package cloudflare

import (
	"github.com/komari-monitor/komari/utils/oauth/factory"
	"github.com/patrickmn/go-cache"
)

func init() {
	factory.RegisterOidcProvider(func() factory.IOidcProvider {
		return &CloudflareAccess{}
	})
}

type CloudflareAccess struct {
	Addition
	stateCache *cache.Cache // 用于存储state的映射
}

type Addition struct {
	TeamName string `json:"team_name" required:"true"`
	Audience string `json:"audience" required:"true"`
}

type CloudflareAccessClaims struct {
	Email string `json:"email"`
}