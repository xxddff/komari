package api

import (
	"encoding/json"
	"fmt"

	"github.com/komari-monitor/komari/database"
	"github.com/komari-monitor/komari/utils/oauth/cloudflare"
	"github.com/komari-monitor/komari/utils/oauth/factory"
)

// getCloudflareProvider 获取 Cloudflare Access 提供商实例
func getCloudflareProvider() (*cloudflare.CloudflareAccess, error) {
	constructor, exists := factory.GetConstructor("cloudflare")
	if !exists {
		return nil, fmt.Errorf("cloudflare provider not found")
	}
	
	provider := constructor().(*cloudflare.CloudflareAccess)
	return provider, nil
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