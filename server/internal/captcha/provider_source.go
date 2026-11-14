// provider_source.go provider 表行 → captcha 窄投影（docs/后端架构.md §3.11）：
// 组合模式实现 ProviderSource，经 repo.ParseProviderExt 取数；除本文件的
// repo 窄投影外，captcha 包不再持有任何 DB 句柄，也不直连 SQL。
package captcha

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"authloft/internal/repo"
)

// providerSource 把 provider 表行转成 captcha 包窄投影（ProviderSource，
// §3.11 行 446：除本文件的 repo 窄投影外，captcha 包不持有 DB 句柄、不直连
// SQL；组合模式，不修改 repo 公共接口）。ext 编解码
// 唯一出口 repo.ParseProviderExt（§12.1：site_key=client_id、
// secret=client_secret、endpoint=自定义校验地址）；未命中唯一键按
// 「无此行」返回 nil,nil，其余错误原样上抛。
type providerSource struct {
	providers *repo.ProviderRepo
}

func (s providerSource) Find(ctx context.Context, providerKey string) (*ProviderRecord, error) {
	if providerKey == "" {
		return nil, nil
	}
	row, err := s.providers.FindByKey(ctx, providerKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		return nil, err
	}
	return &ProviderRecord{
		ProviderKey: row.ProviderKey,
		Category:    row.Category,
		Type:        row.Type,
		Enabled:     row.IsEnabled != 0,
		SiteKey:     ext.GetClientId(),
		Secret:      ext.GetClientSecret(),
		VerifyURL:   ext.GetEndpoint(),
	}, nil
}

// NewProviderSource 注入 provider 仓储（装配层构造）。
func NewProviderSource(providers *repo.ProviderRepo) ProviderSource {
	return providerSource{providers: providers}
}
