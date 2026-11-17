// oidc_consent 表读写（后端架构 §3.10：表与文件对应 oidc_consent →
// oidc_consent_repo.go；§4.5 DDL 与读写口径）。DDL 归 migrations/（§3.16），
// 本文件只做行级读写。scopes 的解析、子集判定与并集计算归上层（§4.5：两套
// 分隔口径的解析统一收进授权参数校验工具，不散落调用点）——repo 拿到什么
// 存什么、查到什么返回什么。
package repo

import (
	"context"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"authloft/internal/repo/model"
)

// OidcConsentRepo oidc_consent 表数据访问，只暴露授权口径的两个窄操作
// （§4.5）：读已授权并集、按 uk_user_client 冲突更新写回。
type OidcConsentRepo struct {
	db *gorm.DB
}

// NewOidcConsentRepo 按 GORM 连接构造。
func NewOidcConsentRepo(db *gorm.DB) *OidcConsentRepo {
	return &OidcConsentRepo{db: db}
}

// GetConsentScopes 取该用户对该客户端的已授权 scope 并集原文（空格分隔，
// §4.5）。无授权记录（从未同意，属正常稳态）返回包装的 gorm.ErrRecordNotFound，
// 由上层按空集口径参与免同意判定（§4.5：请求 scope ⊆ 已授权 scopes）。
func (r *OidcConsentRepo) GetConsentScopes(ctx context.Context, userID int64, clientID string) (string, error) {
	var row model.OidcConsent
	if err := r.db.WithContext(ctx).
		Take(&row, "user_id = ? AND client_id = ?", userID, clientID).Error; err != nil {
		return "", fmt.Errorf("oidc consent repo: get consent scopes: %w", err)
	}
	return row.Scopes, nil
}

// UpsertConsent 按 uk_user_client 冲突更新写授权记录：scopes 为上层算好的
// 最终并集（旧 scopes ∪ 本次勾选集，只扩不缩 §4.5），repo 原样写回——命中
// 唯一键更新 scopes 与 updated_at（created_at 保持首次授权时刻），未命中
// 整行插入（MySQL 方言生成 INSERT ... ON DUPLICATE KEY UPDATE）。
func (r *OidcConsentRepo) UpsertConsent(ctx context.Context, userID int64, clientID, scopes string) error {
	row := model.OidcConsent{UserID: userID, ClientID: clientID, Scopes: scopes}
	err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "client_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"scopes", "updated_at"}),
	}).Create(&row).Error
	if err != nil {
		return fmt.Errorf("oidc consent repo: upsert consent: %w", err)
	}
	return nil
}
