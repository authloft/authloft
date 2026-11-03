// oidc_refresh_token 表读写（后端架构 §3.10 行 415：oidc_token →
// oidc_token_repo.go；§4.5 行 744-758 DDL）。DDL 归 migrations/（§3.16），
// 本文件只做行级读写；事务边界在 service（§3.10）。token 生成、sha256
// 计算、过期时刻计算、未吊销未过期校验均归上层（§14.3 行 1586-1587）——
// repo 拿到 token_hash / expires_at 存什么用什么、查到什么返回什么。吊销
// 一律用条件 UPDATE（WHERE ... AND revoked_at IS NULL）原子完成，避免
// check-then-act；单令牌吊销返回是否真正发生状态跃迁，service 据此按
// RFC 7009 决定响应（接口文档 §4.4 行 1101：未知 / 已吊销令牌同样 200）。
package repo

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"authloft/internal/repo/model"
)

// OidcTokenRepo oidc_refresh_token 表数据访问（§3.10：表与文件对应
// oidc_token(oidc_refresh_token) → oidc_token_repo.go）。
type OidcTokenRepo struct {
	db *gorm.DB
}

// NewOidcTokenRepo 按 GORM 连接构造。
func NewOidcTokenRepo(db *gorm.DB) *OidcTokenRepo {
	return &OidcTokenRepo{db: db}
}

// Create 插入刷新令牌行（token_hash 由 service 算好传入，repo 不生成 /
// 不哈希）。命中 uk_token_hash 返回包装错误，由 service 判别（正常流程
// sha256 碰撞不可达）。
func (r *OidcTokenRepo) Create(ctx context.Context, t *model.OidcRefreshToken) error {
	if err := r.db.WithContext(ctx).Create(t).Error; err != nil {
		return fmt.Errorf("oidc token repo: create: %w", err)
	}
	return nil
}

// FindByTokenHash 按唯一键 uk_token_hash 取刷新令牌行；未命中返回包装的
// gorm.ErrRecordNotFound。是否已吊销 / 已过期由 service 校验（§14.3 行
// 1586），repo 原样返回行，不附加过滤条件。
func (r *OidcTokenRepo) FindByTokenHash(ctx context.Context, tokenHash string) (*model.OidcRefreshToken, error) {
	var t model.OidcRefreshToken
	if err := r.db.WithContext(ctx).Take(&t, "token_hash = ?", tokenHash).Error; err != nil {
		return nil, fmt.Errorf("oidc token repo: find by token hash: %w", err)
	}
	return &t, nil
}

// RevokeByTokenHash 按 token_hash 原子吊销单个令牌：仅当行存在且尚未
// 吊销（revoked_at IS NULL）时写入 revoked_at，返回是否真正发生状态
// 跃迁（rows affected）。未命中 / 已吊销均返回 false, nil——RFC 7009
// 要求未知与已吊销令牌同样成功响应（接口文档 §4.4 行 1101）。
func (r *OidcTokenRepo) RevokeByTokenHash(ctx context.Context, tokenHash string, revokedAt time.Time) (bool, error) {
	res := r.db.WithContext(ctx).
		Model(&model.OidcRefreshToken{}).
		Where("token_hash = ? AND revoked_at IS NULL", tokenHash).
		Update("revoked_at", revokedAt)
	if res.Error != nil {
		return false, fmt.Errorf("oidc token repo: revoke by token hash: %w", res.Error)
	}
	return res.RowsAffected > 0, nil
}

// RevokeByUserID 批量吊销该用户全部未吊销令牌（§14.3 行 1588：改密时
// 批量标记该用户 refresh token 为 revoked），返回本次吊销行数；无未吊销
// 行时返回 0, nil（幂等）。
func (r *OidcTokenRepo) RevokeByUserID(ctx context.Context, userID int64, revokedAt time.Time) (int64, error) {
	res := r.db.WithContext(ctx).
		Model(&model.OidcRefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", revokedAt)
	if res.Error != nil {
		return 0, fmt.Errorf("oidc token repo: revoke by user id: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// RevokeBySessionID 批量吊销该会话全部未吊销令牌（需求 §4.5 行 244：
// 刷新令牌与会话绑定），返回本次吊销行数；无未吊销行时返回 0, nil。
func (r *OidcTokenRepo) RevokeBySessionID(ctx context.Context, sessionID string, revokedAt time.Time) (int64, error) {
	res := r.db.WithContext(ctx).
		Model(&model.OidcRefreshToken{}).
		Where("session_id = ? AND revoked_at IS NULL", sessionID).
		Update("revoked_at", revokedAt)
	if res.Error != nil {
		return 0, fmt.Errorf("oidc token repo: revoke by session id: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// ListByClientAndUser 取该客户端下该用户的全部刷新令牌行（含已吊销 /
// 已过期行，过滤口径归 service）。文档未定义列表顺序，repo 固定
// ORDER BY id DESC（最新在前）保证全序稳定。
func (r *OidcTokenRepo) ListByClientAndUser(ctx context.Context, clientID string, userID int64) ([]model.OidcRefreshToken, error) {
	var rows []model.OidcRefreshToken
	err := r.db.WithContext(ctx).
		Where("client_id = ? AND user_id = ?", clientID, userID).
		Order("id DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("oidc token repo: list by client and user: %w", err)
	}
	return rows, nil
}

// DeleteExpired 删除已过期令牌行（§3.10 行 455：cron 过期 refresh token
// 清理），返回删除行数。过期判据 now >= expires_at（有效期区间为
// [created_at, expires_at)）；已吊销但未过期的行保留，由过期清理统一回收。
func (r *OidcTokenRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("expires_at <= ?", now).
		Delete(&model.OidcRefreshToken{})
	if res.Error != nil {
		return 0, fmt.Errorf("oidc token repo: delete expired: %w", res.Error)
	}
	return res.RowsAffected, nil
}
