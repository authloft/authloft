// oidc_refresh_token 表读写（后端架构 §3.10：oidc_token →
// oidc_token_repo.go；§4.5 DDL）。DDL 归 migrations/（§3.16），本文件只做
// 行级读写；事务边界在 service（§3.10）。token 生成、sha256 计算、过期
// 时刻计算、未吊销未过期校验均归上层（§14.3）——repo 拿到 token_hash /
// expires_at 存什么用什么、查到什么返回什么。吊销一律用条件 UPDATE
// （WHERE ... AND revoked_at IS NULL）原子完成，避免 check-then-act；单令牌
// 吊销返回是否真正发生状态跃迁，service 据此按 RFC 7009 决定响应（接口
// 文档 §4.4：未知 / 已吊销令牌同样 200）。
package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"authloft/internal/repo/model"
)

// OidcTokenRepo oidc_refresh_token 表数据访问（§3.10：表与文件对应
// oidc_token(oidc_refresh_token) → oidc_token_repo.go）。
type OidcTokenRepo struct {
	db *bun.DB
}

// NewOidcTokenRepo 按 bun 连接构造。
func NewOidcTokenRepo(db *bun.DB) *OidcTokenRepo {
	return &OidcTokenRepo{db: db}
}

// Create 插入刷新令牌行（token_hash 由 service 算好传入，repo 不生成 /
// 不哈希）。命中 uk_token_hash 返回包装错误，由 service 判别（正常流程
// sha256 碰撞不可达）。created_at 零值时由本方法补齐（bun 无时间
// 列自动填充）。
func (r *OidcTokenRepo) Create(ctx context.Context, t *model.OidcRefreshToken) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	if _, err := r.db.NewInsert().Model(t).Exec(ctx); err != nil {
		return fmt.Errorf("oidc token repo: create: %w", err)
	}
	return nil
}

// FindByTokenHash 按唯一键 uk_token_hash 取刷新令牌行；未命中返回包装的
// sql.ErrNoRows。是否已吊销 / 已过期由 service 校验（§14.3），repo 原样
// 返回行，不附加过滤条件。
func (r *OidcTokenRepo) FindByTokenHash(ctx context.Context, tokenHash string) (*model.OidcRefreshToken, error) {
	var t model.OidcRefreshToken
	if err := r.db.NewSelect().Model(&t).
		Where("token_hash = ?", tokenHash).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("oidc token repo: find by token hash: %w", err)
	}
	return &t, nil
}

// RevokeByTokenHash 按 token_hash 原子吊销单个令牌：仅当行存在且尚未
// 吊销（revoked_at IS NULL）时写入 revoked_at，返回是否真正发生状态
// 跃迁（rows affected）。未命中 / 已吊销均返回 false, nil——RFC 7009
// 要求未知与已吊销令牌同样成功响应（接口文档 §4.4）。行数直查两库
// 一致：WHERE 限定未吊销，命中行 revoked_at 必由 NULL 变非空
// （matched-rows = changed-rows，无同值重放分歧）；返回的是跃迁判定
// 而非行存在性，不走 requireChangedRow。
func (r *OidcTokenRepo) RevokeByTokenHash(ctx context.Context, tokenHash string, revokedAt time.Time) (bool, error) {
	res, err := r.db.NewUpdate().Model((*model.OidcRefreshToken)(nil)).
		Where("token_hash = ? AND revoked_at IS NULL", tokenHash).
		Set("revoked_at = ?", revokedAt).
		Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("oidc token repo: revoke by token hash: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("oidc token repo: revoke by token hash: %w", err)
	}
	return rows > 0, nil
}

// RevokeByUserID 批量吊销该用户全部未吊销令牌（§14.3：改密时批量标记该
// 用户 refresh token 为 revoked），返回本次吊销行数；无未吊销行时返回
// 0, nil（幂等）。行数直查两库一致：WHERE 限定未吊销，命中必变值
// （matched-rows = changed-rows），返回计数而非行存在性。
func (r *OidcTokenRepo) RevokeByUserID(ctx context.Context, userID int64, revokedAt time.Time) (int64, error) {
	res, err := r.db.NewUpdate().Model((*model.OidcRefreshToken)(nil)).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Set("revoked_at = ?", revokedAt).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("oidc token repo: revoke by user id: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("oidc token repo: revoke by user id: %w", err)
	}
	return rows, nil
}

// RevokeBySessionID 批量吊销该会话全部未吊销令牌（需求 §4.5：刷新令牌与
// 会话绑定），返回本次吊销行数；无未吊销行时返回 0, nil。行数直查两库
// 一致（口径同 RevokeByUserID：命中必变值，返回计数而非行存在性）。
func (r *OidcTokenRepo) RevokeBySessionID(ctx context.Context, sessionID string, revokedAt time.Time) (int64, error) {
	res, err := r.db.NewUpdate().Model((*model.OidcRefreshToken)(nil)).
		Where("session_id = ? AND revoked_at IS NULL", sessionID).
		Set("revoked_at = ?", revokedAt).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("oidc token repo: revoke by session id: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("oidc token repo: revoke by session id: %w", err)
	}
	return rows, nil
}

// ListByClientAndUser 取该客户端下该用户的全部刷新令牌行（含已吊销 /
// 已过期行，过滤口径归 service）。文档未定义列表顺序，repo 固定
// ORDER BY id DESC（最新在前）保证全序稳定。
func (r *OidcTokenRepo) ListByClientAndUser(ctx context.Context, clientID string, userID int64) ([]model.OidcRefreshToken, error) {
	var rows []model.OidcRefreshToken
	err := r.db.NewSelect().Model(&rows).
		Where("client_id = ? AND user_id = ?", clientID, userID).
		OrderExpr("id DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("oidc token repo: list by client and user: %w", err)
	}
	return rows, nil
}

// DeleteExpired 删除已过期令牌行（§3.12：cron 过期 refresh token 清理），
// 返回删除行数（DELETE 两库均返回实际删除行数，行数直查无 changed/matched
// 分歧）。过期判据 now >= expires_at（有效期区间为
// [created_at, expires_at)）；已吊销但未过期的行保留，由过期清理统一回收。
func (r *OidcTokenRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.NewDelete().Model((*model.OidcRefreshToken)(nil)).
		Where("expires_at <= ?", now).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("oidc token repo: delete expired: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("oidc token repo: delete expired: %w", err)
	}
	return rows, nil
}
