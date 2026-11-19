// user_credential_webauthn 表读写（后端架构 §3.9 / §4.2 / §8.3 通行密钥）。
// DDL 归 migrations/（§3.16）。user_credential 行与 webauthn 行在同一事务内
// 创建且主键同值；sign_count 单行更新供延迟队列 flusher 落库（§8.3，合并
// 取最大值归队列策略，repo 只写一行）。
package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"authloft/internal/repo/model"
)

// ErrWebauthnDuplicate Create 命中唯一键 uk_kind_credid（§4.2）时的可判别
// 错误：同 credential_id 的凭据已存在；具体冲突键与值在底层
// *mysql.MySQLError 中。
var ErrWebauthnDuplicate = errors.New("webauthn repo: duplicate unique key")

// WebauthnRepo user_credential_webauthn 表数据访问（§3.9：表与文件对应
// webauthn(user_credential_webauthn) → webauthn_repo.go）。
type WebauthnRepo struct {
	db *bun.DB
}

// NewWebauthnRepo 按 bun 连接构造。
func NewWebauthnRepo(db *bun.DB) *WebauthnRepo {
	return &WebauthnRepo{db: db}
}

// ListByUser 按 idx_user_kind 取该用户全部通行密钥行，id 倒序保证列表全序
// 稳定（口径同 user_repo.ListUsers）。空集返回 nil 切片。
func (r *WebauthnRepo) ListByUser(ctx context.Context, userID int64) ([]model.UserCredentialWebauthn, error) {
	var rows []model.UserCredentialWebauthn
	err := r.db.NewSelect().Model(&rows).
		Where("user_id = ? AND kind = ?", userID, "webauthn").
		OrderExpr("id DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("webauthn repo: list by user: %w", err)
	}
	return rows, nil
}

// FindByCredentialID 按唯一键 uk_kind_credid 取凭据行（kind 恒 'webauthn'，
// 等价于 credential_id 全局唯一命中）。未命中返回包装的 sql.ErrNoRows。
func (r *WebauthnRepo) FindByCredentialID(ctx context.Context, credentialID string) (*model.UserCredentialWebauthn, error) {
	var w model.UserCredentialWebauthn
	if err := r.db.NewSelect().Model(&w).
		Where("kind = ? AND credential_id = ?", "webauthn", credentialID).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("webauthn repo: find by credential id: %w", err)
	}
	return &w, nil
}

// Create 同一事务内建两行（主键同值口径）：先插 user_credential 行（自增
// 主键回填 c.ID），再以同一 id 作 user_credential_webauthn 主键插入
// w.ID = c.ID。任一步失败整体回滚，两表均无残留行。credential_id 命中
// uk_kind_credid 返回 ErrWebauthnDuplicate（errors.Is 可判别；1062 判别复用
// 包内既有 isUserDuplicateKey）。user_credential 行的 created_at /
// updated_at 零值时由本方法补齐（bun 无时间列自动填充）。
func (r *WebauthnRepo) Create(ctx context.Context, c *model.UserCredential, w *model.UserCredentialWebauthn) error {
	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		now := time.Now()
		if c.CreatedAt.IsZero() {
			c.CreatedAt = now
		}
		if c.UpdatedAt.IsZero() {
			c.UpdatedAt = now
		}
		if _, err := tx.NewInsert().Model(c).Exec(ctx); err != nil {
			return err
		}
		w.ID = c.ID
		if _, err := tx.NewInsert().Model(w).Exec(ctx); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if isUserDuplicateKey(err) {
			return fmt.Errorf("webauthn repo: create: %w: %w", ErrWebauthnDuplicate, err)
		}
		return fmt.Errorf("webauthn repo: create: %w", err)
	}
	return nil
}

// Delete 同一事务内删两行（Create 的镜像方向）：先删
// user_credential_webauthn 行、再删 user_credential 行，定位条件均为
// id + user_id + kind（kind 恒 'webauthn'）——uid 不匹配（凭据属他人 /
// 不存在 / 非 webauthn 行）不命中任何行，返回包装的 sql.ErrNoRows，两表
// 均无残留（事务回滚）。任一步失败整体回滚，与 Create 的事务结构一致
// （主键同值口径）。
func (r *WebauthnRepo) Delete(ctx context.Context, id, userID int64) error {
	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewDelete().Model((*model.UserCredentialWebauthn)(nil)).
			Where("id = ? AND user_id = ? AND kind = ?", id, userID, "webauthn").
			Exec(ctx)
		if err != nil {
			return err
		}
		if err := requireChangedRow(ctx, tx, res, (*model.UserCredentialWebauthn)(nil),
			"", "id = ? AND user_id = ? AND kind = ?", id, userID, "webauthn"); err != nil {
			return err
		}
		_, err = tx.NewDelete().Model((*model.UserCredential)(nil)).
			Where("id = ? AND user_id = ? AND kind = ?", id, userID, "webauthn").
			Exec(ctx)
		// user_credential 行与 webauthn 行主键同值同事务创建（Create），正常
		// 数据不可能先删成功后删 zero-affected；脏数据残留（credential 行
		// 缺失）不阻断删除，主目标两行口径以 webauthn 行为准。
		return err
	})
	if err != nil {
		return fmt.Errorf("webauthn repo: delete: %w", err)
	}
	return nil
}

// UpdateSignCount 单行更新 sign_count（§8.3：断言校验通过后投递延迟队列，
// 按凭据同键合并取最大值后经 flusher 调用本方法落库）。行不存在返回包装
// 的 sql.ErrNoRows；同值重放（changed-rows 语义下 RowsAffected=0 但行仍在）
// 幂等成功——rows=0 时补 SELECT 存在性判定，口径同 user_repo.UpdateLastLogin。
func (r *WebauthnRepo) UpdateSignCount(ctx context.Context, id int64, signCount int64) error {
	res, err := r.db.NewUpdate().Model((*model.UserCredentialWebauthn)(nil)).
		Where("id = ?", id).
		Set("sign_count = ?", signCount).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("webauthn repo: update sign count: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.UserCredentialWebauthn)(nil),
		"webauthn repo: update sign count", "id = ?", id); err != nil {
		return err
	}
	return nil
}
