// user_credential_webauthn 表读写（后端架构 §3.9 行 415 / §4.2 行
// 666-675 / §8.3 通行密钥）。DDL 归 migrations/（§3.16）。user_credential
// 行与 webauthn 行在同一事务内创建且主键同值（行 667 口径）；sign_count
// 单行更新供延迟队列 flusher 落库（§8.3 行 1047-1048，合并取最大值归
// 队列策略，repo 只写一行）。
package repo

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"authloft/internal/repo/model"
)

// ErrWebauthnDuplicate Create 命中唯一键 uk_kind_credid（§4.2 行 673）
// 时的可判别错误：同 credential_id 的凭据已存在；具体冲突键与值在底层
// *mysql.MySQLError 中。
var ErrWebauthnDuplicate = errors.New("webauthn repo: duplicate unique key")

// WebauthnRepo user_credential_webauthn 表数据访问（§3.9：表与文件对应
// webauthn(user_credential_webauthn) → webauthn_repo.go）。
type WebauthnRepo struct {
	db *gorm.DB
}

// NewWebauthnRepo 按 GORM 连接构造。
func NewWebauthnRepo(db *gorm.DB) *WebauthnRepo {
	return &WebauthnRepo{db: db}
}

// ListByUser 按 idx_user_kind（行 674）取该用户全部通行密钥行，id 倒序
// 保证列表全序稳定（口径同 user_repo.ListUsers）。空集返回 nil 切片。
func (r *WebauthnRepo) ListByUser(ctx context.Context, userID int64) ([]model.UserCredentialWebauthn, error) {
	var rows []model.UserCredentialWebauthn
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND kind = ?", userID, "webauthn").
		Order("id DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("webauthn repo: list by user: %w", err)
	}
	return rows, nil
}

// FindByCredentialID 按唯一键 uk_kind_credid 取凭据行（kind 恒 'webauthn'，
// 行 669，等价于 credential_id 全局唯一命中）。未命中返回包装的
// gorm.ErrRecordNotFound。
func (r *WebauthnRepo) FindByCredentialID(ctx context.Context, credentialID string) (*model.UserCredentialWebauthn, error) {
	var w model.UserCredentialWebauthn
	if err := r.db.WithContext(ctx).
		Take(&w, "kind = ? AND credential_id = ?", "webauthn", credentialID).Error; err != nil {
		return nil, fmt.Errorf("webauthn repo: find by credential id: %w", err)
	}
	return &w, nil
}

// Create 同一事务内建两行（行 667 主键同值口径）：先插 user_credential
// 行（自增主键回填 c.ID），再以同一 id 作 user_credential_webauthn 主键
// 插入 w.ID = c.ID。任一步失败整体回滚，两表均无残留行。credential_id
// 命中 uk_kind_credid 返回 ErrWebauthnDuplicate（errors.Is 可判别；
// 1062 判别复用包内既有 isUserDuplicateKey）。
func (r *WebauthnRepo) Create(ctx context.Context, c *model.UserCredential, w *model.UserCredentialWebauthn) error {
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(c).Error; err != nil {
			return err
		}
		w.ID = c.ID
		if err := tx.Create(w).Error; err != nil {
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

// UpdateSignCount 单行更新 sign_count（§8.3 行 1047：断言校验通过后投递
// 延迟队列，按凭据同键合并取最大值后经 flusher 调用本方法落库）。行不
// 存在返回包装的 gorm.ErrRecordNotFound；同值重放（changed-rows 语义下
// RowsAffected=0 但行仍在）幂等成功——rows=0 时补 SELECT 存在性判定，
// 口径同 user_repo.UpdateLastLogin。
func (r *WebauthnRepo) UpdateSignCount(ctx context.Context, id int64, signCount int64) error {
	res := r.db.WithContext(ctx).
		Model(&model.UserCredentialWebauthn{}).
		Where("id = ?", id).
		Update("sign_count", signCount)
	if res.Error != nil {
		return fmt.Errorf("webauthn repo: update sign count: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var exists int64
		if err := r.db.WithContext(ctx).
			Model(&model.UserCredentialWebauthn{}).
			Select("COUNT(*)").
			Where("id = ?", id).
			Scan(&exists).Error; err != nil {
			return fmt.Errorf("webauthn repo: update sign count: %w", err)
		}
		if exists == 0 {
			return fmt.Errorf("webauthn repo: update sign count: %w", gorm.ErrRecordNotFound)
		}
	}
	return nil
}
