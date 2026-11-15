// 权限点判定不加缓存：查询故障须原样上抛，让 admin 拦截器 fail-closed，
// 绝不降级为「无权限」（§3.14）。DDL 由迁移管理（§3.16）。
package repo

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// PermissionRepo 权限点表数据访问（§3.10）。
type PermissionRepo struct {
	db *gorm.DB
}

// NewPermissionRepo 连接由装配层注入，不自行建连。
func NewPermissionRepo(db *gorm.DB) *PermissionRepo {
	return &PermissionRepo{db: db}
}

// HasPermission 查询错误须原样上抛，避免被读成「无权限」（§3.14、§4.8）。
func (r *PermissionRepo) HasPermission(ctx context.Context, uid int64, point string) (bool, error) {
	var exists int64
	err := r.db.WithContext(ctx).Raw(
		"SELECT EXISTS(SELECT 1 FROM user_permission WHERE user_id = ? AND point = ? LIMIT 1)",
		uid, point,
	).Scan(&exists).Error
	if err != nil {
		return false, fmt.Errorf("permission repo: has permission: %w", err)
	}
	return exists == 1, nil
}

// HasAnyPermission 同 HasPermission：故障上抛供 fail-closed（§3.14）。
func (r *PermissionRepo) HasAnyPermission(ctx context.Context, uid int64) (bool, error) {
	var exists int64
	err := r.db.WithContext(ctx).Raw(
		"SELECT EXISTS(SELECT 1 FROM user_permission WHERE user_id = ? LIMIT 1)",
		uid,
	).Scan(&exists).Error
	if err != nil {
		return false, fmt.Errorf("permission repo: has any permission: %w", err)
	}
	return exists == 1, nil
}
