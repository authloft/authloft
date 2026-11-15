// 权限点判定集中在本包，供 admin 拦截器探针注入（§3.14、§4.8）：判定只此
// 一处，避免各判定点复制口径。uid 由 handler 从会话传入，本包不读 ctx。
package admin

import (
	"context"

	"authloft/internal/repo"
)

// PointSuperAdmin 唯一权限点，安装时授予（§4.8、§3.15）。
const PointSuperAdmin = "superadmin"

// PermissionStore 窄接口便于注入 fake；*repo.PermissionRepo 天然满足（§20）。
type PermissionStore interface {
	HasPermission(ctx context.Context, uid int64, point string) (bool, error)
	HasAnyPermission(ctx context.Context, uid int64) (bool, error)
}

// PermissionService 权限点判定业务层（§3.7）。
type PermissionService struct {
	store PermissionStore
}

// NewPermissionService 依赖缺失须在装配期暴露，故 fail-fast。
func NewPermissionService(store PermissionStore) *PermissionService {
	if store == nil {
		panic("admin service: NewPermissionService: nil PermissionStore")
	}
	return &PermissionService{store: store}
}

// HasPermission 查询错误原样上抛，供上层 fail-closed 判定。
func (s *PermissionService) HasPermission(ctx context.Context, uid int64, point string) (bool, error) {
	return s.store.HasPermission(ctx, uid, point)
}

// HasAnyPermission 即「有任意管理权限」的探针（§3.14、§4.8）。
func (s *PermissionService) HasAnyPermission(ctx context.Context, uid int64) (bool, error) {
	return s.store.HasAnyPermission(ctx, uid)
}

// 编译期断言：签名漂移在装配前暴露。
var _ PermissionStore = (*repo.PermissionRepo)(nil)
