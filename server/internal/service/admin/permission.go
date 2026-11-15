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
	ListPermissions(ctx context.Context, uid int64) ([]string, error)
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

// ListPermissions 返回 uid 持有的全部权限点，供权限列表下发（§3.9、§5.1）。
func (s *PermissionService) ListPermissions(ctx context.Context, uid int64) ([]string, error) {
	return s.store.ListPermissions(ctx, uid)
}

// PermissionAdminsCache 登录签发侧用到的集合读 / 回填窄接口
// （*cache.PermissionAdminsStore 天然满足）。
type PermissionAdminsCache interface {
	IsMember(ctx context.Context, uid int64) (bool, error)
	Add(ctx context.Context, uid int64) error
}

// IssuingPermissionProbe 登录签发侧「是否持有任意管理权限」判定：集合命中
// 即 true；miss 或 Redis 故障回源 DB（DB 唯一真相、不 fail-closed），回源
// 为 true 时回填补全集合、回填失败仅忽略。与请求期 PermissionLookup 探针
// 分属不同环节，不混用（§5.1、§3.14、§4.8）。
type IssuingPermissionProbe struct {
	admins PermissionAdminsCache
	hasAny func(ctx context.Context, uid int64) (bool, error)
}

// NewIssuingPermissionProbe 依赖缺失须在装配期暴露，故 fail-fast。
func NewIssuingPermissionProbe(admins PermissionAdminsCache, hasAny func(ctx context.Context, uid int64) (bool, error)) *IssuingPermissionProbe {
	if admins == nil || hasAny == nil {
		panic("admin service: NewIssuingPermissionProbe: nil dependency")
	}
	return &IssuingPermissionProbe{admins: admins, hasAny: hasAny}
}

// Probe 供会话签发侧注入；签名与请求期探针同形，但故障语义不同（不 fail-closed）。
func (p *IssuingPermissionProbe) Probe(ctx context.Context, uid int64) (bool, error) {
	hit, err := p.admins.IsMember(ctx, uid)
	if err == nil && hit {
		return true, nil
	}
	// miss（成员不在集合）与 Redis 故障都回源 DB，绝不据缓存缺失判定无权限。
	has, dbErr := p.hasAny(ctx, uid)
	if dbErr != nil {
		return false, dbErr
	}
	if has {
		// 回填补全集合；失败仅忽略，DB 真值已在手，照常签发会话。
		_ = p.admins.Add(ctx, uid)
	}
	return has, nil
}

// 编译期断言：签名漂移在装配前暴露。
var _ PermissionStore = (*repo.PermissionRepo)(nil)
