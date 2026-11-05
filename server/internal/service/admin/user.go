// user.go 实现 AdminService 用户管理族 8 方法（GetMe / ListUsers / GetUser /
// UpdateUserStatus / ResetUserPassword / UnbindUserThirdparty / UnlockUser /
// GetUserEvents，接口文档 §5.1 行 1162、§5.4 行 1249-1255）的业务层
//（docs/后端架构.md §3.9 行 390、§18 行 1792 分层 handler →
// service/admin/user.go → repo / cache）。
//
// 职责边界：会话身份来自 handler（session.UIDFromContext，管理员判定在
// admin 拦截器已收口，本层不做二次鉴权）；参数与状态枚举校验（userStatus
// 仅 0|1、id>0、providerKey 非空）；写路径副作用编排——禁用 / 重置密码
// 走 IncEpoch + al:pwdep 同步（既有会话全部失效，§11.1 行 1236、§5.1 行
// 864「改密 / 重置 / 管理员禁用」三触发项）+ 审计投递；解绑走 Union 行连带
//（§12.7 行 1548）；解锁清 uid 维度键 + 按当前 phone / email 重算「ip +
// 账号哈希」维度键（§8.1 行 1041，ip 未知 → SCAN 模式匹配删除）。
// Connect 错误形态映射归 handler；本层返回可判别哨兵错误（映射口径同
// provider.go 包注释）：
//   - ErrInvalidRequest 参数 / 校验类（映射 invalid_argument + code=invalid_request）；
//   - ErrPasswordWeak 重置密码不满足 §5.6 策略（映射 invalid_argument +
//     code=password_weak，§1.6 封闭集合既有取值）；
//   - gorm.ErrRecordNotFound 资源不存在（映射 not_found）；
//   - 其余错误原样上抛，由错误包装拦截器消毒为 internal。
package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"gorm.io/gorm"

	"authloft/internal/eventlog"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/settings"
)

// ErrPasswordWeak ResetUserPassword 密码不满足 §5.6 策略（handler 映射
// invalid_argument + ErrorInfo domain=admin code=password_weak）。
var ErrPasswordWeak = errors.New("admin service: password does not meet policy")

// providerCategoryUnion provider 表 category=union（§12.7 行 1542：Union
// Provider 是虚拟 Provider 仅用于归并；注册表无该 category 常量——admin
// handler unionProviderKeys 同款字面量）。
const providerCategoryUnion = "union"

// credentialKindPassword user_credential.kind=password（§4.2 行 680-684）。
const credentialKindPassword = "password"

// UserStore user 表读写窄接口（§20 依赖注入）：*repo.UserRepo 天然满足
//（FindByID / ListUsers / IncEpoch 既有 + UpdateUserStatus 列级最小增量），
// 测试可传 fake。
type UserStore interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	ListUsers(ctx context.Context, q repo.UserListQuery) ([]model.User, int64, error)
	UpdateUserStatus(ctx context.Context, id int64, userStatus int8) error
	IncEpoch(ctx context.Context, id int64) (int16, error)
}

// CredentialStore user_credential 表读写窄接口（*repo.CredentialRepo 天然
// 满足，含 ListByUser 最小增量）。
type CredentialStore interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
	ListByUser(ctx context.Context, userID int64) ([]model.UserCredential, error)
	Create(ctx context.Context, c *model.UserCredential) error
	Update(ctx context.Context, c *model.UserCredential) error
}

// BindStore user_thirdparty_bind 表窄接口（*repo.BindRepo 天然满足，
// ListByUserID 既有；UnbindWithUnionCascade 为单事务级联解绑
// 收编项，替代原 Unbind 两跳——连带判定与两行删除同 tx）。
type BindStore interface {
	ListByUserID(ctx context.Context, userID int64) ([]model.UserThirdpartyBind, error)
	UnbindWithUnionCascade(ctx context.Context, id, userID int64, unionProviderKey string) error
}

// ProviderFinder provider 行查询窄接口（Union 归并判定用，§12.7）：
// *repo.ProviderRepo 天然满足。
type ProviderFinder interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
}

// EventReader event_log 表读取窄接口（*repo.EventLogRepo 天然满足，
// ListByUser 为最小增量）。
type EventReader interface {
	ListByUser(ctx context.Context, q repo.EventLogListQuery) ([]model.EventLog, int64, error)
}

// EpochSync epoch 递增后同步 al:pwdep:{uid}（cache.EpochStore.Sync，
// §5.1 行 850、TTL 24h——不同步则校验链最长 24h 读旧值，禁用不生效）。
type EpochSync interface {
	Sync(ctx context.Context, uid int64, epoch int16) error
}

// PwFailUnlocker 管理员解锁所需的密码失败键清除（cache.PwFailStore 天然
// 满足：Reset 清 uid 维度当日计数 + 封禁键；DeleteAccountRef 为
// SCAN 模式清除「ip + 账号哈希」维度键的最小增量）。
type PwFailUnlocker interface {
	Reset(ctx context.Context, userRef string) error
	DeleteAccountRef(ctx context.Context, accountHash string) error
}

// AuditSink 审计事件投递（*eventlog.Writer 满足 PushEvent；非阻塞，队列满
// 由 Writer 静默降级，§5.2 行 893 不影响主链路）。
type AuditSink interface {
	PushEvent(ev model.EventLog)
}

// SettingsReader 密码策略五键现读（§5.6 键为唯一定义处；*settings.Store
// 天然满足，与 orchestrator setpass 同口径每次校验现读保证热更新）。
type SettingsReader interface {
	GetInt64(key string) (int64, bool)
	GetBool(key string) (bool, bool)
}

// UserService admin 域用户管理族业务层。
type UserService struct {
	users     UserStore
	creds     CredentialStore
	binds     BindStore
	providers ProviderFinder
	events    EventReader
	epoch     EpochSync
	pwfail    PwFailUnlocker
	audit     AuditSink
	settings  SettingsReader
	now       func() time.Time
}

// NewUserService 构造；任一依赖为 nil 属程序错误（fail-fast，口径同
// provider.NewService）。
func NewUserService(
	users UserStore, creds CredentialStore, binds BindStore, providers ProviderFinder,
	events EventReader, epoch EpochSync, pwfail PwFailUnlocker, audit AuditSink,
	settings SettingsReader,
) *UserService {
	if users == nil {
		panic("admin service: NewUserService: nil UserStore")
	}
	if creds == nil {
		panic("admin service: NewUserService: nil CredentialStore")
	}
	if binds == nil {
		panic("admin service: NewUserService: nil BindStore")
	}
	if providers == nil {
		panic("admin service: NewUserService: nil ProviderFinder")
	}
	if events == nil {
		panic("admin service: NewUserService: nil EventReader")
	}
	if epoch == nil {
		panic("admin service: NewUserService: nil EpochSync")
	}
	if pwfail == nil {
		panic("admin service: NewUserService: nil PwFailUnlocker")
	}
	if audit == nil {
		panic("admin service: NewUserService: nil AuditSink")
	}
	if settings == nil {
		panic("admin service: NewUserService: nil SettingsReader")
	}
	return &UserService{
		users: users, creds: creds, binds: binds, providers: providers,
		events: events, epoch: epoch, pwfail: pwfail, audit: audit,
		settings: settings, now: time.Now,
	}
}

// GetMe（§5.1 行 1162）：session ctx uid → 用户行投影
// {id, username, nickname, avatarUrl, isAdmin:true}（isAdmin 由 handler 恒
// 置 true——非管理员在拦截器即被拦下）。uid 来自会话载荷（管理员固定
// user.id=1，§5 行 1147），行缺失返回包装的 gorm.ErrRecordNotFound。
func (s *UserService) GetMe(ctx context.Context, uid int64) (*model.User, error) {
	if uid <= 0 {
		return nil, ErrInvalidRequest
	}
	return s.users.FindByID(ctx, uid)
}

// ListUsersFilter ListUsers 入参（§5.4 行 1249：{q, userStatus} + §1.7 分页）。
// UserStatus 非 nil 时仅 0|1 合法（列枚举）；Sort / Order 原样透传 repo
//（§1.7 行 277 后端不做白名单强制校验，字符集防注入归 repo）。
type ListUsersFilter struct {
	Q          string
	UserStatus *int64
	Page       int
	PageSize   int
	Sort       string
	Order      string
}

// ListUsers（§5.4 行 1249）：q 模糊匹配 username / nickname /
// email / phone + userStatus 过滤 + §1.7 分页（q 的列集与 LIKE 规则为
// 默认口径，待定）。返回当页行与总数。
func (s *UserService) ListUsers(ctx context.Context, f ListUsersFilter) ([]model.User, int64, error) {
	q := repo.UserListQuery{Q: f.Q, Sort: f.Sort, Order: f.Order, Page: f.Page, PageSize: f.PageSize}
	if f.UserStatus != nil {
		if *f.UserStatus != 0 && *f.UserStatus != 1 {
			return nil, 0, ErrInvalidRequest
		}
		v := int8(*f.UserStatus)
		q.UserStatus = &v
	}
	return s.users.ListUsers(ctx, q)
}

// UserDetail GetUser 的聚合结果（§5.4 行 1250 详情：user 行 + 凭证概览 +
// 三方绑定列表）；MFA 状态的输入（mfa_setting 行存在性 + user.mfa_required
// 列）由 Credentials 列表（含 kind=mfa_setting 行）与 user 行投影承载。
type UserDetail struct {
	User        *model.User
	Credentials []model.UserCredential
	Bindings    []model.UserThirdpartyBind
}

// GetUser（§5.4 行 1250）：{id} 详情——user 行（含 mfa_required
// 列）+ 凭证概览（全部 kind 行，kind/is_enabled 投影在 dto，secret 不透出，
// 含 mfa_setting 行即「行存在性」）+ 三方绑定列表（bind_repo.ListByUserID）。
func (s *UserService) GetUser(ctx context.Context, id int64) (*UserDetail, error) {
	if id <= 0 {
		return nil, ErrInvalidRequest
	}
	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	creds, err := s.creds.ListByUser(ctx, id)
	if err != nil {
		return nil, err
	}
	binds, err := s.binds.ListByUserID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &UserDetail{User: user, Credentials: creds, Bindings: binds}, nil
}

// UpdateUserStatus（§5.4 行 1251）：{id, userStatus 0|1} 禁用 /
// 启用。列级 UPDATE 收编 repo（UpdateUserStatus）；禁用 → IncEpoch（既有
// 会话与已颁发令牌全部失效，§11.1）+ al:pwdep 同步（§5.1 行 864 触发项）
// + 审计 admin_disable_user（actor=admin，detail 落 NULL——§4.6 行 808 表
// 未定义该事件 detail，默认）；启用不审计（eventlog 无既有常量，不
// 自造事件名，默认）。幂等重放（再次禁用已禁用用户）同样走失效链
// 与审计——每次管理员动作都留痕。
func (s *UserService) UpdateUserStatus(ctx context.Context, actor, id int64, userStatus int64) error {
	if id <= 0 || (userStatus != 0 && userStatus != 1) {
		return ErrInvalidRequest
	}
	if err := s.users.UpdateUserStatus(ctx, id, int8(userStatus)); err != nil {
		return err // 含 gorm.ErrRecordNotFound → 404
	}
	if userStatus != 0 {
		return nil
	}
	if _, err := s.invalidateSessions(ctx, id); err != nil {
		return err
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventAdminDisableUser,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    id,
		CreatedAt: s.now(),
	})
	return nil
}

// ResetUserPassword（§5.4 行 1252）：{id, password} 管理员重置。
// 密码按 §5.6 策略校验（settings 五键现读，与 setpass 同口径）→ password
// credential 更新（无行同构补建，沿用 internal/service/orchestrator/setpass.go
// reset 口径）→ IncEpoch + al:pwdep 同步（先失效旧会话——改密后旧令牌全部
// 失效，§11.1）→ 审计 admin_reset_password（detail={pwd_epoch}，§4.6 行 813
// reset_password 同构）。管理员重置不建新会话（与用户自助 reset 直接登录
// 不同，§5.4 无此语义）。
func (s *UserService) ResetUserPassword(ctx context.Context, actor, id int64, password string) error {
	if id <= 0 || password == "" {
		return ErrInvalidRequest
	}
	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return err
	}
	email := ""
	if user.Email != nil {
		email = *user.Email
	}
	if vs := security.ValidatePassword(s.policy(), user.Username, email, password); len(vs) > 0 {
		return ErrPasswordWeak
	}
	if err := s.writePasswordCredential(ctx, id, password); err != nil {
		return err
	}
	epoch, err := s.invalidateSessions(ctx, id)
	if err != nil {
		return err
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventAdminResetPassword,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    id,
		Detail:    eventlog.DetailPwdEpoch(int64(epoch)),
		CreatedAt: s.now(),
	})
	return nil
}

// UnbindUserThirdparty（§5.4 行 1253）：{id, providerKey} 解绑
// 第三方。Union Provider 行不可单独解绑（§12.7 行 1547，invalid_request）；
// 删普通行 + §12.7 行 1548 连带（该用户已无任何非 Union 绑定行 → 连带
// 删「对应 Union 行」，否则保留，供其他关联 Provider 继续归并）收编为
// repo 单事务 UnbindWithUnionCascade（既定口径 §3.10 行 428：
// 原两跳非同事务，第二跳失败普通行已删、重试 404 无法自愈，孤行 Union
// 行永久占用 uk_provider_openid）→ 审计 thirdparty_unbind（detail=
// {provider_key, open_id}，§4.6 行 816）。
func (s *UserService) UnbindUserThirdparty(ctx context.Context, actor, id int64, providerKey string) error {
	if id <= 0 || providerKey == "" {
		return ErrInvalidRequest
	}
	p, err := s.providers.FindByKey(ctx, providerKey)
	if err != nil {
		return err // provider 行不存在 → 404（绑定行引用 provider_key，无从解绑）
	}
	if p.Category == providerCategoryUnion {
		return ErrInvalidRequest // Union 行不可单独解绑（§12.7 行 1547）
	}
	rows, err := s.binds.ListByUserID(ctx, id)
	if err != nil {
		return err
	}
	var target *model.UserThirdpartyBind
	for i := range rows {
		if rows[i].ProviderKey == providerKey {
			target = &rows[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("admin service: unbind: user %d has no binding for %q: %w", id, providerKey, gorm.ErrRecordNotFound)
	}
	if err := s.binds.UnbindWithUnionCascade(ctx, target.ID, id, p.UnionProvider); err != nil {
		return err
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventThirdpartyUnbind,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    id,
		Target:    providerKey,
		Detail:    eventlog.DetailThirdpartyBind(providerKey, target.OpenID),
		CreatedAt: s.now(),
	})
	return nil
}

// UnlockUser（§5.4 行 1254）：{id} 解除登录限制（§8.1 行 1041）：
// 清 uid 维度键（al:pwf:{uid}:{yyyymmdd} + al:pwban:{uid}，PwFailStore.Reset）
// + 按该用户当前 phone / email 重算「ip + 账号哈希」维度键一并清除（该维度
// user_ref = ip + "|" + hex(sha256(identifier))，factor/password userRef 同款
// 格式；ip 未知 → SCAN 模式匹配删除，PwFailStore.DeleteAccountRef）。无
// 解锁审计常量，不投事件（默认，同启用不审计口径）。
func (s *UserService) UnlockUser(ctx context.Context, id int64) error {
	if id <= 0 {
		return ErrInvalidRequest
	}
	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.pwfail.Reset(ctx, strconv.FormatInt(id, 10)); err != nil {
		return fmt.Errorf("admin service: unlock user %d: %w", id, err)
	}
	for _, ident := range []string{derefString(user.Phone), derefString(user.Email)} {
		if ident == "" {
			continue
		}
		sum := sha256.Sum256([]byte(ident))
		if err := s.pwfail.DeleteAccountRef(ctx, hex.EncodeToString(sum[:])); err != nil {
			return fmt.Errorf("admin service: unlock user %d: %w", id, err)
		}
	}
	return nil
}

// GetUserEvents（§5.4 行 1255）：{id} + 分页的该用户登录记录
//——event=login_success 过滤（「登录记录」视图，§5.4 行 1252；事件类型
// 不在查询参数中重复，user.proto GetUserEventsRequest 注释）。用户 id 的
// 存在性不校验（纯事件视图，无行返回空页，与 §5.6 ListEvents 的 userId
// 过滤同语义，默认口径）。
func (s *UserService) GetUserEvents(ctx context.Context, id int64, page, pageSize int) ([]model.EventLog, int64, error) {
	return s.events.ListByUser(ctx, repo.EventLogListQuery{
		UserID:   id,
		Event:    eventlog.EventLoginSuccess,
		Page:     page,
		PageSize: pageSize,
	})
}

// invalidateSessions 禁用 / 重置密码的会话失效链（§11.1 行 1236、§5.1 行
// 864）：IncEpoch 递增 user.epoch（回绕语义见 repo）→ EpochStore.Sync 同步
// al:pwdep:{uid}（TTL 24h）——不同步则校验链最长 24h 读旧值，失效不生效
//（setpass.go reset 同款链，返回递增后的新值供审计 detail）。
func (s *UserService) invalidateSessions(ctx context.Context, id int64) (int16, error) {
	epoch, err := s.users.IncEpoch(ctx, id)
	if err != nil {
		return 0, err
	}
	if err := s.epoch.Sync(ctx, id, epoch); err != nil {
		return 0, err
	}
	return epoch, nil
}

// writePasswordCredential password credential 更新：有行 Update（secret /
// is_enabled=1 / updated_at），无行同构补建 Create（沿用 setpass.go writeCredential
// reset 口径——无 password 行（如三方免密建号后走重置）按「设置密码」建行）。
// hash 复用 security.HashPassword（argon2id PHC 串，§8.1），不自造。
func (s *UserService) writePasswordCredential(ctx context.Context, id int64, password string) error {
	hash, err := security.HashPassword(password)
	if err != nil {
		return fmt.Errorf("admin service: hash password: %w", err)
	}
	cred, err := s.creds.FindByUserAndKind(ctx, id, credentialKindPassword)
	switch {
	case err == nil:
		cred.Secret = []byte(hash)
		cred.IsEnabled = 1
		cred.UpdatedAt = s.now()
		return s.creds.Update(ctx, cred)
	case errors.Is(err, gorm.ErrRecordNotFound):
		return s.creds.Create(ctx, &model.UserCredential{
			UserID:    id,
			Kind:      credentialKindPassword,
			Secret:    []byte(hash),
			IsEnabled: 1,
			UpdatedAt: s.now(),
		})
	default:
		return err
	}
}

// policy 从 settings 现读 pwd_* 五键构造策略（§5.6 键为唯一定义处；越界 /
// 缺失回落 security 默认档——与 setpass.go policy 同口径同实现，跨包私有
// 无法复用，按 §3.5 各落一份）。
func (s *UserService) policy() security.PasswordPolicy {
	p := security.DefaultPasswordPolicy()
	if v, ok := s.settings.GetInt64(settings.KeyPwdMinLength); ok && v > 0 {
		p.MinLength = int(v)
	}
	if v, ok := s.settings.GetInt64(settings.KeyPwdMaxLength); ok && v > 0 {
		p.MaxLength = int(v)
	}
	if v, ok := s.settings.GetInt64(settings.KeyPwdRequireClasses); ok && v >= 1 && v <= 3 {
		p.RequireClasses = int(v)
	}
	if v, ok := s.settings.GetBool(settings.KeyPwdDisallowUsername); ok {
		p.DisallowUsername = v
	}
	if v, ok := s.settings.GetBool(settings.KeyPwdDisallowCommon); ok {
		p.DisallowCommon = v
	}
	return p
}

// derefString 可空列读值（nil / 空串归一空串）。
func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// compile 时断言 *repo.UserRepo / *repo.CredentialRepo / *repo.BindRepo /
// *repo.ProviderRepo / *repo.EventLogRepo 满足各窄接口（签名漂移在编译
// 期暴露）。
var (
	_ UserStore       = (*repo.UserRepo)(nil)
	_ CredentialStore = (*repo.CredentialRepo)(nil)
	_ BindStore       = (*repo.BindRepo)(nil)
	_ ProviderFinder  = (*repo.ProviderRepo)(nil)
	_ EventReader     = (*repo.EventLogRepo)(nil)
)
