// user.go 实现 AdminService 用户管理族 16 方法（GetMe / ListUsers / GetUser /
// UpdateUserProfile / UpdateUserContact / SetUserMfa / UnbindUserTOTP /
// ResetUserRecoveryCodes / SetCredentialEnabled / DeleteCredential /
// UpdateUserStatus / ResetUserPassword / UnbindUserThirdparty / UnlockUser /
// DeleteUser / GetUserEvents，接口文档 §5.1 / §5.4）的业务层（docs/后端架构.md
// §3.9、§18 分层 handler → service/admin/user.go → repo / cache）。
//
// 职责边界：会话身份来自 handler（session.UIDFromContext，管理员判定在
// admin 拦截器已收口，本层不做二次鉴权）；参数与状态枚举校验（userStatus
// 仅 0|1、mfaRequired 仅 0|1、id / credentialId > 0、providerKey 非空）；
// 写路径副作用编排——禁用 / 重置密码走 IncEpoch + al:pwdep 同步（既有会话
// 全部失效，§11.1）+ 审计投递；救援族按 §5.4 强制下线集合接线——关闭两步
// 验证 / 解绑 TOTP / 删除凭证触发失效链，开启两步验证 / 凭证启停 / 恢复码
// 重置不触发；解绑走 Union 行连带（§12.7）；解锁清 uid 维度键 + 按当前
// phone / email 重算「ip + 账号哈希」维度键（§8.1，ip 未知 → SCAN 模式
// 匹配删除）；删除用户为单事务匿名化改写（§4.2：禁用 + 全端下线 + 匿名化，
// deleted_ 前缀为唯一标记，不新增字段）。
// 针对目标用户的写接口（含旧四写接口禁用启用 / 重置密码 / 解锁 / 解绑）
// 统一走 authorizeUserWrite 目标账户分级门禁（§5.4 门禁矩阵、《后端架构》
// §4.8：superadmin 目标一律拒绝；普通管理员目标仅 superadmin 操作者可写；
// 权限查询故障原样上抛不放行）；删除用户另加 §4.8 两条硬边界（有任意权限点
// 禁删、自删拒绝）。
// Connect 错误形态映射归 handler；本层返回可判别哨兵错误（映射口径同
// provider.go 包注释）：
//   - ErrInvalidRequest 参数 / 校验类（映射 invalid_argument + code=invalid_request）；
//   - ErrPasswordWeak 重置密码不满足 §5.6 策略（映射 invalid_argument +
//     code=password_weak，§1.6 封闭集合既有取值）；
//   - ErrPermissionDenied 权限门禁拒绝（映射 Connect 标准码 permission_denied，
//     不挂 ErrorInfo 细分码，§1.6 封闭集合不新增取值）；
//   - ErrTargetTaken 联系方式被他人占用（映射 already_exists +
//     code=target_taken，§1.6 封闭集合既有取值）；
//   - sql.ErrNoRows 资源不存在（映射 not_found）；
//   - 其余错误原样上抛，由错误包装拦截器消毒为 internal。
package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"database/sql"

	adminv1 "authloft/gen/go/api/admin/v1"
	credentialpb "authloft/gen/go/credential"
	"authloft/internal/dto"
	"authloft/internal/eventlog"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/settings"
)

// ErrPasswordWeak ResetUserPassword 密码不满足 §5.6 策略（handler 映射
// invalid_argument + ErrorInfo domain=admin code=password_weak）。
var ErrPasswordWeak = errors.New("admin service: password does not meet policy")

// ErrPermissionDenied 权限门禁拒绝：superadmin 目标的一切写操作、普通管理员
// 目标遇非 superadmin 操作者、联系方式遇非 superadmin 操作者。handler 映射
// Connect 标准码 permission_denied（HTTP 403），不挂 ErrorInfo 细分码
// （§1.6 封闭集合不新增取值，前端按标准码兜底）。
var ErrPermissionDenied = errors.New("admin service: permission denied")

// ErrTargetTaken UpdateUserContact 的非空 phone / email 已被他人占用
// （§5.4：唯一性冲突 → already_exists + ErrorInfo code=target_taken，字段级
// 提示；唯一冲突不投审计）。
var ErrTargetTaken = errors.New("admin service: contact target taken")

// ErrUsernameTaken CreateUser 的 username 唯一性冲突（§5.4：username 规则与
// 唯一性同 §2.3 建号口径；§1.6 admin 写接口族：唯一性冲突 → already_exists +
// username_taken / target_taken，username 归 username_taken，与联系方式的
// target_taken 区分以便字段级提示）。handler 映射 already_exists +
// ErrorInfo code=username_taken。
var ErrUsernameTaken = errors.New("admin service: username already taken")

// providerCategoryUnion provider 表 category=union（§12.7 行 1542：Union
// Provider 是虚拟 Provider 仅用于归并；注册表无该 category 常量——admin
// handler unionProviderKeys 同款字面量）。
const providerCategoryUnion = "union"

// credentialKindPassword user_credential.kind=password（§4.2 行 680-684）。
const credentialKindPassword = "password"

// credentialKindTotp / credentialKindRecoveryCode user_credential.kind 取值
// （§4.2 凭证类型封闭集：password|totp|webauthn|recovery_code）。
const (
	credentialKindTotp         = "totp"
	credentialKindRecoveryCode = "recovery_code"
)

// deletedUsernamePrefix 删除匿名化保留前缀（§2.3 用户名规则唯一定义处、
// §4.2：删除把 username 改写为 "deleted_<id>"，该前缀是「已删除」的唯一
// 可辨识标记）：设置用户名的一切入口一律拒绝（不分大小写，与列表侧
// LOWER(username) 过滤同口径——uk_username 唯一键在 ci collation 下
// 大小写变体同键，放行任一变体都会制造列表不可见 / 建号撞键的歧义行），
// 对已前缀行的一切写操作按资源不存在拒绝。
const deletedUsernamePrefix = "deleted_"

// hasDeletedPrefix deleted_ 保留前缀判定：不分大小写的字面前缀匹配（§2.3
// 前缀禁用；注册 / 三方建号 / 安装 / 管理员创建四个入口与 repo 列表过滤
// 共用同一大小写口径）。入口校验先行 usernameRE（纯 ASCII），此处字节切片
// 不会撕裂多字节字符。
func hasDeletedPrefix(username string) bool {
	return len(username) >= len(deletedUsernamePrefix) &&
		strings.EqualFold(username[:len(deletedUsernamePrefix)], deletedUsernamePrefix)
}

// adminUsernameRE 后台新建用户的用户名规则（§2.3 唯一定义处）：
// ^[A-Za-z0-9_]{5,20}$，设置后不可改；deleted_ 前缀判定复用同名常量。
// 与注册 / 安装入口各落一份（跨包私有不可复用，§3.5 同款口径）。
var adminUsernameRE = regexp.MustCompile(`^[A-Za-z0-9_]{5,20}$`)

// credentialKindSet 凭证类型封闭集（§5.4 ListUsers.credentialKind：
// password|totp|webauthn|recovery_code，《后端架构》§4.2）。
var credentialKindSet = map[string]bool{
	credentialKindPassword:     true,
	credentialKindTotp:         true,
	"webauthn":                 true,
	credentialKindRecoveryCode: true,
}

// UserStore user / user_profile 表读写窄接口（§20 依赖注入）：*repo.UserRepo
// 天然满足（全部为既有列级最小增量方法），测试可传 fake。
type UserStore interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	FindByPhone(ctx context.Context, phone string) (*model.User, error)
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	ListUsers(ctx context.Context, q repo.UserListQuery) ([]model.User, int64, error)
	// CreateWithCredential 建号与初始 password 凭证同事务写入（§7.4），
	// 供 CreateUser 复用；行回填 ID 即新用户 id。
	CreateWithCredential(ctx context.Context, u *model.User, c *model.UserCredential) error
	UpdateUserStatus(ctx context.Context, id int64, userStatus int8) error
	UpdateProfileColumns(ctx context.Context, id int64, nickname, avatarURL *string) error
	UpdateContactColumns(ctx context.Context, id int64, phone, email *string, phoneVerified, emailVerified *int8) error
	UpdateMfaRequired(ctx context.Context, id int64, mfaRequired int8) error
	GetProfile(ctx context.Context, userID int64) (*model.UserProfile, error)
	SaveProfile(ctx context.Context, p *model.UserProfile) error
	IncEpoch(ctx context.Context, id int64) (int16, error)
	// AnonymizeUser 删除用户的单事务匿名化改写（§4.2：user 行改写 + profile
	// 清空 + 凭证 / WebAuthn 附加表 / 第三方绑定全清 + epoch 递增，跨表单
	// 事务）；返回递增后的新 epoch 供上层同步 al:pwdep:{uid}。跨表事务边界
	// 收编 repo（拆多次调用非同事务会留半删除态），先例 CreateWithCredential。
	AnonymizeUser(ctx context.Context, id int64, at time.Time) (int16, error)
}

// CredentialStore user_credential 表读写窄接口（*repo.CredentialRepo 天然
// 满足，含 ListByUser 最小增量）；FindByID / SetEnabled / DeleteByID 为
// 管理端救援族按 credentialId 定位的最小增量（§5.4）。
type CredentialStore interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
	FindByID(ctx context.Context, id int64) (*model.UserCredential, error)
	ListByUser(ctx context.Context, userID int64) ([]model.UserCredential, error)
	Create(ctx context.Context, c *model.UserCredential) error
	Update(ctx context.Context, c *model.UserCredential) error
	SetEnabled(ctx context.Context, id int64, enabled bool) error
	DeleteByUserAndKind(ctx context.Context, userID int64, kind string) error
	DeleteByID(ctx context.Context, userID, id int64) error
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

// SuperadminChecker 查询某 uid 权限点的窄接口（§20 DI）：*repo.PermissionRepo /
// *PermissionService 天然满足；测试可传 fake。HasPermission 判「是否
// superadmin」、HasAnyPermission 判「是否管理员」（目标分级门禁需区分
// superadmin / 普通管理员 / 普通账户三档，§4.8）。查询故障由调用方原样
// 上抛（fail-closed，不降级为「无权限」或放行）。
type SuperadminChecker interface {
	HasPermission(ctx context.Context, uid int64, point string) (bool, error)
	HasAnyPermission(ctx context.Context, uid int64) (bool, error)
}

// UserService admin 域用户管理族业务层。
type UserService struct {
	users       UserStore
	creds       CredentialStore
	binds       BindStore
	providers   ProviderFinder
	events      EventReader
	epoch       EpochSync
	pwfail      PwFailUnlocker
	audit       AuditSink
	settings    SettingsReader
	permissions SuperadminChecker
	now         func() time.Time
}

// NewUserService 构造；任一依赖为 nil 属程序错误（fail-fast，口径同
// provider.NewService）。
func NewUserService(
	users UserStore, creds CredentialStore, binds BindStore, providers ProviderFinder,
	events EventReader, epoch EpochSync, pwfail PwFailUnlocker, audit AuditSink,
	settings SettingsReader, permissions SuperadminChecker,
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
	if permissions == nil {
		panic("admin service: NewUserService: nil SuperadminChecker")
	}
	return &UserService{
		users: users, creds: creds, binds: binds, providers: providers,
		events: events, epoch: epoch, pwfail: pwfail, audit: audit,
		settings: settings, permissions: permissions, now: time.Now,
	}
}

// GetMe（§5.1）：管理员视图仅对通过统一入口鉴权的会话开放。
// {id, username, nickname, avatarUrl, isAdmin:true}（isAdmin 由 handler 恒
// 置 true——无权限点的会话在 admin 拦截器即被拦下）。uid 来自会话载荷
// （管理员 = 持有权限点的账号，安装时创建 user.id = 1，§5），
// 安装账号被删时按资源不存在处理。
func (s *UserService) GetMe(ctx context.Context, uid int64) (*model.User, error) {
	if uid <= 0 {
		return nil, ErrInvalidRequest
	}
	return s.users.FindByID(ctx, uid)
}

// ListUsersFilter ListUsers 入参（§5.4：{q, userStatus, createdFrom,
// createdTo, lastLoginFrom, lastLoginTo, mfaRequired, credentialKind}
// + §1.7 分页）。UserStatus / MfaRequired 非 nil 时仅 0|1 合法（列枚举）；
// 时间维度为 Unix 秒闭区间；CredentialKind 非空须属封闭集；Sort / Order
// 原样透传 repo（§1.7 后端不做白名单强制校验，字符集防注入归 repo）。
// 默认过滤 deleted_ 前缀的匿名化行（§5.4），由 ExcludeDeleted 透传 repo。
type ListUsersFilter struct {
	Q          string
	UserStatus *int64
	Page       int
	PageSize   int
	Sort       string
	Order      string

	CreatedFrom    *int64
	CreatedTo      *int64
	LastLoginFrom  *int64
	LastLoginTo    *int64
	MfaRequired    *int64
	CredentialKind string
}

// ListUsers（§5.4）：q 模糊匹配 username / nickname / email / phone +
// 各维度筛选 + §1.7 分页。默认过滤已删除用户（deleted_ 前缀不出现在列表）。
// 返回当页行与总数。
func (s *UserService) ListUsers(ctx context.Context, f ListUsersFilter) ([]model.User, int64, error) {
	q := repo.UserListQuery{
		Q: f.Q, Sort: f.Sort, Order: f.Order,
		Page: f.Page, PageSize: f.PageSize,
		CreatedFrom: f.CreatedFrom, CreatedTo: f.CreatedTo,
		LastLoginFrom: f.LastLoginFrom, LastLoginTo: f.LastLoginTo,
		CredentialKind: f.CredentialKind,
		ExcludeDeleted: true,
	}
	if f.UserStatus != nil {
		if *f.UserStatus != 0 && *f.UserStatus != 1 {
			return nil, 0, ErrInvalidRequest
		}
		v := int8(*f.UserStatus)
		q.UserStatus = &v
	}
	if f.MfaRequired != nil {
		if *f.MfaRequired != 0 && *f.MfaRequired != 1 {
			return nil, 0, ErrInvalidRequest
		}
		v := int8(*f.MfaRequired)
		q.MfaRequired = &v
	}
	if f.CredentialKind != "" && !credentialKindSet[f.CredentialKind] {
		return nil, 0, ErrInvalidRequest
	}
	return s.users.ListUsers(ctx, q)
}

// CreateUser（§5.4）：{username, password, nickname?} 后台新建账号。
// username 规则与 deleted_ 前缀禁用同 §2.3 建号口径（前缀不分大小写），
// 唯一性冲突 → ErrUsernameTaken；password 按 §5.6 策略现读校验，违规
// ErrPasswordWeak。建号与初始 password 凭证同事务写入（无行则无凭证可用态），
// 新 id 由 user INSERT 回填；不建会话、不接受联系方式入参（代绑走
// UpdateUserContact）。审计 admin_create_user（detail={username}，不含
// 密码）。沿用 admin 域统一「至少一个权限点」门禁（interceptor，§5）。
func (s *UserService) CreateUser(ctx context.Context, actor int64, req *adminv1.CreateUserRequest) (int64, error) {
	if req == nil {
		return 0, ErrInvalidRequest
	}
	username := strings.TrimSpace(req.GetUsername())
	if !adminUsernameRE.MatchString(username) || hasDeletedPrefix(username) {
		return 0, ErrInvalidRequest
	}
	password := req.GetPassword()
	if password == "" {
		return 0, ErrInvalidRequest
	}
	if vs := security.ValidatePassword(s.policy(), username, "", password); len(vs) > 0 {
		return 0, ErrPasswordWeak
	}
	if err := validateProfileColumns(req.Nickname, nil); err != nil {
		return 0, err
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return 0, fmt.Errorf("admin service: hash password: %w", err)
	}
	now := s.now()
	u := &model.User{
		Username:  username,
		Nickname:  req.GetNickname(),
		CreatedAt: now,
		UpdatedAt: now,
	}
	c := &model.UserCredential{
		Kind:      credentialKindPassword,
		Secret:    []byte(hash),
		IsEnabled: 1,
		UpdatedAt: now,
	}
	if err := s.users.CreateWithCredential(ctx, u, c); err != nil {
		if errors.Is(err, repo.ErrUserDuplicate) {
			return 0, ErrUsernameTaken
		}
		return 0, err
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventAdminCreateUser,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    u.ID,
		Detail:    eventlog.DetailAdminCreateUser(username),
		CreatedAt: now,
	})
	return u.ID, nil
}

// UserDetail GetUser 的聚合结果（§5.4 详情：user 行 + 凭证概览 +
// 三方绑定列表 + user_profile 行投影）；两步验证状态由 user.mfa_required
// 与凭证行 / 联系方式绑定态投影承载。Profile 为 nil 表示 user_profile 行
// 缺失（读口径同 §3.1 GetProfile：不视为错误，dto 出零值 profile 消息）；
// permissions 投影归 handler（与 §5.1 GetMe 同源）。
type UserDetail struct {
	User        *model.User
	Credentials []model.UserCredential
	Bindings    []model.UserThirdpartyBind
	Profile     *model.UserProfile
}

// GetUser（§5.4）：{id} 详情——user 行（含 mfa_required 开关列）+
// 凭证概览（全部 kind 行，kind/is_enabled 投影在 dto，secret 不透出）+
// 三方绑定列表（bind_repo.ListByUserID）+ user_profile 行投影（行缺失
// 容忍为 nil，供编辑表单回填）。
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
	profile, err := s.users.GetProfile(ctx, id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return &UserDetail{User: user, Credentials: creds, Bindings: binds, Profile: profile}, nil
}

// UpdateUserStatus（§5.4 行 1251）：{id, userStatus 0|1} 禁用 /
// 启用。列级 UPDATE 收编 repo（UpdateUserStatus）；禁用 → IncEpoch（既有
// 会话与已颁发令牌全部失效，§11.1）+ al:pwdep 同步（§5.1 行 864 触发项）
// + 审计 admin_disable_user（actor=admin，detail 落 NULL——§4.6 行 808 表
// 未定义该事件 detail，默认）；启用不审计（eventlog 无既有常量，不
// 自造事件名，默认）。幂等重放（再次禁用已禁用用户）同样走失效链
// 与审计——每次管理员动作都留痕。目标分级门禁统一走 authorizeUserWrite
// （禁用与启用同适用：superadmin 目标一律拒绝，含启用分支，§5.4 矩阵；
// 普通管理员目标仅 superadmin 操作者；查询故障原样上抛）。
func (s *UserService) UpdateUserStatus(ctx context.Context, actor, id int64, userStatus int64) error {
	if id <= 0 || (userStatus != 0 && userStatus != 1) {
		return ErrInvalidRequest
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
		return err
	}
	if err := s.users.UpdateUserStatus(ctx, id, int8(userStatus)); err != nil {
		return err // 含 sql.ErrNoRows → 404
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
// 不同，§5.4 无此语义）。目标分级门禁统一走 authorizeUserWrite（收编原
// 「superadmin 目标可被 superadmin 操作者重置」旧口径——重置属强制踢下线
// 动作，superadmin 目标一律拒绝，§5.4 矩阵；普通管理员目标仅 superadmin
// 操作者；查询故障原样上抛，fail-closed）。FindByID 先于门禁：行缺失
// not_found 不查权限表（既有口径）。
func (s *UserService) ResetUserPassword(ctx context.Context, actor, id int64, password string) error {
	if id <= 0 || password == "" {
		return ErrInvalidRequest
	}
	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
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
// {provider_key, open_id}，§4.6 行 816）。目标分级门禁统一走
// authorizeUserWrite（本期补齐，§5.4 矩阵；查询故障原样上抛）。
func (s *UserService) UnbindUserThirdparty(ctx context.Context, actor, id int64, providerKey string) error {
	if id <= 0 || providerKey == "" {
		return ErrInvalidRequest
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
		return err
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
		return fmt.Errorf("admin service: unbind: user %d has no binding for %q: %w", id, providerKey, sql.ErrNoRows)
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
// 解锁审计常量，不投事件（默认，同启用不审计口径）。目标分级门禁统一走
// authorizeUserWrite（本期补齐，§5.4 矩阵；查询故障原样上抛）——解锁是
// epoch 触发动作族的前置救援，目标分级同适用。
func (s *UserService) UnlockUser(ctx context.Context, actor, id int64) error {
	if id <= 0 {
		return ErrInvalidRequest
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
		return err
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
// ——event=login_success 过滤（「登录记录」视图，§5.4 行 1252；事件类型
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

// DeleteUser（§5.4 / 《后端架构》§4.2）：{id} 删除用户 = 禁用 + 全部会话
// 与令牌失效 + 匿名化——单事务匿名化改写收编 repo（AnonymizeUser：user 行
// 改写 user_status=0 / username="deleted_<id>" / 联系方式与资料清空 + epoch
// 递增，user_profile 清空，凭证含 WebAuthn 附加表与第三方绑定含 Union 连带
// 全清，不物理删行、不新增字段），事务成功后同步 al:pwdep:{uid}（已签发
// 令牌全部失效）→ 审计 admin_delete_user（detail={}，user_id 由行列承载、
// 不含明文联系方式，§4.6）。硬边界（§4.8）：自删（actor == id）拒绝、有任意
// 权限点的账户一律禁删（不因操作者是 superadmin 而放宽）——均
// ErrPermissionDenied；已匿名化行（username 带 deleted_ 前缀）按资源不存在
// 返回 not_found（§4.2，先于门禁判定：user_permission 行不随删除清理，
// 门禁先查会把已删 superadmin 误判为 permission_denied）。
func (s *UserService) DeleteUser(ctx context.Context, actor, id int64) error {
	if id <= 0 {
		return ErrInvalidRequest
	}
	if actor == id {
		return ErrPermissionDenied
	}
	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if hasDeletedPrefix(user.Username) {
		return sql.ErrNoRows
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
		return err
	}
	hasPerm, err := s.permissions.HasAnyPermission(ctx, id)
	if err != nil {
		return err // 权限查询故障原样上抛（fail-closed）
	}
	if hasPerm {
		return ErrPermissionDenied
	}
	epoch, err := s.users.AnonymizeUser(ctx, id, s.now())
	if err != nil {
		return err
	}
	if err := s.epoch.Sync(ctx, id, epoch); err != nil {
		return err
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventAdminDeleteUser,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    id,
		Detail:    eventlog.DetailEmpty(),
		CreatedAt: s.now(),
	})
	return nil
}

// writableTarget 写目标行级前置校验（§1.6 admin 写接口族「目标不存在（含
// 已匿名化行）」→ not_found；§4.2 deleted_ 前缀为「已删除」唯一标记）：
// 行缺失与已匿名化行统一 not_found，且先于 authorizeUserWrite——
// user_permission 行不随删除清理，门禁先查会把已删 superadmin 误判为
// permission_denied（DeleteUser 同款顺序）。
func (s *UserService) writableTarget(ctx context.Context, id int64) (*model.User, error) {
	user, err := s.users.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if hasDeletedPrefix(user.Username) {
		return nil, sql.ErrNoRows
	}
	return user, nil
}

// authorizeUserWrite 目标账户分级写门禁（§5.4 门禁矩阵、《后端架构》§4.8）：
// 目标为 superadmin 账户一律拒绝（任何操作者，含其自身）；目标为普通管理员
// 账户（持任意权限点、不含 superadmin）仅 superadmin 操作者可写；目标为
// 普通账户放行（操作者已过 admin 拦截器「至少一个权限点」）。权限查询故障
// 原样上抛不放行（fail-closed）；拒绝统一 ErrPermissionDenied（handler 映射
// Connect 标准码 permission_denied，不挂 ErrorInfo 细分码）。
func (s *UserService) authorizeUserWrite(ctx context.Context, actor, targetID int64) error {
	targetSA, err := s.permissions.HasPermission(ctx, targetID, PointSuperAdmin)
	if err != nil {
		return err // 权限查询故障原样上抛（fail-closed）
	}
	if targetSA {
		return ErrPermissionDenied
	}
	targetAdmin, err := s.permissions.HasAnyPermission(ctx, targetID)
	if err != nil {
		return err // 权限查询故障原样上抛（fail-closed）
	}
	if !targetAdmin {
		return nil // 普通账户：操作者已过 admin 拦截器，放行
	}
	return s.authorizeSuperadminActor(ctx, actor)
}

// authorizeSuperadminActor 操作者必须持 superadmin 权限点（普通管理员目标
// 的写前置、UpdateUserContact 的无条件前置——该能力等价于无凭据接管账号，
// §5.4 门禁矩阵例外行）。查询故障原样上抛不放行（fail-closed）。
func (s *UserService) authorizeSuperadminActor(ctx context.Context, actor int64) error {
	actorSA, err := s.permissions.HasPermission(ctx, actor, PointSuperAdmin)
	if err != nil {
		return err // 权限查询故障原样上抛（fail-closed）
	}
	if !actorSA {
		return ErrPermissionDenied
	}
	return nil
}

// contactPhonePattern / contactEmailPattern 非空联系方式的格式权威校验
// （§1.11 phone / email「后端为唯一权威」；§5.4 PATCH 校验——违规
// invalid_request）。与前端体验性预校验同式：手机号为中国大陆号段，
// 邮箱为「无空白、恰一个 @、@ 两侧非空且域名含点」的宽松式。
var (
	contactPhonePattern = regexp.MustCompile(`^1[3-9]\d{9}$`)
	contactEmailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

// validContactFormat 非空值的格式校验（空串 = 显式清空，不在此校验）。
func validContactFormat(kind, v string) bool {
	if kind == "phone" {
		return contactPhonePattern.MatchString(v)
	}
	return contactEmailPattern.MatchString(v)
}

// validateProfileColumns 昵称 / 头像 URL 列宽校验（违规 invalid_request，
// 字段级提示）：nil = 未传跳过。超宽若放行会被 DB 列宽拒绝并折叠成
// internal，故服务层先于任何写库给出字段级拒绝；CreateUser（仅昵称）与
// UpdateUserProfile 两入口共用。上限取 model 包资料列宽单一来源。
func validateProfileColumns(nickname, avatarURL *string) error {
	if nickname != nil && utf8.RuneCountInString(*nickname) > model.NicknameMaxRunes {
		return ErrInvalidRequest
	}
	if avatarURL != nil && utf8.RuneCountInString(*avatarURL) > model.AvatarURLMaxRunes {
		return ErrInvalidRequest
	}
	return nil
}

// UpdateUserProfile（§5.4）：{id, nickname?, avatarUrl?, profile{...}} PATCH
// 编辑用户资料。has 位口径与 §3.2 UpdateProfile 同源（未设置 = 不修改、
// 显式设值 = 覆盖，含显式空串 = 清空）；校验复用自助域口径（gender ∈ 0/1/2、
// birthday YYYY-MM-DD、extra 为 JSON 对象——birthday / extra 由
// dto.MergeUserProfile 校验），违规一律 invalid_request。不改 username、
// 不触发会话失效（§5.4 强制下线集合不含资料编辑）。全字段未设置 = 空操作
// 直接成功。审计 admin_update_user（detail={changed_fields}，仅字段名）。
func (s *UserService) UpdateUserProfile(ctx context.Context, actor, id int64, req *adminv1.UpdateUserProfileRequest) error {
	if id <= 0 || req == nil {
		return ErrInvalidRequest
	}
	if _, err := s.writableTarget(ctx, id); err != nil {
		return err // 行缺失 / 已匿名化行 → 404（先于门禁，DeleteUser 同款顺序）
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
		return err
	}
	// profile 载荷先合并校验（birthday / extra / gender 值域），非法拒绝时
	// user 表列尚未写入，不产生部分落库。
	var merged *model.UserProfile
	if p := req.GetProfile(); p != nil {
		if g := p.GetGender(); p.Gender != nil && (g < 0 || g > 2) {
			return ErrInvalidRequest // gender ∈ 0/1/2（§5.4 PATCH 校验）
		}
		existing, err := s.users.GetProfile(ctx, id)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		m, changed, err := dto.MergeUserProfile(id, existing, p)
		if err != nil {
			return ErrInvalidRequest
		}
		if changed {
			m.UpdatedAt = s.now()
			merged = m
		}
	}
	// user 表资料列：has 位判定，仅 has 时列级更新（显式空串 = 清空）；
	// 列宽先校验（§3.2 / §5.4），非法拒绝时 user 表列尚未写入。
	if err := validateProfileColumns(req.Nickname, req.AvatarUrl); err != nil {
		return err
	}
	if req.Nickname != nil || req.AvatarUrl != nil {
		if err := s.users.UpdateProfileColumns(ctx, id, req.Nickname, req.AvatarUrl); err != nil {
			return err
		}
	}
	if merged != nil {
		if err := s.users.SaveProfile(ctx, merged); err != nil {
			return err
		}
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventAdminUpdateUser,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    id,
		Detail:    eventlog.DetailChangedFields(userProfileChangedFields(req)),
		CreatedAt: s.now(),
	})
	return nil
}

// userProfileChangedFields UpdateUserProfile 的变更字段名清单（wire 字段名，
// §4.6 admin_update_user detail={changed_fields}，仅字段名不含值）。
func userProfileChangedFields(req *adminv1.UpdateUserProfileRequest) []string {
	var fields []string
	if req.Nickname != nil {
		fields = append(fields, "nickname")
	}
	if req.AvatarUrl != nil {
		fields = append(fields, "avatar_url")
	}
	if p := req.GetProfile(); p != nil {
		if p.Gender != nil {
			fields = append(fields, "gender")
		}
		if p.Birthday != nil {
			fields = append(fields, "birthday")
		}
		if p.Locale != nil {
			fields = append(fields, "locale")
		}
		if p.Timezone != nil {
			fields = append(fields, "timezone")
		}
		if p.Extra != nil {
			fields = append(fields, "extra")
		}
	}
	return fields
}

// UpdateUserContact（§5.4）：{id, phone?, email?} PATCH 编辑用户联系方式。
// has 位口径与 §3.2 同源；写入非空值时服务端直接把对应 *_verified 置 1
// （管理员代写即视为已验证）、清空置 0（写 NULL，repo 归一口径），接口不
// 暴露 *_verified 入参。该能力等价于无凭据接管账号：目标分级门禁之外，
// 操作者还必须持 superadmin（§5.4 门禁矩阵例外行）。非空值先过格式权威
// 校验（§1.11），唯一性冲突返回字段级错误（ErrTargetTaken）且不投审计；
// 改联系方式属强制下线动作（§5.4 触发集合）——写库成功后 IncEpoch +
// al:pwdep 同步，再投审计 admin_update_contact（detail={changed_fields}
// 仅字段名，不记手机号 / 邮箱明文）。
func (s *UserService) UpdateUserContact(ctx context.Context, actor, id int64, req *adminv1.UpdateUserContactRequest) error {
	if id <= 0 || req == nil {
		return ErrInvalidRequest
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
		return err
	}
	if err := s.authorizeSuperadminActor(ctx, actor); err != nil {
		return err
	}
	// trim 归一（bind 链路同口径）后格式校验：非空值违规 → invalid_request；
	// 空串 = 显式清空。trim 后的本地副本承载后续写库值，不改写入参。
	var phone, email *string
	if req.Phone != nil {
		v := strings.TrimSpace(req.GetPhone())
		phone = &v
	}
	if req.Email != nil {
		v := strings.TrimSpace(req.GetEmail())
		email = &v
	}
	if phone != nil && *phone != "" && !validContactFormat("phone", *phone) {
		return ErrInvalidRequest
	}
	if email != nil && *email != "" && !validContactFormat("email", *email) {
		return ErrInvalidRequest
	}
	if _, err := s.users.FindByID(ctx, id); err != nil {
		return err // 行缺失 → 404（先于占用查询与写操作）
	}
	// 唯一性预检（uk_phone / uk_email，§5.4）：命中他人 → ErrTargetTaken
	//（不写库、不失效会话、不投审计）；命中自己 = 原值重放，照常写。
	if err := s.checkContactFree(ctx, id, "phone", derefString(phone)); err != nil {
		return err
	}
	if err := s.checkContactFree(ctx, id, "email", derefString(email)); err != nil {
		return err
	}
	// 写即置已验证：非空 → 1，显式清空 → 0（repo 空串归一写 NULL）。
	var phoneV, emailV *int8
	if phone != nil {
		v := int8(0)
		if *phone != "" {
			v = 1
		}
		phoneV = &v
	}
	if email != nil {
		v := int8(0)
		if *email != "" {
			v = 1
		}
		emailV = &v
	}
	if err := s.users.UpdateContactColumns(ctx, id, phone, email, phoneV, emailV); err != nil {
		// TOCTOU（预检后落库前被他人抢占）→ 唯一键冲突归一字段级错误
		//（§10.2 占用口径，bind 链路同款回补）。
		if errors.Is(err, repo.ErrUserDuplicate) {
			return ErrTargetTaken
		}
		return err
	}
	if _, err := s.invalidateSessions(ctx, id); err != nil {
		return err
	}
	var changed []string
	if phone != nil {
		changed = append(changed, "phone")
	}
	if email != nil {
		changed = append(changed, "email")
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventAdminUpdateContact,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    id,
		Detail:    eventlog.DetailChangedFields(changed),
		CreatedAt: s.now(),
	})
	return nil
}

// checkContactFree 非空联系方式占用预检：命中他人行 → ErrTargetTaken；
// 未占用 / 命中自己 → nil。kind = phone｜email（按列取 FindByPhone /
// FindByEmail）。空值（显式清空）不占用唯一键，直接放行。
func (s *UserService) checkContactFree(ctx context.Context, self int64, kind, value string) error {
	if value == "" {
		return nil
	}
	var holder *model.User
	var err error
	if kind == "phone" {
		holder, err = s.users.FindByPhone(ctx, value)
	} else {
		holder, err = s.users.FindByEmail(ctx, value)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if holder.ID != self {
		return ErrTargetTaken
	}
	return nil
}

// —— 救援族 5 方法：目标分级门禁统一走 authorizeUserWrite；强制下线接线
// 按 §5.4 集合口径（关 MFA / 解绑 TOTP / 删凭证触发，开启 MFA / 凭证启停 /
// 恢复码重置不触发）；管理域救援不做用户侧二次验证（管理员权限即授权）——

// SetUserMfa（§5.4）：{id, mfaRequired 0|1} 管理端开关用户两步验证。
// 值域违规 invalid_request；行缺失（先于写操作）→ 404。开关列走
// UpdateMfaRequired（§3.5 SetMfa 同款唯一写入端，不递增 epoch 由失效链
// 显式承担）。关闭（0）→ IncEpoch + al:pwdep 同步 + 审计 admin_disable_mfa
// （detail={enabled:false}，§4.6）；开启（1）不触发会话失效、不投审计
// （§4.6 无 admin_enable_mfa，不自造事件名）。幂等重放同走失效链与审计
// ——管理员动作都留痕（UpdateUserStatus 同口径）。
func (s *UserService) SetUserMfa(ctx context.Context, actor, id int64, mfaRequired int64) error {
	if id <= 0 || (mfaRequired != 0 && mfaRequired != 1) {
		return ErrInvalidRequest
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
		return err
	}
	if _, err := s.users.FindByID(ctx, id); err != nil {
		return err
	}
	if err := s.users.UpdateMfaRequired(ctx, id, int8(mfaRequired)); err != nil {
		return err
	}
	if mfaRequired != 0 {
		return nil
	}
	if _, err := s.invalidateSessions(ctx, id); err != nil {
		return err
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventAdminDisableMFA,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    id,
		Detail:    eventlog.DetailEnabled(false),
		CreatedAt: s.now(),
	})
	return nil
}

// UnbindUserTOTP（§5.4）：{id} 管理员救援删除该用户 kind=totp 凭证行
// （不要求用户侧二次验证令牌，管理员权限即授权）。recovery_code 行不在
// 本接口契约范围（仅删 totp 行；自助域解绑连带删恢复码系 §3.5 自助口径）。
// user 行或 totp 行缺失 → 404；删除成功 → IncEpoch + al:pwdep 同步 +
// 审计 admin_unbind_totp（detail={}，不记 TOTP 密钥，§4.6）。
func (s *UserService) UnbindUserTOTP(ctx context.Context, actor, id int64) error {
	if id <= 0 {
		return ErrInvalidRequest
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
		return err
	}
	if _, err := s.users.FindByID(ctx, id); err != nil {
		return err
	}
	if err := s.creds.DeleteByUserAndKind(ctx, id, credentialKindTotp); err != nil {
		return err
	}
	if _, err := s.invalidateSessions(ctx, id); err != nil {
		return err
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventAdminUnbindTotp,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    id,
		Detail:    eventlog.DetailEmpty(),
		CreatedAt: s.now(),
	})
	return nil
}

// ResetUserRecoveryCodes（§5.4）：{id} 重生成恢复码写回凭证 meta，响应
// 不下发明文（OkResponse 无字段；明细口径与 §3.5 一致——剩余数量与签发
// 时间可见，码值永不回显）。行缺失（未绑定 totp 即无 recovery_code 行）
// → 404；重生成整行覆盖 meta（生成口径 §4.2：10 条互异 8 位存储形，
// generateRecoveryCodes 与自助域各落一份——跨包私有不可复用）。
// is_enabled 不在本接口改动范围（停用走 SetCredentialEnabled）；不触发
// 会话失效（§5.4 强制下线集合不含恢复码重置）；审计
// admin_recovery_codes_reset（detail={}，不记任何码值，§4.6）。
func (s *UserService) ResetUserRecoveryCodes(ctx context.Context, actor, id int64) error {
	if id <= 0 {
		return ErrInvalidRequest
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
		return err
	}
	if _, err := s.users.FindByID(ctx, id); err != nil {
		return err
	}
	row, err := s.creds.FindByUserAndKind(ctx, id, credentialKindRecoveryCode)
	if err != nil {
		return err
	}
	codes, err := generateRecoveryCodes()
	if err != nil {
		return fmt.Errorf("admin service: generate recovery codes: %w", err)
	}
	meta, err := repo.MarshalCredentialMeta(&credentialpb.CredentialMeta{RecoveryCodes: codes})
	if err != nil {
		return fmt.Errorf("admin service: marshal recovery codes meta: %w", err)
	}
	row.Meta = meta
	row.UpdatedAt = s.now()
	if err := s.creds.Update(ctx, row); err != nil {
		return err
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventAdminRecoveryCodesReset,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    id,
		Detail:    eventlog.DetailEmpty(),
		CreatedAt: s.now(),
	})
	return nil
}

// SetCredentialEnabled（§5.4）：{id, credentialId, enabled} 停用 / 启用
// 单条凭证。凭证行缺失或不属目标用户统一 404（不区分，避免泄露归属）；
// 密码凭证不允许停用（避免无密码可用态，invalid_request）。按 §5.4 契约
// 口径不触发会话失效（强制下线集合不含凭证启停：不 IncEpoch、不失效既有
// 会话）；写一条管理员审计事件 admin_credential_set_enabled（双向单事件，
// detail={credential_id, kind, enabled 写入值}，§4.6 / §5.6）。
func (s *UserService) SetCredentialEnabled(ctx context.Context, actor, id, credentialID int64, enabled bool) error {
	if id <= 0 || credentialID <= 0 {
		return ErrInvalidRequest
	}
	if _, err := s.writableTarget(ctx, id); err != nil {
		return err // 行缺失 / 已匿名化行 → 404（先于门禁，DeleteUser 同款顺序）
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
		return err
	}
	row, err := s.creds.FindByID(ctx, credentialID)
	if err != nil {
		return err
	}
	if row.UserID != id {
		return fmt.Errorf("admin service: credential %d not owned by user %d: %w", credentialID, id, sql.ErrNoRows)
	}
	if !enabled && row.Kind == credentialKindPassword {
		return ErrInvalidRequest
	}
	if err := s.creds.SetEnabled(ctx, credentialID, enabled); err != nil {
		return err
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventAdminCredentialSetEnabled,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    id,
		Detail:    eventlog.DetailCredentialSetEnabled(credentialID, row.Kind, enabled),
		CreatedAt: s.now(),
	})
	return nil
}

// DeleteCredential（§5.4）：{id, credentialId} 删除单条凭证（含 WebAuthn
// 附加行——DeleteByID 单事务同删）。凭证行缺失或不属目标用户统一 404。
// 密码凭证不允许删除——比照停用更彻底的写操作更不允许制造无密码可用态
// （invalid_request，口径同 SetCredentialEnabled 的密码停用拒绝）。
// 属强制下线动作（§5.4 触发集合含「删除凭证」）→ IncEpoch + al:pwdep 同步
// → 审计 admin_credential_delete（detail={credential_id, kind}，不记凭证
// secret，§4.6）。
func (s *UserService) DeleteCredential(ctx context.Context, actor, id, credentialID int64) error {
	if id <= 0 || credentialID <= 0 {
		return ErrInvalidRequest
	}
	if _, err := s.writableTarget(ctx, id); err != nil {
		return err // 行缺失 / 已匿名化行 → 404（先于门禁，DeleteUser 同款顺序）
	}
	if err := s.authorizeUserWrite(ctx, actor, id); err != nil {
		return err
	}
	row, err := s.creds.FindByID(ctx, credentialID)
	if err != nil {
		return err
	}
	if row.UserID != id {
		return fmt.Errorf("admin service: credential %d not owned by user %d: %w", credentialID, id, sql.ErrNoRows)
	}
	if row.Kind == credentialKindPassword {
		return ErrInvalidRequest
	}
	if err := s.creds.DeleteByID(ctx, id, credentialID); err != nil {
		return err
	}
	if _, err := s.invalidateSessions(ctx, id); err != nil {
		return err
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventAdminCredentialDelete,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		UserID:    id,
		Detail:    eventlog.DetailCredentialDelete(credentialID, row.Kind),
		CreatedAt: s.now(),
	})
	return nil
}

// 恢复码生成口径（§4.2：8 位 Crockford Base32 小写存储形、每批 10 条、
// 展示形 xxxx-xxxx 仅在自助签发渠道下发）。与自助域 / factor/recovery 各落
// 一份（跨包私有不可复用）；本域只写回 meta、任何出口不回显码值。
const (
	recoveryCodeLength       = 8
	recoveryCodeCount        = 10
	recoveryCodeCharset      = "0123456789abcdefghjkmnpqrstvwxyz"
	recoveryCodeDedupRetries = 64
)

// generateRecoveryCodes 生成 10 条互异 8 位存储形恢复码（crypto/rand；
// 恢复码命中即删、一码一值，批内重复会让剩余数量与实际可用值不符）。
// 碰撞重生成，重试上限防退化随机源死循环。
func generateRecoveryCodes() ([]string, error) {
	codes := make([]string, 0, recoveryCodeCount)
	seen := make(map[string]bool, recoveryCodeCount)
	buf := make([]byte, recoveryCodeLength)
	for retries := 0; len(codes) < recoveryCodeCount; retries++ {
		if retries > recoveryCodeDedupRetries {
			return nil, errors.New("recovery code entropy exhausted")
		}
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return nil, err
		}
		b := make([]byte, recoveryCodeLength)
		for j := range buf {
			b[j] = recoveryCodeCharset[buf[j]%byte(len(recoveryCodeCharset))]
		}
		c := string(b)
		if seen[c] {
			continue
		}
		seen[c] = true
		codes = append(codes, c)
	}
	return codes, nil
}

// invalidateSessions 禁用 / 重置密码的会话失效链（§11.1 行 1236、§5.1 行
// 864）：IncEpoch 递增 user.epoch（回绕语义见 repo）→ EpochStore.Sync 同步
// al:pwdep:{uid}（TTL 24h）——不同步则校验链最长 24h 读旧值，失效不生效
// （setpass.go reset 同款链，返回递增后的新值供审计 detail）。
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
	case errors.Is(err, sql.ErrNoRows):
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
// *repo.ProviderRepo / *repo.EventLogRepo / *repo.PermissionRepo 满足各窄接口
// （签名漂移在编译期暴露）。
var (
	_ UserStore         = (*repo.UserRepo)(nil)
	_ CredentialStore   = (*repo.CredentialRepo)(nil)
	_ BindStore         = (*repo.BindRepo)(nil)
	_ ProviderFinder    = (*repo.ProviderRepo)(nil)
	_ EventReader       = (*repo.EventLogRepo)(nil)
	_ SuperadminChecker = (*repo.PermissionRepo)(nil)
)
