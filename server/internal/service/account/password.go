// password.go account 域密码族业务层（docs/接口文档.md §3.3 行
// 870-879、docs/需求.md §4.1.9 行 124-129）。
//
// 职责：AccountService/ChangePassword 的改密编排——读 user → §5.6 密码
// 策略校验（settings pwd_* 五键现读保证热更新，违规 → password_weak）→
// 旧密码校验（password 凭证行存在时 currentPassword 必填并经
// security.VerifyPassword 校验，失败 → invalid_credentials〔§1.6 行 247/269
// 默认口径「密码错误与账号不存在同码」；password_incorrect 在
// docs 全域不存在，系笔误，按文档口径实现〕；凭证行缺失 =
// 无密码账号，currentPassword 不参与校验、直接按「设置密码」补建，
// 需求 §4.1.9「无密码的账号可直接设置密码」、setPassReset 行 299-302
// 同口径）→ credential 更新（有行 Update / 无行补建 Create）→ IncEpoch +
// al:pwdep:{uid} Sync → 异步审计 change_password（EventChangePassword +
// DetailPwdEpoch，ActorType=user）。旧密码校验失败不做 pwd_fail_capture
// 锁定计数（§8.1 锁定为密码登录链专用，文档未覆盖改密联动，不自行发挥）。
//
// 会话边界（写进签名与头注）：本层不签发新会话、不触碰会话 Cookie——
// 「当前会话与全部已颁发令牌失效」经 epoch 失效链天然达成（IncEpoch 后
// 旧令牌含当前会话全部失效，§3.3 行 879）；如需显式 Cookie 清除由拼装层
// handler 完成。uid 由 handler 注入（会话载荷），本层不解析会话。
package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"authloft/internal/cache"
	"authloft/internal/eventlog"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/settings"
)

// PasswordUserStore user 表窄接口（§20 依赖注入）：*repo.UserRepo 天然满足
// （FindByID / IncEpoch 均既有），测试可传 fake。
type PasswordUserStore interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	IncEpoch(ctx context.Context, id int64) (int16, error)
}

// PasswordCredentialStore user_credential 表读写窄接口（§20）：
// *repo.CredentialRepo 天然满足。
type PasswordCredentialStore interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
	Create(ctx context.Context, c *model.UserCredential) error
	Update(ctx context.Context, c *model.UserCredential) error
}

// PasswordEpochSync epoch 递增后同步 al:pwdep:{uid}（cache.EpochStore.Sync，
// §5.1 行 850、TTL 24h——不同步则校验链最长 24h 读旧值，失效不生效）：
// *cache.EpochStore 天然满足。
type PasswordEpochSync interface {
	Sync(ctx context.Context, uid int64, epoch int16) error
}

// PasswordSettingsReader 密码策略五键现读（§5.6 键为唯一定义处；
// *settings.Store 天然满足，每次校验现读保证热更新）。
type PasswordSettingsReader interface {
	GetInt64(key string) (int64, bool)
	GetBool(key string) (bool, bool)
}

// 可判别哨兵错误（handler〔拼装层〕转 Connect 错误体 + ErrorInfo，
// §1.6 封闭集成员；本层签名只返回 error，映射归 handler）。
var (
	// ErrPasswordInvalidRequest uid 非法 / newPassword 缺失 / 已设置密码而
	// currentPassword 未填（映射 invalid_argument + code=invalid_request）。
	ErrPasswordInvalidRequest = errors.New("account password: invalid request")
	// ErrPasswordWeak newPassword 不满足 §5.6 策略（映射 invalid_argument +
	// code=password_weak）。
	ErrPasswordWeak = errors.New("account password: password does not meet policy")
	// ErrPasswordInvalidCredentials 旧密码校验失败（映射 invalid_argument +
	// code=invalid_credentials，§1.6 行 247/269 默认口径；
	// password_incorrect 为笔误，不另设码）。
	ErrPasswordInvalidCredentials = errors.New("account password: invalid credentials")
)

// PasswordDeps 依赖注入（§20）；装配层构造（bootstrap 接线）。
type PasswordDeps struct {
	// Users user 表读取 + epoch 递增。
	Users PasswordUserStore
	// Creds password 凭证行读写。
	Creds PasswordCredentialStore
	// Epoch al:pwdep:{uid} 同步。
	Epoch PasswordEpochSync
	// Settings pwd_* 五键现读（nil = 回落 security 默认档，测试用）。
	Settings PasswordSettingsReader
	// Audit change_password 审计投递（nil = 跳过，测试用）。
	Audit AuditSink
	// Now 时钟注入（缺省 time.Now）。
	Now func() time.Time
}

// PasswordService account 域密码族业务层。
type PasswordService struct {
	deps PasswordDeps
	now  func() time.Time
}

// NewPasswordService 构造。
func NewPasswordService(d PasswordDeps) *PasswordService {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &PasswordService{deps: d, now: now}
}

// compile 时断言生产实现满足各窄接口（签名漂移在编译期暴露）。
var (
	_ PasswordUserStore       = (*repo.UserRepo)(nil)
	_ PasswordCredentialStore = (*repo.CredentialRepo)(nil)
	_ PasswordEpochSync       = (*cache.EpochStore)(nil)
	_ PasswordSettingsReader  = (*settings.Store)(nil)
)

// ChangePassword（§3.3 行 872）：当前用户改密 / 无密码账号设密，编排链——
//  1. 入参边界：uid<=0 / newPassword 空 → invalid_request；读 user 行
//     （不存在 → gorm.ErrRecordNotFound 透传，handler 转 not_found）；
//  2. 策略校验：settings pwd_* 五键现读构造 security.PasswordPolicy，
//     newPassword 违规 → password_weak（固定三规则〔>64 / 与用户名或邮箱
//     完全相同 / 含空白〕由 security.ValidatePassword 内建，§5.6 行
//     1311-1315）；
//  3. 旧密码校验：password 凭证行缺失 → currentPassword 不参与校验、
//     直接补建（需求 §4.1.9）；有行 → currentPassword 必填（空 →
//     invalid_request）、VerifyPassword 失败 → invalid_credentials（损坏
//     哈希同口径，factor/password onFailure 同款，不泄露哈希状态；不做
//     pwd_fail_capture 锁定计数）；
//  4. credential 写入：有行 Update、无行补建 Create（writeCredential）；
//  5. IncEpoch + al:pwdep:{uid} Sync——旧令牌含当前会话全部失效（行 879）；
//  6. 异步审计 change_password（ActorType=user、ActorID=uid、
//     detail={pwd_epoch}）。
//
// 本层不签发新会话、不触碰会话 Cookie（见文件头注会话边界）。
func (s *PasswordService) ChangePassword(ctx context.Context, uid int64, currentPassword, newPassword string) error {
	if uid <= 0 || newPassword == "" {
		return ErrPasswordInvalidRequest
	}
	user, err := s.deps.Users.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		return fmt.Errorf("account password: load user: %w", err)
	}
	email := ""
	if user.Email != nil {
		email = *user.Email
	}
	if vs := security.ValidatePassword(s.policy(), user.Username, email, newPassword); len(vs) > 0 {
		return ErrPasswordWeak
	}

	// 旧密码校验 + credential 写入（凭证行缺失 = 无密码账号设密，行在场
	// = 改密须验旧密码，§3.3 行 876「已设置密码时必填」）。
	cred, err := s.deps.Creds.FindByUserAndKind(ctx, uid, kindPassword)
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		// currentPassword 传入值忽略：文档仅约定「已设置密码时必填」，
		// 未约定无行时禁止传入（setPassReset 补建同不校验）。
		if err := s.writeCredential(ctx, uid, newPassword, nil); err != nil {
			return err
		}
	case err != nil:
		return fmt.Errorf("account password: load credential: %w", err)
	default:
		if currentPassword == "" {
			return ErrPasswordInvalidRequest
		}
		if err := security.VerifyPassword(currentPassword, string(cred.Secret)); err != nil {
			if errors.Is(err, security.ErrPasswordMismatch) || errors.Is(err, security.ErrInvalidHash) {
				return ErrPasswordInvalidCredentials
			}
			return fmt.Errorf("account password: verify password: %w", err)
		}
		if err := s.writeCredential(ctx, uid, newPassword, cred); err != nil {
			return err
		}
	}

	// epoch 递增 + al:pwdep:{uid} 同步（§3.3 行 879：当前会话与全部已颁发
	// 令牌失效；同步失败即上抛——DB 密码已改，重试幂等）。
	epoch, err := s.deps.Users.IncEpoch(ctx, uid)
	if err != nil {
		return fmt.Errorf("account password: inc epoch: %w", err)
	}
	if err := s.deps.Epoch.Sync(ctx, uid, epoch); err != nil {
		return fmt.Errorf("account password: sync epoch: %w", err)
	}
	// 异步审计（AuditSink 非阻塞，队列满由 Writer 静默降级，不阻塞主链路）。
	if s.deps.Audit != nil {
		s.deps.Audit.PushEvent(model.EventLog{
			Event:     eventlog.EventChangePassword,
			ActorType: eventlog.ActorTypeUser,
			ActorID:   uid,
			UserID:    uid,
			Detail:    eventlog.DetailPwdEpoch(int64(epoch)),
			CreatedAt: s.now(),
		})
	}
	return nil
}

// writeCredential 写入 password 凭证行：existing 非空走 Update（secret /
// is_enabled=1 / updated_at），为空走 Create 补建（uid 已存在不属建号；
// orchestrator setpass.go writeCredential 行 365-378 同口径）。hash 复用
// security.HashPassword（argon2id PHC 串，§8.1），不自造。
func (s *PasswordService) writeCredential(ctx context.Context, uid int64, password string, existing *model.UserCredential) error {
	hash, err := security.HashPassword(password)
	if err != nil {
		return fmt.Errorf("account password: hash password: %w", err)
	}
	if existing != nil {
		existing.Secret = []byte(hash)
		existing.IsEnabled = 1
		existing.UpdatedAt = s.now()
		return s.deps.Creds.Update(ctx, existing)
	}
	return s.deps.Creds.Create(ctx, &model.UserCredential{
		UserID:    uid,
		Kind:      kindPassword,
		Secret:    []byte(hash),
		IsEnabled: 1,
		UpdatedAt: s.now(),
	})
}

// policy 从 settings 现读 pwd_* 五键构造策略（§5.6 键为唯一定义处；越界 /
// 缺失回落 security 默认档——admin user.go / orchestrator setpass.go 同口径
// 同实现，跨包私有无法复用，按后端架构 §3.5 各落一份）。
func (s *PasswordService) policy() security.PasswordPolicy {
	p := security.DefaultPasswordPolicy()
	if s.deps.Settings == nil {
		return p
	}
	if v, ok := s.deps.Settings.GetInt64(settings.KeyPwdMinLength); ok && v > 0 {
		p.MinLength = int(v)
	}
	if v, ok := s.deps.Settings.GetInt64(settings.KeyPwdMaxLength); ok && v > 0 {
		p.MaxLength = int(v)
	}
	if v, ok := s.deps.Settings.GetInt64(settings.KeyPwdRequireClasses); ok && v >= 1 && v <= 3 {
		p.RequireClasses = int(v)
	}
	if v, ok := s.deps.Settings.GetBool(settings.KeyPwdDisallowUsername); ok {
		p.DisallowUsername = v
	}
	if v, ok := s.deps.Settings.GetBool(settings.KeyPwdDisallowCommon); ok {
		p.DisallowCommon = v
	}
	return p
}
