// setpass.go 承担 register / reset 流的 set_password 步执行
// （docs/接口文档.md §2.3 行 448-451、§2.4 行 466-469、§10.3/§10.4 行 1521-1532；
// docs/后端架构.md §7.4 行 1019-1026）。建号 / 改密的写入经窄接口注入；
// reset 成功后递增 epoch 并同步 al:pwdep:{uid}、异步写审计；两者成功后均复用
// Terminal 直接登录（§10.3 行 1527；§10.4 行 1532「同 10.3」）。
package orchestrator

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/settings"
)

// usernameRE 用户名规则 ^[A-Za-z0-9_]{5,20}$（§2.3 行 449 唯一定义处，
// 设置后不可改）。
var usernameRE = regexp.MustCompile(`^[A-Za-z0-9_]{5,20}$`)

// credentialKindPassword user_credential.kind=password（§4.2 行 680-684）。
const credentialKindPassword = "password"

// ThirdpartySignup 三方免密建号步的 provider 状态查询与绑定写入子集
//（§12.5 行 1504；实现方 service.Thirdparty，装配层注入——thirdparty 域
// 单一写入口，与 LoginOauth 的 auto_bind 写入共用 CreateBind）。
type ThirdpartySignup interface {
	// SignupState 返回 provider 的 enable_signup（建号开关，§2.7.5 行 678
	// 字段映射）与关联 Union Provider（无关联为空串）。
	SignupState(ctx context.Context, providerKey string) (ThirdpartySignupState, error)
	// CreateBind 写绑定行（+ Union 行同事务，§12.7 行 1548）；命中
	// uk_provider_openid 返回 repo.ErrBindDuplicate（判别归调用方）。
	CreateBind(ctx context.Context, b *model.UserThirdpartyBind, unionProviderKey, unionID string) error
}

// ThirdpartySignupState SignupState 的产物。
type ThirdpartySignupState struct {
	Enabled  bool
	UnionKey string
}

// SetPassDeps set_password 步的写入依赖（EngineDeps.SetPass，装配层注入）。
type SetPassDeps struct {
	Users       SignupUsers
	Credentials SignupCredentials
	Epoch       EpochSync
	Audit       ResetAuditSink
	Settings    SettingsReader
	// Thirdparty 三方免密建号（§12.5 行 1501-1505）：nil 时 tp 非空的
	// set_password 一律 failed（生产必注入）。
	Thirdparty ThirdpartySignup
	Now        func() time.Time
}

// SignupUsers 建号 / 改密所需的用户读写子集。factor.UserRepo 只暴露
// 读方法，本包按 §3.8 窄接口声明所需子集由装配方注入（repo.UserRepo 天然
// 满足；password 因子的 FindByUsername 子集接口同款先例，不改公共接口）。
// 建号经 CreateWithCredential 同事务完成（§7.4 行 1025），不单独暴露
// user 表 Create。
type SignupUsers interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	FindByUsername(ctx context.Context, username string) (*model.User, error)
	FindByPhone(ctx context.Context, phone string) (*model.User, error)
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	CreateWithCredential(ctx context.Context, u *model.User, c *model.UserCredential) error
	IncEpoch(ctx context.Context, id int64) (int16, error)
}

// SignupCredentials 密码凭证读写子集（repo.CredentialRepo 天然满足）。
type SignupCredentials interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
	Create(ctx context.Context, c *model.UserCredential) error
	Update(ctx context.Context, c *model.UserCredential) error
}

// EpochSync 改密后同步 al:pwdep:{uid}（cache.EpochStore.Sync，最小增量，
// §5.1 行 850、TTL 24h）。
type EpochSync interface {
	Sync(ctx context.Context, uid int64, epoch int16) error
}

// ResetAuditSink 重置密码异步审计（复用 eventlog 既有任务形态：
// EventResetPassword + DetailPwdEpoch，§7.4 行 1026；装配层接线）。
type ResetAuditSink interface {
	RecordReset(ctx context.Context, uid int64, epoch int16, amr []string)
}

// setPassword 执行 set_password 步（§1.4 行 165：注册 / 重置专用）。
func (e *Engine) setPassword(ctx context.Context, flow string, req Request, p *token.LoginTokenPayload, d *Dispatched) *ssov1.LoginFlowResponse {
	sp := e.setpass
	if sp == nil || sp.Users == nil || sp.Credentials == nil {
		return failed()
	}
	if flow == "register" {
		return e.setPassRegister(ctx, sp, req, p, d.Kind)
	}
	return e.setPassReset(ctx, sp, req, p)
}

// setPassRegister 建号（§2.3 行 448-451）：username 规则与占用校验 →
// 密码策略 → 建号（user + password credential 在同一事务内写入，§7.4 行
// 1025，hash 复用 security 既有口径）→ terminal.Complete 直接登录。
// login_token.tp 非空（三方免密建号，§12.5 行 1501-1505：flow 保持 login、
// 由 Register 端点接受）改走 setPassThirdparty：仅收 username、忽略 password。
func (e *Engine) setPassRegister(ctx context.Context, sp *SetPassDeps, req Request, p *token.LoginTokenPayload, kind factor.FactorKind) *ssov1.LoginFlowResponse {
	if tp := p.GetTp(); tp != nil && p.GetFlow() == "login" {
		return e.setPassThirdparty(ctx, sp, req, p, tp)
	}
	username, password := "", ""
	if req.Payload != nil {
		username = strings.TrimSpace(req.Payload.Username)
		password = req.Payload.Password
	}
	if username == "" || password == "" {
		return &ssov1.LoginFlowResponse{Status: StatusInvalidRequest}
	}
	// 用户名规则违规 → invalid_request（§2.3 行 449 唯一定义处）。
	if !usernameRE.MatchString(username) {
		return &ssov1.LoginFlowResponse{Status: StatusInvalidRequest}
	}
	// 用户名占用 → username_taken（§1.6 行 256）。
	if _, err := sp.Users.FindByUsername(ctx, username); err == nil {
		return &ssov1.LoginFlowResponse{Status: StatusUsernameTaken}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return failed()
	}

	// 注册目标来自 challenge 的 ch.target（otp 注册把 email / phone 建进
	// user 表并置 verified=1——验证码验过即已证明归属；password 直通无
	// challenge，ch 为 nil）。login flow 的绑定中间态 token（§7.4）同走此处。
	var phone, email string
	if target := p.GetCh().GetTarget(); target != "" {
		switch kind {
		case factor.FactorOTPSMS:
			phone = target
		case factor.FactorOTPEmail:
			email = target
		}
	}
	// 注册目标（email / phone）占用于他人 → target_taken（§1.6 行 256）。
	if email != "" {
		if _, err := sp.Users.FindByEmail(ctx, email); err == nil {
			return &ssov1.LoginFlowResponse{Status: StatusTargetTaken}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return failed()
		}
	}
	if phone != "" {
		if _, err := sp.Users.FindByPhone(ctx, phone); err == nil {
			return &ssov1.LoginFlowResponse{Status: StatusTargetTaken}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return failed()
		}
	}

	// 密码策略 → password_weak（§1.6 行 255、§5.6；策略来源沿用 settings
	// pwd_* 键既有口径，每次校验现读保证热更新）。
	if vs := security.ValidatePassword(sp.policy(), username, email, password); len(vs) > 0 {
		return &ssov1.LoginFlowResponse{Status: StatusPasswordWeak}
	}

	u := &model.User{Username: username}
	if phone != "" {
		u.Phone, u.PhoneVerified = &phone, 1
	}
	if email != "" {
		u.Email, u.EmailVerified = &email, 1
	}
	// 建号写入在同一事务内完成（§7.4 行 1025）：user + password credential
	// 两条 INSERT 单事务，credential 失败整体回滚，不留无凭证 user 行。
	cred, err := sp.passwordCredential(password)
	if err != nil {
		return failed()
	}
	if err := sp.Users.CreateWithCredential(ctx, u, cred); err != nil {
		// 预查与建号之间的竞态窗口由唯一键兜底（§4.2 uk_username /
		// uk_phone / uk_email）。
		if errors.Is(err, repo.ErrUserDuplicate) {
			return &ssov1.LoginFlowResponse{Status: StatusUsernameTaken}
		}
		return failed()
	}

	// 成功 → 直接登录写 Cookie（§10.3 行 1527；amr 补记本步因子——直通入口
	// 未经过 verify，本步因子不进 amr 会使 login_success 事件 amr 恒空，
	// 此处补齐；otp 注册 amr 已含该因子，appendOnce 幂等）。
	p.Uid = u.ID
	p.Ch = nil
	p.Amr = appendOnce(p.Amr, string(kind))
	return e.completeSuccess(ctx, req, p)
}

// setPassThirdparty 三方免密建号（§12.5 行 1501-1505、§2.7.5 行 685：
// tp 非空时 set_password 仅提交 username，服务端忽略 password）：
// provider enable_signup 校验（§12.5 行 1504「校验该 Provider 的
// enable_signup=1（否则拒绝）」→ signup_disabled，§1.6 行 257）→ 建号
// （仅 user 行、无 credential，CreateWithCredential nil 分支）→ 写 bind +
// Union 行（同事务，§12.7 行 1548）→ terminal.Complete 直接登录。
// 事务边界此处默认：建号与 bind 分步（bind 失败 tp 仍在 login_token 可
// 重试），Union 行与 bind 同事务（CreateBind 内单 tx），待复核。
func (e *Engine) setPassThirdparty(ctx context.Context, sp *SetPassDeps, req Request, p *token.LoginTokenPayload, tp *token.ThirdParty) *ssov1.LoginFlowResponse {
	if sp.Thirdparty == nil {
		return failed()
	}
	username := ""
	if req.Payload != nil {
		username = strings.TrimSpace(req.Payload.Username)
	}
	// 仅收 username；password 忽略（§2.7.5 行 685）——带不带、带什么都不参与。
	if username == "" {
		return &ssov1.LoginFlowResponse{Status: StatusInvalidRequest}
	}
	if !usernameRE.MatchString(username) {
		return &ssov1.LoginFlowResponse{Status: StatusInvalidRequest}
	}
	if _, err := sp.Users.FindByUsername(ctx, username); err == nil {
		return &ssov1.LoginFlowResponse{Status: StatusUsernameTaken}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return failed()
	}

	// provider enable_signup=1 才允许建号（§12.5 行 1504；provider 不存在 /
	// 已禁用同拒——tp 载荷经服务端加密签发，正常流不会指向失效 provider，
	// 管理端禁用后的在途 token 走此口径收敛）。
	state, err := sp.Thirdparty.SignupState(ctx, tp.GetProviderKey())
	if err != nil {
		return failed()
	}
	if !state.Enabled {
		return &ssov1.LoginFlowResponse{Status: StatusSignupDisabled}
	}

	// 免密建号：仅建 user 行（无 password credential——用户可后置走
	// ResetPassword 的「无行补建」分支设置密码）。
	u := &model.User{Username: username}
	if err := sp.Users.CreateWithCredential(ctx, u, nil); err != nil {
		if errors.Is(err, repo.ErrUserDuplicate) {
			return &ssov1.LoginFlowResponse{Status: StatusUsernameTaken}
		}
		return failed()
	}

	// 写绑定（+ Union 行同事务）；失败时 tp 仍在 login_token，前端可带
	// 原 token 重试（默认分步边界；重试命中已建 username →
	// username_taken 收敛，人工路径走安全中心绑定）。
	if err := sp.Thirdparty.CreateBind(ctx, &model.UserThirdpartyBind{
		UserID:      u.ID,
		ProviderKey: tp.GetProviderKey(),
		OpenID:      tp.GetOpenId(),
		Nickname:    tp.GetNickname(),
		AvatarURL:   tp.GetAvatarUrl(),
	}, state.UnionKey, tp.GetUnionId()); err != nil {
		if errors.Is(err, repo.ErrBindDuplicate) {
			return &ssov1.LoginFlowResponse{Status: StatusTargetTaken}
		}
		return failed()
	}

	// 成功 → 直接登录（§10.3 行 1527 同构；amr 已含 thirdparty）。
	p.Uid = u.ID
	p.Ch = nil
	return e.completeSuccess(ctx, req, p)
}

// setPassReset 改密（§2.4 行 466-469、§10.4 行 1532）：密码策略 →
// credential 更新 → epoch 递增 + al:pwdep 同步 → 异步审计 → 直接登录。
func (e *Engine) setPassReset(ctx context.Context, sp *SetPassDeps, req Request, p *token.LoginTokenPayload) *ssov1.LoginFlowResponse {
	password := ""
	if req.Payload != nil {
		password = req.Payload.Password
	}
	if password == "" {
		return &ssov1.LoginFlowResponse{Status: StatusInvalidRequest}
	}
	// dispatch 已要求 otp 验后（login_token.uid 为 challenge 目标反查的用户），
	// 此处防御性兜底。
	uid := p.GetUid()
	if uid == 0 {
		return failed()
	}
	user, err := sp.Users.FindByID(ctx, uid)
	if err != nil {
		return failed()
	}
	email := ""
	if user.Email != nil {
		email = *user.Email
	}
	if vs := security.ValidatePassword(sp.policy(), user.Username, email, password); len(vs) > 0 {
		return &ssov1.LoginFlowResponse{Status: StatusPasswordWeak}
	}

	// credential 更新：FindByUserAndKind(password) + Update（§4.2 行 681
	// 改密 = UPDATE 这一行）。无 password 行（如三方免密建号后走重置）时
	// 按「设置密码」同构建行——docs 未明说该分支（§2.4 行 461 前提是已设置
	// 密码），默认口径，待定。
	cred, err := sp.Credentials.FindByUserAndKind(ctx, uid, credentialKindPassword)
	switch {
	case err == nil:
		if err := sp.writeCredential(ctx, uid, password, cred); err != nil {
			return failed()
		}
	case errors.Is(err, gorm.ErrRecordNotFound):
		if err := sp.writeCredential(ctx, uid, password, nil); err != nil {
			return failed()
		}
	default:
		return failed()
	}

	// epoch 递增 + al:pwdep:{uid} 同步（§10.4 行 1532：全部会话与已颁发
	// 令牌失效；§5.1 行 850）。同步失败即 failed（DB 密码已改，重试幂等）。
	epoch, err := sp.Users.IncEpoch(ctx, uid)
	if err != nil {
		return failed()
	}
	if sp.Epoch != nil {
		if err := sp.Epoch.Sync(ctx, uid, epoch); err != nil {
			return failed()
		}
	}
	// 异步审计（§7.4 行 1026），不阻塞响应。
	if sp.Audit != nil {
		sp.Audit.RecordReset(ctx, uid, epoch, append([]string(nil), p.GetAmr()...))
	}

	// 成功 → 直接登录（§10.4「同 10.3」——docs 未明说 reset 是否写 Cookie，
	// 默认同构 success，待定）。
	p.Ch = nil
	return e.completeSuccess(ctx, req, p)
}

// passwordCredential 构造新 password 凭证行（hash 复用 security.HashPassword，
// argon2id PHC 串，§8.1，不自造）：register 建号传入 CreateWithCredential 由
// 事务内 user INSERT 回填的自增 ID 关联（§7.4 行 1025）；reset 无行补建经
// writeCredential 补 UserID。
func (sp *SetPassDeps) passwordCredential(password string) (*model.UserCredential, error) {
	hash, err := security.HashPassword(password)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if sp.Now != nil {
		now = sp.Now()
	}
	return &model.UserCredential{
		Kind:       credentialKindPassword,
		Secret:     []byte(hash),
		IsEnabled:  1,
		UpdatedAt:  now,
	}, nil
}

// writeCredential 写入密码凭证：existing 非空走 Update（整行可变列，
// updated_at 由本方法传入），为空走 Create（仅 reset 无 password 行补建——
// uid 已存在不属建号；register 建号已改走 CreateWithCredential 同事务，
// §7.4 行 1025）。hash 复用 security.HashPassword（argon2id PHC 串，§8.1），
// 不自造。
func (sp *SetPassDeps) writeCredential(ctx context.Context, uid int64, password string, existing *model.UserCredential) error {
	c, err := sp.passwordCredential(password)
	if err != nil {
		return err
	}
	if existing != nil {
		existing.Secret = c.Secret
		existing.IsEnabled = c.IsEnabled
		existing.UpdatedAt = c.UpdatedAt
		return sp.Credentials.Update(ctx, existing)
	}
	c.UserID = uid
	return sp.Credentials.Create(ctx, c)
}

// policy 从 settings 现读 pwd_* 五键构造策略（§5.6 键为唯一定义处；越界 /
// 缺失回落 security 默认档，与 setup / password 因子的既有口径一致）。
func (sp *SetPassDeps) policy() security.PasswordPolicy {
	p := security.DefaultPasswordPolicy()
	if sp == nil || sp.Settings == nil {
		return p
	}
	if v, ok := sp.Settings.GetInt64(settings.KeyPwdMinLength); ok && v > 0 {
		p.MinLength = int(v)
	}
	if v, ok := sp.Settings.GetInt64(settings.KeyPwdMaxLength); ok && v > 0 {
		p.MaxLength = int(v)
	}
	if v, ok := sp.Settings.GetInt64(settings.KeyPwdRequireClasses); ok && v >= 1 && v <= 3 {
		p.RequireClasses = int(v)
	}
	if v, ok := sp.Settings.GetBool(settings.KeyPwdDisallowUsername); ok {
		p.DisallowUsername = v
	}
	if v, ok := sp.Settings.GetBool(settings.KeyPwdDisallowCommon); ok {
		p.DisallowCommon = v
	}
	return p
}

// setPasswordForm 构造 verify 通过后 set_password 步的渲染信息（§1.4 行 165
// 渲染 kind=form；§2.3 行 448-449 register 提交 username + password、
// §2.4 行 467 reset 仅 password）。
func setPasswordForm(flow string) *factor.StepResult {
	fields := []factor.Field{
		{Name: "password", Label: "密码", Type: "password", Required: true},
	}
	if flow == "register" {
		fields = append([]factor.Field{{
			Name: "username", Label: "用户名", Type: "text", Required: true, Length: 20,
		}}, fields...)
	}
	return &factor.StepResult{Kind: factor.StepForm, Fields: fields}
}
