// Package account 实现 api.account.v1.AccountService 的 Connect handler
// （docs/后端架构.md §3.4 行 332：account 域方法族，全部需会话）。已落地
// GetProfile 与 GetConfig（四件全量下发：avatarUpload / mfaPolicy /
// captcha / hasPassword，接口文档 §3.2 行 818-847）及三方绑定族四
// 方法（GetThirdpartyBindings / UnbindThirdparty / ThirdpartyOauth /
// GetThirdpartyTicket，§3.7 / §3.7.1——编排全部在 service/account，本层只做
// 请求绑定、Cookie 头解析、信封透传与 Connect 形态映射）；其余方法一律由
// 生成的 UnimplementedAccountServiceHandler 返回 unimplemented（不自造错误
// 信封）。
package account

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"gorm.io/gorm"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/gen/go/api/account/v1/accountv1connect"
	commonv1 "authloft/gen/go/api/common/v1"
	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/internal/captcha"
	internalconnect "authloft/internal/connect"
	"authloft/internal/dto"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/service"
	accountsvc "authloft/internal/service/account"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// UserReader account 域用户读取窄接口（§20 依赖注入）：生产注入
// *repo.UserRepo（FindByID / GetProfile 均已有，不扩公共接口），测试可传 fake。
type UserReader interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	GetProfile(ctx context.Context, userID int64) (*model.UserProfile, error)
}

// CredentialReader account 域凭证读取窄接口（§20）：生产注入
// *repo.CredentialRepo（FindByUserAndKind 已有，不扩公共接口），
// hasPassword / mfaPolicy / mfa 绑定态共用。
type CredentialReader interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
}

// SettingsReader account 域 settings 读取窄接口（§20）：生产注入
// *settings.Store（GetBool / GetString 已有）。
type SettingsReader interface {
	GetBool(key string) (bool, bool)
	GetString(key string) (string, bool)
}

// ProviderReader account 域 provider 行读取窄接口（§20）：生产注入
// *repo.ProviderRepo（FindByKey 已有），avatarUpload 的 storage 行查询。
type ProviderReader interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
}

// CaptchaConfiger captcha 当前生效配置出口（后端架构 §9.1 行 1094：
// 注入快照 / GetConfig / 触发响应三处共用同一出口，每次现算不缓存）：
// 生产注入 *captcha.Gate（nil Gate 的 Config 走 builtin 降级）。
type CaptchaConfiger interface {
	Config(ctx context.Context) captcha.Config
}

// Thirdparty 三方绑定族 service 窄接口（§20 依赖注入）：生产注入
// *accountsvc.ThirdpartyService，测试可传 fake；nil（未装配）时四个方法
// 返回 unimplemented。
type Thirdparty interface {
	GetThirdpartyBindings(ctx context.Context, uid int64) (*accountsvc.BindingsResult, error)
	UnbindThirdparty(ctx context.Context, uid int64, providerKey string) error
	ThirdpartyOauth(ctx context.Context, in accountsvc.OauthInput) (*accountsvc.BindOutcome, error)
	GetThirdpartyTicket(ctx context.Context, in accountsvc.TicketInput) *ssov1.LoginFlowResponse
}

// 线上错误文案：connect.Error 文本直达客户端，一律不携带内部信息
// （口径同 internal/connect interceptors.go）。
var (
	errAuthRequired = errors.New("authentication required")
	errNotFound     = errors.New("not found")
	// errThirdpartyNotConfigured 未装配三方绑定 service（测试桩）。
	errThirdpartyNotConfigured = errors.New("thirdparty service not configured")
	// errThirdpartyInternal 未知异常的固定文案（§1.5：不暴露内部信息；
	// §1.6 行 273 internal 无 ErrorInfo）。
	errThirdpartyInternal = errors.New("internal error")
)

// Handler AccountService 服务实现。内嵌生成的 unimplemented 基类：本包未
// 实现的方法统一返回 Connect CodeUnimplemented。
type Handler struct {
	accountv1connect.UnimplementedAccountServiceHandler
	users      UserReader
	creds      CredentialReader
	settings   SettingsReader
	providers  ProviderReader
	captcha    CaptchaConfiger
	thirdparty Thirdparty
}

// New 构造 AccountService handler。thirdparty 为三方绑定族 service；
// 测试 / 未装配时传 nil（四方法返回 unimplemented）。
func New(users UserReader, creds CredentialReader, settings SettingsReader, providers ProviderReader, captcha CaptchaConfiger, thirdparty Thirdparty) *Handler {
	return &Handler{users: users, creds: creds, settings: settings, providers: providers, captcha: captcha, thirdparty: thirdparty}
}

// GetProfile（接口文档 §3.1 行 774-813 / §3.2 行 820）：从会话取 uid → 读
// user + user_profile → 按 §3.1 统一结构与服务端掩码输出（组装在
// dto.AccountProfile）。会话要求（§1.2 行 96）：本域全接口需 al_session；
// session 拦截器对无 / 无效令牌放行匿名（既定语义），故 ctx 无 uid
// 即 unauthenticated（HTTP 401）。user_profile 行缺失输出零值 profile
// 消息，不视为错误；用户不存在返回 not_found。
func (h *Handler) GetProfile(ctx context.Context, req *connect.Request[accountv1.GetProfileRequest]) (*connect.Response[accountv1.ProfileResponse], error) {
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	user, err := h.users.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errNotFound)
		}
		return nil, fmt.Errorf("account handler: load user: %w", err)
	}
	profile, err := h.users.GetProfile(ctx, uid)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("account handler: load profile: %w", err)
	}
	return connect.NewResponse(dto.AccountProfile(user, profile)), nil
}

// GetConfig（接口文档 §3.2 行 818-847）：account entry 的配置读取处，
// 四件全量下发——avatarUpload（settings avatar_storage_provider →
// provider 表 storage 生效行 Ext 投影）、mfaPolicy（mfa_setting 行摘要）、
// captcha（Gate 现算公开视图，无凭证）、hasPassword（kind=password 且
// is_enabled=1）。鉴权同 GetProfile：session 拦截器放行匿名（既定语义），
// ctx 无 uid 即 unauthenticated。
func (h *Handler) GetConfig(ctx context.Context, req *connect.Request[accountv1.GetConfigRequest]) (*connect.Response[accountv1.AccountConfigResponse], error) {
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	user, err := h.users.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errNotFound)
		}
		return nil, fmt.Errorf("account handler: load user: %w", err)
	}

	avatar, err := h.avatarUpload(ctx)
	if err != nil {
		return nil, err
	}
	mfa, err := h.mfaPolicy(ctx, uid, user)
	if err != nil {
		return nil, err
	}
	hasPassword, err := h.hasPassword(ctx, uid)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accountv1.AccountConfigResponse{
		AvatarUpload: avatar,
		MfaPolicy:    mfa,
		Captcha:      h.captchaConfig(ctx),
		HasPassword:  hasPassword,
	}), nil
}

// avatarUpload 组装 avatarUpload 投影：settings 键 avatar_storage_provider
// （§5.6 行 1337）→ provider 表 category=storage 生效行 → Ext{mode,maxSize,
// allowedTypes}（§5.3 storage 扩展字段，行 1237）。未配置（空串 / 查无该行 /
// is_enabled=0 / category≠storage）→ 零值投影（行 826），投影逻辑在
// dto.AccountAvatarUpload；local 配置 direct 回退 proxy（行 825、§15.1）。
// 基础设施错误（含 ext 解析失败）上抛，按未知异常映射 internal（行 826）。
func (h *Handler) avatarUpload(ctx context.Context) (*accountv1.AvatarUploadConfig, error) {
	key := ""
	if h.settings != nil {
		key, _ = h.settings.GetString(settings.KeyAvatarStorageProvider)
	}
	if key == "" {
		return dto.AccountAvatarUpload("", nil), nil
	}
	row, err := h.providers.FindByKey(ctx, key)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return dto.AccountAvatarUpload("", nil), nil
		}
		return nil, fmt.Errorf("account handler: load avatar storage provider: %w", err)
	}
	if row.Category != providerCategoryStorage || row.IsEnabled != 1 {
		return dto.AccountAvatarUpload("", nil), nil
	}
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		return nil, fmt.Errorf("account handler: parse avatar storage provider ext: %w", err)
	}
	return dto.AccountAvatarUpload(row.Type, ext), nil
}

// providerCategoryStorage provider 表 category=storage（§5.3 行 1237
// storage 类；avatarUpload 只认 storage 行）。
const providerCategoryStorage = "storage"

// credential kind 取值（后端架构 §4.2 行 667 kind 枚举：password|totp|
// webauthn|recovery_code|mfa_setting）。
const (
	kindPassword     = "password"
	kindTotp         = "totp"
	kindWebauthn     = "webauthn"
	kindRecoveryCode = "recovery_code"
	kindMfaSetting   = "mfa_setting"
)

// mfaPolicy 组装 mfaPolicy 摘要（§3.2 行 827-847）：enabled=uid 有
// kind=mfa_setting 行（行 846：行存在即顶层 enabled=true，每用户至多
// 一行；is_enabled 语义归写入端 SetMfa，本实现只读）；required=
// settings.mfa_enabled && user.mfa_required==1（mfa_enabled 缺失回落默认
// true，§5.6 行 1322）；trustedDeviceDays 恒 0；methods[] 五因子序投影
// （dto.AccountMfaPolicy）。mfa_setting 行读取 = FindByUserAndKind +
// UnmarshalCredentialMeta 反序列化取 MfaMethods（repo 现有能力，不扩接口）。
func (h *Handler) mfaPolicy(ctx context.Context, uid int64, user *model.User) (*accountv1.MfaPolicy, error) {
	mfaEnabled := true
	if h.settings != nil {
		if v, ok := h.settings.GetBool(settings.KeyMfaEnabled); ok {
			mfaEnabled = v
		}
	}
	required := mfaEnabled && user.MfaRequired == 1

	var (
		enabled        bool
		enabledMethods []string
	)
	row, err := h.creds.FindByUserAndKind(ctx, uid, kindMfaSetting)
	switch {
	case err == nil:
		enabled = true
		meta, err := repo.UnmarshalCredentialMeta(row.Meta)
		if err != nil {
			return nil, fmt.Errorf("account handler: decode mfa_setting meta: %w", err)
		}
		enabledMethods = meta.GetMfaMethods()
	case errors.Is(err, gorm.ErrRecordNotFound):
		// 行不存在 = 未开启两步验证（行 846）。
	default:
		return nil, fmt.Errorf("account handler: load mfa_setting: %w", err)
	}

	bound, err := h.mfaBound(ctx, uid, user)
	if err != nil {
		return nil, err
	}
	return dto.AccountMfaPolicy(enabled, enabledMethods, required, bound), nil
}

// mfaBound 各因子绑定态（§3.2 行 836-840 bound 仅布尔投影，明细归 §3.5
// GetMfa）：totp / webauthn / recovery_code 走 user_credential 行（存在且
// is_enabled=1；recovery_code 需 meta 余量非空——删空写回空数组等价该 kind
// 不可用，后端架构 §4.2 行 697）；otp_sms / otp_email 走 user.phone /
// email 非空（OTP 因子无凭证行，目标即绑定）。
func (h *Handler) mfaBound(ctx context.Context, uid int64, user *model.User) (dto.MfaBound, error) {
	var bound dto.MfaBound

	totp, err := h.creds.FindByUserAndKind(ctx, uid, kindTotp)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return bound, fmt.Errorf("account handler: load totp credential: %w", err)
	}
	bound.Totp = err == nil && totp.IsEnabled == 1

	webauthn, err := h.creds.FindByUserAndKind(ctx, uid, kindWebauthn)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return bound, fmt.Errorf("account handler: load webauthn credential: %w", err)
	}
	bound.Webauthn = err == nil && webauthn.IsEnabled == 1

	recovery, err := h.creds.FindByUserAndKind(ctx, uid, kindRecoveryCode)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return bound, fmt.Errorf("account handler: load recovery_code credential: %w", err)
	}
	if err == nil && recovery.IsEnabled == 1 {
		meta, err := repo.UnmarshalCredentialMeta(recovery.Meta)
		if err != nil {
			return bound, fmt.Errorf("account handler: decode recovery_code meta: %w", err)
		}
		bound.RecoveryCode = len(meta.GetRecoveryCodes()) > 0
	}

	bound.OtpSms = user.Phone != nil && *user.Phone != ""
	bound.OtpEmail = user.Email != nil && *user.Email != ""
	return bound, nil
}

// hasPassword 当前用户是否存在 kind=password 且 is_enabled=1 的凭证
// （§3.2 行 818：供安全中心判断改密入口与第三方解绑是否可用，§3.7 判定
// 口径）。行不存在 / 已停用均返回 false，不视为错误。
func (h *Handler) hasPassword(ctx context.Context, uid int64) (bool, error) {
	row, err := h.creds.FindByUserAndKind(ctx, uid, kindPassword)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("account handler: load password credential: %w", err)
	}
	return row.IsEnabled == 1, nil
}

// captchaConfig captcha 公开视图（§3.2 行 818：经公开视图消息输出，不含
// 凭证）：Gate 现算保降级一致（§9.1 行 1094 三处共用出口）；未注入时按
// (*captcha.Gate).Config 的 nil 分支降级内置图形码。
func (h *Handler) captchaConfig(ctx context.Context) *commonv1.CaptchaConfig {
	if h.captcha == nil {
		return &commonv1.CaptchaConfig{
			ProviderKey: captcha.BuiltinProviderKey,
			Type:        captcha.TypeImage,
		}
	}
	cfg := h.captcha.Config(ctx)
	return &commonv1.CaptchaConfig{
		ProviderKey: cfg.ProviderKey,
		Type:        cfg.Type,
		SiteKey:     cfg.SiteKey,
	}
}

// —— 三方绑定族四方法（接口文档 §3.7 / §3.7.1）——
// 请求绑定、Cookie 头解析与信封透传归本层，绑定编排全部在
// service/account.ThirdpartyService（§12.6 BindToCurrentUser 内核两通道共用）。
// GetThirdpartyBindings / UnbindThirdparty / ThirdpartyOauth 的业务失败走
// 可判别哨兵错误 → Connect 错误体 + ErrorInfo（§1.5 行 198-211）；GetThirdpartyTicket
// 的轮询结论走 HTTP 200 信封域（§1.3 / §1.6），透传 service 产物。四接口
// 均需 al_session（§1.2 行 96；session 拦截器放行匿名，ctx 无 uid 即 401）。

// GetThirdpartyBindings 双列表（§3.7 行 953-959）：items 已绑定 + available
// 可绑定，投影在 handler（service 返回领域结构体）。
func (h *Handler) GetThirdpartyBindings(ctx context.Context, req *connect.Request[accountv1.GetThirdpartyBindingsRequest]) (*connect.Response[accountv1.ThirdpartyBindingsResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	res, err := h.thirdparty.GetThirdpartyBindings(ctx, uid)
	if err != nil {
		return nil, mapThirdpartyError("get thirdparty bindings", err)
	}
	items := make([]*accountv1.ThirdpartyBinding, len(res.Items))
	for i := range res.Items {
		it := &res.Items[i]
		items[i] = &accountv1.ThirdpartyBinding{
			ProviderKey: it.ProviderKey,
			DisplayName: it.DisplayName,
			Type:        it.Type,
			Channel:     it.Channel,
			Icon:        it.Icon,
			CreatedAt:   it.CreatedAt,
		}
	}
	available := make([]*accountv1.ThirdpartyOption, len(res.Available))
	for i := range res.Available {
		op := &res.Available[i]
		available[i] = &accountv1.ThirdpartyOption{
			ProviderKey: op.ProviderKey,
			DisplayName: op.DisplayName,
			Type:        op.Type,
			Channel:     op.Channel,
			Icon:        op.Icon,
			UiGroup:     op.UiGroup,
			SortOrder:   op.SortOrder,
		}
	}
	return connect.NewResponse(&accountv1.ThirdpartyBindingsResponse{
		Items:     items,
		Available: available,
	}), nil
}

// UnbindThirdparty 解绑（§3.7 行 954）：成功为空响应（OkResponse）。
func (h *Handler) UnbindThirdparty(ctx context.Context, req *connect.Request[accountv1.UnbindThirdpartyRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.thirdparty.UnbindThirdparty(ctx, uid, req.Msg.GetProviderKey()); err != nil {
		return nil, mapThirdpartyError("unbind thirdparty", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// ThirdpartyOauth redirect 绑定回调落地（§3.7.1 A 行 969-1003）：请求 Cookie
// 头解出 al_login_state 交 service 载体校验；成功 {providerKey, displayName}。
// 本接口不返回登录信封、不签发 login_token、不 Set-Cookie、不重建会话
// （行 1000——绑定不改变登录态）。
func (h *Handler) ThirdpartyOauth(ctx context.Context, req *connect.Request[accountv1.ThirdpartyOauthRequest]) (*connect.Response[accountv1.ThirdpartyOauthResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	out, err := h.thirdparty.ThirdpartyOauth(ctx, accountsvc.OauthInput{
		ProviderKey: req.Msg.GetProviderKey(),
		Code:        req.Msg.GetCode(),
		State:       req.Msg.GetState(),
		StateCookie: loginStateCookie(req),
		UID:         uid,
	})
	if err != nil {
		return nil, mapThirdpartyError("thirdparty oauth", err)
	}
	return connect.NewResponse(&accountv1.ThirdpartyOauthResponse{
		ProviderKey: out.ProviderKey,
		DisplayName: out.DisplayName,
	}), nil
}

// GetThirdpartyTicket 扫码绑定长轮询（§3.7.1 B 行 1012-1026）：响应复用
// 登录流程信封（§1.3 行 152-155），轮询结论（pending / scanned / expired /
// success / 失败类）走 HTTP 200 信封域原样透传。不签发 login_token、不
// Set-Cookie、不重建会话（行 1049）。
func (h *Handler) GetThirdpartyTicket(ctx context.Context, req *connect.Request[accountv1.GetThirdpartyTicketRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	resp := h.thirdparty.GetThirdpartyTicket(ctx, accountsvc.TicketInput{
		Ticket: req.Msg.GetTicket(),
		Poll:   req.Msg.GetPoll(),
		UID:    uid,
	})
	return connect.NewResponse(resp), nil
}

// loginStateCookie 从请求 Cookie 头解析 al_login_state（§3.7.1 A redirect
// 绑定通道的载体校验源；与 handler/sso 同款私有助手——跨包复用需导出 sso
// 层，按既有分工各落一份）；未携带返回空串。
func loginStateCookie(req *connect.Request[accountv1.ThirdpartyOauthRequest]) string {
	cookies, err := http.ParseCookie(req.Header().Get("Cookie"))
	if err != nil {
		return ""
	}
	for _, ck := range cookies {
		if ck.Name == service.LoginStateCookieName {
			return ck.Value
		}
	}
	return ""
}

// mapThirdpartyError 三方绑定族 service 错误 → Connect 形态（§1.5 行 182-195
// 统一口径）：参数 / 校验类 → invalid_argument + ErrorInfo domain=account
// （code 取 §1.6 封闭集）；target_taken → already_exists（409，§1.5 行 191
// 「重复绑定」）；资源不存在 → not_found；上游 / 内部故障 → internal 固定文案
// （§1.6 行 273：internal 不挂 ErrorInfo）；其余原样上抛由错误包装拦截器消毒。
func mapThirdpartyError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, accountsvc.ErrInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid request"),
		)
	case errors.Is(err, accountsvc.ErrStateMismatch):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "state_mismatch", "state mismatch"),
		)
	case errors.Is(err, accountsvc.ErrProviderDisabled):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "provider_disabled", "provider not available for binding"),
		)
	case errors.Is(err, accountsvc.ErrTargetTaken):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeAlreadyExists, err),
			internalconnect.NewErrorInfo("account", "target_taken", "该账号已被其他账号绑定"),
		)
	case errors.Is(err, accountsvc.ErrFailed):
		return connect.NewError(connect.CodeInternal, errThirdpartyInternal)
	case errors.Is(err, gorm.ErrRecordNotFound):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}
