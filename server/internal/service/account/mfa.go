// mfa.go account 域两步验证族业务层（docs/接口文档.md §3.5 行 900-927、
// §3.2 行 844-864、docs/后端架构.md §8.4 行 1079-1084、§8.3 行 1071-1075）。
//
// 职责边界（四方法实装）：
//   - GetMfa：五因子绑定明细（§3.5 行 907-915）+recoveryIssuedAt。数据源：
//     totp / recovery_code 走 CredentialRepo.FindByUserAndKind（bound = 行存在
//     且 is_enabled=1；recovery_code 另需 meta 余量非空——删空写回空数组等价
//     该 kind 不可用，后端架构 §4.2 行 697，与 handler mfaBound 同口径）；otp_sms /
//     otp_email 走 user 资料（bound = phone/email 非空，与 handler GetConfig
//     §3.2 摘要 bound 同口径——摘要与明细是同一绑定概念的两处投影，取值必须
//     一致；掩码算法与 dto / oidc 同名实现同款，跨包私有按
//     §3.5「各落一份」先例本包各落一份；OTP 因子无凭证行 → lastUsedAt 无
//     数据源恒 0）；webauthn 凭据数走 WebauthnRepo.ListByUser，boundAt /
//     lastUsedAt 取 user_credential 行（webauthn 每凭据一行）最早 created_at /
//     最大 last_used_at。
//   - SetMfa：两步验证开关（§3.5）。user.mfa_required 是用户唯一开关列：
//     true 要求系统已开放且存在可用因子（白名单 ∩ 已绑定，判定统一走
//     service/mfapolicy），不满足返回 invalid_request；false 直接写 0。
//     写入只更新 mfa_required 列，不触碰 epoch / 会话与凭据。
//   - BindTotp 两态（行 922-923）：challenge 无状态生成 secret（10 字节
//     crypto/rand → 16 字符 Base32，无填充，factor/totp decodeSecret 同款可
//     解）+ otpauthUrl + qrcodeContent（= otpauthUrl 同串，前端 QrImage 直接
//     编码绘制、空串回退 otpauthUrl，TotpBindDialog.tsx:132 消费口径；issuer
//     为产品名 Authloft，account 段取 username，形状与前端样例
//     account.test.tsx:1088 逐字一致）；verify 用 {secret,code}（challenge 未
//     存服务端状态，secret 由前端回传）做 RFC 6238 HMAC-SHA1 ±1 时间步校验
//     （后端架构 §8.4 行 1081，与 factor/totp 内核同款算法、跨包私有各落
//     一份）；secret / code 格式非法 → invalid_request、码不匹配 →
//     invalid_code（§8.4 行 1083 封闭集）；验证通过 = 绑定生效：upsert
//     kind=totp 行（明文 Base32 存 secret 列，§3.11 行 430 口径；meta 带
//     totp_digits/totp_period，§12.2 kind=totp 段）+ 同一响应重签 10 条恢复码
//     （覆盖即全量作废旧码）。
//   - 原 GetRecoveryCodes 已移除（§3.5）：存量恢复码不再提供回显接口；
//     BindTotp verify 与 RegenerateRecoveryCodes 下发新码是唯一展示渠道。
//   - RegenerateRecoveryCodes：{action:"regenerate"} 全量作废重新下发（行
//     925）。生成/重生成归本层（factor/recovery 只管消费）；要求 recovery_code
//     行存在（「重新生成」针对既有签发，首签归 BindTotp verify），无行 /
//     未启用 → code_expired；createdAt 沿行 created_at（CredentialMeta 无签发
//     时间字段、repo Update 更新集不含 created_at，全量作废仅指码集替换）。
//
// 恢复码字符集与消费口径：8 位 Crockford Base32 小写（无 i/l/o/u，factor/
// recovery 同款字符集），存 8 位存储形、下发展示形 xxxx-xxxx；命中即删不可
// 复用、删空即失效均归 factor/recovery 登录链，本层只生成不消费。
//
// 审计：SetMfa 开启投 enable_mfa、关闭投 disable_mfa（detail={enabled:true|
// false}，§4.6）；BindTotp / RegenerateRecoveryCodes 不投——§4.6 事件枚举无
// totp_bind / 恢复码事件，不自造（webauthn_rename「无枚举成员不自造」同款
// 先例）。
package account

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"database/sql"
	"github.com/vmihailenco/msgpack/v5"

	credentialpb "authloft/gen/go/credential"
	"authloft/internal/eventlog"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/service/mfapolicy"
	"authloft/internal/service/verification"
	"authloft/internal/settings"
)

const (
	// totpStepChallenge / totpStepVerify BindTotp.step 取值（§3.5 行 922-923）。
	totpStepChallenge = "challenge"
	totpStepVerify    = "verify"
	// kindTotp / kindRecoveryCode user_credential.kind 取值（§4.2 枚举；
	// handler/account 同值常量为该包私有，本包各落一份）。
	kindTotp         = "totp"
	kindRecoveryCode = "recovery_code"
	// regenerateAction RegenerateRecoveryCodes.action 固定取值（§3.5 行 925）。
	regenerateAction = "regenerate"
	// setMfaIssuer otpauth label / issuer 参数的产品名（Key URI 规范 issuer
	// 为显示名；前端样例 account.test.tsx:1088「Authloft」同款）。
	setMfaIssuer = "Authloft"
	// totpSecretBytes 绑定链生成密钥长度：10 字节 → 16 字符 Base32
	//（Google Authenticator 惯例，与前端样例长度一致；factor/totp 登录链
	// 校验不限制长度，decodeSecret 任意可解）。
	totpSecretBytes = 10
	// totpStepSeconds / totpSkewSteps / totpCodeLength / totpModulus RFC 6238
	// 校验参数（后端架构 §8.4 行 1081：±1 时间步；factor/totp 内核同值）。
	totpStepSeconds = 30
	totpSkewSteps   = 1
	totpCodeLength  = 6
	totpModulus     = 1_000_000
	// recoveryCodeLength 存储形 8 位、recoveryCodeCount 每批 10 条（§8.4
	// 行 1082、§3.5 行 923「10 个恢复码」）。
	recoveryCodeLength = 8
	recoveryCodeCount  = 10
	// recoveryCodeCharset 8 位 Crockford Base32 小写字符集（无 i/l/o/u，
	// factor/recovery 同款，§4.2 行 686）。
	recoveryCodeCharset = "0123456789abcdefghjkmnpqrstvwxyz"
	// recoveryCodeDedupRetries 批内互异去重的碰撞重生成上限（防退化随机源
	// 死循环；crypto/rand 下碰撞概率 ~45/2^40，上限恒不可达）。
	recoveryCodeDedupRetries = 64
)

// 可判别哨兵错误（handler 转 Connect 错误体 + ErrorInfo，§1.6 封闭集成员；
// ErrMfaInternal 例外——映射 internal 无 ErrorInfo，§1.6 行 273）。
var (
	// ErrMfaUnauthenticated 无有效会话（401）。
	ErrMfaUnauthenticated = errors.New("account mfa: authentication required")
	// ErrMfaInvalidRequest 参数缺失 / step 非法 / 开启前置校验不满足 / 格式非法
	//（§8.4 行 1083「格式非法」）。
	ErrMfaInvalidRequest = errors.New("account mfa: invalid request")
	// ErrMfaInvalidCode 码不匹配（§8.4 行 1083「码不匹配」）。
	ErrMfaInvalidCode = errors.New("account mfa: invalid code")
	// ErrMfaCodeExpired 无该 kind 行 / 未启用 / meta 空（消费尽）/「重新生成」
	// 无既有签发（§8.4 行 1083）。
	ErrMfaCodeExpired = errors.New("account mfa: code expired")
	// ErrMfaInternal 基础设施故障（映射 internal）。
	ErrMfaInternal = errors.New("account mfa: failed")
)

// MfaUserStore user 表读写窄接口（§20）：*repo.UserRepo 天然满足
// （factor.UserRepo 同构；SetMfa 写 mfa_required 列、BindTotpChallenge 读
// username 组 otpauth label）。
type MfaUserStore interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	UpdateMfaRequired(ctx context.Context, id int64, mfaRequired int8) error
}

// MfaCredentialStore user_credential 表读写窄接口（§20）：*repo.CredentialRepo
// 天然满足（FindByUserAndKind / ListByUser / Create / Update /
// DeleteByUserAndKind 均既有；ListByUser 供 webauthn 因子 boundAt /
// lastUsedAt 投影，webauthn.go 同款数据源）。
type MfaCredentialStore interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
	ListByUser(ctx context.Context, userID int64) ([]model.UserCredential, error)
	Create(ctx context.Context, c *model.UserCredential) error
	Update(ctx context.Context, c *model.UserCredential) error
	DeleteByUserAndKind(ctx context.Context, userID int64, kind string) error
}

// MfaWebauthnStore user_credential_webauthn 表读取窄接口（§20）：
// *repo.WebauthnRepo 天然满足（GetMfa webauthn 凭据计数数据源）。
type MfaWebauthnStore interface {
	ListByUser(ctx context.Context, userID int64) ([]model.UserCredentialWebauthn, error)
}

// MfaSettingsReader settings 热更新读取窄接口（§20）：*settings.Store 天然
// 满足。未注入属装配缺陷：开启路径经 mfapolicy 判定时 fail-closed 返回
// ErrMfaInternal；读取器已注入但键缺失时按 §5.6 默认值（mfa_enabled=true）。
type MfaSettingsReader interface {
	GetBool(key string) (bool, bool)
	GetStringSlice(key string) ([]string, bool)
}

// MfaDeps 依赖注入（§20）；装配层构造（bootstrap 接线）。
type MfaDeps struct {
	// Users user 表读写（mfa_required 开关 / otpauth label）。
	Users MfaUserStore
	// Creds user_credential 读写（totp / recovery_code 行）。
	Creds MfaCredentialStore
	// Webauthn user_credential_webauthn 读取（凭据计数）。
	Webauthn MfaWebauthnStore
	// Settings 热更新键读取（mfa_enabled 系统开关 / mfa_methods 白名单）。
	Settings MfaSettingsReader
	// Audit enable_mfa / disable_mfa 审计投递（nil = 跳过，测试用）。
	Audit AuditSink
	// Now 时钟注入（缺省 time.Now）。
	Now func() time.Time
	// Rand 随机源注入（缺省 crypto/rand.Reader；TOTP secret 与恢复码生成）。
	Rand io.Reader
	// Assertions 敏感操作断言消费出口（§16 解绑 TOTP）；nil（未装配）时
	// UnbindTotp 返回基础设施失败，不越过校验解绑。
	Assertions AssertionConsumer
}

// AssertionConsumer 断言消费窄接口（§20 依赖注入）：生产注入
// *verification.Service，测试可传 fake。
type AssertionConsumer interface {
	ConsumeAssertion(ctx context.Context, token string, want verification.Want) (verification.Assertion, error)
}

// MfaService account 域两步验证族业务层。
type MfaService struct {
	deps MfaDeps
	now  func() time.Time
}

// NewMfaService 构造。
func NewMfaService(d MfaDeps) *MfaService {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &MfaService{deps: d, now: now}
}

// compile 时断言生产实现满足各窄接口。
var (
	_ MfaUserStore       = (*repo.UserRepo)(nil)
	_ MfaCredentialStore = (*repo.CredentialRepo)(nil)
	_ MfaWebauthnStore   = (*repo.WebauthnRepo)(nil)
	_ MfaSettingsReader  = (*settings.Store)(nil)
)

// MfaFactorDetail GetMfa 单因子绑定明细（§3.5 行 907-913；不同 factor 只填
// 各自相关字段，零值表示不适用 / 未绑定——MfaFactor proto 注释同款）。
type MfaFactorDetail struct {
	// Factor 因子名（totp｜otp_sms｜otp_email｜webauthn｜recovery_code）。
	Factor string
	// Bound 是否已绑定。
	Bound bool
	// BoundAt 绑定时间，Unix 秒（totp / webauthn；webauthn 多凭据取最早）。
	BoundAt int64
	// LastUsedAt 最近使用时间，Unix 秒（otp_sms / otp_email 无凭证行，
	// 无数据源恒 0）。
	LastUsedAt int64
	// Target otp_sms / otp_email 的掩码目标。
	Target string
	// Credentials webauthn 凭据数量。
	Credentials int64
	// Remaining recovery_code 剩余数量。
	Remaining int64
}

// MfaDetail GetMfa 响应明细（§3.5）：五因子序固定（totp → otp_sms →
// otp_email → webauthn → recovery_code，与 admin 详情同一顺序）+
// recoveryIssuedAt。
type MfaDetail struct {
	Factors []MfaFactorDetail
	// RecoveryIssuedAt 恢复码签发时间，Unix 秒；未签发（无 kind=recovery_code
	// 行）为 0。
	RecoveryIssuedAt int64
}

// TotpChallenge BindTotp step=challenge 产物（§3.5 行 922）。
type TotpChallenge struct {
	// Secret TOTP 密钥（16 字符 Base32，明文存 user_credential.secret）。
	Secret string
	// OtpauthUrl otpauth:// 地址（Key URI 格式：issuer=Authloft、account=
	// username、secret、issuer 参数）。
	OtpauthUrl string
	// QrcodeContent 二维码内容（= OtpauthUrl 同串，前端绘制；空串回退
	// otpauthUrl 的消费口径见文件头注）。
	QrcodeContent string
}

// RecoveryCodesResult RegenerateRecoveryCodes 响应（§3.5 行 925，
// RecoveryCodesResponse proto 同构；与 BindTotp verify 的 recoveryCodes
// 同格式）：codes 为展示形 xxxx-xxxx，createdAt 为签发时间
// （kind=recovery_code 行 created_at）。
type RecoveryCodesResult struct {
	Codes     []string
	CreatedAt int64
}

// GetMfa 两步验证明细（§3.5 行 905-915）。
func (s *MfaService) GetMfa(ctx context.Context, uid int64) (*MfaDetail, error) {
	if uid <= 0 {
		return nil, ErrMfaUnauthenticated
	}
	user, err := s.deps.Users.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: load user: %v", ErrMfaInternal, err)
	}

	// totp：行存在且启用即绑定（handler mfaBound 同口径）；boundAt /
	// lastUsedAt 取凭据行既有列。
	totp := MfaFactorDetail{Factor: kindTotp}
	row, err := s.deps.Creds.FindByUserAndKind(ctx, uid, kindTotp)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: load totp credential: %v", ErrMfaInternal, err)
	}
	if err == nil && row.IsEnabled == 1 {
		totp.Bound = true
		totp.BoundAt = row.CreatedAt.Unix()
		if row.LastUsedAt != nil {
			totp.LastUsedAt = row.LastUsedAt.Unix()
		}
	}

	// otp_sms / otp_email：无凭证行，目标即绑定（handler mfaBound 同口径——
	// phone/email 非空即 bound，与 §3.2 摘要保持一致）；lastUsedAt 无数据
	// 源恒 0（OTP 验证码走 Redis，不留凭据行）。
	sms := MfaFactorDetail{Factor: "otp_sms"}
	if user.Phone != nil && *user.Phone != "" {
		sms.Bound = true
		sms.Target = maskMfaPhone(*user.Phone)
	}
	email := MfaFactorDetail{Factor: "otp_email"}
	if user.Email != nil && *user.Email != "" {
		email.Bound = true
		email.Target = maskMfaEmail(*user.Email)
	}

	// webauthn：凭据计数走 WebauthnRepo.ListByUser；boundAt / lastUsedAt 取
	// user_credential 行（每凭据一行）最早 created_at / 最大 last_used_at。
	wa := MfaFactorDetail{Factor: kindWebauthn}
	waRows, err := s.deps.Webauthn.ListByUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("%w: list webauthn rows: %v", ErrMfaInternal, err)
	}
	wa.Credentials = int64(len(waRows))
	if len(waRows) > 0 {
		wa.Bound = true
		credRows, err := s.deps.Creds.ListByUser(ctx, uid)
		if err != nil {
			return nil, fmt.Errorf("%w: list credential rows: %v", ErrMfaInternal, err)
		}
		for i := range credRows {
			if credRows[i].Kind != kindWebauthn {
				continue
			}
			if wa.BoundAt == 0 || credRows[i].CreatedAt.Unix() < wa.BoundAt {
				wa.BoundAt = credRows[i].CreatedAt.Unix()
			}
			if credRows[i].LastUsedAt != nil && credRows[i].LastUsedAt.Unix() > wa.LastUsedAt {
				wa.LastUsedAt = credRows[i].LastUsedAt.Unix()
			}
		}
	}

	// recovery_code：行存在且启用且 meta 余量非空（删空即不可用，§4.2 行
	// 697）；签发时间 = 行 created_at（行存在即已签发过，即便消费尽）。
	rc := MfaFactorDetail{Factor: kindRecoveryCode}
	var recoveryIssuedAt int64
	row, err = s.deps.Creds.FindByUserAndKind(ctx, uid, kindRecoveryCode)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: load recovery_code credential: %v", ErrMfaInternal, err)
	}
	if err == nil && row.IsEnabled == 1 {
		meta, err := repo.UnmarshalCredentialMeta(row.Meta)
		if err != nil {
			return nil, fmt.Errorf("%w: decode recovery_code meta: %v", ErrMfaInternal, err)
		}
		if len(meta.GetRecoveryCodes()) > 0 {
			rc.Bound = true
			rc.Remaining = int64(len(meta.GetRecoveryCodes()))
		}
		recoveryIssuedAt = row.CreatedAt.Unix()
	}
	// 五因子序固定（totp → otp_sms → otp_email → webauthn → recovery_code）；
	// rc 等明细值在组装前定值，避免 slice 值拷贝与后续修改脱节。
	return &MfaDetail{
		Factors:          []MfaFactorDetail{totp, sms, email, wa, rc},
		RecoveryIssuedAt: recoveryIssuedAt,
	}, nil
}

// SetMfa 切换两步验证开关（§3.5）：true 要求系统已开放且存在可用因子
// （白名单 ∩ 已绑定，判定统一走 mfapolicy），不满足按 invalid_request 拒绝；
// false 直接关闭。写入只更新 user.mfa_required，不触碰会话与凭据。
func (s *MfaService) SetMfa(ctx context.Context, uid int64, enabled bool) error {
	if uid <= 0 {
		return ErrMfaUnauthenticated
	}
	if enabled {
		if !mfapolicy.SystemEnabled(s.deps.Settings) {
			return fmt.Errorf("%w: mfa is disabled by system policy", ErrMfaInvalidRequest)
		}
		factors, err := mfapolicy.UsableFactors(ctx, s.policyDeps(), uid)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return err
			}
			return fmt.Errorf("%w: resolve usable mfa factors: %v", ErrMfaInternal, err)
		}
		if len(factors) == 0 {
			return fmt.Errorf("%w: no usable mfa factor bound", ErrMfaInvalidRequest)
		}
	}
	var v int8
	if enabled {
		v = 1
	}
	if err := s.deps.Users.UpdateMfaRequired(ctx, uid, v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return fmt.Errorf("%w: update mfa_required: %v", ErrMfaInternal, err)
	}
	event := eventlog.EventDisableMFA
	if enabled {
		event = eventlog.EventEnableMFA
	}
	// enable_mfa / disable_mfa 审计（§4.6）：detail={enabled:true|false}；
	// 同值重放属用户敏感操作重放，照投记录操作意图。
	if s.deps.Audit != nil {
		s.deps.Audit.PushEvent(model.EventLog{
			Event:     event,
			ActorType: eventlog.ActorTypeUser,
			ActorID:   uid,
			UserID:    uid,
			Detail:    encodeDetailMfaEnabled(enabled),
			CreatedAt: s.now(),
		})
	}
	return nil
}

// policyDeps 组装运行期判定依赖，与登录侧共用同一 mfapolicy 口径。
func (s *MfaService) policyDeps() mfapolicy.Deps {
	return mfapolicy.Deps{Users: s.deps.Users, Creds: s.deps.Creds, Settings: s.deps.Settings}
}

// BindTotpChallenge step=challenge（§3.5 行 922）：无状态生成 secret +
// otpauthUrl + qrcodeContent（secret 由前端在 verify 步回传，服务端不存
// challenge 状态）。
func (s *MfaService) BindTotpChallenge(ctx context.Context, uid int64) (*TotpChallenge, error) {
	if uid <= 0 {
		return nil, ErrMfaUnauthenticated
	}
	user, err := s.deps.Users.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: load user: %v", ErrMfaInternal, err)
	}
	secret, err := s.generateTotpSecret()
	if err != nil {
		return nil, fmt.Errorf("%w: generate totp secret: %v", ErrMfaInternal, err)
	}
	// Key URI 格式（前端样例 account.test.tsx:1088 同形状）：
	// otpauth://totp/Issuer:account?secret=…&issuer=Issuer；account 段
	// PathEscape（空格 %20、冒号转义），issuer 参数 QueryEscape。缺省参数
	// （algorithm=SHA1 / digits=6 / period=30）按 Key URI 规范缺省即生效，
	// 与样例逐字一致不显式携带。
	label := setMfaIssuer + ":" + url.PathEscape(user.Username)
	otpauth := "otpauth://totp/" + label +
		"?secret=" + secret +
		"&issuer=" + url.QueryEscape(setMfaIssuer)
	return &TotpChallenge{
		Secret:        secret,
		OtpauthUrl:    otpauth,
		QrcodeContent: otpauth,
	}, nil
}

// BindTotpVerify step=verify（§3.5 行 923）：RFC 6238 ±1 时间步校验 →
// 通过即绑定生效（upsert kind=totp 行）+ 同一响应重签 10 条恢复码
// （覆盖既有即全量作废旧码），返回展示形恢复码。
func (s *MfaService) BindTotpVerify(ctx context.Context, uid int64, secret, code string) ([]string, error) {
	if uid <= 0 {
		return nil, ErrMfaUnauthenticated
	}
	if secret == "" || len(code) != totpCodeLength || !totpDigits(code) {
		// secret 缺失 / code 格式非法 → invalid_request（§8.4 行 1083）。
		return nil, fmt.Errorf("%w: empty secret or malformed code", ErrMfaInvalidRequest)
	}
	key, err := decodeTotpSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed secret: %v", ErrMfaInvalidRequest, err)
	}
	if !totpValid(key, code, s.now()) {
		return nil, ErrMfaInvalidCode
	}

	now := s.now()
	// 绑定生效：kind=totp 行 upsert（明文 Base32 存 secret 列，§3.11 行 430；
	// meta 带 totp_digits / totp_period，§12.2 kind=totp 段）。
	totpMeta, err := repo.MarshalCredentialMeta(&credentialpb.CredentialMeta{
		TotpDigits: totpCodeLength,
		TotpPeriod: totpStepSeconds,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: marshal totp meta: %v", ErrMfaInternal, err)
	}
	row, err := s.deps.Creds.FindByUserAndKind(ctx, uid, kindTotp)
	switch {
	case err == nil:
		// 重复绑定（换密钥场景）按覆盖处理——文档无「已绑定即拒绝」条款，
		// 不发明 already_exists 语义；旧密钥随覆盖即刻失效。
		row.Secret = []byte(secret)
		row.Meta = totpMeta
		row.IsEnabled = 1
		row.UpdatedAt = now
		if err := s.deps.Creds.Update(ctx, row); err != nil {
			return nil, fmt.Errorf("%w: update totp credential: %v", ErrMfaInternal, err)
		}
	case errors.Is(err, sql.ErrNoRows):
		c := &model.UserCredential{
			UserID:    uid,
			Kind:      kindTotp,
			Secret:    []byte(secret),
			Meta:      totpMeta,
			IsEnabled: 1,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := s.deps.Creds.Create(ctx, c); err != nil {
			return nil, fmt.Errorf("%w: create totp credential: %v", ErrMfaInternal, err)
		}
	default:
		return nil, fmt.Errorf("%w: load totp credential: %v", ErrMfaInternal, err)
	}

	// 同一响应重签恢复码（§3.5 行 923「验证一次后生效，同一响应下发 10 个
	// 恢复码」）：kind=recovery_code 行 upsert，覆盖即全量作废旧码。
	stored, err := s.generateRecoveryCodes()
	if err != nil {
		return nil, fmt.Errorf("%w: generate recovery codes: %v", ErrMfaInternal, err)
	}
	rcMeta, err := repo.MarshalCredentialMeta(&credentialpb.CredentialMeta{RecoveryCodes: stored})
	if err != nil {
		return nil, fmt.Errorf("%w: marshal recovery_code meta: %v", ErrMfaInternal, err)
	}
	row, err = s.deps.Creds.FindByUserAndKind(ctx, uid, kindRecoveryCode)
	switch {
	case err == nil:
		row.Meta = rcMeta
		row.IsEnabled = 1
		row.UpdatedAt = now
		if err := s.deps.Creds.Update(ctx, row); err != nil {
			return nil, fmt.Errorf("%w: update recovery_code credential: %v", ErrMfaInternal, err)
		}
	case errors.Is(err, sql.ErrNoRows):
		c := &model.UserCredential{
			UserID:    uid,
			Kind:      kindRecoveryCode,
			Secret:    []byte{}, // 恢复码在 meta，secret 列无该 kind 语义
			Meta:      rcMeta,
			IsEnabled: 1,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := s.deps.Creds.Create(ctx, c); err != nil {
			return nil, fmt.Errorf("%w: create recovery_code credential: %v", ErrMfaInternal, err)
		}
	default:
		return nil, fmt.Errorf("%w: load recovery_code credential: %v", ErrMfaInternal, err)
	}

	// 展示形下发（存储 8 位、展示 xxxx-xxxx），不回显存储形。
	codes := make([]string, recoveryCodeCount)
	for i, c := range stored {
		codes[i] = formatRecoveryCode(c)
	}
	return codes, nil
}

// RegenerateRecoveryCodes 全量作废并重新下发（§3.5 行 925）：生成 / 重
// 生成归本层（factor/recovery 只管消费）。「重新生成」针对既有签发——
// 无 kind=recovery_code 行（从未绑定 totp）→ code_expired，首签归
// BindTotp verify；行存在即便 meta 空（消费尽）亦重签续命。createdAt 沿
// 行 created_at（CredentialMeta 无签发时间字段，repo Update 更新集不含
// created_at，全量作废仅指码集替换）。
func (s *MfaService) RegenerateRecoveryCodes(ctx context.Context, uid int64, action string) (*RecoveryCodesResult, error) {
	if uid <= 0 {
		return nil, ErrMfaUnauthenticated
	}
	if action != regenerateAction {
		return nil, fmt.Errorf("%w: action must be %q", ErrMfaInvalidRequest, regenerateAction)
	}
	row, err := s.deps.Creds.FindByUserAndKind(ctx, uid, kindRecoveryCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrMfaCodeExpired
		}
		return nil, fmt.Errorf("%w: load recovery_code credential: %v", ErrMfaInternal, err)
	}
	if row == nil || row.IsEnabled != 1 {
		return nil, ErrMfaCodeExpired
	}
	stored, err := s.generateRecoveryCodes()
	if err != nil {
		return nil, fmt.Errorf("%w: generate recovery codes: %v", ErrMfaInternal, err)
	}
	meta, err := repo.MarshalCredentialMeta(&credentialpb.CredentialMeta{RecoveryCodes: stored})
	if err != nil {
		return nil, fmt.Errorf("%w: marshal recovery_code meta: %v", ErrMfaInternal, err)
	}
	row.Meta = meta
	row.UpdatedAt = s.now()
	if err := s.deps.Creds.Update(ctx, row); err != nil {
		return nil, fmt.Errorf("%w: update recovery_code credential: %v", ErrMfaInternal, err)
	}
	codes := make([]string, recoveryCodeCount)
	for i, c := range stored {
		codes[i] = formatRecoveryCode(c)
	}
	return &RecoveryCodesResult{Codes: codes, CreatedAt: row.CreatedAt.Unix()}, nil
}

// maskMfaPhone 手机号掩码（§3.5 行 909 示例「138****8000」；算法与 dto / oidc
// 同名实现同款，跨包私有按 §3.5「各落一份」先例）。
func maskMfaPhone(phone string) string {
	if len(phone) >= 7 {
		return phone[:3] + "****" + phone[len(phone)-4:]
	}
	return "****"
}

// maskMfaEmail 邮箱掩码（算法与 dto / oidc 同名实现同款，跨包私有按
// §3.5「各落一份」先例：保本地段首字符 + 域名全显）。
func maskMfaEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return "***"
	}
	local := email[:at]
	domain := email[at:]
	if len(local) <= 1 {
		return "*" + domain
	}
	return local[:1] + "***" + domain
}

// generateTotpSecret 生成 10 随机字节 → 16 字符 Base32（无填充、大写，
// factor/totp decodeSecret 同款可解）。
func (s *MfaService) generateTotpSecret() (string, error) {
	buf := make([]byte, totpSecretBytes)
	if err := s.readRand(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// generateRecoveryCodes 生成 10 条互异 8 位存储形恢复码（Crockford Base32
// 小写；字符集 32 整除 256，字节取模无偏）。批内互异：恢复码命中即删、
// 一码一值，重复码会让剩余数量与实际可用值不符；碰撞重生成，重试上限
// 防退化随机源死循环。
func (s *MfaService) generateRecoveryCodes() ([]string, error) {
	codes := make([]string, 0, recoveryCodeCount)
	seen := make(map[string]bool, recoveryCodeCount)
	buf := make([]byte, recoveryCodeLength)
	for retries := 0; len(codes) < recoveryCodeCount; retries++ {
		if retries > recoveryCodeDedupRetries {
			return nil, fmt.Errorf("%w: recovery code entropy exhausted", ErrMfaInternal)
		}
		if err := s.readRand(buf); err != nil {
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

// readRand 随机源读取（缺省 crypto/rand.Reader，测试可注入确定性源）。
func (s *MfaService) readRand(buf []byte) error {
	r := s.deps.Rand
	if r == nil {
		r = rand.Reader
	}
	_, err := io.ReadFull(r, buf)
	return err
}

// formatRecoveryCode 存储形 xxxxxxxx → 展示形 xxxx-xxxx（§8.4 行 1082）。
func formatRecoveryCode(stored string) string {
	if len(stored) != recoveryCodeLength {
		return stored
	}
	return stored[:4] + "-" + stored[4:]
}

// totpValid code 是否为 now 前后 ±1 个时间步内的有效值（RFC 6238；与
// factor/totp 内核同款算法，跨包私有按 §3.5「各落一份」先例）。
func totpValid(secret []byte, code string, now time.Time) bool {
	base := now.Unix() / totpStepSeconds
	for off := -int64(totpSkewSteps); off <= int64(totpSkewSteps); off++ {
		counter := base + off
		if counter < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpHotp(secret, uint64(counter))), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// totpHotp RFC 4226 HOTP（HMAC-SHA1 + 动态截断 + 6 位取模；factor/totp
// 内核同款）。
func totpHotp(secret []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", bin%totpModulus)
}

// decodeTotpSecret 解码明文 Base32 密钥（容忍大小写 / 空格 / 填充符差异，
// factor/totp decodeSecret 同款）。
func decodeTotpSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, fmt.Errorf("mfa: empty secret")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

func totpDigits(code string) bool {
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// encodeDetailMfaEnabled 编码 enable_mfa / disable_mfa 审计 detail（§4.6：
// {enabled:true|false}，msgpack 透传——webauthn encodeDetailWebauthn 同款
// 私有实现）。编码失败返回 nil（落 NULL），不影响主链路。
func encodeDetailMfaEnabled(enabled bool) []byte {
	b, err := msgpack.Marshal(map[string]any{"enabled": enabled})
	if err != nil {
		return nil
	}
	return b
}

// UnbindTotp 解除当前 TOTP 绑定（接口文档 §3.5、后端架构 §16）：先消费
// 验证断言，按 biz_purpose=unbind_totp / subject=会话 uid /
// operation=unbind_totp 三重校验（§16、§11.6.7）；通过后删除 kind=totp
// 凭据并作废恢复码。断言缺失直接返回 verification_required，断言无效 /
// 过期由消费方映射 verification_invalid，重放由凭据去重兜住（§3.8.5）。
// 解绑后可用因子为空时回落 mfa_required=0，保证存储值与运行期判定一致
// （§3.5 运行期兜底）。
func (s *MfaService) UnbindTotp(ctx context.Context, uid int64, token string) error {
	if uid <= 0 {
		return ErrMfaUnauthenticated
	}
	if token == "" {
		return &verification.Error{Code: "verification_required"}
	}
	if s.deps.Assertions == nil {
		return fmt.Errorf("%w: assertion consumer not configured", ErrMfaInternal)
	}
	_, err := s.deps.Assertions.ConsumeAssertion(ctx, token, verification.Want{
		BizPurpose: verification.BizPurposeUnbindTOTP,
		Operation:  "unbind_totp",
		Subject:    verification.Subject{Kind: verification.SubjectKindUID, ID: strconv.FormatInt(uid, 10)},
	})
	if err != nil {
		return err
	}
	// 未绑定检查（§3.5）：totp 行不存在即无可解绑。低风险 biz_purpose 按
	// §11.6.7 不加 al:once，一次性由凭据去重保证——解绑成功即删除该行，
	// 同一断言再次提交会命中此分支，按重放返回 verification_invalid
	//（§3.8.5），不新造 Redis 状态键。
	if _, err := s.deps.Creds.FindByUserAndKind(ctx, uid, kindTotp); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &verification.Error{Code: "verification_invalid"}
		}
		return fmt.Errorf("%w: load totp credential: %v", ErrMfaInternal, err)
	}
	if err := s.deps.Creds.DeleteByUserAndKind(ctx, uid, kindTotp); err != nil {
		return fmt.Errorf("%w: delete totp credential: %v", ErrMfaInternal, err)
	}
	// 作废恢复码（§16）：随 TOTP 绑定一并移除。
	if err := s.deps.Creds.DeleteByUserAndKind(ctx, uid, kindRecoveryCode); err != nil {
		return fmt.Errorf("%w: delete recovery codes: %v", ErrMfaInternal, err)
	}
	// 解绑后无可用因子时回落开关（§3.5 运行期兜底）：仅用户已开启时才重算，
	// 开关本为 0 时不重复写库 / 刷 updated_at；仍有其他已绑定因子（如手机号）
	// 则保持原开关。装配裁剪（Users 未注入）无法判定，跳过回落。
	if s.deps.Users != nil {
		user, err := s.deps.Users.FindByID(ctx, uid)
		if err != nil {
			return fmt.Errorf("%w: load user for mfa fallback: %v", ErrMfaInternal, err)
		}
		if user != nil && user.MfaRequired == 1 {
			factors, err := mfapolicy.UsableFactors(ctx, s.policyDeps(), uid)
			if err != nil {
				return fmt.Errorf("%w: resolve usable mfa factors: %v", ErrMfaInternal, err)
			}
			if len(factors) == 0 {
				if err := s.deps.Users.UpdateMfaRequired(ctx, uid, 0); err != nil {
					return fmt.Errorf("%w: reset mfa_required: %v", ErrMfaInternal, err)
				}
			}
		}
	}
	return nil
}
