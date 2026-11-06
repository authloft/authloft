// mfa.go account 域两步验证族业务层（docs/接口文档.md §3.5 行 900-927、
// §3.2 行 844-864、docs/后端架构.md §8.4 行 1079-1084、§8.3 行 1071-1075）。
//
// 职责边界（五方法实装）：
//   - GetMfa：五因子绑定明细（§3.5 行 907-915）+recoveryIssuedAt。数据源：
//     totp / recovery_code 走 CredentialRepo.FindByUserAndKind（bound = 行存在
//     且 is_enabled=1；recovery_code 另需 meta 余量非空——删空写回空数组等价
//     该 kind 不可用，后端架构 §4.2 行 697，与 handler mfaBound 同口径）；otp_sms /
//     otp_email 走 user 资料（bound = phone/email 非空，与 handler GetConfig
//     §3.2 摘要 bound 同口径——摘要与明细是同一绑定概念的两处投影，取值必须
//     一致；掩码算法与 orchestrator.maskPhone/maskEmail 同款，跨包私有按
//     §3.5「各落一份」先例本包各落一份；OTP 因子无凭证行 → lastUsedAt 无
//     数据源恒 0）；webauthn 凭据数走 WebauthnRepo.ListByUser，boundAt /
//     lastUsedAt 取 user_credential 行（webauthn 每凭据一行）最早 created_at /
//     最大 last_used_at。
//   - SetMfa：methods 数组勾选启用（行 921）。值域封闭四值 {totp,otp_sms,
//     otp_email,webauthn}（recovery_code 随 totp 投影不可独立勾选，§3.2 行 862；
//     未知值 → invalid_request）；落库 = mfa_setting 行 CredentialMeta.
//     mfa_methods（既定口径：每用户至多一行，首开 Create / 再开 Update）；
//     空数组 = 关闭，受 required 约束（required = settings.mfa_enabled
//     （缺省 true）&& user.mfa_required==1，handler mfaPolicy / orchestrator
//     Build 同口径）；成功为空响应。关闭 = 删除 mfa_setting 行（既定口径：
//     行 862「行存在即顶层 enabled=true」⇒ 关闭 ⇔ 行
//     不存在），走 CredentialRepo.DeleteByUserAndKind；
//     行本就不存在（已关闭态）→ 未命中幂等成功。
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
//   - GetRecoveryCodes：存量明文一次性展示（行 924；恢复码明文存
//     CredentialMeta.recovery_codes，§4.2 行 686），存储形转展示形 xxxx-xxxx；
//     无行 / 未启用 / meta 空（消费尽）→ code_expired（§8.4 行 1083）。
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
// webauthn fail-closed（§8.3 行 1071-1075 窗口期六要素，既定口径）：六要素
// 仅覆盖登录（主因子拒绝 / 唯一可用因子拒绝）与通行密钥管理（绑定 / 解绑 /
// 管理），**不含 SetMfa 勾选**——SetMfa 勾选 webauthn 是启用集偏好记录，
// 窗口期勾选后的登录链 fail-closed 已由 orchestrator.ErrWebauthnDegraded
// 哨兵兜住，故本层不做 webauthn 可用性判定（与哨兵语义一致的判定源——
// factor 注册表——不在本层依赖面，强行表达需新增依赖，按「无法一致
// 表达就不做该判定」的既定原则处理）。
//
// 审计：SetMfa 开启投 enable_mfa（detail={methods:[...]}）、关闭投
// disable_mfa（detail={methods:[]}，形状对偶；§4.6 行 821 表）；BindTotp /
// RegenerateRecoveryCodes 不投——§4.6 行 790 事件枚举无 totp_bind / 恢复码
// 事件，不自造（webauthn_rename「无枚举成员不自造」同款先例）。
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
	"strings"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"gorm.io/gorm"

	credentialpb "authloft/gen/go/credential"
	"authloft/internal/eventlog"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

const (
	// totpStepChallenge / totpStepVerify BindTotp.step 取值（§3.5 行 922-923）。
	totpStepChallenge = "challenge"
	totpStepVerify    = "verify"
	// kindTotp / kindRecoveryCode / kindMfaSetting user_credential.kind 取值
	//（§4.2 行 667 枚举；handler/account 同值常量为该包私有，本包各落一份）。
	kindTotp         = "totp"
	kindRecoveryCode = "recovery_code"
	kindMfaSetting   = "mfa_setting"
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
	// ErrMfaInvalidRequest 参数缺失 / step 非法 / methods 含未知因子 / 格式非法
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

// MfaUserStore user 表读取窄接口（§20）：*repo.UserRepo 天然满足
//（factor.UserRepo 同构；SetMfa required 判定读 mfa_required 列、
// BindTotpChallenge 读 username 组 otpauth label）。
type MfaUserStore interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
}

// MfaCredentialStore user_credential 表读写窄接口（§20）：*repo.CredentialRepo
// 天然满足（FindByUserAndKind / ListByUser / Create / Update 均既有；
// DeleteByUserAndKind 为本层新增——SetMfa 关闭 = 删除 mfa_setting
// 行；ListByUser 供 webauthn 因子 boundAt / lastUsedAt 投影，webauthn.go
// 同款数据源）。
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
// 满足；nil / 键缺失按 mfa_enabled 默认 true（§5.6 行 1322，handler mfaPolicy
// 同款防御读）。
type MfaSettingsReader interface {
	GetBool(key string) (bool, bool)
}

// MfaDeps 依赖注入（§20）；装配层构造（bootstrap 接线）。
type MfaDeps struct {
	// Users user 表读取（required 判定 / otpauth label）。
	Users MfaUserStore
	// Creds user_credential 读写（totp / recovery_code / mfa_setting 行）。
	Creds MfaCredentialStore
	// Webauthn user_credential_webauthn 读取（凭据计数）。
	Webauthn MfaWebauthnStore
	// Settings 热更新键读取（mfa_enabled）。
	Settings MfaSettingsReader
	// Audit enable_mfa / disable_mfa 审计投递（nil = 跳过，测试用）。
	Audit AuditSink
	// Now 时钟注入（缺省 time.Now）。
	Now func() time.Time
	// Rand 随机源注入（缺省 crypto/rand.Reader；TOTP secret 与恢复码生成）。
	Rand io.Reader
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
	_ MfaUserStore        = (*repo.UserRepo)(nil)
	_ MfaCredentialStore  = (*repo.CredentialRepo)(nil)
	_ MfaWebauthnStore     = (*repo.WebauthnRepo)(nil)
	_ MfaSettingsReader    = (*settings.Store)(nil)
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

// MfaDetail GetMfa 响应明细（§3.5 行 905-915）：五因子序固定 mfa 明细序
//（totp → otp_sms → otp_email → webauthn → recovery_code，dto.mfaFactorOrder
// 同序）+ recoveryIssuedAt。
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

// RecoveryCodesResult GetRecoveryCodes / RegenerateRecoveryCodes 共用响应
//（§3.5 行 924-925，RecoveryCodesResponse proto 同构）：codes 为展示形
// xxxx-xxxx，createdAt 为签发时间（kind=recovery_code 行 created_at）。
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
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: load user: %v", ErrMfaInternal, err)
	}

	// totp：行存在且启用即绑定（handler mfaBound 同口径）；boundAt /
	// lastUsedAt 取凭据行既有列。
	totp := MfaFactorDetail{Factor: kindTotp}
	row, err := s.deps.Creds.FindByUserAndKind(ctx, uid, kindTotp)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
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
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
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
	// 五因子序固定（totp → otp_sms → otp_email → webauthn → recovery_code，
	// dto.mfaFactorOrder 同序）；rc 等明细值在组装前定值，避免 slice 值拷贝
	// 与后续修改脱节。
	return &MfaDetail{
		Factors:          []MfaFactorDetail{totp, sms, email, wa, rc},
		RecoveryIssuedAt: recoveryIssuedAt,
	}, nil
}

// setMfaAllowedMethods SetMfa 可勾选因子的封闭值域（§3.2 行 862 启用因子集 +
// recovery_code 随 totp 投影 → 四值；顺序即 mfaOrder，归一后按此序输出，
// 与 mfa_setting 行 mfa_methods 存储序稳定一致）。
var setMfaAllowedMethods = [...]string{"totp", "otp_sms", "otp_email", "webauthn"}

// SetMfa 勾选启用 / 关闭两步验证（§3.5 行 921）：非空 = 启用集写入
// mfa_setting 行 CredentialMeta.mfa_methods；空数组 = 关闭（受 §3.2
// mfaPolicy.required 约束）。
func (s *MfaService) SetMfa(ctx context.Context, uid int64, methods []string) error {
	if uid <= 0 {
		return ErrMfaUnauthenticated
	}
	// 归一（去重、按封闭序输出）；未知值（含 recovery_code——随 totp 投影
	// 不可独立勾选）→ invalid_request。
	picked := make(map[string]bool, len(methods))
	for _, m := range methods {
		allowed := false
		for _, a := range setMfaAllowedMethods {
			if m == a {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: unknown mfa method %q", ErrMfaInvalidRequest, m)
		}
		picked[m] = true
	}
	ordered := make([]string, 0, len(picked))
	for _, a := range setMfaAllowedMethods {
		if picked[a] {
			ordered = append(ordered, a)
		}
	}

	// required 口径：settings.mfa_enabled（缺省 true）&& user.mfa_required==1
	//（§3.2 行 849；handler mfaPolicy / orchestrator Build 同源同口径）。
	required, err := s.mfaRequired(ctx, uid)
	if err != nil {
		return err
	}

	if len(ordered) == 0 {
		if required {
			// 策略强制不可关闭（§3.2 行 849「true 时用户不可关闭」；
			// §1.6 封闭集内 invalid_request 承载「参数在当前策略下非法」）。
			return fmt.Errorf("%w: mfa required by policy, cannot disable", ErrMfaInvalidRequest)
		}
		// 关闭 ⇔ 删除 mfa_setting 行（行 862「行存在即顶层 enabled=true」⇒
		// 关闭 ⇔ 行不存在，既定口径）。行本就不存在
		//（从未开启 / 已关闭态）→ 未命中视作幂等成功，不放大为错误。
		if err := s.deps.Creds.DeleteByUserAndKind(ctx, uid, kindMfaSetting); err != nil &&
			!errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: delete mfa_setting: %v", ErrMfaInternal, err)
		}
		// disable_mfa 审计（§4.6 行 821 表；detail={methods:[]}——关闭后
		// 启用集为空，与 enable_mfa detail 形状对偶；已关闭态再关属用户
		// 敏感操作重放，照投记录操作意图）。
		if s.deps.Audit != nil {
			s.deps.Audit.PushEvent(model.EventLog{
				Event:     eventlog.EventDisableMFA,
				ActorType: eventlog.ActorTypeUser,
				ActorID:   uid,
				UserID:    uid,
				Detail:    encodeDetailMfaMethods([]string{}),
				CreatedAt: s.now(),
			})
		}
		return nil
	}

	now := s.now()
	meta, err := repo.MarshalCredentialMeta(&credentialpb.CredentialMeta{MfaMethods: ordered})
	if err != nil {
		return fmt.Errorf("%w: marshal mfa_setting meta: %v", ErrMfaInternal, err)
	}
	row, err := s.deps.Creds.FindByUserAndKind(ctx, uid, kindMfaSetting)
	switch {
	case err == nil:
		row.Meta = meta
		row.IsEnabled = 1
		row.UpdatedAt = now
		if err := s.deps.Creds.Update(ctx, row); err != nil {
			return fmt.Errorf("%w: update mfa_setting: %v", ErrMfaInternal, err)
		}
	case errors.Is(err, gorm.ErrRecordNotFound):
		c := &model.UserCredential{
			UserID:    uid,
			Kind:      kindMfaSetting,
			Secret:    []byte{}, // 无口令语义（§4.2 行 674 webauthn 行同款空 secret 先例）
			Meta:      meta,
			IsEnabled: 1,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := s.deps.Creds.Create(ctx, c); err != nil {
			return fmt.Errorf("%w: create mfa_setting: %v", ErrMfaInternal, err)
		}
	default:
		return fmt.Errorf("%w: load mfa_setting: %v", ErrMfaInternal, err)
	}

	// enable_mfa 审计（§4.6 行 821：detail={methods:[...]}）。
	if s.deps.Audit != nil {
		s.deps.Audit.PushEvent(model.EventLog{
			Event:     eventlog.EventEnableMFA,
			ActorType: eventlog.ActorTypeUser,
			ActorID:   uid,
			UserID:    uid,
			Detail:    encodeDetailMfaMethods(ordered),
			CreatedAt: now,
		})
	}
	return nil
}

// mfaRequired required 判定（§3.2 行 849）：settings.mfa_enabled（nil /
// 键缺失缺省 true）&& user.mfa_required==1。user 不存在原样上抛
// gorm.ErrRecordNotFound（handler 映射 not_found）。
func (s *MfaService) mfaRequired(ctx context.Context, uid int64) (bool, error) {
	user, err := s.deps.Users.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, err
		}
		return false, fmt.Errorf("%w: load user: %v", ErrMfaInternal, err)
	}
	enabled := true
	if s.deps.Settings != nil {
		if v, ok := s.deps.Settings.GetBool(settings.KeyMfaEnabled); ok {
			enabled = v
		}
	}
	return enabled && user.MfaRequired == 1, nil
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
		if errors.Is(err, gorm.ErrRecordNotFound) {
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
		Secret:         secret,
		OtpauthUrl:     otpauth,
		QrcodeContent:  otpauth,
	}, nil
}

// BindTotpVerify step=verify（§3.5 行 923）：RFC 6238 ±1 时间步校验 →
// 通过即绑定生效（upsert kind=totp 行）+ 同一响应重签 10 条恢复码
//（覆盖既有即全量作废旧码），返回展示形恢复码。
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
	case errors.Is(err, gorm.ErrRecordNotFound):
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
	case errors.Is(err, gorm.ErrRecordNotFound):
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

// GetRecoveryCodes 存量恢复码一次性展示（§3.5 行 924）：无行 / 未启用 /
// meta 空（消费尽）→ code_expired（§8.4 行 1083）。
func (s *MfaService) GetRecoveryCodes(ctx context.Context, uid int64) (*RecoveryCodesResult, error) {
	if uid <= 0 {
		return nil, ErrMfaUnauthenticated
	}
	row, err := s.deps.Creds.FindByUserAndKind(ctx, uid, kindRecoveryCode)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrMfaCodeExpired
		}
		return nil, fmt.Errorf("%w: load recovery_code credential: %v", ErrMfaInternal, err)
	}
	if row == nil || row.IsEnabled != 1 {
		return nil, ErrMfaCodeExpired
	}
	meta, err := repo.UnmarshalCredentialMeta(row.Meta)
	if err != nil {
		return nil, fmt.Errorf("%w: decode recovery_code meta: %v", ErrMfaInternal, err)
	}
	stored := meta.GetRecoveryCodes()
	if len(stored) == 0 {
		return nil, ErrMfaCodeExpired
	}
	codes := make([]string, len(stored))
	for i, c := range stored {
		codes[i] = formatRecoveryCode(c)
	}
	return &RecoveryCodesResult{Codes: codes, CreatedAt: row.CreatedAt.Unix()}, nil
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
		if errors.Is(err, gorm.ErrRecordNotFound) {
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

// maskMfaPhone 手机号掩码（§3.5 行 909 示例「138****8000」；算法与
// orchestrator.maskPhone 同款，跨包私有按 §3.5「各落一份」先例）。
func maskMfaPhone(phone string) string {
	if len(phone) >= 7 {
		return phone[:3] + "****" + phone[len(phone)-4:]
	}
	return "****"
}

// maskMfaEmail 邮箱掩码（算法与 orchestrator.maskEmail 同款，跨包私有按
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

// encodeDetailMfaMethods 编码 enable_mfa / disable_mfa 审计 detail（§4.6
// 行 821：{methods:[...]}，msgpack 透传——webauthn encodeDetailWebauthn 同款
// 私有实现）。编码失败返回 nil（落 NULL），不影响主链路。
func encodeDetailMfaMethods(methods []string) []byte {
	b, err := msgpack.Marshal(map[string]any{"methods": methods})
	if err != nil {
		return nil
	}
	return b
}
