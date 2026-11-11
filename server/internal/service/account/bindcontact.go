// bindcontact.go account 域手机 / 邮箱换绑族两方法的业务层
// （docs/接口文档.md §3.4 行 881-898、§1.6 行 229-273；docs/后端架构.md
// §10.1 行 1141-1162、§10.2 行 1164-1171、§10.3、§8.2 行 1051）。
//
// 职责：AccountService/BindPhone、BindEmail 的换绑编排——统一走验证码
// （purpose=bind）+ captcha 两步（§3.4 行 883）：
//   - challenge {target, captcha}：captcha 必过（Gate Challenge 恒触发，
//     §3.4 行 896）→ target 非空 → 存在性先判（uid 用户行不存在 →
//     user_not_found 口径哨兵，同 profile.go 先于任何写操作）→ 占用判定
//     （§3.4 行 892：新号码必须未被他人占用——已占他人 → target_taken；
//     已绑自己 → 幂等成功零动作〔不写码 / 不发信 / 不投审计，既有幂等
//     分支口径〕）→ Issue 写 al:code:{target}:bind（owner=uid 字符串，
//     §10.1 行 1158 账号域绑定 / 换绑场景；本场景无 login_token 不记 tid）
//     → core.Judge 限流判定（冷却 / 日限额 → too_many_requests，§1.6 行
//     243）→ 投递（渠道未配置 → provider_disabled，§1.6 行 260；发送失败
//     不回滚已写码，允许 60s 后重发，§8.2 行 1051）。
//   - verify {target, code}：格式先判（不满足 → invalid_request，不进入
//     存储、不消耗尝试次数，factor/otp Verify 同口径）→ 存在性先判 →
//     Check（GETDEL 原子消费，§10.1 行 1148；code 与 owner 双比对——码内
//     uid 与当前会话 uid 不一致由存储层按码不符处理，落 CheckMismatch →
//     invalid_code，§3.4 行 897；cache/lua/verify_code.lua 行 23-33 实证
//     owner 不一致与错码同走 mismatch 分支、同样消耗 tries）→ 成功列级
//     更新 user 行（phone/email + 对应 verified=1）→ 审计 bind_phone /
//     bind_email（detail={target_masked}，§4.6 行 800，必须用掩码后的
//     target；仅在 verify 成功写库后投递，challenge 不投）。
//
// 服务层不解析 proto / 会话（profile.go 边界惯例）：step / target / code
// 由 handler〔拼装层〕从 PhoneBindPayload / EmailBindPayload、captcha 由
// 请求顶层字段（与 payload 平级，§2.5）与会话转换注入；成功返回 nil =
// 空响应（OkResponse，§3.4 行 885）。错误哨兵与 §1.6 封闭集成员一一对应，
// handler 转 Connect 错误体 + ErrorInfo，本层不自造 status 字面量。
package account

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"authloft/internal/captcha"
	"authloft/internal/eventlog"
	core "authloft/internal/otp"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// 域常量（字面量均为文档封闭集成员或文档定义取值）。
const (
	// purposeBind al:code:{target}:bind 的 purpose（§3.4 行 883
	// 「purpose=bind」；factor/otp purposeMFA 同款命名）。
	purposeBind = "bind"
	// bindStepChallenge / bindStepVerify 请求 step 字面量（§3.4 行
	// 887-890；proto BindPhoneRequest.step 注释同源）。
	bindStepChallenge = "challenge"
	bindStepVerify    = "verify"
)

// 可判别哨兵错误（handler〔拼装层〕转 Connect 错误体 + ErrorInfo，
// §1.6 封闭集成员；本层只返回 error，映射归 handler）。
var (
	// ErrBindInvalidRequest step 非法 / target 或 code 缺失 / 码格式错
	//（§1.6 行 246）。
	ErrBindInvalidRequest = errors.New("account bind: invalid request")
	// ErrBindCaptchaRequired challenge 未携带 captcha（§1.6 行 241）。
	ErrBindCaptchaRequired = errors.New("account bind: captcha required")
	// ErrBindCaptchaInvalid captcha 校验不通过 / 已使用（§1.6 行 242）。
	ErrBindCaptchaInvalid = errors.New("account bind: captcha invalid")
	// ErrBindTargetTaken 新号码已占用于他人 / 落库并发被抢（§1.6 行 257）。
	ErrBindTargetTaken = errors.New("account bind: target taken")
	// ErrBindUserNotFound uid 用户行不存在（§1.6 行 255 账号不存在口径，
	// 会话存活期间行被删的防御分支同码）。
	ErrBindUserNotFound = errors.New("account bind: user not found")
	// ErrBindTooManyRequests 发码触发冷却或日限额（§1.6 行 243）。
	ErrBindTooManyRequests = errors.New("account bind: too many requests")
	// ErrBindProviderDisabled 发送渠道未配置（§1.6 行 260 提供商未启用）。
	ErrBindProviderDisabled = errors.New("account bind: provider disabled")
	// ErrBindInvalidCode 验证码错误（§1.6 行 248，含剩余次数）。
	ErrBindInvalidCode = errors.New("account bind: invalid code")
	// ErrBindTooManyAttempts 验证码尝试次数超限（§1.6 行 244）。
	ErrBindTooManyAttempts = errors.New("account bind: too many attempts")
	// ErrBindCodeExpired 验证码过期 / 已作废 / 不存在（§1.6 行 249）。
	ErrBindCodeExpired = errors.New("account bind: code expired")
)

// BindInvalidCodeError invalid_code 且键保留时的携带剩余次数的错误形态
// （§1.6 行 248「验证码错误（含剩余次数）」）：errors.Is 命中基哨兵
// ErrBindInvalidCode，errors.As 取 AttemptsLeft（handler 转 ErrorInfo 时
// 可携带剩余次数，factor/otp 的 VerifyResult.AttemptsLeft 同口径）。
type BindInvalidCodeError struct {
	AttemptsLeft int64
}

func (e *BindInvalidCodeError) Error() string {
	return fmt.Sprintf("account bind: invalid code (attempts left %d)", e.AttemptsLeft)
}

func (e *BindInvalidCodeError) Unwrap() error { return ErrBindInvalidCode }

// BindCaptchaFailure 把 Gate.Evaluate 判定的当前生效 captcha 配置随可判别
// 哨兵错误透出，供上层经 connect.WithCaptchaConfig 并列进错误体 details
// （§2.5 / §9.1 同源）。Config 直接取自该次判定的 Outcome.Config——gate
// 这一处单一出口，本层不重新读取配置、不另造第二份；cause 保留原哨兵，
// errors.Is 仍可判别。
type BindCaptchaFailure struct {
	Config captcha.Config
	cause  error
}

func (f *BindCaptchaFailure) Error() string { return f.cause.Error() }
func (f *BindCaptchaFailure) Unwrap() error { return f.cause }

// bindContactKind 绑定渠道：手机 / 邮箱（FindByX 占用查询、事件名、掩码
// 函数按渠道分派；两渠道编排完全同构，§3.4 行 883「统一走」）。
type bindContactKind int

const (
	bindContactPhone bindContactKind = iota
	bindContactEmail
)

// BindContactStore user 表读写窄接口（§20 依赖注入）：FindByID /
// FindByPhone / FindByEmail 为 *repo.UserRepo 既有方法；
// UpdateContactColumns 为本层新增的列级更新方法——**生产实现在
// repo.UserRepo 上落地**，故此处不写指向 *repo.UserRepo 的
// compile 断言（profile.go / password.go 断言惯例的例外，既定裁量）。
type BindContactStore interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	FindByPhone(ctx context.Context, phone string) (*model.User, error)
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	// UpdateContactColumns 列级更新 user 表 phone / email 与对应 verified
	// 位（nil = 该列不写入，repo UpdateProfileColumns 惯例）；updated_at
	// 一并刷新；命中唯一键（目标已被他人抢占）必须返回 errors.Is 可判别
	// 的 repo.ErrUserDuplicate（与 UserRepo.Create 的 1062 判别同源）。
	UpdateContactColumns(ctx context.Context, id int64, phone, email *string, phoneVerified, emailVerified *int8) error
}

// BindCodeSender 验证码投递通道（factor/otp Sender 同款签名；装配方按
// 渠道注入，service 不直接调第三方 SDK）。
type BindCodeSender interface {
	SendCode(ctx context.Context, target, code string) error
}

// BindContactDeps 依赖注入（§20）；装配层构造（bootstrap 接线）。
type BindContactDeps struct {
	// Users user 表读写（存在性 / 占用查询 / 列更新）。
	Users BindContactStore
	// OTP 验证码生成与校验（*otp.Service 直依赖，qrcode.go *captcha.Gate
	// 同款具体类型惯例；owner 语义由调用方传入，本域传 uid 字符串）。
	OTP *core.Service
	// Sender 码值投递（短信 / 邮件渠道）。
	Sender BindCodeSender
	// Gate captcha 唯一拦截点（§9.3 行 1110；Challenge 恒触发）。
	Gate *captcha.Gate
	// Config 发码限流判定参数（core.Judge 用；*otp.Service 构造自带一份，
	// 此处独立注入同值，factor/otp Factor 同款双注入）。
	Config core.Config
	// Audit bind_phone / bind_email 审计投递（nil = 跳过，测试用）。
	Audit AuditSink
	// Now 时钟注入（缺省 time.Now）。
	Now func() time.Time
}

// BindContactService account 域手机 / 邮箱换绑族业务层。
type BindContactService struct {
	deps BindContactDeps
	now  func() time.Time
}

// NewBindContactService 构造。
func NewBindContactService(d BindContactDeps) *BindContactService {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &BindContactService{deps: d, now: now}
}

// BindPhoneInput BindPhone 入参（handler 由 proto BindPhoneRequest 转换，
// captcha 取请求顶层字段；service 不解析 proto——qrcode.go Input 惯例）。
type BindPhoneInput struct {
	// Step 取值 challenge｜verify（§3.4 行 887）。
	Step string
	// Target 目标手机号；verify 须回传与 challenge 相同的 target（§3.4
	// 行 880）。
	Target string
	// Captcha 请求顶层 captcha（§2.5）；challenge 必填（§3.4 行 896），verify 步忽略。
	Captcha *captcha.Submission
	// Code verify：purpose=bind 的验证码（§3.4 行 888）。
	Code string
	// IP 请求来源 IP（发码侧单 IP 日限额键，§10.3 行 1147）。
	IP string
}

// BindEmailInput BindEmail 入参（handler 由 proto BindEmailRequest 转换，
// captcha 取请求顶层字段；字段与 BindPhoneInput 同构，仅 Target 语义为
// 目标邮箱）。
type BindEmailInput struct {
	// Step 取值 challenge｜verify（§3.4 行 889）。
	Step string
	// Target 目标邮箱；verify 须回传与 challenge 相同的 target（§3.4
	// 行 880）。
	Target string
	// Captcha 请求顶层 captcha（§2.5）；challenge 必填（§3.4 行 896），verify 步忽略。
	Captcha *captcha.Submission
	// Code verify：purpose=bind 的验证码（§3.4 行 890）。
	Code string
	// IP 请求来源 IP（发码侧单 IP 日限额键，§10.3 行 1147）。
	IP string
}

// BindPhone（§3.4 行 887）：当前用户绑定 / 换绑手机号，两步同端点由
// step 区分；成功 nil = 空响应。uid 为当前会话 uid（handler 注入）。
func (s *BindContactService) BindPhone(ctx context.Context, uid int64, in BindPhoneInput) error {
	return s.bindContact(ctx, uid, bindContactPhone, in.Step, in.Target, in.Captcha, in.Code, in.IP)
}

// BindEmail（§3.4 行 889）：当前用户绑定 / 换绑邮箱，两步同端点由 step
// 区分；成功 nil = 空响应。uid 为当前会话 uid（handler 注入）。
func (s *BindContactService) BindEmail(ctx context.Context, uid int64, in BindEmailInput) error {
	return s.bindContact(ctx, uid, bindContactEmail, in.Step, in.Target, in.Captcha, in.Code, in.IP)
}

// bindContact 按 step 分派（§3.4 行 885；同一端点按 step 取用 payload 的
// 一部分，challenge 用 {target, captcha}、verify 用 {target, code}）。
func (s *BindContactService) bindContact(ctx context.Context, uid int64, kind bindContactKind, step, target string, sub *captcha.Submission, code, ip string) error {
	switch step {
	case bindStepChallenge:
		return s.bindChallenge(ctx, uid, kind, target, sub, ip)
	case bindStepVerify:
		return s.bindVerify(ctx, uid, kind, target, code)
	default:
		return fmt.Errorf("%w: step %q", ErrBindInvalidRequest, step)
	}
}

// bindChallenge 发码步编排（§3.4 行 896-898；顺序为既定口径，勿调整）：
// ①captcha 必过 → ②target 非空 → ③存在性先判 → ④占用判定 → ⑤写码 +
// 限流判定 → ⑥投递。
func (s *BindContactService) bindChallenge(ctx context.Context, uid int64, kind bindContactKind, target string, sub *captcha.Submission, ip string) error {
	// ① captcha 必检（Challenge 恒触发，无阈值参与；service/qrcode.go
	// CreateQrcode 同款）。基础设施错误透传（handler 映射 internal，
	// §1.6 行 273）。
	out, err := s.deps.Gate.Evaluate(ctx, captcha.Request{Challenge: true, Submission: sub})
	if err != nil {
		return fmt.Errorf("account bind: gate: %w", err)
	}
	switch out.Status {
	case captcha.StatusRequired:
		return &BindCaptchaFailure{cause: ErrBindCaptchaRequired, Config: out.Config}
	case captcha.StatusInvalid:
		return &BindCaptchaFailure{cause: ErrBindCaptchaInvalid, Config: out.Config}
	}

	// ② target 非空（§1.6 行 246 参数缺失）。
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("%w: empty target", ErrBindInvalidRequest)
	}

	// ③ 存在性先判（uid 用户行不存在 → user_not_found 口径；同 profile.go
	// 先于任何写操作）。
	if _, err := s.deps.Users.FindByID(ctx, uid); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrBindUserNotFound
		}
		return fmt.Errorf("account bind: load user: %w", err)
	}

	// ④ 占用判定（§3.4 行 892「新号码必须未被他人占用」）：命中他人 →
	// target_taken；命中自己 → 幂等成功零动作（不写码 / 不发信 / 不投
	// 审计，幂等分支口径——无状态变化不投递）。
	if user, err := s.findTarget(ctx, kind, target); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("account bind: load target holder: %w", err)
		}
	} else if user != nil {
		if user.ID != uid {
			return ErrBindTargetTaken
		}
		return nil
	}

	// ⑤ 写码（§10.1 行 1153-1158：账号域绑定 / 换绑 owner=uid 字符串，
	// 本场景无 login_token 不记 tid；键 al:code:{target}:bind 值
	// {code,owner,tries,sent_at}）+ 限流判定（冷却 / 日限额 →
	// too_many_requests，§1.6 行 243；factor/otp 同款映射，deny 时码
	// 未覆盖、发信不发生）。
	owner := strconv.FormatInt(uid, 10)
	code, result, err := s.deps.OTP.Issue(ctx, target, purposeBind, owner, bindSourceIP(ip))
	if err != nil {
		return fmt.Errorf("account bind: issue code: %w", err)
	}
	if denial := core.Judge(result, s.deps.Config, s.now()); !denial.Allowed {
		return fmt.Errorf("%w: retry_after=%ds", ErrBindTooManyRequests, denial.RetryAfter)
	}

	// ⑥ 投递（§8.2 行 1051：发送失败不回滚已写码，允许 60s 后重发；
	// 渠道未配置 → provider_disabled，§1.6 行 260）。
	if s.deps.Sender == nil {
		return fmt.Errorf("account bind: sender not configured")
	}
	if err := s.deps.Sender.SendCode(ctx, target, code); err != nil {
		if errors.Is(err, provider.ErrChannelNotConfigured) {
			return ErrBindProviderDisabled
		}
		return fmt.Errorf("account bind: send code: %w", err)
	}
	return nil
}

// bindVerify 核销步编排（§3.4 行 897）：①格式先判（不消耗尝试次数）→
// ②存在性先判 → ③GETDEL 原子消费 + code / owner 双比对 → ④列级更新 →
// ⑤审计。仅成功写库后投审计。
func (s *BindContactService) bindVerify(ctx context.Context, uid int64, kind bindContactKind, target, code string) error {
	// ① 格式先判（factor/otp Verify 同口径：格式错不进入存储、不消耗
	// 尝试次数 → invalid_request）。
	target = strings.TrimSpace(target)
	code = strings.TrimSpace(code)
	if target == "" || !core.WellFormed(code) {
		return fmt.Errorf("%w: bad target or code", ErrBindInvalidRequest)
	}

	// ② 存在性先判（同 challenge ③；先于码消费）。
	if _, err := s.deps.Users.FindByID(ctx, uid); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrBindUserNotFound
		}
		return fmt.Errorf("account bind: load user: %w", err)
	}

	// ③ GETDEL 原子消费 + 双比对（§3.4 行 897：键由请求 target 拼出、
	// 换 target 即取不到码；校验 code 且码内 owner==当前 uid——owner 不
	// 一致由存储层按码不符处理落 CheckMismatch → invalid_code，
	// cache/lua/verify_code.lua 行 23-33：code 与 owner 任一不符即走错码
	// 分支并消耗 tries）。
	owner := strconv.FormatInt(uid, 10)
	res, err := s.deps.OTP.Check(ctx, target, purposeBind, owner, code)
	if err != nil {
		return fmt.Errorf("account bind: check code: %w", err)
	}
	switch res.Outcome {
	case core.CheckOK:
		return s.bindCommit(ctx, uid, kind, target)
	case core.CheckMismatch:
		return &BindInvalidCodeError{AttemptsLeft: res.AttemptsLeft}
	case core.CheckExhausted:
		return ErrBindTooManyAttempts
	default:
		// CheckMissing：未发送 / 已消费 / 已过期 / 值损坏（§1.6 行 249
		// 「验证码过期 / 已作废」）。
		return ErrBindCodeExpired
	}
}

// bindCommit 核销通过的落库 + 审计（列更新 → 审计，顺序固定：审计仅挂
// 成功写库分支）。
func (s *BindContactService) bindCommit(ctx context.Context, uid int64, kind bindContactKind, target string) error {
	// 列级更新 user 行：phone / email + 对应 verified=1（§4.2 列结构；
	// 未动一侧传 nil 不写入，updated_at 由 repo 刷新）。
	one := int8(1)
	var err error
	if kind == bindContactPhone {
		err = s.deps.Users.UpdateContactColumns(ctx, uid, &target, nil, &one, nil)
	} else {
		err = s.deps.Users.UpdateContactColumns(ctx, uid, nil, &target, nil, &one)
	}
	if err != nil {
		// TOCTOU（§10.2 行 1168 占用口径）：challenge 拦截后、verify 落库
		// 前目标被他人抢占 → 唯一键冲突（依赖 repo 层 ErrUserDuplicate
		// 冲突语义，UserRepo.Create 的 1062 判别同源；生产方法由
		// 拼装落地，须保证该语义）→ target_taken。
		if errors.Is(err, repo.ErrUserDuplicate) {
			return ErrBindTargetTaken
		}
		// 会话存活期间行被删的防御分支（正常流已在 ②拦截）。
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrBindUserNotFound
		}
		return fmt.Errorf("account bind: update contact: %w", err)
	}

	// 审计（§4.6 行 800：bind_phone / bind_email detail={target_masked}，
	// 必须用掩码后的 target；ActorType=user、ActorID=UserID=uid〔自身
	// 操作，thirdparty.go 审计填法同款〕；AuditSink 非阻塞，队列满由
	// Writer 静默降级，§5.2 行 893 不影响主链路）。
	if s.deps.Audit != nil {
		masked := bindMaskTarget(kind, target)
		event := eventlog.EventBindPhone
		if kind == bindContactEmail {
			event = eventlog.EventBindEmail
		}
		s.deps.Audit.PushEvent(model.EventLog{
			Event:     event,
			ActorType: eventlog.ActorTypeUser,
			ActorID:   uid,
			UserID:    uid,
			Target:    masked,
			Detail:    eventlog.DetailTargetMasked(masked),
			CreatedAt: s.now(),
		})
	}
	return nil
}

// findTarget 按渠道查目标占用行（§4.2 uk_phone / uk_email 唯一键反查）。
func (s *BindContactService) findTarget(ctx context.Context, kind bindContactKind, target string) (*model.User, error) {
	if kind == bindContactPhone {
		return s.deps.Users.FindByPhone(ctx, target)
	}
	return s.deps.Users.FindByEmail(ctx, target)
}

// bindMaskTarget 按渠道取掩码（detail 与 Target 同源）。
func bindMaskTarget(kind bindContactKind, target string) string {
	if kind == bindContactPhone {
		return bindMaskPhone(target)
	}
	return bindMaskEmail(target)
}

// bindMaskPhone 固定掩码：前 3 + "****" + 后 4；不足 8 位整体 "****"
// （§3.1 行 813 格式；dto/account.go maskPhone 同构私有实现——后端架构
// §3.5「各落一份」惯例，跨包私有不可复用，前后保留位与 dto 版一致）。
func bindMaskPhone(phone string) string {
	if len(phone) <= 7 {
		return "****"
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}

// bindMaskEmail 固定掩码：本地部分首字符 + "***" + 域名；无 "@" 或空本地
// 部分仅 "***"（§3.1 行 813；dto/account.go maskEmail 同构，理由同上）。
func bindMaskEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return "***"
	}
	local := []rune(email[:at])
	if len(local) == 0 {
		return "***" + email[at:]
	}
	return string(local[0]) + "***" + email[at:]
}

// bindSourceIP 发码侧来源 IP 兜底（factor/otp clientIP 同款：空值用固定
// 标记，避免空键绕过单 IP 日限额，§10.3）。
func bindSourceIP(ip string) string {
	if ip != "" {
		return ip
	}
	return "unknown"
}
