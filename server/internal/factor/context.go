package factor

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"authloft/gen/go/token"
	"authloft/internal/repo/model"
)

// Payload 统一承载各 flow 的请求字段（接口文档 §2.2 / §2.3 / §2.4、§2.6）：
// 单次请求只按 method / step 使用其中一部分，字段名与接口文档 payload 列逐字一致。
type Payload struct {
	Username string
	Password string
	Phone    string
	Email    string
	Code     string
	// Credential webauthn/verify 的断言对象原样透传（接口文档 §2.6 行 547）。
	Credential *structpb.Struct
}

// CaptchaInput 人机校验统一提交格式（接口文档 §2.5 行 499-510），
// 第三方与自绘两类 Provider 共用。
type CaptchaInput struct {
	ProviderKey string
	Token       string
	ID          string
	Answer      string
}

// UserRepo 因子所需用户读取窄接口（适配 internal/repo.UserRepo，§8.2 目标存在性检查）。
type UserRepo interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	FindByPhone(ctx context.Context, phone string) (*model.User, error)
	FindByEmail(ctx context.Context, email string) (*model.User, error)
}

// CredentialRepo 因子所需凭证读取窄接口（§8.1 / §8.2 / §8.4）。
type CredentialRepo interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
}

// CaptchaVerifier 人机校验能力注入接口（具体触发 / 降级归 captcha/gate.go，§9.3）。
type CaptchaVerifier interface {
	Verify(ctx context.Context, captcha *CaptchaInput) error
}

// Limiter 限流能力注入接口：Take 申请一次额度，ok=false 时 retryAfter
// 为建议等待时长（冷却 / 日限额由调用方按 key 区分，§10）。
type Limiter interface {
	Take(ctx context.Context, key string) (ok bool, retryAfter time.Duration, err error)
}

// FactorContext 因子执行上下文（后端架构 §3.8 行 386）：只暴露依赖，不暴露 Gin。
type FactorContext struct {
	Context context.Context
	// LoginToken 本次请求回传的原始 login_token；首次请求为空。
	LoginToken string
	// Login 本次请求的 login_token 状态；engine 在 Start 之前即由
	// loadPayload 构建（首步也含已生成的 tid 与选定 flow），故因子在
	// challenge 阶段即可用；仅未接入引擎的调用方可能为 nil。
	Login *token.LoginTokenPayload
	// Payload 本次请求的因子字段。
	Payload *Payload
	// Captcha 本次请求提交的人机校验凭据；未提交为 nil。
	Captcha *CaptchaInput

	CaptchaVerifier CaptchaVerifier
	Limiter         Limiter
	Users           UserRepo
	Credentials     CredentialRepo
}

// Field 渲染侧输入字段描述（接口文档 §1.3 行 114、§1.11）。
type Field struct {
	Name        string
	Label       string
	Type        string
	Required    bool
	Length      int64
	MaxAttempts int64
}

// StepResult 因子 Start 的原始产出：下一步渲染信息（由 engine 组装信封，
// 字段口径同接口文档 §1.3 next_step）。
type StepResult struct {
	Kind          StepKind
	Method        FactorKind
	Fields        []Field
	RetryAfter    int64
	ExpiresIn     int64
	ChallengeData *structpb.Struct
	// Status 非空表示 Start 未产出下一步，直接以该 status 结束信封
	// （如 user_not_found，且不签发 login_token）。
	Status string
}

// VerifyResult 因子 Verify 的原始产出：Passed 表示本次校验是否通过；
// 失败 / 需要重试时由 Status 承载接口文档 §1.6 的封闭集合取值。
type VerifyResult struct {
	Passed       bool
	UID          int64
	Status       string
	RetryAfter   int64
	AttemptsLeft int64
}
